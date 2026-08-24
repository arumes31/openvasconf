package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"openvasconf/internal/id"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const fixedTimeLayout = "2006-01-02T15:04:05.000000000Z"

var ErrNotFound = errors.New("store: not found")

type Store struct {
	db *sql.DB
}

type ManagedResource struct {
	CustomerID      string
	Kind            string
	Class           string
	Sequence        int
	GVMID           string
	DesiredHash     string
	OwnershipMarker string
	State           string
	LastError       string
	UpdatedAt       time.Time
}

type AuditEvent struct {
	ID           int64
	CustomerID   string
	Action       string
	ResourceKind string
	ResourceName string
	Detail       string
	CreatedAt    time.Time
}

type CustomerQuery struct {
	Search         string
	Status         string
	Sort           string
	Descending     bool
	IncludeDeleted bool
	Limit          int
}

type ReconcileProgress struct {
	Phase               string
	CurrentOperation    string
	CompletedOperations int
	TotalOperations     int
	Attempt             int
	MaxAttempts         int
	NextRetryAt         *time.Time
	SafeError           string
	TechnicalError      string
}

type ReconcileRun struct {
	ID                  int64
	CustomerID          string
	StartedAt           time.Time
	FinishedAt          *time.Time
	Status              string
	Phase               string
	SafeError           string
	TechnicalError      string
	Attempt             int
	CompletedOperations int
	TotalOperations     int
	Operations          []ReconcileOperation
}

type ReconcileOperation struct {
	ID           int64
	RunID        int64
	CustomerID   string
	Action       string
	ResourceKind string
	ResourceName string
	Status       string
	Detail       string
	Duration     time.Duration
	CreatedAt    time.Time
}

func Open(ctx context.Context, path, timezone string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) +
		"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	store := &Store{db: db}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite database: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.bootstrapSettings(ctx, timezone); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.bootstrapUpdatePolicy(ctx, timezone); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func closeRows(rows interface{ Close() error }, operation string, returnErr error) error {
	if err := rows.Close(); err != nil {
		return errors.Join(returnErr, fmt.Errorf("closing %s: %w", operation, err))
	}
	return returnErr
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("reading migrations: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versionText := strings.SplitN(entry.Name(), "_", 2)[0]
		version, err := strconv.Atoi(versionText)
		if err != nil {
			return fmt.Errorf("parsing migration version %q: %w", entry.Name(), err)
		}
		contents, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("reading migration %q: %w", entry.Name(), err)
		}
		if err := s.applyMigration(ctx, version, string(contents)); err != nil {
			return fmt.Errorf("applying migration %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, version int, statement string) (returnErr error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquiring migration connection: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("closing migration connection: %w", err))
		}
	}()

	checkForeignKeys := strings.HasPrefix(statement, "-- openvasconf: foreign_keys_off")
	restoreForeignKeys := false
	if checkForeignKeys {
		var foreignKeysEnabled int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeysEnabled); err != nil {
			return fmt.Errorf("reading foreign-key enforcement: %w", err)
		}
		if foreignKeysEnabled != 0 {
			if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
				return fmt.Errorf("disabling foreign-key enforcement: %w", err)
			}
			restoreForeignKeys = true
		}
	}
	defer func() {
		if !restoreForeignKeys {
			return
		}
		if _, err := conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA foreign_keys = ON"); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restoring foreign-key enforcement: %w", err))
		}
	}()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("creating migration table: %w", err)
	}

	var exists int
	if err := tx.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM schema_migrations WHERE version = ?",
		version,
	).Scan(&exists); err != nil {
		return fmt.Errorf("checking migration version: %w", err)
	}
	if exists > 0 {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("executing migration: %w", err)
	}
	if checkForeignKeys {
		rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return fmt.Errorf("checking foreign keys after migration: %w", err)
		}
		if rows.Next() {
			var table, parent string
			var rowID, foreignKeyID int64
			if err := rows.Scan(&table, &rowID, &parent, &foreignKeyID); err != nil {
				return closeRows(rows, "foreign-key check", fmt.Errorf("scanning foreign-key violation: %w", err))
			}
			violationErr := fmt.Errorf(
				"foreign-key violation after migration: table %q row %d references %q (constraint %d)",
				table,
				rowID,
				parent,
				foreignKeyID,
			)
			return closeRows(rows, "foreign-key check", violationErr)
		}
		if err := rows.Err(); err != nil {
			return closeRows(rows, "foreign-key check", fmt.Errorf("checking foreign keys after migration: %w", err))
		}
		if err := closeRows(rows, "foreign-key check", nil); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
		version,
		nowText(),
	); err != nil {
		return fmt.Errorf("recording migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration: %w", err)
	}
	return nil
}

func (s *Store) bootstrapSettings(ctx context.Context, timezone string) error {
	installationID, err := id.New()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO settings(singleton, installation_id, timezone, updated_at)
		VALUES(1, ?, ?, ?)
		ON CONFLICT(singleton) DO NOTHING`,
		installationID,
		timezone,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("bootstrapping settings: %w", err)
	}
	return nil
}

func nowText() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing database time: %w", err)
	}
	return parsed, nil
}
