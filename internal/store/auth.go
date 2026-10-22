package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *Store) AdminPasswordHash(ctx context.Context) ([]byte, error) {
	var hash []byte
	err := s.db.QueryRowContext(
		ctx,
		"SELECT password_hash FROM admins WHERE singleton = 1",
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying admin password: %w", err)
	}
	return hash, nil
}

func (s *Store) CreateAdmin(ctx context.Context, passwordHash []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admins(singleton, username, password_hash, updated_at)
		VALUES(1, 'admin', ?, ?)
		ON CONFLICT(singleton) DO NOTHING`,
		passwordHash,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("creating admin: %w", err)
	}
	return nil
}

// ReplaceAdminPassword stores a rotated admin password hash and revokes every
// session in one transaction, so a rotated credential also ends stolen sessions.
func (s *Store) ReplaceAdminPassword(ctx context.Context, passwordHash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning admin password rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx,
		"UPDATE admins SET password_hash = ?, updated_at = ? WHERE singleton = 1",
		passwordHash,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("updating admin password: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("updating admin password: %w", err)
	} else if affected == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return fmt.Errorf("revoking sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing admin password rotation: %w", err)
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	now := nowText()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions(token_hash, expires_at, created_at, last_seen_at) VALUES(?, ?, ?, ?)`,
		tokenHash,
		expiresAt.UTC().Format(time.RFC3339Nano),
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

func (s *Store) SessionValid(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	return s.SessionActive(ctx, tokenHash, now, 0)
}

// sessionTouchInterval bounds how often an active session's last-seen time is
// written, so UI polling does not turn every request into a database write.
const sessionTouchInterval = time.Minute

// SessionActive reports whether a session is within its absolute lifetime and,
// when idleTimeout is positive, was used within idleTimeout. Active sessions
// have their last-seen time refreshed.
func (s *Store) SessionActive(
	ctx context.Context,
	tokenHash string,
	now time.Time,
	idleTimeout time.Duration,
) (bool, error) {
	var expiresAt, createdAt, lastSeenAt string
	err := s.db.QueryRowContext(
		ctx,
		"SELECT expires_at, created_at, last_seen_at FROM sessions WHERE token_hash = ?",
		tokenHash,
	).Scan(&expiresAt, &createdAt, &lastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("querying session: %w", err)
	}
	expires, err := parseTime(expiresAt)
	if err != nil {
		return false, err
	}
	if !now.Before(expires) {
		return false, nil
	}
	if idleTimeout <= 0 {
		return true, nil
	}
	if lastSeenAt == "" {
		lastSeenAt = createdAt
	}
	lastSeen, err := parseTime(lastSeenAt)
	if err != nil {
		return false, err
	}
	if !now.Before(lastSeen.Add(idleTimeout)) {
		return false, nil
	}
	if now.Sub(lastSeen) >= sessionTouchInterval {
		if _, err := s.db.ExecContext(
			ctx,
			"UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
			now.UTC().Format(time.RFC3339Nano),
			tokenHash,
		); err != nil {
			return false, fmt.Errorf("refreshing session activity: %w", err)
		}
	}
	return true, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(
		ctx,
		"DELETE FROM sessions WHERE token_hash = ?",
		tokenHash,
	); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

// DeleteAllSessions revokes every admin session.
func (s *Store) DeleteAllSessions(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return fmt.Errorf("deleting sessions: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(
		ctx,
		"DELETE FROM sessions WHERE expires_at <= ?",
		now.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("deleting expired sessions: %w", err)
	}
	return nil
}
