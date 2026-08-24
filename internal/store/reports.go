package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Import states of a report snapshot.
const (
	ImportStatePending  = "pending"
	ImportStateImported = "imported"
	ImportStateFailed   = "failed"
)

// ReportSnapshot is the normalized, immutable summary of one Greenbone
// report. Raw report XML is never stored.
type ReportSnapshot struct {
	ID               int64
	ReportID         string
	TaskID           string
	TaskName         string
	CustomerID       string
	CustomerName     string
	ScanStart        time.Time
	ScanEnd          time.Time
	Status           string
	SeverityMax      float64
	CountHigh        int
	CountMedium      int
	CountLow         int
	CountLog         int
	CountFalsePos    int
	FindingCount     int
	ImportState      string
	ImportAttempts   int
	ImportDiagnostic string
	ImportedAt       *time.Time
	CreatedAt        time.Time
}

// FindingSnapshot is one normalized finding row of a report snapshot.
type FindingSnapshot struct {
	ID          int64
	SnapshotID  int64
	Fingerprint string
	NVTOID      string
	Title       string
	Host        string
	Port        string
	Location    string
	Severity    float64
	Threat      string
	QOD         int
	CVEs        []string
	Remediation string
}

// ReportImportStats summarizes report import activity for the health strip.
type ReportImportStats struct {
	ImportedCount  int
	FailedCount    int
	LastImportedAt *time.Time
}

// SaveReportSnapshot upserts one report snapshot with its findings in a
// single transaction. Re-importing a snapshot that is already imported is a
// no-op, which makes imports idempotent by Greenbone report ID. Re-importing
// after a failure replaces the previous rows. A failure rolls the whole
// transaction back so no partial snapshot remains.
func (s *Store) SaveReportSnapshot(
	ctx context.Context,
	snapshot ReportSnapshot,
	findings []FindingSnapshot,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning report snapshot transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existingID int64
	var existingState string
	lookupErr := tx.QueryRowContext(ctx, `
		SELECT id, import_state FROM report_snapshots WHERE report_id = ?`,
		snapshot.ReportID,
	).Scan(&existingID, &existingState)
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		return fmt.Errorf("looking up report snapshot: %w", lookupErr)
	}
	if lookupErr == nil && existingState == ImportStateImported {
		return tx.Commit()
	}

	now := nowText()
	snapshotID := existingID
	if lookupErr == nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE report_snapshots SET
				task_id = ?, task_name = ?, customer_id = NULLIF(?, ''),
				scan_start_at = ?, scan_end_at = ?, status = ?, severity_max = ?,
				count_high = ?, count_medium = ?, count_low = ?, count_log = ?,
				count_false_positive = ?, finding_count = ?,
				import_state = ?, import_diagnostic = '', imported_at = ?
			WHERE id = ?`,
			snapshot.TaskID,
			snapshot.TaskName,
			snapshot.CustomerID,
			reportTimeText(snapshot.ScanStart),
			reportTimeText(snapshot.ScanEnd),
			snapshot.Status,
			snapshot.SeverityMax,
			snapshot.CountHigh,
			snapshot.CountMedium,
			snapshot.CountLow,
			snapshot.CountLog,
			snapshot.CountFalsePos,
			len(findings),
			ImportStateImported,
			now,
			existingID,
		); err != nil {
			return fmt.Errorf("updating report snapshot: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM finding_snapshots WHERE snapshot_id = ?",
			existingID,
		); err != nil {
			return fmt.Errorf("replacing report findings: %w", err)
		}
	} else {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO report_snapshots(
				report_id, task_id, task_name, customer_id,
				scan_start_at, scan_end_at, status, severity_max,
				count_high, count_medium, count_low, count_log,
				count_false_positive, finding_count,
				import_state, import_attempts, import_diagnostic,
				imported_at, created_at
			) VALUES(?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?)`,
			snapshot.ReportID,
			snapshot.TaskID,
			snapshot.TaskName,
			snapshot.CustomerID,
			reportTimeText(snapshot.ScanStart),
			reportTimeText(snapshot.ScanEnd),
			snapshot.Status,
			snapshot.SeverityMax,
			snapshot.CountHigh,
			snapshot.CountMedium,
			snapshot.CountLow,
			snapshot.CountLog,
			snapshot.CountFalsePos,
			len(findings),
			ImportStateImported,
			now,
			now,
		)
		if err != nil {
			return fmt.Errorf("inserting report snapshot: %w", err)
		}
		snapshotID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("reading report snapshot id: %w", err)
		}
	}

	// Findings are inserted in multi-row chunks; the whole snapshot still
	// commits or rolls back as one transaction.
	for start := 0; start < len(findings); start += findingInsertChunk {
		chunk := findings[start:min(start+findingInsertChunk, len(findings))]
		if err := insertFindingChunk(ctx, tx, snapshotID, chunk); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing report snapshot: %w", err)
	}
	return nil
}

// ReportImportState returns the import state of a report snapshot, or
// ErrNotFound when the report has never been seen.
func (s *Store) ReportImportState(ctx context.Context, reportID string) (string, error) {
	var state string
	err := s.db.QueryRowContext(ctx, `
		SELECT import_state FROM report_snapshots WHERE report_id = ?`,
		reportID,
	).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("querying report import state: %w", err)
	}
	return state, nil
}

// RecordReportImportFailure upserts a failed snapshot row and increments the
// attempt counter. Rows that already imported successfully are left untouched.
// The diagnostic must be sanitized by the caller; it never contains raw
// report XML or credentials.
func (s *Store) RecordReportImportFailure(
	ctx context.Context,
	reportID,
	taskID,
	taskName,
	customerID,
	diagnostic string,
) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE report_snapshots SET
			task_id = ?, task_name = ?, customer_id = NULLIF(?, ''),
			import_state = ?, import_attempts = import_attempts + 1,
			import_diagnostic = ?
		WHERE report_id = ? AND import_state != ?`,
		taskID,
		taskName,
		customerID,
		ImportStateFailed,
		diagnostic,
		reportID,
		ImportStateImported,
	)
	if err != nil {
		return fmt.Errorf("recording report import failure: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking report import failure: %w", err)
	}
	if updated > 0 {
		return nil
	}

	var state string
	lookupErr := s.db.QueryRowContext(ctx, `
		SELECT import_state FROM report_snapshots WHERE report_id = ?`,
		reportID,
	).Scan(&state)
	if lookupErr == nil {
		// The row exists and is already imported; do not downgrade it.
		return nil
	}
	if !errors.Is(lookupErr, sql.ErrNoRows) {
		return fmt.Errorf("checking report snapshot: %w", lookupErr)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO report_snapshots(
			report_id, task_id, task_name, customer_id,
			import_state, import_attempts, import_diagnostic, created_at
		) VALUES(?, ?, ?, NULLIF(?, ''), ?, 1, ?, ?)`,
		reportID,
		taskID,
		taskName,
		customerID,
		ImportStateFailed,
		diagnostic,
		nowText(),
	); err != nil {
		return fmt.Errorf("inserting failed report snapshot: %w", err)
	}
	return nil
}

// ListReportSnapshots returns snapshots newest first, joined with the
// customer name. An empty customerID lists snapshots of every customer.
func (s *Store) ListReportSnapshots(
	ctx context.Context,
	customerID string,
	limit int,
) ([]ReportSnapshot, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.report_id, r.task_id, r.task_name,
		       COALESCE(r.customer_id, ''), COALESCE(c.name, ''),
		       r.scan_start_at, r.scan_end_at, r.status, r.severity_max,
		       r.count_high, r.count_medium, r.count_low, r.count_log,
		       r.count_false_positive, r.finding_count,
		       r.import_state, r.import_attempts, r.import_diagnostic,
		       COALESCE(r.imported_at, ''), r.created_at
		FROM report_snapshots r
		LEFT JOIN customers c ON c.id = r.customer_id
		WHERE (? = '' OR r.customer_id = ?)
		ORDER BY r.scan_end_at DESC, r.id DESC
		LIMIT ?`,
		customerID,
		customerID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying report snapshots: %w", err)
	}
	defer rows.Close()

	result := make([]ReportSnapshot, 0)
	for rows.Next() {
		snapshot, err := scanReportSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating report snapshots: %w", err)
	}
	return result, nil
}

// ReportSnapshot returns one snapshot by internal ID, joined with the
// customer name.
func (s *Store) ReportSnapshot(ctx context.Context, id int64) (ReportSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.report_id, r.task_id, r.task_name,
		       COALESCE(r.customer_id, ''), COALESCE(c.name, ''),
		       r.scan_start_at, r.scan_end_at, r.status, r.severity_max,
		       r.count_high, r.count_medium, r.count_low, r.count_log,
		       r.count_false_positive, r.finding_count,
		       r.import_state, r.import_attempts, r.import_diagnostic,
		       COALESCE(r.imported_at, ''), r.created_at
		FROM report_snapshots r
		LEFT JOIN customers c ON c.id = r.customer_id
		WHERE r.id = ?`,
		id,
	)
	if err != nil {
		return ReportSnapshot{}, fmt.Errorf("querying report snapshot: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return ReportSnapshot{}, fmt.Errorf("iterating report snapshot: %w", err)
		}
		return ReportSnapshot{}, ErrNotFound
	}
	snapshot, err := scanReportSnapshot(rows)
	if err != nil {
		return ReportSnapshot{}, err
	}
	return snapshot, nil
}

// ReportFindings returns the findings of one snapshot ordered by severity,
// most severe first.
func (s *Store) ReportFindings(
	ctx context.Context,
	snapshotID int64,
) ([]FindingSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, snapshot_id, fingerprint, nvt_oid, title, host, port,
		       location, severity, threat, qod, cves, remediation
		FROM finding_snapshots
		WHERE snapshot_id = ?
		ORDER BY severity DESC, host, title`,
		snapshotID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying finding snapshots: %w", err)
	}
	defer rows.Close()

	result := make([]FindingSnapshot, 0)
	for rows.Next() {
		var finding FindingSnapshot
		var cves string
		if err := rows.Scan(
			&finding.ID,
			&finding.SnapshotID,
			&finding.Fingerprint,
			&finding.NVTOID,
			&finding.Title,
			&finding.Host,
			&finding.Port,
			&finding.Location,
			&finding.Severity,
			&finding.Threat,
			&finding.QOD,
			&cves,
			&finding.Remediation,
		); err != nil {
			return nil, fmt.Errorf("scanning finding snapshot: %w", err)
		}
		if cves != "" {
			finding.CVEs = strings.Split(cves, ",")
		}
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating finding snapshots: %w", err)
	}
	return result, nil
}

// PendingReportRetries returns failed snapshots that have not yet exhausted
// the retry budget.
func (s *Store) PendingReportRetries(
	ctx context.Context,
	maxAttempts int,
) ([]ReportSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, report_id, task_id, task_name, COALESCE(customer_id, ''),
		       import_attempts
		FROM report_snapshots
		WHERE import_state = ? AND import_attempts < ?
		ORDER BY id`,
		ImportStateFailed,
		maxAttempts,
	)
	if err != nil {
		return nil, fmt.Errorf("querying pending report retries: %w", err)
	}
	defer rows.Close()

	result := make([]ReportSnapshot, 0)
	for rows.Next() {
		var snapshot ReportSnapshot
		if err := rows.Scan(
			&snapshot.ID,
			&snapshot.ReportID,
			&snapshot.TaskID,
			&snapshot.TaskName,
			&snapshot.CustomerID,
			&snapshot.ImportAttempts,
		); err != nil {
			return nil, fmt.Errorf("scanning pending report retry: %w", err)
		}
		snapshot.ImportState = ImportStateFailed
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating pending report retries: %w", err)
	}
	return result, nil
}

// CustomerForManagedTask maps a Greenbone task ID back to the managed
// customer, or returns ErrNotFound for foreign tasks.
func (s *Store) CustomerForManagedTask(ctx context.Context, gvmTaskID string) (string, error) {
	var customerID string
	err := s.db.QueryRowContext(ctx, `
		SELECT customer_id FROM managed_resources
		WHERE kind = 'task' AND gvm_id = ?
		LIMIT 1`,
		gvmTaskID,
	).Scan(&customerID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("mapping greenbone task to customer: %w", err)
	}
	return customerID, nil
}

// ReportImportStats summarizes import activity for the report-sync health
// component.
func (s *Store) ReportImportStats(ctx context.Context) (ReportImportStats, error) {
	var stats ReportImportStats
	var lastImported string
	err := s.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN import_state = 'imported' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN import_state = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(CASE WHEN import_state = 'imported' THEN imported_at END), '')
		FROM report_snapshots`,
	).Scan(&stats.ImportedCount, &stats.FailedCount, &lastImported)
	if err != nil {
		return ReportImportStats{}, fmt.Errorf("querying report import stats: %w", err)
	}
	if lastImported != "" {
		parsed, err := parseTime(lastImported)
		if err != nil {
			return ReportImportStats{}, err
		}
		stats.LastImportedAt = &parsed
	}
	return stats, nil
}

// findingInsertChunk bounds the multi-row finding INSERT so the parameter
// count (12 columns × chunk) stays below every SQLite variable limit.
const findingInsertChunk = 50

// insertFindingChunk inserts one batch of findings with a single multi-row
// INSERT statement inside the snapshot transaction.
func insertFindingChunk(
	ctx context.Context,
	tx *sql.Tx,
	snapshotID int64,
	findings []FindingSnapshot,
) error {
	placeholders := make([]string, len(findings))
	arguments := make([]any, 0, len(findings)*12)
	for index, finding := range findings {
		placeholders[index] = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
		arguments = append(arguments,
			snapshotID,
			finding.Fingerprint,
			finding.NVTOID,
			finding.Title,
			finding.Host,
			finding.Port,
			finding.Location,
			finding.Severity,
			finding.Threat,
			finding.QOD,
			strings.Join(finding.CVEs, ","),
			finding.Remediation,
		)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_snapshots(
			snapshot_id, fingerprint, nvt_oid, title, host, port,
			location, severity, threat, qod, cves, remediation
		) VALUES `+strings.Join(placeholders, ","),
		arguments...,
	); err != nil {
		return fmt.Errorf("inserting finding snapshots: %w", err)
	}
	return nil
}

type reportSnapshotScanner interface {
	Scan(destination ...any) error
}

func scanReportSnapshot(rows reportSnapshotScanner) (ReportSnapshot, error) {
	var snapshot ReportSnapshot
	var scanStart, scanEnd, importedAt, createdAt string
	if err := rows.Scan(
		&snapshot.ID,
		&snapshot.ReportID,
		&snapshot.TaskID,
		&snapshot.TaskName,
		&snapshot.CustomerID,
		&snapshot.CustomerName,
		&scanStart,
		&scanEnd,
		&snapshot.Status,
		&snapshot.SeverityMax,
		&snapshot.CountHigh,
		&snapshot.CountMedium,
		&snapshot.CountLow,
		&snapshot.CountLog,
		&snapshot.CountFalsePos,
		&snapshot.FindingCount,
		&snapshot.ImportState,
		&snapshot.ImportAttempts,
		&snapshot.ImportDiagnostic,
		&importedAt,
		&createdAt,
	); err != nil {
		return ReportSnapshot{}, fmt.Errorf("scanning report snapshot: %w", err)
	}
	var err error
	if snapshot.ScanStart, err = parseReportTime(scanStart); err != nil {
		return ReportSnapshot{}, err
	}
	if snapshot.ScanEnd, err = parseReportTime(scanEnd); err != nil {
		return ReportSnapshot{}, err
	}
	if importedAt != "" {
		parsed, parseErr := parseTime(importedAt)
		if parseErr != nil {
			return ReportSnapshot{}, parseErr
		}
		snapshot.ImportedAt = &parsed
	}
	if snapshot.CreatedAt, err = parseTime(createdAt); err != nil {
		return ReportSnapshot{}, err
	}
	return snapshot, nil
}

func reportTimeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(fixedTimeLayout)
}

func parseReportTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return parseTime(value)
}
