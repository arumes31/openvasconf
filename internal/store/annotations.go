package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Finding dispositions.
const (
	DispositionActive        = "active"
	DispositionFalsePositive = "false_positive"
	DispositionAcceptedRisk  = "accepted_risk"
)

// Remediation states.
const (
	RemediationOpen       = "open"
	RemediationInProgress = "in_progress"
	RemediationResolved   = "resolved"
	RemediationWontFix    = "wont_fix"
)

// Annotation field length caps; longer operator input is truncated.
const (
	maxAnnotationTextLength = 2000
	maxAnnotationNameLength = 200
)

// FindingAnnotation is operator state attached to a finding fingerprint. It
// lives outside the immutable snapshots and survives across scans.
type FindingAnnotation struct {
	CustomerID       string
	Fingerprint      string
	Disposition      string
	Justification    string
	Operator         string
	RemediationState string
	RemediationOwner string
	DueDate          *time.Time
	ExpiresAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// UpsertAnnotation creates or updates the annotation keyed by customer and
// fingerprint. Snapshot rows are never modified.
func (s *Store) UpsertAnnotation(ctx context.Context, value FindingAnnotation) error {
	if value.Disposition == "" {
		value.Disposition = DispositionActive
	}
	if value.RemediationState == "" {
		value.RemediationState = RemediationOpen
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_annotations(
			customer_id, fingerprint, disposition, justification, operator,
			remediation_state, remediation_owner, due_date, expires_at,
			created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(customer_id, fingerprint) DO UPDATE SET
			disposition = excluded.disposition,
			justification = excluded.justification,
			operator = excluded.operator,
			remediation_state = excluded.remediation_state,
			remediation_owner = excluded.remediation_owner,
			due_date = excluded.due_date,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`,
		value.CustomerID,
		value.Fingerprint,
		value.Disposition,
		annotationText(value.Justification, maxAnnotationTextLength),
		annotationText(value.Operator, maxAnnotationNameLength),
		value.RemediationState,
		annotationText(value.RemediationOwner, maxAnnotationNameLength),
		nullableTimeText(value.DueDate),
		nullableTimeText(value.ExpiresAt),
		nowText(),
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("upserting finding annotation: %w", err)
	}
	return nil
}

// Annotation returns one annotation or ErrNotFound when none exists.
func (s *Store) Annotation(
	ctx context.Context,
	customerID,
	fingerprint string,
) (result FindingAnnotation, returnErr error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT customer_id, fingerprint, disposition, justification, operator,
		       remediation_state, remediation_owner,
		       COALESCE(due_date, ''), COALESCE(expires_at, ''),
		       created_at, updated_at
		FROM finding_annotations
		WHERE customer_id = ? AND fingerprint = ?`,
		customerID,
		fingerprint,
	)
	if err != nil {
		return FindingAnnotation{}, fmt.Errorf("querying finding annotation: %w", err)
	}
	defer func() {
		returnErr = closeRows(rows, "finding annotation query", returnErr)
	}()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return FindingAnnotation{}, fmt.Errorf("iterating finding annotation: %w", err)
		}
		return FindingAnnotation{}, ErrNotFound
	}
	return scanAnnotation(rows)
}

// AnnotationsForCustomer returns every annotation of a customer keyed by
// finding fingerprint.
func (s *Store) AnnotationsForCustomer(
	ctx context.Context,
	customerID string,
) (result map[string]FindingAnnotation, returnErr error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT customer_id, fingerprint, disposition, justification, operator,
		       remediation_state, remediation_owner,
		       COALESCE(due_date, ''), COALESCE(expires_at, ''),
		       created_at, updated_at
		FROM finding_annotations
		WHERE customer_id = ?
		ORDER BY updated_at DESC`,
		customerID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying finding annotations: %w", err)
	}
	defer func() {
		returnErr = closeRows(rows, "finding annotations query", returnErr)
	}()

	result = make(map[string]FindingAnnotation)
	for rows.Next() {
		annotation, err := scanAnnotation(rows)
		if err != nil {
			return nil, err
		}
		result[annotation.Fingerprint] = annotation
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating finding annotations: %w", err)
	}
	return result, nil
}

func scanAnnotation(rows reportSnapshotScanner) (FindingAnnotation, error) {
	var annotation FindingAnnotation
	var dueDate, expiresAt, createdAt, updatedAt string
	if err := rows.Scan(
		&annotation.CustomerID,
		&annotation.Fingerprint,
		&annotation.Disposition,
		&annotation.Justification,
		&annotation.Operator,
		&annotation.RemediationState,
		&annotation.RemediationOwner,
		&dueDate,
		&expiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return FindingAnnotation{}, fmt.Errorf("scanning finding annotation: %w", err)
	}
	var err error
	if annotation.DueDate, err = parseNullableTime(dueDate); err != nil {
		return FindingAnnotation{}, err
	}
	if annotation.ExpiresAt, err = parseNullableTime(expiresAt); err != nil {
		return FindingAnnotation{}, err
	}
	if annotation.CreatedAt, err = parseTime(createdAt); err != nil {
		return FindingAnnotation{}, err
	}
	if annotation.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return FindingAnnotation{}, err
	}
	return annotation, nil
}

// PreviousImportedSnapshot returns the imported snapshot of the same customer
// immediately preceding the given one by scan end time, or ErrNotFound when
// the given snapshot is the first.
func (s *Store) PreviousImportedSnapshot(
	ctx context.Context,
	snapshot ReportSnapshot,
) (result ReportSnapshot, returnErr error) {
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
		WHERE r.customer_id = ? AND r.import_state = ?
		  AND (r.scan_end_at < ? OR (r.scan_end_at = ? AND r.id < ?))
		ORDER BY r.scan_end_at DESC, r.id DESC
		LIMIT 1`,
		snapshot.CustomerID,
		ImportStateImported,
		reportTimeText(snapshot.ScanEnd),
		reportTimeText(snapshot.ScanEnd),
		snapshot.ID,
	)
	if err != nil {
		return ReportSnapshot{}, fmt.Errorf("querying previous report snapshot: %w", err)
	}
	defer func() {
		returnErr = closeRows(rows, "previous report snapshot query", returnErr)
	}()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return ReportSnapshot{}, fmt.Errorf("iterating previous report snapshot: %w", err)
		}
		return ReportSnapshot{}, ErrNotFound
	}
	return scanReportSnapshot(rows)
}

// firstSeenChunkSize keeps the fingerprint IN-list below the SQLite variable
// limit.
const firstSeenChunkSize = 500

// FirstSeen returns the earliest scan end time at which each given
// fingerprint appeared in an imported snapshot of the customer. One grouped
// query per chunk avoids per-fingerprint lookups.
func (s *Store) FirstSeen(
	ctx context.Context,
	customerID string,
	fingerprints []string,
) (map[string]time.Time, error) {
	result := make(map[string]time.Time, len(fingerprints))
	for start := 0; start < len(fingerprints); start += firstSeenChunkSize {
		chunk := fingerprints[start:min(start+firstSeenChunkSize, len(fingerprints))]
		placeholders := make([]string, len(chunk))
		arguments := make([]any, 0, len(chunk)+2)
		arguments = append(arguments, customerID, ImportStateImported)
		for index, fingerprint := range chunk {
			placeholders[index] = "?"
			arguments = append(arguments, fingerprint)
		}
		// The only generated SQL fragments are one "?" placeholder per
		// fingerprint; all values remain bound parameters.
		// #nosec G202 -- generated placeholders, never input text.
		rows, err := s.db.QueryContext(ctx, `
			SELECT f.fingerprint, MIN(r.scan_end_at)
			FROM finding_snapshots f
			JOIN report_snapshots r ON r.id = f.snapshot_id
			WHERE r.customer_id = ? AND r.import_state = ?
			  AND f.fingerprint IN (`+strings.Join(placeholders, ",")+`)
			GROUP BY f.fingerprint`,
			arguments...,
		)
		if err != nil {
			return nil, fmt.Errorf("querying first-seen times: %w", err)
		}
		for rows.Next() {
			var fingerprint, seenAt string
			if err := rows.Scan(&fingerprint, &seenAt); err != nil {
				return nil, closeRows(rows, "first-seen query", fmt.Errorf("scanning first-seen time: %w", err))
			}
			parsed, err := parseReportTime(seenAt)
			if err != nil {
				return nil, closeRows(rows, "first-seen query", err)
			}
			result[fingerprint] = parsed
		}
		if err := rows.Err(); err != nil {
			return nil, closeRows(rows, "first-seen query", fmt.Errorf("iterating first-seen times: %w", err))
		}
		if err := closeRows(rows, "first-seen query", nil); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// ReportTrend returns the most recent imported snapshots of a customer with
// their severity totals, oldest first, capped at limit entries.
func (s *Store) ReportTrend(
	ctx context.Context,
	customerID string,
	limit int,
) ([]ReportSnapshot, error) {
	if limit <= 0 || limit > 100 {
		limit = 12
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
		WHERE r.customer_id = ? AND r.import_state = ?
		ORDER BY r.scan_end_at DESC, r.id DESC
		LIMIT ?`,
		customerID,
		ImportStateImported,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying report trend: %w", err)
	}
	result := make([]ReportSnapshot, 0)
	for rows.Next() {
		snapshot, err := scanReportSnapshot(rows)
		if err != nil {
			return nil, closeRows(rows, "report trend query", err)
		}
		result = append(result, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "report trend query", fmt.Errorf("iterating report trend: %w", err))
	}
	if err := closeRows(rows, "report trend query", nil); err != nil {
		return nil, err
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}

func annotationText(value string, maxLength int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > maxLength {
		return string(runes[:maxLength])
	}
	return string(runes)
}

func nullableTimeText(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC().Format(fixedTimeLayout)
}

func parseNullableTime(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := parseTime(value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
