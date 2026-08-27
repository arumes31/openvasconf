package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	FindingScopeActive        = "active"
	FindingScopeSuppressed    = "suppressed"
	maxCurrentFindingPageSize = 100000
)

// CurrentFinding is the latest successful occurrence of one task-scoped
// finding with its persistent operational state.
type CurrentFinding struct {
	FindingSnapshot
	CustomerID       string
	CustomerName     string
	CID              string
	TaskID           string
	TaskName         string
	ScanEnd          time.Time
	FirstSeen        time.Time
	LastSeen         time.Time
	Disposition      string
	Justification    string
	RemediationState string
	TicketState      string
	Lifecycle        string
}

// FindingQuery controls server-side current-exposure filtering and pagination.
type FindingQuery struct {
	CustomerID string
	CID        string
	Task       string
	Severity   string
	Host       string
	Scope      string
	Ticket     string
	Lifecycle  string
	Page       int
	PageSize   int
}

// FindingMetrics summarizes current exposure and ticket-delivery attention.
type FindingMetrics struct {
	ActiveHighCritical int
	Suppressed         int
	TicketQueued       int
	TicketBlocked      int
	Overdue            int
}

func reconcileFindingStatesTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot ReportSnapshot,
	snapshotID int64,
	findings []FindingSnapshot,
) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_states SET present = 0, updated_at = ?
		WHERE customer_id = ? AND task_id = ? AND present = 1`,
		nowText(),
		snapshot.CustomerID,
		snapshot.TaskID,
	); err != nil {
		return fmt.Errorf("marking previous task findings absent: %w", err)
	}

	seenAt := reportTimeText(snapshot.ScanEnd)
	for _, finding := range findings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_states(
				customer_id, task_id, fingerprint, first_seen_at, last_seen_at,
				last_snapshot_id, present, severity, created_at, updated_at
			) VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
			ON CONFLICT(customer_id, task_id, fingerprint) DO UPDATE SET
				last_seen_at = excluded.last_seen_at,
				last_snapshot_id = excluded.last_snapshot_id,
				present = 1,
				severity = excluded.severity,
				updated_at = excluded.updated_at`,
			snapshot.CustomerID,
			snapshot.TaskID,
			finding.Fingerprint,
			seenAt,
			seenAt,
			snapshotID,
			finding.Severity,
			nowText(),
			nowText(),
		); err != nil {
			return fmt.Errorf("reconciling task finding state: %w", err)
		}
	}
	return nil
}

// reconcileHistoricalFindingStatesTx records an out-of-order older import
// without replacing the current exposure selected from a newer snapshot.
func reconcileHistoricalFindingStatesTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot ReportSnapshot,
	snapshotID int64,
	findings []FindingSnapshot,
) error {
	seenAt := reportTimeText(snapshot.ScanEnd)
	for _, finding := range findings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_states(
				customer_id, task_id, fingerprint, first_seen_at, last_seen_at,
				last_snapshot_id, present, severity, created_at, updated_at
			) VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
			ON CONFLICT(customer_id, task_id, fingerprint) DO UPDATE SET
				first_seen_at = MIN(finding_states.first_seen_at, excluded.first_seen_at),
				updated_at = excluded.updated_at`,
			snapshot.CustomerID, snapshot.TaskID, finding.Fingerprint,
			seenAt, seenAt, snapshotID, finding.Severity, nowText(), nowText(),
		); err != nil {
			return fmt.Errorf("recording historical task finding state: %w", err)
		}
	}
	return nil
}

// CurrentFindings returns the current operational exposure, one latest row
// per task-scoped fingerprint, plus the total before pagination.
func (s *Store) CurrentFindings(
	ctx context.Context,
	filter FindingQuery,
) ([]CurrentFinding, int, error) {
	where, args, err := currentFindingWhere(filter)
	if err != nil {
		return nil, 0, err
	}
	from := `
		FROM finding_states s
		JOIN customers c ON c.id = s.customer_id
		JOIN report_snapshots r ON r.id = s.last_snapshot_id
		JOIN finding_snapshots f
		  ON f.snapshot_id = s.last_snapshot_id AND f.fingerprint = s.fingerprint`
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) "+from+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting current findings: %w", err)
	}

	pageSize := filter.PageSize
	if pageSize < 1 || pageSize > maxCurrentFindingPageSize {
		pageSize = 100
	}
	page := max(filter.Page, 1)
	// #nosec G202 -- from and where contain only fixed, allow-listed SQL
	// fragments; every operator value remains a bound parameter.
	query := `SELECT
		f.id, f.snapshot_id, f.fingerprint, f.nvt_oid, f.title, f.host, f.port,
		f.location, f.severity, f.threat, f.qod, f.cves, f.remediation,
		s.customer_id, c.name, c.cid, s.task_id, r.task_name, r.scan_end_at,
		s.first_seen_at, s.last_seen_at, s.disposition, s.justification,
		s.remediation_state, s.ticket_state ` + from + where + `
		ORDER BY f.severity DESC, c.name COLLATE NOCASE, f.host, f.title
		LIMIT ? OFFSET ?`
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying current findings: %w", err)
	}
	result := make([]CurrentFinding, 0, min(total, pageSize))
	for rows.Next() {
		var value CurrentFinding
		var cves, scanEnd, firstSeen, lastSeen string
		if err := rows.Scan(
			&value.ID, &value.SnapshotID, &value.Fingerprint, &value.NVTOID,
			&value.Title, &value.Host, &value.Port, &value.Location,
			&value.Severity, &value.Threat, &value.QOD, &cves, &value.Remediation,
			&value.CustomerID, &value.CustomerName, &value.CID, &value.TaskID,
			&value.TaskName, &scanEnd, &firstSeen, &lastSeen, &value.Disposition,
			&value.Justification, &value.RemediationState, &value.TicketState,
		); err != nil {
			return nil, 0, closeRows(rows, "current findings query", fmt.Errorf("scanning current finding: %w", err))
		}
		value.CVEs = splitCVEs(cves)
		if value.ScanEnd, err = parseReportTime(scanEnd); err != nil {
			return nil, 0, closeRows(rows, "current findings query", err)
		}
		if value.FirstSeen, err = parseReportTime(firstSeen); err != nil {
			return nil, 0, closeRows(rows, "current findings query", err)
		}
		if value.LastSeen, err = parseReportTime(lastSeen); err != nil {
			return nil, 0, closeRows(rows, "current findings query", err)
		}
		value.Lifecycle = "recurring"
		if value.FirstSeen.Equal(value.LastSeen) {
			value.Lifecycle = "new"
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, closeRows(rows, "current findings query", fmt.Errorf("iterating current findings: %w", err))
	}
	if err := closeRows(rows, "current findings query", nil); err != nil {
		return nil, 0, err
	}
	return result, total, nil
}

func currentFindingWhere(filter FindingQuery) (string, []any, error) {
	clauses := []string{"s.present = 1", "c.deleted_at IS NULL"}
	args := make([]any, 0, 8)
	switch filter.Scope {
	case "", FindingScopeActive:
		clauses = append(clauses, "s.remediation_state NOT IN ('resolved', 'wont_fix')")
	case FindingScopeSuppressed:
		clauses = append(clauses, "s.remediation_state IN ('resolved', 'wont_fix')")
	default:
		return "", nil, fmt.Errorf("querying current findings: unsupported scope %q", filter.Scope)
	}
	if filter.CustomerID != "" {
		clauses = append(clauses, "s.customer_id = ?")
		args = append(args, filter.CustomerID)
	}
	if filter.CID != "" {
		clauses = append(clauses, "c.cid LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escapeLike(filter.CID)+"%")
	}
	if filter.Task != "" {
		clauses = append(clauses, "(r.task_name LIKE ? ESCAPE '\\' OR s.task_id LIKE ? ESCAPE '\\')")
		pattern := "%" + escapeLike(filter.Task) + "%"
		args = append(args, pattern, pattern)
	}
	if filter.Host != "" {
		clauses = append(clauses, "f.host LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escapeLike(filter.Host)+"%")
	}
	if filter.Ticket != "" {
		clauses = append(clauses, "s.ticket_state = ?")
		args = append(args, filter.Ticket)
	}
	switch filter.Lifecycle {
	case "":
	case "new":
		clauses = append(clauses, "s.first_seen_at = s.last_seen_at")
	case "recurring":
		clauses = append(clauses, "s.first_seen_at <> s.last_seen_at")
	default:
		return "", nil, fmt.Errorf("querying current findings: unsupported lifecycle %q", filter.Lifecycle)
	}
	switch filter.Severity {
	case "":
	case "critical":
		clauses = append(clauses, "f.severity >= 9.0")
	case "high":
		clauses = append(clauses, "f.severity >= 7.0 AND f.severity < 9.0")
	case "medium":
		clauses = append(clauses, "f.severity >= 4.0 AND f.severity < 7.0")
	case "low":
		clauses = append(clauses, "f.severity > 0 AND f.severity < 4.0")
	default:
		return "", nil, fmt.Errorf("querying current findings: unsupported severity %q", filter.Severity)
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

// CurrentFindingMetrics summarizes operational findings independently of the
// current page filters.
func (s *Store) CurrentFindingMetrics(ctx context.Context) (FindingMetrics, error) {
	var result FindingMetrics
	err := s.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN present = 1 AND severity >= 7
			  AND remediation_state NOT IN ('resolved', 'wont_fix') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN present = 1
			  AND remediation_state IN ('resolved', 'wont_fix') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ticket_state IN ('queued_open', 'queued_close') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ticket_state IN ('blocked', 'failed') THEN 1 ELSE 0 END), 0)
			,COALESCE(SUM(CASE WHEN present = 1 AND severity > 0
			  AND remediation_state NOT IN ('resolved', 'wont_fix')
			  AND julianday('now') > CASE
			    WHEN due_date IS NOT NULL AND julianday(due_date) < julianday(first_seen_at) +
			      CASE WHEN severity >= 9 THEN cfg.sla_critical_days
			           WHEN severity >= 7 THEN cfg.sla_high_days
			           WHEN severity >= 4 THEN cfg.sla_medium_days
			           ELSE cfg.sla_low_days END
			    THEN julianday(due_date)
			    ELSE julianday(first_seen_at) +
			      CASE WHEN severity >= 9 THEN cfg.sla_critical_days
			           WHEN severity >= 7 THEN cfg.sla_high_days
			           WHEN severity >= 4 THEN cfg.sla_medium_days
			           ELSE cfg.sla_low_days END
			  END THEN 1 ELSE 0 END), 0)
		FROM finding_states CROSS JOIN settings cfg ON cfg.singleton = 1`).Scan(
		&result.ActiveHighCritical,
		&result.Suppressed,
		&result.TicketQueued,
		&result.TicketBlocked,
		&result.Overdue,
	)
	if err != nil {
		return FindingMetrics{}, fmt.Errorf("querying current finding metrics: %w", err)
	}
	return result, nil
}

func splitCVEs(value string) []string {
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}
