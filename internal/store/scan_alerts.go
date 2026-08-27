package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	scanFailedAction       = "scan_failed"
	scanAcknowledgedAction = "scan_failure_acknowledged"
)

// ScanAlert is one unacknowledged failed managed scan recorded in the
// immutable audit journal.
type ScanAlert struct {
	ID           int64
	CustomerID   string
	CustomerName string
	CID          string
	TaskID       string
	TaskName     string
	ReportID     string
	Status       string
	Reason       string
	DetectedAt   time.Time
}

type scanAlertDetail struct {
	TaskID   string `json:"task_id"`
	TaskName string `json:"task_name"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

// RecordScanFailure records a failure once per customer and Greenbone report.
// The INSERT ... SELECT guard makes repeated report-sync observations
// idempotent without weakening the append-only audit journal.
func (s *Store) RecordScanFailure(
	ctx context.Context,
	alert ScanAlert,
) (bool, error) {
	if alert.CustomerID == "" || alert.ReportID == "" {
		return false, errors.New("recording scan failure: customer and report are required")
	}
	detail, err := json.Marshal(scanAlertDetail{
		TaskID: alert.TaskID, TaskName: alert.TaskName,
		Status: alert.Status, Reason: alert.Reason,
	})
	if err != nil {
		return false, fmt.Errorf("encoding scan failure: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(
			customer_id, action, resource_kind, resource_name, detail, created_at
		)
		SELECT ?, ?, 'scan', ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_events
			WHERE customer_id = ? AND action = ? AND resource_kind = 'scan'
			  AND resource_name = ?
		)`,
		alert.CustomerID,
		scanFailedAction,
		alert.ReportID,
		string(detail),
		nowText(),
		alert.CustomerID,
		scanFailedAction,
		alert.ReportID,
	)
	if err != nil {
		return false, fmt.Errorf("recording scan failure: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking recorded scan failure: %w", err)
	}
	return inserted > 0, nil
}

// OpenScanAlerts returns failures without a matching acknowledgement event.
func (s *Store) OpenScanAlerts(ctx context.Context, limit int) ([]ScanAlert, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT failed.id, failed.customer_id, customer.name, customer.cid,
		       failed.resource_name, failed.detail, failed.created_at
		FROM audit_events failed
		JOIN customers customer ON customer.id = failed.customer_id
		WHERE failed.action = ? AND failed.resource_kind = 'scan'
		  AND customer.deleted_at IS NULL
		  AND NOT EXISTS (
			SELECT 1 FROM audit_events acknowledged
			WHERE acknowledged.customer_id = failed.customer_id
			  AND acknowledged.action = ?
			  AND acknowledged.resource_kind = 'scan'
			  AND acknowledged.resource_name = failed.resource_name
		  )
		ORDER BY failed.id DESC LIMIT ?`,
		scanFailedAction,
		scanAcknowledgedAction,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying scan alerts: %w", err)
	}
	alerts := make([]ScanAlert, 0)
	for rows.Next() {
		var alert ScanAlert
		var detail, detectedAt string
		if err := rows.Scan(
			&alert.ID,
			&alert.CustomerID,
			&alert.CustomerName,
			&alert.CID,
			&alert.ReportID,
			&detail,
			&detectedAt,
		); err != nil {
			return nil, closeRows(rows, "scan alerts query", fmt.Errorf("scanning scan alert: %w", err))
		}
		var decoded scanAlertDetail
		if err := json.Unmarshal([]byte(detail), &decoded); err != nil {
			return nil, closeRows(rows, "scan alerts query", fmt.Errorf("decoding scan alert: %w", err))
		}
		alert.TaskID = decoded.TaskID
		alert.TaskName = decoded.TaskName
		alert.Status = decoded.Status
		alert.Reason = decoded.Reason
		alert.DetectedAt, err = parseTime(detectedAt)
		if err != nil {
			return nil, closeRows(rows, "scan alerts query", err)
		}
		alerts = append(alerts, alert)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "scan alerts query", fmt.Errorf("iterating scan alerts: %w", err))
	}
	if err := closeRows(rows, "scan alerts query", nil); err != nil {
		return nil, err
	}
	return alerts, nil
}

// AcknowledgeScanAlert appends an acknowledgement while preserving the
// original failure event.
func (s *Store) AcknowledgeScanAlert(ctx context.Context, alertID int64) (returnErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning scan alert acknowledgement: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			returnErr = errors.Join(returnErr, rollbackErr)
		}
	}()

	var customerID, reportID string
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(customer_id, ''), resource_name
		FROM audit_events
		WHERE id = ? AND action = ? AND resource_kind = 'scan'`,
		alertID,
		scanFailedAction,
	).Scan(&customerID, &reportID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("querying scan alert acknowledgement: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			customer_id, action, resource_kind, resource_name, detail, created_at
		)
		SELECT ?, ?, 'scan', ?, 'admin acknowledged failed scan', ?
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_events
			WHERE customer_id = ? AND action = ? AND resource_kind = 'scan'
			  AND resource_name = ?
		)`,
		customerID,
		scanAcknowledgedAction,
		reportID,
		nowText(),
		customerID,
		scanAcknowledgedAction,
		reportID,
	); err != nil {
		return fmt.Errorf("acknowledging scan alert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing scan alert acknowledgement: %w", err)
	}
	return nil
}
