package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *Store) BeginReconcileRun(ctx context.Context, customerID string) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO reconcile_runs(customer_id, started_at, status)
		VALUES(?, ?, 'running')`,
		customerID,
		nowText(),
	)
	if err != nil {
		return 0, fmt.Errorf("beginning reconcile run: %w", err)
	}
	runID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("reading reconcile run id: %w", err)
	}
	return runID, nil
}

func (s *Store) UpdateReconcileProgress(
	ctx context.Context,
	runID int64,
	customerID string,
	progress ReconcileProgress,
) error {
	var nextRetry any
	if progress.NextRetryAt != nil {
		nextRetry = progress.NextRetryAt.UTC().Format(time.RFC3339Nano)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE reconcile_runs SET phase = ?, safe_error = ?, technical_error = ?,
		       attempt = ?, completed_operations = ?, total_operations = ?
		WHERE id = ?`,
		progress.Phase,
		progress.SafeError,
		progress.TechnicalError,
		progress.Attempt,
		progress.CompletedOperations,
		progress.TotalOperations,
		runID,
	)
	if err != nil {
		return fmt.Errorf("updating reconcile run progress: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking reconcile run progress: %w", err)
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE customers SET reconciliation_phase = ?,
		       reconciliation_current_operation = ?,
		       reconciliation_completed_operations = ?,
		       reconciliation_total_operations = ?, reconciliation_attempt = ?,
		       reconciliation_max_attempts = ?, reconciliation_next_retry_at = ?,
		       reconciliation_technical_error = ?,
		       reconciliation_started_at = COALESCE(reconciliation_started_at, ?)
		WHERE id = ?`,
		progress.Phase,
		progress.CurrentOperation,
		progress.CompletedOperations,
		progress.TotalOperations,
		progress.Attempt,
		progress.MaxAttempts,
		nextRetry,
		progress.TechnicalError,
		nowText(),
		customerID,
	)
	if err != nil {
		return fmt.Errorf("updating customer reconcile progress: %w", err)
	}
	return nil
}

func (s *Store) AddReconcileOperation(
	ctx context.Context,
	operation ReconcileOperation,
) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO reconcile_operations(
			run_id, customer_id, action, resource_kind, resource_name,
			status, detail, duration_ms, created_at
		) VALUES(?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)`,
		operation.RunID,
		operation.CustomerID,
		operation.Action,
		operation.ResourceKind,
		operation.ResourceName,
		operation.Status,
		operation.Detail,
		operation.Duration.Milliseconds(),
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("adding reconcile operation: %w", err)
	}
	return nil
}

func (s *Store) FinishReconcileRun(ctx context.Context, runID int64, runError error) error {
	status := "succeeded"
	errorText := ""
	if runError != nil {
		status = "failed"
		errorText = runError.Error()
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE reconcile_runs SET finished_at = ?, status = ?, error = ? WHERE id = ?`,
		nowText(),
		status,
		errorText,
		runID,
	)
	if err != nil {
		return fmt.Errorf("finishing reconcile run: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking reconcile run finish: %w", err)
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	if runError == nil {
		_, err = s.db.ExecContext(ctx, `
			UPDATE customers SET last_successful_reconcile_at = ?,
			       reconciliation_phase = 'complete',
			       reconciliation_current_operation = '',
			       reconciliation_completed_operations = reconciliation_total_operations,
			       reconciliation_next_retry_at = NULL,
			       reconciliation_technical_error = '', reconciliation_started_at = NULL
			WHERE id = (SELECT customer_id FROM reconcile_runs WHERE id = ?)`,
			nowText(),
			runID,
		)
		if err != nil {
			return fmt.Errorf("recording successful reconcile time: %w", err)
		}
	}
	return nil
}

func (s *Store) ReconcileRuns(
	ctx context.Context,
	customerID string,
	limit int,
) ([]ReconcileRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(customer_id, ''), started_at, finished_at, status,
		       phase, safe_error, technical_error, attempt,
		       completed_operations, total_operations
		FROM reconcile_runs
		WHERE (? = '' OR customer_id = ?)
		ORDER BY id DESC LIMIT ?`,
		customerID,
		customerID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying reconcile runs: %w", err)
	}
	defer rows.Close()
	runs := make([]ReconcileRun, 0)
	for rows.Next() {
		var run ReconcileRun
		var startedAt string
		var finishedAt sql.NullString
		if err := rows.Scan(
			&run.ID,
			&run.CustomerID,
			&startedAt,
			&finishedAt,
			&run.Status,
			&run.Phase,
			&run.SafeError,
			&run.TechnicalError,
			&run.Attempt,
			&run.CompletedOperations,
			&run.TotalOperations,
		); err != nil {
			return nil, fmt.Errorf("scanning reconcile run: %w", err)
		}
		run.StartedAt, err = parseTime(startedAt)
		if err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			parsed, parseErr := parseTime(finishedAt.String)
			if parseErr != nil {
				return nil, parseErr
			}
			run.FinishedAt = &parsed
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating reconcile runs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("closing reconcile runs: %w", err)
	}
	for index := range runs {
		runs[index].Operations, err = s.reconcileOperations(ctx, runs[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return runs, nil
}

func (s *Store) reconcileOperations(
	ctx context.Context,
	runID int64,
) ([]ReconcileOperation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, run_id, COALESCE(customer_id, ''), action, resource_kind,
		       resource_name, status, detail, duration_ms, created_at
		FROM reconcile_operations WHERE run_id = ? ORDER BY id`,
		runID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying reconcile operations: %w", err)
	}
	defer rows.Close()
	operations := make([]ReconcileOperation, 0)
	for rows.Next() {
		var operation ReconcileOperation
		var durationMS int64
		var createdAt string
		if err := rows.Scan(
			&operation.ID,
			&operation.RunID,
			&operation.CustomerID,
			&operation.Action,
			&operation.ResourceKind,
			&operation.ResourceName,
			&operation.Status,
			&operation.Detail,
			&durationMS,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("scanning reconcile operation: %w", err)
		}
		operation.Duration = time.Duration(durationMS) * time.Millisecond
		operation.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating reconcile operations: %w", err)
	}
	return operations, nil
}
