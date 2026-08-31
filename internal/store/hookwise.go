package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// HookwiseEvent is one durable, ordered webhook transition ready for delivery.
type HookwiseEvent struct {
	ID          int64
	CustomerID  string
	TaskID      string
	Fingerprint string
	Generation  int
	EventType   string
	Payload     []byte
	Attempts    int
}

// HookwiseStats summarizes durable delivery health without exposing payloads.
type HookwiseStats struct {
	Pending       int
	Failed        int
	LastDelivered *time.Time
}

type ticketCandidate struct {
	CustomerID              string
	CustomerName            string
	ConnectWiseCustomerName string
	TaskID                  string
	TaskName                string
	Fingerprint             string
	Title                   string
	Host                    string
	Port                    string
	Severity                float64
	CVEs                    string
	Remediation             string
	SnapshotID              int64
	Present                 bool
	Disposition             string
	RemediationState        string
	Justification           string
	DesiredOpen             bool
	Generation              int
}

func connectWisePriority(severity float64) string {
	if severity >= 8.5 {
		return "P1-Critical"
	}
	return "P2-High"
}

// ReconcileHookwiseOutbox computes desired ticket transitions from current
// task-scoped finding state. Unique event keys make repeated reconciliation
// safe.
func (s *Store) ReconcileHookwiseOutbox(ctx context.Context) error {
	settings, err := s.Settings(ctx)
	if err != nil {
		return err
	}
	if !settings.Hookwise.Enabled {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning hookwise reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT s.customer_id, c.name, c.connectwise_customer_name,
		       s.task_id, r.task_name,
		       s.fingerprint, f.title, f.host, f.port, s.severity, f.cves,
		       f.remediation, s.last_snapshot_id, s.present, s.disposition,
		       s.remediation_state, s.justification,
		       s.ticket_desired_open, s.ticket_generation
		FROM finding_states s
		JOIN customers c ON c.id = s.customer_id
		JOIN report_snapshots r ON r.id = s.last_snapshot_id
		JOIN finding_snapshots f
		  ON f.snapshot_id = s.last_snapshot_id AND f.fingerprint = s.fingerprint
		WHERE c.deleted_at IS NULL`)
	if err != nil {
		return fmt.Errorf("querying hookwise candidates: %w", err)
	}
	candidates := make([]ticketCandidate, 0)
	for rows.Next() {
		var value ticketCandidate
		if err := rows.Scan(
			&value.CustomerID, &value.CustomerName,
			&value.ConnectWiseCustomerName, &value.TaskID,
			&value.TaskName, &value.Fingerprint, &value.Title, &value.Host,
			&value.Port, &value.Severity, &value.CVEs, &value.Remediation,
			&value.SnapshotID, &value.Present, &value.Disposition,
			&value.RemediationState, &value.Justification,
			&value.DesiredOpen, &value.Generation,
		); err != nil {
			return closeRows(rows, "hookwise candidates query", fmt.Errorf("scanning hookwise candidate: %w", err))
		}
		candidates = append(candidates, value)
	}
	if err := rows.Err(); err != nil {
		return closeRows(rows, "hookwise candidates query", fmt.Errorf("iterating hookwise candidates: %w", err))
	}
	if err := closeRows(rows, "hookwise candidates query", nil); err != nil {
		return err
	}

	for _, value := range candidates {
		eligible := value.Present && value.Severity >= 7.0 &&
			value.Disposition == DispositionActive &&
			value.RemediationState != RemediationResolved &&
			value.RemediationState != RemediationWontFix
		switch {
		case eligible && value.ConnectWiseCustomerName == "":
			if _, err := tx.ExecContext(ctx, `
				UPDATE finding_states SET ticket_state = 'blocked', updated_at = ?
				WHERE customer_id = ? AND task_id = ? AND fingerprint = ?
				  AND ticket_desired_open = 0`,
				nowText(), value.CustomerID, value.TaskID, value.Fingerprint,
			); err != nil {
				return fmt.Errorf("marking hookwise route blocked: %w", err)
			}
		case eligible && !value.DesiredOpen:
			if err := enqueueHookwiseTx(ctx, tx, value, "open", value.Generation+1); err != nil {
				return err
			}
		case !eligible && value.DesiredOpen:
			if err := enqueueHookwiseTx(ctx, tx, value, "closed", value.Generation); err != nil {
				return err
			}
		case !eligible && !value.DesiredOpen:
			if _, err := tx.ExecContext(ctx, `
				UPDATE finding_states SET ticket_state = 'none', updated_at = ?
				WHERE customer_id = ? AND task_id = ? AND fingerprint = ?
				  AND ticket_state = 'blocked'`,
				nowText(), value.CustomerID, value.TaskID, value.Fingerprint,
			); err != nil {
				return fmt.Errorf("clearing obsolete hookwise route block: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing hookwise reconciliation: %w", err)
	}
	return nil
}

func enqueueHookwiseTx(
	ctx context.Context,
	tx *sql.Tx,
	value ticketCandidate,
	eventType string,
	generation int,
) error {
	findingKey := value.CustomerID + ":" + value.TaskID + ":" + value.Fingerprint
	shortKey := value.Fingerprint
	if len(shortKey) > 12 {
		shortKey = shortKey[:12]
	}
	// Hookwise deduplicates by summary, so it must use only fingerprint-stable
	// fields. The mutable NVT title remains available in the payload/body.
	summary := fmt.Sprintf("[OpenVAS] Finding %s on %s:%s", shortKey, value.Host, value.Port)
	description := fmt.Sprintf(
		"%s\n\nCustomer: %s\nTask: %s\nAsset: %s:%s\nSeverity: %.1f\n\nRemediation:\n%s",
		value.Title, value.CustomerName, value.TaskName, value.Host, value.Port,
		value.Severity, value.Remediation,
	)
	payload, err := json.Marshal(map[string]any{
		"event_id":                  fmt.Sprintf("%s:%d:%s", findingKey, generation, eventType),
		"state":                     eventType,
		"connectwise_customer_name": value.ConnectWiseCustomerName,
		"finding_key":               findingKey,
		"customer":                  value.CustomerName,
		"customer_id":               value.CustomerID,
		"task":                      value.TaskName,
		"task_id":                   value.TaskID,
		"fingerprint":               value.Fingerprint,
		"summary":                   summary,
		"description":               description,
		"title":                     value.Title,
		"host":                      value.Host,
		"port":                      value.Port,
		"severity":                  connectWisePriority(value.Severity),
		"severitysource":            value.Severity,
		"cves":                      splitCVEs(value.CVEs),
		"remediation":               value.Remediation,
		"resolution":                value.Justification,
		"remediation_state":         value.RemediationState,
		"report_path":               fmt.Sprintf("/reports/%d", value.SnapshotID),
	})
	if err != nil {
		return fmt.Errorf("encoding hookwise event: %w", err)
	}
	eventKey := fmt.Sprintf("%s:%d:%s", findingKey, generation, eventType)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO hookwise_outbox(
			event_key, customer_id, task_id, fingerprint, generation,
			event_type, payload, next_attempt_at, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(event_key) DO NOTHING`,
		eventKey, value.CustomerID, value.TaskID, value.Fingerprint, generation,
		eventType, string(payload), nowText(), nowText(),
	); err != nil {
		return fmt.Errorf("enqueuing hookwise event: %w", err)
	}
	desiredOpen := eventType == "open"
	ticketState := "queued_close"
	if desiredOpen {
		ticketState = "queued_open"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_states SET ticket_desired_open = ?, ticket_generation = ?,
		       ticket_state = ?, updated_at = ?
		WHERE customer_id = ? AND task_id = ? AND fingerprint = ?`,
		desiredOpen, generation, ticketState, nowText(),
		value.CustomerID, value.TaskID, value.Fingerprint,
	); err != nil {
		return fmt.Errorf("updating queued hookwise state: %w", err)
	}
	return nil
}

func (s *Store) PendingHookwiseEvents(
	ctx context.Context,
	limit int,
) ([]HookwiseEvent, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, customer_id, task_id, fingerprint, generation,
		       event_type, payload, attempts
		FROM hookwise_outbox
		WHERE state = 'pending' AND next_attempt_at <= ?
		ORDER BY id LIMIT ?`, nowText(), limit)
	if err != nil {
		return nil, fmt.Errorf("querying pending hookwise events: %w", err)
	}
	result := make([]HookwiseEvent, 0)
	for rows.Next() {
		var value HookwiseEvent
		if err := rows.Scan(
			&value.ID, &value.CustomerID, &value.TaskID, &value.Fingerprint,
			&value.Generation, &value.EventType, &value.Payload, &value.Attempts,
		); err != nil {
			return nil, closeRows(rows, "pending hookwise events query", fmt.Errorf("scanning hookwise event: %w", err))
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "pending hookwise events query", fmt.Errorf("iterating hookwise events: %w", err))
	}
	if err := closeRows(rows, "pending hookwise events query", nil); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) MarkHookwiseDelivered(ctx context.Context, event HookwiseEvent, status int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning hookwise delivery update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE hookwise_outbox SET state = 'delivered', attempts = attempts + 1,
		       last_status = ?, last_diagnostic = '', delivered_at = ? WHERE id = ?`,
		status, nowText(), event.ID,
	); err != nil {
		return fmt.Errorf("marking hookwise event delivered: %w", err)
	}
	ticketState := "closed"
	if event.EventType == "open" {
		ticketState = "open"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_states SET ticket_state = ?, updated_at = ?
		WHERE customer_id = ? AND task_id = ? AND fingerprint = ?
		  AND ticket_generation = ?`,
		ticketState, nowText(), event.CustomerID, event.TaskID,
		event.Fingerprint, event.Generation,
	); err != nil {
		return fmt.Errorf("updating delivered finding ticket state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing hookwise delivery update: %w", err)
	}
	return nil
}

func (s *Store) MarkHookwiseFailed(
	ctx context.Context,
	event HookwiseEvent,
	status int,
	diagnostic string,
) error {
	attempts := event.Attempts + 1
	shift := min(attempts-1, 8)
	delay := time.Minute * time.Duration(1<<shift)
	diagnostic = strings.Join(strings.Fields(diagnostic), " ")
	if len(diagnostic) > 500 {
		diagnostic = diagnostic[:500]
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning hookwise failure update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE hookwise_outbox SET attempts = ?, next_attempt_at = ?,
		       last_status = ?, last_diagnostic = ? WHERE id = ?`,
		attempts, time.Now().UTC().Add(delay).Format(fixedTimeLayout),
		status, diagnostic, event.ID,
	); err != nil {
		return fmt.Errorf("recording hookwise delivery failure: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_states SET ticket_state = 'failed', updated_at = ?
		WHERE customer_id = ? AND task_id = ? AND fingerprint = ?
		  AND ticket_generation = ?`,
		nowText(), event.CustomerID, event.TaskID, event.Fingerprint, event.Generation,
	); err != nil {
		return fmt.Errorf("updating failed finding ticket state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing hookwise failure update: %w", err)
	}
	return nil
}

func (s *Store) RetryHookwiseEvents(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE hookwise_outbox SET next_attempt_at = ?, last_diagnostic = ''
		WHERE state = 'pending'`, nowText()); err != nil {
		return fmt.Errorf("rearming hookwise events: %w", err)
	}
	return nil
}

// RetryHookwiseFinding makes the failed event for one finding immediately
// eligible without creating a second ticket lifecycle event.
func (s *Store) RetryHookwiseFinding(
	ctx context.Context,
	customerID,
	taskID,
	fingerprint string,
) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE hookwise_outbox SET next_attempt_at = ?, last_diagnostic = ''
		WHERE state = 'pending' AND attempts > 0
		  AND customer_id = ? AND task_id = ? AND fingerprint = ?
		  AND EXISTS (
			SELECT 1 FROM finding_states
			WHERE customer_id = ? AND task_id = ? AND fingerprint = ?
			  AND ticket_state = 'failed'
			  AND ticket_generation = hookwise_outbox.generation
			  AND hookwise_outbox.event_type = CASE
				WHEN ticket_desired_open = 1 THEN 'open' ELSE 'closed'
			  END
		  )`,
		nowText(), customerID, taskID, fingerprint,
		customerID, taskID, fingerprint,
	)
	if err != nil {
		return fmt.Errorf("rearming hookwise finding event: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rearmed hookwise finding event: %w", err)
	}
	if rows < 1 {
		return ErrNotFound
	}
	return nil
}

// RecreateHookwiseFinding queues a fresh open event only when the latest
// generation was delivered and the finding is still eligible for a ticket.
func (s *Store) RecreateHookwiseFinding(
	ctx context.Context,
	customerID,
	taskID,
	fingerprint string,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning hookwise recreation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var value ticketCandidate
	err = tx.QueryRowContext(ctx, `
		SELECT s.customer_id, c.name, c.connectwise_customer_name,
		       s.task_id, r.task_name,
		       s.fingerprint, f.title, f.host, f.port, s.severity, f.cves,
		       f.remediation, s.last_snapshot_id, s.present, s.disposition,
		       s.remediation_state, s.justification,
		       s.ticket_desired_open, s.ticket_generation
		FROM finding_states s
		JOIN customers c ON c.id = s.customer_id
		JOIN report_snapshots r ON r.id = s.last_snapshot_id
		JOIN finding_snapshots f
		  ON f.snapshot_id = s.last_snapshot_id AND f.fingerprint = s.fingerprint
		WHERE s.customer_id = ? AND s.task_id = ? AND s.fingerprint = ?
		  AND c.deleted_at IS NULL AND c.connectwise_customer_name <> ''
		  AND s.present = 1 AND s.severity >= 7.0
		  AND s.disposition = ?
		  AND s.remediation_state NOT IN (?, ?)
		  AND s.ticket_desired_open = 1 AND s.ticket_state = 'open'`,
		customerID,
		taskID,
		fingerprint,
		DispositionActive,
		RemediationResolved,
		RemediationWontFix,
	).Scan(
		&value.CustomerID,
		&value.CustomerName,
		&value.ConnectWiseCustomerName,
		&value.TaskID,
		&value.TaskName,
		&value.Fingerprint,
		&value.Title,
		&value.Host,
		&value.Port,
		&value.Severity,
		&value.CVEs,
		&value.Remediation,
		&value.SnapshotID,
		&value.Present,
		&value.Disposition,
		&value.RemediationState,
		&value.Justification,
		&value.DesiredOpen,
		&value.Generation,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("loading hookwise finding for recreation: %w", err)
	}
	if err := enqueueHookwiseTx(ctx, tx, value, "open", value.Generation+1); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing hookwise recreation: %w", err)
	}
	return nil
}

func (s *Store) HookwiseStats(ctx context.Context) (HookwiseStats, error) {
	var result HookwiseStats
	var lastDelivered string
	err := s.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN state = 'pending' AND attempts > 0 THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(delivered_at), '')
		FROM hookwise_outbox`).Scan(&result.Pending, &result.Failed, &lastDelivered)
	if err != nil {
		return HookwiseStats{}, fmt.Errorf("querying hookwise statistics: %w", err)
	}
	if lastDelivered != "" {
		parsed, err := parseTime(lastDelivered)
		if err != nil {
			return HookwiseStats{}, err
		}
		result.LastDelivered = &parsed
	}
	return result, nil
}
