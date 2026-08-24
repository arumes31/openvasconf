package store

import (
	"context"
	"fmt"
)

func (s *Store) ManagedResources(ctx context.Context, customerID string) ([]ManagedResource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT customer_id, kind, class, sequence, gvm_id, desired_hash,
		       ownership_marker, state, last_error, updated_at
		FROM managed_resources WHERE customer_id = ?
		ORDER BY CASE kind WHEN 'task' THEN 1 WHEN 'target' THEN 2 ELSE 3 END,
		         class, sequence`,
		customerID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying managed resources: %w", err)
	}
	result := make([]ManagedResource, 0)
	for rows.Next() {
		var value ManagedResource
		var updatedAt string
		if err := rows.Scan(
			&value.CustomerID,
			&value.Kind,
			&value.Class,
			&value.Sequence,
			&value.GVMID,
			&value.DesiredHash,
			&value.OwnershipMarker,
			&value.State,
			&value.LastError,
			&updatedAt,
		); err != nil {
			return nil, closeRows(rows, "managed resources query", fmt.Errorf("scanning managed resource: %w", err))
		}
		value.UpdatedAt, err = parseTime(updatedAt)
		if err != nil {
			return nil, closeRows(rows, "managed resources query", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "managed resources query", fmt.Errorf("iterating managed resources: %w", err))
	}
	if err := closeRows(rows, "managed resources query", nil); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) UpsertManagedResource(ctx context.Context, resource ManagedResource) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO managed_resources(
			customer_id, kind, class, sequence, gvm_id, desired_hash,
			ownership_marker, state, last_error, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(customer_id, kind, class, sequence) DO UPDATE SET
			gvm_id = excluded.gvm_id,
			desired_hash = excluded.desired_hash,
			ownership_marker = excluded.ownership_marker,
			state = excluded.state,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at`,
		resource.CustomerID,
		resource.Kind,
		resource.Class,
		resource.Sequence,
		resource.GVMID,
		resource.DesiredHash,
		resource.OwnershipMarker,
		resource.State,
		resource.LastError,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("upserting managed resource: %w", err)
	}
	return nil
}

func (s *Store) DeleteManagedResource(
	ctx context.Context,
	customerID,
	kind,
	class string,
	sequence int,
) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM managed_resources
		WHERE customer_id = ? AND kind = ? AND class = ? AND sequence = ?`,
		customerID,
		kind,
		class,
		sequence,
	)
	if err != nil {
		return fmt.Errorf("deleting managed resource: %w", err)
	}
	return nil
}

func (s *Store) AddAuditEvent(ctx context.Context, event AuditEvent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(
			customer_id, action, resource_kind, resource_name, detail, created_at
		) VALUES(NULLIF(?, ''), ?, ?, ?, ?, ?)`,
		event.CustomerID,
		event.Action,
		event.ResourceKind,
		event.ResourceName,
		event.Detail,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("adding audit event: %w", err)
	}
	return nil
}

func (s *Store) AuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(customer_id, ''), action, resource_kind,
		       resource_name, detail, created_at
		FROM audit_events ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying audit events: %w", err)
	}
	result := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var createdAt string
		if err := rows.Scan(
			&event.ID,
			&event.CustomerID,
			&event.Action,
			&event.ResourceKind,
			&event.ResourceName,
			&event.Detail,
			&createdAt,
		); err != nil {
			return nil, closeRows(rows, "audit events query", fmt.Errorf("scanning audit event: %w", err))
		}
		event.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, closeRows(rows, "audit events query", err)
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "audit events query", fmt.Errorf("iterating audit events: %w", err))
	}
	if err := closeRows(rows, "audit events query", nil); err != nil {
		return nil, err
	}
	return result, nil
}
