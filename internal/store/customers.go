package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"openvasconf/internal/customer"
)

func (s *Store) CreateCustomer(ctx context.Context, value customer.Customer) error {
	if err := customer.ValidateCID(value.CID); err != nil {
		return fmt.Errorf("creating customer: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning customer transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := nowText()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO customers(
			id, name, safe_name, cid, description, tags,
			schedule_weekday, schedule_minute, timezone,
			scanner_id, scanner_name, scan_config_id, scan_config_name,
			port_list_id, port_list_name, desired_revision, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		value.ID,
		value.Name,
		value.SafeName,
		value.CID,
		value.Description,
		strings.Join(value.Tags, ","),
		value.ScheduleWeekday,
		value.ScheduleMinute,
		value.Timezone,
		value.ScannerID,
		value.ScannerName,
		value.ScanConfigID,
		value.ScanConfigName,
		value.PortListID,
		value.PortListName,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("inserting customer: %w", err)
	}
	if err := insertNetworks(ctx, tx, value.Networks, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing customer: %w", err)
	}
	return nil
}

func (s *Store) UpdateCustomer(ctx context.Context, value customer.Customer) error {
	if err := customer.ValidateCID(value.CID); err != nil {
		return fmt.Errorf("updating customer: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning customer update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `
		UPDATE customers SET
			name = ?, safe_name = ?, cid = ?, description = ?, tags = ?,
			schedule_weekday = ?, schedule_minute = ?, timezone = ?,
			scanner_id = ?, scanner_name = ?, scan_config_id = ?, scan_config_name = ?,
			port_list_id = ?, port_list_name = ?, desired_revision = desired_revision + 1,
			reconciliation_status = 'pending', last_reconciliation_error = '', updated_at = ?
		WHERE id = ? AND deleted_at IS NULL`,
		value.Name,
		value.SafeName,
		value.CID,
		value.Description,
		strings.Join(value.Tags, ","),
		value.ScheduleWeekday,
		value.ScheduleMinute,
		value.Timezone,
		value.ScannerID,
		value.ScannerName,
		value.ScanConfigID,
		value.ScanConfigName,
		value.PortListID,
		value.PortListName,
		nowText(),
		value.ID,
	)
	if err != nil {
		return fmt.Errorf("updating customer: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking customer update: %w", err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM networks WHERE customer_id = ?", value.ID); err != nil {
		return fmt.Errorf("replacing customer networks: %w", err)
	}
	if err := insertNetworks(ctx, tx, value.Networks, nowText()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing customer update: %w", err)
	}
	return nil
}

func insertNetworks(
	ctx context.Context,
	tx *sql.Tx,
	networks []customer.Network,
	createdAt string,
) error {
	for _, network := range networks {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO networks(id, customer_id, input, prefix, class, created_at)
			VALUES(?, ?, ?, ?, ?, ?)`,
			network.ID,
			network.CustomerID,
			network.Input,
			network.Prefix,
			network.Class,
			createdAt,
		)
		if err != nil {
			return fmt.Errorf("inserting network %q: %w", network.Prefix, err)
		}
	}
	return nil
}

func (s *Store) Customer(ctx context.Context, customerID string) (customer.Customer, error) {
	value, err := scanCustomer(s.db.QueryRowContext(ctx, customerSelect+" WHERE id = ?", customerID))
	if errors.Is(err, sql.ErrNoRows) {
		return customer.Customer{}, ErrNotFound
	}
	if err != nil {
		return customer.Customer{}, fmt.Errorf("querying customer: %w", err)
	}
	value.Networks, err = s.networks(ctx, customerID)
	if err != nil {
		return customer.Customer{}, err
	}
	return value, nil
}

func (s *Store) Customers(ctx context.Context, includeDeleted bool) ([]customer.Customer, error) {
	return s.ListCustomers(ctx, CustomerQuery{IncludeDeleted: includeDeleted})
}

func (s *Store) ListCustomers(
	ctx context.Context,
	filter CustomerQuery,
) ([]customer.Customer, error) {
	query := customerSelect + " WHERE 1 = 1"
	args := make([]any, 0, 4)
	if !filter.IncludeDeleted {
		query += " AND deleted_at IS NULL"
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		query += " AND (name LIKE ? ESCAPE '\\' OR cid LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')"
		pattern := "%" + escapeLike(search) + "%"
		args = append(args, pattern, pattern, pattern, pattern)
	}
	if filter.Status != "" {
		switch filter.Status {
		case "pending", "syncing", "applied", "error", "deleted":
			query += " AND reconciliation_status = ?"
			args = append(args, filter.Status)
		default:
			return nil, fmt.Errorf("querying customers: unsupported status %q", filter.Status)
		}
	}
	sortColumns := map[string]string{
		"name":       "name COLLATE NOCASE",
		"status":     "reconciliation_status",
		"next_scan":  "schedule_weekday, schedule_minute",
		"updated_at": "updated_at",
	}
	sortColumn := sortColumns[filter.Sort]
	if sortColumn == "" {
		sortColumn = sortColumns["name"]
	}
	query += " ORDER BY " + sortColumn
	if filter.Descending {
		query += " DESC"
	}
	query += ", name COLLATE NOCASE"
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	query += " LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying customers: %w", err)
	}
	result := make([]customer.Customer, 0)
	for rows.Next() {
		value, err := scanCustomer(rows)
		if err != nil {
			return nil, closeRows(rows, "customer query", fmt.Errorf("scanning customer: %w", err))
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "customer query", fmt.Errorf("iterating customers: %w", err))
	}
	if err := closeRows(rows, "customer query", nil); err != nil {
		return nil, err
	}
	for index := range result {
		result[index].Networks, err = s.networks(ctx, result[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "%", "\\%")
	return strings.ReplaceAll(value, "_", "\\_")
}

const customerSelect = `
	SELECT id, name, safe_name, cid, description, tags,
	       schedule_weekday, schedule_minute, timezone,
	       scanner_id, scanner_name, scan_config_id, scan_config_name,
	       port_list_id, port_list_name, desired_revision,
	       reconciliation_status, last_reconciliation_error,
	       last_successful_reconcile_at,
	       reconciliation_phase, reconciliation_current_operation,
	       reconciliation_completed_operations, reconciliation_total_operations,
	       reconciliation_attempt, reconciliation_max_attempts,
	       reconciliation_next_retry_at, reconciliation_technical_error,
	       reconciliation_started_at,
	       deleted_at, created_at, updated_at
	FROM customers`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCustomer(row rowScanner) (customer.Customer, error) {
	var value customer.Customer
	var tags string
	var deletedAt sql.NullString
	var lastSuccess sql.NullString
	var nextRetry sql.NullString
	var reconcileStarted sql.NullString
	var createdAt string
	var updatedAt string
	err := row.Scan(
		&value.ID,
		&value.Name,
		&value.SafeName,
		&value.CID,
		&value.Description,
		&tags,
		&value.ScheduleWeekday,
		&value.ScheduleMinute,
		&value.Timezone,
		&value.ScannerID,
		&value.ScannerName,
		&value.ScanConfigID,
		&value.ScanConfigName,
		&value.PortListID,
		&value.PortListName,
		&value.DesiredRevision,
		&value.ReconciliationStatus,
		&value.LastReconciliationError,
		&lastSuccess,
		&value.Reconciliation.Phase,
		&value.Reconciliation.CurrentOperation,
		&value.Reconciliation.CompletedOperations,
		&value.Reconciliation.TotalOperations,
		&value.Reconciliation.Attempt,
		&value.Reconciliation.MaxAttempts,
		&nextRetry,
		&value.Reconciliation.TechnicalError,
		&reconcileStarted,
		&deletedAt,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return customer.Customer{}, err
	}
	value.Tags = splitStoredTags(tags)
	value.LastSuccessfulReconcile, err = parseOptionalTime(lastSuccess)
	if err != nil {
		return customer.Customer{}, err
	}
	value.Reconciliation.NextRetryAt, err = parseOptionalTime(nextRetry)
	if err != nil {
		return customer.Customer{}, err
	}
	value.Reconciliation.StartedAt, err = parseOptionalTime(reconcileStarted)
	if err != nil {
		return customer.Customer{}, err
	}
	value.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return customer.Customer{}, err
	}
	value.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return customer.Customer{}, err
	}
	if deletedAt.Valid {
		parsed, err := parseTime(deletedAt.String)
		if err != nil {
			return customer.Customer{}, err
		}
		value.DeletedAt = &parsed
	}
	value.Networks = []customer.Network{}
	return value, nil
}

func parseOptionalTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func splitStoredTags(value string) []string {
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}

func (s *Store) networks(ctx context.Context, customerID string) ([]customer.Network, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, customer_id, input, prefix, class, created_at
		FROM networks WHERE customer_id = ? ORDER BY prefix`,
		customerID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying customer networks: %w", err)
	}
	result := make([]customer.Network, 0)
	for rows.Next() {
		var value customer.Network
		var createdAt string
		if err := rows.Scan(
			&value.ID,
			&value.CustomerID,
			&value.Input,
			&value.Prefix,
			&value.Class,
			&createdAt,
		); err != nil {
			return nil, closeRows(rows, "customer network query", fmt.Errorf("scanning customer network: %w", err))
		}
		value.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, closeRows(rows, "customer network query", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, "customer network query", fmt.Errorf("iterating customer networks: %w", err))
	}
	if err := closeRows(rows, "customer network query", nil); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) SoftDeleteCustomer(ctx context.Context, customerID string) error {
	now := nowText()
	result, err := s.db.ExecContext(ctx, `
		UPDATE customers SET deleted_at = ?, desired_revision = desired_revision + 1,
		       reconciliation_status = 'pending', updated_at = ?
		WHERE id = ? AND deleted_at IS NULL`,
		now,
		now,
		customerID,
	)
	if err != nil {
		return fmt.Errorf("soft deleting customer: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking customer deletion: %w", err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetCustomerReconciliation(
	ctx context.Context,
	customerID,
	status,
	lastError string,
) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE customers SET reconciliation_status = ?, last_reconciliation_error = ?, updated_at = ?
		WHERE id = ?`,
		status,
		lastError,
		time.Now().UTC().Format(time.RFC3339Nano),
		customerID,
	)
	if err != nil {
		return fmt.Errorf("updating reconciliation status: %w", err)
	}
	return nil
}
