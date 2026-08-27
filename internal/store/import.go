package store

import (
	"context"
	"fmt"
	"strings"

	"openvasconf/internal/customer"
)

func (s *Store) ApplyImport(
	ctx context.Context,
	settings customer.Settings,
	customers []customer.Customer,
) error {
	if err := customer.ValidateSchedulePolicy(settings.SchedulePolicy); err != nil {
		return fmt.Errorf("applying import: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning import transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE settings SET timezone = ?, schedule_weekdays = ?,
		       schedule_start_minute = ?, schedule_end_minute = ?, updated_at = ?
		WHERE singleton = 1`,
		settings.Timezone,
		customer.FormatWeekdays(settings.SchedulePolicy.Weekdays),
		settings.SchedulePolicy.StartMinute,
		settings.SchedulePolicy.EndMinute,
		nowText(),
	); err != nil {
		return fmt.Errorf("importing settings: %w", err)
	}
	for _, value := range customers {
		if err := customer.ValidateCID(value.CID); err != nil {
			return fmt.Errorf("importing customer %q: %w", value.Name, err)
		}
		now := nowText()
		result, err := tx.ExecContext(ctx, `
			UPDATE customers SET name = ?, safe_name = ?, cid = ?, description = ?, tags = ?,
			       schedule_weekday = ?, schedule_minute = ?, timezone = ?,
			       scanner_id = ?, scanner_name = ?, scan_config_id = ?, scan_config_name = ?,
			       port_list_id = ?, port_list_name = ?, desired_revision = desired_revision + 1,
			       reconciliation_status = 'pending', last_reconciliation_error = '',
			       updated_at = ?
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
			now,
			value.ID,
		)
		if err != nil {
			return fmt.Errorf("updating imported customer %q: %w", value.Name, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("checking imported customer %q: %w", value.Name, err)
		}
		if rows == 0 {
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
				return fmt.Errorf("creating imported customer %q: %w", value.Name, err)
			}
		} else if _, err := tx.ExecContext(
			ctx,
			"DELETE FROM networks WHERE customer_id = ?",
			value.ID,
		); err != nil {
			return fmt.Errorf("replacing imported customer networks: %w", err)
		}
		if err := insertNetworks(ctx, tx, value.Networks, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing import: %w", err)
	}
	return nil
}
