package store

import (
	"context"
	"fmt"
	"time"

	"openvasconf/internal/customer"
)

func (s *Store) Settings(ctx context.Context) (customer.Settings, error) {
	var settings customer.Settings
	var weekdaysText string
	var updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT installation_id,
		       default_scanner_id, default_scanner_name,
		       default_scan_config_id, default_scan_config_name,
		       default_port_list_id, default_port_list_name,
		       timezone, schedule_weekdays, schedule_start_minute,
		       schedule_end_minute,
		       sla_critical_days, sla_high_days, sla_medium_days, sla_low_days,
		       updated_at
		FROM settings WHERE singleton = 1`).Scan(
		&settings.InstallationID,
		&settings.Scanner.ID,
		&settings.Scanner.Name,
		&settings.ScanConfig.ID,
		&settings.ScanConfig.Name,
		&settings.PortList.ID,
		&settings.PortList.Name,
		&settings.Timezone,
		&weekdaysText,
		&settings.SchedulePolicy.StartMinute,
		&settings.SchedulePolicy.EndMinute,
		&settings.SLA.CriticalDays,
		&settings.SLA.HighDays,
		&settings.SLA.MediumDays,
		&settings.SLA.LowDays,
		&updatedAt,
	)
	if err != nil {
		return customer.Settings{}, fmt.Errorf("querying settings: %w", err)
	}
	settings.SchedulePolicy.Weekdays, err = customer.ParseWeekdays(weekdaysText)
	if err != nil {
		return customer.Settings{}, fmt.Errorf("parsing stored schedule weekdays: %w", err)
	}
	settings.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return customer.Settings{}, err
	}
	return settings, nil
}

func (s *Store) UpdateSettings(ctx context.Context, settings customer.Settings) error {
	if _, err := time.LoadLocation(settings.Timezone); err != nil {
		return fmt.Errorf("updating settings: invalid timezone %q: %w", settings.Timezone, err)
	}
	if err := customer.ValidateSchedulePolicy(settings.SchedulePolicy); err != nil {
		return fmt.Errorf("updating settings: %w", err)
	}
	if err := customer.ValidateSLAPolicy(settings.SLA); err != nil {
		return fmt.Errorf("updating settings: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning settings update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `
		UPDATE settings SET
			default_scanner_id = ?, default_scanner_name = ?,
			default_scan_config_id = ?, default_scan_config_name = ?,
			default_port_list_id = ?, default_port_list_name = ?,
			timezone = ?, schedule_weekdays = ?, schedule_start_minute = ?,
			schedule_end_minute = ?,
			sla_critical_days = ?, sla_high_days = ?, sla_medium_days = ?,
			sla_low_days = ?, updated_at = ?
		WHERE singleton = 1`,
		settings.Scanner.ID,
		settings.Scanner.Name,
		settings.ScanConfig.ID,
		settings.ScanConfig.Name,
		settings.PortList.ID,
		settings.PortList.Name,
		settings.Timezone,
		customer.FormatWeekdays(settings.SchedulePolicy.Weekdays),
		settings.SchedulePolicy.StartMinute,
		settings.SchedulePolicy.EndMinute,
		settings.SLA.CriticalDays,
		settings.SLA.HighDays,
		settings.SLA.MediumDays,
		settings.SLA.LowDays,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("updating settings: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking settings update: %w", err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE customers SET desired_revision = desired_revision + 1,
		       reconciliation_status = 'pending', last_reconciliation_error = '', updated_at = ?
		WHERE deleted_at IS NULL`, nowText()); err != nil {
		return fmt.Errorf("marking customers pending after settings update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing settings update: %w", err)
	}
	return nil
}
