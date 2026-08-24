package store

import (
	"context"
	"fmt"

	"openvasconf/internal/updater"
)

func (s *Store) bootstrapUpdatePolicy(ctx context.Context, timezone string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO update_settings(singleton, timezone, updated_at)
		VALUES(1, ?, ?)
		ON CONFLICT(singleton) DO NOTHING`, timezone, nowText())
	if err != nil {
		return fmt.Errorf("bootstrapping update policy: %w", err)
	}
	return nil
}

func (s *Store) UpdatePolicy(ctx context.Context) (updater.Policy, error) {
	var policy updater.Policy
	var feedEnabled, stackEnabled int
	err := s.db.QueryRowContext(ctx, `
		SELECT feed_enabled, feed_minute, stack_enabled, stack_weekday,
		       stack_start_minute, stack_window_minutes, timezone,
		       backup_retention, verification_timeout_minutes
		FROM update_settings WHERE singleton = 1`).Scan(
		&feedEnabled,
		&policy.FeedMinute,
		&stackEnabled,
		&policy.StackWeekday,
		&policy.StackStartMinute,
		&policy.StackWindowMinutes,
		&policy.Timezone,
		&policy.BackupRetention,
		&policy.VerificationTimeoutMinute,
	)
	if err != nil {
		return updater.Policy{}, fmt.Errorf("querying update policy: %w", err)
	}
	policy.FeedEnabled = feedEnabled != 0
	policy.StackEnabled = stackEnabled != 0
	if err := policy.Validate(); err != nil {
		return updater.Policy{}, fmt.Errorf("validating stored update policy: %w", err)
	}
	return policy, nil
}

func (s *Store) SaveUpdatePolicy(ctx context.Context, policy updater.Policy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("saving update policy: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE update_settings SET
			feed_enabled = ?, feed_minute = ?, stack_enabled = ?, stack_weekday = ?,
			stack_start_minute = ?, stack_window_minutes = ?, timezone = ?,
			backup_retention = ?, verification_timeout_minutes = ?, updated_at = ?
		WHERE singleton = 1`,
		boolInteger(policy.FeedEnabled),
		policy.FeedMinute,
		boolInteger(policy.StackEnabled),
		policy.StackWeekday,
		policy.StackStartMinute,
		policy.StackWindowMinutes,
		policy.Timezone,
		policy.BackupRetention,
		policy.VerificationTimeoutMinute,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("updating update policy: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking update policy write: %w", err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}
