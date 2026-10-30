package store

import (
	"context"
	"fmt"
)

// PruneReportSnapshots retains the three newest imported snapshots per
// customer/task. Finding detail rows expire with their report; operational
// finding state and ticket generations survive independently.
func (s *Store) PruneReportSnapshots(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		WITH ranked AS (
			SELECT id, ROW_NUMBER() OVER (
				PARTITION BY customer_id, task_id
				ORDER BY scan_end_at DESC, id DESC
			) AS position
			FROM report_snapshots
			WHERE import_state = 'imported'
			  AND customer_id IS NOT NULL AND customer_id <> '' AND task_id <> ''
		)
		DELETE FROM report_snapshots
		WHERE id IN (SELECT id FROM ranked WHERE position > 3)
		  AND NOT EXISTS (
			SELECT 1 FROM finding_states s
			WHERE s.last_snapshot_id = report_snapshots.id AND s.present = 1
		  )`)
	if err != nil {
		return fmt.Errorf("pruning report snapshots: %w", err)
	}
	return nil
}
