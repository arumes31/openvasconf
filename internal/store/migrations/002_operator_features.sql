ALTER TABLE settings ADD COLUMN schedule_weekdays TEXT NOT NULL DEFAULT '1,2,3,4';
ALTER TABLE settings ADD COLUMN schedule_start_minute INTEGER NOT NULL DEFAULT 420
    CHECK (schedule_start_minute BETWEEN 420 AND 900);
ALTER TABLE settings ADD COLUMN schedule_end_minute INTEGER NOT NULL DEFAULT 900
    CHECK (schedule_end_minute BETWEEN 420 AND 900);

ALTER TABLE customers ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE customers ADD COLUMN tags TEXT NOT NULL DEFAULT '';
ALTER TABLE customers ADD COLUMN last_successful_reconcile_at TEXT;
ALTER TABLE customers ADD COLUMN reconciliation_phase TEXT NOT NULL DEFAULT '';
ALTER TABLE customers ADD COLUMN reconciliation_current_operation TEXT NOT NULL DEFAULT '';
ALTER TABLE customers ADD COLUMN reconciliation_completed_operations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE customers ADD COLUMN reconciliation_total_operations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE customers ADD COLUMN reconciliation_attempt INTEGER NOT NULL DEFAULT 0;
ALTER TABLE customers ADD COLUMN reconciliation_max_attempts INTEGER NOT NULL DEFAULT 3;
ALTER TABLE customers ADD COLUMN reconciliation_next_retry_at TEXT;
ALTER TABLE customers ADD COLUMN reconciliation_technical_error TEXT NOT NULL DEFAULT '';
ALTER TABLE customers ADD COLUMN reconciliation_started_at TEXT;

ALTER TABLE reconcile_runs ADD COLUMN phase TEXT NOT NULL DEFAULT '';
ALTER TABLE reconcile_runs ADD COLUMN safe_error TEXT NOT NULL DEFAULT '';
ALTER TABLE reconcile_runs ADD COLUMN technical_error TEXT NOT NULL DEFAULT '';
ALTER TABLE reconcile_runs ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1;
ALTER TABLE reconcile_runs ADD COLUMN completed_operations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reconcile_runs ADD COLUMN total_operations INTEGER NOT NULL DEFAULT 0;

CREATE TABLE reconcile_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES reconcile_runs(id) ON DELETE CASCADE,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL DEFAULT '',
    resource_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX reconcile_runs_customer_started_idx
    ON reconcile_runs(customer_id, started_at DESC);
CREATE INDEX reconcile_operations_run_idx
    ON reconcile_operations(run_id, id);
CREATE INDEX customers_reconciliation_status_idx
    ON customers(reconciliation_status, name COLLATE NOCASE);
