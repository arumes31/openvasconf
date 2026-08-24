-- openvasconf: foreign_keys_off
-- The migration runner disables enforcement before opening the transaction,
-- validates the rebuilt relationships, and restores the prior setting.
CREATE TABLE customers_new (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    safe_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    schedule_weekday INTEGER NOT NULL CHECK (schedule_weekday BETWEEN 1 AND 7),
    schedule_minute INTEGER NOT NULL CHECK (schedule_minute BETWEEN 0 AND 1439),
    timezone TEXT NOT NULL,
    scanner_id TEXT NOT NULL DEFAULT '',
    scanner_name TEXT NOT NULL DEFAULT '',
    scan_config_id TEXT NOT NULL DEFAULT '',
    scan_config_name TEXT NOT NULL DEFAULT '',
    port_list_id TEXT NOT NULL DEFAULT '',
    port_list_name TEXT NOT NULL DEFAULT '',
    desired_revision INTEGER NOT NULL DEFAULT 1,
    reconciliation_status TEXT NOT NULL DEFAULT 'pending',
    last_reconciliation_error TEXT NOT NULL DEFAULT '',
    last_successful_reconcile_at TEXT,
    reconciliation_phase TEXT NOT NULL DEFAULT '',
    reconciliation_current_operation TEXT NOT NULL DEFAULT '',
    reconciliation_completed_operations INTEGER NOT NULL DEFAULT 0,
    reconciliation_total_operations INTEGER NOT NULL DEFAULT 0,
    reconciliation_attempt INTEGER NOT NULL DEFAULT 0,
    reconciliation_max_attempts INTEGER NOT NULL DEFAULT 3,
    reconciliation_next_retry_at TEXT,
    reconciliation_technical_error TEXT NOT NULL DEFAULT '',
    reconciliation_started_at TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO customers_new(
    id, name, safe_name, description, tags,
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
) SELECT
    id, name, safe_name, description, tags,
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
FROM customers;

DROP TABLE customers;
ALTER TABLE customers_new RENAME TO customers;

CREATE INDEX customers_deleted_at_idx ON customers(deleted_at);
CREATE INDEX customers_reconciliation_status_idx
    ON customers(reconciliation_status, name COLLATE NOCASE);

CREATE TABLE settings_new (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    installation_id TEXT NOT NULL UNIQUE,
    default_scanner_id TEXT NOT NULL DEFAULT '',
    default_scanner_name TEXT NOT NULL DEFAULT '',
    default_scan_config_id TEXT NOT NULL DEFAULT '',
    default_scan_config_name TEXT NOT NULL DEFAULT '',
    default_port_list_id TEXT NOT NULL DEFAULT '',
    default_port_list_name TEXT NOT NULL DEFAULT '',
    timezone TEXT NOT NULL,
    schedule_weekdays TEXT NOT NULL DEFAULT '1,2,3,4',
    schedule_start_minute INTEGER NOT NULL DEFAULT 420
        CHECK (schedule_start_minute BETWEEN 0 AND 1439),
    schedule_end_minute INTEGER NOT NULL DEFAULT 900
        CHECK (schedule_end_minute BETWEEN 0 AND 1439),
    updated_at TEXT NOT NULL
);

INSERT INTO settings_new(
    singleton, installation_id,
    default_scanner_id, default_scanner_name,
    default_scan_config_id, default_scan_config_name,
    default_port_list_id, default_port_list_name,
    timezone, schedule_weekdays, schedule_start_minute,
    schedule_end_minute, updated_at
) SELECT
    singleton, installation_id,
    default_scanner_id, default_scanner_name,
    default_scan_config_id, default_scan_config_name,
    default_port_list_id, default_port_list_name,
    timezone, schedule_weekdays, schedule_start_minute,
    schedule_end_minute, updated_at
FROM settings;

DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;
