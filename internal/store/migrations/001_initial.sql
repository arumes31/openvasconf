CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    installation_id TEXT NOT NULL UNIQUE,
    default_scanner_id TEXT NOT NULL DEFAULT '',
    default_scanner_name TEXT NOT NULL DEFAULT '',
    default_scan_config_id TEXT NOT NULL DEFAULT '',
    default_scan_config_name TEXT NOT NULL DEFAULT '',
    default_port_list_id TEXT NOT NULL DEFAULT '',
    default_port_list_name TEXT NOT NULL DEFAULT '',
    timezone TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    safe_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    schedule_weekday INTEGER NOT NULL CHECK (schedule_weekday BETWEEN 1 AND 4),
    schedule_minute INTEGER NOT NULL CHECK (schedule_minute BETWEEN 420 AND 900),
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
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS customers_deleted_at_idx ON customers(deleted_at);

CREATE TABLE IF NOT EXISTS networks (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    input TEXT NOT NULL,
    prefix TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('PrivateIP', 'WAN')),
    created_at TEXT NOT NULL,
    UNIQUE(customer_id, prefix)
);

CREATE INDEX IF NOT EXISTS networks_customer_id_idx ON networks(customer_id);

CREATE TABLE IF NOT EXISTS managed_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('schedule', 'target', 'task')),
    class TEXT NOT NULL DEFAULT '',
    sequence INTEGER NOT NULL DEFAULT 0,
    gvm_id TEXT NOT NULL DEFAULT '',
    desired_hash TEXT NOT NULL DEFAULT '',
    ownership_marker TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    UNIQUE(customer_id, kind, class, sequence)
);

CREATE INDEX IF NOT EXISTS managed_resources_customer_id_idx
    ON managed_resources(customer_id);

CREATE TABLE IF NOT EXISTS reconcile_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL DEFAULT '',
    resource_name TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_created_at_idx ON audit_events(created_at DESC);

