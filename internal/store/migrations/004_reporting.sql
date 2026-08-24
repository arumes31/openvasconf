CREATE TABLE report_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL DEFAULT '',
    task_name TEXT NOT NULL DEFAULT '',
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    scan_start_at TEXT NOT NULL DEFAULT '',
    scan_end_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    severity_max REAL NOT NULL DEFAULT 0,
    count_high INTEGER NOT NULL DEFAULT 0,
    count_medium INTEGER NOT NULL DEFAULT 0,
    count_low INTEGER NOT NULL DEFAULT 0,
    count_log INTEGER NOT NULL DEFAULT 0,
    count_false_positive INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    import_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (import_state IN ('pending', 'imported', 'failed')),
    import_attempts INTEGER NOT NULL DEFAULT 0,
    import_diagnostic TEXT NOT NULL DEFAULT '',
    imported_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX report_snapshots_customer_scan_idx
    ON report_snapshots(customer_id, scan_end_at DESC);
CREATE INDEX report_snapshots_import_state_idx
    ON report_snapshots(import_state);

CREATE TABLE finding_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES report_snapshots(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    nvt_oid TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    port TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    severity REAL NOT NULL DEFAULT 0,
    threat TEXT NOT NULL DEFAULT '',
    qod INTEGER NOT NULL DEFAULT 0,
    cves TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT ''
);

CREATE INDEX finding_snapshots_snapshot_idx
    ON finding_snapshots(snapshot_id);
CREATE INDEX finding_snapshots_fingerprint_idx
    ON finding_snapshots(fingerprint);
CREATE INDEX finding_snapshots_fingerprint_snapshot_idx
    ON finding_snapshots(fingerprint, snapshot_id);
