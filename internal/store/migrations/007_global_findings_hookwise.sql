ALTER TABLE customers ADD COLUMN cid TEXT NOT NULL DEFAULT '';
CREATE INDEX customers_cid_idx ON customers(cid);

ALTER TABLE settings ADD COLUMN hookwise_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (hookwise_enabled IN (0, 1));
ALTER TABLE settings ADD COLUMN hookwise_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN hookwise_token_cipher TEXT NOT NULL DEFAULT '';

CREATE TABLE finding_states (
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_snapshot_id INTEGER NOT NULL REFERENCES report_snapshots(id) ON DELETE CASCADE,
    present INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0, 1)),
    severity REAL NOT NULL DEFAULT 0,
    disposition TEXT NOT NULL DEFAULT 'active'
        CHECK (disposition IN ('active', 'false_positive', 'accepted_risk')),
    justification TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    remediation_state TEXT NOT NULL DEFAULT 'open'
        CHECK (remediation_state IN ('open', 'in_progress', 'resolved', 'wont_fix')),
    remediation_owner TEXT NOT NULL DEFAULT '',
    due_date TEXT,
    expires_at TEXT,
    ticket_desired_open INTEGER NOT NULL DEFAULT 0 CHECK (ticket_desired_open IN (0, 1)),
    ticket_generation INTEGER NOT NULL DEFAULT 0,
    ticket_state TEXT NOT NULL DEFAULT 'none'
        CHECK (ticket_state IN ('none', 'blocked', 'queued_open', 'open', 'queued_close', 'closed', 'failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (customer_id, task_id, fingerprint)
);

CREATE INDEX finding_states_current_idx
    ON finding_states(present, remediation_state, severity DESC);
CREATE INDEX finding_states_task_idx
    ON finding_states(customer_id, task_id, present);

INSERT INTO finding_states(
    customer_id, task_id, fingerprint,
    first_seen_at, last_seen_at, last_snapshot_id, present, severity,
    disposition, justification, operator, remediation_state,
    remediation_owner, due_date, expires_at, created_at, updated_at
)
SELECT
    r.customer_id,
    r.task_id,
    f.fingerprint,
    MIN(r.scan_end_at),
    MAX(r.scan_end_at),
    (
        SELECT occurrence.id
        FROM report_snapshots occurrence
        JOIN finding_snapshots occurrence_finding
          ON occurrence_finding.snapshot_id = occurrence.id
        WHERE occurrence.customer_id = r.customer_id
          AND occurrence.task_id = r.task_id
          AND occurrence.import_state = 'imported'
          AND occurrence_finding.fingerprint = f.fingerprint
        ORDER BY occurrence.scan_end_at DESC, occurrence.id DESC
        LIMIT 1
    ),
    CASE WHEN (
        SELECT occurrence.id
        FROM report_snapshots occurrence
        JOIN finding_snapshots occurrence_finding
          ON occurrence_finding.snapshot_id = occurrence.id
        WHERE occurrence.customer_id = r.customer_id
          AND occurrence.task_id = r.task_id
          AND occurrence.import_state = 'imported'
          AND occurrence_finding.fingerprint = f.fingerprint
        ORDER BY occurrence.scan_end_at DESC, occurrence.id DESC
        LIMIT 1
    ) = (
        SELECT latest.id
        FROM report_snapshots latest
        WHERE latest.customer_id = r.customer_id
          AND latest.task_id = r.task_id
          AND latest.import_state = 'imported'
        ORDER BY latest.scan_end_at DESC, latest.id DESC
        LIMIT 1
    ) THEN 1 ELSE 0 END,
    (
        SELECT occurrence_finding.severity
        FROM report_snapshots occurrence
        JOIN finding_snapshots occurrence_finding
          ON occurrence_finding.snapshot_id = occurrence.id
        WHERE occurrence.customer_id = r.customer_id
          AND occurrence.task_id = r.task_id
          AND occurrence.import_state = 'imported'
          AND occurrence_finding.fingerprint = f.fingerprint
        ORDER BY occurrence.scan_end_at DESC, occurrence.id DESC
        LIMIT 1
    ),
    COALESCE(a.disposition, 'active'),
    COALESCE(a.justification, ''),
    COALESCE(a.operator, ''),
    COALESCE(a.remediation_state, 'open'),
    COALESCE(a.remediation_owner, ''),
    a.due_date,
    a.expires_at,
    MIN(r.created_at),
    MAX(COALESCE(a.updated_at, r.created_at))
FROM finding_snapshots f
JOIN report_snapshots r ON r.id = f.snapshot_id
LEFT JOIN finding_annotations a
  ON a.customer_id = r.customer_id AND a.fingerprint = f.fingerprint
WHERE r.customer_id IS NOT NULL
  AND r.customer_id <> ''
  AND r.task_id <> ''
  AND r.import_state = 'imported'
GROUP BY r.customer_id, r.task_id, f.fingerprint;

CREATE TABLE hookwise_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    generation INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('open', 'closed')),
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivered')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_status INTEGER NOT NULL DEFAULT 0,
    last_diagnostic TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    delivered_at TEXT
);

CREATE INDEX hookwise_outbox_pending_idx
    ON hookwise_outbox(state, next_attempt_at, id);
