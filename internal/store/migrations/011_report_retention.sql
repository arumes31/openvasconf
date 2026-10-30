-- Preserve operational finding state when report history expires.
CREATE TABLE finding_states_retained (
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_snapshot_id INTEGER REFERENCES report_snapshots(id) ON DELETE SET NULL,
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

INSERT INTO finding_states_retained SELECT * FROM finding_states;
DROP TABLE finding_states;
ALTER TABLE finding_states_retained RENAME TO finding_states;

CREATE INDEX finding_states_current_idx
    ON finding_states(present, remediation_state, severity DESC);
CREATE INDEX finding_states_task_idx
    ON finding_states(customer_id, task_id, present);
