CREATE TABLE finding_annotations (
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    disposition TEXT NOT NULL DEFAULT 'active'
        CHECK (disposition IN ('active', 'false_positive', 'accepted_risk')),
    justification TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    remediation_state TEXT NOT NULL DEFAULT 'open'
        CHECK (remediation_state IN ('open', 'in_progress', 'resolved', 'wont_fix')),
    remediation_owner TEXT NOT NULL DEFAULT '',
    due_date TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (customer_id, fingerprint)
);

ALTER TABLE settings ADD COLUMN sla_critical_days INTEGER NOT NULL DEFAULT 7
    CHECK (sla_critical_days >= 0);
ALTER TABLE settings ADD COLUMN sla_high_days INTEGER NOT NULL DEFAULT 14
    CHECK (sla_high_days >= 0);
ALTER TABLE settings ADD COLUMN sla_medium_days INTEGER NOT NULL DEFAULT 30
    CHECK (sla_medium_days >= 0);
ALTER TABLE settings ADD COLUMN sla_low_days INTEGER NOT NULL DEFAULT 90
    CHECK (sla_low_days >= 0);
