ALTER TABLE finding_snapshots ADD COLUMN evidence TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN cvss_vector TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN summary TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN insight TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN impact TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN affected TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN solution_type TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_snapshots ADD COLUMN nvt_references TEXT NOT NULL DEFAULT '[]';
