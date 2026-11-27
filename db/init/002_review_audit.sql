-- Payload-free error metadata and independent release audit. Existing rows are never replaced.

CREATE TABLE IF NOT EXISTS action_release_audit (
 operation_id TEXT PRIMARY KEY,
 incident_id TEXT NOT NULL,
 approval_id TEXT NOT NULL,
 requested_by TEXT NOT NULL,
 reason TEXT NOT NULL,
 requested_at_utc TIMESTAMPTZ NOT NULL,
 result TEXT NOT NULL CHECK (result IN ('pending','succeeded','failed','unknown')),
 completed_at_utc TIMESTAMPTZ,
 observed_status TEXT,
 observed_at_utc TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_release_audit_incident ON action_release_audit(incident_id,requested_at_utc);
CREATE INDEX IF NOT EXISTS idx_release_audit_approval ON action_release_audit(approval_id,result);
CREATE TABLE IF NOT EXISTS collector_errors (
 error_id TEXT PRIMARY KEY,
 source TEXT NOT NULL,
 file_path TEXT NOT NULL,
 file_inode TEXT NOT NULL,
 line_offset BIGINT NOT NULL,
 byte_length BIGINT NOT NULL,
 content_sha256 TEXT NOT NULL,
 error_code TEXT NOT NULL,
 ingest_mode TEXT NOT NULL,
 received_at_utc TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_collector_errors_source ON collector_errors(source,received_at_utc);
