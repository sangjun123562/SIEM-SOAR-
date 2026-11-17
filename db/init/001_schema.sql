-- 관제용 PostgreSQL 초기 스키마 (ERP DB와 완전 분리)
-- 모든 시각 컬럼은 TIMESTAMPTZ (UTC 기준) 사용

CREATE TABLE IF NOT EXISTS collector_offsets (
    source          TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    byte_offset     BIGINT NOT NULL DEFAULT 0,
    updated_at_utc  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, file_path)
);

CREATE TABLE IF NOT EXISTS raw_logs (
    raw_id          TEXT PRIMARY KEY,
    source          TEXT NOT NULL CHECK (source IN ('gateway', 'caddy', 'erp')),
    file_path       TEXT NOT NULL,
    line_offset     BIGINT NOT NULL,
    raw_payload     TEXT NOT NULL,
    ingest_mode     TEXT NOT NULL DEFAULT 'live' CHECK (ingest_mode IN ('live', 'replay', 'synthetic')),
    received_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source, file_path, line_offset)
);

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id          TEXT PRIMARY KEY,
    raw_id            TEXT NOT NULL REFERENCES raw_logs(raw_id) ON DELETE RESTRICT,
    source            TEXT NOT NULL CHECK (source IN ('gateway', 'caddy', 'erp')),
    event_ts_utc      TIMESTAMPTZ NOT NULL,
    event_type        TEXT NOT NULL,
    outcome           TEXT NOT NULL,
    username          TEXT,
    client_ip         TEXT,
    peer_ip           TEXT,
    client_ip_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    src_ip            TEXT,
    src_port          INTEGER,
    dst_ip            TEXT,
    dst_port          INTEGER,
    protocol          TEXT,
    request_id        TEXT,
    http_method       TEXT,
    http_path         TEXT,
    status_code       INTEGER,
    ingest_mode       TEXT NOT NULL DEFAULT 'live' CHECK (ingest_mode IN ('live', 'replay', 'synthetic')),
    details_json      JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (raw_id)
);

CREATE INDEX IF NOT EXISTS idx_norm_events_ts ON normalized_events (event_ts_utc DESC);
CREATE INDEX IF NOT EXISTS idx_norm_events_req_id ON normalized_events (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_norm_events_user_ip ON normalized_events (username, client_ip, event_ts_utc);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id          TEXT PRIMARY KEY,
    rule_id           TEXT NOT NULL,
    rule_name         TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    username          TEXT,
    client_ip         TEXT,
    window_start_utc  TIMESTAMPTZ NOT NULL,
    window_end_utc    TIMESTAMPTZ NOT NULL,
    failure_count     INTEGER NOT NULL,
    dedup_key         TEXT NOT NULL UNIQUE,
    created_at_utc    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id  TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    event_id  TEXT NOT NULL REFERENCES normalized_events(event_id) ON DELETE RESTRICT,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'approved', 'blocked', 'released', 'closed')),
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    target_ip       TEXT,
    username        TEXT,
    created_at_utc  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at_utc  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id    TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE RESTRICT,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS incident_correlations (
    correlation_id  TEXT PRIMARY KEY,
    incident_id     TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    event_id        TEXT NOT NULL REFERENCES normalized_events(event_id) ON DELETE RESTRICT,
    link_type       TEXT NOT NULL CHECK (link_type IN ('request_id_exact', 'gateway_candidate')),
    reason          TEXT NOT NULL,
    created_at_utc  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (incident_id, event_id, link_type)
);

CREATE TABLE IF NOT EXISTS action_approvals (
    approval_id       TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
    target_ip         TEXT NOT NULL,
    action_type       TEXT NOT NULL CHECK (action_type IN ('block', 'unblock')),
    approved_by       TEXT NOT NULL,
    approved_at_utc   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at_utc    TIMESTAMPTZ NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'expired', 'released', 'rejected')),
    gateway_response  JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at_utc    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Grafana 읽기 전용 계정 (비밀번호는 배포 환경에 맞게 변경)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'grafana_reader') THEN
        CREATE ROLE grafana_reader WITH LOGIN PASSWORD 'grafana_readonly_change_me';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;
