-- +goose Up
-- +goose StatementBegin
-- raw_event_refs: pointer to immutable raw archive in S3/MinIO
CREATE TABLE raw_event_refs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    source          TEXT NOT NULL,     -- "okta" | "m365"
    provider_event_id TEXT NOT NULL,   -- source system event ID (for dedup)
    s3_key          TEXT NOT NULL,
    s3_bucket       TEXT NOT NULL,
    hash_sha256     TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, source, provider_event_id)
);

CREATE INDEX raw_event_refs_tenant_source ON raw_event_refs (tenant_id, source, occurred_at DESC);

ALTER TABLE raw_event_refs ENABLE ROW LEVEL SECURITY;
CREATE POLICY raw_event_refs_tenant_isolation ON raw_event_refs
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

-- normalized_events: canonical events processed by the pipeline
CREATE TABLE normalized_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    source_event_id   TEXT NOT NULL,   -- provider event ID
    source            TEXT NOT NULL,
    category          TEXT NOT NULL,
    action            TEXT NOT NULL,
    outcome           TEXT NOT NULL,
    actor_id          TEXT,
    actor_email       TEXT,            -- PII
    actor_is_privileged BOOLEAN DEFAULT FALSE,
    target_id         TEXT,
    target_type       TEXT,
    source_ip         TEXT,            -- PII
    user_agent        TEXT,
    geo_country       TEXT,
    geo_city          TEXT,
    geo_lat           DOUBLE PRECISION,
    geo_lon           DOUBLE PRECISION,
    authn_method      TEXT,
    mfa_used          BOOLEAN DEFAULT FALSE,
    raw_ref_id        UUID REFERENCES raw_event_refs(id),
    occurred_at       TIMESTAMPTZ NOT NULL,
    ingested_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, source, source_event_id)
);

CREATE INDEX normalized_events_tenant_occurred ON normalized_events (tenant_id, occurred_at DESC);
CREATE INDEX normalized_events_actor ON normalized_events (tenant_id, actor_id, occurred_at DESC);
CREATE INDEX normalized_events_category ON normalized_events (tenant_id, category);

ALTER TABLE normalized_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY normalized_events_tenant_isolation ON normalized_events
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS normalized_events_tenant_isolation ON normalized_events;
DROP TABLE IF EXISTS normalized_events;
DROP POLICY IF EXISTS raw_event_refs_tenant_isolation ON raw_event_refs;
DROP TABLE IF EXISTS raw_event_refs;
