-- +goose Up
-- +goose StatementBegin
-- ingestion_checkpoints: per-tenant watermark for each ingestion source poller.
-- Used by Okta and M365 pollers to track the last successfully processed event time.
CREATE TABLE ingestion_checkpoints (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    source      TEXT NOT NULL,   -- "okta" | "m365"
    watermark   TIMESTAMPTZ NOT NULL,
    next_link   TEXT,            -- Okta pagination cursor (Link header value)
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, source)
);

CREATE INDEX ingestion_checkpoints_tenant ON ingestion_checkpoints (tenant_id, source);

ALTER TABLE ingestion_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY ingestion_checkpoints_tenant_isolation ON ingestion_checkpoints
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS ingestion_checkpoints_tenant_isolation ON ingestion_checkpoints;
DROP TABLE IF EXISTS ingestion_checkpoints;
