-- +goose Up
-- +goose StatementBegin

-- identity_baselines: per-identity rolling feature baselines used by CAS rules.
-- The admin_action_count is a long-term rolling count incremented by the pipeline.
CREATE TABLE identity_baselines (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT NOT NULL,
    actor_id              TEXT NOT NULL,
    admin_action_count    BIGINT NOT NULL DEFAULT 0,
    last_admin_action_at  TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, actor_id)
);

CREATE INDEX identity_baselines_tenant_actor ON identity_baselines (tenant_id, actor_id);

ALTER TABLE identity_baselines ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_baselines_tenant_isolation ON identity_baselines
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS identity_baselines_tenant_isolation ON identity_baselines;
DROP TABLE IF EXISTS identity_baselines;
-- +goose StatementEnd
