-- +goose Up
-- +goose StatementBegin
CREATE TABLE identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    provider_id     TEXT NOT NULL,  -- Okta user ID or M365 UPN
    provider        TEXT NOT NULL,  -- "okta" | "m365"
    email           TEXT,           -- PII: handle per pii-handling.md
    display_name    TEXT,
    roles           TEXT[] DEFAULT '{}',
    is_privileged   BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enrolled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, provider_id)
);

CREATE INDEX identities_tenant_idx ON identities (tenant_id);
CREATE INDEX identities_email_idx ON identities (tenant_id, email);

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY identities_tenant_isolation ON identities
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE TRIGGER identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- sessions
CREATE TABLE sessions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    identity_id          UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    provider_session_id  TEXT,
    authn_method         TEXT,
    ip_address           TEXT,   -- PII
    user_agent           TEXT,
    country              TEXT,
    city                 TEXT,
    lat                  DOUBLE PRECISION,
    lon                  DOUBLE PRECISION,
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ,
    last_activity_at     TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX sessions_tenant_identity ON sessions (tenant_id, identity_id);
CREATE INDEX sessions_tenant_active ON sessions (tenant_id, is_active);

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY sessions_tenant_isolation ON sessions
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE TRIGGER sessions_updated_at
    BEFORE UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS sessions_updated_at ON sessions;
DROP POLICY IF EXISTS sessions_tenant_isolation ON sessions;
DROP TABLE IF EXISTS sessions;
DROP TRIGGER IF EXISTS identities_updated_at ON identities;
DROP POLICY IF EXISTS identities_tenant_isolation ON identities;
DROP TABLE IF EXISTS identities;
