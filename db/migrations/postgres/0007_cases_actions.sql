-- +goose Up
-- +goose StatementBegin
CREATE TABLE cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    identity_id     UUID REFERENCES identities(id),
    title           TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'open',  -- open|in_progress|resolved|closed|false_positive
    severity        TEXT NOT NULL DEFAULT 'medium',
    signal_ids      UUID[] DEFAULT '{}',
    assigned_to     TEXT,
    trace_id        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ
);

CREATE INDEX cases_tenant_status ON cases (tenant_id, status, created_at DESC);
CREATE INDEX cases_identity ON cases (tenant_id, identity_id);

ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
CREATE POLICY cases_tenant_isolation ON cases
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE TRIGGER cases_updated_at
    BEFORE UPDATE ON cases
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Update risk_signals to reference cases
ALTER TABLE risk_signals ADD CONSTRAINT risk_signals_case_fk
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL;

CREATE TABLE response_actions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT NOT NULL,
    case_id               UUID REFERENCES cases(id),
    identity_id           UUID REFERENCES identities(id),
    action_type           TEXT NOT NULL,
    mode                  TEXT NOT NULL DEFAULT 'recommended', -- recommended|manual_executed|autopilot_executed
    status                TEXT NOT NULL DEFAULT 'proposed',    -- proposed|validated|rejected|executing|executed|failed|rolled_back
    parameters_json       JSONB,
    idempotency_key       TEXT NOT NULL,
    validator_decision_id UUID,
    rejection_reason      TEXT,
    before_state_json     JSONB,
    after_state_json      JSONB,
    trace_id              TEXT,
    request_id            TEXT,
    proposed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at           TIMESTAMPTZ,
    executed_by           TEXT,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX response_actions_tenant_status ON response_actions (tenant_id, status, proposed_at DESC);
CREATE INDEX response_actions_case ON response_actions (tenant_id, case_id);
CREATE INDEX response_actions_idempotency ON response_actions (idempotency_key);

ALTER TABLE response_actions ENABLE ROW LEVEL SECURITY;
CREATE POLICY response_actions_tenant_isolation ON response_actions
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE TRIGGER response_actions_updated_at
    BEFORE UPDATE ON response_actions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS response_actions_updated_at ON response_actions;
DROP POLICY IF EXISTS response_actions_tenant_isolation ON response_actions;
DROP TABLE IF EXISTS response_actions;
DROP TRIGGER IF EXISTS cases_updated_at ON cases;
DROP POLICY IF EXISTS cases_tenant_isolation ON cases;
DROP TABLE IF EXISTS cases;
