-- +goose Up
-- +goose StatementBegin
CREATE TABLE risk_signals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    identity_id     UUID REFERENCES identities(id),
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,   -- "low"|"medium"|"high"|"critical"
    cas_score       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    description     TEXT,
    evidence_event_ids TEXT[] DEFAULT '{}',
    case_id         UUID,            -- filled in after case creation
    trace_id        TEXT,
    request_id      TEXT,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX risk_signals_tenant_detected ON risk_signals (tenant_id, detected_at DESC);
CREATE INDEX risk_signals_identity ON risk_signals (tenant_id, identity_id, detected_at DESC);
CREATE INDEX risk_signals_severity ON risk_signals (tenant_id, severity);

ALTER TABLE risk_signals ENABLE ROW LEVEL SECURITY;
CREATE POLICY risk_signals_tenant_isolation ON risk_signals
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS risk_signals_tenant_isolation ON risk_signals;
DROP TABLE IF EXISTS risk_signals;
