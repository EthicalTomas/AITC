-- +goose Up
-- +goose StatementBegin
-- audit_log: append-only event log for compliance and auditability.
-- SECURITY: this table must never have UPDATE or DELETE granted to application roles.
CREATE TABLE audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL,
    event_type    TEXT NOT NULL,  -- e.g., "RiskSignalEmitted", "ActionProposed"
    actor         TEXT NOT NULL,  -- service name or user ID
    subject_type  TEXT,           -- e.g., "Case", "ResponseAction"
    subject_id    TEXT,
    description   TEXT,
    before_state  JSONB,
    after_state   JSONB,
    metadata      JSONB,
    trace_id      TEXT,
    request_id    TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_log_tenant_occurred ON audit_log (tenant_id, occurred_at DESC);
CREATE INDEX audit_log_subject ON audit_log (tenant_id, subject_type, subject_id);

-- Enable RLS
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log;
DROP TABLE IF EXISTS audit_log;
