-- +goose Up
-- +goose StatementBegin
CREATE TABLE evidence_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    report_type     TEXT NOT NULL,  -- "soc2" | "iso27001"
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    s3_key          TEXT,
    s3_bucket       TEXT,
    status          TEXT NOT NULL DEFAULT 'generating',  -- generating|complete|failed
    generated_by    TEXT,
    trace_id        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX evidence_reports_tenant ON evidence_reports (tenant_id, created_at DESC);

ALTER TABLE evidence_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY evidence_reports_tenant_isolation ON evidence_reports
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE TRIGGER evidence_reports_updated_at
    BEFORE UPDATE ON evidence_reports
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE evidence_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    report_id       UUID REFERENCES evidence_reports(id) ON DELETE CASCADE,
    control_id      TEXT NOT NULL,    -- e.g., "CC6.1", "A.9.2.1"
    control_name    TEXT,
    evidence_type   TEXT NOT NULL,    -- "normalized_event" | "response_action" | "audit_log"
    subject_id      UUID,
    description     TEXT,
    payload_json    JSONB,
    occurred_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX evidence_items_report ON evidence_items (tenant_id, report_id);

ALTER TABLE evidence_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY evidence_items_tenant_isolation ON evidence_items
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS evidence_items_tenant_isolation ON evidence_items;
DROP TABLE IF EXISTS evidence_items;
DROP TRIGGER IF EXISTS evidence_reports_updated_at ON evidence_reports;
DROP POLICY IF EXISTS evidence_reports_tenant_isolation ON evidence_reports;
DROP TABLE IF EXISTS evidence_reports;
