-- +goose Up
-- +goose StatementBegin
-- Helper function: set tenant context for RLS
CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('app.tenant_id', p_tenant_id, TRUE);
END;
$$;

-- Helper function: get current tenant from config
CREATE OR REPLACE FUNCTION current_tenant_id()
RETURNS TEXT LANGUAGE sql STABLE AS $$
  SELECT current_setting('app.tenant_id', TRUE)
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS current_tenant_id();
DROP FUNCTION IF EXISTS set_tenant_context(TEXT);
