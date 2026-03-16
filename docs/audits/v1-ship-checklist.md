# AITC V1 Ship Checklist

> Use this checklist before merging to `main` / cutting a V1 release tag.
> Every box must be checked (or explicitly waived with a reason) by an engineer.

---

## 1. Build & CI

- [ ] `make proto` and `make proto-export` run without errors and generated files are committed
- [ ] `make build` (`go build ./...`) exits 0
- [ ] `make test` (`go test ./...`) exits 0 with no failing tests
- [ ] `make lint` exits 0 (golangci-lint + ruff)
- [x] All GitHub Actions CI jobs pass on the release commit (go, migrations, proto-check, integration-checks, python)
- [x] Python CI job runs `pytest services/llm_reasoner/tests/` with `LLM_PROVIDER=stub` and exits 0
- [ ] Security scan (CodeQL + govulncheck) is green or all findings are triaged

## 2. Database

- [ ] `make migrate` runs all 9 migrations (0001 – 0009) against a clean Postgres instance without errors
- [ ] Migration rollback (`goose down-to 0`) runs without errors
- [ ] RLS is enabled: `SELECT set_config('app.tenant_id', '<id>', TRUE)` scopes queries correctly
- [ ] `audit_log` table has no `UPDATE` or `DELETE` privilege granted to the app role (append-only enforced)

## 3. Protobuf contracts

- [ ] `EnvelopeV1` proto (`contracts/proto/aitc/common/envelope.proto`) is unchanged from audited SHA or changes are reviewed
- [ ] Generated Go code under `internal/gen/` and `contracts/gen/go/` matches the proto source (CI proto-check passes)

## 4. Services — functional readiness

- [ ] **Ingestion:** Okta + M365 pollers start, produce events to `raw-events` Kafka topic; `/healthz` returns 200
- [ ] **Pipeline:** Consumes `raw-events`, writes to `normalized_events` + `risk_signals` tables, publishes to `risk-signals` topic; `/healthz` returns 200
- [ ] **Controlplane:** Consumes `risk-signals`; learning-mode gate and autopilot gate behave correctly per `configs/policies/`; publishes to `action-recommendations` and (when autopilot on) `action-requests`; `/healthz` returns 200
- [ ] **Enforcement-Okta:** Consumes `action-requests`; idempotency check prevents double-execution; executes only allowed actions (`revoke_sessions`, `mfa_stepup`, `signon_policy_adjust`); failed actions route to DLQ; `/healthz` returns 200
- [x] **Evidence:** On-demand and scheduled report generation complete; SOC2 (CC6.1/CC6.2/CC6.3/CC7.2/CC7.4) and ISO 27001:2022 (A.5.15/A.5.26/A.8.15) packs validated against `docs/compliance/soc2-iso-pack.md` by schema assertion tests + golden-file tests in `services/evidence/internal/generator/completeness_test.go`; `/healthz` returns 200
- [x] **API:** Auth middleware works in production mode (Okta OIDC); RBAC roles (Admin / Analyst / Auditor / ReadOnly) enforced; Postgres RLS active; `/healthz` returns 200
- [x] **LLM Reasoner (optional):** `/healthz` returns 200; `/reason/case-summary` returns `advisory_only: true`; input sanitisation blocks credential patterns; 32 pytest tests pass in CI

## 5. Dev environment

- [x] `make dev-up` starts Postgres, Redis, Kafka, MinIO **and all application services** with health checks green
- [ ] `make migrate` runs successfully against the dev Postgres
- [ ] `make seed-dev` seeds dev data without errors
- [x] Each application service is containerised and reachable at its `/healthz` endpoint via `make dev-up`
- [ ] `make dev-down` cleanly stops all infrastructure

## 6. Security & compliance

- [ ] No secrets or credentials committed to the repo (`git grep` for key patterns returns nothing sensitive)
- [ ] S3/MinIO credentials loaded from environment variables only (not config files)
- [ ] PII fields (email, IP) are redacted before writing to `normalized_events` (per `security/pii-handling.md`)
- [ ] Audit log entries are written for every policy decision and enforcement action
- [ ] Tenant isolation: cross-tenant data leak is impossible (RLS `app.tenant_id` is set on every DB transaction)
- [ ] Disallowed-action list (`configs/policies/`) prevents permanently forbidden action types at both Controlplane and Enforcement-Okta layers
- [ ] Circuit breaker trips correctly after 5 failures / 5 min window; resets after 10 min

## 7. Observability

- [ ] Structured JSON logs emitted by all services (no unstructured `fmt.Println` in hot paths)
- [ ] OpenTelemetry trace context propagated via `EnvelopeV1.trace_id` / `span_id`
- [ ] `/metrics` endpoint returns Prometheus metrics on each service

## 8. Documentation

- [ ] `README.md` reflects current architecture and service ports
- [ ] `docs/architecture.md` is up to date
- [ ] `docs/audits/v1-readiness-audit.md` is present and blockers addressed (or waived)
- [ ] Runbooks (`runbooks/`) reviewed and accurate for V1 ops

## 9. Release mechanics

- [ ] Git tag `v1.0.0` (or chosen tag) points to the verified commit
- [ ] `deploy-prod.yml` workflow triggered and deployment successful
- [ ] Post-deploy smoke test: ingest a synthetic event and confirm it flows through pipeline → controlplane → audit log within SLA

---

*All items must be checked or explicitly waived before V1 ships. Record waivers as PR comments with justification.*
