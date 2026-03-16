# AITC V1 Readiness Audit

- **Date/time generated (UTC):** 2026-03-16T09:44:46Z
- **Audit updated (UTC):** 2026-03-16T14:01:49Z
- **Commit SHA audited:** `1d9defca75930e82c67e9dff8b3c5034019d48e9`
- **Auditor:** GitHub Copilot coding agent
- **Governing specs:**
  - [`docs/build-spec/vibecode-master-prompt-v2.md`](../build-spec/vibecode-master-prompt-v2.md)
  - [`docs/prd.md`](../prd.md)
  - [`docs/architecture.md`](../architecture.md)

---

## Executive summary

The AITC codebase is **READY for V1**. All three previously identified blockers have been resolved: (1) all six Go application services and the optional LLM reasoner are now defined in `build/docker/docker-compose.dev.yml` — `make dev-up` brings up a fully running system; (2) the evidence service SOC2/ISO27001 export implementation is scaffolded, tested, and validated against `docs/compliance/soc2-iso-pack.md`; (3) the LLM reasoner now has comprehensive pytest coverage (32 tests covering validators, safety guardrails, and API endpoints) that run deterministically in CI using the StubProvider.

- ✅ All six Go services compile, have unit tests, and pass CI.
- ✅ Protobuf contracts (`EnvelopeV1`) are defined, generated, and CI-verified against the source.
- ✅ Nine versioned Postgres migrations including RLS and append-only audit log are present and reversible.
- ✅ Learning-mode gate, autopilot circuit breaker, disallowed-action list, and idempotency are implemented.
- ✅ All application services wired into `docker-compose.dev.yml`; `make dev-up` starts the full system.
- ✅ Evidence export tested and schema validated against compliance-pack spec.
- ✅ LLM reasoner has 32 pytest tests covering safety validators and API endpoints; CI runs them.

---

## PASS / PARTIAL / FAIL table

| Area | Status | Evidence (file paths) | Notes |
|---|---|---|---|
| Build + CI gates | **PASS** | `.github/workflows/ci.yml`, `.github/workflows/security.yml` | Go lint/vet/build/test (race-detected), migration reversibility check, proto freshness check, Python ruff lint + pytest, CodeQL + govulncheck security scan. |
| Protobuf contracts + EnvelopeV1 | **PASS** | `contracts/proto/aitc/common/envelope.proto`, `internal/gen/aitc/common/`, `contracts/gen/go/` | `EnvelopeV1` fully defined with tenant scoping, payload type, tracing fields, and integrity hash. Dual generation targets (`make proto` / `make proto-export`). CI verifies generated files match source. |
| DB migrations + RLS + append-only audit log | **PASS** | `db/migrations/postgres/0001_init.sql` – `0009_ingestion_checkpoints.sql`, `internal/tenant/rls.go` | 9 sequential Goose migrations. `0002_rls.sql` installs `set_tenant_context()` / `current_tenant_id()`. `0003_audit_log.sql` creates append-only `audit_log` table (no UPDATE/DELETE granted to app role). CI runs up + full down in each PR. |
| Ingestion service | **PASS** | `services/ingestion/service.go`, `cmd/ingestion/main.go`, `services/ingestion/internal/okta/poller_test.go`, `services/ingestion/internal/m365/ual_poller_test.go` | Okta System Log poller, M365 UAL poller, Kafka publisher, MinIO/S3 archiver, backfill, mock mode, graceful shutdown. Unit tests present. |
| Pipeline service | **PASS** | `services/pipeline/service.go`, `cmd/pipeline/main.go`, `services/pipeline/internal/cas/cas_test.go`, `services/pipeline/internal/normalizer/normalizer_test.go`, `services/pipeline/internal/cas/rules/rules_test.go` | Kafka consumer → normalizer → Redis TTL-windowed feature extractor → CAS engine (6 rules) → Postgres write → Kafka risk-signals producer. Unit tests present for CAS and normalizer. |
| Controlplane service | **PASS** | `services/controlplane/service.go`, `cmd/controlplane/main.go`, `services/controlplane/internal/autonomy/learning_mode_test.go`, `services/controlplane/internal/policy/validator_test.go` | Risk signal consumer, disallowed-action block, learning-mode gate, autopilot gate, circuit breaker (5 failures / 5 min, 10 min reset), action-recommendations + action-requests publishing, audit log write. |
| Enforcement-okta service | **PASS** | `services/enforcement_okta/service.go`, `cmd/enforcement-okta/main.go`, `services/enforcement_okta/internal/executor/executor_test.go`, `services/enforcement_okta/internal/executor/audit_test.go`, `services/enforcement_okta/internal/executor/actions_test.go` | Kafka consumer, disallowed-action re-check, idempotency via `response_actions` table, before/after state capture, three permitted actions (`revoke_sessions`, `mfa_stepup`, `signon_policy_adjust`), DLQ routing, full audit trail. |
| Evidence service | **PASS** | `services/evidence/service.go`, `cmd/evidence/main.go`, `services/evidence/internal/generator/generator_test.go`, `services/evidence/internal/archive/archive_test.go`, `services/evidence/internal/export/export_test.go`, `services/evidence/internal/scheduler/scheduler_test.go` | On-demand and scheduled modes; generator, archiver, scheduler, and exporter all have tests. SOC2 control packs (CC6.1 access roster, MFA coverage, privileged inventory, admin activity, incident timelines) and ISO27001 packs (access control, incident management, logging/monitoring) are implemented and tested against `docs/compliance/soc2-iso-pack.md`. |
| API service | **PASS** | `services/api/service.go`, `cmd/api/main.go`, `services/api/internal/auth/auth.go`, `services/api/internal/rbac/rbac.go` | chi router, Okta OIDC middleware with dev stub (`DEV_AUTH_STUB=true`), RBAC (Admin / Analyst / Auditor / ReadOnly), Postgres RLS-enabled handlers. |
| Dev environment (docker-compose) | **PASS** | `build/docker/docker-compose.dev.yml`, `build/scripts/dev-up.sh`, `build/scripts/dev-down.sh` | Infrastructure (Postgres 16, Redis 7, Kafka + Zookeeper, MinIO) + all six application services + LLM reasoner — all with health checks and infra dependency ordering. `make dev-up` starts the complete system. |
| LLM reasoner (optional) | **PASS** | `services/llm_reasoner/app/api.py`, `services/llm_reasoner/tests/test_api.py`, `services/llm_reasoner/tests/test_validators.py` | FastAPI service with `/healthz`, `/readyz`, `/reason/case-summary`. 32 pytest tests covering: input secret scanning, output action validation (allowlist + disallow-list), logging sanitization, and all API endpoints using StubProvider. CI `python` job runs pytest deterministically (no LLM key required). |

---

## Blockers to ship V1 (ordered)

~~1. **Application services absent from dev docker-compose**~~
**RESOLVED** — All six Go services and the LLM reasoner are now defined in `build/docker/docker-compose.dev.yml` with health checks and infra dependency ordering. `make dev-up` brings up the full system.

~~2. **Evidence export completeness unverified against compliance-pack spec**~~
**RESOLVED** — SOC2 packs (access roster CC6.1, MFA coverage CC6.3, privileged inventory CC6.2, admin activity CC7.2, incident timelines CC7.3) and ISO27001 packs (access control A.9, incident management A.16, logging/monitoring A.12) are implemented. Export schema (JSON + CSV) tested in `services/evidence/internal/export/export_test.go`. Pack generators tested in `services/evidence/internal/generator/generator_test.go`.

~~3. **LLM reasoner has no automated runtime tests**~~
**RESOLVED** — 32 pytest tests added in `services/llm_reasoner/tests/`. CI `python` job updated to install requirements and run `pytest` with `LLM_PROVIDER=stub` (deterministic, no API key). Tests cover all safety guardrails (Steps 0.1, 0.3, 0.7), all allowed/disallowed actions, and all API endpoints.

---

## Non-blocking improvements

- **Per-service config files:** All services share a monolithic `config.Config` struct. Extracting per-service YAML configs (similar to `configs/env/pipeline.yaml`) would improve isolation and reduce misconfiguration risk.
- **Integration test harness:** The current test suite is entirely unit tests. A lightweight integration test (spawning Postgres + Kafka via `testcontainers-go`) would give higher confidence in the end-to-end Kafka → Postgres write path.
- **Redis in services:** `build/docker/docker-compose.dev.yml` provisions Redis, and the pipeline service uses it for TTL-windowed feature extraction; however, Redis health-check integration in other services' startup code is absent.
- **Infra Terraform state:** `infra/terraform/` exists but remote state backend and variable files are not committed — ensure a `backend.tf` and `terraform.tfvars.example` are present so infra changes can be reviewed in PRs.
- **Runbook cross-links:** `runbooks/` files do not reference the audit-log table or the evidence service. Adding links would help on-call engineers during incidents.
- **golangci-lint config:** `build/scripts/lint.sh` calls golangci-lint but no `.golangci.yml` config file was found in the repo root; adding one would pin linter versions and rules for reproducibility.

---

## Validation commands (copy/paste)

```bash
# Generate protobuf Go code (service-internal)
make proto

# Generate protobuf Go code (public contracts export)
make proto-export

# Start full dev environment (infra + all application services)
make dev-up

# Run database migrations
make migrate

# Seed dev data
make seed-dev

# Run all Go tests (unit)
go test ./...

# Run all Go tests with race detector
go test -race -timeout 120s ./...

# Run linter
make lint

# Tear down dev environment
make dev-down

# --- Per-service health checks (after make dev-up) ---
curl -sf http://localhost:8080/healthz && echo "Ingestion OK"
curl -sf http://localhost:8081/healthz && echo "Pipeline OK"
curl -sf http://localhost:8083/healthz && echo "Enforcement-Okta OK"
curl -sf http://localhost:8084/healthz && echo "Controlplane OK"
curl -sf http://localhost:8085/healthz && echo "API OK"
curl -sf http://localhost:8086/healthz && echo "Evidence OK"
curl -sf http://localhost:8087/healthz && echo "LLM Reasoner OK"

# --- LLM reasoner tests ---
cd services/llm_reasoner && LLM_PROVIDER=stub python -m pytest tests/ -v

# --- Evidence service tests ---
go test ./services/evidence/... -v

# --- Migration reversibility (matches CI) ---
goose -dir db/migrations/postgres postgres "$DATABASE_URL" up
goose -dir db/migrations/postgres postgres "$DATABASE_URL" down-to 0
```

---

## Evidence links

| Concern | File path(s) |
|---|---|
| Learning mode gate | `services/controlplane/service.go`, `services/controlplane/internal/autonomy/learning_mode_test.go` |
| Autopilot gate + circuit breaker | `services/controlplane/service.go` (circuit breaker logic), `services/controlplane/internal/policy/validator_test.go` |
| Validator + disallowed actions | `internal/policy/loader.go`, `internal/policy/types.go`, `configs/policies/tenant_overrides.example.json` |
| Audit log schema | `db/migrations/postgres/0003_audit_log.sql` |
| RLS setup | `db/migrations/postgres/0002_rls.sql`, `internal/tenant/rls.go` |
| Append-only audit log (Go) | `internal/audit/auditlog.go` |
| Evidence pack generation | `services/evidence/internal/generator/generator.go`, `services/evidence/internal/packs/`, `docs/compliance/soc2-iso-pack.md` |
| Evidence export schema | `services/evidence/internal/export/json.go`, `services/evidence/internal/export/csv.go`, `services/evidence/internal/export/export_test.go` |
| CI workflows | `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `.github/workflows/deploy-dev.yml`, `.github/workflows/deploy-prod.yml` |
| EnvelopeV1 proto | `contracts/proto/aitc/common/envelope.proto` |
| Idempotency (enforcement) | `db/migrations/postgres/0007_cases_actions.sql` (`response_actions` table), `services/enforcement_okta/internal/executor/executor.go` |
| Dev docker-compose | `build/docker/docker-compose.dev.yml`, `build/scripts/dev-up.sh` |
| LLM reasoner tests | `services/llm_reasoner/tests/test_api.py`, `services/llm_reasoner/tests/test_validators.py` |

