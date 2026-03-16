# AITC V1 Readiness Audit

- **Date/time generated (UTC):** 2026-03-16T09:44:46Z
- **Commit SHA audited:** `1d9defca75930e82c67e9dff8b3c5034019d48e9`
- **Auditor:** GitHub Copilot coding agent
- **Governing specs:**
  - [`docs/build-spec/vibecode-master-prompt-v2.md`](../build-spec/vibecode-master-prompt-v2.md)
  - [`docs/prd.md`](../prd.md)
  - [`docs/architecture.md`](../architecture.md)

---

## Executive summary

The AITC codebase is **substantially ready for V1** with all six Go microservices and the optional Python LLM reasoner present, functional, and tested. Core data contracts (EnvelopeV1 protobuf), all nine database migrations (including RLS and an append-only audit log), CI/CD gates, and the full Kafka event pipeline are in place. However, three items require attention before a production release is declared: (1) the Go application services are not wired into `docker-compose.dev.yml`, so a developer cannot spin up a fully running system with a single `make dev-up`; (2) the evidence service's SOC2/ISO27001 export implementation is partially scaffolded but completeness is unverified against the compliance-pack spec; (3) the LLM reasoner (Python) has no automated test coverage, which means its CI job lints but does not execute runtime checks.

- ✅ All six Go services compile, have unit tests, and pass CI.
- ✅ Protobuf contracts (`EnvelopeV1`) are defined, generated, and CI-verified against the source.
- ✅ Nine versioned Postgres migrations including RLS and append-only audit log are present and reversible.
- ✅ Learning-mode gate, autopilot circuit breaker, disallowed-action list, and idempotency are implemented.
- ⚠️ Application services missing from `docker-compose.dev.yml`; dev setup requires manual binary execution.
- ⚠️ Evidence export and LLM reasoner tests incomplete.

---

## PASS / PARTIAL / FAIL table

| Area | Status | Evidence (file paths) | Notes |
|---|---|---|---|
| Build + CI gates | **PASS** | `.github/workflows/ci.yml`, `.github/workflows/security.yml` | Go lint/vet/build/test (race-detected), migration reversibility check, proto freshness check, Python ruff lint, CodeQL + govulncheck security scan. |
| Protobuf contracts + EnvelopeV1 | **PASS** | `contracts/proto/aitc/common/envelope.proto`, `internal/gen/aitc/common/`, `contracts/gen/go/` | `EnvelopeV1` fully defined with tenant scoping, payload type, tracing fields, and integrity hash. Dual generation targets (`make proto` / `make proto-export`). CI verifies generated files match source. |
| DB migrations + RLS + append-only audit log | **PASS** | `db/migrations/postgres/0001_init.sql` – `0009_ingestion_checkpoints.sql`, `internal/tenant/rls.go` | 9 sequential Goose migrations. `0002_rls.sql` installs `set_tenant_context()` / `current_tenant_id()`. `0003_audit_log.sql` creates append-only `audit_log` table (no UPDATE/DELETE granted to app role). CI runs up + full down in each PR. |
| Ingestion service | **PASS** | `services/ingestion/service.go`, `cmd/ingestion/main.go`, `services/ingestion/internal/okta/poller_test.go`, `services/ingestion/internal/m365/ual_poller_test.go` | Okta System Log poller, M365 UAL poller, Kafka publisher, MinIO/S3 archiver, backfill, mock mode, graceful shutdown. Unit tests present. |
| Pipeline service | **PASS** | `services/pipeline/service.go`, `cmd/pipeline/main.go`, `services/pipeline/internal/cas/cas_test.go`, `services/pipeline/internal/normalizer/normalizer_test.go`, `services/pipeline/internal/cas/rules/rules_test.go` | Kafka consumer → normalizer → Redis TTL-windowed feature extractor → CAS engine (6 rules) → Postgres write → Kafka risk-signals producer. Unit tests present for CAS and normalizer. |
| Controlplane service | **PASS** | `services/controlplane/service.go`, `cmd/controlplane/main.go`, `services/controlplane/internal/autonomy/learning_mode_test.go`, `services/controlplane/internal/policy/validator_test.go` | Risk signal consumer, disallowed-action block, learning-mode gate, autopilot gate, circuit breaker (5 failures / 5 min, 10 min reset), action-recommendations + action-requests publishing, audit log write. |
| Enforcement-okta service | **PASS** | `services/enforcement_okta/service.go`, `cmd/enforcement-okta/main.go`, `services/enforcement_okta/internal/executor/executor_test.go`, `services/enforcement_okta/internal/executor/audit_test.go`, `services/enforcement_okta/internal/executor/actions_test.go` | Kafka consumer, disallowed-action re-check, idempotency via `response_actions` table, before/after state capture, three permitted actions (`revoke_sessions`, `mfa_stepup`, `signon_policy_adjust`), DLQ routing, full audit trail. |
| Evidence service | **PARTIAL** | `services/evidence/service.go`, `cmd/evidence/main.go`, `services/evidence/internal/generator/generator_test.go`, `services/evidence/internal/generator/archive_test.go`, `services/evidence/internal/generator/export_test.go`, `services/evidence/internal/generator/scheduler_test.go` | On-demand and scheduled modes exist; generator, archiver, scheduler, and exporter all have tests. SOC2 and ISO27001 report content is scaffolded but completeness against `docs/compliance/soc2-iso-pack.md` is **UNKNOWN** — run `go test ./services/evidence/...` and manually review the generated report JSON/CSV output against the compliance-pack spec. |
| API service | **PASS** | `services/api/service.go`, `cmd/api/main.go`, `services/api/internal/auth/auth.go`, `services/api/internal/rbac/rbac.go` | chi router, Okta OIDC middleware with dev stub (`DEV_AUTH_STUB=true`), RBAC (Admin / Analyst / Auditor / ReadOnly), Postgres RLS-enabled handlers. |
| Dev environment (docker-compose) | **PARTIAL** | `build/docker/docker-compose.dev.yml`, `build/scripts/dev-up.sh`, `build/scripts/dev-down.sh` | Infrastructure (Postgres 16, Redis 7, Kafka + Zookeeper, MinIO) fully defined with health checks and seed data. **Application services are not in docker-compose** — developers must run each binary manually after `make dev-up`. |
| LLM reasoner (optional) | **PARTIAL** | `services/llm_reasoner/app/api.py`, `services/llm_reasoner/app/providers/openai.py`, `services/llm_reasoner/app/safety/validators.py`, `services/llm_reasoner/app/safety/allowlist.py` | FastAPI service with `/reason/case-summary` and `/reason/action-recommendation`. Input sanitisation and output safety guards present. StubProvider for offline testing. **No pytest test files exist**; CI only lints with ruff. Not in docker-compose. |

---

## Blockers to ship V1 (ordered)

1. **Application services absent from dev docker-compose**
   - **What is missing:** `services/api`, `services/ingestion`, `services/pipeline`, `services/controlplane`, `services/enforcement_okta`, `services/evidence` are not defined as services in `build/docker/docker-compose.dev.yml`. A developer who runs `make dev-up` only gets infrastructure, not a running system.
   - **Files to change:** `build/docker/docker-compose.dev.yml` (add one service block per binary, mounting the compiled binary or using `build/docker/Dockerfile.go`); optionally update `build/scripts/dev-up.sh`.
   - **Verify the fix:** `make dev-up && curl -sf http://localhost:8085/healthz` (API) and repeat for each service health endpoint.
   - **Why it blocks V1:** A complete local dev loop is a V1 requirement per the build spec; QA and new engineers cannot validate the end-to-end flow without containerised services.

2. **Evidence export completeness unverified against compliance-pack spec**
   - **What is missing:** The SOC2 and ISO27001 export output fields have not been validated against the field list in `docs/compliance/soc2-iso-pack.md`. The scaffolded exporter may be missing required columns or sections.
   - **Files to change:** `services/evidence/internal/generator/export.go` (add/correct field mappings); update `services/evidence/internal/generator/export_test.go` to assert exact output schema.
   - **Verify the fix:** `go test ./services/evidence/... -v -run TestExport` and diff the output against the compliance-pack field table.
   - **Why it blocks V1:** Evidence packs are a customer-facing deliverable; an incomplete or incorrect report format will fail a SOC2/ISO27001 audit.

3. **LLM reasoner has no automated runtime tests**
   - **What is missing:** `services/llm_reasoner/` contains no `test_*.py` or `*_test.py` files. CI only lints with ruff; it does not execute any pytest coverage.
   - **Files to change:** Create `services/llm_reasoner/tests/test_api.py` and `tests/test_validators.py`; update `.github/workflows/ci.yml` `python` job to add `pytest services/llm_reasoner/ --tb=short`.
   - **Verify the fix:** `cd services/llm_reasoner && python -m pytest tests/ -v` must exit 0 in CI.
   - **Why it blocks V1:** The LLM reasoner exposes safety guardrails (input sanitisation, output validation) that must be regression-tested before production; an untested safety boundary is a ship risk.

---

## Non-blocking improvements

- **Per-service config files:** All services share a monolithic `config.Config` struct. Extracting per-service YAML configs (similar to `configs/env/pipeline.yaml`) would improve isolation and reduce misconfiguration risk.
- **Integration test harness:** The current test suite is entirely unit tests. A lightweight integration test (spawning Postgres + Kafka via `testcontainers-go`) would give higher confidence in the end-to-end Kafka → Postgres write path.
- **Redis in services:** `build/docker/docker-compose.dev.yml` provisions Redis, and the pipeline service uses it for TTL-windowed feature extraction; however, Redis health-check integration in other services' startup code is absent.
- **Infra Terraform state:** `infra/terraform/` exists but remote state backend and variable files are not committed — ensure a `backend.tf` and `terraform.tfvars.example` are present so infra changes can be reviewed in PRs.
- **Runbook cross-links:** `runbooks/` files do not reference the audit-log table or the evidence service. Adding links would help on-call engineers during incidents.
- **golangci-lint config:** `build/scripts/lint.sh` calls golangci-lint but no `.golangci.yml` config file was found in the repo root; adding one would pin linter versions and rules for reproducibility.
- **LLM reasoner not in docker-compose:** Even as optional, providing a docker-compose service block (with `OPENAI_API_KEY` env variable stub) would simplify end-to-end local demos.

---

## Validation commands (copy/paste)

```bash
# Generate protobuf Go code (service-internal)
make proto

# Generate protobuf Go code (public contracts export)
make proto-export

# Start dev infrastructure (Postgres, Redis, Kafka, MinIO)
make dev-up

# Run database migrations
make migrate

# Run all Go tests (unit)
go test ./...

# Run all Go tests with race detector
go test -race -timeout 120s ./...

# Run linter
make lint

# Seed dev database
make seed-dev

# Tear down dev infrastructure
make dev-down

# --- Per-service health checks (run after starting each binary) ---

# API service (default port 8085)
DEV_AUTH_STUB=true go run ./cmd/api &
curl -sf http://localhost:8085/healthz && echo "API OK"

# Ingestion service
go run ./cmd/ingestion &
curl -sf http://localhost:8084/healthz && echo "Ingestion OK"

# Pipeline service
go run ./cmd/pipeline &
curl -sf http://localhost:8083/healthz && echo "Pipeline OK"

# Controlplane service
go run ./cmd/controlplane &
curl -sf http://localhost:8082/healthz && echo "Controlplane OK"

# Enforcement-Okta service
go run ./cmd/enforcement-okta &
curl -sf http://localhost:8081/healthz && echo "Enforcement-Okta OK"

# Evidence service
go run ./cmd/evidence &
curl -sf http://localhost:8080/healthz && echo "Evidence OK"

# LLM Reasoner (Python, optional)
cd services/llm_reasoner && pip install -r requirements.txt && uvicorn app.api:app --port 8086 &
curl -sf http://localhost:8086/health && echo "LLM Reasoner OK"

# --- Evidence service tests ---
go test ./services/evidence/... -v

# --- Python linting ---
cd services/llm_reasoner && ruff check .

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
| Evidence pack generation | `services/evidence/internal/generator/export.go`, `services/evidence/internal/generator/generator.go`, `docs/compliance/soc2-iso-pack.md` |
| CI workflows | `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `.github/workflows/deploy-dev.yml`, `.github/workflows/deploy-prod.yml` |
| EnvelopeV1 proto | `contracts/proto/aitc/common/envelope.proto` |
| Idempotency (enforcement) | `db/migrations/postgres/0007_cases_actions.sql` (`response_actions` table), `services/enforcement_okta/internal/executor/executor.go` |
| Dev docker-compose | `build/docker/docker-compose.dev.yml`, `build/scripts/dev-up.sh` |
