# Vibecode Master Prompt — AITC (Autonomous Identity Threat Containment) Platform (Kafka + Redis + Goose)
Date: 2026-03-04  
Target: Regulated mid-market SaaS (SOC 2 + ISO 27001), US-only (v1)  
Default integrations: Okta System Log API (polling) + Microsoft 365 Unified Audit Log (UAL) (polling)  
Control plane (v1): Okta-only enforcement  
Autonomy: 7-day Learning Mode (recommend-only) → Autopilot (safe actions only)  
Streaming: **Kafka** (local docker-compose + MSK-ready wiring)  
Cache: **Redis**  
Migrations: **goose**

You are implementing the entire repo **file-by-file** under the folder structure already created.  
Follow the steps exactly. No skipped steps. No missing files. No “TODO” that breaks build.  
Every service must be secure, auditable, and operationally sane.

---

## 0) Absolute guardrails (non-negotiable)
You are building a security product. Therefore:

### 0.1 Disallowed actions (must never be implemented)
- Account deletion or automated account disablement
- Device isolation
- Network/firewall rule changes
- Production system shutdown
- Bulk user policy mutation

### 0.2 Autopilot rules
- Autopilot is **OFF by default**
- Autopilot cannot be enabled until:
  - tenant has completed ≥7 full days since onboarding start timestamp
  - tenant admin explicitly enables autopilot
- During Learning Mode (days 0–7): recommendations only; no automatic execution.

### 0.3 LLM rules (advisory only)
- LLM reasoner:
  - has **no Okta/M365 credentials**
  - cannot call internal services other than its own API endpoint
  - can only output **strict JSON** that matches a schema
  - cannot modify CAS, cannot trigger actions
- Any LLM output is treated as a note; **validator** decides actions.

### 0.4 Mandatory auditability
Every meaningful decision must be logged in an append-only audit log:
- who/what/why/when
- correlation IDs (trace_id, request_id)
- actor = service name
- before/after snapshots for policy changes (even scoped ones)

### 0.5 Tenant isolation (must be enforced everywhere)
- Every row includes `tenant_id`
- Postgres Row Level Security (RLS) is enabled and used
- Service DB connections set the tenant context (e.g., `SET app.tenant_id = ...`)

### 0.6 Idempotency and dedupe
- Ingestion: dedupe by provider event ID + tenant
- Enforcement: idempotency keys per action execution
- Kafka consumers: exactly-once is not required, but handlers must be idempotent

### 0.7 PII minimization + secret safety
- Never log tokens, auth headers, session tokens, OAuth secrets
- Redact sensitive fields from raw logs before storing normalized attributes
- Raw archive is immutable and access controlled

---

## 1) Repo-wide standards (implement first)
### 1.1 Language/runtime
- Go: 1.22+ (set in `go.mod`)
- Python: 3.12 (LLM reasoner)

### 1.2 Go libraries (choose and stick to them)
- HTTP: `net/http` + `chi` router
- Logging: `zap` (JSON)
- DB: `pgx/v5` + `pgxpool`
- Migrations: `goose` (SQL migrations)
- Metrics: Prometheus client
- Tracing: OpenTelemetry
- Kafka: `segmentio/kafka-go` (simple) OR `confluent-kafka-go` (heavier).  
  **Default: `segmentio/kafka-go`** for speed and fewer deps.

### 1.3 Service invariants (every service must have)
- `/healthz` (liveness) and `/readyz` (readiness)
- `/metrics` (Prometheus)
- structured JSON logs with request IDs
- graceful shutdown (SIGTERM)
- strict config validation on startup
- timeouts on every outbound request
- bounded memory usage (cap payload sizes)

### 1.4 Makefile targets (must exist)
- `make proto`
- `make test`
- `make lint`
- `make migrate`
- `make dev-up`
- `make dev-down`

---

## 2) Implement in the exact order below (step-by-step)

# Step 2.1 — Contracts-first: Protobuf (source of truth)
Create the Protobuf files under `contracts/proto/aitc/**`.  
They must compile with `protoc`.

### Required files
1. `contracts/proto/aitc/common/tenant.proto`
2. `contracts/proto/aitc/common/time.proto`
3. `contracts/proto/aitc/common/envelope.proto`
   - `EnvelopeV1` includes:
     - `tenant_id`
     - `message_id`
     - `schema_version` (string like `v1`)
     - `source` enum: `OKTA_SYSTEM_LOG`, `M365_UAL`, `INTERNAL`
     - `occurred_at`, `ingested_at`
     - `payload_type` (string, fully qualified)
     - `payload` (bytes)
     - `trace_id`, `span_id`, `request_id`
     - `hash_sha256` (optional)
   - Comments: PII and secret redaction requirements

4. `contracts/proto/aitc/identity/identity.proto` (IdentityV1)
5. `contracts/proto/aitc/identity/session.proto` (SessionV1 + AuthContextV1)
6. `contracts/proto/aitc/events/okta.proto` (OktaSystemLogEventV1: minimal needed fields)
7. `contracts/proto/aitc/events/m365.proto` (M365UALEventV1: minimal needed fields)
8. `contracts/proto/aitc/events/normalized_event.proto` (NormalizedEventV1 taxonomy)
9. `contracts/proto/aitc/risk/risk_signal.proto` (RiskSignalV1)
10. `contracts/proto/aitc/risk/cas.proto` (CASUpdateV1)
11. `contracts/proto/aitc/cases/case.proto` (CaseV1)
12. `contracts/proto/aitc/cases/response_action.proto` (ResponseActionV1)
13. `contracts/proto/aitc/policy/action_allowlist.proto` + `policy_decision.proto`

### Proto generation
- Add `make proto` to generate Go code into `internal/gen/aitc/**` (or `contracts/gen/go/**`).
- Generated code is committed (optional), but if not committed, CI must generate it.

---

# Step 2.2 — Database schema + RLS (goose migrations)
Create SQL migrations under `db/migrations/postgres/` using goose format.

### Tables (minimum)
- `tenants` (id, created_at, onboarding_started_at, autopilot_enabled_at, autopilot_enabled boolean, region)
- `identities`
- `sessions`
- `raw_event_refs` (S3 key + hash + source + occurred_at)
- `normalized_events`
- `risk_signals`
- `cases`
- `response_actions`
- `evidence_reports` + `evidence_items` (or a single evidence table with typed rows)
- `audit_log` (append-only)

### RLS requirements
- Enable RLS on tenant-scoped tables
- Policies enforce `tenant_id = current_setting('app.tenant_id')::text`
- Provide helper function or convention to set `app.tenant_id`
- Migration includes indexes for query patterns (identity_id, occurred_at, severity, status)

### Tools
- Use `pressly/goose/v3` from Go to run migrations.
- Provide `build/scripts/migrate.sh` and `Makefile` target `make migrate`.

---

# Step 2.3 — Shared Go packages in `internal/` (stable primitives only)
Implement these before services.

## 2.3.1 Config
- `internal/config/`: YAML loader + env override
- Config struct includes:
  - service name
  - http listen addr
  - postgres DSN
  - redis addr
  - kafka brokers + topics
  - s3 bucket names
  - okta base url + token (from Secrets Manager in prod; env in dev)
  - m365 credentials (dev only in env; prod via secrets)
- Validate required fields. Fail fast.

## 2.3.2 Logging / tracing / metrics
- `internal/logging/`: zap logger, redaction helpers
- `internal/tracing/`: OTel init; propagate trace IDs
- `internal/http/middleware/`: request ID, logging, auth extraction, tenant context injection

## 2.3.3 Tenant + RLS
- `internal/tenant/`: context helpers, `WithTenant`, `TenantFromContext`
- `internal/db/postgres/`: helper to `SET app.tenant_id` per request/transaction

## 2.3.4 Audit logging
- `internal/audit/`: append-only writer
- Must support events:
  - `IngestCheckpointUpdated`
  - `RiskSignalEmitted`
  - `CaseCreated/Updated/Closed`
  - `ActionProposed/Validated/Rejected/Executed/Failed/RolledBack`
  - `AutonomyStateChanged`
  - `ComplianceReportGenerated`

## 2.3.5 Kafka stream wrapper
- `internal/stream/kafka/`: producer/consumer for EnvelopeV1
- Requirements:
  - consumer groups
  - retry strategy
  - DLQ topic naming convention `{topic}.dlq`
  - max message size and timeouts
  - idempotent handler pattern

## 2.3.6 Provider clients
- `internal/okta/`:
  - System Log polling client
  - strict timeouts, retry/backoff, rate limit handling
- `internal/m365/`:
  - UAL polling client
  - strict timeouts, paging, watermark

## 2.3.7 Redis windows
- `internal/redis/` optional helper:
  - short-term windows for MFA fatigue counts etc.
  - TTL-based keys
  - tenant scoping in keys

---

# Step 2.4 — Services (deployables) — implement in this order
## A) `cmd/ingestion` + `services/ingestion/**`
Single deployable, two poller workers (Okta + M365) in one binary.

### Okta poller
- Uses System Log API polling
- Maintains watermark checkpoint per tenant
- Backfill capability
- Writes raw events to S3:
  - partitioned by tenant + date/hour
  - store raw JSON as received (or minimally wrapped)
- Publishes EnvelopeV1 messages to Kafka topic `raw-events`

### M365 UAL poller
- Poll UAL with watermark
- Publishes EnvelopeV1 with source=M365_UAL to `raw-events`
- UI must later show watermark lag due to UAL delays

## B) `cmd/pipeline` + `services/pipeline/**`
Consumes `raw-events`, produces normalized events, features, and risk signals.

- Normalize into NormalizedEventV1 (protobuf payload inside EnvelopeV1)
- Persist normalized events + raw refs to Postgres
- Extract features + update baselines
- CAS scoring rules (v0 deterministic)
- Emit RiskSignalV1 on Kafka topic `risk-signals`
- Create/attach cases in Postgres

## C) `cmd/controlplane` + `services/controlplane/**`
Consumes `risk-signals`, manages learning mode, creates recommendations, validates actions.

- Autonomy state machine:
  - tenant onboarding started timestamp
  - 7-day learning mode enforced
  - admin can enable autopilot only after 7 days
- Policy validator:
  - allowlisted actions only
  - disallowed list enforced
  - blast radius constraints (break-glass exclusion)
- Create ResponseActionV1 records:
  - recommendations topic: `action-recommendations`
  - validated execution requests topic: `action-requests` (only when manual execute OR autopilot allowed)

## D) `cmd/enforcement-okta` + `services/enforcement_okta/**`
Consumes `action-requests` and executes Okta Management API calls.

- Allowed actions:
  - revoke sessions
  - MFA step-up via policy change (scoped)
  - scoped sign-on policy adjustment
- Must log before/after state for policy adjustments
- Must enforce idempotency

## E) `cmd/evidence` + `services/evidence/**`
Generates SOC2/ISO packs from Postgres data.

- Exports JSON/CSV
- Optional PDF (if used, keep as separate container/service like gotenberg OR simple HTML->PDF lib)
- Archives to S3 (versioned + immutable)

## F) `cmd/api` + `services/api/**`
Console/admin API.

Endpoints (minimum):
- list identities/sessions/cases
- view case detail + timeline
- list recommendations
- execute recommendation (manual) → goes to validator → action-requests
- enable autopilot (only after 7 days + explicit confirmation)
- generate/download evidence packs

AuthN: Okta OIDC for your console users  
AuthZ: RBAC roles (Admin/Analyst/Auditor/ReadOnly)

## G) `cmd/llm-reasoner` + `services/llm_reasoner/**` (feature-flag)
FastAPI service:
- POST `/reason/case-summary`
- strict JSON schema output
- no credentials to other systems
- logs redacted

---

# Step 2.5 — Policies and configuration artifacts
- `contracts/json/policy/action_allowlist.v1.json`
- `contracts/json/policy/disallowed_actions.v1.json`
- `configs/policies/tenant_overrides.example.json`
- default policy validator loads these at startup

---

# Step 2.6 — Local development environment
Create `build/docker/docker-compose.dev.yml` to run:
- Postgres
- Redis
- Kafka + Zookeeper (or Kraft mode; pick one and document it)
- MinIO (S3-compatible) for dev raw/report archives
- All services (optional) or at least dependencies + one service at a time

Provide:
- `build/scripts/dev-up.sh`, `dev-down.sh`
- seed scripts under `db/seeds/dev/`

---

# Step 2.7 — CI/CD (GitHub Actions)
Workflows:
- `ci.yml`: proto generation check, `go test`, lint, python checks
- `security.yml`: CodeQL + dependency scanning
- Optional: container build

CI must fail if:
- generated protos out of date
- migrations are invalid
- lint fails
- tests fail

---

# Step 2.8 — Test requirements (no skipping)
- Unit tests for scoring rules:
  - impossible travel
  - MFA fatigue
  - mailbox rule
- Integration tests:
  - learning mode gate (autopilot cannot enable early)
  - policy validator blocks disallowed actions
  - enforcement idempotency
  - ingestion checkpoint correctness
- Provide sample events in `tools/data/`

---

## 3) Kafka topic contract (standardize now)
Define topics (name + payload type):
- `raw-events`: EnvelopeV1 with payload OktaSystemLogEventV1 or M365UALEventV1
- `normalized-events`: EnvelopeV1 payload NormalizedEventV1 (optional if you persist only)
- `risk-signals`: EnvelopeV1 payload RiskSignalV1
- `action-recommendations`: EnvelopeV1 payload ResponseActionV1 (mode=RECOMMENDED)
- `action-requests`: EnvelopeV1 payload ResponseActionV1 (mode=MANUAL_EXECUTED or AUTOPILOT_EXECUTED)
- `{topic}.dlq`: dead-letter envelopes with error metadata in attributes

---

## 4) Output requirements (how you will write files)
When generating each file:
- Output full file contents
- No missing imports
- Must compile in isolation with repo
- Keep functions small and testable
- Include security comments around sensitive code

---

## 5) Definition of Done (market-ready v1)
The platform is “market-ready v1” when:
- `make proto && make migrate && make test && make lint` succeed
- services start locally with docker-compose dependencies
- learning mode is enforced
- all actions go through validator and are audited
- evidence pack generates and archives
- LLM reasoner cannot execute actions and has no creds

---

## 6) Begin coding now (no more questions)
Start implementing **Step 2.1 (Protobuf contracts)** and continue strictly in order.

When you finish Step 2.1, output:
- the full contents of each `.proto` file
- the `Makefile` additions for proto generation
- the folder where generated Go code lands
- a brief note verifying compilation commands for protos

Then proceed to Step 2.2 (goose migrations).
