# AITC

**Autonomous Identity Threat Containment** — a Kafka-powered, SOC2/ISO27001-ready identity security platform.

---

## Architecture

| Service | Port | Role |
|---|---|---|
| `ingestion` | 8080 | Okta + M365 pollers → `raw-events` Kafka topic |
| `pipeline` | 8081 | Normalization, CAS scoring → `risk-signals` topic |
| `enforcement-okta` | 8083 | Okta action executor (Kafka consumer) |
| `controlplane` | 8084 | Learning-mode gate, autopilot, policy validation |
| `api` | 8085 | Console API (chi router, RBAC, Okta OIDC) |
| `evidence` | 8086 | SOC2/ISO27001 report generator |
| `llm-reasoner` | 8087 | Advisory LLM reasoning (optional, stub mode by default) |

Infrastructure: Postgres 16, Redis 7, Kafka (Confluent 7.6 + Zookeeper), MinIO.

---

## Quick start (local dev)

### Prerequisites

- Docker + Docker Compose v2
- Go 1.22+
- Python 3.12 (for LLM reasoner tests only)

### 1. Start all services

```bash
make dev-up
```

This builds and starts infrastructure **and** all application services in Docker.
On the first run, Docker will build the Go binaries (a few minutes); subsequent starts are fast.

### 2. Run database migrations

```bash
make migrate
```

### 3. Seed dev data

```bash
make seed-dev
```

### 4. Verify health

```bash
curl -sf http://localhost:8080/healthz && echo "ingestion OK"
curl -sf http://localhost:8081/healthz && echo "pipeline OK"
curl -sf http://localhost:8083/healthz && echo "enforcement-okta OK"
curl -sf http://localhost:8084/healthz && echo "controlplane OK"
curl -sf http://localhost:8085/healthz && echo "api OK"
curl -sf http://localhost:8086/healthz && echo "evidence OK"
curl -sf http://localhost:8087/healthz && echo "llm-reasoner OK"
```

### 5. Tear down

```bash
make dev-down
```

---

## Development

### Build

```bash
make build        # go build ./...
```

### Test

```bash
make test         # go test -race -timeout=120s ./...
```

### Lint

```bash
make lint         # golangci-lint + ruff
```

### Proto generation

```bash
make proto        # generate internal/gen/
make proto-export # generate contracts/gen/go/
```

---

## LLM Reasoner (optional)

The LLM reasoner starts automatically in **stub mode** (no API key required).
To enable real reasoning, set `OPENAI_API_KEY` before running `make dev-up`:

```bash
export OPENAI_API_KEY=sk-...   # loaded from your secrets manager; never commit
export LLM_PROVIDER=openai
make dev-up
```

To run LLM reasoner tests locally:

```bash
cd services/llm_reasoner
pip install -r requirements.txt
LLM_PROVIDER=stub python -m pytest tests/ -v
```

---

## Configuration

Per-service YAML configs live in `configs/env/`. Environment variables set in
`docker-compose.dev.yml` override the `localhost` defaults in those files so
services find each other inside the Docker network.

---

## Compliance

See `docs/compliance/soc2-iso-pack.md` for the SOC2/ISO27001 evidence pack spec and
`docs/audits/v1-readiness-audit.md` for the V1 readiness audit results.
