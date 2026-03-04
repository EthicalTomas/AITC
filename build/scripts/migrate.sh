#!/usr/bin/env bash
set -euo pipefail

# migrate.sh — run goose migrations against the target Postgres instance.
# Step 1.4: `make migrate` must work.
# Step 0.5: Migrations include RLS setup (see 0002_rls.sql).

MIGRATIONS_DIR="${MIGRATIONS_DIR:-$(git rev-parse --show-toplevel)/db/migrations/postgres}"
DB_DSN="${POSTGRES_DSN:-postgres://aitc:aitc@localhost:5432/aitc?sslmode=disable}"

echo "Running goose migrations from: ${MIGRATIONS_DIR}"
echo "Target DSN: ${DB_DSN//:*@/:*****@}"  # redact password from log output

# Require goose binary
if ! command -v goose &>/dev/null; then
  echo "ERROR: goose not found. Install with: go install github.com/pressly/goose/v3/cmd/goose@latest"
  exit 1
fi

goose -dir "${MIGRATIONS_DIR}" postgres "${DB_DSN}" up

echo "Migrations complete."


