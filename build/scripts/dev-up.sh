#!/usr/bin/env bash
set -euo pipefail
docker compose -f build/docker/docker-compose.dev.yml up -d

