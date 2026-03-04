.PHONY: build test lint migrate seed-dev dev-up dev-down

build:
go build ./...

test:
go test ./...

lint:
bash build/scripts/lint.sh

migrate:
bash build/scripts/migrate.sh

seed-dev:
bash build/scripts/seed-dev.sh

dev-up:
bash build/scripts/dev-up.sh

dev-down:
bash build/scripts/dev-down.sh

