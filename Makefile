.PHONY: proto build test lint migrate seed-dev dev-up dev-down

# Step 1.4: proto — generate Go code from all .proto files under contracts/proto/
proto:
	@echo "Generating protobuf Go code..."
	@mkdir -p internal/gen
	@find contracts/proto -name "*.proto" | xargs protoc \
		--proto_path=contracts/proto \
		--proto_path=vendor/proto \
		--go_out=internal/gen \
		--go_opt=paths=source_relative \
		2>/dev/null || (echo "WARNING: protoc not found; run: apt-get install protobuf-compiler && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; exit 0)

build:
	go build ./...

# Step 1.4: test
test:
	go test ./...

# Step 1.4: lint
lint:
	bash build/scripts/lint.sh

# Step 1.4: migrate
migrate:
	bash build/scripts/migrate.sh

seed-dev:
	bash build/scripts/seed-dev.sh

# Step 1.4: dev-up
dev-up:
	bash build/scripts/dev-up.sh

# Step 1.4: dev-down
dev-down:
	bash build/scripts/dev-down.sh


