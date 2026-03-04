.PHONY: proto proto-export build test lint migrate seed-dev dev-up dev-down

PROTO_FILES := $(shell find contracts/proto -name "*.proto")

# proto — generate Go code into internal/gen (service-internal generated code)
proto:
	@echo "Generating protobuf Go code (internal/gen)..."
	@which protoc > /dev/null 2>&1 || (echo "ERROR: protoc not found. Install with: sudo apt-get install protobuf-compiler && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" && exit 1)
	@which protoc-gen-go > /dev/null 2>&1 || (echo "ERROR: protoc-gen-go not found. Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" && exit 1)
	@mkdir -p internal/gen
	@find contracts/proto -name "*.proto" | xargs protoc \
		--proto_path=contracts/proto \
		--go_out=internal/gen \
		--go_opt=paths=source_relative

# proto-export — generate Go code into contracts/gen/go (public/exported generated code)
proto-export:
	@echo "Generating protobuf Go code (contracts/gen/go)..."
	@which protoc > /dev/null 2>&1 || (echo "ERROR: protoc not found. Install with: sudo apt-get install protobuf-compiler && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" && exit 1)
	@which protoc-gen-go > /dev/null 2>&1 || (echo "ERROR: protoc-gen-go not found. Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" && exit 1)
	@mkdir -p contracts/gen/go
	@find contracts/proto -name "*.proto" | xargs protoc \
		--proto_path=contracts/proto \
		--go_out=contracts/gen/go \
		--go_opt=paths=source_relative

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


