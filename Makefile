.PHONY: help build run-provider run-client run clean test

OS := $(shell uname | awk '{print tolower($$0)}')
ARCH := $(shell case $$(uname -m) in (x86_64) echo amd64 ;; (aarch64|arm64) echo arm64 ;; (*) echo $$(uname -m) ;; esac)
BIN_DIR := ./bin
ATLAS_VERSION := 0.34.0
SQLC_VERSION := 1.30.0

# Platform-specific binary names
ifeq ($(OS),darwin)
	ATLAS_PLATFORM := darwin
	SQLC_PLATFORM := darwin
else ifeq ($(OS),linux)
	ATLAS_PLATFORM := linux
	SQLC_PLATFORM := linux
else
	ATLAS_PLATFORM := $(OS)
	SQLC_PLATFORM := $(OS)
endif

ATLAS := $(abspath $(BIN_DIR)/atlas)
SQLC := $(abspath $(BIN_DIR)/sqlc)

# Default target
help:
	@echo "Available commands:"
	@echo ""
	@echo "Application:"
	@echo "  build        - Build IdP, RP, and RP2 binaries"
	@echo "  run          - Run all servers (IdP, RP, RP2) in background"
	@echo "  run-idp      - Run OIDC Provider (IdP) on port 8080"
	@echo "  run-rp       - Run OIDC Client (RP/Push) on port 8081"
	@echo "  run-rp2      - Run OIDC Client (RP2/Poll) on port 8082"
	@echo "  stop         - Stop all running servers"
	@echo "  demo         - Run complete demo (build + run + open browser)"
	@echo ""
	@echo "Database:"
	@echo "  db-start          - Start PostgreSQL (docker compose)"
	@echo "  db-setup          - Complete setup (migrate + generate code)"
	@echo "  db-migrate        - Create migrations from schema changes (all DBs)"
	@echo "  db-migrate-apply  - Apply pending migrations (all DBs)"
	@echo "  sqlc-gen          - Regenerate Go code from queries"
	@echo ""
	@echo "Development:"
	@echo "  test         - Run tests"
	@echo "  fmt          - Format code"
	@echo "  clean        - Clean build artifacts"

# Build binaries
build:
	@echo "Building IdP (OIDC Provider)..."
	@go build -o bin/idp ./idp/cmd
	@echo "Building RP (OIDC Client - Push)..."
	@go build -o bin/rp ./rp/cmd
	@echo "Building RP2 (OIDC Client - Poll)..."
	@go build -o bin/rp2 ./rp2/cmd
	@echo "Build complete!"

# Run IdP (OIDC Provider)
run-idp:
	@echo "Starting IdP on http://localhost:8080"
	@go run idp/cmd/main.go

# Run RP (OIDC Client - Push)
run-rp:
	@echo "Starting RP (Push) on http://localhost:8081"
	@go run rp/cmd/main.go

# Run RP2 (OIDC Client - Poll)
run-rp2:
	@echo "Starting RP2 (Poll) on http://localhost:8082"
	@go run rp2/cmd/main.go

# Backward compatibility aliases
run-provider: run-idp
run-client: run-rp

# Run all servers in background (IdP + RP + RP2)
run:
	@echo "Starting IdP in background..."
	@go run idp/cmd/main.go &
	@sleep 2
	@echo "Starting RP (Push) in background..."
	@go run rp/cmd/main.go &
	@sleep 2
	@echo "Starting RP2 (Poll) in background..."
	@go run rp2/cmd/main.go &
	@sleep 2
	@echo "All servers are running!"
	@echo "IdP (OIDC Provider): http://localhost:8080"
	@echo "RP (Push):           http://localhost:8081"
	@echo "RP2 (Poll):          http://localhost:8082"
	@echo ""
	@echo "To stop servers, run: make stop"

# Stop all running servers
stop:
	@echo "Stopping all servers..."
	@pkill -f "go run idp/cmd/main.go" || true
	@pkill -f "go run rp/cmd/main.go" || true
	@pkill -f "go run rp2/cmd/main.go" || true
	@pkill -f "bin/idp" || true
	@pkill -f "bin/rp" || true
	@pkill -f "bin/rp2" || true
	@# Kill processes by port if they're still running
	@lsof -ti :8080 | xargs kill -9 2>/dev/null || true
	@lsof -ti :8081 | xargs kill -9 2>/dev/null || true
	@lsof -ti :8082 | xargs kill -9 2>/dev/null || true
	@echo "Servers stopped."

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@echo "Clean complete!"

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Complete demo
demo: build stop
	@echo "Starting OIDC Demo..."
	@echo ""
	@bin/idp &
	@echo "IdP started on http://localhost:8080"
	@sleep 2
	@bin/rp &
	@echo "RP started on http://localhost:8081"
	@sleep 2
	@echo ""
	@echo "Opening browser..."
	@which open > /dev/null && open http://localhost:8081 || echo "Please open http://localhost:8081 in your browser"
	@echo ""
	@echo "Demo Instructions:"
	@echo "1. Click 'OIDC Login' button"
	@echo "2. Enter any username/password on the login page"
	@echo "3. View your profile and token information"
	@echo ""
	@echo "To stop the demo, run: make stop"

# Development helpers
dev-idp:
	@echo "Starting IdP in development mode with hot reload..."
	@which air > /dev/null && air -c .air-idp.toml || go run idp/cmd/main.go

dev-rp:
	@echo "Starting RP in development mode with hot reload..."
	@which air > /dev/null && air -c .air-rp.toml || go run rp/cmd/main.go

# Check dependencies
deps:
	@echo "Installing/updating dependencies..."
	@go mod tidy
	@go mod download

# Lint code
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null && golangci-lint run || echo "golangci-lint not installed"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Check for common issues
check: fmt lint test
	@echo "All checks passed!"

.PHONY: atlas
atlas: $(ATLAS)
$(ATLAS):
	@mkdir -p $(BIN_DIR)
	@echo "Downloading Atlas for $(ATLAS_PLATFORM)-$(ARCH)..."
	@curl -sSfL "https://release.ariga.io/atlas/atlas-$(ATLAS_PLATFORM)-$(ARCH)-v$(ATLAS_VERSION)" -o $(ATLAS)
	@chmod +x $(ATLAS)
	@echo "Atlas installed at $(ATLAS)"

# Database commands
.PHONY: db-setup db-migrate db-migrate-apply sqlc-gen

# Start PostgreSQL (creates databases via init script)
db-start:
	@docker compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@sleep 3

# Setup all databases (create migration + apply + generate code)
db-setup: atlas $(SQLC)
	@mkdir -p idp/db/postgres/migrations rp/db/postgres/migrations rp2/db/postgres/migrations
	@echo "=== Creating IdP migration ==="
	@$(ATLAS) migrate diff --env local --var target=idp || echo "Migration already exists or no changes"
	@echo "=== Creating RP migration ==="
	@$(ATLAS) migrate diff --env local --var target=rp || echo "Migration already exists or no changes"
	@echo "=== Creating RP2 migration ==="
	@$(ATLAS) migrate diff --env local --var target=rp2 || echo "Migration already exists or no changes"
	@echo "=== Applying all migrations ==="
	@$(ATLAS) migrate apply --env local --var target=idp
	@$(ATLAS) migrate apply --env local --var target=rp
	@$(ATLAS) migrate apply --env local --var target=rp2
	@echo "=== Generating Go code ==="
	@$(SQLC) generate
	@echo "All databases ready!"

# Create new migrations from schema changes (all databases)
db-migrate: atlas
	@mkdir -p idp/db/postgres/migrations rp/db/postgres/migrations rp2/db/postgres/migrations
	@echo "=== Creating IdP migration ==="
	@$(ATLAS) migrate diff --env local --var target=idp || echo "No changes"
	@echo "=== Creating RP migration ==="
	@$(ATLAS) migrate diff --env local --var target=rp || echo "No changes"
	@echo "=== Creating RP2 migration ==="
	@$(ATLAS) migrate diff --env local --var target=rp2 || echo "No changes"

# Apply pending migrations (all databases)
db-migrate-apply: atlas
	@echo "=== Applying IdP migrations ==="
	@$(ATLAS) migrate apply --env local --var target=idp
	@echo "=== Applying RP migrations ==="
	@$(ATLAS) migrate apply --env local --var target=rp
	@echo "=== Applying RP2 migrations ==="
	@$(ATLAS) migrate apply --env local --var target=rp2
	@echo "All migrations applied!"

# Regenerate Go code from queries
$(SQLC):
	@mkdir -p $(BIN_DIR)
	@echo "Downloading sqlc for $(SQLC_PLATFORM)-$(ARCH)..."
	@curl -sSfL "https://downloads.sqlc.dev/sqlc_$(SQLC_VERSION)_$(SQLC_PLATFORM)_$(ARCH).tar.gz" | tar -xz -C $(BIN_DIR) sqlc
	@chmod +x $(SQLC)
	@echo "sqlc installed at $(SQLC)"

sqlc-gen: $(SQLC)
	@$(SQLC) generate
	@echo "Go code generated!"

# Benchmark commands
.PHONY: bench-build bench-receiver bench-setup bench-emit bench-poll bench-analyze bench-clean

bench-build:
	@echo "Building benchmark tools..."
	@go build -o bin/receiver ./benchmark/cmd/receiver
	@go build -o bin/driver ./benchmark/cmd/driver
	@echo "Benchmark tools built!"

bench-receiver:
	@echo "Starting Mock SET Receiver on :9090..."
	@bin/receiver -port 9090 -log benchmark/results/receive.jsonl

bench-setup:
	@echo "Setting up benchmark test data..."
	@bin/driver setup -rps $(RPS) -users $(USERS) -mode $(MODE) -receiver-url $(RECEIVER_URL) -idp-url $(IDP_URL) -tokens-file benchmark/results/tokens.json

bench-emit:
	@echo "Emitting events..."
	@bin/driver emit -concurrency $(CONCURRENCY) -idp-url $(IDP_URL)

bench-poll:
	@echo "Starting Poll benchmark..."
	@bin/driver poll -tokens benchmark/results/tokens.json -timeout $(POLL_TIMEOUT) -log benchmark/results/poll.jsonl -idp-url $(IDP_URL)

bench-analyze:
	@echo "Analyzing results..."
	@bin/driver analyze -log benchmark/results/receive.jsonl

bench-clean:
	@echo "Cleaning up benchmark data..."
	@bin/driver cleanup
	@rm -f benchmark/results/receive.jsonl benchmark/results/poll.jsonl benchmark/results/tokens.json

# Default values for benchmark
RPS ?= 5
USERS ?= 100
MODE ?= push
CONCURRENCY ?= 10
POLL_TIMEOUT ?= 60s
RECEIVER_URL ?= http://localhost:9090
IDP_URL ?= http://localhost:8080

# =============================================================================
# Cloud Benchmark
# =============================================================================
.PHONY: bench-cloud-setup bench-cloud-emit bench-cloud-poll bench-cloud-logs

# Cloud URLs (get from terraform output or set manually)
CLOUD_IDP_URL ?= $(shell cd terraform/dev/gcp && terraform output -raw cloud_run_url 2>/dev/null || echo "https://ssf-oidc-provider-dev-XXXXX.asia-northeast1.run.app")
CLOUD_RECEIVER_URL ?= $(shell cd terraform/dev/gcp && terraform output -raw cloud_run_bench_receiver_url 2>/dev/null || echo "https://ssf-bench-receiver-dev-XXXXX.asia-northeast1.run.app")

bench-cloud-setup:
	@echo "Setting up benchmark data on cloud IdP (via DB tunnel)..."
	@echo "Make sure ./scripts/db-tunnel.sh is running in another terminal"
	bin/driver setup \
		-rps $(RPS) \
		-users $(USERS) \
		-mode $(MODE) \
		-receiver-url $(CLOUD_RECEIVER_URL) \
		-idp-url $(CLOUD_IDP_URL) \
		-db "postgres://ssf-app:$$(gcloud secrets versions access latest --secret=ssf-db-password-dev)@127.0.0.1:5432/idp?sslmode=disable" \
		-tokens-file benchmark/results/tokens.json

bench-cloud-emit:
	@echo "Emitting events to cloud IdP..."
	bin/driver emit \
		-idp-url $(CLOUD_IDP_URL) \
		-db "postgres://ssf-app:$$(gcloud secrets versions access latest --secret=ssf-db-password-dev)@127.0.0.1:5432/idp?sslmode=disable" \
		-concurrency $(CONCURRENCY)

bench-cloud-poll:
	@echo "Starting Poll benchmark against cloud IdP..."
	bin/driver poll \
		-idp-url $(CLOUD_IDP_URL) \
		-tokens benchmark/results/tokens.json \
		-timeout $(POLL_TIMEOUT) \
		-log benchmark/results/poll.jsonl

bench-cloud-logs:
	@echo "Downloading logs from Cloud Logging..."
	./scripts/bench-cloud-logs.sh benchmark/results/receive.jsonl $(LOGS_SINCE)

# Default for cloud logs
LOGS_SINCE ?= 1h
