SHELL := /bin/bash
GO    := go
BIN   := bin
ENV   := .env

# Load .env if it exists (for dev targets)
ifneq (,$(wildcard $(ENV)))
  include $(ENV)
  export
endif

.DEFAULT_GOAL := help

.PHONY: help build lint test dev db-setup migrate-up migrate-down generate clean

help: ## List targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build api and iamctl binaries
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/iam-api ./cmd/api
	$(GO) build -o $(BIN)/iamctl ./cmd/iamctl

lint: ## go vet
	$(GO) vet ./...

test: ## Run all tests (requires TEST_DATABASE_URL or local Postgres)
	$(GO) test -p 1 ./...

dev: ## Start dev server (loads .env, auto-runs migrations)
	@test -f $(ENV) || (echo "$(ENV) not found — copy from .env.example" && exit 1)
	@$(MAKE) --no-print-directory migrate-up
	$(GO) run ./cmd/api/

db-setup: ## Create IAM schema + run migrations (one-time setup)
	@test -f $(ENV) || (echo "$(ENV) not found" && exit 1)
	@echo "Creating schema if not exists..."
	@docker exec infra-postgres-1 psql -U postgres -d $${DATABASE_URL##*/} -c "CREATE SCHEMA IF NOT EXISTS $${DATABASE_SCHEMA:-iam};" 2>/dev/null || true
	@$(MAKE) --no-print-directory migrate-up

migrate-up: ## Apply SQL migrations (reads DATABASE_URL from .env)
	@test -f $(ENV) && test -n "$$DATABASE_URL" || (echo "DATABASE_URL required (set in $(ENV))" && exit 1)
	$(GO) run github.com/pressly/goose/v3/cmd/goose@v3.24.1 -dir migrations postgres "$$DATABASE_URL" up

migrate-down: ## Roll back one migration (reads DATABASE_URL from .env)
	@test -f $(ENV) && test -n "$$DATABASE_URL" || (echo "DATABASE_URL required (set in $(ENV))" && exit 1)
	$(GO) run github.com/pressly/goose/v3/cmd/goose@v3.24.1 -dir migrations postgres "$$DATABASE_URL" down

generate: ## Generate Go server from OpenAPI spec
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=api/config.yaml api/openapi.yaml

clean: ## Remove built binaries
	rm -rf $(BIN)
