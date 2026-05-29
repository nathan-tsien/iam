SHELL := /bin/bash
GO    := go
BIN   := bin

.DEFAULT_GOAL := help

.PHONY: help build lint test migrate-up migrate-down generate

help: ## List targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build api and iamctl binaries
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/iam-api ./cmd/api
	$(GO) build -o $(BIN)/iamctl ./cmd/iamctl

lint: ## go vet
	$(GO) vet ./...

test: ## go test (-p 1 for shared test DB)
	$(GO) test -p 1 ./...

migrate-up: ## Apply SQL migrations (requires DATABASE_URL)
	@test -n "$$DATABASE_URL" || (echo "DATABASE_URL is required" && exit 1)
	$(GO) run github.com/pressly/goose/v3/cmd/goose@v3.24.1 -dir migrations postgres "$$DATABASE_URL" up

migrate-down: ## Roll back one migration (requires DATABASE_URL)
	@test -n "$$DATABASE_URL" || (echo "DATABASE_URL is required" && exit 1)
	$(GO) run github.com/pressly/goose/v3/cmd/goose@v3.24.1 -dir migrations postgres "$$DATABASE_URL" down

generate: ## Generate Go server from OpenAPI spec
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=api/config.yaml api/openapi.yaml
