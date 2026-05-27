SHELL := /bin/bash
GO    := go

.DEFAULT_GOAL := help

.PHONY: help build lint test migrate-up

help: ## List targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## go build
	$(GO) build ./...

lint: ## go vet (gofmt diff + golangci-lint when added)
	$(GO) vet ./...

test: ## go test (-p 1 for shared test DB once code lands)
	$(GO) test ./...

migrate-up: ## placeholder; populated when migrations/ has SQL
	@echo "no migrations yet"
