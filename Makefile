SHELL := /bin/bash
GO    := go

.DEFAULT_GOAL := help

.PHONY: help build lint test migrate-up

help: ## List targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## go build
	@if [ -z "$$($(GO) list ./... 2>/dev/null)" ]; then echo "no Go packages yet"; else $(GO) build ./...; fi

lint: ## go vet (gofmt diff + golangci-lint when added)
	@if [ -z "$$($(GO) list ./... 2>/dev/null)" ]; then echo "no Go packages yet"; else $(GO) vet ./...; fi

test: ## go test (-p 1 for shared test DB once code lands)
	@if [ -z "$$($(GO) list ./... 2>/dev/null)" ]; then echo "no Go packages yet"; else $(GO) test ./...; fi

migrate-up: ## placeholder; populated when migrations/ has SQL
	@echo "no migrations yet"
