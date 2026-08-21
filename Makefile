# Scrutexity — development entry points.
#
# `make dev` brings up everything. `make demo` runs the whole treasury story
# from a clean database and asserts every scene, so a broken demo is a failing
# build rather than a bad slide.

SHELL := /bin/bash
.DEFAULT_GOAL := help

DATABASE_ADMIN_URL ?= postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity
DATABASE_URL       ?= postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity
export DATABASE_ADMIN_URL
export DATABASE_URL

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install workspace dependencies
	pnpm install

.PHONY: build
build: ## Compile the workspace packages
	# The scripts below import @scrutexity/core the same way the container
	# image does -- through the package entry point, which is compiled output.
	# Tests do not need this (they alias to source); anything run with tsx does.
	pnpm exec tsc -b tsconfig.build.json

.PHONY: up
up: ## Start Postgres (docker compose, or a local cluster if the daemon is absent)
	@if docker info >/dev/null 2>&1; then \
	  docker compose up -d postgres; \
	  echo "waiting for postgres..."; \
	  until docker compose exec -T postgres pg_isready -q; do sleep 1; done; \
	else \
	  echo "docker daemon unavailable; using the local PostgreSQL cluster"; \
	  scripts/local-postgres.sh start; \
	fi

.PHONY: down
down: ## Stop the local stack
	@docker compose down 2>/dev/null || scripts/local-postgres.sh stop

.PHONY: migrate
migrate: ## Apply pending migrations
	pnpm exec tsx scripts/migrate.ts

.PHONY: reset
reset: ## Drop and recreate the schema, then migrate
	pnpm exec tsx scripts/migrate.ts --reset

.PHONY: seed
seed: build ## Seed the reference tenant and write development credentials
	pnpm exec tsx scripts/seed.ts

.PHONY: dev
dev: install build up reset seed ## Bring up the full local environment
	@echo ""
	@echo "  database  ready"
	@echo "  tenant    seeded (credentials in .seed.local.json)"
	@echo ""
	@echo "  run the API:        make api"
	@echo "  run the dashboard:  make web"
	@echo "  run the demo:       make demo"
	@echo ""

.PHONY: api
api: ## Run the control plane with reload
	pnpm exec tsx watch services/api/src/server.ts

.PHONY: web
web: ## Run the dashboard
	pnpm --filter @scrutexity/web dev

.PHONY: demo
demo: build ## Run the full treasury demo from a clean database
	pnpm exec tsx scripts/demo.ts

.PHONY: test
test: ## Run every test
	pnpm exec vitest run

.PHONY: test-unit
test-unit: ## Run the pure-domain tests (no database required)
	pnpm exec vitest run packages

.PHONY: typecheck
typecheck: ## Typecheck every package
	pnpm exec tsc -b tsconfig.build.json

.PHONY: fmt
fmt: ## Format
	pnpm exec prettier --write .

.PHONY: lint
lint: ## Check formatting, types and contract drift
	pnpm exec prettier --check .
	pnpm exec tsc -b tsconfig.build.json
	pnpm exec tsx scripts/generate-specs.ts --check

.PHONY: spec
spec: ## Regenerate the OpenAPI and policy schema from the code
	pnpm exec tsx scripts/generate-specs.ts

.PHONY: keys
keys: ## Generate a development receipt signing key
	@openssl genpkey -algorithm ed25519 | base64 -w0 > .signing-key.local
	@echo "RECEIPT_SIGNING_KEY_B64=$$(cat .signing-key.local)"
	@echo "(development only; production keys come from a secret manager)"

.PHONY: ci
ci: install lint test build demo ## Everything CI runs
