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

.PHONY: adversarial
adversarial: build ## Run the adversarial conformance suite (12 security invariants)
	# Not an alias for a subset of the unit tests. Each scenario mounts a real
	# attack through the public API against a real database, and reports
	# whether the invariant held, whether the provider was contacted, and what
	# evidence was produced. Exits non-zero if any invariant fails.
	pnpm exec tsx scripts/adversarial.ts

.PHONY: recovery
recovery: build ## Kill the API mid-payment and prove what survived
	# Runs the API as a real child process and destroys it with SIGKILL at two
	# instants: after the execution claim commits but before any money moves,
	# and after the money moves but before settlement is recorded. A different
	# process then retries against the same database. The adversarial suite's
	# A9 and A10 assert the same invariants against rewound state; this proves
	# a real crash produces that state. Exits non-zero if any invariant fails.
	pnpm exec tsx scripts/recovery.ts

.PHONY: test
test: ## Run every test
	pnpm exec vitest run

.PHONY: test-unit
test-unit: ## Run the pure-domain tests (no database required)
	# Its own configuration, with no globalSetup, so "no database required" is
	# enforced rather than described. CI's first job runs exactly this line in a
	# container with no PostgreSQL.
	pnpm exec vitest run --config vitest.unit.config.ts

.PHONY: typecheck
typecheck: ## Typecheck every package, sources and tests
	# Both passes, matching CI exactly. tsconfig.build.json excludes test files,
	# so a type error in a test escaped `make lint` entirely and only surfaced
	# in CI. A local gate that is weaker than the remote one is not a gate.
	pnpm run typecheck

.PHONY: fmt
fmt: ## Format
	pnpm exec prettier --write .

.PHONY: lint
lint: ## Check formatting, types and contract drift
	pnpm exec prettier --check .
	pnpm run typecheck
	pnpm exec tsx scripts/generate-specs.ts --check
	pnpm exec tsx scripts/generate-canonicalization-vectors.ts --check
	# The demo and the seed must reach the control plane the way a partner does.
	# Four defects came from fixtures taking a shortcut the public API lacks.
	scripts/check-public-path.sh

.PHONY: ci-status
ci-status: ## Ask GitHub Actions whether this branch is actually green
	# `make ci` says the suite passes HERE. This says whether it passed where
	# it counts, and prints the run URL to cite instead of the word "green".
	# The two disagreed for the first fourteen runs of this repository.
	scripts/ci-status.sh

.PHONY: onboarding
onboarding: ## Run docs/design-partner/onboarding.md exactly as a partner would
	# The suite exercises the endpoints through an in-process harness, which is
	# why it never noticed that the guide's step 2 produced a file jq refused to
	# parse. This runs the shell a partner copies.
	scripts/onboarding-check.sh

.PHONY: bench
bench: ## Measure decision and enforcement latency against a real database
	# Deliberately not part of `make ci`: the numbers depend on the machine, so
	# a CI threshold would either be so loose it proves nothing or so tight it
	# fails on a noisy runner. Run it, read it, and put the numbers in a doc.
	pnpm exec tsx scripts/bench.ts

.PHONY: spec
spec: ## Regenerate the OpenAPI and policy schema from the code
	pnpm exec tsx scripts/generate-specs.ts

.PHONY: keys
keys: ## Generate a development receipt signing key
	@openssl genpkey -algorithm ed25519 | base64 -w0 > .signing-key.local
	@echo "RECEIPT_SIGNING_KEY_B64=$$(cat .signing-key.local)"
	@echo "(development only; production keys come from a secret manager)"

.PHONY: ci
ci: install lint test build demo adversarial recovery onboarding ## Everything CI runs
