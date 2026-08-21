#!/usr/bin/env bash
#
# Clean-environment verification.
#
# Runs exactly what CI runs, in the same order, from a tree with no build
# output and no installed dependencies. "Works on my machine" is a failure mode
# this script exists to eliminate: an authorization service whose test suite
# depends on a stale artifact is a test suite that can pass against code that
# no longer exists.
#
#   ./scripts/ci-verify.sh              full run, preserving untracked files
#   ./scripts/ci-verify.sh --clean      git clean -fdx first (destructive)
#
set -euo pipefail

cd "$(dirname "$0")/.."

BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m')
GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); RESET=$(printf '\033[0m')
[ -n "${NO_COLOR:-}" ] && { BOLD=""; DIM=""; GREEN=""; RED=""; RESET=""; }

DATABASE_ADMIN_URL="${DATABASE_ADMIN_URL:-postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity}"
DATABASE_URL="${DATABASE_URL:-postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity}"
export DATABASE_ADMIN_URL DATABASE_URL

step_number=0
step() {
  step_number=$((step_number + 1))
  printf '\n%s\n' "${BOLD}[$step_number/8] $1${RESET}"
}

failed() {
  printf '\n%s\n' "${RED}${BOLD}  ci-verify FAILED at step $step_number${RESET}"
  exit 1
}
trap failed ERR

printf '%s\n' "${BOLD}Scrutexity -- clean environment verification${RESET}"

if [ "${1:-}" = "--clean" ]; then
  step "git clean -fdx"
  # Keeps .env and the seeded development credentials, which are git-ignored
  # but expensive to lose and contain no secrets worth protecting.
  git clean -fdx -e .env -e .seed.local.json
else
  step "removing build output (pass --clean for a full git clean)"
  rm -rf packages/core/dist packages/sdk/dist services/api/dist apps/web/.next
  find . -name '*.tsbuildinfo' -not -path './node_modules/*' -delete
fi

step "pnpm install"
pnpm install --frozen-lockfile

step "typecheck and build"
# tsc -b emits, so this doubles as the build the tsx-run scripts need.
pnpm exec tsc -b tsconfig.build.json

step "formatting"
pnpm exec prettier --check .

step "published contracts match the code"
pnpm exec tsx scripts/generate-specs.ts --check

step "database is reachable and migrated"
if ! pg_isready -q 2>/dev/null; then
  printf '%s\n' "${DIM}  starting a local PostgreSQL cluster${RESET}"
  scripts/local-postgres.sh start
fi
pnpm exec tsx scripts/migrate.ts

step "test suite"
pnpm exec vitest run

step "treasury demo, from a clean database"
NO_COLOR=1 pnpm exec tsx scripts/demo.ts >/dev/null

trap - ERR
printf '\n%s\n\n' "${GREEN}${BOLD}  ci-verify passed${RESET}"
