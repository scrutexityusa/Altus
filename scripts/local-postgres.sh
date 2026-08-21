#!/usr/bin/env bash
# Starts a local PostgreSQL cluster when the Docker daemon is unavailable
# (CI runners, restricted sandboxes). Same database, same roles, same RLS.
set -euo pipefail

VERSION="${PG_VERSION:-16}"
CLUSTER="${PG_CLUSTER:-main}"

start() {
  if ! pg_isready -q 2>/dev/null; then
    pg_ctlcluster "$VERSION" "$CLUSTER" start 2>/dev/null || service postgresql start
    for _ in $(seq 1 30); do pg_isready -q && break; sleep 1; done
  fi

  su postgres -c "psql -v ON_ERROR_STOP=1 -q" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='scrutexity_owner') THEN
    -- CREATEDB so the test suite can provision a throwaway database per run.
    -- In CI the owner is the container's superuser and already has it; locally
    -- it must be granted, or `vitest run` cannot isolate itself.
    CREATE ROLE scrutexity_owner LOGIN CREATEDB PASSWORD 'scrutexity';
  ELSE
    ALTER ROLE scrutexity_owner CREATEDB;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='scrutexity_app') THEN
    CREATE ROLE scrutexity_app LOGIN PASSWORD 'scrutexity';
  END IF;
END
$$;
SQL

  if ! su postgres -c "psql -lqt" | cut -d'|' -f1 | grep -qw scrutexity; then
    su postgres -c "createdb -O scrutexity_owner scrutexity"
  fi
  echo "postgres ready on 127.0.0.1:5432"
}

stop() {
  pg_ctlcluster "$VERSION" "$CLUSTER" stop 2>/dev/null || service postgresql stop || true
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 {start|stop}" >&2; exit 2 ;;
esac
