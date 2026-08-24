#!/usr/bin/env bash
#
# Is the remote pipeline green?
#
# `make ci` proves the suite passes here. It has never proved anything about
# GitHub Actions, and for the first fourteen runs of this repository the two
# answers disagreed: every local run was green while every remote run failed,
# because the first job needed a database it did not have and the jobs that
# `needs:` it were skipped in silence. See ADR-0020.
#
# So "green" is defined as a remote conclusion, and this asks for it. It prints
# the run URL, which is the thing to paste when reporting a state rather than
# the word "green".
#
#   make ci-status              the default branch
#   BRANCH=my-branch make ci-status
#
# Auth: none needed while the repository is public. For a private one, set
# GH_TOKEN or GITHUB_TOKEN; `gh` is used automatically when it is installed.

set -euo pipefail

REPO="${CI_STATUS_REPO:-scrutexityusa/Altus}"
WORKFLOW="${CI_STATUS_WORKFLOW:-ci.yml}"
BRANCH="${BRANCH:-$(git symbolic-ref --quiet --short HEAD 2>/dev/null || echo main)}"
API="https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/runs?branch=${BRANCH}&per_page=1"

fetch() {
  # A recorded API response, so this script's own decision logic can be tested
  # without a network and without waiting for a red run to exist. Read-only and
  # test-only: it changes what is examined, never what counts as green.
  if [ -n "${CI_STATUS_PAYLOAD:-}" ]; then
    cat "$CI_STATUS_PAYLOAD"
    return 0
  fi
  if command -v gh >/dev/null 2>&1; then
    gh api "repos/${REPO}/actions/workflows/${WORKFLOW}/runs?branch=${BRANCH}&per_page=1" 2>/dev/null && return 0
  fi
  local auth=()
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  [ -n "$token" ] && auth=(-H "authorization: Bearer ${token}")
  curl -sSfL "${auth[@]}" -H 'accept: application/vnd.github+json' "$API"
}

if ! payload=$(fetch); then
  echo "could not reach the GitHub API for ${REPO}." >&2
  echo "if the repository is private, set GH_TOKEN or GITHUB_TOKEN." >&2
  exit 2
fi

read -r status conclusion url sha title < <(
  printf '%s' "$payload" | python3 -c '
import json, sys
runs = json.load(sys.stdin).get("workflow_runs") or []
if not runs:
    print("none none none none none")
    sys.exit(0)
r = runs[0]
title = (r.get("display_title") or "").splitlines()[0].replace(" ", " ") or "-"
print(r.get("status") or "?", r.get("conclusion") or "pending",
      r.get("html_url") or "-", (r.get("head_sha") or "-")[:8], title)
'
)

if [ "$status" = none ]; then
  echo "no run found for branch ${BRANCH}. push it, or set BRANCH." >&2
  exit 2
fi

printf '\n  branch      %s\n  commit      %s\n  status      %s / %s\n  run         %s\n\n' \
  "$BRANCH" "$sha" "$status" "$conclusion" "$url"

if [ "$status" != completed ]; then
  echo "  the run has not finished. it is not green until it is." >&2
  exit 1
fi
if [ "$conclusion" != success ]; then
  echo "  NOT GREEN. do not report this branch as passing." >&2
  exit 1
fi

echo "  GREEN. cite this URL rather than a local run."
