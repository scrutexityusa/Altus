#!/usr/bin/env bash
#
# The demo and the seed must reach the control plane the way a partner does.
#
# Four of the defects this project found the hard way came from one shape: the
# fixtures took a shortcut the public API does not have, so the path a design
# partner would walk was never exercised. The worst was a policy-review route
# that had never once executed -- it raised a type error on its first real call
# -- because the seed wrote reviews with direct SQL and every test inherited
# that seed.
#
# The rule: **if a design-partner workflow can be performed through the public
# control plane, the demo and the seed must use that same path.** This is that
# rule as a check rather than as a belief. It was a belief until now, which is
# the exact failure mode the rest of this repository exists to avoid.
#
# Narrow on purpose. `scripts/bootstrap.ts` legitimately holds the owner
# connection -- the installation ceremony is the one thing that cannot go
# through an API that does not yet have a tenant to authenticate against -- and
# the harnesses under test/ and scripts/adversarial.ts must reach past the API
# to mount attacks against storage. Neither is a partner workflow.

set -euo pipefail

FILES=(scripts/seed.ts scripts/demo.ts)
FORBIDDEN='(from '"'"'pg'"'"'|require\(('"'"'|")pg('"'"'|")\)|\.query\()'

failed=0
for file in "${FILES[@]}"; do
  if matches=$(grep -nE "$FORBIDDEN" "$file"); then
    failed=1
    printf '\n%s reaches the database directly:\n' "$file" >&2
    printf '%s\n' "$matches" >&2
  fi
done

if [ "$failed" -ne 0 ]; then
  cat >&2 <<'MSG'

The demo and the seed provision through the public API, exactly as the
onboarding guide tells a partner to. A shortcut here means the partner's path
stops being tested -- which is how a published route reached production having
never been called once.

If a genuinely new capability has no API yet, that is the finding. Add the
endpoint, or say out loud in the guide that the workflow is not reachable.
MSG
  exit 1
fi

echo "  = the demo and the seed use the public control plane"
