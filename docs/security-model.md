# Security model

The authorization service is itself a high-value target. A compromise here is
not a data breach — it is the ability to authorise payments.

## Trust boundaries

```
  agent code          ── untrusted ──►  everything it sends is a claim
  external signal src ── untrusted ──►  bounded, TTL'd, superseded, never authoritative
  tenant user         ── semi-trusted ► scoped, dual-controlled, cannot self-approve
  API process         ── trusted ─────►  holds the signing key; cannot rewrite evidence
  database            ── trusted ─────►  enforces isolation and append-only itself
```

The word "claim" is load-bearing. An agent asserting `counterparty_known: true`
is making a claim; the control plane derives that fact from the tenant's own
register and discards what the caller said.

## Controls, and what each one stops

### Identity and tenancy

| Control                                                                | Stops                                                                          |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Tenant derived from the credential, never from a header or body        | A client naming its own tenant.                                                |
| Bearer tokens stored as SHA-256; constant-time comparison              | Database disclosure yielding usable credentials; timing oracles on the prefix. |
| Hash computed even when no credential row is found                     | A missing prefix taking measurably less time than a wrong secret.              |
| `FORCE ROW LEVEL SECURITY` keyed on a transaction-local GUC            | A handler that forgets its tenant. It sees zero rows and writes nothing.       |
| The API connects as a non-owner role                                   | The owner's implicit RLS bypass.                                               |
| Organization id validated against a strict pattern before `set_config` | Injection into the tenant GUC.                                                 |

`api_credentials` is handled differently and deliberately: authentication is
what _resolves_ the tenant, so it cannot be tenant-scoped. RLS is enabled but
not forced, the application role has **no privileges on the table at all**, and
the only way in is a single-row prefix probe through a `SECURITY DEFINER`
function. (`FORCE` there would apply to the owner too and make authentication
impossible — a real trap, found by a failing test, recorded in the migration.)

### Agent privilege

An agent credential **cannot**: create agents, issue itself or anyone authority,
author or activate policy, approve an escalation, delegate authority it does not
hold, authorize on behalf of another agent, or execute against another agent's
decision. Each of these is a test in `services/api/test/security.test.ts`.

### Confused deputy

The actor, the principal and the delegator are always distinct and always
explicit. Possessing another agent's decision id, lease id or handle confers
nothing: every operation re-derives the acting principal from the credential
and compares it to the object's owner.

### Replay

| Vector                            | Control                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------ |
| Resubmitted authorization request | Optional single-use `nonce`, unique per (org, agent).                                |
| Reused execution grant            | Unique constraint on `execution_attempts.decision_id`. A race cannot slip past it.   |
| Late execution grant              | `expires_at` on every ALLOW, checked at execution.                                   |
| Retried mutation                  | Idempotency key claimed **in the same transaction as the effect**.                   |
| Key reused with a different body  | `IDEMPOTENCY_CONFLICT` — reported, because silently honouring it hides a lost write. |

### Policy integrity

A policy version is immutable, content-hashed, and re-verified against its
recorded digest **on every load** — not only on a cache miss. That distinction
was a real bug: caching is a parsing optimisation and must never become the
reason tampering goes unnoticed. Activation re-checks the hash before a
document takes effect over live money.

Activation requires two distinct human reviewers, neither of them the author.

### Hostile signals

Signals are assertions, not instructions. They are bounded on every axis:
`ttl_seconds` ≤ 24h, `issued_at` may not be in the future, a signal already
expired on arrival is refused, and a newer assertion from the same source
supersedes the older one — so a source cannot pin an agent's authority down by
shouting. Freshness is enforced **at read**, so a stale signal cannot suppress
authority indefinitely even if a policy author forgets to check.

Publishing a signal requires the `signals:write` scope. A compromised signal
source can therefore make authority _stricter_, never looser.

### Evidence

Receipts are hash-chained per tenant, Ed25519-signed, and append-only by
database trigger. Verification recomputes the payload digest, the link hash and
the signature, and checks linkage across the surrounding chain segment.

**What this proves:** the evidence you are reading is what was written, in the
order it was written, by the holder of the signing key.

**What it does not prove:** that the decision recorded was correct, lawful or
wise. The verification endpoint returns `attests:
"evidence_integrity_and_provenance"` precisely so nobody reads more into it.

**The residual gap, stated plainly.** An attacker holding both the database and
the signing key can rewrite the entire chain from the tampered point onward and
re-sign every receipt. The result is internally consistent. The mitigations are
(a) every hash from the tampered point changes, so any externally held head
hash exposes it, and (b) `covers_genesis` on the verification response tells a
caller whether the segment was anchored. Closing it properly means publishing
periodic head hashes to a witness the API process cannot reach. That is not
built. It is a known gap, not an implied guarantee.

### Error disclosure

Security-sensitive failures return a generic message; the detail goes to the
structured log under the same request id the caller was given. Detail is
disclosed only when it is the caller's own input reflected back — a rejected
delegation names the axis that failed, because that is the difference between a
fixable integration and a support ticket, and it reveals nothing the caller did
not send.

Every error carries a `reason_code` from a closed, documented vocabulary.
Reason codes are safe to disclose: they say no more than the error code
already does, and without them a caller cannot tell "you may not delegate this
action" from "you may not call this endpoint".

## Threats accepted

Named, so that nobody mistakes silence for coverage:

- **A compromised API process** can issue authorised decisions within its
  tenant's policy and sign receipts for them. Mitigation is operational: key
  custody, least privilege, and the audit trail those decisions leave.
- **A tenant admin** can write policy that permits a great deal. That is the
  point — the customer owns policy semantics (Section 33). Dual-control review
  and immutable versioning make it visible and attributable, not impossible.
- **Denial of service.** Bounded body size, statement and query timeouts, and
  connection caps are in place. Rate limiting is deployment-layer and is not
  implemented here.
- **Side channels.** Token comparison is constant-time. Broader timing analysis
  of decision latency has not been characterised.
