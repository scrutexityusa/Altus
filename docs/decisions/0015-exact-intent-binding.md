# ADR-0015: Exact intent binding

**Status:** Accepted
**Date:** 2026-08-21

## Context

Until now an ALLOW recorded that an agent _may_ move $25,000 to counterparty
cp_100 under lease `lease_x` and policy version 4. It did not record what
"that operation" was in any form that could be compared against what the agent
subsequently did.

`POST /v1/executions` took `{decision_id, status, result}`. The agent reported
an outcome. The system believed it, wrote a receipt, and moved on. Every
control downstream of the ALLOW — the TOCTOU fingerprint, the single-use
constraint, the hash-chained receipt — was protecting a self-report.

That means the property the whole system exists to provide,

```
ExecutedIntent = AuthorizedIntent
```

was not merely unproven. It was **unenforceable**: there was no executed intent
in the system to compare an authorised one against.

## Decision

Record, on every ALLOW, the exact operation it authorises and the authority it
is bound to. Two hashes, deliberately not merged.

### The operation is a projection, not a copy

`canonicalOperation()` builds the operation from the action's entry in the
closed catalog (ADR-0007): `operation_type`, `resource_type`, `resource_id`,
and exactly those `context_fields` the catalog declares the action carries.

Fields the catalog does not declare are dropped. This is the control, not a
convenience. An undeclared field cannot reach the external system, so it must
not be able to move the hash — and a projection is the only way to guarantee
that without trusting the sender to omit it. Unknown context fields do reach
`request_hash` today; they cannot reach the intent hash.

Inside an operation, absent and null collapse to the same fact. The raw
canonicaliser keeps them distinct; the projection does not. Both rules are
right for their layer, and both are specified in
`docs/canonicalization-spec.md`.

### Two hashes, two questions

```
exact_intent_hash = SHA256(canonical(CanonicalOperation))
```

**"Did the operation mutate?"** Covers the operation and nothing else, so it is
stable across policy versions, leases and approvals.

```
binding_hash = SHA256(canonical({
  authorized_intent, authorization_context, grant_id, expires_at, nonce
}))
```

**"Is this operation bound to _this_ authority decision?"**

An attacker who replays a genuine, unmutated operation under a different
decision passes the first check and fails the second. An attacker who mutates
an amount under the correct decision fails both.

Collapsing them would answer neither cleanly. A changed policy version would
read as a mutated wire, which is the wrong thing to put in front of an
operator at 3am.

### The approved context binds, and it binds to the binding

`approved_context_hash` — the TOCTOU fingerprint the approvers were actually
shown — is part of `authorization_context`, not part of the intent hash. A
treasurer approves a specific operation under a specific risk picture. Binding
both means an execution presented against a _different_ approval fails even
though the operation itself is byte-identical, while a moved risk picture never
masquerades as a mutated operation.

### The nonce

Fresh randomness, not a derivation of the decision id. Two legitimately
identical operations — the same supplier, the same amount, twice in one day —
must not produce interchangeable bindings, or this morning's binding validates
this afternoon's wire.

### The server computes it, always

Every input to the binding comes from the request as evaluated, after
server-derived facts have overwritten anything the caller asserted. Nothing is
caller-supplied. The request schema is `.strict()`, so an attempt to send an
`exact_intent_hash` is rejected at the boundary rather than accepted and
quietly discarded — the caller learns immediately that it is not an input.

A hash the agent provides proves only that the agent can compute a hash.

## Consequences

`authorization_decisions` gains four columns under a CHECK constraint that
makes a partial binding impossible: either all four are present or none are. A
half-written binding is worse than no binding, because it looks like a control
and is not one. The table is append-only, so the database enforces that they
are never rewritten.

The binding also goes into the AUTHORIZATION_DECISION receipt, so a verifier
holding only the receipt can recompute both hashes without access to the
database that issued them.

Canonicalisation gained Unicode NFC normalisation as part of this work, because
`"José"` and `"José"` render identically everywhere a human or a bank will
ever look and hashed differently. Two defects surfaced while pinning the rules:
sparse arrays serialised to `[1,,3]`, which is not JSON and which no second
implementation could reproduce; and keys colliding after normalisation made the
output depend on insertion order. Both are fixed, both are now conformance
vectors.

## What this does not yet do

**Nothing enforces the binding.** This ADR records the authorised intent; it
does not compare anything to it, because there is still no component that
reconstructs an operation at execution time. `POST /v1/executions` still takes
a self-reported status.

That is the execution adapter's job, and it is the next slice. Until it exists,
these hashes are evidence — an auditor can prove after the fact what was
authorised — but they are not a control. The distinction matters and should not
be blurred in any description of the system.

## Alternatives considered

**A separate `execution_grants` table.** Rejected. An ALLOW decision already
_is_ the execution grant: it has the TTL, the single-use constraint, the lease,
the policy version and the tenancy. A second table would duplicate the whole
lifecycle and create two places where "is this grant still valid" can disagree.

**One combined hash.** Rejected for the reason above: it answers neither
question cleanly.

**Letting the agent supply the intent hash and verifying it.** Rejected. It
inverts the trust relationship for no gain — the server has to compute the hash
anyway to check the agent's, so accepting one only adds a field an attacker can
probe.
