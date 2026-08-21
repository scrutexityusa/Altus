# ADR-0014 — Signal authentication and key rotation

**Status** Accepted · 2026-08-21

## Problem

Signals can only shrink authority, so forging one grants an attacker nothing.
That argument is why signal authentication is easy to defer, and it is
incomplete.

A forged signal can suppress a competitor's agent — a denial of service against
the business process, not the service. More subtly, a _replayed_ signal can
push the risk picture backwards: redeliver last hour's `fraud_risk = 0.1` to
supersede the current `0.97`, and the window it opens is exactly the window
authority decay exists to close. Both are attacks on the accuracy of the risk
picture, which is the input the whole decay mechanism depends on.

## Decision

Signals are signed by their source and verified before they can influence
anything.

**Ed25519 preferred.** Only a public key is stored, so a database disclosure
yields nothing an attacker can sign with. This matters more here than in most
places: the signal store and the key store are the same database, and an
attacker who reaches one reaches the other.

**HMAC-SHA256 supported.** Some sources cannot manage a keypair. Its shared
secret must live in the database, which is why it is the second choice, and
why the migration carries an explicit note flagging it for encryption at rest
before any real customer data. That note is not a TODO standing in for the
work — it is a recorded, bounded risk with a named remedy, and it is tracked in
`docs/sprint-plan.md`.

**The envelope covers everything that determines the effect.** Subject, type,
value, confidence, source, event id, issue time and TTL are all inside the
signed payload. Changing any of them invalidates the signature; there is a test
for each.

## Key rotation

Keys are per (tenant, source) and carry a `key_id` in the signal envelope, so
verification is a lookup rather than trying every key in turn.

| Status     | Usable             | Purpose                   |
| ---------- | ------------------ | ------------------------- |
| `ACTIVE`   | yes                | Normal operation          |
| `RETIRING` | until `not_after`  | The rotation grace period |
| `REVOKED`  | never, immediately | Compromise                |

The `RETIRING` overlap is the whole point of having two states rather than one:
a source switching keys keeps signing with the old one until it has confirmed
the new one works, and no signals are dropped in between. Dropped signals are
not a neutral failure — they are a risk picture going quietly stale.

Revocation has no grace period, because it is what you reach for when a key is
believed compromised and any overlap is an attack window.

## Failure behaviour

| Case                                    | Result                                                                 |
| --------------------------------------- | ---------------------------------------------------------------------- |
| Valid signature                         | Stored, `authenticated = true`                                         |
| Invalid, unknown key, missing signature | **Rejected.** Not stored, authority unchanged, security event recorded |
| Replayed `event_id`                     | **Rejected** with `REPLAY_DETECTED`, security event recorded           |
| Source has no key configured            | Stored, `authenticated = false`, security event recorded               |

The last row is a tenant's decision, not the platform's: whether an
unauthenticated source may influence authority is a policy question, and the
platform records the choice either way rather than making it silently.

Replay is refused by a unique index on `(organization_id, source, event_id)`.
A valid signature is not sufficient — the same event twice is still the same
event, and that is what stops a replay from displacing a fresher reading.

## The rollback that was not obvious

Recording a rejection and then throwing does not work: the throw rolls the
transaction back and takes the audit record with it. A rejected signal would
leave no signal _and no trace_, which is the worst of both.

Security events for rejected signals therefore travel on the error and are
written by the caller afterwards, on their own transaction. This is the one
place in the codebase with autonomous-transaction semantics, and it is
deliberate: an audit record about a refusal must not be conditional on the
refusal succeeding.

## Revisit when

A tenant needs per-source policy over unauthenticated signals — "accept from
this source, refuse from that one". Today `requireAuthentication` is a
per-request flag; it should become tenant configuration.
