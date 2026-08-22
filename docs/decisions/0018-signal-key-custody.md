# ADR-0018: Signal key custody is Ed25519-only, and enrolment is mandatory

**Status:** Accepted
**Date:** 2026-08-22
**Supersedes in part:** [ADR-0014](0014-signal-authentication.md)

## Context

ADR-0014 established that signals are signed and verified, with Ed25519
preferred and HMAC-SHA256 available for sources that cannot manage a keypair.
"Preferred" turned out to carry no weight. Three things were true of the
implementation that ADR did not say out loud:

1. **A source with no registered key was trusted.** `verifySignal` reported
   `no_key_configured`, and the caller treated that as non-fatal. Anyone
   holding the `signals:write` scope could assert any signal about any subject
   from any source name they invented.

2. **HMAC was the path everything actually used.** Every integration test, and
   the only end-to-end exercise of the key lifecycle, ran on HMAC. The suite
   was proving the algorithm the product says it prefers not to use.

3. **The algorithm rule was enforced at the wrong moment.** Production refused
   to _register_ an HMAC key. A row written before that check existed, or
   restored from a backup taken before it, still authenticated signals.

Underneath all three is one fact about HMAC: the verifier holds the same secret
that produces signatures. Scrutexity would be storing, for every source, a
value that manufactures signals reducing authority over real money. Disclosure
of the signal key table would not merely be an information leak; it would be a
forgery capability.

A signal can only ever subtract authority, so forging one cannot hand an
attacker a payment. It can still suppress a competitor's agent, and — more
quietly — displace the current high-risk reading with a stale low-risk one and
open a window. Both are attacks on the accuracy of the risk picture, which is
what authority decay depends on.

## Decision

### 1. Enrolment is mandatory

A source with no registered key is refused with `SIGNAL_SOURCE_NOT_ENROLLED`.
There is no implicit trust for an unknown source, because nothing an
unattributable source says is attributable to anyone.

`SIGNAL_AUTHENTICATION=permissive` exists for local development and admits an
unenrolled source that presents **no** signature, recording it as
`authenticated: false`. Production cannot select it; `loadConfig` refuses to
start. A _presented_ signature is a claim of authenticity, and a claim that
cannot be checked fails under every posture — including permissive.

### 2. Ed25519 everywhere, not just in production

`SIGNAL_LEGACY_HMAC` defaults to `refused` in development as well as
production. A fallback that exists locally is a fallback the tests exercise and
production does not; the suite then proves nothing about the path that ships.
A deployment migrating a legacy source sets `permitted` deliberately and
knowingly, and production refuses to boot with it.

### 3. The algorithm rule is enforced at verification

Registration refuses HMAC too, so an operator finds out when they enrol a
source rather than when a signal is dropped. But **registration is not the
enforcement point.** Every signal is checked against the permitted algorithms,
which is what rejects a key that predates the check or arrived with a restore.
The rejection is `SIGNAL_KEY_UNKNOWN` with reason code
`ALGORITHM_NOT_PERMITTED`: for the purposes of this signal, a key the
deployment will not accept is not a key.

### 4. Private key material never enters Scrutexity

Only the SPKI public half is registered. The source generates its own keypair
and keeps the private half. The seed holds both ends because it stands up both
ends — the tenant and the fixture source that signs for it — and writes them to
a git-ignored development file.

### 5. Receipt signing keys come from a secret provider

`SecretProvider` (`services/api/src/keys/provider.ts`) has three
implementations: `env`, `file` and `kms`. Production accepts only `kms`, and
setting `RECEIPT_SIGNING_KEY_B64` inline is a boot failure rather than a
preference. An absent key in production is also a boot failure: the development
fallback that generates an ephemeral key is not available there, because
receipts signed by a key that vanishes on restart verify today and fail
tomorrow — worse than no receipts, because they look like proof.

## The layer that matters more than any of this

Every decision above assumes the attacker cannot sign. The containment layer
assumes they can:

> **Authority(after signal) ⊆ Authority(before signal)**, for every signal,
> from every source, at every value — including signals whose signatures
> verify perfectly against a key Scrutexity correctly trusts.

The realistic breach is not a forged signature. It is a fraud engine that is
fully compromised and signing whatever it likes with the real key. So the two
layers are tested independently, and the containment assertions are made with
signatures that verify.

Enforcing this found a real defect. A lease denominated in EUR does not cover a
USD wire; policy named no approver for the ordinary case, so the request was a
hard DENY. Raising the fraud score above the escalation threshold matched a
rule that _does_ name a treasurer — and the authority shortfall became
something a treasurer could approve. Asserting **more** risk produced a **more**
permissive outcome, and a compromised source could summon an approval request
for any action the agent's authority never covered, using the approver as a
confused deputy.

The fix distinguishes two shortfalls:

| Shortfall                                             | May a signal's approver rescue it?                          |
| ----------------------------------------------------- | ----------------------------------------------------------- |
| Decay — the base grant covered it, a signal shrank it | Yes. The human restores authority the agent genuinely held. |
| The agent's own authority falls short                 | No. Only an approver policy named _without any signal_.     |

Found by a randomised property, not by review. See
`packages/core/test/invariants.test.ts`.

## Key rotation runbook

Rotation is an overlap, not a swap. Both keys are valid during the window, so
no signal is dropped while a source switches over.

1. **Generate** a new keypair at the source. The private half never leaves it.
2. **Register** the public half under a new `key_id`:
   `POST /v1/signal-keys` with `algorithm: ED25519`. The source now has two
   `ACTIVE` keys.
3. **Switch** the source to sign with the new `key_id` and confirm signals are
   arriving with `authenticated: true` and the new key id recorded.
4. **Retire** the old key: `POST /v1/signal-keys/:id/retire` with a
   `grace_period_seconds` covering any in-flight deliveries. The key becomes
   `RETIRING` and stays usable until `not_after`.
5. **Verify** no signals are still arriving under the old key id.

The grace period is the whole point of `RETIRING`. Skipping it drops signals,
and a dropped fraud signal is authority that should have decayed and did not.

**Compromise is not rotation.** If a key is believed compromised, use
`POST /v1/signal-keys/:id/revoke`. Revocation takes effect immediately, with no
overlap, because the overlap is exactly what an attacker holding the old key
would use. Dropping some legitimate signals is the correct trade.

Both states are enforced at verification against the authoritative database
clock (ADR-0017), so a source with a fast clock cannot extend its own window.

## Addendum, design-partner phase

Three decisions taken while preparing the first partner package. None changes the
decision above; all three change how it is operated or presented.

### The starter pack is a second policy file, not a rename

`policies/treasury-wire.yaml` (hyphen) is the file a partner copies.
`policies/treasury_wire.yaml` (underscore) stays as the reference tenant's policy
for the seed, the demo and the test suite.

The alternative — one file serving both — was rejected because the two have
genuinely different jobs. The reference policy is tuned to make the demo's story
legible; the starter is parameterised with `CHANGE ME` markers and carries the
reasoning a partner needs to edit it safely. Merging them would mean the demo
narrative constrains a partner's defaults, or the partner's placeholders leak
into the demo.

Two files can drift, so the starter is asserted directly by
`packages/core/test/policy-pack.test.ts` (20 cases) rather than assumed to
resemble its sibling: every tier boundary, the fail-closed settings, the
non-delegable actions, the `$0.00` treasurer ceiling, and that no signal can
expand authority. A partner who moves a threshold finds out which rule broke.

### The permitted-algorithm list is a deployment posture, not a build-time constant

`SIGNAL_LEGACY_HMAC` was introduced as `refused` by default in **development as
well as production**, rather than as a production-only check.

The reasoning is the one this ADR already makes about fallbacks, applied to
ourselves: a fallback that exists locally is a fallback the tests exercise and
production does not, and the suite then proves nothing about the path that ships.
Converting the existing HMAC key-lifecycle tests to Ed25519 was the concrete
benefit — before that, the only end-to-end exercise of rotation, grace periods and
revocation ran on the algorithm the product refuses.

A deployment still migrating a legacy source sets `permitted` deliberately, and
production refuses to boot with it.

### The KMS gap is a deployment prerequisite, not a gap number

`KmsSecretProvider` throwing on every read is the specified behaviour, not an
unfinished one: production refuses to start rather than falling back to local
custody.

It is therefore recorded in `docs/security-surface-map.md` as a **deployment
prerequisite** rather than as a numbered gap, because there is no defect to fix —
there is a decision only a partner can make. Which manager, and whether the key
must never leave it, are questions with different answers per partner. A
never-leaves design (Vault Transit, HSM-backed signing) needs a signing-oriented
interface rather than the current fetching one; that is a real change and it will
be scoped against a partner's obligation rather than guessed at in advance.

What this costs us, stated so it is not discovered later: **no deployment of this
code has ever started in a production posture.** Every claim in this ADR is
established against development and test configurations. The integration seam is
`docs/design-partner/integration-runbook.md` §2.

## Consequences

- A new signal source cannot send anything until an operator enrols it. This is
  friction, and it is the point.
- A deployment still running an HMAC source must set `SIGNAL_LEGACY_HMAC` and
  cannot go to production until that source is migrated.
- Production requires a key manager. There is no wired implementation yet;
  `KmsSecretProvider` throws on every read, which fails the boot loudly rather
  than falling back to local custody silently. Wiring a specific cloud is a
  constructor argument and an SDK dependency, added when a deployment needs one.
- Rejections are `SIGNAL_SOURCE_NOT_ENROLLED`, `SIGNAL_KEY_UNKNOWN` or
  `SIGNAL_SIGNATURE_INVALID`, each with a specific reason code, and each writes
  a durable security event on a transaction that survives the rejection.
