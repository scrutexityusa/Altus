# ADR-0006 — Per-tenant hash chain, Ed25519 signatures, append-only tables

**Status** Accepted · 2026-08-21

## Problem

Evidence must be tamper-evident. It must not overclaim.

## Decision

Three layers, each doing one job:

1. **Append-only by trigger.** `UPDATE` and `DELETE` on any evidence table
   raise `42501`. Enforced by the database, not by convention.
2. **Hash chain, one per tenant.** Each receipt covers its payload digest, its
   position, and the previous hash. The chain head row is locked `FOR UPDATE`
   before a sequence is taken, so concurrent decisions serialise rather than
   fork — a forked chain is an unverifiable chain.
3. **Ed25519 signature** over the link hash, establishing provenance.

Chains are per tenant. A shared chain would leak the existence and rate of one
customer's decisions into another's evidence.

Hashing is over canonical JSON (RFC 8785 in spirit): keys sorted, `undefined`
dropped, and **non-integer numbers rejected outright**. A float in an audit
record whose textual form depends on the serialiser is not evidence.

## What it proves, stated precisely

> This evidence is what was written, in the order it was written, by the holder
> of the signing key.

Not that the decision was correct, lawful or wise. The verification endpoint
returns `attests: "evidence_integrity_and_provenance"` so no reader has to
guess, and the word "proof" appears nowhere near a decision's merits.

## The residual gap

An attacker holding both the database and the signing key can rewrite the chain
from the tampered point and re-sign every receipt; the result verifies. Every
hash from that point changes, so any externally held head hash exposes it, and
`covers_genesis` tells a caller whether the verified segment was anchored.

Closing it properly means publishing periodic head hashes to a witness the API
process cannot reach. That is designed in
[ADR-0021](0021-evidence-anchoring.md), together with the offline-verifiable
bundle it is useless without. **Neither is built.** It is recorded here and in
`docs/security-model.md` as a known gap rather than left as an implied
guarantee.
