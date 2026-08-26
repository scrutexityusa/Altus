# ADR-0021: Evidence anchoring — design, not yet built

**Status:** Proposed
**Date:** 2026-08-24
**Closes, when built:** G-11 (no external anchor), G-13 (no offline-verifiable bundle)
**Extends:** [ADR-0006](0006-evidence-hash-chain.md)

## The gap, stated exactly

ADR-0006 already says it: an attacker holding **both** the database and the
signing key can rewrite the chain from the tampered point, re-link every receipt
after it, re-sign each one, and the result verifies perfectly. Nothing inside the
trust boundary can detect that, because every artefact that would betray it is
inside the boundary too.

This is the difference between two sentences a treasury partner hears very
differently:

> We can show you the hash chain.
>
> We can prove to a third party that this history existed at a time before you
> could have changed it.

Only the second one survives a compromise of our own infrastructure, and only
the second one is worth anything in a dispute where **we** are one of the
parties.

## Decision

Publish the chain head to a witness the API process cannot rewrite, on a fixed
cadence, and ship the witness's own proof inside the evidence bundle so a third
party can check it without us.

Three parts, and they are deliberately one ADR rather than three because none of
them is worth building alone.

### 1. What is anchored

The chain head, and nothing else:

```
(organization_id, seq, head_hash, anchored_at)
```

Not receipts, not payloads, not decisions. A head hash is 32 opaque bytes; it
discloses no counterparty, no amount, no agent, and no policy. This matters
because a witness is by definition somewhere we do not control.

### 2. Where it goes

The requirement is one property: **the party that could rewrite the chain must
not be able to rewrite the witness.** Four shapes satisfy it, with real
trade-offs, and the deployment picks one:

| Witness                                                                                   | What a third party checks                                                                | Cost          | Honest weakness                                                             |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------- | --------------------------------------------------------------------------- |
| **RFC 3161 timestamp authority**                                                          | A signed token binding the head hash to a time, verifiable against the TSA's certificate | Free to cheap | Trusts the TSA; a TSA that colludes or is compromised proves nothing        |
| **Transparency log** (Sigstore Rekor, or a Certificate Transparency-style log)            | An inclusion proof against a published, gossiped Merkle root                             | Free          | Head hashes become public — see _Privacy_                                   |
| **Object storage with retention lock** (S3 Object Lock in compliance mode, or equivalent) | The object version, its immutability window, and the provider's audit log                | Cents         | The partner's own cloud account: strong against _us_, weaker against _them_ |
| **Counterparty countersignature**                                                         | The partner's own signature over the head hash, held in their systems                    | Free          | Only as good as their key custody; useless if they are the disputing party  |

**The partner's own object lock is the likely first choice**, because the
adversary a treasury team is actually insuring against in a pilot is _us_, and a
bucket we cannot write to answers that completely. A TSA is the natural second,
added rather than substituted: two independent witnesses is strictly better than
one, and the interface below permits several.

**Explicitly excluded: a blockchain.** It is a witness with worse latency, worse
cost, mandatory publicity, and no better trust story than a TSA plus an object
lock. It is on the non-goals list and stays there.

### 3. Cadence, and a privacy consequence worth stating

Anchor on a **fixed schedule regardless of activity**, and write an anchor even
when the head has not moved.

The obvious design — anchor whenever the chain advances — leaks the tenant's
decision rate to the witness, and for a public witness, to everyone. "This
treasury made 4,000 authorization decisions on the last Friday of the quarter"
is commercially meaningful. A constant cadence with no-change anchors costs a
few bytes an hour and reveals only that a tenant exists.

The gap between anchors is the window in which the compromise described above is
still undetectable. That window is a deployment choice with an explicit cost
curve, not a constant to be hard-coded.

## The interface

Deliberately small, and mirroring `ReceiptSigner`/`ReceiptVerifier` in
`packages/core/src/receipts.ts` — a witness produces a proof and cannot be asked
to validate its own work.

```ts
/** What was anchored, and the evidence that a third party can check. */
export interface ChainAnchor {
  organization_id: string;
  seq: number; // chain length at the moment of anchoring
  head_hash: string; // hex sha256; the receipt chain head
  anchored_at: string; // OUR clock, and therefore not the proof
  witness: WitnessKind;
  witness_reference: string; // log index, object version id, TSA serial
  witness_proof: string; // base64url; the bytes a verifier checks
}

export interface Witness {
  readonly kind: WitnessKind;
  /** Publish a head. Must reach a store this process cannot rewrite. */
  anchor(head: {
    organization_id: string;
    seq: number;
    head_hash: string;
  }): Promise<Pick<ChainAnchor, 'witness_reference' | 'witness_proof' | 'anchored_at'>>;
}

/**
 * Offline. Takes bytes, returns a verdict, reaches no network and no database.
 * A verification that has to call us is not independent verification.
 */
export function verifyAgainstAnchor(
  receipts: readonly Receipt[],
  anchor: ChainAnchor,
  verifier: ReceiptVerifier,
  witness: WitnessVerifier,
): AnchoredVerificationResult;
```

Note `anchored_at` is **ours** and is therefore not part of the proof. The time
that counts is the one inside `witness_proof`, asserted by somebody else. Naming
the field without that distinction would invite exactly the confusion this ADR
exists to remove.

## The bundle, which is the same feature

G-13 asks for an offline-verifiable export. G-11 asks for an anchor. Shipping
either alone produces something that does not answer the question:

- an anchor with no bundle means a third party must ask _us_ for the receipts
  that hash to the anchored head;
- a bundle with no anchor is a self-consistent artefact signed by whoever
  controls the key — exactly the thing the attacker above can also produce.

So the export is one file containing: the receipt segment, the signing public
key and its id, every anchor covering that segment, and the witness proofs.
Verifying it requires the file and a verifier binary. Not our API, not our
database, not our cooperation.

## What this still does not prove

- **Nothing about the decision's merits.** Unchanged from ADR-0006, and the
  `attests: "evidence_integrity_and_provenance"` wording stays.
- **Nothing after the newest anchor.** Receipts written since the last anchor
  carry the original residual gap. The honest claim becomes: _tamper-evident
  throughout, and independently provable up to the last anchor at T._ Any
  verification response must say which receipts fall after the last anchor
  rather than letting a reader assume the whole chain is covered — `covers_genesis`
  already sets that precedent at the other end of the chain.
- **Nothing about a tenant we never anchored.** Anchoring is per-tenant because
  chains are per-tenant, and a deployment with anchoring off must say so in the
  verification response rather than omitting the field.

## Why this is written before it is built

Three reasons, in order.

The interface commits us to what a third party checks, and that is the part
worth arguing about before there is code to defend. The witness choice belongs
to the first partner, not to us — a treasury team with an existing S3 Object
Lock retention policy has already answered it, and building for a witness nobody
asked for is the mistake this repository has a non-goals list to prevent. And
the claim change is the deliverable: until this ships, the security brief says
"tamper-evident", and it must keep saying exactly that.

## Consequences

- The security brief, `docs/security-model.md` and the surface map keep G-11 and
  G-13 **open**, now pointing here for the design. A proposed ADR is not a
  mitigation.
- No new runtime dependency is implied. A TSA is an HTTP request and an ASN.1
  parse; an object-lock write is an HTTP request. Neither needs a cloud SDK.
- The first partner's witness choice is a discovery question, and belongs in
  `docs/design-partner/` alongside the KMS question rather than being guessed at
  here.
