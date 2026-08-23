import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildReceipt,
  ed25519Signer,
  ed25519Verifier,
  GENESIS_HASH,
  verifyChain,
  verifyReceipt,
  type Receipt,
} from '../src/receipts.js';
import { newId } from '../src/ids.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const signer = ed25519Signer(
  privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  'test-key-1',
);
const verifier = ed25519Verifier(
  publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  'test-key-1',
);

function chain(length: number, orgId = 'org_acme'): Receipt[] {
  const receipts: Receipt[] = [];
  let previous = GENESIS_HASH;
  for (let seq = 1; seq <= length; seq++) {
    const receipt = buildReceipt({
      id: newId('receipt', 1_700_000_000_000 + seq),
      organization_id: orgId,
      seq,
      kind: 'AUTHORIZATION_DECISION',
      decision_id: `dec_${seq}`,
      payload: { decision: 'ALLOW', amount: { currency: 'USD', amountMinor: '2500000' }, seq },
      previous_hash: previous,
      created_at: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
      signer,
    });
    receipts.push(receipt);
    previous = receipt.hash;
  }
  return receipts;
}

describe('receipts', () => {
  it('verifies an untouched receipt', () => {
    const [receipt] = chain(1);
    const result = verifyReceipt(receipt!, verifier);
    expect(result.intact).toBe(true);
    expect(result.checks.map((c) => c.check)).toEqual(['PAYLOAD_HASH', 'LINK_HASH', 'SIGNATURE']);
  });

  it('detects a modified payload', () => {
    const [receipt] = chain(1);
    const tampered = { ...receipt!, payload: { ...receipt!.payload, decision: 'DENY' } };
    const result = verifyReceipt(tampered, verifier);
    expect(result.intact).toBe(false);
    expect(result.checks.find((c) => c.check === 'PAYLOAD_HASH')?.passed).toBe(false);
  });

  it('detects a payload rewritten together with its digest', () => {
    // The attacker recomputes payload_hash, so only the link hash betrays them.
    const [receipt] = chain(1);
    const rebuilt = buildReceipt({
      ...receipt!,
      payload: { decision: 'ALLOW', amount: { currency: 'USD', amountMinor: '99900000' }, seq: 1 },
    });
    const tampered = { ...rebuilt, hash: receipt!.hash, signature: receipt!.signature };
    const result = verifyReceipt(tampered, verifier);
    expect(result.intact).toBe(false);
    expect(result.checks.find((c) => c.check === 'LINK_HASH')?.passed).toBe(false);
  });

  it('detects a fully rebuilt receipt that the attacker could not sign', () => {
    const [receipt] = chain(1);
    const forged = buildReceipt({
      ...receipt!,
      payload: { decision: 'ALLOW', amount: { currency: 'USD', amountMinor: '99900000' }, seq: 1 },
    });
    const result = verifyReceipt(
      { ...forged, signature: receipt!.signature, signing_key_id: 'test-key-1' },
      verifier,
    );
    expect(result.intact).toBe(false);
    expect(result.checks.find((c) => c.check === 'SIGNATURE')?.passed).toBe(false);
  });

  it('detects a forged receipt whose signature was stripped rather than forged', () => {
    // The attack the optional signature check used to permit. An insider with
    // UPDATE on scrutexity.receipts cannot mint a signature -- but they never
    // needed to. They rewrite the payload, recompute both hashes (SHA-256 is
    // public), and delete the signature they could not produce. Structural
    // verification passes on every check it performs; the question is whether
    // it performs the one that matters.
    const [receipt] = chain(1);
    const forged = buildReceipt({
      ...receipt!,
      payload: { decision: 'ALLOW', amount: { currency: 'USD', amountMinor: '99900000' }, seq: 1 },
    });
    const stripped: Receipt = { ...forged, signature: null, signing_key_id: null };

    // Everything the attacker controls is internally consistent.
    const result = verifyReceipt(stripped, verifier);
    expect(result.checks.find((c) => c.check === 'PAYLOAD_HASH')?.passed).toBe(true);
    expect(result.checks.find((c) => c.check === 'LINK_HASH')?.passed).toBe(true);

    // And it is still not intact.
    expect(result.intact).toBe(false);
    expect(result.checks.find((c) => c.check === 'SIGNATURE')?.passed).toBe(false);
  });

  it('detects a rewritten and re-linked tail with the signatures dropped', () => {
    const receipts = chain(4);
    // Rewrite receipt 2 and re-link 3 and 4 behind it, unsigned throughout.
    const rebuilt: Receipt[] = [receipts[0]!];
    let previous = receipts[0]!.hash;
    for (const original of receipts.slice(1)) {
      const forged = buildReceipt({
        ...original,
        payload:
          original.seq === 2
            ? { decision: 'ALLOW', amount: { currency: 'USD', amountMinor: '99900000' }, seq: 2 }
            : original.payload,
        previous_hash: previous,
      });
      rebuilt.push({ ...forged, signature: null, signing_key_id: null });
      previous = forged.hash;
    }

    const result = verifyChain(rebuilt, verifier);
    expect(result.intact).toBe(false);
    // Caught at the first unsigned receipt, not merely at the end.
    expect(result.broken_at?.seq).toBe(2);
  });

  it('refuses to call a signed receipt intact without a key to check it against', () => {
    const [receipt] = chain(1);
    expect(verifyReceipt(receipt!).intact).toBe(false);
  });

  it('rejects a signature made by a different key', () => {
    const other = generateKeyPairSync('ed25519');
    const otherVerifier = ed25519Verifier(
      other.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      'test-key-1',
    );
    const [receipt] = chain(1);
    expect(verifyReceipt(receipt!, otherVerifier).intact).toBe(false);
  });

  it('is order- and formatting-independent in what it hashes', () => {
    const base = {
      id: 'rcpt_x',
      organization_id: 'org_acme',
      seq: 1,
      kind: 'EXECUTION' as const,
      previous_hash: GENESIS_HASH,
      created_at: '2026-03-01T00:00:00.000Z',
    };
    const a = buildReceipt({ ...base, payload: { b: 1, a: '2' } });
    const b = buildReceipt({ ...base, payload: { a: '2', b: 1 } });
    expect(a.hash).toBe(b.hash);
  });
});

describe('receipt chains', () => {
  it('verifies a well-formed chain', () => {
    const result = verifyChain(chain(5), verifier);
    expect(result.intact).toBe(true);
    expect(result.length).toBe(5);
    expect(result.broken_at).toBeNull();
  });

  it('detects a deleted receipt in the middle', () => {
    const receipts = chain(5);
    const withHole = [...receipts.slice(0, 2), ...receipts.slice(3)];
    const result = verifyChain(withHole, verifier);
    expect(result.intact).toBe(false);
    expect(result.broken_at?.seq).toBe(4);
  });

  it('detects a receipt substituted from elsewhere in the chain', () => {
    const receipts = chain(5);
    const swapped = [...receipts];
    swapped[2] = receipts[3]!;
    expect(verifyChain(swapped, verifier).intact).toBe(false);
  });

  it('detects a rewritten history even when every receipt is re-signed', () => {
    // The strongest attack available to whoever holds the signing key short of
    // rewriting the entire chain: it still cannot leave the earlier hashes intact.
    const original = chain(4);
    const forged: Receipt[] = [];
    let previous = GENESIS_HASH;
    for (const [index, receipt] of original.entries()) {
      const rebuilt = buildReceipt({
        ...receipt,
        payload: index === 1 ? { decision: 'ALLOW', tampered: true } : receipt.payload,
        previous_hash: previous,
        signer,
      });
      forged.push(rebuilt);
      previous = rebuilt.hash;
    }
    // Internally consistent...
    expect(verifyChain(forged, verifier).intact).toBe(true);
    // ...but every hash from the tampered point on has changed, so an
    // externally anchored head hash no longer matches.
    expect(forged[3]!.hash).not.toBe(original[3]!.hash);
  });

  it('requires the first receipt to carry the genesis link', () => {
    const receipts = chain(2);
    const badGenesis = [{ ...receipts[0]!, previous_hash: 'f'.repeat(64) }, receipts[1]!];
    expect(verifyChain(badGenesis, verifier).intact).toBe(false);
  });
});
