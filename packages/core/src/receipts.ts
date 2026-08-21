import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { GENESIS_HASH, canonicalize, hashObject, sha256Hex } from './canonical.js';

/**
 * ============================================================================
 * Tamper-evident evidence (Section 19).
 * ============================================================================
 *
 * What this proves: that the evidence you are reading is the evidence that was
 * written, in the order it was written, by the holder of the signing key.
 *
 * What this does not prove: that the decision recorded in it was correct,
 * lawful or wise. Scrutexity makes no such claim, and the verification API
 * deliberately does not use language that implies one.
 *
 * Chains are per-tenant. Cross-tenant linkage would leak the existence and
 * rate of one customer's decisions into another's evidence.
 */

export const RECEIPT_KINDS = [
  'AUTHORIZATION_DECISION',
  'APPROVAL',
  'EXECUTION',
  'LEASE_ISSUED',
  'LEASE_REVOKED',
  'DELEGATION_CREATED',
  'SIGNAL_INGESTED',
  'POLICY_ACTIVATED',
] as const;

export type ReceiptKind = (typeof RECEIPT_KINDS)[number];

export interface Receipt {
  id: string;
  organization_id: string;
  seq: number;
  kind: ReceiptKind;
  subject_id: string | null;
  request_id: string | null;
  decision_id: string | null;
  payload: Record<string, unknown>;
  payload_hash: string;
  previous_hash: string;
  hash: string;
  signature: string | null;
  signing_key_id: string | null;
  created_at: string;
}

export interface ReceiptSigner {
  keyId: string;
  sign(hashHex: string): string;
}

export interface ReceiptVerifier {
  keyId: string;
  verify(hashHex: string, signature: string): boolean;
}

/**
 * The bytes that are hashed. Every field that a reader would rely on is
 * inside the hash, including the position in the chain and the link backwards:
 * an attacker who rewrites one receipt must rewrite every receipt after it and
 * then forge a signature over each.
 */
function linkPreimage(receipt: Omit<Receipt, 'hash' | 'signature' | 'signing_key_id'>): string {
  return canonicalize({
    id: receipt.id,
    organization_id: receipt.organization_id,
    seq: receipt.seq,
    kind: receipt.kind,
    subject_id: receipt.subject_id,
    request_id: receipt.request_id,
    decision_id: receipt.decision_id,
    payload_hash: receipt.payload_hash,
    previous_hash: receipt.previous_hash,
    created_at: receipt.created_at,
  });
}

export interface BuildReceiptInput {
  id: string;
  organization_id: string;
  seq: number;
  kind: ReceiptKind;
  subject_id?: string | null;
  request_id?: string | null;
  decision_id?: string | null;
  payload: Record<string, unknown>;
  previous_hash: string;
  created_at: string;
  signer?: ReceiptSigner;
}

export function buildReceipt(input: BuildReceiptInput): Receipt {
  const core = {
    id: input.id,
    organization_id: input.organization_id,
    seq: input.seq,
    kind: input.kind,
    subject_id: input.subject_id ?? null,
    request_id: input.request_id ?? null,
    decision_id: input.decision_id ?? null,
    payload: input.payload,
    payload_hash: hashObject(input.payload),
    previous_hash: input.previous_hash,
    created_at: input.created_at,
  };
  const hash = sha256Hex(linkPreimage(core));
  return {
    ...core,
    hash,
    signature: input.signer ? input.signer.sign(hash) : null,
    signing_key_id: input.signer?.keyId ?? null,
  };
}

export interface VerificationCheck {
  check: 'PAYLOAD_HASH' | 'LINK_HASH' | 'SIGNATURE' | 'CHAIN_LINKAGE' | 'SEQUENCE';
  passed: boolean;
  detail: string;
}

export interface VerificationResult {
  /** True only when every performed check passed. */
  intact: boolean;
  receipt_id: string;
  checks: VerificationCheck[];
}

/**
 * Verifies one receipt in isolation: that its payload still hashes to the
 * recorded digest, that its link hash is consistent, and -- if a verifier is
 * supplied -- that the signature over the link hash is valid.
 */
export function verifyReceipt(receipt: Receipt, verifier?: ReceiptVerifier): VerificationResult {
  const checks: VerificationCheck[] = [];

  const recomputedPayload = hashObject(receipt.payload);
  checks.push({
    check: 'PAYLOAD_HASH',
    passed: recomputedPayload === receipt.payload_hash,
    detail:
      recomputedPayload === receipt.payload_hash
        ? 'payload matches its recorded digest'
        : `payload digest mismatch: recorded ${receipt.payload_hash}, recomputed ${recomputedPayload}`,
  });

  const recomputedLink = sha256Hex(linkPreimage(receipt));
  checks.push({
    check: 'LINK_HASH',
    passed: recomputedLink === receipt.hash,
    detail:
      recomputedLink === receipt.hash
        ? 'receipt hash matches its contents'
        : `receipt hash mismatch: recorded ${receipt.hash}, recomputed ${recomputedLink}`,
  });

  if (receipt.signature && verifier) {
    const ok =
      receipt.signing_key_id === verifier.keyId && verifier.verify(receipt.hash, receipt.signature);
    checks.push({
      check: 'SIGNATURE',
      passed: ok,
      detail: ok
        ? `signature verified against key ${verifier.keyId}`
        : `signature did not verify against key ${verifier.keyId}`,
    });
  } else if (receipt.signature) {
    checks.push({
      check: 'SIGNATURE',
      passed: false,
      detail: 'receipt is signed but no verification key was supplied',
    });
  }

  return { intact: checks.every((c) => c.passed), receipt_id: receipt.id, checks };
}

export interface ChainVerificationResult {
  intact: boolean;
  organization_id: string | null;
  length: number;
  /** First receipt at which the chain stops verifying, if any. */
  broken_at: { receipt_id: string; seq: number; reason: string } | null;
  receipts: VerificationResult[];
}

/** Verifies an ordered slice of a tenant's chain, including its linkage. */
export function verifyChain(
  receipts: readonly Receipt[],
  verifier?: ReceiptVerifier,
): ChainVerificationResult {
  const results: VerificationResult[] = [];
  let broken: ChainVerificationResult['broken_at'] = null;

  for (const [index, receipt] of receipts.entries()) {
    const result = verifyReceipt(receipt, verifier);
    const previous = index === 0 ? null : receipts[index - 1]!;

    if (previous) {
      const linked = receipt.previous_hash === previous.hash;
      result.checks.push({
        check: 'CHAIN_LINKAGE',
        passed: linked,
        detail: linked
          ? `links to receipt ${previous.id}`
          : `expected previous_hash ${previous.hash}, found ${receipt.previous_hash}`,
      });
      const sequential = receipt.seq === previous.seq + 1;
      result.checks.push({
        check: 'SEQUENCE',
        passed: sequential,
        detail: sequential
          ? 'sequence is contiguous'
          : `sequence jumped ${previous.seq} -> ${receipt.seq}`,
      });
      result.intact = result.checks.every((c) => c.passed);
    } else if (receipt.seq === 1) {
      const genesis = receipt.previous_hash === GENESIS_HASH;
      result.checks.push({
        check: 'CHAIN_LINKAGE',
        passed: genesis,
        detail: genesis ? 'chain genesis' : 'first receipt does not carry the genesis link',
      });
      result.intact = result.checks.every((c) => c.passed);
    }

    results.push(result);
    if (!result.intact && !broken) {
      broken = {
        receipt_id: receipt.id,
        seq: receipt.seq,
        reason: result.checks.find((c) => !c.passed)?.detail ?? 'verification failed',
      };
    }
  }

  return {
    intact: broken === null,
    organization_id: receipts[0]?.organization_id ?? null,
    length: receipts.length,
    broken_at: broken,
    receipts: results,
  };
}

// ---------------------------------------------------------------------------
// Ed25519 signing
// ---------------------------------------------------------------------------

export function ed25519Signer(
  privateKeyPem: string | Buffer | KeyObject,
  keyId: string,
): ReceiptSigner {
  const key =
    privateKeyPem instanceof Object && 'asymmetricKeyType' in privateKeyPem
      ? (privateKeyPem as KeyObject)
      : createPrivateKey(privateKeyPem as string | Buffer);
  return {
    keyId,
    sign: (hashHex) => edSign(null, Buffer.from(hashHex, 'utf8'), key).toString('base64url'),
  };
}

export function ed25519Verifier(
  publicKeyPem: string | Buffer | KeyObject,
  keyId: string,
): ReceiptVerifier {
  const key =
    publicKeyPem instanceof Object && 'asymmetricKeyType' in publicKeyPem
      ? (publicKeyPem as KeyObject)
      : createPublicKey(publicKeyPem as string | Buffer);
  return {
    keyId,
    verify: (hashHex, signature) => {
      try {
        return edVerify(
          null,
          Buffer.from(hashHex, 'utf8'),
          key,
          Buffer.from(signature, 'base64url'),
        );
      } catch {
        return false;
      }
    },
  };
}

export { GENESIS_HASH };
