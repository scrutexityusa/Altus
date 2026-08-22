import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  timingSafeEqual,
  verify as edVerify,
} from 'node:crypto';
import { canonicalize } from './canonical.js';
import { isExpired } from './time.js';

/**
 * ============================================================================
 * Signal authentication.
 * ============================================================================
 *
 * A signal can only shrink authority, so forging one cannot grant an attacker
 * anything. It can still do damage: suppress a competitor's agent, or -- more
 * quietly -- replay a stale low-risk reading to displace the current high-risk
 * one and open a window. Both are attacks on the accuracy of the risk picture,
 * which is the thing authority decay depends on.
 *
 * So signals are signed by their source and verified before they can influence
 * anything.
 *
 * Ed25519 is preferred: only a public key is stored, so a database disclosure
 * yields nothing an attacker can sign with. HMAC-SHA256 exists for sources
 * that cannot manage a keypair, and its shared secret must live in the
 * database -- which is why it is the second choice and is flagged in the
 * migration for encryption at rest before real data.
 */

export const SIGNAL_KEY_ALGORITHMS = ['ED25519', 'HMAC_SHA256'] as const;
export type SignalKeyAlgorithm = (typeof SIGNAL_KEY_ALGORITHMS)[number];

export const SIGNAL_KEY_STATUSES = ['ACTIVE', 'RETIRING', 'REVOKED'] as const;
export type SignalKeyStatus = (typeof SIGNAL_KEY_STATUSES)[number];

export interface SignalSigningKey {
  id: string;
  key_id: string;
  source: string;
  algorithm: SignalKeyAlgorithm;
  /** Ed25519: SPKI PEM public key. HMAC: the shared secret. */
  key_material: string;
  status: SignalKeyStatus;
  not_before: string;
  not_after: string | null;
}

/**
 * The bytes a source signs. Everything that determines the signal's effect is
 * inside: change any of it and the signature stops verifying.
 *
 * `event_id` is in the envelope so that a replayed delivery of an old event is
 * recognisable as the same event, and a re-signed variant of it is a different
 * one that the store will still reject on the unique index.
 */
export interface SignalEnvelope {
  organization_id: string;
  subject_type: string;
  subject_id: string;
  signal_type: string;
  value: string;
  confidence: string;
  source: string;
  event_id: string;
  issued_at: string;
  ttl_seconds: number;
}

export function signalSigningPayload(envelope: SignalEnvelope): string {
  return canonicalize({
    organization_id: envelope.organization_id,
    subject_type: envelope.subject_type,
    subject_id: envelope.subject_id,
    signal_type: envelope.signal_type,
    value: envelope.value,
    confidence: envelope.confidence,
    source: envelope.source,
    event_id: envelope.event_id,
    issued_at: envelope.issued_at,
    ttl_seconds: envelope.ttl_seconds,
  });
}

export const SIGNAL_REJECTION_REASONS = [
  /**
   * The source has no signing key registered at all.
   *
   * Named for the fact rather than for the configuration state that produced
   * it: `no_key_configured`, which this replaces, read as an operator oversight
   * that could reasonably be tolerated. It is not. A source with no key is a
   * source nothing can be attributed to, and enrolment -- not tolerance -- is
   * the fix. See ADR-0018.
   */
  'source_not_enrolled',
  'unknown_key_id',
  'key_revoked',
  'key_not_yet_valid',
  'key_expired',
  'signature_invalid',
  'signature_missing',
  /**
   * The key is enrolled and the signature may even be mathematically valid,
   * but the deployment does not permit that algorithm.
   *
   * This is what rejects a legacy HMAC key. Refusing HMAC at *registration*
   * only stops new ones; a row written before that check existed, or restored
   * from a backup taken before it, would still authenticate. Enforcement has
   * to be at verification, where every signal passes, and not at the one
   * moment a key happens to be created.
   */
  'algorithm_not_permitted',
] as const;

export type SignalRejectionReason = (typeof SIGNAL_REJECTION_REASONS)[number];

export type SignalVerification =
  | { verified: true; key_id: string; algorithm: SignalKeyAlgorithm }
  | { verified: false; reason: SignalRejectionReason; key_id: string | null };

/**
 * Is this key usable right now?
 *
 * RETIRING is deliberately still usable until `not_after`. That overlap is the
 * rotation grace period: a source switching keys keeps signing with the old
 * one until it has confirmed the new one works, and no signals are dropped in
 * between. REVOKED has no grace period, because revocation is what you reach
 * for when a key is believed compromised.
 */
export function isKeyUsable(key: SignalSigningKey, now: Date): SignalRejectionReason | null {
  if (key.status === 'REVOKED') return 'key_revoked';
  if (new Date(key.not_before).getTime() > now.getTime()) return 'key_not_yet_valid';
  if (key.not_after !== null && isExpired(key.not_after, now)) return 'key_expired';
  return null;
}

/**
 * Verifies a signal against the keys registered for its source.
 *
 * Reports rather than throws. Whether an unenrolled source may still influence
 * authority is a deployment posture, not a property of the mathematics, and
 * this function has no business knowing which posture is in force -- so it
 * returns the reason and the caller enforces it. Production has exactly one
 * posture (see config.ts), and the caller records the choice either way.
 */
export interface VerifySignalOptions {
  /**
   * The algorithms this deployment accepts. Defaults to all of them.
   *
   * Narrowing this is how a deployment refuses key material it has decided it
   * should never have held. It is checked before the signature is verified, so
   * a refused algorithm never runs its verification at all.
   */
  allowedAlgorithms?: readonly SignalKeyAlgorithm[];
}

export function verifySignal(
  envelope: SignalEnvelope,
  signature: string | null,
  keyId: string | null,
  keys: readonly SignalSigningKey[],
  now: Date,
  options: VerifySignalOptions = {},
): SignalVerification {
  const candidates = keys.filter((key) => key.source === envelope.source);

  // A presented signature is always verified, even when the source has no
  // registered key. Checking enrolment first -- as this did -- meant
  // a caller could attach any bytes at all and have them ignored, because that
  // reason is treated as non-fatal for sources that have not yet enrolled.
  //
  // Presenting a signature is a claim of authenticity. A claim that cannot be
  // checked is not a claim that passes; it is one that fails. Found by the
  // adversarial suite (A7), which submitted a forged signature against an
  // unenrolled source and got a 201.
  if (signature && candidates.length === 0)
    return { verified: false, reason: 'unknown_key_id', key_id: keyId };

  if (candidates.length === 0)
    return { verified: false, reason: 'source_not_enrolled', key_id: null };
  if (!signature) return { verified: false, reason: 'signature_missing', key_id: keyId };

  const key = keyId ? candidates.find((candidate) => candidate.key_id === keyId) : undefined;
  if (!key) return { verified: false, reason: 'unknown_key_id', key_id: keyId };

  const unusable = isKeyUsable(key, now);
  if (unusable) return { verified: false, reason: unusable, key_id: key.key_id };

  const allowed = options.allowedAlgorithms ?? SIGNAL_KEY_ALGORITHMS;
  if (!allowed.includes(key.algorithm))
    return { verified: false, reason: 'algorithm_not_permitted', key_id: key.key_id };

  const payload = Buffer.from(signalSigningPayload(envelope), 'utf8');
  const ok =
    key.algorithm === 'ED25519'
      ? verifyEd25519(payload, signature, key.key_material)
      : verifyHmac(payload, signature, key.key_material);

  return ok
    ? { verified: true, key_id: key.key_id, algorithm: key.algorithm }
    : { verified: false, reason: 'signature_invalid', key_id: key.key_id };
}

function verifyEd25519(payload: Buffer, signature: string, publicKeyPem: string): boolean {
  try {
    return edVerify(
      null,
      payload,
      createPublicKey(publicKeyPem),
      Buffer.from(signature, 'base64url'),
    );
  } catch {
    return false;
  }
}

function verifyHmac(payload: Buffer, signature: string, secret: string): boolean {
  try {
    const expected = createHmac('sha256', secret).update(payload).digest();
    const supplied = Buffer.from(signature, 'base64url');
    // Length is checked first because timingSafeEqual throws on a mismatch,
    // and a thrown error is itself an oracle.
    return expected.length === supplied.length && timingSafeEqual(expected, supplied);
  } catch {
    return false;
  }
}

/**
 * Signs an envelope with an Ed25519 private key.
 *
 * The production path. Only the public half is ever stored by Scrutexity, so
 * a database disclosure yields nothing an attacker can sign with -- which is
 * the whole reason this is preferred over HMAC, where the verifier necessarily
 * holds the secret that produces signatures.
 *
 * Lives here so a source SDK and the test suite sign exactly the way the
 * verifier expects. Two implementations of "what bytes get signed" eventually
 * disagree, and the disagreement looks like a forged signal.
 */
export function signSignalEd25519(envelope: SignalEnvelope, privateKeyPem: string): string {
  return edSign(
    null,
    Buffer.from(signalSigningPayload(envelope), 'utf8'),
    createPrivateKey(privateKeyPem),
  ).toString('base64url');
}

/**
 * Signs an envelope with an HMAC secret.
 *
 * Development and legacy only. HMAC requires the verifier to hold the same
 * secret that produces signatures, so the party checking authenticity can also
 * manufacture it -- acceptable for a local fixture, not for a source whose
 * signals reduce authority over real money. Production refuses to register
 * HMAC keys at all; see ADR-0018.
 */
export function signSignalHmac(envelope: SignalEnvelope, secret: string): string {
  return createHmac('sha256', secret)
    .update(Buffer.from(signalSigningPayload(envelope), 'utf8'))
    .digest('base64url');
}
