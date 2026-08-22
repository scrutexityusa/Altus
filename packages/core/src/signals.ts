import { createHmac, createPublicKey, timingSafeEqual, verify as edVerify } from 'node:crypto';
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
  'no_key_configured',
  'unknown_key_id',
  'key_revoked',
  'key_not_yet_valid',
  'key_expired',
  'signature_invalid',
  'signature_missing',
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
 * Verifies a signal against the keys configured for its source.
 *
 * When a source has no keys at all the signal is reported unverified rather
 * than rejected outright: whether an unauthenticated source may influence
 * authority is a tenant's decision, not this function's. The caller enforces
 * it, and records the choice either way.
 */
export function verifySignal(
  envelope: SignalEnvelope,
  signature: string | null,
  keyId: string | null,
  keys: readonly SignalSigningKey[],
  now: Date,
): SignalVerification {
  const candidates = keys.filter((key) => key.source === envelope.source);

  // A presented signature is always verified, even when the source has no
  // registered key. Checking `no_key_configured` first -- as this did -- meant
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
    return { verified: false, reason: 'no_key_configured', key_id: null };
  if (!signature) return { verified: false, reason: 'signature_missing', key_id: keyId };

  const key = keyId ? candidates.find((candidate) => candidate.key_id === keyId) : undefined;
  if (!key) return { verified: false, reason: 'unknown_key_id', key_id: keyId };

  const unusable = isKeyUsable(key, now);
  if (unusable) return { verified: false, reason: unusable, key_id: key.key_id };

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

/** Signs an envelope with an HMAC secret. Used by tests and by source SDKs. */
export function signSignalHmac(envelope: SignalEnvelope, secret: string): string {
  return createHmac('sha256', secret)
    .update(Buffer.from(signalSigningPayload(envelope), 'utf8'))
    .digest('base64url');
}
