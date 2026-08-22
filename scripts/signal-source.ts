import { randomUUID } from 'node:crypto';
import { signSignalEd25519, toDecimalString } from '@scrutexity/core';
import type { SeedResult } from './seed.js';

/**
 * A stand-in for an external signal source.
 *
 * Enrolment is mandatory and unsigned signals are refused, so anything that
 * wants a signal to land -- the demo, the test suite, the adversarial runner --
 * has to sign it the way a real fraud engine would. This is that signer, and
 * it lives in one place so the demo and the tests cannot drift into signing
 * differently from each other.
 *
 * In a real deployment none of this is Scrutexity's code: the source generates
 * its own keypair, registers the public half, and keeps the private half. The
 * seed holds both ends only because it is standing up both ends.
 */

export interface SignalRequest {
  subject: { type: string; id: string };
  signal_type: string;
  value: string | number;
  confidence?: string | number;
  source: string;
  ttl_seconds: number;
  issued_at?: string;
  event_id?: string;
  metadata?: Record<string, unknown>;
}

export function signedSignal(tenant: SeedResult, request: SignalRequest) {
  const key = tenant.signal_source_keys[request.source];
  if (!key) throw new Error(`signal source "${request.source}" is not enrolled in this tenant`);

  const eventId = request.event_id ?? `evt-${randomUUID()}`;
  // Filled in here rather than left to the server, because the signature covers
  // it -- a signer that lets the receiver choose part of the payload is not
  // signing the payload. Set slightly in the past so that a database clock a
  // few milliseconds behind this process does not read it as dated forward,
  // which the ingest path refuses.
  const issuedAt = request.issued_at ?? new Date(Date.now() - 1000).toISOString();

  const signature = signSignalEd25519(
    {
      organization_id: tenant.organization_id,
      subject_type: request.subject.type,
      subject_id: request.subject.id,
      signal_type: request.signal_type,
      // The server canonicalises before signing, so the client must too. Both
      // sides go through the same function; two renderings of "0.97" that
      // disagree would look exactly like a forgery.
      value: toDecimalString(request.value),
      confidence: toDecimalString(request.confidence ?? 1),
      source: request.source,
      event_id: eventId,
      issued_at: issuedAt,
      ttl_seconds: request.ttl_seconds,
    },
    key.private_key_pem,
  );

  return {
    ...request,
    event_id: eventId,
    issued_at: issuedAt,
    signature,
    signing_key_id: key.key_id,
  };
}
