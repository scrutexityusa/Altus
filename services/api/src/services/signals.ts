import {
  ScrutexityError,
  addSeconds,
  newId,
  toDecimalString,
  verifySignal,
  type SignalSigningKey,
} from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './evidence.js';

/**
 * The signal plane (Section 12).
 *
 * Scrutexity does not detect fraud, score anomalies or model behaviour. It
 * consumes assertions from systems that do and turns them into authority
 * consequences. Every signal carries a TTL, and a signal without a live TTL is
 * simply not read -- so no stale assertion can suppress an agent's authority
 * indefinitely.
 */

export interface IngestSignalInput {
  organizationId: string;
  subjectType: 'agent' | 'user' | 'organization' | 'resource' | 'counterparty';
  subjectId: string;
  signalType: string;
  value: string | number;
  confidence?: string | number;
  source: string;
  ttlSeconds: number;
  issuedAt?: string;
  metadata?: Record<string, unknown>;
  /** Source-assigned unique id for this observation. Required to be signed. */
  eventId?: string | null;
  signature?: string | null;
  signingKeyId?: string | null;
  /**
   * When true, a signal that does not verify is refused. Set from the tenant's
   * configuration: whether an unauthenticated source may influence authority
   * is the tenant's call, not this service's.
   */
  requireAuthentication?: boolean;
}

const SIGNAL_TYPE = /^[a-z][a-z0-9_]{2,63}$/;
const MAX_TTL_SECONDS = 86_400;

export async function ingestSignal(
  client: PoolClient,
  keys: EvidenceKeys,
  input: IngestSignalInput,
) {
  if (!SIGNAL_TYPE.test(input.signalType)) {
    throw new ScrutexityError('INVALID_REQUEST', 'signal_type must be lower_snake_case');
  }
  if (input.ttlSeconds < 1 || input.ttlSeconds > MAX_TTL_SECONDS) {
    throw new ScrutexityError(
      'INVALID_REQUEST',
      `ttl_seconds must be between 1 and ${MAX_TTL_SECONDS}`,
    );
  }

  let value: string;
  let confidence: string;
  try {
    value = toDecimalString(input.value);
    confidence = toDecimalString(input.confidence ?? 1);
  } catch (error) {
    throw new ScrutexityError(
      'INVALID_REQUEST',
      error instanceof Error ? error.message : 'invalid signal value',
    );
  }

  const now = new Date();
  const issuedAt = input.issuedAt ? new Date(input.issuedAt) : now;
  if (Number.isNaN(issuedAt.getTime())) {
    throw new ScrutexityError('INVALID_REQUEST', 'issued_at is not a valid timestamp');
  }
  // A source may report slightly in the past but never in the future: a signal
  // dated forward would otherwise outlive its intended window.
  if (issuedAt.getTime() > now.getTime()) {
    throw new ScrutexityError('INVALID_REQUEST', 'issued_at may not be in the future');
  }
  if (now.getTime() - issuedAt.getTime() > MAX_TTL_SECONDS * 1000) {
    throw new ScrutexityError(
      'INVALID_REQUEST',
      'issued_at is too far in the past to be actionable',
    );
  }

  const expiresAt = addSeconds(issuedAt, input.ttlSeconds);
  if (expiresAt.getTime() <= now.getTime()) {
    throw new ScrutexityError('INVALID_REQUEST', 'the signal would already be expired on arrival');
  }

  // -- Authentication --------------------------------------------------------
  const signingKeys = await loadSigningKeys(client, input.organizationId, input.source);
  const verification = verifySignal(
    {
      organization_id: input.organizationId,
      subject_type: input.subjectType,
      subject_id: input.subjectId,
      signal_type: input.signalType,
      value,
      confidence,
      source: input.source,
      event_id: input.eventId ?? '',
      issued_at: issuedAt.toISOString(),
      ttl_seconds: input.ttlSeconds,
    },
    input.signature ?? null,
    input.signingKeyId ?? null,
    signingKeys,
    now,
  );

  if (!verification.verified) {
    const fatal =
      verification.reason !== 'no_key_configured' || input.requireAuthentication === true;
    metrics.signalInvalidSignature.inc({ reason: verification.reason, source: input.source });

    const securityEvent: SecurityEventInput = {
      organizationId: input.organizationId,
      kind: fatal ? 'SIGNAL_REJECTED' : 'SIGNAL_UNAUTHENTICATED',
      source: input.source,
      subjectId: input.subjectId,
      detail: {
        reason: verification.reason,
        key_id: verification.key_id,
        signal_type: input.signalType,
        event_id: input.eventId ?? null,
      },
    };

    if (fatal) {
      // Rejected outright: the signal does not reach the store and authority is
      // not modified. A source whose key is compromised must not be able to
      // move an agent's authority in either direction.
      //
      // The audit record travels on the error rather than being written here.
      // Throwing rolls this transaction back, which would take the record with
      // it -- so the caller writes it afterwards on its own transaction. A
      // rejected signal must leave a trace even though it leaves no signal.
      throw new ScrutexityError(
        verification.reason === 'unknown_key_id'
          ? 'SIGNAL_KEY_UNKNOWN'
          : 'SIGNAL_SIGNATURE_INVALID',
        `signal rejected: ${verification.reason}`,
        {
          reasonCode: verification.reason.toUpperCase(),
          disclose: true,
          internal: { securityEvent },
        },
      );
    }
    // Accepted but unauthenticated: this transaction commits, so the record can
    // be written inline.
    await recordSecurityEvent(client, securityEvent);
  }

  const signalId = newId('signal');

  // Insert before superseding: superseded_by_id points at this row, so the
  // row has to exist first or the foreign key rejects the whole ingestion.
  // A failed statement aborts the whole transaction in PostgreSQL, and the
  // rejection path below still needs to write a security event. The savepoint
  // is what lets us recover from the constraint violation and keep going.
  await client.query('SAVEPOINT signal_insert');
  let inserted;
  try {
    inserted = await client.query(
      `INSERT INTO scrutexity.risk_signals
       (id, organization_id, subject_type, subject_id, signal_type, value, confidence,
        source, metadata, issued_at, expires_at, event_id, signature, signing_key_id,
        authenticated)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     RETURNING *`,
      [
        signalId,
        input.organizationId,
        input.subjectType,
        input.subjectId,
        input.signalType,
        value,
        confidence,
        input.source,
        JSON.stringify(input.metadata ?? {}),
        issuedAt,
        expiresAt,
        input.eventId ?? null,
        input.signature ?? null,
        verification.verified ? verification.key_id : null,
        verification.verified,
      ],
    );
  } catch (error) {
    await client.query('ROLLBACK TO SAVEPOINT signal_insert');
    if ((error as { code?: string }).code === '23505') {
      // The unique index on (organization, source, event_id) is the replay
      // boundary. A source that re-delivers an event -- through a retry, or
      // deliberately to displace a fresher reading -- is refused here rather
      // than being allowed to move the risk picture backwards.
      metrics.replayAttempts.inc({ kind: 'signal_event' });
      throw new ScrutexityError('REPLAY_DETECTED', 'this signal event has already been ingested', {
        details: { event_id: input.eventId },
        disclose: true,
        internal: {
          securityEvent: {
            organizationId: input.organizationId,
            kind: 'SIGNAL_REPLAY_REJECTED',
            source: input.source,
            subjectId: input.subjectId,
            detail: { event_id: input.eventId ?? null, signal_type: input.signalType },
          } satisfies SecurityEventInput,
        },
      });
    }
    throw error;
  }

  // A newer assertion from the same source about the same subject replaces the
  // older one rather than accumulating alongside it, so a source cannot pin an
  // agent's authority down by shouting.
  const superseded = await client.query(
    `UPDATE scrutexity.risk_signals
        SET superseded_at = now(), superseded_by_id = $1
      WHERE organization_id = $2 AND subject_type = $3 AND subject_id = $4
        AND signal_type = $5 AND source = $6 AND superseded_at IS NULL
        AND id <> $1
      RETURNING id`,
    [
      signalId,
      input.organizationId,
      input.subjectType,
      input.subjectId,
      input.signalType,
      input.source,
    ],
  );

  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'SIGNAL_INGESTED',
    subjectId: input.subjectId,
    payload: {
      signal_id: signalId,
      subject_type: input.subjectType,
      subject_id: input.subjectId,
      signal_type: input.signalType,
      value,
      confidence,
      source: input.source,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      superseded_signal_ids: superseded.rows.map((r) => r.id as string),
      // Whether this assertion was cryptographically attributable to its
      // source is part of the evidence, not an implementation detail.
      authenticated: verification.verified,
      signing_key_id: verification.verified ? verification.key_id : null,
      event_id: input.eventId ?? null,
    },
  });

  metrics.signalsIngested.inc({ signal_type: input.signalType, source: input.source });

  const row = inserted.rows[0];
  return {
    signal: {
      id: row.id,
      subject_type: row.subject_type,
      subject_id: row.subject_id,
      signal_type: row.signal_type,
      value: String(row.value),
      confidence: String(row.confidence),
      source: row.source,
      issued_at: row.issued_at.toISOString(),
      expires_at: row.expires_at.toISOString(),
      authenticated: row.authenticated as boolean,
    },
    superseded_signal_ids: superseded.rows.map((r) => r.id as string),
    receipt_id: receipt.id,
  };
}

async function loadSigningKeys(
  client: PoolClient,
  organizationId: string,
  source: string,
): Promise<SignalSigningKey[]> {
  const result = await client.query(
    `SELECT id, key_id, source, algorithm, key_material, status, not_before, not_after
       FROM scrutexity.signal_signing_keys
      WHERE organization_id = $1 AND source = $2
      ORDER BY created_at DESC`,
    [organizationId, source],
  );
  return result.rows.map((row) => ({
    id: row.id as string,
    key_id: row.key_id as string,
    source: row.source as string,
    algorithm: row.algorithm as SignalSigningKey['algorithm'],
    key_material: row.key_material as string,
    status: row.status as SignalSigningKey['status'],
    not_before: (row.not_before as Date).toISOString(),
    not_after: row.not_after ? (row.not_after as Date).toISOString() : null,
  }));
}

export interface SecurityEventInput {
  organizationId: string;
  kind: string;
  source?: string | null;
  subjectId?: string | null;
  detail?: Record<string, unknown>;
}

/**
 * Records a security event. Append-only, tenant-scoped, and queryable without
 * reading application logs -- an operator investigating a rejected signal
 * should not need access to stdout on a production node.
 */
export async function recordSecurityEvent(
  client: PoolClient,
  input: SecurityEventInput,
): Promise<void> {
  await client.query(
    `INSERT INTO scrutexity.security_events
       (id, organization_id, kind, source, subject_id, detail)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [
      newId('securityEvent'),
      input.organizationId,
      input.kind,
      input.source ?? null,
      input.subjectId ?? null,
      JSON.stringify(input.detail ?? {}),
    ],
  );
  metrics.securityEvents.inc({ kind: input.kind });
}
