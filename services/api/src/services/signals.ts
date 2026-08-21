import { ScrutexityError, addSeconds, newId, toDecimalString } from '@scrutexity/core';
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
}

const SIGNAL_TYPE = /^[a-z][a-z0-9_]{2,63}$/;
const MAX_TTL_SECONDS = 86_400;

export async function ingestSignal(client: PoolClient, keys: EvidenceKeys, input: IngestSignalInput) {
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
    throw new ScrutexityError('INVALID_REQUEST', 'issued_at is too far in the past to be actionable');
  }

  const expiresAt = addSeconds(issuedAt, input.ttlSeconds);
  if (expiresAt.getTime() <= now.getTime()) {
    throw new ScrutexityError('INVALID_REQUEST', 'the signal would already be expired on arrival');
  }

  const signalId = newId('signal');

  // A newer assertion from the same source about the same subject replaces the
  // older one, rather than accumulating alongside it.
  const superseded = await client.query(
    `UPDATE scrutexity.risk_signals
        SET superseded_at = now(), superseded_by_id = $1
      WHERE organization_id = $2 AND subject_type = $3 AND subject_id = $4
        AND signal_type = $5 AND source = $6 AND superseded_at IS NULL
      RETURNING id`,
    [signalId, input.organizationId, input.subjectType, input.subjectId, input.signalType, input.source],
  );

  const inserted = await client.query(
    `INSERT INTO scrutexity.risk_signals
       (id, organization_id, subject_type, subject_id, signal_type, value, confidence,
        source, metadata, issued_at, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
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
    },
    superseded_signal_ids: superseded.rows.map((r) => r.id as string),
    receipt_id: receipt.id,
  };
}
