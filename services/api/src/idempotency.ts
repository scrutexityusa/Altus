import { hashObject, ScrutexityError } from '@scrutexity/core';
import type { PoolClient } from './db/pool.js';

/**
 * Idempotency for mutating endpoints (Section 25).
 *
 * A retried network call must not issue a second lease, record a second
 * approval, or authorise a second wire. The key is claimed inside the same
 * transaction as the effect, so a concurrent duplicate blocks on the row and
 * then reads the stored response instead of doing the work twice.
 *
 * Reusing a key with a different body is reported rather than silently
 * honoured: that is a client bug, and hiding it would hide a lost write.
 */

export interface IdempotencyHit {
  status_code: number;
  body: unknown;
}

export async function claimIdempotencyKey(
  client: PoolClient,
  organizationId: string,
  endpoint: string,
  key: string,
  requestBody: unknown,
): Promise<IdempotencyHit | null> {
  const requestHash = hashObject(requestBody ?? null);

  const inserted = await client.query(
    `INSERT INTO scrutexity.idempotency_keys (organization_id, endpoint, key, request_hash)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (organization_id, endpoint, key) DO NOTHING
     RETURNING key`,
    [organizationId, endpoint, key, requestHash],
  );
  if ((inserted.rowCount ?? 0) > 0) return null; // first caller: do the work

  // Someone already claimed it. Take the row lock so we serialise behind them.
  const existing = await client.query(
    `SELECT request_hash, status_code, response_body, completed_at
       FROM scrutexity.idempotency_keys
      WHERE organization_id = $1 AND endpoint = $2 AND key = $3
      FOR UPDATE`,
    [organizationId, endpoint, key],
  );
  const row = existing.rows[0] as
    | {
        request_hash: string;
        status_code: number | null;
        response_body: unknown;
        completed_at: Date | null;
      }
    | undefined;
  if (!row) return null;

  if (row.request_hash !== requestHash) {
    throw new ScrutexityError(
      'IDEMPOTENCY_CONFLICT',
      'this idempotency key was already used with a different request body',
    );
  }
  if (row.completed_at === null) {
    // The original attempt is still running or died mid-flight. Refusing is
    // safer than racing it: the caller may retry.
    throw new ScrutexityError(
      'STATE_CONFLICT',
      'a request with this idempotency key is still in progress',
    );
  }
  return { status_code: row.status_code ?? 200, body: row.response_body };
}

export async function completeIdempotencyKey(
  client: PoolClient,
  organizationId: string,
  endpoint: string,
  key: string,
  statusCode: number,
  body: unknown,
): Promise<void> {
  await client.query(
    `UPDATE scrutexity.idempotency_keys
        SET status_code = $4, response_body = $5, completed_at = now()
      WHERE organization_id = $1 AND endpoint = $2 AND key = $3`,
    [organizationId, endpoint, key, statusCode, JSON.stringify(body)],
  );
}
