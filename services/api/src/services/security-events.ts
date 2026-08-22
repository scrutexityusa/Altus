import { newId } from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { metrics } from '../metrics.js';

/**
 * ============================================================================
 * Security evidence must survive the transaction that caused it.
 * ============================================================================
 *
 * This is an architectural invariant, not a convention, and it exists because
 * of a defect that was easy to write and hard to see:
 *
 *   1. A request is refused for a security reason.
 *   2. The handler records a security event.
 *   3. The handler throws.
 *   4. The transaction rolls back -- taking the security event with it.
 *
 * The system refused the attack and then destroyed the only record that the
 * attack happened. Worse, it does that *only* for refusals, so the audit log
 * is complete for everything except the events an operator most needs.
 *
 * The fix has one shape. A refusal attaches its event to the error rather than
 * writing it, and the route layer writes it afterwards on a connection the
 * failing transaction cannot roll back. `recordingRejections` in the route
 * layer is that step, and every mutating route runs inside it.
 *
 * Events covered by this invariant, all of which must reach here on the error:
 *
 *   - replay of a nonce, an execution grant or a signal
 *   - an invalid or unknown signal signature
 *   - an execution whose intent or binding did not match its grant
 *   - an execution against another agent's decision (confused deputy)
 *   - an execution against revoked or expired authority
 *   - a delegation exceeding its parent
 *   - a cross-tenant attempt
 *
 * ## Why not an outbox with a worker
 *
 * An outbox table plus a flush worker reaches the same guarantee with a table,
 * a daemon, a flush lag and a new failure mode. Writing on a second connection
 * at the moment the route unwinds is the same durability with none of that.
 *
 * The honest limit either design shares: if the process dies between the
 * refusal and the write, the event is lost. An outbox does not fix that unless
 * the write happens *before* the work, which would change the record from "we
 * refused this" to "we are about to consider this" -- a different and less
 * useful claim. The window is bounded by a single INSERT, and it is documented
 * rather than papered over.
 */

export interface SecurityEventInput {
  organizationId: string;
  /** Screaming snake case, and stable: operators alert on these. */
  kind: string;
  source?: string | null;
  subjectId?: string | null;
  /**
   * Structured detail. Must never carry a credential, a signature, a bearer
   * token or a full counterparty account number -- this table is read by more
   * people than the ones who may see those.
   */
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

/**
 * Reads a security event off an error, if it carries one.
 *
 * Events ride on `internal`, which is never serialised to a client, so a
 * refusal can carry the full detail of what was attempted without disclosing
 * any of it to whoever attempted it.
 */
export function securityEventOf(error: unknown): SecurityEventInput | undefined {
  return (error as { internal?: { securityEvent?: SecurityEventInput } })?.internal?.securityEvent;
}
