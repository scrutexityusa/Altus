import { ScrutexityError, computeDecisionContextHash } from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';

/**
 * Recomputing a decision's context fingerprint against the world as it stands
 * now.
 *
 * Shared by both execution paths -- the legacy self-report and the enforcement
 * boundary -- and deliberately in one place. Two implementations of "what did
 * this decision rest on" would eventually disagree, and the disagreement would
 * surface as an execution that should have been refused and was not.
 */
/**
 * Recomputes the decision's context fingerprint against the world as it stands
 * now: the same request, the same policy version and authority, and every risk
 * signal live at this instant.
 */
export async function currentContextHash(
  client: PoolClient,
  decision: {
    request_id: string;
    organization_id: string;
    policy_version_id: string | null;
    policy_hash: string | null;
    authority_lease_id: string | null;
  },
): Promise<string> {
  const request = await client.query(
    `SELECT agent_id, request_hash, resource_id, context
       FROM scrutexity.authorization_requests WHERE id = $1`,
    [decision.request_id],
  );
  const requestRow = request.rows[0] as
    | {
        agent_id: string;
        request_hash: string;
        resource_id: string;
        context: Record<string, unknown>;
      }
    | undefined;
  if (!requestRow) {
    throw new ScrutexityError(
      'NOT_FOUND',
      'the authorization request for this decision is missing',
    );
  }

  const subjects = [
    requestRow.agent_id,
    requestRow.resource_id,
    requestRow.context['counterparty_id'] as string | undefined,
    decision.organization_id,
  ].filter((value): value is string => typeof value === 'string');

  const signals = await client.query(
    `SELECT id, signal_type, subject_id, value
       FROM scrutexity.risk_signals
      WHERE organization_id = $1
        AND superseded_at IS NULL
        AND expires_at > now()
        AND subject_id = ANY($2::text[])
      ORDER BY id ASC
      LIMIT 200`,
    [decision.organization_id, subjects],
  );

  return computeDecisionContextHash({
    request_hash: requestRow.request_hash,
    policy_version_id: decision.policy_version_id,
    policy_hash: decision.policy_hash,
    authority_lease_id: decision.authority_lease_id,
    signals: signals.rows.map((row) => ({
      id: row.id as string,
      signal_type: row.signal_type as string,
      subject_id: row.subject_id as string,
      value: String(row.value),
    })),
  });
}
