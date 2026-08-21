import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { ScrutexityError, newId } from '@scrutexity/core';
import type { Database, PoolClient } from './db/pool.js';

/**
 * Bearer credentials for machine and human principals.
 *
 * Token shape: `scr_<prefix>.<secret>`. Only the prefix is indexed and only a
 * SHA-256 of the whole token is stored, so a database disclosure does not
 * yield usable credentials. Comparison is constant time.
 *
 * The tenant is *derived from the credential*, never read from a header or a
 * body field. A client that could name its own tenant would have defeated
 * multi-tenancy in one line (Section 24).
 */

export interface Principal {
  credential_id: string;
  organization_id: string;
  type: 'user' | 'agent' | 'service';
  id: string;
  scopes: string[];
}

const TOKEN_PATTERN = /^scr_([0-9a-z]{16})\.([A-Za-z0-9_-]{32,64})$/;

export function issueToken(): { token: string; prefix: string; hash: Buffer } {
  const prefix = randomBytes(10).toString('hex').slice(0, 16);
  const secret = randomBytes(32).toString('base64url');
  const token = `scr_${prefix}.${secret}`;
  return { token, prefix, hash: createHash('sha256').update(token).digest() };
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

export function newCredentialId(): string {
  return newId('credential');
}

const UNAUTHORIZED = () => new ScrutexityError('UNAUTHORIZED', 'invalid or missing credentials');

export async function authenticate(db: Database, header: string | undefined): Promise<Principal> {
  if (!header || !header.startsWith('Bearer ')) throw UNAUTHORIZED();
  const token = header.slice(7).trim();
  const match = TOKEN_PATTERN.exec(token);
  if (!match) throw UNAUTHORIZED();

  const [, prefix] = match;
  const row = await db.withoutTenant(async (client: PoolClient) => {
    const result = await client.query('SELECT * FROM scrutexity.resolve_credential($1)', [prefix]);
    return result.rows[0] as
      | {
          id: string;
          organization_id: string;
          principal_type: Principal['type'];
          principal_id: string;
          token_hash: Buffer;
          scopes: string[];
          status: 'ACTIVE' | 'REVOKED';
          expires_at: Date | null;
        }
      | undefined;
  });

  // Hash the supplied token regardless of whether a row was found, so a
  // missing prefix and a wrong secret take the same time.
  const supplied = hashToken(token);
  const stored = row?.token_hash ?? Buffer.alloc(32);
  const matches = supplied.length === stored.length && timingSafeEqual(supplied, stored);

  if (!row || !matches) throw UNAUTHORIZED();
  if (row.status !== 'ACTIVE') throw UNAUTHORIZED();
  if (row.expires_at && row.expires_at.getTime() <= Date.now()) throw UNAUTHORIZED();

  return {
    credential_id: row.id,
    organization_id: row.organization_id,
    type: row.principal_type,
    id: row.principal_id,
    scopes: row.scopes,
  };
}

/**
 * Scope check.
 *
 * Agent credentials cannot administer the control plane -- an agent may ask
 * whether it is authorized, but it may not write the policy that answers,
 * issue itself a lease, or approve its own escalation -- and cannot *read* it
 * either. That second half was untrue until the `audit` scope existed: `read`
 * was granted and never asserted against, so an agent could fetch the policy
 * document governing it and the security-event log recording its own attacks.
 *
 * A comment is not a control. What makes the sentence above true is
 * `requireOperatorRead` on every operator route and `assertMayReadSubject` on
 * every per-resource read, each with an adversarial test in
 * services/api/test/security.test.ts.
 */
export const SCOPES = {
  authorize: 'authorization:evaluate',
  delegate: 'delegation:create',
  signalWrite: 'signals:write',
  leaseWrite: 'leases:write',
  approve: 'approvals:write',
  policyWrite: 'policies:write',
  adminWrite: 'admin:write',
  /**
   * Ordinary reads: an agent's own decisions, leases, traces and receipts.
   * Held by everyone, including agents.
   */
  read: 'read',
  /**
   * Operator reads: the policy documents themselves, the security event log,
   * signing key metadata, the agent register, unresolved executions.
   *
   * A separate scope from `read` because an agent must never hold it. Refusals
   * are written carefully not to leak policy internals and the corrective
   * handshake is deliberately narrow -- all of which is defeated if the agent
   * can simply fetch the policy that governs it. The security event log is
   * worse: it is the forensic record of attacks, including that agent's own.
   */
  audit: 'audit:read',
} as const;

export function requireScope(principal: Principal, scope: string): void {
  if (!principal.scopes.includes(scope)) {
    throw new ScrutexityError('FORBIDDEN', `credential lacks the "${scope}" scope`, {
      internal: { principal: principal.id, scope, held: principal.scopes },
    });
  }
}

/**
 * Refuses an agent principal.
 *
 * Distinct from `requireHuman`: a service credential (a fraud engine, a
 * reconciliation job) is a legitimate caller for operator-facing reads, but an
 * agent under policy never is. The thing being kept out is the principal whose
 * behaviour the control plane exists to constrain.
 */
export function requireNonAgent(principal: Principal): void {
  if (principal.type === 'agent') {
    throw new ScrutexityError('FORBIDDEN', 'agent credentials may not read the control plane', {
      internal: { principal: principal.id, principal_type: principal.type },
    });
  }
}

/** Agents may never act as the human half of a control. */
export function requireHuman(principal: Principal): void {
  if (principal.type !== 'user') {
    throw new ScrutexityError('FORBIDDEN', 'this operation requires a human principal', {
      internal: { principal_type: principal.type },
    });
  }
}
