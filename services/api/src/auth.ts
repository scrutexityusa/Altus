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
    const result = await client.query(
      'SELECT * FROM scrutexity.resolve_credential($1)',
      [prefix],
    );
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
 * Scope check. Agent credentials deliberately cannot administer the control
 * plane: an agent may ask whether it is authorized, but it may not write the
 * policy that answers, issue itself a lease, or approve its own escalation.
 */
export const SCOPES = {
  authorize: 'authorization:evaluate',
  delegate: 'delegation:create',
  signalWrite: 'signals:write',
  leaseWrite: 'leases:write',
  approve: 'approvals:write',
  policyWrite: 'policies:write',
  adminWrite: 'admin:write',
  read: 'read',
} as const;

export function requireScope(principal: Principal, scope: string): void {
  if (!principal.scopes.includes(scope)) {
    throw new ScrutexityError('FORBIDDEN', `credential lacks the "${scope}" scope`, {
      internal: { principal: principal.id, scope, held: principal.scopes },
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
