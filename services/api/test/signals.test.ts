import { generateKeyPairSync } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { newId, signSignalEd25519, signSignalHmac } from '@scrutexity/core';
import { buildApp, type App } from '../src/app.js';
import {
  APP_URL,
  ADMIN_URL,
  issueTreasuryLease,
  signedSignal,
  startHarness,
  wireRequest,
  type Harness,
} from './harness.js';

/**
 * ============================================================================
 * G-5: signals cannot forge authority.
 * ============================================================================
 *
 * Two independent layers, tested independently, because a system that relies
 * on one of them is one compromised key away from having none:
 *
 *   Cryptographic   a signal is attributable to an enrolled source, or it does
 *                   not influence anything.
 *   Containment     even a mathematically valid signal from a trusted source
 *                   can only ever subtract authority.
 *
 * The second is the one that matters most. The first assumes an attacker
 * cannot sign; the second holds when they can -- when the fraud engine itself
 * is fully compromised and signing whatever it likes with a key Scrutexity
 * correctly trusts. That is the realistic breach, and it must not be able to
 * turn a DENY into an ALLOW or raise a ceiling by one cent.
 */

let h: Harness;

beforeAll(async () => {
  h = await startHarness();
}, 120_000);

afterAll(async () => {
  await h?.close();
});

async function asOwner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({
    connectionString: process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL,
  });
  await client.connect();
  try {
    await client.query('SELECT set_config($1,$2,false)', [
      'scrutexity.org_id',
      h.tenant.organization_id,
    ]);
    return await fn(client);
  } finally {
    await client.end();
  }
}

const evaluate = (nonce: string, overrides: Record<string, unknown> = {}) =>
  h.call(
    'POST',
    '/v1/authorization/evaluate',
    h.tenant.tokens['treasury_agent']!,
    wireRequest({ nonce, ...overrides }),
  );

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

describe('signal source enrolment is mandatory', () => {
  it('refuses a source that has never registered a key', async () => {
    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.99',
      source: 'never_enrolled_engine',
      ttl_seconds: 600,
      event_id: 'evt-unenrolled-1',
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_SOURCE_NOT_ENROLLED');
  });

  it('records the refusal as a durable security event', async () => {
    await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.99',
      source: 'never_enrolled_engine',
      ttl_seconds: 600,
      event_id: 'evt-unenrolled-2',
    });
    const events = await h.call('GET', '/v1/security-events', h.tenant.tokens['admin']!);
    expect(
      events.body.security_events.some(
        (e: { kind: string; detail: { event_id?: string; reason?: string } }) =>
          e.kind === 'SIGNAL_REJECTED' &&
          e.detail.event_id === 'evt-unenrolled-2' &&
          e.detail.reason === 'source_not_enrolled',
      ),
    ).toBe(true);
  });

  it('writes nothing to the signal store when it refuses', async () => {
    const rows = await asOwner((client) =>
      client.query(`SELECT id FROM scrutexity.risk_signals WHERE source = $1`, [
        'never_enrolled_engine',
      ]),
    );
    expect(rows.rows).toEqual([]);
  });

  it('refuses an enrolled source that presents no signature', async () => {
    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.99',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
      event_id: 'evt-unsigned-1',
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_SIGNATURE_INVALID');
    expect(response.body.error.reason_code).toBe('SIGNATURE_MISSING');
  });

  it('accepts a correctly signed signal from an enrolled source', async () => {
    const response = await h.call(
      'POST',
      '/v1/signals',
      h.tenant.tokens['fraud_engine']!,
      signedSignal(h.tenant, {
        subject: { type: 'agent', id: h.tenant.agents['treasury']! },
        signal_type: 'anomaly_score',
        value: '0.11',
        source: 'external_fraud_engine',
        ttl_seconds: 600,
      }),
    );
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.signal.authenticated).toBe(true);
  });

  it('does not let one tenant sign for another', async () => {
    // The envelope binds organization_id, so a signature produced for one
    // tenant does not verify against another even when both have enrolled the
    // same source name with their own keys.
    const body = signedSignal(h.other, {
      subject: { type: 'agent', id: h.tenant.agents['treasury']! },
      signal_type: 'fraud_risk',
      value: '0.95',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
      event_id: 'evt-cross-tenant-1',
    });
    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, body);
    expect(response.status).toBe(403);
    // Rejected by the mathematics, not by a lookup miss. Both tenants seed the
    // same source under the same key id, so this tenant *finds* a key and
    // checks the signature against it -- and the signature does not verify,
    // because organization_id is inside the signed envelope. That is the
    // stronger of the two refusals: it would still hold if the attacker knew
    // which key id to name.
    expect(response.body.error.code).toBe('SIGNAL_SIGNATURE_INVALID');
  });
});

// ---------------------------------------------------------------------------
// Legacy HMAC
// ---------------------------------------------------------------------------

describe('legacy HMAC keys', () => {
  const legacySource = 'legacy_hmac_engine';
  const legacySecret = 'a-shared-secret-of-adequate-length';
  const legacyKeyId = 'legacy-k1';

  it('refuses to register one', async () => {
    const response = await h.call('POST', '/v1/signal-keys', h.tenant.tokens['admin']!, {
      source: legacySource,
      key_id: legacyKeyId,
      algorithm: 'HMAC_SHA256',
      key_material: legacySecret,
    });
    expect(response.status).toBe(400);
    expect(response.body.error.reason_code).toBe('HMAC_KEY_REFUSED');
  });

  it('refuses a signal signed by one that predates the check', async () => {
    // The migration case, and the reason registration is not the enforcement
    // point. This row is written straight to the table, exactly as one written
    // before the registration check existed -- or restored from a backup taken
    // before it -- would appear. A deployment that only refused new HMAC keys
    // would authenticate this signal.
    await asOwner((client) =>
      client.query(
        `INSERT INTO scrutexity.signal_signing_keys
           (id, organization_id, source, key_id, algorithm, key_material, not_before)
         VALUES ($1,$2,$3,$4,'HMAC_SHA256',$5, now())`,
        [newId('signalKey'), h.tenant.organization_id, legacySource, legacyKeyId, legacySecret],
      ),
    );

    const issuedAt = new Date(Date.now() - 1000).toISOString();
    const envelope = {
      organization_id: h.tenant.organization_id,
      subject_type: 'agent',
      subject_id: h.tenant.agents['treasury']!,
      signal_type: 'fraud_risk',
      value: '0.95',
      confidence: '1',
      source: legacySource,
      event_id: 'evt-legacy-hmac-1',
      issued_at: issuedAt,
      ttl_seconds: 600,
    };

    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: envelope.subject_id },
      signal_type: 'fraud_risk',
      value: '0.95',
      confidence: '1',
      source: legacySource,
      ttl_seconds: 600,
      issued_at: issuedAt,
      event_id: 'evt-legacy-hmac-1',
      // Mathematically correct for the key in the table. It is refused anyway.
      signature: signSignalHmac(envelope, legacySecret),
      signing_key_id: legacyKeyId,
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_KEY_UNKNOWN');
    expect(response.body.error.reason_code).toBe('ALGORITHM_NOT_PERMITTED');
  });

  it('verifies against the same row when a deployment explicitly opts in', async () => {
    // The positive control. Without it, the refusal above would also pass if
    // the signal were being rejected for some unrelated reason -- a bad
    // envelope, a stale timestamp -- and the test would prove nothing about
    // the algorithm rule.
    const migrating = await buildApp({
      NODE_ENV: 'test',
      DATABASE_URL: APP_URL,
      LOG_LEVEL: 'silent',
      SIGNAL_LEGACY_HMAC: 'permitted',
    });
    try {
      const issuedAt = new Date(Date.now() - 1000).toISOString();
      const envelope = {
        organization_id: h.tenant.organization_id,
        subject_type: 'agent',
        subject_id: h.tenant.agents['treasury']!,
        signal_type: 'model_confidence',
        value: '0.95',
        confidence: '1',
        source: legacySource,
        event_id: 'evt-legacy-hmac-2',
        issued_at: issuedAt,
        ttl_seconds: 600,
      };
      const response = await migrating.server.inject({
        method: 'POST',
        url: '/v1/signals',
        headers: {
          authorization: `Bearer ${h.tenant.tokens['fraud_engine']}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          subject: { type: 'agent', id: envelope.subject_id },
          signal_type: 'model_confidence',
          value: '0.95',
          confidence: '1',
          source: legacySource,
          ttl_seconds: 600,
          issued_at: issuedAt,
          event_id: 'evt-legacy-hmac-2',
          signature: signSignalHmac(envelope, legacySecret),
          signing_key_id: legacyKeyId,
        }),
      });
      expect(response.statusCode, response.body).toBe(201);
      expect(JSON.parse(response.body).signal.authenticated).toBe(true);
    } finally {
      await migrating.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Containment: the layer that holds when the crypto does not
// ---------------------------------------------------------------------------

describe('a valid signal from a trusted source cannot manufacture authority', () => {
  const source = 'external_fraud_engine';

  /**
   * Stands in for a fully compromised but legitimately trusted issuer: the
   * attacker holds the real private key and can sign anything. Nothing below
   * is a forgery; every signature verifies.
   */
  const asCompromisedIssuer = (request: Parameters<typeof signedSignal>[1]) =>
    h.call(
      'POST',
      '/v1/signals',
      h.tenant.tokens['fraud_engine']!,
      signedSignal(h.tenant, request),
    );

  it('cannot turn a DENY into an ALLOW', async () => {
    await issueTreasuryLease(h);
    // Denied on its merits: the counterparty is outside the lease entirely.
    const baseline = await evaluate('g5-deny-before', {
      context: {
        amount: '25000.00',
        currency: 'USD',
        counterparty_id: 'cp_999',
        destination_country: 'US',
      },
    });
    expect(baseline.body.decision).not.toBe('ALLOW');

    // Every plausible shape of "everything is fine, let it through".
    for (const [index, signal] of [
      { signal_type: 'fraud_risk', value: '0' },
      { signal_type: 'model_confidence', value: '1' },
      { signal_type: 'counterparty_risk', value: '0' },
      { signal_type: 'anomaly_score', value: '0' },
    ].entries()) {
      const ingested = await asCompromisedIssuer({
        subject: { type: 'agent', id: h.tenant.agents['treasury']! },
        ...signal,
        confidence: '1',
        source,
        ttl_seconds: 600,
        event_id: `evt-g5-allow-${index}`,
      });
      expect(ingested.status, JSON.stringify(ingested.body)).toBe(201);
      expect(ingested.body.signal.authenticated).toBe(true);
    }

    const after = await evaluate('g5-deny-after', {
      context: {
        amount: '25000.00',
        currency: 'USD',
        counterparty_id: 'cp_999',
        destination_country: 'US',
      },
    });
    expect(after.body.decision).not.toBe('ALLOW');
    expect(after.body.decision).toBe(baseline.body.decision);
  });

  it('cannot raise a ceiling', async () => {
    const lease = await issueTreasuryLease(h);
    const overCeiling = {
      amount: '99000.00', // above the policy's unattended threshold
      currency: 'USD',
      counterparty_id: 'cp_100',
      destination_country: 'US',
    };
    const baseline = await evaluate('g5-ceiling-before', { context: overCeiling });
    expect(baseline.body.decision).not.toBe('ALLOW');

    await asCompromisedIssuer({
      subject: { type: 'agent', id: h.tenant.agents['treasury']! },
      signal_type: 'fraud_risk',
      value: '0',
      confidence: '1',
      source,
      ttl_seconds: 600,
      event_id: 'evt-g5-ceiling-1',
    });

    const after = await evaluate('g5-ceiling-after', { context: overCeiling });
    expect(after.body.decision).not.toBe('ALLOW');

    // And the durable authority itself did not move. A decision that stayed
    // the same while the underlying grant widened would be a defect waiting
    // for the next request.
    const reread = await h.call(
      'GET',
      `/v1/authority-leases/${lease.id}`,
      h.tenant.tokens['admin']!,
    );
    expect(reread.body.authority_lease.grant.constraints.max_amount).toEqual({
      currency: 'USD',
      amountMinor: '5000000',
    });
  });

  it('cannot add an action the lease never held', async () => {
    const lease = await issueTreasuryLease(h);
    await asCompromisedIssuer({
      subject: { type: 'agent', id: h.tenant.agents['treasury']! },
      signal_type: 'model_confidence',
      value: '1',
      confidence: '1',
      source,
      ttl_seconds: 600,
      event_id: 'evt-g5-actions-1',
    });
    const reread = await h.call(
      'GET',
      `/v1/authority-leases/${lease.id}`,
      h.tenant.tokens['admin']!,
    );
    expect(reread.body.authority_lease.grant.actions.sort()).toEqual(
      ['account.read', 'counterparty.read', 'wire.create', 'wire.execute', 'wire.submit'].sort(),
    );
  });
});

// ---------------------------------------------------------------------------
// Key custody
// ---------------------------------------------------------------------------

describe('key material never leaves the boundary', () => {
  it('does not echo a public key back, and never saw the private one', async () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const registered = await h.call('POST', '/v1/signal-keys', h.tenant.tokens['admin']!, {
      source: 'custody_probe',
      key_id: 'custody-1',
      algorithm: 'ED25519',
      key_material: pem,
    });
    expect(registered.status).toBe(201);
    expect(JSON.stringify(registered.body)).not.toContain(pem.split('\n')[1]);
  });

  it('does not expose key material through the listing endpoint', async () => {
    const keys = await h.call('GET', '/v1/signal-keys', h.tenant.tokens['admin']!);
    for (const key of keys.body.signal_keys) {
      expect(Object.keys(key)).not.toContain('key_material');
    }
  });

  it('does not expose signal signatures or key material through the overview', async () => {
    const overview = await h.call('GET', '/v1/overview', h.tenant.tokens['admin']!);
    const serialised = JSON.stringify(overview.body);
    expect(serialised).not.toContain('key_material');
    expect(serialised).not.toContain('BEGIN PRIVATE KEY');
  });

  it('keeps the seeded source private key out of every response', async () => {
    // The seed holds both halves because it is standing up both ends. The
    // control plane must never have seen the private one -- if any response
    // contained it, it would have had to come from the database.
    const privatePem = h.tenant.signal_source_keys['external_fraud_engine']!.private_key_pem;
    const body = privatePem.split('\n')[1]!;
    for (const path of ['/v1/signal-keys', '/v1/overview', '/v1/security-events']) {
      const response = await h.call('GET', path, h.tenant.tokens['admin']!);
      expect(JSON.stringify(response.body), path).not.toContain(body);
    }
  });
});

// ---------------------------------------------------------------------------
// Deployment posture
// ---------------------------------------------------------------------------

describe('production refuses local key custody and unauthenticated signals', () => {
  const base = {
    NODE_ENV: 'production',
    DATABASE_URL: APP_URL,
    LOG_LEVEL: 'silent',
    SECRET_PROVIDER: 'kms',
    EXECUTION_PROVIDERS: 'none',
  } as const;

  const boot = (overrides: Record<string, string>) => buildApp({ ...base, ...overrides });

  it('refuses an unauthenticated signal posture', async () => {
    await expect(boot({ SIGNAL_AUTHENTICATION: 'permissive' })).rejects.toThrow(
      /SIGNAL_AUTHENTICATION must be "required"/,
    );
  });

  it('refuses legacy HMAC', async () => {
    await expect(boot({ SIGNAL_LEGACY_HMAC: 'permitted' })).rejects.toThrow(
      /SIGNAL_LEGACY_HMAC must be "refused"/,
    );
  });

  it('refuses a local secret provider', async () => {
    await expect(boot({ SECRET_PROVIDER: 'env' })).rejects.toThrow(/must be "kms"/);
    await expect(boot({ SECRET_PROVIDER: 'file' })).rejects.toThrow(/must be "kms"/);
  });

  it('refuses an inline signing key even when everything else is right', async () => {
    await expect(boot({ RECEIPT_SIGNING_KEY_B64: 'aGVsbG8=' })).rejects.toThrow(
      /RECEIPT_SIGNING_KEY_B64 must not be set in production/,
    );
  });

  it('refuses to start rather than sign evidence with an ephemeral key', async () => {
    // Every posture check above passes here. What stops the boot is that the
    // configured key manager has no key to give -- and the development
    // fallback, which generates one in memory, is not available in production.
    // Receipts signed by a key that vanishes on restart verify today and fail
    // tomorrow, which is worse than no receipts because it looks like proof.
    await expect(boot({})).rejects.toThrow(/no key manager is configured/);
  });
});

// ---------------------------------------------------------------------------
// The permissive posture is a posture, not an accident
// ---------------------------------------------------------------------------

describe('permissive posture', () => {
  let permissive: App;

  beforeAll(async () => {
    permissive = await buildApp({
      NODE_ENV: 'test',
      DATABASE_URL: APP_URL,
      LOG_LEVEL: 'silent',
      SIGNAL_AUTHENTICATION: 'permissive',
    });
  });

  afterAll(async () => {
    await permissive?.close();
  });

  const post = async (body: unknown) => {
    const response = await permissive.server.inject({
      method: 'POST',
      url: '/v1/signals',
      headers: {
        authorization: `Bearer ${h.tenant.tokens['fraud_engine']}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify(body),
    });
    return { status: response.statusCode, body: JSON.parse(response.body) };
  };

  it('admits an unenrolled source that makes no claim of authenticity', async () => {
    const response = await post({
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'anomaly_score',
      value: '0.1',
      source: 'permissive_probe',
      ttl_seconds: 600,
      event_id: 'evt-permissive-1',
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    // Recorded as what it is. Nothing downstream can mistake it for attributed.
    expect(response.body.signal.authenticated).toBe(false);
  });

  it('still refuses a claim of authenticity it cannot check', async () => {
    // The G-17 finding, pinned under the posture that tolerates the most.
    // Presenting a signature is a claim; a claim that cannot be checked fails.
    const response = await post({
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'anomaly_score',
      value: '0.1',
      source: 'permissive_probe',
      ttl_seconds: 600,
      event_id: 'evt-permissive-2',
      signature: 'Zm9yZ2Vk',
      signing_key_id: 'invented',
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_KEY_UNKNOWN');
  });

  it('still refuses a bad signature from an enrolled source', async () => {
    const response = await post({
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'anomaly_score',
      value: '0.1',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
      event_id: 'evt-permissive-3',
      signature: 'Zm9yZ2Vk',
      signing_key_id: h.tenant.signal_source_keys['external_fraud_engine']!.key_id,
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_SIGNATURE_INVALID');
  });

  it('signs correctly when the source has in fact enrolled', async () => {
    const body = signedSignal(h.tenant, {
      subject: { type: 'agent', id: h.tenant.agents['treasury']! },
      signal_type: 'anomaly_score',
      value: '0.05',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
      event_id: 'evt-permissive-4',
    });
    const response = await post(body);
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.signal.authenticated).toBe(true);
  });
});
