import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScrutexityClient } from '../src/index.js';

/**
 * ============================================================================
 * The safe path has to be the easy path.
 * ============================================================================
 *
 * `guard()` is the SDK's ergonomic helper and the one every integration reaches
 * for. It used to authorize, run a caller-supplied callback, and then report
 * the outcome to `POST /v1/executions` -- the self-reported path, which
 * verifies nothing about the operation because it never sees one. So the
 * pleasant, documented, obvious method was the unenforced one, and the
 * enforcement boundary was a separate call a caller had to know to look for.
 *
 * These tests assert the network calls rather than the wiring. A spy on the
 * client's own methods would prove that `guard` calls `execute`, which is a
 * statement about this file's implementation. What a caller actually gets is a
 * sequence of HTTP requests, so that is what is pinned: a real server records
 * every path it receives, and the assertion is that `/v1/execute` appears and
 * `/v1/executions` does not.
 *
 * The distinction is not academic -- those two paths differ by one character.
 */

let server: Server;
let baseUrl: string;
let received: { method: string; path: string; body: unknown }[] = [];

const ALLOW = () => ({
  status: 200,
  body: {
    decision_id: 'dec_test',
    decision: 'ALLOW',
    reason_code: 'WITHIN_LEASED_AUTHORITY',
    corrective_actions: [],
  },
});

/** Canned responses keyed by path. Enough shape for the client to parse. */
const RESPONSES: Record<string, () => { status: number; body: unknown }> = {
  'POST /v1/authorization/evaluate': ALLOW,
  'POST /v1/execute': () => ({
    status: 201,
    body: {
      execution_id: 'xclaim_test',
      claim_id: 'xclaim_test',
      receipt_id: 'rcpt_test',
      status: 'EXECUTED',
      external_reference: 'sim-1',
      provider: 'test-provider',
      intent_verified: true,
      replayed: false,
    },
  }),
  'POST /v1/executions': () => ({
    status: 201,
    body: { execution_id: 'exec_test', receipt_id: 'rcpt_test' },
  }),
};

beforeAll(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk as Buffer));
    req.on('end', () => {
      const path = (req.url ?? '').split('?')[0]!;
      received.push({
        method: req.method ?? '',
        path,
        body: chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null,
      });
      const canned = RESPONSES[`${req.method} ${path}`];
      const result = canned ? canned() : { status: 404, body: { error: { code: 'NOT_FOUND' } } };
      res.writeHead(result.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(result.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const client = () => new ScrutexityClient({ baseUrl, token: 'scr_test.secret' });

const wire = {
  agentId: 'treasury-agent',
  action: 'wire.execute',
  resource: 'bank_account:acct_001',
  context: { amount: '25000.00', currency: 'USD', counterparty_id: 'cp_100' },
};

describe('guard() reaches the enforcement boundary', () => {
  beforeAll(async () => {
    received = [];
    await client().guard(wire);
  });

  it('calls POST /v1/execute and never POST /v1/executions', async () => {
    const paths = received.map((r) => `${r.method} ${r.path}`);
    expect(paths).toContain('POST /v1/execute');
    // The assertion that would have failed before this change, and the reason
    // this test talks to a socket instead of a spy.
    expect(paths).not.toContain('POST /v1/executions');
  });

  it('returns the boundary’s outcome rather than the caller’s word for it', async () => {
    received = [];
    const outcome = await client().guard(wire);
    // The status came from the enforcement boundary, which performed the
    // operation. On the old path this field was whatever the caller reported.
    expect(outcome.execution?.status).toBe('EXECUTED');
  });

  it('sends the operation it authorized, field for field', async () => {
    // The boundary compares hashes. If the SDK reshapes the operation between
    // the two calls -- a defaulted field, a coerced number, a dropped key --
    // every governed execution becomes INTENT_MISMATCH.
    const evaluate = received.find((r) => r.path === '/v1/authorization/evaluate')!;
    const execute = received.find((r) => r.path === '/v1/execute')!;

    const authorized = evaluate.body as { action: string; resource: unknown; context: unknown };
    const presented = (execute.body as { operation: typeof authorized }).operation;

    expect(presented.action).toBe(authorized.action);
    expect(presented.resource).toEqual(authorized.resource);
    expect(presented.context).toEqual(authorized.context);
  });

  it('parses a "type:id" resource string identically on both calls', () => {
    for (const path of ['/v1/authorization/evaluate', '/v1/execute']) {
      const request = received.find((r) => r.path === path)!;
      const body = request.body as { resource?: unknown; operation?: { resource: unknown } };
      expect(body.resource ?? body.operation?.resource, path).toEqual({
        type: 'bank_account',
        id: 'acct_001',
      });
    }
  });
});

describe('guard() does not reach the boundary without an ALLOW', () => {
  beforeAll(() => {
    RESPONSES['POST /v1/authorization/evaluate'] = () => ({
      status: 200,
      body: {
        decision_id: 'dec_escalated',
        decision: 'ESCALATE',
        reason_code: 'TREASURER_APPROVAL_REQUIRED',
        approval_request_id: 'apr_1',
        corrective_actions: [],
      },
    });
    received = [];
  });

  afterAll(() => {
    RESPONSES['POST /v1/authorization/evaluate'] = ALLOW;
  });

  it('stops at the decision and contacts nothing else', async () => {
    const outcome = await client().guard(wire);

    expect(outcome.decision.decision).toBe('ESCALATE');
    expect(outcome.decision.allowed).toBe(false);
    expect(outcome.execution).toBeNull();
    // An escalation is not a soft yes. Nothing downstream is contacted.
    expect(received.map((r) => r.path)).toEqual(['/v1/authorization/evaluate']);
  });
});

describe('the self-reported path is a different verb', () => {
  beforeAll(() => {
    received = [];
  });

  it('is named so it cannot be mistaken for governed execution', () => {
    const sdk = client() as unknown as Record<string, unknown>;
    expect(typeof sdk['recordExternalExecution']).toBe('function');
    // The old name is gone rather than deprecated. A method called
    // `recordExecution` sitting beside `execute` is an invitation to reach for
    // the wrong one, which is exactly what happened.
    expect(sdk['recordExecution']).toBeUndefined();
  });

  it('reaches the unenforced route only when called by name', async () => {
    await client().recordExternalExecution('dec_test', 'SUCCEEDED', { ref: 'WIRE-1' });
    expect(received.map((r) => r.path)).toEqual(['/v1/executions']);
  });
});
