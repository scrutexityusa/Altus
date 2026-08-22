import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { computeDecisionContextHash, compareDecisionContext } from '../src/context.js';
import { evaluateIntent, describeIntentEvaluation } from '../src/intent.js';
import { computeCorrectiveActions, minimalGrantFor } from '../src/corrective.js';
import { evaluateAuthorization } from '../src/evaluate.js';
import { effectiveLeaseStatus, grantState, isClaimableBy } from '../src/authority/lease.js';
import { loadPolicyYaml } from '../src/policy/loader.js';
import {
  signSignalHmac,
  signalSigningPayload,
  verifySignal,
  type SignalSigningKey,
} from '../src/signals.js';
import { lease, signal, snapshot, T0 } from './fixtures.js';

// ---------------------------------------------------------------------------
// Single-use grants
// ---------------------------------------------------------------------------

describe('single-use grant state machine', () => {
  const single = (overrides = {}) =>
    lease({ grant_type: 'SINGLE_USE', ...overrides } as Parameters<typeof lease>[0]);

  it('starts CREATED and reads as usable', () => {
    const grant = single();
    expect(grantState(grant, T0)).toBe('CREATED');
    expect(effectiveLeaseStatus(grant, T0)).toBe('ACTIVE');
  });

  it('is spent the moment it is claimed, not when it is executed', () => {
    // This is the property that makes exactly-once achievable: the claim is
    // what a database can serialise, so the claim is what counts.
    const claimed = single({ claimed_at: T0.toISOString(), claimed_by_decision_id: 'dec_1' });
    expect(grantState(claimed, T0)).toBe('CLAIMED');
    expect(effectiveLeaseStatus(claimed, T0)).toBe('CONSUMED');
  });

  it('reaches USED once executed', () => {
    const used = single({
      claimed_at: T0.toISOString(),
      claimed_by_decision_id: 'dec_1',
      consumed: true,
      used_at: T0.toISOString(),
    });
    expect(grantState(used, T0)).toBe('USED');
    expect(effectiveLeaseStatus(used, T0)).toBe('CONSUMED');
  });

  it('reports consumption rather than blaming the clock', () => {
    const both = single({
      consumed: true,
      claimed_at: T0.toISOString(),
      claimed_by_decision_id: 'dec_1',
      used_at: T0.toISOString(),
      expires_at: new Date(T0.getTime() - 1).toISOString(),
    });
    expect(effectiveLeaseStatus(both, T0)).toBe('CONSUMED');
  });

  it('admits a re-claim by the same decision but never by another', () => {
    const claimed = single({ claimed_at: T0.toISOString(), claimed_by_decision_id: 'dec_1' });
    expect(isClaimableBy(claimed, 'dec_1', T0)).toBe(true);
    expect(isClaimableBy(claimed, 'dec_2', T0)).toBe(false);
  });

  it('leaves reusable leases entirely unaffected', () => {
    const reusable = lease({ claimed_at: T0.toISOString(), claimed_by_decision_id: 'dec_1' });
    expect(grantState(reusable, T0)).toBe('CREATED');
    expect(effectiveLeaseStatus(reusable, T0)).toBe('ACTIVE');
  });

  it('refuses to authorize once spent', () => {
    const spent = single({
      consumed: true,
      claimed_at: T0.toISOString(),
      claimed_by_decision_id: 'd',
      used_at: T0.toISOString(),
    });
    const result = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: spent, chain: [spent] }] }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('AUTHORITY_CONSUMED');
  });
});

// ---------------------------------------------------------------------------
// Context fingerprinting (TOCTOU)
// ---------------------------------------------------------------------------

describe('decision context fingerprint', () => {
  const base = {
    request_hash: 'a'.repeat(64),
    policy_version_id: 'polv_1',
    policy_hash: 'b'.repeat(64),
    authority_lease_id: 'lease_1',
    signals: [
      { id: 'sig_b', signal_type: 'fraud_risk', subject_id: 'agent_1', value: '0.2' },
      { id: 'sig_a', signal_type: 'model_confidence', subject_id: 'agent_1', value: '0.9' },
    ],
  };

  it('is independent of the order signals came back in', () => {
    const reversed = { ...base, signals: [...base.signals].reverse() };
    expect(computeDecisionContextHash(base)).toBe(computeDecisionContextHash(reversed));
  });

  it('moves when a signal value changes', () => {
    const changed = {
      ...base,
      signals: [{ ...base.signals[0]!, value: '0.97' }, base.signals[1]!],
    };
    expect(computeDecisionContextHash(changed)).not.toBe(computeDecisionContextHash(base));
  });

  it('moves when a new signal arrives', () => {
    const extra = {
      ...base,
      signals: [
        ...base.signals,
        { id: 'sig_c', signal_type: 'fraud_risk', subject_id: 'agent_1', value: '0.99' },
      ],
    };
    expect(computeDecisionContextHash(extra)).not.toBe(computeDecisionContextHash(base));
  });

  it('moves when a signal expires away', () => {
    const fewer = { ...base, signals: [base.signals[0]!] };
    expect(computeDecisionContextHash(fewer)).not.toBe(computeDecisionContextHash(base));
  });

  it('moves when the policy version changes underneath', () => {
    expect(computeDecisionContextHash({ ...base, policy_hash: 'c'.repeat(64) })).not.toBe(
      computeDecisionContextHash(base),
    );
  });

  it('treats a decision with no recorded fingerprint as unverifiable', () => {
    // Fail closed. Records that predate the control are exactly the ones least
    // able to prove themselves, so they must not be the ones let through.
    const comparison = compareDecisionContext(null, 'a'.repeat(64), true);
    expect(comparison.matches).toBe(false);
  });

  it('distinguishes an approved decision from an unapproved one', () => {
    expect(compareDecisionContext('x', 'y', true).was_approved).toBe(true);
    expect(compareDecisionContext('x', 'y', false).was_approved).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Intent
// ---------------------------------------------------------------------------

describe('intent evaluation', () => {
  const intents = [
    {
      id: 'reconcile_cash_position',
      allowed_actions: ['account.read', 'statement.read'],
      forbidden_actions: ['wire.execute'],
    },
    {
      id: 'execute_wire_transfers',
      allowed_actions: ['wire.create', 'wire.submit'],
      forbidden_actions: [],
    },
  ];

  const evaluate = (overrides: Partial<Parameters<typeof evaluateIntent>[0]>) =>
    evaluateIntent({
      action: 'wire.execute',
      declared_intent: 'reconcile_cash_position',
      policy_intents: intents,
      require_declaration: false,
      lease_purpose: null,
      ...overrides,
    });

  it('produces the documented shape for a mismatch', () => {
    expect(evaluate({})).toEqual({
      declared_intent: 'reconcile_cash_position',
      attempted_action: 'wire.execute',
      match: false,
      reason: 'action_in_forbidden_list',
      policy_intent_id: 'reconcile_cash_position',
      lease_purpose: null,
    });
  });

  it('matches an action inside the declared intent', () => {
    const result = evaluate({ declared_intent: 'execute_wire_transfers', action: 'wire.create' });
    expect(result.match).toBe(true);
    expect(result.reason).toBe('matched');
  });

  it('refuses an action outside the allowed list', () => {
    expect(
      evaluate({ declared_intent: 'execute_wire_transfers', action: 'wire.read' }).reason,
    ).toBe('action_not_in_allowed_list');
  });

  it('refuses an intent the policy does not declare', () => {
    expect(evaluate({ declared_intent: 'do_whatever' }).reason).toBe('unknown_intent');
  });

  it('lets forbidden win over allowed when a policy contradicts itself', () => {
    const contradictory = [
      { id: 'muddled', allowed_actions: ['wire.execute'], forbidden_actions: ['wire.execute'] },
    ];
    const result = evaluate({ declared_intent: 'muddled', policy_intents: contradictory });
    expect(result.match).toBe(false);
    expect(result.reason).toBe('action_in_forbidden_list');
  });

  it('does not enforce when the policy declares no intents', () => {
    const result = evaluate({ policy_intents: [], declared_intent: null });
    expect(result.match).toBe(true);
    expect(result.reason).toBe('not_enforced');
  });

  it('requires a declaration when the policy says it must', () => {
    expect(evaluate({ declared_intent: null, require_declaration: true }).reason).toBe(
      'intent_not_declared',
    );
    expect(evaluate({ declared_intent: null, require_declaration: false }).match).toBe(true);
  });

  it('binds a purpose-bound grant even where policy does not enforce intent', () => {
    const result = evaluate({
      policy_intents: [],
      declared_intent: 'execute_wire_transfers',
      lease_purpose: 'reconcile_cash_position',
    });
    expect(result.match).toBe(false);
    expect(result.reason).toBe('purpose_mismatch');
  });

  it('renders every reason deterministically, with no prose generation', () => {
    for (const declared of ['reconcile_cash_position', 'do_whatever', null]) {
      const result = evaluate({ declared_intent: declared });
      const once = describeIntentEvaluation(result);
      expect(once).toBe(describeIntentEvaluation(result));
      expect(once.length).toBeGreaterThan(10);
    }
  });
});

describe('intent in the policy document', () => {
  it('normalises the shorthand form into a named intent', () => {
    const { document } = loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: treasury_wire
version: 1.0.0
metadata: { title: Treasury }
intent: execute wire transfers
allowed_actions: [wire.create, wire.submit]
forbidden_actions: [wire.modify, wire.execute]
rules:
  - id: allow_reads
    when: { action: account.read }
    then: { decision: ALLOW }
`);
    expect(document.intents).toHaveLength(1);
    expect(document.intents[0]).toMatchObject({
      id: 'treasury_wire',
      description: 'execute wire transfers',
      allowed_actions: ['wire.create', 'wire.submit'],
      forbidden_actions: ['wire.modify', 'wire.execute'],
    });
  });

  it('refuses intent_required with nothing to require', () => {
    expect(() =>
      loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: broken
version: 1.0.0
metadata: { title: Broken }
intent_required: true
rules:
  - id: allow_reads
    when: { action: account.read }
    then: { decision: ALLOW }
`),
    ).toThrow(/declares no intents/);
  });
});

describe('intent denial through the full evaluator', () => {
  const policy = loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: treasury_wire
version: 2.0.0
metadata: { title: Treasury with intent }
intent_required: true
intents:
  - id: reconcile_cash_position
    allowed_actions: [account.read, statement.read]
    forbidden_actions: [wire.execute, wire.create]
  - id: execute_wire_transfers
    allowed_actions: [wire.create, wire.submit, wire.execute]
rules:
  - id: allow_everything_policy_wise
    when: { action: { prefix: 'wire.' } }
    then: { decision: ALLOW }
  - id: allow_reads
    when: { action: { prefix: 'account.' } }
    then: { decision: ALLOW }
`).document;

  it('denies an action outside the declared intent even when policy allows it', () => {
    const result = evaluateAuthorization(
      snapshot({ amount: '100', policy, declaredIntent: 'reconcile_cash_position' }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('INTENT_MISMATCH');
    expect(result.intent_evaluation).toMatchObject({
      declared_intent: 'reconcile_cash_position',
      attempted_action: 'wire.execute',
      match: false,
      reason: 'action_in_forbidden_list',
    });
  });

  it('offers no corrective action for an out-of-bounds action', () => {
    const result = evaluateAuthorization(
      snapshot({ amount: '100', policy, declaredIntent: 'reconcile_cash_position' }),
    );
    expect(computeCorrectiveActions(result)).toEqual([]);
  });

  it('allows the same action under the right intent', () => {
    const result = evaluateAuthorization(
      snapshot({ amount: '100', policy, declaredIntent: 'execute_wire_transfers' }),
    );
    expect(result.decision).toBe('ALLOW');
    expect(result.intent_evaluation?.reason).toBe('matched');
  });

  it('refuses a request that declares nothing when policy requires it', () => {
    const result = evaluateAuthorization(snapshot({ amount: '100', policy, declaredIntent: null }));
    expect(result.reason_code).toBe('INTENT_MISMATCH');
    expect(result.intent_evaluation?.reason).toBe('intent_not_declared');
  });
});

// ---------------------------------------------------------------------------
// Corrective handshake
// ---------------------------------------------------------------------------

describe('corrective handshake', () => {
  it('offers nothing when the answer was yes', () => {
    const allowed = evaluateAuthorization(snapshot({ amount: '25000' }));
    expect(allowed.decision).toBe('ALLOW');
    expect(computeCorrectiveActions(allowed)).toEqual([]);
  });

  it('offers a lease request when no authority covers the action', () => {
    const result = evaluateAuthorization(snapshot({ amount: '25000', candidates: [] }));
    const actions = computeCorrectiveActions(result);
    expect(actions).toHaveLength(1);
    expect(actions[0]).toMatchObject({
      type: 'REQUEST_LEASE',
      reason: 'no_authority_covers_action',
    });
  });

  it('addresses a delegated agent to the agent that delegated to it', () => {
    const child = lease({
      id: 'lease_child',
      agent_id: 'agent_verification',
      parent_lease_id: 'lease_root',
      depth: 1,
      grant: {
        actions: ['counterparty.read'],
        resources: { counterparty: ['cp_100'] },
        constraints: {},
      },
    });
    const result = evaluateAuthorization(
      snapshot({
        agentId: 'agent_verification',
        action: 'wire.modify',
        amount: '5000',
        candidates: [{ lease: child, chain: [child, lease()] }],
      }),
    );
    const actions = computeCorrectiveActions(result, { delegating_agent_handle: 'treasury-agent' });
    expect(actions[0]).toMatchObject({
      type: 'REQUEST_DELEGATION',
      target_agent: 'treasury-agent',
    });
  });

  it('offers a human escalation carrying the requirement and a prefilled form', () => {
    const result = evaluateAuthorization(snapshot({ amount: '250000' }));
    const actions = computeCorrectiveActions(result, { approval_request_id: 'apr_1' });
    const escalation = actions.find((a) => a.type === 'HUMAN_ESCALATION');
    expect(escalation?.payload).toMatchObject({
      approval_request_id: 'apr_1',
      required_roles: ['treasurer'],
      quorum: 1,
    });
    expect(escalation?.prefilled_approval_form).toMatchObject({ action: 'wire.execute' });
  });

  it('never leaks a threshold, a rule id, or the value that would have passed', () => {
    // The whole point of a bounded handshake: an agent must not be able to
    // binary-search the policy by reading its own denials.
    const result = evaluateAuthorization(snapshot({ amount: '250000' }));
    const serialized = JSON.stringify(
      computeCorrectiveActions(result, { approval_request_id: 'apr_1' }),
    );
    expect(serialized).not.toContain('50000');
    expect(serialized).not.toContain('wire_fifty_thousand_and_above');
    expect(serialized).not.toContain('max_amount');
  });

  it('offers nothing for a hard policy violation', () => {
    for (const options of [
      { amount: '100', counterpartyKnown: false },
      { amount: '100', destinationCountry: 'KP' },
      { amount: '100', agentStatus: 'SUSPENDED' as const },
    ]) {
      const result = evaluateAuthorization(snapshot(options));
      expect(result.decision).toBe('DENY');
      expect(computeCorrectiveActions(result), JSON.stringify(options)).toEqual([]);
    }
  });

  it('offers nothing on revoked authority', () => {
    const revoked = lease({ status: 'REVOKED', revoked_at: T0.toISOString() });
    const result = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: revoked, chain: [revoked] }] }),
    );
    expect(computeCorrectiveActions(result)).toEqual([]);
  });

  it('suggests a fresh grant when a single-use one is spent', () => {
    const spent = lease({
      grant_type: 'SINGLE_USE',
      consumed: true,
      claimed_at: T0.toISOString(),
      claimed_by_decision_id: 'dec_1',
      used_at: T0.toISOString(),
    });
    const result = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: spent, chain: [spent] }] }),
    );
    const actions = computeCorrectiveActions(result);
    expect(actions[0]).toMatchObject({
      type: 'REQUEST_LEASE',
      reason: 'single_use_grant_already_spent',
    });
  });

  it('asks only for what the attempt needed', () => {
    const result = evaluateAuthorization(snapshot({ amount: '25000', candidates: [] }));
    const grant = minimalGrantFor(result);
    expect(grant.actions).toEqual(['wire.execute']);
    expect(grant.resources).toEqual({ bank_account: ['acct_001'] });
    expect(grant.constraints.allowed_counterparties).toEqual(['cp_100']);
  });

  it('is deterministic', () => {
    const result = evaluateAuthorization(snapshot({ amount: '250000' }));
    expect(JSON.stringify(computeCorrectiveActions(result, { approval_request_id: 'a' }))).toBe(
      JSON.stringify(computeCorrectiveActions(result, { approval_request_id: 'a' })),
    );
  });
});

// ---------------------------------------------------------------------------
// Signal authentication
// ---------------------------------------------------------------------------

describe('signal authentication', () => {
  const envelope = {
    organization_id: 'org_acme',
    subject_type: 'agent',
    subject_id: 'agent_treasury',
    signal_type: 'fraud_risk',
    value: '0.97',
    confidence: '0.91',
    source: 'external_fraud_engine',
    event_id: 'evt_1',
    issued_at: T0.toISOString(),
    ttl_seconds: 600,
  };

  const hmacKey: SignalSigningKey = {
    id: 'sigkey_1',
    key_id: 'k1',
    source: 'external_fraud_engine',
    algorithm: 'HMAC_SHA256',
    key_material: 'a-shared-secret-of-adequate-length',
    status: 'ACTIVE',
    not_before: new Date(T0.getTime() - 86_400_000).toISOString(),
    not_after: null,
  };

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const edKey: SignalSigningKey = {
    ...hmacKey,
    id: 'sigkey_2',
    key_id: 'k2',
    algorithm: 'ED25519',
    key_material: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
  const edSignature = edSign(
    null,
    Buffer.from(signalSigningPayload(envelope), 'utf8'),
    privateKey,
  ).toString('base64url');

  it('accepts a correctly signed HMAC signal', () => {
    const result = verifySignal(
      envelope,
      signSignalHmac(envelope, hmacKey.key_material),
      'k1',
      [hmacKey],
      T0,
    );
    expect(result).toMatchObject({ verified: true, key_id: 'k1', algorithm: 'HMAC_SHA256' });
  });

  it('accepts a correctly signed Ed25519 signal', () => {
    expect(verifySignal(envelope, edSignature, 'k2', [edKey], T0)).toMatchObject({
      verified: true,
      algorithm: 'ED25519',
    });
  });

  it('rejects a signature over different facts', () => {
    // Every field that determines the signal's effect is inside the envelope,
    // so tampering with any of them invalidates the signature.
    const signature = signSignalHmac(envelope, hmacKey.key_material);
    for (const tampered of [
      { ...envelope, value: '0.1' },
      { ...envelope, subject_id: 'agent_someone_else' },
      { ...envelope, ttl_seconds: 86_400 },
      { ...envelope, signal_type: 'model_confidence' },
      { ...envelope, event_id: 'evt_2' },
    ]) {
      expect(verifySignal(tampered, signature, 'k1', [hmacKey], T0)).toMatchObject({
        verified: false,
        reason: 'signature_invalid',
      });
    }
  });

  it('rejects a signal signed with the wrong secret', () => {
    expect(
      verifySignal(
        envelope,
        signSignalHmac(envelope, 'the-wrong-secret-entirely'),
        'k1',
        [hmacKey],
        T0,
      ),
    ).toMatchObject({
      verified: false,
      reason: 'signature_invalid',
    });
  });

  it('rejects an unknown key id rather than trying every key', () => {
    expect(verifySignal(envelope, 'whatever', 'k99', [hmacKey], T0)).toMatchObject({
      reason: 'unknown_key_id',
    });
  });

  it('rejects a missing signature when the source has keys configured', () => {
    expect(verifySignal(envelope, null, 'k1', [hmacKey], T0)).toMatchObject({
      reason: 'signature_missing',
    });
  });

  it('reports an unconfigured source distinctly, so the tenant can decide', () => {
    expect(verifySignal(envelope, null, null, [], T0)).toMatchObject({
      reason: 'no_key_configured',
    });
  });

  it('honours the rotation grace period, then stops', () => {
    const retiring: SignalSigningKey = {
      ...hmacKey,
      status: 'RETIRING',
      not_after: new Date(T0.getTime() + 60_000).toISOString(),
    };
    const signature = signSignalHmac(envelope, hmacKey.key_material);
    // Inside the window the outgoing key still works, which is what stops
    // signals being dropped while a source switches over.
    expect(verifySignal(envelope, signature, 'k1', [retiring], T0).verified).toBe(true);
    expect(
      verifySignal(envelope, signature, 'k1', [retiring], new Date(T0.getTime() + 61_000)),
    ).toMatchObject({ verified: false, reason: 'key_expired' });
  });

  it('gives a revoked key no grace period at all', () => {
    const revoked: SignalSigningKey = {
      ...hmacKey,
      status: 'REVOKED',
      not_after: new Date(T0.getTime() + 86_400_000).toISOString(),
    };
    expect(
      verifySignal(envelope, signSignalHmac(envelope, hmacKey.key_material), 'k1', [revoked], T0),
    ).toMatchObject({
      verified: false,
      reason: 'key_revoked',
    });
  });

  it('refuses a key that is not yet valid', () => {
    const future: SignalSigningKey = {
      ...hmacKey,
      not_before: new Date(T0.getTime() + 3_600_000).toISOString(),
    };
    expect(
      verifySignal(envelope, signSignalHmac(envelope, hmacKey.key_material), 'k1', [future], T0),
    ).toMatchObject({
      reason: 'key_not_yet_valid',
    });
  });

  it('does not let one source sign for another', () => {
    // This used to expect `no_key_configured`, which is the *non-fatal*
    // reason: a source that has not enrolled is allowed through as
    // unauthenticated. So a signal bearing another source's perfectly valid
    // signature was being accepted, because the receiving source happened to
    // have no keys of its own.
    //
    // Presenting a signature is a claim of authenticity, and a claim that
    // cannot be checked fails rather than passes. `unknown_key_id` is fatal.
    const otherSource = { ...envelope, source: 'a_different_engine' };
    const verification = verifySignal(
      otherSource,
      signSignalHmac(otherSource, hmacKey.key_material),
      'k1',
      [hmacKey],
      T0,
    );
    expect(verification.verified).toBe(false);
    expect(verification).toMatchObject({ reason: 'unknown_key_id' });
  });

  it('rejects a presented signature even when the source has no keys at all', () => {
    // The adversarial suite's A7 case, pinned here at the unit level: an
    // unenrolled source plus a forged signature must not be a 201.
    const verification = verifySignal(envelope, 'not-a-real-signature', 'no-such-key', [], T0);
    expect(verification.verified).toBe(false);
    expect(verification).toMatchObject({ reason: 'unknown_key_id' });
  });

  it('still admits an unenrolled source that presents no signature', () => {
    // The unauthenticated path is a deliberate posture for sources that have
    // not yet enrolled, and it is distinguishable in evidence. Tightening the
    // default is G-5's job; what must not happen is a *presented* signature
    // being ignored.
    const verification = verifySignal(envelope, null, null, [], T0);
    expect(verification).toMatchObject({ reason: 'no_key_configured' });
  });
});

// ---------------------------------------------------------------------------
// Invariant: signals only ever shrink autonomy
// ---------------------------------------------------------------------------

describe('invariant: a signal can never expand authority', () => {
  it('holds across the value range for every action in the treasury pack', () => {
    for (const action of ['wire.execute', 'wire.create', 'wire.submit']) {
      const withoutSignal = evaluateAuthorization(
        snapshot({ action, amount: '25000', signals: [] }),
      );
      for (const value of ['0', '0.5', '0.89', '0.9', '0.95', '1']) {
        const withSignal = evaluateAuthorization(
          snapshot({ action, amount: '25000', signals: [signal({ value })] }),
        );
        const severity = { ALLOW: 1, ESCALATE: 2, DENY: 3 } as const;
        expect(
          severity[withSignal.decision] >= severity[withoutSignal.decision],
          `${action} @ fraud_risk=${value}: a signal moved the decision towards permission`,
        ).toBe(true);
      }
    }
  });

  it('holds when a signal is added to an already-escalated request', () => {
    const escalated = evaluateAuthorization(snapshot({ amount: '250000' }));
    const withSignal = evaluateAuthorization(
      snapshot({ amount: '250000', signals: [signal({ value: '0.97' })] }),
    );
    expect(escalated.decision).toBe('ESCALATE');
    expect(withSignal.decision).not.toBe('ALLOW');
  });
});
