import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AuthorityGrant } from '../src/authority/grant.js';
import type { AuthorityLease } from '../src/authority/lease.js';
import { loadPolicyYaml } from '../src/policy/loader.js';
import type { PolicyDocument } from '../src/policy/schema.js';
import type { EvaluationSnapshot, LeaseCandidate } from '../src/evaluate.js';
import type { SignalView } from '../src/policy/engine.js';
import { parseMoney } from '../src/money.js';

export const T0 = new Date('2026-03-01T12:00:00.000Z');

export const treasuryPolicy: PolicyDocument = loadPolicyYaml(
  readFileSync(
    fileURLToPath(new URL('../../../policies/treasury_wire.yaml', import.meta.url)),
    'utf8',
  ),
).document;

export function grant(overrides: Partial<AuthorityGrant> = {}): AuthorityGrant {
  return {
    actions: ['wire.create', 'wire.submit', 'wire.execute', 'counterparty.read'],
    resources: { bank_account: ['acct_001', 'acct_002'], counterparty: ['*'] },
    constraints: {
      max_amount: parseMoney('50000', 'USD'),
      currencies: ['USD'],
      allowed_counterparties: ['cp_100', 'cp_101'],
    },
    ...overrides,
  };
}

export function lease(overrides: Partial<AuthorityLease> = {}): AuthorityLease {
  return {
    id: 'lease_root',
    organization_id: 'org_acme',
    agent_id: 'agent_treasury',
    policy_version_id: 'polv_treasury_140',
    grant: grant(),
    status: 'ACTIVE',
    revocable: true,
    parent_lease_id: null,
    depth: 0,
    issued_at: new Date(T0.getTime() - 60_000).toISOString(),
    expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
    revoked_at: null,
    revocation_reason: null,
    ...overrides,
  };
}

export function signal(overrides: Partial<SignalView> = {}): SignalView {
  return {
    id: 'sig_1',
    subject_type: 'agent',
    subject_id: 'agent_treasury',
    signal_type: 'fraud_risk',
    value: '0.97',
    confidence: '0.91',
    source: 'external_fraud_engine',
    issued_at: T0.toISOString(),
    expires_at: new Date(T0.getTime() + 600_000).toISOString(),
    ...overrides,
  };
}

export interface SnapshotOptions {
  now?: Date;
  action?: string;
  amount?: string;
  currency?: string;
  counterpartyId?: string;
  counterpartyKnown?: boolean;
  destinationCountry?: string;
  resourceId?: string;
  resourceType?: string;
  agentStatus?: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  agentId?: string;
  agentHandle?: string;
  ownerUserId?: string | null;
  candidates?: LeaseCandidate[];
  signals?: SignalView[];
  priorApproval?: EvaluationSnapshot['prior_approval'];
  dependencies?: Partial<EvaluationSnapshot['dependencies']>;
  policy?: PolicyDocument | null;
}

export function snapshot(options: SnapshotOptions = {}): EvaluationSnapshot {
  const now = options.now ?? T0;
  const context: Record<string, unknown> = {
    counterparty_id: options.counterpartyId ?? 'cp_100',
    counterparty_known: options.counterpartyKnown ?? true,
    destination_country: options.destinationCountry ?? 'US',
  };
  if (options.amount !== undefined) {
    context['amount'] = parseMoney(options.amount, options.currency ?? 'USD');
    context['currency'] = options.currency ?? 'USD';
  }
  const root = lease();
  return {
    now,
    request: {
      id: 'areq_test',
      organization_id: 'org_acme',
      agent_id: options.agentId ?? 'agent_treasury',
      action: options.action ?? 'wire.execute',
      resource: {
        type: options.resourceType ?? 'bank_account',
        id: options.resourceId ?? 'acct_001',
        attributes: {},
      },
      context,
      presented_lease_id: null,
    },
    agent: {
      id: options.agentId ?? 'agent_treasury',
      handle: options.agentHandle ?? 'treasury-agent',
      status: options.agentStatus ?? 'ACTIVE',
      owner_user_id: options.ownerUserId === undefined ? 'user_owner' : options.ownerUserId,
    },
    policy:
      options.policy === null
        ? null
        : {
            policy_id: 'pol_treasury',
            policy_version_id: 'polv_treasury_140',
            document: options.policy ?? treasuryPolicy,
          },
    candidates: options.candidates ?? [{ lease: root, chain: [root] }],
    signals: options.signals ?? [],
    prior_approval: options.priorApproval ?? null,
    dependencies: {
      policy_available: true,
      signals_available: true,
      enforcement_available: true,
      ...options.dependencies,
    },
  };
}
