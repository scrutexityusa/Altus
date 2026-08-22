/**
 * The treasury demo (Sections 30 and 44).
 *
 * Runs the complete story against a real HTTP server backed by real Postgres:
 * agent identity, authority issuance, an allowed wire, a replayed execution
 * grant, an escalated wire, a human approval, delegation, a delegated
 * violation, a risk signal, authority decay, immediate revocation, and
 * evidence verification including a tampered receipt.
 *
 * It asserts as it goes. `make demo` failing is a real failure, not a cosmetic
 * one -- this script is part of the test suite, not a slideshow.
 */
import { execSync } from 'node:child_process';
import { buildApp } from '../services/api/src/app.js';
import { seed, type SeedResult } from './seed.js';
import { signedSignal } from './signal-source.js';

const ADMIN_URL =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

const ESC = `${String.fromCharCode(27)}[`;
const paint = (code: string, text: string) =>
  process.env['NO_COLOR'] ? text : `${ESC}${code}m${text}${ESC}0m`;
const bold = (t: string) => paint('1', t);
const dim = (t: string) => paint('2', t);
const green = (t: string) => paint('32', t);
const red = (t: string) => paint('31', t);
const yellow = (t: string) => paint('33', t);

let sceneNumber = 0;
function scene(title: string): void {
  sceneNumber += 1;
  process.stdout.write(`\n${bold(`-- Scene ${sceneNumber}: ${title}`)}\n`);
}
function step(text: string): void {
  process.stdout.write(`   ${dim('.')} ${text}\n`);
}
function outcome(decision: string, detail: string): void {
  const colour = decision === 'ALLOW' ? green : decision === 'DENY' ? red : yellow;
  process.stdout.write(`   ${colour(bold(decision.padEnd(8)))} ${detail}\n`);
}

class DemoFailure extends Error {}

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new DemoFailure(message);
}

async function main(): Promise<void> {
  process.stdout.write(bold('\nScrutexity -- treasury authorization demo\n'));

  step('resetting the database and seeding the reference tenant');
  execSync('pnpm exec tsx scripts/migrate.ts --reset', {
    stdio: 'ignore',
    env: { ...process.env, DATABASE_ADMIN_URL: ADMIN_URL },
  });
  const fixtures: SeedResult = await seed(ADMIN_URL);

  const app = await buildApp({
    NODE_ENV: 'development',
    DATABASE_URL: APP_URL,
    LOG_LEVEL: 'silent',
  });
  await app.server.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.addresses()[0]!;
  const base = `http://127.0.0.1:${address.port}`;

  const call = async (
    method: string,
    path: string,
    token: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ) => {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  };

  const t = fixtures.tokens;

  try {
    scene('Agent identity');
    const agentList = await call('GET', '/v1/agents', t['admin']!);
    expect(agentList.status === 200, 'agent listing failed');
    for (const agent of agentList.body.agents) {
      step(`${bold(agent.handle)} -- ${agent.display_name} (owner ${agent.owner_user_id})`);
    }

    scene('Authority issuance');
    const leaseResponse = await call('POST', '/v1/authority-leases', t['admin']!, {
      agent_id: 'treasury-agent',
      grant: {
        actions: [
          'wire.create',
          'wire.submit',
          'wire.execute',
          'wire.read',
          'counterparty.read',
          'account.read',
        ],
        resources: { bank_account: ['acct_001', 'acct_002'], counterparty: ['cp_100', 'cp_101'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '5000000' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100', 'cp_101'],
        },
      },
      ttl_seconds: 3600,
    });
    expect(
      leaseResponse.status === 201,
      `lease issuance failed: ${JSON.stringify(leaseResponse.body)}`,
    );
    const lease = leaseResponse.body.authority_lease;
    step(`lease ${bold(lease.id)} issued to treasury-agent`);
    step('scope: wire.create, wire.submit, wire.execute over acct_001 and acct_002');
    step(`ceiling: ${green('$50,000.00 USD')}; counterparties cp_100 and cp_101`);
    step(`expires: ${lease.expires_at}`);

    scene('A $25,000 wire -- inside the agent discretion');
    const small = await call('POST', '/v1/authorization/evaluate', t['treasury_agent']!, {
      agent_id: 'treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: '25000.00',
        currency: 'USD',
        counterparty_id: 'cp_100',
        destination_country: 'US',
      },
      nonce: `demo-small-${Date.now()}`,
    });
    expect(
      small.body.decision === 'ALLOW',
      `expected ALLOW, got ${small.body.decision} (${small.body.reason_code})`,
    );
    outcome(
      small.body.decision,
      `${small.body.reason_code} -- grant valid until ${small.body.expires_at}`,
    );
    step(
      `policy ${small.body.policy_id} v${small.body.policy_version} (${small.body.policy_hash.slice(0, 12)})`,
    );

    const execution = await call('POST', '/v1/executions', t['treasury_agent']!, {
      decision_id: small.body.decision_id,
      status: 'SUCCEEDED',
      result: { wire_reference: 'WIRE-2026-0001' },
    });
    expect(
      execution.status === 201,
      `execution recording failed: ${JSON.stringify(execution.body)}`,
    );
    step(`executed; receipt ${execution.body.receipt_id}`);

    step('replaying the same execution grant...');
    const replay = await call('POST', '/v1/executions', t['treasury_agent']!, {
      decision_id: small.body.decision_id,
      status: 'SUCCEEDED',
      result: { wire_reference: 'WIRE-2026-0001' },
    });
    expect(
      replay.body.error?.code === 'REPLAY_DETECTED',
      'a reused execution grant must be refused',
    );
    outcome('DENY', `${replay.body.error.code} -- an ALLOW is a single-use grant`);

    scene('A $75,000 wire -- beyond the agent discretion');
    const large = await call('POST', '/v1/authorization/evaluate', t['treasury_agent']!, {
      agent_id: 'treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: '75000.00',
        currency: 'USD',
        counterparty_id: 'cp_101',
        destination_country: 'CH',
      },
      nonce: `demo-large-${Date.now()}`,
    });
    expect(large.body.decision === 'ESCALATE', `expected ESCALATE, got ${large.body.decision}`);
    outcome(large.body.decision, `${large.body.reason_code}`);
    step(
      `requires ${large.body.approval_requirement.quorum} approval from ${large.body.approval_requirement.roles.join(', ')}`,
    );
    const ceiling = large.body.constraints_evaluated.find(
      (c: { constraint: string }) => c.constraint === 'max_amount',
    );
    step(`constraint check: ${ceiling.message}`);

    scene('The treasurer approves');
    const approval = await call('POST', '/v1/approvals', t['treasurer']!, {
      approval_request_id: large.body.approval_request_id,
      vote: 'APPROVED',
      comment: 'Verified against purchase order PO-88431.',
    });
    expect(approval.status === 201, `approval failed: ${JSON.stringify(approval.body)}`);
    expect(approval.body.decision.decision === 'ALLOW', 'approval should have produced an ALLOW');
    outcome(approval.body.decision.decision, `${approval.body.decision.reason_code}`);
    step(
      `approved as ${bold(approval.body.satisfied_role)}; new decision ${approval.body.decision.decision_id}`,
    );
    step('the escalated decision is superseded, never rewritten');

    step('the CFO attempts to approve the same request...');
    const secondApproval = await call('POST', '/v1/approvals', t['cfo']!, {
      approval_request_id: large.body.approval_request_id,
      vote: 'APPROVED',
    });
    expect(
      secondApproval.body.error?.code === 'STATE_CONFLICT',
      'a satisfied approval request must not accept more votes',
    );
    step(dim(`refused: ${secondApproval.body.error.message}`));

    scene('Delegation -- verification only');
    const delegation = await call('POST', '/v1/delegations', t['treasury_agent']!, {
      issuer_agent_id: fixtures.agents['treasury'],
      delegate_agent_id: 'verification-agent',
      parent_lease_id: lease.id,
      grant: {
        actions: ['counterparty.read'],
        resources: { counterparty: ['cp_100', 'cp_101'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '0' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100', 'cp_101'],
        },
      },
      ttl_seconds: 600,
    });
    expect(delegation.status === 201, `delegation failed: ${JSON.stringify(delegation.body)}`);
    step(
      `delegation ${bold(delegation.body.delegation_id)} at depth ${delegation.body.child_lease.depth}`,
    );
    step('verification-agent may read cp_100 and cp_101, and nothing else');

    step('treasury-agent attempts to delegate wire.execute as well...');
    const overreach = await call('POST', '/v1/delegations', t['treasury_agent']!, {
      issuer_agent_id: fixtures.agents['treasury'],
      delegate_agent_id: 'verification-agent',
      parent_lease_id: lease.id,
      grant: {
        actions: ['counterparty.read', 'wire.execute'],
        resources: { counterparty: ['cp_100'], bank_account: ['acct_001'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '100000' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      },
      ttl_seconds: 600,
    });
    expect(overreach.status >= 400, 'delegating payment authority must be refused');
    outcome('DENY', `${overreach.body.error.reason_code} -- policy marks wire.* non-delegable`);

    scene('The delegated agent reaches beyond its remit');
    const readOk = await call('POST', '/v1/authorization/evaluate', t['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_100' },
      context: { counterparty_id: 'cp_100' },
    });
    expect(
      readOk.body.decision === 'ALLOW',
      `the delegated read should be allowed: ${readOk.body.reason_code}`,
    );
    outcome(readOk.body.decision, `counterparty.read on cp_100 -- ${readOk.body.reason_code}`);

    const violation = await call('POST', '/v1/authorization/evaluate', t['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'wire.modify',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: '5000.00',
        currency: 'USD',
        counterparty_id: 'cp_100',
        wire_id: 'wire_991',
      },
    });
    expect(violation.body.decision === 'DENY', `expected DENY, got ${violation.body.decision}`);
    outcome(violation.body.decision, `${violation.body.reason_code}`);

    const explained = await call(
      'GET',
      `/v1/authorization-decisions/${violation.body.decision_id}`,
      t['admin']!,
    );
    process.stdout.write('\n');
    for (const line of explained.body.explanation.text.split('\n')) {
      process.stdout.write(`   ${dim('|')} ${line}\n`);
    }

    scene('Mutation after authorization -- the enforcement boundary');
    step('the agent asks for a $25,000 wire to cp_100 and is allowed');
    const boundContext = {
      amount: '25000.00',
      currency: 'USD',
      counterparty_id: 'cp_100',
      destination_country: 'US',
    };
    const bound = await call('POST', '/v1/authorization/evaluate', t['treasury_agent']!, {
      agent_id: 'treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: boundContext,
      nonce: `demo-bind-${Date.now()}`,
    });
    expect(
      bound.body.decision === 'ALLOW',
      `expected ALLOW, got ${bound.body.decision} (${bound.body.reason_code})`,
    );
    outcome(bound.body.decision, `${bound.body.reason_code}`);
    step(`authorized intent ${dim(bound.body.exact_intent_hash.slice(0, 16))}`);

    step('the agent now presents a different amount to the execution boundary...');
    const mutated = await call('POST', '/v1/execute', t['treasury_agent']!, {
      decision_id: bound.body.decision_id,
      operation: {
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_001' },
        // One field changed. Everything else is byte-identical to the
        // authorized operation, including the decision id it is presented under.
        context: { ...boundContext, amount: '75000.00' },
      },
    });
    expect(
      mutated.body.error?.code === 'INTENT_MISMATCH',
      `expected INTENT_MISMATCH, got ${JSON.stringify(mutated.body)}`,
    );
    outcome(
      'DENY',
      `${mutated.body.error.code} -- mutated: ${mutated.body.error.details.mutated_fields.join(', ')}`,
    );
    step(red('the provider was never contacted; no money moved and none could have'));
    step('the attempt is recorded as a security event, not discarded');

    step('the agent presents the operation it was actually authorized for...');
    const honest = await call('POST', '/v1/execute', t['treasury_agent']!, {
      decision_id: bound.body.decision_id,
      operation: {
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: boundContext,
      },
    });
    expect(honest.status === 201, `enforced execution failed: ${JSON.stringify(honest.body)}`);
    outcome('ALLOW', `${honest.body.status} via ${honest.body.provider}`);
    step(
      `executed intent ${dim(honest.body.executed_intent_hash.slice(0, 16))} ` +
        `${green('matches')} the authorized intent`,
    );

    scene('WHY? -- the causal trace');
    const trace = await call('GET', `/v1/trace/${approval.body.decision.decision_id}`, t['admin']!);
    expect(trace.status === 200, `trace failed: ${JSON.stringify(trace.body)}`);
    step(
      `root cause: ${bold(trace.body.root_cause.name)} ` +
        `(${trace.body.root_cause.type}, ${trace.body.root_cause.timestamp})`,
    );
    for (const node of trace.body.trace) {
      const link = node.causal_parent_id ? node.causal_link_type : 'origin';
      process.stdout.write(
        `   ${dim('|')} ${String(node.step).padStart(2)}. ${dim(link.padEnd(20))} ${node.name}\n`,
      );
    }
    step(
      trace.body.complete
        ? `${green('complete')} -- the chain reaches a policy activation`
        : `${yellow('incomplete')} -- the chain stops short of a policy activation`,
    );

    scene('A fraud signal arrives');
    // Signed by the source, as every signal must be. The fraud engine enrolled
    // an Ed25519 public key when the tenant was set up; Scrutexity has never
    // held the private half, and a signal it cannot attribute to an enrolled
    // source does not influence authority at all.
    const signal = await call(
      'POST',
      '/v1/signals',
      t['fraud_engine']!,
      signedSignal(fixtures, {
        subject: { type: 'agent', id: fixtures.agents['treasury']! },
        signal_type: 'fraud_risk',
        value: '0.97',
        confidence: '0.91',
        source: 'external_fraud_engine',
        ttl_seconds: 600,
      }),
    );
    expect(signal.status === 201, `signal ingestion failed: ${JSON.stringify(signal.body)}`);
    step(
      `fraud_risk = ${red('0.97')} for treasury-agent, valid until ${signal.body.signal.expires_at}`,
    );

    const decayed = await call('POST', '/v1/authorization/evaluate', t['treasury_agent']!, {
      agent_id: 'treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: '25000.00',
        currency: 'USD',
        counterparty_id: 'cp_100',
        destination_country: 'US',
      },
      nonce: `demo-decayed-${Date.now()}`,
    });
    expect(
      decayed.body.decision === 'ESCALATE',
      `expected ESCALATE after decay, got ${decayed.body.decision}`,
    );
    step('the same $25,000 wire that ran unattended a moment ago:');
    outcome(
      decayed.body.decision,
      `${decayed.body.reason_code} -- authority narrowed, role unchanged`,
    );

    scene('Revocation is immediate');
    const revoked = await call('POST', `/v1/authority-leases/${lease.id}/revoke`, t['admin']!, {
      reason: 'Incident INC-2291: treasury agent credential rotation.',
    });
    expect(revoked.status === 200, `revocation failed: ${JSON.stringify(revoked.body)}`);
    step(`lease ${lease.id} revoked -- ${revoked.body.authority_lease.revocation_reason}`);

    const afterRevocation = await call('POST', '/v1/authorization/evaluate', t['treasury_agent']!, {
      agent_id: 'treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: '100.00',
        currency: 'USD',
        counterparty_id: 'cp_100',
        destination_country: 'US',
      },
    });
    expect(
      afterRevocation.body.reason_code === 'AUTHORITY_REVOKED',
      `a revoked lease must not authorize, got ${afterRevocation.body.reason_code}`,
    );
    outcome(
      afterRevocation.body.decision,
      `${afterRevocation.body.reason_code} -- no grace period`,
    );

    const childAfterRevocation = await call(
      'POST',
      '/v1/authorization/evaluate',
      t['verification_agent']!,
      {
        agent_id: 'verification-agent',
        action: 'counterparty.read',
        resource: { type: 'counterparty', id: 'cp_100' },
        context: { counterparty_id: 'cp_100' },
      },
    );
    expect(
      childAfterRevocation.body.decision === 'DENY',
      'revoking a parent must kill its children',
    );
    outcome(
      childAfterRevocation.body.decision,
      `${childAfterRevocation.body.reason_code} -- the delegated lease died with its parent`,
    );

    scene('Evidence');
    const verification = await call(
      'POST',
      `/v1/receipts/${small.body.receipt_id}/verify`,
      t['admin']!,
      {},
    );
    expect(verification.body.integrity === 'INTACT', 'receipt verification failed');
    step(`receipt ${small.body.receipt_id}: ${green(verification.body.integrity)}`);
    for (const check of verification.body.receipt_verification.checks) {
      step(dim(`${check.check.padEnd(14)} ${check.passed ? 'ok' : 'FAIL'}  ${check.detail}`));
    }
    step(
      `chain segment ${verification.body.chain_verification.from_seq}-${verification.body.chain_verification.to_seq}: ` +
        `${verification.body.chain_verification.intact ? green('linked') : red('broken')}` +
        `${verification.body.chain_verification.covers_genesis ? ', anchored at genesis' : ''}`,
    );
    step(dim(`attests: ${verification.body.attests}`));

    const stored = await call('GET', `/v1/receipts/${small.body.receipt_id}`, t['admin']!);
    const tampered = await call('POST', '/v1/receipts/verify', t['admin']!, {
      receipt: { ...stored.body.receipt, payload: { decision: 'ALLOW', tampered: true } },
    });
    expect(tampered.body.integrity === 'COMPROMISED', 'a modified receipt must not verify');
    outcome('DENY', `tampered receipt: ${red(tampered.body.integrity)}`);

    process.stdout.write(
      `\n${green(bold('  Demo complete -- every scene behaved as specified.'))}\n\n`,
    );
  } finally {
    await app.close();
  }
}

try {
  await main();
} catch (error) {
  process.stderr.write(
    `\n${red(bold('  Demo failed'))}: ${error instanceof Error ? error.message : String(error)}\n\n`,
  );
  if (!(error instanceof DemoFailure)) {
    process.stderr.write(`${String(error instanceof Error ? error.stack : '')}\n`);
  }
  process.exit(1);
}
