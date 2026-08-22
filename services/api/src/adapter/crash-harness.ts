import pg from 'pg';
import { moneyMinor, type Money } from '@scrutexity/core';
import type {
  ExecutionProvider,
  ProviderOutcome,
  ProviderRequest,
  VerificationResult,
} from './provider.js';

/**
 * ============================================================================
 * A provider that can be killed mid-payment.
 * ============================================================================
 *
 * The recovery harness needs to destroy the API process at two specific
 * instants and then prove what the outside world saw:
 *
 *   before the payment   the claim is committed, the provider was reached,
 *                        and no money moved.
 *   after the payment    the money moved and the record of it did not.
 *
 * Neither can be arranged from inside the process being killed, because a
 * SIGKILL takes every in-memory record of what happened with it. So this
 * provider's "external system" is a table in its **own** database schema,
 * written on its **own** connection, committed immediately.
 *
 * That is not a convenience. It is the whole mechanism: the ledger has to
 * survive a process that no longer exists, exactly as a bank's ledger does,
 * and the harness has to be able to read it from outside. Anything held in
 * memory would prove nothing, because a crash is precisely when memory is not
 * available.
 *
 * ## Why it blocks rather than sleeping for a while
 *
 * After recording what it did, `execute` never resolves. The harness watches
 * the ledger, sees the row appear, and kills the process at a moment it chose
 * rather than one it raced for. There is no timing window and no retry loop:
 * either the row is there or the harness is still waiting.
 *
 * The enforcement boundary's own 30-second deadline bounds this, so a harness
 * that dies without killing anything does not leave a request open forever.
 *
 * ## Not a mock
 *
 * It honours the idempotency contract for real: a second call with the same
 * key returns what the first produced, from durable state, across a restart.
 * That is the property the boundary relies on when it decides whether a retry
 * is safe, and a harness that faked it would be testing its own fake.
 */

export const CRASH_HARNESS_SCHEMA = 'harness';

/** Where in `execute` this provider stops. */
export type CrashPoint =
  /** Record the arrival, move nothing, then block. The money did not move. */
  | 'before_payment'
  /** Record the arrival and the payment, then block. The money moved. */
  | 'after_payment'
  /** Do not block at all. The control case: a normal, completed execution. */
  | 'none';

export class CrashHarnessProvider implements ExecutionProvider {
  readonly name = 'crash-harness';
  readonly idempotent = true;
  readonly actions = ['wire.execute', 'wire.submit', 'wire.create'] as const;

  readonly #connectionString: string;
  readonly #crashPoint: CrashPoint;

  constructor(connectionString: string, crashPoint: CrashPoint) {
    this.#connectionString = connectionString;
    this.#crashPoint = crashPoint;
  }

  async execute(request: ProviderRequest): Promise<ProviderOutcome> {
    const client = new pg.Client({ connectionString: this.#connectionString });
    await client.connect();
    try {
      // The idempotency contract, honoured from durable state rather than from
      // a Map that a SIGKILL erases. This is the read a resubmission days
      // later, from a different machine, would perform.
      const settled = await client.query(
        `SELECT status, external_reference FROM ${CRASH_HARNESS_SCHEMA}.ledger
          WHERE idempotency_key = $1 AND status = 'EXECUTED'`,
        [request.idempotencyKey],
      );
      if (settled.rows[0]) {
        return {
          status: 'EXECUTED',
          external_reference: settled.rows[0].external_reference as string,
          detail: { replayed_by_provider: true },
        };
      }

      // Arrival is recorded before anything else, and committed. After this
      // the harness can see that the provider was reached, whatever happens to
      // this process next.
      await client.query(
        `INSERT INTO ${CRASH_HARNESS_SCHEMA}.ledger
           (idempotency_key, decision_id, status, amount_minor, account)
         VALUES ($1,$2,'REACHED',$3,$4)
         ON CONFLICT (idempotency_key) DO UPDATE SET reached_count = ${CRASH_HARNESS_SCHEMA}.ledger.reached_count + 1`,
        [
          request.idempotencyKey,
          request.decisionId,
          amountMinorOf(request),
          request.operation.resource_id,
        ],
      );

      if (this.#crashPoint === 'before_payment') return block();

      const externalReference = `harness-${request.idempotencyKey.slice(-12)}`;
      await client.query(
        `UPDATE ${CRASH_HARNESS_SCHEMA}.ledger
            SET status = 'EXECUTED', external_reference = $2, executed_at = now()
          WHERE idempotency_key = $1`,
        [request.idempotencyKey, externalReference],
      );

      if (this.#crashPoint === 'after_payment') return block();

      return { status: 'EXECUTED', external_reference: externalReference };
    } finally {
      // Unreachable on a blocking path, and correct on every other one.
      await client.end().catch(() => undefined);
    }
  }

  /**
   * The only safe external operation against an unresolved claim: ask the
   * provider what it actually did, rather than assuming either answer.
   */
  async verifyExecution(request: ProviderRequest): Promise<VerificationResult> {
    const client = new pg.Client({ connectionString: this.#connectionString });
    await client.connect();
    try {
      const row = await client.query(
        `SELECT status, external_reference FROM ${CRASH_HARNESS_SCHEMA}.ledger
          WHERE idempotency_key = $1`,
        [request.idempotencyKey],
      );
      if (!row.rows[0]) return { status: 'CONFIRMED_FAILURE', reason: 'no record of this key' };
      if (row.rows[0].status === 'EXECUTED') {
        return {
          status: 'CONFIRMED_SUCCESS',
          external_reference: row.rows[0].external_reference as string,
        };
      }
      // Reached but not executed. The provider genuinely cannot say whether it
      // was about to pay when it lost the caller, so it says so.
      return { status: 'AMBIGUOUS', reason: 'the request arrived; no payment was recorded' };
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}

function amountMinorOf(request: ProviderRequest): string {
  const amount = request.operation.parameters['amount'] as Money | undefined;
  return amount ? moneyMinor(amount).toString() : '0';
}

/** Never resolves. The process is expected to be killed while it waits here. */
function block(): Promise<never> {
  return new Promise<never>(() => {});
}
