import { moneyMinor, type Money } from '@scrutexity/core';
import type { ExecutionProvider, ProviderOutcome, ProviderRequest } from './provider.js';

/**
 * A provider whose external system is an in-memory ledger.
 *
 * This is not a mock. It is a real provider that satisfies the whole interface
 * honestly: it honours idempotency keys, it returns a stable external
 * reference, and it can fail or time out. What it lacks is a bank.
 *
 * The distinction matters for what the demo and the tests are allowed to
 * claim. Running against this provider proves the enforcement boundary works
 * -- that a mutated operation is refused, that a grant is consumed once, that
 * a receipt names both hashes. It proves nothing about a real bank's
 * behaviour, and no document should say otherwise.
 *
 * Failure modes are triggered by the operation itself rather than by test
 * plumbing, so the same code path runs in the demo, in tests and in a design
 * partner's sandbox:
 *
 *   reference "FAIL"    -> the provider reports the operation did not happen
 *   reference "TIMEOUT" -> the provider does not answer; the outcome is UNKNOWN
 */
export class SimulatedTreasuryProvider implements ExecutionProvider {
  readonly name = 'simulated-treasury';
  readonly idempotent = true;
  readonly actions = ['wire.execute', 'wire.submit', 'wire.create'] as const;

  /** idempotency key -> the outcome that key already produced. */
  readonly #settled = new Map<string, ProviderOutcome>();
  /** account -> minor units moved, so a double payment would be visible. */
  readonly #ledger = new Map<string, bigint>();

  async execute(request: ProviderRequest): Promise<ProviderOutcome> {
    // The idempotency contract, honoured rather than declared. A retry after a
    // timeout returns what the first call produced instead of moving money a
    // second time -- which is the property the boundary relies on when it
    // decides a retry is safe.
    const settled = this.#settled.get(request.idempotencyKey);
    if (settled) return settled;

    const reference = request.operation.parameters['reference'];
    if (reference === 'TIMEOUT') {
      // Deliberately not recorded in #settled: a timeout is precisely the case
      // where the provider does not know what it did, so a later retry with
      // the same key must be able to reach the real path.
      return {
        status: 'UNKNOWN',
        error: 'the provider did not answer within the deadline',
        detail: { simulated: true },
      };
    }
    if (reference === 'FAIL') {
      const outcome: ProviderOutcome = {
        status: 'FAILED',
        error: 'the provider rejected the operation',
        detail: { simulated: true },
      };
      this.#settled.set(request.idempotencyKey, outcome);
      return outcome;
    }

    const amount = request.operation.parameters['amount'] as Money | undefined;
    if (amount) {
      const account = request.operation.resource_id;
      this.#ledger.set(account, (this.#ledger.get(account) ?? 0n) + moneyMinor(amount));
    }

    const outcome: ProviderOutcome = {
      status: 'EXECUTED',
      external_reference: `sim-${request.idempotencyKey.slice(-12)}`,
      detail: { simulated: true },
    };
    this.#settled.set(request.idempotencyKey, outcome);
    return outcome;
  }

  /** Total minor units this provider has moved out of an account. */
  movedFrom(account: string): bigint {
    return this.#ledger.get(account) ?? 0n;
  }
}
