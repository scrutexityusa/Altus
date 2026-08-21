import type { CanonicalOperation } from '@scrutexity/core';

/**
 * ============================================================================
 * The execution provider interface.
 * ============================================================================
 *
 * A provider is the only thing in the system that talks to an external system
 * capable of moving money. It is deliberately the narrowest interface that can
 * express that: one method, one operation, one idempotency key.
 *
 * The narrowness is the point. Everything interesting -- authority, intent
 * binding, revocation, grant consumption -- happens in the enforcement
 * boundary *before* a provider is reached. A provider that could evaluate
 * policy, or decide whether to proceed, would be a second place where the
 * answer to "may this happen" is computed, and two such places will eventually
 * disagree.
 */

export interface ProviderRequest {
  /**
   * The operation, in the same canonical form the grant was bound to. The
   * boundary has already verified this matches; a provider must not re-derive
   * it or accept a different shape.
   */
  operation: CanonicalOperation;
  /**
   * Derived from the grant and stable across retries, so a repeat after a
   * timeout reaches the provider as the same request rather than a second one.
   * A provider that supports idempotency must honour it; one that does not
   * must say so (see `idempotent` below).
   */
  idempotencyKey: string;
  /** For correlating a provider-side incident back to a decision. */
  decisionId: string;
  organizationId: string;
}

export type ProviderOutcome =
  /** The provider confirmed the operation happened. */
  | { status: 'EXECUTED'; external_reference: string; detail?: Record<string, unknown> }
  /** The provider confirmed the operation did *not* happen. */
  | { status: 'FAILED'; error: string; detail?: Record<string, unknown> }
  /**
   * The provider did not answer, or answered in a way that does not establish
   * whether the operation happened: a timeout, a dropped connection, a 5xx
   * after the request was accepted.
   *
   * This is a first-class outcome and must never be collapsed into FAILED.
   * "The wire did not go" and "I do not know whether the wire went" call for
   * opposite responses from an operator, and a system that reports the second
   * as the first will eventually cause a double payment.
   */
  | { status: 'UNKNOWN'; error: string; detail?: Record<string, unknown> };

export interface ExecutionProvider {
  /** Recorded on the claim, so evidence names what was actually called. */
  readonly name: string;
  /**
   * Whether the external system honours `idempotencyKey`.
   *
   * Declared rather than assumed, because the guarantee the system can offer
   * depends on it and must not be overstated. Scrutexity guarantees a grant is
   * consumed at most once; whether the *external effect* happens at most once
   * is the provider's property, not ours. A provider that returns false here
   * makes retry-after-timeout unsafe, and the boundary will not retry.
   */
  readonly idempotent: boolean;
  /** Which catalog actions this provider can execute. */
  readonly actions: readonly string[];
  execute(request: ProviderRequest): Promise<ProviderOutcome>;
}

export class ProviderRegistry {
  readonly #byAction = new Map<string, ExecutionProvider>();

  constructor(providers: readonly ExecutionProvider[]) {
    for (const provider of providers) {
      for (const action of provider.actions) {
        if (this.#byAction.has(action)) {
          // Two providers claiming one action means the answer to "who
          // executes this" depends on registration order. Refuse at boot
          // rather than pick.
          throw new Error(
            `two providers registered for action "${action}": ` +
              `${this.#byAction.get(action)!.name} and ${provider.name}`,
          );
        }
        this.#byAction.set(action, provider);
      }
    }
  }

  /**
   * Returns undefined when no provider can execute the action. The boundary
   * treats that as a refusal, not as permission to let the caller do it
   * itself -- an operation nobody can execute under enforcement is an
   * operation that must not happen.
   */
  forAction(action: string): ExecutionProvider | undefined {
    return this.#byAction.get(action);
  }

  get actions(): string[] {
    return [...this.#byAction.keys()].sort();
  }
}
