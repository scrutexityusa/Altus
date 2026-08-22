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
   * Derived from the grant and stable **forever**, not merely across retries
   * inside one request.
   *
   * This is the contract that closes the last gap in the exactly-once claim.
   * Scrutexity's own `UNIQUE (decision_id)` stops it issuing a second claim;
   * it does nothing to stop the *bank* executing twice in this sequence:
   *
   *     claim committed
   *     provider accepted the request
   *     settlement failed  (process died before T2)
   *     an operator reconciles and resubmits
   *
   * That resubmission is a different HTTP request, possibly days later,
   * possibly from a different machine. It must carry the same key, or the
   * provider sees a new payment. So the key is derived from the decision id
   * and never regenerated -- not on retry, not on reconciliation, not on
   * manual replay by an operator.
   *
   * `scrutexity:{decision_id}`. Any code that constructs this value other than
   * via `idempotencyKeyFor` is a bug.
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

/**
 * What the provider says about an operation it may or may not have performed.
 *
 * Reconciliation exists because `UNKNOWN` is a real state, and resolving it
 * requires asking the provider rather than guessing. A provider that cannot
 * answer this question honestly cannot support exactly-once external effects,
 * and the correct semantic for its unresolved executions is
 * "unknown; a human decides", never "retry".
 */
export type VerificationResult =
  | { status: 'CONFIRMED_SUCCESS'; external_reference: string }
  | { status: 'CONFIRMED_FAILURE'; reason: string }
  /** The provider has no record either way, or cannot say. */
  | { status: 'AMBIGUOUS'; reason: string };

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
  /**
   * Asks the provider what became of an operation, by the same idempotency key
   * it was submitted under.
   *
   * Optional, because not every provider can answer. One that cannot leaves
   * its unresolved executions permanently `UNKNOWN` until a human settles
   * them out of band -- which is the honest outcome, and better than a
   * confident wrong one.
   *
   * Must never have a side effect. This is the one call that is safe to make
   * against an operation whose status is unknown, and it stops being safe the
   * moment it can cause the thing it is asking about.
   */
  verifyExecution?(request: ProviderRequest): Promise<VerificationResult>;
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
