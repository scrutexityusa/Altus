import { hashObject } from './canonical.js';
import type { SignalView } from './policy/engine.js';

/**
 * ============================================================================
 * Decision context fingerprinting -- the TOCTOU control.
 * ============================================================================
 *
 * A human approves a wire under a particular set of facts: this request, this
 * policy version, this authority, this risk picture. Between that approval and
 * the moment funds move there is a window, and for a payment the difference
 * between an approved transfer and an approved-*looking* transfer lives inside
 * it.
 *
 * So the inputs are fingerprinted. The fingerprint is recorded on the decision
 * and on every approval, and recomputed at execution. If it has moved, the
 * approval no longer describes what is about to happen, and execution is
 * refused rather than reconciled.
 *
 * The fingerprint covers every live signal visible to the decision, not only
 * the ones a rule happened to read. That is deliberate and it is the
 * conservative choice: a rule set can change what it reads between two
 * evaluations, so "no rule looked at this" is not the same as "this could not
 * have mattered". A consequence worth knowing is that a signal expiring
 * naturally also moves the fingerprint and invalidates an unused grant. That
 * is the intended direction -- the risk picture genuinely changed, and
 * re-evaluating is cheap.
 */

export interface DecisionContextInput {
  /** Canonical hash of the semantic authorization request. */
  request_hash: string;
  policy_version_id: string | null;
  policy_hash: string | null;
  authority_lease_id: string | null;
  /** Every live signal the decision could have seen. */
  signals: readonly Pick<SignalView, 'id' | 'signal_type' | 'subject_id' | 'value'>[];
}

/**
 * SHA-256 over the canonical form of the decision's inputs. Deterministic and
 * order-independent: two evaluations of the same facts always agree, whatever
 * order the database returned rows in.
 */
export function computeDecisionContextHash(input: DecisionContextInput): string {
  return hashObject({
    request_hash: input.request_hash,
    policy_version_id: input.policy_version_id,
    policy_hash: input.policy_hash,
    authority_lease_id: input.authority_lease_id,
    signals: [...input.signals]
      .map((signal) => ({
        id: signal.id,
        signal_type: signal.signal_type,
        subject_id: signal.subject_id,
        value: signal.value,
      }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  });
}

export interface ContextComparison {
  matches: boolean;
  expected: string;
  observed: string;
  /** True when the decision being executed was gated on a human approval. */
  was_approved: boolean;
}

/**
 * Compares the conditions now against the conditions the decision was made
 * under. A decision with no recorded fingerprint never matches: it predates
 * this control, and silently letting it through would defeat the control for
 * exactly the records least able to prove themselves.
 */
export function compareDecisionContext(
  recorded: string | null,
  current: string,
  wasApproved: boolean,
): ContextComparison {
  return {
    matches: recorded !== null && recorded === current,
    expected: recorded ?? '',
    observed: current,
    was_approved: wasApproved,
  };
}
