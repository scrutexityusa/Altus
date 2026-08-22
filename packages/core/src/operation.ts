import { hashObject } from './canonical.js';
import { ACTION_CATALOG, lookupAction } from './actions.js';
import { ScrutexityError } from './errors.js';
import type { Money } from './money.js';

/**
 * ============================================================================
 * Exact intent binding -- the enforcement primitive.
 * ============================================================================
 *
 * An authorization decision says an agent *may* move $25,000 to counterparty
 * cp_100. Nothing in that sentence stops the agent from moving $250,000 to
 * cp_999 and presenting the same decision id as its warrant. Closing that gap
 * needs three things, and this module is the first:
 *
 *   1. one deterministic canonical form of an operation  (here)
 *   2. a hash of that form, recorded when the grant is issued  (here)
 *   3. an enforcement boundary that reconstructs the operation from its own
 *      records and recomputes the hash itself  (the execution adapter)
 *
 * The third is what makes the first two worth anything. A hash the agent
 * supplies proves only that the agent can compute a hash.
 *
 * ## Two hashes, two questions
 *
 * These are related and they are not the same, so they are kept apart:
 *
 *   exact_intent_hash  -- "did the operation mutate?"
 *                         Covers the operation and nothing else. Two
 *                         semantically identical operations produce the same
 *                         value whoever computed them, whenever.
 *
 *   binding_hash       -- "is this operation bound to *this* authority?"
 *                         Covers the operation plus the decision, lease,
 *                         policy version and approved context that authorised
 *                         it, plus the grant's own identity and expiry.
 *
 * An attacker who replays a genuine, unmutated operation under a different
 * decision passes the first check and fails the second. An attacker who
 * mutates an amount under the correct decision fails both. Collapsing them
 * into one hash would answer neither question cleanly: a changed policy
 * version would read as a mutated operation, which is a confusing thing to
 * tell an operator at 3am.
 */

// ---------------------------------------------------------------------------
// The canonical operation
// ---------------------------------------------------------------------------

/**
 * The material facts of one operation, projected onto the closed action
 * catalog.
 *
 * "Projected" is the load-bearing word. The parameters are not whatever the
 * caller put in `context` -- they are exactly the fields the catalog declares
 * the action carries. Two consequences, both wanted:
 *
 *   - An agent cannot perturb the hash by appending a field. An undeclared
 *     field cannot affect execution, so it must not affect the intent, and a
 *     projection is the only way to guarantee that without trusting the
 *     sender to omit it.
 *
 *   - A field that *does* affect execution cannot be silently dropped,
 *     because the catalog names it and `required_context` makes the
 *     mandatory ones non-optional at the boundary.
 */
export interface CanonicalOperation {
  /** The catalog action. `wire.execute`, not "send money". */
  operation_type: string;
  resource_type: string;
  resource_id: string;
  /**
   * Catalog-declared context fields that are present, in canonical order.
   * Absent optional fields are omitted rather than written as null -- see
   * the note on null-versus-absent below.
   */
  parameters: Record<string, CanonicalValue>;
}

/**
 * What may appear in a canonical parameter.
 *
 * Money is a record of integer minor units and a currency, never a float.
 * Everything else is a string, a boolean, an integer, or a nested structure
 * of those. This union is narrow on purpose: a value whose serialisation is
 * ambiguous has no place in a hash that decides whether money moves.
 */
export type CanonicalValue =
  | string
  | boolean
  | number
  | Money
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

/**
 * Builds the canonical operation for an action, resource and context.
 *
 * Deterministic and total: same inputs, same output, no clock and no I/O.
 * Both the authority engine (when it issues a grant) and the execution
 * adapter (when it enforces one) call exactly this function, which is what
 * makes their hashes comparable at all. Two implementations that agree today
 * are two implementations that can drift tomorrow.
 */
export function canonicalOperation(input: {
  action: string;
  resource: { type: string; id: string };
  context: Record<string, unknown>;
}): CanonicalOperation {
  const definition = lookupAction(input.action);
  if (!definition) {
    // The catalog is closed, so this is not a "not yet supported" case -- it
    // is an operation the system has no definition of and therefore cannot
    // state the material fields of. Hashing it would be hashing a guess.
    throw new ScrutexityError(
      'INVALID_REQUEST',
      `cannot canonicalise unknown action "${input.action}"`,
      { details: { known_actions: Object.keys(ACTION_CATALOG).sort() } },
    );
  }
  if (!definition.resource_types.includes(input.resource.type)) {
    throw new ScrutexityError(
      'INVALID_REQUEST',
      `action "${input.action}" cannot be attempted against resource type "${input.resource.type}"`,
    );
  }

  const parameters: Record<string, CanonicalValue> = {};
  // Catalog order, not context order. The catalog is the authority on which
  // fields matter; `canonicalize` sorts keys anyway, but iterating the
  // catalog rather than the caller's object is what makes this a projection.
  for (const field of definition.context_fields) {
    const value = input.context[field];
    // Absent and null are the same fact -- "this operation does not carry
    // that field" -- and must hash the same. Writing null for one and
    // omitting the other would make two identical operations differ.
    if (value === undefined || value === null) continue;
    parameters[field] = assertCanonical(value, `context.${field}`);
  }

  for (const field of definition.required_context) {
    if (!(field in parameters)) {
      throw new ScrutexityError(
        'INVALID_REQUEST',
        `action "${input.action}" requires context field "${field}"`,
      );
    }
  }

  return {
    operation_type: input.action,
    resource_type: input.resource.type,
    resource_id: input.resource.id,
    parameters,
  };
}

/**
 * SHA-256 over the canonical form of an operation. The answer to "did the
 * operation mutate?" and nothing else.
 */
export function computeIntentHash(operation: CanonicalOperation): string {
  return hashObject(operation);
}

// ---------------------------------------------------------------------------
// The binding
// ---------------------------------------------------------------------------

/**
 * The authority an operation was authorised under.
 *
 * `approved_context_hash` is the decision's TOCTOU fingerprint at the moment
 * a human said yes. Including it here -- rather than inside the intent hash
 * -- is deliberate. A treasurer approves a specific operation under a
 * specific risk picture; binding both means an execution presented against a
 * *different* approval fails the binding check even though the operation
 * itself is untouched. Folding it into the intent hash would have made a
 * changed risk picture read as a mutated wire, which is the wrong thing to
 * put in front of an operator.
 */
export interface AuthorizationContext {
  decision_id: string;
  authority_lease_id: string | null;
  policy_version_id: string | null;
  policy_hash: string | null;
  approved_context_hash: string | null;
}

/**
 * Everything the enforcement boundary needs to answer both questions, and the
 * exact shape that gets hashed into `binding_hash`.
 */
export interface ExecutionGrantBinding {
  authorized_intent: CanonicalOperation;
  authorization_context: AuthorizationContext;
  /** The grant's own identity. Today an ALLOW decision is the grant. */
  grant_id: string;
  /** ISO-8601 UTC. A grant with no expiry is not a grant. */
  expires_at: string;
  /** Single-use randomness, so two identical operations bind differently. */
  nonce: string;
}

/**
 * SHA-256 over the canonical form of the whole binding. The answer to "is
 * this operation bound to this particular authority decision?"
 *
 * The nonce is what stops two legitimately identical operations -- the same
 * agent paying the same supplier the same amount twice in a day -- from
 * producing interchangeable bindings. Without it, a valid binding from this
 * morning would validate this afternoon's execution.
 */
export function computeBindingHash(binding: ExecutionGrantBinding): string {
  return hashObject({
    authorized_intent: binding.authorized_intent,
    authorization_context: binding.authorization_context,
    grant_id: binding.grant_id,
    expires_at: binding.expires_at,
    nonce: binding.nonce,
  });
}

/**
 * The result of checking a presented operation against a grant.
 *
 * Both checks are reported, always, even when the first one fails. An
 * operator asking "what went wrong" is better served by "the amount changed
 * and it was presented against the wrong decision" than by whichever failure
 * happened to be evaluated first.
 */
export interface IntentVerification {
  intent_matches: boolean;
  binding_matches: boolean;
  expected_intent_hash: string;
  actual_intent_hash: string;
  expected_binding_hash: string;
  actual_binding_hash: string;
  /**
   * The parameters that differ, by name only. Values are deliberately absent:
   * this travels into error responses and logs, and "amount" is enough for an
   * agent to correct itself without echoing a counterparty's account number
   * into a log aggregator.
   */
  mutated_fields: string[];
}

/**
 * Compares an operation reconstructed at execution time against the one the
 * grant was issued for.
 *
 * Pure, and takes hashes rather than computing the authorised side itself:
 * the recorded hash is the authority, not a re-derivation of it. Re-deriving
 * would mean a later change to `canonicalOperation` silently revalidated old
 * grants against new rules.
 */
export function verifyIntent(input: {
  recorded_intent_hash: string;
  recorded_binding_hash: string;
  authorized_intent: CanonicalOperation;
  actual_operation: CanonicalOperation;
  actual_binding: ExecutionGrantBinding;
}): IntentVerification {
  const actualIntentHash = computeIntentHash(input.actual_operation);
  const actualBindingHash = computeBindingHash(input.actual_binding);
  return {
    intent_matches: actualIntentHash === input.recorded_intent_hash,
    binding_matches: actualBindingHash === input.recorded_binding_hash,
    expected_intent_hash: input.recorded_intent_hash,
    actual_intent_hash: actualIntentHash,
    expected_binding_hash: input.recorded_binding_hash,
    actual_binding_hash: actualBindingHash,
    mutated_fields: diffOperations(input.authorized_intent, input.actual_operation),
  };
}

/** Names the fields that differ between two operations. Names only, no values. */
export function diffOperations(
  authorized: CanonicalOperation,
  actual: CanonicalOperation,
): string[] {
  const differences: string[] = [];
  if (authorized.operation_type !== actual.operation_type) differences.push('operation_type');
  if (authorized.resource_type !== actual.resource_type) differences.push('resource_type');
  if (authorized.resource_id !== actual.resource_id) differences.push('resource_id');

  const fields = new Set([
    ...Object.keys(authorized.parameters),
    ...Object.keys(actual.parameters),
  ]);
  for (const field of [...fields].sort()) {
    const a = authorized.parameters[field];
    const b = actual.parameters[field];
    // Compared through the canonical form rather than by value, so the
    // comparison agrees with the hash by construction. Two things that
    // canonicalise identically are identical for every purpose this system
    // has.
    if (hashOrAbsent(a) !== hashOrAbsent(b)) differences.push(field);
  }
  return differences;
}

function hashOrAbsent(value: CanonicalValue | undefined): string {
  return value === undefined ? ' absent' : hashObject(value);
}

/**
 * Rejects anything whose serialisation would be ambiguous.
 *
 * `canonicalize` already refuses floats and non-finite numbers, but it does so
 * at hash time, deep inside evidence writing. Refusing here means an operation
 * that cannot be hashed is rejected at the boundary with a message naming the
 * field, rather than failing later where the caller cannot act on it.
 */
function assertCanonical(value: unknown, path: string): CanonicalValue {
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
      throw new ScrutexityError(
        'INVALID_REQUEST',
        `${path} must be an integer or a decimal string, not a floating-point number`,
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      // Array position is meaningful, so a null cannot be dropped the way it
      // can inside an object -- dropping it would shift every later element.
      // Preserving it would need null in the value union, which then has to
      // be distinguished from absent everywhere else. Refusing is simpler and
      // no operation in the catalog needs a sparse list.
      if (item === null) {
        throw new ScrutexityError(
          'INVALID_REQUEST',
          `${path}[${index}] is null; an operation parameter list may not contain nulls`,
        );
      }
      return assertCanonical(item, `${path}[${index}]`);
    });
  }
  if (typeof value === 'object' && value !== null) {
    const out: Record<string, CanonicalValue> = {};
    for (const [key, nested] of Object.entries(value)) {
      // Same rule as the top level: null and absent are one fact and must
      // hash identically.
      if (nested === undefined || nested === null) continue;
      out[key] = assertCanonical(nested, `${path}.${key}`);
    }
    return out;
  }
  throw new ScrutexityError('INVALID_REQUEST', `${path} is not a canonicalisable value`);
}
