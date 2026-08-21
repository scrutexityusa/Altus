import { z } from 'zod';
import {
  MoneyInputSchema,
  MoneySchema,
  compareMoney,
  formatMoneyWithCurrency,
  type Money,
} from '../money.js';

/**
 * ============================================================================
 * Authority as a first-class object (Section 8).
 * ============================================================================
 *
 * A grant is a point in a lattice with three axes -- actions, resources and
 * constraints. The two operations that matter are:
 *
 *   contains(parent, child)  -- is `child` weaker than or equal to `parent`?
 *   covers(grant, attempt)   -- does `grant` admit this concrete attempt?
 *
 * Everything about delegation safety reduces to the first; everything about
 * runtime authorization reduces to the second. Both are total, deterministic
 * and side-effect free, so a decision can be replayed years later from the
 * evidence record and reach the same answer.
 *
 * Fail-closed defaults are baked into the shape: an omitted `resources` map
 * grants nothing, not everything.
 */

// ---------------------------------------------------------------------------
// Action patterns
// ---------------------------------------------------------------------------

/** `wire.execute` (exact), `wire.*` (prefix), `*` (universal). */
export const ACTION_PATTERN = /^(?:\*|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*(?:\.\*)?)$/;

export function isWildcardPattern(pattern: string): boolean {
  return pattern === '*' || pattern.endsWith('.*');
}

export function actionMatches(pattern: string, action: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('.*')) return action.startsWith(pattern.slice(0, -1));
  return pattern === action;
}

/** Is every action admitted by `child` also admitted by `parent`? */
function patternContains(parent: string, child: string): boolean {
  if (parent === '*') return true;
  if (!isWildcardPattern(child)) return actionMatches(parent, child);
  // child is `Y.*`; only a broader-or-equal wildcard can contain it.
  if (!parent.endsWith('.*')) return false;
  const parentPrefix = parent.slice(0, -1); // "wire."
  const childPrefix = child.slice(0, -1); // "wire.batch."
  return childPrefix.startsWith(parentPrefix);
}

// ---------------------------------------------------------------------------
// Constraint dimensions
// ---------------------------------------------------------------------------

/**
 * The constraint vocabulary is a registry rather than a hard-coded chain of
 * `if` statements, so a new dimension is a table entry plus a test -- not a
 * rewrite of the containment proof. Each dimension declares how it narrows
 * (for delegation) and how it is satisfied (for runtime checks).
 */
export type ConstraintKind = 'money_ceiling' | 'string_allowlist' | 'string_denylist';

export interface ConstraintDimension {
  readonly kind: ConstraintKind;
  /** Path into the authorization request context supplying the checked value. */
  readonly contextPath: string;
  readonly description: string;
}

export const CONSTRAINT_DIMENSIONS = {
  max_amount: {
    kind: 'money_ceiling',
    contextPath: 'amount',
    description: 'Upper bound on the monetary amount of a single action',
  },
  currencies: {
    kind: 'string_allowlist',
    contextPath: 'currency',
    description: 'Currencies the authority may act in',
  },
  allowed_counterparties: {
    kind: 'string_allowlist',
    contextPath: 'counterparty_id',
    description: 'Counterparties the authority may transact with',
  },
  denied_counterparties: {
    kind: 'string_denylist',
    contextPath: 'counterparty_id',
    description: 'Counterparties the authority may never transact with',
  },
  allowed_destination_countries: {
    kind: 'string_allowlist',
    contextPath: 'destination_country',
    description: 'ISO-3166 country codes the funds may be sent to',
  },
} as const satisfies Record<string, ConstraintDimension>;

export type ConstraintName = keyof typeof CONSTRAINT_DIMENSIONS;

export const CONSTRAINT_NAMES = Object.keys(CONSTRAINT_DIMENSIONS) as ConstraintName[];

export interface Constraints {
  max_amount?: Money;
  currencies?: string[];
  allowed_counterparties?: string[];
  denied_counterparties?: string[];
  allowed_destination_countries?: string[];
}

const StringSetSchema = z.array(z.string().min(1)).min(1);

export const ConstraintsSchema = z
  .object({
    /**
     * Either form is accepted and both normalise to exact minor units:
     *
     *   { currency: USD, amount: "500000.00" }   authored -- policies, API callers
     *   { currency: USD, amountMinor: "50000000" }   stored -- re-parsed rows
     *
     * The stored form is tried first because re-parsing a persisted grant is
     * the common path, and a policy document must re-parse to itself byte for
     * byte or its content hash changes and the evidence chain stops meaning
     * anything.
     */
    max_amount: z.union([MoneySchema, MoneyInputSchema]).optional(),
    currencies: StringSetSchema.optional(),
    allowed_counterparties: StringSetSchema.optional(),
    denied_counterparties: StringSetSchema.optional(),
    allowed_destination_countries: StringSetSchema.optional(),
  })
  .strict();

export const GrantSchema = z
  .object({
    actions: z.array(z.string().regex(ACTION_PATTERN, 'malformed action pattern')).min(1),
    /**
     * `{ "bank_account": ["acct_1"], "counterparty": ["*"] }`.
     * A resource type that is absent grants nothing for that type.
     */
    resources: z.record(z.string().min(1), z.array(z.string().min(1)).min(1)).default({}),
    constraints: ConstraintsSchema.default({}),
  })
  .strict();

export type AuthorityGrant = z.infer<typeof GrantSchema>;

// ---------------------------------------------------------------------------
// Containment:  child ⊆ parent
// ---------------------------------------------------------------------------

export interface ContainmentViolation {
  axis: 'actions' | 'resources' | 'constraints';
  dimension: string;
  message: string;
  parent_value?: unknown;
  child_value?: unknown;
}

export interface ContainmentResult {
  contained: boolean;
  violations: ContainmentViolation[];
}

function setContains(parent: readonly string[], child: readonly string[]): boolean {
  if (parent.includes('*')) return true;
  const allowed = new Set(parent);
  return child.every((value) => value !== '*' && allowed.has(value));
}

/**
 * The security invariant of the whole platform:
 *
 *     child_authority ⊆ parent_authority
 *
 * Note the asymmetry that makes this safe. A dimension the parent constrains
 * must also be constrained by the child, at least as tightly; a dimension the
 * child adds is free, because adding a constraint can only shrink authority.
 * Omission is therefore never a widening path.
 */
export function containsGrant(parent: AuthorityGrant, child: AuthorityGrant): ContainmentResult {
  const violations: ContainmentViolation[] = [];

  for (const childAction of child.actions) {
    if (!parent.actions.some((p) => patternContains(p, childAction))) {
      violations.push({
        axis: 'actions',
        dimension: childAction,
        message: `action "${childAction}" is not covered by the parent authority`,
        parent_value: parent.actions,
        child_value: childAction,
      });
    }
  }

  for (const [type, ids] of Object.entries(child.resources)) {
    const parentIds = parent.resources[type];
    if (!parentIds) {
      violations.push({
        axis: 'resources',
        dimension: type,
        message: `the parent authority holds no authority over resource type "${type}"`,
        parent_value: Object.keys(parent.resources),
        child_value: type,
      });
      continue;
    }
    if (!setContains(parentIds, ids)) {
      violations.push({
        axis: 'resources',
        dimension: type,
        message: `resources of type "${type}" are not a subset of the parent authority`,
        parent_value: parentIds,
        child_value: ids,
      });
    }
  }

  for (const name of CONSTRAINT_NAMES) {
    const dimension = CONSTRAINT_DIMENSIONS[name];
    const parentValue = parent.constraints[name];
    const childValue = child.constraints[name];

    if (dimension.kind === 'string_denylist') {
      // Denylists invert: the child must deny at least everything the parent does.
      if (!parentValue) continue;
      const childSet = new Set((childValue as string[] | undefined) ?? []);
      const missing = (parentValue as string[]).filter((v) => !childSet.has(v));
      if (missing.length > 0) {
        violations.push({
          axis: 'constraints',
          dimension: name,
          message: `the child authority must inherit every denied value from its parent (missing: ${missing.join(', ')})`,
          parent_value: parentValue,
          child_value: childValue ?? null,
        });
      }
      continue;
    }

    if (parentValue === undefined) continue; // parent unconstrained on this axis
    if (childValue === undefined) {
      violations.push({
        axis: 'constraints',
        dimension: name,
        message: `the parent authority constrains "${name}"; the child must constrain it at least as tightly`,
        parent_value: parentValue,
        child_value: null,
      });
      continue;
    }

    if (dimension.kind === 'money_ceiling') {
      const parentMoney = parentValue as Money;
      const childMoney = childValue as Money;
      if (parentMoney.currency !== childMoney.currency) {
        violations.push({
          axis: 'constraints',
          dimension: name,
          message: `ceiling currency ${childMoney.currency} cannot be compared with the parent ceiling currency ${parentMoney.currency}`,
          parent_value: parentMoney,
          child_value: childMoney,
        });
      } else if (compareMoney(childMoney, parentMoney) > 0) {
        violations.push({
          axis: 'constraints',
          dimension: name,
          message: `ceiling ${formatMoneyWithCurrency(childMoney)} exceeds the parent ceiling ${formatMoneyWithCurrency(parentMoney)}`,
          parent_value: parentMoney,
          child_value: childMoney,
        });
      }
      continue;
    }

    // string_allowlist
    if (!setContains(parentValue as string[], childValue as string[])) {
      violations.push({
        axis: 'constraints',
        dimension: name,
        message: `"${name}" is not a subset of the parent authority`,
        parent_value: parentValue,
        child_value: childValue,
      });
    }
  }

  return { contained: violations.length === 0, violations };
}

// ---------------------------------------------------------------------------
// Coverage:  does this grant admit this concrete attempt?
// ---------------------------------------------------------------------------

export interface AttemptDescriptor {
  action: string;
  resourceType: string;
  resourceId: string;
  /** Values pulled from the authorization request context, by dimension path. */
  context: Record<string, unknown>;
  /**
   * Context fields the action is *defined* to carry, from the action catalog.
   * A constraint dimension binds this attempt only if the action carries the
   * field that dimension reads -- an amount ceiling says nothing about an
   * action that has no amount. Omit to bind every dimension, which is the
   * strict reading and the safe default for an unrecognised action.
   */
  contextFields?: string[];
}

export interface ConstraintCheck {
  constraint: string;
  satisfied: boolean;
  /** False when the action does not carry the field this dimension reads. */
  applicable: boolean;
  /** Present only when the grant actually constrains this dimension. */
  limit?: unknown;
  observed?: unknown;
  message: string;
}

export interface CoverageResult {
  covered: boolean;
  action_covered: boolean;
  resource_covered: boolean;
  constraint_checks: ConstraintCheck[];
  /** First failure, in evaluation order, as a machine-readable reason. */
  failure?:
    | { kind: 'ACTION_NOT_GRANTED'; detail: string }
    | { kind: 'RESOURCE_NOT_GRANTED'; detail: string }
    | { kind: 'CONSTRAINT_VIOLATION'; constraint: string; detail: string };
}

function readContext(context: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc === null || typeof acc !== 'object') return undefined;
    return (acc as Record<string, unknown>)[key];
  }, context);
}

function asMoney(value: unknown): Money | null {
  const parsed = MoneySchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export function coversAttempt(grant: AuthorityGrant, attempt: AttemptDescriptor): CoverageResult {
  const actionCovered = grant.actions.some((p) => actionMatches(p, attempt.action));

  const grantedIds = grant.resources[attempt.resourceType];
  const resourceCovered =
    grantedIds !== undefined &&
    (grantedIds.includes('*') || grantedIds.includes(attempt.resourceId));

  const checks: ConstraintCheck[] = [];
  let constraintFailure: CoverageResult['failure'];

  for (const name of CONSTRAINT_NAMES) {
    const dimension = CONSTRAINT_DIMENSIONS[name];
    const limit = grant.constraints[name];
    if (limit === undefined) continue;

    if (attempt.contextFields && !attempt.contextFields.includes(dimension.contextPath)) {
      checks.push({
        constraint: name,
        satisfied: true,
        applicable: false,
        limit,
        observed: null,
        message: `action "${attempt.action}" carries no ${dimension.contextPath}, so this constraint does not bind it`,
      });
      continue;
    }

    const observed = readContext(attempt.context, dimension.contextPath);
    let satisfied: boolean;
    let message: string;

    switch (dimension.kind) {
      case 'money_ceiling': {
        const ceiling = limit as Money;
        const value = asMoney(observed);
        if (value === null) {
          // Fail closed: a ceiling that cannot be evaluated does not pass.
          satisfied = false;
          message = `the authority caps ${name} at ${formatMoneyWithCurrency(ceiling)} but the request carried no comparable amount`;
        } else if (value.currency !== ceiling.currency) {
          satisfied = false;
          message = `the authority is denominated in ${ceiling.currency}; the request is in ${value.currency}`;
        } else {
          satisfied = compareMoney(value, ceiling) <= 0;
          message = satisfied
            ? `${formatMoneyWithCurrency(value)} is within the ${formatMoneyWithCurrency(ceiling)} ceiling`
            : `${formatMoneyWithCurrency(value)} exceeds the ${formatMoneyWithCurrency(ceiling)} ceiling`;
        }
        break;
      }
      case 'string_allowlist': {
        const allowed = limit as string[];
        if (allowed.includes('*')) {
          satisfied = true;
          message = `${name} is unrestricted`;
        } else if (typeof observed !== 'string') {
          satisfied = false;
          message = `the authority restricts ${name} but the request carried no value for it`;
        } else {
          satisfied = allowed.includes(observed);
          message = satisfied
            ? `"${observed}" is within the permitted ${name}`
            : `"${observed}" is not among the permitted ${name}`;
        }
        break;
      }
      case 'string_denylist': {
        const denied = limit as string[];
        if (typeof observed !== 'string') {
          satisfied = true;
          message = `no value present for ${name}`;
        } else {
          satisfied = !denied.includes(observed);
          message = satisfied
            ? `"${observed}" is not denied`
            : `"${observed}" is explicitly denied by the authority`;
        }
        break;
      }
    }

    checks.push({
      constraint: name,
      satisfied,
      applicable: true,
      limit,
      observed: observed ?? null,
      message,
    });
    if (!satisfied && !constraintFailure) {
      constraintFailure = { kind: 'CONSTRAINT_VIOLATION', constraint: name, detail: message };
    }
  }

  let failure: CoverageResult['failure'];
  if (!actionCovered) {
    failure = {
      kind: 'ACTION_NOT_GRANTED',
      detail: `action "${attempt.action}" is not present in the authority (granted: ${grant.actions.join(', ')})`,
    };
  } else if (!resourceCovered) {
    failure = {
      kind: 'RESOURCE_NOT_GRANTED',
      detail: `resource ${attempt.resourceType}:${attempt.resourceId} is not within the authority`,
    };
  } else {
    failure = constraintFailure;
  }

  return {
    covered: failure === undefined,
    action_covered: actionCovered,
    resource_covered: resourceCovered,
    constraint_checks: checks,
    ...(failure ? { failure } : {}),
  };
}

// ---------------------------------------------------------------------------
// Restriction (authority decay)
// ---------------------------------------------------------------------------

export interface GrantRestriction {
  /** Action patterns to strip. Removal is by coverage, not string equality. */
  remove_actions?: string[];
  /** Constraints to tighten. Only ever applied in the narrowing direction. */
  tighten?: Constraints;
}

/**
 * Applies a restriction, producing a grant that is guaranteed to be contained
 * by the input. Decay can only ever shrink authority -- there is deliberately
 * no operation in this module that widens one.
 */
export function restrictGrant(
  grant: AuthorityGrant,
  restriction: GrantRestriction,
): AuthorityGrant {
  const removals = restriction.remove_actions ?? [];
  const actions = grant.actions.filter(
    (granted) =>
      !removals.some((removal) =>
        isWildcardPattern(granted)
          ? patternContains(removal, granted)
          : actionMatches(removal, granted),
      ),
  );

  const constraints: Constraints = { ...grant.constraints };
  for (const name of CONSTRAINT_NAMES) {
    const incoming = restriction.tighten?.[name];
    if (incoming === undefined) continue;
    const current = constraints[name];
    const dimension = CONSTRAINT_DIMENSIONS[name];

    if (dimension.kind === 'money_ceiling') {
      const next = incoming as Money;
      const existing = current as Money | undefined;
      if (!existing) {
        constraints[name] = next as never;
      } else if (existing.currency === next.currency) {
        constraints[name] = (compareMoney(next, existing) < 0 ? next : existing) as never;
      }
      // Currencies differ: the incoming ceiling is incomparable with the one
      // already in force, so applying it could not be proven to narrow. The
      // existing ceiling stands. This keeps the contract of this function
      // absolute -- the result is always contained by the input -- at the cost
      // of ignoring an effect the policy author could not have meant, since a
      // grant denominated in one currency already refuses requests in another
      // (see coversAttempt). Per-currency ceilings are tracked in
      // docs/domain-model.md as a known boundary of the v1 constraint model.
    } else if (dimension.kind === 'string_denylist') {
      const merged = new Set([...((current as string[]) ?? []), ...(incoming as string[])]);
      constraints[name] = [...merged].sort() as never;
    } else {
      const existing = current as string[] | undefined;
      const next = incoming as string[];
      constraints[name] = (
        !existing || existing.includes('*')
          ? [...next].sort()
          : next.includes('*')
            ? [...existing].sort()
            : next.filter((v) => existing.includes(v)).sort()
      ) as never;
    }
  }

  return { actions, resources: grant.resources, constraints };
}

/** Stable, comparable rendering used in receipts and diffs. */
export function normalizeGrant(grant: AuthorityGrant): AuthorityGrant {
  const resources: Record<string, string[]> = {};
  for (const type of Object.keys(grant.resources).sort()) {
    resources[type] = [...grant.resources[type]!].sort();
  }
  const constraints: Constraints = {};
  for (const name of CONSTRAINT_NAMES) {
    const value = grant.constraints[name];
    if (value === undefined) continue;
    constraints[name] = (Array.isArray(value) ? [...value].sort() : value) as never;
  }
  return { actions: [...grant.actions].sort(), resources, constraints };
}

/** Bound on delegation chain length. Depth 0 is authority issued from policy. */
export const MAX_DELEGATION_DEPTH = 5;
