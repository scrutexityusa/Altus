import { z } from 'zod';
import { toDecimalString } from '../decimal.js';
import { MoneyInputSchema, MoneySchema } from '../money.js';
import { ACTION_PATTERN, ConstraintsSchema } from '../authority/grant.js';
import { IntentDeclarationSchema } from '../intent.js';

/**
 * ============================================================================
 * Policy-as-code (Sections 11, 13, 32).
 * ============================================================================
 *
 * A policy document is data, never code. There is no expression language to
 * escape from, no user-supplied regular expression to blow up on, and no
 * host-language callback: a rule is a set of selector/matcher pairs evaluated
 * by a total function. That is what makes a decision replayable from a hash
 * years after the fact.
 *
 * Authored numbers are normalised to decimal strings and money to exact minor
 * units at parse time, so the *stored* document -- the thing that gets hashed
 * and versioned -- is already canonical.
 */

export const POLICY_API_VERSION = 'scrutexity.dev/policy/v1';

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

/** Authored decimal: `0.9`, `"0.9"`. Stored as a canonical decimal string. */
const DecimalValue = z.union([z.number(), z.string()]).transform((v, ctx) => {
  try {
    return toDecimalString(v);
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : 'invalid decimal',
    });
    return z.NEVER;
  }
});

/** A comparable quantity: either an exact amount of money or a decimal. */
const OrderedValue = z.union([MoneyInputSchema, MoneySchema, DecimalValue]);

/** Equality operands additionally allow strings and booleans. */
const ScalarValue = z.union([z.boolean(), MoneyInputSchema, MoneySchema, DecimalValue, z.string()]);

export const MatcherSchema = z
  .object({
    eq: ScalarValue.optional(),
    neq: ScalarValue.optional(),
    in: z.array(ScalarValue).min(1).optional(),
    nin: z.array(ScalarValue).min(1).optional(),
    lt: OrderedValue.optional(),
    lte: OrderedValue.optional(),
    gt: OrderedValue.optional(),
    gte: OrderedValue.optional(),
    /** `exists: false` matches an absent or null value. */
    exists: z.boolean().optional(),
    /** Literal prefix test. Deliberately not a regular expression. */
    prefix: z.string().min(1).optional(),
  })
  .strict()
  .refine((m) => Object.keys(m).length > 0, {
    message: 'matcher must declare at least one operator',
  });

export type Matcher = z.infer<typeof MatcherSchema>;

/**
 * Selectors are a closed vocabulary. An unknown selector is a policy authoring
 * error caught at validation time, not a silently-never-matching rule.
 *
 *   action
 *   resource.type | resource.id | resource.attributes.<path>
 *   agent.id | agent.handle
 *   context.<path>
 *   authority.present | authority.lease_id | authority.depth
 *   signal.<signal_type>.<agent|resource|counterparty|organization>[.value|.confidence]
 */
export const SELECTOR_PATTERN =
  /^(?:action|resource\.(?:type|id|attributes\.[a-z0-9_.]+)|agent\.(?:id|handle)|context\.[a-zA-Z0-9_.]+|authority\.(?:present|lease_id|depth)|signal\.[a-z0-9_]+\.(?:agent|resource|counterparty|organization)(?:\.(?:value|confidence))?)$/;

const SelectorKey = z.string().regex(SELECTOR_PATTERN, 'unknown policy selector');

export interface Condition {
  match?: Record<string, Matcher>;
  all_of?: Condition[];
  any_of?: Condition[];
  not?: Condition;
}

/**
 * `when:` is a map of selector -> matcher (implicit AND), optionally combined
 * with all_of / any_of / not. Bare selector keys are sugar for `match`.
 */
export const ConditionSchema: z.ZodType<Condition> = z.lazy(() =>
  z.record(z.string(), z.unknown()).transform((raw, ctx): Condition => {
    const condition: Condition = {};
    const match: Record<string, Matcher> = {};

    for (const [key, value] of Object.entries(raw)) {
      if (key === 'all_of' || key === 'any_of') {
        const parsed = z.array(ConditionSchema).min(1).safeParse(value);
        if (!parsed.success) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `${key}: ${parsed.error.message}`,
            path: [key],
          });
          continue;
        }
        condition[key] = parsed.data;
        continue;
      }
      if (key === 'match') {
        // Already-normalised form. A stored policy must re-parse to itself,
        // or its hash would change every time it round-trips through the
        // database and the evidence chain would stop meaning anything.
        const parsed = z.record(SelectorKey, MatcherSchema).safeParse(value);
        if (!parsed.success) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `match: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
            path: [key],
          });
          continue;
        }
        Object.assign(match, parsed.data);
        continue;
      }
      if (key === 'not') {
        const parsed = ConditionSchema.safeParse(value);
        if (!parsed.success) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `not: ${parsed.error.message}`,
            path: [key],
          });
          continue;
        }
        condition.not = parsed.data;
        continue;
      }

      const selector = SelectorKey.safeParse(key);
      if (!selector.success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `unknown selector "${key}"`,
          path: [key],
        });
        continue;
      }
      // Sugar: `action: wire.execute` means `action: { eq: wire.execute }`.
      const matcherInput =
        value !== null && typeof value === 'object' && !Array.isArray(value)
          ? value
          : Array.isArray(value)
            ? { in: value }
            : { eq: value };
      const matcher = MatcherSchema.safeParse(matcherInput);
      if (!matcher.success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${key}: ${matcher.error.issues.map((i) => i.message).join('; ')}`,
          path: [key],
        });
        continue;
      }
      match[key] = matcher.data;
    }

    if (Object.keys(match).length > 0) condition.match = match;
    if (Object.keys(condition).length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'condition is empty' });
    }
    return condition;
  }),
);

// ---------------------------------------------------------------------------
// Effects
// ---------------------------------------------------------------------------

export const DECISIONS = ['ALLOW', 'DENY', 'ESCALATE'] as const;
export type Decision = (typeof DECISIONS)[number];

export const FAILOVER_BEHAVIORS = ['FAIL_OPEN', 'FAIL_CLOSED', 'ESCALATE'] as const;
export type FailoverBehavior = (typeof FAILOVER_BEHAVIORS)[number];

export const ApprovalRequirementSchema = z
  .object({
    required: z.boolean().default(true),
    /** Number of distinct approvals needed. */
    quorum: z.number().int().min(1).default(1),
    /** Every listed role must be represented among the approvals. */
    roles: z.array(z.string().min(1)).default([]),
    /** Bars the requesting agent's owner from approving their own action. */
    forbid_self_approval: z.boolean().default(true),
    ttl_seconds: z.number().int().min(30).max(86_400).default(3600),
  })
  .strict();

export type ApprovalRequirement = z.infer<typeof ApprovalRequirementSchema>;

/** Authority decay (Section 13): a deterministic, time-boxed narrowing. */
export const AuthorityEffectSchema = z
  .object({
    remove_actions: z.array(z.string().regex(ACTION_PATTERN)).min(1).optional(),
    tighten: ConstraintsSchema.optional(),
    duration_seconds: z.number().int().min(1).max(2_592_000).optional(),
  })
  .strict()
  .refine((e) => e.remove_actions !== undefined || e.tighten !== undefined, {
    message: 'authority_effect must remove actions or tighten a constraint',
  });

export type AuthorityEffect = z.infer<typeof AuthorityEffectSchema>;

export const RuleEffectSchema = z
  .object({
    decision: z.enum(DECISIONS),
    /** Machine-readable reason surfaced in the decision and the receipt. */
    reason_code: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]{2,63}$/, 'reason_code must be SCREAMING_SNAKE_CASE')
      .optional(),
    approval: ApprovalRequirementSchema.optional(),
    authority_effect: AuthorityEffectSchema.optional(),
    failure_mode: z.enum(FAILOVER_BEHAVIORS).optional(),
  })
  .strict();

export const RuleSchema = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/, 'rule id must be lower_snake_case'),
    description: z.string().max(500).optional(),
    /** Lower runs first. Ordering is for readability; outcome is order-free. */
    priority: z.number().int().min(0).max(10_000).default(100),
    when: ConditionSchema,
    then: RuleEffectSchema,
  })
  .strict();

export type PolicyRule = z.infer<typeof RuleSchema>;

const SEMVER = /^\d+\.\d+\.\d+$/;

export const PolicyDocumentSchema = z
  .object({
    apiVersion: z.literal(POLICY_API_VERSION),
    id: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/),
    version: z.string().regex(SEMVER, 'version must be semver (major.minor.patch)'),
    metadata: z
      .object({
        title: z.string().min(1).max(200),
        description: z.string().max(2000).optional(),
        owner: z.string().max(200).optional(),
        tags: z.array(z.string().max(50)).max(20).default([]),
      })
      .strict(),
    defaults: z
      .object({
        /** Decision when no rule matches. Fail-closed by construction. */
        decision: z.enum(DECISIONS).default('DENY'),
        reason_code: z
          .string()
          .regex(/^[A-Z][A-Z0-9_]{2,63}$/)
          .default('NO_RULE_MATCHED'),
        /** Lifetime of the execution grant an ALLOW confers. */
        execution_grant_ttl_seconds: z.number().int().min(5).max(86_400).default(300),
      })
      .strict()
      .default({}),
    /**
     * Failover is policy data, not a global switch (Section 18). Each
     * dependency of the decision names its own behaviour.
     */
    failure_modes: z
      .object({
        policy_unavailable: z.enum(FAILOVER_BEHAVIORS).default('FAIL_CLOSED'),
        signal_unavailable: z.enum(FAILOVER_BEHAVIORS).default('FAIL_CLOSED'),
        enforcement_unavailable: z.enum(FAILOVER_BEHAVIORS).default('FAIL_CLOSED'),
      })
      .strict()
      .default({}),
    /** Constraints every lease issued under this policy must respect. */
    delegation: z
      .object({
        enabled: z.boolean().default(true),
        max_depth: z.number().int().min(1).max(5).default(2),
        max_ttl_seconds: z.number().int().min(60).max(2_592_000).default(3600),
        /** Action patterns that may never be delegated, at any depth. */
        non_delegable_actions: z.array(z.string().regex(ACTION_PATTERN)).default([]),
      })
      .strict()
      .default({}),
    /**
     * Intent binding (see intent.ts). Two authoring forms normalise to one
     * stored shape:
     *
     *   intent: execute wire transfers        # shorthand: one intent
     *   allowed_actions: [wire.create]
     *   forbidden_actions: [wire.execute]
     *
     *   intents:                              # explicit: several named intents
     *     - id: reconcile_cash_position
     *       allowed_actions: [account.read]
     *
     * The shorthand exists because most policies govern a single objective and
     * should not have to say so twice.
     */
    intent: z.string().min(1).max(200).optional(),
    allowed_actions: z.array(z.string().regex(ACTION_PATTERN)).optional(),
    forbidden_actions: z.array(z.string().regex(ACTION_PATTERN)).optional(),
    intents: z.array(IntentDeclarationSchema).max(50).default([]),
    /** When true, a request that declares no intent is refused. */
    intent_required: z.boolean().default(false),
    rules: z.array(RuleSchema).min(1).max(500),
  })
  .strict()
  .transform((doc) => {
    // Normalise the shorthand into `intents` so the stored, hashed document has
    // exactly one shape and the evaluator has exactly one thing to read.
    if (doc.intent === undefined && !doc.allowed_actions && !doc.forbidden_actions) {
      return doc;
    }
    const shorthand = {
      id: doc.id,
      ...(doc.intent ? { description: doc.intent } : {}),
      allowed_actions: doc.allowed_actions ?? [],
      forbidden_actions: doc.forbidden_actions ?? [],
    };
    const {
      intent: _intent,
      allowed_actions: _allowed,
      forbidden_actions: _forbidden,
      ...rest
    } = doc;
    return { ...rest, intents: [shorthand, ...doc.intents] };
  })
  .superRefine((doc, ctx) => {
    const seen = new Set<string>();
    for (const [index, rule] of doc.rules.entries()) {
      if (seen.has(rule.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate rule id "${rule.id}"`,
          path: ['rules', index, 'id'],
        });
      }
      seen.add(rule.id);
      if (rule.then.decision === 'ESCALATE' && !rule.then.approval) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `rule "${rule.id}" escalates but names no approval requirement`,
          path: ['rules', index, 'then', 'approval'],
        });
      }
    }

    const intentIds = new Set<string>();
    for (const [index, declaration] of (doc.intents ?? []).entries()) {
      if (intentIds.has(declaration.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate intent id "${declaration.id}"`,
          path: ['intents', index, 'id'],
        });
      }
      intentIds.add(declaration.id);
    }
    if (doc.intent_required && (doc.intents ?? []).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'intent_required is set but the policy declares no intents',
        path: ['intent_required'],
      });
    }
  });

export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
