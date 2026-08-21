import { compareDecimal, isDecimalString } from '../decimal.js';
import { MoneySchema, compareMoney, type Money } from '../money.js';
import type { Condition, Matcher } from './schema.js';

/**
 * Deterministic matcher evaluation.
 *
 * Every operator is total: an operand of the wrong shape produces `false` and
 * a recorded reason, never a throw and never a coercion. A policy that asks
 * `amount >= $50,000` of a request that carried no amount must not
 * accidentally pass because `undefined >= 50000` is falsy in one branch and
 * truthy in another.
 */

export type PolicyValue = string | boolean | Money | null | undefined;

export interface MatcherTrace {
  operator: string;
  operand: unknown;
  observed: unknown;
  result: boolean;
}

function isMoney(value: unknown): value is Money {
  return MoneySchema.safeParse(value).success;
}

/** Ordered comparison across the two comparable types. Null when incomparable. */
function compare(observed: PolicyValue, operand: unknown): -1 | 0 | 1 | null {
  if (isMoney(operand)) {
    if (!isMoney(observed)) return null;
    if (observed.currency !== operand.currency) return null;
    return compareMoney(observed, operand);
  }
  if (isDecimalString(operand)) {
    if (typeof observed === 'string' && isDecimalString(observed)) {
      return compareDecimal(observed, operand);
    }
    return null;
  }
  return null;
}

function scalarEquals(observed: PolicyValue, operand: unknown): boolean {
  if (isMoney(operand)) {
    return (
      isMoney(observed) &&
      observed.currency === operand.currency &&
      compareMoney(observed, operand) === 0
    );
  }
  if (isDecimalString(operand) && typeof observed === 'string' && isDecimalString(observed)) {
    return compareDecimal(observed, operand) === 0;
  }
  if (typeof operand === 'boolean') return observed === operand;
  return typeof observed === 'string' && observed === operand;
}

export function evaluateMatcher(
  matcher: Matcher,
  observed: PolicyValue,
): { matched: boolean; trace: MatcherTrace[] } {
  const trace: MatcherTrace[] = [];
  const present = observed !== undefined && observed !== null;
  let matched = true;

  const record = (operator: string, operand: unknown, result: boolean) => {
    trace.push({ operator, operand, observed: observed ?? null, result });
    if (!result) matched = false;
  };

  if (matcher.exists !== undefined) record('exists', matcher.exists, present === matcher.exists);
  if (matcher.eq !== undefined) record('eq', matcher.eq, scalarEquals(observed, matcher.eq));
  if (matcher.neq !== undefined) record('neq', matcher.neq, !scalarEquals(observed, matcher.neq));
  if (matcher.in !== undefined) {
    record(
      'in',
      matcher.in,
      matcher.in.some((candidate) => scalarEquals(observed, candidate)),
    );
  }
  if (matcher.nin !== undefined) {
    record('nin', matcher.nin, !matcher.nin.some((candidate) => scalarEquals(observed, candidate)));
  }
  if (matcher.prefix !== undefined) {
    record(
      'prefix',
      matcher.prefix,
      typeof observed === 'string' && observed.startsWith(matcher.prefix),
    );
  }

  for (const [operator, operand] of [
    ['lt', matcher.lt],
    ['lte', matcher.lte],
    ['gt', matcher.gt],
    ['gte', matcher.gte],
  ] as const) {
    if (operand === undefined) continue;
    const ordering = compare(observed, operand);
    // Incomparable operands fail closed rather than defaulting either way.
    const result =
      ordering === null
        ? false
        : operator === 'lt'
          ? ordering < 0
          : operator === 'lte'
            ? ordering <= 0
            : operator === 'gt'
              ? ordering > 0
              : ordering >= 0;
    record(operator, operand, result);
  }

  return { matched, trace };
}

export interface SelectorTrace {
  selector: string;
  observed: unknown;
  matched: boolean;
  operators: MatcherTrace[];
}

export interface ConditionTrace {
  matched: boolean;
  selectors: SelectorTrace[];
  children: ConditionTrace[];
  combinator?: 'all_of' | 'any_of' | 'not';
}

export type SelectorResolver = (selector: string) => PolicyValue;

export function evaluateCondition(condition: Condition, resolve: SelectorResolver): ConditionTrace {
  const selectors: SelectorTrace[] = [];
  const children: ConditionTrace[] = [];
  let matched = true;

  for (const [selector, matcher] of Object.entries(condition.match ?? {})) {
    const observed = resolve(selector);
    const { matched: hit, trace } = evaluateMatcher(matcher, observed);
    selectors.push({ selector, observed: observed ?? null, matched: hit, operators: trace });
    if (!hit) matched = false;
  }

  if (condition.all_of) {
    for (const child of condition.all_of) {
      const trace = evaluateCondition(child, resolve);
      trace.combinator = 'all_of';
      children.push(trace);
      if (!trace.matched) matched = false;
    }
  }

  if (condition.any_of) {
    const traces = condition.any_of.map((child) => {
      const trace = evaluateCondition(child, resolve);
      trace.combinator = 'any_of';
      return trace;
    });
    children.push(...traces);
    if (!traces.some((t) => t.matched)) matched = false;
  }

  if (condition.not) {
    const trace = evaluateCondition(condition.not, resolve);
    trace.combinator = 'not';
    children.push(trace);
    if (trace.matched) matched = false;
  }

  return { matched, selectors, children };
}
