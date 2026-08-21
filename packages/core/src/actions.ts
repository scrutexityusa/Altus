import { z } from 'zod';
import type { ConstraintName } from './authority/grant.js';

/**
 * ============================================================================
 * The action catalog.
 * ============================================================================
 *
 * An action is not an arbitrary string. Each one declares the resource types
 * it can touch, the context fields it is *defined* to carry, and which of
 * those are mandatory. Three things fall out of that, all of which the system
 * needs:
 *
 *  1. A typo cannot become a bypass. `wire.exceute` is rejected at the
 *     boundary rather than matching no rule and quietly taking some default.
 *
 *  2. A money-bearing action can never reach the decision point without an
 *     amount, so the amount ceiling never has to guess what an absent amount
 *     means.
 *
 *  3. A constraint only binds the actions its dimension is defined for. An
 *     authority that caps payments at zero does not thereby forbid reading a
 *     counterparty record, which carries no amount at all.
 *
 * The catalog is data. Making it tenant-extensible is a schema row and a cache,
 * not a redesign -- see ADR-0007.
 */

export interface ActionDefinition {
  /** Resource types this action may be attempted against. */
  resource_types: string[];
  /** Context fields this action is defined to carry. */
  context_fields: string[];
  /** Fields without which the request is not evaluable at all. */
  required_context: string[];
  /** True when the action moves money, and must therefore carry an amount. */
  money_bearing: boolean;
  description: string;
}

const WIRE_CONTEXT = ['amount', 'currency', 'counterparty_id', 'destination_country', 'reference'];
const WIRE_REQUIRED = ['amount', 'currency', 'counterparty_id'];

export const ACTION_CATALOG: Record<string, ActionDefinition> = {
  'wire.create': {
    resource_types: ['bank_account'],
    context_fields: WIRE_CONTEXT,
    required_context: WIRE_REQUIRED,
    money_bearing: true,
    description: 'Draft an outbound wire from an account',
  },
  'wire.modify': {
    resource_types: ['bank_account'],
    context_fields: [...WIRE_CONTEXT, 'wire_id'],
    required_context: WIRE_REQUIRED,
    money_bearing: true,
    description: 'Alter the amount, counterparty or destination of a drafted wire',
  },
  'wire.submit': {
    resource_types: ['bank_account'],
    context_fields: [...WIRE_CONTEXT, 'wire_id'],
    required_context: WIRE_REQUIRED,
    money_bearing: true,
    description: 'Submit a drafted wire for execution',
  },
  'wire.execute': {
    resource_types: ['bank_account'],
    context_fields: [...WIRE_CONTEXT, 'wire_id'],
    required_context: WIRE_REQUIRED,
    money_bearing: true,
    description: 'Release funds against a submitted wire',
  },
  'wire.read': {
    resource_types: ['bank_account'],
    context_fields: ['wire_id'],
    required_context: [],
    money_bearing: false,
    description: 'Read the status of a wire',
  },
  'account.read': {
    resource_types: ['bank_account'],
    context_fields: [],
    required_context: [],
    money_bearing: false,
    description: 'Read account details and balance',
  },
  'statement.read': {
    resource_types: ['bank_account'],
    context_fields: [],
    required_context: [],
    money_bearing: false,
    description: 'Read an account statement',
  },
  'counterparty.read': {
    resource_types: ['counterparty'],
    context_fields: ['counterparty_id'],
    required_context: [],
    money_bearing: false,
    description: 'Read a counterparty record for verification',
  },
};

export const KNOWN_ACTIONS = Object.keys(ACTION_CATALOG).sort();

export function lookupAction(action: string): ActionDefinition | undefined {
  return ACTION_CATALOG[action];
}

/**
 * Which constraint dimensions bind a given action. A dimension binds when the
 * action is defined to carry the field that dimension reads.
 */
export function applicableDimensions(
  action: string,
  dimensionPaths: Record<ConstraintName, string>,
) {
  const definition = ACTION_CATALOG[action];
  const entries = Object.entries(dimensionPaths) as [ConstraintName, string][];
  if (!definition) return [] as ConstraintName[];
  return entries
    .filter(([, path]) => definition.context_fields.includes(path))
    .map(([name]) => name);
}

export interface ActionValidation {
  ok: boolean;
  errors: string[];
}

/**
 * Validates a request against the catalog before any policy runs. This is the
 * guarantee the amount ceiling relies on: a money-bearing action that reaches
 * the decision point always carries an amount.
 */
export function validateActionRequest(
  action: string,
  resourceType: string,
  context: Record<string, unknown>,
): ActionValidation {
  const definition = ACTION_CATALOG[action];
  if (!definition) {
    return { ok: false, errors: [`unknown action "${action}"`] };
  }
  const errors: string[] = [];
  if (!definition.resource_types.includes(resourceType)) {
    errors.push(
      `action "${action}" cannot be attempted against resource type "${resourceType}" (expected ${definition.resource_types.join(' or ')})`,
    );
  }
  for (const field of definition.required_context) {
    if (context[field] === undefined || context[field] === null) {
      errors.push(`action "${action}" requires context field "${field}"`);
    }
  }
  return { ok: errors.length === 0, errors };
}

export const ActionSchema = z.string().refine((value) => value in ACTION_CATALOG, {
  message: 'unknown action',
});
