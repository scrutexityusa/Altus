import { ScrutexityError, parseMoney } from '@scrutexity/core';

/**
 * Turning a caller's context into the shape the system reasons about.
 *
 * Shared by the decision path and the enforcement boundary, and it has to be,
 * because the intent hash is computed over the normalised form. If the two
 * normalised differently -- one parsing "25000.00" into minor units and the
 * other leaving it a string -- every honest execution would be refused as a
 * mutation, and the control would have to be turned off to ship. One function.
 */
export function normalizeContext(context: Record<string, unknown>): Record<string, unknown> {
  const normalized: Record<string, unknown> = { ...context };
  const amount = normalized['amount'];
  const currency = normalized['currency'];
  if (amount !== undefined && amount !== null) {
    if (typeof currency !== 'string') {
      throw new ScrutexityError('INVALID_REQUEST', 'context.amount requires context.currency');
    }
    if (typeof amount !== 'string' && typeof amount !== 'number') {
      throw new ScrutexityError(
        'INVALID_REQUEST',
        'context.amount must be a decimal string or an integer',
      );
    }
    try {
      normalized['amount'] = parseMoney(amount, currency);
    } catch (error) {
      throw new ScrutexityError(
        'INVALID_REQUEST',
        error instanceof Error ? error.message : 'invalid amount',
      );
    }
    normalized['currency'] = currency.toUpperCase();
  }
  return normalized;
}
