import { z } from 'zod';

/**
 * Exact money. Authorization thresholds decide whether a wire leaves the
 * building, so amounts are integer minor units and comparisons are integer
 * comparisons. Floating point never touches an amount.
 */
export interface Money {
  readonly currency: string;
  /** Minor units (cents for USD), as a decimal string to survive JSON. */
  readonly amountMinor: string;
}

/** ISO 4217 minor-unit exponents for the currencies the platform accepts. */
const EXPONENTS: Record<string, number> = {
  USD: 2, EUR: 2, GBP: 2, CHF: 2, CAD: 2, AUD: 2, SGD: 2, HKD: 2,
  SEK: 2, NOK: 2, DKK: 2, NZD: 2, MXN: 2, ZAR: 2, PLN: 2,
  JPY: 0, KRW: 0, CLP: 0, ISK: 0, VND: 0,
  BHD: 3, JOD: 3, KWD: 3, OMR: 3, TND: 3,
};

export class MoneyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MoneyError';
  }
}

export function isSupportedCurrency(currency: string): boolean {
  return Object.hasOwn(EXPONENTS, currency);
}

export function currencyExponent(currency: string): number {
  const exp = EXPONENTS[currency];
  if (exp === undefined) throw new MoneyError(`unsupported currency: ${currency}`);
  return exp;
}

const DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;

/**
 * Parses a major-unit decimal amount ("750000.00") into exact minor units.
 * Accepts a number only when it is an integer, so a policy author cannot
 * silently introduce 0.1 + 0.2 into a threshold.
 */
export function parseMoney(amount: string | number, currency: string): Money {
  const cur = currency.toUpperCase();
  const exponent = currencyExponent(cur);

  let text: string;
  if (typeof amount === 'number') {
    if (!Number.isFinite(amount)) throw new MoneyError('amount is not finite');
    if (!Number.isInteger(amount)) {
      throw new MoneyError(
        `fractional amount ${amount} must be supplied as a decimal string to stay exact`,
      );
    }
    text = String(amount);
  } else {
    text = amount.trim();
  }

  if (!DECIMAL.test(text)) throw new MoneyError(`malformed amount: ${JSON.stringify(amount)}`);

  const negative = text.startsWith('-');
  const unsigned = negative ? text.slice(1) : text;
  const [whole = '0', fraction = ''] = unsigned.split('.');
  if (fraction.length > exponent) {
    throw new MoneyError(
      `amount ${text} has more precision than ${cur} allows (${exponent} minor digits)`,
    );
  }
  const padded = fraction.padEnd(exponent, '0');
  const minor = BigInt(whole + padded) * (negative ? -1n : 1n);
  return { currency: cur, amountMinor: minor.toString() };
}

export function moneyMinor(money: Money): bigint {
  return BigInt(money.amountMinor);
}

/** Formats minor units back to a major-unit decimal string. */
export function formatMoney(money: Money): string {
  const exponent = currencyExponent(money.currency);
  const minor = moneyMinor(money);
  const negative = minor < 0n;
  const digits = (negative ? -minor : minor).toString().padStart(exponent + 1, '0');
  const whole = digits.slice(0, digits.length - exponent);
  const fraction = exponent === 0 ? '' : `.${digits.slice(digits.length - exponent)}`;
  return `${negative ? '-' : ''}${whole}${fraction}`;
}

export function formatMoneyWithCurrency(money: Money): string {
  return `${formatMoney(money)} ${money.currency}`;
}

/**
 * Compares two amounts. Cross-currency comparison is an error rather than a
 * conversion: Scrutexity does not hold exchange rates, and guessing one would
 * silently change an authorization threshold.
 */
export function compareMoney(a: Money, b: Money): -1 | 0 | 1 {
  if (a.currency !== b.currency) {
    throw new MoneyError(`cannot compare ${a.currency} with ${b.currency}`);
  }
  const left = moneyMinor(a);
  const right = moneyMinor(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

export function moneyLte(a: Money, b: Money): boolean {
  return compareMoney(a, b) <= 0;
}

export const MoneySchema: z.ZodType<Money> = z
  .object({
    currency: z
      .string()
      .length(3)
      .transform((c) => c.toUpperCase())
      .refine(isSupportedCurrency, { message: 'unsupported currency' }),
    amountMinor: z.string().regex(/^-?\d+$/, 'minor units must be an integer string'),
  })
  .strict();

/** Wire form used by policies and request context: `{ amount, currency }`. */
export const MoneyInputSchema = z
  .object({
    amount: z.union([z.string(), z.number()]),
    currency: z.string().length(3),
  })
  .strict()
  .transform((v, ctx): Money => {
    try {
      return parseMoney(v.amount, v.currency);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : 'invalid money',
      });
      return z.NEVER;
    }
  });
