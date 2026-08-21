/**
 * Exact decimal comparison for policy thresholds and risk signal values.
 *
 * Signal values arrive from Postgres NUMERIC and from JSON as text; policy
 * thresholds are authored as `0.9`. Both are normalised to decimal strings and
 * compared digit-by-digit, so a threshold of `0.9` behaves identically no
 * matter which side of the wire it came from and no matter how many times the
 * evidence record is round-tripped.
 */

const DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;

export class DecimalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecimalError';
  }
}

export function isDecimalString(value: unknown): value is string {
  return typeof value === 'string' && DECIMAL.test(value);
}

/**
 * Normalises a JSON number or string into a canonical decimal string.
 * Exponential notation is rejected rather than expanded: a policy threshold
 * written as `1e6` is ambiguous to a human reviewer, and policy review is a
 * security control.
 */
export function toDecimalString(value: string | number): string {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new DecimalError('value is not finite');
    const text = String(value);
    if (text.includes('e') || text.includes('E')) {
      throw new DecimalError(`exponential notation is not accepted: ${text}`);
    }
    return normalize(text);
  }
  return normalize(value.trim());
}

function normalize(text: string): string {
  if (!DECIMAL.test(text)) throw new DecimalError(`malformed decimal: ${JSON.stringify(text)}`);
  let [whole = '0', fraction = ''] = text.replace('-', '').split('.');
  fraction = fraction.replace(/0+$/, '');
  whole = whole.replace(/^0+(?=\d)/, '');
  const sign = text.startsWith('-') && !(whole === '0' && fraction === '') ? '-' : '';
  return `${sign}${whole}${fraction ? `.${fraction}` : ''}`;
}

export function compareDecimal(a: string, b: string): -1 | 0 | 1 {
  const left = normalize(a);
  const right = normalize(b);
  if (left === right) return 0;

  const leftNeg = left.startsWith('-');
  const rightNeg = right.startsWith('-');
  if (leftNeg !== rightNeg) return leftNeg ? -1 : 1;

  const magnitude = compareMagnitude(
    leftNeg ? left.slice(1) : left,
    rightNeg ? right.slice(1) : right,
  );
  return leftNeg ? (-magnitude as -1 | 0 | 1) : magnitude;
}

function compareMagnitude(a: string, b: string): -1 | 0 | 1 {
  const [aw = '0', af = ''] = a.split('.');
  const [bw = '0', bf = ''] = b.split('.');
  if (aw.length !== bw.length) return aw.length < bw.length ? -1 : 1;
  if (aw !== bw) return aw < bw ? -1 : 1;
  const width = Math.max(af.length, bf.length);
  const ap = af.padEnd(width, '0');
  const bp = bf.padEnd(width, '0');
  if (ap === bp) return 0;
  return ap < bp ? -1 : 1;
}
