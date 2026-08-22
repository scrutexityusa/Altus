import { createHash } from 'node:crypto';

/**
 * Deterministic JSON serialisation, in the spirit of RFC 8785 (JCS).
 *
 * Evidence integrity depends on two parties hashing the same bytes for the
 * same facts, so serialisation must not depend on key insertion order, on
 * whether an optional field was written as `undefined` or omitted, or on a
 * float's shortest round-trip representation.
 *
 * Rules:
 *   - object keys sorted by UTF-16 code unit
 *   - `undefined` properties and array holes are dropped / become null
 *   - non-integer and non-finite numbers are rejected: money is a Money
 *     record and risk values are decimal strings. A silently reformatted
 *     0.1 + 0.2 has no place in an audit record.
 *   - bigint is serialised as its decimal string
 *   - Date is serialised as an ISO-8601 UTC string with millisecond precision
 *   - strings -- both keys and values -- are normalised to Unicode NFC
 *
 * The NFC rule is a departure from JCS, which deliberately leaves strings
 * alone, and it exists because this hash is a security control rather than an
 * interchange format. "Jose\u0301" and "Jos\u00e9" render identically in
 * every interface a human or a bank will ever see, and without normalisation
 * they produce different hashes -- which means an operation could be approved
 * under one spelling and executed under the other. NFC composes them to the
 * same bytes.
 *
 * NFKC is deliberately *not* used. NFKC is lossy by design: it folds U+2460
 * CIRCLED DIGIT ONE to "1" and full-width forms to ASCII, so two genuinely
 * different account references could collide into one hash. A control that
 * merges distinct operations is worse than no control. NFC only composes
 * sequences that are already canonically equivalent.
 *
 * NFC is the identity function on ASCII, so nothing in an ASCII-only corpus
 * changes shape.
 */
export function canonicalize(value: unknown): string {
  const out = encode(value);
  if (out === undefined) throw new CanonicalizationError('top-level value is not serialisable');
  return out;
}

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(`canonicalization failed: ${message}`);
    this.name = 'CanonicalizationError';
  }
}

function encode(value: unknown): string | undefined {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'undefined':
      return undefined;
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'string':
      return JSON.stringify(value.normalize('NFC'));
    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`non-finite number ${String(value)}`);
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalizationError(
          `non-integer number ${value}: use a decimal string or a Money record`,
        );
      }
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalizationError(`integer ${value} exceeds the safe range`);
      }
      return String(value);
    case 'object':
      break;
    default:
      throw new CanonicalizationError(`unsupported type ${typeof value}`);
  }

  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new CanonicalizationError('invalid Date');
    return JSON.stringify(value.toISOString());
  }
  if (Array.isArray(value)) {
    // Indexed rather than `.map`, which preserves holes: a sparse array went
    // through `.map` untouched and joined to `[1,,3]`, which is not JSON and
    // which a second implementation could never reproduce. Reading by index
    // yields `undefined` for a hole, which becomes null like any other
    // unserialisable element, so positions never shift.
    const parts: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      parts.push(encode(value[index]) ?? 'null');
    }
    return `[${parts.join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const parts: string[] = [];
  // Keys are normalised before they are sorted, so the ordering is over the
  // same bytes that get emitted. Sorting first and normalising afterwards
  // could emit a sequence that is no longer in order.
  const keys = Object.keys(record)
    .map((key) => [key.normalize('NFC'), key] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  let previous: string | undefined;
  for (const [normalizedKey, key] of keys) {
    // Two keys that differ only in normalisation collapse to one here. Which
    // value would win depends on insertion order, and a canonical form that
    // depends on insertion order is not canonical. Refuse rather than pick.
    if (normalizedKey === previous) {
      throw new CanonicalizationError(
        `duplicate key ${JSON.stringify(normalizedKey)} after Unicode normalisation`,
      );
    }
    previous = normalizedKey;
    const encoded = encode(record[key]);
    if (encoded === undefined) continue;
    parts.push(`${JSON.stringify(normalizedKey)}:${encoded}`);
  }
  return `{${parts.join(',')}}`;
}

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** SHA-256 over the canonical form of `value`. The only hashing entry point. */
export function hashObject(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

/** 32 zero bytes: the genesis link of every receipt chain. */
export const GENESIS_HASH = '0'.repeat(64);
