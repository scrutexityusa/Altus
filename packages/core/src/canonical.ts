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
      return JSON.stringify(value);
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
    return `[${value.map((item) => encode(item) ?? 'null').join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of Object.keys(record).sort()) {
    const encoded = encode(record[key]);
    if (encoded === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${encoded}`);
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
