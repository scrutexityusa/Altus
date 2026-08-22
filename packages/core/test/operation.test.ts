import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CanonicalizationError,
  ScrutexityError,
  canonicalOperation,
  canonicalize,
  computeBindingHash,
  computeIntentHash,
  diffOperations,
  hashObject,
  parseMoney,
  verifyIntent,
  type CanonicalOperation,
  type ExecutionGrantBinding,
} from '../src/index.js';

/**
 * Canonicalisation is the foundation the whole enforcement boundary stands on.
 * If two honest implementations can disagree about the bytes for one
 * operation, every downstream comparison is decorative. So these tests are
 * mostly about the boring cases -- ordering, absence, spelling -- because
 * those are where implementations drift.
 */

const wire = (context: Record<string, unknown>): CanonicalOperation =>
  canonicalOperation({
    action: 'wire.execute',
    resource: { type: 'bank_account', id: 'acct_001' },
    context: {
      amount: parseMoney('25000.00', 'USD'),
      currency: 'USD',
      counterparty_id: 'cp_100',
      ...context,
    },
  });

describe('canonical operations', () => {
  it('is independent of the order fields were written in', () => {
    const a = canonicalOperation({
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        reference: 'INV-88',
        counterparty_id: 'cp_100',
        currency: 'USD',
        amount: parseMoney('25000.00', 'USD'),
      },
    });
    const b = canonicalOperation({
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: parseMoney('25000.00', 'USD'),
        currency: 'USD',
        counterparty_id: 'cp_100',
        reference: 'INV-88',
      },
    });
    expect(computeIntentHash(a)).toBe(computeIntentHash(b));
  });

  it('treats an absent optional field and an explicit null identically', () => {
    const absent = wire({});
    const explicitNull = wire({ reference: null });
    expect(computeIntentHash(absent)).toBe(computeIntentHash(explicitNull));
    expect(absent.parameters['reference']).toBeUndefined();
  });

  it('ignores fields the catalog does not declare for the action', () => {
    // The projection is the control. An agent appending a field must not be
    // able to move the hash, because an undeclared field cannot reach the
    // external system and therefore cannot be part of the intent.
    const plain = wire({});
    const embellished = wire({ note: 'ignore me', priority: 'urgent', __proto__: 'x' });
    expect(computeIntentHash(plain)).toBe(computeIntentHash(embellished));
  });

  it('changes the hash when any material field changes', () => {
    const base = computeIntentHash(wire({}));
    const mutations: Record<string, CanonicalOperation> = {
      amount: wire({ amount: parseMoney('25000.01', 'USD') }),
      counterparty: wire({ counterparty_id: 'cp_999' }),
      reference: wire({ reference: 'INV-89' }),
      resource: canonicalOperation({
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_002' },
        context: {
          amount: parseMoney('25000.00', 'USD'),
          currency: 'USD',
          counterparty_id: 'cp_100',
        },
      }),
      action: canonicalOperation({
        action: 'wire.submit',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: {
          amount: parseMoney('25000.00', 'USD'),
          currency: 'USD',
          counterparty_id: 'cp_100',
        },
      }),
    };
    for (const [name, mutated] of Object.entries(mutations)) {
      expect(computeIntentHash(mutated), `${name} did not move the hash`).not.toBe(base);
    }
  });

  it('distinguishes currencies at the same numeric amount', () => {
    const usd = computeIntentHash(wire({ amount: parseMoney('1000.00', 'USD') }));
    const eur = computeIntentHash(wire({ amount: parseMoney('1000.00', 'EUR'), currency: 'EUR' }));
    expect(usd).not.toBe(eur);
  });

  it('refuses an unknown action rather than hashing a guess', () => {
    expect(() =>
      canonicalOperation({
        action: 'wire.exceute',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: {},
      }),
    ).toThrow(ScrutexityError);
  });

  it('refuses an action against the wrong resource type', () => {
    expect(() =>
      canonicalOperation({
        action: 'wire.execute',
        resource: { type: 'counterparty', id: 'cp_100' },
        context: { amount: parseMoney('1.00', 'USD'), currency: 'USD', counterparty_id: 'cp_100' },
      }),
    ).toThrow(/cannot be attempted against resource type/);
  });

  it('refuses an operation missing a field the action requires', () => {
    expect(() =>
      canonicalOperation({
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: { amount: parseMoney('1.00', 'USD'), currency: 'USD' },
      }),
    ).toThrow(/requires context field "counterparty_id"/);
  });

  it('refuses a float in a material field', () => {
    expect(() =>
      canonicalOperation({
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: {
          amount: parseMoney('1.00', 'USD'),
          currency: 'USD',
          counterparty_id: 'cp_100',
          reference: 0.1 + 0.2,
        },
      }),
    ).toThrow(/floating-point/);
  });

  it('refuses a null inside a parameter list, where position is meaningful', () => {
    expect(() =>
      canonicalOperation({
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: {
          amount: parseMoney('1.00', 'USD'),
          currency: 'USD',
          counterparty_id: 'cp_100',
          reference: ['a', null, 'b'] as unknown,
        },
      }),
    ).toThrow(/may not contain nulls/);
  });
});

describe('Unicode normalisation', () => {
  it('hashes canonically equivalent spellings identically', () => {
    // U+00E9 versus "e" + U+0301. A bank statement, a treasurer's screen and
    // a confirmation email all render these the same.
    const composed = wire({ reference: 'José Automotriz' });
    const decomposed = wire({ reference: 'José Automotriz' });
    expect(computeIntentHash(composed)).toBe(computeIntentHash(decomposed));
  });

  it('keeps compatibility-equivalent characters distinct', () => {
    // NFKC would fold U+2460 to "1" and merge these. NFC does not, which is
    // the point: a control that merges distinct references is worse than none.
    expect(hashObject({ ref: '①' })).not.toBe(hashObject({ ref: '1' }));
    expect(hashObject({ ref: 'Ａ' })).not.toBe(hashObject({ ref: 'A' }));
  });

  it('normalises object keys as well as values', () => {
    expect(hashObject({ ['café']: 1 })).toBe(hashObject({ ['café']: 1 }));
  });

  it('refuses an object whose keys collide once normalised', () => {
    // Which value wins would depend on insertion order, and a canonical form
    // that depends on insertion order is not canonical.
    expect(() => canonicalize({ ['café']: 1, ['café']: 2 })).toThrow(CanonicalizationError);
  });
});

describe('JavaScript-only input rules', () => {
  /**
   * These four inputs cannot survive a round trip through a JSON file, so the
   * cross-language conformance vectors cannot carry them. They are still rules
   * the TypeScript implementation must hold to, and a second implementation in
   * another language will have its own equivalents.
   */
  it('drops an undefined property, exactly as if it were absent', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(hashObject({ a: 1, b: undefined })).toBe(hashObject({ a: 1 }));
  });

  it('does not treat undefined and null as the same thing inside an object', () => {
    // Absent means "no such field". Explicit null means "this field is
    // present and empty". The projection in canonicalOperation collapses them
    // deliberately; the raw canonicaliser must not, or evidence loses a
    // distinction its callers may depend on.
    expect(hashObject({ a: undefined })).not.toBe(hashObject({ a: null }));
  });

  it('serialises a bigint as its decimal string', () => {
    expect(canonicalize({ n: 12345678901234567890n })).toBe('{"n":"12345678901234567890"}');
  });

  it('turns an array hole into null, so positions do not shift', () => {
    expect(canonicalize([1, , 3])).toBe('[1,null,3]');
  });

  it('serialises a Date as ISO-8601 UTC with millisecond precision', () => {
    expect(canonicalize(new Date('2026-01-01T00:00:00.000Z'))).toBe('"2026-01-01T00:00:00.000Z"');
  });

  it('refuses an invalid Date rather than emitting a string that reads valid', () => {
    expect(() => canonicalize(new Date('nonsense'))).toThrow(CanonicalizationError);
  });

  it('refuses NaN and Infinity, which JSON cannot express either', () => {
    // Kept here rather than in the vector file for the same reason as bigint:
    // JSON.stringify writes both as null, so a round trip would quietly turn
    // the vector into a test that nothing is wrong.
    expect(() => canonicalize(Number.NaN)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(CanonicalizationError);
    expect(() => canonicalize({ risk: Number.NaN })).toThrow(CanonicalizationError);
  });
});

describe('intent binding versus authority binding', () => {
  const operation = wire({});
  const binding = (overrides: Partial<ExecutionGrantBinding> = {}): ExecutionGrantBinding => ({
    authorized_intent: operation,
    authorization_context: {
      decision_id: 'dec_aaa',
      authority_lease_id: 'lease_aaa',
      policy_version_id: 'polver_aaa',
      policy_hash: 'a'.repeat(64),
      approved_context_hash: null,
    },
    grant_id: 'dec_aaa',
    expires_at: '2026-01-01T00:00:00.000Z',
    nonce: 'nonce-1',
    ...overrides,
  });

  it('answers "did the operation mutate" independently of the authority', () => {
    const recorded = computeIntentHash(operation);
    const verification = verifyIntent({
      recorded_intent_hash: recorded,
      recorded_binding_hash: computeBindingHash(binding()),
      authorized_intent: operation,
      actual_operation: operation,
      actual_binding: binding(),
    });
    expect(verification.intent_matches).toBe(true);
    expect(verification.binding_matches).toBe(true);
    expect(verification.mutated_fields).toEqual([]);
  });

  it('catches a replay under a different decision even though nothing mutated', () => {
    const recorded = computeIntentHash(operation);
    const verification = verifyIntent({
      recorded_intent_hash: recorded,
      recorded_binding_hash: computeBindingHash(binding()),
      authorized_intent: operation,
      // Same operation, different decision. This is the case an intent hash
      // alone cannot see.
      actual_operation: operation,
      actual_binding: binding({
        grant_id: 'dec_bbb',
        authorization_context: {
          ...binding().authorization_context,
          decision_id: 'dec_bbb',
        },
      }),
    });
    expect(verification.intent_matches).toBe(true);
    expect(verification.binding_matches).toBe(false);
  });

  it('catches a mutation under the correct decision, and names the field', () => {
    const mutated = wire({ amount: parseMoney('250000.00', 'USD') });
    const verification = verifyIntent({
      recorded_intent_hash: computeIntentHash(operation),
      recorded_binding_hash: computeBindingHash(binding()),
      authorized_intent: operation,
      actual_operation: mutated,
      actual_binding: binding({ authorized_intent: mutated }),
    });
    expect(verification.intent_matches).toBe(false);
    expect(verification.binding_matches).toBe(false);
    expect(verification.mutated_fields).toEqual(['amount']);
  });

  it('breaks the binding when the approval context moves', () => {
    // The treasurer approved under one risk picture. Executing against a
    // different one is not the operation they said yes to.
    const approved = binding({
      authorization_context: {
        ...binding().authorization_context,
        approved_context_hash: 'b'.repeat(64),
      },
    });
    const drifted = binding({
      authorization_context: {
        ...binding().authorization_context,
        approved_context_hash: 'c'.repeat(64),
      },
    });
    expect(computeBindingHash(approved)).not.toBe(computeBindingHash(drifted));
  });

  it('makes two identical operations bind differently via the nonce', () => {
    // Paying the same supplier the same amount twice in one day is ordinary.
    // Reusing this morning's binding for it is not.
    expect(computeBindingHash(binding({ nonce: 'a' }))).not.toBe(
      computeBindingHash(binding({ nonce: 'b' })),
    );
  });

  it('names every field that differs, not just the first', () => {
    const mutated = wire({
      amount: parseMoney('9.99', 'USD'),
      counterparty_id: 'cp_999',
      reference: 'changed',
    });
    expect(diffOperations(operation, mutated)).toEqual(['amount', 'counterparty_id', 'reference']);
  });

  it('reports no values in the diff, only field names', () => {
    const mutated = wire({ counterparty_id: 'cp_secret_account_12345' });
    const fields = diffOperations(operation, mutated);
    expect(JSON.stringify(fields)).not.toContain('12345');
  });
});

/**
 * The conformance vectors are the contract a second implementation has to
 * meet. They live in a JSON file rather than in this test so that a Python or
 * Go implementation can consume the identical file and assert the identical
 * hashes -- see docs/canonicalization-spec.md.
 */
describe('canonicalisation conformance vectors', () => {
  const vectorsPath = join(
    dirname(fileURLToPath(import.meta.url)),
    '../../../test/canonicalization-vectors.json',
  );
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
    version: number;
    vectors: { name: string; value: unknown; canonical?: string; sha256?: string; error?: true }[];
  };

  it('has enough vectors to be worth calling a conformance suite', () => {
    expect(vectors.vectors.length).toBeGreaterThanOrEqual(50);
  });

  for (const vector of vectors.vectors) {
    it(`vector: ${vector.name}`, () => {
      if (vector.error) {
        expect(() => canonicalize(vector.value)).toThrow(CanonicalizationError);
        return;
      }
      expect(canonicalize(vector.value)).toBe(vector.canonical);
      expect(hashObject(vector.value)).toBe(vector.sha256);
    });
  }
});
