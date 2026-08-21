/**
 * Generates test/canonicalization-vectors.json.
 *
 * The vectors are the contract a second implementation of the canonicalisation
 * rules has to meet. This script pins what the TypeScript reference produces;
 * the file is committed and reviewed, and a change to it in a diff is a change
 * to the wire format of every hash in the system, which is exactly the kind of
 * change that should be impossible to make by accident.
 *
 *   pnpm exec tsx scripts/generate-canonicalization-vectors.ts
 *   pnpm exec tsx scripts/generate-canonicalization-vectors.ts --check
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CanonicalizationError, canonicalize, hashObject } from '../packages/core/src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = join(root, 'test', 'canonicalization-vectors.json');

interface VectorSource {
  name: string;
  value: unknown;
  /** True when canonicalisation must refuse this value outright. */
  error?: true;
}

const usd = (amountMinor: string) => ({ currency: 'USD', amountMinor });

const sources: VectorSource[] = [
  // -- primitives ----------------------------------------------------------
  { name: 'null', value: null },
  { name: 'true', value: true },
  { name: 'false', value: false },
  { name: 'empty string', value: '' },
  { name: 'ascii string', value: 'wire.execute' },
  { name: 'string with quote', value: 'he said "go"' },
  { name: 'string with backslash', value: 'C:\\path' },
  { name: 'string with newline', value: 'line one\nline two' },
  { name: 'string with tab', value: 'a\tb' },
  { name: 'zero', value: 0 },
  { name: 'negative integer', value: -42 },
  { name: 'large safe integer', value: 9007199254740991 },

  // -- numbers that must be refused ----------------------------------------
  //
  // NaN and Infinity are absent here for the same reason bigint is: JSON has
  // no way to write them, so a round trip through this file turns them into
  // null and the vector stops testing anything. They are pinned by TypeScript
  // tests instead.
  { name: 'float is refused', value: 0.1, error: true },
  { name: 'float sum is refused', value: 0.1 + 0.2, error: true },
  { name: 'unsafe integer is refused', value: 9007199254740993, error: true },
  { name: 'nested float is refused', value: { amount: 25000.5 }, error: true },

  // -- objects and ordering ------------------------------------------------
  { name: 'empty object', value: {} },
  { name: 'single key', value: { a: 1 } },
  { name: 'keys sorted', value: { c: 3, a: 1, b: 2 } },
  { name: 'keys sorted the other way round', value: { b: 2, a: 1, c: 3 } },
  { name: 'uppercase sorts before lowercase', value: { a: 1, A: 2 } },
  { name: 'digit keys sort as text', value: { '10': 1, '9': 2, '2': 3 } },
  { name: 'key with a space', value: { 'two words': 1 } },
  { name: 'key that is the empty string', value: { '': 1 } },
  { name: 'nested object', value: { outer: { inner: { deep: 'value' } } } },
  {
    name: 'nested object, keys written innermost-last',
    value: { outer: { inner: { second: 2, first: 1 } } },
  },

  // -- absent versus null ---------------------------------------------------
  //
  // `undefined`, bigint, array holes and Date are JavaScript-only inputs. They
  // cannot survive a round trip through this file, so their rules are pinned
  // by TypeScript tests in packages/core/test/operation.test.ts instead. What
  // lives here is what a second implementation can actually read.
  { name: 'explicit null property is kept', value: { a: 1, b: null } },
  { name: 'null nested two deep', value: { a: { b: null } } },
  { name: 'null inside an object inside an array', value: [{ a: null }] },

  // -- arrays ---------------------------------------------------------------
  { name: 'empty array', value: [] },
  { name: 'array of integers', value: [1, 2, 3] },
  { name: 'array order is significant', value: [3, 2, 1] },
  { name: 'array of strings', value: ['a', 'b'] },
  { name: 'array containing null', value: [1, null, 2] },
  { name: 'nested arrays', value: [[1, 2], [3]] },
  { name: 'array of objects', value: [{ b: 1, a: 2 }] },

  // -- Unicode --------------------------------------------------------------
  { name: 'NFC composed e-acute', value: { name: 'Jos\u00e9' } },
  { name: 'NFD decomposed e-acute normalises to the same bytes', value: { name: 'Jose\u0301' } },
  { name: 'NFC composed key', value: { 'caf\u00e9': 1 } },
  { name: 'NFD decomposed key normalises to the same bytes', value: { 'cafe\u0301': 1 } },
  { name: 'circled digit is not folded to ascii', value: { ref: '\u2460' } },
  { name: 'ascii one, for contrast with the circled digit', value: { ref: '1' } },
  { name: 'fullwidth A is not folded to ascii', value: { ref: '\uff21' } },
  { name: 'ascii A, for contrast with fullwidth', value: { ref: 'A' } },
  { name: 'CJK string', value: { name: '\u9280\u884c' } },
  { name: 'emoji outside the BMP', value: { note: '\u{1f4b8}' } },
  { name: 'right-to-left string', value: { name: '\u0645\u0635\u0631\u0641' } },
  { name: 'zero-width joiner is preserved', value: { note: 'a\u200db' } },
  {
    name: 'keys colliding after normalisation are refused',
    value: { 'caf\u00e9': 1, 'cafe\u0301': 2 },
    error: true,
  },

  // -- money and domain shapes ----------------------------------------------
  { name: 'money record', value: usd('2500000') },
  { name: 'money with zero minor units', value: usd('0') },
  { name: 'money is currency-sensitive', value: { currency: 'EUR', amountMinor: '2500000' } },
  { name: 'money with leading-zero-free minor units', value: usd('1') },
  {
    name: 'a whole canonical operation',
    value: {
      operation_type: 'wire.execute',
      resource_type: 'bank_account',
      resource_id: 'acct_001',
      parameters: {
        amount: usd('2500000'),
        currency: 'USD',
        counterparty_id: 'cp_100',
        reference: 'INV-88',
      },
    },
  },
  {
    name: 'the same operation with the parameters written in another order',
    value: {
      resource_id: 'acct_001',
      parameters: {
        reference: 'INV-88',
        counterparty_id: 'cp_100',
        currency: 'USD',
        amount: usd('2500000'),
      },
      operation_type: 'wire.execute',
      resource_type: 'bank_account',
    },
  },
  {
    name: 'the same operation with a mutated amount',
    value: {
      operation_type: 'wire.execute',
      resource_type: 'bank_account',
      resource_id: 'acct_001',
      parameters: {
        amount: usd('25000000'),
        currency: 'USD',
        counterparty_id: 'cp_100',
        reference: 'INV-88',
      },
    },
  },
  // -- more ordering and shape cases ---------------------------------------
  { name: 'key differing only by trailing space', value: { a: 1, 'a ': 2 } },
  { name: 'key with a dot', value: { 'a.b': 1, a: { b: 2 } } },
  { name: 'deeply nested single chain', value: { a: { b: { c: { d: { e: 1 } } } } } },
  { name: 'mixed value types in one object', value: { s: 'x', n: 1, b: true, z: null, a: [1] } },
  { name: 'array of mixed types', value: ['x', 1, true, null, { a: 1 }] },
  { name: 'object with many keys', value: { e: 5, d: 4, c: 3, b: 2, a: 1, f: 6, g: 7 } },
  { name: 'string that looks like a number', value: { amount: '25000.00' } },
  { name: 'string that looks like JSON', value: { note: '{"a":1}' } },
  { name: 'string of only whitespace', value: { note: '   ' } },
  { name: 'identifier-shaped strings', value: { id: 'dec_01HQZX3N7', lease: 'lease_01HQZX3N7' } },
  { name: 'ISO-8601 timestamp as a string', value: { at: '2026-01-01T00:00:00.000Z' } },
  { name: 'hex hash as a string', value: { hash: 'b'.repeat(64) } },
  { name: 'empty nested containers', value: { obj: {}, arr: [] } },
  { name: 'boolean false is not absent', value: { flag: false } },
  { name: 'zero is not absent', value: { count: 0 } },
  { name: 'empty string is not absent', value: { note: '' } },

  {
    name: 'a full execution grant binding',
    value: {
      authorized_intent: {
        operation_type: 'wire.execute',
        resource_type: 'bank_account',
        resource_id: 'acct_001',
        parameters: { amount: usd('2500000'), currency: 'USD', counterparty_id: 'cp_100' },
      },
      authorization_context: {
        decision_id: 'dec_01HQ',
        authority_lease_id: 'lease_01HQ',
        policy_version_id: 'polver_01HQ',
        policy_hash: 'a'.repeat(64),
        approved_context_hash: null,
      },
      grant_id: 'dec_01HQ',
      expires_at: '2026-01-01T00:00:00.000Z',
      nonce: 'nonce-01HQ',
    },
  },
];

interface Vector {
  name: string;
  value: unknown;
  canonical?: string;
  sha256?: string;
  error?: true;
}

const vectors: Vector[] = sources.map((source) => {
  if (source.error) {
    try {
      canonicalize(source.value);
    } catch (error) {
      if (error instanceof CanonicalizationError) {
        return { name: source.name, value: source.value, error: true };
      }
      throw error;
    }
    throw new Error(`vector "${source.name}" is marked error but canonicalised cleanly`);
  }
  return {
    name: source.name,
    value: source.value,
    canonical: canonicalize(source.value),
    sha256: hashObject(source.value),
  };
});

const names = new Set(vectors.map((v) => v.name));
if (names.size !== vectors.length) throw new Error('vector names must be unique');

const document = {
  $comment:
    'Conformance vectors for the Scrutexity canonicalisation rules. Generated by ' +
    'scripts/generate-canonicalization-vectors.ts; see docs/canonicalization-spec.md. ' +
    'A change here changes the wire format of every hash in the system.',
  version: 1,
  vectors,
};

// JSON.stringify drops `undefined` properties and turns array holes into null,
// which is exactly what the canonicaliser does -- so a round-tripped vector
// still exercises the rule it was written for, and the file stays readable.
const serialised = `${JSON.stringify(document, null, 2)}\n`;

if (process.argv.includes('--check')) {
  const current = existsSync(target) ? readFileSync(target, 'utf8') : '';
  if (current !== serialised) {
    process.stderr.write(
      `  ! ${target} is out of date; run pnpm exec tsx scripts/generate-canonicalization-vectors.ts\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`  = ${target} (${vectors.length} vectors)\n`);
} else {
  writeFileSync(target, serialised);
  process.stdout.write(`  + ${target} (${vectors.length} vectors)\n`);
}
