import { randomBytes } from 'node:crypto';

/**
 * Prefixed, lexicographically sortable identifiers.
 *
 * Format: `<prefix>_<26-char Crockford base32 ULID>`. The time component makes
 * ids sort by creation order (useful for evidence chains and cursor paging);
 * the prefix makes every id in a log line, receipt or trace self-describing.
 */
export const ID_PREFIXES = {
  organization: 'org',
  user: 'user',
  agent: 'agent',
  credential: 'cred',
  resource: 'res',
  policy: 'pol',
  policyVersion: 'polv',
  policyReview: 'polr',
  lease: 'lease',
  delegation: 'dlg',
  signal: 'sig',
  authorizationRequest: 'areq',
  decision: 'dec',
  approvalRequest: 'apr',
  approval: 'apv',
  execution: 'exec',
  receipt: 'rcpt',
} as const;

export type IdKind = keyof typeof ID_PREFIXES;
export type Id<K extends IdKind> = `${(typeof ID_PREFIXES)[K]}_${string}`;

const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32
const TIME_LEN = 10;
const RANDOM_LEN = 16;

let lastTime = -1;
let lastRandom: number[] = [];

function encodeTime(now: number): string {
  let out = '';
  let t = now;
  for (let i = TIME_LEN - 1; i >= 0; i--) {
    out = ENCODING[t % 32]! + out;
    t = Math.floor(t / 32);
  }
  return out;
}

function freshRandom(): number[] {
  const bytes = randomBytes(RANDOM_LEN);
  return Array.from(bytes, (b) => b % 32);
}

/** Increments the random component so ids minted in the same millisecond still sort. */
function bumpRandom(prev: number[]): number[] {
  const next = [...prev];
  for (let i = next.length - 1; i >= 0; i--) {
    if (next[i]! < 31) {
      next[i] = next[i]! + 1;
      return next;
    }
    next[i] = 0;
  }
  return freshRandom(); // overflow after 32^16 ids in one millisecond
}

/** Monotonic ULID. Not exported as an id on its own -- always carries a prefix. */
export function ulid(now = Date.now()): string {
  if (now === lastTime) {
    lastRandom = bumpRandom(lastRandom);
  } else {
    lastTime = now;
    lastRandom = freshRandom();
  }
  return encodeTime(now) + lastRandom.map((v) => ENCODING[v]!).join('');
}

export function newId<K extends IdKind>(kind: K, now = Date.now()): Id<K> {
  return `${ID_PREFIXES[kind]}_${ulid(now)}` as Id<K>;
}

const ID_PATTERN = /^[a-z]+_[0-9A-HJKMNP-TV-Z]{26}$/;

export function isId<K extends IdKind>(kind: K, value: unknown): value is Id<K> {
  return (
    typeof value === 'string' && value.startsWith(`${ID_PREFIXES[kind]}_`) && ID_PATTERN.test(value)
  );
}

/** Extracts the creation timestamp encoded in a prefixed id. */
export function idTimestamp(id: string): number | null {
  const body = id.slice(id.indexOf('_') + 1);
  if (body.length !== TIME_LEN + RANDOM_LEN) return null;
  let t = 0;
  for (const ch of body.slice(0, TIME_LEN)) {
    const v = ENCODING.indexOf(ch);
    if (v < 0) return null;
    t = t * 32 + v;
  }
  return t;
}
