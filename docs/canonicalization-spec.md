# Canonicalization specification

This document defines the byte-exact rules for turning a value into the string
that gets hashed. It is a specification rather than a description: a second
implementation, in any language, must produce identical bytes for every value,
and `test/canonicalization-vectors.json` is the conformance suite that decides
whether it does.

The reference implementation is `packages/core/src/canonical.ts`. Where this
document and that file disagree, the file is wrong and should be fixed.

## Why this is a security document

Three separate controls compare hashes computed at different times, by
different components, over facts that travelled through a database in between:

| Hash                | Computed when           | Compared against                         |
| ------------------- | ----------------------- | ---------------------------------------- |
| `request_hash`      | The request is accepted | Itself, on idempotent replay             |
| `exact_intent_hash` | An ALLOW is issued      | The operation reconstructed at execution |
| `binding_hash`      | An ALLOW is issued      | The binding reconstructed at execution   |
| receipt `hash`      | Evidence is appended    | Any later independent verification       |

If two honest implementations can disagree about the bytes for one operation,
every one of those comparisons fails open or fails noisily for the wrong
reason. That is why the rules below are stated as absolutes and why changing
any of them changes the wire format of every hash the system has ever issued.

## Rules

The output is a JSON-like string in the spirit of RFC 8785 (JCS), with two
deliberate departures noted below.

### 1. Object keys are sorted

Keys are normalised (rule 5), then sorted ascending by UTF-16 code unit, then
emitted. Sorting happens on the normalised form so that the emitted sequence is
in the order it was sorted by.

Uppercase sorts before lowercase (`"A"` < `"a"`). Digit keys sort as text, so
`"10"` sorts before `"9"`.

### 2. Absent and null are different at the raw level

- A property whose value is `undefined` (or, in another language, whose key is
  simply not present) is **omitted**.
- A property whose value is explicitly `null` is **kept**, as `null`.

`{"a":1,"b":undefined}` and `{"a":1}` hash identically. `{"a":null}` and `{}`
do **not**.

Note that `canonicalOperation` (rule 9) collapses this distinction for
operation parameters on purpose. That is a rule of the projection, not of the
canonicaliser.

### 3. Numbers are integers or nothing

- Non-integer numbers are **rejected**. Money is a `Money` record of integer
  minor units; risk values are decimal strings.
- Non-finite numbers (`NaN`, `±Infinity`) are **rejected**.
- Integers outside the safe range (|n| > 2^53 − 1) are **rejected**; use a
  decimal string.
- A big integer type, where the language has one, is serialised as its decimal
  **string**: `12345678901234567890n` → `"12345678901234567890"`.

The rejection of floats is the single most important rule here. A threshold of
$50,000 that a value of `50000.000000000001` slips past is not an audit trail,
it is an anecdote.

### 4. Arrays preserve position

Array order is significant and is never sorted. A hole or an unserialisable
element becomes `null` so that positions never shift.

`[1, <hole>, 3]` → `[1,null,3]`.

### 5. Strings are normalised to Unicode NFC

Both keys and values. This is the first departure from JCS, which deliberately
leaves strings alone.

The reason is that this hash is a security control, not an interchange format.
`"José"` and `"José"` render identically on a treasurer's screen, in
a confirmation email and on a bank statement. Without normalisation they hash
differently, which means an operation could be approved under one spelling and
executed under the other.

**NFKC is not used, and must not be.** NFKC is lossy by design: it folds U+2460
CIRCLED DIGIT ONE to `"1"` and full-width forms to ASCII, so two genuinely
different account references could collide into one hash. A control that merges
distinct operations is worse than no control at all. NFC only composes
sequences that are already canonically equivalent.

NFC is the identity function on ASCII, so an ASCII-only corpus is unaffected.

### 6. Keys that collide after normalisation are rejected

If two keys in one object normalise to the same string, canonicalisation fails
with an error. This is the second departure from JCS, and it exists because the
alternative is worse: which value wins would depend on insertion order, and a
canonical form that depends on insertion order is not canonical.

### 7. Dates are ISO-8601 UTC with millisecond precision

`2026-01-01T00:00:00.000Z`. An invalid date is rejected rather than emitted as
a string that reads valid.

### 8. Everything else is rejected

Functions, symbols, class instances that are not `Date`. There is no
`toJSON()` escape hatch: a value that needs custom serialisation to be hashed
is a value whose hash nobody can independently reproduce.

### 9. Operations are projected onto the action catalog

`canonicalOperation()` is a layer above the canonicaliser and has its own
rules, because an operation is not an arbitrary object.

```
CanonicalOperation {
  operation_type: string     // the catalog action, e.g. "wire.execute"
  resource_type:  string
  resource_id:    string
  parameters:     { ...catalog-declared context fields that are present }
}
```

- **Parameters are a projection, not a copy.** Only fields the action's catalog
  entry declares in `context_fields` appear. A field the catalog does not
  declare cannot reach the external system, so it must not affect the intent —
  and a projection is the only way to guarantee that without trusting the
  sender to omit it.
- **Absent and null collapse.** Inside an operation, "the field is null" and
  "the field is not there" are the same fact and hash the same. This differs
  from rule 2 on purpose.
- **Required fields must be present.** An action's `required_context` fields
  are mandatory; canonicalisation of an operation missing one fails.
- **Nulls inside a parameter array are rejected.** Position is meaningful
  there, so a null can neither be dropped (positions shift) nor kept (it would
  need null in the value union, which then has to be distinguished from absent
  everywhere else). No catalog action needs a sparse list.

## The two hashes

They answer different questions and are deliberately not merged.

```
exact_intent_hash = SHA256(canonical(CanonicalOperation))
```

Answers **"did the operation mutate?"** Covers the operation and nothing else,
so it is stable across policy versions, leases and approvals.

```
binding_hash = SHA256(canonical({
  authorized_intent:      CanonicalOperation,
  authorization_context:  { decision_id, authority_lease_id,
                            policy_version_id, policy_hash,
                            approved_context_hash },
  grant_id, expires_at, nonce
}))
```

Answers **"is this operation bound to _this_ authority decision?"**

An attacker replaying a genuine, unmutated operation under a different decision
passes the first check and fails the second. An attacker mutating an amount
under the correct decision fails both.

`approved_context_hash` lives in the binding rather than in the intent hash on
purpose. A treasurer approves a specific operation under a specific risk
picture; binding both means an execution presented against a _different_
approval fails, even though the operation itself is untouched. Folding it into
the intent hash would have made a changed risk picture read as a mutated wire,
which is the wrong thing to put in front of an operator at 3am.

The `nonce` is what stops two legitimately identical operations — the same
agent paying the same supplier the same amount twice in one day — from
producing interchangeable bindings.

## Conformance

`test/canonicalization-vectors.json` holds 73 vectors, generated by
`scripts/generate-canonicalization-vectors.ts` and verified by
`packages/core/test/operation.test.ts`. Each vector is either

```json
{ "name": "...", "value": <any JSON>, "canonical": "...", "sha256": "..." }
```

or, for inputs that must be refused,

```json
{ "name": "...", "value": <any JSON>, "error": true }
```

A second implementation passes conformance when, for every vector, it produces
the recorded `canonical` string and `sha256` digest, and rejects every vector
marked `error`.

**What the file cannot carry.** JSON has no way to write `undefined`, a big
integer, an array hole, `NaN`, `Infinity`, or a date that is not already a
string. Round-tripping those through the file turns them into `null` and the
vector silently stops testing anything. Their rules are pinned by TypeScript
tests in `packages/core/test/operation.test.ts` instead, and a second
implementation needs its own equivalents.

Regenerating the file changes the hashes of everything the system has issued.
`scripts/generate-canonicalization-vectors.ts --check` fails CI when the file
drifts from the implementation, so that change cannot be made silently.

## Non-guarantees

- **This is not a canonical JSON parser.** It serialises in-memory values. Two
  different JSON documents that parse to the same value hash the same, which is
  the intent; a document that does not parse is not this function's problem.
- **NFC does not defeat homoglyphs.** `"paypal"` with a Cyrillic `а` is a
  different string from `"paypal"` and hashes differently, correctly. Detecting
  that a human would confuse them is a different control and is not attempted
  here.
- **A matching hash proves the operation did not change.** It does not prove
  the operation was a good idea, that the counterparty is legitimate, or that
  the external system did what it was told.
