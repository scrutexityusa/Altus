# ADR-0010 — Money is integer minor units; floats are refused

**Status** Accepted · 2026-08-21

## Problem

An authorization threshold decides whether a wire leaves the building. IEEE 754
cannot represent `0.1` exactly, and JSON has one numeric type.

## Decision

`Money = { currency, amountMinor }` where `amountMinor` is a decimal **string**
holding integer minor units. Comparisons are `bigint` comparisons. Parsing is
exact, from a decimal string, using the ISO 4217 exponent for the currency.

Four refusals, each deliberate:

- A **fractional JSON number** is refused at the API boundary, not coerced. A
  caller sending `0.1 + 0.2` gets `INVALID_REQUEST`, not a threshold comparison
  against `0.30000000000000004`.
- **Excess precision** is refused: `1.005 USD` and `1.5 JPY` are errors, not
  silent rounding.
- **Cross-currency comparison raises.** Scrutexity holds no exchange rates, and
  inventing one would silently move an authorization threshold.
- **Canonical JSON rejects non-integer numbers entirely**, so a float cannot
  enter a hashed evidence record by any route.

Risk signal values get the same treatment one level down: canonical decimal
strings compared digit by digit, so a `fraud_risk >= 0.9` threshold behaves
identically whichever side of the wire the value arrived from.

## Consequences

Policy authors write `{ amount: "50000", currency: USD }` rather than `50000`.
More verbose, and unambiguous — which is the trade to make when a human review
of that threshold is itself a security control.

A lease is denominated in one currency and refuses requests in another. Correct
and fail-closed; a multi-currency treasury needs one lease per currency today.
Per-currency ceilings are the natural fix and are tracked in
`docs/domain-model.md`.
