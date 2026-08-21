# ADR-0004 — Prefixed, time-sortable TEXT primary keys

**Status** Accepted · 2026-08-21

## Problem

Ids appear in receipts, decision records, log lines, traces, support tickets
and customer integrations. A bare UUID in an incident channel tells nobody what
kind of thing it names.

## Options

**A — UUID primary keys.** Compact, conventional. Opaque; random UUIDv4s
fragment index locality.

**B — UUID internally with a prefixed public id.** Readable, but every entity
now has two identities and every lookup must decide which.

**C — Prefixed ULID as the TEXT primary key.** `lease_01JBX7Q8N2K3M4P5R6S7T8V9W0`.

## Decision

**C.** One identity per row. The prefix makes every id self-describing; the
ULID time component sorts by creation, which the evidence chain and cursor
paging both want. Format is enforced by a `CHECK` constraint, so a malformed id
cannot be written.

Cost: ~31 bytes versus 16 per key. Accepted — decision volume is bounded by
human-consequential actions, not by telemetry.

The generator is monotonic within a millisecond, tested with 500 ids minted at
one timestamp remaining strictly ordered and unique.

## Revisit when

Row counts reach a scale where index size measurably affects decision latency.
Measure before changing: `evaluation_duration_us` is on every decision row.
