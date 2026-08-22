# ADR-0012 — The root-cause trace, and the graph underneath it

**Status** Accepted · 2026-08-21

## Problem

`GET /v1/authorization-decisions/{id}` answers "why was this allowed": which
policy matched, which authority applied, which signals were read. That is the
right answer to that question.

It does not answer the question behind it. When a payment goes wrong, the
investigation is not "which rule fired" — it is _how did this agent come to
have this authority at all, and who set that in motion_. That answer is spread
across five tables, and reconstructing it by hand is exactly the kind of work
that gets done inconsistently under pressure.

## Decision

`GET /v1/trace/{decision_id}` walks the relationships backwards from a decision
to its origin and returns the chain as an ordered array of typed nodes.

Four properties, each a deliberate choice:

**Causal order, oldest cause first.** Reverse-chronological is easier to
produce and much harder to read. An investigator wants to start at "the CFO
activated this policy version" and arrive at "so the wire was blocked". Each
node carries `causal_parent_id` and a `causal_link_type` from a closed
vocabulary, so the edges are machine-readable and not merely implied by
position.

**A root cause, named.** The first node is the policy _activation_ — not the
policy version. A version that was never activated could not have admitted any
authority, so the activation is the true origin. `complete: false` says plainly
when the chain stops short of one rather than pretending otherwise.

**Timestamps on every node.** Causal order and chronological order usually
agree, and where they do not, that gap is itself the finding.

**A database traversal, nothing more.** Recursive CTEs over the ancestry that
`authority_leases.parent_lease_id` and `delegations` already encode. Nothing is
summarised, inferred or generated; the same decision always produces the same
trace. A trace that varied between two reads would be unusable as evidence,
which is the only reason to build it.

## The graph model

The data model has been a graph since the first migration; the trace exposes it
rather than adding it.

```
policy_versions --activated--> authority_leases --parent_lease_id--> (itself)
                                     ^                                   |
                                     |                              delegations
      authorization_requests --------+                                   |
              |                                                          v
              +--> authorization_decisions --supersedes--> (itself)   agents
                            |         |
                     risk_signals   approvals --> execution_attempts
```

The indexes that make the walk cheap were in `0001_init.sql` before there was
anything to walk: `delegations (issuer_agent_id, delegate_agent_id)` and its
reverse, `(parent_lease_id, child_lease_id)`, and `authority_leases
(parent_lease_id)`. Both directions were indexed from the start because "who
did this agent delegate to" and "who delegated to this agent" are both
questions the authority graph has to answer.

## What this is not

It is not a graph visualisation, and building one is explicitly out of scope.
The linear explanation ships first because an ordered list is what an
investigator reads, and because a picture of a five-node chain communicates
less than the five sentences do.

It is also not a summarisation surface. There is no natural-language rendering
of a trace and none is planned: the deterministic explanation compiler already
renders individual decisions, and a "summary of the causal chain" would be the
one place in the product where evidence stopped being reproducible.

## Revisit when

Traces routinely exceed what fits on a screen — deep delegation chains, or many
signals. Pagination and a node-type filter are the answer, not summarisation.
