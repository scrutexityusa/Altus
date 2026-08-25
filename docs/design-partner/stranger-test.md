# The stranger test

**The one claim about this product that no automation can make.**

`make onboarding` proves the guide's _commands_ run: it executes the shell from
`onboarding.md` against a real server on a clean database, in CI, on every push.
It cannot tell you whether a person can follow the _prose_ — whether the order
makes sense, whether a step assumes something the reader was never told,
whether the explanation of why three humans are required lands or reads as
bureaucracy.

Two people have run this guide. Both wrote or watched the system being built.
Both times, the run "worked". The second run still missed a defect that made
step 2 produce a file `jq` refused to parse, because whoever ran it supplied the
missing state from memory rather than from the page — which is precisely the
bias the exercise exists to expose, and precisely what a familiar reader cannot
escape.

So this is not a test we can run. It needs somebody who does not know us.

## Who

One competent engineer who has **never seen this repository** and has not been
briefed on the authority model. Backend or platform, comfortable with Docker,
PostgreSQL and curl. A treasury or fintech background is a bonus and not a
requirement; if the guide only works for people who already understand payment
approval ladders, that is a finding.

Not a design partner. Spend a stranger on this before spending a prospect.

## What they receive

Exactly two things:

1. The repository URL.
2. `docs/design-partner/onboarding.md`.

Nothing else. No walkthrough, no architecture summary, no "you'll probably want
to…". If a document is required to make the guide followable, it is part of the
guide and belongs in it.

## The rules

**Do not help them.** This is the whole protocol and it is harder than it
sounds. Every rescue destroys the data point you are paying for: the moment you
answer a question, you have learned that the guide raises it and lost the
chance to learn what they would have done instead.

If they are blocked, they stop and write down what they were trying to do. A
run that halts at step 4 with a clear account of why is worth more than a run
that finishes because someone was watching over their shoulder.

**They hold the stopwatch, not us.** Wall-clock from clone to step 11,
including the time spent stuck.

## What to record

While running, in their own words:

- **Every hesitation.** Not just errors — the places they re-read a paragraph,
  or guessed. A guess that happens to be right is still a defect.
- **Every stop.** What they were trying to do, what they expected, what
  happened, what they tried next.
- **Every question they wanted to ask.** Especially the ones they answered
  themselves, and how.
- **Anything they had to find outside the guide** — a file, the README, a
  source file, a search engine.

Afterwards, five questions, before any discussion:

1. In one sentence, what does this system do?
2. **What exactly prevented that execution from exceeding its authority?**
3. **Why did the policy need two reviewers who did not write it?**
4. Who or what is stopped by it, and from doing what?
5. What would you have to change to point this at your own bank accounts?
6. What did you not trust?

Questions 1, 2 and 3 are the ones that can fail. A stranger who runs all eleven
steps cleanly and cannot answer them has produced an **onboarding success and a
comprehension failure**, which is the more expensive result and the easier one
to miss — the commands worked, so the run looks like a pass.

Answers to watch for on question 1: "it logs what agents do" or "it's an
approval workflow" means the positioning has failed regardless of how smoothly
it ran. On question 2, "the policy said no" is not the answer — the execution
in step 9 was _allowed_; what bounded it was a lease, a ceiling, and a hash
comparison at the boundary. If none of that surfaced, the guide showed them a
sequence rather than a mechanism.

## How to read the result

| Finding                                 | What it means                                  | Who fixes it                    |
| --------------------------------------- | ---------------------------------------------- | ------------------------------- |
| A command fails                         | A defect in the guide or the product           | us, immediately                 |
| They guessed and were right             | The guide is under-specified                   | us                              |
| They guessed and were wrong             | The guide is misleading — worse                | us, immediately                 |
| They looked something up                | A missing sentence, at the point they looked   | us                              |
| They finished and cannot answer Q1      | A positioning failure, not a documentation one | us, and it is the expensive one |
| They disagree with the three-human rule | A conversation, not a defect                   | nobody — record it              |

The last row matters. The three-human requirement, the role-versus-ceiling
distinction, the bootstrap ceremony, two non-author approvals, and the
counterparty registration rule are **deliberate** and have survived a cold read
already. If a stranger dislikes them, that is signal about how to explain them,
not permission to weaken them.

## Definition of done

A stranger, unaided, on a machine we have never touched, reaches step 11 —
`INTACT`, a complete causal trace, ceremony credential revoked — and can answer
question 1 in a sentence that names authority.

Until that has happened, the honest statement is: _the guide's commands are
verified in CI on every push; the guide's prose has been read cold twice by
people who already knew the system, and has never been followed by a stranger._

## After it runs

Write it up like `cold-room-transcript.md`, including whatever it got wrong —
and note that that transcript carries a correction at its head for exactly this
reason. Then fix what was found before the next person sees it.
