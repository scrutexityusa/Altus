# The first call

Thirty minutes. The goal is to find out whether there is a real workflow, not to
explain the product. If you are talking more than half the time, the call has
gone wrong.

## Five discovery questions

**1. Walk me through a payment that goes out today. Who touches it, and where does
a human have to say yes?**

Establishes whether an approval ladder exists at all. Listen for a _number_ — "over
fifty thousand it goes to Priya". A team that cannot name a threshold does not
have a control to encode, and Altus has nothing to bound.

_Bad answer:_ "It depends." _Good answer:_ a specific matrix, possibly one they
are embarrassed by.

**2. What is your agent doing today, and what is the first thing you would let it
do that costs money if it were wrong?**

Separates read-only from consequential, and gets a concrete first workflow rather
than "payments" in the abstract. The answer is the pilot's week-3 transaction.

_Listen for:_ whether they have already tried and stopped. Why they stopped is the
most useful sentence in the call.

**3. If that agent did something wrong at 2am on a Saturday, what would the
investigation look like? What would you actually be able to pull?**

Reveals whether evidence is a real requirement or a hypothetical one. Also reveals
who owns the incident — often a different person than the one on the call.

_Listen for:_ "we'd grep the logs". That is an opening, not a failure.

**4. Who has to say yes for this to reach production, and has anyone told them
about it yet?**

Gets the veto holder named early. If security has not been told, the champion is
optimistic about their own organisation and the pilot will stall in week 4.

_Follow-up:_ "would they take thirty minutes to try to break the model?" A yes here
is the strongest qualification signal available.

**5. What would have to be true, technically, for you to let this move one real
low-value payment in four weeks?**

Converts interest into a checklist and surfaces the blocker you have not thought
of — a key manager, a change board, a vendor review, a bank contract clause.

_This is the qualifying question._ If they cannot answer it, there is no pilot yet,
and the right next step is a smaller one.

## What we are not

Say these before they ask. Every one has been mistaken for a claim we make.

| Not                                             | Because                                                                                                                                               |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Not a fraud detection system**                | We consume signed assertions from systems that do. We change nothing about detection quality.                                                         |
| **Not an agent framework**                      | Bring LangGraph, CrewAI, or your own loop. We do not care what is on the other side of the API.                                                       |
| **Not a workflow or approvals product**         | We enforce an approval requirement. We do not route work, chase people, or replace your queue.                                                        |
| **Not a compliance product**                    | No certification of our own, no control-framework mapping. We produce verifiable evidence; whether it satisfies an obligation is your counsel's call. |
| **Not an observability tool**                   | We produce evidence about authority, not telemetry about behaviour.                                                                                   |
| **Not a hosted service**                        | Self-hosted in your account. We should not hold the authority to move your money.                                                                     |
| **Not a guarantee your agent is safe**          | We bound the consequences of an unsafe one. Those are different products, and only one of them is buildable.                                          |
| **Not a substitute for removing side channels** | If the agent also holds bank credentials directly, we are not in the path — and there is no egress detection to catch it.                             |

## Ending the call

Do not ask for a next meeting. Offer the artifact that fits who was on the call:

- **Engineering-heavy** → the repository, and `make adversarial` / `make recovery`
- **Treasury-heavy** → `security-brief.md` and a ten-minute `make demo`
- **Security in the room** → `red-team-handoff.md` and the review question

Then: _"read it, try to break it, and tell me what is wrong with it."_ A partner
who comes back with a finding is worth more than one who comes back impressed.

## If they ask for something we have not built

Write it down verbatim, including who asked and what they were trying to do. Then
say:

> "We have not built that. Tell me more about what you would use it for."

Do not commit, do not estimate, and do not build it that week. Three partners
asking for the same thing is a roadmap. One partner asking is a conversation, and
building for it immediately is how a control plane turns into a pile of features
with no theorem underneath.

The exception: a **finding** — something that is broken or unsound — is not a
feature request. Fix that immediately.
