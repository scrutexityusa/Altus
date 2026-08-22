# The ideal first design partner

**Status:** Working document. Revised after every discovery call.

The purpose of the first design partner is not revenue. It is evidence that a
security-minded team outside this codebase can understand the authority model,
run the demo, and define a pilot without the founding team in the room.

That goal rules out two tempting profiles at once. A partner too small has no
high-consequence workflow, so nothing about Altus is load-bearing and the pilot
proves nothing. A partner too large takes nine months to approve a sandbox, and
by then the product has been shaped by a procurement process rather than by a
treasury team.

## Company size and stage

**Target: 200–2,000 employees. Series C through pre-IPO, or an established
private company.**

| Signal                                      | Why it matters                                                                                  |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| A named Treasury or Payment Ops team        | Below roughly 200 people, treasury is a part-time finance responsibility and there is no owner. |
| A security function that reviews vendors    | The pilot's value is the review. Without one, nobody scrutinises the model.                     |
| Fewer than ~5 people in a purchase decision | More than that and the cycle outruns the pilot.                                                 |
| No formal RFP process yet                   | An RFP means the buyer already believes they know the category. They do not; nor do we.         |

**Deliberately not targeted first:** tier-1 banks, systemically important
institutions, and anyone whose vendor onboarding starts with a 300-question
security questionnaire. They are the eventual market. They are the wrong first
partner, because the feedback loop is measured in quarters.

## Treasury and payment workflow maturity

The partner must already run **outbound payments with a real approval ladder**.
Not aspirationally — today, with thresholds someone can recite.

**Required:**

- Outbound wires, ACH, or vendor payouts, initiated at least weekly.
- At least one amount threshold above which a human must approve. If everything
  is approved by a human, or nothing is, there is no authority boundary to model.
- A payment provider with an API and an idempotency-key contract (Modern
  Treasury, Increase, Column, JPM Access, Goldman TxB, or an internal service
  fronting a bank).
- Someone who can name the current control and say why it exists.

**Strong signal:** they have already written a bespoke approval service and are
unhappy with it. That means they have hit the problem and know it is not a
workflow problem.

**Disqualifying:** payments are made by a human in a bank portal. There is no
integration seam, and the honest answer is that Altus has nothing to offer yet.

## Existing agent usage

The best partner is at the point of maximum discomfort: **an agent works, and
they are not willing to let it move money.**

| Stage                                             | Fit      | Why                                                                      |
| ------------------------------------------------- | -------- | ------------------------------------------------------------------------ |
| No agents, no plans                               | No       | Nothing to govern. The conversation is theoretical.                      |
| Agents doing read-only reconciliation or drafting | **Best** | The workflow is proven, the blocker is authority, and the risk is real.  |
| An agent already initiating payments, ungoverned  | **Good** | Urgent, but the sale is now remediation. Expect a shorter, tenser pilot. |
| A large in-house agent platform team              | Careful  | They will want to build it. That is a real outcome — see below.          |

An organisation that will build it themselves is not a failed partner. They are
the best possible reviewer of the model, and the four laws are worth more
scrutinised than sold. Treat that conversation as a design review that happens
to have a budget attached.

## Regulatory exposure

Some regulatory pressure is necessary — it is what makes evidence a requirement
rather than a nice-to-have. Too much and the pilot becomes a compliance project.

**Best fit:**

- **SOC 2 Type II** — held or in progress. Establishes that evidence and access
  review are already vocabulary in the building.
- **EU AI Act** — in scope as a deployer of a high-risk or general-purpose AI
  system. Articles on human oversight and record-keeping map directly onto
  escalation and the receipt chain. Useful because the obligation is real and the
  implementation is genuinely unsettled.
- **PCI-DSS** or **NYDFS Part 500** — a security function that already thinks in
  terms of least privilege and key custody.

**Careful:** an institution under direct prudential supervision (OCC, PRA, ECB
SSM). Model risk management review is a legitimate process and a slow one.

**Honest limitation to state on the first call:** Altus is not a compliance
product, has no certification of its own, and does not map controls to a
framework for you. It produces cryptographically tamper-evident and
independently verifiable evidence that a control was enforced. Whether that
evidence satisfies a given obligation is the partner's counsel's call, not ours.

## Security and compliance team involvement

**Non-negotiable: security is in the room from the first technical call.**

This is unusual and it is deliberate. Altus's central claim is a security claim,
and a pilot that reaches a security review only in week four will fail it — not
because the model is wrong, but because nobody had a chance to argue with it.

What the security team should get on day one:

- `docs/design-partner/security-brief.md` — under five minutes to read.
- `docs/design-partner/red-team-handoff.md` — the threat model, the residual
  risks, and the one question we want an independent reviewer to answer.
- The repository, and `make adversarial` and `make recovery` to run themselves.

If the security team declines to engage, that is disqualifying. The product's
value is proportional to how hard someone tries to break it.

## Technical integration capability

**Required:**

- Can run a container against a PostgreSQL 16 instance they control.
- Can issue an outbound HTTPS call from their agent runtime to a service they
  host.
- Can author a YAML policy file and put it through code review.
- Have, or can obtain, a KMS: AWS KMS, GCP KMS, Azure Key Vault, or HashiCorp
  Vault.

**Deployment posture:** self-hosted in the partner's own account, single region,
one Postgres. Altus is a control plane for a partner's own money movement; it
should not be a SaaS holding the authority to move it. There is no hosted
offering to sell, which shortens the security conversation considerably.

**Not required:** Kubernetes, a service mesh, a specific cloud, or a specific
payment provider.

**The one prerequisite to state plainly up front:** production requires
`SECRET_PROVIDER=kms`, and no specific key manager is wired yet. The interface
exists and the deployment refuses to start without it, precisely so that nobody
reaches production on local key custody by accident. Wiring the partner's chosen
manager is a scoped piece of week-one work, done against their key manager
rather than guessed at in advance. See `integration-runbook.md`.

## Decision-maker and economic buyer personas

| Persona                       | Role in the deal        | What they actually care about                                                                                         |
| ----------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **VP/Head of Treasury**       | Economic buyer          | Not being the person who signed off on the agent that wired $2m to the wrong counterparty. Wants a defensible ladder. |
| **Head of AI Platform / Eng** | Champion, usually first | Is blocked. Has a working agent nobody will let near production. Wants to ship without owning the risk personally.    |
| **CISO / Head of Security**   | Veto holder             | Whether the authority model is sound and whether the evidence would survive an incident review.                       |
| **Controller / VP Finance**   | Influencer              | Audit trail, segregation of duties, and what the external auditor will say.                                           |
| **CFO**                       | Signs above a threshold | One paragraph and one theorem. Rarely in the technical calls.                                                         |

**The pattern to expect:** the AI Platform lead finds Altus, Treasury owns the
budget, and Security decides whether it happens. Optimise the first call for the
champion and the first review for the veto holder — they are different documents,
which is why there are two.

## What would make us decline a partner

Stated so it is a decision rather than a drift:

- No high-consequence workflow. Governing something inconsequential proves nothing.
- Security will not engage before contract.
- They want a hosted service that holds their payment authority.
- They want the action catalog broadened to their entire API surface in week one.
  The closed catalog is a control, not a limitation to negotiate away.
- They want Altus to detect fraud. It consumes assertions from systems that do;
  it does not make them.

## The one-line filter

> A team with an agent that works, a payment ladder that matters, a security
> function that will argue with us, and fewer than five people who have to say
> yes.
