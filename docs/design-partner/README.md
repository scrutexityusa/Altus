# Design partner package

Everything a treasury team and their security function need to understand, pilot,
and decide on Altus — without the founding team in the room. That is the bar these
documents are written to.

## Read in this order

| Audience              | Document                                                                                                  | Time   |
| --------------------- | --------------------------------------------------------------------------------------------------------- | ------ |
| Everyone              | [`security-brief.md`](security-brief.md) — what it is, what it guarantees, what it does not               | 5 min  |
| Us, internally        | [`ideal-partner-profile.md`](ideal-partner-profile.md) — who this is for, and who it is not               | 10 min |
| Anyone, live          | [`demo-script.md`](demo-script.md) — `make demo`, scene by scene                                          | 10 min |
| Engineering           | [`onboarding.md`](onboarding.md) — empty database to one governed execution                               | 30 min |
| Anyone                | [`cold-room-transcript.md`](cold-room-transcript.md) — a recorded run of it from a fresh clone            | 3 min  |
| Engineering           | [`api-quickstart.md`](api-quickstart.md) — working curl for the whole surface                             | 30 min |
| Treasury              | [`policy-pack-treasury.md`](policy-pack-treasury.md) — the tier ladder and why each rule exists           | 20 min |
| Engineering           | [`integration-runbook.md`](integration-runbook.md) — provider and KMS seams, reconciliation, monitoring   | 45 min |
| Security              | [`red-team-handoff.md`](red-team-handoff.md) — threat model, coverage, residual risk, the review question | 45 min |
| All                   | [`pilot-plan.md`](pilot-plan.md) — four weeks and six success criteria                                    | 15 min |
| Anyone, first contact | [`outreach/authority-model.md`](outreach/authority-model.md) — the technical thesis in one image          | 2 min  |
| Us, internally        | [`outreach/`](outreach/) — cold emails, one-pager, discovery questions                                    | —      |

## The three commands

```bash
make demo         # the treasury story, asserted end to end
make adversarial  # 11 security invariants, mounted as real attacks
make recovery     # SIGKILL the API mid-payment; assert what survived
```

Give an engineer the repository and these three commands and they can form their
own opinion. That is the intent — the system's own proof is the pitch.

## Honest state, in one place

- **621 tests**, 12/12 adversarial invariants, 3/3 recovery scenarios.
- **[stranger-test.md](stranger-test.md)** — the one claim automation cannot make, and the protocol for making it.
- **Production key custody is implemented and has never been exercised.**
  `SECRET_PROVIDER=agent` takes the signing key from a tmpfs written by your own
  secrets agent — CSI driver, External Secrets Operator, Vault Agent — so Altus
  holds no cloud credential and links no cloud SDK
  ([key-management.md](../key-management.md)). It is unit-tested, including that
  it refuses a persistent mount and a world-readable key. **No deployment has
  run in a production posture**, so day one is your `SecretProviderClass` and
  two environment variables ([runbook §2](integration-runbook.md)).
- **No egress detection, no workload-bound identity, no rate limiting.** All in
  the gap register with a status.
- Every known gap: [`../security-surface-map.md`](../security-surface-map.md).

## Working rule

If a partner asks for something not built, write it down and do not build it that
week. Three partners asking is a roadmap; one asking is a conversation. A
**finding** — something unsound or unenforced — is not a feature request, and gets
fixed immediately.
