import Link from 'next/link';
import { api, type DecisionDetail } from '@/lib/api';
import { Card, Decision, Field, Mono, Relative } from '@/components/ui';

export const dynamic = 'force-dynamic';

/**
 * The why-was-I-allowed screen.
 *
 * It renders GET /v1/authorization-decisions/{id} and nothing else. The five
 * facts are shown separately, exactly as the explanation compiler produces
 * them, because "what policy required" and "what authority existed" are
 * different questions with different owners and collapsing them is how
 * post-incident reviews go wrong.
 */
export default async function DecisionPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const detail = await api<DecisionDetail>(`/v1/authorization-decisions/${encodeURIComponent(id)}`);
  const { decision, request, explanation, evaluation } = {
    ...detail,
    evaluation: detail.decision.evaluation,
  };

  const factOrder: Array<[string, string]> = [
    ['What happened', explanation.facts.what],
    ['What authority existed', explanation.facts.authority],
    ['What policy required', explanation.facts.policy],
    ['What signals influenced the decision', explanation.facts.signals],
    ['What approvals were involved', explanation.facts.approvals],
    ['Why this result', explanation.facts.why],
  ];

  return (
    <div className="space-y-6">
      <div>
        <Link href="/" className="text-xs text-slate-500 underline underline-offset-4">
          ← Authority overview
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold tracking-tight">{explanation.headline}</h1>
          <Decision value={decision.decision} />
          <code className="font-mono text-xs text-slate-500">{decision.reason_code}</code>
        </div>
        <p className="mt-1 text-sm text-slate-600">
          <span className="font-mono">{request.action}</span> on{' '}
          <span className="font-mono">
            {request.resource.type}:{request.resource.id}
          </span>{' '}
          &middot; <Relative iso={decision.decision_timestamp} />
        </p>
      </div>

      <Card
        title="The decision, in the platform's own words"
        description="Assembled deterministically from the structured record. No model wrote this."
      >
        <dl className="divide-y divide-slate-100">
          {factOrder.map(([title, body]) => (
            <div key={title} className="py-3">
              <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                {title}
              </dt>
              <dd className="mt-1 text-sm leading-relaxed text-slate-800">{body}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Authorization chain">
          <dl>
            <Field label="Agent">
              <Mono>{explanation.facts.what.match(/Agent (\S+)/)?.[1] ?? '—'}</Mono>
            </Field>
            <Field label="Authority relied on">
              <Mono>{decision.authority_lease_id ?? 'none'}</Mono>
            </Field>
            <Field label="Policy">
              {decision.policy_version ? (
                <>
                  v{decision.policy_version}{' '}
                  <span className="font-mono text-xs text-slate-500">
                    {decision.policy_hash?.slice(0, 16)}…
                  </span>
                </>
              ) : (
                'unavailable'
              )}
            </Field>
            <Field label="Rules matched">
              {evaluation.policy_outcome?.matched_rule_ids.length ? (
                <span className="font-mono text-xs">
                  {evaluation.policy_outcome.matched_rule_ids.join(', ')}
                </span>
              ) : (
                'none — the policy default applied'
              )}
            </Field>
            <Field label="Failure mode in force">{decision.failover_behavior}</Field>
            {decision.supersedes_decision_id ? (
              <Field label="Supersedes">
                <Mono href={`/decisions/${decision.supersedes_decision_id}`}>
                  {decision.supersedes_decision_id}
                </Mono>
              </Field>
            ) : null}
            {decision.expires_at ? (
              <Field label="Execution grant expires">
                <Relative iso={decision.expires_at} />
              </Field>
            ) : null}
            {decision.evaluation_duration_us !== null ? (
              <Field label="Evaluated in">
                {(decision.evaluation_duration_us / 1000).toFixed(1)} ms
              </Field>
            ) : null}
          </dl>
        </Card>

        <Card
          title="Constraints evaluated"
          description="Each dimension of the held authority, checked against this request."
        >
          {decision.constraints_evaluated.length === 0 ? (
            <p className="py-4 text-sm text-slate-500">No constraint bound this request.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {decision.constraints_evaluated.map((check) => (
                <li key={check.constraint} className="flex items-start gap-3 py-2.5">
                  <span
                    aria-hidden
                    className={`mt-0.5 shrink-0 text-sm font-bold ${
                      !check.applicable
                        ? 'text-slate-400'
                        : check.satisfied
                          ? 'text-allow-fg'
                          : 'text-deny-fg'
                    }`}
                  >
                    {!check.applicable ? '–' : check.satisfied ? '✓' : '✗'}
                  </span>
                  <div className="min-w-0">
                    <p className="font-mono text-xs font-medium">
                      {check.constraint}
                      <span className="sr-only">
                        {!check.applicable
                          ? ' does not apply'
                          : check.satisfied
                            ? ' satisfied'
                            : ' violated'}
                      </span>
                    </p>
                    <p className="mt-0.5 text-xs text-slate-600">{check.message}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Human approvals">
          {detail.approvals.length === 0 ? (
            <p className="py-4 text-sm text-slate-500">
              {decision.approval_requirement
                ? `Awaiting ${decision.approval_requirement.quorum} approval from ${decision.approval_requirement.roles.join(' and ')}.`
                : 'No human approval was required.'}
            </p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {detail.approvals.map((approval) => (
                <li key={approval.id} className="py-3">
                  <p className="text-sm font-medium">
                    {approval.display_name}{' '}
                    <span className="font-normal text-slate-600">
                      {approval.vote === 'APPROVED' ? 'approved' : 'rejected'}
                    </span>
                    {approval.satisfied_role ? (
                      <span className="text-slate-600"> as {approval.satisfied_role}</span>
                    ) : null}
                  </p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {/* Roles as held at that instant, not as they stand now. */}
                    held {approval.roles_at_decision.join(', ')} at the time &middot;{' '}
                    <Relative iso={approval.created_at} />
                  </p>
                  {approval.comment ? (
                    <p className="mt-1 text-sm text-slate-700">&ldquo;{approval.comment}&rdquo;</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          title="Evidence"
          description="Hash-chained and signed. Attests to integrity and provenance — not to whether the decision was right."
        >
          <dl>
            <Field label="Receipt">
              <Mono>{detail.receipt?.id ?? 'none'}</Mono>
            </Field>
            {detail.receipt ? (
              <>
                <Field label="Chain position">#{detail.receipt.seq}</Field>
                <Field label="Hash">
                  <code className="break-all font-mono text-xs text-slate-600">
                    {detail.receipt.hash}
                  </code>
                </Field>
              </>
            ) : null}
            <Field label="Execution">
              {detail.execution
                ? `${detail.execution.status} · ${new Date(detail.execution.created_at).toISOString()}`
                : 'not executed'}
            </Field>
          </dl>
        </Card>
      </div>

      <Card title="Request context" description="Exactly what was asked, as recorded. Immutable.">
        <pre className="overflow-x-auto rounded bg-slate-900 px-4 py-3 font-mono text-xs leading-relaxed text-slate-100">
          {JSON.stringify(request.context, null, 2)}
        </pre>
      </Card>
    </div>
  );
}
