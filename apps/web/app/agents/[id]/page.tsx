import Link from 'next/link';
import { api, type AgentDetail } from '@/lib/api';
import { Card, Decision, Empty, Field, Mono, Relative, Status } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function AgentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const detail = await api<AgentDetail>(`/v1/agents/${encodeURIComponent(id)}`);
  const { agent } = detail;

  return (
    <div className="space-y-6">
      <div>
        <Link href="/" className="text-xs text-slate-500 underline underline-offset-4">
          ← Authority overview
        </Link>
        <h1 className="mt-2 font-mono text-xl font-semibold tracking-tight">{agent.handle}</h1>
        <p className="mt-1 text-sm text-slate-600">{agent.display_name}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Identity">
          <dl>
            <Field label="Agent id">
              <Mono>{agent.id}</Mono>
            </Field>
            <Field label="Status">
              <Status value={agent.status} />
            </Field>
            <Field label="Accountable human">
              {/* A machine principal always has an owner. That is what makes an
                  action attributable to someone who can answer for it. */}
              <Mono>{agent.owner_user_id ?? 'unowned'}</Mono>
            </Field>
            <Field label="Registered">
              <Relative iso={agent.created_at} />
            </Field>
          </dl>
          {agent.description ? (
            <p className="mt-3 border-t border-slate-100 pt-3 text-sm text-slate-600">
              {agent.description}
            </p>
          ) : null}
        </Card>

        <div className="lg:col-span-2">
          <Card
            title="Authority held"
            description="Every lease, live or lapsed. Authority is what this agent may do; the policy decides how much of it runs unattended."
          >
            {detail.authority_leases.length === 0 ? (
              <Empty>This agent holds no authority.</Empty>
            ) : (
              <ul className="divide-y divide-slate-100">
                {detail.authority_leases.map((lease) => (
                  <li key={lease.id} className="py-3">
                    <div className="flex items-baseline justify-between gap-3">
                      <Mono>{lease.id}</Mono>
                      <Status value={lease.status} />
                    </div>
                    <p className="mt-1 font-mono text-xs text-slate-700">
                      {lease.grant.actions.join(', ')}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {Object.entries(lease.grant.resources)
                        .map(([type, ids]) => `${type}: ${ids.join(', ')}`)
                        .join(' · ') || 'no resources'}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {lease.depth === 0 ? 'issued from policy' : `delegated, depth ${lease.depth}`}{' '}
                      &middot; expires <Relative iso={lease.expires_at} />
                      {lease.revocation_reason ? ` · revoked: ${lease.revocation_reason}` : ''}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card
          title="Delegations"
          description="Authority handed to or received from another agent. A child never exceeds its parent."
        >
          {detail.delegations.length === 0 ? (
            <Empty>No delegations.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {detail.delegations.map((delegation) => (
                <li key={delegation.id} className="py-3 text-sm">
                  <p>
                    <Mono href={`/agents/${delegation.issuer_agent_id}`}>
                      {delegation.issuer_agent_id}
                    </Mono>{' '}
                    <span aria-label="delegates to">→</span>{' '}
                    <Mono href={`/agents/${delegation.delegate_agent_id}`}>
                      {delegation.delegate_agent_id}
                    </Mono>
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    parent <Mono>{delegation.parent_lease_id}</Mono> &middot; child{' '}
                    <Mono>{delegation.child_lease_id}</Mono>
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {delegation.status} &middot; expires <Relative iso={delegation.expires_at} />
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Live signals about this agent">
          {detail.risk_signals.length === 0 ? (
            <Empty>No live signals.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {detail.risk_signals.map((signal) => (
                <li key={signal.id} className="py-2.5 text-sm">
                  <span className="font-mono font-medium">{signal.signal_type}</span> ={' '}
                  <span className="font-mono">{signal.value}</span>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {signal.source} &middot; confidence {signal.confidence} &middot; expires{' '}
                    <Relative iso={signal.expires_at} />
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Recent decisions">
        {detail.recent_decisions.length === 0 ? (
          <Empty>No decisions yet.</Empty>
        ) : (
          <ul className="divide-y divide-slate-100">
            {detail.recent_decisions.map((decision) => (
              <li key={decision.id} className="flex items-center justify-between gap-4 py-2.5">
                <Link
                  href={`/decisions/${decision.id}`}
                  className="min-w-0 text-sm underline decoration-slate-300 underline-offset-4 hover:decoration-slate-600"
                >
                  <span className="font-mono">{decision.action}</span>{' '}
                  <span className="font-mono text-slate-500">
                    {decision.resource_type}:{decision.resource_id}
                  </span>
                  <span className="ml-2 text-xs text-slate-500">{decision.reason_code}</span>
                </Link>
                <span className="shrink-0">
                  <Decision value={decision.decision} />
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
