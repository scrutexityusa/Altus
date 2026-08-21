import Link from 'next/link';
import { api, type Overview } from '@/lib/api';
import { Card, Decision, Empty, Field, Mono, Relative, Status } from '@/components/ui';

export const dynamic = 'force-dynamic';

function formatConstraint(name: string, value: unknown): string {
  if (value && typeof value === 'object' && 'amountMinor' in (value as object)) {
    const money = value as { currency: string; amountMinor: string };
    const exponent = money.currency === 'JPY' ? 0 : 2;
    const digits = money.amountMinor.padStart(exponent + 1, '0');
    const whole = digits.slice(0, digits.length - exponent);
    const fraction = exponent ? `.${digits.slice(-exponent)}` : '';
    return `${name} ≤ ${whole}${fraction} ${money.currency}`;
  }
  if (Array.isArray(value)) return `${name}: ${value.join(', ')}`;
  return `${name}: ${String(value)}`;
}

export default async function Dashboard() {
  const overview = await api<Overview>('/v1/overview');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Authority overview</h1>
        <p className="mt-1 text-sm text-slate-600">
          Who holds what authority right now, what is waiting on a human, and what was decided.
        </p>
      </div>

      {overview.pending_approvals.length > 0 ? (
        <Card
          title="Waiting on a human"
          description="Actions inside the agent's role but beyond its unsupervised discretion."
        >
          <ul className="divide-y divide-slate-100">
            {overview.pending_approvals.map((approval) => (
              <li key={approval.id} className="flex items-center justify-between gap-4 py-3">
                <div>
                  <p className="text-sm font-medium">
                    <span className="font-mono">{approval.agent_handle}</span> requested{' '}
                    <span className="font-mono">{approval.action}</span> on{' '}
                    <span className="font-mono">
                      {approval.resource_type}:{approval.resource_id}
                    </span>
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {approval.reason_code} &middot; needs {approval.requirement.quorum} approval
                    {approval.requirement.quorum === 1 ? '' : 's'} from{' '}
                    {approval.requirement.roles.join(' and ')} &middot; window closes{' '}
                    <Relative iso={approval.expires_at} />
                  </p>
                </div>
                <span className="shrink-0">
                  <Decision value="ESCALATE" />
                </span>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Agents" description="Machine principals and the humans accountable for them.">
          {overview.agents.length === 0 ? (
            <Empty>No agents registered.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {overview.agents.map((agent) => (
                <li key={agent.id} className="flex items-center justify-between gap-4 py-3">
                  <div>
                    <Link
                      href={`/agents/${agent.id}`}
                      className="font-mono text-sm font-medium underline decoration-slate-300 underline-offset-4 hover:decoration-slate-600"
                    >
                      {agent.handle}
                    </Link>
                    <p className="mt-0.5 text-xs text-slate-500">{agent.display_name}</p>
                  </div>
                  <Status value={agent.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          title="Live authority"
          description="Active, unexpired leases. Authority is scoped and time-bounded, never a standing permission."
        >
          {overview.active_leases.length === 0 ? (
            <Empty>No authority is currently held.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {overview.active_leases.map((lease) => (
                <li key={lease.id} className="py-3">
                  <div className="flex items-baseline justify-between gap-3">
                    <Mono>{lease.id}</Mono>
                    <span className="text-xs text-slate-500">
                      expires <Relative iso={lease.expires_at} />
                    </span>
                  </div>
                  <p className="mt-1 font-mono text-xs text-slate-700">
                    {lease.grant.actions.join(', ')}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {Object.entries(lease.grant.constraints)
                      .map(([name, value]) => formatConstraint(name, value))
                      .join(' · ') || 'unconstrained'}
                  </p>
                  {lease.depth > 0 ? (
                    <p className="mt-1 text-xs text-slate-500">
                      delegated, depth {lease.depth}, from <Mono>{lease.parent_lease_id}</Mono>
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          title="Live risk signals"
          description="Assertions from external systems. Each expires; none is authoritative on its own."
        >
          {overview.live_signals.length === 0 ? (
            <Empty>No live signals.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {overview.live_signals.map((signal) => (
                <li key={signal.id} className="flex items-baseline justify-between gap-4 py-2.5">
                  <div>
                    <p className="text-sm">
                      <span className="font-mono font-medium">{signal.signal_type}</span> ={' '}
                      <span className="font-mono">{signal.value}</span>
                    </p>
                    <p className="mt-0.5 text-xs text-slate-500">
                      {signal.subject_type} <span className="font-mono">{signal.subject_id}</span>{' '}
                      &middot; {signal.source} &middot; confidence {signal.confidence}
                    </p>
                  </div>
                  <span className="shrink-0 text-xs text-slate-500">
                    expires <Relative iso={signal.expires_at} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Recent decisions" description="Every evaluation, allowed or refused.">
          {overview.recent_decisions.length === 0 ? (
            <Empty>No decisions yet.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {overview.recent_decisions.map((decision) => (
                <li key={decision.id} className="flex items-center justify-between gap-4 py-2.5">
                  <div className="min-w-0">
                    <Link
                      href={`/decisions/${decision.id}`}
                      className="text-sm underline decoration-slate-300 underline-offset-4 hover:decoration-slate-600"
                    >
                      <span className="font-mono">{decision.agent_handle}</span>{' '}
                      <span className="font-mono text-slate-600">{decision.action}</span>
                    </Link>
                    <p className="mt-0.5 truncate text-xs text-slate-500">
                      {decision.reason_code} &middot; <Relative iso={decision.decided_at} />
                    </p>
                  </div>
                  <span className="shrink-0">
                    <Decision value={decision.decision} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
