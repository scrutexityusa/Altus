import Link from 'next/link';
import type { ReactNode } from 'react';

/**
 * The dashboard's whole component vocabulary. Small on purpose: the brief asks
 * for the interfaces needed to understand the infrastructure, not an
 * enterprise dashboard.
 */

export function Decision({ value }: { value: 'ALLOW' | 'DENY' | 'ESCALATE' }) {
  const styles = {
    ALLOW: 'bg-allow-bg text-allow-fg border-allow-border',
    DENY: 'bg-deny-bg text-deny-fg border-deny-border',
    ESCALATE: 'bg-escalate-bg text-escalate-fg border-escalate-border',
  }[value];
  const label = { ALLOW: 'Allowed', DENY: 'Denied', ESCALATE: 'Approval required' }[value];
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${styles}`}
    >
      {/* The word carries the meaning; colour only reinforces it. */}
      <span className="sr-only">Decision: </span>
      {label}
    </span>
  );
}

export function Status({ value }: { value: string }) {
  const tone =
    value === 'ACTIVE'
      ? 'bg-allow-bg text-allow-fg border-allow-border'
      : value === 'REVOKED' || value === 'RETIRED'
        ? 'bg-deny-bg text-deny-fg border-deny-border'
        : 'bg-slate-100 text-slate-700 border-slate-300';
  return (
    <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-medium ${tone}`}>
      {value}
    </span>
  );
}

export function Card({
  title,
  description,
  children,
  action,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <header className="flex items-start justify-between gap-4 border-b border-slate-200 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
          {description ? <p className="mt-0.5 text-xs text-slate-500">{description}</p> : null}
        </div>
        {action}
      </header>
      <div className="px-4 py-3">{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-slate-500">{children}</p>;
}

export function Mono({ children, href }: { children: ReactNode; href?: string }) {
  const text = <code className="font-mono text-xs text-slate-600">{children}</code>;
  return href ? (
    <Link
      href={href}
      className="underline decoration-slate-300 underline-offset-2 hover:decoration-slate-600"
    >
      {text}
    </Link>
  ) : (
    text
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="py-1.5">
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-900">{children}</dd>
    </div>
  );
}

export function Relative({ iso }: { iso: string }) {
  const then = new Date(iso).getTime();
  const delta = Math.round((then - Date.now()) / 1000);
  const abs = Math.abs(delta);
  const [value, unit] =
    abs < 60
      ? [abs, 'second']
      : abs < 3600
        ? [Math.round(abs / 60), 'minute']
        : abs < 86_400
          ? [Math.round(abs / 3600), 'hour']
          : [Math.round(abs / 86_400), 'day'];
  const suffix = delta >= 0 ? 'from now' : 'ago';
  // Built as one string: JSX would insert whitespace between the unit and its
  // plural, rendering "60 minute s".
  const label = `${value} ${unit}${value === 1 ? '' : 's'} ${suffix}`;
  return (
    <time dateTime={iso} title={iso}>
      {label}
    </time>
  );
}
