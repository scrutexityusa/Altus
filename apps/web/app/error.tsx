'use client';

export default function Error({ error }: { error: Error & { digest?: string } }) {
  return (
    <div className="rounded-lg border border-deny-border bg-deny-bg px-5 py-4">
      <h1 className="text-sm font-semibold text-deny-fg">
        The dashboard could not read the control plane
      </h1>
      <p className="mt-2 text-sm text-deny-fg">{error.message}</p>
      <p className="mt-3 text-xs text-deny-fg">
        The dashboard renders the API&rsquo;s own read model, so it shows nothing the API cannot
        confirm. Check that the control plane is running and that{' '}
        <code className="font-mono">SCRUTEXITY_API_TOKEN</code> is set.
      </p>
    </div>
  );
}
