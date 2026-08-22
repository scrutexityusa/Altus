/**
 * A minimal Prometheus-format metrics registry.
 *
 * Deliberately hand-rolled and small: the platform needs a fixed, well-chosen
 * set of authorization metrics far more than it needs a general-purpose
 * metrics library, and every series here is one an on-call engineer would
 * actually page on.
 */
type Labels = Record<string, string>;

interface Series {
  help: string;
  type: 'counter' | 'histogram';
  values: Map<
    string,
    { labels: Labels; value: number; buckets?: number[]; sum?: number; count?: number }
  >;
  buckets?: number[];
}

const registry = new Map<string, Series>();

const LATENCY_BUCKETS = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5];

function key(labels: Labels): string {
  return Object.keys(labels)
    .sort()
    .map((k) => `${k}="${String(labels[k] ?? '').replace(/["\\\n]/g, '_')}"`)
    .join(',');
}

export function counter(name: string, help: string) {
  if (!registry.has(name)) registry.set(name, { help, type: 'counter', values: new Map() });
  return {
    inc(labels: Labels = {}, amount = 1) {
      const series = registry.get(name)!;
      const id = key(labels);
      const existing = series.values.get(id);
      if (existing) existing.value += amount;
      else series.values.set(id, { labels, value: amount });
    },
  };
}

export function histogram(name: string, help: string, buckets = LATENCY_BUCKETS) {
  if (!registry.has(name)) {
    registry.set(name, { help, type: 'histogram', values: new Map(), buckets });
  }
  return {
    observe(value: number, labels: Labels = {}) {
      const series = registry.get(name)!;
      const id = key(labels);
      let entry = series.values.get(id);
      if (!entry) {
        entry = {
          labels,
          value: 0,
          buckets: new Array(buckets.length + 1).fill(0),
          sum: 0,
          count: 0,
        };
        series.values.set(id, entry);
      }
      entry.sum! += value;
      entry.count! += 1;
      const found = buckets.findIndex((b) => value <= b);
      const index = found === -1 ? buckets.length : found;
      entry.buckets![index] = (entry.buckets![index] ?? 0) + 1;
    },
  };
}

export function renderMetrics(): string {
  const lines: string[] = [];
  for (const [name, series] of registry) {
    lines.push(`# HELP ${name} ${series.help}`, `# TYPE ${name} ${series.type}`);
    for (const entry of series.values.values()) {
      const labelText = key(entry.labels);
      if (series.type === 'counter') {
        lines.push(`${name}{${labelText}} ${entry.value}`);
        continue;
      }
      let cumulative = 0;
      for (const [index, bucket] of series.buckets!.entries()) {
        cumulative += entry.buckets![index]!;
        lines.push(
          `${name}_bucket{${labelText}${labelText ? ',' : ''}le="${bucket}"} ${cumulative}`,
        );
      }
      cumulative += entry.buckets![series.buckets!.length]!;
      lines.push(
        `${name}_bucket{${labelText}${labelText ? ',' : ''}le="+Inf"} ${cumulative}`,
        `${name}_sum{${labelText}} ${entry.sum}`,
        `${name}_count{${labelText}} ${entry.count}`,
      );
    }
  }
  return lines.join('\n') + '\n';
}

export function resetMetrics(): void {
  registry.clear();
}

// The fixed instrument set (Section 27).
export const metrics = {
  httpRequests: counter('scrutexity_http_requests_total', 'HTTP requests by route and status'),
  httpLatency: histogram('scrutexity_http_request_duration_seconds', 'HTTP request latency'),
  authorizationDecisions: counter(
    'scrutexity_authorization_decisions_total',
    'Authorization decisions by outcome and reason',
  ),
  authorizationLatency: histogram(
    'scrutexity_authorization_duration_seconds',
    'End-to-end authorization latency, edge to persisted decision',
  ),
  policyEvaluationLatency: histogram(
    'scrutexity_policy_evaluation_duration_seconds',
    'Policy decision point latency, excluding I/O',
    [0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05],
  ),
  policyCache: counter('scrutexity_policy_cache_total', 'Policy version cache hits and misses'),
  leasesIssued: counter('scrutexity_leases_issued_total', 'Authority leases issued by depth'),
  leasesRevoked: counter('scrutexity_leases_revoked_total', 'Authority leases revoked'),
  leasesExpired: counter(
    'scrutexity_leases_expired_total',
    'Authority leases observed expired at evaluation',
  ),
  delegationsCreated: counter('scrutexity_delegations_created_total', 'Delegations created'),
  delegationsRejected: counter(
    'scrutexity_delegations_rejected_total',
    'Delegations rejected by reason',
  ),
  signalsIngested: counter('scrutexity_signals_ingested_total', 'Risk signals ingested by type'),
  approvalsRecorded: counter(
    'scrutexity_approvals_recorded_total',
    'Human approvals recorded by vote',
  ),
  approvalLatency: histogram(
    'scrutexity_approval_latency_seconds',
    'Time from escalation to satisfied approval',
    [1, 5, 15, 60, 300, 900, 3600, 14_400],
  ),
  receiptsAppended: counter(
    'scrutexity_receipts_appended_total',
    'Evidence receipts appended by kind',
  ),
  verificationFailures: counter(
    'scrutexity_verification_failures_total',
    'Receipt verification failures by check',
  ),
  replayAttempts: counter('scrutexity_replay_attempts_total', 'Rejected replays by kind'),

  // -- Causal evidence, corrective handshake and grant lifecycle ------------
  traceDuration: histogram(
    'scrutexity_trace_duration_seconds',
    'Root-cause trace assembly latency',
    [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
  ),
  traceNodes: histogram(
    'scrutexity_trace_nodes',
    'Nodes returned per root-cause trace',
    [1, 2, 3, 5, 8, 13, 21, 34],
  ),
  correctiveActionsReturned: counter(
    'scrutexity_corrective_actions_returned_total',
    'Corrective actions offered with a refusal, by type and reason',
  ),
  singleUseGrantsClaimed: counter(
    'scrutexity_single_use_grant_claimed_total',
    'Single-use grants bound to an authorization decision',
  ),
  singleUseGrantsConsumed: counter(
    'scrutexity_single_use_grant_consumed_total',
    'Single-use grants spent by an execution',
  ),
  contextMismatches: counter(
    'scrutexity_context_mismatch_total',
    'Executions refused because conditions changed since the decision',
  ),
  intentMismatches: counter(
    'scrutexity_intent_mismatch_total',
    'Actions refused as outside the declared intent, by reason',
  ),
  signalInvalidSignature: counter(
    'scrutexity_signal_invalid_signature_total',
    'Signals rejected for a bad or unknown signature, by reason',
  ),
  // -- The execution enforcement boundary -----------------------------------
  executionsClaimed: counter(
    'scrutexity_executions_claimed_total',
    'Execution rights atomically claimed against a grant, by provider',
  ),
  executionsSettled: counter(
    'scrutexity_executions_settled_total',
    'Enforced executions settled, by provider and provider-reported status',
  ),
  intentBindingMismatches: counter(
    'scrutexity_intent_binding_mismatch_total',
    'Executions refused because the operation did not match its grant, by kind',
  ),
  executionsUnresolved: counter(
    'scrutexity_executions_unresolved_total',
    'Enforced executions that ended without an answer from the provider, by provider',
  ),
  /**
   * Any non-zero value here is an incident, not a trend. Alert on the first
   * one within a five-minute window and route it to the security team.
   */
  authorityInvariantViolations: counter(
    'scrutexity_authority_invariant_violations_total',
    'Decisions refused because a constitutional authority invariant did not hold',
  ),
  securityEvents: counter('scrutexity_security_events_total', 'Security events recorded, by kind'),
  policyEvaluationFailures: counter(
    'scrutexity_policy_evaluation_failures_total',
    'Policy evaluations that could not complete',
  ),
};
