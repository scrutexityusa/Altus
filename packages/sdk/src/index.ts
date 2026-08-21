import {
  ScrutexityError,
  verifyReceipt as verifyReceiptOffline,
  type AuthorityGrant,
  type ConstraintCheck,
  type Decision,
  type ErrorCode,
  type Explanation,
  type FailoverBehavior,
  type Receipt,
  type ReceiptVerifier,
  type VerificationResult,
} from '@scrutexity/core';

/**
 * ============================================================================
 * @scrutexity/sdk -- the Policy Enforcement Point that runs beside the agent.
 * ============================================================================
 *
 * The SDK's job is to make the safe path the easy one (Section 36). Three
 * choices follow from that and are worth stating plainly:
 *
 *  1. `decision.allowed` is a getter over an enum, and every other outcome is
 *     falsy. A caller who writes `if (decision.allowed)` cannot accidentally
 *     treat an ESCALATE as a yes.
 *
 *  2. `guard()` exists so the common case -- "do this only if authorised" --
 *     never separates the check from the act. It records the execution result
 *     against the grant, so evidence is a consequence of using the SDK rather
 *     than a step a caller can forget.
 *
 *  3. There is no client-side cache of decisions. A decision is valid only for
 *     the policy version, authority lease and signal state it was made under,
 *     none of which the client can observe changing (Section 38).
 */

export interface ScrutexityOptions {
  baseUrl: string;
  token: string;
  /** Milliseconds before an authorization call is abandoned. */
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
  /** Public key for verifying receipts without trusting the server's answer. */
  receiptVerifier?: ReceiptVerifier;
}

export interface AuthorizeRequest {
  agentId: string;
  action: string;
  resource: string | { type: string; id: string };
  context?: Record<string, unknown>;
  authorityLeaseId?: string;
  /** Single-use value; the control plane refuses a repeat. */
  nonce?: string;
  correlationId?: string;
  idempotencyKey?: string;
}

export interface AuthorizationDecision {
  readonly decision: Decision;
  /** True only for ALLOW. ESCALATE and DENY are both falsy, deliberately. */
  readonly allowed: boolean;
  readonly requiresApproval: boolean;
  readonly denied: boolean;
  readonly decisionId: string;
  readonly authorizationRequestId: string;
  readonly receiptId: string;
  readonly reasonCode: string;
  readonly approvalRequestId: string | null;
  readonly approvalRequirement: {
    quorum: number;
    roles: string[];
    ttl_seconds: number;
  } | null;
  readonly authorityLeaseId: string | null;
  readonly policyId: string | null;
  readonly policyVersion: string | null;
  readonly policyHash: string | null;
  readonly riskSignalIds: string[];
  readonly constraintsEvaluated: ConstraintCheck[];
  readonly failoverBehavior: FailoverBehavior;
  /** When the execution grant lapses. Null unless the decision was ALLOW. */
  readonly expiresAt: string | null;
  readonly decisionTimestamp: string;
}

export interface DelegateRequest {
  issuerAgentId: string;
  delegateAgentId: string;
  parentLeaseId: string;
  grant: AuthorityGrant;
  ttlSeconds: number;
  idempotencyKey?: string;
}

export interface RequestAuthorityRequest {
  agentId: string;
  grant: AuthorityGrant;
  ttlSeconds: number;
  revocable?: boolean;
  idempotencyKey?: string;
}

export interface SignalRequest {
  subject: { type: 'agent' | 'user' | 'organization' | 'resource' | 'counterparty'; id: string };
  signalType: string;
  value: string | number;
  confidence?: string | number;
  source: string;
  ttlSeconds: number;
  idempotencyKey?: string;
}

export class ScrutexityClient {
  readonly #baseUrl: string;
  readonly #token: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof globalThis.fetch;
  readonly #receiptVerifier: ReceiptVerifier | undefined;

  constructor(options: ScrutexityOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#receiptVerifier = options.receiptVerifier;
  }

  async #request<T>(
    method: string,
    path: string,
    body?: unknown,
    idempotencyKey?: string,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    let response: Response;
    try {
      response = await this.#fetch(`${this.#baseUrl}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${this.#token}`,
          'content-type': 'application/json',
          ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
    } catch (error) {
      // A control plane that cannot be reached has not said yes. The caller
      // decides what to do about that; the SDK never invents an answer.
      throw new ScrutexityError(
        'ENFORCEMENT_UNAVAILABLE',
        `the authorization service could not be reached: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    const payload = text ? (JSON.parse(text) as Record<string, unknown>) : {};

    if (!response.ok) {
      const error = payload['error'] as
        | { code?: ErrorCode; reason_code?: string; message?: string; details?: unknown }
        | undefined;
      throw new ScrutexityError(error?.code ?? 'INTERNAL_ERROR', error?.message ?? 'request failed', {
        reasonCode: error?.reason_code,
        details: error?.details,
        disclose: true,
      });
    }
    return payload as T;
  }

  /** Asks whether this action is authorised, right now, in this context. */
  async authorize(request: AuthorizeRequest): Promise<AuthorizationDecision> {
    const resource =
      typeof request.resource === 'string' ? parseResourceRef(request.resource) : request.resource;

    const payload = await this.#request<EvaluateResponse>(
      'POST',
      '/v1/authorization/evaluate',
      {
        agent_id: request.agentId,
        action: request.action,
        resource,
        context: request.context ?? {},
        ...(request.authorityLeaseId ? { authority_lease_id: request.authorityLeaseId } : {}),
        ...(request.nonce ? { nonce: request.nonce } : {}),
        ...(request.correlationId ? { correlation_id: request.correlationId } : {}),
      },
      request.idempotencyKey,
    );
    return toDecision(payload);
  }

  /**
   * Runs `execute` only if the action is authorised, and records what happened
   * against the grant either way.
   *
   * This is the shape the SDK wants callers to reach for: the check and the act
   * cannot drift apart, and the evidence is not something anyone has to
   * remember to write.
   */
  async guard<T>(
    request: AuthorizeRequest,
    execute: (decision: AuthorizationDecision) => Promise<T>,
  ): Promise<{ decision: AuthorizationDecision; result: T | null }> {
    const decision = await this.authorize(request);
    if (!decision.allowed) return { decision, result: null };

    try {
      const result = await execute(decision);
      await this.recordExecution(decision.decisionId, 'SUCCEEDED', { ok: true });
      return { decision, result };
    } catch (error) {
      await this.recordExecution(decision.decisionId, 'FAILED', {
        error: error instanceof Error ? error.message : String(error),
      }).catch(() => undefined);
      throw error;
    }
  }

  async recordExecution(
    decisionId: string,
    status: 'SUCCEEDED' | 'FAILED',
    result: Record<string, unknown> = {},
  ): Promise<{ execution_id: string; receipt_id: string }> {
    return this.#request('POST', '/v1/executions', { decision_id: decisionId, status, result });
  }

  async requestAuthority(request: RequestAuthorityRequest) {
    return this.#request<{ authority_lease: { id: string; expires_at: string }; receipt_id: string }>(
      'POST',
      '/v1/authority-leases',
      {
        agent_id: request.agentId,
        grant: request.grant,
        ttl_seconds: request.ttlSeconds,
        revocable: request.revocable ?? true,
      },
      request.idempotencyKey,
    );
  }

  async revokeAuthority(leaseId: string, reason: string) {
    return this.#request<{ authority_lease: unknown; receipt_id: string | null }>(
      'POST',
      `/v1/authority-leases/${encodeURIComponent(leaseId)}/revoke`,
      { reason },
    );
  }

  async delegateAuthority(request: DelegateRequest) {
    return this.#request<{
      delegation_id: string;
      child_lease: { id: string; expires_at: string; depth: number };
      ttl_clamped: boolean;
      receipt_id: string;
    }>(
      'POST',
      '/v1/delegations',
      {
        issuer_agent_id: request.issuerAgentId,
        delegate_agent_id: request.delegateAgentId,
        parent_lease_id: request.parentLeaseId,
        grant: request.grant,
        ttl_seconds: request.ttlSeconds,
      },
      request.idempotencyKey,
    );
  }

  async publishSignal(request: SignalRequest) {
    return this.#request<{ signal: { id: string; expires_at: string }; receipt_id: string }>(
      'POST',
      '/v1/signals',
      {
        subject: request.subject,
        signal_type: request.signalType,
        value: request.value,
        ...(request.confidence === undefined ? {} : { confidence: request.confidence }),
        source: request.source,
        ttl_seconds: request.ttlSeconds,
      },
      request.idempotencyKey,
    );
  }

  async approve(approvalRequestId: string, vote: 'APPROVED' | 'REJECTED', comment?: string) {
    return this.#request<{
      approval_id: string;
      satisfied_role: string | null;
      decision: { decision: Decision; decision_id: string; reason_code: string } | null;
    }>('POST', '/v1/approvals', {
      approval_request_id: approvalRequestId,
      vote,
      ...(comment ? { comment } : {}),
    });
  }

  /** The why-was-I-allowed call, with its deterministic explanation attached. */
  async explainDecision(decisionId: string) {
    return this.#request<{
      decision: Record<string, unknown>;
      request: Record<string, unknown>;
      approvals: unknown[];
      receipt: { id: string; hash: string } | null;
      execution: unknown | null;
      explanation: Explanation;
    }>('GET', `/v1/authorization-decisions/${encodeURIComponent(decisionId)}`);
  }

  async getReceipt(receiptId: string): Promise<Receipt> {
    const payload = await this.#request<{ receipt: Receipt }>(
      'GET',
      `/v1/receipts/${encodeURIComponent(receiptId)}`,
    );
    return payload.receipt;
  }

  /**
   * Verifies a receipt. When the client was constructed with a public key the
   * check runs locally first, so a compromised control plane cannot vouch for
   * its own evidence; the server's answer is reported alongside, never instead.
   */
  async verifyReceipt(receiptOrId: string | Receipt): Promise<{
    integrity: 'INTACT' | 'COMPROMISED';
    local: VerificationResult | null;
    remote: unknown;
  }> {
    const receipt =
      typeof receiptOrId === 'string' ? await this.getReceipt(receiptOrId) : receiptOrId;

    const local = this.#receiptVerifier ? verifyReceiptOffline(receipt, this.#receiptVerifier) : null;
    const remote = await this.#request<{ integrity: 'INTACT' | 'COMPROMISED' }>(
      'POST',
      `/v1/receipts/${encodeURIComponent(receipt.id)}/verify`,
      {},
    );

    return {
      integrity: local ? (local.intact ? 'INTACT' : 'COMPROMISED') : remote.integrity,
      local,
      remote,
    };
  }
}

/** `"bank_account:acct_991"` or `"account:123"`. */
function parseResourceRef(ref: string): { type: string; id: string } {
  const separator = ref.indexOf(':');
  if (separator <= 0 || separator === ref.length - 1) {
    throw new ScrutexityError(
      'INVALID_REQUEST',
      `resource must be "type:id" (received ${JSON.stringify(ref)})`,
      { disclose: true },
    );
  }
  return { type: ref.slice(0, separator), id: ref.slice(separator + 1) };
}

/** The v1 evaluate response, in the API's own snake_case wire shape. */
interface EvaluateResponse {
  decision: Decision;
  decision_id: string;
  authorization_request_id: string;
  receipt_id: string;
  reason_code: string;
  approval_request_id: string | null;
  approval_requirement: { quorum: number; roles: string[]; ttl_seconds: number } | null;
  authority_lease_id: string | null;
  policy_id: string | null;
  policy_version: string | null;
  policy_hash: string | null;
  risk_signal_ids: string[];
  constraints_evaluated: ConstraintCheck[];
  failover_behavior: FailoverBehavior;
  expires_at: string | null;
  decision_timestamp: string;
}

function toDecision(payload: EvaluateResponse): AuthorizationDecision {
  return {
    decision: payload.decision,
    // Only ALLOW is truthy. ESCALATE is not a soft yes.
    allowed: payload.decision === 'ALLOW',
    requiresApproval: payload.decision === 'ESCALATE',
    denied: payload.decision === 'DENY',
    decisionId: payload.decision_id,
    authorizationRequestId: payload.authorization_request_id,
    receiptId: payload.receipt_id,
    reasonCode: payload.reason_code,
    approvalRequestId: payload.approval_request_id ?? null,
    approvalRequirement: payload.approval_requirement ?? null,
    authorityLeaseId: payload.authority_lease_id ?? null,
    policyId: payload.policy_id ?? null,
    policyVersion: payload.policy_version ?? null,
    policyHash: payload.policy_hash ?? null,
    riskSignalIds: payload.risk_signal_ids ?? [],
    constraintsEvaluated: payload.constraints_evaluated ?? [],
    failoverBehavior: payload.failover_behavior,
    expiresAt: payload.expires_at ?? null,
    decisionTimestamp: payload.decision_timestamp,
  };
}

export { ScrutexityError };
export type { AuthorityGrant, ConstraintCheck, Decision, Explanation, Receipt };
