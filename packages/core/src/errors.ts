/**
 * The failure taxonomy (Section 28). Callers branch on `code`; humans read
 * `message`. Nothing here is a free-form string at the boundary.
 */
export const ERROR_CODES = [
  // Caller identity
  'UNAUTHORIZED',
  'FORBIDDEN',
  'INVALID_REQUEST',
  // Authorization outcomes
  'POLICY_DENIED',
  'APPROVAL_REQUIRED',
  'AUTHORITY_MISSING',
  'AUTHORITY_EXPIRED',
  'AUTHORITY_REVOKED',
  'AUTHORITY_SUSPENDED',
  'CONSTRAINT_VIOLATION',
  'AUTHORITY_CONSUMED',
  'DELEGATION_EXCEEDS_PARENT',
  'INTENT_MISMATCH',
  // The conditions a decision was made under changed before it was used.
  'APPROVAL_CONTEXT_MISMATCH',
  'CONTEXT_CHANGED',
  // Signal plane
  'SIGNAL_SIGNATURE_INVALID',
  'SIGNAL_KEY_UNKNOWN',
  /**
   * The signal's source has no signing key registered in this tenant.
   *
   * Distinct from SIGNAL_KEY_UNKNOWN, which means "this source is enrolled and
   * that key id is not one of its keys". This means the source is not known to
   * the tenant at all, so nothing it asserts is attributable to anyone. The
   * two are separated because they call for different operator actions --
   * enrol the source, versus investigate a key id that should not exist.
   */
  'SIGNAL_SOURCE_NOT_ENROLLED',
  // Control-plane availability
  'POLICY_UNAVAILABLE',
  'SIGNAL_UNAVAILABLE',
  'ENFORCEMENT_UNAVAILABLE',
  // Integrity
  /**
   * A constitutional invariant did not hold at runtime.
   *
   * Deliberately distinct from POLICY_DENIED. A policy denial is ordinary and
   * an operator sees them all day; this means the system's model of its own
   * authority is wrong, which is a different and much worse fact. Collapsing
   * it into a generic 403 would bury the one signal nobody may miss.
   */
  'AUTHORITY_INVARIANT_VIOLATION',
  /**
   * A prior execution against this grant exists and has not been resolved.
   *
   * Distinct from REPLAY_DETECTED, which means "this was already done". This
   * means "this may or may not have been done, and nobody knows yet" -- the
   * state left behind when the provider was reached but the outcome was never
   * recorded. Retrying is not safe; reconciling is the only correct move, and
   * the caller has to be told which of the two it is looking at.
   */
  'EXECUTION_UNRESOLVED',
  'REPLAY_DETECTED',
  'IDEMPOTENCY_CONFLICT',
  'EVIDENCE_TAMPERED',
  'STATE_CONFLICT',
  'NOT_FOUND',
  'RATE_LIMITED',
  'INTERNAL_ERROR',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

const STATUS: Record<ErrorCode, number> = {
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  INVALID_REQUEST: 400,
  POLICY_DENIED: 403,
  APPROVAL_REQUIRED: 202,
  AUTHORITY_MISSING: 403,
  AUTHORITY_EXPIRED: 403,
  AUTHORITY_REVOKED: 403,
  AUTHORITY_SUSPENDED: 403,
  CONSTRAINT_VIOLATION: 403,
  AUTHORITY_CONSUMED: 403,
  DELEGATION_EXCEEDS_PARENT: 422,
  INTENT_MISMATCH: 403,
  APPROVAL_CONTEXT_MISMATCH: 409,
  CONTEXT_CHANGED: 409,
  SIGNAL_SIGNATURE_INVALID: 403,
  SIGNAL_KEY_UNKNOWN: 403,
  SIGNAL_SOURCE_NOT_ENROLLED: 403,
  POLICY_UNAVAILABLE: 503,
  SIGNAL_UNAVAILABLE: 503,
  ENFORCEMENT_UNAVAILABLE: 503,
  REPLAY_DETECTED: 409,
  IDEMPOTENCY_CONFLICT: 409,
  EVIDENCE_TAMPERED: 422,
  AUTHORITY_INVARIANT_VIOLATION: 403,
  EXECUTION_UNRESOLVED: 409,
  STATE_CONFLICT: 409,
  NOT_FOUND: 404,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
};

/**
 * Codes whose details are safe to return verbatim. Anything else gets a
 * generic message at the boundary so a probing caller cannot map out policy
 * internals or another tenant's object graph by reading error text.
 */
const DISCLOSABLE = new Set<ErrorCode>([
  'INVALID_REQUEST',
  'APPROVAL_REQUIRED',
  'DELEGATION_EXCEEDS_PARENT',
  'INTENT_MISMATCH',
  'APPROVAL_CONTEXT_MISMATCH',
  'CONTEXT_CHANGED',
  'AUTHORITY_CONSUMED',
  'REPLAY_DETECTED',
  'IDEMPOTENCY_CONFLICT',
  'STATE_CONFLICT',
  'EVIDENCE_TAMPERED',
  'RATE_LIMITED',
]);

export interface ErrorBody {
  error: {
    code: ErrorCode;
    /**
     * The specific, machine-readable cause within `code`. Reason codes are a
     * closed documented vocabulary, so returning one leaks nothing the code
     * did not already say -- and without it a caller cannot tell "you may not
     * delegate this action" from "you may not call this endpoint".
     */
    reason_code?: string;
    message: string;
    details?: unknown;
    request_id?: string;
  };
}

export interface ScrutexityErrorOptions {
  reasonCode?: string;
  details?: unknown;
  /**
   * Opt in to returning `message` and `details` for a code that is otherwise
   * generic. Set it only when the detail is the caller's own input reflected
   * back -- never for anything derived from another tenant's data or from
   * policy the caller cannot already read.
   */
  disclose?: boolean;
  internal?: unknown;
  cause?: unknown;
}

export class ScrutexityError extends Error {
  readonly code: ErrorCode;
  readonly reasonCode: string | undefined;
  readonly status: number;
  readonly details: unknown;
  readonly disclose: boolean;
  /** Never serialised to a client; carried for the structured log record. */
  readonly internal: unknown;

  constructor(code: ErrorCode, message: string, options: ScrutexityErrorOptions = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'ScrutexityError';
    this.code = code;
    this.reasonCode = options.reasonCode;
    this.status = STATUS[code];
    this.details = options.details;
    this.disclose = options.disclose ?? false;
    this.internal = options.internal;
  }

  toBody(requestId?: string): ErrorBody {
    const disclose = this.disclose || DISCLOSABLE.has(this.code);
    return {
      error: {
        code: this.code,
        ...(this.reasonCode ? { reason_code: this.reasonCode } : {}),
        message: disclose ? this.message : GENERIC_MESSAGES[this.code],
        ...(disclose && this.details !== undefined ? { details: this.details } : {}),
        ...(requestId ? { request_id: requestId } : {}),
      },
    };
  }
}

const GENERIC_MESSAGES: Record<ErrorCode, string> = {
  UNAUTHORIZED: 'Authentication is required.',
  FORBIDDEN: 'The caller is not permitted to perform this operation.',
  INVALID_REQUEST: 'The request is invalid.',
  POLICY_DENIED: 'Policy denied this action.',
  APPROVAL_REQUIRED: 'Human approval is required before this action may proceed.',
  AUTHORITY_MISSING: 'No authority covers this action.',
  AUTHORITY_EXPIRED: 'The authority for this action has expired.',
  AUTHORITY_REVOKED: 'The authority for this action has been revoked.',
  AUTHORITY_SUSPENDED: 'The authority for this action is suspended.',
  CONSTRAINT_VIOLATION: 'The action falls outside the constraints of the held authority.',
  AUTHORITY_CONSUMED: 'This single-use authority has already been spent.',
  DELEGATION_EXCEEDS_PARENT: 'The delegated authority exceeds the authority of its parent.',
  INTENT_MISMATCH: 'The attempted action falls outside the declared intent.',
  APPROVAL_CONTEXT_MISMATCH:
    'The conditions changed since this action was approved. It must be re-evaluated and re-approved.',
  CONTEXT_CHANGED:
    'The conditions changed since this action was authorised. It must be re-evaluated.',
  AUTHORITY_INVARIANT_VIOLATION:
    'This request was refused because an authority invariant did not hold. It has been recorded for review.',
  EXECUTION_UNRESOLVED:
    'A previous execution against this authorization has not been resolved. It must be reconciled against the provider before anything further is attempted.',
  SIGNAL_SIGNATURE_INVALID: 'The signal signature did not verify.',
  SIGNAL_KEY_UNKNOWN: 'No active signing key matches this signal.',
  SIGNAL_SOURCE_NOT_ENROLLED:
    'This signal source is not enrolled. A source must register a signing key before its signals are accepted.',
  POLICY_UNAVAILABLE: 'The policy could not be evaluated.',
  SIGNAL_UNAVAILABLE: 'Required risk signals could not be read.',
  ENFORCEMENT_UNAVAILABLE: 'The enforcement plane is unavailable.',
  REPLAY_DETECTED: 'This request has already been submitted.',
  IDEMPOTENCY_CONFLICT: 'This idempotency key was used with a different request body.',
  EVIDENCE_TAMPERED: 'Evidence integrity verification failed.',
  STATE_CONFLICT: 'The object is not in a state that permits this operation.',
  NOT_FOUND: 'Not found.',
  RATE_LIMITED: 'Too many requests.',
  INTERNAL_ERROR: 'An internal error occurred.',
};

export function errorStatus(code: ErrorCode): number {
  return STATUS[code];
}

export const invalidRequest = (message: string, details?: unknown) =>
  new ScrutexityError('INVALID_REQUEST', message, { details });
export const notFound = (what: string, id?: string) =>
  new ScrutexityError('NOT_FOUND', `${what} not found`, { internal: { id } });
export const stateConflict = (message: string, details?: unknown) =>
  new ScrutexityError('STATE_CONFLICT', message, { details });
