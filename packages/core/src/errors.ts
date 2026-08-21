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
  'DELEGATION_EXCEEDS_PARENT',
  // Control-plane availability
  'POLICY_UNAVAILABLE',
  'SIGNAL_UNAVAILABLE',
  'ENFORCEMENT_UNAVAILABLE',
  // Integrity
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
  DELEGATION_EXCEEDS_PARENT: 422,
  POLICY_UNAVAILABLE: 503,
  SIGNAL_UNAVAILABLE: 503,
  ENFORCEMENT_UNAVAILABLE: 503,
  REPLAY_DETECTED: 409,
  IDEMPOTENCY_CONFLICT: 409,
  EVIDENCE_TAMPERED: 422,
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
  DELEGATION_EXCEEDS_PARENT: 'The delegated authority exceeds the authority of its parent.',
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
