import { z } from 'zod';
import { GrantSchema } from '@scrutexity/core';

/**
 * Request schemas for the v1 surface. These are the single source of truth:
 * the committed OpenAPI document is generated from them (scripts/generate-specs.ts)
 * and CI fails if the two drift, so the published contract cannot quietly stop
 * describing the running service.
 */

export const ResourceRefSchema = z
  .object({ type: z.string().min(1).max(64), id: z.string().min(1).max(128) })
  .strict();

export const CreateAgentSchema = z
  .object({
    handle: z
      .string()
      .regex(/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/, 'handle must be lowercase kebab-case'),
    display_name: z.string().min(1).max(200),
    description: z.string().max(1000).optional(),
    /** The human accountable for this machine principal. */
    owner_user_id: z.string().optional(),
    metadata: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

/**
 * A human principal. Deliberately the narrowest shape the existing model
 * already understands -- name, email, roles, and the organization the
 * credential resolved to. This is not an identity system: there is no password,
 * no session, no invitation flow and no directory sync, because none of those
 * are things Scrutexity decides anything with.
 *
 * `roles` is the tenant's own vocabulary. The approval requirements in a policy
 * match on these strings, so `treasurer` here and `roles: [treasurer]` in the
 * policy are the same fact stated in two places, which is the intended
 * coupling: an organization names its roles once and both sides read it.
 */
export const CreateUserSchema = z
  .object({
    email: z.string().email().max(320),
    display_name: z.string().min(1).max(200),
    /** Free-form and tenant-defined; the policy's approval roles reference these. */
    roles: z.array(z.string().min(1).max(64)).max(32).default([]),
  })
  .strict();

export const UpdateUserSchema = z
  .object({
    display_name: z.string().min(1).max(200).optional(),
    roles: z.array(z.string().min(1).max(64)).max(32).optional(),
    /**
     * DISABLED keeps the row and stops the principal acting. Deleting a user
     * who has approved something would orphan the approval, and an approval
     * whose approver cannot be named is not evidence of anything.
     */
    status: z.enum(['ACTIVE', 'DISABLED']).optional(),
  })
  .strict()
  .refine((body) => Object.keys(body).length > 0, { message: 'no fields to update' });

/**
 * Issue a credential to a principal that already exists in this tenant.
 *
 * The secret is generated server-side and returned exactly once. There is no
 * field for the caller to supply one: a credential a client chose is a
 * credential a client can have chosen badly, and one that arrived over the
 * wire is one that was in a request log.
 */
export const IssueCredentialSchema = z
  .object({
    principal_type: z.enum(['user', 'agent', 'service']),
    /** A user id, an agent id or handle, or a service name. */
    principal_id: z.string().min(1).max(128),
    scopes: z.array(z.string().min(1).max(64)).min(1).max(16),
    /**
     * Required. A credential that never expires is not representable: the
     * column is NOT NULL and the database caps the lifetime, so there is no
     * shape of this request that produces an immortal token.
     *
     * The upper bound is 90 days. It is not a number anybody negotiated; it is
     * short enough that rotation has to be a practised procedure rather than a
     * plan, and long enough that it is not a weekly interruption.
     */
    expires_in_seconds: z.number().int().min(60).max(7_776_000),
  })
  .strict();

/**
 * Register a bank account or a counterparty.
 *
 * `resource_type` is open text in the schema and closed in practice: the action
 * catalog decides which types an action can name, so registering a type nothing
 * references simply produces a row no policy reads. Constraining it here would
 * be a second catalog to keep in sync with the first.
 *
 * `attributes` is what policy reads under `resource.attributes.*`. For a
 * counterparty, `status` is the conventional one -- but note that
 * `counterparty_known` is derived from the row EXISTING, not from any attribute
 * in it. Registering a counterparty is the act that makes it known; there is no
 * field a caller can set to claim it.
 */
export const CreateResourceSchema = z
  .object({
    resource_type: z.string().min(1).max(64),
    /** The id an agent will name in an authorization request, e.g. "acct_001". */
    external_id: z.string().min(1).max(128),
    display_name: z.string().min(1).max(200),
    attributes: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

export const UpdateResourceSchema = z
  .object({
    display_name: z.string().min(1).max(200).optional(),
    attributes: z.record(z.string(), z.unknown()).optional(),
  })
  .strict()
  .refine((body) => Object.keys(body).length > 0, { message: 'no fields to update' });

export const AuthorizationRequestSchema = z
  .object({
    agent_id: z.string().min(1).max(128),
    action: z.string().min(1).max(128),
    resource: ResourceRefSchema,
    context: z.record(z.string(), z.unknown()).default({}),
    /** Optional lease the caller wishes to act under. */
    authority_lease_id: z.string().optional(),
    /**
     * What the agent says it is doing. Bound against the intents the policy
     * declares and against the purpose of any purpose-bound grant, producing
     * INTENT_MISMATCH when the attempted action falls outside it.
     */
    declared_intent: z.string().min(1).max(128).optional(),
    /** Single-use value; reuse is REPLAY_DETECTED. */
    nonce: z.string().min(8).max(128).optional(),
    correlation_id: z.string().max(128).optional(),
  })
  .strict();

export const CreateLeaseSchema = z
  .object({
    agent_id: z.string().min(1),
    grant: GrantSchema,
    ttl_seconds: z.number().int().min(30).max(2_592_000),
    revocable: z.boolean().default(true),
    /**
     * SINGLE_USE grants authorise exactly one action and are spent on use.
     * REUSABLE is the default only for backward compatibility; single-use is
     * the safer shape for high-consequence work.
     */
    grant_type: z.enum(['REUSABLE', 'SINGLE_USE']).default('REUSABLE'),
    /** Objective this authority is granted for; binds against declared intent. */
    purpose: z.string().min(1).max(128).optional(),
    metadata: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

export const RevokeLeaseSchema = z.object({ reason: z.string().min(3).max(500) }).strict();

export const CreateDelegationSchema = z
  .object({
    /** The agent handing authority over. Must hold `parent_lease_id`. */
    issuer_agent_id: z.string().min(1),
    delegate_agent_id: z.string().min(1),
    parent_lease_id: z.string().min(1),
    grant: GrantSchema,
    ttl_seconds: z.number().int().min(30).max(2_592_000),
  })
  .strict();

export const IngestSignalSchema = z
  .object({
    subject: z
      .object({
        type: z.enum(['agent', 'user', 'organization', 'resource', 'counterparty']),
        id: z.string().min(1).max(128),
      })
      .strict(),
    signal_type: z.string().min(3).max(64),
    value: z.union([z.string(), z.number()]),
    confidence: z.union([z.string(), z.number()]).optional(),
    source: z.string().min(1).max(128),
    ttl_seconds: z.number().int().min(1).max(86_400),
    issued_at: z.string().datetime().optional(),
    /**
     * Source-assigned unique id for this observation. Redelivering the same
     * event id is refused as a replay, which is what stops a source pushing a
     * stale low-risk reading over a current high-risk one.
     */
    event_id: z.string().min(1).max(128).optional(),
    /** Base64url signature over the canonical signal envelope. */
    signature: z.string().min(1).max(512).optional(),
    /** Which of the source's keys signed it. */
    signing_key_id: z.string().min(1).max(128).optional(),
    metadata: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

export const RegisterSignalKeySchema = z
  .object({
    source: z.string().min(1).max(128),
    key_id: z.string().min(1).max(128),
    algorithm: z.enum(['ED25519', 'HMAC_SHA256']),
    /**
     * Ed25519: an SPKI PEM public key -- preferred, because only the public
     * half is stored. HMAC_SHA256: the shared secret, which is why it is the
     * second choice.
     */
    key_material: z.string().min(32).max(4096),
    not_before: z.string().datetime().optional(),
    not_after: z.string().datetime().optional(),
  })
  .strict();

export const RotateSignalKeySchema = z
  .object({
    /** Seconds the outgoing key stays valid so the source can switch over. */
    grace_period_seconds: z.number().int().min(0).max(604_800).default(3600),
  })
  .strict();

export const SubmitApprovalSchema = z
  .object({
    approval_request_id: z.string().min(1),
    vote: z.enum(['APPROVED', 'REJECTED']),
    comment: z.string().max(1000).optional(),
  })
  .strict();

export const RecordExecutionSchema = z
  .object({
    decision_id: z.string().min(1),
    status: z.enum(['SUCCEEDED', 'FAILED']),
    result: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

/**
 * The enforced execution path.
 *
 * The caller presents the operation it believes it is about to perform. That
 * is a claim, not an input: the boundary canonicalises it, hashes it, and
 * compares it against the hash recorded when the grant was issued. A caller
 * that changes anything -- an amount, a recipient, an account -- produces a
 * mismatch and a security event rather than a wire.
 *
 * There is deliberately no status field. The caller does not report an
 * outcome here; Scrutexity performs the operation and determines the outcome
 * itself. A caller-reported outcome is what the legacy /v1/executions path
 * accepts, and it is not enforcement.
 */
export const ExecuteSchema = z
  .object({
    decision_id: z.string().min(1),
    operation: z
      .object({
        action: z.string().min(1).max(128),
        resource: ResourceRefSchema,
        context: z.record(z.string(), z.unknown()).default({}),
      })
      .strict(),
  })
  .strict();

export const CreatePolicyVersionSchema = z
  .object({
    /** The policy document, as YAML text or an already-parsed object. */
    document: z.union([z.string(), z.record(z.string(), z.unknown())]),
    policy_key: z
      .string()
      .regex(/^[a-z][a-z0-9_]{2,63}$/)
      .optional(),
  })
  .strict();

export const ReviewPolicyVersionSchema = z
  .object({ vote: z.enum(['APPROVED', 'REJECTED']), comment: z.string().max(1000).optional() })
  .strict();

export type AuthorizationRequestBody = z.infer<typeof AuthorizationRequestSchema>;
