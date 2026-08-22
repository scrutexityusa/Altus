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
