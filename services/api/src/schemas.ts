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
    metadata: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

export const RevokeLeaseSchema = z
  .object({ reason: z.string().min(3).max(500) })
  .strict();

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
    metadata: z.record(z.string(), z.unknown()).default({}),
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

export const CreatePolicyVersionSchema = z
  .object({
    /** The policy document, as YAML text or an already-parsed object. */
    document: z.union([z.string(), z.record(z.string(), z.unknown())]),
    policy_key: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/).optional(),
  })
  .strict();

export const ReviewPolicyVersionSchema = z
  .object({ vote: z.enum(['APPROVED', 'REJECTED']), comment: z.string().max(1000).optional() })
  .strict();

export type AuthorizationRequestBody = z.infer<typeof AuthorizationRequestSchema>;
