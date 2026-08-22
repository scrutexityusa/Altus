/**
 * Generates the published contracts from the code that implements them.
 *
 *   spec/openapi.json        -- the v1 HTTP contract
 *   spec/policy.schema.json  -- JSON Schema for an authored policy document
 *
 * Both are generated from the same Zod schemas the service validates against,
 * and CI runs this with `--check`. A published contract that describes
 * something the service does not do is worse than no contract at all: external
 * agent integrations are built against it.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { ERROR_CODES, GrantSchema, KNOWN_ACTIONS } from '@scrutexity/core';
import {
  AuthorizationRequestSchema,
  CreateAgentSchema,
  CreateResourceSchema,
  CreateUserSchema,
  IssueCredentialSchema,
  UpdateResourceSchema,
  UpdateUserSchema,
  CreateDelegationSchema,
  CreateLeaseSchema,
  CreatePolicyVersionSchema,
  IngestSignalSchema,
  ExecuteSchema,
  RecordExecutionSchema,
  ReviewPolicyVersionSchema,
  RegisterSignalKeySchema,
  RotateSignalKeySchema,
  RevokeLeaseSchema,
  SubmitApprovalSchema,
} from '../services/api/src/schemas.js';
import {
  ApprovalRequirementSchema,
  AuthorityEffectSchema,
  ConstraintsSchema,
  MatcherSchema,
  RuleSchema,
} from '@scrutexity/core';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');

// ---------------------------------------------------------------------------
// Policy JSON Schema
// ---------------------------------------------------------------------------

/**
 * The *authored* policy shape, which is what a policy author writes and a
 * linter or editor should validate against. It differs from the runtime Zod
 * schema in one respect worth stating: the runtime schema normalises authored
 * numbers into canonical decimal strings and money into exact minor units,
 * because the stored, hashed document must be canonical. JSON Schema cannot
 * express that transformation, so the authored form here accepts both.
 */
const AuthoredMoney = z
  .object({
    amount: z
      .union([z.string(), z.number()])
      .describe('Major-unit amount, e.g. "50000" or "50000.00"'),
    currency: z.string().length(3).describe('ISO 4217 code'),
  })
  .strict()
  .describe('An exact monetary amount. Fractional values must be strings to stay exact.');

const AuthoredScalar = z.union([z.string(), z.number(), z.boolean(), AuthoredMoney]);

const AuthoredMatcher = z
  .object({
    eq: AuthoredScalar.optional(),
    neq: AuthoredScalar.optional(),
    in: z.array(AuthoredScalar).min(1).optional(),
    nin: z.array(AuthoredScalar).min(1).optional(),
    lt: z.union([z.string(), z.number(), AuthoredMoney]).optional(),
    lte: z.union([z.string(), z.number(), AuthoredMoney]).optional(),
    gt: z.union([z.string(), z.number(), AuthoredMoney]).optional(),
    gte: z.union([z.string(), z.number(), AuthoredMoney]).optional(),
    exists: z.boolean().optional(),
    prefix: z.string().min(1).optional(),
  })
  .strict()
  .describe('Every declared operator must hold. There is no expression language.');

const AuthoredCondition: z.ZodType<unknown> = z.lazy(() =>
  z
    .record(
      z.string(),
      z.union([AuthoredMatcher, AuthoredScalar, z.array(AuthoredScalar), z.unknown()]),
    )
    .describe(
      'Selector -> matcher, combined with implicit AND. `all_of`, `any_of` and `not` take nested conditions. ' +
        'Selectors are a closed vocabulary: action, resource.type, resource.id, resource.attributes.*, ' +
        'agent.id, agent.handle, context.*, authority.present, authority.lease_id, authority.depth, ' +
        'signal.<type>.<agent|resource|counterparty|organization>[.value|.confidence].',
    ),
);

const AuthoredRule = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/),
    description: z.string().max(500).optional(),
    priority: z
      .number()
      .int()
      .min(0)
      .max(10_000)
      .default(100)
      .describe(
        'Lower evaluates first. Every rule is evaluated; the strictest matched decision wins.',
      ),
    when: AuthoredCondition,
    then: z
      .object({
        decision: z.enum(['ALLOW', 'DENY', 'ESCALATE']),
        reason_code: z
          .string()
          .regex(/^[A-Z][A-Z0-9_]{2,63}$/)
          .optional(),
        approval: z
          .object({
            required: z.boolean().default(true),
            quorum: z.number().int().min(1).default(1),
            roles: z.array(z.string().min(1)).default([]),
            forbid_self_approval: z.boolean().default(true),
            ttl_seconds: z.number().int().min(30).max(86_400).default(3600),
          })
          .strict()
          .optional()
          .describe(
            'Required when decision is ESCALATE. Merged across matched rules in the stricter direction.',
          ),
        authority_effect: z
          .object({
            remove_actions: z.array(z.string()).min(1).optional(),
            tighten: z.record(z.string(), z.unknown()).optional(),
            duration_seconds: z.number().int().min(1).max(2_592_000).optional(),
          })
          .strict()
          .optional()
          .describe(
            'Authority decay. Narrows what the agent may do unattended; never widens, never changes its role.',
          ),
        failure_mode: z.enum(['FAIL_OPEN', 'FAIL_CLOSED', 'ESCALATE']).optional(),
      })
      .strict(),
  })
  .strict();

const AuthoredPolicy = z
  .object({
    apiVersion: z.literal('scrutexity.dev/policy/v1'),
    id: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/),
    version: z
      .string()
      .regex(/^\d+\.\d+\.\d+$/)
      .describe('Semver. A version is immutable once activated.'),
    metadata: z
      .object({
        title: z.string().min(1).max(200),
        description: z.string().max(2000).optional(),
        owner: z.string().max(200).optional(),
        tags: z.array(z.string().max(50)).max(20).default([]),
      })
      .strict(),
    defaults: z
      .object({
        decision: z.enum(['ALLOW', 'DENY', 'ESCALATE']).default('DENY'),
        reason_code: z.string().default('NO_RULE_MATCHED'),
        execution_grant_ttl_seconds: z.number().int().min(5).max(86_400).default(300),
      })
      .strict()
      .optional(),
    failure_modes: z
      .object({
        policy_unavailable: z.enum(['FAIL_OPEN', 'FAIL_CLOSED', 'ESCALATE']).default('FAIL_CLOSED'),
        signal_unavailable: z.enum(['FAIL_OPEN', 'FAIL_CLOSED', 'ESCALATE']).default('FAIL_CLOSED'),
        enforcement_unavailable: z
          .enum(['FAIL_OPEN', 'FAIL_CLOSED', 'ESCALATE'])
          .default('FAIL_CLOSED'),
      })
      .strict()
      .optional(),
    delegation: z
      .object({
        enabled: z.boolean().default(true),
        max_depth: z.number().int().min(1).max(5).default(2),
        max_ttl_seconds: z.number().int().min(60).max(2_592_000).default(3600),
        non_delegable_actions: z.array(z.string()).default([]),
      })
      .strict()
      .optional(),
    issuance: z
      .object({
        enforced: z.boolean().default(true),
        ceilings: z
          .array(
            z
              .object({
                role: z.string().min(1).max(64),
                grant: z
                  .object({
                    actions: z.array(z.string()).min(1),
                    resources: z.record(z.string(), z.array(z.string()).min(1)).default({}),
                    constraints: z.record(z.string(), z.unknown()).default({}),
                  })
                  .strict(),
              })
              .strict(),
          )
          .max(50)
          .default([]),
      })
      .strict()
      .optional()
      .describe(
        'The ceiling each role may issue authority within. A role not named here may issue nothing.',
      ),
    intent: z.string().min(1).max(200).optional(),
    allowed_actions: z.array(z.string()).optional(),
    forbidden_actions: z.array(z.string()).optional(),
    intents: z
      .array(
        z
          .object({
            id: z.string(),
            description: z.string().optional(),
            allowed_actions: z.array(z.string()).default([]),
            forbidden_actions: z.array(z.string()).default([]),
          })
          .strict(),
      )
      .max(50)
      .optional(),
    intent_required: z.boolean().optional(),
    rules: z.array(AuthoredRule).min(1).max(500),
  })
  .strict()
  .describe('A Scrutexity policy document. Data, never code.');

function buildPolicySchema(): unknown {
  const schema = zodToJsonSchema(AuthoredPolicy, {
    name: 'ScrutexityPolicyDocument',
    $refStrategy: 'none',
    target: 'jsonSchema7',
  }) as Record<string, unknown>;
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'https://schemas.scrutexity.dev/policy/v1.json',
    title: 'Scrutexity policy document (v1)',
    ...schema,
  };
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

function jsonSchema(schema: z.ZodTypeAny, name: string): Record<string, unknown> {
  const generated = zodToJsonSchema(schema, {
    name,
    $refStrategy: 'none',
    target: 'jsonSchema7',
  }) as Record<string, unknown>;
  delete generated['$schema'];
  return generated;
}

const ERROR_SCHEMA = {
  type: 'object',
  required: ['error'],
  properties: {
    error: {
      type: 'object',
      required: ['code', 'message'],
      properties: {
        code: { type: 'string', enum: [...ERROR_CODES] },
        reason_code: {
          type: 'string',
          description:
            'The specific cause within `code`, from a closed documented vocabulary. Branch on this, not on the message.',
        },
        message: { type: 'string' },
        details: {},
        request_id: { type: 'string' },
      },
    },
  },
};

const DECISION_SCHEMA = {
  type: 'object',
  required: [
    'authorization_request_id',
    'decision_id',
    'receipt_id',
    'decision',
    'reason_code',
    'failover_behavior',
    'decision_timestamp',
  ],
  properties: {
    authorization_request_id: { type: 'string', example: 'areq_01JBX7Q8N2K3M4P5R6S7T8V9W0' },
    decision_id: { type: 'string' },
    receipt_id: { type: 'string', description: 'Evidence receipt covering this decision.' },
    approval_request_id: {
      type: ['string', 'null'],
      description: 'Present when the decision is ESCALATE. Submit approvals against it.',
    },
    decision: { type: 'string', enum: ['ALLOW', 'DENY', 'ESCALATE'] },
    reason_code: { type: 'string', example: 'TREASURER_APPROVAL_REQUIRED' },
    policy_id: { type: ['string', 'null'] },
    policy_version: { type: ['string', 'null'] },
    policy_hash: {
      type: ['string', 'null'],
      description: 'SHA-256 of the canonical policy document the decision was made under.',
    },
    authority_lease_id: { type: ['string', 'null'] },
    risk_signal_ids: { type: 'array', items: { type: 'string' } },
    constraints_evaluated: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          constraint: { type: 'string' },
          satisfied: { type: 'boolean' },
          applicable: {
            type: 'boolean',
            description: 'False when the action carries no value for this dimension.',
          },
          limit: {},
          observed: {},
          message: { type: 'string' },
        },
      },
    },
    approval_requirement: {
      type: ['object', 'null'],
      properties: {
        required: { type: 'boolean' },
        quorum: { type: 'integer' },
        roles: { type: 'array', items: { type: 'string' } },
        forbid_self_approval: { type: 'boolean' },
        ttl_seconds: { type: 'integer' },
      },
    },
    intent_evaluation: {
      oneOf: [{ $ref: '#/components/schemas/IntentEvaluation' }, { type: 'null' }],
    },
    corrective_actions: {
      type: 'array',
      items: { $ref: '#/components/schemas/CorrectiveAction' },
      description: 'Empty for an ALLOW, and empty for a hard violation.',
    },
    context_hash: {
      type: ['string', 'null'],
      description:
        'Fingerprint of every input this decision rests on. Recomputed at execution; if it has moved, the action is refused rather than reconciled.',
    },
    exact_intent_hash: {
      type: ['string', 'null'],
      pattern: '^[0-9a-f]{64}$',
      description:
        'SHA-256 of the exact operation this ALLOW authorises, projected onto the action catalog. Answers "did the operation mutate?". Null unless the decision was ALLOW. Computed by the server from the request it evaluated; it is not an input, and a request that supplies one is rejected.',
    },
    binding_hash: {
      type: ['string', 'null'],
      pattern: '^[0-9a-f]{64}$',
      description:
        'SHA-256 of the operation together with the decision, lease, policy version and approved context that authorised it. Answers "is this operation bound to this authority decision?". A replay of a genuine, unmutated operation under a different decision matches exact_intent_hash and fails this. Null unless the decision was ALLOW.',
    },
    failover_behavior: { type: 'string', enum: ['FAIL_OPEN', 'FAIL_CLOSED', 'ESCALATE'] },
    expires_at: {
      type: ['string', 'null'],
      format: 'date-time',
      description: 'When the execution grant lapses. Null unless the decision was ALLOW.',
    },
    decision_timestamp: { type: 'string', format: 'date-time' },
  },
};

const IDEMPOTENCY_HEADER = {
  name: 'Idempotency-Key',
  in: 'header',
  required: false,
  schema: { type: 'string', maxLength: 255 },
  description:
    'Makes a retry safe. The key is claimed in the same transaction as the effect, so a duplicate replays the stored response rather than repeating the work. Reusing a key with a different body returns IDEMPOTENCY_CONFLICT.',
};

const REQUEST_ID_HEADER = {
  name: 'X-Request-Id',
  in: 'header',
  required: false,
  schema: { type: 'string', maxLength: 128 },
  description:
    'Correlation id echoed on the response and present on every log line for this request.',
};

function jsonBody(schema: unknown, description?: string) {
  return {
    required: true,
    ...(description ? { description } : {}),
    content: { 'application/json': { schema } },
  };
}

function jsonResponse(description: string, schema: unknown) {
  return { description, content: { 'application/json': { schema } } };
}

const ERROR_RESPONSES = {
  '400': jsonResponse('The request is invalid.', { $ref: '#/components/schemas/Error' }),
  '401': jsonResponse('Authentication is required.', { $ref: '#/components/schemas/Error' }),
  '403': jsonResponse('The caller is not permitted to perform this operation.', {
    $ref: '#/components/schemas/Error',
  }),
  '404': jsonResponse('Not found, or not visible to this tenant.', {
    $ref: '#/components/schemas/Error',
  }),
  '409': jsonResponse('Replay, idempotency conflict or state conflict.', {
    $ref: '#/components/schemas/Error',
  }),
  '503': jsonResponse('A dependency of the decision was unavailable.', {
    $ref: '#/components/schemas/Error',
  }),
};

function buildOpenApi(): unknown {
  return {
    openapi: '3.0.3',
    info: {
      title: 'Scrutexity Authority Control Plane',
      version: '1.0.0',
      description: [
        'Runtime authorization for high-consequence agent actions.',
        '',
        'The API answers one question: was this agent authorized to perform this action,',
        'on this resource, under this context, at this exact point in time -- and it answers',
        'it deterministically, with evidence.',
        '',
        '## Tenancy',
        'The organization is derived from the authenticated credential. There is no tenant',
        'header and no tenant field in any request body: a client that could name its own',
        'tenant would have defeated isolation in one line.',
        '',
        '## Decisions are not errors',
        'POST /v1/authorization/evaluate returns 200 for ALLOW, DENY and ESCALATE alike.',
        'A denial is a successful evaluation that answered "no"; returning 4xx would',
        'conflate it with a malformed request. Branch on `decision`, never on status.',
        '',
        '## Caching',
        'Never cache a decision. It is valid only for the policy version, authority lease',
        'and signal state it was made under, none of which the client can observe changing.',
        'An ALLOW carries `expires_at` and is single-use against POST /v1/executions.',
      ].join('\n'),
      license: { name: 'MIT' },
    },
    servers: [
      { url: 'https://api.scrutexity.dev', description: 'Hosted control plane' },
      { url: 'http://localhost:8080', description: 'Local development' },
    ],
    tags: [
      { name: 'Agents', description: 'Machine identities and their human owners' },
      { name: 'Authority', description: 'Authority leases and delegation' },
      { name: 'Authorization', description: 'Runtime decisions and execution grants' },
      { name: 'Signals', description: 'Risk assertions from external systems' },
      { name: 'Approvals', description: 'Human decisions on escalated actions' },
      { name: 'Evidence', description: 'Tamper-evident receipts and their verification' },
      { name: 'Policy', description: 'Policy versions and their lifecycle' },
      { name: 'Operations', description: 'Health, readiness and metrics' },
    ],
    security: [{ bearerAuth: [] }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          description: [
            'A credential issued to one agent, one human, or one service, in the form',
            '`scr_<prefix>.<secret>`. The credential determines the tenant *and* the',
            'principal: an agent credential cannot administer the control plane, cannot',
            'issue itself authority, and cannot stand in for a human approver.',
          ].join(' '),
        },
      },
      schemas: {
        Error: ERROR_SCHEMA,
        AuthorizationDecision: DECISION_SCHEMA,
        AuthorityGrant: {
          ...jsonSchema(GrantSchema, 'AuthorityGrant'),
          description: [
            'A point in the authority lattice. `actions` and `resources` form the envelope --',
            'what the agent is for -- and a request outside it is denied terminally.',
            '`constraints` are autonomy limits: exceeding one escalates to a human when policy',
            'names an approver, and is denied when it does not. An omitted resource type grants',
            'nothing for that type.',
          ].join(' '),
        },
        Constraints: jsonSchema(ConstraintsSchema, 'Constraints'),
        ApprovalRequirement: jsonSchema(ApprovalRequirementSchema, 'ApprovalRequirement'),
        AuthorityEffect: jsonSchema(AuthorityEffectSchema, 'AuthorityEffect'),
        PolicyRule: jsonSchema(RuleSchema, 'PolicyRule'),
        PolicyMatcher: jsonSchema(MatcherSchema, 'PolicyMatcher'),
        CreateAgentRequest: jsonSchema(CreateAgentSchema, 'CreateAgentRequest'),
        CreateUserRequest: jsonSchema(CreateUserSchema, 'CreateUserRequest'),
        UpdateUserRequest: jsonSchema(UpdateUserSchema, 'UpdateUserRequest'),
        IssueCredentialRequest: jsonSchema(IssueCredentialSchema, 'IssueCredentialRequest'),
        CreateResourceRequest: jsonSchema(CreateResourceSchema, 'CreateResourceRequest'),
        UpdateResourceRequest: jsonSchema(UpdateResourceSchema, 'UpdateResourceRequest'),
        AuthorizationRequest: {
          ...jsonSchema(AuthorizationRequestSchema, 'AuthorizationRequest'),
          description: [
            'Money in `context` must be an exact decimal string plus a currency; a fractional',
            'JSON number is refused rather than compared. `counterparty_known` and',
            '`counterparty_status` are derived by the control plane from the tenant register and',
            'any caller-supplied value is discarded.',
          ].join(' '),
        },
        CreateLeaseRequest: jsonSchema(CreateLeaseSchema, 'CreateLeaseRequest'),
        RevokeLeaseRequest: jsonSchema(RevokeLeaseSchema, 'RevokeLeaseRequest'),
        CreateDelegationRequest: {
          ...jsonSchema(CreateDelegationSchema, 'CreateDelegationRequest'),
          description:
            'The requested grant must be contained by the parent lease on every axis. A request that widens any axis is refused with DELEGATION_EXCEEDS_PARENT rather than silently clamped; only the lifetime is clamped, to the parent expiry and the policy maximum.',
        },
        IngestSignalRequest: jsonSchema(IngestSignalSchema, 'IngestSignalRequest'),
        SubmitApprovalRequest: jsonSchema(SubmitApprovalSchema, 'SubmitApprovalRequest'),
        RecordExecutionRequest: jsonSchema(RecordExecutionSchema, 'RecordExecutionRequest'),
        ExecuteRequest: jsonSchema(ExecuteSchema, 'ExecuteRequest'),
        CreatePolicyVersionRequest: jsonSchema(
          CreatePolicyVersionSchema,
          'CreatePolicyVersionRequest',
        ),
        ReviewPolicyVersionRequest: jsonSchema(
          ReviewPolicyVersionSchema,
          'ReviewPolicyVersionRequest',
        ),
        Receipt: {
          type: 'object',
          required: ['id', 'seq', 'kind', 'payload_hash', 'previous_hash', 'hash'],
          properties: {
            id: { type: 'string' },
            organization_id: { type: 'string' },
            seq: {
              type: 'integer',
              description: 'Position in this tenant chain. Chains are per-tenant.',
            },
            kind: {
              type: 'string',
              enum: [
                'AUTHORIZATION_DECISION',
                'APPROVAL',
                'EXECUTION',
                'LEASE_ISSUED',
                'LEASE_REVOKED',
                'DELEGATION_CREATED',
                'SIGNAL_INGESTED',
                'POLICY_ACTIVATED',
              ],
            },
            payload: { type: 'object' },
            payload_hash: { type: 'string', pattern: '^[0-9a-f]{64}$' },
            previous_hash: { type: 'string', pattern: '^[0-9a-f]{64}$' },
            hash: { type: 'string', pattern: '^[0-9a-f]{64}$' },
            signature: { type: ['string', 'null'], description: 'Ed25519 over `hash`, base64url.' },
            signing_key_id: { type: ['string', 'null'] },
            created_at: { type: 'string', format: 'date-time' },
          },
        },
        VerificationResult: {
          type: 'object',
          properties: {
            receipt_id: { type: 'string' },
            integrity: { type: 'string', enum: ['INTACT', 'COMPROMISED'] },
            attests: {
              type: 'string',
              enum: ['evidence_integrity_and_provenance'],
              description:
                'What the cryptography establishes: that this evidence is what was written, in the order it was written, by the holder of the signing key. It does not attest that the decision recorded was correct or lawful.',
            },
            receipt_verification: { type: 'object' },
            chain_verification: { type: 'object' },
          },
        },
        Explanation: {
          type: 'object',
          description:
            'Assembled deterministically from the structured decision record. No language model is involved: the same decision always renders the same explanation.',
          properties: {
            decision: { type: 'string' },
            reason_code: { type: 'string' },
            headline: { type: 'string' },
            facts: {
              type: 'object',
              description: 'The five questions, kept separate rather than blended into prose.',
              properties: {
                what: { type: 'string' },
                authority: { type: 'string' },
                policy: { type: 'string' },
                signals: { type: 'string' },
                approvals: { type: 'string' },
                why: { type: 'string' },
              },
            },
            sections: { type: 'array', items: { type: 'object' } },
            text: { type: 'string' },
          },
        },
      },
      parameters: {
        IdempotencyKey: IDEMPOTENCY_HEADER,
        RequestId: REQUEST_ID_HEADER,
      },
    },
    paths: {
      '/v1/users': {
        post: {
          tags: ['Tenant setup'],
          summary: 'Create a human principal',
          description:
            'Requires `admin:write` and a human caller. Not an identity system: no password, ' +
            'no session, no directory sync. A user exists so an approval can name who gave it ' +
            'and so a policy’s approval roles have something to match against. `roles` is the ' +
            'tenant’s own vocabulary.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/CreateUserRequest' }),
          responses: {
            '201': jsonResponse('The user was created.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
        get: {
          tags: ['Tenant setup'],
          summary: 'List the humans in this tenant',
          responses: { '200': jsonResponse('Users.', { type: 'object' }), ...ERROR_RESPONSES },
        },
      },
      '/v1/users/{id}': {
        get: {
          tags: ['Tenant setup'],
          summary: 'User detail',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': jsonResponse('User.', { type: 'object' }), ...ERROR_RESPONSES },
        },
        patch: {
          tags: ['Tenant setup'],
          summary: 'Change roles, display name, or disable',
          description:
            'Disabling is terminal rather than deletion: a user who approved a payment must ' +
            'remain nameable forever, and an approval whose approver cannot be named is not ' +
            'evidence of anything.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: jsonBody({ $ref: '#/components/schemas/UpdateUserRequest' }),
          responses: { '200': jsonResponse('User.', { type: 'object' }), ...ERROR_RESPONSES },
        },
      },
      '/v1/credentials': {
        post: {
          tags: ['Tenant setup'],
          summary: 'Issue a credential to a principal in this tenant',
          description:
            'Requires `admin:write` and a human caller. The secret is generated server-side and ' +
            'returned **exactly once**; Scrutexity stores a SHA-256 and a non-secret lookup ' +
            'prefix, and no endpoint can produce the token again.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/IssueCredentialRequest' }),
          responses: {
            '201': jsonResponse('The credential and its one-time token.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
        get: {
          tags: ['Tenant setup'],
          summary: 'List credentials — operational metadata only',
          description: 'Never returns token or hash material. Includes `last_used_at`.',
          responses: {
            '200': jsonResponse('Credentials.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/credentials/{id}/revoke': {
        post: {
          tags: ['Tenant setup'],
          summary: 'Revoke a credential',
          description:
            'Immediate. Authentication reads status on every request and there is no credential ' +
            'cache, so the next call with this token is a 401.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('The revoked credential.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/resources': {
        post: {
          tags: ['Tenant setup'],
          summary: 'Register a bank account or counterparty',
          description:
            'Requires `admin:write` and a human caller. `counterparty_known` is derived from the ' +
            'EXISTENCE of a row here and never from anything a caller asserts, so registering a ' +
            'counterparty is the act that makes money movable to it. An agent cannot do this.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/CreateResourceRequest' }),
          responses: {
            '201': jsonResponse('The resource was registered.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
        get: {
          tags: ['Tenant setup'],
          summary: 'List registered resources',
          parameters: [{ name: 'resource_type', in: 'query', schema: { type: 'string' } }],
          responses: { '200': jsonResponse('Resources.', { type: 'object' }), ...ERROR_RESPONSES },
        },
      },
      '/v1/resources/{id}': {
        patch: {
          tags: ['Tenant setup'],
          summary: 'Update a resource’s display name or policy-readable attributes',
          description:
            'Deliberately no delete: a counterparty that has been paid is referenced by decisions ' +
            'and receipts. To stop paying one, change the attribute the policy reads — the refusal ' +
            'is then a policy decision with a reason code.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: jsonBody({ $ref: '#/components/schemas/UpdateResourceRequest' }),
          responses: { '200': jsonResponse('Resource.', { type: 'object' }), ...ERROR_RESPONSES },
        },
      },
      '/v1/agents': {
        post: {
          tags: ['Agents'],
          summary: 'Register a machine identity',
          description:
            'Requires the `admin:write` scope. An agent credential cannot create agents, including itself.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/CreateAgentRequest' }),
          responses: {
            '201': jsonResponse('The agent was registered.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
        get: {
          tags: ['Agents'],
          summary: 'List the agents in this tenant',
          responses: { '200': jsonResponse('Agents.', { type: 'object' }), ...ERROR_RESPONSES },
        },
      },
      '/v1/agents/{id}': {
        get: {
          tags: ['Agents'],
          summary: 'Agent detail: identity, live authority, delegations, signals, recent decisions',
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string' },
              description: 'Agent id or handle.',
            },
          ],
          responses: {
            '200': jsonResponse('Agent detail.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/authority-leases': {
        post: {
          tags: ['Authority'],
          summary: 'Issue a scoped, time-bounded authority lease',
          description:
            'Requires `leases:write`. Authority is never a boolean permission: a lease is scoped to actions and resources, constrained, time-bounded, revocable and attributable to the policy version it was issued under.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/CreateLeaseRequest' }),
          responses: {
            '201': jsonResponse('The lease was issued.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/authority-leases/{id}': {
        get: {
          tags: ['Authority'],
          summary: 'Read a lease and its full ancestry',
          description:
            'Returns `status` (the stored disposition) alongside `effective_status` (what an authorization decision would conclude right now, on the database clock). They differ for a lease that has simply run out of time: nothing rewrites rows when a clock passes them, so `status` still reads ACTIVE while `effective_status` reads EXPIRED. Read the second one to know whether the authority is usable.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('Lease and ancestry.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/authority-leases/{id}/revoke': {
        post: {
          tags: ['Authority'],
          summary: 'Revoke a lease immediately',
          description:
            'Takes effect on the next decision, with no grace period and no cache to invalidate. Descendants of a revoked lease stop authorizing at the same instant, because the evaluator walks the ancestry on every decision.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: jsonBody({ $ref: '#/components/schemas/RevokeLeaseRequest' }),
          responses: {
            '200': jsonResponse('The lease was revoked.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/delegations': {
        post: {
          tags: ['Authority'],
          summary: 'Delegate a narrowed subset of held authority to another agent',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/CreateDelegationRequest' }),
          responses: {
            '201': jsonResponse('The delegation was created.', { type: 'object' }),
            '422': jsonResponse(
              'The requested authority exceeds the parent. The response names the axis that failed.',
              { $ref: '#/components/schemas/Error' },
            ),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/authorization-requests': {
        post: {
          tags: ['Authorization'],
          summary: 'Submit an authorization request and evaluate it',
          description:
            'Creates the immutable request record and returns the decision. Historical requests are never mutated; a re-evaluation after approval produces a *new* decision that supersedes the escalation.',
          parameters: [
            { $ref: '#/components/parameters/IdempotencyKey' },
            { $ref: '#/components/parameters/RequestId' },
          ],
          requestBody: jsonBody({ $ref: '#/components/schemas/AuthorizationRequest' }),
          responses: {
            '200': jsonResponse(
              'The request was evaluated. ALLOW, DENY and ESCALATE all return 200.',
              { $ref: '#/components/schemas/AuthorizationDecision' },
            ),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/authorization/evaluate': {
        post: {
          tags: ['Authorization'],
          summary: 'Evaluate an authorization request (verb-shaped alias)',
          description:
            'Identical to POST /v1/authorization-requests, sharing one implementation. It exists because SDK callers reach for a verb rather than a resource.',
          parameters: [
            { $ref: '#/components/parameters/IdempotencyKey' },
            { $ref: '#/components/parameters/RequestId' },
          ],
          requestBody: jsonBody({ $ref: '#/components/schemas/AuthorizationRequest' }),
          responses: {
            '200': jsonResponse('The request was evaluated.', {
              $ref: '#/components/schemas/AuthorizationDecision',
            }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/authorization-decisions/{id}': {
        get: {
          tags: ['Authorization'],
          summary: 'Why was this allowed, denied or escalated',
          description: [
            'The full decision record: who, what, why, under which policy version and hash, under',
            'which authority, with which signals, with which approvals, with which constraints,',
            'and what happened. Machine-readable first; the attached explanation is assembled',
            'deterministically from the same facts.',
          ].join(' '),
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('The decision, its inputs and its explanation.', {
              type: 'object',
              properties: {
                decision: { $ref: '#/components/schemas/AuthorizationDecision' },
                request: { type: 'object' },
                approvals: { type: 'array', items: { type: 'object' } },
                receipt: { type: ['object', 'null'] },
                execution: { type: ['object', 'null'] },
                explanation: { $ref: '#/components/schemas/Explanation' },
              },
            }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/execute': {
        post: {
          tags: ['Execution'],
          summary: 'Execute the exact operation an ALLOW authorised',
          description:
            'The enforcement boundary. The caller presents the operation it believes it is about to perform; Scrutexity canonicalises it, recomputes both the intent hash and the binding hash, checks the authority is still live, claims execution rights atomically, and only then calls the provider under a key derived from the grant. A mutated operation is refused before the external system is contacted, and the refusal is recorded as a security event that survives the rolled-back transaction. This is the only path on which Scrutexity performs the operation itself.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/ExecuteRequest' }),
          responses: {
            '200': jsonResponse(
              'The recorded outcome of an earlier execution against this authorization. `replayed` is true, nothing was created, and the provider was not called again. A client retrying after a network failure gets its answer here rather than a second payment.',
              { type: 'object' },
            ),
            '201': jsonResponse(
              'The operation was executed, or the provider reported a definite failure, or the provider did not answer. Read `status`: EXECUTED, FAILED or UNKNOWN. UNKNOWN is never reported as FAILED -- "the wire did not go" and "I do not know whether the wire went" call for opposite responses.',
              { type: 'object' },
            ),
            // Spread first, so the descriptions below replace the generic ones
            // rather than being silently overwritten by them.
            ...ERROR_RESPONSES,
            '403': jsonResponse(
              'The operation does not match the one that was authorised (INTENT_MISMATCH, with the diverging field names in `details.mutated_fields`), the authority behind it is revoked or expired, or the decision belongs to another agent. The external system was not contacted.',
              { $ref: '#/components/schemas/Error' },
            ),
            '409': jsonResponse(
              'EXECUTION_UNRESOLVED: an execution against this authorization is in flight, or reached the provider and was interrupted before its outcome was recorded. It must be reconciled -- see GET /v1/executions/unresolved -- and resubmitted under the same idempotency key. This is deliberately not REPLAY_DETECTED: a replay means "already done", this means "may or may not have been done".',
              { $ref: '#/components/schemas/Error' },
            ),
          },
        },
      },
      '/v1/executions/unresolved': {
        get: {
          tags: ['Execution'],
          summary: 'Execution claims that were started and never settled',
          description:
            'A claim is EXECUTING while a provider call is in flight and UNKNOWN when the provider did not answer. Either state means authority was spent and this system does not know what happened at the other end; only the external system can settle it. Each row carries the idempotency key the provider was called under, which is what a reconciliation job must ask the provider about. Pass `older_than_seconds` to exclude claims that are simply still in progress.',
          parameters: [
            {
              name: 'older_than_seconds',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 0, maximum: 86400 },
            },
          ],
          responses: {
            '200': jsonResponse('Unresolved claims, oldest first.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/executions': {
        post: {
          tags: ['Authorization'],
          summary: 'Record an execution against an ALLOW decision',
          description:
            'An ALLOW is a single-use, time-boxed execution grant. Presenting it twice is a replay and is refused by a unique constraint, not by a check a race could slip past.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/RecordExecutionRequest' }),
          responses: {
            '201': jsonResponse('The execution was recorded.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/signals': {
        post: {
          tags: ['Signals'],
          summary: 'Publish a risk signal',
          description: [
            'Scrutexity does not detect fraud or score anomalies. It consumes assertions from',
            'systems that do and turns them into authority consequences. Every signal carries a',
            'TTL and is simply not read once it lapses, so no stale assertion can suppress an',
            "agent's authority indefinitely. A newer assertion from the same source supersedes",
            'the older one.',
          ].join(' '),
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/IngestSignalRequest' }),
          responses: {
            '201': jsonResponse('The signal was ingested.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/approval-requests': {
        get: {
          tags: ['Approvals'],
          summary: 'List pending approval requests',
          responses: {
            '200': jsonResponse('Pending approvals.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/approvals': {
        post: {
          tags: ['Approvals'],
          summary: 'Record a human decision on an escalated action',
          description: [
            'Requires a human principal and the `approvals:write` scope; an agent credential is',
            'refused. What is recorded is the person, the roles they actually held at that',
            'instant, and the requirement their authority satisfied. Recording an approval',
            're-evaluates the original request and produces a superseding decision.',
          ].join(' '),
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/SubmitApprovalRequest' }),
          responses: {
            '201': jsonResponse('The approval was recorded.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/receipts/{id}': {
        get: {
          tags: ['Evidence'],
          summary: 'Read an evidence receipt',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('The receipt.', {
              type: 'object',
              properties: { receipt: { $ref: '#/components/schemas/Receipt' } },
            }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/receipts/{id}/verify': {
        post: {
          tags: ['Evidence'],
          summary: 'Verify a stored receipt and its chain segment',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('The verification result.', {
              $ref: '#/components/schemas/VerificationResult',
            }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/receipts/verify': {
        post: {
          tags: ['Evidence'],
          summary: 'Verify a receipt supplied by the caller',
          description:
            'Verifies a receipt held outside the platform and reports whether it also matches the stored record. Use this when auditing an exported evidence bundle.',
          requestBody: jsonBody({
            type: 'object',
            required: ['receipt'],
            properties: { receipt: { $ref: '#/components/schemas/Receipt' } },
          }),
          responses: {
            '200': jsonResponse('The verification result.', {
              $ref: '#/components/schemas/VerificationResult',
            }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/policy-versions': {
        post: {
          tags: ['Policy'],
          summary: 'Create an immutable policy version in DRAFT',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/CreatePolicyVersionRequest' }),
          responses: {
            '201': jsonResponse('The policy version was created.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
        get: {
          tags: ['Policy'],
          summary: 'List policy versions and their lifecycle state',
          responses: {
            '200': jsonResponse('Policy versions.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/policy-versions/{id}/reviews': {
        post: {
          tags: ['Policy'],
          summary: 'Review a policy version',
          description:
            'Dual control: two distinct humans, neither of them the author, must approve before a version can be activated. One rejection returns it to DRAFT.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: jsonBody({ $ref: '#/components/schemas/ReviewPolicyVersionRequest' }),
          responses: {
            '201': jsonResponse('The review was recorded.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/policy-versions/{id}/activate': {
        post: {
          tags: ['Policy'],
          summary: 'Activate an approved policy version',
          description:
            'Deprecates the currently active version and takes effect for subsequent decisions. The document is re-hashed and checked against its recorded digest first.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('The version is now active.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/trace/{id}': {
        get: {
          tags: ['Evidence'],
          summary: 'Root-cause trace: where the authority behind a decision came from',
          description: [
            'Walks backwards from a decision to its origin and returns the chain in causal',
            'order, oldest cause first -- policy activation, the authority it admitted, any',
            'delegation, the request, the signals that were read, the humans who approved,',
            'the decision, and what was done with it. Each node carries a timestamp and the',
            'causal edge that produced the next one. A database traversal: deterministic,',
            'replayable, and never summarised.',
          ].join(' '),
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string' },
              description: 'Decision id.',
            },
          ],
          responses: {
            '200': jsonResponse('The causal chain.', {
              type: 'object',
              properties: {
                decision_id: { type: 'string' },
                root_cause: { $ref: '#/components/schemas/TraceNode' },
                trace: { type: 'array', items: { $ref: '#/components/schemas/TraceNode' } },
                complete: {
                  type: 'boolean',
                  description:
                    'True when the chain reaches a policy activation rather than stopping short.',
                },
              },
            }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/signal-keys': {
        post: {
          tags: ['Signals'],
          summary: 'Register a signing key for a signal source',
          description:
            'Ed25519 is preferred: only the public key is stored, so a database disclosure yields nothing an attacker can sign with. Key material is never echoed back.',
          parameters: [{ $ref: '#/components/parameters/IdempotencyKey' }],
          requestBody: jsonBody({ $ref: '#/components/schemas/RegisterSignalKeyRequest' }),
          responses: {
            '201': jsonResponse('The key was registered.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
        get: {
          tags: ['Signals'],
          summary: 'List signing keys and their rotation state',
          responses: {
            '200': jsonResponse('Signing keys.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/signal-keys/{id}/retire': {
        post: {
          tags: ['Signals'],
          summary: 'Retire a key with a grace period',
          description:
            'The outgoing key stays valid for the grace period so the source can switch over without dropping signals. Use revoke instead when a key is believed compromised.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: jsonBody({ $ref: '#/components/schemas/RotateSignalKeyRequest' }),
          responses: {
            '200': jsonResponse('The key is retiring.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/signal-keys/{id}/revoke': {
        post: {
          tags: ['Signals'],
          summary: 'Revoke a key immediately, with no grace period',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': jsonResponse('The key was revoked.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/security-events': {
        get: {
          tags: ['Operations'],
          summary: 'Security events: rejected signatures, replays, key revocations',
          description:
            'Queryable without access to application logs, because an operator investigating a rejected signal should not need a shell on a production node.',
          responses: {
            '200': jsonResponse('Security events.', { type: 'object' }),
            ...ERROR_RESPONSES,
          },
        },
      },
      '/v1/overview': {
        get: {
          tags: ['Agents'],
          summary:
            'Dashboard read model: agents, live authority, pending approvals, recent decisions, live signals',
          description:
            'One read model behind the dashboard, so the UI cannot disagree with the API about what happened.',
          responses: { '200': jsonResponse('Overview.', { type: 'object' }), ...ERROR_RESPONSES },
        },
      },
      '/health': {
        get: {
          tags: ['Operations'],
          security: [],
          summary: 'Liveness',
          description:
            'Deliberately does not touch the database: a liveness probe that fails on a database blip restarts a healthy service.',
          responses: { '200': jsonResponse('The process is up.', { type: 'object' }) },
        },
      },
      '/ready': {
        get: {
          tags: ['Operations'],
          security: [],
          summary: 'Readiness -- this instance can make decisions',
          responses: {
            '200': jsonResponse('Ready.', { type: 'object' }),
            '503': jsonResponse('Not ready.', { type: 'object' }),
          },
        },
      },
      '/metrics': {
        get: {
          tags: ['Operations'],
          security: [],
          summary: 'Prometheus metrics',
          responses: { '200': { description: 'Metrics in Prometheus text format.' } },
        },
      },
    },
    'x-action-catalog': {
      description:
        'Actions are a closed vocabulary, so a typo cannot become a bypass and a money-bearing action can never reach the decision point without an amount.',
      actions: KNOWN_ACTIONS,
    },
  };
}

// ---------------------------------------------------------------------------

const artifacts: Array<{ path: string; content: string }> = [
  {
    path: join(root, 'spec', 'openapi.json'),
    content: JSON.stringify(buildOpenApi(), null, 2) + '\n',
  },
  {
    path: join(root, 'spec', 'policy.schema.json'),
    content: JSON.stringify(buildPolicySchema(), null, 2) + '\n',
  },
];

let drifted = false;
for (const artifact of artifacts) {
  if (check) {
    let existing = '';
    try {
      existing = readFileSync(artifact.path, 'utf8');
    } catch {
      existing = '';
    }
    if (existing !== artifact.content) {
      drifted = true;
      process.stderr.write(
        `drift: ${artifact.path} is out of date -- run \`pnpm spec:generate\`\n`,
      );
    } else {
      process.stdout.write(`  = ${artifact.path}\n`);
    }
  } else {
    writeFileSync(artifact.path, artifact.content);
    process.stdout.write(`  + ${artifact.path}\n`);
  }
}

if (drifted) process.exit(1);
