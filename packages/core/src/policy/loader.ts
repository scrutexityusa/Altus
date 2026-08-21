import { parse as parseYaml } from 'yaml';
import { ScrutexityError } from '../errors.js';
import { PolicyDocumentSchema, type PolicyDocument } from './schema.js';
import { policyHash } from './engine.js';

export interface LoadedPolicy {
  document: PolicyDocument;
  hash: string;
}

function describe(issues: { path: (string | number)[]; message: string }[]): string {
  return issues
    .map((issue) => `${issue.path.length ? issue.path.join('.') : '<root>'}: ${issue.message}`)
    .join('; ');
}

/**
 * Parses and validates a policy document. Validation is total -- a document
 * that loads is guaranteed evaluable, so there is no class of policy error
 * that first appears at 2am while a wire is pending.
 */
export function loadPolicyDocument(input: unknown): LoadedPolicy {
  const parsed = PolicyDocumentSchema.safeParse(input);
  if (!parsed.success) {
    throw new ScrutexityError('INVALID_REQUEST', `invalid policy document: ${describe(parsed.error.issues)}`, {
      details: parsed.error.issues,
    });
  }
  return { document: parsed.data, hash: policyHash(parsed.data) };
}

export function loadPolicyYaml(source: string): LoadedPolicy {
  let raw: unknown;
  try {
    raw = parseYaml(source, { merge: false });
  } catch (error) {
    throw new ScrutexityError('INVALID_REQUEST', `policy YAML is not parseable: ${String(error)}`);
  }
  return loadPolicyDocument(raw);
}
