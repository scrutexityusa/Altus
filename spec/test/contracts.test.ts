import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
// ajv and ajv-formats are CommonJS. Under NodeNext their types describe the
// module namespace, while the value the bundler hands us at runtime is the
// callable default. `createRequire` gets both to agree without pretending the
// namespace is constructible.
import { createRequire } from 'node:module';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';

/**
 * The published contracts must describe the running system.
 *
 * These tests are the reason `spec/` can be trusted: the policy schema is
 * checked against the policy pack the platform actually ships, and the OpenAPI
 * document is checked against the routes the service actually registers. A
 * contract that drifts from the implementation is worse than no contract,
 * because integrators build against it.
 */

const root = fileURLToPath(new URL('../../', import.meta.url));
const openapi = JSON.parse(readFileSync(join(root, 'spec/openapi.json'), 'utf8'));
const policySchema = JSON.parse(readFileSync(join(root, 'spec/policy.schema.json'), 'utf8'));

describe('policy JSON Schema', () => {
  const require = createRequire(import.meta.url);
  const Ajv = require('ajv') as new (options: Record<string, unknown>) => {
    compile: (schema: unknown) => ((data: unknown) => boolean) & { errors?: unknown };
  };
  const addFormats = require('ajv-formats') as (ajv: unknown) => void;
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(policySchema);

  it('accepts every policy pack the platform ships', () => {
    const policyDir = join(root, 'policies');
    const files = readdirSync(policyDir).filter((f) => f.endsWith('.yaml'));
    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      const document = parseYaml(readFileSync(join(policyDir, file), 'utf8'));
      const valid = validate(document);
      expect(valid, `${file}: ${JSON.stringify(validate.errors, null, 2)}`).toBe(true);
    }
  });

  it('rejects a document with an unknown top-level key', () => {
    const document = parseYaml(readFileSync(join(root, 'policies/treasury_wire.yaml'), 'utf8'));
    expect(validate({ ...document, backdoor: true })).toBe(false);
  });

  it('rejects a rule with no decision', () => {
    const document = parseYaml(readFileSync(join(root, 'policies/treasury_wire.yaml'), 'utf8'));
    document.rules[0].then = {};
    expect(validate(document)).toBe(false);
  });
});

describe('OpenAPI document', () => {
  it('is a valid OpenAPI 3.0 document with a security scheme', () => {
    expect(openapi.openapi).toMatch(/^3\.0\./);
    expect(openapi.info.title).toBeTruthy();
    expect(openapi.components.securitySchemes.bearerAuth.scheme).toBe('bearer');
    expect(openapi.security).toEqual([{ bearerAuth: [] }]);
  });

  it('documents every endpoint the service registers', async () => {
    const { buildApp } = await import('../../services/api/src/app.js');
    const app = await buildApp({
      NODE_ENV: 'test',
      DATABASE_URL:
        process.env['DATABASE_URL'] ??
        'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity',
      LOG_LEVEL: 'silent',
    });
    try {
      const registered = new Set(app.routes);

      const documented = new Set<string>();
      for (const [path, operations] of Object.entries(openapi.paths as Record<string, object>)) {
        for (const method of Object.keys(operations)) {
          documented.add(`${method.toUpperCase()} ${path.replace(/\{(\w+)\}/g, ':$1')}`);
        }
      }

      const undocumented = [...registered].filter((route) => !documented.has(route)).sort();
      expect(undocumented, 'these routes exist but are not in the OpenAPI document').toEqual([]);

      const phantom = [...documented].filter((route) => !registered.has(route)).sort();
      expect(phantom, 'these routes are documented but do not exist').toEqual([]);
    } finally {
      await app.close();
    }
  });

  it('describes every error code the platform can return', async () => {
    const { ERROR_CODES } = await import('@scrutexity/core');
    const documented: string[] =
      openapi.components.schemas.Error.properties.error.properties.code.enum;
    expect(new Set(documented)).toEqual(new Set(ERROR_CODES));
  });

  it('lists the closed action vocabulary', async () => {
    const { KNOWN_ACTIONS } = await import('@scrutexity/core');
    expect(openapi['x-action-catalog'].actions).toEqual(KNOWN_ACTIONS);
  });
});
