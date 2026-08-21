import { z } from 'zod';

/**
 * Configuration comes from the environment and is validated once at boot. A
 * misconfigured authorization service should fail to start, loudly, rather
 * than discover at request time that it has no signing key.
 */
const ConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(8080),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(200).default(10),
  RECEIPT_SIGNING_KEY_ID: z.string().min(1).default('dev-local-1'),
  /** Base64-encoded PKCS#8 PEM of an Ed25519 private key. */
  RECEIPT_SIGNING_KEY_B64: z.string().default(''),
  EXECUTION_GRANT_TTL_SECONDS: z.coerce.number().int().min(5).max(86_400).default(300),
  APPROVAL_TTL_SECONDS: z.coerce.number().int().min(30).max(86_400).default(3600),
});

export type Config = z.infer<typeof ConfigSchema> & { isProduction: boolean };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = ConfigSchema.safeParse(env);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`invalid configuration: ${detail}`);
  }
  const config = parsed.data;
  if (config.NODE_ENV === 'production' && config.RECEIPT_SIGNING_KEY_B64 === '') {
    // Unsigned evidence in production would be evidence of nothing.
    throw new Error('RECEIPT_SIGNING_KEY_B64 is required in production');
  }
  return { ...config, isProduction: config.NODE_ENV === 'production' };
}
