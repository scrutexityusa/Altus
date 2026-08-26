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
  /**
   * How often buffered credential last-used ids are written.
   *
   * Also the worst-case telemetry loss if the process dies: nothing
   * authorises on `last_used_at`, so this is a knob over how stale an
   * operator's "is anything still using this credential" view may be, not a
   * security parameter. Tests set it low to make a flush observable.
   */
  CREDENTIAL_USE_FLUSH_MS: z.coerce.number().int().min(100).max(3_600_000).default(60_000),
  RECEIPT_SIGNING_KEY_ID: z.string().min(1).default('dev-local-1'),
  /**
   * Base64-encoded PKCS#8 PEM of an Ed25519 private key.
   *
   * Read through the secret provider, not directly: with SECRET_PROVIDER=env
   * this is the environment variable, with `file` it is the file of that name
   * under SECRET_DIR, and with `kms` it is the name the key manager knows the
   * key by. One name, three custody models, and nothing downstream can tell
   * which one it got.
   */
  RECEIPT_SIGNING_KEY_NAME: z.string().min(1).default('RECEIPT_SIGNING_KEY_B64'),
  RECEIPT_SIGNING_KEY_B64: z.string().default(''),
  EXECUTION_GRANT_TTL_SECONDS: z.coerce.number().int().min(5).max(86_400).default(300),
  APPROVAL_TTL_SECONDS: z.coerce.number().int().min(30).max(86_400).default(3600),
  /**
   * Comma-separated execution providers, or "none".
   *
   * The default is the simulated provider, which is right for development and
   * refused outright in production -- a simulated provider there would emit
   * receipts indistinguishable from real ones for money that never moved.
   */
  EXECUTION_PROVIDERS: z.string().default('simulated-treasury'),
  /**
   * Whether a signal from a source with no enrolled key may influence
   * authority.
   *
   *   required    an unenrolled source is refused. The default.
   *   permissive  an unenrolled source is accepted and recorded as
   *               unauthenticated. Local development only.
   *
   * The default used to be permissive by omission -- there was no setting, and
   * an unenrolled source was simply treated as non-fatal. That meant anyone
   * holding the `signals:write` scope could assert any signal about any
   * subject, and the signal plane reduces authority over real money.
   *
   * Production cannot select `permissive`; `loadConfig` refuses to start.
   */
  /**
   * Connection string and stopping point for the crash-harness provider.
   *
   * Only read when EXECUTION_PROVIDERS names it, which production refuses. The
   * separate connection string is the point: the harness provider's ledger has
   * to be writable by something other than the tenant-scoped application role,
   * and it has to survive the process being killed.
   */
  CRASH_HARNESS_URL: z.string().default(''),
  CRASH_HARNESS_POINT: z.enum(['before_payment', 'after_payment', 'none']).default('none'),
  SIGNAL_AUTHENTICATION: z.enum(['required', 'permissive']).default('required'),
  /**
   * Whether HMAC-SHA256 signal keys are usable at all.
   *
   *   refused    HMAC keys cannot be registered and enrolled HMAC keys do not
   *              verify. The default, everywhere.
   *   permitted  HMAC keys work, for a deployment still migrating a source
   *              that cannot yet manage a keypair.
   *
   * Ed25519 stores only a public key, so a disclosure of this database yields
   * nothing an attacker can sign with. HMAC requires Scrutexity to hold the
   * same secret that manufactures signals reducing authority over real money,
   * which makes the signal key table a forgery capability.
   *
   * The default is `refused` in development too, and not only in production,
   * for two reasons: a fallback that exists locally is a fallback the tests
   * exercise and production does not, and a deployment discovers a missing
   * capability at enrolment rather than in an incident. Production cannot
   * select `permitted`.
   */
  SIGNAL_LEGACY_HMAC: z.enum(['refused', 'permitted']).default('refused'),
  /**
   * Where private key material comes from.
   *
   *   env   read from the environment. Fine locally, and the only provider
   *         that needs no external system.
   *   file  read from a path, so a secret can be mounted rather than exported
   *         into a process environment that `ps` and crash dumps can see.
   *   kms   fetched from a key manager. The only provider production accepts.
   *
   * See services/api/src/keys/provider.ts.
   */
  SECRET_PROVIDER: z.enum(['env', 'file', 'agent', 'kms']).default('env'),
  /**
   * Lets `agent` custody accept a persistent mount.
   *
   * Exists for development on a platform without tmpfs, and is refused in
   * production below. Without it the custody check runs identically everywhere,
   * which is the point: a check that only runs in production is a check nobody
   * has seen pass.
   */
  SECRET_AGENT_ALLOW_PERSISTENT: z.coerce.boolean().default(false),
  /** Directory the `file` provider reads from. */
  SECRET_DIR: z.string().default('./.secrets'),
});

export type Config = z.infer<typeof ConfigSchema> & { isProduction: boolean };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = ConfigSchema.safeParse(env);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`invalid configuration: ${detail}`);
  }
  const config = parsed.data;
  if (config.NODE_ENV === 'production' && config.RECEIPT_SIGNING_KEY_B64 !== '') {
    // Inverted from what it used to say, which was that this variable is
    // *required* in production. That was the wrong requirement: an Ed25519
    // private key in an environment variable is visible to anything that can
    // read /proc, is captured by most crash reporters, and is inherited by
    // every child process. Production takes its signing key from the secret
    // provider under RECEIPT_SIGNING_KEY_NAME; setting the inline variable is
    // now the misconfiguration, and boot refuses rather than preferring it.
    //
    // Production still cannot start unsigned: an absent key makes
    // loadEvidenceKeys throw rather than fall back to an ephemeral one.
    throw new Error(
      'RECEIPT_SIGNING_KEY_B64 must not be set in production; ' +
        'the signing key is read from the configured secret provider',
    );
  }
  if (config.NODE_ENV === 'production' && config.SIGNAL_AUTHENTICATION !== 'required') {
    // A signal plane that accepts unauthenticated input is one where anyone
    // who reaches the API can shrink an agent's authority -- a denial of
    // service against a legitimate agent, delivered through the control plane
    // itself.
    throw new Error(
      'SIGNAL_AUTHENTICATION must be "required" in production; ' +
        'unenrolled signal sources cannot be trusted with authority reduction',
    );
  }
  if (config.NODE_ENV === 'production' && config.SIGNAL_LEGACY_HMAC !== 'refused') {
    // Holding a source's HMAC secret means holding the ability to forge that
    // source's signals. Refused at boot rather than at enrolment, so a
    // deployment cannot reach a state where the table already contains one.
    throw new Error(
      'SIGNAL_LEGACY_HMAC must be "refused" in production; ' +
        'a shared signal secret is a forgery capability held in the database',
    );
  }
  if (config.NODE_ENV === 'production' && config.SECRET_AGENT_ALLOW_PERSISTENT) {
    throw new Error(
      'SECRET_AGENT_ALLOW_PERSISTENT must not be set in production; it defeats the ' +
        'only check that distinguishes an agent-delivered key from a file on a disk',
    );
  }

  if (
    config.NODE_ENV === 'production' &&
    config.SECRET_PROVIDER !== 'kms' &&
    config.SECRET_PROVIDER !== 'agent'
  ) {
    // Local key custody in production means the private key lives wherever the
    // process does: in an environment variable a crash dump captures, or a
    // file on a disk that gets snapshotted. Refuse at boot rather than
    // discover it during an incident.
    throw new Error(
      `SECRET_PROVIDER must be "kms" or "agent" in production; ` +
        `"${config.SECRET_PROVIDER}" is local custody`,
    );
  }
  return { ...config, isProduction: config.NODE_ENV === 'production' };
}
