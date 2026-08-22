import { readFileSync } from 'node:fs';
import { isAbsolute, join, normalize, resolve } from 'node:path';
import type { Config } from '../config.js';

/**
 * ============================================================================
 * Key custody.
 * ============================================================================
 *
 * A narrow interface over "where does private key material come from", so the
 * authority engine never learns the answer. Three providers today; a fourth
 * would be a file in this directory and nothing else.
 *
 * The interface is deliberately one method returning a Buffer. Anything richer
 * -- a key object, a signer, a rotation callback -- would push cloud-specific
 * shapes into code that has no business knowing about them, and the point of
 * the abstraction is that `evidence.ts` cannot tell whether its key came from
 * an environment variable or a hardware module.
 *
 * ## The rule that matters more than the interface
 *
 * Secret material returned here must never reach a log, an error message, a
 * metric label, a trace attribute, a database row, an API response or a
 * receipt. There is no formatting helper on this type on purpose: a `toString`
 * that redacted would be a `toString` somebody eventually trusts.
 */

export interface SecretProvider {
  /** Named so an operator can find the same secret in the provider's console. */
  readonly kind: 'env' | 'file' | 'kms';
  /**
   * Whether this provider keeps key material outside the process's own
   * environment and filesystem.
   *
   * Declared rather than inferred, because production refuses to start without
   * it and that refusal must not depend on a string comparison somebody
   * later "simplifies".
   */
  readonly externallyManaged: boolean;
  getSecret(name: string): Promise<Buffer>;
}

export class SecretNotFoundError extends Error {
  constructor(name: string, kind: string) {
    // The name, never the value, and never the place it was looked for -- a
    // path in an error message is a map for whoever reads the error.
    super(`secret "${name}" is not available from the ${kind} provider`);
    this.name = 'SecretNotFoundError';
  }
}

/**
 * Reads from the process environment.
 *
 * Adequate locally and nowhere else: an environment variable is visible to
 * anything that can read `/proc`, is captured by most crash reporters, and
 * survives into child processes that had no need for it.
 */
class EnvSecretProvider implements SecretProvider {
  readonly kind = 'env' as const;
  readonly externallyManaged = false;

  async getSecret(name: string): Promise<Buffer> {
    const value = process.env[name];
    if (value === undefined || value === '') throw new SecretNotFoundError(name, this.kind);
    return Buffer.from(value, 'base64');
  }
}

/**
 * Reads from a directory, one secret per file.
 *
 * Better than the environment because a mounted file is not inherited by child
 * processes and is not in a crash dump, and it is how a container orchestrator
 * delivers a secret. Still local custody: whoever can read the disk has the
 * key.
 */
class FileSecretProvider implements SecretProvider {
  readonly kind = 'file' as const;
  readonly externallyManaged = false;
  readonly #dir: string;

  constructor(dir: string) {
    this.#dir = resolve(dir);
  }

  async getSecret(name: string): Promise<Buffer> {
    // A secret name comes from configuration rather than a request, but
    // treating it as trusted is how a traversal gets in later when somebody
    // wires it to something that is.
    const candidate = normalize(join(this.#dir, name));
    if (!candidate.startsWith(this.#dir) || isAbsolute(name)) {
      throw new SecretNotFoundError(name, this.kind);
    }
    try {
      return Buffer.from(readFileSync(candidate, 'utf8').trim(), 'base64');
    } catch {
      throw new SecretNotFoundError(name, this.kind);
    }
  }
}

/**
 * The production shape, not yet connected to a key manager.
 *
 * It exists as a distinct type so that `externallyManaged` can be true and the
 * boot check in `config.ts` has something real to assert against. It throws on
 * every read, which is the correct behaviour for a deployment that has
 * selected `kms` without wiring one: refusing at the first secret is louder
 * than silently falling back to the environment, and a silent fallback is
 * exactly how local custody reaches production.
 *
 * Wiring a specific cloud is a constructor argument and an SDK dependency.
 * Neither is added until a deployment actually needs one, per the non-goals.
 */
class KmsSecretProvider implements SecretProvider {
  readonly kind = 'kms' as const;
  readonly externallyManaged = true;

  async getSecret(name: string): Promise<Buffer> {
    throw new SecretNotFoundError(
      name,
      'kms (no key manager is configured; see docs/key-management.md)',
    );
  }
}

export function loadSecretProvider(config: Config): SecretProvider {
  switch (config.SECRET_PROVIDER) {
    case 'file':
      return new FileSecretProvider(config.SECRET_DIR);
    case 'kms':
      return new KmsSecretProvider();
    case 'env':
    default:
      return new EnvSecretProvider();
  }
}
