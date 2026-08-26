import { readFileSync, statSync, statfsSync } from 'node:fs';
import { isAbsolute, join, normalize, resolve } from 'node:path';
import type { Config } from '../config.js';

/**
 * ============================================================================
 * Key custody.
 * ============================================================================
 *
 * A narrow interface over "where does private key material come from", so the
 * authority engine never learns the answer. Four providers today; a fifth
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
  readonly kind: 'env' | 'file' | 'agent' | 'kms';
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

/**
 * Distinct from SecretNotFoundError: the secret is *there* and the way it is
 * held is unacceptable. Conflating them would let a custody failure read as a
 * missing key and get "fixed" by pointing at a worse location.
 */
export class SecretCustodyError extends Error {
  constructor(message: string) {
    super(`key custody: ${message}`);
    this.name = 'SecretCustodyError';
  }
}

/**
 * Resolves `name` inside `dir`, or null if it escapes.
 *
 * A secret name comes from configuration rather than a request, but treating
 * it as trusted is how a traversal gets in later when somebody wires it to
 * something that is.
 */
function safeSecretPath(dir: string, name: string): string | null {
  const candidate = normalize(join(dir, name));
  if (!candidate.startsWith(dir) || isAbsolute(name)) return null;
  return candidate;
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
    const candidate = safeSecretPath(this.#dir, name);
    if (candidate === null) throw new SecretNotFoundError(name, this.kind);
    try {
      return Buffer.from(readFileSync(candidate, 'utf8').trim(), 'base64');
    } catch {
      throw new SecretNotFoundError(name, this.kind);
    }
  }
}

/**
 * Key material delivered by an external secrets agent into an ephemeral mount.
 *
 * This is how AWS Secrets Manager, GCP Secret Manager, Azure Key Vault and
 * HashiCorp Vault are actually consumed by a container in practice: a sidecar
 * or CSI driver authenticates with the workload's own identity, fetches the
 * secret, and projects it into a tmpfs the process can read. The key never
 * enters the image, never enters the environment, is rotated by the manager,
 * and disappears when the pod does.
 *
 * It is deliberately *not* a cloud SDK. One provider covers every key manager
 * that can write a file, which is all of them, and adds no dependency to a
 * control plane whose dependency list is a security property.
 *
 * ## Why this is allowed to claim `externallyManaged` and `file` is not
 *
 * The difference is not the syscall -- both read a file. It is custody: whether
 * the key exists anywhere the deployment durably controls. A `SECRET_DIR` on a
 * persistent volume is local custody with extra steps; a tmpfs projection whose
 * source of truth is a key manager is not.
 *
 * That distinction is worthless if it rests on an operator ticking a box, so it
 * is checked rather than asserted:
 *
 *   the mount is tmpfs or ramfs   -- the key cannot survive a reboot, which
 *                                    means it cannot be the source of truth
 *   the file is not readable by
 *   group or other                -- a secret any process on the box can read
 *                                    is not in anybody's custody
 *
 * Neither check proves a key manager is behind the mount. Together they refuse
 * the ways of pretending one is that cost nothing, which is what a check is
 * for. `SECRET_AGENT_ALLOW_PERSISTENT` exists for development on a platform
 * with no tmpfs, is refused in production by `config.ts`, and is the only way
 * past the first check.
 */
class AgentSecretProvider implements SecretProvider {
  readonly kind = 'agent' as const;
  readonly externallyManaged = true;
  readonly #dir: string;
  readonly #allowPersistent: boolean;
  #custodyChecked = false;

  constructor(dir: string, allowPersistent: boolean) {
    this.#dir = resolve(dir);
    this.#allowPersistent = allowPersistent;
  }

  /**
   * tmpfs and ramfs, by their `statfs` magic numbers.
   *
   * Linux exposes no friendlier name for this, and a string comparison against
   * `mount` output would be worse: parseable by an attacker who controls a
   * mount label, and absent entirely on a container with no `mount` binary.
   */
  static readonly #EPHEMERAL_FS = new Set([0x0102_1994, 0x8584_58f6]);

  #assertCustody(): void {
    if (this.#custodyChecked) return;

    if (!this.#allowPersistent) {
      let type: number;
      try {
        type = Number(statfsSync(this.#dir).type);
      } catch {
        throw new SecretCustodyError(
          `the secret mount ${this.#dir} could not be inspected; it must exist before startup`,
        );
      }
      if (!AgentSecretProvider.#EPHEMERAL_FS.has(type)) {
        throw new SecretCustodyError(
          `the secret mount is on a persistent filesystem (0x${type.toString(16)}). ` +
            'An agent-delivered secret must land on tmpfs or ramfs, so that the key ' +
            'manager remains the only durable copy. Mount it with `medium: Memory`, ' +
            'or set SECRET_AGENT_ALLOW_PERSISTENT for local development.',
        );
      }
    }
    this.#custodyChecked = true;
  }

  async getSecret(name: string): Promise<Buffer> {
    this.#assertCustody();

    const candidate = safeSecretPath(this.#dir, name);
    if (candidate === null) throw new SecretNotFoundError(name, this.kind);

    let mode: number;
    try {
      mode = statSync(candidate).mode;
    } catch {
      throw new SecretNotFoundError(name, this.kind);
    }
    if ((mode & 0o077) !== 0) {
      // Refused rather than warned. A key readable by every process on the
      // node is not in custody, and a warning about it is a note somebody
      // reads after the incident.
      throw new SecretCustodyError(
        `the secret "${name}" is readable beyond its owner (mode ${(mode & 0o777).toString(8)}). ` +
          'Project it with defaultMode 0400.',
      );
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
  const provider = build(config);
  if (config.isProduction && !provider.externallyManaged) {
    // The interface says this check does not depend on a string comparison
    // somebody later simplifies. `config.ts` performs one anyway, early, for a
    // legible boot failure; this is the assertion the comment actually
    // promises, made against the constructed provider.
    throw new Error(
      `SECRET_PROVIDER="${provider.kind}" is local custody and production refuses it`,
    );
  }
  return provider;
}

function build(config: Config): SecretProvider {
  switch (config.SECRET_PROVIDER) {
    case 'file':
      return new FileSecretProvider(config.SECRET_DIR);
    case 'agent':
      return new AgentSecretProvider(config.SECRET_DIR, config.SECRET_AGENT_ALLOW_PERSISTENT);
    case 'kms':
      return new KmsSecretProvider();
    case 'env':
    default:
      return new EnvSecretProvider();
  }
}
