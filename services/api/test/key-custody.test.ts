import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  loadSecretProvider,
  SecretCustodyError,
  SecretNotFoundError,
} from '../src/keys/provider.js';
import { loadConfig } from '../src/config.js';

/**
 * ============================================================================
 * Key custody.
 * ============================================================================
 *
 * Production refuses local custody. That refusal is only worth something if the
 * providers claiming to be *not* local can be made to prove it, so these tests
 * attack the claim rather than exercise the happy path.
 *
 * The `agent` provider is how a key manager is actually consumed by a
 * container -- AWS Secrets Manager's CSI driver, External Secrets Operator,
 * Vault Agent -- and none of them is a dependency here: they all end at a file
 * on a tmpfs. What separates that from `SECRET_DIR` on a persistent volume is
 * custody, not the syscall, so custody is what gets checked.
 */

/** tmpfs on Linux, and the reason these tests state their platform. */
const SHM = '/dev/shm';

function config(over: Record<string, string> = {}) {
  return loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgres://u:p@127.0.0.1:5432/d',
    LOG_LEVEL: 'silent',
    ...over,
  });
}

function secretDir(base: string): string {
  const dir = mkdtempSync(join(base, 'altus-custody-'));
  return dir;
}

function writeSecret(dir: string, name: string, mode: number): void {
  const path = join(dir, name);
  writeFileSync(path, Buffer.from('a'.repeat(32)).toString('base64'));
  chmodSync(path, mode);
}

describe('agent-delivered key custody', () => {
  it('reads a secret projected into an ephemeral mount', async () => {
    const dir = secretDir(SHM);
    try {
      writeSecret(dir, 'receipt-signing-key', 0o400);
      const provider = loadSecretProvider(config({ SECRET_PROVIDER: 'agent', SECRET_DIR: dir }));
      expect(provider.kind).toBe('agent');
      expect(provider.externallyManaged).toBe(true);
      await expect(provider.getSecret('receipt-signing-key')).resolves.toBeInstanceOf(Buffer);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a persistent mount, because the key manager must be the durable copy', async () => {
    // The whole difference between this provider and `file`. A key that
    // survives a reboot on the node is a key the node is the source of truth
    // for, whatever the deployment calls it.
    const dir = secretDir(tmpdir());
    try {
      writeSecret(dir, 'receipt-signing-key', 0o400);
      const provider = loadSecretProvider(config({ SECRET_PROVIDER: 'agent', SECRET_DIR: dir }));
      await expect(provider.getSecret('receipt-signing-key')).rejects.toThrow(SecretCustodyError);
      await expect(provider.getSecret('receipt-signing-key')).rejects.toThrow(/persistent/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a secret readable beyond its owner', async () => {
    const dir = secretDir(SHM);
    try {
      writeSecret(dir, 'receipt-signing-key', 0o444);
      const provider = loadSecretProvider(config({ SECRET_PROVIDER: 'agent', SECRET_DIR: dir }));
      await expect(provider.getSecret('receipt-signing-key')).rejects.toThrow(SecretCustodyError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not confuse a missing secret with a custody failure', async () => {
    // Conflating them would let a custody failure read as a missing key and
    // get "fixed" by pointing the deployment at a worse location.
    const dir = secretDir(SHM);
    try {
      const provider = loadSecretProvider(config({ SECRET_PROVIDER: 'agent', SECRET_DIR: dir }));
      await expect(provider.getSecret('absent')).rejects.toThrow(SecretNotFoundError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a name that escapes the mount', async () => {
    const dir = secretDir(SHM);
    try {
      const provider = loadSecretProvider(config({ SECRET_PROVIDER: 'agent', SECRET_DIR: dir }));
      await expect(provider.getSecret('../../etc/passwd')).rejects.toThrow(SecretNotFoundError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('lets development past the mount check, and never production', async () => {
    const dir = secretDir(tmpdir());
    try {
      writeSecret(dir, 'receipt-signing-key', 0o400);
      // The escape hatch works where it is meant to...
      const provider = loadSecretProvider(
        config({
          SECRET_PROVIDER: 'agent',
          SECRET_DIR: dir,
          SECRET_AGENT_ALLOW_PERSISTENT: 'true',
        }),
      );
      await expect(provider.getSecret('receipt-signing-key')).resolves.toBeInstanceOf(Buffer);

      // ...and cannot be carried into production, where it would defeat the
      // only check that distinguishes this provider from `file`.
      expect(() =>
        config({
          NODE_ENV: 'production',
          SECRET_PROVIDER: 'agent',
          SECRET_DIR: dir,
          SECRET_AGENT_ALLOW_PERSISTENT: 'true',
        }),
      ).toThrow(/ALLOW_PERSISTENT/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('production refuses local custody', () => {
  for (const kind of ['env', 'file'] as const) {
    it(`refuses SECRET_PROVIDER=${kind}`, () => {
      expect(() => config({ NODE_ENV: 'production', SECRET_PROVIDER: kind })).toThrow(
        /local custody/,
      );
    });
  }

  it('accepts agent and kms', () => {
    for (const kind of ['agent', 'kms'] as const) {
      expect(() =>
        config({ NODE_ENV: 'production', SECRET_PROVIDER: kind, SECRET_DIR: SHM }),
      ).not.toThrow();
    }
  });

  it('kms still refuses every read, because no manager is wired', async () => {
    const provider = loadSecretProvider(config({ SECRET_PROVIDER: 'kms' }));
    expect(provider.externallyManaged).toBe(true);
    await expect(provider.getSecret('receipt-signing-key')).rejects.toThrow(SecretNotFoundError);
  });
});
