# Key management

Altus holds one long-lived private key: the Ed25519 key that signs evidence
receipts. Everything the system claims about its own history rests on where that
key lives, so this page says exactly where it may live and how the code refuses
the alternatives.

Signal source keys are a separate matter and belong to the sources, not to us —
a fraud engine generates its own keypair and registers only the public half. See
[ADR-0018](decisions/0018-signal-key-custody.md).

## The rule

**Production refuses local custody.** `NODE_ENV=production` requires
`SECRET_PROVIDER` to be `agent` or `kms`, and the boot fails loudly otherwise.
It also refuses to sign with an ephemeral key: a production process that cannot
read its signing key stops, rather than generating one and producing receipts
nobody can verify tomorrow.

| Provider | Where the key lives                           | Production                  | Use it for              |
| -------- | --------------------------------------------- | --------------------------- | ----------------------- |
| `env`    | An environment variable                       | **refused**                 | Nothing but a laptop    |
| `file`   | A file in `SECRET_DIR`                        | **refused**                 | Local development, CI   |
| `agent`  | A tmpfs projection written by a secrets agent | **yes**                     | Every real deployment   |
| `kms`    | A key manager, via an SDK                     | **yes**, but throws on read | Nothing yet — see below |

## `agent` — the one to use

This is how AWS Secrets Manager, GCP Secret Manager, Azure Key Vault and
HashiCorp Vault are actually consumed by a container: a CSI driver or sidecar
authenticates with the workload's own identity, fetches the secret, and projects
it into a memory-backed volume. The key never enters the image, never enters the
environment, is rotated by the manager, and vanishes with the pod.

One provider covers all of them, and adds **no cloud SDK** to a control plane
whose dependency list is itself a security property.

### What separates it from `file`

Not the syscall — both read a file. **Custody:** whether the key exists anywhere
the deployment durably controls. `SECRET_DIR` on a persistent volume is local
custody with extra steps.

A distinction that rests on an operator ticking a box is worth nothing, so it is
checked:

- **The mount is tmpfs or ramfs.** A key that survives a reboot is a key the
  node is the source of truth for, whatever the deployment calls it.
- **The file is not readable by group or other.** Refused, not warned: a key
  every process on the node can read is not in anybody's custody, and a warning
  about it is a note somebody reads after the incident.

Neither proves a key manager is behind the mount. Together they refuse the ways
of pretending one is that cost nothing, which is what a check is for.

`SECRET_AGENT_ALLOW_PERSISTENT=true` skips the first check for development on a
platform without tmpfs. `config.ts` refuses it in production. It is the only way
past, and it cannot travel.

### AWS, concretely

Using the [Secrets Store CSI driver] with the AWS provider. Nothing here is
Altus-specific except the two environment variables at the end.

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: altus-receipt-signing-key
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "altus/receipt-signing-key"
        objectType: "secretsmanager"
        objectAlias: "receipt-signing-key"
---
# In the Deployment. The volume is memory-backed by the driver, and the pod
# authenticates to Secrets Manager with IRSA -- its own identity, not a
# credential Altus holds.
volumes:
  - name: signing-key
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: altus-receipt-signing-key
containers:
  - name: api
    volumeMounts:
      - name: signing-key
        mountPath: /var/run/altus/secrets
        readOnly: true
    env:
      - { name: SECRET_PROVIDER, value: agent }
      - { name: SECRET_DIR, value: /var/run/altus/secrets }
```

GCP, Azure and Vault differ only in the `SecretProviderClass`. External Secrets
Operator and Vault Agent Injector reach the same place by a different route and
work unchanged.

The file must contain the **base64 of the PEM**, and be projected mode `0400`.

[Secrets Store CSI driver]: https://secrets-store-csi-driver.sigs.k8s.io/

## `kms` — deliberately unfinished

`KmsSecretProvider` exists so `externallyManaged` can be true and the boot check
has something real to assert against. **It throws on every read.** A deployment
that selects `kms` without wiring one fails at the first secret, which is louder
than a silent fallback to the environment — and a silent fallback is exactly how
local custody reaches production.

Wiring a specific cloud is a constructor argument and an SDK dependency. Neither
is added until a deployment needs something `agent` cannot do. The case for that
is envelope encryption or signing _inside_ the HSM, where the private key never
leaves the manager at all — a stronger posture than `agent`, and worth building
when a partner asks for it rather than before.

## Rotation

The receipt signing key is **append-forward**: rotating it does not invalidate
old receipts, because each receipt records the `signing_key_id` that signed it
and verification looks up that key. Retire a key by ceasing to sign with it, not
by deleting it — an old public key is needed forever to verify old evidence.

1. Create the new key in the manager. Give it a new `RECEIPT_SIGNING_KEY_ID`.
2. Roll the deployment with the new id and secret name. New receipts carry the
   new id from the first one.
3. Keep the old public key. Publish both in whatever the verifier consumes.

There is no re-signing step and there must never be one: re-signing historical
evidence with a current key is indistinguishable from forging it.

## What none of this fixes

An attacker holding both the database **and** the signing key can rewrite the
chain and re-sign it. No custody choice closes that; it needs an external
witness. Designed in [ADR-0021](decisions/0021-evidence-anchoring.md), and not
built.
