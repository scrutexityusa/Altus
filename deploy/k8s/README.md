# Kubernetes deployment

Templates, not a Helm chart. A chart is the right shape once there is more than
one environment to parameterise; today there is one, and a chart would hide the
manifests behind indirection for no gain.

## Apply order

```bash
kubectl apply -f namespace.yaml
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.example.yaml   # after filling it in from a secret manager
kubectl apply -f networkpolicy.yaml
kubectl apply -f deployment.yaml
```

Migrations run as the **owner** role, separately from the service, which runs
as a non-owner (ADR-0005). Run them as a `Job` before rolling a release, not
from an init container inside the Deployment — three replicas racing the same
migration is a way to discover that your migrations were not idempotent.

## Deployment models

| Model                     | Manifest             | When                                                      |
| ------------------------- | -------------------- | --------------------------------------------------------- |
| Standalone control plane  | `deployment.yaml`    | Default. Central service, several callers.                |
| Sidecar enforcement point | `sidecar-patch.yaml` | The agent must not cross the network to get a decision.   |
| Gateway filter            | not templated        | Enforcement at the ingress in front of the protected API. |
| SDK in-process            | none needed          | `@scrutexity/sdk` inside the agent runtime.               |

Semantics are identical across all four: each calls the same pure evaluator.
Placement changes latency and blast radius, never the answer.

## Notes worth reading before deploying

- **`maxUnavailable: 0`.** Callers fail closed when the control plane is
  unreachable, which for treasury actions means payments stop. Never roll below
  full capacity.
- **No CPU limit.** Throttling adds latency to the one path that must not have
  any; the request guarantees the floor.
- **Liveness does not touch the database.** Readiness does.
- **`automountServiceAccountToken: false`.** The service needs no Kubernetes API
  access at all.
- **Signing key rotation.** Publish the new public key to verifiers _before_
  switching `RECEIPT_SIGNING_KEY_ID`. Receipts record the key id they were
  signed with, so historical receipts stay verifiable against the old key.

`secretproviderclass.example.yaml` is the production key custody posture:
the signing key projected into a tmpfs by a secrets agent, with no cloud SDK
and no credential held by Altus. `secret.example.yaml` is the development
shape and is refused in production. See `docs/key-management.md`.
