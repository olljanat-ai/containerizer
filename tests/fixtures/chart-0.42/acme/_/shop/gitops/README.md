# Deploying ci-demo with GitOps

Commit the generated app folder (the one with `kustomization.yaml`) to `https://git.example.com/platform/deployments.git` at
`deploy/ci-demo` on `main`, then apply the Flux files below. They apply the manifests with tight
limits: only namespace `ci-demo`, Pod Security "restricted" on the namespace, pruning and drift correction on.

## Flux

```sh
kubectl apply -f flux/tenant.yaml          # platform admin: namespace, ServiceAccounts, RoleBinding, store access
kubectl apply -f flux/git/sync.yaml        # or flux/oci/sync.yaml, not both
kubectl apply -f flux/git/image-automation.yaml   # optional
```

- `tenant.yaml` is the only part that needs cluster rights. Everything else lives in `ci-demo` and is
  applied as ServiceAccount `ci-demo-reconciler`, bound to the built-in `admin` role in that
  namespace only. Run the controllers with `--no-cross-namespace-refs` and
  `--default-service-account` for a full lockdown.
- No credential is in these files. Each Secret Flux needs is an `ExternalSecret` that External Secrets
  Operator fills from the secret store (see `../HARDENING.md` and docs/external-secrets.md). Put these
  remote secrets in the store first:

  | Remote key | Keys | Used by |
  | --- | --- | --- |
  | `ci-demo--cz-git` | `identity` + `known_hosts` (deploy key), or `username` + `password` (token) | `GitRepository` (read-only; write for image automation) |
  | `ci-demo--cz-registry` | `.dockerconfigjson` | `OCIRepository`, `ImageRepository`, image pulls |
  | `ci-demo--cz-cosign-pub` | `cosign.pub` | `OCIRepository` signature check |

- `git/sync.yaml`: `GitRepository` with a read-only deploy key and a `Kustomization`
  (prune, wait, health checks). Set commit verification (`spec.verify`) when your commits are signed.
- `oci/sync.yaml`: the same, from an OCI artifact (`flux push artifact oci://<registry>/ci-demo/manifests:1.0.0
  --path=deploy/ci-demo`), accepted only when signed with the cosign key in Secret `ci-demo-cosign-pub`.
- `git/image-automation.yaml`: `ImageRepository`, `ImagePolicy` (semver `>=1.0.0`, digest reflection
  `Always`) and `ImageUpdateAutomation`; the `$imagepolicy` markers in `kustomization.yaml` say what it may
  change: the image's name, tag and digest, so the workloads run `<image>:<tag>@sha256:...` (by digest) once
  it ran. Without it, pin by hand: `kustomize edit set image <image>:<tag>@sha256:<digest>` (the build
  pipeline's `digests.txt`).
  It needs a deploy key with write access, so keep it separate from the read-only sync key if you
  can.

Components `demo-web` are `HelmRelease`s of the shared chart `charts/containerizer-app/0.42.0` (at the root of this repository; docs/helm-chart.md): Flux's helm-controller installs them as ServiceAccount `ci-demo-reconciler`, from the same `GitRepository`. Their image setters are in their `helmrelease.yaml`, not in `kustomization.yaml`. The OCI delivery (`oci/sync.yaml`) does not carry the chart: deploy these from Git, or set the application's deploy mode to manifests.
