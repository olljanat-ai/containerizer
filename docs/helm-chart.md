# Deploy mode: shared Helm chart or plain manifests

An organization scan writes each application's components to the output repository in one of two forms:

| Mode | A component's files | Applied by |
| --- | --- | --- |
| `chart` (the default) | `<component>/helmrelease.yaml`: a Flux `HelmRelease` of the shared chart `charts/containerizer-app/<version>/`, whose values hold only what the component has beyond the chart's baseline | Flux helm-controller |
| `manifests` | `<component>/k8s.yaml`: the component's objects themselves | Flux kustomize-controller |

The objects that run are the same either way. The generator always makes, hardens, lints, scans and runs the plain
objects first (the security gate). Only when the application is written to the output repository does Containerizer
turn a component into a HelmRelease, and only when the chart renders **exactly** the objects it generated. The unit
tests check that `helm template` and Containerizer's own renderer agree.

## The hardening is in the chart, not in the values

The chart's templates set the hardening on every pod and container after the values, so no value can change or
remove it:

- the pod's own user namespace (`hostUsers: false`), no service account token, `runAsNonRoot`, seccomp `RuntimeDefault`
- every container (and init container) not privileged, no privilege escalation, a read-only root file system,
  `runAsNonRoot`, seccomp `RuntimeDefault`, all capabilities dropped
- ServiceAccounts mount no token

A HelmRelease that asks for host namespaces, `hostPath` volumes, `hostPort`s, unsafe sysctls, capabilities other than
`NET_BIND_SERVICE`, or a container without a memory limit fails to render. A component that needs a hardening
exception (for example a Kubernetes API client that mounts its token) therefore stays plain manifests, where the
exception is visible in its `k8s.yaml` and in `HARDENING.md`.

## When the shared chart is not the better fit

A shared chart removes the repeated baseline: the security contexts, labels and selectors, the ServiceAccount, the
NetworkPolicy rules for DNS and sibling components, the shape of the ExternalSecrets and the Data Protection key. On
the 39 components of the lab environment, the HelmReleases are 42% shorter than the manifests, and `helm template`
gives back every object unchanged. It is not always the better choice:

- **Unusual resources.** Sidecars, init containers, StatefulSets, operator custom resources and other kinds the chart
  has no defaults for are carried in the values as they are. When little of a component matches the baseline, its
  values are about as long as its manifests and Helm only adds a layer. A component stays manifests when its
  HelmRelease would not be at least `deploy.min_saving` (30%) shorter.
- **Hardening exceptions.** The chart enforces the hardening, so a component that needs an exception stays manifests.
- **What Helm cannot carry faithfully.** Helm keeps numbers as floats, so a number of a million or more would change
  form. Such a component stays manifests too.
- **Switching recreates objects.** helm-controller takes the objects over from kustomize-controller: the pods restart,
  PersistentVolumeClaims are made again (empty) and the generated Data Protection keys change (users are signed out).
  So a deployed application keeps its mode when the default changes. An administrator switches it deliberately.
- **Fleet-wide changes.** With one shared chart, a change to the chart changes every application at once. Each
  HelmRelease names the chart version it was generated with (`charts/containerizer-app/<version>/`). A new Containerizer
  version changes nothing that runs until an application is generated again. `containerizer org` removes chart
  versions that no HelmRelease names any more.
- **Teams that own their files.** An application moved to its own repository (Admin -> Applications -> Output
  repository) takes the chart versions it uses along. A team that wants to edit plain YAML can set the mode to
  manifests before the move.
- **OCI delivery.** `gitops/flux/oci/sync.yaml` pushes the application's folder only, without the chart. Deploy chart
  mode applications from Git, or set them to manifests.
- **Platform migrations** (`containerizer replatform`) are written as manifests.

## Setting the mode

Which mode an application gets, first match wins:

1. **The administrators' choice for the application:** Admin -> Applications -> the application -> Deploy mode
   (`Application.DeployMode`; the change history records it).
2. **The mode it is deployed with.** This applies when it was deployed before and `deploy.switch_existing` is false.
   Applications made before 0.33.0 are manifests.
3. **The system default:** `deploy.mode` in `rules/60-security.yaml`, overridden by `CONTAINERIZER_DEPLOY_MODE` (a
   site setting), or `containerizer org --deploy-mode` for one run.

```yaml
# rules/60-security.yaml
deploy:
  mode: chart              # or manifests
  switch_existing: false   # true: deployed applications switch at their next deployment too
  min_saving: 0.3          # a component stays manifests unless its HelmRelease is this much shorter
```

`containerizer.json` records each application's `deploy_mode`, why that mode applies (`deploy_mode_reason`), and
each component's `deploy_mode` (with `deploy_mode_reason` when it stayed manifests).

## What a chart mode application looks like

```
charts/containerizer-app/0.33.0/        the chart, once per repository and version
<org>/<project>/<repo>/
  kustomization.yaml                    lists <component>/helmrelease.yaml (no images: entry for it) and
                                        <component>/settings.yaml
  <component>/helmrelease.yaml          HelmRelease: chart path and version, values
  <component>/settings.yaml             ConfigMap <component>-settings, when the component has one
  gitops/flux/git/sync.yaml             the same GitRepository serves the chart
```

The values have `component`, `partOf`, `image` (with the Flux image automation markers for name, tag and digest) and
`objects`: one entry per object (except the settings ConfigMap: it is in `settings.yaml`, a plain file you edit
per environment, applied by the app's Kustomization, not by Helm), holding only what differs from the chart's `values.yaml`. Maps merge key by key, a
list replaces the default list, `~unset` removes a default key, and `"@<name>"` stands for a shared fragment (the DNS
egress rule, the health probes, ...). The HelmRelease runs as the namespace's `<namespace>-reconciler`
ServiceAccount, like the Kustomization. helm-controller is part of the default Flux install, and the appliance runs it.

The sandbox routes with its own Ingress. Its copy of each Kustomization sets `values.skipKinds: [HTTPRoute]` on the
HelmReleases, as it deletes the HTTPRoutes of plain manifests.

## User namespaces

Every generated pod runs in its own [user namespace](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
(`hostUsers: false`). Root in a container is then an unprivileged user on the node. This is on by default since
Kubernetes 1.33. The nodes need:

- Linux 6.3 or newer
- containerd 2.0+ (or CRI-O 1.25+) with runc 1.2+ or crun 1.9+
- volume file systems that support idmapped mounts: ext4, xfs, btrfs, tmpfs, overlayfs

The appliance's k3s (1.37, Debian 13's kernel 6.12, btrfs) has all of these. A cluster without the feature drops the
field. On a cluster that has the feature but an older runtime, the pods fail to start: set
`CONTAINERIZER_USER_NAMESPACES=false` there (or `hardening.user_namespaces: false`). Those components then stay
manifests in chart mode, because the chart always sets `hostUsers: false`.
