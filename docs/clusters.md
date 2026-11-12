# Clusters: sandbox, development, acceptance, production

The output repository is laid out for several clusters, all under `clusters/`: the **sandbox** (`clusters/sandbox/`, the
appliance's own k3s) and by default **development**, **acceptance** and **production**. Every cluster
deploys the same app folders, the same images and the same shared Helm chart (docs/helm-chart.md) with Flux. What
differs per cluster lives in that cluster's own folder.

```
sandbox/flux/apps/kustomization.yaml  a pointer to clusters/sandbox/ (where the sandbox was before 0.41.0)
clusters/
  README.md                           the clusters and how many apps each runs
  sandbox/                            the sandbox (docs/scheduled-scans.md#the-sandbox-cluster)
  <cluster>/
    cluster.yaml                      which apps it runs, the registry it pulls from        yours
    README.md                         its apps and how to bootstrap it                      generated
    flux/bootstrap.yaml               the root GitRepository + Kustomization                generated
    flux/apps/kustomization.yaml      each app's gitops/flux, pointed at its overlay below   generated
    apps/<namespace>/
      kustomization.yaml              the app folder, the cluster's registry, custom/       generated
      custom/kustomization.yaml       the cluster's settings of this app (kustomize Component) yours
<org>/<project>/<repo>/gitops/sandbox/kustomization.yaml
                                      the app's Flux objects (../flux) with the sandbox's patch  generated
```

The sandbox's `flux/apps/kustomization.yaml` only lists each app folder's `gitops/sandbox/`. What the sandbox
changes about an app (no waiting for every object, no Gateway API routes, the settings read from OpenBao, debug mode)
is in that app's own folder, next to the `gitops/flux` the other clusters deploy unchanged.

"Yours": Containerizer writes it once and no later run rewrites it. `cluster.yaml` is written with the cluster's
folder, and `custom/` when the cluster first runs the app. "Generated": every `containerizer org` run rewrites it.

## Which apps a cluster runs

```yaml
# clusters/production/cluster.yaml
deploy: listed          # all: every app in the repository; listed: only the namespaces below
apps:
- containerization-challenge-shop
registry: registry.example.com/apps   # images become <registry>/<namespace>/<component>; empty: as built
```

| Cluster | `deploy` by default | Images |
| --- | --- | --- |
| development | `all`: every app, new ones as soon as a scan writes them | follow every new build |
| acceptance, production | `listed`, with an empty list: nothing until you list an app | pinned when the cluster first runs the app |

Taking an app off the list prunes it from the cluster. Its `custom/` stays, so listing it again brings back the same
settings. The sandbox's on/off switch (Admin -> Applications -> Sandbox) applies to the sandbox only.

## Promoting a build

In acceptance and production, `apps/<namespace>/custom/kustomization.yaml` starts pinned to the image tags and
digests the app had when the cluster first ran it:

```yaml
apiVersion: kustomize.config.k8s.io/v1alpha1
kind: Component
images:                                   # components of plain manifests
- name: localhost:5000/sandbox/containerization-challenge-shop/api
  newTag: 1.20261107.200
  digest: sha256:...
patches:                                  # components of the shared Helm chart
- target: {group: helm.toolkit.fluxcd.io, version: v2, kind: HelmRelease, name: web}
  patch: '[{"op": "add", "path": "/spec/values/image/tag", "value": "1.20261107.200"},
           {"op": "add", "path": "/spec/values/image/digest", "value": "sha256:..."}]'
```

Promoting a build is a commit that changes the tag and digest there, for example from what acceptance runs to
production. The scan's tags and digests are in the app folder's `containerizer.json`. An empty digest deploys by tag.

## Other per-cluster settings

Anything else that differs per cluster goes into the same `custom/` Component as kustomize patches: replicas,
resources, Ingress hosts, or the values of a chart mode component (its `objects`). The hardening is enforced by the
chart's templates and the cluster's Pod Security, so no cluster can loosen it.

```yaml
patches:
- target: {kind: Deployment, name: api}
  patch: '[{"op": "replace", "path": "/spec/replicas", "value": 3}]'
- target: {kind: Ingress, name: api}
  patch: '[{"op": "replace", "path": "/spec/rules/0/host", "value": "shop.example.com"}]'
```

## Bootstrapping a cluster

The prerequisites are those of the sandbox: Flux (with helm-controller), External Secrets Operator with the
`ClusterSecretStore` `app-secrets` (`cluster/secret-store.yaml`), and the output repository's read-only token in the
store under `flux-system--cz-git` and `<namespace>--cz-git` of every app the cluster runs (docs/external-secrets.md).
The cluster kit in `cluster/` (signed images with Kyverno, the API server's audit policy) is meant for these
clusters. Then:

```sh
kubectl apply -f clusters/production/flux/bootstrap.yaml
```

Unlike the sandbox, the clusters keep each app Kustomization's `wait: true` (a secret missing from the store stops
the rollout), deploy the Gateway API HTTPRoutes, and have no sandbox identity provider. The secrets of the apps'
settings, and of the lab services they used in the sandbox (`<namespace>--cz-lab-*`), are remote keys in the
cluster's own secret store: put the real values there. The health read-back (`containerizer sandbox verify`) is for
the sandbox only.

## Cluster names

`CONTAINERIZER_CLUSTERS` (a site setting) names the clusters, comma separated: the default is
`development,acceptance,production`, and `none` writes no `clusters/`. A new name gets `deploy: listed`, except
`development`, which runs every app. The folder of a cluster that is no longer named stays as it is.

## Where the sandbox was

Before 0.41.0 the sandbox's folder was `sandbox/` at the repository's root. It is now `clusters/sandbox/`, next to the
other clusters, and `sandbox/flux/apps/kustomization.yaml` only points there: the appliance's Flux (and a cluster
bootstrapped from the old `sandbox/flux/bootstrap.yaml`) reads `./sandbox/flux/apps` and keeps working unchanged. The
patches are written as YAML, not as JSON strings, and since 0.42.0 the sandbox's are in each app folder's
`gitops/sandbox/kustomization.yaml`.

