"""Flux files for the generated manifests (the only GitOps tool: Argo CD support was removed in 0.9.2).

They deploy the app folder that `generate` writes (its kustomization.yaml) with a least-privilege layout:

- the reconciler may only touch the app's namespace;
- the namespace itself (with Pod Security "restricted" labels) is created by the platform side
  (the Flux tenant file), not by the app's own manifests;
- Flux applies as a namespace-scoped ServiceAccount (impersonation), never as the controller;
- the OCI source variant only accepts artifacts signed with cosign.

`harden.harden_gitops(docs, a)`, when present, post-processes the result (security thread).
"""
from __future__ import annotations

from dataclasses import dataclass

from .generate import k8s_name

FLUX_NS = "flux-system"
SOURCE_API = "source.toolkit.fluxcd.io/v1"
KUSTOMIZE_API = "kustomize.toolkit.fluxcd.io/v1"
IMAGE_API = "image.toolkit.fluxcd.io/v1"


@dataclass
class GitOpsOptions:
    git_url: str = "https://git.example.com/platform/deployments.git"
    branch: str = "main"
    path: str = ""                        # folder of the app's kustomization.yaml in that repo
    oci_url: str = ""                     # oci://registry/<app>/manifests (default from the registry)
    tag_range: str = ">=1.0.0"            # semver range image automation may roll out
    verify_commits: bool = False          # Flux: only reconcile commits signed with a key in <app>-git-gpg
    image_pull_secret: str = ""           # Secret name the workloads pull with (an ExternalSecret, cz-registry)
    ingress_domain: str = ""              # wildcard domain: an HTTPS Ingress per web component (sandbox_https.py)
    sandbox_idp: bool = True              # with a domain: point components that sign in at the sandbox IdP (idp.py)


def _namespace_delete_patch(ns: str) -> dict:
    """Kustomize patch that drops the app's Namespace from the synced set: the platform creates it."""
    return {"patch": f"$patch: delete\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: {ns}\n",
            "target": {"kind": "Namespace", "name": ns}}


def gitops_manifests(a, kinds: list[tuple[str, str]], images: list[tuple[str, str]], namespace_doc: dict,
                     opts: GitOpsOptions | None = None, registry: str = "registry.local",
                     secret_keys: list[str] | tuple = ()) -> dict[str, list[dict]]:
    """`kinds`: (apiVersion, kind) of every generated namespaced resource; `images`: (component, image);
    `secret_keys`: remote keys the app's own ExternalSecrets read (granted to the namespace in the tenant)."""
    from . import eso
    o = opts or GitOpsOptions()
    ns = k8s_name(a.name)
    path = (o.path or f"deploy/{ns}").strip("/")
    oci_url = o.oci_url or f"oci://{registry}/{ns}/manifests"
    labels = {"app.kubernetes.io/part-of": ns, "app.kubernetes.io/managed-by": "containerizer"}
    ns_labels = dict(namespace_doc.get("metadata", {}).get("labels") or {})
    out: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------ Flux
    sa = f"{ns}-reconciler"
    out["flux/tenant.yaml"] = [
        {**namespace_doc, "metadata": {**namespace_doc["metadata"], "labels": {**ns_labels, **labels}}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa, "namespace": ns, "labels": labels},
         "automountServiceAccountToken": False},
        # namespace-scoped: the built-in "admin" role through a RoleBinding grants nothing outside ns
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": sa, "namespace": ns, "labels": labels},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "admin"},
         "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": ns}]},
    ]

    def credential(name: str, remote: str, what: str, secret_type: str | None = None) -> dict:
        return eso.external_secret(name, ns, eso.remote_key(ns, remote), labels=labels, secret_type=secret_type,
                                   set_namespace=True,
                                   comment=f"{what}: every key of remote secret {eso.remote_key(ns, remote)} "
                                           "in the secret store, never from Git")

    git_secrets = [credential(f"{ns}-git", eso.GIT, "read-only deploy key or token (identity + known_hosts, "
                                                    "or username + password)")]
    if o.verify_commits:
        git_secrets.append(credential(f"{ns}-git-gpg", eso.GIT_GPG, "public GPG keys commits must be signed with"))
    registry_secret = credential(f"{ns}-registry", eso.REGISTRY, "registry read credential (.dockerconfigjson)",
                                 eso.DOCKERCONFIG)
    oci_secrets = [registry_secret, credential(f"{ns}-cosign-pub", eso.COSIGN_PUB, "cosign public key (cosign.pub)")]
    flux_keys = eso.remote_keys(git_secrets + oci_secrets) + list(secret_keys)
    out["flux/tenant.yaml"] += [eso.reader_service_account(ns, labels, set_namespace=True)] + \
        eso.store_access(ns, flux_keys, labels)

    def kustomization(source_kind: str) -> dict:
        return {"apiVersion": KUSTOMIZE_API, "kind": "Kustomization",
                "metadata": {"name": ns, "namespace": ns, "labels": labels},
                "spec": {"interval": "10m", "retryInterval": "2m", "timeout": "5m",
                         "sourceRef": {"kind": source_kind, "name": ns},
                         "path": f"./{path}" if source_kind == "GitRepository" else "./",
                         "prune": True, "wait": True, "targetNamespace": ns,
                         "serviceAccountName": sa,
                         "patches": [_namespace_delete_patch(ns)]}}

    git_source = {"apiVersion": SOURCE_API, "kind": "GitRepository",
                  "metadata": {"name": ns, "namespace": ns, "labels": labels},
                  "spec": {"interval": "5m", "url": o.git_url, "ref": {"branch": o.branch},
                           # read-only deploy key or token for this repository only
                           "secretRef": {"name": f"{ns}-git"},
                           **({"verify": {"mode": "HEAD", "secretRef": {"name": f"{ns}-git-gpg"}}}
                              if o.verify_commits else {})}}
    out["flux/git/sync.yaml"] = git_secrets + [git_source, kustomization("GitRepository")]

    oci_source = {"apiVersion": SOURCE_API, "kind": "OCIRepository",
                  "metadata": {"name": ns, "namespace": ns, "labels": labels},
                  "spec": {"interval": "5m", "url": oci_url, "ref": {"semver": o.tag_range},
                           "secretRef": {"name": f"{ns}-registry"},
                           # only artifacts signed with the key in this Secret are applied
                           "verify": {"provider": "cosign", "secretRef": {"name": f"{ns}-cosign-pub"}}}}
    out["flux/oci/sync.yaml"] = oci_secrets + [oci_source, kustomization("OCIRepository")]

    if images:
        auto: list[dict] = [registry_secret]
        for c, img in images:
            name = k8s_name(c)
            auto += [
                {"apiVersion": IMAGE_API, "kind": "ImageRepository",
                 "metadata": {"name": name, "namespace": ns, "labels": labels},
                 "spec": {"image": img.rsplit(":", 1)[0], "interval": "10m",
                          "secretRef": {"name": f"{ns}-registry"}}},
                {"apiVersion": IMAGE_API, "kind": "ImagePolicy",
                 "metadata": {"name": name, "namespace": ns, "labels": labels},
                 "spec": {"imageRepositoryRef": {"name": name}, "policy": {"semver": {"range": o.tag_range}}}},
            ]
        auto.append(
            {"apiVersion": IMAGE_API, "kind": "ImageUpdateAutomation",
             "metadata": {"name": ns, "namespace": ns, "labels": labels},
             "spec": {"interval": "30m",
                      "sourceRef": {"kind": "GitRepository", "name": ns},
                      "git": {"checkout": {"ref": {"branch": o.branch}},
                              "commit": {"author": {"name": "fluxcdbot", "email": "fluxcdbot@users.noreply.github.com"},
                                         "messageTemplate": "Update {{range .Changed.Changes}}{{.OldValue}} -> {{.NewValue}} {{end}}"},
                              "push": {"branch": o.branch}},
                      "update": {"strategy": "Setters", "path": f"./{path}"}}})
        out["flux/git/image-automation.yaml"] = auto

    try:
        from .harden import harden_gitops
    except ImportError:
        harden_gitops = None
    if harden_gitops:
        harden_gitops(out, a)
    return out


def image_setters(ns: str, images: list[tuple[str, str]]) -> str:
    """kustomization.yaml `images:` block with Flux setter markers."""
    lines = ["images:"]
    for c, img in images:
        repo, tag = img.rsplit(":", 1)
        lines += [f"  - name: {repo}",
                  f'    newTag: {tag} # {{"$imagepolicy": "{ns}:{k8s_name(c)}:tag"}}']
    return "\n".join(lines) + "\n"


def readme(a, opts: GitOpsOptions | None = None) -> str:
    o = opts or GitOpsOptions()
    ns = k8s_name(a.name)
    path = (o.path or f"deploy/{ns}").strip("/")
    return f"""# Deploying {a.name} with GitOps

Commit the generated app folder (the one with `kustomization.yaml`) to `{o.git_url}` at
`{path}` on `{o.branch}`, then apply the Flux files below. They apply the manifests with tight
limits: only namespace `{ns}`, Pod Security "restricted" on the namespace, pruning and drift correction on.

## Flux

```sh
kubectl apply -f flux/tenant.yaml          # platform admin: namespace, ServiceAccounts, RoleBinding, store access
kubectl apply -f flux/git/sync.yaml        # or flux/oci/sync.yaml, not both
kubectl apply -f flux/git/image-automation.yaml   # optional
```

- `tenant.yaml` is the only part that needs cluster rights. Everything else lives in `{ns}` and is
  applied as ServiceAccount `{ns}-reconciler`, bound to the built-in `admin` role in that
  namespace only. Run the controllers with `--no-cross-namespace-refs` and
  `--default-service-account` for a full lockdown.
- No credential is in these files. Each Secret Flux needs is an `ExternalSecret` that External Secrets
  Operator fills from the secret store (see `../HARDENING.md` and docs/external-secrets.md). Put these
  remote secrets in the store first:

  | Remote key | Keys | Used by |
  | --- | --- | --- |
  | `{ns}--cz-git` | `identity` + `known_hosts` (deploy key), or `username` + `password` (token) | `GitRepository` (read-only; write for image automation) |{f"""
  | `{ns}--cz-git-gpg` | the public keys, one per key | commit verification |""" if o.verify_commits else ""}
  | `{ns}--cz-registry` | `.dockerconfigjson` | `OCIRepository`, `ImageRepository`, image pulls |
  | `{ns}--cz-cosign-pub` | `cosign.pub` | `OCIRepository` signature check |

- `git/sync.yaml`: `GitRepository` with a read-only deploy key and a `Kustomization`
  (prune, wait, health checks).{" Commits must be signed with a key in Secret `" + ns + "-git-gpg`." if o.verify_commits else " Set commit verification (`spec.verify`) when your commits are signed."}
- `oci/sync.yaml`: the same, from an OCI artifact (`flux push artifact {o.oci_url or f"oci://<registry>/{ns}/manifests"}:1.0.0
  --path={path}`), accepted only when signed with the cosign key in Secret `{ns}-cosign-pub`.
- `git/image-automation.yaml`: `ImageRepository`, `ImagePolicy` (semver `{o.tag_range}`) and
  `ImageUpdateAutomation`; the `$imagepolicy` markers in `kustomization.yaml` say what it may change.
  It needs a deploy key with write access, so keep it separate from the read-only sync key if you
  can.

No Helm chart is generated, so there is no `HelmRelease`: the app is plain Kustomize.
"""
