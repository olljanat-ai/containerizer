"""External Secrets Operator: how every Secret in the generated configuration is produced.

No generated file holds a Secret object or a secret value. Each Secret that a workload, a Flux source
or an image pull needs is an `ExternalSecret`, which External Secrets Operator (ESO) fills from the
store in `rules/60-security.yaml` (`secrets.store`, default ClusterSecretStore `app-secrets`).

Isolation between namespaces: the store names ServiceAccount `app-secrets-reader` without a namespace,
so ESO authenticates as that ServiceAccount *in the namespace of the ExternalSecret* ("referent"
authentication). A namespace therefore reads only what its own reader identity is granted: a Role
over named remote Secrets (kubernetes provider), a Vault role bound to the namespace, an IAM role
(IRSA) or an Azure workload identity. Remote keys are `<namespace>--<name>`, a form every provider
accepts, so one prefix rule (Vault templated policy, IAM resource pattern) can keep a namespace to its
own keys.
"""
from __future__ import annotations

import copy
import os

API = "external-secrets.io/v1"
STORE_KINDS = ("ClusterSecretStore", "SecretStore")
PROVIDERS = ("kubernetes", "vault", "azurekv", "aws")
# remote names of the platform credentials, `<namespace>--cz-...`: the cz- prefix keeps them apart
# from component keys (`<namespace>--<component>`)
GIT, GIT_GPG, REGISTRY, COSIGN_PUB = "cz-git", "cz-git-gpg", "cz-registry", "cz-cosign-pub"
DOCKERCONFIG = "kubernetes.io/dockerconfigjson"


def cfg() -> dict:
    from .harden import security
    c = security()["secrets"]
    mode = c.get("mode", "external-secrets")
    if mode != "external-secrets":
        raise ValueError(f"rules/60-security.yaml secrets.mode {mode!r}: only external-secrets is supported; "
                         "generated configurations never contain Secret objects")
    if c["store"].get("kind") not in STORE_KINDS:
        raise ValueError(f"secrets.store.kind must be one of {', '.join(STORE_KINDS)}")
    return c


def provider() -> str:
    """The store backend `cluster/secret-store.yaml` is written for (CONTAINERIZER_SECRET_STORE overrides
    the rules)."""
    p = os.environ.get("CONTAINERIZER_SECRET_STORE") or cfg().get("provider", "kubernetes")
    if p not in PROVIDERS or p not in (cfg().get("providers") or {}):
        raise ValueError(f"secret store provider {p!r}: use one of {', '.join(PROVIDERS)}")
    return p


def store_ref() -> dict:
    return dict(cfg()["store"])


def reader() -> str:
    return cfg()["reader"]["name"]


def remote_namespace() -> str:
    """Namespace that holds the remote Secrets (kubernetes provider)."""
    return cfg()["providers"]["kubernetes"]["remoteNamespace"]


def remote_key(namespace: str, name: str) -> str:
    return cfg().get("key_format", "{namespace}--{name}").format(namespace=namespace, name=name)


def external_secret(name: str, namespace: str, remote: str, keys: list[str] | None = None, labels: dict | None = None,
                    secret_type: str | None = None, comment: str | None = None, set_namespace: bool = False) -> dict:
    """ExternalSecret `name` (and its target Secret) in `namespace`: `keys` from properties of the
    remote secret `remote`, or every property when `keys` is empty."""
    c = cfg()
    spec: dict = {"refreshInterval": c.get("refresh_interval", "1h"),
                  "secretStoreRef": store_ref(),
                  "target": {"name": name, "creationPolicy": "Owner", "deletionPolicy": "Retain"}}
    if secret_type:
        # keep the fetched keys, set the Secret type (dockerconfigjson, tls, ...)
        spec["target"]["template"] = {"type": secret_type, "engineVersion": "v2", "mergePolicy": "Merge"}
    if keys:
        spec["data"] = [{"secretKey": k, "remoteRef": {"key": remote, "property": k}} for k in keys]
    else:
        spec["dataFrom"] = [{"extract": {"key": remote}}]
    meta: dict = {"name": name}
    if set_namespace:
        meta["namespace"] = namespace
    if labels:
        meta["labels"] = dict(labels)
    doc = {"apiVersion": API, "kind": "ExternalSecret", "metadata": meta, "spec": spec}
    doc["_comment"] = comment or (f"values come from the secret store ({c['store']['kind']} {c['store']['name']}, "
                                  f"remote key {remote}); never from Git")
    return doc


def reader_service_account(namespace: str, labels: dict | None = None, set_namespace: bool = False) -> dict:
    """The identity the store uses for `namespace`. It runs no pod and mounts no token: ESO asks the
    API for a short-lived token of it (TokenRequest) when it reads the store. `{namespace}` in the
    configured annotations (an IAM role ARN, say) becomes the namespace."""
    c = cfg()
    meta: dict = {"name": reader()}
    if set_namespace:
        meta["namespace"] = namespace
    if labels:
        meta["labels"] = dict(labels)
    ann = {**(c["reader"].get("annotations") or {}),
           **((c["providers"].get(provider()) or {}).get("readerAnnotations") or {})}
    if ann:
        meta["annotations"] = {k: str(v).replace("{namespace}", namespace) for k, v in ann.items()}
    return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta, "automountServiceAccountToken": False}


def store_access(namespace: str, keys: list[str], labels: dict | None = None) -> list[dict]:
    """kubernetes provider: Role + RoleBinding in the remote namespace that let `namespace`'s reader get
    exactly `keys` (no list, no watch, no other Secret). Other providers grant access outside the
    cluster (see docs/external-secrets.md), so this is empty for them."""
    if provider() != "kubernetes" or not keys:
        return []
    rns, name = remote_namespace(), f"{reader()}-{namespace}"
    meta = {"name": name, "namespace": rns, **({"labels": dict(labels)} if labels else {})}
    return [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": dict(meta),
             "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": sorted(set(keys)),
                        "verbs": ["get"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": dict(meta),
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
             "subjects": [{"kind": "ServiceAccount", "name": reader(), "namespace": namespace}]}]


def secret_store(labels: dict | None = None) -> list[dict]:
    """The store definition for the configured provider (cluster-scoped: the platform applies it once).
    kubernetes: also the remote namespace, which may run no pods at all."""
    c, p = cfg(), provider()
    spec = copy.deepcopy(c["providers"][p])
    spec.pop("readerAnnotations", None)
    lab = {"labels": dict(labels)} if labels else {}
    store = {"apiVersion": API, "kind": c["store"]["kind"], "metadata": {"name": c["store"]["name"], **lab},
             "spec": {"provider": {p: spec}}}
    if c["store"]["kind"] == "SecretStore":
        store["_comment"] = "SecretStore: apply one per application namespace (kubectl -n <namespace> apply)"
    if p != "kubernetes":
        return [store]
    rns = spec["remoteNamespace"]
    return [{"apiVersion": "v1", "kind": "Namespace",
             "metadata": {"name": rns, "labels": {**(labels or {}),
                          "pod-security.kubernetes.io/enforce": "restricted",
                          "pod-security.kubernetes.io/enforce-version": "latest"}},
             "_comment": "holds the secret values; only cluster admins and the per-namespace readers' Roles touch it"},
            {"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": "no-workloads", "namespace": rns, **lab},
             "spec": {"hard": {"pods": "0"}}},
            store]


def remote_keys(docs: list[dict]) -> list[str]:
    """Remote keys the ExternalSecrets in `docs` read through the configured store."""
    ref = store_ref()
    keys: set[str] = set()
    for d in docs:
        if not isinstance(d, dict) or d.get("kind") != "ExternalSecret":
            continue
        spec = d.get("spec") or {}
        if (spec.get("secretStoreRef") or {}).get("name") != ref["name"]:
            continue
        keys |= {x["remoteRef"]["key"] for x in spec.get("data") or [] if (x.get("remoteRef") or {}).get("key")}
        keys |= {x["extract"]["key"] for x in spec.get("dataFrom") or [] if (x.get("extract") or {}).get("key")}
    return sorted(keys)
