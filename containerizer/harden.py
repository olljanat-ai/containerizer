"""Kubernetes hardening and a security lint for generated manifests and Dockerfiles.

The baseline in `rules/60-security.yaml` (`hardening.baseline`) is applied to
every generated pod. `hardening.exceptions` relax or extend it only when a rule
condition shows the application needs it (writable folders for nginx, the ping
sysctl for ICMP, a service account token for Kubernetes API clients). Every
applied exception is written on the pod template as an annotation with its
reason, and `lint_manifests` checks the result against Pod Security
"restricted" plus extra hardening checks, honouring only declared waivers.
"""
from __future__ import annotations

import copy
import re
from dataclasses import asdict, dataclass
from datetime import date
from functools import lru_cache

import yaml

from .assess import _closure
from .rules import RULES_DIR, Context, Rule, run_rule

ANNOTATION = "containerizer.io"
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod")


@lru_cache(maxsize=1)
def security() -> dict:
    return yaml.safe_load((RULES_DIR / "60-security.yaml").read_text())


def _merge(dst: dict, src: dict) -> dict:
    """Deep merge; lists are unioned, scalars from src win."""
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        elif isinstance(v, list) and isinstance(dst.get(k), list):
            dst[k] += [x for x in v if x not in dst[k]]
        else:
            dst[k] = copy.deepcopy(v)
    return dst


def _k8s_name(s: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-")
    return s[:63].rstrip("-") or "x"


# --------------------------------------------------------------------------- exceptions

def exceptions_for(repo, c, plan: dict) -> list[dict]:
    """The hardening exceptions whose conditions hold for this component."""
    out = []
    for ex in security()["hardening"].get("exceptions") or []:
        ok = True
        for key, rx in (ex.get("if_plan") or {}).items():
            if plan.get(key) is None or not re.search(str(rx), str(plan.get(key)), re.I):
                ok = False
        if ok and ex.get("when"):
            r = Rule.from_dict({"id": ex["id"], "when": ex["when"], "phase": "harden", "scope": ex.get("scope", "project")})
            if r.scope == "repo":
                ok = run_rule(r, Context(repo, None, c.role)) is not None
            else:
                # the component and the libraries it references ship in the same image
                projects = [c.project] + (_closure(repo, c.project) if ex.get("closure", True) else [])
                ok = any(run_rule(r, Context(repo, p, c.role)) is not None for p in projects)
        if ok and (ex.get("when") or ex.get("if_plan")):
            out.append(ex)
    return out


def run_as_uid(c, plan: dict) -> int:
    ra = security()["hardening"]["run_as"]
    key = "spa" if c.role == "spa" else plan.get("kind")
    return int(ra.get(key, ra["default"]))


def _pod_specs(doc: dict) -> list[tuple[dict, dict]]:
    """(template metadata, pod spec) pairs of a workload document."""
    k = doc.get("kind")
    spec = doc.get("spec") or {}
    if k == "Pod":
        return [(doc.setdefault("metadata", {}), spec)]
    if k == "CronJob":
        tpl = spec.get("jobTemplate", {}).get("spec", {}).get("template")
    elif k in WORKLOAD_KINDS:
        tpl = spec.get("template")
    else:
        return []
    if not tpl:
        return []
    return [(tpl.setdefault("metadata", {}), tpl.setdefault("spec", {}))]


def _volume_name(path: str, taken: set) -> str:
    base = "x-" + _k8s_name(path.strip("/").replace("/", "-") or "root")[:40]
    name, i = base, 1
    while name in taken:
        i += 1
        name = f"{base}-{i}"
    return name


def harden_pod(meta: dict, pod: dict, uid: int, component: str, exceptions: list[dict]) -> None:
    hc = security()["hardening"]
    base = hc["baseline"]
    patch: dict = {}
    for ex in exceptions:
        _merge(patch, ex.get("patch") or {})
    _merge(pod, base["pod"])
    sc = pod.setdefault("securityContext", {})
    sc.update({"runAsUser": uid, "runAsGroup": uid, "fsGroup": uid})
    if patch.get("sysctls"):
        sc["sysctls"] = sc.get("sysctls", []) + [s for s in patch["sysctls"] if s not in sc.get("sysctls", [])]
    if patch.get("automount_token"):
        pod["automountServiceAccountToken"] = True
    volumes = pod.setdefault("volumes", [])
    taken = {v["name"] for v in volumes}
    for c in pod.get("containers", []):
        csc = c.setdefault("securityContext", {})
        _merge(csc, base["container"]["securityContext"])
        csc["capabilities"]["drop"] = ["ALL"]
        if hc.get("apparmor") and hc["apparmor"] != "none":
            csc["appArmorProfile"] = {"type": hc["apparmor"]}
        if patch.get("capabilities_add"):
            csc["capabilities"]["add"] = sorted(set(csc["capabilities"].get("add", [])) | set(patch["capabilities_add"]))
        res = c.setdefault("resources", {})
        for k, v in base["container"]["resources"].items():
            for rk, rv in v.items():
                res.setdefault(k, {}).setdefault(rk, rv)
        _merge(res, patch.get("resources") or {})
        mounts = c.setdefault("volumeMounts", [])
        mounted = {m["mountPath"]: m for m in mounts}
        for w in patch.get("writable") or []:
            if w not in mounted:
                name = _volume_name(w, taken)
                taken.add(name)
                volumes.append({"name": name, "emptyDir": {}})
                mounted[w] = {"name": name, "mountPath": w}
                mounts.append(mounted[w])
        for sm in patch.get("secret_mounts") or []:
            if sm["path"] in mounted:
                continue
            name = _volume_name(sm["name"], taken)
            taken.add(name)
            vol = {"secretName": f"{component}-{sm['name']}", "optional": True, "defaultMode": 0o440}
            if sm.get("items"):
                vol["items"] = sm["items"]
            volumes.append({"name": name, "secret": vol})
            mounted[sm["path"]] = {"name": name, "mountPath": sm["path"], "readOnly": True}
            mounts.append(mounted[sm["path"]])
        env = c.setdefault("env", [])
        have = {e["name"] for e in env}
        for k, v in sorted((patch.get("env") or {}).items()):
            if k not in have:
                env.append({"name": k, "value": str(v)})
        # emptyDir size limits, by the path they are mounted at
        by_vol = {m["name"]: m["mountPath"] for m in mounts}
        for v in volumes:
            if "emptyDir" in v:
                path = by_vol.get(v["name"])
                limit = (patch.get("size_limits") or {}).get(path) or v["emptyDir"].get("sizeLimit") \
                    or base.get("empty_dir_size_limit")
                if limit:
                    v["emptyDir"]["sizeLimit"] = limit
    if exceptions:
        ann = meta.setdefault("annotations", {})
        ann[f"{ANNOTATION}/exceptions"] = ",".join(ex["id"] for ex in exceptions)
        for ex in exceptions:
            ann[f"{ANNOTATION}/exception.{ex['id']}"[:253]] = " ".join(str(ex.get("why", "")).split())
        waives = sorted({w for ex in exceptions for w in ex.get("waives") or []})
        if waives:
            ann[f"{ANNOTATION}/waives"] = ",".join(waives)


def harden_manifests(docs: list[dict], repo, c, plan: dict, component: str) -> list[dict]:
    """Harden every workload in `docs` in place, add the component's ServiceAccount, its
    least-privilege NetworkPolicy and external secrets; returns the applied exceptions."""
    exceptions = exceptions_for(repo, c, plan)
    uid = run_as_uid(c, plan)
    labels = next((d["metadata"].get("labels") for d in docs if d.get("kind") in WORKLOAD_KINDS), None) or \
        {"app.kubernetes.io/name": component}
    hc = security()["hardening"]
    for d in docs:
        for meta, pod in _pod_specs(d):
            harden_pod(meta, pod, uid, component, exceptions)
            if hc.get("service_account"):
                pod["serviceAccountName"] = component
    if hc.get("service_account"):
        docs.insert(0, service_account(component, labels, any(ex.get("patch", {}).get("automount_token") for ex in exceptions)))
        if any(ex.get("patch", {}).get("automount_token") for ex in exceptions):
            docs[1:1] = api_role(component, labels)
    if security().get("network", {}).get("default_deny"):
        egress = egress_for(repo, c)
        plan["egress"] = egress
        docs[:] = [d for d in docs if d.get("kind") != "NetworkPolicy"]
        docs.append(network_policy(component, labels, plan.get("port"), egress))
    externalize_secrets(docs, component, labels, plan)
    return [{"id": ex["id"], "why": ex.get("why", "")} for ex in exceptions]


def service_account(component: str, labels: dict, token: bool) -> dict:
    return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": component, "labels": labels},
            "automountServiceAccountToken": bool(token)}


def api_role(component: str, labels: dict) -> list[dict]:
    """An empty Role bound to the component: Kubernetes API clients get only the verbs added here."""
    return [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": component, "labels": labels},
             "rules": [], "_comment": "add only the API groups, resources and verbs this component uses"},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": component, "labels": labels},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": component},
             "subjects": [{"kind": "ServiceAccount", "name": component}]}]


# --------------------------------------------------------------------------- network

def _projects(repo, c) -> list:
    return [c.project] + _closure(repo, c.project)


def egress_for(repo, c) -> list[dict]:
    """External dependencies a component needs to reach: [{id, ports: [{port, protocol}]}]."""
    from .rules import _candidate_files
    net = security()["network"]
    if c.role in (net.get("no_egress_roles") or []):
        return []
    out = []
    for dep in net.get("egress") or []:
        ports: list = []
        if dep.get("captures_port"):
            rxs = [x["config"] for x in (dep["when"].get("any") or [dep["when"]]) if "config" in x]
            found = set()
            for p in _projects(repo, c):
                ctx = Context(repo, p, c.role)
                for f in _candidate_files(ctx, "config", None):
                    rel = repo.rel(f).replace("\\", "/")
                    if re.search(r"\.Development\.|launchSettings|(^|/)\.vscode/|(^|/)\.idea/", rel, re.I):
                        continue        # development settings are not shipped in the image
                    txt = ctx.text(f, True)
                    for rx in rxs:
                        for m in re.finditer(rx, txt):
                            host = re.search(r"(?:://|=\s*)(?:[^@/\s]*@)?([\w.\-\[\]:*+]+?)(?::\d+|,\d+)", m.group(0))
                            if host and re.match(net.get("local_hosts", "$^"), host.group(1), re.I):
                                continue
                            found.add(int(m.group("port")))
            ports = sorted(x for x in found if 0 < x < 65536)
        else:
            r = Rule.from_dict({"id": dep["id"], "when": dep["when"], "phase": "network"})
            if any(run_rule(r, Context(repo, p, c.role)) is not None for p in _projects(repo, c)):
                ports = dep["ports"]
        if ports:
            norm = []
            for x in ports:
                e = x if isinstance(x, dict) else {"port": int(x), "protocol": "TCP"}
                e.setdefault("protocol", "TCP")
                if e not in norm:
                    norm.append(e)
            out.append({"id": dep["id"], "ports": norm})
    return out


def network_policy(component: str, labels: dict, port, egress: list[dict]) -> dict:
    """Least-privilege NetworkPolicy: the service port in, siblings + DNS + inferred dependencies out."""
    net = security()["network"]
    app = labels.get("app.kubernetes.io/part-of")
    siblings = [{"podSelector": {"matchLabels": {"app.kubernetes.io/part-of": app}}}] if app else []
    ingress = []
    if port:
        ingress.append({"from": copy.deepcopy(net.get("ingress_from") or [{"namespaceSelector": {}}]),
                        "ports": [{"port": port, "protocol": "TCP"}]})
    dns = net["dns"]
    rules = [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": dns["namespace"]}},
                      "podSelector": {"matchLabels": dns["pod_labels"]}}],
              "ports": copy.deepcopy(dns["ports"])}]
    if siblings:
        rules.append({"to": siblings})
    ports = []
    for dep in egress:
        ports += [p for p in dep["ports"] if p not in ports]
    if ports:
        rules.append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": [x for x in net["blocked_cidrs"] if ":" not in x]}},
                             {"ipBlock": {"cidr": "::/0", "except": [x for x in net["blocked_cidrs"] if ":" in x]}},
                             {"namespaceSelector": {}}],
                      "ports": ports})
    doc = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
           "metadata": {"name": component, "labels": labels,
                        "annotations": {f"{ANNOTATION}/egress": ",".join(d["id"] for d in egress) or "none"}},
           "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"],
                    "ingress": ingress, "egress": rules}}
    if siblings:
        doc["spec"]["ingress"].append({"from": siblings})
    return doc


def default_deny_policy() -> dict:
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "default-deny-all"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}


# --------------------------------------------------------------------------- secrets

def externalize_secrets(docs: list[dict], component: str, labels: dict, plan: dict) -> None:
    """Replace Secret skeletons, and Secrets that volumes reference, by ExternalSecrets (External
    Secrets Operator, rules/60-security.yaml `secrets`): the values come from the secret store under
    the remote key `<namespace>--<component>`, one property per Secret key."""
    from . import eso
    eso.cfg()
    wanted: dict[str, list[str]] = {}
    keep = []
    for d in docs:
        if d.get("kind") == "Secret":
            wanted[d["metadata"]["name"]] = list((d.get("stringData") or {}).keys())
        else:
            keep.append(d)
    for d in keep:
        for _, pod in _pod_specs(d):
            for v in pod.get("volumes") or []:
                sec = v.get("secret")
                if sec and sec["secretName"] not in wanted:
                    keys = [i["key"] for i in sec.get("items") or []]
                    if not keys and sec["secretName"].endswith("-files"):
                        keys = list(plan.get("secret_files") or [])
                    if not keys and sec["secretName"].endswith("-keytab"):
                        keys = [_basename(plan.get("env", {}).get("KRB5_KTNAME") or "service.keytab")]
                    wanted[sec["secretName"]] = keys
    docs[:] = keep
    app = labels.get("app.kubernetes.io/part-of", component)
    for name, keys in sorted(wanted.items()):
        # unknown keys: the whole remote secret of that name
        remote = eso.remote_key(app, component if keys else name)
        docs.append(eso.external_secret(name, app, remote, keys, labels))


def _basename(p: str) -> str:
    return p.replace("\\", "/").rsplit("/", 1)[-1]


def namespace_manifest(name: str) -> dict:
    """Namespace that enforces Pod Security "restricted" for everything generated into it."""
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "latest",
                "pod-security.kubernetes.io/warn": "restricted",
                "pod-security.kubernetes.io/audit": "restricted"}}}


# --------------------------------------------------------------------------- application level

_UNITS = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "k": 1e3, "M": 1e6, "G": 1e9, "m": 1e-3}


def _qty(v) -> float:
    m = re.fullmatch(r"([\d.]+)([A-Za-z]*)", str(v))
    return float(m.group(1)) * _UNITS.get(m.group(2), 1) if m else 0.0


def _fmt_qty(v: float, kind: str) -> str:
    if kind == "cpu":
        return f"{int(round(v * 1000))}m"
    return f"{int(-(-v // 2**20))}Mi"


def namespace_policies(app_docs: list[dict]) -> list[dict]:
    """Default-deny NetworkPolicy, LimitRange and a ResourceQuota sized from the generated workloads."""
    np = security()["namespace_policy"]
    totals = {"requests.cpu": 0.0, "requests.memory": 0.0, "limits.memory": 0.0,
              "requests.ephemeral-storage": 0.0, "limits.ephemeral-storage": 0.0}
    pods = 0
    for d in app_docs:
        n = int((d.get("spec") or {}).get("replicas", 1)) if d.get("kind") != "CronJob" else 1
        for _, pod in _pod_specs(d):
            pods += n
            for c in pod.get("containers") or []:
                res = c.get("resources") or {}
                for k in totals:
                    sect, r = k.split(".", 1)
                    totals[k] += n * _qty((res.get(sect) or {}).get(r, 0))
    head = float(np.get("quota_headroom", 1.5))
    hard = {}
    for k, v in totals.items():
        kind = "cpu" if k.endswith("cpu") else "mem"
        val = v * head
        floor = np.get("quota_floor", {}).get(k)
        if floor is not None:
            val = max(val, _qty(floor))
        if val:
            hard[k] = _fmt_qty(val, kind)
    extra = dict(np.get("quota_extra") or {})
    extra["pods"] = max(int(extra.get("pods", 0)), int(pods * head) + 1)
    hard.update({k: str(v) for k, v in extra.items()})
    lr = np["limit_range"]
    out = [{"apiVersion": "v1", "kind": "LimitRange", "metadata": {"name": "defaults"},
            "spec": {"limits": [{"type": "Container", "default": dict(lr["default"]),
                                 "defaultRequest": dict(lr["defaultRequest"]), "max": dict(lr["max"])}]}},
           {"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": "quota"}, "spec": {"hard": hard}}]
    if security().get("network", {}).get("default_deny"):
        out.insert(0, default_deny_policy())
    return out


def cluster_kit(app: str, registry: str) -> dict[str, list[dict]]:
    """Cluster-level starting points (not part of the app's kustomization): audit policy and
    image signature verification."""
    audit = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy",
             "_comment": "NSA/CISA 'Kubernetes native audit logging configuration'; pass with --audit-policy-file",
             "omitStages": ["RequestReceived"],
             "rules": [
                 {"level": "Metadata", "resources": [{"group": "", "resources": ["secrets", "configmaps"]},
                                                     {"group": "authentication.k8s.io", "resources": ["tokenreviews"]}]},
                 {"level": "RequestResponse", "resources": [{"group": "rbac.authorization.k8s.io"}]},
                 {"level": "Request", "verbs": ["create", "update", "patch", "delete", "deletecollection"],
                  "resources": [{"group": ""}, {"group": "apps"}, {"group": "batch"}, {"group": "networking.k8s.io"},
                                {"group": "policy"}]},
                 {"level": "Metadata", "verbs": ["get", "list", "watch"], "resources": [{"group": "", "resources": ["pods/exec", "pods/attach", "pods/portforward"]}]},
                 {"level": "None", "users": ["system:kube-proxy"], "verbs": ["watch"]},
                 {"level": "None", "nonResourceURLs": ["/healthz*", "/readyz*", "/livez*", "/version"]},
                 {"level": "Metadata"}]}
    verify = {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
              "metadata": {"name": f"verify-images-{app}"},
              "_comment": "Kyverno: only cosign-signed images from the application registry run in the namespace; "
                          "replace the key with your signing identity (or use keyless attestors)",
              "spec": {"validationFailureAction": "Enforce", "webhookTimeoutSeconds": 30, "background": False,
                       "rules": [{"name": "signed-images",
                                  "match": {"any": [{"resources": {"kinds": ["Pod"], "namespaces": [app]}}]},
                                  "verifyImages": [{"imageReferences": [f"{registry}/{app}/*"],
                                                    "mutateDigest": True, "verifyDigest": True, "required": True,
                                                    "attestors": [{"entries": [{"keys": {"publicKeys":
                                                        "-----BEGIN PUBLIC KEY-----\n<cosign.pub>\n-----END PUBLIC KEY-----"}}]}]}]}]}}
    return {"cluster/audit-policy.yaml": [audit], "cluster/verify-images.yaml": [verify]}


def write_app_security(out, app: str, comp_docs: dict[str, list[dict]], registry: str, dump) -> list[str]:
    """Write security.yaml (kustomization resource), the cluster/ kit and HARDENING.md.
    Returns (resources to add to the app's kustomization, the namespace policy docs)."""
    from pathlib import Path
    out = Path(out)
    from . import eso
    all_docs = [d for docs in comp_docs.values() for d in docs]
    # the namespace's identity towards the secret store (docs/external-secrets.md)
    ns_docs = namespace_policies(all_docs) + [eso.reader_service_account(app)]
    _NS_POLICIES[app] = ns_docs
    (out / "security.yaml").write_text(dump(ns_docs))
    for rel, docs in cluster_kit(app, registry).items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_text(dump(docs))
    (out / "HARDENING.md").write_text(hardening_markdown(app, comp_docs))
    return ["security.yaml"], ns_docs


# namespace policies of the app being generated, for harden_gitops (called by gitops.py right after)
_NS_POLICIES: dict[str, list[dict]] = {}


PLATFORM_KINDS = ("ResourceQuota", "LimitRange")


def _delete_patch(kind: str, name: str, api: str = "v1") -> dict:
    return {"patch": f"$patch: delete\napiVersion: {api}\nkind: {kind}\nmetadata:\n  name: {name}\n",
            "target": {"kind": kind, "name": name}}


def harden_gitops(docs: dict[str, list[dict]], a=None) -> dict[str, list[dict]]:
    """Security post-processing of the Argo CD / Flux manifests from gitops.py.

    - Flux: the tenant ServiceAccount is bound to `admin`, which cannot manage quotas, and the
      default-deny policy should not be removable from the app repository; so the namespace
      policies (default deny, LimitRange, ResourceQuota) move into the platform-owned tenant file
      and are dropped from the synced set.
    - Argo CD: the controller applies them; the AppProject keeps cluster-scoped kinds to the
      Namespace that CreateNamespace needs, and denies RBAC objects unless a component needs an API Role.
    - Both: secrets come from the external store, so the secret CRD is the only Secret source allowed.
    """
    from .generate import k8s_name
    ns = k8s_name(a.name) if a is not None else None
    policies = copy.deepcopy(_NS_POLICIES.get(ns) or namespace_policies([]))
    for p in policies:
        p.setdefault("metadata", {})["namespace"] = ns
    from .eso import reader
    # the secret store reader too: the Flux source's own ExternalSecret needs it before the first sync
    platform = [(p["kind"], p["metadata"]["name"], p["apiVersion"]) for p in policies
                if p["kind"] in PLATFORM_KINDS or p["metadata"]["name"] == "default-deny-all"
                or (p["kind"], p["metadata"]["name"]) == ("ServiceAccount", reader())]
    for path, items in docs.items():
        for d in items:
            kind = d.get("kind")
            if kind not in ("AppProject", "Application", "Kustomization"):
                continue        # no spec to add (a ServiceAccount, Role or Namespace has none)
            spec = d.setdefault("spec", {})
            if kind == "AppProject":
                spec["clusterResourceWhitelist"] = [w for w in spec.get("clusterResourceWhitelist") or []
                                                    if (w.get("group"), w.get("kind")) == ("", "Namespace")]
                wl = spec.setdefault("namespaceResourceWhitelist", [])
                # a plain Secret from Git would overwrite the values the external store manages
                wl[:] = [w for w in wl if (w.get("group"), w.get("kind")) != ("", "Secret")]
                spec["sourceNamespaces"] = []
                spec["orphanedResources"] = {"warn": True}
                spec.setdefault("signatureKeys", [])
            elif kind == "Application":
                opts = spec.setdefault("syncPolicy", {}).setdefault("syncOptions", [])
                for o in ("ServerSideApply=true", "PruneLast=true", "FailOnSharedResource=true"):
                    if o not in opts:
                        opts.append(o)
            elif kind == "Kustomization" and str(d.get("apiVersion", "")).startswith("kustomize.toolkit.fluxcd.io"):
                patches = spec.setdefault("patches", [])
                for k, n, api in platform:
                    dp = _delete_patch(k, n, api)
                    if dp not in patches:
                        patches.append(dp)
                spec["force"] = False
        if path == "flux/tenant.yaml":
            names = {(x.get("kind"), (x.get("metadata") or {}).get("name")) for x in items}
            items += [p for p in policies if (p["kind"], p["metadata"]["name"]) not in names]
    return docs


# --------------------------------------------------------------------------- report

def hardening_markdown(app: str, comp_docs: dict[str, list[dict]]) -> str:
    """Each NSA/CISA and CIS control: applied, applied with exception, not applied, not applicable,
    or an action for the cluster operator / pipeline, with the guide section."""
    viol: dict[str, list[Violation]] = {}
    exceptions: dict[str, set] = {}
    egress: dict[str, str] = {}
    provided = external_secret_targets([d for docs in comp_docs.values() for d in docs])
    for comp, docs in comp_docs.items():
        for v in lint_manifests(docs, f"{comp}: ", provided):
            viol.setdefault(v.check, []).append(v)
        for d in docs:
            for meta, _ in _pod_specs(d):
                for e in ((meta.get("annotations") or {}).get(f"{ANNOTATION}/exceptions") or "").split(","):
                    if e:
                        exceptions.setdefault(e, set()).add(comp)
            if d.get("kind") == "NetworkPolicy":
                egress[comp] = (d["metadata"].get("annotations") or {}).get(f"{ANNOTATION}/egress", "")
    rows = []
    counts: dict[str, int] = {}
    for ctl in security().get("controls") or []:
        scope = ctl.get("scope")
        checks = ctl.get("checks") or []
        bad = [v for c in checks for v in viol.get(c, [])]
        exc = sorted({f"{e} ({', '.join(sorted(exceptions[e]))})" for e in ctl.get("exception") or [] if e in exceptions})
        if scope == "cluster":
            status, note = "cluster action", ctl.get("action", "")
        elif scope == "deviation":
            status, note = "not applied", ctl.get("action", "")
        elif scope == "gitops":
            status, note = "applied in gitops/", ctl.get("action", "")
        elif bad:
            status = "not applied"
            note = "; ".join(sorted({f"{v.check}: {v.message} ({v.target.strip(': ')})" for v in bad})[:4])
            if ctl.get("action"):
                note = f"{ctl['action']} Now: {note}"
        elif exc:
            status, note = "applied with exception", "exception: " + ", ".join(exc)
        else:
            status = "applied"
            note = ctl.get("action", "") if scope == "pipeline" else ""
            if ctl["id"] in ("sa-tokens", "rbac-apps") and "kubernetes-api-client" not in exceptions:
                note = "no component calls the Kubernetes API"
            if ctl["id"] == "network-policies":
                note = ctl.get("action", "")
        counts[status] = counts.get(status, 0) + 1
        rows.append(f"| {ctl['title']} | {status} | {ctl.get('nsa', '')} | {ctl.get('cis', '')} | {note} |")
    lines = [f"# Hardening report: {app}", "",
             "Controls from the NSA/CISA Kubernetes Hardening Guide (v1.2) and the CIS Kubernetes Benchmark, "
             "checked against the generated manifests. " + ", ".join(f"{v} {k}" for k, v in counts.items()) + ".", "",
             "| Control | Status | NSA/CISA guide section | CIS | Notes |", "| --- | --- | --- | --- | --- |", *rows, ""]
    if egress:
        lines += ["## Network egress per component", "",
                  "Inferred from packages and configuration; everything else is denied. Review before production.", "",
                  "| Component | Allowed external dependencies |", "| --- | --- |"]
        lines += [f"| {c} | {e or 'none (DNS and sibling components only)'} |" for c, e in sorted(egress.items())]
        lines.append("")
    if exceptions:
        lines += ["## Hardening exceptions", "", "| Exception | Components |", "| --- | --- |"]
        lines += [f"| {e} | {', '.join(sorted(c))} |" for e, c in sorted(exceptions.items())]
        lines.append("")
    remote = []
    for comp, docs in sorted(comp_docs.items()):
        for d in docs:
            if d.get("kind") != "ExternalSecret":
                continue
            spec = d.get("spec") or {}
            for x in spec.get("data") or []:
                remote.append((x["remoteRef"]["key"], f"`{x['remoteRef'].get('property', '')}`", comp, d["metadata"]["name"]))
            for x in spec.get("dataFrom") or []:
                if (x.get("extract") or {}).get("key"):
                    remote.append((x["extract"]["key"], "every key", comp, d["metadata"]["name"]))
    if remote:
        lines += ["## Secret store keys", "",
                  "Put these in the secret store before the first sync (docs/external-secrets.md); External Secrets "
                  "Operator copies them into the Secrets the workloads use. If one property is missing, that whole "
                  "Secret is not created; the references are optional, so the pod still starts, without its values.", "",
                  "| Remote key | Property | Component | Secret |", "| --- | --- | --- | --- |"]
        lines += [f"| `{k}` | {p} | {c} | `{n}` |" for k, p, c, n in sorted(remote)]
        lines.append("")
    lines += ["## Files", "",
              "- `security.yaml`: default-deny NetworkPolicy, LimitRange and ResourceQuota for the namespace",
              "- `namespace.yaml`: Pod Security Admission `restricted` (enforce, warn, audit)",
              "- `<component>/k8s.yaml`: hardened workloads, own ServiceAccount, least-privilege NetworkPolicy, ExternalSecrets",
              "- `cluster/audit-policy.yaml`, `cluster/verify-images.yaml`, `cluster/secret-store.yaml` (the secret "
              "store and this namespace's read access): for the cluster operator, not applied with the app", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- lint

@dataclass
class Violation:
    check: str
    severity: str
    target: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


class _Lint:
    def __init__(self):
        self.cfg = security()["lint"]
        self.out: list[Violation] = []

    def add(self, check: str, target: str, message: str, waived: set | None = None) -> None:
        if waived and check in waived:
            return
        sev = self.cfg["checks"].get(check, {}).get("severity", "error")
        self.out.append(Violation(check, sev, target, message))


def _secret_name(name: str) -> bool:
    return bool(re.search(security()["lint"]["secret_names"], name or ""))


def external_secret_targets(docs: list[dict]) -> set[str]:
    """Names of the Secrets that ExternalSecrets in `docs` produce."""
    return {((d.get("spec") or {}).get("target") or {}).get("name") or (d.get("metadata") or {}).get("name")
            for d in docs if isinstance(d, dict) and d.get("kind") == "ExternalSecret"}


def _secret_refs(pod: dict) -> list[tuple[str, str]]:
    """(Secret name, where) for every Secret a pod spec references."""
    out = [(p.get("name"), "imagePullSecrets") for p in pod.get("imagePullSecrets") or []]
    for v in pod.get("volumes") or []:
        if (v.get("secret") or {}).get("secretName"):
            out.append((v["secret"]["secretName"], f"volume {v.get('name')}"))
        for src in (v.get("projected") or {}).get("sources") or []:
            if (src.get("secret") or {}).get("name"):
                out.append((src["secret"]["name"], f"projected volume {v.get('name')}"))
    for c in (pod.get("initContainers") or []) + (pod.get("containers") or []):
        for e in c.get("env") or []:
            ref = ((e.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name")
            if ref:
                out.append((ref, f"{c.get('name')} env {e.get('name')}"))
        for e in c.get("envFrom") or []:
            if (e.get("secretRef") or {}).get("name"):
                out.append((e["secretRef"]["name"], f"{c.get('name')} envFrom"))
    return [(n, w) for n, w in out if n]


def _lint_external_secret(L: "_Lint", d: dict, tgt: str) -> None:
    """ExternalSecrets read a store (or an in-cluster generator) and never carry a value themselves."""
    from .eso import STORE_KINDS
    spec = d.get("spec") or {}
    ref = spec.get("secretStoreRef") or {}
    generated = any((x.get("sourceRef") or {}).get("generatorRef") for x in spec.get("dataFrom") or [])
    if not generated and (ref.get("kind", "SecretStore") not in STORE_KINDS or not ref.get("name")):
        L.add("external-secret-store", tgt, "secretStoreRef names no SecretStore / ClusterSecretStore")
    for k, v in (((spec.get("target") or {}).get("template") or {}).get("data") or {}).items():
        if _secret_name(k) and isinstance(v, str) and v and "{{" not in v:
            L.add("secret-literals", tgt, f"template key {k} carries a literal value; read it from the store")


def lint_manifests(docs: list[dict], where: str = "", provided: set[str] | None = None) -> list[Violation]:
    """`provided`: Secret names that ExternalSecrets elsewhere in the app produce (another component's
    folder, pull-secret.yaml)."""
    L = _Lint()
    cfg = L.cfg
    docs = [d for d in docs if isinstance(d, dict)]
    policies = [d for d in docs if d.get("kind") == "NetworkPolicy"]
    produced = external_secret_targets(docs) | set(provided or ())
    for d in docs:
        kind, name = d.get("kind"), (d.get("metadata") or {}).get("name", "?")
        tgt = f"{where}{kind}/{name}"
        if kind == "Secret":
            for k, v in {**(d.get("stringData") or {}), **(d.get("data") or {})}.items():
                if v not in ("", None):
                    L.add("secret-literals", tgt, f"Secret key {k} carries a value; keep values out of manifests")
            L.add("plain-secret", tgt, "Secret object in the manifests; use an ExternalSecret (External Secrets Operator)")
            continue
        if kind in ("SecretStore", "ClusterSecretStore"):
            L.add("external-secret-store", tgt, f"{kind} in the app's manifests; the platform defines the store "
                                                "(cluster/secret-store.yaml)")
            continue
        if kind == "ExternalSecret":
            _lint_external_secret(L, d, tgt)
            continue
        for meta, pod in _pod_specs(d):
            waived = {w.strip() for w in ((meta.get("annotations") or {}).get(f"{ANNOTATION}/waives") or "").split(",") if w.strip()}
            psc = pod.get("securityContext") or {}
            for hk in ("hostNetwork", "hostPID", "hostIPC"):
                if pod.get(hk):
                    L.add("host-namespaces", tgt, f"{hk} is true", waived)
            for v in pod.get("volumes") or []:
                vt = next((k for k in v if k != "name"), None)
                if vt not in cfg["allowed_volume_types"]:
                    L.add("volume-types", tgt, f"volume {v.get('name')} uses {vt}", waived)
                if vt == "emptyDir" and not (v.get("emptyDir") or {}).get("sizeLimit"):
                    L.add("empty-dir-limit", tgt, f"emptyDir {v.get('name')} has no sizeLimit", waived)
            for s in psc.get("sysctls") or []:
                if s.get("name") not in cfg["safe_sysctls"]:
                    L.add("sysctls", tgt, f"sysctl {s.get('name')} is not in the safe set", waived)
            if pod.get("automountServiceAccountToken") is not False:
                L.add("sa-token", tgt, "automountServiceAccountToken is not false", waived)
            for ref, at in _secret_refs(pod):
                if ref not in produced:
                    L.add("secret-source", tgt, f"Secret {ref} ({at}) is not produced by an ExternalSecret", waived)
            labels = (meta.get("labels") or {})
            selecting = [p for p in policies if _selects((p.get("spec") or {}).get("podSelector") or {}, labels)]
            if not selecting:
                L.add("network-policy", tgt, "no NetworkPolicy selects this workload", waived)
            if not any("Egress" in ((p.get("spec") or {}).get("policyTypes") or []) for p in selecting):
                L.add("egress-policy", tgt, "egress is not restricted by any NetworkPolicy", waived)
            if pod.get("serviceAccountName") in (None, "", "default") and pod.get("serviceAccount") in (None, "", "default"):
                L.add("service-account", tgt, "runs as the namespace's default ServiceAccount", waived)
            pod_nonroot = psc.get("runAsNonRoot") is True
            pod_seccomp = (psc.get("seccompProfile") or {}).get("type")
            for c in (pod.get("initContainers") or []) + (pod.get("containers") or []):
                ct = f"{tgt}/{c.get('name')}"
                sc = c.get("securityContext") or {}
                if sc.get("privileged"):
                    L.add("privileged", ct, "privileged is true", waived)
                caps = sc.get("capabilities") or {}
                if "ALL" not in (caps.get("drop") or []):
                    L.add("capabilities", ct, "capabilities.drop does not include ALL", waived)
                extra = [x for x in caps.get("add") or [] if x not in cfg["allowed_capabilities"]]
                if extra:
                    L.add("capabilities", ct, f"adds capabilities {', '.join(extra)}", waived)
                if sc.get("allowPrivilegeEscalation") is not False:
                    L.add("privilege-escalation", ct, "allowPrivilegeEscalation is not false", waived)
                nonroot = sc.get("runAsNonRoot", pod_nonroot) is True
                if not nonroot or 0 in (sc.get("runAsUser"), psc.get("runAsUser")):
                    L.add("run-as-non-root", ct, "not guaranteed to run as non-root", waived)
                if (sc.get("seccompProfile") or {}).get("type", pod_seccomp) not in ("RuntimeDefault", "Localhost"):
                    L.add("seccomp", ct, "no RuntimeDefault/Localhost seccomp profile", waived)
                if not (sc.get("appArmorProfile") or psc.get("appArmorProfile")
                        or any(k.startswith("container.apparmor.security.beta.kubernetes.io/")
                               for k in (meta.get("annotations") or {}))):
                    L.add("apparmor", ct, "no AppArmor profile", waived)
                if sc.get("readOnlyRootFilesystem") is not True:
                    L.add("readonly-rootfs", ct, "readOnlyRootFilesystem is not true", waived)
                for p in c.get("ports") or []:
                    if p.get("hostPort"):
                        L.add("host-ports", ct, f"hostPort {p['hostPort']}", waived)
                res = c.get("resources") or {}
                req, lim = res.get("requests") or {}, res.get("limits") or {}
                if not (req.get("cpu") and req.get("memory") and lim.get("memory")):
                    L.add("resources", ct, "needs cpu/memory requests and a memory limit", waived)
                for e in c.get("env") or []:
                    if "value" in e and e.get("value") not in ("", None) and _secret_name(e.get("name", "")) \
                            and not _looks_like_path(str(e["value"])):
                        L.add("secret-literals", ct, f"env {e['name']} has a literal value; use a secretKeyRef", waived)
                img = c.get("image") or ""
                if "@sha256:" not in img and (":" not in img.rsplit("/", 1)[-1] or img.endswith(":latest")):
                    L.add("image-tag", ct, f"image {img} uses latest or no tag", waived)
                if "@sha256:" not in img:
                    L.add("image-digest", ct, f"image {img} is not pinned to a digest", waived)
    return L.out


def _looks_like_path(v: str) -> bool:
    return v.startswith(("/", "FILE:", "file:")) or v.lower() in ("true", "false")


def _selects(selector: dict, labels: dict) -> bool:
    ml = selector.get("matchLabels") or {}
    if not ml and not selector.get("matchExpressions"):
        return True     # empty selector selects every pod
    return all(labels.get(k) == v for k, v in ml.items())


# --------------------------------------------------------------------------- Dockerfiles

def _stages(dockerfile: str) -> list[dict]:
    """FROM stages of a Dockerfile: [{'base', 'name', 'lines'}]."""
    stages: list[dict] = []
    text = re.sub(r"\\\n", " ", dockerfile)
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", s, re.I)
        if m:
            stages.append({"base": m.group(1), "name": (m.group(2) or "").lower(), "lines": []})
        elif stages:
            stages[-1]["lines"].append(s)
    return stages


def lifecycle(ref: str, today: date | None = None) -> dict | None:
    """End-of-support entry for an image reference, with days left."""
    today = today or date.today()
    for e in security()["images"].get("lifecycle") or []:
        if re.search(e["match"], ref):
            eol = e["eol"] if isinstance(e["eol"], date) else date.fromisoformat(str(e["eol"]))
            return {**e, "eol": eol.isoformat(), "days_left": (eol - today).days}
    return None


def lint_dockerfile(dockerfile: str, where: str = "Dockerfile", today: date | None = None) -> list[Violation]:
    L = _Lint()
    cfg = L.cfg
    stages = _stages(dockerfile)
    names = {s["name"] for s in stages if s["name"]}
    warn_days = security()["images"].get("warn_days_before_eol", 60)
    for i, st in enumerate(stages):
        final = i == len(stages) - 1
        refs = [st["base"]] + [m.group(1) for ln in st["lines"] for m in [re.search(r"COPY\s+.*--from=(\S+)", ln)] if m]
        for ref in refs:
            if ref.lower() in names or ref.lower() == "scratch" or ref.isdigit():
                continue
            repo_tag = ref.split("@")[0]
            last = repo_tag.rsplit("/", 1)[-1]
            if "@sha256:" not in ref and (":" not in last or last.endswith(":latest")):
                L.add("df-base-tag", where, f"{ref} has no explicit version tag")
            elif last.endswith(":latest"):
                L.add("df-base-tag", where, f"{ref} uses latest")
            if "@sha256:" not in ref:
                L.add("df-base-digest", where, f"{ref} is not pinned to a digest (generate --pin-digests)")
            lc = lifecycle(ref, today)
            if lc and lc["days_left"] < warn_days:
                when = f"reached end of support on {lc['eol']}" if lc["days_left"] < 0 else \
                    f"reaches end of support on {lc['eol']} ({lc['days_left']} days)"
                nxt = f"; move to {lc['next']}" if lc.get("next") else ""
                L.add("df-base-eol", where, f"{'runtime' if final else 'build'} image {ref} {when}{nxt}")
        for ln in st["lines"]:
            if re.match(r"ADD\s+(--\S+\s+)*https?://", ln, re.I) or re.search(r"(curl|wget)\b[^|;&]*\|\s*(ba|z)?sh\b", ln):
                L.add("df-remote-add", where, f"remote code fetched at build time: {ln[:100]}")
            m = re.match(r"ENV\s+(.*)", ln, re.I)
            if m:
                for k, v in re.findall(r'([A-Za-z_][\w.]*)=("[^"]*"|\S+)', m.group(1)):
                    v = v.strip('"')
                    if v and _secret_name(k) and not _looks_like_path(v):
                        L.add("secret-literals", where, f"ENV {k} carries a literal value")
    if stages:
        last = stages[-1]
        users = [ln.split(None, 1)[1].strip() for ln in last["lines"] if re.match(r"USER\s+\S", ln, re.I)]
        if users:
            u = users[-1].split(":")[0]
            if u in ("0", "root"):
                L.add("df-user", where, "final stage runs as root")
        elif not any(re.search(p, last["base"]) for p in cfg["nonroot_bases"]):
            L.add("df-user", where, f"final stage has no USER and {last['base']} is not a known non-root image")
    return L.out


def summarize(violations: list[Violation]) -> dict:
    out = {"error": 0, "warning": 0, "info": 0}
    for v in violations:
        out[v.severity] = out.get(v.severity, 0) + 1
    return out


def load_yaml_docs(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if d]
