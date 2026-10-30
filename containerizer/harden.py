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
    """Harden every workload in `docs` in place; returns the applied exceptions."""
    exceptions = exceptions_for(repo, c, plan)
    uid = run_as_uid(c, plan)
    for d in docs:
        for meta, pod in _pod_specs(d):
            harden_pod(meta, pod, uid, component, exceptions)
    return [{"id": ex["id"], "why": ex.get("why", "")} for ex in exceptions]


def namespace_manifest(name: str) -> dict:
    """Namespace that enforces Pod Security "restricted" for everything generated into it."""
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "latest",
                "pod-security.kubernetes.io/warn": "restricted",
                "pod-security.kubernetes.io/audit": "restricted"}}}


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


def lint_manifests(docs: list[dict], where: str = "") -> list[Violation]:
    L = _Lint()
    cfg = L.cfg
    docs = [d for d in docs if isinstance(d, dict)]
    policies = [d for d in docs if d.get("kind") == "NetworkPolicy"]
    for d in docs:
        kind, name = d.get("kind"), (d.get("metadata") or {}).get("name", "?")
        tgt = f"{where}{kind}/{name}"
        if kind == "Secret":
            for k, v in {**(d.get("stringData") or {}), **(d.get("data") or {})}.items():
                if v not in ("", None):
                    L.add("secret-literals", tgt, f"Secret key {k} carries a value; keep values out of manifests")
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
            labels = (meta.get("labels") or {})
            if labels and not any(_selects((p.get("spec") or {}).get("podSelector") or {}, labels) for p in policies):
                L.add("network-policy", tgt, "no NetworkPolicy selects this workload", waived)
            elif not labels and policies == []:
                L.add("network-policy", tgt, "no NetworkPolicy selects this workload", waived)
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
