"""Generates container build files and Kubernetes manifests from an assessment.

Nothing is written into the application's source tree: Dockerfiles use the
application folder as build context and carry their own
`<Dockerfile>.dockerignore` (BuildKit), so the application needs no changes.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
from functools import lru_cache
from pathlib import Path, PurePosixPath

import yaml

from .assess import AppAssessment, Component
from .harden import cronjob_limits, harden_manifests, namespace_manifest, write_app_security
from .rules import RULES_DIR, Context, Rule, load_rules, run_rule

CONTAINER_PORT = 8080
SAFE_NAME = re.compile(r"[^a-z0-9-]+")


IMAGES_LOCK = RULES_DIR / "images.lock.yaml"


def images_lock() -> dict:
    """Patched base image tags chosen by `containerizer images --update` (CONTAINERIZER_IMAGES_LOCK=0 ignores it)."""
    if os.environ.get("CONTAINERIZER_IMAGES_LOCK", "1") == "0" or not IMAGES_LOCK.exists():
        return {}
    return (yaml.safe_load(IMAGES_LOCK.read_text()) or {}).get("images") or {}


@lru_cache(maxsize=1)
def images() -> dict:
    lock = images_lock()

    def sub(v):
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        if isinstance(v, str) and v in lock:
            return lock[v]["tag"]
        return v
    return sub(yaml.safe_load((RULES_DIR / "images.yaml").read_text()))


_DIGESTS: dict[str, str | None] = {}


def resolve_digest(ref: str) -> str | None:
    """Registry digest of an image tag (multi-arch index digest), via docker buildx."""
    import subprocess
    locked = {e["tag"]: e.get("digest") for e in images_lock().values()}
    if ref not in _DIGESTS and locked.get(ref):
        _DIGESTS[ref] = locked[ref]
    if ref not in _DIGESTS:
        try:
            p = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest.Digest}}"],
                               capture_output=True, text=True, timeout=120)
            d = p.stdout.strip().strip('"')
            _DIGESTS[ref] = d if p.returncode == 0 and d.startswith("sha256:") else None
        except (OSError, subprocess.TimeoutExpired):
            _DIGESTS[ref] = None
    return _DIGESTS[ref]


def pin_digests(dockerfile: str) -> str:
    """Pin every base image to an immutable digest, keeping the tag for readability."""
    def sub(m):
        ref = m.group(2)
        if "@" in ref or ref.lower() in ("scratch",) or re.fullmatch(r"[a-z][\w-]*", ref):   # stage names
            return m.group(0)
        d = resolve_digest(ref)
        return f"{m.group(1)}{ref}@{d}" if d else m.group(0)
    return re.sub(r"^((?:FROM\s+(?:--platform=\S+\s+)?)|(?:COPY\s+(?:--\w+=\S+\s+)*?--from=))(\S+)", sub,
                  dockerfile, flags=re.M)


def target_tfm() -> str:
    """TFM of the runtime line the images run (images.yaml dotnet.version)."""
    return "net" + str(images()["dotnet"].get("version", "10.0"))


def _tfm_major(tfm: str) -> int:
    """net10.0 -> 10, netcoreapp3.1 -> 3, net6.0-windows -> 6; .NET Framework (net48) -> 0."""
    m = re.match(r"net(?:coreapp)?(\d+)\.\d", tfm or "")
    return int(m.group(1)) if m else 0


def k8s_name(s: str) -> str:
    s = SAFE_NAME.sub("-", s.lower().replace(".", "-")).strip("-")
    return s[:63].rstrip("-") or "app"


# Namespaces an application must never get: the cluster's, the platform's and Containerizer's own. Its namespace gets
# a Flux tenant with the `admin` role, default-deny NetworkPolicies and Pod Security labels, and is deleted with the
# application: a scanned repository called external-secrets or containerizer-secrets must not take over (and later
# delete) the External Secrets Operator or the secret store.
RESERVED_NAMESPACES = frozenset({
    "default", "flux-system", "external-secrets", "cert-manager", "ingress-nginx", "argocd", "kyverno",
    "gatekeeper-system", "local-path-storage", "monitoring", "traefik", "metallb-system", "longhorn-system",
    "cattle-system", "istio-system", "linkerd", "calico-system", "tigera-operator"})
RESERVED_PREFIXES = ("kube-", "openshift", "containerizer-", "cattle-")


def reserved_namespace(ns: str) -> bool:
    return ns in RESERVED_NAMESPACES or ns.startswith(RESERVED_PREFIXES)


def app_ns(name: str) -> str:
    """The Kubernetes name of an application: its namespace, and the first part of its image paths, Ingress hosts
    and IdP clients. k8s_name, with `app-` in front of a reserved namespace (reserved_namespace). Idempotent."""
    ns = k8s_name(name)
    if reserved_namespace(ns):
        ns = k8s_name(f"app-{ns}")
    return ns


def buildable(c: Component) -> bool:
    """Can we produce a Linux container for this component (perhaps after code changes)?"""
    if c.tier != "server":
        return False
    if c.verdict == "blocker":
        return False
    if c.project.kind_hint == "dotnet":
        return c.project.is_core and bool(c.project.best_core_tfm())
    if c.project.kind_hint == "java":
        # an EAR needs a full Jakarta EE server (finding java-ee-application-server)
        return (c.project.properties or {}).get("Packaging", "jar") in ("jar", "war")
    if c.project.kind_hint == "node":
        from .gen_jvm_node import node_buildable
        return c.role == "spa" or node_buildable(c)
    return False


# --------------------------------------------------------------------------- plan

def default_plan(c: Component) -> dict:
    p = c.project
    tfm = p.best_core_tfm() if p.kind_hint == "dotnet" else None
    plan = {
        "component": c.name,
        "kind": p.kind_hint,
        "role": c.role,
        "project": p.rel.replace("\\", "/"),
        "tfm": tfm,
        "multi_target": len(p.tfms) > 1,
        "strategy": "rollforward",
        "base": "chiseled",
        "add_packages": [],
        "env": {},
        "add_writable": ["/tmp"],
        "publish_args": [],
        "remove_files": [],
        "single_replica": False,
        "uid": images()["dotnet"]["app_uid"] if p.kind_hint == "dotnet" else None,
        "port": CONTAINER_PORT if c.role in ("web", "spa") else None,
        "health": c.facts.get("health"),
        "entry": c.facts.get("entry"),
        "spa_root": c.facts.get("spa_root"),
        "args": [],
        "applied": [],
    }
    for d in c.facts.get("writable_dirs", []) or []:
        plan["add_writable"].append(d)
    if c.facts.get("console_arg"):           # runs as a console app, not as a Windows service (rules/05-facts.yaml)
        plan["args"].append(str(c.facts["console_arg"]))
        add_reason(plan, "console-switch", f"The app starts as a Windows service unless it gets "
                   f"{c.facts['console_arg']}; the container passes it so it runs as a console app.")
    if c.role == "web" and p.kind_hint == "dotnet":
        plan["env"]["ASPNETCORE_HTTP_PORTS"] = str(CONTAINER_PORT)
        for i, ep in enumerate(c.facts.get("kestrel_endpoints", []) or []):
            # Kestrel endpoints from appsettings win over ASPNETCORE_HTTP_PORTS; re-point them
            plan["env"][f"Kestrel__Endpoints__{ep}__Url"] = f"http://+:{CONTAINER_PORT + i}"
    if p.kind_hint == "dotnet":
        _repoint_config(plan, c.facts)
        _repoint_nlog(plan, c.facts)
        dataprotection_plan(plan, c.facts)
        plan["env"]["DOTNET_ENVIRONMENT"] = "Production"
        if c.role == "web":
            plan["env"]["ASPNETCORE_ENVIRONMENT"] = "Production"
        if tfm and _tfm_major(tfm) < _tfm_major(target_tfm()):
            if legacy_runtime(tfm):
                plan["runtime_line"] = legacy_runtime(tfm)   # its own runtime (dockerfile_dotnet)
                if c.role == "web":         # before .NET 8 ASPNETCORE_HTTP_PORTS is ignored: the old images listen on 80
                    plan["env"]["ASPNETCORE_URLS"] = f"http://+:{CONTAINER_PORT}"
                add_reason(plan, "own-runtime", f"Targets {tfm}, which is out of support: it runs on its own "
                           f".NET {plan['runtime_line']} runtime image (no longer patched), as built and tested, "
                           "not rolled forward onto a newer runtime.")
            else:
                plan["env"]["DOTNET_ROLL_FORWARD"] = "Major"     # run on the supported runtime line
    return plan


def reason_comments(plan: dict) -> list[str]:
    """Dockerfile header lines that explain each non-default build or run decision."""
    import textwrap
    out = []
    for r in plan.get("reasons") or []:
        out += textwrap.wrap(f"{r['rule']}: {r['why']}", 100, initial_indent="# - ", subsequent_indent="#   ")
        out += [f"#   see {u}" for u in r.get("refs") or []]
    return (["#", "# Why this differs from a default build:"] + out) if out else []


def add_reason(plan: dict, rule: str, why: str, refs: list[str] | None = None) -> None:
    """Record why the build or run setup differs from the default, for the Dockerfile and plan.json."""
    why = " ".join((why or "").split())
    rs = plan.setdefault("reasons", [])
    if why and not any(r["rule"] == rule for r in rs):
        rs.append({"rule": rule, "why": why, **({"refs": list(refs)} if refs else {})})


CONFIG_DOCS = "https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/"


def _repoint_config(plan: dict, facts: dict) -> None:
    """Override configuration through environment variables instead of editing the app:
    file-only Serilog sinks log to stdout, Windows paths move under /data (a volume)."""
    for key in facts.get("listen_url_settings") or []:
        plan["env"][key.replace(":", "__")] = f"http://+:{CONTAINER_PORT}"
        add_reason(plan, "config-listen-url", f"Listen addresses from configuration are overridden to port "
                   f"{CONTAINER_PORT} with environment variables (they take precedence over appsettings.json).",
                   ["https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints"])
    for var in facts.get("nlog_env_folders") or []:
        plan["env"][var] = "/app/logs"
        if "logs" not in plan["add_writable"]:
            plan["add_writable"].append("logs")
    sinks = set(facts.get("serilog_file_sinks") or [])
    for i in sorted(sinks):
        plan["env"][f"Serilog__WriteTo__{i}__Name"] = "Console"
        add_reason(plan, "config-serilog-console", "Serilog file sinks are switched to the console with an "
                   "environment variable, so the cluster collects the logs from stdout.",
                   ["https://github.com/serilog/serilog-sinks-console", CONFIG_DOCS])
    for key, val in sorted((facts.get("windows_paths") or {}).items()):
        parts = key.split(":")
        if parts[:2] == ["Serilog", "WriteTo"] and len(parts) > 2 and parts[2].isdigit() and int(parts[2]) in sinks:
            continue
        new = linux_path(plan, val)
        if new:
            plan["env"]["__".join(parts)] = new
            if new.startswith("/data"):
                add_reason(plan, "config-windows-paths", "Windows paths in configuration (drive letters, UNC shares) are "
                           "overridden with environment variables to folders under /data, which the manifests mount as "
                           "volumes; the application code is not changed.", [CONFIG_DOCS])


DATAPROTECTION_DOCS = "https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview"


def dataprotection_plan(plan: dict, facts: dict) -> None:
    """The Data Protection key ring folder the code persists the keys to (facts.dataprotection_folder). A folder
    from configuration gets the cluster-generated key Secret mounted read-only there (plan["dataprotection_dirs"],
    k8s_manifests), like the default folder of plan-dataprotection-keys: one key on every replica and restart,
    no code change. An unset setting is pointed at DATAPROTECTION_DIR. A folder that is a literal in code is a
    persistent volume (plan["dataprotection_pvc"], ReadWriteOnce: one replica)."""
    dirs = []
    for key, val in sorted((facts.get("dataprotection_key_settings") or {}).items()):
        var = key.replace(":", "__")
        folder = plan["env"].get(var) or val        # a Windows path is re-pointed under /data (_repoint_config)
        if not folder or re.match(r"^([A-Za-z]:|\\\\)", folder) or hides_app(folder):
            folder = DATAPROTECTION_DIR
        if folder != val:
            plan["env"][var] = folder
        folder = _writable_abs(folder)
        if folder not in [_writable_abs(w) for w in plan["add_writable"]]:
            plan["add_writable"].append(folder)
        if folder not in dirs:
            dirs.append(folder)
    if dirs:
        plan["dataprotection_dirs"] = dirs
        names = ", ".join(sorted(facts["dataprotection_key_settings"]))
        add_reason(plan, "dataprotection-key-folder", f"The code keeps the Data Protection key ring in the folder "
                   f"configured by {names}: the manifests mount one key at {', '.join(dirs)}, read-only, from a "
                   "Secret that External Secrets Operator generates once in the cluster, so every replica and restart "
                   "shares it (cookies and antiforgery tokens stay valid); the application code is not changed.",
                   [DATAPROTECTION_DOCS])
        return
    lit = facts.get("dataprotection_key_literal")
    if lit:
        # relative to the working folder (/app) on Linux, where a drive path (D:\keys) is a relative name too
        folder = _writable_abs(lit) if lit.startswith("/") else APP_DIR + "/" + lit.strip("/")
        if hides_app(folder):
            return
        plan["dataprotection_pvc"] = folder
        plan["single_replica"] = True
        if re.fullmatch(r"[\w\-./]+", folder) and folder not in [_writable_abs(w) for w in plan["add_writable"]]:
            plan["add_writable"].append(folder)
        add_reason(plan, "dataprotection-key-volume", f"The code keeps the Data Protection key ring in a folder "
                   f"written in the code ({lit}), which configuration cannot re-point: the folder is a persistent "
                   "volume (ReadWriteOnce) so the keys survive restarts, with one replica, replaced rather than rolled "
                   "on update. Reading the folder from configuration would let the manifests mount one shared key "
                   "there instead.", [DATAPROTECTION_DOCS, PV_DOCS])


def linux_path(plan: dict, val: str) -> str | None:
    """The Linux replacement of a Windows path from configuration: an installed tool becomes its
    Linux binary name (from PATH), a key or certificate file comes from the Secret volume at
    /secrets, anything else moves under /data (made writable; the manifests mount it)."""
    segs = [s for s in re.split(r"[\\/]+", val) if s]
    if not segs:
        return None
    segs = segs[1:] if re.fullmatch(r"[A-Za-z]:", segs[0]) else segs[2:]   # drop drive or \\server\share
    is_file = bool(re.search(r"\.[A-Za-z]\w{0,7}$", segs[-1])) if segs else False
    if any(x.lower() in ("program files", "program files (x86)") for x in segs[:1]) or val.lower().endswith(".exe"):
        if not is_file:
            return None
        name = segs[-1]
        if name.lower().endswith(".dll"):     # native library: Linux naming
            name = "lib" + name[:-4] + ".so"
        return re.sub(r"\.exe$", "", name, flags=re.I)
    if is_file and re.search(r"\.(pem|pfx|p12|key|crt|cer|snk|jks|keytab)$", segs[-1], re.I):
        # keys and certificates come from a Kubernetes Secret volume, never from the image
        if segs[-1] not in plan.setdefault("secret_files", []):
            plan["secret_files"].append(segs[-1])
        return f"/secrets/{segs[-1]}"
    folder = "/data/" + "/".join(k8s_name(s) for s in (segs[:-1] if is_file else segs)) if segs else "/data"
    folder = folder.rstrip("/") or "/data"
    if folder not in plan["add_writable"]:
        plan["add_writable"].append(folder)
    return f"{folder}/{segs[-1]}" if is_file else folder


def _repoint_nlog(plan: dict, facts: dict) -> None:
    for item in facts.get("nlog_folder_settings") or []:
        # trailing slash: NLog targets append "\\file.log", which on Linux then stays inside the folder
        key = item.replace(".", "__")
        plan["env"][key] = plan["env"].get(key, "/app/logs").rstrip("/") + "/"
        add_reason(plan, "config-nlog-folder", "NLog log folders get a trailing '/' so that file names the config "
                   "joins with a backslash still land inside the folder on Linux.",
                   ["https://github.com/NLog/NLog/wiki/File-target"])
        if plan["env"][key] == "/app/logs/" and "logs" not in plan["add_writable"]:
            plan["add_writable"].append("logs")


def apply_plan_rules(plan: dict, repo, c: Component, rules: list[Rule]) -> dict:
    from .techniques import technique_patch
    for r in rules:
        if r.phase != "plan":
            continue
        if r.resolves:
            # a platform technique (containerizer/techniques.py): configuration that satisfies findings
            patch = technique_patch(r, repo, c)
            if patch is not None:
                note = patch.pop("_note", "")
                merge_plan(plan, patch)
                plan["applied"].append(r.id)
                add_reason(plan, r.id, f"{r.why} {note}".strip(), getattr(r, "refs", None))
                plan.setdefault("resolved", {})[r.id] = sorted(
                    {f.rule.id for f in c.findings if f.resolved_by == r.id})
            continue
        ctx = Context(repo, None if r.scope == "repo" else c.project, c.role)
        if run_rule(r, ctx):
            merge_plan(plan, r.plan)
            plan["applied"].append(r.id)
            add_reason(plan, r.id, r.why, getattr(r, "refs", None))
    return plan


def merge_plan(plan: dict, patch: dict) -> dict:
    for k, v in (patch or {}).items():
        if k in ("add_packages", "add_writable", "publish_args", "remove_files", "args", "x509_stores"):
            plan.setdefault(k, [])
            for x in v:
                if k == "add_writable" and hides_app(x):
                    continue                    # a mount there hides the app itself
                if x not in plan[k]:
                    plan[k].append(x)
        elif k == "env":
            plan["env"].update({kk: str(vv) for kk, vv in v.items()})
        else:
            plan[k] = v
    if plan["add_packages"]:
        plan["base"] = "full"
    return plan


def make_plan(a: AppAssessment, c: Component, rules: list[Rule] | None = None, extra: dict | None = None) -> dict:
    rules = rules if rules is not None else load_rules()
    plan = default_plan(c)
    if c.project.kind_hint in ("java", "node"):
        from .gen_jvm_node import java_plan, node_build_plan, node_plan
        if c.role == "spa":
            if c.project.kind_hint == "node":
                node_build_plan(a, c, plan)
        else:
            (java_plan if c.project.kind_hint == "java" else node_plan)(a, c, plan)
    plan = apply_plan_rules(plan, a.repo, c, rules)
    state_plan(c, plan)
    if extra:
        merge_plan(plan, extra)
    workload_lifecycle(c, plan)         # its reasons (k8s_manifests applies it)
    return plan


# --------------------------------------------------------------------------- local state

STATE_DIR = "/data"                 # where an embedded database file from the app folder goes (a volume)
NOT_STATE = re.compile(r"(^|/)(te?mp|logs?|cache|\.cache)(/|$)", re.I)
PV_DOCS = "https://kubernetes.io/docs/concepts/storage/persistent-volumes/"


def stateful_settings() -> dict:
    """rules/36-state.yaml `stateful:`: labels, storage_class, size, node_selector, tolerations."""
    try:
        cfg = (yaml.safe_load((RULES_DIR / "36-state.yaml").read_text()) or {}).get("stateful") or {}
    except OSError:
        cfg = {}
    return {"labels": {str(k): str(v) for k, v in (cfg.get("labels") or {}).items()},
            "storage_class": str(cfg.get("storage_class") or ""), "size": str(cfg.get("size") or "1Gi"),
            "node_selector": {str(k): str(v) for k, v in (cfg.get("node_selector") or {}).items()},
            "tolerations": list(cfg.get("tolerations") or [])}


def state_dirs(c: Component) -> list[str]:
    """The folders a component that keeps its own data (findings of rules with `state: local`) keeps it in,
    absolute: the folders its code and configuration write to (facts writable_dirs, without temp, logs and
    caches), App_Data when the code names data folders under it, and STATE_DIR for an embedded database file
    that sits in the app folder. Empty for a stateless component, or when the folder is not known."""
    if getattr(c, "stateless", True):
        return []
    facts = c.facts or {}
    out = {_writable_abs(w) for w in facts.get("writable_dirs") or [] if not NOT_STATE.search(_writable_abs(w))}
    ids = {f.rule.id for f in c.state_findings}
    if "state-app-data-folders" in ids:
        out.add(_writable_abs("App_Data"))
    if facts.get("embedded_db_files"):
        out.add(STATE_DIR)
    return sorted(w for w in out if not hides_app(w))


def local_state_unplaced(c: Component) -> bool:
    """A component that keeps data on its own disk (`state: local`) in a folder the generator does not know, so
    no volume can be mounted for it (state in memory needs none: one replica is enough)."""
    return any(f.rule.state == "local" for f in c.state_findings) and not state_dirs(c)


def state_plan(c: Component, plan: dict) -> None:
    """A component that keeps its own data runs as it is, without code changes: one replica, replaced rather than
    rolled (Recreate: two pods never write the same files), its data folders on PersistentVolumeClaims
    (plan["state_dirs"]), an embedded database file of the app folder re-pointed to STATE_DIR by an
    environment variable that overrides its connection string (plan["state_env"]: those keys do not come from
    the secret store). The root file system stays read-only; fsGroup lets the non-root user write the volumes."""
    if getattr(c, "stateless", True):
        return
    plan["single_replica"] = True
    plan["stateful"] = True
    dirs = state_dirs(c)
    for key, val in sorted(((c.facts or {}).get("embedded_db_files") or {}).items()):
        name = re.sub(r"[\w\s]*=\s*([\w\-.]+).*", r"\1", val.strip(), count=1)
        var = "ConnectionStrings__" + key
        plan["env"][var] = re.sub(r"=\s*[\w\-.]+", f"={STATE_DIR}/{name}", val.strip(), count=1)
        plan.setdefault("state_env", []).append(var)
    for d in dirs:
        if d not in [_writable_abs(w) for w in plan["add_writable"]]:
            plan["add_writable"].append(d)
    plan["state_dirs"] = dirs
    titles = ", ".join(dict.fromkeys(f.rule.title for f in c.state_findings))
    where = (f" on a persistent volume at {', '.join(dirs)}" if dirs else "")
    add_reason(plan, "state-volume", f"The component keeps its own data ({titles}). It runs as it is, without code "
               f"changes: one replica, replaced rather than rolled on update{where}"
               + ("; the embedded database file is moved there with an environment variable that overrides its "
                  "connection string" if plan.get("state_env") else "")
               + ". Scaling out needs the data in a shared service first.", [PV_DOCS])


# --------------------------------------------------------------------------- Dockerfiles

DOCKERIGNORE = """# generated by containerizer - build context is the application root
**/bin/
**/obj/
**/node_modules/
**/.vs/
**/.git
**/TestResults/
**/*.user
**/*.pfx
**/*.snk.private
**/secrets*.json
**/appsettings.Development.json
**/.env
**/.gradle/
**/.next/
**/.nuxt/
**/.turbo/
**/*.ps1
!**/ClientApp/**/*.ps1
"""


def dockerignore(repo) -> str:
    """The build context filter. A repository that commits source under a node_modules folder
    (Node-RED keeps its packages in packages/node_modules) keeps those folders in the context."""
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(repo.root), "ls-files", "--", ":(glob)**/node_modules/**"],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    if not out.strip():
        return DOCKERIGNORE
    return DOCKERIGNORE.replace("**/node_modules/\n", "# node_modules folders are kept: the repository commits source in them\n")


def _writable_abs(w: str) -> str:
    """A writable folder as an absolute path; relative ones are under the app folder (./data/ -> /app/data)."""
    import posixpath
    return posixpath.normpath(w if w.startswith("/") else "/app/" + w.strip("/"))


APP_DIR = "/app"


def hides_app(w: str) -> bool:
    """A writable folder that is the app folder or contains it: mounted there (a volume, a tmpfs), it would hide
    the application's own files ("The application 'X.dll' does not exist")."""
    a = _writable_abs(w)
    return a == "/" or APP_DIR == a or APP_DIR.startswith(a.rstrip("/") + "/")


# where ASP.NET Core keeps its Data Protection key ring in the container (rules/40-plan.yaml plan-dataprotection-keys,
# only when the code does not persist the keys itself), and the Secret that holds the key mounted there
DATAPROTECTION_DIR = "/home/app/.aspnet/DataProtection-Keys"
DATAPROTECTION_SUFFIX = "-dataprotection"
# where .NET on Linux keeps the CurrentUser certificate stores (one folder per store, *.pfx files)
X509_STORE_DIR = "/home/app/.dotnet/corefx/cryptography/x509stores"


def writable_dirs(plan: dict) -> list[str]:
    """The plan's writable folders, absolute, without those that would hide the app folder."""
    return sorted({_writable_abs(w) for w in plan["add_writable"] if not hides_app(w)})


def legacy_runtime(tfm: str | None) -> str | None:
    """The out-of-support runtime line ("6.0") a TFM runs on in its own image (rules/images.yaml dotnet.legacy),
    or None (a supported line, .NET Framework, or no image: the app rolls forward)."""
    m = re.fullmatch(r"(?:netcoreapp|net)(\d+)\.(\d+)", str(tfm or ""))
    line = f"{m.group(1)}.{m.group(2)}" if m else None
    return line if line and line in (images()["dotnet"].get("legacy") or {}) else None


def _legacy_line(plan: dict) -> str | None:
    """The plan's own out-of-support runtime line, unless it runs on the supported one: it needs OS packages (the
    old images' Debian versions are archived), or it was retargeted."""
    line = plan.get("runtime_line")
    if not line or plan["base"] == "full" or plan["strategy"] == "retarget":
        return None
    return line if line in (images()["dotnet"].get("legacy") or {}) else None


def dockerfile_dotnet(plan: dict) -> str:
    im = images()["dotnet"]
    uid = im["app_uid"]
    worker = plan["role"] != "web" and not plan.get("aspnet_runtime")
    full = plan["base"] == "full"
    base = im[("runtime" if worker else "aspnet") + ("_full" if full else "")]
    legacy = _legacy_line(plan)
    if legacy:
        base = im["legacy"][legacy]["runtime" if worker else "aspnet"]
    elif plan.get("runtime_line"):           # planned for its own runtime, but it cannot: roll forward
        plan = {**plan, "env": {**plan["env"], "DOTNET_ROLL_FORWARD": "Major"},
                "reasons": [r for r in plan.get("reasons") or [] if r.get("rule") != "own-runtime"]}
    proj = plan["project"]
    tfm = plan["tfm"]
    # RID-specific publish keeps the image lean; "portable" avoids RID restore graphs that old
    # netstandard1.x packages break (NU1605) and works for any CPU architecture
    rid = plan.get("rid") or "linux-x64"
    rid_arg = "" if rid == "portable" else f" -p:RuntimeIdentifier={rid}"
    pub = ["-c Release", "-o /out", "-p:UseAppHost=false"] + ([rid_arg.strip(), "--self-contained false"] if rid_arg else [])
    target = target_tfm()
    retarget = plan["strategy"] == "retarget" and tfm and _tfm_major(tfm) != _tfm_major(target)
    if retarget:
        # the entry project is retargeted in the build stage's copy of its .csproj; a global
        # -p:TargetFramework would also retarget its netstandard libraries and break their restore.
        # Only when the TFM is not in the .csproj (Directory.Build.props) is the global property used.
        pub.append("$TFP")
    elif plan["multi_target"] or (tfm and "-" in tfm):
        pub.append(f"-f {tfm}")
    pub += plan["publish_args"]
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, {tfm})",
             *reason_comments(plan),
             f"FROM {im['sdk']} AS build"]
    if plan.get("spa_root"):
        node = images()["node"]["build"]
        lines += [f"COPY --from={node} /usr/local/bin/node /usr/local/bin/node",
                  f"COPY --from={node} /usr/local/lib/node_modules /usr/local/lib/node_modules",
                  "RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \\",
                  " && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx"]
    lines += ["WORKDIR /src", "COPY . ."]
    for f in plan["remove_files"]:
        lines.append(f"RUN find . -name '{f}' -not -path '*/node_modules/*' -delete")
    if plan.get("spa_root"):
        spa = str(PurePosixPath(proj).parent / plan["spa_root"])
        # build the front end once before dotnet publish: publish snapshots wwwroot (static web
        # assets) before the project's own npm target runs, and a bundler that renames hashed files
        # would otherwise leave publish copying files that no longer exist. During publish, npm is
        # then a no-op shim so the project's npm target cannot rebuild under new file names.
        lines += ["RUN --mount=type=secret,id=ca,required=false \\",
                  "    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \\",
                  f'    if grep -qs \'"build"\' "{spa}/package.json"; then cd "{spa}" && \\',
                  "      if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm run build && \\",
                  "      mkdir -p /opt/npm-prebuilt && printf '#!/bin/sh\\necho \"npm $*: skipped, the front end was built before dotnet publish\" >&2\\n' \\",
                  "        > /opt/npm-prebuilt/npm && chmod +x /opt/npm-prebuilt/npm; fi"]
    restore_tfm = " $TFP" if retarget else ""
    lines += ["# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies",
              'RUN --mount=type=cache,target=/root/.nuget/packages --mount=type=secret,id=ca,required=false \\',
              '    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \\',
              *([f"    TFP=''; if grep -qE '<TargetFrameworks?[ >]' \"{proj}\"; then \\",
                 f"      sed -i -E 's#<TargetFrameworks?([^>]*)>[^<]*</TargetFrameworks?>#<TargetFramework\\1>{target}</TargetFramework>#' \"{proj}\"; \\",
                 f"    else TFP='-p:TargetFramework={target} -p:TargetFrameworks={target}'; fi; \\"] if retarget else []),
              *(["    export PATH=/opt/npm-prebuilt:$PATH; \\"] if plan.get("spa_root") else []),
              f'    dotnet restore "{proj}"{rid_arg}{restore_tfm} \\',
              f' && dotnet publish "{proj}" --no-restore {" ".join(pub)}']
    writable = writable_dirs(plan)
    if writable:
        lines.append("RUN mkdir -p " + " ".join("/writable" + w for w in writable))
    lines += ["", f"FROM {base} AS final"]
    if full:
        pk = " ".join(sorted(plan["add_packages"]))
        lines += ["RUN apt-get update \\",
                  f" && apt-get install -y --no-install-recommends {pk} \\",
                  " && rm -rf /var/lib/apt/lists/*"] if pk else []
    lines += ["WORKDIR /app",
              "# application files stay owned by root: read-only for the app user",
              "COPY --from=build /out ."]
    for w in writable:
        lines.append(f"COPY --from=build --chown={uid}:{uid} /writable{w} {w}")
    env = dict(plan["env"])
    if legacy:
        env["HOME"] = "/home/app"           # the old images have no 'app' user: the same home as the new ones
    if env:
        lines.append("ENV " + " \\\n    ".join(f'{k}="{v}"' for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    entry = json.dumps(["dotnet", plan["entry"]] + plan["args"])
    lines.append(f"ENTRYPOINT {entry}")
    return "\n".join(lines) + "\n"


def dockerfile_spa(plan: dict, facts: dict) -> str:
    n = images()["node"]
    dist = facts.get("dist_dir") or "dist"
    if plan.get("pm"):
        # the package manager and workspace of the repository, then the static files
        from .gen_jvm_node import node_build_stage
        mod = plan.get("module") or "."
        out = str(PurePosixPath(mod) / dist)
        return "\n".join([
            "# syntax=docker/dockerfile:1.7",
            f"# Generated by containerizer for {plan['component']} (single-page app, {plan['pm']})",
            *reason_comments(plan), *node_build_stage(plan),
            # the output folder from the facts, else the usual ones (Angular puts the site in browser/)
            f"RUN for d in '{out}/browser' '{out}' '{mod}/dist' '{mod}/build' '{mod}/out'; do "
            'if [ -f "$d/index.html" ]; then cp -r "$d" /site; break; fi; done; '
            '[ -d /site ] || { echo "containerizer: no built index.html found" >&2; exit 1; }',
            "",
        ] + _static_site_stage("/site")) + "\n"
    proj_dir = str(Path(plan["project"]).parent)
    return "\n".join([
        "# syntax=docker/dockerfile:1.7",
        f"# Generated by containerizer for {plan['component']} (single-page app)",
        f"FROM {n['build']} AS build",
        "WORKDIR /src",
        f"COPY {proj_dir}/package*.json ./",
        "RUN --mount=type=cache,target=/root/.npm --mount=type=secret,id=ca,required=false \\",
        "    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca npm_config_cafile=/run/secrets/ca; fi; \\",
        "    npm ci --no-audit --no-fund || npm install --no-audit --no-fund",
        f"COPY {proj_dir}/ .",
        "RUN npm run build",
        f"RUN if [ -d '{dist}/browser' ]; then cp -r '{dist}/browser' /site; else cp -r '{dist}' /site; fi",
        "",
    ] + _static_site_stage("/site")) + "\n"


def _static_site_stage(site: str, extra: str = "") -> list[str]:
    n = images()["node"]
    return [
        f"FROM {n['static']} AS final",
        "# nginx-unprivileged runs as uid 101 and listens on 8080",
        f"COPY --from=build {site} /usr/share/nginx/html",
        "RUN printf 'server {\\n listen 8080;\\n root /usr/share/nginx/html;\\n" + extra
        + " location / { try_files $uri $uri/ /index.html; }\\n location = /healthz { return 200 \"ok\"; }\\n}\\n' > /etc/nginx/conf.d/default.conf",
        "EXPOSE 8080",
    ]


def dockerfile_blazor_wasm(plan: dict) -> str:
    """Standalone Blazor WebAssembly: static files after `dotnet publish`, served by nginx."""
    im = images()["dotnet"]
    proj = plan["project"]
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} (Blazor WebAssembly, static files)",
             f"FROM {im['sdk']} AS build", "WORKDIR /src", "COPY . ."]
    for f in plan["remove_files"]:
        lines.append(f"RUN find . -name '{f}' -not -path '*/node_modules/*' -delete")
    lines += ["RUN --mount=type=cache,target=/root/.nuget/packages --mount=type=secret,id=ca,required=false \\",
              "    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi; \\",
              f'    dotnet publish "{proj}" -c Release -o /out {" ".join(plan["publish_args"])}'.rstrip(), ""]
    # framework files: precompressed variants, and a real 404 instead of the SPA fallback
    extra = " gzip_static on;\\n location /_framework/ { try_files $uri =404; }\\n"
    return "\n".join(lines + _static_site_stage("/out/wwwroot", extra)) + "\n"


def dockerfile_for(plan: dict, c: Component) -> str:
    if c.role == "spa":
        return dockerfile_blazor_wasm(plan) if c.project.kind_hint == "dotnet" else dockerfile_spa(plan, c.facts)
    if c.project.kind_hint in ("java", "node"):
        from .gen_jvm_node import dockerfile_java, dockerfile_node
        return (dockerfile_java if c.project.kind_hint == "java" else dockerfile_node)(plan)
    return dockerfile_dotnet(plan)


# --------------------------------------------------------------------------- Kubernetes

def _timeout_seconds(snippet: str) -> int | None:
    """The longest request time from IIS configuration: executionTimeout (seconds) or an ANCM requestTimeout
    ([d.]hh:mm:ss)."""
    best = None
    for m in re.finditer(r'executionTimeout="(\d+)"', snippet):
        best = max(best or 0, int(m.group(1)))
    for m in re.finditer(r'requestTimeout="(?:(\d+)\.)?(\d+):(\d\d):(\d\d)"', snippet):
        d, h, mi, se = (int(x or 0) for x in m.groups())
        best = max(best or 0, ((d * 24 + h) * 60 + mi) * 60 + se)
    return best


def workload_lifecycle(c: Component, plan: dict) -> dict:
    """Rollout strategy and stop grace period of the component (rules/60-security.yaml hardening.workloads),
    with the reasons in plan.json: a worker is replaced, not rolled, unless a plan rule set `scale_out`;
    raised IIS request timeouts raise the grace period."""
    from .harden import role_lifecycle, workloads
    cfg = role_lifecycle(c.role)
    strategy = cfg.get("strategy") or "RollingUpdate"
    grace = int(cfg.get("terminationGracePeriodSeconds") or 30)
    scale_out = False
    if plan.get("single_replica"):
        strategy = "Recreate"           # state_plan: two pods never write the same files
    elif strategy == "Recreate" and plan.get("scale_out"):
        strategy, scale_out = "RollingUpdate", True
    elif strategy == "Recreate":
        add_reason(plan, "worker-recreate", f"A {c.role} was one process on one server: its Deployment is replaced "
                   "(strategy Recreate), not rolled, so two copies never poll the same queue or folder or run the "
                   "same recurring job during a rollout. A plan rule with scale_out: true marks it safe to run twice.",
                   ["https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#recreate-deployment"])
    lr = workloads().get("long_requests") or {}
    found = [f for f in c.findings if f.rule.id == lr.get("finding")]
    if found:
        longest = max((_timeout_seconds(str(e)) or 0 for f in found for e in f.evidence), default=0)
        want = min(int(lr.get("max_seconds") or 600),
                   longest + int(lr.get("margin_seconds") or 0) if longest else int(lr.get("max_seconds") or 600))
        if want > grace:
            grace = want
            add_reason(plan, "long-request-grace", f"IIS let requests run for {longest or 'several minutes'}"
                       f"{' s' if longest else ''}: the pod gets {grace} s after SIGTERM to finish them "
                       "(terminationGracePeriodSeconds).",
                       ["https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/"])
    if grace != 30 and not any(r["rule"] == "long-request-grace" for r in plan.get("reasons") or []):
        add_reason(plan, "grace-period", f"terminationGracePeriodSeconds {grace}: the {c.role} gets that long to "
                   "finish its work after SIGTERM (Kubernetes and the .NET host default to 30 s).")
    return {"strategy": strategy, "grace": grace, "scale_out": scale_out}


MEMORY_DOCS = "https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/"


def measured_usage(a: AppAssessment, c: Component) -> dict | None:
    """What the verification run of this component measured (verify.run: `usage`), None when it measured nothing."""
    v = next((r for r in getattr(a, "verification", None) or [] if r.get("component") == c.name), None)
    u = (v or {}).get("usage") or {}
    return u if (u.get("memory_peak_mib") or 0) > 0 else None


def measured_memory(plan: dict, usage: dict | None) -> None:
    """Memory requests and limits from the peak the verification run measured (rules/60-security.yaml
    hardening.measured_memory); nothing measured: the baseline stays. A size a plan rule set is only raised."""
    from .harden import _fmt_qty, _qty, security
    if not usage or not (usage.get("memory_peak_mib") or 0) > 0:
        return
    sec = security()
    m = sec["hardening"].get("measured_memory") or {}
    if not m:
        return
    peak = float(usage["memory_peak_mib"]) * 2**20
    step = _qty(m.get("round_to", "64Mi")) or 2**20
    floor = _qty(m.get("floor", "128Mi"))
    ceiling = _qty((sec.get("namespace_policy", {}).get("limit_range", {}).get("max") or {}).get("memory", 0)) or None

    def size(factor) -> float:
        v = max(-(-peak * float(factor) // step) * step, floor)
        return min(v, ceiling) if ceiling else v
    req, lim = size(m.get("request_factor", 1.25)), size(m.get("limit_factor", 2))
    have = plan.get("memory") or {}
    req = max(req, _qty(have.get("request", 0)))
    lim = max(lim, _qty(have.get("limit", 0)), req)
    plan["memory"] = {"request": _fmt_qty(req, "mem"), "limit": _fmt_qty(lim, "mem")}
    plan["memory_measured"] = f"{-(-peak // 2**20):.0f}Mi"
    add_reason(plan, "measured-memory", f"measured {plan['memory_measured']} peak in the verification run: "
               f"requests {plan['memory']['request']}, limits {plan['memory']['limit']}.", [MEMORY_DOCS])


def k8s_manifests(a: AppAssessment, c: Component, plan: dict, image: str) -> list[dict]:
    name = k8s_name(c.name)
    labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": app_ns(a.name)}
    env = [{"name": k, "value": v} for k, v in sorted(plan["env"].items())]
    secret_name = f"{name}-secrets"
    secret_keys = []
    for cs in c.facts.get("connection_strings", []) or []:
        key = f"ConnectionStrings__{cs}"
        if key in (plan.get("state_env") or ()):
            continue            # an embedded database file on the volume (state_plan): set in plan["env"]
        secret_keys.append(key)
        env.append({"name": key, "valueFrom": {"secretKeyRef": {"name": secret_name, "key": key, "optional": True}}})
    for s in c.facts.get("secret_settings", []) or []:
        key = s.replace(":", "__")          # .NET configuration keys; Java/Node facts are variable names already
        secret_keys.append(key)
        env.append({"name": key, "valueFrom": {"secretKeyRef": {"name": secret_name, "key": key, "optional": True}}})
    volumes, mounts = [], []
    dp_pvc = plan.get("dataprotection_pvc")     # a key ring folder written in code (dataprotection_plan)
    for i, w in enumerate(writable_dirs(plan)):
        vname = f"w{i}-" + k8s_name(w.split("/")[-1] or "root")[:40]
        if w == DATAPROTECTION_DIR or w in (plan.get("dataprotection_dirs") or ()):
            # one Data Protection key for every replica and restart, generated in the cluster (harden.py
            # dataprotection_docs): cookies and antiforgery tokens of one pod decrypt in the others
            volumes.append({"name": vname, "secret": {"secretName": f"{name}{DATAPROTECTION_SUFFIX}"}})
            mounts.append({"name": vname, "mountPath": w, "readOnly": True})
            continue
        persistent = w == dp_pvc or w in (plan.get("state_dirs") or ()) or (
            plan.get("single_replica")
            and any(x in w.lower() for x in ("app_data", "data", "keys", "archive", "store", "uploads", "documents")))
        if persistent:
            volumes.append({"name": vname, "persistentVolumeClaim": {"claimName": f"{name}-{vname}"}})
        else:
            volumes.append({"name": vname, "emptyDir": {}})
        mounts.append({"name": vname, "mountPath": w})
    if dp_pvc and dp_pvc not in writable_dirs(plan):
        # a path the Dockerfile cannot create (a drive path is a relative name on Linux: /app/D:\Keys)
        volumes.append({"name": "dataprotection-keys",
                        "persistentVolumeClaim": {"claimName": f"{name}-dataprotection-keys"}})
        mounts.append({"name": "dataprotection-keys", "mountPath": dp_pvc})
    for store in plan.get("x509_stores") or []:
        # .NET on Linux reads CurrentUser\<store> from *.pfx files (no password) in this folder (techniques.py)
        volumes.append({"name": f"x509-{store}", "secret": {"secretName": f"{name}-x509-{store}", "optional": True,
                                                            "defaultMode": 0o440}})
        mounts.append({"name": f"x509-{store}", "mountPath": f"{X509_STORE_DIR}/{store}", "readOnly": True})
    if plan.get("secret_files"):
        volumes.append({"name": "secret-files", "secret": {"secretName": f"{name}-files", "optional": True,
                                                           "defaultMode": 0o440}})
        mounts.append({"name": "secret-files", "mountPath": "/secrets", "readOnly": True})
    container = {
        "name": name, "image": image, "imagePullPolicy": "IfNotPresent", "env": env,
        "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "100m", "memory": (plan.get("memory") or {}).get("request", "256Mi")},
                      "limits": {"memory": (plan.get("memory") or {}).get("limit", "512Mi")}},
        "volumeMounts": mounts,
    }
    if plan.get("port"):
        container["ports"] = [{"name": "http", "containerPort": plan["port"]}]
        probe = {"httpGet": {"path": plan["health"], "port": "http"}} if plan.get("health") else {"tcpSocket": {"port": "http"}}
        ready = {"httpGet": {"path": plan["readiness"], "port": "http"}} if plan.get("readiness") and plan.get("health") else probe
        container["readinessProbe"] = {**ready, "periodSeconds": 10}
        container["livenessProbe"] = {**probe, "periodSeconds": 20, "initialDelaySeconds": 20}
        container["startupProbe"] = {**probe, "periodSeconds": 5, "failureThreshold": 30}
    uid = 101 if c.role == "spa" else plan.get("uid") or images()["dotnet"]["app_uid"]
    pod = {"securityContext": {"runAsNonRoot": True, "fsGroup": uid,
                               **({"fsGroupChangePolicy": "OnRootMismatch"}
                                  if any("persistentVolumeClaim" in v for v in volumes) else {}),
                               "seccompProfile": {"type": "RuntimeDefault"}},
           "automountServiceAccountToken": False, "containers": [container], "volumes": volumes}
    if plan.get("hostname"):
        pod["hostname"] = plan["hostname"]       # Environment.MachineName in the pod (techniques.py)
    life = workload_lifecycle(c, plan)          # rollout strategy, stop grace period (rules/60-security.yaml)
    pod["terminationGracePeriodSeconds"] = life["grace"]
    docs: list[dict] = []
    oneshot = c.facts.get("oneshot_arg") if c.role == "console" else None
    if c.role == "console" and not oneshot:
        oneshot = ""
    if c.role == "console":
        pod["restartPolicy"] = "OnFailure"
        # one CronJob per sub-command (schedules are placeholders: take them from the old Task Scheduler)
        for cmd in (c.facts.get("commands") or [oneshot]):
            jpod = copy.deepcopy(pod)
            if cmd:
                jpod["containers"][0]["args"] = [cmd]
            jname = name if cmd == oneshot else k8s_name(f"{name}-{cmd}")
            docs.append({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": jname, "labels": labels},
                         "spec": {"schedule": "0 2 * * *", "concurrencyPolicy": "Forbid",
                                  "jobTemplate": {"spec": {"template": {"metadata": {"labels": labels}, "spec": jpod}}}}})
            cronjob_limits(docs[-1]["spec"])     # retries, run deadline, history (rules/60-security.yaml)
    else:
        docs.append({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "labels": labels},
                     # one replica: the goal is a container that runs, not scaling out. A second replica needs shared
                     # state first (Data Protection keys, sessions, caches: the findings say which), which is a code
                     # change; with per-pod keys, two replicas failed every form post that landed on the other pod.
                     "spec": {"replicas": 1,
                              "strategy": {"type": life["strategy"]},
                              "selector": {"matchLabels": labels},
                              "template": {"metadata": {"labels": labels}, "spec": pod}}})
        if life["scale_out"]:
            docs[-1]["metadata"]["annotations"] = {"containerizer.io/scale-out": "a plan rule marks it safe to run twice"}
    if plan.get("port"):
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "labels": labels},
                     "spec": {"selector": labels, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}})
    st = stateful_settings() if plan.get("stateful") else None
    if st:
        # the stateful label on the workload and its pods (never in the selector: it is immutable), a node pool
        for d in docs:
            if d["kind"] in ("Deployment", "CronJob"):
                d["metadata"]["labels"] = {**labels, **st["labels"]}
                tpl = d["spec"]["template"] if d["kind"] == "Deployment" else d["spec"]["jobTemplate"]["spec"]["template"]
                tpl["metadata"]["labels"] = {**labels, **st["labels"]}
                if st["node_selector"]:
                    tpl["spec"]["nodeSelector"] = dict(st["node_selector"])
                if st["tolerations"]:
                    tpl["spec"]["tolerations"] = copy.deepcopy(st["tolerations"])
    for v in volumes:
        if "persistentVolumeClaim" in v:
            docs.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                         "metadata": {"name": v["persistentVolumeClaim"]["claimName"],
                                      "labels": {**labels, **(st["labels"] if st else {})}},
                         "spec": {"accessModes": ["ReadWriteOnce"],
                                  **({"storageClassName": st["storage_class"]} if st and st["storage_class"] else {}),
                                  "resources": {"requests": {"storage": st["size"] if st else "1Gi"}}},
                         "_comment": "the application's own data: back it up; the cluster's default StorageClass "
                                     "provides it (set storageClassName and the size for production)"})
    if secret_keys:
        docs.append({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret_name, "labels": labels},
                     "type": "Opaque", "stringData": {k: "" for k in secret_keys},
                     "_comment": "skeleton: harden_manifests turns it into an ExternalSecret"})
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                 "metadata": {"name": f"{name}-ingress", "labels": labels},
                 "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress"],
                          "ingress": [{"ports": [{"port": plan["port"]}]}] if plan.get("port") else []}})
    # security baseline + the exceptions this component needs (rules/60-security.yaml)
    plan["hardening_exceptions"] = harden_manifests(docs, a.repo, c, plan, name)
    return docs


def _lab_inject(a: AppAssessment, c: Component, docs: list[dict], devdb, lab: set, plan) -> None:
    """Point the component at the lab services it needs that are on (labservices.py); a restored dev
    database backup takes the place of the lab SQL Server."""
    from . import labservices
    need = labservices.needs(a.repo, c)
    ns = app_ns(a.name)
    for svc, why in need.items():
        plan.needed.setdefault(svc, {})[c.name] = why
        if svc not in lab or (devdb is not None and svc == devdb.engine):
            continue
        notes = labservices.inject(docs, svc, ns, c, need)
        names = [e["name"] for e in labservices.env_for(svc, ns, c, need)[0]]
        plan.overrides.setdefault(c.name, []).extend(f"{svc}:{n}" for n in names)
        if notes:
            plan.notes.setdefault(c.name, []).extend(notes)
        if svc not in plan.provided:
            plan.provided.append(svc)
    plan.provided.sort(key=labservices.ORDER.index)



class _NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _yaml_docs(docs: list[dict]) -> str:
    out = []
    for d in docs:
        d = dict(d)
        comment = d.pop("_comment", None)
        s = yaml.dump(d, Dumper=_NoAlias, sort_keys=False, default_flow_style=False)
        out.append((f"# {comment}\n" if comment else "") + s)
    return "---\n".join(out)


# --------------------------------------------------------------------------- app

def generate_app(a: AppAssessment, out: Path, rules: list[Rule] | None = None, registry: str = "registry.local",
                 plans: dict | None = None, pin: bool = False, gitops=None, tag: str = "latest",
                 devdb=None, lab: set | None = None, lab_report: dict | None = None,
                 approved_egress: list[dict] | None = None, links: tuple | None = None,
                 ci_provider: str | None = None) -> list[Path]:
    """`ci_provider`: where the application's code is (github, gitlab, azure-devops; an organization scan's
    provider): the build pipeline is written for that one only (None: from the repository's remote URL).
    `approved_egress`: the approved outbound entries of the application's connectivity.yaml in the output
    repository (connectivity.approved_entries): kept in the new connectivity.yaml as they are. Approval documents
    a destination for the real environment; it opens nothing in the sandbox (its NetworkPolicies stay as
    inferred, and on the appliance only the administrators' egress rules let anything out).
    `links`: the confirmed links between applications (connectivity.linked_entries): opened in the NetworkPolicies
    (calls inside the sandbox cluster).
    `devdb`: a devdb.SandboxDb when an operator uploaded a database backup for this application.
    `lab`: the lab services that are on (labservices.py), None where the appliance's lab does not run;
    `lab_report` (a dict) receives what the app needs, what it was pointed at and what is turned off."""
    from .gitops import gitops_manifests, image_setters, readme
    from .report import migration_markdown, write_agent_prompts

    rules = rules if rules is not None else load_rules()
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    idp_sb = None
    if gitops is not None and getattr(gitops, "ingress_domain", "") and getattr(gitops, "sandbox_idp", False):
        from .idp import Sandbox
        idp_sb = Sandbox(gitops.ingress_domain)
    all_k8s = []
    images: list[tuple[str, str]] = []
    comp_docs: dict[str, list[dict]] = {}
    lab_plan = None
    if lab is not None:
        from . import labservices
        lab_plan = labservices.AppPlan(needed={}, provided=[], missing=[], notes={}, overrides={})
    for c in a.components:
        cdir = out / k8s_name(c.name)
        if buildable(c):
            plan = (plans or {}).get(c.name) or make_plan(a, c, rules)
            measured_memory(plan, measured_usage(a, c))
            cdir.mkdir(parents=True, exist_ok=True)
            if c.role == "spa":
                plan["port"], plan["health"] = 8080, "/healthz"
            df = dockerfile_for(plan, c)
            if pin:
                df = pin_digests(df)
            (cdir / "Dockerfile").write_text(df)
            (cdir / "Dockerfile.dockerignore").write_text(dockerignore(a.repo))
            image = f"{registry}/{app_ns(a.name)}/{k8s_name(c.name)}:{tag}"
            docs = k8s_manifests(a, c, plan, image)
            domain = getattr(gitops, "ingress_domain", "") if gitops is not None else ""
            if domain and plan.get("port"):         # HTTPS at <component>-<app>.<domain> (sandbox_https.py)
                from .sandbox_https import ingress
                svc = next(d for d in docs if d.get("kind") == "Service")
                docs.append(ingress(domain, app_ns(a.name), svc["metadata"]["name"], dict(svc["metadata"]["labels"])))
            if devdb is not None:
                from .devdb import inject
                inject(docs, devdb, c.name)
            if idp_sb is not None:
                from . import idp as _idp
                clients, notes = _idp.clients_for(app_ns(a.name), k8s_name(c.name), c.facts or {},
                                                  list(c.project.packages), idp_sb)
                _idp.inject(docs, clients)
                if clients or notes:
                    (cdir / "idp.json").write_text(json.dumps({
                        "idp": idp_sb.url, "project": c.project.rel, "clients": [x.to_dict() for x in clients],
                        "applications": [_idp.wso2_application(x) for x in clients], "notes": notes},
                        indent=2) + "\n")
                    written.append(cdir / "idp.json")
            if lab_plan is not None:
                _lab_inject(a, c, docs, devdb, lab, lab_plan)
            if links:                       # confirmed links of connectivity.yaml (links.py)
                from .links import apply_links
                apply_links(docs, k8s_name(c.name), links[0], links[1])
            images.append((c.name, image))
            all_k8s += docs
            comp_docs[k8s_name(c.name)] = docs
            (cdir / "k8s.yaml").write_text(_yaml_docs(docs))
            (cdir / "plan.json").write_text(json.dumps(plan, indent=2))
            written += [cdir / "Dockerfile", cdir / "Dockerfile.dockerignore", cdir / "k8s.yaml", cdir / "plan.json"]
    if all_k8s and devdb is not None:
        from .devdb import HOST, manifests
        if HOST in comp_docs:
            raise ValueError(f"a component is named {HOST!r}, the name of the sandbox database")
        docs = manifests(app_ns(a.name), devdb)
        (out / HOST).mkdir(parents=True, exist_ok=True)
        (out / HOST / "k8s.yaml").write_text(_yaml_docs(docs))
        written.append(out / HOST / "k8s.yaml")
        all_k8s += docs
        comp_docs[HOST] = docs
        images.append((HOST, devdb.image))
    if lab_plan is not None:
        lab_plan.missing = [s for s in lab_plan.needed if s not in lab_plan.provided and s not in lab
                            and not (devdb is not None and s == devdb.engine)]
        if lab_report is not None:
            lab_report.update(lab_plan.to_dict())
    if all_k8s and lab_plan is not None and lab_plan.provided:
        from . import labservices
        if "lab" in comp_docs:
            raise ValueError("a component is named 'lab', the folder of the lab service credentials")
        docs = labservices.app_docs(app_ns(a.name), lab_plan.provided)
        init_md = ""
        if "sqlserver" in lab_plan.provided:
            # the repository's own SQL setup scripts, which the lab agent runs once into the app's database
            from . import labinit
            scripts, how = labinit.find(Path(a.repo.root))
            if scripts:
                cm, notes = labinit.configmap(app_ns(a.name), scripts)
                if cm:
                    docs.append(cm)
                    if lab_report is not None:
                        lab_report["init_scripts"] = [r for r, _ in scripts]
                init_md = "\n".join(
                    ["## SQL Server: the repository's setup scripts", "",
                     (f"The lab agent runs these once into the app's database ({how}), as the app's own login, and "
                      "again when they change or the database is made again. A batch that fails is reported on "
                      "Admin -> Lab services and the rest goes on." if cm else
                      "Found, but not run:")] + [f"- `{r}`" for r, _ in scripts] + [""]
                    + ([f"- {n}" for n in notes] + [""] if notes else []))
        (out / "lab").mkdir(parents=True, exist_ok=True)
        (out / "lab" / "k8s.yaml").write_text(_yaml_docs(docs))
        (out / "lab" / "README.md").write_text(labservices.readme(app_ns(a.name), lab_plan) + ("\n" + init_md if init_md else ""))
        written += [out / "lab" / "k8s.yaml", out / "lab" / "README.md"]
        all_k8s += docs
        comp_docs["lab"] = docs
    if all_k8s:
        written += app_files(a, out, all_k8s, comp_docs, images, registry, gitops)
        written += _connectivity(a, out, approved_egress, links)
    (out / "MIGRATION.md").write_text(migration_markdown(a))
    written.append(out / "MIGRATION.md")
    written += write_agent_prompts(a, out)
    written += _build_pipeline(a, out, registry, ci_provider)
    return written


def _connectivity(a: AppAssessment, out: Path, approved_egress: list[dict] | None, links: tuple | None = None) -> list[Path]:
    """connectivity.yaml, CONNECTIVITY.md and connectivity.svg: what the application needs from the network as the
    assessment infers it, with the approved egress (org.deploy_app merges the output repository's file in)."""
    from . import connectivity
    try:
        existing = {"outbound": list(approved_egress or []) + list((links or ([], []))[0]),
                    "inbound": list((links or ([], []))[1])}
        doc = connectivity.model(a.name, a.network(), existing=existing, namespace=app_ns(a.name))
        return connectivity.write_files(out, doc)
    except Exception as ex:  # noqa: BLE001 - documentation only: the manifests stand
        print(f"warning: {a.name}: connectivity.yaml not written: {type(ex).__name__}: {ex}", file=sys.stderr)
        return []


def _build_pipeline(a: AppAssessment, out: Path, registry: str, provider: str | None = None) -> list[Path]:
    """The image build pipeline for the application's own repository (pipelines.py): `pipeline/` in the
    output (an organization scan commits it to the output repository).
    A failure here never fails the generation."""
    from . import pipelines
    try:
        sp = pipelines.spec(a, out, registry)
        a.build_pipeline = sp
        if not sp:
            return []
        if pipelines.OUTPUT_DIR in {k8s_name(c.name) for c in a.components}:
            print(f"warning: {a.name}: build pipeline not written to {pipelines.OUTPUT_DIR}/, a component's folder",
                  file=sys.stderr)
            return []
        return pipelines.write_output(out, sp, provider)
    except Exception as ex:  # noqa: BLE001
        print(f"warning: {a.name}: no build pipeline: {type(ex).__name__}: {ex}", file=sys.stderr)
        return []


def app_files(a, out: Path, all_k8s: list[dict], comp_docs: dict[str, list[dict]], images: list[tuple[str, str]],
              registry: str, gitops=None) -> list[Path]:
    """The application-level files around the components' manifests: namespace, namespace security, the
    kustomization with its image setters, the GitOps files, the secret store kit and the GitOps README.
    `a` needs only a `name` (platform migrations, replatform.py, call this too)."""
    from .gitops import gitops_manifests, image_setters, readme
    written: list[Path] = []
    from . import eso
    ns = app_ns(a.name)
    extra: list[str] = []
    if gitops is not None and gitops.image_pull_secret:
        # the pull secret the workloads reference (org --image-pull-secret): from the store, never Git
        pull = [eso.external_secret(gitops.image_pull_secret, ns, eso.remote_key(ns, eso.REGISTRY),
                                    labels={"app.kubernetes.io/part-of": ns}, secret_type=eso.DOCKERCONFIG,
                                    comment="image pull credential (.dockerconfigjson) from the secret store")]
        (out / "pull-secret.yaml").write_text(_yaml_docs(pull))
        written.append(out / "pull-secret.yaml")
        all_k8s += pull
        extra.append("pull-secret.yaml")
    ns_doc = namespace_manifest(app_ns(a.name))
    (out / "namespace.yaml").write_text(_yaml_docs([ns_doc]))
    # namespace-level security (default deny, quota, limits), HARDENING.md and the cluster/ kit
    sec, sec_docs = write_app_security(out, app_ns(a.name), comp_docs, registry, _yaml_docs,
                                       {img.rsplit(":", 1)[0] for _, img in images})
    (out / "kustomization.yaml").write_text(yaml.safe_dump(
        {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
         "namespace": app_ns(a.name),
         "resources": ["namespace.yaml"] + sec + extra
                      + sorted(f"{d.name}/k8s.yaml" for d in out.iterdir() if (d / "k8s.yaml").exists())},
        sort_keys=False) + image_setters(app_ns(a.name), images))
    written += [out / "namespace.yaml", out / "kustomization.yaml", out / "HARDENING.md"] + [out / r for r in sec]
    kinds = sorted({(d["apiVersion"], d["kind"]) for d in all_k8s + sec_docs if isinstance(d, dict) and d.get("kind")})
    app_keys = eso.remote_keys(all_k8s)
    g_docs = gitops_manifests(a, kinds, images, ns_doc, gitops, registry, secret_keys=app_keys)
    for rel, docs in g_docs.items():
        f = out / "gitops" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_yaml_docs(docs))
        written.append(f)
    # the store and this namespace's read access to its keys, for the cluster operator
    keys = sorted(set(app_keys) | set(eso.remote_keys([d for docs in g_docs.values() for d in docs])))
    (out / "cluster" / "secret-store.yaml").write_text(_yaml_docs(
        eso.secret_store() + eso.store_access(ns, keys, {"app.kubernetes.io/part-of": ns})))
    written.append(out / "cluster" / "secret-store.yaml")
    (out / "gitops" / "README.md").write_text(readme(a, gitops))
    written.append(out / "gitops" / "README.md")
    return written
