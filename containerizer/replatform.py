"""Move applications that are already containerized from their current platform to Kubernetes.

Organization scans skip repositories with a Dockerfile. When an administrator enables one anyway
(Admin → Repositories → Enabled), the scan reads how the application is deployed today (platforms.py:
Docker Swarm and Compose files, Nomad jobs, Azure Container Apps YAML/ARM/Bicep, ECS task definitions)
and generates the same output as for applications it containerizes itself:

    <component>/k8s.yaml    hardened Deployment or CronJob, Service, PVCs, ExternalSecrets, ServiceAccount,
                            least-privilege NetworkPolicy, HTTPS Ingress, sandbox IdP settings
    <component>/idp.json    sandbox identity provider registration (when the settings show OIDC/WS-Fed/SAML)
    <component>/build.json  which Dockerfile and context the image is built from, or the image it mirrors
    namespace, security.yaml, kustomization.yaml, gitops/, cluster/, HARDENING.md, SECURITY.md
    MIGRATION.md            what was carried over, what was not, and what to check
    migration.json          the services as read from the descriptors

The image is the application's own: built from the repository's Dockerfile, or the image the platform
runs today pulled and mirrored to the scan's registry. It goes through the same gate as generated images
(manifest lint, image scan, a run with the hardened security context, SBOM).

LLM-heavy mode (off by default; CONTAINERIZER_LLM_HEAVY=true on the worker and the scan's "LLM-heavy"
setting) lets the LLM translate descriptors the rules cannot read (other platforms, broken parses),
review the services before generation (settings that are secrets, health paths, writable folders) and
fix a container that fails the hardened run, as many rounds as CONTAINERIZER_LLM_HEAVY_ROUNDS (default 3).
Every call is tagged `platform-migration` in the LLM usage metrics.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .platforms import ENV_NAME_RE, PLATFORM_TEXT, SECRET_NAME_RE, Descriptor, Service, find_descriptors, split_env

FEATURE = "platform-migration"
FIXES_FILE = "sandbox-fixes.json"
DEFAULT_ROUNDS = 3
PATH_IN_ERROR = re.compile(r"(?:Read-only file system|Permission denied|EACCES|EROFS|denied)[^\n]{0,120}?['\"`(]?(/[\w.@/-]+)"
                           r"|['\"`(](/[\w.@/-]+)['\"`)]?[^\n]{0,60}?(?:Read-only file system|Permission denied|EACCES|EROFS)")

SYSTEM = """You are a senior platform engineer who moves containerized applications from Docker Swarm, Docker Compose,
HashiCorp Nomad, Azure Container Apps, Amazon ECS, Fly.io, Cloud Foundry, Google App Engine and similar platforms to
Kubernetes. A rule-based migration tool calls you with the deployment descriptors it found. The Kubernetes manifests it
generates are hardened: non-root user, read-only root file system, all capabilities dropped, secrets from an external
secret store, default-deny network policies. Judge only from the evidence given and answer only with JSON matching
the requested schema."""

TRANSLATE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["services_json", "notes"],
    "properties": {
        "services_json": {"type": "string", "description": "JSON array of services, see the prompt for the fields"},
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}
PATCH_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["diagnosis", "patches_json"],
    "properties": {
        "diagnosis": {"type": "string"},
        "patches_json": {"type": "string", "description": "JSON object: service name -> patch, see the prompt"},
    },
}
SERVICE_HELP = """Each service is an object with: name, image (the image it runs today, "" if built), build_context and
dockerfile (paths relative to the repository, "" if not built here), command and args (lists of strings: Kubernetes
command replaces the ENTRYPOINT, args the CMD), env (object of plain settings), secrets (names of settings whose values
are secret), ports (container ports, main first), public (reachable from outside today), replicas, cpu (e.g. "250m"),
memory (e.g. "512Mi"), health_path ("" if no HTTP health check), schedule (cron if it runs on a schedule, else ""),
volumes (list of {path, persistent}), backing (true for a database, cache or broker image that is not the application
itself), notes (what could not be carried over)."""
PATCH_HELP = """A patch may contain: env (object: settings to add or change; never secret values), secrets (names of
settings that are secrets and must come from the secret store), writable (absolute folders the container writes to),
health_path (an HTTP path that answers 200 when the app is up, or "" to use a TCP check), port (the container port the
app listens on), command and args (lists of strings), memory (limit, e.g. "1Gi"), notes (list of strings for the
operator). Leave out what should not change."""
PATCH_KEYS = {"env", "secrets", "writable", "health_path", "port", "command", "args", "memory", "notes"}


@dataclass
class Plan:
    app: str
    services: list = field(default_factory=list)        # Service: migrated
    excluded: list = field(default_factory=list)        # {"component", "reason"}
    descriptors: list = field(default_factory=list)     # Descriptor.to_dict()
    notes: list = field(default_factory=list)
    llm: bool = False
    llm_notes: list = field(default_factory=list)

    @property
    def platforms(self) -> list[str]:
        return sorted({d["platform"] for d in self.descriptors if d.get("services")})


def heavy_rounds() -> int:
    try:
        return max(0, min(10, int(os.environ.get("CONTAINERIZER_LLM_HEAVY_ROUNDS", DEFAULT_ROUNDS))))
    except ValueError:
        return DEFAULT_ROUNDS


def k8s_name(s: str) -> str:
    from .generate import k8s_name as kn
    return kn(s)


# --------------------------------------------------------------------------- planning

def _merge(a: Service, b: Service) -> Service:
    """The same service in two descriptors (compose file + override, stack file + compose file): fill
    what the first one lacks from the second; settings and ports are combined."""
    for f in ("image", "cpu", "memory", "schedule"):
        if not getattr(a, f) and getattr(b, f):
            setattr(a, f, getattr(b, f))
    for f in ("build", "health"):
        if not getattr(a, f) and getattr(b, f):
            setattr(a, f, getattr(b, f))
    for f in ("command", "args"):
        if not getattr(a, f) and getattr(b, f):
            setattr(a, f, list(getattr(b, f)))
    a.env = {**b.env, **a.env}
    a.secrets = sorted(set(a.secrets) | set(b.secrets))
    a.ports = list(dict.fromkeys(a.ports + b.ports))
    a.public = a.public or b.public
    a.replicas = max(a.replicas, b.replicas)
    have = {v["path"] for v in a.volumes}
    a.volumes += [v for v in b.volumes if v["path"] not in have]
    have = {v["path"] for v in a.secret_files}
    a.secret_files += [v for v in b.secret_files if v["path"] not in have]
    a.depends_on = list(dict.fromkeys(a.depends_on + b.depends_on))
    a.notes += [n for n in b.notes if n not in a.notes]
    if a.source != b.source:
        a.notes.append(f"also described in {b.source} ({PLATFORM_TEXT.get(b.platform, b.platform)})")
    return a


def _rank(d: Descriptor) -> tuple:
    """Which descriptor wins for a service: Swarm stack > Nomad/ACA/ECS > compose; base files before overrides."""
    order = {"docker-swarm": 0, "nomad": 1, "azure-container-apps": 1, "aws-ecs": 1, "docker-compose": 2}
    name = Path(d.path).name.lower()
    return (order.get(d.platform, 3), "override" in name or bool(re.search(r"\.(dev|local|test|ci)\.", name)), d.path)


def match_dockerfile(sv: Service, dockerfiles: list[str]) -> dict | None:
    """The repository Dockerfile a service with only an image reference is built from: one in a folder
    named like the service or its image, a Dockerfile.<name>/<name>.Dockerfile, or the only Dockerfile."""
    if sv.build:
        return sv.build
    img = re.sub(r"[:@].*$", "", sv.image.rsplit("/", 1)[-1]).lower() if sv.image else ""
    names = {sv.name.lower(), img} - {""}
    for df in dockerfiles:
        p = Path(df)
        parts = {x.lower() for x in p.parent.parts}
        stem = p.name.lower()
        if parts & names or any(stem in (f"dockerfile.{n}", f"{n}.dockerfile", f"containerfile.{n}") for n in names):
            return {"context": p.parent.as_posix() or ".", "dockerfile": df}
    return None


def plan_migration(src: Path, app: str, dockerfiles: list[str], llm: bool = False, model: str | None = None,
                   log=print) -> Plan:
    """Read the descriptors and decide what is migrated. With `llm`, descriptors the rules cannot read are
    translated by the LLM and every service is reviewed by it."""
    src = Path(src)
    plan = Plan(app=app, llm=llm)
    descs = find_descriptors(src)
    if llm:
        for d in descs:
            if not d.services and (not d.parsed or d.error):
                d.services = llm_translate(src, d, dockerfiles, model, plan)
                d.parsed = bool(d.services)
    for d in descs:
        if not d.parsed and not d.services:
            plan.notes.append(f"{d.path}: {PLATFORM_TEXT.get(d.platform, d.platform)} descriptor"
                              + (f" could not be read ({d.error})" if d.error else "")
                              + ("; the LLM could not translate it either" if llm else
                                 "; turn on LLM-heavy mode to translate it, or move it by hand"))
    plan.descriptors = [d.to_dict() for d in descs]
    by_name: dict[str, Service] = {}
    for d in sorted(descs, key=_rank):
        for sv in d.services:
            key = k8s_name(sv.name)
            by_name[key] = _merge(by_name[key], copy.deepcopy(sv)) if key in by_name else copy.deepcopy(sv)
    single = [df for df in dockerfiles if not re.search(r"(?i)(^|/)(test|tests|docs?|examples?|\.devcontainer)/", df)]
    apps = [sv for sv in by_name.values() if not sv.backing]
    used = {sv.build.get("dockerfile") for sv in apps if sv.build}
    single = [df for df in single if df not in used]
    for sv in apps:
        found = match_dockerfile(sv, [df for df in dockerfiles if df not in used] if not sv.build else dockerfiles)
        if not found and not sv.build and len(single) == 1 and len([x for x in apps if not x.build]) == 1:
            found = {"context": Path(single[0]).parent.as_posix() or ".", "dockerfile": single[0]}
        if found and (src / found.get("dockerfile", "")).is_file():
            sv.build = found
        elif sv.build:
            sv.notes.append(f"build: {sv.build.get('dockerfile') or '?'} is not in the repository; using the image "
                            f"{sv.image or '(none)'}")
            sv.build = None
    if llm and apps:
        llm_review(src, apps, plan, model)
    for key, sv in sorted(by_name.items()):
        if sv.backing:
            plan.excluded.append({"component": sv.name, "reason": f"backing service ({sv.image or 'not a container'}): "
                                  "use a managed service or the appliance's lab service and point the app at it"})
        elif not sv.image and not sv.build:
            plan.excluded.append({"component": sv.name, "reason": "neither an image nor a Dockerfile to build it from"})
        else:
            for k, v in sv.env.items():
                if "${" in v:
                    sv.notes.append(f"{k}={v}: an expression of the descriptor; set the real value in the manifest")
            plan.services.append(sv)
    return plan


# --------------------------------------------------------------------------- LLM-heavy mode

def _ask(prompt: str, schema: dict, model: str | None) -> dict:
    from .ai import ask_json
    return ask_json(prompt, schema, model=model, feature=FEATURE, system=SYSTEM)


def _clip(text: str, n: int = 12000) -> str:
    return text if len(text) <= n else text[:n] + "\n... (cut)"


def _llm_service(d: dict, rel: str, platform: str) -> Service | None:
    """A service from the LLM, validated: names, paths, ports and quantities that do not fit are dropped."""
    if not isinstance(d, dict) or not isinstance(d.get("name"), str) or not k8s_name(d["name"]):
        return None
    sv = Service(name=d["name"][:63], platform=platform, source=rel, image=str(d.get("image") or "")[:300])
    ctx, df = str(d.get("build_context") or ""), str(d.get("dockerfile") or "")
    if df and not df.startswith("/") and ".." not in df:
        sv.build = {"context": ctx if ctx and not ctx.startswith("/") and ".." not in ctx else ".", "dockerfile": df}
    sv.command = [str(x) for x in d.get("command") or [] if isinstance(x, (str, int))][:50]
    sv.args = [str(x) for x in d.get("args") or [] if isinstance(x, (str, int))][:50]
    env = {str(k): str(v) for k, v in (d.get("env") or {}).items() if ENV_NAME_RE.fullmatch(str(k))} \
        if isinstance(d.get("env"), dict) else {}
    split_env(sv, env)
    sv.secrets = sorted(set(sv.secrets) | {str(x) for x in d.get("secrets") or [] if ENV_NAME_RE.fullmatch(str(x))})
    sv.ports = [int(p) for p in d.get("ports") or [] if isinstance(p, (int, float)) and 0 < int(p) < 65536][:10]
    sv.public = bool(d.get("public"))
    sv.replicas = max(1, min(20, int(d["replicas"]))) if isinstance(d.get("replicas"), (int, float)) else 1
    sv.cpu = str(d.get("cpu") or "") if re.fullmatch(r"\d+m|\d+(\.\d+)?", str(d.get("cpu") or "")) else ""
    sv.memory = str(d.get("memory") or "") if re.fullmatch(r"\d+(Mi|Gi)", str(d.get("memory") or "")) else ""
    hp = str(d.get("health_path") or "")
    if hp.startswith("/") and sv.ports:
        sv.health = {"type": "http", "path": hp[:200], "port": sv.ports[0]}
    sch = str(d.get("schedule") or "")
    sv.schedule = sch if re.fullmatch(r"(\S+\s+){4}\S+|@\w+", sch) else ""
    sv.volumes = [{"path": str(v["path"]), "persistent": bool(v.get("persistent")), "size": "1Gi"}
                  for v in d.get("volumes") or [] if isinstance(v, dict) and str(v.get("path", "")).startswith("/")][:10]
    sv.backing = bool(d.get("backing"))
    sv.notes = [f"{rel}: {str(n)[:300]}" for n in d.get("notes") or []][:20] + \
        [f"{rel}: translated by the LLM; check it against the descriptor"]
    return sv


def llm_translate(src: Path, d: Descriptor, dockerfiles: list[str], model: str | None, plan: Plan) -> list[Service]:
    try:
        text = (src / d.path).read_text(errors="replace")
    except OSError:
        return []
    prompt = (f"The repository deploys with {PLATFORM_TEXT.get(d.platform, d.platform)}. Descriptor {d.path}:\n\n"
              f"```\n{_clip(text)}\n```\n\nDockerfiles in the repository: {', '.join(dockerfiles) or 'none'}\n\n"
              f"Translate every container it runs into a service. {SERVICE_HELP}")
    try:
        r = _ask(prompt, TRANSLATE_SCHEMA, model)
        items = json.loads(r.get("services_json") or "[]")
    except Exception as ex:                                  # noqa: BLE001 - the rules' result stands
        plan.llm_notes.append(f"{d.path}: LLM translation failed: {type(ex).__name__}: {str(ex)[:200]}")
        return []
    out = [s for s in (_llm_service(x, d.path, d.platform) for x in (items if isinstance(items, list) else [])) if s]
    plan.llm_notes += [f"{d.path}: {str(n)[:300]}" for n in r.get("notes") or []][:20]
    return out


def apply_patch(sv: Service, p: dict, why: str = "") -> list[str]:
    """Apply a validated patch to a service; returns what changed (for MIGRATION.md)."""
    done = []
    if not isinstance(p, dict):
        return done
    env = p.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            k = str(k)
            if ENV_NAME_RE.fullmatch(k) and not SECRET_NAME_RE.search(k) and sv.env.get(k) != str(v):
                sv.env[k] = str(v)[:1000]
                done.append(f"set {k}")
    for k in p.get("secrets") or []:
        k = str(k)
        if ENV_NAME_RE.fullmatch(k) and k not in sv.secrets:
            sv.secrets.append(k)
            sv.env.pop(k, None)
            done.append(f"{k} from the secret store")
    for w in p.get("writable") or []:
        w = str(w)
        if re.fullmatch(r"/[\w.@/-]{0,200}", w) and w not in ("/", "/proc", "/sys", "/dev") and \
                w not in {v["path"] for v in sv.volumes}:
            sv.volumes.append({"path": w, "persistent": False})
            done.append(f"writable {w}")
    if isinstance(p.get("health_path"), str):
        hp = p["health_path"]
        if hp.startswith("/") and len(hp) < 200 and sv.ports:
            sv.health = {"type": "http", "path": hp, "port": (sv.health or {}).get("port") or sv.ports[0]}
            done.append(f"health check {hp}")
        elif hp == "" and sv.ports and (sv.health or {}).get("type") == "http":
            sv.health = {"type": "tcp", "port": sv.ports[0]}
            done.append("TCP health check")
    port = p.get("port")
    if isinstance(port, (int, float)) and 0 < int(port) < 65536 and (not sv.ports or sv.ports[0] != int(port)):
        sv.ports = [int(port)] + [x for x in sv.ports if x != int(port)]
        if sv.health and sv.health.get("port"):
            sv.health["port"] = int(port)
        done.append(f"port {int(port)}")
    for k in ("command", "args"):
        if isinstance(p.get(k), list) and all(isinstance(x, (str, int)) for x in p[k]) and len(p[k]) <= 50:
            setattr(sv, k, [str(x) for x in p[k]])
            done.append(k)
    if isinstance(p.get("memory"), str) and re.fullmatch(r"\d{2,5}Mi|\d{1,2}Gi", p["memory"]):
        sv.memory = p["memory"]
        done.append(f"memory {p['memory']}")
    for n in p.get("notes") or []:
        sv.notes.append(f"LLM: {str(n)[:300]}")
    if done and why:
        sv.notes.append(f"{why}: {', '.join(done)}")
    return done


def _patches(r: dict, names: set[str]) -> dict:
    try:
        p = json.loads(r.get("patches_json") or "{}")
    except ValueError:
        return {}
    return {k: {kk: vv for kk, vv in v.items() if kk in PATCH_KEYS} for k, v in p.items()
            if isinstance(v, dict) and k in names} if isinstance(p, dict) else {}


def llm_review(src: Path, services: list[Service], plan: Plan, model: str | None) -> None:
    """The LLM reads the services as the rules read them, the descriptors and the Dockerfiles, and patches
    what it can tell from them (secret settings, health paths, writable folders, ports)."""
    files = []
    for rel in sorted({sv.source for sv in services} | {sv.build["dockerfile"] for sv in services if sv.build}):
        try:
            files.append(f"--- {rel}\n{_clip((src / rel).read_text(errors='replace'), 6000)}")
        except OSError:
            pass
    model_json = json.dumps([{k: v for k, v in sv.to_dict().items() if k not in ("notes", "source")} for sv in services],
                            indent=1)
    prompt = (f"Services read from the deployment descriptors:\n{_clip(model_json, 16000)}\n\nFiles:\n"
              + _clip("\n\n".join(files), 30000) + f"\n\nReview each service for Kubernetes. {PATCH_HELP}\n"
              "patches_json maps a service name to its patch; leave out services that need nothing.")
    try:
        r = _ask(prompt, PATCH_SCHEMA, model)
    except Exception as ex:                                  # noqa: BLE001
        plan.llm_notes.append(f"LLM review failed: {type(ex).__name__}: {str(ex)[:200]}")
        return
    by = {sv.name: sv for sv in services}
    for name, p in _patches(r, set(by)).items():
        apply_patch(by[name], p, "LLM review")
    if r.get("diagnosis"):
        plan.llm_notes.append(f"LLM review: {str(r['diagnosis'])[:500]}")


def llm_fix_run(sv: Service, docs: list[dict], run: dict, model: str | None) -> tuple[dict, str]:
    """A patch for a container that failed the hardened run (or the sandbox), from the LLM."""
    from .generate import _yaml_docs
    prompt = (f"The container of service {sv.name} (image built from "
              f"{(sv.build or {}).get('dockerfile') or sv.image}) failed when started with this Kubernetes manifest:\n"
              f"{_clip(_yaml_docs(docs), 12000)}\n\nResult: {run.get('status')} {', '.join(run.get('errors') or [])}\n"
              f"Log tail:\n{_clip(run.get('log') or '', 6000)}\n\nWhat makes it start? {PATCH_HELP}\n"
              f"patches_json maps \"{sv.name}\" to its patch (an empty object when only an external service is missing).")
    r = _ask(prompt, PATCH_SCHEMA, model)
    return _patches(r, {sv.name}).get(sv.name) or {}, str(r.get("diagnosis") or "")[:500]


def rule_fix_run(run: dict) -> dict:
    """Without the LLM: folders a hardening failure names become writable."""
    paths = []
    for m in PATH_IN_ERROR.finditer((run.get("log") or "") + "\n" + "\n".join(run.get("errors") or [])):
        p = (m.group(1) or m.group(2) or "").rstrip("/.")
        if not p or p in ("/", "/proc", "/sys", "/dev"):
            continue
        # a file: its folder
        if re.search(r"\.\w{1,5}$", p.rsplit("/", 1)[-1]):
            p = p.rsplit("/", 1)[0] or "/"
        if p != "/" and p not in paths:
            paths.append(p)
    return {"writable": paths[:5]} if paths else {}


# --------------------------------------------------------------------------- manifests

def env_facts(env: dict, secrets: list[str]) -> dict:
    """Sign-in settings in environment variables (OpenIdConnect__Authority, AzureAd__ClientId, ...) as the
    facts the sandbox IdP reads (idp.py), so a migrated app gets its registration like a scanned one."""
    from .idp import find_sections
    tree: dict = {}
    for k in list(env) + list(secrets):
        parts = [p for p in re.split(r"__|:", k) if p]
        if len(parts) < 2:
            continue
        node = tree
        for p in parts[:-1]:
            node = node.setdefault(p, {})
            if not isinstance(node, dict):
                break
        else:
            node[parts[-1]] = env.get(k, "")
    sections = find_sections(tree) if tree else []
    facts = {"auth_sections": sections}
    for s in sections:
        facts[f"auth_{s['protocol']}"] = True
    return facts


def egress_from_settings(sv: Service) -> list[dict]:
    """Ports the app talks to: from the URLs and connection strings in its settings (read when the
    descriptor was parsed, secret ones included), the names of secret settings, and HTTPS."""
    from .platforms import egress_ports
    ports = set(sv.egress) | set(egress_ports(sv.env))
    for k in sv.secrets + list(sv.env):
        low = k.lower()
        for word, p in (("postgres", 5432), ("pg_", 5432), ("mysql", 3306), ("redis", 6379), ("mongo", 27017),
                        ("rabbit", 5672), ("amqp", 5672), ("kafka", 9092), ("mssql", 1433), ("sqlserver", 1433),
                        ("smtp", 587)):
            if word in low:
                ports.add(p)
    ports.add(443)                                            # HTTPS APIs: the most common outbound need
    return [{"id": "from-settings", "ports": [{"port": p, "protocol": "TCP"} for p in sorted(ports) if 0 < p < 65536]}]


def manifests(ns: str, sv: Service, image: str, uid: int, domain: str = "", idp_sb=None) -> tuple[list[dict], dict | None]:
    """The hardened Kubernetes manifests of one migrated service, and its sandbox IdP registration."""
    from .harden import externalize_secrets, harden_pod, network_policy, security, service_account
    name = k8s_name(sv.name)
    labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": ns,
              "containerizer.io/migrated-from": sv.platform}
    secret_name = f"{name}-secrets"
    env = [{"name": k, "value": v} for k, v in sorted(sv.env.items()) if k not in sv.secrets]
    env += [{"name": k, "valueFrom": {"secretKeyRef": {"name": secret_name, "key": k, "optional": True}}}
            for k in sorted(set(sv.secrets))]
    volumes, mounts = [], []
    paths = [v for v in sv.volumes if v.get("path")]
    if not any(v["path"] == "/tmp" for v in paths):
        paths.append({"path": "/tmp", "persistent": False})   # nearly every runtime writes there
    persistent = any(v.get("persistent") for v in paths)
    docs: list[dict] = []
    for i, v in enumerate(paths):
        vname = f"v{i}-" + (k8s_name(v["path"].strip("/").split("/")[-1] or "root")[:40] or "data")
        if v.get("persistent"):
            claim = f"{name}-{vname}"
            volumes.append({"name": vname, "persistentVolumeClaim": {"claimName": claim}})
            docs.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": claim, "labels": labels},
                         "spec": {"accessModes": ["ReadWriteOnce"],
                                  "resources": {"requests": {"storage": v.get("size") or "1Gi"}}}})
        else:
            volumes.append({"name": vname, "emptyDir": {}})
        mounts.append({"name": vname, "mountPath": v["path"]})
    files = {}
    for f in sv.secret_files:
        files.setdefault(str(Path(f["path"]).parent), []).append(f)
    for j, (folder, fs) in enumerate(sorted(files.items())):
        vname = f"files{j}"
        volumes.append({"name": vname, "secret": {"secretName": f"{name}-files{'' if j == 0 else j}", "optional": True,
                                                  "defaultMode": 0o440,
                                                  "items": [{"key": f["name"], "path": Path(f["path"]).name} for f in fs]}})
        mounts.append({"name": vname, "mountPath": folder, "readOnly": True})
    mem = sv.memory or "512Mi"
    container = {"name": name, "image": image, "imagePullPolicy": "IfNotPresent", "env": env,
                 "resources": {"requests": {"cpu": sv.cpu or "100m", "memory": _half(mem)}, "limits": {"memory": mem}},
                 "volumeMounts": mounts}
    if sv.command:
        container["command"] = list(sv.command)
    if sv.args:
        container["args"] = list(sv.args)
    port = sv.ports[0] if sv.ports else None
    if sv.ports:
        container["ports"] = [{"name": "http" if i == 0 else f"p{p}", "containerPort": p} for i, p in enumerate(sv.ports)]
        h = sv.health or {"type": "tcp"}
        if h.get("type") == "http":
            probe = {"httpGet": {"path": h.get("path") or "/", "port": h.get("port") or port}}
        elif h.get("type") == "exec":
            probe = {"exec": {"command": list(h.get("command") or ["true"])}}
        else:
            probe = {"tcpSocket": {"port": h.get("port") or port}}
        container["readinessProbe"] = {**probe, "periodSeconds": 10}
        container["livenessProbe"] = {**probe, "periodSeconds": 20, "initialDelaySeconds": 20}
        container["startupProbe"] = {**probe, "periodSeconds": 5, "failureThreshold": 30}
    elif (sv.health or {}).get("type") == "exec":
        container["livenessProbe"] = {"exec": {"command": list(sv.health["command"])}, "periodSeconds": 30}
    pod = {"containers": [container], "volumes": volumes}
    if sv.schedule:
        pod["restartPolicy"] = "OnFailure"
        docs.insert(0, {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": name, "labels": labels},
                        "spec": {"schedule": sv.schedule, "concurrencyPolicy": "Forbid",
                                 "jobTemplate": {"spec": {"template": {"metadata": {"labels": labels}, "spec": pod}}}}})
    else:
        single = persistent or sv.replicas <= 1
        docs.insert(0, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "labels": labels},
                        "spec": {"replicas": 1 if persistent else max(1, sv.replicas),
                                 "strategy": {"type": "Recreate"} if persistent else {"type": "RollingUpdate"},
                                 "selector": {"matchLabels": labels},
                                 "template": {"metadata": {"labels": labels}, "spec": pod}}})
        if persistent and sv.replicas > 1:
            sv.notes.append(f"{sv.name}: ran {sv.replicas} replicas; one replica here because it keeps data on a "
                            "ReadWriteOnce volume")
        del single
    if port:
        svc_ports = [{"name": "http", "port": 80, "targetPort": "http"}]
        svc_ports += [{"name": f"p{p}", "port": p, "targetPort": f"p{p}"} for p in sv.ports[1:]]
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "labels": labels},
                     "spec": {"selector": labels, "ports": svc_ports}})
    if sv.secrets:
        docs.append({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret_name, "labels": labels},
                     "type": "Opaque", "stringData": {k: "" for k in sorted(set(sv.secrets))},
                     "_comment": "skeleton: harden_manifests turns it into an ExternalSecret"})
    meta_pod = next(((d["spec"]["template"]["metadata"], d["spec"]["template"]["spec"]) for d in docs
                     if d["kind"] == "Deployment"), None) or \
        next((d["spec"]["jobTemplate"]["spec"]["template"]["metadata"], d["spec"]["jobTemplate"]["spec"]["template"]["spec"])
             for d in docs if d["kind"] == "CronJob")
    harden_pod(meta_pod[0], meta_pod[1], uid, name, [])
    hc = security()["hardening"]
    if hc.get("service_account"):
        meta_pod[1]["serviceAccountName"] = name
        docs.insert(0, service_account(name, labels, False))
    if security().get("network", {}).get("default_deny"):
        docs.append(network_policy(name, labels, port, egress_from_settings(sv)))
    externalize_secrets(docs, name, labels, {"secret_files": [f["name"] for f in sv.secret_files]})
    if domain and port and sv.public:
        from .sandbox_https import ingress
        docs.append(ingress(domain, ns, name, dict(labels)))
    idp = None
    if idp_sb is not None and port:
        from . import idp as _idp
        clients, notes = _idp.clients_for(ns, name, env_facts(sv.env, sv.secrets), [], idp_sb)
        _idp.inject(docs, clients)
        if clients or notes:
            idp = {"idp": idp_sb.url, "project": sv.source, "clients": [x.to_dict() for x in clients],
                   "applications": [_idp.wso2_application(x) for x in clients], "notes": notes}
    if port and port < 1024:
        sv.notes.append(f"{sv.name}: listens on port {port}; without NET_BIND_SERVICE a non-root container cannot bind "
                        "it. Make it listen on 8080 or above")
    return docs, idp


def _half(mem: str) -> str:
    m = re.fullmatch(r"(\d+)(Mi|Gi)", mem)
    if not m:
        return "256Mi"
    mib = int(m.group(1)) * (1024 if m.group(2) == "Gi" else 1)
    return f"{max(64, mib // 2)}Mi"


def dockerfile_uid(src: Path, sv: Service) -> int | None:
    """A numeric non-root USER of the final stage of the service's Dockerfile."""
    if not sv.build:
        return None
    try:
        text = (src / sv.build["dockerfile"]).read_text(errors="replace")
    except OSError:
        return None
    users = re.findall(r"^\s*USER\s+(\S+)", text.split("\nFROM ")[-1] if "\nFROM " in text else text, re.M | re.I)
    if users:
        u = users[-1].split(":")[0]
        if u.isdigit() and int(u) != 0:
            return int(u)
    return None


# --------------------------------------------------------------------------- images and the gate

def _docker(args: list[str], timeout: int = 1800) -> tuple[int, str]:
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, errors="replace")
    except (OSError, subprocess.TimeoutExpired) as ex:
        return 1, f"{type(ex).__name__}: {ex}"
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def build_or_pull(src: Path, sv: Service, local: str, cdir: Path, timeout: int = 1800) -> tuple[bool, str]:
    """The service's image as `local`: built from the repository's Dockerfile, or the image it runs today
    pulled and tagged."""
    if sv.build:
        from .verify import _build_env_args
        ctx = (src / (sv.build.get("context") or ".")).resolve()
        df = (src / sv.build["dockerfile"]).resolve()
        if not str(ctx).startswith(str(src.resolve())) or not str(df).startswith(str(src.resolve())):
            return False, "the build context or Dockerfile is outside the repository"
        args = ["build", "--progress=plain", *_build_env_args(), "-f", str(df), "-t", local]
        for k, v in (sv.build.get("args") or {}).items():
            if ENV_NAME_RE.fullmatch(k):
                args += ["--build-arg", f"{k}={v}"]
        if sv.build.get("target"):
            args += ["--target", sv.build["target"]]
        rc, out = _docker(args + [str(ctx)], timeout)
        (cdir / "build.log").write_text(out)
        return rc == 0, out[-2000:]
    rc, out = _docker(["pull", sv.image], timeout)
    if rc != 0:
        return False, f"docker pull {sv.image}: {out.strip()[-600:]}"
    rc, out2 = _docker(["tag", sv.image, local], 60)
    return rc == 0, (out + out2)[-2000:]


def image_uid(local: str) -> int | None:
    """The numeric user the image runs as, when it is not root."""
    rc, out = _docker(["image", "inspect", "-f", "{{.Config.User}}", local], 60)
    u = out.strip().split(":")[0] if rc == 0 else ""
    if u.isdigit():
        return int(u) if int(u) != 0 else None
    if u and u != "root":
        rc, out = _docker(["run", "--rm", "--network", "none", "--entrypoint", "id", local, "-u"], 60)
        if rc == 0 and out.strip().splitlines() and out.strip().splitlines()[-1].isdigit():
            n = int(out.strip().splitlines()[-1])
            return n if n != 0 else None
    return None


# --------------------------------------------------------------------------- writing it out

def write_component(out: Path, ns: str, sv: Service, image: str, uid: int, domain: str, idp_sb, local: str = "") -> list[dict]:
    from .generate import _yaml_docs
    cdir = out / k8s_name(sv.name)
    cdir.mkdir(parents=True, exist_ok=True)
    docs, idp = manifests(ns, sv, image, uid, domain, idp_sb)
    (cdir / "k8s.yaml").write_text(_yaml_docs(docs))
    build = {"platform": sv.platform, "descriptor": sv.source, "uid": uid,
             **({"context": sv.build.get("context"), "dockerfile": sv.build.get("dockerfile")} if sv.build
                else {"mirrors": sv.image})}
    (cdir / "build.json").write_text(json.dumps(build, indent=2) + "\n")
    if idp:
        (cdir / "idp.json").write_text(json.dumps(idp, indent=2) + "\n")
    elif (cdir / "idp.json").exists():
        (cdir / "idp.json").unlink()
    return docs


def migration_markdown(plan: Plan, results: dict[str, dict] | None = None) -> str:
    results = results or {}
    plats = ", ".join(PLATFORM_TEXT.get(p, p) for p in plan.platforms) or "an unknown platform"
    lines = [f"# Kubernetes migration: {plan.app}", "",
             f"Deployed today with {plats}. The images are the application's own (built from its Dockerfile or "
             "mirrored from the image the platform runs); containerizer generated hardened Kubernetes manifests, "
             "External Secrets for the secret settings, and the GitOps files.", ""]
    if plan.llm:
        lines += ["LLM-heavy mode was on: the LLM translated descriptors the rules could not read, reviewed the "
                  "services and fixed containers that failed the hardened run. Check what it changed (marked LLM below).",
                  ""]
    lines += ["| Component | From | Image | Ports | Replicas | Result |", "| --- | --- | --- | --- | ---: | --- |"]
    for sv in plan.services:
        r = results.get(k8s_name(sv.name)) or {}
        src = f"{sv.build['dockerfile']}" if sv.build else f"`{sv.image}`"
        lines.append(f"| {sv.name} | {PLATFORM_TEXT.get(sv.platform, sv.platform)} (`{sv.source}`) | {src} | "
                     f"{', '.join(map(str, sv.ports)) or '-'} | {1 if sv.schedule else sv.replicas} | "
                     f"{r.get('result', 'generated')} |")
    for x in plan.excluded:
        lines.append(f"| {x['component']} | | | | | not migrated: {x['reason']} |")
    lines.append("")
    for sv in plan.services:
        items = []
        if sv.secrets:
            items.append(f"secret settings from the store (remote key `{plan.app}--{k8s_name(sv.name)}`): "
                         + ", ".join(f"`{s}`" for s in sorted(set(sv.secrets))))
        if sv.secret_files:
            items.append("secret files: " + ", ".join(f"`{f['path']}`" for f in sv.secret_files))
        if sv.schedule:
            items.append(f"runs as a CronJob: `{sv.schedule}`")
        items += sv.notes
        r = results.get(k8s_name(sv.name)) or {}
        if items:
            lines += [f"## {sv.name}", ""] + [f"- {x}" for x in items] + [""]
    if plan.notes or plan.llm_notes:
        lines += ["## Descriptors", ""] + [f"- {n}" for n in plan.notes + plan.llm_notes] + [""]
    lines += ["## Before production", "",
              "- Put the secret values into the secret store under the remote keys above (docs/external-secrets.md).",
              "- Point the settings at the databases and services the app uses in the new environment.",
              "- Check the resources, replicas and health checks against what the platform did (autoscaling rules, "
              "placement and node constraints are not carried over).", ""]
    return "\n".join(lines)


def load_fixes(folder: Path) -> dict:
    """Patches the sandbox tester made in an earlier run (component -> patch), kept in the output repository."""
    try:
        d = json.loads((folder / FIXES_FILE).read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


# --------------------------------------------------------------------------- one repository in an organization scan

class _App:
    """What generate.app_files and gitops need of an application: its name (the namespace)."""

    def __init__(self, name: str):
        self.name = name


def _gate_component(src: Path, sv: Service, cdir: Path, docs: list[dict], local: str, provided: set, o, pol,
                    scanner: str) -> dict:
    from .harden import lint_dockerfile, lint_manifests
    from .imagescan import _scan_entry, evaluate, run_as_manifest, scan_image
    cn = cdir.name
    lint = [v.to_dict() for v in lint_manifests(docs, f"{cn}/k8s.yaml: ", provided)]
    if sv.build:
        try:
            for v in lint_dockerfile((src / sv.build["dockerfile"]).read_text(errors="replace"), sv.build["dockerfile"]):
                d = v.to_dict()
                if d.get("severity") == "error":     # the repository's own Dockerfile: reported, fixed there
                    d["severity"] = "warning"
                    d["message"] = f"{d.get('message')} (the repository's Dockerfile: fix it there)"
                lint.append(d)
        except OSError:
            pass
    comp = {"component": cn, "base": None, "lint": lint, "scans": []}
    res = scan_image(local, scanner, local=True)
    comp["scans"].append(_scan_entry(res, evaluate(res, pol), "image"))
    from .sbom import component_sbom, config as sbom_config
    if sbom_config().get("enabled", True):
        comp["sbom"] = component_sbom(local, cdir, [] if res.error else res.vulns, (sv.name, sv.name))
    comp["run"] = run_as_manifest(local, docs)
    return comp


def migrate_repo(src: Path, o, res, app: str, rel: str, dest: Path, gen: Path, reg, tag: str, gitops,
                 dockerfiles: list[str], log=print):
    """The platform migration of one repository an administrator enabled although it has a Dockerfile.
    Returns the RepoResult, or None when no deployment descriptor with a container was found (the scan
    then containerizes the source code as before)."""
    import shutil
    from .ai import usage_scope
    from .generate import _yaml_docs, app_files
    from .harden import external_secret_targets, security
    from .imagescan import policy, security_markdown
    from .org import add_pull_secret, gate_failure, gitops_kustomizations, _clean_generated
    from .orgsource import REDACT

    llm = bool(getattr(o, "llm_heavy", False))
    with usage_scope(feature=FEATURE):
        plan = plan_migration(src, app, dockerfiles, llm=llm, model=o.model, log=log)
    if not plan.services and not plan.excluded:
        if not plan.descriptors:
            return None
        res.status, res.reason = "no-a-components", "; ".join(plan.notes)[:900] or "no container in the descriptors"
        if dest.exists():
            shutil.rmtree(dest)
        return res
    res.migration = {"platforms": plan.platforms, "descriptors": [d["path"] for d in plan.descriptors],
                     "llm_heavy": llm}
    earlier = load_fixes(dest) if dest.exists() else {}
    for sv in plan.services:
        if k8s_name(sv.name) in earlier:
            apply_patch(sv, earlier[k8s_name(sv.name)], "kept from an earlier sandbox test")
    if gen.exists():
        shutil.rmtree(gen)
    gen.mkdir(parents=True)
    from .sandbox_https import configured_domain
    domain = getattr(gitops, "ingress_domain", "") or ""
    idp_sb = None
    if domain and getattr(gitops, "sandbox_idp", False):
        from .idp import Sandbox
        idp_sb = Sandbox(domain)
    default_uid = int(security()["hardening"]["run_as"]["default"])
    build = o.gate or o.push_images
    keep: list[Service] = []
    images: dict[str, tuple[str, str, int]] = {}             # folder -> (ref, local, uid)
    for sv in plan.services:
        cn = k8s_name(sv.name)
        cdir = gen / cn
        cdir.mkdir(parents=True, exist_ok=True)
        local = f"containerizer/{app}-{cn}:gate"
        ref = f"{o.registry.rstrip('/')}/{app}/{cn}:{tag}"
        uid = dockerfile_uid(src, sv) or default_uid
        if build:
            ok, tail = build_or_pull(src, sv, local, cdir, o.timeout)
            if not ok:
                plan.excluded.append({"component": sv.name, "reason": ("image build failed: " if sv.build else
                                                                       "image could not be pulled: ") + REDACT(tail)[-300:]})
                shutil.rmtree(cdir, ignore_errors=True)
                continue
            uid = image_uid(local) or uid
        elif not sv.build:
            ref = sv.image                                     # no build, no push: the image it runs today
        images[cn] = (ref, local, uid)
        keep.append(sv)
    results: dict[str, dict] = {}
    comp_docs: dict[str, list[dict]] = {}
    for sv in keep:
        cn = k8s_name(sv.name)
        comp_docs[cn] = write_component(gen, app, sv, images[cn][0], images[cn][2], domain, idp_sb)
    g = None
    if o.gate and keep:
        pol = policy(o.fail_on)
        scanner = o.scanner or security()["scan"].get("default_scanner", "auto")
        provided = external_secret_targets([d for docs in comp_docs.values() for d in docs])
        comps = []
        for sv in list(keep):
            cn = k8s_name(sv.name)
            cdir = gen / cn
            ref, local, uid = images[cn]
            fixes: list[str] = []
            comp = _gate_component(src, sv, cdir, comp_docs[cn], local, provided, o, pol, scanner)
            rounds = heavy_rounds() if llm else 2
            for i in range(rounds):
                if (comp.get("run") or {}).get("status") != "hardening-failure":
                    break
                patch, why = {}, "fixed after the hardened run"
                if llm:
                    try:
                        with usage_scope(feature=FEATURE):
                            patch, diag = llm_fix_run(sv, comp_docs[cn], comp["run"], o.model)
                        why = f"LLM fix after the hardened run ({diag[:200]})" if diag else "LLM fix after the hardened run"
                    except Exception as ex:                     # noqa: BLE001
                        plan.llm_notes.append(f"{sv.name}: LLM fix failed: {type(ex).__name__}: {str(ex)[:200]}")
                if not patch:
                    patch = rule_fix_run(comp["run"])
                if not patch or not apply_patch(sv, patch, why):
                    break
                fixes.append(f"round {i + 1}: {why}")
                comp_docs[cn] = write_component(gen, app, sv, ref, uid, domain, idp_sb)
                from .imagescan import run_as_manifest
                comp["run"] = run_as_manifest(local, comp_docs[cn])
            if fixes:
                comp["build_fixes"] = fixes
            why = gate_failure(comp)
            results[cn] = {"result": f"excluded: {why}" if why else f"gate passed, hardened run {comp['run'].get('status')}",
                           "fixes": fixes}
            if why:
                plan.excluded.append({"component": sv.name, "reason": f"security gate: {why}"})
                keep.remove(sv)
                comp_docs.pop(cn, None)
                shutil.rmtree(cdir, ignore_errors=True)
            comps.append(comp)
        lint_all = [v for c in comps for v in c["lint"]]
        g = {"app": app, "policy": {"fail_on": pol["fail_on"], "ignore_unfixed": pol.get("ignore_unfixed", True)},
             "passed": all(not gate_failure(c) for c in comps),
             "lint": {"error": sum(1 for v in lint_all if v.get("severity") == "error"),
                      "warning": sum(1 for v in lint_all if v.get("severity") == "warning")},
             "components": comps, "notes": []}
        (gen / "security.json").write_text(json.dumps(g, indent=2, default=str))
        (gen / "SECURITY.md").write_text(security_markdown(g))
    res.excluded = list(plan.excluded)
    (gen / "migration.json").write_text(json.dumps({
        "app": app, "platforms": plan.platforms, "llm_heavy": llm, "descriptors": plan.descriptors,
        "services": [sv.to_dict() for sv in plan.services], "excluded": plan.excluded,
        "notes": plan.notes + plan.llm_notes}, indent=2, default=str) + "\n")
    if not keep:
        res.status = "no-a-components"
        res.reason = (f"none of {len(plan.excluded)} containers qualifies" if plan.excluded else "no container")
        if dest.exists():
            shutil.rmtree(dest)
        return res
    all_k8s = [d for docs in comp_docs.values() for d in docs]
    imgs = [(sv.name, images[k8s_name(sv.name)][0]) for sv in keep]
    app_files(_App(app), gen, all_k8s, comp_docs, imgs, o.registry, gitops)
    (gen / "MIGRATION.md").write_text(migration_markdown(plan, results))
    if earlier:
        (gen / FIXES_FILE).write_text(json.dumps({k: v for k, v in earlier.items() if k in comp_docs}, indent=2) + "\n")

    comps_out = []
    for sv in keep:
        cn = k8s_name(sv.name)
        ref, local, _ = images[cn]
        gc = next((c for c in (g or {}).get("components", []) if c["component"] == cn), {})
        entry = {"component": sv.name, "folder": cn, "image": ref, "rating": "A", "verdict": "info",
                 "role": "cron" if sv.schedule else ("web" if sv.ports else "worker"), "project": sv.source,
                 "project_name": sv.name, "platform": sv.platform,
                 "verification": (gc.get("run") or {}).get("status", "not run")}
        if o.push_images and reg and build:
            entry["digest"] = reg.push(local, ref, [f"{ref.rsplit(':', 1)[0]}:git-{res.commit[:12]}"] if res.commit else [])
            if o.cosign_key and entry["digest"]:
                entry["signature"] = reg.sign(ref, entry["digest"], o.cosign_key)
            sb = gc.get("sbom")
            if sb and not sb.get("error") and entry["digest"] and (gen / cn / "sbom.cdx.json").exists():
                from .sbom import attach
                sb["attestation"] = attach(ref, entry["digest"], gen / cn / "sbom.cdx.json", o.cosign_key, reg.config)
        sb = gc.get("sbom")
        if sb and not sb.get("error"):
            entry["sbom"] = {k: sb.get(k) for k in ("file", "format", "tool", "attestation")} | {
                "summary": {k: v for k, v in (sb.get("summary") or {}).items() if k not in ("warn", "denied")}}
        comps_out.append(entry)
    res.components, res.rating = comps_out, "A"
    _clean_generated(gen)
    if o.image_pull_secret and (gen / "kustomization.yaml").exists():
        add_pull_secret(gen / "kustomization.yaml", o.image_pull_secret)
    gitops_kustomizations(gen)
    res.status, res.path = "deployed", rel
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(gen, dest)
    return res


# --------------------------------------------------------------------------- sandbox tester

SANDBOX_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["outcome", "diagnosis", "patch_json"],
    "properties": {
        "outcome": {"type": "string", "enum": ["fixable", "external", "code", "unknown"]},
        "diagnosis": {"type": "string"},
        "patch_json": {"type": "string", "description": "JSON object: the patch for outcome=fixable, else {}"},
    },
}


def llm_sandbox_diagnosis(r: dict, manifest: str, model: str | None = None) -> dict | None:
    """The sandbox tester's LLM step for a component that is failing or pending in the cluster: what is wrong
    and, when the manifest can fix it, a patch. None when the LLM cannot be asked."""
    from .ai import ask_json
    evidence = {k: r.get(k) for k in ("status", "reason", "states", "events", "ready", "restarts", "url_check")
                if r.get(k) not in (None, "", [])}
    prompt = (f"A component deployed to the sandbox Kubernetes cluster is {r.get('status')}.\n\nWhat the cluster shows:\n"
              f"{json.dumps(evidence, indent=1, default=str)[:8000]}\n\nLog tail (redacted):\n{_clip(r.get('log_tail') or '', 6000)}"
              f"\n\nIts manifest:\n{_clip(manifest, 12000)}\n\noutcome: fixable (a manifest change makes it run), external "
              "(a database, service or secret value it needs is missing), code (the application must change), unknown. "
              f"{PATCH_HELP}")
    try:
        a = ask_json(prompt, SANDBOX_SCHEMA, model=model, feature="sandbox-tester", system=SYSTEM)
        patch = json.loads(a.get("patch_json") or "{}")
    except Exception:                                         # noqa: BLE001 - the rules' diagnosis stands
        return None
    patch = {k: v for k, v in patch.items() if k in PATCH_KEYS} if isinstance(patch, dict) else {}
    return {"outcome": a["outcome"], "diagnosis": str(a["diagnosis"])[:1000],
            "patch": patch if a["outcome"] == "fixable" else {}}


def apply_sandbox_fixes(root: Path, doc: dict, log=print) -> list[str]:
    """Patches the sandbox tester's LLM proposed for migrated apps: applied to their manifests in the output
    repository and kept in <app>/sandbox-fixes.json, so the next scan generates them too. Returns the
    folders changed (the caller commits and verifies again)."""
    from .harden import security
    from .sandbox_https import configured_domain
    changed = []
    by_folder: dict[str, list[dict]] = {}
    for r in doc.get("components") or []:
        if (r.get("llm") or {}).get("patch"):
            by_folder.setdefault(r["folder"], []).append(r)
    for folder, rs in by_folder.items():
        d = Path(root) / folder
        try:
            mig = json.loads((d / "migration.json").read_text())
            meta = json.loads((d / "containerizer.json").read_text())
        except (OSError, ValueError):
            continue                                          # containerized from source: report only
        services = {k8s_name(s["name"]): Service.from_dict(s) for s in mig.get("services") or []}
        fixes = load_fixes(d)
        idp_sb = None
        domain = ""
        ing = any((d / c).is_dir() and "kind: Ingress" in (d / c / "k8s.yaml").read_text()
                  for c in services if (d / c / "k8s.yaml").exists())
        if ing:
            domain = configured_domain() or ""
        for r in rs:
            comp = next((c for c in meta.get("components") or [] if c.get("component") == r["component"]), None)
            if not comp or comp.get("folder") not in services:
                continue
            cn = comp["folder"]
            sv = services[cn]
            if not apply_patch(sv, r["llm"]["patch"], "LLM fix from the sandbox test"):
                continue
            try:
                uid = int(json.loads((d / cn / "build.json").read_text()).get("uid"))
            except (OSError, ValueError, TypeError):
                uid = int(security()["hardening"]["run_as"]["default"])
            if (d / cn / "idp.json").exists() and domain:
                from .idp import Sandbox
                idp_sb = Sandbox(domain)
            write_component(d, meta.get("app") or "", sv, comp["image"], uid, domain, idp_sb)
            fixes[cn] = {**fixes.get(cn, {}), **r["llm"]["patch"]}
            changed.append(folder)
            log(f"sandbox tester: {folder}/{cn}: applied the LLM's fix ({r['llm']['diagnosis'][:120]})")
        if fixes:
            (d / FIXES_FILE).write_text(json.dumps(fixes, indent=2) + "\n")
            mig["services"] = [s.to_dict() for s in services.values()]
            (d / "migration.json").write_text(json.dumps(mig, indent=2, default=str) + "\n")
    return sorted(set(changed))
