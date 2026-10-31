"""Lab services: backing services that the appliance runs in its k3s sandbox for the scanned apps.

An administrator turns each service on or off under Admin -> Lab services (admin_lab.py). The system
agent writes the result to `lab-services.json` (CONFIG_PATH). The lab agent (labagent.py, root) runs the
services, and the scans (org.py) read the same file. Then, for every component that depends on a
service that is on:

- the generated manifests point the component at the lab service by overriding its configuration
  with environment variables (`ConnectionStrings__Shop`, `AWS_ENDPOINT_URL_S3`, ...), so the code does
  not change;
- the credentials come from External Secrets Operator: an ExternalSecret `lab-<service>` in the app's
  namespace reads remote key `<namespace>--cz-lab-<service>` from the secret store, and the lab agent
  fills that key in when it creates the app's database, user or instance;
- the component's NetworkPolicy may reach the service's port in namespace `containerizer-lab`, and the
  lab's NetworkPolicies let in only the namespaces the agent provisioned.

Two kinds of service:

- shared (SQL Server, PostgreSQL): one server; each app gets its own database and login, owner of that
  database only;
- per app (Redis, S3, Azure Blob): one small instance per app, because these protocols cannot keep
  apps apart on one server without code changes (Redis has no per-database ACL; S3 bucket and Azure
  container names would collide between apps).

Data lives on persistent volumes (k3s local-path storage, on the appliance's persistent partition).
Turning a service off stops it but keeps the volumes and the credentials, so turning it on again
brings the data back.

This module is pure (no I/O besides reading the rules): the catalog, names, detection, the generated
app-side documents and the lab-side manifests.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

LAB_NS = "containerizer-lab"
LABEL = "containerizer.io/lab-service"          # on everything that belongs to one service
APP_LABEL = "containerizer.io/lab-app"          # the app namespace a per-app object belongs to
MANAGED = {"app.kubernetes.io/managed-by": "containerizer-appliance"}
CONFIG_ENV = "CONTAINERIZER_LAB_SERVICES"       # path of lab-services.json for the scans
CONFIG_PATH = Path("/var/lib/containerizer/system/lab-services.json")
REMOTE_PREFIX = "cz-lab-"                       # remote keys <namespace>--cz-lab-<service>
SECRET_PREFIX = "lab-"                          # ExternalSecret / Secret lab-<service> in the app namespace
RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "lab-services.yaml"
# namespaces that may never ask for lab credentials
RESERVED_NS = frozenset({LAB_NS, "containerizer-secrets", "kube-system", "kube-public", "kube-node-lease",
                         "default", "flux-system", "external-secrets", "containerizer-verify"})
NS_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")


@dataclass(frozen=True)
class Service:
    id: str
    title: str
    engine: str                 # what runs: shown on the page
    shared: bool                # one server with a database per app, or one instance per app
    port: int
    uid: int                    # runAsUser / runAsGroup / fsGroup
    image_var: str              # images.env
    default: bool               # on before an administrator has chosen
    memory: tuple[str, str]     # request, limit
    storage: str                # PersistentVolumeClaim request
    summary: str


SERVICES: dict[str, Service] = {s.id: s for s in (
    Service("sqlserver", "SQL Server", "SQL Server 2022 Developer edition", True, 1433, 10001,
            "CZ_IMAGE_MSSQL", True, ("2Gi", "3Gi"), "20Gi",
            "One server, a database and login per app (db_owner of its own database only). Apps with an "
            "uploaded dev database backup get that backup restored next to them instead."),
    Service("postgres", "PostgreSQL", "PostgreSQL 18", True, 5432, 70,
            "CZ_IMAGE_LAB_POSTGRES", False, ("256Mi", "1Gi"), "10Gi",
            "One server, a database and role per app (owner of its own database only)."),
    Service("redis", "Redis", "Redis 8.8", False, 6379, 999,
            "CZ_IMAGE_LAB_REDIS", False, ("32Mi", "256Mi"), "1Gi",
            "One instance per app with its own password; append-only file on a persistent volume."),
    Service("s3", "S3 object storage", "Versity S3 Gateway (S3 API over files)", False, 7070, 10001,
            "CZ_IMAGE_LAB_S3", False, ("32Mi", "256Mi"), "5Gi",
            "One S3 endpoint per app with its own access key; any bucket the app creates is its own."),
    Service("azure-blob", "Azure Blob storage", "Azurite (Azure Storage emulator), blob service", False, 10000, 1000,
            "CZ_IMAGE_LAB_AZURITE", False, ("64Mi", "512Mi"), "5Gi",
            "One Azurite blob endpoint per app with its own account key."),
)}
ORDER = list(SERVICES)


class LabError(ValueError):
    pass


# --------------------------------------------------------------------------- configuration

def defaults() -> dict[str, bool]:
    return {s.id: s.default for s in SERVICES.values()}


def validate(services) -> dict[str, bool]:
    """{service id: on} with exactly the known services; anything else is refused."""
    if not isinstance(services, dict) or set(services) != set(SERVICES) \
            or not all(isinstance(v, bool) for v in services.values()):
        raise LabError("lab services: give true or false for each of " + ", ".join(ORDER))
    return {k: services[k] for k in ORDER}


def load_config(path: Path | None = None) -> dict:
    """lab-services.json: {"services": {id: bool}, "changed_by", "changed_at"}; the defaults when the
    file does not exist yet."""
    p = Path(path) if path else CONFIG_PATH
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError:
        return {"services": defaults(), "changed_by": None, "changed_at": None}
    except (OSError, ValueError) as ex:
        raise LabError(f"{p}: {ex}") from None
    return {"services": validate((data or {}).get("services")), "changed_by": data.get("changed_by"),
            "changed_at": data.get("changed_at")}


def enabled_from_env(env=None) -> set[str] | None:
    """The services the scans may use: None when lab services are not set up here (no
    CONTAINERIZER_LAB_SERVICES), else the ids that are on."""
    env = os.environ if env is None else env
    path = (env.get(CONFIG_ENV) or "").strip()
    if not path:
        return None
    return {k for k, v in load_config(Path(path))["services"].items() if v}


# --------------------------------------------------------------------------- names

def _label(base: str, key: str) -> str:
    """A DNS label (Service name, at most 63, starts with a letter) for `base`; long names keep a hash."""
    if len(base) <= 63:
        return base
    h = hashlib.sha256(key.encode()).hexdigest()[:8]
    return base[:54].rstrip("-") + "-" + h


def instance(svc: str, ns: str) -> str:
    """Name of a per-app instance (Deployment, Service, PVC prefix) in the lab namespace."""
    return _label(f"{svc}-{ns}", f"{svc}/{ns}")


def host(svc: str, ns: str) -> str:
    name = svc if SERVICES[svc].shared else instance(svc, ns)
    return f"{name}.{LAB_NS}.svc.cluster.local"


def secret_name(svc: str) -> str:
    return f"{SECRET_PREFIX}{svc}"


def remote_name(svc: str) -> str:
    return f"{REMOTE_PREFIX}{svc}"


def remote_key(ns: str, svc: str) -> str:
    from . import eso
    return eso.remote_key(ns, remote_name(svc))


def db_name(ns: str) -> str:
    """Database and login/role of an app on a shared server: its namespace, hyphens as underscores."""
    return ns.replace("-", "_")


def check_namespace(ns: str) -> None:
    if not NS_RE.fullmatch(ns or "") or ns in RESERVED_NS:
        raise LabError(f"namespace {ns!r} cannot use lab services")


# --------------------------------------------------------------------------- what an app needs

_SQLSERVER = re.compile(r"(?i)\b(Initial Catalog|Integrated Security|Trusted_Connection|MultipleActiveResultSets|"
                        r"TrustServerCertificate|Persist Security Info)\s*=|\(localdb\)|"
                        r"\b(Data Source|Server|Addr|Address)\s*=\s*(tcp:)?[^;]*(\\|,\s*\d{2,5}\b)")
_SERVER_DB = re.compile(r"(?i)\b(Server|Data Source)\s*=[^;]+;.*\bDatabase\s*=")
_NOT_SQLSERVER = re.compile(r"(?i)\b(Port|Host|SslMode|Ssl Mode|Uid|CharSet|AllowPublicKeyRetrieval)\s*=")
_POSTGRES = re.compile(r"(?i)^\s*postgres(ql)?://|\bHost\s*=[^;]+;.*\b(Username|User ID|User Id|UserName|Database|Port)\s*=|"
                       r"\b(Username|Database|Port)\s*=[^;]*;.*\bHost\s*=")
_REDIS_OPTS = re.compile(r"(?i)^\s*rediss?://|,\s*(abortConnect|connectTimeout|syncTimeout|allowAdmin|ssl|password|"
                         r"defaultDatabase|connectRetry|keepAlive)\s*=")
_HOSTPORT = re.compile(r"^\s*[\w.\-]+:\d{2,5}\s*(,|$)")
_AZURE = re.compile(r"(?i)\bUseDevelopmentStorage\s*=\s*true|\bAccountName\s*=[^;]+;.*\bAccountKey\s*=|"
                    r"\bBlobEndpoint\s*=|\bDefaultEndpointsProtocol\s*=")
_S3_SECTION = re.compile(r"(?i)(^|:)[^:]*(s3|minio|aws)[^:]*:")
_S3_LEAF = {"serviceurl": "s3:endpoint", "endpoint": "s3:endpoint", "endpointurl": "s3:endpoint",
            "serviceuri": "s3:endpoint", "accesskey": "s3:access-key", "accesskeyid": "s3:access-key",
            "secretkey": "s3:secret-key", "secretaccesskey": "s3:secret-key", "region": "s3:region",
            "authenticationregion": "s3:region", "forcepathstyle": "s3:path-style"}


def classify(key: str, value) -> str | None:
    """Which lab service a configuration value (appsettings key `Section:Name`) is the setting of:
    a service id, `s3:<part>` for the pieces of an S3 client configuration, or None."""
    if not isinstance(value, (str, bool)) or key.startswith("Logging:"):
        return None
    leaf = key.rsplit(":", 1)[-1].replace("_", "").lower()
    if _S3_SECTION.search(key) and leaf in _S3_LEAF:
        return _S3_LEAF[leaf]
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        return None
    if _AZURE.search(value):
        return "azure-blob"
    if _POSTGRES.search(value):
        return "postgres"
    if _SQLSERVER.search(value) or (_SERVER_DB.search(value) and not _NOT_SQLSERVER.search(value)):
        return "sqlserver"
    rediskey = re.search(r"(?i)redis|cache", key)
    if _REDIS_OPTS.search(value) and (rediskey or _HOSTPORT.match(value) or value.lower().startswith("redis")):
        return "redis"
    if rediskey and _HOSTPORT.match(value):
        return "redis"
    if _HOSTPORT.match(value) and re.search(r":63(79|80)\b", value):
        return "redis"
    return None


def settings_facts(flat: list[tuple[str, object]]) -> dict[str, str]:
    """facts["lab_settings"]: {configuration key: what classify() says} for one appsettings.json."""
    out = {}
    for k, v in flat:
        kind = classify(k, v)
        if kind:
            out[k] = kind
    return out


def rules() -> dict:
    data = yaml.safe_load(RULES_FILE.read_text()) or {}
    svcs = data.get("services") or {}
    unknown = set(svcs) - set(SERVICES)
    if unknown:
        raise LabError(f"{RULES_FILE.name}: unknown services {sorted(unknown)}")
    return svcs


def needs(repo, c) -> dict[str, list[str]]:
    """{service id: why} for one component: a package rule from rules/lab-services.yaml on the component
    or a project it references, or a setting the scan classified (facts["lab_settings"])."""
    from .harden import _projects
    from .rules import Context, Rule, run_rule
    out: dict[str, list[str]] = {}
    for svc, spec in rules().items():
        if not spec.get("when"):
            continue
        r = Rule.from_dict({"id": f"lab-{svc}", "when": spec["when"], "phase": "network"})
        for p in _projects(repo, c):
            m = run_rule(r, Context(repo, p, c.role))
            if m is not None:
                out.setdefault(svc, []).append(f"package in {p.rel}" if p is not c.project else "package")
                break
    for key, kind in sorted(((c.facts or {}).get("lab_settings") or {}).items()):
        svc = "s3" if kind.startswith("s3:") else kind
        if svc in SERVICES:
            out.setdefault(svc, []).append(f"setting {key}")
    return {k: out[k] for k in ORDER if k in out}


# --------------------------------------------------------------------------- the app side

def _env_key(key: str) -> str:
    return key.replace(":", "__")


def connection_keys(c, svc: str, needed: dict) -> list[str]:
    """The connection string / setting keys of component `c` that should point at `svc`."""
    lab = (c.facts or {}).get("lab_settings") or {}
    keys = [k for k, v in lab.items() if v == svc]
    if keys or svc in ("s3", "azure-blob"):
        return sorted(keys)
    if svc == "redis":
        return ["ConnectionStrings:Redis"]
    # databases: connection strings whose engine the scan could not tell, when this is the only
    # database the component needs; otherwise the conventional DefaultConnection
    css = [f"ConnectionStrings:{k}" for k in (c.facts or {}).get("connection_strings") or []]
    unknown = [k for k in css if k not in lab]
    dbs = [s for s in ("sqlserver", "postgres") if s in needed]
    if unknown and dbs == [svc]:
        return unknown
    if not css:
        return ["ConnectionStrings:DefaultConnection"]
    return []


def env_for(svc: str, ns: str, c, needed: dict) -> tuple[list[dict], list[str]]:
    """Environment entries (secret references first, then plain settings, which may use them with
    Kubernetes' $(VAR) expansion) and notes for the README."""
    sec = secret_name(svc)

    def ref(name: str, key: str) -> dict:
        return {"name": name, "valueFrom": {"secretKeyRef": {"name": sec, "key": key}}}
    h, notes = host(svc, ns), []
    keys = connection_keys(c, svc, needed)
    if svc in ("sqlserver", "postgres", "redis"):
        # the whole connection string comes from the store: nothing secret in the manifest
        return [ref(_env_key(k), "connection-string") for k in keys], notes
    if svc == "s3":
        endpoint = f"http://{h}:7070"
        env = [ref("AWS_ACCESS_KEY_ID", "access-key-id"), ref("AWS_SECRET_ACCESS_KEY", "secret-access-key"),
               {"name": "AWS_REGION", "value": "us-east-1"}, {"name": "AWS_ENDPOINT_URL_S3", "value": endpoint}]
        lab = (c.facts or {}).get("lab_settings") or {}
        part = {"s3:endpoint": endpoint, "s3:access-key": "$(AWS_ACCESS_KEY_ID)",
                "s3:secret-key": "$(AWS_SECRET_ACCESS_KEY)", "s3:region": "us-east-1", "s3:path-style": "true"}
        env += [{"name": _env_key(k), "value": part[lab[k]]} for k in sorted(lab) if lab[k] in part]
        if not any(lab.get(k) == "s3:endpoint" for k in lab):
            notes.append("No S3 endpoint setting found in appsettings.json: the AWS SDK reads AWS_ENDPOINT_URL_S3 "
                         "(AWSSDK.S3 3.7.300 or later); a client that sets ServiceURL in code still needs that setting.")
        return env, notes
    if svc == "azure-blob":
        if not keys:
            notes.append("No Azure Storage connection string found in appsettings.json: point the app's setting at "
                         f"the Secret {sec}, key connection-string.")
        return [ref(_env_key(k), "connection-string") for k in keys], notes
    raise LabError(f"unknown lab service {svc!r}")


def egress_rule(svc: str, ns: str) -> dict:
    """NetworkPolicy egress to the service's pods in the lab namespace."""
    pods = {LABEL: svc} if SERVICES[svc].shared else {LABEL: svc, APP_LABEL: ns}
    return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": LAB_NS}},
                    "podSelector": {"matchLabels": pods}}],
            "ports": [{"port": SERVICES[svc].port, "protocol": "TCP"}]}


def inject(docs: list[dict], svc: str, ns: str, c, needed: dict) -> list[str]:
    """Point component `c`'s workloads at the lab service: environment (replacing entries of the same
    name, secret references first so $(VAR) resolves) and NetworkPolicy egress. Returns notes."""
    env, notes = env_for(svc, ns, c, needed)
    names = {e["name"] for e in env}
    refs = [e for e in env if "valueFrom" in e]
    vals = [e for e in env if "valueFrom" not in e]
    for d in docs:
        if d.get("kind") in ("Deployment", "StatefulSet", "CronJob", "Job"):
            spec = d.get("spec") or {}
            tpl = ((spec.get("jobTemplate") or {}).get("spec") or spec).get("template") or {}
            for ct in (tpl.get("spec") or {}).get("containers") or []:
                rest = [e for e in ct.get("env") or [] if e["name"] not in names]
                ct["env"] = copy.deepcopy(refs) + rest + copy.deepcopy(vals)
        elif d.get("kind") == "NetworkPolicy" and "Egress" in ((d.get("spec") or {}).get("policyTypes") or []):
            rule = egress_rule(svc, ns)
            eg = d["spec"].setdefault("egress", [])
            if rule not in eg:
                eg.append(rule)
            ann = d.setdefault("metadata", {}).setdefault("annotations", {})
            key = "containerizer.io/egress"
            have = [x for x in (ann.get(key) or "").split(",") if x and x != "none"]
            if f"lab-{svc}" not in have:
                ann[key] = ",".join(have + [f"lab-{svc}"])
    return notes


def app_docs(ns: str, services: list[str]) -> list[dict]:
    """lab/k8s.yaml of an app: one ExternalSecret per lab service it uses."""
    from . import eso
    out = []
    for svc in services:
        doc = eso.external_secret(secret_name(svc), ns, remote_key(ns, svc),
                                  labels={"app.kubernetes.io/part-of": ns, "app.kubernetes.io/managed-by": "containerizer",
                                          LABEL: svc},
                                  comment=f"{SERVICES[svc].title} in the lab: the appliance's lab agent puts the "
                                          f"credentials in the secret store (remote key {remote_key(ns, svc)})")
        out.append(doc)
    return out


@dataclass
class AppPlan:
    """What generate_app records about lab services for one app."""
    needed: dict          # service -> {component: [why]}
    provided: list        # services the app was pointed at
    missing: list         # needed but turned off
    notes: dict           # component -> [notes]
    overrides: dict       # component -> [env names]

    def to_dict(self) -> dict:
        return {"needed": {k: sorted(v) for k, v in self.needed.items()}, "provided": self.provided,
                "missing": self.missing, "overrides": self.overrides}


def readme(app: str, plan: AppPlan) -> str:
    lines = [f"# Lab services of {app}", "",
             "The appliance runs these services in namespace `containerizer-lab` (Admin -> Lab services). "
             "The app's configuration is overridden with environment variables; its code is unchanged. "
             "Credentials come from the secret store through External Secrets Operator.", ""]
    for svc in plan.provided:
        s = SERVICES[svc]
        lines += [f"## {s.title}", "", f"- Host `{host(svc, app)}`, port {s.port} ({s.engine}).",
                  f"- Credentials: Secret `{secret_name(svc)}` (ExternalSecret, remote key `{remote_key(app, svc)}`)."]
        if s.shared:
            lines.append(f"- Database and login `{db_name(app)}`, owner of that database only.")
        for comp, envs in sorted(plan.overrides.items()):
            mine = [e for e in envs if e.startswith(f"{svc}:")]
            if mine:
                lines.append(f"- **{comp}**: " + ", ".join(f"`{e.split(':', 1)[1]}`" for e in mine))
        lines.append("")
    if plan.missing:
        lines += ["## Needed but turned off", ""]
        for svc in plan.missing:
            comps = ", ".join(sorted(plan.needed.get(svc) or {}))
            lines.append(f"- **{SERVICES[svc].title}** ({comps}): turn it on under Admin -> Lab services and scan "
                         "again; until then the app keeps its own settings.")
        lines.append("")
    notes = [(comp, n) for comp, ns in sorted(plan.notes.items()) for n in ns]
    if notes:
        lines += ["## Notes", ""] + [f"- {comp}: {n}" for comp, n in notes] + [""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- the lab side

def _labels(svc: str, ns: str | None = None) -> dict:
    lab = {"app.kubernetes.io/name": instance(svc, ns) if ns else svc, "app.kubernetes.io/part-of": LAB_NS,
           LABEL: svc, **MANAGED}
    if ns:
        lab[APP_LABEL] = ns
    return lab


def namespace_docs() -> list[dict]:
    """The lab namespace: Pod Security restricted, deny everything not allowed below, quota defaults."""
    meta = {"labels": dict(MANAGED)}
    return [
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": LAB_NS, "labels": {**MANAGED, "pod-security.kubernetes.io/enforce": "restricted",
                                                 "pod-security.kubernetes.io/enforce-version": "latest",
                                                 "pod-security.kubernetes.io/audit": "restricted",
                                                 "pod-security.kubernetes.io/warn": "restricted"}}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "default-deny-all", "namespace": LAB_NS, **copy.deepcopy(meta)},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        {"apiVersion": "v1", "kind": "LimitRange", "metadata": {"name": "defaults", "namespace": LAB_NS, **copy.deepcopy(meta)},
         "spec": {"limits": [{"type": "Container", "default": {"memory": "256Mi", "ephemeral-storage": "1Gi"},
                              "defaultRequest": {"cpu": "50m", "memory": "64Mi", "ephemeral-storage": "64Mi"},
                              "max": {"memory": "4Gi"}}]}},
        # no API access from any lab pod
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "lab-service", "namespace": LAB_NS, **copy.deepcopy(meta)},
         "automountServiceAccountToken": False},
    ]


def _pod(svc: str, labels: dict, container: dict, volumes: list[dict], caps_add: list[str] | None = None) -> dict:
    """A pod template hardened like the generated apps (rules/60-security.yaml baseline): non-root,
    read-only root file system, no capabilities, RuntimeDefault seccomp and AppArmor, no token."""
    from .harden import harden_pod
    s = SERVICES[svc]
    meta = {"labels": dict(labels)}
    pod = {"containers": [container], "volumes": volumes}
    harden_pod(meta, pod, s.uid, svc, [])
    pod["serviceAccountName"] = "lab-service"
    pod["automountServiceAccountToken"] = False
    pod["enableServiceLinks"] = False
    if caps_add:
        container["securityContext"]["capabilities"]["add"] = list(caps_add)
    req, lim = s.memory
    container["resources"] = {"requests": {"cpu": "50m", "memory": req, "ephemeral-storage": "64Mi"},
                              "limits": {"memory": lim, "ephemeral-storage": "1Gi"}}
    return {"metadata": meta, "spec": pod}


def _scratch(*paths: str) -> tuple[list[dict], list[dict]]:
    vols, mounts = [], []
    for i, p in enumerate(paths):
        vols.append({"name": f"tmp{i}", "emptyDir": {"sizeLimit": "256Mi"}})
        mounts.append({"name": f"tmp{i}", "mountPath": p})
    return vols, mounts


def pvc(name: str, labels: dict, size: str) -> dict:
    """Persistent volume (default StorageClass: k3s local-path, under /var/lib/rancher on the persistent
    partition). Kept when the service is turned off."""
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": size}}}}


def _deployment(name: str, labels: dict, template: dict, checksum: str | None = None) -> dict:
    sel = {k: labels[k] for k in ("app.kubernetes.io/name", LABEL)}
    tpl = copy.deepcopy(template)
    tpl["metadata"]["labels"].update(sel)
    if checksum:
        tpl["metadata"].setdefault("annotations", {})["containerizer.io/config-sha256"] = checksum
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
            "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "revisionHistoryLimit": 2,
                     "selector": {"matchLabels": sel}, "template": tpl}}


def _service(name: str, labels: dict, port: int) -> dict:
    sel = {k: labels[k] for k in ("app.kubernetes.io/name", LABEL)}
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
            "spec": {"selector": sel, "ports": [{"name": "svc", "port": port, "targetPort": port, "protocol": "TCP"}]}}


def ingress_policy(svc: str, ns: str) -> dict:
    """Lets app namespace `ns` (its own pods only) reach the service's port; nothing else gets in."""
    s = SERVICES[svc]
    labels = {**_labels(svc), APP_LABEL: ns}
    pods = {LABEL: svc} if s.shared else {LABEL: svc, APP_LABEL: ns}
    name = _label(f"{svc}-from-{ns}", f"from/{svc}/{ns}")
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": LAB_NS, "labels": labels},
            "spec": {"podSelector": {"matchLabels": pods}, "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
                                            "podSelector": {"matchLabels": {"app.kubernetes.io/part-of": ns}}}],
                                  "ports": [{"port": s.port, "protocol": "TCP"}]}]}}


def admin_secret_name(svc: str) -> str:
    return f"{svc}-admin"


def shared_manifests(svc: str, image: str) -> list[dict]:
    """Server of a shared service: Deployment (one replica, Recreate), Service, data volume. Its admin
    password is the Secret `<svc>-admin` (key `password`), created by the lab agent."""
    s = SERVICES[svc]
    labels = _labels(svc)
    admin = {"valueFrom": {"secretKeyRef": {"name": admin_secret_name(svc), "key": "password"}}}
    if svc == "sqlserver":
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}})
        mounts.append({"name": "data", "mountPath": "/var/opt/mssql"})
        ready = ["/bin/sh", "-c", 'SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" /opt/mssql-tools18/bin/sqlcmd -C -S localhost '
                                  '-U sa -b -Q "SET NOCOUNT ON; SELECT 1" -o /dev/null']
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             # Developer edition: free for development and test, not licensed for production; lab only
             "env": [{"name": "ACCEPT_EULA", "value": "Y"}, {"name": "MSSQL_PID", "value": "Developer"},
                     {"name": "MSSQL_MEMORY_LIMIT_MB", "value": "2048"},
                     {"name": "MSSQL_AGENT_ENABLED", "value": "false"},
                     {"name": "MSSQL_SA_PASSWORD", **admin}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10, "failureThreshold": 60},
             "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 15, "timeoutSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        # sqlservr carries the file capability cap_net_bind_service; exec needs it in the bounding set
        # (the only capability Pod Security "restricted" allows). With no_new_privs it is never raised.
        tpl = _pod(svc, labels, c, vols, caps_add=["NET_BIND_SERVICE"])
    elif svc == "postgres":
        vols, mounts = _scratch("/tmp", "/var/run/postgresql")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}})
        mounts.append({"name": "data", "mountPath": "/var/lib/postgresql"})
        ready = ["pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", "postgres"]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "args": ["postgres", "-c", "listen_addresses=*", "-c", "password_encryption=scram-sha-256",
                      "-c", "log_connections=on", "-c", "log_disconnections=on", "-c", "max_connections=200"],
             "env": [{"name": "POSTGRES_PASSWORD", **admin}, {"name": "POSTGRES_HOST_AUTH_METHOD", "value": "scram-sha-256"},
                     {"name": "POSTGRES_INITDB_ARGS", "value": "--auth-host=scram-sha-256 --auth-local=peer"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"exec": {"command": ready}, "periodSeconds": 5, "failureThreshold": 60},
             "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        tpl = _pod(svc, labels, c, vols)
    else:
        raise LabError(f"{svc} is not a shared service")
    return [pvc(f"{svc}-data", labels, s.storage), _deployment(svc, labels, tpl), _service(svc, labels, s.port)]


def per_app_manifests(svc: str, ns: str, image: str, cred: dict) -> list[dict]:
    """A per-app instance: its config Secret (built from the app's credentials), Deployment, Service,
    data volume and the ingress policy for its app."""
    s = SERVICES[svc]
    name = instance(svc, ns)
    labels = _labels(svc, ns)
    if svc == "redis":
        # the password only as its SHA-256: the config file holds no secret that works against the server
        digest = hashlib.sha256(cred["password"].encode()).hexdigest()
        conf = ("bind * -::*\nport 6379\nprotected-mode yes\ndir /data\nappendonly yes\nappendfsync everysec\n"
                "save 3600 1 300 100 60 10000\nmaxmemory 200mb\nmaxmemory-policy noeviction\n"
                f"user default on #{digest} ~* &* +@all -@admin\n")
        files = {"redis.conf": conf}
        vols, mounts = _scratch("/tmp")
        vols += [{"name": "config", "secret": {"secretName": name, "defaultMode": 0o440}},
                 {"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}}]
        mounts += [{"name": "config", "mountPath": "/etc/redis", "readOnly": True},
                   {"name": "data", "mountPath": "/data"}]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["redis-server", "/etc/redis/redis.conf"],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "s3":
        files = {"ROOT_ACCESS_KEY_ID": cred["access-key-id"], "ROOT_SECRET_ACCESS_KEY": cred["secret-access-key"]}
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}})
        mounts.append({"name": "data", "mountPath": "/data"})
        env = [{"name": k, "valueFrom": {"secretKeyRef": {"name": name, "key": k}}} for k in sorted(files)]
        # objects under /data/buckets, their metadata in a sidecar directory (no extended attributes needed)
        env += [{"name": "VGW_PORT", "value": ":7070"}, {"name": "VGW_HEALTH", "value": "/health"},
                {"name": "VGW_REGION", "value": "us-east-1"},
                {"name": "VGW_VIRTUAL_DOMAIN", "value": host(svc, ns)},
                {"name": "VGW_META_SIDECAR", "value": "/data/meta"}]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["/bin/sh", "-c", "mkdir -p /data/buckets /data/meta && exec /usr/local/bin/versitygw posix /data/buckets"],
             "env": env, "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"httpGet": {"path": "/health", "port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "azure-blob":
        # AZURITE_ACCOUNTS replaces the emulator's well-known account: only this app's account exists
        files = {"AZURITE_ACCOUNTS": f"{cred['account-name']}:{cred['account-key']}"}
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}})
        mounts.append({"name": "data", "mountPath": "/data"})
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["azurite-blob", "--blobHost", "0.0.0.0", "--blobPort", str(s.port), "--location", "/data",
                         "--disableProductStyleUrl", "--disableTelemetry", "--skipApiVersionCheck"],
             "env": [{"name": "AZURITE_ACCOUNTS", "valueFrom": {"secretKeyRef": {"name": name, "key": "AZURITE_ACCOUNTS"}}},
                     {"name": "HOME", "value": "/tmp"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    else:
        raise LabError(f"{svc} is not a per-app service")
    checksum = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
              "type": "Opaque", "stringData": files}
    tpl = _pod(svc, labels, c, vols)
    return [secret, pvc(f"{name}-data", labels, s.storage), _deployment(name, labels, tpl, checksum),
            _service(name, labels, s.port), ingress_policy(svc, ns)]


# --------------------------------------------------------------------------- credentials and provisioning

_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def new_password(length: int = 32) -> str:
    """Letters and digits only (nothing to escape in a connection string or SQL literal), always with
    upper, lower and digit (SQL Server's password policy)."""
    import secrets
    while True:
        p = "".join(secrets.choice(_ALNUM) for _ in range(length))
        if re.search(r"[A-Z]", p) and re.search(r"[a-z]", p) and re.search(r"\d", p):
            return p


SECRET_PARTS = ("password", "access-key-id", "secret-access-key", "account-key")


def new_credentials(svc: str, ns: str, keep: dict | None = None) -> dict:
    """The remote key's properties for an app; secret parts already in `keep` (the store) are kept,
    everything derived from them (connection strings) is built again."""
    import base64
    import secrets
    keep = {k: v for k, v in (keep or {}).items() if k in SECRET_PARTS and isinstance(v, str) and v}
    h, port = host(svc, ns), str(SERVICES[svc].port)
    if svc in ("sqlserver", "postgres"):
        cred = {"host": h, "port": port, "database": db_name(ns), "username": db_name(ns),
                "password": keep.get("password") or new_password()}
        return {**cred, "connection-string": connection_string(svc, cred)}
    if svc == "redis":
        cred = {"host": h, "port": port, "password": keep.get("password") or new_password()}
        return {**cred, "connection-string": connection_string(svc, cred)}
    if svc == "s3":
        return {"endpoint": f"http://{h}:{port}", "region": "us-east-1",
                "access-key-id": keep.get("access-key-id") or
                "CZ" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(18)),
                "secret-access-key": keep.get("secret-access-key") or new_password(40)}
    if svc == "azure-blob":
        account = "lab" + hashlib.sha256(ns.encode()).hexdigest()[:12]
        key = keep.get("account-key") or base64.b64encode(secrets.token_bytes(64)).decode()
        return {"account-name": account, "account-key": key,
                "connection-string": f"DefaultEndpointsProtocol=http;AccountName={account};AccountKey={key};"
                                     f"BlobEndpoint=http://{h}:{port}/{account};"}
    raise LabError(f"unknown lab service {svc!r}")


def connection_string(svc: str, c: dict) -> str:
    """ADO.NET (Microsoft.Data.SqlClient, Npgsql) and StackExchange.Redis connection strings. SQL Server
    encrypts with its own certificate; the lab's other traffic stays on the node (see docs)."""
    if svc == "sqlserver":
        return (f"Server={c['host']},{c['port']};Database={c['database']};User Id={c['username']};"
                f"Password={c['password']};Encrypt=True;TrustServerCertificate=True")
    if svc == "postgres":
        return f"Host={c['host']};Port={c['port']};Database={c['database']};Username={c['username']};Password={c['password']}"
    if svc == "redis":
        return f"{c['host']}:{c['port']},password={c['password']},abortConnect=false"
    raise LabError(f"{svc} has no connection string")


def complete(svc: str, ns: str, cred: dict) -> bool:
    """The stored credentials are whole and match the names this version derives (host, connection
    string): nothing to write."""
    return bool(cred) and new_credentials(svc, ns, cred) == cred


def _safe(v: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]{1,128}", v):
        raise LabError("unsafe identifier or password")
    return v


def provision_sql(svc: str, ns: str, cred: dict) -> str:
    """Script (on stdin, never arguments) that creates or updates the app's database and login."""
    db, user, pw = _safe(db_name(ns)), _safe(cred["username"]), _safe(cred["password"])
    if svc == "sqlserver":
        return f"""SET NOCOUNT ON;
IF SUSER_ID(N'{user}') IS NULL
BEGIN
    CREATE LOGIN [{user}] WITH PASSWORD = N'{pw}', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = [master];
END
ELSE
BEGIN
    ALTER LOGIN [{user}] WITH PASSWORD = N'{pw}';
END
IF DB_ID(N'{db}') IS NULL CREATE DATABASE [{db}];
GO
ALTER AUTHORIZATION ON DATABASE::[{db}] TO [{user}];
ALTER LOGIN [{user}] WITH DEFAULT_DATABASE = [{db}];
DENY VIEW ANY DATABASE TO [{user}];
DENY VIEW SERVER STATE TO [{user}];
GO
"""
    if svc == "postgres":
        return f"""\\set ON_ERROR_STOP on
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
SELECT 'CREATE ROLE "{user}" LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{user}')\\gexec
ALTER ROLE "{user}" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{pw}';
SELECT 'CREATE DATABASE "{db}" OWNER "{user}"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{db}')\\gexec
ALTER DATABASE "{db}" OWNER TO "{user}";
REVOKE ALL ON DATABASE "{db}" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "{db}" TO "{user}";
\\connect "{db}"
ALTER SCHEMA public OWNER TO "{user}";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
"""
    raise LabError(f"{svc} has no database to provision")


def provision_command(svc: str) -> list[str]:
    """What the lab agent runs in the server's container (kubectl exec -i), the script on stdin. The
    admin password stays in the container's environment."""
    if svc == "sqlserver":
        return ["/bin/sh", "-c", 'SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" exec /opt/mssql-tools18/bin/sqlcmd -C -S localhost '
                                 '-U sa -b -I -i /dev/stdin']
    if svc == "postgres":
        return ["psql", "-X", "-q", "-U", "postgres", "-d", "postgres", "-f", "-"]
    raise LabError(f"{svc} has no database to provision")
