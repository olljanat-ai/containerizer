"""Deployment descriptors of applications that are already containerized, read into one neutral model.

Repositories with a Dockerfile are skipped by organization scans unless an administrator enables them.
When one is enabled, the scan looks for how the application is deployed today and moves that to
Kubernetes (replatform.py) instead of containerizing the source code again:

    docker-swarm / docker-compose   docker-compose*.yml, compose*.yaml, *stack*.yml (services:)
    nomad                           *.nomad, *.nomad.hcl, *.hcl with a job block, Nomad job JSON
    azure-container-apps            `az containerapp --yaml` files, ARM templates and Bicep files with
                                    Microsoft.App/containerApps or Microsoft.App/jobs resources
    aws-ecs                         ECS task definitions (containerDefinitions)

Descriptors of other platforms are recognised (fly.toml, Cloud Foundry manifest.yml, Google App Engine
app.yaml, Render render.yaml, Marathon, Heroku heroku.yml, Kamal deploy.yml) but only translated in
LLM-heavy mode (replatform.py), because they carry too little structure to read reliably with rules.

Every parser returns `Service` objects. What a parser could not carry over goes to `Service.notes`,
which end up in MIGRATION.md, so nothing is dropped silently.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "bin", "obj", "target", "dist", "build"}
MAX_FILE = 512 * 1024
PLATFORM_TEXT = {"docker-swarm": "Docker Swarm", "docker-compose": "Docker Compose", "nomad": "HashiCorp Nomad",
                 "azure-container-apps": "Azure Container Apps", "aws-ecs": "Amazon ECS", "fly": "Fly.io",
                 "cloud-foundry": "Cloud Foundry", "app-engine": "Google App Engine", "render": "Render",
                 "marathon": "Marathon", "heroku": "Heroku", "kamal": "Kamal"}
# images that are a backing service (database, cache, broker), not the application itself
BACKING_RE = re.compile(r"(^|/)(postgres|postgis|mysql|mariadb|mongo|redis|valkey|memcached|rabbitmq|"
                        r"elasticsearch|opensearch|mssql/server|azure-sql-edge|cassandra|zookeeper|kafka|"
                        r"cp-kafka|nats|minio|azurite|consul|vault|etcd|mailhog|mailpit|localstack)([:@]|$)", re.I)
SECRET_NAME_RE = re.compile(r"(?i)(passw|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
                            r"credential|connection[_-]?string|connstr|conn[_-]?str|sas|signing[_-]?key|"
                            r"client[_-]?secret|^ConnectionStrings__|dsn$|_url_with_password)")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,250}")


@dataclass
class Service:
    name: str
    platform: str                                     # see PLATFORM_TEXT
    source: str                                       # descriptor file, relative to the repository
    image: str = ""                                   # the image it runs today
    build: dict | None = None                         # {"context": dir, "dockerfile": file} relative to the repo
    command: list = field(default_factory=list)       # Kubernetes `command` (replaces the image ENTRYPOINT)
    args: list = field(default_factory=list)          # Kubernetes `args` (replaces the image CMD)
    env: dict = field(default_factory=dict)           # plain settings
    secrets: list = field(default_factory=list)       # env names whose values come from the secret store
    secret_files: list = field(default_factory=list)  # [{"name", "path"}]: files from the secret store
    ports: list = field(default_factory=list)         # container ports, the first one is the main one
    public: bool = False                              # reachable from outside today (published, ingress)
    replicas: int = 1
    cpu: str = ""                                     # Kubernetes quantities
    memory: str = ""
    health: dict | None = None                        # {"type": "http", "path", "port"} | {"type": "tcp"} | {"type": "exec", "command"}
    volumes: list = field(default_factory=list)       # [{"path", "persistent": bool, "size"}]
    schedule: str = ""                                # cron: runs as a CronJob
    depends_on: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    backing: bool = False                             # a database/cache/broker image: not migrated as an app
    egress: list = field(default_factory=list)        # ports it calls out to (from its settings, secret ones too)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Service":
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class Descriptor:
    path: str                                         # relative to the repository
    platform: str
    services: list = field(default_factory=list)
    error: str = ""                                   # why it could not be read
    parsed: bool = True                               # False: recognised, needs LLM-heavy mode to translate

    def to_dict(self) -> dict:
        return {"path": self.path, "platform": self.platform, "error": self.error, "parsed": self.parsed,
                "services": [s.to_dict() for s in self.services]}


# --------------------------------------------------------------------------- helpers

def _quantity_mem(v, unit_default: str = "") -> str:
    """'512M', '1g', '1.5Gi', 512 (MB), '536870912' (bytes) -> a Kubernetes memory quantity."""
    if v is None or v == "":
        return ""
    s = str(v).strip()
    m = re.fullmatch(r"(?i)(\d+(?:\.\d+)?)\s*([kmgt]i?b?|b)?", s)
    if not m:
        return ""
    n, u = float(m.group(1)), (m.group(2) or unit_default).lower().rstrip("b")
    mib = {"": n / (1024 * 1024), "k": n / 1024, "ki": n / 1024, "m": n, "mi": n, "g": n * 1024, "gi": n * 1024,
           "t": n * 1024 * 1024, "ti": n * 1024 * 1024}.get(u)
    if mib is None:
        return ""
    return f"{max(1, round(mib))}Mi"


def _quantity_cpu(v) -> str:
    """'0.5', 0.25, '1.5' cores -> millicores."""
    try:
        f = float(str(v).strip())
    except (TypeError, ValueError):
        return ""
    return f"{max(1, round(f * 1000))}m" if f > 0 else ""


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def interpolate(value: str, env: dict, notes: list, where: str) -> str:
    """Compose variable substitution: ${VAR}, ${VAR:-default}, ${VAR-default}, $VAR, $$ (a literal $)."""
    if not isinstance(value, str) or "$" not in value:
        return value

    def sub(m):
        name = m.group(1) or m.group(4)
        op, default = m.group(2), m.group(3)
        if name in env and (env[name] != "" or op not in (":-",)):
            return env[name]
        if op in (":-", "-"):
            return default or ""
        notes.append(f"{where}: ${{{name}}} is set where the stack is deployed; set it in the generated manifest")
        return m.group(0)
    return _VAR.sub(sub, value.replace("$$", "\0")).replace("\0", "$")


URL_PORTS = {"postgres": 5432, "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "redis": 6379, "rediss": 6380,
             "mongodb": 27017, "mongodb+srv": 27017, "amqp": 5672, "amqps": 5671, "https": 443, "http": 80,
             "nats": 4222, "kafka": 9092, "sqlserver": 1433, "mssql": 1433, "ldap": 389, "ldaps": 636,
             "smtp": 25, "smtps": 465}
LISTEN_HOSTS = {"+", "*", "0.0.0.0", "[::]", "localhost", "127.0.0.1"}


def egress_ports(env: dict) -> list[int]:
    """Ports a service calls out to, from the URLs and connection strings in its settings (the values are
    only read here: secret ones are never kept)."""
    ports: set[int] = set()
    for v in env.values():
        v = "" if v is None else str(v)
        for m in re.finditer(r"\b([a-z][a-z0-9+.-]*)://(?:[^@/\s]*@)?([^/\s:;,]+)(?::(\d{1,5}))?", v):
            if m.group(2) in LISTEN_HOSTS:
                continue                                      # a listen address, not something it calls
            p = int(m.group(3)) if m.group(3) else URL_PORTS.get(m.group(1).lower())
            if p:
                ports.add(p)
        for m in re.finditer(r"(?i)\b(?:server|data source|host)\s*=\s*(?:tcp:)?[^;,]+[,:](\d{2,5})", v):
            ports.add(int(m.group(1)))
        if re.search(r"(?i)(server|data source)\s*=", v) and not re.search(r"(?i)(server|data source)\s*=[^;]*[,:]\d", v):
            ports.add(1433)
    return sorted(p for p in ports if 0 < p < 65536)


def split_env(sv: "Service", env: dict) -> None:
    """Settings into the service: plain values, the names of the secret ones, and the ports they point at."""
    plain, secret = classify_env(env)
    sv.env = {**sv.env, **plain}
    sv.secrets = sorted(set(sv.secrets) | set(secret))
    sv.egress = sorted(set(sv.egress) | set(egress_ports(env)))


def classify_env(env: dict) -> tuple[dict, list]:
    """Split settings into plain values and the names whose values are secrets (by name, or a URL with
    a password in it)."""
    plain, secret = {}, []
    for k, v in env.items():
        sv = "" if v is None else str(v)
        if SECRET_NAME_RE.search(k) or re.search(r"\w+://[^/\s:@]+:[^/\s@]+@", sv) or \
                re.search(r"(?i)(password|pwd)\s*=", sv):
            secret.append(k)
        else:
            plain[k] = sv
    return plain, sorted(set(secret))


def _split_cmd(v) -> list:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    try:
        return shlex.split(str(v))
    except ValueError:
        return [str(v)]


def health_from_cmd(cmd: list, ports: list) -> dict | None:
    """A container health check command -> an HTTP probe when it calls curl/wget on localhost, else exec."""
    if not cmd:
        return None
    if cmd[0] in ("CMD", "CMD-SHELL"):
        cmd = cmd[1:] if cmd[0] == "CMD" else _split_cmd(" ".join(cmd[1:]))
    if cmd and cmd[0] == "NONE":
        return None
    text = " ".join(cmd)
    m = re.search(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::(\d+))?(/[^\s'\"|;&]*)?", text)
    if m and re.search(r"\b(curl|wget|http)\b", text):
        port = int(m.group(1)) if m.group(1) else (ports[0] if ports else 80)
        return {"type": "http", "path": m.group(2) or "/", "port": port}
    return {"type": "exec", "command": cmd if len(cmd) > 1 or " " not in text else ["sh", "-c", text]}


def _env_list(v) -> dict:
    """['A=1', 'B'] or {'A': 1} or [{'name': 'A', 'value': '1'}] -> {'A': '1'}."""
    out = {}
    if isinstance(v, dict):
        for k, x in v.items():
            out[str(k)] = "" if x is None else (str(x).lower() if isinstance(x, bool) else str(x))
    elif isinstance(v, list):
        for x in v:
            if isinstance(x, dict) and "name" in x:
                out[str(x["name"])] = "" if x.get("value") is None else str(x.get("value"))
            elif isinstance(x, str):
                k, _, val = x.partition("=")
                out[k] = val
    return out


def _read_env_file(root: Path, rel: str) -> dict:
    p = (root / rel).resolve()
    if not str(p).startswith(str(root.resolve())) or not p.is_file() or p.stat().st_size > MAX_FILE:
        return {}
    out = {}
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.removeprefix("export ").partition("=")
        out[k.strip()] = v.strip().strip("'\"")
    return out


def _rel(root: Path, base: Path, p: str) -> str:
    """A path from a descriptor (relative to the descriptor's folder) as a path relative to the repository."""
    full = (base / p).resolve()
    try:
        return full.relative_to(root.resolve()).as_posix() or "."
    except ValueError:
        return ""


# --------------------------------------------------------------------------- Docker Compose / Swarm

COMPOSE_NAME_RE = re.compile(r"(?i)^(docker-)?compose([.-][\w.-]+)?\.ya?ml$|^[\w.-]*stack[\w.-]*\.ya?ml$")


def _compose_port(p) -> tuple[int | None, bool]:
    """'8080:80', '127.0.0.1:8080:80/tcp', '80', 80, {'target': 80, 'published': 8080} -> (container port, published)."""
    if isinstance(p, dict):
        t = p.get("target")
        return (int(t) if str(t).isdigit() else None), bool(p.get("published"))
    s = str(p).split("/")[0]
    parts = s.split(":")
    t = parts[-1].split("-")[0]
    return (int(t) if t.isdigit() else None), len(parts) > 1


def parse_compose(root: Path, rel: str, text: str) -> Descriptor:
    doc = yaml.safe_load(text) or {}
    services = (doc.get("services") or {}) if isinstance(doc, dict) else {}
    swarm = bool(re.search(r"(?i)stack", Path(rel).name)) or any(isinstance(s, dict) and isinstance(s.get("deploy"), dict)
                                                               and (s["deploy"].get("mode") or s["deploy"].get("placement")
                                                                    or s["deploy"].get("update_config"))
                                                               for s in services.values())
    d = Descriptor(rel, "docker-swarm" if swarm else "docker-compose")
    base = (root / rel).parent
    top_secrets = doc.get("secrets") or {}
    top_volumes = doc.get("volumes") or {}
    for name, s in services.items():
        if not isinstance(s, dict):
            continue
        sv = Service(name=str(name), platform=d.platform, source=rel, image=str(s.get("image") or ""))
        where = f"{rel}: service {name}"
        env = {}
        for ef in ([s["env_file"]] if isinstance(s.get("env_file"), (str, dict)) else s.get("env_file") or []):
            path = ef.get("path") if isinstance(ef, dict) else ef
            if path:
                found = _read_env_file(root, _rel(root, base, path) or "")
                if not found:
                    sv.notes.append(f"{where}: env_file {path} is not in the repository; its settings are not carried over")
                env.update(found)
        env.update(_env_list(s.get("environment")))
        split_env(sv, env)
        sv.env = {k: interpolate(v, {}, sv.notes, where) for k, v in sv.env.items()}
        b = s.get("build")
        if b:
            ctx = b if isinstance(b, str) else (b.get("context") or ".")
            ctx_rel = _rel(root, base, ctx)
            df = "Dockerfile" if isinstance(b, str) else (b.get("dockerfile") or "Dockerfile")
            sv.build = {"context": ctx_rel, "dockerfile": _rel(root, root / ctx_rel, df) if ctx_rel else ""}
            if isinstance(b, dict) and b.get("args"):
                sv.build["args"] = _env_list(b["args"])
            if isinstance(b, dict) and b.get("target"):
                sv.build["target"] = str(b["target"])
        sv.command = _split_cmd(s.get("entrypoint"))
        sv.args = _split_cmd(s.get("command"))
        for p in s.get("ports") or []:
            port, published = _compose_port(p)
            if port and port not in sv.ports:
                sv.ports.append(port)
            sv.public = sv.public or published
        for p in s.get("expose") or []:
            port, _ = _compose_port(p)
            if port and port not in sv.ports:
                sv.ports.append(port)
        labels = _env_list(s.get("labels")) | _env_list((s.get("deploy") or {}).get("labels"))
        if any(k.startswith("traefik.") for k in labels) and labels.get("traefik.enable", "true") != "false":
            sv.public = True
            lp = next((v for k, v in labels.items() if re.search(r"loadbalancer\.server\.port$", k)), None)
            if lp and str(lp).isdigit() and int(lp) not in sv.ports:
                sv.ports.insert(0, int(lp))
        dep = s.get("deploy") or {}
        if dep.get("mode") == "global":
            sv.notes.append(f"{where}: deploy.mode global (one per node) becomes a Deployment; use a DaemonSet if it "
                            "really needs one replica on every node")
        if str(dep.get("replicas", "")).isdigit():
            sv.replicas = int(dep["replicas"])
        res = dep.get("resources") or {}
        lim, rsv = res.get("limits") or {}, res.get("reservations") or {}
        sv.memory = _quantity_mem(lim.get("memory") or s.get("mem_limit"))
        sv.cpu = _quantity_cpu(rsv.get("cpus") or lim.get("cpus") or s.get("cpus") or "")
        if (dep.get("placement") or {}).get("constraints"):
            sv.notes.append(f"{where}: placement constraints {dep['placement']['constraints']} are not carried over "
                            "(use nodeSelector or affinity)")
        hc = s.get("healthcheck") or {}
        if hc and not hc.get("disable"):
            sv.health = health_from_cmd(_split_cmd(hc.get("test")), sv.ports)
        for v in s.get("volumes") or []:
            if isinstance(v, dict):
                src, target, typ = v.get("source") or "", v.get("target") or "", v.get("type") or ""
            else:
                parts = str(v).split(":")
                src, target = (parts[0], parts[1]) if len(parts) > 1 else ("", parts[0])
                typ = "bind" if src.startswith((".", "/", "~")) else ("volume" if src else "anonymous")
            if not target:
                continue
            if typ == "bind" or src.startswith((".", "/", "~")):
                if src.startswith("/var/run/docker.sock"):
                    sv.notes.append(f"{where}: mounts the Docker socket; that is not available (or safe) in Kubernetes")
                else:
                    sv.notes.append(f"{where}: bind mount {src} -> {target} becomes an empty writable folder; ship the "
                                    "files in the image or as a ConfigMap")
                sv.volumes.append({"path": target, "persistent": False})
            elif typ == "tmpfs":
                sv.volumes.append({"path": target, "persistent": False})
            else:
                sv.volumes.append({"path": target, "persistent": bool(src) and src in top_volumes or bool(src), "size": "1Gi"})
        for t in s.get("tmpfs") or []:
            sv.volumes.append({"path": str(t).split(":")[0], "persistent": False})
        for sec in s.get("secrets") or []:
            src = sec if isinstance(sec, str) else sec.get("source")
            target = (None if isinstance(sec, str) else sec.get("target")) or src
            if not src:
                continue
            path = target if str(target).startswith("/") else f"/run/secrets/{target}"
            sv.secret_files.append({"name": re.sub(r"[^A-Za-z0-9_.-]", "-", str(src)), "path": path})
            if src not in top_secrets:
                sv.notes.append(f"{where}: secret {src} is not declared at the top level")
        for c in s.get("configs") or []:
            src = c if isinstance(c, str) else c.get("source")
            sv.notes.append(f"{where}: config {src} becomes a file from the secret store; move it to a ConfigMap if "
                            "it holds nothing secret")
            target = (None if isinstance(c, str) else c.get("target")) or f"/{src}"
            sv.secret_files.append({"name": re.sub(r"[^A-Za-z0-9_.-]", "-", str(src)), "path": str(target)})
        dep_on = s.get("depends_on") or []
        sv.depends_on = list(dep_on.keys()) if isinstance(dep_on, dict) else [str(x) for x in dep_on]
        for k in ("privileged", "cap_add", "network_mode", "pid", "ipc", "devices", "sysctls", "extra_hosts"):
            if s.get(k):
                sv.notes.append(f"{where}: {k} is not carried over (the hardened pod security baseline does not allow it)"
                                if k in ("privileged", "cap_add", "pid", "ipc", "devices", "sysctls")
                                else f"{where}: {k} is not carried over")
        if s.get("user"):
            sv.notes.append(f"{where}: runs as user {s['user']}; the hardened manifest runs it as a non-root user")
        sv.backing = bool(sv.image and not sv.build and BACKING_RE.search(sv.image))
        d.services.append(sv)
    return d


# --------------------------------------------------------------------------- HCL (Nomad)

class HclError(ValueError):
    pass


_HCL_TOKEN = re.compile(r"""
    (?P<ws>[ \t\r]+|\\\n)
  | (?P<comment>\#[^\n]*|//[^\n]*|/\*.*?\*/)
  | (?P<nl>\n)
  | (?P<heredoc><<-?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)\n)
  | (?P<string>"(?:[^"\\$]|\\.|\$\{(?:[^{}]|\{[^{}]*\})*\}|\$)*")
  | (?P<number>-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_\-.]*(?:\[[^\]]*\])*(?:\([^()]*\))?)
  | (?P<punct>[{}\[\]=,:()])
""", re.X | re.S)


def _hcl_tokens(text: str) -> list[tuple[str, str]]:
    out, i = [], 0
    while i < len(text):
        m = _HCL_TOKEN.match(text, i)
        if not m:
            raise HclError(f"unexpected {text[i:i + 20]!r} at offset {i}")
        kind = m.lastgroup if m.lastgroup != "tag" else "heredoc"
        if m.group("heredoc"):
            tag = m.group("tag")
            end = re.compile(rf"^[ \t]*{re.escape(tag)}[ \t]*$", re.M)
            e = end.search(text, m.end())
            if not e:
                raise HclError(f"unterminated heredoc {tag}")
            body = text[m.end():e.start()]
            if m.group(0).startswith("<<-"):
                lines = body.splitlines(True)
                indent = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
                body = "".join(x[indent:] for x in lines)
            out.append(("string", body))
            i = e.end()
            continue
        if kind == "string":
            out.append(("string", json.loads(re.sub(r"\\(?![\"\\/bfnrtu])", r"\\\\", m.group(0)).replace("\n", "\\n"))
                        if "\\" in m.group(0) else m.group(0)[1:-1]))
        elif kind in ("ws", "comment"):
            pass
        else:
            out.append((kind, m.group(0)))
        i = m.end()
    return out


def parse_hcl(text: str) -> dict:
    """A small HCL parser for Nomad job files: blocks become {"type": [{"_labels": [...], ...}]},
    attributes plain values; expressions (variables, functions) stay as their source text."""
    toks = _hcl_tokens(text)
    pos = 0

    def peek(skip_nl=True):
        nonlocal pos
        j = pos
        while skip_nl and j < len(toks) and toks[j][0] == "nl":
            j += 1
        return toks[j] if j < len(toks) else ("eof", ""), j

    def take(skip_nl=True):
        nonlocal pos
        t, j = peek(skip_nl)
        pos = j + 1
        return t

    def value():
        t = take()
        if t[0] == "string":
            return t[1]
        if t[0] == "number":
            return float(t[1]) if any(c in t[1] for c in ".eE") else int(t[1])
        if t[0] == "ident":
            return {"true": True, "false": False, "null": None}.get(t[1], t[1])
        if t == ("punct", "["):
            items = []
            while True:
                n, _ = peek()
                if n == ("punct", "]"):
                    take()
                    return items
                items.append(value())
                n, _ = peek()
                if n == ("punct", ","):
                    take()
        if t == ("punct", "{"):
            obj = {}
            while True:
                n, _ = peek()
                if n == ("punct", "}"):
                    take()
                    return obj
                k = take()
                if k[0] not in ("ident", "string"):
                    raise HclError(f"expected a key, got {k[1]!r}")
                sep = take()
                if sep not in (("punct", "="), ("punct", ":")):
                    raise HclError(f"expected = after {k[1]}")
                obj[k[1]] = value()
                n, _ = peek()
                if n == ("punct", ","):
                    take()
        raise HclError(f"unexpected {t[1]!r}")

    def body(end: str | None) -> dict:
        out: dict = {}
        while True:
            t = take()
            if t[0] == "eof":
                if end:
                    raise HclError("unexpected end of file")
                return out
            if t == ("punct", end or ""):
                return out
            if t[0] == "nl":
                continue
            if t[0] not in ("ident", "string"):
                raise HclError(f"unexpected {t[1]!r}")
            n, _ = peek(skip_nl=False)
            if n == ("punct", "="):
                take()
                out[t[1]] = value()
                continue
            labels = []
            while True:
                n = take()
                if n[0] in ("string", "ident"):
                    labels.append(n[1])
                elif n == ("punct", "{"):
                    break
                else:
                    raise HclError(f"expected a block after {t[1]}")
            blk = body("}")
            blk["_labels"] = labels
            out.setdefault(t[1], []).append(blk)
    return body(None)


def _blocks(node: dict, name: str) -> list[dict]:
    v = node.get(name)
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    return [v] if isinstance(v, dict) else []


def _label(b: dict, default: str = "") -> str:
    return (b.get("_labels") or [default])[0]


TEMPLATE_ENV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", re.M)


def nomad_services(job: dict, rel: str) -> list[Service]:
    """Services of a parsed Nomad job ({job: [{_labels: [name], group: [...]}]} from HCL; JSON is normalised
    into the same shape)."""
    out = []
    for j in _blocks(job, "job"):
        jname = _label(j, "job")
        jtype = j.get("type") or "service"
        periodic = _blocks(j, "periodic")
        cron = (periodic[0].get("crons") or [periodic[0].get("cron")])[0] if periodic else ""
        for g in _blocks(j, "group") or [{"_labels": [jname], "task": j.get("task")}]:
            gname = _label(g, jname)
            nets = _blocks(g, "network")
            port_map: dict[str, int] = {}
            published = set()
            for n in nets:
                for p in _blocks(n, "port"):
                    lbl = _label(p)
                    to = p.get("to") or p.get("static")
                    if isinstance(to, (int, float)) and to > 0:
                        port_map[lbl] = int(to)
                    if p.get("static"):
                        published.add(lbl)
            services = _blocks(g, "service")
            vols = {_label(v): v for v in _blocks(g, "volume")}
            tasks = _blocks(g, "task")
            for t in tasks:
                tname = _label(t, gname)
                where = f"{rel}: job {jname}, task {tname}"
                cfg = (_blocks(t, "config") or [{}])[0]
                driver = t.get("driver") or ""
                if driver not in ("docker", "podman", "containerd-driver"):
                    sv = Service(name=tname, platform="nomad", source=rel,
                                 notes=[f"{where}: driver {driver or '?'} does not run a container image; not migrated"])
                    sv.backing = True
                    out.append(sv)
                    continue
                groups = _blocks(j, "group")
                name = (jname if len(groups) <= 1 and len(tasks) == 1 else
                        gname if len(tasks) == 1 else tname if tname != gname else f"{gname}-{tname}")
                sv = Service(name=name, platform="nomad", source=rel, image=str(cfg.get("image") or ""))
                if isinstance(cfg.get("entrypoint"), list):
                    sv.command = [str(x) for x in cfg["entrypoint"]]
                if cfg.get("command"):
                    sv.args = [str(cfg["command"]), *[str(x) for x in cfg.get("args") or []]]
                elif cfg.get("args"):
                    sv.args = [str(x) for x in cfg["args"]]
                env = {}
                for e in _blocks(t, "env"):
                    env.update({k: str(v) for k, v in e.items() if k != "_labels"})
                if isinstance(t.get("env"), dict):
                    env.update({k: str(v) for k, v in t["env"].items()})
                for tpl in _blocks(t, "template"):
                    data = str(tpl.get("data") or "")
                    if tpl.get("env"):
                        for k, v in TEMPLATE_ENV_RE.findall(data):
                            if "secret" in v or "Secret" in v or SECRET_NAME_RE.search(k):
                                sv.secrets.append(k)
                            elif "{{" not in v:
                                env[k] = v.strip().strip('"')
                            else:
                                sv.notes.append(f"{where}: {k} comes from a Consul template ({v.strip()[:80]}); set it "
                                                "in the generated manifest")
                    elif tpl.get("destination"):
                        dest = str(tpl["destination"])
                        path = dest if dest.startswith("/") else "/" + dest.split("/", 1)[-1]
                        if "secret" in data:
                            sv.secret_files.append({"name": re.sub(r"[^A-Za-z0-9_.-]", "-", Path(dest).name), "path": path})
                        else:
                            sv.notes.append(f"{where}: template {dest} is rendered by Nomad; ship it in the image or as a "
                                            "ConfigMap")
                if _blocks(t, "vault") or j.get("vault") or g.get("vault"):
                    sv.notes.append(f"{where}: reads from Vault; the generated ExternalSecrets read the same keys from "
                                    "the cluster's secret store")
                split_env(sv, env)
                labels = cfg.get("ports") or []
                main = [port_map[x] for x in labels if x in port_map]
                svc_ports = [s.get("port") for s in services + _blocks(t, "service")]
                for x in svc_ports:
                    if x in port_map and port_map[x] not in main:
                        main.append(port_map[x])
                    elif isinstance(x, int) and x not in main:
                        main.append(x)
                sv.ports = main or list(dict.fromkeys(port_map.values()))
                for s in services + _blocks(t, "service"):
                    tags = " ".join(str(x) for x in s.get("tags") or [])
                    if "traefik" in tags or "urlprefix" in tags or s.get("port") in published:
                        sv.public = True
                    for chk in _blocks(s, "check"):
                        typ = chk.get("type")
                        port = port_map.get(chk.get("port") or s.get("port"), sv.ports[0] if sv.ports else None)
                        if typ == "http" and not sv.health:
                            sv.health = {"type": "http", "path": chk.get("path") or "/", "port": port}
                        elif typ == "tcp" and not sv.health:
                            sv.health = {"type": "tcp", "port": port}
                        elif typ == "script" and not sv.health:
                            sv.health = {"type": "exec", "command": [str(chk.get("command") or "true"),
                                                                    *[str(x) for x in chk.get("args") or []]]}
                sv.public = sv.public or bool(published & set(labels))
                res = (_blocks(t, "resources") or [{}])[0]
                if res.get("cpu"):
                    sv.cpu = f"{int(res['cpu'])}m"         # Nomad MHz: about 1000 MHz to a core
                if res.get("memory_max") or res.get("memory"):
                    sv.memory = _quantity_mem(res.get("memory_max") or res.get("memory"), "m")
                if isinstance(g.get("count"), int):
                    sv.replicas = g["count"]
                for vm in _blocks(t, "volume_mount"):
                    v = vols.get(vm.get("volume"), {})
                    sv.volumes.append({"path": str(vm.get("destination") or "/data"), "persistent": True, "size": "1Gi"})
                    if v.get("type") == "host":
                        sv.notes.append(f"{where}: host volume {v.get('source')} becomes a PersistentVolumeClaim")
                for m in cfg.get("volumes") or []:
                    target = str(m).split(":")[-1] if ":" in str(m) else str(m)
                    sv.volumes.append({"path": target, "persistent": False})
                    sv.notes.append(f"{where}: docker volume {m} becomes an empty writable folder")
                if jtype == "batch" and cron:
                    sv.schedule = str(cron)
                elif jtype == "batch":
                    sv.schedule = "0 2 * * *"
                    sv.notes.append(f"{where}: a batch job without a schedule; the CronJob schedule is a placeholder")
                elif jtype == "system":
                    sv.notes.append(f"{where}: a system job (one per node) becomes a Deployment; use a DaemonSet if "
                                    "it really needs every node")
                for c in _blocks(j, "constraint") + _blocks(g, "constraint"):
                    sv.notes.append(f"{where}: constraint {c.get('attribute', '')} {c.get('operator', '=')} "
                                    f"{c.get('value', '')} is not carried over")
                if cfg.get("privileged") or cfg.get("cap_add") or cfg.get("network_mode") == "host":
                    sv.notes.append(f"{where}: privileged, cap_add or host networking is not carried over (hardened "
                                    "pod security baseline)")
                sv.backing = bool(BACKING_RE.search(sv.image))
                out.append(sv)
    return out


def _nomad_json(doc: dict) -> dict:
    """Nomad API JSON ({"Job": {...}}) -> the HCL-shaped dict nomad_services reads."""
    j = doc.get("Job") or doc

    def port_list(nets):
        return [{"_labels": [p.get("Label")], "to": p.get("To") or p.get("Value"), "static": p.get("Value")}
                for n in nets or [] for p in (n.get("DynamicPorts") or []) + (n.get("ReservedPorts") or [])]

    def svc(s):
        return {"port": s.get("PortLabel"), "tags": s.get("Tags") or [],
                "check": [{"type": c.get("Type"), "path": c.get("Path"), "port": c.get("PortLabel")}
                          for c in s.get("Checks") or []]}
    groups = []
    for g in j.get("TaskGroups") or []:
        groups.append({"_labels": [g.get("Name")], "count": g.get("Count"),
                       "network": [{"port": port_list(g.get("Networks"))}], "service": [svc(s) for s in g.get("Services") or []],
                       "task": [{"_labels": [t.get("Name")], "driver": t.get("Driver"), "config": [t.get("Config") or {}],
                                 "env": t.get("Env") or {},
                                 "resources": [{"cpu": (t.get("Resources") or {}).get("CPU"),
                                                "memory": (t.get("Resources") or {}).get("MemoryMB")}],
                                 "service": [svc(s) for s in t.get("Services") or []],
                                 "template": [{"data": x.get("EmbeddedTmpl"), "destination": x.get("DestPath"),
                                               "env": x.get("Envvars")} for x in t.get("Templates") or []]}
                                for t in g.get("Tasks") or []]})
    per = j.get("Periodic") or {}
    return {"job": [{"_labels": [j.get("Name") or j.get("ID") or "job"], "type": (j.get("Type") or "service"),
                     "periodic": [{"cron": per.get("Spec")}] if per.get("Spec") else [], "group": groups}]}


def parse_nomad(root: Path, rel: str, text: str) -> Descriptor:
    d = Descriptor(rel, "nomad")
    if rel.endswith(".json"):
        d.services = nomad_services(_nomad_json(json.loads(text)), rel)
    else:
        d.services = nomad_services(parse_hcl(text), rel)
    return d


# --------------------------------------------------------------------------- Azure Container Apps

def _aca_services(name: str, props: dict, rel: str, kind: str = "app") -> list[Service]:
    """properties of a Microsoft.App/containerApps (or jobs) resource -> services (one per container)."""
    out = []
    conf = props.get("configuration") or {}
    tpl = props.get("template") or {}
    ingress = conf.get("ingress") or {}
    secrets = {s.get("name"): s for s in conf.get("secrets") or [] if isinstance(s, dict)}
    scale = tpl.get("scale") or {}
    vols = {v.get("name"): v for v in tpl.get("volumes") or [] if isinstance(v, dict)}
    containers = [c for c in tpl.get("containers") or [] if isinstance(c, dict)]
    for i, c in enumerate(containers):
        cname = str(c.get("name") or name)
        sname = str(name) if i == 0 or len(containers) == 1 else f"{name}-{cname}"
        where = f"{rel}: {kind} {name}, container {cname}"
        sv = Service(name=sname, platform="azure-container-apps", source=rel, image=str(c.get("image") or ""))
        sv.command = _split_cmd(c.get("command"))
        sv.args = _split_cmd(c.get("args"))
        env = {}
        for e in c.get("env") or []:
            if not isinstance(e, dict) or not e.get("name"):
                continue
            if e.get("secretRef"):
                sv.secrets.append(str(e["name"]))
                ref = secrets.get(e["secretRef"]) or {}
                if ref.get("keyVaultUrl"):
                    sv.notes.append(f"{where}: {e['name']} comes from Key Vault ({ref['keyVaultUrl']}); the "
                                    "ExternalSecret reads it from the cluster's secret store")
            else:
                env[str(e["name"])] = "" if e.get("value") is None else str(e["value"])
        split_env(sv, env)
        res = c.get("resources") or {}
        sv.cpu = _quantity_cpu(res.get("cpu"))
        sv.memory = _quantity_mem(res.get("memory"))
        if i == 0 and (ingress.get("targetPort")):
            sv.ports = [int(ingress["targetPort"])] if str(ingress["targetPort"]).isdigit() else []
            sv.public = bool(ingress.get("external"))
            for extra in ingress.get("additionalPortMappings") or []:
                if str(extra.get("targetPort", "")).isdigit():
                    sv.ports.append(int(extra["targetPort"]))
        for p in c.get("probes") or []:
            if not isinstance(p, dict):
                continue
            hg, tcp = p.get("httpGet") or {}, p.get("tcpSocket") or {}
            if p.get("type", "").lower() in ("readiness", "liveness", "startup") and not sv.health:
                if hg:
                    port = hg.get("port") if str(hg.get("port", "")).isdigit() else (sv.ports[0] if sv.ports else None)
                    sv.health = {"type": "http", "path": hg.get("path") or "/", "port": int(port) if port else None}
                elif tcp:
                    sv.health = {"type": "tcp", "port": tcp.get("port")}
        for vm in c.get("volumeMounts") or []:
            v = vols.get(vm.get("volumeName"), {})
            st = (v.get("storageType") or "EmptyDir").lower()
            sv.volumes.append({"path": str(vm.get("mountPath") or "/data"), "persistent": st in ("azurefile", "nfsazurefile"),
                               "size": "1Gi"})
            if st == "secret":
                sv.volumes.pop()
                for s in v.get("secrets") or [{"secretRef": n} for n in secrets]:
                    nm = s.get("path") or s.get("secretRef")
                    sv.secret_files.append({"name": re.sub(r"[^A-Za-z0-9_.-]", "-", str(s.get("secretRef"))),
                                            "path": f"{vm.get('mountPath', '/mnt/secrets').rstrip('/')}/{nm}"})
        if str(scale.get("minReplicas", "")).isdigit():
            sv.replicas = max(1, int(scale["minReplicas"]))
        if scale.get("rules"):
            sv.notes.append(f"{where}: scale rules ({', '.join(str(r.get('name')) for r in scale['rules'])}) are not "
                            "carried over; add a HorizontalPodAutoscaler or KEDA ScaledObject")
        if conf.get("dapr", {}).get("enabled"):
            sv.notes.append(f"{where}: uses Dapr; install Dapr in the cluster and add its annotations")
        if conf.get("registries"):
            sv.notes.append(f"{where}: pulls from {', '.join(str(r.get('server')) for r in conf['registries'])}; the "
                            "image is rebuilt from the repository or needs an image pull secret")
        trig = conf.get("scheduleTriggerConfig") or {}
        if kind == "job":
            sv.schedule = str(trig.get("cronExpression") or "0 2 * * *")
            if not trig.get("cronExpression"):
                sv.notes.append(f"{where}: a manual or event job; the CronJob schedule is a placeholder")
        sv.backing = bool(BACKING_RE.search(sv.image))
        out.append(sv)
    for ic in tpl.get("initContainers") or []:
        out and out[0].notes.append(f"{rel}: init container {ic.get('name')} is not carried over")
    return out


def _aca_kind(typ: str) -> str | None:
    t = (typ or "").lower()
    if t.startswith("microsoft.app/containerapps"):
        return "app"
    if t.startswith("microsoft.app/jobs"):
        return "job"
    return None


def parse_aca_yaml(root: Path, rel: str, text: str) -> Descriptor:
    d = Descriptor(rel, "azure-container-apps")
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict):
            continue
        kind = _aca_kind(doc.get("type", "")) or ("job" if (doc.get("properties") or {}).get("configuration", {})
                                                   .get("triggerType") else "app")
        name = doc.get("name") or Path(rel).stem
        d.services += _aca_services(str(name), doc.get("properties") or {}, rel, kind)
    return d


def _arm_resources(node) -> list[dict]:
    out = []
    if isinstance(node, dict):
        if _aca_kind(str(node.get("type", ""))) and isinstance(node.get("properties"), dict):
            out.append(node)
        for v in node.values():
            out += _arm_resources(v)
    elif isinstance(node, list):
        for v in node:
            out += _arm_resources(v)
    return out


def _arm_name(n) -> str:
    """ARM names are often expressions: "[parameters('appName')]" -> appName."""
    s = str(n or "app")
    m = re.search(r"(?:parameters|variables)\('([^']+)'\)", s)
    return m.group(1) if m else re.sub(r"[\[\]'()]", "", s).split("/")[-1] or "app"


def parse_arm(root: Path, rel: str, text: str) -> Descriptor:
    d = Descriptor(rel, "azure-container-apps")
    doc = json.loads(text)
    for r in _arm_resources(doc.get("resources") or []):
        d.services += _aca_services(_arm_name(r.get("name")), r["properties"], rel, _aca_kind(r["type"]))
    return d


# Bicep: only the object and array literals of the resource bodies are read; expressions stay as text

_BICEP_TOKEN = re.compile(r"""
    (?P<ws>[ \t\r]+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<nl>\n)
  | (?P<mstring>'''.*?''')
  | (?P<string>'(?:[^'\\]|\\.)*')
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<punct>[{}\[\]:,])
  | (?P<expr>[A-Za-z_][\w.]*\((?:[^()\n]|\([^()\n]*\))*\)(?:\.[\w.]+)?|[^\s{}\[\]:,'()]+)
""", re.X | re.S)


def parse_bicep_object(text: str, start: int) -> tuple[object, int]:
    """Parse the Bicep object or array literal at `start` (an opening brace or bracket)."""
    toks: list[tuple[str, str]] = []
    i = start
    depth = 0
    while i < len(text):
        m = _BICEP_TOKEN.match(text, i)
        if not m:
            raise ValueError(f"bicep: unexpected {text[i:i + 20]!r}")
        k = m.lastgroup
        v = m.group(0)
        i = m.end()
        if k in ("ws", "comment"):
            continue
        if k == "punct" and v in "{[":
            depth += 1
        elif k == "punct" and v in "}]":
            depth -= 1
        toks.append((k, v))
        if depth == 0:
            break
    p = 0

    def nxt():
        nonlocal p
        while p < len(toks) and toks[p][0] == "nl":
            p += 1
        t = toks[p] if p < len(toks) else ("eof", "")
        p += 1
        return t

    def peek():
        j = p
        while j < len(toks) and toks[j][0] == "nl":
            j += 1
        return toks[j] if j < len(toks) else ("eof", "")

    def val():
        t = nxt()
        if t == ("punct", "{"):
            obj = {}
            while peek() != ("punct", "}"):
                k = nxt()
                key = k[1].strip("'")
                if nxt() != ("punct", ":"):
                    raise ValueError(f"bicep: expected : after {key}")
                obj[key] = val()
                if peek() == ("punct", ","):
                    nxt()
            nxt()
            return obj
        if t == ("punct", "["):
            arr = []
            while peek() != ("punct", "]"):
                arr.append(val())
                if peek() == ("punct", ","):
                    nxt()
            nxt()
            return arr
        if t[0] == "string":
            return t[1][1:-1].replace("\\'", "'")
        if t[0] == "mstring":
            return t[1][3:-3]
        if t[0] == "number":
            return float(t[1]) if "." in t[1] else int(t[1])
        if t[0] == "expr":
            return {"true": True, "false": False, "null": None}.get(t[1], "${" + t[1] + "}")
        raise ValueError(f"bicep: unexpected {t[1]!r}")
    return val(), i


BICEP_RESOURCE_RE = re.compile(r"^\s*resource\s+(\w+)\s+'(Microsoft\.App/(?:containerApps|jobs))@[^']*'\s*(?:existing\s*)?=\s*"
                               r"(?:if\s*\([^)]*\)\s*)?\{", re.M | re.I)
BICEP_PARAM_RE = re.compile(r"^\s*(?:param|var)\s+(\w+)\s+(?:\w+\s*)?=\s*'([^'$]*)'", re.M)


def parse_bicep(root: Path, rel: str, text: str) -> Descriptor:
    d = Descriptor(rel, "azure-container-apps")
    params = dict(BICEP_PARAM_RE.findall(text))
    for m in BICEP_RESOURCE_RE.finditer(text):
        body, _ = parse_bicep_object(text, m.end() - 1)
        if not isinstance(body, dict):
            continue
        body = _bicep_resolve(body, params)
        name = body.get("name") if isinstance(body.get("name"), str) and "${" not in body["name"] else m.group(1)
        d.services += _aca_services(str(name), body.get("properties") or {}, rel, _aca_kind(m.group(2)) or "app")
    return d


def _bicep_resolve(node, params: dict):
    if isinstance(node, dict):
        return {k: _bicep_resolve(v, params) for k, v in node.items()}
    if isinstance(node, list):
        return [_bicep_resolve(v, params) for v in node]
    if isinstance(node, str):
        m = re.fullmatch(r"\$\{(\w+)\}", node)
        if m and m.group(1) in params:
            return params[m.group(1)]
        m = re.fullmatch(r"\$\{(?:json|string|int)\('([^']*)'\)\}", node)
        if m:
            return m.group(1)
        return re.sub(r"\$\{(\w+)\}", lambda x: params.get(x.group(1), x.group(0)), node)
    return node


# --------------------------------------------------------------------------- Amazon ECS

def parse_ecs(root: Path, rel: str, text: str) -> Descriptor:
    d = Descriptor(rel, "aws-ecs")
    doc = json.loads(text)
    doc = doc.get("taskDefinition") or doc
    for c in doc.get("containerDefinitions") or []:
        name = str(c.get("name") or doc.get("family") or "app")
        sv = Service(name=name, platform="aws-ecs", source=rel, image=str(c.get("image") or ""))
        sv.command = _split_cmd(c.get("entryPoint"))
        sv.args = _split_cmd(c.get("command"))
        split_env(sv, _env_list(c.get("environment")))
        sv.secrets = sorted(set(sv.secrets) | {str(s["name"]) for s in c.get("secrets") or [] if s.get("name")})
        sv.ports = [int(p["containerPort"]) for p in c.get("portMappings") or [] if str(p.get("containerPort", "")).isdigit()]
        sv.public = bool(sv.ports) and c.get("essential", True)
        if c.get("memory") or c.get("memoryReservation"):
            sv.memory = _quantity_mem(c.get("memory") or c.get("memoryReservation"), "m")
        if c.get("cpu"):
            sv.cpu = f"{max(1, round(int(c['cpu']) * 1000 / 1024))}m"       # ECS: 1024 units to a vCPU
        hc = c.get("healthCheck") or {}
        sv.health = health_from_cmd([str(x) for x in hc.get("command") or []], sv.ports) if hc else None
        if c.get("environmentFiles"):
            sv.notes.append(f"{rel}: container {name}: environmentFiles from S3 are not carried over")
        for mp in c.get("mountPoints") or []:
            sv.volumes.append({"path": str(mp.get("containerPath")), "persistent": True, "size": "1Gi"})
        sv.backing = bool(BACKING_RE.search(sv.image))
        d.services.append(sv)
    return d


# --------------------------------------------------------------------------- finding them

OTHER = [  # (platform, file name pattern, content check): recognised, translated in LLM-heavy mode
    ("fly", re.compile(r"^fly\.toml$"), re.compile(r"^\s*app\s*=", re.M)),
    ("cloud-foundry", re.compile(r"^manifest\.ya?ml$"), re.compile(r"^\s*applications\s*:", re.M)),
    ("app-engine", re.compile(r"^app\.ya?ml$"), re.compile(r"^\s*(runtime|env)\s*:\s*(custom|flex)", re.M)),
    ("render", re.compile(r"^render\.ya?ml$"), re.compile(r"^\s*services\s*:", re.M)),
    ("marathon", re.compile(r"^marathon[\w.-]*\.json$"), re.compile(r'"container"\s*:')),
    ("heroku", re.compile(r"^heroku\.ya?ml$"), re.compile(r"^\s*build\s*:", re.M)),
    ("kamal", re.compile(r"^deploy[\w.-]*\.ya?ml$"), re.compile(r"^\s*servers\s*:", re.M)),
]


def classify(rel: str, text: str) -> str | None:
    """Which parser reads this file: compose, nomad, nomad-json, aca-yaml, arm, bicep, ecs, other:<platform>."""
    name = Path(rel).name.lower()
    if name.endswith((".yml", ".yaml")):
        if COMPOSE_NAME_RE.match(name) and re.search(r"^services\s*:", text, re.M):
            return "compose"
        if re.search(r"(?i)^type\s*:\s*['\"]?Microsoft\.App/(containerApps|jobs)", text, re.M) or (
                re.search(r"^properties\s*:", text, re.M) and re.search(r"^\s+template\s*:", text, re.M)
                and re.search(r"^\s+containers\s*:", text, re.M)):
            return "aca-yaml"
        if re.search(r"^services\s*:", text, re.M) and re.search(r"^\s+(image|build)\s*:", text, re.M) and \
                re.search(r"^version\s*:|^\s+deploy\s*:", text, re.M) and not name.startswith("render."):
            return "compose"
    if name.endswith((".nomad", ".nomad.hcl")) or (name.endswith(".hcl") and re.search(r'^\s*job\s+"[^"]+"\s*\{', text, re.M)):
        return "nomad"
    if name.endswith(".bicep") and re.search(r"'Microsoft\.App/(containerApps|jobs)@", text, re.I):
        return "bicep"
    if name.endswith(".json"):
        if re.search(r'"type"\s*:\s*"Microsoft\.App/(containerApps|jobs)"', text, re.I):
            return "arm"
        if '"containerDefinitions"' in text:
            return "ecs"
        if re.search(r'"Job"\s*:\s*\{', text) and '"TaskGroups"' in text:
            return "nomad-json"
    for platform, fname, content in OTHER:
        if fname.match(name) and content.search(text):
            return f"other:{platform}"
    return None


PARSERS = {"compose": parse_compose, "nomad": parse_nomad, "nomad-json": parse_nomad, "aca-yaml": parse_aca_yaml,
           "arm": parse_arm, "bicep": parse_bicep, "ecs": parse_ecs}
WANTED_EXT = (".yml", ".yaml", ".json", ".hcl", ".nomad", ".bicep", ".toml")


def find_descriptors(root: Path, limit: int = 40) -> list[Descriptor]:
    """Every deployment descriptor in the repository, read into services. Overrides of a compose file
    (docker-compose.override.yml, compose.prod.yaml, ...) are separate descriptors: replatform.py uses
    the most complete one per service."""
    root = Path(root)
    out: list[Descriptor] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(filenames):
            if not f.lower().endswith(WANTED_EXT):
                continue
            p = Path(dirpath, f)
            try:
                if p.stat().st_size > MAX_FILE:
                    continue
                text = p.read_text(errors="replace")
            except OSError:
                continue
            rel = p.relative_to(root).as_posix()
            kind = classify(rel, text)
            if not kind:
                continue
            if kind.startswith("other:"):
                out.append(Descriptor(rel, kind.split(":", 1)[1], parsed=False))
            else:
                try:
                    out.append(PARSERS[kind](root, rel, text))
                except Exception as ex:                    # a broken file must not stop the others
                    d = Descriptor(rel, {"compose": "docker-compose", "nomad": "nomad", "nomad-json": "nomad",
                                         "ecs": "aws-ecs"}.get(kind, "azure-container-apps"), parsed=False)
                    d.error = f"{type(ex).__name__}: {str(ex)[:200]}"
                    out.append(d)
            if len(out) >= limit:
                return out
    return out
