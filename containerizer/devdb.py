"""Development database backups per application, uploaded by operators on the admin pages.

An operator uploads a backup of the application's development database (SQL Server .bak, PostgreSQL
custom-format dump, or a plain / gzipped SQL script for PostgreSQL or MySQL) and writes the
instructions an AI agent needs to point the application at it: which connection string or setting
to use, the database name, test users, anything to run after the restore. The file goes to
CONTAINERIZER_DEV_DB_DIR (a volume shared with the scan worker), never to the database or to git;
the database keeps its name, size, SHA-256, the prompt and who uploaded it, and the audit triggers
record every change.

Uploads are streamed to disk (no size limit in memory), checked for the engine's file signature,
and only accepted from a signed-in admin or operator whose CSRF token comes before the file in the
form. The files are never served back by the web UI.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

CHUNK = 64 * 1024
MAX_FIELD = 64 * 1024
ENGINES = {
    "sqlserver": ("SQL Server", "backup (.bak) made with BACKUP DATABASE ... TO DISK"),
    "postgresql": ("PostgreSQL", "pg_dump custom format (-Fc, .dump) or a plain / gzipped SQL script"),
    "mysql": ("MySQL / MariaDB", "mysqldump SQL script (.sql or .sql.gz)"),
}
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
FILE_RE = re.compile(r"[\w.\- ]{1,200}")
PROMPT_MAX = 8000


class UploadError(Exception):
    """The upload was refused; the message is safe to show to the operator."""


@dataclass
class Settings:
    directory: Path
    max_bytes: int

    @classmethod
    def from_env(cls, env) -> "Settings | None":
        d = (env.get("CONTAINERIZER_DEV_DB_DIR") or "").strip()
        if not d:
            return None
        mb = (env.get("CONTAINERIZER_DEV_DB_MAX_MB") or "2048").strip()
        if not mb.isdigit() or not 1 <= int(mb) <= 1024 * 1024:
            raise ValueError("CONTAINERIZER_DEV_DB_MAX_MB must be a number of megabytes")
        return cls(Path(d), int(mb) * 1024 * 1024)


# --------------------------------------------------------------------------- file checks

def sniff(head: bytes, filename: str) -> str | None:
    """The engine a file's first bytes say it is for, or None. Plain SQL scripts could be either
    PostgreSQL or MySQL: returns "sql" and the operator's choice decides."""
    if head.startswith(b"TAPE"):                       # Microsoft Tape Format: SQL Server native backup
        return "sqlserver"
    if head.startswith(b"PGDMP"):                      # pg_dump custom / directory archive
        return "postgresql"
    data = head
    if head.startswith(b"\x1f\x8b"):
        try:
            data = gzip.decompress(head) if len(head) < 64 else _gunzip_prefix(head)
        except (OSError, EOFError):
            return None
    text = data[:4096].decode("utf-8", "replace").lstrip("﻿").lstrip()
    if re.match(r"(--|/\*|SET |CREATE |INSERT |DROP |USE |BEGIN|START TRANSACTION|\\connect)", text, re.I):
        return "sql"
    return None


def _gunzip_prefix(b: bytes) -> bytes:
    import zlib
    return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(b, 8192)


def check_engine(engine: str, kind: str | None) -> None:
    if engine not in ENGINES:
        raise UploadError("Pick the database engine.")
    if kind is None:
        raise UploadError("That file is not a database backup this tool recognises: a SQL Server .bak, "
                          "a pg_dump custom-format dump, or a SQL script.")
    if kind == "sql" and engine == "sqlserver":
        raise UploadError("For SQL Server upload a native backup (.bak), not a SQL script.")
    if kind not in ("sql", engine):
        raise UploadError(f"The file is a {ENGINES[kind][0]} backup, but {ENGINES[engine][0]} was selected.")


# --------------------------------------------------------------------------- multipart

@dataclass
class Upload:
    fields: dict = field(default_factory=dict)
    filename: str | None = None
    path: Path | None = None          # temporary file in the storage folder
    size: int = 0
    sha256: str = ""
    head: bytes = b""


def parse_multipart(rfile, length: int, ctype: str, tmpdir: Path, max_bytes: int, before_file=None) -> Upload:
    """Stream a multipart/form-data body of `length` bytes. Small fields are kept in memory; the one
    file part goes to a temporary file in `tmpdir`. `before_file(fields)` runs when the file part
    starts, with the fields seen so far, and may raise to refuse it before anything is written."""
    m = re.search(r'boundary="?([^";]{1,200})"?', ctype or "")
    if not ctype.lower().startswith("multipart/form-data") or not m:
        raise UploadError("Send the form as multipart/form-data.")
    if length > max_bytes + 1024 * 1024:
        raise UploadError(f"The file is larger than {max_bytes // (1024 * 1024)} MB.")
    delim = b"\r\n--" + m.group(1).encode("latin-1")
    left = length
    buf = b"\r\n"                                     # so the first boundary looks like the others

    def more() -> bool:
        nonlocal buf, left
        if left <= 0:
            return False
        chunk = rfile.read(min(CHUNK, left))
        if not chunk:
            raise UploadError("The upload was cut off.")
        left -= len(chunk)
        buf += chunk
        return True

    up = Upload()
    # opening boundary
    while delim not in buf[:4096]:
        if len(buf) > 4096 or not more():
            raise UploadError("The form is not valid multipart data.")
    buf = buf[buf.index(delim) + len(delim):]
    try:
        while True:
            while len(buf) < 2 and more():
                pass
            if buf.startswith(b"--"):
                break                                 # closing boundary
            while b"\r\n\r\n" not in buf[:8192]:
                if len(buf) > 8192 or not more():
                    raise UploadError("The form is not valid multipart data.")
            raw, buf = buf.split(b"\r\n\r\n", 1)
            headers = raw.decode("utf-8", "replace")
            name = re.search(r'name="([^"]{1,100})"', headers)
            fname = re.search(r'filename="([^"]{0,400})"', headers)
            if not name:
                raise UploadError("The form is not valid multipart data.")
            if fname is None:                         # an ordinary field
                while delim not in buf[:MAX_FIELD + len(delim)]:
                    if len(buf) > MAX_FIELD + len(delim) or not more():
                        raise UploadError("A form field is too long.")
                value, buf = buf.split(delim, 1)
                up.fields.setdefault(name.group(1), []).append(value.decode("utf-8", "replace"))
                continue
            if up.path is not None:
                raise UploadError("Upload one file at a time.")
            if before_file:
                before_file(up.fields)
            up.filename = os.path.basename(fname.group(1).replace("\\", "/"))
            tmpdir.mkdir(parents=True, exist_ok=True)
            up.path = tmpdir / f".upload-{secrets.token_hex(16)}"
            h = hashlib.sha256()
            fd = os.open(up.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                while True:
                    i = buf.find(delim)
                    if i >= 0:
                        data, buf = buf[:i], buf[i + len(delim):]
                    else:                             # keep a tail that could be the start of the boundary
                        keep = len(delim) - 1
                        data, buf = (buf[:-keep], buf[-keep:]) if len(buf) > keep else (b"", buf)
                    if data:
                        up.size += len(data)
                        if up.size > max_bytes:
                            raise UploadError(f"The file is larger than {max_bytes // (1024 * 1024)} MB.")
                        if len(up.head) < 4096:
                            up.head += data[:4096 - len(up.head)]
                        h.update(data)
                        out.write(data)
                    if i >= 0:
                        break
                    if not more():
                        raise UploadError("The upload was cut off.")
            up.sha256 = h.hexdigest()
    except BaseException:
        if up.path is not None:
            up.path.unlink(missing_ok=True)
        raise
    return up


# --------------------------------------------------------------------------- the stored file

def store(settings: Settings, up: Upload, engine: str) -> str:
    """Move the checked temporary file to its final name (content-addressed) and return that name."""
    ext = {"sqlserver": ".bak", "postgresql": ".dump" if up.head.startswith(b"PGDMP") else ".sql",
           "mysql": ".sql"}[engine]
    if up.head.startswith(b"\x1f\x8b"):
        ext += ".gz"
    name = f"{up.sha256}{ext}"
    final = settings.directory / name
    os.replace(up.path, final)
    os.chmod(final, 0o600)
    return name


def remove_unused(settings: Settings, conn, name: str | None) -> None:
    """Delete a stored file no application refers to any more (several may share one by content)."""
    if not name or not re.fullmatch(r"[0-9a-f]{64}\.[a-z.]{3,8}", name):
        return
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cz.DevDatabase WHERE StoredAs = %s", (name,))
    if cur.fetchone()[0] == 0:
        (settings.directory / name).unlink(missing_ok=True)


# --------------------------------------------------------------------------- the AI prompt

def default_prompt(app: dict, engine: str, dbname: str) -> str:
    """A starting point for the operator's instructions; they edit it before saving."""
    eng = ENGINES.get(engine, ("the database",))[0]
    return (f"The development database of {app.get('DisplayName') or app.get('Name')} is a {eng} database named "
            f"{dbname or '<name>'}, restored from the uploaded backup.\n"
            "Configure the application to use it:\n"
            "- Connection string / setting to set: <e.g. ConnectionStrings:Default>\n"
            "- Read the connection string from an environment variable or secret, never from a committed file.\n"
            "- Test users or API keys in this database: <none / where to find them>\n"
            "- Anything to run after the restore (migrations, seed scripts): <none>\n")


def human_size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


# --------------------------------------------------------------------------- the sandbox database
#
# For an application with an uploaded backup, the scan worker builds a database image that restores
# the backup when it starts (pushed next to the application's images), and the generated manifests
# get a `devdb` Deployment + Service in the application's namespace. Passwords never touch Git:
# External Secrets Operator's Password generator creates them in the cluster (secrets.mode
# external-secrets), otherwise the platform team creates the two Secrets. The application's
# containers get the connection settings as environment variables that reference the password with
# Kubernetes' $(VAR) expansion; which settings to set comes from the LLM, reading the operator's
# prompt and the component's configuration, or from the connection strings the scan found.

PORTS = {"sqlserver": 1433, "postgresql": 5432, "mysql": 3306}
UIDS = {"sqlserver": 10001, "postgresql": 999, "mysql": 999}
WRITABLE = {"sqlserver": ["/var/opt/mssql", "/tmp"],
            "postgresql": ["/var/lib/postgresql/data", "/var/run/postgresql", "/tmp"],
            "mysql": ["/var/lib/mysql", "/var/run/mysqld", "/tmp"]}
MEMORY = {"sqlserver": ("2Gi", "3Gi"), "postgresql": ("256Mi", "1Gi"), "mysql": ("512Mi", "1Gi")}
APP_USER = "app"
PASSWORD_ENV = "CZ_DEVDB_PASSWORD"
SECRET, ADMIN_SECRET = "devdb", "devdb-admin"
HOST = "devdb"
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,199}")
PLACEHOLDERS = ("host", "port", "database", "user", "password")
CONNECTION = {
    "sqlserver": "Server={host},{port};Database={database};User Id={user};Password={password};Encrypt=True;TrustServerCertificate=True",
    "postgresql": "Host={host};Port={port};Database={database};Username={user};Password={password}",
    "mysql": "Server={host};Port={port};Database={database};User ID={user};Password={password}",
}


@dataclass
class SandboxDb:
    """What generate_app needs to add the database to an application's manifests."""
    engine: str
    database: str
    image: str                                         # <registry>/<app>/devdb:<tag>
    env: dict = field(default_factory=dict)            # component name -> [{"name", "value"}] (templates)
    source: str = "default"                            # "ai" or "default": who chose the settings
    notes: list = field(default_factory=list)


def base_image(engine: str) -> str:
    from .generate import images
    return (images().get("devdb") or {}).get(engine) or {
        "sqlserver": "mcr.microsoft.com/mssql/server:2022-latest",
        "postgresql": "postgres:16-bookworm", "mysql": "mysql:8.4"}[engine]


def build_context(stored: Path, engine: str, database: str, ctx: Path) -> Path:
    """A docker build context that bakes the backup into the engine's image, restored at first start."""
    if not NAME_RE.fullmatch(database):
        raise ValueError(f"invalid database name {database!r}")
    ctx.mkdir(parents=True, exist_ok=True)
    name = stored.name
    ext = name.split(".", 1)[1]
    target = ctx / f"backup.{ext}"
    try:
        os.link(stored, target)                        # no copy of a multi-GB file when on the same disk
    except OSError:
        import shutil
        shutil.copyfile(stored, target)
    lines = [f"FROM {base_image(engine)}", f"LABEL org.opencontainers.image.description=\"containerizer dev database {database}\""]
    if engine == "sqlserver":
        (ctx / "start.sh").write_text(SQLSERVER_START)
        lines += [f"COPY --chown=10001:0 backup.{ext} /devdb/backup.bak", "COPY --chown=10001:0 --chmod=0555 start.sh /devdb/start.sh",
                  f"ENV DEVDB_NAME={database} ACCEPT_EULA=Y MSSQL_PID=Developer", "USER 10001",
                  'ENTRYPOINT ["/bin/bash", "/devdb/start.sh"]']
    elif engine == "postgresql" and ext == "dump":
        (ctx / "10-restore.sh").write_text(POSTGRES_RESTORE)
        lines += ["COPY --chown=999:999 backup.dump /devdb/backup.dump",
                  "COPY --chown=999:999 --chmod=0555 10-restore.sh /docker-entrypoint-initdb.d/10-restore.sh",
                  f"ENV POSTGRES_DB={database} POSTGRES_USER={APP_USER}", "USER 999"]
    elif engine == "postgresql":
        lines += [f"COPY --chown=999:999 backup.{ext} /docker-entrypoint-initdb.d/10-backup.{ext}",
                  f"ENV POSTGRES_DB={database} POSTGRES_USER={APP_USER}", "USER 999"]
    else:
        lines += [f"COPY --chown=999:999 backup.{ext} /docker-entrypoint-initdb.d/10-backup.{ext}",
                  f"ENV MYSQL_DATABASE={database} MYSQL_USER={APP_USER}", "USER 999"]
    (ctx / "Dockerfile").write_text("\n".join(lines) + "\n")
    (ctx / ".dockerignore").write_text("*\n!Dockerfile\n!backup.*\n!start.sh\n!10-restore.sh\n")
    return ctx


# SQL Server: start the server, restore once (moving every file into the data volume), add the app's
# login as db_owner of the restored database, then stay in the foreground with the server.
SQLSERVER_START = r"""#!/bin/bash
set -euo pipefail
export MSSQL_SA_PASSWORD="${DEVDB_ADMIN_PASSWORD:?}"
/opt/mssql/bin/sqlservr &
pid=$!
sq() { /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -b -h -1 -W "$@"; }
for _ in $(seq 1 120); do sq -Q "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
if [ "$(sq -Q "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.databases WHERE name = N'${DEVDB_NAME}'")" = "0" ]; then
  echo "devdb: restoring ${DEVDB_NAME}"
  moves=$(sq -s '|' -Q "RESTORE FILELISTONLY FROM DISK = N'/devdb/backup.bak'" | \
    awk -F'|' -v db="${DEVDB_NAME}" 'NF > 3 && ($3 == "D" || $3 == "L" || $3 == "F" || $3 == "S") {
      ext = ($3 == "L") ? "ldf" : "mdf"; gsub(/'"'"'/, "'"'"''"'"'", $1);
      printf "MOVE N'"'"'%s'"'"' TO N'"'"'/var/opt/mssql/data/%s_%d.%s'"'"', ", $1, db, NR, ext }')
  sq -Q "RESTORE DATABASE [${DEVDB_NAME}] FROM DISK = N'/devdb/backup.bak' WITH ${moves} REPLACE, RECOVERY"
fi
sq -Q "IF SUSER_ID(N'app') IS NULL CREATE LOGIN [app] WITH PASSWORD = N'$(printf %s "${DEVDB_PASSWORD:?}" | sed "s/'/''/g")', CHECK_POLICY = OFF;
USE [${DEVDB_NAME}];
IF USER_ID(N'app') IS NULL CREATE USER [app] FOR LOGIN [app] ELSE ALTER USER [app] WITH LOGIN = [app];
ALTER ROLE db_owner ADD MEMBER [app];"
touch /tmp/devdb-ready
echo "devdb: ${DEVDB_NAME} is ready"
wait "$pid"
"""

POSTGRES_RESTORE = """#!/bin/sh
set -eu
echo "devdb: restoring $POSTGRES_DB"
pg_restore --no-owner --no-privileges --exit-on-error --role="$POSTGRES_USER" -U "$POSTGRES_USER" -d "$POSTGRES_DB" /devdb/backup.dump
"""


def secret_docs(labels: dict) -> list[dict]:
    """The two passwords, generated in the cluster by External Secrets Operator (secrets.mode
    external-secrets); an empty list in the other modes, where the platform team creates them."""
    from .harden import security
    if security()["secrets"].get("mode") != "external-secrets":
        return []
    docs = []
    for name in (SECRET, ADMIN_SECRET):
        docs += [{"apiVersion": "generators.external-secrets.io/v1alpha1", "kind": "Password",
                  "metadata": {"name": name, "labels": labels},
                  # letters and digits only: no character that needs escaping in a connection string
                  "spec": {"length": 32, "digits": 6, "symbols": 0, "noUpper": False, "allowRepeat": True}},
                 {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
                  "metadata": {"name": name, "labels": labels},
                  "spec": {"refreshInterval": "0",          # generated once, never rotated under the running database
                           "target": {"name": name, "creationPolicy": "Owner", "deletionPolicy": "Delete"},
                           "dataFrom": [{"sourceRef": {"generatorRef": {
                               "apiVersion": "generators.external-secrets.io/v1alpha1", "kind": "Password", "name": name}}}]}}]
    return docs


def manifests(app: str, db: SandboxDb) -> list[dict]:
    """Deployment, Service, NetworkPolicy and the password secrets of the sandbox database."""
    from .harden import harden_pod, service_account, security
    eng = db.engine
    port, uid = PORTS[eng], UIDS[eng]
    labels = {"app.kubernetes.io/name": HOST, "app.kubernetes.io/part-of": app,
              "app.kubernetes.io/component": "database", "app.kubernetes.io/managed-by": "containerizer"}

    def pw(secret: str) -> dict:
        return {"valueFrom": {"secretKeyRef": {"name": secret, "key": "password"}}}
    env = {"sqlserver": [{"name": "DEVDB_ADMIN_PASSWORD", **pw(ADMIN_SECRET)}, {"name": "DEVDB_PASSWORD", **pw(SECRET)}],
           "postgresql": [{"name": "POSTGRES_PASSWORD", **pw(SECRET)}, {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"}],
           "mysql": [{"name": "MYSQL_ROOT_PASSWORD", **pw(ADMIN_SECRET)}, {"name": "MYSQL_PASSWORD", **pw(SECRET)}]}[eng]
    ready = {"sqlserver": ["/bin/sh", "-c", "test -f /tmp/devdb-ready"],
             "postgresql": ["/bin/sh", "-c", f"pg_isready -h 127.0.0.1 -U {APP_USER} -d {db.database}"],
             "mysql": ["/bin/sh", "-c", 'mysqladmin ping -h 127.0.0.1 -u app -p"$MYSQL_PASSWORD" --silent']}[eng]
    req, lim = MEMORY[eng]
    volumes, mounts = [], []
    for i, path in enumerate(WRITABLE[eng]):
        volumes.append({"name": f"w{i}", "emptyDir": {"sizeLimit": "4Gi" if i == 0 else "256Mi"}})
        mounts.append({"name": f"w{i}", "mountPath": path})
    container = {"name": HOST, "image": db.image, "imagePullPolicy": "IfNotPresent", "env": env,
                 "ports": [{"name": "db", "containerPort": port}],
                 "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 10, "timeoutSeconds": 5},
                 "startupProbe": {"tcpSocket": {"port": "db"}, "periodSeconds": 10, "failureThreshold": 60},
                 "resources": {"requests": {"cpu": "250m", "memory": req, "ephemeral-storage": "64Mi"},
                               "limits": {"memory": lim, "ephemeral-storage": "1Gi"}},
                 "volumeMounts": mounts}
    pod = {"containers": [container], "volumes": volumes}
    meta = {"labels": dict(labels), "annotations": {"containerizer.io/devdb": f"{eng}:{db.database}"}}
    harden_pod(meta, pod, uid, HOST, [])
    pod["serviceAccountName"] = HOST
    pod["automountServiceAccountToken"] = False
    deploy = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": HOST, "labels": labels},
              "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": labels},
                       "template": {"metadata": meta, "spec": pod}}}
    dns = security()["network"]["dns"]
    siblings = [{"podSelector": {"matchLabels": {"app.kubernetes.io/part-of": app}}}]
    policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
              "metadata": {"name": HOST, "labels": labels, "annotations": {"containerizer.io/egress": "none"}},
              "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"],
                       # only the application's own pods reach the database; it reaches nothing but DNS
                       "ingress": [{"from": siblings, "ports": [{"port": port, "protocol": "TCP"}]}],
                       "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": dns["namespace"]}},
                                           "podSelector": {"matchLabels": dns["pod_labels"]}}],
                                   "ports": [dict(p) for p in dns["ports"]]}]}}
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": HOST, "labels": labels},
               "spec": {"selector": labels, "ports": [{"name": "db", "port": port, "targetPort": "db"}]}}
    return [service_account(HOST, labels, False), deploy, service, policy] + secret_docs(labels)


def render_env(db: SandboxDb, template: list[dict]) -> list[dict]:
    """Environment entries for a component: the password first, then the settings with the
    placeholders filled in ({password} becomes the $(CZ_DEVDB_PASSWORD) reference)."""
    vals = {"host": HOST, "port": str(PORTS[db.engine]), "database": db.database, "user": APP_USER,
            "password": f"$({PASSWORD_ENV})"}
    out = [{"name": PASSWORD_ENV, "valueFrom": {"secretKeyRef": {"name": SECRET, "key": "password"}}}]
    for e in template:
        v = e["value"]
        for k, rep in vals.items():
            v = v.replace("{" + k + "}", rep)
        out.append({"name": e["name"], "value": v})
    return out


def inject(docs: list[dict], db: SandboxDb, component: str) -> None:
    """Set the component's connection settings in its workloads (replacing any secret reference
    with the same name), keeping $(VAR) order: the password variable comes first."""
    template = db.env.get(component)
    if not template:
        return
    entries = render_env(db, template)
    names = {e["name"] for e in entries}
    for d in docs:
        tpl = ((d.get("spec") or {}).get("template") or {}).get("spec")
        if d.get("kind") not in ("Deployment", "StatefulSet") or not tpl:
            continue
        for c in tpl.get("containers") or []:
            rest = [e for e in c.get("env") or [] if e["name"] not in names]
            c["env"] = entries[:1] + rest + entries[1:]


def default_env(engine: str, keys: list[str]) -> list[dict]:
    """Without the LLM: every connection string the scan found points at the sandbox database
    (ConnectionStrings__DefaultConnection when it found none)."""
    keys = keys or ["DefaultConnection"]
    return [{"name": f"ConnectionStrings__{k.replace(':', '__')}", "value": CONNECTION[engine]} for k in keys]


AI_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["components", "notes"],
    "properties": {
        "components": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["component", "env"],
            "properties": {"component": {"type": "string"},
                           "env": {"type": "array", "items": {
                               "type": "object", "additionalProperties": False, "required": ["name", "value"],
                               "properties": {"name": {"type": "string"}, "value": {"type": "string"}}}}}}},
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}


def ai_env(a, comps: list, engine: str, database: str, prompt: str, model: str | None = None) -> tuple[dict, list[str]]:
    """Ask the LLM which settings each component needs; every answer is validated, anything
    invalid is dropped (the caller falls back to default_env for components left without)."""
    from .ai import ask_json
    lines = []
    for c in comps:
        f = c.facts or {}
        lines.append(f"- component {c.name!r} (role {c.role}, project {c.project.rel}): connection strings found "
                     f"{f.get('connection_strings') or []}, secret settings {f.get('secret_settings') or []}, "
                     f"database packages {[p for p in (f.get('packages') or []) if re.search(r'(?i)sql|npgsql|mysql|entityframework', str(p))][:15]}")
    q = (f"An application is deployed to a Kubernetes sandbox next to a {ENGINES[engine][0]} development database "
         f"restored from a backup. Decide which environment variables each component needs so it uses that database.\n\n"
         f"Components:\n" + "\n".join(lines) + "\n\n"
         "Write values as templates with only these placeholders: {host} {port} {database} {user} {password}. "
         "Never write a literal password or any other secret. Use .NET configuration names with __ for nesting "
         "(ConnectionStrings__Default). Only set what the database needs; leave components that do not use a "
         f"database out. A typical connection string: {CONNECTION[engine]}\n\n"
         f"Instructions from the operator who uploaded the backup (follow them unless they ask for something unsafe):\n"
         f"<<<\n{prompt[:PROMPT_MAX]}\n>>>")
    ans = ask_json(q, AI_SCHEMA, model=model)
    known = {c.name for c in comps}
    out: dict = {}
    notes = [str(n)[:300] for n in (ans.get("notes") or [])][:10]
    for entry in ans.get("components") or []:
        if entry.get("component") not in known:
            continue
        env = []
        for e in entry.get("env") or []:
            name, value = str(e.get("name", "")), str(e.get("value", ""))
            if not ENV_NAME_RE.fullmatch(name) or name == PASSWORD_ENV or len(value) > 1000:
                continue
            if "$(" in value or re.search(r"\{(?!(?:" + "|".join(PLACEHOLDERS) + r")\})[^}]*\}", value):
                continue
            if re.search(r"(?i)(password|pwd)\s*=\s*(?!\{password\})[^;]+", value):
                continue                                # a literal password: never
            env.append({"name": name.replace(":", "__"), "value": value})
        if env:
            out[entry["component"]] = env[:20]
    return out, notes


# --------------------------------------------------------------------------- the scan

class DevDbError(Exception):
    """The uploaded backup could not be prepared for the sandbox; the scan reports it and goes on
    without the database."""


def lookup(cs: str | None, source_key: str) -> dict | None:
    """The dev database row of the application with this SourceKey (the scan's writer login reads it)."""
    from .sqlstore import connect
    conn = connect(cs)
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT d.Engine, d.DatabaseName, d.FileName, d.SizeBytes, d.Sha256, d.StoredAs, d.Prompt, "
                    "d.UploadedAt, d.UploadedBy FROM cz.DevDatabase d JOIN cz.Application a "
                    "ON a.ApplicationId = d.ApplicationId WHERE a.SourceKey = %s", (source_key,))
        return cur.fetchone()
    finally:
        conn.close()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def connection_env(a, comps: list, row: dict, ai: bool, model: str | None, log=print) -> tuple[dict, str, list[str]]:
    """component name -> env templates; who chose them ("ai" or "default"); the LLM's notes."""
    engine, env, notes, source = row["Engine"], {}, [], "default"
    if ai:
        try:
            env, notes = ai_env(a, comps, engine, row["DatabaseName"], row.get("Prompt") or "", model)
            source = "ai" if env else "default"
        except Exception as ex:                          # the LLM is optional: fall back to the scan's findings
            log(f"  dev database: the LLM gave no usable settings ({str(ex)[:200]}); using the connection strings found")
    found = {c.name: (c.facts or {}).get("connection_strings") or [] for c in comps}
    for c in comps:
        if c.name not in env and (found[c.name] or not any(found.values())):
            env[c.name] = default_env(engine, found[c.name])
    return env, source, notes


def prepare(row: dict, a, comps: list, settings: Settings, image: str, local: str, work: Path,
            ai: bool = False, model: str | None = None, timeout: int = 3600, log=print) -> SandboxDb:
    """Build the database image (the backup restored at its first start) as `local` and decide the
    application's settings. Pushing `local` to `image` is the caller's."""
    import subprocess
    stored = settings.directory / row["StoredAs"]
    if not re.fullmatch(r"[0-9a-f]{64}\.[a-z.]{3,8}", row["StoredAs"]) or not stored.is_file():
        raise DevDbError(f"the uploaded file {row['FileName']} is missing from CONTAINERIZER_DEV_DB_DIR")
    if _sha256(stored) != row["Sha256"]:
        raise DevDbError(f"the uploaded file {row['FileName']} does not match its SHA-256 (changed on disk)")
    ctx = work / "devdb-build"
    if ctx.exists():
        import shutil
        shutil.rmtree(ctx)
    build_context(stored, row["Engine"], row["DatabaseName"], ctx)
    p = subprocess.run(["docker", "build", "--progress=plain", "-t", local, str(ctx)], capture_output=True, text=True,
                       timeout=timeout, errors="replace")
    if p.returncode != 0:
        raise DevDbError(f"building the database image failed: {(p.stderr or p.stdout)[-400:]}")
    env, source, notes = connection_env(a, comps, row, ai, model, log)
    return SandboxDb(engine=row["Engine"], database=row["DatabaseName"], image=image, env=env, source=source, notes=notes)


def readme(app: str, db: SandboxDb, row: dict) -> str:
    """devdb/README.md in the generated folder: what runs, how the application reaches it."""
    eng = ENGINES[db.engine][0]
    lines = [f"# Dev database of {app}", "",
             f"A {eng} database `{db.database}` restored from `{row['FileName']}` (SHA-256 `{row['Sha256']}`), "
             f"uploaded by {row['UploadedBy']} on {str(row['UploadedAt'])[:16]}. It runs as the `{HOST}` Deployment "
             f"next to the application, from the image `{db.image}`, and is restored again whenever its pod starts "
             "(nothing is kept on a volume: it is a disposable copy for testing).", "",
             f"- Reached at `{HOST}:{PORTS[db.engine]}` by the application's own pods only (NetworkPolicy `{HOST}`).",
             f"- The application signs in as `{APP_USER}`; the password is in the Secret `{SECRET}` (key `password`), "
             f"the {('sa' if db.engine == 'sqlserver' else 'root')} password in `{ADMIN_SECRET}`"
             + (" (PostgreSQL: the application user is the database owner)" if db.engine == "postgresql" else "") + ".",
             "- With External Secrets Operator (secrets.mode external-secrets) both are generated in the cluster by "
             "its Password generator and never rotated; otherwise create them before the sync:",
             "", "      kubectl -n <namespace> create secret generic devdb --from-literal=password=<random>",
             "      kubectl -n <namespace> create secret generic devdb-admin --from-literal=password=<random>", "",
             f"## Settings given to the application ({'chosen by the AI from the operator instructions' if db.source == 'ai' else 'the connection strings the scan found'})",
             ""]
    for comp, env in sorted(db.env.items()):
        lines.append(f"- **{comp}**: " + ", ".join(f"`{e['name']}`" for e in env))
    if not db.env:
        lines.append("- none: no component reads a connection string the scan could find")
    if db.notes:
        lines += ["", "Notes from the AI:", ""] + [f"- {n}" for n in db.notes]
    if row.get("Prompt"):
        lines += ["", "## Operator instructions", "", "```text", row["Prompt"].replace("```", "'''"), "```"]
    return "\n".join(lines) + "\n"
