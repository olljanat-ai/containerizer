"""Write assessment results to Microsoft SQL Server (schema in sql/schema.sql).

The connection string uses the familiar ADO.NET/ODBC keys and is read from --sql or CONTAINERIZER_SQL:

    Server=tcp:sql.example.com,1433;Database=Containerizer;User Id=cz_scanner;Encrypt=yes;Schema=containerizer

The password comes from CONTAINERIZER_SQL_PASSWORD (preferred: it keeps it out of the process list and
shell history) or from Password= in the string. Like Microsoft's ODBC Driver 18, the connection is
encrypted and the server certificate is validated against the system CAs by default;
TrustServerCertificate=yes skips that check (local development only), Encrypt=no turns TLS off.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = Path(__file__).resolve().parent / "sql" / "schema.sql"
SCHEMA_FILES = [SCHEMA, SCHEMA.parent / "sbom.sql"]          # applied in this order by `db init`
SEV_RANK = {"info": 0, "config": 1, "refactor": 2, "rewrite": 3, "blocker": 4}
_TRUE = {"yes", "true", "1", "mandatory", "strict"}
_FALSE = {"no", "false", "0", "optional"}


class SqlError(Exception):
    pass


# ---------------------------------------------------------------------------
# connection

def parse_connection_string(cs: str) -> dict:
    """`Key=Value;...` -> dict with lower-case keys without spaces; values may be {braced}."""
    out, i = {}, 0
    while i < len(cs):
        j = cs.find("=", i)
        if j < 0:
            if cs[i:].strip():
                raise SqlError(f"connection string: expected Key=Value near {cs[i:i + 20]!r}")
            break
        key = re.sub(r"\s+", "", cs[i:j]).lower()
        j += 1
        while j < len(cs) and cs[j] == " ":
            j += 1
        if j < len(cs) and cs[j] == "{":
            k = j + 1
            val = []
            while k < len(cs):
                if cs[k] == "}":
                    if cs[k + 1:k + 2] == "}":
                        val.append("}")
                        k += 2
                        continue
                    break
                val.append(cs[k])
                k += 1
            value, i = "".join(val), cs.find(";", k) + 1 or len(cs)
        else:
            k = cs.find(";", j)
            value, i = (cs[j:] if k < 0 else cs[j:k]).strip(), (len(cs) if k < 0 else k + 1)
        if key:
            out[key] = value
    return out


def _pick(d: dict, *keys: str, default=None):
    for k in keys:
        if k in d and d[k] != "":
            return d[k]
    return default


def connect_args(cs: str, password: str | None = None) -> dict:
    """pymssql.connect() keyword arguments plus `_ca` (CA file or None when not validating)."""
    d = parse_connection_string(cs)
    server = _pick(d, "server", "datasource", "address", "addr", "networkaddress")
    if not server:
        raise SqlError("connection string has no Server=")
    server = re.sub(r"^tcp:", "", server, flags=re.I)
    host, _, port = server.partition(",")
    if "\\" in host:
        raise SqlError("named instances (host\\instance) are not supported; give the port: Server=host,1433")
    database = _pick(d, "database", "initialcatalog")
    if not database:
        raise SqlError("connection string has no Database=")
    user = _pick(d, "userid", "uid", "user", "username")
    if not user:
        raise SqlError("connection string has no User Id= (SQL authentication is required)")
    pwd = password if password is not None else os.environ.get("CONTAINERIZER_SQL_PASSWORD") or _pick(d, "password", "pwd")
    if not pwd:
        raise SqlError("no password: set CONTAINERIZER_SQL_PASSWORD (or Password= in the connection string)")
    encrypt = str(_pick(d, "encrypt", default="yes")).lower()
    trust = str(_pick(d, "trustservercertificate", default="no")).lower()
    if encrypt not in _TRUE | _FALSE or trust not in _TRUE | _FALSE:
        raise SqlError("Encrypt= and TrustServerCertificate= take yes or no")
    ca = None
    if encrypt in _TRUE and trust not in _TRUE:
        ca = _pick(d, "cafile", "servercertificate", default="system")
    return {"server": host.strip(), "port": (port.strip() or "1433"), "user": user, "password": pwd,
            "database": database, "encryption": "require" if encrypt in _TRUE else "off",
            "login_timeout": int(_pick(d, "connecttimeout", "connectiontimeout", "logintimeout", default="30")),
            "appname": _pick(d, "applicationname", "app", default="containerizer"), "_ca": ca,
            "_schema": schema_name(_pick(d, "schema"))}


DEFAULT_SCHEMA = "containerizer"


def schema_name(name: str | None = None) -> str:
    """The dedicated schema: Schema= in the connection string, CONTAINERIZER_SQL_SCHEMA, or "containerizer"."""
    name = name or os.environ.get("CONTAINERIZER_SQL_SCHEMA") or DEFAULT_SCHEMA
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) or name.lower() in ("dbo", "sys", "guest", "information_schema"):
        raise SqlError(f"schema must be a plain identifier other than dbo/sys: {name!r}")
    return name


_CZ = re.compile(r"(?<![\w\]\.])cz\.(?=[A-Za-z])")


class Connection:
    """pymssql connection whose queries name tables `cz.X`; `cz.` becomes the configured schema."""

    def __init__(self, conn, schema: str):
        self._conn, self.schema = conn, schema

    def sql(self, text: str) -> str:
        return _CZ.sub(f"[{self.schema}].", text)

    def cursor(self, as_dict: bool = False):
        return _Cursor(self._conn.cursor(as_dict=as_dict), self)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def set_user(self, user: str, name: str | None = None, via: str = "admin UI", role: str | None = None) -> None:
        """Who the audit log names for changes on this connection, and in which role (read-only for its lifetime)."""
        cur = self._conn.cursor()
        if role:
            cur.execute("EXEC sp_set_session_context @key = N'containerizer.role', @value = %s, @read_only = 1", (role[:40],))
        cur.execute("EXEC sp_set_session_context @key = N'containerizer.via', @value = %s, @read_only = 1", (via[:20],))
        cur.execute("EXEC sp_set_session_context @key = N'containerizer.user', @value = %s, @read_only = 1", (user[:256],))
        if name:
            cur.execute("EXEC sp_set_session_context @key = N'containerizer.user_name', @value = %s, @read_only = 1",
                        (name[:256],))


class _Cursor:
    def __init__(self, cur, conn: Connection):
        self._cur, self._conn = cur, conn

    def execute(self, sql: str, params=None):
        return self._cur.execute(self._conn.sql(sql), params) if params is not None else self._cur.execute(self._conn.sql(sql))

    def executemany(self, sql: str, rows: list):
        return self._cur.executemany(self._conn.sql(sql), rows)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    @property
    def rowcount(self):
        return self._cur.rowcount


_CONF: dict = {}


def _freetds_conf(ca: str | None) -> str:
    """FreeTDS (the TDS library inside pymssql) validates the certificate only when a CA file is set."""
    if ca in _CONF:
        return _CONF[ca]
    d = Path(tempfile.mkdtemp(prefix="cz-tds-"))
    lines = ["[global]", "\ttds version = 7.4"]
    if ca:
        lines += [f"\tca file = {ca}", "\tcheck certificate hostname = yes"]
    (d / "freetds.conf").write_text("\n".join(lines) + "\n")
    _CONF[ca] = str(d / "freetds.conf")
    return _CONF[ca]


def connect(cs: str | None = None, password: str | None = None, autocommit: bool = False):
    cs = cs or os.environ.get("CONTAINERIZER_SQL")
    if not cs:
        raise SqlError("no connection string: pass --sql or set CONTAINERIZER_SQL")
    try:
        import pymssql
    except ImportError as e:
        raise SqlError("the SQL Server output needs pymssql: pip install -r requirements-sql.txt") from e
    args = connect_args(cs, password)
    ca = args.pop("_ca")
    schema = args.pop("_schema")
    os.environ["FREETDSCONF"] = _freetds_conf(ca)
    try:
        return Connection(pymssql.connect(autocommit=autocommit, **args), schema)
    except pymssql.Error as e:
        hint = " (is the server certificate trusted? set CaFile= to its CA, or TrustServerCertificate=yes for local development only)" if ca else ""
        raise SqlError(f"cannot connect to {args['server']},{args['port']} database {args['database']}{hint}: "
                       f"{_err(e)}") from None


def _err(e) -> str:
    a = getattr(e, "args", ())
    m = a[1] if len(a) > 1 else (a[0] if a else e)
    return (m.decode(errors="replace") if isinstance(m, bytes) else str(m)).strip().splitlines()[-1]


# ---------------------------------------------------------------------------
# schema

def schema_batches(schema: str = DEFAULT_SCHEMA, text: str | None = None) -> list[str]:
    from string import Template
    if text is None:
        text = "\nGO\n".join(f.read_text() for f in SCHEMA_FILES)
    text = Template(text).substitute(schema=schema_name(schema))
    return [b.strip() for b in re.split(r"^\s*GO\s*$", text, flags=re.M | re.I) if b.strip()]


def init_schema(conn) -> None:
    cur = conn._conn.cursor()          # the schema script names its schema itself
    for b in schema_batches(conn.schema):
        cur.execute(b)
    conn.commit()


# ---------------------------------------------------------------------------
# what is written

def effective_severity(f: dict) -> str:
    """The severity a finding counts with for its component (mirrors assess.Finding.severity)."""
    if f.get("dormant"):
        return "info"
    if f.get("only_commands") and f["severity"] in ("blocker", "rewrite"):
        return "refactor"
    return f["severity"]


def _git(path: Path, *args: str) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=path, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def clean_remote(url: str) -> str:
    """https form of a git remote without credentials: git@h:o/r.git and https://user:token@h/o/r -> https://h/o/r."""
    url = url.strip()
    m = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url)
    if m:
        url = f"https://{m[1]}/{m[2]}"
    url = re.sub(r"^ssh://(?:[^@/]+@)?([^/:]+)(?::\d+)?/", r"https://\1/", url)
    url = re.sub(r"^(https?://)[^@/]+@", r"\1", url)
    return re.sub(r"\.git$", "", url.rstrip("/"))


def source_info(path: Path, name: str) -> dict:
    """Stable identity of an app: git remote + folder in the repository, else the app name."""
    path = Path(path).resolve()
    top = _git(path, "rev-parse", "--show-toplevel")
    if not top:
        return {"key": name, "repository_url": None, "path": None, "commit": None, "branch": None}
    rel = path.relative_to(Path(top).resolve()).as_posix() if path != Path(top).resolve() else ""
    remote = clean_remote(_git(path, "remote", "get-url", "origin")) or None
    branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("BUILD_SOURCEBRANCHNAME") \
        or _git(path, "rev-parse", "--abbrev-ref", "HEAD") or None
    return {"key": f"{remote}#{rel}" if remote else name, "repository_url": remote, "path": rel or ".",
            "commit": _git(path, "rev-parse", "HEAD") or None, "branch": None if branch == "HEAD" else branch}


def tool_version() -> str | None:
    return _git(Path(__file__).resolve().parent, "rev-parse", "--short=12", "HEAD") or None


def _cut(s, n: int):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def store_assessment(conn, doc: dict, source: dict, assessed_at=None, sboms: dict | None = None) -> int:
    """Insert one application's assessment (an assessment.json entry); returns the AssessmentId.

    The application and its components are created or matched automatically (by source key and by
    project path); people-maintained columns (ProductId, DisplayName, Owner, ...) are never written."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT ApplicationId FROM cz.Application WITH (UPDLOCK, HOLDLOCK) WHERE SourceKey = %s",
                    (_cut(source["key"], 400),))
        row = cur.fetchone()
        if row:
            app_id = row[0]
            cur.execute("UPDATE cz.Application SET Name = %s, RepositoryUrl = %s, SourcePath = %s, "
                        "LastSeenAt = SYSUTCDATETIME() WHERE ApplicationId = %s",
                        (_cut(doc["name"], 200), _cut(source.get("repository_url"), 400),
                         _cut(source.get("path"), 400), app_id))
        else:
            # SCOPE_IDENTITY, not OUTPUT: the audit trigger on Application rules out a bare OUTPUT clause
            cur.execute("INSERT cz.Application (SourceKey, Name, RepositoryUrl, SourcePath) "
                        "VALUES (%s, %s, %s, %s); SELECT CAST(SCOPE_IDENTITY() AS int)",
                        (_cut(source["key"], 400), _cut(doc["name"], 200), _cut(source.get("repository_url"), 400),
                         _cut(source.get("path"), 400)))
            app_id = cur.fetchone()[0]

        ver = {r.get("component"): r for r in doc.get("verification") or []}
        cur.execute("INSERT cz.ApplicationAssessment (ApplicationId, AssessedAt, Rating, Score, Confidence, "
                    "Summary, Verified, SourceCommit, SourceBranch, ToolVersion, ReportJson) OUTPUT INSERTED.AssessmentId "
                    "VALUES (%s, COALESCE(%s, SYSUTCDATETIME()), %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (app_id, assessed_at, doc["rating"], int(doc["score"]),
                     float(doc["confidence"]), _cut(doc.get("summary", ""), 2000),
                     any(r.get("status") not in (None, "skipped") for r in ver.values()),
                     _cut(source.get("commit"), 64), _cut(source.get("branch"), 200), _cut(tool_version(), 64),
                     json.dumps(doc, default=str)))
        assessment_id = cur.fetchone()[0]

        for c in doc.get("components", []):
            comp_id = _component(cur, app_id, c)
            v = ver.get(c["name"]) or {}
            status = v.get("status") if v.get("status") not in (None, "skipped") else None
            detail = v.get("detail") or (v.get("finding") or {}).get("title")
            cur.execute("INSERT cz.ComponentAssessment (AssessmentId, ComponentId, Role, Tier, TargetFramework, Verdict, "
                        "VerdictText, Score, Confidence, WindowsContainerOk, VerifyStatus, VerifyDetail) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (assessment_id, comp_id, c["role"], c.get("tier", "other"), _cut(";".join(c.get("tfm") or []), 200),
                         c["verdict"], _cut(c.get("verdict_text", c["verdict"]), 200), int(c["score"]),
                         float(c.get("confidence", 1)), bool(c.get("windows_container_ok")),
                         status, _cut(detail if status else None, 2000)))
            if c.get("migration"):
                _migration(cur, assessment_id, comp_id, c["migration"])
            for f in c.get("findings", []):
                _finding(cur, assessment_id, comp_id, f)
            if v.get("finding"):
                _finding(cur, assessment_id, comp_id, _runtime_finding(v["finding"]))
            if sboms and c["name"] in sboms:
                sdoc, pkgs = sboms[c["name"]]
                _sbom(cur, assessment_id, comp_id, "source", sdoc, pkgs, tool="containerizer")
        for f in doc.get("repo_findings", []):
            _finding(cur, assessment_id, None, f)
        conn.commit()
        return assessment_id
    except Exception:
        conn.rollback()
        raise


def _component(cur, app_id: int, c: dict) -> int:
    path = _cut(c.get("project") or c["name"], 400)
    cur.execute("SELECT ComponentId FROM cz.Component WITH (UPDLOCK, HOLDLOCK) WHERE ApplicationId = %s AND ProjectPath = %s",
                (app_id, path))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE cz.Component SET Name = %s, LastSeenAt = SYSUTCDATETIME() WHERE ComponentId = %s",
                    (_cut(c["name"], 200), row[0]))
        return row[0]
    cur.execute("INSERT cz.Component (ApplicationId, ProjectPath, Name) OUTPUT INSERTED.ComponentId VALUES (%s, %s, %s)",
                (app_id, path, _cut(c["name"], 200)))
    return cur.fetchone()[0]


def _migration(cur, assessment_id: int, comp_id: int, m: dict) -> None:
    plan = {k: v for k, v in m.items() if k != "prompt"}
    cur.execute("INSERT cz.ComponentMigration (AssessmentId, ComponentId, Outcome, ItemCount, PlanJson, "
                "AgentPrompt) VALUES (%s, %s, %s, %s, %s, %s)",
                (assessment_id, comp_id, _cut(m.get("outcome") or "linux-container", 40),
                 len(m.get("items") or []), json.dumps(plan, default=str),
                 m.get("prompt")))


def _runtime_finding(f: dict) -> dict:
    return {"id": f.get("id") or "runtime", "severity": f.get("severity") or "refactor", "category": "runtime",
            "title": f.get("title") or "Runtime finding", "why": f.get("why"), "fix": f.get("fix"),
            "refs": f.get("refs") or [], "source": "runtime"}


def _finding(cur, assessment_id: int, comp_id: int | None, f: dict) -> None:
    sev = f.get("severity") or "info"
    eff = effective_severity({**f, "severity": sev})
    refs = [u for u in f.get("refs") or [] if isinstance(u, str) and u.startswith(("https://", "http://"))]
    cur.execute("INSERT cz.Finding (AssessmentId, ComponentId, RuleId, Severity, RuleSeverity, Category, Title, Why, Fix, "
                "Via, OnlyCommands, Evidence, Refs, Source) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (assessment_id, comp_id, _cut(f.get("id") or "", 200), eff, sev, _cut(f.get("category"), 100),
                 _cut(f.get("title") or f.get("id") or "", 400), f.get("why"), f.get("fix"),
                 _cut(f.get("via") or None, 200),
                 _cut(", ".join(f.get("only_commands") or []) or None, 400),
                 _cut("\n".join(f.get("evidence") or []) or None, 2000), json.dumps(refs) if refs else None,
                 _cut(f.get("source"), 40)))


def _sbom(cur, assessment_id: int, comp_id: int, kind: str, doc: dict, packages: list, tool: str | None = None,
          image_ref: str | None = None, digest: str | None = None, attestation: str | None = None,
          os_name: str | None = None) -> int:
    """Insert one SBOM and its packages (dicts as sbom.Package.to_dict(), or Package objects)."""
    cur.execute("INSERT cz.ComponentSbom (AssessmentId, ComponentId, Kind, ImageRef, ImageDigest, Format, Tool, "
                "OperatingSystem, PackageCount, Attestation, Document) OUTPUT INSERTED.SbomId "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (assessment_id, comp_id, kind, _cut(image_ref, 400), _cut(digest, 100),
                 _cut(f"CycloneDX {doc.get('specVersion', '')}".strip(), 40), _cut(tool, 100), _cut(os_name, 100),
                 len(packages), _cut(attestation, 300), json.dumps(doc)))
    sbom_id = cur.fetchone()[0]
    rows = []
    for i, p in enumerate(packages, 1):
        p = p if isinstance(p, dict) else p.to_dict()
        c = p.get("counts") or {}
        vulns = p.get("vulns") or []
        rows.append((sbom_id, i, _cut(p["name"], 400), _cut(p.get("version") or None, 200), _cut(p.get("type") or None, 40),
                     _cut(p.get("purl") or None, 1000), _cut(p.get("license") or None, 1000),
                     _cut(p.get("license_source") or None, 20), p.get("status") or "unknown", _cut(p.get("scope") or "app", 10),
                     bool(p.get("applies", True)), _cut(p.get("accepted") or None, 400), _cut(p.get("found_by") or "sbom", 10),
                     int(c.get("CRITICAL", 0)), int(c.get("HIGH", 0)), int(c.get("MEDIUM", 0)), int(c.get("LOW", 0)),
                     json.dumps(vulns) if vulns else None))
    if rows:
        cur.executemany("INSERT cz.SbomPackage (SbomId, PackageNo, Name, Version, Type, Purl, License, LicenseSource, "
                        "LicenseStatus, Scope, PolicyApplies, Accepted, FoundBy, Critical, High, Medium, Low, Vulns) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", rows)
    return sbom_id


def store_image_sboms(conn, assessment_id: int, entries: list[dict]) -> int:
    """Image SBOMs of components built after an assessment was stored (`containerizer org`). Each entry:
    project (path as stored), document, packages, tool, os, image, digest, attestation. Returns rows written."""
    cur = conn.cursor()
    n = 0
    try:
        for e in entries:
            cur.execute("SELECT c.ComponentId FROM cz.Component c JOIN cz.ApplicationAssessment aa "
                        "ON aa.ApplicationId = c.ApplicationId WHERE aa.AssessmentId = %s AND c.ProjectPath = %s",
                        (assessment_id, _cut(e["project"], 400)))
            row = cur.fetchone()
            if not row:
                continue
            _sbom(cur, assessment_id, row[0], "image", e["document"], e["packages"], e.get("tool"), e.get("image"),
                  e.get("digest"), e.get("attestation"), e.get("os"))
            n += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return n


def store_idp_clients(conn, assessment_id: int, entries: list[dict]) -> int:
    """Sandbox IdP registrations of the components deployed after an assessment (`containerizer org`).
    Each entry: project (path as stored), protocol, idp_url, app_url, identifier, metadata_url, settings
    (dict, no secret values), notes. Returns rows written."""
    cur = conn.cursor()
    n = 0
    try:
        for e in entries:
            cur.execute("SELECT c.ComponentId FROM cz.Component c JOIN cz.ApplicationAssessment aa "
                        "ON aa.ApplicationId = c.ApplicationId WHERE aa.AssessmentId = %s AND c.ProjectPath = %s",
                        (assessment_id, _cut(e["project"], 400)))
            row = cur.fetchone()
            if not row:
                continue
            cur.execute("INSERT cz.SandboxIdpClient (AssessmentId, ComponentId, Protocol, IdpUrl, AppUrl, Identifier, "
                        "MetadataUrl, Settings, Notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (assessment_id, row[0], _cut(e.get("protocol") or "none", 10), _cut(e["idp_url"], 300),
                         _cut(e.get("app_url") or None, 300), _cut(e.get("identifier") or None, 400),
                         _cut(e.get("metadata_url") or None, 400),
                         json.dumps(e.get("settings") or {}, sort_keys=True) if e.get("settings") else None,
                         _cut("; ".join(e.get("notes") or []) or None, 2000)))
            n += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return n


def source_sboms(a) -> dict:
    """Source SBOMs of an AppAssessment's components (sbom.source in rules/60-security.yaml)."""
    from .sbom import config, source_component_sbom
    cfg = config()
    if not cfg.get("enabled", True) or not cfg.get("source", True):
        return {}
    out = {}
    for c in a.components:
        try:
            out[c.name] = source_component_sbom(c, getattr(a, "repo", None))
        except Exception as ex:          # an SBOM must never cost the assessment
            print(f"warning: no source SBOM for {c.name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    return out


def assessment_doc(a) -> dict:
    """The assessment.json entry of an AppAssessment (with build-and-run results when there are any)."""
    return {**a.to_dict(), **({"verification": a.verification} if getattr(a, "verification", None) else {})}


def store_results(cs: str | None, results: list, paths: list[Path], password: str | None = None) -> list[int]:
    """Store AppAssessments assessed from `paths` (same order). Returns the AssessmentIds."""
    conn = connect(cs, password)
    try:
        return [store_assessment(conn, assessment_doc(a), source_info(p, a.name), sboms=source_sboms(a))
                for a, p in zip(results, paths)]
    finally:
        conn.close()


def import_json(cs: str | None, files: list[Path], key_prefix: str = "", password: str | None = None) -> list[int]:
    """Load assessment.json files written earlier (`assess --out`, `analyze`, the GitHub Action)."""
    conn = connect(cs, password)
    ids = []
    try:
        for fp in files:
            docs = json.loads(Path(fp).read_text())
            for doc in docs if isinstance(docs, list) else [docs]:
                src = {"key": key_prefix + doc["name"], "repository_url": None, "path": None, "commit": None,
                       "branch": None, **(doc.get("source") or {})}
                ids.append(store_assessment(conn, doc, src))
    finally:
        conn.close()
    return ids


def sandbox_key(r: dict) -> str:
    """The Application.SourceKey of a checked component: recorded at deploy time, else what a scan of the
    cloned repository root would have used (`<remote URL>#`)."""
    if r.get("source_key"):
        return r["source_key"]
    return f"{clean_remote(r['clone_url'])}#" if r.get("clone_url") else ""


def store_sandbox_checks(conn, doc: dict) -> tuple[int, int]:
    """Insert one SandboxCheck per checked component of a sandbox health document. Components are matched
    by application source key and project path; returns (rows written, components not found)."""
    from datetime import datetime
    when = None
    try:
        when = datetime.fromisoformat(doc.get("checked_at") or "").replace(tzinfo=None)
    except ValueError:
        pass
    cur = conn.cursor()
    n = missing = 0
    try:
        for r in doc.get("components", []):
            if r.get("status") == "skipped":
                continue
            key = sandbox_key(r)
            cur.execute("SELECT ApplicationId FROM cz.Application WHERE SourceKey = %s", (_cut(key, 400),))
            row = cur.fetchone()
            if not row:
                missing += 1
                continue
            app_id = row[0]
            cur.execute("SELECT ComponentId FROM cz.Component WHERE ApplicationId = %s AND ProjectPath = %s",
                        (app_id, _cut(r.get("project") or r.get("component"), 400)))
            row = cur.fetchone()
            if not row:
                missing += 1
            d = r.get("diagnosis") or {}
            events = [{k: e.get(k) for k in ("reason", "message", "count", "object")} for e in r.get("events") or []]
            cur.execute("INSERT cz.SandboxCheck (ApplicationId, ComponentId, CheckedAt, Status, Reason, GitOps, Namespace, "
                        "Workloads, ImageRef, Revision, Ready, Restarts, RuleId, Outcome, Diagnosis, Events, LogTail, Url, UrlCheck) "
                        "VALUES (%s, %s, COALESCE(%s, SYSUTCDATETIME()), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (app_id, row[0] if row else None, when, _cut(r["status"], 20), _cut(r.get("reason"), 2000),
                         _cut(r.get("gitops") or None, 20), _cut(r.get("app") or "", 63),
                         _cut(", ".join(r.get("workloads") or []) or None, 400), _cut(r.get("image") or None, 400),
                         _cut(doc.get("revision") or None, 64), _cut(r.get("ready") or None, 20), r.get("restarts"),
                         _cut(d.get("rule"), 200), _cut(d.get("outcome"), 20), _cut(d.get("diagnosis"), 2000),
                         json.dumps(events) if events else None, r.get("log_tail") or None,
                         _cut(r.get("url") or None, 300), _cut(r.get("url_check") or None, 300)))
            n += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return n, missing


def store_sandbox(cs: str | None, doc: dict, password: str | None = None) -> tuple[int, int]:
    conn = connect(cs, password)
    try:
        return store_sandbox_checks(conn, doc)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# logins: the docker compose stack and the appliance (its own SQL Server or an external one)

def create_login(conn, login: str, password: str, role: str) -> None:
    """Create (or reset) a SQL login + database user in role writer, reader or admin. Needs an admin connection."""
    role = role.removeprefix(conn.schema + "_")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", login) or role not in ("writer", "reader", "admin"):
        raise SqlError(f"bad login or role: {login} {role} (roles: writer, reader, admin)")
    pw = password.replace("'", "''")
    conn.cursor().execute(f"IF SUSER_ID(N'{login}') IS NULL CREATE LOGIN [{login}] WITH PASSWORD = N'{pw}', CHECK_POLICY = ON "
                          f"ELSE ALTER LOGIN [{login}] WITH PASSWORD = N'{pw}'")
    add_member(conn, login, role)


def add_member(conn, login: str, role: str) -> None:
    """Put a login (or a contained database user) in role writer, reader or admin; creates the database user
    FOR LOGIN when it is missing. Needs db_owner, not server permissions (an external database whose DBA made
    the logins)."""
    role = role.removeprefix(conn.schema + "_")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", login) or role not in ("writer", "reader", "admin"):
        raise SqlError(f"bad login or role: {login} {role} (roles: writer, reader, admin)")
    role = f"{conn.schema}_{role}"
    cur = conn.cursor()
    # a database restored from another server keeps users whose login SID is gone: map them to the login here
    cur.execute(f"IF DATABASE_PRINCIPAL_ID(N'{login}') IS NULL CREATE USER [{login}] FOR LOGIN [{login}] "
                f"ELSE IF SUSER_SID(N'{login}') IS NOT NULL AND (SELECT sid FROM sys.database_principals "
                f"WHERE name = N'{login}') <> SUSER_SID(N'{login}') ALTER USER [{login}] WITH LOGIN = [{login}]")
    cur.execute(f"ALTER ROLE [{role}] ADD MEMBER [{login}]")
    conn.commit()


def create_database(cs: str | None, password: str | None = None) -> None:
    """CREATE DATABASE when it does not exist (connects to master with the same credentials)."""
    args = parse_connection_string(cs or os.environ.get("CONTAINERIZER_SQL") or "")
    db = _pick(args, "database", "initialcatalog") or ""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", db):
        raise SqlError(f"database name must be a plain identifier: {db!r}")
    master = re.sub(r"(?i)(^|;)\s*(database|initial\s*catalog)\s*=[^;]*", r"\1Database=master", cs or os.environ["CONTAINERIZER_SQL"])
    conn = connect(master, password, autocommit=True)
    try:
        conn.cursor().execute(f"IF DB_ID(N'{db}') IS NULL CREATE DATABASE [{db}]")
    finally:
        conn.close()
