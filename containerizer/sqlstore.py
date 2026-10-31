"""Write assessment results to Microsoft SQL Server (schema in sql/schema.sql, docs/results-database.md).

The connection string uses the familiar ADO.NET/ODBC keys and is read from --sql or CONTAINERIZER_SQL:

    Server=tcp:sql.example.com,1433;Database=Containerizer;User Id=cz_scanner;Encrypt=yes

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
import tempfile
from pathlib import Path

SCHEMA = Path(__file__).resolve().parent / "sql" / "schema.sql"
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
            "appname": _pick(d, "applicationname", "app", default="containerizer"), "_ca": ca}


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
    os.environ["FREETDSCONF"] = _freetds_conf(ca)
    try:
        return pymssql.connect(autocommit=autocommit, **args)
    except pymssql.Error as e:
        hint = " (is the server certificate trusted? see docs/results-database.md#tls)" if ca else ""
        raise SqlError(f"cannot connect to {args['server']},{args['port']} database {args['database']}{hint}: "
                       f"{_err(e)}") from None


def _err(e) -> str:
    a = getattr(e, "args", ())
    m = a[1] if len(a) > 1 else (a[0] if a else e)
    return (m.decode(errors="replace") if isinstance(m, bytes) else str(m)).strip().splitlines()[-1]


# ---------------------------------------------------------------------------
# schema

def schema_batches(text: str | None = None) -> list[str]:
    text = SCHEMA.read_text() if text is None else text
    return [b.strip() for b in re.split(r"^\s*GO\s*$", text, flags=re.M | re.I) if b.strip()]


def init_schema(conn) -> None:
    cur = conn.cursor()
    for b in schema_batches():
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


def store_assessment(conn, doc: dict, source: dict, assessed_at=None) -> int:
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
            cur.execute("INSERT cz.Application (SourceKey, Name, RepositoryUrl, SourcePath) "
                        "OUTPUT INSERTED.ApplicationId VALUES (%s, %s, %s, %s)",
                        (_cut(source["key"], 400), _cut(doc["name"], 200), _cut(source.get("repository_url"), 400),
                         _cut(source.get("path"), 400)))
            app_id = cur.fetchone()[0]

        ver = {r.get("component"): r for r in doc.get("verification") or []}
        cur.execute("INSERT cz.ApplicationAssessment (ApplicationId, AssessedAt, Rating, Score, EffortDays, Confidence, "
                    "Summary, Verified, SourceCommit, SourceBranch, ToolVersion, ReportJson) OUTPUT INSERTED.AssessmentId "
                    "VALUES (%s, COALESCE(%s, SYSUTCDATETIME()), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (app_id, assessed_at, doc["rating"], int(doc["score"]), float(doc["effort_days"]),
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
                        "VerdictText, Score, EffortDays, Confidence, WindowsContainerOk, VerifyStatus, VerifyDetail) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (assessment_id, comp_id, c["role"], c.get("tier", "other"), _cut(";".join(c.get("tfm") or []), 200),
                         c["verdict"], _cut(c.get("verdict_text", c["verdict"]), 200), int(c["score"]),
                         float(c["effort_days"]), float(c.get("confidence", 1)), bool(c.get("windows_container_ok")),
                         status, _cut(detail if status else None, 2000)))
            for f in c.get("findings", []):
                _finding(cur, assessment_id, comp_id, f)
            if v.get("finding"):
                _finding(cur, assessment_id, comp_id, _runtime_finding(v["finding"]))
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


def _runtime_finding(f: dict) -> dict:
    return {"id": f.get("id") or "runtime", "severity": f.get("severity") or "refactor", "category": "runtime",
            "title": f.get("title") or "Runtime finding", "why": f.get("why"), "fix": f.get("fix"),
            "refs": f.get("refs") or [], "source": "runtime"}


def _finding(cur, assessment_id: int, comp_id: int | None, f: dict) -> None:
    sev = f.get("severity") or "info"
    eff = effective_severity({**f, "severity": sev})
    refs = [u for u in f.get("refs") or [] if isinstance(u, str) and u.startswith(("https://", "http://"))]
    cur.execute("INSERT cz.Finding (AssessmentId, ComponentId, RuleId, Severity, RuleSeverity, Category, Title, Why, Fix, "
                "EffortDays, Via, OnlyCommands, Evidence, Refs, Source) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (assessment_id, comp_id, _cut(f.get("id") or "", 200), eff, sev, _cut(f.get("category"), 100),
                 _cut(f.get("title") or f.get("id") or "", 400), f.get("why"), f.get("fix"),
                 f.get("effort_days"), _cut(f.get("via") or None, 200),
                 _cut(", ".join(f.get("only_commands") or []) or None, 400),
                 _cut("\n".join(f.get("evidence") or []) or None, 2000), json.dumps(refs) if refs else None,
                 _cut(f.get("source"), 40)))


def assessment_doc(a) -> dict:
    """The assessment.json entry of an AppAssessment (with build-and-run results when there are any)."""
    return {**a.to_dict(), **({"verification": a.verification} if getattr(a, "verification", None) else {})}


def store_results(cs: str | None, results: list, paths: list[Path], password: str | None = None) -> list[int]:
    """Store AppAssessments assessed from `paths` (same order). Returns the AssessmentIds."""
    conn = connect(cs, password)
    try:
        return [store_assessment(conn, assessment_doc(a), source_info(p, a.name)) for a, p in zip(results, paths)]
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


# ---------------------------------------------------------------------------
# local development: logins for the docker compose stack

def create_login(conn, login: str, password: str, role: str) -> None:
    """Create (or reset) a SQL login + database user in `role`. Needs an admin connection."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", login) or role not in ("cz_writer", "cz_reader", "cz_mapper"):
        raise SqlError(f"bad login or role: {login} {role}")
    cur = conn.cursor()
    pw = password.replace("'", "''")
    cur.execute(f"IF SUSER_ID(N'{login}') IS NULL CREATE LOGIN [{login}] WITH PASSWORD = N'{pw}', CHECK_POLICY = ON "
                f"ELSE ALTER LOGIN [{login}] WITH PASSWORD = N'{pw}'")
    cur.execute(f"IF DATABASE_PRINCIPAL_ID(N'{login}') IS NULL CREATE USER [{login}] FOR LOGIN [{login}]")
    cur.execute(f"ALTER ROLE {role} ADD MEMBER [{login}]")
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
