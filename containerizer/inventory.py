"""The inventory: from source code to binary name, databases and external services, across every application.

Large estates lose track of which repository builds which binary, which databases an application uses and which
external APIs and services it calls. Every assessment written to the results database (sqlstore.store_assessment)
updates cz.InventoryItem (schema 60) from the assessment entry:

- **binary**: the main binary of each component (facts `entry`: Orders.Api.dll, the executable or package name),
  from A-rated assessments only: what a build that can ship produces. A later scan rated lower leaves them as they
  were, so the list keeps the last A-rated build's names.
- **database**: each connection string's server and database (facts `databases`, from appsettings.json with the
  build's transform and appsettings.Production.json, and web.config/app.config), never the user or password.
- **service**: each destination the configuration or code names (assessment `network`: URLs and hosts with their
  port), and the NServiceBus transport an endpoint uses (facts `nservicebus`).

An item the next assessment no longer has is marked removed (RemovedAt), not deleted: FirstSeenAt and LastSeenAt
say when it was first and last found. The results page /inventory lists them with a search (every signed-in viewer:
reader role, vInventory).
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlencode, urlparse

e = html.escape

KINDS = {"binary": "Binaries", "database": "Databases", "service": "External services"}
KIND_TEXT = {"binary": "binary", "database": "database", "service": "service"}

# ------------------------------------------------------------------ connection strings

_PAIR = re.compile(r"\s*(?P<k>[^=;]+?)\s*=\s*(?P<v>\"[^\"]*\"|'[^']*'|[^;]*)\s*(?:;|$)")
SERVER_KEYS = {"server", "data source", "datasource", "address", "addr", "network address", "host", "hostname",
               "endpoint", "dsn"}
DB_KEYS = {"database", "initial catalog", "dbname", "db", "databasename", "service name", "servicename"}
URL_DB = re.compile(r"(?i)^(?P<scheme>postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|sqlserver|mariadb|oracle)://")
JDBC = re.compile(r"(?i)^jdbc:(?P<kind>sqlserver|postgresql|mysql|mariadb|oracle:thin|db2|h2|sqlite):(?P<rest>.*)$")
SCHEME_KIND = {"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql",
               "mongodb": "mongodb", "mongodb+srv": "mongodb", "redis": "redis", "rediss": "redis",
               "sqlserver": "sqlserver", "oracle": "oracle"}
JDBC_KIND = {"sqlserver": "sqlserver", "postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql",
             "oracle:thin": "oracle", "db2": "db2", "h2": "h2", "sqlite": "sqlite"}
DB_KINDS = ("sqlserver", "postgres", "mysql", "mongodb", "redis", "oracle", "db2", "sqlite", "h2")
MAX_NAME = 200


def _clean(v: str | None) -> str | None:
    v = (v or "").strip().strip("\"'").strip()
    return v[:MAX_NAME] or None


def _split_port(server: str) -> tuple[str, int | None]:
    s = re.sub(r"(?i)^(tcp|np|lpc):", "", server.strip())
    m = re.fullmatch(r"(?P<h>[^,]+?)\s*,\s*(?P<p>\d{1,5})", s) or re.fullmatch(r"(?P<h>[^:\\]+):(?P<p>\d{1,5})", s)
    if m:
        return m["h"].strip(), int(m["p"])
    return s, None


def parse_connection(value, kind: str | None = None) -> dict | None:
    """{kind, server, port, database} of a connection string or database URL, without its credentials; None when it
    names neither a server nor a database."""
    if not isinstance(value, str) or not value.strip() or len(value) > 4000:
        return None
    v = value.strip()
    out = {"kind": kind, "server": None, "port": None, "database": None}
    m = JDBC.match(v)
    if m:
        out["kind"] = kind or JDBC_KIND.get(m["kind"].lower())
        rest = m["rest"]
        if rest.startswith("//"):
            host = re.match(r"//(?:[^@/;]*@)?(?P<h>[^/;:?]+)(?::(?P<p>\d{1,5}))?(?:/(?P<d>[^;?]*))?", rest)
            if host:
                out["server"], out["port"] = _clean(host["h"]), int(host["p"]) if host["p"] else None
                out["database"] = _clean(host["d"])
        props = dict((k.strip().lower(), x) for k, x in re.findall(r";\s*([^=;]+)=([^;]*)", rest))
        out["database"] = out["database"] or _clean(props.get("databasename") or props.get("database"))
        if not out["server"] and out["kind"] in ("sqlite", "h2"):
            out["database"] = _clean(rest)
    elif URL_DB.match(v) or re.match(r"(?i)^amqps?://", v):
        u = urlparse(v)
        out["kind"] = kind or SCHEME_KIND.get(u.scheme.lower())
        try:
            out["server"], out["port"] = _clean(u.hostname), u.port
        except ValueError:
            out["server"] = _clean((u.netloc.rsplit("@", 1)[-1]).split(":")[0])
        path = u.path.strip("/")
        out["database"] = _clean(path.split("/")[0]) if path and out["kind"] != "redis" else None
    elif re.fullmatch(r"[\w.\-]+:\d{2,5}(,.*)?", v):            # host:port[,options] (Redis)
        host, _, rest = v.partition(",")
        h, p = host.rsplit(":", 1)
        out["server"], out["port"] = _clean(h), int(p)
    elif "=" in v:
        pairs = {m["k"].strip().lower(): m["v"] for m in _PAIR.finditer(v)}
        server = next((pairs[k] for k in SERVER_KEYS if pairs.get(k)), None)
        db = next((pairs[k] for k in DB_KEYS if pairs.get(k)), None)
        if server:
            if re.match(r"(?i)\s*\|DataDirectory\||.*\.(db|sqlite|sqlite3|mdf|ldf|litedb)\s*$", server):
                out["kind"] = out["kind"] or "sqlite"
                out["database"] = _clean(server)
            else:
                host, port = _split_port(server)
                out["server"], out["port"] = _clean(host), port
        if pairs.get("port") and re.fullmatch(r"\d{1,5}", pairs["port"].strip()):
            out["port"] = int(pairs["port"].strip())
        if pairs.get("attachdbfilename"):
            db = db or pairs["attachdbfilename"]
        out["database"] = out["database"] or _clean(db)
    if not out["server"] and not out["database"]:
        return None
    return out


def database_facts(entries: list[tuple[str, object, str | None]]) -> list[dict]:
    """facts["databases"]: [{key, kind, server, port, database}] for each (configuration key, value, the lab's
    classification) that is a database connection; a key once."""
    out, seen = [], set()
    for key, value, kind in entries:
        svc = (kind or "").split(":", 1)[0] or None
        if svc and svc not in DB_KINDS:
            continue
        if not svc and not str(key).lower().startswith("connectionstrings"):
            continue
        d = parse_connection(value, svc)
        if d is None or key in seen:
            continue
        seen.add(key)
        out.append({"key": str(key)[:200], **{k: d[k] for k in ("kind", "server", "port", "database")}})
    return out


def config_connection_strings(text: str) -> list[tuple[str, str]]:
    """(ConnectionStrings:<name>, value) of a web.config/app.config's <connectionStrings>."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    for cs in root.iter("connectionStrings"):
        for add in cs.iter("add"):
            name, value = add.get("name"), add.get("connectionString")
            if name and value:
                out.append((f"ConnectionStrings:{name}", value))
    return out


# ------------------------------------------------------------------ NServiceBus

NSB_TRANSPORTS = {
    "rabbitmq": "RabbitMQ", "sqlserver": "SQL Server", "postgresql": "PostgreSQL", "msmq": "MSMQ",
    "azure-service-bus": "Azure Service Bus", "azure-storage-queues": "Azure Storage Queues",
    "amazon-sqs": "Amazon SQS", "learning": "Learning (files)", "ibmmq": "IBM MQ", "activemq": "ActiveMQ",
    "bridge": "Bridge", "unknown": "not found",
}
NSB_LAB = {"rabbitmq": "rabbitmq", "sqlserver": "sqlserver", "postgresql": "postgres"}


def nsb_transport(name: str | None) -> str | None:
    """The transport of a package (NServiceBus.Transport.SqlServer) or of the code (UseTransport<SqlServerTransport>)."""
    n = re.sub(r"(?i)^NServiceBus\.(Transport\.|Transports\.|Azure\.Transports\.)?", "", (name or "").strip()).lower()
    if not n:
        return None
    for key, words in (("rabbitmq", ("rabbitmq",)), ("sqlserver", ("sqlserver",)), ("postgresql", ("postgresql", "postgres")),
                       ("msmq", ("msmq",)), ("azure-storage-queues", ("storagequeue", "azurestoragequeues")),
                       ("azure-service-bus", ("servicebus", "azureservicebus")), ("amazon-sqs", ("sqs", "amazonsqs")),
                       ("learning", ("learning",)), ("ibmmq", ("ibmmq",)), ("activemq", ("activemq",)), ("bridge", ("bridge",))):
        if any(w in n for w in words):
            return key
    return None


def nservicebus_facts(facts: dict, packages: dict | None = None) -> None:
    """facts["nservicebus"]: {"transport", "endpoint", "version"} from what the facts rules found (05-facts.yaml nsb-*):
    the transport package first, else the code; NServiceBus 6 and earlier without either uses MSMQ, its default."""
    if not facts.get("nservicebus") and not facts.get("nsb_transport"):
        return
    code = facts.pop("nsb_transport_code", None)
    facts.pop("nsb_transport", None)
    t, version = None, None
    for name, ver in sorted((packages or {}).items()):
        if name.lower() == "nservicebus":
            version = str(ver or "") or None
        elif name.lower().startswith("nservicebus."):
            t = t or nsb_transport(name)            # the transport's package (NServiceBus.Transport.SqlServer)
    t = t or nsb_transport(code)
    if not t:
        major = re.match(r"\[?\s*(\d+)", version or "")
        t = "msmq" if major and int(major[1]) <= 6 else "unknown"
    out = {"transport": t}
    if facts.get("nsb_endpoint"):
        out["endpoint"] = str(facts.pop("nsb_endpoint"))[:100]
    if version:
        out["version"] = version[:40]
    facts["nservicebus"] = out


# ------------------------------------------------------------------ items of an assessment entry

def _internal(host: str) -> bool:
    h = host.lower().rstrip(".")
    return (h in ("localhost",) or h.endswith((".svc", ".cluster.local", ".svc.cluster.local", ".local"))
            or re.fullmatch(r"127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0", h) is not None)


def items(doc: dict) -> list[dict]:
    """The inventory items of one assessment entry: {kind, component, name, server, port, detail, source}."""
    out: list[dict] = []
    rated_a = str(doc.get("rating") or "")[:1] == "A"
    for c in doc.get("components") or []:
        f = c.get("facts") or {}
        comp = c.get("name")
        if rated_a and f.get("entry"):
            tfm = ";".join(c.get("tfm") or []) if isinstance(c.get("tfm"), list) else c.get("tfm")
            out.append({"kind": "binary", "component": comp, "name": str(f["entry"]), "server": None, "port": None,
                        "detail": c.get("role"), "source": tfm or None})
        for d in f.get("databases") or []:
            if not isinstance(d, dict):
                continue
            out.append({"kind": "database", "component": comp, "name": d.get("database") or "(default)",
                        "server": d.get("server"), "port": d.get("port"), "detail": d.get("kind"), "source": d.get("key")})
        nsb = f.get("nservicebus")
        if isinstance(nsb, dict):
            t = nsb.get("transport") or "unknown"
            out.append({"kind": "service", "component": comp, "name": f"NServiceBus: {NSB_TRANSPORTS.get(t, t)}",
                        "server": nsb.get("endpoint"), "port": None, "detail": "nservicebus",
                        "source": f"NServiceBus {nsb['version']}" if nsb.get("version") else "NServiceBus"})
    db_hosts = {str(i["server"]).lower() for i in out if i["kind"] == "database" and i["server"]}
    for nc in (doc.get("network") or {}).get("components") or []:
        for d in nc.get("destinations") or []:
            host = str(d.get("host") or "")
            if not host or _internal(host) or host.lower() in db_hosts:      # a database server: under Databases
                continue
            src = f"{d['file']}:{d['line']}" if d.get("file") and d.get("line") else d.get("file") or d.get("source")
            out.append({"kind": "service", "component": nc.get("name"), "name": host[:MAX_NAME], "server": None,
                        "port": d.get("port"), "detail": d.get("scheme") or d.get("protocol"), "source": src})
    seen, uniq = set(), []
    for i in out:
        k = (i["kind"], i["component"] or "", i["name"], i["server"] or "", i["port"] or 0)
        if k not in seen:
            seen.add(k)
            uniq.append(i)
    return uniq


def _cut(s, n: int):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def sync(cur, app_id: int, assessment_id: int, doc: dict) -> None:
    """Record one assessment's items (cz.InventoryItem): new ones are added, found ones seen again, the application's
    ones it no longer has marked removed. Binaries only from an A-rated assessment (the others leave them as they
    were)."""
    found = items(doc)
    kinds = ["database", "service"] + (["binary"] if str(doc.get("rating") or "")[:1] == "A" else [])
    cur.execute("SELECT ItemId, Kind, COALESCE(ComponentName, N'') AS C, Name, COALESCE(Server, N'') AS S, "
                "COALESCE(Port, 0) AS P, RemovedAt FROM cz.InventoryItem WITH (UPDLOCK, HOLDLOCK) WHERE ApplicationId = %s",
                (app_id,))
    have = {(r[1], r[2], r[3], r[4], int(r[5])): (r[0], r[6]) for r in cur.fetchall()}
    keep = set()
    for i in found:
        k = (i["kind"], _cut(i["component"], 200) or "", _cut(i["name"], MAX_NAME), _cut(i["server"], MAX_NAME) or "",
             int(i["port"] or 0))
        if k in have:
            keep.add(have[k][0])
            cur.execute("UPDATE cz.InventoryItem SET LastSeenAt = SYSUTCDATETIME(), LastAssessmentId = %s, RemovedAt = NULL, "
                        "Detail = %s, Source = %s WHERE ItemId = %s",
                        (assessment_id, _cut(i["detail"], 100), _cut(i["source"], 400), have[k][0]))
        else:
            cur.execute("INSERT cz.InventoryItem (ApplicationId, Kind, ComponentName, Name, Server, Port, Detail, Source, "
                        "FirstAssessmentId, LastAssessmentId) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (app_id, i["kind"], _cut(i["component"], 200), k[2], _cut(i["server"], MAX_NAME),
                         int(i["port"]) if i["port"] else None, _cut(i["detail"], 100), _cut(i["source"], 400),
                         assessment_id, assessment_id))
            have[k] = (None, None)
    gone = [iid for (kind, *_), (iid, removed) in have.items() if iid and iid not in keep and removed is None and kind in kinds]
    for iid in gone:
        cur.execute("UPDATE cz.InventoryItem SET RemovedAt = SYSUTCDATETIME() WHERE ItemId = %s", (iid,))


# ------------------------------------------------------------------ the results page /inventory

MAX_ROWS = 500


def parse_query(q: dict) -> tuple[str, str, bool]:
    kind = (q.get("kind") or ["binary"])[0]
    kind = kind if kind in KINDS else "binary"
    text = " ".join((q.get("q") or [""])[0].split())[:100]
    return kind, text, (q.get("removed") or [""])[0] == "1"


def keep_query(q: dict) -> str:
    kind, text, removed = parse_query(q)
    return urlencode([(k, v) for k, v in (("kind", kind), ("q", text), ("removed", "1" if removed else "")) if v])


def load(conn, kind: str, text: str, removed: bool) -> tuple[list[dict], dict]:
    """The items of one kind (matching the search in any column), and the count of each kind."""
    cur = conn.cursor(as_dict=True)
    where, params = ["Kind = %s"], [kind]
    if not removed:
        where.append("RemovedAt IS NULL")
    if text:
        like = "%" + re.sub(r"([%_\[])", r"[\1]", text) + "%"
        where.append("(Name LIKE %s OR Server LIKE %s OR ComponentName LIKE %s OR ApplicationName LIKE %s "
                     "OR ProductName LIKE %s OR Source LIKE %s OR Detail LIKE %s OR RepositoryUrl LIKE %s)")
        params += [like] * 8
    cur.execute(f"SELECT TOP ({MAX_ROWS + 1}) * FROM cz.vInventory WHERE {' AND '.join(where)} "
                "ORDER BY Name, Server, ApplicationName, ComponentName", tuple(params))
    rows = cur.fetchall()
    cur.execute("SELECT Kind, COUNT(*) AS N FROM cz.vInventory WHERE RemovedAt IS NULL GROUP BY Kind")
    counts = {r["Kind"]: r["N"] for r in cur.fetchall()}
    return rows, counts


def _d(t) -> str:
    return t.strftime("%Y-%m-%d") if t else ""


def render(rows: list[dict], counts: dict, kind: str, text: str, removed: bool, nav: str = "") -> str:
    from .webui import _nav, page
    tabs = "".join(
        f"<a class='chip{' on' if k == kind else ''}' href='/inventory?{e(urlencode({'kind': k, **({'q': text} if text else {})}))}'"
        f"{' aria-current=page' if k == kind else ''}>{e(t)} <span class='muted'>{int(counts.get(k, 0))}</span></a>"
        for k, t in KINDS.items())
    more = len(rows) > MAX_ROWS
    rows = rows[:MAX_ROWS]
    head = {"binary": ("Binary", "Role", "Target framework"),
            "database": ("Database", "Server", "Type and setting"),
            "service": ("Service", "Port", "Protocol and where")}[kind]
    trs = []
    for r in rows:
        app = (f"<a href='/app/{int(r['ApplicationId'])}'>{e(r['ApplicationName'] or '')}</a>"
               f"<div class='muted small'>{e(r.get('ProductName') or '')}</div>")
        comp = e(r.get("ComponentName") or "")
        if kind == "binary":
            a, b = e(r.get("Detail") or ""), e(r.get("Source") or "")
        elif kind == "database":
            srv = (r.get("Server") or "") + (f",{r['Port']}" if r.get("Port") else "")
            a, b = f"<code>{e(srv)}</code>" if srv else "", f"{e(r.get('Detail') or '')} <span class='muted small'>{e(r.get('Source') or '')}</span>"
        else:
            a = e(str(r.get("Port") or r.get("Server") or ""))
            b = f"{e(r.get('Detail') or '')} <span class='muted small'>{e(r.get('Source') or '')}</span>"
        gone = f" <span class='st st-off'>removed {_d(r.get('RemovedAt'))}</span>" if r.get("RemovedAt") else ""
        repo = r.get("RepositoryUrl") or ""
        repo_html = (f"<a href='{e(repo)}' rel='noopener noreferrer' target='_blank'>{e(repo.rstrip('/').rsplit('/', 1)[-1])}</a>"
                     if repo.startswith("https://") else e(repo))
        trs.append(f"<tr><td><code>{e(r['Name'])}</code>{gone}</td><td>{a}</td><td>{b}</td><td>{app}</td><td>{comp}</td>"
                   f"<td>{repo_html}</td><td class='small'>{_d(r.get('FirstSeenAt'))}<div class='muted'>{_d(r.get('LastSeenAt'))}</div></td></tr>")
    intro = {"binary": "The main binary of each component of the A-rated applications, as their last A-rated scan "
                       "found it: which repository builds which binary.",
             "database": "The databases the applications' connection strings name (server and database, never the "
                         "credentials), from their production configuration.",
             "service": "The external APIs and services the applications' configuration and code name, and the "
                        "NServiceBus transports of their endpoints."}[kind]
    form = (f"<form method='get' action='/inventory' class='invsearch'><input type='hidden' name='kind' value='{e(kind)}'>"
            f"<input name='q' value='{e(text)}' placeholder='Search: name, server, application, repository' "
            f"aria-label='Search the inventory' maxlength='100'> "
            f"<label class='check'><input type='checkbox' name='removed' value='1'{' checked' if removed else ''}> "
            f"Also removed</label> <button>Search</button></form>")
    table = (f"<table><thead><tr><th>{head[0]}</th><th>{head[1]}</th><th>{head[2]}</th><th>Application</th>"
             f"<th>Component</th><th>Repository</th><th>First seen<div class='muted'>last seen</div></th></tr></thead>"
             f"<tbody>{''.join(trs) or '<tr><td colspan=7 class=muted>Nothing found.</td></tr>'}</tbody></table>"
             + (f"<p class='muted small'>The first {MAX_ROWS} only: search to narrow it down.</p>" if more else ""))
    return page("Inventory", f"""{_nav(nav)}
<header><h1>Inventory</h1><p class='lead'>From source code to binaries, databases and external services.</p>
<p class='muted small'><a href='/'>Readiness</a> · <a href='/trends'>Trends over time</a> · <a href='/connectivity'>Connectivity</a></p>
</header>
<nav class='chips'>{tabs}</nav>
<p class='muted'>{e(intro)} Each scan updates it; what a later scan no longer finds is marked removed.</p>
{form}
{table}""")


def backfill(conn) -> int:
    """Once, when the inventory is empty: fill it from each application's latest assessment, and its binaries from
    its latest A-rated one (the assessments made before schema 60). Returns the applications done."""
    import json
    cur = conn.cursor()
    cur.execute("SELECT CASE WHEN EXISTS (SELECT 1 FROM cz.InventoryItem) THEN 1 ELSE 0 END")
    if cur.fetchone()[0]:
        return 0
    cur.execute("""SELECT x.AssessmentId, x.ApplicationId, x.ReportJson FROM cz.Application a
                   CROSS APPLY (SELECT TOP (1) aa.AssessmentId, aa.ApplicationId, aa.ReportJson
                                FROM cz.ApplicationAssessment aa WHERE aa.ApplicationId = a.ApplicationId
                                ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x
                   UNION
                   SELECT y.AssessmentId, y.ApplicationId, y.ReportJson FROM cz.Application a
                   CROSS APPLY (SELECT TOP (1) aa.AssessmentId, aa.ApplicationId, aa.ReportJson
                                FROM cz.ApplicationAssessment aa WHERE aa.ApplicationId = a.ApplicationId AND aa.Rating = 'A'
                                ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) y
                   ORDER BY 2, 1""")
    rows = cur.fetchall()
    apps = set()
    for assessment_id, app_id, report in rows:      # the older (A-rated) one first, then the latest
        try:
            doc = json.loads(report or "{}")
        except ValueError:
            continue
        if isinstance(doc, dict):
            sync(cur, app_id, assessment_id, doc)
            apps.add(app_id)
    conn.commit()
    return len(apps)
