"""SQL Server results store and the read-only web UI.

The integration tests need a SQL Server: set CONTAINERIZER_TEST_SQL to an admin connection string
(and CONTAINERIZER_SQL_PASSWORD), e.g. the container from results/compose.yaml or the CI service.
"""
import json
import os
import re
import threading
import urllib.error
import urllib.request
import uuid
from collections import Counter
from datetime import datetime
from http.server import ThreadingHTTPServer

import pytest

from containerizer import sqlstore, webui
from containerizer.assess import Finding, assess
from containerizer.rules import Rule
from containerizer.sqlstore import SqlError, clean_remote, connect_args, effective_severity, parse_connection_string

from test_engine import web_app, write


# ---------------------------------------------------------------------------
# connection strings

def test_connection_string_parsing():
    d = parse_connection_string("Server=tcp:db.example.com,14330; Initial Catalog=Cz;User ID=scan;"
                                "Password={a;b}}c};Encrypt=yes")
    assert d == {"server": "tcp:db.example.com,14330", "initialcatalog": "Cz", "userid": "scan",
                 "password": "a;b}c", "encrypt": "yes"}


def test_tls_is_validated_by_default(monkeypatch):
    monkeypatch.delenv("CONTAINERIZER_SQL_PASSWORD", raising=False)
    a = connect_args("Server=tcp:db.example.com,14330;Database=Cz;User Id=scan;Password=x")
    assert (a["server"], a["port"], a["database"], a["user"]) == ("db.example.com", "14330", "Cz", "scan")
    assert a["encryption"] == "require" and a["_ca"] == "system"
    a = connect_args("Server=db;Database=Cz;User Id=scan;Password=x;TrustServerCertificate=yes")
    assert a["encryption"] == "require" and a["_ca"] is None and a["port"] == "1433"
    assert connect_args("Server=db;Database=Cz;User Id=scan;Password=x;Encrypt=no")["encryption"] == "off"
    assert connect_args("Server=db;Database=Cz;User Id=s;Password=x;CaFile=/etc/ca.pem")["_ca"] == "/etc/ca.pem"


def test_password_from_environment_wins(monkeypatch):
    monkeypatch.setenv("CONTAINERIZER_SQL_PASSWORD", "from-env")
    assert connect_args("Server=db;Database=Cz;User Id=s;Password=inline")["password"] == "from-env"


@pytest.mark.parametrize("cs, msg", [
    ("Database=Cz;User Id=s;Password=x", "Server"),
    ("Server=db;User Id=s;Password=x", "Database"),
    ("Server=db;Database=Cz;Password=x", "User Id"),
    ("Server=db\\SQLEXPRESS;Database=Cz;User Id=s;Password=x", "named instances"),
    ("Server=db;Database=Cz;User Id=s;Password=x;Encrypt=maybe", "yes or no"),
])
def test_bad_connection_strings(cs, msg, monkeypatch):
    monkeypatch.delenv("CONTAINERIZER_SQL_PASSWORD", raising=False)
    with pytest.raises(SqlError, match=msg):
        connect_args(cs)


def test_remote_urls_lose_credentials():
    assert clean_remote("https://user:ghp_secret@github.com/o/r.git") == "https://github.com/o/r"
    assert clean_remote("git@github.com:o/r.git") == "https://github.com/o/r"
    assert clean_remote("ssh://git@ssh.dev.azure.com:22/v3/org/p/r") == "https://ssh.dev.azure.com/v3/org/p/r"
    assert clean_remote("https://dev.azure.com/org/p/_git/r") == "https://dev.azure.com/org/p/_git/r"


def test_effective_severity_matches_assess():
    rule = Rule.__new__(Rule)
    for sev in ("info", "config", "refactor", "rewrite", "blocker"):
        rule.severity = sev
        for dormant in (False, True):
            for modes in ([], ["export"]):
                f = Finding(rule=rule, evidence=[], dormant=dormant, modes=modes)
                d = {"severity": sev, "dormant": dormant, "only_commands": modes}
                assert effective_severity(d) == f.severity


def test_schema_batches():
    b = sqlstore.schema_batches("shared_cz")
    text = "\n".join(b)
    assert len(b) > 15 and not any(re.match(r"(?im)^\s*GO\s*$", x) for x in b)
    assert "${" not in text and not re.search(r"\bdbo\.\w", text) and "[shared_cz].AuditLog" in text
    # the scanner may never write the columns people maintain
    grant = re.search(r"GRANT UPDATE ON \[shared_cz\]\.Application \(([^)]*)\) TO \[shared_cz_writer\]", text)[1]
    assert "ProductId" not in grant and "DisplayName" not in grant
    # nobody may rewrite the audit trail
    assert not re.search(r"GRANT [^;]*(UPDATE|DELETE)[^;]*AuditLog", text)
    # work estimates were removed (schema 16): no table or view has them, older databases drop them
    assert all(re.search(r"COL_LENGTH|DROP COLUMN|^\s*--", ln) for ln in text.splitlines() if "EffortDays" in ln)
    assert text.count("DROP COLUMN EffortDays") == 4


@pytest.mark.parametrize("bad", ["dbo", "sys", "a-b", "x;drop", "1abc", ""])
def test_schema_name_is_validated(bad, monkeypatch):
    monkeypatch.delenv("CONTAINERIZER_SQL_SCHEMA", raising=False)
    if bad == "":
        assert sqlstore.schema_name(bad) == "containerizer"
    else:
        with pytest.raises(SqlError):
            sqlstore.schema_name(bad)


def test_queries_use_the_configured_schema():
    c = sqlstore.Connection(None, "shared_cz")
    assert c.sql("SELECT * FROM cz.vApplicationLatest a JOIN cz.Product p") == \
        "SELECT * FROM [shared_cz].vApplicationLatest a JOIN [shared_cz].Product p"
    assert c.sql("SELECT x.cz.y, 'cz' FROM t") == "SELECT x.cz.y, 'cz' FROM t"
    assert connect_args("Server=db;Database=D;User Id=u;Password=p;Schema=shared_cz")["_schema"] == "shared_cz"


# ---------------------------------------------------------------------------
# web UI rendering and HTTP handler, with canned data

def _app(i, name, rating, bu=None, bid=None, product=None, pid=None):
    return {"ApplicationId": i, "ApplicationName": name, "ProductId": pid, "ProductName": product,
            "BusinessUnitId": bid, "BusinessUnitName": bu, "Rating": rating, "Score": 80,
            "Confidence": 0.9, "Summary": "s", "AssessedAt": datetime(2026, 10, 31), "Verified": False,
            "Components": 2, "MainObstacle": ""}


def overview_data():
    return {"apps": [_app(1, "<script>alert(1)</script>", "A", "Finance", 1, "Billing", 1),
                     _app(2, "ledger", "E", "Finance", 1, "Billing", 1),
                     _app(3, "orphan", "C")],
            "unmapped": {"Application": 1}}


def test_overview_groups_and_escapes():
    html = webui.render_overview(overview_data())
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert html.index("Finance") < html.index("Billing") < html.index("Not assigned to a business unit")
    assert "1 application(s) are not mapped to a product" in html
    assert "style=" not in html                       # the CSP allows no inline styles
    assert "/app/3" in html
    assert "Effort" not in html and "person-day" not in html     # work estimates were removed


def test_overview_business_unit_filter():
    html = webui.render_overview(overview_data(), bu_filter="none")
    assert "/app/3" in html and "/app/2" not in html


def test_segmented_bar_is_proportional():
    svg = webui.segmented(Counter({"A": 3, "E": 1}), 4, "x")
    widths = [float(w) for w in re.findall(r"width='([\d.]+)'", svg)]
    assert widths[0] == pytest.approx(3 * widths[1], rel=0.01)


def application_data():
    return {"ApplicationId": 7, "ApplicationName": "billing", "BusinessUnitId": None, "BusinessUnitName": None,
            "ProductName": None, "Rating": "D", "Score": 40, "Confidence": 0.4, "Verified": True,
            "AssessedAt": datetime(2026, 10, 31), "Summary": "1 cannot run", "Description": None, "Owner": "Ops",
            "ProductOwner": None, "BusinessUnitOwner": None, "RepositoryUrl": "javascript:alert(1)",
            "SourcePath": ".", "SourceCommit": "abc",
            "components": [{"ComponentId": 1, "ComponentName": "Web", "ProjectPath": "src/Web/Web.csproj", "Role": "web",
                            "Verdict": "blocker", "VerdictText": "Not feasible", "TargetFramework": "net48",
                            "WindowsContainerOk": True, "VerifyStatus": "build-failed"}],
            "findings": [{"ComponentId": 1, "ComponentName": "Web", "RuleId": "com", "Severity": "blocker",
                          "Title": "Office automation", "Why": "COM", "Fix": "Use OpenXML", "Via": None,
                          "OnlyCommands": None, "Source": "curated",
                          "Refs": json.dumps(["https://learn.microsoft.com/x", "javascript:alert(1)"])}],
            "history": [{"AssessedAt": datetime(2026, 10, 31), "Rating": "D", "Score": 40}]}


def test_application_page():
    html = webui.render_application(application_data())
    assert "Effort" not in html and "person-day" not in html
    assert "Office automation" in html and "Use OpenXML" in html and "Main obstacles" in html
    assert "href='https://learn.microsoft.com/x'" in html
    assert "href='javascript" not in html             # only http(s) links
    assert "Low" in html and "confirmed by building and running" in html
    assert "Windows container is a workable stop-gap" in html


class FakeConn:
    def __init__(self, data):
        self.data = data

    def cursor(self, as_dict=False):
        return FakeCursor(self.data)

    def close(self):
        pass


class FakeCursor:
    def __init__(self, data):
        self.data, self.rows = data, []

    def execute(self, sql, params=()):
        a = application_data()
        if "FROM cz.vApplicationLatest WHERE ApplicationId" in sql:
            self.rows = [a] if params[0] == 7 else []
        elif "FROM cz.vComponentLatest WHERE" in sql:
            self.rows = a["components"]
        elif "FROM cz.vFindingLatest WHERE ApplicationId" in sql:
            self.rows = a["findings"]
        elif "FROM cz.ApplicationAssessment" in sql:
            self.rows = a["history"]
        elif "FROM cz.vApplicationLatest" in sql:
            self.rows = overview_data()["apps"]
        else:
            self.rows = []

    def fetchall(self):
        return self.rows


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webui.make_handler(lambda: FakeConn(None)))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _get(url, method="GET"):
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=10)
        return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def test_http_pages_and_headers(server):
    s, h, body = _get(server + "/")
    assert s == 200 and "Containerization readiness" in body
    assert "default-src 'none'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY"
    assert h["Server"] == "containerizer"
    assert _get(server + "/app/7")[0] == 200
    assert _get(server + "/app/8")[0] == 404
    assert _get(server + "/app/x")[0] == 404
    assert _get(server + "/static/app.css")[1]["Content-Type"].startswith("text/css")
    assert _get(server + "/?bu=1%3BDROP")[0] == 200   # ignored, not passed anywhere
    assert _get(server + "/", "POST")[0] == 405


def test_http_errors_hide_details():
    def broken():
        raise RuntimeError("password=secret")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webui.make_handler(broken))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        s, _, body = _get(f"http://127.0.0.1:{httpd.server_address[1]}/")
        assert s == 500 and "secret" not in body
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------
# integration with a real SQL Server

ADMIN = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@pytest.fixture(scope="module")
def db():
    """A fresh database with the schema; yields its admin connection string."""
    name = "cztest_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)        # idempotent
    for login, role in (("cz_t_reader", "reader"), ("cz_t_writer", "writer"), ("cz_t_editor", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()
    yield cs
    m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
    m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
    m.close()


def _as(cs, login):
    return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)


@needs_sql
def test_store_maps_components_and_keeps_human_mapping(db, tmp_path):
    web_app(tmp_path / "shop")
    write(tmp_path / "shop", "src/Worker/Worker.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Worker">
          <PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>
        </Project>""")
    write(tmp_path / "shop", "src/Worker/Program.cs", "class P { static void Main() { } }")
    a = assess(tmp_path / "shop")
    writer = _as(db, "cz_t_writer")
    ids = sqlstore.store_results(writer, [a], [tmp_path / "shop"], password="Test-Passw0rd!x")
    assert len(ids) == 1

    # a person maps the application, as an administrator does on the admin pages
    ed = sqlstore.connect(_as(db, "cz_t_editor"), password="Test-Passw0rd!x")
    ed.set_user("jane@example.com", "Jane Doe")
    cur = ed.cursor()
    cur.execute("INSERT cz.BusinessUnit (Name) VALUES (N'Retail')")
    cur.execute("INSERT cz.Product (Name, BusinessUnitId) SELECT N'Web shop', BusinessUnitId FROM cz.BusinessUnit WHERE Name = N'Retail'")
    cur.execute("UPDATE cz.Application SET ProductId = (SELECT ProductId FROM cz.Product WHERE Name = N'Web shop'), "
                "DisplayName = N'Web Shop' WHERE Name = N'shop'")
    ed.commit()
    with pytest.raises(Exception):
        cur.execute("UPDATE cz.ApplicationAssessment SET Rating = 'A'")
    with pytest.raises(Exception):
        cur.execute("DELETE cz.AuditLog")
    with pytest.raises(Exception):     # the signed-in user cannot be swapped on the same connection
        cur.execute("EXEC sp_set_session_context @key = N'containerizer.user', @value = N'mallory'")
    ed.close()

    # a second scan reuses the application and components and leaves the mapping alone
    sqlstore.store_results(writer, [a], [tmp_path / "shop"], password="Test-Passw0rd!x")
    rd = sqlstore.connect(_as(db, "cz_t_reader"), password="Test-Passw0rd!x")
    try:
        ov = webui.load_overview(rd)
        assert len(ov["apps"]) == 1
        app = ov["apps"][0]
        assert (app["ApplicationName"], app["ProductName"], app["BusinessUnitName"]) == ("Web Shop", "Web shop", "Retail")
        assert app["Rating"] == a.rating and app["Components"] == len(a.components)
        detail = webui.load_application(rd, app["ApplicationId"])
        assert {c["ProjectPath"] for c in detail["components"]} == {c.project.rel for c in a.components}
        assert len(detail["history"]) == 2
        assert "Web Shop" in webui.render_application(detail)
        assert "Retail" in webui.render_overview(ov)
        with pytest.raises(Exception):
            rd.cursor().execute("SELECT ReportJson FROM cz.ApplicationAssessment")
    finally:
        rd.close()
    adm = sqlstore.connect(db)
    cur = adm.cursor()
    cur.execute("SELECT COUNT(*) FROM cz.Application")
    assert cur.fetchone()[0] == 1
    cur.execute("SELECT COUNT(*) FROM cz.Component")
    assert cur.fetchone()[0] == len(a.components)
    # the audit trail names the person and the values before and after; the second scan added nothing
    cur = adm.cursor(as_dict=True)
    cur.execute("SELECT ChangedBy, ChangedByName, DbLogin, Via, TableName, Action, OldValues, NewValues FROM cz.AuditLog "
                "ORDER BY AuditId")
    log = cur.fetchall()
    assert [(r["TableName"], r["Action"], r["Via"]) for r in log] == [
        ("Application", "insert", "scan"), ("BusinessUnit", "insert", "admin UI"), ("Product", "insert", "admin UI"),
        ("Application", "update", "admin UI")]
    upd = log[-1]
    assert (upd["ChangedBy"], upd["ChangedByName"], upd["DbLogin"]) == ("jane@example.com", "Jane Doe", "cz_t_editor")
    assert json.loads(upd["OldValues"])["Product"] is None and json.loads(upd["NewValues"])["Product"] == "Web shop"
    assert log[0]["ChangedBy"] == "cz_t_writer"
    adm.close()


@needs_sql
def test_import_json(db, tmp_path):
    web_app(tmp_path / "importme", code='var t = Type.GetTypeFromProgID("Excel.Application");')
    a = assess(tmp_path / "importme")
    f = tmp_path / "assessment.json"
    f.write_text(json.dumps([sqlstore.assessment_doc(a)], default=str))
    sqlstore.import_json(_as(db, "cz_t_writer"), [f], key_prefix="https://git.example.com/x#", password="Test-Passw0rd!x")
    rd = sqlstore.connect(_as(db, "cz_t_reader"), password="Test-Passw0rd!x")
    cur = rd.cursor(as_dict=True)
    cur.execute("SELECT Rating FROM cz.vApplicationLatest WHERE ScanName = N'importme'")  # schema from the connection
    assert cur.fetchone()["Rating"] == "E"
    cur.execute("SELECT COUNT(*) AS N FROM cz.vFindingLatest WHERE ApplicationName = N'importme' AND Severity = 'blocker'")
    assert cur.fetchone()["N"] >= 1
    # migration assistant: plan and AI agent prompt, readable by the UI login
    cur.execute("SELECT ApplicationId FROM cz.vApplicationLatest WHERE ScanName = N'importme'")
    app_id = cur.fetchone()["ApplicationId"]
    migs = webui.load_migrations(rd, app_id)
    assert len(migs) == 1 and migs[0]["ItemCount"] >= 1
    assert "replace-office-automation" in migs[0]["PlanJson"]
    assert migs[0]["AgentPrompt"].startswith("# Task: make `Web`")
    assert "Prompt for an AI coding agent" in webui.render_application(webui.load_application(rd, app_id))
    rd.close()


@needs_sql
def test_member_puts_a_login_the_dba_made_in_its_role(db):
    """External database with CZ_SQL_LOGINS=existing: the owner only adds the logins to the roles (idempotent)."""
    login = "cz_t_dba_" + uuid.uuid4().hex[:6]
    m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", db), autocommit=True)
    m.cursor().execute(f"CREATE LOGIN [{login}] WITH PASSWORD = N'Dba-Passw0rd!x'")
    m.close()
    try:
        conn = sqlstore.connect(db)
        sqlstore.add_member(conn, login, "reader")
        sqlstore.add_member(conn, login, "reader")
        with pytest.raises(SqlError):
            sqlstore.add_member(conn, login, "owner")
        conn.close()
        rd = sqlstore.connect(_as(db, login), password="Dba-Passw0rd!x")
        try:
            assert isinstance(webui.load_overview(rd), dict)
            with pytest.raises(Exception):
                rd.cursor().execute("INSERT cz.BusinessUnit (Name) VALUES (N'x')")
        finally:
            rd.close()
        # the database moved to another server (a restored backup): the login there has another SID
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", db), autocommit=True)
        m.cursor().execute(f"DROP LOGIN [{login}]; CREATE LOGIN [{login}] WITH PASSWORD = N'Dba-Passw0rd!y'")
        m.close()
        conn = sqlstore.connect(db)
        sqlstore.add_member(conn, login, "reader")
        conn.close()
        sqlstore.connect(_as(db, login), password="Dba-Passw0rd!y").close()
    finally:
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", db), autocommit=True)
        m.cursor().execute(f"DROP LOGIN [{login}]")
        m.close()
