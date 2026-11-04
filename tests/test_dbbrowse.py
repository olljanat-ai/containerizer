"""The database browser of Admin -> Dev databases (dbbrowse.py, admin_dbbrowse.py), without a cluster: statements and
quoting per engine, the clients' output, the caps, the system agent's checks and answers, deleting a database, and the
pages by role. The clients against real servers are in test_dbbrowse_real.py."""
from __future__ import annotations

import base64
import json
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit

import pytest

from containerizer import admin_dbbrowse as B
from containerizer import dbbrowse as D
from containerizer import labservices as L
from containerizer.admin import Admin, render_audit
from containerizer.appliance import SystemPage
from containerizer.oidc import OidcConfig

NS = "parts-catalog"
VARIANT = "parts-catalog-refactor-7"
PW = "Abcdefgh12345678Zyxw"


# =============================================================================== quoting and statements

def test_literals_and_identifiers_per_engine():
    assert D.literal("sqlserver", "O'Brien") == "N'O''Brien'"
    assert D.literal("postgres", "O'Brien") == "'O''Brien'"
    assert D.literal("postgres", "a\\b'c") == "E'a\\\\b''c'"
    assert D.literal("mysql", "O'B\\") == "_utf8mb4 X'" + "O'B\\".encode().hex() + "'"
    assert D.literal("mysql", "") == "''"
    for eng in D.ENGINES:
        assert D.literal(eng, None) == "NULL"
        with pytest.raises(D.DbError):
            D.literal(eng, "a\x00b")
    assert D.ident("sqlserver", "a]b") == "[a]]b]" and D.ident("mysql", "a`b") == "`a``b`" and D.ident("postgres", 'a"b') == '"a""b"'
    with pytest.raises(D.DbError):
        D.ident("postgres", "")
    assert D.table_ref("mysql", "whatever", "parts") == "`parts`"            # always the app's own database
    assert D.table_ref("sqlserver", "dbo", "Parts") == "[dbo].[Parts]"
    # wildcards in a "contains" filter are literal
    assert D.contains("sqlserver", "[Name]", "5%_[") == "CAST([Name] AS nvarchar(max)) LIKE N'%5!%!_![%' ESCAPE '!'"
    assert D.contains("postgres", '"name"', "a!b") == "CAST(\"name\" AS text) ILIKE '%a!!b%' ESCAPE '!'"
    assert D.contains("mysql", "`n`", "x").startswith("CAST(`n` AS CHAR) LIKE _utf8mb4 X'")


COLS = [D.Column("Id", "int", False, None, True, False, 1), D.Column("Sku", "nvarchar(40)", False),
        D.Column("Note", "nvarchar(max)"), D.Column("Ver", "timestamp", True, None, False, True),
        D.Column("Img", "varbinary(16)")]


def test_statements_by_primary_key():
    key = {"Id": "7"}
    assert D.update_sql("sqlserver", "dbo", "Parts", COLS, key, {"Note": "it's", "Sku": None}) == \
        "UPDATE [dbo].[Parts] SET [Note] = N'it''s', [Sku] = NULL WHERE [Id] = N'7'"
    assert D.delete_sql("postgres", "public", "parts", COLS, key) == 'DELETE FROM "public"."parts" WHERE "Id" = \'7\''
    assert D.insert_sql("mysql", "x", "parts", COLS, {"Sku": "A"}) == "INSERT INTO `parts` (`Sku`) VALUES (_utf8mb4 X'41')"
    assert D.insert_sql("sqlserver", "dbo", "Parts", COLS, {}) == "INSERT INTO [dbo].[Parts] DEFAULT VALUES"
    assert D.insert_sql("mysql", "x", "parts", COLS, {}) == "INSERT INTO `parts` () VALUES ()"
    for bad in ({"Ver": "1"}, {"Img": "0x00"}, {"Nope": "1"}):          # computed, binary, unknown: never written
        with pytest.raises(D.DbError):
            D.update_sql("sqlserver", "dbo", "Parts", COLS, key, bad)
    with pytest.raises(D.DbError):
        D.update_sql("sqlserver", "dbo", "Parts", COLS, {"Sku": "x"}, {"Note": "n"})     # not the primary key
    with pytest.raises(D.DbError):
        D.update_sql("sqlserver", "dbo", "Parts", COLS, key, {})
    assert D.read_only_reason(COLS) is None
    assert "primary key" in D.read_only_reason([D.Column("a", "int")])
    assert "view" in D.read_only_reason(COLS, "view")
    assert "binary" in D.read_only_reason([D.Column("k", "varbinary(8)", pk=1)])


def test_rows_page_per_engine():
    sql = D.rows_sql("sqlserver", "dbo", "Parts", COLS, ("Sku", "contains", "a"), "Sku", True, 50, 51)
    assert sql.endswith("WHERE CAST([Sku] AS nvarchar(max)) LIKE N'%a%' ESCAPE '!' ORDER BY [Sku] DESC OFFSET 50 ROWS FETCH NEXT 51 ROWS ONLY")
    assert "[Ver]" in sql
    assert D.rows_sql("sqlserver", "dbo", "T", [D.Column("a", "int")]).endswith("ORDER BY (SELECT NULL) OFFSET 0 ROWS FETCH NEXT 51 ROWS ONLY")
    assert D.rows_sql("postgres", "public", "parts", COLS).endswith('ORDER BY "Id" LIMIT 51 OFFSET 0')
    assert 'WHERE "Note" IS NULL' in D.rows_sql("postgres", "public", "parts", COLS, ("Note", "null", ""))
    assert "WHERE `Sku` = _utf8mb4 X'41'" in D.rows_sql("mysql", "", "parts", COLS, ("Sku", "eq", "A"))
    assert D.rows_sql("postgres", "public", "parts", COLS, limit=10_000).endswith("LIMIT 500 OFFSET 0")     # the row cap
    with pytest.raises(D.DbError):
        D.rows_sql("postgres", "public", "parts", COLS, ("Evil", "eq", "1"))
    geo = D.rows_sql("sqlserver", "dbo", "T", [D.Column("g", "geography"), D.Column("x", "xml")])
    assert "[g].ToString() AS [g]" in geo and "CAST([x] AS nvarchar(max)) AS [x]" in geo


def test_parse_columns():
    res = {"columns": ["name", "type", "nullable", "default", "auto", "generated", "pk"],
           "rows": [["Id", "int", "0", None, "1", "0", "1"], ["Ver", "timestamp", "0", None, "0", "1", None]]}
    cols = D.parse_columns(res)
    assert cols[0].pk == 1 and cols[0].auto and not cols[0].nullable and cols[1].generated and not cols[1].editable


# =============================================================================== the clients' output

def test_parse_postgres_csv():
    out = 'id,name,note\n1,"a,b",NULLX\n2,"line1\nline2",""\nM 2\n'
    res = D.parse_postgres(out, "M", "NULLX")
    assert res["columns"] == ["id", "name", "note"] and res["rows"] == [["1", "a,b", None], ["2", "line1\nline2", ""]]
    assert D.parse_postgres("M 3\n", "M", "N") == {"kind": "count", "rowcount": 3}
    assert D.parse_postgres("a\n" + "".join(f"{i}\n" for i in range(600)) + "M 600\n", "M", "N", 500)["truncated"]
    with pytest.raises(D.DbError):
        D.parse_postgres("garbage", "M", "N")


def test_parse_mysql_xml():
    nil = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    out = (f'<?xml version="1.0"?>\n<resultset statement="SELECT" {nil}>\n<row>\n<field name="id">1</field>\n'
           f'<field name="note" xsi:nil="true" />\n<field name="t">a &lt;b&gt;\r\nc</field>\n</row>\n</resultset>\n'
           f'<?xml version="1.0"?>\n<resultset statement="x" {nil}>\n<row>\n<field name="M">-1</field>\n</row>\n</resultset>\n')
    res = D.parse_mysql(out, "M")
    assert res["columns"] == ["id", "note", "t"] and res["rows"] == [["1", None, "a <b>\r\nc"]]
    count = f'<?xml version="1.0"?>\n<resultset statement="x" {nil}>\n<row>\n<field name="M">4</field>\n</row>\n</resultset>\n'
    assert D.parse_mysql(count, "M") == {"kind": "count", "rowcount": 4}
    with pytest.raises(D.DbError):
        D.parse_mysql('<!DOCTYPE x [<!ENTITY a "b">]>' + count, "M")
    with pytest.raises(D.DbError):
        D.parse_mysql(count.replace('name="M"', 'name="other"'), "M")


def test_parse_sqlserver_json():
    cols = json.dumps([{"o": 1, "name": "Id", "t": "int"}, {"o": 2, "name": "Img", "t": "varbinary(16)"},
                       {"o": 3, "name": "On", "t": "bit"}, {"o": 4, "name": "Price", "t": "decimal(38,10)"},
                       {"o": 5, "name": None, "t": "int"}])
    rows = json.dumps([{"c1": 1, "c2": base64.b64encode(b"\x00\xff").decode(), "c3": True, "c4": 0.1234567890123456789,
                        "c5": None}]).replace("0.12345678901234568", "0.1234567890123456789")
    out = f"\n----\nM:COLS:{cols}\n\n----\nM:ROWS:1:{rows}\n"
    res = D.parse_sqlserver(out, "M")
    assert res["columns"] == ["Id", "Img", "On", "Price", "column5"]
    assert res["rows"] == [["1", "0x00FF", "1", "0.1234567890123456789", None]]        # decimals keep every digit
    assert D.parse_sqlserver("M:COUNT:12\n", "M") == {"kind": "count", "rowcount": 12}
    assert D.parse_sqlserver("M:TEXT\n", "M") == {"kind": "needs-text"}
    many = json.dumps([{"c1": i} for i in range(501)])
    capped = D.parse_sqlserver(f"M:COLS:{json.dumps([{'o': 1, 'name': 'n', 't': 'int'}])}\nM:ROWS:2000:{many}\n", "M")
    assert len(capped["rows"]) == 500 and capped["truncated"] and capped["total"] == 2000
    with pytest.raises(D.DbError):
        D.parse_sqlserver(f"M:COLS:{cols}\nM:ROWS:1:[{{\"c1\"", "M")       # cut off: larger than 1 MB


def test_mssql_wrapper_carries_the_statement_as_hex():
    stmt = "SELECT N'$(MSSQL_SA_PASSWORD)'\n:!! id\nGO"
    body = D.client_input("sqlserver", PW, stmt, "M")
    first, rest = body.split("\n", 1)
    assert first == PW
    assert "$(" not in rest and ":!!" not in rest and "GO" not in rest.replace("GOTO", "")
    assert D._mssql_hex(stmt)[2:] in rest
    assert bytes.fromhex(D._mssql_hex(stmt)[2:]).decode("utf-16-le") == stmt


def test_clients_never_get_the_password_on_the_command_line():
    for eng in D.ENGINES:
        argv = D.client_command(eng, "parts_catalog", "parts_catalog", "M", "N")
        assert PW not in " ".join(argv) and argv[0] == "/bin/sh"
        assert D.client_input(eng, PW, "SELECT 1", "M").startswith(PW + "\n")
    pg = D.client_command("postgres", "u", "d", "M", "N")
    assert '-c "$SQL"' in pg[2]                       # psql -c: never a backslash command, never interpolated
    assert D.client_input("postgres", PW, "\\! id", "M") == PW + "\n\n\\! id"     # the newline comes first
    my = D.client_command("mysql", "u", "d", "M")[2]
    assert "--binary-mode" in my and "--local-infile=0" in my and "--no-defaults" in my
    with pytest.raises(D.DbError):
        D.run_statement(D.Target("postgres", [], "u;x", "d", PW), "SELECT 1", runner=lambda *a: (0, "", "", ""))
    with pytest.raises(D.DbError):
        D.run_statement(D.Target("postgres", [], "u", "d", "short"), "SELECT 1", runner=lambda *a: (0, "", "", ""))


def test_run_capped_limits_size_and_time():
    py = sys.executable
    rc, out, err, problem = D.run_capped([py, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"], "abc")
    assert (rc, out, problem) == (0, "ABC", "")
    *_, problem = D.run_capped([py, "-c", "import sys; sys.stdout.write('x' * 3_000_000)"], "", cap=D.MAX_BYTES)
    assert problem == "too large"
    t0 = time.time()
    *_, problem = D.run_capped([py, "-c", "import time; time.sleep(30)"], "", timeout=0.5)
    assert problem == "timeout" and time.time() - t0 < 10


def test_run_statement_reports_errors_without_the_password():
    def runner(argv, stdin, timeout=0, cap=0):
        return 1, "", f"ERROR: relation \"x\" does not exist (password {PW})", ""
    with pytest.raises(D.DbError) as ex:
        D.run_statement(D.Target("postgres", ["kubectl"], "u", "d", PW), "SELECT * FROM x", runner=runner)
    assert "does not exist" in str(ex.value) and PW not in str(ex.value)
    for problem, text in (("timeout", "seconds"), ("too large", "1 MB")):
        with pytest.raises(D.DbError) as ex:
            D.run_statement(D.Target("postgres", [], "u", "d", PW), "SELECT 1", runner=lambda *a, p=problem: (0, "", "", p))
        assert text in str(ex.value)


# =============================================================================== the system agent

class FakeKube:
    cmd = ["kubectl"]
    kubeconfig = "/etc/rancher/k3s/k3s.yaml"

    def __init__(self, devdb_engine="postgres"):
        self.runs = []
        self.devdb_engine = devdb_engine

    def get(self, args):
        if args[:3] == ["-n", "containerizer-secrets", "secret"]:
            key = args[3]
            ns = key.split("--")[0]
            name = L.db_name(ns)
            return {"data": {k: base64.b64encode(v.encode()).decode() for k, v in
                             {"username": name, "database": name, "password": PW}.items()}}
        if args[:2] == ["-n", "containerizer-lab"] and args[2] == "pods":
            return {"items": [_pod("sqlserver-abc")]}
        if args[2:3] == ["pods"]:
            return {"items": [_pod("devdb-xyz", {D.DEVDB_ANNOTATION: f"{self.devdb_engine}:ShopDb"})]}
        if args[2:4] == ["secret", "devdb"]:
            return {"data": {"password": base64.b64encode(PW.encode()).decode()}}
        if args[2:3] == ["deployments"]:
            return {"items": [{"metadata": {"name": "parts-api"}}, {"metadata": {"name": "devdb"}},
                              {"metadata": {"name": "parts-web"}}]}
        return None

    def run(self, args, input=None, check=True, timeout=None, redact=()):
        self.runs.append(args)


def _pod(name, ann=None):
    return {"metadata": {"name": name, "annotations": ann or {}},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}


def _agent(tmp_path, owned=True, ready=(NS,), runner=None, kube=None, **kw):
    st = tmp_path / "lab-status.json"
    st.write_text(json.dumps({"services": {"sqlserver": {"apps": list(ready), "ready": list(ready)}}}))
    calls = []

    def default_runner(argv, stdin, timeout=0, cap=0):
        calls.append((argv, stdin))
        return 0, f"{_marker(stdin)}:COUNT:1\n", "", ""
    owner = owned if callable(owned) else (lambda ns, app: owned)
    agent = D.Agent(kube=kube or FakeKube(), lab_status=st, owner_check=owner, runner=runner or default_runner,
                    lab_state=tmp_path / "state.json", **kw)
    return agent, calls


def _marker(stdin: str) -> str:
    import re
    m = re.search(r"N'(CZ[0-9a-f]{16}):COUNT:'", stdin)
    return m[1] if m else "none"


def _req(**kw):
    r = {"action": "dbquery", "id": "a" * 32, "application_id": 3, "source": "lab", "engine": "sqlserver",
         "namespace": NS, "statements": ["UPDATE dbo.Parts SET Note = NULL"], "requested_by": "john.doe@example.com",
         "expires_at": time.time() + 45}
    r.update(kw)
    return r


def test_agent_runs_as_the_apps_login_in_the_lab(tmp_path):
    agent, calls = _agent(tmp_path)
    ans = agent.query(_req())
    assert ans == {"results": [{"ok": True, "result": {"kind": "count", "rowcount": 1}}]}
    argv, stdin = calls[0]
    assert argv[:8] == ["kubectl", "--kubeconfig=/etc/rancher/k3s/k3s.yaml", "-n", "containerizer-lab", "exec", "-i",
                        "sqlserver-abc", "-c"]
    assert argv[-2:] == ["parts_catalog", "parts_catalog"]            # the app's own login and database
    assert PW not in " ".join(argv) and stdin.startswith(PW + "\n")


def test_agent_refuses_what_is_not_the_apps(tmp_path):
    agent, calls = _agent(tmp_path)
    for bad, why in ((dict(source="x"), "kind"), (dict(engine="mongodb"), "engine"), (dict(namespace="kube-system"), "namespace"),
                     (dict(namespace="containerizer-lab"), "namespace"), (dict(namespace="A_B"), "namespace"),
                     (dict(application_id="3"), "application"), (dict(expires_at=time.time() - 1), "expired"),
                     (dict(statements=[]), "statements"), (dict(statements=["x\x00"]), "statements"),
                     (dict(statements=["a"] * 4), "statements"), (dict(namespace="other-app"), "has no database")):
        with pytest.raises(D.DbError) as ex:
            agent.query(_req(**bad))
        assert why in str(ex.value).lower(), (bad, str(ex.value))
    agent, _ = _agent(tmp_path, owned=False)
    with pytest.raises(D.DbError, match="not one of this application's"):
        agent.query(_req())

    def broken(ns, app):
        raise OSError("no database")
    agent, _ = _agent(tmp_path, owned=broken)
    with pytest.raises(D.DbError, match="could not check"):
        agent.query(_req())
    assert not calls


def test_agent_checks_the_stored_credentials(tmp_path):
    kube = FakeKube()
    orig = kube.get

    def get(args):
        d = orig(args)
        if args[:3] == ["-n", "containerizer-secrets", "secret"]:
            d["data"]["username"] = base64.b64encode(b"other_app").decode()
        return d
    kube.get = get
    agent, _ = _agent(tmp_path, kube=kube)
    with pytest.raises(D.DbError, match="not this application's"):
        agent.query(_req())


def test_agent_dev_database_from_the_pods_annotation(tmp_path):
    calls = []

    def runner(argv, stdin, timeout=0, cap=0):
        calls.append(argv)
        marker = argv[-1]
        return 0, f"{marker} 2\n", "", ""
    agent, _ = _agent(tmp_path, runner=runner)
    ans = agent.query(_req(source="devdb", engine="postgres", namespace=VARIANT, statements=["DELETE FROM t"]))
    assert ans["results"][0]["result"] == {"kind": "count", "rowcount": 2}
    assert calls[0][2:7] == ["-n", VARIANT, "exec", "-i", "devdb-xyz"] and "app" in calls[0] and "ShopDb" in calls[0]
    with pytest.raises(D.DbError, match="not SQL Server"):
        agent.query(_req(source="devdb", engine="sqlserver"))


def test_agent_request_answers_with_the_id(tmp_path):
    agent, _ = _agent(tmp_path)
    answers = tmp_path / "answers"
    D.agent_request(_req(), answers, agent)
    ans = json.loads((answers / ("a" * 32 + ".json")).read_text())
    assert ans["id"] == "a" * 32 and ans["results"][0]["ok"]
    assert oct((answers / ("a" * 32 + ".json")).stat().st_mode & 0o777) == "0o640"
    D.agent_request(_req(id="b" * 32, namespace="kube-system"), answers, agent)
    assert "namespace" in json.loads((answers / ("b" * 32 + ".json")).read_text())["error"]
    D.agent_request(_req(id="../../etc/x"), answers, agent)                # no answer for a bad id
    assert sorted(p.name for p in answers.iterdir()) == ["a" * 32 + ".json", "b" * 32 + ".json"]


def test_ask_waits_for_the_answer(tmp_path):
    (tmp_path / "requests").mkdir()
    sp = SystemPage(status_dir=tmp_path)
    agent, _ = _agent(tmp_path)
    stop = threading.Event()

    def fake_sysagent():                                                  # what containerizer-sysagent.path starts
        while not stop.is_set():
            for f in sorted((tmp_path / "requests").glob("*.json")):
                req = json.loads(f.read_text())
                f.unlink()
                D.agent_request(req, tmp_path / "answers", agent)
            time.sleep(0.05)
    t = threading.Thread(target=fake_sysagent, daemon=True)
    t.start()
    try:
        ans = sp.ask("dbquery", "john.doe@example.com", "John Doe", wait=30, application_id=3, source="lab",
                     engine="sqlserver", namespace=NS, statements=["UPDATE x SET y = 1"], max_rows=10)
        assert ans["results"][0]["result"]["rowcount"] == 1
        assert not list((tmp_path / "answers").glob("*.json"))           # picked up and removed
        # too little time left to run a statement: not started at all
        ans = sp.ask("dbquery", "john.doe@example.com", "John Doe", wait=5, application_id=3, source="lab",
                     engine="sqlserver", namespace=NS, statements=["UPDATE x SET y = 1"])
        assert not ans["results"][0]["ok"] and "no longer be waiting" in ans["results"][0]["error"]
    finally:
        stop.set()
        t.join()
    t0 = time.time()
    assert sp.ask("dbquery", "u", "n", wait=0.3) is None                  # nobody answers
    assert time.time() - t0 < 2


def test_delete_lab_database_drops_and_recreates(tmp_path):
    calls = []

    def runner(argv, stdin, timeout=0, cap=0):
        calls.append((argv, stdin))
        return 0, "", "", ""
    systemctl = []
    kube = FakeKube()
    agent, _ = _agent(tmp_path, runner=runner, kube=kube, systemctl=systemctl.append)
    (tmp_path / "state.json").write_text(json.dumps({"sqlserver": {NS: "uid:mark", "other-app": "uid:x"}}))
    with pytest.raises(D.DbError, match="name"):
        agent.delete(_req(action="dbdelete", confirm="other_app"))       # the agent derives the name itself
    assert not calls
    answer, after = agent.delete(_req(action="dbdelete", confirm="parts_catalog"))
    assert answer["deleted"] == "parts_catalog"
    argv, stdin = calls[0]
    assert argv[-len(L.provision_command("sqlserver")):] == L.provision_command("sqlserver")     # as the server's admin
    assert "ALTER DATABASE [parts_catalog] SET SINGLE_USER WITH ROLLBACK IMMEDIATE" in stdin and "DROP DATABASE [parts_catalog]" in stdin
    assert json.loads((tmp_path / "state.json").read_text()) == {"sqlserver": {"other-app": "uid:x"}}   # provisioned again
    after()
    assert systemctl == [["start", "containerizer-lab.service"]] * 2                # once more after a run already going
    assert kube.runs == [["-n", NS, "rollout", "restart", "deployment/parts-api"],
                         ["-n", NS, "rollout", "restart", "deployment/parts-web"]]


def test_delete_dev_database_restores_it_again(tmp_path):
    kube = FakeKube()
    agent, calls = _agent(tmp_path, kube=kube)
    with pytest.raises(D.DbError):
        agent.delete(_req(action="dbdelete", source="devdb", engine="postgres", confirm="parts_catalog"))
    answer, after = agent.delete(_req(action="dbdelete", source="devdb", engine="postgres", confirm="ShopDb"))
    assert answer == {"deleted": "ShopDb", "message": "restore"} and after is None
    assert kube.runs == [["-n", NS, "rollout", "restart", "deployment/devdb"]] and not calls


def test_drop_scripts():
    assert "DROP DATABASE IF EXISTS \"x_y\" WITH (FORCE)" in D.drop_script("postgres", "x_y")
    assert "pg_terminate_backend" in D.drop_script("postgres", "x_y")
    assert D.drop_script("mysql", "x_y") == "DROP DATABASE IF EXISTS `x_y`;\n"
    with pytest.raises(D.DbError):
        D.drop_script("mysql", "x`; DROP")


# =============================================================================== the pages

class FakeCursor:
    def __init__(self, conn, as_dict):
        self.conn, self.as_dict, self.rows, self.rowcount = conn, as_dict, [], 0

    def execute(self, sql, params=None):
        c = self.conn
        c.log.append((sql, params))
        self.rows = []
        if "cz.vSandboxNamespace WHERE ApplicationId" in sql:
            self.rows = [{"Namespace": VARIANT, "Variant": True, "CheckedAt": "2026-11-04"},
                         {"Namespace": NS, "Variant": False, "CheckedAt": "2026-11-03"}]
        elif "FROM cz.vSandboxNamespace n JOIN" in sql:
            self.rows = [{"Namespace": NS, "ApplicationId": 3, "AppName": "parts-catalog"}]
        elif "FROM cz.DevDatabase" in sql:
            self.rows = []
        elif "COALESCE(DisplayName, Name) AS N FROM cz.Application" in sql:
            self.rows = [{"N": "parts-catalog"}] if params[0] == 3 else []
        elif sql.startswith("INSERT cz.DatabaseEdit"):
            if c.record_fails:
                raise RuntimeError("Invalid object name 'cz.DatabaseEdit'")
            c.edits.append(params)
            self.rows = [(len(c.edits),)]
        elif sql.startswith("UPDATE cz.DatabaseEdit"):
            c.outcomes.append(params)
        elif "FROM cz.DatabaseEdit" in sql:
            self.rows = []
        elif sql.startswith("INSERT cz.AccessLog"):
            c.access.append(params)
        elif "FROM cz.Application WHERE ApplicationId" in sql:
            self.rows = [{"ApplicationId": 3, "Name": "parts-catalog", "DisplayName": None, "RepositoryUrl": None,
                          "SourcePath": None}]
        elif "cz.BusinessUnit" in sql or "cz.Product" in sql:
            self.rows = []
        if not self.as_dict:
            self.rows = [tuple(r.values()) if isinstance(r, dict) else r for r in self.rows]

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    def __init__(self):
        self.log, self.edits, self.outcomes, self.access, self.record_fails = [], [], [], [], False

    def cursor(self, as_dict=False):
        return FakeCursor(self, as_dict)

    def set_user(self, *a, **kw):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


TABLES = {"kind": "rows", "columns": ["schema", "name", "kind", "rows"], "rows": [["dbo", "Parts", "table", "3"]]}
COLUMNS = {"kind": "rows", "columns": ["name", "type", "nullable", "default", "auto", "generated", "pk"],
           "rows": [["Id", "int", "0", None, "1", "0", "1"], ["Sku", "nvarchar(40)", "0", None, "0", "0", None],
                    ["Note", "nvarchar(max)", "1", None, "0", "0", None]]}
ROWS = {"kind": "rows", "columns": ["Id", "Sku", "Note"], "rows": [["1", "PC-<1>", None], ["2", "PC-2", "multi\nline"]]}


class FakeSystem:
    def __init__(self, tmp_path):
        self.status_dir = tmp_path
        (tmp_path / "lab-status.json").write_text(json.dumps(
            {"services": {"sqlserver": {"apps": [NS, VARIANT], "ready": [NS, VARIANT]}}}))
        self.asked = []
        self.answer = None

    def pending(self):
        return []

    def ask(self, action, user, name, wait=45, **args):
        self.asked.append((action, user, args))
        if self.answer is not None:
            return self.answer
        if action == "dbdelete":
            return {"deleted": "parts_catalog", "message": "recreate"}
        out = []
        for st in args["statements"]:
            if "sys.objects" in st:
                out.append({"ok": True, "result": TABLES})
            elif "sys.columns" in st:
                out.append({"ok": True, "result": COLUMNS})
            elif st.startswith("SELECT"):
                out.append({"ok": True, "result": ROWS})
            elif st.startswith("BAD"):
                out.append({"ok": False, "error": "Incorrect syntax near 'BAD'."})
            else:
                out.append({"ok": True, "result": {"kind": "count", "rowcount": 1}})
        return {"results": out}


@pytest.fixture()
def site(tmp_path):
    B._cache.clear()
    conn = FakeConn()
    adm = Admin(OidcConfig(issuer="https://idp.example.com", client_id="c", client_secret=None,
                           public_url="https://cz.example.com", admins=[]), lambda: conn, provider=object())
    adm.system = FakeSystem(tmp_path)
    return adm, conn


def _as(adm, role):
    roles = {"admin": (True, True, False, []), "operator": (False, True, True, []), "owner": (False, True, False, ["product:Parts"]),
             "viewer": (False, True, False, [])}[role]
    sid = adm.sessions.create("john.doe@example.com", "John Doe", roles[0], roles[1], roles[2], roles[3])
    return {"Cookie": f"{adm.cookie}={sid}"}, adm.sessions.get(sid)


def _get(adm, headers, path):
    u = urlsplit(path)
    return adm.handle("GET", u.path, u.query, headers, b"")


def _post(adm, headers, s, path, fields, csrf=True):
    body = urlencode(([("csrf", s.csrf)] if csrf else []) + list(fields.items()), doseq=True).encode()
    return adm.handle("POST", path, "", headers, body)


KEY = f"lab-sqlserver@{NS}"


def test_only_admins_and_operators(site):
    adm, conn = site
    for role in ("owner", "viewer"):
        h, s = _as(adm, role)
        r = _get(adm, h, f"/admin/dev-databases/3/browse?d={KEY}")
        assert r.status == 403 and "Dev databases" not in r.body, role
        r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": KEY, "sql": "DELETE FROM x"})
        assert r.status == 403
    r = _get(adm, {}, f"/admin/dev-databases/3/browse?d={KEY}")
    assert r.status == 303 and "/login" in dict(r.headers)["Location"]            # anonymous: sign in first
    h, s = _as(adm, "operator")
    r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": KEY, "sql": "DELETE FROM x"}, csrf=False)
    assert r.status == 403 and "expired" in r.body                                 # no CSRF token
    assert not adm.system.asked and not conn.edits
    for role in ("admin", "operator"):
        h, s = _as(adm, role)
        r = _get(adm, h, "/admin/dev-databases")
        assert r.status == 200 and "Databases in the sandbox" in r.body and "/admin/dev-databases/3#databases" in r.body


def test_application_page_lists_its_databases_latest_namespace_first(site):
    adm, _ = site
    h, _s = _as(adm, "operator")
    r = _get(adm, h, "/admin/dev-databases/3")
    assert r.status == 200
    assert r.body.index(f"<td>{VARIANT}") < r.body.index(f"<td>{NS}<")
    assert "(runs a Make it A patch)" in r.body and "parts_catalog_refactor_7" in r.body


def test_tables_rows_and_editor(site):
    adm, conn = site
    h, s = _as(adm, "admin")
    r = _get(adm, h, f"/admin/dev-databases/3/browse?d={KEY}")
    assert r.status == 200 and ">dbo.Parts</a>" in r.body and "Delete database" in r.body
    assert adm.system.asked[0][2]["namespace"] == NS and adm.system.asked[0][2]["application_id"] == 3
    r = _get(adm, h, "/admin/dev-databases/3/browse?" + urlencode({"d": KEY, "schema": "dbo", "table": "Parts",
                                                                   "f": "Sku", "op": "contains", "v": "PC", "sort": "Sku"}))
    assert r.status == 200 and "PC-&lt;1&gt;" in r.body and "<span class='null'>NULL</span>" in r.body
    stmt = adm.system.asked[-1][2]["statements"][0]
    assert "LIKE N'%PC%' ESCAPE '!' ORDER BY [Sku] OFFSET 0 ROWS" in stmt
    assert "Add a row" in r.body and "Edit</a>" in r.body
    r = _get(adm, h, "/admin/dev-databases/3/browse?" + urlencode({"d": KEY, "schema": "dbo", "table": "Parts",
                                                                  "row": json.dumps({"Id": "1"})}))
    assert r.status == 200 and "name='o1' value='PC-&lt;1&gt;'" in r.body and "name='on2' value='1'" in r.body
    assert "Delete the row" in r.body
    assert not conn.edits                                                         # reads change nothing


def test_save_row_records_then_runs_only_the_changes(site):
    adm, conn = site
    h, s = _as(adm, "operator")
    base = {"d": KEY, "schema": "dbo", "table": "Parts", "key": json.dumps({"Id": "1"}), "do": "update",
            "c0": "Id", "v0": "1", "o0": "1", "c1": "Sku", "v1": "PC-1", "o1": "PC-1", "c2": "Note", "v2": "it's\r\nok", "o2": ""}
    r = _post(adm, h, s, "/admin/dev-databases/3/row", dict(base, on2="1"))
    assert r.status == 303 and "notice=saved" in dict(r.headers)["Location"]
    stmt = "UPDATE [dbo].[Parts] SET [Note] = N'it''s\nok' WHERE [Id] = N'1'"
    assert conn.edits[-1] == (3, NS, "lab", "sqlserver", "update", "dbo.Parts", stmt)
    assert adm.system.asked[-1][2]["statements"] == [stmt]
    assert conn.outcomes[-1] == ("1 row(s) affected", 1)
    # nothing changed: nothing recorded, nothing run
    r = _post(adm, h, s, "/admin/dev-databases/3/row", dict(base, v2="", n2="1", on2="1"))
    assert "notice=nochange" in dict(r.headers)["Location"] and len(conn.edits) == 1
    assert sum(a[2]["statements"][0].startswith("UPDATE") for a in adm.system.asked) == 1
    # a new row: columns left on their default are left out
    r = _post(adm, h, s, "/admin/dev-databases/3/row", {"d": KEY, "schema": "dbo", "table": "Parts", "do": "insert",
                                                        "c0": "Id", "x0": "1", "c1": "Sku", "v1": "PC-9", "c2": "Note", "n2": "1"})
    assert "notice=added" in dict(r.headers)["Location"]
    assert conn.edits[-1][-1] == "INSERT INTO [dbo].[Parts] ([Sku], [Note]) VALUES (N'PC-9', NULL)"
    # delete needs the box ticked
    r = _post(adm, h, s, "/admin/dev-databases/3/row", {"d": KEY, "schema": "dbo", "table": "Parts", "do": "delete",
                                                        "key": json.dumps({"Id": "2"})})
    assert "notice=confirm" in dict(r.headers)["Location"]
    r = _post(adm, h, s, "/admin/dev-databases/3/row", {"d": KEY, "schema": "dbo", "table": "Parts", "do": "delete",
                                                        "key": json.dumps({"Id": "2"}), "confirm": "yes"})
    assert "notice=deleted" in dict(r.headers)["Location"] and conn.edits[-1][4] == "delete"


def test_change_not_recorded_is_not_run(site):
    adm, conn = site
    h, s = _as(adm, "admin")
    conn.record_fails = True
    r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": KEY, "sql": "DELETE FROM dbo.Parts"})
    assert "schema 38" in r.body
    assert not any(a[0] == "dbquery" and a[2]["statements"] == ["DELETE FROM dbo.Parts"] for a in adm.system.asked)
    r = _post(adm, h, s, "/admin/dev-databases/3/drop", {"d": KEY, "confirm": "parts_catalog"})
    assert not any(a[0] == "dbdelete" for a in adm.system.asked)


def test_sql_results_errors_and_no_answer(site):
    adm, conn = site
    h, s = _as(adm, "admin")
    r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": KEY, "sql": "SELECT * FROM dbo.Parts"})
    assert r.status == 200 and "2 row(s)." in r.body and "multi\nline" in r.body
    assert conn.edits[-1][4:] == ("sql", None, "SELECT * FROM dbo.Parts") and adm.system.asked[-1][2]["max_rows"] == 500
    r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": KEY, "sql": "BAD <x>"})
    assert "Incorrect syntax near &#x27;BAD&#x27;." in r.body and "BAD &lt;x&gt;</textarea>" in r.body
    assert conn.outcomes[-1][0].startswith("error: Incorrect syntax")
    adm.system.answer = {}
    adm.system.ask = lambda *a, **kw: None
    r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": KEY, "sql": "SELECT 1"})
    assert "did not answer" in r.body


def test_unknown_database_or_namespace_refused(site):
    adm, _ = site
    h, s = _as(adm, "admin")
    r = _get(adm, h, "/admin/dev-databases/3/browse?d=lab-sqlserver@someone-else")
    assert r.status == 404 and "not one of this application" in r.body
    r = _post(adm, h, s, "/admin/dev-databases/3/sql", {"d": "lab-mysql@" + NS, "sql": "SELECT 1"})
    assert r.status == 404 and not adm.system.asked


def test_drop_needs_the_typed_name(site):
    adm, conn = site
    h, s = _as(adm, "operator")
    r = _post(adm, h, s, "/admin/dev-databases/3/drop", {"d": KEY, "confirm": "parts"})
    assert "notice=dropconfirm" in dict(r.headers)["Location"] and not adm.system.asked
    r = _post(adm, h, s, "/admin/dev-databases/3/drop", {"d": KEY, "confirm": "parts_catalog"})
    assert r.status == 303 and "notice=dropped-lab" in dict(r.headers)["Location"]
    action, user, args = adm.system.asked[-1]
    assert action == "dbdelete" and args["namespace"] == NS and args["confirm"] == "parts_catalog"
    assert conn.edits[-1][4] == "drop" and conn.outcomes[-1][0] == "deleted"
    r = _get(adm, h, "/admin/dev-databases/3?notice=dropped-lab")
    assert "The lab agent creates it again empty" in r.body


def test_no_lab_database_says_so(site, tmp_path):
    adm, _ = site
    (tmp_path / "lab-status.json").write_text(json.dumps({"services": {}}))
    h, _s = _as(adm, "admin")
    r = _get(adm, h, "/admin/dev-databases/3")
    assert "uses no lab-service database" in r.body and "MongoDB" in r.body
    r = _get(adm, h, f"/admin/dev-databases/3/browse?d={KEY}")
    assert r.status == 404


def test_reads_logged_only_with_view_audit(site):
    adm, conn = site
    h, _s = _as(adm, "admin")
    _get(adm, h, f"/admin/dev-databases/3/browse?d={KEY}")
    assert not conn.access
    adm.cfg.view_audit = True
    _get(adm, h, f"/admin/dev-databases/3/browse?d={KEY}")
    assert conn.access and conn.access[0][2] == "view" and conn.access[0][4] == 3


def test_change_history_shows_the_statement():
    row = {"ChangedAt": "2026-11-04", "ChangedBy": "john.doe@example.com", "ChangedByName": "John Doe",
           "ChangedByRole": "operator", "DbLogin": "cz_admin", "Via": "admin UI", "TableName": "DatabaseEdit", "RowId": 1,
           "RowName": "parts-catalog: parts-catalog", "Action": "insert", "OldValues": None,
           "NewValues": json.dumps({"ApplicationId": 3, "Namespace": NS, "Source": "lab", "Engine": "sqlserver",
                                    "Kind": "sql", "TableName": None, "Statement": "DELETE FROM <x>"})}
    html = render_audit([row])
    assert "Ran SQL in a sandbox database" in html and "Statement: DELETE FROM &lt;x&gt;" in html
    assert "Sandbox database: <b>parts-catalog: parts-catalog</b>" in html


# =============================================================================== schema 38 on SQL Server

ADMIN_SQL = __import__("os").environ.get("CONTAINERIZER_TEST_SQL")


@pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")
def test_schema_38_records_changes_in_the_history():
    import os
    import re
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czdbb_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT MAX(Version) FROM cz.SchemaVersion")
    assert cur.fetchone()[0] >= 38
    cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'k', N'parts-catalog')")
    cur.execute("SELECT ApplicationId FROM cz.Application WHERE SourceKey = N'k'")
    app_id = cur.fetchone()[0]
    cur.execute("INSERT cz.SandboxCheck (ApplicationId, Status, Namespace) VALUES (%s, N'healthy', N'parts-catalog')", (app_id,))
    conn.commit()
    sqlstore.create_login(conn, "cz_dbb_admin", pw, "admin")
    conn.close()
    adm = sqlstore.connect(re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", "User Id=cz_dbb_admin", cs), pw)
    adm.set_user("john.doe@example.com", "John Doe", role="operator")
    db = B.Db("lab", "sqlserver", "parts-catalog", database="parts_catalog")
    assert B.namespaces(adm, app_id)[0]["Namespace"] == "parts-catalog"           # the admin login reads the view
    rid = B.record(adm, app_id, db, "sql", None, "UPDATE dbo.Parts SET Note = N'x'")
    assert rid
    B.outcome(adm, rid, "3 row(s) affected")
    c = adm.cursor(as_dict=True)
    c.execute("SELECT ChangedBy, Outcome FROM cz.DatabaseEdit WHERE DatabaseEditId = %s", (rid,))
    assert c.fetchone() == {"ChangedBy": "john.doe@example.com", "Outcome": "3 row(s) affected"}
    c.execute("SELECT ChangedBy, ChangedByRole, TableName, RowName, Action, NewValues FROM cz.AuditLog "
              "WHERE TableName = N'DatabaseEdit'")
    logs = c.fetchall()
    assert len(logs) == 1                                                         # the outcome is not audited again
    log = logs[0]
    assert (log["ChangedBy"], log["ChangedByRole"], log["Action"]) == ("john.doe@example.com", "operator", "insert")
    assert log["RowName"] == "parts-catalog: parts-catalog"
    assert json.loads(log["NewValues"])["Statement"] == "UPDATE dbo.Parts SET Note = N'x'"
    with pytest.raises(Exception):                                                # what was recorded stays
        c.execute("UPDATE cz.DatabaseEdit SET Statement = N'nothing' WHERE DatabaseEditId = %s", (rid,))
    adm.rollback()
    with pytest.raises(Exception):
        c.execute("DELETE FROM cz.DatabaseEdit")
    adm.rollback()
    adm.close()
