"""LLM token usage per application and component (llmusage.py, schema 43): what is written (answered calls only,
the tokens the LLM reported), what the call is tagged with, and the views Grafana reads with its usage role."""
import os
import re
import uuid
from datetime import datetime, timezone

import pytest

from containerizer import ai, llmusage


def test_only_answered_calls_with_their_reported_tokens():
    e = {"feature": "assessment", "repo": "acme/shop", "source_key": "https://git/acme/shop#", "component": "Shop.Api",
         "backend": "api", "model": "claude-opus-5-5", "input_tokens": 1200, "output_tokens": 300, "cost_usd": 0.0123456,
         "cost_known": True, "seconds": 4.21, "job": "17", "scan": "nightly"}
    r = llmusage.row(e, "llm-queue lab")
    assert r == ("https://git/acme/shop#", None, "Shop.Api", "acme/shop", "assessment", "api", "claude-opus-5-5",
                 1200, 300, 0.01235, True, 4.2, 17, "nightly", "llm-queue lab")
    assert llmusage.row({**e, "cached": True}, "x") is None                 # cost nothing now
    assert llmusage.row({**e, "error": True}, "x") is None
    assert llmusage.row({**e, "input_tokens": 0, "output_tokens": 0}, "x") is None
    assert llmusage.row({"input_tokens": 5}, "x")[4] == "other"


def test_calls_are_tagged_with_the_application_component_and_job(monkeypatch, tmp_path):
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "api")
    monkeypatch.setattr(ai, "_ask_api", lambda prompt, schema, model, effort, system: (
        {"ok": True}, {"input_tokens": 900, "output_tokens": 100}))
    seen = []
    ai.LISTENERS.append(seen.append)
    try:
        with ai.usage_scope(feature="refactor-queued", repo="acme/shop", source_key="k#", application_id=7, job=42):
            with ai.usage_scope(component="Shop.Web"):
                ai.ask_json("q1", {"type": "object"})
            ai.ask_json("q1", {"type": "object"})               # cached: recorded, not written
    finally:
        ai.LISTENERS.remove(seen.append)
    assert seen[0]["component"] == "Shop.Web" and seen[0]["application_id"] == 7 and seen[0]["job"] == 42
    assert seen[0]["source_key"] == "k#" and seen[0]["input_tokens"] == 900 and not seen[0].get("cached")
    assert seen[1]["cached"] and "component" not in seen[1]
    rows = [llmusage.row(e, "w") for e in seen]
    assert rows[1] is None and rows[0][1] == 7 and rows[0][2] == "Shop.Web" and rows[0][12] == 42


def test_the_recorder_never_breaks_a_call():
    logs, calls = [], {"n": 0}

    class Conn:
        def cursor(self):
            return self

        def execute(self, sql, params):
            calls["n"] += 1
            raise RuntimeError("db away")

        def commit(self):
            pass

        def close(self):
            pass
    rec = llmusage.Recorder(lambda: Conn(), "worker w1", log=logs.append)
    e = {"input_tokens": 10, "output_tokens": 2, "feature": "assessment"}
    rec(e)
    rec(e)
    assert calls["n"] == 4 and rec.written == 0 and len(logs) == 1 and "db away" in logs[0]   # retried once, logged once


ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_usage_rows_and_the_views_grafana_reads():
    """The writer inserts; vLlmUsage resolves the application by SourceKey or ApplicationId, with its product and
    business unit as mapped now; vLlmUsageDaily sums by day; the usage role reads those two views and nothing else."""
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czusage_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    try:
        sqlstore.init_schema(conn)
        sqlstore.init_schema(conn)                          # idempotent
        for login, role in (("cz_u_writer", "writer"), ("cz_u_grafana", "usage")):
            sqlstore.create_login(conn, login, pw, role)
        cur = conn.cursor()
        cur.execute("INSERT cz.BusinessUnit (Name) VALUES (N'Retail'); "
                    "INSERT cz.Product (Name, BusinessUnitId) SELECT N'Stores', BusinessUnitId FROM cz.BusinessUnit; "
                    "INSERT cz.Application (Name, SourceKey, ProductId) SELECT N'shop', N'https://git/acme/shop#', ProductId "
                    "FROM cz.Product; INSERT cz.Application (Name, SourceKey) VALUES (N'crm', N'https://git/acme/crm#')")
        conn.commit()
        cur.execute("SELECT ApplicationId FROM cz.Application WHERE Name = N'crm'")
        crm = int(cur.fetchone()[0])

        def as_(login):
            return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
        rec = llmusage.Recorder(lambda: sqlstore.connect(as_("cz_u_writer"), pw), "worker test")
        base = {"feature": "assessment", "backend": "api", "model": "m", "cost_usd": 0.01, "seconds": 2.0}
        rec({**base, "source_key": "https://git/acme/shop#", "component": "Shop.Api", "input_tokens": 1000, "output_tokens": 200})
        rec({**base, "source_key": "https://git/acme/shop#", "component": "Shop.Web", "input_tokens": 500, "output_tokens": 50})
        rec({**base, "application_id": crm, "feature": "refactor-queued", "job": 3, "input_tokens": 70, "output_tokens": 7})
        rec({**base, "repo": "acme/unknown", "input_tokens": 9, "output_tokens": 1})
        rec({**base, "cached": True, "input_tokens": 999, "output_tokens": 1})
        assert rec.written == 4
        rec.close()
        g = sqlstore.connect(as_("cz_u_grafana"), pw)
        try:
            c = g.cursor(as_dict=True)
            c.execute("SELECT ApplicationName, ProductName, BusinessUnitName, SUM(Tokens) AS T, COUNT(*) AS N "
                      "FROM cz.vLlmUsage GROUP BY ApplicationName, ProductName, BusinessUnitName ORDER BY ApplicationName")
            got = [(r["ApplicationName"], r["ProductName"], r["BusinessUnitName"], int(r["T"]), r["N"]) for r in c.fetchall()]
            assert got == [("acme/unknown", "(no product)", "(no business unit)", 10, 1),
                           ("crm", "(no product)", "(no business unit)", 77, 1),
                           ("shop", "Stores", "Retail", 1750, 2)]
            c.execute("SELECT Day, ApplicationName, Calls, InputTokens, OutputTokens FROM cz.vLlmUsageDaily "
                      "WHERE ApplicationName = N'shop'")
            d = c.fetchall()
            assert len(d) == 1 and d[0]["Calls"] == 2 and d[0]["InputTokens"] == 1500 and d[0]["OutputTokens"] == 250
            assert d[0]["Day"] == datetime.now(timezone.utc).date()
            # every query of the dashboard runs as the usage role (Grafana's macros and variables filled in)
            import json as _json
            from containerizer.sysagent import GRAFANA_DASHBOARD
            dash = _json.loads(GRAFANA_DASHBOARD.read_text())
            sqls = [t["rawSql"] for p in dash["panels"] for t in p.get("targets") or [] if t.get("rawSql")]
            sqls += [v["query"] for v in dash.get("templating", {}).get("list", []) if isinstance(v.get("query"), str)]
            assert any("GROUP BY Model, Backend" in q for q in sqls)
            for q in sqls:
                q = re.sub(r"\$__timeFilter\((\w+)\)", r"\1 >= '2000-01-01'", q)
                q = re.sub(r"\b(\w+) IN \(\$\w+\)", r"\1 IS NOT NULL", q).replace("containerizer.", "cz.")
                t = g.cursor()                                # stat panels have columns without names
                t.execute(q)
                t.fetchall()
            c.execute("SELECT Model, Backend, COUNT(*) AS Calls FROM cz.vLlmUsage GROUP BY Model, Backend")
            assert [(r["Model"], r["Calls"]) for r in c.fetchall()] == [("m", 4)]
            with pytest.raises(Exception):
                c.execute("SELECT TOP 1 * FROM cz.Application")         # nothing but the usage views
        finally:
            g.close()
    finally:
        conn.close()
        m = sqlstore.connect(re.sub(r"(?i)Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        for login in ("cz_u_writer", "cz_u_grafana"):
            m.cursor().execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        m.close()


@needs_sql
def test_mapping_snapshots_and_the_mapping_dashboard():
    """cz.RecordMappingSnapshot (schema 59, the end of every scan run) counts how the applications are mapped; the
    usage role reads vMappingHistory, and every query of the mapping dashboard runs as it."""
    import json as _json
    from containerizer import sqlstore
    from containerizer.sysagent import GRAFANA_DASHBOARDS
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czmap_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    try:
        sqlstore.init_schema(conn)
        sqlstore.init_schema(conn)
        for login, role in (("cz_m_writer", "writer"), ("cz_m_grafana", "usage")):
            sqlstore.create_login(conn, login, pw, role)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cz.MappingSnapshot")
        assert cur.fetchone()[0] == 1                       # the first one, made by the schema step
        cur.execute("""
            INSERT cz.OrgScan (Name, Provider, Organization, Registry) VALUES (N's', N'github', N'acme', N'r');
            DECLARE @s int = SCOPE_IDENTITY();
            INSERT cz.OrgRepository (ScanId, ProjectName, Name, CloneUrl, RepositoryUrl, ExternalAppId) VALUES
                (@s, N'_', N'shop', N'https://g/acme/shop.git', N'https://g/acme/shop', N'APP-1'),
                (@s, N'_', N'crm', N'https://g/acme/crm.git', N'https://g/acme/crm', NULL),
                (@s, N'_', N'new', N'https://g/acme/new.git', N'https://g/acme/new', N'APP-9'),
                (@s, N'_', N'pay', N'https://g/acme/pay.git', N'https://g/acme/pay', N'APP-3');
            INSERT cz.Product (Name, ExternalId) VALUES (N'Stores', N'APP-1');
            INSERT cz.Product (Name) VALUES (N'Back office');
            INSERT cz.Application (Name, SourceKey, RepositoryUrl) VALUES
                (N'shop', N'https://g/acme/shop#', N'https://g/acme/shop'),
                (N'crm', N'https://g/acme/crm#', N'https://g/acme/crm'),
                (N'pay', N'https://g/acme/pay#', N'https://g/acme/pay'),
                (N'old', N'https://g/acme/old#', N'https://g/acme/old');
            UPDATE cz.Application SET ProductId = (SELECT ProductId FROM cz.Product WHERE Name = N'Back office')
            WHERE Name = N'crm';""")
        conn.commit()
        cur.execute("EXEC cz.MapProductExternalIds")       # shop: by its repository's metadata.json
        conn.commit()

        def as_(login):
            return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
        wr = sqlstore.connect(as_("cz_m_writer"), pw)
        wr.cursor().execute("EXEC cz.RecordMappingSnapshot")
        wr.commit()
        wr.close()
        g = sqlstore.connect(as_("cz_m_grafana"), pw)
        try:
            c = g.cursor(as_dict=True)
            c.execute("SELECT TOP (1) * FROM cz.vMappingHistory ORDER BY At DESC, Repositories DESC")
            r = c.fetchone()
            assert {k: r[k] for k in ("Repositories", "ReposDeclaring", "ReposDeclaringNoApp", "Applications", "AppsWithId",
                                      "AppsByExternalId", "AppsByProject", "AppsByHand", "AppsNoProduct",
                                      "IdsWithoutProduct")} == {
                "Repositories": 4, "ReposDeclaring": 3, "ReposDeclaringNoApp": 1, "Applications": 4, "AppsWithId": 2,
                "AppsByExternalId": 1, "AppsByProject": 0, "AppsByHand": 1, "AppsNoProduct": 2, "IdsWithoutProduct": 1}
            path = next(p for p, key, _ in GRAFANA_DASHBOARDS if key == "dashboard-mapping")
            dash = _json.loads(path.read_text())
            sqls = [t["rawSql"] for p in dash["panels"] for t in p.get("targets") or [] if t.get("rawSql")]
            assert len(sqls) == 9
            for q in sqls:
                q = re.sub(r"\$__timeFilter\((\w+)\)", r"\1 >= '2000-01-01'", q).replace("containerizer.", "cz.")
                t = g.cursor()
                t.execute(q)
                assert t.fetchall()
            with pytest.raises(Exception):
                c.execute("SELECT TOP 1 * FROM cz.MappingSnapshot")     # the view only
        finally:
            g.close()
    finally:
        conn.close()
        m = sqlstore.connect(re.sub(r"(?i)Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        for login in ("cz_m_writer", "cz_m_grafana"):
            m.cursor().execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        m.close()
