"""Suspected Containerizer bugs (bugreports.py): flagging, the page, the export and its anonymization."""
import gzip
import json
import os
import random
import re
import uuid
from datetime import datetime

import pytest

from containerizer import bugreports as br
from containerizer import verifylog


def test_keywords_and_anonymization():
    kws = br.parse_keywords("Contoso\n\n contoso \nexpense-claims\nx\nbuild01.contoso.local\r\n")
    assert kws == ["build01.contoso.local", "expense-claims", "Contoso"]            # longest first, once, 2+ characters
    replace, counts = br.anonymizer(kws, random.Random(1))
    case = {"application": "expense-claims", "note": "CONTOSO feed",
            "attempts": [{"log": "GET https://build01.contoso.local/x for Contoso.Framework\ncontoso again"}],
            "paths": {"src/Contoso.Web/Web.csproj": 1}, "n": 3, "none": None}
    out = br.anonymize(case, replace)
    text = json.dumps(out)
    assert "contoso" not in text.casefold() and "expense-claims" not in text and counts["n"] == 6
    host = out["attempts"][0]["log"].split("https://")[1].split("/")[0]
    company = out["note"].split(" ")[0]
    assert re.fullmatch(r"[a-z]+-[0-9a-f]{4}", host) and re.fullmatch(r"[a-z]+-[0-9a-f]{4}", company) and host != company
    # the same word for the same keyword, whatever its case; structure and other values untouched
    assert out["attempts"][0]["log"] == f"GET https://{host}/x for {company}.Framework\n{company} again"
    assert list(out["paths"]) == [f"src/{company}.Web/Web.csproj"] and out["n"] == 3 and out["none"] is None
    # another export: other words
    again = br.anonymize(case, br.anonymizer(kws, random.Random(2))[0])
    assert again["note"] != out["note"]
    same, counts = br.anonymizer([])
    assert same("Contoso") == "Contoso" and counts["n"] == 0


def test_a_long_log_keeps_its_start_and_end():
    text = "start\n" + "x" * 1000 + "\nthe error"
    cut = br._cut(text, 100)
    assert cut.startswith("start\n") and cut.endswith("the error") and "characters left out" in cut and len(cut) < 200
    assert br._cut("short", 100) == "short"


def test_the_flag_on_the_applications_page():
    c = {"ComponentId": 5, "VerifyStatus": "build-failed"}
    assert br.flag_html(c, {}) == ""                                             # not an administrator
    ctx = {"bug_csrf": "<input type='hidden' name='csrf' value='t'>", "bugs": {}}
    html = br.flag_html(c, ctx)
    assert "action='/admin/bugs/flag/5'" in html and "Flag as a Containerizer bug" in html and "name='Note'" in html
    html = br.flag_html(c, {**ctx, "bugs": {5: 12}, "bug_notice": "flagged"})
    assert "action='/admin/bugs/unflag/5'" in html and "report #12" in html and "notice-ok" in html
    assert "notice" not in br.flag_html({"ComponentId": 6}, {**ctx, "bugs": {5: 12}, "bug_notice": "flagged"})
    from containerizer import webui
    block = webui._verify_detail({"ComponentId": 5, "VerifyStatus": "build-failed", "VerifyDetail": "a\nb"}, ctx=ctx)
    assert "Flag as a Containerizer bug" in block
    assert "Flag as" not in webui._verify_detail({"ComponentId": 5, "VerifyStatus": "build-failed", "VerifyDetail": "a\nb"})


def test_the_admin_page_and_roles():
    pytest.importorskip("jwt")
    from test_refactor import _get, _post
    from test_refactor import adm as adm_fixture
    adm = adm_fixture.__wrapped__()
    rows = [{"BugId": 3, "ApplicationId": 7, "ComponentId": 5, "App": "shop", "Component": "<Api>", "VerifyStatus": "build-failed",
             "Status": "open", "Note": "NU1301 on a <Windows> folder", "CreatedBy": "john.doe@example.com",
             "CreatedAt": datetime(2026, 11, 27, 12, 0), "ExportedAt": None, "Bytes": 900}]
    case = {"application": "shop", "component": {"name": "Api"}, "verification": {"status": "build-failed", "detail": "x"},
            "attempts": [{"attempt": 1, "stage": "build", "log": "restore from https://pkgs.contoso.example/ failed"}]}
    adm.conn.answers = {r"DATALENGTH\(DataGz\)": rows, r"SELECT Keywords FROM cz.BugReportSettings": [{"Keywords": "contoso\nshop"}],
                        r"SELECT BugId, Status, Note, CreatedAt, DataGz": [
                            {"BugId": 3, "Status": "open", "Note": "seen at Contoso", "CreatedAt": datetime(2026, 11, 27, 12, 0),
                             "DataGz": gzip.compress(json.dumps(case).encode())}]}
    a = adm.sessions.create("a@example.com", "A", True)
    page = _get(adm, a, "/admin/bugs")
    assert page.status == 200 and "&lt;Api&gt;" in page.body and "NU1301 on a &lt;Windows&gt; folder" in page.body
    assert "Export JSON" in page.body and "2 keywords" in page.body and ">contoso\nshop</textarea>" in page.body
    assert "href='/admin/bugs'" in page.body                                     # the tab
    r = _get(adm, a, "/admin/bugs/export.json")
    data = json.loads(r.body)
    assert r.status == 200 and data["format"] == "containerizer-bug-reports/1" and data["anonymized"]["keywords"] == 2
    text = json.dumps(data["reports"]).casefold()
    assert "contoso" not in text and "shop" not in text and data["anonymized"]["replacements"] == 3
    assert data["reports"][0]["id"] == 3 and "attachment" in dict(r.headers)["Content-Disposition"]
    assert adm.conn.sql(r"UPDATE cz.BugReport SET ExportedAt")
    assert _post(adm, a, "/admin/bugs/keywords", Keywords="b\nContoso\ncontoso").status in (302, 303)
    assert adm.conn.sql(r"BugReportSettings")[-1][1] == ("Contoso",)
    assert _post(adm, a, "/admin/bugs/3/close").status in (302, 303) and adm.conn.sql(r"SET Status = %s")[-1][1] == ("closed", 3)
    assert _post(adm, a, "/admin/bugs/3/remove").status in (302, 303) and adm.conn.sql(r"DELETE FROM cz.BugReport WHERE BugId")
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _get(adm, op, "/admin/bugs").status == 403 and _post(adm, op, "/admin/bugs/flag/5").status == 403
    assert "href='/admin/bugs'" not in _get(adm, op, "/admin/refactoring").body


def test_flagging_and_exporting_in_sql_server():
    """Schema 65 with the roles' real grants: an administrator flags a failed component (its logs are copied), flags it
    again (replaced), exports with keywords; the report survives the next scan's logs; operators' logins (the reader
    and the writer) have no access. Needs CONTAINERIZER_TEST_SQL."""
    from containerizer import sqlstore
    admin_sql = os.environ.get("CONTAINERIZER_TEST_SQL")
    if not admin_sql:
        pytest.skip("set CONTAINERIZER_TEST_SQL to run against SQL Server")
    name = "czbug_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", admin_sql)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_bug_reader", "reader"), ("cz_bug_writer", "writer"), ("cz_bug_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    cur = conn.cursor()
    cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'shop', N'contoso-shop')")
    cur.execute("INSERT cz.ApplicationAssessment (ApplicationId, Rating, Score, Confidence, Summary, ToolVersion, SourceCommit) "
                "SELECT ApplicationId, 'B', 70, 0.9, N'x', N'0.54.7', N'abcdef0123456789' FROM cz.Application")
    cur.execute("INSERT cz.Component (ApplicationId, ProjectPath, Name) SELECT ApplicationId, N'src/Api/Api.csproj', N'Api' "
                "FROM cz.Application")
    cur.execute("INSERT cz.Component (ApplicationId, ProjectPath, Name) SELECT ApplicationId, N'src/Ok/Ok.csproj', N'Ok' "
                "FROM cz.Application")
    cur.execute("INSERT cz.ComponentAssessment (AssessmentId, ComponentId, Role, Tier, Verdict, VerdictText, Score, Confidence, "
                "WindowsContainerOk, VerifyStatus, VerifyDetail) SELECT a.AssessmentId, c.ComponentId, N'web', N'server', "
                "N'config', N'Needs configuration', 80, 0.9, 0, CASE c.Name WHEN N'Api' THEN N'build-failed' ELSE N'ok' END, "
                "N'error NU1301' FROM cz.ApplicationAssessment a CROSS JOIN cz.Component c")
    cur.execute("INSERT cz.Finding (AssessmentId, ComponentId, RuleId, Severity, RuleSeverity, Title, Evidence) "
                "SELECT a.AssessmentId, c.ComponentId, N'cert-store', N'config', N'config', N'Certificate store', "
                "N'src/Api/Program.cs:3' FROM cz.ApplicationAssessment a JOIN cz.Component c ON c.Name = N'Api'")
    log = verifylog.header("docker build -t x .", "FROM mcr.microsoft.com/dotnet/sdk:10.0") + "restore from Contoso feed\nerror NU1301\n"
    cur.execute("INSERT cz.ComponentVerifyLog (AssessmentId, ComponentId, Attempt, Stage, Chars, LogGz) "
                "SELECT a.AssessmentId, c.ComponentId, 1, N'build', %s, %s FROM cz.ApplicationAssessment a "
                "JOIN cz.Component c ON c.Name = N'Api'", (len(log), gzip.compress(log.encode())))
    conn.commit()
    cur.execute("SELECT ComponentId FROM cz.Component ORDER BY Name")
    api, ok = (r[0] for r in cur.fetchall())
    as_ = lambda login: sqlstore.connect(re.sub(r"(?i)(user id|uid)\s*=[^;]*", f"User Id={login}", cs), "Test-Passw0rd!x")  # noqa: E731
    adm = as_("cz_bug_admin")
    assert br.flag(adm, ok, "", "john.doe@example.com") is None                  # nothing failed
    first = br.flag(adm, api, "first", "john.doe@example.com")
    bug = br.flag(adm, api, "restore asks a Windows folder", "john.doe@example.com")
    adm.commit()
    assert bug and bug != first
    c = adm.cursor()
    c.execute("SELECT COUNT(*) FROM cz.BugReport")
    assert c.fetchone()[0] == 1
    conn.cursor().execute("DELETE FROM cz.ComponentVerifyLog")                   # the next scan: the report keeps its copy
    conn.commit()
    c = adm.cursor()
    c.execute("INSERT cz.BugReportSettings (Id, Keywords) VALUES (1, N'contoso')")
    adm.commit()
    data = br.export(adm)
    rep = data["reports"][0]
    assert rep["id"] == bug and rep["note"] == "restore asks a Windows folder" and rep["commit"] == "abcdef012345"
    assert rep["component"]["project"] == "src/Api/Api.csproj" and rep["verification"]["status"] == "build-failed"
    assert rep["findings"] == [{"rule": "cert-store", "severity": "config", "title": "Certificate store",
                                "evidence": "src/Api/Program.cs:3"}]
    att = rep["attempts"][0]
    assert "FROM mcr.microsoft.com/dotnet/sdk:10.0" in att["dockerfile_and_command"] and "error NU1301" in att["log"]
    assert "contoso" not in json.dumps(data["reports"]).casefold() and data["anonymized"]["replacements"] == 2
    assert br.flagged(type("A", (), {"connect_admin": lambda self: as_("cz_bug_admin")})(), {"ApplicationId": rep_app(adm)}) == {api: bug}
    # a try is a job of the LLM queue's kind bugtry, and its result comes back with the report
    from containerizer import llmprompts
    from containerizer.llmqueue import SqlJobQueue
    jid = SqlJobQueue(None).add_with(adm, {"Kind": "bugtry", "App": "contoso-shop", "ApplicationId": rep_app(adm),
                                           "Component": "Api", "Priority": 1700, "DedupeKey": "t1", "RequestedBy": "john.doe@example.com",
                                           "Payload": {"bug_id": bug, "hint": "try the full image at Contoso"}})
    adm.commit()
    assert jid
    conn.cursor().execute("UPDATE cz.LlmJob SET Status = N'answered', Result = %s WHERE JobId = %s",
                          (json.dumps({"outcome": "helped", "llm": {"diagnosis": "d", "plan_patch": {"base": "full"}}}), jid))
    conn.commit()
    t = br.export(adm)["reports"][0]["tries"]
    assert len(t) == 1 and t[0]["outcome"] == "helped" and "contoso" not in t[0]["hint"].casefold()
    # a replaced system prompt: the administrator writes it, the writer (worker, queue runner) reads it
    assert llmprompts.save(adm, "refactor", "Keep every appender.", "john.doe@example.com") == "saved"
    adm.commit()
    assert llmprompts.load(as_("cz_bug_writer"))["refactor"]["text"] == "Keep every appender."
    assert br.export(adm)["replaced_system_prompts"] == {"refactor": "Keep every appender."}
    assert llmprompts.save(adm, "refactor", "", "x") == "default"
    adm.commit()
    assert llmprompts.load(adm) == {}
    for login in ("cz_bug_reader", "cz_bug_writer"):
        with pytest.raises(Exception):
            x = as_(login).cursor()
            x.execute("SELECT COUNT(*) FROM cz.BugReport")
            x.fetchall()


def rep_app(conn) -> int:
    c = conn.cursor()
    c.execute("SELECT ApplicationId FROM cz.BugReport")
    return c.fetchone()[0]


# --------------------------------------------------------------------------- let the LLM try

def _source(tmp_path):
    import subprocess
    from tests.test_engine import web_app
    root = tmp_path / "app"
    web_app(root)
    git = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *a], cwd=root,  # noqa: E731
                                    check=True, capture_output=True)
    git("init", "-q")
    git("add", "-A")
    git("commit", "-qm", "x")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, check=True).stdout.decode().strip()
    return {"type": "local", "path": str(root)}, commit


def test_the_outcome_of_a_try():
    assert br.outcome_of("ok", None) == "already-fixed" and br.outcome_of("ok-external", "ok") == "already-fixed"
    assert br.outcome_of("build-failed", None) == "nothing-to-try"
    assert br.outcome_of("build-failed", "ok") == "helped" and br.outcome_of("run-failed", "ok-external") == "helped"
    assert br.outcome_of("build-failed", "run-failed") == "further"
    assert br.outcome_of("build-failed", "build-failed") == "not-helped" and br.outcome_of("run-failed", "run-failed") == "not-helped"


def test_the_runner_tries_the_hint_and_says_whether_it_helped(tmp_path, monkeypatch):
    from containerizer import refactor as rf
    from containerizer import verify as vf
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    monkeypatch.setattr(vf, "_run", lambda *a, **k: None)                       # docker info
    source, commit = _source(tmp_path)
    pl = {"bug_id": 3, "app": "shop", "component": "Web", "project": "src/Web/Web.csproj", "source": source,
          "commit": commit, "hint": "it needs libgdiplus", "flagged_status": "run-failed"}
    seen = {"prompts": [], "patches": []}

    def ask(prompt, schema):
        seen["prompts"].append(prompt)
        return {"diagnosis": "GDI+ is missing; the patch installs it.",
                "fix_json": json.dumps({"add_packages": ["libgdiplus"], "user": "root", "base": "full"})}

    def verify(status_before, status_after):
        def run(a, c, rules, work, patch):
            seen["patches"].append(patch)
            st = status_after if patch else status_before
            return {"status": st, "attempts": [{"attempt": 1, "stage": "run" if st.startswith("run") else "build",
                                                "status": st, "log_tail": "DllNotFoundException: libgdiplus"}]}
        return run
    out = br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("run-failed", "ok"))
    res = out["result"]
    assert res["outcome"] == "helped" and out["summary"].startswith("Helped")
    assert res["llm"]["plan_patch"] == {"add_packages": ["libgdiplus"], "base": "full"}     # only build-plan keys
    assert seen["patches"] == [None, {"add_packages": ["libgdiplus"], "base": "full"}]
    assert "An administrator suggests what to try:\nit needs libgdiplus" in seen["prompts"][0]
    assert "DllNotFoundException" in seen["prompts"][0] and res["before"]["status"] == "run-failed" and res["after"]["log_tail"] == ""
    assert br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("build-failed", "build-failed"))["result"]["outcome"] == "not-helped"
    assert br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("build-failed", "run-failed"))["result"]["outcome"] == "further"
    # it already works with this version: the LLM is not asked
    seen["prompts"].clear()
    assert br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("ok", "ok"))["result"]["outcome"] == "already-fixed"
    assert not seen["prompts"]
    none = br.try_handler({"JobId": 9, "Payload": pl}, ask=lambda p, s: {"diagnosis": "code must change", "fix_json": "{}"},
                          verify=verify("build-failed", "ok"))
    assert none["result"]["outcome"] == "nothing-to-try" and "after" not in none["result"]
    gone = br.try_handler({"JobId": 9, "Payload": {**pl, "project": "src/Other/Other.csproj"}}, ask=ask, verify=verify("ok", "ok"))
    assert gone["result"]["outcome"] == "not-tried" and "not in the source" in gone["summary"]
    lost = br.try_handler({"JobId": 9, "Payload": {**pl, "commit": "0" * 40}}, ask=ask, verify=verify("ok", "ok"))
    assert lost["result"]["outcome"] == "not-tried" and not list((tmp_path / "scratch").glob("bugtry-*"))


def test_verification_takes_a_plan_patch(tmp_path, monkeypatch):
    from containerizer import verify as vf
    from containerizer.assess import assess
    from containerizer.rules import load_rules
    from tests.test_engine import web_app
    web_app(tmp_path / "app")
    a = assess(tmp_path / "app")
    plans = []
    monkeypatch.setattr(vf, "build", lambda a, c, plan, workdir, timeout: plans.append(plan) or (False, "boom", "t"))
    monkeypatch.setattr(vf, "diagnose", lambda *x, **k: None)
    try:
        vf.verify_component(a, a.components[0], load_rules(), work=tmp_path / "w", plan_patch={"env": {"TRY": "1"}})
    except Exception:  # noqa: BLE001      the fake build gives nothing to diagnose
        pass
    assert plans and plans[0]["env"]["TRY"] == "1"


def test_tries_on_the_page_and_in_the_export():
    pytest.importorskip("jwt")
    from test_refactor import _get, _post
    from test_refactor import adm as adm_fixture
    adm = adm_fixture.__wrapped__()
    rows = [{"BugId": 3, "ApplicationId": 7, "ComponentId": 5, "App": "shop", "Component": "Api", "VerifyStatus": "run-failed",
             "Status": "open", "Note": None, "CreatedBy": "john.doe@example.com", "CreatedAt": datetime(2026, 11, 27, 12, 0),
             "ExportedAt": None, "Bytes": 900}]
    case = {"application": "shop", "component": {"name": "Api", "project": "src/Api/Api.csproj"},
            "verification": {"status": "run-failed", "detail": "x"}, "attempts": []}
    jobs = [{"JobId": 21, "Status": "answered", "Error": None, "Note": None, "QueuedAt": datetime(2026, 11, 27, 12, 5),
             "FinishedAt": None, "RequestedBy": "john.doe@example.com",
             "Payload": json.dumps({"bug_id": 3, "hint": "add <libgdiplus> for Contoso"}),
             "Result": json.dumps({"outcome": "helped", "before": {"status": "run-failed"}, "after": {"status": "ok"},
                                   "llm": {"diagnosis": "GDI+ is missing at Contoso", "plan_patch": {"add_packages": ["libgdiplus"]}}})},
            {"JobId": 22, "Status": "queued", "Error": None, "Note": None, "QueuedAt": datetime(2026, 11, 27, 12, 9),
             "FinishedAt": None, "RequestedBy": "john.doe@example.com", "Payload": json.dumps({"bug_id": 3, "hint": "second"}),
             "Result": None},
            {"JobId": 23, "Status": "answered", "Error": None, "Note": None, "QueuedAt": None, "FinishedAt": None,
             "RequestedBy": None, "Payload": json.dumps({"bug_id": 99, "hint": "another report"}), "Result": "{}"}]
    adm.conn.answers = {r"DATALENGTH\(DataGz\)": rows, r"SELECT Keywords FROM cz.BugReportSettings": [{"Keywords": "contoso"}],
                        r"WHERE Kind = N'bugtry'": jobs,
                        r"SELECT BugId, Status, Note, CreatedAt, DataGz": [
                            {"BugId": 3, "Status": "open", "Note": "", "CreatedAt": datetime(2026, 11, 27, 12, 0),
                             "DataGz": gzip.compress(json.dumps(case).encode())}],
                        r"FROM cz.BugReport b JOIN cz.Application": [
                            {"BugId": 3, "ApplicationId": 7, "AssessmentId": 70, "App": "shop", "Component": "Api",
                             "DataGz": gzip.compress(json.dumps(case).encode()), "RepositoryUrl": "https://example.com/r",
                             "SourcePath": None, "SourceKey": "k", "SourceCommit": "a" * 40}],
                        r"FROM cz.OrgRepository": [{"ScanId": 4, "AppName": "shop"}],
                        r"EXEC cz.QueueLlmJob": [{"JobId": 31}]}
    a = adm.sessions.create("a@example.com", "A", True)
    page = _get(adm, a, "/admin/bugs").body
    assert "Let the LLM try" in page and "action='/admin/bugs/3/try'" in page and "another report" not in page
    assert "Helped: it builds and runs with the change" in page and "add &lt;libgdiplus&gt; for Contoso" in page
    assert "Waiting in the LLM queue" in page and "&quot;libgdiplus&quot;" in page
    data = json.loads(_get(adm, a, "/admin/bugs/export.json").body)
    t = data["reports"][0]["tries"]
    assert [x["state"] for x in t] == ["done", "queued"] and t[0]["outcome"] == "helped" and "job" not in t[0]
    assert t[0]["llm"]["plan_patch"] == {"add_packages": ["libgdiplus"]} and "contoso" not in json.dumps(t).casefold()
    r = _post(adm, a, "/admin/bugs/3/try", Hint="  use the full image  ")
    assert r.status in (302, 303) and "Queued" in dict(r.headers)["Location"]
    sql, params = adm.conn.sql(r"EXEC cz.QueueLlmJob")[-1]
    payload = json.loads([p for p in params if isinstance(p, str) and p.startswith("{")][-1])
    assert payload["hint"] == "use the full image" and payload["bug_id"] == 3 and payload["project"] == "src/Api/Api.csproj"
    assert payload["source"]["type"] == "org-clone" and payload["commit"] == "a" * 40 and "bugtry" in params
    assert "Write+what" in dict(_post(adm, a, "/admin/bugs/3/try", Hint=" ").headers)["Location"].replace("%20", "+")


# --------------------------------------------------------------------------- system prompts

def test_a_replaced_system_prompt_is_what_the_llm_gets(monkeypatch, tmp_path):
    from containerizer import ai, llmprompts
    from containerizer import refactor as rf
    from test_llm_queue import FakeConn
    known = llmprompts.prompts()
    assert set(known) == {"assessment", "refactor", "egress", "links", "replatform"} and known["refactor"][2] == rf.SYSTEM
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "api")
    seen = []
    monkeypatch.setattr(ai, "_ask_api", lambda prompt, schema, model, effort, system: seen.append(system) or ({"a": 1}, {}))
    conn = FakeConn({r"FROM cz.LlmPrompt": [{"Name": "refactor", "Text": "Keep every log4net appender.", "UpdatedBy": "a",
                                             "UpdatedAt": datetime(2026, 11, 27)},
                                            {"Name": "gone", "Text": "x", "UpdatedBy": "a", "UpdatedAt": None}]})
    try:
        before = ai.cache_key("p", {}, system=rf.SYSTEM)
        assert llmprompts.apply(conn) == 1
        ai.ask_json("p", {}, system=rf.SYSTEM)
        ai.ask_json("p2", {})                                                    # another prompt: untouched
        assert seen == ["Keep every log4net appender.", ai.SYSTEM]
        assert ai.cache_key("p", {}, system=rf.SYSTEM) != before                 # another prompt, another answer
        assert llmprompts.apply(FakeConn()) == 0 and ai.system_prompt(rf.SYSTEM) == rf.SYSTEM
    finally:
        ai.set_system_overrides(None)
    c = FakeConn()
    assert llmprompts.save(c, "refactor", "  New text \r\n", "john.doe@example.com") == "saved"
    assert c.sql(r"INSERT cz.LlmPrompt")[-1][1] == ("refactor", "New text", "john.doe@example.com")
    assert llmprompts.save(c, "refactor", rf.SYSTEM, "x") == "default" and llmprompts.save(c, "refactor", " ", "x") == "default"
    assert len(c.sql(r"INSERT cz.LlmPrompt")) == 1 and len(c.sql(r"DELETE FROM cz.LlmPrompt")) == 3
    assert llmprompts.save(c, "nope", "x", "x") == "bad"


def test_system_prompts_on_the_page_and_in_the_export():
    pytest.importorskip("jwt")
    from containerizer import refactor as rf
    from test_refactor import _get, _post
    from test_refactor import adm as adm_fixture
    adm = adm_fixture.__wrapped__()
    adm.conn.answers = {r"FROM cz.LlmPrompt": [{"Name": "refactor", "Text": "Keep <every> appender at Contoso.",
                                                "UpdatedBy": "john.doe@example.com", "UpdatedAt": datetime(2026, 11, 27, 13, 0)}],
                        r"SELECT Keywords FROM cz.BugReportSettings": [{"Keywords": "contoso"}]}
    a = adm.sessions.create("a@example.com", "A", True)
    page = _get(adm, a, "/admin/bugs").body
    assert "System prompts" in page and "Keep &lt;every&gt; appender at Contoso.</textarea>" in page
    assert "<b>replaced</b>" in page and "Back to the built-in text" in page and page.count("<span class='muted small'>built-in</span>") == 4
    assert "You are a senior software engineer who makes the smallest safe code change" in page      # the built-in, to compare
    data = json.loads(_get(adm, a, "/admin/bugs/export.json").body)
    assert list(data["replaced_system_prompts"]) == ["refactor"] and "contoso" not in json.dumps(data).casefold()
    r = _post(adm, a, "/admin/bugs/prompts/refactor", Text="Do not remove log4net appenders.")
    assert r.status in (302, 303) and "#prompt-refactor" in dict(r.headers)["Location"]
    assert adm.conn.sql(r"INSERT cz.LlmPrompt")[-1][1][:2] == ("refactor", "Do not remove log4net appenders.")
    n = len(adm.conn.sql(r"INSERT cz.LlmPrompt"))
    assert "built-in" in dict(_post(adm, a, "/admin/bugs/prompts/refactor", Text="still here", Reset="1").headers)["Location"]
    assert len(adm.conn.sql(r"INSERT cz.LlmPrompt")) == n and "<form" not in page.split("id='prompt-refactor'")[1].split("</form>")[0].split("<form", 2)[-1]
    assert _post(adm, a, "/admin/bugs/prompts/nope", Text="x").status == 404
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _post(adm, op, "/admin/bugs/prompts/refactor", Text="x").status == 403
    assert rf.SYSTEM
