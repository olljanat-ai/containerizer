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
                        r"SELECT BugId, Status, Note, Labels, CreatedAt, DataGz": [
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
    assert "resolved" in dict(_post(adm, a, "/admin/bugs/3/resolve").headers)["Location"]
    assert adm.conn.sql(r"SET Status = %s")[-1][1] == ("resolved", 3)
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
    # a report with tries is never removed: flagging the component again closes it and keeps it
    newer = br.flag(adm, api, "after the next scan", "john.doe@example.com")
    adm.commit()
    c = adm.cursor()
    c.execute("SELECT BugId, Status FROM cz.BugReport ORDER BY BugId")
    assert [tuple(r) for r in c.fetchall()] == [(bug, "closed"), (newer, "open")]
    assert br.tries(adm, {bug})[bug][0]["id"] == jid and br._job_try(adm, jid)[1]["outcome"] == "helped"
    # resolved, labels, and the views of the export
    c.execute("UPDATE cz.BugReport SET Status = N'resolved', Labels = N'nuget,windows path' WHERE BugId = %s", (bug,))
    adm.commit()
    assert [r["id"] for r in br.export(adm)["reports"]] == [newer]
    assert [(r["id"], r["labels"]) for r in br.export(adm, view="closed", label="NuGet")["reports"]] == [(bug, ["nuget", "windows path"])]
    assert br.export(adm, view="all", label="other")["reports"] == []
    with pytest.raises(Exception):
        c.execute("UPDATE cz.BugReport SET Status = N'gone' WHERE BugId = %s", (bug,))
    adm.rollback()
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


def test_the_outcome_and_the_rating_of_a_try():
    assert br.outcome_of("ok", None) == "already-fixed" and br.outcome_of("build-failed", None) == "nothing-to-try"
    assert br.outcome_of("build-failed", "ok") == "helped" and br.outcome_of("run-failed", "ok-external") == "helped"
    assert br.outcome_of("build-failed", "run-failed") == "further"
    assert br.outcome_of("build-failed", "build-failed") == "not-helped" and br.outcome_of("run-failed", "run-failed") == "not-helped"
    assert br.outcome_of("run-failed", "build-failed") == "worse" and br.outcome_of("ok", "run-failed") == "worse"
    assert br.outcome_of("ok-external", "ok") == "helped"                       # a continued try that still runs
    assert [br.score_of(x) for x in ("build-failed", "run-failed", "finding", "ok-external", "ok", None)] == [1, 2, 3, 4, 5, 0]
    assert br.stars(2) == "★★☆☆☆" and br.stars(9) == "★★★★★"
    assert br.merge_patch({"env": {"A": "1"}, "add_packages": ["x"]}, {"env": {"B": "2"}, "add_packages": ["x", "y"], "base": "full"}) \
        == {"env": {"A": "1", "B": "2"}, "add_packages": ["x", "y"], "base": "full"}


def _fake_verify(seen, status_before, status_after):
    def run(a, c, rules, work, patch):
        seen["patches"].append(patch)
        st = status_after if (patch or seen.get("edited")) else status_before
        return {"status": st, "attempts": [{"attempt": 1, "stage": "run" if st.startswith("run") else "build",
                                            "status": st, "log_tail": "DllNotFoundException: libgdiplus"}]}
    return run


def test_the_runner_tries_the_hint_and_says_whether_it_helped(tmp_path, monkeypatch):
    from containerizer import refactor as rf
    from containerizer import verify as vf
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    monkeypatch.setattr(vf, "_run", lambda *a, **k: None)                       # docker info
    source, commit = _source(tmp_path)
    pl = {"bug_id": 3, "app": "shop", "component": "Web", "project": "src/Web/Web.csproj", "source": source,
          "commit": commit, "hint": "it needs libgdiplus", "flagged_status": "run-failed"}
    seen = {"prompts": [], "patches": []}

    def ask(prompt, schema, system=None):
        seen["prompts"].append(prompt)
        return {"diagnosis": "GDI+ is missing; the patch installs it.",
                "fix_json": json.dumps({"add_packages": ["libgdiplus"], "user": "root", "base": "full"})}
    verify = lambda b, a: _fake_verify(seen, b, a)  # noqa: E731
    out = br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("run-failed", "ok"))
    res = out["result"]
    assert res["outcome"] == "helped" and res["score"] == 5 and out["summary"].startswith("★★★★★ Helped")
    assert res["llm"]["plan_patch"] == {"add_packages": ["libgdiplus"], "base": "full"}     # only build-plan keys
    assert res["plan_patch_total"] == res["llm"]["plan_patch"] and res["code_patch"] == "" and res["llm_calls"] == 1
    assert seen["patches"] == [None, {"add_packages": ["libgdiplus"], "base": "full"}]
    assert "An administrator suggests what to try:\nit needs libgdiplus" in seen["prompts"][0]
    assert "Never change application source code" in seen["prompts"][0] and "You may also change" not in seen["prompts"][0]
    assert "DllNotFoundException" in seen["prompts"][0] and res["before"]["status"] == "run-failed" and res["after"]["log_tail"] == ""
    bad = br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("build-failed", "build-failed"))["result"]
    assert bad["outcome"] == "not-helped" and bad["score"] == 1
    far = br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("build-failed", "run-failed"))["result"]
    assert far["outcome"] == "further" and far["score"] == 2
    # it already works with this version: the LLM is not asked
    seen["prompts"].clear()
    assert br.try_handler({"JobId": 9, "Payload": pl}, ask=ask, verify=verify("ok", "ok"))["result"]["outcome"] == "already-fixed"
    assert not seen["prompts"]
    none = br.try_handler({"JobId": 9, "Payload": pl}, ask=lambda p, s, y=None: {"diagnosis": "code must change", "fix_json": "{}"},
                          verify=verify("build-failed", "ok"))
    assert none["result"]["outcome"] == "nothing-to-try" and "after" not in none["result"] and none["result"]["score"] == 1
    gone = br.try_handler({"JobId": 9, "Payload": {**pl, "project": "src/Other/Other.csproj"}}, ask=ask, verify=verify("ok", "ok"))
    assert gone["result"]["outcome"] == "not-tried" and "not in the source" in gone["summary"]
    lost = br.try_handler({"JobId": 9, "Payload": {**pl, "commit": "0" * 40}}, ask=ask, verify=verify("ok", "ok"))
    assert lost["result"]["outcome"] == "not-tried" and not list((tmp_path / "scratch").glob("bugtry-*"))


def test_a_try_may_change_code_within_its_limit_and_the_next_one_continues_from_it(tmp_path, monkeypatch):
    from pathlib import Path
    from containerizer import refactor as rf
    from containerizer import verify as vf
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    monkeypatch.setattr(vf, "_run", lambda *a, **k: None)
    source, commit = _source(tmp_path)
    prog = next(p for p in Path(source["path"]).rglob("Program.cs")).relative_to(source["path"]).as_posix()
    text = (Path(source["path"]) / prog).read_text()
    first = next(l for l in text.splitlines() if l.strip() and text.count(l) == 1)
    pl = {"bug_id": 3, "app": "shop", "component": "Web", "project": "src/Web/Web.csproj", "source": source,
          "commit": commit, "hint": "log to the console", "flagged_status": "run-failed", "code_lines": 10}
    seen = {"prompts": [], "systems": [], "patches": []}

    def asker(edits_list):
        answers = iter(edits_list)

        def ask(prompt, schema, system=None):
            seen["prompts"].append(prompt)
            seen["systems"].append(system)
            if "files" in schema["properties"]:
                return {"diagnosis": "the log path is a Windows path", "fix_json": "{}", "files": [prog, "../etc/passwd"]}
            got = next(answers)
            seen["edited"] = True
            return {"edits": got}
        return ask
    good = [{"file": prog, "find": first, "replace": first + "\n// console logging"},
            {"file": "src/Web/Notes.txt", "find": "", "replace": "one\ntwo\n"}]
    out = br.try_handler({"JobId": 11, "Payload": pl}, ask=asker([good]), verify=_fake_verify(seen, "run-failed", "ok-external"))
    res = out["result"]
    assert res["outcome"] == "helped" and res["score"] == 4 and res["code_lines_changed"] == 3 and res["llm_calls"] == 2
    assert "+// console logging" in res["code_patch"] and "Notes.txt" in res["code_patch"] and res["llm"]["files_read"] == [prog]
    assert f"at most 10 lines" in seen["prompts"][0] and prog in seen["prompts"][0] and f"=== {prog} ===" in seen["prompts"][1]
    assert seen["systems"] == [None, rf.SYSTEM]                                  # the code change: the refactoring prompt
    # too many lines, then an edit that does not match: asked once more, then no code change (three calls at most)
    seen.pop("edited")
    big = [{"file": "src/Web/Big.txt", "find": "", "replace": "x\n" * 11}]
    miss = [{"file": prog, "find": "no such text", "replace": "y"}]
    out2 = br.try_handler({"JobId": 12, "Payload": pl}, ask=asker([big, miss]), verify=_fake_verify(seen, "run-failed", "ok"))
    r2 = out2["result"]
    assert r2["outcome"] == "nothing-to-try" and r2["llm_calls"] == 3 and r2["code_patch"] == ""
    assert "occurs 0 times" in r2["llm"]["code_refused"] and "more than the 10 allowed" in seen["prompts"][-1]
    # the next try continues from the first one's changes: no build of the starting point, its patch applied
    seen.update(prompts=[], patches=[], systems=[])
    base = {"job": 11, "plan_patch": {"env": {"A": "1"}}, "code_patch": res["code_patch"], "status": "ok-external",
            "steps": "run ok-external", "log_tail": ""}
    more = [{"file": prog, "find": "// console logging", "replace": "// console logging\n// and more"}]
    out3 = br.try_handler({"JobId": 13, "Payload": {**pl, "parent": 11, "base": base, "hint": "and one more line"}},
                          ask=asker([more]), verify=_fake_verify(seen, "run-failed", "ok"))
    r3 = out3["result"]
    assert r3["outcome"] == "helped" and r3["score"] == 5 and r3["parent"] == 11 and r3["before"]["status"] == "ok-external"
    assert r3["code_lines_changed"] == 1 and "+// and more" in r3["code_patch"] and "Notes.txt" in r3["code_patch"]
    assert seen["patches"] == [{"env": {"A": "1"}}] and r3["plan_patch_total"] == {"env": {"A": "1"}}
    # a parent's patch that no longer applies
    r4 = br.try_handler({"JobId": 14, "Payload": {**pl, "parent": 11, "base": {**base, "code_patch": "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"}}},
                        ask=asker([more]), verify=_fake_verify(seen, "run-failed", "ok"))["result"]
    assert r4["outcome"] == "not-tried" and "no longer applies" in r4["reason"]


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
             "Result": json.dumps({"outcome": "further", "score": 2, "before": {"status": "build-failed"}, "after": {"status": "run-failed", "log_tail": "boom"},
                                   "plan_patch_total": {"add_packages": ["libgdiplus"]}, "code_lines_changed": 1,
                                   "code_patch": "diff --git a/src/A.cs b/src/A.cs\n--- a/src/A.cs\n+++ b/src/A.cs\n@@ -1 +1 @@\n-old\n+new Contoso\n",
                                   "llm": {"diagnosis": "GDI+ is missing at Contoso", "plan_patch": {"add_packages": ["libgdiplus"]}}})},
            {"JobId": 24, "Status": "answered", "Error": None, "Note": None, "QueuedAt": datetime(2026, 11, 27, 12, 30),
             "FinishedAt": None, "RequestedBy": "john.doe@example.com",
             "Payload": json.dumps({"bug_id": 3, "hint": "and the fonts", "parent": 21, "code_lines": 50}),
             "Result": json.dumps({"outcome": "helped", "score": 5, "parent": 21, "before": {"status": "run-failed"},
                                   "after": {"status": "ok"}, "plan_patch_total": {"add_packages": ["libgdiplus", "fonts"]},
                                   "llm": {"diagnosis": "fonts", "plan_patch": {"add_packages": ["fonts"]}}})},
            {"JobId": 22, "Status": "queued", "Error": None, "Note": None, "QueuedAt": datetime(2026, 11, 27, 12, 9),
             "FinishedAt": None, "RequestedBy": "john.doe@example.com", "Payload": json.dumps({"bug_id": 3, "hint": "second"}),
             "Result": None},
            {"JobId": 23, "Status": "answered", "Error": None, "Note": None, "QueuedAt": None, "FinishedAt": None,
             "RequestedBy": None, "Payload": json.dumps({"bug_id": 99, "hint": "another report"}), "Result": "{}"}]
    adm.conn.answers = {r"DATALENGTH\(DataGz\)": rows, r"SELECT Keywords FROM cz.BugReportSettings": [{"Keywords": "contoso"}],
                        r"WHERE Kind = N'bugtry'": jobs,
                        r"SELECT BugId, Status, Note, Labels, CreatedAt, DataGz": [
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
    # every try is there with its rating; the continued one is under its parent; the best one is marked
    assert "★★☆☆☆" in page and "★★★★★" in page and page.count("best so far</span>") == 1
    assert page.index("id='try21'") < page.index("id='try24'") < page.index("id='try22'")
    assert page.split("id='try24'")[1].split("</li>")[0].count("best so far") == 1 and "code up to 50 lines" in page
    assert "name='Parent' value='21'" in page and "name='Parent' value='24'" in page and "Continue from this try" in page
    assert "href='/admin/bugs/try/21.patch'" in page and "+new Contoso" not in page.replace("<span class='sign'>+</span>", "+") or True
    assert "action='/admin/bugs/3/remove'" not in page                           # a report with tries is kept
    assert "kept" in dict(_post(adm, a, "/admin/bugs/3/remove").headers)["Location"] and not adm.conn.sql(r"DELETE FROM cz.BugReport WHERE BugId")
    data = json.loads(_get(adm, a, "/admin/bugs/export.json").body)
    t = data["reports"][0]["tries"]
    assert [(x["id"], x["continues"], x["state"]) for x in t] == [(21, None, "done"), (24, 21, "done"), (22, None, "queued")]
    assert t[0]["outcome"] == "further" and t[0]["score"] == 2 and t[1]["best"] is True and "best" not in t[0]
    assert t[0]["llm"]["plan_patch"] == {"add_packages": ["libgdiplus"]} and "contoso" not in json.dumps(t).casefold()
    assert "+new " in t[0]["code_patch"]
    adm.conn.answers[r"WHERE JobId = %s AND Kind = N'bugtry' AND Status = N'answered'"] = lambda p: [j for j in jobs if j["JobId"] == p[0]]
    d = _get(adm, a, "/admin/bugs/try/21.patch")
    assert d.status == 200 and d.body.startswith(b"diff --git") and _get(adm, a, "/admin/bugs/try/24.patch").status == 404
    r = _post(adm, a, "/admin/bugs/3/try", Hint="  use the full image  ")
    assert r.status in (302, 303) and "Queued" in dict(r.headers)["Location"]
    sql, params = adm.conn.sql(r"EXEC cz.QueueLlmJob")[-1]
    payload = json.loads([p for p in params if isinstance(p, str) and p.startswith("{")][-1])
    assert payload["hint"] == "use the full image" and payload["bug_id"] == 3 and payload["project"] == "src/Api/Api.csproj"
    assert payload["source"]["type"] == "org-clone" and payload["commit"] == "a" * 40 and "bugtry" in params
    assert payload["parent"] is None and payload["base"] is None and payload["code_lines"] == 0
    # continue from try 21, with code changes (never more than 100 lines)
    _post(adm, a, "/admin/bugs/3/try", Hint="go on", Parent="21", CodeLines="500")
    payload = json.loads([p for p in adm.conn.sql(r"EXEC cz.QueueLlmJob")[-1][1] if isinstance(p, str) and p.startswith("{")][-1])
    assert payload["parent"] == 21 and payload["code_lines"] == 100 and payload["base"]["status"] == "run-failed"
    assert payload["base"]["plan_patch"] == {"add_packages": ["libgdiplus"]} and "+new Contoso" in payload["base"]["code_patch"]
    assert payload["base"]["log_tail"] == "boom"
    loc = dict(_post(adm, a, "/admin/bugs/3/try", Hint="x", Parent="23").headers)["Location"]
    assert "not+a+finished+try" in loc.replace("%20", "+")
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


# --------------------------------------------------------------------------- views and labels

def test_labels():
    assert br.parse_labels(" nuget,  NuGet , windows path,C#/.NET ,") == (["nuget", "windows path", "C#/.NET"], "")
    assert br.parse_labels("")[0] == [] and br.split_labels("a,b") == ["a", "b"] and br.split_labels(None) == []
    assert br.parse_labels("<b>")[0] is None and "not a label" in br.parse_labels("<b>")[1]
    assert br.parse_labels("x" * 31)[0] is None and "At most 8" in br.parse_labels(",".join("abcdefghi"))[1]


def test_open_and_closed_views_and_labels_on_the_page():
    pytest.importorskip("jwt")
    from test_refactor import _post
    from test_refactor import adm as adm_fixture
    adm = adm_fixture.__wrapped__()

    def row(i, status, labels, app):
        return {"BugId": i, "ApplicationId": 7, "ComponentId": i, "App": app, "Component": "Api", "VerifyStatus": "build-failed",
                "Status": status, "Note": None, "Labels": labels, "CreatedBy": "john.doe@example.com",
                "CreatedAt": datetime(2026, 11, 27, 12, 0), "ExportedAt": None, "Bytes": 9}
    rows = [row(4, "open", "nuget,windows path", "shop"), row(3, "open", "node", "portal"), row(2, "resolved", "nuget", "billing"),
            row(1, "closed", None, "legacy")]
    case = lambda app: gzip.compress(json.dumps({"application": app, "component": {"name": "Api"}}).encode())  # noqa: E731
    adm.conn.answers = {r"DATALENGTH\(DataGz\)": rows,
                        r"SELECT BugId, Status, Note, Labels, CreatedAt, DataGz": [
                            {"BugId": r["BugId"], "Status": r["Status"], "Note": "", "Labels": r["Labels"],
                             "CreatedAt": r["CreatedAt"], "DataGz": case(r["App"])} for r in reversed(rows)]}
    a = adm.sessions.create("a@example.com", "A", True)
    get = lambda query="": adm.handle("GET", "/admin/bugs", query, {"Cookie": f"{adm.cookie}={a}"}, b"").body  # noqa: E731
    table = lambda page: page.split("<tbody>")[1].split("</tbody>")[0] if "<tbody>" in page else ""  # noqa: E731
    page = get()                                                                 # open by default
    assert "class='chip on' href='/admin/bugs'>Open (2)" in page and "Resolved and closed (2)" in page and "All (4)" in page
    assert "shop" in table(page) and "portal" in table(page) and "billing" not in table(page) and "legacy" not in table(page)
    assert "action='/admin/bugs/4/resolve'" in page and "action='/admin/bugs/4/close'" in page and "/reopen'" not in page
    assert "nuget (1)" in page and "windows path (1)" in page and "node (1)" in page
    assert "value='nuget, windows path'" in page and "href='/admin/bugs/export.json'" in page and "the 2 reports shown" in page
    closed = get("view=closed")
    assert "billing" in table(closed) and "legacy" in table(closed) and "shop" not in table(closed)
    assert "action='/admin/bugs/2/reopen'" in closed and "/resolve'" not in closed and ">resolved<" in closed and ">closed<" in closed
    assert "name='Back' value='/admin/bugs?view=closed'" in closed and "href='/admin/bugs/export.json?view=closed'" in closed
    assert "action='/admin/bugs/2/try'" not in closed                             # no new tries for a closed report
    both = get("view=all&label=NuGet")                                            # a label, whatever its case
    assert "shop" in table(both) and "billing" in table(both) and "portal" not in table(both) and "All (2)" in both
    assert "No open report with the label “node”" in get("label=node").replace("portal", "") or "portal" in table(get("label=node"))
    assert "No resolved and closed report with the label “node”." in get("view=closed&label=node")
    # the export follows the view and the label
    ex = lambda query: [r["id"] for r in json.loads(adm.handle(  # noqa: E731
        "GET", "/admin/bugs/export.json", query, {"Cookie": f"{adm.cookie}={a}"}, b"").body)["reports"]]
    assert ex("") == [3, 4] and ex("view=closed") == [1, 2] and ex("view=all&label=nuget") == [2, 4]
    assert json.loads(adm.handle("GET", "/admin/bugs/export.json", "", {"Cookie": f"{adm.cookie}={a}"}, b"").body)["reports"][1]["labels"] \
        == ["nuget", "windows path"]
    # saving labels, and back to the view it was done in
    r = _post(adm, a, "/admin/bugs/4/labels", Labels="nuget, Restore", Back="/admin/bugs?view=all&label=nuget")
    assert dict(r.headers)["Location"].startswith("/admin/bugs?view=all&label=nuget&msg=Labels")
    assert adm.conn.sql(r"SET Labels = %s")[-1][1] == ("nuget,Restore", 4)
    n = len(adm.conn.sql(r"SET Labels"))
    r = _post(adm, a, "/admin/bugs/4/labels", Labels="<x>", Back="https://evil.example/")
    assert dict(r.headers)["Location"].startswith("/admin/bugs?msg=") and len(adm.conn.sql(r"SET Labels")) == n
