"""The results page's Migration plan (migrationplan.py), the Sandbox cluster column of the Components table and the
front page's "ready now" marker. No SQL Server needed (vSandboxDeploy on SQL Server: test_sqlstore.py)."""
import json
import re
from datetime import datetime
from types import SimpleNamespace

import pytest

from containerizer import migrationplan as mp
from containerizer import webui
from containerizer.assess import AppAssessment, assess, rating_of

STATE_RULE = "node-session-file-store"     # a rule with `state: local` (rules/13-node.yaml)


def _c(i, name, verdict, role="web", tier="server", verify="ok", wc=False):
    return {"ComponentId": i, "ComponentName": name, "ProjectPath": f"src/{name}/{name}.csproj", "Role": role, "Tier": tier,
            "Verdict": verdict, "VerdictText": webui.VERDICT_LABEL[verdict], "TargetFramework": "net8.0",
            "WindowsContainerOk": wc, "VerifyStatus": verify}


def _f(i, name, sev, title, rule="r"):
    return {"ComponentId": i, "ComponentName": name, "RuleId": rule, "Severity": sev, "Title": title, "Why": "", "Fix": "",
            "Via": None, "OnlyCommands": None, "Refs": "[]", "Source": "curated"}


def loans(**kw):
    """consumer-loans-like: two components ready, one keeps its data, three cannot run in a Linux container."""
    comps = [_c(1, "Lending.Api", "blocker", wc=True, verify=None), _c(2, "BackOffice", "blocker", verify=None),
             _c(3, "Collections", "blocker", "worker", verify=None), _c(4, "CustomerPortal", "config"),
             _c(5, "Documents", "config", "worker"), _c(6, "LoanTape", "config", "console"),
             _c(7, "Loans.Database", "info", "sqldb", "database", None)]
    finds = [_f(i, n, "blocker", "OLE DB / Access database engine") for i, n in ((1, "Lending.Api"), (2, "BackOffice"), (3, "Collections"))]
    finds += [_f(6, "LoanTape", "config", "Application data written to its own disk", STATE_RULE)]
    now = datetime(2026, 11, 4)
    base = {"SandboxEnabled": True, "ScanStatus": "deployed", "ScannedAt": now, "Kind": None, "ComponentName": None,
            "ProjectPath": None, "Reason": None}
    d = lambda host, port, scheme: {"host": host, "port": port, "scheme": scheme, "protocol": "TCP",   # noqa: E731
                                    "source": "config", "file": "appsettings.json", "line": 3, "quote": host}
    net = {"components": [
        {"name": "CustomerPortal", "destinations": [d("lending-api.corp.local", 443, "https")]},
        {"name": "Lending.Api", "destinations": [d("lending-api.corp.local", 443, "https"),
                                         d("payhub.corp.local", 443, "https")]},
        {"name": "BackOffice", "destinations": [d("documents", 80, "http")]}]}
    app = {"ApplicationId": 7, "ApplicationName": "consumer-loans", "BusinessUnitId": None, "BusinessUnitName": None,
           "ProductName": None, "Rating": "C", "Score": 44, "Confidence": 0.9, "Verified": True, "AssessedAt": now,
           "Summary": "", "Description": None, "Owner": None, "ProductOwner": None, "BusinessUnitOwner": None,
           "RepositoryUrl": None, "SourcePath": ".", "SourceCommit": "abc", "components": comps, "findings": finds,
           "sandbox": [{"ComponentId": 4, "ComponentName": "CustomerPortal", "CheckedAt": now, "Status": "healthy",
                        "Reason": "1/1 ready", "GitOps": "flux", "Namespace": "consumer-loans", "Ready": "1/1",
                        "Restarts": 0, "RuleId": None, "Outcome": None, "Events": "[]", "Url": None, "UrlCheck": None}],
           "deploys": [base, {**base, "Kind": "deployed", "ComponentName": "CustomerPortal"},
                       {**base, "Kind": "deployed", "ComponentName": "Documents", "ProjectPath": "src/Documents/Documents.csproj"},
                       {**base, "Kind": "excluded", "ComponentName": "LoanTape", "Reason": "keeps local state"}],
           "history": [], "migrations": [], "refactors": [],
           "connectivity": {"network": net, "flows": [], "decisions": [], "available": True}}
    app.update(kw)
    return app


@pytest.fixture(autouse=True)
def _state_rule(monkeypatch):
    monkeypatch.setattr(webui, "_STATE_RULES", {STATE_RULE: "local"})


def _plan_html(html):
    s = html.index("<section class='card plan'")
    return html[s:html.index("</section>", s)]


def test_rating_of_is_the_application_rule(tmp_path):
    """assess.rating_of on stand-ins gives what AppAssessment.rating gives (the plan rates parts with it)."""
    from test_engine import web_app
    web_app(tmp_path, code='var t = Type.GetTypeFromProgID("Excel.Application");')
    a = assess(tmp_path)
    assert rating_of(a.components) == a.rating
    s = lambda v, st=True, t="server": SimpleNamespace(tier=t, verdict=v, stateless=st)   # noqa: E731
    for comps in ([s("config")], [s("config", False)], [s("refactor"), s("info")], [s("rewrite")], [s("blocker"), s("info")],
                  [s("blocker")], [], [s("info", t="client")]):
        assert rating_of(comps) == AppAssessment(None, comps, [], [], []).rating


def test_plan_splits_into_waves():
    p = mp.build(loans())
    assert [x["c"]["ComponentName"] for x in p["now"]] == ["CustomerPortal", "Documents"]
    assert [c["ComponentName"] for c in p["after"]] == ["LoanTape"]
    assert [c["ComponentName"] for c in p["windows"]] == ["Lending.Api", "BackOffice", "Collections"]
    assert [c["ComponentName"] for c in p["other"]] == ["Loans.Database"]
    # the Linux part rated by the application rule: as it is, and with LoanTape's data moved out
    stand = lambda c, keeps: SimpleNamespace(tier="server", verdict=c, stateless=not keeps)   # noqa: E731
    assert p["linux_now"] == rating_of([stand("config", False), stand("config", False), stand("config", True)])
    assert p["linux_after"] == rating_of([stand("config", False)] * 3) == "A"
    assert p["linux_now"] != p["linux_after"]
    assert mp.summary(p) == ("2 of 6 components can run in Linux containers now; 1 more after code changes; "
                             "3 stay on Windows.")
    states = {x["c"]["ComponentName"]: x["sandbox"] for x in p["now"]}
    assert states["CustomerPortal"]["state"] == "checked" and states["Documents"]["state"] == "deployed"


def test_build_failure_keeps_a_ready_component_out_of_wave_1():
    app = loans()
    app["components"][4]["VerifyStatus"] = "run-failed"
    p = mp.build(app)
    assert [x["c"]["ComponentName"] for x in p["now"]] == ["CustomerPortal"]
    assert "it did not run" in mp._fixes(app["components"][4], p)


def test_section_on_the_page():
    html = webui.render_application(loans())
    assert html.index("Main obstacles") < html.index("Migration plan") < html.index("<h2 id='components'>Components</h2>")
    sec = _plan_html(html)
    assert "2 of 6 components can run in Linux containers now; 1 more after code changes; 3 stay on Windows." in sec
    assert "Wave 1, now" in sec and "to Kubernetes" in sec and "Wave 2, after code changes" in sec
    assert "Stays on Windows" in sec and "OLE DB / Access database engine" in sec
    assert "a Windows container is a workable stop-gap" in sec          # Api: WindowsContainerOk
    assert "Deployed and healthy" in sec and "deployed, not checked yet" in sec
    assert "keeps its own data: Application data written to its own disk" in sec
    assert f"{webui.RATING_TITLE['A']}" in sec and "The part that can run in Linux containers (3 components)" in sec
    assert "Not in the plan: Loans.Database (lives with the database)" in sec
    # no Refactoring box on this page: the plan points to the findings instead of Make it A
    assert "#refactoring" not in sec and "The findings below say what to change" in sec
    assert " style=" not in sec and not re.search(r"<script(?![^>]*\bsrc=)", html)


def test_between_the_parts():
    sec = _plan_html(webui.render_application(loans()))
    calls = re.findall(r"<li><b>([^<]+)</b> calls <b>([^<]+)</b>", sec)
    # CustomerPortal names lending-api.corp.local (Api's name), BackOffice the service `documents`; Api calling
    # itself and the payment hub (not a component) are not crossings
    assert calls == [("CustomerPortal", "Lending.Api"), ("BackOffice", "Documents")]
    assert "over HTTPS: the Windows part must be reachable from the cluster" in sec
    assert "the cluster must be reachable from the Windows servers" in sec
    assert "lending-api.corp.local" in sec and "payhub" not in sec


def test_between_the_parts_omitted_without_data():
    sec = _plan_html(webui.render_application(loans(connectivity={"available": False})))
    assert "Between the parts" not in sec


def test_make_it_a_link_when_the_box_is_there():
    app = loans(Rating="B")
    app["components"] = [c for c in app["components"] if c["Verdict"] != "blocker"]
    sec = _plan_html(webui.render_application(app))
    assert "<a href='#refactoring'>Make it A ↓</a>" in sec and "id='refactoring'" in webui.render_application(app)
    assert "Stays on Windows" not in sec and "Between the parts" not in sec


def test_nothing_ready_until_the_port():
    app = loans(Rating="D")
    app["components"] = [_c(1, "Web", "rewrite"), _c(2, "Jobs", "rewrite", "worker")]
    app["findings"] = [_f(1, "Web", "rewrite", "ASP.NET Web Forms")]
    sec = _plan_html(webui.render_application(app))
    assert "0 of 2 components can run in Linux containers now; 2 after a framework port or rewrite." in sec
    assert "Nothing runs in a Linux container until the framework port is done." in sec
    assert "No component rates A on its own yet." in sec and "ASP.NET Web Forms" in sec


def test_no_plan_for_a():
    app = loans(Rating="A")
    app["components"] = [_c(4, "CustomerPortal", "config")]
    assert "Migration plan" not in webui.render_application(app)


def test_names_are_escaped():
    app = loans()
    app["components"][3]["ComponentName"] = "<script>x</script>"
    app["findings"][0]["Title"] = "<img src=x>"
    sec = _plan_html(webui.render_application(app))
    assert "<script>x" not in sec and "&lt;script&gt;x" in sec and "<img" not in sec


@pytest.mark.parametrize("deploys, check, state, text", [
    (None, None, "unknown", ""),
    ([{"SandboxEnabled": False, "Kind": None}], None, "off", "the application's sandbox is turned off"),
    ([{"SandboxEnabled": True, "ScanStatus": "sandbox-off", "Kind": None}], None, "off", "turned off"),
    ([{"SandboxEnabled": True, "ScanStatus": None, "Kind": None}], None, "none", "no organization scan deploys"),
    ([{"SandboxEnabled": True, "ScanStatus": "deployed", "Kind": "deployed", "ComponentName": "Web"}], None,
     "deployed", "deployed, not checked yet"),
    ([{"SandboxEnabled": True, "ScanStatus": "deployed", "Kind": "deployed", "ComponentName": "Web"}],
     {"Status": "not-found"}, "none", "not found in the sandbox"),
    ([{"SandboxEnabled": True, "ScanStatus": "deployed", "Kind": "excluded", "ComponentName": "Web",
       "Reason": "keeps local state"}], None, "excluded", "not deployed: keeps local state"),
    ([{"SandboxEnabled": True, "ScanStatus": "no-a-components", "Kind": None}], None, "none", "latest organization scan"),
    (None, {"Status": "healthy"}, "checked", ""),
])
def test_sandbox_state(deploys, check, state, text):
    c = _c(1, "Web", "config")
    checks = {1: {"ComponentId": 1, **check}} if check else {}
    x = mp.sandbox_state(c, checks, deploys)
    assert x["state"] == state and text in x["text"]


def test_components_table_sandbox_column():
    app = loans(sandbox=[])                 # deployed by the scan, no check has a result yet
    html = webui.render_application(app)
    assert "<th>Sandbox cluster</th>" in html
    table = html[html.index("<h2 id='components'>Components</h2>"):html.index("What needs to change")]
    assert table.count("deployed, not checked yet") == 2
    assert "title='keeps local state'>not deployed</span>" in table
    # nothing deployed and no check: no column
    app = loans(sandbox=[], deploys=[{"SandboxEnabled": False, "Kind": None}])
    assert "<th>Sandbox cluster</th>" not in webui.render_application(app)
    assert "the application&#x27;s sandbox is turned off" in _plan_html(webui.render_application(app))


def test_front_page_marker():
    from test_sqlstore import overview_data
    data = overview_data()
    a = data["apps"][0]
    a.update(Rating="C", ReadyNow=2, PlanComponents=6)
    html = webui.render_overview(data)
    assert "<span class='ready-now' title='2 of 6 components rate A on their own" in html and ">2/6 ready now</span>" in html
    a.update(ReadyNow=0)
    assert "ready now</span>" not in webui.render_overview(data)
    a.update(Rating="A", ReadyNow=6)
    assert "ready now</span>" not in webui.render_overview(data)


def test_load_overview_counts_ready_components():
    rows = {"comps": [{"ApplicationId": 1, **{k: v for k, v in c.items() if k in ("ComponentId", "Tier", "Verdict", "VerifyStatus")}}
                      for c in loans()["components"]],
            "state": [{"ApplicationId": 1, "ComponentId": 6, "RuleId": STATE_RULE, "Title": "data on disk"}]}

    class Cur:
        def execute(self, sql, params=()):
            self.sql, self.params = sql, params
            if "FROM cz.vComponentLatest" in sql:
                self.rows = rows["comps"]
            elif "FROM cz.vFindingLatest WHERE RuleId IN" in sql:
                assert params == (STATE_RULE,)
                self.rows = rows["state"]
            elif "FROM cz.vApplicationLatest" in sql and "vRefactorOrder" not in sql:
                self.rows = [{"ApplicationId": 1, "ApplicationName": "loans", "Rating": "C", "Score": 44}]
            else:
                self.rows = []

        def fetchall(self):
            return self.rows

    class Conn:
        def cursor(self, as_dict=False):
            return Cur()

        def rollback(self):
            pass
    a = webui.load_overview(Conn())["apps"][0]
    assert (a["ReadyNow"], a["PlanComponents"], a["Components"]) == (2, 6, 7)


def test_agent_prompt_route_is_gone():
    from test_sqlstore import FakeConn, _get
    from http.server import ThreadingHTTPServer
    import threading
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webui.make_handler(lambda: FakeConn(None)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        assert _get(f"http://127.0.0.1:{httpd.server_address[1]}/app/7/component/1/agent-prompt.md")[0] == 404
        css = _get(f"http://127.0.0.1:{httpd.server_address[1]}/static/app.css")[2]
        assert ".gens{" in css and ".ready-now{" in css
    finally:
        httpd.shutdown()


def test_the_plan_says_when_a_make_it_a_patch_runs_in_place():
    """A Make it A patched copy runs in the application's own folder and namespace (variant.py): the plan says the
    Sandbox column shows the patched copy."""
    orders = [{"JobId": 40, "Goal": "rating-a", "SandboxStatus": "outdated"},
              {"JobId": 42, "Goal": "rating-a", "SandboxStatus": "running"}, {"JobId": 43, "Goal": "fix"}]
    assert mp.patch_in_sandbox(loans(refactors=orders))["JobId"] == 42
    sec = _plan_html(webui.render_application(loans(Rating="B", refactors=orders)))
    assert "The sandbox runs the Make it A patch of order #42 in place of this application's scan output" in sec
    assert mp.patch_in_sandbox(loans(refactors=orders[:1])) is None
    assert "Make it A patch of order" not in _plan_html(webui.render_application(loans(Rating="B")))


def test_what_runs_in_the_sandbox_is_shown_on_the_front_page_and_the_app_page():
    """Applications that run in the sandbox only in part (C: 1 of 6 components) are listed with what runs and the link
    to open (a UI before an API); the ones a Make it A patch runs for are in their own list."""
    from test_sqlstore import overview_data
    data = overview_data()
    a = data["apps"][0]
    a.update(Rating="C", ReadyNow=2, PlanComponents=6,
             Running={"n": 1, "url": "https://customerportal-consumer-loans.sb.example/"})
    html = webui.render_overview(data)
    sec = html[html.index("<section class='running'>"):]
    assert "<h2>Running in the sandbox</h2>" in sec and ">1 of 6 components</span>" in sec
    assert "href='https://customerportal-consumer-loans.sb.example/' target='_blank'" in sec
    a.update(Running={"n": 1, "url": "javascript:alert(1)"})                  # never anything but https
    assert "javascript:" not in webui.render_overview(data)
    a.update(APatch={"JobId": 9, "SandboxStatus": "running", "SandboxUrl": None, "FinishedAt": None})
    assert "<section class='running'>" not in webui.render_overview(data)      # in "Made A by a patch" instead
    a.update(APatch=None, Running=None)
    assert "<section class='running'>" not in webui.render_overview(data)
    # the application's page: at the top, with the link and where the plan says the rest
    app = loans()
    app["sandbox"][0]["Url"] = "https://customerportal-consumer-loans.sb.example/"
    html = webui.render_application(app)
    assert ("<p class='in-sandbox'><span class='st st-ok'>In the sandbox</span> 1 of 6 components run there now "
            "<a href='https://customerportal-consumer-loans.sb.example/'") in html and "href='#plan'>what runs" in html
    assert "class='in-sandbox'" not in webui.render_application(loans(sandbox=[]))


def test_load_running_prefers_the_ui():
    class Cur:
        def execute(self, sql, params=()):
            assert "FROM cz.vSandboxLatest" in sql
            self.rows = [{"ApplicationId": 1, "ComponentName": "Shop.Api", "Status": "healthy", "Url": "https://api.x/"},
                         {"ApplicationId": 1, "ComponentName": "Shop.Web", "Status": "healthy", "Url": "https://web.x/"},
                         {"ApplicationId": 1, "ComponentName": "Shop.Nightly", "Status": "scheduled", "Url": None},
                         {"ApplicationId": 2, "ComponentName": "Jobs", "Status": "scheduled", "Url": None}]

        def fetchall(self):
            return self.rows

    class Conn:
        def cursor(self, as_dict=False):
            return Cur()
    assert webui.load_running(Conn()) == {1: {"n": 3, "url": "https://web.x/"}, 2: {"n": 1, "url": None}}


def test_what_failed_is_shown_for_a_component_the_gate_left_out():
    """org.gate_detail keeps what the security gate saw (the build log's end, the hardened run's errors) next to its
    reason; the plan's and the Components table's Sandbox cells show it under What failed."""
    from containerizer import migrationplan as mp, webui
    from containerizer.org import gate_detail
    d = gate_detail({"build_error": "x" * 5000 + "\nerror NU1101: Unable to find package Acme.Core",
                     "lint": [{"severity": "error", "check": "DL3006", "message": "pin the base image"},
                              {"severity": "warning", "check": "DL3008", "message": "pin versions"}],
                     "run": {"status": "hardening-failure", "errors": ["read-only file system"], "log": "boom <x>"}})
    assert "Image build, the end of its log:" in d and d.endswith("boom <x>") and len(d) <= 3000
    assert "DL3006: pin the base image" in d and "DL3008" not in d and "read-only file system" in d
    assert gate_detail({"run": {"status": "ok"}}) == ""
    c = {"ComponentId": 1, "ComponentName": "web", "ProjectPath": None}
    deploys = [{"SandboxEnabled": True, "ScanStatus": "deployed", "Kind": "excluded", "ComponentName": "web",
                "Reason": "security gate: image build failed", "Detail": "npm ERR! <404>"}]
    sb = mp.sandbox_state(c, {}, deploys)
    assert sb["state"] == "excluded" and sb["detail"] == "npm ERR! <404>"
    for html in (mp._sandbox_html(sb), webui._sandbox_cell(sb)):
        assert "<summary>What failed</summary>" in html and "npm ERR! &lt;404&gt;" in html
    assert "What failed" not in webui._sandbox_cell(mp.sandbox_state(c, {}, [{**deploys[0], "Detail": None}]))


def test_the_lab_services_the_application_needs_are_on_its_page():
    """control-tower: RabbitMQ and SFTP needed and turned off, SQL Server provided. The page says so at the top,
    and the Sandbox cells of the components that run without them say which."""
    lab = json.dumps({"needed": {"sqlserver": ["CustomerPortal", "Documents"], "rabbitmq": ["Documents"],
                                 "sftp": ["Documents", "LoanTape"]},
                      "provided": ["sqlserver"], "missing": ["rabbitmq", "sftp"]})
    app = loans()
    app["deploys"] = [{**d, "LabServices": lab} for d in app["deploys"]]
    html = webui.render_application(app, "", {"lab_admin": True})
    top = html[html.index("class='lab-needs"):]
    top = top[:top.index("</p>")]
    assert "<span class='st st-ok'>provided</span> SQL Server" in top
    assert "<span class='st st-bad'>turned off</span> RabbitMQ, SFTP: Documents, LoanTape run without them" in top
    assert "href='/admin/lab-services'" in top
    assert "href='/admin/lab-services'" not in webui.render_application(app, "", {})
    assert "needs RabbitMQ, SFTP: turned off in the lab" in html and "needs SFTP: turned off in the lab" in html
    assert "class='lab-needs" not in webui.render_application(loans())


def test_a_split_repository_keeps_each_applications_lab_services():
    from containerizer.org import merge_lab_services
    a = {"needed": {"sqlserver": ["A.Api"], "rabbitmq": ["A.Api"]}, "provided": ["sqlserver"], "missing": ["rabbitmq"]}
    b = {"needed": {"sftp": ["B.Jobs"]}, "provided": [], "missing": ["sftp"]}
    assert merge_lab_services([a, b, {}]) == {"needed": {"rabbitmq": ["A.Api"], "sftp": ["B.Jobs"], "sqlserver": ["A.Api"]},
                                              "provided": ["sqlserver"], "missing": ["rabbitmq", "sftp"]}
    assert merge_lab_services([{}, None]) == {}


def test_admin_lab_services_names_each_application_of_a_split_repository():
    from containerizer import admin_lab

    class Cur:
        def execute(self, *a):
            pass

        def fetchall(self):
            return [{"AppName": "containerization-challenge", "LastDetail": json.dumps({
                "lab_services": {"missing": ["rabbitmq", "sftp"]},
                "apps": [{"app": "containerization-challenge-control-tower",
                          "lab_services": {"missing": ["rabbitmq", "sftp"]}},
                         {"app": "containerization-challenge-expense-claims", "lab_services": {"missing": []}},
                         {"app": "containerization-challenge-trade-rebates"}]})},
                    {"AppName": "shop", "LastDetail": json.dumps({"lab_services": {"missing": ["rabbitmq"]}})}]

    class Conn:
        def cursor(self, as_dict=False):
            return Cur()
    assert admin_lab.needs_off(Conn()) == {"rabbitmq": ["containerization-challenge-control-tower", "shop"],
                                           "sftp": ["containerization-challenge-control-tower"]}
