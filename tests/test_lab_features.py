"""Features made with the lab's feedback: API keys, approval of LLM jobs, the stateless and repair goals of
refactoring orders, the clearer statuses, why an application has its rating, external links, the favicon."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from containerizer import admin_apikeys as ak, admin_llmqueue, admin_refactor, refactor as rf, webui
from test_llm_queue import FakeConn
from test_refactor import _get, _loc, _post, adm  # noqa: F401 - the fixture


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- API keys

def test_a_key_is_random_and_only_its_hash_is_kept():
    key, prefix, digest = ak.new_key()
    assert ak.KEY_RE.fullmatch(key) and key.startswith(f"czk_{prefix}_") and digest == hashlib.sha256(key.encode()).digest()
    assert ak.new_key()[0] != key


def _key_conn(key, prefix, **row):
    base = {"ApiKeyId": 3, "Name": "CMDB sync", "Prefix": prefix, "KeyHash": hashlib.sha256(key.encode()).digest(),
            "Role": "read", "ExpiresAt": None, "LastUsedAt": None, "RevokedAt": None}
    return FakeConn({r"FROM cz.ApiKey WHERE Prefix": [{**base, **row}]})


def test_check_key():
    key, prefix, _ = ak.new_key()
    conn = _key_conn(key, prefix)
    claims = ak.check_key(lambda: conn, key)
    assert claims["_api_key"] and claims["_role"] == "read" and claims["_prefix"] == prefix
    assert conn.sql(r"UPDATE cz.ApiKey SET LastUsedAt")                     # first use is written back
    conn = _key_conn(key, prefix, LastUsedAt=_now())
    ak.check_key(lambda: conn, key)
    assert not conn.sql(r"UPDATE cz.ApiKey SET LastUsedAt")                 # not again within 5 minutes
    assert ak.check_key(lambda: _key_conn(key, prefix), key[:-1] + ("A" if key[-1] != "A" else "B")) is None
    assert ak.check_key(lambda: _key_conn(key, prefix, RevokedAt=_now()), key) is None
    assert ak.check_key(lambda: _key_conn(key, prefix, ExpiresAt=_now() - timedelta(minutes=1)), key) is None
    assert ak.check_key(lambda: _key_conn(key, prefix), "czk_nothex00_x") is None


def test_the_api_takes_keys_and_their_role(monkeypatch):
    from containerizer import api
    a = api.Api(object(), "", [], lambda: FakeConn())
    monkeypatch.setattr(ak, "check_key", lambda connect, token: {"_api_key": True, "_role": "read", "_prefix": "ab12cd34",
                                                                "sub": "api-key:ab12cd34", "name": "API key x"})
    claims = a._authenticate({"Authorization": "Bearer czk_ab12cd34_" + "x" * 43})
    assert a.roles(claims)[:3] == (False, True, [])                          # read only
    assert a.roles({**claims, "_role": "full"})[:3] == (True, False, [])
    with pytest.raises(api.ApiError, match="send an API key"):                # no audience: access tokens are off
        a._authenticate({"Authorization": "Bearer eyJhbGciOi.x.y"})
    monkeypatch.setattr(ak, "check_key", lambda connect, token: None)
    with pytest.raises(api.ApiError, match="not valid"):
        a._authenticate({"Authorization": "Bearer czk_ab12cd34_" + "x" * 43})


def test_api_page_makes_and_revokes_keys(adm):  # noqa: F811
    adm.api = SimpleNamespace(audience="")
    sid = adm.sessions.create("alice@example.com", "Alice", True)
    r = _get(adm, sid, "/admin/api")
    assert r.status == 200 and "How to use it" in r.body and "/api/v1" in r.body and "No API keys yet" in r.body
    r = _post(adm, sid, "/admin/api/keys", Name="CMDB sync", Role="full", Expires="90")
    (sql, params), = adm.conn.sql(r"INSERT cz.ApiKey")
    key = ak.KEY_RE.search(r.body)[0]
    assert params[1] == key.split("_")[1] and params[2] == hashlib.sha256(key.encode()).digest() and params[3] == "full"
    assert ("Cache-Control", "no-store") in r.headers and "not stored" in r.body
    assert "Not+made" in _loc(_post(adm, sid, "/admin/api/keys", Name="", Role="full", Expires="90"))
    assert "Not+made" in _loc(_post(adm, sid, "/admin/api/keys", Name="x", Role="root", Expires="90"))
    _post(adm, sid, "/admin/api/keys/3/revoke")
    assert adm.conn.sql(r"UPDATE cz.ApiKey SET RevokedAt")
    op = adm.sessions.create("bob@example.com", "Bob", False, True, True)
    assert _get(adm, op, "/admin/api").status == 403


# --------------------------------------------------------------------------- approval of LLM jobs

def test_approval_settings():
    v, errors = admin_llmqueue.validate_settings({"ApproveKind": ["refactor", "evil"], "ApproveMinTokens": ["1500"]})
    assert not errors and v["ApproveKinds"] == "refactor" and v["ApproveMinTokens"] == 1500
    v, errors = admin_llmqueue.validate_settings({"ApproveMinTokens": ["-1"]})
    assert errors and v["ApproveKinds"] is None


def test_only_admins_approve(adm):  # noqa: F811
    adm.route_scans = lambda *a: None
    admin = adm.sessions.create("alice@example.com", "Alice", True)
    _post(adm, admin, "/admin/llm-queue/5/approve")
    (sql, params), = adm.conn.sql(r"SET Status = N'queued', ApprovedBy")
    assert params == ("alice@example.com", 5)
    _post(adm, admin, "/admin/llm-queue/6/reject")
    assert adm.conn.sql(r"SET Status = N'skipped'.*Note")
    op = adm.sessions.create("bob@example.com", "Bob", False, True, True)
    assert "Only+administrators" in _loc(_post(adm, op, "/admin/llm-queue/7/approve"))


# --------------------------------------------------------------------------- refactoring goals

def _stateful_doc():
    return {"name": "parts", "rating": "B", "components": [
        {"name": "Parts", "project": "src/Parts/Parts.csproj", "tier": "server", "verdict": "config", "stateless": False,
         "state": [{"id": "sqlite-local", "title": "Embedded file database (SQLite/LiteDB)"}],
         "findings": [{"id": "sqlite-local", "severity": "config", "title": "SQLite", "fix": "Use a server database.",
                       "evidence": ["src/Parts/Parts.csproj: package Microsoft.EntityFrameworkCore.Sqlite"]}]}]}


def test_stateless_goal(tmp_path):
    doc = _stateful_doc()
    with pytest.raises(rf.RefactorError, match="nothing to change"):
        rf.build_payload(doc, {"type": "local", "path": str(tmp_path)}, "c" * 40)           # no refactor finding
    pl = rf.build_payload(doc, {"type": "local", "path": str(tmp_path)}, "c" * 40, goal="stateless")
    assert pl["goal"] == "stateless" and pl["include_config"] and pl["state"][0]["component"] == "Parts"
    assert rf.dedupe_key(pl) != rf.dedupe_key({**pl, "goal": "fix"})
    with pytest.raises(rf.RefactorError, match="unknown goal"):
        rf.build_payload(doc, {}, None, goal="everything")
    # the runner adds the files that use the embedded database (the finding names only the project)
    (tmp_path / "src/Parts/Data").mkdir(parents=True)
    (tmp_path / "src/Parts/Parts.csproj").write_text("<Project/>")
    (tmp_path / "src/Parts/Program.cs").write_text("var b = 1;\nservices.AddDbContext<Db>(o => o.UseSqlite(cs));\n")
    (tmp_path / "src/Parts/appsettings.json").write_text('{"ConnectionStrings": {"Parts": "Data Source=parts.db"}}')
    (tmp_path / "src/Parts/Data/Other.cs").write_text("class Other {}")
    tasks = rf.state_tasks(pl, tmp_path)
    assert sorted(t["file"] for t in tasks) == ["src/Parts/Program.cs", "src/Parts/appsettings.json"]
    assert tasks[0]["findings"][0]["rule"] == "move-state-out" and tasks[0]["findings"][0]["evidence"][0]["line"]
    prompt, _ = rf.task_prompt(pl, tasks[0], tmp_path)
    assert "Microsoft.EntityFrameworkCore.SqlServer" in prompt and "ConnectionStrings__" in prompt


BUILD_LOG = """10.71 /src/src/PartsCatalog/Program.cs(10,33): error CS1729: 'FileLoggerProvider' does not contain a constructor
that takes 1 arguments [/src/src/PartsCatalog/PartsCatalog.csproj]
10.72 /src/src/PartsCatalog/Program.cs(10,33): error CS1729: 'FileLoggerProvider' does not contain a constructor that takes 1 arguments [x]
"""


def test_repair_from_the_build_log(tmp_path):
    errs = rf.build_errors(BUILD_LOG)
    assert errs == [{"file": "src/PartsCatalog/Program.cs", "line": 10, "code": "CS1729",
                     "text": "'FileLoggerProvider' does not contain a constructor"}]
    assert rf.build_errors("/src/../../etc/passwd(1,1): error CS1: x") == []
    patch = "From x\nSubject: [PATCH] Containerizer: parts: sqlite-local\n\ndiff --git a/src/PartsCatalog/X.cs b/src/PartsCatalog/X.cs\n"
    pl = rf.repair_payload({"app": "parts", "commit": "c" * 40, "source": {"type": "local"}, "components": [
        {"name": "PartsCatalog", "project": "src/PartsCatalog/PartsCatalog.csproj"}]},
        {"patch": patch, "status": "applies-only", "verification": [{"status": "build-failed", "log_tail": BUILD_LOG}]}, 7)
    assert pl["goal"] == "repair" and pl["base_job"] == 7 and pl["base_subject"] == "Containerizer: parts: sqlite-local"
    (tmp_path / "src/PartsCatalog").mkdir(parents=True)
    (tmp_path / "src/PartsCatalog/Program.cs").write_text("x")
    t, = rf.repair_tasks(pl, tmp_path, [])
    assert t["file"] == "src/PartsCatalog/Program.cs" and "CS1729" in t["findings"][0]["title"]
    # no compiler error (it built, but did not start): the patch's files, with the log
    t, = rf.repair_tasks({**pl, "errors": []}, tmp_path, ["src/PartsCatalog/Program.cs"])
    assert "does not run" in t["findings"][0]["title"]
    with pytest.raises(rf.RefactorError, match="no patch"):
        rf.repair_payload({}, {"patch": None}, 1)


def test_statuses_say_what_went_wrong():
    assert rf.status_label("applies-only", ["build-failed"])[0] == "Does not build"
    assert rf.status_label("applies-only", ["ok", "run-failed"])[0] == "Does not start"
    assert rf.status_label("applies-only", [])[0] == "Not built"
    assert rf.status_label("verified") == ("Verified", "")
    assert rf.status_label("approval")[0] == "Waiting for approval" and rf.order_status("approval") == "approval"
    assert rf.summary({"status": "applies-only", "verification": [{"status": "build-failed"}], "findings": [
        {"status": "fixed"}], "files": [{}]}).startswith("does not build: 1 of 1 finding fixed")
    assert admin_refactor.repairable("applies-only", {"patch": "x", "verification": [{"status": "build-failed"}]})
    assert not admin_refactor.repairable("applies-only", {"patch": "x", "verification": [{"status": "ok"}]})
    assert "title='The patch applies" in admin_refactor.chip("applies-only", ["build-failed"])


def test_product_owners_order_for_their_products_only():
    from containerizer.roles import Access
    owner = Access(False, False, products={3})
    conn = FakeConn({r"SELECT ProductId FROM cz.Application WHERE ApplicationId = %s": lambda p: [
        {"ProductId": 3 if p[0] == 1 else 4}]})
    assert admin_refactor.allowed_app(owner, conn, 1) and not admin_refactor.allowed_app(owner, conn, 2)
    assert admin_refactor.allowed_app(Access(False, True), conn, 2)
    assert not admin_refactor.allowed_app(Access(False, False), conn, 1)


# --------------------------------------------------------------------------- results pages

def test_why_the_rating(monkeypatch):
    monkeypatch.setattr(webui, "_STATE_RULES", {"sqlite-local": "local"})
    app = {"Rating": "B", "components": [{"ComponentName": "Parts", "Verdict": "config", "Tier": "server", "ComponentId": 1}],
           "findings": [{"ComponentName": "Parts", "RuleId": "sqlite-local", "Title": "Embedded file database"}]}
    html, stateful, refactor = webui.rating_why(app)
    assert "Why B:</b> Not stateless: Parts keeps its own data (Embedded file database)" in html
    assert [c["ComponentName"] for c in stateful] == ["Parts"] and refactor == []
    app = {"Rating": "B", "components": [{"ComponentName": "Jobs", "Verdict": "refactor", "Tier": "server"}], "findings": []}
    assert "Jobs need targeted code changes." in webui.rating_why(app)[0]
    assert "configuration only and keeps no data" in webui.rating_why({"Rating": "A", "components": [], "findings": []})[0]


def test_estimates_text_and_order_button():
    assert webui.est_text({"in": 3000, "out": 569, "seconds": 130}) == "~3,569 tokens · ~2 min"
    assert webui.est_text({"in": 10, "out": 0, "seconds": None}).endswith("time: learning")
    html = webui.order_button(7, 3, "stateless", "<input name='csrf'>", "Patch with LLM", {"in": 1, "out": 1, "seconds": 60})
    assert "name='Goal' value='stateless'" in html and "name='Component' value='3'" in html and "~2 tokens" in html


def test_notices_after_an_order_are_fixed_texts():
    from urllib.parse import parse_qs
    assert "waits for an administrator" in webui.refactor_notice(parse_qs("refactor=approval&files=2"))
    assert "own products" in webui.refactor_notice(parse_qs("refactor=not-yours"))


def test_external_links_open_in_a_new_tab():
    html = webui.external_links("<a href='https://example.com/x'>a</a><a href='/app/1'>b</a>"
                                "<a href=\"http://example.org\" target='_self'>c</a>")
    assert "<a href='https://example.com/x' target='_blank' rel='noopener noreferrer'>" in html
    assert "<a href='/app/1'>" in html and "target='_self'>c" in html
    assert "target='_blank'" in webui.page("t", "<a href='https://example.com'>x</a>")


def test_favicon():
    assert webui.FAVICON.startswith("<svg") and "<script" not in webui.FAVICON
    assert "<link rel='icon' href='/static/favicon.svg'" in webui.page("t", "")


def test_the_approval_policy_in_a_sentence():
    assert "no job needs approval" in admin_llmqueue.approval_text({"ApproveKinds": None, "ApproveMinTokens": 1})
    assert admin_llmqueue.approval_text({"ApproveKinds": "refactor", "ApproveMinTokens": 0}) == \
        "Now: all refactoring orders wait for approval."
    assert "10,000 input tokens or more wait" in admin_llmqueue.approval_text(
        {"ApproveKinds": "refactor,review", "ApproveMinTokens": 10000})
