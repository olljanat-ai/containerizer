"""Rule review: what the learning loop learns waits as a candidate with its evidence until someone
approves or rejects it. Unit tests use the file store and a copy of the ruleset; the end-to-end test
(admin pages, stored procedure, audit trail, grants) needs SQL Server (CONTAINERIZER_TEST_SQL)."""
import json
import os
import re
import shutil
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from containerizer import ai, cli, confidence, rules, verify
from containerizer import rulereview as rr
from containerizer.rules import RULES_DIR, load_rules

PLAN_RULE = {"id": "learned-run-readonly-path-shop-web", "phase": "plan", "source": "learned",
             "when": {"name": r"^Shop\.Web$"}, "plan": {"add_writable": ["/app/data"]},
             "why": "The app writes to a folder that is read-only in the hardened container.",
             "learned_from": "shop/Shop.Web", "learned_at": "2026-10-31"}
RESULT = {"app": "shop", "component": "Shop.Web", "status": "ok", "attempts": [
    {"attempt": 1, "stage": "run", "rule": "run-readonly-path", "outcome": "retry", "diagnosis": "read-only folder",
     "exit_code": "134", "log_tail": "System.UnauthorizedAccessException: Access to the path '/app/data' is denied.\n"
                                     "Server=db;User Id=sa;Password=hunter2;\nAuthorization: Bearer abc.def.ghi"},
    {"attempt": 2, "stage": "run", "status": "ok"}]}
FINDING_RULE = {"id": "learned-runtime-shop-web-1", "source": "learned", "severity": "refactor",
                "category": "runtime-observed", "title": "Windows-only API at runtime: System.Management",
                "why": "A Windows-only API was called at runtime: System.Management only works on Windows.",
                "fix": "Replace the call with a cross-platform API or guard it with OperatingSystem.IsWindows().",
                "refs": ["https://learn.microsoft.com/en-us/dotnet/standard/analyzers/platform-compat-analyzer"],
                "when": {"name": r"^Shop\.Web$"}, "learned_from": "shop/Shop.Web", "learned_at": "2026-10-31"}


@pytest.fixture
def learned(tmp_path, monkeypatch):
    """A learned folder of its own, so the tests never touch the repository's rules/learned."""
    d = tmp_path / "learned"
    shutil.copytree(RULES_DIR / "learned", d)
    monkeypatch.setattr(rules, "LEARNED_DIR", d)
    monkeypatch.setattr(verify, "LEARNED", d)
    monkeypatch.setattr(ai, "LEARNED", d)
    monkeypatch.delenv("CONTAINERIZER_SQL", raising=False)
    monkeypatch.delenv("CONTAINERIZER_RULE_REVIEW", raising=False)
    confidence.reset_cache()
    yield d
    confidence.reset_cache()


def learn_plan_rule(rule=PLAN_RULE):
    """What verify.persist_learning does, through the module's LEARNED path."""
    p = verify.LEARNED / "plan.yaml"
    d = verify._load(p, "rules")
    d["rules"].append(dict(rule))
    verify._save(p, d, "# test\n")


def ruleset_copy(tmp_path) -> Path:
    """The rules folder of a checkout of the internal rules repository (empty at first)."""
    d = tmp_path / "internal" / "rules"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# the learning run

def test_learning_run_stages_and_proposes(learned, tmp_path):
    before = (learned / "plan.yaml").read_text()
    store = rr.FileStore(tmp_path / "review")
    with rr.LearningSession(store, app="shop") as ls:
        assert verify.LEARNED != learned and rules.LEARNED_DIR == verify.LEARNED == ai.LEARNED
        learn_plan_rule()
        # the run itself uses what it learned
        assert PLAN_RULE["id"] in {r.id for r in load_rules()}
        ls.add_results([RESULT])
    # ... the ruleset does not
    assert rules.LEARNED_DIR == learned and (learned / "plan.yaml").read_text() == before
    assert PLAN_RULE["id"] not in {r.id for r in load_rules()}
    assert ls.proposed == [(1, "new", PLAN_RULE["id"])]
    [c] = store.list()
    assert c["Status"] == "pending" and c["Kind"] == "rule" and c["Confidence"] == 0.9 and c["Source"] == "learned"
    assert c["TargetFile"] == "70-reviewed.yaml" and c["LearnedFrom"] == "shop/Shop.Web"
    assert "+- id: learned-run-readonly-path-shop-web" in c["Diff"]
    ev = store.get(c["CandidateId"])["evidence"][0]
    assert ev["Application"] == "shop" and ev["Component"] == "Shop.Web" and ev["Outcome"] == "ok" and ev["Stage"] == "run"
    assert "run-readonly-path (retry) exit code 134: read-only folder" in ev["ExitReason"]
    # the failing log, with credentials masked
    assert "UnauthorizedAccessException" in ev["LogExcerpt"]
    assert "hunter2" not in ev["LogExcerpt"] and "abc.def.ghi" not in ev["LogExcerpt"] and "Password=***" in ev["LogExcerpt"]
    assert "log_tail" not in ev["AttemptsJson"]


def test_seen_again_rejected_is_remembered(learned, tmp_path):
    store = rr.FileStore(tmp_path / "review")
    for _ in range(2):
        with rr.LearningSession(store) as ls:
            learn_plan_rule({**PLAN_RULE, "learned_at": "2026-11-0" + str(_ + 1)})     # metadata differs, rule does not
            ls.add_results([RESULT])
    [c] = store.list()
    assert c["SeenCount"] == 2 and len(store.get(c["CandidateId"])["evidence"]) == 2
    rr.reject(store, c["CandidateId"], "jane@example.com", "Jane", "too specific")
    with rr.LearningSession(store) as ls:
        learn_plan_rule()
    assert ls.proposed == [(c["CandidateId"], "rejected", PLAN_RULE["id"])]
    assert store.list() == [] and len(store.get(c["CandidateId"])["evidence"]) == 2
    # a different rule is still proposed
    with rr.LearningSession(store) as ls:
        learn_plan_rule({**PLAN_RULE, "id": "learned-x", "plan": {"add_writable": ["/app/logs"]}})
    assert ls.proposed[0][1] == "new"


def test_review_off_keeps_the_old_direct_learning(learned, monkeypatch, tmp_path):
    monkeypatch.setenv("CONTAINERIZER_RULE_REVIEW", "off")
    with rr.LearningSession(rr.FileStore(tmp_path / "r")) as ls:
        assert verify.LEARNED == learned
        learn_plan_rule()
    assert ls.proposed == [] and PLAN_RULE["id"] in (learned / "plan.yaml").read_text()


def test_ai_rules_and_packages(learned, tmp_path):
    store = rr.FileStore(tmp_path / "review")
    with rr.LearningSession(store, ai=True, model="local-llm") as ls:
        p = ai.LEARNED / "ai-rules.yaml"
        p.write_text(yaml.safe_dump({"rules": [{**FINDING_RULE, "id": "ai-x", "source": "ai", "confidence": 0.7,
                                                "model": "local-llm", "learned_from": "shop/Shop.Web"}]}))
        pk = verify.LEARNED / "packages.yaml"
        d = yaml.safe_load(pk.read_text()) if pk.exists() else {}
        d = d or {}
        d.setdefault("linux_ok", []).append(r"Contoso\.Widgets")
        pk.write_text(yaml.safe_dump(d))
        ls.add_results([RESULT])
    by = {c["Kind"]: c for c in store.list()}
    assert by["rule"]["Model"] == "local-llm" and by["rule"]["Confidence"] == 0.7 and by["rule"]["Source"] == "ai"
    ev = store.get(by["rule"]["CandidateId"])["evidence"][0]
    assert ev["Model"] == "local-llm"
    assert by["package"]["RuleId"] == r"Contoso\.Widgets" and by["package"]["TargetFile"] == "packages-reviewed.yaml"


def test_a_failing_store_does_not_break_the_run(learned):
    class Broken:
        def propose(self, *a):
            raise RuntimeError("database down")
    msgs = []
    with rr.LearningSession(Broken(), log=msgs.append):
        learn_plan_rule()
    assert "could not store" in msgs[0] and rules.LEARNED_DIR == learned


# ---------------------------------------------------------------------------
# validation and fingerprints

def test_fingerprint_is_what_the_rule_does():
    a = rr.fingerprint("rule", PLAN_RULE)
    assert a == rr.fingerprint("rule", {**PLAN_RULE, "id": "other", "learned_at": "x", "why": "reworded", "model": "m"})
    assert a != rr.fingerprint("rule", {**PLAN_RULE, "plan": {"add_writable": ["/other"]}})
    assert a != rr.fingerprint("failure", PLAN_RULE)


@pytest.mark.parametrize("kind,entry,msg", [
    ("rule", {**FINDING_RULE, "why": "too short"}, "at least 60"),
    ("rule", {**FINDING_RULE, "severity": "blocker", "refs": []}, "verified https reference"),
    ("rule", {**FINDING_RULE, "refs": ["http://example.com"]}, "not an https URL"),
    ("rule", {**FINDING_RULE, "when": {"code": "(unclosed"}}, "not a valid regular expression"),
    ("rule", {**FINDING_RULE, "when": {}}, "a condition is required"),
    ("rule", {**FINDING_RULE, "id": "Bad Id!"}, "lower-case"),
    ("rule", {**FINDING_RULE, "id": "wcf-server"}, "already used"),
    ("rule", {**PLAN_RULE, "plan": {"privileged": True}}, "unknown build-plan keys"),
    ("rule", {**PLAN_RULE, "phase": "role"}, "phase"),
    ("failure", {"id": "x-fail", "stage": "run", "outcome": "retry", "match": ".*", "diagnosis": "d", "fix": {"base": "full"}},
     "matches an empty log"),
    ("failure", {"id": "x-fail", "stage": "run", "outcome": "retry", "match": "boom", "diagnosis": "d", "fix": {}},
     "patch is required"),
    ("package", ".*", "almost) any"),
    ("package", "(", "not a valid"),
    ("package", ["a"], "one regular expression"),
])
def test_validation_holds_learned_rules_to_the_curated_bar(kind, entry, msg):
    assert any(msg in p for p in rr.validate(kind, entry)), rr.validate(kind, entry)


def test_valid_rules_pass():
    assert rr.validate("rule", FINDING_RULE) == []
    assert rr.validate("rule", PLAN_RULE) == []
    assert rr.validate("failure", {"id": "x-fail", "stage": "build", "outcome": "retry", "match": "NU1605",
                                   "diagnosis": "Package downgrade", "fix": {"rid": "portable"}}) == []
    assert rr.validate("package", r"Contoso\.Widgets") == []


def test_redact():
    text = ("Password=s3cret; pwd: 'x y'; AccountKey=abc==; https://bob:pa55@host/x; Authorization: Basic Zm9vOmJhcg==\n"
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    out = rr.redact(text)
    for secret in ("s3cret", "x y", "abc==", "pa55", "Zm9vOmJhcg", "dozjgNryP4J3"):
        assert secret not in out
    assert "Password=***" in out and "https://***@host/x" in out


# ---------------------------------------------------------------------------
# approving

def _pending(store, entry=PLAN_RULE, kind="rule"):
    ev = rr.evidence_for(kind, entry, [RESULT], {}, False, None)
    return store.propose(rr.candidate_from(kind, entry, ev), ev)[0]


def test_approve_direct_writes_the_ruleset(tmp_path):
    store = rr.FileStore(tmp_path / "review")
    rdir = ruleset_copy(tmp_path)
    cfg = rr.ApplyConfig(mode="direct", rules_dir=rdir)
    cid = _pending(store)
    r = rr.approve(store, cid, "jane@example.com", "Jane", "looks right", None, cfg)
    assert r == {"candidate": cid, "applied": "direct", "where": str(rdir / "70-reviewed.yaml"), "edited": False}
    loaded = {x.id: x for x in load_rules([rdir])}
    rule = loaded[PLAN_RULE["id"]]
    assert rule.plan == {"add_writable": ["/app/data"]} and rule.meta["reviewed"]["by"] == "Jane"
    assert rule.meta["reviewed"]["candidate"] == cid
    c = store.get(cid)
    assert c["Status"] == "approved" and c["ReviewNote"] == "looks right" and c["AppliedAs"] == "direct"
    assert c["history"][-1]["Action"] == "approved"
    with pytest.raises(rr.ReviewError, match="already approved"):
        rr.approve(store, cid, "bob", cfg=cfg)
    # a second approved rule is appended after the first; the file stays valid YAML
    cid2 = _pending(store, FINDING_RULE)
    rr.approve(store, cid2, "jane", cfg=cfg)
    assert [x["id"] for x in yaml.safe_load((rdir / "70-reviewed.yaml").read_text())["rules"]] == \
        [PLAN_RULE["id"], FINDING_RULE["id"]]


def test_edit_then_approve_and_invalid_edits(tmp_path):
    store = rr.FileStore(tmp_path / "review")
    rdir = ruleset_copy(tmp_path)
    cfg = rr.ApplyConfig(mode="direct", rules_dir=rdir)
    cid = _pending(store, {**FINDING_RULE, "why": "short"})
    with pytest.raises(rr.ReviewError, match="at least 60"):
        rr.approve(store, cid, "jane", cfg=cfg)                       # as learned it is not good enough
    with pytest.raises(rr.ReviewError, match="not valid YAML"):
        rr.approve(store, cid, "jane", edited_yaml="id: [", cfg=cfg)
    assert store.get(cid)["Status"] == "pending" and not (rdir / "70-reviewed.yaml").exists()
    assert store.claim(cid, "x") and (store.release(cid) or True)    # a refused approval leaves no claim behind
    r = rr.approve(store, cid, "jane", "Jane", None, rr.to_yaml(FINDING_RULE), cfg)
    assert r["edited"] and store.get(cid)["Status"] == "approved"
    assert "only works on Windows" in store.get(cid)["FinalYaml"]


def test_claims_keep_two_reviewers_apart(tmp_path):
    store = rr.FileStore(tmp_path / "review")
    cid = _pending(store)
    assert store.claim(cid, "jane")
    with pytest.raises(rr.ReviewError, match="someone else"):
        rr.approve(store, cid, "bob", cfg=rr.ApplyConfig(mode="direct", rules_dir=ruleset_copy(tmp_path)))


def test_failure_rules_reach_the_verification_loop(tmp_path, monkeypatch):
    rdir = ruleset_copy(tmp_path)
    rr.append_rule(rdir, "failure", {"id": "x-reviewed", "stage": "build", "outcome": "retry", "match": "NU9999",
                                     "diagnosis": "d", "fix": {"rid": "portable"}})
    monkeypatch.setenv("CONTAINERIZER_REVIEWED_RULES", str(rdir))
    assert "x-reviewed" in {f["id"] for f in verify.load_failures()}


def test_approved_rules_load_from_the_internal_repository(tmp_path, monkeypatch):
    rdir = ruleset_copy(tmp_path)
    rr.append_rule(rdir, "rule", PLAN_RULE)
    rr.append_rule(rdir, "package", r"Contoso\.Widgets")
    assert PLAN_RULE["id"] not in {r.id for r in load_rules()}
    monkeypatch.setenv("CONTAINERIZER_REVIEWED_RULES", str(rdir))
    confidence.reset_cache()
    try:
        loaded = {r.id: r for r in load_rules()}
        assert loaded[PLAN_RULE["id"]].file == "reviewed/70-reviewed.yaml"
        assert confidence._catalog()[0].match("Contoso.Widgets")
        # ids are unique across the curated and the approved rules
        assert any("already used" in p for p in rr.validate("rule", PLAN_RULE))
    finally:
        monkeypatch.delenv("CONTAINERIZER_REVIEWED_RULES")
        confidence.reset_cache()
    # nothing was written into this tool's own rules folder
    assert not list(RULES_DIR.glob("*reviewed*"))


def test_appended_text_keeps_the_file_valid():
    assert yaml.safe_load(rr.appended_text("rule", PLAN_RULE, "# h\nrules: []\n"))["rules"] == [PLAN_RULE]
    with pytest.raises(rr.ReviewError, match="last list"):
        rr.appended_text("rule", PLAN_RULE, "rules:\n- id: a\n  when: {name: x}\nother: 1\n")


def test_apply_config(monkeypatch, tmp_path):
    assert rr.ApplyConfig.from_env({}).mode == "pr"
    with pytest.raises(rr.ReviewError, match="CONTAINERIZER_RULES_REPO"):
        rr.ApplyConfig.from_env({}).check()
    c = rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_REPO": "https://x-access-token:t@github.com/acme/rules.git"})
    assert c.repo == "https://github.com/acme/rules.git" and c.provider == "github"
    c.check()
    with pytest.raises(rr.ReviewError, match="https"):
        rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_REPO": "http://github.com/acme/rules"}).check()
    with pytest.raises(rr.ReviewError, match="provider"):
        rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_REPO": "https://git.example.com/rules"}).check()
    with pytest.raises(rr.ReviewError, match="pr or direct"):
        rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_APPLY": "yolo"}).check()
    with pytest.raises(rr.ReviewError, match="CONTAINERIZER_REVIEWED_RULES"):
        rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_APPLY": "direct"}).check()
    with pytest.raises(rr.ReviewError, match="tool's own folder"):
        rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_APPLY": "direct", "CONTAINERIZER_REVIEWED_RULES": str(RULES_DIR)}).check()
    rr.ApplyConfig.from_env({"CONTAINERIZER_RULES_APPLY": "direct", "CONTAINERIZER_REVIEWED_RULES": "/srv/rules"}).check()
    assert rr._pr_api(rr.ApplyConfig(repo="https://github.com/acme/rules.git", provider="github"))[0] == \
        "https://api.github.com/repos/acme/rules"
    assert rr._pr_api(rr.ApplyConfig(repo="https://gitlab.example.com/plat/sub/rules", provider="gitlab"))[0] == \
        "https://gitlab.example.com/api/v4/projects/plat%2Fsub%2Frules"
    assert rr._pr_api(rr.ApplyConfig(repo="https://dev.azure.com/org/Platform/_git/rules", provider="azure-devops"))[0] == \
        "https://dev.azure.com/org/Platform/_apis/git/repositories/rules"
    assert rr.infer_provider("https://contoso.visualstudio.com/P/_git/r") == "azure-devops"


@pytest.mark.parametrize("prov,repo,status,reply,url", [
    ("github", "https://github.com/acme/rules", 201, {"html_url": "https://github.com/acme/rules/pull/7"},
     "https://github.com/acme/rules/pull/7"),
    ("gitlab", "https://gitlab.com/acme/rules", 201, {"web_url": "https://gitlab.com/acme/rules/-/merge_requests/3"},
     "https://gitlab.com/acme/rules/-/merge_requests/3"),
    ("azure-devops", "https://dev.azure.com/acme/P/_git/rules", 201, {"pullRequestId": 12},
     "https://dev.azure.com/acme/P/_git/rules/pullrequest/12"),
])
def test_approve_opens_a_pull_request(tmp_path, monkeypatch, prov, repo, status, reply, url):
    import subprocess
    from containerizer import orgsource
    upstream = ruleset_copy(tmp_path / "up")

    def fake_clone(u, dest, branch="", header="", depth=1):
        assert u == repo and branch == "main" and header.startswith("Authorization: Basic ")
        shutil.copytree(upstream.parent, dest)
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
    pushed, calls = [], []
    real_git = orgsource.git

    def fake_git(args, cwd=None, url=None, header="", timeout=1800, check=True):
        if args[0] == "push":
            pushed.append((args, url, bool(header)))
            return ""
        return real_git(args, cwd=cwd, timeout=timeout, check=check)

    def fake_http(method, u, headers, body=None, timeout=60):
        if method == "GET":                                       # the repository's visibility
            return 200, {"visibility": "private"} if prov != "github" else {"private": True}
        calls.append((method, u, body))
        return status, reply
    monkeypatch.setattr(orgsource, "clone", fake_clone)
    monkeypatch.setattr(orgsource, "git", fake_git)
    monkeypatch.setattr(rr, "_http", fake_http)
    monkeypatch.setenv("CONTAINERIZER_RULES_TOKEN", "tok-123456")
    store = rr.FileStore(tmp_path / "review")
    cid = _pending(store)
    r = rr.approve(store, cid, "jane@example.com", "Jane", "ok",
                   cfg=rr.ApplyConfig(mode="pr", repo=repo, provider=prov))
    assert r["applied"] == "pr" and r["where"] == url and store.get(cid)["PullRequestUrl"] == url
    assert pushed and pushed[0][0][-1] == f"HEAD:refs/heads/containerizer/rule-review-{cid}" and pushed[0][2]
    method, api, body = calls[0]
    assert method == "POST" and "learned-run-readonly-path-shop-web" in json.dumps(body)
    assert "hunter2" not in json.dumps(body)                     # evidence logs stay out of the pull request
    assert not (upstream / "70-reviewed.yaml").exists()           # only the clone was changed


@pytest.mark.parametrize("prov,repo,reply", [
    ("github", "https://github.com/olljanat-ai/containerizer", {"private": False, "visibility": "public"}),
    ("gitlab", "https://gitlab.com/acme/rules", {"visibility": "public"}),
    ("azure-devops", "https://dev.azure.com/acme/P/_git/rules", {"visibility": "public"}),
    ("github", "https://github.com/acme/rules", {"_error": "HTTP 404"}),
])
def test_public_rules_repositories_are_refused(tmp_path, monkeypatch, prov, repo, reply):
    from containerizer import orgsource
    gets = []
    monkeypatch.setattr(orgsource, "clone", lambda *a, **k: pytest.fail("must not clone a public repository"))
    monkeypatch.setattr(rr, "_http", lambda m, u, h, b=None, timeout=60: gets.append(u) or (404 if "_error" in reply else 200, reply))
    monkeypatch.setenv("CONTAINERIZER_RULES_TOKEN", "tok-123456")
    store = rr.FileStore(tmp_path / "review")
    cid = _pending(store)
    with pytest.raises(rr.ReviewError, match="public|visibility"):
        rr.approve(store, cid, "jane", cfg=rr.ApplyConfig(mode="pr", repo=repo, provider=prov))
    assert store.get(cid)["Status"] == "pending"
    if prov == "azure-devops":
        assert gets == ["https://dev.azure.com/acme/_apis/projects/P?api-version=7.1"]


def test_pull_request_failure_keeps_it_pending(tmp_path, monkeypatch):
    from containerizer import orgsource
    monkeypatch.setattr(orgsource, "clone", lambda *a, **k: (_ for _ in ()).throw(orgsource.SourceError("denied")))
    monkeypatch.setattr(rr, "_http", lambda *a, **k: (200, {"private": True}))
    monkeypatch.setenv("CONTAINERIZER_RULES_TOKEN", "tok-123456")
    store = rr.FileStore(tmp_path / "review")
    cid = _pending(store)
    with pytest.raises(rr.ReviewError, match="denied"):
        rr.approve(store, cid, "jane", cfg=rr.ApplyConfig(mode="pr", repo="https://github.com/a/r", provider="github"))
    c = store.get(cid)
    assert c["Status"] == "pending" and not c["ClaimedBy"]


# ---------------------------------------------------------------------------
# command line

def test_cli(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CONTAINERIZER_SQL", raising=False)
    monkeypatch.delenv("CONTAINERIZER_ADMIN_SQL", raising=False)
    store = rr.FileStore(tmp_path / "review")
    cid = _pending(store)
    cid2 = _pending(store, FINDING_RULE)
    d = ["--dir", str(tmp_path / "review"), "--as", "jane@example.com"]
    assert cli.main(["rules", "list", *d]) == 0
    out = capsys.readouterr().out
    assert PLAN_RULE["id"] in out and "learned from shop/Shop.Web" in out
    assert cli.main(["rules", "show", str(cid), *d]) == 0
    out = capsys.readouterr().out
    assert "Password=***" in out and "+- id: learned-run-readonly-path-shop-web" in out
    monkeypatch.setenv("CONTAINERIZER_RULES_APPLY", "direct")
    monkeypatch.setenv("CONTAINERIZER_REVIEWED_RULES", str(ruleset_copy(tmp_path)))
    edited = tmp_path / "edit.yaml"
    edited.write_text(rr.to_yaml({**PLAN_RULE, "id": "reviewed-shop-web-data"}))
    assert cli.main(["rules", "approve", str(cid), "--edit", str(edited), "--note", "renamed", *d]) == 0
    assert "approved (edited)" in capsys.readouterr().out
    assert cli.main(["rules", "reject", str(cid2), "--note", "dup", *d]) == 0
    assert cli.main(["rules", "reject", str(cid2), *d]) == 1
    assert "already rejected" in capsys.readouterr().err
    assert cli.main(["rules", "list", "--status", "all", "--json", *d]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert {r["Status"] for r in rows} == {"approved", "rejected"}
    assert store.get(cid)["ReviewedBy"] == "jane@example.com"


# ---------------------------------------------------------------------------
# the role gate of the admin pages

def test_rule_review_gate(monkeypatch):
    pytest.importorskip("jwt")
    from containerizer import admin as adminmod
    from containerizer import admin_rules
    from containerizer.oidc import OidcConfig
    c = OidcConfig(issuer="https://idp.example.com", client_id="cz", client_secret="s", public_url="https://cz.example.com",
                   admins=["group:a"])
    reached = []

    class Conn:
        def set_user(self, *a):
            pass

        def close(self):
            pass
    adm = adminmod.Admin(c, lambda: Conn(), provider=object())
    monkeypatch.setattr(admin_rules, "route", lambda *a, **k: reached.append(1) or adminmod.Response(200, "rules"))

    def get(sid, path):
        return adm.handle("GET", path, "", {"Cookie": f"{adm.cookie}={sid}"}, b"")
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    assert get(viewer, "/admin/rules").status == 403 and not reached
    operator = adm.sessions.create("o@example.com", "O", False, True)
    adm.sessions.get(operator).operator = True            # what the Operator role will set at sign-in
    assert get(operator, "/admin/rules").status == 200 and reached
    assert get(operator, "/admin/rules/3").status == 200
    assert get(operator, "/admin/products").status == 403
    r = get(operator, "/admin")
    assert r.status == 303 and dict(r.headers)["Location"] == "/admin/rules"
    admin_ = adm.sessions.create("a@example.com", "A", True)
    assert get(admin_, "/admin/rules").status == 200
    assert adm.may_review_rules(adm.sessions.get(operator)) and not adm.may_review_rules(adm.sessions.get(viewer))
    assert "Rule review" in adm.nav({"Cookie": f"{adm.cookie}={operator}"})


# ---------------------------------------------------------------------------
# end to end with SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_rule_review_end_to_end(tmp_path, monkeypatch):
    import uuid
    pytest.importorskip("jwt")
    from test_admin import Browser, MockIdP, cfg, free_port
    from containerizer import admin as adminmod
    from containerizer import sqlstore, webui
    name = "czrr_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL) + ";Schema=rr_cz"
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)        # idempotent
    for login, role in (("cz_r_reader", "reader"), ("cz_r_writer", "writer"), ("cz_r_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    pw = "Test-Passw0rd!x"
    idp = MockIdP()
    httpd = None
    try:
        # the scan (writer login) proposes; the same rule again only adds evidence
        w = rr.SqlStore.connect(as_("cz_r_writer"), pw)
        ids = [_pending(w), _pending(w), _pending(w, FINDING_RULE), _pending(w, {**FINDING_RULE, "id": "x2", "title": "Other"})]
        assert ids[0] == ids[1] and len(set(ids)) == 3
        # the writer can only propose: no reading, no deciding
        for sql in ("SELECT TOP 1 * FROM cz.RuleCandidate", f"UPDATE cz.RuleCandidate SET Status = N'approved' WHERE CandidateId = {ids[0]}",
                    "INSERT cz.RuleCandidate (Kind, Fingerprint, RuleId, Title, Source, TargetFile, RuleYaml, Confidence, Status) "
                    "VALUES (N'rule', REPLICATE('a', 64), N'x', N'x', N'x', N'x', N'x', 1, N'approved')"):
            with pytest.raises(Exception, match="permission was denied"):
                w.conn.cursor().execute(sql)
            w.conn.rollback()
        w.close()
        # the reader (results pages) sees none of it
        r = sqlstore.connect(as_("cz_r_reader"), pw)
        with pytest.raises(Exception, match="permission was denied"):
            r.cursor().execute("SELECT TOP 1 * FROM cz.RuleEvidence")
        r.close()

        rdir = ruleset_copy(tmp_path)
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        adm = adminmod.Admin(cfg(idp, base), lambda: sqlstore.connect(as_("cz_r_admin"), pw))
        adm.rule_apply = rr.ApplyConfig(mode="direct", rules_dir=rdir)
        httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(lambda: sqlstore.connect(as_("cz_r_reader"), pw), adm))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        idp.claims = {"email": "jane@example.com", "name": "Jane Doe", "groups": ["cz-admins"]}
        b = Browser(base, idp)
        s, h, body = b.follow("/admin/rules")
        assert s == 200 and "Rule review" in body and "Waiting for review (3)" in body and PLAN_RULE["id"] in body
        assert "form-action 'self'" in h["Content-Security-Policy"]
        s, _, body = b.follow(f"/admin/rules/{ids[0]}")
        assert s == 200 and "seen 2 time(s)" in body and "Password=***" in body and "hunter2" not in body
        assert "UnauthorizedAccessException" in body and "run-readonly-path (retry) exit code 134" in body
        assert "<span class='add'>+- id: learned-run-readonly-path-shop-web</span>" in body
        csrf = b.csrf(body)
        # no token, no decision
        assert b.go(f"/admin/rules/{ids[0]}/approve", {"Yaml": "x"})[0] == 403
        # an invalid edit is refused with the reason and nothing changes
        s, _, body = b.follow(f"/admin/rules/{ids[0]}/approve", {"csrf": csrf, "Yaml": "id: [", "Note": ""})
        assert "Not saved: not valid YAML" in body and not (rdir / "70-reviewed.yaml").exists()
        # edit, then approve
        edited = rr.to_yaml({**PLAN_RULE, "id": "reviewed-shop-web-data"})
        s, _, body = b.follow(f"/admin/rules/{ids[0]}/approve", {"csrf": csrf, "Yaml": edited, "Note": "renamed the id"})
        assert "Approved with your edits; it was written to the ruleset files." in body and "Jane Doe" in body
        assert "reviewed-shop-web-data" in {x.id for x in load_rules([rdir])}
        # reject another with a reason
        s, _, body = b.follow(f"/admin/rules/{ids[2]}/reject", {"csrf": csrf, "Note": "duplicates a curated rule"})
        assert "Rejected" in body and "Waiting for review (1)" in body
        assert b.follow(f"/admin/rules/{ids[2]}/reject", {"csrf": csrf, "Note": ""})[2].count("already rejected") == 1
        # the change history names who decided what
        body = b.follow("/admin/audit?table=RuleCandidate")[2]
        assert "Proposed by the learning loop" in body and "duplicates a curated rule" in body
        assert body.count("Jane Doe") >= 2 and "<ins>approved</ins>" in body and "<ins>rejected</ins>" in body
        # a rejected rule is not proposed again; the writer is told so
        w = rr.SqlStore.connect(as_("cz_r_writer"), pw)
        assert w.propose(*_cand(FINDING_RULE)) == (ids[2], "rejected")
        w.close()
        a = rr.SqlStore.connect(as_("cz_r_admin"), pw)
        assert len(a.get(ids[2])["evidence"]) == 1 and a.counts() == {"pending": 1, "approved": 1, "rejected": 1}
        a.close()
    finally:
        idp.claims = {}
        if httpd:
            httpd.shutdown()
        idp.httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()


def _cand(entry, kind="rule"):
    ev = rr.evidence_for(kind, entry, [RESULT], {}, False, None)
    return rr.candidate_from(kind, entry, ev), ev
