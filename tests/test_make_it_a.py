""""Make it A" (refactor.py goal rating-a, variant.py, docs/refactoring.md#make-it-a): the order's plan, the loop
in one job (generate, apply, verify, repair round, re-assessment, a second pass, the call cap), the rating
before and after, the names of the patched copy (DNS-safe, unique per job), the deploy step shared with the
organization scan (org.deploy_app; local images), the sandbox variant, its own application (written to the
output repository, picked up by write_sandbox, removed again), its health for one namespace only, the result
and the view, and the web pages (the button, the bulk confirmation, Remove; roles, CSRF, fixed notices)."""
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from containerizer import admin_refactor, llmqueue as lq, org as orgmod, refactor as rf, variant
from containerizer import verify as vf
from test_llm_queue import FakeConn
from test_refactor import BANK, CSPROJ, REPLACE, SEARCH, _git, _post, _get, _loc, adm  # noqa: F401 - fixture

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "ci-demo"
SQLITE_CSPROJ = CSPROJ.replace('<PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />',
                               '<PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />\n'
                               '    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.0" />')
PROGRAM = ('var b = WebApplication.CreateBuilder(args);\n'
           'b.Services.AddDbContext<Db>(o => o.UseSqlite("Data Source=shop.db"));\n'
           'var app = b.Build();\napp.MapGet("/", () => "ok");\napp.Run();\n')
SQLITE_LINE = 'b.Services.AddDbContext<Db>(o => o.UseSqlite("Data Source=shop.db"));'
SQLSERVER_LINE = 'b.Services.AddDbContext<Db>(o => o.UseSqlServer(b.Configuration.GetConnectionString("Shop")));'


@pytest.fixture
def stateful(tmp_path):
    """A B-rated app: the LocalMachine certificate store (refactor) and an SQLite file (not stateless)."""
    root = tmp_path / "shop"
    (root / "src/Shop.Api").mkdir(parents=True)
    (root / "src/Shop.Api/Shop.Api.csproj").write_text(SQLITE_CSPROJ)
    (root / "src/Shop.Api/Program.cs").write_text(PROGRAM)
    (root / "src/Shop.Api/Bank.cs").write_text(BANK)
    _git(root, "init", "--quiet")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "initial")
    return root


def _doc(root):
    from containerizer.assess import assess
    return assess(root).to_dict()


def _pl(root, **kw):
    commit = _git(root, "rev-parse", "HEAD").strip()
    return rf.build_payload(_doc(root), {"type": "local", "path": str(root), "subdir": ".", "git": True}, commit,
                            source_key="shop", goal="rating-a", **kw)


def edit(file, search, replace, fixed=(), **kw):
    return {"edits": [{"file": file, "search": search, "replace": replace}], "new_files": [],
            "package_changes": kw.get("packages", []), "fixed": list(fixed), "not_fixed": [], "notes": ""}


NOTHING = {"edits": [], "new_files": [], "package_changes": [], "fixed": [], "not_fixed": [], "notes": ""}
PACKAGES = [{"action": "remove", "package": "Microsoft.EntityFrameworkCore.Sqlite", "version": "8.0.0"},
            {"action": "add", "package": "Microsoft.EntityFrameworkCore.SqlServer", "version": "8.0.0"}]


class Asker:
    """A fake LLM: answers by the file the prompt is about, counting the questions per file."""

    def __init__(self, answers):
        self.answers, self.asked, self.prompts = answers, {}, []

    def __call__(self, prompt, schema):
        self.prompts.append(prompt)
        if "An earlier change (the patch below)" in prompt:
            f = re.search(r"File (\S+) \(", prompt)[1]
            key = ("repair", f)
        else:
            f = re.search(r"^File (\S+) \(", prompt, re.M)[1]
            key = f
        self.asked[key] = self.asked.get(key, 0) + 1
        a = self.answers.get(key)
        return a(self.asked[key]) if callable(a) else (a or NOTHING)


GOOD = {"src/Shop.Api/Bank.cs": edit("src/Shop.Api/Bank.cs", SEARCH, REPLACE, ["cert-store-localmachine-code", "cert-store"]),
        "src/Shop.Api/Shop.Api.csproj": {**NOTHING, "package_changes": PACKAGES, "fixed": ["sqlite-local"]},
        "src/Shop.Api/Program.cs": edit("src/Shop.Api/Program.cs", SQLITE_LINE, SQLSERVER_LINE, ["move-state-out"])}


@pytest.fixture
def builds(monkeypatch):
    """verify.verify_component, mocked: the outcomes in order (the last one repeats)."""
    outcomes = ["ok"]
    seen = []
    monkeypatch.setattr(vf, "_run", lambda cmd, timeout, cwd=None: (0, ""))

    def fake(a, c, rules, timeout=900, work=None, **kw):
        seen.append({"app": a.name, "component": c.name, "root": Path(a.repo.root),
                     "bank": (Path(a.repo.root) / "src/Shop.Api/Bank.cs").read_text()})
        st = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        log = ("#12 /src/src/Shop.Api/Bank.cs(10,16): error CS0103: The name 'X509CertificateLoader' does not exist "
               "in the current context [/src/src/Shop.Api/Shop.Api.csproj]") if st == "build-failed" else ""
        return {"status": st, "attempts": [{"stage": "build", "status": st, "log_tail": log}], "seconds": 30}
    monkeypatch.setattr(vf, "verify_component", fake)
    return outcomes, seen


# --------------------------------------------------------------------------- the plan

def test_the_plan_takes_every_finding_and_the_state_move(stateful):
    pl = _pl(stateful)
    assert pl["goal"] == "rating-a" and pl["include_config"] is True and pl["deploy"] is True
    assert (pl["max_calls"], pl["max_passes"], pl["max_repairs"]) == (rf.MAX_CALLS_A, rf.MAX_PASSES_A, rf.MAX_REPAIRS_A)
    assert [(t["file"], [f["rule"] for f in t["findings"]]) for t in pl["tasks"]] == [
        ("src/Shop.Api/Bank.cs", ["cert-store-localmachine-code", "cert-store"]),
        ("src/Shop.Api/Shop.Api.csproj", ["sqlite-local"])]
    assert pl["state"] == [{"component": "Shop.Api", "state": ["Embedded file database (SQLite/LiteDB)"]}]
    # the runner adds the file that opens the embedded database, with the stateless guidance in its prompt
    (t,) = rf.state_tasks(pl, stateful)
    assert t["file"] == "src/Shop.Api/Program.cs" and t["findings"][0]["rule"] == "move-state-out"
    assert "Move the embedded database (SQLite or LiteDB) to Microsoft SQL Server" in rf.task_prompt(pl, t, stateful)[0]
    # and to the stateful component's other files too (the certificate fix needs no data move, but it is the
    # same component: the guidance is shown)
    assert "make the component stateless" in rf.task_prompt(pl, pl["tasks"][0], stateful)[0]
    # a fix order of the same app is unchanged
    fix = rf.build_payload(_doc(stateful), {"type": "none"}, None)
    assert fix["goal"] == "fix" and fix["max_calls"] == rf.MAX_CALLS and "max_passes" not in fix
    assert rf.dedupe_key(fix) != rf.dedupe_key(pl)
    # estimates: the state move adds a typical file per stateful component
    assert rf.order_chars(pl) == rf.estimate_chars(pl) + 6000


def test_an_app_with_nothing_to_change_is_refused(tmp_path):
    from tests.test_engine import web_app
    web_app(tmp_path)
    with pytest.raises(rf.RefactorError, match="nothing to change"):
        rf.build_payload(_doc(tmp_path), {"type": "none"}, None, goal="rating-a")


# --------------------------------------------------------------------------- the loop

def test_one_pass_reaches_a(stateful, tmp_path, builds):
    ask = Asker(GOOD)
    progress = []
    res = rf.run_order(_pl(stateful), tmp_path / "w", ask=ask, progress=progress.append, name="shop-refactor-7")
    assert res["status"] == "verified" and res["goal"] == "rating-a", res.get("reason")
    assert (res["rating_before"], res["rating_after"], res["rating_reached"]) == ("B", "A", True)
    assert res["calls"] == 3 and res["passes"] == 1 and res["still_state"] == [] and res["remaining"] == []
    assert [(x["pass"], x["round"], x["kind"]) for x in res["loop"]] == [(1, 0, "generate")]
    assert res["loop"][0]["rating"] == "A" and res["loop"][0]["verification"] == [{"component": "Shop.Api", "status": "ok"}]
    # one combined commit for the assessed commit, with every file
    assert res["patch"].count("Subject: [PATCH]") == 1 and "make it A" in res["patch"]
    assert {f["file"] for f in res["files"]} == {"src/Shop.Api/Bank.cs", "src/Shop.Api/Program.cs",
                                                 "src/Shop.Api/Shop.Api.csproj"}
    st = {(f["rule"], f["file"]): (f["status"], f.get("rules_after")) for f in res["findings"]}
    assert st[("move-state-out", "src/Shop.Api/Program.cs")] == ("fixed", "resolved")
    assert st[("sqlite-local", "src/Shop.Api/Shop.Api.csproj")] == ("fixed", "resolved")
    # the clean copy is named after the job: the verify step's image tags are unique per order
    _, seen = builds
    assert seen[0]["app"] == "shop-refactor-7" and seen[0]["root"] == (tmp_path / "w" / "shop-refactor-7").resolve()
    assert any(p.startswith("generating: pass 1: file 1 of 3") for p in progress)
    assert any(p.startswith("verifying: pass 1, round 1") for p in progress)
    assert any(p.startswith("verifying: pass 1: assessing the patched copy again") for p in progress)
    s = rf.summary(res)
    assert s.startswith("verified: B → A: Rating A reached; 4 of 4 fixed, 3 files changed")
    with pytest.raises(rf.RefactorError):          # git am applies it to the commit
        rf.git(["am", "--abort"], cwd=stateful)
    patch = tmp_path / "x.patch"
    patch.write_text(res["patch"])
    _git(stateful, "am", "--keep-cr", str(patch))
    assert "UseSqlServer" in (stateful / "src/Shop.Api/Program.cs").read_text()


def test_a_build_failure_gets_a_repair_round_in_the_same_job(stateful, tmp_path, builds):
    outcomes, seen = builds
    outcomes[:] = ["build-failed", "ok"]
    fixed_line = '        return X509CertificateLoader.LoadPkcs12FromFile(path, null);'
    answers = {**GOOD, ("repair", "src/Shop.Api/Bank.cs"):
               edit("src/Shop.Api/Bank.cs", fixed_line, '        return new X509Certificate2(path);', ["build-error"])}
    ask = Asker(answers)
    res = rf.run_order(_pl(stateful), tmp_path / "w", ask=ask, name="shop-refactor-8")
    assert res["status"] == "verified" and res["rating_reached"], res.get("reason")
    assert [(x["pass"], x["round"], x["kind"]) for x in res["loop"]] == [(1, 0, "generate"), (1, 1, "repair")]
    assert res["loop"][0]["verification"] == [{"component": "Shop.Api", "status": "build-failed"}]
    assert res["loop"][1]["verification"] == [{"component": "Shop.Api", "status": "ok"}]
    assert ask.asked[("repair", "src/Shop.Api/Bank.cs")] == 1 and res["calls"] == 4
    repair_prompt = next(p for p in ask.prompts if "An earlier change" in p)
    assert "CS0103" in repair_prompt and "LoadPkcs12FromFile" in repair_prompt           # the errors and the patch
    # the second build saw the repaired file; the patch is still one commit, with both changes
    assert "new X509Certificate2(path)" in seen[-1]["bank"]
    assert res["patch"].count("Subject: [PATCH]") == 1 and "new X509Certificate2(path)" in res["patch"]
    assert res["repairs"][0]["rule"] == "build-error" and res["repairs"][0]["status"] == "fixed"
    assert "build-error" not in {f["rule"] for f in res["findings"]}


def test_repair_rounds_are_capped(stateful, tmp_path, builds):
    outcomes, _ = builds
    outcomes[:] = ["build-failed"]
    fixed_line = '        return X509CertificateLoader.LoadPkcs12FromFile(path, null);'
    answers = {**GOOD, ("repair", "src/Shop.Api/Bank.cs"): lambda n: edit(
        "src/Shop.Api/Bank.cs", fixed_line if n == 1 else f"        return new X509Certificate2(path{'!' * (n - 1)});",
        f"        return new X509Certificate2(path{'!' * n});")}
    res = rf.run_order(_pl(stateful), tmp_path / "w", ask=Asker(answers), name="shop-refactor-9")
    assert [x["kind"] for x in res["loop"]] == ["generate", "repair", "repair"]       # max_repairs = 2
    assert res["status"] == "applies-only" and not res["rating_reached"] and res["passes"] == 1
    assert rf.status_label(res["status"], [v["status"] for v in res["verification"]])[0] == "Does not build"
    assert "Rating A reached" not in rf.summary(res) and "B → A by the rules, but not verified" in rf.summary(res)



def test_a_framework_package_is_fixed_without_the_llm_also_in_the_last_round(stateful, tmp_path, monkeypatch):
    """The lab's expense-claims: the LLM wrote Microsoft.AspNetCore.HttpOverrides into the project file itself (no
    package exists for it since .NET Core 3.0), and the last round's build failed only on that (NU1102). Before, the
    order stopped as "Does not build": the fix that needs no LLM ran only while repair rounds were left."""
    monkeypatch.setattr(vf, "_run", lambda cmd, timeout, cwd=None: (0, ""))
    builds = []

    def fake(a, c, rules, timeout=900, work=None, **kw):
        bad = "HttpOverrides" in (Path(a.repo.root) / "src/Shop.Api/Shop.Api.csproj").read_text()
        builds.append(bad)
        log = ("#12 3.620 /src/src/Shop.Api/Shop.Api.csproj : error NU1102: Unable to find package "
               "Microsoft.AspNetCore.HttpOverrides with version (>= 8.0.0)\n#12 3.620 /src/src/Shop.Api/Shop.Api.csproj"
               " : error NU1102:   - Found 39 version(s) in nuget.org [ Nearest version: 2.3.13 ]") if bad else ""
        st = "build-failed" if bad else "ok"
        return {"status": st, "attempts": [{"stage": "build", "status": st, "log_tail": log}], "seconds": 30}
    monkeypatch.setattr(vf, "verify_component", fake)
    serilog = '<PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />'
    csproj = {**edit("src/Shop.Api/Shop.Api.csproj", serilog,
                     serilog + '\n    <PackageReference Include="Microsoft.AspNetCore.HttpOverrides" Version="8.0.0" />',
                     ["sqlite-local"]), "package_changes": PACKAGES}
    ask = Asker({**GOOD, "src/Shop.Api/Shop.Api.csproj": csproj})
    res = rf.run_order({**_pl(stateful), "max_repairs": 0}, tmp_path / "w", ask=ask, name="shop-refactor-12")
    assert builds == [True, False]                      # the free fix, then a build that works
    assert res["status"] == "verified" and res["rating_reached"], res.get("reason")
    assert [(x["round"], x["kind"], x["calls"]) for x in res["loop"]] == [(0, "generate", 3), (1, "repair", 0)]
    assert '+    <PackageReference Include="Microsoft.AspNetCore.HttpOverrides"' not in res["patch"]
    assert any("removed the package Microsoft.AspNetCore.HttpOverrides" in n for n in res["notes"])
    assert not [p for p in ask.prompts if "An earlier change" in p]                  # no LLM repair asked

def test_still_b_gets_a_second_pass_on_what_remains(stateful, tmp_path, builds):
    # pass 1: the LLM leaves the project file and the database code alone; pass 2 does them
    answers = {**GOOD, "src/Shop.Api/Shop.Api.csproj": lambda n: NOTHING if n == 1 else GOOD["src/Shop.Api/Shop.Api.csproj"],
               "src/Shop.Api/Program.cs": lambda n: NOTHING if n == 1 else GOOD["src/Shop.Api/Program.cs"]}
    ask = Asker(answers)
    res = rf.run_order(_pl(stateful), tmp_path / "w", ask=ask, name="shop-refactor-10")
    assert res["passes"] == 2 and res["rating_reached"], (res["loop"], res.get("reason"))
    assert [(x["pass"], x["kind"], x.get("rating")) for x in res["loop"]] == [(1, "generate", "B"), (2, "generate", "A")]
    assert ask.asked["src/Shop.Api/Shop.Api.csproj"] == 2 and ask.asked["src/Shop.Api/Program.cs"] == 2
    assert ask.asked["src/Shop.Api/Bank.cs"] == 1                                      # fixed in pass 1: not again
    st = {(f["rule"], f["file"]): (f["status"], f["pass"]) for f in res["findings"]}
    assert st[("sqlite-local", "src/Shop.Api/Shop.Api.csproj")] == ("fixed", 2)
    assert st[("cert-store", "src/Shop.Api/Bank.cs")] == ("fixed", 1)


def test_the_call_cap_ends_the_loop_and_the_summary_says_what_is_left(stateful, tmp_path, builds):
    ask = Asker(GOOD)
    res = rf.run_order(_pl(stateful, max_calls=1), tmp_path / "w", ask=ask, name="shop-refactor-11")
    assert res["calls"] == 1 and res["passes"] == 1 and res["rating_after"] == "B" and not res["rating_reached"]
    assert list(ask.asked) == ["src/Shop.Api/Bank.cs"]
    skipped = [f for f in res["findings"] if f["status"] == "skipped"]
    assert skipped and "at most 1 LLM calls" in skipped[0]["reason"]
    assert res["still_state"] == [{"component": "Shop.Api", "state": ["Embedded file database (SQLite/LiteDB)"]}]
    s = rf.summary(res)
    assert s.startswith("verified: B → B; 2 of 2 fixed, 1 file changed")
    assert "still keeps data in Shop.Api (Embedded file database (SQLite/LiteDB))" in s


def test_no_usable_edits_fails_without_a_patch(stateful, tmp_path, builds):
    res = rf.run_order(_pl(stateful), tmp_path / "w", ask=Asker({}), name="shop-refactor-12")
    assert res["status"] == "failed" and res["patch"] is None and "no usable edits" in res["reason"]
    assert not res["rating_reached"] and rf.summary(res).startswith("failed: no usable edits")


def test_handler_without_a_database_does_not_deploy(stateful, tmp_path, monkeypatch, builds):
    from containerizer import ai
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    monkeypatch.setattr(ai, "ask_json", lambda prompt, schema, **kw: Asker(GOOD)(prompt, schema))
    out = lq.JOB_KINDS["refactor"].handler({"JobId": 5, "Payload": _pl(stateful)})
    res = out["result"]
    assert res["rating_reached"] and res["sandbox"] == {
        "status": "skipped", "reason": "not deployed: no results database (the order ran from a queue file)"}
    assert out["summary"].startswith("verified: B → A: Rating A reached") and out["summary"].endswith("; not deployed")
    json.dumps(res)
    assert list((tmp_path / "scratch").iterdir()) == []


def test_after_order_deploys_only_an_a_that_verifies():
    job = {"JobId": 3, "_connect": lambda: None}
    assert "rates B, not A" in variant.after_order(job, {}, {"rating_reached": False, "rating_after": "B"},
                                                   Path("/x"), "n")["reason"]
    assert "not verified" in variant.after_order(job, {}, {"rating_reached": True, "status": "applies-only"},
                                                 Path("/x"), "n")["reason"]
    assert "deployment is off" in variant.after_order(job, {"deploy": False}, {"rating_reached": True, "status": "verified"},
                                                      Path("/x"), "n")["reason"]


# --------------------------------------------------------------------------- names

@pytest.mark.parametrize("app,job,want", [
    ("shop", 42, "shop-refactor-42"),
    ("Shop_Floor.Api", 7, "shop-floor-api-refactor-7"),
    ("a" * 80, 123456, "a" * (63 - len("-refactor-123456")) + "-refactor-123456"),
    ("--x--", 1, "x-refactor-1"), ("", 1, "app-refactor-1"), (None, "cli123", "app-refactor-cli123"),
    ("proj--repo", 2, "proj-repo-refactor-2"),
])
def test_variant_names_are_dns_labels(app, job, want):
    n = rf.variant_name(app, job)
    assert n == want and len(n) <= 63 and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", n)
    from containerizer.generate import k8s_name
    assert k8s_name(n) == n                         # the namespace is the folder's name as it is


def test_variant_folder_tag_and_what_may_be_deleted():
    rel = variant.variant_rel("Contoso", "Shop Floor", "shop", 42)
    assert rel == "Contoso/Shop Floor/shop-refactor-42"
    assert variant.valid_folder(rel, 42) and not variant.valid_folder(rel, 43)
    assert not variant.valid_folder("Contoso/Shop Floor/shop", 42)
    assert not variant.valid_folder("Contoso/../shop-refactor-42", 42)
    assert not variant.valid_folder("sandbox/x/shop-refactor-42", 42)
    assert not variant.valid_folder("Contoso/shop-refactor-42", 42)
    t = variant.variant_tag(datetime(2026, 11, 1, 9, 5, tzinfo=timezone.utc), 42)
    assert t == "1.20261101.905-refactor.42"         # a pre-release: the original's semver range never takes it
    assert variant._same_commit("abcdef123456", "ABCDEF1234567890") and not variant._same_commit("abc", "abd")
    assert not variant._same_commit("", "abc") and not variant._same_commit(None, None)


# --------------------------------------------------------------------------- deploy_app: shared with the scan

def _getq(adm, sid, path, query):
    return adm.handle("GET", path, query, {"Cookie": f"{adm.cookie}={sid}"}, b"")


def _a_app(tmp_path, name):
    """The A-rated demo app in a folder of that name, verified (as analyze_app records it)."""
    from containerizer.assess import assess
    src = tmp_path / name
    shutil.copytree(DEMO, src)
    a = assess(src)
    a.verification = [{"component": c.name, "status": "ok"} for c in a.components]
    return src, a


class _Out:
    def __init__(self, root):
        self.root, self.url, self.git, self.push = root, "https://git.example/platform/sandbox.git", False, False


def _deploy(tmp_path, monkeypatch, **opts):
    from containerizer.gitops import GitOpsOptions
    from containerizer import imagescan
    builds, tags = [], []
    monkeypatch.setattr(imagescan, "build_image", lambda src, cdir, tag, timeout=1800: builds.append(tag) or (True, ""))
    monkeypatch.setattr(orgmod, "tag_local", lambda local, ref: tags.append((local, ref)))
    monkeypatch.delenv(orgmod.LOCAL_IMAGES_ENV, raising=False)
    src, a = _a_app(tmp_path, "shop-web")
    o = orgmod.OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", verify=True, gate=False,
                          **opts)
    out = _Out(tmp_path / "out")
    res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error", app="shop-web")
    rel = "acme/_/shop"
    gitops = GitOpsOptions(git_url=out.url, path=rel)
    res = orgmod.deploy_app(a, src, rel, o, out, None, "1.2.3", gitops, res, tmp_path / "work", "shop-web")
    return res, out.root / rel, builds, tags



def test_the_gate_waives_the_hardened_run_only_for_the_components_named(tmp_path, monkeypatch):
    """variant.deploy names the components a patch does not change (the lab's trade-rebates: the API ran in the
    sandbox, the patch changed only the portal, and the patched copy's gate dropped the API on its hardened run).
    Their hardened run is waived, nothing else: a build error, lint or vulnerabilities still exclude them."""
    from containerizer.gitops import GitOpsOptions
    from containerizer import imagescan
    from containerizer.generate import generate_app, k8s_name
    monkeypatch.delenv(orgmod.LOCAL_IMAGES_ENV, raising=False)
    failure = {"run": {"status": "hardening-failure"}}

    def gate_app(fa, gen, **kw):
        generate_app(fa, gen, registry=kw["registry"], gitops=kw["gitops"], tag=kw["tag"])
        return {"components": [{"component": k8s_name(c.name), "lint": [], "scans": [], **failure}
                               for c in fa.components]}
    monkeypatch.setattr(imagescan, "gate_app", gate_app)

    def deploy(waive, n):
        src, a = _a_app(tmp_path / f"d{n}", "shop-web")
        o = orgmod.OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", verify=True, gate=True)
        out = _Out(tmp_path / f"out{n}")
        res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error", app="shop-web")
        return orgmod.deploy_app(a, src, "acme/_/shop", o, out, None, "1.2.3", GitOpsOptions(git_url=out.url,
                                 path="acme/_/shop"), res, tmp_path / f"work{n}", "shop-web", gate_waive=waive), a
    res, a = deploy(None, 1)
    name = a.components[0].name
    assert res.status == "no-a-components" and res.excluded == [
        {"component": name, "reason": "security gate: does not run with the hardened pod security context"}]
    res, _ = deploy({name}, 2)
    assert res.status == "deployed" and not res.excluded
    assert res.components[0]["gate_waived"].startswith("does not run with the hardened pod security context: waived")
    failure = {"run": {"status": "ok"}, "build_error": "boom"}                  # not waived
    res, _ = deploy({name}, 3)
    assert res.status == "no-a-components" and res.excluded[0]["reason"] == "security gate: image build failed"

def test_deploy_app_pushes_as_before(tmp_path, monkeypatch):
    class Reg:
        pushed = []

        def push(self, local, ref, extra=()):
            self.pushed.append((local, ref))
            return "sha256:" + "a" * 64
    from containerizer.gitops import GitOpsOptions
    from containerizer import imagescan
    builds = []
    monkeypatch.setattr(imagescan, "build_image", lambda src, cdir, tag, timeout=1800: builds.append(tag) or (True, ""))
    monkeypatch.setattr(orgmod, "tag_local", lambda local, ref: pytest.fail("no local tag when pushing"))
    monkeypatch.setenv(orgmod.LOCAL_IMAGES_ENV, "1")              # ignored: Push images is on
    src, a = _a_app(tmp_path, "shop-web")
    o = orgmod.OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", verify=True, gate=False,
                          push_images=True)
    out = _Out(tmp_path / "out")
    res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error", app="shop-web",
                            commit="c" * 40)
    reg = Reg()
    res = orgmod.deploy_app(a, src, "acme/_/shop", o, out, reg, "1.2.3", GitOpsOptions(path="acme/_/shop"), res,
                            tmp_path / "work", "shop-web")
    assert res.status == "deployed" and builds == ["containerizer/shop-web-demo-web:gate"]
    assert reg.pushed == [("containerizer/shop-web-demo-web:gate", "reg.example/sandbox/shop-web/demo-web:1.2.3")]
    assert res.components[0]["digest"] == "sha256:" + "a" * 64 and "image_source" not in res.components[0]
    meta = json.loads((out.root / "acme/_/shop/containerizer.json").read_text())
    assert meta["status"] == "deployed" and meta["components"][0]["image"].endswith("/shop-web/demo-web:1.2.3")


def test_deploy_app_with_local_images_tags_and_never_pushes(tmp_path, monkeypatch):
    res, dest, builds, tags = _deploy(tmp_path, monkeypatch, push_images=False, local_images=True)
    ref = "reg.example/sandbox/shop-web/demo-web:1.2.3"
    assert res.status == "deployed" and builds == ["containerizer/shop-web-demo-web:gate"]
    assert tags == [("containerizer/shop-web-demo-web:gate", ref)]
    c = res.components[0]
    assert c["image"] == ref and c["image_source"] == "local" and "digest" not in c and "signature" not in c
    assert "not pushed" in c["note"]
    docs = [d for d in yaml.safe_load_all((dest / "demo-web" / "k8s.yaml").read_text()) if d]
    ctr = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert ctr["image"] == ref and ctr["imagePullPolicy"] == "IfNotPresent" and "@sha256" not in ctr["image"]
    assert "newTag: 1.2.3" in (dest / "kustomization.yaml").read_text()


def test_local_images_setting(monkeypatch):
    monkeypatch.setenv(orgmod.LOCAL_IMAGES_ENV, "1")
    assert orgmod.local_images(orgmod.OrgOptions(provider="github", org="a", registry="r", push_images=False))
    assert not orgmod.local_images(orgmod.OrgOptions(provider="github", org="a", registry="r", push_images=True))
    assert not orgmod.local_images(orgmod.OrgOptions(provider="github", org="a", registry="r", push_images=False,
                                                     local_images=False))
    monkeypatch.delenv(orgmod.LOCAL_IMAGES_ENV)
    assert not orgmod.local_images(orgmod.OrgOptions(provider="github", org="a", registry="r", push_images=False))


def test_deploy_app_without_push_or_local_images_builds_nothing(tmp_path, monkeypatch):
    res, dest, builds, tags = _deploy(tmp_path, monkeypatch, push_images=False)
    assert res.status == "deployed" and builds == [] and tags == []          # exactly as before
    assert "image_source" not in res.components[0]


def test_deploy_app_without_an_a_component_removes_the_folder(tmp_path, monkeypatch):
    from containerizer.gitops import GitOpsOptions
    src, a = _a_app(tmp_path, "shop-web")
    a.verification = [{"component": c.name, "status": "build-failed"} for c in a.components]
    out = _Out(tmp_path / "out")
    (out.root / "acme/_/shop").mkdir(parents=True)
    o = orgmod.OrgOptions(provider="github", org="acme", registry="r", verify=True, gate=False, push_images=False)
    res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error")
    res = orgmod.deploy_app(a, src, "acme/_/shop", o, out, None, "1", GitOpsOptions(), res, tmp_path / "w", "shop-web")
    assert res.status == "no-a-components" and "qualifies" in res.reason and not (out.root / "acme/_/shop").exists()


# --------------------------------------------------------------------------- the variant in the output repository

def _output(tmp_path):
    """An output repository (a local git folder) with the original app deployed by a scan."""
    from containerizer.gitops import GitOpsOptions
    out = tmp_path / "output"
    out.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=out, check=True)
    src, a = _a_app(tmp_path / "orig", "shop")
    o = orgmod.OrgOptions(provider="github", org="Contoso", registry="reg.example/sandbox", verify=True, gate=False,
                          push_images=False, output_dir=str(out))
    o2 = orgmod.Output(o, tmp_path / "w0")
    res = orgmod.RepoResult(provider="github", org="Contoso", project="_", repo="shop", status="error", app="shop",
                            source_key="https://github.com/contoso/shop#")
    orgmod.deploy_app(a, src, "Contoso/_/shop", o, o2, None, "1.0.0", GitOpsOptions(git_url=o2.url, path="Contoso/_/shop"),
                      res, tmp_path / "w0", "shop")
    orgmod.write_sandbox(out, o2.url, "main")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"], cwd=out, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "scan"], cwd=out, check=True)
    return out, o


TARGET = {"scan": {"ScanId": 3, "Provider": "github", "Organization": "Contoso", "Registry": "reg.example/sandbox",
                   "OutputRepo": None, "OutputBranch": "main", "PushImages": False, "Gate": False, "ImagePullSecret": None},
          "repo": {"ProjectName": "_", "Name": "shop", "CloneUrl": "https://github.com/contoso/shop.git",
                   "WebUrl": "https://github.com/contoso/shop", "DefaultBranch": "main", "AppName": "shop"}}
PAYLOAD = {"app": "shop", "commit": "c" * 40, "application_id": 7, "goal": "rating-a",
           "source": {"type": "org-clone", "scan_id": 3, "dir": "scan-3/repos/shop", "subdir": "."}}


def _log(out, n=1):
    return subprocess.run(["git", "log", f"-{n}", "--format=%s"], cwd=out, capture_output=True, text=True).stdout


def _head(out):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=out, capture_output=True, text=True).stdout.strip()


def _patched(tmp_path, monkeypatch, jid, out, o, now=None, payload=PAYLOAD, patch="From 1 Mon Sep 17 00:00:00 2001\n"):
    """An order's patched copy (the demo app, as run_rating_a leaves it) deployed by variant.deploy."""
    monkeypatch.setattr(variant, "_open", lambda connect, key, payload, work, deploying=True: (TARGET, o))
    monkeypatch.delenv(variant.KUBECONFIG_ENV, raising=False)
    work = tmp_path / f"job-{jid}"
    name = rf.variant_name("shop", jid)
    shutil.copytree(DEMO, work / name)
    result = {"status": "verified", "rating_reached": True, "verification": [{"component": "demo-web", "status": "ok"}],
              "patch": patch}
    now = now or datetime(2026, 11, 1, 9, 5, tzinfo=timezone.utc)
    result["sandbox"] = variant.deploy(None, None, payload, jid, result, work, name, lambda t: None, now=now)
    return result


def _scan(tmp_path, out, commit, tag="1.1.0"):
    """The organization scan of the application at `commit` (org.deploy_app, as _process_repo calls it), committed."""
    from containerizer.gitops import GitOpsOptions
    src, a = _a_app(tmp_path / f"scan-{tag}", "shop")
    o = orgmod.OrgOptions(provider="github", org="Contoso", registry="reg.example/sandbox", verify=True, gate=False,
                          push_images=False, output_dir=str(out))
    o2 = orgmod.Output(o, tmp_path / f"w-{tag}")
    res = orgmod.RepoResult(provider="github", org="Contoso", project="_", repo="shop", status="error", app="shop",
                            source_key="https://github.com/contoso/shop#", commit=commit)
    res = orgmod.deploy_app(a, src, "Contoso/_/shop", o, o2, None, tag, GitOpsOptions(git_url=o2.url, path="Contoso/_/shop"),
                            res, tmp_path / f"w-{tag}", "shop")
    orgmod.write_sandbox(out, o2.url, "main")
    o2.commit(f"scan {tag}")
    return res


def test_the_patched_copy_runs_in_place_and_remove_brings_the_scan_output_back(tmp_path, monkeypatch):
    out, o = _output(tmp_path)
    before = (out / "Contoso/_/shop/containerizer.json").read_text()
    scan_rev = _head(out)
    result = _patched(tmp_path, monkeypatch, 42, out, o)
    sb = result["sandbox"]
    assert sb["status"] == "deployed" and "health not checked (no cluster access configured" in sb["reason"]
    assert sb["in_place"] and sb["namespace"] == "shop" and sb["folder"] == "Contoso/_/shop" == sb["of"]
    assert sb["tag"] == "1.20261101.905-refactor.42" and sb["previous_revision"] == scan_rev
    assert sb["images"] == ["reg.example/sandbox/shop/demo-web:1.20261101.905-refactor.42"]   # the app's image path
    assert sb["commit"] == PAYLOAD["commit"] and len(sb["revision"]) == 40
    # one folder: the scan's output replaced, no -refactor- folder, sandbox/ lists the application once
    assert sorted(p.name for p in (out / "Contoso/_").iterdir()) == ["shop"]
    d = out / "Contoso/_/shop"
    meta = json.loads((d / "containerizer.json").read_text())
    assert meta["app"] == "shop" and meta["repo"] == "shop" and meta["source_key"] == "https://github.com/contoso/shop#"
    assert meta["patched"] == {"job": 42, "commit": PAYLOAD["commit"], "application_id": 7, "app": "shop",
                               "tag": "1.20261101.905-refactor.42", "deployed_at": "2026-11-01T09:05:00",
                               "previous_revision": scan_rev}
    assert (d / variant.PATCH_FILE).read_text() == result["patch"]
    assert yaml.safe_load((d / "kustomization.yaml").read_text())["namespace"] == "shop"
    ks = next(x for x in yaml.safe_load_all((d / "gitops/flux/git/sync.yaml").read_text()) if x and x["kind"] == "Kustomization")
    assert ks["metadata"]["name"] == "shop" and ks["spec"]["path"] == "./Contoso/_/shop"
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\n"
    assert yaml.safe_load((out / "sandbox/flux/apps/kustomization.yaml").read_text())["resources"] == [
        "../../../Contoso/_/shop/gitops/flux"]
    assert _log(out) == f"sandbox: shop runs the Make it A patch of order #42 (commit {'c' * 12})\n"
    # Remove from the sandbox: the scan's output is back from the output repository's history
    later = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)
    sb2 = variant.remove(None, None, 42, PAYLOAD, sb, tmp_path / "rm", "removed", "o@example.com", now=later)
    assert sb2["status"] == "removed" and sb2["removed_at"] == "2026-11-03T08:00:00" and sb2["removed_by"] == "o@example.com"
    assert sb2["reason"] == "removed from the sandbox by o@example.com: the scan's output is back in the application's folder"
    assert (d / "containerizer.json").read_text() == before and not (d / variant.PATCH_FILE).exists()
    assert subprocess.run(["git", "diff", "--quiet", scan_rev, "HEAD", "--", "Contoso"], cwd=out).returncode == 0
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\n"
    assert "gets the scan's output back: the Make it A patch of order #42 removed" in _log(out)
    with pytest.raises(variant.Skip):
        variant.remove(None, None, 42, PAYLOAD, {**sb, "folder": "../shop"}, tmp_path / "rm2")


def test_an_application_without_scan_output_goes_back_to_no_folder(tmp_path, monkeypatch):
    """The scan deployed nothing of it (no component rated A on its own): the patched copy gets the folder, and a
    removal takes it away again."""
    out, o = _output(tmp_path)
    shutil.rmtree(out / "Contoso/_/shop")
    orgmod.write_sandbox(out, "https://git.example/x.git", "main")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "nothing A"], cwd=out, check=True)
    sb = _patched(tmp_path, monkeypatch, 43, out, o)["sandbox"]
    assert sb["status"] == "deployed" and sb["folder"] == "Contoso/_/shop" and sb["namespace"] == "shop"
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\n"
    variant.remove(None, None, 43, PAYLOAD, sb, tmp_path / "rm")
    assert not (out / "Contoso/_/shop").exists() and (out / "sandbox/namespaces.txt").read_text() == ""


def test_a_scan_of_the_same_commit_keeps_the_patch_and_newer_code_replaces_it(tmp_path, monkeypatch):
    out, o = _output(tmp_path)
    scan_rev = _head(out)
    result = _patched(tmp_path, monkeypatch, 44, out, o)
    d = out / "Contoso/_/shop"
    patched = (d / "containerizer.json").read_text()
    # the same commit: the folder stays as it is; the scan's result says what runs there (LastDetail)
    res = _scan(tmp_path, out, "c" * 12, tag="1.1.0")
    assert res.status == "deployed" and res.patched["job"] == 44 and "order #44" in res.reason
    assert [c["image"] for c in res.components] == result["sandbox"]["images"]
    assert (d / "containerizer.json").read_text() == patched and (d / variant.PATCH_FILE).exists()
    # newer code: the scan writes its own output, and the order's copy is outdated
    res = _scan(tmp_path, out, "d" * 40, tag="1.2.0")
    assert res.status == "deployed" and not res.patched
    meta = json.loads((d / "containerizer.json").read_text())
    assert "patched" not in meta or not meta["patched"]
    assert meta["components"][0]["image"].endswith("/shop/demo-web:1.2.0") and not (d / variant.PATCH_FILE).exists()
    rows = [{"JobId": 44, "Payload": json.dumps(PAYLOAD), "Result": json.dumps(result), "RemoveRequestedAt": None,
             "RemoveRequestedBy": None}]
    conn = FakeConn({r"SELECT JobId, Payload, Result, RemoveRequestedAt": rows,
                     r"FROM cz.vApplicationLatest": [{"ApplicationId": 7, "SourceCommit": "d" * 40}]})
    rev = _head(out)
    assert variant.housekeep(lambda: conn, None, tmp_path / "hk", log=lambda m: None) == 1
    assert _head(out) == rev                    # nothing of the patch is left in the folder: nothing to commit
    (sql, params), = conn.sql(r"UPDATE cz.LlmJob SET Result")
    sb = json.loads(params[0])["sandbox"]
    assert sb["status"] == "outdated" and sb["reason"].startswith(f"replaced by newer code: a scan assessed commit {'d' * 12}")
    assert scan_rev


def test_a_newer_order_overwrites_the_older_one_in_place(tmp_path, monkeypatch):
    """Two orders of one application (the lab: jobs 168 and 172): the newer one's copy replaces the older one's in
    the same folder, keeping the scan's commit to go back to; housekeep records the older one as replaced; removing
    the newer one brings the scan's output back."""
    out, o = _output(tmp_path)
    before = (out / "Contoso/_/shop/containerizer.json").read_text()
    scan_rev = _head(out)
    now = datetime(2026, 11, 4, 9, 5, tzinfo=timezone.utc)
    rows = []
    for jid in (168, 172):
        result = _patched(tmp_path, monkeypatch, jid, out, o, now=now)
        assert result["sandbox"]["status"] == "deployed"
        rows.append({"JobId": jid, "Payload": json.dumps(PAYLOAD), "Result": json.dumps(result),
                     "RemoveRequestedAt": None, "RemoveRequestedBy": None})
    sb172 = json.loads(rows[1]["Result"])["sandbox"]
    assert sb172["previous_revision"] == scan_rev and sb172["replaced_job"] == 168
    meta = json.loads((out / "Contoso/_/shop/containerizer.json").read_text())
    assert meta["patched"]["job"] == 172 and meta["patched"]["previous_revision"] == scan_rev
    assert meta["patched"]["replaced_job"] == 168
    assert sorted(p.name for p in (out / "Contoso/_").iterdir()) == ["shop"]
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\n"
    conn = FakeConn({r"SELECT JobId, Payload, Result, RemoveRequestedAt": rows,
                     r"FROM cz.vApplicationLatest": [{"ApplicationId": 7, "SourceCommit": PAYLOAD["commit"]}]})
    rev = _head(out)
    assert variant.housekeep(lambda: conn, None, tmp_path / "hk", log=lambda m: None, now=now) == 1
    assert _head(out) == rev and json.loads((out / "Contoso/_/shop/containerizer.json").read_text())["patched"]["job"] == 172
    (sql, params), = conn.sql(r"UPDATE cz.LlmJob SET Result")
    sb = json.loads(params[0])["sandbox"]
    assert params[1] == 168 and sb["status"] == "outdated" and sb["removed_at"] == "2026-11-04T09:05:00"
    assert sb["removed_by"] is None and sb["reason"].startswith("replaced by newer code: order #172 deployed a newer")
    assert variant.STATUS_TEXT[sb["status"]] == "Replaced by newer code"
    variant.remove(None, None, 172, PAYLOAD, sb172, tmp_path / "rm")
    assert (out / "Contoso/_/shop/containerizer.json").read_text() == before


def _legacy(tmp_path, out, jid):
    """A variant folder of before (`<app>-refactor-<job>`, its own namespace), as variant.deploy wrote it until now."""
    from containerizer.gitops import GitOpsOptions
    src, a = _a_app(tmp_path / f"legacy-{jid}", f"shop-refactor-{jid}")
    o = orgmod.OrgOptions(provider="github", org="Contoso", registry="reg.example/sandbox", verify=True, gate=False,
                          push_images=False, output_dir=str(out))
    o2 = orgmod.Output(o, tmp_path / f"wl-{jid}")
    rel = f"Contoso/_/shop-refactor-{jid}"
    tag = f"1.20261101.905-refactor.{jid}"
    res = orgmod.RepoResult(provider="github", org="Contoso", project="_", repo=f"shop-refactor-{jid}", status="error",
                            app=f"shop-refactor-{jid}", commit="c" * 40)
    res = orgmod.deploy_app(a, src, rel, o, o2, None, tag, GitOpsOptions(git_url=o2.url, path=rel), res,
                            tmp_path / f"wl-{jid}", f"shop-refactor-{jid}", dev_database=False)
    doc = res.to_dict()
    doc["variant"] = {"of": "Contoso/_/shop", "of_app": "shop", "job": jid, "application_id": 7, "commit": "c" * 40}
    (out / rel / "containerizer.json").write_text(json.dumps(doc))
    orgmod.write_sandbox(out, o2.url, "main")
    o2.commit(f"containerizer: sandbox variant {rel} of Contoso/_/shop")
    return {"status": "running", "namespace": f"shop-refactor-{jid}", "folder": rel, "of": "Contoso/_/shop", "tag": tag,
            "images": [c["image"] for c in res.components], "url": f"https://demo-web-shop-refactor-{jid}.sb.example/",
            "commit": "c" * 40}


def test_housekeep_moves_the_variants_of_before_into_the_applications_folder(tmp_path, monkeypatch):
    """The latest active `<app>-refactor-<job>` of an application moves into its own folder (the source at the commit
    with the patch, generated under the application's name, the images it was built as), the variant folders go,
    sandbox/ lists the application once: one commit. The order's result points at the application's namespace."""
    out, o = _output(tmp_path)
    scan_rev0 = _head(out)
    # the scan worker's clone (the order's source) and the order's patch
    clone = tmp_path / "sources" / "scan-3" / "repos" / "shop"
    shutil.copytree(DEMO, clone)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=clone, check=True)
    subprocess.run(git + ["add", "-A"], cwd=clone, check=True)
    subprocess.run(git + ["commit", "-qm", "app"], cwd=clone, check=True)
    commit = _head(clone)
    (clone / "PATCHED.md").write_text("made A\n")
    subprocess.run(git + ["add", "-A"], cwd=clone, check=True)
    subprocess.run(git + ["commit", "-qm", "make it A"], cwd=clone, check=True)
    patch = subprocess.run(["git", "format-patch", "-1", "--stdout", "HEAD"], cwd=clone, capture_output=True,
                           text=True).stdout
    subprocess.run(["git", "reset", "-q", "--hard", "HEAD~1"], cwd=clone, check=True)
    monkeypatch.setenv(rf.SOURCES_ENV, str(tmp_path / "sources"))
    monkeypatch.setattr(variant, "_open", lambda connect, key, payload, work, deploying=True: (TARGET, o))
    pl = {**PAYLOAD, "commit": commit}
    old = {jid: _legacy(tmp_path, out, jid) for jid in (150, 151)}
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\nshop-refactor-150\nshop-refactor-151\n"
    scan_rev = _head(out)
    rows = [{"JobId": jid, "Payload": json.dumps(pl), "RemoveRequestedAt": None, "RemoveRequestedBy": None,
             "Result": json.dumps({"status": "verified", "patch": patch, "sandbox": {**sb, "commit": commit}})}
            for jid, sb in old.items()]
    conn = FakeConn({r"SELECT JobId, Payload, Result, RemoveRequestedAt": rows,
                     r"FROM cz.vApplicationLatest": [{"ApplicationId": 7, "SourceCommit": commit}]})
    now = datetime(2026, 11, 5, 7, 0, tzinfo=timezone.utc)
    logs = []
    assert variant.housekeep(lambda: conn, None, tmp_path / "hk", log=logs.append, now=now) == 2
    assert sorted(p.name for p in (out / "Contoso/_").iterdir()) == ["shop"]
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\n"
    assert yaml.safe_load((out / "sandbox/flux/apps/kustomization.yaml").read_text())["resources"] == [
        "../../../Contoso/_/shop/gitops/flux"]
    assert _log(out) == (f"sandbox: shop runs the Make it A patch of order #151 (commit {commit[:12]}), moved from "
                         f"Contoso/_/shop-refactor-151 (patched copies run in their application's folder now)\n")
    d = out / "Contoso/_/shop"
    meta = json.loads((d / "containerizer.json").read_text())
    assert meta["app"] == "shop" and meta["patched"]["job"] == 151 and meta["patched"]["previous_revision"] == scan_rev
    assert yaml.safe_load((d / "kustomization.yaml").read_text())["namespace"] == "shop"
    # the images it was built as: nothing was built again
    old_img = "reg.example/sandbox/shop-refactor-151/demo-web:1.20261101.905-refactor.151"
    assert meta["components"][0]["image"] == old_img
    assert f"image: {old_img}" in (d / "demo-web/k8s.yaml").read_text()
    assert "shop-refactor" not in (d / "gitops/flux/git/sync.yaml").read_text()
    upd = {p[1]: json.loads(p[0])["sandbox"] for _, p in conn.sql(r"UPDATE cz.LlmJob SET Result")}
    assert upd[151]["status"] == "deployed" and upd[151]["in_place"] and upd[151]["namespace"] == "shop"
    assert upd[151]["folder"] == "Contoso/_/shop" and upd[151]["moved_from"]["namespace"] == "shop-refactor-151"
    assert upd[151]["url"] != old[151]["url"] and "shop-refactor" not in str(upd[151]["url"])
    assert upd[150]["status"] == "outdated" and upd[150]["reason"].startswith("replaced by newer code: order #151")
    # removal of the moved one: the scan's output of before the move comes back
    variant.remove(None, None, 151, pl, upd[151], tmp_path / "rm")
    assert subprocess.run(["git", "diff", "--quiet", scan_rev0, "HEAD", "--", "Contoso"], cwd=out).returncode == 0


def test_no_output_repository_is_a_clear_note():
    conn = FakeConn({r"FROM cz.OrgScan WHERE ScanId": [{"ScanId": 3, "OutputRepo": None}]})
    with pytest.raises(variant.Skip, match="no output repository: the organization scan"):
        variant.load_target(conn, PAYLOAD)
    with pytest.raises(variant.Skip, match="not assessed by an organization scan"):
        variant.load_target(conn, {**PAYLOAD, "source": {"type": "git-url", "url": "https://x/y"}})
    r = variant.after_order({"JobId": 3, "_connect": lambda: conn}, PAYLOAD,
                            {"rating_reached": True, "status": "verified"}, Path("/nope"), "shop-refactor-3")
    assert r["status"] == "skipped" and r["reason"].startswith("no output repository")


def test_what_the_runner_removes_and_when():
    """Only what someone asked to remove, and copies whose application a scan assessed at another commit: a copy
    does not expire with time (an old expiry date is ignored)."""
    def row(jid, status="running", commit="a" * 40, app=7, req=None, removed=None, by=None):
        return {"JobId": jid, "RemoveRequestedAt": req, "RemoveRequestedBy": by,
                "Payload": json.dumps({"application_id": app, "commit": commit}),
                "Result": json.dumps({"sandbox": {"status": status, "expires_at": "2020-01-01T00:00:00",
                                                  "removed_at": removed}})}
    rows = [row(1), row(2, app=8), row(3, req=datetime(2026, 11, 1), by="o@example.com"),
            row(4, status="skipped", app=8), row(5, status="removed", removed="x", app=8), row(6, status="failing", app=8),
            row(7, app=9)]
    latest = {7: "a" * 12, 8: "b" * 40}                  # 7: the same commit (written short); 8: newer code; 9: unknown
    assert [(r["JobId"], why, by) for r, why, by in variant.due(rows, latest)] == [
        (2, "outdated", "b" * 40), (3, "removed", "o@example.com"), (6, "outdated", "b" * 40)]
    # no scan since: nothing is outdated by a commit, but job 6 is the latest order of application 8 and replaces 2
    assert variant.due(rows, {}) == [(rows[2], "removed", "o@example.com"), (rows[1], "outdated", 6)]


def _vrow(jid, app=7, commit="c" * 40, status="running", req=None, of="Contoso/_/shop", name="shop"):
    return {"JobId": jid, "RemoveRequestedAt": req, "RemoveRequestedBy": "o@example.com" if req else None,
            "Payload": json.dumps({"application_id": app, "app": name, "commit": commit}),
            "Result": json.dumps({"status": "verified", "sandbox": {
                "status": status, "folder": f"{of.rsplit('/', 1)[0]}/{name}-refactor-{jid}",
                "namespace": f"{name}-refactor-{jid}", "of": of, "commit": commit}})}


def test_only_the_latest_orders_variant_of_an_application_stays():
    """Two orders of one application on the same commit (the lab: jobs 168 and 172 of trade-rebates both ran):
    the newer order's variant replaces the older ones, whatever commit each was made for; other applications'
    variants stay; a variant someone asked to remove does not count as the one that stays."""
    rows = [_vrow(168), _vrow(172), _vrow(150, commit="e" * 40), _vrow(160, app=8, name="crm", of="Contoso/_/crm"),
            _vrow(175, status="deploying"), _vrow(171, app=9, name="hr", of="Contoso/_/hr"),
            _vrow(173, app=9, name="hr", of="Contoso/_/hr", req=datetime(2026, 11, 4))]
    got = [(r["JobId"], why, by) for r, why, by in variant.due(rows, {7: "c" * 12})]
    assert got == [(150, "outdated", "c" * 12), (173, "removed", "o@example.com"), (168, "outdated", 172)]
    # without an assessment of the application, the older commit's variant is replaced by the latest order too
    assert sorted((r["JobId"], by) for r, _, by in variant.due(rows, {}) if r["JobId"] in (150, 168)) == [
        (150, 172), (168, 172)]
    # variants without an ApplicationId: one application by the original's folder and its name
    old = [{**r, "Payload": json.dumps({"app": "shop", "commit": "c" * 40})} for r in (_vrow(3), _vrow(4))]
    assert [(r["JobId"], by) for r, _, by in variant.due(old)] == [(3, 4)]


def test_housekeep_records_the_removal(monkeypatch, tmp_path):
    sb = {"status": "running", "folder": "Contoso/_/shop-refactor-9", "namespace": "shop-refactor-9"}
    conn = FakeConn({r"SELECT JobId, Payload, Result, RemoveRequestedAt": [
        {"JobId": 9, "Payload": json.dumps(PAYLOAD), "Result": json.dumps({"status": "verified", "sandbox": sb}),
         "RemoveRequestedAt": datetime(2026, 11, 1), "RemoveRequestedBy": "o@example.com"}]})
    seen = []
    monkeypatch.setattr(variant, "remove", lambda connect, key, job, payload, s, work, status, by, now:
                        seen.append((job, status, by)) or {**s, "status": status, "removed_at": "t", "removed_by": by})
    assert variant.housekeep(lambda: conn, None, tmp_path, log=lambda m: None) == 1
    assert seen == [(9, "removed", "o@example.com")]
    (sql, params), = conn.sql(r"UPDATE cz.LlmJob SET Result")
    assert json.loads(params[0])["sandbox"]["status"] == "removed" and params[1] == 9
    # the runner calls it at most every minute, and a failure does not stop the queue
    logs = []

    def away():
        raise RuntimeError("db away")
    r = lq.Runner(away, name="r", log=logs.append, metrics=object.__new__(lq.QueueMetrics))
    # one line per step (sandbox variants, their state, applications' own output repositories, egress), once a
    # minute
    assert r.housekeep() == 0 and r.housekeep() == 0 and len(logs) == 4 and all("db away" in m for m in logs)



def _srow(jid, status="deployed", app=7, req=None, **sb):
    return {"JobId": jid, "RemoveRequestedAt": req, "Payload": json.dumps({"application_id": app, "app": "shop"}),
            "Result": json.dumps({"status": "verified", "sandbox": {
                "status": status, "in_place": True, "folder": "Contoso/_/shop", "of": "Contoso/_/shop",
                "namespace": "shop", **sb}})}


def test_which_sandbox_states_are_looked_at_again():
    """Health not known: again after 10 minutes; running or failing: hourly; the application's sandbox turned off:
    off at once (no cluster needed), looked at as soon as it is on again; removed: only the latest order of the
    application, hourly; asked to be removed, a variant of before: never."""
    now = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
    t = lambda m: variant._iso(now - timedelta(minutes=m))      # noqa: E731
    rows = [_srow(1, checked_at=t(11)), _srow(2, checked_at=t(5)), _srow(3, "running", app=8, checked_at=t(30)),
            _srow(4, "failing", app=9, checked_at=t(61)), _srow(5, "running", app=10, deployed_at=t(1)),
            _srow(6, "removed", app=11, removed_at=t(120)), _srow(7, "removed", app=11, removed_at=t(120)),
            _srow(8, "running", app=12, req=now), _srow(9, "off", app=13, looked_at=t(1)),
            _srow(10, "off", app=14), {**_srow(11, app=15), "Payload": "{"}]
    legacy = json.loads(rows[0]["Result"])
    legacy["sandbox"].update(in_place=False, folder="Contoso/_/shop-refactor-12")
    rows.append({**_srow(12, app=16), "Result": json.dumps(legacy)})
    now_set, look = variant.stale(rows, {10, 14, "https://x#"}, now)
    assert [(r["JobId"], sb["status"], sb["reason"]) for r, sb in now_set] == [(5, "off", variant.SANDBOX_OFF_TEXT)]
    assert [(r["JobId"], why) for r, why in look] == [
        (7, "is it in its application's folder again"), (4, "checked again"), (1, "checked again"),
        (9, "its application's sandbox is on again")]


def test_refresh_keeps_the_sandbox_state_true(tmp_path, monkeypatch):
    """A copy deployed while the cluster could not be read is checked again; one taken out while its folder still
    runs it is back; the application's sandbox turned off is shown as such; a folder that runs the scan's output
    again means the copy is not in the sandbox any more."""
    out, o = _output(tmp_path)
    now = datetime(2026, 11, 1, 9, 5, tzinfo=timezone.utc)
    result = _patched(tmp_path, monkeypatch, 9, out, o, now=now)
    sb = result["sandbox"]
    assert sb["status"] == "deployed" and "health not checked" in sb["reason"]
    monkeypatch.setattr(variant, "_open", lambda connect, key, payload, work, deploying=True: (TARGET, o))
    state = {"result": result, "off": []}

    def rows(_):
        return [{"JobId": 9, "Payload": json.dumps(PAYLOAD), "Result": json.dumps(state["result"]),
                 "RemoveRequestedAt": None}]
    conn = FakeConn({r"SELECT JobId, Payload, Result, RemoveRequestedAt": rows,
                     r"FROM cz.Application WHERE SandboxEnabled = 0": lambda _: state["off"]})
    checks = []

    def health(root, ns, rev, timeout=None):
        checks.append((ns, rev, timeout))
        return {"status": "running", "reason": "demo-web: Healthy", "checked_at": "now"}

    def step(at, n=1):
        before = len(conn.sql(r"UPDATE cz.LlmJob SET Result"))
        got = variant.refresh(lambda: conn, None, tmp_path / "rf", log=lambda m: None, now=at, health=health)
        upd = conn.sql(r"UPDATE cz.LlmJob SET Result")
        if len(upd) > before:
            state["result"] = json.loads(upd[-1][1][0])
        assert got == n
        return state["result"]["sandbox"]

    assert step(now + timedelta(minutes=5), 0) == sb and not checks          # too soon
    s = step(now + timedelta(minutes=11))
    assert s["status"] == "running" and checks == [("shop", "", variant.RECHECK_TIMEOUT)]
    assert step(now + timedelta(minutes=30), 0)["status"] == "running"        # hourly once it is known
    # taken out (an LLM-heavy chain, a removal that found the folder written since) while the folder runs it
    state["result"]["sandbox"] = {**s, "status": "removed", "removed_at": variant._iso(now + timedelta(hours=1)),
                                  "removed_by": "LLM-heavy mode (tried again)"}
    s = step(now + timedelta(hours=2, minutes=1))
    assert s["status"] == "running" and "removed_at" not in s and "removed_by" not in s
    assert s["back_at"] and s["reason"].startswith("in the sandbox again: its application's folder Contoso/_/shop")
    # the application's sandbox turned off, and on again
    state["off"] = [{"ApplicationId": 7, "SourceKey": "https://github.com/contoso/shop#"}]
    n = len(checks)
    s = step(now + timedelta(hours=2, minutes=2))
    assert s["status"] == "off" and s["reason"] == variant.SANDBOX_OFF_TEXT and len(checks) == n
    assert variant.STATUS_TEXT["off"] == "Sandbox turned off" and "off" in variant.ACTIVE
    assert step(now + timedelta(hours=5), 0)["status"] == "off"
    state["off"] = []
    assert step(now + timedelta(hours=5, minutes=1))["status"] == "running" and len(checks) == n + 1
    # the scan's output back in the folder: not in the sandbox any more
    variant.remove(None, None, 9, PAYLOAD, sb, tmp_path / "rm")
    s = step(now + timedelta(hours=7))
    assert s["status"] == "removed" and s["removed_at"] and s["removed_by"] is None
    assert s["reason"] == "not in the sandbox any more: its application's folder Contoso/_/shop runs the scan's output now"
    assert step(now + timedelta(hours=7, minutes=30), 0)["status"] == "removed"
    assert len(checks) == n + 1

# --------------------------------------------------------------------------- health: this namespace only

def test_verify_sandbox_filter_and_the_variants_health(tmp_path):
    from test_sandbox import FakeKube, deployment, flux_ks, output_repo, pod, SHA
    from containerizer import sandbox as sbm
    root = output_repo(tmp_path, app="shop-web")
    v = root / "Contoso" / "_" / "shop-refactor-4"
    shutil.copytree(root / "Contoso" / "_" / "shop", v)
    meta = json.loads((v / "containerizer.json").read_text())
    (v / "containerizer.json").write_text(json.dumps({**meta, "app": "shop-refactor-4"}))
    assert [a["app"] for a in sbm.deployed_apps(root)] == ["shop-web", "shop-refactor-4"]
    assert [a["app"] for a in sbm.deployed_apps(root, {"shop-refactor-4"})] == ["shop-refactor-4"]
    calls = {"n": 0}

    def flux():
        calls["n"] += 1
        if calls["n"] == 1:                         # the verifier's Role in the new namespace comes a little later
            raise sbm.KubeError("kustomizations is forbidden", "forbidden")
        return flux_ks()
    kube = FakeKube({(sbm.FLUX_KS, "shop-refactor-4", "shop-refactor-4"): flux,
                     ("deployments.apps", "shop-refactor-4", "web"): deployment("web"),
                     ("pods", "shop-refactor-4", "app.kubernetes.io/name=web"): {"items": [pod("web-1")]}})
    cfg = tmp_path / "kc"
    cfg.write_text("apiVersion: v1\n")
    kube.o = sbm.KubeOptions(kubeconfig=str(cfg))
    from test_sandbox import Clock
    clock = Clock()
    import containerizer.sandbox as sandbox_mod
    real = sandbox_mod.verify_sandbox
    h = variant.check_health(root, "shop-refactor-4", SHA, env={variant.KUBECONFIG_ENV: str(cfg),
                                                                 variant.TIMEOUT_ENV: "300"}, kube=kube,
                             sleep=clock.sleep)
    assert real is sandbox_mod.verify_sandbox
    assert h["status"] == "running", h
    assert calls["n"] >= 2
    assert not [c for c in kube.calls if c[0] == "get" and "shop-web" in c]          # nothing of the original read
    assert variant.check_health(root, "x", SHA, env={})["status"] == "deployed"
    # never readable within the timeout (the sandbox not connected): deployed, not checked; not "failing"
    never = FakeKube({(sbm.FLUX_KS, "shop-refactor-4", "shop-refactor-4"): sbm.KubeError("forbidden", "forbidden")})
    never.o = kube.o
    h = variant.check_health(root, "shop-refactor-4", SHA, env={variant.KUBECONFIG_ENV: str(cfg),
                                                                 variant.TIMEOUT_ENV: "60"}, kube=never, sleep=Clock().sleep)
    assert h["status"] == "deployed" and "health not checked: no read access" in h["reason"], h


def test_a_cronjob_that_has_not_run_yet_is_not_failing(tmp_path, monkeypatch):
    from containerizer import sandbox as sbm
    comps = [{"component": "Api", "status": sbm.HEALTHY, "status_text": "deployed and healthy"},
             {"component": "StatementWorker", "status": sbm.SCHEDULED, "status_text": "deployed, scheduled job has not run yet",
              "reason": "no run yet (the schedule is a placeholder: see HARDENING.md)", "log_tail": "x"}]
    monkeypatch.setattr(sbm, "verify_sandbox", lambda *a, **k: {"components": comps, "checked_at": "now"})
    cfg = tmp_path / "kc"
    cfg.write_text("apiVersion: v1\n")
    h = variant.check_health(tmp_path, "ns", "a" * 40, env={variant.KUBECONFIG_ENV: str(cfg)})
    assert h["status"] == "running", h
    assert "StatementWorker: deployed, scheduled job has not run yet" in h["reason"]
    assert not any("log_tail" in c for c in h["health"])
    comps[0]["status"] = sbm.FAILING
    assert variant.check_health(tmp_path, "ns", "a" * 40, env={variant.KUBECONFIG_ENV: str(cfg)})["status"] == "failing"


# --------------------------------------------------------------------------- the pages

APP = {"ApplicationId": 7, "ApplicationName": "Shop", "ScanName": "shop", "AssessmentId": 70, "Rating": "B",
       "SourceCommit": "a" * 40, "RepositoryUrl": "https://github.com/acme/shop", "SourcePath": "."}


def _answers(doc, **more):
    return {r"FROM cz.vApplicationLatest WHERE ApplicationId": [APP],
            r"FROM cz.vApplicationLatest WHERE Rating = 'B'": [APP, {**APP, "ApplicationId": 8, "ApplicationName": "Old",
                                                                   "SourceCommit": None}],
            r"SELECT ReportJson FROM cz.ApplicationAssessment": [{"ReportJson": json.dumps(doc)}],
            r"SELECT SourceKey FROM cz.Application": [{"SourceKey": "https://github.com/acme/shop#"}],
            r"FROM cz.OrgRepository WHERE RepositoryUrl": [{"ScanId": 3, "AppName": "shop"}],
            r"SELECT \* FROM cz.LlmQueueSettings": [{"ApproveKinds": "refactor", "ApproveMinTokens": 100, "Parallel": 1}],
            r"EXEC cz.QueueLlmJob": [{"JobId": 42}], **more}


def test_make_it_a_is_ordered_from_the_results_page(adm, stateful):
    adm.conn.answers = _answers(_doc(stateful))
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    r = _post(adm, op, "/admin/refactoring/new", ApplicationId="7", Goal="rating-a")
    assert _loc(r) == "/app/7?refactor=ordered-a&job=42&files=2#refactoring"
    (sql, params), = adm.conn.sql("EXEC cz.QueueLlmJob")
    pl = json.loads(params[-1])
    assert pl["goal"] == "rating-a" and pl["deploy"] is True and pl["source"]["scan_id"] == 3
    assert params[19] == lq.estimate_tokens("x" * rf.order_chars(pl))       # the estimate includes the state move
    # a repair is not ordered this way
    _post(adm, op, "/admin/refactoring/new", ApplicationId="7", Goal="repair")
    assert json.loads(adm.conn.sql("EXEC cz.QueueLlmJob")[-1][1][-1])["goal"] == "fix"
    adm.conn.answers[r"SELECT Status FROM cz.LlmJob WHERE JobId"] = [{"Status": "approval"}]
    assert "refactor=approval-a" in _loc(_post(adm, op, "/admin/refactoring/new", ApplicationId="7", Goal="rating-a"))


def test_results_page_make_it_a_button_and_variant_chip():
    from containerizer import webui
    app = {"ApplicationId": 7, "Rating": "B", "refactors": [
        {"JobId": 42, "Component": None, "Status": "verified", "Summary": "verified: B → A: Rating A reached",
         "Goal": "rating-a", "SandboxStatus": "running", "SandboxUrl": "https://web-shop-refactor-42.sandbox.example.com/",
         "QueuedAt": datetime(2026, 11, 1), "FinishedAt": datetime(2026, 11, 2)},
        {"JobId": 43, "Component": None, "Status": "verified", "Goal": "rating-a", "SandboxStatus": "failing",
         "SandboxUrl": "javascript:alert(1)//", "QueuedAt": datetime(2026, 11, 1)}],
           "components": [{"ComponentId": 11, "ComponentName": "Shop.Api", "Verdict": "refactor"}]}
    est = {"in": 9000, "out": 3000, "seconds": 1200}
    html = webui._refactoring(app, {"csrf": "<input type='hidden' name='csrf' value='t'>",
                                    "estimates": {(None, "rating-a"): est}})
    assert "<h3>Make it A</h3>" in html and "name='Goal' value='rating-a'" in html and ">Make it A</button>" in html
    assert "~12,000 tokens · ~20 min" in html and "until a scan finds newer code" in html
    assert "Running in the sandbox" in html and "Failing in the sandbox" in html
    assert "href='https://web-shop-refactor-42.sandbox.example.com/' target='_blank'" in html and "open ↗" in html
    assert "javascript:" not in html
    assert "Make it A</a>" in html                                         # the order's name in the list
    viewer = webui._refactoring(app, {"signin": True})
    assert "<form" not in viewer and "Running in the sandbox" in viewer
    from urllib.parse import parse_qs
    assert "&quot;Make it A&quot; requested: 2 file(s)" in webui.refactor_notice(parse_qs("refactor=ordered-a&files=2"))


def test_order_page_shows_the_loop_and_the_sandbox(adm):
    from test_refactor import _job, RESULT
    res = {**RESULT, "goal": "rating-a", "rating_before": "B", "rating_after": "A", "rating_reached": True, "passes": 1,
           "loop": [{"pass": 1, "round": 0, "kind": "generate", "files": 3, "calls": 3, "changes": 4,
                     "verification": [{"component": "Api", "status": "build-failed"}]},
                    {"pass": 1, "round": 1, "kind": "repair", "files": 1, "calls": 1, "changes": 1, "rating": "A",
                     "verification": [{"component": "Api", "status": "ok"}]}],
           "limits": {"max_calls": 16, "max_passes": 2, "max_repairs": 2}, "calls": 4,
           "sandbox": {"status": "running", "namespace": "shop-refactor-42", "folder": "Contoso/_/shop-refactor-42",
                       "of": "Contoso/_/shop", "url": "https://web-shop-refactor-42.sb.example.com/<x>",
                       "expires_at": "2026-11-08T09:05:00", "reason": "web: deployed and healthy <b>"}}
    job = _job(result=res, Payload=json.dumps({"commit": "a" * 40, "goal": "rating-a", "tasks": []}))
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [job],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}]}
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "Make it A #42" in b and "Rating A reached" in b and "Repair of the build or run" in b
    assert "Api: Build failed" in b and "16 LLM calls, 2 passes, 2 repair rounds a pass; 4 calls made" in b
    assert "Running in the sandbox" in b and "shop-refactor-42" in b and "Expires" not in b     # no expiry
    assert "&lt;b&gt;" in b and "<x>" not in b and "sb.example.com/&lt;x&gt;" not in b   # not plain: not linked
    assert "action='/admin/refactoring/42/remove'" in b and "Remove from the sandbox" in b
    ok = {**res["sandbox"], "url": "https://web-shop-refactor-42.sb.example.com/"}
    adm.conn.answers[r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'"] = [
        {**job, "Result": json.dumps({**res, "sandbox": ok})}]
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "href='https://web-shop-refactor-42.sb.example.com/' target='_blank' rel='noopener noreferrer'" in b
    # a removal asked for: no second button
    adm.conn.answers[r"SELECT RemoveRequestedAt FROM cz.LlmJob"] = [{"RemoveRequestedAt": datetime(2026, 11, 2)}]
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "Removal requested" in b and "/42/remove'" not in b and "(removal requested)" in b
    # the notice codes are fixed texts; anything else shows nothing of the URL
    assert "Removal requested: the LLM queue runner" in _getq(adm, op, "/admin/refactoring/42", "notice=remove-requested").body
    assert "evil" not in _getq(adm, op, "/admin/refactoring/42", "notice=%3Cb%3Eevil").body
    # in place (the application's own folder and namespace): no "Beside"; Remove brings the scan's output back
    here = {"status": "running", "in_place": True, "namespace": "shop", "folder": "Contoso/_/shop", "of": "Contoso/_/shop",
            "url": "https://web-shop.sb.example.com/", "moved_from": {"namespace": "shop-refactor-42"}}
    adm.conn.answers[r"SELECT RemoveRequestedAt FROM cz.LlmJob"] = [{"RemoveRequestedAt": None}]
    adm.conn.answers[r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'"] = [
        {**job, "Result": json.dumps({**res, "sandbox": here})}]
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "Beside" not in b and "It runs in place of the application's scan output" in b
    assert "<span class='label'>Before</span> <code>shop-refactor-42</code>" in b
    assert "Puts the scan's output back into the application's folder" in b
    assert "href='https://web-shop.sb.example.com/' target='_blank'" in b


def test_remove_needs_the_csrf_token_and_the_application(adm):
    from test_refactor import _job, RESULT
    res = {**RESULT, "goal": "rating-a", "sandbox": {"status": "running", "folder": "C/_/shop-refactor-42"}}
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [_job(result=res)],
                        r"SELECT ProductId FROM cz.Application": [{"ProductId": 5}]}
    other = adm.sessions.create("p@example.com", "P", False, True, False, ["bu:Finance"])
    assert _post(adm, other, "/admin/refactoring/42/remove").status in (403, 404)  # not their product's application
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _post(adm, op, "/admin/refactoring/42/remove", csrf="wrong").status == 403
    assert not adm.conn.sql("RemoveRequestedAt = SYSUTCDATETIME")
    r = _post(adm, op, "/admin/refactoring/42/remove")
    assert _loc(r) == "/admin/refactoring/42?notice=remove-requested"
    (sql, params), = adm.conn.sql("RemoveRequestedAt = SYSUTCDATETIME")
    assert params == ("o@example.com", 42) and "RemoveRequestedAt IS NULL" in sql
    adm.conn.answers[r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'"] = [
        _job(result={**res, "sandbox": {"status": "removed", "removed_at": "x"}})]
    assert _loc(_post(adm, op, "/admin/refactoring/42/remove")).endswith("notice=remove-not-active")


def test_make_it_a_for_every_b_app_smallest_first(adm, stateful, monkeypatch):
    """Admin -> Refactoring -> Make it A: every B application: the orders by their estimated tokens, smallest first,
    with the running total; queueing the ones under a number of tokens queues them approved."""
    from containerizer import admin_refactor
    big = {**APP, "ApplicationId": 9, "ApplicationName": "Big"}
    adm.conn.answers = _answers(_doc(stateful))
    adm.conn.answers[r"FROM cz.vApplicationLatest WHERE Rating = 'B'"] = [
        big, APP, {**APP, "ApplicationId": 8, "ApplicationName": "Old", "SourceCommit": None}]
    real = rf.order_chars
    monkeypatch.setattr(admin_refactor.rf, "order_chars",
                        lambda pl: 900_000 if pl.get("application_id") == 9 else real(pl))
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _get(adm, op, "/admin/refactoring/make-all-a").status == 403          # administrators only
    assert _post(adm, op, "/admin/refactoring/make-all-a").status == 403
    assert "make-all-a" not in _get(adm, op, "/admin/refactoring").body
    ad = adm.sessions.create("a@example.com", "A", True)
    assert "href='/admin/refactoring/make-all-a'" in _get(adm, ad, "/admin/refactoring").body
    r = _get(adm, ad, "/admin/refactoring/make-all-a")
    assert r.status == 200 and not adm.conn.sql("EXEC cz.QueueLlmJob")             # a GET orders nothing
    b = r.body
    assert b.index(">Shop<") < b.index(">Big<") < b.index(">Old<")                 # smallest first, unorderable last
    assert "<b>2 order(s)</b> can be queued" in b and "up to here:" in b
    assert "not ordered: the assessment recorded no commit" in b
    assert "Queue 1 order(s) under 20,000 tokens, approved" in b and "name='Limit' value='20000'" in b
    assert "style=" not in b                                                         # the CSP allows no inline style
    b = _getq(adm, ad, "/admin/refactoring/make-all-a", "limit=99999999").body
    assert "Queue 2 order(s) under 99,999,999 tokens, approved" in b
    assert _post(adm, ad, "/admin/refactoring/make-all-a", csrf="wrong").status == 403
    assert not adm.conn.sql("EXEC cz.QueueLlmJob")
    r = _post(adm, ad, "/admin/refactoring/make-all-a", Limit="20000")
    assert _loc(r) == "/admin/refactoring?bulk=queued&q=1&w=0&x=0&n=2&h=0"
    assert not adm.conn.sql("INSERT cz.LlmHeavyWindow")                             # not asked for
    (sql, params), = adm.conn.sql("EXEC cz.QueueLlmJob")
    assert json.loads(params[-1])["goal"] == "rating-a" and json.loads(params[-1])["application_id"] == 7
    (sql, params), = adm.conn.sql(r"SET Status = N'queued', ApprovedBy")             # approved at once
    assert params == ("a@example.com", 42)
    b = _getq(adm, ad, "/admin/refactoring", "bulk=queued&q=1&w=0&x=0&n=2").body
    assert "queued and approved for 1 application(s)" in b and "2 left out" in b
    assert "evil" not in _getq(adm, ad, "/admin/refactoring", "bulk=queued&q=%3Cevil%3E").body
    # and LLM-heavy mode for the applications ordered from here, for the hours chosen
    assert "name='Heavy' value='1'" in _get(adm, ad, "/admin/refactoring/make-all-a").body
    adm.conn.log.clear()
    adm.conn.answers[r"SELECT EndsAt FROM cz.LlmHeavyWindow"] = [{"EndsAt": datetime(2026, 11, 5)}]
    r = _post(adm, ad, "/admin/refactoring/make-all-a", Limit="20000", Heavy="1", Hours="12")
    assert _loc(r) == "/admin/refactoring?bulk=queued-heavy&q=1&w=0&x=0&n=2&h=12"
    (sql, params), = adm.conn.sql("INSERT cz.LlmHeavyWindow")
    assert params[:5] == (7, None, None, 12, 12) and params[5] == "a@example.com"   # the whole application
    assert adm.conn.sql("AutoApproveLlmJobs")                                        # what else of it waits
    b = _getq(adm, ad, "/admin/refactoring", "bulk=queued-heavy&q=1&w=0&x=0&n=2&h=12").body
    assert "each LLM-heavy for 12 hour(s)" in b
    adm.conn.log.clear()
    _post(adm, ad, "/admin/refactoring/make-all-a", Limit="20000", Heavy="1", Hours="999")     # not a choice: no window
    assert adm.conn.sql("EXEC cz.QueueLlmJob") and not adm.conn.sql("INSERT cz.LlmHeavyWindow")
    # an application with an order in the queue already is shown, not ordered again
    adm.conn.answers[r"FROM cz.LlmJob WHERE Kind = N'refactor'\s+AND Status IN"] = [
        {"ApplicationId": 7, "JobId": 42, "Status": "queued"}]
    b = _get(adm, ad, "/admin/refactoring/make-all-a").body
    assert "href='/admin/refactoring/42'>in the queue</a>" in b and "<b>1 order(s)</b> can be queued" in b
    # one that a verified patch makes A already is shown with it, not queued again from here
    adm.conn.answers[r"FROM cz.LlmJob WHERE Kind = N'refactor'\s+AND Status IN"] = []
    adm.conn.answers[r"FROM cz.vRefactorOrder\s+WHERE Goal = N'rating-a'"] = [
        {"ApplicationId": 7, "JobId": 77, "SandboxStatus": "skipped", "SandboxUrl": None, "FinishedAt": None,
         "SourceCommit": None}]
    adm.conn.answers[r"SELECT ApplicationId, SourceCommit FROM cz.vApplicationLatest$"] = [
        {"ApplicationId": 7, "SourceCommit": APP["SourceCommit"]}]
    b = _getq(adm, ad, "/admin/refactoring/make-all-a", "limit=99999999").body
    assert "made A by <a href='/admin/refactoring/77'>a patch</a>" in b and "<b>1 order(s)</b> can be queued" in b
    assert b.index(">Big<") < b.index(">Shop<") and "Queue 1 order(s) under 99,999,999 tokens" in b


# --------------------------------------------------------------------------- SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_schema_23_removal_request_and_the_view():
    """Schema 23: the admin login records a removal request (and nothing else of the result), the writer (the
    queue runner) records the variant in Result, the reader sees the goal, the rating after, the variant's state
    and URL in vRefactorOrder (and 'deploying' while it deploys); init is idempotent."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czmakea_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT MAX(Version) FROM cz.SchemaVersion")
    assert cur.fetchone()[0] >= 23
    cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'k', N'shop')")
    cur.execute("SELECT ApplicationId FROM cz.Application WHERE SourceKey = N'k'")
    app_id = cur.fetchone()[0]
    cur.execute("INSERT cz.SandboxCheck (ApplicationId, Status, Namespace) VALUES (%s, N'healthy', N'shop')", (app_id,))
    conn.commit()
    for login, role in (("cz_ma_admin", "admin"), ("cz_ma_reader", "reader"), ("cz_ma_writer", "writer")):
        sqlstore.create_login(conn, login, pw, role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    adm = sqlstore.connect(as_("cz_ma_admin"), pw)
    adm.set_user("o@example.com", "O", role="operator")
    job = {"Kind": "refactor", "App": "shop", "SourceKey": "k", "Priority": rf.PRIORITY, "DedupeKey": "e" * 64,
           "RequestedBy": None, "InputChars": 7000, "Payload": {"commit": "a" * 40, "goal": "rating-a", "tasks": []}}
    jid = lq.SqlJobQueue(None).add_with(adm, job)
    assert jid > 0
    w = sqlstore.connect(as_("cz_ma_writer"), pw)
    c = w.cursor()
    c.execute("UPDATE cz.LlmJob SET Status = N'running', Summary = N'deploying: building the images' WHERE JobId = %s", (jid,))
    w.commit()
    rd = sqlstore.connect(as_("cz_ma_reader"), pw)
    rc = rd.cursor(as_dict=True)
    rc.execute("SELECT * FROM cz.vRefactorOrder WHERE JobId = %s", (jid,))
    o = rc.fetchone()
    assert (o["Status"], o["SandboxStatus"], o["Goal"]) == ("deploying", "deploying", "rating-a")
    result = {"status": "verified", "rating_after": "A", "patch": "x",
              "sandbox": {"status": "running", "url": "https://web-shop-refactor-1.sb.example.com/",
                          "folder": "C/_/shop-refactor-1", "expires_at": "2026-11-08T00:00:00"}}
    c.execute("UPDATE cz.LlmJob SET Status = N'answered', Result = %s WHERE JobId = %s", (json.dumps(result), jid))
    w.commit()
    rc.execute("SELECT * FROM cz.vRefactorOrder WHERE ApplicationId = %s", (app_id,))
    (o,) = rc.fetchall()
    assert (o["Status"], o["RatingAfter"], o["SandboxStatus"]) == ("verified", "A", "running")
    assert o["SandboxUrl"] == "https://web-shop-refactor-1.sb.example.com/" and "RemoveRequestedBy" not in o
    # schema 42: one row per namespace; a patch running in place marks the application's own namespace (Variant, Own)
    ns = lambda: variant._rows(w, "SELECT Namespace, ApplicationId, Variant, Own, Status FROM cz.vSandboxNamespace "  # noqa: E731
                                  "WHERE ApplicationId = %s ORDER BY Namespace", (app_id,))
    assert [(r["Namespace"], r["Variant"], r["Own"]) for r in ns()] == [("shop", False, True)]   # no namespace yet
    for sb, want in (({"namespace": "shop-refactor-1"}, [("shop", False, True), ("shop-refactor-1", True, False)]),
                     ({"namespace": "shop", "in_place": True}, [("shop", True, True)])):
        c.execute("UPDATE cz.LlmJob SET Result = %s WHERE JobId = %s",
                  (json.dumps({**result, "sandbox": {**result["sandbox"], **sb}}), jid))
        w.commit()
        assert [(r["Namespace"], r["Variant"], r["Own"]) for r in ns()] == want
    c.execute("UPDATE cz.LlmJob SET Result = %s WHERE JobId = %s", (json.dumps(result), jid))
    w.commit()
    # "Remove from the sandbox": the admin login records the request, cannot touch the result
    a = adm.cursor()
    a.execute("UPDATE cz.LlmJob SET RemoveRequestedAt = SYSUTCDATETIME(), RemoveRequestedBy = %s WHERE JobId = %s",
              ("o@example.com", jid))
    adm.commit()
    with pytest.raises(Exception):
        adm.cursor().execute("UPDATE cz.LlmJob SET Result = N'{}' WHERE JobId = %s", (jid,))
    adm.rollback()
    # the runner sees it (variant.housekeep's query) and records the removal
    rows = variant._rows(w, "SELECT JobId, Payload, Result, RemoveRequestedAt, RemoveRequestedBy FROM cz.LlmJob "
                            "WHERE Kind = N'refactor' AND Status = N'answered' "
                            "AND JSON_VALUE(Result, '$.sandbox.folder') IS NOT NULL "
                            "AND JSON_VALUE(Result, '$.sandbox.removed_at') IS NULL")
    assert [r["JobId"] for r, why, by in variant.due(rows)] == [jid] and rows[0]["RemoveRequestedBy"] == "o@example.com"
    result["sandbox"].update(status="removed", removed_at="2026-11-02T00:00:00")
    c.execute("UPDATE cz.LlmJob SET Result = %s WHERE JobId = %s", (json.dumps(result), jid))
    w.commit()
    rc.execute("SELECT SandboxStatus FROM cz.vRefactorOrder WHERE JobId = %s", (jid,))
    assert rc.fetchone()["SandboxStatus"] == "removed"
    with pytest.raises(Exception):
        rd.cursor().execute("SELECT Result FROM cz.LlmJob")
    for x in (rd, w, adm):
        x.close()


# --------------------------------------------------------------------------- the call budget and LLM-heavy chains

def test_a_pass_leaves_calls_for_its_repair_round(stateful, tmp_path, builds):
    outcomes, _ = builds
    outcomes[:] = ["build-failed", "ok"]
    fixed_line = '        return X509CertificateLoader.LoadPkcs12FromFile(path, null);'
    answers = {**GOOD, ("repair", "src/Shop.Api/Bank.cs"):
               edit("src/Shop.Api/Bank.cs", fixed_line, '        return new X509Certificate2(path);', ["build-error"])}
    ask = Asker(answers)
    res = rf.run_order(_pl(stateful, max_calls=4), tmp_path / "w", ask=ask, name="shop-refactor-20")
    # 4 calls: one kept for the repair round (a quarter), so 3 for the files, and the repair still happens
    assert [x["kind"] for x in res["loop"]] == ["generate", "repair"] and res["calls"] == 4
    assert res["status"] == "verified" and res["rating_reached"], res.get("reason")


def test_an_llm_heavy_order_continues_from_the_patch_and_repairs_the_sandbox_failure(stateful, tmp_path, builds):
    first = rf.run_order(_pl(stateful), tmp_path / "w1", ask=Asker(GOOD), name="shop-refactor-21")
    assert first["status"] == "verified"
    line = '        return X509CertificateLoader.LoadPkcs12FromFile(path, null);'
    ask = Asker({("repair", "src/Shop.Api/Bank.cs"): edit("src/Shop.Api/Bank.cs", line,
                                                           '        return new X509Certificate2(path);')})
    pl = {**_pl(stateful), "base_patch": first["patch"], "heavy_round": 2,
          "sandbox_errors": "Shop.Api: failing: CrashLoopBackOff\nUnhandled exception: X509 store not found"}
    res = rf.run_order(pl, tmp_path / "w2", ask=ask, name="shop-refactor-22")
    assert [x["kind"] for x in res["loop"]][:2] == ["generate", "repair"]
    assert res["loop"][0]["files"] == 0                          # nothing generated again: the earlier patch stands
    prompt = next(p for p in ask.prompts if "An earlier change" in p)
    assert "X509 store not found" in prompt and "does not run" in prompt
    assert "UseSqlServer" in res["patch"] and "new X509Certificate2(path)" in res["patch"]   # both, one commit
    assert res["patch"].count("Subject: [PATCH]") == 1 and res["heavy_round"] == 2
    # after the window: no LLM call
    late = {**_pl(stateful), "deadline": "2020-01-01T00:00:00+00:00"}
    ask = Asker(GOOD)
    res = rf.run_order(late, tmp_path / "w3", ask=ask, name="shop-refactor-23")
    assert ask.asked == {} and "the LLM-heavy window ended: no further LLM calls" in res["notes"]


class Q:
    def __init__(self):
        self.jobs = []

    def add(self, job):
        self.jobs.append(job)
        return 500 + len(self.jobs)


def test_heavy_next_queues_until_it_runs_in_the_sandbox(stateful, tmp_path):
    ends = datetime.now(timezone.utc) + timedelta(hours=2)
    pl = {**_pl(stateful), "heavy_round": 3, "deadline": "x"}
    job = {"JobId": 41}
    assert rf.heavy_next(job, pl, {"sandbox": {"status": "running"}}, ends, tmp_path)["done"] == "running in the sandbox"
    assert rf.heavy_next(job, pl, {"patch": "p"}, ends, tmp_path, now=ends)["stopped"] == "the LLM-heavy window ended"
    q = Q()
    sb = {"status": "failing", "health": [{"component": "Shop.Api", "status": "failing", "reason": "CrashLoopBackOff",
                                           "log_tail": "boom"}, {"component": "Web", "status": "healthy"}]}
    out = rf.heavy_next(job, pl, {"patch": "P2", "status": "verified", "sandbox": sb}, ends, tmp_path, queue=q)
    assert out["next_job"] == 501 and out["round"] == 3 and out["next"] == "repair in the sandbox"
    nxt = q.jobs[0]["Payload"]
    assert nxt["base_patch"] == "P2" and nxt["heavy_round"] == 4 and nxt["heavy_parent"] == 41 and "deadline" not in nxt
    assert nxt["sandbox_errors"] == "Shop.Api: failing: CrashLoopBackOff\nboom"
    assert q.jobs[0]["RequestedBy"] == "LLM-heavy: after #41" and q.jobs[0]["Priority"] == rf.PRIORITY
    assert q.jobs[0]["DedupeKey"] != rf.dedupe_key(pl)          # a new order, not "already waiting"
    # it builds or runs no better: the next one repairs that; twice nothing new: stopped
    out = rf.heavy_next(job, {**pl, "base_patch": "P2"}, {"patch": "P2", "status": "applies-only"}, ends, tmp_path, queue=q)
    assert out["next"] == "repair the build or run" and q.jobs[-1]["Payload"]["heavy_same"] == 1
    out = rf.heavy_next(job, {**pl, "base_patch": "P2", "heavy_same": 1}, {"patch": None}, ends, tmp_path, queue=q)
    assert out["stopped"] == "two orders in a row changed nothing"
    assert rf.heavy_next(job, {**pl, "heavy_round": rf.HEAVY_MAX_ROUNDS}, {}, ends, tmp_path, queue=q)["stopped"].startswith("30")
    big = rf.heavy_payload(_pl(stateful), ends)
    assert (big["max_calls"], big["max_passes"], big["max_repairs"]) == (40, 4, 4) and big["deadline"]


def test_the_order_page_says_a_by_the_rules_is_not_a_yet(adm):
    from test_refactor import _job, RESULT
    res = {**RESULT, "status": "applies-only", "goal": "rating-a", "rating_before": "B", "rating_after": "A",
           "rating_reached": False, "loop": [], "remaining": [{"component": "Web", "rule": "unc-shares"}],
           "heavy": {"round": 2, "next_job": 77, "next": "repair the build or run", "until": "2026-11-04T06:00:00+00:00"}}
    job = _job(result=res, Payload=json.dumps({"commit": "a" * 40, "goal": "rating-a", "tasks": [], "heavy_round": 2,
                                               "heavy_parent": 70}))
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [job],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}]}
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "Still A" not in b and "A by the rules, but the patched copy does not build or run" in b
    assert "Findings left (they do not keep it from A):" in b
    assert "LLM-heavy mode, order 2 of the chain" in b and "href='/admin/refactoring/77'" in b and "#70" in b
    assert "2026-11-04 06:00 UTC" in b


def test_the_front_page_lists_the_apps_a_patch_makes_a():
    from containerizer import webui
    from test_sqlstore import _app
    apps = [{**_app(1, "billing", "B"), "APatch": {"JobId": 9, "SandboxStatus": "running",
                                                   "SandboxUrl": "https://billing-refactor-9.sb.example.com/",
                                                   "FinishedAt": datetime(2026, 11, 2)}},
            {**_app(2, "ledger", "B"), "APatch": {"JobId": 8, "SandboxStatus": "expired", "SandboxUrl": None,
                                                  "FinishedAt": datetime(2026, 10, 1)}},
            {**_app(3, "orders", "B"), "APatch": None}]
    html = webui.render_overview({"apps": apps, "unmapped": {}})
    assert "Made A by a patch" in html and "A with a patch (B → A)" in html and "1 running in the sandbox" in html
    assert "in place of the application's scan output" in html and "-refactor-&lt;order&gt;" not in html
    assert html.index(">Running in the sandbox<") < html.index("Expired in the sandbox")    # running ones first
    assert "href='https://billing-refactor-9.sb.example.com/' target='_blank'" in html
    assert "href='/app/1#refactoring'" in html and "/admin/refactoring/9" not in html  # the patch link: staff only
    assert html.count("class='a-patch here'") == 1 and html.count("class='a-patch'") == 1
    assert "/admin/refactoring/9" in webui.render_overview({"apps": apps, "unmapped": {}}, nav="<nav></nav>")
    assert "Made A by a patch" not in webui.render_overview({"apps": [apps[2]], "unmapped": {}})
    conn = FakeConn({r"FROM cz.vRefactorOrder": [
        {"ApplicationId": 1, "JobId": 3, "SandboxStatus": "failing", "SandboxUrl": None, "FinishedAt": None,
         "SourceCommit": None},
        {"ApplicationId": 1, "JobId": 2, "SandboxStatus": "running", "SandboxUrl": None, "FinishedAt": None,
         "SourceCommit": None},
        {"ApplicationId": 1, "JobId": 4, "SandboxStatus": "removed", "SandboxUrl": None, "FinishedAt": None,
         "SourceCommit": None}],
        r"FROM cz.vApplicationLatest": [{"ApplicationId": 1, "SourceCommit": "a" * 40}]})
    assert webui.load_a_patches(conn)[1]["JobId"] == 2                 # the one running in the sandbox


def test_a_chain_stuck_on_the_same_errors_starts_over_from_the_original_code(stateful, tmp_path):
    ends = datetime.now(timezone.utc) + timedelta(hours=2)
    job, q = {"JobId": 60}, Q()

    def failed(n):     # the same NuGet error each time; only the times and the patch differ
        log = (f"#11 {n}.4 /src/src/Web/Web.csproj : error NU1605: Detected package downgrade: X from 8.0.11 to 8.0.0\n"
               f"{n}.5 Failed to restore /src/src/Web/Web.csproj (in 1.{n} sec).")
        return {"patch": f"P{n}", "status": "applies-only",
                "verification": [{"component": "Web", "status": "build-failed", "log_tail": log},
                                 {"component": "Worker", "status": "ok"}]}

    pl = {**_pl(stateful), "base_patch": "P0", "heavy_round": 2}
    for n in (1, 2):
        rf.heavy_next(job, pl, failed(n), ends, tmp_path, queue=q)
        pl = q.jobs[-1]["Payload"]
        assert pl["base_patch"] == f"P{n}" and pl["heavy_stuck"] == n
    out = rf.heavy_next(job, pl, failed(3), ends, tmp_path, queue=q)
    assert out["next"] == "start over from the original code (3 orders in a row failed with the same errors)"
    fresh = q.jobs[-1]["Payload"]
    assert "base_patch" not in fresh and fresh["heavy_restarts"] == 1 and fresh["heavy_stuck"] == 0
    assert "NU1605" in fresh["heavy_avoid"] and fresh["tasks"] == _pl(stateful)["tasks"]
    # a different error resets the count; the second fresh start is the last
    other = {**failed(4), "verification": [{"component": "Web", "status": "run-failed", "log_tail": "Unhandled exception"}]}
    rf.heavy_next(job, {**fresh, "base_patch": "P3"}, other, ends, tmp_path, queue=q)
    assert q.jobs[-1]["Payload"]["heavy_stuck"] == 1
    last = {**pl, "heavy_restarts": rf.HEAVY_RESTARTS}
    assert rf.heavy_next(job, last, failed(5), ends, tmp_path, queue=q)["stopped"] == (
        "3 orders in a row failed with the same errors, after 2 fresh starts")


def test_the_runner_regenerates_the_sandbox_index_only_when_a_switch_changed(tmp_path, monkeypatch):
    from containerizer import credentials, org, variant, worker as wk
    off = {"set": set()}
    commits, written = [], []

    class Conn:
        def close(self):
            pass

    class Write:
        token, username = "t", "x-access-token"

    class Creds:
        def write_for(self, repo):
            return Write()

        def hosts(self):
            return {"git.example.com"}

    class Out:
        def __init__(self, o, d):
            self.root, self.url = d, o.output_repo

        def commit(self, msg):
            commits.append(msg)
            return True
    monkeypatch.setattr(org, "load_sandbox_off", lambda conn: set(off["set"]))
    monkeypatch.setattr(org, "Output", Out)
    monkeypatch.setattr(org, "write_sandbox", lambda root, url, branch, o=None: written.append((url, set(o or ()))))
    monkeypatch.setattr(credentials, "load", lambda conn, key=None: Creds())
    monkeypatch.setattr(wk, "allowed_hosts", lambda: set())
    scan = {"ScanId": 1, "Provider": "github", "Organization": "acme", "OutputRepo": "https://git.example.com/out",
            "OutputBranch": "main", "Gate": False, "PushImages": True, "ImagePullSecret": None, "Registry": "x"}
    monkeypatch.setattr(variant, "_rows", lambda conn, sql, params=(): [scan, {**scan, "ScanId": 2}])
    work = tmp_path / "w"
    assert variant.sync_sandbox(Conn, "key", work, log=lambda s: None) == 1          # the first time: once per repo
    assert written == [("https://git.example.com/out", set())]
    assert variant.sync_sandbox(Conn, "key", work, log=lambda s: None) == 0 and len(written) == 1   # nothing changed
    off["set"] = {"https://x/shop#", 5}                                           # turned off
    assert variant.sync_sandbox(Conn, "key", work, log=lambda s: None) == 1 and written[-1][1] == {"https://x/shop#", 5}
    off["set"] = set()                                                            # on again
    assert variant.sync_sandbox(Conn, "key", work, log=lambda s: None) == 1 and written[-1][1] == set()
    assert "sandbox switches" in commits[0]


def test_a_make_it_a_copy_of_an_application_whose_sandbox_is_off_is_not_deployed():
    from containerizer import variant

    class Cur:
        def execute(self, sql, params=()):
            self.sql = sql

        def fetchone(self):
            return (False,)

    class Conn:
        def cursor(self, as_dict=False):
            return Cur()

        def close(self):
            pass
    with pytest.raises(variant.Skip, match="sandbox is turned off"):
        variant._open(Conn, None, {"application_id": 5, "source": {"type": "org-clone", "scan_id": 1}}, Path("/tmp/x"))


def test_the_order_page_says_why_each_component_was_left_out(adm):
    from test_refactor import _job, RESULT
    res = {**RESULT, "status": "verified", "goal": "rating-a", "rating_before": "B", "rating_after": "A",
           "rating_reached": True, "loop": [],
           "sandbox": {"status": "skipped", "namespace": "pc-refactor-152",
                       "reason": "not deployed: none of 1 server components qualifies",
                       "excluded": [{"component": "PartsCatalog", "reason": "security gate: <b>3 fixable</b> vulnerabilities"}]}}
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [_job(result=res, Payload=json.dumps({"commit": "a" * 40, "goal": "rating-a", "tasks": []}))],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}]}
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "<li><b>PartsCatalog</b>: security gate: &lt;b&gt;3 fixable&lt;/b&gt; vulnerabilities</li>" in b


# --------------------------------------------------------------------------- newer code: the earlier patch reused

def _new_commit(root, path, old, new):
    f = root / path
    f.write_text(f.read_text().replace(old, new) if old else f.read_text() + new)
    _git(root, "commit", "--quiet", "-am", "newer code")


def test_newer_code_starts_from_the_earlier_patch_without_the_llm(stateful, tmp_path, builds):
    first = rf.run_order(_pl(stateful), tmp_path / "w1", ask=Asker(GOOD), name="shop-refactor-30")
    assert first["status"] == "verified" and first["rating_after"] == "A"
    _new_commit(stateful, "src/Shop.Api/Bank.cs", "", "// newer code, elsewhere in the file\n")
    pl = {**_pl(stateful), "reuse_patch": first["patch"], "reuse_job": 30, "reuse_commit": first["commit"]}
    ask = Asker(GOOD)
    res = rf.run_order(pl, tmp_path / "w2", ask=ask, name="shop-refactor-31")
    assert ask.asked == {} and res["calls"] == 0                  # every file of the earlier patch still applies
    assert res["status"] == "verified" and res["rating_reached"], res.get("reason")
    assert sorted(res["reused"]["files"]) == ["src/Shop.Api/Bank.cs", "src/Shop.Api/Program.cs",
                                               "src/Shop.Api/Shop.Api.csproj"] and res["reused"]["edited"] == []
    assert res["commit"] != first["commit"] and "for the assessment of commit " + res["commit"][:12] in res["patch"]
    assert any("reused order #30's patch" in n for n in res["notes"])


def test_a_file_the_earlier_patch_no_longer_applies_to_is_edited_again(stateful, tmp_path, builds):
    first = rf.run_order(_pl(stateful), tmp_path / "w1", ask=Asker(GOOD), name="shop-refactor-32")
    moved = SQLITE_LINE.replace("shop.db", "data/shop.db")
    _new_commit(stateful, "src/Shop.Api/Program.cs", SQLITE_LINE, moved)
    pl = {**_pl(stateful), "reuse_patch": first["patch"], "reuse_job": 32, "reuse_commit": first["commit"]}
    ask = Asker({"src/Shop.Api/Program.cs": edit("src/Shop.Api/Program.cs", moved, SQLSERVER_LINE, ["move-state-out"])})
    res = rf.run_order(pl, tmp_path / "w2", ask=ask, name="shop-refactor-33")
    assert list(ask.asked) == ["src/Shop.Api/Program.cs"]          # only the file it did not apply to
    assert res["reused"]["edited"] == ["src/Shop.Api/Program.cs"] and "src/Shop.Api/Bank.cs" in res["reused"]["files"]
    assert res["status"] == "verified" and res["rating_reached"], res.get("reason")
    assert "UseSqlServer" in res["patch"] and "<<<<<<<" not in res["patch"]


def test_a_reused_patch_is_not_carried_into_the_orders_after_it(stateful, tmp_path):
    pl = {**_pl(stateful), "reuse_patch": "P", "reuse_job": 3, "reuse_commit": "c" * 40}
    rep = rf.repair_payload(pl, {"patch": "P2", "verification": []}, 9)
    assert rep["base_patch"] == "P2" and not set(rf.REUSE_KEYS) & set(rep)
    q = Q()
    rf.heavy_next({"JobId": 41}, {**pl, "heavy_round": 2}, {"patch": "P2", "status": "applies-only"},
                  datetime.now(timezone.utc) + timedelta(hours=2), tmp_path, queue=q)
    assert q.jobs[0]["Payload"]["base_patch"] == "P2" and not set(rf.REUSE_KEYS) & set(q.jobs[0]["Payload"])


def test_reusable_patch_is_the_newest_working_one_for_another_commit():
    seen = []

    def rows(params):
        seen.append(params)
        return [{"JobId": 12, "SourceCommit": "a" * 40, "Result": json.dumps({"patch": "From x\n"})}]
    conn = FakeConn({r"FROM cz.vRefactorOrder o JOIN cz.LlmJob j": rows})
    assert admin_refactor.reusable_patch(conn, 5, "b" * 40) == {"reuse_patch": "From x\n", "reuse_job": 12,
                                                                "reuse_commit": "a" * 40}
    assert seen == [(5, "b" * 40)]
    assert admin_refactor.reusable_patch(FakeConn({}), 5, "b" * 40) == {}


def test_a_patch_for_older_code_no_longer_counts_as_made_a():
    from containerizer import webui
    def o(jid, commit, app=1):
        return {"ApplicationId": app, "JobId": jid, "SandboxStatus": "running", "SandboxUrl": None, "FinishedAt": None,
                "SourceCommit": commit}
    latest = [{"ApplicationId": 1, "SourceCommit": "a" * 40}, {"ApplicationId": 2, "SourceCommit": None}]
    conn = FakeConn({r"FROM cz.vRefactorOrder": [o(5, "b" * 40), o(2, "a" * 40), o(3, None, app=2), o(4, "c" * 40, app=3)],
                     r"FROM cz.vApplicationLatest": latest})
    got = webui.load_a_patches(conn)
    # the newer order (5) was made for older code; application 3 has no latest assessment (retired, hidden)
    assert {k: v["JobId"] for k, v in got.items()} == {1: 2, 2: 3} and "SourceCommit" not in got[1]
    assert not conn.sql(r"JOIN cz.vApplicationLatest")         # no join: SQL Server parsed every Payload per pair


# --------------------------------------------------------------------------- Build again (no LLM)

def test_build_again_reuses_the_patch_without_the_llm(stateful, tmp_path, builds):
    outcomes, _ = builds
    outcomes[:] = ["build-failed", "build-failed", "build-failed", "ok"]
    first = rf.run_order({**_pl(stateful), "max_repairs": 0}, tmp_path / "w1", ask=Asker(GOOD), name="shop-refactor-50")
    assert first["status"] != "verified" and first["patch"]
    pl = rf.rebuild_payload({**_pl(stateful), "heavy_round": 3, "deadline": "x", "reuse_patch": "P"}, first, 50)
    assert pl["max_calls"] == 0 and pl["rebuild"] and pl["base_job"] == 50 and pl["base_patch"] == first["patch"]
    assert not any(k.startswith("heavy_") for k in pl) and "deadline" not in pl and "reuse_patch" not in pl
    outcomes[:] = ["ok"]                                     # the firewall rule is in now
    ask = Asker(GOOD)
    res = rf.run_order(pl, tmp_path / "w2", ask=ask, name="shop-refactor-51")
    assert ask.asked == {} and res["calls"] == 0
    assert res["status"] == "verified" and res["rating_reached"], res.get("reason")
    outcomes[:] = ["build-failed"]                           # still failing: no repair round, still no LLM
    res = rf.run_order(pl, tmp_path / "w3", ask=ask, name="shop-refactor-52")
    assert ask.asked == {} and res["status"] != "verified" and [x["kind"] for x in res["loop"]] == ["generate"]
    with pytest.raises(rf.RefactorError):
        rf.rebuild_payload({**pl, "goal": "fix"}, first, 50)


def test_build_again_button_queues_an_approved_order(adm):
    from test_refactor import _job, RESULT
    res = {**RESULT, "status": "applies-only", "goal": "rating-a", "rating_before": "B", "rating_after": "A",
           "rating_reached": False, "loop": []}
    job = _job(result=res, Payload=json.dumps({"commit": "a" * 40, "goal": "rating-a", "tasks": [],
                                                                  "components": [{"name": "Web", "project": "Web"}]}))
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [job],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}],
                        r"EXEC cz.QueueLlmJob": [{"JobId": 43}]}
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "action='/admin/refactoring/42/rebuild'" in b and "Build again (no LLM)" in b
    r = _post(adm, op, "/admin/refactoring/42/rebuild")
    assert "/admin/refactoring/43" in _loc(r)
    (sql, params), = adm.conn.sql("EXEC cz.QueueLlmJob")
    pl = json.loads(params[-1])
    assert pl["rebuild"] and pl["max_calls"] == 0 and pl["base_job"] == 42
    assert adm.conn.sql(r"SET Status = N'queued', ApprovedBy")                    # no approval wait: no LLM call


def test_which_components_a_patch_leaves_unchanged():
    """trade-rebates: the patch changed only the portal, so the API and the worker are deployed as they were. A file
    of a shared library, or outside every project, and no component counts as unchanged."""
    from types import SimpleNamespace as NS

    def comp(name, rel, tier="server"):
        return NS(name=name, tier=tier, project=NS(rel=rel))
    a = NS(components=[comp("Api", "src/Api/Api.csproj"), comp("Portal", "src/Portal/Portal.csproj"),
                       comp("Worker", "src/Worker/Worker.csproj"), comp("Data", "src/Data/Data.csproj", "library")])
    patch = ("From 1 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\n---\n"
             "diff --git a/apps/tr/src/Portal/web.config b/apps/tr/src/Portal/web.config\n"
             "--- a/apps/tr/src/Portal/web.config\n+++ b/apps/tr/src/Portal/web.config\n@@ -1 +1 @@\n-a\n+b\n")
    pl = {"source": {"subdir": "apps/tr"}}
    files = variant.changed_files({"patch": patch}, pl)
    assert files == ["src/Portal/web.config"]
    assert variant.unchanged(a, files) == {"Api", "Worker"}
    assert variant.unchanged(a, files + ["src/Data/Repo.cs"]) == set()          # a shared library changed
    assert variant.unchanged(a, files + ["Directory.Build.props"]) == set()     # outside every project
    assert variant.unchanged(a, None) == set()
    assert variant.changed_files({"patch": patch}, {"source": {"subdir": "apps/other"}}) is None
    assert variant.changed_files({}, pl) is None


def test_the_open_link_goes_to_the_ui_not_the_api():
    """trade-rebates: "Open" went to TradeRebates.Api, whose "/" answers 404 (only /ping and /api/v1/...)."""
    from containerizer.sandbox import main_url
    api = {"component": "TradeRebates.Api", "url": "https://api.example/"}
    portal = {"component": "TradeRebates.Portal", "url": "https://portal.example/"}
    worker = {"component": "TradeRebates.StatementWorker"}
    assert main_url([api, portal, worker]) == "https://portal.example/"
    assert main_url([api, worker]) == "https://api.example/"                      # only an API: that one
    assert main_url([{"component": "Shop.WebApi", "url": "u1"}, {"component": "shop-web", "url": "u2"}]) == "u2"
    assert main_url([{"component": "Rapid", "url": "u1"}]) == "u1" and main_url([worker]) is None
