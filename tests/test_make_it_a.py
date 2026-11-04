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


def test_the_variant_is_deployed_beside_the_original_and_removed_again(tmp_path, monkeypatch):
    out, o = _output(tmp_path)
    before = (out / "Contoso/_/shop/containerizer.json").read_text()
    monkeypatch.setattr(variant, "_open", lambda connect, key, payload, work, deploying=True: (TARGET, o))
    monkeypatch.delenv(variant.KUBECONFIG_ENV, raising=False)
    work = tmp_path / "job"
    name = rf.variant_name("shop", 42)
    shutil.copytree(DEMO, work / name)                     # the patched copy, as run_rating_a leaves it
    result = {"status": "verified", "rating_reached": True, "verification": [{"component": "demo-web", "status": "ok"}]}
    progress = []
    now = datetime(2026, 11, 1, 9, 5, tzinfo=timezone.utc)
    sb = variant.deploy(None, None, PAYLOAD, 42, result, work, name, progress.append, now=now)
    assert sb["status"] == "deployed" and "health not checked (no cluster access configured" in sb["reason"]
    assert sb["namespace"] == "shop-refactor-42" and sb["folder"] == "Contoso/_/shop-refactor-42"
    assert sb["of"] == "Contoso/_/shop" and sb["tag"] == "1.20261101.905-refactor.42"
    assert sb["images"] == ["reg.example/sandbox/shop-refactor-42/demo-web:1.20261101.905-refactor.42"]
    assert "expires_at" not in sb and sb["commit"] == PAYLOAD.get("commit") and len(sb["revision"]) == 40
    assert progress and all(p.startswith("deploying:") for p in progress)
    d = out / sb["folder"]
    meta = json.loads((d / "containerizer.json").read_text())
    assert meta["app"] == "shop-refactor-42" and meta["source_key"] == "" and meta["repo"] == "shop-refactor-42"
    assert meta["variant"] == {"of": "Contoso/_/shop", "of_app": "shop", "job": 42, "application_id": 7,
                               "commit": PAYLOAD.get("commit")}
    # its own namespace, image path and GitOps objects; the original is untouched
    assert (out / "Contoso/_/shop/containerizer.json").read_text() == before
    k = yaml.safe_load((d / "kustomization.yaml").read_text())
    assert k["namespace"] == "shop-refactor-42"
    ks = next(x for x in yaml.safe_load_all((d / "gitops/flux/git/sync.yaml").read_text()) if x and x["kind"] == "Kustomization")
    assert ks["metadata"]["name"] == "shop-refactor-42" and ks["spec"]["path"] == "./Contoso/_/shop-refactor-42"
    # write_sandbox picked it up next to the original
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\nshop-refactor-42\n"
    flux = yaml.safe_load((out / "sandbox/flux/apps/kustomization.yaml").read_text())["resources"]
    assert flux == ["../../../Contoso/_/shop/gitops/flux", "../../../Contoso/_/shop-refactor-42/gitops/flux"]
    assert "namespace: shop-refactor-42" in (out / "sandbox/verify-rbac.yaml").read_text()
    log = subprocess.run(["git", "log", "--format=%s"], cwd=out, capture_output=True, text=True).stdout
    assert "sandbox variant Contoso/_/shop-refactor-42 of Contoso/_/shop" in log
    # removal: the folder goes, sandbox/ is regenerated, the original stays
    later = now + timedelta(days=8)
    sb2 = variant.remove(None, None, 42, PAYLOAD, sb, tmp_path / "rm", "outdated", "d" * 40, now=later)
    assert sb2["status"] == "outdated" and sb2["removed_at"] == "2026-11-09T09:05:00" and sb2["removed_by"] is None
    assert sb2["reason"] == f"replaced by newer code: a scan assessed commit {'d' * 12} of the application, and the " \
                            f"patch was made for {'c' * 12}"
    assert not d.exists() and (out / "Contoso/_/shop").is_dir()
    assert (out / "sandbox/namespaces.txt").read_text() == "shop\n"
    assert "sandbox variant Contoso/_/shop-refactor-42 outdated" in subprocess.run(
        ["git", "log", "-1", "--format=%s"], cwd=out, capture_output=True, text=True).stdout
    with pytest.raises(variant.Skip):
        variant.remove(None, None, 42, PAYLOAD, {**sb, "folder": "Contoso/_/shop"}, tmp_path / "rm2")


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
    assert variant.due(rows, {}) == [(rows[2], "removed", "o@example.com")]       # no scan since: nothing goes


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
    # one line per step (sandbox variants, egress), once a minute
    assert r.housekeep() == 0 and r.housekeep() == 0 and len(logs) == 2 and all("db away" in m for m in logs)


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
    assert _loc(r) == "/admin/refactoring?bulk=queued&q=1&w=0&x=0&n=2"
    (sql, params), = adm.conn.sql("EXEC cz.QueueLlmJob")
    assert json.loads(params[-1])["goal"] == "rating-a" and json.loads(params[-1])["application_id"] == 7
    (sql, params), = adm.conn.sql(r"SET Status = N'queued', ApprovedBy")             # approved at once
    assert params == ("a@example.com", 42)
    b = _getq(adm, ad, "/admin/refactoring", "bulk=queued&q=1&w=0&x=0&n=2").body
    assert "queued and approved for 1 application(s)" in b and "2 left out" in b
    assert "evil" not in _getq(adm, ad, "/admin/refactoring", "bulk=queued&q=%3Cevil%3E").body
    # an application with an order in the queue already is shown, not ordered again
    adm.conn.answers[r"FROM cz.LlmJob WHERE Kind = N'refactor'\s+AND Status IN"] = [
        {"ApplicationId": 7, "JobId": 42, "Status": "queued"}]
    b = _get(adm, ad, "/admin/refactoring/make-all-a").body
    assert "href='/admin/refactoring/42'>in the queue</a>" in b and "<b>1 order(s)</b> can be queued" in b
    # one that a verified patch makes A already is shown with it, not queued again from here
    adm.conn.answers[r"FROM cz.LlmJob WHERE Kind = N'refactor'\s+AND Status IN"] = []
    adm.conn.answers[r"FROM cz.vRefactorOrder\s+WHERE Goal = N'rating-a' AND Status = N'verified'"] = [
        {"ApplicationId": 7, "JobId": 77, "SandboxStatus": "skipped", "SandboxUrl": None, "FinishedAt": None}]
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
    assert [r["JobId"] for r, why in variant.due(rows)] == [jid] and rows[0]["RemoveRequestedBy"] == "o@example.com"
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
    assert html.index(">Running in the sandbox<") < html.index("Expired in the sandbox")    # running ones first
    assert "href='https://billing-refactor-9.sb.example.com/' target='_blank'" in html
    assert "href='/app/1#refactoring'" in html and "/admin/refactoring/9" not in html  # the patch link: staff only
    assert html.count("class='a-patch here'") == 1 and html.count("class='a-patch'") == 1
    assert "/admin/refactoring/9" in webui.render_overview({"apps": apps, "unmapped": {}}, nav="<nav></nav>")
    assert "Made A by a patch" not in webui.render_overview({"apps": [apps[2]], "unmapped": {}})
    conn = FakeConn({r"FROM cz.vRefactorOrder": [
        {"ApplicationId": 1, "JobId": 3, "SandboxStatus": "failing", "SandboxUrl": None, "FinishedAt": None},
        {"ApplicationId": 1, "JobId": 2, "SandboxStatus": "running", "SandboxUrl": None, "FinishedAt": None},
        {"ApplicationId": 1, "JobId": 4, "SandboxStatus": "removed", "SandboxUrl": None, "FinishedAt": None}]})
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
