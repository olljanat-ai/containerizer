"""Refactoring patches (refactor.py, admin_refactor.py, docs/refactoring.md): which findings an order sends to
the LLM, the prompt and its size cap, applying the LLM's structured edits (exact, ambiguous and missing
matches, the retry with the errors), the patch from `git format-patch` that `git am` applies to a clean
copy, the verification status, the queue handler, the admin pages (roles, CSRF, the download, escaping in
the diff), the results page's Refactoring box, the command line, and the schema (CONTAINERIZER_TEST_SQL)."""
import json
import shutil
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

import pytest

from containerizer import admin_refactor, ai, llmqueue as lq, refactor as rf
from test_llm_queue import FakeConn

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />
  </ItemGroup>
</Project>
"""
BANK = """using System.Security.Cryptography.X509Certificates;

namespace Shop.Api;

public static class Bank
{
    public static X509Certificate2 Load(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];
    }
}
"""
SEARCH = "        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);\n        store.Open(OpenFlags.ReadOnly);\n" \
         "        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];"
REPLACE = ('        var path = Environment.GetEnvironmentVariable("BANK_CERT_PATH") ?? "/certs/bank.pfx";\n'
           '        return X509CertificateLoader.LoadPkcs12FromFile(path, null);')


def _git(cwd, *args):
    return rf.git(list(args), cwd=Path(cwd)).stdout.decode()


@pytest.fixture
def shop(tmp_path):
    """A one-component B-rated app in a git repository (the LocalMachine certificate store)."""
    root = tmp_path / "shop"
    (root / "src/Shop.Api").mkdir(parents=True)
    (root / "src/Shop.Api/Shop.Api.csproj").write_text(CSPROJ)
    (root / "src/Shop.Api/Program.cs").write_text('var app = WebApplication.CreateBuilder(args).Build();\n'
                                                  'app.MapGet("/", () => "ok");\napp.Run();\n')
    (root / "src/Shop.Api/Bank.cs").write_text(BANK)
    (root / "src/Shop.Api/appsettings.json").write_text('{\n  "Bank": {\n    "Thumbprint": "AB12"\n  }\n}\n')
    _git(root, "init", "--quiet")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "initial")
    return root


def _doc(root):
    from containerizer.assess import assess
    return assess(root).to_dict()


def _payload(root, **kw):
    commit = _git(root, "rev-parse", "HEAD").strip()
    return rf.build_payload(_doc(root), {"type": "local", "path": str(root), "subdir": ".", "git": True}, commit,
                            source_key="shop", **kw)


def good_answer(prompt=None, schema=None):
    return {"edits": [{"file": "src/Shop.Api/Bank.cs", "search": SEARCH, "replace": REPLACE}], "new_files": [],
            "package_changes": [], "fixed": ["cert-store-localmachine-code", "cert-store"], "not_fixed": [],
            "notes": "Mount the certificate from a Secret at /certs/bank.pfx."}


# --------------------------------------------------------------------------- what is sent

def comp(name, findings, verdict="refactor", project=None):
    return {"name": name, "project": project or f"src/{name}/{name}.csproj", "role": "web", "verdict": verdict,
            "tfm": ["net8.0"], "findings": findings}


def finding(rid, sev, evidence, fix="Change the code.", **kw):
    return {"id": rid, "severity": sev, "title": rid, "why": "because", "fix": fix, "evidence": evidence,
            "dormant": False, **kw}


def test_only_refactor_and_config_findings_are_sent():
    c = comp("Api", [
        finding("cert-code", "refactor", ["src/Api/Bank.cs:9: new X509Store(StoreName.My, StoreLocation.LocalMachine)"] * 2),
        finding("cert-store", "config", ["src/Api/Bank.cs:9: new X509Store(...)"]),
        finding("drive-path", "config", ["src/Api/Options.cs:3: = @\"D:\\Out\""]),
        finding("com-interop", "blocker", ["src/Api/Com.cs:1: [ComImport]"]),
        finding("webforms", "rewrite", ["src/Api/Default.aspx"]),
        finding("tz", "info", ["src/Api/Clock.cs:2: DateTime.Now"]),
        finding("lib-thing", "refactor", ["src/Lib/X.cs:1: x"], dormant=True),
        finding("vendor-sdk", "refactor", ["src/Api/Vendor.cs:4: Sdk.Open()"], fix="Keep this component on Windows."),
        finding("opc", "refactor", ["src/Api/Opc.cs:4: Opc.Connect()"],
                fix="Use OPC UA through a gateway, or keep the collector on Windows."),
        finding("no-file", "refactor", []),
    ])
    tasks, skipped = rf.plan_tasks([c])
    assert [(t["file"], [f["rule"] for f in t["findings"]]) for t in tasks] == [
        ("src/Api/Bank.cs", ["cert-code", "cert-store"]), ("src/Api/Opc.cs", ["opc"])]
    assert len(tasks[0]["findings"][0]["evidence"]) == 1                  # the same evidence line once
    assert tasks[0]["findings"][0]["evidence"][0] == {"file": "src/Api/Bank.cs", "line": 9,
                                                      "text": "new X509Store(StoreName.My, StoreLocation.LocalMachine)"}
    why = {s["rule"]: s["reason"] for s in skipped}
    assert "blocker" in why["com-interop"] and "rewrite" in why["webforms"] and "tz" not in why
    assert "Windows" in why["vendor-sdk"] and "no file" in why["no-file"] and "dormant" in why["lib-thing"]
    assert "configuration finding" in why["drive-path"]
    # with configuration findings: the drive path too (its own file)
    tasks, _ = rf.plan_tasks([c], include_config=True)
    assert [t["file"] for t in tasks] == ["src/Api/Bank.cs", "src/Api/Opc.cs", "src/Api/Options.cs"]


def test_payload_from_an_assessment(shop):
    pl = _payload(shop)
    assert pl["app"] == "shop" and pl["rating"] == "B" and len(pl["commit"]) == 40
    assert [c["name"] for c in pl["components"]] == ["Shop.Api"]
    assert pl["components"][0]["language"] == "C#" and pl["components"][0]["tfm"] == ["net8.0"]
    assert [(t["file"], [f["rule"] for f in t["findings"]]) for t in pl["tasks"]] == [
        ("src/Shop.Api/Bank.cs", ["cert-store-localmachine-code", "cert-store"])]
    f = pl["tasks"][0]["findings"][0]
    assert f["fix"].startswith("Load the certificate from a file") and f["evidence"][0]["line"] == 9
    assert pl["source"]["type"] == "local" and pl["verify"] is True
    assert rf.dedupe_key(pl) == rf.dedupe_key(json.loads(json.dumps(pl))) and len(rf.dedupe_key(pl)) == 64
    with pytest.raises(rf.RefactorError, match="no component"):
        _payload(shop, component="Nope")
    job = rf.queue_job(pl, rf.estimate_chars(pl, shop))
    assert job["Kind"] == "refactor" and job["Priority"] == rf.PRIORITY and job["Component"] is None
    assert job["InputChars"] > len(BANK) and job["DedupeKey"] == rf.dedupe_key(pl)
    # without the source (the web UI at order time): from the findings and a typical file size
    assert rf.estimate_chars(pl) > rf.DEFAULT_FILE_CHARS
    one = _payload(shop, component="Shop.Api")
    assert rf.queue_job(one, 1)["ProjectPath"] == "src/Shop.Api/Shop.Api.csproj"


def test_prompt_shows_the_file_its_settings_and_the_fix(shop):
    pl = _payload(shop)
    prompt, shown = rf.task_prompt(pl, pl["tasks"][0], shop)
    assert shown == ["src/Shop.Api/Bank.cs", "src/Shop.Api/appsettings.json"]
    assert "Serilog.AspNetCore 8.0.0" in prompt and "target framework net8.0" in prompt
    assert "Evidence: line 9: using var store" in prompt and "(complete)" in prompt and BANK.strip() in prompt
    assert '"Thumbprint": "AB12"' in prompt and "copied EXACTLY" in prompt


def test_prompt_size_is_capped_with_a_window_around_the_evidence(shop):
    big = "\n".join(f"    // line {i} " + "x" * 120 for i in range(3000))
    text = BANK.replace("namespace Shop.Api;", "namespace Shop.Api;\n" + big)
    (shop / "src/Shop.Api/Bank.cs").write_text(text)
    pl = _payload(shop)
    line = pl["tasks"][0]["findings"][0]["evidence"][0]["line"]
    assert line > 3000
    prompt, _ = rf.task_prompt(pl, pl["tasks"][0], shop)
    assert len(prompt) <= rf.MAX_PROMPT_CHARS + 500
    assert "using var store = new X509Store" in prompt and f"of {text.count(chr(10)) + 1}" in prompt
    assert "only this part is shown" in prompt and "// line 0 " not in prompt
    # the whole job stays under ~12K tokens a call with the system prompt and the schema
    assert len(prompt) + len(rf.SYSTEM) + len(json.dumps(rf.EDIT_SCHEMA)) < 12000 * 3.5
    text_, lo, hi = rf.window("a\nb\nc\nd\ne", [3], 3)
    assert (lo, hi) != (1, 5) and "c" in text_


# --------------------------------------------------------------------------- applying the edits

def test_edits_need_exactly_one_match(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "A.cs").write_bytes(b"\xef\xbb\xbfint a = 1;\r\nint b = 1;\r\nint b = 1;\r\n")
    shown = ["A.cs"]
    ch, err = rf.apply_answer(root, {"edits": [{"file": "A.cs", "search": "int a = 1;", "replace": "int a = 2;"}]}, shown, None)
    assert err == [] and ch == [{"file": "A.cs", "kind": "edit"}]
    assert (root / "A.cs").read_bytes() == b"\xef\xbb\xbfint a = 2;\r\nint b = 1;\r\nint b = 1;\r\n"   # BOM and CRLF kept
    before = (root / "A.cs").read_bytes()
    ch, err = rf.apply_answer(root, {"edits": [{"file": "A.cs", "search": "int a = 2;", "replace": "int a = 3;"},
                                               {"file": "A.cs", "search": "int b = 1;", "replace": "int b = 2;"}]}, shown, None)
    assert ch == [] and len(err) == 1 and "occurs 2 times" in err[0]
    assert (root / "A.cs").read_bytes() == before                     # all or nothing
    ch, err = rf.apply_answer(root, {"edits": [{"file": "A.cs", "search": "int c = 1;", "replace": "int c = 2;"}]}, shown, None)
    assert "was not found" in err[0] and "'int c = 1;'" in err[0]
    for bad in ("../x.cs", "/etc/passwd", ".git/config", "C:\\x.cs"):
        _, err = rf.apply_answer(root, {"edits": [{"file": bad, "search": "a", "replace": "b"}]}, shown, None)
        assert "not a path inside" in err[0], bad
    (root / "B.cs").write_text("int x;\n")
    _, err = rf.apply_answer(root, {"edits": [{"file": "B.cs", "search": "int x;", "replace": "int y;"}]}, shown, None)
    assert "may not be edited" in err[0]
    os.symlink("/etc/hostname", root / "L.cs")
    _, err = rf.apply_answer(root, {"edits": [{"file": "L.cs", "search": "a", "replace": "b"}]}, ["L.cs"], None)
    assert "not a file of the application" in err[0]
    _, err = rf.apply_answer(root, {"edits": [{"file": "A.cs", "search": "int a = 2;", "replace": "int a = 2;"}]}, shown, None)
    assert "the same" in err[0]
    ch, err = rf.apply_answer(root, {"new_files": [{"file": "Certs/Loader.cs", "content": "class Loader {}\n"}]}, shown, None)
    assert err == [] and (root / "Certs/Loader.cs").read_text() == "class Loader {}\n"
    _, err = rf.apply_answer(root, {"new_files": [{"file": "A.cs", "content": "x"}]}, shown, None)
    assert "already exists" in err[0]


def test_json_escaped_backslashes_and_the_retry_hint(tmp_path):
    """Seen with qwen3-coder on a CPU: C# `"LocalMachine\\\\My"` came back as `LocalMachine\\My` in the search
    text. The same text with every backslash run scaled the same way still applies; anything else is an error
    that points at the line that differs."""
    root = tmp_path / "app"
    root.mkdir()
    (root / "A.cs").write_text('throw new X($"not found in LocalMachine\\\\My.");\nvar p = "C:\\\\x";\n')
    ch, err = rf.apply_answer(root, {"edits": [{"file": "A.cs", "search": 'throw new X($"not found in LocalMachine\\My.");',
                                               "replace": 'throw new X($"not found in {path}\\n");'}]}, ["A.cs"], None)
    assert err == [] and ch[0]["detail"] == "backslashes as in the file"
    assert (root / "A.cs").read_text().startswith('throw new X($"not found in {path}\\\\n");')
    _, err = rf.apply_answer(root, {"edits": [{"file": "A.cs", "search": 'var p = "D:\\\\x";', "replace": "y"}]}, ["A.cs"], None)
    assert "line 1 of the search text is not in the file" in err[0] and "the file has 'var p = \"C:\\\\\\\\x\";'" in err[0]
    assert rf._names("os-drive-path-default", 1, ["config-os-drive-path-default"])
    assert rf._names("cert-store", 2, ["2"]) and not rf._names("cert-store", 1, ["cert-store-localmachine-code"])


def test_package_changes_go_into_the_project_file(tmp_path):
    root = tmp_path / "app"
    (root / "Api").mkdir(parents=True)
    (root / "Api/Api.csproj").write_text(CSPROJ)
    ch, err = rf.apply_answer(root, {"package_changes": [{"action": "add", "package": "Polly", "version": "8.4.0"},
                                                         {"action": "remove", "package": "Serilog.AspNetCore", "version": ""}]},
                              [], "Api/Api.csproj")
    assert err == [] and [c["detail"] for c in ch] == ["add Polly 8.4.0", "remove Serilog.AspNetCore"]
    text = (root / "Api/Api.csproj").read_text()
    assert '    <PackageReference Include="Polly" Version="8.4.0" />' in text and "Serilog" not in text
    _, err = rf.apply_answer(root, {"package_changes": [{"action": "add", "package": "Bad Name\"/>", "version": "1"}]},
                             [], "Api/Api.csproj")
    assert "not a package name" in err[0]
    # not a project file it can change: left to the person, with a note
    ch, err = rf.apply_answer(root, {"package_changes": [{"action": "add", "package": "x", "version": "1"}]}, [], "package.json")
    assert err == [] and ch[0]["kind"] == "package-manual"


# --------------------------------------------------------------------------- the whole run

def test_patch_applies_with_git_am_to_a_clean_copy(shop, tmp_path):
    pl = _payload(shop, verify=False)
    asked = []
    res = rf.run_order(pl, tmp_path / "work", ask=lambda p, s: asked.append(p) or good_answer())
    assert res["status"] == "applies-only" and "verification was off" in res["reason"]
    assert len(asked) == 1 and res["calls"] == 1
    assert [(f["rule"], f["status"], f["rules_after"]) for f in res["findings"]] == [
        ("cert-store-localmachine-code", "fixed", "resolved"), ("cert-store", "fixed", "resolved")]
    patch = res["patch"]
    assert patch.startswith("From ") and "From: Containerizer <containerizer@localhost>" in patch
    assert "Subject: [PATCH] Containerizer: shop: cert-store, cert-store-localmachine-code" in patch
    assert "+        return X509CertificateLoader.LoadPkcs12FromFile(path, null);" in patch
    assert res["files"] == [{"file": "src/Shop.Api/Bank.cs", "status": "modified", "added": 2, "removed": 3, "binary": False}]
    assert res["filename"] == "shop-all-containerizer.patch" and "Mount the certificate" in res["notes"][0]
    # the source was not touched, and `git am` applies the patch to a clean clone as a commit
    assert (shop / "src/Shop.Api/Bank.cs").read_text() == BANK and _git(shop, "status", "--porcelain") == ""
    clean = tmp_path / "clean"
    _git(tmp_path, "clone", "--quiet", str(shop), str(clean))
    (tmp_path / "x.patch").write_text(patch)
    _git(clean, "am", "--keep-cr", str(tmp_path / "x.patch"))
    assert "LoadPkcs12FromFile" in (clean / "src/Shop.Api/Bank.cs").read_text()
    assert _git(clean, "log", "-1", "--format=%an %s").startswith("Containerizer Containerizer: shop:")


def test_an_answer_that_does_not_apply_is_asked_again_with_the_errors(shop, tmp_path):
    pl = _payload(shop, verify=False)
    asked = []

    def ask(prompt, schema):
        asked.append(prompt)
        if len(asked) == 1:
            return {**good_answer(), "edits": [{"file": "src/Shop.Api/Bank.cs", "search": "store.Open(OpenFlags.ReadWrite);",
                                                "replace": "x"}]}
        return good_answer()
    res = rf.run_order(pl, tmp_path / "w", ask=ask)
    assert len(asked) == 2 and res["status"] == "applies-only"
    assert "could not be applied" in asked[1] and "was not found" in asked[1] and asked[1].startswith(asked[0])
    # twice wrong: nothing changes, and no patch is offered (a fresh store: the answer above would be reused)
    import shutil as _sh
    _sh.rmtree(rf.shared_dir(), ignore_errors=True)
    res = rf.run_order(pl, tmp_path / "w2", ask=lambda p, s: {**good_answer(), "edits": [
        {"file": "src/Shop.Api/Bank.cs", "search": "nope", "replace": "x"}]})
    assert res["status"] == "failed" and res["patch"] is None and "no usable edits" in res["reason"]
    assert res["findings"][0]["status"] == "not-fixed" and "did not apply" in res["findings"][0]["reason"]
    # the LLM fails: an LLM error for the finding, no patch
    res = rf.run_order(pl, tmp_path / "w3", ask=lambda p, s: (_ for _ in ()).throw(RuntimeError("timed out")))
    assert res["status"] == "failed" and res["findings"][0]["status"] == "llm-error" and "timed out" in res["findings"][0]["reason"]


def test_rules_after_are_per_file(shop, tmp_path):
    """The same rule in two files: fixing one shows as gone from that file, still found in the other."""
    for name in ("Options", "Other"):
        (shop / f"src/Shop.Api/{name}.cs").write_text(
            f'public class {name}\n{{\n    public string Folder {{ get; set; }} = @"D:\\Shop\\{name}";\n}}\n')
    _git(shop, "add", "-A")
    _git(shop, "commit", "--quiet", "-m", "paths")
    pl = _payload(shop, verify=False, include_config=True)

    def ask(prompt, schema):
        if "File src/Shop.Api/Options.cs" in prompt:
            return {"edits": [{"file": "src/Shop.Api/Options.cs", "search": '@"D:\\Shop\\Options"',
                               "replace": '"/data/options"'}], "new_files": [], "package_changes": [],
                    "fixed": ["os-drive-path-default"], "not_fixed": [], "notes": ""}
        if "File src/Shop.Api/Other.cs" in prompt:
            return {"edits": [], "new_files": [], "package_changes": [], "fixed": [],
                    "not_fixed": [{"rule": "os-drive-path-default", "reason": "a deployment setting"}], "notes": ""}
        return good_answer()
    res = rf.run_order(pl, tmp_path / "w", ask=ask)
    got = {(f["file"].split("/")[-1], f["rule"]): (f["status"], f["rules_after"], f["reason"]) for f in res["findings"]}
    assert got[("Options.cs", "os-drive-path-default")] == ("fixed", "resolved", "")
    assert got[("Other.cs", "os-drive-path-default")] == ("not-fixed", "still found", "a deployment setting")


def test_the_call_limit(shop, tmp_path):
    pl = _payload(shop, verify=False, include_config=True, max_calls=0)
    res = rf.run_order(pl, tmp_path / "w", ask=lambda p, s: good_answer())
    assert res["status"] == "failed" and {f["status"] for f in res["findings"]} == {"skipped"}


def test_a_commit_that_is_gone_fails_clearly(shop, tmp_path):
    pl = _payload(shop, verify=False)
    pl["commit"] = "0" * 40
    with pytest.raises(rf.RefactorError, match="no longer in the clone.*Scan it again"):
        rf.run_order(pl, tmp_path / "w", ask=lambda p, s: good_answer())


def test_org_clone_source_must_stay_in_the_worker_folder(tmp_path, monkeypatch, shop):
    monkeypatch.setenv(rf.SOURCES_ENV, str(tmp_path))
    for bad in ("../etc", "scan-1/repos/../../x", "/abs", "scan-x/repos/a"):
        with pytest.raises(rf.RefactorError, match="bad clone folder"):
            rf.resolve_source({"type": "org-clone", "dir": bad})
    with pytest.raises(rf.RefactorError, match="is not at"):
        rf.resolve_source({"type": "org-clone", "dir": "scan-1/repos/shop"})
    (tmp_path / "scan-1/repos").mkdir(parents=True)
    os.rename(shop, tmp_path / "scan-1/repos/shop")
    top, sub, is_git = rf.resolve_source({"type": "org-clone", "dir": "scan-1/repos/shop", "subdir": "."})
    assert top == (tmp_path / "scan-1/repos/shop").resolve() and is_git
    with pytest.raises(rf.RefactorError, match="no source"):
        rf.resolve_source({"type": "none"})
    # a runner serving the worker's clones reads no other folder (a job in the database names the path)
    with pytest.raises(rf.RefactorError, match="only reads the scan worker's clones"):
        rf.resolve_source({"type": "local", "path": "/etc"})
    assert rf.resolve_source({"type": "local", "path": str(tmp_path / "scan-1/repos/shop")})[2]
    monkeypatch.delenv(rf.SOURCES_ENV)
    assert rf.resolve_source({"type": "local", "path": "/etc", "git": False})[0] == Path("/etc")


def test_verification_status():
    assert rf.verification_status(False, 3, [{"status": "ok"}]) == "failed"
    assert rf.verification_status(True, 0, [{"status": "ok"}]) == "failed"
    assert rf.verification_status(True, 1, [{"status": "ok"}, {"status": "ok-external"}]) == "verified"
    assert rf.verification_status(True, 1, [{"status": "ok"}, {"status": "build-failed"}]) == "applies-only"
    assert rf.verification_status(True, 1, []) == "applies-only"
    assert rf.verification_status(True, 1, None) == "applies-only"
    assert rf.order_status("queued") == "queued"
    assert rf.order_status("running", "generating: file 1 of 2") == "generating"
    assert rf.order_status("running", "verifying: building") == "verifying"
    assert rf.order_status("answered", "x", "verified") == "verified"
    assert rf.order_status("answered", "x", None) == "failed"
    assert rf.order_status("failed") == "failed" and rf.order_status("skipped") == "cancelled"


def test_verified_and_applies_only_with_the_build(shop, tmp_path, monkeypatch):
    """The changed components are built and run on the patched copy (verify.verify_component, mocked)."""
    from containerizer import verify as vf
    seen = []
    monkeypatch.setattr(vf, "_run", lambda cmd, timeout, cwd=None: (0, ""))

    def fake_verify(a, c, rules, timeout=900, work=None, **kw):
        seen.append((c.name, Path(a.repo.root), work))
        assert "LoadPkcs12FromFile" in (Path(a.repo.root) / "src/Shop.Api/Bank.cs").read_text()   # the patched copy
        return {"status": outcome, "attempts": [{"stage": "build", "status": "unexplained",
                                                 "log_tail": "error CS0103: X509CertificateLoader"}], "seconds": 40}
    monkeypatch.setattr(vf, "verify_component", fake_verify)
    pl = _payload(shop)
    outcome = "ok"
    res = rf.run_order(pl, tmp_path / "w", ask=lambda p, s: good_answer())
    assert res["status"] == "verified" and res["verification"][0]["status"] == "ok"
    assert res["verification"][0]["log_tail"] == "" and seen[0][0] == "Shop.Api"
    assert seen[0][2] == tmp_path / "w" / "verify-work"
    outcome = "build-failed"
    res = rf.run_order(pl, tmp_path / "w2", ask=lambda p, s: good_answer())
    assert res["status"] == "applies-only" and "Shop.Api: build-failed" in res["reason"]
    assert "CS0103" in res["verification"][0]["log_tail"] and res["patch"]
    # no Docker: applies only, and why
    monkeypatch.setattr(vf, "_run", lambda cmd, timeout, cwd=None: (_ for _ in ()).throw(vf.DockerUnavailable("no docker")))
    res = rf.run_order(pl, tmp_path / "w3", ask=lambda p, s: good_answer())
    assert res["status"] == "applies-only" and "Docker is not available" in res["verification"][0]["detail"]


def test_queue_handler_result_shape(shop, tmp_path, monkeypatch):
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "api")
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    calls = []
    monkeypatch.setattr(ai, "_ask_api", lambda prompt, schema, model, effort, system:
                        calls.append(system) or (good_answer(), {"input_tokens": 3000, "output_tokens": 400}))
    progress = []
    pl = _payload(shop, verify=False)
    out = lq.JOB_KINDS["refactor"].handler({"JobId": 5, "Payload": pl, "_progress": progress.append})
    assert set(out) == {"result", "summary", "note"} and calls == [rf.SYSTEM]
    assert out["summary"] == "not built: 2 of 2 findings fixed, 1 file changed"     # applies; Docker was not there
    assert out["note"].startswith("the patch applies; verification was off")
    assert out["result"]["status"] == "applies-only" and out["result"]["patch"].startswith("From ")
    json.dumps(out["result"])                                                          # stored as JSON
    assert progress[0].startswith("generating") and any(p.startswith("verifying") for p in progress)
    assert list((tmp_path / "scratch").iterdir()) == []                               # scratch copies removed
    assert lq.kind_title("refactor") == "Refactoring" and lq.JOB_KINDS["refactor"].feature == "refactor-queued"


def test_edit_answers_are_capped(shop, tmp_path, monkeypatch):
    """A runaway answer of a self-hosted model must not hold a CPU slot for an hour: each edit request asks for
    at most 4096 tokens plus half the prompt's, never more than 8192."""
    assert rf.answer_tokens("") == 4096
    assert rf.answer_tokens("x" * 14000) == 4096 + 2000
    assert rf.answer_tokens("x" * 200000) == 8192
    caps = []
    monkeypatch.setattr(ai, "ask_json", lambda prompt, schema, **kw: caps.append(kw["max_tokens"]) or good_answer())
    rf.run_order(_payload(shop, verify=False), tmp_path / "w")
    assert len(caps) == 1 and rf.ANSWER_TOKENS_MIN <= caps[0] <= rf.ANSWER_TOKENS_MAX


def test_runner_records_progress(monkeypatch):
    conn = FakeConn()
    r = lq.Runner(lambda: conn, name="r1", metrics=object.__new__(lq.QueueMetrics), log=lambda m: None)
    r.progress({"JobId": 4}, "verifying: building")
    (sql, params), = conn.sql(r"UPDATE cz.LlmJob SET Summary")
    assert params == ("verifying: building", 4, "r1") and "Status = N'running'" in sql


# --------------------------------------------------------------------------- the diff

PATCH = """From 1111111111111111111111111111111111111111 Mon Sep 17 00:00:00 2001
From: Containerizer <containerizer@localhost>
Subject: [PATCH] Containerizer: shop: cert-store

---
 src/A.cs | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/src/A.cs b/src/A.cs
index 1..2 100644
--- a/src/A.cs
+++ b/src/A.cs
@@ -8,3 +8,4 @@ class A
     {
-        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
+        // <script>alert("x")</script> & co
+        var c = Load();
     }
diff --git a/src/New.cs b/src/New.cs
new file mode 100644
index 0000000..3
--- /dev/null
+++ b/src/New.cs
@@ -0,0 +1 @@
+class New {}
\\ No newline at end of file
--
2.47.0

"""


def test_diff_rendering_escapes_and_numbers_lines():
    p = rf.parse_patch(PATCH)
    assert [(f["new"], f["status"], f["added"], f["removed"]) for f in p["files"]] == [
        ("src/A.cs", "modified", 2, 1), ("src/New.cs", "added", 1, 0)]
    html = admin_refactor.render_diff(PATCH)
    assert "<script>" not in html and "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; co" in html
    assert "<tr class='del'><td class='ln'>9</td><td class='ln'></td>" in html
    assert "<tr class='add'><td class='ln'></td><td class='ln'>9</td>" in html
    assert "<tr class='ctx'><td class='ln'>8</td><td class='ln'>8</td>" in html
    assert "<tr class='hunk'>" in html and "new file" in html and "+2</span>" in html
    assert "2.47.0" not in html                                   # the signature is not a removed line
    assert rf.diffstat(PATCH)[1] == {"file": "src/New.cs", "status": "added", "added": 1, "removed": 0, "binary": False}


# --------------------------------------------------------------------------- the admin pages

@pytest.fixture
def adm():
    pytest.importorskip("jwt")
    from containerizer import admin as adminmod
    from containerizer.oidc import OidcConfig
    c = OidcConfig(issuer="https://idp.example.com", client_id="cz", client_secret="s", public_url="https://cz.example.com",
                   admins=["group:a"])
    conn = FakeConn()
    a = adminmod.Admin(c, lambda: conn, provider=object())
    a.conn = conn
    return a


def _get(adm, sid, path):
    return adm.handle("GET", path, "", {"Cookie": f"{adm.cookie}={sid}"}, b"")


def _post(adm, sid, path, csrf=None, **form):
    s = adm.sessions.get(sid)
    return adm.handle("POST", path, "", {"Cookie": f"{adm.cookie}={sid}"},
                      urlencode({"csrf": csrf if csrf is not None else s.csrf, **form}, doseq=True).encode())


def _loc(r):
    return dict(r.headers)["Location"]


APP = {"ApplicationId": 7, "ApplicationName": "Shop", "ScanName": "shop", "AssessmentId": 70, "Rating": "B",
       "SourceCommit": "a" * 40, "RepositoryUrl": "https://github.com/acme/shop", "SourcePath": "."}


def test_ordering_needs_an_operator_or_admin_and_the_csrf_token(adm, shop):
    doc = _doc(shop)
    adm.conn.answers = {r"FROM cz.vApplicationLatest WHERE ApplicationId": [APP],
                        r"SELECT ReportJson FROM cz.ApplicationAssessment": [{"ReportJson": json.dumps(doc)}],
                        r"SELECT SourceKey FROM cz.Application": [{"SourceKey": "https://github.com/acme/shop#"}],
                        r"FROM cz.OrgRepository WHERE RepositoryUrl": [{"ScanId": 3, "AppName": "shop"}],
                        r"EXEC cz.QueueLlmJob": [{"JobId": 42}]}
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    owner = adm.sessions.create("p@example.com", "P", False, True, False, ["bu:Finance"])
    for sid in (viewer, owner):
        assert _post(adm, sid, "/admin/refactoring/new", ApplicationId="7").status == 403
        assert _get(adm, sid, "/admin/refactoring").status == 403
    assert not adm.conn.sql("EXEC cz.QueueLlmJob")
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _post(adm, op, "/admin/refactoring/new", csrf="wrong", ApplicationId="7").status == 403
    r = _post(adm, op, "/admin/refactoring/new", ApplicationId="7", Component="", IncludeConfig="1")
    assert r.status == 303 and _loc(r) == "/app/7?refactor=ordered&job=42&files=1#refactoring"   # back where it was ordered
    (sql, params), = adm.conn.sql("EXEC cz.QueueLlmJob")
    assert params[0] == "refactor" and params[6] == "shop" and params[17] is None      # RequestedBy: the session's
    pl = json.loads(params[-1])
    assert pl["source"] == {"type": "org-clone", "scan_id": 3, "dir": "scan-3/repos/shop", "subdir": "."}
    assert pl["commit"] == "a" * 40 and pl["include_config"] is True and pl["application_id"] == 7
    assert [t["file"] for t in pl["tasks"]][0] == "src/Shop.Api/Bank.cs" and params[19] > 0   # estimated tokens
    # one component, by its id
    adm.conn.answers[r"SELECT ProjectPath FROM cz.vComponentLatest"] = [{"ProjectPath": "src/Shop.Api/Shop.Api.csproj"}]
    _post(adm, op, "/admin/refactoring/new", ApplicationId="7", Component="11")
    params = adm.conn.sql("EXEC cz.QueueLlmJob")[-1][1]
    assert params[10] == "Shop.Api" and params[11] == "src/Shop.Api/Shop.Api.csproj"
    assert "Shop.Api" in json.loads(params[-1])["component"]
    # already waiting: to the order that waits
    adm.conn.answers[r"EXEC cz.QueueLlmJob"] = [{"JobId": 0}]
    adm.conn.answers[r"SELECT TOP \(1\) JobId FROM cz.LlmJob"] = [{"JobId": 41}]
    r = _post(adm, op, "/admin/refactoring/new", ApplicationId="7")
    assert _loc(r) == "/app/7?refactor=exists&job=41#refactoring"


def test_ordering_is_refused_when_it_cannot_work(adm, shop):
    a = adm.sessions.create("a@example.com", "A", True)
    adm.conn.answers = {r"FROM cz.vApplicationLatest WHERE ApplicationId": [{**APP, "Rating": "C"}]}
    assert "refactor=not-b" in _loc(_post(adm, a, "/admin/refactoring/new", ApplicationId="7"))
    adm.conn.answers = {r"FROM cz.vApplicationLatest WHERE ApplicationId": [APP]}
    assert "refactor=no-source" in _loc(_post(adm, a, "/admin/refactoring/new", ApplicationId="7"))
    adm.conn.answers = {r"FROM cz.vApplicationLatest WHERE ApplicationId": [{**APP, "SourceCommit": None}]}
    assert "refactor=no-commit" in _loc(_post(adm, a, "/admin/refactoring/new", ApplicationId="7"))
    adm.conn.answers = {r"FROM cz.vApplicationLatest WHERE ApplicationId": [APP],
                        r"FROM cz.OrgRepository WHERE RepositoryUrl": [{"ScanId": 3, "AppName": "../../etc"}]}
    assert "refactor=no-source" in _loc(_post(adm, a, "/admin/refactoring/new", ApplicationId="7"))
    assert "refactor=no-component" in _loc(_post(adm, a, "/admin/refactoring/new", ApplicationId="7", Component="x"))
    assert not adm.conn.sql("EXEC cz.QueueLlmJob")


def _job(status="answered", result=None, **kw):
    return {"JobId": 42, "Status": status, "Summary": "verified: 2 of 2 findings fixed, 1 file changed", "Error": None,
            "Note": None, "App": "shop", "Repository": "Shop", "Component": None, "ProjectPath": None, "ApplicationId": 7,
            "AssessmentId": 70, "SourceKey": "k", "RequestedBy": "o@example.com", "Model": None, "Endpoint": "openai x qwen",
            "InputTokens": 3000, "OutputTokens": 400, "EstInputTokens": 2800, "Seconds": 600, "Attempts": 1,
            "QueuedAt": datetime(2026, 11, 1, 2, 0), "StartedAt": None, "FinishedAt": datetime(2026, 11, 1, 2, 10),
            "Payload": json.dumps({"commit": "a" * 40, "tasks": [], "skipped": [{"rule": "core-eol", "component": "Api",
                                                                               "reason": "configuration finding"}]}),
            "Result": json.dumps(result) if result is not None else None, **kw}


RESULT = {"status": "verified", "app": "shop", "component": None, "commit": "a" * 40, "model": "qwen3-coder", "calls": 1,
          "findings": [{"rule": "cert-store", "title": "<b>store</b>", "severity": "config", "component": "Api",
                        "file": "src/A.cs", "status": "fixed", "reason": "", "rules_after": "resolved"}],
          "notes": ["mount <the> certificate"], "filename": "shop-all-containerizer.patch", "patch": PATCH,
          "files": rf.diffstat(PATCH), "apply_log": "", "verify": True, "new_findings": [{"component": "Api", "rule": "x"}],
          "verification": [{"component": "Api", "status": "ok", "detail": "", "log_tail": ""}]}


def test_patch_page_download_and_list(adm):
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [_job(result=RESULT)],
                        r"WHERE Kind = N'refactor' ORDER BY JobId DESC": [{**_job(), "PatchStatus": "verified"},
                                                                         {**_job(status="running"), "JobId": 43,
                                                                          "Summary": "verifying: building", "PatchStatus": None}]}
    r = _get(adm, op, "/admin/refactoring/42")
    assert r.status == 200, r.body
    b = r.body
    assert "<script>" not in b and "&lt;script&gt;" in b and "&lt;b&gt;store&lt;/b&gt;" in b and "mount &lt;the&gt;" in b
    assert "Download .patch" in b and "/admin/refactoring/42.patch" in b and "Verified" in b
    assert "git checkout -b containerizer-refactor aaaaaaaaaaaa" in b and "git am --keep-cr &lt; shop-all-containerizer.patch" in b
    assert "git apply --3way" in b and "open a pull request yourself" in b
    assert "3,000 in / 400 out" in b and "qwen3-coder" in b and "10 min" in b and "gone from this file" in b
    assert "New findings on the patched copy" in b and "core-eol" in b and "/admin/llm-queue/42" in b
    d = _get(adm, op, "/admin/refactoring/42.patch")
    assert d.status == 200 and d.ctype == "text/x-diff; charset=utf-8" and d.body == PATCH.encode()
    assert dict(d.headers)["Content-Disposition"] == 'attachment; filename="shop-all-containerizer.patch"'
    lst = _get(adm, op, "/admin/refactoring")
    assert lst.status == 200 and "Verifying" in lst.body and "/admin/refactoring/42.patch" in lst.body
    assert "/admin/refactoring/43.patch" not in lst.body
    assert ("refactoring", "Refactoring") in adm._tabs(adm.sessions.get(op), __import__(
        "containerizer.roles", fromlist=["Access"]).Access(False, True))
    # a failed patch: no download
    adm.conn.answers[r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'"] = [
        _job(result={**RESULT, "status": "failed", "patch": None, "reason": "no usable edits: x"})]
    assert _get(adm, op, "/admin/refactoring/42.patch").status == 404
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "Download .patch" not in b and "no usable edits: x" in b
    # still queued
    adm.conn.answers[r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'"] = [_job(status="queued", result=None)]
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "Queued" in b and "Download .patch" not in b
    assert _get(adm, op, "/admin/refactoring/42.patch").status == 404
    assert _get(adm, op, "/admin/refactoring/99x").status == 404


def test_queue_page_links_refactor_jobs():
    from containerizer import admin_llmqueue
    html = admin_llmqueue.what({"JobId": 9, "Kind": "refactor", "App": "shop", "Repository": "Shop", "Component": None})
    assert "href='/admin/refactoring/9'" in html and "Refactoring" in html
    assert "href='/admin/llm-queue/9'" in admin_llmqueue.what({"JobId": 9, "Kind": "review", "Repository": "x"})


# --------------------------------------------------------------------------- the results page

def _app(rating="B", orders=()):
    return {"ApplicationId": 7, "Rating": rating, "refactors": list(orders),
            "components": [{"ComponentId": 11, "ComponentName": "Shop.Api", "Verdict": "refactor"},
                           {"ComponentId": 12, "ComponentName": "Web", "Verdict": "info"}]}


def test_results_page_refactoring_box():
    from containerizer import webui
    orders = [{"JobId": 42, "Component": None, "Status": "verified", "Summary": "verified: <1> fixed",
               "QueuedAt": datetime(2026, 11, 1), "FinishedAt": datetime(2026, 11, 2)}]
    staff = webui._refactoring(_app(orders=orders), {"csrf": "<input type='hidden' name='csrf' value='t'>", "signin": True})
    assert "action='/admin/refactoring/new'" in staff and "name='csrf' value='t'" in staff
    assert "<option value='11'>Shop.Api" in staff and "value='12'" not in staff
    assert "href='/admin/refactoring/42'" in staff and "Verified" in staff and "&lt;1&gt;" in staff
    viewer = webui._refactoring(_app(orders=orders), {"signin": True})
    assert "Verified" in viewer and "<form" not in viewer and "/admin/refactoring/42" not in viewer
    assert "Operators and administrators can request" in viewer
    assert webui._refactoring(_app(rating="A"), {"csrf": "x"}) == ""                  # only B-rated applications
    assert "Verified" in webui._refactoring(_app(rating="C", orders=orders), {})       # past orders still show
    assert "<form" not in webui._refactoring(_app(rating="C", orders=orders), {"csrf": "x"})


# --------------------------------------------------------------------------- the command line

def test_cli_runs_and_writes_the_patch_and_summary(shop, tmp_path, monkeypatch, capsys):
    from containerizer import cli
    monkeypatch.setattr(ai, "ask_json", lambda prompt, schema, **kw: good_answer())
    out = tmp_path / "out"
    assert cli.main(["refactor", str(shop), "--out", str(out), "--no-verify"]) == 0
    patch = (out / "shop-all-containerizer.patch").read_text()
    assert "LoadPkcs12FromFile" in patch
    summary = json.loads((out / "shop-all-containerizer.json").read_text())
    assert summary["status"] == "applies-only" and summary["payload"]["tasks"][0]["file"] == "src/Shop.Api/Bank.cs"
    text = capsys.readouterr().out
    assert "not built: 2 of 2 findings fixed" in text and "git am --keep-cr" in text
    # --queue without SQL Server: a queue file `containerizer llm-queue --file` works through
    monkeypatch.delenv("CONTAINERIZER_SQL", raising=False)
    assert cli.main(["refactor", str(shop), "--component", "Shop.Api", "--queue", "--out", str(out), "--no-verify"]) == 0
    q = lq.FileJobQueue(out / "llm-queue.json")
    (job,) = q.load()
    assert job["Kind"] == "refactor" and job["Component"] == "Shop.Api" and job["RequestedBy"] == "command line"
    assert job["EstInputTokens"] > 0 and "queued as job #1" in capsys.readouterr().out
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    assert lq.run_file(q.path, log=lambda m: None) == 0
    (job,) = q.load()
    assert job["Status"] == "answered" and job["Result"]["patch"].startswith("From ")
    assert cli.main(["refactor", str(tmp_path / "nope")]) == 2


# --------------------------------------------------------------------------- SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_schema_20_refactor_kind_and_view():
    """Schema 20: CK_LlmJob_Kind takes 'refactor' (also on a database made with schema 19), the admin login
    queues a refactoring and reads the report, the reader sees the order's status in vRefactorOrder."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czrefac_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    cur = conn.cursor()
    # as schema 19 made it: only 'review'; the next `db init` widens it
    cur.execute("ALTER TABLE cz.LlmJob DROP CONSTRAINT CK_LlmJob_Kind")
    cur.execute("ALTER TABLE cz.LlmJob ADD CONSTRAINT CK_LlmJob_Kind CHECK (Kind IN (N'review'))")
    cur.execute("DELETE FROM cz.SchemaVersion WHERE Version = 20")
    conn.commit()
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT MAX(Version) FROM cz.SchemaVersion")
    assert cur.fetchone()[0] >= 20                                         # later versions add to it
    cur.execute("SELECT definition FROM sys.check_constraints WHERE name = N'CK_LlmJob_Kind'")
    assert "refactor" in cur.fetchone()[0]
    cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'k', N'shop')")
    cur.execute("SELECT ApplicationId FROM cz.Application WHERE SourceKey = N'k'")
    app_id = cur.fetchone()[0]
    conn.commit()
    for login, role in (("cz_rf_admin", "admin"), ("cz_rf_reader", "reader"), ("cz_rf_writer", "writer")):
        sqlstore.create_login(conn, login, pw, role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    adm = sqlstore.connect(as_("cz_rf_admin"), pw)
    adm.set_user("o@example.com", "O", role="operator")
    payload = {"commit": "a" * 40, "tasks": [], "components": []}
    job = {"Kind": "refactor", "App": "shop", "SourceKey": "k", "Priority": rf.PRIORITY, "DedupeKey": "d" * 64,
           "RequestedBy": None, "InputChars": 7000, "Payload": payload}
    jid = lq.SqlJobQueue(None).add_with(adm, job)
    assert jid > 0 and lq.SqlJobQueue(None).add_with(adm, job) == 0              # one waiting order at a time
    cur = adm.cursor(as_dict=True)
    cur.execute("SELECT RequestedBy, ApplicationId, EstInputTokens FROM cz.LlmJob WHERE JobId = %s", (jid,))
    row = cur.fetchone()
    assert row["RequestedBy"] == "o@example.com" and row["ApplicationId"] == app_id and row["EstInputTokens"] == 2000
    cur.execute("SELECT TOP (1) ReportJson, SourceCommit FROM cz.ApplicationAssessment")    # granted to the admin role
    with pytest.raises(Exception):
        adm.cursor().execute("INSERT cz.LlmJob (Kind, Priority, DedupeKey, Payload) VALUES (N'other', 1, N'x', N'{}')")
    adm.close()
    w = sqlstore.connect(as_("cz_rf_writer"), pw)
    c = w.cursor()
    c.execute("UPDATE cz.LlmJob SET Status = N'running', Summary = N'verifying: building' WHERE JobId = %s", (jid,))
    w.commit()
    rd = sqlstore.connect(as_("cz_rf_reader"), pw)
    cur = rd.cursor(as_dict=True)
    cur.execute("SELECT * FROM cz.vRefactorOrder WHERE ApplicationId = %s", (app_id,))
    (o,) = cur.fetchall()
    assert o["Status"] == "verifying" and o["SourceCommit"] == "a" * 40 and "RequestedBy" not in o
    c.execute("UPDATE cz.LlmJob SET Status = N'answered', Result = %s WHERE JobId = %s",
              (json.dumps({"status": "applies-only", "patch": "x"}), jid))
    w.commit()
    cur.execute("SELECT Status FROM cz.vRefactorOrder WHERE JobId = %s", (jid,))
    assert cur.fetchone()["Status"] == "applies-only"
    with pytest.raises(Exception):
        rd.cursor().execute("SELECT Result FROM cz.LlmJob")                    # the patch is not for readers
    rd.close()
    w.close()


def test_git_am_is_what_the_guidance_says():
    html = admin_refactor.how_to_apply("b" * 40, "x.patch")
    assert "git checkout -b containerizer-refactor bbbbbbbbbbbb" in html and "git am --keep-cr &lt; x.patch" in html
    assert subprocess.run(["git", "am", "-h"], capture_output=True).returncode in (0, 129)


def test_the_rules_confirm_a_fix_the_llm_did_not_name(shop, tmp_path):
    """Seen with Qwen3-Coder: it changed the drive path but listed only the other rule as fixed; the rules on
    the edited copy show the finding is gone from that file, so it is fixed (and named in the commit)."""
    (shop / "src/Shop.Api/Options.cs").write_text(
        'public class Options\n{\n    public string Folder { get; set; } = @"D:\\Shop\\Options";\n}\n')
    _git(shop, "add", "-A")
    _git(shop, "commit", "--quiet", "-m", "path")
    pl = _payload(shop, verify=False, include_config=True)

    def ask(prompt, schema):
        if "File src/Shop.Api/Options.cs" in prompt:
            return {"edits": [{"file": "src/Shop.Api/Options.cs", "search": '@"D:\\Shop\\Options"',
                               "replace": '"/data/options"'}], "new_files": [], "package_changes": [],
                    "fixed": ["some-other-rule"], "not_fixed": [], "notes": ""}
        return good_answer()
    res = rf.run_order(pl, tmp_path / "w", ask=ask)
    f = next(x for x in res["findings"] if x["file"].endswith("Options.cs"))
    assert (f["status"], f["rules_after"], f["reason"], f.get("confirmed_by")) == ("fixed", "resolved", "", "rules")
    assert "os-drive-path-default" in res["patch"].split("\n\n")[0]          # in the commit subject


def test_the_results_page_says_what_happened_with_fixed_texts_only():
    from urllib.parse import parse_qs
    from containerizer import webui
    html = webui.refactor_notice(parse_qs("refactor=ordered&job=42&files=3"))
    assert "notice-ok" in html and "Refactoring patch requested: 3 file(s) to change" in html
    assert "already requested" in webui.refactor_notice(parse_qs("refactor=exists&job=42"))
    # nothing from the URL is shown: unknown codes show nothing, numbers must be numbers
    assert webui.refactor_notice(parse_qs("refactor=%3Cscript%3Ealert(1)%3C/script%3E")) == ""
    assert "<script" not in webui.refactor_notice(parse_qs("refactor=ordered&files=%3Cscript%3E"))
    assert "some file(s)" in webui.refactor_notice(parse_qs("refactor=ordered&files=%3Cscript%3E"))
    assert webui.refactor_notice({}) == ""


def test_the_same_code_is_changed_once_for_every_order(shop, tmp_path):
    """A library's file with the same code and findings in another application (here at another path) gets the
    change made for the first order without asking the LLM again; changed code is asked about."""
    first = []
    res = rf.run_order(_payload(shop, verify=False), tmp_path / "w", ask=lambda p, s: first.append(p) or good_answer())
    assert len(first) == 1 and res["calls"] == 1 and len(list(rf.shared_dir().glob("*.json"))) == 1
    # the same code in another repository, under lib/ instead of src/
    other = tmp_path / "other"
    (other / "lib").mkdir(parents=True)
    shutil.copytree(shop / "src", other / "lib", dirs_exist_ok=True)
    _git(other, "init", "--quiet")
    _git(other, "add", "-A")
    _git(other, "commit", "--quiet", "-m", "initial")
    doc = json.loads(json.dumps(_doc(shop)).replace("src/Shop.Api", "lib/Shop.Api"))
    pl = rf.build_payload(doc, {"type": "local", "path": str(other), "subdir": ".", "git": True},
                          _git(other, "rev-parse", "HEAD").strip(), source_key="other")
    pl["app"] = "other"
    asked = []
    res = rf.run_order(pl, tmp_path / "w2", ask=lambda p, s: asked.append(p) or good_answer())
    assert asked == [] and res["calls"] == 0, res.get("reason")
    assert [f["status"] for f in res["findings"]] == ["fixed", "fixed"]
    assert "+        return X509CertificateLoader.LoadPkcs12FromFile(path, null);" in res["patch"]
    assert "lib/Shop.Api/Bank.cs" in res["patch"] and "src/Shop.Api" not in res["patch"]
    assert any("was reused (no LLM call)" in n for n in res["notes"])
    # different code: the LLM is asked
    (other / "lib/Shop.Api/Bank.cs").write_text(BANK + "// changed\n")
    _git(other, "commit", "--quiet", "-am", "change")
    pl["commit"] = _git(other, "rev-parse", "HEAD").strip()
    rf.run_order(pl, tmp_path / "w3", ask=lambda p, s: asked.append(p) or good_answer())
    assert asked and asked[0].startswith("Application other")         # asked (the fake answer's path is src/: retried)


def test_an_answer_moves_with_the_file():
    a = {"edits": [{"file": "src/Lib/A.cs", "search": "x", "replace": "y"}, {"file": "src/Lib/appsettings.json",
                                                                              "search": "a", "replace": "b"}],
         "new_files": [{"file": "src/Lib/Certs.cs", "content": "c"}]}
    m = rf._moved(a, "src/Lib/A.cs", "libs/common/Lib/A.cs")
    assert [e["file"] for e in m["edits"]] == ["libs/common/Lib/A.cs", "libs/common/Lib/appsettings.json"]
    assert m["new_files"][0]["file"] == "libs/common/Lib/Certs.cs"
    assert rf._moved(a, "src/Lib/A.cs", "src/Lib/A.cs") is a
    assert rf._moved({"edits": [{"file": "A.cs"}]}, "A.cs", "x/A.cs")["edits"][0]["file"] == "x/A.cs"


# --------------------------------------------------------------------------- LLM-heavy refactoring orders

class _Q:
    def __init__(self):
        self.jobs = []

    def add(self, job):
        self.jobs.append(job)
        return 900 + len(self.jobs)


def _ends(hours=2):
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def test_a_heavy_refactoring_order_has_more_calls_and_stops_at_the_end_of_the_window(shop, tmp_path):
    pl = _payload(shop, verify=False)
    big = rf.heavy_payload(pl, _ends())
    assert big["max_calls"] == rf.HEAVY_CALLS == 40 and big["deadline"] and "max_passes" not in big
    asked = []
    late = {**pl, "deadline": "2020-01-01T00:00:00+00:00"}
    res = rf.run_order(late, tmp_path / "w", ask=lambda p, s: asked.append(p) or good_answer())
    assert asked == [] and {f["status"] for f in res["findings"]} == {"skipped"}
    assert "not attempted: the LLM-heavy window ended" in rf.summary(res)


def test_heavy_next_fix_continues_until_every_finding_is_fixed(shop, tmp_path):
    q, ends = _Q(), _ends()
    # the call limit left every finding: the next order asks about them again (nothing changed yet: heavy_same 1)
    pl = _payload(shop, verify=False, max_calls=0)
    res = rf.run_order(pl, tmp_path / "w1", ask=lambda p, s: good_answer())
    out = rf.heavy_next_fix({"JobId": 11}, pl, res, ends, queue=q)
    assert out["next_job"] == 901 and out["next"] == "the findings left (1 file)"
    nxt = q.jobs[0]["Payload"]
    assert nxt["heavy_round"] == 2 and nxt["heavy_parent"] == 11 and nxt["heavy_same"] == 1 and nxt["goal"] == "fix"
    assert [t["file"] for t in nxt["tasks"]] == ["src/Shop.Api/Bank.cs"] and "base_patch" not in nxt
    assert q.jobs[0]["RequestedBy"] == "LLM-heavy: after #11" and q.jobs[0]["DedupeKey"] != rf.dedupe_key(pl)
    # it fixes them: done
    res2 = rf.run_order({**nxt, "max_calls": 40}, tmp_path / "w2", ask=lambda p, s: good_answer())
    assert rf.heavy_next_fix({"JobId": 901}, nxt, res2, ends, queue=q) == {
        "round": 2, "until": ends.isoformat(timespec="seconds"), "done": "every finding fixed"}
    assert len(q.jobs) == 1
    # twice nothing: stopped; after the window, or 30 orders: stopped
    assert rf.heavy_next_fix({"JobId": 12}, nxt, res, ends, queue=q)["stopped"] == "two orders in a row changed nothing"
    assert rf.heavy_next_fix({"JobId": 12}, pl, res, _ends(-1), queue=q)["stopped"] == "the LLM-heavy window ended"
    assert rf.heavy_next_fix({"JobId": 12}, {**pl, "heavy_round": 30}, res, ends, queue=q)["stopped"].startswith("30")


def test_heavy_next_fix_repairs_a_patch_that_does_not_build_then_does_the_rest(shop, tmp_path):
    q, ends = _Q(), _ends()
    pl = _payload(shop)
    rest = {**pl["tasks"][0], "file": "src/Shop.Api/Program.cs"}
    pl = {**pl, "tasks": [*pl["tasks"], rest]}
    log = "/src/src/Shop.Api/Bank.cs(9,16): error CS0103: The name 'X509CertificateLoader' does not exist"
    res = {"status": "applies-only", "verify": True, "patch": "From x\nSubject: [PATCH] Containerizer: shop: cert-store\n",
           "verification": [{"component": "Shop.Api", "status": "build-failed", "log_tail": log}],
           "findings": [{"file": "src/Shop.Api/Bank.cs", "rule": "cert-store", "status": "fixed"},
                        {"file": "src/Shop.Api/Program.cs", "rule": "cert-store", "status": "skipped"}]}
    out = rf.heavy_next_fix({"JobId": 20}, pl, res, ends, queue=q)
    assert out["next"] == "repair the build or run"
    rep = q.jobs[-1]["Payload"]
    assert rep["goal"] == "repair" and rep["base_patch"] == res["patch"] and rep["errors"][0]["code"] == "CS0103"
    assert [t["file"] for t in rep["heavy_tasks"]] == ["src/Shop.Api/Program.cs"] and rep["heavy_goal"] == "fix"
    # the repair builds: the findings left come next, from the repaired patch
    fixed = {"status": "verified", "verify": True, "patch": "REPAIRED",
             "findings": [{"file": "src/Shop.Api/Bank.cs", "rule": "build-error", "status": "fixed"}]}
    out = rf.heavy_next_fix({"JobId": 21}, rep, fixed, ends, queue=q)
    cont = q.jobs[-1]["Payload"]
    assert out["next"] == "the findings left (1 file)" and cont["goal"] == "fix" and cont["base_patch"] == "REPAIRED"
    assert [t["file"] for t in cont["tasks"]] == ["src/Shop.Api/Program.cs"]
    assert not {"errors", "heavy_tasks", "base_job", "log_tail"} & set(cont) and cont["heavy_round"] == 3


def test_a_continued_order_makes_one_patch_with_both_changes(shop, tmp_path):
    first = rf.run_order(_payload(shop, verify=False), tmp_path / "w1", ask=lambda p, s: good_answer())
    pl = _payload(shop, verify=False)
    task = {**pl["tasks"][0], "file": "src/Shop.Api/Program.cs",
            "findings": [{**pl["tasks"][0]["findings"][0], "rule": "x-rule"}]}
    answer = {"edits": [{"file": "src/Shop.Api/Program.cs", "search": 'app.MapGet("/", () => "ok");',
                         "replace": 'app.MapGet("/", () => "ok!");'}], "new_files": [], "package_changes": [],
              "fixed": ["x-rule"], "not_fixed": []}
    res = rf.run_order({**pl, "tasks": [task], "base_patch": first["patch"], "heavy_parent": 31, "heavy_round": 2},
                       tmp_path / "w2", ask=lambda p, s: answer)
    assert res["status"] == "applies-only", res
    assert res["patch"].count("Subject: [PATCH]") == 1 and "LoadPkcs12FromFile" in res["patch"] and '"ok!"' in res["patch"]
    head = res["patch"].replace("\n ", " ")                    # the long subject is folded
    assert "cert-store-localmachine-code (continued)" in head and "Continues order #31" in head
    assert {f["file"] for f in res["files"]} == {"src/Shop.Api/Bank.cs", "src/Shop.Api/Program.cs"}
    assert rf._patch_subject(res["patch"]) == "Containerizer: shop: cert-store, cert-store-localmachine-code (continued)"


def test_the_handler_runs_a_refactoring_order_llm_heavy(shop, tmp_path, monkeypatch):
    monkeypatch.setenv(rf.WORK_ENV, str(tmp_path / "scratch"))
    seen = {}
    monkeypatch.setattr(rf, "heavy_window", lambda job: seen.setdefault("job", job) and _ends())
    real = rf.run_order
    monkeypatch.setattr(rf, "run_order", lambda pl, work, **kw: seen.setdefault("pl", pl) and real(
        pl, work, ask=lambda p, s: good_answer(), **kw))
    out = rf.handler({"JobId": 5, "Payload": _payload(shop, verify=False), "ProjectPath": "src/Shop.Api/Shop.Api.csproj"})
    assert seen["pl"]["max_calls"] == 40 and seen["pl"]["deadline"]
    assert out["result"]["heavy"]["done"] == "every finding fixed" and "LLM-heavy: every finding fixed" in out["summary"]


def test_the_order_page_shows_the_llm_heavy_chain_of_a_refactoring_order(adm):
    res = {**RESULT, "heavy": {"round": 2, "next_job": 77, "next": "the findings left (3 files)",
                               "until": "2026-11-04T06:00:00+00:00"}}
    job = _job(result=res, Payload=json.dumps({"commit": "a" * 40, "goal": "fix", "tasks": [], "heavy_round": 2,
                                               "heavy_parent": 70}))
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [job],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}]}
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    b = _get(adm, op, "/admin/refactoring/42").body
    assert "LLM-heavy mode, order 2 of the chain" in b and "not finished yet" in b and "href='/admin/refactoring/77'" in b
    assert "#70" in b and "the findings left (3 files)" in b and "Make it A" not in b


def test_a_patch_of_an_app_in_a_folder_is_repaired_in_that_folder(tmp_path):
    """A split repository's application lives in a folder: the patch names files from the repository's root, the
    repair asks about them relative to the application (they were not found, so nothing was repaired)."""
    repo = tmp_path / "mono"
    app = repo / "scenarios" / "field-service"
    (app / "src").mkdir(parents=True)
    (app / "src" / "Job.cs").write_text("class Job {}\n")
    (repo / "README.md").write_text("x\n")
    patch = ("From x\nSubject: [PATCH] c\n\n---\n"
             "diff --git a/scenarios/field-service/src/Job.cs b/scenarios/field-service/src/Job.cs\n"
             "--- a/scenarios/field-service/src/Job.cs\n+++ b/scenarios/field-service/src/Job.cs\n"
             "@@ -1 +1 @@\n-class Job {}\n+class Job { }\n"
             "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-x\n+y\n")
    assert rf.app_files(repo, app, patch) == ["src/Job.cs"]             # the file outside the application: left out
    tasks = rf.repair_tasks({"components": [{"name": "Web", "project": "src/Web.csproj"}], "log_tail": "boom"}, app,
                            rf.app_files(repo, app, patch))
    assert [t["file"] for t in tasks] == ["src/Job.cs"] and "does not run: boom" in tasks[0]["findings"][0]["title"]


def test_fix_it_with_the_llm_on_a_make_it_a_order_goes_on_as_make_it_a():
    pl = {"goal": "rating-a", "app": "shop", "commit": "c" * 40, "components": [{"name": "Web", "project": "p"}],
          "tasks": [{"file": "a.cs", "findings": []}], "deadline": "x", "heavy_round": 2, "max_calls": 16}
    res = {"patch": "PATCH", "status": "applies-only",
           "verification": [{"component": "Web", "status": "build-failed", "log_tail": "error"}]}
    nxt = rf.repair_payload(pl, res, 41)
    assert nxt["goal"] == "rating-a" and nxt["base_patch"] == "PATCH" and nxt["base_job"] == 41
    assert nxt["heavy_parent"] == 41 and nxt["heavy_round"] == 3 and "deadline" not in nxt
    assert rf.repair_payload({**pl, "goal": "fix"}, res, 41)["goal"] == "repair"       # other orders: a repair


NUGET_LOG = """#12 3.385 /src/src/FieldService.Web/FieldService.Web.csproj : error NU1605: Warning As Error: Detected package downgrade: Microsoft.EntityFrameworkCore.SqlServer from 8.0.11 to 8.0.0. Reference the package directly from the project to select a different version.  [/src/src/FieldService.Web/FieldService.Web.csproj]
3.385 /src/src/FieldService.Web/FieldService.Web.csproj : error NU1605:  FieldService.Web -> FieldService.Data -> Microsoft.EntityFrameworkCore.SqlServer (>= 8.0.11)
3.385 /src/src/FieldService.Web/FieldService.Web.csproj : error NU1605:  FieldService.Web -> Microsoft.EntityFrameworkCore.SqlServer (>= 8.0.0)
3.492   Failed to restore /src/src/FieldService.Web/FieldService.Web.csproj (in 1.24 sec).
------
Dockerfile:22
ERROR: failed to solve: process "/bin/sh -c dotnet restore" did not complete successfully: exit code: 1"""


def test_a_nuget_error_of_a_project_is_repaired_in_that_project():
    """NU1605 (package downgrade) names the project, without a line: the repair asks about that project file, with
    every dependency path NuGet printed; the last characters of the log are only Docker's report of the step."""
    errs = rf.build_errors(NUGET_LOG)
    assert {e["file"] for e in errs} == {"src/FieldService.Web/FieldService.Web.csproj"}
    assert [e["code"] for e in errs] == ["NU1605"] * 3 and errs[0]["line"] == 0
    assert "from 8.0.11 to 8.0.0" in errs[0]["text"] and "FieldService.Data -> " in errs[1]["text"]
    assert rf.build_errors("/src/a/B.cs(3,7): error CS0103: x [/src/a/a.csproj]")[0] == {
        "file": "a/B.cs", "line": 3, "code": "CS0103", "text": "x"}
    lines = rf.error_lines(NUGET_LOG)
    assert "Detected package downgrade" in lines and "failed to solve" not in lines


def test_heavy_stop_reason_is_in_the_result_line():
    res = {"status": "applies-only", "verify": True, "files": [1], "findings": [{"status": "fixed"}],
           "verification": [{"status": "build-failed"}], "heavy": {"stopped": "two orders in a row changed nothing"}}
    assert rf.summary(res).endswith("; LLM-heavy: stopped: two orders in a row changed nothing")


def test_a_repair_builds_the_components_its_patch_changes(shop, tmp_path, monkeypatch):
    """A repair (or an order that continues an earlier patch) has no tasks of its own: the components to build are
    those whose files the patch changes. Before, nothing was built: "Not built" with Docker there."""
    from containerizer import verify as vf
    built = []
    monkeypatch.setattr(vf, "_run", lambda cmd, timeout: None)
    monkeypatch.setattr(vf, "verify_component", lambda a, c, rules, timeout, work: built.append(c.name) or
                        {"status": "ok", "attempts": []})
    pl = _payload(shop)
    out = rf.verify_components({**pl, "tasks": []}, shop, tmp_path / "v", files=["src/Shop.Api/Bank.cs"])
    assert built == ["Shop.Api"] and [v["status"] for v in out] == ["ok"]
    assert rf.verify_components({**pl, "tasks": []}, shop, tmp_path / "v2") == []          # nothing changed
