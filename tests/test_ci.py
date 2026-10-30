"""CI gate: base-ref comparison, outputs, and the Azure DevOps comment poster."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from containerizer.ci import MARKER, annotations, diff, sarif, snapshot
from containerizer.cli import main

from test_engine import web_app

ROOT = Path(__file__).resolve().parent.parent


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def repo_with_change(tmp_path: Path, code: str = "", packages: str = "") -> Path:
    """A git repo whose HEAD~1 is a clean web app and HEAD adds `code` / `packages`."""
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    web_app(tmp_path / "app")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    web_app(tmp_path / "app", code=code, packages=packages)
    git(tmp_path, "commit", "-qam", "change")
    return tmp_path / "app"


def test_new_blocker_fails_against_base_ref(tmp_path):
    app = repo_with_change(tmp_path, code='var t = Type.GetTypeFromProgID("Excel.Application");')
    out = tmp_path / "out"
    rc = main(["check", str(app), "--base-ref", "HEAD~1", "--markdown", str(out) + ".md",
               "--sarif", str(out) + ".sarif", "--json", str(out) + ".json"])
    assert rc == 1
    md = Path(str(out) + ".md").read_text()
    assert md.startswith(MARKER) and "was **A**" in md and "Office automation" in md
    assert "app/src/Web/Program.cs" in md            # paths are relative to the git root, not the app
    res = json.loads(Path(str(out) + ".sarif").read_text())["runs"][0]["results"]
    new = [r for r in res if r["baselineState"] == "new"]
    assert new and new[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("app/src/Web/")
    # the working tree is untouched
    assert "Excel.Application" in (app / "src/Web/Program.cs").read_text()


def test_unchanged_app_passes(tmp_path):
    app = repo_with_change(tmp_path, code="// just a comment")
    assert main(["check", str(app), "--base-ref", "HEAD~1"]) == 0


def test_refactor_only_respects_threshold_and_rating(tmp_path):
    app = repo_with_change(tmp_path, code='var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("x");')
    # a refactor-level finding is below the default threshold, but the rating drops A -> B
    assert main(["check", str(app), "--base-ref", "HEAD~1"]) == 1
    assert main(["check", str(app), "--base-ref", "HEAD~1", "--allow-rating-drop"]) == 0
    assert main(["check", str(app), "--base-ref", "HEAD~1", "--allow-rating-drop", "--fail-on", "refactor"]) == 1


def test_baseline_file_and_max_rating(tmp_path):
    web_app(tmp_path)
    base = tmp_path / "base.json"
    assert main(["check", str(tmp_path), "--save-baseline", str(base)]) == 0
    web_app(tmp_path, code='var t = Type.GetTypeFromProgID("Word.Application");')
    assert main(["check", str(tmp_path), "--baseline", str(base)]) == 1
    assert main(["check", str(tmp_path), "--max-rating", "D"]) == 1      # E is worse than D, no baseline needed
    assert main(["check", str(tmp_path), "--fail-on", "none", "--allow-rating-drop", "--baseline", str(base)]) == 0


def test_new_app_at_base_is_all_new(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "README.md").write_text("x")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    web_app(tmp_path / "svc", code='var t = Type.GetTypeFromProgID("Excel.Application");')
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "add svc")
    head = snapshot([tmp_path / "svc"], root=tmp_path)
    from containerizer.ci import snapshot_at_ref
    d = diff(head, snapshot_at_ref([tmp_path / "svc"], "HEAD~1"))
    assert d["failed"] and d["apps"][0]["is_new_app"] and d["apps"][0]["new"]


def test_annotations_and_sarif_shape(tmp_path):
    web_app(tmp_path, code='var t = Type.GetTypeFromProgID("Excel.Application");')
    head = snapshot([tmp_path])
    base = {"version": 1, "apps": [{**head["apps"][0], "rating": "A", "findings": []}]}
    d = diff(head, base)
    gh = annotations(d, "github")
    assert gh and gh[0].startswith("::error file=src/Web/Program.cs,line=")
    az = annotations(d, "azure")
    assert az[0].startswith("##vso[task.logissue type=error;sourcepath=src/Web/Program.cs;linenumber=")
    s = sarif(d)
    assert s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["rules"]
    assert {r["level"] for r in s["runs"][0]["results"]} <= {"error", "warning", "note"}


def test_dormant_library_code_does_not_fail(tmp_path):
    """Windows-only code in a referenced library that the app never calls must not trip the gate."""
    web_app(tmp_path)
    (tmp_path / "src/Lib").mkdir(parents=True)
    (tmp_path / "src/Lib/Lib.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    (tmp_path / "src/Lib/Office.cs").write_text(
        'public static class OfficeExport { public static object Go() => Type.GetTypeFromProgID("Excel.Application"); }')
    csproj = tmp_path / "src/Web/Web.csproj"
    csproj.write_text(csproj.read_text().replace("<ItemGroup>", '<ItemGroup><ProjectReference Include="../Lib/Lib.csproj" />'))
    head = snapshot([tmp_path])
    assert not [f for f in head["apps"][0]["findings"] if f["severity"] == "blocker"]


class _AdoMock(BaseHTTPRequestHandler):
    threads: list = []
    calls: list = []

    def _send(self, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    def do_GET(self):
        self.calls.append(("GET", self.path, self.headers["Authorization"]))
        self._send({"value": self.threads})

    def do_POST(self):
        b = self._body()
        self.calls.append(("POST", self.path, b))
        t = {"id": len(self.threads) + 1, "comments": [{"id": 1, "content": b["comments"][0]["content"]}]}
        self.threads.append(t)
        self._send(t)

    def do_PATCH(self):
        b = self._body()
        self.calls.append(("PATCH", self.path, b))
        self._send({})

    def log_message(self, *a):
        pass


def test_azure_comment_create_then_update(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _AdoMock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    md = tmp_path / "c.md"
    md.write_text(MARKER + "\nrating A\n")
    env = {**os.environ, "SYSTEM_ACCESSTOKEN": "tok", "SYSTEM_PULLREQUEST_PULLREQUESTID": "7",
           "SYSTEM_COLLECTIONURI": f"http://127.0.0.1:{srv.server_port}/org/", "SYSTEM_TEAMPROJECTID": "proj",
           "BUILD_REPOSITORY_ID": "repo", "BUILD_REPOSITORY_PROVIDER": "TfsGit", "NO_PROXY": "127.0.0.1",
           "no_proxy": "127.0.0.1"}
    script = str(ROOT / "ci/azure/post_comment.py")
    try:
        r1 = subprocess.run([sys.executable, script, str(md)], env=env, capture_output=True, text=True)
        r2 = subprocess.run([sys.executable, script, str(md)], env=env, capture_output=True, text=True)
    finally:
        srv.shutdown()
    assert "created PR comment" in r1.stdout, r1.stdout + r1.stderr
    assert "updated PR comment in thread 1" in r2.stdout, r2.stdout + r2.stderr
    methods = [c[0] for c in _AdoMock.calls]
    assert methods == ["GET", "POST", "GET", "PATCH"]
    assert _AdoMock.calls[0][1].startswith("/org/proj/_apis/git/repositories/repo/pullRequests/7/threads")
    assert _AdoMock.calls[0][2] == "Bearer tok"
    assert _AdoMock.calls[3][1].startswith("/org/proj/_apis/git/repositories/repo/pullRequests/7/threads/1/comments/1")


def test_explanations_and_references_reach_every_output(tmp_path, monkeypatch):
    from containerizer import rules as rules_mod
    from containerizer.ci import markdown
    from containerizer.report import migration_markdown, portfolio_html, ref_label
    from containerizer.assess import assess

    url = "https://github.com/dotnet/runtime/issues/12345"
    assert ref_label(url) == "dotnet/runtime#12345"
    real = rules_mod.load_rules

    def with_refs(*a, **k):
        out = real(*a, **k)
        for r in out:
            r.refs = [url]
        return out
    monkeypatch.setattr(rules_mod, "load_rules", with_refs)
    import containerizer.ci as ci_mod
    monkeypatch.setattr(ci_mod, "load_rules", with_refs)
    web_app(tmp_path, code='var t = Type.GetTypeFromProgID("Excel.Application");')
    head = snapshot([tmp_path])
    d = diff(head, {"version": 1, "apps": [{**head["apps"][0], "rating": "A", "findings": []}]})
    md = markdown(d)
    assert "[dotnet/runtime#12345](" + url + ")" in md and "**Fix:**" in md
    rule = next(r for r in sarif(d)["runs"][0]["tool"]["driver"]["rules"])
    assert rule["helpUri"] == url and "Learn more" in rule["help"]["markdown"]
    a = assess(tmp_path, with_refs())
    assert "Learn more: [dotnet/runtime#12345]" in migration_markdown(a)
    assert f"<a href='{url}'>" in portfolio_html([a])
