"""An application's own output repository (appoutput.py): the one-time move, the stub the scans leave alone, the
sandbox's read token, and the admin page."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from containerizer import appoutput as ao, credentials, org as orgmod, worker as wk
from test_llm_queue import FakeConn
from test_make_it_a import _output
from test_refactor import _get, _loc, _post, adm  # noqa: F401 - fixture

APP_REL = "Contoso/_/shop"
KEY = "https://github.com/contoso/shop#"


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=root, check=True,
                          capture_output=True, text=True).stdout


class Local:
    """A repository opened by the runner (org.Output's interface): a local work tree, commits made there."""

    def __init__(self, url: str, root: Path):
        self.url, self.root = url, root

    def commit(self, message: str) -> bool:
        _git(self.root, "add", "-A")
        if not _git(self.root, "status", "--porcelain").strip():
            return False
        _git(self.root, "commit", "-qm", message)
        return True


class Write:
    def __init__(self, token="t0ken", username="x-access-token"):
        self.token, self.username = token, username


class Creds:
    items: list = []

    def write_for(self, url):
        return Write() if url else None

    def hosts(self):
        return {"git.example.com"}


def _team_repo(tmp_path: Path) -> Path:
    d = tmp_path / "team"
    d.mkdir()
    _git(d, "init", "-q", "-b", "main")
    (d / "README.md").write_text("team\n")
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "init")
    return d


def _setup(tmp_path, monkeypatch, apps):
    out, _ = _output(tmp_path)
    doc = json.loads((out / APP_REL / "containerizer.json").read_text())
    doc["source_key"] = KEY
    (out / APP_REL / "containerizer.json").write_text(json.dumps(doc))
    _git(out, "commit", "-qam", "key")
    team = _team_repo(tmp_path)
    repos = {"https://git.example.com/out": out, "https://git.example.com/team/shop": team}
    scan = {"ScanId": 3, "Provider": "github", "Organization": "Contoso", "OutputRepo": "https://git.example.com/out",
            "OutputBranch": "main"}
    conn = FakeConn({r"FROM cz.Application WHERE OutputRepo IS NOT NULL": lambda p: apps["rows"],
                     r"FROM cz.OrgScan WHERE OutputRepo": [scan]})
    monkeypatch.setattr(credentials, "load", lambda c, key=None: Creds())
    monkeypatch.setattr(wk, "allowed_hosts", lambda: set())
    tokens = tmp_path / "run" / "sandbox-git"
    tokens.parent.mkdir()
    env = {ao.TOKENS_ENV: str(tokens)}

    def opener(url, branch, write, work):
        assert write.token == "t0ken"
        return Local(url, repos[url])

    def run():
        return ao.housekeep(lambda: conn, "key", tmp_path / "w", log=lambda m: None, opener=opener, env=env)
    return out, team, conn, tokens, run


def test_clean_path():
    assert ao.clean_path("") == "deploy" and ao.clean_path(" /deploy/shop/ ") == "deploy/shop"
    for bad in ("../x", "a/../b", "a b", "sandbox", ".git/x", "-x", "a//b", "x" * 201):
        assert ao.clean_path(bad) is None, bad


def test_the_files_move_once_and_the_sandbox_follows(tmp_path, monkeypatch):
    app = {"ApplicationId": 7, "Name": "shop", "SourceKey": KEY, "OutputRepo": "https://git.example.com/team/shop",
           "OutputBranch": "main", "OutputPath": "deploy", "OutputMovedAt": None, "OutputMovedCommit": None,
           "OutputNamespace": None, "OutputMoveError": None}
    apps = {"rows": [app]}
    out, team, conn, tokens, run = _setup(tmp_path, monkeypatch, apps)
    assert run() == 2                                         # one commit in each repository
    # its own repository: the whole folder, pointed at itself
    d = team / "deploy"
    moved = json.loads((d / "containerizer.json").read_text())
    assert moved["moved_from"]["repo"] == "https://git.example.com/out" and moved["moved_from"]["path"] == APP_REL
    assert "moved_to" not in moved and (d / "kustomization.yaml").is_file() and (d / "MOVED.md").is_file()
    docs = [x for x in yaml.safe_load_all((d / "gitops/flux/git/sync.yaml").read_text()) if x]
    src = next(x for x in docs if x["kind"] == "GitRepository")
    ks = next(x for x in docs if x["kind"] == "Kustomization")
    assert src["spec"]["url"] == "https://git.example.com/team/shop" and src["spec"]["ref"] == {"branch": "main"}
    assert ks["spec"]["path"] == "./deploy"
    assert "moved here from https://git.example.com/out" in _git(team, "log", "-1", "--format=%s")
    commit = _git(team, "rev-parse", "HEAD").strip()
    # the scan's output repository: a stub the sandbox still deploys, from the application's repository
    s = out / APP_REL
    stub = json.loads((s / "containerizer.json").read_text())
    assert stub["moved_to"]["repo"] == "https://git.example.com/team/shop" and stub["moved_to"]["commit"] == commit
    assert not (s / "kustomization.yaml").exists() and (s / "README.md").is_file()
    assert sorted(p.relative_to(s).as_posix() for p in s.rglob("*") if p.is_file() and "gitops" in p.parts) == [
        "gitops/flux/git/sync.yaml", "gitops/flux/kustomization.yaml", "gitops/flux/tenant.yaml"]
    sdocs = [x for x in yaml.safe_load_all((s / "gitops/flux/git/sync.yaml").read_text()) if x]
    assert next(x for x in sdocs if x["kind"] == "GitRepository")["spec"]["url"] == "https://git.example.com/team/shop"
    apps_k = yaml.safe_load((out / "clusters/sandbox/flux/apps/kustomization.yaml").read_text())
    assert f"../../../../{APP_REL}/gitops/flux" in apps_k["resources"]
    assert ao.moved_to(s)["path"] == "deploy" and orgmod.repo_dirs(out, APP_REL) == []   # scans leave it alone
    (sql, params), = conn.sql(r"SET OutputMovedAt = SYSUTCDATETIME\(\)")
    assert params == (commit, "shop", 7, "https://git.example.com/team/shop")
    # the moved state: the sandbox's read token for its namespace, nothing moved again
    app.update(OutputMovedAt=datetime(2026, 11, 4), OutputMovedCommit=commit, OutputNamespace="shop")
    assert run() == 0
    assert (tokens / "shop").read_text() == "https://git.example.com/team/shop\nx-access-token\nt0ken\n"
    assert oct((tokens / "shop").stat().st_mode & 0o777) == "0o600"
    assert run() == 0 and len(conn.sql(r"SET OutputMovedAt")) == 1
    # cleared: the stub goes (the next scan deploys it here again), the token too; its own copy stays
    apps["rows"] = []
    assert run() == 1
    assert not (out / APP_REL).exists() and f"{APP_REL}/gitops/flux" not in (out / "clusters/sandbox/flux/apps/kustomization.yaml").read_text()
    assert not (tokens / "shop").exists() and (team / "deploy/containerizer.json").is_file()


def test_a_folder_that_is_not_empty_is_not_overwritten(tmp_path, monkeypatch):
    app = {"ApplicationId": 7, "Name": "shop", "SourceKey": KEY, "OutputRepo": "https://git.example.com/team/shop",
           "OutputBranch": "main", "OutputPath": "deploy", "OutputMovedAt": None}
    out, team, conn, tokens, run = _setup(tmp_path, monkeypatch, {"rows": [app]})
    (team / "deploy").mkdir()
    (team / "deploy/theirs.yaml").write_text("x: 1\n")
    assert run() == 0
    (sql, params), = conn.sql(r"SET OutputMoveError")
    assert "folder deploy/ of https://git.example.com/team/shop is not empty" in params[0]
    assert not ao.moved_to(out / APP_REL) and (team / "deploy/theirs.yaml").read_text() == "x: 1\n"
    assert run() == 0 and len(conn.sql(r"SET OutputMoveError")) == 1         # tried again in 10 minutes, not now


def test_an_application_no_scan_deployed_waits(tmp_path, monkeypatch):
    app = {"ApplicationId": 8, "Name": "ledger", "SourceKey": "https://github.com/contoso/ledger#",
           "OutputRepo": "https://git.example.com/team/shop", "OutputBranch": "main", "OutputPath": None,
           "OutputMovedAt": None}
    out, team, conn, tokens, run = _setup(tmp_path, monkeypatch, {"rows": [app]})
    assert run() == 0
    (sql, params), = conn.sql(r"SET OutputMoveError")
    assert params == (ao.WAITING, 8, ao.WAITING) and not (team / "deploy").exists()


def test_the_scan_assesses_a_moved_application_only(tmp_path):
    out, o = _output(tmp_path)
    m = {"repo": "https://git.example.com/team/shop", "branch": "main", "path": "deploy", "commit": "c" * 40,
         "from_repo": "x", "from_branch": "main", "from_path": APP_REL}
    ao.make_stub(out / APP_REL, m)
    before = sorted(p.as_posix() for p in (out / APP_REL).rglob("*"))
    res = orgmod.RepoResult(provider="github", org="Contoso", project="_", repo="shop", status="error", app="shop",
                            source_key=KEY)
    o2 = orgmod.Output(o, tmp_path / "w1")
    res = orgmod.deploy_app(None, tmp_path, APP_REL, o, o2, None, "1.0.1", None, res, tmp_path / "w1", "shop")
    assert res.status == "moved" and "https://git.example.com/team/shop" in res.reason and "assessed only" in res.reason
    assert sorted(p.as_posix() for p in (out / APP_REL).rglob("*")) == before
    from containerizer.admin_scans import LAST_TEXT
    assert "own output repository" in LAST_TEXT["moved"]
    split = orgmod.combine_split(orgmod.RepoResult(provider="github", org="C", project="_", repo="r", status="error"),
                                 [("a", res)], "apps/*")
    assert split.status == "moved"


def test_repoint_keeps_comments_when_it_can(tmp_path):
    f = tmp_path / "gitops/flux/git/sync.yaml"
    f.parent.mkdir(parents=True)
    f.write_text("# read-only key\napiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: s\n"
                 "spec:\n  url: https://old.example/out\n  ref:\n    branch: main\n---\n"
                 "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: s\nspec:\n"
                 "  sourceRef:\n    kind: GitRepository\n    name: s\n  path: ./Contoso/_/shop\n")
    ao.repoint(tmp_path, "https://new.example/team", "prod", "deploy",
               old={"repo": "https://old.example/out", "branch": "main", "path": "Contoso/_/shop"})
    t = f.read_text()
    assert t.startswith("# read-only key") and "url: https://new.example/team" in t and "branch: prod" in t
    assert "path: ./deploy" in t


# --------------------------------------------------------------------------- the admin page

APP_ROW = {"ApplicationId": 7, "Name": "shop", "DisplayName": None, "Description": None, "Owner": None, "ProductId": None,
           "Retired": False, "RepositoryUrl": "https://github.com/contoso/shop", "SandboxEnabled": True, "SourcePath": ".",
           "FirstSeenAt": datetime(2026, 11, 1), "LastSeenAt": datetime(2026, 11, 2), "ProductName": None,
           "OutputRepo": None, "OutputBranch": None, "OutputPath": None, "OutputMovedAt": None, "OutputMovedCommit": None,
           "OutputMoveError": None}


def test_admins_set_and_clear_it(adm, monkeypatch):
    from containerizer import admin_scans
    monkeypatch.setattr(admin_scans, "_output_repos", lambda conn: ["https://git.example.com/team/shop"])
    row = dict(APP_ROW)
    adm.conn.answers = {r"FROM cz.Application x": lambda p: [row],
                        r"WITH \(UPDLOCK, HOLDLOCK\)": [{"ApplicationId": 7, "ProductId": None, "AppName": "shop"}],
                        r"SELECT OutputMovedAt FROM cz.Application": lambda p: [{"OutputMovedAt": row["OutputMovedAt"]}]}
    ad = adm.sessions.create("a@example.com", "A", True)
    b = _get(adm, ad, "/admin/applications/7").body
    assert "<h2>Output repository</h2>" in b and "<option value='https://git.example.com/team/shop'>" in b
    assert "name='OutputPath' maxlength='200' value='deploy'" in b
    # only administrators: a product owner sees no section, and a post is refused
    po = adm.sessions.create("p@example.com", "P", False, False, True, [])
    assert "<h2>Output repository</h2>" not in _get(adm, po, "/admin/applications/7").body
    r = _post(adm, po, "/admin/applications/7/output", Action="save", OutputRepo="https://git.example.com/team/shop")
    assert not adm.conn.sql(r"UPDATE cz.Application SET OutputRepo")
    assert _post(adm, ad, "/admin/applications/7/output", csrf="wrong", Action="clear").status == 403
    for form, why in (({"OutputRepo": "https://git.example.com/other"}, "write token"),
                      ({"OutputRepo": "https://git.example.com/team/shop", "OutputPath": "../x"}, "relative"),
                      ({"OutputRepo": "https://git.example.com/team/shop", "OutputBranch": "a..b"}, "branch")):
        r = _post(adm, ad, "/admin/applications/7/output", Action="save", **form)
        assert "Not+saved" in _loc(r) and why.replace(" ", "+") in _loc(r), form
    assert not adm.conn.sql(r"UPDATE cz.Application SET OutputRepo")
    r = _post(adm, ad, "/admin/applications/7/output", Action="save", OutputRepo="https://git.example.com/team/shop",
              OutputBranch="main", OutputPath="deploy/shop")
    (sql, params), = adm.conn.sql(r"UPDATE cz.Application SET OutputRepo")
    assert params == ("https://git.example.com/team/shop", "main", "deploy/shop", 7) and "OutputMovedAt = NULL" in sql
    row.update(OutputRepo="https://git.example.com/team/shop", OutputBranch="main", OutputPath="deploy/shop")
    assert "<span class='st st-wait'>Pending</span>" in _get(adm, ad, "/admin/applications/7").body
    row["OutputMoveError"] = "folder deploy/shop/ of x is not empty"
    assert "<span class='st st-bad'>Not moved</span> folder deploy/shop/ of x is not empty" in \
        _get(adm, ad, "/admin/applications/7").body
    # moved: only "back to the scan's output repository"; another target needs that first
    row.update(OutputMovedAt=datetime(2026, 11, 4, 10, 0), OutputMovedCommit="c" * 40, OutputMoveError=None)
    b = _get(adm, ad, "/admin/applications/7").body
    assert "<span class='st st-ok'>Moved</span>" in b and "Back to the scan" in b and "name='OutputRepo'" not in b
    r = _post(adm, ad, "/admin/applications/7/output", Action="save", OutputRepo="https://git.example.com/team/shop")
    assert "moved+already" in _loc(r) and len(adm.conn.sql(r"UPDATE cz.Application SET OutputRepo")) == 1
    r = _post(adm, ad, "/admin/applications/7/output", Action="clear")
    assert "Cleared" in _loc(r)
    assert adm.conn.sql(r"UPDATE cz.Application SET OutputRepo")[-1][1] == (None, None, None, 7)


def test_cz_sandbox_uses_the_moved_applications_own_token():
    script = (Path(__file__).resolve().parent.parent / "appliance/rootfs/usr/lib/containerizer/bin/cz-sandbox").read_text()
    assert "SANDBOX_GIT_DIR=/var/lib/containerizer/refactor/sandbox-git" in script
    assert ao.TOKENS_DIR == "/var/lib/containerizer/refactor/sandbox-git"
    assert 'cz_store_put "$ns--cz-git" username="${OWN_USER:-git}" password="$OWN_PASS"' in script
    assert 'own_token "$ns" "$url" || continue' in script


@pytest.mark.parametrize("ns", ["shop", "a-b"])
def test_tokens_go_only_to_moved_applications(tmp_path, ns):
    d = tmp_path / "t"
    tmp_path.joinpath("x").mkdir()
    (tmp_path / "t").mkdir()
    (d / "old").write_text("stale")
    apps = [{"OutputRepo": "https://u:p@git.example.com/team/shop", "OutputMovedAt": datetime(2026, 11, 4),
             "OutputNamespace": ns},
            {"OutputRepo": "https://git.example.com/x", "OutputMovedAt": None, "OutputNamespace": "x"},
            {"OutputRepo": "https://git.example.com/y", "OutputMovedAt": datetime(2026, 11, 4), "OutputNamespace": "../y"}]
    assert ao.write_tokens(apps, Creds(), {ao.TOKENS_ENV: str(d)}) == 1
    assert sorted(p.name for p in d.iterdir()) == [ns]
    assert (d / ns).read_text().startswith("https://git.example.com/team/shop\n")      # no user info in the URL
    assert ao.write_tokens(apps, Creds(), {ao.TOKENS_ENV: str(tmp_path / "none" / "t")}) == 0   # not the appliance
