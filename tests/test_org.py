"""Organization-wide runner: providers (against local fake APIs), naming, skips, selection, output layout."""
import base64
import http.server
import json
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from containerizer import org as orgmod
from containerizer import orgsource
from containerizer.assess import assess
from containerizer.org import (OrgOptions, add_pull_secret, app_name, default_tag, run_org, segment,
                               select_components, unique_names)
from containerizer.orgsource import (NO_PROJECT, Redactor, SourceRepo, existing_dockerfiles, git_env, provider)
from containerizer.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "ci-demo"


# --------------------------------------------------------------------------- fake APIs

class _Api:
    def __init__(self, routes):
        self.routes, self.seen = routes, []
        api = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                api.seen.append((self.path, dict(self.headers)))
                for prefix, fn in api.routes:
                    if self.path.startswith(prefix):
                        status, body, headers = fn(self.path, f"http://127.0.0.1:{api.port}")
                        self.send_response(status)
                        for k, v in headers.items():
                            self.send_header(k, v)
                        self.end_headers()
                        self.wfile.write(json.dumps(body).encode())
                        return
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"message":"Not Found"}')

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def api():
    made = []

    def make(routes):
        a = _Api(routes)
        made.append(a)
        return a
    yield make
    for a in made:
        a.close()


def test_github_paginates_and_authenticates(api):
    def repos(path, base):
        if "page=2" in path:
            return 200, [{"name": "b", "clone_url": "https://github.com/acme/b.git", "pushed_at": "2026-01-01T00:00:00Z",
                          "default_branch": "main", "archived": True, "size": 5}], {}
        return 200, [{"name": "a", "clone_url": "https://github.com/acme/a.git", "pushed_at": "2026-10-01T00:00:00Z",
                      "default_branch": "dev", "size": 0, "fork": True}], \
            {"Link": f'<{base}/orgs/acme/repos?page=2>; rel="next", <{base}/x>; rel="last"'}
    a = api([("/orgs/acme/repos", repos)])
    got = list(provider("github", "acme", "tok123", a.url).repos())
    assert [(r.name, r.project, r.default_branch, r.archived, r.empty, r.fork) for r in got] == [
        ("a", NO_PROJECT, "dev", False, True, True), ("b", NO_PROJECT, "main", True, False, False)]
    assert got[0].last_activity == datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert all(h.get("Authorization") == "Bearer tok123" for _, h in a.seen)


def test_github_user_account_fallback(api):
    a = api([("/user/repos", lambda p, b: (200, [{"name": "mine", "clone_url": "https://github.com/me/mine.git"}], {})),
             ("/user", lambda p, b: (200, {"login": "Me"}, {}))])
    assert [r.name for r in provider("github", "me", "t", a.url).repos()] == ["mine"]


def test_gitlab_subgroups_become_project_folders(api):
    def projects(path, base):
        assert "include_subgroups=true" in path or "page=2" in path
        if "page=2" in path:
            return 200, [{"path": "deep", "namespace": {"full_path": "acme/team/sub"}, "id": 3,
                          "http_url_to_repo": "https://gitlab.com/acme/team/sub/deep.git", "empty_repo": False}], {}
        return 200, [{"path": "top", "namespace": {"full_path": "acme"}, "id": 1, "default_branch": "main",
                      "http_url_to_repo": "https://gitlab.com/acme/top.git", "last_activity_at": "2026-10-01T00:00:00.000Z"},
                     {"path": "svc", "namespace": {"full_path": "acme/team"}, "id": 2, "archived": True,
                      "http_url_to_repo": "https://gitlab.com/acme/team/svc.git", "forked_from_project": {"id": 9}}], \
            {"Link": f'<{base}/api/v4/groups/acme/projects?page=2>; rel="next"'}
    commits = lambda p, b: (200, [{"committed_date": "2025-02-03T04:05:06.000+02:00"}], {})
    a = api([("/api/v4/groups/acme/projects", projects), ("/api/v4/projects/1/repository/commits", commits)])
    p = provider("gitlab", "acme", "glpat", a.url)
    got = list(p.repos())
    assert [(r.project, r.name, r.archived, r.fork) for r in got] == [
        (NO_PROJECT, "top", False, False), ("team", "svc", True, True), ("team--sub", "deep", False, False)]
    assert p.last_commit(got[0]) == datetime(2025, 2, 3, 2, 5, 6, tzinfo=timezone.utc)
    assert all({k.lower(): v for k, v in h.items()}.get("private-token") == "glpat" for _, h in a.seen)


def test_azure_devops_projects_continuation_and_repos(api):
    def projects(path, base):
        if "continuationToken=next1" in path:
            return 200, {"value": [{"name": "Beta Project"}]}, {}
        return 200, {"value": [{"name": "Alpha"}]}, {"x-ms-continuationtoken": "next1"}

    def repos(proj):
        return lambda path, base: (200, {"value": [
            {"name": f"{proj}-repo", "id": f"id-{proj}", "defaultBranch": "refs/heads/main", "size": 10,
             "remoteUrl": f"https://contoso@dev.azure.com/contoso/{proj}/_git/{proj}-repo", "webUrl": "w"},
            {"name": "disabled", "id": "x", "isDisabled": True, "remoteUrl": "https://dev.azure.com/c/p/_git/d"},
            {"name": "empty", "id": "y", "remoteUrl": "https://dev.azure.com/c/p/_git/e"}]}, {})

    def commits(path, base):
        assert "searchCriteria.itemVersion.version=main" in path
        return 200, {"value": [{"committer": {"date": "2026-03-01T10:00:00.1234567Z"}}]}, {}
    a = api([("/contoso/_apis/projects", projects), ("/contoso/Alpha/_apis/git/repositories/id-Alpha/commits", commits),
             ("/contoso/Alpha/_apis/git/repositories", repos("Alpha")),
             ("/contoso/Beta%20Project/_apis/git/repositories", repos("Beta"))])
    p = provider("azure-devops", "contoso", "pat", a.url)
    got = list(p.repos())
    assert [(r.project, r.name, r.archived, r.empty) for r in got] == [
        ("Alpha", "Alpha-repo", False, False), ("Alpha", "disabled", True, True), ("Alpha", "empty", False, True),
        ("Beta Project", "Beta-repo", False, False), ("Beta Project", "disabled", True, True),
        ("Beta Project", "empty", False, True)]
    assert got[0].clone_url == "https://dev.azure.com/contoso/Alpha/_git/Alpha-repo"      # no user info
    assert got[0].default_branch == "main"
    assert p.last_commit(got[0]) == datetime(2026, 3, 1, 10, 0, 0, 123456, tzinfo=timezone.utc)
    auth = "Basic " + base64.b64encode(b":pat").decode()
    assert all(h.get("Authorization") == auth for _, h in a.seen)


def test_http_errors_are_redacted(api):
    a = api([("/orgs/acme/repos", lambda p, b: (401, {"message": "bad credentials sekrit-token-1"}, {}))])
    with pytest.raises(orgsource.SourceError) as e:
        list(provider("github", "acme", "sekrit-token-1", a.url).repos())
    assert "sekrit-token-1" not in str(e.value) and "401" in str(e.value)


# --------------------------------------------------------------------------- git and secrets

def test_git_header_is_scoped_to_host_and_only_in_env():
    env = git_env("https://dev.azure.com/contoso/p/_git/r", "Authorization: Basic abc")
    n = int(env["GIT_CONFIG_COUNT"]) - 1
    assert env[f"GIT_CONFIG_KEY_{n}"] == "http.https://dev.azure.com/.extraHeader"
    assert env[f"GIT_CONFIG_VALUE_{n}"] == "Authorization: Basic abc"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    ssh = git_env("git@ssh.example:x.git", "Authorization: x")
    assert "Authorization: x" not in ssh.values()


def test_redactor_hides_plain_and_basic_forms():
    r = Redactor()
    r.add("tok-abcdef", "x-access-token")
    b = base64.b64encode(b"x-access-token:tok-abcdef").decode()
    assert r(f"fatal: tok-abcdef {b}") == "fatal: *** ***"


def test_strip_userinfo():
    assert orgsource.strip_userinfo("https://u:p@host/x.git") == "https://host/x.git"
    assert orgsource.strip_userinfo("git@host:x.git") == "git@host:x.git"


def test_existing_dockerfiles(tmp_path):
    for f in ["src/Api/Dockerfile", "deploy/api.Dockerfile", "Containerfile", "x/Dockerfile.prod",
              "node_modules/pkg/Dockerfile", "Dockerfile.dockerignore", "docs/dockerfile-notes.md"]:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("FROM scratch\n")
    assert existing_dockerfiles(tmp_path) == ["Containerfile", "deploy/api.Dockerfile", "src/Api/Dockerfile",
                                              "x/Dockerfile.prod"]


# --------------------------------------------------------------------------- naming

def test_segments_and_app_names():
    assert segment("Beta Project") == "Beta Project"
    assert segment("../evil") == "--evil"
    assert segment("a:b*c") == "a_b_c"
    assert app_name(NO_PROJECT, "Parts.Catalog") == "parts-catalog"
    assert app_name("Beta Project", "Api_Svc") == "beta-project-api-svc"
    assert app_name(NO_PROJECT, "default") == "app-default"
    assert app_name(NO_PROJECT, "kube-tools") == "app-kube-tools"
    long = app_name("p" * 40, "r" * 40)
    assert len(long) <= 63 and long != app_name("p" * 40, "r" * 41)


def test_unique_names_on_collision():
    rs = [SourceRepo("gitlab", "g", "a-b", "c", ""), SourceRepo("gitlab", "g", "a", "b-c", ""),
          SourceRepo("gitlab", "g", NO_PROJECT, "solo", "")]
    n = unique_names(rs)
    assert n["a-b/c"] != n["a/b-c"] and n["a-b/c"].startswith("a-b-c-") and n["_/solo"] == "solo"


def test_default_tag_is_semver():
    assert default_tag(datetime(2026, 10, 31, 7, 5, tzinfo=timezone.utc)) == "1.20261031.705"
    assert default_tag(datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)) == "1.20260102.0"


# --------------------------------------------------------------------------- selection

def test_select_components_requires_a_and_confirmed_run():
    a = assess(DEMO, load_rules())
    a.verification = []
    keep, exc = select_components(a, verified=False)
    assert [c.name for c in keep] == ["Demo.Web"] and exc == []
    keep, exc = select_components(a, verified=True)
    assert keep == [] and "not run" in exc[0]["reason"]
    a.verification = [{"component": "Demo.Web", "status": "run-failed"}]
    assert select_components(a, verified=True)[0] == []
    a.verification = [{"component": "Demo.Web", "status": "ok-external"}]
    assert [c.name for c in select_components(a, verified=True)[0]] == ["Demo.Web"]


def test_select_components_honours_stateless_flag(monkeypatch):
    a = assess(DEMO, load_rules())
    monkeypatch.setattr(type(a.components[0]), "stateless", property(lambda self: False), raising=False)
    keep, exc = select_components(a, verified=False)
    assert keep == [] and exc == [{"component": "Demo.Web", "reason": "keeps local state"}]


def test_component_rating_is_per_component():
    a = assess(ROOT / "examples" / "ci-demo", load_rules())
    assert orgmod.component_rating(a, a.components[0]) == "A"


# --------------------------------------------------------------------------- pull secret patch

def test_pull_secret_patch_keeps_image_markers(tmp_path):
    k = tmp_path / "kustomization.yaml"
    k.write_text("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- a/k8s.yaml\n"
                 'images:\n  - name: r/x/a\n    newTag: 1.0.0 # {"$imagepolicy": "x:a:tag"}\n')
    add_pull_secret(k, "regcred")
    text = k.read_text()
    assert '{"$imagepolicy": "x:a:tag"}' in text
    doc = yaml.safe_load(text)
    kinds = {p["target"]["kind"]: yaml.safe_load(p["patch"])[0] for p in doc["patches"]}
    assert kinds["CronJob"]["path"] == "/spec/jobTemplate/spec/template/spec/imagePullSecrets"
    assert kinds["Deployment"]["value"] == [{"name": "regcred"}]


# --------------------------------------------------------------------------- whole run, no docker

def _commit(path: Path, date: str | None = None):
    env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date} if date else {}
    import os
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"], cwd=path, check=True,
                   env={**os.environ, **env})


class _FakeProvider:
    def __init__(self, repos):
        self._repos = repos

    def repos(self):
        return iter(self._repos)

    def last_commit(self, r):
        return None

    def git_header(self):
        return ""


def test_run_org_writes_layout_sandbox_and_commits(tmp_path, monkeypatch):
    sources = {}
    for name, df, date in [("ci-demo", False, None), ("dockerized", True, None),
                           ("old", False, "2025-01-01T00:00:00Z")]:
        d = tmp_path / "src" / name
        shutil.copytree(DEMO, d)
        if df:
            (d / "src" / "Dockerfile").write_text("FROM scratch\n")
        _commit(d, date)
        sources[name] = d
    repos = [SourceRepo("azure-devops", "Contoso", "Shop Floor", n, f"https://dev.azure.com/c/p/_git/{n}",
                        default_branch="main", web_url=f"https://dev.azure.com/c/p/_git/{n}") for n in sources]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    monkeypatch.setattr(orgmod, "clone", lambda url, dest, branch="", header="", depth=1:
                        shutil.copytree(sources[url.rsplit("/", 1)[1]], dest))
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=out, check=True)
    # a component from an earlier run of the now-dockerized repo must disappear
    (out / "Contoso" / "Shop Floor" / "dockerized" / "old").mkdir(parents=True)
    (out / "Contoso" / "Shop Floor" / "dockerized" / "old" / "k8s.yaml").write_text("x: 1\n")
    o = OrgOptions(provider="azure-devops", org="Contoso", registry="reg.example/sandbox", output_dir=str(out),
                   verify=False, gate=False, push_images=False, image_pull_secret="regcred", tag="1.2.3",
                   work_dir=str(tmp_path / "work"), now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    assert res["ci-demo"].status == "deployed", res["ci-demo"]
    assert res["dockerized"].status == "skipped-dockerfile" and "src/Dockerfile" in res["dockerized"].reason
    assert res["old"].status == "skipped-stale"
    app = out / "Contoso" / "Shop Floor" / "ci-demo"
    assert (app / "demo-web" / "Dockerfile").exists() and (app / "demo-web" / "k8s.yaml").exists()
    assert not (out / "Contoso" / "Shop Floor" / "dockerized").exists()
    meta = json.loads((app / "containerizer.json").read_text())
    assert meta["app"] == "shop-floor-ci-demo"
    assert meta["components"][0]["image"] == "reg.example/sandbox/shop-floor-ci-demo/demo-web:1.2.3"
    k = (app / "kustomization.yaml").read_text()
    assert "newTag: 1.2.3" in k and "regcred" in k
    argo = yaml.safe_load((app / "gitops" / "argocd" / "application.yaml").read_text())
    assert argo["spec"]["source"]["path"] == "Contoso/Shop Floor/ci-demo"
    assert argo["metadata"]["name"] == "shop-floor-ci-demo"
    sb = out / "sandbox"
    assert yaml.safe_load((sb / "argocd" / "apps" / "kustomization.yaml").read_text())["resources"] == [
        "../../../Contoso/Shop Floor/ci-demo/gitops/argocd"]
    assert yaml.safe_load((sb / "flux" / "apps" / "kustomization.yaml").read_text())["resources"] == [
        "../../../Contoso/Shop Floor/ci-demo/gitops/flux"]
    assert (sb / "namespaces.txt").read_text() == "shop-floor-ci-demo\n"
    boot = list(yaml.safe_load_all((sb / "flux" / "bootstrap.yaml").read_text()))
    assert boot[1]["spec"]["path"] == "./sandbox/flux/apps"
    argo_boot = list(yaml.safe_load_all((sb / "argocd" / "bootstrap.yaml").read_text()))
    assert argo_boot[0]["spec"]["clusterResourceWhitelist"] == []
    index = json.loads((out / "Contoso" / "org-run.json").read_text())
    assert {r["repo"]: r["status"] for r in index["repositories"]} == {
        "ci-demo": "deployed", "dockerized": "skipped-dockerfile", "old": "skipped-stale"}
    assert "ci-demo" in (out / "Contoso" / "README.md").read_text()
    log = subprocess.run(["git", "log", "--format=%s"], cwd=out, capture_output=True, text=True).stdout
    assert "containerizer: Contoso/Shop Floor/ci-demo deployed" in log
    assert not list(app.rglob("*.log"))
    # nothing in the output carries a token or a work path
    for f in out.rglob("*"):
        if f.is_file() and ".git" not in f.parts:
            assert str(tmp_path / "work") not in f.read_text(errors="replace")
