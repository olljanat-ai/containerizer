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
from containerizer import progress
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

def test_git_header_is_scoped_to_the_repository_and_only_in_env(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")                    # nothing inherited survives
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "http.extraHeader")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "X-Leak: 1")
    env = git_env("https://u@dev.azure.com/contoso/p/_git/r/", "Authorization: Basic abc")
    keys = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert keys == {"credential.helper": "", "http.https://dev.azure.com/contoso/p/_git/r.extraHeader": "Authorization: Basic abc"}
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    # git itself: the header covers this repository only, not a sibling on the same host or a longer name
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    def match(url):
        return subprocess.run(["git", "config", "--get-urlmatch", "http.extraHeader", url], cwd=tmp_path, env=env,
                              capture_output=True, text=True).stdout.strip()
    assert match("https://dev.azure.com/contoso/p/_git/r/info/refs") == "Authorization: Basic abc"
    assert match("https://dev.azure.com/contoso/p/_git/r2/info/refs") == ""
    assert match("https://dev.azure.com/contoso/p/_git/sandbox/info/refs") == ""
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


def test_select_components_deploys_stateful_with_a_volume(monkeypatch):
    """Keeps its own data: rated A and deployed with a volume, one replica."""
    a = assess(DEMO, load_rules())
    cls = type(a.components[0])
    monkeypatch.setattr(cls, "stateless", property(lambda self: False), raising=False)
    monkeypatch.setattr(cls, "state_findings", property(lambda self: []), raising=False)
    assert orgmod.component_rating(a, a.components[0]) == "A" and orgmod.stateful_ready(a, a.components[0])
    keep, exc = select_components(a, verified=False)
    assert [c.name for c in keep] == ["Demo.Web"] and exc == []


def test_select_components_leaves_out_local_state_without_a_folder(monkeypatch):
    a = assess(DEMO, load_rules())
    cls = type(a.components[0])
    monkeypatch.setattr(cls, "stateless", property(lambda self: False), raising=False)
    monkeypatch.setattr(cls, "state_unplaced", property(lambda self: True), raising=False)
    assert orgmod.component_rating(a, a.components[0]) == "B"
    keep, exc = select_components(a, verified=False)
    assert keep == [] and exc[0]["reason"].startswith("keeps local state in a folder Containerizer could not find")


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


def test_run_org_deploys_java_and_node_repos(tmp_path, monkeypatch):
    from tests.test_java_node import EXPRESS, SERVER, WEB, boot_app, dep, node
    from tests.test_engine import write
    sources = {"orders": tmp_path / "src" / "orders", "api": tmp_path / "src" / "api", "docs": tmp_path / "src" / "docs"}
    boot_app(sources["orders"], WEB + dep("org.springframework.boot", "spring-boot-starter-actuator"))
    node(sources["api"], "", EXPRESS, {"server.js": SERVER})
    write(sources["api"], "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "api"}}}))
    write(sources["docs"], "README.md", "# docs only\n")
    for d in sources.values():
        _commit(d)
    repos = [SourceRepo("github", "acme", "", n, f"https://github.com/acme/{n}", default_branch="main",
                        web_url=f"https://github.com/acme/{n}") for n in sources]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    monkeypatch.setattr(orgmod, "clone", lambda url, dest, branch="", header="", depth=1:
                        shutil.copytree(sources[url.rsplit("/", 1)[1]], dest))
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=out, check=True)
    o = OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", output_dir=str(out), token="t",
                   verify=False, gate=False, push_images=False, tag="1.0.0", work_dir=str(tmp_path / "work"),
                   now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    assert res["orders"].status == "deployed", res["orders"]
    assert res["api"].status == "deployed", res["api"]
    assert res["docs"].status != "deployed"
    java = next((out).rglob("orders/**/Dockerfile")).read_text()
    assert "distroless/java17" in java and "USER 65532" in java
    nodedf = next((out).rglob("api/**/Dockerfile")).read_text()
    assert "distroless/nodejs" in nodedf and "npm ci" in nodedf
    k8s = next((out).rglob("orders/**/k8s.yaml")).read_text()
    assert "/actuator/health/readiness" in k8s


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
    repos = [SourceRepo("azure-devops", "Contoso", "Shop Floor", n, f"https://dev.azure.com/Contoso/Shop%20Floor/_git/{n}",
                        default_branch="main", web_url=f"https://dev.azure.com/Contoso/Shop%20Floor/_git/{n}") for n in sources]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    monkeypatch.setattr(orgmod, "clone", lambda url, dest, branch="", header="", depth=1:
                        shutil.copytree(sources[url.rsplit("/", 1)[1]], dest))
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=out, check=True)
    # a component from an earlier run of the now-dockerized repo must disappear
    (out / "Contoso" / "Shop Floor" / "dockerized" / "old").mkdir(parents=True)
    (out / "Contoso" / "Shop Floor" / "dockerized" / "old" / "k8s.yaml").write_text("x: 1\n")
    o = OrgOptions(provider="azure-devops", org="Contoso", registry="reg.example/sandbox", output_dir=str(out), token="pat",
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
    ks = next(d for d in yaml.safe_load_all((app / "gitops" / "flux" / "git" / "sync.yaml").read_text())
              if d and d["kind"] == "Kustomization")
    assert ks["spec"]["path"] == "./Contoso/Shop Floor/ci-demo" and ks["metadata"]["name"] == "shop-floor-ci-demo"
    assert not (app / "gitops" / "argocd").exists()            # Flux is the only GitOps tool
    sb = out / "sandbox"
    assert not (sb / "argocd").exists()
    assert yaml.safe_load((sb / "flux" / "apps" / "kustomization.yaml").read_text())["resources"] == [
        "../../../Contoso/Shop Floor/ci-demo/gitops/flux"]
    assert (sb / "namespaces.txt").read_text() == "shop-floor-ci-demo\n"
    boot = {d["kind"]: d for d in yaml.safe_load_all((sb / "flux" / "bootstrap.yaml").read_text())}
    assert boot["Kustomization"]["spec"]["path"] == "./sandbox/flux/apps"
    # the root Git credential comes from the secret store, readable only by flux-system's reader
    assert "Secret" not in boot
    assert boot["ExternalSecret"]["metadata"]["name"] == boot["GitRepository"]["spec"]["secretRef"]["name"]
    assert boot["ExternalSecret"]["spec"]["dataFrom"] == [{"extract": {"key": "flux-system--cz-git"}}]
    assert boot["Role"]["metadata"]["namespace"] == "containerizer-secrets"
    assert boot["Role"]["rules"][0]["resourceNames"] == ["flux-system--cz-git"]
    assert boot["RoleBinding"]["subjects"] == [{"kind": "ServiceAccount", "name": "app-secrets-reader",
                                                "namespace": "flux-system"}]
    # --image-pull-secret: an ExternalSecret of type dockerconfigjson, granted to the app's namespace
    pull = yaml.safe_load((app / "pull-secret.yaml").read_text())
    assert (pull["kind"], pull["metadata"]["name"]) == ("ExternalSecret", "regcred")
    assert pull["spec"]["target"]["template"]["type"] == "kubernetes.io/dockerconfigjson"
    assert "pull-secret.yaml" in yaml.safe_load(k)["resources"]
    tenant = list(yaml.safe_load_all((app / "gitops" / "flux" / "tenant.yaml").read_text()))
    role = next(d for d in tenant if d["kind"] == "Role")
    assert "shop-floor-ci-demo--cz-registry" in role["rules"][0]["resourceNames"]
    assert not [d for f in app.rglob("*.yaml") for d in yaml.safe_load_all(f.read_text())
                if isinstance(d, dict) and d.get("kind") == "Secret"]
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


# --------------------------------------------------------------------------- clone cache, no-code skip, overrides

def _git(path, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=path, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_update_clone_clones_then_pulls(tmp_path, monkeypatch):
    # a local "remote"; the file transport is refused for real runs, allow it for this test only
    monkeypatch.setattr(orgsource, "SAFE_CLONE", [a.replace("protocol.file.allow=never", "protocol.file.allow=always")
                                                  for a in orgsource.SAFE_CLONE])
    remote = tmp_path / "remote"
    remote.mkdir()
    (remote / "a.txt").write_text("1\n")
    _commit(remote)
    url = remote.as_uri()
    dest = tmp_path / "cache" / "app"
    assert orgsource.update_clone(url, dest, "main") == "cloned"
    first = _git(dest, "rev-parse", "HEAD")
    (remote / "a.txt").write_text("2\n")
    _git(remote, "commit", "-qam", "two")
    # local changes and build output in the cache are thrown away
    (dest / "a.txt").write_text("local edit\n")
    (dest / "bin").mkdir()
    (dest / "bin" / "out.dll").write_text("x")
    assert orgsource.update_clone(url, dest, "main") == "pulled"
    assert _git(dest, "rev-parse", "HEAD") == _git(remote, "rev-parse", "HEAD") != first
    assert (dest / "a.txt").read_text() == "2\n" and not (dest / "bin").exists()
    assert _git(dest, "rev-parse", "--is-shallow-repository") == "true"
    # a failing fetch keeps the clone; a broken one is cloned again, and kept until the new clone worked
    with pytest.raises(orgsource.SourceError):
        orgsource.update_clone((tmp_path / "missing").as_uri(), dest, "main")
    assert (dest / "a.txt").read_text() == "2\n"
    (dest / ".git" / "HEAD").write_text("garbage\n")
    with pytest.raises(orgsource.SourceError):
        orgsource.update_clone((tmp_path / "missing").as_uri(), dest, "main")
    assert (dest / "a.txt").exists() and not (tmp_path / "cache" / "app.cloning").exists()
    assert orgsource.update_clone(url, dest, "main") == "cloned"
    assert (dest / "a.txt").read_text() == "2\n"


def test_no_code_reasons(tmp_path):
    docs = tmp_path / "docs"
    (docs / "guide").mkdir(parents=True)
    for f in ("README.md", "guide/a.md", "guide/b.md", "pipeline.yml"):
        (docs / f).write_text("# x\n")
    assert orgmod.no_code_reason(docs) == ("skipped-no-code", "4 files (.md 3, .yml 1), no source code")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "fix.sql").write_text("select 1")
    (scripts / "deploy.sh").write_text("echo")
    assert orgmod.no_code_reason(scripts) == ("skipped-no-code", "2 files (.sh 1, .sql 1), no source code")
    ruby = tmp_path / "ruby"
    (ruby / "app").mkdir(parents=True)
    for f in ("app/a.rb", "app/b.rb", "app/view.erb", "Gemfile"):
        (ruby / f).write_text("x")
    st, why = orgmod.no_code_reason(ruby)
    assert st == "skipped-unsupported" and why.startswith("Ruby (3 files), but no project the tool can build")
    assert why.endswith("4 files (.rb 2, (no extension) 1, .erb 1)")
    lib = tmp_path / "lib"
    (lib / "src" / "Lib").mkdir(parents=True)
    (lib / "src" / "Lib" / "Lib.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
        '<OutputType>Library</OutputType></PropertyGroup></Project>')
    (lib / "src" / "Lib" / "Class1.cs").write_text("namespace Lib; public class C { }")
    assert orgmod.no_code_reason(lib) == ("skipped-no-app", "only library: 1 project, nothing that runs on its own")
    assert orgmod.no_code_reason(DEMO) == ("", "")


def test_host_allow_list():
    allowed = {"github.com", "*.visualstudio.com"}
    assert orgmod.host_allowed("https://github.com/a/b.git", allowed)
    assert orgmod.host_allowed("https://contoso.visualstudio.com/p/_git/r", allowed)
    assert not orgmod.host_allowed("https://github.com.evil.example/a", allowed)
    assert not orgmod.host_allowed("https://evilvisualstudio.com/x", allowed)
    assert orgmod.host_allowed("https://anything", None)


def test_cache_folder_must_be_ours(tmp_path):
    o = OrgOptions(provider="github", org="acme", registry="r", cache_dir=str(tmp_path / "c"))
    c = orgmod.prepare_cache(o)
    assert (c / orgmod.CACHE_MARK).exists()
    assert orgmod.prepare_cache(o) == c
    with pytest.raises(orgsource.SourceError, match="one cache folder per organization"):
        orgmod.prepare_cache(OrgOptions(provider="github", org="other", registry="r", cache_dir=str(c)))
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "notes.txt").write_text("mine")
    with pytest.raises(orgsource.SourceError, match="not a containerizer clone cache"):
        orgmod.prepare_cache(OrgOptions(provider="github", org="acme", registry="r", cache_dir=str(tmp_path / "home")))


class _State:
    def __init__(self, admin):
        self.admin, self.synced, self.recorded = admin, None, {}

    def sync(self, repos, names):
        self.synced = [r.key for r in repos]
        return self.admin

    def record(self, r, res):
        self.recorded[r.name] = res


class _Hooks:
    def __init__(self, stop_after=None):
        self.events, self.stop_after = [], stop_after

    def start(self, total):
        self.events.append(("start", total))

    def repo_start(self, i, r):
        self.events.append(("repo", r.name))

    def repo_done(self, i, r, res):
        self.events.append(("done", r.name, res.status))

    def repo_step(self, r, kind, text):
        self.events.append((kind, r.name, text))

    def phase(self, text):
        self.events.append(("phase", text))

    def steps(self, name):
        return [e[2] for e in self.events if e[0] == "step" and e[1] == name]

    def git(self, op, seconds, ok):
        self.events.append(("git", op, ok))

    def should_stop(self):
        return self.stop_after is not None and sum(e[0] == "done" for e in self.events) >= self.stop_after


def test_run_org_with_cache_state_and_overrides(tmp_path, monkeypatch):
    sources = {}
    for name in ("web", "dockerized", "docs", "off", "skipme", "readme"):
        d = tmp_path / "src" / name
        if name in ("docs", "readme"):
            d.mkdir(parents=True)
            (d / "README.md").write_text("# docs only\n")
        else:
            shutil.copytree(DEMO, d)
        if name == "dockerized":
            (d / "Dockerfile").write_text("FROM scratch\n")
        _commit(d)
        sources[name] = d
    repos = [SourceRepo("github", "acme", NO_PROJECT, n, f"https://github.com/acme/{n}.git", default_branch="main",
                        id=str(i)) for i, n in enumerate(sources)]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    pulls = []

    def fake_update(url, dest, branch="", header=""):
        name = url.rsplit("/", 1)[1].removesuffix(".git")
        if dest.exists():
            pulls.append(name)
            return "pulled"
        shutil.copytree(sources[name], dest)
        return "cloned"
    monkeypatch.setattr(orgmod, "update_clone", fake_update)
    cache = tmp_path / "cache"
    state = _State({"_/dockerized": "enabled", "_/off": "disabled", "_/readme": "enabled"})
    hooks = _Hooks()
    o = OrgOptions(provider="github", org="acme", registry="reg.example/sb", output_dir=str(tmp_path / "out"), token="t",
                   verify=False, gate=False, push_images=False, tag="1.0.0", work_dir=str(tmp_path / "work"),
                   cache_dir=str(cache), exclude="skipme", state=state, hooks=hooks,
                   allowed_hosts={"github.com"}, now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    assert state.synced == ["_/web", "_/dockerized", "_/docs", "_/off", "_/skipme", "_/readme"]
    assert res["web"].status == "deployed"
    # enabled by an administrator: processed although it has a Dockerfile, and the skip is reported
    assert res["dockerized"].status == "deployed"
    assert res["dockerized"].overridden == [{"status": "skipped-dockerfile", "reason": "found Dockerfile"}]
    assert res["docs"].status == "skipped-no-code" and "no source code" in res["docs"].reason
    # disabled: left out of the run before it starts (not in its results or progress), recorded as not processed
    assert "off" not in res and "skipme" not in res
    assert state.recorded["off"].status == "disabled" and state.recorded["off"].reason == "disabled by an administrator"
    # enabled although it has no code: analyzed, nothing to deploy
    assert res["readme"].status == "no-a-components" and res["readme"].overridden[0]["status"] == "skipped-no-code"
    assert state.recorded["skipme"].status == "skipped-filter"
    assert set(state.recorded) == {"web", "dockerized", "docs", "off", "skipme", "readme"}
    assert ("start", 4) in hooks.events and ("git", "clone", True) in hooks.events
    # the progress page: each repository's steps as it goes, and the run's phases
    assert hooks.steps("web") == [progress.CLONE, progress.CODE, progress.ASSESS, progress.REASSESS,
                                  progress.GENERATE, progress.DEVDB, progress.GENERATE, progress.OUTPUT]
    assert hooks.steps("docs") == [progress.CLONE, progress.CODE]
    assert ("phase", "Listing the repositories") in hooks.events and ("phase", "Scanning the repositories") in hooks.events
    assert ("phase", "Committing web to the output repository") in hooks.events
    i = hooks.events.index(("repo", "web"))
    assert hooks.events[i + 1] == ("step", "web", progress.CLONE)       # after repo_start, before its result
    assert not (cache / "off").exists()                 # disabled: never fetched
    assert (cache / "web").is_dir() and (cache / orgmod.CACHE_MARK).exists()
    # second run: clones are pulled, not cloned again; a repository that left the organization loses its clone
    repos.pop(0)
    run_org(o, log=lambda *a, **k: None)
    assert sorted(pulls) == ["dockerized", "docs", "readme"] and not (cache / "web").exists()
    # a stop request ends the run between repositories, and nothing is pruned
    hooks2 = _Hooks(stop_after=1)
    o.hooks = hooks2
    out = run_org(o, log=lambda *a, **k: None)
    assert len(out) == 1


def test_run_org_in_parallel_processes(tmp_path, monkeypatch):
    """Several repositories at a time, each in its own process: the same results as one at a time, the output
    folders in place, the git operations and LLM usage reported back to the run, and a stop request honoured."""
    sources = {}
    for name in ("web", "api", "docs", "shop", "off"):
        d = tmp_path / "src" / name
        if name == "docs":
            d.mkdir(parents=True)
            (d / "README.md").write_text("# docs only\n")
        else:
            shutil.copytree(DEMO, d)
        _commit(d)
        sources[name] = d
    repos = [SourceRepo("github", "acme", NO_PROJECT, n, f"https://github.com/acme/{n}.git", default_branch="main",
                        id=str(i)) for i, n in enumerate(sources)]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))

    def fake_update(url, dest, branch="", header=""):
        name = url.rsplit("/", 1)[1].removesuffix(".git")
        if dest.exists():
            return "pulled"
        shutil.copytree(sources[name], dest)
        return "cloned"
    monkeypatch.setattr(orgmod, "update_clone", fake_update)
    state, hooks = _State({"_/off": "disabled"}), _Hooks()
    out = tmp_path / "out"
    o = OrgOptions(provider="github", org="acme", registry="reg.example/sb", output_dir=str(out), token="t",
                   verify=False, gate=False, push_images=False, tag="1.0.0", work_dir=str(tmp_path / "work"),
                   cache_dir=str(tmp_path / "cache"), state=state, hooks=hooks, parallel=3,
                   allowed_hosts={"github.com"}, now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    logs = []
    res = {r.repo: r for r in run_org(o, log=logs.append)}
    assert "acme: 3 repositories at a time" in logs
    assert {k: v.status for k, v in res.items()} == {"web": "deployed", "api": "deployed", "shop": "deployed",
                                                    "docs": "skipped-no-code"}
    assert set(state.recorded) == {"web", "api", "shop", "docs", "off"} and res["web"].seconds > 0
    for n in ("web", "api", "shop"):
        assert (out / "acme" / "_" / n / "containerizer.json").is_file()
    assert not (out / "acme" / "_" / "docs").exists()
    assert sorted(e[1] for e in hooks.events if e[0] == "done") == ["api", "docs", "shop", "web"]
    assert sum(e == ("git", "clone", True) for e in hooks.events) == 4        # reported back from the processes
    for n in ("web", "api", "shop"):                                          # the steps too, as they happen
        steps = hooks.steps(n)
        assert steps[0] == progress.CLONE and steps[-1] == progress.OUTPUT and progress.ASSESS in steps, steps
        assert hooks.events.index(("step", n, progress.CLONE)) < hooks.events.index(("done", n, "deployed"))
    assert not (tmp_path / "work" / "parallel").exists() or not any((tmp_path / "work" / "parallel").iterdir())
    index = json.loads((out / "acme" / "index.json").read_text()) if (out / "acme" / "index.json").exists() else None
    if index is not None:
        assert len(index.get("repositories", index.get("results", []))) == 4
    # the second run updates the folders in place (the staged copy starts from them)
    (out / "acme" / "_" / "web" / "keep.txt").write_text("x")
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    assert res["web"].status == "deployed" and (out / "acme" / "_" / "web" / "containerizer.json").is_file()
    # a stop request: nothing more starts, the ones running finish
    o.hooks = _Hooks(stop_after=1)
    o.parallel = 2
    done = run_org(o, log=lambda *a, **k: None)
    assert 1 <= len(done) <= 3 and len(done) < 4


def test_disallowed_clone_host_is_an_error(tmp_path, monkeypatch):
    repos = [SourceRepo("github", "acme", NO_PROJECT, "x", "https://evil.example/acme/x.git", default_branch="main")]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    monkeypatch.setattr(orgmod, "update_clone", lambda *a, **k: pytest.fail("must not clone"))
    o = OrgOptions(provider="github", org="acme", registry="r", output_dir=str(tmp_path / "out"), push_images=False,
                   token="t", work_dir=str(tmp_path / "w"), cache_dir=str(tmp_path / "c"), allowed_hosts={"github.com"})
    [r] = run_org(o, log=lambda *a, **k: None)
    assert r.status == "error" and "outside the organization acme" in r.reason


def test_github_last_commit_on_the_default_branch(api):
    def commits(path, base):
        assert "sha=dev" in path and "per_page=1" in path
        return 200, [{"commit": {"committer": {"date": "2025-12-24T18:00:00Z"}}}], {}
    a = api([("/repos/acme/svc/commits", commits)])
    p = provider("github", "acme", "tok", a.url)
    r = SourceRepo("github", "acme", NO_PROJECT, "svc", "https://github.com/acme/svc.git", default_branch="dev",
                   extra={"full_name": "acme/svc"})
    assert p.last_commit(r) == datetime(2025, 12, 24, 18, 0, tzinfo=timezone.utc)


def test_discover_org_lists_without_cloning(monkeypatch, tmp_path):
    """Discovery: every repository with its latest commit from the API and the skips the API alone shows;
    nothing is cloned, the output repository is not touched, an administrator's decisions are kept."""
    def repo(proj, n, **kw):
        return SourceRepo("azure-devops", "contoso", proj, n, f"https://dev.azure.com/contoso/{proj}/_git/{n}",
                          default_branch="main", **kw)
    repos = [repo("A", "fresh"), repo("A", "old"), repo("A", "gone", archived=True), repo("A", "blank", empty=True),
             repo("B", "fork", fork=True), repo("B", "sandbox"), repo("C", "off"), repo("A", "broken")]
    dates = {"A/fresh": datetime(2026, 10, 1, tzinfo=timezone.utc), "A/old": datetime(2020, 1, 1, tzinfo=timezone.utc)}

    class Prov(_FakeProvider):
        asked = []

        def last_commit(self, r):
            self.asked.append(r.key)
            if r.name == "broken":
                raise orgsource.SourceError("HTTP 500")
            return dates.get(r.key)
    prov = Prov(repos)
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: prov)
    monkeypatch.setattr(orgmod, "update_clone", lambda *a, **k: pytest.fail("discovery must not clone"))
    monkeypatch.setattr(orgmod, "clone", lambda *a, **k: pytest.fail("discovery must not clone"))

    class State:
        seen = []

        def sync(self, listed, names):
            return {"C/off": "project-disabled"}

        def discovered(self, d):
            self.seen.append(d)
    st = State()
    o = OrgOptions(provider="azure-devops", org="contoso", registry="r.example/x", token="t", skip_forks=True,
                   exclude="sandbox", state=st, now=datetime(2026, 11, 1, tzinfo=timezone.utc),
                   work_dir=str(tmp_path / "work"))
    found = {d.repo.key: d for d in orgmod.discover_org(o, log=lambda m: None)}
    assert len(st.seen) == len(repos) and not (tmp_path / "work").exists()
    assert found["A/fresh"].skip is None and found["A/fresh"].last_commit == dates["A/fresh"]
    assert found["A/old"].skip == ("skipped-stale", "last commit 2020-01-01")
    assert found["A/gone"].skip[0] == "skipped-archived" and found["A/blank"].skip[0] == "skipped-empty"
    assert found["B/fork"].skip[0] == "skipped-fork" and found["B/sandbox"].skip[0] == "skipped-filter"
    assert found["A/broken"].error and found["A/broken"].skip is None
    assert "C/off" not in prov.asked and "A/blank" not in prov.asked     # disabled and empty: no API call

    class Stop:
        def start(self, n):
            self.n = n

        def should_stop(self):
            return True
    o.hooks = Stop()
    st.seen.clear()
    assert orgmod.discover_org(o, log=lambda m: None) == [] and st.seen == []


def test_split_helpers(tmp_path):
    for d in ("scenarios/billing/src", "scenarios/claims", "scenarios/crm", "docs", ".git/x"):
        (tmp_path / d).mkdir(parents=True)
    for d in ("scenarios/billing", "scenarios/claims", "scenarios/crm"):
        (tmp_path / d / "App.sln").write_text("")
    (tmp_path / "scenarios/billing/src/Api.csproj").write_text("")
    assert orgmod.suggest_split(tmp_path) == {"pattern": "scenarios/*", "count": 3}
    assert orgmod.split_folders(tmp_path, "scenarios/*") == ["scenarios/billing", "scenarios/claims", "scenarios/crm"]
    assert orgmod.split_folders(tmp_path, "*") == ["docs", "scenarios"]                 # hidden folders never
    for bad in ("../x", "a/../b", "/etc/*", "", "x" * 201, "a;b"):
        assert not orgmod.valid_split(bad) and orgmod.split_folders(tmp_path, bad) == []
    # one application with several projects: one root, no hint
    single = tmp_path / "single"
    for d in ("src/Api", "src/Web", "src/Worker"):
        (single / d).mkdir(parents=True)
        (single / d / "x.csproj").write_text("")
    (single / "App.sln").write_text("")
    assert orgmod.suggest_split(single) == {}
    assert orgmod.folder_segments(["a/x", "b/x", "c/y"]) == {"a/x": "a--x", "b/x": "b--x", "c/y": "y"}
    assert orgmod.split_app_name("challenge", "account-statements") == "challenge-account-statements"
    assert len(orgmod.split_app_name("a" * 60, "b" * 30)) <= 63


@pytest.mark.parametrize("parallel", [1, 2])
def test_run_org_split_repository(tmp_path, monkeypatch, parallel):
    """A mono-repo split into applications: each folder is assessed and deployed as its own application (its own
    output folder <repo>@<folder>, namespace <app>-<folder>, results), the repository's result sums them up, and
    going back to the whole repository removes the per-folder folders."""
    mono = tmp_path / "src" / "mono"
    for n in ("orders", "billing"):
        shutil.copytree(DEMO, mono / "apps" / n)
    (mono / "apps" / "handbook").mkdir(parents=True)
    (mono / "apps" / "handbook" / "README.md").write_text("# no code\n")
    _commit(mono)
    repos = [SourceRepo("github", "acme", NO_PROJECT, "mono", "https://github.com/acme/mono.git", default_branch="main",
                        id="1"), SourceRepo("github", "acme", NO_PROJECT, "solo", "https://github.com/acme/solo.git",
                                            default_branch="main", id="2")]
    solo = tmp_path / "src" / "solo"
    shutil.copytree(DEMO, solo)
    _commit(solo)
    sources = {"mono": mono, "solo": solo}
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))

    def fake_update(url, dest, branch="", header=""):
        name = url.rsplit("/", 1)[1].removesuffix(".git")
        if dest.exists():
            return "pulled"
        shutil.copytree(sources[name], dest)
        return "cloned"
    monkeypatch.setattr(orgmod, "update_clone", fake_update)
    out = tmp_path / "out"
    o = OrgOptions(provider="github", org="acme", registry="reg.example/sb", output_dir=str(out), token="t",
                   verify=False, gate=False, push_images=False, tag="1.0.0", work_dir=str(tmp_path / "work"),
                   cache_dir=str(tmp_path / "cache"), splits={"_/mono": "apps/*"}, parallel=parallel,
                   allowed_hosts={"github.com"}, now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    mono_res = res["mono"]
    assert mono_res.status == "deployed" and mono_res.rating == "A", mono_res
    apps = {x["folder"]: x for x in mono_res.apps}
    assert set(apps) == {"apps/billing", "apps/handbook", "apps/orders"}
    assert apps["apps/orders"]["status"] == "deployed" and apps["apps/orders"]["path"] == "acme/_/mono@orders"
    assert apps["apps/handbook"]["status"].startswith("skipped-")
    assert "3 applications (apps/*): 2 deployed" in mono_res.reason
    assert {c["application"] for c in mono_res.components} == {"apps/billing", "apps/orders"}
    for n in ("orders", "billing"):
        meta = json.loads((out / "acme" / "_" / f"mono@{n}" / "containerizer.json").read_text())
        assert meta["app"] == f"mono-{n}"
    assert not (out / "acme" / "_" / "mono").exists() and not (out / "acme" / "_" / "mono@handbook").exists()
    assert "../../../acme/_/mono@orders/gitops/flux" in (out / "sandbox" / "flux" / "apps" / "kustomization.yaml").read_text()
    assert res["solo"].status == "deployed" and not res["solo"].apps and (out / "acme" / "_" / "solo").is_dir()
    # back to one application: the per-folder folders go, the hint says what it looks like
    o.splits = None
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    assert res["mono"].status in ("deployed", "no-a-components") and not res["mono"].apps
    assert not list((out / "acme" / "_").glob("mono@*")) and (out / "acme" / "_" / "mono").is_dir() == \
        (res["mono"].status == "deployed")
    assert res["solo"].split_hint == {}


def test_the_sandbox_index_leaves_out_applications_whose_sandbox_is_off(tmp_path):
    """Admin → Applications → Sandbox off: the original's folder (by SourceKey) and its Make it A copies (by
    ApplicationId) stay in the output repository, out of sandbox/; on again lists the same folders."""
    import json as _json
    from containerizer import org
    root = tmp_path / "out"

    def app(rel, doc):
        d = root / rel
        (d / "gitops" / "flux").mkdir(parents=True)
        (d / "gitops" / "flux" / "kustomization.yaml").write_text("resources: []\\n")
        (d / "containerizer.json").write_text(_json.dumps(doc))
    app("acme/p/shop", {"source_key": "https://x/shop#"})
    app("acme/p/shop-refactor-7", {"source_key": "", "variant": {"application_id": 5, "job": 7}})
    app("acme/p/billing", {"source_key": "https://x/billing#"})

    def listed():
        return (root / "sandbox" / "flux" / "apps" / "kustomization.yaml").read_text()
    org.write_sandbox(root, "https://git/out", "main")
    assert "acme/p/shop/" in listed() and "shop-refactor-7" in listed()
    org.write_sandbox(root, "https://git/out", "main", {"https://x/shop#", 5})
    assert "acme/p/shop/" not in listed() and "shop-refactor-7" not in listed() and "acme/p/billing/" in listed()
    assert (root / "acme/p/shop/containerizer.json").exists() and (root / "acme/p/shop-refactor-7").is_dir()
    org.write_sandbox(root, "https://git/out", "main", set())
    assert "acme/p/shop/" in listed() and "shop-refactor-7" in listed()


def test_a_scan_of_an_application_whose_sandbox_is_off_builds_nothing_and_keeps_its_folder(tmp_path):
    from containerizer import org
    dest = tmp_path / "out" / "acme/p/shop"
    dest.mkdir(parents=True)
    (dest / "containerizer.json").write_text("{}")
    o = org.OrgOptions(provider="github", org="acme", registry="localhost:5000/sandbox", sandbox_off={"k"})
    res = org.RepoResult(provider="github", org="acme", project="p", repo="shop", status="error", source_key="k")

    class Out:
        root = tmp_path / "out"
    r = org.deploy_app(None, tmp_path, "acme/p/shop", o, Out(), None, "1", None, res, tmp_path / "w", "shop")
    assert (r.status, r.reason) == ("sandbox-off", org.SANDBOX_OFF_REASON) and (dest / "containerizer.json").exists()
    assert not org.sandbox_off(o, "other") and not org.sandbox_off(org.OrgOptions(provider="github", org="a", registry="r"), "k")


def test_output_repository_git_is_tried_again_after_an_outage_and_a_refused_token_is_said_plainly(monkeypatch):
    """A Make it A deploy failed with git's 'could not read Username ... terminal prompts disabled' (GitHub refused
    the token), and a push during a GitHub outage failed at once with '[remote rejected] (Internal Server Error)'."""
    from containerizer.orgsource import SourceError
    url = "https://github.com/acme/out.git"
    calls, slept, pulls = [], [], []

    def flaky(fails):
        def what():
            calls.append(1)
            if len(calls) <= fails:
                raise SourceError("git push: remote: Internal Server Error\n ! [remote rejected] HEAD -> main "
                                  "(Internal Server Error)")
            return "ok"
        return what
    assert orgmod._retry(url, flaky(2), sleep=slept.append, before_retry=lambda: pulls.append(1)) == "ok"
    assert slept == list(orgmod.OUTPUT_RETRY_PAUSES[:2]) and len(pulls) == 2
    calls.clear()
    with pytest.raises(SourceError):                     # it stays down: given up after the last pause
        orgmod._retry(url, flaky(99), sleep=lambda s: None)
    assert len(calls) == len(orgmod.OUTPUT_RETRY_PAUSES) + 1

    def refused():
        calls.append(1)
        raise SourceError("git clone: fatal: could not read Username for 'https://github.com': terminal prompts disabled")
    calls.clear()
    with pytest.raises(SourceError) as e:                # not tried again
        orgmod._retry(url, refused, sleep=slept.append)
    assert len(calls) == 1
    assert "github.com refused the write token for https://github.com/acme/out.git" in str(e.value)
    assert "Admin → Source control" in str(e.value)

    def other():
        raise SourceError("git clone: Remote branch main not found in upstream origin")
    with pytest.raises(SourceError) as e:                # another error: as it is, at once
        orgmod._retry(url, other, sleep=lambda s: pytest.fail("no pause"))
    assert "not found in upstream" in str(e.value)
    assert not orgmod.TRANSIENT_RE.search("git clone: timed out after 1800s")     # our own timeout is not tried again


@pytest.mark.parametrize("parallel", [1, 2])
def test_cancel_ends_repositories_in_progress(tmp_path, monkeypatch, parallel):
    """An administrator's cancel (hooks.should_abort) ends the repositories in progress at once, with the tools they
    started, and records nothing for them; the worker stopping (should_stop alone) lets them finish."""
    import os
    import subprocess as sp
    import time as _t
    pids = tmp_path / "pids"
    pids.mkdir()

    def slow(r, *a, **k):
        p = sp.Popen(["sleep", "60"])                  # a tool the scan started (git, docker build)
        (pids / r.name).write_text(str(p.pid))
        p.wait()
        return orgmod.RepoResult(provider=r.provider, org="acme", project=r.project, repo=r.name, status="deployed")
    monkeypatch.setattr(orgmod, "_repo_job", slow)
    repos = [SourceRepo("github", "acme", NO_PROJECT, n, f"https://github.com/acme/{n}.git", id=str(i))
             for i, n in enumerate(("one", "two", "three"))]

    class Hooks:
        def should_stop(self):
            return len(list(pids.iterdir())) >= parallel
        should_abort = should_stop
    o = OrgOptions(provider="github", org="acme", registry="r.example/x", token="t", hooks=Hooks(), parallel=parallel)
    finished = []
    t0 = _t.monotonic()
    stopped = orgmod._run_parallel(repos, parallel, o, None, None, tmp_path / "work", None, "1.0.0", None, False, {},
                                   {r.key: r.name for r in repos}, lambda *a: finished.append(a), lambda m: None)
    assert stopped and finished == [] and _t.monotonic() - t0 < 30
    assert len(list(pids.iterdir())) == parallel
    for f in pids.iterdir():                           # the tools are gone too
        pid = int(f.read_text())
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            _t.sleep(0.1)
        else:
            raise AssertionError(f"process {pid} of {f.name} still runs")
    assert not (tmp_path / "work" / "parallel" / "one").exists()
