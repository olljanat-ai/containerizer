"""Container image build pipelines for the application's own repository (pipelines.py, pipelineui.py)."""
import copy
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

from containerizer import pipelines as pl
from containerizer import refactor as rf
from containerizer.harden import security

ROOT = Path(__file__).resolve().parent.parent
CI_DEMO = ROOT / "examples" / "ci-demo"
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(repo, *args):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, check=True, capture_output=True,
                          text=True, env={**os.environ, **GIT_ENV}).stdout.strip()


def make_repo(path: Path, remote: str | None = "https://github.com/acme/shop.git", src: Path = CI_DEMO) -> Path:
    shutil.copytree(src, path)
    git(path, "init", "-q", "-b", "main")
    if remote:
        git(path, "remote", "add", "origin", remote)
    git(path, "add", "-A")
    git(path, "commit", "-qm", "initial")
    return path


def docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_docker = pytest.mark.skipif(not docker_ok(), reason="needs Docker")


# --------------------------------------------------------------------------- provider detection

@pytest.mark.parametrize("url,provider", [
    ("https://github.com/acme/shop", "github"),
    ("https://github.com/acme/shop.git", "github"),
    ("git@github.com:acme/shop.git", "github"),
    ("ssh://git@github.com/acme/shop.git", "github"),
    ("https://x-access-token:secret@github.com/acme/shop", "github"),
    ("https://acme.ghe.com/team/shop", "github"),                     # GitHub Enterprise Cloud (data residency)
    ("https://github.acme.example/team/shop", "github"),              # GitHub Enterprise Server
    ("https://ghe.acme.example/team/shop", "github"),
    ("https://gitlab.com/acme/group/shop", "gitlab"),
    ("git@gitlab.com:acme/shop.git", "gitlab"),
    ("https://gitlab.acme.example/team/shop.git", "gitlab"),          # GitLab self-managed
    ("ssh://git@gitlab.acme.example:2222/team/shop.git", "gitlab"),
    ("https://dev.azure.com/acme/Shop/_git/shop", "azure-devops"),
    ("https://acme@dev.azure.com/acme/Shop/_git/shop", "azure-devops"),
    ("git@ssh.dev.azure.com:v3/acme/Shop/shop", "azure-devops"),
    ("https://acme.visualstudio.com/Shop/_git/shop", "azure-devops"),
    ("acme@vs-ssh.visualstudio.com:v3/acme/Shop/shop", "azure-devops"),
    ("https://tfs.acme.example/tfs/DefaultCollection/Shop/_git/shop", "azure-devops"),   # TFS
    ("https://devops.acme.example/Collection/Shop/_git/shop", "azure-devops"),          # Azure DevOps Server
    ("https://code.acme.example/team/shop", None),
    ("https://bitbucket.org/acme/shop", None),
    ("", None),
    (None, None),
])
def test_provider_from_the_repository_url(url, provider):
    assert pl.detect_provider(url) == provider


def test_the_organization_scans_provider_wins_and_api_urls_help():
    # a self-hosted host that names no provider: the organization scan knows it
    assert pl.detect_provider("https://code.acme.example/team/shop", provider="gitlab") == "gitlab"
    assert pl.detect_provider("https://github.com/acme/shop", provider="azure-devops") == "azure-devops"
    assert pl.detect_provider(None, provider="github") == "github"
    assert pl.detect_provider("https://code.acme.example/team/shop", provider="nonsense") is None
    assert pl.detect_provider("https://code.acme.example/team/shop", api_url="https://code.acme.example/api/v4") == "gitlab"
    assert pl.detect_provider("https://code.acme.example/team/shop", api_url="https://code.acme.example/api/v3") == "github"
    assert pl.detect_provider("https://code.acme.example/team/shop", api_url="https://other.example/api/v4") is None


def test_severities_follow_the_gate():
    assert pl.severities("CRITICAL") == "CRITICAL"
    assert pl.severities("high") == "HIGH,CRITICAL"
    assert pl.severities("LOW") == "LOW,MEDIUM,HIGH,CRITICAL"
    assert pl.severities("bogus") == "CRITICAL"


def test_scanner_pins_are_the_security_rules_versions_with_their_digests():
    sec = security()
    trivy = next(s["image"] for s in sec["scan"]["scanners"] if s["name"] == "trivy")
    syft = sec["sbom"]["generator"]["image"]
    assert trivy in pl.DIGESTS and syft in pl.DIGESTS, "add the digest of a new scanner version to pipelines.DIGESTS"
    t, s = pl.scanner_images()
    assert t == f"{trivy}@{pl.DIGESTS[trivy]}" and s == f"{syft}@{pl.DIGESTS[syft]}"
    for image, digest in pl.DIGESTS.items():
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), image
    for action, (sha, tag) in pl.ACTIONS.items():
        assert re.fullmatch(r"[0-9a-f]{40}", sha) and tag.startswith("v"), action
    assert re.fullmatch(r"[0-9a-f]{64}", pl.COSIGN[1])


# --------------------------------------------------------------------------- the spec

SPEC = {"version": 1, "app": "Shop", "namespace": "shop", "registry": "", "subdir": "", "folder": "containerizer",
        "branch": "main", "repository_url": None, "detected": None, "gitlab_ci": False, "existing": [],
        "fail_on": "HIGH", "ignore_unfixed": True, "tlog": True,
        "components": [{"name": "Shop.Web", "folder": "shop-web", "project": "src/Web/Shop.Web.csproj",
                        "paths": ["src/Lib/", "src/Web/", "Directory.Build.props"], "dockerfile": "FROM scratch\n",
                        "dockerignore": "**/bin/\n"},
                       {"name": "Shop.Api", "folder": "shop-api", "project": "src/Api/Shop.Api.csproj",
                        "paths": ["src/Api/", "src/Lib/"], "dockerfile": "FROM scratch\n", "dockerignore": "**/bin/\n"}]}


def spec(**kw):
    s = copy.deepcopy(SPEC)
    s.update(kw)
    return s


def test_generate_records_the_spec_and_writes_the_pipeline_folder(tmp_path):
    from containerizer.assess import assess
    from containerizer.generate import generate_app, k8s_name
    from containerizer.rules import load_rules
    from containerizer.sqlstore import assessment_doc
    repo = make_repo(tmp_path / "shop")
    a = assess(repo, load_rules())
    out = tmp_path / "out"
    written = generate_app(a, out, registry="registry.example.com/team")
    sp = a.build_pipeline
    assert sp["detected"] == "github" and sp["registry"] == "registry.example.com/team" and sp["branch"] == "main"
    assert sp["subdir"] == "" and sp["repository_url"] == "https://github.com/acme/shop" and not sp["existing"]
    (c,) = sp["components"]
    assert c["folder"] == k8s_name(c["name"]) and c["paths"] == ["src/Demo.Web/"]
    assert c["dockerfile"] == (out / c["folder"] / "Dockerfile").read_text()
    gh = out / "pipeline" / "github"
    assert (gh / ".github/workflows/containerizer-images.yml") in written
    assert (gh / "containerizer" / c["folder"] / "Dockerfile").read_text() == c["dockerfile"]
    ign = (gh / "containerizer" / c["folder"] / "Dockerfile.dockerignore").read_text()
    assert ign.startswith((out / c["folder"] / "Dockerfile.dockerignore").read_text()) and ign.endswith("\ncontainerizer/\n")
    assert "copy the files of `github`" in (out / "pipeline" / "README.md").read_text()
    assert not (out / "pipeline" / "gitlab").exists()
    # the pipeline folder is not a component: not in the kustomization
    assert "pipeline" not in (out / "kustomization.yaml").read_text()
    # stored with the assessment for the results page
    assert assessment_doc(a)["build_pipeline"] == sp
    # the gate changed the Dockerfile: the copy follows
    (out / c["folder"] / "Dockerfile").write_text(c["dockerfile"] + "RUN apk upgrade --no-cache x\n")
    pl.refresh_dockerfiles(out)
    assert (gh / "containerizer" / c["folder"] / "Dockerfile").read_text().endswith("apk upgrade --no-cache x\n")


def test_unknown_provider_writes_all_three_and_a_subfolder_app_builds_from_its_folder(tmp_path):
    from containerizer.assess import assess
    from containerizer.generate import generate_app
    from containerizer.rules import load_rules
    top = tmp_path / "mono"
    shutil.copytree(CI_DEMO, top / "apps" / "shop")
    (top / ".gitlab-ci.yml").write_text("test:\n  script: [true]\n")
    git(top, "init", "-q", "-b", "trunk")
    git(top, "remote", "add", "origin", "https://code.acme.example/team/mono.git")
    git(top, "add", "-A")
    git(top, "commit", "-qm", "x")
    a = assess(top / "apps" / "shop", load_rules())
    out = tmp_path / "out"
    generate_app(a, out)
    sp = a.build_pipeline
    assert sp["detected"] is None and sp["subdir"] == "apps/shop" and sp["branch"] == "trunk" and sp["gitlab_ci"]
    assert sp["registry"] == ""                           # registry.local: not known
    assert sorted(p.name for p in (out / "pipeline").iterdir()) == ["README.md", "azure-devops", "github", "gitlab"]
    folder = sp["components"][0]["folder"]
    assert (out / "pipeline/gitlab/containerizer.gitlab-ci.yml").exists()    # the repository has a .gitlab-ci.yml
    assert not (out / "pipeline/gitlab/.gitlab-ci.yml").exists()
    assert (out / f"pipeline/azure-devops/apps/shop/containerizer/{folder}/Dockerfile").exists()
    wf = yaml.safe_load((out / "pipeline/github/.github/workflows/containerizer-images.yml").read_text())
    assert wf["on"]["push"]["branches"] == ["trunk"]
    assert f"apps/shop/src/Demo.Web/**" in wf["on"]["pull_request"]["paths"]
    gl = yaml.safe_load((out / "pipeline/gitlab/containerizer.gitlab-ci.yml").read_text())
    assert gl[f"containerizer:{folder}:check"]["variables"] == {
        "FOLDER": folder, "DOCKERFILE": f"apps/shop/containerizer/{folder}/Dockerfile", "CONTEXT": "apps/shop",
        "IMAGE_NAME": f"shop/{folder}"}


def test_component_paths_follow_project_references(tmp_path):
    from containerizer.assess import assess
    from containerizer.rules import load_rules
    app = tmp_path / "app"
    (app / "src" / "Lib").mkdir(parents=True)
    (app / "src" / "Lib" / "Lib.csproj").write_text(
        "<Project Sdk='Microsoft.NET.Sdk'><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
    (app / "src" / "Web").mkdir(parents=True)
    (app / "src" / "Web" / "Web.csproj").write_text(
        "<Project Sdk='Microsoft.NET.Sdk.Web'><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>"
        "<ItemGroup><ProjectReference Include='..\\Lib\\Lib.csproj' /></ItemGroup></Project>")
    (app / "src" / "Web" / "Program.cs").write_text("var app = WebApplication.Create(args); app.Run();\n")
    (app / "Directory.Build.props").write_text("<Project />")
    a = assess(app, load_rules())
    web = next(c for c in a.components if c.name == "Web")
    assert pl.component_paths(web, app, a.repo) == ["src/Lib/", "src/Web/", "Directory.Build.props"]


# --------------------------------------------------------------------------- GitHub Actions

def gh(sp, sign="none"):
    text = pl.files(sp, "github", sign)[pl.GITHUB_FILE]
    return text, yaml.safe_load(text)


def test_github_workflow_least_privilege_pins_and_paths():
    text, wf = gh(spec())
    assert wf["permissions"] == {}
    jobs = wf["jobs"]
    assert jobs["changes"]["permissions"] == {"contents": "read"} and jobs["check"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "read", "packages": "write"}     # GHCR by default
    assert "pull_request" in jobs["check"]["if"] and "!= 'pull_request'" in jobs["publish"]["if"]
    assert "default_branch" in jobs["publish"]["if"]
    # every action by full commit SHA, with its tag as a comment
    uses = re.findall(r"uses: (\S+)@(\S+)(.*)", text)
    assert uses and all(re.fullmatch(r"[0-9a-f]{40}", sha) and re.fullmatch(r" # v[\d.]+", c) for _, sha, c in uses)
    assert {u for u, _, _ in uses} == {"actions/checkout", "actions/upload-artifact"}
    for step in jobs["check"]["steps"] + jobs["publish"]["steps"]:
        if "checkout" in step.get("uses", ""):
            assert step["with"]["persist-credentials"] is False
    trivy, syft = pl.scanner_images()
    assert trivy in text and syft in text and "@sha256:" in trivy
    # nothing pushed or signed in pull requests; no secrets in the check job
    check = json.dumps(jobs["check"])
    assert "docker push" not in check and "secrets." not in check and "cosign" not in check
    assert "docker push" in json.dumps(jobs["publish"]) and "cosign" not in text
    # path filters: the union in the triggers, per component in the changes job
    assert wf["on"]["pull_request"]["paths"] == [
        "Directory.Build.props", "containerizer/shop-api/**", "containerizer/shop-web/**", "src/Api/**", "src/Lib/**",
        "src/Web/**", pl.GITHUB_FILE]
    assert wf["on"]["push"]["branches"] == ["main"]
    run = jobs["changes"]["steps"][1]["run"]
    assert "'^(src/Lib/|src/Web/|Directory\\.Build\\.props$|containerizer/shop-web/)'" in run
    assert "'^(src/Api/|src/Lib/|containerizer/shop-api/)'" in run
    assert jobs["check"]["env"]["TRIVY_SEVERITY"] == "${{ vars.CONTAINERIZER_TRIVY_SEVERITY || 'HIGH,CRITICAL' }}"
    login = next(s for s in jobs["publish"]["steps"] if s.get("name") == "Log in to the registry")
    assert 'REGISTRY="${CONTAINERIZER_REGISTRY:-ghcr.io/$OWNER}"' in login["run"]
    assert login["env"]["REGISTRY_USERNAME"] == "${{ secrets.CONTAINERIZER_REGISTRY_USERNAME }}"


def test_github_signing_and_an_external_registry():
    _, wf = gh(spec(), "keyless")
    pub = wf["jobs"]["publish"]
    assert pub["permissions"] == {"contents": "read", "packages": "write", "id-token": "write"}
    push = next(s for s in pub["steps"] if s.get("name", "").startswith("Push"))
    assert "/tmp/cosign sign --yes \"$DIGEST_REF\"" in push["run"] and "sha256sum -c -" in push["run"]
    assert "--type cyclonedx" in push["run"] and pl.COSIGN[1] in push["run"]
    assert "id-token" not in json.dumps(wf["jobs"]["check"])
    _, wf = gh(spec(registry="registry.example.com/team"), "key")
    pub = wf["jobs"]["publish"]
    assert pub["permissions"] == {"contents": "read"}             # no GHCR, no OIDC: nothing more
    push = next(s for s in pub["steps"] if s.get("name", "").startswith("Push"))
    assert "--key env://COSIGN_PRIVATE_KEY" in push["run"] and push["env"]["COSIGN_PRIVATE_KEY"] == "${{ secrets.COSIGN_PRIVATE_KEY }}"
    login = next(s for s in pub["steps"] if s.get("name") == "Log in to the registry")
    assert 'REGISTRY="${CONTAINERIZER_REGISTRY:-registry.example.com/team}"' in login["run"] and "OWNER" not in login["run"]
    _, wf = gh(spec(tlog=False), "key")
    assert "--tlog-upload=false" in json.dumps(wf["jobs"]["publish"])


def test_a_component_at_the_top_has_no_path_filter():
    sp = spec(components=[{**SPEC["components"][0], "paths": [""]}])
    _, wf = gh(sp)
    assert wf["on"]["pull_request"] is None and "paths" not in wf["on"]["push"]
    assert "if true; then" in wf["jobs"]["changes"]["steps"][1]["run"]


def _changes_run(repo: Path, run: str, base: str, event: str = "push") -> list[str]:
    out = repo / "gh_output"
    out.write_text("")
    env = {**os.environ, "EVENT": event, "BEFORE": base, "PR_BASE": base, "GITHUB_OUTPUT": str(out)}
    subprocess.run(["bash", "-c", run], cwd=repo, env=env, check=True, capture_output=True)
    vals = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert re.fullmatch(r"1\.\d{8}\.\d{1,4}", vals["version"])          # semver, as the scans' tags
    return [c["folder"] for c in json.loads(vals["components"])]


def test_the_changes_job_picks_the_components_whose_paths_changed(tmp_path):
    repo = tmp_path / "mono"
    for d in ("src/Web", "src/Api", "src/Lib", "docs"):
        (repo / d).mkdir(parents=True)
        (repo / d / "a.txt").write_text("1")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    run = gh(spec())[1]["jobs"]["changes"]["steps"][1]["run"]

    def change(*files):
        for f in files:
            (repo / f).parent.mkdir(parents=True, exist_ok=True)
            (repo / f).write_text(str(len(f)) + (repo / f).read_text() if (repo / f).exists() else "new")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "c")
        return git(repo, "rev-parse", "HEAD~1")

    assert _changes_run(repo, run, change("src/Api/a.txt")) == ["shop-api"]
    assert _changes_run(repo, run, change("src/Web/a.txt")) == ["shop-web"]
    assert _changes_run(repo, run, change("src/Lib/a.txt")) == ["shop-web", "shop-api"]      # both reference it
    assert _changes_run(repo, run, change("Directory.Build.props")) == ["shop-web"]
    assert _changes_run(repo, run, change("containerizer/shop-api/Dockerfile")) == ["shop-api"]
    assert _changes_run(repo, run, change("docs/a.txt")) == []
    assert _changes_run(repo, run, change("src/Apix/a.txt")) == []               # a folder, not a prefix of a name
    assert _changes_run(repo, run, change(pl.GITHUB_FILE)) == ["shop-web", "shop-api"]   # the workflow changed: all
    assert _changes_run(repo, run, "0" * 40) == ["shop-web", "shop-api"]            # a new branch: all
    assert _changes_run(repo, run, "", event="workflow_dispatch") == ["shop-web", "shop-api"]
    assert _changes_run(repo, run, base, event="pull_request") == ["shop-web", "shop-api"]


# --------------------------------------------------------------------------- GitLab CI/CD

def test_gitlab_jobs_rules_pins_and_tokens():
    files = pl.files(spec(), "gitlab", "keyless")
    text = files[".gitlab-ci.yml"]
    doc = yaml.safe_load(text)
    assert doc["stages"] == ["build"]
    base = doc[".containerizer-image"]
    assert base["image"] == f"{pl.DOCKER_CLI}@{pl.DIGESTS[pl.DOCKER_CLI]}"
    assert base["services"][0]["name"] == f"{pl.DOCKER_DIND}@{pl.DIGESTS[pl.DOCKER_DIND]}"
    assert base["variables"]["TRIVY_SEVERITY"] == "HIGH,CRITICAL" and base["variables"]["DOCKER_TLS_VERIFY"] == "1"
    assert "docker push" not in json.dumps(base) and "id_tokens" not in base
    pub = doc[".containerizer-publish"]
    assert pub["id_tokens"] == {"SIGSTORE_ID_TOKEN": {"aud": "sigstore"}}
    script = "\n".join(pub["script"])
    assert "$CI_REGISTRY_PASSWORD" in script and 'REGISTRY="${CONTAINERIZER_REGISTRY:-$CI_REGISTRY_IMAGE}"' in script
    assert "CI_PIPELINE_CREATED_AT" in script and "wget -qO /tmp/cosign" in script
    mr = doc["containerizer:shop-api:check"]
    assert mr["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"',
                            "changes": {"paths": ["src/Api/**/*", "src/Lib/**/*", "containerizer/shop-api/**/*",
                                                  ".gitlab-ci.yml"]}}]
    push = doc["containerizer:shop-web:publish"]
    assert all('$CI_COMMIT_REF_PROTECTED == "true"' in r["if"] and "$CI_DEFAULT_BRANCH" in r["if"] for r in push["rules"])
    assert push["variables"]["IMAGE_NAME"] == "shop/shop-web" and push["extends"] == ".containerizer-publish"
    # no signing: no OIDC token
    assert "id_tokens" not in pl.files(spec(), "gitlab")[".gitlab-ci.yml"]
    # an external registry: masked variables, the scan's registry by default
    doc = yaml.safe_load(pl.files(spec(registry="registry.example.com/team"), "gitlab", "key")[".gitlab-ci.yml"])
    script = "\n".join(doc[".containerizer-publish"]["script"])
    assert 'REGISTRY="${CONTAINERIZER_REGISTRY:-registry.example.com/team}"' in script
    assert '--key "$COSIGN_PRIVATE_KEY"' in script


def test_gitlab_with_an_existing_ci_file_is_an_include():
    files = pl.files(spec(gitlab_ci=True), "gitlab")
    assert ".gitlab-ci.yml" not in files and pl.GITLAB_INCLUDE_FILE in files
    text = files[pl.GITLAB_INCLUDE_FILE]
    doc = yaml.safe_load(text)
    assert "stages" not in doc and "include: [{local: containerizer.gitlab-ci.yml}]" in text
    assert pl.GITLAB_INCLUDE_FILE in doc["containerizer:shop-web:check"]["rules"][0]["changes"]["paths"]
    assert "variables" not in doc                    # nothing global leaks into the including pipeline
    readme = files["containerizer/README.md"]
    assert "include: [{local: containerizer.gitlab-ci.yml}]" in readme


# --------------------------------------------------------------------------- Azure Pipelines

def test_azure_pipeline_service_connection_and_no_secrets_in_yaml():
    files = pl.files(spec(), "azure-devops")
    text = files[pl.AZURE_FILE]
    doc = yaml.safe_load(text)
    assert doc["pool"] == {"vmImage": "ubuntu-latest"}
    assert {"name": "CONTAINERIZER_REGISTRY", "value": pl.AZURE_PLACEHOLDER} in doc["variables"]
    assert "placeholder" in text and "REPLACE-ME" in text
    image = doc["jobs"][1]
    logins = [s for s in image["steps"] if s.get("task") == "Docker@2"]
    assert [s["inputs"]["command"] for s in logins] == ["login", "logout"]
    assert all(s["inputs"]["containerRegistry"] == "${{ variables.registryConnection }}" for s in logins)
    assert {"name": "registryConnection", "value": "containerizer-registry"} in doc["variables"]
    assert not re.search(r"(?i)password|pat\b|token", json.dumps(doc["variables"]))
    assert sorted(image["strategy"]["matrix"]) == ["shop_api", "shop_web"]
    assert image["strategy"]["matrix"]["shop_api"]["DOCKERFILE"] == "containerizer/shop-api/Dockerfile"
    push = next(s for s in image["steps"] if s.get("displayName") == "Push")
    assert "refs/heads/main" in push["condition"] and "PullRequest" in push["condition"]
    assert doc["trigger"]["paths"]["include"][-1] == pl.AZURE_FILE and "src/Api" in doc["pr"]["paths"]["include"]
    assert image["variables"]["VERSION"] == "$[ dependencies.version.outputs['v.VERSION'] ]"
    # keyless is not possible: a key from a secure file
    doc = yaml.safe_load(pl.files(spec(registry="acme.azurecr.io/shop"), "azure-devops", "keyless")[pl.AZURE_FILE])
    steps = doc["jobs"][1]["steps"]
    assert any(s.get("task") == "DownloadSecureFile@1" and s["inputs"]["secureFile"] == "cosign.key" for s in steps)
    push = next(s for s in steps if s.get("displayName") == "Push and sign")
    assert push["env"]["COSIGN_KEY_FILE"] == "$(cosignKey.secureFilePath)" and '--key "$COSIGN_KEY_FILE"' in push["bash"]
    assert {"name": "CONTAINERIZER_REGISTRY", "value": "acme.azurecr.io/shop"} in doc["variables"]


@pytest.mark.parametrize("provider", pl.PROVIDERS)
@pytest.mark.parametrize("sign", pl.SIGN_MODES)
def test_every_variant_is_valid_yaml_with_the_readme(provider, sign):
    files = pl.files(spec(), provider, sign)
    ci = pl.ci_file(spec(), provider)
    assert isinstance(yaml.safe_load(files[ci]), dict)
    assert set(files) == {ci, "containerizer/README.md", "containerizer/shop-web/Dockerfile",
                          "containerizer/shop-web/Dockerfile.dockerignore", "containerizer/shop-api/Dockerfile",
                          "containerizer/shop-api/Dockerfile.dockerignore"}
    readme = files["containerizer/README.md"]
    assert f"`{ci}`" in readme and "shop/shop-api" in readme and "1.<yyyymmdd>.<hhmm>" in readme
    with pytest.raises(pl.PipelineError):
        pl.files(spec(), "bitbucket", sign)
    with pytest.raises(pl.PipelineError):
        pl.files(spec(components=[]), provider, sign)


# --------------------------------------------------------------------------- the patch

def test_the_patch_applies_with_git_am_to_a_clean_copy(tmp_path):
    repo = make_repo(tmp_path / "shop")
    sp = spec(components=[{**SPEC["components"][0], "folder": "demo-web"}])
    patch = pl.patch_for(sp, "github")                               # without the source: on an empty commit
    text = patch.decode()
    assert text.startswith("From ") and "Subject: [PATCH] Container image build pipeline (GitHub Actions)" in text
    assert "From: Containerizer <containerizer@localhost>" in text
    assert [f["status"] for f in rf.diffstat(text)] == ["added"] * 4
    ok, log = rf.apply_patch(repo, patch)
    assert ok, log
    assert (repo / pl.GITHUB_FILE).exists() and (repo / "containerizer/demo-web/Dockerfile").read_text() == "FROM scratch\n"
    assert git(repo, "log", "-1", "--format=%s") == "Container image build pipeline (GitHub Actions)"
    assert git(repo, "status", "--porcelain") == ""
    # the next organization scan does not take the pipeline's Dockerfile for the repository's own
    from containerizer.orgsource import existing_dockerfiles
    assert existing_dockerfiles(repo) == []
    (repo / "containerizer" / "demo-web" / "Dockerfile.dockerignore").write_text("**/bin/\n")
    assert existing_dockerfiles(repo) == ["containerizer/demo-web/Dockerfile"]       # not ours (any more)
    (repo / "Dockerfile").write_text("FROM scratch\n")
    assert "Dockerfile" in existing_dockerfiles(repo)
    # a second generation keeps the folder name when the folder is the pipeline's
    assert pl._ours(repo / "containerizer") is False
    (repo / "containerizer" / "demo-web" / "Dockerfile.dockerignore").write_text(pl.PIPELINE_MARK + "\n")
    assert pl._ours(repo / "containerizer") is True
    git(repo, "checkout", "-q", "--", ".")
    (repo / "Dockerfile").unlink()
    # on a checkout at the commit (the CLI): the same files
    co = tmp_path / "co"
    r, _ = rf.checkout({"type": "local", "path": str(make_repo(tmp_path / "shop2")), "git": True},
                       git(tmp_path / "shop2", "rev-parse", "HEAD"), co)
    p2 = pl.patch_for(sp, "github", repo=r)
    assert rf.diffstat(p2.decode()) == rf.diffstat(text)
    ok, _ = pl.check_patch(p2, {"type": "local", "path": str(tmp_path / "shop2"), "git": True},
                           git(tmp_path / "shop2", "rev-parse", "HEAD"))
    assert ok
    # already there: it does not apply
    ok, log = rf.apply_patch(repo, patch)
    assert not ok and "already exists" in log


def test_tarball_has_the_files(tmp_path):
    fm = pl.files(spec(), "gitlab")
    data = pl.tarball(fm, "shop-build-pipeline-gitlab")
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        names = tf.getnames()
        assert names == [f"shop-build-pipeline-gitlab/{p}" for p in fm]
        assert tf.extractfile(names[0]).read().decode() == fm[list(fm)[0]]
    assert pl.tarball(fm, "x") == pl.tarball(fm, "x")                # deterministic


# --------------------------------------------------------------------------- the command line

def test_cli_writes_the_files_or_a_patch(tmp_path, capsys):
    from containerizer import cli
    repo = make_repo(tmp_path / "shop", remote="git@gitlab.example.com:acme/shop.git")
    out = tmp_path / "out"
    assert cli.main(["pipeline", str(repo), "--out", str(out)]) == 0
    assert "GitLab CI/CD pipeline for 1 component(s)" in capsys.readouterr().out
    assert (out / "pipeline/gitlab/.gitlab-ci.yml").exists() and not (out / "pipeline/github").exists()
    assert cli.main(["pipeline", str(repo), "--provider", "azure-devops", "--registry", "acme.azurecr.io/shop",
                     "--patch", "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    patch = next(out.glob("*-build-pipeline-azure-devops.patch"))
    assert "git am applies it to" in printed
    assert "acme.azurecr.io/shop" in patch.read_text() and pl.AZURE_FILE in patch.read_text()
    ok, log = rf.apply_patch(repo, patch.read_bytes())
    assert ok, log
    assert cli.main(["pipeline", str(tmp_path / "nope")]) == 2


# --------------------------------------------------------------------------- Docker

@needs_docker
def test_the_dockerignore_next_to_the_dockerfile_filters_the_repository_context(tmp_path):
    repo = make_repo(tmp_path / "shop")
    (repo / "src/Demo.Web/bin").mkdir()
    (repo / "src/Demo.Web/bin/old.dll").write_text("x")
    (repo / ".dockerignore").write_text("src/\n")          # the repository's own: does not apply
    fm = pl.files(spec(components=[{**SPEC["components"][0], "folder": "probe",
                                    "dockerfile": "FROM scratch\nCOPY . /ctx/\n",
                                    "dockerignore": "**/bin/\n"}]), "github")
    for rel, text in fm.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    tag = f"cz-test-pipeline-probe:{os.getpid()}"
    env = {**os.environ, "DOCKER_BUILDKIT": "1"}
    p = subprocess.run(["docker", "build", "-q", "-f", "containerizer/probe/Dockerfile", "-t", tag, "."], cwd=repo,
                       capture_output=True, text=True, env=env, timeout=600)
    assert p.returncode == 0, p.stderr
    try:
        cid = subprocess.run(["docker", "create", tag, "x"], capture_output=True, text=True, check=True).stdout.strip()
        tar = subprocess.run(["docker", "export", cid], capture_output=True, check=True).stdout
        subprocess.run(["docker", "rm", cid], capture_output=True)
        names = tarfile.open(fileobj=io.BytesIO(tar)).getnames()
        assert "ctx/src/Demo.Web/Program.cs" in names                     # the repository root is the context
        assert not any(n.startswith("ctx/containerizer") for n in names)  # the pipeline's own files are not
        assert not any("/bin/" in n for n in names)
    finally:
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


@needs_docker
def test_ci_demo_builds_from_the_repository_root_with_the_copied_dockerfile(tmp_path):
    """The workflow's build step, as GitHub runs it, on examples/ci-demo (pulls the .NET images)."""
    from containerizer.assess import assess
    from containerizer.generate import generate_app
    from containerizer.rules import load_rules
    repo = make_repo(tmp_path / "shop")
    a = assess(repo, load_rules())
    generate_app(a, tmp_path / "gen")
    fm = pl.files(a.build_pipeline, "github")
    for rel, text in fm.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    wf = yaml.safe_load(fm[pl.GITHUB_FILE])
    run = next(s for s in wf["jobs"]["check"]["steps"] if s.get("name", "").startswith("Build"))["run"]
    build = run.split("docker run", 1)[0]          # the build itself; SBOM and scan need the network's databases
    folder = a.build_pipeline["components"][0]["folder"]
    env = {**os.environ, "FOLDER": folder, "DOCKERFILE": f"containerizer/{folder}/Dockerfile", "CONTEXT": ".",
           "COMMIT_SHA": "0" * 40, "SOURCE_URL": "https://github.com/acme/shop", "DOCKER_BUILDKIT": "1"}
    p = subprocess.run(["bash", "-c", build], cwd=repo, env=env, capture_output=True, text=True, timeout=1500)
    try:
        assert p.returncode == 0, p.stderr[-3000:]
        labels = subprocess.run(["docker", "inspect", "--format", "{{json .Config.Labels}}", f"cz-local/{folder}:ci"],
                                capture_output=True, text=True, check=True).stdout
        assert json.loads(labels)["org.opencontainers.image.revision"] == "0" * 40
    finally:
        subprocess.run(["docker", "rmi", "-f", f"cz-local/{folder}:ci"], capture_output=True)


# --------------------------------------------------------------------------- the results page

def _app(**kw):
    return {"ApplicationId": 7, "ApplicationName": "Shop", "ProductId": 5, "AssessmentId": 70, "Rating": "A",
            "SourceCommit": "b" * 40, "RepositoryUrl": "https://github.com/acme/shop",
            "components": [{"ComponentId": 11, "ComponentName": "Shop.Web", "Verdict": "info", "Tier": "server"}], **kw}


def test_the_box_for_viewers_says_it_exists():
    from containerizer import pipelineui as ui
    html = ui.section(_app(), {"pipeline": {"allowed": False, "signin": True}})
    assert "id='build-pipeline'" in html and "for GitHub Actions" in html and "(sign in)" in html
    assert "/admin/build-pipeline" not in html and "<code>containerizer/" not in html
    assert "containerizer pipeline" in ui.section(_app(), {"pipeline": {"allowed": False, "signin": False}})
    # nothing to build: no box
    assert ui.section(_app(components=[{"Verdict": "blocker", "Tier": "server"}]), {}) == ""


def test_the_box_for_operators_shows_the_files_the_patch_and_escapes(monkeypatch):
    from containerizer import pipelineui as ui
    sp = spec(app="<Shop>", existing=["containerizer/<x>"])
    sp["components"][0]["dockerfile"] = "FROM scratch\n# <script>alert(1)</script>\n"
    d = {"allowed": True, "spec": sp, "provider": "github", "how": "the repository URL", "chosen": "github",
         "sign": "none", "files": pl.files(sp, "github"), "patch": pl.patch_for(sp, "github").decode()}
    html = ui.section(_app(), {"pipeline": d})
    assert "<script>" not in html and "&lt;script&gt;" in html and "containerizer/&lt;x&gt;" in html
    assert "<b>GitHub</b> (from the repository URL)" in html
    assert "/admin/build-pipeline/7.patch?provider=github&amp;sign=none" in html and ".tar.gz" in html
    assert "git checkout -b containerizer-build-pipeline bbbbbbbbbbbb" in html
    assert "git am &lt; Shop-build-pipeline-github.patch" in html
    assert "<code>.github/workflows/containerizer-images.yml</code>" in html and "class='diff'" in html
    assert "GitHub Container Registry" in html
    # provider not known: a link per provider
    html = ui.section(_app(), {"pipeline": {**d, "provider": None, "chosen": None, "files": None, "patch": None}})
    assert html.count("Download .patch") == 3 and "<b>not known</b>" in html and "Provider…" in html
    # no build pipeline in this assessment
    html = ui.section(_app(), {"pipeline": {"allowed": True, "spec": None}})
    assert "Scan the repository again" in html and "Download" not in html


@pytest.fixture
def adm():
    pytest.importorskip("jwt")
    from test_llm_queue import FakeConn
    from containerizer import admin as adminmod
    from containerizer.oidc import OidcConfig
    c = OidcConfig(issuer="https://idp.example.com", client_id="cz", client_secret="s", public_url="https://cz.example.com",
                   admins=["group:a"])
    conn = FakeConn()
    a = adminmod.Admin(c, lambda: conn, provider=object())
    a.conn = conn
    return a


def _get(adm, sid, path, query=""):
    return adm.handle("GET", path, query, {"Cookie": f"{adm.cookie}={sid}"}, b"")


def test_downloads_need_a_role_and_the_application(adm):
    sp = spec(components=[{**SPEC["components"][0], "folder": "demo-web"}])
    adm.conn.answers = {
        r"FROM cz.vApplicationLatest WHERE ApplicationId": [_app()],
        r"SELECT ReportJson FROM cz.ApplicationAssessment": [{"ReportJson": json.dumps({"build_pipeline": sp})}],
        r"FROM cz.OrgRepository r JOIN cz.OrgScan": [{"Provider": "gitlab", "ApiUrl": None, "Registry": "cz.lab:5000",
                                                    "DefaultBranch": "develop"}],
        r"SELECT BusinessUnitId AS Id, Name FROM cz.BusinessUnit": [{"Id": 1, "Name": "Finance"}],
        r"SELECT ProductId AS Id, Name, BusinessUnitId FROM cz.Product": [{"Id": 5, "Name": "Shop", "BusinessUnitId": 1},
                                                                         {"Id": 6, "Name": "Other", "BusinessUnitId": 2}]}
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    assert _get(adm, viewer, "/admin/build-pipeline/7.patch").status == 403
    other = adm.sessions.create("p@example.com", "P", False, True, False, ["product:Other"])
    assert _get(adm, other, "/admin/build-pipeline/7.patch").status == 404
    owner = adm.sessions.create("q@example.com", "Q", False, True, False, ["product:Shop"])
    r = _get(adm, owner, "/admin/build-pipeline/7.patch")
    assert r.status == 200 and r.ctype == "text/x-diff; charset=utf-8"
    assert dict(r.headers)["Content-Disposition"] == 'attachment; filename="Shop-build-pipeline-gitlab.patch"'
    body = r.body.decode()
    assert "Container image build pipeline (GitLab CI/CD)" in body              # the organization scan's provider
    assert 'REGISTRY="${CONTAINERIZER_REGISTRY:-cz.lab:5000}"' in body                # the organization scan's registry
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    r = _get(adm, op, "/admin/build-pipeline/7.patch", "provider=azure-devops&sign=key")
    text = r.body.decode()
    assert r.status == 200 and "Azure Pipelines" in text and "cosign.key" in text and "- develop" in text
    r = _get(adm, op, "/admin/build-pipeline/7.tar.gz", "provider=github")
    assert r.status == 200 and r.ctype == "application/gzip"
    names = tarfile.open(fileobj=io.BytesIO(r.body)).getnames()
    assert "Shop-build-pipeline-github/.github/workflows/containerizer-images.yml" in names
    # a bad provider is ignored (the scan's is used); bad paths are not found
    assert "GitLab" in _get(adm, op, "/admin/build-pipeline/7.patch", "provider=<x>").body.decode()
    for path in ("/admin/build-pipeline/7", "/admin/build-pipeline/x.patch", "/admin/build-pipeline/7.zip",
                 "/admin/build-pipeline"):
        assert _get(adm, op, path).status == 404, path
    assert adm.handle("POST", "/admin/build-pipeline/7.patch", "", {"Cookie": f"{adm.cookie}={op}"},
                      b"csrf=" + adm.sessions.get(op).csrf.encode()).status == 404
    # no build pipeline recorded
    adm.conn.answers[r"SELECT ReportJson FROM cz.ApplicationAssessment"] = [{"ReportJson": "{}"}]
    assert _get(adm, op, "/admin/build-pipeline/7.patch").status == 404


def test_page_data_reads_with_the_admin_login_for_who_may_download(adm):
    from containerizer import pipelineui as ui
    adm.conn.answers = {
        r"SELECT ReportJson FROM cz.ApplicationAssessment": [{"ReportJson": json.dumps({"build_pipeline": spec()})}],
        r"SELECT ProductId AS Id, Name, BusinessUnitId FROM cz.Product": [{"Id": 5, "Name": "Shop", "BusinessUnitId": 1}]}
    viewer = adm.sessions.get(adm.sessions.create("v@example.com", "V", False, True))
    assert ui.page_data(adm, viewer, _app(), {}) == {"allowed": False, "signin": True}
    assert ui.page_data(adm, None, _app(), {}) == {"allowed": False, "signin": True}
    assert ui.page_data(None, None, _app(), {}) == {"allowed": False, "signin": False}
    owner = adm.sessions.get(adm.sessions.create("q@example.com", "Q", False, True, False, ["product:Shop"]))
    d = ui.page_data(adm, owner, _app(), {"pipeline": ["gitlab"], "sign": ["keyless"]})
    assert d["allowed"] and d["provider"] == "github" and d["chosen"] == "gitlab" and d["sign"] == "keyless"
    assert ".gitlab-ci.yml" in d["files"] and d["patch"].startswith("From ")
    d = ui.page_data(adm, owner, _app(), {"pipeline": ["nope"], "sign": ["<x>"]})
    assert d["chosen"] == "github" and d["sign"] == "none"
    assert not ui.page_data(adm, owner, _app(ProductId=6), {})["allowed"]


def test_results_page_has_the_box_after_the_findings():
    from containerizer import webui
    app = {**_app(), "BusinessUnitId": None, "BusinessUnitName": None, "ProductName": None, "Score": 90,
           "Confidence": 0.9, "Verified": False, "AssessedAt": None, "Summary": "s", "findings": [], "history": [],
           "components": [{**_app()["components"][0], "ProjectPath": "src/W.csproj", "Role": "web", "VerifyStatus": None,
                           "VerdictText": "", "WindowsContainerOk": False, "TargetFramework": "net8.0"}]}
    html = webui.render_application(app, "", {"signin": True, "pipeline": {"allowed": False, "signin": True}})
    assert html.index("What needs to change") < html.index("id='build-pipeline'") < html.index("<h2>History")
