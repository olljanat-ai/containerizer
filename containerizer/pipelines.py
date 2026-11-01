"""Container image build pipelines for the application's own repository (docs/build-pipelines.md).

Deterministic, no LLM: from the generated Dockerfiles of an application, the CI file of the provider its
source lives on (GitHub Actions, GitLab CI/CD or Azure Pipelines) plus a copy of the Dockerfiles under
`containerizer/<component>/` in the repository:

- pull / merge requests: build, SBOM (Syft), vulnerability scan (Trivy), nothing pushed;
- the default branch: the same, then push `<registry>/<app>/<component>` with the tags `1.<yyyymmdd>.<hhmm>`
  (the semver scheme of the scans, org.default_tag, which the generated GitOps image automation follows)
  and `sha-<commit>` (and `latest` when asked), the SBOM kept as a pipeline artifact, optionally signed
  with cosign (keyless where the provider gives an OIDC token, else with a key).

The build context is the application's folder in the repository, as for the scans (`docker build -f
<generated>/<component>/Dockerfile <application folder>`), and `Dockerfile.dockerignore` next to the
Dockerfile is the context filter (BuildKit reads `<Dockerfile>.dockerignore`).

`spec()` captures what the files are made of when the application is generated (generate_app): stored
with the assessment (assessment.json `build_pipeline`), the results page builds the files and a
`git am` patch from it without the source (pipelineui.py). `files()` renders them for one provider.
"""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import yaml

PROVIDERS = ("github", "gitlab", "azure-devops")
PROVIDER_TEXT = {"github": "GitHub Actions", "gitlab": "GitLab CI/CD", "azure-devops": "Azure Pipelines"}
HOST_TEXT = {"github": "GitHub", "gitlab": "GitLab", "azure-devops": "Azure DevOps"}
SIGN_MODES = ("none", "keyless", "key")
FOLDER = "containerizer"                 # in the repository, at the application's folder
ALT_FOLDER = "containerizer-build"       # when the application already has a `containerizer` entry
OUTPUT_DIR = "pipeline"                  # in the generated output (next to the components' folders)
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
UNKNOWN_REGISTRIES = ("", "registry.local")
AZURE_PLACEHOLDER = "REPLACE-ME.azurecr.io"
SPEC_VERSION = 1
# the last lines of every Dockerfile.dockerignore the pipeline adds: how scans recognise its Dockerfiles
PIPELINE_MARK = "# the build pipeline's own files are not part of the image"

# Pinned by digest (multi-arch index). The scanners' versions come from rules/60-security.yaml (scan.scanners,
# sbom.generator): when one changes there, add its digest here (tests/test_pipelines.py checks it):
#   docker buildx imagetools inspect aquasec/trivy:<version> | grep Digest
DIGESTS = {
    "aquasec/trivy:0.67.2": "sha256:e2b22eac59c02003d8749f5b8d9bd073b62e30fefaef5b7c8371204e0a4b0c08",
    "anchore/syft:v1.33.0": "sha256:f94e5d9fce1f2278491a8e3a63bd5f6ddb81fdfdbb8bf7a1637565c1d5344357",
    "docker:29.9.2-cli": "sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb",
    "docker:29.9.2-dind": "sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977",
}
DOCKER_CLI = "docker:29.9.2-cli"
DOCKER_DIND = "docker:29.9.2-dind"
# GitHub Actions by full commit SHA (the tag in the comment): update with
#   git ls-remote https://github.com/actions/checkout refs/tags/v7.0.1
ACTIONS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/upload-artifact": ("cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2"),
}
# cosign: the release binary, checked against the SHA-256 of the release's cosign_checksums.txt
COSIGN = ("v2.6.1", "064954c5d8c7e3b28188eee5b1727b31c411550bc5fefd41aa672d3c761d103a")
# root files of the application folder that change every component's build
BUILD_FILES = ("Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props", "global.json",
               "NuGet.config", "NuGet.Config", "nuget.config", "pom.xml", "settings.gradle", "settings.gradle.kts",
               "package.json", "package-lock.json", "pnpm-workspace.yaml", "yarn.lock", "pnpm-lock.yaml")


class PipelineError(RuntimeError):
    """A build pipeline cannot be made (the message says why)."""


# --------------------------------------------------------------------------- provider detection

def _url_parts(url: str) -> tuple[str, str]:
    """(host, path) of a git remote: https, ssh:// and scp-like `git@host:path` forms."""
    u = (url or "").strip()
    m = re.match(r"^(?:[\w.+-]+@)?([\w.-]+):(?!//)(?!\d+/)(.*)$", u)
    if m and "://" not in u:
        return m[1].lower(), "/" + m[2].lstrip("/")
    if "://" not in u:
        u = "https://" + u
    p = urlsplit(u)
    return (p.hostname or "").lower(), p.path or "/"


def detect_provider(url: str | None = None, provider: str | None = None, api_url: str | None = None) -> str | None:
    """Where the code lives: 'github', 'gitlab', 'azure-devops' or None (not known: offer all three).

    `provider` (an organization scan's Provider, which also covers GitHub Enterprise Server, GitLab
    self-managed and Azure DevOps Server through its ApiUrl) wins; otherwise the repository URL's host and
    path say it: github.com and *.ghe.com (GitHub Enterprise Cloud) or a host named github, gitlab.com or a
    host named gitlab, dev.azure.com / *.visualstudio.com or an Azure DevOps Server / TFS URL (`/_git/`,
    `/tfs/`). `api_url`: a self-hosted API whose host is the URL's host, with `provider` unknown."""
    p = (provider or "").strip().lower().replace("_", "-")
    p = {"azure": "azure-devops", "azuredevops": "azure-devops", "ado": "azure-devops", "tfs": "azure-devops",
         "ghe": "github", "github-enterprise": "github"}.get(p, p)
    if p in PROVIDERS:
        return p
    host, path = _url_parts(url or "")
    if not host and api_url:
        host, path = _url_parts(api_url)
    if not host:
        return None
    low = path.lower()
    if host in ("dev.azure.com", "ssh.dev.azure.com") or host.endswith(".visualstudio.com") \
            or "/_git/" in low + "/" or low.startswith("/tfs/") or low.startswith("/v3/") and host.startswith("ssh."):
        return "azure-devops"
    if host == "github.com" or host.endswith(".github.com") or host.endswith(".ghe.com") or host == "ghe.com" \
            or re.search(r"(^|[.-])(github|ghe)([.-]|$)", host):
        return "github"
    if host == "gitlab.com" or host.endswith(".gitlab.com") or re.search(r"(^|[.-])gitlab([.-]|$)", host):
        return "gitlab"
    if api_url:
        ahost, apath = _url_parts(api_url)
        if ahost == host:
            if "/api/v4" in apath:
                return "gitlab"
            if "/api/v3" in apath:
                return "github"
    return None


# --------------------------------------------------------------------------- the spec (from a generated app)

def _git(path: Path, *args: str) -> str:
    try:
        r = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=path, capture_output=True, text=True,
                           timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def _norm(p: str) -> str:
    p = p.replace("\\", "/").strip("/")
    return "" if p in ("", ".") else p


def component_paths(c, app_root: Path, repo=None) -> list[str]:
    """Folders (ending in /) and files, relative to the application folder, whose change rebuilds the
    component: its project folder, the projects it references (transitively, through `repo`), the
    application folder's shared build files. [""]: the whole folder (a project at the top)."""
    root = Path(app_root).resolve()
    seen, todo, dirs = set(), [Path(c.project.path)], []
    while todo:
        path = todo.pop().resolve()
        if path in seen:
            continue
        seen.add(path)
        try:
            dirs.append(_norm(path.parent.relative_to(root).as_posix()))
        except ValueError:
            continue
        pr = repo.project_by_path(path) if repo is not None else (c.project if path == Path(c.project.path).resolve() else None)
        for ref in (getattr(pr, "project_refs", None) or []) if pr is not None else []:
            ref = Path(ref)
            todo.append(ref if ref.is_absolute() else path.parent / ref)
    if "" in dirs:
        return [""]
    out = sorted({d + "/" for d in dirs})
    out = [d for d in out if not any(d != o and d.startswith(o) for o in out)]
    return out + [f for f in BUILD_FILES if (root / f).is_file()]


def _ours(folder: Path) -> bool:
    """A `containerizer/` folder an earlier build pipeline added (its Dockerfile.dockerignore files are marked)."""
    return folder.is_dir() and any(PIPELINE_MARK in f.read_text(errors="replace")
                                   for f in folder.glob("*/Dockerfile.dockerignore"))


def spec(a, out: Path, registry: str = "registry.local", branch: str | None = None,
         repository_url: str | None = None) -> dict | None:
    """What the build pipeline of a generated application is made of (None: no Linux image to build).
    Reads the Dockerfiles generate_app wrote to `out/<component>/`."""
    from .generate import buildable, k8s_name
    from .harden import security
    app_root = Path(a.repo.root).resolve()
    top = _git(app_root, "rev-parse", "--show-toplevel")
    top_p = Path(top).resolve() if top else app_root
    try:
        subdir = _norm(app_root.relative_to(top_p).as_posix())
    except ValueError:
        top_p, subdir = app_root, ""
    folder = ALT_FOLDER if (app_root / FOLDER).exists() and not _ours(app_root / FOLDER) else FOLDER
    comps = []
    for c in a.components:
        name = k8s_name(c.name)
        df = Path(out) / name / "Dockerfile"
        if not buildable(c) or not df.is_file():
            continue
        di = Path(out) / name / "Dockerfile.dockerignore"
        comps.append({"name": c.name, "folder": name, "project": c.project.rel,
                      "paths": component_paths(c, app_root, a.repo), "dockerfile": df.read_text(),
                      "dockerignore": di.read_text() if di.is_file() else ""})
    if not comps:
        return None
    if repository_url is None:
        from .sqlstore import clean_remote
        repository_url = clean_remote(_git(top_p, "remote", "get-url", "origin")) or None
    if branch is None:
        head = _git(top_p, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
        branch = head.split("/", 1)[1] if "/" in head else (_git(top_p, "rev-parse", "--abbrev-ref", "HEAD") or None)
        if branch == "HEAD":
            branch = None
    sec = security()
    scan = sec.get("scan") or {}
    pre = (subdir + "/") if subdir else ""
    targets = [pre + f"{folder}/{c['folder']}/{n}" for c in comps for n in ("Dockerfile", "Dockerfile.dockerignore")]
    targets += [pre + f"{folder}/README.md", ".github/workflows/containerizer-images.yml",
                "containerizer.gitlab-ci.yml", "azure-pipelines.containerizer.yml"]
    return {"version": SPEC_VERSION, "app": a.name, "namespace": k8s_name(a.name),
            "registry": "" if (registry or "").rstrip("/") in UNKNOWN_REGISTRIES else registry.rstrip("/"),
            "subdir": subdir, "folder": folder, "branch": branch, "repository_url": repository_url,
            "detected": detect_provider(repository_url),
            "gitlab_ci": (top_p / ".gitlab-ci.yml").exists(),
            "existing": sorted(t for t in targets if (top_p / t).exists()),
            "fail_on": str(scan.get("fail_on") or "CRITICAL").upper(),
            "ignore_unfixed": bool(scan.get("ignore_unfixed", True)),
            "tlog": bool((sec.get("sbom") or {}).get("cosign_tlog_upload", True)),
            "components": comps}


def severities(fail_on: str) -> str:
    """The Trivy severities that fail the scan: the gate's fail_on and above (HIGH -> HIGH,CRITICAL)."""
    f = (fail_on or "CRITICAL").upper()
    i = SEVERITIES.index(f) if f in SEVERITIES else SEVERITIES.index("CRITICAL")
    return ",".join(SEVERITIES[i:])


def pinned(image: str) -> str:
    d = DIGESTS.get(image)
    return f"{image}@{d}" if d else image


def scanner_images() -> tuple[str, str]:
    """(Trivy, Syft) images of rules/60-security.yaml, pinned by digest."""
    from .harden import security
    sec = security()
    trivy = next((s.get("image") for s in (sec.get("scan") or {}).get("scanners") or [] if s.get("name") == "trivy"),
                 None) or "aquasec/trivy:0.67.2"
    syft = ((sec.get("sbom") or {}).get("generator") or {}).get("image") or "anchore/syft:v1.33.0"
    return pinned(trivy), pinned(syft)


# --------------------------------------------------------------------------- shell steps (POSIX sh)

def _sh_build() -> str:
    return ('docker build --pull -f "$DOCKERFILE" -t "cz-local/$FOLDER:ci" \\\n'
            '  --label "org.opencontainers.image.revision=$COMMIT_SHA" \\\n'
            '  --label "org.opencontainers.image.source=$SOURCE_URL" \\\n'
            '  "$CONTEXT"\n')


def _sh_sbom_scan(trivy: str, syft: str) -> str:
    # both read the image from the Docker daemon through its socket (on GitLab: the dind service's own socket)
    return (f'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock {syft} \\\n'
            f'  scan "docker:cz-local/$FOLDER:ci" -q -o cyclonedx-json > "sbom-$FOLDER.cdx.json"\n'
            f'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\\n'
            f'  -e TRIVY_SEVERITY -e TRIVY_IGNORE_UNFIXED -e TRIVY_EXIT_CODE=1 -e TRIVY_NO_PROGRESS=true -e TRIVY_SKIP_VERSION_CHECK=true \\\n'
            f'  -e TRIVY_SCANNERS=vuln {trivy} image "cz-local/$FOLDER:ci"\n')


SH_VERSION = "1.$(date -u +%Y%m%d).$(date -u +%H%M | sed 's/^0*\\(.\\)/\\1/')"


def _sh_push() -> str:
    # the digest from the push itself: RepoDigests also lists the local name (containerd image store)
    return ('IMAGE="$REGISTRY/$IMAGE_NAME"\n'
            'SHORT=$(printf %s "$COMMIT_SHA" | cut -c1-12)\n'
            'TAGS="$VERSION sha-$SHORT"\n'
            'if [ "${CONTAINERIZER_PUSH_LATEST:-false}" = true ]; then TAGS="$TAGS latest"; fi\n'
            'for t in $TAGS; do\n'
            '  docker tag "cz-local/$FOLDER:ci" "$IMAGE:$t"\n'
            '  docker push "$IMAGE:$t" > "push-$FOLDER.log"\n'
            '  cat "push-$FOLDER.log"\n'
            'done\n'
            "DIGEST=$(sed -n 's/.*digest: \\(sha256:[0-9a-f]\\{64\\}\\).*/\\1/p' \"push-$FOLDER.log\" | tail -n 1)\n"
            'if [ -z "$DIGEST" ]; then echo "no digest in the output of docker push" >&2; exit 1; fi\n'
            'DIGEST_REF="$IMAGE@$DIGEST"\n'
            'echo "pushed $IMAGE:$VERSION and sha-$SHORT: $DIGEST_REF"\n'
            'echo "$DIGEST_REF" > "image-$FOLDER.txt"\n')


def _sh_sign(sign: str, fetch: str, key_ref: str, tlog: bool) -> str:
    if sign == "none":
        return ""
    ver, sha = COSIGN
    args = (f" --key {key_ref}" if sign == "key" else "") + (" --tlog-upload=false" if sign == "key" and not tlog else "")
    url = f"https://github.com/sigstore/cosign/releases/download/{ver}/cosign-linux-amd64"
    get = f'curl -fsSLo /tmp/cosign "{url}"' if fetch == "curl" else f'wget -qO /tmp/cosign "{url}"'
    return (f"# cosign {ver}, checked against its release checksum\n{get}\n"
            f'echo "{sha}  /tmp/cosign" | sha256sum -c -\n'
            "chmod +x /tmp/cosign\n"
            f'/tmp/cosign sign --yes{args} "$DIGEST_REF"\n'
            f'/tmp/cosign attest --yes{args} --type cyclonedx --predicate "sbom-$FOLDER.cdx.json" "$DIGEST_REF"\n')


# --------------------------------------------------------------------------- YAML

class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _str(dumper, s):
    if "\n" in s:
        return dumper.represent_scalar("tag:yaml.org,2002:str", s, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", s)


_Dumper.add_representer(str, _str)


def _dump(doc: dict) -> str:
    text = yaml.dump(doc, Dumper=_Dumper, sort_keys=False, default_flow_style=False, width=200, allow_unicode=True)
    for action, (sha, tag) in ACTIONS.items():       # the version next to each pinned SHA
        text = re.sub(rf"(uses: {re.escape(action)}@{sha})$", rf"\1 # {tag}", text, flags=re.M)
    return text


def _header(spec_: dict, provider: str, extra: str = "") -> str:
    return (f"# Container image build pipeline for {spec_['app']}, generated by containerizer "
            f"({PROVIDER_TEXT[provider]}).\n"
            f"# Pull/merge requests: build, SBOM (Syft) and vulnerability scan (Trivy), nothing is pushed.\n"
            f"# Default branch: the same, then push <registry>/{spec_['namespace']}/<component> tagged 1.<yyyymmdd>.<hhmm>\n"
            f"# (UTC; the GitOps image automation follows these semver tags) and sha-<commit>.\n"
            f"# Setup and the secrets it needs: {spec_.get('folder') or FOLDER}/README.md "
            f"(https://containerizer.eu/build-pipelines/).\n" + extra)


def _rel(spec_: dict, p: str) -> str:
    return (spec_["subdir"] + "/" + p) if spec_.get("subdir") else p


def _repo_paths(spec_: dict, c: dict) -> list[str]:
    """The component's paths in the repository ('' = everything), with its own pipeline files."""
    if "" in c["paths"]:
        return [""]
    return [_rel(spec_, p) for p in c["paths"]] + [_rel(spec_, f"{spec_['folder']}/{c['folder']}/")]


def _globs(paths: list[str], style: str) -> list[str]:
    out = []
    for p in paths:
        if p.endswith("/"):
            out.append({"github": p + "**", "gitlab": p + "**/*", "azure": p.rstrip("/")}[style])
        else:
            out.append(p)
    return out


def _ere(paths: list[str]) -> str:
    """An extended regular expression matching the changed files of these paths."""
    parts = []
    for p in paths:
        q = re.sub(r"([.\[\]()*+?{}|^$\\])", r"\\\1", p)
        parts.append(q if p.endswith("/") else q + "$")
    return "^(" + "|".join(parts) + ")"


def _image_name(spec_: dict, c: dict) -> str:
    return f"{spec_['namespace']}/{c['folder']}"


def _component_vars(spec_: dict, c: dict) -> dict:
    return {"FOLDER": c["folder"], "DOCKERFILE": _rel(spec_, f"{spec_['folder']}/{c['folder']}/Dockerfile"),
            "CONTEXT": spec_["subdir"] or ".", "IMAGE_NAME": _image_name(spec_, c)}


def _all_paths(spec_: dict, own: str) -> list[str] | None:
    """Union of the components' paths and the pipeline file; None: no path filter (a component is everything)."""
    paths: list[str] = []
    for c in spec_["components"]:
        rp = _repo_paths(spec_, c)
        if "" in rp:
            return None
        paths += rp
    return sorted(set(paths)) + [own]


# --------------------------------------------------------------------------- GitHub Actions

GITHUB_FILE = ".github/workflows/containerizer-images.yml"


def github(spec_: dict, sign: str = "none") -> str:
    trivy, syft = scanner_images()
    reg = spec_.get("registry") or ""
    ghcr = not reg or reg.startswith("ghcr.io")
    branch = spec_.get("branch") or "main"
    paths = _all_paths(spec_, GITHUB_FILE)
    checkout = {"uses": f"actions/checkout@{ACTIONS['actions/checkout'][0]}", "with": {"persist-credentials": False}}
    on: dict = {"pull_request": ({"paths": _globs(paths, "github")} if paths else None),
                "push": {"branches": [branch], **({"paths": _globs(paths, "github")} if paths else {})},
                "workflow_dispatch": None}
    picks = []
    for c in spec_["components"]:
        rp = _repo_paths(spec_, c)
        entry = json.dumps({"folder": c["folder"], **{k.lower(): v for k, v in _component_vars(spec_, c).items()
                                                      if k != "FOLDER"}}, separators=(",", ":"))
        cond = "true" if "" in rp else f"changed '{_ere(rp)}'"
        picks.append(f"if {cond}; then list=\"$list${{list:+,}}{entry.replace(chr(34), chr(92) + chr(34))}\"; fi")
    changes = ("set -euo pipefail\n"
               'case "$EVENT" in\n'
               '  pull_request) BASE="$PR_BASE" ;;\n'
               '  push) BASE="$BEFORE" ;;\n'
               '  *) BASE="" ;;\n'
               "esac\n"
               "ALL=1\nCHANGED=\"\"\n"
               'if [ -n "$BASE" ] && git cat-file -e "$BASE^{commit}" 2>/dev/null; then\n'
               '  CHANGED=$(git diff --name-only "$BASE" HEAD)\n'
               f'  if ! printf \'%s\\n\' "$CHANGED" | grep -qxF "{GITHUB_FILE}"; then ALL=0; fi\n'
               "fi\n"
               'changed() { [ "$ALL" = 1 ] || printf \'%s\\n\' "$CHANGED" | grep -qE "$1"; }\n'
               'list=""\n' + "\n".join(picks) + "\n"
               'echo "components=[$list]" >> "$GITHUB_OUTPUT"\n'
               f'echo "version={SH_VERSION}" >> "$GITHUB_OUTPUT"\n'
               'echo "components to build: [$list]"\n')
    env_common = {"FOLDER": "${{ matrix.folder }}", "DOCKERFILE": "${{ matrix.dockerfile }}",
                  "CONTEXT": "${{ matrix.context }}", "COMMIT_SHA": "${{ github.sha }}",
                  "SOURCE_URL": "${{ github.server_url }}/${{ github.repository }}",
                  "TRIVY_SEVERITY": "${{ vars.CONTAINERIZER_TRIVY_SEVERITY || '" + severities(spec_["fail_on"]) + "' }}",
                  "TRIVY_IGNORE_UNFIXED": "${{ vars.CONTAINERIZER_TRIVY_IGNORE_UNFIXED || '"
                                          + ("true" if spec_["ignore_unfixed"] else "false") + "' }}"}
    upload = {"name": "SBOM", "if": "always()", "uses": f"actions/upload-artifact@{ACTIONS['actions/upload-artifact'][0]}",
              "with": {"name": "sbom-${{ matrix.folder }}", "path": "sbom-${{ matrix.folder }}.cdx.json",
                       "if-no-files-found": "ignore"}}
    matrix = {"fail-fast": False, "matrix": {"include": "${{ fromJSON(needs.changes.outputs.components) }}"}}
    build_step = {"name": "Build, SBOM and vulnerability scan", "run": "set -eu\n" + _sh_build() + _sh_sbom_scan(trivy, syft)}
    default_reg = reg if not ghcr or reg else "ghcr.io/$OWNER"
    login = ("set -eu\n"
             + ("OWNER=$(printf %s \"$GITHUB_REPOSITORY_OWNER\" | tr '[:upper:]' '[:lower:]')\n"   # GHCR: lower case
                if "$OWNER" in default_reg else "") +
             f'REGISTRY="${{CONTAINERIZER_REGISTRY:-{default_reg}}}"\n'
             'HOST="${REGISTRY%%/*}"\n'
             'if [ -n "${REGISTRY_USERNAME:-}" ]; then\n'
             '  printf %s "$REGISTRY_PASSWORD" | docker login "$HOST" -u "$REGISTRY_USERNAME" --password-stdin\n'
             'elif [ "$HOST" = ghcr.io ]; then\n'
             '  printf %s "$GITHUB_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin\n'
             "else\n"
             '  echo "::error::$HOST needs the CONTAINERIZER_REGISTRY_USERNAME and CONTAINERIZER_REGISTRY_PASSWORD secrets"\n'
             "  exit 1\n"
             "fi\n"
             'echo "REGISTRY=$REGISTRY" >> "$GITHUB_ENV"\n')
    push_env = {"IMAGE_NAME": "${{ matrix.image_name }}", "VERSION": "${{ needs.changes.outputs.version }}",
                "CONTAINERIZER_PUSH_LATEST": "${{ vars.CONTAINERIZER_PUSH_LATEST || 'false' }}"}
    sign_env = {}
    if sign == "key":
        sign_env = {"COSIGN_PRIVATE_KEY": "${{ secrets.COSIGN_PRIVATE_KEY }}", "COSIGN_PASSWORD": "${{ secrets.COSIGN_PASSWORD }}"}
    publish_perms = {"contents": "read"}
    if ghcr:
        publish_perms["packages"] = "write"
    if sign == "keyless":
        publish_perms["id-token"] = "write"
    steps_pub = [checkout, build_step, upload,
                 {"name": "Log in to the registry", "env": {
                     "CONTAINERIZER_REGISTRY": "${{ vars.CONTAINERIZER_REGISTRY }}",
                     "REGISTRY_USERNAME": "${{ secrets.CONTAINERIZER_REGISTRY_USERNAME }}",
                     "REGISTRY_PASSWORD": "${{ secrets.CONTAINERIZER_REGISTRY_PASSWORD }}",
                     "GITHUB_TOKEN": "${{ github.token }}"}, "run": login},
                 {"name": "Push" + (" and sign" if sign != "none" else ""), "env": {**push_env, **sign_env},
                  "run": "set -eu\n" + _sh_push() + 'echo "$DIGEST_REF" >> "$GITHUB_STEP_SUMMARY"\n'
                         + _sh_sign(sign, "curl", "env://COSIGN_PRIVATE_KEY", spec_["tlog"])},
                 {"name": "Log out", "if": "always()", "run": 'docker logout "${REGISTRY%%/*}" || true'}]
    doc = {
        "name": f"containerizer images ({spec_['app']})",
        "on": on,
        "permissions": {},
        "concurrency": {"group": "${{ github.workflow }}-${{ github.ref }}",
                        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"},
        "jobs": {
            "changes": {"name": "Components to build", "runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                        "outputs": {"components": "${{ steps.pick.outputs.components }}",
                                    "version": "${{ steps.pick.outputs.version }}"},
                        "steps": [{**checkout, "with": {"persist-credentials": False, "fetch-depth": 0}},
                                  {"id": "pick", "env": {"EVENT": "${{ github.event_name }}",
                                                         "PR_BASE": "${{ github.event.pull_request.base.sha }}",
                                                         "BEFORE": "${{ github.event.before }}"},
                                   "run": changes}]},
            "check": {"name": "Build and scan ${{ matrix.folder }}", "needs": "changes",
                      "if": "github.event_name == 'pull_request' && needs.changes.outputs.components != '[]'",
                      "runs-on": "ubuntu-latest", "timeout-minutes": 60, "permissions": {"contents": "read"},
                      "strategy": matrix, "env": env_common, "steps": [checkout, build_step, upload]},
            "publish": {"name": "Build, scan and push ${{ matrix.folder }}", "needs": "changes",
                        "if": "github.event_name != 'pull_request' && needs.changes.outputs.components != '[]' && "
                              "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
                        "runs-on": "ubuntu-latest", "timeout-minutes": 60, "permissions": publish_perms,
                        "strategy": matrix, "env": env_common, "steps": steps_pub},
        },
    }
    return _header(spec_, "github") + _dump(doc)


# --------------------------------------------------------------------------- GitLab CI/CD

GITLAB_FILE = ".gitlab-ci.yml"
GITLAB_INCLUDE_FILE = "containerizer.gitlab-ci.yml"


def gitlab(spec_: dict, sign: str = "none", include: bool = False) -> str:
    trivy, syft = scanner_images()
    reg = spec_.get("registry") or ""
    own = GITLAB_INCLUDE_FILE if include else GITLAB_FILE
    version = ('VERSION="1.$(printf %s "$CI_PIPELINE_CREATED_AT" | cut -c1-4,6-7,9-10).'
               "$(printf %s \"$CI_PIPELINE_CREATED_AT\" | cut -c12-13,15-16 | sed 's/^0*\\(.\\)/\\1/')\"\n")
    login = (f'REGISTRY="${{CONTAINERIZER_REGISTRY:-{reg or "$CI_REGISTRY_IMAGE"}}}"\n'
             'HOST="${REGISTRY%%/*}"\n'
             'if [ -n "${CONTAINERIZER_REGISTRY_USER:-}" ]; then\n'
             '  printf %s "$CONTAINERIZER_REGISTRY_PASSWORD" | docker login "$HOST" -u "$CONTAINERIZER_REGISTRY_USER" --password-stdin\n'
             'elif [ "$HOST" = "$CI_REGISTRY" ]; then\n'
             '  printf %s "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin\n'
             "else\n"
             '  echo "$HOST needs the CONTAINERIZER_REGISTRY_USER and CONTAINERIZER_REGISTRY_PASSWORD variables" >&2\n'
             "  exit 1\n"
             "fi\n")
    base = {
        "image": pinned(DOCKER_CLI),
        "services": [{"name": pinned(DOCKER_DIND), "alias": "docker"}],
        "variables": {"DOCKER_HOST": "tcp://docker:2376", "DOCKER_TLS_CERTDIR": "/certs", "DOCKER_TLS_VERIFY": "1",
                      "DOCKER_CERT_PATH": "/certs/client", "DOCKER_BUILDKIT": "1",
                      "TRIVY_SEVERITY": severities(spec_["fail_on"]),
                      "TRIVY_IGNORE_UNFIXED": "true" if spec_["ignore_unfixed"] else "false",
                      "CONTAINERIZER_PUSH_LATEST": "false"},
        "before_script": ["for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done",
                          'export COMMIT_SHA="$CI_COMMIT_SHA" SOURCE_URL="$CI_PROJECT_URL"'],
        "script": ["set -eu\n" + _sh_build() + _sh_sbom_scan(trivy, syft)],
        "artifacts": {"when": "always", "expire_in": "30 days", "paths": ["sbom-$FOLDER.cdx.json"]},
        "interruptible": True,
        "timeout": "1h",
    }
    publish = {"extends": ".containerizer-image", "interruptible": False,
               "script": ["set -eu\n" + _sh_build() + _sh_sbom_scan(trivy, syft), "set -eu\n" + version + login + _sh_push()
                          + _sh_sign(sign, "wget", '"$COSIGN_PRIVATE_KEY"', spec_["tlog"])],
               "artifacts": {"when": "always", "expire_in": "90 days", "paths": ["sbom-$FOLDER.cdx.json", "image-$FOLDER.txt"]}}
    if sign == "keyless":
        publish["id_tokens"] = {"SIGSTORE_ID_TOKEN": {"aud": "sigstore"}}
    doc: dict = {}
    if not include:
        doc["stages"] = ["build"]
    doc[".containerizer-image"] = base
    doc[".containerizer-publish"] = publish
    protected = '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_COMMIT_REF_PROTECTED == "true"'
    for c in spec_["components"]:
        rp = _repo_paths(spec_, c)
        ch = None if "" in rp else {"paths": _globs(rp, "gitlab") + [own]}
        v = _component_vars(spec_, c)
        mr_rule = {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"', **({"changes": ch} if ch else {})}
        pub_rules = [{"if": f'{protected} && $CI_PIPELINE_SOURCE == "push"', **({"changes": ch} if ch else {})},
                     {"if": f'{protected} && $CI_PIPELINE_SOURCE =~ /^(web|api|schedule)$/'}]
        doc[f"containerizer:{c['folder']}:check"] = {"extends": ".containerizer-image", "stage": "build",
                                                    "variables": v, "rules": [mr_rule]}
        doc[f"containerizer:{c['folder']}:publish"] = {"extends": ".containerizer-publish", "stage": "build",
                                                      "variables": v, "rules": pub_rules}
    extra = ("# Included from .gitlab-ci.yml:  include: [{local: containerizer.gitlab-ci.yml}]\n"
             "# Its jobs use the stage `build`: if your `stages:` list does not have it, add it.\n") if include else ""
    return _header(spec_, "gitlab", extra) + _dump(doc)


# --------------------------------------------------------------------------- Azure Pipelines

AZURE_FILE = "azure-pipelines.containerizer.yml"


def azure(spec_: dict, sign: str = "none") -> str:
    trivy, syft = scanner_images()
    reg = spec_.get("registry") or AZURE_PLACEHOLDER
    branch = spec_.get("branch") or "main"
    paths = _all_paths(spec_, AZURE_FILE)
    flt = {"paths": {"include": _globs(paths, "azure")}} if paths else {}
    key = "key" if sign in ("key", "keyless") else "none"      # no OIDC token for Sigstore in Azure Pipelines
    publish_if = (f"and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/{branch}'), "
                  "ne(variables['Build.Reason'], 'PullRequest'))")
    env = {"COMMIT_SHA": "$(Build.SourceVersion)", "SOURCE_URL": "$(Build.Repository.Uri)",
           "TRIVY_SEVERITY": "$(TRIVY_SEVERITY)", "TRIVY_IGNORE_UNFIXED": "$(TRIVY_IGNORE_UNFIXED)"}
    push = ('REGISTRY="$CONTAINERIZER_REGISTRY"\n'
            'case "$REGISTRY" in *REPLACE-ME*) echo "##vso[task.logissue type=error]set the CONTAINERIZER_REGISTRY '
            'variable to your registry (and the containerizer-registry service connection)"; exit 1 ;; esac\n'
            + _sh_push()
            + _sh_sign(key, "curl", "\"$COSIGN_KEY_FILE\"", spec_["tlog"]))
    steps = [{"checkout": "self", "fetchDepth": "1", "persistCredentials": "false"},
             {"bash": "set -eu\n" + _sh_build() + _sh_sbom_scan(trivy, syft),
              "displayName": "Build, SBOM and vulnerability scan", "env": env},
             {"publish": "sbom-$(FOLDER).cdx.json", "artifact": "sbom-$(FOLDER)", "displayName": "SBOM",
              "condition": "succeededOrFailed()"},
             {"task": "Docker@2", "displayName": "Log in to the registry", "condition": publish_if,
              "inputs": {"command": "login", "containerRegistry": "${{ variables.registryConnection }}"}}]
    if key == "key":
        steps.append({"task": "DownloadSecureFile@1", "name": "cosignKey", "displayName": "cosign key",
                      "condition": publish_if, "inputs": {"secureFile": "cosign.key"}})
    push_env = {**env, "CONTAINERIZER_REGISTRY": "$(CONTAINERIZER_REGISTRY)", "VERSION": "$(VERSION)",
                "CONTAINERIZER_PUSH_LATEST": "$(CONTAINERIZER_PUSH_LATEST)"}
    if key == "key":
        push_env.update({"COSIGN_KEY_FILE": "$(cosignKey.secureFilePath)", "COSIGN_PASSWORD": "$(COSIGN_PASSWORD)"})
    steps += [{"bash": "set -eu\n" + push, "displayName": "Push" + (" and sign" if key != "none" else ""),
               "condition": publish_if, "env": push_env},
              {"task": "Docker@2", "displayName": "Log out", "condition": publish_if.replace("succeeded()", "always()", 1),
               "inputs": {"command": "logout", "containerRegistry": "${{ variables.registryConnection }}"}}]
    doc = {
        "trigger": {"branches": {"include": [branch]}, **flt},
        "pr": {"branches": {"include": [branch]}, **flt},
        "variables": [
            {"name": "registryConnection", "value": "containerizer-registry"},
            {"name": "CONTAINERIZER_REGISTRY", "value": reg},
            {"name": "TRIVY_SEVERITY", "value": severities(spec_["fail_on"])},
            {"name": "TRIVY_IGNORE_UNFIXED", "value": "true" if spec_["ignore_unfixed"] else "false"},
            {"name": "CONTAINERIZER_PUSH_LATEST", "value": "false"},
            {"name": "DOCKER_BUILDKIT", "value": "1"}],
        "pool": {"vmImage": "ubuntu-latest"},
        "jobs": [
            {"job": "version", "displayName": "Image version",
             "steps": [{"checkout": "none"},
                       {"bash": f'echo "##vso[task.setvariable variable=VERSION;isOutput=true]{SH_VERSION}"', "name": "v"}]},
            {"job": "image", "displayName": "Image", "dependsOn": "version", "timeoutInMinutes": "60",
             "variables": {"VERSION": "$[ dependencies.version.outputs['v.VERSION'] ]"},
             "strategy": {"matrix": {c["folder"].replace("-", "_"): _component_vars(spec_, c)
                                     for c in spec_["components"]}},
             "steps": steps}],
    }
    extra = ("# Azure Pipelines has no per-job path filters: a change under any component's folder rebuilds\n"
             "# every component. Pull requests from Azure Repos: add this pipeline as a build validation policy.\n")
    if not spec_.get("registry"):
        extra += f"# CONTAINERIZER_REGISTRY is a placeholder ({AZURE_PLACEHOLDER}): set it to your registry.\n"
    return _header(spec_, "azure-devops", extra) + _dump(doc)


# --------------------------------------------------------------------------- the files

def ci_file(spec_: dict, provider: str) -> str:
    if provider == "github":
        return GITHUB_FILE
    if provider == "gitlab":
        return GITLAB_INCLUDE_FILE if spec_.get("gitlab_ci") else GITLAB_FILE
    return AZURE_FILE


def files(spec_: dict, provider: str, sign: str = "none") -> dict[str, str]:
    """Repository path -> content of every file the build pipeline adds, for one provider."""
    if provider not in PROVIDERS:
        raise PipelineError(f"unknown provider {provider!r} (one of {', '.join(PROVIDERS)})")
    if sign not in SIGN_MODES:
        raise PipelineError(f"unknown signing mode {sign!r} (one of {', '.join(SIGN_MODES)})")
    if not spec_ or not spec_.get("components"):
        raise PipelineError("no component with a Linux Dockerfile: nothing to build")
    out: dict[str, str] = {}
    folder = spec_.get("folder") or FOLDER
    for c in spec_["components"]:
        base = _rel(spec_, f"{folder}/{c['folder']}/")
        out[base + "Dockerfile"] = c["dockerfile"]
        ign = c.get("dockerignore") or ""
        if ign and not ign.endswith("\n"):
            ign += "\n"
        out[base + "Dockerfile.dockerignore"] = ign + f"{PIPELINE_MARK}\n{folder}/\n"
    if provider == "github":
        out[GITHUB_FILE] = github(spec_, sign)
    elif provider == "gitlab":
        out[ci_file(spec_, provider)] = gitlab(spec_, sign, include=bool(spec_.get("gitlab_ci")))
    else:
        out[AZURE_FILE] = azure(spec_, sign)
    rp = _rel(spec_, f"{folder}/README.md")
    out[rp] = readme(spec_, provider, sorted([*out, rp]), sign)
    return dict(sorted(out.items()))


def setup_steps(spec_: dict, provider: str, sign: str = "none") -> list[str]:
    """What to set up in the provider before the first run (Markdown, one item per entry)."""
    reg = spec_.get("registry") or ""
    if provider == "github":
        s = []
        if not reg or reg.startswith("ghcr.io"):
            s.append("Images go to GitHub Container Registry (`ghcr.io/<owner>`) with the workflow's `GITHUB_TOKEN`: "
                     "nothing to set up. After the first push, link each package to the repository (package "
                     "settings) so the token keeps write access, and make it public or give the cluster a pull "
                     "secret.")
        else:
            s.append(f"Repository secrets `CONTAINERIZER_REGISTRY_USERNAME` and `CONTAINERIZER_REGISTRY_PASSWORD`: "
                     f"a push credential for `{reg.split('/', 1)[0]}` (Settings → Secrets and variables → Actions).")
        s.append("Optional repository variables: `CONTAINERIZER_REGISTRY` (another registry and path, e.g. "
                 "`registry.example.com/team`), `CONTAINERIZER_TRIVY_SEVERITY` (e.g. `HIGH,CRITICAL`), "
                 "`CONTAINERIZER_TRIVY_IGNORE_UNFIXED`, `CONTAINERIZER_PUSH_LATEST=true`.")
        if sign == "keyless":
            s.append("Keyless signing: nothing to set up; the `publish` job gets `id-token: write` and signs with "
                     "the workflow's identity (recorded in the public Rekor log).")
        elif sign == "key":
            s.append("Key-based signing: secrets `COSIGN_PRIVATE_KEY` (the contents of `cosign.key`, from "
                     "`cosign generate-key-pair`) and `COSIGN_PASSWORD`.")
        s.append("Pushes to the default branch publish only if Actions may run (Settings → Actions → General); "
                 "protect the branch so only reviewed changes publish images.")
        return s
    if provider == "gitlab":
        s = []
        if spec_.get("gitlab_ci"):
            s.append("The repository has a `.gitlab-ci.yml`: add `include: [{local: containerizer.gitlab-ci.yml}]` "
                     "to it, and the stage `build` to its `stages:` if it lists them.")
        if not reg:
            s.append("Images go to the project's container registry (`$CI_REGISTRY_IMAGE`) with the job token: "
                     "enable the Container Registry for the project (Settings → General → Visibility).")
        else:
            s.append(f"CI/CD variables `CONTAINERIZER_REGISTRY_USER` and `CONTAINERIZER_REGISTRY_PASSWORD` "
                     f"(protected and masked): a push credential for `{reg.split('/', 1)[0]}`.")
        s.append("Optional CI/CD variables: `CONTAINERIZER_REGISTRY`, `TRIVY_SEVERITY`, `TRIVY_IGNORE_UNFIXED`, "
                 "`CONTAINERIZER_PUSH_LATEST=true`.")
        s.append("The default branch must be protected: only pipelines of protected branches push.")
        s.append("Runners: the jobs use Docker-in-Docker (a `privileged` Docker executor; GitLab.com's hosted "
                 "runners have it).")
        if sign == "keyless":
            s.append("Keyless signing: nothing to set up; the publish jobs get an `id_tokens` OIDC token for "
                     "Sigstore (recorded in the public Rekor log).")
        elif sign == "key":
            s.append("Key-based signing: a protected *File* variable `COSIGN_PRIVATE_KEY` (the `cosign.key`) and a "
                     "masked variable `COSIGN_PASSWORD`.")
        return s
    s = [f"Create a Docker Registry service connection named `containerizer-registry` (Project settings → Service "
         f"connections) for {('`' + reg.split('/', 1)[0] + '`') if reg else 'your registry'}, and allow this "
         f"pipeline to use it; no token is written in the YAML.",
         "Create the pipeline from `azure-pipelines.containerizer.yml` (Pipelines → New pipeline → Existing Azure "
         "Pipelines YAML file)."]
    if not reg:
        s.append(f"Set the variable `CONTAINERIZER_REGISTRY` (now the placeholder `{AZURE_PLACEHOLDER}`) to the "
                 "registry and path, e.g. `myregistry.azurecr.io/team`: in the YAML or as a pipeline variable.")
    s.append("Pull requests of Azure Repos: add the pipeline as a build validation branch policy of the default "
             "branch (the `pr:` trigger applies to GitHub and Bitbucket repositories only).")
    if sign in ("key", "keyless"):
        s.append("Signing (with a key: Azure Pipelines has no Sigstore OIDC token): upload `cosign.key` as the "
                 "secure file `cosign.key` (Pipelines → Library) and set the secret variable `COSIGN_PASSWORD`.")
    s.append("Self-hosted agents: replace `pool: vmImage: ubuntu-latest` with `pool: name: <your pool>`; the "
             "agent needs Linux, bash and Docker.")
    return s


def readme(spec_: dict, provider: str, paths: list[str], sign: str = "none") -> str:
    reg = spec_.get("registry") or {"github": "ghcr.io/<owner>", "gitlab": "$CI_REGISTRY_IMAGE",
                                     "azure-devops": AZURE_PLACEHOLDER}[provider]
    folder = spec_.get("folder") or FOLDER
    ctx = spec_["subdir"] or "."
    L = [f"# Container image build pipeline: {spec_['app']}", "",
         f"Generated by containerizer for {PROVIDER_TEXT[provider]}. It builds the application's components from "
         f"this repository with the Dockerfiles the assessment generated, scans them and pushes them to the "
         f"registry the generated Kubernetes manifests use.", "",
         "## Files", ""]
    L += [f"- `{p}`" for p in paths]
    L += ["", "## What it does", "",
          "- Pull/merge requests: build, SBOM (Syft, CycloneDX JSON, kept as an artifact) and vulnerability scan "
          f"(Trivy: fails on {severities(spec_['fail_on'])}"
          + (", fixable ones only" if spec_["ignore_unfixed"] else "") + "). Nothing is pushed.",
          "- Default branch: the same, then push and tag `1.<yyyymmdd>.<hhmm>` (UTC) and `sha-<commit>`"
          + (", signed with cosign" if sign != "none" else "") + ".",
          "", "| Component | Dockerfile | Image |", "|---|---|---|"]
    for c in spec_["components"]:
        L.append(f"| {c['name']} | `{_rel(spec_, folder + '/' + c['folder'] + '/Dockerfile')}` | "
                 f"`{reg}/{_image_name(spec_, c)}` |")
    L += ["", f"The build context is `{ctx}` (the application's folder). `Dockerfile.dockerignore` next to each "
              "Dockerfile is the context filter (BuildKit reads `<Dockerfile>.dockerignore`), so the repository's "
              "own `.dockerignore`, if any, does not apply. Build locally the same way:", "",
          "```sh", f"DOCKER_BUILDKIT=1 docker build -f {_rel(spec_, folder + '/<component>/Dockerfile')} {ctx}", "```",
          "", "## Set up", ""]
    L += [f"{i}. {s}" for i, s in enumerate(setup_steps(spec_, provider, sign), 1)]
    L += ["", "## The GitOps sandbox", "",
          "The generated GitOps files (Flux `gitops/flux/git/image-automation.yaml`, Argo CD Image Updater "
          "annotations) follow the newest semver tag `>=1.0.0` of each image and write it to the "
          "`kustomization.yaml` of the output repository. The tags this pipeline pushes are that scheme (the "
          "same as the containerizer scans), so a push to the default branch reaches the sandbox without "
          "another step, as long as both use the same registry.", "",
          "## Pins", "",
          "Scanner images are pinned by version and digest, GitHub actions by commit SHA (the tag in the "
          "comment), cosign by its release checksum. Update them by generating the pipeline again with a newer "
          "containerizer (`containerizer pipeline`), or by hand: `docker buildx imagetools inspect <image>:<tag>` "
          "for a digest, `git ls-remote https://github.com/<action> refs/tags/<tag>` for an action.", "",
          "More: https://containerizer.eu/build-pipelines/", ""]
    return "\n".join(L)


def providers_for(spec_: dict, provider: str | None = None) -> list[str]:
    p = provider or spec_.get("detected")
    return [p] if p in PROVIDERS else list(PROVIDERS)


def write_output(out: Path, spec_: dict, provider: str | None = None, sign: str = "none") -> list[Path]:
    """`out/pipeline/<provider>/<repository layout>` and `out/pipeline/README.md` (how to add it)."""
    base = Path(out) / OUTPUT_DIR
    if base.exists():
        shutil.rmtree(base)
    written = []
    provs = providers_for(spec_, provider)
    for p in provs:
        for rel, text in files(spec_, p, sign).items():
            f = base / p / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
            written.append(f)
    which = (f"The application's code is on {HOST_TEXT[provs[0]]}" if len(provs) == 1 else
             "Where the application's code lives is not known, so there is a version for each provider")
    idx = [f"# Build pipeline: {spec_['app']}", "",
           f"{which}: copy the files of `{'`, `'.join(provs)}` into the root of the application's repository "
           "(the folders mirror the repository), commit them on a branch and open a pull request. The "
           "`README.md` in its `" + (spec_.get('folder') or FOLDER) + "/` folder says which secrets or "
           "variables to create first.", "",
           "Or download the same files as a patch (`git am`) from the application's results page "
           "(Build pipeline), or make it from a checkout with `containerizer pipeline <path> --patch`.", "",
           "More: https://containerizer.eu/build-pipelines/", ""]
    if spec_.get("existing"):
        idx[4:4] = ["These files exist in the repository already, check them before copying: "
                    + ", ".join(f"`{x}`" for x in spec_["existing"]), ""]
    (base / "README.md").write_text("\n".join(idx))
    written.append(base / "README.md")
    return written


def refresh_dockerfiles(out: Path) -> None:
    """After the security gate changed a component's Dockerfile (OS package upgrades, build fixes): the copies
    in `out/pipeline/` follow."""
    base = Path(out) / OUTPUT_DIR
    if not base.is_dir():
        return
    for f in base.rglob("Dockerfile"):
        src = Path(out) / f.parent.name / "Dockerfile"
        if src.is_file() and f.parent.parent.name in (FOLDER, ALT_FOLDER) and f.read_text() != src.read_text():
            f.write_text(src.read_text())


# --------------------------------------------------------------------------- the patch

SUBJECT = "Container image build pipeline ({provider})"


def commit_message(spec_: dict, provider: str, paths: list[str]) -> tuple[str, str]:
    body = (f"Build, scan (Trivy) and SBOM (Syft) the container images of {spec_['app']} on pull/merge requests;\n"
            f"push them from the default branch, tagged 1.<yyyymmdd>.<hhmm> and sha-<commit>.\n\n"
            f"Generated by containerizer (deterministic, no LLM). Before the first run, see\n"
            f"{_rel(spec_, (spec_.get('folder') or FOLDER) + '/README.md')}.\n\nFiles:\n"
            + "".join(f"  {p}\n" for p in paths))
    return SUBJECT.format(provider=PROVIDER_TEXT[provider]), body


def make_patch(file_map: dict[str, str], subject: str, body: str, repo: Path | None = None) -> bytes:
    """A `git am` patch that adds `file_map`. With `repo` (a scratch checkout at the assessed commit, which
    is changed) the patch is made on it; without, on an empty commit: the patch only adds files, so it
    applies to any commit that does not have them."""
    from . import refactor as rf
    with tempfile.TemporaryDirectory(prefix="cz-pipeline-") as t:
        if repo is None:
            repo = Path(t) / "repo"
            repo.mkdir()
            rf.git(["init", "--quiet"], cwd=repo)
            rf.git(["commit", "--quiet", "--allow-empty", "-m", "base"], cwd=repo)
        for rel, text in file_map.items():
            if rf.safe_rel(rel) is None:
                raise PipelineError(f"bad path {rel!r}")
            f = Path(repo) / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        patch = rf.make_patch(Path(repo), subject, body)
    if patch is None:
        raise PipelineError("the files are in the repository already: nothing to add")
    return patch


def patch_for(spec_: dict, provider: str, sign: str = "none", repo: Path | None = None) -> bytes:
    fm = files(spec_, provider, sign)
    subject, body = commit_message(spec_, provider, list(fm))
    return make_patch(fm, subject, body, repo)


def patch_filename(app: str, provider: str) -> str:
    from .refactor import slug
    return f"{slug(app)}-build-pipeline-{provider}.patch"


def tarball(file_map: dict[str, str], prefix: str) -> bytes:
    """The files as a .tar.gz (deterministic: fixed times and owners)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tf:
        for rel, text in file_map.items():
            data = text.encode()
            ti = tarfile.TarInfo(f"{prefix}/{rel}")
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0o644, 0, 0, "", ""
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def check_patch(patch: bytes, source: dict, commit: str | None) -> tuple[bool, str]:
    """Apply the patch with `git am` on a clean scratch checkout of `source` at `commit` (refactor.checkout)."""
    from . import refactor as rf
    with tempfile.TemporaryDirectory(prefix="cz-pipeline-check-") as t:
        repo, _ = rf.checkout(source, commit, Path(t) / "repo")
        return rf.apply_patch(repo, patch)


# --------------------------------------------------------------------------- CLI

def cli(args) -> int:
    """containerizer pipeline <app-path> [--provider P] [--registry R] [--out DIR] [--patch] [--sign MODE]"""
    import sys
    from . import refactor as rf
    from .assess import assess
    from .generate import generate_app
    from .rules import load_rules

    app = Path(args.path).resolve()
    if not app.is_dir():
        print(f"error: {app} is not a folder", file=sys.stderr)
        return 2
    a = assess(app, load_rules())
    with tempfile.TemporaryDirectory(prefix="cz-pipeline-gen-") as t:
        gen = Path(t) / "gen"
        generate_app(a, gen, registry=args.registry or "registry.local")
        sp = getattr(a, "build_pipeline", None) or spec(a, gen, args.registry or "registry.local")
    if not sp:
        print(f"{a.name}: no component with a Linux Dockerfile, so no build pipeline", file=sys.stderr)
        return 1
    if args.registry:
        sp["registry"] = "" if args.registry.rstrip("/") in UNKNOWN_REGISTRIES else args.registry.rstrip("/")
    provs = providers_for(sp, args.provider)
    out = Path(args.out) if args.out else Path.cwd()
    if not args.provider and not sp.get("detected"):
        print(f"{a.name}: the repository's provider is not known (remote {sp.get('repository_url') or 'none'}): "
              f"writing all three; choose with --provider")
    for p in provs:
        print(f"{a.name}: {PROVIDER_TEXT[p]} pipeline for {len(sp['components'])} component(s)")
    if sp.get("existing"):
        print("warning: already in the repository: " + ", ".join(sp["existing"]), file=sys.stderr)
    if not args.patch:
        written = write_output(out, sp, args.provider, args.sign)
        print(f"{len(written)} files -> {out / OUTPUT_DIR}")
        return 0
    top = _git(app, "rev-parse", "--show-toplevel")
    commit = _git(app, "rev-parse", "HEAD") if top else ""
    out.mkdir(parents=True, exist_ok=True)
    rc = 0
    for p in provs:
        source = {"type": "local", "path": top, "git": True}
        try:
            with tempfile.TemporaryDirectory(prefix="cz-pipeline-co-") as t:
                if top and commit:
                    repo, _ = rf.checkout(source, commit, Path(t) / "repo")
                    patch = patch_for(sp, p, args.sign, repo)
                else:
                    patch = patch_for(sp, p, args.sign)
            if top and commit:
                ok, log = check_patch(patch, source, commit)
                if not ok:
                    print(f"error: the patch does not apply to {commit[:12]}:\n{log}", file=sys.stderr)
                    rc = 1
        except (rf.RefactorError, PipelineError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        f = out / patch_filename(a.name, p)
        f.write_bytes(patch)
        print(f"{f} ({'git am applies it to ' + commit[:12] if top and commit else 'adds new files only'})")
    return rc
