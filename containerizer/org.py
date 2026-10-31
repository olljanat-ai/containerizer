"""Organization-wide run: every Git repository of one Azure DevOps, GitHub or GitLab organization.

For each repository: clone (shallow, read-only token), skip it when it has not changed for
`stale_days` or already has a Dockerfile, run the one-shot `analyze` (assess, build and run every
feasible component, learn, re-assess), keep only the components rated A (lift and shift, stateless,
confirmed by the build-and-run when verification is on), pass them through the security gate (lint,
image scan, hardened run), push their images to the registry and write the generated files to the
output Git repository at

    <Organization>/<Project>/<Repository>/<component>/

GitHub has no project level and GitLab projects can sit directly in the group: those use the
project folder `_`. GitLab subgroups become one folder (`team/sub` -> `team--sub`).

The output repository also gets `sandbox/`: an Argo CD app-of-apps and a Flux root Kustomization
that deploy every generated app to a sandbox cluster through the per-app GitOps files.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from .orgsource import (NO_PROJECT, REDACT, SourceError, SourceRepo, clone, existing_dockerfiles, git, head_commit,
                        provider, read_token, strip_userinfo)

RESERVED_NS = {"default", "argocd", "flux-system", "cert-manager", "ingress-nginx", "kyverno", "gatekeeper-system"}
OK_VERIFY = ("ok", "ok-external")
SANDBOX = "sandbox"
GIT_USER = ("containerizer", "containerizer@users.noreply.invalid")


@dataclass
class OrgOptions:
    provider: str
    org: str
    registry: str
    api_url: str | None = None
    token_env: str | None = None
    output_repo: str | None = None
    output_dir: str | None = None
    output_branch: str = "main"
    output_token_env: str = "OUTPUT_GIT_TOKEN"
    output_username: str = "x-access-token"
    push: bool = True                   # push commits of the output repository
    push_images: bool = True
    tag: str | None = None
    image_pull_secret: str | None = None
    cosign_key: str | None = None
    include: str | None = None
    exclude: str | None = None
    skip_forks: bool = False
    stale_days: int = 183
    max_repos: int = 0
    ai: bool = False
    model: str | None = None
    verify: bool = True
    gate: bool = True
    scanner: str | None = None
    fail_on: str | None = None
    timeout: int = 1800
    pin: bool = False
    verify_commits: bool = False
    sql: str | None = None
    work_dir: str = ".work/org"
    keep_work: bool = False
    dry_run: bool = False
    now: datetime | None = None


@dataclass
class RepoResult:
    provider: str
    org: str
    project: str
    repo: str
    status: str                       # deployed | no-a-components | skipped-* | error
    reason: str = ""
    web_url: str = ""
    clone_url: str = ""
    branch: str = ""
    commit: str = ""
    last_commit: str = ""
    app: str = ""                     # namespace / application name in the cluster
    path: str = ""                    # folder in the output repository
    rating: str = ""
    components: list = field(default_factory=list)
    excluded: list = field(default_factory=list)
    processed_at: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------- naming

def segment(s: str) -> str:
    """A folder name from an organization, project or repository name (spaces kept, no path tricks)."""
    s = re.sub(r"[^\w .\-]", "_", s.replace("/", "--")).strip().strip(".")
    return s or "_"


def _dns(s: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", s.lower().replace(".", "-").replace("_", "-")).strip("-")


def app_name(project: str, repo: str) -> str:
    """Stable, cluster-unique app name (Kubernetes namespace): <project>-<repo>, or <repo> without a project."""
    base = _dns(repo) if project == NO_PROJECT else _dns(f"{project}-{repo}")
    base = re.sub(r"-{2,}", "-", base) or "app"
    if base in RESERVED_NS or base.startswith(("kube-", "openshift")):
        base = f"app-{base}"
    if len(base) > 63:
        h = hashlib.sha1(f"{project}/{repo}".encode()).hexdigest()[:8]
        base = f"{base[:54].rstrip('-')}-{h}"
    return base


def unique_names(repos: list[SourceRepo]) -> dict[str, str]:
    """key -> app name; names that would collide (a-b/c vs a/b-c) get a hash suffix."""
    names = {r.key: app_name(r.project, r.name) for r in repos}
    seen: dict[str, list[str]] = {}
    for k, n in names.items():
        seen.setdefault(n, []).append(k)
    for n, keys in seen.items():
        if len(keys) > 1:
            for k in keys:
                h = hashlib.sha1(k.encode()).hexdigest()[:8]
                names[k] = f"{n[:54].rstrip('-')}-{h}"
    return names


def default_tag(now: datetime) -> str:
    """Semver tag for this run (the GitOps image automation ranges are semver): 1.<yyyymmdd>.<hhmm>."""
    return f"1.{now:%Y%m%d}.{int(now.strftime('%H%M'))}"


# --------------------------------------------------------------------------- selection

def component_rating(a, c) -> str:
    """The app rating of a one-component app: the same A-E scale (incl. the stateless cap for A)."""
    return dataclasses.replace(a, components=[c]).rating


def select_components(a, verified: bool) -> tuple[list, list[dict]]:
    """Components rated A that a Linux image can be generated for (and that built and ran, when verified)."""
    from .generate import buildable
    ver = {r.get("component"): r for r in (getattr(a, "verification", None) or [])}
    keep, excluded = [], []
    for c in a.components:
        if c.tier != "server":
            continue
        rating = component_rating(a, c)
        why = ""
        if rating != "A":
            why = f"rated {rating} ({c.verdict})"
        elif getattr(c, "stateless", True) is False:
            why = "keeps local state"
        elif not buildable(c):
            why = "no Linux container build for this component"
        elif verified and (ver.get(c.name) or {}).get("status") not in OK_VERIFY:
            why = f"build-and-run: {(ver.get(c.name) or {}).get('status', 'not run')}"
        if why:
            excluded.append({"component": c.name, "reason": why})
        else:
            keep.append(c)
    return keep, excluded


def gate_failure(comp: dict) -> str:
    if comp.get("build_error"):
        return "image build failed"
    errs = [v for v in comp.get("lint", []) if v.get("severity") == "error"]
    if errs:
        return f"manifest/Dockerfile lint: {errs[0].get('check')}: {errs[0].get('message')}"[:300]
    for s in comp.get("scans", []):
        if not s.get("passed"):
            if s.get("error"):
                return f"{s.get('kind', 'image')} scan failed: {s['error']}"[:300]
            return f"{len(s.get('blocking', []))} fixable vulnerabilities at or above the gate threshold ({s.get('kind')})"
    if (comp.get("run") or {}).get("status") == "hardening-failure":
        return "does not run with the hardened pod security context"
    return ""


# --------------------------------------------------------------------------- images

class Registry:
    """docker push with credentials kept out of ~/.docker: REGISTRY_USERNAME/REGISTRY_PASSWORD go to
    a temporary --config directory (password on stdin), removed at the end."""

    def __init__(self, registry: str):
        self.registry = registry.rstrip("/")
        self.host = self.registry.split("/", 1)[0]
        self.config: str | None = None
        user, pw = os.environ.get("REGISTRY_USERNAME"), os.environ.get("REGISTRY_PASSWORD")
        if user and pw:
            REDACT.add(pw)
            self.config = tempfile.mkdtemp(prefix="cz-docker-")
            os.chmod(self.config, 0o700)
            p = subprocess.run(["docker", "--config", self.config, "login", self.host, "--username", user,
                                "--password-stdin"], input=pw, capture_output=True, text=True)
            if p.returncode != 0:
                self.close()
                raise SourceError(f"docker login {self.host}: {REDACT(p.stderr.strip())[-300:]}")

    def _docker(self, *args: str, timeout: int = 1800) -> subprocess.CompletedProcess:
        cfg = ["--config", self.config] if self.config else []
        return subprocess.run(["docker", *cfg, *args], capture_output=True, text=True, timeout=timeout, errors="replace")

    def push(self, local: str, ref: str, extra_tags: list[str] = ()) -> str:
        """Tag and push; returns the pushed digest."""
        digest = ""
        for r in [ref, *extra_tags]:
            if subprocess.run(["docker", "tag", local, r], capture_output=True).returncode != 0:
                raise SourceError(f"docker tag {local} {r} failed")
            p = self._docker("push", r)
            if p.returncode != 0:
                raise SourceError(f"docker push {r}: {REDACT((p.stderr or p.stdout).strip())[-400:]}")
            m = re.search(r"digest: (sha256:[0-9a-f]{64})", p.stdout)
            digest = digest or (m.group(1) if m else "")
        return digest

    def sign(self, ref: str, digest: str, key: str) -> str:
        if not shutil.which("cosign"):
            return "cosign not installed"
        env = {**os.environ, **({"DOCKER_CONFIG": self.config} if self.config else {})}
        p = subprocess.run(["cosign", "sign", "--yes", "--key", key, f"{ref.rsplit(':', 1)[0]}@{digest}"],
                           capture_output=True, text=True, env=env, timeout=600)
        return "signed" if p.returncode == 0 else f"cosign failed: {REDACT(p.stderr.strip())[-200:]}"

    def close(self) -> None:
        if self.config:
            shutil.rmtree(self.config, ignore_errors=True)
            self.config = None


# --------------------------------------------------------------------------- output repository

PULL_SECRET_PATCHES = [("Deployment", "/spec/template/spec"), ("StatefulSet", "/spec/template/spec"),
                       ("Job", "/spec/template/spec"), ("CronJob", "/spec/jobTemplate/spec/template/spec")]


def add_pull_secret(kustomization: Path, secret: str) -> None:
    """imagePullSecrets on every workload, as kustomize patches (the $imagepolicy comments stay intact)."""
    text = kustomization.read_text()
    if re.search(r"^patches:", text, re.M):
        raise SourceError(f"{kustomization} already has patches; add imagePullSecrets by hand")
    lines = ["patches:"]
    for kind, path in PULL_SECRET_PATCHES:
        lines += [f"  - target:", f"      kind: {kind}", "    patch: |-", "      - op: add",
                  f"        path: {path}/imagePullSecrets", "        value:", f"          - name: {secret}"]
    kustomization.write_text(text.rstrip("\n") + "\n" + "\n".join(lines) + "\n")


def gitops_kustomizations(app_dir: Path) -> None:
    """Kustomizations over the per-app GitOps files, so sandbox/ can include each app as a directory."""
    g = app_dir / "gitops"
    k = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization"}
    if (g / "argocd" / "application.yaml").exists():
        (g / "argocd" / "kustomization.yaml").write_text(yaml.safe_dump(
            {**k, "resources": ["project.yaml", "application.yaml"]}, sort_keys=False))
    if (g / "flux" / "tenant.yaml").exists():
        (g / "flux" / "kustomization.yaml").write_text(yaml.safe_dump(
            {**k, "resources": ["tenant.yaml", "git/sync.yaml"]}, sort_keys=False))


def _apps_in(root: Path) -> list[tuple[str, Path, dict]]:
    """(relative app folder, folder, containerizer.json) of every deployed app in the output repository."""
    out = []
    for meta in sorted(root.glob("*/*/*/containerizer.json")):
        if meta.parts[len(root.parts)] == SANDBOX:
            continue
        try:
            doc = json.loads(meta.read_text())
        except ValueError:
            continue
        if (meta.parent / "gitops" / "argocd" / "kustomization.yaml").exists():
            out.append((meta.parent.relative_to(root).as_posix(), meta.parent, doc))
    return out


def write_sandbox(root: Path, git_url: str, branch: str) -> list[str]:
    """sandbox/: Argo CD app-of-apps and Flux root Kustomization over every app in the repository."""
    from .gitops import ARGO_API, ARGO_NS, FLUX_NS, IN_CLUSTER, KUSTOMIZE_API, SOURCE_API
    apps = _apps_in(root)
    sb = root / SANDBOX
    if sb.exists():
        shutil.rmtree(sb)
    (sb / "argocd" / "apps").mkdir(parents=True)
    (sb / "flux" / "apps").mkdir(parents=True)
    k = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization"}
    labels = {"app.kubernetes.io/part-of": "containerizer-sandbox", "app.kubernetes.io/managed-by": "containerizer"}
    name = "containerizer-sandbox"

    def dump(docs):
        return "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)

    (sb / "argocd" / "apps" / "kustomization.yaml").write_text(yaml.safe_dump(
        {**k, "resources": [f"../../../{rel}/gitops/argocd" for rel, _, _ in apps]}, sort_keys=False))
    (sb / "argocd" / "bootstrap.yaml").write_text(dump([
        {"apiVersion": ARGO_API, "kind": "AppProject",
         "metadata": {"name": name, "namespace": ARGO_NS, "labels": labels},
         "spec": {"description": "containerizer sandbox: creates only the per-app AppProjects and Applications",
                  "sourceRepos": [git_url],
                  "destinations": [{"server": IN_CLUSTER, "namespace": ARGO_NS}],
                  "clusterResourceWhitelist": [],
                  "namespaceResourceWhitelist": [{"group": "argoproj.io", "kind": "AppProject"},
                                                 {"group": "argoproj.io", "kind": "Application"}],
                  "orphanedResources": {"warn": True}}},
        {"apiVersion": ARGO_API, "kind": "Application",
         "metadata": {"name": name, "namespace": ARGO_NS, "labels": labels,
                      "finalizers": ["resources-finalizer.argocd.argoproj.io"]},
         "spec": {"project": name,
                  "source": {"repoURL": git_url, "targetRevision": branch, "path": f"{SANDBOX}/argocd/apps"},
                  "destination": {"server": IN_CLUSTER, "namespace": ARGO_NS},
                  "syncPolicy": {"automated": {"prune": True, "selfHeal": True},
                                 "syncOptions": ["ServerSideApply=true", "PruneLast=true"],
                                 "retry": {"limit": 5, "backoff": {"duration": "10s", "factor": 2,
                                                                   "maxDuration": "5m"}}}}},
    ]))
    (sb / "flux" / "apps" / "kustomization.yaml").write_text(yaml.safe_dump(
        {**k, "resources": [f"../../../{rel}/gitops/flux" for rel, d, _ in apps
                            if (d / "gitops" / "flux" / "kustomization.yaml").exists()]}, sort_keys=False))
    (sb / "flux" / "bootstrap.yaml").write_text(dump([
        {"apiVersion": SOURCE_API, "kind": "GitRepository",
         "metadata": {"name": name, "namespace": FLUX_NS, "labels": labels},
         "spec": {"interval": "5m", "url": git_url, "ref": {"branch": branch}, "secretRef": {"name": f"{name}-git"}}},
        {"apiVersion": KUSTOMIZE_API, "kind": "Kustomization",
         "metadata": {"name": name, "namespace": FLUX_NS, "labels": labels},
         "spec": {"interval": "10m", "retryInterval": "2m", "timeout": "5m", "prune": True, "wait": False,
                  "sourceRef": {"kind": "GitRepository", "name": name}, "path": f"./{SANDBOX}/flux/apps"}},
    ]))
    namespaces = sorted({doc.get("app") for _, _, doc in apps if doc.get("app")})
    (sb / "namespaces.txt").write_text("".join(f"{n}\n" for n in namespaces))
    (sb / "README.md").write_text(sandbox_readme(git_url, branch, apps))
    return namespaces


def sandbox_readme(git_url: str, branch: str, apps) -> str:
    rows = "\n".join(f"| `{doc.get('app')}` | [{rel}]({rel.replace(' ', '%20')}/) | "
                     f"{', '.join(c['component'] for c in doc.get('components', []))} |" for rel, _, doc in apps)
    return f"""# Sandbox deployment

Every app in this repository that has components rated **A** (lift and shift, stateless, built,
run and passed the security gate). Pick Argo CD **or** Flux, not both. Generated by
`containerizer org`; do not edit, the next run rewrites this folder.

| Namespace | Folder | Components |
| --- | --- | --- |
{rows}

## Argo CD

```sh
argocd repo add {git_url} --username <user> --password <read-only token>   # private repository
kubectl apply -f {SANDBOX}/argocd/bootstrap.yaml
```

`bootstrap.yaml` is an app-of-apps: AppProject `containerizer-sandbox` may only create AppProjects and
Applications in `argocd`, from this repository. Each app then has its own AppProject pinned to its
namespace and generated kinds (see `<app>/gitops/README.md`).

## Flux

```sh
kubectl -n flux-system create secret generic containerizer-sandbox-git \\
  --from-literal=username=git --from-literal=password=<read-only token>
kubectl apply -f {SANDBOX}/flux/bootstrap.yaml
# each app reconciles as its own namespace-scoped ServiceAccount from its own source:
while read -r ns; do
  kubectl -n "$ns" create secret generic "$ns-git" \\
    --from-literal=username=git --from-literal=password=<read-only token>
done < {SANDBOX}/namespaces.txt
```

The root Kustomization applies each app's `gitops/flux/tenant.yaml` (namespace with Pod Security
"restricted", ServiceAccount, namespace-only RoleBinding) and `gitops/flux/git/sync.yaml`. Image
automation (`gitops/flux/git/image-automation.yaml`) is left out: it needs a write key.

## Cluster prerequisites

- Pulling images: if the registry is private, create the pull secret named in the run (`--image-pull-secret`)
  in every namespace listed in `namespaces.txt`, or give the nodes registry credentials.
- Secrets: the apps read them through External Secrets from a `ClusterSecretStore` named `app-secrets`
  (keys `<app>/<component>`), see each app's `HARDENING.md`.
- Signed images: each app's `cluster/verify-images.yaml` (Kyverno) only admits images signed with your
  cosign key; images were signed only if the run had `--cosign-key`.
"""


def org_index(root: Path, org_dir: Path, results: list[dict], run: dict) -> None:
    """<Organization>/README.md and org-run.json: every repository and what happened to it."""
    index = org_dir / "org-run.json"
    prev = {}
    if index.exists():
        try:
            prev = {(r["project"], r["repo"]): r for r in json.loads(index.read_text()).get("repositories", [])}
        except (ValueError, KeyError):
            prev = {}
    for r in results:
        prev[(r["project"], r["repo"])] = r
    repos = sorted(prev.values(), key=lambda r: (r["project"].lower(), r["repo"].lower()))
    org_dir.mkdir(parents=True, exist_ok=True)
    index.write_text(json.dumps({"run": run, "repositories": repos}, indent=2, default=str) + "\n")
    count = {}
    for r in repos:
        count[r["status"]] = count.get(r["status"], 0) + 1
    lines = [f"# {run['org']} ({run['provider']})", "",
             f"Last run {run['started']} with tag `{run['tag']}`, images in `{run['registry']}`. "
             "Only components rated A are deployed.", "",
             " · ".join(f"{k}: {v}" for k, v in sorted(count.items())), "",
             "| Project | Repository | Status | Rating | Components deployed | Not deployed |",
             "| --- | --- | --- | --- | --- | --- |"]
    for r in repos:
        comps = ", ".join(f"`{c['component']}`" for c in r.get("components", []))
        exc = "; ".join(f"{e['component']}: {e['reason']}" for e in r.get("excluded", []))
        repo = f"[{r['repo']}]({r['web_url']})" if r.get("web_url") else r["repo"]
        status = f"[{r['status']}]({r['path'].split('/', 1)[1].replace(' ', '%20')}/)" if r.get("path") and \
            r["status"] == "deployed" else r["status"]
        reason = f" ({r['reason']})" if r.get("reason") else ""
        lines.append(f"| {r['project']} | {repo} | {status}{reason} | {r.get('rating', '')} | {comps} | "
                     f"{exc.replace('|', '/')} |")
    (org_dir / "README.md").write_text("\n".join(lines) + "\n")


class Output:
    """The output Git repository: cloned (token from the environment) or a local folder."""

    def __init__(self, o: OrgOptions, work: Path):
        self.o = o
        self.header = ""
        self.push = o.push
        if o.output_repo:
            self.url = strip_userinfo(o.output_repo)
            tok = read_token("", o.output_token_env)
            if tok:
                import base64
                REDACT.add(tok, o.output_username)
                self.header = "Authorization: Basic " + base64.b64encode(f"{o.output_username}:{tok}".encode()).decode()
            self.root = work / "output"
            if self.root.exists():
                shutil.rmtree(self.root)
            try:
                clone(self.url, self.root, o.output_branch, self.header)
            except SourceError as e:
                if "not found in upstream" not in str(e) and "Remote branch" not in str(e):
                    raise
                clone(self.url, self.root, "", self.header)       # new branch in an existing (maybe empty) repo
                git(["checkout", "-B", o.output_branch], cwd=self.root)
            self.git = True
        else:
            self.root = Path(o.output_dir or "containerizer-org").resolve()
            self.root.mkdir(parents=True, exist_ok=True)
            self.git = (self.root / ".git").exists()
            remote = git(["remote", "get-url", "origin"], cwd=self.root, check=False).strip() if self.git else ""
            self.url = strip_userinfo(remote) if remote else "https://git.example.com/platform/sandbox-deployments.git"
            self.push = self.push and bool(remote)

    def commit(self, message: str) -> bool:
        if not self.git:
            return False
        git(["add", "-A"], cwd=self.root)
        if not git(["status", "--porcelain"], cwd=self.root).strip():
            return False
        name = os.environ.get("GIT_AUTHOR_NAME") or GIT_USER[0]
        email = os.environ.get("GIT_AUTHOR_EMAIL") or GIT_USER[1]
        git(["-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-q", "-m", message], cwd=self.root)
        if self.push:
            for attempt in range(3):
                try:
                    git(["push", "-q", "origin", f"HEAD:{self.o.output_branch}"], cwd=self.root, url=self.url,
                        header=self.header)
                    break
                except SourceError:
                    if attempt == 2:
                        raise
                    # someone else pushed: rebase our generated commit on top and retry
                    git(["pull", "-q", "--rebase", "--depth", "50", "origin", self.o.output_branch], cwd=self.root,
                        url=self.url, header=self.header, check=False)
        return True


# --------------------------------------------------------------------------- one repository

def _clean_generated(d: Path) -> None:
    for f in list(d.rglob("*.log")):
        f.unlink()


def process_repo(r: SourceRepo, prov, o: OrgOptions, app: str, out: Output, work: Path, reg: Registry | None,
                 tag: str, cutoff: datetime | None, rules_reset) -> RepoResult:
    from .analyze import analyze_app
    from .generate import generate_app, k8s_name
    from .gitops import GitOpsOptions

    org_seg, proj_seg, repo_seg = segment(o.org), segment(r.project), segment(r.name)
    rel = f"{org_seg}/{proj_seg}/{repo_seg}"
    dest = out.root / rel
    res = RepoResult(provider=r.provider, org=o.org, project=r.project, repo=r.name, status="error",
                     web_url=r.web_url, clone_url=r.clone_url, branch=r.default_branch, app=app,
                     processed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def skip(status: str, reason: str) -> RepoResult:
        res.status, res.reason = status, reason
        if not o.dry_run and dest.exists():                        # it no longer qualifies: stop deploying it
            shutil.rmtree(dest)
        return res

    if r.archived:
        return skip("skipped-archived", "archived or disabled")
    if r.empty:
        return skip("skipped-empty", "empty repository")
    if o.skip_forks and r.fork:
        return skip("skipped-fork", "fork")
    if cutoff and r.last_activity and r.last_activity < cutoff:
        # the provider's activity date covers every push, so the default branch is at least as old
        return skip("skipped-stale", f"no update since {r.last_activity:%Y-%m-%d}")
    if cutoff and not r.last_activity:
        try:
            lc = prov.last_commit(r)
        except SourceError:
            lc = None
        if lc and lc < cutoff:
            res.last_commit = lc.isoformat()
            return skip("skipped-stale", f"last commit {lc:%Y-%m-%d}")
    if o.dry_run:
        res.status, res.reason = "would-process", ""
        return res

    src = work / "src" / app
    if src.exists():
        shutil.rmtree(src)
    src.parent.mkdir(parents=True, exist_ok=True)
    try:
        clone(r.clone_url, src, r.default_branch, prov.git_header())
    except SourceError as e:
        res.reason = str(e)
        return res                               # keep whatever was deployed before
    try:
        res.commit, when = head_commit(src)
        res.last_commit = when.isoformat() if when else ""
        if cutoff and when and when < cutoff:
            return skip("skipped-stale", f"last commit on {r.default_branch or 'default branch'} {when:%Y-%m-%d}")
        dockerfiles = existing_dockerfiles(src)
        if dockerfiles:
            return skip("skipped-dockerfile", "already has " + ", ".join(dockerfiles[:3])
                        + (" ..." if len(dockerfiles) > 3 else ""))

        gitops = GitOpsOptions(git_url=out.url, branch=o.output_branch, path=rel, verify_commits=o.verify_commits)
        scratch = work / "analyze"
        if scratch.exists():
            shutil.rmtree(scratch)
        rules_reset()
        a = analyze_app(src, scratch, ai=o.ai, model=o.model, verify=o.verify, registry=o.registry, pin=o.pin,
                        timeout=o.timeout, gitops=gitops)
        res.rating = a.rating
        if o.sql or os.environ.get("CONTAINERIZER_SQL"):
            from .sqlstore import store_results
            store_results(o.sql, [a], [src])
        keep, res.excluded = select_components(a, o.verify)
        gen = work / "gen" / app
        names = {k8s_name(c.name): c for c in keep}
        while keep:
            if gen.exists():
                shutil.rmtree(gen)
            fa = dataclasses.replace(a, components=keep)
            if not o.gate:
                generate_app(fa, gen, registry=o.registry, pin=o.pin, gitops=gitops, tag=tag)
                break
            from .harden import security
            from .imagescan import gate_app
            g = gate_app(fa, gen, build=True, scan=True, run=True, registry=o.registry, pin=o.pin, gitops=gitops,
                         tag=tag, scanner=o.scanner or security()["scan"].get("default_scanner", "auto"),
                         fail_on=o.fail_on)
            failed = {c["component"]: gate_failure(c) for c in g["components"] if gate_failure(c)}
            if not failed:
                break
            for cname, why in failed.items():
                res.excluded.append({"component": names[cname].name if cname in names else cname,
                                     "reason": f"security gate: {why}"})
            keep = [c for c in keep if k8s_name(c.name) not in failed]
        if not keep:
            return skip("no-a-components", f"none of {len(res.excluded)} server components qualifies" if res.excluded
                        else "no server component")

        # images: built by the gate (or here), pushed under <registry>/<app>/<component>:<tag>
        from .imagescan import build_image
        comps = []
        for c in keep:
            cn = k8s_name(c.name)
            cdir = gen / cn
            local = f"containerizer/{k8s_name(a.name)}-{cn}:gate"
            if not o.gate and o.push_images:
                ok, tail = build_image(src, cdir, local, timeout=o.timeout)
                if not ok:
                    raise SourceError(f"{c.name}: image build failed: {tail[-300:]}")
            ref = f"{o.registry.rstrip('/')}/{k8s_name(a.name)}/{cn}:{tag}"
            entry = {"component": c.name, "folder": cn, "image": ref, "rating": "A", "verdict": c.verdict,
                     "role": c.role, "project": c.project.rel,
                     "verification": next((v.get("status") for v in getattr(a, "verification", None) or [] if v.get("component") == c.name),
                                          "not run")}
            if o.push_images and reg:
                entry["digest"] = reg.push(local, ref, [f"{ref.rsplit(':', 1)[0]}:git-{res.commit[:12]}"]
                                           if res.commit else [])
                if o.cosign_key and entry["digest"]:
                    entry["signature"] = reg.sign(ref, entry["digest"], o.cosign_key)
            comps.append(entry)
        res.components = comps

        _clean_generated(gen)
        if o.image_pull_secret and (gen / "kustomization.yaml").exists():
            add_pull_secret(gen / "kustomization.yaml", o.image_pull_secret)
        gitops_kustomizations(gen)
        res.status, res.path = "deployed", rel
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(gen, dest)
        (dest / "containerizer.json").write_text(json.dumps(res.to_dict(), indent=2, default=str) + "\n")
        return res
    finally:
        if not o.keep_work:
            shutil.rmtree(src, ignore_errors=True)


# --------------------------------------------------------------------------- the run

def run_org(o: OrgOptions, log=print) -> list[RepoResult]:
    from .confidence import reset_cache

    now = o.now or datetime.now(timezone.utc)
    tag = o.tag or default_tag(now)
    cutoff = now - timedelta(days=o.stale_days) if o.stale_days else None
    token = read_token(o.provider, o.token_env)
    if not token:
        from .orgsource import TOKEN_ENVS
        print(f"warning: no token in {o.token_env or ' / '.join(TOKEN_ENVS[o.provider])}: "
              "only public repositories are visible", file=sys.stderr)
    prov = provider(o.provider, o.org, token, o.api_url)
    work = Path(o.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o700)

    repos = list(prov.repos())
    inc = re.compile(o.include) if o.include else None
    exc = re.compile(o.exclude) if o.exclude else None
    repos = [r for r in repos if (not inc or inc.search(r.key)) and not (exc and exc.search(r.key))]
    if o.max_repos:
        repos = repos[:o.max_repos]
    names = unique_names(repos)
    log(f"{o.org}: {len(repos)} repositories")

    out = Output(o, work) if not o.dry_run else None
    reg = Registry(o.registry) if (o.push_images and not o.dry_run) else None
    run = {"provider": o.provider, "org": o.org, "registry": o.registry, "tag": tag,
           "started": now.isoformat(timespec="seconds"), "stale_days": o.stale_days,
           "verify": o.verify, "gate": o.gate}
    results: list[RepoResult] = []
    try:
        for i, r in enumerate(repos, 1):
            if o.dry_run:
                res = process_repo(r, prov, o, names[r.key], _DryOut(), work, None, tag, cutoff, reset_cache)
            else:
                try:
                    res = process_repo(r, prov, o, names[r.key], out, work, reg, tag, cutoff, reset_cache)
                except Exception as e:          # one repository must not stop the organization run
                    res = RepoResult(provider=r.provider, org=o.org, project=r.project, repo=r.name, status="error",
                                     reason=REDACT(f"{type(e).__name__}: {e}")[:500], web_url=r.web_url,
                                     app=names[r.key])
            results.append(res)
            detail = ", ".join(c["component"] for c in res.components) or res.reason
            log(f"[{i}/{len(repos)}] {r.project}/{r.name}: {res.status}" + (f" - {detail}" if detail else ""))
            if out:
                ns = write_sandbox(out.root, out.url, o.output_branch)
                org_index(out.root, out.root / segment(o.org), [x.to_dict() for x in results], run)
                out.commit(f"containerizer: {o.org}/{r.project}/{r.name} {res.status}"
                           + (f" ({len(res.components)} components, {tag})" if res.components else "")
                           + f"\n\n{len(ns)} apps in {SANDBOX}/.")
    finally:
        if reg:
            reg.close()
    return results


class _DryOut:
    root = Path(tempfile.gettempdir()) / "containerizer-dry-run"
    url = ""
