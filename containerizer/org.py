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

from .credentials import in_org, same_repo
from .orgsource import (NO_PROJECT, REDACT, SourceError, SourceRepo, clone, code_summary, existing_dockerfiles, git,
                        head_commit, provider, read_token, strip_userinfo, update_clone)

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
    token: str | None = None            # the organization's read-only token (worker: registered credential);
                                        # None: from token_env or the provider's usual environment variables
    output_repo: str | None = None
    output_dir: str | None = None
    output_branch: str = "main"
    output_token_env: str = "OUTPUT_GIT_TOKEN"
    output_token: str | None = None     # write token of the output repository (worker: registered credential)
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
    ingress_domain: str | None = None   # wildcard domain for the HTTPS Ingresses (None: the appliance's setting)
    sandbox_idp: bool = True            # with a domain: components that sign in use the sandbox IdP (idp.py)
    sql: str | None = None
    work_dir: str = ".work/org"
    keep_work: bool = False
    cache_dir: str | None = None        # keep clones here and only pull the newest commit on later runs
    skip_no_code: bool = True           # skip repositories without application code (docs, config, libraries only)
    dry_run: bool = False
    now: datetime | None = None
    state: object = None                # RepoState store (worker.SqlRepoStore): admin enable/disable, repo history
    hooks: object = None                # progress callbacks (worker): start, repo_done, git, should_stop
    allowed_hosts: object = None        # worker: hosts the tokens may be sent to (API, clone and output URLs)
    on_listed: object = None            # worker: (provider, number of repositories) after the listing
    verify_sandbox: bool = False        # after the run: wait for the GitOps sync and read back pod health
    kubeconfig: str | None = None
    kube_context: str | None = None
    gitops: str = "auto"                # auto | argocd | flux
    sandbox_timeout: int = 900
    lab: set | None = None              # lab services that are on (labservices.py); None: from CONTAINERIZER_LAB_SERVICES


@dataclass
class RepoResult:
    provider: str
    org: str
    project: str
    repo: str
    status: str                       # deployed | no-a-components | skipped-* | disabled | error
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
    overridden: list = field(default_factory=list)   # automatic skips an administrator overrode (enabled)
    seconds: float = 0.0
    source_key: str = ""              # Application.SourceKey in the results database
    dev_database: dict = field(default_factory=dict)   # the uploaded dev database restored next to it, if any
    lab_services: dict = field(default_factory=dict)   # lab services needed, provided and turned off (labservices.py)

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
            if rating == "B" and c.verdict in ("info", "config") and getattr(c, "stateless", True) is False:
                why = "keeps local state"     # otherwise ready: the stateless cap made it B
        elif not buildable(c):
            why = "no Linux container build for this component"
        elif verified and (ver.get(c.name) or {}).get("status") not in OK_VERIFY:
            why = f"build-and-run: {(ver.get(c.name) or {}).get('status', 'not run')}"
        if why:
            excluded.append({"component": c.name, "reason": why})
        else:
            keep.append(c)
    return keep, excluded


def sbom_entry(g: dict | None, folder: str, cdir: Path, local: str, c, o: OrgOptions) -> dict | None:
    """The SBOM the gate made for a component; without the gate, one made here (no CVEs: nothing was scanned)."""
    if g is not None:
        sb = next((x.get("sbom") for x in g["components"] if x["component"] == folder), None)
        return sb if sb and not sb.get("error") else None
    from .sbom import component_sbom, config
    if not o.push_images or not config().get("enabled", True):
        return None
    sb = component_sbom(local, cdir, [], (c.name, c.project.name))
    return None if sb.get("error") else sb


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
    denied = ((comp.get("sbom") or {}).get("summary") or {}).get("denied") or []
    if denied:
        return f"licence denied by policy: {', '.join(denied[:3])}"[:300]
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


def idp_entries(gen: Path, comps: list) -> list[dict]:
    """Rows for the results database from the components' idp.json (written by the generator)."""
    rows = []
    for c in comps:
        from .generate import k8s_name
        f = gen / k8s_name(c.name) / "idp.json"
        if not f.is_file():
            continue
        d = json.loads(f.read_text())
        for cl in d.get("clients") or []:
            rows.append({"project": c.project.rel, "protocol": cl["protocol"], "idp_url": d["idp"], "app_url": cl["url"],
                         "identifier": cl["identifier"], "metadata_url": cl["metadata_url"],
                         "settings": {"env": cl.get("env") or {}, "secret": cl.get("secret_env") or "",
                                      "section": cl.get("section") or ""},
                         "notes": cl.get("notes") or []})
        if not d.get("clients") and d.get("notes"):
            rows.append({"project": c.project.rel, "protocol": "none", "idp_url": d["idp"], "notes": d["notes"]})
    return rows


def write_idp(root: Path, apps) -> str:
    """sandbox/idp/: the sandbox identity provider and every component registered at it (each
    component's idp.json in the output repository). Returns the IdP URL, or "" when no component uses it."""
    from collections import Counter
    from .idp import Sandbox, config, sandbox_files
    found = []
    for rel, d, _ in apps:
        for f in sorted(d.glob("*/idp.json")):
            try:
                found.append(json.loads(f.read_text()))
            except ValueError:
                continue
    found = [x for x in found if x.get("applications")]
    if not found:
        return ""
    # one IdP: the domain most components were generated with (an app generated before the domain changed
    # is registered again by its next run)
    prefix = f"https://{config()['host_label']}."
    domains = Counter(x["idp"][len(prefix):] for x in found if str(x.get("idp", "")).startswith(prefix))
    if not domains:
        return ""
    domain = sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    sb = Sandbox(domain)
    defs = {a["name"]: a for x in found if x["idp"] == sb.url for a in x["applications"]}
    for rel, content in sandbox_files(sb, defs).items():
        p = root / SANDBOX / "idp" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return sb.url


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
    (sb / "argocd" / "bootstrap.yaml").write_text(dump(sandbox_credentials(ARGO_NS, name, labels, git_url) + [
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
    idp_url = write_idp(root, apps)
    (sb / "flux" / "apps" / "kustomization.yaml").write_text(yaml.safe_dump(
        {**k, "resources": [f"../../../{rel}/gitops/flux" for rel, d, _ in apps
                            if (d / "gitops" / "flux" / "kustomization.yaml").exists()]
         + (["../../idp"] if idp_url else [])}, sort_keys=False))
    (sb / "flux" / "bootstrap.yaml").write_text(dump(sandbox_credentials(FLUX_NS, name, labels) + [
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
    from .sandbox import verify_rbac
    (sb / "verify-rbac.yaml").write_text(
        "# Read-only access for `containerizer sandbox verify` (docs/sandbox-verification.md). Apply it as a\n"
        "# cluster admin after the namespaces exist; it grants nothing cluster-wide and no access to Secrets.\n"
        + dump(verify_rbac(namespaces)))
    (sb / "README.md").write_text(sandbox_readme(git_url, branch, apps, idp_url))
    return namespaces


def sandbox_credentials(namespace: str, name: str, labels: dict, argocd_repo: str | None = None) -> list[dict]:
    """The read-only Git credential of the root sync, as an ExternalSecret from the secret store (remote
    key `<namespace>--cz-git`), with the namespace's store reader and its access. Argo CD: a repository
    Secret (labelled for Argo CD) for `argocd_repo`."""
    from . import eso
    remote = eso.remote_key(namespace, eso.GIT)
    es = eso.external_secret(f"{name}-git" if argocd_repo is None else f"{name}-repo", namespace, remote,
                             labels=labels, set_namespace=True,
                             comment=f"read-only token of the output repository (username + password), "
                                     f"remote key {remote} in the secret store")
    es.pop("_comment")
    if argocd_repo is not None:
        # Argo CD finds repositories by label; url and type are not secret
        es["spec"]["target"]["template"] = {
            "engineVersion": "v2", "mergePolicy": "Merge",
            "metadata": {"labels": {"argocd.argoproj.io/secret-type": "repository"}},
            "data": {"type": "git", "url": argocd_repo}}
    return eso.store_access(namespace, [remote], labels) + \
        [eso.reader_service_account(namespace, labels, set_namespace=True), es]


def sandbox_readme(git_url: str, branch: str, apps, idp_url: str = "") -> str:
    rows = "\n".join(f"| `{doc.get('app')}` | [{rel}]({rel.replace(' ', '%20')}/) | "
                     f"{', '.join(c['component'] for c in doc.get('components', []))} |" for rel, _, doc in apps)
    if idp_url:
        idp_text = (f"\nThe components that sign users in with OpenID Connect, SAML 2.0 or WS-Federation are registered at\n"
                    f"the sandbox identity provider (WSO2 Identity Server) at {idp_url}/. Flux applies `{SANDBOX}/idp`\n"
                    f"with the apps; with Argo CD apply it once with `kubectl apply -k {SANDBOX}/idp`. Clients, test\n"
                    f"users and passwords: `{SANDBOX}/idp/README.md` (docs/sandbox-idp.md).\n")
    else:
        idp_text = ("\nNo component signs users in with OpenID Connect, SAML 2.0 or WS-Federation, or no sandbox domain\n"
                    "was set (`--ingress-domain`), so no identity provider is deployed.\n")
    return f"""# Sandbox deployment

Every app in this repository that has components rated **A** (lift and shift, stateless, built,
run and passed the security gate). Pick Argo CD **or** Flux, not both. Generated by
`containerizer org`; do not edit, the next run rewrites this folder.

| Namespace | Folder | Components |
| --- | --- | --- |
{rows}

Credentials come from External Secrets Operator: nothing in this repository is a Secret. Install ESO
and a `ClusterSecretStore` named `app-secrets` first (every app's `cluster/secret-store.yaml` has one;
docs/external-secrets.md shows Vault, Azure Key Vault and AWS Secrets Manager). Then put the read-only
token of this repository in the store as `username` + `password` under these remote keys:

| Remote key | For |
| --- | --- |
| `argocd--cz-git` | Argo CD: the repository Secret in `argocd` |
| `flux-system--cz-git` | Flux: the root `GitRepository` |
| `<namespace>--cz-git`, for every line of `namespaces.txt` | Flux: each app's own `GitRepository` |

With the default kubernetes provider the store reads Secrets in namespace `containerizer-secrets`, so:

```sh
kubectl -n containerizer-secrets create secret generic flux-system--cz-git \\
  --from-literal=username=git --from-literal=password=<read-only token>
```

The containerizer appliance does this by itself from `sandbox.env`.

## Argo CD

```sh
kubectl apply -f {SANDBOX}/argocd/bootstrap.yaml
```

`bootstrap.yaml` is an app-of-apps: AppProject `containerizer-sandbox` may only create AppProjects and
Applications in `argocd`, from this repository. Each app then has its own AppProject pinned to its
namespace and generated kinds (see `<app>/gitops/README.md`). Apply each app's `cluster/secret-store.yaml`
too: it lets the app's namespace read its own keys.

## Flux

```sh
kubectl apply -f {SANDBOX}/flux/bootstrap.yaml
```

The root Kustomization applies each app's `gitops/flux/tenant.yaml` (namespace with Pod Security
"restricted", ServiceAccount, namespace-only RoleBinding) and `gitops/flux/git/sync.yaml`. Image
automation (`gitops/flux/git/image-automation.yaml`) is left out: it needs a write key.

## Identity provider
{idp_text}
## Health read-back

`containerizer org --verify-sandbox` (or `containerizer sandbox verify` on a checkout of this repository)
waits until Argo CD or Flux has synced the commit, reads back rollout, readiness, restarts and Warning
events of every component and writes `{SANDBOX}/HEALTH.md` and `{SANDBOX}/health.json`. It only reads the
cluster, as ServiceAccount `containerizer-verifier` with the Roles in `verify-rbac.yaml`:

```sh
kubectl apply -f {SANDBOX}/verify-rbac.yaml        # after the namespaces exist; again when apps are added
kubectl -n containerizer-verify create token containerizer-verifier --duration=1h   # short-lived token
```

## Cluster prerequisites

- Pulling images: if the registry is private, the run's `--image-pull-secret` is an ExternalSecret in each
  app; put a `.dockerconfigjson` with a read-only registry credential in the store as `<namespace>--cz-registry`,
  or give the nodes registry credentials.
- Secrets: the apps read them through External Secrets from the `ClusterSecretStore` `app-secrets`
  (remote keys `<namespace>--<component>`), see each app's `HARDENING.md`.
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
    """The output Git repository: cloned with its own write token (never the organization's read-only
    token; the header is scoped to this repository's URL) or a local folder."""

    def __init__(self, o: OrgOptions, work: Path):
        self.o = o
        self.header = ""
        self.push = o.push
        if o.output_repo:
            self.url = strip_userinfo(o.output_repo)
            tok = o.output_token if o.output_token is not None else read_token("", o.output_token_env)
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


def host_allowed(url: str, allowed) -> bool:
    """`allowed` is None (no restriction) or a set of host names, `*.example.com` for subdomains."""
    if allowed is None:
        return True
    import urllib.parse
    host = (urllib.parse.urlsplit(url if "://" in url else "https://" + url).hostname or "").lower()
    return bool(host) and any(host == h or (h.startswith("*.") and host.endswith(h[1:])) for h in allowed)


NO_CODE_STATUS = ("skipped-no-code", "skipped-unsupported", "skipped-no-app")


def no_code_reason(src: Path) -> tuple[str, str]:
    """(status, reason) when a repository has nothing the tool can containerize, ("", "") when it has:
    skipped-no-code: no source code at all (documentation, configuration, pipelines, SQL or shell scripts);
    skipped-unsupported: source code, but no project the tool can build (a language it does not handle,
    or loose files without a project file); skipped-no-app: projects, but only libraries, tests and tools."""
    from .assess import assess
    from .scan import scan
    repo = scan(src)
    if not repo.projects:
        s = code_summary(src)
        n = s["files"]
        if not n:
            return "skipped-no-code", "no files on the default branch"
        files = f"{n} file{'s' if n != 1 else ''} ({', '.join(f'{x} {c}' for x, c in s['top'])})"
        if s["languages"]:
            langs = ", ".join(f"{lang} ({c} file{'s' if c != 1 else ''})" for lang, c in s["languages"][:3])
            return ("skipped-unsupported", f"{langs}, but no project the tool can build (.NET project, package.json, "
                    f"requirements.txt or pyproject.toml, pom.xml or build.gradle, go.mod); {files}")
        return "skipped-no-code", f"{files}, no source code"
    a = assess(src, repo=repo)
    if not a.components:
        kinds = sorted({c.role for c in a.libraries + a.tests} or {p.kind_hint for p in repo.projects})
        n = len(repo.projects)
        return "skipped-no-app", f"only {', '.join(kinds)}: {n} project{'s' if n != 1 else ''}, nothing that runs on its own"
    return "", ""


def process_repo(r: SourceRepo, prov, o: OrgOptions, app: str, out: Output, work: Path, reg: Registry | None,
                 tag: str, cutoff: datetime | None, rules_reset, admin: str | None = None) -> RepoResult:
    """One repository. `admin` is an administrator's decision from the worker's repository list:
    "disabled" (never processed, stops deploying), "enabled" (processed even when an automatic skip
    applies: stale, fork, Dockerfile, no application code) or None (automatic)."""
    from .analyze import analyze_app
    from .generate import generate_app, k8s_name
    from .gitops import GitOpsOptions

    org_seg, proj_seg, repo_seg = segment(o.org), segment(r.project), segment(r.name)
    rel = f"{org_seg}/{proj_seg}/{repo_seg}"
    dest = out.root / rel
    res = RepoResult(provider=r.provider, org=o.org, project=r.project, repo=r.name, status="error",
                     web_url=r.web_url, clone_url=r.clone_url, branch=r.default_branch, app=app,
                     processed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    hooks = o.hooks

    def stop(status: str, reason: str) -> RepoResult:
        res.status, res.reason = status, reason
        if not o.dry_run and dest.exists():                        # it no longer qualifies: stop deploying it
            shutil.rmtree(dest)
        return res

    def skip(status: str, reason: str) -> RepoResult | None:
        """An automatic skip; None when an administrator enabled the repository anyway."""
        if admin == "enabled":
            res.overridden.append({"status": status, "reason": reason})
            return None
        return stop(status, reason)

    if o.output_repo and same_repo(r.clone_url, o.output_repo):
        # the generated files live here: never scanned, and its write token is never used for scanning
        return stop("skipped-output", "the output repository of this scan (generated files)")
    if not in_org(r.clone_url, o.provider, o.org, o.api_url):
        res.reason = (f"clone URL {strip_userinfo(r.clone_url)} is outside the organization {o.org}: "
                      "the organization's token is not sent with it")
        return res
    if admin == "disabled":
        return stop("disabled", "disabled by an administrator")
    if r.archived:
        return stop("skipped-archived", "archived or disabled")
    if r.empty:
        return stop("skipped-empty", "empty repository")
    if o.skip_forks and r.fork and (x := skip("skipped-fork", "forked from another repository")):
        return x
    if cutoff and r.last_activity and r.last_activity < cutoff:
        # the provider's activity date covers every push, so the default branch is at least as old
        if x := skip("skipped-stale", f"no update since {r.last_activity:%Y-%m-%d}"):
            return x
    elif cutoff and not r.last_activity:
        try:
            lc = prov.last_commit(r)
        except SourceError:
            lc = None
        if lc and lc < cutoff:
            res.last_commit = lc.isoformat()
            if x := skip("skipped-stale", f"last commit {lc:%Y-%m-%d}"):
                return x
    if o.dry_run:
        res.status, res.reason = "would-process", ""
        return res
    if not host_allowed(r.clone_url, o.allowed_hosts):
        res.reason = f"clone URL host is not in the worker's allowed hosts (CONTAINERIZER_WORKER_HOSTS): {r.clone_url}"
        return res

    cached = bool(o.cache_dir)
    src = Path(o.cache_dir) / app if cached else work / "src" / app
    if not cached and src.exists():
        shutil.rmtree(src)
    src.parent.mkdir(parents=True, exist_ok=True)
    import time as _time
    t0 = _time.monotonic()
    op = "pull" if cached and (src / ".git").is_dir() else "clone"
    try:
        if cached:
            op = "pull" if update_clone(r.clone_url, src, r.default_branch, prov.git_header()) == "pulled" else "clone"
        else:
            clone(r.clone_url, src, r.default_branch, prov.git_header())
    except SourceError as e:
        if hooks and hasattr(hooks, "git"):
            hooks.git(op, _time.monotonic() - t0, False)
        res.reason = str(e)
        return res                               # keep whatever was deployed before
    if hooks and hasattr(hooks, "git"):
        hooks.git(op, _time.monotonic() - t0, True)
    try:
        res.commit, when = head_commit(src)
        res.last_commit = when.isoformat() if when else ""
        if cutoff and when and when < cutoff and \
                (x := skip("skipped-stale", f"last commit on {r.default_branch or 'default branch'} {when:%Y-%m-%d}")):
            return x
        dockerfiles = existing_dockerfiles(src)
        if dockerfiles and (x := skip("skipped-dockerfile", "found " + ", ".join(dockerfiles[:3])
                                      + (" ..." if len(dockerfiles) > 3 else ""))):
            return x
        if o.skip_no_code:
            rules_reset()
            status, why = no_code_reason(src)
            if status and (x := skip(status, why)):
                return x

        from .sandbox_https import configured_domain, normalize_domain
        domain = normalize_domain(o.ingress_domain) if o.ingress_domain else configured_domain()
        gitops = GitOpsOptions(git_url=out.url, branch=o.output_branch, path=rel, verify_commits=o.verify_commits,
                               image_pull_secret=o.image_pull_secret or "", ingress_domain=domain,
                               sandbox_idp=o.sandbox_idp)
        scratch = work / "analyze"
        if scratch.exists():
            shutil.rmtree(scratch)
        rules_reset()
        a = analyze_app(src, scratch, ai=o.ai, model=o.model, verify=o.verify, registry=o.registry, pin=o.pin,
                        timeout=o.timeout, gitops=gitops, sql=o.sql)
        res.rating = a.rating
        from .sqlstore import source_info
        res.source_key = source_info(src, a.name)["key"]
        assessment_id = None
        if o.sql or os.environ.get("CONTAINERIZER_SQL"):
            from .sqlstore import store_results
            assessment_id = store_results(o.sql, [a], [src])[0]
        keep, res.excluded = select_components(a, o.verify)
        lab = _lab_services(o)
        lab_report: dict = {}
        dd, dd_row = (_dev_database(o, res, a, keep, work, reg, tag, lab) if keep else (None, None))
        gen = work / "gen" / app
        names = {k8s_name(c.name): c for c in keep}
        g = None
        while keep:
            if gen.exists():
                shutil.rmtree(gen)
            fa = dataclasses.replace(a, components=keep)
            if not o.gate:
                generate_app(fa, gen, registry=o.registry, pin=o.pin, gitops=gitops, tag=tag, devdb=dd, lab=lab,
                             lab_report=lab_report)
                break
            from .harden import security
            from .imagescan import gate_app
            g = gate_app(fa, gen, build=True, scan=True, run=True, registry=o.registry, pin=o.pin, gitops=gitops,
                         tag=tag, scanner=o.scanner or security()["scan"].get("default_scanner", "auto"),
                         fail_on=o.fail_on, devdb=dd, lab=lab, lab_report=lab_report)
            failed = {c["component"]: gate_failure(c) for c in g["components"] if gate_failure(c)}
            if not failed:
                break
            for cname, why in failed.items():
                res.excluded.append({"component": names[cname].name if cname in names else cname,
                                     "reason": f"security gate: {why}"})
            keep = [c for c in keep if k8s_name(c.name) not in failed]
        if not keep:
            return stop("no-a-components", f"none of {len(res.excluded)} server components qualifies" if res.excluded
                        else "no server component")

        # images: built by the gate (or here), pushed under <registry>/<app>/<component>:<tag>
        from .imagescan import build_image
        comps, sboms = [], []
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
                     "project_name": c.project.name,
                     "verification": next((v.get("status") for v in getattr(a, "verification", None) or [] if v.get("component") == c.name),
                                          "not run")}
            sb = sbom_entry(g, cn, cdir, local, c, o)
            if o.push_images and reg:
                entry["digest"] = reg.push(local, ref, [f"{ref.rsplit(':', 1)[0]}:git-{res.commit[:12]}"]
                                           if res.commit else [])
                if o.cosign_key and entry["digest"]:
                    entry["signature"] = reg.sign(ref, entry["digest"], o.cosign_key)
                if sb and entry["digest"]:
                    from .sbom import attach
                    sb["attestation"] = attach(ref, entry["digest"], cdir / "sbom.cdx.json", o.cosign_key, reg.config)
            if sb:
                entry["sbom"] = {k: sb.get(k) for k in ("file", "format", "tool", "attestation")} | {
                    "summary": {k: v for k, v in sb["summary"].items() if k not in ("warn", "denied")}}
                sboms.append({"project": c.project.rel, "document": json.loads((cdir / "sbom.cdx.json").read_text()),
                              "packages": sb["packages"], "tool": sb.get("tool"), "os": sb.get("os"), "image": ref,
                              "digest": entry.get("digest"), "attestation": sb.get("attestation")})
            comps.append(entry)
        res.components = comps
        idp_rows = idp_entries(gen, keep)
        if assessment_id and idp_rows:
            from .sqlstore import connect, store_idp_clients
            try:
                conn = connect(o.sql)
                try:
                    store_idp_clients(conn, assessment_id, idp_rows)
                finally:
                    conn.close()
            except Exception as e:
                print(f"warning: sandbox IdP registrations not written to SQL Server: {type(e).__name__}: "
                      f"{REDACT(str(e))[:300]}", file=sys.stderr)
        if assessment_id and sboms:
            from .sqlstore import connect, store_image_sboms
            try:                              # the images are pushed already: a database error must not undo that
                conn = connect(o.sql)
                try:
                    store_image_sboms(conn, assessment_id, sboms)
                finally:
                    conn.close()
            except Exception as e:
                print(f"warning: SBOMs not written to SQL Server: {type(e).__name__}: {REDACT(str(e))[:300]}",
                      file=sys.stderr)

        if lab is not None:
            res.lab_services = lab_report
        if dd is not None and (gen / "devdb").is_dir():
            from .devdb import readme
            (gen / "devdb" / "README.md").write_text(readme(k8s_name(a.name), dd, dd_row))
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
        if not o.keep_work and not cached:
            shutil.rmtree(src, ignore_errors=True)


# --------------------------------------------------------------------------- the run

def _lab_services(o: OrgOptions) -> set | None:
    """The lab services that are on: OrgOptions.lab, else lab-services.json on the appliance
    (CONTAINERIZER_LAB_SERVICES), read for each repository so a change applies to the next one."""
    if o.lab is not None:
        return set(o.lab)
    from .labservices import LabError, enabled_from_env
    try:
        return enabled_from_env()
    except LabError as ex:
        print(f"warning: lab services not used: {ex}", file=sys.stderr)
        return None


def _dev_database(o: OrgOptions, res: RepoResult, a, comps: list, work: Path, reg: "Registry | None", tag: str,
                  lab: set | None = None):
    """The dev database an operator uploaded for this application (admin pages): its image built and
    pushed next to the application's, and the settings that point the application at it.
    (None, None) when there is none, or when it cannot be prepared (the reason is in res.dev_database).
    On the appliance, SQL Server turned off under Lab services turns these off too."""
    from . import devdb
    from .generate import k8s_name
    settings = devdb.Settings.from_env(os.environ)
    if settings is None or not (o.sql or os.environ.get("CONTAINERIZER_SQL")) or not res.source_key:
        return None, None
    try:
        row = devdb.lookup(o.sql, res.source_key)
    except Exception as ex:                                  # e.g. a database from before the DevDatabase table
        res.dev_database = {"status": "error", "reason": f"could not read the dev database settings: {str(ex)[:200]}"}
        return None, None
    if not row:
        return None, None
    if lab is not None and "sqlserver" not in lab:
        res.dev_database = {"engine": row["Engine"], "database": row["DatabaseName"], "file": row["FileName"],
                            "status": "disabled", "reason": "SQL Server is turned off under Admin -> Lab services"}
        return None, None
    ns = k8s_name(a.name)
    image = f"{o.registry.rstrip('/')}/{ns}/devdb:{tag}"
    local = f"containerizer/{ns}-devdb:gate"
    info = {"engine": row["Engine"], "database": row["DatabaseName"], "file": row["FileName"], "sha256": row["Sha256"],
            "image": image}
    try:
        db = devdb.prepare(row, a, comps, settings, image, local, work, ai=o.ai, model=o.model,
                           timeout=max(o.timeout, 1800))
        if o.push_images and reg:
            info["digest"] = reg.push(local, image, [f"{image.rsplit(':', 1)[0]}:sha-{row['Sha256'][:12]}"])
    except (devdb.DevDbError, SourceError, OSError, ValueError) as ex:
        res.dev_database = {**info, "status": "error", "reason": str(ex)[:500]}
        return None, None
    res.dev_database = {**info, "status": "deployed", "settings": db.source,
                        "components": {c: [e["name"] for e in env] for c, env in db.env.items()}}
    return db, row


def run_org(o: OrgOptions, log=print) -> list[RepoResult]:
    from .confidence import reset_cache

    now = o.now or datetime.now(timezone.utc)
    tag = o.tag or default_tag(now)
    cutoff = now - timedelta(days=o.stale_days) if o.stale_days else None
    token = o.token if o.token is not None else read_token(o.provider, o.token_env)
    if not token:
        from .orgsource import TOKEN_ENVS
        # no anonymous access: only organizations someone gave a token for are listed and cloned
        raise SourceError(f"no read-only token for the {o.provider} organization {o.org}: set "
                          f"{o.token_env or ' or '.join(TOKEN_ENVS[o.provider])} (scheduled scans: register one under "
                          "Admin → Source control); organizations are never read anonymously")
    if o.output_repo and o.output_token and o.output_token == token:
        raise SourceError("the output repository's write token is the same as the organization's read-only token: "
                          "use a separate read-only token for scanning")
    prov = provider(o.provider, o.org, token, o.api_url)
    work = Path(o.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o700)

    listed = list(prov.repos())
    if o.on_listed:
        o.on_listed(prov, len(listed))
    names = unique_names(listed)              # over every listed repository, so a filter change keeps the names
    inc = re.compile(o.include) if o.include else None
    exc = re.compile(o.exclude) if o.exclude else None
    repos = [r for r in listed if (not inc or inc.search(r.key)) and not (exc and exc.search(r.key))]
    if o.max_repos:
        repos = repos[:o.max_repos]
    log(f"{o.org}: {len(listed)} repositories" + (f", {len(repos)} selected by the filters" if len(repos) != len(listed) else ""))
    admin = o.state.sync(listed, names) if o.state else {}
    if o.state:
        chosen = {r.key for r in repos}
        for r in listed:
            if r.key not in chosen:
                o.state.record(r, RepoResult(provider=r.provider, org=o.org, project=r.project, repo=r.name,
                                             status="skipped-filter", web_url=r.web_url, clone_url=r.clone_url,
                                             reason="left out by the scan's include/exclude filter or repository limit",
                                             app=names[r.key]))
    cache = prepare_cache(o) if o.cache_dir and not o.dry_run else None

    out = Output(o, work) if not o.dry_run else None
    reg = Registry(o.registry) if (o.push_images and not o.dry_run) else None
    run = {"provider": o.provider, "org": o.org, "registry": o.registry, "tag": tag,
           "started": now.isoformat(timespec="seconds"), "stale_days": o.stale_days,
           "verify": o.verify, "gate": o.gate}
    results: list[RepoResult] = []
    hooks = o.hooks
    if hooks and hasattr(hooks, "start"):
        hooks.start(len(repos))
    import time as _time
    try:
        for i, r in enumerate(repos, 1):
            if hooks and hasattr(hooks, "should_stop") and hooks.should_stop():
                log(f"stopped before {r.project}/{r.name}: {len(results)} of {len(repos)} repositories done")
                break
            if hooks and hasattr(hooks, "repo_start"):
                hooks.repo_start(i, r)
            t0 = _time.monotonic()
            if o.dry_run:
                res = process_repo(r, prov, o, names[r.key], _DryOut(), work, None, tag, cutoff, reset_cache,
                                   admin.get(r.key))
            else:
                try:
                    res = process_repo(r, prov, o, names[r.key], out, work, reg, tag, cutoff, reset_cache,
                                       admin.get(r.key))
                except Exception as e:          # one repository must not stop the organization run
                    res = RepoResult(provider=r.provider, org=o.org, project=r.project, repo=r.name, status="error",
                                     reason=REDACT(f"{type(e).__name__}: {e}")[:500], web_url=r.web_url,
                                     app=names[r.key])
            res.seconds = round(_time.monotonic() - t0, 1)
            results.append(res)
            detail = ", ".join(c["component"] for c in res.components) or res.reason
            log(f"[{i}/{len(repos)}] {r.project}/{r.name}: {res.status}" + (f" - {detail}" if detail else ""))
            if o.state and not o.dry_run:
                o.state.record(r, res)
            if out:
                ns = write_sandbox(out.root, out.url, o.output_branch)
                org_index(out.root, out.root / segment(o.org), [x.to_dict() for x in results], run)
                out.commit(f"containerizer: {o.org}/{r.project}/{r.name} {res.status}"
                           + (f" ({len(res.components)} components, {tag})" if res.components else "")
                           + f"\n\n{len(ns)} apps in {SANDBOX}/.")
            if hooks and hasattr(hooks, "repo_done"):
                hooks.repo_done(i, r, res)
        else:
            if cache:
                prune_cache(cache, set(names.values()), log)
    finally:
        if reg:
            reg.close()
    if o.verify_sandbox and out:
        sandbox_step(o, out, log)
    return results


CACHE_MARK = ".containerizer-org-cache"


def prepare_cache(o: OrgOptions) -> Path:
    """The clone cache folder of one organization. It is marked on first use, and a folder that holds
    something else (or another organization's clones) is refused, so pruning never deletes foreign files."""
    cache = Path(o.cache_dir).resolve()
    ident = f"{o.provider} {o.api_url or ''} {o.org}".strip()
    mark = cache / CACHE_MARK
    if mark.exists():
        if mark.read_text().strip() != ident:
            raise SourceError(f"{cache} is the clone cache of {mark.read_text().strip()!r}, not {ident!r}: "
                              "use one cache folder per organization")
    elif cache.exists() and any(cache.iterdir()):
        raise SourceError(f"{cache} is not empty and not a containerizer clone cache: give an empty or new folder")
    else:
        cache.mkdir(parents=True, exist_ok=True)
        mark.write_text(ident + "\n")
    os.chmod(cache, 0o700)
    return cache


def prune_cache(cache: Path, keep: set[str], log=print) -> None:
    """Remove the clones of repositories the organization no longer lists (deleted or renamed)."""
    for d in cache.iterdir():
        if d.is_dir() and d.name not in keep and (d / ".git").is_dir():
            shutil.rmtree(d, ignore_errors=True)
            log(f"removed the clone of {d.name}: no longer in the organization")


def sandbox_step(o: OrgOptions, out: "Output", log=print) -> dict:
    """Wait for the sandbox cluster to sync what was pushed and record the health of every component:
    sandbox/HEALTH.md + health.json in the output repository, the results database, the learning loop."""
    from .sandbox import KubeOptions, SandboxOptions, summary, verify_sandbox, write_health
    so = SandboxOptions(kube=KubeOptions(kubeconfig=o.kubeconfig, context=o.kube_context), gitops=o.gitops,
                        timeout=o.sandbox_timeout)
    if out.git and not out.push:
        doc = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "revision": "",
               "gitops": o.gitops, "cluster": "", "components": [],
               "skipped": "the output repository was not pushed (--no-push or no remote): the cluster cannot sync it"}
        log(f"sandbox verification skipped: {doc['skipped']}")
    else:
        doc = verify_sandbox(out.root, so, log=log)
    write_health(out.root, doc)
    log(f"sandbox health: {summary(doc)}" + (f" (skipped: {doc['skipped']})" if doc.get("skipped") else ""))
    if doc.get("learned"):
        log(f"learned from the cluster: {', '.join(doc['learned'])}")
    if (o.sql or os.environ.get("CONTAINERIZER_SQL")) and doc.get("components") and not doc.get("skipped"):
        from .sqlstore import SqlError, store_sandbox
        try:
            n, missing = store_sandbox(o.sql, doc)
            log(f"{n} sandbox check(s) written to SQL Server" + (f"; {missing} not matched to an assessed component"
                                                                 if missing else ""))
        except SqlError as e:
            print(f"warning: sandbox health not written to SQL Server: {e}", file=sys.stderr)
    out.commit(f"containerizer: sandbox health {summary(doc)}")
    return doc


class _DryOut:
    root = Path(tempfile.gettempdir()) / "containerizer-dry-run"
    url = ""
