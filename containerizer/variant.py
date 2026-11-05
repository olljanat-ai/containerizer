"""The sandbox deployment of "Make it A" orders (refactor.py, goal rating-a; docs/refactoring.md#the-sandbox-variant).

A "Make it A" order whose patched copy assesses as A and verifies is deployed to the sandbox IN PLACE of the scan's
output: into the application's own folder of the output repository of the organization scan that assessed it
(`<Org>/<Project>/<Repo>[@<folder>]/`, the one the scan writes), the way a scan deploys (org.deploy_app), under the
application's own name. So it runs in the application's namespace (generate.app_ns), with its image paths
(`<registry>/<app>/<component>:1.<yyyymmdd>.<hhmm>-refactor.<job>`: the tag says it is the patch), Ingress hosts, IdP
clients, lab services (the application's lab database), connectivity.yaml and egress and link decisions. One commit
("sandbox: <app> runs the Make it A patch of order #<job> (commit <sha>)") writes the folder and regenerates sandbox/
(org.write_sandbox); Flux rolls the application over to it. containerizer.json records it (`patched`: the order, the
source commit it was made for, and `previous_revision`, the output repository's commit before the first patch, whose
folder is the scan's output: never lost, it stays in the repository's history).

- One per application: a newer order's patched copy overwrites the older one in place (it keeps the older one's
  `previous_revision`); the older order's state becomes outdated (due).
- Scans: a scan that assesses the same commit leaves the folder as it is (org.kept_patch: the patch is newer than what
  the scan would write) and still records its assessment; a scan of newer code writes its own output, and the order's
  state becomes outdated ("replaced by newer code").
- Remove from the sandbox (cz.LlmJob.RemoveRequestedAt, the queue runner's housekeep): the scan's output is put back
  into the folder from `previous_revision` (absent there: the folder goes, as before the patch), sandbox/ regenerated,
  one commit.
- Settings: the organization scan's (cz.OrgScan: Registry, OutputRepo, OutputBranch, ImagePullSecret, Gate,
  PushImages), found through the order's source (the scan worker's clone of the repository); the output
  repository's write token is the registered one, opened with the credential key (as the scan worker does).
  An application no organization scan with an output repository assessed is not deployed (the reason says so).
- Health: read back with a read-only kubeconfig (CONTAINERIZER_SANDBOX_KUBECONFIG, optional
  CONTAINERIZER_SANDBOX_CONTEXT) for the application's namespace only (sandbox.verify_sandbox with `apps`), without
  the learning loop and without cz.SandboxCheck rows: the order's result (`result["sandbox"]`) has it; the scan's
  sandbox checks of the application see the patched copy from then on. Without a kubeconfig: "deployed; health not
  checked".
- Before this, a patched copy ran beside the application as `<app>-refactor-<job>` (folder
  `<Org>/<Project>/<Repo>-refactor-<job>/`, its own namespace). housekeep moves the latest active one of each
  application into the application's folder (migrate: the source at the commit with the patch, generated again under
  the application's name, its images as they were) and deletes the `-refactor-` folders; Flux prunes those
  namespaces.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

KUBECONFIG_ENV = "CONTAINERIZER_SANDBOX_KUBECONFIG"
PATCH_FILE = "make-it-a.patch"                 # the order's patch, in the application's folder while it runs
MARKER = "patched"                             # containerizer.json: the folder runs this order's patch
CONTEXT_ENV = "CONTAINERIZER_SANDBOX_CONTEXT"
TIMEOUT_ENV = "CONTAINERIZER_SANDBOX_VARIANT_TIMEOUT"
DEFAULT_TIMEOUT = 900
SUFFIX = "-refactor-"                          # the folders and namespaces of the variants of before (migrate)
STATUSES = ("deploying", "running", "failing", "deployed", "off", "skipped", "error", "removed", "outdated", "expired")
STATUS_TEXT = {"deploying": "Deploying", "running": "Running in the sandbox", "failing": "Failing in the sandbox",
               "deployed": "Deployed, health not checked", "off": "Sandbox turned off", "skipped": "Not deployed",
               "error": "Deploy failed",
               "removed": "Removed from the sandbox", "outdated": "Replaced by newer code",
               "expired": "Expired"}                    # (expired: variants removed by the old 7-day expiry)
ACTIVE = ("running", "failing", "deployed", "off")  # in the output repository: can be removed
RECHECK_UNCHECKED = 600                             # refresh: a copy whose health is not known, checked again after
RECHECK_CHECKED = 3600                              # ... one running or failing, and a removed one (is it back?)
RECHECK_PER_PASS = 3                                # at most this many cluster checks per housekeeping pass
RECHECK_TIMEOUT = 180                               # seconds one re-check waits for the cluster
HOUSEKEEP_SECONDS = 300                             # how often the runner looks for outdated variants


class Skip(Exception):
    """The variant is not deployed, for a reason the order page shows."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _same_commit(a: str | None, b: str | None) -> bool:
    """The same commit, one written short (12 characters) and the other in full."""
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    return bool(a and b) and (a.startswith(b) or b.startswith(a))


def variant_tag(now: datetime, job: int) -> str:
    """The images' tag: org.default_tag with a pre-release part, so the original's image automation (semver
    range >=1.0.0) never takes it, and the tag says which order's patch it is."""
    from .org import default_tag
    return f"{default_tag(now)}-refactor.{int(job)}"


def variant_rel(org: str, project: str, repo: str, job: int) -> str:
    """`<Org>/<Project>/<Repo>-refactor-<job>`: the folder a variant had before patched copies ran in place."""
    from .org import segment
    return f"{segment(org)}/{segment(project)}/{segment(repo)}{SUFFIX}{int(job)}"


def valid_folder(rel: str, job: int) -> bool:
    """A variant folder of before the runner may delete: three plain segments, the last one a variant of this job."""
    from .refactor import safe_rel
    parts = str(rel or "").split("/")
    return safe_rel(rel) == rel and len(parts) == 3 and parts[0] != "sandbox" and parts[2].endswith(f"{SUFFIX}{int(job)}")


def valid_app_folder(rel: str) -> bool:
    """An application folder (three plain segments, not sandbox/) a removal may put the scan's output back into."""
    from .refactor import safe_rel
    parts = str(rel or "").split("/")
    return safe_rel(rel) == rel and len(parts) == 3 and parts[0] != "sandbox"


def in_place(sb: dict) -> bool:
    """The order's copy runs in its application's folder (not in a `-refactor-` folder of before)."""
    return bool(sb.get("in_place"))


def _doc(folder: Path) -> dict:
    try:
        d = json.loads((folder / "containerizer.json").read_text())
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def marker(folder: Path) -> dict:
    """The Make it A patch the folder runs (containerizer.json `patched`), or {}."""
    m = _doc(folder).get(MARKER)
    return m if isinstance(m, dict) and m.get("job") is not None else {}


def app_folder(root: Path, org: str, project: str, repo: str, repo_app: str | None, payload: dict) -> tuple[str, str]:
    """(the application's folder in the output repository, its name): the folder the scan writes for it, found by its
    containerizer.json (the name or SourceKey), else the repository's folder (the whole repository) or `<repo>@<folder>`
    (one folder of a split repository: OrgRepository.SplitPath)."""
    from .generate import app_ns
    from .org import segment, split_app_name, split_dirs
    original = f"{segment(org)}/{segment(project)}/{segment(repo)}"
    if not payload.get("app"):
        raise Skip("not deployed: the order does not name its application")
    want = app_ns(str(payload["app"]))
    key = payload.get("source_key")
    for d in [root / original] + split_dirs(root, original):
        doc = _doc(d)
        if doc and (doc.get("app") == want or (key and doc.get("source_key") == key)):
            return d.relative_to(root).as_posix(), str(doc.get("app") or want)
    subdir = str((payload.get("source") or {}).get("subdir") or ".").strip("/")
    if subdir in ("", "."):
        return original, want
    leaf = subdir.rsplit("/", 1)[-1]
    for seg in (segment(leaf), segment(subdir)):
        if split_app_name(str(repo_app or ""), seg) == want:
            return f"{original}@{seg}", want
    raise Skip(f"not deployed: the folder of application {want} was not found in the output repository (scan it again)")




def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def load_target(conn, payload: dict) -> dict:
    """The organization scan and repository the order's application came from: {"scan", "repo"}."""
    src = payload.get("source") or {}
    if src.get("type") != "org-clone" or not src.get("scan_id"):
        raise Skip("no output repository: the application was not assessed by an organization scan on this machine "
                   "(order it after an organization scan with an output repository)")
    scan = _rows(conn, "SELECT * FROM cz.OrgScan WHERE ScanId = %s", (int(src["scan_id"]),))
    if not scan or not scan[0].get("OutputRepo"):
        raise Skip("no output repository: the organization scan that assessed the application writes no output "
                   "repository, so the sandbox cannot pull a variant")
    app = str(src.get("dir") or "").rsplit("/", 1)[-1]
    repo = _rows(conn, "SELECT TOP (1) ProjectName, Name, CloneUrl, WebUrl, DefaultBranch, AppName FROM cz.OrgRepository "
                       "WHERE ScanId = %s AND AppName = %s ORDER BY RepositoryId DESC", (int(src["scan_id"]), app))
    if not repo:
        raise Skip("no output repository: the organization scan no longer lists the application's repository")
    return {"scan": scan[0], "repo": repo[0]}


def options(scan: dict, write, work: Path):
    """OrgOptions of the scan, for one deployment (no SQL Server: nothing is stored as an assessment)."""
    from .org import OrgOptions
    from .org import SANDBOX_REGISTRY, scan_pushes
    return OrgOptions(provider=scan["Provider"], org=scan["Organization"], registry=SANDBOX_REGISTRY,
                      api_url=scan.get("ApiUrl"), token="", output_repo=scan["OutputRepo"],
                      output_branch=scan.get("OutputBranch") or "main", output_token=write.token or "",
                      output_username=write.username or "x-access-token", push_images=scan_pushes(),
                      image_pull_secret=None, verify=True, gate=bool(scan.get("Gate")),
                      sql=None, work_dir=str(work), ai=False)


def _off(connect) -> set:
    """The applications whose sandbox is turned off (org.load_sandbox_off): left out of sandbox/."""
    from .org import load_sandbox_off
    if connect is None:
        return set()
    conn = connect()
    try:
        return load_sandbox_off(conn)
    finally:
        conn.close()


def _open(connect, key, payload: dict, work: Path, deploying: bool = True):
    """(target, OrgOptions) with the output repository's write token; Skip when it cannot be deployed (`deploying`:
    also when the application's sandbox is turned off; a removal goes ahead)."""
    from .credentials import CredentialError, load, private_key_from_env
    from .org import host_allowed
    from .orgsource import REDACT
    from .worker import allowed_hosts
    conn = connect()
    try:
        if deploying and payload.get("application_id") is not None:
            cur = conn.cursor()
            cur.execute("SELECT SandboxEnabled FROM cz.Application WHERE ApplicationId = %s", (int(payload["application_id"]),))
            row = cur.fetchone()
            if row is not None and not row[0]:
                from .org import SANDBOX_OFF_REASON
                raise Skip(f"not deployed: {SANDBOX_OFF_REASON}")
        target = load_target(conn, payload)
        try:
            creds = load(conn, key if key is not None else private_key_from_env())
        except CredentialError as ex:
            raise Skip(f"no output repository access: {ex}") from None
    finally:
        conn.close()
    scan = target["scan"]
    write = creds.write_for(scan["OutputRepo"])
    if write is None or not write.token:
        raise Skip("no output repository access: no write token for it is registered (Admin → Source control)")
    REDACT.add(write.token, write.username)
    hosts = allowed_hosts() | creds.hosts()
    if not host_allowed(scan["OutputRepo"], hosts):
        raise Skip("no output repository access: its host is not allowed on this machine (CONTAINERIZER_WORKER_HOSTS)")
    return target, options(scan, write, work)


# --------------------------------------------------------------------------- deploy

def after_order(job: dict, payload: dict, result: dict, work: Path, name: str, progress=None) -> dict:
    """What happens in the sandbox after a "Make it A" order: deployed when the patched copy rates A and is
    verified, else why not. Never raises: the patch is the order's result either way."""
    from .orgsource import REDACT
    if not result.get("rating_reached"):
        why = (f"the patched copy rates {result['rating_after']}, not A" if result.get("rating_after")
               else "the patched copy was not assessed")
        return {"status": "skipped", "reason": f"not deployed: {why}"}
    if result.get("status") != "verified":
        return {"status": "skipped", "reason": "not deployed: the patch is not verified (it must build and run)"}
    if not payload.get("deploy", True):
        return {"status": "skipped", "reason": "not deployed: deployment is off for this order"}
    if not job.get("_connect"):
        return {"status": "skipped", "reason": "not deployed: no results database (the order ran from a queue file)"}
    try:
        return deploy(job["_connect"], job.get("_key"), payload, int(job.get("JobId") or 0), result, work, name,
                      progress or (lambda text: None))
    except Skip as ex:
        return {"status": "skipped", "reason": str(ex)[:600]}
    except Exception as ex:  # noqa: BLE001 - the patch stands; the deployment failed
        return {"status": "error", "reason": REDACT(f"{type(ex).__name__}: {ex}")[:600]}


def _assessed(src: Path, name: str, result: dict, work: Path):
    """The patched copy assessed with every rule, named `name`, with a verification for every buildable server
    component: the order's own for the changed ones, a build and run of the others."""
    from .assess import assess
    from .generate import buildable
    from .rules import load_rules
    from . import verify as vf
    a = assess(src)
    a.repo.name = name
    done = {v.get("component"): v for v in result.get("verification") or []}
    ver = []
    rules = None
    for c in a.components:
        if c.name in done:
            ver.append({"component": c.name, "status": done[c.name].get("status")})
        elif c.tier == "server" and buildable(c):
            rules = rules or load_rules()
            try:
                r = vf.verify_component(a, c, rules, work=work)
                ver.append({"component": c.name, "status": r.get("status")})
            except Exception as ex:  # noqa: BLE001
                ver.append({"component": c.name, "status": "error", "detail": f"{type(ex).__name__}: {ex}"[:300]})
    a.verification = ver
    return a


def _git(root: Path, args: list[str], check: bool = True, url: str | None = None, header: str = "") -> str:
    from .orgsource import git
    return git(args, cwd=root, url=url, header=header, check=check)


def _has_commit(root: Path, rev: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{rev}^{{commit}}"], cwd=root, capture_output=True).returncode == 0


def restore(out, rel: str, rev: str | None) -> bool:
    """The folder as it was at commit `rev` of the output repository (the scan's output before a patch ran there), or
    gone when it was not there then. The clone is shallow: the commit is fetched first. Returns whether the folder
    is there now."""
    d = out.root / rel
    if d.exists():
        shutil.rmtree(d)
    if not rev:
        return False
    if not _has_commit(out.root, rev) and getattr(out, "url", None):
        _git(out.root, ["fetch", "-q", "--no-tags", "--depth", "1", "origin", rev], check=False, url=out.url,
             header=getattr(out, "header", ""))
        if not _has_commit(out.root, rev):
            _git(out.root, ["fetch", "-q", "--no-tags", "--unshallow", "origin"], check=False, url=out.url,
                 header=getattr(out, "header", ""))
    if not _has_commit(out.root, rev):
        raise Skip(f"the scan's output (commit {rev[:12]} of the output repository) is not in its history")
    if not _git(out.root, ["ls-tree", "--name-only", rev, "--", rel], check=False).strip():
        return False
    _git(out.root, ["checkout", rev, "--", rel])
    return True


def _repoint(folder: Path, new_ref: str, old_ref: str) -> None:
    """The manifests of a regenerated folder use the image a variant of before was built as (migrate)."""
    new_name, old_name = new_ref.rsplit(":", 1)[0], old_ref.rsplit(":", 1)[0]
    pat = re.compile(re.escape(new_name) + r"(?![\w./-])")
    for f in list(folder.rglob("*.yaml")) + list(folder.rglob("*.yml")):
        text = f.read_text()
        new = pat.sub(old_name, text.replace(new_ref, old_ref))
        if new != text:
            f.write_text(new)


def _write_in_place(connect, target: dict, o, out, payload: dict, job: int, a, src: Path, rel: str, app: str, tag: str,
                    now: datetime, work: Path, patch: str | None = None, images: dict | None = None,
                    also: tuple = (), message: str = ""):
    """The patched copy (assessed `a`, named `app`) into the application's folder `rel`, in place of what is there, and
    one commit. `images` (migrate): component -> its entry of before, whose image the manifests keep (nothing is
    built). `also`: folders deleted in the same commit. Returns the RepoResult; when it is not deployed, the folder is
    left as it was and nothing is committed."""
    from .generate import app_ns
    from .gitops import GitOpsOptions
    from .org import Registry, RepoResult, deploy_app, write_sandbox
    from .sandbox_https import configured_domain
    scan, repo = target["scan"], target["repo"]
    d = out.root / rel
    before, old = marker(d), _doc(d)
    head = _head(out.root)
    prev = before.get("previous_revision") if before else head
    gitops = GitOpsOptions(git_url=out.url, branch=o.output_branch, path=rel, image_pull_secret=o.image_pull_secret or "",
                           ingress_domain=configured_domain(), sandbox_idp=True)
    res = RepoResult(provider=scan["Provider"], org=scan["Organization"], project=repo["ProjectName"], repo=repo["Name"],
                     status="error", web_url=repo.get("WebUrl") or "", clone_url=repo.get("CloneUrl") or "",
                     branch=repo.get("DefaultBranch") or "", commit=str(payload.get("commit") or ""), app=app,
                     rating=a.rating, processed_at=_iso(now) + "Z",
                     source_key=str(payload.get("source_key") or old.get("source_key") or ""))
    reg = Registry(o.registry) if o.push_images and not images else None
    try:
        res = deploy_app(a, src, rel, o, out, reg, tag, gitops, res, work, app, dev_database=False, keep_patched=False)
    except BaseException:
        if head:
            restore(out, rel, head)
        raise
    finally:
        if reg:
            reg.close()
    if res.status != "deployed":
        if head:                            # what the scan (or an earlier patch) put there stays
            restore(out, rel, head)
        return res
    for c in res.components:
        was = (images or {}).get(c.get("component"))
        if was and was.get("image") and was["image"] != c.get("image"):
            _repoint(d, c["image"], was["image"])
            c.update({k: was[k] for k in ("image", "digest", "signature", "image_source", "note") if k in was})
    res.patched = {"job": int(job), "commit": payload.get("commit"), "application_id": payload.get("application_id"),
                   "app": payload.get("app"), "tag": tag, "deployed_at": _iso(now), "previous_revision": prev}
    if before and before.get("job") is not None and int(before["job"]) != int(job):
        res.patched["replaced_job"] = int(before["job"])
    (d / "containerizer.json").write_text(json.dumps(res.to_dict(), indent=2, default=str) + "\n")
    if patch:                   # the order's patch, for developers who look here (apply it to the commit)
        (d / PATCH_FILE).write_text(str(patch))
    for f in also:
        if (out.root / f).is_dir():
            shutil.rmtree(out.root / f)
    write_sandbox(out.root, out.url, o.output_branch, _off(connect))
    sha = str(payload.get("commit") or "")[:12] or "unknown"
    out.commit(message or f"sandbox: {app_ns(app)} runs the Make it A patch of order #{job} (commit {sha})")
    return res


def deploy(connect, key, payload: dict, job: int, result: dict, work: Path, name: str, progress,
           now: datetime | None = None, health=None) -> dict:
    """Deploy the patched copy (work/<name>[/<subdir>]) into its application's folder; returns result["sandbox"]."""
    from .generate import app_ns
    from .org import Output
    now = now or utcnow()
    progress("deploying: preparing the sandbox deployment")
    target, o = _open(connect, key, payload, work / "deploy")
    scan, repo = target["scan"], target["repo"]
    subdir = (payload.get("source") or {}).get("subdir") or "."
    src = (work / name / subdir) if subdir != "." else work / name
    if not src.is_dir():
        raise Skip("not deployed: the patched copy is gone")
    tag = variant_tag(now, job)
    progress("deploying: building and running the components that did not change")
    a = _assessed(src, name, result, work / "deploy-verify")
    (work / "deploy").mkdir(parents=True, exist_ok=True)
    out = Output(o, work / "deploy")
    rel, app = app_folder(out.root, scan["Organization"], repo["ProjectName"], repo["Name"], repo.get("AppName"), payload)
    a.repo.name = app                       # the application's namespace, image paths, hosts and IdP clients
    ns = app_ns(app)
    progress("deploying: building the images and writing the GitOps files")
    res = _write_in_place(connect, target, o, out, payload, job, a, src, rel, app, tag, now, work / "deploy",
                          patch=result.get("patch"))
    if res.status != "deployed":
        return {"status": "skipped", "namespace": ns, "folder": rel, "in_place": True,
                "reason": f"not deployed: {res.reason}", "excluded": res.excluded}
    rev = _head(out.root)
    from .sandbox import deployed_apps
    comps = next((x["components"] for x in deployed_apps(out.root, {ns})), [])
    sb = {"status": "deployed", "in_place": True, "namespace": ns, "folder": rel, "of": rel, "scan_id": int(scan["ScanId"]),
          "tag": tag, "images": [c.get("image") for c in res.components], "revision": rev,
          "previous_revision": res.patched.get("previous_revision"), "replaced_job": res.patched.get("replaced_job"),
          "url": next((c.get("url") for c in comps if c.get("url")), None), "url_check": None, "checked_at": None,
          "deployed_at": _iso(now), "commit": payload.get("commit"), "excluded": res.excluded,
          "local_images": any(c.get("image_source") == "local" for c in res.components),
          "reason": "deployed"}
    progress("deploying: waiting for the sandbox to run it")
    sb.update((health or check_health)(out.root, ns, rev))
    return sb


def _head(root: Path) -> str:
    p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


def check_health(root: Path, namespace: str, revision: str, env=None, kube=None, sleep=None,
                 timeout: int | None = None) -> dict:
    """The variant's health from the cluster (read only, this namespace only): status running, failing or
    deployed (not checked), the reason, the URL check and when. No `revision`: whatever the cluster applied
    counts (refresh: a copy deployed earlier, checked again)."""
    from .sandbox import HEALTHY, SCHEDULED, KubeOptions, SandboxOptions, verify_sandbox
    env = os.environ if env is None else env
    kc = env.get(KUBECONFIG_ENV)
    if not kc and kube is None:
        return {"status": "deployed", "reason": "deployed; health not checked (no cluster access configured: "
                                                f"{KUBECONFIG_ENV})"}
    if timeout is None:
        try:
            timeout = int(env.get(TIMEOUT_ENV) or DEFAULT_TIMEOUT)
        except ValueError:
            timeout = DEFAULT_TIMEOUT
    so = SandboxOptions(kube=KubeOptions(kubeconfig=kc, context=env.get(CONTEXT_ENV) or None),
                        timeout=timeout, revision=revision, any_revision=not revision, learn=False,
                        apps=[namespace], wait_forbidden=bool(revision))
    kw = {"sleep": sleep} if sleep else {}
    doc = verify_sandbox(root, so, kube=kube, log=lambda m: None, **kw)
    from .sandbox import SKIPPED
    comps = doc.get("components") or []
    when = doc.get("checked_at")
    if doc.get("skipped") or not comps:
        return {"status": "deployed", "reason": f"deployed; health not checked: {doc.get('skipped') or 'no component'}",
                "checked_at": when}
    if all(c.get("status") == SKIPPED for c in comps):      # nothing could be observed: not known to fail
        return {"status": "deployed", "checked_at": when,
                "reason": f"deployed; health {str(comps[0].get('reason') or 'not checked')}"[:800]}
    comps = [c for c in comps if c.get("status") != SKIPPED]
    # a CronJob that has not run yet (its schedule is a placeholder) is deployed as it should be: not failing
    ok = all(c.get("status") in (HEALTHY, SCHEDULED) for c in comps)
    return {"status": "running" if ok else "failing", "checked_at": when,
            "reason": "; ".join(f"{c.get('component')}: {c.get('status_text')}" + (f" ({c['reason']})" if c.get("reason") else "")
                                for c in comps)[:800],
            "url_check": next((c.get("url_check") for c in comps if c.get("url_check")), None),
            "health": [{"component": c.get("component"), "status": c.get("status"), "reason": str(c.get("reason") or "")[:300],
                        **({"log_tail": str(c["log_tail"])[-1500:]} if c.get("log_tail") and c.get("status") not in (HEALTHY, SCHEDULED) else {})}
                       for c in comps]}


# --------------------------------------------------------------------------- removal

def _refresh_connectivity(connect, payload: dict, folder: Path, namespace: str) -> None:
    """The restored folder's connectivity.yaml and NetworkPolicies with the egress and link decisions made meanwhile
    (they are the application's, whichever copy ran): best effort, the egress review commits them otherwise."""
    if connect is None or payload.get("application_id") is None or not folder.is_dir() or not namespace:
        return
    try:
        from .egress import refresh_folder
        conn = connect()
        try:
            refresh_folder(conn, int(payload["application_id"]), folder, namespace)
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - the scan's output as it was
        pass


def remove(connect, key, job: int, payload: dict, sandbox: dict, work: Path, status: str = "removed",
           by: str | int | None = None, now: datetime | None = None) -> dict:
    """Take the order's patched copy out of the sandbox (one commit, sandbox/ regenerated). In place: when the
    application's folder still runs this order's patch, the scan's output is put back from the output repository's
    history (`previous_revision`); when a scan or a newer order wrote the folder since, nothing is left to undo and
    only the state is recorded. A variant folder of before (`<app>-refactor-<job>`) is deleted: Flux prunes its
    namespace. Returns the new result["sandbox"]."""
    from .org import Output, write_sandbox
    now = now or utcnow()
    folder = sandbox.get("folder") or ""
    here = in_place(sandbox)
    if not (valid_app_folder(folder) if here else valid_folder(folder, job)):
        raise Skip(f"not a sandbox folder of order #{job}: {folder!r}")
    newer = by if status == "outdated" and isinstance(by, int) else None    # the newer order that replaced it
    _, o = _open(connect, key, payload, work, deploying=False)
    work.mkdir(parents=True, exist_ok=True)
    out = Output(o, work)
    d = out.root / folder
    why = ("removed" if status != "outdated" else f"replaced by the patch of order #{newer}" if newer is not None
           else "outdated: its application's code changed")
    mine = False
    if here:
        m = marker(d)
        mine = bool(m) and int(m.get("job") or -1) == int(job)
        if mine:            # else a scan or a newer order wrote the folder since: nothing of this order is left there
            restore(out, folder, m.get("previous_revision"))
            _refresh_connectivity(connect, payload, d, sandbox.get("namespace") or "")
            write_sandbox(out.root, out.url, o.output_branch, _off(connect))
            out.commit(f"sandbox: {folder} gets the scan's output back: the Make it A patch of order #{job} {why}")
    else:
        if d.exists():
            shutil.rmtree(d)
        write_sandbox(out.root, out.url, o.output_branch, _off(connect))
        out.commit(f"containerizer: sandbox variant {folder} {why} (\"Make it A\" order #{job})")
    if newer is not None:
        reason = (f"replaced by newer code: order #{newer} deployed a newer patched copy of the application, and only "
                  f"the latest order's copy runs in the sandbox")
        by = None
    elif status == "outdated":          # `by` is the commit a scan assessed since
        reason = (f"replaced by newer code: a scan assessed commit {str(by or '')[:12]} of the application, and the "
                  f"patch was made for {str(payload.get('commit') or '')[:12]}")
        by = None
    else:
        reason = "removed from the sandbox" + (f" by {by}" if by else "")
        if mine:
            reason += ": the scan's output is back in the application's folder"
    return {**sandbox, "status": status, "removed_at": _iso(now), "removed_by": by, "reason": reason,
            "revision": _head(out.root)}


def _app_key(pl: dict, sb: dict):
    """What makes two orders' copies copies of one application: its ApplicationId, else its folder and app."""
    if pl.get("application_id") is not None:
        try:
            return ("id", int(pl["application_id"]))
        except (TypeError, ValueError):
            pass
    if sb.get("of"):
        return ("of", str(sb["of"]), str(pl.get("app") or ""))
    return None


def _parse(r: dict) -> tuple[dict, dict, dict] | None:
    try:
        res = json.loads(r["Result"]) if isinstance(r.get("Result"), str) else dict(r.get("Result") or {})
        pl = json.loads(r["Payload"]) if isinstance(r.get("Payload"), str) else dict(r.get("Payload") or {})
    except (ValueError, TypeError):
        return None
    return pl, res, res.get("sandbox") or {}


def due(rows: list[dict], latest: dict | None = None) -> list[tuple[dict, str, str | int | None]]:
    """(row, 'removed' | 'outdated', who asked, the new commit or the newer order's JobId (an int)) of the copies
    the runner takes out now: the ones someone asked to remove, the ones whose application a scan assessed at another
    commit than the patch was made for (`latest`: ApplicationId -> its latest assessed commit), and the ones a newer
    order of the same application replaced (only the copy of an application's latest order runs, whatever commit
    each was made for). A copy does not expire otherwise."""
    out, live = [], []
    for r in rows:
        x = _parse(r)
        if x is None:
            continue
        pl, _, sb = x
        if sb.get("status") not in ACTIVE or sb.get("removed_at"):
            continue
        if r.get("RemoveRequestedAt"):
            out.append((r, "removed", r.get("RemoveRequestedBy")))
            continue
        app_id = pl.get("application_id")
        now_at = (latest or {}).get(int(app_id)) if app_id is not None else None
        made_for = pl.get("commit")
        if now_at and made_for and not _same_commit(now_at, made_for):
            out.append((r, "outdated", now_at))
            continue
        live.append((r, _app_key(pl, sb)))
    newest: dict = {}
    for r, k in live:                   # the latest order of each application stays
        if k is not None and int(r["JobId"]) > newest.get(k, -1):
            newest[k] = int(r["JobId"])
    for r, k in live:
        if k is not None and int(r["JobId"]) < newest[k]:
            out.append((r, "outdated", newest[k]))
    return out


def latest_commits(conn) -> dict:
    """ApplicationId -> the commit its latest assessment is of."""
    return {int(r["ApplicationId"]): r["SourceCommit"] for r in _rows(
        conn, "SELECT ApplicationId, SourceCommit FROM cz.vApplicationLatest WHERE SourceCommit IS NOT NULL")}


# --------------------------------------------------------------------------- the variants of before move in place

def _patch_text(result: dict) -> bytes | None:
    import base64
    if result.get("patch_b64"):
        return base64.b64decode(result["patch_b64"])
    return str(result["patch"]).encode("utf-8") if result.get("patch") else None


def migrate(connect, key, job: int, payload: dict, result: dict, work: Path, also: tuple = (),
            now: datetime | None = None) -> dict:
    """Move a variant of before (`<Org>/<Project>/<Repo>-refactor-<job>`, its own namespace) into its application's
    folder: the source at the order's commit with its patch, generated again under the application's name (its
    namespace, hosts, IdP clients, lab services), with the images it was built as (nothing is built or verified
    again: it rated A and ran), the variant folder and `also` (older variants of the application) deleted, sandbox/
    regenerated: one commit. Returns the new result["sandbox"]; Skip when it cannot be moved."""
    from . import refactor as rf
    from .assess import assess
    from .generate import app_ns
    from .org import OK_VERIFY, Output
    now = now or utcnow()
    sb = result.get("sandbox") or {}
    old = sb.get("folder") or ""
    if not valid_folder(old, job):
        raise Skip(f"not a sandbox variant folder of order #{job}: {old!r}")
    patch = _patch_text(result)
    if not patch:
        raise Skip("the order has no patch")
    target, o = _open(connect, key, payload, work / "deploy", deploying=False)
    o = dataclasses.replace(o, push_images=False, local_images=False)      # the images are there already
    scan, repo = target["scan"], target["repo"]
    name = rf.variant_name(payload.get("app"), job)
    try:
        top, _ = rf.checkout(payload["source"], payload.get("commit"), work / name)
    except (rf.RefactorError, KeyError) as ex:
        raise Skip(f"the source is not there: {ex}") from None
    ok, _ = rf.apply_patch(top, patch)
    if not ok:
        raise Skip("the patch no longer applies to its commit")
    subdir = (payload.get("source") or {}).get("subdir") or "."
    src = top / subdir if subdir != "." else top
    (work / "deploy").mkdir(parents=True, exist_ok=True)
    out = Output(o, work / "deploy")
    was = _doc(out.root / old)
    images = {c.get("component"): c for c in was.get("components") or [] if c.get("image")}
    if not images:
        raise Skip("its folder records no image")
    a = assess(src)
    a.verification = [{"component": n, "status": c.get("verification") if c.get("verification") in OK_VERIFY else "ok"}
                      for n, c in images.items()]
    rel, app = app_folder(out.root, scan["Organization"], repo["ProjectName"], repo["Name"], repo.get("AppName"), payload)
    a.repo.name = app
    ns = app_ns(app)
    sha = str(payload.get("commit") or "")[:12] or "unknown"
    res = _write_in_place(connect, target, o, out, payload, job, a, src, rel, app, sb.get("tag") or variant_tag(now, job),
                          now, work / "deploy", patch=result.get("patch"), images=images,
                          also=(old, *also),
                          message=f"sandbox: {ns} runs the Make it A patch of order #{job} (commit {sha}), moved from "
                                  f"{old} (patched copies run in their application's folder now)")
    if res.status != "deployed":
        raise Skip(f"not moved: {res.reason}")
    from .sandbox import deployed_apps
    comps = next((x["components"] for x in deployed_apps(out.root, {ns})), [])
    return {**sb, "status": "deployed", "in_place": True, "namespace": ns, "folder": rel, "of": rel,
            "images": [c.get("image") for c in res.components], "revision": _head(out.root),
            "previous_revision": res.patched.get("previous_revision"), "replaced_job": res.patched.get("replaced_job"),
            "url": next((c.get("url") for c in comps if c.get("url")), None), "url_check": None, "checked_at": None,
            "health": None, "moved_at": _iso(now),
            "moved_from": {"folder": old, "namespace": sb.get("namespace"), "url": sb.get("url")},
            "reason": f"moved from {old} into the application's own folder and namespace {ns} (patched copies run in "
                      f"place now); health not checked since the move"}


def _move_variants(connect, key, rows: list[dict], todo: list, work: Path, log, now) -> int:
    """The variants of before: the latest active one of each application moves into its folder (migrate), with the
    older ones' folders deleted in the same commit; one that cannot move is taken out (removed, with why)."""
    from .orgsource import REDACT
    gone = {int(r["JobId"]) for r, _, _ in todo}
    legacy: dict = {}
    for r in rows:
        x = _parse(r)
        if x is None:
            continue
        pl, _, sb = x
        if sb.get("status") in ACTIVE and not sb.get("removed_at") and not in_place(sb) and sb.get("folder"):
            legacy.setdefault(_app_key(pl, sb), []).append(r)
    n = 0
    for k, group in legacy.items():
        stay = [r for r in group if int(r["JobId"]) not in gone]
        if not stay:
            continue                    # removed or outdated: housekeep deletes the folders
        r = max(stay, key=lambda x: int(x["JobId"]))
        jid = int(r["JobId"])
        pl, result, sb = _parse(r)
        also = tuple(f for x in group if x is not r and int(x["JobId"]) in gone
                     and valid_folder(f := str(_parse(x)[2].get("folder") or ""), int(x["JobId"])))
        try:
            new = migrate(connect, key, jid, pl, result, work / f"move-{jid}", also, now)
        except Skip as ex:
            try:
                new = remove(connect, key, jid, pl, sb, work / f"move-{jid}-rm", "removed", None, now)
                new["reason"] = (f"taken out of the sandbox: it could not be moved into its application's folder "
                                 f"({ex}); Build again (no LLM) deploys the patch there")[:600]
            except Skip as ex2:
                new = {**sb, "status": "error", "reason": f"could not be moved or removed: {ex}; {ex2}"[:600]}
            except Exception as ex2:  # noqa: BLE001 - tried again next time
                log(f"#{jid}: sandbox variant not moved: {REDACT(f'{type(ex2).__name__}: {ex2}')[:300]}")
                continue
        except Exception as ex:  # noqa: BLE001 - tried again next time
            log(f"#{jid}: sandbox variant not moved: {REDACT(f'{type(ex).__name__}: {ex}')[:300]}")
            continue
        finally:
            shutil.rmtree(work / f"move-{jid}", ignore_errors=True)
            shutil.rmtree(work / f"move-{jid}-rm", ignore_errors=True)
        result["sandbox"] = new
        r["Result"] = json.dumps(result)        # the removals below see where it runs now
        _save(connect, jid, result)
        log(f"#{jid}: sandbox variant {sb.get('namespace')} -> {new.get('namespace')} ({new['status']})")
        n += 1
    return n


def _save(connect, jid: int, result: dict) -> None:
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE cz.LlmJob SET Result = %s WHERE JobId = %s AND Status = N'answered'",
                    (json.dumps(result), jid))
        conn.commit()
    finally:
        conn.close()


def housekeep(connect, key, work: Path, log=print, now: datetime | None = None) -> int:
    """The queue runner's periodic step: move the variants of before into their applications' folders
    (_move_variants), then take out the copies whose application's code changed (a scan assessed another commit),
    that a newer order of the same application replaced, or that someone asked to remove. Returns how many changed."""
    from .orgsource import REDACT
    conn = connect()
    try:
        rows = _rows(conn, "SELECT JobId, Payload, Result, RemoveRequestedAt, RemoveRequestedBy FROM cz.LlmJob "
                           "WHERE Kind = N'refactor' AND Status = N'answered' "
                           "AND JSON_VALUE(Result, '$.sandbox.folder') IS NOT NULL "
                           "AND JSON_VALUE(Result, '$.sandbox.removed_at') IS NULL")
        latest = latest_commits(conn) if rows else {}
    finally:
        conn.close()
    todo = due(rows, latest)
    n = _move_variants(connect, key, rows, todo, work, log, now) if rows else 0
    for r, status, by in todo:
        jid = int(r["JobId"])
        result = json.loads(r["Result"]) if isinstance(r["Result"], str) else dict(r["Result"])
        payload = json.loads(r["Payload"]) if isinstance(r["Payload"], str) else dict(r["Payload"] or {})
        try:
            sb = remove(connect, key, jid, payload, result["sandbox"], work / f"remove-{jid}", status, by, now)
        except Skip as ex:
            sb = {**result["sandbox"], "status": "error", "reason": f"could not be removed: {ex}"[:600]}
        except Exception as ex:  # noqa: BLE001 - tried again next time
            log(f"#{jid}: sandbox copy not removed: {REDACT(f'{type(ex).__name__}: {ex}')[:300]}")
            continue
        finally:
            shutil.rmtree(work / f"remove-{jid}", ignore_errors=True)
        result["sandbox"] = sb
        _save(connect, jid, result)
        log(f"#{jid}: sandbox copy in {sb.get('namespace')} {sb['status']}")
        n += 1
    return n



# --------------------------------------------------------------------------- what runs in the sandbox now

SANDBOX_OFF_TEXT = ("the application's sandbox is turned off (Admin → Applications): the patched copy stays in its "
                    "folder and runs again when it is turned on")


def _parse_iso(v) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(v).replace("Z", ""))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _last_look(sb: dict) -> datetime | None:
    """When the order's sandbox state was last compared with the cluster or the output repository."""
    ts = [t for t in (_parse_iso(sb.get(k)) for k in ("checked_at", "looked_at", "deployed_at", "moved_at",
                                                      "removed_at")) if t]
    return max(ts) if ts else None


def stale(rows: list[dict], off: set, now: datetime) -> tuple[list[tuple[dict, dict]], list[tuple[dict, str]]]:
    """(the rows whose sandbox state the cluster or the output repository says something else about by now: (row,
    the new state) with no Git or cluster access needed, the rows to look at in the output repository and the
    cluster: (row, why)). Copies in their application's folder only; an active one is checked again after
    RECHECK_UNCHECKED (health not known) or RECHECK_CHECKED; the latest removed copy of an application hourly, in
    case its folder runs it again (taken out by an LLM-heavy chain, a removal that found the folder written since);
    one whose application's sandbox is turned off is `off` until it is turned on again."""
    latest: dict = {}
    for r in rows:
        x = _parse(r)
        if x is None:
            continue
        pl, _, sb = x
        k = _app_key(pl, sb)
        if k is not None and in_place(sb) and int(r["JobId"]) > latest.get(k, -1):
            latest[k] = int(r["JobId"])
    now_set, look = [], []
    for r in rows:
        x = _parse(r)
        if x is None or r.get("RemoveRequestedAt"):
            continue
        pl, _, sb = x
        if not in_place(sb) or not valid_app_folder(str(sb.get("folder") or "")):
            continue
        st, aid = sb.get("status"), pl.get("application_id")
        is_off = aid is not None and str(aid).isdigit() and int(aid) in off
        last = _last_look(sb)
        age = (now - last).total_seconds() if last else float("inf")
        if st in ACTIVE and not sb.get("removed_at"):
            if is_off:
                if st != "off":
                    now_set.append((r, {**sb, "status": "off", "reason": SANDBOX_OFF_TEXT, "looked_at": _iso(now)}))
            elif st == "off":
                look.append((r, "its application's sandbox is on again"))
            elif age >= (RECHECK_UNCHECKED if st == "deployed" else RECHECK_CHECKED):
                look.append((r, "checked again"))
        elif st == "removed" and sb.get("removed_at") and latest.get(_app_key(pl, sb)) == int(r["JobId"]) \
                and age >= RECHECK_CHECKED:
            look.append((r, "is it in its application's folder again"))
    look.sort(key=lambda x: _last_look(_parse(x[0])[2]) or datetime.min.replace(tzinfo=timezone.utc))
    return now_set, look


def refresh(connect, key, work: Path, log=print, now: datetime | None = None, health=None,
            limit: int = RECHECK_PER_PASS) -> int:
    """The queue runner's periodic step after housekeep: the sandbox state of the orders' patched copies kept true
    (stale): the health read again from the cluster (a deploy's check may have found nothing yet, the copy may break
    or recover later), `off` while the application's sandbox is turned off, and the state taken from the output
    repository, whose application folder says which order's patch runs there: removed when it no longer runs this
    one, active again when it does. Returns how many changed."""
    from .orgsource import REDACT
    from .org import Output, load_sandbox_off
    now = now or utcnow()
    conn = connect()
    try:
        rows = _rows(conn, "SELECT JobId, Payload, Result, RemoveRequestedAt FROM cz.LlmJob "
                           "WHERE Kind = N'refactor' AND Status = N'answered' "
                           "AND JSON_VALUE(Result, '$.sandbox.folder') IS NOT NULL "
                           "AND JSON_VALUE(Result, '$.sandbox.status') IN (N'running', N'failing', N'deployed', N'off', "
                           "N'removed')")
        off = load_sandbox_off(conn) if rows else set()
    finally:
        conn.close()
    if not rows:
        return 0
    now_set, look = stale(rows, off, now)
    n = 0
    for r, sb in now_set:
        res = _parse(r)[1]
        res["sandbox"] = sb
        _save(connect, int(r["JobId"]), res)
        log(f"#{r['JobId']}: sandbox copy in {sb.get('namespace')} off (its application's sandbox is turned off)")
        n += 1
    outs: dict = {}
    try:
        for r, why in look[:max(0, limit)]:
            jid = int(r["JobId"])
            pl, res, sb = _parse(r)
            try:
                target, o = _open(connect, key, pl, work / f"look-{jid}", deploying=False)
                repo = target["scan"]["OutputRepo"]
                if repo not in outs:
                    d = work / f"look-out-{len(outs)}"
                    d.mkdir(parents=True, exist_ok=True)
                    outs[repo] = Output(o, d)
                out = outs[repo]
                folder = str(sb.get("folder") or "")
                m = marker(out.root / folder)
                mine = bool(m) and int(m.get("job") or -1) == jid
                if not mine:
                    if sb.get("status") == "removed":
                        new = {**sb, "looked_at": _iso(now)}
                    else:
                        ran = f"the patch of order #{m['job']}" if m else "the scan's output"
                        new = {**sb, "status": "removed", "removed_at": _iso(now), "removed_by": None,
                               "looked_at": _iso(now),
                               "reason": f"not in the sandbox any more: its application's folder {folder} runs {ran} now"}
                else:
                    h = (health or check_health)(out.root, sb.get("namespace") or "", "", timeout=RECHECK_TIMEOUT)
                    new = {k: v for k, v in sb.items() if k not in ("removed_at", "removed_by")}
                    new.update(h)
                    new["looked_at"] = _iso(now)
                    if sb.get("status") == "removed":
                        new["back_at"] = _iso(now)
                        new["reason"] = (f"in the sandbox again: its application's folder {folder} runs this patch; "
                                         f"{h.get('reason') or ''}")[:800]
            except Skip as ex:
                new = {**sb, "looked_at": _iso(now)}
                log(f"#{jid}: sandbox state not refreshed: {ex}"[:400])
            except Exception as ex:  # noqa: BLE001 - tried again next time
                log(f"#{jid}: sandbox state not refreshed: {REDACT(f'{type(ex).__name__}: {ex}')[:300]}")
                continue
            changed = {k: new.get(k) for k in ("status", "reason", "removed_at")} != \
                {k: sb.get(k) for k in ("status", "reason", "removed_at")}
            res["sandbox"] = new
            _save(connect, jid, res)
            if changed:
                log(f"#{jid}: sandbox copy in {new.get('namespace')} {new['status']} ({why})")
                n += 1
    finally:
        for i in range(len(outs)):
            shutil.rmtree(work / f"look-out-{i}", ignore_errors=True)
    return n


# --------------------------------------------------------------------------- the applications' sandbox switch

SYNC_STATE = "sandbox-off.json"


def sync_sandbox(connect, key, work: Path, log=print) -> int:
    """The queue runner's periodic step: when an administrator turned an application's sandbox off or on, regenerate
    sandbox/ in every output repository (org.write_sandbox leaves those applications out; their folders and images
    stay, so on again deploys them as they were, without a build). Only when the set changed since the last sync
    (work/sandbox-off.json). Returns the commits made."""
    from .credentials import load, private_key_from_env
    from .org import Output, host_allowed, load_sandbox_off, write_sandbox
    from .orgsource import REDACT
    from .worker import allowed_hosts
    conn = connect()
    try:
        off = load_sandbox_off(conn)
        scans = _rows(conn, "SELECT * FROM cz.OrgScan WHERE OutputRepo IS NOT NULL ORDER BY ScanId")
        creds = load(conn, key if key is not None else private_key_from_env()) if scans else None
    finally:
        conn.close()
    sig = json.dumps(sorted(str(x) for x in off))
    state = work / SYNC_STATE
    if state.is_file() and state.read_text() == sig:
        return 0
    n, seen = 0, set()
    hosts = allowed_hosts() | (creds.hosts() if creds else set())
    for scan in scans:
        repo = scan["OutputRepo"]
        if repo in seen:
            continue
        seen.add(repo)
        write = creds.write_for(repo) if creds else None
        if write is None or not write.token or not host_allowed(repo, hosts):
            log(f"sandbox switch: {repo} not updated: no write token for it, or its host is not allowed")
            continue
        REDACT.add(write.token, write.username)
        d = work / f"sync-{len(seen)}"
        shutil.rmtree(d, ignore_errors=True)
        try:
            o = options(scan, write, d)
            out = Output(o, d)
            write_sandbox(out.root, out.url, o.output_branch, off)
            if out.commit("containerizer: sandbox/ follows the applications' sandbox switches (Admin → Applications)"):
                n += 1
                log(f"sandbox switch: {repo}: sandbox/ regenerated")
        finally:
            shutil.rmtree(d, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    state.write_text(sig)
    return n

