"""Sandbox variants of "Make it A" orders (refactor.py, goal rating-a; docs/refactoring.md#the-sandbox-variant).

A "Make it A" order whose patched copy assesses as A and verifies is deployed to the sandbox BESIDE the
original application, never in its place, the way an organization scan deploys (org.deploy_app): the
patched copy's folder is named `<app>-refactor-<job>` (refactor.variant_name), so its namespace, image paths
(`<registry>/<app>-refactor-<job>/<component>:1.<yyyymmdd>.<hhmm>-refactor.<job>`), Ingress hosts, IdP client
names and lab services (a new, empty lab database) all derive from that name. Its files go to a sibling
folder of the original in the output repository of the organization scan that assessed the application,
`<Org>/<Project>/<Repo>-refactor-<job>/`, and sandbox/ is regenerated (org.write_sandbox); Flux (or Argo CD)
pulls it from there.

- Settings: the organization scan's (cz.OrgScan: Registry, OutputRepo, OutputBranch, ImagePullSecret, Gate,
  PushImages), found through the order's source (the scan worker's clone of the repository); the output
  repository's write token is the registered one, opened with the credential key (as the scan worker does).
  An application no organization scan with an output repository assessed is not deployed (the reason says so).
- Health: read back with a read-only kubeconfig (CONTAINERIZER_SANDBOX_KUBECONFIG, optional
  CONTAINERIZER_SANDBOX_CONTEXT) for this namespace only (sandbox.verify_sandbox with `apps`), without the
  learning loop and without cz.SandboxCheck rows: the variant's health is in the order's result
  (`result["sandbox"]`), so the original application's sandbox results stay as they are. Without a kubeconfig:
  "deployed; health not checked".
- Expiry and removal: a variant expires after CONTAINERIZER_SANDBOX_VARIANT_DAYS days (default 7); "Remove from
  the sandbox" on the order page asks for its removal (cz.LlmJob.RemoveRequestedAt). The queue runner removes
  expired and requested variants (housekeep): the folder is deleted, sandbox/ regenerated and committed, and
  the removal recorded in the result.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

EXPIRY_ENV = "CONTAINERIZER_SANDBOX_VARIANT_DAYS"
KUBECONFIG_ENV = "CONTAINERIZER_SANDBOX_KUBECONFIG"
CONTEXT_ENV = "CONTAINERIZER_SANDBOX_CONTEXT"
GITOPS_ENV = "CONTAINERIZER_SANDBOX_GITOPS"
TIMEOUT_ENV = "CONTAINERIZER_SANDBOX_VARIANT_TIMEOUT"
DEFAULT_DAYS = 7
DEFAULT_TIMEOUT = 900
SUFFIX = "-refactor-"
STATUSES = ("deploying", "running", "failing", "deployed", "skipped", "error", "removed", "expired")
STATUS_TEXT = {"deploying": "Deploying", "running": "Running in the sandbox", "failing": "Failing in the sandbox",
               "deployed": "Deployed, health not checked", "skipped": "Not deployed", "error": "Deploy failed",
               "removed": "Removed from the sandbox", "expired": "Expired"}
ACTIVE = ("running", "failing", "deployed")         # in the output repository: can be removed
HOUSEKEEP_SECONDS = 300                             # how often the runner looks for expired variants


class Skip(Exception):
    """The variant is not deployed, for a reason the order page shows."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def expiry_days(env=None) -> int:
    env = os.environ if env is None else env
    try:
        return max(1, min(365, int(env.get(EXPIRY_ENV) or DEFAULT_DAYS)))
    except ValueError:
        return DEFAULT_DAYS


def variant_tag(now: datetime, job: int) -> str:
    """The images' tag: org.default_tag with a pre-release part, so the original's image automation (semver
    range >=1.0.0) never takes it."""
    from .org import default_tag
    return f"{default_tag(now)}-refactor.{int(job)}"


def variant_rel(org: str, project: str, repo: str, job: int) -> str:
    """`<Org>/<Project>/<Repo>-refactor-<job>`: a sibling of the original's folder (three levels, so
    org._apps_in and write_sandbox take it)."""
    from .org import segment
    return f"{segment(org)}/{segment(project)}/{segment(repo)}{SUFFIX}{int(job)}"


def valid_folder(rel: str, job: int) -> bool:
    """A folder the runner may delete: three plain segments, the last one a variant of this job."""
    from .refactor import safe_rel
    parts = str(rel or "").split("/")
    return safe_rel(rel) == rel and len(parts) == 3 and parts[0] != "sandbox" and parts[2].endswith(f"{SUFFIX}{int(job)}")


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
    return OrgOptions(provider=scan["Provider"], org=scan["Organization"], registry=scan["Registry"],
                      api_url=scan.get("ApiUrl"), token="", output_repo=scan["OutputRepo"],
                      output_branch=scan.get("OutputBranch") or "main", output_token=write.token or "",
                      output_username=write.username or "x-access-token", push_images=bool(scan.get("PushImages")),
                      image_pull_secret=scan.get("ImagePullSecret"), verify=True, gate=bool(scan.get("Gate")),
                      sql=None, work_dir=str(work), ai=False)


def _open(connect, key, payload: dict, work: Path):
    """(target, OrgOptions) with the output repository's write token; Skip when it cannot be deployed."""
    from .credentials import CredentialError, load, private_key_from_env
    from .org import host_allowed
    from .orgsource import REDACT
    from .worker import allowed_hosts
    conn = connect()
    try:
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
    if scan.get("PushImages") and not host_allowed(scan["Registry"], hosts):
        raise Skip("the registry host is not allowed on this machine (CONTAINERIZER_WORKER_HOSTS)")
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


def deploy(connect, key, payload: dict, job: int, result: dict, work: Path, name: str, progress,
           now: datetime | None = None, health=None) -> dict:
    """Deploy the patched copy (work/<name>[/<subdir>]) as a variant; returns result["sandbox"]."""
    from .gitops import GitOpsOptions
    from .org import Output, Registry, RepoResult, deploy_app, write_sandbox
    from .sandbox_https import configured_domain
    now = now or utcnow()
    progress("deploying: preparing the sandbox variant")
    target, o = _open(connect, key, payload, work / "deploy")
    scan, repo = target["scan"], target["repo"]
    subdir = (payload.get("source") or {}).get("subdir") or "."
    src = (work / name / subdir) if subdir != "." else work / name
    if not src.is_dir():
        raise Skip("not deployed: the patched copy is gone")
    rel = variant_rel(scan["Organization"], repo["ProjectName"], repo["Name"], job)
    from .org import segment
    original = f"{segment(scan['Organization'])}/{segment(repo['ProjectName'])}/{segment(repo['Name'])}"
    tag = variant_tag(now, job)
    expires = now + timedelta(days=expiry_days())
    progress("deploying: building and running the components that did not change")
    a = _assessed(src, name, result, work / "deploy-verify")
    (work / "deploy").mkdir(parents=True, exist_ok=True)
    out = Output(o, work / "deploy")
    gitops = GitOpsOptions(git_url=out.url, branch=o.output_branch, path=rel, image_pull_secret=o.image_pull_secret or "",
                           ingress_domain=configured_domain(), sandbox_idp=True)
    res = RepoResult(provider=scan["Provider"], org=scan["Organization"], project=repo["ProjectName"],
                     repo=f"{repo['Name']}{SUFFIX}{job}", status="error", web_url=repo.get("WebUrl") or "",
                     clone_url=repo.get("CloneUrl") or "", branch=repo.get("DefaultBranch") or "",
                     commit=str(payload.get("commit") or ""), app=name, rating=a.rating,
                     processed_at=_iso(now) + "Z")
    progress("deploying: building the images and writing the GitOps files")
    reg = Registry(o.registry) if o.push_images else None
    try:
        res = deploy_app(a, src, rel, o, out, reg, tag, gitops, res, work / "deploy", name, dev_database=False)
    finally:
        if reg:
            reg.close()
    if res.status != "deployed":
        return {"status": "skipped", "namespace": name, "reason": f"not deployed: {res.reason}",
                "excluded": res.excluded}
    doc = res.to_dict()
    doc["variant"] = {"of": original, "of_app": payload.get("app"), "job": job, "application_id": payload.get("application_id"),
                      "expires_at": _iso(expires)}
    (out.root / rel / "containerizer.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
    write_sandbox(out.root, out.url, o.output_branch)
    out.commit(f"containerizer: sandbox variant {rel} of {original} (\"Make it A\" order #{job}, {tag})")
    rev = _head(out.root)
    from .sandbox import deployed_apps
    comps = next((x["components"] for x in deployed_apps(out.root, {name})), [])
    sb = {"status": "deployed", "namespace": name, "folder": rel, "of": original, "scan_id": int(scan["ScanId"]),
          "tag": tag, "images": [c.get("image") for c in res.components], "revision": rev,
          "url": next((c.get("url") for c in comps if c.get("url")), None), "url_check": None, "checked_at": None,
          "deployed_at": _iso(now), "expires_at": _iso(expires), "excluded": res.excluded,
          "local_images": any(c.get("image_source") == "local" for c in res.components),
          "reason": "deployed"}
    progress("deploying: waiting for the sandbox to run it")
    sb.update((health or check_health)(out.root, name, rev))
    return sb


def _head(root: Path) -> str:
    p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


def check_health(root: Path, namespace: str, revision: str, env=None, kube=None, sleep=None) -> dict:
    """The variant's health from the cluster (read only, this namespace only): status running, failing or
    deployed (not checked), the reason, the URL check and when."""
    from .sandbox import HEALTHY, KubeOptions, SandboxOptions, verify_sandbox
    env = os.environ if env is None else env
    kc = env.get(KUBECONFIG_ENV)
    if not kc and kube is None:
        return {"status": "deployed", "reason": "deployed; health not checked (no cluster access configured: "
                                                f"{KUBECONFIG_ENV})"}
    try:
        timeout = int(env.get(TIMEOUT_ENV) or DEFAULT_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    so = SandboxOptions(kube=KubeOptions(kubeconfig=kc, context=env.get(CONTEXT_ENV) or None),
                        gitops=env.get(GITOPS_ENV) or "auto", timeout=timeout, revision=revision, learn=False,
                        apps=[namespace], wait_forbidden=True)
    kw = {"sleep": sleep} if sleep else {}
    doc = verify_sandbox(root, so, kube=kube, log=lambda m: None, **kw)
    comps = doc.get("components") or []
    when = doc.get("checked_at")
    if doc.get("skipped") or not comps:
        return {"status": "deployed", "reason": f"deployed; health not checked: {doc.get('skipped') or 'no component'}",
                "checked_at": when}
    ok = all(c.get("status") == HEALTHY for c in comps)
    return {"status": "running" if ok else "failing", "checked_at": when,
            "reason": "; ".join(f"{c.get('component')}: {c.get('status_text')}" + (f" ({c['reason']})" if c.get("reason") else "")
                                for c in comps)[:800],
            "url_check": next((c.get("url_check") for c in comps if c.get("url_check")), None),
            "health": [{"component": c.get("component"), "status": c.get("status"), "reason": str(c.get("reason") or "")[:300]}
                       for c in comps]}


# --------------------------------------------------------------------------- removal

def remove(connect, key, job: int, payload: dict, sandbox: dict, work: Path, status: str = "removed",
           by: str | None = None, now: datetime | None = None) -> dict:
    """Take a variant out of the output repository (its folder, sandbox/ regenerated, one commit): Flux prunes
    the namespace. Returns the new result["sandbox"]."""
    from .org import Output, write_sandbox
    now = now or utcnow()
    folder = sandbox.get("folder") or ""
    if not valid_folder(folder, job):
        raise Skip(f"not a sandbox variant folder of order #{job}: {folder!r}")
    _, o = _open(connect, key, payload, work)
    work.mkdir(parents=True, exist_ok=True)
    out = Output(o, work)
    d = out.root / folder
    if d.exists():
        shutil.rmtree(d)
    write_sandbox(out.root, out.url, o.output_branch)
    why = "expired" if status == "expired" else "removed"
    out.commit(f"containerizer: sandbox variant {folder} {why} (\"Make it A\" order #{job})")
    return {**sandbox, "status": status, "removed_at": _iso(now), "removed_by": by,
            "reason": (f"expired after {expiry_days()} days" if status == "expired" else
                       "removed from the sandbox" + (f" by {by}" if by else "")), "revision": _head(out.root)}


def due(rows: list[dict], now: datetime | None = None) -> list[tuple[dict, str]]:
    """(row, 'removed' | 'expired') of the variants the runner takes out now."""
    now = now or utcnow()
    out = []
    for r in rows:
        try:
            sb = (json.loads(r["Result"]) if isinstance(r.get("Result"), str) else r.get("Result") or {}).get("sandbox") or {}
        except ValueError:
            continue
        if sb.get("status") not in ACTIVE or sb.get("removed_at"):
            continue
        if r.get("RemoveRequestedAt"):
            out.append((r, "removed"))
            continue
        try:
            exp = datetime.fromisoformat(str(sb.get("expires_at"))).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if exp <= now:
            out.append((r, "expired"))
    return out


def housekeep(connect, key, work: Path, log=print, now: datetime | None = None) -> int:
    """The queue runner's periodic step: remove the variants that expired or that someone asked to remove.
    Returns how many were removed."""
    from .orgsource import REDACT
    conn = connect()
    try:
        rows = _rows(conn, "SELECT JobId, Payload, Result, RemoveRequestedAt, RemoveRequestedBy FROM cz.LlmJob "
                           "WHERE Kind = N'refactor' AND Status = N'answered' "
                           "AND JSON_VALUE(Result, '$.sandbox.folder') IS NOT NULL "
                           "AND JSON_VALUE(Result, '$.sandbox.removed_at') IS NULL")
    finally:
        conn.close()
    n = 0
    for r, status in due(rows, now):
        jid = int(r["JobId"])
        result = json.loads(r["Result"]) if isinstance(r["Result"], str) else dict(r["Result"])
        payload = json.loads(r["Payload"]) if isinstance(r["Payload"], str) else dict(r["Payload"] or {})
        try:
            sb = remove(connect, key, jid, payload, result["sandbox"], work / f"remove-{jid}", status,
                        r.get("RemoveRequestedBy"), now)
        except Skip as ex:
            sb = {**result["sandbox"], "status": "error", "reason": f"could not be removed: {ex}"[:600]}
        except Exception as ex:  # noqa: BLE001 - tried again next time
            log(f"#{jid}: sandbox variant not removed: {REDACT(f'{type(ex).__name__}: {ex}')[:300]}")
            continue
        finally:
            shutil.rmtree(work / f"remove-{jid}", ignore_errors=True)
        result["sandbox"] = sb
        conn = connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET Result = %s WHERE JobId = %s AND Status = N'answered'",
                        (json.dumps(result), jid))
            conn.commit()
        finally:
            conn.close()
        log(f"#{jid}: sandbox variant {sb.get('namespace')} {sb['status']}")
        n += 1
    return n
