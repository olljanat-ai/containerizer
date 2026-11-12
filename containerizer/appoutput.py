"""An application's own output repository (Admin → Applications → Output repository, administrators; schema 36).

An organization scan writes every application it deploys to its output repository (`<Org>/<Project>/<Repo>/`).
An administrator can give one application a repository of its own (one with a write token under Source control),
a branch and a folder (`deploy` by default): the starting point of its real deployment. The LLM queue runner (it
holds the write tokens) then moves the application's files there, once (housekeep):

1. the application's folder in the scan's output repository is copied to `<folder>/` of its own repository, its
   Flux files (`gitops/flux/git/sync.yaml`, `image-automation.yaml`, `gitops/README.md`) pointed at that
   repository, branch and folder; `containerizer.json` says where it came from (`moved_from`). One commit there.
   A folder that is not empty is not overwritten: an earlier copy of the same application is kept as it is.
2. the folder in the scan's output repository becomes a stub: `containerizer.json` (with `moved_to`), the Flux
   tenant and sync files (pointed at the application's repository, so `sandbox/` still includes it and the sandbox
   deploys it from there), each component's `idp.json` and `k8s.yaml` (the sandbox's IdP and health checks read
   them) and a README. `sandbox/` is regenerated; one commit.
3. Application.OutputMovedAt/Commit/Namespace are recorded (or OutputMoveError, tried again every 10 minutes).

Afterwards Containerizer does not write the application's files again: the scans assess it only (status `moved`,
org.deploy_app) and never remove its stub. The sandbox reads the application's repository with that repository's
read token: the runner writes it for cz-sandbox (root) to `<CONTAINERIZER_SANDBOX_GIT_DIR>/<namespace>` (0600,
the runner's user; url, user name and token on three lines), which puts it into the namespace's `<ns>--cz-git`
key. A read token registered for the organization the repository is in is used, else its write token.

Clearing the setting brings the application back: the runner removes the stub (the sandbox removes the
application), and the next scan generates and deploys it in the scan's output repository again. The copy in the
application's own repository stays.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

DEFAULT_PATH = "deploy"
PATH_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*")
NS_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
TOKENS_ENV = "CONTAINERIZER_SANDBOX_GIT_DIR"
TOKENS_DIR = "/var/lib/containerizer/refactor/sandbox-git"
STATE = "app-output.json"
RETRY_SECONDS = 600
MOVED = "moved"
WAITING = "waiting for a scan to deploy it to its output repository"


class MoveError(RuntimeError):
    pass


def clean_path(p: str | None) -> str | None:
    """The folder in the application's repository: relative, no `..`, letters, digits, `._-` (None: not valid)."""
    p = (p or "").strip().strip("/") or DEFAULT_PATH
    if len(p) > 200 or not PATH_RE.fullmatch(p) or any(x in ("..", ".git") for x in p.split("/")) \
            or p.split("/")[0] in ("sandbox", "clusters"):
        return None
    return p


def _doc(folder: Path) -> dict | None:
    try:
        doc = json.loads((folder / "containerizer.json").read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def moved_to(folder: Path) -> dict | None:
    """Where an application's files were moved ({repo, branch, path, commit, at}), from its stub in the scan's output
    repository; None when they were not."""
    m = (_doc(folder) or {}).get("moved_to")
    return m if isinstance(m, dict) and m.get("repo") else None


def moved_reason(m: dict) -> str:
    return (f"its files were moved to {m.get('repo')} (folder {m.get('path')}, branch {m.get('branch')}): "
            "assessed only, the scans no longer write them")


# --------------------------------------------------------------------------- the files

FLUX_FILES = ("gitops/flux/git/sync.yaml", "gitops/flux/git/image-automation.yaml")


def _repoint_docs(docs: list, url: str, branch: str, path: str) -> None:
    for d in docs:
        if not isinstance(d, dict):
            continue
        spec = d.setdefault("spec", {})
        kind = d.get("kind")
        if kind == "GitRepository":
            spec["url"] = url
            spec["ref"] = {"branch": branch}
        elif kind == "Kustomization" and (spec.get("sourceRef") or {}).get("kind") == "GitRepository":
            spec["path"] = f"./{path}"
        elif kind == "ImageUpdateAutomation":
            g = spec.setdefault("git", {})
            g.setdefault("checkout", {})["ref"] = {"branch": branch}
            g.setdefault("push", {})["branch"] = branch
            spec.setdefault("update", {})["path"] = f"./{path}"


def _check(docs: list, url: str, branch: str, path: str) -> bool:
    got = [d for d in docs if isinstance(d, dict)]
    want = json.loads(json.dumps(got, default=str))
    _repoint_docs(want, url, branch, path)
    return json.loads(json.dumps(got, default=str)) == want


def repoint(folder: Path, url: str, branch: str, path: str, old: dict | None = None) -> None:
    """The Flux files of an application folder point at `url`, `branch` and `path` (GitRepository, its
    Kustomization, the image automation). `old` ({repo, branch, path}): edited in place, keeping comments, when the
    result is the same; else rewritten. gitops/README.md names the new place."""
    for rel in FLUX_FILES:
        f = folder / rel
        if not f.is_file():
            continue
        text = f.read_text()
        if old:
            t = text.replace(f"url: {old['repo']}\n", f"url: {url}\n").replace(
                f"path: ./{old['path']}\n", f"path: ./{path}\n").replace(
                f"branch: {old['branch']}\n", f"branch: {branch}\n")
            try:
                if _check([x for x in yaml.safe_load_all(t)], url, branch, path):
                    f.write_text(t)
                    continue
            except yaml.YAMLError:
                pass
        docs = [x for x in yaml.safe_load_all(text) if x is not None]
        _repoint_docs(docs, url, branch, path)
        f.write_text("---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs))
    readme = folder / "gitops" / "README.md"
    if old and readme.is_file():
        readme.write_text(readme.read_text().replace(f"`{old['repo']}`", f"`{url}`").replace(
            f"`{old['path']}`", f"`{path}`").replace(f"`{old['branch']}`", f"`{branch}`"))


def copy_app(src: Path, dst_root: Path, path: str, url: str, branch: str, moved_from: dict) -> bool:
    """The application's folder (`src`, in the scan's output repository) copied to `dst_root/path` and pointed at it.
    Returns False when the folder holds this application's copy already (a move tried again, or made before):
    kept as it is. A folder with anything else in it is refused."""
    dst = dst_root / path
    if dst.exists() and (not dst.is_dir() or any(dst.iterdir())):
        mine = _doc(dst) or {}
        if mine.get("source_key") and mine.get("source_key") == moved_from.get("source_key"):
            return False
        raise MoveError(f"folder {path}/ of {url} is not empty: empty it, or choose another folder")
    if dst.exists():
        dst.rmdir()
    dst.parent.mkdir(parents=True, exist_ok=True)
    from .helmchart import unchart_app
    unchart_app(src)                    # deployed with the shared Helm chart before 0.43.0: plain manifests first
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git"))
    repoint(dst, url, branch, path, old=moved_from)
    doc = _doc(dst) or {}
    doc.pop("moved_to", None)
    doc["moved_from"] = moved_from
    (dst / "containerizer.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
    (dst / "MOVED.md").write_text(
        f"# {doc.get('app') or path}\n\nGenerated by Containerizer and moved here from `{moved_from.get('repo')}` "
        f"(`{moved_from.get('path')}`). It is yours now: Containerizer does not write here again. The appliance's "
        "sandbox deploys it from this folder (Flux, `gitops/flux/`), so what you change here runs there too.\n")
    return True


def make_stub(folder: Path, m: dict) -> None:
    """The application's folder in the scan's output repository, after the move: what the sandbox needs to deploy it
    from its own repository (containerizer.json with `moved_to`, the Flux tenant and sync, the components' idp.json
    and k8s.yaml) and a README; nothing else."""
    doc = _doc(folder) or {}
    old = {"repo": m.get("from_repo") or "", "branch": m.get("from_branch") or "", "path": m.get("from_path") or ""}
    keep = ["containerizer.json", "gitops/flux/tenant.yaml", "gitops/flux/git/sync.yaml", "gitops/flux/kustomization.yaml"]
    for c in doc.get("components") or []:
        if c.get("folder"):
            keep += [f"{c['folder']}/idp.json", f"{c['folder']}/k8s.yaml"]
            from .manifests import KUSTOMIZATION, is_split, split_files
            if is_split(folder / c["folder"]):        # a file per kind (manifests.write_split)
                keep += [f"{c['folder']}/{f}" for f in [KUSTOMIZATION, *split_files(folder / c["folder"])]]
    tmp = folder.parent / (folder.name + ".stub")
    if tmp.exists():
        shutil.rmtree(tmp)
    for rel in keep:
        if (folder / rel).is_file():
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(folder / rel, tmp / rel)
    shutil.rmtree(folder)
    tmp.rename(folder)
    repoint(folder, m["repo"], m["branch"], m["path"], old=old if old["repo"] else None)
    doc["moved_to"] = {k: m[k] for k in ("repo", "branch", "path", "commit", "at") if k in m}
    (folder / "containerizer.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
    (folder / "README.md").write_text(
        f"# {doc.get('app') or folder.name}: moved\n\nIts files are in `{m['repo']}`, folder `{m['path']}`, branch "
        f"`{m['branch']}` (commit {str(m.get('commit') or '')[:12]}). Containerizer assesses the application but no "
        "longer writes its files. This folder only keeps what the sandbox needs to deploy it from there: the Flux "
        "tenant and sync (`gitops/flux/`), and the components' `idp.json` and `k8s.yaml` for the sandbox's identity "
        "provider and health checks.\n")


# --------------------------------------------------------------------------- the sandbox's read token

def sandbox_credential(creds, url: str):
    """The token the sandbox reads the application's repository with: a read token of the organization it is in,
    else its write token."""
    from .credentials import in_org
    for c in getattr(creds, "items", []) or []:
        if c.purpose == "read" and c.enabled and c.token:
            try:
                if in_org(url, c.provider, c.scope, c.api_url):
                    return c
            except Exception:  # noqa: BLE001
                continue
    return creds.write_for(url) if creds is not None else None


def write_tokens(apps: list[dict], creds, env=None) -> int:
    """`<dir>/<namespace>` for every moved application (url, user name, token; 0600) and no other file. Nothing
    when the folder's parent does not exist (not the appliance). Returns the files written."""
    from .orgsource import strip_userinfo
    env = os.environ if env is None else env
    d = Path(env.get(TOKENS_ENV) or TOKENS_DIR)
    if not d.parent.is_dir():
        return 0
    d.mkdir(mode=0o700, exist_ok=True)
    want = {}
    for a in apps:
        ns = str(a.get("OutputNamespace") or "")
        if not a.get("OutputMovedAt") or not NS_RE.fullmatch(ns):
            continue
        url = strip_userinfo(str(a["OutputRepo"]))
        c = sandbox_credential(creds, url) if creds is not None else None
        if c is not None and c.token:
            want[ns] = f"{url}\n{c.username or 'git'}\n{c.token}\n"
    n = 0
    for f in d.iterdir():
        if f.name not in want:
            f.unlink()
    for ns, text in want.items():
        f = d / ns
        if f.is_file() and f.read_text() == text:
            continue
        tmp = d / f".{ns}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, f)
        n += 1
    return n


# --------------------------------------------------------------------------- the queue runner's step

def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def _head(root: Path) -> str:
    p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


def _open(url: str, branch: str, write, work: Path):
    """The repository cloned with its write token (org.Output)."""
    from .org import OrgOptions, Output
    o = OrgOptions(provider="", org="", registry="", output_repo=url, output_branch=branch,
                   output_token=write.token or "", output_username=write.username or "x-access-token")
    return Output(o, work)


def _app_folders(root: Path) -> list[tuple[str, Path, dict]]:
    from .org import _apps_in
    return [x for x in _apps_in(root) if not x[2].get("variant")]


def _sig(apps: list[dict]) -> str:
    return json.dumps(sorted(f"{a['SourceKey']}|{a['OutputRepo']}|{a.get('OutputBranch') or ''}|{a.get('OutputPath') or ''}"
                             for a in apps if a.get("OutputMovedAt")))


def _set(connect, sql: str, params: tuple) -> None:
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def housekeep(connect, key, work: Path, log=print, opener=None, env=None) -> int:
    """Move the files of the applications given an output repository of their own (once), take the stubs of the
    ones whose setting was cleared out again, and keep the sandbox's read tokens for the moved ones up to date.
    Returns the commits made."""
    from .credentials import load, private_key_from_env
    from .org import host_allowed, load_sandbox_off, write_sandbox
    from .orgsource import REDACT, strip_userinfo
    from .worker import allowed_hosts
    opener = opener or _open
    conn = connect()
    try:
        try:
            apps = _rows(conn, "SELECT ApplicationId, Name, SourceKey, OutputRepo, OutputBranch, OutputPath, OutputMovedAt, "
                               "OutputMovedCommit, OutputNamespace, OutputMoveError FROM cz.Application "
                               "WHERE OutputRepo IS NOT NULL")
        except Exception:  # noqa: BLE001 - before schema 36
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            return 0
        work.mkdir(parents=True, exist_ok=True)
        sf = work / STATE
        try:
            state = json.loads(sf.read_text()) if sf.is_file() else {}
        except ValueError:
            state = {}
        tried = state.get("tried") or {}
        now = time.time()
        pending = [a for a in apps if not a.get("OutputMovedAt")
                   and now - float(tried.get(str(a["ApplicationId"])) or 0) >= RETRY_SECONDS]
        unmove = _sig(apps) != state.get("sig", "[]")
        if not apps and not unmove:
            return 0
        scans = _rows(conn, "SELECT * FROM cz.OrgScan WHERE OutputRepo IS NOT NULL ORDER BY ScanId") \
            if pending or unmove else []
        off = load_sandbox_off(conn) if pending or unmove else set()
        creds = load(conn, key if key is not None else private_key_from_env())
    finally:
        conn.close()
    try:
        write_tokens(apps, creds, env)
    except OSError as ex:
        log(f"application output repositories: the sandbox's read tokens not written: {ex}")
    if not pending and not unmove:
        return 0
    hosts = allowed_hosts() | creds.hosts()
    n = 0
    outs = []                                          # (scan, Output) of every scan output repository
    dirs = []
    seen = set()
    for scan in scans:
        repo = scan["OutputRepo"]
        if repo in seen:
            continue
        seen.add(repo)
        write = creds.write_for(repo)
        if write is None or not write.token or not host_allowed(repo, hosts):
            log(f"application output repositories: {repo} not opened: no write token for it, or its host is not allowed")
            continue
        REDACT.add(write.token, write.username)
        dirs.append(work / f"scan-{len(seen)}")
        outs.append((scan, opener(repo, scan.get("OutputBranch") or "main", write, dirs[-1])))
    try:
        for a in pending:
            aid = int(a["ApplicationId"])
            tried[str(aid)] = now
            found = next(((scan, out, rel, d, doc) for scan, out in outs for rel, d, doc in _app_folders(out.root)
                          if doc.get("source_key") == a["SourceKey"] and not moved_to(d)), None)
            try:
                if found is None:
                    raise MoveError(WAITING)
                n += _move(connect, a, found, creds, hosts, work, opener, off, log)
                tried.pop(str(aid), None)
                a["OutputMovedAt"] = datetime.now(timezone.utc)      # its new stub stays (below)
            except Exception as ex:  # noqa: BLE001 - recorded, tried again in 10 minutes
                why = REDACT(str(ex) if isinstance(ex, MoveError) else f"{type(ex).__name__}: {ex}")[:800]
                log(f"application {a['Name']}: files not moved to {a['OutputRepo']}: {why}")
                _set(connect, "UPDATE cz.Application SET OutputMoveError = %s WHERE ApplicationId = %s AND OutputMovedAt "
                              "IS NULL AND (OutputMoveError IS NULL OR OutputMoveError <> %s)", (why, aid, why))
        if unmove:
            keep = {(a["SourceKey"], strip_userinfo(str(a["OutputRepo"])), clean_path(a.get("OutputPath")))
                    for a in apps if a.get("OutputMovedAt")}
            for scan, out in outs:
                gone = []
                for rel, d, doc in _app_folders(out.root):
                    m = moved_to(d)
                    if m and (doc.get("source_key"), m.get("repo"), m.get("path")) not in keep:
                        shutil.rmtree(d)
                        gone.append(rel)
                if gone:
                    write_sandbox(out.root, out.url, scan.get("OutputBranch") or "main", off)
                    if out.commit("containerizer: back in the scans' hands (its own output repository was cleared): "
                                  + ", ".join(gone)):
                        n += 1
                        log(f"application output repositories: {out.url}: stub removed: {', '.join(gone)}")
            state["sig"] = _sig(apps)
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)
    state["tried"] = tried
    sf.write_text(json.dumps(state))
    return n


def _move(connect, a: dict, found, creds, hosts, work: Path, opener, off, log) -> int:
    """One application's move (module doc, steps 1 to 3). Returns the commits made."""
    from .org import host_allowed, write_sandbox
    from .orgsource import REDACT, strip_userinfo
    scan, out, rel, folder, doc = found
    url = strip_userinfo(str(a["OutputRepo"]))
    branch = (a.get("OutputBranch") or "").strip() or "main"
    path = clean_path(a.get("OutputPath"))
    if path is None:
        raise MoveError(f"the folder {a.get('OutputPath')!r} is not a valid relative folder")
    write = creds.write_for(url)
    if write is None or not write.token:
        raise MoveError(f"no write token is registered for {url} (Admin → Source control)")
    if not host_allowed(url, hosts):
        raise MoveError(f"the host of {url} is not allowed on this machine (CONTAINERIZER_WORKER_HOSTS)")
    REDACT.add(write.token, write.username)
    from_branch = scan.get("OutputBranch") or "main"
    moved_from = {"repo": out.url, "branch": from_branch, "path": rel, "source_key": doc.get("source_key"),
                  "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    tw = work / f"app-{int(a['ApplicationId'])}"
    shutil.rmtree(tw, ignore_errors=True)
    n = 0
    try:
        tgt = opener(url, branch, write, tw)
        if copy_app(folder, tgt.root, path, url, branch, moved_from):
            if tgt.commit(f"containerizer: {doc.get('app') or a['Name']} moved here from {out.url} ({rel})\n\n"
                          "Generated by Containerizer; yours from now on: Containerizer does not write here again."):
                n += 1
        commit = _head(tgt.root)
    finally:
        shutil.rmtree(tw, ignore_errors=True)
    m = {"repo": url, "branch": branch, "path": path, "commit": commit,
         "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
         "from_repo": out.url, "from_branch": from_branch, "from_path": rel}
    make_stub(folder, m)
    write_sandbox(out.root, out.url, from_branch, off)
    if out.commit(f"containerizer: {rel} moved to {url} ({path} on {branch}); the sandbox deploys it from there"):
        n += 1
    ns = str(doc.get("app") or "")
    _set(connect, "UPDATE cz.Application SET OutputMovedAt = SYSUTCDATETIME(), OutputMovedCommit = %s, OutputNamespace = %s, "
                  "OutputMoveError = NULL WHERE ApplicationId = %s AND OutputRepo = %s",
         (commit[:64] or None, ns[:63] or None, int(a["ApplicationId"]), a["OutputRepo"]))
    log(REDACT(f"application {a['Name']}: files moved to {url} ({path} on {branch}, {commit[:12]})"))
    return n
