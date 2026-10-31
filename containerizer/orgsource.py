"""Repositories of one Azure DevOps, GitHub or GitLab organization, and authenticated git without
tokens on disk or on the command line.

Tokens are read from environment variables only. Git gets them as an `http.<url>.extraHeader`
through GIT_CONFIG_COUNT/KEY/VALUE environment variables, scoped to the provider's host, so they
are not written to `.git/config`, not shown in `ps`, and not sent to any other host (redirects,
submodules, LFS servers). Errors are redacted before they are printed.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

PROVIDERS = ("azure-devops", "github", "gitlab")
TOKEN_ENVS = {
    "azure-devops": ("AZURE_DEVOPS_TOKEN", "AZURE_DEVOPS_EXT_PAT", "SYSTEM_ACCESSTOKEN"),
    "github": ("GITHUB_TOKEN", "GH_TOKEN"),
    "gitlab": ("GITLAB_TOKEN", "CI_JOB_TOKEN"),
}
DEFAULT_API = {"azure-devops": "https://dev.azure.com", "github": "https://api.github.com", "gitlab": "https://gitlab.com"}
NO_PROJECT = "_"            # project folder for repositories that have no project level (GitHub, top-level GitLab)


class SourceError(RuntimeError):
    pass


@dataclass
class SourceRepo:
    provider: str
    org: str
    project: str                  # Azure DevOps project, GitLab subgroup path below the group, or NO_PROJECT
    name: str
    clone_url: str
    default_branch: str = ""
    web_url: str = ""
    last_activity: datetime | None = None   # from the API; the cloned HEAD commit date is checked as well
    archived: bool = False
    empty: bool = False
    fork: bool = False
    id: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.project}/{self.name}"


def parse_time(s) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        # Azure DevOps sometimes returns 7 fractional digits
        m = re.match(r"(.*?\.\d{6})\d*(.*)", str(s))
        if not m:
            return None
        d = datetime.fromisoformat((m.group(1) + m.group(2)).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def strip_userinfo(url: str) -> str:
    """https://org@dev.azure.com/... -> https://dev.azure.com/...; never keep credentials in a URL."""
    u = urllib.parse.urlsplit(url)
    if u.scheme in ("http", "https") and "@" in u.netloc:
        u = u._replace(netloc=u.netloc.rsplit("@", 1)[1])
    return urllib.parse.urlunsplit(u)


def host_prefix(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc.rsplit('@', 1)[-1]}/"


def read_token(provider: str, env: str | None = None) -> str:
    names = (env,) if env else TOKEN_ENVS.get(provider, ())
    for n in names:
        if n and os.environ.get(n):
            return os.environ[n].strip()
    return ""


class Redactor:
    """Removes tokens (plain and in the base64 forms used in headers) from text shown to people."""

    def __init__(self):
        self.secrets: set[str] = set()

    def add(self, token: str, *usernames: str) -> None:
        if not token:
            return
        self.secrets.add(token)
        for u in ("", *usernames):
            self.secrets.add(base64.b64encode(f"{u}:{token}".encode()).decode())

    def __call__(self, text: str) -> str:
        for s in sorted(self.secrets, key=len, reverse=True):
            if len(s) >= 4:
                text = text.replace(s, "***")
        return text


REDACT = Redactor()


# --------------------------------------------------------------------------- HTTP

def http_json(url: str, headers: dict, timeout: int = 60, retries: int = 4):
    """GET a JSON document. Retries on rate limits and server errors. Returns (data, response headers)."""
    delay = 2.0
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "containerizer", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                return (json.loads(body) if body else None), {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            retry_after = e.headers.get("Retry-After") if e.headers else None
            limited = e.code == 429 or (e.code == 403 and e.headers and e.headers.get("X-RateLimit-Remaining") == "0")
            if attempt < retries and (limited or e.code >= 500):
                time.sleep(min(float(retry_after), 300) if retry_after and retry_after.isdigit() else delay)
                delay *= 2
                continue
            detail = REDACT(e.read()[:300].decode(errors="replace")) if e.fp else ""
            raise SourceError(f"GET {url}: HTTP {e.code} {e.reason} {detail}".strip()) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise SourceError(f"GET {url}: {REDACT(str(e))}") from None


def _next_link(headers: dict) -> str | None:
    for part in (headers.get("link") or "").split(","):
        m = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------- providers

class Provider:
    name = ""
    git_username = "x-access-token"

    def __init__(self, org: str, token: str = "", api_url: str | None = None):
        self.org = org.strip("/")
        self.token = token
        self.api = (api_url or DEFAULT_API[self.name]).rstrip("/")
        REDACT.add(token, self.git_username)

    def headers(self) -> dict:
        return {}

    def get(self, url: str):
        return http_json(url, self.headers())

    def repos(self):
        raise NotImplementedError

    def last_commit(self, r: SourceRepo) -> datetime | None:
        return None

    def git_header(self) -> str:
        if not self.token:
            return ""
        return "Authorization: Basic " + base64.b64encode(f"{self.git_username}:{self.token}".encode()).decode()


class GitHub(Provider):
    """Organization repositories (`/orgs/{org}/repos`, all types incl. private and internal with a
    token that can read them); a user account falls back to `/users/{name}/repos` (public only)
    or `/user/repos` when the token belongs to that user. GitHub has no project level."""
    name = "github"

    def headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def repos(self):
        q = urllib.parse.quote(self.org)
        url = f"{self.api}/orgs/{q}/repos?per_page=100&type=all&sort=full_name"
        try:
            data, h = self.get(url)
        except SourceError as e:
            if "HTTP 404" not in str(e):
                raise
            me = None
            if self.token:
                try:
                    me = (self.get(f"{self.api}/user")[0] or {}).get("login")
                except SourceError:
                    me = None
            url = (f"{self.api}/user/repos?per_page=100&affiliation=owner&sort=full_name"
                   if me and me.lower() == self.org.lower() else f"{self.api}/users/{q}/repos?per_page=100&type=owner")
            data, h = self.get(url)
        while True:
            for d in data or []:
                yield SourceRepo(
                    provider=self.name, org=self.org, project=NO_PROJECT, name=d["name"],
                    clone_url=d["clone_url"], default_branch=d.get("default_branch") or "",
                    web_url=d.get("html_url") or "", last_activity=parse_time(d.get("pushed_at")),
                    archived=bool(d.get("archived") or d.get("disabled")), empty=d.get("size") == 0,
                    fork=bool(d.get("fork")), id=str(d.get("id", "")))
            nxt = _next_link(h)
            if not nxt:
                return
            data, h = self.get(nxt)


class GitLab(Provider):
    """Projects of a group and all its subgroups (`/groups/:id/projects?include_subgroups=true`).
    The project folder is the subgroup path below the group (`team/sub` -> `team--sub`)."""
    name = "gitlab"
    git_username = "oauth2"

    def headers(self) -> dict:
        return {"PRIVATE-TOKEN": self.token} if self.token else {}

    def repos(self):
        g = urllib.parse.quote(self.org, safe="")
        data, h = self.get(f"{self.api}/api/v4/groups/{g}/projects?include_subgroups=true&per_page=100"
                           f"&order_by=id&sort=asc&with_shared=false")
        while True:
            for d in data or []:
                ns = (d.get("namespace") or {}).get("full_path") or self.org
                rel = ns[len(self.org):].strip("/") if ns.lower().startswith(self.org.lower()) else ns
                yield SourceRepo(
                    provider=self.name, org=self.org, project=rel.replace("/", "--") if rel else NO_PROJECT,
                    name=d["path"], clone_url=d["http_url_to_repo"], default_branch=d.get("default_branch") or "",
                    web_url=d.get("web_url") or "", last_activity=parse_time(d.get("last_activity_at")),
                    archived=bool(d.get("archived")), empty=bool(d.get("empty_repo")),
                    fork=bool(d.get("forked_from_project")), id=str(d.get("id", "")))
            nxt = _next_link(h)          # GitLab sends rel="next" for offset and keyset pagination
            if not nxt:
                return
            data, h = self.get(nxt)

    def last_commit(self, r: SourceRepo) -> datetime | None:
        if not r.default_branch:
            return None
        data, _ = self.get(f"{self.api}/api/v4/projects/{r.id}/repository/commits?per_page=1"
                           f"&ref_name={urllib.parse.quote(r.default_branch, safe='')}")
        return parse_time((data or [{}])[0].get("committed_date")) if data else None


class AzureDevOps(Provider):
    """All projects of an organization (or an Azure DevOps Server collection: --api-url
    https://server/tfs and the collection as the organization) and their Git repositories."""
    name = "azure-devops"
    git_username = "pat"
    API = "api-version=7.1"

    def headers(self) -> dict:
        if not self.token:
            return {}
        return {"Authorization": "Basic " + base64.b64encode(f":{self.token}".encode()).decode()}

    @property
    def base(self) -> str:
        return f"{self.api}/{urllib.parse.quote(self.org)}"

    def projects(self) -> list[str]:
        out, token = [], ""
        while True:
            url = f"{self.base}/_apis/projects?{self.API}&stateFilter=wellFormed&$top=100"
            if token:
                url += "&continuationToken=" + urllib.parse.quote(token)
            data, h = self.get(url)
            out += [p["name"] for p in (data or {}).get("value", [])]
            token = h.get("x-ms-continuationtoken") or ""
            if not token:
                return sorted(out, key=str.lower)

    def repos(self):
        for proj in self.projects():
            data, _ = self.get(f"{self.base}/{urllib.parse.quote(proj)}/_apis/git/repositories?{self.API}")
            for d in sorted((data or {}).get("value", []), key=lambda d: d["name"].lower()):
                yield SourceRepo(
                    provider=self.name, org=self.org, project=proj, name=d["name"],
                    clone_url=strip_userinfo(d.get("remoteUrl") or ""),
                    default_branch=(d.get("defaultBranch") or "").removeprefix("refs/heads/"),
                    web_url=d.get("webUrl") or "", archived=bool(d.get("isDisabled")),
                    empty=not d.get("defaultBranch") or d.get("size") == 0,
                    fork=bool(d.get("isFork")), id=d.get("id", ""), extra={"project_q": urllib.parse.quote(proj)})

    def last_commit(self, r: SourceRepo) -> datetime | None:
        url = (f"{self.base}/{r.extra.get('project_q', urllib.parse.quote(r.project))}/_apis/git/repositories/{r.id}"
               f"/commits?searchCriteria.$top=1&{self.API}")
        if r.default_branch:
            url += "&searchCriteria.itemVersion.version=" + urllib.parse.quote(r.default_branch, safe="")
        data, _ = self.get(url)
        v = (data or {}).get("value") or []
        return parse_time((v[0].get("committer") or {}).get("date")) if v else None


def provider(name: str, org: str, token: str = "", api_url: str | None = None) -> Provider:
    cls = {"github": GitHub, "gitlab": GitLab, "azure-devops": AzureDevOps}.get(name)
    if not cls:
        raise SourceError(f"unknown provider {name}; use one of {', '.join(PROVIDERS)}")
    return cls(org, token, api_url)


# --------------------------------------------------------------------------- git

def git_env(url: str | None = None, header: str = "") -> dict:
    """Environment for git: no prompts, no LFS downloads, the auth header scoped to the URL's host."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"}
    if header and url and url.startswith(("https://", "http://")):
        n = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
        env["GIT_CONFIG_COUNT"] = str(n + 1)
        env[f"GIT_CONFIG_KEY_{n}"] = f"http.{host_prefix(url)}.extraHeader"
        env[f"GIT_CONFIG_VALUE_{n}"] = header
    return env


# hardening for cloning code we do not trust: no symlinks out of the tree, no local-path or
# ext:: transports, no submodules
SAFE_CLONE = ["-c", "core.symlinks=false", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
              "-c", "submodule.recurse=false", "-c", "core.hooksPath=/dev/null"]


def git(args: list[str], cwd: Path | None = None, url: str | None = None, header: str = "",
        timeout: int = 1800, check: bool = True) -> str:
    try:
        p = subprocess.run(["git", *args], cwd=cwd, env=git_env(url, header), capture_output=True, text=True,
                           timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        raise SourceError(f"git {args[0]}: timed out after {timeout}s") from None
    if check and p.returncode != 0:
        raise SourceError(f"git {' '.join(a for a in args if not a.startswith('http'))}: "
                          f"{REDACT((p.stderr or p.stdout).strip())[-600:]}")
    return p.stdout


def clone(url: str, dest: Path, branch: str = "", header: str = "", depth: int | None = 1) -> None:
    args = [*SAFE_CLONE, "clone", "--quiet", "--no-tags", "--single-branch"]
    if depth:
        args += ["--depth", str(depth)]
    if branch:
        args += ["--branch", branch]
    git(args + ["--", url, str(dest)], url=url, header=header)


def update_clone(url: str, dest: Path, branch: str = "", header: str = "") -> str:
    """Keep a shallow clone of the default branch in `dest` up to date: the first time clone it, later
    fetch the newest commit and check it out, dropping any local change or untracked file. Returns
    "cloned" or "pulled". A failed fetch (network, credentials) keeps the clone as it was; a clone that
    cannot be checked out any more (corrupt, interrupted) is cloned again."""
    healthy = (dest / ".git").is_dir() and \
        git(["rev-parse", "--is-inside-work-tree"], cwd=dest, check=False).strip() == "true"
    if healthy:
        git([*SAFE_CLONE, "remote", "set-url", "origin", url], cwd=dest)
        git([*SAFE_CLONE, "fetch", "--quiet", "--no-tags", "--prune", "--depth", "1", "origin", branch or "HEAD"],
            cwd=dest, url=url, header=header)
        try:
            if branch:
                git([*SAFE_CLONE, "checkout", "--quiet", "--force", "-B", branch, "FETCH_HEAD"], cwd=dest)
            else:
                git([*SAFE_CLONE, "reset", "--quiet", "--hard", "FETCH_HEAD"], cwd=dest)
            git([*SAFE_CLONE, "clean", "-ffdxq"], cwd=dest)
            # shallow fetches leave the previous commits behind: let git prune them when it is worth it
            git([*SAFE_CLONE, "-c", "gc.reflogExpire=now", "-c", "gc.reflogExpireUnreachable=now", "-c",
                 "gc.autoDetach=false", "gc", "--auto", "--prune=now", "--quiet"], cwd=dest, check=False)
            return "pulled"
        except SourceError:
            pass
    import shutil
    fresh = dest.with_name(dest.name + ".cloning")
    if fresh.exists():
        shutil.rmtree(fresh)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        clone(url, fresh, branch, header)
    except SourceError:
        shutil.rmtree(fresh, ignore_errors=True)
        raise                                    # the old clone, if any, stays until a clone succeeds
    if dest.exists():
        shutil.rmtree(dest)
    fresh.rename(dest)
    return "cloned"


# source files of application code, by language (scripts, SQL and markup do not count)
LANGUAGES = {".cs": "C#", ".cshtml": "C#", ".razor": "C#", ".aspx": "ASP.NET", ".ascx": "ASP.NET", ".asmx": "ASP.NET",
             ".svc": "WCF", ".ashx": "ASP.NET", ".asax": "ASP.NET", ".master": "ASP.NET", ".vb": "Visual Basic",
             ".vbhtml": "Visual Basic", ".fs": "F#", ".xaml": "XAML", ".js": "JavaScript", ".mjs": "JavaScript",
             ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python",
             ".java": "Java", ".kt": "Kotlin", ".scala": "Scala", ".groovy": "Groovy", ".go": "Go", ".php": "PHP",
             ".rb": "Ruby", ".erb": "Ruby", ".rs": "Rust", ".c": "C", ".cpp": "C++", ".cc": "C++", ".swift": "Swift",
             ".m": "Objective-C", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".clj": "Clojure", ".jl": "Julia",
             ".pl": "Perl", ".lua": "Lua", ".r": "R", ".cob": "COBOL", ".cbl": "COBOL", ".pas": "Pascal", ".dpr": "Delphi"}


def code_summary(root: Path, limit: int = 20000) -> dict:
    """What a repository holds, for the "no application code" decision: file count, source files per
    language, and the most common file types (outside .git and node_modules)."""
    total, langs, ext = 0, {}, {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            total += 1
            x = os.path.splitext(f)[1].lower() or "(no extension)"
            ext[x] = ext.get(x, 0) + 1
            if x in LANGUAGES:
                langs[LANGUAGES[x]] = langs.get(LANGUAGES[x], 0) + 1
            if total >= limit:
                break
        if total >= limit:
            break
    return {"files": total, "languages": sorted(langs.items(), key=lambda kv: (-kv[1], kv[0])),
            "top": sorted(ext.items(), key=lambda kv: (-kv[1], kv[0]))[:4]}


def head_commit(path: Path) -> tuple[str, datetime | None]:
    out = git(["log", "-1", "--format=%H %cI"], cwd=path, check=False).strip()
    if not out:
        return "", None
    sha, _, when = out.partition(" ")
    return sha, parse_time(when)


DOCKERFILE_RE = re.compile(r"^(dockerfile|containerfile)(\..+)?$|.+\.(dockerfile|containerfile)$", re.I)
SKIP_DIRS = {".git", "node_modules"}


def existing_dockerfiles(root: Path, limit: int = 10) -> list[str]:
    """Dockerfiles already in the repository (Dockerfile, Dockerfile.prod, api.Dockerfile, Containerfile);
    third-party folders such as node_modules are not counted."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if DOCKERFILE_RE.match(f) and not f.lower().endswith(".dockerignore"):
                found.append(Path(dirpath, f).relative_to(root).as_posix())
                if len(found) >= limit:
                    return sorted(found)
    return sorted(found)
