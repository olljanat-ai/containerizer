"""Refactoring patches for B-rated applications (docs/refactoring.md).

An application rated B needs targeted code changes: findings of severity `refactor` (and `config` ones that
are best fixed in code), each with a plain-text `fix:` in its rule. An operator or administrator orders a
refactoring of the application or of one component (Admin → Refactoring, the Refactoring box on the
results page, or `containerizer refactor`); the order is a job of kind `refactor` in the LLM queue
(llmqueue.py), and the queue runner turns it into a git patch:

1. **Source.** A scratch copy of the application's repository at the assessed commit (`git clone --shared`
   of the scan worker's clone, or of the local checkout; never written to). A commit that is gone fails
   the order with a message.
2. **Generate.** One LLM call per affected file (all the findings in that file), never the whole app: the
   rule's fix and why, the evidence lines, the file (or a window around the evidence when it is large),
   the component's target framework and packages, and strict instructions. The LLM answers with
   structured edits, not a diff: `{"edits": [{"file", "search", "replace"}], "new_files": [...],
   "package_changes": [...], "fixed": [...], "not_fixed": [...], "notes"}`. The edits are applied
   deterministically: a search text must occur exactly once in the file; an answer that does not apply
   is asked again once with the errors; one that still does not apply changes nothing.
3. **Patch.** The changes are committed in the scratch copy ("Containerizer: <app>: <findings fixed>",
   author Containerizer <containerizer@localhost>) and written with `git format-patch -1 --stdout`, so
   `git am` applies it.
4. **Verify.** A second, clean scratch copy at the same commit: `git apply --check`, then `git am`; the
   rules run again on the patched copy (which findings the patch resolved, which remain, any new ones);
   then each changed component is built and run with the verify step (verify.py). The patch is
   *verified* (applies, builds and runs), *applies only* (applies, but the build or the run failed or
   could not be done: the log tail says why) or *failed* (does not apply, or no usable edits). A patch
   that does not apply cleanly is never offered.

Delivery is download only: no pull requests; the source credentials stay read-only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

KIND = "refactor"
FEATURE = "refactor-queued"             # LLM usage feature of the refactoring calls
PRIORITY = 1800                         # a person ordered it: before the automatic reviews (people may move it)
ELIGIBLE = ("refactor", "config")       # severities a refactoring changes code for
MAX_CALLS = 8                           # LLM calls (files) per order; the rest are listed as not attempted
MAX_PROMPT_CHARS = 36000                # with the system prompt and the schema: under ~12K tokens (22K a CPU slot)
DEFAULT_FILE_CHARS = 9000               # estimate of a file not readable when the order is made
EXTRA_FILE_CHARS = 6000                 # the component's appsettings.json is shown when it is at most this long
MAX_NEW_FILE = 100_000
# Output cap of an edit answer (OpenAI-compatible backend; CONTAINERIZER_LLM_MAX_TOKENS still caps it): edits
# repeat only the lines they change, so a few thousand tokens; a runaway answer must not hold a CPU slot for an hour
ANSWER_TOKENS_MIN, ANSWER_TOKENS_MAX = 4096, 8192
STATUSES = ("queued", "generating", "verifying", "verified", "applies-only", "failed", "cancelled")
STATUS_TEXT = {"approval": "Waiting for approval", "queued": "Queued", "generating": "Generating", "verifying": "Verifying", "verified": "Verified",
               "applies-only": "Applies only", "failed": "Failed", "cancelled": "Cancelled"}
AUTHOR = ("Containerizer", "containerizer@localhost")
SOURCES_ENV = "CONTAINERIZER_REFACTOR_SOURCES"   # the scan worker's data folder (its clone cache)
WORK_ENV = "CONTAINERIZER_REFACTOR_WORK"         # where the runner makes its scratch copies
DEFAULT_SOURCES = "/var/lib/containerizer/worker"
# Lab only: the runner may clone a public https repository itself (orders made in development mode, for apps no
# organization scan here holds). Never set on the appliance: a job in the database must not make it fetch URLs.
CLONE_ENV = "CONTAINERIZER_REFACTOR_CLONE"
CLONE_DIR_RE = re.compile(r"scan-\d{1,9}/repos/[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
EVIDENCE_RE = re.compile(r"^(?P<file>[^\n]+?)(?::(?P<line>\d+))?(?:: (?P<text>.*))?$", re.S)
# a fix that only says to keep the component on Windows: nothing to change in code ("..., or keep it on
# Windows" offers the alternative, which is what the LLM is asked to do)
KEEP_ON_WINDOWS = re.compile(r"(?<!or )(?<!otherwise )(?<!otherwise, )\b(keep|leave|stays?)\b[^.;]{0,60}\bwindows\b", re.I)


class RefactorError(RuntimeError):
    """The order cannot be carried out (source gone, nothing to fix): a failed attempt of the job."""


# --------------------------------------------------------------------------- what to fix

def parse_evidence(s: str) -> dict:
    """"src/A.cs:52: using var store = ..." -> {"file", "line", "text"} (line 0 when there is none)."""
    m = EVIDENCE_RE.match(str(s).strip())
    if not m:
        return {"file": str(s), "line": 0, "text": ""}
    return {"file": m["file"].strip(), "line": int(m["line"] or 0), "text": (m["text"] or "").strip()}


def keeps_windows(fix: str) -> bool:
    return bool(KEEP_ON_WINDOWS.search(" ".join(str(fix or "").split())))


def skip_reason(f: dict) -> str | None:
    """Why a finding is not sent to the LLM (None: it is)."""
    sev = f.get("severity")
    if f.get("dormant"):
        return "dormant: library code the component never reaches"
    if sev in ("blocker", "rewrite"):
        return f"severity {sev}: a port or a component that stays on Windows, not a targeted change"
    if sev not in ELIGIBLE:
        return f"severity {sev}: nothing to change"
    if keeps_windows(f.get("fix", "")):
        return "the fix is to keep this part on Windows"
    if not f.get("fix"):
        return "the rule says nothing about how to fix it"
    return None


def _language(project: str) -> str:
    p = project.lower()
    if p.endswith(".csproj"):
        return "C#"
    if p.endswith(".vbproj"):
        return "VB.NET"
    if p.endswith(".fsproj"):
        return "F#"
    if p.endswith(("pom.xml", ".gradle", ".gradle.kts")):
        return "Java"
    if p.endswith("package.json"):
        return "JavaScript/TypeScript"
    return "code"


def plan_tasks(components: list[dict], include_config: bool = False) -> tuple[list[dict], list[dict]]:
    """The LLM calls of an order, from assessment.json components (AppAssessment.to_dict()["components"]):
    one task per file, with every finding to fix in it. Refactor findings always; config findings when
    `include_config`, or when they are in a file a refactor finding already sends. Findings whose evidence
    names no file in the application are skipped. Returns (tasks, skipped)."""
    tasks: dict[str, dict] = {}
    skipped: list[dict] = []
    candidates: list[tuple[dict, dict, list[dict]]] = []
    for c in components:
        for f in c.get("findings") or []:
            why = skip_reason(f)
            ident = {"rule": f.get("id"), "title": f.get("title"), "component": c.get("name"), "severity": f.get("severity")}
            if why:
                if f.get("severity") in ("refactor", "config", "rewrite", "blocker"):
                    skipped.append({**ident, "reason": why})
                continue
            ev = [parse_evidence(e) for e in f.get("evidence") or []]
            ev = [e for e in ev if e["file"] and not e["file"].startswith("/") and ".." not in Path(e["file"]).parts]
            seen, uniq = set(), []
            for e in ev:
                if (e["file"], e["line"], e["text"]) not in seen:
                    seen.add((e["file"], e["line"], e["text"]))
                    uniq.append(e)
            if not uniq:
                skipped.append({**ident, "reason": "the evidence names no file to change"})
                continue
            candidates.append((c, f, uniq))
    refactor_files = {e["file"] for c, f, ev in candidates if f.get("severity") == "refactor" for e in ev}
    for c, f, ev in candidates:
        files = sorted({e["file"] for e in ev}, key=lambda x: [e["file"] for e in ev].index(x))
        if f.get("severity") != "refactor" and not include_config:
            files = [x for x in files if x in refactor_files]
            if not files:
                skipped.append({"rule": f.get("id"), "title": f.get("title"), "component": c.get("name"),
                                "severity": f.get("severity"), "reason": "configuration finding: not included "
                                "(order with configuration findings to have code changed for it)"})
                continue
        for file in files:
            t = tasks.setdefault(file, {"file": file, "component": c.get("name"), "project": c.get("project"),
                                        "findings": []})
            if any(x["rule"] == f.get("id") for x in t["findings"]):
                continue
            t["findings"].append({"rule": f.get("id"), "severity": f.get("severity"), "title": f.get("title"),
                                  "why": " ".join(str(f.get("why") or "").split()),
                                  "fix": " ".join(str(f.get("fix") or "").split()),
                                  "component": c.get("name"),
                                  "evidence": [e for e in ev if e["file"] == file][:6]})
    # refactor findings first, then the files with the most findings
    ordered = sorted(tasks.values(), key=lambda t: (not any(x["severity"] == "refactor" for x in t["findings"]),
                                                    -len(t["findings"]), t["file"]))
    return ordered, skipped


def eligible_components(doc: dict) -> list[dict]:
    """Components of an assessment.json entry a refactoring can change: verdict refactor or config, with at
    least one finding that would be sent (refactor, or config ones with a file)."""
    out = []
    for c in doc.get("components") or []:
        if c.get("verdict") not in ELIGIBLE:
            continue
        tasks, _ = plan_tasks([c], include_config=True)
        if tasks:
            out.append(c)
    return out


GOALS = ("fix", "stateless", "repair")

# A compiler error in a build log: /src/<path>(line,col): error CODE: message [project]
BUILD_ERROR_RE = re.compile(r"(?:^|\s)/src/(?P<file>[^\s(:]+\.(?:cs|vb|fs|cshtml|razor|csproj|vbproj|fsproj))"
                            r"\((?P<line>\d+)(?:,\d+)?\): error (?P<code>[A-Z]+\d+): (?P<msg>[^\[\n]+)")
REPAIR_GUIDANCE = """An earlier change (the patch below) was made to fix the findings, but the result does not build
(or does not run). Fix the errors listed for this file so that the code builds and runs, and keep the intent of
the earlier change. Often another file of the patch changed something this file uses (a constructor, a method, a
setting): adapt this file to it, do not undo the earlier change."""


def build_errors(log: str) -> list[dict]:
    """The compiler errors of a build log, one per file and line (the build context's /src is the app's root)."""
    seen, out = set(), []
    for m in BUILD_ERROR_RE.finditer(log or ""):
        rel = safe_rel(m["file"])
        key = (rel, m["line"], m["code"])
        if rel and key not in seen:
            seen.add(key)
            out.append({"file": rel, "line": int(m["line"]), "code": m["code"], "text": " ".join(m["msg"].split())[:300]})
    return out[:40]


def repair_payload(payload: dict, result: dict, base_job: int) -> dict:
    """An order that repairs the patch of an earlier one whose build or run failed: the same source and
    commit, the earlier patch applied first, and the errors of its verification."""
    if not result.get("patch"):
        raise RefactorError("the earlier order has no patch to repair")
    logs = "\n".join(str(v.get("log_tail") or v.get("detail") or "") for v in result.get("verification") or [])
    errors = build_errors(logs)
    keep = ("version", "app", "rating", "application_id", "assessment_id", "source_key", "commit", "source",
            "component", "components", "verify")
    return {**{k: payload.get(k) for k in keep}, "goal": "repair", "base_job": int(base_job),
            "base_patch": result["patch"], "base_status": result.get("status"),
            "base_subject": next((l[len("Subject: [PATCH] "):] for l in result["patch"].splitlines()
                                  if l.startswith("Subject: [PATCH] ")), ""),
            "errors": errors, "log_tail": logs[-4000:], "tasks": [], "skipped": [], "include_config": False,
            "max_calls": max(4, len({e["file"] for e in errors}) or 4)}


def repair_tasks(payload: dict, app_root: Path, changed: list[str]) -> list[dict]:
    """One task per file with compiler errors; without any (it built, but did not run), the patch's files."""
    comp = (payload.get("components") or [{}])[0]
    by_file: dict[str, list[dict]] = {}
    for err in payload.get("errors") or []:
        if (app_root / err["file"]).is_file():
            by_file.setdefault(err["file"], []).append(err)
    if not by_file:
        tail = " ".join(str(payload.get("log_tail") or "").split())[-600:]
        by_file = {f: [{"file": f, "line": 0, "code": "run", "text": "the patched component does not run: " + tail}]
                   for f in changed if (app_root / f).is_file()}
    return [{"file": f, "component": comp.get("name"), "project": comp.get("project"), "findings": [{
        "rule": "build-error", "severity": "refactor",
        "title": "; ".join(f"{x['code']}: {x['text']}" for x in errs)[:300],
        "why": "The patched code does not build (or run).", "fix": "Fix these errors; keep the earlier change.",
        "component": comp.get("name"),
        "evidence": [{"file": f, "line": x["line"] or None, "text": f"{x['code']}: {x['text']}"} for x in errs[:6]]}]}
        for f, errs in by_file.items()]



def stateful_components(doc: dict) -> list[dict]:
    """Server components that keep their own data (assessment.json `stateless: false`): what keeps an otherwise
    ready application from rating A."""
    return [c for c in doc.get("components") or [] if c.get("stateless") is False
            and c.get("tier") in ("server", "platform", None) and c.get("verdict") in ("info", "config", "refactor")]


def build_payload(doc: dict, source: dict, commit: str | None, component: str | None = None,
                  include_config: bool = False, application_id: int | None = None, assessment_id: int | None = None,
                  source_key: str | None = None, verify: bool = True, max_calls: int = MAX_CALLS,
                  goal: str = "fix") -> dict:
    """The job's payload from an assessment.json entry: what the runner needs and nothing it must look up.
    `component` is a component name or project path (None: every component that needs changes).
    `goal`: 'fix' (the refactor findings) or 'stateless' (move the components' own data out, to SQL Server: the
    state findings and configuration ones; the runner also adds the files that use the embedded database)."""
    if goal not in GOALS:
        raise RefactorError(f"unknown goal {goal!r}")
    comps = [c for c in doc.get("components") or [] if c.get("verdict") in ELIGIBLE]
    if goal == "stateless":
        include_config = True
        comps = stateful_components(doc)
        if not comps:
            raise RefactorError("nothing to change: no component keeps its own data")
    if component:
        comps = [c for c in comps if component in (c.get("name"), c.get("project"))]
        if not comps:
            raise RefactorError(f"no component {component!r} in {doc.get('name')}"
                                + (" that keeps its own data" if goal == "stateless" else ""))
    tasks, skipped = plan_tasks(comps, include_config)
    if not tasks and goal != "stateless":
        raise RefactorError("nothing to change: no refactor finding (or configuration finding with a file) "
                            "to send to the LLM" + (" in " + component if component else ""))
    return {"version": 1, "app": doc.get("name"), "rating": doc.get("rating"), "application_id": application_id,
            "assessment_id": assessment_id, "source_key": source_key, "commit": commit, "source": source,
            "component": component,
            "components": [{"name": c.get("name"), "project": c.get("project"), "role": c.get("role"),
                            "verdict": c.get("verdict"), "tfm": list(c.get("tfm") or []),
                            "language": _language(str(c.get("project") or "")),
                            "rules": sorted({f.get("id") for f in c.get("findings") or [] if not f.get("dormant")})}
                           for c in comps],
            "tasks": tasks, "skipped": skipped, "include_config": bool(include_config), "verify": bool(verify),
            "max_calls": int(max_calls), "goal": goal,
            "state": [{"component": c.get("name"), "state": [s.get("title") for s in c.get("state") or []]}
                      for c in comps if c.get("stateless") is False]}


def dedupe_key(payload: dict) -> str:
    """One waiting order per application, commit, components and findings."""
    basis = json.dumps([payload.get("source_key") or payload.get("app"), payload.get("commit"),
                        sorted(c["project"] or "" for c in payload["components"]), payload.get("include_config"),
                        payload.get("goal", "fix"),
                        [(t["file"], [f["rule"] for f in t["findings"]]) for t in payload["tasks"]]], sort_keys=True)
    return hashlib.sha256(basis.encode()).hexdigest()


def slug(s: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(s or "")).strip("-.")[:80] or "app"


def patch_filename(app: str | None, component: str | None) -> str:
    return f"{slug(app)}-{slug(component or 'all')}-containerizer.patch"


# --------------------------------------------------------------------------- the prompt

SYSTEM = """You are a senior software engineer who makes the smallest safe code change that lets an application
run in a Linux container on Kubernetes. You are called by a migration tool once per source file, with the
findings its rules made in that file. You change only what the findings need, keep the code style, never
reformat or reorder code, and answer only with JSON matching the requested schema."""

EDIT_SCHEMA = {
    "type": "object",
    "properties": {
        "edits": {"type": "array", "items": {"type": "object", "properties": {
            "file": {"type": "string"}, "search": {"type": "string"}, "replace": {"type": "string"}},
            "required": ["file", "search", "replace"]}},
        "new_files": {"type": "array", "items": {"type": "object", "properties": {
            "file": {"type": "string"}, "content": {"type": "string"}}, "required": ["file", "content"]}},
        "package_changes": {"type": "array", "items": {"type": "object", "properties": {
            "action": {"type": "string", "enum": ["add", "remove"]}, "package": {"type": "string"},
            "version": {"type": "string"}}, "required": ["action", "package", "version"]}},
        "fixed": {"type": "array", "items": {"type": "string"}},
        "not_fixed": {"type": "array", "items": {"type": "object", "properties": {
            "rule": {"type": "string"}, "reason": {"type": "string"}}, "required": ["rule", "reason"]}},
        "notes": {"type": "string"},
    },
    "required": ["edits", "new_files", "package_changes", "fixed", "not_fixed", "notes"],
}

INSTRUCTIONS = """Rules for your answer:
- Fix each finding the way its "Fix" says. Make the smallest change that does it; change nothing else.
- "edits": each "search" is text copied EXACTLY from a file shown below (same spaces, indentation and
  punctuation), whole lines, long enough to occur exactly once in that file (usually 1 to 6 lines);
  "replace" is the new text for those lines. Do not repeat the whole file. Only edit the files shown.
- Prefer settings over hard-coded values: read paths, certificates and credentials from configuration
  (appsettings.json / environment variables) with Linux defaults (for example /data/...), and keep the
  setting names the code already uses.
- "new_files": only when a new file is really needed (path relative to the application folder, next to the
  project); otherwise an empty list.
- "package_changes": NuGet/Maven/npm packages to add or remove for the component's project, with a version
  that supports its target framework; do not edit the project file for it yourself. Usually empty.
- "fixed": the rule ids your edits fix. "not_fixed": the ones you did not fix, each with the reason (for
  example: nothing to change in code, it is a deployment setting; or it cannot be fixed safely here).
- "notes": one or two sentences for the reviewer (what to configure, what to test).
- Use only APIs that exist in the component's target framework and packages (for example no .NET 9 API in a
  net6.0 project, even when the Fix names one: then use the older equivalent).
- Never remove functionality, never disable security checks, never add secrets or passwords to code.
- If unsure, change less and explain in not_fixed."""


def _read_text(path: Path) -> tuple[str, dict]:
    """A source file as text with its line endings normalized to \\n, and how to write it back
    (encoding, BOM, CRLF)."""
    raw = path.read_bytes()
    bom = raw.startswith(b"\xef\xbb\xbf")
    try:
        text, enc = raw.decode("utf-8-sig" if bom else "utf-8"), "utf-8"
    except UnicodeDecodeError:
        text, enc = raw.decode("cp1252", errors="replace"), "cp1252"
    crlf = "\r\n" in text
    return text.replace("\r\n", "\n"), {"encoding": enc, "bom": bom, "crlf": crlf}


def _write_text(path: Path, text: str, how: dict) -> None:
    if how.get("crlf"):
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    data = text.encode(how.get("encoding") or "utf-8", errors="replace")
    path.write_bytes((b"\xef\xbb\xbf" if how.get("bom") else b"") + data)


def _packages(project_file: Path) -> list[str]:
    try:
        text = project_file.read_text(errors="replace")
    except OSError:
        return []
    if project_file.suffix.lower().endswith("proj"):
        return [f"{m[1]} {m[2] or ''}".strip() for m in
                re.finditer(r"<PackageReference\s+Include=\"([^\"]+)\"(?:\s+Version=\"([^\"]*)\")?", text)][:40]
    if project_file.name == "package.json":
        try:
            d = json.loads(text)
            return [f"{k} {v}" for k, v in (d.get("dependencies") or {}).items()][:40]
        except ValueError:
            return []
    return []


def window(text: str, lines: list[int], budget: int) -> tuple[str, int, int]:
    """The file, or the part around the evidence lines that fits `budget` characters:
    (text, first line, last line), 1-based."""
    all_lines = text.split("\n")
    if len(text) <= budget or not all_lines:
        return text, 1, len(all_lines)
    hits = [n for n in lines if 0 < n <= len(all_lines)] or [1]
    for ctx in (80, 40, 20, 10, 5, 2, 1, 0):
        lo, hi = max(1, min(hits) - ctx), min(len(all_lines), max(hits) + ctx)
        part = "\n".join(all_lines[lo - 1:hi])
        if len(part) <= budget:
            return part, lo, hi
    return part[:budget], lo, hi                       # evidence lines far apart, or one huge line: cut


STATE_CODE_RE = re.compile(r"UseSqlite|SqliteConnection|Microsoft\.Data\.Sqlite|System\.Data\.SQLite|LiteDatabase|"
                           r"LiteDB|UseInMemoryDatabase|Data Source=[^;\"]*\.(db|sqlite3?|litedb)", re.I)
STATE_GUIDANCE = """The goal of this change: make the component stateless, so it can run as several replicas
that can be replaced at any time. Its data must live in an external database, not in a file inside the container.
- Move the embedded database (SQLite or LiteDB) to Microsoft SQL Server. With Entity Framework Core: replace the
  package Microsoft.EntityFrameworkCore.Sqlite with Microsoft.EntityFrameworkCore.SqlServer (the same version as
  the other EF Core packages; use package_changes), UseSqlite(...) with UseSqlServer(...), SqliteConnection with
  SqlConnection (package Microsoft.Data.SqlClient). Keep EnsureCreated or Migrate as it is.
- The connection string comes from configuration (ConnectionStrings in appsettings.json, overridden by the
  environment variable ConnectionStrings__<Name>), never a file path. In appsettings.json put a placeholder such as
  "Server=sqlserver;Database=<App>;User Id=<user>;Password=<from a secret>;TrustServerCertificate=True" with no real
  password.
- Code that creates the database file or its folder is no longer needed: remove it.
- EF Core migrations generated for SQLite must be generated again for SQL Server: do not edit them; say so in notes.
- Log to the console (stdout) instead of files. Files the application must keep (uploads, exports) go to a
  configurable folder; say in notes that it must be a shared volume or object storage.
- In notes, also say how to move the existing data (export from the SQLite file, import into SQL Server).
"""


def state_tasks(payload: dict, app_root: Path, limit: int = 6) -> list[dict]:
    """The goal 'stateless': files of the stateful components that use the embedded database (the findings name
    only the project file), as tasks with one finding that carries the goal."""
    have = {t["file"] for t in payload.get("tasks") or []}
    out: list[dict] = []
    for c in payload.get("components") or []:
        proj = app_root / (c.get("project") or "")
        folder = proj.parent if proj.suffix else proj
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            if len(out) >= limit:
                return out
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in (".cs", ".vb", ".fs", ".json") \
                    or any(part in ("bin", "obj", "node_modules", ".git", "Migrations") for part in path.parts) \
                    or path.stat().st_size > 400_000:
                continue
            rel = path.relative_to(app_root).as_posix()
            if rel in have or (path.suffix.lower() == ".json" and not path.name.lower().startswith("appsettings")):
                continue
            text, _ = _read_text(path)
            hits = [(i, line.strip()) for i, line in enumerate(text.splitlines(), 1) if STATE_CODE_RE.search(line)]
            if not hits:
                continue
            out.append({"file": rel, "component": c["name"], "project": c.get("project"), "findings": [{
                "rule": "move-state-out", "severity": "config",
                "title": "Move the embedded database to SQL Server",
                "why": "The component keeps its data in a file inside the container: it cannot run as several "
                       "replicas, and the data is lost when the container is replaced.",
                "fix": "Use SQL Server with the connection string from configuration (see the goal above).",
                "component": c["name"],
                "evidence": [{"file": rel, "line": i, "text": t[:200]} for i, t in hits[:6]]}]})
    return out


def task_prompt(payload: dict, task: dict, app_root: Path) -> tuple[str, list[str]]:
    """The question for one file, and the files it shows (the ones the answer may edit)."""
    comp = next((c for c in payload["components"] if c["name"] == task["component"]), payload["components"][0])
    proj = app_root / (task.get("project") or comp.get("project") or "")
    pk = _packages(proj) if proj.is_file() else []
    head = [f"Application {payload.get('app')}, component {comp['name']} ({comp.get('project')}): "
            f"{comp.get('language')}, role {comp.get('role')}, target framework {', '.join(comp.get('tfm') or []) or 'unknown'}.",
            f"Packages: {', '.join(pk) if pk else 'none listed'}.", "",
            "The assessment found these in the file below; they keep it from running in a Linux container:"]
    for i, f in enumerate(task["findings"], 1):
        head.append(f"{i}. [{f['severity']}] {f['rule']}: {f['title']}")
        head.append(f"   Why: {f['why']}")
        head.append(f"   Fix: {f['fix']}")
        for e in f["evidence"]:
            head.append(f"   Evidence: line {e['line']}: {e['text']}" if e["line"] else f"   Evidence: {e['text'] or e['file']}")
    if payload.get("goal") == "stateless":
        head += ["", STATE_GUIDANCE]
    if payload.get("goal") == "repair":
        diff = str(payload.get("base_patch") or "")
        diff = diff[diff.find("diff --git"):] if "diff --git" in diff else diff
        head += ["", REPAIR_GUIDANCE, "", "The earlier patch (already applied to the file below):",
                 "```diff", diff[:12000] + ("\n... (cut)" if len(diff) > 12000 else ""), "```"]
    head += ["", INSTRUCTIONS, ""]
    shown = [task["file"]]
    parts = []
    extra = proj.parent / "appsettings.json" if proj.name else None
    extra_rel = None
    if extra is not None and extra.is_file() and extra.stat().st_size <= EXTRA_FILE_CHARS:
        try:
            extra_rel = extra.relative_to(app_root).as_posix()
        except ValueError:
            extra_rel = None
    if extra_rel and extra_rel != task["file"]:
        etext, _ = _read_text(extra)
        parts.append(f"File {extra_rel} (the component's settings, complete):\n```\n{etext}\n```")
        shown.append(extra_rel)
    text, _ = _read_text(app_root / task["file"])
    used = len("\n".join(head)) + sum(len(p) for p in parts) + 200
    body, lo, hi = window(text, [e["line"] for f in task["findings"] for e in f["evidence"]],
                          max(2000, MAX_PROMPT_CHARS - used))
    n = text.count("\n") + 1
    what = "complete" if (lo, hi) == (1, n) or len(body) == len(text) else \
        f"lines {lo} to {hi} of {n}; only this part is shown: copy search text from it"
    parts.insert(0, f"File {task['file']} ({what}):\n```\n{body}\n```")
    return "\n".join(head) + "\n" + "\n\n".join(parts), shown


def estimate_chars(payload: dict, app_root: Path | None = None) -> int:
    """Characters sent to the LLM for the order (system, prompts, schema), for the queue's token estimate:
    the real prompts when the source is readable, else the findings' texts and a typical file size."""
    total = 0
    fixed = len(SYSTEM) + len(json.dumps(EDIT_SCHEMA)) + 120
    for t in payload["tasks"][:payload.get("max_calls", MAX_CALLS)]:
        size = None
        if app_root is not None:
            try:
                size = len(task_prompt(payload, t, app_root)[0])
            except OSError:
                size = None
        if size is None:
            size = len(INSTRUCTIONS) + 400 + sum(len(f["why"]) + len(f["fix"]) + len(f["title"]) + 80
                                                 + sum(len(e["text"]) + 20 for e in f["evidence"])
                                                 for f in t["findings"]) + DEFAULT_FILE_CHARS
        total += fixed + min(size, MAX_PROMPT_CHARS)
    return total


# --------------------------------------------------------------------------- applying the answer

def safe_rel(p: str) -> str | None:
    """A relative path inside the application (forward slashes), or None."""
    p = str(p or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if not parts or p.startswith("/") or re.match(r"^[A-Za-z]:", p) or ".." in parts or parts[0] == ".git" \
            or any(x == ".git" for x in parts):
        return None
    return "/".join(parts)


PKG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,199}")
VER_RE = re.compile(r"[0-9][0-9A-Za-z.\-+*]{0,63}")


def _csproj_change(text: str, action: str, package: str, version: str) -> tuple[str | None, str | None]:
    """(new project text, error)."""
    ref = re.compile(r"[ \t]*<PackageReference\s+Include=\"" + re.escape(package) + r"\"[^>]*?(/>|>.*?</PackageReference>)[ \t]*\n?",
                     re.S | re.I)
    if action == "remove":
        new, n = ref.subn("", text)
        return (new, None) if n else (None, f"package {package} is not referenced")
    if ref.search(text):
        return text, None                                  # already there
    line = f'<PackageReference Include="{package}" Version="{version}" />'
    m = re.search(r"(<ItemGroup[^>]*>)((?:(?!</ItemGroup>).)*?<PackageReference\b(?:(?!</ItemGroup>).)*?)(\n([ \t]*)</ItemGroup>)",
                  text, re.S)
    if m:
        indent = re.search(r"\n([ \t]*)<PackageReference", m[2])
        ind = indent[1] if indent else "    "
        return text[:m.end(2)] + f"\n{ind}{line}" + text[m.end(2):], None
    if "</Project>" not in text:
        return None, "no </Project> in the project file"
    i = text.rindex("</Project>")
    return text[:i] + f"  <ItemGroup>\n    {line}\n  </ItemGroup>\n" + text[i:], None


def _backslash_match(text: str, search: str, replace: str) -> str | None:
    """LLMs often get backslashes wrong when they write code into JSON (`"LocalMachine\\\\My"` in C# comes
    back as `LocalMachine\\My`). When the search text matches exactly once with every run of backslashes
    `k` times as long as in the file (the same k everywhere), the edit applies with the replacement's
    backslash runs scaled the same way. Returns the new text, or None."""
    if "\\" not in search:
        return None
    parts = re.split(r"(\\+)", search)
    rx = "".join(r"(\\+)" if p.startswith("\\") else re.escape(p) for p in parts if p)
    found = list(re.finditer(rx, text))
    if len(found) != 1:
        return None
    m = found[0]
    runs = [p for p in parts if p.startswith("\\")]
    factors = {len(g) / len(r) for g, r in zip(m.groups(), runs)}
    if len(factors) != 1:
        return None
    k = factors.pop()
    if k != int(k) or k < 1:
        return None
    new = re.sub(r"\\+", lambda r: "\\" * (len(r[0]) * int(k)), replace)
    return text[:m.start()] + new + text[m.end():]


def _first_mismatch(text: str, search: str) -> str:
    """Where a search text that was not found goes wrong: its first line that is not in the file, and the
    file's closest line, so the retry can copy it exactly."""
    import difflib
    lines = text.split("\n")
    for n, ln in enumerate(search.split("\n"), 1):
        if ln.strip() and ln not in text:
            close = difflib.get_close_matches(ln, lines, n=1, cutoff=0.6)
            return (f"line {n} of the search text is not in the file: {ln.strip()[:120]!r}"
                    + (f"; the file has {close[0].strip()[:160]!r}" if close else ""))
    return f"its lines are in the file, but not one after the other as given (it starts with {search.strip()[:80]!r})"


def apply_answer(app_root: Path, answer: dict, shown: list[str], project: str | None) -> tuple[list[dict], list[str]]:
    """Apply one answer: every edit's search text must occur exactly once (in the file as changed by the
    edits before it). All or nothing: on any error nothing is written. Returns (changes, errors)."""
    errors: list[str] = []
    files: dict[str, tuple[str, dict]] = {}
    changes: list[dict] = []
    root = app_root.resolve()
    allowed = set(shown)
    for i, ed in enumerate(answer.get("edits") or [], 1):
        rel = safe_rel(ed.get("file"))
        if rel is None:
            errors.append(f"edit {i}: {ed.get('file')!r} is not a path inside the application")
            continue
        if rel not in allowed:
            errors.append(f"edit {i}: {rel} may not be edited (only the files shown: {', '.join(shown)})")
            continue
        path = root / rel
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
            errors.append(f"edit {i}: {rel} is not a file of the application")
            continue
        if rel not in files:
            files[rel] = _read_text(path)
        text, how = files[rel]
        search = str(ed.get("search") or "").replace("\r\n", "\n")
        replace = str(ed.get("replace") or "").replace("\r\n", "\n")
        if not search.strip():
            errors.append(f"edit {i} ({rel}): the search text is empty")
            continue
        if search == replace:
            errors.append(f"edit {i} ({rel}): the replacement is the same as the search text")
            continue
        n = text.count(search)
        if n == 0:
            fixed = _backslash_match(text, search, replace)
            if fixed is not None:                  # the same text but for JSON-escaped backslashes
                files[rel] = (fixed, how)
                changes.append({"file": rel, "kind": "edit", "detail": "backslashes as in the file"})
                continue
            errors.append(f"edit {i} ({rel}): the search text was not found in the file; copy it exactly from the "
                          f"file shown ({_first_mismatch(text, search)})")
            continue
        if n > 1:
            errors.append(f"edit {i} ({rel}): the search text occurs {n} times; include more of the surrounding lines "
                          "so that it occurs exactly once")
            continue
        files[rel] = (text.replace(search, replace, 1), how)
        changes.append({"file": rel, "kind": "edit"})
    new_files: dict[str, str] = {}
    for i, nf in enumerate(answer.get("new_files") or [], 1):
        rel = safe_rel(nf.get("file"))
        content = str(nf.get("content") or "")
        if rel is None:
            errors.append(f"new file {i}: {nf.get('file')!r} is not a path inside the application")
        elif (root / rel).exists() or rel in new_files:
            errors.append(f"new file {i}: {rel} already exists; edit it instead")
        elif not content.strip() or len(content) > MAX_NEW_FILE:
            errors.append(f"new file {i}: {rel} is empty or too large")
        elif not (root / rel).parent.resolve().is_relative_to(root):
            errors.append(f"new file {i}: {rel} is outside the application")
        else:
            new_files[rel] = content
            changes.append({"file": rel, "kind": "new"})
    pkgs = [p for p in answer.get("package_changes") or [] if isinstance(p, dict)]
    if pkgs:
        rel = safe_rel(project or "")
        path = root / rel if rel else None
        if path is None or not path.is_file() or not path.suffix.lower().endswith("proj"):
            for p in pkgs:
                changes.append({"file": project or "", "kind": "package-manual",
                                "detail": f"{p.get('action')} {p.get('package')} {p.get('version')}".strip()})
        else:
            text, how = files.get(rel) or _read_text(path)
            for i, p in enumerate(pkgs, 1):
                name, ver, act = str(p.get("package") or ""), str(p.get("version") or ""), p.get("action")
                if not PKG_RE.fullmatch(name) or act not in ("add", "remove") or (act == "add" and not VER_RE.fullmatch(ver)):
                    errors.append(f"package change {i}: {act} {name!r} {ver!r} is not a package name and version")
                    continue
                new, err = _csproj_change(text, act, name, ver)
                if err:
                    errors.append(f"package change {i}: {err}")
                    continue
                if new != text:
                    text = new
                    changes.append({"file": rel, "kind": "package", "detail": f"{act} {name} {ver}".strip()})
            files[rel] = (text, how)
    if errors:
        return [], errors
    for rel, (text, how) in files.items():
        _write_text(root / rel, text, how)
    for rel, content in new_files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(content)
    return changes, []


def _names(rule: str, number: int, said: list[str]) -> bool:
    """Whether the LLM's list names the finding: its rule id, the id with a prefix it made up
    ("config-os-drive-path-default"), or its number in the prompt."""
    for s in said:
        s = s.strip().strip("[]").strip()
        if s == rule or s.endswith("-" + rule) or s.endswith(" " + rule) or s == str(number):
            return True
    return False


def answer_tokens(prompt: str) -> int:
    """The output cap of one edit answer: 4096 tokens plus half the prompt's (a larger file may need larger
    edits), at most 8192."""
    from .llmqueue import estimate_tokens
    return max(ANSWER_TOKENS_MIN, min(ANSWER_TOKENS_MAX, ANSWER_TOKENS_MIN + estimate_tokens(prompt) // 2))


def retry_prompt(prompt: str, answer: dict, errors: list[str]) -> str:
    return (prompt + "\n\nYour previous answer could not be applied, so nothing was changed:\n"
            + "\n".join(f"- {e}" for e in errors[:10])
            + "\nYour previous answer was:\n" + json.dumps(answer, indent=1)[:12000]
            + "\nAnswer again with the complete set of edits; copy every search text exactly from the file shown.")


# --------------------------------------------------------------------------- git

def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_NAME=AUTHOR[0], GIT_AUTHOR_EMAIL=AUTHOR[1], GIT_COMMITTER_NAME=AUTHOR[0],
               GIT_COMMITTER_EMAIL=AUTHOR[1])
    return env


GIT_SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "core.quotepath=off",
            "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", "-c", "submodule.recurse=false"]


def git(args: list[str], cwd: Path | None = None, check: bool = True, input: bytes | None = None,
        timeout: int = 600, safe_dir: Path | None = None) -> subprocess.CompletedProcess:
    extra = ["-c", f"safe.directory={safe_dir}"] if safe_dir else []
    p = subprocess.run(["git", *GIT_SAFE, *extra, *args], cwd=cwd, env=_git_env(), capture_output=True,
                       input=input, timeout=timeout)
    if check and p.returncode != 0:
        raise RefactorError(f"git {args[0]}: {(p.stderr or p.stdout).decode(errors='replace').strip()[-600:]}")
    return p


def resolve_source(source: dict) -> tuple[Path, str, bool]:
    """(folder to copy from, the application's folder inside it, whether it is a git repository)."""
    kind = source.get("type")
    subdir = source.get("subdir") or "."
    if subdir != "." and safe_rel(subdir) is None:
        raise RefactorError(f"bad application folder {subdir!r}")
    if kind == "git-url":
        url = str(source.get("url") or "")
        if os.environ.get(CLONE_ENV) != "1":
            raise RefactorError(f"this runner does not clone repositories ({CLONE_ENV}=1 allows it in a lab): "
                                "scan the repository with an organization scan on this machine instead")
        if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+", url) or ".." in url:
            raise RefactorError(f"not an https repository URL: {url!r}")
        cache = Path(os.environ.get(WORK_ENV) or tempfile.gettempdir()) / "clones" / hashlib.sha256(url.encode()).hexdigest()[:16]
        if (cache / ".git").exists():
            git(["fetch", "--quiet", "origin"], cwd=cache, safe_dir=cache)
        else:
            cache.parent.mkdir(parents=True, exist_ok=True)
            git(["clone", "--quiet", "--no-checkout", url, str(cache)])
        return cache, subdir, True
    if kind == "org-clone":
        base = Path(os.environ.get(SOURCES_ENV) or DEFAULT_SOURCES).resolve()
        d = str(source.get("dir") or "")
        if not CLONE_DIR_RE.fullmatch(d):
            raise RefactorError(f"bad clone folder {d!r}")
        top = (base / d).resolve()
        if not top.is_relative_to(base) or not (top / ".git").exists():
            raise RefactorError(f"the scan worker's clone of this repository is not at {top} (set {SOURCES_ENV} to "
                                "the worker's data folder, or scan the repository again)")
        return top, subdir, True
    if kind == "local":
        p = Path(str(source.get("path") or "")).resolve()
        # A runner that serves the scan worker's clones (the appliance) takes no other folder: a job in the
        # database must not make it read (and build) any folder of the machine.
        if os.environ.get(SOURCES_ENV) and not p.is_relative_to(Path(os.environ[SOURCES_ENV]).resolve()):
            raise RefactorError(f"this runner only reads the scan worker's clones ({SOURCES_ENV}), not {p}: "
                                "run `containerizer refactor` on that machine without --queue")
        if not p.is_dir():
            raise RefactorError(f"the source folder {p} does not exist")
        return p, subdir, bool(source.get("git", True))
    raise RefactorError(f"no source for this application ({kind or 'none'}): order it with `containerizer refactor` "
                        "on a checkout")


def checkout(source: dict, commit: str | None, dest: Path) -> tuple[Path, Path]:
    """A scratch git repository with the application's source at `commit` (never writes to the source).
    Returns (repository root, application folder)."""
    top, subdir, is_git = resolve_source(source)
    if dest.exists():
        shutil.rmtree(dest)
    if is_git:
        git(["clone", "--quiet", "--shared", "--no-checkout", str(top), str(dest)], safe_dir=top)
        if not commit:
            raise RefactorError("the assessment recorded no commit: scan the repository again")
        p = git(["checkout", "--quiet", "--detach", commit], cwd=dest, check=False)
        if p.returncode != 0:
            raise RefactorError(f"commit {commit[:12]} is no longer in the clone of {source.get('dir') or top}: the "
                                "repository moved on since this assessment. Scan it again and order a new refactoring.")
    else:
        shutil.copytree(top, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        git(["init", "--quiet"], cwd=dest)
        git(["add", "-A"], cwd=dest)
        git(["commit", "--quiet", "--allow-empty", "-m", "Containerizer: the source as assessed"], cwd=dest)
    app = (dest / subdir).resolve() if subdir != "." else dest.resolve()
    if not app.is_dir():
        raise RefactorError(f"the application folder {subdir} is not in commit {str(commit)[:12]}")
    return dest.resolve(), app


def make_patch(repo: Path, subject: str, body: str) -> bytes | None:
    """Commit everything changed in the scratch repository; the commit as a `git am` patch (None: no change)."""
    git(["add", "-A"], cwd=repo)
    if git(["diff", "--cached", "--quiet"], cwd=repo, check=False).returncode == 0:
        return None
    git(["commit", "--quiet", "-F", "-"], cwd=repo, input=(subject + "\n\n" + body).encode())
    return git(["format-patch", "-1", "--stdout", "--binary", "--no-signature", "HEAD"], cwd=repo).stdout


def apply_patch(repo: Path, patch: bytes) -> tuple[bool, str]:
    """`git apply --check`, then `git am --keep-cr`, on a clean scratch copy."""
    f = repo.parent / (repo.name + ".patch")
    f.write_bytes(patch)
    p = git(["apply", "--check", str(f)], cwd=repo, check=False)
    log = (p.stdout + p.stderr).decode(errors="replace")
    if p.returncode != 0:
        return False, "git apply --check:\n" + log
    p = git(["am", "--quiet", "--keep-cr", str(f)], cwd=repo, check=False)
    log += (p.stdout + p.stderr).decode(errors="replace")
    if p.returncode != 0:
        git(["am", "--abort"], cwd=repo, check=False)
        return False, "git am:\n" + log
    return True, log


# --------------------------------------------------------------------------- the patch as data

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def parse_patch(text: str) -> dict:
    """A format-patch (or plain git diff) as {"header": [...lines], "files": [{"old", "new", "status",
    "binary", "added", "removed", "hunks": [{"head", "lines": [(kind, old_no, new_no, text)]}]}]}.
    Hunks are read by their line counts, so the "-- " signature after the last one is not taken for a
    removed line."""
    lines = text.replace("\r\n", "\n").split("\n")
    out = {"header": [], "files": []}
    i, cur = 0, None
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("diff --git "):
            m = re.match(r"diff --git a/(.*) b/(.*)$", ln)
            cur = {"old": m[1] if m else ln[11:], "new": m[2] if m else ln[11:], "status": "modified",
                   "binary": False, "added": 0, "removed": 0, "hunks": []}
            out["files"].append(cur)
            i += 1
            continue
        if cur is None:
            out["header"].append(ln)
            i += 1
            continue
        if ln.startswith("new file mode"):
            cur["status"] = "added"
        elif ln.startswith("deleted file mode"):
            cur["status"] = "deleted"
        elif ln.startswith("rename from "):
            cur["status"] = "renamed"
        elif ln.startswith("GIT binary patch") or ln.startswith("Binary files "):
            cur["binary"] = True
        m = HUNK_RE.match(ln)
        if m:
            old_no, new_no = int(m[1]), int(m[3])
            old_left = int(m[2]) if m[2] is not None else 1
            new_left = int(m[4]) if m[4] is not None else 1
            h = {"head": ln, "lines": []}
            cur["hunks"].append(h)
            i += 1
            while i < len(lines) and (old_left > 0 or new_left > 0):
                t = lines[i]
                if t.startswith("\\"):
                    h["lines"].append(("note", None, None, t))
                elif t.startswith("+"):
                    h["lines"].append(("add", None, new_no, t[1:]))
                    new_no += 1
                    new_left -= 1
                    cur["added"] += 1
                elif t.startswith("-"):
                    h["lines"].append(("del", old_no, None, t[1:]))
                    old_no += 1
                    old_left -= 1
                    cur["removed"] += 1
                else:
                    h["lines"].append(("ctx", old_no, new_no, t[1:] if t.startswith(" ") else t))
                    old_no += 1
                    new_no += 1
                    old_left -= 1
                    new_left -= 1
                i += 1
            while i < len(lines) and lines[i].startswith("\\"):
                h["lines"].append(("note", None, None, lines[i]))
                i += 1
            continue
        i += 1
    return out


def diffstat(text: str) -> list[dict]:
    return [{"file": f["new"] if f["status"] != "deleted" else f["old"], "status": f["status"], "added": f["added"],
             "removed": f["removed"], "binary": f["binary"]} for f in parse_patch(text)["files"]]


# --------------------------------------------------------------------------- statuses

def verification_status(applies: bool, changes: int, verify: list[dict] | None) -> str:
    """verified: applies, and every changed component built and ran; applies-only: applies, but a build or
    run failed or could not be done (or verification was off); failed: does not apply or changes nothing."""
    if not applies or not changes:
        return "failed"
    if verify and all(v.get("status") in ("ok", "ok-external") for v in verify):
        return "verified"
    return "applies-only"


# What a patch that applies but is not verified needs, by its verification (what the pages show)
APPLIES_TEXT = {"build": ("Does not build", "The patch applies to the commit, but the component does not compile "
                          "with it: the errors are under Verification. Fix it with the LLM, or by hand."),
                "run": ("Does not start", "The patch applies and the component builds, but its container does not "
                        "start or answer: the log is under Verification. Fix it with the LLM, or by hand."),
                "none": ("Not built", "The patch applies to the commit, but it was not built and run (verification "
                         "was off, or Docker was not available): build and test it yourself.")}


def status_label(status: str, verify_statuses=()) -> tuple[str, str]:
    """(label, explanation) of an order's status; 'applies-only' says what went wrong."""
    if status != "applies-only":
        return STATUS_TEXT.get(status, status), ""
    vs = [v for v in verify_statuses if v]
    kind = "build" if "build-failed" in vs else "run" if "run-failed" in vs else "none"
    return APPLIES_TEXT[kind]


def order_status(job_status: str, summary: str | None = None, patch_status: str | None = None) -> str:
    """The status of an order from its LLM queue job: queued, generating, verifying, verified, applies-only,
    failed, cancelled."""
    if job_status in ("queued", "approval"):
        return job_status
    if job_status == "running":
        return "verifying" if str(summary or "").startswith("verifying") else "generating"
    if job_status == "answered":
        return patch_status if patch_status in ("verified", "applies-only", "failed") else "failed"
    if job_status == "skipped":
        return "cancelled"
    return "failed"


# --------------------------------------------------------------------------- the run

def _tail(text: str, n: int = 60) -> str:
    return "\n".join(str(text or "").splitlines()[-n:])[-6000:]


def rules_after(payload: dict, app_root: Path) -> tuple[dict, list[dict]]:
    """Run the rules on the patched copy: for each (component, rule) sent, 'resolved', 'partly' (fewer
    places) or 'still found'; and findings of the changed components that were not there before."""
    from .assess import assess
    a = assess(app_root)
    by_project = {c.project.rel: c for c in [*a.components, *a.libraries, *a.tests]}
    out: dict = {}
    new: list[dict] = []
    for comp in payload["components"]:
        c = by_project.get(comp.get("project"))
        found = {}
        for f in c.findings if c else []:
            if not f.dormant:
                found.setdefault(f.rule.id, []).extend(str(e) for e in f.evidence)
        for t in payload["tasks"]:
            for f in t["findings"]:
                if f["component"] != comp["name"]:
                    continue
                # the same rule may have places in other files: only the ones in this task's file count
                now = {(e["file"], e["text"]) for e in map(parse_evidence, found.get(f["rule"], [])) if e["file"] == t["file"]}
                before = {(e["file"], e["text"]) for e in f["evidence"]}
                state = "resolved" if not now else ("partly" if len(now) < len(before) else "still found")
                out[f"{comp['name']}|{f['rule']}|{t['file']}"] = state
        for rid in sorted(set(found) - set(comp.get("rules") or [])):
            new.append({"component": comp["name"], "rule": rid})
    return out, new


def verify_components(payload: dict, app_root: Path, work: Path, timeout: int = 900) -> list[dict]:
    """Build and run each changed component of the patched copy (verify.verify_component)."""
    from .assess import assess
    from .generate import buildable
    from .rules import load_rules
    from . import verify as vf
    a = assess(app_root)
    by_project = {c.project.rel: c for c in a.components}
    rules = load_rules()
    try:
        vf._run(["docker", "info"], 60)
    except Exception as ex:  # noqa: BLE001 - DockerUnavailable, OSError
        return [{"component": c["name"], "status": "not-built", "detail": f"Docker is not available: {ex}"[:400]}
                for c in payload["components"]]
    out = []
    changed = {t["component"] for t in payload["tasks"]}
    for comp in payload["components"]:
        if comp["name"] not in changed:
            continue
        c = by_project.get(comp.get("project"))
        if c is None:
            out.append({"component": comp["name"], "status": "not-built", "detail": "not a deployable component"})
            continue
        if not buildable(c):
            out.append({"component": comp["name"], "status": "not-built",
                        "detail": f"cannot be built in a Linux container as it is (verdict {c.verdict}, role {c.role})"})
            continue
        try:
            r = vf.verify_component(a, c, rules, timeout=timeout, work=work)
        except Exception as ex:  # noqa: BLE001
            out.append({"component": comp["name"], "status": "error", "detail": f"{type(ex).__name__}: {ex}"[:400]})
            continue
        wd = work / "verify" / a.name / vf.k8s_name(c.name)
        last = (r.get("attempts") or [{}])[-1]
        log = last.get("log_tail") or ""
        for name in (("build.log",) if r["status"] == "build-failed" else ("run.log", "build.log")):
            if not log and (wd / name).exists():
                log = (wd / name).read_text(errors="replace")
        out.append({"component": comp["name"], "status": r["status"], "mode": r.get("mode"),
                    "detail": "; ".join(str(h.get("rule") or h.get("status")) for h in r.get("attempts") or []),
                    "seconds": r.get("seconds"),
                    "finding": (r.get("finding") or {}).get("title") if r.get("finding") else None,
                    "log_tail": "" if r["status"] == "ok" else _tail(log)})
    return out


def run_order(payload: dict, work: Path, ask=None, progress=None, verify: bool | None = None, log=None) -> dict:
    """Carry out one order: generate, patch, apply to a clean copy, rules again, build and run.
    `ask(prompt, schema)` asks the LLM (default ai.ask_json with this module's system prompt).
    Returns the job's result (JSON-ready)."""
    from . import ai
    ask = ask or (lambda prompt, schema: ai.ask_json(prompt, schema, feature=FEATURE, system=SYSTEM,
                                                     max_tokens=answer_tokens(prompt)))
    progress = progress or (lambda text: None)
    log = log or (lambda text: None)
    verify = payload.get("verify", True) if verify is None else verify
    work.mkdir(parents=True, exist_ok=True)
    progress("generating: preparing the source")
    repo, app_root = checkout(payload["source"], payload.get("commit"), work / "edit")
    try:
        model = ai.model_name()
    except Exception:  # noqa: BLE001
        model = None
    findings: list[dict] = []
    notes: list[str] = []
    changes_all: list[dict] = []
    tasks = list(payload["tasks"])
    if payload.get("goal") == "stateless":
        tasks += state_tasks(payload, app_root)
    if payload.get("goal") == "repair":
        ok, alog = apply_patch(repo, str(payload.get("base_patch") or "").encode("utf-8"))
        if not ok:
            raise RefactorError("the earlier patch no longer applies to the commit: " + alog[-400:])
        changed = [d["file"] for d in diffstat(str(payload.get("base_patch") or ""))]
        tasks += repair_tasks(payload, app_root, changed)
    if not tasks:
        raise RefactorError("nothing to change: no file of the component uses an embedded database or names a finding")
    limit = int(MAX_CALLS if payload.get("max_calls") is None else payload["max_calls"])
    calls = 0
    for n, t in enumerate(tasks, 1):
        rows = [{"rule": f["rule"], "title": f["title"], "severity": f["severity"], "component": f["component"],
                 "file": t["file"], "status": "not-fixed", "reason": ""} for f in t["findings"]]
        findings += rows
        if n > limit:
            for r in rows:
                r.update(status="skipped", reason=f"not attempted: an order makes at most {limit} LLM calls")
            continue
        if not (app_root / t["file"]).is_file():
            for r in rows:
                r["reason"] = f"{t['file']} is not in the source at this commit"
            continue
        progress(f"generating: file {n} of {min(len(tasks), limit)}: {t['file']}")
        log(f"asking about {t['file']} ({', '.join(f['rule'] for f in t['findings'])})")
        prompt, shown = task_prompt(payload, t, app_root)
        answer, errors, changes = None, [], []
        for attempt in (1, 2):
            q = prompt if attempt == 1 else retry_prompt(prompt, answer, errors)
            try:
                calls += 1
                answer = ask(q, EDIT_SCHEMA)
            except Exception as ex:  # noqa: BLE001 - the LLM failed on this file: the others still go
                for r in rows:
                    r.update(status="llm-error", reason=f"{type(ex).__name__}: {ex}"[:400])
                answer = None
                break
            changes, errors = apply_answer(app_root, answer, shown, t.get("project"))
            if not errors:
                break
        if answer is None:
            continue
        if errors:
            for r in rows:
                r["reason"] = "the edits did not apply: " + "; ".join(errors)[:600]
            continue
        changes_all += changes
        if answer.get("notes"):
            notes.append(f"{t['file']}: {' '.join(str(answer['notes']).split())[:600]}")
        said_fixed = [str(x) for x in answer.get("fixed") or []]
        reasons = {str(x.get("rule")): str(x.get("reason") or "") for x in answer.get("not_fixed") or [] if isinstance(x, dict)}
        code_changes = [c for c in changes if c["kind"] != "package-manual"]
        for k, r in enumerate(rows, 1):
            said = _names(r["rule"], k, said_fixed)
            why = next((v for s, v in reasons.items() if _names(r["rule"], k, [s])), None)
            if code_changes and (said or (not said_fixed and why is None)):
                r.update(status="fixed", reason="")
            else:
                r["reason"] = why or ("no change made" if not code_changes else "the LLM did not say this one is fixed")
    for c in changes_all:
        if c["kind"] == "package-manual":
            notes.append(f"package change to make by hand in {c['file'] or 'the project'}: {c['detail']}")
    # The rules are the better judge than the LLM's own list: a finding the edits removed from a file they changed
    # is fixed even when the answer did not name it (and the commit message lists it too).
    changed = {c["file"] for c in changes_all if c["kind"] != "package-manual"}
    if changed and any(r["status"] != "fixed" and r["file"] in changed for r in findings):
        try:
            states, _ = rules_after(payload, app_root)
            for r in findings:
                if r["status"] not in ("fixed", "skipped") and r["file"] in changed \
                        and states.get(f"{r['component']}|{r['rule']}|{r['file']}") == "resolved":
                    r.update(status="fixed", reason="", confirmed_by="rules")
        except Exception as ex:  # noqa: BLE001 - only an upgrade of the LLM's own claims
            notes.append(f"the rules could not run on the edited copy: {type(ex).__name__}: {ex}"[:400])
    fixed = [r for r in findings if r["status"] == "fixed"]
    # the component in the file name only for an order of one component ("all" otherwise)
    comp_name = payload["components"][0]["name"] if payload.get("component") and payload["components"] else None
    result = {"status": "failed", "app": payload.get("app"), "component": comp_name, "commit": payload.get("commit"),
              "model": model, "calls": calls, "findings": findings, "skipped": payload.get("skipped") or [],
              "notes": notes, "filename": patch_filename(payload.get("app"), comp_name), "patch": None, "files": [],
              "apply_log": "", "verification": [], "new_findings": [], "verify": bool(verify)}
    rule_ids = sorted({r["rule"] for r in fixed})
    subject = f"Containerizer: {payload.get('app')}: " + (", ".join(rule_ids) if rule_ids else "refactoring")
    if len(subject) > 120:
        subject = subject[:117] + "..."
    body = ("Code changes generated by Containerizer (LLM: " + (model or "unknown") + ") for the findings of the\n"
            "assessment of commit " + str(payload.get("commit") or "?")[:12] + ". Review them before you merge.\n\n"
            + "\n".join(f"- {r['rule']} in {r['file']} ({r['component']}): {r['title']}" for r in fixed)
            + ("\n\nNotes:\n" + "\n".join(f"- {x}" for x in notes) if notes else "") + "\n")
    if payload.get("goal") == "repair" and changes_all:
        # one patch with the earlier change and its repair, for the assessed commit
        subject = (payload.get("base_subject") or subject.replace("build-error", "refactoring")).strip() + " (repaired)"
        body = body.replace("Code changes generated", f"Repairs order #{payload.get('base_job')}: code changes generated", 1)
        git(["reset", "--soft", str(payload.get("commit"))], cwd=repo)
    patch = make_patch(repo, subject, body) if fixed or changes_all else None
    if patch is None:
        result["reason"] = "no usable edits: " + ("; ".join(f"{r['rule']}: {r['reason']}" for r in findings if r["reason"])[:800]
                                                  or "the LLM changed nothing")
        return result
    text = patch.decode("utf-8", errors="replace")
    result.update(patch=text, files=diffstat(text))
    if text.encode("utf-8") != patch:
        result["patch_b64"] = base64.b64encode(patch).decode()
    progress("verifying: applying the patch to a clean copy")
    check_repo, check_app = checkout(payload["source"], payload.get("commit"), work / "check")
    ok, alog = apply_patch(check_repo, patch)
    result["apply_log"] = _tail(alog, 40)
    if not ok:
        result.update(status="failed", reason="the patch does not apply cleanly to the commit")
        result["patch"] = None
        result.pop("patch_b64", None)
        return result
    progress("verifying: running the rules on the patched copy")
    try:
        states, new = rules_after(payload, check_app)
        for r in findings:
            r["rules_after"] = states.get(f"{r['component']}|{r['rule']}|{r['file']}")
        result["new_findings"] = new
    except Exception as ex:  # noqa: BLE001
        notes.append(f"the rules could not run on the patched copy: {type(ex).__name__}: {ex}"[:400])
    if verify:
        progress("verifying: building and running the changed components")
        result["verification"] = verify_components(payload, check_app, work / "verify-work")
    result["status"] = verification_status(True, len(changes_all), result["verification"] if verify else None)
    if not verify:
        result["reason"] = "verification was off: the patch applies, it was not built"
    elif result["status"] != "verified":
        bad = [v for v in result["verification"] if v.get("status") not in ("ok", "ok-external")]
        result["reason"] = "; ".join(f"{v['component']}: {v['status']}" + (f" ({v['detail']})" if v.get("detail") else "")
                                     for v in bad)[:600] or "no component could be built"
    return result


def summary(result: dict) -> str:
    fx = [f for f in result.get("findings") or [] if f.get("status") == "fixed"]
    n = len([f for f in result.get("findings") or [] if f.get("status") != "skipped"])
    left = len(result.get("findings") or []) - n
    st = status_label(result.get("status") or "?", [v.get("status") for v in result.get("verification") or []])[0].lower()
    if result.get("status") == "failed":
        return f"{st}: {result.get('reason') or 'no patch'}"[:400]
    files = len(result.get("files") or [])
    return (f"{st}: {len(fx)} of {n} finding{'s' if n != 1 else ''} fixed, {files} file{'s' if files != 1 else ''} changed"
            + (f" ({left} not attempted: call limit)" if left else ""))


def handler(job: dict) -> dict:
    """The LLM queue's handler of `refactor` jobs."""
    pl = job["Payload"]
    base = Path(os.environ.get(WORK_ENV) or tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"refactor-{int(job.get('JobId') or 0)}-", dir=base))
    progress = job.get("_progress") or (lambda text: None)
    try:
        result = run_order(pl, work, progress=progress)
    finally:
        if not os.environ.get("CONTAINERIZER_KEEP_REFACTOR_WORK"):
            shutil.rmtree(work, ignore_errors=True)
    note = None
    if result["status"] == "applies-only":
        note = "the patch applies; " + (result.get("reason") or "it was not verified")
    return {"result": result, "summary": summary(result), "note": note[:400] if note else None}


# --------------------------------------------------------------------------- queueing

def queue_job(payload: dict, input_chars: int, requested_by: str | None = None) -> dict:
    """The LLM queue job of an order (JobQueue.add / cz.QueueLlmJob columns)."""
    comps = payload["components"]
    one = comps[0] if len(comps) == 1 and payload.get("component") else None
    return {"Kind": KIND, "Reason": None, "App": payload.get("app"), "SourceKey": payload.get("source_key"),
            "ApplicationId": payload.get("application_id"), "AssessmentId": payload.get("assessment_id"),
            "Component": one["name"] if one else None, "ProjectPath": one["project"] if one else None,
            "RuleVerdict": one["verdict"] if one else None, "Priority": PRIORITY, "DedupeKey": dedupe_key(payload),
            "Model": None, "RequestedBy": requested_by, "InputChars": int(input_chars), "Payload": payload}


# --------------------------------------------------------------------------- the command line

def cli(args) -> int:
    """`containerizer refactor <app-path> [--component NAME] [--out DIR] [--queue]`."""
    from .assess import assess
    from .sqlstore import source_info
    from .llmqueue import estimate_tokens
    path = Path(args.path).resolve()
    if not path.is_dir():
        print(f"error: {path} is not a folder", file=sys.stderr)
        return 2
    a = assess(path)
    doc = a.to_dict()
    info = source_info(path, a.name)
    top = None
    if info.get("commit"):
        top = Path(git(["rev-parse", "--show-toplevel"], cwd=path, safe_dir=path).stdout.decode().strip())
        source = {"type": "local", "path": str(top), "subdir": info.get("path") or ".", "git": True}
    else:
        source = {"type": "local", "path": str(path), "subdir": ".", "git": False}
    if doc.get("rating") != "B":
        print(f"note: {a.name} is rated {doc.get('rating')}; refactoring patches are meant for B-rated applications "
              "(targeted code changes)", file=sys.stderr)
    try:
        payload = build_payload(doc, source, info.get("commit"), component=args.component,
                                include_config=args.include_config, source_key=info.get("key"),
                                verify=not args.no_verify, max_calls=args.max_calls)
    except RefactorError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    if info.get("commit"):
        dirty = git(["status", "--porcelain"], cwd=top, safe_dir=top).stdout.strip()
        if dirty:
            print(f"note: {top} has uncommitted changes; the patch is made for commit {info['commit'][:12]}",
                  file=sys.stderr)
    chars = estimate_chars(payload, path)
    n = min(len(payload["tasks"]), payload["max_calls"])
    print(f"{a.name}: {n} LLM call{'s' if n != 1 else ''} ({sum(len(t['findings']) for t in payload['tasks'])} findings in "
          f"{len(payload['tasks'])} file{'s' if len(payload['tasks']) != 1 else ''}), "
          f"~{estimate_tokens('x' * chars):,} input tokens", file=sys.stderr)
    for s in payload["skipped"]:
        print(f"  skipped {s['component']}/{s['rule']}: {s['reason']}", file=sys.stderr)
    if args.queue:
        from .llmqueue import FileJobQueue, SqlJobQueue
        cs = args.sql or os.environ.get("CONTAINERIZER_SQL")
        if cs:
            from .sqlstore import connect
            q = SqlJobQueue(lambda: connect(cs))
        else:
            out = Path(args.out or ".")
            q = FileJobQueue(out / "llm-queue.json")
        job = queue_job(payload, chars, requested_by="command line")
        jid = q.add(job)
        where = "SQL Server" if cs else str(q.path)
        if jid:
            print(f"queued as job #{jid} in {where}" + ("" if cs else f": run `containerizer llm-queue --file {q.path}`"))
        else:
            print(f"an identical order is already waiting in {where}")
        return 0
    out = Path(args.out or ".").resolve()
    out.mkdir(parents=True, exist_ok=True)
    if os.environ.get(WORK_ENV):
        Path(os.environ[WORK_ENV]).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="refactor-", dir=os.environ.get(WORK_ENV) or None))
    try:
        result = run_order(payload, work, progress=lambda t: print(t, file=sys.stderr, flush=True),
                           log=lambda t: print("  " + t, file=sys.stderr, flush=True))
    finally:
        if not os.environ.get("CONTAINERIZER_KEEP_REFACTOR_WORK"):
            shutil.rmtree(work, ignore_errors=True)
    patch_file = out / result["filename"]
    if result.get("patch"):
        data = base64.b64decode(result["patch_b64"]) if result.get("patch_b64") else result["patch"].encode()
        patch_file.write_bytes(data)
    stem = result["filename"][:-len(".patch")]
    (out / f"{stem}.json").write_text(json.dumps({**result, "payload": payload}, indent=1, default=str) + "\n")
    print(summary(result))
    if result.get("patch"):
        print(f"patch: {patch_file}")
        print(f"apply: git checkout -b containerizer-refactor {str(result.get('commit') or 'HEAD')[:12]} && "
              f"git am --keep-cr < {patch_file.name}")
    print(f"summary: {out / (stem + '.json')}")
    return 0 if result["status"] != "failed" else 1
