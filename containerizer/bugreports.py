"""Suspected Containerizer bugs (docs/bug-reports.md): an administrator flags a component whose build or run failed
in a way that looks like the tool's fault, and exports the flagged cases as one JSON file for whoever maintains
Containerizer.

- **Flag** (the application's page, the failed component's *Build and run* block; administrators): the case is
  copied at that moment into cz.BugReport (schema 65), because the next scan replaces the component's logs: the
  component's facts, its verification result, every attempt's Dockerfile, build command and log, and its findings,
  as gzip JSON. One open report per component: flagging again replaces it.
- **Bug reports** (Admin → Bug reports; administrators): the reports, a note each, close and remove, the
  anonymization keywords, and **Export JSON**.
- **Anonymization**: every keyword (one per line: company, product, project, host and people's names) is replaced
  in the export by a random word, the same word for the same keyword within one file, so the case stays readable.
  Matching ignores case. The mapping is not in the file and not kept. Secrets are already masked in the stored logs.

- **Let the LLM try** (a report on the Bug reports page): the administrator writes what to try; the LLM queue
  (kind `bugtry`, `try_handler`) builds and runs the component as it is, asks the LLM for a build-plan change that
  follows the hint, builds and runs again with it, and records whether that helped. The tries are part of the
  export: what was suggested, what the LLM changed, and the result, for whoever fixes the tool.

- **System prompts** (the same page; llmprompts.py): what Containerizer tells the LLM about its role, per kind of
  question, shown and replaceable; the replaced ones are in the export.

Source file contents are not in a report: logs, the Dockerfile and finding evidence can still name things, which is
what the keywords are for.
"""
from __future__ import annotations

import gzip
import json
import re
import secrets
import sys
from datetime import datetime, timezone
from html import escape as e

BASE = "/admin/bugs"
MAX_LOG = 300_000                 # characters of one attempt's log kept in a report (its start and its end)
MAX_NOTE = 1000
MAX_KEYWORDS = 200
MAX_HINT = 2000
KIND = "bugtry"
PRIORITY = 1700                   # a person asked for it: before the automatic reviews
OK = ("ok", "ok-external")
MAX_CODE_LINES = 1000             # lines of the application's code one try may change, when the administrator allows it
CODE_LINE_CHOICES = (0, 25, 50, 100, 200, 500, 1000)
DEFAULT_CODE_LINES = 50
MAX_CODE_FILES = 6                # files the LLM may read (and so change) in one try that may change over 100 lines


def code_files_allowed(code_lines: int) -> int:
    """How many files the LLM may read (and so change) in a try: three, and six when it may change over 100 lines."""
    return 3 if code_lines <= 100 else MAX_CODE_FILES
MAX_FILE_CHARS = 24000            # of a file shown to the LLM
MAX_LISTED = 300                  # file names offered to the LLM
MAX_LLM_CALLS = 3                 # per try: the plan, the code change, and one more when its edits were refused
MAX_PATCH_CHARS = 200_000
OUTCOME_TEXT = {"helped": "Helped: it builds and runs with the change",
                "further": "Got further: it gets further with the change, and still fails",
                "not-helped": "Did not help: it fails as before with the change",
                "worse": "Worse: it gets less far with the change",
                "already-fixed": "Already fixed: it builds and runs with this version, without a change",
                "nothing-to-try": "Nothing to try: the LLM found no change for it",
                "not-tried": "Not tried"}
EDIT_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["edits"],
               "properties": {"edits": {"type": "array", "items": {
                   "type": "object", "additionalProperties": False, "required": ["file", "find", "replace"],
                   "properties": {"file": {"type": "string"}, "find": {"type": "string"}, "replace": {"type": "string"}}}}}}
TRY_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["diagnosis", "fix_json"],
              "properties": {"diagnosis": {"type": "string", "description": "what fails and what the change does, two sentences"},
                             "fix_json": {"type": "string", "description": "JSON object: the build-plan patch, or {} when no key can do it"}}}
NOTICES = {"flagged": ("ok", "Flagged as a suspected Containerizer bug: it is on Admin → Bug reports."),
           "unflagged": ("ok", "The flag was removed."),
           "nothing": ("bad", "This component has no failed build or run in its latest scan."),
           "unavailable": ("bad", "Bug reports need the database of version 0.54.7 or later.")}
STATUSES = ("open", "resolved", "closed")
VIEWS = {"open": ("Open", ("open",)), "closed": ("Resolved and closed", ("resolved", "closed")), "all": ("All", STATUSES)}
MAX_LABELS = 8
LABEL_RE = re.compile(r"[\w .+#/-]{1,30}")
WORDS = ("amber", "birch", "cedar", "delta", "ember", "fjord", "grove", "harbor", "iris", "juniper", "kestrel", "lumen",
         "maple", "nectar", "onyx", "pebble", "quartz", "raven", "sorrel", "tundra", "umber", "violet", "willow", "zephyr")


# --------------------------------------------------------------------------- anonymization

def parse_keywords(text: str) -> list[str]:
    """The keywords of the settings text: one per line, at least two characters, longest first, each once."""
    out: list[str] = []
    for line in (text or "").replace("\r", "").split("\n"):
        k = line.strip()
        if len(k) >= 2 and k.casefold() not in {x.casefold() for x in out}:
            out.append(k[:200])
    return sorted(out[:MAX_KEYWORDS], key=lambda k: (-len(k), k.casefold()))


def anonymizer(keywords: list[str], rand=None):
    """(replace(text) -> text, counts {index: replacements}): each keyword becomes one random word of this run."""
    rand = rand or secrets.SystemRandom()
    names: dict[str, str] = {}
    used: set[str] = set()
    for k in keywords:
        while True:
            w = f"{rand.choice(WORDS)}-{rand.randrange(16 ** 4):04x}"
            if w not in used:
                break
        used.add(w)
        names[k.casefold()] = w
    counts = {"n": 0}
    if not names:
        return (lambda text: text), counts
    rx = re.compile("|".join(re.escape(k) for k in keywords), re.I)

    def sub(m) -> str:
        counts["n"] += 1
        return names[m.group(0).casefold()]
    return (lambda text: rx.sub(sub, text)), counts


def anonymize(value, replace):
    """A JSON value with every string (keys too) passed through `replace`."""
    if isinstance(value, str):
        return replace(value)
    if isinstance(value, list):
        return [anonymize(v, replace) for v in value]
    if isinstance(value, dict):
        return {replace(k) if isinstance(k, str) else k: anonymize(v, replace) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------- labels

def split_labels(stored) -> list[str]:
    return [x for x in (stored or "").split(",") if x]


def parse_labels(text: str) -> tuple[list[str] | None, str]:
    """The labels of a form field (comma-separated): (labels, "") or (None, what is wrong)."""
    out: list[str] = []
    for raw in (text or "").split(","):
        t = " ".join(raw.split())
        if not t:
            continue
        if not LABEL_RE.fullmatch(t):
            return None, f"“{t[:40]}” is not a label: letters, digits, spaces and . + # / - , at most 30 characters."
        if t.casefold() not in {x.casefold() for x in out}:
            out.append(t)
    if len(out) > MAX_LABELS:
        return None, f"At most {MAX_LABELS} labels a report."
    return out, ""


# --------------------------------------------------------------------------- flagging

def _cut(text: str, limit: int = MAX_LOG) -> str:
    if len(text) <= limit:
        return text
    head = limit // 4
    return text[:head] + f"\n[... {len(text) - limit:,} characters left out ...]\n" + text[-(limit - head):]


def collect(conn, component_id: int) -> dict | None:
    """The case of a component as its latest scan left it (None: no such component, or nothing failed)."""
    from . import __version__, verifylog
    from .webui import VERIFY_FAILED
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT c.ApplicationId, c.ApplicationName, c.AssessmentId, c.ComponentId, c.ComponentName, c.ProjectPath, "
                "c.Role, c.Tier, c.TargetFramework, c.Verdict, c.VerdictText, c.VerifyStatus, c.VerifyDetail, "
                "aa.Rating, aa.SourceCommit, aa.AssessedAt FROM cz.vComponentLatest c "
                "JOIN cz.vApplicationLatest aa ON aa.AssessmentId = c.AssessmentId WHERE c.ComponentId = %s",
                (int(component_id),))
    rows = cur.fetchall()
    if not rows or rows[0].get("VerifyStatus") not in VERIFY_FAILED:
        return None
    r = rows[0]
    cur.execute("SELECT RuleId, Severity, Title, Evidence FROM cz.vFindingLatest WHERE AssessmentId = %s AND ComponentId = %s "
                "ORDER BY FindingId", (r["AssessmentId"], r["ComponentId"]))
    findings = [{"rule": f["RuleId"], "severity": f["Severity"], "title": f["Title"],
                 "evidence": (f.get("Evidence") or "")[:400]} for f in cur.fetchall()]
    attempts = []
    try:
        cur.execute("SELECT Attempt, Stage, Truncated, LogGz FROM cz.ComponentVerifyLog WHERE AssessmentId = %s AND "
                    "ComponentId = %s ORDER BY Attempt, Stage", (r["AssessmentId"], r["ComponentId"]))
        for x in cur.fetchall():
            try:
                text = gzip.decompress(bytes(x["LogGz"])).decode("utf-8", "replace")
            except (OSError, EOFError, ValueError, TypeError):
                continue
            head = verifylog.header_of(text) if x["Stage"] == "build" else ""
            attempts.append({"attempt": int(x["Attempt"]), "stage": x["Stage"], "log_was_cut_by_the_scan": bool(x["Truncated"]),
                             "dockerfile_and_command": head, "log": _cut(text[len(head):] if head else text)})
    except Exception:  # noqa: BLE001      a database from before schema 61: the excerpt alone
        pass
    return {"application_id": r["ApplicationId"], "assessment_id": r["AssessmentId"], "component_id": r["ComponentId"],
            "case": {"containerizer": __version__,
                     "scanned_at": r["AssessedAt"].isoformat() if r.get("AssessedAt") else None,
                     "application": r["ApplicationName"], "rating": r.get("Rating"),
                     "commit": r.get("SourceCommit") or None,
                     "component": {"name": r["ComponentName"], "project": r["ProjectPath"], "role": r["Role"],
                                   "tier": r["Tier"], "target_framework": r.get("TargetFramework"),
                                   "verdict": r["Verdict"], "verdict_text": r.get("VerdictText")},
                     "verification": {"status": r["VerifyStatus"], "detail": r.get("VerifyDetail") or ""},
                     "attempts": attempts, "findings": findings}}


def flag(conn, component_id: int, note: str, user: str) -> int | None:
    """Keep the component's case as an open report (replacing its open one). The report's id, or None: nothing failed."""
    got = collect(conn, component_id)
    if got is None:
        return None
    case = got["case"]
    data = gzip.compress(json.dumps(case, ensure_ascii=False).encode("utf-8"), 6)
    retire(conn, got["component_id"])
    cur = conn.cursor()
    cur.execute("INSERT cz.BugReport (ApplicationId, ComponentId, AssessmentId, App, Component, VerifyStatus, Note, CreatedBy, "
                "DataGz) OUTPUT inserted.BugId VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (got["application_id"], got["component_id"], got["assessment_id"], case["application"][:200],
                 case["component"]["name"][:200], case["verification"]["status"][:40], (note or "").strip()[:MAX_NOTE] or None,
                 (user or "")[:200], data))
    row = cur.fetchone()
    return int(row[0] if not isinstance(row, dict) else row["BugId"])


def tried(conn, bug_ids) -> set:
    """The reports that have tries: they are closed, never removed (the history of what was tried stays)."""
    try:
        return set(tries(conn, set(bug_ids)))
    except Exception:  # noqa: BLE001      no LLM queue in this database
        return set()


def retire(conn, component_id: int) -> None:
    """The component's open reports give way (a new flag, or the flag removed): one with tries is closed and kept,
    one without is removed."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT BugId FROM cz.BugReport WHERE ComponentId = %s AND Status = N'open'", (int(component_id),))
    ids = [int(r["BugId"]) for r in cur.fetchall()]
    keep = tried(conn, ids)
    for i in ids:
        if i in keep:
            cur.execute("UPDATE cz.BugReport SET Status = N'closed', StatusNote = N'closed when the component was flagged "
                        "again or its flag was removed' WHERE BugId = %s", (i,))
        else:
            cur.execute("DELETE FROM cz.BugReport WHERE BugId = %s", (i,))


AUTO_NOTE = "automatically: a try got five stars, the application rates A and the component runs healthy in the sandbox"


def auto_resolve(conn) -> list[int]:
    """Mark resolved the open reports that are settled: one of their tries got five stars, the application's latest
    scan rates it A, and the latest sandbox check found the component deployed and healthy. Only reports nobody
    set a status on (a reopened one stays open). The ids resolved."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT b.BugId FROM cz.BugReport b JOIN cz.vApplicationLatest a ON a.ApplicationId = b.ApplicationId "
                "JOIN cz.vSandboxLatest s ON s.ApplicationId = b.ApplicationId AND s.ComponentId = b.ComponentId "
                "WHERE b.Status = N'open' AND b.StatusNote IS NULL AND a.Rating = 'A' AND s.Status = N'healthy'")
    ids = [int(r["BugId"]) for r in cur.fetchall()]
    if not ids:
        return []
    done = tries(conn, set(ids))
    ids = [i for i in ids if any(int(t.get("score") or 0) >= 5 for t in done.get(i, []))]
    for i in ids:
        cur.execute("UPDATE cz.BugReport SET Status = N'resolved', StatusNote = %s WHERE BugId = %s AND Status = N'open'",
                    (AUTO_NOTE, i))
    return ids


def flagged(admin, app: dict) -> dict:
    """{ComponentId: BugId} of the application's open reports (the results page; {} on a database before schema 65)."""
    try:
        conn = admin.connect_admin()
    except Exception:  # noqa: BLE001
        return {}
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT ComponentId, BugId FROM cz.BugReport WHERE ApplicationId = %s AND Status = N'open'",
                    (int(app["ApplicationId"]),))
        return {r["ComponentId"]: int(r["BugId"]) for r in cur.fetchall()}
    except Exception:  # noqa: BLE001
        return {}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def flag_html(c: dict, ctx: dict) -> str:
    """The flag of a failed component, in its Build and run block (administrators)."""
    csrf = ctx.get("bug_csrf")
    if not csrf or c.get("ComponentId") is None:
        return ""
    cid = int(c["ComponentId"])
    bug = (ctx.get("bugs") or {}).get(c["ComponentId"])
    code = ctx.get("bug_notice") or ""
    note = notice_html(code) if code and (code == "flagged") == bool(bug) else ""
    if bug:
        return (f"{note}<form method='post' action='{BASE}/unflag/{cid}' class='formrow small'>{csrf}"
                f"<span>🚩 Flagged as a suspected Containerizer bug (<a href='{BASE}#bug{int(bug)}'>report #{int(bug)}</a>).</span>"
                "<button class='secondary'>Remove the flag</button></form>")
    return (f"{note}<form method='post' action='{BASE}/flag/{cid}' class='formrow small'>{csrf}"
            "<input name='Note' maxlength='1000' style='min-width:420px' placeholder='Why it looks like a Containerizer bug (optional)' "
            "aria-label='Why it looks like a Containerizer bug'>"
            "<button class='secondary'>Flag as a Containerizer bug</button></form>")


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{e(text)}</div>"


# --------------------------------------------------------------------------- let the LLM try

def score_of(status: str | None) -> int:
    """How far a build and run got, 0 to 5: the rating of a try (its stars)."""
    return {"ok": 5, "ok-external": 4, "finding": 3, "run-failed": 2, "build-failed": 1}.get(str(status or ""), 0)


def merge_patch(base: dict | None, more: dict | None) -> dict:
    """Two build-plan patches as one (lists joined, env merged, the later value for the rest)."""
    out = json.loads(json.dumps(base or {}))
    for k, v in (more or {}).items():
        if isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + [x for x in v if x not in out[k]]
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


def _job_try(conn, job_id: int) -> tuple[dict, dict] | None:
    """(payload, result) of an answered try."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT Payload, Result FROM cz.LlmJob WHERE JobId = %s AND Kind = N'bugtry' AND Status = N'answered'",
                (int(job_id),))
    rows = cur.fetchall()
    if not rows:
        return None
    try:
        return json.loads(rows[0]["Payload"] or "{}"), json.loads(rows[0]["Result"] or "{}")
    except ValueError:
        return None


def queue_try(conn, bug_id: int, hint: str, parent: int | None = None, code_lines: int = 0) -> tuple[int | None, str]:
    """Queue a try for a report: (job id or 0 when the same one waits, "") or (None, why not). `parent`: the try
    to continue from (its changes are the starting point). `code_lines`: how many lines of the application's code
    the LLM may change (0: the build plan only)."""
    import hashlib
    from .admin_refactor import order_source
    from .llmqueue import SqlJobQueue
    hint = (hint or "").strip()[:MAX_HINT]
    code_lines = max(0, min(int(code_lines or 0), MAX_CODE_LINES))
    if not hint:
        return None, "Write what the LLM should try."
    cur = conn.cursor(as_dict=True)
    # the commit is the report's own (the case): the application may have been scanned again since
    cur.execute("SELECT b.BugId, b.ApplicationId, b.AssessmentId, b.App, b.Component, b.DataGz, a.RepositoryUrl, a.SourcePath "
                "FROM cz.BugReport b JOIN cz.vApplicationLatest a ON a.ApplicationId = b.ApplicationId "
                "WHERE b.BugId = %s", (int(bug_id),))
    rows = cur.fetchall()
    if not rows:
        return None, "The report's application is no longer there."
    r = rows[0]
    try:
        case = json.loads(gzip.decompress(bytes(r["DataGz"])).decode("utf-8"))
    except (OSError, EOFError, ValueError, TypeError):
        return None, "The report cannot be read."
    source = order_source(conn, {"RepositoryUrl": r.get("RepositoryUrl"), "SourcePath": r.get("SourcePath")})
    if source is None or not case.get("commit"):
        return None, ("No organization scan on this machine has the application's source at the flagged commit: "
                      "scan it again and flag it again.")
    base = None
    if parent:
        got = _job_try(conn, parent)
        if got is None or got[0].get("bug_id") != int(r["BugId"]):
            return None, "That try is not a finished try of this report."
        res = got[1]
        last = res.get("after") or res.get("before") or {}
        base = {"job": int(parent), "plan_patch": res.get("plan_patch_total") or {}, "code_patch": res.get("code_patch") or "",
                "status": last.get("status"), "steps": last.get("steps") or "", "log_tail": last.get("log_tail") or ""}
    project = (case.get("component") or {}).get("project")
    payload = {"bug_id": int(r["BugId"]), "app": r["App"], "application_id": r["ApplicationId"], "component": r["Component"],
               "project": project, "source": source, "commit": case["commit"], "hint": hint, "code_lines": code_lines,
               "parent": int(parent) if parent else None, "base": base,
               "flagged_status": (case.get("verification") or {}).get("status")}
    key = hashlib.sha256(f"{r['BugId']}|{parent or 0}|{code_lines}|{hint}".encode()).hexdigest()
    # no ProjectPath: QueueLlmJob skips a waiting job of the same component, and every try is kept
    job = {"Kind": KIND, "Reason": None, "App": r["App"], "Repository": r["App"], "SourceKey": r.get("SourceKey"),
           "ApplicationId": r["ApplicationId"], "AssessmentId": r["AssessmentId"], "Component": r["Component"],
           "ProjectPath": None, "RuleVerdict": None, "Priority": PRIORITY, "DedupeKey": key, "Model": None,
           "RequestedBy": None, "InputChars": 12000 + len(hint) + (40000 if code_lines else 0), "Payload": payload}
    return SqlJobQueue(None).add_with(conn, job), ""


def try_prompt(app: str, component: str, kind: str, plan: dict, stage: str, log_tail: str, hint: str,
               files: list[str] | None = None, code_lines: int = 0) -> str:
    from .ai import PLAN_HELP, PLAN_RULES
    rules = PLAN_RULES if not code_lines else "Never run as root or disable security settings."
    code = ""
    if code_lines:
        code = (f"\n\nYou may also change the application's code, at most {code_lines} lines in all, when the build plan "
                "alone cannot do it. Name in `files` the files you need to read first (at most "
                f"{code_files_allowed(code_lines)}, from this list; [] when the plan patch is enough):\n" + "\n".join(files or []))
    return (f"A generated container for {app}/{component} failed at the {stage} stage.\n\nBuild plan:\n"
            f"{json.dumps({k: v for k, v in plan.items() if k not in ('applied', 'reasons')}, indent=1, default=str)[:6000]}\n\n"
            f"{PLAN_HELP.get(kind, PLAN_HELP['dotnet'])}\n{rules}\n\nLog tail:\n{log_tail[-8000:]}\n\n"
            f"An administrator suggests what to try:\n{hint}\n\nGive the build-plan patch that carries out the suggestion "
            "(only the keys above; {} when none of them can do it), and say in the diagnosis what fails and what the "
            f"patch does.{code}")


def edit_prompt(hint: str, diagnosis: str, log_tail: str, texts: dict[str, str], code_lines: int, problem: str = "") -> str:
    shown = "\n\n".join(f"=== {p} ===\n{t}" for p, t in texts.items())
    return (f"The build or run of an application fails in its container.\n\nLog tail:\n{log_tail[-4000:]}\n\n"
            f"Diagnosis so far: {diagnosis}\n\nAn administrator suggests what to try:\n{hint}\n\n"
            f"Change the files below to carry it out, with at most {code_lines} changed lines in all. Each edit names a "
            "file, the exact text to find (it must occur exactly once in that file; an empty `find` with a file that "
            "does not exist creates it) and its replacement. Change nothing else, keep the code style, and give no edit "
            "when the code should stay as it is.\n"
            + (f"\nYour earlier edits were not applied: {problem}\n" if problem else "") + f"\n{shown}")


def code_files(repo, app_root, project: str) -> list[str]:
    """The text-like files the LLM may ask for: the component's folder first, then the rest of the application."""
    from pathlib import PurePosixPath
    from . import refactor as rf
    raw = rf.git(["ls-files", "-z", "--", "."], cwd=app_root, safe_dir=repo).stdout.decode("utf-8", "replace")
    skip = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".dll", ".exe", ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".snk",
            ".pfx", ".lock", ".min.js", ".min.css", ".map")
    paths = [p for p in raw.split("\0") if p and not p.casefold().endswith(skip) and "/node_modules/" not in "/" + p]
    d = PurePosixPath(project or "").parent.as_posix()
    own = [p for p in paths if d not in ("", ".") and p.startswith(d + "/")]
    return (own + [p for p in paths if p not in set(own)])[:MAX_LISTED]


def apply_edits(repo, app_root, edits: list, code_lines: int, listed: set) -> tuple[int, str]:
    """Apply the LLM's edits to the scratch copy: (changed lines, "") or (0, why not; the copy is put back)."""
    from . import refactor as rf
    todo = []
    for ed in edits[:40]:
        rel = rf.safe_rel(str(ed.get("file") or "")) if isinstance(ed, dict) else None
        if rel is None:
            return 0, f"{ed.get('file') if isinstance(ed, dict) else ed!r} is not a path inside the application"
        f = app_root / rel
        find, new = str(ed.get("find") or ""), str(ed.get("replace") or "")
        if not find:
            if f.exists():
                return 0, f"{rel} exists: an edit of it needs the text to find"
            todo.append((f, None, new, rel))
            continue
        if rel not in listed or not f.is_file():
            return 0, f"{rel} is not one of the application's files"
        text = f.read_text(encoding="utf-8", errors="surrogateescape")
        if text.count(find) != 1:
            return 0, f"the text to find occurs {text.count(find)} times in {rel}, not once"
        bad = rf.harmful_edit(rel, find, new)
        if bad:
            return 0, f"{rel}: {'; '.join(bad)}"
        todo.append((f, find, new, rel))
    undo, lines = [], 0
    for f, find, new, rel in todo:
        if find is None:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(new, encoding="utf-8")
            undo.append((f, None))
            lines += len(new.splitlines())
        else:
            text = f.read_text(encoding="utf-8", errors="surrogateescape")
            undo.append((f, text))
            f.write_text(text.replace(find, new, 1), encoding="utf-8", errors="surrogateescape")
    # against the index: the changes of the try it continues are staged, so only this try's lines count
    stat = rf.git(["diff", "--numstat"], cwd=repo, safe_dir=repo).stdout.decode("utf-8", "replace")
    lines += sum(int(x) for row in stat.splitlines() for x in row.split("\t")[:2] if x.isdigit())
    if lines > code_lines:
        for f, text in reversed(undo):
            if text is None:
                f.unlink(missing_ok=True)
            else:
                f.write_text(text, encoding="utf-8", errors="surrogateescape")
        return 0, f"the edits change {lines} lines, more than the {code_lines} allowed"
    return lines, ""


def _result_of(r: dict) -> dict:
    """What a verification left, for the report: the status, the steps and the end of the last log."""
    last = (r.get("attempts") or [{}])[-1]
    return {"status": r.get("status"), "steps": "; ".join(f"{h.get('stage')} {h.get('rule') or h.get('status')}"
                                                        for h in r.get("attempts") or [])[:600],
            "log_tail": "" if r.get("status") in OK else str(last.get("log_tail") or "")[-3000:]}


def outcome_of(before: str, after: str | None) -> str:
    if after is None:
        return "already-fixed" if before in OK else "nothing-to-try"
    if before in OK:
        return "helped" if after in OK else "worse"
    if after in OK:
        return "helped"
    if score_of(after) > score_of(before):
        return "further"
    return "worse" if score_of(after) < score_of(before) else "not-helped"


def try_handler(job: dict, ask=None, verify=None) -> dict:
    """The LLM queue's handler of `bugtry` jobs. From the flagged commit, or from the changes of the try it continues
    (payload base): build and run the component as it is (a continued try takes its parent's result), ask the LLM
    for a build-plan patch that follows the administrator's hint and, when code changes are allowed (code_lines),
    for edits of up to that many lines in files it asks to read; build and run with the changes. At most
    MAX_LLM_CALLS calls. The result keeps everything the next try needs to continue: the plan patch and the code
    change so far. `ask(prompt, schema, system)` and `verify(a, c, rules, work, plan_patch)` are replaced in tests."""
    import os
    import shutil
    import tempfile
    from pathlib import Path
    from . import ai
    from . import refactor as rf
    from . import verify as vf
    from .assess import assess
    from .generate import buildable, make_plan
    from .rules import load_rules
    pl = job["Payload"]
    progress = job.get("_progress") or (lambda text: None)
    ask = ask or (lambda prompt, schema, system=None: ai.ask_json(prompt, schema, feature="bugtry-queued", system=system,
                                                                  max_tokens=ai.SHORT_ANSWER_TOKENS if system is None else None))
    verify = verify or (lambda a, c, rules, work, patch: vf.verify_component(a, c, rules, work=work, plan_patch=patch))
    base = pl.get("base") or {}
    code_lines = max(0, min(int(pl.get("code_lines") or 0), MAX_CODE_LINES))
    tmp = Path(os.environ.get(rf.WORK_ENV) or tempfile.gettempdir())
    tmp.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"bugtry-{int(job.get('JobId') or 0)}-", dir=tmp))
    result = {"bug_id": pl.get("bug_id"), "hint": pl.get("hint"), "flagged_status": pl.get("flagged_status"),
              "parent": pl.get("parent"), "code_lines_allowed": code_lines, "outcome": "not-tried", "score": 0,
              "plan_patch_total": base.get("plan_patch") or {}, "code_patch": base.get("code_patch") or "", "llm_calls": 0}

    def done(reason: str = "") -> dict:
        if reason:
            result["reason"] = reason[:600]
        text = OUTCOME_TEXT[result["outcome"]] + (f" ({reason})" if reason and result["outcome"] == "not-tried" else "")
        return {"result": result, "summary": f"{stars(result['score'])} {text}"[:400], "note": None}

    def named(a):
        return next((x for x in a.components if x.project.rel == pl.get("project")), None)
    try:
        progress("preparing the source")
        repo, app_root = rf.checkout(pl["source"], pl.get("commit"), work / "src")
        if base.get("code_patch"):
            p = rf.git(["apply", "--whitespace=nowarn", "-"], cwd=repo, check=False, safe_dir=repo,
                       input=base["code_patch"].encode("utf-8", "surrogateescape"))
            if p.returncode != 0:
                return done("the code change of the try it continues no longer applies")
            rf.git(["add", "-A", "."], cwd=repo, safe_dir=repo)
        a = assess(app_root)
        a.repo.name = f"bugtry-{int(pl.get('bug_id') or 0)}"
        c = named(a)
        if c is None or not buildable(c):
            return done("the component is not one this version builds in a Linux container"
                        if c is not None else "the component's project is not in the source")
        rules = load_rules()
        try:
            vf._run(["docker", "info"], 60)
        except Exception as ex:  # noqa: BLE001
            return done(f"Docker is not available: {ex}")
        if base.get("status"):                  # continued: its parent's result is where it starts
            result["before"] = {k: base.get(k) for k in ("status", "steps", "log_tail")}
            stage = "run" if base["status"] == "run-failed" else "build"
        else:
            progress("building and running it as it is")
            before = verify(a, c, rules, work / "before", None)
            result["before"] = _result_of(before)
            stage = str(((before.get("attempts") or [{}])[-1]).get("stage") or "build")
            if before.get("status") in OK:
                result.update(outcome="already-fixed", score=score_of(before.get("status")))
                return done()
        result["score"] = score_of(result["before"]["status"])
        log_tail = str(result["before"].get("log_tail") or "")
        rf._stop_if_cancelled()
        progress("asking the LLM what to change")
        kind = c.project.kind_hint if c.project.kind_hint in ai.PLAN_KEYS and c.role != "spa" else "dotnet"
        plan = make_plan(a, c, rules)
        if base.get("plan_patch"):
            from .generate import merge_plan
            merge_plan(plan, base["plan_patch"])
        listed = code_files(repo, app_root, str(pl.get("project") or "")) if code_lines else []
        schema = TRY_SCHEMA if not code_lines else {**TRY_SCHEMA, "required": ["diagnosis", "fix_json", "files"],
                                                    "properties": {**TRY_SCHEMA["properties"],
                                                                   "files": {"type": "array", "items": {"type": "string"}}}}
        answer = ask(try_prompt(a.name, c.name, kind, plan, stage, log_tail, str(pl.get("hint") or ""), listed, code_lines),
                     schema, None)
        result["llm_calls"] += 1
        try:
            fix = json.loads(answer.get("fix_json") or "{}")
        except ValueError:
            fix = {}
        fix = {k: v for k, v in fix.items() if k in ai.PLAN_KEYS[kind]} if isinstance(fix, dict) else {}
        result["llm"] = {"diagnosis": str(answer.get("diagnosis") or "")[:1500], "plan_patch": fix}
        try:
            result["llm"]["model"] = ai.model_name(None)
        except Exception:  # noqa: BLE001
            pass
        changed = 0
        want = [p for p in (answer.get("files") or []) if p in set(listed)][:code_files_allowed(code_lines)] if code_lines else []
        if want:
            rf._stop_if_cancelled()
            texts = {}
            for p in want:
                t = (app_root / p).read_text(encoding="utf-8", errors="replace")
                texts[p] = t if len(t) <= MAX_FILE_CHARS else t[:MAX_FILE_CHARS] + "\n[... the rest of the file is left out ...]"
            result["llm"]["files_read"] = want
            problem = ""
            while result["llm_calls"] < MAX_LLM_CALLS:
                progress("asking the LLM for the code change")
                ans = ask(edit_prompt(str(pl.get("hint") or ""), result["llm"]["diagnosis"], log_tail, texts, code_lines,
                                      problem), EDIT_SCHEMA, rf.SYSTEM)
                result["llm_calls"] += 1
                edits = ans.get("edits") or []
                if not edits:
                    problem = ""
                    break
                changed, problem = apply_edits(repo, app_root, edits, code_lines, set(listed))
                if not problem:
                    break
            if problem:
                result["llm"]["code_refused"] = problem[:400]
        result["code_lines_changed"] = changed
        if not fix and not changed:
            result["outcome"] = "nothing-to-try"
            return done()
        if changed:
            rf.git(["add", "-A", "."], cwd=repo, safe_dir=repo)
            result["code_patch"] = rf.git(["diff", "--cached", "HEAD"], cwd=repo, safe_dir=repo).stdout.decode(
                "utf-8", "surrogateescape")[:MAX_PATCH_CHARS]
            a = assess(app_root)
            a.repo.name = f"bugtry-{int(pl.get('bug_id') or 0)}"
            c = named(a)
            if c is None or not buildable(c):
                result["outcome"] = "worse"
                return done("with the code change the component is no longer one that is built in a Linux container")
        result["plan_patch_total"] = merge_patch(base.get("plan_patch"), fix)
        rf._stop_if_cancelled()
        progress("building and running it with the change")
        after = verify(a, c, rules, work / "after", result["plan_patch_total"] or None)
        result["after"] = _result_of(after)
        result["outcome"] = outcome_of(str(result["before"]["status"]), str(after.get("status")))
        result["score"] = score_of(after.get("status"))
        return done()
    except rf.RefactorError as ex:
        return done(str(ex))
    finally:
        if not os.environ.get("CONTAINERIZER_KEEP_REFACTOR_WORK"):
            shutil.rmtree(work, ignore_errors=True)


def stars(score: int) -> str:
    score = max(0, min(int(score or 0), 5))
    return "★" * score + "☆" * (5 - score)


def tries(conn, bug_ids=None) -> dict:
    """{BugId: [the tries of the report, oldest first]}: the hint, where the job is, and its result. `best` marks
    the try to continue from: the highest rating, then the smallest change, then the earliest."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT JobId, Status, Error, Note, Payload, Result, QueuedAt, FinishedAt, RequestedBy FROM cz.LlmJob "
                "WHERE Kind = N'bugtry' ORDER BY JobId")
    out: dict = {}
    for r in cur.fetchall():
        try:
            pl, res = json.loads(r.get("Payload") or "{}"), json.loads(r.get("Result") or "{}")
        except ValueError:
            continue
        bug = pl.get("bug_id")
        if bug is None or (bug_ids is not None and bug not in bug_ids):
            continue
        state = {"answered": "done", "failed": "failed", "skipped": "cancelled"}.get(r["Status"], r["Status"])
        t = {"id": int(r["JobId"]), "continues": pl.get("parent"), "hint": pl.get("hint") or "", "state": state,
             "code_lines_allowed": int(pl.get("code_lines") or 0),
             "asked_at": r["QueuedAt"].isoformat() if r.get("QueuedAt") else None, "asked_by": r.get("RequestedBy")}
        if r["Status"] == "answered":
            t.update({k: res.get(k) for k in ("outcome", "score", "reason", "before", "llm", "after", "plan_patch_total",
                                              "code_patch", "code_lines_changed", "llm_calls") if res.get(k) is not None})
        elif r["Status"] == "failed":
            t["error"] = r.get("Error") or ""
        out.setdefault(int(bug), []).append(t)
    for items in out.values():
        ranked = [t for t in items if t["state"] == "done" and t.get("outcome") in ("helped", "further", "not-helped", "worse")]
        if ranked:
            best = max(ranked, key=lambda t: (int(t.get("score") or 0), -len(t.get("code_patch") or ""),
                                              -len(json.dumps(t.get("plan_patch_total") or {})), -t["id"]))
            if int(best.get("score") or 0) > 0:
                best["best"] = True
    return out


def _try_form(bug_id: int, csrf: str, parent: int | None = None) -> str:
    lines = "".join(f"<option value='{n}'{' selected' if n == DEFAULT_CODE_LINES else ''}>"
                    f"{'No code changes' if not n else f'Code changes: up to {n:,} lines'}</option>" for n in CODE_LINE_CHOICES)
    ph = ("What should the LLM try next, on top of this try?" if parent else
          "What should the LLM try? For example: build on the full image and add the package libgdiplus")
    return (f"<form method='post' action='{BASE}/{int(bug_id)}/try' class='formrow'>{csrf}"
            + (f"<input type='hidden' name='Parent' value='{int(parent)}'>" if parent else "")
            + f"<textarea name='Hint' rows='2' maxlength='{MAX_HINT}' required style='min-width:520px' "
            f"aria-label='What the LLM should try' placeholder='{e(ph)}'></textarea>"
            f"<select name='CodeLines' aria-label='Code changes'>{lines}</select>"
            f"<button class='secondary'>{'Continue from this try' if parent else 'Let the LLM try'}</button></form>")


def tries_html(bug: dict, items: list[dict], csrf: str) -> str:
    """A report's tries, each under the one it continues, and the forms for the next one (the Bug reports page)."""
    from .admin_refactor import render_diff
    kids: dict = {}
    for t in items:
        kids.setdefault(t.get("continues") if any(x["id"] == t.get("continues") for x in items) else None, []).append(t)
    is_open = bug["Status"] == "open"

    def one(t: dict) -> str:
        more = ""
        if t["state"] == "done":
            oc = t.get("outcome") or "not-tried"
            cls = {"helped": "good", "already-fixed": "good", "not-helped": "bad", "worse": "bad"}.get(oc, "")
            head = (f"<span class='cb-stars' title='How far the build and run got: {int(t.get('score') or 0)} of 5'>"
                    f"{stars(t.get('score') or 0)}</span> <b class='{cls}'>{e(OUTCOME_TEXT.get(oc, oc))}</b>"
                    + (" <span class='chip'>best so far</span>" if t.get("best") else "")
                    + (f" <span class='muted'>({e(t['reason'])})</span>" if t.get("reason") else ""))
            llm = t.get("llm") or {}
            if llm:
                more += (f"<div class='small'>{e(llm.get('diagnosis') or '')}</div>"
                         + (f"<pre class='code'>{e(json.dumps(llm.get('plan_patch'), indent=1))}</pre>" if llm.get("plan_patch") else "")
                         + (f"<div class='small muted'>Code change not applied: {e(llm['code_refused'])}</div>"
                            if llm.get("code_refused") else ""))
            if t.get("code_patch"):
                n = int(t.get("code_lines_changed") or 0)
                more += (f"<details><summary class='small'>The code change so far ({n} line{'s' if n != 1 else ''} in this try) · "
                         f"<a href='{BASE}/try/{int(t['id'])}.patch'>Download .patch</a></summary>{render_diff(t['code_patch'], 600)}</details>")
            if (t.get("after") or {}).get("log_tail"):
                more += f"<details><summary class='small'>The log with the change</summary><pre class='code'>{e(t['after']['log_tail'])}</pre></details>"
            if is_open and oc not in ("not-tried", "already-fixed"):
                more += f"<details><summary class='small'>Continue from this try</summary>{_try_form(bug['BugId'], csrf, t['id'])}</details>"
        else:
            head = {"queued": "Waiting in the LLM queue", "approval": "Waiting for approval on the LLM queue page",
                    "running": "Running", "failed": "Failed", "cancelled": "Cancelled"}.get(t["state"], t["state"])
            head = f"<b>{e(head)}</b>" + (f" <span class='muted'>{e(t.get('error') or '')}</span>" if t.get("error") else "")
        code = f" <span class='muted small'>· code up to {t['code_lines_allowed']} lines</span>" if t.get("code_lines_allowed") else ""
        sub = "".join(one(k) for k in kids.get(t["id"], []))
        return (f"<li id='try{int(t['id'])}'><span class='small muted'><a href='/admin/llm-queue/{int(t['id'])}'>#{int(t['id'])}</a></span> "
                f"“{e(t['hint'])}”{code}<br>{head}{more}" + (f"<ul class='checks'>{sub}</ul>" if sub else "") + "</li>")
    rows = "".join(one(t) for t in kids.get(None, []))
    form = _try_form(bug["BugId"], csrf) if is_open else ""
    if not rows and not form:
        return ""
    return (f"<section class='diff' id='tries{int(bug['BugId'])}' style='padding:10px 14px'><b>#{int(bug['BugId'])} {e(bug['App'])} / {e(bug['Component'])}</b>"
            + (f"<ul class='checks'>{rows}</ul>" if rows else "")
            + (f"<p class='small muted' style='margin:8px 0 2px'>A new try from the flagged commit:</p>{form}" if form else "")
            + "</section>")


# --------------------------------------------------------------------------- the export

def keywords_text(conn) -> str:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT Keywords FROM cz.BugReportSettings WHERE Id = 1")
    rows = cur.fetchall()
    return (rows[0]["Keywords"] or "") if rows else ""


def export(conn, ids: list[int] | None = None, rand=None, now: datetime | None = None, view: str = "open",
           label: str = "") -> dict:
    """The open reports (or those of another view, with a label, or the ones named) as the export's JSON value,
    anonymized with the stored keywords."""
    from . import __version__
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT BugId, Status, Note, Labels, CreatedAt, DataGz FROM cz.BugReport "
                + ("WHERE BugId IN (" + ",".join(str(int(i)) for i in ids) + ")" if ids else "")
                + " ORDER BY BugId")
    bugs = []
    for r in cur.fetchall():
        labels = split_labels(r.get("Labels"))
        if not ids and (r["Status"] not in VIEWS.get(view, VIEWS["open"])[1]
                        or (label and label.casefold() not in {x.casefold() for x in labels})):
            continue
        try:
            case = json.loads(gzip.decompress(bytes(r["DataGz"])).decode("utf-8"))
        except (OSError, EOFError, ValueError, TypeError):
            continue
        bugs.append({"id": int(r["BugId"]), "status": r["Status"],
                     "flagged_at": r["CreatedAt"].isoformat() if r.get("CreatedAt") else None,
                     "labels": labels, "note": r.get("Note") or "", **case, "tries": []})
    try:                                    # what the LLM was asked to try, and whether it helped
        done = tries(conn, {b["id"] for b in bugs})
        for b in bugs:
            b["tries"] = [{k: v for k, v in t.items() if k != "asked_by"} for t in done.get(b["id"], [])]
    except Exception:  # noqa: BLE001      no LLM queue in this database
        pass
    keywords = parse_keywords(keywords_text(conn))
    replace, counts = anonymizer(keywords, rand)
    bugs = anonymize(bugs, replace)
    from . import llmprompts
    replaced = anonymize({name: o["text"] for name, o in llmprompts.load(conn).items()}, replace)
    return {"format": "containerizer-bug-reports/1", "containerizer": __version__,
            "exported_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anonymized": {"keywords": len(keywords), "replacements": counts["n"],
                           "how": "each keyword is replaced by one random word, the same within this file"},
            "replaced_system_prompts": replaced, "reports": bugs}


# --------------------------------------------------------------------------- the pages

def _when(d) -> str:
    return d.strftime("%Y-%m-%d %H:%M") + " UTC" if d else ""


def show(adm, conn, s, a, q: dict | None = None) -> "Response":  # noqa: F821
    from urllib.parse import urlencode
    from .admin import Response
    from .webui import VERIFY_TEXT
    q = q or {}
    flash = q.get("msg", [""])[0][:200]
    view = q.get("view", ["open"])[0]
    view = view if view in VIEWS else "open"
    label = " ".join(q.get("label", [""])[0].split())[:30]
    cur = conn.cursor(as_dict=True)
    try:
        if auto_resolve(conn):
            conn.commit()
    except Exception as ex:  # noqa: BLE001      no sandbox checks or no LLM queue in this database: nothing settles by itself
        conn.rollback()
        print(f"bug reports, resolving automatically: {type(ex).__name__}: {ex}", file=sys.stderr)
    try:
        cur.execute("SELECT BugId, ApplicationId, ComponentId, App, Component, VerifyStatus, Status, StatusNote, Note, Labels, "
                    "CreatedBy, CreatedAt, ExportedAt, DATALENGTH(DataGz) AS Bytes FROM cz.BugReport ORDER BY BugId DESC")
        every = cur.fetchall()
        kw = keywords_text(conn)
    except Exception as ex:  # noqa: BLE001      a database from before schema 65
        print(f"bug reports: {type(ex).__name__}: {ex}", file=sys.stderr)
        return Response(200, adm._shell(s, a, "Bug reports", "bugs", f"<p class='note'>{e(NOTICES['unavailable'][1])}</p>"))
    csrf = adm._csrf(s)

    def has(r, lab: str) -> bool:
        return not lab or lab.casefold() in {x.casefold() for x in split_labels(r.get("Labels"))}
    in_view = [r for r in every if r["Status"] in VIEWS[view][1]]
    rows = [r for r in in_view if has(r, label)]
    try:
        done = tries(conn, {int(r["BugId"]) for r in every})
    except Exception:  # noqa: BLE001      no LLM queue in this database
        done = {}
    here = lambda **kw_: BASE + (("?" + urlencode({k: v for k, v in kw_.items() if v and (k, v) != ("view", "open")}))  # noqa: E731
                                 if any(v and (k, v) != ("view", "open") for k, v in kw_.items()) else "")
    back = f"<input type='hidden' name='Back' value='{e(here(view=view, label=label))}'>"
    body = ["<p class='lead'>Builds and runs that failed in a way that looks like a fault of Containerizer itself, flagged "
            "on the applications' pages. Export them as one JSON file and give it to whoever maintains Containerizer: it "
            "holds each case's Dockerfile, build command, logs and findings, not the source code.</p>"]
    views = " ".join(f"<a class='chip{' on' if k == view else ''}' href='{e(here(view=k, label=label))}'>{e(t)} "
                     f"({sum(1 for r in every if r['Status'] in st and has(r, label))})</a>" for k, (t, st) in VIEWS.items())
    counts: dict = {}
    for r in in_view:
        for x in split_labels(r.get("Labels")):
            counts[x] = counts.get(x, 0) + 1
    labels = " ".join(f"<a class='chip{' on' if x.casefold() == label.casefold() else ''}' "
                      f"href='{e(here(view=view, label='' if x.casefold() == label.casefold() else x))}'>{e(x)} ({n})</a>"
                      for x, n in sorted(counts.items(), key=lambda kv: kv[0].casefold()))
    body.append(f"<p class='chips'>{views}</p>" + (f"<p class='chips small'><span class='label'>Labels</span> {labels}</p>"
                                                   if labels else ""))
    open_n = len(rows)
    if rows:
        trs = []
        for r in rows:
            bid = int(r["BugId"])
            app = (f"<a href='/app/{int(r['ApplicationId'])}#c{int(r['ComponentId'] or 0)}'>{e(r['App'])}</a>"
                   if r.get("ApplicationId") else e(r["App"]))

            def act(what: str, text: str, cls: str = "link") -> str:
                return (f"<form method='post' action='{BASE}/{bid}/{what}' class='inline'>{csrf}{back}"
                        f"<button class='{cls}'>{text}</button></form>")
            acts = ([act("resolve", "Resolved"), act("close", "Close")] if r["Status"] == "open" else [act("reopen", "Reopen")])
            acts.append(f"<a href='{BASE}/export.json?id={bid}'>JSON</a>")
            if bid not in done:
                acts.append(act("remove", "Remove", "link danger"))
            mine = split_labels(r.get("Labels"))
            lab = (" ".join(f"<a class='chip' href='{e(here(view=view, label=x))}'>{e(x)}</a>" for x in mine)
                   + f"<form method='post' action='{BASE}/{bid}/labels' class='inline'>{csrf}{back}"
                   f"<input name='Labels' value='{e(', '.join(mine))}' maxlength='300' size='22' placeholder='labels, comma-separated' "
                   f"aria-label='Labels of report {bid}'> <button class='link'>Save</button></form>")
            n_tries = len(done.get(bid, []))
            trs.append(f"<tr id='bug{bid}'><td>#{bid}</td><td>{app} / {e(r['Component'])}"
                       + (f"<br><a class='small' href='#tries{bid}'>{n_tries} tr{'ies' if n_tries != 1 else 'y'}</a>" if n_tries else "")
                       + f"</td><td>{e(VERIFY_TEXT.get(r['VerifyStatus'], r['VerifyStatus'] or ''))}</td>"
                       f"<td class='small'>{e(r.get('Note') or '')}<div>{lab}</div></td>"
                       f"<td class='small'>{e(r.get('CreatedBy') or '')}<br><span class='muted'>{_when(r.get('CreatedAt'))}</span></td>"
                       f"<td>{e(r['Status'])}"
                       + (f"<br><span class='muted small'>{e(r['StatusNote'])}</span>" if r.get("StatusNote") else "")
                       + (f"<br><span class='muted small'>exported {_when(r['ExportedAt'])}</span>" if r.get("ExportedAt") else "")
                       + f"</td><td class='small nowrap'>{' · '.join(acts)}</td></tr>")
        body.append("<table><thead><tr><th></th><th>Application / component</th><th>Failed</th><th>Note and labels</th>"
                    f"<th>Flagged by</th><th>Status</th><th></th></tr></thead><tbody>{''.join(trs)}</tbody></table>")
    elif every:
        body.append(f"<p class='muted'>No {'report' if view == 'all' else VIEWS[view][0].lower() + ' report'}"
                    + (f" with the label “{e(label)}”" if label else "") + ".</p>")
    else:
        body.append("<p class='muted'>Nothing is flagged. On an application's page, a component whose build or run failed "
                    "has <b>Flag as a Containerizer bug</b> in its <i>Build and run</i> block.</p>")
    blocks = "".join(tries_html(r, done.get(int(r["BugId"]), []), csrf) for r in rows)
    if blocks:
        body.append("<h2 id='tries'>Let the LLM try</h2><p class='small'>Write what to try for a report. The LLM queue builds "
                    "and runs the component, asks the LLM for a change that follows your words, and builds and runs it again "
                    "with that change. The change is to the build plan (base image, packages, environment, writable "
                    f"folders, build arguments) and, when you allow it, to the application's code: as many lines as you choose (50 unless "
                    f"you change it, at most {MAX_CODE_LINES:,}) in up to {MAX_CODE_FILES} files per try, and at most {MAX_LLM_CALLS} LLM calls. Every try is kept. The "
                    "stars say how far the build and run got (★ the build fails, ★★ it builds and the run fails, ★★★★★ it "
                    "builds and runs), and <b>best so far</b> marks the try to go on from; <i>Continue from this try</i> "
                    "starts the next one from any try's changes, not only the latest. A report with tries cannot be "
                    "removed, only closed.</p>" + blocks)
    n = len(parse_keywords(kw))
    body.append("<h2 id='export'>Export</h2>"
                + (f"<p><a class='button' href='{e(BASE + '/export.json' + here(view=view, label=label)[len(BASE):])}' download>"
                   f"Export JSON</a> <span class='muted small'>the {open_n} report{'s' if open_n != 1 else ''} shown above"
                   f", with {n} keyword{'s' if n != 1 else ''} replaced</span></p>" if open_n
                   else "<p class='muted'>No report to export in this view.</p>"))
    body.append("<h2 id='keywords'>Anonymization keywords</h2><p class='small'>One per line: company, product, project, "
                "host and people's names, anything the export must not carry. Each is replaced everywhere in the export "
                "(logs, paths, Dockerfiles, names, your notes) by a random word, the same word for the same keyword within "
                "one file, whatever its case. Application and component names are replaced only when they are listed here. "
                "Open the file before you send it: a name that is not listed stays.</p>"
                f"<form method='post' action='{BASE}/keywords'>{csrf}<textarea name='Keywords' rows='8' maxlength='20000' "
                f"spellcheck='false' aria-label='Anonymization keywords' placeholder='contoso&#10;expense-claims&#10;build01'>"
                f"{e(kw)}</textarea><p><button>Save keywords</button></p></form>")
    from . import llmprompts
    body.append(llmprompts.section_html(conn, csrf, BASE))
    return Response(200, adm._shell(s, a, "Bug reports", "bugs", "".join(body), flash))


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict):
    from .admin import Response, page, redirect
    if not a.admin:
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Only administrators handle bug reports.</p>"))
    nf = Response(404, page("Not found", "<h1>Not found</h1>"))
    if len(parts) == 1 and method == "GET":
        return show(adm, conn, s, a, q)
    if len(parts) == 2 and parts[1] == "export.json" and method == "GET":
        raw = (q.get("id") or [""])[0]
        ids = [int(raw)] if re.fullmatch(r"\d{1,9}", raw) else None
        data = export(conn, ids, view=q.get("view", ["open"])[0], label=" ".join(q.get("label", [""])[0].split())[:30])
        got = [int(b["id"]) for b in data["reports"]]
        if got:
            cur = conn.cursor()
            cur.execute("UPDATE cz.BugReport SET ExportedAt = SYSUTCDATETIME() WHERE BugId IN ("
                        + ",".join(str(i) for i in got) + ")")
            conn.commit()
        name = f"containerizer-bug-reports-{datetime.now(timezone.utc):%Y%m%d-%H%M}.json"
        return Response(200, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"),
                        [("Content-Disposition", f'attachment; filename="{name}"'), ("X-Content-Type-Options", "nosniff")],
                        ctype="application/json; charset=utf-8")
    m = re.fullmatch(r"(\d{1,9})\.patch", parts[2]) if len(parts) == 3 and parts[1] == "try" and method == "GET" else None
    if m:
        got = _job_try(conn, int(m[1]))
        if got is None or not got[1].get("code_patch"):
            return nf
        return Response(200, got[1]["code_patch"].encode("utf-8", "surrogateescape"),
                        [("Content-Disposition", f'attachment; filename="containerizer-bug-try-{int(m[1])}.patch"'),
                         ("X-Content-Type-Options", "nosniff")], ctype="text/x-diff; charset=utf-8")
    if method != "POST":
        return nf
    if len(parts) == 3 and parts[1] == "prompts":
        from . import llmprompts
        try:
            text = "" if form.get("Reset", [""])[0] == "1" else form.get("Text", [""])[0]
            got = llmprompts.save(conn, parts[2], text, s.user)
            conn.commit()
        except Exception as ex:  # noqa: BLE001      a database from before schema 65
            conn.rollback()
            print(f"system prompt {parts[2]}: {type(ex).__name__}: {ex}", file=sys.stderr)
            got = "bad"
        if got == "bad":
            return nf
        msg = "Saved:+used+from+the+next+scan+or+queue+job." if got == "saved" else "The+built-in+text+is+used+again."
        return redirect(f"{BASE}?msg={msg}#prompt-{parts[2]}")
    if len(parts) == 2 and parts[1] == "keywords":
        text = "\n".join(parse_keywords(form.get("Keywords", [""])[0]))
        cur = conn.cursor()
        cur.execute("UPDATE cz.BugReportSettings SET Keywords = %s WHERE Id = 1", (text,))
        if not cur.rowcount:
            cur.execute("INSERT cz.BugReportSettings (Id, Keywords) VALUES (1, %s)", (text,))
        conn.commit()
        return redirect(f"{BASE}?msg=Keywords+saved.#keywords")
    if len(parts) == 3 and parts[1] in ("flag", "unflag") and re.fullmatch(r"\d{1,9}", parts[2]):
        cid = int(parts[2])
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT ApplicationId FROM cz.vComponentLatest WHERE ComponentId = %s", (cid,))
        rows = cur.fetchall()
        if not rows:
            return nf
        back = lambda code: redirect(f"/app/{int(rows[0]['ApplicationId'])}?bug={code}#c{cid}")  # noqa: E731
        try:
            if parts[1] == "flag":
                bug = flag(conn, cid, form.get("Note", [""])[0], s.user)
                conn.commit()
                return back("flagged" if bug else "nothing")
            retire(conn, cid)
            conn.commit()
            return back("unflagged")
        except Exception as ex:  # noqa: BLE001      a database from before schema 65
            conn.rollback()
            print(f"bug report of component {cid}: {type(ex).__name__}: {ex}", file=sys.stderr)
            return back("unavailable")
    if len(parts) == 3 and re.fullmatch(r"\d{1,9}", parts[1]) and parts[2] == "try":
        from urllib.parse import quote
        try:
            parent, lines = form.get("Parent", [""])[0], form.get("CodeLines", ["0"])[0]
            jid, why = queue_try(conn, int(parts[1]), form.get("Hint", [""])[0],
                                 int(parent) if re.fullmatch(r"\d{1,9}", parent) else None,
                                 int(lines) if re.fullmatch(r"\d{1,3}", lines) else 0)
            conn.commit()
        except Exception as ex:  # noqa: BLE001
            conn.rollback()
            print(f"bug report try {parts[1]}: {type(ex).__name__}: {ex}", file=sys.stderr)
            jid, why = None, "The LLM queue could not take it."
        msg = why or ("Queued: the LLM queue page shows how far it is." if jid else "The same try already waits.")
        return redirect(f"{BASE}?msg={quote(msg)}#tries")
    if len(parts) == 3 and re.fullmatch(r"\d{1,9}", parts[1]) and parts[2] in ("resolve", "close", "reopen", "remove", "labels"):
        from urllib.parse import quote
        bid = int(parts[1])
        target = form.get("Back", [""])[0]
        target = target if target == BASE or target.startswith(BASE + "?") else BASE      # this page only
        say = lambda text: redirect(target + ("&" if "?" in target else "?") + "msg=" + quote(text))  # noqa: E731
        cur = conn.cursor()
        if parts[2] == "labels":
            labels, why = parse_labels(form.get("Labels", [""])[0])
            if labels is None:
                return say(why)
            cur.execute("UPDATE cz.BugReport SET Labels = %s WHERE BugId = %s", (",".join(labels) or None, bid))
            conn.commit()
            return say("Labels saved.")
        if parts[2] == "remove" and tried(conn, [bid]):
            return say("A report with tries is kept: close it instead.")
        if parts[2] == "remove":
            cur.execute("DELETE FROM cz.BugReport WHERE BugId = %s", (bid,))
        else:
            # a status a person set is not changed automatically later (auto_resolve)
            cur.execute("UPDATE cz.BugReport SET Status = %s, StatusNote = %s WHERE BugId = %s",
                        ({"resolve": "resolved", "close": "closed", "reopen": "open"}[parts[2]],
                         f"{'reopened' if parts[2] == 'reopen' else 'set'} by {s.user}"[:300], bid))
        conn.commit()
        return say({"resolve": "Marked resolved.", "close": "Closed.", "reopen": "Reopened.", "remove": "Removed."}[parts[2]])
    return nf
