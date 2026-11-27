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
OUTCOME_TEXT = {"helped": "Helped: it builds and runs with the change",
                "further": "Got further: it builds with the change, the run still fails",
                "not-helped": "Did not help: it fails with the change too",
                "already-fixed": "Already fixed: it builds and runs with this version, without a change",
                "nothing-to-try": "Nothing to try: the LLM found no build-plan change for it",
                "not-tried": "Not tried"}
TRY_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["diagnosis", "fix_json"],
              "properties": {"diagnosis": {"type": "string", "description": "what fails and what the change does, two sentences"},
                             "fix_json": {"type": "string", "description": "JSON object: the build-plan patch, or {} when no key can do it"}}}
NOTICES = {"flagged": ("ok", "Flagged as a suspected Containerizer bug: it is on Admin → Bug reports."),
           "unflagged": ("ok", "The flag was removed."),
           "nothing": ("bad", "This component has no failed build or run in its latest scan."),
           "unavailable": ("bad", "Bug reports need the database of version 0.54.7 or later.")}
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
                "aa.Rating, aa.ToolVersion, aa.SourceCommit, aa.AssessedAt FROM cz.vComponentLatest c "
                "JOIN cz.ApplicationAssessment aa ON aa.AssessmentId = c.AssessmentId WHERE c.ComponentId = %s",
                (int(component_id),))
    rows = cur.fetchall()
    if not rows or rows[0].get("VerifyStatus") not in VERIFY_FAILED:
        return None
    r = rows[0]
    cur.execute("SELECT RuleId, Severity, Title, Evidence FROM cz.Finding WHERE AssessmentId = %s AND ComponentId = %s "
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
            "case": {"containerizer": __version__, "scanned_with": r.get("ToolVersion"),
                     "scanned_at": r["AssessedAt"].isoformat() if r.get("AssessedAt") else None,
                     "application": r["ApplicationName"], "rating": r.get("Rating"),
                     "commit": (r.get("SourceCommit") or "")[:12] or None,
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
    cur = conn.cursor()
    cur.execute("DELETE FROM cz.BugReport WHERE ComponentId = %s AND Status = N'open'", (got["component_id"],))
    cur.execute("INSERT cz.BugReport (ApplicationId, ComponentId, AssessmentId, App, Component, VerifyStatus, Note, CreatedBy, "
                "DataGz) OUTPUT inserted.BugId VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (got["application_id"], got["component_id"], got["assessment_id"], case["application"][:200],
                 case["component"]["name"][:200], case["verification"]["status"][:40], (note or "").strip()[:MAX_NOTE] or None,
                 (user or "")[:200], data))
    row = cur.fetchone()
    return int(row[0] if not isinstance(row, dict) else row["BugId"])


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

def queue_try(conn, bug_id: int, hint: str) -> tuple[int | None, str]:
    """Queue a try for a report: (job id or 0 when the same one waits, "") or (None, why not)."""
    import hashlib
    from .admin_refactor import order_source
    from .llmqueue import SqlJobQueue
    hint = (hint or "").strip()[:MAX_HINT]
    if not hint:
        return None, "Write what the LLM should try."
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT b.BugId, b.ApplicationId, b.AssessmentId, b.App, b.Component, b.DataGz, a.RepositoryUrl, a.SourcePath, "
                "a.SourceKey, aa.SourceCommit FROM cz.BugReport b JOIN cz.Application a ON a.ApplicationId = b.ApplicationId "
                "LEFT JOIN cz.ApplicationAssessment aa ON aa.AssessmentId = b.AssessmentId WHERE b.BugId = %s", (int(bug_id),))
    rows = cur.fetchall()
    if not rows:
        return None, "The report's application is no longer there."
    r = rows[0]
    source = order_source(conn, {"RepositoryUrl": r.get("RepositoryUrl"), "SourcePath": r.get("SourcePath")})
    if source is None or not r.get("SourceCommit"):
        return None, ("No organization scan on this machine has the application's source at the flagged commit: "
                      "scan it again and flag it again.")
    try:
        case = json.loads(gzip.decompress(bytes(r["DataGz"])).decode("utf-8"))
    except (OSError, EOFError, ValueError, TypeError):
        return None, "The report cannot be read."
    project = (case.get("component") or {}).get("project")
    payload = {"bug_id": int(r["BugId"]), "app": r["App"], "application_id": r["ApplicationId"], "component": r["Component"],
               "project": project, "source": source, "commit": r["SourceCommit"], "hint": hint,
               "flagged_status": (case.get("verification") or {}).get("status")}
    key = hashlib.sha256(f"{r['BugId']}|{hint}".encode()).hexdigest()
    job = {"Kind": KIND, "Reason": None, "App": r["App"], "Repository": r["App"], "SourceKey": r.get("SourceKey"),
           "ApplicationId": r["ApplicationId"], "AssessmentId": r["AssessmentId"], "Component": r["Component"],
           "ProjectPath": project, "RuleVerdict": None, "Priority": PRIORITY, "DedupeKey": key, "Model": None,
           "RequestedBy": None, "InputChars": 12000 + len(hint), "Payload": payload}
    return SqlJobQueue(None).add_with(conn, job), ""


def try_prompt(app: str, component: str, kind: str, plan: dict, stage: str, log_tail: str, hint: str) -> str:
    from .ai import PLAN_HELP, PLAN_RULES
    return (f"A generated container for {app}/{component} failed at the {stage} stage.\n\nBuild plan:\n"
            f"{json.dumps({k: v for k, v in plan.items() if k not in ('applied', 'reasons')}, indent=1, default=str)[:6000]}\n\n"
            f"{PLAN_HELP.get(kind, PLAN_HELP['dotnet'])}\n{PLAN_RULES}\n\nLog tail:\n{log_tail[-8000:]}\n\n"
            f"An administrator suggests what to try:\n{hint}\n\nGive the build-plan patch that carries out the suggestion "
            "(only the keys above; {} when none of them can do it), and say in the diagnosis what fails and what the "
            "patch does.")


def _result_of(r: dict) -> dict:
    """What a verification left, for the report: the status, the steps and the end of the last log."""
    last = (r.get("attempts") or [{}])[-1]
    return {"status": r.get("status"), "steps": "; ".join(f"{h.get('stage')} {h.get('rule') or h.get('status')}"
                                                        for h in r.get("attempts") or [])[:600],
            "log_tail": "" if r.get("status") in OK else str(last.get("log_tail") or "")[-3000:]}


def outcome_of(before: str, after: str | None) -> str:
    if before in OK:
        return "already-fixed"
    if after is None:
        return "nothing-to-try"
    if after in OK:
        return "helped"
    return "further" if before == "build-failed" and after != "build-failed" else "not-helped"


def try_handler(job: dict, ask=None, verify=None) -> dict:
    """The LLM queue's handler of `bugtry` jobs: build and run the component as it is; if it still fails, ask the LLM
    for a build-plan patch that follows the administrator's hint and build and run with it. `ask(prompt, schema)` and
    `verify(a, c, rules, work, plan_patch)` are replaced in tests."""
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
    ask = ask or (lambda prompt, schema: ai.ask_json(prompt, schema, feature="bugtry-queued",
                                                     max_tokens=ai.SHORT_ANSWER_TOKENS))
    verify = verify or (lambda a, c, rules, work, patch: vf.verify_component(a, c, rules, work=work, plan_patch=patch))
    base = Path(os.environ.get(rf.WORK_ENV) or tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"bugtry-{int(job.get('JobId') or 0)}-", dir=base))
    result = {"bug_id": pl.get("bug_id"), "hint": pl.get("hint"), "flagged_status": pl.get("flagged_status"),
              "outcome": "not-tried"}

    def done(reason: str = "") -> dict:
        if reason:
            result["reason"] = reason[:600]
        text = OUTCOME_TEXT[result["outcome"]] + (f" ({reason})" if reason and result["outcome"] == "not-tried" else "")
        return {"result": result, "summary": text[:400], "note": None}
    try:
        progress("preparing the source")
        repo, app_root = rf.checkout(pl["source"], pl.get("commit"), work / "src")
        a = assess(app_root)
        a.repo.name = f"bugtry-{int(pl.get('bug_id') or 0)}"
        c = next((x for x in a.components if x.project.rel == pl.get("project")), None)
        if c is None or not buildable(c):
            return done("the component is not one this version builds in a Linux container"
                        if c is not None else "the component's project is not in the source")
        rules = load_rules()
        try:
            vf._run(["docker", "info"], 60)
        except Exception as ex:  # noqa: BLE001
            return done(f"Docker is not available: {ex}")
        progress("building and running it as it is")
        before = verify(a, c, rules, work / "before", None)
        result["before"] = _result_of(before)
        if before.get("status") in OK:
            result["outcome"] = "already-fixed"
            return done()
        rf._stop_if_cancelled()
        progress("asking the LLM what to change")
        kind = c.project.kind_hint if c.project.kind_hint in ai.PLAN_KEYS and c.role != "spa" else "dotnet"
        last = (before.get("attempts") or [{}])[-1]
        answer = ask(try_prompt(a.name, c.name, kind, make_plan(a, c, rules), str(last.get("stage") or "build"),
                                str(last.get("log_tail") or ""), str(pl.get("hint") or "")), TRY_SCHEMA)
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
        if not fix:
            result["outcome"] = "nothing-to-try"
            return done()
        rf._stop_if_cancelled()
        progress("building and running it with the change")
        after = verify(a, c, rules, work / "after", fix)
        result["after"] = _result_of(after)
        result["outcome"] = outcome_of(str(before.get("status")), str(after.get("status")))
        return done()
    except rf.RefactorError as ex:
        return done(str(ex))
    finally:
        if not os.environ.get("CONTAINERIZER_KEEP_REFACTOR_WORK"):
            shutil.rmtree(work, ignore_errors=True)


def tries(conn, bug_ids=None) -> dict:
    """{BugId: [the tries of the report, oldest first]}: the hint, where the job is, and its result."""
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
        t = {"job": int(r["JobId"]), "hint": pl.get("hint") or "", "state": state,
             "asked_at": r["QueuedAt"].isoformat() if r.get("QueuedAt") else None, "asked_by": r.get("RequestedBy")}
        if r["Status"] == "answered":
            t.update({k: res.get(k) for k in ("outcome", "reason", "before", "llm", "after") if res.get(k) is not None})
        elif r["Status"] == "failed":
            t["error"] = r.get("Error") or ""
        out.setdefault(int(bug), []).append(t)
    return out


def tries_html(bug: dict, items: list[dict], csrf: str) -> str:
    """A report's tries and the form for the next one (the Bug reports page)."""
    rows = []
    for t in items:
        if t["state"] == "done":
            oc = t.get("outcome") or "not-tried"
            cls = {"helped": "good", "already-fixed": "good", "not-helped": "bad"}.get(oc, "")
            head = (f"<b class='{cls}'>{e(OUTCOME_TEXT.get(oc, oc))}</b>"
                    + (f" <span class='muted'>({e(t['reason'])})</span>" if t.get("reason") else ""))
            llm = t.get("llm") or {}
            more = ""
            if llm:
                more += (f"<div class='small'>{e(llm.get('diagnosis') or '')}</div>"
                         + (f"<pre class='code'>{e(json.dumps(llm.get('plan_patch'), indent=1))}</pre>" if llm.get("plan_patch") else ""))
            if (t.get("after") or {}).get("log_tail"):
                more += f"<details><summary class='small'>The log with the change</summary><pre class='code'>{e(t['after']['log_tail'])}</pre></details>"
        else:
            head = {"queued": "Waiting in the LLM queue", "approval": "Waiting for approval on the LLM queue page",
                    "running": "Running", "failed": "Failed", "cancelled": "Cancelled"}.get(t["state"], t["state"])
            head = f"<b>{e(head)}</b>" + (f" <span class='muted'>{e(t.get('error') or '')}</span>" if t.get("error") else "")
            more = ""
        rows.append(f"<li><span class='small muted'><a href='/admin/llm-queue/{int(t['job'])}'>#{int(t['job'])}</a></span> "
                    f"“{e(t['hint'])}”<br>{head}{more}</li>")
    form = (f"<form method='post' action='{BASE}/{int(bug['BugId'])}/try' class='formrow'>{csrf}"
            "<textarea name='Hint' rows='2' maxlength='2000' required style='min-width:520px' aria-label='What the LLM should try' "
            "placeholder='What should the LLM try? For example: build on the full image and add the package libgdiplus'></textarea>"
            "<button class='secondary'>Let the LLM try</button></form>") if bug["Status"] == "open" else ""
    if not rows and not form:
        return ""
    return (f"<section class='diff' style='padding:10px 14px'><b>#{int(bug['BugId'])} {e(bug['App'])} / {e(bug['Component'])}</b>"
            + (f"<ul class='checks'>{''.join(rows)}</ul>" if rows else "") + form + "</section>")


# --------------------------------------------------------------------------- the export

def keywords_text(conn) -> str:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT Keywords FROM cz.BugReportSettings WHERE Id = 1")
    rows = cur.fetchall()
    return (rows[0]["Keywords"] or "") if rows else ""


def export(conn, ids: list[int] | None = None, rand=None, now: datetime | None = None) -> dict:
    """The open reports (or the ones named) as the export's JSON value, anonymized with the stored keywords."""
    from . import __version__
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT BugId, Status, Note, CreatedAt, DataGz FROM cz.BugReport "
                + ("WHERE BugId IN (" + ",".join(str(int(i)) for i in ids) + ")" if ids else "WHERE Status = N'open'")
                + " ORDER BY BugId")
    bugs = []
    for r in cur.fetchall():
        try:
            case = json.loads(gzip.decompress(bytes(r["DataGz"])).decode("utf-8"))
        except (OSError, EOFError, ValueError, TypeError):
            continue
        bugs.append({"id": int(r["BugId"]), "status": r["Status"],
                     "flagged_at": r["CreatedAt"].isoformat() if r.get("CreatedAt") else None,
                     "note": r.get("Note") or "", **case, "tries": []})
    try:                                    # what the LLM was asked to try, and whether it helped
        done = tries(conn, {b["id"] for b in bugs})
        for b in bugs:
            b["tries"] = [{k: v for k, v in t.items() if k not in ("job", "asked_by")} for t in done.get(b["id"], [])]
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


def show(adm, conn, s, a, flash: str = "") -> "Response":  # noqa: F821
    from .admin import Response
    from .webui import VERIFY_TEXT
    cur = conn.cursor(as_dict=True)
    try:
        cur.execute("SELECT BugId, ApplicationId, ComponentId, App, Component, VerifyStatus, Status, Note, CreatedBy, CreatedAt, "
                    "ExportedAt, DATALENGTH(DataGz) AS Bytes FROM cz.BugReport ORDER BY CASE Status WHEN N'open' THEN 0 ELSE 1 END, "
                    "BugId DESC")
        rows = cur.fetchall()
        kw = keywords_text(conn)
    except Exception as ex:  # noqa: BLE001      a database from before schema 65
        print(f"bug reports: {type(ex).__name__}: {ex}", file=sys.stderr)
        return Response(200, adm._shell(s, a, "Bug reports", "bugs", f"<p class='note'>{e(NOTICES['unavailable'][1])}</p>"))
    csrf = adm._csrf(s)
    body = ["<p class='lead'>Builds and runs that failed in a way that looks like a fault of Containerizer itself, flagged "
            "on the applications' pages. Export them as one JSON file and give it to whoever maintains Containerizer: it "
            "holds each case's Dockerfile, build command, logs and findings, not the source code.</p>"]
    open_n = sum(1 for r in rows if r["Status"] == "open")
    if rows:
        trs = []
        for r in rows:
            app = (f"<a href='/app/{int(r['ApplicationId'])}#c{int(r['ComponentId'] or 0)}'>{e(r['App'])}</a>"
                   if r.get("ApplicationId") else e(r["App"]))
            acts = (f"<form method='post' action='{BASE}/{int(r['BugId'])}/"
                    f"{'close' if r['Status'] == 'open' else 'reopen'}' class='inline'>{csrf}<button class='link'>"
                    f"{'Close' if r['Status'] == 'open' else 'Reopen'}</button></form> · "
                    f"<a href='{BASE}/export.json?id={int(r['BugId'])}'>JSON</a> · "
                    f"<form method='post' action='{BASE}/{int(r['BugId'])}/remove' class='inline'>{csrf}"
                    "<button class='link danger'>Remove</button></form>")
            trs.append(f"<tr id='bug{int(r['BugId'])}'><td>#{int(r['BugId'])}</td><td>{app} / {e(r['Component'])}</td>"
                       f"<td>{e(VERIFY_TEXT.get(r['VerifyStatus'], r['VerifyStatus'] or ''))}</td>"
                       f"<td class='small'>{e(r.get('Note') or '')}</td>"
                       f"<td class='small'>{e(r.get('CreatedBy') or '')}<br><span class='muted'>{_when(r.get('CreatedAt'))}</span></td>"
                       f"<td>{'open' if r['Status'] == 'open' else 'closed'}"
                       + (f"<br><span class='muted small'>exported {_when(r['ExportedAt'])}</span>" if r.get("ExportedAt") else "")
                       + f"</td><td class='small nowrap'>{acts}</td></tr>")
        body.append("<table><thead><tr><th></th><th>Application / component</th><th>Failed</th><th>Note</th><th>Flagged by</th>"
                    f"<th>Status</th><th></th></tr></thead><tbody>{''.join(trs)}</tbody></table>")
    else:
        body.append("<p class='muted'>Nothing is flagged. On an application's page, a component whose build or run failed "
                    "has <b>Flag as a Containerizer bug</b> in its <i>Build and run</i> block.</p>")
    try:
        done = tries(conn, {int(r["BugId"]) for r in rows})
    except Exception:  # noqa: BLE001
        done = {}
    blocks = "".join(tries_html(r, done.get(int(r["BugId"]), []), csrf) for r in rows)
    if blocks:
        body.append("<h2 id='tries'>Let the LLM try</h2><p class='small'>Write what to try for a report. The LLM queue builds "
                    "and runs the component as it is, asks the LLM for a change of the build plan (base image, packages, "
                    "environment, writable folders, build arguments; never the application's code) that follows your "
                    "words, and builds and runs it again with that change. Whether it helped is kept with the report and "
                    "goes into the export.</p>" + blocks)
    n = len(parse_keywords(kw))
    body.append("<h2 id='export'>Export</h2>"
                + (f"<p><a class='button' href='{BASE}/export.json' download>Export JSON</a> <span class='muted small'>"
                   f"the {open_n} open report{'s' if open_n != 1 else ''}, with {n} keyword{'s' if n != 1 else ''} "
                   "replaced</span></p>" if open_n else "<p class='muted'>No open report to export.</p>"))
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
        return show(adm, conn, s, a, q.get("msg", [""])[0][:200])
    if len(parts) == 2 and parts[1] == "export.json" and method == "GET":
        raw = (q.get("id") or [""])[0]
        ids = [int(raw)] if re.fullmatch(r"\d{1,9}", raw) else None
        data = export(conn, ids)
        cur = conn.cursor()
        cur.execute("UPDATE cz.BugReport SET ExportedAt = SYSUTCDATETIME() WHERE "
                    + ("BugId = %s" if ids else "Status = N'open'"), (ids[0],) if ids else None)
        conn.commit()
        name = f"containerizer-bug-reports-{datetime.now(timezone.utc):%Y%m%d-%H%M}.json"
        return Response(200, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"),
                        [("Content-Disposition", f'attachment; filename="{name}"'), ("X-Content-Type-Options", "nosniff")],
                        ctype="application/json; charset=utf-8")
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
        cur.execute("SELECT ApplicationId FROM cz.Component WHERE ComponentId = %s", (cid,))
        rows = cur.fetchall()
        if not rows:
            return nf
        back = lambda code: redirect(f"/app/{int(rows[0]['ApplicationId'])}?bug={code}#c{cid}")  # noqa: E731
        try:
            if parts[1] == "flag":
                bug = flag(conn, cid, form.get("Note", [""])[0], s.user)
                conn.commit()
                return back("flagged" if bug else "nothing")
            cur.execute("DELETE FROM cz.BugReport WHERE ComponentId = %s AND Status = N'open'", (cid,))
            conn.commit()
            return back("unflagged")
        except Exception as ex:  # noqa: BLE001      a database from before schema 65
            conn.rollback()
            print(f"bug report of component {cid}: {type(ex).__name__}: {ex}", file=sys.stderr)
            return back("unavailable")
    if len(parts) == 3 and re.fullmatch(r"\d{1,9}", parts[1]) and parts[2] == "try":
        from urllib.parse import quote
        try:
            jid, why = queue_try(conn, int(parts[1]), form.get("Hint", [""])[0])
            conn.commit()
        except Exception as ex:  # noqa: BLE001
            conn.rollback()
            print(f"bug report try {parts[1]}: {type(ex).__name__}: {ex}", file=sys.stderr)
            jid, why = None, "The LLM queue could not take it."
        msg = why or ("Queued: the LLM queue page shows how far it is." if jid else "The same try already waits.")
        return redirect(f"{BASE}?msg={quote(msg)}#tries")
    if len(parts) == 3 and re.fullmatch(r"\d{1,9}", parts[1]) and parts[2] in ("close", "reopen", "remove"):
        cur = conn.cursor()
        if parts[2] == "remove":
            cur.execute("DELETE FROM cz.BugReport WHERE BugId = %s", (int(parts[1]),))
        else:
            cur.execute("UPDATE cz.BugReport SET Status = %s WHERE BugId = %s",
                        ("closed" if parts[2] == "close" else "open", int(parts[1])))
        conn.commit()
        return redirect(f"{BASE}?msg=" + {"close": "Closed.", "reopen": "Reopened.", "remove": "Removed."}[parts[2]])
    return nf
