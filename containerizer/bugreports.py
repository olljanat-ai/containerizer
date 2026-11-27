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
NOTICES = {"flagged": ("ok", "Flagged as a suspected Containerizer bug: it is on Admin → Bug reports."),
           "unflagged": ("ok", "The flag was removed."),
           "nothing": ("bad", "This component has no failed build or run in its latest scan."),
           "unavailable": ("bad", "Bug reports need the database of version 0.54.9 or later.")}
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
                     "note": r.get("Note") or "", **case})
    keywords = parse_keywords(keywords_text(conn))
    replace, counts = anonymizer(keywords, rand)
    bugs = anonymize(bugs, replace)
    return {"format": "containerizer-bug-reports/1", "containerizer": __version__,
            "exported_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anonymized": {"keywords": len(keywords), "replacements": counts["n"],
                           "how": "each keyword is replaced by one random word, the same within this file"},
            "reports": bugs}


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
