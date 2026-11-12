"""Web UI over the results database: business unit -> product -> application -> components.

`python -m containerizer web --sql "<reader connection string>"`. Standard library HTTP server; every
page is rendered on the server (scripts only on the admin pages) from the v* views with parameterised queries, all
text is HTML-escaped, and responses carry a strict Content-Security-Policy. The results pages are
read-only and need no sign-in; the admin pages (admin.py: mapping, products, business units, change
history) appear when OpenID Connect sign-in is configured (docs/sign-in.md).
"""
from __future__ import annotations

import html
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from .tags import AUTO_TAGS, STATEFUL, TAG_RE, has_tag, split_tags, with_auto

RATINGS = ["A", "B", "C", "D", "E"]
RATING_TITLE = {"A": "Container-ready", "B": "Minor refactoring", "C": "Partial", "D": "Major refactoring",
                "E": "Not feasible"}
RATING_TEXT = {"A": "Modern stack, containers with configuration only, no code changes", "B": "Small code changes",
               "C": "Some components must stay on Windows, the rest need at most minor changes",
               "D": "Framework port needed",
               "E": "Core depends on Windows-only technology"}
ROLE_TEXT = {"web": "Web application", "worker": "Background service", "console": "Console / scheduled job",
             "spa": "Browser front end", "desktop": "Desktop client", "biztalk": "BizTalk integration",
             "sharepoint": "SharePoint solution", "sitecore": "Sitecore site", "sqlclr": "SQL Server CLR code",
             "ssis": "SSIS package", "sqldb": "Database project"}
VERDICT_LABEL = {"info": "Ready", "config": "Ready with configuration", "refactor": "Needs code changes",
                 "rewrite": "Needs a port or rewrite", "blocker": "Cannot run in a Linux container"}
SEV_ORDER = ["blocker", "rewrite", "refactor", "config", "info"]
UNASSIGNED = "Not assigned"
e = html.escape


# ---------------------------------------------------------------------------
# data (cz_reader can read exactly these)

UPLOAD_DRAIN_MAX = 64 * 1024 * 1024     # unread rest of a refused upload read and dropped before replying


class _CountingReader:
    """Counts what an upload handler read from the request body."""

    def __init__(self, f):
        self.f, self.count = f, 0

    def read(self, n=-1):
        b = self.f.read(n)
        self.count += len(b)
        return b

    def readline(self, n=-1):
        b = self.f.readline(n)
        self.count += len(b)
        return b


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def load_overview(conn) -> dict:
    cols = ("ApplicationId, ApplicationName, ProductId, ProductName, ProductInfoUrl, BusinessUnitId, BusinessUnitName, "
            "Rating, Score, Confidence, Summary, AssessedAt, Verified")
    try:
        apps = _rows(conn, f"SELECT {cols}, Tags FROM cz.vApplicationLatest")
    except Exception:  # noqa: BLE001 - a database from before schema 37 has no tags
        try:
            conn.rollback()
        except Exception:
            pass
        apps = _rows(conn, f"SELECT {cols} FROM cz.vApplicationLatest")
    comps = _rows(conn, "SELECT ApplicationId, ComponentId, Tier, Verdict, VerifyStatus FROM cz.vComponentLatest")
    rules = sorted(state_rules())
    state_rows = _rows(conn, "SELECT DISTINCT ApplicationId, ComponentId, RuleId, Title FROM cz.vFindingLatest "
                             f"WHERE RuleId IN ({', '.join(['%s'] * len(rules))}) "
                             "AND (OnlyCommands IS NULL OR OnlyCommands = N'')", tuple(rules)) if rules else []
    top = _rows(conn, "SELECT ApplicationId, Title, Severity, COUNT(*) AS N FROM cz.vFindingLatest "
                      "WHERE Severity IN ('blocker', 'rewrite') GROUP BY ApplicationId, Title, Severity")
    unmapped = _rows(conn, "SELECT Kind, COUNT(*) AS N FROM cz.vUnmapped GROUP BY Kind")
    from .migrationplan import count_ready, ready_now, stateful
    by_app: dict = {}
    for r in comps:
        by_app.setdefault(r["ApplicationId"], []).append(r)
    state = stateful(state_rows, set(rules))
    best: dict = {}
    for r in top:
        k = (SEV_ORDER.index(r["Severity"]), -r["N"], r["Title"])
        if r["ApplicationId"] not in best or k < best[r["ApplicationId"]][0]:
            best[r["ApplicationId"]] = (k, r["Title"])
    ready = load_a_patches(conn)
    running = load_running(conn)
    for a in apps:
        a["Components"] = len(by_app.get(a["ApplicationId"], []))
        a["ReadyNow"], a["PlanComponents"] = count_ready(by_app.get(a["ApplicationId"], []), state)
        a["ReadyStateful"] = sum(1 for c in by_app.get(a["ApplicationId"], [])
                                 if c["ComponentId"] in state and ready_now(c, state))
        a["AutoTags"] = [STATEFUL] if any(c["ComponentId"] in state and (c.get("Tier") or "server") in ("server", "platform")
                                          for c in by_app.get(a["ApplicationId"], [])) else []
        a["Tags"] = with_auto(a.get("Tags"), a["AutoTags"])
        a["MainObstacle"] = best.get(a["ApplicationId"], (None, ""))[1]
        a["APatch"] = ready.get(a["ApplicationId"])
        a["Running"] = running.get(a["ApplicationId"])
    return {"apps": apps, "unmapped": {r["Kind"]: r["N"] for r in unmapped}}


RUNNING = ("healthy", "scheduled")      # a component the latest sandbox check found running (or a job waiting to run)


def load_running(conn) -> dict[int, dict]:
    """Per application, what of it runs in the sandbox by its latest check: {"n": components running, "url": the
    link to open (sandbox.main_url: a UI before an API)}. Applications without one running are left out."""
    from .sandbox import URL_RE, main_url
    try:
        rows = _rows(conn, "SELECT ApplicationId, ComponentName, Status, Url FROM cz.vSandboxLatest "
                           "WHERE Status IN (N'healthy', N'scheduled')")
    except Exception:  # noqa: BLE001 - a database without sandbox checks
        try:
            conn.rollback()
        except Exception:
            pass
        return {}
    out: dict[int, dict] = {}
    for r in rows:
        x = out.setdefault(r["ApplicationId"], {"n": 0, "comps": []})
        x["n"] += 1
        if URL_RE.fullmatch(r.get("Url") or "") and r.get("Status") == "healthy":
            x["comps"].append({"component": r.get("ComponentName") or "", "url": r["Url"]})
    return {k: {"n": v["n"], "url": main_url(v["comps"])} for k, v in out.items()}


def _open_link(url) -> str:
    from .sandbox import URL_RE
    return (f" <a href='{e(url)}' target='_blank' rel='noopener noreferrer'>Open</a>"
            if isinstance(url, str) and URL_RE.fullmatch(url) else "")


def running_html(apps: list[dict]) -> str:
    """The applications that run in the sandbox, whole or in part, by its latest check: try them there. The ones a
    "Make it A" patch runs for are in their own list (a_patches_html)."""
    rows = []
    for a in sorted(apps, key=lambda a: (a["Rating"], a["ApplicationName"].lower())):
        run = a.get("Running")
        ap = a.get("APatch") or {}
        if not run or (a.get("Rating") != "A" and ap.get("SandboxStatus") in SANDBOX_HERE):
            continue
        total = int(a.get("PlanComponents") or 0) or int(a.get("Components") or 0)
        part = f"{int(run['n'])} of {total} components" if total and run["n"] < total else "all of it"
        rows.append(f"<tr><td>{badge(a['Rating'])}</td>"
                    f"<td><a href='/app/{int(a['ApplicationId'])}#plan'>{e(a['ApplicationName'])}</a></td>"
                    f"<td><span class='st st-ok'>{e(part)}</span>{_open_link(run.get('url'))}</td></tr>")
    if not rows:
        return ""
    return ("<section class='running'><h2>Running in the sandbox</h2><p class='muted'>What of these applications runs in "
            "the sandbox now, by its latest check: the components that are ready, also where the rest of the application "
            "still needs changes. Open one to try it; the application's migration plan says what runs and what does "
            "not yet.</p><table><thead><tr><th>Rating</th><th>Application</th><th>In the sandbox</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table></section>")


# a sandbox variant's state as the front page groups it: running there, deployed without a health check, or not there
SANDBOX_HERE = ("running", "deployed")


def load_a_patches(conn) -> dict[int, dict]:
    """Per application, its best "Make it A" patch that works: verified (it builds and runs) and rated A by the
    rules (cz.vRefactorOrder), for the commit the application's latest assessment is of (a patch for older code
    no longer makes it A: a new order starts from it, admin_refactor.reusable_patch). One running in the sandbox
    comes first, then the newest. Empty before schema 23.

    Two queries, the commits compared here: joined in SQL, the commit comparison made SQL Server parse every
    order's Payload (JSON with the LLM prompts) for each pair, about 300 ms on the front page."""
    try:
        orders = _rows(conn, "SELECT ApplicationId, JobId, SandboxStatus, SandboxUrl, FinishedAt, SourceCommit "
                             "FROM cz.vRefactorOrder "
                             "WHERE Goal = N'rating-a' AND Status = N'verified' AND RatingAfter = N'A'")
        latest = {r["ApplicationId"]: r["SourceCommit"] for r in _rows(
            conn, "SELECT ApplicationId, SourceCommit FROM cz.vApplicationLatest")} if orders else {}
        rows = [{k: v for k, v in o.items() if k != "SourceCommit"} for o in orders
                if o["ApplicationId"] in latest
                and (o["SourceCommit"] is None or latest[o["ApplicationId"]] is None
                     or o["SourceCommit"] == latest[o["ApplicationId"]])]
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return {}
    best: dict[int, dict] = {}
    for r in rows:
        k = (r.get("SandboxStatus") == "running", r.get("SandboxStatus") in SANDBOX_HERE, int(r["JobId"]))
        cur = best.get(r["ApplicationId"])
        if cur is None or k > cur["_k"]:
            best[r["ApplicationId"]] = {**r, "_k": k}
    return best


def load_application(conn, app_id: int) -> dict | None:
    rows = _rows(conn, "SELECT * FROM cz.vApplicationLatest WHERE ApplicationId = %s", (app_id,))
    if not rows:
        return None
    app = rows[0]
    app["components"] = _rows(conn, "SELECT * FROM cz.vComponentLatest WHERE ApplicationId = %s "
                                    "ORDER BY ComponentName", (app_id,))
    app["findings"] = _rows(conn, "SELECT ComponentId, ComponentName, RuleId, Severity, Title, Why, Fix, Via, OnlyCommands, "
                                  "Refs, Source FROM cz.vFindingLatest WHERE ApplicationId = %s AND Severity <> 'info'",
                            (app_id,))
    app["sandbox"] = _rows(conn, "SELECT ComponentId, ComponentName, CheckedAt, Status, Reason, GitOps, Namespace, Workloads, "
                                 "Ready, Restarts, RuleId, Outcome, Diagnosis, Events, Url, UrlCheck FROM cz.vSandboxLatest "
                                 "WHERE ApplicationId = %s", (app_id,))
    app["history"] = _rows(conn, "SELECT TOP (20) AssessedAt, Rating, Score FROM cz.ApplicationAssessment "
                                 "WHERE ApplicationId = %s ORDER BY AssessedAt DESC, AssessmentId DESC", (app_id,))
    app["migrations"] = load_migrations(conn, app_id)
    app["idp"] = load_idp_clients(conn, app_id)
    app["scheduled_tasks"] = load_scheduled_tasks(conn, app_id)
    app["llm_reviews"] = load_llm_reviews(conn, app_id)
    app["refactors"] = load_refactor_orders(conn, app_id)
    from .connectivityui import load as load_connectivity
    app["connectivity"] = load_connectivity(conn, app_id)
    from .migrationplan import load_deploys
    app["deploys"] = load_deploys(conn, app_id)
    try:
        from .llmqueue import load_speed
        app["llm_speed"] = load_speed(conn) if app["refactors"] else None
    except Exception:  # noqa: BLE001 - no estimates before the schema allows the read
        app["llm_speed"] = None
    return app


def load_refactor_orders(conn, app_id: int) -> list[dict]:
    """The application's refactoring orders, newest first (empty before `db init` added them: schema 20; without
    the estimates and goal before schema 22, the sandbox variant before schema 23)."""
    base = "JobId, Component, ProjectPath, Status, Summary, SourceCommit, QueuedAt, FinishedAt, VerifyStatus"
    est = ", InputChars, EstInputTokens, InputTokens, OutputTokens, Seconds, Goal"
    for cols in (base + est + ", RatingAfter, SandboxStatus, SandboxUrl", base + est, base):
        try:
            return _rows(conn, f"SELECT TOP (20) {cols} FROM cz.vRefactorOrder WHERE ApplicationId = %s ORDER BY JobId DESC",
                         (app_id,))
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
    return []


REFACTOR_STATUS_CSS = {"approval": "st-wait", "queued": "st-run", "generating": "st-run", "verifying": "st-run",
                       "deploying": "st-run", "verified": "st-ok",
                       "applies-only": "st-warn", "failed": "st-bad", "cancelled": "st-off"}


# What the Refactoring box says after an order (admin_refactor._to_app): fixed texts only, chosen by a code in
# the URL, so a link cannot make the page show any text. (kind, text); {files} and {job} are numbers.
REFACTOR_NOTICES = {
    "ordered": ("ok", "Refactoring patch requested: {files} file(s) to change. It waits in the LLM queue; its status "
                      "shows below, and the patch appears here when it is ready."),
    "exists": ("info", "The same refactoring is already requested: its status shows below."),
    "approval": ("info", "Refactoring patch requested: {files} file(s) to change. It waits for an administrator to "
                         "approve it (Admin → LLM queue); its status shows below."),
    "ordered-a": ("ok", "\"Make it A\" requested: {files} file(s) to change first. It waits in the LLM queue; its "
                        "progress shows below, and a copy that rates A and runs takes this application's place in the sandbox."),
    "approval-a": ("info", "\"Make it A\" requested: {files} file(s) to change first. It waits for an administrator "
                           "to approve it (Admin → LLM queue); its status shows below."),
    "not-b": ("bad", "Refactoring patches are for applications rated B."),
    "no-component": ("bad", "That component is not part of this application."),
    "no-commit": ("bad", "The assessment recorded no commit: scan the repository again, then request the patch."),
    "no-source": ("bad", "The source of this application is not kept on this machine (no organization scan here has "
                         "its repository). Run `containerizer refactor` on a checkout instead."),
    "not-yours": ("bad", "Product owners can request patches for the applications of their own products only."),
    "nothing": ("info", "Nothing to change: no finding of this application (or component) can be fixed in code."),
    "failed": ("bad", "The refactoring could not be requested. The reason is in the web UI's log."),
}


_STATE_RULES: dict | None = None


def state_rules() -> dict:
    """Rule id -> its state ('local' or 'memory'): the rules that say a component keeps its own data."""
    global _STATE_RULES
    if _STATE_RULES is None:
        from .rules import load_rules
        try:
            _STATE_RULES = {r.id: r.state for r in load_rules() if r.state}
        except Exception:  # noqa: BLE001 - only the explanation is missing
            _STATE_RULES = {}
    return _STATE_RULES


def rating_why(app: dict) -> tuple[str, list[dict], list[dict]]:
    """Why the application has its rating, in a sentence; and its stateful and refactor components.
    A needs every server component to run with configuration only; data of its own is on a persistent volume."""
    comps = [c for c in app.get("components") or [] if (c.get("Tier") or "server") in ("server", "platform")]
    by = lambda v: [c for c in comps if c.get("Verdict") == v]     # noqa: E731
    rules = state_rules()
    state: dict[str, list[str]] = {}
    for f in app.get("findings") or []:
        if f.get("RuleId") in rules and not f.get("OnlyCommands"):
            state.setdefault(f.get("ComponentName") or "", [])
            if f.get("Title") not in state[f["ComponentName"]]:
                state[f["ComponentName"]].append(f.get("Title"))
    stateful = [c for c in comps if c.get("ComponentName") in state and c.get("Verdict") in ("info", "config", "refactor")]
    refactor = by("refactor")
    names = lambda cs: ", ".join(c["ComponentName"] for c in cs)   # noqa: E731
    r = app.get("Rating")
    parts = []
    if r in ("C", "D", "E") and by("blocker"):
        parts.append(f"{names(by('blocker'))} cannot run in Linux containers (blockers).")
    if r in ("D", "E") and by("rewrite"):
        parts.append(f"{names(by('rewrite'))} need a port or rewrite.")
    if refactor:
        parts.append(f"{names(refactor)} need targeted code changes.")
    keeps = "; ".join(f"{c['ComponentName']} keeps its own data ({', '.join(state[c['ComponentName']])})"
                      for c in stateful)
    if stateful and r == "B":
        parts.append(keeps + (". It runs with a persistent volume and one replica, no code change." if refactor else
                              ", in a folder Containerizer could not find, so no persistent volume can hold it: its "
                              "findings say what it writes (a folder setting or a path in the configuration places it)."))
    if r == "A":
        parts = ["Every server component runs in Linux containers with configuration only"
                 + (f". Stateful: {keeps}, and runs as it is with a persistent volume and one replica; scaling out "
                    "needs that data in a shared service first." if stateful else " and keeps no data of its own.")]
    if not parts:
        return "", stateful, refactor
    return f"<p class='why-rating'><b>Why {e(r)}:</b> {e(' '.join(parts))}</p>", stateful, refactor


def scan_again_ctx(admin, app: dict) -> dict:
    """The Try again button's state (scanagain.state), read with the admin login; nothing when it cannot be read."""
    from .scanagain import state
    try:
        conn = admin.connect_admin()
    except Exception:  # noqa: BLE001
        return {}
    try:
        return {"scan_state": state(conn, int(app["ApplicationId"]))}
    except Exception:  # noqa: BLE001 - a database from before the organization scans
        return {}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def refactor_estimates(admin, app: dict) -> dict:
    """What each refactoring order of the application would cost, as the LLM queue estimates it (the order
    built as when it is placed; the speed learned from earlier answers). Key (component id or None, goal).
    Reads the assessment's report with the admin login, so only for people who may order."""
    from . import refactor as rf
    from .llmqueue import load_speed
    out = {}
    try:
        conn = admin.connect_admin()
    except Exception:  # noqa: BLE001 - no estimates, the buttons still work
        return out
    try:
        rows = _rows(conn, "SELECT ReportJson FROM cz.ApplicationAssessment WHERE AssessmentId = %s",
                     (app["AssessmentId"],))
        doc = json.loads(rows[0]["ReportJson"]) if rows and rows[0].get("ReportJson") else {}
        speed = load_speed(conn)
    except Exception:  # noqa: BLE001
        return out
    finally:
        conn.close()
    try:
        pl = rf.build_payload(doc, {"type": "none"}, None, goal="rating-a")
        out[(None, "rating-a")] = speed.job({"Kind": rf.KIND, "InputChars": rf.order_chars(pl), "Model": None})
    except rf.RefactorError:
        pass
    return out


def _mins(seconds) -> str:
    return f"{max(1, round(seconds / 60))} min" if seconds < 5400 else f"{seconds / 3600:.1f} h"


PROGRESS_RE = re.compile(r"file (\d+) of (\d+)")


def order_effort(o: dict, speed) -> str:
    """Tokens and time of an order: the queue's estimate while it waits or runs (with the time left while it
    generates), what it took once it is done."""
    if o.get("FinishedAt") and (o.get("InputTokens") is not None or o.get("Seconds")):
        tok = int(o.get("InputTokens") or 0) + int(o.get("OutputTokens") or 0)
        took = f" · {_mins(float(o['Seconds']))}" if o.get("Seconds") else ""
        return f"{tok:,} tokens{took}" if tok else took.strip(" ·")
    if o.get("FinishedAt") or speed is None:
        return ""
    from .refactor import KIND
    est = speed.job({"Kind": KIND, "InputChars": o.get("InputChars"), "EstInputTokens": o.get("EstInputTokens"),
                     "Model": None})
    text = est_text(est)
    m = PROGRESS_RE.search(o.get("Summary") or "")
    if m and est.get("seconds") is not None and o.get("Status") == "generating":
        done, total = int(m[1]) - 1, max(1, int(m[2]))
        text += f" · about {_mins(est['seconds'] * (total - done) / total)} left"
    return text


def est_text(est: dict | None) -> str:
    if not est:
        return ""
    mins = "time: learning" if est.get("seconds") is None else \
        (f"~{max(1, round(est['seconds'] / 60))} min" if est["seconds"] < 5400 else f"~{est['seconds'] / 3600:.1f} h")
    return f"~{int(est['in'] + est['out']):,} tokens · {mins}"


def existing_order(orders: list, project_path: str | None, goal: str) -> dict | None:
    """The newest order of this component (None: all components) and goal that is waiting, running or has a
    patch (a repair counts for the goal it repairs). Failed or cancelled ones do not count."""
    for o in orders or []:                       # newest first
        same = (o.get("ProjectPath") or None) == (project_path or None)
        if same and o.get("Goal") in (goal, "repair") and o.get("Status") not in ("failed", "cancelled"):
            return o
    return None


def existing_offer(o: dict, ctx: dict, app_id, comp_id, goal: str, speed=None) -> str:
    """Instead of the request button: the order there already is, its status and its patch."""
    from .refactor import status_label
    st = o.get("Status") or "queued"
    label, why = status_label(st, [o.get("VerifyStatus")])
    chip = (f"<span class='st {REFACTOR_STATUS_CSS.get(st, '')}'" + (f" title='{e(why)}'" if why else "")
            + f">{e(label)}</span>")
    jid = int(o["JobId"])
    staff = bool(ctx.get("csrf"))
    eff = order_effort(o, speed)
    if st in ("verified", "applies-only"):
        head = "A patch is ready" if st == "verified" else "A patch was made"
        links = (f" <a href='/admin/refactoring/{jid}'>Open the patch</a> · "
                 f"<a href='/admin/refactoring/{jid}.patch'>Download .patch</a>") if staff else ""
        # the earlier targeted or data-move orders are not offered again: Make it A does both (one button)
        again = (" " + order_button(app_id, comp_id, goal, ctx["csrf"], "Request a new one", None, small=True)
                 if staff and goal == "rating-a" else "")
        return (f"<b>{head}:</b> {chip} <span class='small'>{e(o.get('Summary') or '')}</span>"
                + (f" <span class='muted small'>{e(eff)}</span>" if eff else "") + links
                + f"<div class='muted small'>Made for commit {e(str(o.get('SourceCommit') or '')[:12])}; "
                  + ("request a new one when the code has changed." if goal == "rating-a" else
                     "<a href='#refactoring'>Make it A</a> makes these changes and the rest, verified in the sandbox.")
                  + f"{again}</div>")
    link = f" <a href='/admin/refactoring/{jid}'>Follow it</a>" if staff else ""
    return (f"<b>Already requested:</b> {chip}" + (f" <span class='muted small'>{e(eff)}</span>" if eff else "") + link)


def order_button(app_id, comp_id, goal: str, csrf: str, label: str, est: dict | None, small: bool = False) -> str:
    """One-click refactoring order (POST to the admin pages, like the Refactoring box's forms)."""
    comp = f"<input type='hidden' name='Component' value='{int(comp_id)}'>" if comp_id else ""
    tip = est_text(est)
    return (f"<form method='post' action='/admin/refactoring/new' class='inline order'>{csrf}"
            f"<input type='hidden' name='ApplicationId' value='{int(app_id)}'>{comp}"
            f"<input type='hidden' name='Goal' value='{e(goal)}'>"
            f"<button class='{'link' if small else ''}'>{e(label)}</button>"
            + (f" <span class='muted small'>{e(tip)}</span>" if tip else "") + "</form>")


VARIANT_CSS = {"deploying": "st-run", "running": "st-ok", "failing": "st-bad", "deployed": "st-warn", "off": "st-off",
               "removed": "st-off", "outdated": "st-off", "expired": "st-off", "error": "st-bad"}
VARIANT_URL_RE = re.compile(r"https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::\d{1,5})?/[A-Za-z0-9._~/-]{0,200}")


def _variant_chip(o: dict) -> str:
    """The sandbox state of a "Make it A" order (vRefactorOrder.SandboxStatus) and its URL (open ↗)."""
    from .variant import STATUS_TEXT
    st = o.get("SandboxStatus")
    if not st or st == "skipped":
        return ""
    out = f" <span class='st {VARIANT_CSS.get(st, '')}'>{e(STATUS_TEXT.get(st, st))}</span>"
    u = o.get("SandboxUrl")
    if st in ("running", "failing", "deployed") and isinstance(u, str) and VARIANT_URL_RE.fullmatch(u):
        out += f" <a href='{e(u)}' target='_blank' rel='noopener noreferrer'>open ↗</a>"
    return out


def refactor_notice(q: dict) -> str:
    code = (q.get("refactor") or [""])[0]
    if code not in REFACTOR_NOTICES:
        return ""
    kind, text = REFACTOR_NOTICES[code]
    nums = {k: int(v) for k in ("files", "job") for v in [(q.get(k) or [""])[0]] if re.fullmatch(r"\d{1,6}", v or "")}
    text = text.replace("{files}", str(nums.get("files", "some")))
    return f"<div class='notice notice-{kind}' role='status'>{e(text)}</div>"


def _refactoring(app: dict, ctx: dict | None) -> str:
    """The Refactoring box of a B-rated application: its orders (everyone sees their status) and, for signed-in
    operators and administrators, the form that orders one (POST to the admin pages, with the CSRF token).
    The patches themselves are on the admin pages."""
    from .refactor import STATUS_TEXT
    orders = app.get("refactors") or []
    if not has_refactoring_box(app):
        return ""
    ctx = ctx or {}
    staff = bool(ctx.get("csrf"))
    rows = []
    for o in orders:
        st = o.get("Status") or "queued"
        what = e(o.get("Component") or "All components")
        if staff:
            what = f"<a href='/admin/refactoring/{int(o['JobId'])}'>{what}</a>"
        when = _date(o.get("FinishedAt") or o.get("QueuedAt"))
        from .refactor import status_label
        label, why = status_label(st, [o.get("VerifyStatus")])
        tip = f" title='{e(why)}'" if why else ""
        if o.get("Goal") == "rating-a":
            what = what.replace("All components", "Make it A")
        rows.append(f"<tr><td>{what}</td><td><span class='st {REFACTOR_STATUS_CSS.get(st, '')}'{tip}>"
                    f"{e(label)}</span>{_variant_chip(o)}</td><td class='small'>{e(o.get('Summary') or '')}"
                    + (f"<div class='muted'>{e(eff)}</div>" if (eff := order_effort({**o, 'Status': st}, app.get('llm_speed'))) else "")
                    + (f"<div class='muted'>{e(why)}</div>" if why else "") + "</td>"
                    f"<td class='small nowrap'>{when}</td></tr>")
    out = ["<section class='card refactor' id='refactoring'><h2>Refactoring</h2>" + (ctx or {}).get("notice", "") +
           "<p class='muted small'>A patch has the LLM make the code changes this application needs, then applies it "
           "to the assessed commit, runs the rules on it again and builds and runs the changed components. The patch "
           "is a download with how to apply it: nothing is written to the repository, and every change needs a "
           "review.</p>"]
    if rows:
        out.append("<table><thead><tr><th>Component</th><th>Status</th><th>Result</th><th>When</th></tr></thead>"
                   f"<tbody>{''.join(rows)}</tbody></table>")
    _, stateful, refactor = rating_why(app)
    if staff and app.get("Rating") == "B":
        if refactor or stateful:
            est = (ctx.get("estimates") or {}).get((None, "rating-a"))
            out.append("<h3>Make it A</h3><p class='muted small'>One order for everything that keeps this application "
                       "from A: the LLM changes the code for every finding (and moves the data of the components that "
                       "keep their own), the patch is verified and repaired when it does not build, and the patched copy "
                       "is assessed again, with one more pass on what remains. A copy that rates A and runs is deployed "
                       "to the sandbox in place of this application's scan output (its namespace, URLs and lab database), until a scan finds newer "
                       "code of this application.</p>"
                       + (f"<div class='note offer'>{existing_offer(have_a, ctx, app['ApplicationId'], None, 'rating-a', ctx.get('speed'))}</div>"
                          if (have_a := existing_order(ctx.get("orders"), None, "rating-a")) else
                          order_button(app["ApplicationId"], None, "rating-a", ctx["csrf"], "Make it A", est)
                          + (" <span class='muted small'>(first pass; repair rounds and a second pass add more)</span>"
                             if est else "")))
        if not refactor and not stateful:
            out.append("<p class='muted small'>No finding of this application can be fixed in code.</p>")
    elif ctx.get("signin") and app.get("Rating") == "B":
        out.append("<p class='muted small'>Operators and administrators can request a refactoring patch (sign in).</p>")
    return "".join(out) + "</section>"


def load_llm_reviews(conn, app_id: int) -> list[dict]:
    """The latest queued LLM review of each component (empty before `db init` added the LLM queue)."""
    try:
        return _rows(conn, "SELECT ComponentId, Reason, Status, QueuedAt, FinishedAt, Model, Verdict, LlmConfidence, "
                           "Reasoning FROM cz.vLlmReviewLatest WHERE ApplicationId = %s", (app_id,))
    except Exception:
        return []


def _llm_review(r: dict | None, assessed_at) -> str:
    """"LLM review queued" or "LLM review answered: <verdict> (<confidence>)" for a component."""
    if not r or r.get("Status") not in ("queued", "running", "answered"):
        return ""
    if r["Status"] != "answered":
        return ("<p class='small'><b>LLM review queued</b> <span class='muted'>(the LLM is asked when the queue runs; "
                "the next scan uses the answer)</span></p>")
    later = r.get("FinishedAt") and assessed_at and r["FinishedAt"] > assessed_at
    conf = f" ({float(r['LlmConfidence']):.2f})" if r.get("LlmConfidence") is not None else ""
    return (f"<p class='small'><b>LLM review answered: {e(VERDICT_LABEL.get(r.get('Verdict'), r.get('Verdict') or '?'))}"
            f"{conf}</b> <span class='muted'>{'after this assessment: the next scan applies it' if later else ''}</span>"
            f"<br><span class='muted'>{e(_ws(r.get('Reasoning'))[:1500])}</span></p>")


def load_idp_clients(conn, app_id: int) -> list[dict]:
    """Sandbox identity provider registrations of the latest deployment (empty before `db init` added them)."""
    try:
        return _rows(conn, "SELECT ComponentId, ComponentName, WrittenAt, Protocol, IdpUrl, AppUrl, Identifier, MetadataUrl, "
                           "Settings, Notes FROM cz.vSandboxIdpLatest WHERE ApplicationId = %s ORDER BY ComponentName, Protocol",
                     (app_id,))
    except Exception as ex:       # schema not upgraded yet
        print(f"warning: sandbox IdP clients not available ({type(ex).__name__}); run `containerizer db init`",
              file=sys.stderr)
        return []


def load_scheduled_tasks(conn, app_id: int) -> list[dict]:
    """The Task Scheduler jobs of the latest assessment (empty before `db init` made schema 45)."""
    try:
        r = _rows(conn, "SELECT ScheduledTasksJson FROM cz.vScheduledTaskLatest WHERE ApplicationId = %s", (app_id,))
        return json.loads(r[0]["ScheduledTasksJson"]) if r and r[0].get("ScheduledTasksJson") else []
    except Exception:  # noqa: BLE001 - schema not upgraded yet
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return []


def _scheduled_tasks(rows: list[dict]) -> str:
    """The repository's Windows Task Scheduler jobs, their schedule and the CronJob each became (schedules.report)."""
    if not rows:
        return ""
    items = []
    for t in rows:
        names = ", ".join(f"<code>{e(n)}</code>" for n in t.get("cronjobs") or [])
        if names:
            became = f"CronJob {names}" + (f" <span class='muted small'>({e(t['component'])})</span>"
                                           if t.get("component") else "")
        else:
            became = f"<span class='muted'>{e(t.get('why_not') or '')}</span>"
        note = f"<div class='muted small'>{e(t['note'])}</div>" if t.get("note") and t.get("schedule") else ""
        sched = f"<code>{e(t['schedule'])}</code>" if t.get("schedule") else "-"
        items.append(f"<tr><td>{e(t.get('name') or '(unnamed)')}<div class='muted small'><code>{e(t.get('file'))}:"
                     f"{int(t.get('line') or 0)}</code></div></td><td>{e(t.get('trigger') or '')}</td>"
                     f"<td>{sched}{note}</td><td>{became}</td></tr>")
    return ("<h2 id='scheduled-tasks'>Scheduled tasks</h2><p class='muted small'>Windows Task Scheduler jobs in the "
            "repository's deploy scripts and exports. Each job of a console component becomes a CronJob with the same "
            "arguments and schedule (at the hours of the server's local time); a CronJob no job matched keeps a "
            "placeholder schedule, annotated <code>containerizer.io/schedule: placeholder</code>.</p>"
            "<table><thead><tr><th>Job</th><th>Trigger</th><th>Schedule</th><th>Became</th></tr></thead>"
            f"<tbody>{''.join(items)}</tbody></table>")


IDP_PROTOCOL = {"oidc": "OpenID Connect", "wsfed": "WS-Federation", "saml": "SAML 2.0"}
IDP_ID_LABEL = {"oidc": "Client ID", "wsfed": "Realm (wtrealm)", "saml": "SP entity ID"}


def _link(u) -> str:
    u = str(u or "")
    return f"<a href='{e(u)}' rel='noopener noreferrer'>{e(u)}</a>" if re.match(r"https://[^\s'\"<>]+$", u) else e(u)


def _idp_section(rows: list[dict]) -> str:
    """Sign-in at the sandbox identity provider: where it is, and what each component was registered as
    and configured with (no secret values: the client secret is named, it lives in the secret store)."""
    if not rows:
        return ""
    idp = next((r["IdpUrl"] for r in rows if r.get("IdpUrl")), "")
    from .idp import config
    users = ", ".join(f"<code>{e(u['username'])}</code> ({e(', '.join(u.get('groups') or []))})"
                      for u in config().get("users") or [])
    items = []
    for r in rows:
        try:
            st = json.loads(r.get("Settings") or "{}")
        except ValueError:
            st = {}
        notes = f"<div class='muted small'>{e(r['Notes'])}</div>" if r.get("Notes") else ""
        if r["Protocol"] == "none":
            items.append(f"<tr><td>{e(r['ComponentName'])}</td><td colspan='3'>Not registered{notes}</td></tr>")
            continue
        env = "".join(f"<div><code>{e(k)}</code> = {_link(v)}</div>" for k, v in sorted((st.get("env") or {}).items()))
        if st.get("secret"):
            env += f"<div><code>{e(st['secret'])}</code> = <span class='muted'>client secret, from the secret store</span></div>"
        items.append(f"<tr><td>{e(r['ComponentName'])}<div class='muted small'>{_link(r.get('AppUrl'))}</div></td>"
                     f"<td>{e(IDP_PROTOCOL.get(r['Protocol'], r['Protocol']))}</td>"
                     f"<td><div class='muted small'>{e(IDP_ID_LABEL.get(r['Protocol'], 'Identifier'))}</div>"
                     f"<code>{e(r.get('Identifier') or '')}</code>"
                     f"<div class='muted small'>Metadata</div>{_link(r.get('MetadataUrl'))}</td>"
                     f"<td class='small'>{env or '-'}{notes}</td></tr>")
    return (f"<h2>Sign-in in the sandbox</h2><p>Components that sign users in are registered at the sandbox identity "
            f"provider {_link(idp + '/') if idp else ''} (WSO2 Identity Server: OpenID Connect, SAML 2.0, WS-Federation) "
            f"and pointed at it through configuration only. Test users: {users}; an administrator sees their "
            f"passwords with <code>containerizer idp users</code> on the appliance console.</p>"
            f"<table><thead><tr><th>Component</th><th>Protocol</th><th>Registered as</th><th>Settings applied</th></tr></thead>"
            f"<tbody>{''.join(items)}</tbody></table>")


def load_migrations(conn, app_id: int, component_id: int | None = None) -> list[dict]:
    """Migration plans of the latest assessment (empty before `db init` added them)."""
    sql = ("SELECT ComponentId, ComponentName, Outcome, ItemCount, PlanJson "
           "FROM cz.vComponentMigrationLatest WHERE ApplicationId = %s")
    params: tuple = (app_id,)
    if component_id is not None:
        sql += " AND ComponentId = %s"
        params += (component_id,)
    try:
        return _rows(conn, sql, params)
    except Exception as ex:       # schema not upgraded yet: show the page without plans
        print(f"warning: migration plans not available ({type(ex).__name__}); run `containerizer db init`",
              file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# rendering (pure functions of the data above)

def _num(x, digits: int = 0) -> str:
    x = float(x or 0)
    return f"{x:,.{digits}f}" if digits else f"{round(x):,}"


def _date(d) -> str:
    return d.strftime("%Y-%m-%d") if hasattr(d, "strftime") else e(str(d or ""))


def _confidence_source(app: dict) -> str:
    """Where the confidence comes from: a build and run confirms it only when none of them failed."""
    failed = sum(1 for c in app.get("components") or [] if c.get("VerifyStatus") in VERIFY_FAILED)
    if failed:
        return f"from source analysis; the build or run failed for {failed} component{'s' if failed != 1 else ''}"
    return "confirmed by building and running" if app.get("Verified") else "from source analysis"


def _confidence(c) -> str:
    c = float(c or 0)
    return "High" if c >= 0.8 else "Medium" if c >= 0.5 else "Low"


def badge(r: str, big: bool = False) -> str:
    r = r if r in RATINGS else "E"
    return f"<span class='badge r{r}{' big' if big else ''}' title='{e(RATING_TITLE[r])}'>{r}</span>"


def segmented(counts: Counter, total: int, label: str, height: int = 28) -> str:
    """One whole split by rating (inline SVG: no inline styles, so the CSP stays strict)."""
    if not total:
        return ""
    parts = [r for r in RATINGS if counts[r]]
    width, gap = 1000.0, 3.0
    usable = width - gap * (len(parts) - 1)
    x, rects = 0.0, []
    for r in parts:
        w = max(usable * counts[r] / total, 4.0)
        rects.append(f"<rect class='f{r}' x='{x:.1f}' y='0' width='{w:.1f}' height='{height}'>"
                     f"<title>{r} {e(RATING_TITLE[r])}: {counts[r]} of {total}</title></rect>")
        x += w + gap
    return (f"<svg class='bar' viewBox='0 0 {width:.0f} {height}' preserveAspectRatio='none' height='{height}' "
            f"role='img' aria-label='{e(label)}'>{''.join(rects)}</svg>")


def legend(counts: Counter | None = None) -> str:
    items = "".join(f"<li><span class='key r{r}'></span><b>{r}</b> {e(RATING_TITLE[r])}"
                    f"{f' <span class=muted>{counts[r]}</span>' if counts is not None else ''}</li>" for r in RATINGS)
    return f"<ul class='legend'>{items}</ul>"


def _mix(apps: list[dict]) -> Counter:
    return Counter(a["Rating"] for a in apps)


def _summary_line(apps: list[dict]) -> str:
    c = _mix(apps)
    ready = c["A"]
    return f"{len(apps)} application{'s' if len(apps) != 1 else ''} · {ready} ready to containerize"


def _bu_href(bu) -> str:
    return "/?bu=" + quote(str(bu if bu is not None else "none"))


def _overview_href(bu=None, tag=None) -> str:
    q = {k: v for k, v in (("bu", bu), ("tag", tag)) if v is not None}
    return "/" + ("?" + urlencode(q) if q else "")


def _tag_chips(stored) -> str:
    """An application's tags, each a link to the front page filtered by it (an automatic one, AUTO_TAGS, says so)."""
    return "".join(f" <a class='tag{' auto' if t in AUTO_TAGS else ''}' href='{e(_overview_href(tag=t))}'"
                   + (f" title='{e(AUTO_TAGS[t])}'" if t in AUTO_TAGS else "") + f">{e(t)}</a>" for t in split_tags(stored))


def app_auto_tags(app: dict) -> list[str]:
    """The automatic tags of an application on its results page: `stateful` when a server component keeps its own
    data (findings of rules with a state)."""
    from .migrationplan import stateful
    state = stateful(app.get("findings"), state_rules())
    return [STATEFUL] if any(c.get("ComponentId") in state and (c.get("Tier") or "server") in ("server", "platform")
                             for c in app.get("components") or []) else []


def _stateful_mark(auto) -> str:
    """Next to an A rating: the application keeps data of its own (on a persistent volume, one replica)."""
    return (f" <span class='stateful-mark' title='{e(AUTO_TAGS[STATEFUL])}'>stateful</span>"
            if STATEFUL in (auto or ()) else "")


def _trends_href(bu) -> str:
    return "/trends" + (f"?bu={quote(str(bu))}" if bu is not None else "")


VARIANT_TEXT = {"running": "Running in the sandbox", "deployed": "In the sandbox (health not checked)",
                "off": "Sandbox turned off",
                "failing": "Failing in the sandbox", "deploying": "Deploying", "removed": "Removed from the sandbox",
                "outdated": "Replaced by newer code", "expired": "Expired in the sandbox", "skipped": "Not deployed",
                "error": "Deploy failed"}


def _a_patch_mark(a: dict) -> str:
    """→ A next to a B application's rating when a verified patch makes it A (green when it runs in the sandbox)."""
    ap = a.get("APatch")
    if not ap or a.get("Rating") == "A":
        return ""
    here = ap.get("SandboxStatus") in SANDBOX_HERE
    return (f" <span class='a-patch{' here' if here else ''}' title='A verified patch makes it A"
            f"{' and runs in the sandbox' if here else ''}'>→ A</span>")


def _ready_mark(a: dict) -> str:
    """Next to the rating of an application that is not A: how many of its components can run in Linux containers
    now (rate A on their own: the first wave of its migration plan), when at least one can."""
    n, total = a.get("ReadyNow") or 0, a.get("PlanComponents") or 0
    if a.get("Rating") == "A" or not n or not total:
        return ""
    vol = a.get("ReadyStateful") or 0
    tip = (f"{n} of {total} components can run in Linux containers now without code changes (the organization scan "
           f"deploys them to the sandbox)"
           + (f"; {vol} of them keep{'s' if vol == 1 else ''} its own data and run{'s' if vol == 1 else ''} with a "
              f"persistent volume, one replica" if vol else "")
           + "; the rating grades the whole application. See its migration plan.")
    return (f"<span class='ready-now' title='{e(tip)}'>{n}/{total} ready now"
            + (f"<span class='stateful'>, {'with a volume' if vol == n else f'{vol} with a volume'}</span>" if vol else "")
            + "</span>")


def a_patches_html(apps: list[dict], nav: str = "") -> str:
    """The applications a verified "Make it A" patch makes A, the ones running in the sandbox first."""
    if not apps:
        return ""
    rows = []
    for a in sorted(apps, key=lambda a: (a["APatch"].get("SandboxStatus") not in SANDBOX_HERE, a["ApplicationName"].lower())):
        ap = a["APatch"]
        st = ap.get("SandboxStatus") or ""
        css = "st-ok" if st in SANDBOX_HERE else "st-bad" if st in ("failing", "error") else "st-off"
        url = ap.get("SandboxUrl") if st in SANDBOX_HERE else None
        link = (f" <a href='{e(url)}' target='_blank' rel='noopener noreferrer'>Open</a>"
                if url and re.match(r"https?://", str(url)) else "")
        patch = f" · <a href='/admin/refactoring/{int(ap['JobId'])}'>The patch</a>" if nav else ""
        rows.append(f"<tr><td>{badge(a['Rating'])} → {badge('A')}</td>"
                    f"<td><a href='/app/{int(a['ApplicationId'])}#refactoring'>{e(a['ApplicationName'])}</a>{patch}</td>"
                    f"<td><span class='st {css}'>{e(VARIANT_TEXT.get(st, 'Not in the sandbox'))}</span>{link}</td>"
                    f"<td class='small'>{_date(ap.get('FinishedAt'))}</td></tr>")
    return ("<section class='a-patches'><h2>Made A by a patch</h2><p class='muted'>A \"Make it A\" patch for these "
            "applications builds, runs and rates A. The patched copy runs in the sandbox in place of the application's "
            "scan output (often none: only components that rate A on their own run without it), in the application's "
            "own namespace, at its URLs and with its lab database. Merging the patch makes the application itself A."
            "</p><table><thead><tr><th>Rating</th>"
            "<th>Application</th><th>Sandbox</th><th>Patch made</th></tr></thead><tbody>" + "".join(rows)
            + "</tbody></table></section>")


def render_overview(data: dict, bu_filter: str | None = None, nav: str = "", tag_filter: str | None = None,
                    admin: bool = True) -> str:
    """`admin`: the reader may see the applications not mapped to a product yet: an administrator, or anyone where
    there is no sign-in (no admin pages, so nobody else could map them). For everyone else they are left out: nobody
    has said whose they are."""
    apps = data["apps"]
    unmapped_apps = [a for a in apps if a.get("ProductId") is None]
    if not admin:
        apps = [a for a in apps if a.get("ProductId") is not None]
    all_apps = apps
    if bu_filter is not None:
        apps = [a for a in apps if str(a["BusinessUnitId"] if a["BusinessUnitId"] is not None else "none") == bu_filter]
    in_bu = apps
    if tag_filter is not None:
        apps = [a for a in apps if has_tag(a.get("Tags"), tag_filter)]
    c = _mix(apps)
    total = len(apps)
    last = max((a["AssessedAt"] for a in apps if a["AssessedAt"]), default=None)

    def pct(n):
        return f"{round(100 * n / total)}%" if total else "-"
    patched = [a for a in apps if a.get("APatch") and a.get("Rating") != "A"]
    in_sb = [a for a in patched if a["APatch"].get("SandboxStatus") in SANDBOX_HERE]
    tiles = (f"<div class='tile'><div class='label'>Applications assessed</div><div class='value'>{total}</div></div>"
             f"<div class='tile'><div class='label'>Ready now (A)</div><div class='value'>{c['A']}</div>"
             f"<div class='sub'>{pct(c['A'])} of applications</div></div>"
             f"<div class='tile'><div class='label'>Need code changes (B, D)</div><div class='value'>{c['B'] + c['D']}</div>"
             f"<div class='sub'>{pct(c['B'] + c['D'])}</div></div>"
             f"<div class='tile'><div class='label'>Partly or not feasible (C, E)</div><div class='value'>{c['C'] + c['E']}</div>"
             f"<div class='sub'>{pct(c['C'] + c['E'])}</div></div>"
             + (f"<div class='tile'><div class='label'>A with a patch (B → A)</div><div class='value'>{len(patched)}</div>"
                f"<div class='sub'>{len(in_sb)} running in the sandbox</div></div>" if patched else ""))

    bus: dict = {}
    for a in all_apps:
        key = (a["BusinessUnitName"] or "", a["BusinessUnitId"])
        bus.setdefault(key, []).append(a)
    chips = [f"<a class='chip{' on' if bu_filter is None else ''}' href='{e(_overview_href(tag=tag_filter))}'>All</a>"]
    for (name, bid), lst in sorted(bus.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
        on = bu_filter == str(bid if bid is not None else "none")
        chips.append(f"<a class='chip{' on' if on else ''}' href='{e(_overview_href(str(bid if bid is not None else 'none'), tag_filter))}'>"
                     f"{e(name or UNASSIGNED)} <span class='muted'>{len(lst)}</span></a>")
    # tags of the applications in the business unit shown (the one filtered by stays, even with none left)
    tag_n: dict = {}
    for a in in_bu:
        for t in split_tags(a.get("Tags")):
            k = t.casefold()
            tag_n[k] = (tag_n.get(k, (t, 0))[0], tag_n.get(k, (t, 0))[1] + 1)
    if tag_filter is not None and tag_filter.casefold() not in tag_n:
        tag_n[tag_filter.casefold()] = (tag_filter, 0)
    tag_chips = []
    if tag_n:
        tag_chips.append(f"<span class='muted small'>Tags</span><a class='chip tagchip{' on' if tag_filter is None else ''}' "
                         f"href='{e(_overview_href(bu_filter))}'>Any</a>")
        for k, (t, n) in sorted(tag_n.items()):
            on = tag_filter is not None and tag_filter.casefold() == k
            tag_chips.append(f"<a class='chip tagchip{' on' if on else ''}' href='{e(_overview_href(bu_filter, None if on else t))}'"
                             f"{' aria-current=true' if on else ''}>{e(t)} <span class='muted'>{n}</span></a>")

    sections = []
    groups: dict = {}
    for a in apps:
        groups.setdefault((a["BusinessUnitName"] or "", a["BusinessUnitId"]), {}).setdefault(
            (a["ProductName"] or "", a["ProductId"]), []).append(a)
    for (bu, bid), products in sorted(groups.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
        bu_apps = [a for lst in products.values() for a in lst]
        body = []
        for (prod, pid), lst in sorted(products.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
            rows = "".join(
                f"<tr><td>{badge(a['Rating'])}{_stateful_mark(a.get('AutoTags'))}{_a_patch_mark(a)}{_ready_mark(a)}</td>"
                f"<td><a href='/app/{int(a['ApplicationId'])}'>{e(a['ApplicationName'])}</a>{_tag_chips(a.get('Tags'))}"
                f"<div class='muted small'>{e(RATING_TITLE.get(a['Rating'], ''))}: {e(RATING_TEXT.get(a['Rating'], ''))}</div></td>"
                f"<td class='num'>{int(a['Score'])}</td>"
                f"<td class='num'>{int(a['Components'])}</td><td>{e(a['MainObstacle'] or '-')}</td></tr>"
                for a in sorted(lst, key=lambda a: (a["Rating"], -int(a["Score"]), a["ApplicationName"].lower())))
            body.append(f"<div class='product'><h3>{e(prod or UNASSIGNED + ' to a product')}{_info_link(lst[0].get('ProductInfoUrl'))} "
                        f"<span class='muted small'>{_summary_line(lst)}</span></h3>"
                        f"<table><thead><tr><th>Rating</th><th>Application</th><th class='num'>Readiness</th>"
                        f"<th class='num'>Components</th><th>Main obstacle</th></tr></thead>"
                        f"<tbody>{rows}</tbody></table></div>")
        bc = _mix(bu_apps)
        sections.append(f"<section class='bu'><h2>{e(bu or UNASSIGNED + ' to a business unit')}</h2>"
                        f"<p class='muted'>{_summary_line(bu_apps)}</p>"
                        f"{segmented(bc, len(bu_apps), f'Ratings in {bu or UNASSIGNED}', 10)}{''.join(body)}</section>")

    um = data.get("unmapped") or {}
    note = a_patches_html(patched, nav) + running_html(apps)
    if admin and unmapped_apps and nav:
        note += (f"<p class='note'>{len(unmapped_apps)} application(s) not mapped to a product are shown to administrators "
                 f"only; <a href='/admin/applications?show=unmapped'>map them</a> to show them to everyone.</p>")
    elif admin and (um.get("Application") or um.get("Product")):
        parts = []
        if um.get("Application"):
            parts.append(f"{um['Application']} application(s) are not mapped to a product")
        if um.get("Product"):
            parts.append(f"{um['Product']} product(s) are not mapped to a business unit")
        note += (f"<p class='note'>{e('; '.join(parts))}. Administrators maintain the mapping on the "
                f"<a href='/admin'>admin pages</a>.</p>") if nav else (
                f"<p class='note'>{e('; '.join(parts))}.</p>")
    empty = "<p>No assessments yet. Run <code>containerizer assess --sql …</code> to add some.</p>" if not all_apps else ""
    meta = " · ".join(([f"Last assessed {_date(last)}"] if last else [])
                      + ([f"<a href='{e(_trends_href(bu_filter))}'>Trends over time</a>"] if all_apps else []))
    return page("Containerization readiness", f"""{_nav(nav)}
<header><h1>Containerization readiness</h1>
<p class='lead'>How ready are our applications to run in Linux containers?</p>
{f"<p class='muted small'>{meta}</p>" if meta else ''}
</header>
{empty}<nav class='chips'>{''.join(chips) if all_apps else ''}</nav>
{f"<nav class='chips tags' aria-label='Filter by tag'>{''.join(tag_chips)}</nav>" if tag_chips else ''}
{f"<p class='muted'>No applications{' in this business unit' if bu_filter is not None else ''} have the tag <b>{e(tag_filter)}</b>.</p>" if tag_filter is not None and not apps and all_apps else ''}
<div class='tiles'>{tiles if all_apps else ''}</div>
{f"<div class='overall'>{segmented(c, total, 'Ratings of all applications shown')}{legend(c)}</div>" if total else ''}
{note}{''.join(sections)}
<footer>{legend()}<p class='muted small'>Readiness is 0-100 (higher is better) across the server components.
Ratings come from rule-based analysis of the source code,
and where noted were confirmed by building and running the generated containers.</p></footer>""")


def _refs(raw) -> list[str]:
    try:
        refs = json.loads(raw) if raw else []
    except ValueError:
        return []
    return [u for u in refs if isinstance(u, str) and re.match(r"https?://[^\s'\"<>]+$", u)]


def _ref_label(u: str) -> str:
    from .report import ref_label     # "learn.microsoft.com: kestrel endpoints", same as the reports
    return ref_label(u)


def _nav(nav: str) -> str:
    """The results pages' top bar: Containerizer's logo and name in the right corner, the sign-in links under it."""
    from .theme import BUTTON
    return f"<div class='topnav'><span></span><span class='topnav-right'>{BRAND}<span>{nav}{BUTTON}</span></span></div>"


def _info_link(url) -> str:
    from .admin import info_link
    return info_link(url)


def _scan_again(app: dict, ctx: dict | None) -> str:
    """Try again (scanagain.py) for administrators and operators, when the latest scan left a component out."""
    from .scanagain import section
    excluded = [d for d in app.get("deploys") or [] if d.get("Kind") == "excluded"]
    return section(app, ctx or {}, excluded)


def _lab_needs(app: dict, ctx: dict | None) -> str:
    """What the application needs from the sandbox lab (labservices.py) and whether the lab gives it: from the
    latest organization scan (cz.vSandboxDeploy LabServices). A service turned off names the components that run
    without it (they keep their own settings, and often stop)."""
    from .migrationplan import lab_report
    from .labservices import SERVICES
    rep = lab_report(app.get("deploys"))
    needed = rep.get("needed") or {}
    if not needed:
        return ""
    title = lambda x: SERVICES[x].title if x in SERVICES else x          # noqa: E731
    on = [title(x) for x in rep.get("provided") or [] if x in needed]
    off = [x for x in rep.get("missing") or [] if x in needed]
    parts = []
    if on:
        parts.append(f"<span class='st st-ok'>provided</span> {e(', '.join(on))}")
    if "smtp" in (rep.get("provided") or []) and "smtp" in needed:
        parts.append("the mail it sends is caught in the lab, not sent: "
                     + ("<a href='/admin/lab-mail'>Admin → Lab mail</a>" if (ctx or {}).get("lab_mail")
                        else "Admin → Lab mail (administrators and operators)"))
    if off:
        comps = sorted({c for x in off for c in needed.get(x) or []})
        where = ("<a href='/admin/lab-services'>Admin → Lab services</a>" if (ctx or {}).get("lab_admin")
                 else "Admin → Lab services (administrators)")
        parts.append(f"<span class='st st-bad'>turned off</span> {e(', '.join(title(x) for x in off))}: "
                     f"{e(', '.join(comps))} run{'s' if len(comps) == 1 else ''} without "
                     f"{'it' if len(off) == 1 else 'them'} (their own settings). Turn {'it' if len(off) == 1 else 'them'} "
                     f"on under {where}; the next scan points the app at {'it' if len(off) == 1 else 'them'}.")
    return ("<p class='lab-needs small'><span class='label'>Lab services</span> Needs in the sandbox: "
            + "; ".join(parts) + " <a href='https://containerizer.eu/lab-services/'>About lab services</a></p>")


def _in_sandbox(app: dict) -> str:
    """What of the application runs in the sandbox by its latest check, with the link to open, at the top of its page."""
    from .sandbox import URL_RE, main_url
    up = [s for s in app.get("sandbox") or [] if s.get("Status") in RUNNING]
    if not up:
        return ""
    total = sum(1 for c in app.get("components") or [] if c.get("Tier") == "server") or len(app.get("sandbox") or [])
    url = main_url([{"component": s.get("ComponentName") or "", "url": s["Url"]} for s in up
                    if s.get("Status") == "healthy" and URL_RE.fullmatch(s.get("Url") or "")])
    part = f"{len(up)} of {total} components run" if len(up) < total else "it runs"
    plan = " · <a href='#plan'>what runs and what does not yet</a>" if len(up) < total else ""
    return f"<p class='in-sandbox'><span class='st st-ok'>In the sandbox</span> {e(part)} there now{_open_link(url)}{plan}</p>"


def render_application(app: dict, nav: str = "", refactor: dict | None = None) -> str:
    r = app["Rating"]
    refactor = dict(refactor or {})
    refactor.update(orders=app.get("refactors") or [], speed=app.get("llm_speed"),
                    paths={int(c["ComponentId"]): c.get("ProjectPath") for c in app.get("components") or []})
    # the components Make it A changes (it is offered for B applications): their "How to fix" points to it
    _, st_, rf_ = rating_why(app)
    refactor["fixable"] = {int(c["ComponentId"]) for c in st_ + rf_} if r == "B" else set()
    crumbs = (f"<a href='/'>All</a> › <a href='{e(_bu_href(app['BusinessUnitId']))}'>"
              f"{e(app['BusinessUnitName'] or UNASSIGNED)}</a> › {e(app['ProductName'] or UNASSIGNED)}"
              f"{_info_link(app.get('ProductInfoUrl'))}")
    sandbox = {s["ComponentId"]: s for s in app.get("sandbox") or []}
    by_comp: dict = {}
    for f in app["findings"]:
        by_comp.setdefault(f["ComponentId"], []).append(f)
    obstacles: dict = {}
    for f in app["findings"]:
        if f["Severity"] in ("blocker", "rewrite"):
            o = obstacles.setdefault(f["Title"], {"sev": f["Severity"], "comps": []})
            if f["ComponentName"] and f["ComponentName"] not in o["comps"]:
                o["comps"].append(f["ComponentName"])
    obs = sorted(obstacles.items(), key=lambda kv: (SEV_ORDER.index(kv[1]["sev"]), -len(kv[1]["comps"])))[:5]
    obs_html = "".join(f"<li><span class='sev s-{o['sev']}'>{e(VERDICT_LABEL[o['sev']])}</span> <b>{e(t)}</b>"
                       f"{' <span class=muted>(' + e(', '.join(o['comps'])) + ')</span>' if o['comps'] else ''}</li>"
                       for t, o in obs)

    migs = {m["ComponentId"]: m for m in app.get("migrations") or []}
    reviews = {r["ComponentId"]: r for r in app.get("llm_reviews") or []}
    from .migrationplan import sandbox_state
    in_sb = {c["ComponentId"]: sandbox_state(c, sandbox, app.get("deploys")) for c in app["components"]}
    sb_col = bool(sandbox) or any(x["state"] in ("checked", "deployed", "excluded") for x in in_sb.values())
    comp_rows = "".join(
        f"<tr><td><a href='#c{int(c['ComponentId'])}'>{e(c['ComponentName'])}</a>"
        f"<div class='muted small'>{e(c['ProjectPath'])}</div></td>"
        f"<td>{e(ROLE_TEXT.get(c['Role'], c['Role'].title()))}</td>"
        f"<td><span class='sev s-{e(c['Verdict'])}'>{e(VERDICT_LABEL.get(c['Verdict'], c['Verdict']))}</span></td>"
        f"<td>{_verify(c)}</td>"
        + (f"<td>{_sandbox_cell(in_sb[c['ComponentId']])}</td>" if sb_col else "")
        + f"<td>{_plan_cell(app['ApplicationId'], c, migs.get(c['ComponentId']), refactor)}</td>"
        + "</tr>"
        for c in app["components"])

    details = []
    for c in app["components"]:
        fs = sorted(by_comp.get(c["ComponentId"], []), key=lambda f: SEV_ORDER.index(f["Severity"]))
        items = "".join(_finding(f) for f in fs) or "<p class='muted'>Nothing to change.</p>"
        details.append(f"<details id='c{int(c['ComponentId'])}'{' open' if len(app['components']) == 1 else ''}>"
                       f"<summary><b>{e(c['ComponentName'])}</b> · {e(VERDICT_LABEL.get(c['Verdict'], c['Verdict']))}"
                       f" <span class='muted'>({len(fs)} item{'s' if len(fs) != 1 else ''})</span></summary>"
                       f"<div class='muted small'>{e(c['VerdictText'])}"
                       f"{'; targets ' + e(c['TargetFramework']) if c['TargetFramework'] else ''}</div>"
                       f"{_llm_review(reviews.get(c['ComponentId']), app.get('AssessedAt'))}"
                       f"{_verify_detail(c)}{_sandbox_detail(sandbox.get(c['ComponentId']))}{items}"
                       f"{_migration(app['ApplicationId'], migs.get(c['ComponentId']), refactor)}</details>")
    repo = by_comp.get(None, [])
    if repo:
        details.append("<details><summary><b>Repository</b></summary>" + "".join(_finding(f) for f in repo) + "</details>")

    hist = "".join(f"<tr><td>{_date(h['AssessedAt'])}</td><td>{badge(h['Rating'])}</td><td class='num'>{int(h['Score'])}</td></tr>"
                   for h in app["history"])
    src = ""
    if app.get("RepositoryUrl"):
        u = app["RepositoryUrl"]
        link = f"<a href='{e(u)}' rel='noopener noreferrer'>{e(u)}</a>" if re.match(r"https?://", u) else e(u)
        src = (f"<div><span class='label'>Source</span> {link}{' / ' + e(app['SourcePath']) if app.get('SourcePath') not in (None, '.') else ''}"
               f"{' @ ' + e(str(app['SourceCommit'])[:12]) if app.get('SourceCommit') else ''}</div>")
    owner = "".join(f"<div><span class='label'>{k}</span> {e(v)}</div>" for k, v in
                    (("Owner", app.get("Owner")), ("Product owner", app.get("ProductOwner")),
                     ("Business unit owner", app.get("BusinessUnitOwner"))) if v)
    return page(app["ApplicationName"], f"""{_nav(nav)}
<p class='crumbs'>{crumbs}</p>{_admin_links_html(refactor.get("admin_links"))}
<header class='app'>{badge(r, True)}{_stateful_mark(app_auto_tags(app))}<div><h1>{e(app['ApplicationName'])}</h1>
<p class='lead'><b>{e(RATING_TITLE.get(r, ''))}</b>: {e(RATING_TEXT.get(r, ''))}</p>
{f"<p>{e(app['Description'])}</p>" if app.get('Description') else ''}<p>{e(app['Summary'])}</p>{rating_why(app)[0]}{_verify_failed_note(app)}{_in_sandbox(app)}{_lab_needs(app, refactor)}</div></header>
<div class='tiles'>
<div class='tile'><div class='label'>Readiness</div><div class='value'>{int(app['Score'])}<span class='unit'>/100</span></div></div>
<div class='tile'><div class='label'>Confidence</div><div class='value'>{_confidence(app['Confidence'])}</div>
<div class='sub'>{_confidence_source(app)}</div></div>
<div class='tile'><div class='label'>Last assessed</div><div class='value small-value'>{_date(app['AssessedAt'])}</div></div>
</div>
<div class='meta'>{owner}{src}</div>
{_tags_section(app, refactor)}
{f"<h2>Main obstacles</h2><ul class='obstacles'>{obs_html}</ul>" if obs_html else ''}
{_migration_plan(app, refactor)}
<h2 id='components'>Components</h2>
<table><thead><tr><th>Component</th><th>What it is</th><th>Verdict</th><th>Build and run</th>{"<th>Sandbox cluster</th>" if sb_col else ""}<th>Migration</th></tr></thead>
<tbody>{comp_rows}</tbody></table>
{_scan_again(app, refactor)}
{_idp_section(app.get("idp") or [])}
{_scheduled_tasks(app.get("scheduled_tasks") or [])}
{_refactoring(app, refactor)}
<h2>What needs to change, and why</h2>{''.join(details)}
{_connectivity(app, refactor)}
<h2>History</h2><p class='muted small'><a href='/trends'>Trends of all applications</a></p><table class='narrow'><thead><tr><th>Assessed</th><th>Rating</th><th class='num'>Readiness</th>
</tr></thead><tbody>{hist}</tbody></table>
<footer>{legend()}</footer>""")


def admin_links(admin, conn, s, app: dict) -> list[tuple[str, str]]:
    """The admin pages of this application the signed-in person may open, for the results page: its settings
    (administrators, and product owners of its product) and its sandbox databases (administrators, operators)."""
    from .admin_devdb import enabled as devdb_enabled
    from .roles import Access
    app_id = int(app["ApplicationId"])
    a = Access.resolve(conn, s.admin, s.operator, s.scopes)
    out = []
    if a.can_edit_app(app.get("ProductId")):
        out.append(("Application settings", f"/admin/applications/{app_id}"))
    if devdb_enabled(admin, a):
        out.append(("Dev databases", f"/admin/dev-databases/{app_id}"))
    if a.admin or a.operator:
        out.append(("Refactoring orders", "/admin/refactoring"))
    return out


def _admin_links_html(links) -> str:
    if not links:
        return ""
    return ("<p class='adminlinks small'><span class='label'>Admin</span>"
            + " · ".join(f"<a href='{e(h)}'>{e(t)}</a>" for t, h in links) + "</p>")


def _tags_section(app: dict, ctx: dict | None) -> str:
    """The application's tags; administrators and operators edit them here (tags.py)."""
    from .tags import notice_html
    ctx = ctx or {}
    tags = [t for t in split_tags(app.get("Tags")) if t.casefold() not in AUTO_TAGS]   # people's tags: the editor's
    every = with_auto(",".join(tags), app_auto_tags(app))          # automatic ones are shown, never in the editor
    shown = _tag_chips(every) if every else (" <span class='muted'>none</span>" if ctx.get("tags_csrf") else "")
    if not shown:
        return ""
    form = ""
    if ctx.get("tags_csrf"):
        form = (f"<form method='post' action='/admin/tags/{int(app['ApplicationId'])}' class='formrow tagform'>{ctx['tags_csrf']}"
                f"<label for='Tags' class='sr'>Tags, separated by commas</label>"
                f"<input id='Tags' name='Tags' maxlength='900' value='{e(', '.join(tags))}' "
                f"placeholder='e.g. customer-facing, pci, wave 1'> <button class='secondary'>Save tags</button></form>")
    return (f"<div id='tags' class='tags-row'>{notice_html(ctx.get('tags_notice') or '')}"
            f"<span class='label'>Tags</span>{shown}{form}</div>")


def _connectivity(app: dict, ctx: dict | None) -> str:
    from .connectivityui import section
    try:
        return section(app, ctx)
    except Exception as ex:  # noqa: BLE001 - one section must not take the page down
        print(f"connectivity section of {app.get('ApplicationId')}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return ""


PLAN_OUTCOME_TEXT = {"linux-container": "Can move to a Linux container",
                "partial": "Can move once the Windows-only parts are isolated",
                "stays-on-windows": "Stays on Windows"}
KIND_TEXT = {"replace": "Replace", "port": "Port", "externalize": "Move out of the process", "isolate": "Keep on Windows"}


def _plan_cell(app_id, c: dict, m: dict | None, ctx: dict | None = None) -> str:
    """One link per component: to its migration section (the steps and the patch the LLM can make, with its
    estimate), or to the Refactoring box when only a patch is possible."""
    cid = int(c["ComponentId"])
    est = (ctx or {}).get("estimates") or {}
    if m:
        return f"<a href='#m{cid}'>How to fix ↓</a>"
    if cid in ((ctx or {}).get("fixable") or ()):
        return "<a href='#refactoring'>How to fix ↓</a>"
    return "<span class='muted'>-</span>"

def _migration(app_id, m: dict | None, ctx: dict | None = None) -> str:
    """Migration assistant of one component: suggested replacements, and the patch the LLM can make."""
    if not m:
        return ""
    cid = int(m["ComponentId"])
    try:
        plan = json.loads(m["PlanJson"] or "{}")
    except ValueError:
        plan = {}
    rows = []
    for it in plan.get("items") or []:
        refs = [u for u in it.get("refs") or [] if isinstance(u, str) and re.match(r"https?://[^\s'\"<>]+$", u)][:3]
        pk = it.get("packages") or {}
        extra = []
        if pk.get("add"):
            extra.append("add " + ", ".join(f"<code>{e(str(p))}</code>" for p in pk["add"]))
        if pk.get("remove"):
            extra.append("remove " + ", ".join(f"<code>{e(str(p))}</code>" for p in pk["remove"]))
        rows.append(
            f"<tr><td>{e(KIND_TEXT.get(it.get('kind'), str(it.get('kind'))))}</td><td>{e(_ws(it.get('replace')))}"
            f"<div class='muted small'>{e(', '.join(_ws(f.get('title')) for f in it.get('findings') or []))}</div></td>"
            f"<td>{e(_ws(it.get('with')))}"
            + (f"<div class='small'>{'; '.join(extra)}</div>" if extra else "")
            + ("<div class='small'>" + ", ".join(f"<a href='{e(u)}' rel='noopener noreferrer'>{e(_ref_label(u))}</a>"
                                                 for u in refs) + "</div>" if refs else "")
            + "</td></tr>")
    out = [f"<section class='migration' id='m{cid}'><h3>Migration assistant "
           f"<span class='muted small'>{e(PLAN_OUTCOME_TEXT.get(m['Outcome'], m['Outcome']))}</span></h3>"]
    if rows:
        out.append("<table><thead><tr><th>Action</th><th>Replace</th><th>With</th>"
                   "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
    ctx = ctx or {}
    path = (ctx.get("paths") or {}).get(cid)
    # an order made before Make it A was the only one (one component's targeted changes or data move): still shown
    have = next(((g, o) for g in ("fix", "stateless") if (o := existing_order(ctx.get("orders"), path, g))), None)
    if have:
        out.append("<div class='note offer'>" + existing_offer(have[1], ctx, app_id, cid, have[0], ctx.get("speed")) + "</div>")
    elif cid in (ctx.get("fixable") or ()) and ctx.get("csrf"):
        out.append("<div class='note offer'><b>Or let Containerizer make the change:</b> "
                   "<a href='#refactoring'>Make it A</a> has the LLM make it, with every other change the application "
                   "needs, verifies the patch by building and running it, and deploys the patched copy to the sandbox.</div>")
    return "".join(out) + "</section>"


VERIFY_TEXT = {"ok": "Runs", "ok-external": "Runs (stops only at missing external services)",
               "finding": "Runs with a finding", "build-failed": "Build failed", "run-failed": "Run failed"}
VERIFY_FAILED = ("build-failed", "run-failed")


def _verify(c: dict) -> str:
    s = c.get("VerifyStatus")
    if not s:
        return "<span class='muted'>not run</span>"
    out = f"<span class='v-{e(s)}'>{e(VERIFY_TEXT.get(s, s))}</span>"
    if s in VERIFY_FAILED and c.get("ComponentId") is not None:
        out += f" <a class='small' href='#c{int(c['ComponentId'])}'>why</a>"
    return out


def _verify_detail(c: dict) -> str:
    """Why a component's build or run failed, with the end of its log (VerifyDetail), in its details."""
    s = c.get("VerifyStatus")
    if s not in VERIFY_FAILED:
        return ""
    detail = (c.get("VerifyDetail") or "").strip()
    if "\n" in detail:
        body = f"<pre class='code'>{e(detail)}</pre>"
    else:                                   # a scan before the log was kept: only the steps it tried
        body = ((f"<p class='small'><span class='label'>Steps</span> {e(detail)}</p>" if detail else "")
                + "<p class='muted small'>This scan kept no log; the next scan shows the end of it here.</p>")
    return (f"<div class='sandbox'><div><span class='label'>Build and run</span> {_verify(dict(c, ComponentId=None))}"
            " <span class='muted small'>(in the scan's verification, before anything is generated)</span></div>"
            f"{body}<p class='muted small'>A component whose build or run failed is left out of the generated files "
            "and the sandbox; its rating comes from its source code.</p></div>")


def _verify_failed_note(app: dict) -> str:
    """At the top of the page: the rating comes from the source code, but the build or run failed."""
    bad = [c for c in app.get("components") or [] if c.get("VerifyStatus") in VERIFY_FAILED]
    if not bad:
        return ""
    names = ", ".join(f"<a href='#c{int(c['ComponentId'])}'>{e(c['ComponentName'])}</a>" for c in bad)
    return (f"<p class='note'><b>Not confirmed:</b> building or running {names} failed in the scan's "
            "verification. The rating comes from the source code; the failed components are not deployed until the "
            "next scan builds and runs them.</p>")


SANDBOX_TEXT = {"healthy": "Deployed and healthy", "failing": "Deployed but failing", "pending": "Not ready in time",
                "scheduled": "Deployed, job not run yet", "not-found": "Not deployed", "error": "Could not be checked"}
OUTCOME_TEXT = {"environment": "a sandbox cluster setting, not the application",
                "external": "a missing external service (database, broker, identity provider)",
                "code": "the application: needs a change", "platform": "the application: a Windows-only API",
                "retry": "the generated configuration: fixed on the next scan"}


def _sandbox(s: dict | None) -> str:
    if not s:
        return "<span class='muted'>not deployed</span>"
    st = s["Status"]
    return f"<span class='v-sb-{e(st)}'>{e(SANDBOX_TEXT.get(st, st))}</span>" + \
        (f" <span class='muted small'>{e(s['Ready'])}</span>" if s.get("Ready") and st == "healthy" else "") + \
        (f"<div class='small'>{_app_url(s)}</div>" if _app_url(s) else "")


def _sandbox_cell(x: dict) -> str:
    """The Components table's Sandbox cluster cell (migrationplan.sandbox_state), and the lab services it needs
    that are turned off."""
    from .migrationplan import lab_off_html
    return _sandbox_cell_state(x) + lab_off_html(x)


def _sandbox_cell_state(x: dict) -> str:
    """The check's result, "deployed, not checked yet" when the latest organization scan deployed it and no check
    has a result, or not deployed."""
    if x["state"] == "checked" or x.get("check"):
        return _sandbox(x["check"])
    if x["state"] == "deployed":
        return f"<span class='v-sb-scheduled'>{e(x['text'])}</span>"
    head, _, why = (x.get("text") or "not deployed").partition(": ")
    more = (f"<details class='small gate-detail'><summary>What failed</summary><pre>{e(x['detail'])}</pre></details>"
            if x.get("detail") else "")
    if more:                        # left out with what failed: the reason in full, then the details
        return f"<span class='muted'>{e(head)}</span><div class='muted small'>{e(why)}</div>{more}"
    return f"<span class='muted'{' title=' + chr(39) + e(why) + chr(39) if why else ''}>{e(head)}</span>"


def has_refactoring_box(app: dict) -> bool:
    """Whether the page has the Refactoring box (_refactoring): applications rated B, and any with orders."""
    return app.get("Rating") == "B" or bool(app.get("refactors"))


def _migration_plan(app: dict, ctx: dict | None) -> str:
    from .migrationplan import section
    try:
        return section(app, ctx, has_refactoring_box(app))
    except Exception as ex:  # noqa: BLE001 - one section must not take the page down
        print(f"migration plan of {app.get('ApplicationId')}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return ""


def _app_url(s: dict | None) -> str:
    """The component's public HTTPS URL as a link (only well-formed https URLs from the health check)."""
    from .sandbox import URL_RE
    url = (s or {}).get("Url") or ""
    if not URL_RE.fullmatch(url):
        return ""
    return f"<a href='{e(url)}' rel='noopener noreferrer' target='_blank'>{e(url.removeprefix('https://').rstrip('/'))}</a>"


def _sandbox_detail(s: dict | None) -> str:
    """What the sandbox cluster showed for a component: status, why, the Warning events."""
    if not s:
        return ""
    st = s["Status"]
    where = " · ".join(x for x in (f"namespace {s['Namespace']}" if s.get("Namespace") else "",
                                    {"argocd": "Argo CD", "flux": "Flux"}.get(s.get("GitOps") or "", ""),
                                    f"checked {_date(s['CheckedAt'])}") if x)
    out = [f"<div class='sandbox'><div><span class='label'>Sandbox cluster</span> {_sandbox(s)}"
           f" <span class='muted small'>({e(where)})</span></div>"]
    if _app_url(s):
        out.append(f"<p><span class='label'>URL</span> {_app_url(s)}"
                   f"{' <span class=' + chr(39) + 'muted small' + chr(39) + '>(' + e(s['UrlCheck']) + ')</span>' if s.get('UrlCheck') else ''}</p>")
    if st != "healthy" and s.get("Reason"):
        out.append(f"<p><span class='label'>Why</span> {e(_ws(s['Reason']))}</p>")
    elif st == "healthy":
        out.append(f"<p class='muted small'>{e(_ws(s.get('Reason') or ''))}"
                   f"{'; restarted ' + str(int(s['Restarts'])) + ' time(s)' if s.get('Restarts') else ''}</p>")
    if s.get("Outcome") in OUTCOME_TEXT and st != "healthy":
        out.append(f"<p><span class='label'>Caused by</span> {e(OUTCOME_TEXT[s['Outcome']])}"
                   f"{' (rule ' + e(s['RuleId']) + ')' if s.get('RuleId') else ''}</p>")
    try:
        events = json.loads(s.get("Events") or "[]")
    except ValueError:
        events = []
    if events and st != "healthy":
        out.append("<ul class='events small'>" + "".join(
            f"<li><b>{e(ev.get('reason', ''))}</b> {e(ev.get('message', ''))}"
            f"{' (' + str(int(ev['count'])) + '×)' if isinstance(ev.get('count'), int) and ev['count'] > 1 else ''}</li>"
            for ev in events[:5]) + "</ul>")
    return "".join(out) + "</div>"


def _finding(f: dict) -> str:
    refs = _refs(f.get("Refs"))
    extra = []
    if f.get("Via"):
        extra.append(f"comes from the shared library {e(f['Via'])}")
    if f.get("OnlyCommands"):
        extra.append(f"only the {e(f['OnlyCommands'])} command(s)")
    if f.get("Source") == "runtime":
        extra.append("found by building and running")
    out = [f"<div class='finding'><div><span class='sev s-{e(f['Severity'])}'>"
           f"{e(VERDICT_LABEL.get(f['Severity'], f['Severity']))}</span> <b>{e(f['Title'])}</b>"
           + (" <span class='muted'>(" + "; ".join(extra) + ")</span>" if extra else "") + "</div>"]
    for label, key in (("Why", "Why"), ("Fix", "Fix")):
        if f.get(key):
            out.append(f"<p><span class='label'>{label}</span> {e(_ws(f[key]))}</p>")
    if refs:
        out.append("<p><span class='label'>Learn more</span> " + ", ".join(
            f"<a href='{e(u)}' rel='noopener noreferrer'>{e(_ref_label(u))}</a>" for u in refs) + "</p>")
    return "".join(out) + "</div>"


def _ws(s) -> str:
    return " ".join(str(s or "").split())


SCRIPT_TAG = "<script src='/static/app.js'></script>"
# The icon: a container, and the green check of a container-ready application (also docs/images/favicon.svg).
FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <title>Containerizer</title>
  <rect width="64" height="64" rx="14" fill="#1f4e9a"/>
  <rect x="8" y="22" width="40" height="30" rx="3" fill="#fff"/>
  <path d="M16 27v20M24 27v20M32 27v20M40 27v20" stroke="#1f4e9a" stroke-width="3.5" stroke-linecap="round"/>
  <circle cx="47" cy="19" r="13" fill="#2e9e47" stroke="#1f4e9a" stroke-width="3"/>
  <path d="M40.5 19.5l4.5 4.5 8.5-9" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""


EXTERNAL_A = re.compile(r"<a\b(?P<pre>[^>]*?)\bhref=(?P<q>['\"])(?P<url>https?://[^'\"]*)(?P=q)(?P<post>[^>]*)>", re.I)


def external_links(html: str) -> str:
    """Every link to another site opens in a new tab or window, without access back to this page (noopener)."""
    def add(m):
        attrs = m["pre"] + m["post"]
        if re.search(r"\btarget=", attrs, re.I):
            return m[0]
        return f"<a{m['pre']}href={m['q']}{m['url']}{m['q']}{m['post']} target='_blank' rel='noopener noreferrer'>"
    return EXTERNAL_A.sub(add, html)


SITE = "https://containerizer.eu"
# the front page's brand line, above its title: the logo and the name, linking to the project's site
BRAND = (f"<a class='brand' href='{SITE}/' title='Containerizer: which of your applications can run in containers?'>"
         f"<img src='/static/favicon.svg' alt='' width='28' height='28'><span>Containerizer</span></a>")
# every page's last line (no version: the server does not tell it to anyone, see version_string)
BRAND_FOOTER = (f"<p class='brand-foot'>Assessed with <a href='{SITE}/' target='_blank' rel='noopener noreferrer'>"
                f"Containerizer</a>, open source containerization assessment, generation and sandbox</p>")

# Set by serve() in development mode (CONTAINERIZER_DEV_NO_AUTH): shown at the top of every page.
DEV_BANNER = ""


def page(title: str, body: str, script: bool = False, refresh: int = 0) -> str:
    """`refresh`: reload the page every so many seconds (a running scan's progress page; no script needed)."""
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            + (f"<meta http-equiv='refresh' content='{int(refresh)}'>" if refresh > 0 else "") +
            f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>{e(title)} · Containerizer</title>"
            f"<link rel='stylesheet' href='/static/app.css'><link rel='icon' href='/static/favicon.svg' type='image/svg+xml'>"
            f"<script src='/static/theme.js'></script></head>"
            f"<body>{DEV_BANNER}<main>{external_links(body)}{BRAND_FOOTER}</main>{SCRIPT_TAG if script else ''}</body></html>")


CSS = """
.offer{margin:8px 0}.offer form.order{margin-top:6px}form.inline.order{display:inline}
.st-wait{color:#8a5a00;border-color:#c98a00}@media (prefers-color-scheme:dark){.st-wait{color:#ffc857;border-color:#ffc857}}
.newkey{border:2px solid #2e7d32;border-radius:8px;padding:10px 14px;margin:12px 0}.newkey pre{margin:8px 0 0;user-select:all}
.why-rating{background:var(--card);border-left:4px solid #e0a800;padding:8px 12px;margin:10px 0}section.refactor h3{font-size:16px;margin:16px 0 4px}
table.make-a tr.under td:first-child{box-shadow:inset 3px 0 0 #2e7d32}
.notice{padding:10px 14px;border-radius:8px;margin:10px 0;border:1px solid}.notice-ok{background:#e8f5e9;border-color:#2e7d32;color:#1b5e20}.notice-info{background:#e3f2fd;border-color:#1565c0;color:#0d47a1}.notice-bad{background:#fdecea;border-color:#c62828;color:#8e1c1c}@media (prefers-color-scheme:dark){.notice-ok{background:#16301a;color:#b9f6ca}.notice-info{background:#132a40;color:#bbdefb}.notice-bad{background:#3a1715;color:#ffcdd2}}
.adminlinks{margin:2px 0 0}.topnav-right{display:inline-flex;flex-direction:column;align-items:flex-end;gap:4px}
a.brand{display:inline-flex;align-items:center;gap:6px;color:var(--fg);text-decoration:none;font-weight:650;font-size:15px;
letter-spacing:.01em}a.brand img{display:block;width:22px;height:22px}a.brand:hover span{text-decoration:underline}
.brand-foot{margin:40px 0 0;padding-top:12px;border-top:1px solid var(--line);
color:var(--muted);font-size:12px;text-align:center}.brand-foot a{color:var(--muted)}
.devmode{background:#b3261e;color:#fff;padding:8px 16px;text-align:center;font-size:14px}.devmode b{color:#fff}
:root{--bg:#f9f9f7;--card:#fff;--fg:#0b0b0b;--muted:#5f5e58;--line:#e1e0d9;--link:#1f5fbf;
--rA:#0ca30c;--rB:#74c476;--rC:#fab219;--rD:#ec835a;--rE:#d03b3b}
@media (prefers-color-scheme:dark){:root{--bg:#1a1a19;--card:#232321;--fg:#f0efe9;--muted:#a8a69c;--line:#383835;--link:#7fb0ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 20px 48px}a{color:var(--link)}h1{font-size:28px;margin:0 0 4px}
h2{font-size:20px;margin:32px 0 8px}h3{font-size:16px;margin:20px 0 6px}h3 .small{font-weight:400}.muted{color:var(--muted)}.small{font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .label,.label{color:var(--muted);font-size:13px}.tile .value{font-size:30px;font-weight:650;line-height:1.2}
.small-value{font-size:20px!important}.unit{font-size:15px;color:var(--muted);font-weight:400}.tile .sub{color:var(--muted);font-size:13px}
.label{margin-right:6px;font-weight:600}
.bar{display:block;width:100%;margin:8px 0;border-radius:6px}.bu .bar{border-radius:5px}
.fA{fill:var(--rA)}.fB{fill:var(--rB)}.fC{fill:var(--rC)}.fD{fill:var(--rD)}.fE{fill:var(--rE)}
.rA{background:var(--rA)}.rB{background:var(--rB)}.rC{background:var(--rC)}.rD{background:var(--rD)}.rE{background:var(--rE)}
.legend{list-style:none;padding:0;margin:6px 0;display:flex;flex-wrap:wrap;gap:4px 18px;font-size:13px}
.key{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:baseline}
.badge{display:inline-block;width:28px;height:28px;line-height:28px;text-align:center;border-radius:6px;font-weight:700;color:#fff}
.badge.rB,.badge.rC{color:#0b0b0b}.badge.big{width:64px;height:64px;line-height:64px;font-size:34px;border-radius:12px;flex:none}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.chip{border:1px solid var(--line);border-radius:999px;padding:4px 12px;
text-decoration:none;color:var(--fg);background:var(--card)}.chip.on{border-color:var(--fg);font-weight:600}
section.bu{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 18px 14px;margin:18px 0}
table{border-collapse:collapse;width:100%;font-size:14px;background:var(--card)}th{font-weight:600;color:var(--muted);font-size:13px}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}.num{text-align:right;white-space:nowrap}
table.narrow{width:auto;min-width:420px}
header.app{display:flex;gap:18px;align-items:flex-start;margin-top:8px}.lead{font-size:17px;margin:4px 0}
.crumbs{font-size:13px;color:var(--muted)}.meta{display:grid;gap:4px;font-size:14px}
.sev{display:inline-block;font-size:12px;font-weight:600;border-radius:4px;padding:1px 7px;border:1px solid currentColor;white-space:nowrap}
.s-blocker{color:#b42727}.s-rewrite{color:#b85a2e}.s-refactor{color:#8a6100}.s-config,.s-info{color:#0a7d0a}
@media (prefers-color-scheme:dark){.s-blocker{color:#f07a7a}.s-rewrite{color:#f2a07f}.s-refactor{color:#fac35a}.s-config,.s-info{color:#4fd14f}}
.v-ok,.v-ok-external{color:#0a7d0a}.v-build-failed,.v-run-failed{color:#b42727}
.v-sb-healthy{color:#0a7d0a;font-weight:600}.v-sb-failing,.v-sb-not-found,.v-sb-error{color:#b42727;font-weight:600}
.v-sb-pending,.v-sb-scheduled{color:#8a6100}
@media (prefers-color-scheme:dark){.v-ok,.v-ok-external,.v-sb-healthy{color:#4fd14f}
.v-build-failed,.v-run-failed,.v-sb-failing,.v-sb-not-found,.v-sb-error{color:#f07a7a}.v-sb-pending,.v-sb-scheduled{color:#fac35a}}
.sandbox{margin-top:8px;padding:8px 10px;border-radius:6px;background:var(--bg)}.sandbox p{margin:4px 0}
ul.events{margin:4px 0;padding-left:18px}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0}
summary{cursor:pointer}.finding{border-top:1px solid var(--line);padding:10px 0 4px;margin-top:10px}.finding p{margin:4px 0}
.obstacles{padding-left:18px}.obstacles li{margin:4px 0}
.note{background:var(--card);border-left:4px solid var(--rC);padding:8px 12px;border-radius:4px}
.mail-body{white-space:pre-wrap;word-break:break-word;background:var(--card);border:1px solid var(--line);padding:10px 12px;border-radius:6px;max-height:70vh;overflow:auto}
footer{margin-top:36px;border-top:1px solid var(--line);padding-top:12px}code{font-size:13px}
.topnav{display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:14px;margin-bottom:12px}
form.inline{display:inline}button{font:inherit;border:1px solid var(--fg);background:var(--fg);color:var(--bg);border-radius:6px;
padding:6px 14px;cursor:pointer}button.link{border:0;background:none;color:var(--link);padding:0;text-decoration:underline}
form.edit{display:grid;gap:6px;max-width:640px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
form.edit label{font-weight:600;font-size:14px;margin-top:6px}form.edit label.check{font-weight:400}
input:not([type=checkbox]):not([type=radio]),select,textarea{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;
background:var(--bg);color:var(--fg);width:100%}.formrow{display:flex;gap:10px;align-items:center;margin:12px 0;flex-wrap:wrap}
.formrow select{width:auto;min-width:260px}form.danger button{background:#b42727;border-color:#b42727;color:#fff;margin-top:12px}
ul.changes{margin:2px 0;padding-left:18px}del{color:var(--muted)}ins{text-decoration:none;font-weight:600}.nowrap{white-space:nowrap}
.ext{white-space:nowrap;font-weight:400}
section.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 18px 14px;margin:18px 0}
section.card details{border:0;padding:0;background:none}
.chart{display:block;width:100%;height:auto;margin:6px 0;--grid:#e1e0d9;--axis:#c3c2b7;--o1:#2a78d6;--o2:#eb6834}
@media (prefers-color-scheme:dark){.chart{--grid:#2c2c2a;--axis:#4a4a46;--o1:#3987e5;--o2:#d95926}}
.chart .grid{stroke:var(--grid);stroke-width:1}.chart .axis{stroke:var(--axis);stroke-width:1}
.chart .tick{fill:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}.chart .val{fill:var(--fg);font-size:13px;font-weight:600}
.chart .hit{fill:transparent}.chart g:hover .hit{fill:var(--line);fill-opacity:.35}
.chart .line{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.chart .line.o1{stroke:var(--o1)}.chart .line.o2{stroke:var(--o2)}
.chart .dot{stroke:var(--card);stroke-width:2}.chart .dot.o1{fill:var(--o1)}.chart .dot.o2{fill:var(--o2)}
.lkey{display:inline-block;width:14px;height:2px;border-radius:1px;margin-right:6px;vertical-align:middle}
.legend .lkey.o1{background:#2a78d6}.legend .lkey.o2{background:#eb6834}
@media (prefers-color-scheme:dark){.legend .lkey.o1{background:#3987e5}.legend .lkey.o2{background:#d95926}}
.strip{display:inline-flex;gap:2px}.cell{display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;
font-size:11px;font-weight:700;border-radius:4px;color:#fff}.cell.rB,.cell.rC{color:#0b0b0b}
.cell.none{background:var(--line);opacity:.5}
.good{color:#006300;font-weight:600}.bad{color:#b42727;font-weight:600}
@media (prefers-color-scheme:dark){.good{color:#4fd14f}.bad{color:#f07a7a}}
.chips+.chips{margin-top:8px}
.tag.auto{font-style:italic}.stateful-mark{display:inline-block;margin-left:6px;font-size:12px;padding:1px 6px;border:1px solid currentColor;border-radius:8px;opacity:.8;vertical-align:middle}
.chips.tags{align-items:center}.chip.tagchip{font-size:13px;padding:2px 10px}
span.role{display:inline-flex;gap:6px;align-items:center;border:1px solid var(--line);border-radius:999px;padding:1px 10px;font-size:13px;
margin:2px 6px 2px 0;background:var(--card)}span.role.admin{font-weight:600;border-color:var(--fg)}span.role button.link{text-decoration:none;font-size:15px;line-height:1}
a.tag{display:inline-block;font-size:12px;line-height:1.5;padding:0 8px;margin-left:4px;border-radius:999px;border:1px solid var(--line);
background:var(--card);color:var(--muted);text-decoration:none;vertical-align:1px}a.tag:hover{color:var(--fg);border-color:var(--fg)}
.tags-row{margin:12px 0;font-size:14px}.tags-row .label{margin-right:2px}.tagform{margin:8px 0 0}.formrow.tagform input:not([type=hidden]):not([type=checkbox]){min-width:340px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.a-patch{font-size:12px;font-weight:700;color:var(--muted);margin-left:4px;white-space:nowrap}.a-patch.here{color:#0a7d0a}
@media (prefers-color-scheme:dark){.a-patch.here{color:#4fd14f}}
.a-patches,.running{margin:18px 0}.a-patches table,.running table{margin-top:6px}.in-sandbox{margin:8px 0 0}
@media (forced-colors:active){.bar,.badge,.key,.cell,.chart{forced-color-adjust:none;border:1px solid CanvasText}}
.st{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;border:1px solid currentColor;white-space:nowrap}
.st-ok{color:#0a7d0a}.st-bad{color:#b42727}.st-off{color:var(--muted)}.st-run{color:#1f5fbf}
@media (prefers-color-scheme:dark){.st-ok{color:#4fd14f}.st-bad{color:#f07a7a}.st-run{color:#7fb0ff}}
form.edit h3{margin:14px 0 0;font-size:15px;border-top:1px solid var(--line);padding-top:12px}.days{display:flex;flex-wrap:wrap;gap:4px 14px}
button.secondary{background:var(--card);color:var(--fg)}.formrow input:not([type=checkbox]):not([type=radio]){width:auto;min-width:240px}
.migration{border-top:1px solid var(--line);margin-top:12px;padding-top:4px}.migration table{margin:6px 0}
.st{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;border:1px solid currentColor;white-space:nowrap}
.st-ok{color:#0a7d0a}.st-bad{color:#b42727}.st-off{color:var(--muted)}.st-run{color:#1f5fbf}
@media (prefers-color-scheme:dark){.st-ok{color:#4fd14f}.st-bad{color:#f07a7a}.st-run{color:#7fb0ff}}
button.secondary{background:var(--card);color:var(--fg)}button[disabled]{opacity:.5;cursor:not-allowed}
pre.code,textarea.code{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre.code{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow:auto;
white-space:pre-wrap;word-break:break-word;max-height:460px}
pre.diff .add{color:#0a7d0a}pre.diff .del{color:#b42727}pre.diff .hunk{color:var(--muted)}
@media (prefers-color-scheme:dark){pre.diff .add{color:#4fd14f}pre.diff .del{color:#f07a7a}}
form.edit.wide{max-width:none;margin:12px 0}nav.chips+div.meta{margin-top:16px}
.st-warn{color:#8a6100}@media (prefers-color-scheme:dark){.st-warn{color:#fac35a}}
a.button{display:inline-block;border:1px solid var(--fg);background:var(--fg);color:var(--bg);border-radius:6px;
padding:6px 14px;text-decoration:none}section.refactor .formrow select{min-width:220px}section.refactor label.check{display:inline-flex;gap:6px;align-items:center;margin:0}
section.diff{margin:14px 0;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--card)}
.diff-file{padding:6px 10px;border-bottom:1px solid var(--line);font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.diff-stat{float:right}.diff-add{color:#0a7d0a}.diff-del{color:#b42727}
table.diff{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;table-layout:auto}
table.diff td{padding:0 8px;border:0;white-space:pre-wrap;word-break:break-word}
table.diff td.ln{width:1%;min-width:3.5em;text-align:right;color:var(--muted);user-select:none;white-space:nowrap}
table.diff tr.add td{background:#e6f4e6}table.diff tr.del td{background:#fbe9e9}
table.diff tr.hunk td{background:var(--bg);color:var(--muted)}table.diff tr.note td{color:var(--muted)}
table.diff .sign{display:inline-block;width:1.2em;color:var(--muted);user-select:none}
@media (prefers-color-scheme:dark){.diff-add{color:#4fd14f}.diff-del{color:#f07a7a}
table.diff tr.add td{background:#16351a}table.diff tr.del td{background:#3d1a1a}}
ol.steps li{margin:6px 0}ol.steps pre.code{margin:4px 0}ul.checks{padding-left:18px}ul.checks li{margin:6px 0}
.dbwrap{overflow-x:auto;margin:10px 0}table.dbrows{font-size:13px}table.dbrows td{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
white-space:pre;vertical-align:top}table.dbrows th{white-space:nowrap;vertical-align:bottom}
.dbkey{font-size:10px;font-weight:600;border:1px solid currentColor;border-radius:4px;padding:0 4px;margin-left:4px;color:var(--muted)}
table.dbrows th a{color:inherit}table.dbrows .null{color:var(--muted);font-style:italic}.dbtype{display:block;font-weight:400;font-size:11px;color:var(--muted)}
.dbpick select{min-width:340px}form.dbfilter{margin:10px 0}form.dbfilter select{min-width:0}form.dbfilter input:not([type=hidden]){min-width:220px}
.dbfield{display:grid;grid-template-columns:minmax(160px,220px) 1fr auto;gap:8px;align-items:start;padding:6px 0;border-top:1px solid var(--line)}
.dbfield label{margin:0}.dbfield .dbval{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.dbfield .opts{display:flex;gap:10px;white-space:nowrap;font-size:13px}.pager{display:flex;gap:14px;align-items:center;margin:8px 0}
form.inline-form{display:flex;gap:6px;align-items:center;margin:0}form.inline-form select{width:auto;min-width:180px}
table.devs td.repos{max-width:420px}table.devs details.more{border:0;padding:0;margin:2px 0;background:none;display:inline}
table.devs details.more summary{font-size:13px;color:var(--muted);cursor:pointer}td.num{text-align:right}
table.devs select{width:auto;min-width:150px}span.sugg.sure{font-weight:600}
nav.chips.sub{margin-top:10px;gap:6px}nav.chips.sub .chip{font-size:13px;padding:2px 10px}
.formrow input.wide:not([type=checkbox]){min-width:380px}
"""

# The only script (admin pages): a header checkbox that checks or clears the checkboxes of its column.
JS = """// a header checkbox with data-select-all='<name>' checks or clears every checkbox of that name in its form
document.addEventListener('change', function (ev) {
  var all = ev.target;
  var name = all.getAttribute && all.getAttribute('data-select-all');
  if (!name || !all.form) return;
  var boxes = all.form.querySelectorAll('input[type=checkbox]');
  for (var i = 0; i < boxes.length; i++) if (boxes[i].name === name) boxes[i].checked = all.checked;
});
"""

HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",       # cross-site: nothing; same-site POSTs keep a real Origin for the CSRF check
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cache-Control": "no-store",
}


def _keep_query(path: str, q: dict) -> str:
    """The validated filters of a results page, kept through sign-in and written to the access log."""
    if path == "/trends":
        from .trends import parse_query
        rng, bu, product = parse_query(q)
        return urlencode([(k, v) for k, v in (("range", rng), ("bu", bu), ("product", product)) if v is not None])
    if path == "/connectivity":
        return urlencode([(k, q[k][0]) for k in ("product", "bu") if re.fullmatch(r"\d{1,9}", (q.get(k) or [""])[0])])
    if path == "/":
        bu = q.get("bu", [None])[0]
        return f"bu={bu}" if bu and re.fullmatch(r"\d{1,9}|none", bu) else ""
    return ""


def make_handler(connect, admin=None):
    """`connect()` returns a reader connection for one request; `admin` is an admin.Admin or None."""

    class Handler(BaseHTTPRequestHandler):
        def version_string(self):
            return "containerizer"

        def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8", head: bool = False,
                  extra: list | None = None, forms: bool = False):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in HEADERS.items():
                if forms and k == "Content-Security-Policy":
                    v = v.replace("form-action 'none'", "form-action 'self'")
                self.send_header(k, v)
            if admin and admin.cfg.secure:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(data)

        def do_HEAD(self):
            self.do_GET(head=True)

        def _admin(self, method: str, head: bool = False):
            u = urlsplit(self.path)
            body = b""
            if method == "POST" and admin.is_upload(u.path):
                # dev database backups: streamed to disk by admin_devdb.py, never held in memory
                self.close_connection = True               # the body may be left unread on a refusal
                self.connection.settimeout(120)            # a stalled upload does not hold a thread forever
                n = int(self.headers.get("Content-Length") or 0)
                body_in = _CountingReader(self.rfile)
                r = admin.handle_upload(u.path, self.headers, body_in, n)
                # A refusal can come before the whole body is read (too large, not a backup). Read and drop
                # a bounded rest first, so the client is not cut off mid-send and gets the page that says why.
                left = n - body_in.count
                if 0 < left <= UPLOAD_DRAIN_MAX:
                    try:
                        while left > 0:
                            chunk = self.rfile.read(min(left, 1 << 16))
                            if not chunk:
                                break
                            left -= len(chunk)
                    except OSError:
                        pass
                return self._send(r.status, r.body, r.ctype, head, r.headers, forms=True)
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > 64 * 1024:
                    return self._send(413, page("Too large", "<h1>Request too large</h1>"))
                body = self.rfile.read(n)
            r = admin.handle(method, u.path, u.query, self.headers, body, self.client_address[0])
            return self._send(r.status, r.body, r.ctype, head, r.headers, forms=True)

        def _api(self, method: str, head: bool = False):
            u = urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, 64 * 1024 + 1)) if n else b""
            r = admin.api.handle(method, u.path, parse_qs(u.query), self.headers, body)
            return self._send(r.status, r.body, r.ctype, head, r.headers)

        def _write(self, method: str):
            u = urlsplit(self.path)
            try:
                if admin and admin.api and admin.api.handles(u.path):
                    return self._api(method)
                if method == "POST" and admin and admin.handles(u.path):
                    return self._admin("POST")
                return self._not_allowed()
            except Exception as ex:
                return self._error(ex)

        def do_POST(self):
            return self._write("POST")

        def do_PATCH(self):
            return self._write("PATCH")

        def do_PUT(self):
            return self._write("PUT")

        def do_DELETE(self):
            return self._write("DELETE")

        def do_GET(self, head: bool = False):
            u = urlsplit(self.path)
            try:
                if u.path == "/static/app.css":
                    from .connectivityui import CSS as CONNECTIVITY_CSS
                    from .migrationplan import CSS as PLAN_CSS
                    from . import theme
                    return self._send(200, theme.themed(CSS + CONNECTIVITY_CSS + PLAN_CSS + theme.CSS),
                                      "text/css; charset=utf-8", head)
                if u.path == "/static/theme.js":
                    from .theme import JS as THEME_JS
                    return self._send(200, THEME_JS, "text/javascript; charset=utf-8", head)
                if u.path == "/static/app.js":
                    return self._send(200, JS, "text/javascript; charset=utf-8", head)
                if u.path in ("/static/favicon.svg", "/favicon.ico"):
                    return self._send(200, FAVICON, "image/svg+xml", head)
                if u.path == "/healthz":
                    return self._send(200, "ok", "text/plain; charset=utf-8", head)
                if admin and admin.api and admin.api.handles(u.path):
                    return self._api("GET", head)
                if admin and admin.handles(u.path):
                    return self._admin("GET", head)
                nav = admin.nav(self.headers) if admin else ""
                m = re.fullmatch(r"/app/(\d{1,9})", u.path)
                if admin and (u.path in ("/", "/trends", "/connectivity") or m):    # sign-in first when CONTAINERIZER_VIEWERS is set
                    keep = _keep_query(u.path, parse_qs(u.query))
                    stop, s = admin.gate(self.headers, u.path, keep)
                    if stop:
                        return self._send(stop.status, stop.body, stop.ctype, head, stop.headers, forms=True)
                    if s and not head and admin.viewers_required:
                        admin.log_access(s.user, s.name, "view", u.path + ("?" + keep if keep else ""),
                                         int(m[1]) if m else None, self.client_address[0])
                if u.path == "/connectivity":      # how the applications connect (connectivityui.py)
                    from . import connectivityui
                    q = parse_qs(u.query)
                    pr, bu = q.get("product", [""])[0], q.get("bu", [""])[0]
                    pr = int(pr) if re.fullmatch(r"\d{1,9}", pr or "") else None
                    bu = int(bu) if re.fullmatch(r"\d{1,9}", bu or "") else None
                    conn = connect()
                    try:
                        data = connectivityui.load_portfolio(conn, pr, bu)
                    finally:
                        conn.close()
                    name = next((a.get("ProductName") for a in data["apps"] if pr is not None and a.get("ProductId") == pr), None)
                    title = f"Connectivity: {name}" if name else "Connectivity of all applications"
                    return self._send(200, connectivityui.render_portfolio(data, title, nav), head=head, forms=bool(nav))
                if u.path == "/trends":
                    from . import trends
                    rng, bu, product = trends.parse_query(parse_qs(u.query))
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    since = trends.since_for(rng, now)
                    conn = connect()
                    try:
                        data = trends.compute(trends.load_history(conn, since), now, since)
                    finally:
                        conn.close()
                    return self._send(200, trends.render_trends(data, rng, bu, product, nav), head=head, forms=bool(nav))
                if u.path == "/" or m:
                    conn = connect()
                    try:
                        if m:
                            app = load_application(conn, int(m[1]))
                            if app is None:
                                return self._send(404, page("Not found", "<h1>Application not found</h1><p><a href='/'>Back</a></p>"),
                                                  head=head)
                            from .connectivityui import notice_code
                            ctx = {"signin": bool(admin), "notice": refactor_notice(parse_qs(u.query)),
                                   "egress_notice": notice_code(parse_qs(u.query)),
                                   "link_notice": notice_code(parse_qs(u.query), "link")}
                            s, cookie = admin.dev_session(self.headers) if admin else (None, [])
                            if s and (s.admin or s.operator or s.scopes):   # may order (product owners: their products)
                                ctx["csrf"] = admin._csrf(s)
                                if app.get("Rating") == "B":
                                    ctx["estimates"] = refactor_estimates(admin, app)
                            if s and (s.admin or s.operator):                   # may tag it (tags.py)
                                ctx["tags_csrf"] = admin._csrf(s)
                            ctx["tags_notice"] = parse_qs(u.query).get("tags", [""])[0]
                            if s and (s.admin or s.operator):                   # may scan it again (scanagain.py)
                                ctx.update(scan_again_ctx(admin, app))
                                ctx["scan_csrf"] = admin._csrf(s)
                            ctx["lab_admin"] = bool(s and s.admin)              # may turn lab services on
                            ctx["lab_mail"] = bool(s and (s.admin or s.operator) and getattr(admin, "system", None))
                            ctx["scan_notice"] = parse_qs(u.query).get("scanagain", [""])[0]
                            if s and (s.admin or s.operator or s.scopes):
                                ctx["admin_links"] = admin_links(admin, conn, s, app)
                            return self._send(200, render_application(app, nav, ctx), head=head, forms=bool(nav),
                                              extra=cookie or None)
                        bu = parse_qs(u.query).get("bu", [None])[0]
                        if bu is not None and not re.fullmatch(r"\d{1,9}|none", bu):
                            bu = None
                        tag = " ".join(parse_qs(u.query).get("tag", [""])[0].split()) or None
                        if tag is not None and not TAG_RE.fullmatch(tag):
                            tag = None
                        s, cookie = admin.dev_session(self.headers) if admin else (None, [])
                        sees_unmapped = admin is None or bool(s and s.admin)
                        return self._send(200, render_overview(load_overview(conn), bu, nav, tag, sees_unmapped),
                                          head=head, forms=bool(nav), extra=cookie or None)
                    finally:
                        conn.close()
                return self._send(404, page("Not found", "<h1>Not found</h1><p><a href='/'>Back</a></p>"), head=head)
            except Exception as ex:      # never show internals to the browser
                return self._error(ex, head)

        def _error(self, ex, head: bool = False):
            print(f"error: {self.command} {urlsplit(self.path).path}: {type(ex).__name__}: {ex}", file=sys.stderr)
            return self._send(500, page("Error", "<h1>Something went wrong</h1><p>The results database could not be "
                                                 "read or updated. The details are in the server log.</p>"), head=head)

        def _not_allowed(self):
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD" + (", POST" if admin else ""))
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_OPTIONS = _not_allowed

        def log_request(self, code="-", size="-"):
            # the path only: query strings can carry sign-in codes
            print(f"{self.address_string()} {self.command} {urlsplit(self.path).path} {code}", file=sys.stderr)

        def log_message(self, fmt, *args):
            print(f"{self.address_string()} {fmt % args}", file=sys.stderr)

    return Handler


def serve(cs: str | None, host: str = "127.0.0.1", port: int = 8080) -> int:
    global DEV_BANNER
    from .admin import build
    from .oidc import OidcError
    from .roles import role_label
    from .sqlstore import SqlError, connect
    try:
        connect(cs).close()           # fail fast on a bad connection string or credentials
        admin = build()
        if admin and admin.dev:
            DEV_BANNER = (f"<div class='devmode' role='alert'><b>Development mode: no sign-in.</b> Everyone who can reach "
                          f"this page uses it as {e(admin.dev.name)} ({e(role_label(admin.dev.admin, admin.dev.operator, []) or 'viewer')}). "
                          f"Never on the appliance or a shared network.</div>")
        if admin:
            admin.connect_admin().close()
    except (SqlError, OidcError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 3
    httpd = ThreadingHTTPServer((host, port), make_handler(lambda: connect(cs), admin))
    print(f"containerizer results UI on http://{host}:{port}/ ("
          + ("results behind sign-in" + (", access logged" if admin.cfg.view_audit else "") if admin and admin.viewers_required
             else "results read-only without sign-in") + "; "
          + (f"admin pages WITHOUT sign-in (development mode) at {admin.cfg.public_url}/admin" if admin and admin.dev
             else f"admin pages behind sign-in at {admin.cfg.public_url}/admin" if admin else "admin pages off: no sign-in configured")
          + ("; JSON API at /api/v1)" if admin and admin.api else ")"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
