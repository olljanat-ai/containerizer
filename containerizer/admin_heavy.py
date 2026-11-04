"""LLM-heavy windows (Admin -> Applications, docs/source-control.md#llm-heavy-for-a-while).

An administrator turns LLM-heavy mode on for one application, or one of its components, for some hours
(cz.LlmHeavyWindow). Until the window ends:

- its LLM jobs (component reviews, refactoring, egress and link reviews) need no approval: those waiting are
  approved at once (cz.AutoApproveLlmJobs), new ones are queued approved (cz.QueueLlmJob);
- they go before every other job in the LLM queue (cz.fnLlmJobHeavy, llmqueue.HEAVY_FIRST);
- scans with queued LLM reviews queue a review of each of its components, not only the uncertain ones
  (llmqueue.queue_reviews, reason `heavy`);
- scans run LLM-heavy mode for it (platform migrations and the sandbox tester ask the LLM) when the appliance
  allows LLM-heavy mode (CZ_LLM_HEAVY) and the scan asks the LLM (org.OrgOptions.heavy).

The form is on the application's admin page; the windows still open are listed there and on the LLM queue
page, each with End now.
"""
from __future__ import annotations

import re
from urllib.parse import urlencode

from .admin import Response, _d, e, redirect

HOURS = (1, 2, 4, 8, 12, 24, 48, 72, 168)       # the choices of the form; the table allows 1 to 168
DEFAULT_HOURS = 8


def active(conn, app_id: int | None = None) -> list[dict]:
    """The windows open now (cz.vLlmHeavyActive), of one application or all, the one ending first first."""
    cur = conn.cursor(as_dict=True)
    where, args = ("WHERE ApplicationId = %s", (app_id,)) if app_id is not None else ("", ())
    cur.execute(f"SELECT WindowId, ApplicationId, ApplicationName, ProjectPath, Component, StartsAt, EndsAt, Hours, "
                f"CreatedBy, CreatedByName FROM cz.vLlmHeavyActive {where} ORDER BY EndsAt, WindowId", args)
    return cur.fetchall()


def _scope(w: dict) -> str:
    return f"component <b>{e(w['Component'] or w['ProjectPath'])}</b>" if w.get("ProjectPath") else "the whole application"


def windows_html(adm, s, a, rows: list[dict], back: str, with_app: bool = False) -> str:
    """The open windows as a table, with End now for administrators."""
    if not rows:
        return ""
    trs = []
    for w in rows:
        app = (f"<td><a href='/admin/applications/{int(w['ApplicationId'])}'>{e(w['ApplicationName'])}</a></td>"
               if with_app else "")
        end = (f"<form method='post' action='/admin/llm-queue/heavy/{int(w['WindowId'])}/end' class='inline'>"
               f"{adm._csrf(s)}<input type='hidden' name='back' value='{e(back)}'>"
               f"<button class='secondary'>End now</button></form>") if a.admin else ""
        trs.append(f"<tr>{app}<td>{_scope(w)}</td><td class='small'>{_d(w['StartsAt'])}</td>"
                   f"<td class='small'><b>{_d(w['EndsAt'])}</b></td>"
                   f"<td class='small'>{e(w.get('CreatedByName') or w.get('CreatedBy') or '')}</td><td>{end}</td></tr>")
    head = "<th>Application</th>" if with_app else ""
    return (f"<table class='heavy'><thead><tr>{head}<th>LLM-heavy for</th><th>Since</th><th>Until</th><th>By</th>"
            f"<th></th></tr></thead><tbody>{''.join(trs)}</tbody></table>")


def _components(conn, app_id: int) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ComponentId, ProjectPath, Name FROM cz.Component WHERE ApplicationId = %s ORDER BY Name, ProjectPath",
                (app_id,))
    return cur.fetchall()


def section(adm, conn, s, a, app_id: int) -> str:
    """The application page's LLM-heavy section: the open windows and, for administrators, the form."""
    from .ai import heavy_allowed
    rows = active(conn, app_id)
    inline = ("Scans also run LLM-heavy mode for it: platform migrations and the sandbox tester ask the LLM as often as "
              "they need." if heavy_allowed() else
              "LLM-heavy mode in the scans themselves is off on this appliance (set CZ_LLM_HEAVY=true in "
              "/etc/containerizer/appliance.env and reboot); the queue part below still applies.")
    intro = (f"<p class='muted small'>For a few hours, give this application, or one of its components, all the LLM's "
             f"attention: its LLM jobs are approved automatically and go to the top of the LLM queue, and scans that "
             f"queue their LLM reviews queue a review of each of its components. {e(inline)} Every LLM call is counted "
             f"on the Grafana dashboard.</p>")
    form = ""
    if a.admin:
        opts = "<option value=''>The whole application</option>" + "".join(
            f"<option value='{int(c['ComponentId'])}'>{e(c['Name'])} ({e(c['ProjectPath'])})</option>"
            for c in _components(conn, app_id))
        hours = hours_options()
        form = (f"<form method='post' action='/admin/applications/{app_id}/heavy' class='edit'>{adm._csrf(s)}"
                f"<label for='Scope'>LLM-heavy for</label><select id='Scope' name='Scope'>{opts}</select>"
                f"<label for='Hours'>How long</label><select id='Hours' name='Hours'>{hours}</select>"
                f"<label class='check'><input type='checkbox' name='ScanNow' value='1' checked> Scan its repository now "
                f"(otherwise the reviews are queued at its next scheduled scan)</label>"
                f"<div><button>Turn on LLM-heavy</button></div></form>")
    return (f"<h2 id='llm-heavy'>LLM-heavy mode</h2>{intro}"
            f"{windows_html(adm, s, a, rows, f'/admin/applications/{app_id}')}{form}")


def hours_options(selected: int = DEFAULT_HOURS) -> str:
    """The <option>s of How long."""
    return "".join(f"<option value='{h}'{' selected' if h == selected else ''}>"
                   f"{h if h < 24 else h // 24} {('hour' if h == 1 else 'hours') if h < 24 else ('day' if h == 24 else 'days')}"
                   f"</option>" for h in HOURS)


def parse_hours(raw) -> int | None:
    return int(raw) if re.fullmatch(r"\d{1,3}", raw or "") and 1 <= int(raw) <= 168 else None


def open_window(conn, s, app_id: int, hours: int, comp: dict | None = None):
    """Insert an LLM-heavy window of the application (or one component) for `hours` from now; its end. The caller
    commits, and then approves what waits (llmqueue.auto_approve)."""
    cur = conn.cursor(as_dict=True)
    # no OUTPUT clause: the table has an audit trigger
    cur.execute("INSERT cz.LlmHeavyWindow (ApplicationId, ProjectPath, Component, EndsAt, Hours, CreatedBy, CreatedByName) "
                "VALUES (%s, %s, %s, DATEADD(hour, %s, SYSUTCDATETIME()), %s, %s, %s); "
                "SELECT EndsAt FROM cz.LlmHeavyWindow WHERE WindowId = SCOPE_IDENTITY()",
                (app_id, comp["ProjectPath"] if comp else None, comp["Name"] if comp else None, hours, hours,
                 s.user[:256], (s.name or "")[:256] or None))
    return cur.fetchone()["EndsAt"]


def _back(url: str, msg: str) -> Response:
    return redirect(url + ("&" if "?" in url else "?") + urlencode({"msg": msg}) + "#llm-heavy")


def start(conn, s, a, app_id: int, form: dict) -> Response:
    """Turn LLM-heavy mode on (administrators only): the whole application or one of its components."""
    back = f"/admin/applications/{app_id}"
    if not a.admin:
        return _back(back, "Only administrators turn LLM-heavy mode on.")
    hours = parse_hours(form.get("Hours", [""])[0])
    if hours is None:
        return _back(back, "Choose for how many hours (1 to 168).")
    scope = form.get("Scope", [""])[0]
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ApplicationId, RepositoryUrl, COALESCE(DisplayName, Name) AS Name FROM cz.Application "
                "WHERE ApplicationId = %s", (app_id,))
    app = cur.fetchone()
    if not app:
        return Response(404, "<h1>Application not found</h1>")
    comp = None
    if scope:
        if not re.fullmatch(r"\d{1,9}", scope):
            return _back(back, "Unknown component.")
        cur.execute("SELECT ProjectPath, Name FROM cz.Component WHERE ComponentId = %s AND ApplicationId = %s",
                    (int(scope), app_id))
        comp = cur.fetchone()
        if not comp:
            return _back(back, "That component is not part of this application.")
    try:
        ends = open_window(conn, s, app_id, int(hours), comp)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    from . import llmqueue as lq
    approved = lq.auto_approve(conn)
    what = f"{comp['Name']} of {app['Name']}" if comp else app["Name"]
    msg = f"LLM-heavy mode on for {what} until {_d(ends)}."
    if approved:
        msg += f" {approved} waiting job{'s' if approved != 1 else ''} approved."
    if form.get("ScanNow", [""])[0] == "1" and app.get("RepositoryUrl"):
        cur.execute("SELECT RepositoryId FROM cz.OrgRepository WHERE RepositoryUrl = %s AND RemovedAt IS NULL",
                    (app["RepositoryUrl"],))
        ids = [int(r["RepositoryId"]) for r in cur.fetchall()]
        if ids:
            from .admin_scans import scan_now
            r = scan_now(conn, [], ids, back)
            loc = dict(r.headers).get("Location", "")
            note = re.search(r"msg=([^&#]*)", loc)
            if note:
                from urllib.parse import unquote_plus
                msg += " " + unquote_plus(note.group(1))
        else:
            msg += " No organization scan lists its repository: it is reviewed at its next scan."
    return _back(back, msg)


def end(conn, s, a, window_id: int, form: dict) -> Response:
    """End a window now (administrators only)."""
    back = form.get("back", ["/admin/llm-queue"])[0]
    if not re.fullmatch(r"/admin/(llm-queue|applications/\d{1,9})", back):
        back = "/admin/llm-queue"
    if not a.admin:
        return _back(back, "Only administrators end LLM-heavy mode.")
    cur = conn.cursor()
    cur.execute("UPDATE cz.LlmHeavyWindow SET EndsAt = SYSUTCDATETIME(), EndedAt = SYSUTCDATETIME(), EndedBy = %s, "
                "EndedByName = %s WHERE WindowId = %s AND EndsAt > SYSUTCDATETIME()",
                (s.user[:256], (s.name or "")[:256] or None, window_id))
    n = cur.rowcount
    conn.commit()
    return _back(back, "LLM-heavy mode ended: its jobs take their usual place in the queue again." if n
                 else "That LLM-heavy window had already ended.")
