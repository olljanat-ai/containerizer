"""Try again: an administrator or operator scans one application again from its results page, when a component is
not in the sandbox (left out by the scan's security gate, by its build-and-run, ...). It queues a full scan of only
the application's repository (cz.QueueOrgScanRun with a scope, as Admin → Repositories → Scan now), and the page
says while that scan is queued or running; afterwards the Sandbox cells show the new result, with what failed
(org.gate_detail) when a component is still left out.

POST /admin/scan-again/<ApplicationId> (admin.py routes it; the CSRF token is checked there).
"""
from __future__ import annotations

import json
import re
import sys
from html import escape

NOTICES = {"queued": ("ok", "Scan queued: the scan worker starts it within a minute. This page shows the result when "
                            "it is done."),
           "busy": ("bad", "Not queued: a scan of this organization is queued or running, or the scan is paused. Try "
                           "again when it is done."),
           "none": ("bad", "No organization scan lists this application's repository: there is nothing to scan again "
                           "here (Admin → Organization scans)."),
           "unavailable": ("bad", "Not queued: the results database could not be asked.")}


def may_scan(s) -> bool:
    """Administrators and operators."""
    return bool(s and (s.admin or s.operator))


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{escape(text)}</div>"


def repositories(conn, app_id: int) -> list[dict]:
    """The organization scans' repositories of an application: its repository (a split repository: the whole of it)."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT o.RepositoryId, o.ScanId, o.ProjectName + N'/' + o.Name AS Name, o.LastScannedAt, o.LastStatus "
                "FROM cz.OrgRepository o JOIN cz.Application a ON a.RepositoryUrl = o.RepositoryUrl "
                "WHERE a.ApplicationId = %s AND o.RemovedAt IS NULL", (app_id,))
    return cur.fetchall()


def state(conn, app_id: int) -> dict:
    """What the page shows next to the button: the runs of the application's repositories queued or running now
    ([{RunId, Status, QueuedAt, StartedAt}]) and when they were last scanned. Needs the admin login (the reader
    reads no OrgRepository)."""
    repos = repositories(conn, app_id)
    if not repos:
        return {"repos": 0, "runs": [], "scanned_at": None}
    cur = conn.cursor(as_dict=True)
    scans = sorted({int(r["ScanId"]) for r in repos})
    cur.execute("SELECT RunId, ScanId, Status, RequestedAt AS QueuedAt, StartedAt, Scope FROM cz.OrgScanRun "
                f"WHERE ScanId IN ({', '.join(['%s'] * len(scans))}) AND Status IN (N'queued', N'running') "
                "ORDER BY RunId", tuple(scans))
    names = {str(r["Name"]) for r in repos}
    runs = []
    for r in cur.fetchall():
        try:
            scope = json.loads(r.get("Scope") or "null")
        except ValueError:
            scope = None
        if scope and names.isdisjoint(scope.get("repositories") or []) and not scope.get("projects"):
            continue                    # a run of other repositories of the same scan
        runs.append({k: r[k] for k in ("RunId", "Status", "QueuedAt", "StartedAt")})
    scanned = [r["LastScannedAt"] for r in repos if r.get("LastScannedAt")]
    return {"repos": len(repos), "runs": runs, "scanned_at": max(scanned) if scanned else None}


def route(adm, conn, s, a, method: str, parts: list, form: dict):
    from .admin import Response, page, redirect
    if not (a.admin or a.operator):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    if len(parts) != 2 or method != "POST" or not re.fullmatch(r"\d{1,9}", parts[1]):
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    app_id = int(parts[1])

    def back(code: str):
        return redirect(f"/app/{app_id}?scanagain={code}#components")
    try:
        repos = repositories(conn, app_id)
        if not repos:
            return back("none")
        by_scan: dict = {}
        for r in repos:
            by_scan.setdefault(int(r["ScanId"]), []).append(str(r["Name"]))
        queued = 0
        cur = conn.cursor()
        for scan_id, names in sorted(by_scan.items()):
            cur.execute("EXEC cz.QueueOrgScanRun @ScanId = %s, @TriggeredBy = N'manual', @Kind = N'full', @Scope = %s",
                        (scan_id, json.dumps({"projects": [], "repositories": sorted(set(names))})))
            rid = (cur.fetchone() or [0])[0]
            conn.commit()
            queued += 1 if rid else 0
    except Exception as ex:  # noqa: BLE001 - a database from before the organization scans
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        print(f"scan again of application {app_id}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return back("unavailable")
    return back("queued" if queued else "busy")


def section(app: dict, ctx: dict, excluded: list[dict]) -> str:
    """Under the Components table, for administrators and operators when a component is not in the sandbox: the
    state of a scan of it and the Try again button."""
    if not ctx.get("scan_csrf"):
        return ""
    st = ctx.get("scan_state") or {}
    runs = st.get("runs") or []
    names = ", ".join(c["ComponentName"] for c in excluded[:6]) + (" ..." if len(excluded) > 6 else "")
    out = [f"<div class='scan-again' id='scan-again'>{notice_html(ctx.get('scan_notice') or '')}"]
    if runs:
        r = runs[-1]
        when = r.get("StartedAt") or r.get("QueuedAt")
        out.append(f"<p class='note small'>Scan #{int(r['RunId'])} of this application is {escape(str(r['Status']))} "
                   f"(since {escape(str(when)[:16])} UTC): the Sandbox column shows its result when it is done. "
                   "Reload this page to see it.</p>")
    elif excluded:
        out.append(f"<form method='post' action='/admin/scan-again/{int(app['ApplicationId'])}' class='inline'>"
                   f"{ctx['scan_csrf']}<button>Try again</button></form> <span class='muted small'>Not in the sandbox: "
                   f"{escape(names)}. Scans this application again now (build, check, deploy); a component still left "
                   "out shows what failed (<b>What failed</b> in its Sandbox cell).</span>")
    out.append("</div>")
    return "".join(out)
