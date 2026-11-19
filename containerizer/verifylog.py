"""The whole build and run logs of a component whose verification failed (cz.ComponentVerifyLog, schema 61), for
download from the application's results page: /admin/verify-log/<assessment>/<component>/<stage>-<attempt>.log.

Administrators and operators only, read with the admin login: a log carries what the build or the application
printed (secrets are masked when it is stored, sqlstore.verify_logs). The results page's own excerpt
(ComponentAssessment.VerifyDetail) is 2000 characters, which is often not where the error is."""
from __future__ import annotations

import gzip
import re

NAME_RE = re.compile(r"(build|run)-(\d{1,2})\.log")


def available(admin, app: dict) -> dict:
    """{ComponentId: [{"stage", "attempt", "chars", "truncated", "url"}]} of the application's latest assessment;
    nothing when it cannot be read (a database before schema 61)."""
    try:
        conn = admin.connect_admin()
    except Exception:  # noqa: BLE001
        return {}
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT l.AssessmentId, l.ComponentId, l.Attempt, l.Stage, l.Chars, l.Truncated "
                    "FROM cz.ComponentVerifyLog l WHERE l.AssessmentId = (SELECT MAX(AssessmentId) FROM "
                    "cz.ApplicationAssessment WHERE ApplicationId = %s) ORDER BY l.ComponentId, l.Attempt, l.Stage",
                    (int(app["ApplicationId"]),))
        out: dict = {}
        for r in cur.fetchall():
            out.setdefault(r["ComponentId"], []).append({
                "stage": r["Stage"], "attempt": int(r["Attempt"]), "chars": int(r["Chars"]), "truncated": bool(r["Truncated"]),
                "url": f"/admin/verify-log/{int(r['AssessmentId'])}/{int(r['ComponentId'])}/{r['Stage']}-{int(r['Attempt'])}.log"})
        return out
    except Exception:  # noqa: BLE001 - no table before schema 61
        return {}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def links_html(logs: list[dict] | None) -> str:
    """The download links of one component, for its Build and run block."""
    from .webui import e
    if not logs:
        return ""
    items = " · ".join(
        f"<a href='{e(x['url'])}'>{e(x['stage'])}, attempt {int(x['attempt'])}</a> "
        f"<span class='muted'>({max(1, round(x['chars'] / 1024)):,} KB{', its end' if x.get('truncated') else ''})</span>"
        for x in logs)
    return (f"<p class='small'><span class='label'>Whole log</span> {items} <span class='muted'>· secrets masked; for "
            "administrators and operators</span></p>")


def route(adm, conn, s, a, method: str, parts: list):
    from .admin import Response, page
    if not (a.admin or a.operator):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    m = NAME_RE.fullmatch(parts[3]) if len(parts) == 4 and method == "GET" else None
    if not m or not re.fullmatch(r"\d{1,9}", parts[1]) or not re.fullmatch(r"\d{1,9}", parts[2]):
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT l.LogGz, c.Name AS ComponentName, COALESCE(ap.DisplayName, ap.Name) AS ApplicationName "
                "FROM cz.ComponentVerifyLog l JOIN cz.Component c ON c.ComponentId = l.ComponentId "
                "JOIN cz.Application ap ON ap.ApplicationId = c.ApplicationId "
                "WHERE l.AssessmentId = %s AND l.ComponentId = %s AND l.Stage = %s AND l.Attempt = %s",
                (int(parts[1]), int(parts[2]), m[1], int(m[2])))
    rows = cur.fetchall()
    if not rows:
        return Response(404, page("Not found", "<h1>Not found</h1><p>This scan kept no such log.</p>"))
    try:
        data = gzip.decompress(bytes(rows[0]["LogGz"]))
    except (OSError, EOFError, ValueError, TypeError):
        return Response(404, page("Not found", "<h1>Not found</h1><p>The log cannot be read.</p>"))
    name = "-".join(re.sub(r"[^A-Za-z0-9._-]+", "-", str(x or "")).strip("-")[:60] or "x"
                    for x in (rows[0]["ApplicationName"], rows[0]["ComponentName"])) + f"-{m[1]}-{int(m[2])}.log"
    return Response(200, data, [("Content-Disposition", f'attachment; filename="{name}"'),
                                ("X-Content-Type-Options", "nosniff")], ctype="text/plain; charset=utf-8")
