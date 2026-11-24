"""The whole build and run logs of a component whose verification failed (cz.ComponentVerifyLog, schema 61), for
download from the application's results page: /admin/verify-log/<assessment>/<component>/<stage>-<attempt>.log.

Administrators and operators only, read with the admin login: a log carries what the build or the application
printed (secrets are masked when it is stored, sqlstore.verify_logs). The results page's own excerpt
(ComponentAssessment.VerifyDetail) is 2000 characters, which is often not where the error is.

A build log starts with what was built and how (header: the `docker build` command and the Dockerfile of that
attempt, from 0.54.3). /admin/verify-log/<assessment>/<component>/dockerfile-<attempt>.txt shows that part alone,
in the browser."""
from __future__ import annotations

import gzip
import re

NAME_RE = re.compile(r"(build|run)-(\d{1,2})\.log|(dockerfile)-(\d{1,2})\.txt")
H_CMD, H_FILE, H_OUT = ("==== containerizer: the build command ====", "==== containerizer: the Dockerfile ====",
                        "==== containerizer: the build's output ====")


def header(cmd: str, dockerfile: str) -> str:
    """What a stored build log starts with: the command and the Dockerfile of the attempt."""
    return f"{H_CMD}\n{cmd.strip()}\n\n{H_FILE}\n{dockerfile.rstrip()}\n\n{H_OUT}\n"


def header_of(text: str) -> str:
    """The command and the Dockerfile of a stored build log; "" for a log without them (a scan before 0.54.3)."""
    end = text.find("\n" + H_OUT + "\n")
    return text[:end].rstrip() + "\n" if text.startswith(H_CMD + "\n") and end > 0 else ""


def _has_header(start) -> bool:
    """Whether a stored log begins with the header, from the first bytes of its gzip."""
    import zlib
    try:
        return zlib.decompressobj(31).decompress(bytes(start or b""), len(H_CMD) + 8).decode("utf-8", "replace").startswith(H_CMD)
    except (zlib.error, TypeError, ValueError):
        return False


def available(admin, app: dict) -> dict:
    """{ComponentId: [{"stage", "attempt", "chars", "truncated", "url"}]} of the application's latest assessment;
    nothing when it cannot be read (a database before schema 61)."""
    try:
        conn = admin.connect_admin()
    except Exception:  # noqa: BLE001
        return {}
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT l.AssessmentId, l.ComponentId, l.Attempt, l.Stage, l.Chars, l.Truncated, "
                    "CASE WHEN l.Stage = N'build' THEN SUBSTRING(l.LogGz, 1, 600) END AS Start "
                    "FROM cz.ComponentVerifyLog l WHERE l.AssessmentId = (SELECT MAX(AssessmentId) FROM "
                    "cz.ApplicationAssessment WHERE ApplicationId = %s) ORDER BY l.ComponentId, l.Attempt, l.Stage",
                    (int(app["ApplicationId"]),))
        out: dict = {}
        for r in cur.fetchall():
            out.setdefault(r["ComponentId"], []).append({
                "stage": r["Stage"], "attempt": int(r["Attempt"]), "chars": int(r["Chars"]), "truncated": bool(r["Truncated"]),
                "url": f"/admin/verify-log/{int(r['AssessmentId'])}/{int(r['ComponentId'])}/{r['Stage']}-{int(r['Attempt'])}.log",
                "dockerfile": (f"/admin/verify-log/{int(r['AssessmentId'])}/{int(r['ComponentId'])}/dockerfile-{int(r['Attempt'])}.txt"
                               if _has_header(r.get("Start")) else "")})
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
    files = " · ".join(f"<a href='{e(x['dockerfile'])}' target='_blank' rel='noopener'>attempt {int(x['attempt'])}</a>"
                       for x in logs if x.get("dockerfile"))
    files = (f"<p class='small'><span class='label'>Dockerfile and build command</span> {files} <span class='muted'>· what "
             "the scan built, and with which <code>docker build</code>; opens in a new tab</span></p>") if files else ""
    return (f"{files}<p class='small'><span class='label'>Whole log</span> {items} <span class='muted'>· secrets masked; for "
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
                (int(parts[1]), int(parts[2]), m[1] or "build", int(m[2] or m[4])))
    rows = cur.fetchall()
    if not rows:
        return Response(404, page("Not found", "<h1>Not found</h1><p>This scan kept no such log.</p>"))
    try:
        data = gzip.decompress(bytes(rows[0]["LogGz"]))
    except (OSError, EOFError, ValueError, TypeError):
        return Response(404, page("Not found", "<h1>Not found</h1><p>The log cannot be read.</p>"))
    if m[3]:                                # the Dockerfile and the command alone, shown in the browser
        head = header_of(data.decode("utf-8", "replace"))
        if not head:
            return Response(404, page("Not found", "<h1>Not found</h1><p>This scan kept no Dockerfile: scans from "
                                                   "0.54.3 on do.</p>"))
        return Response(200, head.encode("utf-8"), [("X-Content-Type-Options", "nosniff"),
                                                    ("Content-Security-Policy", "default-src 'none'")],
                        ctype="text/plain; charset=utf-8")
    name = "-".join(re.sub(r"[^A-Za-z0-9._-]+", "-", str(x or "")).strip("-")[:60] or "x"
                    for x in (rows[0]["ApplicationName"], rows[0]["ComponentName"])) + f"-{m[1]}-{int(m[2])}.log"
    return Response(200, data, [("Content-Disposition", f'attachment; filename="{name}"'),
                                ("X-Content-Type-Options", "nosniff")], ctype="text/plain; charset=utf-8")
