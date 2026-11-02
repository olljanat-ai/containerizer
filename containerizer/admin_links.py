"""Links between applications on the admin pages (links.py, docs/egress.md#links-between-applications):
administrators, operators and the calling application's product owners (admin_refactor.allowed_app).

- POST /admin/links/<id>/confirm: a proposed link (configuration match, observed call, LLM) is confirmed;
- POST /admin/links/<id>/reject: a proposed or unresolved link is rejected;
- POST /admin/links/<id>/link: Link manually: the destination is linked to a component picked from the
  components assessed here (Target = "<application id>:<component>"), confirmed at once.

The queue runner then writes both applications' connectivity.yaml and NetworkPolicies (egress.commit_pending).
Plain HTML forms with the session's CSRF token (admin.py checks every POST), fixed notice texts, back to the
results page.
"""
from __future__ import annotations

import re
import sys

from .admin import Response, e, redirect
from .admin_refactor import _rows, allowed_app
from .admin_scans import _nf

BASE = "/admin/links"
NOTICES = {"confirmed": ("ok", "Linked: the LLM queue runner writes the link to both applications' connectivity.yaml and "
                               "opens it in both NetworkPolicies within a few minutes."),
           "rejected": ("info", "Rejected: the destination is not linked to that component."),
           "decided": ("info", "Nothing changed: it was decided already."),
           "bad-target": ("bad", "Pick one of the components assessed here."),
           "not-yours": ("bad", "That application is outside your products."),
           "unavailable": ("bad", "Links need the database schema of this version: run `containerizer db init`.")}


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{e(text)}</div>"


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict) -> Response:
    if not (a.admin or a.operator or a.owner):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    if len(parts) == 3 and method == "POST" and re.fullmatch(r"\d{1,9}", parts[1]) and parts[2] in ("confirm", "reject", "link"):
        return decide(conn, s, a, int(parts[1]), parts[2], form)
    return _nf()


def _back(app_id, code: str) -> Response:
    return redirect(f"/app/{int(app_id)}?link={code}#connectivity")


def decide(conn, s, a, ident: int, action: str, form: dict) -> Response:
    try:
        r = _rows(conn, "SELECT LinkId, FromApplicationId, FromComponent, Status, ToApplicationId, ToComponent "
                        "FROM cz.ComponentLink WHERE LinkId = %s", (ident,))
    except Exception as ex:  # noqa: BLE001 - a database from before schema 25
        print(f"link #{ident}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return redirect("/?link=unavailable")
    if not r:
        return _nf()
    lk = r[0]
    if not allowed_app(a, conn, lk["FromApplicationId"]):
        return _back(lk["FromApplicationId"], "not-yours")
    cur = conn.cursor()
    who = (s.user, s.name)
    if action == "confirm":
        if lk["Status"] != "proposed" or not lk["ToApplicationId"]:
            return _back(lk["FromApplicationId"], "decided")
        cur.execute("UPDATE cz.ComponentLink SET Status = N'confirmed', DecidedBy = %s, DecidedByName = %s, "
                    "DecidedAt = SYSUTCDATETIME(), CommittedAt = NULL WHERE LinkId = %s AND Status = N'proposed'", (*who, ident))
        code = "confirmed"
    elif action == "reject":
        if lk["Status"] not in ("proposed", "unresolved"):
            return _back(lk["FromApplicationId"], "decided")
        cur.execute("UPDATE cz.ComponentLink SET Status = N'rejected', DecidedBy = %s, DecidedByName = %s, "
                    "DecidedAt = SYSUTCDATETIME(), CommittedAt = NULL WHERE LinkId = %s "
                    "AND Status IN (N'proposed', N'unresolved')", (*who, ident))
        code = "rejected"
    else:
        m = re.fullmatch(r"(\d{1,9}):([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)", (form.get("Target") or [""])[0])
        if not m or int(m[1]) == int(lk["FromApplicationId"]):
            return _back(lk["FromApplicationId"], "bad-target")
        from .generate import k8s_name
        cands = _rows(conn, "SELECT ComponentName FROM cz.vLinkCandidate WHERE ApplicationId = %s", (int(m[1]),))
        if not any(k8s_name(c["ComponentName"] or "") == m[2] for c in cands):
            return _back(lk["FromApplicationId"], "bad-target")
        if lk["Status"] == "confirmed":
            return _back(lk["FromApplicationId"], "decided")
        cur.execute("UPDATE cz.ComponentLink SET ToApplicationId = %s, ToComponent = %s, Method = N'manual', "
                    "Status = N'confirmed', Reason = %s, DecidedBy = %s, DecidedByName = %s, DecidedAt = SYSUTCDATETIME(), "
                    "CommittedAt = NULL WHERE LinkId = %s AND Status <> N'confirmed'",
                    (int(m[1]), m[2], "linked by hand", *who, ident))
        code = "confirmed"
    changed = cur.rowcount
    conn.commit()
    return _back(lk["FromApplicationId"], code if changed else "decided")


def actions_html(entry: dict, csrf: str, candidates: list[dict], app_id) -> str:
    """Confirm / Reject of a proposed link, Link manually of an unresolved destination."""
    lk = entry.get("link") or {}
    if not lk.get("id"):
        return ""
    lid = int(lk["id"])
    out = []
    if lk.get("status") == "proposed":
        out.append(f"<form method='post' action='{BASE}/{lid}/confirm' class='inline'>{csrf}<button>Confirm</button></form>")
    if lk.get("status") in ("proposed", "unresolved"):
        out.append(f"<form method='post' action='{BASE}/{lid}/reject' class='inline'>{csrf}"
                   f"<button class='secondary'>Reject</button></form>")
    if lk.get("status") in ("unresolved", "proposed") and candidates:
        from .generate import k8s_name
        opts = "".join(f"<option value='{int(c['ApplicationId'])}:{e(k8s_name(c['ComponentName'] or ''))}'>"
                       f"{e(c['ApplicationName'])} / {e(c['ComponentName'])}</option>"
                       for c in candidates if int(c["ApplicationId"]) != int(app_id or 0))
        if opts:
            out.append(f"<form method='post' action='{BASE}/{lid}/link' class='formrow link-manual'>{csrf}"
                       f"<label class='small'>Link manually <select name='Target'>{opts}</select></label>"
                       f"<button class='secondary'>Link</button></form>")
    return " ".join(out)
