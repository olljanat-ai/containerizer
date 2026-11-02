"""Admin → Egress (egress.py, docs/egress.md): administrators, operators and the application's product owners
(the access rules of refactoring: admin_refactor.allowed_app).

- /admin/egress: the egress review's decisions of the applications this person may decide for, open ones
  first: the destination, port and protocol, the component, the verdict and why, the evidence (the quoted
  line of the source, the blocked flows and pods).
- POST /admin/egress/<id>/approve, /admin/egress/<id>/reject: the decision, recorded with who made it
  (DecidedBy/At; the change history records it too). The LLM queue runner then writes connectivity.yaml and
  the NetworkPolicy to the output repository (egress.commit_pending). An approved destination stays approved:
  taking it back is a commit of one's own in the output repository.

Plain HTML forms with the session's CSRF token (admin.py checks every POST), no JavaScript, fixed notice texts
chosen by a code in the URL, everything escaped. Reads go through the views (vEgressDecision).
"""
from __future__ import annotations

import json
import re
import sys

from .admin import Response, e, redirect
from .admin_refactor import _rows, allowed_app
from .admin_scans import _nf

BASE = "/admin/egress"
# approve: something the review proposed or reported with a name (never suspicious, platform or an IP address)
APPROVABLE = {"propose", "report"}
APPROVE_FROM = {"proposed", "reported", "rejected"}
REJECT_FROM = {"proposed", "reported", "suspicious"}
NOTICES = {"approved": ("ok", "Approved: the LLM queue runner writes it to connectivity.yaml and opens the port in the "
                              "component's NetworkPolicy within a few minutes; the sandbox applies the commit."),
           "rejected": ("info", "Rejected: it stays blocked, and connectivity.yaml records the decision."),
           "not-allowed": ("bad", "That cannot be approved: only named destinations the review proposed or reported can "
                                  "be (never suspicious ones, the platform's, or IP addresses)."),
           "decided": ("info", "Nothing changed: it was decided already."),
           "not-yours": ("bad", "That application is outside your products."),
           "unavailable": ("bad", "Egress decisions need the database schema of this version: run `containerizer db init`.")}
STATUS_CSS = {"proposed": "st-wait", "reported": "st-off", "suspicious": "st-bad", "approved": "st-ok", "rejected": "st-off"}
VERDICT_TEXT = {"propose": "Proposed", "report": "Reported", "suspicious": "Suspicious", "platform": "Platform",
                "unnamed": "IP address only", "in-cluster": "In the cluster"}


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{e(text)}</div>"


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict, flash: str) -> Response:
    if not (a.admin or a.operator or a.owner):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    if len(parts) == 1 and method == "GET":
        return show_list(adm, conn, s, a, (q.get("notice") or [""])[0], flash)
    if len(parts) == 3 and method == "POST" and re.fullmatch(r"\d{1,9}", parts[1]) and parts[2] in ("approve", "reject"):
        return decide(adm, conn, s, a, int(parts[1]), parts[2], form)
    return _nf()


def _back(form: dict, app_id, code: str) -> Response:
    if (form.get("back") or [""])[0] == "app" and app_id is not None:
        return redirect(f"/app/{int(app_id)}?egress={code}#connectivity")
    return redirect(f"{BASE}?notice={code}")


def decide(adm, conn, s, a, ident: int, action: str, form: dict) -> Response:
    try:
        r = _rows(conn, "SELECT DecisionId, ApplicationId, Verdict, Status, Destination FROM cz.EgressDecision "
                        "WHERE DecisionId = %s", (ident,))
    except Exception as ex:  # noqa: BLE001 - a database from before schema 24
        print(f"egress decision #{ident}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return redirect(f"{BASE}?notice=unavailable")
    if not r:
        return _nf()
    d = r[0]
    if not allowed_app(a, conn, d["ApplicationId"]):
        return _back(form, d["ApplicationId"], "not-yours")
    if action == "approve":
        if d["Verdict"] not in APPROVABLE:
            return _back(form, d["ApplicationId"], "not-allowed")
        if d["Status"] not in APPROVE_FROM:
            return _back(form, d["ApplicationId"], "decided")
        new, allowed_from = "approved", APPROVE_FROM
    else:
        if d["Status"] not in REJECT_FROM:
            return _back(form, d["ApplicationId"], "decided")
        new, allowed_from = "rejected", REJECT_FROM
    marks = ", ".join(["%s"] * len(allowed_from))
    cur = conn.cursor()
    cur.execute(f"UPDATE cz.EgressDecision SET Status = %s, DecidedBy = %s, DecidedByName = %s, DecidedAt = SYSUTCDATETIME(), "
                f"CommittedAt = NULL WHERE DecisionId = %s AND Status IN ({marks})",
                (new, s.user, s.name, ident, *sorted(allowed_from)))
    changed = cur.rowcount
    conn.commit()
    return _back(form, d["ApplicationId"], new if changed else "decided")


def _json(s, default):
    try:
        return json.loads(s) if s else default
    except (TypeError, ValueError):
        return default


def evidence_html(d: dict) -> str:
    out = []
    for ev in _json(d.get("Evidence"), [])[:3]:
        if isinstance(ev, dict) and ev.get("file"):
            out.append(f"<div class='small'><code>{e(ev['file'])}:{int(ev.get('line') or 0)}</code> "
                       f"<code class='quote'>{e(str(ev.get('quote') or '')[:200])}</code></div>")
    fl = _json(d.get("Flows"), {})
    if isinstance(fl, dict) and fl.get("packets"):
        pods = ", ".join(str(p) for p in (fl.get("pods") or [])[:3])
        out.append(f"<div class='small muted'>{int(fl['packets'])} dropped packet(s), {e(str(fl.get('first_seen') or '')[:16])}"
                   f" – {e(str(fl.get('last_seen') or '')[:16])}{' · ' + e(pods) if pods else ''}"
                   f"{' · ' + e(', '.join(fl.get('ips') or [])) if fl.get('ips') else ''}</div>")
    return "".join(out) or "<span class='muted small'>-</span>"


def actions_html(d: dict, csrf: str, back: str = "") -> str:
    """Approve / Reject buttons of one decision (only those its status allows)."""
    hidden = csrf + (f"<input type='hidden' name='back' value='{e(back)}'>" if back else "")
    out = []
    if d.get("Verdict") in APPROVABLE and d.get("Status") in APPROVE_FROM:
        out.append(f"<form method='post' action='{BASE}/{int(d['DecisionId'])}/approve' class='inline'>{hidden}"
                   f"<button>Approve</button></form>")
    if d.get("Status") in REJECT_FROM:
        out.append(f"<form method='post' action='{BASE}/{int(d['DecisionId'])}/reject' class='inline'>{hidden}"
                   f"<button class='secondary'>Reject</button></form>")
    return " ".join(out)


def status_chip(d: dict) -> str:
    st = d.get("Status") or ""
    from .egress import STATUS_TEXT
    return f"<span class='st {STATUS_CSS.get(st, '')}'>{e(STATUS_TEXT.get(st, st))}</span>"


def show_list(adm, conn, s, a, code: str, flash: str) -> Response:
    try:
        rows = _rows(conn, "SELECT d.*, x.ApplicationName FROM cz.vEgressDecision d JOIN cz.vApplicationLatest x "
                           "ON x.ApplicationId = d.ApplicationId ORDER BY CASE d.Status WHEN N'proposed' THEN 0 "
                           "WHEN N'suspicious' THEN 1 WHEN N'reported' THEN 2 ELSE 3 END, d.CreatedAt DESC")
    except Exception as ex:  # noqa: BLE001 - a database from before schema 24
        print(f"egress decisions: {type(ex).__name__}: {ex}", file=sys.stderr)
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        rows, code = [], "unavailable"
    mine: dict = {}
    rows = [r for r in rows if mine.setdefault(r["ApplicationId"], allowed_app(a, conn, r["ApplicationId"]))]
    csrf = adm._csrf(s)
    body = [notice_html(code),
            "<p class='muted'>Connections the sandbox's NetworkPolicies blocked for applications rated A, as the egress "
            "review sees them: <b>proposed</b> (the configuration or code names it), <b>reported</b> (nothing explains it, "
            "or a person decides) and <b>suspicious</b> (never proposed). Approving one writes it to the application's "
            "connectivity.yaml in the output repository and opens the port in the component's NetworkPolicy: a "
            "NetworkPolicy cannot name an FQDN, so the port opens to every address but the blocked ranges. The FQDN in "
            "connectivity.yaml is for the production firewall. <a href='https://containerizer.eu/egress/'>How it works</a></p>"]
    if not rows:
        body.append("<p class='muted'>No blocked connections reviewed yet.</p>")
    else:
        trs = []
        for r in rows:
            who = (f"<div class='small muted'>{e(r.get('DecidedByName') or r.get('DecidedBy') or '')} "
                   f"{e(str(r.get('DecidedAt') or '')[:16])}</div>") if r.get("DecidedAt") else ""
            commit = ""
            if r.get("CommittedAt"):
                commit = f"<div class='small muted'>committed {e(str(r.get('CommitRevision') or '')[:12])}</div>"
            elif r.get("CommitError"):
                commit = f"<div class='small st-bad'>not committed: {e(str(r['CommitError'])[:160])}</div>"
            trs.append(f"<tr><td><a href='/app/{int(r['ApplicationId'])}#connectivity'>{e(r['ApplicationName'])}</a>"
                       f"<div class='muted small'>{e(r['Namespace'])} / {e(r['Component'] or '-')}</div></td>"
                       f"<td><b>{e(r['Destination'])}</b><div class='muted small'>{int(r['Port'])}/{e(r['Protocol'])}</div></td>"
                       f"<td>{status_chip(r)}<div class='small muted'>{e(VERDICT_TEXT.get(r['Verdict'], r['Verdict']))}</div>{who}{commit}</td>"
                       f"<td class='small'>{e(r.get('Reason') or '')}</td><td>{evidence_html(r)}</td>"
                       f"<td>{actions_html(r, csrf)}</td></tr>")
        body.append("<table><thead><tr><th>Application</th><th>Destination</th><th>Status</th><th>Why</th><th>Evidence</th>"
                    f"<th></th></tr></thead><tbody>{''.join(trs)}</tbody></table>")
    return Response(200, adm._shell(s, a, "Egress", "egress", "".join(body), flash))
