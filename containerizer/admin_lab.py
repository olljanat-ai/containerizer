"""Admin -> Lab services (/admin/lab-services), administrators only, on the appliance.

Turns each lab service (labservices.py) on or off. A change is saved in cz.LabService first, so the
change history records who made it, then handed to the system agent with the full set of switches,
which checks it again and writes lab-services.json; the lab agent (labagent.py) applies it within
seconds and the next scans point the apps at what is on. The page shows what the lab agent last saw:
each service's state and the apps that use it, and warns about apps that need a service that is off.
"""
from __future__ import annotations

import html
import json
from urllib.parse import urlencode

from . import labservices as L
from .admin import Response, page, redirect, render_audit

e = html.escape
TAB = ("lab-services", "Lab services")
STATE_TEXT = {"running": ("Running", "st-ok"), "starting": ("Starting", "st-run"), "idle": ("On, not in use", "st-off"),
              "off": ("Off", "st-off"), "error": ("Problem", "st-bad")}


def enabled(adm, a) -> bool:
    return bool(a.admin and adm.system)


def rows(conn) -> dict[str, dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT LabServiceId, Name, Title, Enabled, Note, ChangedAt FROM cz.LabService")
    return {r["Name"]: r for r in cur.fetchall() if r["Name"] in L.SERVICES}


def lab_status(adm) -> dict:
    try:
        data = json.loads((adm.system.status_dir / "lab-status.json").read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def needs_off(conn) -> dict[str, list[str]]:
    """{service: [app]} from the latest scan of each repository: apps that need a service that was off."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT AppName, LastDetail FROM cz.OrgRepository WHERE RemovedAt IS NULL AND LastDetail IS NOT NULL "
                "AND LastDetail LIKE N'%\"missing\"%'")
    out: dict[str, set] = {}
    for r in cur.fetchall():
        try:
            lab = (json.loads(r["LastDetail"]) or {}).get("lab_services") or {}
        except ValueError:
            continue
        try:
            apps = (json.loads(r["LastDetail"]) or {}).get("apps") or []
        except ValueError:
            apps = []
        # a repository split into applications: each one by its own name (before 0.16.1 only the whole repository)
        per = [((x.get("app") or x.get("folder") or "?"), x.get("lab_services") or {}) for x in apps
               if isinstance(x, dict) and x.get("lab_services")] or [(r["AppName"] or "?", lab)]
        for name, rep in per:
            for svc in rep.get("missing") or []:
                if svc in L.SERVICES:
                    out.setdefault(svc, set()).add(name)
    return {k: sorted(v) for k, v in out.items()}


def needed_by(conn) -> dict[str, list[dict]]:
    """{service: [{id, name, components, provided}]}: the applications whose latest organization scan found that
    they need the service (cz.vSandboxDeploy LabServices, each application of a split repository on its own),
    with the components that need it and whether the scan pointed them at the lab's service. {} before 0.16.1's
    view."""
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT DISTINCT d.ApplicationId, COALESCE(a.DisplayName, a.Name) AS Name, d.LabServices "
                    "FROM cz.vSandboxDeploy d JOIN cz.Application a ON a.ApplicationId = d.ApplicationId "
                    "WHERE d.LabServices IS NOT NULL")
        found = cur.fetchall()
    except Exception:  # noqa: BLE001 - a database from before the LabServices column
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {}
    out: dict[str, list[dict]] = {}
    for r in found:
        try:
            rep = json.loads(r["LabServices"]) or {}
        except (TypeError, ValueError):
            continue
        provided = set(rep.get("provided") or [])
        for svc, comps in (rep.get("needed") or {}).items():
            if svc in L.SERVICES and comps:
                out.setdefault(svc, []).append({"id": int(r["ApplicationId"]), "name": str(r["Name"] or "?"),
                                                "components": sorted(comps), "provided": svc in provided})
    return {k: sorted(v, key=lambda x: x["name"].lower()) for k, v in out.items()}


def needed_by_html(by: dict[str, list[dict]], on: dict[str, bool]) -> str:
    """The other direction of an application's Lab services line: per service, the applications that need it."""
    if not by:
        return ("<h2>Applications that need each service</h2><p class='muted'>No organization scan has found an "
                "application that needs a lab service yet (or none since 0.16.1: the next scan of each repository "
                "fills this in).</p>")
    out = ["<h2>Applications that need each service</h2><p class='muted small'>From each application's latest "
           "organization scan. <b>Provided</b>: the scan pointed the application at the lab's service. <b>Without "
           "it</b>: the service was off at that scan, and the application kept its own settings; turn the service "
           "on and scan again.</p><table class='audit'><thead><tr><th>Service</th><th>Application</th>"
           "<th>Components that need it</th><th></th></tr></thead><tbody>"]
    for svc in L.ORDER:
        apps = by.get(svc) or []
        for i, x in enumerate(apps):
            head = (f"<td rowspan='{len(apps)}'><b>{e(L.SERVICES[svc].title)}</b><div class='muted small'>"
                    f"{'on' if on.get(svc) else 'off'} · {len(apps)} application{'s' if len(apps) != 1 else ''}</div></td>"
                    if i == 0 else "")
            st = ("<span class='st st-ok'>Provided</span>" if x["provided"] else
                  "<span class='st st-bad'>Without it</span>")
            out.append(f"<tr>{head}<td><a href='/app/{x['id']}'>{e(x['name'])}</a></td>"
                       f"<td class='small'>{e(', '.join(x['components']))}</td><td>{st}</td></tr>")
    out.append("</tbody></table>")
    return "".join(out)


def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict) -> Response:
    if not enabled(adm, a):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Only administrators can change the lab services.</p>"))
    if method == "POST" and len(parts) == 2 and parts[1] in L.SERVICES:
        return save(adm, conn, s, parts[1], form)
    if method != "GET" or len(parts) > 1:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    return listing(adm, conn, s, a, q.get("msg", [""])[0][:300])


def _back(msg: str) -> Response:
    return redirect("/admin/lab-services?" + urlencode({"msg": msg}))


def save(adm, conn, s, svc: str, form: dict) -> Response:
    want = form.get("Enabled", [""])[0]
    if want not in ("on", "off"):
        return _back("Choose on or off.")
    on = want == "on"
    note = " ".join(form.get("Note", [""])[0].split())[:400] or None
    current = rows(conn)
    if svc not in current:
        return _back("That service is not in the database yet: run `containerizer db init` (schema version 14).")
    st = (lab_status(adm).get("services") or {}).get(svc) or {}
    in_use = list(st.get("apps") or [])
    if not on and in_use and form.get("confirm", [""])[0] != "yes":
        return _back(f"{L.SERVICES[svc].title} is in use by {len(in_use)} app(s). Tick the box to confirm turning it off.")
    cur = conn.cursor()
    cur.execute("UPDATE cz.LabService SET Enabled = %s, Note = %s, ChangedAt = SYSUTCDATETIME() WHERE Name = %s",
                (1 if on else 0, note, svc))
    conn.commit()
    services = {k: bool(r["Enabled"]) for k, r in rows(conn).items()}
    services = {k: services.get(k, L.SERVICES[k].default) for k in L.ORDER}
    adm.system.request("lab", s.user, s.name, services=services)
    what = "on" if on else "off"
    extra = (" Apps that use it lose it now; the next scan generates them without it." if not on and in_use else
             " The next scan of each app that needs it points the app at it." if on else "")
    return _back(f"{L.SERVICES[svc].title} turned {what}.{extra}")


def _state(st: dict, on: bool, pending: bool) -> str:
    if pending:
        return "<span class='st st-run'>Applying</span>"
    text, css = STATE_TEXT.get(st.get("state") or "", ("Not checked yet", "st-off"))
    if not st and not on:
        text, css = STATE_TEXT["off"]
    return f"<span class='st {css}'>{e(text)}</span>"


def listing(adm, conn, s, a, flash: str) -> Response:
    db = rows(conn)
    st = lab_status(adm)
    seen = st.get("services") or {}
    applied = ((st.get("config") or {}).get("services") or {})
    pending_req = any(r.get("action") == "lab" for r in adm.system.pending())
    missing = needs_off(conn)
    trs = []
    warnings = []
    state_on = {}
    for svc in L.ORDER:
        sv = L.SERVICES[svc]
        r = db.get(svc)
        on = bool(r["Enabled"]) if r else sv.default
        state_on[svc] = on
        x = seen.get(svc) or {}
        pending = pending_req or (bool(applied) and applied.get(svc) != on)
        apps = x.get("apps") or []
        ready = set(x.get("ready") or [])
        used = ", ".join(f"{e(n)}{'' if n in ready or not on else ' <span class=muted>(waiting)</span>'}" for n in apps) \
            or "<span class='muted'>none</span>"
        msg = f"<div class='muted small'>{e(x['message'])}</div>" if x.get("message") else ""
        # the repository's SQL setup scripts the lab agent ran into the apps' databases (labinit.py)
        msg += "".join(f"<div class='muted small'>{e(str(n))}</div>" for n in (x.get("init") or [])[:20])
        need = missing.get(svc) or []
        if not on and (need or apps):
            names = sorted(set(need) | set(apps))
            warnings.append(f"<li><b>{e(sv.title)}</b> is off, but {len(names)} app(s) need it: {e(', '.join(names[:20]))}"
                            f"{' ...' if len(names) > 20 else ''}. They keep their own settings and cannot reach a "
                            "database or store in the sandbox until it is turned on.</li>")
        confirm = (f"<label class='check small'><input type='checkbox' name='confirm' value='yes'> {len(apps)} app(s) use it: "
                   "turn it off anyway</label>") if on and apps else ""
        toggle = (f"<form method='post' action='/admin/lab-services/{svc}' class='inline'>{adm._csrf(s)}"
                  f"<input type='hidden' name='Enabled' value='{'off' if on else 'on'}'>"
                  f"<input name='Note' maxlength='400' placeholder='Note (why)' value=''>{confirm}"
                  f"<button{' class=secondary' if on else ''}>{'Turn off' if on else 'Turn on'}</button></form>")
        note = f"<div class='muted small'>Note: {e(r['Note'])}</div>" if r and r.get("Note") else ""
        trs.append(f"<tr><td><b>{e(sv.title)}</b><div class='muted small'>{e(sv.engine)}</div></td>"
                   f"<td class='small'>{e(sv.summary)}</td>"
                   f"<td>{_state(x, on, pending)}{msg}{note}</td><td class='small'>{used}</td><td>{toggle}</td></tr>")
    err = f"<p class='note'>{e(st['error'])}</p>" if st.get("error") else ""
    when = st.get("checked_at")
    warn = f"<h2>Needed but off</h2><ul>{''.join(warnings)}</ul>" if warnings else ""
    body = (
        "<p class='muted'>Backing services the sandbox runs for the scanned apps, in namespace "
        f"<code>{L.LAB_NS}</code>. When an app depends on a service that is on, its generated manifests point it at the "
        "service through configuration overrides (no code changes), with credentials from the secret store (External "
        "Secrets Operator). Each app gets its own database and login, or its own instance, and only its namespace can reach "
        "it. Data stays on the appliance's persistent partition; turning a service off stops it and keeps the data. "
        "<a href='https://containerizer.eu/lab-services/' rel='noopener noreferrer' target='_blank'>How it works ↗</a></p>"
        + err + warn +
        "<table class='audit'><thead><tr><th>Service</th><th>What each app gets</th><th>State</th><th>Apps using it</th>"
        f"<th></th></tr></thead><tbody>{''.join(trs)}</tbody></table>"
        + (f"<p class='muted small'>Checked {e(str(when))}. The lab agent checks every 2 minutes and right after a change.</p>"
           if when else "<p class='muted small'>The lab agent has not reported yet.</p>")
        + needed_by_html(needed_by(conn), state_on)
        + "<h2>Changes</h2>" + render_audit(adm._audit_rows(conn, "LabService", None, 50), show_target=True))
    return Response(200, adm._shell(s, a, "Lab services", TAB[0], body, flash))
