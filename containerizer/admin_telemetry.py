"""Make it A+: the pages (docs/telemetry.md; the work is in telemetry.py).

- The results page of an application rated A has the box **OpenTelemetry** (`section`): its state, the instrumented
  components, and for administrators the button **Make it A+** (or **Turn it off**).
- /admin/telemetry (administrators): **Make it A+: every A application**: every application rated A with its state;
  the ones ticked are turned on with one button. Nothing is ordered by opening the page.
- POST /admin/telemetry/<ApplicationId> (On=1|0) and POST /admin/telemetry/all (app=<id>...): Application.Telemetry
  (the change history records it). Only an application whose latest assessment rates A can be turned on. No LLM and
  no build: the queue runner writes the sandbox's patches within a few minutes (variant.sync_sandbox).
"""
from __future__ import annotations

import re
import sys
from html import escape as e
from urllib.parse import quote

from . import telemetry

BASE = "/admin/telemetry"
DASHBOARD = "d/containerizer-telemetry/containerizer-application-telemetry"
K3S_DASHBOARD = "d/containerizer-k3s/containerizer-k3s-sandbox-cluster"
NOTICES = {
    "on": ("ok", "Make it A+ ordered: the queue runner instruments the application in the sandbox within a few "
                 "minutes, and its pods restart. It is A+ once its telemetry arrives."),
    "off": ("ok", "OpenTelemetry turned off: within a few minutes the application's pods in the sandbox restart "
                  "without the instrumentation."),
    "not-a": ("bad", "Not ordered: only an application rated A can be made A+ (Make it A first)."),
    "not-admin": ("bad", "Not ordered: only administrators order Make it A+."),
    "unavailable": ("bad", "Not ordered: the results database could not be written (is its schema up to date?)."),
}
LATEST_RATING = ("(SELECT TOP (1) aa.Rating FROM cz.ApplicationAssessment aa WHERE aa.ApplicationId = a.ApplicationId "
                 "ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC)")
ST_CLASS = {telemetry.RECEIVING: "st-ok", telemetry.WAITING: "st-warn", telemetry.SILENT: "st-bad",
            telemetry.PARTIAL: "st-warn", telemetry.NOTHING: "st-bad", telemetry.NOT_DEPLOYED: "st-warn"}


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{e(text)}</div>"


def _when(iso) -> str:
    return e(str(iso or "")[:16].replace("T", " ") + " UTC") if iso else ""


def grafana_base(url: str) -> str:
    """Grafana's own address from CONTAINERIZER_GRAFANA_URL, which may name a dashboard (.../grafana/d/<uid>)."""
    return (url or "").split("/d/")[0].rstrip("/")


def _dashboard(grafana: str, dashboard: str, namespaces: list[str], text: str) -> str:
    q = "&".join(f"var-namespace={quote(n)}" for n in namespaces)
    return (f"<a href='{e(grafana_base(grafana) + '/' + dashboard + '?' + q)}' rel='noopener noreferrer' target='_blank'>"
            f"{e(text)} ↗</a>")


def grafana_link(grafana: str, namespace: str) -> str:
    if not grafana or not namespace:
        return ""
    return _dashboard(grafana, DASHBOARD, [namespace], "Open its telemetry in Grafana")


def grafana_links(app: dict, grafana: str) -> str:
    """The application's own view of Grafana's dashboards, for its results page: its pods in the sandbox (the k3s
    dashboard, for its namespaces) and, with OpenTelemetry on, its telemetry. Nothing without a namespace there."""
    if not grafana:
        return ""
    st = telemetry.parse_state(app.get("TelemetryState")) if app.get("Telemetry") else {}
    spaces = sorted({str(s["Namespace"]) for s in app.get("sandbox") or [] if s.get("Namespace")})
    links = []
    if spaces:
        links.append(_dashboard(grafana, K3S_DASHBOARD, spaces, "its pods in the sandbox"))
    if st.get("namespace"):
        links.append(_dashboard(grafana, DASHBOARD, [str(st["namespace"])], "its traces, metrics and logs"))
    return f"<div><span class='label'>Grafana</span> {' · '.join(links)}</div>" if links else ""


def state_html(st: dict, plus: bool) -> str:
    """The state in a sentence, as a status chip with its explanation."""
    if not st:
        return ("<span class='st st-warn'>Ordered</span> The queue runner instruments it in the sandbox within a few "
                "minutes.")
    status = st.get("status")
    label = "A+" if plus else {telemetry.WAITING: "Instrumented", telemetry.SILENT: "No telemetry",
                              telemetry.PARTIAL: "Partly instrumented", telemetry.NOTHING: "Not instrumented",
                              telemetry.NOT_DEPLOYED: "Not in the sandbox"}.get(status, "Instrumented")
    text = telemetry.summary(st)
    return (f"<span class='st {'st-ok' if plus else ST_CLASS.get(status, 'st-warn')}'>{e(label)}</span> {e(text[:1].upper() + text[1:])}."
            + (f" <span class='muted'>Last received {_when(st.get('seen_at'))}.</span>" if st.get("seen_at") else ""))


def components_html(st: dict) -> str:
    comps = st.get("components") or []
    if not comps:
        return ""
    rows = []
    for c in comps:
        mode = c.get("mode")
        how = {"agent": "agent injected", "sdk": "its own SDK"}.get(mode, "not instrumented")
        seen = (f"received {_when(c.get('seen_at'))}" if c.get("seen_at") else
                ("<span class='muted'>nothing received yet</span>" if mode != "none" else ""))
        rows.append(f"<tr><td>{e(str(c.get('component') or ''))}</td><td>{e(how)}</td>"
                    f"<td class='small'>{e(str(c.get('reason') or ''))}</td><td class='small'>{seen}</td></tr>")
    return ("<table class='small'><thead><tr><th>Component</th><th>OpenTelemetry</th><th>How</th><th>Telemetry</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


def section(app: dict, ctx: dict) -> str:
    """The OpenTelemetry box of an application's results page: for an application rated A, or one with it on."""
    on = bool(app.get("Telemetry"))
    if "Telemetry" not in app or (app.get("Rating") != "A" and not on):
        return ""
    st = telemetry.parse_state(app.get("TelemetryState"))
    plus = telemetry.is_plus(app.get("Rating"), on, st)
    app_id = int(app["ApplicationId"])
    csrf = ctx.get("telemetry_csrf")
    out = [f"<h2 id='telemetry'>OpenTelemetry</h2>{notice_html(ctx.get('telemetry_notice') or '')}"]
    if not on:
        out.append("<p><b>Make it A+</b> instruments this application with OpenTelemetry in the sandbox, without a code "
                   "change and without the LLM: each component gets the auto-instrumentation agent of its runtime "
                   "(.NET, Java, Node.js, Python) and sends its traces, metrics and logs to the sandbox's collector, "
                   "where Grafana shows them. Nothing is built again. It is <b>A+</b> once its telemetry arrives.</p>")
        if csrf:
            out.append(f"<form method='post' action='{BASE}/{app_id}' class='formrow'>{csrf}"
                       "<input type='hidden' name='On' value='1'><button>Make it A+</button></form>")
        else:
            out.append("<p class='muted'>An administrator orders it here.</p>")
        return "".join(out)
    out.append(f"<p>{state_html(st, plus)}</p>")
    if app.get("Rating") != "A":
        out.append("<p class='muted'>The application no longer rates A, so it is not A+; its instrumentation stays "
                   "until it is turned off.</p>")
    out.append(components_html(st))
    link = grafana_link(ctx.get("grafana") or "", str(st.get("namespace") or ""))
    if link:
        out.append(f"<p>{link}</p>")
    if csrf:
        out.append(f"<form method='post' action='{BASE}/{app_id}' class='formrow'>{csrf}"
                   "<input type='hidden' name='On' value='0'><button class='secondary'>Turn it off</button></form>")
    return "".join(out)


# --------------------------------------------------------------------------- the admin page

def candidates(conn) -> list[dict]:
    """Every application rated A, and every one with telemetry on whatever it rates now."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ApplicationId, ApplicationName, ProductName, BusinessUnitName, Rating, Telemetry, TelemetryState "
                "FROM cz.vApplicationLatest WHERE Rating = 'A' OR Telemetry = 1 ORDER BY ApplicationName")
    return cur.fetchall()


def turn_on(conn, ids: list[int]) -> int:
    """Telemetry on for the applications of `ids` that rate A and do not have it yet. Returns how many."""
    n = 0
    cur = conn.cursor()
    for i in sorted(set(ids)):
        cur.execute("UPDATE a SET Telemetry = 1, TelemetryState = NULL FROM cz.Application a "
                    f"WHERE a.ApplicationId = %s AND a.Telemetry = 0 AND a.Retired = 0 AND {LATEST_RATING} = 'A'", (i,))
        n += max(cur.rowcount, 0)
    conn.commit()
    return n


def turn_off(conn, app_id: int) -> int:
    cur = conn.cursor()
    cur.execute("UPDATE cz.Application SET Telemetry = 0, TelemetryState = NULL WHERE ApplicationId = %s AND Telemetry = 1",
                (app_id,))
    n = max(cur.rowcount, 0)
    conn.commit()
    return n


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict):
    from .admin import Response, page, redirect
    if not a.admin:
        if method == "POST" and len(parts) == 2 and re.fullmatch(r"\d{1,9}", parts[1]):
            return redirect(f"/app/{int(parts[1])}?telemetry=not-admin#telemetry")
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Only administrators order Make it A+.</p>"))
    if method == "GET" and len(parts) == 1:
        return view(adm, conn, s, a, q)
    if method != "POST" or len(parts) != 2:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    try:
        if parts[1] == "all":
            ids = [int(x) for x in form.get("app", []) if re.fullmatch(r"\d{1,9}", x)]
            n = turn_on(conn, ids) if ids else 0
            return redirect(f"{BASE}?done={n}&asked={len(set(ids))}")
        if not re.fullmatch(r"\d{1,9}", parts[1]):
            return Response(404, page("Not found", "<h1>Not found</h1>"))
        app_id = int(parts[1])
        back = (lambda code: redirect(f"{BASE}?one={code}")) if form.get("back", [""])[0] == "list" else \
            (lambda code: redirect(f"/app/{app_id}?telemetry={code}#telemetry"))
        if form.get("On", [""])[0] == "1":
            return back("on" if turn_on(conn, [app_id]) else "not-a")
        turn_off(conn, app_id)
        return back("off")
    except Exception as ex:  # noqa: BLE001 - a database from before schema 63
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        print(f"make it A+: {type(ex).__name__}: {ex}", file=sys.stderr)
        if len(parts) == 2 and re.fullmatch(r"\d{1,9}", parts[1]) and form.get("back", [""])[0] != "list":
            return redirect(f"/app/{int(parts[1])}?telemetry=unavailable#telemetry")
        return redirect(f"{BASE}?one=unavailable")


def view(adm, conn, s, a, q: dict):
    from .admin import Response
    try:
        apps = candidates(conn)
    except Exception as ex:  # noqa: BLE001 - a database from before schema 63
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        print(f"make it A+ page: {type(ex).__name__}: {ex}", file=sys.stderr)
        return Response(200, adm._shell(s, a, "Make it A+", "telemetry",
                                        "<p>The results database has no telemetry columns yet: update its schema "
                                        "(<code>containerizer db init</code>).</p>"))
    csrf = adm._csrf(s)
    grafana = getattr(adm, "grafana_url", "") or ""
    rows, can, n_plus, n_on = [], 0, 0, 0
    for r in apps:
        on = bool(r["Telemetry"])
        st = telemetry.parse_state(r["TelemetryState"])
        plus = telemetry.is_plus(r["Rating"], on, st)
        n_plus += plus
        n_on += on
        app_id = int(r["ApplicationId"])
        name = f"<a href='/app/{app_id}#telemetry'>{e(r['ApplicationName'])}</a>"
        where = e(" / ".join(x for x in (r.get("BusinessUnitName"), r.get("ProductName")) if x))
        if on:
            ns = str(st.get("namespace") or "")
            link = grafana_link(grafana, ns)
            state = state_html(st, plus) + (f" {link}" if link else "") + (
                "" if r["Rating"] == "A" else f" <span class='muted'>(now rated {e(str(r['Rating']))})</span>")
            box = "<span class='muted'>on</span>"
        else:
            can += 1
            state = "<span class='muted'>A: OpenTelemetry off</span>"
            box = (f"<label class='sr' for='app{app_id}'>{e(r['ApplicationName'])}</label>"
                   f"<input type='checkbox' id='app{app_id}' name='app' value='{app_id}' checked>")
        rows.append(f"<tr><td>{box}</td><td>{name}</td><td class='small muted'>{where}</td><td class='small'>{state}</td></tr>")
    flash = ""
    done = (q.get("done") or [""])[0]
    if re.fullmatch(r"\d{1,9}", done or ""):
        asked = (q.get("asked") or ["0"])[0]
        flash = (f"Make it A+ ordered for {int(done)} application(s)"
                 + (f"; {int(asked) - int(done)} no longer rate A or had it already" if re.fullmatch(r"\d{1,9}", asked)
                    and int(asked) > int(done) else "")
                 + ": the queue runner instruments them in the sandbox within a few minutes." if int(done) else
                 "Nothing ordered: tick the applications first.")
    one = notice_html((q.get("one") or [""])[0])
    intro = ("<p><b>A+</b> is an application rated A whose OpenTelemetry telemetry is collected. <b>Make it A+</b> "
             "instruments an A application in the sandbox without a code change and without the LLM: each component "
             "gets the auto-instrumentation agent of its runtime (.NET, Java, Node.js, Python) and sends traces, metrics "
             "and logs to the sandbox's collector. Nothing is built again; the pods restart once. A component that brings "
             "the OpenTelemetry SDK in its code gets the collector's address only. Nothing is ordered by opening "
             "this page.</p>"
             f"<p><b>{len([r for r in apps if r['Rating'] == 'A'])}</b> application(s) rate A: <b>{n_plus}</b> A+, "
             f"<b>{n_on - n_plus}</b> ordered or not there yet, <b>{can}</b> without OpenTelemetry.</p>")
    table = ("<table><thead><tr><th><span class='sr'>Order</span></th><th>Application</th><th>Business unit / product</th>"
             f"<th>OpenTelemetry</th></tr></thead><tbody>{''.join(rows)}</tbody></table>" if rows else
             "<p class='muted'>No application rates A yet.</p>")
    button = (f"<p><button>Make it A+: the ticked applications</button> <span class='muted small'>{can} can be "
              "ordered. Turn one off on its results page.</span></p>" if can else "")
    body = f"{intro}{one}<form method='post' action='{BASE}/all'>{csrf}{table}{button}</form>"
    return Response(200, adm._shell(s, a, "Make it A+: every A application", "telemetry", body, flash))
