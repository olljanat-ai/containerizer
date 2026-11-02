"""The results page's **Network connectivity** section (connectivity.py, docs/egress.md#network-connectivity).

Everything the application needs from the network, from every source, in one server-side SVG diagram (no
script, no inline styles: the page's stylesheet colours it, light and dark) and a table with the details and the
evidence: what the assessment inferred (configured URLs and connection strings with their file and line, the
dependencies the NetworkPolicy opens, lab services), what the generated NetworkPolicy allows, what the sandbox
blocked (the egress observer) and what people approved. Applications not (yet) in the sandbox show what was
inferred, and say it is not observed. Approve / Reject (admin_egress.py) show for signed-in staff; the POST
checks who may decide for the application.
"""
from __future__ import annotations

import json
import re

from .connectivity import SOURCE_TEXT, STATUS_TEXT, model, svg

STATUS_CSS = {"allowed": "st-ok", "approved": "st-ok", "proposed": "st-wait", "blocked": "st-bad", "not-allowed": "st-bad",
              "suspicious": "st-bad", "rejected": "st-off", "reported": "st-off", "linked": "st-ok", "link-proposed": "st-wait"}


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def load(conn, app_id: int) -> dict:
    """What the section shows: the latest assessment's network needs, the observed flows, the decisions (empty
    before `db init` made schema 24)."""
    out = {"network": None, "flows": [], "decisions": [], "available": True}
    try:
        r = _rows(conn, "SELECT NetworkJson FROM cz.vNetworkLatest WHERE ApplicationId = %s", (app_id,))
        out["network"] = json.loads(r[0]["NetworkJson"]) if r and r[0].get("NetworkJson") else None
        out["flows"] = _rows(conn, "SELECT * FROM cz.vEgressFlow WHERE ApplicationId = %s ORDER BY LastSeen DESC", (app_id,))
        out["decisions"] = _rows(conn, "SELECT * FROM cz.vEgressDecision WHERE ApplicationId = %s", (app_id,))
    except Exception:  # noqa: BLE001 - a database from before schema 24
        _rollback(conn)
        out["available"] = False
        return out
    try:                                    # links between applications (schema 25)
        out["links_out"] = _rows(conn, "SELECT * FROM cz.vComponentLink WHERE FromApplicationId = %s", (app_id,))
        out["links_in"] = _rows(conn, "SELECT * FROM cz.vComponentLink WHERE ToApplicationId = %s", (app_id,))
        if any(x.get("Status") in ("unresolved", "proposed") for x in out["links_out"]):
            out["candidates"] = _rows(conn, "SELECT ApplicationId, ApplicationName, ComponentName, Role FROM cz.vLinkCandidate "
                                            "WHERE ApplicationId <> %s AND Role NOT IN (N'library', N'test', N'client') "
                                            "ORDER BY ApplicationName, ComponentName", (app_id,))
    except Exception:  # noqa: BLE001
        _rollback(conn)
    return out


def _rollback(conn) -> None:
    try:
        conn.rollback()
    except Exception:  # noqa: BLE001
        pass


def _e(s) -> str:
    from html import escape
    return escape(str(s if s is not None else ""), quote=True)


def section(app: dict, ctx: dict | None) -> str:
    ctx = ctx or {}
    data = app.get("connectivity") or {}
    if not data.get("available", True):
        return ""
    net = data.get("network")
    flows, decisions = data.get("flows") or [], data.get("decisions") or []
    sandbox = app.get("sandbox") or []
    ns = next((s.get("Namespace") for s in sandbox if s.get("Namespace")), None)
    links_out, links_in = data.get("links_out") or [], data.get("links_in") or []
    doc = model(app.get("ApplicationName") or "", net, flows, decisions, None, sandbox, ns,
                links_out=links_out, links_in=[x for x in links_in if x.get("Status") == "confirmed"])
    staff = bool(ctx.get("csrf"))
    from .admin_egress import actions_html, notice_html
    from . import admin_links
    head = ["<section class='card connectivity' id='connectivity'><h2>Network connectivity</h2>",
            notice_html(ctx.get("egress_notice") or ""), admin_links.notice_html(ctx.get("link_notice") or "")]
    if net is None and not flows and not decisions:
        head.append("<p class='muted small'>Scan the application again to see what it needs from the network (this "
                    "assessment was made by an earlier version).</p></section>")
        return "".join(head)
    head.append("<p class='muted small'>What the application needs from the network: inferred from its configuration and "
                "code, allowed by the generated NetworkPolicy, observed (blocked) in the sandbox, and approved for the "
                "real environment. Approval documents a destination; the sandbox stays isolated (on the appliance only "
                "the administrators' egress rules let anything out): the Sandbox column says whether it can reach it. "
                + ("Observed in the sandbox namespace <code>" + _e(ns) + "</code>." if doc["observed"] else
                   "<b>Not observed in the sandbox</b>: everything here is inferred.")
                + " The output repository has the same as <code>connectivity.yaml</code> next to the manifests, for the "
                "real environment's firewall rules. <a href='https://containerizer.eu/egress/'>How it works</a></p>")
    head.append(f"<div class='cf-wrap'>{svg(doc)}</div>")
    rows = []
    by_dec = {(d["Component"], d["Destination"].lower(), int(d["Port"]), d["Protocol"]): d for d in decisions}
    for x in doc["outbound"]:
        ev = "".join(f"<div class='small'><code>{_e(v.get('file'))}:{int(v.get('line') or 0)}</code> "
                     f"<code class='quote'>{_e(str(v.get('quote') or '')[:160])}</code></div>"
                     for v in (x.get("evidence") or [])[:2] if v.get("file"))
        ob = x.get("observed") or {}
        seen = ""
        if ob:
            seen = (f"<div class='small muted'>{int(ob.get('packets') or 0)} dropped · last {_e(str(ob.get('last_seen') or '')[:16])}"
                    + (f" · {_e(', '.join(ob.get('pods') or []))}" if ob.get("pods") else "") + "</div>")
        who = ""
        if x.get("approved_by") and staff:
            who = f"<div class='small muted'>approved by {_e(x['approved_by'])} {_e(str(x.get('approved_at') or '')[:16])}</div>"
        d = by_dec.get((x.get("component"), str(x.get("destination") or "").lower(), int(x.get("port") or 0),
                        x.get("protocol")))
        act = actions_html(d, ctx["csrf"], "app") if d and staff else ""
        if staff and x.get("link"):
            act += admin_links.actions_html(x, ctx["csrf"], data.get("candidates") or [], app.get("ApplicationId"))
        why = x.get("reason") or (f"opened for {x['allowed_by']}" if x.get("allowed_by") else "")
        lk = x.get("link") or {}
        if lk.get("reason") and lk.get("reason") != why:
            why = (why + " · " if why else "") + lk["reason"]
        t = x.get("target") or {}
        to = ""
        if t.get("application_id"):
            to = (f"<div class='small'>→ <a href='/app/{int(t['application_id'])}#connectivity'>{_e(t.get('application'))}</a>"
                  f" / {_e(t.get('component'))} <span class='muted'>({_e(t.get('namespace'))}, port {int(t.get('port') or 0)})"
                  "</span></div>")
            if lk.get("confidence") is not None:
                to += f"<div class='small muted'>confidence {float(lk['confidence']):.2f}</div>"
        if x.get("linked_by") and staff:
            who += f"<div class='small muted'>linked by {_e(x['linked_by'])} {_e(str(x.get('linked_at') or '')[:16])}</div>"
        rows.append(f"<tr><td>{_e(x.get('component'))}</td><td><b>{_e(x.get('destination'))}</b>"
                    f"<div class='muted small'>{_e(_port(x))}</div>{to}</td>"
                    f"<td><span class='st {STATUS_CSS.get(x.get('status'), '')}'>{_e(STATUS_TEXT.get(x.get('status'), x.get('status')))}</span>{who}</td>"
                    f"<td class='small'>{_e(', '.join(SOURCE_TEXT.get(s, s) for s in x.get('sources') or []))}</td>"
                    f"<td class='small'>{_e(why)}</td><td>{ev}{seen}</td><td class='small'>{_sandbox(x)}</td>"
                    f"<td>{act}</td></tr>")
    body = list(head)
    if rows:
        body.append("<h3>Outbound</h3><table><thead><tr><th>Component</th><th>Destination</th><th>Status</th><th>Source</th>"
                    f"<th>Why</th><th>Evidence</th><th>Sandbox</th><th></th></tr></thead><tbody>{''.join(rows)}</tbody></table>")
    else:
        body.append("<p class='muted small'>No outbound destination: DNS and the application's own components only.</p>")
    if doc["inbound"] or doc["internal"]:
        body.append("<h3>Inbound and between components</h3><table class='narrow'><thead><tr><th>From</th><th>To</th>"
                    "<th>Port</th><th>Source</th></tr></thead><tbody>"
                    + "".join(f"<tr><td>{_from(i)}</td><td>{_e(i['to'] if 'to' in i else i['component'])}</td>"
                              f"<td>{int(i['port'])}/{_e(i['protocol'])}</td>"
                              f"<td class='small'>{_e(SOURCE_TEXT.get(i.get('source'), i.get('source') or ''))}</td></tr>"
                              for i in [*({**i, "to": i["component"]} for i in doc["inbound"]), *doc["internal"]])
                    + "</tbody></table>")
    if doc["findings"]:
        body.append("<h3>Findings</h3><ul class='findings'>"
                    + "".join(f"<li><span class='st {FINDING_CSS.get(f['kind'], 'st-warn')}'>"
                              f"{FINDING_TEXT.get(f['kind'], f['kind'])}</span> {_e(f['text'])}</li>"
                              for f in doc["findings"]) + "</ul>")
    if app.get("ProductId") is not None:
        body.append(f"<p class='small'><a href='/connectivity?product={int(app['ProductId'])}'>How the applications of "
                    f"{_e(app.get('ProductName') or 'this product')} connect</a> · <a href='/connectivity'>All applications</a></p>")
    else:
        body.append("<p class='small'><a href='/connectivity'>How all applications connect</a></p>")
    body.append("</section>")
    return "".join(body)


LAYER = {"network-policy": "NetworkPolicy", "appliance-firewall": "appliance firewall", "dns-filter": "DNS filter"}


def _port(x: dict) -> str:
    if not int(x.get("port") or 0):
        return "port unknown (the name was refused)"
    return f"{int(x['port'])}/{x.get('protocol')}"


def _sandbox(x: dict) -> str:
    """Whether the sandbox can reach a destination: its NetworkPolicy and the appliance's egress rules."""
    sb = x.get("sandbox") or {}
    if not sb:
        return ""
    head = {True: "<span class='st st-ok'>Reachable</span>", False: "<span class='st st-off'>Not reachable</span>",
            None: "<span class='st st-off'>Unknown</span>"}[sb.get("reachable")]
    lines = [f"NetworkPolicy {_e(sb.get('network_policy'))}", _e(sb.get("appliance"))]
    seen = [LAYER.get(b, b) for b in x.get("blocked_by") or []]
    if seen:
        lines.append("blocked by the " + _e(", ".join(seen)))
    return head + "".join(f"<div class='muted'>{t}</div>" for t in lines if t)


FINDING_TEXT = {"missing": "Missing", "unexplained": "Unexplained", "link": "Link"}
FINDING_CSS = {"missing": "st-bad", "unexplained": "st-warn", "link": "st-wait"}


def _from(i: dict) -> str:
    if i.get("source") == "link" and i.get("application_id"):
        return (f"<a href='/app/{int(i['application_id'])}#connectivity'>{_e(i.get('application'))}</a>"
                f" / {_e(i.get('from_component'))}")
    return _e(i["from"])


def notice_code(q: dict, key: str = "egress") -> str:
    code = (q.get(key) or [""])[0]
    return code if re.fullmatch(r"[a-z-]{1,20}", code or "") else ""


# --------------------------------------------------------------------------- how applications connect

def load_portfolio(conn, product: int | None = None, bu: int | None = None) -> dict:
    """The applications (of a product or business unit, or all), their components, the links between them and a
    summary of their other outbound destinations."""
    where, params = "", ()
    if product is not None:
        where, params = " WHERE ProductId = %s", (product,)
    elif bu is not None:
        where, params = " WHERE BusinessUnitId = %s", (bu,)
    apps = _rows(conn, "SELECT ApplicationId, ApplicationName, ProductId, ProductName, BusinessUnitName, Rating "
                       f"FROM cz.vApplicationLatest{where} ORDER BY ApplicationName", params)
    ids = {int(a["ApplicationId"]) for a in apps}
    out = {"apps": apps, "links": [], "components": {}, "external": {}, "available": True}
    try:
        for r in _rows(conn, "SELECT ApplicationId, NetworkJson FROM cz.vNetworkLatest"):
            if int(r["ApplicationId"]) in ids and r.get("NetworkJson"):
                net = json.loads(r["NetworkJson"])
                out["components"][int(r["ApplicationId"])] = [c.get("k8s") for c in net.get("components") or []]
        links = _rows(conn, "SELECT * FROM cz.vComponentLink WHERE Status IN (N'proposed', N'confirmed')")
        out["links"] = [x for x in links if int(x["FromApplicationId"]) in ids or (x.get("ToApplicationId") and int(x["ToApplicationId"]) in ids)]
        for x in out["links"]:              # the other side of a link from outside the selection is shown too
            for aid, name, comp in ((x["FromApplicationId"], x["FromApplication"], x["FromComponent"]),
                                    (x["ToApplicationId"], x["ToApplication"], x["ToComponent"])):
                if aid is None:
                    continue
                if int(aid) not in ids:
                    ids.add(int(aid))
                    apps.append({"ApplicationId": aid, "ApplicationName": name, "ProductName": None, "outside": True})
                comps = out["components"].setdefault(int(aid), [])
                if comp and comp not in comps:
                    comps.append(comp)
        for d in _rows(conn, "SELECT ApplicationId, Status FROM cz.vEgressDecision"):
            if int(d["ApplicationId"]) in ids:
                e = out["external"].setdefault(int(d["ApplicationId"]), {})
                e[d["Status"]] = e.get(d["Status"], 0) + 1
    except Exception:  # noqa: BLE001 - a database from before schema 25
        _rollback(conn)
        out["available"] = False
    if product is None and bu is None:      # all applications: those that know their network, or are linked
        out["apps"] = [a for a in apps if out["components"].get(int(a["ApplicationId"])) or out["external"].get(int(a["ApplicationId"]))]
    return out


def portfolio_svg(data: dict) -> str:
    """Applications as columns of their components, links between components (confirmed solid, proposed dashed),
    and each application's decided outbound destinations summed up under it."""
    from html import escape
    apps = data["apps"]
    if not apps:
        return ""
    col_w, box_w, box_h, gap = 320, 200, 30, 44
    per_row = 4
    rows = [apps[i:i + per_row] for i in range(0, len(apps), per_row)]
    pos: dict[tuple, tuple] = {}
    parts, lines = [], []
    y0 = 10
    for row in rows:
        h = 0
        for j, a in enumerate(row):
            aid = int(a["ApplicationId"])
            x = 10 + j * col_w
            comps = data["components"].get(aid) or ["(not assessed)"]
            ext = data["external"].get(aid) or {}
            inner = 40 + len(comps) * gap + (8 + 16 * (len(ext) + 1) if ext else 0)
            h = max(h, inner)
            cls = "cf-group cf-outside" if a.get("outside") else "cf-group"
            parts.append(f"<g><title>{escape(str(a['ApplicationName']))}</title><rect class='{cls}' x='{x}' y='{y0}' "
                         f"width='{box_w + 20}' height='{inner}' rx='10'/>"
                         f"<a href='/app/{aid}#connectivity'><text class='cf-t cf-strong' x='{x + 10}' y='{y0 + 22}'>"
                         f"{escape(_trim(str(a['ApplicationName']), 26))}</text></a></g>")
            for k, c in enumerate(comps):
                cy = y0 + 40 + k * gap
                pos[(aid, c)] = (x + 10, cy + box_h / 2)
                parts.append(f"<rect class='cf-box cf-comp' x='{x + 10}' y='{cy}' width='{box_w}' height='{box_h}' rx='6'/>"
                             f"<text class='cf-t' x='{x + 18}' y='{cy + 20}'>{escape(_trim(c, 26))}</text>")
            if ext:
                ty = y0 + 40 + len(comps) * gap + 10
                parts.append(f"<text class='cf-s' x='{x + 10}' y='{ty}'>Outbound (egress review):</text>")
                for n_, (st, n) in enumerate(sorted(ext.items())):
                    parts.append(f"<text class='cf-s' x='{x + 18}' y='{ty + 16 * (n_ + 1)}'>{int(n)} {escape(st)}</text>")
        y0 += h + 30
    for x in data["links"]:
        a = pos.get((int(x["FromApplicationId"]), x["FromComponent"]))
        b = pos.get((int(x["ToApplicationId"]), x["ToComponent"])) if x.get("ToApplicationId") else None
        if not a or not b:
            continue
        x1, y1 = a[0] + box_w, a[1]
        x2, y2 = b[0], b[1]
        if x2 <= x1:
            x1, x2 = a[0], b[0] + box_w
        cls = "cf-linked" if x["Status"] == "confirmed" else "cf-link-proposed"
        mx = (x1 + x2) / 2
        lines.append(f"<path class='{cls}' d='M{x1:.0f},{y1:.0f} C{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}'>"
                     f"<title>{escape(str(x['FromApplication']))}/{escape(x['FromComponent'])} → "
                     f"{escape(str(x['ToApplication']))}/{escape(str(x['ToComponent']))} ({escape(x['Status'])})</title></path>")
    width = 20 + min(len(apps), per_row) * col_w
    height = y0 + 30
    legend = (f"<path class='cf-linked' d='M10,{height - 12} L38,{height - 12}'/><text class='cf-s' x='44' y='{height - 8}'>"
              f"Linked</text><path class='cf-link-proposed' d='M110,{height - 12} L138,{height - 12}'/>"
              f"<text class='cf-s' x='144' y='{height - 8}'>Link proposed</text>")
    return (f"<svg xmlns='http://www.w3.org/2000/svg' class='cf' viewBox='0 0 {width} {height}' width='{width}' "
            f"height='{height}' role='img' aria-label='How the applications connect'>{''.join(parts)}{''.join(lines)}"
            f"{legend}</svg>")


def _trim(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def render_portfolio(data: dict, title: str, nav: str = "") -> str:
    from .webui import _nav, page
    if not data.get("available", True):
        body = "<p class='muted'>Links between applications need the database schema of this version.</p>"
    else:
        rows = "".join(
            f"<tr><td><a href='/app/{int(x['FromApplicationId'])}#connectivity'>{_e(x['FromApplication'])}</a> / "
            f"{_e(x['FromComponent'])}</td><td><code>{_e(x['Destination'])}:{int(x['Port'])}</code></td>"
            f"<td><a href='/app/{int(x['ToApplicationId'])}#connectivity'>{_e(x['ToApplication'])}</a> / {_e(x['ToComponent'])}</td>"
            f"<td><span class='st {'st-ok' if x['Status'] == 'confirmed' else 'st-wait'}'>"
            f"{'Linked' if x['Status'] == 'confirmed' else 'Proposed'}</span></td>"
            f"<td class='small'>{_e(METHOD.get(x['Method'], x['Method']))}</td></tr>"
            for x in data["links"] if x.get("ToApplicationId"))
        body = (f"<div class='cf-wrap'>{portfolio_svg(data)}</div>"
                + (f"<h2>Links</h2><table><thead><tr><th>From</th><th>Destination</th><th>To</th><th>Status</th><th>Found by</th>"
                   f"</tr></thead><tbody>{rows}</tbody></table>" if rows else
                   "<p class='muted'>No links between these applications yet.</p>"))
    return page(title, f"""{_nav(nav)}<p class='crumbs'><a href='/'>All</a> › Connectivity</p><h1>{_e(title)}</h1>
<p class='muted'>How the applications connect: their components, the links between them (confirmed links solid, proposed ones
dashed) and their other outbound destinations as the egress review decided them. Each application's page has the details.
<a href='https://containerizer.eu/egress/#links-between-applications'>How links are found</a></p>{body}""")


METHOD = {"config": "configuration matches", "observed": "observed in the sandbox", "llm": "LLM", "manual": "by hand"}


CSS = """
.cf-wrap{overflow-x:auto;margin:8px 0 12px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px}
svg.cf{display:block;max-width:100%;height:auto}svg.cf path{fill:none;stroke-width:2}
.cf-box{fill:var(--bg);stroke:var(--muted);stroke-width:1}.cf-comp{fill:#e8f0fe;stroke:#1f5fbf}
.cf-t{font:13px system-ui,-apple-system,"Segoe UI",sans-serif;fill:var(--fg)}.cf-s{font:11px system-ui,sans-serif;fill:var(--muted)}
.cf-h{font:600 12px system-ui,sans-serif;fill:var(--muted);letter-spacing:.04em}
.cf-allowed{stroke:#2e7d32}.cf-approved{stroke:#1565c0}.cf-proposed{stroke:#c98a00;stroke-dasharray:6 4}
.cf-blocked{stroke:#c62828;stroke-dasharray:6 4}.cf-missing{stroke:#e65100;stroke-dasharray:2 4}
svg.cf path.cf-suspicious{stroke:#8e24aa;stroke-width:3;stroke-dasharray:2 3}.cf-rejected{stroke:#8a8983;stroke-dasharray:1 5}
.cf-internal{stroke:var(--muted);stroke-dasharray:4 3}.cf-inbound{stroke:var(--muted)}
.cf-linked{stroke:#00897b}.cf-link-proposed{stroke:#00897b;stroke-dasharray:6 4}.cf-app{fill:#e0f2f1;stroke:#00897b}
svg.cf path.cf-unreachable{stroke-width:1.2;stroke-dasharray:1 3}
.cf-group{fill:var(--card);stroke:var(--line);stroke-width:1}.cf-outside{stroke-dasharray:4 3}.cf-strong{font-weight:600}
form.link-manual{margin-top:6px;display:block}form.link-manual label{display:block}
form.link-manual select{display:block;max-width:170px;margin:2px 0 4px}
code.quote{white-space:pre-wrap;word-break:break-all}ul.findings{padding-left:18px}ul.findings li{margin:4px 0}
@media (prefers-color-scheme:dark){.cf-comp{fill:#16263f;stroke:#7fb0ff}.cf-allowed{stroke:#66bb6a}.cf-approved{stroke:#64b5f6}
.cf-proposed{stroke:#ffc857}.cf-blocked{stroke:#ef5350}.cf-missing{stroke:#ff9800}svg.cf path.cf-suspicious{stroke:#ce93d8}
.cf-linked,.cf-link-proposed{stroke:#4db6ac}.cf-app{fill:#10302d;stroke:#4db6ac}}
"""
