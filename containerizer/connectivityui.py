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
              "suspicious": "st-bad", "rejected": "st-off", "reported": "st-off"}


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
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        out["available"] = False
    return out


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
    doc = model(app.get("ApplicationName") or "", net, flows, decisions, None, sandbox, ns)
    staff = bool(ctx.get("csrf"))
    from .admin_egress import actions_html, notice_html
    head = ["<section class='card connectivity' id='connectivity'><h2>Network connectivity</h2>",
            notice_html(ctx.get("egress_notice") or "")]
    if net is None and not flows and not decisions:
        head.append("<p class='muted small'>Scan the application again to see what it needs from the network (this "
                    "assessment was made by an earlier version).</p></section>")
        return "".join(head)
    head.append("<p class='muted small'>What the application needs from the network: inferred from its configuration and "
                "code, allowed by the generated NetworkPolicy, observed (blocked) in the sandbox, and approved. "
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
        why = x.get("reason") or (f"opened for {x['allowed_by']}" if x.get("allowed_by") else "")
        rows.append(f"<tr><td>{_e(x.get('component'))}</td><td><b>{_e(x.get('destination'))}</b>"
                    f"<div class='muted small'>{int(x.get('port') or 0)}/{_e(x.get('protocol'))}</div></td>"
                    f"<td><span class='st {STATUS_CSS.get(x.get('status'), '')}'>{_e(STATUS_TEXT.get(x.get('status'), x.get('status')))}</span>{who}</td>"
                    f"<td class='small'>{_e(', '.join(SOURCE_TEXT.get(s, s) for s in x.get('sources') or []))}</td>"
                    f"<td class='small'>{_e(why)}</td><td>{ev}{seen}</td><td>{act}</td></tr>")
    body = list(head)
    if rows:
        body.append("<h3>Outbound</h3><table><thead><tr><th>Component</th><th>Destination</th><th>Status</th><th>Source</th>"
                    f"<th>Why</th><th>Evidence</th><th></th></tr></thead><tbody>{''.join(rows)}</tbody></table>")
    else:
        body.append("<p class='muted small'>No outbound destination: DNS and the application's own components only.</p>")
    if doc["inbound"] or doc["internal"]:
        body.append("<h3>Inbound and between components</h3><table class='narrow'><thead><tr><th>From</th><th>To</th>"
                    "<th>Port</th><th>Source</th></tr></thead><tbody>"
                    + "".join(f"<tr><td>{_e(i['from'])}</td><td>{_e(i['to'] if 'to' in i else i['component'])}</td>"
                              f"<td>{int(i['port'])}/{_e(i['protocol'])}</td>"
                              f"<td class='small'>{_e(SOURCE_TEXT.get(i.get('source'), i.get('source') or ''))}</td></tr>"
                              for i in [*({"from": i["from"], "to": i["component"], "port": i["port"], "protocol": i["protocol"],
                                           "source": i["source"]} for i in doc["inbound"]), *doc["internal"]])
                    + "</tbody></table>")
    if doc["findings"]:
        body.append("<h3>Findings</h3><ul class='findings'>"
                    + "".join(f"<li><span class='st {'st-bad' if f['kind'] == 'missing' else 'st-warn'}'>"
                              f"{'Missing' if f['kind'] == 'missing' else 'Unexplained'}</span> {_e(f['text'])}</li>"
                              for f in doc["findings"]) + "</ul>")
    body.append("</section>")
    return "".join(body)


def notice_code(q: dict) -> str:
    code = (q.get("egress") or [""])[0]
    return code if re.fullmatch(r"[a-z-]{1,20}", code or "") else ""


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
code.quote{white-space:pre-wrap;word-break:break-all}ul.findings{padding-left:18px}ul.findings li{margin:4px 0}
@media (prefers-color-scheme:dark){.cf-comp{fill:#16263f;stroke:#7fb0ff}.cf-allowed{stroke:#66bb6a}.cf-approved{stroke:#64b5f6}
.cf-proposed{stroke:#ffc857}.cf-blocked{stroke:#ef5350}.cf-missing{stroke:#ff9800}svg.cf path.cf-suspicious{stroke:#ce93d8}}
"""
