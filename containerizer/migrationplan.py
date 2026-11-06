"""The results page's **Migration plan**: an application that does not rate A, split into what can go first.

The letter grades the whole application's end state. Its components do not have to move together: an organization
scan already deploys every component that rates A on its own to the sandbox (org.select_components). The plan shows

- **Wave 1, now**: components that rate A on their own (the same rule as the application rating,
  assess.rating_of, on one component), build and run, and are in the sandbox or why not;
- **Wave 2, after code changes**: components whose findings can be fixed in code (targeted changes, data kept
  in external services), and what the part that can run in Linux containers rates once they are fixed;
- **Later, after a port or rewrite**: components that need a framework port;
- **Stays on Windows (VMs)**: components that cannot run in a Linux container, with their main obstacle;
- **Between the parts**: the calls from one part to the other (connectivity data), so the reader sees what each
  part needs to reach in the other.

Everything here is a pure function of webui.load_application's data (plus vSandboxDeploy: load_deploys).
"""
from __future__ import annotations

import html
import json
import re
from types import SimpleNamespace

e = html.escape

PLAN_TIERS = ("server", "platform")     # the components the application rating counts (AppAssessment.server)
FAILED_VERIFY = ("build-failed", "run-failed")
TIER_TEXT = {"database": "lives with the database", "client": "desktop client", "other": "not deployed on its own"}


# ---------------------------------------------------------------------------------------------- data

def load_deploys(conn, app_id: int) -> list[dict] | None:
    """The application's sandbox switch and what the latest organization scan deployed (cz.vSandboxDeploy, schema 39);
    None before that schema (the page then knows only the sandbox checks)."""
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT SandboxEnabled, ScanStatus, ScannedAt, Kind, ComponentName, ProjectPath, Reason, Detail, "
                    "LabServices "
                    "FROM cz.vSandboxDeploy WHERE ApplicationId = %s", (app_id,))
        return cur.fetchall()
    except Exception:  # noqa: BLE001 - a database from before schema 39
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None


def stateful(findings, rules: dict) -> dict:
    """Component id -> the titles of its findings that say it keeps its own data (rules with a state)."""
    out: dict = {}
    for f in findings or []:
        if f.get("RuleId") in rules and not f.get("OnlyCommands") and f.get("ComponentId") is not None:
            t = out.setdefault(f["ComponentId"], [])
            if f.get("Title") not in t:
                t.append(f.get("Title"))
    return out


def _stand_in(c: dict, keeps_data: bool, verdict: str | None = None):
    return SimpleNamespace(tier=c.get("Tier") or "server", verdict=verdict or c.get("Verdict") or "info",
                           stateless=not keeps_data)


def rating_of(comps: list[dict], state: dict, fixed: tuple = ()) -> str | None:
    """The rating of these components as an application of their own (assess.rating_of); components in `fixed` (ids)
    count as fixed: configuration only, no data of their own."""
    from .assess import rating_of as rate
    if not comps:
        return None
    return rate(_stand_in(c, False, "config") if c["ComponentId"] in fixed else _stand_in(c, c["ComponentId"] in state)
                for c in comps)


def ready_now(c: dict, state: dict) -> bool:
    """Wave 1: a server component that rates A on its own and has not failed to build and run (what an
    organization scan deploys to the sandbox, org.select_components)."""
    from .assess import rating_of as rate
    return ((c.get("Tier") or "server") == "server" and c.get("VerifyStatus") not in FAILED_VERIFY
            and rate([_stand_in(c, c["ComponentId"] in state)]) == "A")


def count_ready(comps: list[dict], state: dict) -> tuple[int, int]:
    """(components ready now, components the plan counts) of one application: the front page's "2/6 ready now"."""
    plan = [c for c in comps if (c.get("Tier") or "server") in PLAN_TIERS]
    return sum(1 for c in plan if ready_now(c, state)), len(plan)


def lab_report(deploys: list[dict] | None) -> dict:
    """The application's lab services from its latest organization scan ({needed: {service: [component]},
    provided, missing}), or {}."""
    raw = next((d.get("LabServices") for d in deploys or [] if d.get("LabServices")), None)
    try:
        rep = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return {}
    return rep if isinstance(rep, dict) else {}


def lab_off(c: dict, deploys: list[dict] | None) -> list[str]:
    """The lab services this component needs and the lab has turned off."""
    rep = lab_report(deploys)
    needed = rep.get("needed") or {}
    names = {c.get("ComponentName"), c.get("Name")} - {None}
    return [x for x in rep.get("missing") or [] if names & set(needed.get(x) or [])]


def lab_off_html(sb: dict) -> str:
    if not sb.get("lab_off"):
        return ""
    from .labservices import SERVICES
    names = ", ".join(SERVICES[x].title if x in SERVICES else x for x in sb["lab_off"])
    return f"<div class='small lab-off'>needs {e(names)}: turned off in the lab</div>"


def sandbox_state(c: dict, checks: dict, deploys: list[dict] | None) -> dict:
    """sandbox_state_of, with the lab services the component needs that are turned off (lab_off)."""
    st = sandbox_state_of(c, checks, deploys)
    off = lab_off(c, deploys)
    return {**st, "lab_off": off} if off else st


def sandbox_state_of(c: dict, checks: dict, deploys: list[dict] | None) -> dict:
    """Is the component in the sandbox? {state, text, check}: state 'checked' (a sandbox check has a result for it),
    'deployed' (the latest organization scan put it in the output repository, no check result yet), 'off' (the
    application's sandbox switch is off), 'excluded' (the scan left it out: reason), 'none' (not deployed), or
    'unknown' (a database from before schema 39, and no check)."""
    s = checks.get(c["ComponentId"])
    if s and s.get("Status") != "not-found":
        return {"state": "checked", "check": s, "text": ""}
    if deploys is None:
        return {"state": "none", "check": s, "text": "not deployed"} if s else {"state": "unknown", "text": ""}
    base = deploys[0] if deploys else {}
    if base.get("SandboxEnabled") is not None and not base["SandboxEnabled"]:
        return {"state": "off", "text": "not deployed: the application's sandbox is turned off (Admin → Applications)"}
    rows = [d for d in deploys if d.get("Kind") and (
        (d.get("ProjectPath") and d["ProjectPath"] == c.get("ProjectPath")) or d.get("ComponentName") == c.get("ComponentName"))]
    dep = next((d for d in rows if d["Kind"] == "deployed"), None)
    if dep:
        if s:              # the latest check did not find it
            return {"state": "none", "check": s, "text": "not found in the sandbox at the latest check"}
        return {"state": "deployed", "text": "deployed, not checked yet"}
    ex = next((d for d in rows if d["Kind"] == "excluded"), None)
    if ex:
        return {"state": "excluded", "text": f"not deployed: {ex.get('Reason') or 'left out by the scan'}",
                "detail": ex.get("Detail") or ""}
    st = base.get("ScanStatus")
    if st == "sandbox-off":
        return {"state": "off", "text": "not deployed: the application's sandbox is turned off (Admin → Applications)"}
    if st == "moved":
        return {"state": "none", "text": "deployed from the application's own output repository (not checked here)"}
    if not st:
        return {"state": "none", "text": "not deployed: no organization scan deploys this application"}
    return {"state": "none", "text": "not deployed by the latest organization scan"}


def build(app: dict) -> dict:
    """The plan's data: the groups of components, the ratings of the Linux part, the calls between the parts."""
    from .webui import state_rules
    comps = app.get("components") or []
    plan = [c for c in comps if (c.get("Tier") or "server") in PLAN_TIERS]
    other = [c for c in comps if (c.get("Tier") or "server") not in PLAN_TIERS]
    state = stateful(app.get("findings"), state_rules())
    by_comp: dict = {}
    for f in app.get("findings") or []:
        by_comp.setdefault(f.get("ComponentId"), []).append(f)
    checks = {s["ComponentId"]: s for s in app.get("sandbox") or [] if s.get("ComponentId") is not None}
    deploys = app.get("deploys")
    now, after, port, windows = [], [], [], []
    for c in plan:
        v = c.get("Verdict")
        if v == "blocker":
            windows.append(c)
        elif v == "rewrite":
            port.append(c)
        elif ready_now(c, state):
            now.append(c)
        else:
            after.append(c)
    linux = now + after + port
    fix_ids = tuple(c["ComponentId"] for c in after)
    port_ids = tuple(c["ComponentId"] for c in port)
    return {
        "plan": plan, "other": other, "state": state, "findings": by_comp,
        "now": [{"c": c, "sandbox": sandbox_state(c, checks, deploys)} for c in now],
        "after": after, "port": port, "windows": windows,
        "linux_now": rating_of(linux, state),
        "linux_after": rating_of(linux, state, fix_ids) if after else None,
        "linux_after_port": rating_of(linux, state, fix_ids + port_ids) if port else None,
        "calls": crossings(app, linux, windows),
        "checks": checks, "deploys": deploys,
    }


# ------------------------------------------------------------------------------------- between the parts

def _k8s(name: str) -> str:
    from .generate import k8s_name
    return k8s_name(name or "")


def _match(host: str, comps: list[dict], urls: dict) -> tuple[dict | None, str]:
    """The component of the application a configured host names, and how: its Kubernetes service name
    (connectivity's own rule), its sandbox URL, or a host whose first label is the end of the component's name
    ("lending-api.corp.local" for Lucerne.Lending.Api), when exactly one component matches."""
    host = (host or "").lower().rstrip(".")
    first = host.split(".")[0]
    for c in comps:
        k = _k8s(c["ComponentName"])
        if ("." not in host or host.endswith(".svc.cluster.local")) and first == k:
            return c, "service name"
        if urls.get(c["ComponentId"]) and urls[c["ComponentId"]] == host:
            return c, "sandbox URL"
    from .links import internal_looking
    if not internal_looking(host) or not re.fullmatch(r"[a-z0-9-]+", first):
        return None, ""
    hits = [c for c in comps if _k8s(c["ComponentName"]) == first or _k8s(c["ComponentName"]).endswith("-" + first)]
    return (hits[0], "name") if len(hits) == 1 else (None, "")


def crossings(app: dict, linux: list[dict], windows: list[dict]) -> list[dict]:
    """Calls from a component of one part to a component of the other: {from, to, way ('to-windows' or 'to-linux'),
    host, port, scheme, how}. From the destinations the assessment found in configuration and code
    (connectivity data), and links between components of this application."""
    if not linux or not windows:
        return []
    from urllib.parse import urlsplit
    conn = app.get("connectivity") or {}
    net = conn.get("network") or {}
    comps = linux + windows
    by_name = {c["ComponentName"]: c for c in comps}
    by_k8s = {_k8s(c["ComponentName"]): c for c in comps}
    side = {c["ComponentId"]: ("linux" if c in linux else "windows") for c in comps}
    urls = {}
    for s in app.get("sandbox") or []:
        if s.get("ComponentId") is not None and s.get("Url"):
            urls[s["ComponentId"]] = (urlsplit(s["Url"]).hostname or "").lower()
    out, seen = [], set()

    def add(src, dst, host, port, scheme, how):
        if not src or not dst or src is dst or side[src["ComponentId"]] == side[dst["ComponentId"]]:
            return
        k = (src["ComponentId"], dst["ComponentId"])
        if k in seen:
            return
        seen.add(k)
        out.append({"from": src, "to": dst, "way": "to-windows" if side[dst["ComponentId"]] == "windows" else "to-linux",
                    "host": host, "port": port, "scheme": scheme, "how": how})

    for nc in net.get("components") or []:
        src = by_name.get(nc.get("name")) or by_k8s.get(nc.get("k8s") or _k8s(nc.get("name")))
        if not src:
            continue
        for d in nc.get("destinations") or []:
            dst, how = _match(d.get("host"), comps, urls)
            add(src, dst, d.get("host"), d.get("port"), d.get("scheme"), how)
    app_id = app.get("ApplicationId")
    for lk in conn.get("links_out") or []:
        if lk.get("ToApplicationId") == app_id and lk.get("Status") in ("confirmed", "proposed"):
            add(by_name.get(lk.get("FromComponent")), by_name.get(lk.get("ToComponent")), lk.get("Destination"),
                lk.get("Port"), None, "link")
    return sorted(out, key=lambda x: (x["way"] != "to-windows", x["from"]["ComponentName"].lower(),
                                      x["to"]["ComponentName"].lower()))


# ------------------------------------------------------------------------------------------- rendering

def _names(cs: list[dict]) -> str:
    return ", ".join(c["ComponentName"] for c in cs)


def _rated(r: str | None) -> str:
    from .webui import RATING_TITLE, badge
    return f"{badge(r)} <b>{e(RATING_TITLE.get(r, ''))}</b>" if r else ""


def _sandbox_html(sb: dict) -> str:
    return _sandbox_html_state(sb) + lab_off_html(sb)


def _sandbox_html_state(sb: dict) -> str:
    from .webui import SANDBOX_TEXT, _app_url
    if sb["state"] == "checked":       # the status, and the URL as a short link (the Components table has it in full)
        s = sb["check"]
        st = s.get("Status") or ""
        link = _app_url(s)
        if link:
            link = re.sub(r">[^<]*</a>$", ">Open ↗</a>", link)
        return (f"<span class='v-sb-{e(st)}'>{e(SANDBOX_TEXT.get(st, st))}</span>"
                + (f" <span class='small'>{link}</span>" if link else ""))
    if sb["state"] == "deployed":
        return f"<span class='v-sb-scheduled'>{e(sb['text'])}</span>"
    if sb["state"] == "unknown":
        return "<span class='muted'>no sandbox check yet</span>"
    head, _, why = sb["text"].partition(": ")
    # what the gate saw (the build log's end, the hardened run's errors): org.gate_detail
    more = (f"<details class='small gate-detail'><summary>What failed</summary><pre>{e(sb['detail'])}</pre></details>"
            if sb.get("detail") else "")
    return f"<span class='muted'>{e(head)}</span>" + (f"<div class='muted small'>{e(why)}</div>" if why else "") + more


def _fixes(c: dict, plan: dict) -> str:
    fs = plan["findings"].get(c["ComponentId"]) or []
    titles = [f["Title"] for f in fs if f.get("Severity") == "refactor"]
    parts = []
    if titles:
        parts.append("code changes: " + ", ".join(dict.fromkeys(titles)))
    if c["ComponentId"] in plan["state"]:
        parts.append("keeps its own data: " + ", ".join(plan["state"][c["ComponentId"]]))
    if c.get("VerifyStatus") in FAILED_VERIFY:
        parts.append({"build-failed": "the build failed", "run-failed": "it did not run"}[c["VerifyStatus"]]
                     + " when Containerizer built and ran it")
    if (c.get("Tier") or "server") != "server":
        parts.append("needs a Windows product to host it")
    return "; ".join(parts) or "see its findings"


def _obstacle(c: dict, plan: dict, sev: tuple) -> str:
    fs = [f for f in plan["findings"].get(c["ComponentId"]) or [] if f.get("Severity") in sev]
    return fs[0]["Title"] if fs else (c.get("VerdictText") or "")


def summary(plan: dict) -> str:
    n = len(plan["plan"])
    now, after, port, win = (len(plan[k]) for k in ("now", "after", "port", "windows"))
    parts = [f"{now} of {n} component{'s' if n != 1 else ''} can run in Linux containers now"]
    if after:
        parts.append(f"{after} more after code changes")
    if port:
        parts.append(f"{port} after a framework port or rewrite")
    if win:
        parts.append(f"{win} stay{'s' if win == 1 else ''} on Windows")
    line = "; ".join(parts) + "."
    if not now and (after or port):
        line += (" Nothing runs in a Linux container until the framework port is done." if port and not after else
                 " Nothing runs in a Linux container until the code changes are made.")
    elif not now:
        line += " Nothing of it can run in a Linux container."
    return line


def patch_in_sandbox(app: dict) -> dict | None:
    """The "Make it A" order (vRefactorOrder row) whose patched copy runs in the application's folder and namespace
    (variant.py: in place of the scan's output), or None."""
    from .variant import ACTIVE
    live = [o for o in app.get("refactors") or [] if o.get("Goal") == "rating-a" and o.get("SandboxStatus") in ACTIVE]
    return max(live, key=lambda o: int(o.get("JobId") or 0)) if live else None


def section(app: dict, ctx: dict | None = None, refactoring_box: bool = False) -> str:
    """The Migration plan section (empty for an application that rates A, or with no server component)."""
    if app.get("Rating") == "A":
        return ""
    plan = build(app)
    if not plan["plan"]:
        return ""
    from .webui import RATING_TITLE
    out = ["<section class='card plan' id='plan'><h2>Migration plan</h2>",
           f"<p class='plan-sum'><b>{e(summary(plan))}</b></p>",
           "<p class='muted small'>The rating grades the whole application's end state. The plan shows what can go "
           "first: its components do not have to move together, and the ones that are ready run in the sandbox "
           "already. <a href='https://containerizer.eu/overview/#migration-plan'>How it works</a></p>"]
    if (p := patch_in_sandbox(app)):
        out.append(f"<p class='note small'>The sandbox runs the Make it A patch of order #{int(p['JobId'])} in place of "
                   "this application's scan output (its own namespace and URLs): the Sandbox column shows the patched "
                   "copy. <a href='#refactoring'>Refactoring ↓</a></p>")
    n = len(plan["now"]) + len(plan["after"]) + len(plan["port"])
    if n and plan["linux_now"]:
        txt = (f"<p class='plan-rating'>The part that can run in Linux containers ({n} component{'s' if n != 1 else ''}) "
               f"rates {_rated(plan['linux_now'])} now")
        if plan["linux_after"] and plan["linux_after"] != plan["linux_now"]:
            txt += f"; {_rated(plan['linux_after'])} once the code changes below are made"
        if plan["linux_after_port"] and plan["linux_after_port"] not in (plan["linux_now"], plan["linux_after"]):
            txt += f"; {_rated(plan['linux_after_port'])} after the port too"
        out.append(txt + ".</p>")

    out.append("<div class='gens'>")
    # wave 1
    rows = "".join(f"<tr><td><a href='#c{int(x['c']['ComponentId'])}'>{e(x['c']['ComponentName'])}</a></td>"
                   f"<td>{_sandbox_html(x['sandbox'])}</td></tr>" for x in plan["now"])
    out.append("<div class='gen g1'><h3>Wave 1, now <span class='muted small'>to Kubernetes</span></h3>"
               + (f"<p class='muted small'>Rate A on their own: configuration only, no data of their own.</p>"
                  f"<table><thead><tr><th>Component</th><th>Sandbox</th></tr></thead><tbody>{rows}</tbody></table>"
                  if rows else "<p class='muted'>No component rates A on its own yet.</p>") + "</div>")
    # wave 2
    if plan["after"]:
        link = ("<a href='#refactoring'>Make it A ↓</a> (the Refactoring box) has the LLM make these changes"
                if refactoring_box else "The findings below say what to change")
        rows = "".join(f"<tr><td><a href='#c{int(c['ComponentId'])}'>{e(c['ComponentName'])}</a></td>"
                       f"<td class='small'>{e(_fixes(c, plan))}</td></tr>" for c in plan["after"])
        out.append("<div class='gen g2'><h3>Wave 2, after code changes</h3>"
                   f"<p class='muted small'>{link}"
                   + (f"; then the Linux part rates {e(plan['linux_after'])} ({e(RATING_TITLE.get(plan['linux_after'], ''))})"
                      if plan["linux_after"] else "") + ".</p>"
                   f"<table><thead><tr><th>Component</th><th>What to fix</th></tr></thead><tbody>{rows}</tbody></table></div>")
    if plan["port"]:
        rows = "".join(f"<tr><td><a href='#c{int(c['ComponentId'])}'>{e(c['ComponentName'])}</a></td>"
                       f"<td class='small'>{e(_obstacle(c, plan, ('rewrite',)))}</td></tr>" for c in plan["port"])
        out.append("<div class='gen g3'><h3>Later, after a framework port or rewrite</h3>"
                   "<p class='muted small'>Not a targeted change: the component moves to a framework that runs on "
                   "Linux (the migration assistant below lists the replacements).</p>"
                   f"<table><thead><tr><th>Component</th><th>Main obstacle</th></tr></thead><tbody>{rows}</tbody></table></div>")
    if plan["windows"]:
        rows = "".join(f"<tr><td><a href='#c{int(c['ComponentId'])}'>{e(c['ComponentName'])}</a></td>"
                       f"<td class='small'>{e(_obstacle(c, plan, ('blocker',)))}</td></tr>" for c in plan["windows"])
        out.append("<div class='gen gw'><h3>Stays on Windows <span class='muted small'>VMs</span></h3>"
                   "<p class='muted small'>Cannot run in a Linux container: Windows-only technology.</p>"
                   f"<table><thead><tr><th>Component</th><th>Main obstacle</th></tr></thead><tbody>{rows}</tbody></table></div>")
    out.append("</div>")
    if plan["calls"]:
        items = []
        for x in plan["calls"]:
            proto = {"https": " over HTTPS", "http": " over HTTP"}.get(str(x.get("scheme") or "").lower(), "")
            where = " · ".join(v for v in (str(x.get("host") or ""), f"port {int(x['port'])}" if x.get("port") else "") if v)
            need = ("the Windows part must be reachable from the cluster" if x["way"] == "to-windows" else
                    "the cluster must be reachable from the Windows servers")
            how = {"name": "the host name matches the component's name", "service name": "its service name",
                   "sandbox URL": "its sandbox URL", "link": "a link"}.get(x["how"], "")
            items.append(f"<li><b>{e(x['from']['ComponentName'])}</b> calls <b>{e(x['to']['ComponentName'])}</b>{proto}: "
                         f"{e(need)}. <span class='muted small'>({e(where)}{'; ' + e(how) if how else ''})</span></li>")
        out.append("<h3>Between the parts</h3><ul class='plan-calls'>" + "".join(items) + "</ul>"
                   "<p class='muted small'>From the destinations in the components' configuration and code "
                   "(<a href='#connectivity'>Network connectivity ↓</a>): the parts are separately deployable services "
                   "when these calls go over the network.</p>")
    if plan["other"]:
        out.append("<p class='muted small'>Not in the plan: " + "; ".join(
            f"{e(c['ComponentName'])} ({e(TIER_TEXT.get(c.get('Tier'), c.get('Tier') or ''))})" for c in plan["other"]) + ".</p>")
    return "".join(out) + "</section>"


CSS = """
.lab-off{color:#8a5a00}@media (prefers-color-scheme:dark){.lab-off{color:#ffc857}}.lab-needs{margin:6px 0}
.gate-detail summary{cursor:pointer}.gate-detail pre{white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;font-size:12px;margin:4px 0;min-width:340px;max-width:560px}
.scan-again{margin:8px 0}.scan-again form.inline{display:inline}
section.plan .plan-sum{font-size:16px;margin:8px 0 4px}section.plan .plan-rating{margin:6px 0}
section.plan .plan-rating .badge{width:22px;height:22px;line-height:22px;font-size:13px;border-radius:5px;vertical-align:-4px}
.gens{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;margin:12px 0}
.gen{border:1px solid var(--line);border-radius:10px;padding:2px 12px 10px;background:var(--bg);border-top:4px solid var(--line)}
.gen h3{margin:10px 0 2px}.gen p{margin:2px 0 6px}.gen table{background:transparent}.gen{min-width:0}.gen td .small a{overflow-wrap:anywhere}
.gen.g1{border-top-color:var(--rA)}.gen.g2{border-top-color:var(--rB)}.gen.g3{border-top-color:#e0a800}.gen.gw{border-top-color:var(--rE)}
ul.plan-calls{padding-left:18px}ul.plan-calls li{margin:4px 0}
.ready-now{display:block;font-size:11px;font-weight:600;color:#0a7d0a;white-space:nowrap;margin-top:3px}
@media (prefers-color-scheme:dark){.ready-now{color:#4fd14f}}
"""
