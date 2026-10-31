"""Web UI over the results database: business unit -> product -> application -> components.

`python -m containerizer web --sql "<reader connection string>"`. Standard library HTTP server, no
JavaScript: every page is rendered on the server from the v* views with parameterised queries, all
text is HTML-escaped, and responses carry a strict Content-Security-Policy. The results pages are
read-only and need no sign-in; the admin pages (admin.py: mapping, products, business units, change
history) appear when OpenID Connect sign-in is configured (docs/results-database.md#admin-pages).
"""
from __future__ import annotations

import html
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

RATINGS = ["A", "B", "C", "D", "E"]
RATING_TITLE = {"A": "Lift and shift", "B": "Minor refactoring", "C": "Major refactoring", "D": "Partial",
                "E": "Not feasible"}
RATING_TEXT = {"A": "Containers with configuration only", "B": "Small code changes",
               "C": "Framework port needed", "D": "Some components must stay on Windows",
               "E": "Core depends on Windows-only technology"}
ROLE_TEXT = {"web": "Web application", "worker": "Background service", "console": "Console / scheduled job",
             "spa": "Browser front end", "desktop": "Desktop client", "biztalk": "BizTalk integration",
             "sharepoint": "SharePoint solution", "sitecore": "Sitecore site", "sqlclr": "SQL Server CLR code",
             "ssis": "SSIS package", "sqldb": "Database project"}
VERDICT_LABEL = {"info": "Ready", "config": "Ready with configuration", "refactor": "Needs code changes",
                 "rewrite": "Needs a port or rewrite", "blocker": "Cannot run in a Linux container"}
SEV_ORDER = ["blocker", "rewrite", "refactor", "config", "info"]
UNASSIGNED = "Not assigned"
e = html.escape


# ---------------------------------------------------------------------------
# data (cz_reader can read exactly these)

def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def load_overview(conn) -> dict:
    apps = _rows(conn, "SELECT ApplicationId, ApplicationName, ProductId, ProductName, ProductInfoUrl, BusinessUnitId, BusinessUnitName, "
                       "Rating, Score, EffortDays, Confidence, Summary, AssessedAt, Verified FROM cz.vApplicationLatest")
    comps = _rows(conn, "SELECT ApplicationId, COUNT(*) AS N FROM cz.vComponentLatest GROUP BY ApplicationId")
    top = _rows(conn, "SELECT ApplicationId, Title, Severity, COUNT(*) AS N FROM cz.vFindingLatest "
                      "WHERE Severity IN ('blocker', 'rewrite') GROUP BY ApplicationId, Title, Severity")
    unmapped = _rows(conn, "SELECT Kind, COUNT(*) AS N FROM cz.vUnmapped GROUP BY Kind")
    n = {r["ApplicationId"]: r["N"] for r in comps}
    best: dict = {}
    for r in top:
        k = (SEV_ORDER.index(r["Severity"]), -r["N"], r["Title"])
        if r["ApplicationId"] not in best or k < best[r["ApplicationId"]][0]:
            best[r["ApplicationId"]] = (k, r["Title"])
    for a in apps:
        a["Components"] = n.get(a["ApplicationId"], 0)
        a["MainObstacle"] = best.get(a["ApplicationId"], (None, ""))[1]
    return {"apps": apps, "unmapped": {r["Kind"]: r["N"] for r in unmapped}}


def load_application(conn, app_id: int) -> dict | None:
    rows = _rows(conn, "SELECT * FROM cz.vApplicationLatest WHERE ApplicationId = %s", (app_id,))
    if not rows:
        return None
    app = rows[0]
    app["components"] = _rows(conn, "SELECT * FROM cz.vComponentLatest WHERE ApplicationId = %s "
                                    "ORDER BY ComponentName", (app_id,))
    app["findings"] = _rows(conn, "SELECT ComponentId, ComponentName, RuleId, Severity, Title, Why, Fix, Via, OnlyCommands, "
                                  "Refs, Source FROM cz.vFindingLatest WHERE ApplicationId = %s AND Severity <> 'info'",
                            (app_id,))
    app["history"] = _rows(conn, "SELECT TOP (20) AssessedAt, Rating, Score, EffortDays FROM cz.ApplicationAssessment "
                                 "WHERE ApplicationId = %s ORDER BY AssessedAt DESC, AssessmentId DESC", (app_id,))
    return app


# ---------------------------------------------------------------------------
# rendering (pure functions of the data above)

def _num(x, digits: int = 0) -> str:
    x = float(x or 0)
    return f"{x:,.{digits}f}" if digits else f"{round(x):,}"


def _date(d) -> str:
    return d.strftime("%Y-%m-%d") if hasattr(d, "strftime") else e(str(d or ""))


def _confidence(c) -> str:
    c = float(c or 0)
    return "High" if c >= 0.8 else "Medium" if c >= 0.5 else "Low"


def badge(r: str, big: bool = False) -> str:
    r = r if r in RATINGS else "E"
    return f"<span class='badge r{r}{' big' if big else ''}' title='{e(RATING_TITLE[r])}'>{r}</span>"


def segmented(counts: Counter, total: int, label: str, height: int = 28) -> str:
    """One whole split by rating (inline SVG: no inline styles, so the CSP stays strict)."""
    if not total:
        return ""
    parts = [r for r in RATINGS if counts[r]]
    width, gap = 1000.0, 3.0
    usable = width - gap * (len(parts) - 1)
    x, rects = 0.0, []
    for r in parts:
        w = max(usable * counts[r] / total, 4.0)
        rects.append(f"<rect class='f{r}' x='{x:.1f}' y='0' width='{w:.1f}' height='{height}'>"
                     f"<title>{r} {e(RATING_TITLE[r])}: {counts[r]} of {total}</title></rect>")
        x += w + gap
    return (f"<svg class='bar' viewBox='0 0 {width:.0f} {height}' preserveAspectRatio='none' height='{height}' "
            f"role='img' aria-label='{e(label)}'>{''.join(rects)}</svg>")


def legend(counts: Counter | None = None) -> str:
    items = "".join(f"<li><span class='key r{r}'></span><b>{r}</b> {e(RATING_TITLE[r])}"
                    f"{f' <span class=muted>{counts[r]}</span>' if counts is not None else ''}</li>" for r in RATINGS)
    return f"<ul class='legend'>{items}</ul>"


def _mix(apps: list[dict]) -> Counter:
    return Counter(a["Rating"] for a in apps)


def _summary_line(apps: list[dict]) -> str:
    c = _mix(apps)
    ready = c["A"]
    return (f"{len(apps)} application{'s' if len(apps) != 1 else ''} · {ready} ready to containerize · "
            f"{_num(sum(float(a['EffortDays'] or 0) for a in apps), 0)} person-days estimated")


def _bu_href(bu) -> str:
    return "/?bu=" + quote(str(bu if bu is not None else "none"))


def _trends_href(bu) -> str:
    return "/trends" + (f"?bu={quote(str(bu))}" if bu is not None else "")


def render_overview(data: dict, bu_filter: str | None = None, nav: str = "") -> str:
    apps = data["apps"]
    all_apps = apps
    if bu_filter is not None:
        apps = [a for a in apps if str(a["BusinessUnitId"] if a["BusinessUnitId"] is not None else "none") == bu_filter]
    c = _mix(apps)
    total = len(apps)
    effort = sum(float(a["EffortDays"] or 0) for a in apps)
    last = max((a["AssessedAt"] for a in apps if a["AssessedAt"]), default=None)

    def pct(n):
        return f"{round(100 * n / total)}%" if total else "-"
    tiles = (f"<div class='tile'><div class='label'>Applications assessed</div><div class='value'>{total}</div></div>"
             f"<div class='tile'><div class='label'>Ready now (A)</div><div class='value'>{c['A']}</div>"
             f"<div class='sub'>{pct(c['A'])} of applications</div></div>"
             f"<div class='tile'><div class='label'>Need code changes (B, C)</div><div class='value'>{c['B'] + c['C']}</div>"
             f"<div class='sub'>{pct(c['B'] + c['C'])}</div></div>"
             f"<div class='tile'><div class='label'>Partly or not feasible (D, E)</div><div class='value'>{c['D'] + c['E']}</div>"
             f"<div class='sub'>{pct(c['D'] + c['E'])}</div></div>"
             f"<div class='tile'><div class='label'>Estimated effort</div><div class='value'>{_num(effort)}</div>"
             f"<div class='sub'>person-days</div></div>")

    bus: dict = {}
    for a in all_apps:
        key = (a["BusinessUnitName"] or "", a["BusinessUnitId"])
        bus.setdefault(key, []).append(a)
    chips = [f"<a class='chip{' on' if bu_filter is None else ''}' href='/'>All</a>"]
    for (name, bid), lst in sorted(bus.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
        on = bu_filter == str(bid if bid is not None else "none")
        chips.append(f"<a class='chip{' on' if on else ''}' href='{e(_bu_href(bid))}'>{e(name or UNASSIGNED)}"
                     f" <span class='muted'>{len(lst)}</span></a>")

    sections = []
    groups: dict = {}
    for a in apps:
        groups.setdefault((a["BusinessUnitName"] or "", a["BusinessUnitId"]), {}).setdefault(
            (a["ProductName"] or "", a["ProductId"]), []).append(a)
    for (bu, bid), products in sorted(groups.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
        bu_apps = [a for lst in products.values() for a in lst]
        body = []
        for (prod, pid), lst in sorted(products.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
            rows = "".join(
                f"<tr><td>{badge(a['Rating'])}</td>"
                f"<td><a href='/app/{int(a['ApplicationId'])}'>{e(a['ApplicationName'])}</a>"
                f"<div class='muted small'>{e(RATING_TITLE.get(a['Rating'], ''))}: {e(RATING_TEXT.get(a['Rating'], ''))}</div></td>"
                f"<td class='num'>{int(a['Score'])}</td><td class='num'>{_num(a['EffortDays'], 1)}</td>"
                f"<td class='num'>{int(a['Components'])}</td><td>{e(a['MainObstacle'] or '-')}</td></tr>"
                for a in sorted(lst, key=lambda a: (a["Rating"], -int(a["Score"]), a["ApplicationName"].lower())))
            body.append(f"<div class='product'><h3>{e(prod or UNASSIGNED + ' to a product')}{_info_link(lst[0].get('ProductInfoUrl'))} "
                        f"<span class='muted small'>{_summary_line(lst)}</span></h3>"
                        f"<table><thead><tr><th>Rating</th><th>Application</th><th class='num'>Readiness</th>"
                        f"<th class='num'>Effort (days)</th><th class='num'>Components</th><th>Main obstacle</th></tr></thead>"
                        f"<tbody>{rows}</tbody></table></div>")
        bc = _mix(bu_apps)
        sections.append(f"<section class='bu'><h2>{e(bu or UNASSIGNED + ' to a business unit')}</h2>"
                        f"<p class='muted'>{_summary_line(bu_apps)}</p>"
                        f"{segmented(bc, len(bu_apps), f'Ratings in {bu or UNASSIGNED}', 10)}{''.join(body)}</section>")

    um = data.get("unmapped") or {}
    note = ""
    if um.get("Application") or um.get("Product"):
        parts = []
        if um.get("Application"):
            parts.append(f"{um['Application']} application(s) are not mapped to a product")
        if um.get("Product"):
            parts.append(f"{um['Product']} product(s) are not mapped to a business unit")
        note = (f"<p class='note'>{e('; '.join(parts))}. Administrators maintain the mapping on the "
                f"<a href='/admin'>admin pages</a>.</p>") if nav else (
                f"<p class='note'>{e('; '.join(parts))}.</p>")
    empty = "<p>No assessments yet. Run <code>containerizer assess --sql …</code> to add some.</p>" if not all_apps else ""
    return page("Containerization readiness", f"""{_nav(nav)}
<header><h1>Containerization readiness</h1>
<p class='muted'>How ready our applications are to run in Linux containers{f' · last assessed {_date(last)}' if last else ''}
{f" · <a href='{e(_trends_href(bu_filter))}'>Trends over time</a>" if all_apps else ''}</p></header>
{empty}<nav class='chips'>{''.join(chips) if all_apps else ''}</nav>
<div class='tiles'>{tiles if all_apps else ''}</div>
{f"<div class='overall'>{segmented(c, total, 'Ratings of all applications shown')}{legend(c)}</div>" if total else ''}
{note}{''.join(sections)}
<footer>{legend()}<p class='muted small'>Readiness is 0-100 (higher is better) across the server components. Effort is
an estimate in person-days for the work the rules identified. Ratings come from rule-based analysis of the source code,
and where noted were confirmed by building and running the generated containers.</p></footer>""")


def _refs(raw) -> list[str]:
    try:
        refs = json.loads(raw) if raw else []
    except ValueError:
        return []
    return [u for u in refs if isinstance(u, str) and re.match(r"https?://[^\s'\"<>]+$", u)]


def _ref_label(u: str) -> str:
    from .report import ref_label     # "learn.microsoft.com: kestrel endpoints", same as the reports
    return ref_label(u)


def _nav(nav: str) -> str:
    return f"<div class='topnav'><span></span><span>{nav}</span></div>" if nav else ""


def _info_link(url) -> str:
    from .admin import info_link
    return info_link(url)


def render_application(app: dict, nav: str = "") -> str:
    r = app["Rating"]
    crumbs = (f"<a href='/'>All</a> › <a href='{e(_bu_href(app['BusinessUnitId']))}'>"
              f"{e(app['BusinessUnitName'] or UNASSIGNED)}</a> › {e(app['ProductName'] or UNASSIGNED)}"
              f"{_info_link(app.get('ProductInfoUrl'))}")
    by_comp: dict = {}
    for f in app["findings"]:
        by_comp.setdefault(f["ComponentId"], []).append(f)
    obstacles: dict = {}
    for f in app["findings"]:
        if f["Severity"] in ("blocker", "rewrite"):
            o = obstacles.setdefault(f["Title"], {"sev": f["Severity"], "comps": []})
            if f["ComponentName"] and f["ComponentName"] not in o["comps"]:
                o["comps"].append(f["ComponentName"])
    obs = sorted(obstacles.items(), key=lambda kv: (SEV_ORDER.index(kv[1]["sev"]), -len(kv[1]["comps"])))[:5]
    obs_html = "".join(f"<li><span class='sev s-{o['sev']}'>{e(VERDICT_LABEL[o['sev']])}</span> <b>{e(t)}</b>"
                       f"{' <span class=muted>(' + e(', '.join(o['comps'])) + ')</span>' if o['comps'] else ''}</li>"
                       for t, o in obs)

    comp_rows = "".join(
        f"<tr><td><a href='#c{int(c['ComponentId'])}'>{e(c['ComponentName'])}</a>"
        f"<div class='muted small'>{e(c['ProjectPath'])}</div></td>"
        f"<td>{e(ROLE_TEXT.get(c['Role'], c['Role'].title()))}</td>"
        f"<td><span class='sev s-{e(c['Verdict'])}'>{e(VERDICT_LABEL.get(c['Verdict'], c['Verdict']))}</span></td>"
        f"<td class='num'>{_num(c['EffortDays'], 1)}</td>"
        f"<td>{_verify(c)}</td></tr>" for c in app["components"])

    details = []
    for c in app["components"]:
        fs = sorted(by_comp.get(c["ComponentId"], []), key=lambda f: SEV_ORDER.index(f["Severity"]))
        items = "".join(_finding(f) for f in fs) or "<p class='muted'>Nothing to change.</p>"
        details.append(f"<details id='c{int(c['ComponentId'])}'{' open' if len(app['components']) == 1 else ''}>"
                       f"<summary><b>{e(c['ComponentName'])}</b> · {e(VERDICT_LABEL.get(c['Verdict'], c['Verdict']))}"
                       f" <span class='muted'>({len(fs)} item{'s' if len(fs) != 1 else ''})</span></summary>"
                       f"<div class='muted small'>{e(c['VerdictText'])}{'; a Windows container is a workable stop-gap' if c['WindowsContainerOk'] and c['Verdict'] in ('rewrite', 'blocker') else ''}"
                       f"{'; targets ' + e(c['TargetFramework']) if c['TargetFramework'] else ''}</div>{items}</details>")
    repo = by_comp.get(None, [])
    if repo:
        details.append("<details><summary><b>Repository</b></summary>" + "".join(_finding(f) for f in repo) + "</details>")

    hist = "".join(f"<tr><td>{_date(h['AssessedAt'])}</td><td>{badge(h['Rating'])}</td><td class='num'>{int(h['Score'])}</td>"
                   f"<td class='num'>{_num(h['EffortDays'], 1)}</td></tr>" for h in app["history"])
    src = ""
    if app.get("RepositoryUrl"):
        u = app["RepositoryUrl"]
        link = f"<a href='{e(u)}' rel='noopener noreferrer'>{e(u)}</a>" if re.match(r"https?://", u) else e(u)
        src = (f"<div><span class='label'>Source</span> {link}{' / ' + e(app['SourcePath']) if app.get('SourcePath') not in (None, '.') else ''}"
               f"{' @ ' + e(str(app['SourceCommit'])[:12]) if app.get('SourceCommit') else ''}</div>")
    owner = "".join(f"<div><span class='label'>{k}</span> {e(v)}</div>" for k, v in
                    (("Owner", app.get("Owner")), ("Product owner", app.get("ProductOwner")),
                     ("Business unit owner", app.get("BusinessUnitOwner"))) if v)
    return page(app["ApplicationName"], f"""{_nav(nav)}
<p class='crumbs'>{crumbs}</p>
<header class='app'>{badge(r, True)}<div><h1>{e(app['ApplicationName'])}</h1>
<p class='lead'><b>{e(RATING_TITLE.get(r, ''))}</b>: {e(RATING_TEXT.get(r, ''))}</p>
{f"<p>{e(app['Description'])}</p>" if app.get('Description') else ''}<p>{e(app['Summary'])}</p></div></header>
<div class='tiles'>
<div class='tile'><div class='label'>Readiness</div><div class='value'>{int(app['Score'])}<span class='unit'>/100</span></div></div>
<div class='tile'><div class='label'>Estimated effort</div><div class='value'>{_num(app['EffortDays'], 1)}</div><div class='sub'>person-days</div></div>
<div class='tile'><div class='label'>Confidence</div><div class='value'>{_confidence(app['Confidence'])}</div>
<div class='sub'>{'confirmed by building and running' if app['Verified'] else 'from source analysis'}</div></div>
<div class='tile'><div class='label'>Last assessed</div><div class='value small-value'>{_date(app['AssessedAt'])}</div></div>
</div>
<div class='meta'>{owner}{src}</div>
{f"<h2>Main obstacles</h2><ul class='obstacles'>{obs_html}</ul>" if obs_html else ''}
<h2>Components</h2>
<table><thead><tr><th>Component</th><th>What it is</th><th>Verdict</th><th class='num'>Effort (days)</th><th>Build and run</th></tr></thead>
<tbody>{comp_rows}</tbody></table>
<h2>What needs to change, and why</h2>{''.join(details)}
<h2>History</h2><p class='muted small'><a href='/trends'>Trends of all applications</a></p><table class='narrow'><thead><tr><th>Assessed</th><th>Rating</th><th class='num'>Readiness</th>
<th class='num'>Effort (days)</th></tr></thead><tbody>{hist}</tbody></table>
<footer>{legend()}</footer>""")


def _verify(c: dict) -> str:
    s = c.get("VerifyStatus")
    if not s:
        return "<span class='muted'>not run</span>"
    text = {"ok": "Runs", "ok-external": "Runs (stops only at missing external services)",
            "finding": "Runs with a finding", "build-failed": "Build failed", "run-failed": "Run failed"}.get(s, s)
    return f"<span class='v-{e(s)}'>{e(text)}</span>"


def _finding(f: dict) -> str:
    refs = _refs(f.get("Refs"))
    extra = []
    if f.get("Via"):
        extra.append(f"comes from the shared library {e(f['Via'])}")
    if f.get("OnlyCommands"):
        extra.append(f"only the {e(f['OnlyCommands'])} command(s)")
    if f.get("Source") == "runtime":
        extra.append("found by building and running")
    out = [f"<div class='finding'><div><span class='sev s-{e(f['Severity'])}'>"
           f"{e(VERDICT_LABEL.get(f['Severity'], f['Severity']))}</span> <b>{e(f['Title'])}</b>"
           + (" <span class='muted'>(" + "; ".join(extra) + ")</span>" if extra else "") + "</div>"]
    for label, key in (("Why", "Why"), ("Fix", "Fix")):
        if f.get(key):
            out.append(f"<p><span class='label'>{label}</span> {e(_ws(f[key]))}</p>")
    if refs:
        out.append("<p><span class='label'>Learn more</span> " + ", ".join(
            f"<a href='{e(u)}' rel='noopener noreferrer'>{e(_ref_label(u))}</a>" for u in refs) + "</p>")
    return "".join(out) + "</div>"


def _ws(s) -> str:
    return " ".join(str(s or "").split())


def page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>{e(title)}</title>"
            f"<link rel='stylesheet' href='/static/app.css'><link rel='icon' href='data:,'></head>"
            f"<body><main>{body}</main></body></html>")


CSS = """
:root{--bg:#f9f9f7;--card:#fff;--fg:#0b0b0b;--muted:#5f5e58;--line:#e1e0d9;--link:#1f5fbf;
--rA:#0ca30c;--rB:#74c476;--rC:#fab219;--rD:#ec835a;--rE:#d03b3b}
@media (prefers-color-scheme:dark){:root{--bg:#1a1a19;--card:#232321;--fg:#f0efe9;--muted:#a8a69c;--line:#383835;--link:#7fb0ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 20px 48px}a{color:var(--link)}h1{font-size:28px;margin:0 0 4px}
h2{font-size:20px;margin:32px 0 8px}h3{font-size:16px;margin:20px 0 6px}h3 .small{font-weight:400}.muted{color:var(--muted)}.small{font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .label,.label{color:var(--muted);font-size:13px}.tile .value{font-size:30px;font-weight:650;line-height:1.2}
.small-value{font-size:20px!important}.unit{font-size:15px;color:var(--muted);font-weight:400}.tile .sub{color:var(--muted);font-size:13px}
.label{margin-right:6px;font-weight:600}
.bar{display:block;width:100%;margin:8px 0;border-radius:6px}.bu .bar{border-radius:5px}
.fA{fill:var(--rA)}.fB{fill:var(--rB)}.fC{fill:var(--rC)}.fD{fill:var(--rD)}.fE{fill:var(--rE)}
.rA{background:var(--rA)}.rB{background:var(--rB)}.rC{background:var(--rC)}.rD{background:var(--rD)}.rE{background:var(--rE)}
.legend{list-style:none;padding:0;margin:6px 0;display:flex;flex-wrap:wrap;gap:4px 18px;font-size:13px}
.key{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:baseline}
.badge{display:inline-block;width:28px;height:28px;line-height:28px;text-align:center;border-radius:6px;font-weight:700;color:#fff}
.badge.rB,.badge.rC{color:#0b0b0b}.badge.big{width:64px;height:64px;line-height:64px;font-size:34px;border-radius:12px;flex:none}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.chip{border:1px solid var(--line);border-radius:999px;padding:4px 12px;
text-decoration:none;color:var(--fg);background:var(--card)}.chip.on{border-color:var(--fg);font-weight:600}
section.bu{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 18px 14px;margin:18px 0}
table{border-collapse:collapse;width:100%;font-size:14px;background:var(--card)}th{font-weight:600;color:var(--muted);font-size:13px}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}.num{text-align:right;white-space:nowrap}
table.narrow{width:auto;min-width:420px}
header.app{display:flex;gap:18px;align-items:flex-start;margin-top:8px}.lead{font-size:17px;margin:4px 0}
.crumbs{font-size:13px;color:var(--muted)}.meta{display:grid;gap:4px;font-size:14px}
.sev{display:inline-block;font-size:12px;font-weight:600;border-radius:4px;padding:1px 7px;border:1px solid currentColor;white-space:nowrap}
.s-blocker{color:#b42727}.s-rewrite{color:#b85a2e}.s-refactor{color:#8a6100}.s-config,.s-info{color:#0a7d0a}
@media (prefers-color-scheme:dark){.s-blocker{color:#f07a7a}.s-rewrite{color:#f2a07f}.s-refactor{color:#fac35a}.s-config,.s-info{color:#4fd14f}}
.v-ok,.v-ok-external{color:#0a7d0a}.v-build-failed,.v-run-failed{color:#b42727}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0}
summary{cursor:pointer}.finding{border-top:1px solid var(--line);padding:10px 0 4px;margin-top:10px}.finding p{margin:4px 0}
.obstacles{padding-left:18px}.obstacles li{margin:4px 0}
.note{background:var(--card);border-left:4px solid var(--rC);padding:8px 12px;border-radius:4px}
footer{margin-top:36px;border-top:1px solid var(--line);padding-top:12px}code{font-size:13px}
.topnav{display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:14px;margin-bottom:12px}
form.inline{display:inline}button{font:inherit;border:1px solid var(--fg);background:var(--fg);color:var(--bg);border-radius:6px;
padding:6px 14px;cursor:pointer}button.link{border:0;background:none;color:var(--link);padding:0;text-decoration:underline}
form.edit{display:grid;gap:6px;max-width:640px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
form.edit label{font-weight:600;font-size:14px;margin-top:6px}form.edit label.check{font-weight:400}
input:not([type=checkbox]),select,textarea{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;
background:var(--bg);color:var(--fg);width:100%}.formrow{display:flex;gap:10px;align-items:center;margin:12px 0;flex-wrap:wrap}
.formrow select{width:auto;min-width:260px}form.danger button{background:#b42727;border-color:#b42727;color:#fff;margin-top:12px}
ul.changes{margin:2px 0;padding-left:18px}del{color:var(--muted)}ins{text-decoration:none;font-weight:600}.nowrap{white-space:nowrap}
.ext{white-space:nowrap;font-weight:400}
section.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 18px 14px;margin:18px 0}
section.card details{border:0;padding:0;background:none}
.chart{display:block;width:100%;height:auto;margin:6px 0;--grid:#e1e0d9;--axis:#c3c2b7;--o1:#2a78d6;--o2:#eb6834}
@media (prefers-color-scheme:dark){.chart{--grid:#2c2c2a;--axis:#4a4a46;--o1:#3987e5;--o2:#d95926}}
.chart .grid{stroke:var(--grid);stroke-width:1}.chart .axis{stroke:var(--axis);stroke-width:1}
.chart .tick{fill:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}.chart .val{fill:var(--fg);font-size:13px;font-weight:600}
.chart .hit{fill:transparent}.chart g:hover .hit{fill:var(--line);fill-opacity:.35}
.chart .line{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.chart .line.o1{stroke:var(--o1)}.chart .line.o2{stroke:var(--o2)}
.chart .dot{stroke:var(--card);stroke-width:2}.chart .dot.o1{fill:var(--o1)}.chart .dot.o2{fill:var(--o2)}
.lkey{display:inline-block;width:14px;height:2px;border-radius:1px;margin-right:6px;vertical-align:middle}
.legend .lkey.o1{background:#2a78d6}.legend .lkey.o2{background:#eb6834}
@media (prefers-color-scheme:dark){.legend .lkey.o1{background:#3987e5}.legend .lkey.o2{background:#d95926}}
.strip{display:inline-flex;gap:2px}.cell{display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;
font-size:11px;font-weight:700;border-radius:4px;color:#fff}.cell.rB,.cell.rC{color:#0b0b0b}
.cell.none{background:var(--line);opacity:.5}
.good{color:#006300;font-weight:600}.bad{color:#b42727;font-weight:600}
@media (prefers-color-scheme:dark){.good{color:#4fd14f}.bad{color:#f07a7a}}
.chips+.chips{margin-top:8px}
@media (forced-colors:active){.bar,.badge,.key,.cell,.chart{forced-color-adjust:none;border:1px solid CanvasText}}
"""

HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",       # cross-site: nothing; same-site POSTs keep a real Origin for the CSRF check
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cache-Control": "no-store",
}


def make_handler(connect, admin=None):
    """`connect()` returns a reader connection for one request; `admin` is an admin.Admin or None."""

    class Handler(BaseHTTPRequestHandler):
        def version_string(self):
            return "containerizer"

        def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8", head: bool = False,
                  extra: list | None = None, forms: bool = False):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in HEADERS.items():
                if forms and k == "Content-Security-Policy":
                    v = v.replace("form-action 'none'", "form-action 'self'")
                self.send_header(k, v)
            if admin and admin.cfg.secure:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(data)

        def do_HEAD(self):
            self.do_GET(head=True)

        def _admin(self, method: str, head: bool = False):
            u = urlsplit(self.path)
            body = b""
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > 64 * 1024:
                    return self._send(413, page("Too large", "<h1>Request too large</h1>"))
                body = self.rfile.read(n)
            r = admin.handle(method, u.path, u.query, self.headers, body)
            return self._send(r.status, r.body, r.ctype, head, r.headers, forms=True)

        def _api(self, method: str, head: bool = False):
            u = urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, 64 * 1024 + 1)) if n else b""
            r = admin.api.handle(method, u.path, parse_qs(u.query), self.headers, body)
            return self._send(r.status, r.body, r.ctype, head, r.headers)

        def _write(self, method: str):
            u = urlsplit(self.path)
            try:
                if admin and admin.api and admin.api.handles(u.path):
                    return self._api(method)
                if method == "POST" and admin and admin.handles(u.path):
                    return self._admin("POST")
                return self._not_allowed()
            except Exception as ex:
                return self._error(ex)

        def do_POST(self):
            return self._write("POST")

        def do_PATCH(self):
            return self._write("PATCH")

        def do_PUT(self):
            return self._write("PUT")

        def do_DELETE(self):
            return self._write("DELETE")

        def do_GET(self, head: bool = False):
            u = urlsplit(self.path)
            try:
                if u.path == "/static/app.css":
                    return self._send(200, CSS, "text/css; charset=utf-8", head)
                if u.path == "/healthz":
                    return self._send(200, "ok", "text/plain; charset=utf-8", head)
                if admin and admin.api and admin.api.handles(u.path):
                    return self._api("GET", head)
                if admin and admin.handles(u.path):
                    return self._admin("GET", head)
                nav = admin.nav(self.headers) if admin else ""
                if u.path == "/trends":
                    from . import trends
                    rng, bu, product = trends.parse_query(parse_qs(u.query))
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    since = trends.since_for(rng, now)
                    conn = connect()
                    try:
                        data = trends.compute(trends.load_history(conn, since), now, since)
                    finally:
                        conn.close()
                    return self._send(200, trends.render_trends(data, rng, bu, product, nav), head=head, forms=bool(nav))
                m = re.fullmatch(r"/app/(\d{1,9})", u.path)
                if u.path == "/" or m:
                    conn = connect()
                    try:
                        if m:
                            app = load_application(conn, int(m[1]))
                            if app is None:
                                return self._send(404, page("Not found", "<h1>Application not found</h1><p><a href='/'>Back</a></p>"),
                                                  head=head)
                            return self._send(200, render_application(app, nav), head=head, forms=bool(nav))
                        bu = parse_qs(u.query).get("bu", [None])[0]
                        if bu is not None and not re.fullmatch(r"\d{1,9}|none", bu):
                            bu = None
                        return self._send(200, render_overview(load_overview(conn), bu, nav), head=head, forms=bool(nav))
                    finally:
                        conn.close()
                return self._send(404, page("Not found", "<h1>Not found</h1><p><a href='/'>Back</a></p>"), head=head)
            except Exception as ex:      # never show internals to the browser
                return self._error(ex, head)

        def _error(self, ex, head: bool = False):
            print(f"error: {self.command} {urlsplit(self.path).path}: {type(ex).__name__}: {ex}", file=sys.stderr)
            return self._send(500, page("Error", "<h1>Something went wrong</h1><p>The results database could not be "
                                                 "read or updated. The details are in the server log.</p>"), head=head)

        def _not_allowed(self):
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD" + (", POST" if admin else ""))
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_OPTIONS = _not_allowed

        def log_request(self, code="-", size="-"):
            # the path only: query strings can carry sign-in codes
            print(f"{self.address_string()} {self.command} {urlsplit(self.path).path} {code}", file=sys.stderr)

        def log_message(self, fmt, *args):
            print(f"{self.address_string()} {fmt % args}", file=sys.stderr)

    return Handler


def serve(cs: str | None, host: str = "127.0.0.1", port: int = 8080) -> int:
    from .admin import build
    from .oidc import OidcError
    from .sqlstore import SqlError, connect
    try:
        connect(cs).close()           # fail fast on a bad connection string or credentials
        admin = build()
        if admin:
            admin.connect_admin().close()
    except (SqlError, OidcError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 3
    httpd = ThreadingHTTPServer((host, port), make_handler(lambda: connect(cs), admin))
    print(f"containerizer results UI on http://{host}:{port}/ (results read-only without sign-in; "
          + (f"admin pages behind sign-in at {admin.cfg.public_url}/admin" if admin else "admin pages off: no sign-in configured")
          + ("; JSON API at /api/v1)" if admin and admin.api else ")"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
