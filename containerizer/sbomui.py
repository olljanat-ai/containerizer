"""Web UI pages for software bills of materials: a component's packages, and the portfolio's licences and CVEs.

    /app/{id}/component/{cid}                 packages of one component: version, licence and its status, CVEs
    /app/{id}/component/{cid}/sbom.cdx.json   the CycloneDX document
    /sbom[?bu=&product=]                      licences and CVEs across the portfolio, by business unit and product

Read from cz.vSbomLatest, cz.vSbomPackageLatest and cz.vSbomDocumentLatest (containerizer/sql/sbom.sql)
with parameterised queries; server-rendered, inline SVG with native tooltips, no inline styles, and every
chart has a table view, like the rest of the UI.
"""
from __future__ import annotations

import json
import re
import sys
from urllib.parse import urlencode

from .webui import UNASSIGNED, _date, _nav, _num, e, page

STATUS_TEXT = {"allowed": "Allowed", "warn": "Review", "denied": "Denied", "unknown": "Unknown"}
STATUS_HELP = {"allowed": "the licence policy allows it",
               "warn": "the licence policy asks for a review (for example a copyleft licence)",
               "denied": "the licence policy does not allow it: the security gate fails",
               "unknown": "no licence was found, or it is not a standard (SPDX) licence"}
STATUS_ORDER = ["denied", "warn", "unknown", "allowed"]
TYPE_TEXT = {"nuget": "NuGet", "npm": "npm", "deb": "OS package (deb)", "apk": "OS package (apk)",
             "rpm": "OS package (rpm)", "pypi": "Python", "maven": "Java", "golang": "Go", "gem": "Ruby"}
SEV = (("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low"))


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def _missing(ex) -> list:
    print(f"warning: SBOM views not available ({type(ex).__name__}); run `containerizer db init`", file=sys.stderr)
    return []


# ---------------------------------------------------------------------------
# data

def load_app_sboms(conn, app_id: int) -> dict:
    """ComponentId -> package counts of the latest SBOMs of one application (application page column)."""
    try:
        rows = _rows(conn, "SELECT ComponentId, MAX(Kind) AS Kind, COUNT(*) AS Packages, "
                           "SUM(CASE WHEN PolicyApplies = 1 AND LicenseStatus = 'denied' THEN 1 ELSE 0 END) AS Denied, "
                           "SUM(CASE WHEN PolicyApplies = 1 AND LicenseStatus = 'warn' THEN 1 ELSE 0 END) AS Warn, "
                           "SUM(Critical) AS Critical, SUM(High) AS High "
                           "FROM cz.vSbomPackageLatest WHERE ApplicationId = %s GROUP BY ComponentId", (app_id,))
        empty = _rows(conn, "SELECT ComponentId, Kind FROM cz.vSbomLatest WHERE ApplicationId = %s AND PackageCount = 0",
                      (app_id,))
    except Exception as ex:          # schema not upgraded yet
        return {x: x for x in _missing(ex)}
    out = {r["ComponentId"]: r for r in rows}
    for r in empty:
        out.setdefault(r["ComponentId"], {**r, "Packages": 0, "Denied": 0, "Warn": 0, "Critical": 0, "High": 0})
    return out


def load_component(conn, app_id: int, comp_id: int) -> dict | None:
    rows = _rows(conn, "SELECT c.ApplicationId, c.ApplicationName, c.ComponentId, c.ComponentName, c.ProjectPath, c.Role, "
                       "c.Verdict, a.ProductName, a.ProductInfoUrl, a.BusinessUnitId, a.BusinessUnitName, a.AssessedAt "
                       "FROM cz.vComponentLatest c JOIN cz.vApplicationLatest a ON a.ApplicationId = c.ApplicationId "
                       "WHERE c.ApplicationId = %s AND c.ComponentId = %s", (app_id, comp_id))
    if not rows:
        return None
    comp = rows[0]
    try:
        sb = _rows(conn, "SELECT SbomId, Kind, CreatedAt, ImageRef, ImageDigest, Format, Tool, OperatingSystem, PackageCount, "
                         "Attestation FROM cz.vSbomLatest WHERE ApplicationId = %s AND ComponentId = %s", (app_id, comp_id))
        comp["sbom"] = sb[0] if sb else None
        comp["packages"] = _rows(conn, "SELECT Name, Version, Type, Purl, License, LicenseSource, LicenseStatus, Scope, "
                                       "PolicyApplies, Accepted, FoundBy, Critical, High, Medium, Low, Vulns "
                                       "FROM cz.vSbomPackageLatest WHERE ApplicationId = %s AND ComponentId = %s "
                                       "ORDER BY PackageNo", (app_id, comp_id)) if sb else []
    except Exception as ex:
        comp["sbom"], comp["packages"] = None, _missing(ex)
    return comp


def load_document(conn, app_id: int, comp_id: int) -> str | None:
    try:
        rows = _rows(conn, "SELECT Document FROM cz.vSbomDocumentLatest WHERE ApplicationId = %s AND ComponentId = %s",
                     (app_id, comp_id))
    except Exception as ex:
        rows = _missing(ex)
    return rows[0]["Document"] if rows else None


def parse_query(q: dict) -> tuple[str | None, str | None]:
    bu = q.get("bu", [None])[0]
    bu = bu if bu is not None and re.fullmatch(r"\d{1,9}|none", bu) else None
    product = q.get("product", [None])[0]
    product = product if product is not None and re.fullmatch(r"\d{1,9}|none", product) and bu is not None else None
    return bu, product


def _where(bu: str | None, product: str | None) -> tuple[str, tuple]:
    w, p = [], []
    for col, v in (("BusinessUnitId", bu), ("ProductId", product)):
        if v == "none":
            w.append(f"{col} IS NULL")
        elif v is not None:
            w.append(f"{col} = %s")
            p.append(int(v))
    return (" WHERE " + " AND ".join(w)) if w else "", tuple(p)


def load_portfolio(conn, bu: str | None = None, product: str | None = None) -> dict:
    """Aggregates for the portfolio page, computed in SQL (a portfolio has many packages)."""
    where, params = _where(bu, product)
    try:
        apps_all = _rows(conn, "SELECT DISTINCT ApplicationId, ApplicationName, ProductId, ProductName, BusinessUnitId, "
                               "BusinessUnitName FROM cz.vSbomLatest")
        comps = _rows(conn, f"SELECT Kind, COUNT(*) AS N FROM cz.vSbomLatest{where} GROUP BY Kind", params)
        # one row per distinct package version: CVE counts belong to the version, not to where it is used
        and_ = " AND " if where else " WHERE "
        pk = _rows(conn, "SELECT COUNT(*) AS Packages, SUM(CASE WHEN Critical + High + Medium + Low > 0 THEN 1 ELSE 0 END) AS Vulnerable, "
                         "SUM(Critical) AS Critical, SUM(High) AS High FROM (SELECT Name, Version, Type, MAX(Critical) AS Critical, "
                         "MAX(High) AS High, MAX(Medium) AS Medium, MAX(Low) AS Low FROM cz.vSbomPackageLatest"
                         f"{where} GROUP BY Name, Version, Type) x", params)[0]
        status = _rows(conn, "SELECT LicenseStatus, COUNT(*) AS N FROM (SELECT DISTINCT Name, Version, Type, LicenseStatus "
                             f"FROM cz.vSbomPackageLatest{where}{and_}PolicyApplies = 1) x GROUP BY LicenseStatus", params)
        # licence page links are one group: each URL is different, none is a standard licence
        grp = "CASE WHEN License LIKE 'LicenseRef-url:%' THEN 'LicenseRef-url:' ELSE COALESCE(License, '') END"
        licenses = _rows(conn, f"SELECT TOP (12) {grp} AS License, MAX(LicenseStatus) AS LicenseStatus, "
                               "COUNT(*) AS N FROM (SELECT DISTINCT Name, Version, Type, License, LicenseStatus FROM "
                               f"cz.vSbomPackageLatest{where}{and_}PolicyApplies = 1) x GROUP BY {grp} "
                               f"ORDER BY COUNT(*) DESC, {grp}", params)
        per_app = _rows(conn, "SELECT ApplicationId, ApplicationName, ProductName, BusinessUnitName, COUNT(DISTINCT ComponentId) AS Components, "
                              "COUNT(*) AS Packages, "
                              "SUM(CASE WHEN PolicyApplies = 1 AND LicenseStatus = 'denied' THEN 1 ELSE 0 END) AS Denied, "
                              "SUM(CASE WHEN PolicyApplies = 1 AND LicenseStatus = 'warn' THEN 1 ELSE 0 END) AS Warn, "
                              "SUM(CASE WHEN PolicyApplies = 1 AND LicenseStatus = 'unknown' THEN 1 ELSE 0 END) AS Unknown, "
                              f"SUM(Critical) AS Critical, SUM(High) AS High FROM cz.vSbomPackageLatest{where} "
                              "GROUP BY ApplicationId, ApplicationName, ProductName, BusinessUnitName", params)
        attention = _rows(conn, "SELECT TOP (50) Name, Version, Type, License, LicenseStatus, MAX(Accepted) AS Accepted, "
                                "COUNT(DISTINCT ApplicationId) AS Apps, MIN(ApplicationName) AS FirstApp, MIN(ApplicationId) AS FirstAppId "
                                f"FROM cz.vSbomPackageLatest{where}{and_}PolicyApplies = 1 AND LicenseStatus IN ('denied', 'warn', 'unknown') "
                                "GROUP BY Name, Version, Type, License, LicenseStatus "
                                "ORDER BY CASE LicenseStatus WHEN 'denied' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, "
                                "COUNT(DISTINCT ApplicationId) DESC, Name", params)
        vulnerable = _rows(conn, "SELECT TOP (20) Name, Version, Type, MAX(Critical) AS Critical, MAX(High) AS High, "
                                 "MAX(Medium) AS Medium, MAX(Low) AS Low, MAX(Vulns) AS Vulns, MAX(Scope) AS Scope, "
                                 "COUNT(DISTINCT ApplicationId) AS Apps, MIN(ApplicationName) AS FirstApp, "
                                 f"MIN(ApplicationId) AS FirstAppId FROM cz.vSbomPackageLatest{where}{and_}Critical + High > 0 "
                                 "GROUP BY Name, Version, Type ORDER BY MAX(Critical) DESC, MAX(High) DESC, "
                                 "COUNT(DISTINCT ApplicationId) DESC, Name", params)
    except Exception as ex:
        _missing(ex)
        return {"available": False, "apps_all": []}
    return {"available": True, "apps_all": apps_all, "components": {r["Kind"]: r["N"] for r in comps},
            "packages": pk, "status": {r["LicenseStatus"]: r["N"] for r in status}, "licenses": licenses,
            "per_app": per_app, "attention": attention, "vulnerable": vulnerable}


# ---------------------------------------------------------------------------
# small pieces

def status_badge(st: str, applies: bool = True) -> str:
    st = st if st in STATUS_TEXT else "unknown"
    cls = f"ls ls-{st}" if applies else "ls ls-muted"
    return f"<span class='{cls}' title='{e(STATUS_HELP[st])}'>{e(STATUS_TEXT[st])}</span>"


def _vuln_href(vid: str) -> str | None:
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", vid):
        return f"https://nvd.nist.gov/vuln/detail/{vid}"
    if re.fullmatch(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", vid):
        return f"https://github.com/advisories/{vid}"
    return None


def _cves(p: dict, details: bool = True) -> str:
    counts = [(label, cls, int(p.get(label) or 0)) for label, cls in SEV]
    if not any(n for _, _, n in counts):
        return "<span class='muted'>none known</span>"
    head = " · ".join(f"<span class='cv cv-{cls}'>{n} {label.lower()}</span>" for label, cls, n in counts if n)
    if not details:
        return head
    try:
        vulns = json.loads(p.get("Vulns") or "[]")
    except ValueError:
        vulns = []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulns = sorted(vulns, key=lambda v: (order.get(v.get("severity"), 9), str(v.get("id"))))
    items = []
    for v in vulns[:12]:
        vid = str(v.get("id") or "")
        href = _vuln_href(vid)
        link = f"<a href='{e(href)}' rel='noopener noreferrer'>{e(vid)}</a>" if href else e(vid)
        items.append(f"<li>{link} <span class='muted'>{e(str(v.get('severity') or '').lower())}</span>"
                     + (f" · fixed in {e(str(v['fixed']))}" if v.get("fixed") else " · no fix yet") + "</li>")
    more = f"<li class='muted'>and {len(vulns) - 12} more</li>" if len(vulns) > 12 else ""
    return f"<details class='cves'><summary>{head}</summary><ul class='small'>{''.join(items)}{more}</ul></details>"


def _license(p: dict) -> str:
    lic = p.get("License") or ""
    if p.get("Scope") == "self" and not lic:
        return "<span class='muted'>the application's own code</span>"
    if lic.startswith("LicenseRef-url:"):
        u = lic[len("LicenseRef-url:"):]
        text = (f"see <a href='{e(u)}' rel='noopener noreferrer'>licence page</a>"
                if re.match(r"https?://[^\s'\"<>]+$", u) else e(u))
    elif lic == "LicenseRef-see-package-file":
        text = "licence text inside the package"
    else:
        text = e(lic.replace("LicenseRef-", "")) if lic else "<span class='muted'>not found</span>"
    src = {"nuget": " <span class='muted small'>(from the NuGet feed)</span>"}.get(p.get("LicenseSource") or "", "")
    return text + src


def license_label(lic: str | None) -> str:
    """Plain words for a licence group in charts."""
    if not lic:
        return "No licence found"
    if lic.startswith("LicenseRef-url:"):
        return "Only a link to a licence page"
    if lic == "LicenseRef-see-package-file":
        return "Licence text inside the package"
    return lic.replace("LicenseRef-", "")


def _chip(label: str, href: str, on: bool, count: int | None = None) -> str:
    n = f" <span class='muted'>{count}</span>" if count is not None else ""
    return f"<a class='chip{' on' if on else ''}' href='{e(href)}'>{e(label)}{n}</a>"


def _href(path: str, **q) -> str:
    q = {k: v for k, v in q.items() if v is not None}
    return path + ("?" + urlencode(q) if q else "")


def _tile(label: str, value, sub: str = "") -> str:
    return (f"<div class='tile'><div class='label'>{e(label)}</div><div class='value'>{value}</div>"
            + (f"<div class='sub'>{sub}</div>" if sub else "") + "</div>")


# ---------------------------------------------------------------------------
# component page

def app_cell(app_id: int, comp_id: int, s: dict | None) -> str:
    """The "Packages" cell of a component on the application page."""
    if not s:
        return "<span class='muted'>-</span>"
    n = int(s.get("Packages") or 0)
    link = f"<a href='/app/{int(app_id)}/component/{int(comp_id)}'>{n} package{'s' if n != 1 else ''}</a>"
    notes = []
    if s.get("Denied"):
        notes.append(f"<span class='ls ls-denied'>{int(s['Denied'])} denied</span>")
    if s.get("Warn"):
        notes.append(f"<span class='ls ls-warn'>{int(s['Warn'])} to review</span>")
    if s.get("Critical") or s.get("High"):
        notes.append(f"<span class='cv cv-critical'>{int(s.get('Critical') or 0)} critical</span> · "
                     f"<span class='cv cv-high'>{int(s.get('High') or 0)} high</span>")
    kind = "" if s.get("Kind") == "image" else " <span class='muted small'>(declared)</span>"
    return link + kind + (f"<div class='small'>{' '.join(notes)}</div>" if notes else "")


def render_component(c: dict, show: str = "all", nav: str = "") -> str:
    app_id, comp_id = int(c["ApplicationId"]), int(c["ComponentId"])
    crumbs = (f"<a href='/'>All</a> › <a href='/?bu={e(str(c['BusinessUnitId'] if c['BusinessUnitId'] is not None else 'none'))}'>"
              f"{e(c['BusinessUnitName'] or UNASSIGNED)}</a> › {e(c['ProductName'] or UNASSIGNED)} › "
              f"<a href='/app/{app_id}'>{e(c['ApplicationName'])}</a>")
    head = f"""{_nav(nav)}<p class='crumbs'>{crumbs}</p>
<header><h1>{e(c['ComponentName'])}</h1><p class='muted'>Software bill of materials: the packages this component is
made of, their licences and known vulnerabilities · <span class='small'>{e(c['ProjectPath'])}</span></p></header>"""
    sb = c.get("sbom")
    if not sb:
        return page(f"{c['ComponentName']} packages", head + "<p>No software bill of materials for this component in "
                    "the latest assessment. It is made when the component is assessed with <code>--sql</code> (declared "
                    "packages) or built by the security gate (the full image).</p>")
    pkgs = c.get("packages") or []
    applies = [p for p in pkgs if p["PolicyApplies"]]
    st = {s: sum(1 for p in applies if p["LicenseStatus"] == s) for s in STATUS_TEXT}
    sev = {label: sum(int(p.get(label) or 0) for p in pkgs) for label, _ in SEV}
    if sb["Kind"] == "image":
        where = (f"From the built image <code>{e(sb['ImageRef'] or '')}</code>"
                 + (f" <span class='muted small'>@ {e(str(sb['ImageDigest'])[:19])}…</span>" if sb.get("ImageDigest") else "")
                 + f", made with {e(sb['Tool'] or 'syft')} on {_date(sb['CreatedAt'])}"
                 + (f"; base image {e(sb['OperatingSystem'])}" if sb.get("OperatingSystem") else "") + ".")
        att = sb.get("Attestation") or ""
        if att:
            where += (" Signed attestation in the registry." if att == "attested" else
                      " Attached to the image in the registry." if att == "attached" else f" Not in the registry: {e(att)}.")
        cve_note = "Vulnerabilities come from the security gate's image scan (Trivy, Grype)."
    else:
        where = (f"From the project files on {_date(sb['CreatedAt'])}: the packages the component declares, or every "
                 f"runtime package when the project has a lock file. The image was not built, so no vulnerability "
                 f"scan ran.")
        cve_note = ""
    tiles = (_tile("Packages", f"{len(pkgs):,}")
             + _tile("Licences denied", f"{st['denied']:,}", "the gate fails on these")
             + _tile("Licences to review", f"{st['warn']:,}", "for example copyleft")
             + _tile("Licence unknown", f"{st['unknown']:,}")
             + (_tile("Critical vulnerabilities", f"{sev['Critical']:,}", f"{sev['High']:,} high") if sb["Kind"] == "image" else ""))
    attention = [p for p in pkgs if (p["PolicyApplies"] and p["LicenseStatus"] != "allowed")
                 or int(p.get("Critical") or 0) + int(p.get("High") or 0)]
    shown = attention if show == "attention" else pkgs
    base = f"/app/{app_id}/component/{comp_id}"
    chips = (f"<nav class='chips'>{_chip('All packages', base, show != 'attention', len(pkgs))}"
             f"{_chip('Needs attention', base + '?show=attention', show == 'attention', len(attention))}</nav>")
    rows = []
    for p in shown:
        scope = {"os": " <span class='muted small'>base image</span>", "self": " <span class='muted small'>this application</span>"
                 }.get(p["Scope"], "")
        if p["FoundBy"] == "scanner":
            scope += " <span class='muted small'>found by the vulnerability scan</span>"
        note = ""
        if p.get("Accepted"):
            note = f"<div class='muted small'>accepted: {e(p['Accepted'])}</div>"
        elif not p["PolicyApplies"] and p["Scope"] == "os" and p["LicenseStatus"] != "allowed":
            note = "<div class='muted small'>OS package of the base image: reported, not counted</div>"
        rows.append(f"<tr><td><b>{e(p['Name'])}</b>{scope}</td><td>{e(p['Version'] or '-')}</td>"
                    f"<td>{e(TYPE_TEXT.get(p['Type'] or '', p['Type'] or '-'))}</td>"
                    f"<td>{_license(p)}{note}</td><td>{status_badge(p['LicenseStatus'], p['PolicyApplies'])}</td>"
                    f"<td>{_cves(p) if sb['Kind'] == 'image' else '<span class=muted>not scanned</span>'}</td></tr>")
    table = (f"<table><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>Licence</th><th>Policy</th>"
             f"<th>Vulnerabilities</th></tr></thead><tbody>{''.join(rows)}</tbody></table>" if rows
             else "<p class='muted'>Nothing needs attention.</p>")
    body = f"""{head}
<p>{where} <a href='{base}/sbom.cdx.json'>Download CycloneDX JSON</a></p>
<div class='tiles'>{tiles}</div>
{chips}{table}
<footer><p class='muted small'>Licence policy: <b>Denied</b> fails the security gate, <b>Review</b> needs a decision
(for example a copyleft licence), <b>Unknown</b> means no standard (SPDX) licence was found. Grey statuses are shown
but not counted: OS packages of the base image, the application itself and accepted exceptions. {e(cve_note)}</p></footer>"""
    return page(f"{c['ComponentName']} packages", body, script=False)


# ---------------------------------------------------------------------------
# portfolio page

def status_bar(counts: dict, label: str) -> str:
    """Thin segmented bar of licence status (status colours; the legend beside it carries names and numbers)."""
    total = sum(counts.get(s, 0) for s in STATUS_ORDER)
    if not total:
        return ""
    parts = [s for s in ("allowed", "unknown", "warn", "denied") if counts.get(s)]
    width, gap, height = 1000.0, 3.0, 14
    usable = width - gap * (len(parts) - 1)
    x, rects = 0.0, []
    for s in parts:
        w = max(usable * counts[s] / total, 4.0)
        rects.append(f"<rect class='st-{s}' x='{x:.1f}' y='0' width='{w:.1f}' height='{height}' rx='3'>"
                     f"<title>{STATUS_TEXT[s]}: {counts[s]:,} of {total:,} packages</title></rect>")
        x += w + gap
    return (f"<svg class='bar' viewBox='0 0 {width:.0f} {height}' preserveAspectRatio='none' height='{height}' "
            f"role='img' aria-label='{e(label)}'>{''.join(rects)}</svg>")


def status_legend(counts: dict) -> str:
    total = sum(counts.get(s, 0) for s in STATUS_ORDER) or 1
    return "<ul class='legend'>" + "".join(
        f"<li><span class='key st-{s}'></span><b>{e(STATUS_TEXT[s])}</b> {counts.get(s, 0):,} "
        f"<span class='muted'>({round(100 * counts.get(s, 0) / total)}%)</span></li>"
        for s in ("allowed", "warn", "denied", "unknown")) + "</ul>"


def license_bars(rows: list[dict]) -> str:
    """Ranked horizontal bars: packages per licence, largest first, one hue; the status is written in the label."""
    if not rows:
        return ""
    W, LBL, ROW, BAR, PAD = 760, 300, 30, 16, 6
    top = max(int(r["N"]) for r in rows) or 1
    span = W - LBL - 70
    out = [f"<svg class='chart hbars' viewBox='0 0 {W} {len(rows) * ROW + PAD}' role='img' "
           f"aria-label='Packages per licence, most used first'>"]
    out.append(f"<line class='axis' x1='{LBL}' y1='0' x2='{LBL}' y2='{len(rows) * ROW}'/>")
    for i, r in enumerate(rows):
        y = i * ROW
        n = int(r["N"])
        w = max(span * n / top, 3.0)
        lic = license_label(r["License"])
        lic_short = lic
        lic_short = lic_short if len(lic_short) <= 34 else lic_short[:33] + "…"
        st = r["LicenseStatus"] if r["License"] else "unknown"
        by = y + (ROW - BAR) / 2
        # bar with a rounded data end (right), square at the baseline
        rr = min(4.0, w / 2)
        path = (f"M{LBL} {by:.1f}h{w - rr:.1f}a{rr} {rr} 0 0 1 {rr} {rr}v{BAR - 2 * rr:.1f}"
                f"a{rr} {rr} 0 0 1 -{rr} {rr}h-{w - rr:.1f}z")
        out.append(f"<g><rect class='hit' x='0' y='{y}' width='{W}' height='{ROW}'/>"
                   f"<title>{e(lic)}: {n:,} package{'s' if n != 1 else ''} ({e(STATUS_TEXT[st])})</title>"
                   f"<text class='tick' x='{LBL - 10}' y='{y + ROW / 2 + 4:.1f}' text-anchor='end'>{e(lic_short)}"
                   f"{'' if st == 'allowed' else ' · ' + e(STATUS_TEXT[st].lower())}</text>"
                   f"<path class='hb' d='{path}'/>"
                   f"<text class='val' x='{LBL + w + 8:.1f}' y='{y + ROW / 2 + 4:.1f}'>{n:,}</text></g>")
    out.append("</svg>")
    return "".join(out)


def render_portfolio(d: dict, bu: str | None = None, product: str | None = None, nav: str = "") -> str:
    head = f"""{_nav(nav)}
<p class='crumbs'><a href='/'>Readiness</a> › Dependencies and licences</p>
<header><h1>Dependencies and licences</h1>
<p class='muted'>The packages our applications are made of: licences against the licence policy, and known
vulnerabilities in the images the security gate built</p></header>"""
    if not d.get("available"):
        return page("Dependencies and licences", head + "<p>The results database has no SBOM tables yet: run "
                    "<code>containerizer db init</code>.</p>")
    apps_all = d["apps_all"]
    bus: dict = {}
    for a in apps_all:
        bus.setdefault((a["BusinessUnitName"] or "", a["BusinessUnitId"]), []).append(a)
    bu_chips = [_chip("All business units", "/sbom", bu is None)]
    for (name, bid), lst in sorted(bus.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
        k = str(bid if bid is not None else "none")
        bu_chips.append(_chip(name or UNASSIGNED, _href("/sbom", bu=k), bu == k, len(lst)))
    prod_chips = []
    if bu is not None:
        prods: dict = {}
        for a in apps_all:
            if str(a["BusinessUnitId"] if a["BusinessUnitId"] is not None else "none") == bu:
                prods.setdefault((a["ProductName"] or "", a["ProductId"]), []).append(a)
        prod_chips = [_chip("All products", _href("/sbom", bu=bu), product is None)]
        for (name, pid), lst in sorted(prods.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
            k = str(pid if pid is not None else "none")
            prod_chips.append(_chip(name or UNASSIGNED, _href("/sbom", bu=bu, product=k), product == k, len(lst)))
    filters = (f"<nav class='chips'>{''.join(bu_chips)}</nav>"
               + (f"<nav class='chips'>{''.join(prod_chips)}</nav>" if prod_chips else ""))
    if not apps_all:
        return page("Dependencies and licences", head + "<p>No software bills of materials yet. They are made by "
                    "<code>containerizer assess --sql …</code> (declared packages) and by the security gate in "
                    "<code>containerizer org</code> (built images).</p>")

    pk, st, comps = d["packages"], d["status"], d["components"]
    n_comp = sum(comps.values())
    tiles = (_tile("Components with an SBOM", f"{n_comp:,}", f"{comps.get('image', 0):,} from built images")
             + _tile("Packages", f"{int(pk['Packages'] or 0):,}", "distinct package versions")
             + _tile("Licences denied", f"{st.get('denied', 0):,}", "packages; the gate fails on these")
             + _tile("Licences to review", f"{st.get('warn', 0):,}", "packages, for example copyleft")
             + _tile("Critical vulnerabilities", f"{int(pk['Critical'] or 0):,}",
                     f"{int(pk['High'] or 0):,} high; {int(pk['Vulnerable'] or 0):,} packages have a known vulnerability"))

    lic_rows = [[license_label(r["License"]), STATUS_TEXT.get(r["LicenseStatus"] if r["License"] else "unknown"),
                 int(r["N"])] for r in d["licenses"]]
    lic_table = ("<table class='narrow'><thead><tr><th>Licence</th><th>Policy</th><th class='num'>Packages</th></tr></thead><tbody>"
                 + "".join(f"<tr><td>{e(a)}</td><td>{e(b)}</td><td class='num'>{c:,}</td></tr>" for a, b, c in lic_rows)
                 + "</tbody></table>")

    per_app = sorted(d["per_app"], key=lambda r: (-int(r["Denied"] or 0), -int(r["Critical"] or 0), -int(r["High"] or 0),
                                                  -int(r["Warn"] or 0), r["ApplicationName"].lower()))
    app_rows = "".join(
        f"<tr><td><a href='/app/{int(r['ApplicationId'])}'>{e(r['ApplicationName'])}</a>"
        f"<div class='muted small'>{e(r['BusinessUnitName'] or UNASSIGNED)} › {e(r['ProductName'] or UNASSIGNED)}</div></td>"
        f"<td class='num'>{int(r['Components'])}</td><td class='num'>{int(r['Packages']):,}</td>"
        f"<td class='num'>{_count(r['Denied'], 'denied')}</td><td class='num'>{_count(r['Warn'], 'warn')}</td>"
        f"<td class='num'>{int(r['Unknown'] or 0):,}</td>"
        f"<td class='num'>{_count(r['Critical'], 'critical')}</td><td class='num'>{_count(r['High'], 'high')}</td></tr>"
        for r in per_app)

    att_rows = "".join(
        f"<tr><td><b>{e(r['Name'])}</b> {e(r['Version'] or '')}<div class='muted small'>"
        f"{e(TYPE_TEXT.get(r['Type'] or '', r['Type'] or ''))}</div></td><td>{_license(r)}</td>"
        f"<td>{status_badge(r['LicenseStatus'])}</td><td>{_used_in(r)}</td></tr>" for r in d["attention"])
    vul_rows = "".join(
        f"<tr><td><b>{e(r['Name'])}</b> {e(r['Version'] or '')}<div class='muted small'>"
        f"{e(TYPE_TEXT.get(r['Type'] or '', r['Type'] or ''))}{' · base image' if r.get('Scope') == 'os' else ''}</div></td>"
        f"<td>{_cves(r)}</td><td>{_fix(r)}</td><td>{_used_in(r)}</td></tr>" for r in d["vulnerable"])

    body = f"""{head}
{filters}
<div class='tiles'>{tiles}</div>
<section class='card'><h2>Licences against the policy</h2>
<p class='muted small'>Distinct package versions the licence policy applies to (OS packages of base images, the
applications themselves and accepted exceptions are left out).</p>
{status_bar(st, 'Packages by licence policy status')}{status_legend(st)}
<h3>Most used licences</h3>{license_bars(d['licenses'])}
<details><summary>Show as a table</summary>{lic_table}</details></section>
<section class='card'><h2>Applications</h2>
<table><thead><tr><th>Application</th><th class='num'>Components</th><th class='num'>Packages</th>
<th class='num'>Denied</th><th class='num'>Review</th><th class='num'>Unknown</th><th class='num'>Critical</th>
<th class='num'>High</th></tr></thead><tbody>{app_rows}</tbody></table></section>
<section class='card'><h2>Licences that need attention</h2>
{('<table><thead><tr><th>Package</th><th>Licence</th><th>Policy</th><th>Used in</th></tr></thead><tbody>' + att_rows + '</tbody></table>') if att_rows else "<p class='muted'>None: every package has an allowed licence.</p>"}
</section>
<section class='card'><h2>Packages with critical or high vulnerabilities</h2>
{('<table><thead><tr><th>Package</th><th>Vulnerabilities</th><th>Fix</th><th>Used in</th></tr></thead><tbody>' + vul_rows + '</tbody></table>') if vul_rows else "<p class='muted'>None found in the scanned images.</p>"}
</section>
<footer><p class='muted small'>From the latest assessment of each application: the SBOM of the built image where the
security gate built one (with its vulnerability scan), else the packages the project files declare. Licence policy and
how to change it: <code>rules/60-security.yaml</code> (<code>sbom.licenses</code>).</p></footer>"""
    return page("Dependencies and licences", body)


def _count(n, kind: str) -> str:
    n = int(n or 0)
    if not n:
        return "<span class='muted'>0</span>"
    cls = {"denied": "ls ls-denied", "warn": "ls ls-warn", "critical": "cv cv-critical", "high": "cv cv-high"}[kind]
    return f"<span class='{cls}'>{n:,}</span>"


def _used_in(r: dict) -> str:
    n = int(r.get("Apps") or 0)
    first = f"<a href='/app/{int(r['FirstAppId'])}'>{e(r['FirstApp'])}</a>" if r.get("FirstAppId") else ""
    return first + (f" <span class='muted'>and {n - 1} more</span>" if n > 1 else "")


def _fix(r: dict) -> str:
    try:
        vulns = json.loads(r.get("Vulns") or "[]")
    except ValueError:
        vulns = []
    bad = [v for v in vulns if v.get("severity") in ("CRITICAL", "HIGH")]
    fixed = sorted({str(v["fixed"]) for v in bad if v.get("fixed")})
    if not bad:
        return "<span class='muted'>-</span>"
    if len(fixed) and all(v.get("fixed") for v in bad):
        return "upgrade to " + e(", ".join(fixed[:2]))
    return ("partly: " + e(", ".join(fixed[:2]))) if fixed else "<span class='muted'>no fix yet</span>"


CSS = """
.ls{display:inline-block;font-size:12px;font-weight:600;border-radius:4px;padding:1px 7px;border:1px solid currentColor;white-space:nowrap}
.ls-allowed{color:#0a7d0a}.ls-warn{color:#8a6100}.ls-denied{color:#b42727}.ls-unknown,.ls-muted{color:var(--muted)}
.ls-muted{border-style:dashed}
.cv{font-weight:600;white-space:nowrap}.cv-critical{color:#b42727}.cv-high{color:#b85a2e}.cv-medium{color:#8a6100}.cv-low{color:var(--muted)}
@media (prefers-color-scheme:dark){.ls-allowed{color:#4fd14f}.ls-warn{color:#fac35a}.ls-denied,.cv-critical{color:#f07a7a}
.cv-high{color:#f2a07f}.cv-medium{color:#fac35a}}
details.cves{border:0;padding:0;margin:0;background:none}details.cves ul{margin:4px 0;padding-left:18px}
.st-allowed{fill:#0ca30c;background:#0ca30c}.st-warn{fill:#fab219;background:#fab219}.st-denied{fill:#d03b3b;background:#d03b3b}
.st-unknown{fill:#c3c2b7;background:#c3c2b7}
@media (prefers-color-scheme:dark){.st-unknown{fill:#5f5e58;background:#5f5e58}}
.hbars .hb{fill:var(--o1)}.hbars{max-width:760px}
@media (forced-colors:active){.ls,.st-allowed,.st-warn,.st-denied,.st-unknown{forced-color-adjust:none}}
"""
