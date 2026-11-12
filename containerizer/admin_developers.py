"""Admin -> Developers (/admin/developers), administrators only.

The people who committed to the organizations' repositories in the last six months (developers.py collects them at
every organization scan run), the repositories each of them committed to, and their business unit, which
administrators set. From those the page suggests (weighed by commits):

- Developers: a developer's business unit, from the products of the repositories they commit to;
- Suggestions: the business unit of the products that have none (the ones made from projects, say), and of the
  repositories nobody mapped, from the business units of their developers;
- Projects: the product of each Azure DevOps project (GitLab subgroup). At first one product per project, made by
  the organization scan (cz.AutoMapProjects); the project's applications nobody mapped get it.

Every change goes through the admin login with the administrator in SESSION_CONTEXT, so the change history records it.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode

from .admin import Response, _d, page, redirect
from .developers import HISTORY_DAYS, SUGGEST_SHARE, Suggestion, suggest

e = html.escape
TAB = "developers"
ROWS = 500                    # developers shown at once (search for the others)
NOTE_MAX = 400
VIEWS = (("", "Developers"), ("suggestions", "Suggestions"), ("projects", "Projects → products"))


# -- the data ---------------------------------------------------------------------------------------------------

@dataclass
class Model:
    bus: dict = field(default_factory=dict)            # id -> name
    devs: dict = field(default_factory=dict)           # id -> row
    repos: dict = field(default_factory=dict)          # id -> row (with developers)
    links: list = field(default_factory=list)          # DeveloperId, RepositoryId, Commits, LastCommitAt
    apps: dict = field(default_factory=dict)           # repository id -> [application rows]
    products: dict = field(default_factory=dict)       # id -> row

    def repo_bus(self, rid: int) -> set:
        return {a["BusinessUnitId"] for a in self.apps.get(rid, []) if a["BusinessUnitId"] is not None}

    def links_of_dev(self) -> dict:
        out: dict = {}
        for x in self.links:
            out.setdefault(x["DeveloperId"], []).append(x)
        return out

    def links_of_repo(self) -> dict:
        out: dict = {}
        for x in self.links:
            out.setdefault(x["RepositoryId"], []).append(x)
        return out

    def dev_suggestions(self) -> dict:
        """developer id -> Suggestion, from the business units of the repositories they commit to."""
        out = {}
        for did, xs in self.links_of_dev().items():
            s = suggest((bu, x["Commits"]) for x in xs for bu in self.repo_bus(x["RepositoryId"]))
            if s:
                out[did] = s
        return out

    def _votes(self, xs) -> list:
        votes = []
        for x in xs:
            d = self.devs.get(x["DeveloperId"])
            if d and not d["Ignored"] and d["BusinessUnitId"] is not None:
                votes.append((d["BusinessUnitId"], x["Commits"]))
        return votes

    def repo_suggestions(self) -> dict:
        """repository id -> Suggestion, from the business units of its developers."""
        out = {}
        for rid, xs in self.links_of_repo().items():
            s = suggest(self._votes(xs))
            if s:
                out[rid] = s
        return out

    def product_suggestions(self) -> dict:
        """product id (without a business unit) -> (Suggestion, its repository ids), from the developers of its
        applications' repositories."""
        by_repo = self.links_of_repo()
        out = {}
        for pid in self.products:
            if self.products[pid]["BusinessUnitId"] is not None:
                continue
            rids = sorted({rid for rid, apps in self.apps.items() for a in apps if a["ProductId"] == pid})
            s = suggest(v for rid in rids for v in self._votes(by_repo.get(rid, [])))
            out[pid] = (s, rids)
        return out


def load(conn) -> Model:
    m = Model()
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT BusinessUnitId, Name FROM cz.BusinessUnit ORDER BY Name")
    m.bus = {r["BusinessUnitId"]: r["Name"] for r in cur.fetchall()}
    cur.execute("SELECT DeveloperId, Email, Name, BusinessUnitId, Ignored, Note, FirstSeenAt, LastCommitAt FROM cz.Developer")
    m.devs = {r["DeveloperId"]: r for r in cur.fetchall()}
    cur.execute("SELECT dr.DeveloperId, dr.RepositoryId, dr.Commits, dr.LastCommitAt FROM cz.DeveloperRepository dr "
                "JOIN cz.OrgRepository r ON r.RepositoryId = dr.RepositoryId WHERE r.RemovedAt IS NULL")
    m.links = cur.fetchall()
    cur.execute("SELECT r.RepositoryId, r.ProjectName, r.Name, r.WebUrl, r.ScanId, s.Name AS ScanName, r.LastStatus, "
                "r.SkipStatus FROM cz.OrgRepository r JOIN cz.OrgScan s ON s.ScanId = r.ScanId WHERE r.RemovedAt IS NULL "
                "AND EXISTS (SELECT 1 FROM cz.DeveloperRepository dr WHERE dr.RepositoryId = r.RepositoryId)")
    m.repos = {r["RepositoryId"]: r for r in cur.fetchall()}
    cur.execute("SELECT DISTINCT r.RepositoryId, a.ApplicationId, COALESCE(a.DisplayName, a.Name) AS AppName, a.ProductId, "
                "p.Name AS ProductName, p.BusinessUnitId FROM cz.OrgRepository r "
                "JOIN cz.Application a ON a.RepositoryUrl = r.RepositoryUrl AND a.Retired = 0 "
                "LEFT JOIN cz.Product p ON p.ProductId = a.ProductId WHERE r.RemovedAt IS NULL")
    for r in cur.fetchall():
        m.apps.setdefault(r["RepositoryId"], []).append(r)
    cur.execute("SELECT ProductId, Name, BusinessUnitId FROM cz.Product ORDER BY Name")
    m.products = {r["ProductId"]: r for r in cur.fetchall()}
    return m


# -- routes -----------------------------------------------------------------------------------------------------

def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict) -> Response:
    if not a.admin:
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Only administrators map developers.</p>"))
    sub = parts[1] if len(parts) > 1 else ""
    if method == "POST" and len(parts) == 2:
        action = {"save": save, "apply": apply_developers, "product-bu": product_bu, "project": project,
                  "automap": automap}.get(sub)
        if action:
            return action(conn, form)
    if method != "GET" or len(parts) > 2 or sub not in {k for k, _ in VIEWS}:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    m = load(conn)
    nav = "<nav class='chips sub' aria-label='Developers'>" + "".join(
        f"<a class='chip{' on' if k == sub else ''}' href='/admin/developers{'/' + k if k else ''}'>{t}</a>"
        for k, t in VIEWS) + "</nav>"
    if sub == "suggestions":
        body = suggestions_view(adm, s, m)
    elif sub == "projects":
        body = projects_view(adm, s, conn)
    else:
        body = developers_view(adm, s, m, q.get("show", ["all"])[0], q.get("q", [""])[0][:100])
    return Response(200, adm._shell(s, a, "Developers", TAB, nav + body, q.get("msg", [""])[0][:300]))


def _back(msg: str, sub: str = "", extra: dict | None = None) -> Response:
    return redirect(f"/admin/developers{'/' + sub if sub else ''}?" + urlencode({**(extra or {}), "msg": msg}))


def _ids(form: dict, key: str) -> list[int]:
    return [int(v) for v in form.get(key, []) if re.fullmatch(r"\d{1,9}", v)][:5000]


# -- Developers -------------------------------------------------------------------------------------------------

def _bu_select(m: Model, name: str, selected, blank: str = "(none)") -> str:
    opts = [f"<option value=''>{e(blank)}</option>"] + [
        f"<option value='{int(i)}'{' selected' if i == selected else ''}>{e(n)}</option>" for i, n in m.bus.items()]
    return f"<select name='{e(name)}' aria-label='Business unit'>{''.join(opts)}</select>"


def _sugg(m: Model, sg: Suggestion | None, what: str) -> str:
    if not sg:
        return "<span class='muted'>-</span>"
    cls = "sugg sure" if sg.share >= SUGGEST_SHARE else "sugg"
    return (f"<span class='{cls}' title='{e(f'{sg.weight} commits by {sg.voters} {what}')}'>{e(m.bus.get(sg.bu, '?'))}"
            f" <span class='muted'>{round(sg.share * 100)}%</span></span>")


def _dev_sugg(m: Model, d: dict, sg: Suggestion | None) -> str:
    """A developer's suggestion where it adds something: none set yet, or a different one."""
    if sg and d["BusinessUnitId"] == sg.bu:
        return "<span class='muted small'>matches</span>"
    if sg and d["BusinessUnitId"] is not None:
        return "<span class='small'>differs: </span>" + _sugg(m, sg, "repositories with a business unit")
    return _sugg(m, sg, "repositories with a business unit")


def _repo_name(r: dict) -> str:
    return r["Name"] if r["ProjectName"] == "_" else f"{r['ProjectName']}/{r['Name']}"


def _repo_link(r: dict) -> str:
    name = e(_repo_name(r))
    if r.get("WebUrl") and str(r["WebUrl"]).startswith("https://"):
        return f"<a href='{e(r['WebUrl'])}' rel='noopener noreferrer' target='_blank'>{name}</a>"
    return name


def developers_view(adm, s, m: Model, show: str, text: str) -> str:
    show = show if show in ("all", "unmapped", "ignored") else "all"
    by_dev = m.links_of_dev()
    sugg = m.dev_suggestions()
    devs = sorted(m.devs.values(), key=lambda d: (d["LastCommitAt"] is None, -(d["LastCommitAt"].timestamp())
                                                   if d["LastCommitAt"] else 0, d["Email"]))
    counts = {"all": sum(1 for d in devs if not d["Ignored"]),
              "unmapped": sum(1 for d in devs if not d["Ignored"] and d["BusinessUnitId"] is None),
              "ignored": sum(1 for d in devs if d["Ignored"])}
    if show == "unmapped":
        devs = [d for d in devs if not d["Ignored"] and d["BusinessUnitId"] is None]
    elif show == "ignored":
        devs = [d for d in devs if d["Ignored"]]
    else:
        devs = [d for d in devs if not d["Ignored"]]
    if text:
        t = text.lower()
        devs = [d for d in devs if t in d["Email"] or t in (d["Name"] or "").lower()
                or (d["BusinessUnitId"] is not None and t in m.bus.get(d["BusinessUnitId"], "").lower())
                or any(t in _repo_name(m.repos[x["RepositoryId"]]).lower() for x in by_dev.get(d["DeveloperId"], [])
                       if x["RepositoryId"] in m.repos)]
    shown = devs[:ROWS]
    sure = [d for d in m.devs.values() if not d["Ignored"] and d["BusinessUnitId"] is None
            and (x := sugg.get(d["DeveloperId"])) and x.sure]
    rows = []
    for d in shown:
        did = int(d["DeveloperId"])
        xs = sorted(by_dev.get(did, []), key=lambda x: (-x["Commits"], -(x["LastCommitAt"].timestamp())))
        xs = [x for x in xs if x["RepositoryId"] in m.repos]
        chips = [f"<span class='role' title='{e('last commit ' + _d(x['LastCommitAt']))}'>{_repo_link(m.repos[x['RepositoryId']])}"
                 f" <span class='muted'>{int(x['Commits'])}</span></span>" for x in xs]
        repos = "".join(chips[:4]) + (f"<details class='more'><summary>{len(chips) - 4} more</summary>{''.join(chips[4:])}</details>"
                                      if len(chips) > 4 else "")
        commits = sum(int(x["Commits"]) for x in xs)
        was = f"{d['BusinessUnitId'] if d['BusinessUnitId'] is not None else ''}|{1 if d['Ignored'] else 0}"
        rows.append(
            f"<tr><td><input type='hidden' name='d' value='{did}'><input type='hidden' name='was-{did}' value='{e(was)}'>"
            f"<b>{e(d['Name'] or d['Email'])}</b><div class='muted small'>{e(d['Email'])}</div></td>"
            f"<td>{_bu_select(m, f'bu-{did}', d['BusinessUnitId'])}</td>"
            f"<td>{_dev_sugg(m, d, sugg.get(did))}</td>"
            f"<td class='repos'>{repos or '<span class=muted>-</span>'}</td><td class='num'>{commits}</td>"
            f"<td class='nowrap'>{e(d['LastCommitAt'].strftime('%Y-%m-%d')) if d['LastCommitAt'] else '-'}</td>"
            f"<td><input type='checkbox' name='ign-{did}' value='1'{' checked' if d['Ignored'] else ''} "
            f"aria-label='Ignore {e(d['Email'])}' title='A service account or bot: left out of the suggestions'></td></tr>")
    filters = " ".join(f"<a class='chip{' on' if k == show else ''}' href='/admin/developers?{urlencode({'show': k, 'q': text})}'>"
                       f"{t} <span class='muted'>{counts[k]}</span></a>"
                       for k, t in (("all", "All"), ("unmapped", "No business unit"), ("ignored", "Ignored")))
    search = (f"<form method='get' action='/admin/developers' class='formrow'><input type='hidden' name='show' value='{e(show)}'>"
              f"<input type='search' name='q' value='{e(text)}' class='wide' placeholder='Name, e-mail, repository or business unit' "
              f"aria-label='Search'><button class='secondary'>Search</button></form>")
    mapped = sum(1 for d in m.devs.values() if not d["Ignored"] and d["BusinessUnitId"] is not None)
    intro = (f"<p class='muted'>The people who committed to the organizations' repositories in the last {HISTORY_DAYS // 30} "
             f"months, read from the commit history at every organization scan run. {counts['all']} developers, {mapped} with "
             f"a business unit. Set their business unit here: the <a href='/admin/developers/suggestions'>suggestions</a> then "
             f"show which repositories and products nobody mapped belong to which business unit.</p>")
    apply = ""
    if sure:
        apply = (f"<form method='post' action='/admin/developers/apply' class='formrow'>{adm._csrf(s)}"
                 f"<button>Apply {len(sure)} suggestion{'s' if len(sure) != 1 else ''}</button>"
                 f"<span class='muted small'>to the developers without a business unit whose suggestion is at least "
                 f"{round(SUGGEST_SHARE * 100)}% sure (from the products of the repositories they commit to)</span></form>")
    if not m.devs:
        return intro + ("<p class='muted'>No developers yet. They appear after the next run of an "
                        "<a href='/admin/scans'>organization scan</a> (a discovery run is enough).</p>")
    more = (f"<p class='muted small'>The {ROWS} most recent of {len(devs)} are shown: search for the others.</p>"
            if len(devs) > ROWS else "")
    if not m.bus:
        save = "<p class='muted'>Create a <a href='/admin/business-units'>business unit</a> first.</p>"
    else:
        save = "<div class='formrow'><button>Save changes</button></div>"
    table = (f"<form method='post' action='/admin/developers/save'>{adm._csrf(s)}"
             f"<input type='hidden' name='back' value='{e(urlencode({'show': show, 'q': text}))}'>{save}"
             f"<table class='devs'><thead><tr><th>Developer</th><th>Business unit</th><th>Suggested</th>"
             f"<th>Repositories <span class='muted small'>(commits)</span></th><th>Commits</th><th>Last commit</th>"
             f"<th>Ignore</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=7 class=muted>Nobody here.</td></tr>'}"
             f"</tbody></table>{save if rows else ''}</form>")
    return intro + apply + f"<nav class='chips'>{filters}</nav>" + search + more + table


def save(conn, form: dict) -> Response:
    back = parse_qs(form.get("back", [""])[0][:300])
    extra = {k: back[k][0][:100] for k in ("show", "q") if back.get(k)}
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT BusinessUnitId FROM cz.BusinessUnit")
    bus = {r["BusinessUnitId"] for r in cur.fetchall()}
    changed = 0
    c = conn.cursor()
    try:
        for did in _ids(form, "d"):
            v = form.get(f"bu-{did}", [""])[0]
            bu = int(v) if re.fullmatch(r"\d{1,9}", v) and int(v) in bus else None
            ign = form.get(f"ign-{did}", [""])[0] == "1"
            now = f"{bu if bu is not None else ''}|{1 if ign else 0}"
            if form.get(f"was-{did}", [""])[0] == now:
                continue
            c.execute("UPDATE cz.Developer SET BusinessUnitId = %s, Ignored = %s WHERE DeveloperId = %s", (bu, ign, did))
            changed += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _back(f"Saved {changed} developer{'s' if changed != 1 else ''}." if changed else "Nothing changed.", extra=extra)


def apply_developers(conn, form: dict) -> Response:
    m = load(conn)
    sugg = m.dev_suggestions()
    n = 0
    c = conn.cursor()
    try:
        for did, d in m.devs.items():
            sg = sugg.get(did)
            if sg and sg.sure and not d["Ignored"] and d["BusinessUnitId"] is None:
                c.execute("UPDATE cz.Developer SET BusinessUnitId = %s WHERE DeveloperId = %s AND BusinessUnitId IS NULL",
                          (sg.bu, did))
                n += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _back(f"Business unit set for {n} developer{'s' if n != 1 else ''}.")


# -- Suggestions ------------------------------------------------------------------------------------------------

def _apps_text(m: Model, rid: int) -> str:
    apps = m.apps.get(rid, [])
    if not apps:
        r = m.repos[rid]
        why = r.get("SkipStatus") or r.get("LastStatus")
        return f"<span class='muted'>not assessed{' (' + e(why) + ')' if why else ''}</span>"
    out = []
    for x in apps[:4]:
        where = (e(x["ProductName"]) if x["ProductName"] else "<span class='muted'>no product</span>")
        out.append(f"<a href='/admin/applications/{int(x['ApplicationId'])}'>{e(x['AppName'])}</a> → {where}")
    return "<br>".join(out) + (f"<br><span class='muted'>and {len(apps) - 4} more</span>" if len(apps) > 4 else "")


def _people(m: Model, xs: list, n: int = 3) -> str:
    xs = sorted((x for x in xs if not m.devs.get(x["DeveloperId"], {}).get("Ignored")), key=lambda x: -x["Commits"])
    names = []
    for x in xs[:n]:
        d = m.devs.get(x["DeveloperId"])
        if d and not d["Ignored"]:
            bu = m.bus.get(d["BusinessUnitId"]) if d["BusinessUnitId"] is not None else None
            names.append(f"{e(d['Name'] or d['Email'])}{' <span class=muted>(' + e(bu) + ')</span>' if bu else ''}")
    return ", ".join(names) + (f" <span class='muted'>+{len(xs) - n}</span>" if len(xs) > n else "")


def suggestions_view(adm, s, m: Model) -> str:
    psugg = m.product_suggestions()
    rsugg = m.repo_suggestions()
    by_repo = m.links_of_repo()
    sure_products = [pid for pid, (sg, _) in psugg.items() if sg and sg.sure]
    prows = []
    for pid, (sg, rids) in sorted(psugg.items(), key=lambda kv: (kv[1][0] is None, -(kv[1][0].weight if kv[1][0] else 0),
                                                                 m.products[kv[0]]["Name"].lower())):
        p = m.products[pid]
        repos = ", ".join(_repo_link(m.repos[r]) for r in rids[:3] if r in m.repos) + \
            (f" <span class='muted'>+{len(rids) - 3}</span>" if len(rids) > 3 else "")
        prows.append(
            f"<tr><td><a href='/admin/products/{int(pid)}'>{e(p['Name'])}</a></td><td>{repos or '<span class=muted>-</span>'}</td>"
            f"<td>{_sugg(m, sg, 'developers with a business unit')}</td>"
            f"<td><form method='post' action='/admin/developers/product-bu' class='inline-form'>{adm._csrf(s)}"
            f"<input type='hidden' name='ProductId' value='{int(pid)}'>{_bu_select(m, 'BusinessUnitId', sg.bu if sg else None, '(choose)')}"
            f"<button class='secondary'>Set</button></form></td></tr>")
    products = ("<h2>Products without a business unit</h2>"
                "<p class='muted'>Suggested from the business units of the developers who commit to the products' "
                "repositories, weighed by commits.</p>")
    if sure_products:
        products += (f"<form method='post' action='/admin/developers/product-bu' class='formrow'>{adm._csrf(s)}"
                     f"<input type='hidden' name='all' value='1'><button>Apply {len(sure_products)} suggestion"
                     f"{'s' if len(sure_products) != 1 else ''}</button><span class='muted small'>the ones at least "
                     f"{round(SUGGEST_SHARE * 100)}% sure</span></form>")
    products += (f"<table><thead><tr><th>Product</th><th>Repositories</th><th>Suggested</th><th>Business unit</th></tr></thead>"
                 f"<tbody>{''.join(prows) or '<tr><td colspan=4 class=muted>Every product has a business unit.</td></tr>'}"
                 f"</tbody></table>")
    # repositories none of whose applications has a product with a business unit
    rrows = []
    unmapped = [rid for rid in m.repos if not m.repo_bus(rid)]
    unmapped.sort(key=lambda rid: (rid not in rsugg, -(rsugg[rid].weight if rid in rsugg else 0), _repo_name(m.repos[rid]).lower()))
    for rid in unmapped[:ROWS]:
        r = m.repos[rid]
        rrows.append(f"<tr><td>{_repo_link(r)}<div class='muted small'>{e(r['ScanName'])}</div></td>"
                     f"<td>{_apps_text(m, rid)}</td><td>{_people(m, by_repo.get(rid, []))}</td>"
                     f"<td>{_sugg(m, rsugg.get(rid), 'developers with a business unit')}</td></tr>")
    repos = ("<h2>Repositories without a business unit</h2>"
             "<p class='muted'>Repositories with commits in the last six months whose applications have no product with a "
             "business unit, or that were not assessed. Map their applications on <a href='/admin/applications'>Applications</a> "
             "to a product of the suggested business unit.</p>"
             f"<table><thead><tr><th>Repository</th><th>Applications → product</th><th>Developers</th><th>Suggested</th>"
             f"</tr></thead><tbody>{''.join(rrows) or '<tr><td colspan=4 class=muted>Every repository is mapped.</td></tr>'}"
             f"</tbody></table>")
    if not any(d["BusinessUnitId"] is not None for d in m.devs.values()):
        repos = ("<p class='muted'>Set the business unit of some <a href='/admin/developers'>developers</a> first: "
                 "the suggestions come from them.</p>") + repos
    return products + repos


def product_bu(conn, form: dict) -> Response:
    c = conn.cursor()
    try:
        if form.get("all", [""])[0] == "1":
            m = load(conn)
            n = 0
            for pid, (sg, _) in m.product_suggestions().items():
                if sg and sg.sure:
                    c.execute("UPDATE cz.Product SET BusinessUnitId = %s WHERE ProductId = %s AND BusinessUnitId IS NULL",
                              (sg.bu, pid))
                    n += 1
            conn.commit()
            return _back(f"Business unit set for {n} product{'s' if n != 1 else ''}.", "suggestions")
        pid, bu = _ids(form, "ProductId"), _ids(form, "BusinessUnitId")
        if not pid or not bu:
            return _back("Choose a business unit.", "suggestions")
        c.execute("UPDATE cz.Product SET BusinessUnitId = %s WHERE ProductId = %s", (bu[0], pid[0]))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _back("Saved.", "suggestions")


# -- Projects -> products ---------------------------------------------------------------------------------------

def _projects(conn) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("""SELECT p.ProjectId, p.ScanId, s.Name AS ScanName, s.Provider, p.Name, p.ProductId, p.ProductMappedAt,
               p.AdminState, pr.Name AS ProductName, pr.BusinessUnitId,
               (SELECT COUNT(*) FROM cz.OrgRepository r WHERE r.ScanId = p.ScanId AND r.ProjectName = p.Name
                AND r.RemovedAt IS NULL) AS Repos,
               (SELECT COUNT(DISTINCT a.ApplicationId) FROM cz.OrgRepository r
                JOIN cz.Application a ON a.RepositoryUrl = r.RepositoryUrl AND a.Retired = 0
                WHERE r.ScanId = p.ScanId AND r.ProjectName = p.Name AND r.RemovedAt IS NULL) AS Apps,
               (SELECT COUNT(DISTINCT a.ApplicationId) FROM cz.OrgRepository r
                JOIN cz.Application a ON a.RepositoryUrl = r.RepositoryUrl AND a.Retired = 0
                WHERE r.ScanId = p.ScanId AND r.ProjectName = p.Name AND r.RemovedAt IS NULL AND a.ProductId IS NULL) AS Unmapped
        FROM cz.OrgProject p JOIN cz.OrgScan s ON s.ScanId = p.ScanId
        LEFT JOIN cz.Product pr ON pr.ProductId = p.ProductId
        WHERE p.RemovedAt IS NULL ORDER BY s.Name, p.Name""")
    return cur.fetchall()


def projects_view(adm, s, conn) -> str:
    rows = _projects(conn)
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT p.ProductId, p.Name, b.Name AS BusinessUnitName FROM cz.Product p "
                "LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId ORDER BY p.Name")
    products = cur.fetchall()
    trs = []
    for r in rows:
        if r["ProductMappedAt"] is None:
            cur_v = "auto"
        else:
            cur_v = str(int(r["ProductId"])) if r["ProductId"] is not None else "none"
        opts = [("auto", "Automatic: a product named after the project"), ("none", "No product")] + [
            (str(int(p["ProductId"])), p["Name"] + (f" · {p['BusinessUnitName']}" if p["BusinessUnitName"] else ""))
            for p in products]
        sel = "".join(f"<option value='{e(v)}'{' selected' if v == cur_v else ''}>{e(t)}</option>" for v, t in opts)
        state = ""
        if r["AdminState"] == "disabled":
            state = " <span class='muted small'>(disabled)</span>"
        elif cur_v == "auto":
            state = (" <span class='muted small'>(waiting for its first assessed application)</span>" if not r["Apps"]
                     else " <span class='muted small'>(at the next scan run, or Map now)</span>")
        unm = f" <span class='muted'>({int(r['Unmapped'])} not mapped)</span>" if r["Unmapped"] else ""
        trs.append(f"<tr><td>{e(r['Name'].replace('--', '/'))}{state}<div class='muted small'>{e(r['ScanName'])}</div></td>"
                   f"<td class='num'>{int(r['Repos'])}</td><td class='num'>{int(r['Apps'])}{unm}</td>"
                   f"<td><form method='post' action='/admin/developers/project' class='inline-form'>{adm._csrf(s)}"
                   f"<input type='hidden' name='ProjectId' value='{int(r['ProjectId'])}'>"
                   f"<select name='Product' aria-label='Product of {e(r['Name'])}'>{sel}</select>"
                   f"<button class='secondary'>Save</button></form></td></tr>")
    intro = ("<p class='muted'>As a starting point every Azure DevOps project (GitLab subgroup) is one product: after each "
             "run the organization scan makes a product named after each project that has an assessed application, and maps "
             "the project's applications nobody mapped to it. Change a project's product here: the applications mapped "
             "automatically follow it, the ones people mapped stay. GitHub organizations have no projects.</p>"
             f"<form method='post' action='/admin/developers/automap' class='formrow'>{adm._csrf(s)}"
             "<button class='secondary'>Map now</button><span class='muted small'>instead of waiting for the next run</span></form>")
    return intro + (f"<table><thead><tr><th>Project</th><th>Repositories</th><th>Applications</th><th>Product</th></tr></thead>"
                    f"<tbody>{''.join(trs) or '<tr><td colspan=4 class=muted>No projects: they appear after an organization scan run of an Azure DevOps organization or GitLab group.</td></tr>'}"
                    f"</tbody></table>")


def project(conn, form: dict) -> Response:
    pid = _ids(form, "ProjectId")
    v = form.get("Product", [""])[0]
    if not pid or not (v in ("auto", "none") or re.fullmatch(r"\d{1,9}", v)):
        return _back("Choose a product.", "projects")
    cur = conn.cursor(as_dict=True)
    try:
        cur.execute("SELECT ProjectId, ScanId, Name, ProductId FROM cz.OrgProject WITH (UPDLOCK, HOLDLOCK) WHERE ProjectId = %s",
                    (pid[0],))
        p = cur.fetchone()
        if not p:
            conn.rollback()
            return _back("That project is gone.", "projects")
        new = int(v) if v not in ("auto", "none") else None
        c = conn.cursor()
        c.execute("UPDATE cz.OrgProject SET ProductId = %s, ProductMappedAt = " +
                  ("NULL" if v == "auto" else "SYSUTCDATETIME()") + " WHERE ProjectId = %s", (new, p["ProjectId"]))
        # the project's applications that were mapped automatically follow; the ones people mapped stay
        repos = ("FROM cz.Application a JOIN cz.OrgRepository r ON r.RepositoryUrl = a.RepositoryUrl "
                 "WHERE r.ScanId = %s AND r.ProjectName = %s AND r.RemovedAt IS NULL")
        if new is not None:
            c.execute(f"UPDATE a SET ProductId = %s, ProductAutoAt = SYSUTCDATETIME() {repos} AND a.Retired = 0 AND "
                      "(a.ProductId IS NULL OR (a.ProductAutoAt IS NOT NULL AND a.ProductId = %s))",
                      (new, p["ScanId"], p["Name"], p["ProductId"]))
        elif p["ProductId"] is not None:
            c.execute(f"UPDATE a SET ProductId = NULL, ProductAutoAt = " + ("NULL" if v == "auto" else "a.ProductAutoAt") +
                      f" {repos} AND a.ProductAutoAt IS NOT NULL AND a.ProductId = %s", (p["ScanId"], p["Name"], p["ProductId"]))
        conn.commit()
    except Exception as ex:
        conn.rollback()
        from .admin import _code
        if _code(ex) == 547:
            return _back("That product is gone.", "projects")
        raise
    if v == "auto":
        return automap(conn, {})
    return _back("Saved.", "projects")


def automap(conn, form: dict) -> Response:
    try:
        conn.cursor().execute("EXEC cz.AutoMapProjects")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _back("Projects mapped to products.", "projects")
