"""Trends page of the web UI: how ratings and obstacles changed over the scans.

Every scan is kept (cz.ApplicationAssessment, read through cz.vAssessmentHistory), so the state of the
portfolio at any date is, per application, its latest scan up to that date. The page shows that state
at the end of each period (day, week, month or quarter, picked from the time range): the rating mix,
the number of obstacles, and each application's rating per period. Applications are grouped by their
current business unit and product. Server-rendered inline SVG with native tooltips, no JavaScript,
no inline styles (the CSP stays strict); every chart has a table view.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import urlencode

from .webui import RATING_TITLE, RATINGS, UNASSIGNED, _nav, badge, e, legend, page

RANGES = {"3m": ("Last 3 months", 92), "12m": ("Last 12 months", 366), "all": ("All time", None)}
DEFAULT_RANGE = "12m"
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
STRIP = 12               # periods shown per application in the history table
OBSTACLES = (("Blockers", "Cannot run in a Linux container", "o1"),
             ("Rewrites", "Needs a port or rewrite", "o2"))


# ---------------------------------------------------------------------------
# data

def load_history(conn, since: datetime | None) -> list[dict]:
    """Scans from `since` on, plus each application's last scan before it (its state when the range starts)."""
    cols = ("AssessmentId, ApplicationId, ApplicationName, ProductId, ProductName, BusinessUnitId, BusinessUnitName, "
            "AssessedAt, Rating, Score, Blockers, Rewrites")
    cur = conn.cursor(as_dict=True)
    if since is None:
        cur.execute(f"SELECT {cols} FROM cz.vAssessmentHistory")
    else:
        cur.execute(f"SELECT {cols} FROM (SELECT {cols}, ROW_NUMBER() OVER (PARTITION BY ApplicationId, "
                    "CASE WHEN AssessedAt < %s THEN 0 ELSE 1 END ORDER BY AssessedAt DESC, AssessmentId DESC) AS Rn "
                    "FROM cz.vAssessmentHistory) h WHERE AssessedAt >= %s OR Rn = 1", (since, since))
    return cur.fetchall()


# ---------------------------------------------------------------------------
# periods and the state at the end of each

def _month_start(d: datetime, step: int = 1) -> datetime:
    m = (d.month - 1) // step * step
    return datetime(d.year, m + 1, 1)


def _add_months(d: datetime, n: int) -> datetime:
    m = d.month - 1 + n
    return datetime(d.year + m // 12, m % 12 + 1, 1)


def periods(first: datetime, now: datetime) -> tuple[str, list[tuple[datetime, datetime]]]:
    """(granularity, [(start, end)]) covering first..now; end is exclusive. At most ~40 periods."""
    first = datetime(first.year, first.month, first.day)
    days = (now - first).days
    out = []
    if days <= 31:
        gran, d = "day", first
        while d <= now:
            out.append((d, d + timedelta(days=1)))
            d += timedelta(days=1)
    elif days <= 280:
        gran, d = "week", first - timedelta(days=first.weekday())     # weeks start on Monday
        while d <= now:
            out.append((d, d + timedelta(days=7)))
            d += timedelta(days=7)
    else:
        step = 1 if days <= 36 * 31 else 3
        gran, d = ("month" if step == 1 else "quarter"), _month_start(first, step)
        while d <= now:
            out.append((d, _add_months(d, step)))
            d = _add_months(d, step)
    return gran, out


def period_label(gran: str, start: datetime, short: bool = False) -> str:
    if gran == "month":
        return f"{MONTHS[start.month - 1]} {start.year}" if not short or start.month == 1 else MONTHS[start.month - 1]
    if gran == "quarter":
        return f"Q{(start.month - 1) // 3 + 1} {start.year}"
    if gran == "week":
        return (f"{MONTHS[start.month - 1]} {start.day}" if short else
                f"week of {MONTHS[start.month - 1]} {start.day}, {start.year}")
    return f"{MONTHS[start.month - 1]} {start.day}" + ("" if short else f", {start.year}")


def compute(rows: list[dict], now: datetime, since: datetime | None) -> dict:
    """The portfolio at the end of every period: rating mix, obstacles, each application's rating."""
    by_app: dict = {}
    for r in rows:
        by_app.setdefault(r["ApplicationId"], []).append(r)
    for lst in by_app.values():
        lst.sort(key=lambda r: (r["AssessedAt"], r["AssessmentId"]))
    if not by_app:
        return {"gran": "day", "periods": [], "dist": [], "obstacles": [], "apps": []}
    first = min(r["AssessedAt"] for r in rows)
    if since is not None:
        first = max(first, since)
    gran, ps = periods(first, now)
    apps = []
    for app_id, lst in by_app.items():
        cur = lst[-1]
        states, i, last = [], 0, None
        for _start, end in ps:
            while i < len(lst) and lst[i]["AssessedAt"] < end:
                last, i = lst[i], i + 1
            states.append(last)
        apps.append({"ApplicationId": app_id, "ApplicationName": cur["ApplicationName"],
                     "ProductId": cur["ProductId"], "ProductName": cur["ProductName"],
                     "BusinessUnitId": cur["BusinessUnitId"], "BusinessUnitName": cur["BusinessUnitName"],
                     "states": states, "scans": sum(1 for r in lst if since is None or r["AssessedAt"] >= since)})
    return summarise({"gran": gran, "periods": ps, "apps": apps})


def summarise(data: dict) -> dict:
    """Per-period totals of the (possibly filtered) applications."""
    n = len(data["periods"])
    dist = [Counter() for _ in range(n)]
    obst = [{k: 0 for k, _, _ in OBSTACLES} for _ in range(n)]
    for a in data["apps"]:
        for i, s in enumerate(a["states"]):
            if s is not None:
                dist[i][s["Rating"]] += 1
                for k, _, _ in OBSTACLES:
                    obst[i][k] += int(s[k] or 0)
        known = [s for s in a["states"] if s is not None]
        a["from"] = known[0]["Rating"] if known else None
        a["to"] = known[-1]["Rating"] if known else None
    return {**data, "dist": dist, "obstacles": obst}


def filtered(data: dict, bu: str | None, product: str | None) -> dict:
    def key(v):
        return str(v if v is not None else "none")
    apps = [a for a in data["apps"] if (bu is None or key(a["BusinessUnitId"]) == bu)
            and (product is None or key(a["ProductId"]) == product)]
    return summarise({**data, "apps": apps})


def change(a: dict) -> int:
    """< 0 improved (towards A), > 0 regressed, 0 unchanged, over the range."""
    if not a["from"] or not a["to"]:
        return 0
    return RATINGS.index(a["to"]) - RATINGS.index(a["from"])


# ---------------------------------------------------------------------------
# charts (inline SVG; every mark carries a <title> tooltip, the tables below carry every value)

W, H, PAD_L, PAD_R, PAD_T, PAD_B = 1000, 260, 44, 120, 16, 30


def _ticks(top: int) -> tuple[int, list[int]]:
    """A clean axis maximum and its ticks (0 and 3-5 round steps)."""
    top = max(top, 1)
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000, 10000, 20000, 50000):
        if top / step <= 5:
            hi = -(-top // step) * step
            return hi, list(range(0, hi + 1, step))
    step = 10 ** len(str(top))
    return step, [0, step]


def _frame(hi: int, ticks: list[int], labels: list[str], label: str) -> tuple[list[str], callable, callable]:
    n = len(labels)
    plot_w, plot_h = W - PAD_L - PAD_R, H - PAD_T - PAD_B
    slot = plot_w / max(n, 1)

    def x(i):
        return PAD_L + slot * (i + 0.5)

    def y(v):
        return PAD_T + plot_h * (1 - v / hi)
    out = [f"<svg class='chart' viewBox='0 0 {W} {H}' role='img' aria-label='{e(label)}'>"]
    for t in ticks:
        cls = "axis" if t == 0 else "grid"
        out.append(f"<line class='{cls}' x1='{PAD_L}' x2='{W - PAD_R}' y1='{y(t):.1f}' y2='{y(t):.1f}'/>"
                   f"<text class='tick' x='{PAD_L - 8}' y='{y(t) + 4:.1f}' text-anchor='end'>{t:,}</text>")
    every = max(1, -(-n // 10))
    for i, lab in enumerate(labels):
        if (n - 1 - i) % every == 0:     # always label the latest period
            out.append(f"<text class='tick' x='{x(i):.1f}' y='{H - 8}' text-anchor='middle'>{e(lab)}</text>")
    return out, x, y


def _cap_path(x0: float, y0: float, w: float, h: float, r: float) -> str:
    """A rectangle with rounded top corners only (square at the baseline)."""
    r = min(r, w / 2, h)
    return (f"M{x0:.1f},{y0 + h:.1f}V{y0 + r:.1f}Q{x0:.1f},{y0:.1f} {x0 + r:.1f},{y0:.1f}"
            f"H{x0 + w - r:.1f}Q{x0 + w:.1f},{y0:.1f} {x0 + w:.1f},{y0 + r:.1f}V{y0 + h:.1f}Z")


def rating_columns(data: dict) -> str:
    """Stacked columns: how many applications had each rating at the end of each period."""
    labels = [period_label(data["gran"], s, short=True) for s, _ in data["periods"]]
    long = [period_label(data["gran"], s) for s, _ in data["periods"]]
    totals = [sum(c.values()) for c in data["dist"]]
    hi, ticks = _ticks(max(totals, default=0))
    out, x, y = _frame(hi, ticks, labels, "Applications by rating at the end of each period")
    slot = (W - PAD_L - PAD_R) / max(len(labels), 1)
    w = min(24.0, slot * 0.6)
    for i, c in enumerate(data["dist"]):
        if not totals[i]:
            continue
        summary = "; ".join(f"{r}: {c[r]}" for r in RATINGS if c[r])
        out.append(f"<g><rect class='hit' x='{x(i) - slot / 2:.1f}' y='{PAD_T}' width='{slot:.1f}' "
                   f"height='{H - PAD_T - PAD_B}'><title>{e(long[i])}: {totals[i]} applications ({summary})</title></rect>")
        base, parts = y(0), [r for r in RATINGS if c[r]]
        for j, r in enumerate(parts):
            h = y(0) - y(c[r])
            gap = 2.0 if j < len(parts) - 1 else 0.0       # 2px surface gap between segments
            top = base - h
            seg_h = max(h - gap, 1.0)
            title = f"<title>{e(long[i])}: {c[r]} of {totals[i]} applications rated {r} ({e(RATING_TITLE[r])})</title>"
            if j == len(parts) - 1:
                out.append(f"<path class='f{r}' d='{_cap_path(x(i) - w / 2, top, w, seg_h, 4)}'>{title}</path>")
            else:
                out.append(f"<rect class='f{r}' x='{x(i) - w / 2:.1f}' y='{top + gap:.1f}' width='{w:.1f}' "
                           f"height='{seg_h:.1f}'>{title}</rect>")
            base = top
        out.append("</g>")
    last = len(totals) - 1
    if last >= 0 and totals[last]:
        out.append(f"<text class='val' x='{x(last):.1f}' y='{y(totals[last]) - 6:.1f}' text-anchor='middle'>"
                   f"{totals[last]:,}</text>")
    out.append("</svg>")
    return "".join(out)


def obstacle_lines(data: dict) -> str:
    """Two lines: open obstacles of each kind across the applications, at the end of each period."""
    labels = [period_label(data["gran"], s, short=True) for s, _ in data["periods"]]
    long = [period_label(data["gran"], s) for s, _ in data["periods"]]
    active = [i for i, c in enumerate(data["dist"]) if sum(c.values())]
    hi, ticks = _ticks(max((o[k] for o in data["obstacles"] for k, _, _ in OBSTACLES), default=0))
    out, x, y = _frame(hi, ticks, labels, "Obstacles found at the end of each period")
    ends = []
    for k, name, cls in OBSTACLES:
        pts = [(x(i), y(data["obstacles"][i][k])) for i in active]
        if len(pts) > 1:
            out.append(f"<polyline class='line {cls}' points='{' '.join(f'{px:.1f},{py:.1f}' for px, py in pts)}'/>")
        if pts:
            ends.append((pts[-1][1], data["obstacles"][active[-1]][k], name, cls))
    for i in active:       # markers last, so their surface ring sits on top of both lines
        for k, name, cls in OBSTACLES:
            v = data["obstacles"][i][k]
            out.append(f"<g><circle class='hit' cx='{x(i):.1f}' cy='{y(v):.1f}' r='12'/>"
                       f"<circle class='dot {cls}' cx='{x(i):.1f}' cy='{y(v):.1f}' r='4'/>"
                       f"<title>{e(long[i])}: {v:,} × {e(name)}</title></g>")
    # direct end labels, unless they would collide (the legend and table carry them then)
    if len(ends) == 2 and abs(ends[0][0] - ends[1][0]) >= 16 or len(ends) == 1:
        lx = x(active[-1]) + 12
        for py, v, name, _cls in ends:
            out.append(f"<text class='val' x='{lx:.1f}' y='{py + 4:.1f}'>{v:,}</text>")
    out.append("</svg>")
    return "".join(out)


def line_legend() -> str:
    items = "".join(f"<li><span class='lkey {cls}'></span>{e(name)}</li>" for _, name, cls in OBSTACLES)
    return f"<ul class='legend'>{items}</ul>"


def strip(states: list, labels: list[str]) -> str:
    """One application's rating per period: letter-in-colour cells (letter = identity without colour)."""
    cells = []
    for s, lab in zip(states, labels):
        if s is None:
            cells.append(f"<span class='cell none' title='{e(lab)}: not assessed yet'></span>")
        else:
            r = s["Rating"]
            cells.append(f"<span class='cell r{r}' title='{e(lab)}: {r} {e(RATING_TITLE[r])}'>{r}</span>")
    return f"<span class='strip'>{''.join(cells)}</span>"


# ---------------------------------------------------------------------------
# page

def _href(rng: str, bu: str | None, product: str | None) -> str:
    q = {k: v for k, v in (("range", rng if rng != DEFAULT_RANGE else None), ("bu", bu), ("product", product)) if v}
    return "/trends" + ("?" + urlencode(q) if q else "")


def _chip(label: str, href: str, on: bool, count: int | None = None) -> str:
    n = f" <span class='muted'>{count}</span>" if count is not None else ""
    return f"<a class='chip{' on' if on else ''}' href='{e(href)}'>{e(label)}{n}</a>"


def _delta(now: int, then: int, since: str, up_good: bool) -> str:
    d = now - then
    if not d:
        return f"<div class='sub'>no change since {e(since)}</div>"
    good = (d > 0) == up_good
    return (f"<div class='sub'><span class='{'good' if good else 'bad'}'>{'▲' if d > 0 else '▼'} {abs(d):,}</span>"
            f" since {e(since)}</div>")


def _table(head: list[str], rows: list[list], first_text: bool = True) -> str:
    th = "".join(f"<th{'' if (i == 0 and first_text) else ' class=num'}>{e(h)}</th>" for i, h in enumerate(head))
    body = "".join("<tr>" + "".join(f"<td{'' if (i == 0 and first_text) else ' class=num'}>{e(str(v))}</td>"
                                    for i, v in enumerate(r)) + "</tr>" for r in rows)
    return f"<table class='narrow'><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def render_trends(full: dict, rng: str = DEFAULT_RANGE, bu: str | None = None, product: str | None = None,
                  nav: str = "") -> str:
    data = filtered(full, bu, product)
    gran, ps = data["gran"], data["periods"]
    long = [period_label(gran, s) for s, _ in ps]
    active = [i for i, c in enumerate(data["dist"]) if sum(c.values())]

    chips = [_chip(label, _href(k, bu, product), k == rng) for k, (label, _) in RANGES.items()]
    bus: dict = {}
    for a in full["apps"]:
        bus.setdefault((a["BusinessUnitName"] or "", a["BusinessUnitId"]), []).append(a)
    bu_chips = [_chip("All business units", _href(rng, None, None), bu is None)]
    for (name, bid), lst in sorted(bus.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
        k = str(bid if bid is not None else "none")
        bu_chips.append(_chip(name or UNASSIGNED, _href(rng, k, None), bu == k, len(lst)))
    prod_chips = []
    if bu is not None:
        prods: dict = {}
        for a in full["apps"]:
            if str(a["BusinessUnitId"] if a["BusinessUnitId"] is not None else "none") == bu:
                prods.setdefault((a["ProductName"] or "", a["ProductId"]), []).append(a)
        prod_chips = [_chip("All products", _href(rng, bu, None), product is None)]
        for (name, pid), lst in sorted(prods.items(), key=lambda kv: (kv[0][1] is None, kv[0][0].lower())):
            k = str(pid if pid is not None else "none")
            prod_chips.append(_chip(name or UNASSIGNED, _href(rng, bu, k), product == k, len(lst)))

    filters = (f"<nav class='chips'>{''.join(chips)}</nav><nav class='chips'>{''.join(bu_chips)}</nav>"
               + (f"<nav class='chips'>{''.join(prod_chips)}</nav>" if prod_chips else ""))
    head = f"""{_nav(nav)}
<p class='crumbs'><a href='/'>Readiness</a> › Trends</p>
<header><h1>Readiness over time</h1>
<p class='muted'>How the ratings and obstacles of our applications changed from scan to scan</p></header>"""
    if not active:
        return page("Readiness over time", head + (filters if full["apps"] else "") +
                    "<p>No assessments in this range yet. Every scan adds a point here.</p>")

    f, l = active[0], active[-1]
    since = long[f]
    dist_f, dist_l = data["dist"][f], data["dist"][l]
    ob_f, ob_l = data["obstacles"][f], data["obstacles"][l]
    improved = sum(1 for a in data["apps"] if change(a) < 0)
    regressed = sum(1 for a in data["apps"] if change(a) > 0)
    tiles = (f"<div class='tile'><div class='label'>Applications assessed</div><div class='value'>{sum(dist_l.values()):,}</div>"
             f"{_delta(sum(dist_l.values()), sum(dist_f.values()), since, True)}</div>"
             f"<div class='tile'><div class='label'>Ready now (A)</div><div class='value'>{dist_l['A']:,}</div>"
             f"{_delta(dist_l['A'], dist_f['A'], since, True)}</div>"
             f"<div class='tile'><div class='label'>Cannot run in a Linux container</div><div class='value'>{ob_l['Blockers']:,}</div>"
             f"{_delta(ob_l['Blockers'], ob_f['Blockers'], since, False)}</div>"
             f"<div class='tile'><div class='label'>Rating improved</div><div class='value'>{improved:,}</div>"
             f"<div class='sub'>applications, since {e(since)}</div></div>"
             f"<div class='tile'><div class='label'>Rating got worse</div><div class='value'>{regressed:,}</div>"
             f"<div class='sub'>applications, since {e(since)}</div></div>")

    dist_rows = [[long[i]] + [data["dist"][i][r] for r in RATINGS] + [sum(data["dist"][i].values())] for i in active]
    ob_rows = [[long[i]] + [data["obstacles"][i][k] for k, _, _ in OBSTACLES] for i in active]

    shown = list(range(max(0, len(ps) - STRIP), len(ps)))
    strip_labels = [long[i] for i in shown]
    apps = sorted(data["apps"], key=lambda a: ((a["BusinessUnitName"] or "￿").lower(),
                                               (a["ProductName"] or "￿").lower(), a["ApplicationName"].lower()))
    rows = []
    for a in apps:
        ch = change(a)
        text = ("<span class='good'>▲ better</span>" if ch < 0 else "<span class='bad'>▼ worse</span>" if ch > 0
                else "<span class='muted'>no change</span>")
        frm = f"{badge(a['from'])} → " if a["from"] and a["from"] != a["to"] else ""
        rows.append(f"<tr><td><a href='/app/{int(a['ApplicationId'])}'>{e(a['ApplicationName'])}</a>"
                    f"<div class='muted small'>{e(a['BusinessUnitName'] or UNASSIGNED)} › {e(a['ProductName'] or UNASSIGNED)}</div></td>"
                    f"<td>{strip([a['states'][i] for i in shown], strip_labels)}</td>"
                    f"<td class='nowrap'>{frm}{badge(a['to']) if a['to'] else ''}</td><td>{text}</td>"
                    f"<td class='num'>{int(a['scans'])}</td></tr>")
    strip_note = (f"{period_label(gran, ps[shown[0]][0])} to {period_label(gran, ps[shown[-1]][0])}, one cell per {gran}"
                  if shown else "")

    body = f"""{head}
{filters}
<div class='tiles'>{tiles}</div>
<section class='card'><h2>Applications by rating</h2>
<p class='muted small'>Each column is the portfolio at the end of a {gran}: every application counts once, with the
rating of its latest scan by then. Applications appear from their first scan.</p>
{legend()}{rating_columns(data)}
<details><summary>Show as a table</summary>{_table(['Period'] + RATINGS + ['Total'], dist_rows)}</details></section>
<section class='card'><h2>Obstacles</h2>
<p class='muted small'>Distinct obstacles found by the latest scan of each application, added up. Fewer is better.</p>
{line_legend()}{obstacle_lines(data)}
<details><summary>Show as a table</summary>{_table(['Period'] + [n for _, n, _ in OBSTACLES], ob_rows)}</details></section>
<section class='card'><h2>Rating history per application</h2>
<p class='muted small'>{e(strip_note)}. Change compares the first and the latest rating in the range.</p>
<table><thead><tr><th>Application</th><th>Rating per {e(gran)}</th><th>Rating</th><th>Change</th>
<th class='num'>Scans</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<footer>{legend()}<p class='muted small'>Applications are grouped by their current business unit and product.
Retired applications are left out. A period without a new scan repeats the application's previous result.</p></footer>"""
    return page("Readiness over time", body)


def parse_query(q: dict) -> tuple[str, str | None, str | None]:
    import re
    rng = q.get("range", [DEFAULT_RANGE])[0]
    rng = rng if rng in RANGES else DEFAULT_RANGE
    bu = q.get("bu", [None])[0]
    bu = bu if bu is not None and re.fullmatch(r"\d{1,9}|none", bu) else None
    product = q.get("product", [None])[0]
    product = product if product is not None and re.fullmatch(r"\d{1,9}|none", product) and bu is not None else None
    return rng, bu, product


def since_for(rng: str, now: datetime) -> datetime | None:
    days = RANGES[rng][1]
    return None if days is None else datetime(now.year, now.month, now.day) - timedelta(days=days)
