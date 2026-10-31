"""Trends page: per-period state of the portfolio from the kept scan history."""
import os
import re
import threading
import urllib.request
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer

import pytest

from containerizer import sqlstore, trends, webui
from containerizer.assess import assess

from test_engine import web_app

NOW = datetime(2026, 10, 31, 12)


def _scan(i, app, name, when, rating, blockers=0, rewrites=0, bu=None, bid=None, product=None, pid=None):
    return {"AssessmentId": i, "ApplicationId": app, "ApplicationName": name, "ProductId": pid, "ProductName": product,
            "BusinessUnitId": bid, "BusinessUnitName": bu, "AssessedAt": when, "Rating": rating, "Score": 50,
            "Blockers": blockers, "Rewrites": rewrites}


def history():
    fin = {"bu": "Finance", "bid": 1, "product": "Billing", "pid": 10}
    return [
        _scan(1, 1, "billing", datetime(2026, 1, 5), "C", 0, 2, **fin),
        _scan(2, 1, "billing", datetime(2026, 4, 2), "B", 0, 1, **fin),
        _scan(3, 1, "billing", datetime(2026, 9, 9), "A", **fin),
        _scan(4, 2, "<ledger>", datetime(2026, 2, 1), "A", **fin),
        _scan(5, 2, "<ledger>", datetime(2026, 8, 1), "E", 3, 0, **fin),
        _scan(6, 3, "orphan", datetime(2026, 6, 15), "D", 1, 1),
    ]


def test_periods_pick_a_granularity():
    assert trends.periods(NOW - timedelta(days=10), NOW)[0] == "day"
    gran, ps = trends.periods(NOW - timedelta(days=90), NOW)
    assert gran == "week" and all(s.weekday() == 0 for s, _ in ps) and ps[-1][0] <= NOW < ps[-1][1]
    gran, ps = trends.periods(datetime(2025, 11, 20), NOW)
    assert gran == "month" and ps[0][0] == datetime(2025, 11, 1) and ps[-1] == (datetime(2026, 10, 1), datetime(2026, 11, 1))
    gran, ps = trends.periods(datetime(2020, 2, 3), NOW)
    assert gran == "quarter" and ps[0][0] == datetime(2020, 1, 1) and len(ps) <= 40


def test_state_carries_forward_to_each_period_end():
    d = trends.compute(history(), NOW, None)
    assert d["gran"] == "month" and len(d["periods"]) == 10          # Jan..Oct 2026
    jan, mar, jun, oct_ = d["dist"][0], d["dist"][2], d["dist"][5], d["dist"][9]
    assert jan == {"C": 1} and mar == {"C": 1, "A": 1} and jun == {"B": 1, "A": 1, "D": 1}
    assert oct_ == {"A": 1, "E": 1, "D": 1}
    assert d["obstacles"][0] == {"Blockers": 0, "Rewrites": 2}
    assert d["obstacles"][9] == {"Blockers": 4, "Rewrites": 1}
    by = {a["ApplicationName"]: a for a in d["apps"]}
    assert trends.change(by["billing"]) < 0 and trends.change(by["<ledger>"]) > 0 and trends.change(by["orphan"]) == 0


def test_range_start_uses_the_last_scan_before_it():
    since = datetime(2026, 5, 1)
    d = trends.compute(history(), NOW, since)     # load_history would also return scan 2 (billing, B) and 4
    assert d["periods"][0][0] == datetime(2026, 4, 27)                # weekly, from the week of May 1
    assert d["dist"][0] == {"B": 1, "A": 1}
    by = {a["ApplicationName"]: a for a in d["apps"]}
    assert (by["billing"]["from"], by["billing"]["to"]) == ("B", "A") and by["billing"]["scans"] == 1


def test_filters_by_business_unit_and_product():
    d = trends.compute(history(), NOW, None)
    assert trends.filtered(d, "none", None)["dist"][9] == {"D": 1}
    assert trends.filtered(d, "1", "10")["dist"][9] == {"A": 1, "E": 1}
    assert trends.filtered(d, "1", "99")["apps"] == []
    assert trends.parse_query({"range": ["x"], "bu": ["1;DROP"], "product": ["2"]}) == ("12m", None, None)
    assert trends.parse_query({"range": ["all"], "bu": ["none"], "product": ["2"]}) == ("all", "none", "2")


def test_page_renders_charts_tables_and_escapes():
    d = trends.compute(history(), NOW, None)
    html = trends.render_trends(d, "all")
    assert "<ledger>" not in html and "&lt;ledger&gt;" in html
    assert "style=" not in html and "<script" not in html             # the CSP allows neither
    assert html.count("<svg class='chart'") == 2 and html.count("Show as a table") == 2
    assert "Rating improved" in html and "▲ better" in html and "▼ worse" in html
    assert "/app/1" in html and "Finance" in html and "Oct 2026" in html
    # every column segment and line marker has a tooltip
    assert html.count("applications rated") == sum(len(c) for c in d["dist"])
    assert "× Cannot run in a Linux container" in html
    # the product filter appears once a business unit is chosen, and keeps the range
    assert "All products" not in html
    html = trends.render_trends(d, "all", "1")
    assert "All products" in html and "href='/trends?range=all&amp;bu=1&amp;product=10'" in html
    assert "orphan" not in html


def test_stacked_columns_are_proportional():
    d = trends.compute(history(), NOW, None)
    svg = trends.rating_columns(trends.filtered(d, None, None))
    # October: A, D, E one each -> equal segment heights (allowing for the 2px gaps)
    oct_ = svg.split("<g>")[-1]
    hs = [float(h) for h in re.findall(r"class='f.' x='[\d.]+' y='[\d.]+' width='[\d.]+' height='([\d.]+)'", oct_)]
    assert len(hs) == 2 and hs[0] == pytest.approx(hs[1], abs=0.2)     # A and D; E is the rounded cap


def test_empty_history():
    html = trends.render_trends(trends.compute([], NOW, None))
    assert "No assessments in this range yet" in html


class _Conn:
    def cursor(self, as_dict=False):
        return self

    def execute(self, sql, params=()):
        self.sql, self.params = sql, params

    def fetchall(self):
        return [r for r in history() if not self.params or r["AssessedAt"] >= self.params[0]]

    def close(self):
        pass


def test_http_trends_page():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webui.make_handler(_Conn))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        for q in ("", "?range=all", "?range=3m&bu=1&product=10", "?bu=x'"):
            r = urllib.request.urlopen(base + "/trends" + q, timeout=10)
            assert r.status == 200 and "Readiness over time" in r.read().decode()
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------
# integration with a real SQL Server: every scan is kept and the reader can read the history

ADMIN = os.environ.get("CONTAINERIZER_TEST_SQL")


@pytest.mark.skipif(not ADMIN, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")
def test_history_view_keeps_every_scan(tmp_path):
    import uuid
    name = "cztrend_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    sqlstore.create_login(conn, "cz_tr_reader", "Test-Passw0rd!x", "reader")
    try:
        web_app(tmp_path / "blocked", code='var t = Type.GetTypeFromProgID("Excel.Application");')
        web_app(tmp_path / "ready")
        blocked, ready = assess(tmp_path / "blocked"), assess(tmp_path / "ready")
        src = {"key": "app-1", "path": "."}
        sqlstore.store_assessment(conn, sqlstore.assessment_doc(blocked), src, datetime(2026, 3, 1))
        sqlstore.store_assessment(conn, sqlstore.assessment_doc(ready), src, datetime(2026, 9, 1))
        rd = sqlstore.connect(re.sub(r"(?i)user\s*id\s*=[^;]*", "User Id=cz_tr_reader", cs), "Test-Passw0rd!x")
        try:
            rows = trends.load_history(rd, None)
            assert [(r["Rating"], r["Blockers"] > 0) for r in sorted(rows, key=lambda r: r["AssessedAt"])] == \
                [(blocked.rating, True), (ready.rating, False)]
            rows = trends.load_history(rd, datetime(2026, 6, 1))   # the scan before the range is kept as its start
            assert len(rows) == 2
            d = trends.compute(rows, NOW, datetime(2026, 6, 1))
            assert d["dist"][0] == {blocked.rating: 1} and d["dist"][-1] == {ready.rating: 1}
            assert "Readiness over time" in trends.render_trends(d)
            assert len(trends.load_history(rd, datetime(2026, 10, 1))) == 1
        finally:
            rd.close()
    finally:
        conn.close()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.cursor().execute("IF SUSER_ID(N'cz_tr_reader') IS NOT NULL DROP LOGIN cz_tr_reader")
        m.close()


def test_overview_and_application_link_to_trends():
    from test_sqlstore import application_data, overview_data
    assert "href='/trends'" in webui.render_overview(overview_data())
    assert "href='/trends?bu=1'" in webui.render_overview(overview_data(), bu_filter="1")
    assert "href='/trends'" in webui.render_application(application_data())
