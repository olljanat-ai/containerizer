"""The rating scale: C partial (blocked components, the rest need at most minor changes), D major refactoring
(a framework port, also with blocked components), E not feasible; and schema 40, which swaps the stored C and D
once (SQL Server, CONTAINERIZER_TEST_SQL)."""
import json
import os
import re
import uuid
from types import SimpleNamespace

import pytest

from containerizer import webui
from containerizer.assess import APP_RATINGS, AppAssessment


def rate(*verdicts, stateless=True, extra_tiers=()):
    comps = [SimpleNamespace(name=f"c{i}", tier="server", verdict=v, stateless=stateless)
             for i, v in enumerate(verdicts)]
    comps += [SimpleNamespace(name=f"x{i}", tier=t, verdict="blocker", stateless=True) for i, t in enumerate(extra_tiers)]
    return AppAssessment(repo=None, components=comps, libraries=[], tests=[], repo_findings=[]).rating


def test_partial_is_c_when_the_movable_part_needs_at_most_minor_changes():
    assert rate("blocker", "config", "info") == "C"
    assert rate("blocker", "refactor", "config", "info") == "C"
    assert rate("blocker", "config", stateless=False) == "C"


def test_framework_port_is_d_also_with_blocked_components():
    assert rate("rewrite") == "D"
    assert rate("rewrite", "config", "refactor") == "D"
    assert rate("blocker", "rewrite", "config") == "D"           # the worse of the two


def test_not_feasible_and_the_unchanged_ends():
    assert rate("blocker", "blocker", "blocker", "rewrite") == "E"  # three quarters blocked
    assert rate("blocker", "blocker", "blocker", "config") == "E"
    assert rate("blocker") == "E"
    assert rate() == "E"                                          # no server component
    assert rate(extra_tiers=("client",)) == "E"                   # a desktop client does not count
    assert rate("blocker", "blocker", "config") == "C"            # two thirds blocked: still partial
    assert rate("config", "info") == "A"
    assert rate("config", stateless=False) == "A"                 # its data on a persistent volume: still A
    assert rate("refactor", "config") == "B"
    assert rate("config", extra_tiers=("client", "database")) == "A"


def test_titles_follow_the_new_scale():
    assert APP_RATINGS["C"].startswith("Partial") and APP_RATINGS["D"].startswith("Major refactoring")
    assert webui.RATING_TITLE["C"] == "Partial" and webui.RATING_TITLE["D"] == "Major refactoring"
    assert webui.RATINGS == ["A", "B", "C", "D", "E"]


def test_why_c_names_the_blocked_components_and_why_d_the_port():
    comps = [{"ComponentName": "Signing", "Verdict": "blocker", "Tier": "server"},
             {"ComponentName": "Portal", "Verdict": "config", "Tier": "server"}]
    html = webui.rating_why({"Rating": "C", "components": comps, "findings": []})[0]
    assert "Signing cannot run in Linux containers" in html
    comps.append({"ComponentName": "Legacy", "Verdict": "rewrite", "Tier": "server"})
    html = webui.rating_why({"Rating": "D", "components": comps, "findings": []})[0]
    assert "Signing cannot run in Linux containers" in html and "Legacy need a port or rewrite" in html


# --------------------------------------------------------------------------- SQL Server: schema 40

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


def _report(rating, *verdicts):
    return json.dumps({"name": "x", "rating": rating, "rating_text": "old",
                       "components": [{"name": f"c{i}", "tier": "server", "verdict": v} for i, v in enumerate(verdicts)]
                       + [{"name": "client", "tier": "client", "verdict": "rewrite"}]})


@needs_sql
def test_schema_40_swaps_stored_c_and_d_once():
    from containerizer import sqlstore
    sa_pw = os.environ.get("CONTAINERIZER_SQL_PASSWORD")
    name = "czrating_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    try:
        sqlstore.init_schema(conn)
        cur = conn.cursor()
        # the database as schema 39 left it: ratings on the old scale (C framework port, D partial)
        cur.execute("DELETE FROM cz.SchemaVersion WHERE Version = 40")
        cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'k', N'shop')")
        cur.execute("SELECT ApplicationId FROM cz.Application WHERE SourceKey = N'k'")
        app_id = cur.fetchone()[0]
        rows = [("A", None), ("C", _report("C", "rewrite", "config")),            # port -> D
                ("D", _report("D", "blocker", "config", "refactor")),               # partial -> C
                ("D", _report("D", "blocker", "rewrite", "config")),                # partial and port -> stays D
                ("D", None),                                                        # no report: plain swap -> C
                ("E", None)]
        ids = []
        for rating, rep in rows:
            cur.execute("INSERT cz.ApplicationAssessment (ApplicationId, Rating, Score, Confidence, Summary, ReportJson) "
                        "OUTPUT INSERTED.AssessmentId VALUES (%s, %s, 50, 0.9, N's', %s)", (app_id, rating, rep))
            ids.append(cur.fetchone()[0])
        cur.execute("INSERT cz.OrgScan (Name, Provider, Organization, Registry) "
                    "VALUES (N't', N'github', N'o', N'registry.example.com')")
        cur.execute("SELECT ScanId FROM cz.OrgScan WHERE Name = N't'")
        scan = cur.fetchone()
        detail = json.dumps({"apps": [{"folder": "a", "rating": "C"}, {"folder": "b", "rating": "D"}]})
        for i, r in enumerate(("C", "D", "B")):
            cur.execute("INSERT cz.OrgRepository (ScanId, ProjectName, Name, CloneUrl, LastRating, LastDetail) "
                        "VALUES (%s, N'_', %s, N'https://example.com/r.git', %s, %s)", (scan[0], f"r{i}", r, detail if r == "C" else None))
        payload = json.dumps({"goal": "rating-a", "rating": "D", "components": []})
        result = json.dumps({"status": "failed", "rating_before": "D", "rating_after": "C",
                             "loop": [{"pass": 1, "rating": "C"}, {"pass": 2, "rating": "B"}]})
        cur.execute("INSERT cz.LlmJob (Kind, App, SourceKey, Priority, DedupeKey, Status, Payload, Result) "
                    "VALUES (N'refactor', N'shop', N'k', 5, %s, N'answered', %s, %s)", ("d" * 64, payload, result))
        conn.commit()

        sqlstore.init_schema(conn)
        sqlstore.init_schema(conn)                   # the second run must not swap them back
        cur = conn.cursor()
        cur.execute("SELECT AssessmentId, Rating, ReportJson FROM cz.ApplicationAssessment ORDER BY AssessmentId")
        got = cur.fetchall()
        assert [r[1] for r in got] == ["A", "D", "C", "D", "C", "E"]
        assert json.loads(got[1][2])["rating"] == "D" and json.loads(got[1][2])["rating_text"].startswith("Major")
        assert json.loads(got[2][2])["rating"] == "C" and json.loads(got[2][2])["rating_text"].startswith("Partial")
        assert json.loads(got[3][2])["rating"] == "D"
        cur.execute("SELECT Name, LastRating, LastDetail FROM cz.OrgRepository WHERE ScanId = %s ORDER BY Name", (scan[0],))
        repos = cur.fetchall()
        assert [r[1] for r in repos] == ["D", "C", "B"]
        assert [x["rating"] for x in json.loads(repos[0][2])["apps"]] == ["D", "C"]
        cur.execute("SELECT Payload, Result FROM cz.LlmJob WHERE Kind = N'refactor'")
        pl, res = cur.fetchone()
        assert json.loads(pl)["rating"] == "C"
        res = json.loads(res)
        assert (res["rating_before"], res["rating_after"]) == ("C", "D")
        assert [x["rating"] for x in res["loop"]] == ["D", "B"]
        cur.execute("SELECT Title FROM cz.Rating WHERE Rating IN ('C', 'D') ORDER BY Rating")
        assert [r[0] for r in cur.fetchall()] == ["Partial", "Major refactoring"]
        cur.execute("SELECT COUNT(*) FROM cz.SchemaVersion WHERE Version = 40")
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()
        m = sqlstore.connect(re.sub(r"(?i)Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()
