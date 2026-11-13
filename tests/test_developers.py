"""Developers: commit authors from the providers' APIs, who commits where, and the business unit suggestions
(developers.py, admin_developers.py)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from containerizer import admin as adminmod
from containerizer import admin_developers as ad
from containerizer import developers as dv
from containerizer.oidc import OidcConfig
from containerizer.orgsource import AzureDevOps, GitHub, GitLab, SourceRepo

D = datetime
NOW = D(2026, 11, 12, 6, 0)

# sample data (placeholders only): also used for the docs screenshots
BUS = [{"BusinessUnitId": 1, "Name": "Finance"}, {"BusinessUnitId": 2, "Name": "Logistics"},
       {"BusinessUnitId": 3, "Name": "People"}]
PRODUCTS = [{"ProductId": 5, "Name": "Billing", "BusinessUnitId": 1}, {"ProductId": 6, "Name": "General ledger", "BusinessUnitId": 1},
            {"ProductId": 7, "Name": "Freight rates", "BusinessUnitId": 2}, {"ProductId": 8, "Name": "Warehouse", "BusinessUnitId": None},
            {"ProductId": 9, "Name": "Payroll", "BusinessUnitId": None}]


def dev(i, email, name, bu=None, ignored=False, last=None):
    return {"DeveloperId": i, "Email": email, "Name": name, "BusinessUnitId": bu, "Ignored": ignored, "Note": None,
            "FirstSeenAt": D(2026, 6, 1), "LastCommitAt": last or D(2026, 11, 10)}


DEVS = [dev(1, "john.doe@example.com", "John Doe", 1, last=D(2026, 11, 11, 15)),
        dev(2, "jane.doe@example.com", "Jane Doe", 1, last=D(2026, 11, 10, 9)),
        dev(3, "jack.doe@example.com", "Jack Doe", 2, last=D(2026, 11, 9, 12)),
        dev(4, "judy.doe@example.com", "Judy Doe", None, last=D(2026, 11, 11, 8)),
        dev(5, "jim.doe@example.com", "Jim Doe", None, last=D(2026, 11, 7, 16)),
        dev(6, "jill.doe@example.com", "Jill Doe", 3, last=D(2026, 10, 30, 10)),
        dev(7, "joe.doe@example.com", "Joe Doe", 2, last=D(2026, 11, 3, 13)),
        dev(8, "build.service@example.com", "Build Service", None, ignored=True, last=D(2026, 11, 11, 2))]


def repo(i, project, name, status="deployed", skip=None):
    return {"RepositoryId": i, "ProjectName": project, "Name": name, "ScanId": 1, "ScanName": "Contoso Azure DevOps",
            "WebUrl": f"https://dev.azure.com/contoso/{project}/_git/{name}", "LastStatus": status, "SkipStatus": skip}


REPOS = [repo(11, "Finance", "billing-api"), repo(12, "Finance", "ledger-web"), repo(13, "Logistics", "freight-rates"),
         repo(14, "Warehouse", "wms-api"), repo(15, "Warehouse", "wms-scanner"), repo(16, "Payroll", "payroll-service"),
         repo(17, "Shared", "common-auth", "skipped-no-code", "skipped-no-code"),
         repo(18, "Logistics", "route-planner", "no-a-components")]


def link(d, r, n, day):
    return {"DeveloperId": d, "RepositoryId": r, "Commits": n, "LastCommitAt": D(2026, 11, day, 12)}


LINKS = [link(1, 11, 84, 11), link(1, 12, 12, 2), link(2, 12, 61, 10), link(2, 11, 9, 1), link(3, 13, 40, 9),
         link(3, 14, 31, 8), link(7, 14, 22, 3), link(7, 15, 18, 3), link(4, 11, 27, 11), link(4, 12, 5, 4),
         link(5, 14, 14, 7), link(5, 13, 3, 1), link(6, 16, 35, 30 - 20), link(1, 17, 4, 5), link(2, 17, 3, 6),
         link(3, 18, 19, 6), link(7, 18, 11, 2), link(8, 11, 120, 11), link(8, 14, 90, 11)]


def app(rid, aid, name, pid):
    p = next((x for x in PRODUCTS if x["ProductId"] == pid), None)
    return {"RepositoryId": rid, "ApplicationId": aid, "AppName": name, "ProductId": pid,
            "ProductName": p["Name"] if p else None, "BusinessUnitId": p["BusinessUnitId"] if p else None}


APPS = [app(11, 21, "billing-api", 5), app(12, 22, "ledger-web", 6), app(13, 23, "freight-rates", 7),
        app(14, 24, "wms-api", 8), app(15, 25, "wms-scanner", 8), app(16, 26, "payroll-service", 9),
        app(18, 28, "route-planner", None)]

PROJECTS = [
    {"ProjectId": 1, "ScanId": 1, "ScanName": "Contoso Azure DevOps", "Provider": "azure-devops", "Name": "Finance",
     "ProductId": None, "ProductMappedAt": D(2026, 10, 1), "AdminState": None, "ProductName": None, "BusinessUnitId": None,
     "Repos": 2, "Apps": 2, "Unmapped": 0},
    {"ProjectId": 2, "ScanId": 1, "ScanName": "Contoso Azure DevOps", "Provider": "azure-devops", "Name": "Logistics",
     "ProductId": 7, "ProductMappedAt": D(2026, 10, 1), "AdminState": None, "ProductName": "Freight rates",
     "BusinessUnitId": 2, "Repos": 2, "Apps": 2, "Unmapped": 1},
    {"ProjectId": 3, "ScanId": 1, "ScanName": "Contoso Azure DevOps", "Provider": "azure-devops", "Name": "Payroll",
     "ProductId": 9, "ProductMappedAt": D(2026, 11, 11), "AdminState": None, "ProductName": "Payroll",
     "BusinessUnitId": None, "Repos": 1, "Apps": 1, "Unmapped": 0},
    {"ProjectId": 4, "ScanId": 1, "ScanName": "Contoso Azure DevOps", "Provider": "azure-devops", "Name": "Shared",
     "ProductId": None, "ProductMappedAt": None, "AdminState": None, "ProductName": None, "BusinessUnitId": None,
     "Repos": 1, "Apps": 0, "Unmapped": 0},
    {"ProjectId": 5, "ScanId": 1, "ScanName": "Contoso Azure DevOps", "Provider": "azure-devops", "Name": "Warehouse",
     "ProductId": 8, "ProductMappedAt": D(2026, 11, 11), "AdminState": None, "ProductName": "Warehouse",
     "BusinessUnitId": None, "Repos": 2, "Apps": 2, "Unmapped": 0},
]


class FakeCursor:
    def __init__(self, conn, as_dict):
        self.conn, self.as_dict, self.rows, self.rowcount = conn, as_dict, [], 0

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.conn.log.append((sql, tuple(params or ())))
        rows, self.rowcount = self.conn.answer(sql, tuple(params or ()))
        self.rows = [dict(r) for r in rows]

    def fetchall(self):
        return self.rows if self.as_dict else [tuple(r.values()) for r in self.rows]

    def fetchone(self):
        r = self.rows[0] if self.rows else None
        return r if self.as_dict or r is None else tuple(r.values())


class FakeConn:
    """Answers the queries of admin_developers.py and developers.py from the sample data."""

    def __init__(self, devs=None, links=None, repos=None, apps=None, products=None, bus=None, projects=None, history=None):
        self.devs = [dict(d) for d in (DEVS if devs is None else devs)]
        self.links = [dict(x) for x in (LINKS if links is None else links)]
        self.repos = REPOS if repos is None else repos
        self.apps = APPS if apps is None else apps
        self.products = PRODUCTS if products is None else products
        self.bus = BUS if bus is None else bus
        self.projects = PROJECTS if projects is None else projects
        self.history = history or []
        self.log, self.committed, self.rolled_back, self.closed, self.who = [], 0, 0, 0, None
        self.next_id = 100

    def cursor(self, as_dict=False):
        return FakeCursor(self, as_dict)

    def answer(self, sql, params):
        if sql.startswith("SELECT BusinessUnitId, Name FROM cz.BusinessUnit"):
            return self.bus, 0
        if sql.startswith("SELECT BusinessUnitId FROM cz.BusinessUnit"):
            return [{"BusinessUnitId": b["BusinessUnitId"]} for b in self.bus], 0
        if sql.startswith("SELECT DeveloperId, Email, Name"):
            return self.devs, 0
        if sql.startswith("SELECT DeveloperId, Email, LastCommitAt FROM cz.Developer"):
            return [{"DeveloperId": d["DeveloperId"], "Email": d["Email"], "LastCommitAt": d["LastCommitAt"]} for d in self.devs], 0
        if sql.startswith("SELECT dr.DeveloperId"):
            return self.links, 0
        if sql.startswith("SELECT DeveloperId, Commits, LastCommitAt FROM cz.DeveloperRepository"):
            return [x for x in self.links if x["RepositoryId"] == params[0]], 0
        if sql.startswith("SELECT r.RepositoryId, r.ProjectName"):
            return self.repos, 0
        if sql.startswith("SELECT DISTINCT r.RepositoryId"):
            return self.apps, 0
        if sql.startswith("SELECT ProductId, Name, BusinessUnitId FROM cz.Product"):
            return self.products, 0
        if sql.startswith("SELECT p.ProductId, p.Name, b.Name"):
            names = {b["BusinessUnitId"]: b["Name"] for b in self.bus}
            return [{"ProductId": p["ProductId"], "Name": p["Name"], "BusinessUnitName": names.get(p["BusinessUnitId"])}
                    for p in self.products], 0
        if sql.startswith("SELECT p.ProjectId, p.ScanId"):
            return self.projects, 0
        if sql.startswith("SELECT ProjectId, ScanId, Name, ProductId FROM cz.OrgProject"):
            return [p for p in self.projects if p["ProjectId"] == params[0]], 0
        if sql.startswith("SELECT v.RepositoryId"):
            return self.history, 0
        if sql.startswith("INSERT cz.Developer ("):
            self.next_id += 1
            self.devs.append(dev(self.next_id, params[0], params[1], last=params[2]))
            return [{"DeveloperId": self.next_id}], 1
        if sql.startswith("INSERT cz.DeveloperRepository"):
            self.links.append({"DeveloperId": params[0], "RepositoryId": params[1], "Commits": params[2], "LastCommitAt": params[3]})
            return [], 1
        if sql.startswith("SELECT TOP"):
            return [], 0
        return [], 1

    def writes(self, prefix):
        return [p for s, p in self.log if s.startswith(prefix)]

    def set_user(self, user, name=None, via="admin UI", role=None):
        self.who = (user, name, role)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


def make_admin(conn, admin=True):
    cfg = OidcConfig.from_env({"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
                               "CONTAINERIZER_PUBLIC_URL": "https://containerizer.example.com",
                               "CONTAINERIZER_ADMINS": "role:Containerizer.Admin"})
    adm = adminmod.Admin(cfg, lambda: conn, provider=object())
    adm.route_scans = lambda *a, **k: None
    sid = adm.sessions.create("john.doe@example.com", "John Doe", admin, False, False, [])
    return adm, sid


def get(adm, sid, path):
    path, _, query = path.partition("?")
    return adm.handle("GET", path, query, {"Cookie": f"{adm.cookie}={sid}"}, b"")


def post(adm, sid, path, fields):
    from urllib.parse import urlencode
    s = adm.sessions.get(sid)
    body = urlencode([("csrf", s.csrf)] + list(fields)).encode()
    return adm.handle("POST", path, "", {"Cookie": f"{adm.cookie}={sid}", "Origin": "https://containerizer.example.com"}, body)


# -- collection -------------------------------------------------------------------------------------------------

def test_authors_count_people_and_leave_out_bots():
    a = dv.Authors()
    a.add("John.Doe@Example.com", "John Doe", datetime(2026, 11, 1, tzinfo=timezone.utc))
    a.add("john.doe@example.com", "John D", datetime(2026, 11, 3, tzinfo=timezone.utc))
    a.add("dependabot[bot]@users.noreply.github.com", "dependabot[bot]", datetime(2026, 11, 4, tzinfo=timezone.utc))
    a.add("noreply@github.com", "GitHub", datetime(2026, 11, 2, tzinfo=timezone.utc))
    a.add("Build\\12345", "Project Collection Build Service", datetime(2026, 11, 5, tzinfo=timezone.utc))
    a.add("1234+jane@users.noreply.github.com", "Jane Doe", datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert set(a.by_email) == {"john.doe@example.com", "1234+jane@users.noreply.github.com"}
    assert a.by_email["john.doe@example.com"][0] == 2 and a.by_email["john.doe@example.com"][2] == "John D"
    assert a.newest == datetime(2026, 11, 5, tzinfo=timezone.utc)      # the newest commit of anyone


def test_due_reads_new_commits_and_refreshes_weekly():
    cutoff = NOW - timedelta(days=dv.HISTORY_DAYS)
    base = {"RemovedAt": None, "AdminState": None, "ProjectState": None}
    assert dv.due({**base, "LatestCommitAt": NOW, "HistoryAt": None, "HistoryCommitAt": None}, NOW, cutoff)
    assert not dv.due({**base, "LatestCommitAt": D(2025, 1, 1), "HistoryAt": None, "HistoryCommitAt": None}, NOW, cutoff)
    seen = {**base, "LatestCommitAt": D(2026, 11, 1), "HistoryAt": D(2026, 11, 10), "HistoryCommitAt": D(2026, 11, 1)}
    assert not dv.due(seen, NOW, cutoff)
    assert dv.due({**seen, "LatestCommitAt": D(2026, 11, 11)}, NOW, cutoff)
    assert dv.due({**seen, "HistoryAt": D(2026, 11, 1)}, NOW, cutoff)
    # disabled (a new repository may start so): read while someone commits there, who to ask before enabling it
    assert dv.due({**seen, "AdminState": "disabled", "HistoryAt": None}, NOW, cutoff)
    assert dv.due({**seen, "ProjectState": "disabled", "HistoryAt": None}, NOW, cutoff)
    assert not dv.due({**seen, "AdminState": "disabled", "LatestCommitAt": D(2025, 1, 1), "HistoryAt": D(2025, 2, 1)},
                      NOW, cutoff)                                       # deprecated: nobody committed in six months
    assert not dv.due({**seen, "ProjectState": "disabled", "LatestCommitAt": None, "HistoryAt": None}, NOW, cutoff)
    assert not dv.due({**seen, "RemovedAt": NOW}, NOW, cutoff)


class FakeProvider:
    def __init__(self, commits):
        self.commits_by_repo = commits
        self.asked = []

    def commits(self, r, since):
        self.asked.append((r.name, since))
        if r.name == "broken":
            raise RuntimeError("HTTP 500")
        yield from self.commits_by_repo.get(r.name, [])


def src(name, project="Finance"):
    return SourceRepo(provider="azure-devops", org="contoso", project=project, name=name, clone_url=f"https://x/{name}")


def test_collect_stores_developers_and_moves_the_last_commit_forward_only():
    t = lambda d: datetime(2026, 11, d, 12, tzinfo=timezone.utc)          # noqa: E731
    history = [{"RepositoryId": 11, "ProjectName": "Finance", "Name": "billing-api", "AdminState": None, "ProjectState": None,
                "RemovedAt": None, "LatestCommitAt": D(2026, 11, 11), "HistoryAt": None, "HistoryCommitAt": None},
               {"RepositoryId": 12, "ProjectName": "Finance", "Name": "broken", "AdminState": None, "ProjectState": None,
                "RemovedAt": None, "LatestCommitAt": D(2026, 11, 11), "HistoryAt": None, "HistoryCommitAt": None},
               {"RepositoryId": 13, "ProjectName": "Finance", "Name": "old", "AdminState": None, "ProjectState": None,
                "RemovedAt": None, "LatestCommitAt": D(2024, 1, 1), "HistoryAt": None, "HistoryCommitAt": None}]
    conn = FakeConn(devs=[dev(1, "john.doe@example.com", "John Doe", 1, last=D(2026, 11, 20))],
                    links=[link(1, 11, 3, 20), link(2, 11, 5, 1)], history=history)
    prov = FakeProvider({"billing-api": [("John.Doe@example.com", "John Doe", t(11)), ("john.doe@example.com", "John Doe", t(2)),
                                         ("jane.doe@example.com", "Jane Doe", t(9))]})
    n = dv.collect(conn, 1, prov, [src("billing-api"), src("broken"), src("old")],
                   now=datetime(2026, 11, 12, tzinfo=timezone.utc), log=lambda m: None, workers=2)
    assert n == {"repositories": 1, "errors": 1, "developers": 2}
    assert [a for a, _ in prov.asked] == ["billing-api", "broken"]          # "old": no commit in six months
    assert prov.asked[0][1] == datetime(2026, 11, 12, tzinfo=timezone.utc) - timedelta(days=183)
    assert conn.writes("INSERT cz.Developer (") == [("jane.doe@example.com", "Jane Doe", D(2026, 11, 9, 12))]
    assert not conn.writes("UPDATE cz.Developer SET LastCommitAt")     # John's newest (11-20) is newer than this one
    ups = conn.writes("UPDATE cz.DeveloperRepository SET Commits = %s, LastCommitAt")
    assert ups == [(2, D(2026, 11, 20, 12), 1, 11)]                     # count replaced, the date never goes back
    assert conn.writes("UPDATE cz.DeveloperRepository SET Commits = 0") == [(2, 11)]   # not in the six months any more
    assert conn.writes("UPDATE cz.OrgRepository SET HistoryAt") == [(D(2026, 11, 12), D(2026, 11, 11, 12), 11)]
    assert conn.writes("UPDATE cz.OrgRepository SET HistoryError")[0][0].startswith("RuntimeError: HTTP 500")


def test_provider_commit_requests(monkeypatch):
    seen = []

    def fake(url, headers, timeout=60, retries=4):
        seen.append(url)
        if "dev.azure.com" in url:
            return {"value": [{"author": {"email": "a@example.com", "name": "A", "date": "2026-11-01T10:00:00Z"}}]}, {}
        if "gitlab" in url:
            return [{"author_email": "b@example.com", "author_name": "B", "authored_date": "2026-11-02T10:00:00Z"}], {}
        return [{"commit": {"author": {"email": "c@example.com", "name": "C", "date": "2026-11-03T10:00:00Z"}}}], {}
    monkeypatch.setattr("containerizer.orgsource.http_json", fake)
    since = datetime(2026, 5, 13, tzinfo=timezone.utc)
    r = SourceRepo(provider="azure-devops", org="contoso", project="Fin ance", name="x", clone_url="", default_branch="main",
                   id="guid", extra={"project_q": "Fin%20ance"})
    assert list(AzureDevOps("contoso", "t").commits(r, since))[0][:2] == ("a@example.com", "A")
    assert "searchCriteria.fromDate=2026-05-13T00%3A00%3A00Z" in seen[-1] and "itemVersion.version=main" in seen[-1]
    r = SourceRepo(provider="gitlab", org="grp", project="_", name="x", clone_url="", default_branch="main", id="42")
    assert list(GitLab("grp", "t").commits(r, since))[0][:2] == ("b@example.com", "B")
    assert "/projects/42/repository/commits?per_page=100&since=2026-05-13" in seen[-1]
    r = SourceRepo(provider="github", org="o", project="_", name="x", clone_url="", default_branch="main",
                   extra={"full_name": "o/x"})
    assert list(GitHub("o", "t").commits(r, since))[0][:2] == ("c@example.com", "C")
    assert "/repos/o/x/commits?per_page=100&since=2026-05-13" in seen[-1] and "&sha=main" in seen[-1]


# -- suggestions ------------------------------------------------------------------------------------------------

def test_suggest_weighs_by_commits():
    s = dv.suggest([(1, 30), (2, 10), (None, 100), (1, 0)])
    assert (s.bu, round(s.share, 2), s.weight, s.voters, s.sure) == (1, 0.75, 30, 1, True)
    assert dv.suggest([(None, 3)]) is None
    assert not dv.suggest([(1, 5), (2, 5)]).sure


def test_model_suggests_developers_repositories_and_products():
    m = ad.load(FakeConn())
    d = m.dev_suggestions()
    assert d[4].bu == 1 and d[4].sure                         # Judy commits to Finance's repositories
    assert d[5].bu == 2                                       # Jim: freight-rates (Logistics); wms-api has no business unit
    r = m.repo_suggestions()
    assert r[14].bu == 2 and r[14].sure                       # wms-api: Jack and Joe are in Logistics; the bot is ignored
    assert r[17].bu == 1                                      # common-auth (not assessed): John and Jane
    p = m.product_suggestions()
    assert p[8][0].bu == 2 and p[8][1] == [14, 15]            # Warehouse -> Logistics
    assert p[9][0].bu == 3                                    # Payroll -> People (Jill)
    assert 5 not in p                                         # Billing has a business unit


# -- the page ---------------------------------------------------------------------------------------------------

def test_tab_is_for_administrators_only():
    conn = FakeConn()
    adm, sid = make_admin(conn)
    r = get(adm, sid, "/admin/developers")
    assert r.status == 200 and "Developers" in r.body
    assert "jane.doe@example.com" in r.body and "build.service@example.com" not in r.body       # ignored: own filter
    assert "Apply 2 suggestions" in r.body                                                      # Judy and Jim
    assert "Ignored <span class='muted'>1</span>" in r.body
    adm2, sid2 = make_admin(conn, admin=False)
    assert get(adm2, sid2, "/admin/developers").status in (302, 303, 403)


def test_search_and_filters():
    adm, sid = make_admin(FakeConn())
    r = get(adm, sid, "/admin/developers?show=unmapped")
    assert "judy.doe@example.com" in r.body and "jane.doe@example.com" not in r.body
    r = get(adm, sid, "/admin/developers?q=wms")
    assert "jack.doe@example.com" in r.body and "jill.doe@example.com" not in r.body


def test_save_updates_only_changed_rows():
    conn = FakeConn()
    adm, sid = make_admin(conn)
    r = post(adm, sid, "/admin/developers/save", [("back", "show=unmapped"), ("d", "4"), ("was-4", "|0"), ("bu-4", "1"),
                                                  ("d", "5"), ("was-5", "|0"), ("bu-5", ""),
                                                  ("d", "3"), ("was-3", "2|0"), ("bu-3", "2"), ("ign-3", "1"),
                                                  ("d", "6"), ("was-6", "3|0"), ("bu-6", "999")])
    assert r.status == 303 and "show=unmapped" in dict(r.headers)["Location"]
    assert conn.writes("UPDATE cz.Developer SET BusinessUnitId") == [(1, False, 4), (2, True, 3), (None, False, 6)]


def test_apply_sets_sure_suggestions_only():
    conn = FakeConn()
    adm, sid = make_admin(conn)
    post(adm, sid, "/admin/developers/apply", [])
    assert sorted(conn.writes("UPDATE cz.Developer SET BusinessUnitId")) == [(1, 4), (2, 5)]


def test_suggestions_page_and_product_business_unit():
    conn = FakeConn()
    adm, sid = make_admin(conn)
    r = get(adm, sid, "/admin/developers/suggestions")
    assert r.status == 200 and "Products without a business unit" in r.body and "Warehouse" in r.body
    assert "common-auth" in r.body and "not assessed" in r.body
    assert "billing-api</a><div" not in r.body                # mapped: not listed
    post(adm, sid, "/admin/developers/product-bu", [("all", "1")])
    assert sorted(conn.writes("UPDATE cz.Product SET BusinessUnitId")) == [(2, 8), (3, 9)]
    post(adm, sid, "/admin/developers/product-bu", [("ProductId", "8"), ("BusinessUnitId", "1")])
    assert conn.writes("UPDATE cz.Product SET BusinessUnitId")[-1] == (1, 8)


def test_projects_page_and_changing_a_projects_product():
    conn = FakeConn()
    adm, sid = make_admin(conn)
    r = get(adm, sid, "/admin/developers/projects")
    assert r.status == 200 and "Automatic: a product named after the project" in r.body
    assert "waiting for its first assessed application" in r.body          # Shared
    post(adm, sid, "/admin/developers/project", [("ProjectId", "5"), ("Product", "7")])
    assert conn.writes("UPDATE cz.OrgProject SET ProductId = %s, ProductMappedAt = SYSUTCDATETIME()") == [(7, 5)]
    moved = conn.writes("UPDATE a SET ProductId = %s, ProductAutoAt")
    assert moved == [(7, 1, "Warehouse", 8)]                                # the ones mapped automatically follow
    post(adm, sid, "/admin/developers/project", [("ProjectId", "3"), ("Product", "auto")])
    assert conn.writes("UPDATE a SET ProductId = NULL, ProductAutoAt = NULL") == [(1, "Payroll", 9)]
    assert any(sql == "EXEC cz.AutoMapProjects" for sql, _ in conn.log)
    r = post(adm, sid, "/admin/developers/project", [("ProjectId", "3"), ("Product", "x")])
    assert "Choose" in dict(r.headers)["Location"] or "Choose" in r.body


def test_schema_has_the_tables_and_the_procedure():
    from pathlib import Path
    sql = (Path(__file__).resolve().parents[1] / "containerizer/sql/schema.sql").read_text()
    for x in ("CREATE TABLE [${schema}].Developer (", "CREATE TABLE [${schema}].DeveloperRepository (",
              "PROCEDURE [${schema}].AutoMapProjects", "GRANT EXECUTE ON [${schema}].AutoMapProjects TO [${schema}_writer]",
              "VALUES (50)"):
        assert x in sql
    assert json.dumps(ad.VIEWS)
