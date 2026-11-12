"""External application IDs from metadata.json (appmeta.py) and Forget application (admin_forget.py)."""
from __future__ import annotations

import json
from datetime import datetime

from containerizer import appmeta
from containerizer import admin_forget  # noqa: F401 - imported by the admin routes
from test_developers import FakeConn as _Base, get, make_admin, post

GUID = "3f2b8c1e-5d6a-4b7c-9e0f-1a2b3c4d5e6f"


def test_read_metadata(tmp_path):
    assert appmeta.read_metadata(tmp_path) == ""
    (tmp_path / "metadata.json").write_text(json.dumps({"applicationId": "{" + GUID.upper() + "}"}))
    assert appmeta.read_metadata(tmp_path) == GUID.upper()
    (tmp_path / "metadata.json").write_text('﻿{"ApplicationID": "APP-0042"}')
    assert appmeta.read_metadata(tmp_path) == "APP-0042"
    for bad in ('{"applicationId": "a b"}', '{"applicationId": "<x>"}', "[1]", "not json", '{"applicationId": ""}',
                json.dumps({"applicationId": "x" * 101})):
        (tmp_path / "metadata.json").write_text(bad)
        assert appmeta.read_metadata(tmp_path) == "", bad
    (tmp_path / "metadata.json").unlink()
    (tmp_path / "metadata.json").symlink_to("/etc/hostname")
    assert appmeta.read_metadata(tmp_path) == ""


REPOS = [{"RepositoryId": 1, "ProjectName": "Finance", "Name": "billing-api", "WebUrl": "https://dev.azure.com/c/Finance/_git/b",
          "RepositoryUrl": "https://dev.azure.com/c/Finance/_git/billing-api", "ExternalAppId": GUID, "ScanName": "Contoso"},
         {"RepositoryId": 2, "ProjectName": "Shared", "Name": "common-auth", "WebUrl": None,
          "RepositoryUrl": "https://dev.azure.com/c/Shared/_git/common-auth", "ExternalAppId": "APP-7", "ScanName": "Contoso"}]
APPS = [{"ApplicationId": 21, "AppName": "billing-api", "RepositoryUrl": REPOS[0]["RepositoryUrl"], "SourcePath": ".",
         "ExternalId": None, "Retired": False}]


class Conn(_Base):
    def answer(self, sql, params):
        if sql.startswith("SELECT r.RepositoryId, r.ProjectName, r.Name, r.WebUrl, r.RepositoryUrl, r.ExternalAppId"):
            return REPOS, 0
        if sql.startswith("SELECT a.ApplicationId, COALESCE(a.DisplayName, a.Name) AS AppName, a.RepositoryUrl"):
            return APPS, 0
        if sql.startswith("SELECT ExternalAppId FROM cz.OrgRepository"):
            return [{"ExternalAppId": r["ExternalAppId"]} for r in REPOS if r["RepositoryId"] == params[0]], 0
        if sql.startswith("EXEC cz.AddRepositoryApplication"):
            return [{"ApplicationId": 99}], 1
        if sql.startswith("SELECT a.ApplicationId, a.Name, a.RepositoryUrl, d.StoredAs"):
            return [{"ApplicationId": 21, "Name": "billing-api", "RepositoryUrl": REPOS[0]["RepositoryUrl"], "StoredAs": None}], 0
        if sql.startswith("SELECT ScanId, ProjectName, Name FROM cz.OrgRepository"):
            return [{"ScanId": 1, "ProjectName": "Finance", "Name": "billing-api"}], 0
        if sql.startswith("EXEC cz.QueueOrgScanRun"):
            return [{"RunId": 5}], 1
        if sql.startswith("SELECT x.ApplicationId"):
            return [{"ApplicationId": 21, "Name": "billing-api", "DisplayName": None, "Description": None, "Owner": None,
                     "ProductId": None, "Retired": False, "RepositoryUrl": REPOS[0]["RepositoryUrl"], "SandboxEnabled": True,
                     "SourcePath": ".", "FirstSeenAt": datetime(2026, 11, 1), "LastSeenAt": datetime(2026, 11, 12),
                     "ProductName": None, "OutputRepo": None, "OutputBranch": None, "OutputPath": None,
                     "OutputMovedAt": None, "OutputMovedCommit": None, "OutputMoveError": None, "DeployMode": None,
                     "SandboxDebug": False, "ExternalId": None, "SourceKey": REPOS[0]["RepositoryUrl"] + "#"}], 0
        return super().answer(sql, params)


def test_external_ids_view_and_actions():
    conn = Conn()
    adm, sid = make_admin(conn)
    r = get(adm, sid, "/admin/applications?show=external")
    assert r.status == 200 and GUID in r.body and "Link to billing-api" in r.body and "Add application" in r.body
    assert "Link 1 proposal" in r.body
    post(adm, sid, "/admin/applications/external-link", [("all", "1")])
    assert conn.writes("UPDATE cz.Application SET ExternalId = %s WHERE ApplicationId = %s AND ExternalId IS NULL") == [(GUID, 21)]
    post(adm, sid, "/admin/applications/external-link", [("ApplicationId", "21"), ("ExternalId", "{" + GUID + "}")])
    assert conn.writes("UPDATE cz.Application SET ExternalId = %s WHERE ApplicationId = %s")[-1] == (GUID, 21)
    r = post(adm, sid, "/admin/applications/external-add", [("RepositoryId", "2")])
    assert dict(r.headers)["Location"].startswith("/admin/applications/99?")
    assert conn.writes("EXEC cz.AddRepositoryApplication") == [(2, "APP-7")]
    r = post(adm, sid, "/admin/applications/21/external-id", [("ExternalId", "bad id!")])
    assert "Not+saved" in dict(r.headers)["Location"]
    post(adm, sid, "/admin/applications/21/external-id", [("ExternalId", "")])
    assert conn.writes("UPDATE cz.Application SET ExternalId = %s WHERE ApplicationId = %s")[-1] == (None, 21)


def test_forget_needs_the_name_and_queues_the_repository():
    conn = Conn()
    adm, sid = make_admin(conn)
    page = get(adm, sid, "/admin/applications/21")
    assert "Forget application" in page.body and "External ID" in page.body
    r = post(adm, sid, "/admin/applications/21/forget", [("confirm", "billing")])
    assert "Not+forgotten" in dict(r.headers)["Location"] and not conn.writes("EXEC cz.ForgetApplication")
    r = post(adm, sid, "/admin/applications/21/forget", [("confirm", "billing-api")])
    assert conn.writes("EXEC cz.ForgetApplication") == [(21, "billing-api", "application billing-api forgotten by john.doe@example.com")]
    scope = json.loads(conn.writes("EXEC cz.QueueOrgScanRun")[0][1])
    assert scope == {"projects": [], "repositories": ["Finance/billing-api"]}
    assert "forgotten" in dict(r.headers)["Location"]


def test_scan_records_the_declared_id():
    from containerizer.org import RepoResult
    from containerizer.worker import SqlRepoStore
    conn = Conn()
    st = SqlRepoStore(conn, 1, 7)

    class R:
        project, name = "Finance", "billing-api"
    res = RepoResult(provider="azure-devops", org="c", project="Finance", repo="billing-api", status="deployed")
    st.record(R, res)                                          # not cloned: left as it was
    assert "ExternalAppId" not in conn.log[-1][0]
    res.external_app_id = GUID
    st.record(R, res)
    assert "ExternalAppId = %s" in conn.log[-1][0] and GUID in conn.log[-1][1]
    res.external_app_id = ""
    st.record(R, res)                                          # the file is gone: cleared
    assert None in conn.log[-1][1][-4:]


def test_forget_asks_the_system_agent_to_forget_the_openbao_entries():
    from types import SimpleNamespace
    calls, asked = [], []

    class Cur:
        def __init__(self, *a, **k):
            pass

        def execute(self, sql, args=()):
            calls.append(sql)

        def fetchone(self):
            return {"ApplicationId": 7, "Name": "shop", "RepositoryUrl": None, "StoredAs": None} \
                if "FROM cz.Application" in calls[-1] else [0]

        def fetchall(self):
            return []
    conn = SimpleNamespace(cursor=Cur, commit=lambda: None, rollback=lambda: None)
    system = SimpleNamespace(request=lambda action, user, name, **kw: asked.append((action, kw)))
    adm = SimpleNamespace(system=system, devdb=None)
    s = SimpleNamespace(user="john.doe@contoso.com", name="John Doe")
    admin_forget.forget(adm, conn, s, 7, {"confirm": ["shop"]})
    from containerizer.generate import app_ns
    assert asked == [("openbao-forget", {"namespace": app_ns("shop")})]
    assert any("ForgetApplication" in c for c in calls)
