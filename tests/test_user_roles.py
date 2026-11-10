"""Users and roles on the admin pages (CONTAINERIZER_ROLE_SOURCE=ui): configuration, binding a pending e-mail to
the subject, roles read again on every request, the Admin -> Users and roles page and the API. Without a database:
a fake connection answers the queries. The end-to-end test against SQL Server is in tests/test_roles.py."""
from datetime import datetime

import pytest

from containerizer import admin as adminmod
from containerizer import admin_users, userroles
from containerizer.oidc import OidcConfig, OidcError

BASE_ENV = {"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
            "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com", "CONTAINERIZER_ADMINS": "group:g"}
UI_ENV = {**BASE_ENV, "CONTAINERIZER_ROLE_SOURCE": "ui"}


# -- configuration ----------------------------------------------------------------------------------

def test_env_mode_is_the_default_and_unchanged():
    c = OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_VIEWERS": "group:v"})
    assert c.role_source == "env" and not c.ui_roles and c.viewers_required
    assert not OidcConfig.from_env(BASE_ENV).viewers_required


def test_ui_mode_refuses_the_role_lists_of_the_environment():
    c = OidcConfig.from_env(UI_ENV)
    assert c.ui_roles and not c.viewers_required and c.admins == ["group:g"]
    # empty values are not set (the appliance's web.env has them empty)
    assert OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_OPERATORS": "", "CONTAINERIZER_VIEWERS": " "}).ui_roles
    with pytest.raises(OidcError, match="CONTAINERIZER_OPERATORS must not be set"):
        OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_OPERATORS": "role:Ops"})
    with pytest.raises(OidcError, match="CONTAINERIZER_PRODUCT_OWNERS and CONTAINERIZER_VIEWERS must not be set"):
        OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_PRODUCT_OWNERS": "role:F=bu:Finance", "CONTAINERIZER_VIEWERS": "group:v"})
    with pytest.raises(OidcError, match="not set: .*CONTAINERIZER_ADMINS"):            # admins stay required
        OidcConfig.from_env({k: v for k, v in UI_ENV.items() if k != "CONTAINERIZER_ADMINS"})
    with pytest.raises(OidcError, match="env or ui"):
        OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_ROLE_SOURCE": "database"})


def test_viewers_required_is_for_ui_mode():
    c = OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_VIEWERS_REQUIRED": "true", "CONTAINERIZER_VIEW_AUDIT": "true"})
    assert c.viewers_required and c.view_audit
    with pytest.raises(OidcError, match="CONTAINERIZER_VIEWERS_REQUIRED is for CONTAINERIZER_ROLE_SOURCE=ui"):
        OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_VIEWERS_REQUIRED": "true"})
    with pytest.raises(OidcError, match="needs CONTAINERIZER_VIEWERS_REQUIRED=true"):
        OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_VIEW_AUDIT": "true"})
    with pytest.raises(OidcError, match="true or false"):
        OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_VIEWERS_REQUIRED": "maybe"})


# -- binding a pending e-mail -----------------------------------------------------------------------

def test_binding_addresses_need_a_verified_email_when_the_provider_says():
    assert userroles.binding_addresses({"email": "Jane.Doe@Example.com", "email_verified": True}) == ["jane.doe@example.com"]
    assert userroles.binding_addresses({"email": "jane.doe@example.com", "email_verified": "true"}) == ["jane.doe@example.com"]
    assert userroles.binding_addresses({"email": "jane.doe@example.com", "email_verified": False}) == []
    # email_verified sent: the user name does not count instead
    assert userroles.binding_addresses({"email": "x@example.com", "email_verified": False,
                                        "preferred_username": "jane.doe@example.com"}) == []
    # no email_verified (Entra ID): what the audit log names the person by
    assert userroles.binding_addresses({"preferred_username": "John.Doe@example.com"}) == ["john.doe@example.com"]
    assert userroles.binding_addresses({"upn": "john.doe@example.com"}) == ["john.doe@example.com"]
    assert userroles.binding_addresses({"preferred_username": "jdoe"}) == []
    assert userroles.binding_addresses({"sub": "abc"}) == []


class FakeCursor:
    def __init__(self, conn, as_dict):
        self.conn, self.as_dict, self.rows, self.rowcount = conn, as_dict, [], 0

    def execute(self, sql, params=None):
        sql = " ".join(sql.split())
        self.conn.log.append((sql, params))
        rows, self.rowcount = self.conn.answer(sql, params)
        self.rows = rows if self.as_dict else [tuple(r.values()) for r in rows]

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    """Answers the queries of userroles.py and admin_users.py from lists of rows."""

    def __init__(self, users=(), assignments=(), bus=(), products=(), existing_account=None):
        self.users, self.assignments, self.bus, self.products = list(users), list(assignments), list(bus), list(products)
        self.existing_account = existing_account
        self.log, self.committed, self.closed, self.who = [], 0, 0, None

    def cursor(self, as_dict=False):
        return FakeCursor(self, as_dict)

    def answer(self, sql, params):
        if sql.startswith("SELECT UserAccountId FROM cz.UserAccount"):
            return ([{"UserAccountId": self.existing_account}] if self.existing_account else []), 0
        if sql.startswith("INSERT cz.UserAccount"):
            return [{"Id": 41}], 1
        if sql.startswith("SELECT r.Role, r.BusinessUnitId"):          # userroles.load
            return [r for r in self.assignments if r.get("UserAccountId") == params[0]], 0
        if sql.startswith("SELECT r.RoleAssignmentId"):                 # the page
            return self.assignments, 0
        if sql.startswith("SELECT UserAccountId, Email"):
            return self.users, 0
        if sql.startswith("SELECT COALESCE(DisplayName, Email), AdminAtSignIn"):
            return [{"N": u["DisplayName"], "A": u["AdminAtSignIn"]} for u in self.users if u["UserAccountId"] == params[0]], 0
        if sql.startswith("SELECT BusinessUnitId, Name FROM cz.BusinessUnit"):
            return self.bus, 0
        if sql.startswith("SELECT p.ProductId, p.Name"):
            return self.products, 0
        if sql.startswith("SELECT TOP"):                               # the change history
            return [], 0
        return [], 1

    def set_user(self, user, name=None, via="admin UI", role=None):
        self.who = (user, name, role)

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass

    def close(self):
        self.closed += 1


def test_sign_in_records_the_subject_and_binds_pending_roles_by_verified_email():
    conn = FakeConn()
    claims = {"iss": "https://login.example.com", "sub": "s-jane", "email": "Jane.Doe@example.com", "email_verified": True,
              "name": "Jane Doe"}
    assert userroles.sign_in(conn, claims, admin=False) == 41
    sqls = [s for s, _ in conn.log]
    assert sqls[0].startswith("SELECT UserAccountId FROM cz.UserAccount WITH (UPDLOCK, HOLDLOCK) WHERE Issuer = %s AND Subject = %s")
    assert conn.log[0][1] == ("https://login.example.com", "s-jane")
    assert conn.log[1][1] == ("https://login.example.com", "s-jane", "Jane.Doe@example.com", "Jane Doe", False)
    bind = next(p for s, p in conn.log if s.startswith("UPDATE cz.RoleAssignment SET UserAccountId"))
    assert bind == (41, "jane.doe@example.com") and conn.committed == 1
    # the pending row is cleared as it binds: later, only the subject matches
    assert "PendingEmail = NULL WHERE UserAccountId IS NULL" in next(s for s, _ in conn.log if s.startswith("UPDATE cz.RoleAssignment"))
    # a returning user: updated, and an unverified address binds nothing
    conn = FakeConn(existing_account=7)
    assert userroles.sign_in(conn, {**claims, "email_verified": False}, admin=True) == 7
    assert any(s.startswith("UPDATE cz.UserAccount SET") and p[-2:] == (True, 7) for s, p in conn.log)
    assert not any("RoleAssignment" in s for s, _ in conn.log)


def test_load_gives_scopes_by_id():
    conn = FakeConn(assignments=[
        {"UserAccountId": 3, "Role": "operator", "BusinessUnitId": None, "ProductId": None, "BusinessUnitName": None, "ProductName": None},
        {"UserAccountId": 3, "Role": "product-owner", "BusinessUnitId": 2, "ProductId": None, "BusinessUnitName": "Finance", "ProductName": None},
        {"UserAccountId": 3, "Role": "product-owner", "BusinessUnitId": None, "ProductId": 12, "BusinessUnitName": None, "ProductName": "Billing"},
        {"UserAccountId": 4, "Role": "viewer", "BusinessUnitId": None, "ProductId": None, "BusinessUnitName": None, "ProductName": None}])
    assert userroles.load(conn, 3) == (True, False, ["bu:#2", "product:#12"], ["bu:Finance", "product:Billing"])
    assert userroles.load(conn, 4) == (False, True, [], [])
    assert userroles.load(conn, None) == (False, False, [], [])


# -- roles read again on every request --------------------------------------------------------------

def _ui_admin(conn, viewers_required=True):
    c = OidcConfig.from_env({**UI_ENV, "CONTAINERIZER_VIEWERS_REQUIRED": "true" if viewers_required else "false"})
    return adminmod.Admin(c, lambda: conn, provider=object())


def test_a_removed_role_is_gone_at_the_next_request(monkeypatch):
    monkeypatch.setattr(adminmod, "ROLE_REFRESH", 0)
    row = {"UserAccountId": 5, "Role": "product-owner", "BusinessUnitId": None, "ProductId": 12,
           "BusinessUnitName": None, "ProductName": "Billing"}
    conn = FakeConn(assignments=[row])
    adm = _ui_admin(conn)
    sid = adm.sessions.create("jane.doe@example.com", "Jane Doe", False, False, False, ["product:#12"],
                              account=5, scope_names=["product:Billing"])
    headers = {"Cookie": f"{adm.cookie}={sid}"}
    s = adm.session(headers)
    assert s.scopes == ["product:#12"] and s.viewer and adm.nav(headers).startswith("<a href='/admin'>Admin</a>")
    conn.assignments = []                                   # an administrator removed the role
    s = adm.session(headers)
    assert s.scopes == [] and not s.viewer and not s.operator
    stop, _ = adm.gate(headers, "/", "")
    assert stop.status == 403 and "not been given access" in stop.body       # results need a role here
    r = adm.handle("GET", "/admin/applications", "", headers, b"")
    assert r.status == 403 and "not an administrator, operator or product owner" in r.body
    conn.assignments = [dict(row, Role="viewer", ProductId=None, ProductName=None)]
    assert adm.gate(headers, "/", "")[0] is None                               # a viewer again


def test_roles_are_read_once_for_the_lookups_of_one_page():
    conn = FakeConn()
    adm = _ui_admin(conn)
    sid = adm.sessions.create("jane.doe@example.com", "Jane Doe", False, account=5)
    headers = {"Cookie": f"{adm.cookie}={sid}"}
    adm.sessions.get(sid).roles_at = 0
    adm.nav(headers)
    adm.gate(headers, "/", "")
    assert conn.closed == 1


def test_administrators_need_no_lookup_and_env_mode_never_reads_roles():
    def no_db():
        raise AssertionError("no database access")
    adm = adminmod.Admin(OidcConfig.from_env(UI_ENV), no_db, provider=object())
    sid = adm.sessions.create("ada@example.com", "Ada", True, account=1)
    assert adm.session({"Cookie": f"{adm.cookie}={sid}"}).admin
    adm = adminmod.Admin(OidcConfig.from_env(BASE_ENV), no_db, provider=object())
    sid = adm.sessions.create("olga@example.com", "Olga", False, operator=True)
    assert adm.session({"Cookie": f"{adm.cookie}={sid}"}).operator


# -- the page ---------------------------------------------------------------------------------------

SEEN = datetime(2026, 11, 9, 8, 30)
USERS = [{"UserAccountId": 1, "Email": "john.doe@example.com", "DisplayName": "John Doe", "AdminAtSignIn": True,
          "FirstSeenAt": SEEN, "LastSignInAt": SEEN},
         {"UserAccountId": 2, "Email": "jane.doe@example.com", "DisplayName": "Jane Doe", "AdminAtSignIn": False,
          "FirstSeenAt": SEEN, "LastSignInAt": SEEN}]
ASSIGNED = [{"RoleAssignmentId": 10, "UserAccountId": 2, "PendingEmail": None, "Role": "product-owner", "BusinessUnitId": 3,
             "ProductId": None, "Note": "Finance lead", "AssignedBy": "john.doe@example.com", "AssignedAt": SEEN,
             "BusinessUnitName": "Finance", "ProductName": None},
            {"RoleAssignmentId": 11, "UserAccountId": None, "PendingEmail": "sam.roe@example.com", "Role": "operator",
             "BusinessUnitId": None, "ProductId": None, "Note": None, "AssignedBy": "john.doe@example.com", "AssignedAt": SEEN,
             "BusinessUnitName": None, "ProductName": None}]


def _page_conn():
    return FakeConn(users=USERS, assignments=ASSIGNED, bus=[{"BusinessUnitId": 3, "Name": "Finance"}],
                    products=[{"ProductId": 12, "Name": "Billing", "BusinessUnitName": "Finance"}])


def _signed_in(adm, admin=True, **kw):
    sid = adm.sessions.create("john.doe@example.com", "John Doe", admin, **kw)
    return {"Cookie": f"{adm.cookie}={sid}"}, adm.sessions.get(sid)


def test_users_page_lists_users_roles_and_the_forms():
    conn = _page_conn()
    adm = _ui_admin(conn, viewers_required=False)
    headers, s = _signed_in(adm)
    r = adm.handle("GET", "/admin/users", "", headers, b"")
    assert r.status == 200 and "<a class='chip on' href='/admin/users'>Users and roles</a>" in r.body
    assert "admin (from configuration)" in r.body and "product owner: Finance (business unit)" in r.body
    assert "sam.roe@example.com" in r.body and "Waiting for a first sign-in" in r.body
    assert "<option value='bu:3'>Finance</option>" in r.body and "<option value='product:12'>Billing · Finance</option>" in r.body
    assert "<option value='2'>Jane Doe · jane.doe@example.com</option>" in r.body
    assert "<option value='1'>" not in r.body                    # an administrator gets no roles here
    assert "value='admin'" not in r.body and r.body.count(f"name='csrf' value='{s.csrf}'") >= 4
    assert "are readable without sign-in" in r.body


def test_users_page_is_for_administrators_only():
    conn = _page_conn()
    adm = _ui_admin(conn)
    conn.assignments = [{"UserAccountId": 9, "Role": "operator", "BusinessUnitId": None, "ProductId": None,
                         "BusinessUnitName": None, "ProductName": None}]
    headers, s = _signed_in(adm, admin=False, operator=True, account=9)
    assert adm.handle("GET", "/admin/users", "", headers, b"").status == 403
    r = adm.handle("POST", "/admin/users/assign", "", headers,
                   f"csrf={s.csrf}&UserAccountId=9&Role=operator".encode())
    assert r.status == 403 and not any(sql.startswith("INSERT cz.RoleAssignment") for sql, _ in conn.log)
    assert "href='/admin/users'" not in adm.handle("GET", "/admin/audit", "", headers, b"").body


def _post(adm, headers, s, path, **form):
    from urllib.parse import urlencode
    return adm.handle("POST", path, "", headers, urlencode({"csrf": s.csrf, **form}, doseq=True).encode())


def test_assign_and_remove():
    conn = _page_conn()
    adm = _ui_admin(conn)
    headers, s = _signed_in(adm)
    # CSRF like every admin form
    assert adm.handle("POST", "/admin/users/assign", "", headers, b"csrf=x&UserAccountId=2&Role=viewer").status == 403
    for form, msg in (({"UserAccountId": "2", "Role": "admin"}, "CONTAINERIZER_ADMINS+only"),
                      ({"UserAccountId": "2", "Role": "owner"}, "choose+a+role"),
                      ({"UserAccountId": "2", "Email": "a@example.com", "Role": "viewer"}, "one+of+them"),
                      ({"Role": "viewer"}, "one+of+them"),
                      ({"Email": "not-an-address", "Role": "viewer"}, "not+an+e-mail"),
                      ({"UserAccountId": "2", "Role": "product-owner"}, "at+least+one"),
                      ({"UserAccountId": "1", "Role": "operator"}, "is+an+administrator")):
        r = _post(adm, headers, s, "/admin/users/assign", **form)
        assert r.status == 303 and msg in dict(r.headers)["Location"], form
    assert not any(sql.startswith("INSERT cz.RoleAssignment") for sql, _ in conn.log)
    r = _post(adm, headers, s, "/admin/users/assign", UserAccountId="2", Role="product-owner",
              Scope=["bu:3", "product:12", "team:4"], Note="Finance  lead")
    assert "Saved" in dict(r.headers)["Location"]
    inserts = [p for sql, p in conn.log if sql.startswith("INSERT cz.RoleAssignment")]
    assert [p[:6] for p in inserts] == [(2, None, "product-owner", 3, None, "Finance lead"),
                                        (2, None, "product-owner", None, 12, "Finance lead")]
    assert conn.who == ("john.doe@example.com", "John Doe", "admin")         # the change history names the administrator
    r = _post(adm, headers, s, "/admin/users/assign", Email="Sam.Roe@Example.com", Role="operator", Scope=["bu:3"])
    assert "first+sign-in" in dict(r.headers)["Location"]
    assert [p for sql, p in conn.log if sql.startswith("INSERT cz.RoleAssignment")][-1][:5] == (None, "sam.roe@example.com", "operator", None, None)
    r = _post(adm, headers, s, "/admin/users/remove", RoleAssignmentId="10")
    assert "Removed" in dict(r.headers)["Location"]
    assert ("DELETE cz.RoleAssignment WHERE RoleAssignmentId = %s", (10,)) in conn.log


def test_env_mode_page_is_read_only():
    conn = _page_conn()
    c = OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_OPERATORS": "role:Ops",
                             "CONTAINERIZER_PRODUCT_OWNERS": "role:F=bu:Finance,product:#12"})
    adm = adminmod.Admin(c, lambda: conn, provider=object())
    headers, s = _signed_in(adm)
    r = adm.handle("GET", "/admin/users", "", headers, b"")
    assert r.status == 200 and "CONTAINERIZER_ROLE_SOURCE=env" in r.body and "<code>role:Ops</code>" in r.body
    assert "<code>role:F</code> → <code>bu:Finance</code>, <code>product:#12</code>" in r.body
    assert "readable without sign-in" in r.body and "action='/admin/users/assign'" not in r.body
    r = _post(adm, headers, s, "/admin/users/assign", UserAccountId="2", Role="viewer")
    assert "come+from+the+environment" in dict(r.headers)["Location"]
    assert not any(sql.startswith("INSERT") for sql, _ in conn.log)


def test_scope_names_in_the_header():
    conn = FakeConn(assignments=[{"UserAccountId": 5, "Role": "product-owner", "BusinessUnitId": 3, "ProductId": None,
                                  "BusinessUnitName": "Finance", "ProductName": None}])
    adm = _ui_admin(conn)
    headers, s = _signed_in(adm, admin=False, account=5)
    s.roles_at = 0
    r = adm.handle("GET", "/admin/audit", "", headers, b"")
    assert r.status == 200 and "product owner: bu:Finance" in r.body and "Users and roles" not in r.body.split("<nav")[1][:400]


# -- the API ----------------------------------------------------------------------------------------

def test_api_user_tokens_get_their_roles_from_the_assignments():
    from containerizer import api as apimod
    conn = FakeConn(existing_account=5, assignments=[
        {"UserAccountId": 5, "Role": "product-owner", "BusinessUnitId": None, "ProductId": 12,
         "BusinessUnitName": None, "ProductName": "Billing"}])
    a = apimod.Api(object(), "api://cz", ["client:automation"], lambda: conn, ["group:admins"], ui_roles=True)
    iss = "https://login.example.com"
    assert a.roles({"iss": iss, "sub": "s-jane", "azp": "other"}) == (False, False, ["product:#12"], "product owner")
    assert conn.log[0][1] == (iss, "s-jane")
    conn.existing_account = None                              # an unknown subject: no role, whatever the e-mail says
    assert a.roles({"iss": iss, "sub": "s-other", "email": "jane.doe@example.com", "email_verified": True,
                    "azp": "other"}) == (False, False, [], "")
    # API clients and administrators are unchanged, and need no lookup
    n = len(conn.log)
    assert a.roles({"iss": iss, "sub": "x", "azp": "automation"})[3] == "API client"
    assert a.roles({"iss": iss, "sub": "x", "groups": ["admins"], "azp": "other"})[0] is True
    assert len(conn.log) == n
    # env mode ignores the database
    b = apimod.Api(object(), "api://cz", [], lambda: pytest.fail("no lookup"), ["group:admins"], ["role:Ops"])
    assert b.roles({"sub": "x", "roles": ["Ops"]}) == (False, True, [], "operator")
