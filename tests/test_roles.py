"""Roles: viewer, product owner (scoped), operator, admin (containerizer/roles.py). The end-to-end
tests through the admin pages and the API need SQL Server (CONTAINERIZER_TEST_SQL)."""
import os
import re
import threading
from http.server import ThreadingHTTPServer

import pytest

pytest.importorskip("jwt")
from containerizer import admin as adminmod  # noqa: E402
from containerizer import sqlstore, webui  # noqa: E402
from containerizer.appliance import SystemPage  # noqa: E402
from containerizer.oidc import OidcConfig, OidcError  # noqa: E402
from containerizer.roles import Access, owner_scopes, parse_owners, role_label  # noqa: E402

from test_admin import Browser, access_token, api_call, cfg, free_port, idp  # noqa: E402,F401
from test_engine import web_app  # noqa: E402

BASE_ENV = {"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
            "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com", "CONTAINERIZER_ADMINS": "group:g"}


def test_product_owner_config():
    owners = parse_owners("role:Finance.Owner = bu:Finance ; group:g1, email:bo@x.com=product:Billing, product:#12")
    assert owners == [(["role:Finance.Owner"], ["bu:Finance"]), (["group:g1", "email:bo@x.com"], ["product:Billing", "product:#12"])]
    assert parse_owners("") == [] and parse_owners(None) == []
    for bad, msg in (("role:x", "<rules>=<scopes>"), ("role:x=team:Finance", "unknown scope"), ("anyone=bu:x", "unknown rule"),
                     ("=bu:x", "<rules>=<scopes>"), ("role:x=bu:#abc", "unknown scope")):
        with pytest.raises(OidcError, match=msg):
            parse_owners(bad)
    c = OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_OPERATORS": "role:Ops", "CONTAINERIZER_PRODUCT_OWNERS": "role:F=bu:Finance"})
    assert c.operators == ["role:Ops"] and c.owners == [(["role:F"], ["bu:Finance"])]
    with pytest.raises(OidcError, match="CONTAINERIZER_OPERATORS: unknown rule"):
        OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_OPERATORS": "ops"})


def test_owner_scopes_and_labels():
    owners = parse_owners("role:F=bu:Finance; role:B=product:Billing,bu:Finance")
    assert owner_scopes({"roles": ["F", "B"]}, owners) == ["bu:Finance", "product:Billing"]
    assert owner_scopes({"roles": ["other"]}, owners) == []
    assert role_label(True, True, ["bu:x"]) == "admin"
    assert role_label(False, True, ["bu:x"]) == "operator, product owner"
    assert role_label(False, False, []) == ""


def test_access_rules():
    admin = Access(admin=True)
    bu_owner = Access(admin=False, bus={1}, products={10, 11})        # business unit 1 with products 10 and 11
    p_owner = Access(admin=False, products={20})                      # just product 20 (in business unit 2)
    op = Access(admin=False, operator=True)
    assert admin.maps and bu_owner.maps and p_owner.maps and not op.maps
    # applications: pick up unmapped ones, move and unmap their own, never touch others'
    assert bu_owner.can_map(None, 10) and bu_owner.can_map(10, 11) and bu_owner.can_map(10, None)
    assert not bu_owner.can_map(20, 10) and not bu_owner.can_map(10, 20) and not bu_owner.can_map(None, 20)
    assert not op.can_map(None, None) and not op.can_edit_app(None)
    assert bu_owner.can_edit_app(10) and not bu_owner.can_edit_app(None) and not bu_owner.can_edit_app(20)
    # products
    assert bu_owner.can_create_product(1) and not bu_owner.can_create_product(2) and not bu_owner.can_create_product(None)
    assert not p_owner.can_create_product(2) and not p_owner.can_delete_product(2)
    assert p_owner.can_edit_product(20) and p_owner.can_set_bu(2, 2) and not p_owner.can_set_bu(2, 1)
    assert not p_owner.can_set_bu(2, None) and not bu_owner.can_set_bu(1, None) and not bu_owner.can_set_bu(1, 2)
    assert bu_owner.can_delete_product(1) and not bu_owner.can_edit_bu()
    assert admin.can_set_bu(1, None) and admin.can_edit_bu() and admin.can_map(20, None)


ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_roles_end_to_end(idp, tmp_path):  # noqa: F811
    import uuid
    from containerizer import api as apimod
    from containerizer.assess import assess
    name = "czroles_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_r_reader", "reader"), ("cz_r_writer", "writer"), ("cz_r_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    cur = conn.cursor()
    cur.execute("INSERT containerizer.BusinessUnit (Name) VALUES (N'Finance'), (N'Operations')")
    cur.execute("INSERT containerizer.Product (Name, BusinessUnitId) SELECT N'Billing', BusinessUnitId FROM containerizer.BusinessUnit "
                "WHERE Name = N'Finance' UNION ALL SELECT N'Freight', BusinessUnitId FROM containerizer.BusinessUnit WHERE Name = N'Operations'")
    conn.commit()
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    for app in ("billing", "freight", "ledger"):
        web_app(tmp_path / app)
    sqlstore.store_results(as_("cz_r_writer"), [assess(tmp_path / x) for x in ("billing", "freight", "ledger")],
                           [tmp_path / x for x in ("billing", "freight", "ledger")], password="Test-Passw0rd!x")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    c = cfg(idp, base)
    c.operators = ["role:Ops"]
    c.owners = parse_owners("role:Finance.Owner=bu:Finance; role:Freight.Owner=product:Freight")
    connect_admin = lambda: sqlstore.connect(as_("cz_r_admin"), "Test-Passw0rd!x")  # noqa: E731
    adm = adminmod.Admin(c, connect_admin)
    sysdir = tmp_path / "system"                       # as on the appliance: the System and Firewall pages
    (sysdir / "requests").mkdir(parents=True)
    (sysdir / "status.json").write_text('{"version": "v1.0.0", "image": "ghcr.io/x/y", "snapshots": [], '
                                        '"egress": {"mode": "enforce", "rules": [], "system_rules": []}}')
    adm.system = SystemPage(status_dir=sysdir, fetch_tags=lambda image: ["v1.0.0"])
    adm.api = apimod.Api(adm.provider, "api://containerizer", ["client:automation"], connect_admin,
                         c.admins, c.operators, c.owners)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(
        lambda: sqlstore.connect(as_("cz_r_reader"), "Test-Passw0rd!x"), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        # -- operator: organization scans, repositories and change history, no mapping
        op = Browser(base, idp)
        idp.claims = {"email": "olga@example.com", "name": "Olga Ops", "roles": ["Ops"]}
        s, _, body = op.follow("/admin")
        assert s == 200 and "Change history" in body and "operator" in body and "href='/admin/applications'" not in body
        for path in ("/admin/applications", "/admin/products", "/admin/business-units", "/admin/access"):
            assert op.follow(path)[0] == 403, path
        assert op.go("/admin/applications/bulk", {"csrf": op.csrf(body), "app": ["1"], "ProductId": ""})[0] == 403
        assert op.follow("/")[0] == 200
        # operators tag applications on their results page; everyone filters the front page by the tags
        assert ">billing</a>" not in op.follow("/")[2]          # not mapped to a product yet: administrators only
        a_ = connect_admin()
        cr_ = a_.cursor()
        cr_.execute("SELECT ApplicationId FROM cz.Application WHERE Name = N'billing'")
        tag_app = str(cr_.fetchone()[0])
        a_.close()
        s, _, page = op.follow(f"/app/{tag_app}")
        assert "action='/admin/tags/" in page
        # the results page links to the admin pages operators may open, not to the application's settings
        assert "class='adminlinks small'" in page and "href='/admin/refactoring'>Refactoring orders</a>" in page
        assert f"href='/admin/applications/{tag_app}'" not in page
        assert op.go(f"/admin/tags/{tag_app}", {"Tags": "pci"})[0] == 403                     # no CSRF token
        s, _, page = op.follow(f"/admin/tags/{tag_app}", {"csrf": op.csrf(page), "Tags": "PCI, wave 1, pci"})
        assert s == 200 and "Tags saved." in page and "<a class='tag' href='/?tag=PCI'>PCI</a>" in page
        assert "Not saved" in op.follow(f"/admin/tags/{tag_app}", {"csrf": op.csrf(page), "Tags": "<b>"})[2]
        s, _, page = op.follow(f"/app/{tag_app}")
        assert "<a class='tag' href='/?tag=PCI'>PCI</a>" in page              # the filter: tests/test_tags.py
        for path in ("/admin/scans", "/admin/repositories", "/admin/scans/new"):
            s, _, page = op.follow(path)
            assert s == 200 and "href='/admin/scans'" in page, path
        # the appliance's System and Firewall pages are for administrators only
        assert "href='/admin/system'" not in body and "href='/admin/firewall'" not in body
        for path in ("/admin/system", "/admin/firewall"):
            assert op.follow(path)[0] == 403, path
        assert op.go("/admin/firewall", {"csrf": op.csrf(body), "do": "add", "target": "evil.example", "ports": "443"})[0] == 403
        assert not list((sysdir / "requests").glob("*.json"))
        # -- product owner of the Finance business unit
        fo = Browser(base, idp)
        idp.claims = {"email": "fiona@example.com", "name": "Fiona Finance", "roles": ["Finance.Owner"]}
        s, _, body = fo.follow("/admin/applications")
        assert s == 200 and "product owner: bu:Finance" in body and "href='/admin/business-units'" not in body
        assert "href='/admin/scans'" not in body
        for path in ("/admin/scans", "/admin/repositories", "/admin/scans/new"):
            assert fo.follow(path)[0] == 403, path
        csrf = fo.csrf(body)
        ids = {n: re.search(rf"value='(\d+)' id='a\d+' aria-label='Select {n}'", body)[1] for n in ("billing", "freight", "ledger")}
        prods = dict((n, i) for i, n in re.findall(r"<option value='(\d+)'>(\w+)", body))
        assert set(prods) == {"Billing"}                                   # only their products to pick
        s, _, body = fo.follow("/admin/applications/bulk", {"csrf": csrf, "app": [ids["billing"], ids["ledger"]],
                                                            "ProductId": prods["Billing"]})
        assert "2 application(s) updated." in body
        # someone else's product: refused, nothing changes
        freight_pid = None
        a = connect_admin()
        cr = a.cursor(as_dict=True)
        cr.execute("SELECT ProductId FROM cz.Product WHERE Name = N'Freight'")
        freight_pid = cr.fetchone()["ProductId"]
        a.close()
        s, _, body = fo.follow("/admin/applications/bulk", {"csrf": csrf, "app": [ids["freight"]], "ProductId": str(freight_pid)})
        assert "Not saved" in body
        s, _, body = fo.follow(f"/admin/applications/{ids['ledger']}", {"csrf": csrf, "ProductId": prods["Billing"],
                                                                         "DisplayName": "General Ledger", "Owner": "Team L",
                                                                         "Description": ""})
        assert "Saved." in body and "as product owner" in body
        # a new product in their business unit, but not in somebody else's
        s, _, body = fo.follow("/admin/products")
        assert "(view only)" in body and "Freight" in body
        bus = dict((n, i) for i, n in re.findall(r"<option value='(\d+)'>(\w+)</option>", body))
        assert set(bus) == {"Finance"}
        s, _, body = fo.follow("/admin/products/new", {"csrf": csrf, "Name": "Payroll", "BusinessUnitId": bus["Finance"],
                                                       "InfoUrl": "", "Owner": "", "Description": ""})
        assert "Saved." in body
        assert "Not saved" in fo.follow(f"/admin/products/{freight_pid}", {"csrf": csrf, "Name": "Freight 2", "BusinessUnitId": "",
                                                                          "InfoUrl": "", "Owner": "", "Description": ""})[2]
        assert "Not saved" in fo.follow("/admin/products/new", {"csrf": csrf, "Name": "Nope", "BusinessUnitId": "",
                                                                 "InfoUrl": "", "Owner": "", "Description": ""})[2]
        assert fo.follow("/admin/business-units")[0] == 403
        # tags are for administrators and operators: no editor, and a post is refused
        assert "action='/admin/tags/" not in fo.follow(f"/app/{ids['billing']}")[2]
        # a product owner's results page links to the settings of their own application only
        assert f"href='/admin/applications/{ids['billing']}'>Application settings</a>" in fo.follow(f"/app/{ids['billing']}")[2]
        assert f"href='/admin/applications/{ids['freight']}'" not in fo.follow(f"/app/{ids['freight']}")[2]
        assert f"href='/app/{ids['billing']}' title='Its results page'>results</a>" in fo.follow("/admin/applications?show=all")[2]
        assert fo.go(f"/admin/tags/{ids['billing']}", {"csrf": csrf, "Tags": "x"})[0] == 403
        assert "Not deleted" in fo.follow(f"/admin/products/{freight_pid}/delete", {"csrf": csrf})[2]
        s, _, body = fo.follow(f"/admin/products/{freight_pid}")
        assert "you can only look at it" in body and "Delete" not in body
        # -- product owner of a single product, through the API with a delegated token
        tok = access_token(idp, email="fred@example.com", name="Fred Freight", azp="other", roles=["Freight.Owner"])
        s, _, b = api_call(base, "PATCH", f"/api/v1/applications/{ids['freight']}", tok, {"productId": freight_pid, "owner": "Fred"})
        assert s == 200 and b["productName"] == "Freight"
        assert api_call(base, "PATCH", f"/api/v1/applications/{ids['billing']}", tok, {"owner": "x"})[0] == 403
        assert api_call(base, "PATCH", f"/api/v1/products/{freight_pid}", tok, {"infoUrl": "https://cmdb.example.com/f"})[0] == 200
        assert api_call(base, "PATCH", f"/api/v1/products/{freight_pid}", tok, {"businessUnitId": int(bus["Finance"])})[0] == 403
        assert api_call(base, "POST", "/api/v1/products", tok, {"name": "X", "businessUnitId": int(bus["Finance"])})[0] == 403
        assert api_call(base, "POST", "/api/v1/business-units", tok, {"name": "X"})[0] == 403
        assert api_call(base, "GET", "/api/v1/applications", tok)[0] == 200            # reads everything
        # operators read through the API, never write
        otok = access_token(idp, email="olga@example.com", azp="other", roles=["Ops"])
        assert api_call(base, "GET", "/api/v1/products", otok)[0] == 200
        s, _, b = api_call(base, "PATCH", f"/api/v1/products/{freight_pid}", otok, {"owner": "x"})
        assert s == 403 and b["error"] == "forbidden"
        assert api_call(base, "GET", "/api/v1/products", access_token(idp, azp="other", roles=["nothing"]))[0] == 403
        # -- the change history records the role
        s, _, log = api_call(base, "GET", "/api/v1/audit?limit=50", access_token(idp))
        roles = {(i["changedBy"], i["changedByRole"]) for i in log["items"]}
        assert ("fiona@example.com", "product owner") in roles and ("fred@example.com", "product owner") in roles
        assert all(i["changedByRole"] is None for i in log["items"] if i["via"] == "scan")
        body = fo.follow("/admin/audit")[2]
        assert "admin UI as product owner" in body and "API as product owner" in body
        ad = Browser(base, idp)
        idp.claims = {"email": "ada@example.com", "name": "Ada Admin", "groups": ["cz-admins"]}
        s, _, body = ad.follow("/admin/system")
        assert s == 200 and "href='/admin/firewall'" in body and "v1.0.0 is the newest release" in body
        s, _, body = ad.follow("/admin/firewall", {"csrf": ad.csrf(body), "do": "add", "target": "api.nuget.org",
                                                   "ports": "443"})
        assert s == 200 and len(list((sysdir / "requests").glob("*.json"))) == 1
    finally:
        idp.claims = {}
        httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()


@needs_sql
def test_ui_roles_end_to_end(idp, monkeypatch):  # noqa: F811
    """CONTAINERIZER_ROLE_SOURCE=ui: an administrator gives roles on Admin -> Users and roles; a pending e-mail binds
    to the subject at the first verified sign-in; a removed role is gone at the next request; the table, its
    trigger and its grants."""
    import uuid
    from containerizer import api as apimod
    monkeypatch.setattr(adminmod, "ROLE_REFRESH", 0)
    name = "czui_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)                         # idempotent
    for login, role in (("cz_u_reader", "reader"), ("cz_u_writer", "writer"), ("cz_u_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    cur = conn.cursor()
    cur.execute("SELECT MAX(Version) FROM containerizer.SchemaVersion")
    assert cur.fetchone()[0] >= 46
    cur.execute("INSERT containerizer.BusinessUnit (Name) VALUES (N'Finance'), (N'Operations')")
    cur.execute("INSERT containerizer.Product (Name, BusinessUnitId) SELECT N'Billing', BusinessUnitId FROM containerizer.BusinessUnit "
                "WHERE Name = N'Finance' UNION ALL SELECT N'Freight', BusinessUnitId FROM containerizer.BusinessUnit WHERE Name = N'Operations'")
    conn.commit()
    cur.execute("SELECT Name, BusinessUnitId FROM containerizer.BusinessUnit")
    bus = dict(cur.fetchall())
    cur.execute("SELECT Name, ProductId FROM containerizer.Product")
    products = dict(cur.fetchall())
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    c = cfg(idp, base)
    c.role_source, c.viewers_ui = "ui", True
    c.check()
    connect_admin = lambda: sqlstore.connect(as_("cz_u_admin"), "Test-Passw0rd!x")  # noqa: E731
    adm = adminmod.Admin(c, connect_admin)
    adm.api = apimod.Api(adm.provider, "api://containerizer", [], connect_admin, c.admins, ui_roles=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(
        lambda: sqlstore.connect(as_("cz_u_reader"), "Test-Passw0rd!x"), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        # someone signs in before having any role: recorded, but the results pages are refused
        jane = Browser(base, idp)
        idp.claims = {"sub": "s-jane", "email": "jane.doe@example.com", "email_verified": True, "name": "Jane Doe"}
        s, _, body = jane.follow("/")
        assert s == 403 and "not been given access" in body
        # the administrator (from CONTAINERIZER_ADMINS) gives roles
        ad = Browser(base, idp)
        idp.claims = {"sub": "s-john", "email": "john.doe@example.com", "email_verified": True, "name": "John Doe",
                      "groups": ["cz-admins"]}
        s, _, body = ad.follow("/admin/users")
        assert s == 200 and "admin (from configuration)" in body and "Jane Doe" in body
        csrf = ad.csrf(body)
        jane_id = re.search(r"<option value='(\d+)'>Jane Doe", body)[1]
        assert "Not saved" in ad.follow("/admin/users/assign", {"csrf": csrf, "UserAccountId": jane_id, "Role": "admin"})[2]
        s, _, body = ad.follow("/admin/users/assign", {"csrf": csrf, "UserAccountId": jane_id, "Role": "product-owner",
                                                       "Scope": [f"bu:{bus['Finance']}"], "Note": "Finance lead"})
        assert "Saved: Jane Doe is now product owner" in body and "product owner: Finance (business unit)" in body
        # a pending e-mail for someone who has not signed in yet
        s, _, body = ad.follow("/admin/users/assign", {"csrf": csrf, "Email": "Sam.Roe@example.com", "Role": "operator"})
        assert "from their first sign-in" in body and "sam.roe@example.com" in body
        ad.follow("/admin/users/assign", {"csrf": csrf, "Email": "max.moe@example.com", "Role": "viewer"})
        # effective at Jane's next request, scopes by id
        s, _, body = jane.follow("/admin/applications")
        assert s == 200 and "product owner: bu:Finance" in body
        assert jane.follow("/")[0] == 200 and jane.follow("/admin/users")[0] == 403
        # the API: Jane's access token, by subject
        tok = access_token(idp, sub="s-jane", azp="other")
        assert api_call(base, "PATCH", f"/api/v1/products/{products['Billing']}", tok, {"owner": "Jane"})[0] == 200
        assert api_call(base, "PATCH", f"/api/v1/products/{products['Freight']}", tok, {"owner": "Jane"})[0] == 403
        assert api_call(base, "GET", "/api/v1/products", access_token(idp, sub="s-nobody", azp="other",
                                                                      email="jane.doe@example.com"))[0] == 403
        # Sam signs in with the verified address: the pending role binds to Sam's subject
        sam = Browser(base, idp)
        idp.claims = {"sub": "s-sam", "email": "sam.roe@example.com", "email_verified": True, "name": "Sam Roe"}
        s, _, body = sam.follow("/admin/scans")
        assert s == 200 and "operator" in body
        # someone else later gets the same address: no role (matched by subject only now)
        other = Browser(base, idp)
        idp.claims = {"sub": "s-new-sam", "email": "sam.roe@example.com", "email_verified": True, "name": "Sam Roe 2"}
        assert other.follow("/admin/scans")[0] == 403
        # an unverified address binds nothing
        mx = Browser(base, idp)
        idp.claims = {"sub": "s-max", "email": "max.moe@example.com", "email_verified": False, "name": "Max Moe"}
        assert mx.follow("/")[0] == 403
        # removing a role: gone at the next request
        body = ad.follow("/admin/users")[2]
        rid = re.search(r"name='RoleAssignmentId' value='(\d+)'><button class='link' aria-label='Remove product owner: Finance", body)[1]
        assert "Removed" in ad.follow("/admin/users/remove", {"csrf": csrf, "RoleAssignmentId": rid})[2]
        assert jane.follow("/admin/applications")[0] == 403 and jane.follow("/")[0] == 403
        assert api_call(base, "PATCH", f"/api/v1/products/{products['Billing']}", tok, {"owner": "x"})[0] == 403
        # the change history names the administrator; the binding names the person who signed in
        a_ = connect_admin()
        cr = a_.cursor(as_dict=True)
        cr.execute("SELECT ChangedBy, ChangedByRole, Action, RowName, OldValues, NewValues FROM cz.AuditLog "
                   "WHERE TableName = N'RoleAssignment' ORDER BY AuditId")
        log = cr.fetchall()
        assert [(r["ChangedBy"], r["Action"]) for r in log] == [
            ("john.doe@example.com", "insert"), ("john.doe@example.com", "insert"), ("john.doe@example.com", "insert"),
            ("sam.roe@example.com", "update"), ("john.doe@example.com", "delete")]
        assert log[0]["ChangedByRole"] == "admin" and log[0]["RowName"] == "jane.doe@example.com: product-owner"
        assert '"BusinessUnit":"Finance"' in log[0]["NewValues"] and '"Note":"Finance lead"' in log[0]["NewValues"]
        assert '"User":"sam.roe@example.com"' in log[3]["NewValues"] and log[3]["ChangedByRole"] == "sign-in"
        # the database refuses an admin role, and a product owner without a scope, even from the admin login
        cur_ = a_.cursor()
        for sql in ("INSERT cz.RoleAssignment (PendingEmail, Role) VALUES (N'x@example.com', N'admin')",
                    "INSERT cz.RoleAssignment (PendingEmail, Role) VALUES (N'x@example.com', N'product-owner')",
                    "INSERT cz.RoleAssignment (PendingEmail, Role) VALUES (N'not-an-address', N'viewer')",
                    "UPDATE cz.UserAccount SET Subject = N'stolen'"):
            with pytest.raises(Exception):
                cur_.execute(sql)
            a_.rollback()
        # deleting a product deletes its scopes (audited)
        cur_.execute("INSERT cz.RoleAssignment (PendingEmail, Role, ProductId) VALUES (N'x@example.com', N'product-owner', %s)",
                     (products["Freight"],))
        a_.commit()
        cur_.execute("DELETE cz.Product WHERE ProductId = %s", (products["Freight"],))
        a_.commit()
        cur_.execute("SELECT COUNT(*) FROM cz.RoleAssignment WHERE PendingEmail = N'x@example.com'")
        assert cur_.fetchone()[0] == 0
        cur_.execute("SELECT COUNT(*) FROM cz.AuditLog WHERE TableName = N'RoleAssignment' AND Action = N'delete'")
        assert cur_.fetchone()[0] == 2
        a_.close()
        # the reader and writer logins can neither read nor change them
        for login in ("cz_u_reader", "cz_u_writer"):
            x = sqlstore.connect(as_(login), "Test-Passw0rd!x")
            for sql in ("SELECT * FROM cz.RoleAssignment", "SELECT * FROM cz.UserAccount",
                        "INSERT cz.RoleAssignment (PendingEmail, Role) VALUES (N'y@example.com', N'viewer')"):
                with pytest.raises(Exception):
                    x.cursor().execute(sql)
                x.rollback()
            x.close()
    finally:
        idp.claims = {}
        httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()
