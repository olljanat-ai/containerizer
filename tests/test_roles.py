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
