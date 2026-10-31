"""Admin pages: OpenID Connect sign-in against a mock identity provider, authorization, CSRF, the
mapping forms, and the audit trail. The end-to-end test needs SQL Server (CONTAINERIZER_TEST_SQL)."""
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

from containerizer import admin as adminmod  # noqa: E402
from containerizer import oidc, sqlstore, webui  # noqa: E402
from containerizer.oidc import OidcConfig, OidcError, allowed  # noqa: E402

from test_engine import web_app  # noqa: E402

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class MockIdP:
    """Discovery, JWKS and a token endpoint that checks the PKCE verifier and client secret."""

    def __init__(self):
        self.codes: dict = {}
        self.claims: dict = {}
        self.tamper: dict = {}
        idp = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj, status=200):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    return self._json({"issuer": idp.issuer, "authorization_endpoint": idp.issuer + "/authorize",
                                       "token_endpoint": idp.issuer + "/token", "jwks_uri": idp.issuer + "/jwks",
                                       "id_token_signing_alg_values_supported": ["RS256"],
                                       "token_endpoint_auth_methods_supported": ["client_secret_basic"]})
                if self.path == "/jwks":
                    jwk = json.loads(RSAAlgorithm.to_jwk(KEY.public_key()))
                    return self._json({"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]})
                self._json({}, 404)

            def do_POST(self):
                form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                auth = base64.b64decode(self.headers.get("Authorization", "Basic ").split()[1]).decode()
                code = form["code"][0]
                c = idp.codes.pop(code, None)
                ch = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
                if not c or auth != "cz:s3cret" or ch != c["challenge"] or form["redirect_uri"][0] != c["redirect_uri"]:
                    return self._json({"error": "invalid_grant"}, 400)
                now = int(time.time())
                claims = {"iss": idp.issuer, "aud": "cz", "sub": "u1", "iat": now, "exp": now + 300,
                          "nonce": c["nonce"], **idp.claims, **idp.tamper}
                key = OTHER_KEY if idp.tamper.pop("_wrong_key", None) else KEY
                claims.pop("_wrong_key", None)
                tok = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})
                self._json({"access_token": "a", "token_type": "Bearer", "id_token": tok})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.issuer = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def authorize(self, url: str) -> str:
        """What the user's browser does at the provider: returns the redirect back to the app."""
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        assert q["code_challenge_method"] == ["S256"] and q["response_type"] == ["code"]
        code = os.urandom(8).hex()
        self.codes[code] = {"challenge": q["code_challenge"][0], "nonce": q["nonce"][0],
                            "redirect_uri": q["redirect_uri"][0]}
        return q["redirect_uri"][0] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"][0]})


@pytest.fixture(scope="module")
def idp():
    i = MockIdP()
    yield i
    i.httpd.shutdown()


def cfg(idp, public, admins=("group:cz-admins",), viewers=(), view_audit=False):
    c = OidcConfig(issuer=idp.issuer, client_id="cz", client_secret="s3cret", public_url=public, admins=list(admins),
                   viewers=list(viewers), view_audit=view_audit)
    c.check()
    return c


# ---------------------------------------------------------------------------
# configuration and authorization rules

def test_admin_rules():
    rules = ["group:g1", "role:Containerizer.Admin", "email:jane@contoso.com", "domain:fabrikam.com", "sub:abc"]
    assert allowed({"groups": ["g1"]}, rules)
    assert allowed({"roles": ["Containerizer.Admin"]}, rules)
    assert allowed({"email": "Jane@Contoso.com", "email_verified": True}, rules)
    assert not allowed({"email": "jane@contoso.com"}, rules)                     # not verified
    assert allowed({"email": "bob@fabrikam.com", "email_verified": True}, rules)
    assert not allowed({"email": "bob@evilfabrikam.com", "email_verified": True}, rules)
    assert allowed({"sub": "abc"}, rules)
    assert not allowed({"sub": "x", "groups": ["g2"]}, rules)


@pytest.mark.parametrize("env, msg", [
    ({"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com"}, "not set"),
    ({"CONTAINERIZER_OIDC_ISSUER": "http://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
      "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com", "CONTAINERIZER_ADMINS": "group:g"}, "https"),
    ({"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
      "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com", "CONTAINERIZER_ADMINS": "anyone"}, "unknown rule"),
])
def test_config_is_checked(env, msg):
    with pytest.raises(OidcError, match=msg):
        OidcConfig.from_env(env)
    assert OidcConfig.from_env({}) is None


BASE_ENV = {"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
            "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com", "CONTAINERIZER_ADMINS": "group:g"}


def test_viewer_config():
    assert OidcConfig.from_env(BASE_ENV).viewers == [] and not OidcConfig.from_env(BASE_ENV).view_audit
    c = OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_VIEWERS": "group:v, domain:contoso.com",
                             "CONTAINERIZER_VIEW_AUDIT": "true"})
    assert c.viewers == ["group:v", "domain:contoso.com"] and c.view_audit
    with pytest.raises(OidcError, match="needs CONTAINERIZER_VIEWERS"):
        OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_VIEW_AUDIT": "true"})
    with pytest.raises(OidcError, match="true or false"):
        OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_VIEWERS": "group:v", "CONTAINERIZER_VIEW_AUDIT": "maybe"})
    with pytest.raises(OidcError, match="CONTAINERIZER_VIEWERS: unknown rule"):
        OidcConfig.from_env({**BASE_ENV, "CONTAINERIZER_VIEWERS": "everyone"})


# ---------------------------------------------------------------------------
# token validation

def _login_claims(idp, tamper):
    c = cfg(idp, "http://127.0.0.1:1")
    p = oidc.Provider(c)
    s = oidc.Sessions()
    _, pend = s.begin("/admin")
    back = idp.authorize(p.authorize_url(pend["state"], pend["nonce"], pend["verifier"]))
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(back).query)["code"][0]
    idp.tamper = dict(tamper)
    try:
        tok = p.exchange(code, pend["verifier"])
        return p.validate(tok["id_token"], pend["nonce"])
    finally:
        idp.tamper = {}


def test_valid_token(idp):
    assert _login_claims(idp, {})["sub"] == "u1"


@pytest.mark.parametrize("tamper, msg", [
    ({"nonce": "other"}, "nonce"),
    ({"aud": "someone-else"}, "audience"),
    ({"iss": "https://evil.example.com"}, "issuer"),
    ({"exp": 1000}, "expired"),
    ({"_wrong_key": True}, "Signature"),
])
def test_bad_tokens_are_rejected(idp, tamper, msg):
    with pytest.raises(OidcError, match=f"(?i){msg}"):
        _login_claims(idp, tamper)


def test_unsigned_token_is_rejected(idp):
    c = cfg(idp, "http://127.0.0.1:1")
    p = oidc.Provider(c)
    now = int(time.time())
    tok = jwt.encode({"iss": idp.issuer, "aud": "cz", "sub": "u1", "iat": now, "exp": now + 60, "nonce": "n"},
                     None, algorithm="none")
    with pytest.raises(OidcError):
        p.validate(tok, "n")


# ---------------------------------------------------------------------------
# HTTP flow (no database needed up to the authorization decision)

class Browser:
    """Cookies + manual redirects, like a browser talking to the app and the provider."""

    def __init__(self, base: str, idp: MockIdP):
        self.base, self.idp = base, idp
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def go(self, url: str, data: dict | None = None, headers: dict | None = None):
        url = url if url.startswith("http") else self.base + url
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers=headers or {})
        try:
            r = self.opener.open(req, timeout=10)
            return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def follow(self, url: str, data: dict | None = None, headers: dict | None = None, hops: int = 6):
        status, h, body = self.go(url, data, headers)
        while status in (302, 303) and hops:
            loc = h["Location"]
            if loc.startswith(self.idp.issuer + "/authorize"):
                loc = self.idp.authorize(loc)
            status, h, body = self.go(loc)
            hops -= 1
        return status, h, body

    def csrf(self, body: str) -> str:
        return re.search(r"name='csrf' value='([^']+)'", body)[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def free_port() -> int:
    import socket
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def test_sign_in_flow_and_authorization(idp):
    port = free_port()
    base = f"http://127.0.0.1:{port}"

    def no_db():
        raise AssertionError("no database access before authorization")
    adm = adminmod.Admin(cfg(idp, base), no_db)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(no_db, adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        b = Browser(base, idp)
        s, h, _ = b.go("/admin/products")
        assert s == 303 and h["Location"].startswith("/login?next=%2Fadmin%2Fproducts")
        s, h, _ = b.go(h["Location"])
        assert s == 303 and h["Location"].startswith(idp.issuer + "/authorize")
        assert "HttpOnly" in h["Set-Cookie"] and "SameSite=Lax" in h["Set-Cookie"]
        # a callback with someone else's state is refused
        forged = idp.authorize(h["Location"]).replace("state=", "state=x")
        assert b.go(forged)[0] == 400
        # signed in, but not on the allow-list
        idp.claims = {"email": "eve@example.com", "name": "Eve", "groups": ["other"]}
        s, _, body = b.follow("/login?next=/admin/products")
        assert s == 403 and "not an administrator" in body and "eve@example.com" in body
        # the read-only pages still work without the database being touched for sign-in
        csrf = b.csrf(body)
        assert b.go("/logout", {"csrf": "wrong"})[0] == 303
        assert b.go("/logout", {"csrf": csrf}, {"Origin": "https://evil.example.com"})[0] == 303
        assert b.follow("/admin/products")[0] == 403            # still signed in: both were refused
        assert b.go("/logout", {"csrf": csrf})[0] == 303
        assert b.go("/admin/products")[0] == 303                 # signed out
        # open redirect after sign-in is not possible
        idp.claims = {"email": "eve@example.com", "groups": ["other"]}
        s, h, _ = b.go("/login?next=//evil.example.com/")
        back = idp.authorize(h["Location"])
        assert b.go(back)[1]["Location"] == "/admin"
    finally:
        idp.claims = {}
        httpd.shutdown()


def test_results_pages_need_sign_in_when_viewers_are_set(idp):
    port = free_port()
    base = f"http://127.0.0.1:{port}"

    def no_db():
        raise AssertionError("no database access before authorization")
    adm = adminmod.Admin(cfg(idp, base, viewers=["group:cz-viewers"]), no_db)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(no_db, adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        b = Browser(base, idp)
        # straight to the identity provider, no sign-in page in between
        for path in ("/", "/app/7", "/?bu=3", "/trends?range=3m"):
            s, h, _ = b.go(path)
            assert s == 303 and h["Location"].startswith(idp.issuer + "/authorize"), path
        assert b.go("/static/app.css")[0] == 200 and b.go("/healthz")[0] == 200
        # signed in, but neither a viewer nor an admin
        idp.claims = {"email": "eve@example.com", "groups": ["other"]}
        s, h, body = b.follow("/app/7")
        assert s == 403 and "not been given access" in body and "form-action 'self'" in h["Content-Security-Policy"]
        # sign-out shows a page instead of bouncing back to the provider
        s, _, body = b.go("/logout", {"csrf": b.csrf(body)})
        assert s == 200 and "signed out" in body
        # the page asked for is kept through the sign-in, the query string only for the business unit filter
        s, h, _ = b.go("/?bu=3&x=<script>")
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(h["Location"]).query)
        back = idp.authorize(h["Location"])
        assert b.go(back)[1]["Location"] == "/?bu=3" and q["response_type"] == ["code"]
    finally:
        idp.claims = {}
        httpd.shutdown()


# ---------------------------------------------------------------------------
# end to end with SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_admin_maps_and_audits(idp, tmp_path):
    import uuid
    name = "czadm_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL) + ";Schema=shared_cz"
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_a_reader", "reader"), ("cz_a_writer", "writer"), ("cz_a_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    from containerizer.assess import assess
    web_app(tmp_path / "shop")
    sqlstore.store_results(as_("cz_a_writer"), [assess(tmp_path / "shop")], [tmp_path / "shop"], password="Test-Passw0rd!x")

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    adm = adminmod.Admin(cfg(idp, base), lambda: sqlstore.connect(as_("cz_a_admin"), "Test-Passw0rd!x"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(
        lambda: sqlstore.connect(as_("cz_a_reader"), "Test-Passw0rd!x"), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    idp.claims = {"email": "jane@example.com", "name": "Jane Doe", "groups": ["cz-admins"]}
    try:
        b = Browser(base, idp)
        s, h, body = b.follow("/admin")
        assert s == 200 and "Application mapping" in body and "shop" in body and "Jane Doe" in body
        assert "form-action 'self'" in h["Content-Security-Policy"]
        csrf = b.csrf(body)
        # business unit, product with a product page link, then map the app
        assert b.go("/admin/business-units/new", {"csrf": csrf, "Name": "Retail", "Owner": "", "Description": ""})[0] == 303
        s, _, body = b.follow("/admin/products")
        bu = re.search(r"<option value='(\d+)'>Retail</option>", body)[1]
        s, _, body = b.follow("/admin/products/new", {"csrf": csrf, "Name": "Web shop", "BusinessUnitId": bu,
                                                      "InfoUrl": "javascript:alert(1)", "Owner": "", "Description": ""})
        assert "plain https" in body
        s, _, body = b.follow("/admin/products/new", {"csrf": csrf, "Name": "Web shop", "BusinessUnitId": bu,
                                                      "InfoUrl": "https://cmdb.example.com/products/42", "Owner": "Team A",
                                                      "Description": ""})
        assert s == 200 and "Saved." in body
        pid = re.search(r"<option value='(\d+)'>Web shop", b.follow("/admin/applications?show=all")[2])[1]
        app = re.search(r"name='app' value='(\d+)'", b.follow("/admin/applications")[2])[1]
        s, _, body = b.follow("/admin/applications/bulk", {"csrf": csrf, "app": [app], "ProductId": pid})
        assert "1 application(s) updated." in body
        # a browser posting from our own pages sends our Origin; anything else is refused even with the token
        assert b.go("/admin/business-units/new", {"csrf": csrf, "Name": "X", "Owner": "", "Description": ""},
                    {"Origin": base})[0] == 303
        for origin in ("null", "https://evil.example.com", base + ".evil.example.com"):
            assert b.go("/admin/business-units/new", {"csrf": csrf, "Name": "Y", "Owner": "", "Description": ""},
                        {"Origin": origin})[0] == 403
        # missing CSRF token: refused, nothing changes
        assert b.go(f"/admin/applications/{app}", {"ProductId": "", "DisplayName": "x"})[0] == 403
        s, _, body = b.follow(f"/admin/applications/{app}", {"csrf": csrf, "ProductId": pid, "DisplayName": "Web Shop",
                                                              "Owner": "", "Description": ""})
        assert "Saved." in body and "Jane Doe" in body and "Web shop" in body      # its change history
        # results pages show the mapping and the product page link
        body = b.follow("/")[2]
        assert "Retail" in body and "Web Shop" in body and "https://cmdb.example.com/products/42" in body
        # the change history names who changed what
        body = b.follow("/admin/audit")[2]
        assert body.count("Jane Doe") >= 4 and "<del>(empty)</del> → <ins>Web shop</ins>" in body
        assert "Found by a scan" in body
        # a product still in use cannot be deleted
        s, _, body = b.follow(f"/admin/products/{pid}/delete", {"csrf": csrf})
        assert "To delete it" in body
    finally:
        idp.claims = {}
        httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()


# ---------------------------------------------------------------------------
# JSON API with bearer access tokens

def access_token(idp, aud="api://containerizer", key=None, **claims):
    now = int(time.time())
    c = {"iss": idp.issuer, "aud": aud, "sub": "svc-1", "azp": "automation", "iat": now, "exp": now + 300, **claims}
    return jwt.encode(c, key or KEY, algorithm="RS256", headers={"kid": "k1"})


def api_call(base, method, path, token=None, body=None, ctype="application/json"):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": ctype} if data is not None else {}
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=10)
        raw = r.read().decode()
        return r.status, dict(r.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, dict(e.headers), json.loads(raw) if raw else None


def _api_server(idp, connect_admin):
    from containerizer import api as apimod
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    adm = adminmod.Admin(cfg(idp, base), connect_admin)
    adm.api = apimod.Api(adm.provider, "api://containerizer", ["client:automation", "role:Containerizer.Write"],
                         connect_admin)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(connect_admin, adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return base, httpd


def test_api_authentication(idp):
    def no_db():
        raise AssertionError("no database access before authentication")
    base, httpd = _api_server(idp, no_db)
    try:
        s, h, b = api_call(base, "GET", "/api/v1/products")
        assert s == 401 and h["WWW-Authenticate"].startswith("Bearer") and b["error"] == "invalid_request"
        assert api_call(base, "GET", "/api/v1/products", "not-a-jwt")[0] == 401
        assert api_call(base, "GET", "/api/v1/products", access_token(idp, aud="cz"))[0] == 401      # an ID token's audience
        assert api_call(base, "GET", "/api/v1/products", access_token(idp, key=OTHER_KEY))[0] == 401
        assert api_call(base, "GET", "/api/v1/products", access_token(idp, exp=1000))[0] == 401
        s, _, b = api_call(base, "GET", "/api/v1/products", access_token(idp, azp="someone-else"))
        assert s == 403 and b["error"] == "insufficient_scope"
        # cookies do not authenticate the API
        req = urllib.request.Request(base + "/api/v1/products", headers={"Cookie": "cz_session=x"})
        with pytest.raises(urllib.error.HTTPError) as ex:
            urllib.request.urlopen(req, timeout=10)
        assert ex.value.code == 401
    finally:
        httpd.shutdown()


@needs_sql
def test_api_updates_are_audited(idp, tmp_path):
    import uuid
    name = "czapi_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_p_writer", "writer"), ("cz_p_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    from containerizer.assess import assess
    for app in ("billing", "ledger"):
        web_app(tmp_path / app)
    sqlstore.store_results(as_("cz_p_writer"), [assess(tmp_path / a) for a in ("billing", "ledger")],
                           [tmp_path / "billing", tmp_path / "ledger"], password="Test-Passw0rd!x")
    base, httpd = _api_server(idp, lambda: sqlstore.connect(as_("cz_p_admin"), "Test-Passw0rd!x"))
    tok = access_token(idp)
    try:
        s, _, bu = api_call(base, "POST", "/api/v1/business-units", tok, {"name": "Finance", "owner": "CFO office"})
        assert s == 201 and bu["name"] == "Finance"
        assert api_call(base, "POST", "/api/v1/business-units", tok, {"name": "Finance"})[0] == 409
        assert api_call(base, "POST", "/api/v1/products", tok, {"name": "Billing"}, ctype="text/plain")[0] == 415
        s, _, b = api_call(base, "POST", "/api/v1/products", tok, {"name": "Billing", "infoUrl": "javascript:x"})
        assert s == 400 and "https" in b["message"]
        assert api_call(base, "POST", "/api/v1/products", tok, {"name": "Billing", "rating": "A"})[0] == 400
        s, _, p = api_call(base, "POST", "/api/v1/products", tok, {"name": "Billing", "businessUnitId": bu["id"],
                                                                    "infoUrl": "https://cmdb.example.com/p/billing"})
        assert s == 201 and p["businessUnitName"] == "Finance"
        s, _, apps = api_call(base, "GET", "/api/v1/applications?unmapped=true", tok)
        assert sorted(a["name"] for a in apps["items"]) == ["billing", "ledger"] and apps["items"][0]["rating"]
        bid = next(a["id"] for a in apps["items"] if a["name"] == "billing")
        s, _, a = api_call(base, "PATCH", f"/api/v1/applications/{bid}", tok, {"productId": p["id"], "owner": "Team B"})
        assert s == 200 and a["productName"] == "Billing" and a["owner"] == "Team B"
        assert api_call(base, "PATCH", f"/api/v1/applications/{bid}", tok, {"name": "renamed"})[0] == 400   # scan-owned
        assert api_call(base, "PATCH", "/api/v1/applications/999999", tok, {"owner": "x"})[0] == 404
        assert api_call(base, "PATCH", f"/api/v1/applications/{bid}", tok, {"productId": 999999})[0] == 409
        assert api_call(base, "DELETE", f"/api/v1/products/{p['id']}", tok)[0] == 409                    # still in use
        assert api_call(base, "POST", "/api/v1/applications", tok, {"displayName": "x"})[0] == 405
        assert [x["name"] for x in api_call(base, "GET", "/api/v1/applications?unmapped=true", tok)[2]["items"]] == ["ledger"]
        # a user's delegated token is recorded with the user's identity
        utok = access_token(idp, email="jane@example.com", name="Jane Doe", azp="other", roles=["Containerizer.Write"])
        assert api_call(base, "PATCH", f"/api/v1/products/{p['id']}", utok, {"owner": "Jane"})[0] == 200
        s, _, log = api_call(base, "GET", "/api/v1/audit?limit=10", tok)
        items = log["items"]
        assert items[0]["changedBy"] == "jane@example.com" and items[0]["via"] == "API"
        assert items[0]["oldValues"]["Owner"] is None and items[0]["newValues"]["Owner"] == "Jane"
        app_change = next(i for i in items if i["tableName"] == "Application" and i["action"] == "update")
        assert app_change["changedBy"] == "client:automation" and app_change["via"] == "API"
        assert app_change["newValues"]["Product"] == "Billing" and app_change["dbLogin"] == "cz_p_admin"
    finally:
        httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()


@needs_sql
def test_viewer_sign_in_and_access_log(idp, tmp_path):
    import uuid
    name = "czview_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_v_reader", "reader"), ("cz_v_writer", "writer"), ("cz_v_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    from containerizer.assess import assess
    web_app(tmp_path / "shop")
    sqlstore.store_results(as_("cz_v_writer"), [assess(tmp_path / "shop")], [tmp_path / "shop"], password="Test-Passw0rd!x")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    adm = adminmod.Admin(cfg(idp, base, viewers=["group:cz-viewers"], view_audit=True),
                         lambda: sqlstore.connect(as_("cz_v_admin"), "Test-Passw0rd!x"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(
        lambda: sqlstore.connect(as_("cz_v_reader"), "Test-Passw0rd!x"), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        viewer = Browser(base, idp)
        idp.claims = {"email": "bob@example.com", "name": "Bob Viewer", "groups": ["cz-viewers"]}
        s, _, body = viewer.follow("/")
        assert s == 200 and "shop" in body and "Bob Viewer" in body and "Sign out" in body
        app = re.search(r"href='/app/(\d+)'", body)[1]
        assert viewer.follow(f"/app/{app}")[0] == 200
        assert viewer.follow("/?bu=none")[0] == 200
        assert viewer.follow("/trends?range=all&x=1")[0] == 200
        assert viewer.follow("/admin/access")[0] == 403              # a viewer is not an admin
        assert viewer.go("/logout", {"csrf": viewer.csrf(viewer.follow("/")[2])})[0] == 200
        outsider = Browser(base, idp)
        idp.claims = {"email": "eve@example.com", "name": "Eve", "groups": ["other"]}
        assert outsider.follow("/")[0] == 403
        boss = Browser(base, idp)
        idp.claims = {"email": "jane@example.com", "name": "Jane Admin", "groups": ["cz-admins"]}
        assert boss.follow("/")[0] == 200                            # admins see the results without being viewers
        s, _, body = boss.follow(f"/admin/access?app={app}")
        assert s == 200 and "Bob Viewer" in body and "Jane Admin" not in body.split("<tbody>")[1]
        s, _, body = boss.follow("/admin/access")
        assert "Sign-in refused" in body and "eve@example.com" in body and "Signed out" in body
        assert "Overview, one business unit" in body and "127.0.0.1" in body
        c = sqlstore.connect(cs)
        cur = c.cursor(as_dict=True)
        cur.execute("SELECT UserName, Event, Path, ApplicationId FROM containerizer.AccessLog ORDER BY AccessId")
        log = [(r["UserName"], r["Event"], r["Path"], r["ApplicationId"]) for r in cur.fetchall()]
        c.close()
        assert log[:7] == [("bob@example.com", "sign-in", None, None), ("bob@example.com", "view", "/", None),
                           ("bob@example.com", "view", f"/app/{app}", int(app)), ("bob@example.com", "view", "/?bu=none", None),
                           ("bob@example.com", "view", "/trends?range=all", None), ("bob@example.com", "view", "/", None),
                           ("bob@example.com", "sign-out", None, None)]
        assert ("eve@example.com", "sign-in refused", None, None) in log
        assert not any(u == "eve@example.com" and ev == "view" for u, ev, _, _ in log)
        # the log is append-only for the web UI's login, and other logins cannot write it
        a = sqlstore.connect(as_("cz_v_admin"), "Test-Passw0rd!x")
        for stmt in ("UPDATE cz.AccessLog SET UserName = N'x'", "DELETE cz.AccessLog"):
            with pytest.raises(Exception, match="(?i)permission"):
                a.cursor().execute(stmt)
        a.close()
        r = sqlstore.connect(as_("cz_v_reader"), "Test-Passw0rd!x")
        with pytest.raises(Exception, match="(?i)permission"):
            r.cursor().execute("INSERT cz.AccessLog (UserName, Event) VALUES (N'x', N'view')")
        r.close()
    finally:
        idp.claims = {}
        httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()
