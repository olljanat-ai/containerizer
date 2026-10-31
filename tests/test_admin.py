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


def cfg(idp, public, admins=("group:cz-admins",)):
    c = OidcConfig(issuer=idp.issuer, client_id="cz", client_secret="s3cret", public_url=public, admins=list(admins))
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
