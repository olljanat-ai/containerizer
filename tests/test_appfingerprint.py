"""tools/appfingerprint.py against a small application served on 127.0.0.1."""
import base64
import importlib.util
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

import pytest

spec = importlib.util.spec_from_file_location("appfingerprint",
                                              Path(__file__).resolve().parents[1] / "tools" / "appfingerprint.py")
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)

INDEX = """<!doctype html><html><head><title> Orders  portal </title>
<meta name="generator" content="Orders 4.2"><link rel="stylesheet" href="css/site.9f8e7d6c5b.css">
<link rel="icon" href="img/orders.png"><!-- build 4.2.1 -->
<script>window.cfg = {clientId: "orders-spa-client", api: "https://orders-api.corp.example/"};</script>
<script src="js/main.3f2a1b9c0d.js"></script><script src="https://cdn.example.net/lib/jquery.min.js"></script>
</head><body><app-orders id="root"></app-orders>
<form action="/Account/Login?x=1" method="post"><input type="hidden" name="__RequestVerificationToken" value="s3cret">
</form></body></html>"""
MAIN_JS = ('(self.webpackChunkorders_web=self.webpackChunkorders_web||[]).push([]);fetch("/api/orders/{id}");'
           'const r=[{path:"orders/:id"}];load("Contoso.Orders.Client.wasm");\n//# sourceMappingURL=main.js.map\n')
MAP = {"version": 3, "file": "main.js", "sources": ["webpack://orders-web/./src/app/orders.component.ts",
                                                    "webpack://orders-web/./node_modules/rxjs/index.js"],
       "sourcesContent": ["secret source", ""]}
BOOT = {"mainAssemblyName": "Contoso.Orders.Client", "resources": {"assembly": {
    "Contoso.Orders.Client.wasm": "sha256-x", "System.Text.Json.wasm": "sha256-y"}}}
SWAGGER = {"openapi": "3.0.1", "info": {"title": "Orders API", "version": "v1"}, "paths": {"/api/orders": {}}}
SAML = base64.b64encode(zlib.compress(
    b'<samlp:AuthnRequest AssertionConsumerServiceURL="https://hr.example/acs"><saml:Issuer>urn:hr:portal</saml:Issuer>'
    b'</samlp:AuthnRequest>')[2:-4]).decode()


class App(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        App.seen.append((self.path, self.headers.get("Cookie")))
        path = self.path.split("?")[0]
        body, ctype, status, extra = None, "text/html; charset=utf-8", 200, []
        if path == "/orders":
            status, extra = 302, [("Location", "/orders/")]
        elif path == "/orders/":
            body, extra = INDEX, [("Set-Cookie", "OrdersSession=abc; Path=/"), ("X-Powered-By", "ASP.NET")]
        elif path == "/orders/js/main.3f2a1b9c0d.js":
            body, ctype = MAIN_JS, "text/javascript"
        elif path == "/orders/js/main.js.map":
            body, ctype = json.dumps(MAP), "application/json"
        elif path == "/orders/_framework/blazor.boot.json":
            body, ctype = json.dumps(BOOT), "application/json"
        elif path == "/orders/swagger/v1/swagger.json":
            body, ctype = json.dumps(SWAGGER), "application/json"
        elif path == "/orders/img/orders.png":
            body, ctype = "\x89PNG-not-really", "image/png"
        elif path == "/oidc":
            status, extra = 302, [("Location", "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize"
                                               "?client_id=11111111-2222-3333-4444-555555555555&state=xyz"
                                               "&redirect_uri=https%3A%2F%2Fhr.example%2Fsignin-oidc")]
        elif path == "/saml":
            status, extra = 302, [("Location", "https://idp.example/saml2/sso?SAMLRequest=" + quote(SAML, safe=""))]
        elif path.startswith("/orders/"):
            body = INDEX                                   # a single-page application answers every path with its page
        else:
            status, body = 404, "not found"
        data = (body or "").encode("latin-1" if ctype == "image/png" else "utf-8")
        self.send_response(status)
        for k, v in [("Content-Type", ctype), ("Content-Length", str(len(data))), *extra]:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def run(tmp_path, *args):
    out = tmp_path / "out.json"
    assert fp.main([*args, "-o", str(out), "--delay", "0"]) == 0
    return json.loads(out.read_text())["applications"]


def test_page_scripts_maps_and_probes(site, tmp_path):
    csv = tmp_path / "apps.csv"
    csv.write_text(f"Id;Name;URL\nA-1;Orders;{site}/orders\n", encoding="utf-8")
    App.seen.clear()
    (d,) = run(tmp_path, str(csv), "--header", "Cookie: sso=1")
    assert (d["id"], d["name"]) == ("A-1", "Orders")
    assert d["redirects"][0]["toPath"] == "/orders/"
    p = d["page"]
    assert p["title"] == "Orders portal" and p["meta"]["generator"] == "Orders 4.2"
    assert p["scripts"] == ["/orders/js/main.3f2a1b9c0d.js", "cdn.example.net/lib/jquery.min.js"]
    assert p["assetNames"] == ["main.js", "jquery.min.js", "site.css"]
    assert p["customElements"] == ["app-orders"] and p["hiddenFields"] == ["__RequestVerificationToken"]
    assert p["forms"][0]["action"] == "/Account/Login" and p["comments"] == ["build 4.2.1"]
    assert d["inline"]["clientIds"] == ["orders-spa-client"] and d["inline"]["hosts"] == ["orders-api.corp.example"]
    b = d["bundles"]
    assert b["globals"] == ["webpackChunkorders_web"] and b["apiPaths"] == ["/api/orders/{id}"]
    assert b["routes"] == ["orders/:id"] and b["assemblies"] == ["Contoso.Orders.Client"]
    (m,) = d["sourceMaps"]
    assert m["sources"] == ["orders-web/src/app/orders.component.ts"] and m["packageCount"] == 1
    assert d["blazor"]["assemblies"] == ["Contoso.Orders.Client"] and d["blazor"]["frameworkAssemblies"] == 1
    assert d["openapi"]["title"] == "Orders API" and d["openapi"]["paths"] == ["/api/orders"]
    assert d["favicon"]["url"] == "/orders/img/orders.png" and len(d["favicon"]["sha256"]) == 64
    assert "manifest" not in d and "robots" not in d and "actuator" not in d      # the page for every path is no hit
    assert d["cookies"] == ["OrdersSession"] and d["headers"]["x-powered-by"] == "ASP.NET"
    text = json.dumps(d)
    assert "s3cret" not in text and "abc" not in d["cookies"] and "secret source" not in text
    assert all("sso=1" in (c or "") for _, c in App.seen)             # the header goes to the application's host


def test_sign_in_is_recorded_not_followed(site, tmp_path):
    oidc, saml = run(tmp_path, f"{site}/oidc", f"{site}/saml", "--no-probes")
    s = oidc["signIn"]
    assert s["host"] == "login.microsoftonline.com" and s["clientId"] == "11111111-2222-3333-4444-555555555555"
    assert s["redirectUri"] == "https://hr.example/signin-oidc" and "state" in s["params"] and "xyz" not in json.dumps(oidc)
    assert oidc["requests"] == 1 and "page" not in oidc
    assert saml["signIn"]["samlIssuer"] == "urn:hr:portal" and saml["signIn"]["samlAcsUrl"] == "https://hr.example/acs"


def test_request_budget_and_asset_names(site, tmp_path):
    (d,) = run(tmp_path, f"{site}/orders/", "--max-requests", "3")
    assert d["requests"] == 3 and "stopped at 3 requests" in d["errors"][0]
    assert fp.asset_name("/a/index-DiwrgTda.js") == "index.js"
    assert fp.asset_name("/a/bootstrap-datepicker3.min.js") == "bootstrap-datepicker3.min.js"
    assert fp.asset_name("/a/jquery-validation.js?v=1") == "jquery-validation.js"
