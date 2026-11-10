"""The build feed proxy (feedproxy.py): feed credentials are added by the proxy, never given to the builds."""
import base64
import http.client
import http.server
import ssl
import threading
from types import SimpleNamespace

import pytest

from containerizer import feedproxy as fp


@pytest.fixture
def feed_server(tmp_path):
    """An HTTPS server on 127.0.0.1 that answers 401 without the right Authorization and records what it got."""
    key, cert = fp._ca(tmp_path / "upstream-ca")
    chain, k = fp._leaf(key, cert, "localhost")
    (tmp_path / "c.pem").write_bytes(chain)
    (tmp_path / "k.pem").write_bytes(k)
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            auth = self.headers.get("Authorization")
            seen.append((self.path, auth, self.headers.get("Connection")))
            ok = auth == "Basic " + base64.b64encode(b"builder:s3cret-token").decode() or not self.path.startswith("/feed")
            body = (b"x" * (2 * 1024 * 1024) if self.path.endswith("/big") else b"package") if ok else b"no"
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield SimpleNamespace(port=srv.server_address[1], seen=seen, ca=str(tmp_path / "upstream-ca" / "ca.pem"))
    srv.shutdown()


def _get(proxy, port, path, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    c = http.client.HTTPSConnection(proxy.address.rsplit(":", 1)[0], int(proxy.address.rsplit(":", 1)[1]),
                                    context=ctx, timeout=20)
    c.set_tunnel("localhost", port)
    c.request("GET", path)
    r = c.getresponse()
    return r.status, r.read()


def test_the_proxy_adds_the_feed_token_only_under_the_feed(tmp_path, feed_server):
    logs = []
    p = fp.FeedProxy(tmp_path / "proxy", "127.0.0.1:0", log=logs.append, policy=fp.Policy(allow_local=True),
                     upstream_cafile=feed_server.ca)
    cred = SimpleNamespace(id=7)
    try:
        p.set_feeds([fp.Feed("nuget", f"https://localhost:{feed_server.port}/feed/", "s3cret-token", "builder", cred)])
        assert fp.active() is None or fp.active() is not p           # not the process's proxy: use() was not called
        # the builds trust the proxy's CA through the bundle (system CAs + corporate + the proxy's)
        assert "BEGIN CERTIFICATE" in p.bundle.read_text()
        assert _get(p, feed_server.port, "/feed/v3/index.json", str(p.bundle)) == (200, b"package")
        assert _get(p, feed_server.port, "/other/thing", str(p.bundle)) == (200, b"package")
        assert feed_server.seen[0][1].startswith("Basic ") and feed_server.seen[0][2] == "close"
        assert feed_server.seen[1] == ("/other/thing", None, "close")       # not under the feed: no token
        assert p.results == {7: "ok: used by the builds"}
        # big answers, many at once (Maven downloads in parallel): complete, never cut short
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(8) as pool:
            got = list(pool.map(lambda i: _get(p, feed_server.port, f"/feed/{i}/big", str(p.bundle)), range(16)))
        assert all(code == 200 and len(body) == 2 * 1024 * 1024 for code, body in got)
        # a wrong token: recorded as failed
        p.set_feeds([fp.Feed("nuget", f"https://localhost:{feed_server.port}/feed", "wrong-token-x", "builder", cred)])
        assert _get(p, feed_server.port, "/feed/x", str(p.bundle))[0] == 401
        assert p.results[7].startswith("failed: HTTP 401")
        # without feeds for the host: a plain tunnel, the client sees the server's own certificate
        p.set_feeds([])
        with pytest.raises(ssl.SSLError):
            _get(p, feed_server.port, "/feed/x", str(p.bundle))
        assert _get(p, feed_server.port, "/feed/x", feed_server.ca)[0] == 401
    finally:
        p.close()


def test_the_proxy_refuses_this_machine_and_plain_http(tmp_path):
    p = fp.FeedProxy(tmp_path / "proxy", "127.0.0.1:0", log=lambda m: None)
    try:
        for target in ("127.0.0.1:1433", "localhost:5000", "169.254.53.53:53", "[::1]:22"):
            c = http.client.HTTPConnection(*p.address.rsplit(":", 1), timeout=10)
            c.request("CONNECT", target)
            assert c.getresponse().status == 403, target
        c = http.client.HTTPConnection(*p.address.rsplit(":", 1), timeout=10)
        c.request("GET", "http://example.com/")
        assert c.getresponse().status == 405
    finally:
        p.close()


def test_rewrite_and_build_env(monkeypatch):
    f = fp.Feed("npm", "https://pkgs.dev.azure.com/Contoso/_packaging/web/npm/registry/", "tok-12345678")
    head = (b"GET /contoso/_packaging/web/npm/registry/left-pad HTTP/1.1\r\nHost: pkgs.dev.azure.com\r\n"
            b"Authorization: Bearer old\r\nProxy-Authorization: x\r\nConnection: keep-alive\r\n\r\n")
    out, feed = fp.rewrite(head, [f])
    assert feed is f and b"Authorization: Bearer tok-12345678" in out and b"Bearer old" not in out
    assert b"Proxy-Authorization" not in out and out.endswith(b"Connection: close\r\n\r\n")
    out, feed = fp.rewrite(head.replace(b"/web/", b"/other/"), [f])
    assert feed is None and b"Bearer old" in out                        # the client's own, untouched
    fake = SimpleNamespace(feeds=[f], url="http://172.17.0.1:3128", bundle="/x/ca-bundle.pem",
                           hosts=lambda: {"pkgs.dev.azure.com"})
    monkeypatch.setitem(fp._PROXY, "proxy", fake)
    env = fp.build_proxy_env("localhost,.dev.azure.com,example.org")
    assert env == {"proxy": "http://172.17.0.1:3128", "no_proxy": "localhost,example.org", "ca": "/x/ca-bundle.pem"}
    from containerizer import verify
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    args = verify._build_env_args()
    assert "HTTPS_PROXY=http://172.17.0.1:3128" in args and "id=ca,src=/x/ca-bundle.pem" in args
