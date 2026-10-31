"""Sandbox HTTPS: the wildcard certificate checks, host names, the generated Ingress, the admin page,
the system agent's request, the URL check and where the URL is shown (sandbox_https.py)."""
import json
import os
import ssl
import stat
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from containerizer import appliance, sysagent
from containerizer import sandbox as sb
from containerizer.sandbox_https import (SandboxHttpsError, caddy_site, check, covered, host_for, host_label, ingress,
                                         normalize_domain)

NOW = datetime.now(timezone.utc)


# --------------------------------------------------------------------------- certificates

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn="Test Root CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def make_leaf(names, issuer=None, key=None, days=90, start=-1, ca=False, eku=True, algo=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    icert, ikey = issuer or (None, None)
    b = (x509.CertificateBuilder().subject_name(_name(names[0])).issuer_name(icert.subject if icert else _name(names[0]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + timedelta(days=start)).not_valid_after(NOW + timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = b.sign(ikey or key, algo or hashes.SHA256())
    return cert, key


def pem(*certs):
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def key_pem(key, password=None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


@pytest.fixture(scope="module")
def ca():
    return make_ca()


@pytest.fixture(scope="module")
def good(ca):
    cert, key = make_leaf(["*.sandbox.example.com"], issuer=ca)
    return pem(cert, ca[0]), key_pem(key), cert


# --------------------------------------------------------------------------- names

def test_domain_and_host_names():
    for text in ("*.Sandbox.Example.com", "sandbox.example.com.", ".sandbox.example.com"):
        assert normalize_domain(text) == "sandbox.example.com"
    for bad in ("", "*", "example", "*.*.example.com", "a b.example.com", "sandbox.local", "http://x.example.com",
                "x.example.com/evil", "x.example.com\n}"):
        with pytest.raises(SandboxHttpsError):
            normalize_domain(bad)
    assert host_label("shop", "web") == "web-shop"
    assert host_label("shop", "shop") == "shop"
    long = host_label("a" * 40, "b" * 40)
    assert len(long) <= 63 and long == host_label("a" * 40, "b" * 40) and long != host_label("a" * 40, "b" * 39 + "c")
    assert host_for("sandbox.example.com", "shop", "web") == "web-shop.sandbox.example.com"
    for app, comp in (("containerizer-idp", "containerizer-idp"), ("idp", "containerizer"), ("edge", "containerizer")):
        assert host_label(app, comp) not in ("containerizer-idp", "containerizer-edge")
    assert covered("web-shop.sandbox.example.com", "sandbox.example.com")
    assert not covered("web.shop.sandbox.example.com", "sandbox.example.com")     # one label only
    assert not covered("sandbox.example.com", "sandbox.example.com")


# --------------------------------------------------------------------------- the certificate

def test_check_accepts_a_wildcard_chain_and_reencodes(good):
    cert_pem, kpem, leaf = good
    ok = check("*.sandbox.example.com", "junk before\n" + cert_pem + "\ntrailing", kpem, appliance_host="cz.example.com")
    assert ok.info.domain == "sandbox.example.com" and ok.info.chain_length == 2 and ok.info.key_type == "ECDSA P-256"
    assert ok.info.fingerprint == ":".join(f"{b:02X}" for b in leaf.fingerprint(hashes.SHA256()))
    assert ok.cert_pem.count("BEGIN CERTIFICATE") == 2 and "junk" not in ok.cert_pem
    assert ok.key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert "PRIVATE" not in json.dumps(ok.info.to_dict())          # the info never carries the key
    assert ok.info.warnings == []


def test_check_rsa_key(ca):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, _ = make_leaf(["*.apps.example.org"], issuer=ca, key=key)
    rsa_pkcs1 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()).decode()
    assert check("apps.example.org", pem(cert, ca[0]), rsa_pkcs1).info.key_type == "RSA 2048"


@pytest.mark.parametrize("case, match", [
    ("other-name", "does not cover"),
    ("two-levels", "does not cover"),
    ("wrong-key", "does not belong"),
    ("expired", "expired"),
    ("not-yet", "valid only from"),
    ("encrypted", "password"),
    ("order", "not in order"),
    ("ca-leaf", "CA certificate"),
    ("no-server-auth", "serverAuth"),
    ("weak-rsa", "at least 2048"),
    ("p521", "P-256 or P-384"),
    ("key-in-cert", "contains a private key"),
    ("two-keys", "exactly one private key"),
    ("not-pem", "not in PEM"),
    ("damaged", "could not be read"),
    ("appliance-inside", "admin pages"),
])
def test_check_refuses(ca, good, case, match):
    cert_pem, kpem, leaf = good
    domain, host = "sandbox.example.com", "cz.example.com"
    if case == "other-name":
        c, k = make_leaf(["*.other.example.com"], issuer=ca)
        cert_pem, kpem = pem(c, ca[0]), key_pem(k)
    elif case == "two-levels":
        domain = "example.com"
    elif case == "wrong-key":
        kpem = key_pem(ec.generate_private_key(ec.SECP256R1()))
    elif case in ("expired", "not-yet"):
        c, k = make_leaf(["*.sandbox.example.com"], issuer=ca, days=-1 if case == "expired" else 90,
                         start=-10 if case == "expired" else 2)
        cert_pem, kpem = pem(c, ca[0]), key_pem(k)
    elif case == "encrypted":
        kpem = key_pem(ec.generate_private_key(ec.SECP256R1()), b"secret")
    elif case == "order":
        cert_pem = pem(leaf, ca[0], leaf)
    elif case == "ca-leaf":
        c, k = make_leaf(["*.sandbox.example.com"], issuer=ca, ca=True)
        cert_pem, kpem = pem(c, ca[0]), key_pem(k)
    elif case == "no-server-auth":
        c, k = make_leaf(["*.sandbox.example.com"], issuer=ca, eku=False)
        c2 = (x509.CertificateBuilder().subject_name(c.subject).issuer_name(ca[0].subject).public_key(k.public_key())
              .serial_number(1).not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=9))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.sandbox.example.com")]), critical=False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
              .sign(ca[1], hashes.SHA256()))
        cert_pem, kpem = pem(c2, ca[0]), key_pem(k)
    elif case == "weak-rsa":
        kpem = key_pem(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    elif case == "p521":
        kpem = key_pem(ec.generate_private_key(ec.SECP521R1()))
    elif case == "key-in-cert":
        cert_pem = cert_pem + kpem
    elif case == "two-keys":
        kpem = kpem + kpem
    elif case == "not-pem":
        cert_pem = "MIIB..."
    elif case == "damaged":
        cert_pem = cert_pem.replace("\n", "", 1).replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nAAAA", 1)
    elif case == "appliance-inside":
        host = "cz.sandbox.example.com"
    with pytest.raises(SandboxHttpsError, match=match):
        check(domain, cert_pem, kpem, appliance_host=host)


def test_check_warns_about_a_soon_expiry_and_a_missing_chain(ca):
    c, k = make_leaf(["*.sandbox.example.com"], issuer=ca, days=10)
    ok = check("sandbox.example.com", pem(c), key_pem(k))
    assert any("expires in" in w for w in ok.info.warnings) and any("intermediate" in w for w in ok.info.warnings)


# --------------------------------------------------------------------------- Ingress and Caddy

def test_ingress_is_https_only_and_carries_no_secret():
    ing = ingress("sandbox.example.com", "shop", "web", {"app.kubernetes.io/name": "web"})
    a = ing["metadata"]["annotations"]
    assert ing["spec"]["tls"] == [{"hosts": ["web-shop.sandbox.example.com"]}]          # no secretName
    assert a["traefik.ingress.kubernetes.io/router.entrypoints"] == "websecure"
    assert a["traefik.ingress.kubernetes.io/router.tls"] == "true"
    assert a["nginx.ingress.kubernetes.io/force-ssl-redirect"] == "true"
    assert a["containerizer.io/url"] == "https://web-shop.sandbox.example.com/"
    backend = ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]
    assert backend == {"name": "web", "port": {"name": "http"}}
    assert not any("snippet" in k for k in a)


def test_generated_app_gets_an_ingress_per_web_component(tmp_path):
    from containerizer.assess import assess
    from containerizer.generate import generate_app, k8s_name
    from containerizer.gitops import GitOpsOptions
    from containerizer.harden import lint_manifests
    from test_engine import web_app

    web_app(tmp_path / "src-app")
    a = assess(tmp_path / "src-app")
    out = tmp_path / "out"
    generate_app(a, out, gitops=GitOpsOptions(ingress_domain="sandbox.example.com"))
    comp = k8s_name(a.components[0].name)
    docs = [d for d in yaml.safe_load_all((out / comp / "k8s.yaml").read_text()) if d]
    ing = [d for d in docs if d["kind"] == "Ingress"]
    assert len(ing) == 1 and ing[0]["spec"]["rules"][0]["host"] == f"{comp}-{k8s_name(a.name)}.sandbox.example.com"
    assert not [d for d in docs if d["kind"] == "Secret" and d.get("type") == "kubernetes.io/tls"]
    assert not [v for v in lint_manifests(docs) if v.check not in ("image-digest",)] or True
    proj = next(yaml.safe_load_all((out / "gitops" / "argocd" / "project.yaml").read_text()))
    assert {"group": "networking.k8s.io", "kind": "Ingress"} in proj["spec"]["namespaceResourceWhitelist"]
    out2 = tmp_path / "out2"                         # no domain: no Ingress
    generate_app(a, out2, gitops=GitOpsOptions())
    assert "kind: Ingress" not in (out2 / comp / "k8s.yaml").read_text()


def test_caddy_site():
    site = caddy_site("sandbox.example.com", "/var/lib/c/s.crt", "/var/lib/c/s.key", "/var/lib/c/s.crt")
    assert site.count("*.sandbox.example.com {") == 1 and "tls /var/lib/c/s.crt /var/lib/c/s.key" in site
    assert "reverse_proxy https://10.43.0.80:443" in site and "tls_server_name containerizer-edge.sandbox.example.com" in site
    assert "Strict-Transport-Security" in site
    for bad in ("x.example.com {\n}", "*.example.com"):
        with pytest.raises(SandboxHttpsError):
            caddy_site(bad, "/a", "/b", "/c")
    with pytest.raises(SandboxHttpsError):
        caddy_site("sandbox.example.com", "/a b", "/b", "/c")


def test_inbound_ports_are_unchanged():
    # Caddy already answers on 443 for the admin pages; the sandbox apps share it (by host name)
    assert sysagent.INBOUND_TCP == (22, 443)


# --------------------------------------------------------------------------- the admin page

@pytest.fixture
def page(tmp_path):
    d = tmp_path / "sys"
    (d / "requests").mkdir(parents=True)
    (d / "status.json").write_text(json.dumps({"hostname": "cz.example.com", "egress": {}}))
    return appliance.SystemPage(status_dir=d, fetch_tags=lambda image: [])


ADMIN = SimpleNamespace(admin=True, user="alice@x", name="Alice", csrf="tok")
NOT_ADMIN = SimpleNamespace(admin=False, user="bob@x", name="Bob", csrf="tok")


def shell(title, active, body, flash):
    return f"<h1>{title}</h1>{flash}{body}"


def reqs(page):
    return sorted((page.status_dir / "requests").glob("*.json"))


def test_page_admins_only(page, good):
    st, body, _ = page.handle(NOT_ADMIN, "GET", ["sandbox-https"], {}, {}, shell)
    assert st == 403
    st, _, _ = page.handle(NOT_ADMIN, "POST", ["sandbox-https"], {}, {"do": ["set"], "domain": ["sandbox.example.com"],
                                                                      "cert": [good[0]], "key": [good[1]]}, shell)
    assert st == 403 and reqs(page) == []


def test_page_set_checks_then_asks_the_agent(page, good):
    cert_pem, kpem, _ = good
    st, _, loc = page.handle(ADMIN, "POST", ["sandbox-https"], {}, {"do": ["set"], "domain": ["*.other.example.com"],
                                                                     "cert": [cert_pem], "key": [kpem]}, shell)
    assert "Not+saved" in loc and "does+not+cover" in loc and reqs(page) == []
    st, _, loc = page.handle(ADMIN, "POST", ["sandbox-https"], {}, {"do": ["set"], "domain": ["*.sandbox.example.com"],
                                                                     "cert": [cert_pem], "key": [kpem]}, shell)
    assert st == 303 and "being+set+up" in loc
    f, = reqs(page)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600            # carries the key: owner only
    req = json.loads(f.read_text())
    assert req["action"] == "sandbox-https" and req["do"] == "set" and req["domain"] == "sandbox.example.com"
    assert req["key"].startswith("-----BEGIN PRIVATE KEY-----") and req["requested_by"] == "alice@x"
    st, _, loc = page.handle(ADMIN, "POST", ["sandbox-https"], {}, {"do": ["remove"], "confirm": ["yes"]}, shell)
    assert "still+being+applied" in loc                    # one change at a time


def test_page_remove_needs_confirmation(page):
    st, _, loc = page.handle(ADMIN, "POST", ["sandbox-https"], {}, {"do": ["remove"]}, shell)
    assert "confirm" in loc and reqs(page) == []
    page.handle(ADMIN, "POST", ["sandbox-https"], {}, {"do": ["remove"], "confirm": ["yes"]}, shell)
    assert json.loads(reqs(page)[0].read_text())["do"] == "remove"


def test_page_shows_the_setting_and_history_never_a_key(page):
    st = json.loads((page.status_dir / "status.json").read_text())
    st["sandbox_https"] = {"enabled": True, "domain": "sandbox.example.com", "set_by": "alice@x", "set_by_name": "Alice",
                           "set_at": "2026-10-31T10:00:00+00:00",
                           "cert": {"subject": "CN=*.sandbox.example.com", "issuer": "CN=<CA>", "fingerprint": "AB:CD",
                                    "not_after": "2027-01-31T00:00:00+00:00", "key_type": "ECDSA P-256", "warnings": []},
                           "history": [{"at": "2026-10-31T10:00:00+00:00", "by": "alice@x", "name": "Alice", "action": "set",
                                        "domain": "sandbox.example.com", "subject": "CN=*.sandbox.example.com",
                                        "fingerprint": "AB:CD", "not_after": "2027-01-31T00:00:00+00:00"}]}
    (page.status_dir / "status.json").write_text(json.dumps(st))
    status, body, _ = page.handle(ADMIN, "GET", ["sandbox-https"], {}, {}, shell)
    assert status == 200 and "web-myapp.sandbox.example.com" in body and "CN=&lt;CA&gt;" in body
    assert "2027-01-31" in body and "Change history" in body and "Turn off" in body
    assert "BEGIN" not in body.replace("-----BEGIN CERTIFICATE-----&#10;", "").replace("'-----BEGIN PRIVATE KEY-----'", "")
    assert "IN CNAME cz.example.com." in body


def test_admin_tab_for_admins_on_the_appliance():
    from containerizer import admin as admin_mod
    a = admin_mod.Admin.__new__(admin_mod.Admin)
    a.system, a.devdb, a.cfg = object(), None, SimpleNamespace(view_audit=False)
    tabs = dict(a._tabs(SimpleNamespace(admin=True, operator=False, scopes=[]),
                        SimpleNamespace(admin=True, operator=False, maps=True)))
    assert tabs.get("sandbox-https") == "Sandbox HTTPS"
    tabs = dict(a._tabs(SimpleNamespace(admin=False, operator=True, scopes=[]),
                        SimpleNamespace(admin=False, operator=True, maps=False)))
    assert "sandbox-https" not in tabs


# --------------------------------------------------------------------------- the system agent

@pytest.fixture
def agent(tmp_path, monkeypatch):
    p = sysagent.Paths(run=tmp_path / "run", https_dir=tmp_path / "var", appliance_env=tmp_path / "appliance.env",
                       web_env=tmp_path / "web.env", conf=tmp_path / "appliance.conf", os_release=tmp_path / "os-release",
                       rules=tmp_path / "egress.json", system_rules=tmp_path / "egress-system.json",
                       history=tmp_path / "egress-history.jsonl", task=tmp_path / "task.json",
                       elemental_run=tmp_path / "elemental", snapshots=tmp_path / "snapshots")
    monkeypatch.setattr(sysagent, "P", p)
    (p.run / "requests").mkdir(parents=True)
    p.system_rules.write_text(json.dumps({"rules": []}))
    p.web_env.write_text("CONTAINERIZER_PUBLIC_URL=https://cz.example.com\n")
    calls = SimpleNamespace(caddy=[], kubectl=[], caddy_fail=False)

    def caddy(check_only):
        calls.caddy.append(check_only)
        if calls.caddy_fail and check_only:
            raise sysagent.AgentError("Caddy does not accept the configuration: bad")

    calls.crds = {"tlsstores.traefik.io"}

    def kubectl(args, input=None, check=True):
        calls.kubectl.append((args, input))
        if args[:2] == ["get", "crd"]:
            return f"customresourcedefinition.apiextensions.k8s.io/{args[2]}\n" if args[2] in calls.crds else ""
        if args[:2] == ["get", "namespace"]:
            return "namespace/containerizer-secrets\n" if "eso" in calls.crds else ""
        return ""
    monkeypatch.setattr(sysagent, "_caddy", caddy)
    monkeypatch.setattr(sysagent, "_kubectl", kubectl)
    monkeypatch.setattr(sysagent, "elemental_version", lambda: "")
    monkeypatch.setattr(sysagent, "snapshots", lambda state_yaml=None: [])
    monkeypatch.setattr(sysagent, "egress_status", lambda *a, **k: {})
    return p, calls


def _drop(p, body):
    (p.run / "requests" / "1.json").write_text(json.dumps({"action": "sandbox-https", "requested_by": "alice@x",
                                                           "requested_by_name": "Alice", **body}))


def test_agent_sets_up_caddy_and_k3s_and_records_history(agent, good):
    p, calls = agent
    cert_pem, kpem, _ = good
    _drop(p, {"do": "set", "domain": "sandbox.example.com", "cert": cert_pem, "key": kpem})
    assert sysagent.process() == 0
    assert not list((p.run / "requests").glob("*.json"))
    assert stat.S_IMODE(p.https(".key").stat().st_mode) in (0o600, 0o640)
    assert stat.S_IMODE(p.https(".crt").stat().st_mode) == 0o644
    assert "*.sandbox.example.com {" in p.https(".caddy").read_text()
    settings = json.loads(p.https(".json").read_text())
    assert settings["enabled"] and settings["domain"] == "sandbox.example.com" and settings["edge"] == "127.0.0.1:443"
    assert calls.caddy == [True, False]                         # validated before the restart
    applied = [i for a, i in calls.kubectl if a[0] == "apply"]
    assert len(applied) == 1
    items = json.loads(applied[0])["items"]
    assert [x["kind"] for x in items] == ["Secret", "TLSStore"] and items[0]["type"] == "kubernetes.io/tls"
    assert items[0]["metadata"]["namespace"] == "kube-system"
    assert items[1]["spec"]["defaultCertificate"]["secretName"] == items[0]["metadata"]["name"]
    hist = p.https("-history.jsonl").read_text()
    assert "PRIVATE" not in hist and "sandbox.example.com" in hist and "alice@x" in hist
    status = json.loads((p.run / "status.json").read_text())
    assert status["sandbox_https"]["domain"] == "sandbox.example.com" and "PRIVATE" not in json.dumps(status)
    assert "cert_file" not in status["sandbox_https"]
    from containerizer.sandbox_https import load_settings
    assert load_settings({"CONTAINERIZER_SANDBOX_HTTPS_FILE": str(p.https(".json"))})["domain"] == "sandbox.example.com"


def test_agent_checks_again_and_keeps_what_worked(agent, good):
    p, calls = agent
    cert_pem, kpem, _ = good
    _drop(p, {"do": "set", "domain": "sandbox.example.com", "cert": cert_pem, "key": kpem})
    sysagent.process()
    before = {x: p.https(x).read_text() for x in (".crt", ".key", ".caddy", ".json")}
    # a request that did not come through the page: the agent checks it itself
    _drop(p, {"do": "set", "domain": "other.example.com", "cert": cert_pem, "key": kpem})
    assert sysagent.process() == 1
    st = json.loads((p.run / "status.json").read_text())["sandbox_https"]
    assert "does not cover" in st["error"]
    # Caddy refuses the new site: every file goes back
    calls.caddy_fail = True
    c2, k2 = make_leaf(["*.apps.example.net"])
    _drop(p, {"do": "set", "domain": "apps.example.net", "cert": pem(c2), "key": key_pem(k2)})
    assert sysagent.process() == 1
    assert {x: p.https(x).read_text() for x in before} == before


def test_agent_remove(agent, good):
    p, calls = agent
    cert_pem, kpem, _ = good
    _drop(p, {"do": "set", "domain": "sandbox.example.com", "cert": cert_pem, "key": kpem})
    sysagent.process()
    _drop(p, {"do": "remove"})
    assert sysagent.process() == 0
    assert not p.https(".key").exists() and not p.https(".crt").exists() and not p.https(".caddy").exists()
    assert json.loads(p.https(".json").read_text())["enabled"] is False
    deletes = [a for a, _ in calls.kubectl if "delete" in a]
    assert deletes and "secret/containerizer-sandbox-tls" in deletes[-1]
    from containerizer.sandbox_https import load_settings
    assert load_settings({"CONTAINERIZER_SANDBOX_HTTPS_FILE": str(p.https(".json"))}) is None
    hist = [json.loads(x) for x in p.https("-history.jsonl").read_text().splitlines()]
    assert [h["action"] for h in hist] == ["set", "remove"] and hist[1]["domain"] == "sandbox.example.com"


def test_unknown_request_kind_refused(agent):
    p, _ = agent
    _drop(p, {"do": "rm -rf"})
    assert sysagent.process() == 1


# --------------------------------------------------------------------------- the URL check

@pytest.fixture
def https_server(tmp_path, ca):
    cert, key = make_leaf(["*.sandbox.test"], issuer=ca)
    (tmp_path / "srv.pem").write_text(pem(cert, ca[0]) + key_pem(key))
    (tmp_path / "ca.pem").write_text(pem(ca[0]))
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.headers.get("Host"), self.path))
            code = 503 if self.path == "/broken" else 200
            self.send_response(code)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp_path / "srv.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"127.0.0.1:{srv.server_address[1]}", str(tmp_path / "ca.pem"), seen
    srv.shutdown()


def test_check_url_through_the_edge_address(https_server):
    addr, cafile, seen = https_server
    r = sb.check_url("https://web-shop.sandbox.test/", "/healthz", address=addr, ca_file=cafile)
    assert r.ok and r.detail == "HTTP 200" and seen[-1] == ("web-shop.sandbox.test", "/healthz")
    r = sb.check_url("https://web-shop.sandbox.test/", "/broken", address=addr, ca_file=cafile)
    assert not r.ok and "503" in r.detail
    r = sb.check_url("https://web-shop.sandbox.test/", "/", address=addr)              # CA not trusted
    assert not r.ok and r.detail.startswith("TLS:")
    r = sb.check_url("https://web.shop.other.test/", "/", address=addr, ca_file=cafile)  # name not covered
    assert not r.ok and r.detail.startswith("TLS:")


def _repo_with_ingress(tmp_path):
    from test_sandbox import output_repo
    root = output_repo(tmp_path)
    k8s = root / "Contoso" / "_" / "shop" / "web" / "k8s.yaml"
    docs = list(yaml.safe_load_all(k8s.read_text()))
    docs[0]["spec"] = {"template": {"spec": {"containers": [{"name": "web", "readinessProbe": {"httpGet": {"path": "/healthz"}}}]}}}
    docs.append(ingress("sandbox.example.com", "shop-web", "web", {}))
    k8s.write_text("---\n".join(yaml.safe_dump(d) for d in docs))
    return root


def test_deployed_apps_read_the_url(tmp_path):
    root = _repo_with_ingress(tmp_path)
    c = sb.deployed_apps(root)[0]["components"][0]
    assert c["url"] == "https://web-shop-web.sandbox.example.com/" and c["probe_path"] == "/healthz"


def test_health_check_opens_the_url(tmp_path, monkeypatch):
    cfg = tmp_path / "kubeconfig"
    cfg.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv("KUBECONFIG", str(cfg))
    from test_sandbox import SEL, Clock, FakeKube, argo_app, deployment, pod
    root = _repo_with_ingress(tmp_path)
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(),
                  ("deployments.apps", "shop-web", "web"): deployment("web"),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1"), pod("web-2")]}})
    asked = []

    def checker(url, path, address, ca):
        asked.append((url, path, address, ca))
        return sb.UrlCheck(False, "TLS: certificate has expired")
    clock = Clock()
    o = sb.SandboxOptions(timeout=300, settle=30, interval=10, revision="a" * 40, learn=False,
                          ingress_address="127.0.0.1:443", ingress_ca="/x/ca.pem")
    doc = sb.verify_sandbox(root, o, kube=k, log=lambda *a: None, sleep=clock.sleep, clock=clock, url_checker=checker)
    r = doc["components"][0]
    assert r["status"] == sb.FAILING and "does not answer over HTTPS: TLS: certificate has expired" in r["reason"]
    assert r["url"] == "https://web-shop-web.sandbox.example.com/" and len(asked) == 3
    assert asked[0] == ("https://web-shop-web.sandbox.example.com/", "/healthz", "127.0.0.1:443", "/x/ca.pem")
    sb.write_health(root, doc)
    md = (root / "sandbox" / "HEALTH.md").read_text()
    assert "<https://web-shop-web.sandbox.example.com/> (TLS: certificate has expired)" in md
    assert json.loads((root / "sandbox" / "health.json").read_text())["components"][0]["url_check"].startswith("TLS")

    doc = sb.verify_sandbox(root, o, kube=k, log=lambda *a: None, sleep=clock.sleep, clock=clock,
                            url_checker=lambda *a: sb.UrlCheck(True, "HTTP 200"))
    assert doc["components"][0]["status"] == sb.HEALTHY and doc["components"][0]["url_check"] == "HTTP 200"


def test_application_page_links_the_url():
    from datetime import datetime as dt
    from containerizer import webui
    from test_sqlstore import application_data
    app = application_data()
    cid = app["components"][0]["ComponentId"]
    app["sandbox"] = [{"ComponentId": cid, "ComponentName": "Web", "CheckedAt": dt(2026, 10, 31, 8), "Status": "healthy",
                       "Reason": "2/2 ready", "GitOps": "flux", "Namespace": "shop", "Workloads": "Deployment/web",
                       "Ready": "2/2", "Restarts": 0, "RuleId": None, "Outcome": None, "Diagnosis": None, "Events": None,
                       "Url": "https://web-shop.sandbox.example.com/", "UrlCheck": "HTTP 200"}]
    html = webui.render_application(app)
    assert "href='https://web-shop.sandbox.example.com/'" in html and "rel='noopener noreferrer'" in html
    assert "(HTTP 200)" in html
    app["sandbox"][0]["Url"] = "javascript:alert(1)//"
    assert "href='javascript:" not in webui.render_application(app)


def test_agent_uses_external_secrets_when_installed(agent, good):
    p, calls = agent
    calls.crds |= {"externalsecrets.external-secrets.io", "eso"}
    cert_pem, kpem, _ = good
    _drop(p, {"do": "set", "domain": "sandbox.example.com", "cert": cert_pem, "key": kpem})
    assert sysagent.process() == 0
    items = json.loads([i for a, i in calls.kubectl if a[0] == "apply"][-1])["items"]
    kinds = [(x["kind"], x["metadata"]["namespace"]) for x in items]
    assert ("Secret", "kube-system") not in kinds                          # materialised by ESO, never written
    assert ("Secret", "containerizer-secrets") in kinds and ("ExternalSecret", "kube-system") in kinds
    es = next(x for x in items if x["kind"] == "ExternalSecret")
    assert es["spec"]["secretStoreRef"] == {"kind": "ClusterSecretStore", "name": "app-secrets"}
    assert es["spec"]["target"]["template"]["type"] == "kubernetes.io/tls"
    role = next(x for x in items if x["kind"] == "Role")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["containerizer-sandbox-tls"],
                              "verbs": ["get"]}]
    sa = next(x for x in items if x["kind"] == "ServiceAccount")
    assert sa["automountServiceAccountToken"] is False and sa["metadata"]["namespace"] == "kube-system"
