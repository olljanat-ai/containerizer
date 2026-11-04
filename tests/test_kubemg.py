"""kubemg on the appliance (optional): the sandbox cluster's registration (containerizer.kubemg) and the appliance's
units, settings and Caddy site for it."""
import os
import sys
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from containerizer import kubemg

ROOT = Path(__file__).resolve().parents[1]
APPLIANCE = ROOT / "appliance"
RFS = APPLIANCE / "rootfs"
UNITS = RFS / "usr/lib/systemd/system"

MANIFEST = """apiVersion: v1
kind: Namespace
metadata:
  name: kubemg-system
---
apiVersion: v1
kind: Secret
metadata:
  name: kubemg-agent
  namespace: kubemg-system
stringData:
  bastion-url: "https://kubemg.example.com"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubemg-agent
  namespace: kubemg-system
spec:
  template:
    spec:
      containers:
        - name: agent
          image: ghcr.io/kubemg/kubemg-agent:0.17.0
"""


class FakeKubemg:
    def __init__(self, password="pw", clusters=None, mfa=False, repos=None):
        self.password, self.clusters, self.mfa, self.calls = password, list(clusters or []), mfa, []
        self.repos = [dict(r) for r in repos or []]

    def __call__(self, method, path, token=None, body=None, raw=False, timeout=30):
        self.calls.append((method, path.split("?")[0], token))
        if path == "/auth/login":
            if body["password"] != self.password:
                raise kubemg.KubemgError("POST /auth/login: HTTP 401: invalid credentials")
            return {"mfa_required": True, "challenge": "c"} if self.mfa else {"token": "T", "user": {"id": 1}}
        assert token == "T"
        if method == "GET" and path == "/helm/repositories":
            return {"repositories": [dict(r) for r in self.repos]}
        if method == "DELETE" and path.startswith("/helm/repositories/"):
            self.repos = [r for r in self.repos if r["name"] != path.rsplit("/", 1)[1]]
            return {"message": "removed"}
        if method == "GET" and path == "/clusters":
            return {"clusters": self.clusters}
        if method == "POST" and path == "/clusters":
            assert body == {"name": "sandbox", "environment": "dev", "connection_mode": "agent"}
            c = {"id": 7, "name": "sandbox", "connection_mode": "agent", "agent_attached": False}
            self.clusters.append(c)
            return c
        if path == "/clusters/7/kustomize?format=yaml":
            return MANIFEST
        raise AssertionError(path)


def test_registers_the_sandbox_once_and_installs_the_agent_with_a_host_alias():
    api, applied, logs = FakeKubemg(), [], []
    out = kubemg.sandbox("kubemg.example.com", "pw", call=api, installed=lambda: False, apply=applied.append,
                         ip=lambda: "192.0.2.10", log=logs.append)
    assert out == "the sandbox cluster is registered in kubemg as sandbox and its agent is installed"
    assert [c[:2] for c in api.calls if c[1] not in ("/auth/login", "/helm/repositories")] == [
        ("GET", "/clusters"), ("POST", "/clusters"), ("GET", "/clusters/7/kustomize")]
    docs = list(yaml.safe_load_all(applied[0]))
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["hostAliases"] == [{"ip": "192.0.2.10", "hostnames": ["kubemg.example.com"]}]
    assert [d["kind"] for d in docs] == ["Namespace", "Secret", "Deployment"]            # the rest as it was
    # again (the agent is gone): the cluster is there already, its manifest is applied again
    kubemg.sandbox("kubemg.example.com", "pw", call=api, installed=lambda: False, apply=applied.append,
                   ip=lambda: "192.0.2.10", log=logs.append)
    assert sum(c[:2] == ("POST", "/clusters") for c in api.calls) == 1 and len(applied) == 2
    # the agent is there: it is not registered again
    n = len(api.calls)
    assert "installed" in kubemg.sandbox("kubemg.example.com", "pw", call=api, installed=lambda: True)
    assert not [c for c in api.calls[n:] if "/clusters" in c[1]]


def test_the_seeded_chart_repositories_it_cannot_reach_are_deleted_while_the_password_works():
    seeded = [{"name": n, "url": u + "/", "seeded": True} for n, u in kubemg.SEEDED_REPOS.items()]
    own = [{"name": "bitnami-mirror", "url": "https://charts.example.com/bitnami"},
           {"name": "grafana", "url": "https://charts.example.com/grafana"}]           # a seeded name, moved
    api, logs = FakeKubemg(repos=seeded[:2] + own), []
    out = kubemg.sandbox("kubemg.example.com", "pw", call=api, installed=lambda: True, log=logs.append)
    assert "installed" in out
    assert [r["name"] for r in api.repos] == ["bitnami-mirror", "grafana"]
    assert "argo, bitnami" in logs[0]
    # the password was changed: nothing is asked of kubemg
    api = FakeKubemg(password="changed", repos=seeded)
    kubemg.sandbox("kubemg.example.com", "pw", call=api, installed=lambda: True)
    assert len(api.repos) == 6 and {c[1] for c in api.calls} == {"/auth/login"}


def test_a_failed_repository_cleanup_does_not_stop_the_registration():
    def call(method, path, token=None, body=None, raw=False, timeout=30):
        if path == "/helm/repositories":
            raise kubemg.KubemgError("GET /helm/repositories: HTTP 500: boom")
        return api(method, path, token, body, raw, timeout)
    api, applied, logs = FakeKubemg(), [], []
    out = kubemg.sandbox("kubemg.example.com", "pw", call=call, installed=lambda: False, apply=applied.append,
                         ip=lambda: "192.0.2.10", log=logs.append)
    assert "registered" in out and applied and "were not deleted" in logs[0]


@pytest.mark.parametrize("api", [FakeKubemg(password="changed"), FakeKubemg(mfa=True)])
def test_a_changed_password_or_a_second_factor_leaves_it_to_the_administrator(api):
    applied = []
    out = kubemg.sandbox("kubemg.example.com", "pw", call=api, installed=lambda: False, apply=applied.append,
                         ip=lambda: "192.0.2.10")
    assert "Register it in kubemg" in out and applied == []


def test_the_host_alias_replaces_an_earlier_one_and_needs_the_deployment():
    once = kubemg.with_host_alias(MANIFEST, "kubemg.example.com", "192.0.2.10")
    twice = kubemg.with_host_alias(once, "kubemg.example.com", "192.0.2.11")
    dep = [d for d in yaml.safe_load_all(twice) if d["kind"] == "Deployment"][0]
    assert dep["spec"]["template"]["spec"]["hostAliases"] == [{"ip": "192.0.2.11", "hostnames": ["kubemg.example.com"]}]
    with pytest.raises(kubemg.KubemgError, match="no kubemg-agent Deployment"):
        kubemg.with_host_alias(MANIFEST.split("---")[0], "x", "1.2.3.4")


def _unit(name):
    out = {}
    for line in (UNITS / name).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out.setdefault(k, []).append(v)
    return out


def test_units_start_only_when_turned_on_and_are_locked_down():
    images = (RFS / "usr/lib/containerizer/images.env").read_text()
    for name in ("CZ_IMAGE_KUBEMG", "CZ_IMAGE_KUBEMG_AGENT", "CZ_IMAGE_KUBEMG_SHELL", "CZ_IMAGE_KUBEMG_POSTGRES"):
        line = next(l for l in images.splitlines() if l.startswith(name + "="))
        assert "@sha256:" in line                                                  # pinned by digest
    for unit in ("containerizer-kubemg-db.service", "containerizer-kubemg.service", "containerizer-kubemg-sandbox.service"):
        u = _unit(unit)
        assert "/run/containerizer/kubemg/kubemg.env" in u["ConditionPathExists"], unit
        assert u["WantedBy"] == ["multi-user.target"]
        enabled = (APPLIANCE / "Dockerfile").read_text().split("systemctl enable", 1)[1].split("\n\n", 1)[0]
        assert unit in enabled
    srv = (UNITS / "containerizer-kubemg.service").read_text()
    db = (UNITS / "containerizer-kubemg-db.service").read_text()
    # loopback only behind Caddy, non-root, read-only; the database on loopback too
    assert "KUBEMG_LISTEN_ADDR=127.0.0.1:8444" in srv and "KUBEMG_TLS_ENABLED=true" in srv and "ALLOW_INSECURE" not in srv
    assert "--volume /var/lib/containerizer/kubemg/tls/ssl:/etc/kubemg/ssl:ro" in srv           # its loopback certificate
    assert "DB_HOST=127.0.0.1 --env DB_PORT=5434" in db.replace("\\\n  ", "") or "DB_PORT=5434" in srv
    assert "listen_addresses=127.0.0.1 -c port=5434" in db
    for text, user in ((srv, "65532:65532"), (db, "70:70")):
        assert f"--user {user}" in text and "--read-only" in text and "--cap-drop ALL" in text
        assert "no-new-privileges" in text
    assert "KUBEMG_AGENT_IMAGE=${CZ_IMAGE_KUBEMG_AGENT}" in srv and "/etc/containerizer/secrets/kubemg.env" in srv
    defaults = (RFS / "usr/lib/containerizer/defaults/appliance.env").read_text()
    assert "\nCZ_KUBEMG=false\n" in defaults and "\nCZ_KUBEMG_HOSTNAME=\n" in defaults
    caddy = (RFS / "etc/caddy/Caddyfile").read_text()
    assert "import /run/containerizer/kubemg*.caddy" in caddy


@pytest.mark.skipif(not shutil.which("bash"), reason="bash")
def test_firstboot_writes_the_settings_site_and_secrets_only_when_turned_on(tmp_path):
    """cz-firstboot's kubemg block, run on its own with the paths moved into tmp_path."""
    fb = (RFS / "usr/lib/containerizer/bin/cz-firstboot").read_text()
    block = fb[fb.index("# kubemg (optional, CZ_KUBEMG=true)"):]
    block = block[:block.index("\nfi\n") + 4]
    run, s, d = tmp_path / "run", tmp_path / "secrets", tmp_path / "data"
    for p in (run, s, d):
        p.mkdir()
    (run / "web-url.env").write_text("CONTAINERIZER_PUBLIC_URL=https://cz.example.com\n")
    script = block.replace("/run/containerizer", str(run)).replace("install -d -m 0700 -o 70 -g 70", "mkdir -p") \
        .replace("install -d -m 0700 -o 65532 -g 65532", "mkdir -p").replace("install -d -m 0755 -o root -g root", "mkdir -p") \
        .replace("install -d -m 0755", "mkdir -p") \
        .replace("/usr/lib/containerizer/venv/bin/python", sys.executable).replace(" --group 65532", "")
    secret = ("secret() { [ -s \"$S/$1\" ] || { printf '%s' \"$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' "
              "| head -c 32)Aa1!\" > \"$S/$1\"; chmod 0400 \"$S/$1\"; }; }\n")

    def go(on: str):
        env = {**os.environ, "S": str(s), "D": str(d), "host": "cz.example.com", "CZ_KUBEMG": on,
               "CZ_KUBEMG_HOSTNAME": "", "CZ_ACME_EMAIL": ""}
        subprocess.run(["bash", "-euo", "pipefail", "-c", secret + script], env=env, check=True)
    go("true")
    kenv = (run / "kubemg/kubemg.env").read_text()
    assert "CZ_KUBEMG_HOST=kubemg.cz.example.com" in kenv and "KUBEMG_PUBLIC_URL=https://kubemg.cz.example.com" in kenv
    site = (run / "kubemg.caddy").read_text()
    assert site.startswith("https://kubemg.cz.example.com {") and "tls {$CZ_CADDY_TLS}" in site
    assert "reverse_proxy https://127.0.0.1:8444 {" in site
    assert f"tls_trusted_ca_certs {run}/kubemg/loopback-ca.pem" in site
    assert (run / "kubemg/loopback-ca.pem").read_text() == (d / "kubemg/tls/ca.crt").read_text()
    assert "CONTAINERIZER_KUBEMG_URL=https://kubemg.cz.example.com/" in (run / "web-url.env").read_text()
    sec = dict(l.split("=", 1) for l in (s / "kubemg.env").read_text().splitlines())
    assert set(sec) == {"DB_PASSWORD", "KUBEMG_ADMIN_PASSWORD", "KUBEMG_SECRET_KEY", "KUBEMG_SESSION_RECORDING_KEY"}
    import base64
    assert len(base64.b64decode(sec["KUBEMG_SECRET_KEY"])) == 32 and sec["KUBEMG_ADMIN_PASSWORD"].endswith("Aa1!")
    key = sec["KUBEMG_SECRET_KEY"]
    go("true")                                                        # kept across boots: the database needs it
    assert dict(l.split("=", 1) for l in (s / "kubemg.env").read_text().splitlines())["KUBEMG_SECRET_KEY"] == key
    go("false")                                                       # off: nothing starts, the secrets stay
    assert not (run / "kubemg").exists() and not (run / "kubemg.caddy").exists() and (s / "kubemg-secret-key").exists()


def test_the_admin_pages_link_kubemg():
    from containerizer.admin import build
    from containerizer.oidc import OidcError, Session
    from containerizer.roles import Access
    base = {"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
            "CONTAINERIZER_OIDC_CLIENT_SECRET": "s", "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com",
            "CONTAINERIZER_ADMINS": "group:g", "CONTAINERIZER_ADMIN_SQL": "Server=x", "CONTAINERIZER_ADMIN_SQL_PASSWORD": "p"}
    admin_s, admin_a = Session(user="u", name="U", admin=True), Access(admin=True)
    assert "kubemg" not in build(base)._shell(admin_s, admin_a, "T", "scans", "")
    adm = build({**base, "CONTAINERIZER_KUBEMG_URL": "https://kubemg.cz.example.com/"})
    page = adm._shell(admin_s, admin_a, "T", "scans", "")
    assert "href='https://kubemg.cz.example.com/'" in page and "kubemg ↗" in page and "target='_blank'" in page
    assert "kubemg ↗" in adm._shell(Session(user="o", name="O", admin=False), Access(admin=False, operator=True), "T", "scans", "")
    assert "kubemg" not in adm._shell(Session(user="p", name="P", admin=False), Access(admin=False, products={1}),
                                      "T", "applications", "")
    with pytest.raises(OidcError, match="KUBEMG_URL"):
        build({**base, "CONTAINERIZER_KUBEMG_URL": "javascript:alert(1)"})


def test_the_loopback_certificate_is_issued_by_its_own_ca_once(tmp_path):
    from cryptography import x509
    assert kubemg.loopback_tls(tmp_path / "tls") is True
    ca = x509.load_pem_x509_certificate((tmp_path / "tls/ca.crt").read_bytes())
    cert = x509.load_pem_x509_certificate((tmp_path / "tls/ssl/tls.crt").read_bytes())
    cert.verify_directly_issued_by(ca)                                     # not self-signed: kubemg's check is ok
    assert cert.issuer != cert.subject
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
    assert oct((tmp_path / "tls/ca.key").stat().st_mode & 0o777) == "0o400"
    assert oct((tmp_path / "tls/ssl/tls.key").stat().st_mode & 0o777) == "0o400"
    before = (tmp_path / "tls/ssl/tls.crt").read_bytes()
    assert kubemg.loopback_tls(tmp_path / "tls") is False and (tmp_path / "tls/ssl/tls.crt").read_bytes() == before


def test_the_loopback_certificate_is_readable_by_kubemgs_group_whatever_the_umask(tmp_path):
    """0.9.3: cz-firstboot's umask 077 cut ssl/ to 0700, and kubemg (65532, not root) could not stat
    /etc/kubemg/ssl/tls.crt. The modes are set explicitly, and again on every call (cz-kubemg ca), which heals."""
    tls, gid = tmp_path / "tls", os.getgid()
    mode = lambda p: oct(p.stat().st_mode & 0o777)
    old = os.umask(0o077)
    try:
        assert kubemg.loopback_tls(tls, gid) is True
    finally:
        os.umask(old)

    def check():
        assert (mode(tls), mode(tls / "ca.key"), mode(tls / "ca.crt")) == ("0o700", "0o400", "0o644")
        assert (mode(tls / "ssl"), mode(tls / "ssl/tls.crt"), mode(tls / "ssl/tls.key")) == ("0o750", "0o644", "0o440")
        assert (tls / "ssl").stat().st_gid == gid and (tls / "ssl/tls.key").stat().st_gid == gid
    check()
    before = (tls / "ssl/tls.key").read_bytes()
    os.chmod(tls / "ssl", 0o700)                                      # as 0.9.3 left it
    os.chmod(tls / "ssl/tls.key", 0o400)
    assert kubemg.loopback_tls(tls, gid) is False
    check()
    assert (tls / "ssl/tls.key").read_bytes() == before                # healed, not replaced: Caddy pins its CA
    ca = (RFS / "usr/lib/containerizer/bin/cz-kubemg").read_text()
    ca = ca[ca.index("\nca)\n"):ca.index(";;")]
    assert "-m containerizer.kubemg loopback-tls --dir \"$KT\" --group 65532" in ca
    assert "KT=/var/lib/containerizer/kubemg/tls" in ca
    srv = (RFS / "usr/lib/systemd/system/containerizer-kubemg.service").read_text()
    assert "--volume /var/lib/containerizer/kubemg/tls/ssl:/etc/kubemg/ssl:ro" in srv and "--user 65532:65532" in srv
    assert srv.index("cz-kubemg ca") < srv.index("ExecStart=")


def test_wait_up_stops_at_once_on_a_tls_failure(monkeypatch):
    """A refused connection is kubemg starting (wait); a failed TLS handshake is not (say so at once, with the
    client's error), so the sandbox service does not retry silently every 5 s for 10 minutes."""
    import ssl
    import urllib.error

    import pytest

    from containerizer import kubemg
    calls = []

    def refused_then_up(method, path, **kw):
        calls.append(path)
        if len(calls) < 3:
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        raise kubemg.KubemgError("HTTP 401")
    monkeypatch.setattr(kubemg.time, "sleep", lambda s: None)
    kubemg.wait_up(call=refused_then_up)
    assert len(calls) == 3

    def bad_mac(method, path, **kw):
        calls.append(path)
        raise urllib.error.URLError(ssl.SSLError(1, "[SSL: BAD_RECORD_MAC] bad record mac"))
    calls.clear()
    with pytest.raises(kubemg.KubemgError, match="TLS handshake fails: .*bad record mac"):
        kubemg.wait_up(call=bad_mac)
    assert len(calls) == 1
