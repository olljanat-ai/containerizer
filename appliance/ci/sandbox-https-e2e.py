"""End-to-end check of Sandbox HTTPS on a real k3s with the appliance's Traefik settings and a real Caddy
(CI job `sandbox-https`; needs k3s with appliance/rootfs/var/lib/rancher/k3s/server/manifests/
containerizer-traefik.yaml, a readable /etc/rancher/k3s/k3s.yaml, and the `caddy` binary).

What the appliance does, with the system agent's own code: check and save the wildcard certificate,
write the Caddy site and have Caddy validate it, install the certificate as Traefik's default, then an
app with the generated Ingress answers at https://web-ci.<domain>/ through Caddy and Traefik; HTTP
inside the cluster redirects to HTTPS; turning it off removes it again. Caddy listens on 8443 here.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from containerizer import sandbox, sysagent
from containerizer.sandbox_https import TRAEFIK_ADDR, ingress

DOMAIN = "sandbox.test"
PORT = 8443
NOW = datetime.now(timezone.utc)
work = Path(tempfile.mkdtemp(prefix="cz-https-"))


def step(msg: str) -> None:
    print(f"\n=== {msg}", flush=True)


def kubectl(*args: str, input: str | None = None, check: bool = True) -> str:
    p = subprocess.run(["k3s", "kubectl", *args], capture_output=True, text=True, input=input)
    if check and p.returncode:
        raise RuntimeError(f"kubectl {' '.join(args)}: {p.stderr}")
    return p.stdout


def wait(what: str, fn, timeout: int = 300):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            v = fn()
            if v:
                print(f"ok: {what}", flush=True)
                return v
        except Exception as ex:          # noqa: BLE001 - keep trying until the timeout
            last = ex
        time.sleep(5)
    raise SystemExit(f"timed out: {what} ({last})")


def certs() -> tuple[str, str, str]:
    """A private CA and a wildcard certificate for *.sandbox.test (with the CA as its chain)."""
    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("CI Root")).issuer_name(name("CI Root"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(name(f"*.{DOMAIN}")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"*.{DOMAIN}")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    p = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    k = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    return p(leaf) + p(ca), k, p(ca)


# --------------------------------------------------------------------------- the system agent, pointed here

caddy_proc: list[subprocess.Popen] = []
real_run = sysagent.run


def fake_run(cmd, timeout=3600, check=True, input=None):
    """`systemctl restart caddy.service` starts our Caddy process instead; everything else runs for real."""
    if cmd[:2] == ["systemctl", "restart"] and cmd[2] == "caddy.service":
        for p in caddy_proc:
            p.terminate()
            p.wait(30)
        caddy_proc.clear()
        log = open(work / "caddy.log", "a")
        env = {**os.environ, **sysagent.read_env(sysagent.P.caddy_env)}
        caddy_proc.append(subprocess.Popen(["caddy", "run", "--config", str(sysagent.P.caddyfile), "--adapter", "caddyfile"],
                                           stdout=log, stderr=log, env=env))
        time.sleep(3)
        if caddy_proc[0].poll() is not None:
            raise sysagent.AgentError("caddy exited: " + (work / "caddy.log").read_text()[-2000:])
        return ""
    return real_run(cmd, timeout=timeout, check=check, input=input)


sysagent.run = fake_run
sysagent.P = sysagent.Paths(https_dir=work / "system", caddyfile=work / "Caddyfile", caddy_env=work / "caddy.env",
                            appliance_env=work / "appliance.env", web_env=work / "web.env", run=work / "run")
(work / "web.env").write_text("CONTAINERIZER_PUBLIC_URL=https://cz.example.org\n")
# the appliance's Caddyfile, with the ports moved for an unprivileged run and the import pointed here
appliance_caddyfile = (Path(__file__).parents[1] / "rootfs/etc/caddy/Caddyfile").read_text()
assert "import /var/lib/containerizer/system/sandbox-https*.caddy" in appliance_caddyfile
(work / "Caddyfile").write_text(
    appliance_caddyfile.replace("http_port 8081", f"http_port 8081\n\thttps_port {PORT}\n\tskip_install_trust")
    .replace("/var/lib/containerizer/system/", f"{work}/system/"))
(work / "caddy.env").write_text("CZ_SITES=https://cz.example.org\nCZ_CADDY_TLS=internal\nCZ_CADDY_ACME=\n")
(work / "system").mkdir()

step("the appliance's Caddyfile is valid without a sandbox domain (the import matches nothing)")
sysagent._caddy(check_only=True)

step("Traefik from the appliance's HelmChartConfig")
wait("Traefik service at the fixed address",
     lambda: kubectl("-n", "kube-system", "get", "svc", "traefik", "-o", "jsonpath={.spec.clusterIP} {.spec.type}",
                     check=False) == f"{TRAEFIK_ADDR} ClusterIP", 600)
wait("Traefik running", lambda: "condition met" in kubectl("-n", "kube-system", "wait", "--for=condition=Available",
                                                           "deploy/traefik", "--timeout=10s", check=False), 600)
wait("TLSStore CRD", lambda: kubectl("get", "crd", "tlsstores.traefik.io", "-o", "name", check=False).strip(), 300)

step("an administrator saves the domain and certificate (the system agent's request)")
cert_pem, key_pem, ca_pem = certs()
(work / "ca.pem").write_text(ca_pem)
settings = sysagent.save_sandbox_https({"do": "set", "domain": f"*.{DOMAIN}", "cert": cert_pem, "key": key_pem},
                                       "ci@example.org", "CI")
print(json.dumps({k: v for k, v in settings.items() if k != "cert"}))
assert sysagent.P.https(".key").stat().st_mode & 0o077 in (0, 0o040)
kubectl("-n", "kube-system", "get", "secret/containerizer-sandbox-tls", "tlsstores.traefik.io/default")

step("an app with the generated Ingress")
labels = {"app.kubernetes.io/name": "web", "app.kubernetes.io/part-of": "ci"}
docs = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ci"}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "ci", "labels": labels},
         "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
             "containers": [{"name": "web", "image": "docker.io/traefik/whoami:v1.10.1", "args": ["--port", "8080"],
                             "ports": [{"name": "http", "containerPort": 8080}],
                             "readinessProbe": {"httpGet": {"path": "/health", "port": "http"}}}]}}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "web", "namespace": "ci", "labels": labels},
         "spec": {"selector": labels, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}},
        {**ingress(DOMAIN, "ci", "web", labels)}]
docs[-1]["metadata"]["namespace"] = "ci"
kubectl("apply", "-f", "-", input=json.dumps({"apiVersion": "v1", "kind": "List", "items": docs}))
kubectl("-n", "ci", "rollout", "status", "deploy/web", "--timeout=300s")

url = f"https://web-ci.{DOMAIN}/"
step(f"{url} through Caddy and Traefik")
r = wait("the URL answers over HTTPS", lambda: (x := sandbox.check_url(url, "/", f"127.0.0.1:{PORT}", str(work / "ca.pem")))
         .ok and x, 180)
print(r)


def get(path: str, host: str) -> tuple[int, dict, str]:
    ctx = ssl.create_default_context(cafile=str(work / "ca.pem"))
    with socket.create_connection(("127.0.0.1", PORT), 10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        t.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := t.recv(65536):
            data += chunk
    head, _, body = data.decode(errors="replace").partition("\r\n\r\n")
    lines = head.split("\r\n")
    return int(lines[0].split()[1]), {k.lower(): v.strip() for k, _, v in (x.partition(":") for x in lines[1:])}, body


status, headers, body = get("/", f"web-ci.{DOMAIN}")
assert status == 200, (status, body)
assert headers.get("strict-transport-security", "").startswith("max-age="), headers
assert "server" not in headers, headers
assert "X-Forwarded-Proto: https" in body, body                     # the app knows it was HTTPS
assert f"Host: web-ci.{DOMAIN}" in body, body
print("ok: HSTS, no Server header, the app sees Host and X-Forwarded-Proto https")
status, _, _ = get("/", f"nothing-here.{DOMAIN}")
assert status == 404, status
print("ok: an unknown name under the domain is 404")
status, _, _ = get("/", "cz.example.org")
print(f"ok: the admin pages' site still answers ({status})")

step("Traefik itself serves the wildcard certificate (Caddy's upstream check)")
ctx = ssl.create_default_context(cafile=str(work / "ca.pem"))
with socket.create_connection((TRAEFIK_ADDR, 443), 10) as s, \
        ctx.wrap_socket(s, server_hostname=f"containerizer-edge.{DOMAIN}") as t:
    print("ok:", t.getpeercert()["subjectAltName"])

step("HTTP inside the cluster only redirects to HTTPS")
req = urllib.request.Request(f"http://{TRAEFIK_ADDR}/", headers={"Host": f"web-ci.{DOMAIN}"})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


try:
    urllib.request.build_opener(NoRedirect).open(req, timeout=10)
    raise SystemExit("HTTP was served without a redirect")
except urllib.error.HTTPError as ex:
    assert ex.code in (301, 308) and ex.headers["Location"].startswith(f"https://web-ci.{DOMAIN}"), (ex.code, ex.headers)
    print(f"ok: {ex.code} -> {ex.headers['Location']}")

step("turn it off")
sysagent.save_sandbox_https({"do": "remove"}, "ci@example.org", "CI")
assert not sysagent.P.https(".key").exists()
assert not kubectl("-n", "kube-system", "get", "secret/containerizer-sandbox-tls", "--ignore-not-found", "-o", "name").strip()
try:
    get("/", f"web-ci.{DOMAIN}")
    raise SystemExit("still served after turning it off")
except (ssl.SSLError, OSError) as ex:
    print(f"ok: no longer served ({type(ex).__name__})")
hist = sysagent.P.https("-history.jsonl").read_text()
assert "PRIVATE" not in hist and hist.count("\n") == 2
for p in caddy_proc:
    p.terminate()
print("\nALL SANDBOX HTTPS CHECKS PASSED")
sys.exit(0)
