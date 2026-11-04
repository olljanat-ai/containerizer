"""kubemg on the appliance (optional, CZ_KUBEMG=true; docs/appliance-admin.md#kubemg): connect the k3s sandbox cluster.

kubemg (https://kubemg.readthedocs.io/) is an audited console and kubectl gateway for Kubernetes clusters. On the
appliance it runs as a container behind Caddy at https://kubemg.<CZ_HOSTNAME>/ (containerizer-kubemg.service), and
its agent runs in the sandbox cluster (namespace kubemg-system) and dials back to that URL; no port is opened.

`sandbox()` (containerizer-kubemg-sandbox.service, after kubemg and k3s) registers the sandbox cluster through kubemg's
API in agent mode and applies the agent's manifest to k3s, with a host alias that sends the kubemg name to the node
(the sandbox's DNS filter does not resolve it; pods reach the appliance on 443 like any client). It signs in as the
bootstrap administrator with the generated password, which kubemg's setup wizard has the administrator change at
the first sign-in: so it registers once, on the first start, and later only checks that the agent is there.

While that password still works it also deletes the Helm chart repositories kubemg seeds on its first start
(`SEEDED_REPOS`): the appliance's outbound allow-list does not let it reach them, so their hourly sync only logs
warnings. A repository the administrator adds, or one whose address was changed, is kept.
"""
from __future__ import annotations

import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

API = "https://127.0.0.1:8444/api/v1"
# kubemg's loopback certificate is issued by the appliance's local CA (cz-firstboot)
LOOPBACK_CA = "/run/containerizer/kubemg/loopback-ca.pem"
CLUSTER = "sandbox"
NAMESPACE = "kubemg-system"
KUBECTL = ["/usr/bin/k3s", "kubectl"]
# the chart repositories kubemg 0.17 seeds on its first start, by name and address
SEEDED_REPOS = {
    "argo": "https://argoproj.github.io/argo-helm",
    "bitnami": "https://charts.bitnami.com/bitnami",
    "grafana": "https://grafana.github.io/helm-charts",
    "ingress-nginx": "https://kubernetes.github.io/ingress-nginx",
    "jetstack": "https://charts.jetstack.io",
    "prometheus-community": "https://prometheus-community.github.io/helm-charts",
}


class KubemgError(Exception):
    pass


def _call(method: str, path: str, token: str | None = None, body: dict | None = None, raw: bool = False,
          timeout: int = 30):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        ctx = ssl.create_default_context(cafile=LOOPBACK_CA) if API.startswith("https:") else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        raise KubemgError(f"{method} {path}: HTTP {e.code}: {e.read()[:300].decode(errors='replace')}") from None
    return data.decode() if raw else json.loads(data or b"{}")


def wait_up(seconds: int = 600, call=_call) -> None:
    end = time.monotonic() + seconds
    while True:
        try:
            call("POST", "/auth/login", body={"username": "", "password": ""})
            return
        except KubemgError:
            return                      # it answers (401): up
        except ssl.SSLError as ex:      # it answers, but the TLS handshake fails: waiting does not help
            raise KubemgError(f"kubemg answers on {API}, but the TLS handshake fails: {ex} (CA {LOOPBACK_CA})") from None
        except urllib.error.URLError as ex:
            if isinstance(ex.reason, ssl.SSLError):
                raise KubemgError(f"kubemg answers on {API}, but the TLS handshake fails: {ex.reason} "
                                  f"(CA {LOOPBACK_CA})") from None
            if time.monotonic() > end:
                raise KubemgError(f"kubemg did not answer on {API} in {seconds} s: {ex.reason}") from None
            time.sleep(5)
        except OSError:
            if time.monotonic() > end:
                raise KubemgError(f"kubemg did not answer on {API} in {seconds} s") from None
            time.sleep(5)


def login(username: str, password: str, call=_call) -> str | None:
    """A session token, or None when the password no longer works (changed in kubemg's setup wizard)."""
    try:
        out = call("POST", "/auth/login", body={"username": username, "password": password})
    except KubemgError as e:
        if "HTTP 401" in str(e):
            return None
        raise
    if not out.get("token"):           # a second factor is owed: not for an automated sign-in
        return None
    return out["token"]


def ensure_cluster(token: str, call=_call) -> dict:
    """The sandbox cluster in kubemg (agent mode), created when missing."""
    for c in call("GET", "/clusters", token).get("clusters") or []:
        if c.get("name") == CLUSTER:
            return c
    return call("POST", "/clusters", token, {"name": CLUSTER, "environment": "dev", "connection_mode": "agent"})


def drop_seeded_repos(token: str, call=_call) -> list[str]:
    """Delete the chart repositories kubemg seeded (unchanged ones only). Returns their names."""
    out = call("GET", "/helm/repositories", token)
    repos = out if isinstance(out, list) else out.get("repositories") or out.get("items") or []
    gone = []
    for r in repos:
        name, url = r.get("name"), (r.get("url") or "").rstrip("/")
        if name in SEEDED_REPOS and url == SEEDED_REPOS[name]:
            call("DELETE", f"/helm/repositories/{urllib.parse.quote(name)}", token)
            gone.append(name)
    return gone


def with_host_alias(manifest: str, host: str, ip: str) -> str:
    """The agent's manifest with hostAliases on its Deployment: <host> is the node's address."""
    docs = [d for d in yaml.safe_load_all(manifest) if d]
    found = False
    for d in docs:
        if d.get("kind") == "Deployment" and d.get("metadata", {}).get("name") == "kubemg-agent":
            spec = d["spec"]["template"]["spec"]
            spec["hostAliases"] = [a for a in spec.get("hostAliases") or [] if host not in a.get("hostnames", [])] + [
                {"ip": ip, "hostnames": [host]}]
            found = True
    if not found:
        raise KubemgError("the agent manifest has no kubemg-agent Deployment")
    return yaml.safe_dump_all(docs, sort_keys=False)


def _kubectl(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([*KUBECTL, *args], input=stdin, capture_output=True, text=True, timeout=300)


def agent_installed() -> bool:
    return _kubectl("-n", NAMESPACE, "get", "deployment", "kubemg-agent").returncode == 0


def node_ip() -> str:
    r = _kubectl("get", "nodes", "-o", "jsonpath={.items[0].status.addresses[?(@.type==\"InternalIP\")].address}")
    ip = r.stdout.strip().split()[0] if r.returncode == 0 and r.stdout.strip() else ""
    if not ip:
        raise KubemgError(f"the sandbox node's address is not known yet: {r.stderr.strip()[:200]}")
    return ip


def sandbox(host: str, password: str, username: str = "admin", call=_call, installed=agent_installed,
            apply=None, ip=node_ip, log=print) -> str:
    """Register the sandbox cluster and install kubemg's agent in it. Returns what it did."""
    done = installed()
    wait_up(call=call)
    token = login(username, password, call)
    if token is not None:
        try:
            gone = drop_seeded_repos(token, call)
        except KubemgError as e:            # not worth failing the registration for
            log(f"kubemg: the seeded chart repositories were not deleted: {e}")
        else:
            if gone:
                log(f"kubemg: deleted the seeded chart repositories {', '.join(gone)} (not on the outbound "
                    "allow-list); add your own in kubemg (Admin → Settings → Helm)")
    if done:
        return "the kubemg agent is installed in the sandbox cluster"
    if token is None:
        return ("kubemg's administrator password was changed (its setup wizard asks for that): the sandbox cluster was "
                "not registered by the appliance. Register it in kubemg (Admin → Clusters → Add, agent mode) and apply "
                "its manifest with `k3s kubectl apply -f`")
    c = ensure_cluster(token, call)
    manifest = call("GET", f"/clusters/{int(c['id'])}/kustomize?format=yaml", token, raw=True)
    doc = with_host_alias(manifest, host, ip())
    if apply is None:
        r = _kubectl("apply", "-f", "-", stdin=doc)
        if r.returncode != 0:
            raise KubemgError(f"kubectl apply: {r.stderr.strip()[:500]}")
    else:
        apply(doc)
    log(f"kubemg: cluster {CLUSTER} (#{int(c['id'])}) registered; its agent dials https://{host}")
    return f"the sandbox cluster is registered in kubemg as {CLUSTER} and its agent is installed"


def loopback_tls(folder: Path, group: int | None = None, days: int = 7300) -> bool:
    """kubemg's HTTPS certificate on loopback (KUBEMG_TLS_ENABLED=true; its setup refuses plain HTTP): a local CA
    that only Caddy trusts (ca.crt; its key ca.key, root only) and a certificate for 127.0.0.1 it issued
    (ssl/tls.crt, ssl/tls.key readable by kubemg's group). Made once: returns whether it made (or issued again) them.

    Both carry the key identifiers strict X.509 checking needs (Python 3.13's default, VERIFY_X509_STRICT: "Missing
    Authority Key Identifier"): certificates made before 0.9.6 lacked them, so the sandbox registration could not
    connect while Caddy (Go) could. Those are issued again with the same keys, so Caddy, which still holds the old
    CA certificate (same name and key), keeps trusting kubemg until it reloads. The modes and owners are set on
    every call, whatever the umask (cz-firstboot's is 077)."""
    import os
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    ssl_dir = folder / "ssl"
    files = (folder / "ca.crt", folder / "ca.key", ssl_dir / "tls.crt", ssl_dir / "tls.key")
    keys = None
    if all(f.is_file() and f.stat().st_size for f in files):
        if _strict_ok(folder / "ca.crt", ssl_dir / "tls.crt"):
            _loopback_tls_modes(folder, group)
            return False
        load = serialization.load_pem_private_key
        keys = (load((folder / "ca.key").read_bytes(), None), load((ssl_dir / "tls.key").read_bytes(), None))
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    ssl_dir.mkdir(mode=0o700, exist_ok=True)
    ca_key, key = keys or (ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1()))
    ca, cert = _loopback_certs(ca_key, key, days)

    def write(path: Path, data: bytes) -> None:
        path.unlink(missing_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

    pem = serialization.Encoding.PEM
    raw = dict(encoding=pem, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    if keys is None:
        write(folder / "ca.key", ca_key.private_bytes(**raw))
        write(ssl_dir / "tls.key", key.private_bytes(**raw))
    write(folder / "ca.crt", ca.public_bytes(pem))
    write(ssl_dir / "tls.crt", cert.public_bytes(pem))
    _loopback_tls_modes(folder, group)
    return True


def _loopback_certs(ca_key, key, days: int):
    """The CA certificate and kubemg's, with what strict X.509 checking requires: key identifiers on both (the
    CA's subject key identifier, kubemg's authority key identifier pointing at it), critical basic constraints and
    key usage."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    until = now + datetime.timedelta(days=days)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "containerizer kubemg loopback CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(until)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(ca_ski, critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(until)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return ca, cert


def _strict_ok(ca_path: Path, cert_path: Path) -> bool:
    """Whether the certificates carry the key identifiers strict X.509 checking needs."""
    from cryptography import x509
    try:
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        return True
    except (x509.ExtensionNotFound, ValueError, OSError):
        return False


def _loopback_tls_modes(folder: Path, group: int | None) -> None:
    """The modes of loopback_tls's files, set explicitly (mkdir and open modes are cut by the umask). The folder and
    the CA's key are root's; ssl/ (bind-mounted as kubemg's /etc/kubemg/ssl) and its key are open to kubemg's group
    only, its certificate to all."""
    import os
    ssl_dir = folder / "ssl"
    os.chmod(folder, 0o700)
    os.chmod(folder / "ca.key", 0o400)
    os.chmod(folder / "ca.crt", 0o644)
    if group is not None:
        os.chown(ssl_dir, -1, group)
        os.chown(ssl_dir / "tls.key", -1, group)
    os.chmod(ssl_dir, 0o750 if group is not None else 0o700)
    os.chmod(ssl_dir / "tls.crt", 0o644)
    os.chmod(ssl_dir / "tls.key", 0o440 if group is not None else 0o400)


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="python -m containerizer.kubemg")
    p.add_argument("command", choices=["sandbox", "loopback-tls"])
    p.add_argument("--host", help="kubemg's DNS name (the agent dials https://<host>)")
    p.add_argument("--password-file")
    p.add_argument("--dir", help="loopback-tls: the folder of the CA and of ssl/ (kubemg's /etc/kubemg/ssl)")
    p.add_argument("--group", type=int, help="loopback-tls: the group that may read the certificate's key")
    a = p.parse_args(argv)
    if a.command == "loopback-tls":
        if not a.dir:
            p.error("loopback-tls needs --dir")
        if loopback_tls(Path(a.dir), a.group):
            print(f"kubemg: made its loopback certificate in {a.dir}")  # else: its modes set again
        return 0
    if not a.host or not a.password_file:
        p.error("sandbox needs --host and --password-file")
    try:
        with open(a.password_file) as f:
            pw = f.read().strip()
        print(sandbox(a.host, pw))
        return 0
    except (KubemgError, OSError) as e:
        print(f"kubemg: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
