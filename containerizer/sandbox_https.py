"""HTTPS for the apps in the sandbox cluster: one wildcard domain and its certificate.

An administrator gives a wildcard domain (`*.sandbox.example.com`) and the matching certificate and
private key (Admin → Sandbox HTTPS on the appliance, docs/sandbox-https.md). Then:

- every generated component that serves HTTP gets an Ingress for `<component>-<app>.<domain>` (just
  `<app>.<domain>` when the component has the app's name), HTTPS only (see `ingress`);
- on the appliance, Caddy, which already answers on 443 for the web UI, answers for `*.<domain>` too
  with this certificate and passes the requests to Traefik in the k3s sandbox over TLS (Traefik's
  default certificate is the same one, a TLS Secret in kube-system), which routes them by host name to
  the app's Service;
- the sandbox health check opens each URL and the URL is shown on the application page and in
  sandbox/HEALTH.md.

One label per app host: a wildcard certificate covers exactly one label, so `web.myapp.<domain>` would
not be covered by `*.<domain>`. Names longer than a DNS label (63) are shortened with a hash.

Everything here is pure (no I/O): the web UI checks what an administrator pasted, the system agent
(root) checks it again before it writes anything, and the generator only needs the domain.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

DOMAIN_RE = re.compile(r"(?=.{4,200}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
LABEL_MAX = 63
MAX_CERT_BYTES = 32 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_CHAIN = 6
EXPIRY_WARN_DAYS = 30
# Traefik in the k3s sandbox: its Service gets this fixed address (HelmChartConfig in the OS image), so
# Caddy on the host can reach it. 10.43.0.0/16 is the k3s service network; .10 is CoreDNS.
TRAEFIK_ADDR = "10.43.0.80"
SECRET_NAME = "containerizer-sandbox-tls"
SECRET_NAMESPACE = "kube-system"
EDGE_LABEL = "containerizer-edge"        # the name Caddy asks Traefik's certificate for (inside the wildcard)
URL_ANNOTATION = "containerizer.io/url"
# labels the appliance itself uses under the domain: an app never gets one of them
RESERVED_LABELS = frozenset({EDGE_LABEL, "containerizer-idp"})

CERT_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
KEY_BLOCK = re.compile(r"-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----[A-Za-z0-9+/=\s]+?-----END \1-----")


class SandboxHttpsError(ValueError):
    pass


# --------------------------------------------------------------------------- names

def normalize_domain(text: str) -> str:
    """`*.sandbox.example.com`, `sandbox.example.com` or `.sandbox.example.com.` -> `sandbox.example.com`."""
    d = (text or "").strip().lower().rstrip(".")
    d = d.removeprefix("*.").removeprefix(".")
    if not DOMAIN_RE.fullmatch(d):
        raise SandboxHttpsError("Enter the wildcard domain as *.sandbox.example.com (letters, digits, hyphens, "
                                "at least two labels)")
    if d.endswith((".local", ".localhost", ".arpa")):
        raise SandboxHttpsError(f"{d} is not a domain browsers can reach the sandbox under")
    return d


def host_label(app: str, component: str) -> str:
    """The one DNS label of a component under the wildcard domain. `app` and `component` are the
    Kubernetes names (namespace and Service). Deterministic; at most 63 characters."""
    label = app if component == app else f"{component}-{app}"
    if len(label) > LABEL_MAX or label in RESERVED_LABELS:
        h = hashlib.sha256(f"{app}/{component}".encode()).hexdigest()[:8]
        label = label[:LABEL_MAX - 9].rstrip("-") + "-" + h
    return label


def host_for(domain: str, app: str, component: str) -> str:
    return f"{host_label(app, component)}.{domain}"


def covered(host: str, domain: str) -> bool:
    """True when the wildcard *.domain covers `host` (exactly one label more)."""
    host, domain = host.lower().rstrip("."), domain.lower()
    return host.endswith("." + domain) and "." not in host[: -len(domain) - 1]


# --------------------------------------------------------------------------- the certificate

@dataclass
class CertInfo:
    domain: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    fingerprint: str                  # SHA-256 of the leaf, hex with colons
    key_type: str
    chain_length: int
    names: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Checked:
    info: CertInfo
    cert_pem: str = field(repr=False)        # the chain, re-encoded (leaf first)
    key_pem: str = field(repr=False)         # PKCS#8, re-encoded


def _x509():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError as ex:              # PyJWT[crypto] in requirements.txt brings it
        raise SandboxHttpsError("the 'cryptography' package is needed to check certificates") from ex
    return x509, hashes, serialization, ec, rsa


def _utc(c, attr: str) -> datetime:
    v = getattr(c, attr + "_utc", None)              # cryptography >= 42
    return v if v is not None else getattr(c, attr).replace(tzinfo=timezone.utc)


def _name(n) -> str:
    try:
        return n.rfc4514_string()[:300]
    except Exception:                    # noqa: BLE001 - a name we cannot print is not a reason to refuse
        return "?"


def check(domain: str, cert_text: str, key_text: str, appliance_host: str | None = None,
          now: datetime | None = None) -> Checked:
    """Check what an administrator pasted: the domain, the certificate chain (leaf first) and its
    private key. Raises SandboxHttpsError with a sentence for the page; returns the re-encoded PEMs."""
    x509, hashes, serialization, ec, rsa = _x509()
    now = now or datetime.now(timezone.utc)
    domain = normalize_domain(domain)
    cert_text, key_text = (cert_text or "").strip(), (key_text or "").strip()
    if not cert_text:
        raise SandboxHttpsError("Paste the certificate (PEM, the server certificate first, then the intermediates)")
    if not key_text:
        raise SandboxHttpsError("Paste the private key (PEM)")
    if len(cert_text.encode()) > MAX_CERT_BYTES or len(key_text.encode()) > MAX_KEY_BYTES:
        raise SandboxHttpsError("The certificate or key is too large")
    if "ENCRYPTED PRIVATE KEY" in key_text or "Proc-Type: 4,ENCRYPTED" in key_text:
        raise SandboxHttpsError("The private key is protected with a password: export it without one "
                                "(openssl pkey -in key.pem -out plain.pem)")
    if "PRIVATE KEY" in cert_text:
        raise SandboxHttpsError("The certificate field contains a private key: paste the key in its own field")
    blocks = CERT_BLOCK.findall(cert_text)
    if not blocks:
        raise SandboxHttpsError("The certificate is not in PEM format (-----BEGIN CERTIFICATE-----)")
    if len(blocks) > MAX_CHAIN:
        raise SandboxHttpsError(f"At most {MAX_CHAIN} certificates: the server certificate and its intermediates")
    if len(KEY_BLOCK.findall(key_text)) != 1 or key_text.count("-----BEGIN ") != 1:
        raise SandboxHttpsError("Paste exactly one private key in PEM format (-----BEGIN PRIVATE KEY-----)")
    try:
        chain = [x509.load_pem_x509_certificate(b.encode()) for b in blocks]
    except ValueError:
        raise SandboxHttpsError("A certificate could not be read: check that it was copied completely") from None
    try:
        key = serialization.load_pem_private_key(KEY_BLOCK.search(key_text).group(0).encode(), password=None)
    except (ValueError, TypeError):
        raise SandboxHttpsError("The private key could not be read: check that it was copied completely") from None

    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise SandboxHttpsError(f"The RSA key has {key.key_size} bits: use at least 2048")
        key_type = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name not in ("secp256r1", "secp384r1"):
            raise SandboxHttpsError(f"The EC key uses {key.curve.name}: use P-256 or P-384, which every browser supports")
        key_type = {"secp256r1": "ECDSA P-256", "secp384r1": "ECDSA P-384"}[key.curve.name]
    else:
        raise SandboxHttpsError("Use an RSA (2048 bits or more) or ECDSA P-256/P-384 key")

    leaf = chain[0]
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if leaf.public_key().public_bytes(*spki) != key.public_key().public_bytes(*spki):
        raise SandboxHttpsError("The private key does not belong to the first certificate (the server certificate "
                                "must come first, then its intermediates)")
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    if f"*.{domain}" not in names:
        shown = ", ".join(names[:6]) or "no DNS names"
        raise SandboxHttpsError(f"The certificate does not cover *.{domain} (it has {shown})")
    try:
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise SandboxHttpsError("The first certificate is a CA certificate, not a server certificate")
    except x509.ExtensionNotFound:
        pass
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise SandboxHttpsError("The certificate is not for TLS servers (no serverAuth extended key usage)")
    except x509.ExtensionNotFound:
        pass
    nb, na = _utc(leaf, "not_valid_before"), _utc(leaf, "not_valid_after")
    if nb > now:
        raise SandboxHttpsError(f"The certificate is valid only from {nb:%Y-%m-%d %H:%M} UTC")
    if na <= now:
        raise SandboxHttpsError(f"The certificate expired on {na:%Y-%m-%d}")
    for c in chain:
        algo = c.signature_hash_algorithm
        if algo is not None and algo.name in ("md5", "sha1"):
            raise SandboxHttpsError(f"A certificate is signed with {algo.name.upper()}: browsers refuse it")
    for child, parent in zip(chain, chain[1:]):
        if child.issuer != parent.subject:
            raise SandboxHttpsError("The certificates are not in order: the server certificate first, then the "
                                    "certificate that issued it, and so on")
        try:
            child.verify_directly_issued_by(parent)
        except Exception:                # noqa: BLE001 - InvalidSignature, ValueError, TypeError
            raise SandboxHttpsError(f"{_name(child.subject)} is not signed by the next certificate in the chain") from None
    if appliance_host:
        h = appliance_host.lower().rstrip(".")
        if h == domain or h.endswith("." + domain):
            raise SandboxHttpsError(f"The appliance itself is {h}, inside {domain}: use a domain of its own for the "
                                    "sandbox apps, so they never share a host name with the admin pages")

    warnings = []
    if na - now < timedelta(days=EXPIRY_WARN_DAYS):
        warnings.append(f"expires in {(na - now).days} days")
    if len(chain) == 1 and leaf.issuer != leaf.subject:
        warnings.append("no intermediate certificates: browsers may not trust it unless the issuer is a root they know")
    info = CertInfo(domain=domain, subject=_name(leaf.subject), issuer=_name(leaf.issuer),
                    not_before=nb.isoformat(timespec="seconds"), not_after=na.isoformat(timespec="seconds"),
                    fingerprint=":".join(f"{b:02X}" for b in leaf.fingerprint(hashes.SHA256())),
                    key_type=key_type, chain_length=len(chain), names=names[:20], warnings=warnings)
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return Checked(info=info, cert_pem=pem, key_pem=key_pem)


# --------------------------------------------------------------------------- the generated Ingress

def ingress(domain: str, app: str, component: str, labels: dict, service_port: str = "http") -> dict:
    """An Ingress for one component at https://<label>.<domain>/, HTTPS only.

    - `spec.tls` names the host without a secretName: the ingress controller's default certificate
      (the wildcard) serves it, so the private key never has to be copied into the app's namespace,
      where the app's own reconciler could read it.
    - Traefik (k3s): only the websecure entry point, TLS on; its web entry point redirects every HTTP
      request to HTTPS (HelmChartConfig in the appliance image; docs/sandbox-https.md for other clusters).
    - ingress-nginx: ssl-redirect and force-ssl-redirect (HTTP -> HTTPS, 308), HSTS from its defaults.
    """
    host = host_for(domain, app, component)
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": component, "labels": labels, "annotations": {
            URL_ANNOTATION: f"https://{host}/",
            "traefik.ingress.kubernetes.io/router.entrypoints": "websecure",
            "traefik.ingress.kubernetes.io/router.tls": "true",
            "nginx.ingress.kubernetes.io/ssl-redirect": "true",
            "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
        }},
        "spec": {
            "tls": [{"hosts": [host]}],
            "rules": [{"host": host, "http": {"paths": [{
                "path": "/", "pathType": "Prefix",
                "backend": {"service": {"name": component, "port": {"name": service_port}}}}]}}],
        }}


# --------------------------------------------------------------------------- the appliance's Caddy

def caddy_site(domain: str, cert_file: str, key_file: str, trust_file: str, upstream: str = TRAEFIK_ADDR) -> str:
    """The Caddyfile site for *.<domain> (imported by /etc/caddy/Caddyfile). `domain` must have been
    through normalize_domain (it is checked again here: it goes into a configuration file)."""
    if not DOMAIN_RE.fullmatch(domain):
        raise SandboxHttpsError(f"not a domain: {domain!r}")
    for p in (cert_file, key_file, trust_file):
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", p):
            raise SandboxHttpsError(f"unexpected path {p!r}")
    return f"""# generated by containerizer.sysagent from Admin -> Sandbox HTTPS; do not edit
# The apps in the k3s sandbox: TLS with the administrators' wildcard certificate, then to Traefik in the
# cluster, again over TLS, checked against the same certificate.
*.{domain} {{
	tls {cert_file} {key_file}
	header {{
		-Server
		Strict-Transport-Security "max-age=31536000"
	}}
	reverse_proxy https://{upstream}:443 {{
		transport http {{
			tls_server_name {EDGE_LABEL}.{domain}
			tls_trusted_ca_certs {trust_file}
		}}
	}}
	log {{
		output stderr
		format console
	}}
}}
"""


# --------------------------------------------------------------------------- the appliance's settings

SETTINGS_ENV = "CONTAINERIZER_SANDBOX_HTTPS_FILE"
SETTINGS_FILE = "/var/lib/containerizer/system/sandbox-https.json"     # written by the system agent, no secrets


def load_settings(env=None) -> dict | None:
    """What the appliance's system agent published (domain, certificate details, the certificate chain
    file and the address Caddy answers on), or None when Sandbox HTTPS is not set up."""
    import json
    import os
    env = os.environ if env is None else env
    path = env.get(SETTINGS_ENV) or SETTINGS_FILE
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("enabled"):
        return None
    try:
        data["domain"] = normalize_domain(str(data.get("domain") or ""))
    except SandboxHttpsError:
        return None
    return data


def configured_domain(env=None) -> str:
    s = load_settings(env)
    return s["domain"] if s else ""
