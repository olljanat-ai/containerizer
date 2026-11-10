"""Package feeds that need a sign-in, for the builds of scanned code (docs/source-control.md#package-feeds).

Administrators register a NuGet, npm or Maven/Gradle feed and its token on Admin → Source control (credentials.py,
Purpose `feed`). The token never enters a build: the scan worker and the LLM queue runner each run this small HTTPS
proxy, and their builds get its address as HTTPS_PROXY (verify._build_env_args; the generated Dockerfiles already
pass a proxy on to dotnet, npm, Maven and Gradle).

- A CONNECT to a host with a registered feed is opened here: the proxy answers TLS with a certificate of its own
  CA (the builds trust it through the optional `ca` build secret the generated Dockerfiles read for TLS-inspecting
  corporate proxies; the bundle also holds the system's and the corporate CAs), checks the server's certificate
  itself, and adds the feed's Authorization header (Basic with the user name, else Bearer) to a request whose URL
  is under the feed's URL. Requests elsewhere on that host get no header.
- Any other CONNECT is a plain tunnel: the proxy sees nothing of it.
- The proxy runs with the worker's own network access, so it refuses what a build could not reach itself: this
  machine's own addresses, loopback, link-local and multicast addresses, and the networks of Docker's bridges and of
  the k3s cluster. Everything else stays subject to the appliance's DNS filter and egress firewall.
- One request per connection (Connection: close): the proxy reads only the first request's head.

The appliance's firewall lets Docker's bridges reach the proxy's port on the DNS filter's address
(sysagent.FEED_PROXY_PORTS); CONTAINERIZER_FEED_PROXY_LISTEN sets where it listens (default: docker0's address, any
free port).
"""
from __future__ import annotations

import base64
import datetime as _dt
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

LISTEN_ENV = "CONTAINERIZER_FEED_PROXY_LISTEN"
MAX_HEAD = 64 * 1024
IDLE = 300                      # seconds a connection may stay silent
SYSTEM_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")
K3S_NETS = ("10.42.0.0/16", "10.43.0.0/16")
BRIDGE_IFACES = re.compile(r"^(docker\d*|br-.*|cni\d*|flannel.*|veth.*|cali.*|vxlan.*)$")
HOP_HEADERS = (b"connection:", b"proxy-connection:", b"keep-alive:", b"proxy-authorization:")


class Denied(Exception):
    pass


@dataclass
class Feed:
    """A registered feed with its token opened: requests under `url` get the Authorization header."""
    kind: str
    url: str
    token: str = field(repr=False)
    username: str = ""
    cred: object = None          # credentials.Credential, to record how it went

    @property
    def hostport(self) -> str:
        return _hostport_key(self.url)

    @property
    def path(self) -> str:
        return urllib.parse.unquote(urllib.parse.urlsplit(self.url).path).rstrip("/").casefold()

    def header(self) -> bytes:
        if self.username:
            return b"Basic " + base64.b64encode(f"{self.username}:{self.token}".encode())
        return b"Bearer " + self.token.encode()

    def covers(self, path: str) -> bool:
        p = urllib.parse.unquote(path.split("?", 1)[0]).casefold()
        return not self.path or p == self.path or p.startswith(self.path + "/")


def _hostport_key(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").lower()
    port = u.port or 443
    return f"{host}:{port}"


# --------------------------------------------------------------------------- certificates

def _ca(folder: Path):
    """The proxy's CA (made once, kept in its folder, mode 600): (key, certificate)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    kf, cf = folder / "ca.key", folder / "ca.pem"
    if kf.exists() and cf.exists():
        key = serialization.load_pem_private_key(kf.read_bytes(), None)
        cert = x509.load_pem_x509_certificate(cf.read_bytes())
        if cert.not_valid_after_utc > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30):
            return key, cert
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Containerizer build feed proxy ({socket.gethostname()[:30]})")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    folder.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    finally:
        os.umask(old)
    return key, cert


def _leaf(ca_key, ca_cert, host: str) -> tuple[bytes, bytes]:
    """(certificate chain PEM, key PEM) for `host`, signed by the proxy's CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM)
    return pem, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())


# --------------------------------------------------------------------------- what may be reached

def _local_networks() -> tuple[set, list]:
    """(this machine's addresses, networks of its bridges: Docker, k3s) from `ip -j addr`."""
    addrs, nets = set(), []
    try:
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=10).stdout
        for itf in json.loads(out or "[]"):
            for a in itf.get("addr_info") or []:
                ip = ipaddress.ip_address(a["local"])
                addrs.add(ip)
                if BRIDGE_IFACES.match(itf.get("ifname") or ""):
                    nets.append(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
                    if (itf.get("ifname") or "").startswith(("cni", "flannel")):
                        nets += [ipaddress.ip_network(n) for n in K3S_NETS]
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        pass
    return addrs, nets


class Policy:
    """Which addresses the proxy refuses to connect to (refreshed once a minute)."""

    def __init__(self, allow_local: bool = False):
        self.allow_local = allow_local          # tests only: a feed on this machine
        self._at, self._addrs, self._nets = 0.0, set(), []

    def check(self, ip) -> None:
        ip = ipaddress.ip_address(ip)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if self.allow_local:
            return
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise Denied(f"{ip} is not reachable from builds")
        if time.monotonic() - self._at > 60:
            self._addrs, self._nets = _local_networks()
            self._at = time.monotonic()
        if ip in self._addrs or any(ip in n for n in self._nets):
            raise Denied(f"{ip} is this machine or one of its container networks")


def _parse_target(target: str) -> tuple[str, int]:
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\]:(\d{1,5})|([A-Za-z0-9.\-_]{1,253}):(\d{1,5})", target)
    if not m:
        raise Denied("CONNECT needs host:port")
    host, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    if not 0 < int(port) < 65536:
        raise Denied("bad port")
    return host.lower().rstrip("."), int(port)


def _read_head(sock, limit: int = MAX_HEAD) -> tuple[bytes, bytes]:
    """The request or response head (up to and including the blank line), and what came after it."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(16384)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise Denied("head too long")
    i = buf.find(b"\r\n\r\n")
    return (buf[:i + 4], buf[i + 4:]) if i >= 0 else (buf, b"")


def rewrite(head: bytes, feeds: list[Feed]) -> tuple[bytes, Feed | None]:
    """The first request's head with the feed's Authorization header (when its URL is under a feed) and
    Connection: close. Hop-by-hop headers go; the client's own Authorization goes only where a feed's replaces it."""
    lines = head.rstrip(b"\r\n").split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3:
        raise Denied("not an HTTP request")
    target = parts[1].decode("latin-1")
    path = urllib.parse.urlsplit(target).path if "://" in target else target
    feed = max((f for f in feeds if f.covers(path)), key=lambda f: len(f.path), default=None)
    keep = [ln for ln in lines[1:] if ln and not ln.lower().startswith(HOP_HEADERS)
            and not (feed and ln.lower().startswith(b"authorization:"))]
    if feed:
        keep.append(b"Authorization: " + feed.header())
    keep.append(b"Connection: close")
    return b"\r\n".join([lines[0], *keep]) + b"\r\n\r\n", feed


# --------------------------------------------------------------------------- the proxy

class FeedProxy:
    def __init__(self, folder: str | Path, listen: str = "", log=print, policy: Policy | None = None,
                 upstream_cafile: str | None = None):
        self.folder = Path(folder)
        self.log = log
        self.policy = policy or Policy()
        self.feeds: list[Feed] = []
        self.results: dict[int, str] = {}        # Credential id -> how its last request went
        self._lock = threading.Lock()
        self._ctx: dict[str, ssl.SSLContext] = {}
        self.ca_key, self.ca_cert = _ca(self.folder)
        host, _, port = (listen or "").rpartition(":") if listen else ("", "", "")
        host = host.strip("[]") or _docker0() or "127.0.0.1"
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(fam, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, int(port or 0)))
        self.sock.listen(128)
        self.address = f"{host}:{self.sock.getsockname()[1]}" if fam == socket.AF_INET else \
            f"[{host}]:{self.sock.getsockname()[1]}"
        self.url = f"http://{self.address}"
        self.upstream = ssl.create_default_context()
        self.upstream.set_alpn_protocols(["http/1.1"])
        for extra in (upstream_cafile, os.environ.get("CONTAINERIZER_CA_BUNDLE")):
            if extra and os.path.isfile(extra):
                self.upstream.load_verify_locations(extra)
        self.bundle = self._write_bundle()
        threading.Thread(target=self._serve, name="feed-proxy", daemon=True).start()

    # -- settings ----------------------------------------------------------------------------

    def set_feeds(self, feeds: list[Feed]) -> None:
        with self._lock:
            self.feeds = list(feeds)
            self.results = {}

    def hosts(self) -> set[str]:
        return {f.hostport.rsplit(":", 1)[0] for f in self.feeds}

    def _write_bundle(self) -> Path:
        """System CAs + the corporate bundle + this proxy's CA: the builds' `ca` secret (it replaces their store)."""
        from cryptography.hazmat.primitives import serialization
        parts = []
        system = next((p for p in SYSTEM_BUNDLES if os.path.isfile(p)), None)
        if system is None:
            try:
                import certifi
                system = certifi.where()
            except ImportError:
                pass
        for p in (system, os.environ.get("CONTAINERIZER_CA_BUNDLE")):
            if p and os.path.isfile(p):
                parts.append(Path(p).read_text(errors="replace").strip())
        parts.append(self.ca_cert.public_bytes(serialization.Encoding.PEM).decode().strip())
        out = self.folder / "ca-bundle.pem"
        out.write_text("\n".join(dict.fromkeys(parts)) + "\n")
        return out

    def _server_ctx(self, host: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._ctx.get(host)
            if ctx:
                return ctx
        pem, key = _leaf(self.ca_key, self.ca_cert, host)
        import tempfile
        with tempfile.TemporaryDirectory(dir=self.folder) as d:
            (Path(d) / "c.pem").write_bytes(pem)
            (Path(d) / "k.pem").write_bytes(key)
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(str(Path(d) / "c.pem"), str(Path(d) / "k.pem"))
        ctx.set_alpn_protocols(["http/1.1"])
        with self._lock:
            self._ctx[host] = ctx
        return ctx

    # -- connections -------------------------------------------------------------------------

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _answer(self, conn, code: int, text: str) -> None:
        try:
            conn.sendall(f"HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        except OSError:
            pass

    def _connect(self, host: str, port: int):
        """A TCP connection to host:port (through the worker's own HTTPS proxy, if it has one), refused for
        addresses builds may not reach."""
        upstream_proxy = _upstream_proxy(host)
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            if not upstream_proxy or host == "localhost":
                raise
            infos = []                          # only the corporate proxy can resolve it
        if not infos and not upstream_proxy:
            raise Denied(f"{host} does not resolve")
        for *_, sa in infos:
            self.policy.check(sa[0])
        if upstream_proxy:
            u = urllib.parse.urlsplit(upstream_proxy)
            s = socket.create_connection((u.hostname, u.port or 8080), timeout=30)
            target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            head, rest = _read_head(s)
            if not re.match(rb"HTTP/1\.[01] 200", head) or rest:
                s.close()
                raise OSError(f"the upstream proxy answered {head[:40]!r}")
            s.settimeout(IDLE)
            return s
        err = None
        for fam, typ, proto, _, sa in infos:
            s = socket.socket(fam, typ, proto)
            s.settimeout(30)
            try:
                s.connect(sa)
                s.settimeout(IDLE)
                return s
            except OSError as ex:
                err = ex
                s.close()
        raise err or OSError(f"cannot connect to {host}:{port}")

    def _handle(self, conn) -> None:
        conn.settimeout(IDLE)
        up = None
        try:
            head, rest = _read_head(conn)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            if len(parts) != 3 or parts[0].upper() != "CONNECT":
                return self._answer(conn, 405, "Only CONNECT (HTTPS) goes through this proxy")
            host, port = _parse_target(parts[1])
            try:
                up = self._connect(host, port)
            except Denied as ex:
                self.log(f"feed proxy: refused {host}:{port}: {ex}")
                return self._answer(conn, 403, "Forbidden")
            except OSError as ex:
                return self._answer(conn, 502, f"Bad Gateway ({type(ex).__name__})")
            with self._lock:
                feeds = [f for f in self.feeds if f.hostport == f"{host}:{port}"]
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if not feeds:
                if rest:
                    up.sendall(rest)
                return _splice(conn, up)
            client = self._server_ctx(host).wrap_socket(conn, server_side=True)
            upstream = self.upstream.wrap_socket(up, server_hostname=host)
            req, more = _read_head(client)
            if not req:
                return
            method = req.split(b" ", 1)[0].upper()
            req, feed = rewrite(req, feeds)
            body = _body(client, req, more)
            upstream.sendall(req + body)
            self._relay(client, upstream, feed, host, method)
        except (Denied, OSError, ssl.SSLError) as ex:
            if not isinstance(ex, (ConnectionResetError, BrokenPipeError, TimeoutError)):
                self.log(f"feed proxy: {type(ex).__name__}: {str(ex)[:200]}")
        finally:
            for s in (conn, up):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass

    def _relay(self, client, upstream, feed: Feed | None, host: str, method: bytes = b"GET") -> None:
        """The answer, in this thread only (an SSL socket is not used from two threads): its head with
        Connection: close, then its body by its length, or until the server closes."""
        head, rest = _read_head(upstream)
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        code = int(m.group(1)) if m else 0
        if feed is not None and feed.cred is not None:
            with self._lock:
                if code in (401, 403):
                    self.results[feed.cred.id] = f"failed: HTTP {code} from {host}"
                elif code and not self.results.get(feed.cred.id, "").startswith("failed"):
                    self.results[feed.cred.id] = "ok: used by the builds"
        if not m:
            client.sendall(head + rest)
            return _drain(upstream, client, None)
        lines = head.rstrip(b"\r\n").split(b"\r\n")
        keep = [ln for ln in lines[1:] if ln and not ln.lower().startswith(HOP_HEADERS)]
        client.sendall(b"\r\n".join([lines[0], *keep, b"Connection: close"]) + b"\r\n\r\n")
        length = _header(keep, b"content-length")
        if method == b"HEAD" or code in (204, 304) or 100 <= code < 200:
            return
        chunked = b"chunked" in (_header(keep, b"transfer-encoding") or b"").lower()
        _drain(upstream, client, None if chunked or length is None or not length.isdigit() else int(length), rest)


def _header(lines: list, name: bytes) -> bytes | None:
    for ln in lines:
        k, _, v = ln.partition(b":")
        if k.strip().lower() == name:
            return v.strip()
    return None


def _body(sock, head: bytes, more: bytes) -> bytes:
    """A request's body: Content-Length bytes (requests here are GETs, sometimes a small POST)."""
    lines = head.rstrip(b"\r\n").split(b"\r\n")[1:]
    n = _header(lines, b"content-length")
    if n is None or not n.isdigit():
        return more
    n = int(n)
    if n > 64 * 1024 * 1024:
        raise Denied("request body too large")
    while len(more) < n:
        chunk = sock.recv(min(65536, n - len(more)))
        if not chunk:
            break
        more += chunk
    return more


def _drain(src, dst, length: int | None, first: bytes = b"") -> None:
    """Copy src to dst: `length` bytes, or until src closes (a chunked answer: the server closes after it, as the
    request asked)."""
    sent, data = 0, first
    while True:
        if data:
            if length is not None:
                data = data[:length - sent]
            dst.sendall(data)
            sent += len(data)
            if length is not None and sent >= length:
                return
        try:
            data = src.recv(65536)
        except (OSError, ssl.SSLError):
            return
        if not data:
            return


def _splice(a, b) -> None:
    """Copy both ways until either side closes, then close both (one request per connection: the server closes
    after its answer, a tunnel's client after its last one)."""
    done = threading.Event()

    def pump(src, dst):
        try:
            while not done.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            done.set()

    threading.Thread(target=pump, args=(b, a), daemon=True).start()
    threading.Thread(target=pump, args=(a, b), daemon=True).start()
    done.wait()
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass
        try:
            s.close()
        except OSError:
            pass


def _upstream_proxy(host: str) -> str | None:
    """The worker's own HTTPS proxy (a corporate one) for host, unless NO_PROXY covers it."""
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy:
        return None
    for x in (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(","):
        x = x.strip().lstrip(".").lower()
        if x == "*" or (x and (host == x or host.endswith("." + x))):
            return None
    return proxy if "://" in proxy else f"http://{proxy}"


def _docker0() -> str | None:
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show", "docker0"], capture_output=True, text=True,
                             timeout=10).stdout
        for itf in json.loads(out or "[]"):
            for a in itf.get("addr_info") or []:
                return a["local"]
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        pass
    return None


# --------------------------------------------------------------------------- the builds' side

_PROXY: dict = {"proxy": None}


def use(feeds: list[Feed], folder: str | Path, log=print) -> FeedProxy | None:
    """Serve these feeds to the builds of this process (and the processes it forks): starts the proxy the first time
    feeds are registered. No feeds: the builds go on as before (the proxy, if started, serves none)."""
    p = _PROXY["proxy"]
    if p is None and feeds:
        try:
            p = _PROXY["proxy"] = FeedProxy(Path(folder) / "feed-proxy", os.environ.get(LISTEN_ENV, ""), log=log)
            log(f"feed proxy: listening on {p.address} for the builds")
        except (OSError, ValueError) as ex:
            log(f"feed proxy: cannot listen ({type(ex).__name__}: {ex}); builds get no feed credentials")
            return None
    if p is not None:
        p.set_feeds(feeds)
    return p


def active() -> FeedProxy | None:
    """The proxy the builds go through, when it serves at least one feed."""
    p = _PROXY["proxy"]
    return p if p is not None and p.feeds else None


def build_proxy_env(no_proxy: str | None) -> dict | None:
    """For a build when feeds are served: HTTPS_PROXY (this proxy), NO_PROXY without the feeds' hosts (they must go
    through it), and the CA bundle for the `ca` secret. None otherwise."""
    p = active()
    if p is None:
        return None
    hosts = p.hosts()
    no = ",".join(x for x in (no_proxy or "").split(",")
                  if x.strip() and not any(h == x.strip().lstrip(".").lower() or h.endswith("." + x.strip().lstrip(".").lower())
                                          for h in hosts))
    return {"proxy": p.url, "no_proxy": no, "ca": str(p.bundle)}
