"""Source control tokens that administrators register on the admin pages (Admin → Source control).

Two kinds, never mixed:

- **read**: a read-only token for one Azure DevOps organization (or Azure DevOps Server collection),
  GitHub organization or GitLab group, on github.com / gitlab.com / dev.azure.com or a self-hosted
  server. An organization scan only runs for an organization that has one: there is no anonymous
  access, and a token is never sent for a repository outside its organization.
- **write**: a token that can push to one output repository, where the generated Dockerfiles,
  manifests and GitOps files are committed. It is chosen by the repository's URL, never by its host or
  organization, so it can live in the same organization as the scanned repositories; it is never used
  to list or clone them, and the output repository itself is never scanned.

Tokens are sealed for the scan worker's public key (X25519, HKDF-SHA256, AES-256-GCM, with the
credential's purpose and scope as associated data). The web UI holds only the public key: it can seal
a token an administrator enters but cannot open it, nothing shows a token again after it was saved,
and the admin database role cannot even read the sealed value back. Only the worker, with the private
key (CONTAINERIZER_CREDENTIAL_KEY_FILE), opens them, just before a run. A sealed token moved to
another organization, repository or purpose does not open.

Create the key pair with `containerizer credentials keygen` (the appliance does it at first boot).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import urllib.parse
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

PRIVATE_KEY_ENV = "CONTAINERIZER_CREDENTIAL_KEY_FILE"            # the scan worker
PUBLIC_KEY_ENV = "CONTAINERIZER_CREDENTIAL_PUBLIC_KEY_FILE"      # the web UI
PURPOSES = ("read", "write")
MAGIC = b"CZ1"
INFO = b"containerizer source control token v1"
TOKEN_RE = re.compile(r"[\x21-\x7e]{8,1000}")                       # printable ASCII, no spaces
GIT_USERNAMES = {"github": "x-access-token", "gitlab": "oauth2", "azure-devops": "pat"}
PROVIDER_TEXT = {"azure-devops": "Azure DevOps", "github": "GitHub", "gitlab": "GitLab"}
CLOUD = {"github": "https://api.github.com", "gitlab": "https://gitlab.com", "azure-devops": "https://dev.azure.com"}


class CredentialError(RuntimeError):
    pass


# --------------------------------------------------------------------------- keys and sealing

def _x25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    except ImportError as ex:                       # PyJWT[crypto] in requirements.txt brings it
        raise CredentialError("the 'cryptography' package is needed for source control tokens") from ex
    return X25519PrivateKey, X25519PublicKey


def _raw_public(pub) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pub) -> str:
    """16 hex characters naming a public key; stored next to each sealed token."""
    return hashlib.sha256(_raw_public(pub)).hexdigest()[:16]


def keygen(private_path: str | Path, public_path: str | Path) -> str:
    """Write a new key pair (private key mode 600, never overwritten). Returns the key id."""
    from cryptography.hazmat.primitives import serialization
    priv_cls, _ = _x25519()
    private_path, public_path = Path(private_path), Path(public_path)
    for p in (private_path, public_path):
        if p.exists():
            raise CredentialError(f"{p} exists: keeping it (tokens sealed for it would no longer open)")
    k = priv_cls.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = k.public_key()
    public_path.write_bytes(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key_id(pub)


def load_public(path: str | Path):
    from cryptography.hazmat.primitives import serialization
    _, pub_cls = _x25519()
    try:
        k = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as ex:
        raise CredentialError(f"credential public key {path}: {type(ex).__name__}") from None
    if not isinstance(k, pub_cls):
        raise CredentialError(f"credential public key {path}: not an X25519 key (make one with containerizer credentials keygen)")
    return k


def load_private(path: str | Path):
    from cryptography.hazmat.primitives import serialization
    priv_cls, _ = _x25519()
    p = Path(path)
    try:
        mode = p.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise CredentialError(f"credential key {path}: readable by others; chmod 600 it")
        k = serialization.load_pem_private_key(p.read_bytes(), password=None)
    except OSError as ex:
        raise CredentialError(f"credential key {path}: {ex.strerror or type(ex).__name__}") from None
    except ValueError:
        raise CredentialError(f"credential key {path}: not a PEM private key") from None
    if not isinstance(k, priv_cls):
        raise CredentialError(f"credential key {path}: not an X25519 key (make one with containerizer credentials keygen)")
    return k


def _aead_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub, info=INFO).derive(shared)


def binding(purpose: str, provider: str, api_url: str | None, scope: str) -> bytes:
    """Associated data of a sealed token: what it is for. A token sealed for one organization, output
    repository or purpose does not open for another."""
    return "\n".join(("containerizer-credential", purpose, provider, server_key(provider, api_url),
                      scope_key(purpose, scope))).encode()


def seal(pub, token: str, aad: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    priv_cls, _ = _x25519()
    eph = priv_cls.generate()
    eph_pub = _raw_public(eph.public_key())
    key = _aead_key(eph.exchange(pub), eph_pub, _raw_public(pub))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, token.encode(), aad)
    return base64.b64encode(MAGIC + eph_pub + nonce + ct).decode()


def unseal(priv, sealed: str, aad: bytes) -> str:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _, pub_cls = _x25519()
    try:
        blob = base64.b64decode(sealed, validate=True)
    except (ValueError, TypeError):
        raise CredentialError("the sealed token is damaged") from None
    if len(blob) < 3 + 32 + 12 + 16 or blob[:3] != MAGIC:
        raise CredentialError("the sealed token is damaged")
    eph_pub, nonce, ct = blob[3:35], blob[35:47], blob[47:]
    key = _aead_key(priv.exchange(pub_cls.from_public_bytes(eph_pub)), eph_pub, _raw_public(priv.public_key()))
    try:
        return AESGCM(key).decrypt(nonce, ct, aad).decode()
    except InvalidTag:
        raise CredentialError("the token does not open with this worker's key, or was saved for another "
                              "organization or repository: enter it again") from None


def check_token_text(token: str) -> str | None:
    """Why a pasted token is not acceptable, or None."""
    if not token:
        return "Enter the token"
    if not TOKEN_RE.fullmatch(token):
        return "The token must be 8 to 1000 printable characters without spaces"
    return None


# --------------------------------------------------------------------------- what a token covers

def _split(url: str) -> tuple[str, str, str]:
    """(scheme, host[:port], path) in a comparable form: lower-case scheme and host, no user info,
    percent-decoded path without a trailing slash."""
    u = urllib.parse.urlsplit(url.strip())
    host = (u.hostname or "").lower() + (f":{u.port}" if u.port else "")
    path = urllib.parse.unquote(u.path).rstrip("/")
    return u.scheme.lower(), host, path


def server_key(provider: str, api_url: str | None) -> str:
    """The server a credential or scan talks to: empty for the cloud service, else its normalised URL."""
    if not api_url:
        return ""
    s, h, p = _split(api_url)
    url = f"{s}://{h}{p}"
    return "" if url == CLOUD.get(provider) else url.casefold()


def scope_key(purpose: str, scope: str) -> str:
    return repo_key(scope) if purpose == "write" else scope.strip().strip("/").casefold()


def repo_key(url: str) -> str:
    """An https repository URL in a comparable form: https://host/path (no .git, no trailing slash, case folded)."""
    s, h, p = _split(url)
    return f"{s}://{h}{p.removesuffix('.git')}".casefold()


def host_of(provider: str, api_url: str | None) -> str:
    """The host a read credential's token is sent to (API and clones)."""
    if not server_key(provider, api_url):
        return {"github": "github.com", "gitlab": "gitlab.com", "azure-devops": "dev.azure.com"}[provider]
    return _split(api_url)[1]


def org_prefixes(provider: str, org: str, api_url: str | None) -> list[tuple[str, str]]:
    """(host, path prefix) pairs the repositories of an organization live under, case folded. A clone
    URL must be under one of them for the organization's token to be sent with it."""
    org = org.strip().strip("/").casefold()
    if not server_key(provider, api_url):
        if provider == "github":
            return [("github.com", f"/{org}")]
        if provider == "gitlab":
            return [("gitlab.com", f"/{org}")]
        return [("dev.azure.com", f"/{org}"), (f"{org}.visualstudio.com", "")]
    _, h, p = _split(api_url)
    p = p.casefold()
    if provider == "github":
        p = p.removesuffix("/api/v3")             # GitHub Enterprise Server: the API is under /api/v3
    return [(h, f"{p}/{org}")]


def in_org(url: str, provider: str, org: str, api_url: str | None) -> bool:
    """True when `url` is an https URL of a repository in the organization (on a path boundary)."""
    s, h, p = _split(url)
    if s != "https" and not (s == "http" and h.split(":")[0] in ("localhost", "127.0.0.1")):
        return False
    p = p.casefold()
    for host, prefix in org_prefixes(provider, org, api_url):
        if h == host and p.startswith(prefix + "/"):
            return True
    return False


def same_repo(a: str, b: str) -> bool:
    return bool(a and b) and repo_key(a) == repo_key(b)


def guess_provider(url: str) -> str | None:
    h = _split(url)[1]
    if h == "github.com":
        return "github"
    if h == "gitlab.com":
        return "gitlab"
    if h == "dev.azure.com" or h.endswith(".visualstudio.com"):
        return "azure-devops"
    return None


# --------------------------------------------------------------------------- the registered credentials

@dataclass
class Credential:
    id: int
    purpose: str
    provider: str
    api_url: str | None
    scope: str                       # organization (read) or repository URL (write)
    enabled: bool = True
    expires_on: date | None = None
    key_id: str = ""
    note: str = ""
    sealed: str = field(default="", repr=False)
    token: str | None = field(default=None, repr=False)     # opened by the worker; None elsewhere
    error: str = ""                                          # why it did not open

    @property
    def host(self) -> str:
        return host_of(self.provider, self.api_url) if self.purpose == "read" else _split(self.scope)[1]

    @property
    def username(self) -> str:
        return GIT_USERNAMES[self.provider]

    @property
    def label(self) -> str:
        where = f" ({self.host})" if self.purpose == "read" and self.api_url else ""
        return f"{PROVIDER_TEXT.get(self.provider, self.provider)} {self.scope}{where}"

    def expired(self, today: date | None = None) -> bool:
        return bool(self.expires_on) and self.expires_on < (today or date.today())

    def aad(self) -> bytes:
        return binding(self.purpose, self.provider, self.api_url, self.scope)

    @classmethod
    def from_row(cls, r: dict) -> "Credential":
        return cls(id=int(r["CredentialId"]), purpose=r["Purpose"], provider=r["Provider"], api_url=r.get("ApiUrl"),
                   scope=r["Scope"], enabled=bool(r.get("Enabled", True)), expires_on=r.get("ExpiresOn"),
                   key_id=(r.get("KeyId") or "").strip(), note=r.get("Note") or "", sealed=r.get("TokenSealed") or "")


class Credentials:
    """The registered credentials, with lookups by what a scan needs."""

    def __init__(self, items: list[Credential]):
        self.items = items

    def read_for(self, provider: str, api_url: str | None, org: str) -> Credential | None:
        sk, ok = server_key(provider, api_url), scope_key("read", org or "")
        for c in self.items:
            if c.purpose == "read" and c.enabled and c.provider == provider and server_key(c.provider, c.api_url) == sk \
                    and scope_key("read", c.scope) == ok:
                return c
        return None

    def write_for(self, url: str | None) -> Credential | None:
        if not url:
            return None
        k = repo_key(url)
        for c in self.items:
            if c.purpose == "write" and c.enabled and repo_key(c.scope) == k:
                return c
        return None

    def hosts(self) -> set[str]:
        return {c.host.split(":")[0] for c in self.items if c.enabled}

    def problems(self, scan: dict, public_key_id: str | None = None, today: date | None = None) -> list[str]:
        """What keeps a scan from getting the tokens it needs (empty when it has them)."""
        PROVIDERS = PROVIDER_TEXT
        out = []
        prov, org = scan.get("Provider"), scan.get("Organization") or ""
        name = f"{PROVIDERS.get(prov, prov)} organization {org}" + \
            (f" on {host_of(prov, scan.get('ApiUrl'))}" if scan.get("ApiUrl") and prov in PROVIDERS else "")
        read = self.read_for(prov, scan.get("ApiUrl"), org) if prov in PROVIDERS else None
        write = self.write_for(scan.get("OutputRepo"))
        if prov in PROVIDERS and not read:
            out.append(f"no read-only token is registered for {name}: add one under Source control "
                       "(organizations without one are never scanned)")
        if scan.get("OutputRepo") and not write:
            out.append(f"no write token is registered for the output repository {scan['OutputRepo']}: add one under "
                       "Source control")
        for c, what in ((read, "read-only token"), (write, "output repository token")):
            if not c:
                continue
            if c.expired(today):
                out.append(f"the {what} for {c.scope} expired on {c.expires_on:%Y-%m-%d}: enter a new one")
            if c.error:
                out.append(f"the {what} for {c.scope}: {c.error}")
            elif public_key_id and c.key_id and c.key_id != public_key_id:
                out.append(f"the {what} for {c.scope} was saved for another worker key: enter it again")
        if read and write and read.token and write.token and read.token == write.token:
            out.append("the output repository's write token is also the organization's read-only token: register a "
                       "separate read-only token for scanning")
        return out


SELECT_COLS = ("CredentialId, Purpose, Provider, ApiUrl, Host, Scope, Note, Enabled, ExpiresOn, KeyId, TokenSetAt, "
               "TokenSetBy, CreatedAt, LastUsedAt, LastResult")


def load(conn, private_key=None, include_disabled: bool = False) -> Credentials:
    """The registered credentials. With the worker's private key, enabled ones are opened (token set,
    or error saying why not); without it, only what they are for (the admin pages)."""
    cur = conn.cursor(as_dict=True)
    cols = SELECT_COLS + (", TokenSealed" if private_key is not None else "")
    cur.execute(f"SELECT {cols} FROM cz.SourceCredential" + ("" if include_disabled else " WHERE Enabled = 1")
                + " ORDER BY Purpose, Provider, Scope")
    items = []
    for r in cur.fetchall():
        c = Credential.from_row(r)
        if private_key is not None and c.enabled:
            try:
                c.token = unseal(private_key, c.sealed, c.aad())
            except CredentialError as ex:
                c.error = str(ex)
        c.sealed = ""
        items.append(c)
    return Credentials(items)


def mark(conn, cred_id: int, result: str) -> None:
    """Record when and how the worker last used a credential (shown on the admin page)."""
    cur = conn.cursor()
    cur.execute("UPDATE cz.SourceCredential SET LastUsedAt = SYSUTCDATETIME(), LastResult = %s WHERE CredentialId = %s",
                (result[:1000], cred_id))
    conn.commit()


def private_key_from_env(env=None):
    env = os.environ if env is None else env
    path = (env.get(PRIVATE_KEY_ENV) or "").strip()
    if not path:
        raise CredentialError(f"the worker has no credential key: set {PRIVATE_KEY_ENV} to the private key made with "
                              "`containerizer credentials keygen`")
    return load_private(path)


def public_key_from_env(env=None):
    env = os.environ if env is None else env
    path = (env.get(PUBLIC_KEY_ENV) or "").strip()
    return load_public(path) if path else None


def main(args) -> int:
    """`containerizer credentials keygen`."""
    import sys
    try:
        kid = keygen(args.private, args.public)
    except CredentialError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    print(f"key {kid}: private key {args.private} (the scan worker only, {PRIVATE_KEY_ENV}), "
          f"public key {args.public} (the web UI, {PUBLIC_KEY_ENV})")
    return 0
