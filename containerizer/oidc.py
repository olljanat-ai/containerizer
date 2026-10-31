"""OpenID Connect sign-in for the web UI (Microsoft Entra ID, Okta, Keycloak, Google, ...).

Authorization code flow with PKCE (S256), state and nonce; the ID token's signature is checked against
the provider's published keys (JWKS), as are its issuer, audience, expiry and nonce. Sessions live in
the server's memory behind a random, HttpOnly, SameSite=Lax cookie (Secure, and __Host- prefixed, when
the public URL is https). Who may use the admin pages is an explicit allow-list: nobody is an admin
unless CONTAINERIZER_ADMINS names them. When CONTAINERIZER_VIEWERS is set, the read-only results pages
need sign-in too (an automatic redirect to the provider) and only the users it names, and the admins,
may see them; CONTAINERIZER_VIEW_AUDIT=true then also records who signed in and what they opened.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

SESSION_TTL = 8 * 3600        # absolute lifetime of a sign-in
IDLE_TTL = 3600               # signed out after an hour without requests
LOGIN_TTL = 600               # time allowed at the identity provider
SAFE_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}


class OidcError(Exception):
    pass


def _local(url: str) -> bool:
    return urllib.parse.urlsplit(url).hostname in ("localhost", "127.0.0.1", "::1")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str | None
    public_url: str                     # e.g. https://containerizer.example.com (redirect URI base)
    admins: list[str]                   # allow-list rules, see allowed()
    scopes: str = "openid profile email"
    timeout: int = 15
    viewers: list[str] = field(default_factory=list)   # non-empty: the results pages need sign-in too
    view_audit: bool = False                           # record sign-ins and page views in AccessLog

    @classmethod
    def from_env(cls, env=os.environ) -> "OidcConfig | None":
        issuer = env.get("CONTAINERIZER_OIDC_ISSUER")
        if not issuer:
            return None
        missing = [k for k in ("CONTAINERIZER_OIDC_CLIENT_ID", "CONTAINERIZER_PUBLIC_URL", "CONTAINERIZER_ADMINS")
                   if not env.get(k)]
        if missing:
            raise OidcError("sign-in is configured but these are not set: " + ", ".join(missing))
        cfg = cls(issuer=issuer.rstrip("/"), client_id=env["CONTAINERIZER_OIDC_CLIENT_ID"],
                  client_secret=env.get("CONTAINERIZER_OIDC_CLIENT_SECRET") or None,
                  public_url=env["CONTAINERIZER_PUBLIC_URL"].rstrip("/"),
                  admins=[r.strip() for r in env["CONTAINERIZER_ADMINS"].split(",") if r.strip()],
                  scopes=env.get("CONTAINERIZER_OIDC_SCOPES") or "openid profile email",
                  viewers=[r.strip() for r in (env.get("CONTAINERIZER_VIEWERS") or "").split(",") if r.strip()],
                  view_audit=_flag(env, "CONTAINERIZER_VIEW_AUDIT"))
        cfg.check()
        return cfg

    def check(self) -> None:
        for name, url in (("issuer", self.issuer), ("public URL", self.public_url)):
            if not url.startswith("https://") and not (url.startswith("http://") and _local(url)):
                raise OidcError(f"the {name} must be https (http only for localhost): {url}")
        check_rules(self.admins)
        if self.viewers:
            check_rules(self.viewers, name="CONTAINERIZER_VIEWERS")
        if self.view_audit and not self.viewers:
            raise OidcError("CONTAINERIZER_VIEW_AUDIT needs CONTAINERIZER_VIEWERS: without sign-in on the results "
                            "pages there is nobody to record")

    @property
    def secure(self) -> bool:
        return self.public_url.startswith("https://")

    @property
    def redirect_uri(self) -> str:
        return self.public_url + "/auth/callback"


def _flag(env, key: str) -> bool:
    v = (env.get(key) or "").strip().lower()
    if v in ("", "0", "false", "no", "off"):
        return False
    if v in ("1", "true", "yes", "on"):
        return True
    raise OidcError(f"{key} must be true or false, not {v!r}")


def allowed(claims: dict, rules: list[str]) -> bool:
    """Is this signed-in user an admin? Rules: email:jane@contoso.com, domain:contoso.com (both need
    email_verified=true), group:<group id>, role:<app role>, sub:<subject id>."""
    email = str(claims.get("email") or "").lower()
    verified = claims.get("email_verified") in (True, "true")
    groups = {str(g) for g in claims.get("groups") or []}
    roles = {str(r) for r in claims.get("roles") or []}
    for r in rules:
        kind, _, value = r.partition(":")
        if kind == "email" and verified and email == value.lower():
            return True
        if kind == "domain" and verified and email.endswith("@" + value.lower().lstrip("@")):
            return True
        if (kind == "group" and value in groups) or (kind == "role" and value in roles) or \
                (kind == "sub" and value == str(claims.get("sub"))):
            return True
    return False


def allowed_client(claims: dict, rules: list[str]) -> bool:
    """API callers: client:<client/application id> (azp, appid or client_id claim), plus the allowed() rules."""
    client = str(claims.get("azp") or claims.get("appid") or claims.get("client_id") or "")
    if any(r.partition(":")[0] == "client" and r.partition(":")[2] == client and client for r in rules):
        return True
    return allowed(claims, [r for r in rules if not r.startswith("client:")])


def check_rules(rules: list[str], kinds=("email", "domain", "group", "role", "sub"), name: str = "CONTAINERIZER_ADMINS"):
    if not rules:
        raise OidcError(f"{name} is empty: nobody would be let in")
    for r in rules:
        kind, _, value = r.partition(":")
        if kind not in kinds or not value:
            raise OidcError(f"{name}: unknown rule {r!r} ({', '.join(k + ':' for k in kinds)})")


def identity(claims: dict) -> tuple[str, str]:
    """(user, display name) for the audit log: e-mail / UPN when there is one, else the subject."""
    user = claims.get("email") or claims.get("preferred_username") or claims.get("upn") or f"sub:{claims['sub']}"
    return str(user), str(claims.get("name") or user)


class Provider:
    """Discovery document, keys and the token exchange of one OpenID provider."""

    def __init__(self, cfg: OidcConfig, opener=None):
        self.cfg = cfg
        self._meta: dict | None = None
        self._jwks = None
        self._open = opener or urllib.request.urlopen

    def _get_json(self, url: str, data: bytes | None = None, headers: dict | None = None) -> dict:
        if not url.startswith("https://") and not (url.startswith("http://") and _local(url)):
            raise OidcError(f"refusing a non-https provider URL: {url}")
        req = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})
        try:
            with self._open(req, timeout=self.cfg.timeout) as r:
                return json.loads(r.read(1 << 20))
        except urllib.error.HTTPError as e:
            body = e.read(2000).decode(errors="replace")
            raise OidcError(f"{url}: HTTP {e.code}: {body}") from None
        except (OSError, ValueError) as e:
            raise OidcError(f"{url}: {e}") from None

    @property
    def meta(self) -> dict:
        if self._meta is None:
            m = self._get_json(self.cfg.issuer + "/.well-known/openid-configuration")
            if m.get("issuer", "").rstrip("/") != self.cfg.issuer:
                raise OidcError(f"discovery issuer {m.get('issuer')!r} does not match {self.cfg.issuer!r}")
            for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not m.get(k):
                    raise OidcError(f"discovery document has no {k}")
            self._meta = m
        return self._meta

    def authorize_url(self, state: str, nonce: str, verifier: str) -> str:
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        q = {"response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.cfg.redirect_uri,
             "scope": self.cfg.scopes, "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        ep = self.meta["authorization_endpoint"]
        return ep + ("&" if "?" in ep else "?") + urllib.parse.urlencode(q)

    def exchange(self, code: str, verifier: str) -> dict:
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.cfg.redirect_uri,
                "code_verifier": verifier, "client_id": self.cfg.client_id}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.cfg.client_secret:
            methods = self.meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
            if "client_secret_basic" in methods:
                cred = f"{urllib.parse.quote(self.cfg.client_id, safe='')}:{urllib.parse.quote(self.cfg.client_secret, safe='')}"
                headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
            else:
                form["client_secret"] = self.cfg.client_secret
        tok = self._get_json(self.meta["token_endpoint"], urllib.parse.urlencode(form).encode(), headers)
        if "id_token" not in tok:
            raise OidcError("the token response has no id_token (is the openid scope allowed?)")
        return tok

    def _decode(self, token: str, audience: str) -> dict:
        import jwt
        if self._jwks is None:
            self._jwks = jwt.PyJWKClient(self.meta["jwks_uri"], cache_keys=True, lifespan=3600, timeout=self.cfg.timeout)
        algs = sorted(SAFE_ALGS & set(self.meta.get("id_token_signing_alg_values_supported") or ["RS256"]))
        if not algs:
            raise OidcError("the provider offers no asymmetric token signing algorithm")
        try:
            key = self._jwks.get_signing_key_from_jwt(token)
            return jwt.decode(token, key.key, algorithms=algs, audience=audience, issuer=self.meta["issuer"], leeway=60,
                              options={"require": ["exp", "iss", "aud", "sub"]})
        except (jwt.PyJWTError, OidcError) as e:
            raise OidcError(f"token rejected: {e}") from None

    def validate_access(self, token: str, audience: str) -> dict:
        """An OAuth access token (JWT) issued for this API (`audience`) by the same provider."""
        return self._decode(token, audience)

    def validate(self, id_token: str, nonce: str) -> dict:
        import jwt
        if self._jwks is None:
            self._jwks = jwt.PyJWKClient(self.meta["jwks_uri"], cache_keys=True, lifespan=3600, timeout=self.cfg.timeout)
        algs = sorted(SAFE_ALGS & set(self.meta.get("id_token_signing_alg_values_supported") or ["RS256"]))
        if not algs:
            raise OidcError("the provider offers no asymmetric ID token signing algorithm")
        try:
            key = self._jwks.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(id_token, key.key, algorithms=algs, audience=self.cfg.client_id,
                                issuer=self.meta["issuer"], leeway=60,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.PyJWTError as e:
            raise OidcError(f"ID token rejected: {e}") from None
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("ID token nonce does not match")
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.cfg.client_id:
            raise OidcError("ID token azp does not match")
        return claims


@dataclass
class Session:
    user: str
    name: str
    admin: bool
    viewer: bool = False                # may see the results pages (admins always may)
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    created: float = field(default_factory=time.time)
    seen: float = field(default_factory=time.time)


class Sessions:
    """In-memory sessions and pending sign-ins (one web process; a restart signs everyone out)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._pending: dict[str, dict] = {}

    def _prune(self, now: float) -> None:
        for sid in [k for k, s in self._sessions.items()
                    if now - s.created > SESSION_TTL or now - s.seen > IDLE_TTL]:
            del self._sessions[sid]
        for k in [k for k, p in self._pending.items() if now - p["at"] > LOGIN_TTL]:
            del self._pending[k]

    def begin(self, next_url: str) -> tuple[str, dict]:
        p = {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
             "verifier": secrets.token_urlsafe(64), "next": next_url, "at": time.time()}
        key = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(time.time())
            self._pending[key] = p
        return key, p

    def finish(self, key: str | None) -> dict | None:
        with self._lock:
            self._prune(time.time())
            return self._pending.pop(key, None) if key else None

    def create(self, user: str, name: str, admin: bool, viewer: bool = False) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[sid] = Session(user, name, admin, admin or viewer)
        return sid

    def get(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        now = time.time()
        with self._lock:
            self._prune(now)
            s = self._sessions.get(sid)
            if s:
                s.seen = now
            return s

    def end(self, sid: str | None) -> None:
        with self._lock:
            self._sessions.pop(sid or "", None)
