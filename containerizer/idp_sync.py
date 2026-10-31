"""Apply the sandbox identity provider's declarative configuration (sandbox/idp/ in the output
repository) to WSO2 Identity Server, through its REST APIs. Idempotent: run it as often as you like.

It runs in the cluster as a CronJob (sandbox/idp/sync.yaml) from a ConfigMap of the files in Git, so it
uses only the Python standard library. Inputs:

    /config/idp.json             OIDC claim settings, groups, test users (no passwords)
    /config/apps__*.json         one WSO2 application per component (no client secrets)
    /secrets/<name>              values from the secret store (External Secrets): admin-password,
                                 user-<username>, client-<app>--<component>

What it does, in order:
1. waits until the IdP answers its health check;
2. maps the OIDC claims the sandbox uses (`name`, `groups` in the profile scope);
3. creates missing groups and test users and adds the users to their groups;
4. creates every application, or updates its protocol settings and claims when they differ, and
   deletes applications it created earlier that are no longer in the configuration (only those whose
   description carries MARKER: applications someone made by hand stay).

Nothing secret is printed: errors show the HTTP status and WSO2's error code and message only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MARKER = "[managed by containerizer: sandbox/idp]"
SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
NAME_SAFE = set("abcdefghijklmnopqrstuvwxyz0123456789-._")


class SyncError(Exception):
    pass


class Api:
    def __init__(self, base: str, user: str, password: str, timeout: int = 30):
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.timeout = timeout
        self.ctx = ssl.create_default_context()

    def call(self, method: str, path: str, body=None, ok=(200, 201, 202, 204), ctype: str = "application/json"):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": self.auth, "Accept": "application/json", **({"Content-Type": ctype} if data else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
                status = r.status
        except urllib.error.HTTPError as ex:
            raw, status = ex.read(), ex.code
        except (urllib.error.URLError, OSError) as ex:
            raise SyncError(f"{method} {path}: {getattr(ex, 'reason', ex)}") from None
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        if status not in ok:
            msg = doc.get("description") or doc.get("detail") or doc.get("message") or ""
            raise SyncError(f"{method} {path}: HTTP {status} {doc.get('code', '')} {str(msg)[:300]}".rstrip())
        return status, doc


def secret(secrets: Path, name: str) -> str:
    if not set(name) <= NAME_SAFE | set("ABCDEFGHIJKLMNOPQRSTUVWXYZ_"):
        raise SyncError(f"unexpected secret name {name!r}")
    p = secrets / name
    try:
        v = p.read_text(encoding="utf-8").strip()
    except OSError:
        raise SyncError(f"secret {name} is missing (the secret store has no value for it yet)") from None
    if not v:
        raise SyncError(f"secret {name} is empty")
    return v


def wait_healthy(base: str, timeout: int, log) -> None:
    ctx = ssl.create_default_context()
    end = time.monotonic() + timeout
    last = ""
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(base.rstrip("/") + "/api/health-check/v1.0/health", timeout=10, context=ctx) as r:
                if r.status == 200:
                    return
        except Exception as ex:   # noqa: BLE001 - keep waiting, report the last reason
            last = str(getattr(ex, "reason", ex))[:200]
        time.sleep(5)
    raise SyncError(f"the identity provider at {base} did not become healthy in {timeout}s ({last})")


def _scim_filter(attr: str, value: str) -> str:
    return urllib.parse.quote(f'{attr} eq "{value}"')


def ensure_groups(api: Api, groups: list[str], log) -> dict[str, str]:
    ids = {}
    for g in groups:
        _, doc = api.call("GET", f"/scim2/Groups?filter={_scim_filter('displayName', g)}")
        found = [r for r in doc.get("Resources") or [] if r.get("displayName", "").split("/")[-1] == g]
        if found:
            ids[g] = found[0]["id"]
            continue
        _, doc = api.call("POST", "/scim2/Groups", {"displayName": g, "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]},
                          ctype="application/scim+json")
        ids[g] = doc["id"]
        log(f"created group {g}")
    return ids


def ensure_users(api: Api, users: list[dict], group_ids: dict[str, str], secrets: Path, log) -> None:
    for u in users:
        name = u["username"]
        _, doc = api.call("GET", f"/scim2/Users?filter={_scim_filter('userName', name)}")
        found = [r for r in doc.get("Resources") or [] if r.get("userName", "").split("/")[-1] == name]
        if found:
            uid = found[0]["id"]
        else:
            _, doc = api.call("POST", "/scim2/Users", {
                "schemas": [SCIM_USER], "userName": name, "password": secret(secrets, f"user-{name}"),
                "name": {"givenName": u.get("givenName", name), "familyName": u.get("familyName", "Tester"),
                         "formatted": f"{u.get('givenName', name)} {u.get('familyName', 'Tester')}"},
                "displayName": name,
                "emails": [{"primary": True, "value": u["email"]}]}, ctype="application/scim+json")
            uid = doc["id"]
            log(f"created user {name}")
        for g in u.get("groups") or []:
            gid = group_ids[g]
            _, gdoc = api.call("GET", f"/scim2/Groups/{gid}")
            if any(m.get("value") == uid for m in gdoc.get("members") or []):
                continue
            api.call("PATCH", f"/scim2/Groups/{gid}", {"schemas": [SCIM_PATCH], "Operations": [
                {"op": "add", "value": {"members": [{"display": name, "value": uid}]}}]}, ctype="application/scim+json")
            log(f"added {name} to {g}")


def _app_body(path: Path, secrets: Path) -> dict:
    body = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(body, dict) or not body.get("name"):
        raise SyncError(f"{path.name}: not an application definition")
    body["description"] = (body.get("description", "").replace(MARKER, "").strip() + " " + MARKER).strip()
    ref = body.pop("x-containerizer-client-secret", None)
    for k in [k for k in body if k.startswith("x-containerizer-")]:
        body.pop(k)
    oidc = (body.get("inboundProtocolConfiguration") or {}).get("oidc")
    if oidc is not None and ref:
        oidc["clientSecret"] = secret(secrets, ref)
    return body


def _find_app(api: Api, name: str) -> dict | None:
    _, doc = api.call("GET", f"/api/server/v1/applications?filter={urllib.parse.quote(f'name eq {name}')}&limit=10")
    for a in doc.get("applications") or []:
        if a.get("name") == name:
            return a
    return None


PROTOCOL_PATH = {"oidc": "oidc", "saml": "saml", "passiveSts": "passive-sts"}


def ensure_app(api: Api, body: dict, log) -> str:
    name = body["name"]
    existing = _find_app(api, name)
    if existing is None:
        api.call("POST", "/api/server/v1/applications", body)
        log(f"created application {name}")
        return "created"
    aid = existing["id"]
    changed = False
    for proto, cfg in (body.get("inboundProtocolConfiguration") or {}).items():
        sub = PROTOCOL_PATH[proto]
        st, cur = api.call("GET", f"/api/server/v1/applications/{aid}/inbound-protocols/{sub}", ok=(200, 404))
        want = cfg.get("manualConfiguration", cfg) if proto == "saml" else cfg
        if st == 200 and _subset(want, cur):
            continue
        api.call("PUT", f"/api/server/v1/applications/{aid}/inbound-protocols/{sub}", cfg)
        changed = True
    patch = {k: body[k] for k in ("description", "claimConfiguration", "accessUrl", "advancedConfigurations") if k in body}
    if patch:
        _, cur = api.call("GET", f"/api/server/v1/applications/{aid}")
        if not _subset(patch, cur):
            api.call("PATCH", f"/api/server/v1/applications/{aid}", patch)
            changed = True
    if changed:
        log(f"updated application {name}")
    return "updated" if changed else "unchanged"


def _subset(want, have) -> bool:
    """True when every value in `want` is in `have` (lists: same items, any order). Secrets are not
    read back by WSO2 in the same form, so clientSecret is ignored."""
    if isinstance(want, dict):
        if not isinstance(have, dict):
            return False
        return all(k == "clientSecret" or _subset(v, have.get(k)) for k, v in want.items())
    if isinstance(want, list):
        if not isinstance(have, list) or len(want) != len(have):
            return False
        return all(any(_subset(w, h) for h in have) for w in want)
    return want == have


def prune_apps(api: Api, keep: set[str], log) -> None:
    _, doc = api.call("GET", "/api/server/v1/applications?limit=500")
    for a in doc.get("applications") or []:
        if MARKER in (a.get("description") or "") and a.get("name") not in keep:
            api.call("DELETE", f"/api/server/v1/applications/{a['id']}")
            log(f"deleted application {a['name']} (no longer in sandbox/idp)")


def ensure_oidc_claims(api: Api, oidc: dict, log) -> None:
    """OIDC claims of the sandbox: `name` from the user's formatted name, and the claims each scope
    releases (e.g. groups with profile), so apps that read `name` or `groups` work without changes."""
    dialect = base64.urlsafe_b64encode(b"http://wso2.org/oidc/claim").decode().rstrip("=")
    for claim, local in sorted((oidc.get("claims") or {}).items()):
        cid = base64.urlsafe_b64encode(claim.encode()).decode().rstrip("=")
        st, cur = api.call("GET", f"/api/server/v1/claim-dialects/{dialect}/claims/{cid}", ok=(200, 404))
        if st == 200 and cur.get("mappedLocalClaimURI") == local:
            continue
        if st == 200:
            api.call("PUT", f"/api/server/v1/claim-dialects/{dialect}/claims/{cid}",
                     {"claimURI": claim, "mappedLocalClaimURI": local})
        else:
            api.call("POST", f"/api/server/v1/claim-dialects/{dialect}/claims",
                     {"claimURI": claim, "mappedLocalClaimURI": local})
        log(f"OIDC claim {claim} -> {local}")
    for scope, add in sorted((oidc.get("scope_claims") or {}).items()):
        _, cur = api.call("GET", f"/api/server/v1/oidc/scopes/{urllib.parse.quote(scope)}")
        claims = list(cur.get("claims") or [])
        missing = [c for c in add if c not in claims]
        if not missing:
            continue
        api.call("PUT", f"/api/server/v1/oidc/scopes/{urllib.parse.quote(scope)}",
                 {"displayName": cur.get("displayName") or scope, "description": cur.get("description") or "",
                  "claims": claims + missing})
        log(f"OIDC scope {scope}: added {', '.join(missing)}")


def sync(base: str, config: Path, secrets: Path, wait: int = 600, log=print) -> dict:
    cfg = json.loads((config / "idp.json").read_text(encoding="utf-8"))
    wait_healthy(base, wait, log)
    api = Api(base, cfg.get("admin", "admin"), secret(secrets, "admin-password"))
    ensure_oidc_claims(api, cfg.get("oidc") or {}, log)
    gids = ensure_groups(api, cfg.get("groups") or [], log)
    ensure_users(api, cfg.get("users") or [], gids, secrets, log)
    result, failed = {}, []
    # a ConfigMap mounted as a folder has one flat file per key: apps__<name>.json
    files = sorted(config.glob("apps__*.json"))
    names = set()
    for f in files:
        try:
            body = _app_body(f, secrets)
            names.add(body["name"])
            result[body["name"]] = ensure_app(api, body, log)
        except (SyncError, ValueError, KeyError) as ex:
            failed.append(f"{f.name}: {ex}")
            log(f"error: {f.name}: {ex}")
    if not failed:
        prune_apps(api, names, log)
    return {"applications": result, "failed": failed}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=os.environ.get("IDP_URL", ""), help="public URL of the IdP (https://...)")
    ap.add_argument("--config", default="/config")
    ap.add_argument("--secrets", default="/secrets")
    ap.add_argument("--wait", type=int, default=600)
    a = ap.parse_args(argv)
    if not a.url.startswith("https://"):
        print("--url (IDP_URL) must be the https:// URL of the identity provider", file=sys.stderr)
        return 2
    try:
        r = sync(a.url, Path(a.config), Path(a.secrets), a.wait)
    except SyncError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1
    print(json.dumps(r, sort_keys=True))
    return 1 if r["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
