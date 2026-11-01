"""Admin → API: how to use the JSON API, and its keys.

An API key is `czk_<prefix>_<secret>`: the prefix (8 hex characters) names the key in lists and the change
history, the secret is 32 random bytes. Only the key's SHA-256 is stored, so a key is shown once, right after
it is made. A key has a role: `read` (GET only) or `full` (everything an administrator may change through the
API), and may expire. Revoked and expired keys are refused (api.Api._authenticate -> check_key).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from .admin import Response, e, redirect

KEY_RE = re.compile(r"czk_([0-9a-f]{8})_[A-Za-z0-9_-]{43}")
ROLES = {"read": "Read only (GET)", "full": "Full: read and change the mapping"}
EXPIRY = {"30": "30 days", "90": "90 days", "365": "1 year", "never": "Never"}
LAST_USED_EVERY = timedelta(minutes=5)          # how often a key's last use is written back


def new_key() -> tuple[str, str, bytes]:
    """(key, prefix, sha256 of the key)."""
    prefix = secrets.token_hex(4)
    key = f"czk_{prefix}_{secrets.token_urlsafe(32)}"
    return key, prefix, hashlib.sha256(key.encode()).digest()


def check_key(connect_admin, key: str) -> dict | None:
    """The caller of an API key, as claims for api.Api (None: unknown, revoked or expired)."""
    m = KEY_RE.fullmatch(key)
    if not m:
        return None
    conn = connect_admin()
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT ApiKeyId, Name, Prefix, KeyHash, Role, ExpiresAt, LastUsedAt, RevokedAt FROM cz.ApiKey "
                    "WHERE Prefix = %s", (m[1],))
        row = cur.fetchone()
        if not row or not hmac.compare_digest(bytes(row["KeyHash"]), hashlib.sha256(key.encode()).digest()):
            return None
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if row["RevokedAt"] is not None or (row["ExpiresAt"] is not None and row["ExpiresAt"] <= now):
            return None
        if row["LastUsedAt"] is None or now - row["LastUsedAt"] >= LAST_USED_EVERY:
            cur.execute("UPDATE cz.ApiKey SET LastUsedAt = SYSUTCDATETIME() WHERE ApiKeyId = %s", (row["ApiKeyId"],))
            conn.commit()
        return {"_api_key": True, "_role": row["Role"], "_prefix": row["Prefix"], "sub": f"api-key:{row['Prefix']}",
                "name": f"API key {row['Name']}"}
    finally:
        conn.close()


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict) -> Response:
    if not a.admin:
        return Response(403, adm._shell(s, a, "Not allowed", "api", "<p>Only administrators manage API keys.</p>"))
    if method == "POST" and parts[1:] == ["keys"]:
        return create(adm, conn, s, a, form)
    if method == "POST" and len(parts) == 4 and parts[1] == "keys" and parts[3] == "revoke" and parts[2].isdigit():
        cur = conn.cursor()
        cur.execute("UPDATE cz.ApiKey SET RevokedAt = SYSUTCDATETIME(), RevokedBy = %s WHERE ApiKeyId = %s "
                    "AND RevokedAt IS NULL", (s.user, int(parts[2])))
        conn.commit()
        return redirect("/admin/api?msg=" + ("Revoked." if cur.rowcount else "Already revoked."))
    if method != "GET" or len(parts) > 1:
        return Response(404, adm._shell(s, a, "Not found", "api", ""))
    return Response(200, adm._shell(s, a, "API", "api", page(adm, conn, s), q.get("msg", [""])[0][:200]))


def create(adm, conn, s, a, form: dict) -> Response:
    name = " ".join((form.get("Name") or [""])[0].split())[:100]
    role = (form.get("Role") or [""])[0]
    expiry = (form.get("Expires") or [""])[0]
    if not name or role not in ROLES or expiry not in EXPIRY:
        return redirect("/admin/api?msg=Not+made:+give+the+key+a+name,+a+role+and+an+expiry.")
    key, prefix, digest = new_key()
    expires = None if expiry == "never" else \
        datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) + timedelta(days=int(expiry))
    cur = conn.cursor()
    cur.execute("INSERT cz.ApiKey (Name, Prefix, KeyHash, Role, CreatedBy, ExpiresAt) VALUES (%s, %s, %s, %s, %s, %s)",
                (name, prefix, digest, role, s.user, expires))
    conn.commit()
    shown = (f"<div class='newkey' role='status'><b>API key “{e(name)}” made.</b> Copy it now: it is not stored and "
             f"is not shown again.<pre class='prompt'>{e(key)}</pre></div>")
    return Response(200, adm._shell(s, a, "API", "api", shown + page(adm, conn, s, example_key=key), ""),
                    [("Cache-Control", "no-store")])


def _when(v) -> str:
    return v.strftime("%Y-%m-%d %H:%M UTC") if v else "<span class='muted'>-</span>"


def page(adm, conn, s, example_key: str | None = None) -> str:
    base = adm.cfg.public_url.rstrip("/") + "/api/v1"
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ApiKeyId, Name, Prefix, Role, CreatedBy, CreatedAt, ExpiresAt, LastUsedAt, RevokedAt, RevokedBy "
                "FROM cz.ApiKey ORDER BY RevokedAt, CreatedAt DESC")
    rows = cur.fetchall()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    trs = []
    for r in rows:
        if r["RevokedAt"]:
            st = f"<span class='st st-off'>Revoked</span><div class='muted small'>{_when(r['RevokedAt'])} by {e(r['RevokedBy'])}</div>"
        elif r["ExpiresAt"] and r["ExpiresAt"] <= now:
            st = "<span class='st st-off'>Expired</span>"
        else:
            st = "<span class='st st-ok'>Active</span>"
        act = "" if r["RevokedAt"] else (
            f"<form method='post' action='/admin/api/keys/{int(r['ApiKeyId'])}/revoke' class='inline'>{adm._csrf(s)}"
            "<button class='secondary'>Revoke</button></form>")
        trs.append(f"<tr><td><b>{e(r['Name'])}</b><div class='muted small'><code>czk_{e(r['Prefix'])}_…</code></div></td>"
                   f"<td>{e(ROLES.get(r['Role'], r['Role']))}</td><td class='small'>{st}</td>"
                   f"<td class='small'>{_when(r['CreatedAt'])}<div class='muted'>{e(r['CreatedBy'])}</div></td>"
                   f"<td class='small'>{_when(r['ExpiresAt']) if r['ExpiresAt'] else 'never'}</td>"
                   f"<td class='small'>{_when(r['LastUsedAt'])}</td><td>{act}</td></tr>")
    keys = ("<table><thead><tr><th>Key</th><th>Role</th><th>Status</th><th>Made</th><th>Expires</th><th>Last used</th>"
            f"<th></th></tr></thead><tbody>{''.join(trs)}</tbody></table>" if trs
            else "<p class='muted'>No API keys yet.</p>")
    roles = "".join(f"<option value='{k}'>{e(v)}</option>" for k, v in ROLES.items())
    exp = "".join(f"<option value='{k}'{' selected' if k == '90' else ''}>{e(v)}</option>" for k, v in EXPIRY.items())
    k = example_key or "$CZ_API_KEY"
    tokens = " OpenID Connect access tokens for the API's audience work too." if getattr(adm.api, "audience", "") else ""
    return f"""
<p>The JSON API reads and changes the mapping of applications to products and business units, and reads the
software bills of materials and the change history: for scripts, CMDB synchronisation and reports.{e(tokens)}</p>

<h2>API keys</h2>
{keys}
<h3>Make a key</h3>
<form method='post' action='/admin/api/keys' class='formrow'>{adm._csrf(s)}
<input name='Name' maxlength='100' placeholder='What uses it, e.g. CMDB sync' aria-label='Name' required>
<select name='Role' aria-label='Role'>{roles}</select>
<select name='Expires' aria-label='Expires'>{exp}</select>
<button>Make the key</button></form>
<p class='muted small'>The key is shown once. Keep it in a secret store; anyone with a full key can change the
mapping. Revoke a key that may have leaked and make a new one. Every change made with a key is in the change
history as <code>api-key:&lt;prefix&gt;</code>.</p>

<h2>How to use it</h2>
<p>Base URL <code>{e(base)}</code>. Send the key in the <code>Authorization</code> header; bodies are JSON
(<code>Content-Type: application/json</code>, at most 64 KiB).</p>
<pre class='prompt'>export CZ_API_KEY='{e(k)}'

# the applications, and the ones not mapped to a product yet
curl -s -H "Authorization: Bearer $CZ_API_KEY" {e(base)}/applications
curl -s -H "Authorization: Bearer $CZ_API_KEY" '{e(base)}/applications?unmapped=true'

# map application 12 to product 3 (a full key)
curl -s -X PATCH -H "Authorization: Bearer $CZ_API_KEY" -H 'Content-Type: application/json' \\
     -d '{{"productId": 3}}' {e(base)}/applications/12</pre>
<pre class='prompt'>import json, os, urllib.request

def api(method, path, body=None):
    req = urllib.request.Request("{e(base)}" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={{"Authorization": "Bearer " + os.environ["CZ_API_KEY"], "Content-Type": "application/json"}})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

for app in api("GET", "/applications?unmapped=true")["items"]:
    print(app["id"], app["name"])</pre>

<h3>Endpoints</h3>
<table class='narrow'><thead><tr><th>Method</th><th>Path</th><th>What</th></tr></thead><tbody>
<tr><td>GET</td><td><code>/business-units</code>, <code>/business-units/{{id}}</code></td><td>business units</td></tr>
<tr><td>POST, PATCH, DELETE</td><td><code>/business-units</code>, <code>/business-units/{{id}}</code></td><td>add, change, remove (full)</td></tr>
<tr><td>GET</td><td><code>/products[?businessUnitId=]</code>, <code>/products/{{id}}</code></td><td>products</td></tr>
<tr><td>POST, PATCH, DELETE</td><td><code>/products</code>, <code>/products/{{id}}</code></td><td>add, change, remove (full)</td></tr>
<tr><td>GET</td><td><code>/applications[?unmapped=true&amp;productId=&amp;name=]</code>, <code>/applications/{{id}}</code></td><td>applications with their latest rating</td></tr>
<tr><td>PATCH</td><td><code>/applications/{{id}}</code></td><td>display name, owner, description, product, retired (full)</td></tr>
<tr><td>GET</td><td><code>/audit[?table=&amp;rowId=&amp;limit=]</code></td><td>the change history</td></tr>
<tr><td>GET</td><td><code>/applications/{{id}}/components/{{cid}}/sbom</code>, <code>/sbom/packages</code>, <code>/sbom/summary</code></td><td>software bills of materials</td></tr>
</tbody></table>
<p class='muted small'>Errors are JSON <code>{{"error": ..., "message": ...}}</code>: 401 a missing, unknown, revoked or
expired key; 403 a read-only key that tries to change something; 404 an unknown id; 415 a body that is not JSON.
All the details: <a href='https://containerizer.eu/api/'>the API documentation</a>.</p>
"""
