"""OpenBao on the appliance: where administrators and operators enter the values of the sandbox apps' secrets
(docs/openbao.md).

The apps' ExternalSecrets keep reading the appliance's own store (ClusterSecretStore app-secrets, the kubernetes
provider over namespace containerizer-secrets, docs/external-secrets.md); the appliance's own writers (Git tokens,
the Flux webhook, the sandbox IdP, lab services) keep writing there. OpenBao is the place for people:

- **Placeholders.** For every component's `<component>-secrets` ExternalSecret in the sandbox, OpenBao gets the
  entry `apps/<namespace>/<component>` (KV version 2) with one key per property the component reads: empty, or the
  value already in the store (set by hand before). Keys another appliance writer owns (the sandbox IdP's client
  secret) are left out: they are filled automatically.
- **Starting values.** A placeholder starts with the value the app's own settings files give it (appsettings.json and
  the development files: what a developer runs it with), which the scan leaves outside Git (SEED_DIR). Each key is
  filled from there once; a value a person empties later stays empty.
- **Copy.** The keys with a value are copied to the store's remote Secret `<namespace>--<component>` (server-side
  apply, field manager `containerizer-openbao`, so the other writers' keys stay); a key emptied in OpenBao is removed
  there. In the sandbox the component's ExternalSecret reads every key the remote Secret has (sandbox_patches), so a
  value that is not filled yet is simply not set: the app's own appsettings value applies.
- **Forget.** Admin -> Applications -> Forget application asks the system agent to forget the namespace
  (FORGET_PATH, root only). Once the scan has pruned its ExternalSecrets, the sync deletes its entries (every version),
  its policy and the copied values in the store (the remote Secrets `<namespace>--<component>`). The sync's own token
  policy may delete since 0.41.3; an older appliance's is updated once, signed in as the appliance's user `admin`, or
  by `cz openbao-policy` when that password was changed.
- **Delegation.** Every app namespace gets the policy `app-<namespace>`: read and write its own entries, nothing
  else. An administrator gives it to an operator's user, or to a group of the identity provider (SSO).

The appliance runs `python -m containerizer.openbao sync` as root every 2 minutes (cz-sandbox): it initialises
OpenBao the first time (setup), then does the above. OpenBao unseals itself with the static key in
/etc/containerizer/secrets/openbao-unseal.key; the recovery key and the sync job's token are next to it (root only).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ADDR = os.environ.get("CZ_OPENBAO_ADDR", "http://127.0.0.1:8200")
SECRETS = Path(os.environ.get("CZ_OPENBAO_SECRETS", "/etc/containerizer/secrets"))
# the development values of the apps' secret settings, from their own settings files (org.write_secret_seed, the scan
# worker; never in Git), and which keys were filled from them already (each once: a value a person empties stays empty)
SEED_DIR = Path(os.environ.get("CZ_OPENBAO_SEED", "/var/lib/containerizer/worker/secret-seed"))
SEEDED_PATH = Path(os.environ.get("CZ_OPENBAO_SEEDED", "/var/lib/containerizer/system/openbao-seeded.json"))
FORGET_PATH = Path(os.environ.get("CZ_OPENBAO_FORGET", "/var/lib/containerizer/system/openbao-forget.json"))
MOUNT = "apps"                              # KV version 2: apps/<namespace>/<component>
MANAGER = "containerizer-openbao"           # field manager of the copied keys in the store
RESTART_ANNOTATION = "containerizer.io/secrets"    # fingerprint of the Secrets a workload reads (apply_now)
PROPERTIES = "containerizer.io/properties"  # the properties a component reads (sandbox_patches keeps them)
SUFFIX = "-secrets"                         # the ExternalSecret of a component's settings (harden.externalize_secrets)
FILES = "-files"                            # ... and of its files (base64): entry apps/<namespace>/<component>-files
ADMIN_POLICY, SYNC_POLICY = "cz-admin", "cz-sync"

# administrators: the apps' values, the users and groups, policies and sign-in methods (SSO): everything except the
# seal, the storage and the root token
ADMIN_HCL = f"""
path "{MOUNT}/*" {{ capabilities = ["create", "read", "update", "patch", "delete", "list"] }}
path "auth/*" {{ capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"] }}
path "sys/auth" {{ capabilities = ["read"] }}
path "sys/auth/*" {{ capabilities = ["create", "read", "update", "delete", "sudo"] }}
path "sys/mounts/auth/*" {{ capabilities = ["read", "update"] }}
path "sys/policies/acl" {{ capabilities = ["list"] }}
path "sys/policies/acl/*" {{ capabilities = ["create", "read", "update", "patch", "delete", "list"] }}
path "identity/*" {{ capabilities = ["create", "read", "update", "patch", "delete", "list"] }}
path "sys/mounts" {{ capabilities = ["read"] }}
path "sys/internal/ui/*" {{ capabilities = ["read", "list"] }}
"""
# the sync job: the apps' entries and the operators' policies, its own token
SYNC_HCL = f"""
path "{MOUNT}/data/*" {{ capabilities = ["create", "read", "update"] }}
path "{MOUNT}/metadata/*" {{ capabilities = ["read", "list", "delete"] }}
path "sys/policies/acl/app-*" {{ capabilities = ["create", "read", "update", "delete"] }}
path "auth/token/renew-self" {{ capabilities = ["update"] }}
"""


def oidc_enabled(api: str, timeout: float = 2.0) -> bool:
    """Whether OpenBao has the OIDC sign-in method at auth/oidc (docs/openbao.md), asked without a token: its
    auth_url endpoint answers 403 when the method is not there, 400 or 200 when it is (configured or not)."""
    req = urllib.request.Request(api.rstrip("/") + "/v1/auth/oidc/oidc/auth_url", method="POST",
                                 data=json.dumps({"role": "", "redirect_uri": "http://localhost:8250/oidc/callback"}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except urllib.error.HTTPError as ex:
        return ex.code not in (403, 404, 405)
    except (urllib.error.URLError, OSError, ValueError):
        return False


CALLBACK = "/ui/vault/auth/oidc/oidc/callback"   # OpenBao's UI callback: the redirect URI people register (docs)


def _post_json(url: str, body: dict | None, headers: dict | None = None, method: str = "POST", timeout: float = 10.0):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def sso_start(api: str, public_url: str) -> tuple[str, str, str] | None:
    """The OIDC sign-in to OpenBao without its sign-in page, step 1: (the identity provider's URL, its state, our
    client nonce), for the redirect URI the UI uses (so nothing new to register). None when OpenBao refuses."""
    import secrets
    from urllib.parse import parse_qs, urlsplit
    nonce = secrets.token_urlsafe(24)
    try:
        d = _post_json(api.rstrip("/") + "/v1/auth/oidc/oidc/auth_url",
                       {"role": "", "redirect_uri": public_url.rstrip("/") + CALLBACK, "client_nonce": nonce})
    except (urllib.error.URLError, OSError, ValueError):
        return None
    url = ((d or {}).get("data") or {}).get("auth_url") or ""
    state = parse_qs(urlsplit(url).query).get("state", [""])[0]
    if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")) or not state:
        return None
    return url, state, nonce


def sso_finish(api: str, state: str, code: str, nonce: str) -> str | None:
    """Step 2, at the callback: OpenBao completes the sign-in and answers with its token wrapped (single use, one
    minute). The UI signs in with it (/ui/vault/auth?wrapped_token=...). None when OpenBao refuses."""
    from urllib.parse import urlencode
    try:
        d = _post_json(api.rstrip("/") + "/v1/auth/oidc/oidc/callback?" +
                       urlencode({"state": state, "code": code, "client_nonce": nonce}), None,
                       {"X-Vault-Wrap-TTL": "60s"}, method="GET")
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return ((d or {}).get("wrap_info") or {}).get("token") or None


def app_policy(ns: str) -> str:
    """An operator of namespace `ns`: its own entries only (the list of namespaces shows names, never values)."""
    return (f'path "{MOUNT}/data/{ns}/*" {{ capabilities = ["create", "read", "update", "patch", "delete"] }}\n'
            f'path "{MOUNT}/metadata/{ns}/*" {{ capabilities = ["read", "list", "delete"] }}\n'
            f'path "{MOUNT}/metadata/{ns}" {{ capabilities = ["list"] }}\n'
            f'path "{MOUNT}/metadata/" {{ capabilities = ["list"] }}\n')


class BaoError(Exception):
    pass


class Bao:
    """The OpenBao HTTP API. The token goes in a header, never on a command line."""

    def __init__(self, addr: str = ADDR, token: str | None = None):
        self.addr, self.token = addr.rstrip("/"), token

    def call(self, method: str, path: str, body: dict | None = None, ok404: bool = False) -> dict | None:
        req = urllib.request.Request(f"{self.addr}/v1/{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if self.token:
            req.add_header("X-Vault-Token", self.token)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
        except urllib.error.HTTPError as ex:
            if ex.code == 404 and ok404:
                return None
            detail = ex.read()[:300].decode(errors="replace")
            raise BaoError(f"{method} {path}: HTTP {ex.code} {detail}") from None
        except OSError as ex:
            raise BaoError(f"{method} {path}: {ex}") from None
        return json.loads(raw) if raw.strip() else {}


def _write_secret(name: str, value: str) -> None:
    p = SECRETS / name
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    os.replace(tmp, p)


def _read_secret(name: str) -> str:
    try:
        return (SECRETS / name).read_text().strip()
    except OSError:
        return ""


def _ready(bao: Bao, timeout: float = 120.0) -> None:
    """Wait until OpenBao is unsealed and active: right after init the static seal unseals it a moment later."""
    import time
    end = time.monotonic() + timeout
    while True:
        try:
            st = bao.call("GET", "sys/seal-status") or {}
            if st.get("initialized") and not st.get("sealed"):
                bao.call("GET", "sys/health")       # 200 only when active (429 standby, 503 sealed)
                return
        except BaoError:
            pass
        if time.monotonic() > end:
            raise BaoError("OpenBao did not become active after its init (sys/health)")
        time.sleep(2)


def _exists_ok(fn) -> None:
    """A setup step that a run before may have done (a resumed setup)."""
    try:
        fn()
    except BaoError as ex:
        if "already in use" not in str(ex) and "existing mount" not in str(ex):
            raise


def setup(bao: Bao, log=print) -> str:
    """Initialise OpenBao once: the apps' KV mount, user name and password sign-in with the user `admin` (password
    in openbao-admin), the policies, a token for the sync job; the root token is revoked afterwards. Returns the
    sync job's token. Resumable: the root token is kept (root only) until every step is done, so a setup that
    stopped half-way (OpenBao still unsealing after its init, a restart) is finished by the next run."""
    st = bao.call("GET", "sys/seal-status") or {}
    token = _read_secret("openbao-sync-token")
    if st.get("initialized") and token:
        if st.get("sealed"):
            raise BaoError("OpenBao is sealed: is /etc/containerizer/secrets/openbao-unseal.key its key?")
        return token
    password = _read_secret("openbao-admin")
    if not password:
        raise BaoError("secrets/openbao-admin is missing (cz-firstboot makes it)")
    root_token = _read_secret("openbao-root-token")
    if not st.get("initialized"):
        init = bao.call("PUT", "sys/init", {"recovery_shares": 1, "recovery_threshold": 1}) or {}
        _write_secret("openbao-recovery-key", init["recovery_keys_base64"][0])
        root_token = init["root_token"]
        _write_secret("openbao-root-token", root_token)     # until setup is done
    elif not root_token:
        raise BaoError("OpenBao is initialised but the sync token (secrets/openbao-sync-token) is missing: make a "
                       "new one with a root token from the recovery key (docs/openbao.md#recovery)")
    _ready(bao)
    root = Bao(bao.addr, root_token)
    _exists_ok(lambda: root.call("POST", f"sys/mounts/{MOUNT}", {
        "type": "kv", "options": {"version": "2"}, "description": "values of the sandbox apps' secrets (containerizer)"}))
    _exists_ok(lambda: root.call("POST", "sys/auth/userpass", {"type": "userpass"}))
    root.call("PUT", f"sys/policies/acl/{ADMIN_POLICY}", {"policy": ADMIN_HCL})
    root.call("PUT", f"sys/policies/acl/{SYNC_POLICY}", {"policy": SYNC_HCL})
    _write_secret("openbao-sync-policy", policy_hash())
    if root.call("GET", "auth/userpass/users/admin", ok404=True) is None:
        root.call("POST", "auth/userpass/users/admin", {"password": password, "token_policies": [ADMIN_POLICY]})
    t = root.call("POST", "auth/token/create-orphan", {"policies": [SYNC_POLICY], "no_default_policy": True,
                                                       "period": "768h", "display_name": "containerizer-sync"}) or {}
    token = t["auth"]["client_token"]
    _write_secret("openbao-sync-token", token)
    root.call("POST", "auth/token/revoke-self")
    try:
        (SECRETS / "openbao-root-token").unlink()
    except OSError:
        pass
    log("openbao: initialised (user admin, mount apps/, root token revoked; recovery key in "
        "secrets/openbao-recovery-key)")
    return token


# --------------------------------------------------------------------------- the store side (kubectl)

def _kubectl_cmd() -> list[str]:
    return (os.environ.get("CZ_KUBECTL") or "kubectl").split()


def _run(args: list[str], stdin: str | None = None, ok_missing: bool = False) -> str | None:
    p = subprocess.run(_kubectl_cmd() + args, input=stdin, capture_output=True, text=True, timeout=120)
    if p.returncode:
        if ok_missing and ("NotFound" in p.stderr or "not found" in p.stderr):
            return None
        # kubectl errors name objects, never values (values only ever go through stdin)
        raise BaoError(f"kubectl {' '.join(args[:3])}: {p.stderr.strip()[:300]}")
    return p.stdout


def component_secrets(items: list[dict]) -> list[dict]:
    """The components' settings and files ExternalSecrets among `items` (kubectl get externalsecrets -A): namespace,
    component (the entry's name: <component> for its settings, <component>-files for its files), the ExternalSecret,
    remote key and the properties it reads (the annotation the sandbox patch keeps, or its data list; none when it
    reads every key: `every`)."""
    out: dict[tuple, dict] = {}
    for es in items:
        meta, spec = es.get("metadata") or {}, es.get("spec") or {}
        name, ns = meta.get("name") or "", meta.get("namespace") or ""
        suffix = SUFFIX if name.endswith(SUFFIX) else FILES if name.endswith(FILES) else ""
        if not suffix or not ns or ns.startswith(("containerizer-", "flux-system", "kube-")):
            continue
        ann = (meta.get("annotations") or {}).get(PROPERTIES)
        data = spec.get("data") or []
        remotes = {(d.get("remoteRef") or {}).get("key") for d in data} | \
                  {(d.get("extract") or {}).get("key") for d in spec.get("dataFrom") or [] if d.get("extract")}
        remotes.discard(None)
        if len(remotes) != 1:
            continue
        component, remote = (name[:-len(suffix)] if suffix == SUFFIX else name), remotes.pop()
        # only the namespace's own key: an ExternalSecret naming another namespace's key must not let this
        # namespace's operators write that one (the store's Role keeps it from reading it anyway)
        if remote != _remote_key(ns, component):
            continue
        props = [p for p in ann.split(",") if p] if ann is not None else [d.get("secretKey") for d in data]
        c = out.setdefault((ns, component), {"namespace": ns, "component": component, "es": name, "remote": remote,
                                             "properties": [], "every": not data})
        c["properties"] = sorted(set(c["properties"]) | {p for p in props if p})
    return list(out.values())


def _remote_key(ns: str, component: str) -> str:
    from . import eso
    return eso.remote_key(ns, component)


def _owners(secret: dict) -> dict[str, str]:
    """{data key: field manager} of a Secret (its managedFields)."""
    out = {}
    for mf in (secret.get("metadata") or {}).get("managedFields") or []:
        for k in ((mf.get("fieldsV1") or {}).get("f:data") or {}):
            if k.startswith("f:"):
                out[k[2:]] = mf.get("manager") or ""
    return out


def _system(manager: str) -> bool:
    """A key another appliance writer fills (the sandbox IdP's client secret): not for people."""
    return manager.startswith("containerizer-") and manager not in (MANAGER, "containerizer-appliance")


def _decode(secret: dict | None) -> dict[str, str]:
    import base64
    return {k: base64.b64decode(v).decode(errors="replace") for k, v in ((secret or {}).get("data") or {}).items()}


def _apply_store(store_ns: str, remote: str, values: dict[str, str], exists: bool) -> None:
    """Our keys of the remote Secret: exactly `values` (a key we no longer apply is removed by server-side apply)."""
    import base64
    if not values and not exists:
        return
    doc = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
           "metadata": {"name": remote, "namespace": store_ns,
                        "labels": {"app.kubernetes.io/managed-by": "containerizer-appliance"}}}
    if values:
        doc["data"] = {k: base64.b64encode(v.encode()).decode() for k, v in sorted(values.items())}
    _run(["apply", "--server-side", "--force-conflicts", f"--field-manager={MANAGER}", "-f", "-"],
         stdin=json.dumps(doc))


def _json_file(p: Path) -> dict:
    try:
        v = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}
    return v if isinstance(v, dict) else {}


def seed_values(ns: str, component: str) -> dict[str, str]:
    return {str(k): str(v) for k, v in _json_file(SEED_DIR / ns / f"{component}.json").items() if v not in (None, "")}


def _save_seeded(seeded: dict) -> None:
    SEEDED_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SEEDED_PATH.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(seeded, sort_keys=True))
    os.replace(tmp, SEEDED_PATH)


def sync_component(bao: Bao, store_ns: str, c: dict, log=print) -> dict:
    """Placeholders in OpenBao for one component (empty, the value already in the store, or the app's own starting
    value), then its filled values into the store. Returns counts."""
    path = f"{c['namespace']}/{c['component']}"
    got = bao.call("GET", f"{MOUNT}/data/{path}", ok404=True)
    data = dict(((got or {}).get("data") or {}).get("data") or {})
    version = (((got or {}).get("data") or {}).get("metadata") or {}).get("version") or 0
    if got is None:     # none, or its latest version deleted (its values are cleared): write after that version
        meta = bao.call("GET", f"{MOUNT}/metadata/{path}", ok404=True)
        version = ((meta or {}).get("data") or {}).get("current_version") or 0
    # kubectl leaves managedFields out unless asked: without them every key looked set by hand, and was written again
    raw = _run(["-n", store_ns, "get", "secret", c["remote"], "-o", "json", "--show-managed-fields"], ok_missing=True)
    secret = json.loads(raw) if raw else None
    owners, have = _owners(secret or {}), _decode(secret)
    system = {k for k, m in owners.items() if _system(m)}
    added = [p for p in c["properties"] if p not in data and p not in system]
    if got is None and not version and not c["properties"]:
        # an entry to add keys to (a component's files): there before anyone adds one, so people see where
        bao.call("POST", f"{MOUNT}/data/{path}", {"options": {"cas": 0}, "data": {}})
    seed, seeded = seed_values(c["namespace"], c["component"]), _json_file(SEEDED_PATH)
    done = set(seeded.get(path) or [])
    fill = {p: seed[p] for p in c["properties"] if p in seed and p not in done and p not in system
            and not data.get(p) and not (have.get(p) and not _system(owners.get(p, "")))}
    if added or fill:
        # an empty placeholder, the value someone already put in the store by hand, or the app's starting value
        data.update({p: have.get(p, "") if not _system(owners.get(p, "")) else "" for p in added})
        data.update(fill)
        try:
            bao.call("POST", f"{MOUNT}/data/{path}", {"options": {"cas": version}, "data": data})
        except BaoError as ex:
            if "check-and-set" in str(ex):
                return {"added": 0, "copied": 0}      # someone saved it just now: next round
            raise
    if seed and set(seed) & set(c["properties"]) - done:
        seeded[path] = sorted(done | (set(seed) & set(c["properties"])))
        _save_seeded(seeded)
    values = {k: str(v) for k, v in data.items() if v not in ("", None) and k not in system}
    mine = {k for k, m in owners.items() if m == MANAGER}
    # a changed value, one we do not own yet (set by hand: emptying it in OpenBao must remove it), or one emptied
    if c.get("every") and secret is None:
        _apply_store(store_ns, c["remote"], values, True)     # the ExternalSecret reads every key: the Secret must exist
        return {"added": len(added), "copied": len(values), "changed": bool(values)}
    why = sorted({k for k, v in values.items() if have.get(k) != v or owners.get(k) != MANAGER} | (mine - set(values)))
    if why:
        log(f"openbao: {path}: store updated ({', '.join(why)})")
        _apply_store(store_ns, c["remote"], values, secret is not None)
        return {"added": len(added), "copied": len(values), "changed": True}
    return {"added": len(added), "copied": len(values)}


def sync_policies(bao: Bao, namespaces: set[str]) -> int:
    n = 0
    for ns in sorted(namespaces):
        name = f"app-{ns}"
        cur = bao.call("GET", f"sys/policies/acl/{name}", ok404=True)
        if ((cur or {}).get("data") or {}).get("policy") != app_policy(ns):
            bao.call("PUT", f"sys/policies/acl/{name}", {"policy": app_policy(ns)})
            n += 1
    return n


def _secret_names(obj: dict) -> set[str]:
    """The Secrets a Deployment's or StatefulSet's pods read: environment variables, and files (a file mounted alone,
    with subPath, as the certificates are, changes only when the pod restarts)."""
    pod = ((obj.get("spec") or {}).get("template") or {}).get("spec") or {}
    out = set()
    for ct in (pod.get("containers") or []) + (pod.get("initContainers") or []):
        out |= {((e.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name") for e in ct.get("env") or []}
        out |= {(e.get("secretRef") or {}).get("name") for e in ct.get("envFrom") or []}
    out |= {(v.get("secret") or {}).get("secretName") for v in pod.get("volumes") or []}
    out.discard(None)
    return out


def _uses(obj: dict, secret: str) -> bool:
    return secret in _secret_names(obj)


def _secret_versions(ns: str) -> dict[str, str]:
    """{Secret: what its data is} in `ns`, without reading a value: ESO's hash of the data it wrote (else the
    Secret's resourceVersion)."""
    raw = _run(["-n", ns, "get", "secrets", "-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\t\"}"
                "{.metadata.resourceVersion}{\"\\t\"}{.metadata.annotations.reconcile\\.external-secrets\\.io/data-hash}"
                "{\"\\n\"}{end}"], ok_missing=True) or ""
    out = {}
    for line in raw.splitlines():
        name, rv, h = (line.split("\t") + ["", ""])[:3]
        if name:
            out[name] = h or rv
    return out


def apply_now(changed: list[dict], log=print, wait: float = 60.0) -> None:
    """New values without waiting: each changed component's ExternalSecret syncs now (ESO's force-sync annotation,
    instead of its refresh interval), then the workloads that read the Secret restart (environment variables are
    read when a container starts). CronJobs read it at their next run.

    A workload restarts by a fingerprint of the Secrets it reads in its pod template (RESTART_ANNOTATION), not by
    `kubectl rollout restart`: the same values give the same fingerprint, so nothing restarts when the store was
    written but what the app gets did not change, and a workload whose settings and files both changed restarts
    once."""
    import hashlib
    import time
    stamp = str(int(time.time()))
    for c in changed:
        _run(["-n", c["namespace"], "annotate", "externalsecrets.external-secrets.io", c.get("es") or c["component"] + SUFFIX,
              f"force-sync={stamp}", "--overwrite"], ok_missing=True)
    end = time.monotonic() + wait
    targets: dict[str, set[str]] = {}
    for c in changed:
        name = c.get("es") or c["component"] + SUFFIX
        while True:     # synced after the annotation (status.refreshTime is RFC 3339, seconds)
            raw = _run(["-n", c["namespace"], "get", "externalsecrets.external-secrets.io", name, "-o", "json"],
                       ok_missing=True)
            es = json.loads(raw) if raw else {}
            t = (es.get("status") or {}).get("refreshTime") or ""
            if not raw or _epoch(t) >= int(stamp) or time.monotonic() > end:
                break
            time.sleep(3)
        target = (((es.get("spec") or {}).get("target") or {}).get("name")) or name
        targets.setdefault(c["namespace"], set()).add(target)
    for ns, names in sorted(targets.items()):
        raw = _run(["-n", ns, "get", "deployments.apps,statefulsets.apps", "-o", "json"], ok_missing=True)
        versions = None
        for w in (json.loads(raw).get("items") or []) if raw else []:
            reads = _secret_names(w)
            if not reads & names:
                continue
            if versions is None:
                versions = _secret_versions(ns)
            mark = hashlib.sha256("\n".join(f"{s}={versions.get(s, '')}" for s in sorted(reads)).encode()).hexdigest()[:16]
            have = ((((w.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("annotations") or {})
            if have.get(RESTART_ANNOTATION) == mark:
                continue
            _run(["-n", ns, "patch", f"{w['kind'].lower()}/{w['metadata']['name']}", "--type", "merge", "-p",
                  json.dumps({"spec": {"template": {"metadata": {"annotations": {RESTART_ANNOTATION: mark}}}}})],
                 ok_missing=True)
            log(f"openbao: {ns}/{w['metadata']['name']} restarted with its new values")


def _epoch(t: str) -> int:
    from datetime import datetime
    try:
        return int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


FORGET_WAIT = 24 * 3600     # a forgotten namespace still in the sandbox after this (enabled again): request dropped


def pending_forgets(path: Path | None = None) -> dict[str, float]:
    """{namespace: when it was asked for (epoch)}."""
    try:
        v = json.loads((path or FORGET_PATH).read_text())
    except (OSError, ValueError):
        return {}
    return {str(k): float(t) for k, t in v.items() if isinstance(t, (int, float))} if isinstance(v, dict) else {}


def _save_forgets(pending: dict[str, float], path: Path | None = None) -> None:
    p = path or FORGET_PATH
    if not pending:
        p.unlink(missing_ok=True)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(pending, sort_keys=True))
    os.replace(tmp, p)


def request_forget(ns: str, path: Path | None = None, now: float | None = None) -> None:
    """The system agent (root): remember that namespace `ns`'s OpenBao entries are to go (sync does it)."""
    import time
    from .labservices import NS_RE, RESERVED_NS
    if not NS_RE.fullmatch(ns or "") or ns in RESERVED_NS or ns.startswith(("containerizer-", "kube-")):
        raise ValueError(f"not an application namespace: {ns!r}")
    _save_forgets({**pending_forgets(path), ns: time.time() if now is None else now}, path)


def login(addr: str, username: str, password: str) -> Bao:
    """A user name and password sign-in (userpass)."""
    t = Bao(addr).call("POST", f"auth/userpass/login/{username}", {"password": password}) or {}
    token = (t.get("auth") or {}).get("client_token")
    if not token:
        raise BaoError(f"signing in as {username} gave no token")
    return Bao(addr, token)


def policy_hash() -> str:
    import hashlib
    return hashlib.sha256(SYNC_HCL.encode()).hexdigest()


def write_sync_policy(admin: Bao) -> None:
    """The sync job's policy as this version has it, written by an administrator (cz-admin may write policies)."""
    try:
        admin.call("PUT", f"sys/policies/acl/{SYNC_POLICY}", {"policy": SYNC_HCL})
    finally:
        try:
            admin.call("POST", "auth/token/revoke-self")
        except BaoError:
            pass
    _write_secret("openbao-sync-policy", policy_hash())


def sync_policy_current(bao: Bao) -> None:
    """Appliances set up before Forget deleted anything (0.41.2 and older) have a sync policy without delete: update
    it once as the appliance's user admin. When its password was changed (docs/openbao.md says to), an administrator
    runs `cz openbao-policy` once. The policy's hash is kept next to the sync token."""
    if _read_secret("openbao-sync-policy") == policy_hash():
        return
    password = _read_secret("openbao-admin")
    try:
        admin = login(bao.addr, "admin", password) if password else None
    except BaoError:
        admin = None
    if admin is None:
        raise BaoError("the sync job may not delete yet: run `cz openbao-policy` as root once (it asks for an OpenBao "
                       "administrator's user name and password) and the forgotten apps' entries go")
    write_sync_policy(admin)


def forget_namespace(bao: Bao, store_ns: str, ns: str, log=print) -> int:
    """Delete namespace `ns`'s entries (all versions), its policy and the remote Secrets of those components in the
    store. Returns the number of entries deleted."""
    listed = bao.call("LIST", f"{MOUNT}/metadata/{ns}", ok404=True) or {}
    comps = [k for k in (listed.get("data") or {}).get("keys") or [] if not k.endswith("/")]
    for comp in comps:
        bao.call("DELETE", f"{MOUNT}/metadata/{ns}/{comp}", ok404=True)
        _run(["-n", store_ns, "delete", "secret", _remote_key(ns, comp), "--ignore-not-found"], ok_missing=True)
    bao.call("DELETE", f"sys/policies/acl/app-{ns}", ok404=True)
    import shutil
    shutil.rmtree(SEED_DIR / ns, ignore_errors=True)
    seeded = _json_file(SEEDED_PATH)
    if any(k.startswith(f"{ns}/") for k in seeded):
        _save_seeded({k: v for k, v in seeded.items() if not k.startswith(f"{ns}/")})
    log(f"openbao: forgot {ns}: {len(comps)} entr{'y' if len(comps) == 1 else 'ies'}, policy app-{ns}")
    return len(comps)


def sync(log=print) -> int:
    from . import eso
    bao = Bao()
    try:
        bao.token = setup(bao, log)
        bao.call("POST", "auth/token/renew-self", {})
        items = json.loads(_run(["get", "externalsecrets.external-secrets.io", "-A", "-o", "json"]) or "{}").get("items") or []
    except BaoError as ex:
        log(f"openbao: {ex}")
        return 1
    store_ns, comps, rc = eso.remote_namespace(), component_secrets(items), 0
    # forgotten applications: nothing of theirs is synced; their entries go once the scan pruned their namespace
    forget = pending_forgets()
    if forget:
        import time
        live = {c["namespace"] for c in comps}
        done = []
        for ns, asked in sorted(forget.items()):
            if ns in live:
                if time.time() - asked > FORGET_WAIT:
                    log(f"openbao: forget {ns}: still in the sandbox a day later (enabled again?): its entries stay")
                    done.append(ns)
                continue
            try:
                sync_policy_current(bao)
                forget_namespace(bao, store_ns, ns, log)
                done.append(ns)
            except BaoError as ex:
                log(f"openbao: forget {ns}: {ex}")
                rc = 1
        if done:
            _save_forgets({k: v for k, v in pending_forgets().items() if k not in done})
        comps = [c for c in comps if c["namespace"] not in pending_forgets()]
    added = copied = 0
    changed = []
    for c in comps:
        try:
            r = sync_component(bao, store_ns, c, log)
            added, copied = added + r["added"], copied + r["copied"]
            if r.get("changed"):
                changed.append(c)
        except BaoError as ex:
            log(f"openbao: {c['namespace']}/{c['component']}: {ex}")
            rc = 1
    try:
        sync_policies(bao, {c["namespace"] for c in comps})
    except BaoError as ex:
        log(f"openbao: policies: {ex}")
        rc = 1
    if added:
        log(f"openbao: {added} new placeholder(s); {copied} value(s) in the store for {len(comps)} component(s)")
    try:
        apply_now(changed, log)
    except BaoError as ex:
        log(f"openbao: {ex}")
        rc = 1
    return rc


# --------------------------------------------------------------------------- the sandbox side (generated)

def sandbox_patches(docs: list[dict]) -> list[dict]:
    """kustomize patches for the sandbox: each component's settings ExternalSecret reads every key its remote Secret
    has (dataFrom extract) instead of a fixed list, keeping the list in an annotation for the appliance. A key nobody
    filled yet is then not set (the app's appsettings value applies) instead of keeping the whole Secret away: ESO
    creates none of a Secret's keys when one listed property is missing."""
    out = []
    for d in docs:
        meta, spec = d.get("metadata") or {}, d.get("spec") or {}
        data = spec.get("data") or []
        if d.get("kind") != "ExternalSecret" or not str(meta.get("name", "")).endswith(SUFFIX) or not data:
            continue
        remotes = {(x.get("remoteRef") or {}).get("key") for x in data}
        if len(remotes) != 1 or None in remotes:
            continue
        props = ",".join(sorted(x["secretKey"] for x in data if x.get("secretKey")))
        patch = {"apiVersion": d.get("apiVersion"), "kind": "ExternalSecret",
                 "metadata": {"name": meta["name"], "annotations": {PROPERTIES: props}},
                 "spec": {"data": None, "dataFrom": [{"extract": {"key": remotes.pop()}}]}}
        out.append({"target": {"group": "external-secrets.io", "kind": "ExternalSecret", "name": meta["name"]},
                    "patch": json.dumps(patch)})
    return out


def main(argv: list[str]) -> int:
    if argv[:1] == ["sync"]:
        return sync(lambda m: print(m, file=sys.stderr))
    if argv[:1] == ["status"]:
        print(json.dumps(Bao().call("GET", "sys/seal-status"), indent=2))
        return 0
    print("usage: python -m containerizer.openbao sync|status", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
