"""OpenBao on the appliance: where administrators and operators enter the values of the sandbox apps' secrets
(docs/openbao.md).

The apps' ExternalSecrets keep reading the appliance's own store (ClusterSecretStore app-secrets, the kubernetes
provider over namespace containerizer-secrets, docs/external-secrets.md); the appliance's own writers (Git tokens,
the Flux webhook, the sandbox IdP, lab services) keep writing there. OpenBao is the place for people:

- **Placeholders.** For every component's `<component>-secrets` ExternalSecret in the sandbox, OpenBao gets the
  entry `apps/<namespace>/<component>` (KV version 2) with one key per property the component reads: empty, or the
  value already in the store (set by hand before). Keys another appliance writer owns (the sandbox IdP's client
  secret) are left out: they are filled automatically.
- **Copy.** The keys with a value are copied to the store's remote Secret `<namespace>--<component>` (server-side
  apply, field manager `containerizer-openbao`, so the other writers' keys stay); a key emptied in OpenBao is removed
  there. In the sandbox the component's ExternalSecret reads every key the remote Secret has (sandbox_patches), so a
  value that is not filled yet is simply not set: the app's own appsettings value applies.
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
MOUNT = "apps"                              # KV version 2: apps/<namespace>/<component>
MANAGER = "containerizer-openbao"           # field manager of the copied keys in the store
PROPERTIES = "containerizer.io/properties"  # the properties a component reads (sandbox_patches keeps them)
SUFFIX = "-secrets"                         # the ExternalSecret of a component's settings (harden.externalize_secrets)
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
path "{MOUNT}/metadata/*" {{ capabilities = ["read", "list"] }}
path "sys/policies/acl/app-*" {{ capabilities = ["create", "read", "update"] }}
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
    """The components' settings ExternalSecrets among `items` (kubectl get externalsecrets -A): namespace, component,
    remote key and the properties it reads (the annotation the sandbox patch keeps, or its data list)."""
    out = []
    for es in items:
        meta, spec = es.get("metadata") or {}, es.get("spec") or {}
        name, ns = meta.get("name") or "", meta.get("namespace") or ""
        if not name.endswith(SUFFIX) or not ns or ns.startswith(("containerizer-", "flux-system", "kube-")):
            continue
        ann = (meta.get("annotations") or {}).get(PROPERTIES)
        data = spec.get("data") or []
        remotes = {(d.get("remoteRef") or {}).get("key") for d in data} | \
                  {(d.get("extract") or {}).get("key") for d in spec.get("dataFrom") or [] if d.get("extract")}
        remotes.discard(None)
        if len(remotes) != 1:
            continue
        component, remote = name[:-len(SUFFIX)], remotes.pop()
        # only the namespace's own key: an ExternalSecret naming another namespace's key must not let this
        # namespace's operators write that one (the store's Role keeps it from reading it anyway)
        if remote != _remote_key(ns, component):
            continue
        props = [p for p in ann.split(",") if p] if ann is not None else [d.get("secretKey") for d in data]
        out.append({"namespace": ns, "component": component, "remote": remote,
                    "properties": sorted(p for p in props if p)})
    return out


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


def sync_component(bao: Bao, store_ns: str, c: dict, log=print) -> dict:
    """Placeholders in OpenBao for one component, then its filled values into the store. Returns counts."""
    path = f"{c['namespace']}/{c['component']}"
    got = bao.call("GET", f"{MOUNT}/data/{path}", ok404=True)
    data = dict(((got or {}).get("data") or {}).get("data") or {})
    version = (((got or {}).get("data") or {}).get("metadata") or {}).get("version") or 0
    if got is None:     # none, or its latest version deleted (its values are cleared): write after that version
        meta = bao.call("GET", f"{MOUNT}/metadata/{path}", ok404=True)
        version = ((meta or {}).get("data") or {}).get("current_version") or 0
    raw = _run(["-n", store_ns, "get", "secret", c["remote"], "-o", "json"], ok_missing=True)
    secret = json.loads(raw) if raw else None
    owners, have = _owners(secret or {}), _decode(secret)
    system = {k for k, m in owners.items() if _system(m)}
    added = [p for p in c["properties"] if p not in data and p not in system]
    if added:
        # an empty placeholder, or the value someone already put in the store by hand
        data.update({p: have.get(p, "") if not _system(owners.get(p, "")) else "" for p in added})
        try:
            bao.call("POST", f"{MOUNT}/data/{path}", {"options": {"cas": version}, "data": data})
        except BaoError as ex:
            if "check-and-set" in str(ex):
                return {"added": 0, "copied": 0}      # someone saved it just now: next round
            raise
    values = {k: str(v) for k, v in data.items() if v not in ("", None) and k not in system}
    mine = {k for k, m in owners.items() if m == MANAGER}
    # a changed value, one we do not own yet (set by hand: emptying it in OpenBao must remove it), or one emptied
    if any(have.get(k) != v or owners.get(k) != MANAGER for k, v in values.items()) or mine - set(values):
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


def _uses(obj: dict, secret: str) -> bool:
    """A Deployment or StatefulSet whose containers read Secret `secret` as environment variables."""
    pod = ((obj.get("spec") or {}).get("template") or {}).get("spec") or {}
    for ct in (pod.get("containers") or []) + (pod.get("initContainers") or []):
        if any(((e.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name") == secret for e in ct.get("env") or []):
            return True
        if any((e.get("secretRef") or {}).get("name") == secret for e in ct.get("envFrom") or []):
            return True
    return False


def apply_now(changed: list[dict], log=print, wait: float = 60.0) -> None:
    """New values without waiting: each changed component's ExternalSecret syncs now (ESO's force-sync annotation,
    instead of its refresh interval), then the workloads that read the Secret restart (environment variables are
    read when a container starts). CronJobs read it at their next run."""
    import time
    stamp = str(int(time.time()))
    for c in changed:
        _run(["-n", c["namespace"], "annotate", "externalsecrets.external-secrets.io", c["component"] + SUFFIX,
              f"force-sync={stamp}", "--overwrite"], ok_missing=True)
    end = time.monotonic() + wait
    for c in changed:
        name = c["component"] + SUFFIX
        while True:     # synced after the annotation (status.refreshTime is RFC 3339, seconds)
            raw = _run(["-n", c["namespace"], "get", "externalsecrets.external-secrets.io", name, "-o", "json"],
                       ok_missing=True)
            st = (json.loads(raw).get("status") or {}) if raw else {}
            t = st.get("refreshTime") or ""
            if not raw or _epoch(t) >= int(stamp) or time.monotonic() > end:
                break
            time.sleep(3)
        raw = _run(["-n", c["namespace"], "get", "deployments.apps,statefulsets.apps", "-o", "json"], ok_missing=True)
        for w in (json.loads(raw).get("items") or []) if raw else []:
            if _uses(w, name):
                _run(["-n", c["namespace"], "rollout", "restart", f"{w['kind'].lower()}/{w['metadata']['name']}"],
                     ok_missing=True)
                log(f"openbao: {c['namespace']}/{w['metadata']['name']} restarted with its new values")


def _epoch(t: str) -> int:
    from datetime import datetime
    try:
        return int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


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
