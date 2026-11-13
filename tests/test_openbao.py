"""OpenBao on the appliance (containerizer/openbao.py): placeholders, the copy into the store, operators' policies
and the sandbox's ExternalSecret patch."""
import base64
import json
from pathlib import Path

import pytest

from containerizer import openbao as ob


class FakeBao(ob.Bao):
    def __init__(self):
        super().__init__("http://bao", "t")
        self.kv: dict[str, tuple[dict, int]] = {}
        self.policies: dict[str, str] = {}
        self.calls = []

    def call(self, method, path, body=None, ok404=False):
        self.calls.append((method, path))
        if path == "auth/token/renew-self":
            return {}
        if path.startswith("apps/data/"):
            p = path[len("apps/data/"):]
            if method == "GET":
                if p not in self.kv:
                    return None
                data, v = self.kv[p]
                return {"data": {"data": dict(data), "metadata": {"version": v}}}
            data, v = self.kv.get(p, ({}, 0))
            if body["options"]["cas"] != v:
                raise ob.BaoError("check-and-set parameter did not match the current version")
            self.kv[p] = (dict(body["data"]), v + 1)
            return {}
        if path.startswith("apps/metadata/"):
            return None
        if path.startswith("sys/policies/acl/"):
            name = path.rsplit("/", 1)[1]
            if method == "GET":
                return {"data": {"policy": self.policies[name]}} if name in self.policies else None
            self.policies[name] = body["policy"]
            return {}
        raise AssertionError(path)


def es(ns, name, props=None, annotated=None):
    meta = {"name": name, "namespace": ns}
    spec = {}
    if annotated is not None:
        meta["annotations"] = {ob.PROPERTIES: annotated}
        spec["dataFrom"] = [{"extract": {"key": f"{ns}--{name[:-8]}"}}]
    else:
        spec["data"] = [{"secretKey": p, "remoteRef": {"key": f"{ns}--{name[:-8]}", "property": p}} for p in props]
    return {"metadata": meta, "spec": spec}


def test_component_secrets_from_patched_and_plain_external_secrets():
    items = [es("shop", "web-secrets", annotated="Api__Url,Smtp__Auth"),
             es("shop", "api-secrets", ["ConnectionStrings__Main"]),
             es("shop", "web-files", ["cert.pfx"]),                       # files of another remote key: not its own
             es("flux-system", "x-secrets", ["a"]),                       # the appliance's own
             {"metadata": {"name": "web-secrets", "namespace": "evil"},   # another namespace's key: never written
              "spec": {"data": [{"secretKey": "a", "remoteRef": {"key": "shop--web", "property": "a"}}]}}]
    assert ob.component_secrets(items) == [
        {"namespace": "shop", "component": "web", "es": "web-secrets", "remote": "shop--web",
         "properties": ["Api__Url", "Smtp__Auth"], "every": True},
        {"namespace": "shop", "component": "api", "es": "api-secrets", "remote": "shop--api",
         "properties": ["ConnectionStrings__Main"], "every": False}]


def store_secret(values: dict, owners: dict):
    return {"metadata": {"managedFields": [{"manager": m, "fieldsV1": {"f:data": {f"f:{k}": {}}}}
                                           for k, m in owners.items()]},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in values.items()}}


@pytest.fixture
def kube(monkeypatch):
    state = {"secret": None, "applied": []}

    def run(args, stdin=None, ok_missing=False):
        if args[:2] == ["-n", "containerizer-secrets"] and args[2] == "get":
            return json.dumps(state["secret"]) if state["secret"] else None
        if args[0] == "apply":
            assert f"--field-manager={ob.MANAGER}" in args
            state["applied"].append(json.loads(stdin))
            return ""
        raise AssertionError(args)
    monkeypatch.setattr(ob, "_run", run)
    return state


C = {"namespace": "shop", "component": "web", "remote": "shop--web",
     "properties": ["Api__Url", "ClientSecret", "Smtp__Auth"]}


def test_placeholders_keep_values_set_by_hand_and_skip_the_idp_key(kube):
    """Empty entries for the admin to fill; a value someone put in the store by hand is kept (moved into OpenBao);
    the sandbox IdP's client secret is not a placeholder (another appliance writer fills it)."""
    kube["secret"] = store_secret({"Smtp__Auth": "s3cret", "ClientSecret": "idp"},
                                  {"Smtp__Auth": "kubectl-client-side-apply", "ClientSecret": "containerizer-idp"})
    bao = FakeBao()
    r = ob.sync_component(bao, "containerizer-secrets", C)
    assert bao.kv["shop/web"] == ({"Api__Url": "", "Smtp__Auth": "s3cret"}, 1)
    assert r == {"added": 2, "copied": 1, "changed": True}
    # the filled value is copied (ours now), the empty one is not
    assert kube["applied"][-1]["data"] == {"Smtp__Auth": base64.b64encode(b"s3cret").decode()}


def test_filled_values_are_copied_and_an_emptied_one_is_removed(kube):
    bao = FakeBao()
    bao.kv["shop/web"] = ({"Api__Url": "https://api", "Smtp__Auth": "", "ClientSecret": ""}, 3)
    ob.sync_component(bao, "containerizer-secrets", C)
    assert kube["applied"][-1]["data"] == {"Api__Url": base64.b64encode(b"https://api").decode()}
    # nothing changed: no apply
    kube["secret"] = store_secret({"Api__Url": "https://api"}, {"Api__Url": ob.MANAGER})
    n = len(kube["applied"])
    ob.sync_component(bao, "containerizer-secrets", C)
    assert len(kube["applied"]) == n
    # emptied in OpenBao: applied without it, so server-side apply removes our key
    bao.kv["shop/web"] = ({"Api__Url": "", "Smtp__Auth": "", "ClientSecret": ""}, 4)
    ob.sync_component(bao, "containerizer-secrets", C)
    assert "data" not in kube["applied"][-1]


def test_a_concurrent_save_is_left_for_the_next_round(kube):
    bao = FakeBao()
    real = bao.call

    def racing(method, path, body=None, ok404=False):
        if method == "POST":
            raise ob.BaoError("POST apps/data/shop/web: HTTP 400 check-and-set parameter did not match")
        return real(method, path, body, ok404)
    bao.call = racing
    assert ob.sync_component(bao, "containerizer-secrets", C) == {"added": 0, "copied": 0}
    assert kube["applied"] == []


def test_operators_get_one_policy_per_namespace_written_once():
    bao = FakeBao()
    assert ob.sync_policies(bao, {"shop", "hr"}) == 2
    assert 'path "apps/data/shop/*"' in bao.policies["app-shop"] and "hr" not in bao.policies["app-shop"]
    assert ob.sync_policies(bao, {"shop", "hr"}) == 0


def test_sandbox_patch_reads_every_key_and_keeps_the_list():
    docs = [{"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret", "metadata": {"name": "web-secrets"},
             "spec": {"data": [{"secretKey": k, "remoteRef": {"key": "shop--web", "property": k}}
                               for k in ("B", "A")]}},
            {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret", "metadata": {"name": "web-files"},
             "spec": {"data": [{"secretKey": "c.pfx", "remoteRef": {"key": "shop--web", "property": "c.pfx"}}]}}]
    [p] = ob.sandbox_patches(docs)
    assert p["target"] == {"group": "external-secrets.io", "kind": "ExternalSecret", "name": "web-secrets"}
    body = json.loads(p["patch"])
    assert body["metadata"]["annotations"] == {ob.PROPERTIES: "A,B"}
    assert body["spec"] == {"data": None, "dataFrom": [{"extract": {"key": "shop--web"}}]}


def test_changed_values_sync_now_and_restart_the_workloads_that_read_them(monkeypatch):
    """A workload restarts by a fingerprint of the Secrets it reads in its pod template: once, though its settings and
    its files both changed, and never again while what ESO wrote stays the same (a restart every sync round made a
    new ReplicaSet every 2 minutes)."""
    calls = []
    dep = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {"template": {"spec": {
        "containers": [{"env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "web-secrets", "key": "A"}}}]}],
        "volumes": [{"name": "files", "secret": {"secretName": "web-files"}}]}}}}
    other = {"kind": "StatefulSet", "metadata": {"name": "db"}, "spec": {"template": {"spec": {"containers": [{}]}}}}
    hashes = {"web-secrets": "h1", "web-files": "h2"}

    def run(args, stdin=None, ok_missing=False):
        calls.append(args)
        if args[2] == "get" and args[3].startswith("externalsecrets"):
            return json.dumps({"status": {"refreshTime": "2999-01-01T00:00:00Z"}})
        if args[2:4] == ["get", "secrets"]:
            return "".join(f"{k}\t7\t{v}\n" for k, v in hashes.items())
        if args[2] == "get":
            return json.dumps({"items": [dep, other]})
        if args[2] == "patch":
            ann = json.loads(args[-1])["spec"]["template"]["metadata"]["annotations"]
            dep["spec"]["template"].setdefault("metadata", {}).setdefault("annotations", {}).update(ann)
        return ""
    monkeypatch.setattr(ob, "_run", run)
    both = [{"namespace": "shop", "component": "web", "es": "web-secrets"},
            {"namespace": "shop", "component": "web-files", "es": "web-files"}]
    ob.apply_now(both, log=lambda m: None)
    assert calls[0][:4] == ["-n", "shop", "annotate", "externalsecrets.external-secrets.io"]
    assert calls[0][5].startswith("force-sync=")
    patches = [c for c in calls if c[2] == "patch"]
    assert [c[3] for c in patches] == ["deployment/web"]
    assert not any("rollout" in c for c in calls)
    # the next round: the store was written again, but the app's Secrets are the same: no restart
    calls.clear()
    ob.apply_now(both, log=lambda m: None)
    assert not any(c[2] == "patch" for c in calls)
    # a value changed: ESO's data hash changes, the app restarts
    hashes["web-files"] = "h3"
    calls.clear()
    ob.apply_now(both[1:], log=lambda m: None)
    assert [c[3] for c in calls if c[2] == "patch"] == ["deployment/web"]


def test_secrets_link_opens_oidc_sign_in_once_openbao_has_it(monkeypatch):
    """The admin pages' Secrets link: OpenBao's sign-in with OIDC selected when it has the method (asked without a
    token, at most once a minute), its front page otherwise."""
    import urllib.error
    from containerizer import admin as adminmod, openbao
    answers = []

    def fake(req, timeout=0):
        assert req.full_url == "http://127.0.0.1:8200/v1/auth/oidc/oidc/auth_url" and req.get_method() == "POST"
        answers.append(1)
        code = codes[0]
        if code == 200:
            class R:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False
            return R()
        if code == 0:
            raise urllib.error.URLError("refused")
        raise urllib.error.HTTPError(req.full_url, code, "x", {}, None)
    monkeypatch.setattr(openbao.urllib.request, "urlopen", fake)
    codes = [403]
    assert not openbao.oidc_enabled("http://127.0.0.1:8200")
    for c, want in ((400, True), (200, True), (0, False), (404, False)):
        codes[0] = c
        assert openbao.oidc_enabled("http://127.0.0.1:8200") is want

    adm = adminmod.Admin.__new__(adminmod.Admin)
    adm.openbao_url, adm.openbao_api, adm._openbao_sso = "https://cz.example.com/ui/", "", None
    assert adm.openbao_link() == "https://cz.example.com/ui/"                 # not on the appliance: never asked
    adm.openbao_api = "http://127.0.0.1:8200"
    codes[0], n = 403, len(answers)
    assert adm.openbao_link(now=100.0) == "https://cz.example.com/ui/"
    codes[0] = 400
    assert adm.openbao_link(now=130.0) == "https://cz.example.com/ui/"        # asked once a minute
    assert adm.openbao_link(now=161.0) == "/admin/secrets"                     # straight to the provider (below)
    assert len(answers) == n + 2


def test_secrets_link_signs_in_to_openbao_without_its_sign_in_page(monkeypatch):
    """/admin/secrets starts OpenBao's OIDC sign-in for the UI's own redirect URI, with the state in a cookie only the
    callback gets; the callback (Caddy sends it to the web UI when the cookie is there) has OpenBao finish it and opens
    the UI with the wrapped token. A callback without our state goes to OpenBao's sign-in page."""
    from urllib.parse import urlencode
    from containerizer import admin as adminmod, openbao
    from containerizer.oidc import OidcConfig
    calls = []
    monkeypatch.setattr(openbao, "sso_start", lambda api, pub: calls.append(("start", api, pub)) or
                        ("https://login.example.com/authorize?state=st1&x=1", "st1", "nonce1"))
    monkeypatch.setattr(openbao, "sso_finish", lambda api, st, code, nonce: calls.append(("finish", st, code, nonce))
                        or ("hvs.wrapped" if code == "good" else None))
    cfg = OidcConfig.from_env({"CONTAINERIZER_OIDC_ISSUER": "https://login.example.com", "CONTAINERIZER_OIDC_CLIENT_ID": "c",
                               "CONTAINERIZER_PUBLIC_URL": "https://cz.example.com", "CONTAINERIZER_ADMINS": "role:Admin"})
    adm = adminmod.Admin(cfg, lambda: None, provider=object())
    adm.openbao_url, adm.openbao_api = "https://cz.example.com/ui/", "http://127.0.0.1:8200"
    r = adm.openbao_start()
    h = dict(r.headers)
    assert r.status == 303 and h["Location"].startswith("https://login.example.com/authorize?state=st1")
    assert h["Set-Cookie"].startswith("cz_bao_sso=st1; Path=/ui/vault/auth/oidc/oidc/callback; HttpOnly; SameSite=Lax")
    assert calls[0] == ("start", "http://127.0.0.1:8200", "https://cz.example.com")
    assert adm.handles("/ui/vault/auth/oidc/oidc/callback")

    def cb(query, cookie):
        return adm.handle("GET", "/ui/vault/auth/oidc/oidc/callback", urlencode(query), {"Cookie": cookie}, b"")
    r = cb({"state": "st1", "code": "good"}, "cz_bao_sso=other")          # not the browser that started it
    assert dict(r.headers)["Location"] == "https://cz.example.com/ui/vault/auth?with=oidc%2F"
    r = cb({"state": "st1", "code": "good"}, "a=b; cz_bao_sso=st1")
    h = dict(r.headers)
    assert h["Location"] == "https://cz.example.com/ui/vault/auth?wrapped_token=hvs.wrapped"
    assert ("finish", "st1", "good", "nonce1") in calls and "Max-Age=0" in h["Set-Cookie"]
    r = cb({"state": "st1", "code": "good"}, "cz_bao_sso=st1")            # used once only
    assert dict(r.headers)["Location"].endswith("with=oidc%2F")
    adm.openbao_start()
    r = cb({"state": "st1", "code": "bad"}, "cz_bao_sso=st1")             # OpenBao refused: its own sign-in page
    assert dict(r.headers)["Location"].endswith("with=oidc%2F")
    monkeypatch.setattr(openbao, "sso_start", lambda api, pub: None)
    assert dict(adm.openbao_start().headers)["Location"].endswith("with=oidc%2F")
    adm.openbao_api = ""
    assert not adm.handles("/ui/vault/auth/oidc/oidc/callback")        # not on the appliance: never routed here


def test_forget_waits_for_the_prune_then_deletes_entries_policy_and_store_values(tmp_path, monkeypatch):
    """Forget application: the namespace is left alone while its ExternalSecrets are still in the sandbox (so the
    placeholders are not written again), then its entries, policy and remote Secrets go; other apps stay."""
    monkeypatch.setattr(ob, "FORGET_PATH", tmp_path / "forget.json")
    monkeypatch.setattr(ob, "SECRETS", tmp_path)
    ob._write_secret("openbao-sync-policy", ob.policy_hash())
    with pytest.raises(ValueError):
        ob.request_forget("kube-system")
    ob.request_forget("shop")
    bao = FakeBao()
    bao.kv = {"shop/web": ({"A": "1"}, 2), "other/api": ({"B": "2"}, 1)}
    bao.policies = {"app-shop": "x", "app-other": "y"}
    base = bao.call

    def call(method, path, body=None, ok404=False):
        if method == "LIST" and path == "apps/metadata/shop":
            return {"data": {"keys": ["web"]}}
        if method == "DELETE":
            bao.calls.append((method, path))
            if path.startswith("apps/metadata/"):
                bao.kv.pop(path[len("apps/metadata/"):], None)
            else:
                bao.policies.pop(path.rsplit("/", 1)[1], None)
            return {}
        return base(method, path, body, ok404)
    bao.call = call
    cluster = {"items": [es("shop", "web-secrets", ["A"]), es("other", "api-secrets", ["B"])]}
    kubectl = []

    def run(args, stdin=None, ok_missing=False):
        kubectl.append(args)
        return json.dumps(cluster) if "externalsecrets.external-secrets.io" in args else None
    monkeypatch.setattr(ob, "_run", run)
    monkeypatch.setattr(ob, "setup", lambda b, log=print: "t")
    monkeypatch.setattr(ob, "Bao", lambda *a, **k: bao)
    monkeypatch.setattr(ob, "apply_now", lambda changed, log=print: None)
    assert ob.sync(lambda m: None) == 0
    assert "shop/web" in bao.kv and ("GET", "apps/data/shop/web") not in bao.calls      # left alone, not synced
    cluster["items"] = cluster["items"][1:]                                           # the scan pruned shop
    assert ob.sync(lambda m: None) == 0
    assert "shop/web" not in bao.kv and "app-shop" not in bao.policies and ob.pending_forgets() == {}
    assert ["-n", "containerizer-secrets", "delete", "secret", "shop--web", "--ignore-not-found"] in kubectl
    assert "other/api" in bao.kv and "app-other" in bao.policies


def test_forget_of_a_namespace_scanned_again_is_dropped_after_a_day(tmp_path, monkeypatch):
    monkeypatch.setattr(ob, "FORGET_PATH", tmp_path / "forget.json")
    ob.request_forget("shop", now=0)
    assert set(ob.pending_forgets()) == {"shop"}
    monkeypatch.setattr(ob, "setup", lambda b, log=print: "t")
    bao = FakeBao()
    monkeypatch.setattr(ob, "Bao", lambda *a, **k: bao)
    monkeypatch.setattr(ob, "_run", lambda args, stdin=None, ok_missing=False: json.dumps(
        {"items": [es("shop", "web-secrets", ["A"])]}) if "externalsecrets.external-secrets.io" in args else None)
    monkeypatch.setattr(ob, "apply_now", lambda changed, log=print: None)
    ob.sync(lambda m: None)
    assert ob.pending_forgets() == {} and "shop/web" in bao.kv        # synced again as usual


def test_placeholders_start_with_the_apps_own_values_once(tmp_path, kube, monkeypatch):
    """The scan leaves the development values of the secret settings outside Git (org.write_secret_seed); the sync
    fills each empty key with them once: a key a person empties afterwards stays empty, a filled one is not touched."""
    monkeypatch.setattr(ob, "SEED_DIR", tmp_path / "seed")
    monkeypatch.setattr(ob, "SEEDED_PATH", tmp_path / "seeded.json")
    (tmp_path / "seed" / "shop").mkdir(parents=True)
    (tmp_path / "seed" / "shop" / "web.json").write_text(json.dumps({"Snow__ClientSecret": "dev-secret",
                                                                    "Snow__Password": "dev-pw"}))
    bao = FakeBao()
    bao.kv["shop/web"] = ({"Snow__ClientSecret": "", "Snow__Password": "mine"}, 1)
    c = {"namespace": "shop", "component": "web", "remote": "shop--web",
         "properties": ["Snow__ClientSecret", "Snow__Password", "Other"]}
    ob.sync_component(bao, "containerizer-secrets", c, log=lambda m: None)
    assert bao.kv["shop/web"][0] == {"Snow__ClientSecret": "dev-secret", "Snow__Password": "mine", "Other": ""}
    bao.kv["shop/web"] = ({**bao.kv["shop/web"][0], "Snow__ClientSecret": ""}, bao.kv["shop/web"][1] + 1)
    ob.sync_component(bao, "containerizer-secrets", c, log=lambda m: None)
    assert bao.kv["shop/web"][0]["Snow__ClientSecret"] == ""                  # emptied by a person: stays empty


def test_the_scan_leaves_the_development_values_outside_git(tmp_path):
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_engine import web_app, write
    from containerizer.assess import assess
    from containerizer.org import write_secret_seed
    web_app(tmp_path / "src")
    write(tmp_path / "src", "src/Web/appsettings.json", """
        {"ConnectionStrings": {"Main": "Server=db;Database=a;User Id=u;Password=dev"},
         "Snow": {"ClientSecret": "dev-secret", "TokenEndpoint": "https://snow.example.com/token"}}""")
    write(tmp_path / "src", "src/Web/appsettings.Production.json", '{"Snow": {"ClientSecret": "#{Snow.Secret}#"}}')
    a = assess(tmp_path / "src")
    write_secret_seed(tmp_path / "seed", "shop", a.components)
    f = tmp_path / "seed" / "shop" / "web.json"
    assert json.loads(f.read_text()) == {"ConnectionStrings__Main": "Server=db;Database=a;User Id=u;Password=dev",
                                         "Snow__ClientSecret": "dev-secret"}
    assert f.stat().st_mode & 0o777 == 0o600


def test_a_files_entry_exists_before_anyone_adds_a_file(kube):
    """A component whose repository mounts its files (every key): its OpenBao entry <component>-files is made empty, so
    people see where to add files, and the store's Secret exists so the ExternalSecret syncs; a file added in OpenBao
    (base64) is copied there."""
    bao = FakeBao()
    c = {"namespace": "shop", "component": "web-files", "es": "web-files", "remote": "shop--web-files",
         "properties": [], "every": True}
    ob.sync_component(bao, "containerizer-secrets", c, log=lambda m: None)
    assert bao.kv["shop/web-files"] == ({}, 1)
    assert kube["applied"][-1]["metadata"]["name"] == "shop--web-files" and "data" not in kube["applied"][-1]
    bao.kv["shop/web-files"] = ({"app.pfx": "MIIK"}, 2)
    kube["secret"] = {"metadata": {"name": "shop--web-files", "managedFields": []}, "data": {}}
    r = ob.sync_component(bao, "containerizer-secrets", c, log=lambda m: None)
    assert r["copied"] == 1 and kube["applied"][-1]["data"] == {"app.pfx": base64.b64encode(b"MIIK").decode()}
