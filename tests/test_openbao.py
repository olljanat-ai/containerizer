"""OpenBao on the appliance (containerizer/openbao.py): placeholders, the copy into the store, operators' policies
and the sandbox's ExternalSecret patch."""
import base64
import json

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
             es("shop", "web-files", ["cert.pfx"]),                       # files: not settings
             es("flux-system", "x-secrets", ["a"]),                       # the appliance's own
             {"metadata": {"name": "web-secrets", "namespace": "evil"},   # another namespace's key: never written
              "spec": {"data": [{"secretKey": "a", "remoteRef": {"key": "shop--web", "property": "a"}}]}}]
    assert ob.component_secrets(items) == [
        {"namespace": "shop", "component": "web", "remote": "shop--web", "properties": ["Api__Url", "Smtp__Auth"]},
        {"namespace": "shop", "component": "api", "remote": "shop--api", "properties": ["ConnectionStrings__Main"]}]


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
    calls = []
    dep = {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {"template": {"spec": {"containers": [
        {"env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "web-secrets", "key": "A"}}}]}]}}}}
    other = {"kind": "StatefulSet", "metadata": {"name": "db"}, "spec": {"template": {"spec": {"containers": [{}]}}}}

    def run(args, stdin=None, ok_missing=False):
        calls.append(args)
        if args[2] == "get" and args[3].startswith("externalsecrets"):
            return json.dumps({"status": {"refreshTime": "2999-01-01T00:00:00Z"}})
        if args[2] == "get":
            return json.dumps({"items": [dep, other]})
        return ""
    monkeypatch.setattr(ob, "_run", run)
    ob.apply_now([{"namespace": "shop", "component": "web"}], log=lambda m: None)
    assert calls[0][:4] == ["-n", "shop", "annotate", "externalsecrets.external-secrets.io"]
    assert calls[0][5].startswith("force-sync=")
    assert ["-n", "shop", "rollout", "restart", "deployment/web"] in calls
    assert not any("statefulset/db" in c for c in calls)


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
    assert adm.openbao_link(now=161.0) == "https://cz.example.com/ui/vault/auth?with=oidc%2F"
    assert len(answers) == n + 2
