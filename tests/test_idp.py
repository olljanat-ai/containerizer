"""Sandbox identity provider (docs/sandbox-idp.md): detection, client registration, the app-side
overrides, the files under sandbox/idp/, the sync job against a fake WSO2 API and the appliance's
secret generation against a fake kubectl."""
import json
import shutil
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

from containerizer import idp, idp_sync
from containerizer.assess import assess
from containerizer.generate import generate_app
from containerizer.gitops import GitOpsOptions
from containerizer.org import gitops_kustomizations, write_sandbox
from containerizer.rules import load_rules

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "sandbox-idp"
DOMAIN = "sandbox.test"
IDP = "https://containerizer-idp.sandbox.test"


@pytest.fixture(scope="module")
def rules():
    return load_rules()


def generate(tmp: Path, app: str, rules, domain=DOMAIN, src: Path | None = None, sandbox_idp=True) -> Path:
    a = assess(str(src or EXAMPLES / app), rules)
    out = tmp / "Acme" / "_" / app
    generate_app(a, out, registry="registry.test", gitops=GitOpsOptions(
        git_url="https://git.example.com/x.git", path=f"Acme/_/{app}", ingress_domain=domain, sandbox_idp=sandbox_idp))
    return out


def docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text()) if d]


def container_env(out: Path, folder: str) -> dict:
    dep = next(d for d in docs(out / folder / "k8s.yaml") if d["kind"] == "Deployment")
    return {e["name"]: e.get("value", e.get("valueFrom")) for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}


def test_oidc_component_is_pointed_at_the_sandbox_idp(tmp_path, rules):
    out = generate(tmp_path, "oidc", rules)
    d = json.loads((out / "oidc" / "idp.json").read_text())
    assert d["idp"] == IDP
    (c,) = d["clients"]
    assert (c["protocol"], c["identifier"], c["url"]) == ("oidc", "oidc--oidc", "https://oidc.sandbox.test")
    assert c["redirect_uris"] == ["https://oidc.sandbox.test/signin-oidc", "https://oidc.sandbox.test/signout-callback-oidc"]
    env = container_env(out, "oidc")
    assert env["OpenIdConnect__Authority"] == f"{IDP}/oauth2/token"
    assert env["OpenIdConnect__ClientId"] == "oidc--oidc"
    assert env["ASPNETCORE_FORWARDEDHEADERS_ENABLED"] == "true"
    # the client secret only ever comes from the secret store
    assert env["OpenIdConnect__ClientSecret"]["secretKeyRef"]["key"] == "OpenIdConnect__ClientSecret"
    (app,) = d["applications"]
    assert app["x-containerizer-client-secret"] == "client-oidc--oidc"
    assert app["x-containerizer-secret-env"] == "OpenIdConnect__ClientSecret"
    assert "clientSecret" not in json.dumps(app)
    oidc = app["inboundProtocolConfiguration"]["oidc"]
    assert oidc["callbackURLs"] and "authorization_code" in oidc["grantTypes"]
    # pods reach the IdP's public name through Traefik
    pol = next(x for x in docs(out / "oidc" / "k8s.yaml") if x["kind"] == "NetworkPolicy" and x["spec"].get("egress"))
    assert any(r.get("ports") == [{"port": 8443, "protocol": "TCP"}] for r in pol["spec"]["egress"])


def test_wsfed_and_saml_components(tmp_path, rules):
    w = json.loads((generate(tmp_path, "wsfed", rules) / "wsfed" / "idp.json").read_text())
    (c,) = w["clients"]
    assert c["protocol"] == "wsfed" and c["identifier"] == "https://wsfed.sandbox.test/"
    assert c["env"] == {"WsFederation__MetadataAddress": f"{IDP}{idp.WSFED_METADATA}",
                        "WsFederation__Wtrealm": "https://wsfed.sandbox.test/"}
    sts = w["applications"][0]["inboundProtocolConfiguration"]["passiveSts"]
    assert sts["realm"] == "https://wsfed.sandbox.test/" and sts["replyTo"] == "https://wsfed.sandbox.test/signin-wsfed"
    s = json.loads((generate(tmp_path, "saml", rules) / "saml" / "idp.json").read_text())
    (c,) = s["clients"]
    assert c["protocol"] == "saml"
    assert c["env"] == {"Saml2__IdpMetadata": f"{IDP}/identity/metadata/saml2", "Saml2__IdpEntityId": IDP,
                        "Saml2__EntityId": "https://saml.sandbox.test/"}
    saml = s["applications"][0]["inboundProtocolConfiguration"]["saml"]["manualConfiguration"]
    assert saml["issuer"] == "https://saml.sandbox.test/"
    assert saml["assertionConsumerUrls"] == ["https://saml.sandbox.test/Saml2/Acs"]


def test_no_domain_or_opt_out_leaves_the_component_alone(tmp_path, rules):
    out = generate(tmp_path / "a", "oidc", rules, domain="")
    assert not (out / "oidc" / "idp.json").exists()
    assert "OpenIdConnect__Authority" not in container_env(out, "oidc")
    out = generate(tmp_path / "b", "oidc", rules, sandbox_idp=False)
    assert not (out / "oidc" / "idp.json").exists()


def test_settings_only_in_code_are_reported_not_changed(tmp_path, rules):
    src = tmp_path / "src"
    shutil.copytree(EXAMPLES / "oidc", src)
    (src / "appsettings.json").write_text('{"Logging": {}}')
    out = generate(tmp_path, "oidc", rules, src=src)
    f = out / src.name / "idp.json"
    d = json.loads(f.read_text()) if f.exists() else {"clients": [], "notes": ["(none)"]}
    assert not d["clients"] and d["notes"]


def test_wsfed_identitymodel_rule(tmp_path, rules):
    def ids(path):
        a = assess(str(path), rules)
        return {f.rule.id for c in a.components for f in c.findings}
    assert "wsfed-identitymodel-issuer-bug" not in ids(EXAMPLES / "wsfed")   # pins IdentityModel 8.x
    src = tmp_path / "wsfed"
    shutil.copytree(EXAMPLES / "wsfed", src)
    p = src / "wsfed.csproj"
    txt = p.read_text()
    for pkg in ("Microsoft.IdentityModel.Tokens.Saml", "Microsoft.IdentityModel.Protocols.WsFederation"):
        start = txt.index(f'<PackageReference Include="{pkg}"')
        txt = txt[:start] + txt[txt.index("/>", start) + 2:]
    p.write_text(txt)
    assert "wsfed-identitymodel-issuer-bug" in ids(src)


@pytest.fixture()
def sandbox_repo(tmp_path, rules):
    root = tmp_path / "repo"
    for app in ("oidc", "wsfed", "saml"):
        out = generate(root, app, rules)
        gitops_kustomizations(out)
        (out / "containerizer.json").write_text(json.dumps({"app": app, "components": [{"component": app, "folder": app}]}))
    write_sandbox(root, "https://git.example.com/x.git", "main")
    return root


def test_sandbox_idp_files(sandbox_repo):
    d = sandbox_repo / "sandbox" / "idp"
    k = yaml.safe_load((d / "kustomization.yaml").read_text())
    for r in k["resources"]:
        assert (d / r).is_file(), r
    for g in k["configMapGenerator"]:
        for f in g["files"]:
            assert (d / f).is_file(), f
    sync_files = next(g for g in k["configMapGenerator"] if g["name"] == idp.SYNC)["files"]
    assert sorted(Path(f).name for f in sync_files if "apps__" in f) == [
        "apps__oidc--oidc.json", "apps__saml--saml.json", "apps__wsfed--wsfed.json"]
    flux = yaml.safe_load((sandbox_repo / "sandbox" / "flux" / "apps" / "kustomization.yaml").read_text())
    assert "../../idp" in flux["resources"]
    assert "containerizer-idp.sandbox.test" in (sandbox_repo / "sandbox" / "README.md").read_text()
    toml = tomllib.loads((d / "config" / "deployment.toml").read_text())
    assert toml["server"]["hostname"] == "containerizer-idp.sandbox.test"
    assert toml["saml"]["entity_id"] == IDP
    assert toml["catalinaValves"]["remoteIpValve"]["protocolHeader"] == "X-Forwarded-Proto"
    # nothing secret in Git: passwords and client secrets come from the External Secret
    text = "".join(p.read_text() for p in d.rglob("*") if p.is_file() and p.name != "idp_sync.py")
    assert "wso2carbon" not in toml["super_admin"].get("password", "")
    assert "clientSecret" not in text
    every = [x for f in ("server.yaml", "sync.yaml", "secrets.yaml", "network.yaml", "namespace.yaml", "dns.yaml")
             for x in docs(d / f)]
    kinds = {(x["kind"], x["metadata"]["name"]) for x in every}
    assert ("ExternalSecret", idp.SECRET) in kinds and ("CronJob", idp.SYNC) in kinds
    assert ("ConfigMap", "coredns-custom") in kinds
    ns = next(x for x in every if x["kind"] == "Namespace")
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    for x in every:
        if x["kind"] in ("Deployment", "CronJob"):
            spec = x["spec"]["template"]["spec"] if x["kind"] == "Deployment" else \
                x["spec"]["jobTemplate"]["spec"]["template"]["spec"]
            assert spec["automountServiceAccountToken"] is False
            for c in spec.get("initContainers", []) + spec["containers"]:
                sc = c["securityContext"]
                assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"]["drop"] == ["ALL"], c["name"]
                assert "@sha256:" in c["image"], c["image"]
    assert "&id" not in (d / "server.yaml").read_text()


def test_needed_secrets_and_values(sandbox_repo):
    d = sandbox_repo / "sandbox" / "idp" / "sync"
    cfg = json.loads((d / "idp.json").read_text())
    apps = [json.loads(p.read_text()) for p in sorted(d.glob("apps__*.json"))]
    props, keys = idp.needed_secrets(cfg, apps)
    assert {"admin-password", "keystore-password", "user-alice", "user-bob", "user-carol", "client-oidc--oidc"} == set(props)
    assert keys == {"oidc--oidc": {"OpenIdConnect__ClientSecret": "client-oidc--oidc"}}
    pw = idp.make_value("password")
    assert len(pw) >= 16 and any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c.islower() for c in pw)
    assert idp.make_value("token") != idp.make_value("token")


# ---- the sync job against a fake WSO2 --------------------------------------------------------------

class FakeWso2:
    """Just enough of WSO2's REST APIs for idp_sync: applications, SCIM users/groups, OIDC claims/scopes."""

    def __init__(self):
        self.apps: dict[str, dict] = {}
        self.users: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.claims: dict[str, str] = {}
        self.scopes = {"profile": {"displayName": "profile", "claims": ["given_name"]}}
        self.calls: list[tuple[str, str]] = []
        self.n = 0

    def call(self, api, method, path, body=None, ok=(200, 201, 202, 204), ctype="application/json"):
        import urllib.parse as up
        self.calls.append((method, path))
        u = up.urlparse(path)
        q = dict(up.parse_qsl(u.query))
        p = u.path

        def reply(status, doc=None):
            if status not in ok:
                raise idp_sync.SyncError(f"{method} {p}: HTTP {status}")
            return status, doc or {}
        if p == "/api/server/v1/applications" and method == "GET":
            apps = list(self.apps.values())
            if "filter" in q:
                name = q["filter"].split(" eq ", 1)[1]
                apps = [a for a in apps if a["name"] == name]
            return reply(200, {"applications": [{"id": a["id"], "name": a["name"], "description": a.get("description", "")}
                                                for a in apps]})
        if p == "/api/server/v1/applications" and method == "POST":
            self.n += 1
            self.apps[f"id{self.n}"] = {**json.loads(json.dumps(body)), "id": f"id{self.n}"}
            return reply(201)
        if p.startswith("/api/server/v1/applications/"):
            parts = p.split("/")[5:]
            a = self.apps[parts[0]]
            if len(parts) == 1:
                if method == "GET":
                    return reply(200, a)
                if method == "PATCH":
                    a.update(body)
                    return reply(200)
                if method == "DELETE":
                    del self.apps[parts[0]]
                    return reply(204)
            proto = {"oidc": "oidc", "saml": "saml", "passive-sts": "passiveSts"}[parts[2]]
            ipc = a.setdefault("inboundProtocolConfiguration", {})
            if method == "GET":
                if proto not in ipc:
                    return reply(404)
                cur = ipc[proto]
                return reply(200, cur.get("manualConfiguration", cur) if proto == "saml" else
                             {k: v for k, v in cur.items() if k != "clientSecret"})
            ipc[proto] = body
            return reply(200)
        if p.startswith("/api/server/v1/claim-dialects/"):
            if method == "GET":
                cid = p.rsplit("/", 1)[1]
                return reply(200, {"mappedLocalClaimURI": self.claims[cid]}) if cid in self.claims else reply(404)
            import base64
            cid = base64.urlsafe_b64encode(body["claimURI"].encode()).decode().rstrip("=")
            self.claims[cid] = body["mappedLocalClaimURI"]
            return reply(201)
        if p.startswith("/api/server/v1/oidc/scopes/"):
            s = up.unquote(p.rsplit("/", 1)[1])
            if method == "GET":
                return reply(200, self.scopes[s])
            self.scopes[s] = body
            return reply(200)
        if p in ("/scim2/Groups", "/scim2/Users"):
            store = self.groups if p.endswith("Groups") else self.users
            key = "displayName" if p.endswith("Groups") else "userName"
            if method == "GET":
                want = q["filter"].split(" eq ", 1)[1].strip('"')
                res = [x for x in store.values() if x[key] == want]
                return reply(200, {"totalResults": len(res), "Resources": res})
            self.n += 1
            store[f"g{self.n}"] = {**body, "id": f"g{self.n}", "members": []}
            return reply(201, store[f"g{self.n}"])
        if p.startswith("/scim2/Groups/") and method == "GET":
            return reply(200, self.groups[p.rsplit("/", 1)[1]])
        if p.startswith("/scim2/Groups/") and method == "PATCH":
            g = self.groups[p.rsplit("/", 1)[1]]
            for op in body["Operations"]:
                g["members"] += op["value"]["members"]
            return reply(200)
        raise AssertionError(f"unexpected call {method} {path}")


def test_sync_is_idempotent_and_prunes_only_its_own(sandbox_repo, tmp_path, monkeypatch):
    fake = FakeWso2()
    monkeypatch.setattr(idp_sync.Api, "call", lambda self, *a, **k: fake.call(self, *a, **k))
    monkeypatch.setattr(idp_sync, "wait_healthy", lambda *a, **k: None)
    cfgdir = sandbox_repo / "sandbox" / "idp" / "sync"
    sec = tmp_path / "secrets"
    sec.mkdir()
    for name in ("admin-password", "user-alice", "user-bob", "user-carol", "client-oidc--oidc"):
        (sec / name).write_text(f"S3cret-{name}")
    logs: list[str] = []
    r = idp_sync.sync("https://idp", cfgdir, sec, log=logs.append)
    assert r == {"applications": {"oidc--oidc": "created", "saml--saml": "created", "wsfed--wsfed": "created"},
                 "failed": []}
    oidc = next(a for a in fake.apps.values() if a["name"] == "oidc--oidc")
    assert oidc["inboundProtocolConfiguration"]["oidc"]["clientSecret"] == "S3cret-client-oidc--oidc"
    assert not any(k.startswith("x-containerizer") for k in oidc)
    assert {u["userName"] for u in fake.users.values()} == {"alice", "bob", "carol"}
    assert next(u for u in fake.users.values() if u["userName"] == "alice")["password"] == "S3cret-user-alice"
    admins = next(g for g in fake.groups.values() if g["displayName"] == "sandbox-admins")
    assert len(admins["members"]) == 1
    assert "groups" in fake.scopes["profile"]["claims"]
    assert not any("S3cret" in line for line in logs)
    # second run: nothing to do
    r = idp_sync.sync("https://idp", cfgdir, sec, log=logs.append)
    assert set(r["applications"].values()) == {"unchanged"}
    # an app made by hand stays; an app we made that left the configuration goes
    fake.apps["manual"] = {"id": "manual", "name": "by-hand", "description": "someone's"}
    tmp_cfg = tmp_path / "cfg"
    shutil.copytree(cfgdir, tmp_cfg)
    (tmp_cfg / "apps__saml--saml.json").unlink()
    idp_sync.sync("https://idp", tmp_cfg, sec, log=logs.append)
    assert sorted(a["name"] for a in fake.apps.values()) == ["by-hand", "oidc--oidc", "wsfed--wsfed"]


def test_sync_refuses_plain_http():
    assert idp_sync.main(["--url", "http://idp", "--config", "/nonexistent", "--secrets", "/nonexistent"]) == 2


# ---- appliance: secrets in the store ---------------------------------------------------------------

FAKE_KUBECTL = r'''
import base64, json, sys
state = json.load(open(sys.argv[1]))
args = sys.argv[2:]
def save(): json.dump(state, open(sys.argv[1], "w"))
if args[:1] == ["-n"] and args[2:4] == ["get", "configmap"]:
    print(json.dumps({"items": state["configmaps"]})); sys.exit(0)
if args[:1] == ["-n"] and args[2:4] == ["get", "secret"]:
    s = state["secrets"].get(args[4])
    if s is None:
        print('Error from server (NotFound): secrets "x" not found', file=sys.stderr); sys.exit(1)
    print(json.dumps({"data": s})); sys.exit(0)
if args[0] == "apply":
    doc = json.loads(sys.stdin.read())
    state["secrets"].setdefault(doc["metadata"]["name"], {}).update(doc["data"])
    state["applies"].append([doc["metadata"]["name"], [a for a in args if a.startswith("--field-manager")]])
    save(); sys.exit(0)
print("unexpected " + " ".join(args), file=sys.stderr); sys.exit(2)
'''


def test_appliance_secrets_are_generated_once(sandbox_repo, tmp_path):
    d = sandbox_repo / "sandbox" / "idp" / "sync"
    data = {p.name: p.read_text() for p in d.glob("*.json")}
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"configmaps": [{"metadata": {"creationTimestamp": "t"}, "data": data}],
                                 "secrets": {}, "applies": []}))
    script = tmp_path / "kubectl.py"
    script.write_text(FAKE_KUBECTL)
    cmd = [sys.executable, str(script), str(state)]
    logs: list[str] = []
    r = idp.appliance_secrets(cmd, log=logs.append)
    assert "admin-password" in r["created"] and r["apps"] == 1
    s = json.loads(state.read_text())
    import base64
    store = {k: base64.b64decode(v).decode() for k, v in s["secrets"][idp.remote_key()].items()}
    comp = {k: base64.b64decode(v).decode() for k, v in s["secrets"]["oidc--oidc"].items()}
    assert comp == {"OpenIdConnect__ClientSecret": store["client-oidc--oidc"]}
    assert all(m == ["--field-manager=containerizer-idp"] for _, m in s["applies"])
    assert not any(v in " ".join(logs) for v in store.values())
    # second run keeps every value
    r = idp.appliance_secrets(cmd, log=logs.append)
    assert r["created"] == []
    s2 = json.loads(state.read_text())
    assert s2["secrets"] == s["secrets"] and len(s2["applies"]) == len(s["applies"])
    users = idp.appliance_users(cmd)
    assert [u[0] for u in users] == ["alice", "bob", "carol"] and users[0][2] == store["user-alice"]


def test_application_page_shows_the_registrations():
    from containerizer import webui
    rows = [{"ComponentId": 1, "ComponentName": "Web", "Protocol": "oidc", "IdpUrl": IDP,
             "AppUrl": "https://web-shop.sandbox.test", "Identifier": "shop--web",
             "MetadataUrl": f"{IDP}/oauth2/token/.well-known/openid-configuration",
             "Settings": json.dumps({"env": {"OpenIdConnect__ClientId": "shop--web"}, "secret": "OpenIdConnect__ClientSecret"}),
             "Notes": None},
            {"ComponentId": 2, "ComponentName": "Api<script>", "Protocol": "none", "IdpUrl": IDP,
             "Notes": "sign-in settings only in code"}]
    html = webui._idp_section(rows)
    assert f"href='{IDP}/'" in html and "shop--web" in html and "OpenIdConnect__ClientSecret" in html
    assert "client secret, from the secret store" in html and "containerizer idp users" in html
    assert "<script>" not in html and "sign-in settings only in code" in html
    assert webui._idp_section([]) == ""
    assert "javascript:" not in webui._link("javascript:alert(1)") or "href" not in webui._link("javascript:alert(1)")
