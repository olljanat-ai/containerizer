"""Gateway API HTTPRoutes per web component (containerizer/gateway.py, issue #278)."""
from pathlib import Path

import yaml

from containerizer.assess import assess
from containerizer.gateway import GATEWAY_ENV, LISTENER_ENV, RESOLVED_BY, host, parse_config
from containerizer.generate import generate_app, k8s_name
from containerizer.gitops import GitOpsOptions
from containerizer.harden import lint_manifests
from tests.test_engine import web_app, write

ROOT = Path(__file__).resolve().parent.parent
ROUTE_CHECKS = {"route-parent", "route-listener", "route-hostname"}

HTTPS_RULE = """
          <rule name="Force HTTPS" stopProcessing="true">
            <match url="(.*)" />
            <conditions><add input="{HTTPS}" pattern="^OFF$" /></conditions>
            <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
          </rule>"""
PREFIX_RULE = """
          <rule name="Old API" stopProcessing="true">
            <match url="^api/v1/(.*)$" />
            <action type="Rewrite" url="api/v2/{R:1}" />
          </rule>"""
AGENT_RULE = """
          <rule name="Mobile">
            <match url="(.*)" />
            <conditions><add input="{HTTP_USER_AGENT}" pattern="iPhone" /></conditions>
            <action type="Redirect" url="/m/{R:1}" />
          </rule>"""


def web_config(rules: str, extra: str = "") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
    <configuration>
      <system.webServer>
        <rewrite><rules>{rules}
        </rules></rewrite>{extra}
      </system.webServer>
    </configuration>"""


def generate(tmp_path, domain="apps.example.com", **kw):
    a = assess(tmp_path / "src-app")
    out = tmp_path / "out"
    generate_app(a, out, gitops=GitOpsOptions(ingress_domain=domain, sandbox_idp=False), **kw)
    comp = k8s_name(a.components[0].name)
    docs = [d for d in yaml.safe_load_all((out / comp / "k8s.yaml").read_text()) if d]
    return a, out, comp, docs


def routes(docs):
    return [d for d in docs if d["kind"] == "HTTPRoute"]


def test_ci_demo_gets_an_httproute_per_web_component(tmp_path):
    a = assess(ROOT / "examples" / "ci-demo")
    out = tmp_path / "out"
    generate_app(a, out, gitops=GitOpsOptions(ingress_domain="apps.example.com"))
    web = [c for c in a.components if c.role in ("web", "spa")]
    assert web
    for c in web:
        docs = [d for d in yaml.safe_load_all((out / k8s_name(c.name) / "k8s.yaml").read_text()) if d]
        [r] = routes(docs)
        assert r["apiVersion"] == "gateway.networking.k8s.io/v1"
        assert r["spec"]["hostnames"] == [f"{k8s_name(c.name)}.ci-demo.apps.example.com"]
        assert r["spec"]["parentRefs"] == [{"group": "gateway.networking.k8s.io", "kind": "Gateway",
                                            "namespace": "gateway-system", "name": "platform-gateway",
                                            "sectionName": "https"}]
        rule = r["spec"]["rules"][-1]
        assert rule["backendRefs"] == [{"name": k8s_name(c.name), "port": 80}]
        hsts = rule["filters"][0]["responseHeaderModifier"]["set"]
        assert {"name": "Strict-Transport-Security", "value": "max-age=31536000"} in hsts
        assert not [v for v in lint_manifests(docs) if v.check in ROUTE_CHECKS or v.severity == "error"]
        # the Gateway's namespace may call the service port
        np = next(d for d in docs if d["kind"] == "NetworkPolicy" and d["spec"]["ingress"])
        sources = [s["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                   for s in np["spec"]["ingress"][0]["from"]]
        assert "gateway-system" in sources
    # the Flux tenant may manage the routes (`admin` does not cover Gateway API)
    tenant = list(yaml.safe_load_all((out / "gitops" / "flux" / "tenant.yaml").read_text()))
    role = next(d for d in tenant if d["kind"] == "Role" and d["metadata"]["name"].endswith("-routes"))
    assert role["rules"][0]["resources"] == ["httproutes"]
    assert "## Gateway API routes" in (out / "MIGRATION.md").read_text()
    assert "## Gateway API routes" in (out / "HARDENING.md").read_text()


def test_no_domain_uses_the_placeholder(tmp_path):
    web_app(tmp_path / "src-app")
    a, out, comp, docs = generate(tmp_path, domain="")
    [r] = routes(docs)
    assert r["spec"]["hostnames"][0].endswith(".example.invalid")
    assert "placeholder domain" in (out / "MIGRATION.md").read_text()
    assert host("example.com", "shop", "shop") == "shop.example.com"


def test_gateway_options(tmp_path, monkeypatch):
    monkeypatch.setenv(GATEWAY_ENV, "edge/public")
    monkeypatch.setenv(LISTENER_ENV, "https-apps")
    web_app(tmp_path / "src-app")
    a, out, comp, docs = generate(tmp_path)
    [r] = routes(docs)
    ref = r["spec"]["parentRefs"][0]
    assert (ref["namespace"], ref["name"], ref["sectionName"]) == ("edge", "public", "https-apps")
    assert not [v for v in lint_manifests(docs) if v.check in ROUTE_CHECKS]
    np = next(d for d in docs if d["kind"] == "NetworkPolicy" and d["spec"]["ingress"])
    assert {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "edge"}}} \
        in np["spec"]["ingress"][0]["from"]


def test_long_requests_get_route_timeouts_and_grace(tmp_path):
    web_app(tmp_path / "src-app")
    write(tmp_path / "src-app", "src/Web/web.config", """
        <configuration><system.web><httpRuntime executionTimeout="600" /></system.web></configuration>""")
    a, out, comp, docs = generate(tmp_path)
    [r] = routes(docs)
    assert r["spec"]["rules"][-1]["timeouts"] == {"request": "600s", "backendRequest": "600s"}
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] == 600


def test_in_memory_session_gets_cookie_session_persistence(tmp_path):
    web_app(tmp_path / "src-app", code="builder.Services.AddSession();")
    a, out, comp, docs = generate(tmp_path)
    [r] = routes(docs)
    sp = r["spec"]["rules"][-1]["sessionPersistence"]
    assert sp["type"] == "Cookie" and sp["sessionName"]
    assert "experimental channel" in (out / "MIGRATION.md").read_text()


def test_web_config_rewrite_translates(tmp_path):
    web_app(tmp_path / "src-app")
    write(tmp_path / "src-app", "src/Web/web.config", web_config(HTTPS_RULE + PREFIX_RULE))
    a, out, comp, docs = generate(tmp_path)
    f = next(f for f in a.components[0].findings if f.rule.id == "web-config-rewrite")
    assert f.resolved_by == RESOLVED_BY
    [r] = routes(docs)
    first = r["spec"]["rules"][0]
    assert first["matches"] == [{"path": {"type": "PathPrefix", "value": "/api/v1"}}]
    assert first["filters"][0] == {"type": "URLRewrite", "urlRewrite": {
        "path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/api/v2"}}}
    assert first["backendRefs"] and len(r["spec"]["rules"]) == 2       # HTTP -> HTTPS: the Gateway's HTTP listener
    md = (out / "MIGRATION.md").read_text()
    assert "Force HTTPS" in md and "Not translated" not in md
    assert not [v for v in lint_manifests(docs) if v.check in ROUTE_CHECKS]


def test_server_variable_rule_is_listed(tmp_path):
    web_app(tmp_path / "src-app")
    write(tmp_path / "src-app", "src/Web/web.config", web_config(HTTPS_RULE + PREFIX_RULE + AGENT_RULE))
    a, out, comp, docs = generate(tmp_path)
    f = next(f for f in a.components[0].findings if f.rule.id == "web-config-rewrite")
    assert not f.resolved_by
    [r] = routes(docs)
    assert len(r["spec"]["rules"]) == 2                     # the prefix rewrite and the app
    md = (out / "MIGRATION.md").read_text()
    assert 'rewrite rule "Mobile"' in md and "{HTTP_USER_AGENT}" in md and "```xml" in md
    assert 'rewrite rule "Old API"' in md


def test_redirects_headers_and_gateway_settings():
    cfg = web_config("""
          <rule name="About">
            <match url="^about$" />
            <action type="Redirect" url="about/" redirectType="Found" />
          </rule>
          <rule name="Canonical" stopProcessing="true">
            <match url="(.*)" />
            <conditions><add input="{HTTP_HOST}" pattern="^old\\.example\\.com$" /></conditions>
            <action type="Redirect" url="https://www.example.com/{R:1}" />
          </rule>
          <rule name="Map"><match url="(.*)" /><action type="Rewrite" url="{Legacy:{R:1}}" /></rule>""", """
        <httpProtocol><customHeaders><remove name="X-Powered-By" /><add name="X-Frame-Options" value="DENY" />
        </customHeaders></httpProtocol>
        <security>
          <ipSecurity allowUnlisted="false"><add ipAddress="10.0.0.0" subnetMask="255.0.0.0" allowed="true" /></ipSecurity>
          <requestFiltering><requestLimits maxAllowedContentLength="104857600" /></requestFiltering>
        </security>""")
    r = parse_config([("Web/web.config", cfg)])
    about = r.rules[0]
    assert about["matches"] == [{"path": {"type": "Exact", "value": "/about"}}]
    assert about["filters"][0]["requestRedirect"] == {
        "path": {"type": "ReplaceFullPath", "replaceFullPath": "/about/"}, "statusCode": 302}
    [(old, f)] = r.host_redirects
    assert old == "old.example.com" and f["requestRedirect"]["hostname"] == "www.example.com"
    assert r.headers_set == {"X-Frame-Options": "DENY"} and r.headers_remove == ["X-Powered-By"]
    assert any("only 10.0.0.0/8 " in s for s in r.gateway_settings)
    assert any("104,857,600 bytes" in s for s in r.gateway_settings)
    assert [u["what"] for u in r.untranslated] == ['rewrite rule "Map"']
    assert not r.complete


def test_route_lint():
    good = {"kind": "HTTPRoute", "metadata": {"name": "web"},
            "spec": {"parentRefs": [{"name": "gw", "sectionName": "https"}], "hostnames": ["web.example.com"]}}
    assert not lint_manifests([good])
    bad = {"kind": "HTTPRoute", "metadata": {"name": "web"},
           "spec": {"parentRefs": [{"name": "gw", "sectionName": "http"}], "hostnames": ["*.example.com"]}}
    assert {v.check for v in lint_manifests([bad])} == {"route-listener", "route-hostname"}
    bare = {"kind": "HTTPRoute", "metadata": {"name": "web"}, "spec": {}}
    assert {v.check for v in lint_manifests([bare])} == {"route-parent", "route-hostname"}
    assert all(v.severity == "error" for v in lint_manifests([bad, bare]))


def test_sandbox_drops_the_routes(tmp_path):
    from containerizer.org import sandbox_wait_patch
    import json
    (tmp_path / "web").mkdir()
    (tmp_path / "kustomization.yaml").write_text("resources: [web/k8s.yaml]\n")
    (tmp_path / "web" / "k8s.yaml").write_text(yaml.safe_dump(
        {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": {"name": "web"}}))
    ops = json.loads(sandbox_wait_patch(tmp_path, {"app": "shop"})["patch"])
    drop = next(o for o in ops if o["path"] == "/spec/patches/-")["value"]
    assert drop["target"] == {"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}
    assert drop["patch"].startswith("$patch: delete")
