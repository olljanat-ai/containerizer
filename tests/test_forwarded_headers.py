"""Behind the ingress (#276): forwarded headers come from configuration, the code stays as it is."""

import yaml

from containerizer.assess import assess
from containerizer.generate import generate_app, make_plan
from containerizer.rules import load_rules
from tests.test_engine import web_app
from tests.test_java_node import BOOT_APP, EXPRESS, SERVER, WEB, boot_app, comp, dep, ids, node

OIDC = "builder.Services.AddAuthentication().AddOpenIdConnect(o => {});"


def _finding(c, rid):
    return next(f for f in c.findings if f.rule.id == rid)


def test_dotnet_finding_resolved_by_env_var(tmp_path):
    web_app(tmp_path, OIDC)
    a = assess(tmp_path)
    c = a.components[0]
    f = _finding(c, "host-forwarded-headers-missing")
    assert f.resolved_by == "plan-forwarded-headers" and f.severity == "config"
    # config stays config: the rating is the same with and without the technique
    without = [r for r in load_rules() if r.id != "plan-forwarded-headers"]
    assert assess(tmp_path, rules=without).rating == a.rating
    plan = make_plan(a, c)
    assert plan["env"]["ASPNETCORE_FORWARDEDHEADERS_ENABLED"] == "true"
    assert plan["resolved"]["plan-forwarded-headers"] == ["host-forwarded-headers-missing"]

    out = tmp_path / "out"
    generate_app(a, out)
    docs = [d for d in yaml.safe_load_all((out / "web" / "k8s.yaml").read_text()) if d]
    env = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]
    assert {"name": "ASPNETCORE_FORWARDEDHEADERS_ENABLED", "value": "true"} in env


def test_dotnet_app_with_own_forwarded_headers_keeps_its_configuration(tmp_path):
    # UseForwardedHeaders in code (with its own KnownProxies): no finding, so the variable is not set
    web_app(tmp_path, OIDC + " app.UseForwardedHeaders();")
    a = assess(tmp_path)
    c = a.components[0]
    assert "host-forwarded-headers-missing" not in ids(c)
    assert "ASPNETCORE_FORWARDEDHEADERS_ENABLED" not in make_plan(a, c)["env"]
    plain = tmp_path / "plain"
    web_app(plain)
    a = assess(plain)
    assert "ASPNETCORE_FORWARDEDHEADERS_ENABLED" not in make_plan(a, a.components[0])["env"]


def test_spring_oauth2_client_gets_forward_headers_strategy(tmp_path):
    boot_app(tmp_path, WEB + dep("org.springframework.boot", "spring-boot-starter-oauth2-client"))
    a = assess(tmp_path)
    c = comp(a, "orders")
    f = _finding(c, "java-forwarded-headers-missing")
    assert f.resolved_by == "plan-spring-forward-headers" and f.severity == "config"
    plan = make_plan(a, c)
    assert plan["env"]["SERVER_FORWARD_HEADERS_STRATEGY"] == "native"


def test_spring_without_sso_or_with_strategy_configured(tmp_path):
    boot_app(tmp_path)
    a = assess(tmp_path)
    c = comp(a, "orders")
    assert "java-forwarded-headers-missing" not in ids(c)
    assert "SERVER_FORWARD_HEADERS_STRATEGY" not in make_plan(a, c)["env"]

    cfg = tmp_path / "cfg"
    boot_app(cfg, WEB + dep("org.springframework.boot", "spring-boot-starter-oauth2-client"))
    (cfg / "src/main/resources").mkdir(parents=True)
    (cfg / "src/main/resources/application.properties").write_text("server.forward-headers-strategy=framework\n")
    assert "java-forwarded-headers-missing" not in ids(comp(assess(cfg), "orders"))


def test_spring_current_request_links(tmp_path):
    code = BOOT_APP + """
        class L { String u() { return org.springframework.web.servlet.support.ServletUriComponentsBuilder
            .fromCurrentRequestUri().toUriString(); } }
        """
    boot_app(tmp_path, code=code)
    assert "java-forwarded-headers-missing" in ids(comp(assess(tmp_path), "orders"))


def test_express_sso_without_trust_proxy_is_info(tmp_path):
    manifest = {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "openid-client": "^5.0.0"}}
    node(tmp_path, "", manifest, {"server.js": SERVER})
    c = comp(assess(tmp_path), "api")
    assert _finding(c, "node-trust-proxy-missing").severity == "info"

    ok = tmp_path / "ok"
    node(ok, "", manifest, {"server.js": SERVER + "\napp.set('trust proxy', 1);"})
    assert "node-trust-proxy-missing" not in ids(comp(assess(ok), "api"))

    plain = tmp_path / "plain"
    node(plain, "", EXPRESS, {"server.js": SERVER})
    assert "node-trust-proxy-missing" not in ids(comp(assess(plain), "api"))


def test_hardening_report_names_the_trusted_proxy_headers(tmp_path):
    web_app(tmp_path, OIDC)
    out = tmp_path / "out"
    generate_app(assess(tmp_path), out)
    md = (out / "HARDENING.md").read_text()
    assert "## Forwarded headers from the ingress" in md
    assert "| web | `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` |" in md
