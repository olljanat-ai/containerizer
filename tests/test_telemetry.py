"""Make it A+ (telemetry.py, admin_telemetry.py; docs/telemetry.md): what is instrumented, the patches, the state and
A+, the pages, and sandbox/ with and without it."""
import json

import yaml

from containerizer import admin_telemetry as at
from containerizer import org as orgmod
from containerizer import sandboxdebug as d
from containerizer import telemetry as t
from containerizer.gitops import GitOpsOptions

DOTNET = "FROM sdk AS build\nFROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:abc\nENV A=1 \\\n    B=\"c d\"\n"
JAVA = 'FROM gcr.io/distroless/java21-debian12:nonroot\nENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"\n'


def _docs(name="web", env=None):
    labels = {"app.kubernetes.io/name": name}
    c = {"name": name, "image": f"reg/app/{name}:1", **({"env": env} if env else {})}
    return [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "labels": labels},
             "spec": {"template": {"metadata": {"labels": labels}, "spec": {"containers": [c]}}}},
            {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name},
             "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"], "egress": [{"to": []}]}}]


def test_the_runtime_is_read_from_the_image_the_component_runs_on():
    assert t.runtime_of(DOTNET)[:2] == ("dotnet", "10.0")
    assert t.runtime_of(JAVA)[:2] == ("java", "21")
    assert t.runtime_of("FROM eclipse-temurin:8-jre-noble")[:2] == ("java", "8")
    assert t.runtime_of("FROM tomcat:10.1-jre17-temurin-noble")[:2] == ("java", "17")
    assert t.runtime_of("FROM gcr.io/distroless/nodejs22-debian12:nonroot")[:2] == ("node", "22")
    assert t.runtime_of("FROM node:24-bookworm-slim")[:2] == ("node", "24")
    assert t.runtime_of("FROM python:3.12-slim-bookworm")[:2] == ("python", "3.12")
    assert t.runtime_of("FROM gcr.io/distroless/static-debian12:nonroot")[0] is None
    assert t.runtime_of(None)[0] is None
    assert t.image_env(DOTNET) == {"A": "1", "B": "c d"}
    assert t.image_env("FROM a\nENV X=1\nFROM b\nENV OLD value here\n") == {"OLD": "value here"}


def test_the_plan_of_a_component():
    e = {"component": "Shop.Web", "folder": "shop-web"}
    assert t.plan(e, DOTNET)["mode"] == "agent" and t.plan(e, DOTNET)["runtime"] == "dotnet"
    old = t.plan(e, "FROM mcr.microsoft.com/dotnet/aspnet:6.0")
    assert old["mode"] == "none" and old["blocking"] and "8.0 or later" in old["reason"]
    new = t.plan(e, "FROM mcr.microsoft.com/dotnet/aspnet:11.0-noble-chiseled")
    assert new["mode"] == "none" and new["blocking"] and "up to .NET 10.0" in new["reason"]
    assert t.plan(e, "FROM gcr.io/distroless/nodejs20-debian12:nonroot")["mode"] == "none"
    go = t.plan(e, "FROM gcr.io/distroless/static-debian12:nonroot")
    assert go["mode"] == "none" and go["blocking"] and "SDK" in go["reason"]
    spa = t.plan(e, "FROM nginxinc/nginx-unprivileged:1.27-alpine")
    assert spa["mode"] == "none" and not spa["blocking"]                  # no code runs there: it does not keep A+ away
    sdk = t.plan({**e, "otel_sdk": True}, "FROM gcr.io/distroless/static-debian12:nonroot")
    assert sdk["mode"] == "sdk"                                           # its own SDK: any runtime


def test_the_sdk_is_found_in_the_components_packages():
    class P:
        def __init__(self, packages, dev=()):
            self.packages, self.dev_packages = dict.fromkeys(packages, "1"), dict.fromkeys(dev, "1")

    class C:
        def __init__(self, p):
            self.project = p

    class Repo:
        pass
    for names in (["OpenTelemetry.Extensions.Hosting"], ["OpenTelemetry"], ["@opentelemetry/sdk-node"],
                  ["opentelemetry-sdk"], ["io.opentelemetry:opentelemetry-sdk"], ["go.opentelemetry.io/otel/sdk"]):
        assert t.has_sdk(Repo(), C(P(names))), names
    assert not t.has_sdk(Repo(), C(P(["OpenTelemetry.Api", "Serilog", "@opentelemetry/api"])))
    assert not t.has_sdk(Repo(), C(P(["@opentelemetry/sdk-node"], dev=["@opentelemetry/sdk-node"])))


def test_a_workload_gets_the_agent_and_the_way_to_the_collector():
    pl = t.plan({"component": "Shop.Web", "folder": "web"}, DOTNET)
    patches = t.workload_patches(_docs(), "shop", pl, DOTNET)
    assert [p["target"]["kind"] for p in patches] == ["Deployment", "NetworkPolicy"]
    patch = yaml.safe_load(patches[0]["patch"])
    pod = patch["spec"]["template"]["spec"]
    init = pod["initContainers"][0]
    agent = t.settings()["agents"]["dotnet"]
    assert init["image"] == agent["image"] and "@sha256:" in init["image"]
    assert init["command"] == ["cp", "-r", "/autoinstrumentation/.", "/target"]
    sc = init["securityContext"]
    assert sc["runAsNonRoot"] and sc["runAsUser"] and sc["readOnlyRootFilesystem"] and sc["capabilities"] == {"drop": ["ALL"]}
    assert not sc["allowPrivilegeEscalation"] and init["resources"]["limits"]["memory"]
    main = pod["containers"][0]
    env = {e["name"]: e.get("value") for e in main["env"]}
    assert main["name"] == "web" and env["OTEL_SERVICE_NAME"] == "web"
    assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://otel-collector.cz-monitoring.svc.cluster.local:4318"
    assert "service.namespace=shop" in env["OTEL_RESOURCE_ATTRIBUTES"] and "k8s.namespace.name=shop" in env["OTEL_RESOURCE_ATTRIBUTES"]
    assert env["CORECLR_PROFILER_PATH"] == "/otel-auto-instrumentation-dotnet/linux/OpenTelemetry.AutoInstrumentation.Native.so"
    assert env["CORECLR_ENABLE_PROFILING"] == "1" and env["OTEL_DOTNET_AUTO_HOME"] == "/otel-auto-instrumentation-dotnet"
    names = [e["name"] for e in main["env"]]
    assert names.index("OTEL_K8S_POD_NAME") < names.index("OTEL_RESOURCE_ATTRIBUTES")      # $(VAR) needs it first
    assert main["volumeMounts"] == [{"name": t.VOLUME, "mountPath": "/otel-auto-instrumentation-dotnet", "readOnly": True}]
    assert pod["volumes"] == [{"name": t.VOLUME, "emptyDir": {"sizeLimit": "200Mi"}}]
    assert patch["spec"]["template"]["metadata"]["annotations"] == {t.ANNOTATION: "dotnet"}
    op = json.loads(patches[1]["patch"])[0]
    assert op["path"] == "/spec/egress/-" and op["value"] == t.egress_rule()
    assert op["value"]["ports"] == [{"port": 4318, "protocol": "TCP"}]
    assert op["value"]["to"][0]["namespaceSelector"] == {"matchLabels": {"kubernetes.io/metadata.name": "cz-monitoring"}}


def test_option_lists_keep_what_the_image_and_the_manifest_set():
    pl = t.plan({"component": "api", "folder": "api"}, JAVA)
    env = {e["name"]: e.get("value") for e in
           yaml.safe_load(t.workload_patches(_docs("api"), "shop", pl, JAVA)[0]["patch"])["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["JAVA_TOOL_OPTIONS"] == ("-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError "
                                        "-javaagent:/otel-auto-instrumentation-java/javaagent.jar")
    docs = _docs("api", [{"name": "JAVA_TOOL_OPTIONS", "value": "-Xmx1g"}])          # the manifest wins over the image
    env = {e["name"]: e.get("value") for e in
           yaml.safe_load(t.workload_patches(docs, "shop", pl, JAVA)[0]["patch"])["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["JAVA_TOOL_OPTIONS"] == "-Xmx1g -javaagent:/otel-auto-instrumentation-java/javaagent.jar"
    py = "FROM python:3.12-slim-bookworm\nENV PYTHONPATH=/app/src\n"
    env = {e["name"]: e["value"] for e in t.agent_env("python", t.image_env(py))}
    assert env["PYTHONPATH"] == ("/otel-auto-instrumentation-python/opentelemetry/instrumentation/auto_instrumentation:"
                                 "/otel-auto-instrumentation-python:/app/src")
    assert t.agent_env("node", {})[0] == {"name": "NODE_OPTIONS",
                                          "value": "--require /otel-auto-instrumentation-nodejs/autoinstrumentation.js"}
    again = t.agent_env("node", {"NODE_OPTIONS": "--require /otel-auto-instrumentation-nodejs/autoinstrumentation.js"})
    assert again[0]["value"].count("--require") == 1


def test_its_own_sdk_gets_the_address_only_and_a_cronjob_is_patched_in_its_job_template():
    pl = t.plan({"component": "api", "folder": "api", "otel_sdk": True}, DOTNET)
    docs = _docs("api")
    docs[0] = {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "api"},
               "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "api"}]}}}}}}
    patches = t.workload_patches(docs, "shop", pl, DOTNET)
    patch = yaml.safe_load(patches[0]["patch"])
    assert patches[0]["target"] == {"group": "batch", "kind": "CronJob", "name": "api"}
    pod = patch["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert "initContainers" not in pod and "volumes" not in pod
    names = {e["name"] for e in pod["containers"][0]["env"]}
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" in names and "CORECLR_ENABLE_PROFILING" not in names
    assert len(patches) == 2                                                  # and the NetworkPolicy rule
    assert t.workload_patches(_docs(), "shop", t.plan({"folder": "x"}, "FROM gcr.io/distroless/static-debian12"), None) == []


def test_the_collector_can_be_another_one(monkeypatch):
    monkeypatch.setenv(t.ENDPOINT_ENV, "http://collector.observability.svc:4318/")
    assert t.endpoint() == "http://collector.observability.svc:4318"
    assert {e["name"]: e.get("value") for e in t.common_env("ns", "svc", "c")}["OTEL_EXPORTER_OTLP_ENDPOINT"] == \
        "http://collector.observability.svc:4318"


def test_the_state_and_a_plus():
    agent = {"component": "Web", "folder": "web", "mode": "agent", "runtime": "dotnet"}
    go = {"component": "Api", "folder": "api", "mode": "none", "blocking": True, "reason": "Go"}
    spa = {"component": "Ui", "folder": "ui", "mode": "none", "blocking": False, "reason": "static"}
    assert t.applied_status([]) == t.NOT_DEPLOYED and t.applied_status([go]) == t.NOTHING
    assert t.applied_status([agent, go]) == t.PARTIAL and t.applied_status([agent, spa]) == t.WAITING
    st = t.new_state("shop", [agent, spa])
    assert st["status"] == t.WAITING and st["namespace"] == "shop" and not t.is_plus("A", True, st)
    assert not t.is_plus("A", True, {}) and not t.is_plus("A", True, None)
    seen = t.with_seen(st, {"web"}, "2026-11-20T10:00:00Z")
    assert seen["status"] == t.RECEIVING and seen["seen_at"] == "2026-11-20T10:00:00Z" and seen["check"] == "prometheus"
    assert seen["components"][0]["seen_at"] and "seen_at" not in seen["components"][1]
    assert t.is_plus("A", True, seen) and t.is_plus("A", True, json.dumps(seen))
    assert not t.is_plus("B", True, seen) and not t.is_plus("A", False, seen)
    gone = t.with_seen(seen, set(), "2026-11-20T11:00:00Z")
    assert gone["status"] == t.SILENT and gone["seen_at"] == "2026-11-20T10:00:00Z" and not t.is_plus("A", True, gone)
    assert t.with_seen(gone, {"web"})["status"] == t.RECEIVING
    # written again (a scan, the refresh): what was known of the same components stays
    kept = t.new_state("shop", [agent, spa], seen)
    assert kept["status"] == t.RECEIVING and kept["applied_at"] == seen["applied_at"] and kept["components"][0]["seen_at"]
    changed = t.new_state("shop", [agent, go], seen)
    assert changed["status"] == t.PARTIAL and not t.is_plus("A", True, changed)
    # nobody to ask whether it arrives: instrumented is as far as it goes
    assert t.is_plus("A", True, {**st, "check": "none"}) and not t.is_plus("A", True, {**st, "check": "prometheus"})
    assert "1 of 2 components instrumented" in t.summary(seen) and "requested" in t.summary({})


class _Cur:
    def __init__(self, db, as_dict):
        self.db, self.as_dict, self.rows = db, as_dict, []

    def execute(self, sql, params=()):
        self.db["sql"].append((sql, params))
        if sql.startswith("SELECT"):
            self.rows = [dict(r) for r in self.db["rows"]]
        elif sql.startswith("UPDATE cz.Application SET TelemetryState"):
            for r in self.db["rows"]:
                if r["ApplicationId"] == params[1]:
                    r["TelemetryState"] = params[0]

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self, db):
        self.db = db

    def cursor(self, as_dict=False):
        return _Cur(self.db, as_dict)

    def commit(self):
        self.db["commits"] = self.db.get("commits", 0) + 1

    def rollback(self):
        pass

    def close(self):
        pass


def test_the_runner_stores_the_plans_and_asks_prometheus(monkeypatch):
    agent = {"component": "Web", "folder": "web", "mode": "agent", "runtime": "dotnet"}
    db = {"sql": [], "rows": [{"ApplicationId": 1, "SourceKey": "k1", "TelemetryState": None},
                              {"ApplicationId": 2, "SourceKey": "k2", "TelemetryState": None}]}
    monkeypatch.delenv(t.PROMETHEUS_ENV, raising=False)
    assert t.store_plans(_Conn(db), {"k1": ("shop", [agent])}, log=lambda m: None) == 2
    one, two = (json.loads(r["TelemetryState"]) for r in db["rows"])
    assert one["status"] == t.WAITING and one["check"] == "none" and one["namespace"] == "shop"
    assert two["status"] == t.NOT_DEPLOYED                                   # on, but no folder in the sandbox
    assert t.check(lambda: _Conn(db)) == 0                                   # no Prometheus to ask: the states stay
    monkeypatch.setenv(t.PROMETHEUS_ENV, "http://127.0.0.1:9090/")
    assert t.store_plans(_Conn(db), {"k1": ("shop", [agent])}, log=lambda m: None) == 2     # now it can be asked
    asked = []

    class Resp:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout=0):
        asked.append(req.full_url)
        return Resp(json.dumps({"status": "success", "data": {"result": [
            {"metric": {"k8s_namespace_name": "shop", "service_name": "web"}, "value": [0, "3"]},
            {"metric": {"k8s_namespace_name": "other", "service_name": "x"}, "value": [0, "1"]}]}}).encode())
    logs = []
    assert t.check(lambda: _Conn(db), log=logs.append, opener=opener) == 1
    assert asked[0].startswith("http://127.0.0.1:9090/api/v1/query?query=")
    one = json.loads(db["rows"][0]["TelemetryState"])
    assert one["status"] == t.RECEIVING and t.is_plus("A", True, one) and "telemetry arrives" in logs[0]
    writes = len([s for s, _ in db["sql"] if s.startswith("UPDATE")])
    assert t.check(lambda: _Conn(db), opener=opener) == 0                    # nothing new: not written again
    assert len([s for s, _ in db["sql"] if s.startswith("UPDATE")]) == writes

    def away(req, timeout=0):
        raise OSError("connection refused")
    assert t.check(lambda: _Conn(db), opener=away) == 0                      # Prometheus away: what was known stays
    assert json.loads(db["rows"][0]["TelemetryState"])["status"] == t.RECEIVING


def test_switches_carry_telemetry():
    s = d.Switches(telemetry={"k1", 7})
    assert s and not len(s) and not d.debug_of(s)
    assert t.on({"source_key": "k1"}, s) and t.on({"patched": {"application_id": 7}}, s)
    assert not t.on({"source_key": "other"}, s) and not t.on({"source_key": "k1"}, set()) and not t.on({}, None)


def test_load_sandbox_off_reads_telemetry_and_survives_an_older_schema():
    class Cur:
        def __init__(self, old):
            self.old = old

        def execute(self, sql, params=()):
            self.sql = sql
            if self.old and "Telemetry" in sql:
                raise RuntimeError("Invalid column name 'Telemetry'")

        def fetchall(self):
            return [(3, "k3")] if "Telemetry = 1" in self.sql else []

    class Conn:
        def __init__(self, old=False):
            self.old = old

        def cursor(self):
            return Cur(self.old)

        def rollback(self):
            pass
    assert orgmod.load_sandbox_off(Conn()).telemetry == {3, "k3"}
    assert orgmod.load_sandbox_off(Conn(old=True)).telemetry == set()


def test_sandbox_instruments_the_application_with_telemetry_on(tmp_path, monkeypatch):
    from tests.test_make_it_a import _a_app, _Out
    from containerizer import imagescan
    monkeypatch.setattr(imagescan, "build_image", lambda src, cdir, tag, timeout=1800: (True, ""))
    src, a = _a_app(tmp_path, "shop-web")
    out = _Out(tmp_path / "out")
    rel = "acme/_/shop"
    o = orgmod.OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", verify=True, gate=False,
                          push_images=False)
    res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error", app="shop-web",
                            source_key="k1")
    orgmod.deploy_app(a, src, rel, o, out, None, "1.2.3", GitOpsOptions(path=rel), res, tmp_path / "work", "shop-web")
    kfile = out.root / rel / "gitops" / "sandbox" / "kustomization.yaml"      # the app's sandbox overlay

    def own():      # what the other clusters deploy: everything but the app's sandbox overlay
        return {p: p.read_bytes() for p in (out.root / rel).rglob("*") if p.is_file() and "sandbox" not in p.parts}
    orgmod.write_sandbox(out.root, out.url, "main", d.Switches())
    assert "otel" not in kfile.read_text()
    before = own()
    reports: dict = {}
    orgmod.write_sandbox(out.root, out.url, "main", d.Switches(telemetry={"k1"}), telemetry_reports=reports)
    ops = [op for p in yaml.safe_load(kfile.read_text())["patches"] for op in yaml.safe_load(p["patch"])]
    added = [op["value"] for op in ops if op["path"] == "/spec/patches/-" and "otel" in str(op["value"]["patch"])]
    assert sorted(p["target"]["kind"] for p in added) == ["Deployment", "NetworkPolicy"]
    workload = yaml.safe_load(next(p for p in added if p["target"]["kind"] == "Deployment")["patch"])
    pod = workload["spec"]["template"]["spec"]
    assert pod["initContainers"][0]["name"] == t.INIT and pod["containers"][0]["volumeMounts"][0]["readOnly"]
    ns, plans = reports["k1"]
    assert ns == "shop-web" and [p["mode"] for p in plans] == ["agent"] and plans[0]["runtime"] == "dotnet"
    assert own() == before                                  # the application's own files are as they were
    orgmod.write_sandbox(out.root, out.url, "main", d.Switches())
    assert "otel" not in kfile.read_text()                  # off again: as before


def test_the_results_page_box():
    app = {"ApplicationId": 5, "Rating": "A", "Telemetry": False, "TelemetryState": None}
    html = at.section(app, {"telemetry_csrf": "<input type='hidden' name='csrf' value='x'>"})
    assert "Make it A+</button>" in html and "action='/admin/telemetry/5'" in html and "name='On' value='1'" in html
    assert "Make it A+</button>" not in at.section(app, {}) and "An administrator" in at.section(app, {})
    assert at.section({**app, "Rating": "B"}, {"telemetry_csrf": "x"}) == ""            # only an application rated A
    assert at.section({"ApplicationId": 5, "Rating": "A"}, {"telemetry_csrf": "x"}) == ""   # before schema 63
    st = t.with_seen(t.new_state("shop", [{"component": "Shop.Web", "folder": "web", "mode": "agent", "runtime": "dotnet",
                                           "reason": ".NET agent"},
                                          {"component": "Ui", "folder": "ui", "mode": "none", "blocking": False,
                                           "reason": "static files"}]), {"web"})
    on = at.section({**app, "Telemetry": True, "TelemetryState": json.dumps(st)},
                    {"telemetry_csrf": "<i>", "grafana": "https://cz.example/grafana/"})
    assert "st-ok'>A+</span>" in on and "Shop.Web" in on and "agent injected" in on and "Turn it off" in on
    assert ("href='https://cz.example/grafana/d/containerizer-telemetry/containerizer-application-telemetry"
            "?var-namespace=shop'") in on
    # the address may name a dashboard (the appliance's CONTAINERIZER_GRAFANA_URL does)
    assert at.grafana_link("https://cz.example/grafana/d/containerizer-scans", "shop").startswith(
        "<a href='https://cz.example/grafana/d/containerizer-telemetry/")
    # the line of every application's page: its pods (each namespace), and its telemetry when that is on
    sandbox = [{"Namespace": "shop"}, {"Namespace": "shop-jobs"}, {"Namespace": "shop"}, {"Namespace": None}]
    links = at.grafana_links({**app, "sandbox": sandbox}, "https://cz.example/grafana/d/containerizer-scans")
    assert ("href='https://cz.example/grafana/d/containerizer-k3s/containerizer-k3s-sandbox-cluster"
            "?var-namespace=shop&amp;var-namespace=shop-jobs'") in links and "containerizer-telemetry" not in links
    both = at.grafana_links({**app, "sandbox": sandbox, "Telemetry": True, "TelemetryState": json.dumps(st)},
                            "https://cz.example/grafana")
    assert "containerizer-k3s" in both and "containerizer-application-telemetry?var-namespace=shop'" in both
    assert at.grafana_links({**app, "sandbox": sandbox}, "") == "" and at.grafana_links({**app, "sandbox": []}, "x") == ""
    assert st["plus_at"] == st["seen_at"]                   # since when it is A+ (the trends page)
    waiting = at.section({**app, "Telemetry": True, "TelemetryState": None}, {})
    assert "Ordered" in waiting and "Turn it off" not in waiting
    assert at.notice_html("on") and at.notice_html("nope") == ""


def test_the_badge_and_the_overview_count():
    from containerizer import webui
    assert ">A+</span>" in webui.badge("A", plus=True) and "plus" in webui.badge("A", True, True)
    assert ">B</span>" in webui.badge("B", plus=True) and ">A</span>" in webui.badge("A")


def test_the_appliance_collects_and_shows_what_the_rules_send_to():
    """The collector the rules name is the one the appliance runs; Prometheus and Grafana on the host read it, Tempo
    and Loki at the fixed cluster addresses of their Services; every image is pinned by digest."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    rootfs = root / "appliance" / "rootfs"
    docs = [x for x in yaml.safe_load_all((rootfs / "var/lib/rancher/k3s/server/manifests/containerizer-telemetry.yaml").read_text()) if x]
    by = {(x["kind"], x["metadata"]["name"]): x for x in docs}
    assert all(x["metadata"]["namespace"] == "cz-monitoring" for x in docs)
    c = t.settings()["collector"]
    dep = by[("Deployment", "otel-collector")]
    assert c["namespace"] == "cz-monitoring" and dep["spec"]["template"]["metadata"]["labels"] == c["pod_labels"]
    svc = by[("Service", "otel-collector")]
    assert c["endpoint"] == f"http://{svc['metadata']['name']}.{c['namespace']}.svc.cluster.local:{c['port']}"
    assert any(p["port"] == c["port"] for p in svc["spec"]["ports"])
    for name in ("otel-collector", "tempo", "loki"):
        pod = by[("Deployment", name)]["spec"]["template"]["spec"]
        ct = pod["containers"][0]
        assert re.fullmatch(r"docker\.io/[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", ct["image"]), ct["image"]
        assert pod["securityContext"]["runAsNonRoot"] and ct["securityContext"]["readOnlyRootFilesystem"]
        assert ct["securityContext"]["capabilities"] == {"drop": ["ALL"]} and ct["resources"]["limits"]["memory"]
    cfg = yaml.safe_load(by[("ConfigMap", "otel-collector")]["data"]["config.yaml"])
    pipes = cfg["service"]["pipelines"]
    assert set(pipes) == {"traces", "metrics", "logs"}
    for p in pipes.values():                                   # everything a pipeline names is configured
        for kind in ("receivers", "processors", "exporters"):
            for name in p[kind]:
                assert name in cfg.get(kind, {}) or name in cfg["connectors"], name
    assert cfg["receivers"]["otlp"]["protocols"]["http"]["endpoint"].endswith(f":{c['port']}")
    yaml.safe_load(by[("ConfigMap", "tempo")]["data"]["tempo.yaml"])
    yaml.safe_load(by[("ConfigMap", "loki")]["data"]["loki.yaml"])
    # the host reads them at fixed cluster addresses
    ips = {n: by[("Service", n)]["spec"]["clusterIP"] for n in ("tempo", "loki", "otel-collector-metrics")}
    assert len(set(ips.values())) == 3 and all(ip.startswith("10.43.0.") for ip in ips.values())
    prom = yaml.safe_load((rootfs / "usr/lib/containerizer/prometheus/prometheus.yml").read_text())
    job = next(j for j in prom["scrape_configs"] if j["job_name"] == "sandbox-telemetry")
    assert job["static_configs"][0]["targets"] == [f"{ips['otel-collector-metrics']}:8889"] and job["honor_labels"]
    assert cfg["exporters"]["prometheus"]["endpoint"].endswith(":8889")
    ds = {x["uid"]: x for x in yaml.safe_load(
        (rootfs / "usr/lib/containerizer/grafana/provisioning/datasources/telemetry.yaml").read_text())["datasources"]}
    assert ds["tempo"]["url"] == f"http://{ips['tempo']}:3200" and ds["loki"]["url"] == f"http://{ips['loki']}:3100"
    assert ds["tempo"]["jsonData"]["tracesToLogsV2"]["datasourceUid"] == "loki"
    assert ds["loki"]["jsonData"]["derivedFields"][0]["datasourceUid"] == "tempo"
    unit = (rootfs / "usr/lib/systemd/system/containerizer-llm-queue.service").read_text()
    assert f"Environment={t.PROMETHEUS_ENV}=http://127.0.0.1:9090" in unit
    # the dashboard: its own uid (the pages link to it), panels that do not overlap, the labels the collector exports
    dash = json.loads((root / "monitoring/grafana/containerizer-telemetry.json").read_text())
    assert f"d/{dash['uid']}/" in at.DASHBOARD and "containerizer" in dash["tags"]
    assert {v["name"] for v in dash["templating"]["list"]} >= {"namespace", "service"}
    # the traces by HTTP status: a choice of TraceQL conditions (both names of the attribute: the agents differ),
    # none with the comma that separates the choices, and "All" that filters nothing
    status = next(v for v in dash["templating"]["list"] if v["name"] == "status")
    choices = dict(c.split(" : ") for c in status["query"].split(","))
    assert choices["All"] == "true" and [o["value"] for o in status["options"]] == list(choices.values())
    assert all("span.http.response.status_code" in v and "span.http.status_code" in v
               for k, v in choices.items() if k != "All")
    traces = next(p for p in dash["panels"] if p.get("datasource", {}).get("type") == "tempo")
    assert "${status:raw}" in traces["targets"][0]["query"]
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids))
    cells = set()
    for p in dash["panels"]:
        g = p["gridPos"]
        mine = {(x, y) for x in range(g["x"], g["x"] + g["w"]) for y in range(g["y"], g["y"] + g["h"])}
        assert not mine & cells and g["x"] + g["w"] <= 24, p["title"]
        cells |= mine
    assert c["namespace_label"] in json.dumps(dash) and c["service_label"] in json.dumps(dash)
    assert c["namespace_label"] in c["seen_query"] and c["service_label"] in c["seen_query"]
    # the agents: pinned by digest, from a registry the appliance's firewall lets k3s reach
    egress = (rootfs / "usr/lib/containerizer/egress-system.json").read_text()
    for a in t.settings()["agents"].values():
        assert re.fullmatch(r"ghcr\.io/[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", a["image"]), a["image"]
    assert '"ghcr.io"' in egress


def test_the_switch_and_the_state_in_sql_server():
    """Schema 63 with the roles' real grants: an administrator turns it on only for an application rated A, the
    writer (the queue runner) stores the state, the reader sees A+ through vApplicationLatest, and the change
    history records the switch (not the state). Needs CONTAINERIZER_TEST_SQL."""
    import os
    import re
    import uuid
    import pytest
    from containerizer import sqlstore, webui
    admin_sql = os.environ.get("CONTAINERIZER_TEST_SQL")
    if not admin_sql:
        pytest.skip("set CONTAINERIZER_TEST_SQL to run against SQL Server")
    name = "cztel_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", admin_sql)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_t_reader", "reader"), ("cz_t_writer", "writer"), ("cz_t_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    cur = conn.cursor()
    for key, rating in (("shop", "A"), ("legacy", "B")):
        cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (%s, %s)", (key, key))
        cur.execute("INSERT cz.ApplicationAssessment (ApplicationId, Rating, Score, Confidence, Summary) "
                    "SELECT ApplicationId, %s, 90, 0.9, N'x' FROM cz.Application WHERE SourceKey = %s", (rating, key))
    conn.commit()
    cur.execute("SELECT SourceKey, ApplicationId FROM cz.Application")
    ids = {r[0]: int(r[1]) for r in cur.fetchall()}
    conn.close()

    def as_(login):
        return sqlstore.connect(re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs), password="Test-Passw0rd!x")
    try:
        adm = as_("cz_t_admin")
        assert at.turn_on(adm, [ids["shop"], ids["legacy"]]) == 1               # only the one rated A
        assert at.turn_on(adm, [ids["shop"]]) == 0                               # already on
        assert {r["ApplicationName"]: bool(r["Telemetry"]) for r in at.candidates(adm)} == {"shop": True}
        adm.close()
        runner = as_("cz_t_writer")
        assert orgmod.load_sandbox_off(runner).telemetry == {ids["shop"], "shop"}
        agent = {"component": "Web", "folder": "web", "mode": "agent", "runtime": "dotnet"}
        assert t.store_plans(runner, {"shop": ("shop", [agent])}, log=lambda m: None) == 1
        cur = runner.cursor()
        cur.execute("SELECT TelemetryState FROM cz.Application WHERE ApplicationId = %s", (ids["shop"],))
        st = t.with_seen(json.loads(cur.fetchone()[0]), {"web"})
        cur.execute("UPDATE cz.Application SET TelemetryState = %s WHERE ApplicationId = %s", (json.dumps(st), ids["shop"]))
        runner.commit()
        with pytest.raises(Exception):                                           # the runner never orders it
            cur.execute("UPDATE cz.Application SET Telemetry = 1 WHERE ApplicationId = %s", (ids["legacy"],))
        runner.rollback()
        runner.close()
        reader = as_("cz_t_reader")
        assert webui.load_plus(reader) == {ids["shop"]}
        app = webui.load_application(reader, ids["shop"])
        assert app["Telemetry"] and t.is_plus(app["Rating"], app["Telemetry"], app["TelemetryState"])
        reader.close()
        adm = as_("cz_t_admin")
        cur = adm.cursor()
        cur.execute("SELECT COUNT(*) FROM cz.AuditLog WHERE TableName = N'Application' AND RowId = %s "
                    "AND NewValues LIKE N'%%\"Telemetry\":true%%'", (ids["shop"],))
        assert cur.fetchone()[0] == 1                                            # the switch once, the state never
        assert at.turn_off(adm, ids["shop"]) == 1
        cur.execute("SELECT Telemetry, TelemetryState FROM cz.Application WHERE ApplicationId = %s", (ids["shop"],))
        assert tuple(cur.fetchone()) == (False, None)
        adm.close()
    finally:
        pass


def test_grafana_links_for_everyone_only_when_grafana_is_open():
    from containerizer import webui
    env = {"CONTAINERIZER_GRAFANA_URL": "https://cz.example/grafana/d/containerizer-scans"}
    assert webui.public_grafana(env) == "" and webui.public_grafana() == ""
    assert webui.public_grafana({**env, "CONTAINERIZER_GRAFANA_PUBLIC": "true"}) == env["CONTAINERIZER_GRAFANA_URL"]
    assert webui.public_grafana({"CONTAINERIZER_GRAFANA_PUBLIC": "true"}) == ""
    assert webui.public_grafana({"CONTAINERIZER_GRAFANA_URL": "javascript:alert(1)", "CONTAINERIZER_GRAFANA_PUBLIC": "1"}) == ""


OWN = """ARG RUNTIME=mcr.microsoft.com/dotnet/aspnet:8.0
FROM ${RUNTIME} AS base
ENV ASPNETCORE_URLS=http://+:8080
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ENV BUILD_ONLY=1
RUN dotnet publish -o /app
FROM base AS final
ENV APP_MODE="prod mode"
COPY --from=build /app .
"""


def test_own_dockerfile_stage_names_and_args_are_followed():
    assert t.final_image(OWN) == "mcr.microsoft.com/dotnet/aspnet:8.0"
    assert t.image_env(OWN) == {"ASPNETCORE_URLS": "http://+:8080", "APP_MODE": "prod mode"}
    assert t.runtime_of(OWN)[:2] == ("dotnet", "8.0")
    assert t.final_image("FROM node:22 AS deps\nFROM deps\n") == "node:22"
    assert t.final_image("FROM ${BASE:-python:3.12-slim}\n") == "python:3.12-slim"
    assert t.final_image("") == ""


def test_alpine_images_get_no_dotnet_or_python_agent():
    rid, _, why = t.runtime_of("FROM python:3.12-alpine\n")
    assert rid is None and "Alpine" in why
    assert t.runtime_of("FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine\n")[0] is None
    assert t.runtime_of("FROM node:22-alpine\n")[0] == "node"


def test_component_moved_from_another_platform_is_instrumented(tmp_path):
    """Its folder has no Dockerfile: build.json says what its own image runs on (replatform.write_component)."""
    import json
    import yaml
    dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"},
           "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "r/shop/web:1"}]}}}}
    for name, build in (("web", {"dockerfile": "web/Dockerfile", "runs_on": t.runs_on(OWN)}),
                        ("sync", {"mirrors": "docker.io/library/node:22-slim"}),
                        ("old", {"dockerfile": "old/Dockerfile"}),
                        ("db", {"mirrors": "postgres:16"})):
        d = tmp_path / name
        d.mkdir()
        (d / "k8s.yaml").write_text(yaml.safe_dump({**dep, "metadata": {"name": name, "namespace": "shop"}}))
        (d / "build.json").write_text(json.dumps(build))
    text, why = t.own_image(tmp_path / "web")
    assert text.startswith("FROM mcr.microsoft.com/dotnet/aspnet:8.0\n") and 'ENV APP_MODE="prod mode"' in text and not why
    doc = {"app": "shop", "components": [{"component": n, "folder": n} for n in ("web", "sync", "old", "db")]}
    ops, plans = t.ops(tmp_path, doc)
    by = {p["component"]: p for p in plans}
    assert (by["web"]["mode"], by["web"]["runtime"]) == ("agent", "dotnet")
    assert (by["sync"]["mode"], by["sync"]["runtime"]) == ("agent", "node")
    assert by["old"]["mode"] == "none" and "known from the next scan" in by["old"]["reason"]
    assert by["db"]["mode"] == "none" and "postgres:16" in by["db"]["reason"]
    assert ops


def test_healthy_in_the_sandbox_counts_as_runs():
    from containerizer import webui
    assert "not run" in webui._verify({"VerifyStatus": None, "ComponentId": 5})
    assert "Runs" in webui._verify({"VerifyStatus": None, "ComponentId": 5}, {5})
    assert "not run" in webui._verify({"VerifyStatus": None, "ComponentId": None}, {5})


def test_migration_notes_what_the_own_dockerfile_runs_on(tmp_path):
    import json
    from types import SimpleNamespace
    from containerizer import replatform
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "Dockerfile").write_text(OWN)
    sv = SimpleNamespace(build={"context": "web", "dockerfile": "web/Dockerfile"})
    out = tmp_path / "out"
    out.mkdir()
    on = replatform._runs_on(tmp_path, sv, out)
    assert on["image"] == "mcr.microsoft.com/dotnet/aspnet:8.0" and on["env"]["APP_MODE"] == "prod mode"
    (out / "build.json").write_text(json.dumps({"runs_on": on}))
    assert replatform._runs_on(None, sv, out) == on                  # a rewrite without the source keeps it
    assert replatform._runs_on(tmp_path, SimpleNamespace(build=None), out) is None
