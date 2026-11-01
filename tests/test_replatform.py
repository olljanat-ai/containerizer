"""Platform migrations of already containerized apps (platforms.py, replatform.py) and LLM usage stats."""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from containerizer import ai, platforms, replatform
from containerizer.harden import external_secret_targets, lint_manifests, load_yaml_docs

EX = Path(__file__).resolve().parent.parent / "examples" / "replatform"


def _svc(descs, name):
    return next(s for d in descs for s in d.services if s.name == name)


# --------------------------------------------------------------------------- readers

def test_swarm_stack_is_read():
    descs = platforms.find_descriptors(EX / "swarm-shop")
    assert [(d.path, d.platform) for d in descs] == [("docker-stack.yml", "docker-swarm")]
    api = _svc(descs, "api")
    assert api.build == {"context": "api", "dockerfile": "api/Dockerfile"}
    assert api.ports == [8080] and api.public and api.replicas == 3
    assert api.cpu == "500m" and api.memory == "512Mi"
    assert api.health == {"type": "http", "path": "/healthz", "port": 8080}
    assert set(api.secrets) == {"ConnectionStrings__Shop", "OpenIdConnect__ClientSecret"}
    assert "ConnectionStrings__Shop" not in api.env and api.env["LOG_LEVEL"] == "info"     # ${LOG_LEVEL:-info}
    assert api.secret_files == [{"name": "shop_cert", "path": "/run/secrets/cert.pfx"}]
    assert api.volumes == [{"path": "/app/uploads", "persistent": True, "size": "1Gi"}]
    assert any("placement constraints" in n for n in api.notes)
    worker = _svc(descs, "worker")
    assert worker.args == ["dotnet", "Worker.dll", "--queue", "orders"] and worker.secrets == ["RABBIT_URL"]
    assert _svc(descs, "db").backing


def test_compose_ports_env_files_and_bind_mounts(tmp_path):
    (tmp_path / "web.env").write_text("# settings\nAPI_URL=https://api.example.com\nexport API_TOKEN='abc'\n")
    (tmp_path / "docker-compose.yml").write_text(yaml.safe_dump({"services": {
        "web": {"build": ".", "ports": ["127.0.0.1:8081:3000/tcp", {"target": 9090}], "env_file": ["web.env", "missing.env"],
                "volumes": ["./conf:/etc/web", "/var/run/docker.sock:/var/run/docker.sock", "cache:/cache"],
                "healthcheck": {"test": "wget -qO- http://localhost:3000/ping || exit 1"}, "privileged": True,
                "labels": ["traefik.enable=true"]}},
        "volumes": {"cache": {}}}))
    (tmp_path / "Dockerfile").write_text("FROM node:22\n")
    [d] = platforms.find_descriptors(tmp_path)
    assert d.platform == "docker-compose"
    [web] = d.services
    assert web.ports == [3000, 9090] and web.public
    assert web.env == {"API_URL": "https://api.example.com"} and web.secrets == ["API_TOKEN"]
    assert web.build == {"context": ".", "dockerfile": "Dockerfile"}
    assert web.health == {"type": "http", "path": "/ping", "port": 3000}
    assert {"path": "/cache", "persistent": True, "size": "1Gi"} in web.volumes
    notes = " ".join(web.notes)
    assert "missing.env" in notes and "Docker socket" in notes and "bind mount ./conf" in notes and "privileged" in notes


def test_nomad_hcl_job_is_read():
    descs = platforms.find_descriptors(EX / "nomad-web")
    web, cleanup = _svc(descs, "web"), _svc(descs, "cleanup")
    assert web.platform == "nomad" and web.image == "ghcr.io/acme/web:2.0"
    assert web.ports == [3000] and web.public and web.replicas == 2
    assert web.health == {"type": "http", "path": "/api/health", "port": 3000}
    assert web.env["NODE_ENV"] == "production" and web.env["API_BASE"] == "https://api.example.com"
    assert web.secrets == ["DATABASE_URL"]                 # from the Vault template
    assert web.cpu == "500m" and web.memory == "256Mi"
    assert cleanup.schedule == "*/15 * * * *" and cleanup.args == ["--days", "7"]


def test_hcl_parser_handles_comments_heredocs_lists_and_maps():
    doc = platforms.parse_hcl('''
    /* block comment */
    job "x" {
      meta { owner = "team-a" }   // trailing comment
      list = [1, 2.5, "three", true]
      group "g" {
        task "t" {
          config = { image = "img:1", args = ["-v"] }
          template {
            data = <<-EOT
              A=1
              B=${env.X}
            EOT
          }
        }
      }
    }''')
    j = doc["job"][0]
    assert j["_labels"] == ["x"] and j["meta"][0]["owner"] == "team-a" and j["list"] == [1, 2.5, "three", True]
    t = j["group"][0]["task"][0]
    assert t["config"] == {"image": "img:1", "args": ["-v"]}
    assert t["template"][0]["data"] == "A=1\nB=${env.X}\n"


def test_nomad_json_job(tmp_path):
    (tmp_path / "api.json").write_text(json.dumps({"Job": {"Name": "api", "Type": "service", "TaskGroups": [{
        "Name": "api", "Count": 3, "Networks": [{"DynamicPorts": [{"Label": "http", "To": 8080}]}],
        "Services": [{"PortLabel": "http", "Checks": [{"Type": "http", "Path": "/health", "PortLabel": "http"}]}],
        "Tasks": [{"Name": "api", "Driver": "docker", "Config": {"image": "api:1", "ports": ["http"]},
                   "Env": {"MODE": "prod"}, "Resources": {"CPU": 250, "MemoryMB": 128}}]}]}}))
    [d] = platforms.find_descriptors(tmp_path)
    [api] = d.services
    assert (api.name, api.image, api.ports, api.replicas, api.memory) == ("api", "api:1", [8080], 3, "128Mi")
    assert api.health == {"type": "http", "path": "/health", "port": 8080}


def test_azure_container_apps_yaml_and_bicep():
    descs = platforms.find_descriptors(EX / "aca-billing")
    orders = _svc(descs, "orders")
    assert orders.platform == "azure-container-apps" and orders.ports == [5000] and orders.public
    assert orders.secrets == ["DB"] and orders.env == {"FEATURE_X": "on"} and orders.replicas == 2
    assert orders.health == {"type": "http", "path": "/ready", "port": 5000}
    assert any("KEDA" in n for n in orders.notes)
    billing, nightly = _svc(descs, "billing"), _svc(descs, "billing-nightly")
    assert billing.image == "myacr.azurecr.io/billing:1.0" and billing.ports == [8080] and not billing.public
    assert billing.secrets == ["API_KEY"] and billing.cpu == "250m" and billing.memory == "512Mi"
    assert nightly.schedule == "0 3 * * *" and nightly.args == ["--nightly"]


def test_arm_template_and_ecs_task_definition(tmp_path):
    (tmp_path / "azuredeploy.json").write_text(json.dumps({"resources": [{
        "type": "Microsoft.App/containerApps", "name": "[parameters('appName')]",
        "properties": {"configuration": {"ingress": {"external": True, "targetPort": 80}},
                       "template": {"containers": [{"name": "c", "image": "nginx:1", "env": [{"name": "A", "value": "1"}]}]}}}]}))
    (tmp_path / "task-def.json").write_text(json.dumps({"family": "jobs", "containerDefinitions": [{
        "name": "jobs", "image": "123.dkr.ecr.eu-west-1.amazonaws.com/jobs:7", "cpu": 512, "memory": 1024,
        "portMappings": [{"containerPort": 7000}], "environment": [{"name": "MODE", "value": "x"}],
        "secrets": [{"name": "DB_PASSWORD", "valueFrom": "arn:aws:ssm:..."}],
        "healthCheck": {"command": ["CMD-SHELL", "curl -f http://localhost:7000/health || exit 1"]}}]}))
    descs = platforms.find_descriptors(tmp_path)
    app = _svc(descs, "appName")
    assert app.ports == [80] and app.env == {"A": "1"} and app.public
    jobs = _svc(descs, "jobs")
    assert jobs.platform == "aws-ecs" and jobs.cpu == "500m" and jobs.memory == "1024Mi"
    assert jobs.secrets == ["DB_PASSWORD"] and jobs.health == {"type": "http", "path": "/health", "port": 7000}


def test_other_platforms_are_recognised_but_need_llm_heavy(tmp_path):
    (tmp_path / "fly.toml").write_text('app = "shop"\n[http_service]\ninternal_port = 8080\n')
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    [d] = platforms.find_descriptors(tmp_path)
    assert (d.platform, d.parsed, d.services) == ("fly", False, [])
    plan = replatform.plan_migration(tmp_path, "shop", ["Dockerfile"])
    assert not plan.services and "LLM-heavy" in plan.notes[0]


def test_secret_classification():
    plain, secret = platforms.classify_env({"DB_PASSWORD": "x", "API_KEY": "k", "URL": "postgres://u:p@db/x",
                                            "CONN": "Server=s;Password=p", "MODE": "prod", "ConnectionStrings__Db": "x"})
    assert plain == {"MODE": "prod"}
    assert secret == ["API_KEY", "CONN", "ConnectionStrings__Db", "DB_PASSWORD", "URL"]


# --------------------------------------------------------------------------- generation

def test_replatform_cli_generates_hardened_gitops_output(tmp_path):
    from containerizer.cli import main
    out = tmp_path / "out"
    assert main(["replatform", str(EX / "swarm-shop"), "--out", str(out), "--name", "shop",
                 "--ingress-domain", "sandbox.example.com", "--registry", "reg.example/sb", "--tag", "1.0.0"]) == 0
    for f in ("kustomization.yaml", "namespace.yaml", "security.yaml", "HARDENING.md", "MIGRATION.md", "migration.json",
              "gitops/argocd/application.yaml", "gitops/flux/tenant.yaml", "cluster/secret-store.yaml",
              "api/k8s.yaml", "api/build.json", "api/idp.json", "worker/k8s.yaml"):
        assert (out / f).exists(), f
    assert not (out / "db").exists()                        # backing service: not migrated
    docs = {f.parent.name: load_yaml_docs(f.read_text()) for f in out.glob("*/k8s.yaml")}
    provided = external_secret_targets([d for v in docs.values() for d in v])
    for name, d in docs.items():
        assert not [v for v in lint_manifests(d, name, provided) if v.severity == "error"], name
    api = docs["api"]
    dep = next(d for d in api if d["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert c["image"] == "reg.example/sb/shop/api:1.0.0"
    assert c["securityContext"]["readOnlyRootFilesystem"] and pod["securityContext"]["runAsNonRoot"]
    assert c["readinessProbe"]["httpGet"] == {"path": "/healthz", "port": 8080}
    assert dep["spec"]["replicas"] == 1 and dep["spec"]["strategy"] == {"type": "Recreate"}   # RWO volume
    env = {e["name"]: e for e in c["env"]}
    assert env["ConnectionStrings__Shop"]["valueFrom"]["secretKeyRef"]["name"] == "api-secrets"
    # sign-in settings in the environment: pointed at the sandbox IdP and registered there
    assert env["OpenIdConnect__ClientId"]["value"] == "shop--api"
    assert "containerizer-idp.sandbox.example.com" in env["OpenIdConnect__Authority"]["value"]
    assert {d["kind"] for d in api} >= {"ServiceAccount", "Service", "NetworkPolicy", "ExternalSecret",
                                        "PersistentVolumeClaim", "Ingress"}
    assert not any(d["kind"] == "Secret" for d in api)
    np = next(d for d in api if d["kind"] == "NetworkPolicy")
    ports = {p["port"] for r in np["spec"]["egress"] for p in r.get("ports") or []}
    assert 443 in ports and 1433 in ports and 8080 not in ports       # the listen URL is not egress
    worker = docs["worker"]
    assert not any(d["kind"] in ("Service", "Ingress") for d in worker)  # no ports
    assert next(d for d in worker if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["image"] \
        == "registry.example.com/shop/worker:1.4.2"                   # not built here: the image it runs today
    kust = yaml.safe_load((out / "kustomization.yaml").read_text())
    assert kust["namespace"] == "shop" and "api/k8s.yaml" in kust["resources"]
    md = (out / "MIGRATION.md").read_text()
    assert "Docker Swarm" in md and "backing service" in md and "shop--api" in md


def test_nomad_and_aca_cron_jobs(tmp_path):
    from containerizer.cli import main
    assert main(["replatform", str(EX / "aca-billing"), "--out", str(tmp_path / "aca")]) == 0
    nightly = load_yaml_docs((tmp_path / "aca" / "billing-nightly" / "k8s.yaml").read_text())
    cj = next(d for d in nightly if d["kind"] == "CronJob")
    assert cj["spec"]["schedule"] == "0 3 * * *"
    pod = cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert pod["restartPolicy"] == "OnFailure" and pod["containers"][0]["args"] == ["--nightly"]
    orders = load_yaml_docs((tmp_path / "aca" / "orders" / "k8s.yaml").read_text())
    assert not any(d["kind"] == "Ingress" for d in orders)            # no --ingress-domain


def test_cli_without_descriptor_says_so(tmp_path, capsys):
    from containerizer.cli import main
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Dockerfile").write_text("FROM scratch\n")
    assert main(["replatform", str(tmp_path / "app"), "--out", str(tmp_path / "out")]) == 1
    assert "no Docker Swarm" in capsys.readouterr().err


def test_rule_fix_makes_named_folders_writable():
    run = {"status": "hardening-failure", "log": "Error: EROFS: read-only file system, open '/app/logs/app.log'\n"
           "nginx: [emerg] mkdir() \"/var/cache/nginx/client_temp\" failed (13: Permission denied)",
           "errors": []}
    assert replatform.rule_fix_run(run) == {"writable": ["/app/logs", "/var/cache/nginx/client_temp"]}
    sv = platforms.Service(name="x", platform="nomad", source="x.nomad", image="x", ports=[80])
    assert replatform.apply_patch(sv, {"writable": ["/app/logs", "/"], "env": {"A": "1", "DB_PASSWORD": "no"},
                                       "secrets": ["TOKEN"], "port": 8080, "memory": "1Gi", "health_path": "/up"}) \
        == ["set A", "TOKEN from the secret store", "writable /app/logs", "health check /up", "port 8080", "memory 1Gi"]
    assert sv.ports == [8080, 80] and "DB_PASSWORD" not in sv.env and sv.health["port"] == 8080


# --------------------------------------------------------------------------- LLM-heavy mode and usage stats

@pytest.fixture
def fake_llm(monkeypatch, tmp_path):
    """ask_json without a backend: answers from `answers` by schema, records usage like the real one."""
    calls = []
    monkeypatch.setattr(ai, "CACHE", tmp_path / "ai-cache")
    monkeypatch.setattr(ai, "_backend", lambda: "api")

    def fake_api(prompt, schema, model, effort, system=ai.SYSTEM):
        calls.append({"prompt": prompt, "schema": schema, "system": system})
        if schema is replatform.TRANSLATE_SCHEMA:
            return {"services_json": json.dumps([{"name": "shop", "image": "", "build_context": ".", "dockerfile": "Dockerfile",
                                                  "env": {"PORT": "8080", "SECRET_KEY": "x"}, "ports": [8080],
                                                  "public": True, "health_path": "/healthz", "replicas": 2,
                                                  "volumes": [{"path": "/data", "persistent": True}],
                                                  "notes": ["fly regions are not carried over"]}]),
                    "notes": ["one app"]}, {"input_tokens": 1000, "output_tokens": 200}
        if schema is replatform.PATCH_SCHEMA:
            return {"diagnosis": "it writes its cache under /app/cache",
                    "patches_json": json.dumps({"shop": {"writable": ["/app/cache"], "env": {"LOG_FORMAT": "json"}},
                                                "nobody": {"env": {"X": "1"}}})}, {"input_tokens": 500, "output_tokens": 50}
        raise AssertionError(schema)
    monkeypatch.setattr(ai, "_ask_api", fake_api)
    return calls


def test_llm_heavy_translates_reviews_and_counts_usage(tmp_path, fake_llm):
    (tmp_path / "fly.toml").write_text('app = "shop"\n[http_service]\ninternal_port = 8080\n')
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    seen = []
    ai.LISTENERS.append(seen.append)
    try:
        with ai.usage_scope(repo="acme/shop"):
            plan = replatform.plan_migration(tmp_path, "shop", ["Dockerfile"], llm=True, model="claude-sonnet-5-5")
    finally:
        ai.LISTENERS.remove(seen.append)
    [sv] = plan.services
    assert sv.platform == "fly" and sv.build == {"context": ".", "dockerfile": "Dockerfile"}
    assert sv.secrets == ["SECRET_KEY"] and sv.env["LOG_FORMAT"] == "json"
    assert {"path": "/app/cache", "persistent": False} in sv.volumes and sv.health["path"] == "/healthz"
    assert all(c["system"] == replatform.SYSTEM for c in fake_llm)
    assert [(u["feature"], u["repo"]) for u in seen] == [("platform-migration", "acme/shop")] * 2
    s = ai.usage_summary(seen)["platform-migration"]
    assert (s["calls"], s["input_tokens"], s["output_tokens"]) == (2, 1500, 250)
    assert s["cost_usd"] == pytest.approx((1500 * 2.0 + 250 * 10.0) / 1e6)


def test_usage_records_failures_cache_and_self_hosted_prices(tmp_path, monkeypatch):
    monkeypatch.setattr(ai, "CACHE", tmp_path / "c")
    monkeypatch.setattr(ai, "_backend", lambda: "openai")
    monkeypatch.setattr(ai, "_llm_base_url", lambda: "http://localhost:11434/v1")
    seen = []
    ai.LISTENERS.append(seen.append)
    try:
        monkeypatch.setattr(ai, "_ask_openai", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
        with pytest.raises(RuntimeError):
            ai.ask_json("p", {"type": "object"}, model="qwen3", feature="sandbox-tester")
        monkeypatch.setattr(ai, "_ask_openai", lambda *a, **k: ({"ok": True}, {"input_tokens": 10, "output_tokens": 5}))
        with ai.configured({"CONTAINERIZER_LLM_PRICE_INPUT": "1", "CONTAINERIZER_LLM_PRICE_OUTPUT": "2"}):
            ai.ask_json("p", {"type": "object"}, model="qwen3", feature="assessment")
        ai.ask_json("p", {"type": "object"}, model="qwen3", feature="assessment")        # cached now
    finally:
        ai.LISTENERS.remove(seen.append)
    assert [bool(u.get("error")) for u in seen] == [True, False, False] and seen[2]["cached"]
    assert seen[1]["cost_usd"] == pytest.approx(20e-6) and seen[1]["cost_known"]
    s = ai.usage_summary(seen)
    assert s["sandbox-tester"]["errors"] == 1 and s["assessment"] == {
        "calls": 2, "cached": 1, "errors": 0, "input_tokens": 10, "output_tokens": 5, "cost_usd": 0.00002}


def test_llm_heavy_is_off_unless_appliance_and_scan_say_so():
    from containerizer.worker import llm_heavy
    assert not ai.heavy_allowed({})
    assert ai.heavy_allowed({"CONTAINERIZER_LLM_HEAVY": "true"})
    on = {"CONTAINERIZER_LLM_HEAVY": "1"}
    assert llm_heavy({"LlmHeavy": True, "UseAi": True}, on)
    assert not llm_heavy({"LlmHeavy": True, "UseAi": False}, on)
    assert not llm_heavy({"LlmHeavy": False, "UseAi": True}, on)
    assert not llm_heavy({"LlmHeavy": True, "UseAi": True}, {})


def test_worker_exports_llm_metrics():
    from containerizer import worker
    m = worker.ScanMetrics({"data": "/"}, "w1")
    m.scan_name = "acme"
    try:
        m.llm({"feature": "platform-migration", "repo": "team/api", "model": "claude-opus-5-5", "backend": "api",
               "input_tokens": 1200, "output_tokens": 300, "cost_usd": 0.0108, "seconds": 4.5})
        m.llm({"feature": "platform-migration", "repo": "team/api", "model": "claude-opus-5-5", "backend": "api",
               "cached": True, "input_tokens": 1200})
        m.llm({"feature": "sandbox-tester", "repo": "team/api", "model": "claude-opus-5-5", "backend": "api", "error": True})
    finally:
        ai.LISTENERS.remove(m.llm)
    text = m.registry.render()
    lab = 'scan="acme",repository="team/api",feature="platform-migration",model="claude-opus-5-5"'
    assert f"containerizer_llm_input_tokens_total{{{lab}}} 1200" in text
    assert f"containerizer_llm_output_tokens_total{{{lab}}} 300" in text
    assert f"containerizer_llm_cost_usd_total{{{lab}}} 0.0108" in text
    assert 'result="cached"} 1' in text and 'feature="sandbox-tester",backend="api",model="claude-opus-5-5",result="failed"} 1' in text
    assert "containerizer_llm_heavy_allowed 0" in text


def test_grafana_dashboard_shows_llm_usage():
    d = json.loads((Path(__file__).resolve().parent.parent / "monitoring" / "grafana" / "containerizer-scans.json").read_text())
    titles = {p.get("title") for p in d["panels"]}
    assert "LLM usage" in titles
    exprs = " ".join(t.get("expr", "") for p in d["panels"] for t in p.get("targets") or [])
    for metric in ("containerizer_llm_calls_total", "containerizer_llm_input_tokens_total",
                   "containerizer_llm_output_tokens_total", "containerizer_llm_cost_usd_total"):
        assert metric in exprs
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids))
    for p in d["panels"]:
        refs = [t.get("refId") for t in p.get("targets") or []]
        assert len(refs) == len(set(refs)), p["title"]
        if p["type"] == "timeseries":
            assert not any(t.get("instant") for t in p.get("targets") or []), p["title"]


def test_grafana_dashboard_shows_the_llm_queue():
    root = Path(__file__).resolve().parent.parent
    d = json.loads((root / "monitoring" / "grafana" / "containerizer-scans.json").read_text())
    titles = {p.get("title") for p in d["panels"]}
    assert {"LLM queue", "Jobs waiting", "Oldest waiting", "Waiting jobs by kind", "Jobs finished by result"} <= titles
    exprs = " ".join(t.get("expr", "") for p in d["panels"] for t in p.get("targets") or [])
    for metric in ("containerizer_llm_queue_jobs{", "containerizer_llm_queue_oldest_waiting_seconds",
                   "containerizer_llm_queue_jobs_finished_total", "containerizer_llm_queue_estimated_tokens"):
        assert metric in exprs
    cells = set()                           # panels do not overlap
    for p in d["panels"]:
        g = p["gridPos"]
        for x in range(g["x"], g["x"] + g["w"]):
            for y in range(g["y"], g["y"] + g["h"]):
                assert (x, y) not in cells, p["title"]
                cells.add((x, y))
    scrape = (root / "monitoring" / "prometheus" / "scrape.yml").read_text()
    assert "job_name: containerizer-llm-queue" in scrape and ":9465" in scrape


def test_sandbox_tester_llm_fix_is_applied_and_kept(tmp_path, monkeypatch):
    from containerizer.cli import main
    out = tmp_path / "repo" / "acme" / "_" / "shop"
    assert main(["replatform", str(EX / "swarm-shop"), "--out", str(out), "--name", "shop"]) == 0
    (out / "containerizer.json").write_text(json.dumps({"app": "shop", "components": [
        {"component": "api", "folder": "api", "image": "registry.local/shop/api:latest"}]}))
    doc = {"components": [{"app": "shop", "folder": "acme/_/shop", "component": "api", "status": "failing",
                           "llm": {"outcome": "fixable", "diagnosis": "writes to /app/logs",
                                   "patch": {"writable": ["/app/logs"], "env": {"LOG_DIR": "/app/logs"}}}}]}
    changed = replatform.apply_sandbox_fixes(tmp_path / "repo", doc, log=lambda *a: None)
    assert changed == ["acme/_/shop"]
    k8s = (out / "api" / "k8s.yaml").read_text()
    assert "/app/logs" in k8s and "LOG_DIR" in k8s
    assert replatform.load_fixes(out) == {"api": {"writable": ["/app/logs"], "env": {"LOG_DIR": "/app/logs"}}}


# --------------------------------------------------------------------------- organization scans

def _commit(d: Path):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x"], cwd=d, check=True)


def test_enabled_dockerfile_repo_is_migrated_in_an_org_scan(tmp_path, monkeypatch):
    from containerizer import org as orgmod
    from containerizer.org import OrgOptions, run_org
    from containerizer.orgsource import NO_PROJECT, SourceRepo
    from tests.test_org import _FakeProvider, _State
    sources = {"shop": tmp_path / "src" / "shop", "plain": tmp_path / "src" / "plain"}
    shutil.copytree(EX / "swarm-shop", sources["shop"])
    sources["plain"].mkdir(parents=True)
    (sources["plain"] / "Dockerfile").write_text("FROM scratch\n")
    for d in sources.values():
        _commit(d)
    repos = [SourceRepo("github", "acme", NO_PROJECT, n, f"https://github.com/acme/{n}", default_branch="main")
             for n in sources]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    monkeypatch.setattr(orgmod, "clone", lambda url, dest, branch="", header="", depth=1:
                        shutil.copytree(sources[url.rsplit("/", 1)[1]], dest))
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=out, check=True)
    state = _State({"_/shop": "enabled"})
    o = OrgOptions(provider="github", org="acme", registry="reg.example/sb", output_dir=str(out), token="t",
                   verify=False, gate=False, push_images=False, tag="1.0.0", work_dir=str(tmp_path / "work"),
                   state=state, now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    res = {r.repo: r for r in run_org(o, log=lambda *a, **k: None)}
    shop = res["shop"]
    assert shop.status == "deployed", shop
    assert shop.overridden[0]["status"] == "skipped-dockerfile"
    assert shop.migration["platforms"] == ["docker-swarm"] and not shop.migration["llm_heavy"]
    assert {c["component"] for c in shop.components} == {"api", "worker"}
    assert any(x["component"] == "db" for x in shop.excluded)
    assert res["plain"].status == "skipped-dockerfile"        # not enabled: skipped as before
    app = out / "acme" / "_" / "shop"
    meta = json.loads((app / "containerizer.json").read_text())
    assert meta["migration"]["platforms"] == ["docker-swarm"] and meta["app"] == "shop"
    assert (app / "gitops" / "argocd" / "kustomization.yaml").exists()
    # the sandbox app-of-apps includes it, and the sandbox tester finds its workloads
    from containerizer.sandbox import deployed_apps
    [a] = [x for x in deployed_apps(out) if x["app"] == "shop"]
    assert {c["component"]: c["workloads"] for c in a["components"]} == {"api": [("Deployment", "api")],
                                                                         "worker": [("Deployment", "worker")]}
    assert "acme/_/shop/gitops/argocd" in (out / "sandbox" / "argocd" / "apps" / "kustomization.yaml").read_text()


@pytest.mark.skipif(not __import__("os").environ.get("CONTAINERIZER_TEST_DOCKER"),
                    reason="set CONTAINERIZER_TEST_DOCKER=1 to build and run the migrated image in docker")
def test_gate_builds_runs_hardened_and_fixes_writable_folders(tmp_path, monkeypatch):
    """The repository's own Dockerfile is built and run with the hardened security context; a folder the
    container writes to is made writable by the rule fix and the run passes on the next round."""
    from containerizer import imagescan
    from containerizer.gitops import GitOpsOptions
    from containerizer.org import OrgOptions, RepoResult
    # the image scanners are covered elsewhere; here the build, the hardened run and the fix loop count
    monkeypatch.setattr(imagescan, "scan_image", lambda ref, scanner="auto", local=False:
                        imagescan.ScanResult(image=ref, scanner="test"))
    src = tmp_path / "app"
    src.mkdir()
    (src / "Dockerfile").write_text('FROM busybox:1.37\nRUN mkdir -p /www && echo ok > /www/healthz\n'
                                    'CMD ["sh", "-c", "mkdir -p /app/cache && echo x > /app/cache/f && '
                                    'exec httpd -f -p 8080 -h /www"]\n')
    (src / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n    ports: ['8080:8080']\n"
                                            "    healthcheck:\n      test: [CMD, wget, -qO-, http://localhost:8080/healthz]\n")
    o = OrgOptions(provider="local", org="local", registry="reg.local/sb", gate=True, push_images=False)
    res = RepoResult(provider="local", org="local", project="_", repo="app", status="error", app="gt")
    r = replatform.migrate_repo(src, o, res, "gt", ".", tmp_path / "out", tmp_path / "gen", None, "1.0.0",
                                GitOpsOptions(git_url="https://git.example.com/x.git"), ["Dockerfile"])
    assert r.status == "deployed", (r.reason, r.excluded)
    [c] = json.loads((tmp_path / "out" / "security.json").read_text())["components"]
    assert c["run"]["status"] == "ok" and c["build_fixes"]
    assert "/app" in (tmp_path / "out" / "web" / "k8s.yaml").read_text()
    assert r.components[0]["verification"] == "ok"


def test_sandbox_tester_llm_diagnosis_and_what_is_published(monkeypatch):
    from containerizer import sandbox
    asked = []

    def fake(prompt, schema, model=None, effort="medium", feature=None, system=None):
        asked.append((feature, "CrashLoopBackOff" in prompt, "/app/logs" in prompt))
        return {"outcome": "fixable", "diagnosis": "the app writes its log file under /app/logs",
                "patch_json": json.dumps({"writable": ["/app/logs"], "unknown": 1})}
    monkeypatch.setattr(ai, "ask_json", fake)
    r = {"status": "failing", "reason": "CrashLoopBackOff", "states": ["CrashLoopBackOff"],
         "log_tail": "open '/app/logs/x.log': read-only file system"}
    d = replatform.llm_sandbox_diagnosis(r, "kind: Deployment")
    assert asked == [("sandbox-tester", True, True)]
    assert d == {"outcome": "fixable", "diagnosis": "the app writes its log file under /app/logs",
                 "patch": {"writable": ["/app/logs"]}}
    pub = sandbox.public({"app": "a", "folder": "f", "component": "c", "status": "failing", "llm": d,
                          "log_tail": "secret"})
    assert pub["llm"] == {"outcome": "fixable", "diagnosis": d["diagnosis"]} and "log_tail" not in pub
    monkeypatch.setattr(ai, "ask_json", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no LLM")))
    assert replatform.llm_sandbox_diagnosis(r, "") is None


def test_an_answer_that_cannot_be_cached_is_not_lost(monkeypatch, tmp_path):
    ro = tmp_path / "read-only"
    ro.write_text("")                      # a file where the cache folder should be: mkdir fails
    monkeypatch.setattr(ai, "CACHE", ro / "ai-cache")
    monkeypatch.setattr(ai, "_backend", lambda: "api")
    monkeypatch.setattr(ai, "_ask_api", lambda *a, **k: ({"ok": True}, {"input_tokens": 10, "output_tokens": 2}))
    assert ai.ask_json("q", {"type": "object"}, model="claude-opus-5-5") == {"ok": True}
