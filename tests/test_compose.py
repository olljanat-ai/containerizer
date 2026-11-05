"""Docker Compose output (compose.py): compose.yaml per application from the same hardened specs as k8s.yaml,
its secrets and lab dependencies, and the gate lint."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

import pytest
import yaml

from containerizer import compose
from containerizer.assess import assess
from containerizer.generate import generate_app
from test_engine import web_app, write

ROOT = Path(__file__).resolve().parent.parent


def _gen(tmp_path, packages: str = "", settings: dict | None = None, build: bool = True):
    web_app(tmp_path / "app", packages=packages)
    if settings:
        write(tmp_path / "app", "src/Web/appsettings.json", json.dumps(settings))
    a = assess(tmp_path / "app")
    out = tmp_path / "out"
    files = generate_app(a, out, compose_build=build)
    return out, files, yaml.safe_load((out / "compose.yaml").read_text())


def test_compose_carries_the_pod_hardening(tmp_path):
    out, files, doc = _gen(tmp_path)
    assert out / "compose.yaml" in files and out / ".env.example" in files
    [(name, s)] = doc["services"].items()
    k8s = [d for d in yaml.safe_load_all((out / name / "k8s.yaml").read_text()) if d and d["kind"] == "Deployment"][0]
    pod = k8s["spec"]["template"]["spec"]
    assert s["user"] == f"{pod['securityContext']['runAsUser']}:{pod['securityContext']['runAsGroup']}"
    assert s["read_only"] is True and s["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in s["security_opt"]
    assert not any("unconfined" in o for o in s["security_opt"])     # Docker's default seccomp and AppArmor
    assert s["mem_limit"] == "512m" and s["mem_reservation"] == "256m" and s["pids_limit"] > 0
    assert any(t.startswith("/tmp:size=") for t in s["tmpfs"])
    # web component: published on loopback by default, on the internal network and the edge network
    assert s["ports"] == ["${BIND_ADDRESS:-127.0.0.1}:${WEB_PORT:-8080}:8080"]
    assert doc["networks"]["internal"] == {"internal": True}
    # chiseled .NET has no program to run an HTTP check: the probe is kept for an outside checker
    assert "healthcheck" not in s and s["x-containerizer-probe"] == {"http": "/healthz", "port": 8080}
    # built from the application's folder with the generated Dockerfile, the image name of the pipeline
    assert (out / s["build"]["context"]).resolve() == (tmp_path / "app").resolve()
    assert ((out / s["build"]["context"]) / s["build"]["dockerfile"]).resolve() == (out / name / "Dockerfile").resolve()
    assert s["image"].endswith(f"/{name}:latest")
    assert compose.lint(doc) == []
    assert ".env" in (out / ".gitignore").read_text().splitlines()


def test_without_build_compose_uses_the_pipeline_image(tmp_path):
    _, _, doc = _gen(tmp_path, build=False)
    [s] = doc["services"].values()
    assert "build" not in s and s["image"]


def test_secrets_come_from_an_env_file_never_the_compose_file(tmp_path):
    out, _, doc = _gen(tmp_path, settings={"ConnectionStrings": {"Main": "Server=db;Database=x;User Id=u;Password=p"},
                                           "Api": {"ApiKey": "abc"}})
    [(name, s)] = [(n, s) for n, s in doc["services"].items() if "profiles" not in s]
    assert s["env_file"] == [{"path": f"{name}/secrets.env", "required": False}]
    text = (out / "compose.yaml").read_text()
    assert "Password=p" not in text and "abc" not in text
    example = (out / name / "secrets.env.example").read_text()
    assert "ConnectionStrings__Main=\n" in example and "Password=p" not in example
    assert f"*/secrets.env" in (out / ".gitignore").read_text()


def test_lab_dependencies_under_a_profile(tmp_path):
    pk = ('<PackageReference Include="Npgsql" Version="8.0.0" />'
          '<PackageReference Include="StackExchange.Redis" Version="2.8.0" />')
    out, _, doc = _gen(tmp_path, packages=pk, settings={"ConnectionStrings": {"Db": "Host=db;Database=x;Username=u"}})
    for svc in ("postgres", "redis"):
        s = doc["services"][svc]
        assert s["profiles"] == ["lab"] and s["networks"] == ["internal"]
        assert "no-new-privileges:true" in s["security_opt"]
        assert "${LAB_PASSWORD" in json.dumps(s)          # the password from .env, never a value in the file
    assert "LAB_PASSWORD=" in (out / ".env.example").read_text()
    [name] = [n for n, s in doc["services"].items() if "profiles" not in s]
    example = (out / name / "secrets.env.example").read_text()
    assert "# with --profile lab: ConnectionStrings__Db=Host=postgres;" in example
    assert compose.lint(doc) == []                     # lab services are development dependencies: not gated


def test_worker_without_egress_is_internal_only(tmp_path):
    write(tmp_path / "app", "src/Worker/Worker.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Worker">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup>
        </Project>""")
    write(tmp_path / "app", "src/Worker/Program.cs", "Host.CreateDefaultBuilder(args).Build().Run();")
    a = assess(tmp_path / "app")
    generate_app(a, tmp_path / "out")
    doc = yaml.safe_load((tmp_path / "out" / "compose.yaml").read_text())
    [s] = doc["services"].values()
    assert "ports" not in s and s["networks"] == ["internal"] and "edge" not in doc["networks"]


def test_mem_and_cpu_quantities():
    assert compose._mem("512Mi") == "512m" and compose._mem("1Gi") == "1g" and compose._mem("64Mi") == "64m"
    assert compose._mem(None) is None and compose._cpus("500m") == "0.5" and compose._cpus("2") == "2"


BAD = {"services": {"x": {"image": "x", "privileged": True, "network_mode": "host", "user": "0",
                          "cap_add": ["SYS_ADMIN"], "security_opt": ["seccomp:unconfined"],
                          "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
                          "environment": {"DB_PASSWORD": "hunter2", "TOKEN_FILE": "/run/secrets/t",
                                          "API_KEY": "${API_KEY}"}}}}


def test_lint_refuses_what_the_platform_should_not_allow():
    got = {(v.check, v.message) for v in compose.lint(BAD)}
    checks = {c for c, _ in got}
    assert {"privileged", "host-namespaces", "capabilities", "privilege-escalation", "seccomp", "run-as-non-root",
            "readonly-rootfs", "resources", "volume-types", "secret-literals"} <= checks
    lits = [m for c, m in got if c == "secret-literals"]
    assert lits == ["environment DB_PASSWORD carries a value; use env_file or secrets"]


def test_lint_honours_the_components_waivers():
    doc = {"services": {"x": {"image": "x", "user": "1000", "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                              "mem_limit": "1g", "read_only": False,
                              "labels": {compose.WAIVES_LABEL: "readonly-rootfs"}}}}
    assert compose.lint(doc) == []


def test_gate_lints_compose(tmp_path, monkeypatch):
    from containerizer import imagescan
    web_app(tmp_path / "app")
    a = assess(tmp_path / "app")
    out = tmp_path / "out"
    real = compose.write

    def tampered(o, app, parts, lab):
        files = real(o, app, parts, lab)
        d = yaml.safe_load((o / "compose.yaml").read_text())
        next(iter(d["services"].values()))["privileged"] = True
        (o / "compose.yaml").write_text(yaml.safe_dump(d))
        return files
    monkeypatch.setattr(compose, "write", tampered)
    res = imagescan.gate_app(a, out, scan=False, refresh=False)
    assert not res["passed"]
    assert any(v["check"] == "privileged" and "compose.yaml" in v["target"]
               for c in res["components"] for v in c["lint"])


@pytest.mark.skipif(not os.environ.get("CONTAINERIZER_TEST_DOCKER") or not shutil.which("docker"),
                    reason="set CONTAINERIZER_TEST_DOCKER=1 to run compose.yaml of examples/ci-demo in docker")
def test_ci_demo_runs_hardened_in_docker_compose(tmp_path):
    """`containerizer generate examples/ci-demo` writes a compose.yaml that `docker compose config` accepts and
    `docker compose up` runs with the hardening. A TLS-inspecting proxy's CA: CONTAINERIZER_TEST_CA (a file)."""
    out = tmp_path / "out"
    subprocess.run(["python", "-m", "containerizer", "generate", str(ROOT / "examples" / "ci-demo"), "--out", str(out)],
                   check=True, cwd=ROOT)
    app = out / "ci-demo"
    subprocess.run(["docker", "compose", "config", "-q"], cwd=app, check=True)
    ca = os.environ.get("CONTAINERIZER_TEST_CA")
    if ca:      # the Dockerfile's optional build secret "ca"
        shutil.copy(ca, app / "ca.crt")
        (app / "compose.override.yaml").write_text(
            "services:\n  demo-web:\n    build:\n      secrets: [ca]\nsecrets:\n  ca:\n    file: ./ca.crt\n")
    port = "18080"
    (app / ".env").write_text(f"BIND_ADDRESS=127.0.0.1\nDEMO_WEB_PORT={port}\n")
    try:
        subprocess.run(["docker", "compose", "up", "-d", "--build", "--wait", "--wait-timeout", "120"], cwd=app,
                       check=False, timeout=900)
        cid = subprocess.run(["docker", "compose", "ps", "-q", "demo-web"], cwd=app, capture_output=True, text=True,
                             check=True).stdout.strip()
        info = json.loads(subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, check=True).stdout)[0]
        hc = info["HostConfig"]
        assert info["State"]["Running"], info["State"]
        assert info["Config"]["User"] == "1654:1654" and hc["ReadonlyRootfs"] is True
        assert hc["CapDrop"] == ["ALL"] and "no-new-privileges:true" in hc["SecurityOpt"]
        assert hc["Memory"] == 512 * 1024 ** 2 and "/tmp" in hc["Tmpfs"]
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
                    assert r.status == 200
                    break
            except OSError:
                import time
                time.sleep(1)
        else:
            pytest.fail("demo-web did not answer /healthz")
    finally:
        subprocess.run(["docker", "compose", "down", "-v"], cwd=app, check=False)
