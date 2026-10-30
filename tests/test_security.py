"""Security gate: manifest hardening, exceptions, lint, scan policy and base image bumps."""
import copy
import json
from datetime import date

from containerizer import generate, imagescan
from containerizer.assess import assess
from containerizer.generate import k8s_manifests, make_plan
from containerizer.harden import lint_dockerfile, lint_manifests

from test_engine import web_app, write


def _pods(docs):
    out = []
    for d in docs:
        spec = d.get("spec", {})
        tpl = spec.get("template") or spec.get("jobTemplate", {}).get("spec", {}).get("template")
        if tpl:
            out.append(tpl)
    return out


def _manifests(root, role=None):
    a = assess(root)
    c = a.components[0]
    if role:
        c.role = role
    plan = make_plan(a, c)
    return k8s_manifests(a, c, plan, "registry.local/x/y:1.0"), plan


def test_baseline_hardening_passes_lint(tmp_path):
    web_app(tmp_path)
    docs, plan = _manifests(tmp_path)
    tpl = _pods(docs)[0]
    pod = tpl["spec"]
    sc = pod["securityContext"]
    assert sc["runAsUser"] == sc["runAsGroup"] == sc["fsGroup"] == 1654
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"
    assert pod["automountServiceAccountToken"] is False and pod["enableServiceLinks"] is False
    c = pod["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert c["resources"]["limits"]["memory"] and c["resources"]["requests"]["ephemeral-storage"]
    assert all(v["emptyDir"].get("sizeLimit") for v in pod["volumes"] if "emptyDir" in v)
    assert "annotations" not in tpl["metadata"]
    assert [v for v in lint_manifests(docs) if v.severity == "error"] == []


def test_spa_runs_as_nginx_with_writable_cache(tmp_path):
    web_app(tmp_path)
    docs, _ = _manifests(tmp_path, role="spa")
    tpl = _pods(docs)[0]
    assert tpl["spec"]["securityContext"]["fsGroup"] == 101
    mounts = {m["mountPath"] for m in tpl["spec"]["containers"][0]["volumeMounts"]}
    assert {"/tmp", "/var/cache/nginx"} <= mounts
    assert tpl["metadata"]["annotations"]["containerizer.io/exceptions"] == "nginx-writable-dirs"


def test_negotiate_gets_keytab_secret_and_ccache(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="8.0.0" />')
    docs, plan = _manifests(tmp_path)
    pod = _pods(docs)[0]["spec"]
    c = pod["containers"][0]
    keytab = next(m for m in c["volumeMounts"] if m["mountPath"] == "/etc/krb5/keytab")
    vol = next(v for v in pod["volumes"] if v["name"] == keytab["name"])
    assert keytab["readOnly"] and vol["secret"]["secretName"].endswith("-keytab")
    assert {"name": "KRB5CCNAME", "value": "FILE:/tmp/krb5cc_app"} in c["env"]
    assert any(e["id"] == "kerberos-keytab" for e in plan["hardening_exceptions"])


def test_uploads_and_rendering_raise_limits_from_referenced_library(tmp_path):
    web_app(tmp_path, code="class U { void M(IFormFile f) {} }")
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Docs/Docs.csproj" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Docs/Docs.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="QuestPDF" Version="2024.3.0" /></ItemGroup></Project>""")
    docs, _ = _manifests(tmp_path)
    pod = _pods(docs)[0]["spec"]
    c = pod["containers"][0]
    assert c["resources"]["limits"]["memory"] == "1Gi"
    tmp = next(m["name"] for m in c["volumeMounts"] if m["mountPath"] == "/tmp")
    assert next(v for v in pod["volumes"] if v["name"] == tmp)["emptyDir"]["sizeLimit"] == "1Gi"


def test_ping_sysctl_and_k8s_client_waiver(tmp_path):
    web_app(tmp_path, code="class P { void M() { new Ping().Send(\"db\"); } }",
            packages='<PackageReference Include="KubernetesClient" Version="13.0.0" />')
    docs, _ = _manifests(tmp_path)
    tpl = _pods(docs)[0]
    assert {"name": "net.ipv4.ping_group_range", "value": "0 2147483647"} in tpl["spec"]["securityContext"]["sysctls"]
    assert tpl["spec"]["automountServiceAccountToken"] is True
    assert tpl["metadata"]["annotations"]["containerizer.io/waives"] == "sa-token"
    assert [v for v in lint_manifests(docs) if v.check in ("sa-token", "sysctls")] == []


def test_cronjobs_are_hardened_too(tmp_path):
    write(tmp_path, "src/Jobs/Jobs.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>
          <TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>""")
    write(tmp_path, "src/Jobs/Program.cs", 'Console.WriteLine("run");')
    docs, _ = _manifests(tmp_path)
    jobs = [d for d in docs if d["kind"] == "CronJob"]
    assert jobs
    for t in _pods(jobs):
        assert t["spec"]["securityContext"]["runAsUser"] == 1654
        assert t["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True


def test_lint_catches_unsafe_manifests(tmp_path):
    web_app(tmp_path)
    docs, _ = _manifests(tmp_path)
    bad = copy.deepcopy(docs)
    pod = _pods(bad)[0]["spec"]
    c = pod["containers"][0]
    pod["hostNetwork"] = True
    pod["volumes"].append({"name": "host", "hostPath": {"path": "/"}})
    pod["securityContext"]["sysctls"] = [{"name": "kernel.msgmax", "value": "1"}]
    c["securityContext"].update({"privileged": True, "readOnlyRootFilesystem": False,
                                 "capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]}})
    c["env"].append({"name": "Db__Password", "value": "hunter2"})
    checks = {v.check for v in lint_manifests(bad) if v.severity == "error"}
    assert {"host-namespaces", "volume-types", "sysctls", "privileged", "readonly-rootfs", "capabilities",
            "secret-literals"} <= checks
    # a waiver annotation relaxes only the named check
    _pods(bad)[0]["metadata"]["annotations"] = {"containerizer.io/waives": "readonly-rootfs"}
    checks = {v.check for v in lint_manifests(bad)}
    assert "readonly-rootfs" not in checks and "privileged" in checks


def test_dockerfile_lint():
    df = "FROM node:latest AS build\nRUN curl -fsSL https://x.example/install.sh | sh\n" \
         "FROM ubuntu:24.04\nENV API_KEY=abc123\nCOPY --from=build /out /app\n"
    checks = {v.check for v in lint_dockerfile(df)}
    assert {"df-base-tag", "df-remote-add", "secret-literals", "df-user"} <= checks
    ok = "FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build\nFROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled\nUSER 1654\n"
    assert [v for v in lint_dockerfile(ok) if v.severity == "error"] == []
    eol = lint_dockerfile("FROM mcr.microsoft.com/dotnet/aspnet:8.0-noble\nUSER 1654\n", today=date(2026, 12, 1))
    assert any(v.check == "df-base-eol" and "move to 10.0" in v.message for v in eol)


def test_generated_challenge_like_app_has_no_lint_errors(tmp_path):
    web_app(tmp_path / "app", packages='<PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="8.0.0" />')
    out = tmp_path / "out"
    generate.generate_app(assess(tmp_path / "app"), out)
    assert (out / "namespace.yaml").read_text().count("restricted") >= 3
    from containerizer.harden import load_yaml_docs
    for k in out.glob("*/k8s.yaml"):
        assert [v for v in lint_manifests(load_yaml_docs(k.read_text())) if v.severity == "error"] == []
        assert [v for v in lint_dockerfile((k.parent / "Dockerfile").read_text()) if v.severity == "error"] == []


# --------------------------------------------------------------------------- scanning

TRIVY = {"Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}}, "Results": [
    {"Target": "x (ubuntu 24.04)", "Type": "ubuntu", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "libssl3", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1.3", "FixedVersion": "", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-3", "PkgName": "tar", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "HIGH"}]},
    {"Target": "app/x.deps.json", "Type": "dotnet-core", "Vulnerabilities": [
        {"VulnerabilityID": "GHSA-4", "PkgName": "System.Text.Json", "InstalledVersion": "8.0.0", "FixedVersion": "8.0.5", "Severity": "HIGH"}]}]}

GRYPE = {"distro": {"name": "ubuntu", "version": "24.04"}, "matches": [
    {"vulnerability": {"id": "CVE-1", "severity": "Critical", "fix": {"versions": ["3.0.2"], "state": "fixed"}},
     "artifact": {"name": "libssl3", "version": "3.0.1", "type": "deb"}},
    {"vulnerability": {"id": "CVE-2", "severity": "Critical", "fix": {"versions": [], "state": "not-fixed"}},
     "artifact": {"name": "zlib", "version": "1.3", "type": "deb"}}]}


def test_parsers_agree():
    t, g = imagescan.parse_trivy(TRIVY), imagescan.parse_grype(GRYPE)
    assert [(v.id, v.fixed) for v in t[:2]] == [(v.id, v.fixed) for v in g] == [("CVE-1", "3.0.2"), ("CVE-2", "")]
    assert t[3].type == "dotnet-core"


def test_gate_policy_threshold_unfixed_and_allowlist():
    res = imagescan.ScanResult("mcr.microsoft.com/dotnet/aspnet:8.0", "trivy", imagescan.parse_trivy(TRIVY))
    pol = imagescan.policy()
    ev = imagescan.evaluate(res, pol)
    assert not ev["passed"] and [v.id for v in ev["blocking"]] == ["CVE-1"]      # unfixed CVE-2 ignored
    assert [v.id for v in imagescan.evaluate(res, imagescan.policy("HIGH"))["blocking"]] == ["CVE-1", "CVE-3", "GHSA-4"]
    assert len(imagescan.evaluate(res, imagescan.policy(ignore_unfixed=False))["blocking"]) == 2
    pol = {**pol, "allowlist": [{"id": "CVE-1", "reason": "not reachable", "expires": "2099-01-01", "images": "dotnet"}]}
    ev = imagescan.evaluate(res, pol)
    assert ev["passed"] and ev["accepted"][0]["id"] == "CVE-1"
    pol["allowlist"][0]["expires"] = "2020-01-01"
    ev = imagescan.evaluate(res, pol)
    assert not ev["passed"] and ev["expired_allowlist"] == ["CVE-1 (expired 2020-01-01)"]
    pol["allowlist"][0].update(expires="2099-01-01", images="nginx")
    assert not imagescan.evaluate(res, pol)["passed"]


def test_split_ref():
    assert imagescan.split_ref("node:20-bookworm-slim") == ("registry-1.docker.io", "library/node", "20-bookworm-slim")
    assert imagescan.split_ref("nginxinc/nginx-unprivileged:1.27-alpine")[1] == "nginxinc/nginx-unprivileged"
    assert imagescan.split_ref("mcr.microsoft.com/dotnet/aspnet:8.0@sha256:ab") == \
        ("mcr.microsoft.com", "dotnet/aspnet", "8.0")
    assert imagescan.split_ref("localhost:5000/app")[2] == "latest"


def test_bump_candidates_patch_and_minor():
    tags = ["8.0", "8.0.9-noble-chiseled-extra", "8.0.33-noble-chiseled-extra", "8.0.33-noble-chiseled-extra-amd64",
            "10.0.9-noble-chiseled-extra", "8.0-noble-chiseled-extra"]
    c = imagescan.candidates("mcr.microsoft.com/dotnet/aspnet:8.0-noble-chiseled-extra", tags)
    assert c[:2] == ["mcr.microsoft.com/dotnet/aspnet:8.0.33-noble-chiseled-extra",
                     "mcr.microsoft.com/dotnet/aspnet:8.0.9-noble-chiseled-extra"]
    tags = ["1.27-alpine", "1.27.5-alpine", "1.29-alpine", "1.29.8-alpine", "1.30-alpine", "1.30.6-alpine",
            "1.30.6-alpine-slim", "1.31-alpine", "1.31.7-alpine"]
    c = imagescan.candidates("nginxinc/nginx-unprivileged:1.27-alpine", tags)
    assert c[0] == "nginxinc/nginx-unprivileged:1.30.6-alpine"         # newest stable (even) line
    assert all("1.31" not in x and "1.29" not in x for x in c)
    c = imagescan.candidates("eclipse-temurin:21-jre-jammy", ["21_35-jre-jammy", "21.0.9_10-jre-jammy", "21.0.10_7-jre-jammy"])
    assert c[0] == "eclipse-temurin:21.0.10_7-jre-jammy"


def test_lock_overlays_images(tmp_path, monkeypatch):
    lock = tmp_path / "images.lock.yaml"
    lock.write_text(json.dumps({"images": {"mcr.microsoft.com/dotnet/aspnet:8.0-noble-chiseled-extra": {
        "tag": "mcr.microsoft.com/dotnet/aspnet:8.0.33-noble-chiseled-extra", "digest": "sha256:" + "a" * 64}}}))
    monkeypatch.setattr(generate, "IMAGES_LOCK", lock)
    generate.images.cache_clear()
    try:
        assert generate.images()["dotnet"]["aspnet"].endswith(":8.0.33-noble-chiseled-extra")
        assert generate.resolve_digest("mcr.microsoft.com/dotnet/aspnet:8.0.33-noble-chiseled-extra") == "sha256:" + "a" * 64
        monkeypatch.setenv("CONTAINERIZER_IMAGES_LOCK", "0")
        generate.images.cache_clear()
        assert generate.images()["dotnet"]["aspnet"].endswith(":8.0-noble-chiseled-extra")
    finally:
        generate.images.cache_clear()
