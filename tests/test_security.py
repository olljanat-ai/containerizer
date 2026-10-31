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
    lock.write_text(json.dumps({"images": {"mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra": {
        "tag": "mcr.microsoft.com/dotnet/aspnet:10.0.14-noble-chiseled-extra", "digest": "sha256:" + "a" * 64}}}))
    monkeypatch.setattr(generate, "IMAGES_LOCK", lock)
    generate.images.cache_clear()
    try:
        assert generate.images()["dotnet"]["aspnet"].endswith(":10.0.14-noble-chiseled-extra")
        assert generate.resolve_digest("mcr.microsoft.com/dotnet/aspnet:10.0.14-noble-chiseled-extra") == "sha256:" + "a" * 64
        monkeypatch.setenv("CONTAINERIZER_IMAGES_LOCK", "0")
        generate.images.cache_clear()
        assert generate.images()["dotnet"]["aspnet"].endswith(":10.0-noble-chiseled-extra")
    finally:
        generate.images.cache_clear()


def test_hardening_error_patterns_need_whole_words():
    assert not imagescan.HARDENING_ERRORS.search("at ServiceProvider.CreateServiceAccessor(ServiceIdentifier id)")
    assert imagescan.HARDENING_ERRORS.search("Error: EACCES: permission denied, open '/app/x'")
    assert imagescan.HARDENING_ERRORS.search("System.IO.IOException: Read-only file system : '/app/logs'")


# --------------------------------------------------------------------------- NSA/CISA hardening

def _kind(docs, kind):
    return [d for d in docs if d.get("kind") == kind]


def test_network_policy_default_deny_with_inferred_egress(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.0" />')
    write(tmp_path, "src/Web/appsettings.json", '{"Nav": {"Url": "http://nav01.corp.local:7048/odata"},'
                                                ' "Self": "http://localhost:5241"}')
    docs, plan = _manifests(tmp_path)
    [np] = _kind(docs, "NetworkPolicy")
    spec = np["spec"]
    assert spec["policyTypes"] == ["Ingress", "Egress"]
    dns, siblings, external = spec["egress"]
    assert {"port": 53, "protocol": "UDP"} in dns["ports"]
    ports = {p["port"] for p in external["ports"]}
    assert {1433, 7048} <= ports and 5241 not in ports            # localhost is not a dependency
    assert "169.254.169.254/32" in external["to"][0]["ipBlock"]["except"]
    assert spec["ingress"][0]["ports"] == [{"port": 8080, "protocol": "TCP"}]
    assert {e["id"] for e in plan["egress"]} == {"sql-server", "configured-ports"}
    assert [v for v in lint_manifests(docs) if v.check in ("network-policy", "egress-policy")] == []


def test_spa_gets_no_external_egress(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.0" />')
    docs, _ = _manifests(tmp_path, role="spa")
    [np] = _kind(docs, "NetworkPolicy")
    assert len(np["spec"]["egress"]) == 2                      # DNS and sibling components only


def test_own_service_account_apparmor_and_external_secrets(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.json", '{"ConnectionStrings": {"Main": "Server=db;Database=x"}}')
    docs, _ = _manifests(tmp_path)
    [sa] = _kind(docs, "ServiceAccount")
    assert sa["automountServiceAccountToken"] is False
    pod = _pods(docs)[0]["spec"]
    assert pod["serviceAccountName"] == sa["metadata"]["name"]
    assert pod["containers"][0]["securityContext"]["appArmorProfile"] == {"type": "RuntimeDefault"}
    assert not _kind(docs, "Secret") and not _kind(docs, "Role")
    [es] = _kind(docs, "ExternalSecret")
    assert es["spec"]["secretStoreRef"]["kind"] == "ClusterSecretStore"
    assert es["spec"]["data"][0]["secretKey"] == "ConnectionStrings__Main"
    checks = {v.check for v in lint_manifests(docs)}
    assert not checks & {"service-account", "apparmor", "plain-secret", "secret-literals", "secret-source",
                         "external-secret-store"}
    # remote key <namespace>--<component>, one property per key
    app = pod["containers"][0]["name"]
    assert es["spec"]["data"][0]["remoteRef"] == {"key": f"{es['metadata']['labels']['app.kubernetes.io/part-of']}--{app}",
                                                  "property": "ConnectionStrings__Main"}


def test_lint_secret_checks():
    pod = {"automountServiceAccountToken": False, "imagePullSecrets": [{"name": "regcred"}],
           "volumes": [{"name": "f", "secret": {"secretName": "files"}},
                       {"name": "p", "projected": {"sources": [{"secret": {"name": "proj"}}]}}],
           "containers": [{"name": "c", "env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "env", "key": "A"}}}],
                           "envFrom": [{"secretRef": {"name": "bulk"}}]}]}
    deploy = {"kind": "Deployment", "metadata": {"name": "w"}, "spec": {"template": {"metadata": {}, "spec": pod}}}
    es = lambda n, **spec: {"kind": "ExternalSecret", "metadata": {"name": n},
                            "spec": {"secretStoreRef": {"kind": "ClusterSecretStore", "name": "app-secrets"}, **spec}}
    missing = {v.message.split()[1] for v in lint_manifests([deploy]) if v.check == "secret-source"}
    assert missing == {"regcred", "files", "proj", "env", "bulk"}
    produced = [es("files"), es("x", target={"name": "proj"}), es("env"), es("bulk")]
    left = [v for v in lint_manifests([deploy] + produced, provided={"regcred"}) if v.check == "secret-source"]
    assert left == [] and all(v.severity == "error" for v in lint_manifests([deploy]) if v.check == "secret-source")
    # a plain Secret, a store in the app, an ExternalSecret without a store or with a literal in its template
    bad = [{"kind": "Secret", "metadata": {"name": "s"}, "stringData": {"k": ""}},
           {"kind": "ClusterSecretStore", "metadata": {"name": "mine"}},
           {"kind": "ExternalSecret", "metadata": {"name": "nostore"}, "spec": {}},
           es("lit", target={"template": {"data": {"Password": "hunter2", "url": "https://x", "Token": "{{ .t }}"}}})]
    got = {(v.check, v.target) for v in lint_manifests(bad)}
    assert ("plain-secret", "Secret/s") in got and ("external-secret-store", "ClusterSecretStore/mine") in got
    assert ("external-secret-store", "ExternalSecret/nostore") in got
    assert [v.message for v in lint_manifests(bad) if v.target == "ExternalSecret/lit"] == [
        "template key Password carries a literal value; read it from the store"]
    # a generator (devdb passwords) needs no store
    gen = {"kind": "ExternalSecret", "metadata": {"name": "g"},
           "spec": {"dataFrom": [{"sourceRef": {"generatorRef": {"kind": "Password", "name": "g"}}}]}}
    assert not lint_manifests([gen])


def test_secret_store_per_provider(monkeypatch):
    from containerizer import eso
    docs = eso.secret_store()
    assert [d["kind"] for d in docs] == ["Namespace", "ResourceQuota", "ClusterSecretStore"]
    ns, quota, store = docs
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    assert quota["spec"]["hard"] == {"pods": "0"}
    k8s = store["spec"]["provider"]["kubernetes"]
    # referent auth: no namespace, so ESO uses the reader of each ExternalSecret's own namespace
    assert k8s["auth"] == {"serviceAccount": {"name": "app-secrets-reader"}}
    assert k8s["server"]["caProvider"]["namespace"] == k8s["remoteNamespace"] == "containerizer-secrets"
    for p, auth in (("vault", lambda s: s["auth"]["kubernetes"]["serviceAccountRef"]),
                    ("azurekv", lambda s: s["serviceAccountRef"]),
                    ("aws", lambda s: s["auth"]["jwt"]["serviceAccountRef"])):
        monkeypatch.setenv("CONTAINERIZER_SECRET_STORE", p)
        [store] = eso.secret_store()
        spec = store["spec"]["provider"][p]
        assert "namespace" not in auth(spec) and auth(spec)["name"] == "app-secrets-reader"
        assert "readerAnnotations" not in spec
        assert eso.store_access("shop", ["shop--web"]) == []          # access is granted outside the cluster
    sa = eso.reader_service_account("shop")
    assert sa["metadata"]["annotations"]["eks.amazonaws.com/role-arn"].endswith("role/app-secrets-shop")
    monkeypatch.setenv("CONTAINERIZER_SECRET_STORE", "plaintext")
    import pytest
    with pytest.raises(ValueError):
        eso.secret_store()


def test_kubernetes_api_client_gets_token_and_empty_role(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="KubernetesClient" Version="13.0.0" />')
    docs, _ = _manifests(tmp_path)
    [sa] = _kind(docs, "ServiceAccount")
    [role] = _kind(docs, "Role")
    [rb] = _kind(docs, "RoleBinding")
    assert sa["automountServiceAccountToken"] is True and role["rules"] == []
    assert rb["subjects"][0]["name"] == sa["metadata"]["name"]


def test_keytab_secret_becomes_external_secret(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="8.0.0" />')
    docs, _ = _manifests(tmp_path)
    es = {d["metadata"]["name"]: d for d in _kind(docs, "ExternalSecret")}
    keytab = next(v for k, v in es.items() if k.endswith("-keytab"))
    assert keytab["spec"]["data"][0]["secretKey"] == "service.keytab"
    [np] = _kind(docs, "NetworkPolicy")
    assert any(p["port"] == 88 and p["protocol"] == "UDP" for r in np["spec"]["egress"] for p in r.get("ports", []))


def test_namespace_policies_and_report(tmp_path):
    from containerizer.harden import hardening_markdown, namespace_policies
    web_app(tmp_path)
    docs, _ = _manifests(tmp_path)
    ns = namespace_policies(docs)
    deny, lr, quota = ns
    assert deny["spec"] == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
    assert "cpu" not in lr["spec"]["limits"][0]["default"]          # no CPU throttling by default
    hard = quota["spec"]["hard"]
    assert hard["limits.memory"] == "2048Mi"                        # floor (2 replicas x 512Mi x 1.5 = 1536Mi)
    md = hardening_markdown("app", {"web": docs})
    assert "| Containers run as a non-root user | applied |" in md
    assert "| API server audit logging | cluster action |" in md
    assert "Images are deployed by digest | not applied" in md      # :latest in the test manifests


def test_generate_writes_security_files(tmp_path):
    web_app(tmp_path / "app")
    out = tmp_path / "out"
    generate.generate_app(assess(tmp_path / "app"), out)
    import yaml as _y
    kz = _y.safe_load((out / "kustomization.yaml").read_text())
    assert "security.yaml" in kz["resources"]
    assert (out / "HARDENING.md").exists() and (out / "cluster" / "audit-policy.yaml").exists()


def test_gitops_hardening_keeps_platform_policies_out_of_sync(tmp_path):
    web_app(tmp_path / "app")
    out = tmp_path / "out"
    generate.generate_app(assess(tmp_path / "app"), out)
    import yaml as _y
    tenant = [d for d in _y.safe_load_all((out / "gitops/flux/tenant.yaml").read_text()) if d]
    assert {"ResourceQuota", "LimitRange", "NetworkPolicy"} <= {d["kind"] for d in tenant}
    sync = [d for d in _y.safe_load_all((out / "gitops/flux/git/sync.yaml").read_text()) if d]
    ks = next(d for d in sync if d["kind"] == "Kustomization")
    deleted = {p["target"]["kind"] for p in ks["spec"]["patches"] if "$patch: delete" in p["patch"]}
    assert {"ResourceQuota", "LimitRange", "NetworkPolicy"} <= deleted and ks["spec"]["force"] is False
    proj = _y.safe_load((out / "gitops/argocd/project.yaml").read_text())
    assert proj["spec"]["clusterResourceWhitelist"] == [{"group": "", "kind": "Namespace"}]
    assert {"group": "", "kind": "Secret"} not in proj["spec"]["namespaceResourceWhitelist"]
    assert proj["spec"]["sourceNamespaces"] == []
    # the store reader is platform-owned on Flux (the source's ExternalSecret needs it before the first sync)
    assert ("ServiceAccount", "app-secrets-reader") in {(d["kind"], d["metadata"]["name"]) for d in tenant}
    assert "ServiceAccount" in deleted
    # kinds without a spec stay without one (strict field validation rejects `spec` on them)
    assert not [d for d in tenant if d["kind"] in ("ServiceAccount", "Role", "RoleBinding") and "spec" in d]
    store = list(_y.safe_load_all((out / "cluster/secret-store.yaml").read_text()))
    assert {d["kind"] for d in store} == {"Namespace", "ResourceQuota", "ClusterSecretStore", "Role", "RoleBinding"}
    md = (out / "HARDENING.md").read_text()
    assert "| Each namespace reads only its own keys from the secret store | cluster action |" in md
