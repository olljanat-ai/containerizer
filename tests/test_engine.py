"""Small self-contained tests: synthetic projects in a temp folder."""
import re
import textwrap
from pathlib import Path

from containerizer.assess import assess
from containerizer.generate import buildable, dockerfile_dotnet, make_plan


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))


def web_app(root: Path, code: str = "", packages: str = "", tfm: str = "net8.0") -> None:
    write(root, "src/Web/Web.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>{tfm}</TargetFramework></PropertyGroup>
          <ItemGroup>{packages}</ItemGroup>
        </Project>""")
    write(root, "src/Web/Program.cs", """
        var app = WebApplication.CreateBuilder(args).Build();
        app.MapGet("/healthz", () => "ok");
        app.Run();
        """ + code)


def test_plain_web_is_ready(tmp_path):
    web_app(tmp_path)
    a = assess(tmp_path)
    c = a.components[0]
    assert c.role == "web" and c.verdict in ("info", "config")
    assert a.rating == "A"
    assert c.facts["health"] == "/healthz"
    assert buildable(c)
    df = dockerfile_dotnet(make_plan(a, c))
    assert "USER 1654" in df and "chiseled" in df


def test_office_automation_blocks(tmp_path):
    web_app(tmp_path, 'class W { void M() { var t = Type.GetTypeFromProgID("Word.Application"); } }')
    a = assess(tmp_path)
    assert a.components[0].verdict == "blocker"
    assert a.rating == "E"


def test_guarded_eventlog_is_ignored(tmp_path):
    web_app(tmp_path, 'class L { void M() { if (OperatingSystem.IsWindows()) { EventLog.WriteEntry("a", "b"); } } }')
    ids = {f.rule.id for f in assess(tmp_path).components[0].findings}
    assert "eventlog-write" not in ids


def test_unreferenced_library_blocker_is_dormant(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Lib/Lib.csproj" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Lib/Lib.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>""")
    write(tmp_path, "src/Lib/Legacy.cs", """
        public class LegacyImporter { void M() { var t = Type.GetTypeFromProgID("Excel.Application"); } }""")
    c = assess(tmp_path).components[0]
    assert c.verdict != "blocker"
    assert any(f.dormant for f in c.findings)


def test_netfx_webforms_needs_port(tmp_path):
    write(tmp_path, "src/Site/Site.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>
          <ItemGroup><Reference Include="System.Web" /></ItemGroup></Project>""")
    write(tmp_path, "src/Site/Default.aspx", "<%@ Page %>")
    write(tmp_path, "src/Site/Web.config", "<configuration/>")
    write(tmp_path, "src/Site/Global.asax", "<%@ Application %>")
    a = assess(tmp_path)
    assert a.components[0].role == "web"
    assert a.components[0].verdict == "rewrite"
    assert a.rating == "D"


def test_windows_paths_and_file_logs_are_repointed(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.json", r"""
        {"Archive": {"Folder": "D:\\Archive\\Docs"}, "Import": {"File": "\\\\fs01\\drop\\in.csv"},
         "Serilog": {"WriteTo": [{"Name": "File", "Args": {"path": "D:\\Logs\\web-.log"}}]}}""")
    a = assess(tmp_path)
    plan = make_plan(a, a.components[0])
    assert plan["env"]["Archive__Folder"] == "/data/archive/docs"
    assert plan["env"]["Import__File"] == "/data/in.csv"
    assert plan["env"]["Serilog__WriteTo__0__Name"] == "Console"
    assert "Serilog__WriteTo__0__Args__path" not in plan["env"]
    assert "/data/archive/docs" in plan["add_writable"]


def test_blocker_only_in_optional_command_is_refactor(tmp_path):
    write(tmp_path, "src/Tool/Tool.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Worker"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>""")
    write(tmp_path, "src/Tool/Program.cs", """
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddHostedService<Scanner>();
        switch (args.FirstOrDefault())
        {
            case "--scan":
                builder.Build().Run();
                return 0;
            case "--import-legacy":
                return LegacyImport.Run(args[1]);
            default:
                return 1;
        }""")
    write(tmp_path, "src/Tool/Scanner.cs", "public class Scanner : BackgroundService { }")
    write(tmp_path, "src/Tool/LegacyImport.cs", """
        public static class LegacyImport { public static int Run(string p) { var t = Type.GetTypeFromProgID("Excel.Application"); return 0; } }""")
    c = assess(tmp_path).components[0]
    f = next(f for f in c.findings if f.rule.severity == "blocker")
    assert f.modes == ["--import-legacy"] and f.severity == "refactor"
    assert c.verdict != "blocker"


def test_nlog_and_tool_paths(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/nlog.config", r"""
        <nlog><variable name="d" value="${environment:APP_LOG_DIR:whenEmpty=D\:/App/Logs}" />
        <targets><target xsi:type="File" fileName="${var:d}/x.log" /></targets></nlog>""")
    write(tmp_path, "src/Web/appsettings.json", r"""
        {"Pdf": {"Tool": "C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe"},
         "Routing": {"Db": "D:\\Data\\map.routerdb"}}""")
    a = assess(tmp_path)
    plan = make_plan(a, a.components[0])
    assert plan["env"]["APP_LOG_DIR"] == "/app/logs" and "logs" in plan["add_writable"]
    assert plan["env"]["Pdf__Tool"] == "wkhtmltopdf"
    assert plan["env"]["Routing__Db"] == "/data/data/map.routerdb"


def test_old_tfm_rolls_forward_to_supported_line(tmp_path):
    web_app(tmp_path / "c30", tfm="netcoreapp3.0")          # no runtime image of its own: rolled forward
    a = assess(tmp_path / "c30")
    assert make_plan(a, a.components[0])["env"]["DOTNET_ROLL_FORWARD"] == "Major"
    web_app(tmp_path / "n6", tfm="net6.0")
    a = assess(tmp_path / "n6")
    plan = make_plan(a, a.components[0])
    assert plan["runtime_line"] == "6.0" and "DOTNET_ROLL_FORWARD" not in plan["env"]
    plan["strategy"] = "retarget"                          # the build could not target net6.0 (build-eol-targeting)
    df = dockerfile_dotnet(plan)
    assert ">net10.0</TargetFramework>#" in df and "-p:TargetFramework=net10.0" in df and "aspnet:10.0" in df


def test_blazor_wasm_is_served_as_static_files():
    from containerizer.generate import dockerfile_blazor_wasm
    plan = {"component": "W", "project": "src/W/W.csproj", "remove_files": ["global.json"], "publish_args": []}
    df = dockerfile_blazor_wasm(plan)
    assert 'dotnet publish "src/W/W.csproj" -c Release -o /out' in df
    assert "COPY --from=build /out/wwwroot /usr/share/nginx/html" in df
    assert "ENTRYPOINT" not in df and "listen 8080" in df and "location /_framework/" in df


def test_vendored_js_and_config_comments_are_ignored(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/wwwroot/lib/editor/sql.js", 'var k = ["FILESTREAM", "xp_cmdshell", "cmd.exe"];')
    write(tmp_path, "src/Web/Scripts/media.min.js", 'var t = {".mdb": db, "Process.Start(\\"a.exe\\")": 1};')
    write(tmp_path, "src/Web/Web.Release.config", """
        <configuration>
          <!-- <add name="Db" connectionString="Data Source=.;Integrated Security=True" /> -->
        </configuration>""")
    write(tmp_path, "src/Web/appsettings.json", '{\n  // "Password": "admin"\n  "Logging": {}\n}')
    c = assess(tmp_path).components[0]
    sev = {f.rule.id: f.severity for f in c.findings}
    assert c.verdict in ("info", "config"), sev
    assert "sql-integrated-security" not in sev and "secrets-in-config" not in sev


def test_old_style_reference_to_known_package_is_not_unknown(tmp_path):
    from containerizer.confidence import unknowns
    write(tmp_path, "src/Svc/Svc.csproj", """
        <Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion>
          <OutputType>Exe</OutputType></PropertyGroup>
          <ItemGroup><Reference Include="Newtonsoft.Json, Version=13.0.0.0"><HintPath>..\\packages\\x.dll</HintPath></Reference>
          </ItemGroup></Project>""")
    write(tmp_path, "src/Svc/Program.cs", "class P { static void Main() {} }")
    c = assess(tmp_path).components[0]
    assert "reference:Newtonsoft.Json" not in unknowns(c)


def test_build_decisions_are_explained_in_the_dockerfile(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.0" />')
    write(tmp_path, "src/Web/appsettings.json", r'{"Archive": {"Folder": "D:\\Archive"}}')
    a = assess(tmp_path)
    plan = make_plan(a, a.components[0])
    why = {r["rule"]: r for r in plan["reasons"]}
    assert "plan-sqlite-data" in why and why["plan-sqlite-data"]["refs"]
    assert "config-windows-paths" in why
    df = dockerfile_dotnet(plan)
    assert "# Why this differs from a default build:" in df and "# - plan-sqlite-data: SQLite" in df


def test_spa_is_built_before_publish():
    plan = {"component": "X", "role": "web", "project": "src/X/X.csproj", "tfm": "net8.0", "multi_target": False,
            "strategy": "rollforward", "base": "chiseled", "add_packages": [], "env": {}, "add_writable": [],
            "publish_args": [], "remove_files": [], "entry": "X.dll", "args": [], "applied": [], "spa_root": "ClientApp"}
    df = dockerfile_dotnet(plan)
    assert df.index('"src/X/ClientApp/package.json"') < df.index(" && dotnet publish")
    assert df.index("export PATH=/opt/npm-prebuilt:$PATH") < df.index(" && dotnet publish")


def test_gitops_files_are_flux_only(tmp_path):
    import yaml
    from containerizer.generate import generate_app
    from containerizer.gitops import GitOpsOptions

    web_app(tmp_path / "src-app")
    a = assess(tmp_path / "src-app")
    out = tmp_path / "out"
    generate_app(a, out, gitops=GitOpsOptions(git_url="https://git.example.com/deploy.git", verify_commits=True))
    g = out / "gitops"
    load = lambda p: list(yaml.safe_load_all((g / p).read_text()))
    assert not (g / "argocd").exists()                  # Flux is the only GitOps tool
    assert "Argo CD" not in (g / "README.md").read_text()
    git_es, gpg_es, src, ks = load("flux/git/sync.yaml")
    assert src["spec"]["verify"]["mode"] == "HEAD"
    assert ks["spec"]["serviceAccountName"] == f"{a.name}-reconciler" and ks["spec"]["prune"]
    # the source credentials are ExternalSecrets, never Secrets
    assert (git_es["kind"], git_es["metadata"]["name"]) == ("ExternalSecret", src["spec"]["secretRef"]["name"])
    assert git_es["spec"]["dataFrom"] == [{"extract": {"key": f"{a.name}--cz-git"}}]
    assert gpg_es["metadata"]["name"] == src["spec"]["verify"]["secretRef"]["name"]
    reg_es, cos_es, oci, _ = load("flux/oci/sync.yaml")
    assert oci["spec"]["verify"]["provider"] == "cosign"
    assert reg_es["spec"]["target"]["template"]["type"] == "kubernetes.io/dockerconfigjson"
    assert cos_es["metadata"]["name"] == oci["spec"]["verify"]["secretRef"]["name"]
    kinds = [d["kind"] for d in load("flux/git/image-automation.yaml")]
    assert kinds == ["ExternalSecret", "ImageRepository", "ImagePolicy", "ImageUpdateAutomation"]
    tenant = load("flux/tenant.yaml")
    assert not [d for d in tenant + load("flux/git/sync.yaml") if d["kind"] == "Secret"]
    reader = next(d for d in tenant if d["kind"] == "ServiceAccount" and d["metadata"]["name"] == "app-secrets-reader")
    assert reader["automountServiceAccountToken"] is False
    role = next(d for d in tenant if d["kind"] == "Role")
    assert role["metadata"]["namespace"] == "containerizer-secrets"
    [rule] = role["rules"]
    assert rule["verbs"] == ["get"] and rule["resources"] == ["secrets"]          # no list/watch: named keys only
    assert set(rule["resourceNames"]) >= {f"{a.name}--cz-{k}" for k in ("git", "git-gpg", "registry", "cosign-pub")}
    assert '{"$imagepolicy": "' in (out / "kustomization.yaml").read_text()


def test_docker_outage_is_not_a_build_failure(monkeypatch):
    import subprocess
    import pytest
    from containerizer import verify

    class P:
        returncode, stdout = 1, "ERROR: Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    with pytest.raises(verify.DockerUnavailable):
        verify._run(["docker", "build", "."], 10)


def test_netfx_component_gets_no_windows_container_files(tmp_path):
    """Linux-only (#271): a .NET Framework component that a Windows container could run gets no Dockerfile.windows
    and no stop-gap column in MIGRATION.md; it stays on a Windows VM until it is ported."""
    from containerizer.generate import generate_app

    web_app(tmp_path / "src-app", tfm="net48")
    a = assess(tmp_path / "src-app")
    c = a.components[0]
    assert c.project.is_netfx and c.windows_container_ok and c.verdict != "blocker"
    out = tmp_path / "out"
    generate_app(a, out)
    assert not [p for p in out.rglob("Dockerfile.windows*")]
    migration = [p.read_text() for p in out.rglob("MIGRATION.md")]
    assert migration and not any("stop-gap" in m for m in migration)
    from containerizer.imagescan import image_refs
    assert not [ref for _, ref in image_refs() if "windows" in ref]    # `images --update` cannot re-add them


def test_windows_sign_in_in_code_needs_a_change_also_with_iis_turned_off(tmp_path):
    """The lab's trade-rebates portal: a Make it A patch turned windowsAuthentication off in web.config (only IIS
    reads it) and kept AddNegotiate; it rated A and nobody could sign in in the sandbox. Negotiate in code is the
    same Windows sign-in: refactor, with OpenID Connect as the fix."""
    web_app(tmp_path, code="builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();\n",
            packages='<PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="8.0.0" />')
    write(tmp_path, "src/Web/web.config", """
        <configuration><system.webServer><security><authentication>
          <windowsAuthentication enabled="false" />
        </authentication></security></system.webServer></configuration>""")
    a = assess(tmp_path)
    f = next(f for f in a.components[0].findings if f.rule.id == "windows-auth-iis")
    assert f.rule.severity == "refactor" and "AddOpenIdConnect" in f.rule.fix and a.rating == "B"
    assert str(f.evidence[0].file).endswith("Program.cs")


def test_a_service_with_a_console_switch_gets_it_in_the_container(tmp_path):
    """The Windows service pattern of the .NET docs: it runs as a service unless it gets --console, and a service
    stops at once in a container (ServiceBase: PlatformNotSupportedException)."""
    write(tmp_path / "svc", "src/Feed/Feed.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
        </Project>""")
    write(tmp_path / "svc", "src/Feed/Program.cs", """
        using Microsoft.Extensions.Hosting;
        var isService = !(System.Diagnostics.Debugger.IsAttached || args.Contains("--console"));
        var host = Host.CreateDefaultBuilder(args).ConfigureServices(s => s.AddHostedService<Worker>()).Build();
        if (isService) await host.RunAsServiceAsync(); else await host.RunAsync();
        """)
    a = assess(tmp_path / "svc")
    c = next(c for c in a.components if c.name == "Feed")
    plan = make_plan(a, c)
    assert plan["args"] == ["--console"] and any(r["rule"] == "console-switch" for r in plan["reasons"])
    assert '"--console"]' in dockerfile_dotnet(plan)
    web_app(tmp_path / "web")
    w = assess(tmp_path / "web")
    assert make_plan(w, w.components[0])["args"] == []


def test_an_out_of_support_dotnet_runs_on_its_own_runtime(tmp_path):
    """net6.0 / netcoreapp3.1: the matching Microsoft image, as built and tested (no roll-forward, no retarget);
    the same user and home as the supported images. OS packages (archived Debian) or no image: roll forward."""
    for tfm, image in (("net6.0", "mcr.microsoft.com/dotnet/aspnet:6.0"),
                       ("netcoreapp3.1", "mcr.microsoft.com/dotnet/aspnet:3.1")):
        web_app(tmp_path / tfm, tfm=tfm)
        a = assess(tmp_path / tfm)
        plan = make_plan(a, a.components[0])
        df = dockerfile_dotnet(plan)
        assert f"FROM {image} AS final" in df and "DOTNET_ROLL_FORWARD" not in df
        assert 'HOME="/home/app"' in df and "USER 1654" in df and "own-runtime" in df
        assert 'ASPNETCORE_URLS="http://+:8080"' in df            # ASPNETCORE_HTTP_PORTS is .NET 8+
        assert "FROM mcr.microsoft.com/dotnet/sdk:10.0" in df and "TargetFramework=net10.0" not in df
        full = dockerfile_dotnet({**plan, "base": "full", "add_packages": ["libgdiplus"]})
        assert re.search(r"aspnet:10\.0[.\d]*-noble AS final", full) and 'DOTNET_ROLL_FORWARD="Major"' in full
        assert "own-runtime" not in full
    web_app(tmp_path / "c30", tfm="netcoreapp3.0")
    a = assess(tmp_path / "c30")
    df = dockerfile_dotnet(make_plan(a, a.components[0]))
    assert "chiseled-extra AS final" in df and 'DOTNET_ROLL_FORWARD="Major"' in df and "own-runtime" not in df
    web_app(tmp_path / "n10", tfm="net10.0")
    a = assess(tmp_path / "n10")
    df = dockerfile_dotnet(make_plan(a, a.components[0]))
    assert "noble-chiseled-extra AS final" in df and "HOME" not in df
