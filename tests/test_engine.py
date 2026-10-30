"""Small self-contained tests: synthetic projects in a temp folder."""
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
    assert a.rating == "C"


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
    web_app(tmp_path, tfm="net6.0")
    a = assess(tmp_path)
    plan = make_plan(a, a.components[0])
    assert plan["env"]["DOTNET_ROLL_FORWARD"] == "Major"
    plan["strategy"] = "retarget"
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
    assert df.index('"src/X/ClientApp/package.json"') < df.index("dotnet publish")
