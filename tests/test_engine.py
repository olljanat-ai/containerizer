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
