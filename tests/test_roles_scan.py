"""Role classification and project-file scanning fixes found on public repositories."""
import textwrap
from pathlib import Path

from containerizer.assess import assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import scan


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))


def roles(root: Path) -> dict[str, str]:
    repo, rules = scan(root), load_rules()
    return {p.name: classify_role(repo, p, rules)[0] for p in repo.projects}


def proj(root: Path, rel: str, sdk: str = "Microsoft.NET.Sdk", props: str = "", items: str = "") -> None:
    write(root, rel, f"""
        <Project Sdk="{sdk}">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework>{props}</PropertyGroup>
          <ItemGroup>{items}</ItemGroup>
        </Project>""")


NETFX_WEB_GUIDS = ("<ProjectTypeGuids>{349c5851-65df-11da-9384-00065b846f21};"
                   "{fae04ec0-301f-11d3-bf4b-00c04f79efbc}</ProjectTypeGuids>")


def netfx(root: Path, rel: str, output: str = "Library", extra: str = "") -> None:
    write(root, rel, f"""<?xml version="1.0" encoding="utf-8"?>
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup>
            <OutputType>{output}</OutputType>
            <TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>
            {extra}
          </PropertyGroup>
        </Project>""")


# 1. packages.config ---------------------------------------------------------

def test_packages_config_feeds_package_conditions(tmp_path):
    netfx(tmp_path, "Svc/Svc.csproj", output="Exe")
    write(tmp_path, "Svc/packages.config", """<?xml version="1.0" encoding="utf-8"?>
        <packages>
          <package id="Microsoft.Owin.Hosting" version="4.2.2" targetFramework="net472" />
          <package id="EntityFramework" version="6.4.4" targetFramework="net472" />
        </packages>""")
    write(tmp_path, "Svc/Program.cs", "class P { static void Main() { } }")
    p = scan(tmp_path).projects[0]
    assert p.packages["EntityFramework"] == "6.4.4"
    assert roles(tmp_path)["Svc"] == "web"          # role-web-selfhost via package from packages.config


# 2. TargetFrameworks: conditions and $(Prop) ---------------------------------

def test_conditional_tfm_append_does_not_override(tmp_path):
    write(tmp_path, "App/App.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <TargetFrameworks>net10.0-android;net10.0</TargetFrameworks>
            <TargetFrameworks Condition="$([MSBuild]::IsOSPlatform('windows'))">$(TargetFrameworks);net10.0-windows10.0.19041.0</TargetFrameworks>
            <OutputType Condition="'$(TargetFramework)' != 'net10.0'">Exe</OutputType>
          </PropertyGroup>
        </Project>""")
    p = scan(tmp_path).projects[0]
    assert p.tfms == ["net10.0-android", "net10.0"]
    assert p.output_type == "Exe"                    # conditional value still used when nothing else sets it


def test_tfm_property_reference_from_imported_props(tmp_path):
    write(tmp_path, "Directory.Build.props", """
        <Project><Import Project="build\\Tfms.props" /></Project>""")
    write(tmp_path, "build/Tfms.props", """
        <Project>
          <PropertyGroup>
            <DefaultTargetFramework Condition="'$(DefaultTargetFramework)' == ''">net10.0</DefaultTargetFramework>
            <CommonTargetFrameworks Condition="'$(CommonTargetFrameworks)' == ''">net10.0;net9.0</CommonTargetFrameworks>
          </PropertyGroup>
          <PropertyGroup Condition="'$(BuildingInsideVisualStudio)' == 'true'">
            <CommonTargetFrameworks>$(DefaultTargetFramework)</CommonTargetFrameworks>
          </PropertyGroup>
        </Project>""")
    write(tmp_path, "src/Lib/Lib.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFrameworks>$(CommonTargetFrameworks)</TargetFrameworks></PropertyGroup>
        </Project>""")
    assert scan(tmp_path).projects[0].tfms == ["net10.0", "net9.0"]


# 3. Windows services built as WinExe ------------------------------------------

def test_winexe_windows_service_is_worker(tmp_path):
    netfx(tmp_path, "Svc/Svc.csproj", output="WinExe")
    write(tmp_path, "Svc/Program.cs", """
        using System.ServiceProcess;
        static class Program { static void Main() { ServiceBase.Run(new ServiceBase[] { new MySvc() }); } }
        partial class MySvc : ServiceBase { }""")
    netfx(tmp_path, "Ui/Ui.csproj", output="WinExe")
    write(tmp_path, "Ui/Program.cs", """
        using System.Windows.Forms;
        static class Program { static void Main() { Application.Run(new Form1()); } }
        class Form1 : Form { }""")
    r = roles(tmp_path)
    assert r["Svc"] == "worker"
    assert r["Ui"] == "desktop"
    svc = next(c for c in assess(tmp_path).components if c.project.name == "Svc")
    assert "desktop-ui" not in {f.rule.id for f in svc.findings}


# 4./5. MAUI clients and Aspire hosts -----------------------------------------

def test_maui_client_and_aspire_host_do_not_count_as_servers(tmp_path):
    proj(tmp_path, "src/Api/Api.csproj", sdk="Microsoft.NET.Sdk.Web")
    write(tmp_path, "src/Api/Program.cs", "var app = WebApplication.CreateBuilder(args).Build(); app.Run();")
    proj(tmp_path, "src/ClientApp/ClientApp.csproj", props="<UseMaui>true</UseMaui><OutputType>Exe</OutputType>")
    write(tmp_path, "src/ClientApp/MauiProgram.cs", "class MauiProgram { }")
    proj(tmp_path, "src/MauiLib/MauiLib.csproj", props="<UseMaui>true</UseMaui>")
    proj(tmp_path, "src/AppHost/AppHost.csproj", sdk="Aspire.AppHost.Sdk/13.0.0", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/AppHost/Program.cs", "var b = DistributedApplication.CreateBuilder(args); b.Build().Run();")
    proj(tmp_path, "src/OldHost/OldHost.csproj", props="<OutputType>Exe</OutputType><IsAspireHost>true</IsAspireHost>")
    write(tmp_path, "src/OldHost/Program.cs", "var b = DistributedApplication.CreateBuilder(args); b.Build().Run();")
    proj(tmp_path, "src/ServiceDefaults/ServiceDefaults.csproj", props="<IsAspireSharedProject>true</IsAspireSharedProject>",
         items='<FrameworkReference Include="Microsoft.AspNetCore.App" />')
    r = roles(tmp_path)
    assert r["ClientApp"] == "desktop" and r["MauiLib"] == "library"
    assert r["AppHost"] == "tool" and r["OldHost"] == "tool"
    assert r["ServiceDefaults"] == "library"
    assert assess(tmp_path).rating == "A"


# 6. tests, benchmarks, installers ---------------------------------------------

def test_test_benchmark_and_installer_projects(tmp_path):
    exe = "<OutputType>Exe</OutputType>"
    main = "class P { static void Main() { } }"
    for name, sdk, props, items in [
        ("Basket.FunctionalTests", "Microsoft.NET.Sdk", "", ""),
        ("Api.Checks", "Microsoft.NET.Sdk", exe, '<PackageReference Include="xunit.v3.mtp-v2" Version="3.0.0" />'),
        ("Unit.Checks", "Microsoft.NET.Sdk", exe, '<PackageReference Include="TUnit" Version="0.50.0" />'),
        ("Ms.Checks", "MSTest.Sdk/3.6.0", "", ""),
        ("App.Benchmarks", "Microsoft.NET.Sdk", exe, ""),
        ("Perf", "Microsoft.NET.Sdk", exe, '<PackageReference Include="BenchmarkDotNet" Version="0.14.0" />'),
        ("App.Setup", "Microsoft.NET.Sdk", exe, ""),
        ("Cms.Setup", "Microsoft.NET.Sdk", "", ""),        # a library module, not an installer
    ]:
        proj(tmp_path, f"{name}/{name}.csproj", sdk=sdk, props=props, items=items)
        write(tmp_path, f"{name}/Program.cs", main)
    write(tmp_path, "Installer/Product.wixproj", "<Project />")
    write(tmp_path, "TestData/readme.txt", "fixtures")
    r = roles(tmp_path)
    for n in ("Basket.FunctionalTests", "Api.Checks", "Unit.Checks", "Ms.Checks"):
        assert r[n] == "test", n
    for n in ("App.Benchmarks", "Perf", "App.Setup", "Product"):
        assert r[n] == "tool", n
    assert r["Cms.Setup"] == "library"


# 7. Windows-TFM libraries -----------------------------------------------------

def test_windows_tfm_library_with_forms_code_is_library(tmp_path):
    write(tmp_path, "HelpersLib/HelpersLib.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net9.0-windows</TargetFramework><OutputType>Library</OutputType></PropertyGroup>
        </Project>""")
    write(tmp_path, "HelpersLib/Helpers.cs", """
        using System.Windows.Forms;
        public static class H { public static void Show(Form f) { Application.Run(f); } }""")
    assert roles(tmp_path)["HelpersLib"] == "library"


# 8. System.Web plugins/areas vs applications ----------------------------------

def test_systemweb_plugin_without_global_asax_is_library(tmp_path):
    for name in ("Store.Web", "Store.Plugin", "Store.Owin"):
        netfx(tmp_path, f"{name}/{name}.csproj", extra=NETFX_WEB_GUIDS)
        write(tmp_path, f"{name}/packages.config", """
            <packages><package id="Microsoft.AspNet.Mvc" version="5.2.7" /></packages>""")
        write(tmp_path, f"{name}/web.config", "<configuration />")
        write(tmp_path, f"{name}/Controllers/HomeController.cs", "public class HomeController : Controller { }")
    write(tmp_path, "Store.Web/Global.asax", '<%@ Application Inherits="Store.MvcApplication" %>')
    write(tmp_path, "Store.Owin/packages.config", """
        <packages><package id="Microsoft.Owin.Host.SystemWeb" version="4.2.2" /></packages>""")
    write(tmp_path, "Store.Owin/Startup.cs", "[assembly: OwinStartup(typeof(Store.Startup))]\nnamespace Store { class Startup { } }")
    r = roles(tmp_path)
    assert r["Store.Web"] == "web"
    assert r["Store.Plugin"] == "library"
    assert r["Store.Owin"] == "web"


# 9. Blazor WebAssembly --------------------------------------------------------

def test_blazor_wasm_standalone_is_spa_and_hosted_is_assets(tmp_path):
    proj(tmp_path, "Standalone/Standalone.csproj", sdk="Microsoft.NET.Sdk.BlazorWebAssembly")
    proj(tmp_path, "Hosted.Client/Hosted.Client.csproj", sdk="Microsoft.NET.Sdk.BlazorWebAssembly")
    proj(tmp_path, "Hosted/Hosted.csproj", sdk="Microsoft.NET.Sdk.Web",
         items='<ProjectReference Include="../Hosted.Client/Hosted.Client.csproj" />')
    write(tmp_path, "Hosted/Program.cs", "var app = WebApplication.CreateBuilder(args).Build(); app.Run();")
    r = roles(tmp_path)
    assert r["Standalone"] == "spa"
    assert r["Hosted.Client"] == "spa-assets"
    assert r["Hosted"] == "web"
