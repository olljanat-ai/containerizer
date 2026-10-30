"""Round 7 regression tests from the real-world corpus (rw5-*): VB.NET and F# projects, references
given as file paths, old-style MSTest projects, Xamarin/UWP heads, web apps on the plain SDK,
qualified and VB SupportedOSPlatform guards, and services that manage the host's Windows services."""
from containerizer.assess import assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import reference_name, scan
from tests.test_engine import web_app, write
from tests.test_round3 import oldstyle, proj

RULES = load_rules()


def roles(root) -> dict[str, str]:
    repo = scan(root)
    return {p.name: classify_role(repo, p, RULES)[0] for p in repo.projects}


def sev(root, rid: str, comp: str | None = None) -> str | None:
    for c in assess(root, RULES).components:
        if comp is None or c.name == comp:
            for f in c.findings:
                if f.rule.id == rid:
                    return f.severity
    return None


def rating(root) -> str:
    return assess(root, RULES).rating


def vb_service(root, code: str, refs: str = "") -> None:
    write(root, "Svc/Svc.vbproj", f"""
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup>
            <OutputType>WinExe</OutputType>
            <TargetFrameworkVersion>v4.8</TargetFrameworkVersion>
          </PropertyGroup>
          <ItemGroup><Reference Include="System.ServiceProcess" />{refs}</ItemGroup>
          <ItemGroup><Compile Include="Service1.vb" /></ItemGroup>
        </Project>""")
    write(root, "Svc/Service1.vb", code)


# ------------------------------------------------------------------ references given as paths

def test_reference_name_normalises_paths_and_strong_names():
    assert reference_name(r"..\References\$(SharePointVersion)\Microsoft.SharePoint.dll") == "Microsoft.SharePoint"
    assert reference_name("../tools/xunit/xunit.dll") == "xunit"
    assert reference_name("System.Web, Version=4.0.0.0, Culture=neutral") == "System.Web"
    assert reference_name("Microsoft.SharePoint") == "Microsoft.SharePoint"
    assert reference_name("Tool.exe") == "Tool"


def test_sharepoint_and_test_roles_from_path_references(tmp_path):
    # rw5-slk: Slk/Dll/SlkDll.csproj, Slk/unitTest
    oldstyle(tmp_path, "Slk/Dll/SlkDll.csproj", "Library",
             extra='</PropertyGroup><ItemGroup><Reference Include="..\\References\\15\\Microsoft.SharePoint.dll" /></ItemGroup><PropertyGroup>')
    write(tmp_path, "Slk/Dll/Class1.cs", "class C { void M(SPWeb web) {} }")
    oldstyle(tmp_path, "Slk/unitTest/unitTest.csproj", "Library",
             extra='</PropertyGroup><ItemGroup><Reference Include="..\\..\\tools\\xunit\\xunit.dll" /></ItemGroup><PropertyGroup>')
    write(tmp_path, "Slk/unitTest/Class1.cs", "public class T { [Fact] public void A() {} }")
    r = roles(tmp_path)
    assert r["SlkDll"] == "sharepoint"
    assert r["unitTest"] == "test"
    assert rating(tmp_path) == "E"


def test_old_style_mstest_project_is_a_test(tmp_path):
    # rw5-biztalk-learning-path: UnitTestProject1 (test GUID + QualityTools reference)
    oldstyle(tmp_path, "T1/T1.csproj", "Library",
             extra="<ProjectTypeGuids>{3AC096D0-A1C2-E12C-1390-A8335801FDAB};{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}</ProjectTypeGuids>")
    oldstyle(tmp_path, "T2/T2.csproj", "Library",
             extra='</PropertyGroup><ItemGroup><Reference Include="Microsoft.VisualStudio.QualityTools.UnitTestFramework, Version=10.0.0.0" /></ItemGroup><PropertyGroup>')
    oldstyle(tmp_path, "Lib/Lib.csproj", "Library")
    r = roles(tmp_path)
    assert r["T1"] == "test" and r["T2"] == "test" and r["Lib"] == "library"


# ------------------------------------------------------------------ mobile heads

def test_xamarin_and_uwp_heads_are_clients(tmp_path):
    # rw5-smarthotel-mobile: Android head is OutputType Library + AndroidApplication
    oldstyle(tmp_path, "App.Android/App.Android.csproj", "Library",
             extra="<ProjectTypeGuids>{EFBA0AD7-5A72-4C68-AF49-83D382785DCF};{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}</ProjectTypeGuids>"
                   "<AndroidApplication>true</AndroidApplication><TargetFrameworkVersion>v9.0</TargetFrameworkVersion>")
    oldstyle(tmp_path, "App.iOS/App.iOS.csproj", "Exe",
             extra="<ProjectTypeGuids>{FEACFBD2-3405-455C-9665-78FE426C6842};{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}</ProjectTypeGuids>")
    write(tmp_path, "App.iOS/Main.cs", "public class Application { static void Main(string[] a) { UIApplication.Main(a); } }")
    oldstyle(tmp_path, "App.UWP/App.UWP.csproj", "AppContainerExe")
    repo = scan(tmp_path)
    android = next(p for p in repo.projects if p.name == "App.Android")
    assert android.tfms == ["monoandroid9.0"]
    r = roles(tmp_path)
    assert r == {"App.Android": "desktop", "App.iOS": "desktop", "App.UWP": "desktop"}
    assert rating(tmp_path) == "E"   # no server component


# ------------------------------------------------------------------ web app on the plain SDK

def test_webapplication_exe_on_plain_sdk_is_web(tmp_path):
    # rw5-papercut: Papercut.Service uses Microsoft.NET.Sdk; ASP.NET Core comes transitively
    proj(tmp_path, "Svc/Svc.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "Svc/Program.cs", "var builder = WebApplication.CreateBuilder(args);\nbuilder.Build().Run();")
    assert roles(tmp_path)["Svc"] == "web"


def test_worker_sdk_with_webapplication_host_stays_worker(tmp_path):
    # rw-eshop: src/OrderProcessor (Sdk.Worker, WebApplication only for MapDefaultEndpoints)
    proj(tmp_path, "Proc/Proc.csproj", sdk="Microsoft.NET.Sdk.Worker", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "Proc/Program.cs", "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddHostedService<Job>();\nvar app = builder.Build();\napp.MapDefaultEndpoints();\napp.Run();")
    assert roles(tmp_path)["Proc"] == "worker"


# ------------------------------------------------------------------ SupportedOSPlatform guards

def test_fully_qualified_supported_os_platform_guards_a_method(tmp_path):
    # rw5-papercut: src/Papercut.Message/Helpers/MessageHelper.cs:52
    web_app(tmp_path, code="""
        class H {
            [System.Runtime.Versioning.SupportedOSPlatform("windows")]
            static string Mime() { return (string)Registry.ClassesRoot.OpenSubKey(".eml").GetValue("Content Type"); }
            [global::System.Runtime.Versioning.SupportedOSPlatformAttribute("windows")]
            static object K() => Registry.CurrentUser.OpenSubKey("x");
        }""")
    assert sev(tmp_path, "registry", "Web") is None


def test_vb_supported_os_platform_guards_a_member(tmp_path):
    vb_service(tmp_path, """
        Imports Microsoft.Win32
        Public Class Service1
            Inherits System.ServiceProcess.ServiceBase
            <SupportedOSPlatform("windows")> _
            Private Function Mime() As String
                Return Registry.ClassesRoot.OpenSubKey(".eml").GetValue("Content Type")
            End Function
        End Class""")
    assert sev(tmp_path, "registry") is None
    vb_service(tmp_path, """
        Imports Microsoft.Win32
        Public Class Service1
            Inherits System.ServiceProcess.ServiceBase
            <SupportedOSPlatform("windows")>
            Private Function Mime() As String
                Return ""
            End Function
            Private Function Other() As Object
                Return Registry.CurrentUser.OpenSubKey("x")
            End Function
        End Class""")
    assert sev(tmp_path, "registry") == "refactor"   # the guard ends at End Function


# ------------------------------------------------------------------ host Windows services

def test_managing_host_windows_services_is_a_blocker(tmp_path):
    # rw5-restmsc: Rest.msc/Utils/ServiceManager.vb, Wmi.vb
    vb_service(tmp_path, """
        Public Class Service1
            Inherits System.ServiceProcess.ServiceBase
            Function All() As Object
                Dim q = New ManagementObjectSearcher("SELECT * FROM Win32_Service")
                Return ServiceController.GetServices()
            End Function
        End Class""")
    assert sev(tmp_path, "windows-host-services") == "blocker"
    assert rating(tmp_path) == "E"


def test_controlling_own_service_is_not_host_management(tmp_path):
    web_app(tmp_path, code='class C { void M() { using var sc = new ServiceController("MySvc"); var x = "Win32_Processor"; } }')
    assert sev(tmp_path, "windows-host-services", "Web") is None
    web_app(tmp_path, code='class C { void M() { if (OperatingSystem.IsWindows()) { var s = ServiceController.GetServices(); } } }')
    assert sev(tmp_path, "windows-host-services", "Web") is None


# ------------------------------------------------------------------ VB syntax in code patterns

def test_vb_service_base_declare_and_imports(tmp_path):
    # rw5-powerwallservice: PowerwallService.Designer.vb:3 `Inherits System.ServiceProcess.ServiceBase`
    vb_service(tmp_path, """
        Imports System.Drawing
        Partial Class Service1
            Inherits System.ServiceProcess.ServiceBase
            Private Declare Auto Function MessageBox Lib "user32.dll" (h As IntPtr, t As String, c As String, k As UInteger) As Integer
            Private Declare Function GetTickCount Lib "kernel32" () As Integer
        End Class""")
    r = roles(tmp_path)
    assert r["Svc"] == "worker"
    assert sev(tmp_path, "windows-service-netfx") == "refactor"
    assert sev(tmp_path, "pinvoke-gui") is not None
    assert sev(tmp_path, "pinvoke-kernel32") is not None


def test_library_import_is_pinvoke(tmp_path):
    web_app(tmp_path, code='partial class N { [LibraryImport("user32.dll")] private static partial int GetDC(nint h); }')
    assert sev(tmp_path, "pinvoke-gui", "Web") is not None


def test_vb_wcf_service_contract_attribute(tmp_path):
    vb_service(tmp_path, """
        <ServiceContract()>
        Public Interface IApi
            <OperationContract()> Function Ping() As String
        End Interface""", refs='<Reference Include="System.ServiceModel" />')
    assert any(f.rule.id.startswith("wcf") for c in assess(tmp_path, RULES).components for f in c.findings)


# ------------------------------------------------------------------ F#

def test_fsharp_sources_are_scanned(tmp_path):
    # rw5-giraffesample / rw5-saturn-example: .fsproj with code in .fs files
    write(tmp_path, "Api/Api.fsproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><Compile Include="Program.fs" /></ItemGroup>
        </Project>""")
    write(tmp_path, "Api/Program.fs", """
        open Microsoft.Win32
        [<EntryPoint>]
        let main argv =
            let builder = WebApplication.CreateBuilder(argv)
            let k = Registry.LocalMachine.OpenSubKey("SOFTWARE")
            0
        """)
    assert roles(tmp_path)["Api"] == "web"
    assert sev(tmp_path, "registry", "Api") == "refactor"
