"""Round 11 regression tests from the real-world corpus (rw7-*): stray test-framework packages in
production projects, remote WMI, impersonation of non-Windows identities, private callers of
guarded P/Invokes, ASP.NET Core apps that still restore MVC 5 packages, portable checked-in
assemblies, WCF workflow services (.xamlx), CoreWCF hosts, Worker-SDK projects that are web apps or
WinForms tools, QRCoder's GDI+ renderers and Windows choices of a configured option switch."""
import struct

from containerizer.assess import classify_role
from containerizer.scan import scan
from tests.test_engine import web_app, write
from tests.test_round7 import RULES, rating, sev

WEB_GUID = "{349c5851-65df-11da-9384-00065b846f21};{fae04ec0-301f-11d3-bf4b-00c04f79efbc}"


def role_of(root, name):
    repo = scan(root)
    p = next(p for p in repo.projects if p.name == name)
    return classify_role(repo, p, RULES)[0]


def sdk_proj(root, rel, sdk="Microsoft.NET.Sdk", tfm="net8.0", props="", items=""):
    write(root, rel, f"""
        <Project Sdk="{sdk}">
          <PropertyGroup><TargetFramework>{tfm}</TargetFramework>{props}</PropertyGroup>
          <ItemGroup>{items}</ItemGroup>
        </Project>""")


# ------------------------------------------------------------------ test projects

XUNIT = '<PackageReference Include="xunit" Version="2.4.1" />'


def test_stray_xunit_in_a_service_exe_is_not_a_test(tmp_path):
    sdk_proj(tmp_path, "src/Ftp/Ftp.csproj", props="<OutputType>Exe</OutputType>", items=XUNIT)
    write(tmp_path, "src/Ftp/Program.cs", "class P { static void Main() { } }")
    assert role_of(tmp_path, "Ftp") != "test"


def test_stray_xunit_in_a_referenced_library_is_not_a_test(tmp_path):
    sdk_proj(tmp_path, "src/Common/Common.csproj", items=XUNIT)
    write(tmp_path, "src/Common/Lib.cs", "public class Lib { }")
    web_app(tmp_path)
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Common/Common.csproj" /></ItemGroup>
        </Project>""")
    assert role_of(tmp_path, "Common") == "library"


def test_xunit_library_with_facts_is_a_test(tmp_path):
    sdk_proj(tmp_path, "src/Checks/Checks.csproj", items=XUNIT)
    write(tmp_path, "src/Checks/C.cs", "public class C { [Fact] public void Works() { } }")
    assert role_of(tmp_path, "Checks") == "test"


def test_unreferenced_xunit_library_is_a_test(tmp_path):
    sdk_proj(tmp_path, "src/Checks/Checks.csproj", items=XUNIT)
    write(tmp_path, "src/Checks/C.cs", "public class C { }")
    assert role_of(tmp_path, "Checks") == "test"


def test_runner_package_alone_makes_a_test(tmp_path):
    sdk_proj(tmp_path, "src/T/T.csproj", props="<OutputType>Exe</OutputType>",
             items='<PackageReference Include="xunit.v3" Version="1.0.0" />')
    assert role_of(tmp_path, "T") == "test"


def test_projects_in_top_level_tests_folder_are_tests(tmp_path):
    sdk_proj(tmp_path, "tests/Stub.Server/Stub.Server.csproj", tfm="net462",
             props="<OutputType>Exe</OutputType>")
    write(tmp_path, "tests/Stub.Server/Program.cs", "class P { static void Main() { } }")
    assert role_of(tmp_path, "Stub.Server") == "test"


def test_other_projects_in_tests_folder_keep_their_role(tmp_path):
    sdk_proj(tmp_path, "tests/Shop.TestData/Shop.TestData.csproj")
    write(tmp_path, "tests/Shop.TestData/Seed.cs", "public class Seed { }")
    sdk_proj(tmp_path, "tests/Shop.Benchmarks/Shop.Benchmarks.csproj", props="<OutputType>Exe</OutputType>",
             items='<PackageReference Include="BenchmarkDotNet" Version="0.13.0" />')
    assert role_of(tmp_path, "Shop.TestData") == "library"
    assert role_of(tmp_path, "Shop.Benchmarks") == "tool"


def test_aspire_apphost_in_tests_folder_stays_a_tool(tmp_path):
    sdk_proj(tmp_path, "tests/TestAppHost/TestAppHost.csproj", sdk="Aspire.AppHost.Sdk/13.0.0",
             props="<OutputType>Exe</OutputType>")
    assert role_of(tmp_path, "TestAppHost") == "tool"


def test_test_automation_name_is_a_test(tmp_path):
    sdk_proj(tmp_path, "src/Shop.TestAutomation/Shop.TestAutomation.csproj")
    assert role_of(tmp_path, "Shop.TestAutomation") == "test"


# ------------------------------------------------------------------ host services / identity

def test_remote_wmi_service_query_is_not_host_management(tmp_path):
    web_app(tmp_path, '''
    class Wmi {
        object Q(string host) {
            var scope = new ManagementScope($"\\\\\\\\{host}\\\\root\\\\cimv2");
            return new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_Service"));
        }
    }''')
    assert sev(tmp_path, "windows-host-services") is None


def test_local_wmi_service_query_is_host_management(tmp_path):
    web_app(tmp_path, '''
    class Wmi {
        object Q() => new ManagementObjectSearcher("SELECT * FROM Win32_Service");
    }''')
    assert sev(tmp_path, "windows-host-services") == "blocker"


def test_get_services_of_remote_machine_is_not_host_management(tmp_path):
    web_app(tmp_path, 'class S { object L(string m) => ServiceController.GetServices(m); }')
    assert sev(tmp_path, "windows-host-services") is None


def test_impersonate_with_arguments_is_not_windows_impersonation(tmp_path):
    web_app(tmp_path, 'class A { void M(IUser u, Session s) { s.Impersonate(u.Id); } }')
    assert sev(tmp_path, "windows-identity-impersonation") is None
    web_app(tmp_path, 'class A { void M(System.Security.Principal.WindowsIdentity w) { using var c = w.Impersonate(); } }')
    assert sev(tmp_path, "windows-identity-impersonation") == "rewrite"


# ------------------------------------------------------------------ guards through private members

def test_pinvoke_called_only_from_a_guarded_private_method_is_guarded(tmp_path):
    # also: `=> Open()` in an expression body is a call, not a declaration of a generic-typed Open
    web_app(tmp_path, '''
    public class Native {
        [DllImport("vendor.dll")] static extern int Open();
        private int Load() => Open();
        public int Get() { if (OperatingSystem.IsWindows()) return Load(); return 0; }
    }''')
    assert sev(tmp_path, "pinvoke-vendor") is None


def test_pinvoke_called_from_an_unguarded_private_method_is_reported(tmp_path):
    web_app(tmp_path, '''
    public class Native {
        [DllImport("vendor.dll")] static extern int Open();
        private int Load() => Open();
        public int Get() => Load();
    }''')
    assert sev(tmp_path, "pinvoke-vendor") == "blocker"


def test_same_named_call_in_another_file_does_not_unguard_a_private_method(tmp_path):
    web_app(tmp_path, '''
    public class Native {
        [DllImport("vendor.dll")] static extern int Open();
        private int Load() => Open();
        public int Get() { if (OperatingSystem.IsWindows()) return Load(); return 0; }
    }''')
    write(tmp_path, "src/Web/Other.cs", "class Other { int Load() => 1; int X() => Load(); }")
    assert sev(tmp_path, "pinvoke-vendor") is None


# ------------------------------------------------------------------ ASP.NET Core with System.Web leftovers

def test_aspnetcore_app_restoring_mvc5_packages_is_not_an_mvc5_app(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.AspNet.Mvc" Version="5.2.9" />',
            tfm="net10.0")
    assert sev(tmp_path, "aspnet-mvc5") is None
    assert sev(tmp_path, "aspnet-mvc5-packages-on-core") == "info"


def test_netfx_mvc5_app_still_needs_a_rewrite(tmp_path):
    write(tmp_path, "src/Site/Site.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="Microsoft.AspNet.Mvc" Version="5.2.9" /></ItemGroup></Project>""")
    write(tmp_path, "src/Site/Web.config", "<configuration/>")
    write(tmp_path, "src/Site/Global.asax", "<%@ Application %>")
    assert sev(tmp_path, "aspnet-mvc5") == "rewrite"
    assert sev(tmp_path, "aspnet-mvc5-packages-on-core") is None


def test_own_static_named_httpcontext_current_is_not_system_web(tmp_path):
    web_app(tmp_path, 'class C { object M() => AspNetCoreHttpContext.Current; }')
    assert sev(tmp_path, "system-web-apis-in-core") is None
    web_app(tmp_path, 'class C { object M() => HttpContext.Current; }')
    assert sev(tmp_path, "system-web-apis-in-core") is not None


# ------------------------------------------------------------------ checked-in assemblies

def pe_image(cli_flags=1, target=b".NETStandard,Version=v2.0", clr=True) -> bytes:
    """A minimal PE32 image: one .text section holding a CLI header and a target-framework string."""
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HH", data, pe + 4, 0x14C, 1)          # machine, one section
    struct.pack_into("<H", data, pe + 20, 224)               # optional header size
    opt = pe + 24
    struct.pack_into("<H", data, opt, 0x10B)                 # PE32
    if clr:
        struct.pack_into("<II", data, opt + 96 + 14 * 8, 0x2008, 72)
    sh = opt + 224
    data[sh:sh + 5] = b".text"
    struct.pack_into("<IIII", data, sh + 8, 0x1000, 0x2000, 0x200, 0x200)
    struct.pack_into("<I", data, 0x208, 72)                  # cb
    struct.pack_into("<I", data, 0x208 + 16, cli_flags)
    data[0x300:0x300 + len(target)] = target
    return bytes(data)


def shipped_dll(root, image: bytes):
    web_app(root)
    p = root / "src/Web/lib/Vendor.License.dll"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(image)


def test_checked_in_netstandard_il_assembly_is_not_a_native_dll(tmp_path):
    shipped_dll(tmp_path, pe_image())
    assert sev(tmp_path, "native-dll-shipped") is None


def test_checked_in_native_or_32bit_or_netfx_dll_is_reported(tmp_path):
    for image in (pe_image(clr=False), pe_image(cli_flags=0x3),
                  pe_image(target=b".NETFramework,Version=v4.5"), b"not a pe file" * 64):
        shipped_dll(tmp_path, image)
        assert sev(tmp_path, "native-dll-shipped") == "refactor", image[:16]


# ------------------------------------------------------------------ WCF

def test_xamlx_workflow_service_is_a_system_web_app(tmp_path):
    write(tmp_path, "Svc/Svc.csproj", f"""
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup><ProjectTypeGuids>{WEB_GUID}</ProjectTypeGuids>
            <TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>
        </Project>""")
    write(tmp_path, "Svc/Order.xamlx", "<WorkflowService />")
    assert role_of(tmp_path, "Svc") == "web"


def test_config_activated_wcf_service_is_a_system_web_app(tmp_path):
    write(tmp_path, "Svc/Svc.csproj", f"""
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup><ProjectTypeGuids>{WEB_GUID}</ProjectTypeGuids>
            <TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>
        </Project>""")
    write(tmp_path, "Svc/Web.config", """<configuration><system.serviceModel>
        <serviceHostingEnvironment><serviceActivations>
          <add relativeAddress="Ball.svc" service="Ball.Service" />
        </serviceActivations></serviceHostingEnvironment></system.serviceModel></configuration>""")
    assert role_of(tmp_path, "Svc") == "web"


SERVICE_CONFIG = """<configuration><system.serviceModel><services>
    <service name="S"><endpoint binding="netTcpBinding" contract="IS" /></service>
    </services></system.serviceModel></configuration>"""


def test_corewcf_host_is_not_a_framework_wcf_server(tmp_path):
    sdk_proj(tmp_path, "Host/Host.csproj", props="<OutputType>Exe</OutputType>",
             items='<PackageReference Include="CoreWCF.NetTcp" Version="1.5.0" />')
    write(tmp_path, "Host/App.config", SERVICE_CONFIG)
    write(tmp_path, "Host/Program.cs", "class P { static void Main() { } }")
    assert sev(tmp_path, "wcf-server") is None
    assert sev(tmp_path, "wcf-nettcp-msmq") is None


def test_nettcp_on_net_framework_is_still_reported(tmp_path):
    sdk_proj(tmp_path, "Host/Host.csproj", tfm="net48", props="<OutputType>Exe</OutputType>",
             items='<Reference Include="System.ServiceModel" />')
    write(tmp_path, "Host/App.config", SERVICE_CONFIG)
    write(tmp_path, "Host/Program.cs", "class P { static void Main() { } }")
    assert sev(tmp_path, "wcf-server") == "rewrite"
    assert sev(tmp_path, "wcf-nettcp-msmq") == "rewrite"


# ------------------------------------------------------------------ Worker SDK projects

def test_worker_sdk_with_winforms_is_not_desktop(tmp_path):
    sdk_proj(tmp_path, "Scan/Scan.csproj", sdk="Microsoft.NET.Sdk.Worker", tfm="net8.0-windows",
             props="<UseWindowsForms>true</UseWindowsForms>")
    write(tmp_path, "Scan/Program.cs", "var b = Host.CreateApplicationBuilder(args); b.Services.AddHostedService<W>(); b.Build().Run();")
    assert role_of(tmp_path, "Scan") == "worker"


def test_worker_sdk_mapping_endpoints_is_web(tmp_path):
    sdk_proj(tmp_path, "Proc/Proc.csproj", sdk="Microsoft.NET.Sdk.Worker")
    write(tmp_path, "Proc/Program.cs", """
        var app = WebApplication.Create(args);
        app.UseWorkflowsApi();
        app.Run();""")
    assert role_of(tmp_path, "Proc") == "web"


def test_worker_sdk_without_endpoints_stays_worker(tmp_path):
    sdk_proj(tmp_path, "Proc/Proc.csproj", sdk="Microsoft.NET.Sdk.Worker")
    write(tmp_path, "Proc/Program.cs", "var app = WebApplication.Create(args); app.Run();")
    assert role_of(tmp_path, "Proc") == "worker"


def test_clickonce_console_exe_is_not_a_desktop_app(tmp_path):
    write(tmp_path, "Agg/Agg.csproj", """
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFrameworkVersion>v4.8</TargetFrameworkVersion>
            <PublishUrl>publish\\</PublishUrl><Install>true</Install><BootstrapperEnabled>true</BootstrapperEnabled>
            <IsWebBootstrapper>false</IsWebBootstrapper><ApplicationRevision>0</ApplicationRevision></PropertyGroup>
        </Project>""")
    write(tmp_path, "Agg/Program.cs", "class P { static void Main() { } }")
    assert role_of(tmp_path, "Agg") == "console"


# ------------------------------------------------------------------ QRCoder

def qr_app(root, version, code):
    web_app(root, code, packages=f'<PackageReference Include="QRCoder" Version="{version}" />')


def test_old_qrcoder_base64_renderer_needs_gdi(tmp_path):
    qr_app(tmp_path, "1.3.6", "class Q { string M(QRCodeData d) => new Base64QRCode(d).GetGraphic(20); }")
    assert sev(tmp_path, "pkg-qrcoder-gdi") == "refactor"


def test_new_qrcoder_base64_renderer_is_portable(tmp_path):
    qr_app(tmp_path, "1.5.1", "class Q { string M(QRCodeData d) => new Base64QRCode(d).GetGraphic(20); }")
    assert sev(tmp_path, "pkg-qrcoder-gdi") is None


def test_qrcoder_bitmap_renderer_needs_gdi_in_any_version(tmp_path):
    qr_app(tmp_path, "1.6.0", "class Q { object M(QRCodeData d) => new QRCode(d).GetGraphic(20); }")
    assert sev(tmp_path, "pkg-qrcoder-gdi") == "refactor"


def test_qrcoder_png_renderer_is_portable(tmp_path):
    qr_app(tmp_path, "1.3.6", "class Q { byte[] M(QRCodeData d) => new PngByteQRCode(d).GetGraphic(20); }")
    assert sev(tmp_path, "pkg-qrcoder-gdi") is None


# ------------------------------------------------------------------ configured option switch

def test_windows_case_of_option_switch_is_configuration(tmp_path):
    web_app(tmp_path, '''
    static class Keys {
        public static void Add(IDataProtectionBuilder b, KeyMode mode) {
            switch (mode) {
                case KeyMode.Windows:
                    b.ProtectKeysWithDpapi();
                    break;
                case KeyMode.Certificate:
                    b.ProtectKeysWithCertificate(Load());
                    break;
            }
        }
    }''')
    assert sev(tmp_path, "dpapi") is None
    assert sev(tmp_path, "cfg-windows-option-switch") == "config"
    assert rating(tmp_path) in ("A", "B")


def test_dpapi_outside_a_windows_case_is_reported(tmp_path):
    web_app(tmp_path, '''
    static class Keys {
        public static void Add(IDataProtectionBuilder b, KeyMode mode) {
            switch (mode) {
                case KeyMode.Certificate:
                    b.ProtectKeysWithDpapi();
                    break;
            }
        }
    }''')
    assert sev(tmp_path, "dpapi") == "refactor"
    assert sev(tmp_path, "cfg-windows-option-switch") is None


def test_qrcodejs_in_razor_views_is_not_qrcoder(tmp_path):
    qr_app(tmp_path, "1.8.1", "")
    write(tmp_path, "src/Web/Views/Home/Index.cshtml",
          '<script>new QRCode(document.getElementById("qr"), { text: "@Model.Uri" });</script>')
    assert sev(tmp_path, "pkg-qrcoder-gdi") is None
