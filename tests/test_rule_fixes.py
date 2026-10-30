"""Regression tests for false positives found by validating on public repositories
(nopCommerce, Umbraco 8, SmartStoreNET, ImageProcessor, eShopModernizing, Jellyfin, ...)."""
from containerizer.assess import assess
from containerizer.rules import Context, evaluate
from containerizer.scan import scan
from tests.test_engine import web_app, write


def pkg(*names: str) -> str:
    return "".join(f'<PackageReference Include="{n}" Version="1.0.0" />' for n in names)


def comp(tmp_path, code: str = "", packages: str = "", tfm: str = "net8.0"):
    web_app(tmp_path, code=code, packages=packages, tfm=tfm)
    return assess(tmp_path).components[0]


def sev(c, rid: str) -> str | None:
    return next((f.severity for f in c.findings if f.rule.id == rid), None)


def netfx_web(root, refs: str = "", files: dict | None = None) -> None:
    write(root, "src/Site/Site.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>
          <ItemGroup><Reference Include="System.Web" />{refs}</ItemGroup></Project>""")
    write(root, "src/Site/Global.asax", "<%@ Application %>")
    write(root, "src/Site/Web.config", "<configuration/>")
    for rel, text in (files or {}).items():
        write(root, f"src/Site/{rel}", text)


# ------------------------------------------------------------------ 1 same_file

def test_same_file_engine_option(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/A.cs", "class A { void M() { Assembly.LoadFrom(p); } }")
    write(tmp_path, "src/Web/B.cs", 'class B { string p = "Program Files"; }')
    repo = scan(tmp_path)
    ctx = Context(repo, repo.projects[0])
    cond = {"all": [{"code": r"Assembly\.LoadFrom"}, {"code": "Program Files"}]}
    assert evaluate(cond, ctx)[0]
    assert not evaluate({**cond, "same_file": True}, ctx)[0]
    write(tmp_path, "src/Web/B.cs", 'class B { string p = "Program Files"; void M() { Assembly.LoadFrom(p); } }')
    repo = scan(tmp_path)
    ok, ev, _ = evaluate({**cond, "same_file": True}, Context(repo, repo.projects[0]))
    assert ok and {e.file for e in ev} == {"src/Web/B.cs"}


def test_vendor_sdk_install_dir_needs_one_file(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/BindingRedirects.cs",
          "class R { void M() { AppDomain.CurrentDomain.AssemblyResolve += (s, e) => null; } }")
    write(tmp_path, "src/Web/LocalDb.cs", 'class L { string p = Environment.GetFolderPath(SpecialFolder.ProgramFiles); }')
    c = assess(tmp_path).components[0]
    assert sev(c, "vendor-sdk-install-dir") is None
    write(tmp_path, "src/Web/Vendor.cs", '''class V { void M() {
        var dir = Path.Combine(Environment.GetFolderPath(SpecialFolder.ProgramFiles), "Acme");
        Assembly.LoadFrom(Path.Combine(dir, "Acme.dll")); } }''')
    assert sev(assess(tmp_path).components[0], "vendor-sdk-install-dir") == "blocker"


# ------------------------------------------------------------------ 2 SupportedOSPlatform guard

ACL_CODE = '''
public class FilePermissionHelper {
    [SupportedOSPlatform("windows")]
    public static bool CheckPermissions(string path) {
        var security = new DirectoryInfo(path).GetAccessControl();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        return rules.Count > 0;
    }
    [SupportedOSPlatform("windows")]
    public virtual DirectorySecurity GetAccess(string path) => new DirectoryInfo(path).GetAccessControl();
}'''


def test_supported_os_platform_member_is_guarded(tmp_path):
    c = comp(tmp_path, ACL_CODE)
    assert sev(c, "efs-ntfs") is None
    assert sev(c, "supported-os-windows") is None
    assert sev(c, "supported-os-windows-member") == "info"
    assert assess(tmp_path).rating == "A"


def test_code_after_attributed_member_is_not_guarded(tmp_path):
    c = comp(tmp_path, '''
public class H {
    [SupportedOSPlatform("windows")]
    public static void Win() { Console.WriteLine("x"); }
    public static void Any(string p) { new FileInfo(p).SetAccessControl(new FileSecurity()); }
}''')
    assert sev(c, "efs-ntfs") == "refactor"


def test_supported_os_platform_on_type_stays_refactor(tmp_path):
    c = comp(tmp_path, '[SupportedOSPlatform("windows")]\npublic sealed class Tray { }')
    assert sev(c, "supported-os-windows") == "refactor"
    c = comp(tmp_path, '[assembly: SupportedOSPlatform("windows")]')
    assert sev(c, "supported-os-windows") == "refactor"


# ------------------------------------------------------------------ 3 Windows system DLLs

def test_windows_system_dlls_are_not_vendor_libraries(tmp_path):
    c = comp(tmp_path, '''class N {
        [DllImport("dbghelp.dll")] static extern bool MiniDumpWriteDump(IntPtr h);
        [DllImport("shlwapi.dll")] static extern int StrCmpLogicalW(string a, string b);
        [DllImport("credui.dll")] static extern int CredUIPromptForCredentials(IntPtr i); }''')
    assert sev(c, "pinvoke-vendor") is None
    assert sev(c, "pinvoke-kernel32") == "refactor"
    assert sev(c, "pinvoke-security") == "rewrite"
    c = comp(tmp_path, 'class N { [DllImport("dwmapi.dll")] static extern int DwmFlush(); }')
    assert sev(c, "pinvoke-vendor") is None and sev(c, "pinvoke-gui") == "blocker"
    c = comp(tmp_path, 'class N { [DllImport("AcmeScan.dll")] static extern int Scan(); }')
    assert sev(c, "pinvoke-vendor") == "blocker"


# ------------------------------------------------------------------ 4 WindowsIdentity.GetCurrent

def test_windows_identity_get_current_is_not_impersonation(tmp_path):
    c = comp(tmp_path, 'class U { string N = WindowsIdentity.GetCurrent().Name; }')
    assert sev(c, "windows-identity-impersonation") is None
    assert sev(c, "windows-identity-current") == "config"
    c = comp(tmp_path, 'class U { void M() { if (OperatingSystem.IsWindows()) {\n var g = WindowsIdentity.GetCurrent().Groups; } } }')
    assert sev(c, "windows-identity-current") is None
    c = comp(tmp_path, 'class U { void M(WindowsIdentity id) { WindowsIdentity.RunImpersonated(id.AccessToken, () => {}); } }')
    assert sev(c, "windows-identity-impersonation") == "rewrite"


# ------------------------------------------------------------------ 5 msmq

def test_msmq_needs_real_queue_use(tmp_path):
    c = comp(tmp_path)
    write(tmp_path, "src/Web/Views/QueuedEmail/List.cshtml", '<a href="@Docs.MessageQueue">docs</a>')
    assert sev(assess(tmp_path).components[0], "msmq") is None
    c = comp(tmp_path, 'class Q { void M() { var q = new MessageQueue(@".\\\\private$\\\\orders"); } }')
    assert sev(c, "msmq") == "refactor"
    c = comp(tmp_path, packages=pkg("NServiceBus.Transport.Msmq"))
    assert sev(c, "msmq") == "refactor"


# ------------------------------------------------------------------ 6 unused template references

def test_unused_template_references_are_info(tmp_path):
    netfx_web(tmp_path, '<Reference Include="System.EnterpriseServices" /><Reference Include="System.Management" />'
                        '<Reference Include="System.Windows.Forms" />',
              {"Home.cs": "public class Home { public string Index() => \"hi\"; }"})
    c = assess(tmp_path).components[0]
    assert sev(c, "enterprise-services") is None and sev(c, "enterprise-services-reference") == "info"
    assert sev(c, "wmi") is None and sev(c, "wmi-reference") == "info"
    assert sev(c, "winforms-reference-library") is None and sev(c, "winforms-reference-unused") == "info"


def test_used_references_still_flagged(tmp_path):
    netfx_web(tmp_path, '<Reference Include="System.EnterpriseServices" /><Reference Include="System.Management" />'
                        '<Reference Include="System.Windows.Forms" />',
              {"Svc.cs": '''public class Svc : ServicedComponent {
                   void M() { var s = new ManagementObjectSearcher("select * from Win32_Process");
                              System.Windows.Forms.Clipboard.SetText("x"); } }'''})
    c = assess(tmp_path).components[0]
    assert sev(c, "enterprise-services") == "rewrite"
    assert sev(c, "wmi") == "refactor"
    assert sev(c, "winforms-reference-library") == "refactor"


# ------------------------------------------------------------------ 7 msdtc

def test_plain_transaction_scope_is_info(tmp_path):
    c = comp(tmp_path, '''class D { async Task M() {
        using var tx = new TransactionScope(TransactionScopeOption.Required, TransactionScopeAsyncFlowOption.Enabled);
        await db.SaveAsync(); tx.Complete(); } }''')
    assert sev(c, "msdtc") is None and sev(c, "transaction-scope") == "info"
    c = comp(tmp_path, '''class D { void M() {
        using (var tx = new TransactionScope()) {
            using (var a = new SqlConnection(cs1)) { a.Open(); }
            using (var b = new SqlConnection(cs2)) { b.Open(); }
            tx.Complete(); } } }''')
    assert sev(c, "msdtc") == "refactor" and sev(c, "transaction-scope") is None


# ------------------------------------------------------------------ 8 wcf-server

def test_wcf_services_config_outside_service_model(tmp_path):
    c = comp(tmp_path)
    write(tmp_path, "src/Web/config/imageprocessor/security.config",
          '<security><services><service name="LocalFileImageService" type="X" /></services></security>')
    assert sev(assess(tmp_path).components[0], "wcf-server") is None
    write(tmp_path, "src/Web/Web.config", '''<configuration><system.serviceModel>
          <bindings/><services>
            <service name="Svc"><endpoint binding="basicHttpBinding" contract="ISvc" /></service>
          </services></system.serviceModel></configuration>''')
    assert sev(assess(tmp_path).components[0], "wcf-server") == "rewrite"


def test_wcf_rest_webservicehost(tmp_path):
    write(tmp_path, "src/Host/Host.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework>
          <OutputType>Exe</OutputType></PropertyGroup>
          <ItemGroup><Reference Include="System.ServiceModel.Web" /></ItemGroup></Project>""")
    write(tmp_path, "src/Host/Program.cs", '''
        public interface IApi { [WebGet(UriTemplate = "/ping")] string Ping(); }
        class P { static void Main() { var h = new WebServiceHost(typeof(Api), new Uri("http://localhost:8080")); h.Open(); } }''')
    c = assess(tmp_path).components[0]
    assert sev(c, "wcf-server") == "rewrite"


# ------------------------------------------------------------------ 9 System.Drawing

def test_system_drawing_primitives_and_lookalikes_are_fine(tmp_path):
    c = comp(tmp_path, '''using System.Drawing;
        class S { Size Thumb = new Size(100, 100); Color C = Color.Red; }''')
    assert sev(c, "system-drawing-core") is None
    write(tmp_path, "src/Web/Pdf.cs", "using iTextSharp.text; class P { Font F = new Font(Font.FontFamily.HELVETICA, 12); }")
    write(tmp_path, "src/Web/Ui.cs", "using Avalonia.Media.Imaging; class U { Bitmap B = new Bitmap(stream); }")
    assert sev(assess(tmp_path).components[0], "system-drawing-core") is None


def test_system_drawing_gdi_use_is_flagged(tmp_path):
    c = comp(tmp_path, '''using System.Drawing;
        class S { void M(Stream s) { using var bmp = new Bitmap(s); } }''')
    assert sev(c, "system-drawing-core") == "refactor"
    c = comp(tmp_path, 'class S { void M() { using var g = Graphics.FromImage(img); } }')
    assert sev(c, "system-drawing-core") == "refactor"
    c = comp(tmp_path, packages=pkg("System.Drawing.Common"))
    assert sev(c, "system-drawing-core") == "refactor"


# ------------------------------------------------------------------ 10 dataprotection-default

def _dp_repo(tmp_path, startup_code: str, lib_code: str = "") -> list[str]:
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Framework/Framework.csproj" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Web/Program.cs", "var b = WebApplication.CreateBuilder(args);\n" + startup_code +
          '\nvar app = b.Build(); app.MapGet("/healthz", () => "ok"); app.Run();')
    write(tmp_path, "src/Framework/Framework.csproj",
          '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    write(tmp_path, "src/Framework/Startup.cs", "class S { void C(IServiceCollection s) { " + lib_code + " } }")
    return [f.rule.id for f in assess(tmp_path).repo_findings]


def test_dataprotection_keys_persisted_in_library(tmp_path):
    assert "dataprotection-default" in _dp_repo(tmp_path / "a", "b.Services.AddControllersWithViews();")
    assert "dataprotection-default" not in _dp_repo(
        tmp_path / "b", "b.Services.AddControllersWithViews();",
        "s.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(\"/keys\"));")


def test_dataprotection_ignores_js_antiforgery(tmp_path):
    ids = _dp_repo(tmp_path, "")
    assert "dataprotection-default" not in ids
    write(tmp_path, "src/Web/Views/Shared/_Layout.cshtml", "<script>function addAntiForgeryToken(d) { return d; }</script>")
    write(tmp_path, "src/Web/wwwroot/js/site.js", "function addAntiForgeryToken(d) { return d; }")
    assert "dataprotection-default" not in [f.rule.id for f in assess(tmp_path).repo_findings]


# ------------------------------------------------------------------ 11 sqlserver / AD / secrets

def test_postgres_connection_string_is_not_sqlserver(tmp_path):
    web_app(tmp_path, packages=pkg("Npgsql"))
    write(tmp_path, "src/Web/appsettings.json",
          '{"ConnectionStrings": {"Db": "Server=db;Port=5432;Database=app;User Id=app"}}')
    assert sev(assess(tmp_path).components[0], "sqlserver") is None
    write(tmp_path, "src/Web/appsettings.json", '{"ConnectionStrings": {"Db": "Server=sql01,1433;Database=app"}}')
    assert sev(assess(tmp_path).components[0], "sqlserver") == "info"


def test_directory_entry_word_boundary(tmp_path):
    c = comp(tmp_path, "class C { object x = new CursorDirectoryEntry(1); }")
    assert sev(c, "active-directory-ds") is None
    c = comp(tmp_path, 'class C { object x = new DirectoryEntry("LDAP://dc"); }')
    assert sev(c, "active-directory-ds") == "refactor"


def test_secret_placeholders_are_not_secrets(tmp_path):
    web_app(tmp_path)
    for value in ("[AccessKey]", "<your-key>", "{key}", "xxxxxx", "changeme", "your-api-key"):
        write(tmp_path, "src/Web/appsettings.json", '{"ApiKey": "%s"}' % value)
        assert sev(assess(tmp_path).components[0], "secrets-in-config") is None, value
    write(tmp_path, "src/Web/appsettings.json", '{"ApiKey": "9f8e7d6c5b4a"}')
    assert sev(assess(tmp_path).components[0], "secrets-in-config") == "config"


# ------------------------------------------------------------------ 12 winrt tfm

def test_windows10_tfm_alone_is_refactor(tmp_path):
    c = comp(tmp_path, tfm="net8.0-windows10.0.19041.0")
    assert sev(c, "winrt-apis") is None and sev(c, "winrt-tfm") == "refactor"
    c = comp(tmp_path, "using Windows.Media.Ocr;\nclass O { }", tfm="net8.0-windows10.0.19041.0")
    assert sev(c, "winrt-apis") == "blocker" and sev(c, "winrt-tfm") is None


# ------------------------------------------------------------------ 13 ibm / 14 catalog / 15 wsfed / 16 ssrs

def test_db2_luw_package_is_not_ibm_i(tmp_path):
    c = comp(tmp_path, packages=pkg("Net.IBM.Data.Db2"))
    assert sev(c, "ibm-i-access") is None and sev(c, "pkg-db2-windows-package") is not None


def test_windows_only_packages_not_in_linux_catalog(tmp_path):
    from containerizer.confidence import _catalog, reset_cache
    reset_cache()
    ok, _ = _catalog()
    for name in ("Microsoft.ReportViewer.WebForms", "AjaxControlToolkit", "NServiceBus.Host",
                 "NServiceBus.Transport.Msmq"):
        assert not ok.match(name), name
    for name in ("NServiceBus", "NServiceBus.RabbitMQ", "NServiceBus.Hosting.Azure"):
        assert ok.match(name), name
    # still explained by finding rules, so they do not lower confidence on their own
    netfx_web(tmp_path, '<Reference Include="AjaxControlToolkit" /><Reference Include="Microsoft.ReportViewer.WebForms" />')
    c = assess(tmp_path).components[0]
    assert sev(c, "pkg-web-ui-suite-systemweb") and sev(c, "ssrs")
    assert not any("AjaxControlToolkit" in u or "ReportViewer" in u for u in c.uncertain)


def test_wif_is_not_reported_as_linux_ready(tmp_path):
    netfx_web(tmp_path, '<Reference Include="System.IdentityModel.Services" />')
    c = assess(tmp_path).components[0]
    assert sev(c, "adfs-wsfed-saml") is None and sev(c, "mig-wif") == "refactor"
    c = comp(tmp_path / "core", packages=pkg("Microsoft.AspNetCore.Authentication.WsFederation"))
    assert sev(c, "adfs-wsfed-saml") == "info"


def test_rdlc_with_reportviewercore_is_config(tmp_path):
    web_app(tmp_path, packages=pkg("ReportViewerCore.NETCore"))
    write(tmp_path, "src/Web/Reports/Invoice.rdlc", "<Report/>")
    c = assess(tmp_path).components[0]
    assert sev(c, "ssrs") is None and sev(c, "ssrs-reportviewercore") == "refactor"
    web_app(tmp_path)
    assert sev(assess(tmp_path).components[0], "ssrs") == "rewrite"


# ------------------------------------------------------------------ 17 ASP.NET Core on netfx

def test_aspnetcore2_on_net461_is_retarget(tmp_path):
    c = comp(tmp_path, packages=pkg("Microsoft.AspNetCore", "Microsoft.AspNetCore.Mvc"), tfm="net461")
    assert sev(c, "netfx-target") is None
    assert sev(c, "aspnetcore-on-netfx") == "refactor"
    assert c.verdict == "refactor"


# ------------------------------------------------------------------ 18 local time

def test_local_time_only_for_business_logic(tmp_path):
    c = comp(tmp_path, 'class L { void M() { log.Info($"started {DateTime.Now}"); var t = DateTime.Now - start; } }')
    assert sev(c, "os-local-timezone") is None
    c = comp(tmp_path, "class L { bool Due() => DateTime.Now.Hour >= 2 && DateTime.Today.DayOfWeek == DayOfWeek.Monday; }")
    assert sev(c, "os-local-timezone") == "info"


def test_acl_interface_declaration_is_not_acl_use(tmp_path):
    c = comp(tmp_path, "public interface IFiles { DirectorySecurity GetAccessControl(string path); }")
    assert sev(c, "efs-ntfs") is None
    c = comp(tmp_path, "class F { void M(string p) { var s = new DirectoryInfo(p).GetAccessControl(); } }")
    assert sev(c, "efs-ntfs") == "refactor"


def test_access_extension_in_mime_map_is_not_oledb(tmp_path):
    c = comp(tmp_path, 'class M { Dictionary<string, string> T = new() { {".accdb", "application/msaccess"}, {".mdb", "x"} }; }')
    assert sev(c, "oledb-odbc-access") is None
    c = comp(tmp_path, 'class M { string F = "App_Data/orders.mdb"; }')
    assert sev(c, "oledb-odbc-access") == "blocker"
