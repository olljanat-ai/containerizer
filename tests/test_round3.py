"""Round 3 regression tests: false positives and role mistakes found on the real-world corpus
(BlogEngine.NET, Squidex, BTCPay Server, BlazorHero, Duplicati, MusicStore, Exceptionless,
BugNET, WinSW, Windows-appsample-customers-orders, NorthwindTraders)."""
from containerizer.assess import assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import scan
from tests.test_engine import web_app, write
from tests.test_rule_fixes import comp, sev

RULES = load_rules()


def roles(root) -> dict[str, str]:
    repo = scan(root)
    return {p.name: classify_role(repo, p, RULES)[0] for p in repo.projects}


def proj(root, rel: str, sdk: str = "Microsoft.NET.Sdk", props: str = "", items: str = "") -> None:
    write(root, rel, f"""
        <Project Sdk="{sdk}">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework>{props}</PropertyGroup>
          <ItemGroup>{items}</ItemGroup>
        </Project>""")


def oldstyle(root, rel: str, output: str, extra: str = "") -> None:
    write(root, rel, f"""
        <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup>
            <OutputType>{output}</OutputType>
            <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>
            <PublishUrl>publish\\</PublishUrl>
            <Install>true</Install>
            <IsWebBootstrapper>false</IsWebBootstrapper>
            {extra}
          </PropertyGroup>
          <ItemGroup><Compile Include="Class1.cs" /></ItemGroup>
        </Project>""")


# ------------------------------------------------------------------ roles

def test_tools_subfolder_inside_a_project_does_not_make_it_a_tool(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Areas/Mcp/Tools/AssetTools.cs", "class AssetTools {}")
    proj(tmp_path, "tools/Gen/Gen.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "tools/Gen/Program.cs", "class P { static void Main() {} }")
    proj(tmp_path, "src/Tools/App.Tools.csproj")   # a library whose own folder is named Tools
    r = roles(tmp_path)
    assert r["Web"] == "web"
    assert r["Gen"] == "tool"
    assert r["App.Tools"] == "library"


def test_clickonce_boilerplate_in_library_and_console(tmp_path):
    oldstyle(tmp_path, "Core/Core.csproj", "Library", "<IsWebBootstrapper>true</IsWebBootstrapper>")
    write(tmp_path, "Core/Class1.cs", "public class C {}")
    oldstyle(tmp_path, "Hook/Repo.Importer.csproj", "Exe")
    write(tmp_path, "Hook/Class1.cs", "class P { static void Main() {} }")
    oldstyle(tmp_path, "Client/Client.csproj", "WinExe", "<GenerateManifests>true</GenerateManifests>")
    write(tmp_path, "Client/Class1.cs", "class P { static void Main() {} }")
    r = roles(tmp_path)
    assert r["Core"] == "library"
    assert r["Repo.Importer"] == "console"
    assert r["Client"] == "desktop"


def test_vcs_hook_executables_are_tools(tmp_path):
    oldstyle(tmp_path, "Svn/App.SubversionHooks.csproj", "Exe")
    write(tmp_path, "Svn/Class1.cs", "class P { static void Main() {} }")
    oldstyle(tmp_path, "Wh/App.Webhooks.csproj", "Exe")
    write(tmp_path, "Wh/Class1.cs", "class P { static void Main() {} }")
    r = roles(tmp_path)
    assert r["App.SubversionHooks"] == "tool"
    assert r["App.Webhooks"] == "console"


def test_dotnet_tool_msbuild_task_and_code_generator_are_tools(tmp_path):
    proj(tmp_path, "Packer/Packer.csproj", props="<OutputType>Exe</OutputType><PackAsTool>true</PackAsTool>")
    proj(tmp_path, "Tasks/App.Tasks.csproj",
         items='<PackageReference Include="Microsoft.Build.Utilities.Core" Version="17.4.0" />')
    proj(tmp_path, "Gen/Generator.csproj", props="<OutputType>Exe</OutputType>",
         items='<PackageReference Include="NSwag.CodeGeneration.TypeScript" Version="14.3.0" />')
    for d in ("Packer", "Gen"):
        write(tmp_path, f"{d}/Program.cs", "class P { static void Main() {} }")
    r = roles(tmp_path)
    assert r["Packer"] == r["App.Tasks"] == r["Generator"] == "tool"


def test_e2e_test_project_name(tmp_path):
    proj(tmp_path, "test/MusicStore.E2ETests/MusicStore.E2ETests.csproj")
    assert roles(tmp_path)["MusicStore.E2ETests"] == "test"


def test_exe_hosting_kestrel_through_a_library_is_web(tmp_path):
    proj(tmp_path, "Executables/App.Server/App.Server.csproj", props="<OutputType>Exe</OutputType>",
         items='<ProjectReference Include="../../Lib/Server/App.Server.Impl.csproj" />')
    write(tmp_path, "Executables/App.Server/Program.cs", """
        namespace App.Server.Launcher { public static class Program {
            public static int Main(string[] args) => App.Server.Program.Main(args); } }""")
    proj(tmp_path, "Executables/App.Cli/App.Cli.csproj", props="<OutputType>Exe</OutputType>",
         items='<ProjectReference Include="../../Lib/Server/App.Server.Impl.csproj" />')
    write(tmp_path, "Executables/App.Cli/Program.cs", """
        namespace App.Cli { public static class Program {
            public static int Main(string[] args) { var dto = new App.Server.StatusDto(); return 0; } } }""")
    proj(tmp_path, "Lib/Server/App.Server.Impl.csproj",
         items='<ProjectReference Include="../Web/App.Webserver.csproj" />')
    write(tmp_path, "Lib/Server/Program.cs", """
        namespace App.Server { public class StatusDto {} public static class Program {
            public static int Main(string[] args) { AppWebserver.Start(args); return 0; } } }""")
    proj(tmp_path, "Lib/Web/App.Webserver.csproj", sdk="Microsoft.NET.Sdk.Web", props="<OutputType>Library</OutputType>")
    write(tmp_path, "Lib/Web/AppWebserver.cs", """
        public static class AppWebserver { public static void Start(string[] a) {
            var b = WebApplication.CreateBuilder(a); b.Build().Run(); } }""")
    by = {c.project.name: c for c in assess(tmp_path).components}
    assert by["App.Server"].role == "web"
    assert by["App.Cli"].role == "console"


def test_aspnetcore_host_serving_only_health_checks_is_a_worker(tmp_path):
    proj(tmp_path, "Job/Job.csproj", sdk="Microsoft.NET.Sdk.Web", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "Job/Program.cs", """
        Host.CreateDefaultBuilder().ConfigureWebHostDefaults(w => w.Configure(app => {
            app.UseHealthChecks("/health"); app.UseHealthChecks("/ready"); }))
          .ConfigureServices(s => s.AddHostedService<QueueJob>()).Build().Run();""")
    assert roles(tmp_path)["Job"] == "worker"
    write(tmp_path, "Job/Api.cs", "class Api { void M(WebApplication app) { app.MapControllers(); } }")
    assert roles(tmp_path)["Job"] == "web"


# ------------------------------------------------------------------ findings

def test_own_form_model_is_not_winforms(tmp_path):
    c = comp(tmp_path, "namespace Shop.Forms; class FormsController { object M() => new Form { Fields = 1 }; }")
    assert sev(c, "winforms-in-library") is None
    c = comp(tmp_path, "using System.Windows.Forms;\nclass Dlg { object M() => new Form(); }")
    assert sev(c, "winforms-in-library") == "blocker"


def test_active_directory_needs_the_adsi_types(tmp_path):
    c = comp(tmp_path, "class S { string M(ClaimsPrincipal userPrincipal) => userPrincipal.FindFirstValue(\"sub\");"
                       " object N(Ctx context) => context.UserPrincipal.Token(); }")
    assert sev(c, "active-directory-ds") is None
    c = comp(tmp_path, "interface ISystemIO { IFileEntry DirectoryEntry(string path); }"
                       " class X { object M(ISystemIO io) => io.DirectoryEntry(\"/tmp\"); }")
    assert sev(c, "active-directory-ds") is None
    c = comp(tmp_path, "using System.DirectoryServices;\n"
                       "class L { void M(string cs) { using var de = new DirectoryEntry(cs); var s = new DirectorySearcher(de); } }")
    assert sev(c, "active-directory-ds") == "refactor"
    c = comp(tmp_path, "using System.DirectoryServices.AccountManagement;\n"
                       "class L { void M(PrincipalContext ctx) { var u = UserPrincipal.FindByIdentity(ctx, \"bob\"); } }")
    assert sev(c, "active-directory-ds") == "refactor"


def test_windows_api_sets_and_unix_libraries_are_not_vendor_sdks(tmp_path):
    c = comp(tmp_path, 'class P { [DllImport("api-ms-win-core-sysinfo-l1-2-1.dll")] static extern bool GetProductInfo(int a); }')
    assert sev(c, "pinvoke-vendor") is None and sev(c, "pinvoke-kernel32") == "refactor"
    c = comp(tmp_path, '''[SupportedOSPlatform("macOS")]
        public sealed class SleepAssertion {
            private const string IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit";
            [DllImport(IOKIT)] private static extern int IOPMAssertionRelease(uint id);
            [DllImport(CoreFoundation)] private static extern void CFRelease(IntPtr p); }''')
    assert sev(c, "pinvoke-vendor") is None
    c = comp(tmp_path, 'class U { [DllImport("/usr/lib/libutil.dylib")] static extern int openpty(); '
                       '[DllImport("libc.so.6")] static extern int geteuid(); }')
    assert sev(c, "pinvoke-vendor") is None
    c = comp(tmp_path, '''class V { void M() { if (OperatingSystem.IsWindows())
                                   Scan(); }
        [SupportedOSPlatform("windows")] [DllImport("AcmeScan.dll")] static extern int Scan(); }''')
    assert sev(c, "pinvoke-vendor") is None
    c = comp(tmp_path, 'class N { [DllImport("AcmeScan.dll")] static extern int Scan(); }')
    assert sev(c, "pinvoke-vendor") == "blocker"


def test_supported_os_platform_after_dllimport_counts(tmp_path):
    c = comp(tmp_path, '''class U {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        [SupportedOSPlatform("windows")]
        static extern bool GetDiskFreeSpaceEx(string d, out ulong a, out ulong t, out ulong f); }''')
    assert sev(c, "pinvoke-kernel32") is None


def test_early_return_guard(tmp_path):
    c = comp(tmp_path, '''class R {
        public static bool Check() {
            if (!OperatingSystem.IsWindows())
                return false;
            var a = 1;
            var b = 2;
            var c = 3;
            var d = 4;
            using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            return k != null;
        } }''')
    assert sev(c, "registry") is None
    c = comp(tmp_path, '''class R {
        public static bool Check() {
            if (!OperatingSystem.IsWindows())
                return false;
            return true;
        }
        // the plain positional guard looks back six lines; keep this method out of that window
        static int A() => 1;
        static int B() => 2;
        static int C() => 3;
        static int D() => 4;
        public static object Other() => Registry.GetValue("HKEY_LOCAL_MACHINE\\\\X", "v", null);
        }''')
    assert sev(c, "registry") == "refactor"


def test_private_helper_type_used_only_behind_a_guard(tmp_path):
    helper = '''
        private class PrivilegeChecker {
            [DllImport("advapi32.dll", SetLastError = true)]
            static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
            public static bool TryEnable(string p) => OpenProcessToken(IntPtr.Zero, 0, out _);
        }'''
    c = comp(tmp_path, '''class PermissionHelper {
        public static bool HasBackupPrivilege() {
            if (OperatingSystem.IsWindows())
                return PrivilegeChecker.TryEnable("SeBackupPrivilege");
            return false;
        }''' + helper + "}")
    assert sev(c, "pinvoke-security") is None
    c = comp(tmp_path, '''class PermissionHelper {
        public static bool HasBackupPrivilege() => PrivilegeChecker.TryEnable("SeBackupPrivilege");
        ''' + helper + "}")
    assert sev(c, "pinvoke-security") == "rewrite"


def test_cmd_string_constant_is_not_a_process_start(tmp_path):
    c = comp(tmp_path, 'class F { public const string CommandLine = "cmd"; void M(string cmd) { '
                       'if (cmd == null) throw new ArgumentNullException("cmd"); var d = "Cmd" + "/"; } }')
    assert sev(c, "process-start-exe") is None
    c = comp(tmp_path, 'class F { void M() { var p = new ProcessStartInfo { FileName = "cmd", Arguments = "/c ver" }; } }')
    assert sev(c, "process-start-exe") == "refactor"
    c = comp(tmp_path, 'class F { void M() { Run("powershell", "-NoProfile -Command Get-Volume"); } }')
    assert sev(c, "process-start-exe") == "refactor"


def test_certificate_store_in_configuration(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.Production.json",
          '{"IdentityServer": {"Key": {"Type": "Store", "StoreName": "My", "StoreLocation": "CurrentUser", "Name": "CN=x"}}}')
    assert sev(assess(tmp_path).components[0], "cert-store") == "config"


def test_connection_string_from_a_constants_class(tmp_path):
    c = comp(tmp_path, '''class S { void M(IServiceCollection s) {
        s.AddDbContext<Ctx>(o => o.UseSqlServer(
            Constants.SqlAzureConnectionString,
            x => x.EnableRetryOnFailure())); } }''')
    assert sev(c, "conn-string-compiled-in") == "refactor"
    c = comp(tmp_path, 'class S { void M(IServiceCollection s, IConfiguration c) { '
                       's.AddDbContext<Ctx>(o => o.UseSqlServer(c.GetConnectionString("Db"))); } }')
    assert sev(c, "conn-string-compiled-in") is None
