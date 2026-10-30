"""Round 6 regression tests from the real-world corpus (rw4-*): target-framework conditions on
MSBuild items, indirect OS guards (helpers, if/else blocks, guarded callers), `#if` branches the
project's TFMs never compile, and role fixes (run-once hosted services, web-application plugins,
Web Site projects, front-end builds into a .NET project, build/dev tool projects)."""
from containerizer.assess import _closure, assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import (_tfm_vars, eval_condition, nearest_tfms, preprocessor_symbol, scan,
                                strip_inactive_branches)
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


def web_with_lib(tmp_path, lib_code: str, lib_items: str = "", lib_tfm: str = "net8.0", web_code: str = "") -> None:
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Lib/Lib.csproj" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Web/Program.cs", "var app = WebApplication.CreateBuilder(args).Build(); Lib.Api.Run(); app.Run();\n" + web_code)
    write(tmp_path, "src/Lib/Lib.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFrameworks>{lib_tfm}</TargetFrameworks></PropertyGroup>
          {lib_items}
        </Project>""")
    write(tmp_path, "src/Lib/Api.cs", "namespace Lib { public static class Api { public static void Run() { Native.Go(); } } }\n" + lib_code)


# ------------------------------------------------------------------ 1 TFM conditions on items

def test_condition_evaluation_per_tfm():
    net8, win, fx = _tfm_vars("net8.0", True), _tfm_vars("net7.0-windows", True), _tfm_vars("net472", True)
    assert [eval_condition("'$(TargetFramework)' == 'net472'", v) for v in (net8, fx)] == [False, True]
    assert eval_condition("$([MSBuild]::GetTargetPlatformIdentifier('$(TargetFramework)')) == 'windows'", win) is True
    assert eval_condition("$(TargetFramework.Contains('-windows'))", net8) is False
    assert eval_condition("'$(TargetFrameworkIdentifier)' == '.NETFramework'", fx) is True
    # anything that is not the target framework stays unknown, so the item is kept
    assert eval_condition("'$(Configuration)' == 'Debug'", net8) is None
    assert eval_condition("Exists('x.props') and '$(TargetFramework)' == 'net472'", net8) is False
    assert eval_condition("Exists('x.props') and '$(TargetFramework)' == 'net472'", fx) is None
    assert nearest_tfms(["net8.0"], ["netstandard2.0", "net6.0", "net472"]) == ["net6.0"]
    assert nearest_tfms(["net48"], ["netstandard2.0", "net8.0"]) == ["netstandard2.0"]


def test_netfx_only_items_of_a_multitargeted_library_do_not_reach_a_core_consumer(tmp_path):
    # systemweb-adapters: Aspire.Microsoft.AspNetCore.SystemWebAdapters.csproj:19-24
    web_with_lib(tmp_path, "namespace Lib { static class Native { public static void Go() {} } }", lib_tfm="net8.0;net472", lib_items="""
        <ItemGroup Condition=" '$(TargetFramework)' == 'net472' ">
          <Reference Include="System.Web" />
          <ProjectReference Include="../Fx/Fx.csproj" />
        </ItemGroup>""")
    write(tmp_path, "src/Fx/Fx.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net472</TargetFramework></PropertyGroup>
          <ItemGroup><Reference Include="System.Web" /></ItemGroup></Project>""")
    write(tmp_path, "src/Fx/Mod.cs", "using System.Web; public class Mod : IHttpModule { }")
    repo = scan(tmp_path)
    lib = next(p for p in repo.projects if p.name == "Lib")
    assert lib.references == ["System.Web"] and lib.tfm_items[("reference", "System.Web")] == {"net472"}
    web = next(p for p in repo.projects if p.name == "Web")
    assert [p.name for p in _closure(repo, web)] == ["Lib"]
    assert _closure(repo, web)[0].references == []
    assert sev(tmp_path, "aspnet-mvc5", "Web") is None
    # a single-TFM project drops an item no TFM of it gets
    proj(tmp_path, "src/One/One.csproj", items='</ItemGroup><ItemGroup Condition="\'$(TargetFramework)\' == \'net48\'">'
                                              '<Reference Include="System.Web" />')
    assert next(p for p in scan(tmp_path).projects if p.name == "One").references == []


def test_compile_remove_per_tfm(tmp_path):
    # Samples.ServiceDefaults: <Compile Remove="Framework/**/*" /> for the $(SAMPLES_TFM) build
    web_with_lib(tmp_path, "namespace Lib { static class Native { public static void Go() {} } }", lib_tfm="net481;$(SAMPLES_TFM)",
                 lib_items="""<PropertyGroup><SAMPLES_TFM>net8.0</SAMPLES_TFM></PropertyGroup>
        <ItemGroup Condition=" '$(TargetFramework)' == '$(SAMPLES_TFM)' "><Compile Remove="Framework/**/*" /></ItemGroup>""")
    write(tmp_path, "src/Lib/Framework/Cache.cs", "using System.Web.Caching; namespace Lib { public class C { } }")
    repo = scan(tmp_path)
    lib = next(p for p in repo.projects if p.name == "Lib")
    assert lib.tfms == ["net481", "net8.0"]
    view = lib.view(["net8.0"])
    assert not any(f.name == "Cache.cs" for f in view.files) and any(f.name == "Cache.cs" for f in lib.files)


# ------------------------------------------------------------------ 2 indirect guards

NATIVE = '''
namespace Lib {
internal static class Native {
    [DllImport("aspnetcorev2_inprocess.dll")]
    private static extern int http_get_application_properties(ref int data);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string name);
    internal static int Properties()
    {
        int d = 0;
        http_get_application_properties(ref d);
        return d;
    }
    public static void Go() { Other.Configure(); }
    // the helper lives below its callers, out of reach of the "few lines after a check" window
    internal static bool IsModuleLoaded()
        => OperatingSystem.IsWindows() && GetModuleHandle("aspnetcorev2_inprocess.dll") != IntPtr.Zero;
}
static class Other {
    public static void Configure()
    {
        var x = 1;
        if (Native.IsModuleLoaded())
        {
            var p = Native.Properties();
        }
    }
}
}'''


def test_dllimport_called_only_behind_an_os_check_helper(tmp_path):
    # systemweb-adapters CoreServices/NativeMethods.cs:19-24, HostingRuntimeExtensions.cs:73
    web_with_lib(tmp_path, NATIVE)
    assert sev(tmp_path, "pinvoke-vendor") is None
    # the same call without the helper check is a finding
    web_with_lib(tmp_path, NATIVE.replace("if (Native.IsModuleLoaded())", "if (x == 1)"))
    assert sev(tmp_path, "pinvoke-vendor") == "blocker"


def test_helper_that_is_not_only_an_os_check_does_not_guard(tmp_path):
    web_with_lib(tmp_path, NATIVE.replace("=> OperatingSystem.IsWindows() && GetModuleHandle",
                                          "=> OperatingSystem.IsWindows() || GetModuleHandle"))
    assert sev(tmp_path, "pinvoke-vendor") == "blocker"


def test_ternary_on_a_runtime_info_property_of_a_referenced_project(tmp_path):
    # Smartstore LightningCssTransformer.cs:160 / RuntimeInfo.cs:71
    web_with_lib(tmp_path, '''namespace Lib {
        public class RuntimeInfo { public bool IsWindows { get; } = RuntimeInformation.IsOSPlatform(OSPlatform.Windows); }
        static class Native { public static void Go() {} } }''',
                 web_code='''class T { string Exe(RuntimeInfo info) {
            var fileName = info.IsWindows ? "lightningcss.exe" : "lightningcss";
            return fileName; } }''')
    assert sev(tmp_path, "process-start-exe") is None


def test_if_and_else_blocks_on_os_checks(tmp_path):
    body = '''
        if (!OperatingSystem.IsWindows())
        {
            Log("not supported");
        }
        else
        {
            var a = 1;
            var b = 2;
            var c = 3;
            var d = 4;
            var e = 5;
            var f = 6;
            EventLog.WriteEntry("app", "started");
        }'''
    web_app(tmp_path, "class L { void M() {" + body + "} }")
    assert sev(tmp_path, "eventlog-write") is None
    web_app(tmp_path, "class L { void M() {" + body.replace("!OperatingSystem.IsWindows()", "OperatingSystem.IsWindows()") + "} }")
    assert sev(tmp_path, "eventlog-write") is not None


# ------------------------------------------------------------------ 3 #if branches

def test_preprocessor_branches_the_tfms_never_compile():
    src = "#if NETCF || NETSTANDARD\n[DllImport(\"CoreDll.dll\")]\n#else\n[DllImport(\"Kernel32.dll\")]\n#endif\n" \
          "#if MY_FEATURE\nfeature\n#endif\n#if NET8_0_OR_GREATER\ncore\n#else\nfx\n#endif\n"
    old = strip_inactive_branches(src, ["net48"], False, set())
    assert "CoreDll" not in old and "Kernel32" in old and "feature" in old and "core" not in old
    multi = strip_inactive_branches(src, ["net8.0", "net472"], True, set())
    assert "core" in multi and "fx" in multi and "CoreDll" not in multi
    assert strip_inactive_branches(src, ["netstandard2.0"], True, set()).count("CoreDll") == 1
    assert preprocessor_symbol("MONO", "net48", False, {"MONO"}) is None       # defined by the project
    assert len(old.split("\n")) == len(src.split("\n"))                        # line numbers kept


def test_vendored_netcf_dllimport_does_not_count_for_a_net48_build(tmp_path):
    # DNN vendored log4net OutputDebugStringAppender.cs:104
    oldstyle(tmp_path, "Log/Log.csproj", "Library", "<DefineConstants>TRACE;NET_2_0</DefineConstants>")
    write(tmp_path, "Log/Class1.cs", '''
        class OutputDebugStringAppender {
        #if NETCF || NETSTANDARD
            [DllImport("CoreDll.dll")]
        #else
            [DllImport("Kernel32.dll")]
        #endif
            protected static extern void OutputDebugString(string message);
        }''')
    a = assess(tmp_path, RULES)
    lib = next(c for c in a.libraries if c.name == "Log")
    assert "pinvoke-vendor" not in {f.rule.id for f in lib.findings}


# ------------------------------------------------------------------ 4 Umbraco 13

SYSTEM_LOCK = '''namespace Lib {
public class SystemLock {
    private readonly Semaphore _s;
    public SystemLock(string name) { _s = new Semaphore(1, 1, name); }
}
public class SemaphoreLock {
    private readonly SystemLock _lock;
    public SemaphoreLock(string id)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException("Windows only");
        }
        _lock = new SystemLock("UMBRACO-" + id);
    }
}
static class Native { public static void Go() { var l = new SemaphoreLock("x"); } }
}'''


def test_named_semaphore_only_constructed_behind_an_early_exit(tmp_path):
    # Umbraco.Core SystemLock.cs:52, MainDomSemaphoreLock.cs:23
    web_with_lib(tmp_path, SYSTEM_LOCK)
    assert sev(tmp_path, "os-named-sync-objects") is None
    web_with_lib(tmp_path, SYSTEM_LOCK, web_code='class X { object L = new Lib.SystemLock("global"); }')
    assert sev(tmp_path, "os-named-sync-objects") == "refactor"


def test_localhost_null_fallback_and_localdb_attach_path(tmp_path):
    web_app(tmp_path, '''class C {
        Uri _u; Uri RequestUrl;
        public Uri OriginalRequestUrl => _u ??= RequestUrl ?? new Uri("http://localhost");
        string Cs(string name) => new SqlConnectionStringBuilder {
            AttachDBFilename = @$"{DataDirectory}\\{name}.mdf" }.ConnectionString;
    }''')
    assert sev(tmp_path, "cfg-localhost-endpoint-in-code") is None
    assert sev(tmp_path, "os-backslash-path-join") is None
    web_app(tmp_path, 'class C { HttpClient H = new HttpClient { BaseAddress = new Uri("http://localhost:5001") }; }')
    assert sev(tmp_path, "cfg-localhost-endpoint-in-code") == "refactor"


def test_runtime_library_with_msbuild_package_is_not_a_tool(tmp_path):
    # Umbraco.Infrastructure references Microsoft.Build.Tasks.Core for in-memory model compilation
    web_app(tmp_path)
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Infra/Infra.csproj" /></ItemGroup></Project>""")
    proj(tmp_path, "src/Infra/Infra.csproj", items='<PackageReference Include="Microsoft.Build.Tasks.Core" Version="17.8.3" />')
    write(tmp_path, "src/Infra/Compiler.cs", "class ModelsCompiler { void Build() { } }")
    proj(tmp_path, "build/Tasks/Tasks.csproj", items='<PackageReference Include="Microsoft.Build.Utilities.Core" Version="17.8.3" />')
    write(tmp_path, "build/Tasks/Copy.cs", "public class CopyModule : Microsoft.Build.Utilities.Task { }")
    write(tmp_path, "src/Web/Startup.cs", "class S { }")
    proj(tmp_path, "src/Host2/Host2.csproj", items='<ProjectReference Include="../../build/Tasks/Tasks.csproj" />')
    r = roles(tmp_path)
    assert r["Infra"] == "library" and r["Tasks"] == "tool"


# ------------------------------------------------------------------ 5 Smartstore

def test_backslash_join_into_a_normalising_virtual_file_system(tmp_path):
    fs = '''namespace Lib {
        public class LocalFileSystem {
            public IFile GetFile(string subpath) => null;
            static ReadOnlySpan<char> Transform(ReadOnlySpan<char> value) {
                var d = new char[value.Length];
                for (var i = 0; i < value.Length; i++) d[i] = value[i] == '\\\\' ? '/' : value[i];
                return d; } }
        static class Native { public static void Go() {} } }'''
    call = 'class M { async Task D(LocalFileSystem root, string name) { var backup = await root.GetFileAsync(BackupDir + "\\\\" + name); } }'
    web_with_lib(tmp_path, fs, web_code=call)
    assert sev(tmp_path, "os-backslash-path-join") is None
    web_with_lib(tmp_path, "namespace Lib { static class Native { public static void Go() {} } }", web_code=call)
    assert sev(tmp_path, "os-backslash-path-join") == "refactor"


def test_nuke_cake_and_bullseye_build_projects_are_tools(tmp_path):
    proj(tmp_path, "src/Smartstore.Build/Smartstore.Build.csproj", props="<OutputType>Exe</OutputType>",
         items='<PackageReference Include="Nuke.Common" Version="9.0.4" />')
    write(tmp_path, "src/Smartstore.Build/Build.cs", "class Build : NukeBuild { public static int Main() => Execute<Build>(x => x.Compile); }")
    proj(tmp_path, "build/Cake/Cake.csproj", props="<OutputType>Exe</OutputType>",
         items='<PackageReference Include="Cake.Frosting" Version="5.0.0" />')
    write(tmp_path, "build/Cake/Program.cs", "return new CakeHost().Run(args);")
    proj(tmp_path, "src/Batch/Batch.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Batch/Program.cs", "class P { static void Main() {} }")
    r = roles(tmp_path)
    assert r["Smartstore.Build"] == r["Cake"] == "tool" and r["Batch"] == "console"


# ------------------------------------------------------------------ 6 System.Drawing.Common

def test_bare_system_drawing_package_is_info(tmp_path):
    pkg = '<PackageReference Include="System.Drawing.Common" Version="8.0.0" />'
    web_app(tmp_path, "class C { }", packages=pkg)
    assert sev(tmp_path, "system-drawing-core") is None
    assert sev(tmp_path, "system-drawing-package") == "info"
    web_app(tmp_path, "using System.Drawing;\nclass C { void M(Bitmap b) { b.Save(\"x.png\"); } }", packages=pkg)
    assert sev(tmp_path, "system-drawing-core") == "refactor"


# ------------------------------------------------------------------ 7 run-to-completion hosted service

def test_hosted_service_that_stops_the_application_is_a_job(tmp_path):
    proj(tmp_path, "shared/Keycloak.DbMigrator/Keycloak.DbMigrator.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "shared/Keycloak.DbMigrator/Program.cs",
          "var b = Host.CreateApplicationBuilder(args); b.Services.AddHostedService<DbMigratorHostedService>(); b.Build().Run();")
    write(tmp_path, "shared/Keycloak.DbMigrator/DbMigratorHostedService.cs", '''
        public class DbMigratorHostedService : IHostedService
        {
            public async Task StartAsync(CancellationToken cancellationToken)
            {
                using (var application = Create())
                {
                    await application.MigrateAsync(cancellationToken);
                    _hostApplicationLifetime.StopApplication();
                }
            }

            public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        }''')
    # a long-running worker that stops the host only on a fatal error stays a worker
    proj(tmp_path, "src/Worker/Worker.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Worker/Program.cs", "var b = Host.CreateApplicationBuilder(args); b.Services.AddHostedService<W>();")
    write(tmp_path, "src/Worker/W.cs", '''
        public class W : BackgroundService
        {
            protected override async Task ExecuteAsync(CancellationToken ct)
            {
                try { while (!ct.IsCancellationRequested) { await Work(ct); } }
                catch (Exception) { _lifetime.StopApplication(); }
            }
        }''')
    r = roles(tmp_path)
    assert r["Keycloak.DbMigrator"] == "console" and r["Worker"] == "worker"


# ------------------------------------------------------------------ 8 web-application plugins

def test_page_project_built_against_a_host_web_app_is_a_plugin(tmp_path):
    guid = "<ProjectTypeGuids>{349c5851-65df-11da-9384-00065b846f21};{fae04ec0-301f-11d3-bf4b-00c04f79efbc}</ProjectTypeGuids>"
    oldstyle(tmp_path, "Web/mojoPortal.Web.csproj", "Library", guid)
    for f in ("Global.asax", "Web.config", "Default.aspx"):
        write(tmp_path, f"Web/{f}", "<%@ Page %>" if f.endswith("aspx") else "<configuration/>")
    oldstyle(tmp_path, "Features.UI/Features.UI.csproj", "Library",
             guid + '</PropertyGroup><ItemGroup><ProjectReference Include="..\\Web\\mojoPortal.Web.csproj" /></ItemGroup><PropertyGroup>')
    write(tmp_path, "Features.UI/Web.config", "<configuration/>")
    write(tmp_path, "Features.UI/Blog/ViewPost.aspx", "<%@ Page %>")
    # a site of its own (pages + Web.config, no host reference) stays web
    oldstyle(tmp_path, "Admin/Admin.csproj", "Library", guid)
    write(tmp_path, "Admin/Web.config", "<configuration/>")
    write(tmp_path, "Admin/Default.aspx", "<%@ Page %>")
    r = roles(tmp_path)
    assert r["mojoPortal.Web"] == "web" and r["Features.UI"] == "library" and r["Admin"] == "web"


# ------------------------------------------------------------------ 9 Rock RMS

def test_web_site_project_from_the_solution(tmp_path):
    proj(tmp_path, "Rock/Rock.csproj")
    write(tmp_path, "Rock/Entity.cs", "namespace Rock { public class Entity { } }")
    write(tmp_path, "Rock.sln", '''
Microsoft Visual Studio Solution File, Format Version 12.00
Project("{E24C65DC-7377-472B-9ABA-BC803B73C61A}") = "RockWeb", "RockWeb\\", "{E43B5D55-BED0-4E74-BF97-9327F9A9D656}"
\tProjectSection(ProjectDependencies) = postProject
\t\t{11111111-1111-1111-1111-111111111111} = {11111111-1111-1111-1111-111111111111}
\tEndProjectSection
\tProjectSection(WebsiteProperties) = preProject
\t\tTargetFrameworkMoniker = ".NETFramework,Version%3Dv4.7.2"
\t\tProjectReferences = ""
\tEndProjectSection
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Rock", "Rock\\Rock.csproj", "{11111111-1111-1111-1111-111111111111}"
EndProject
''')
    write(tmp_path, "RockWeb/Global.asax", '<%@ Application Language="C#" %>')
    write(tmp_path, "RockWeb/web.config", "<configuration/>")
    write(tmp_path, "RockWeb/Default.aspx", "<%@ Page %>")
    write(tmp_path, "Rock.JavaScript.Obsidian/package.json",
          '{"name": "obsidian", "scripts": {"copy": "copyfiles -u 2 \\"dist/System/*\\" \\"../RockWeb/Obsidian/\\""},'
          ' "dependencies": {"vue": "3.4.0"}}')
    write(tmp_path, "Rock.JavaScript.Obsidian/Rock.JavaScript.Obsidian.esproj", '<Project Sdk="Microsoft.VisualStudio.JavaScript.Sdk/1.0.586930" />')
    write(tmp_path, "Standalone/package.json", '{"name": "standalone", "dependencies": {"react": "18.0.0"}}')
    repo = scan(tmp_path)
    site = next(p for p in repo.projects if p.name == "RockWeb")
    assert site.tfms == ["net472"] and site.rel_dir == "RockWeb" and [r.name for r in site.project_refs] == ["Rock.csproj"]
    r = roles(tmp_path)
    assert r["RockWeb"] == "web" and r["obsidian"] == "spa-assets" and r["standalone"] == "spa"
    a = assess(tmp_path, RULES)
    assert next(c for c in a.components if c.name == "RockWeb").verdict == "rewrite"


def test_dev_tools_folders_and_code_generators_are_tools(tmp_path):
    for d in ("Dev Tools/BlockGenerator", "DevTools/Seeder2", "BuildTools/LicenseUpdater"):
        name = d.split("/")[-1]
        proj(tmp_path, f"{d}/{name}.csproj", props="<OutputType>WinExe</OutputType><UseWPF>true</UseWPF>")
    oldstyle(tmp_path, "Rock.CodeGeneration/Rock.CodeGeneration.csproj", "WinExe")
    oldstyle(tmp_path, "Rock.CheckScanner/Rock.CheckScanner.csproj", "WinExe")
    proj(tmp_path, "src/Web/Areas/Tools/Web.Tools.csproj")
    r = roles(tmp_path)
    assert r["BlockGenerator"] == r["Seeder2"] == r["LicenseUpdater"] == r["Rock.CodeGeneration"] == "tool"
    assert r["Rock.CheckScanner"] == "desktop" and r["Web.Tools"] == "library"


# ------------------------------------------------------------------ 10 Duplicati

def test_windows_only_type_used_only_behind_os_checks(tmp_path):
    lib = '''namespace Lib {
        [SupportedOSPlatform("windows")]
        public static class RegistryUtility { public static string Get(string k) => k; }
        static class Native { public static void Go() {
            if (OperatingSystem.IsWindows())
            {
                var path = RegistryUtility.Get("SOFTWARE\\\\GnuPG");
            }
        } } }'''
    web_with_lib(tmp_path, lib)
    assert sev(tmp_path, "supported-os-windows") is None
    assert sev(tmp_path, "supported-os-windows-member") == "info"
    web_with_lib(tmp_path, lib, web_code='class U { string P = Lib.RegistryUtility.Get("x"); }')
    assert sev(tmp_path, "supported-os-windows") == "refactor"


def test_local_named_pipes_on_modern_dotnet_are_info(tmp_path):
    web_app(tmp_path, 'class P { void M() { using var pipe = new NamedPipeServerStream("ctl", PipeDirection.InOut); } }')
    assert sev(tmp_path, "named-pipes") is None and sev(tmp_path, "named-pipes-local") == "info"
    web_app(tmp_path, 'class P { void M() { var c = new NamedPipeClientStream("fileserver01", "ctl", PipeDirection.InOut); } }')
    assert sev(tmp_path, "named-pipes") == "refactor"
