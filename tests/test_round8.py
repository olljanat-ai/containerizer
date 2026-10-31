"""Round 8: Paket-managed projects (paket.references + paket.lock) expose their packages to rules."""
from containerizer.scan import scan
from tests.test_engine import write
from tests.test_round7 import sev


def paket_app(root):
    write(root, "paket.lock", """\
        NUGET
          remote: https://api.nuget.org/v3/index.json
            CrystalReports.Engine (13.0.4000)
            Newtonsoft.Json (13.0.1)
        """)
    write(root, "src/App/paket.references", """\
        // runtime packages
        Newtonsoft.Json
        CrystalReports.Engine
        File: Helpers.fs
        group Build
          Fake.Core.Target
        """)
    write(root, "src/App/App.fsproj", """\
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
        </Project>
        """)


def test_paket_references_become_packages(tmp_path):
    paket_app(tmp_path)
    pkgs = scan(tmp_path).projects[0].packages
    assert pkgs["Newtonsoft.Json"] == "13.0.1"
    assert pkgs["CrystalReports.Engine"] == "13.0.4000"
    assert "Fake.Core.Target" not in pkgs  # group Build is tooling
    assert "File" not in pkgs and "group" not in pkgs and "Helpers.fs" not in pkgs


def test_paket_package_triggers_rule(tmp_path):
    paket_app(tmp_path)
    assert sev(tmp_path, "pkg-crystal-reports") is not None


# ------------------------------------------------------------------ development-only branches

def comp(root, code):
    from tests.test_engine import web_app
    web_app(root, code=code)
    return root


def test_backslash_join_in_development_branch_is_not_reported(tmp_path):
    c = comp(tmp_path, '''class M { void Load(IWebHostEnvironment env, string root) {
        if (env.IsDevelopment())
        {
            var src = Path.GetFullPath(Path.Combine(root, @"..\\Modules\\src"));
            Directory.CreateDirectory(src);
        }
    } }''')
    assert sev(c, "os-backslash-path-join") is None


def test_backslash_join_in_production_branch_is_reported(tmp_path):
    c = comp(tmp_path, '''class M { void Load(IWebHostEnvironment env, string root) {
        if (!env.IsDevelopment())
        {
            var src = Path.GetFullPath(Path.Combine(root, @"..\\Modules\\src"));
            Directory.CreateDirectory(src);
        }
    } }''')
    assert sev(c, "os-backslash-path-join") == "refactor"


def test_replace_to_backslash_for_own_normalising_file_system(tmp_path):
    fs = '''public class PhysicalFileSystem { string Full(string p) => p.Replace('\\\\', Path.DirectorySeparatorChar); }'''
    use = '''class P { void Pack(IEnumerable<string> v) { var views = v.Select(x => x.RelativePath.Replace('/', '\\\\'));
        Package(views, _fileSystems.PartialsFileSystem); } }'''
    c = comp(tmp_path, fs + "\n" + use)
    assert sev(c, "os-backslash-path-join") is None
    c = comp(tmp_path / "plain", use + "\nclass Q { string F(string dir) => dir + \"/x\"; }")
    assert sev(c, "os-backslash-path-join") == "refactor"


def test_dbghelp_minidump_is_info(tmp_path):
    c = comp(tmp_path, '''static class MiniDump {
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump")]
        static extern bool Write(IntPtr p, uint id, SafeHandle f, int t, IntPtr e, IntPtr u, IntPtr c);
        public static bool Dump(SafeHandle f) => Write(IntPtr.Zero, 0, f, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero); }''')
    assert sev(c, "pinvoke-dbghelp") == "info"
    assert sev(c, "pinvoke-kernel32") is None and sev(c, "pinvoke-vendor") is None


# ------------------------------------------------------------------ Duplicati: guarded Windows branches

def test_cim_session_only_behind_os_check_is_not_reported(tmp_path):
    from tests.test_vendor_packages import ids_of, pkg
    mmi = pkg("Microsoft.Management.Infrastructure")
    used = "class W { void Q() { using var s = CimSession.Create(null); } }"
    assert "pkg-mmi-cim" in ids_of(tmp_path / "a", code=used, packages=mmi)
    guarded = "class W { void Q() { if (!OperatingSystem.IsWindows()) return; using var s = CimSession.Create(null); } }"
    assert "pkg-mmi-cim" not in ids_of(tmp_path / "b", code=guarded, packages=mmi)


def test_unbraced_os_if_spanning_lines_guards_its_statement(tmp_path):
    c = comp(tmp_path, '''
[SupportedOSPlatform("windows")]
public class WinPower { public WinPower() { } }
public static class Power {
    public static object Get(int kind)
    {
        if (OperatingSystem.IsWindows())
            return kind switch
            {
                1 => new WinPower(),
                2 => Other(),
                3 => Other(),
                4 => Other(),
                5 => Other(),
                _ => new WinPower()
            };
        return null;
    }
    static object Other() => null;
}''')
    assert sev(c, "supported-os-windows") is None


def test_unbraced_os_if_ends_at_its_statement(tmp_path):
    c = comp(tmp_path, '''
[SupportedOSPlatform("windows")]
public class WinPower { public WinPower() { } }
public static class Power {
    public static object Get(int kind)
    {
        if (OperatingSystem.IsWindows())
            Log("windows");
        var a = 1;
        var b = 2;
        var c = 3;
        var d = 4;
        var e = 5;
        var f = 6;
        return new WinPower();
    }
    static void Log(string s) { }
}''')
    assert sev(c, "supported-os-windows") == "refactor"


def test_microsoft_win32_namespace_is_not_a_use_of_own_win32_class(tmp_path):
    c = comp(tmp_path, '''
namespace App.Util {
    [SupportedOSPlatform("windows")]
    public static class Win32 { [DllImport("kernel32.dll")] public static extern bool Beep(uint f, uint d); }
    public static class Use {
        public static void A() { if (OperatingSystem.IsWindows()) Win32.Beep(1, 1); }
        public static void B() { using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("x"); }
        static Win32.Hint field;
    }
}''')
    assert sev(c, "supported-os-windows") is None


def test_windows_only_enum_is_not_windows_code(tmp_path):
    c = comp(tmp_path, '[SupportedOSPlatform("windows")]\n[Flags]\npublic enum WinAttrs : uint { A = 1 }\n'
                       'class U { uint M() => (uint)WinAttrs.A; }')
    assert sev(c, "supported-os-windows") is None


def test_windows_companion_executable_is_a_tool(tmp_path):
    from tests.test_round7 import roles
    write(tmp_path, "src/App.Server/App.Server.csproj", """\
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>
        <TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>
        """)
    write(tmp_path, "src/App.Server/Program.cs", "class P { static void Main() { } }")
    write(tmp_path, "src/App.WindowsModulesLoader/App.WindowsModulesLoader.csproj", """\
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>
        <TargetFramework>net10.0-windows10.0.17763.0</TargetFramework></PropertyGroup></Project>
        """)
    write(tmp_path, "src/App.WindowsModulesLoader/Program.cs", "class P { static void Main() { } }")
    assert roles(tmp_path)["App.WindowsModulesLoader"] == "tool"


def test_windows_only_executable_alone_is_not_a_tool(tmp_path):
    from tests.test_round7 import roles
    write(tmp_path, "src/App.WindowsAgent/App.WindowsAgent.csproj", """\
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>
        <TargetFramework>net8.0-windows</TargetFramework></PropertyGroup></Project>
        """)
    write(tmp_path, "src/App.WindowsAgent/Program.cs", "class P { static void Main() { } }")
    assert roles(tmp_path)["App.WindowsAgent"] != "tool"


def test_kernel32_helpers_of_minidump_writer_are_info(tmp_path):
    c = comp(tmp_path, '''static class MiniDump {
        [DllImport("dbghelp.dll")] static extern bool MiniDumpWriteDump(IntPtr p, uint id, IntPtr f, int t, IntPtr e, IntPtr u, IntPtr c);
        [DllImport("kernel32.dll", EntryPoint = "GetCurrentThreadId")] static extern uint GetCurrentThreadId();
        public static void Dump(IntPtr f) { var t = GetCurrentThreadId(); MiniDumpWriteDump(IntPtr.Zero, t, f, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero); } }''')
    assert sev(c, "pinvoke-kernel32") is None and sev(c, "pinvoke-dbghelp") == "info"
    c = comp(tmp_path / "other", '''static class Native {
        [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
        public static uint Id() { return GetCurrentThreadId(); } }''')
    assert sev(c, "pinvoke-kernel32") == "refactor"


def test_smb_client_share_paths_are_not_file_paths(tmp_path):
    code = '''class Share { void Mk(string currentPath, string part) {
        currentPath = currentPath.Length == 0 ? part : $"{currentPath}\\\\{part}"; } }'''
    c = comp(tmp_path, "using SMBLibrary;\nusing SMBLibrary.Client;\n" + code)
    assert sev(c, "os-backslash-path-join") is None
    c = comp(tmp_path / "plain", code)
    assert sev(c, "os-backslash-path-join") == "refactor"


def _svc(root, name, tfm="net10.0"):
    write(root, f"src/{name}/{name}.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>
        <TargetFramework>{tfm}</TargetFramework></PropertyGroup></Project>
        """)


def test_windows_service_wrapper_with_cross_platform_twin_is_a_tool(tmp_path):
    from tests.test_round7 import roles
    _svc(tmp_path, "App.Service")
    write(tmp_path, "src/App.Service/Program.cs", "class P { static void Main() { } }")
    _svc(tmp_path, "App.WindowsService")
    write(tmp_path, "src/App.WindowsService/Program.cs",
          "class S : ServiceBase { static void Main() { ServiceBase.Run(new S()); } }")
    assert roles(tmp_path)["App.WindowsService"] == "tool"


def test_windows_service_without_twin_stays_worker(tmp_path):
    from tests.test_round7 import roles
    _svc(tmp_path, "App.Web")
    write(tmp_path, "src/App.Web/Program.cs", "class P { static void Main() { } }")
    _svc(tmp_path, "App.WindowsService")
    write(tmp_path, "src/App.WindowsService/Program.cs",
          "class S : ServiceBase { static void Main() { ServiceBase.Run(new S()); } }")
    assert roles(tmp_path)["App.WindowsService"] == "worker"
