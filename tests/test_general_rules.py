"""Rules written in terms of the technology, not of one way of writing it: the console switch of a Windows service
and a job's run-once argument in the usual comparison shapes, a vendor SDK loaded from its installation whatever the
variable is called, TPM types (not words that start with "tpm"), connection strings compiled in as a literal, the
key ring folder setting by its usual names, and packages that are known without being called Linux-safe."""
import re

import pytest
import yaml

from containerizer import confidence
from containerizer.assess import assess
from containerizer.generate import make_plan
from containerizer.harden import security
from containerizer.rules import RULES_DIR
from tests.test_engine import web_app, write
from tests.test_rule_fixes import comp, sev

EXE = """
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
    </Project>"""


def _exe(tmp_path, program: str):
    write(tmp_path, "src/Job/Job.csproj", EXE)
    write(tmp_path, "src/Job/Program.cs", program)
    a = assess(tmp_path)
    return a, next(c for c in a.components if c.name == "Job")


@pytest.mark.parametrize("test, arg", [
    ('args.Contains("--console")', "--console"),
    ('args.Any(a => a == "/console")', "/console"),
    ('args.Length > 0 && args[0] == "--console"', "--console"),
    ('args.Length > 0 && string.Equals(args[0], "/console", StringComparison.OrdinalIgnoreCase)', "/console"),
    ('args.Any(a => a.Equals("-interactive", StringComparison.OrdinalIgnoreCase))', "-interactive"),
    ('args.Any(a => string.Equals(a, "--no-service", StringComparison.OrdinalIgnoreCase))', "--no-service"),
])
def test_console_switch_in_the_usual_shapes(tmp_path, test, arg):
    a, c = _exe(tmp_path, f"""
        using Microsoft.Extensions.Hosting;
        var console = {test};
        var host = Host.CreateDefaultBuilder(args).ConfigureServices(s => s.AddHostedService<Worker>()).Build();
        if (console) await host.RunAsync(); else await host.RunAsServiceAsync();
        """)
    assert c.facts.get("console_arg") == arg
    assert make_plan(a, c)["args"] == [arg]


def test_console_switch_is_not_a_word_in_a_message(tmp_path):
    _, c = _exe(tmp_path, """
        using Microsoft.Extensions.Hosting;
        Console.WriteLine("Start with " + "--console" + " to run in the foreground");
        await Host.CreateDefaultBuilder(args).ConfigureServices(s => s.AddHostedService<Worker>()).Build().RunAsync();
        """)
    assert "console_arg" not in c.facts


@pytest.mark.parametrize("program, arg", [
    ('if (args.Contains("--once")) { Run(); return; } Loop();', "--once"),
    ('switch (args[0]) { case "--import-orders": Import(); break; default: Loop(); break; }', "--import-orders"),
    ('var folder = ArgValue(args, "--export"); Export(folder);', "--export"),
    ('if (args.Length > 0 && args[0] == "--run-nightly") Nightly();', "--run-nightly"),
    # an option of another program, or a help text: not this program's argument
    ('Process.Start("pg_dump", "--export-all"); Console.WriteLine("use " + "--once");', None),
])
def test_run_once_argument_is_one_the_arguments_are_compared_with(tmp_path, program, arg):
    _, c = _exe(tmp_path, "class P { static void Main(string[] args) { " + program + " } }")
    assert c.facts.get("oneshot_arg") == arg


LOADER = """
    using System.Reflection; using System.Runtime.Loader;
    class Engine {{
        {body}
    }}"""


def test_vendor_sdk_loaded_from_its_installation_whatever_the_variable_is_called(tmp_path):
    for i, body in enumerate((
            'Assembly Load(Options o) => Assembly.LoadFrom(Path.Combine(o.InstallDir, "bin", "Engine.dll"));',
            'Assembly Load() { var dir = (string)Registry.LocalMachine.OpenSubKey(@"SOFTWARE\\Acme").GetValue("Path"); '
            'return Assembly.LoadFrom(Path.Combine(dir, "Acme.Engine.dll")); }',
            'Assembly Load(string sdkRoot) => AssemblyLoadContext.Default.LoadFromAssemblyPath(sdkRoot + "/x.dll");',
            'Assembly Load() => Assembly.LoadFrom(@"C:\\Program Files\\Acme\\Acme.dll");')):
        c = comp(tmp_path / f"v{i}", LOADER.format(body=body))
        assert sev(c, "vendor-sdk-install-dir") == "blocker", body
    # the application's own plug-ins, loaded from under its folder: not a vendor installation
    for i, body in enumerate((
            'void Load(string pluginDir) { foreach (var f in Directory.GetFiles(pluginDir, "*.dll")) Assembly.LoadFrom(f); }',
            'void Load() { var installPath = Path.Combine(AppContext.BaseDirectory, "plugins"); '
            'foreach (var f in Directory.GetFiles(installPath)) Assembly.LoadFrom(f); }')):
        c = comp(tmp_path / f"p{i}", LOADER.format(body=body))
        assert sev(c, "vendor-sdk-install-dir") is None, body


def test_tpm_types_are_hardware_and_a_cmdlet_name_in_a_message_is_not(tmp_path):
    c = comp(tmp_path / "a", 'class K { void M() { using var tpm = new Tpm2(new TbsDevice()); } }')
    assert sev(c, "hardware-sdk") == "blocker"
    c = comp(tmp_path / "b", 'class K { void M() { var h = TpmHandle.RhOwner; } }')
    assert sev(c, "hardware-sdk") == "blocker"
    c = comp(tmp_path / "c", 'class K { int tpmCount; string M() => "Run Get-Tpm to check; see " + nameof(TpmlessMode); }')
    assert sev(c, "hardware-sdk") is None


def test_prose_is_not_a_scheduled_task_or_an_agent_job(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/README.md", "Was started by Register-ScheduledTask; the old SQL Server Agent job is gone.")
    write(tmp_path, "src/Web/docs/ops.md", "schtasks /create is no longer needed. New-ScheduledTaskTrigger -Daily")
    c = assess(tmp_path).components[0]
    assert sev(c, "scheduled-tasks") is None and sev(c, "sql-agent-ssis") is None
    write(tmp_path, "src/Web/deploy/jobs.ps1", "Register-ScheduledTask -TaskName x -Trigger (New-ScheduledTaskTrigger -Daily -At 02:00)")
    write(tmp_path, "src/Web/db/jobs.sql", "EXEC msdb.dbo.sp_add_job @job_name = N'Purge';")
    c = assess(tmp_path).components[0]
    assert sev(c, "scheduled-tasks") and sev(c, "sql-agent-ssis")


def test_connection_string_compiled_in_as_a_literal_or_a_const_of_any_class(tmp_path):
    for i, code in enumerate((
            'class S { void M(IServiceCollection s) { s.AddDbContext<Ctx>(o => '
            'o.UseSqlServer("Server=db1;Database=Shop;User Id=shop;Password=x")); } }',
            'class Repo { System.Data.IDbConnection Open() => new SqlConnection(@"Data Source=db1;Initial Catalog=Shop"); }',
            'class Db { const string Shop = "Host=pg1;Database=shop"; '
            'void M(IServiceCollection s) { s.AddDbContext<Ctx>(o => o.UseNpgsql(Shop)); } }')):
        assert sev(comp(tmp_path / f"y{i}", code), "conn-string-compiled-in") == "refactor", code
    for i, code in enumerate((
            # read from configuration; a provider name is not a connection string
            'class S { void M(IServiceCollection s, IConfiguration c) { '
            's.AddDbContext<Ctx>(o => o.UseSqlServer(c["Db"] ?? throw new Exception("Server= is missing"))); } }',
            # only `dotnet ef` runs the design-time factory
            'class F : IDesignTimeDbContextFactory<Ctx> { public Ctx CreateDbContext(string[] a) => new Ctx('
            'new DbContextOptionsBuilder<Ctx>().UseSqlServer("Server=(localdb)\\\\mssqllocaldb;Database=x").Options); }')):
        assert sev(comp(tmp_path / f"n{i}", code), "conn-string-compiled-in") is None, code


def test_machine_name_as_an_identity_whatever_the_member_is_called(tmp_path):
    for i, code in enumerate((
            'class O { public string LeaseHolder { get; set; } = Environment.MachineName; }',
            'class O { string _schedulerName = "jobs-" + Environment.MachineName; }',
            'class O { void M(Options o) { o.AgentId = Environment.MachineName; } }')):
        assert sev(comp(tmp_path / f"y{i}", code), "os-machine-name-identity") == "info", code
    c = comp(tmp_path / "n", 'class O { void M(ILogger log) { var machine = Environment.MachineName; '
                             'log.LogInformation("on {Machine}", machine); } }')
    assert sev(c, "os-machine-name-identity") is None


def test_key_ring_folder_setting_by_its_usual_names():
    names = re.compile(security()["lint"]["keyring_names"])
    for key in ("DataProtection:KeyFolder", "DataProtection__KeysFolder", "DataProtectionKeysPath", "KeyRing:Path",
                "App:DataProtectionPath", "DataProtection:KeyStoragePath", "KeyStoragePath", "KeyStorage__Directory"):
        assert names.search(key), key
    for key in ("KeysFolder", "Ssh:KeyPath", "Signing:KeyFolder", "DataProtection:ApplicationName", "StoragePath"):
        assert not names.search(key), key


def test_windows_bound_packages_are_known_but_not_called_linux_safe(tmp_path):
    doc = yaml.safe_load((RULES_DIR / "packages.yaml").read_text())
    safe = re.compile("^(?:" + "|".join(doc["linux_ok"]) + ")$", re.I)
    judged = re.compile("^(?:" + "|".join(doc["judged_by_rules"]) + ")$", re.I)
    names = ("System.IO.Ports", "System.Management", "System.DirectoryServices.AccountManagement", "System.Data.OleDb",
             "System.Drawing.Common", "Topshelf", "DinkToPdf", "Net.IBM.Data.Db2", "EnterpriseLibrary.Data",
             "Microsoft.ReportingServices.ReportViewerControl.WebForms", "System.Diagnostics.EventLog",
             "System.ServiceProcess.ServiceController")
    for n in names:
        assert not safe.match(n) and judged.match(n), n
    # ... and still known: no "unknown package" lowers the confidence
    confidence.reset_cache()
    web_app(tmp_path, packages="".join(f'<PackageReference Include="{n}" Version="1.0.0" />' for n in names))
    c = assess(tmp_path).components[0]
    assert not [u for u in c.uncertain if u.startswith("package:")]
