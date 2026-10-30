"""Round 5 regression tests from the real-world corpus: build-time helper executables (nopCommerce
ClearPluginAssemblies, Smartstore ModuleBuilder, Squidex.Translator), .NET Remoting / socket
listener servers (My-Smart-Home), and backslash paths that are only probed for existence
(nopCommerce SummernoteHelper) or used as zip-entry lookup keys (Duplicati)."""
from containerizer.assess import assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import scan
from tests.test_engine import web_app, write
from tests.test_round3 import oldstyle, proj

RULES = load_rules()


def roles(root) -> dict[str, str]:
    repo = scan(root)
    return {p.name: classify_role(repo, p, RULES)[0] for p in repo.projects}


def finding_sev(root) -> dict[str, str]:
    return {f.rule.id: f.severity for c in assess(root).components for f in c.findings}


# ---------------------------------------------------------------- build-time executables
def test_exe_run_by_msbuild_exec_is_tool(tmp_path):
    proj(tmp_path, "src/Build/src/Cleaner/Cleaner.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Build/src/Cleaner/Program.cs", "class P { static void Main() {} }")
    write(tmp_path, "src/Build/Cleaner.proj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <Target Name="Clear">
            <Exec Command='dotnet "Cleaner.dll" "OutputPath=$(OutputPath)"' />
          </Target>
        </Project>""")
    proj(tmp_path, "src/Batch/Batch.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Batch/Program.cs", "class P { static void Main() {} }")
    r = roles(tmp_path)
    assert r["Cleaner"] == "tool"
    assert r["Batch"] == "console"


def test_exec_that_deletes_a_dll_does_not_make_a_tool(tmp_path):
    # RockRMS-style post-build cleanup: `del ...\\X.dll` names the dll but does not run it
    proj(tmp_path, "src/Rock.Job/Rock.Job.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Rock.Job/Program.cs", "class P { static void Main() {} }")
    proj(tmp_path, "src/Web/Web.csproj", items="""
        </ItemGroup><Target Name="Post" AfterTargets="Build">
          <Exec Command="if Exist &quot;$(ProjectDir)bin\\Rock.Job.dll&quot; del &quot;$(ProjectDir)bin\\Rock.Job.dll&quot;" />
        </Target><ItemGroup>""")
    assert roles(tmp_path)["Rock.Job"] == "console"


def test_web_app_run_by_build_stays_web(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "build.targets", """
        <Project><Target Name="Gen"><Exec Command="dotnet Web.dll --swagger" /></Target></Project>""")
    assert roles(tmp_path)["Web"] == "web"


def test_exe_started_with_dotnet_run_by_a_repo_script_is_tool(tmp_path):
    proj(tmp_path, "backend/i18n/translator/Translator/Translator.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "backend/i18n/translator/Translator/Program.cs", "class P { static int Main() => 0; }")
    write(tmp_path, "backend/i18n/translate.sh", """
        #!/bin/bash
        cd translator/Translator
        dotnet run --no-restore translate check-backend ../../../..
        """)
    write(tmp_path, "build.ps1", "dotnet run --project ./Build/Build.csproj -- $args\n")
    proj(tmp_path, "Build/Build.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "Build/Program.cs", "class P { static void Main() {} }")
    # a worker that a developer script starts with `dotnet run` is still a worker
    proj(tmp_path, "src/Job/Job.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Job/Program.cs", "var b = Host.CreateApplicationBuilder(args); b.Services.AddHostedService<W>();")
    write(tmp_path, "run-job.sh", "cd src/Job\ndotnet run\n")
    # `dotnet App.dll` in a script is how a deployed program starts: not a tool signal
    proj(tmp_path, "src/Batch/Batch.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Batch/Program.cs", "class P { static void Main() {} }")
    write(tmp_path, "start.sh", "dotnet /app/Batch.dll\n")
    r = roles(tmp_path)
    assert r["Translator"] == "tool"
    assert r["Build"] == "tool"
    assert r["Job"] == "worker"
    assert r["Batch"] == "console"


# ---------------------------------------------------------------- listener servers
REMOTING_SERVER = """
    using System; using System.Runtime.Remoting; using System.Runtime.Remoting.Channels;
    using System.Runtime.Remoting.Channels.Tcp;
    class Program { static void Main() {
        TcpChannel ch = new TcpChannel(8090);
        ChannelServices.RegisterChannel(ch);
        RemotingConfiguration.RegisterWellKnownServiceType(typeof(ServerImp), "Server", WellKnownObjectMode.SingleCall);
        Console.WriteLine("running");
        Console.Read();
    } }"""

REMOTING_CLIENT = """
    using System; using System.Runtime.Remoting.Channels; using System.Runtime.Remoting.Channels.Tcp;
    class Program { static void Main() {
        ChannelServices.RegisterChannel(new TcpChannel());
        var o = (IServer)Activator.GetObject(typeof(IServer), "tcp://localhost:8090/Server");
        o.Ping();
        Console.ReadLine();
    } }"""


def test_remoting_listener_exe_is_worker_and_client_stays_console(tmp_path):
    oldstyle(tmp_path, "Server/Server.csproj", "Exe")
    write(tmp_path, "Server/Program.cs", REMOTING_SERVER)
    oldstyle(tmp_path, "Client/Client.csproj", "Exe")
    write(tmp_path, "Client/Program.cs", REMOTING_CLIENT)
    r = roles(tmp_path)
    assert r["Server"] == "worker"
    assert r["Client"] == "console"


def test_remoting_server_from_config_file_is_worker(tmp_path):
    oldstyle(tmp_path, "Host/Host.csproj", "Exe")
    write(tmp_path, "Host/Program.cs", """
        class Program { static void Main() {
            System.Runtime.Remoting.RemotingConfiguration.Configure("Host.exe.config", false);
            System.Console.ReadLine(); } }""")
    write(tmp_path, "Host/App.config", """
        <configuration><system.runtime.remoting><application><service>
          <wellknown mode="Singleton" type="Svc, Host" objectUri="svc" />
        </service><channels><channel ref="tcp" port="9000" /></channels></application></system.runtime.remoting></configuration>""")
    assert roles(tmp_path)["Host"] == "worker"


def test_tcp_listener_loop_is_worker_but_oauth_loopback_cli_is_console(tmp_path):
    proj(tmp_path, "src/Mllp/Mllp.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Mllp/Program.cs", """
        var l = new TcpListener(IPAddress.Any, 2575); l.Start();
        while (true) { var c = l.AcceptTcpClient(); Handle(c); }""")
    proj(tmp_path, "src/Cli/Cli.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "src/Cli/Program.cs", """
        var http = new HttpListener(); http.Prefixes.Add("http://localhost:7890/"); http.Start();
        var ctx = await http.GetContextAsync(); var code = ctx.Request.QueryString["code"]; http.Stop();""")
    r = roles(tmp_path)
    assert r["Mllp"] == "worker"
    assert r["Cli"] == "console"


# ---------------------------------------------------------------- backslash paths
def test_backslash_path_only_probed_for_existence_is_info(tmp_path):
    web_app(tmp_path, r'''
        class H { bool L(string directoryPath, string langFile) {
            var fileExists = _fp.FileExists($"{directoryPath}\\{langFile}");
            return fileExists; } }''')
    s = finding_sev(tmp_path)
    assert s.get("os-backslash-path-probe") == "info"
    assert "os-backslash-path-join" not in s
    assert assess(tmp_path).rating == "A"


def test_negated_probe_and_writes_stay_refactor(tmp_path):
    web_app(tmp_path, r'''
        class H { void L(string dir) {
            if (!File.Exists(dir + "\\settings.json")) throw new FileNotFoundException();
            File.WriteAllText(dir + "\\out.txt", "x"); } }''')
    assert finding_sev(tmp_path).get("os-backslash-path-join") == "refactor"


def test_zip_entry_key_fallback_is_not_a_path(tmp_path):
    web_app(tmp_path, r'''
        class Z { IEntry Get(string file) {
            if (dict.TryGetValue(file, out var e)) return e;
            if (dict.TryGetValue(file.Replace('/', '\\'), out e)) return e;
            return null; } }''')
    assert "os-backslash-path-join" not in finding_sev(tmp_path)
