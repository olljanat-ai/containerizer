"""Analysis and generation that does not depend on how one set of sample applications was laid out: sub-commands
of command-line libraries, console programs that run until stopped, the E rating's share as a setting, two shares
with the same folder, READMEs other than a root README.md, connection strings without a port, and a folder called
scenarios."""
from containerizer import assess as assess_mod
from containerizer.assess import assess, classify_role
from containerizer.connectivity import _scan_destinations, line_hosts
from containerizer.generate import k8s_manifests, linux_path, make_plan
from containerizer.rules import load_rules
from containerizer.scan import scan
from tests.test_engine import web_app, write
from tests.test_role_false_positives import proj

RULES = load_rules()
EXE = "<OutputType>Exe</OutputType>"


def _console(root, name: str, code: str, items: str = "") -> None:
    proj(root, f"src/{name}/{name}.csproj", props=EXE, items=items)
    write(root, f"src/{name}/Program.cs", code)


def _comp(root, name: str):
    a = assess(root)
    return a, next(c for c in a.components if c.name == name)


# ---------------------------------------------------------------- sub-commands of command-line libraries
def test_commands_of_cli_libraries(tmp_path):
    _console(tmp_path, "Tool.SystemCommandLine", """
        var root = new RootCommand("x");
        root.Add(new Command("import", "Import files"));
        root.Add(new Command("export", "Export files"));
        var file = new Option<string>("--file");
        return root.Invoke(args);""")
    _console(tmp_path, "Tool.Parser", """
        [Verb("sync", HelpText = "x")] class SyncOptions {}
        [Verb("purge")] class PurgeOptions {}
        class P { static int Main(string[] args) => Parser.Default.ParseArguments<SyncOptions, PurgeOptions>(args).MapResult(_ => 0, _ => 1); }""")
    _console(tmp_path, "Tool.Spectre", """
        var app = new CommandApp();
        app.Configure(c => { c.AddCommand<LoadCommand>("load"); c.AddCommand<CheckCommand>("check"); });
        return app.Run(args);""")
    _console(tmp_path, "mytool", """
        [Command("mytool")] [Subcommand(typeof(A), typeof(B))] class P { static int Main(string[] a) => CommandLineApplication.Execute<P>(a); }
        [Command("report")] class A {}
        [Command(Name = "archive")] class B {}""")
    a = assess(tmp_path)
    cmds = {c.name: c.facts.get("commands") for c in a.components}
    assert cmds == {"Tool.SystemCommandLine": ["import", "export"], "Tool.Parser": ["sync", "purge"],
                    "Tool.Spectre": ["load", "check"], "mytool": ["report", "archive"]}
    c = next(c for c in a.components if c.name == "Tool.Parser")
    docs = k8s_manifests(a, c, make_plan(a, c), "img")
    assert sorted(d["metadata"]["name"] for d in docs if d["kind"] == "CronJob") == ["tool-parser-purge", "tool-parser-sync"]


# ---------------------------------------------------------------- runs until stopped: a Deployment
def _roles(root) -> dict:
    repo = scan(root)
    return {p.name: classify_role(repo, p, RULES) for p in repo.projects}


def test_console_that_runs_until_stopped_is_a_deployment(tmp_path):
    _console(tmp_path, "Sleeper", """
        class P { static void Main() { var t = new Timer(_ => Poll(), null, 0, 60000); Thread.Sleep(Timeout.Infinite); } }""")
    _console(tmp_path, "Hosted", """
        var host = Host.CreateDefaultBuilder(args).ConfigureServices(s => s.AddPolling()).Build();
        await host.RunAsync();""")
    _console(tmp_path, "Poller", """
        class P { static async Task Main() {
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            while (!cts.Token.IsCancellationRequested) { Work(); await Task.Delay(5000); } } }""")
    _console(tmp_path, "Looper", """
        class P { static void Main() { while (true) { Work(); Thread.Sleep(5000); } } }""")
    # run and exit: a retry loop that a break leaves, a plain batch
    _console(tmp_path, "Retry", """
        class P { static void Main() { while (true) { try { Work(); break; } catch { Thread.Sleep(1000); } } } }""")
    _console(tmp_path, "Batch", "class P { static int Main(string[] args) { Export(); return 0; } }")
    roles = _roles(tmp_path)
    for name in ("Sleeper", "Hosted", "Poller", "Looper"):
        assert roles[name] == ("worker", "role-runs-until-stopped"), name
    assert roles["Retry"][0] == "console" and roles["Batch"][0] == "console"
    a, c = _comp(tmp_path, "Sleeper")
    plan = make_plan(a, c)
    assert [d["kind"] for d in k8s_manifests(a, c, plan, "img") if d["kind"] in ("Deployment", "CronJob")] == ["Deployment"]
    assert any(r["rule"] == "workload-deployment" for r in plan["reasons"])
    c = next(x for x in a.components if x.name == "Batch")
    plan = make_plan(a, c)
    assert [d["kind"] for d in k8s_manifests(a, c, plan, "img") if d["kind"] in ("Deployment", "CronJob")] == ["CronJob"]
    assert any(r["rule"] == "workload-cronjob" for r in plan["reasons"])


# ---------------------------------------------------------------- the E rating's share is a setting
def test_not_feasible_share_is_a_rules_setting(tmp_path, monkeypatch):
    assert assess_mod.not_feasible_share() == 0.75
    web_app(tmp_path)
    for name in ("Opc1", "Opc2"):
        proj(tmp_path, f"src/{name}/{name}.csproj", sdk="Microsoft.NET.Sdk.Worker")
        write(tmp_path, f"src/{name}/Program.cs", "var port = new SerialPort(\"COM1\"); Host.CreateDefaultBuilder().Build().Run();")
    a = assess(tmp_path)
    assert [c.verdict for c in a.components].count("blocker") == 2 and a.rating == "C"      # 2 of 3 is under 75%
    monkeypatch.setattr(assess_mod, "not_feasible_share", lambda: 0.6)
    assert a.rating == "E"


# ---------------------------------------------------------------- two shares with the same folder
def test_two_shares_with_the_same_folder_stay_two_folders():
    plan = {"add_writable": []}
    assert linux_path(plan, r"\\fs1\in\orders") == "/data/orders"
    assert linux_path(plan, r"\\fs1\in\orders\new.csv") == "/data/orders/new.csv"      # the same share again
    assert linux_path(plan, r"\\fs2\in\orders") == "/data/fs2-in/orders"
    assert linux_path(plan, r"\\fs2\in\orders\new.csv") == "/data/fs2-in/orders/new.csv"
    assert linux_path(plan, r"D:\Archive") == "/data/archive" and linux_path(plan, r"E:\Archive") == "/data/e/archive"
    assert plan["add_writable"] == ["/data/orders", "/data/fs2-in/orders", "/data/archive", "/data/e/archive"]


# ---------------------------------------------------------------- README
def test_readme_of_other_names_and_places(tmp_path):
    for i, (rel, text) in enumerate([("README.rst", "root rst"), ("ReadMe", "root plain"), ("docs/README.md", "docs"),
                                     ("src/Web/readme.md", "component")]):
        root = tmp_path / str(i)
        web_app(root)
        write(root, "tests/README.md", "tests")
        write(root, rel, text)
        assert scan(root).readme.strip() == text, rel
    web_app(tmp_path / "md")
    write(tmp_path / "md", "README.rst", "rst")
    write(tmp_path / "md", "readme.md", "md")
    assert scan(tmp_path / "md").readme.strip() == "md"
    web_app(tmp_path / "none")
    assert scan(tmp_path / "none").readme == ""


# ---------------------------------------------------------------- connection strings without a port
def test_connection_string_without_a_port_has_the_providers_default():
    port = lambda line: [(h, p) for h, p, _ in line_hosts(line)]      # noqa: E731
    assert port('"Server=sql.intra.example.net;Database=Shop;Integrated Security=true"') == [("sql.intra.example.net", 1433)]
    assert port('"Server=sql,14330;Database=Shop"') == [("sql", 14330)]
    assert port('"Server=my1;Database=x;Uid=u;Pwd=p;SslMode=Required"') == [("my1", 3306)]
    assert port('"Server=my1;Port=3307;Database=x;Uid=u"') == [("my1", 3307)]
    assert port('"Host=pg1;Database=x;Username=u;Password=p"') == [("pg1", 5432)]
    assert port('"Host=pg1;Port=5433;Database=x"') == [("pg1", 5433)]
    # each connection string of a one-line JSON file is read on its own
    assert port('{"A": "Server=sql1;Database=x", "B": "Host=pg1;Port=5433;Database=y"}') == \
        [("sql1", 1433), ("pg1", 5433)]
    assert port('"host=mq1;virtualHost=/;username=u;password=p"') == [("mq1", 5672)]
    # a named instance has no fixed port; a file is no host; code is no connection string
    assert port(r'"Data Source=sqlprod\\INST1;Initial Catalog=Shop"') == [("sqlprod", None)]
    assert port('"Data Source=app.db"') == [("app.db", None)]
    assert port('var host = cfg["Host"]; Host = builder.Build();') == []


def test_database_server_without_a_port_is_a_destination(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.json", """
        {"ConnectionStrings": {"Shop": "Server=sql.intra.contoso.net;Database=Shop;Integrated Security=true",
                               "Local": "Data Source=app.db"}}""")
    a = assess(tmp_path)
    found = {(d["host"], d["port"]) for d in _scan_destinations(a.repo, a.components[0])}
    assert found == {("sql.intra.contoso.net", 1433)}


# ---------------------------------------------------------------- a folder called scenarios
def test_a_folder_called_scenarios_is_part_of_the_application(tmp_path):
    from containerizer.cli import _apps
    (tmp_path / "scenarios" / "load-test").mkdir(parents=True)
    assert _apps([str(tmp_path)]) == [tmp_path]
