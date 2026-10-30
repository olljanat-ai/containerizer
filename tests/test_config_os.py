"""Configuration, secrets, identity and Windows-vs-Linux OS behaviour rules (rules/35-config-os.yaml)."""
from containerizer.assess import assess
from tests.test_engine import web_app, write


def ids(root):
    return {f.rule.id for c in assess(root).components for f in c.findings}


def worker(root, code: str) -> None:
    write(root, "src/Job/Job.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Worker"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>""")
    write(root, "src/Job/Program.cs", """
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddHostedService<Work>();
        builder.Build().Run();
        """ + code)


# ---------------------------------------------------------------- paths
def test_drive_path_default_is_config_and_hardcoded_is_refactor(tmp_path):
    web_app(tmp_path, r'''
        public class Opt { public string Root { get; set; } = @"D:\Archive\Docs"; }''')
    sev = {f.rule.id: f.severity for f in assess(tmp_path).components[0].findings}
    assert sev["os-drive-path-default"] == "config" and "os-drive-path-hardcoded" not in sev
    other = tmp_path / "b"
    web_app(other, r'''
        public class S { const string Settings = @"C:\ProgramData\Acme\app.json";
                         string R() => File.ReadAllText("C:\\Temp\\x.txt"); }''')
    sev = {f.rule.id: f.severity for f in assess(other).components[0].findings}
    assert sev["os-drive-path-hardcoded"] == "refactor" and "os-drive-path-default" not in sev


def test_drive_path_fallback_and_regex_are_not_hardcoded(tmp_path):
    web_app(tmp_path, r'''
        public class K { const string DefaultFolder = @"C:\Logs";
          string F(IConfiguration c) => c["Keys"] ?? Path.Combine(@"D:\Keys", "x");
          bool M(string s) => Regex.IsMatch(s, @"\d+:\w");
          string N = "a:\\b"; }''')
    found = ids(tmp_path)
    assert "os-drive-path-hardcoded" not in found
    assert "os-drive-path-default" in found


def test_backslash_path_join(tmp_path):
    web_app(tmp_path, r'''
        class A { string P(string folder, string name) => folder + "\\" + name;
                  string Q(string root) => Path.Combine(root, "Logs\\app.log"); }''')
    assert "os-backslash-path-join" in ids(tmp_path)


def test_backslash_account_names_are_not_paths(tmp_path):
    web_app(tmp_path, r'''
        class A { string U(string domain, string sam) => domain + "\\" + sam;
                  string V() => $@"{Environment.UserDomainName}\{Environment.UserName}";
                  string W(string pattern) => pattern + @"\d+";
                  string X(string dir) => Path.Combine(dir, "logs", "app.log"); }''')
    assert "os-backslash-path-join" not in ids(tmp_path)


def test_special_folders(tmp_path):
    web_app(tmp_path, '''
        class A { string D = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                  string P = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles); }''')
    found = ids(tmp_path)
    assert {"os-special-folder-profile", "os-special-folder-windows"} <= found


def test_guarded_special_folder_and_temp_path_are_fine(tmp_path):
    web_app(tmp_path, '''
        class A { string T = Path.GetTempPath();
          string P() { if (OperatingSystem.IsWindows()) { return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles); } return "/opt"; } }''')
    found = ids(tmp_path)
    assert "os-special-folder-windows" not in found and "os-special-folder-profile" not in found


def test_windows_env_vars_in_code_and_config(tmp_path):
    web_app(tmp_path, 'class A { string R = Environment.ExpandEnvironmentVariables(@"%ProgramData%\\Acme"); }')
    assert "os-windows-env-vars" in ids(tmp_path)
    other = tmp_path / "b"
    web_app(other)
    write(other, "src/Web/appsettings.json", r'{"Logs": {"Path": "%LOCALAPPDATA%\\Acme\\logs"}}')
    assert "os-windows-env-vars" in ids(other)


def test_linux_env_vars_are_fine(tmp_path):
    web_app(tmp_path, 'class A { string H = Environment.GetEnvironmentVariable("HOME"); string P = Environment.GetEnvironmentVariable("ASPNETCORE_URLS"); }')
    write(tmp_path, "src/Web/web.config", r'''<configuration><system.webServer><handlers>
        <add name="ISAPI" path="*." verb="GET" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\aspnet_isapi.dll" />
        </handlers></system.webServer></configuration>''')
    assert "os-windows-env-vars" not in ids(tmp_path)


def test_drive_letters_and_exe_location(tmp_path):
    web_app(tmp_path, '''
        class A { long F = new DriveInfo("D").AvailableFreeSpace;
                  string B = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName); }''')
    found = ids(tmp_path)
    assert {"os-drive-letters", "os-exe-location"} <= found


def test_driveinfo_from_path_root_and_basedirectory_are_fine(tmp_path):
    web_app(tmp_path, '''
        class A { long F(string p) => new DriveInfo(Path.GetPathRoot(Path.GetFullPath(p))).AvailableFreeSpace;
                  string B = AppContext.BaseDirectory; }''')
    found = ids(tmp_path)
    assert "os-drive-letters" not in found and "os-exe-location" not in found


def test_newline_split(tmp_path):
    web_app(tmp_path, 'class A { string[] L(string t) => t.Split(Environment.NewLine); }')
    assert "os-newline-split" in ids(tmp_path)
    ok = tmp_path / "b"
    web_app(ok, 'class A { string[] L(string t) => t.Split(new[] { "\\r\\n", "\\n" }, StringSplitOptions.None); }')
    assert "os-newline-split" not in ids(ok)


# ---------------------------------------------------------------- identity and host
def test_process_account_and_machine_name(tmp_path):
    web_app(tmp_path, '''
        class A { string Who = Environment.UserDomainName + "/" + Environment.UserName;
                  void C(BackgroundJobServerOptions o) { o.ServerName = Environment.MachineName + ":jobs"; } }''')
    found = ids(tmp_path)
    assert {"os-process-account-name", "os-machine-name-identity"} <= found


def test_machine_name_in_logs_and_health_is_fine(tmp_path):
    web_app(tmp_path, '''
        class A { object H() => new { status = "ok", server = Environment.MachineName };
                  void L(ILogger l) { l.LogInformation("Started on {Host}", Environment.MachineName); } }''')
    found = ids(tmp_path)
    assert "os-machine-name-identity" not in found and "os-machine-name-switch" not in found


def test_machine_name_switch_is_refactor(tmp_path):
    web_app(tmp_path, 'class A { bool Prod = Environment.MachineName.ToUpperInvariant() == "PRODWEB01"; }')
    c = assess(tmp_path).components[0]
    assert any(f.rule.id == "os-machine-name-switch" and f.severity == "refactor" for f in c.findings)


def test_console_input_and_userinteractive_in_service_host(tmp_path):
    worker(tmp_path, '''
        class P { static void Main() { if (Environment.UserInteractive) { Start(); Console.ReadLine(); }
                                       else { ServiceBase.Run(new Svc()); } } }''')
    found = ids(tmp_path)
    assert {"os-console-input", "os-userinteractive"} <= found


def test_userinteractive_alone_and_console_in_tests_are_fine(tmp_path):
    web_app(tmp_path, 'class L { void W(string s) { if (Environment.UserInteractive) Console.WriteLine(s); } }')
    write(tmp_path, "tests/T/T.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="xunit" Version="2.9.0" /></ItemGroup></Project>""")
    write(tmp_path, "tests/T/T.cs", "public class T { [Fact] public void M() { Console.ReadLine(); } }")
    found = ids(tmp_path)
    assert "os-userinteractive" not in found and "os-console-input" not in found


def test_named_semaphore_is_refactor_and_mutex_is_info(tmp_path):
    worker(tmp_path, '''
        class W { void M() { using var s = new Semaphore(1, 1, @"Global\\Acme.Import");
                             using var m = new Mutex(false, @"Global\\Acme.Job"); } }''')
    c = assess(tmp_path).components[0]
    sev = {f.rule.id: f.severity for f in c.findings}
    assert sev["os-named-sync-objects"] == "refactor"
    assert sev["os-named-mutex"] == "info"


def test_unnamed_sync_primitives_are_fine(tmp_path):
    worker(tmp_path, '''
        class W { SemaphoreSlim s = new SemaphoreSlim(1, 1); Mutex m = new Mutex();
                  ManualResetEvent e = new ManualResetEvent(false); Semaphore x = new Semaphore(0, 4); }''')
    found = ids(tmp_path)
    assert "os-named-sync-objects" not in found and "os-named-mutex" not in found


def test_local_time_info(tmp_path):
    web_app(tmp_path, 'class A { string D = DateTime.Now.ToString("d"); }')
    c = assess(tmp_path).components[0]
    assert any(f.rule.id == "os-local-timezone" and f.severity == "info" for f in c.findings)
    assert assess(tmp_path).rating == "A"


def test_isolated_storage_and_user_settings(tmp_path):
    worker(tmp_path, '''
        class W { void M() { var s = IsolatedStorageFile.GetUserStoreForAssembly();
                             Properties.Settings.Default.Save(); } }''')
    assert {"os-isolated-storage", "cfg-user-scoped-settings"} <= ids(tmp_path)


# ---------------------------------------------------------------- ports
def test_privileged_port_in_code(tmp_path):
    web_app(tmp_path, '')
    write(tmp_path, "src/Web/Program.cs", """
        var b = WebApplication.CreateBuilder(args);
        b.WebHost.UseUrls("http://*:80");
        var app = b.Build(); app.MapGet("/healthz", () => "ok"); app.Run();""")
    assert "cfg-privileged-port" in ids(tmp_path)


def test_unprivileged_ports_are_fine(tmp_path):
    web_app(tmp_path, '')
    write(tmp_path, "src/Web/Program.cs", """
        var b = WebApplication.CreateBuilder(args);
        b.WebHost.UseUrls("http://*:8080");
        b.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8443));
        var l = new HttpListener(); l.Prefixes.Add("http://+:8085/");
        var app = b.Build(); app.MapGet("/healthz", () => "ok"); app.Run();""")
    write(tmp_path, "src/Web/appsettings.json", '{"urls": "http://*:5000"}')
    assert "cfg-privileged-port" not in ids(tmp_path)


# ---------------------------------------------------------------- local services and credentials
def test_local_sql_server(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.json", r'''
        {"ConnectionStrings": {"Db": "Server=(localdb)\\mssqllocaldb;Database=App;Trusted_Connection=True"}}''')
    assert "cfg-local-sql-server" in ids(tmp_path)


def test_remote_sql_and_sqlite_are_not_local(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.json", r'''
        {"ConnectionStrings": {"Db": "Server=sql01.corp.local;Database=App;User Id=app;Password=${DB_PWD}",
                               "Cache": "Data Source=app.db"}}''')
    write(tmp_path, "src/Web/appsettings.Development.json", '{"ConnectionStrings": {"Db": "Server=localhost;Database=App"}}')
    assert "cfg-local-sql-server" not in ids(tmp_path)


def test_default_credentials(tmp_path):
    worker(tmp_path, 'class W { HttpClientHandler H = new HttpClientHandler { UseDefaultCredentials = true }; }')
    assert "os-default-credentials" in ids(tmp_path)


def test_smtp_pickup(tmp_path):
    worker(tmp_path, '''
        class W { void M(SmtpClient a, SmtpClient b) { a.DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory;
                                                       b.DeliveryMethod = SmtpDeliveryMethod.PickupDirectoryFromIis; } }''')
    c = assess(tmp_path).components[0]
    sev = {f.rule.id: f.severity for f in c.findings}
    assert sev["cfg-smtp-pickup-folder"] == "config" and sev["cfg-smtp-pickup-iis"] == "refactor"


def test_smtp_network_delivery_is_fine(tmp_path):
    worker(tmp_path, 'class W { SmtpClient C = new SmtpClient("smtp.example.com", 587) { DeliveryMethod = SmtpDeliveryMethod.Network }; }')
    found = ids(tmp_path)
    assert "cfg-smtp-pickup-folder" not in found and "cfg-smtp-pickup-iis" not in found


def test_external_config_files(tmp_path):
    write(tmp_path, "src/Svc/Svc.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Worker"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>""")
    write(tmp_path, "src/Svc/Program.cs", "Host.CreateApplicationBuilder(args).Build().Run();")
    write(tmp_path, "src/Svc/App.config", r'''
        <configuration><appSettings file="..\..\shared\settings.config" />
          <connectionStrings configSource="Config\connections.config" /></configuration>''')
    assert "cfg-external-config-files" in ids(tmp_path)


# ---------------------------------------------------------------- secrets and cloud identity
def test_user_secrets_key_vault_and_managed_identity(tmp_path):
    web_app(tmp_path, '''
        class A { void M(IConfigurationBuilder b) { b.AddAzureKeyVault(new Uri("https://kv.vault.azure.net/"), new DefaultAzureCredential()); } }''',
            packages='<PackageReference Include="Azure.Extensions.AspNetCore.Configuration.Secrets" Version="1.3.2" />')
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework><UserSecretsId>abc-123</UserSecretsId></PropertyGroup>
          <ItemGroup><PackageReference Include="Azure.Extensions.AspNetCore.Configuration.Secrets" Version="1.3.2" /></ItemGroup>
        </Project>""")
    found = ids(tmp_path)
    assert {"cfg-user-secrets", "cfg-azure-key-vault", "cfg-azure-managed-identity"} <= found
    assert assess(tmp_path).rating == "A"


def test_aws_profile(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/appsettings.json", '{"AWS": {"Profile": "prod", "Region": "eu-west-1"}}')
    assert "cfg-aws-profile-credentials" in ids(tmp_path)


def test_hardcoded_credentials(tmp_path):
    web_app(tmp_path, '''
        class A { string Cs = "Server=sql01;Database=App;User Id=app;Password=Sup3rSecret!;";
                  NetworkCredential N = new NetworkCredential("svc-app", "P@ssw0rd"); }''')
    c = assess(tmp_path).components[0]
    assert any(f.rule.id == "cfg-hardcoded-credentials" and f.severity == "refactor" for f in c.findings)


def test_credentials_from_config_are_not_hardcoded(tmp_path):
    web_app(tmp_path, '''
        class A { string Cs(IConfiguration c) => $"Server={c["Host"]};Database=App;Password={c["Pwd"]};";
                  string Label = "Password"; string Tpl = "Server=x;Password=;";
                  NetworkCredential N(IConfiguration c) => new NetworkCredential(c["User"], c["Pwd"]);
                  string Hint = "Server=localhost;Database=Orchard;User Id=username;Password=password;";
                  string Hint2 = "server=.\\SQLExpress;database=YOURDB;user id=YOURUSER;password=YOURPASS"; }''')
    assert "cfg-hardcoded-credentials" not in ids(tmp_path)


def test_exe_location_that_expects_dotnet_host_is_fine(tmp_path):
    from containerizer.assess import assess
    from tests.test_engine import web_app
    web_app(tmp_path, '''class R { void M() {
        var dotnet = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.Equals(Path.GetFileNameWithoutExtension(dotnet), "dotnet")) { } } }''')
    assert "os-exe-location" not in {f.rule.id for f in assess(tmp_path).components[0].findings}


def test_localhost_endpoint_in_code(tmp_path):
    from containerizer.assess import assess
    from tests.test_engine import web_app
    web_app(tmp_path, '''class W { void M() {
        var f = new ConnectionFactory { HostName = "localhost" };
        o.Authority = "https://localhost:5005"; } }''')
    assert "cfg-localhost-endpoint-in-code" in {f.rule.id for f in assess(tmp_path).components[0].findings}


def test_localhost_listen_address_is_not_a_client_endpoint(tmp_path):
    from containerizer.assess import assess
    from tests.test_engine import web_app
    web_app(tmp_path, 'class W { void M(IWebHostBuilder b) { b.UseUrls("http://localhost:5000"); } }')
    assert "cfg-localhost-endpoint-in-code" not in {f.rule.id for f in assess(tmp_path).components[0].findings}
