"""Hosting-model and cloud-coupling rules (rules/35-hosting.yaml)."""
from containerizer.assess import assess
from tests.test_engine import web_app, write


def ids(c):
    return {f.rule.id for f in c.findings}


def repo_ids(a):
    return {f.rule.id for f in a.repo_findings}


def lib_project(root, rel, packages="", tfm="net8.0", props=""):
    write(root, rel, f"""
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>{tfm}</TargetFramework>{props}</PropertyGroup>
          <ItemGroup>{packages}</ItemGroup>
        </Project>""")


# ---------------------------------------------------------------- Azure Functions / WebJobs

def test_functions_inprocess_is_worker_needing_refactor(tmp_path):
    lib_project(tmp_path, "src/Fn/Fn.csproj", '<PackageReference Include="Microsoft.NET.Sdk.Functions" Version="4.4.0" />',
                props="<AzureFunctionsVersion>v4</AzureFunctionsVersion>")
    write(tmp_path, "src/Fn/Orders.cs", """
        public static class Orders {
          [FunctionName("Orders")] public static IActionResult Run([HttpTrigger] HttpRequest req) => null; }""")
    a = assess(tmp_path)
    c = a.components[0]
    assert c.role == "worker"
    assert "host-azure-functions-inprocess" in ids(c)
    assert "host-azure-functions-isolated" not in ids(c)
    assert c.verdict == "refactor" and a.rating == "B"


def test_functions_isolated_is_config_and_durable(tmp_path):
    write(tmp_path, "src/Fn/Fn.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup>
          <ItemGroup>
            <PackageReference Include="Microsoft.Azure.Functions.Worker" Version="1.23.0" />
            <PackageReference Include="Microsoft.Azure.Functions.Worker.Sdk" Version="1.18.0" />
            <PackageReference Include="Microsoft.Azure.Functions.Worker.Extensions.DurableTask" Version="1.1.0" />
          </ItemGroup>
        </Project>""")
    write(tmp_path, "src/Fn/Program.cs", "var host = new HostBuilder().ConfigureFunctionsWorkerDefaults().Build(); host.Run();")
    a = assess(tmp_path)
    c = a.components[0]
    assert c.role == "worker"       # not a run-once console CronJob
    assert {"host-azure-functions-isolated", "host-durable-functions"} <= ids(c)
    assert c.verdict == "config" and a.rating == "A"


def test_shared_library_with_functions_worker_package_is_not_flagged(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Shared/Shared.csproj" /></ItemGroup>
        </Project>""")
    lib_project(tmp_path, "src/Shared/Shared.csproj", '<PackageReference Include="Microsoft.Azure.Functions.Worker" Version="1.23.0" />')
    write(tmp_path, "src/Shared/Dto.cs", "public class Dto {}")
    a = assess(tmp_path)
    web = next(c for c in a.components if c.role == "web")
    assert not {i for i in ids(web) if i.startswith("host-azure-functions")}


def test_webjobs_sdk(tmp_path):
    write(tmp_path, "src/Job/Job.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup>
          <ItemGroup><PackageReference Include="Microsoft.Azure.WebJobs" Version="3.0.39" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Job/Program.cs", "var b = new HostBuilder().ConfigureWebJobs(b => b.AddAzureStorageQueues()); b.Build().Run();")
    write(tmp_path, "src/Job/settings.job", '{"schedule": "0 */5 * * * *"}')
    c = assess(tmp_path).components[0]
    assert "host-webjobs-sdk" in ids(c)


# ---------------------------------------------------------------- Cloud Services / Service Fabric

def test_cloud_services_worker_role(tmp_path):
    write(tmp_path, "src/Worker/Worker.csproj", """
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup><OutputType>Library</OutputType><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion></PropertyGroup>
          <ItemGroup><Reference Include="Microsoft.WindowsAzure.ServiceRuntime" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Worker/WorkerRole.cs", """
        using Microsoft.WindowsAzure.ServiceRuntime;
        public class WorkerRole : RoleEntryPoint {
          public override void Run() { var s = RoleEnvironment.GetConfigurationSettingValue("Queue"); } }""")
    write(tmp_path, "src/Cloud/ServiceDefinition.csdef", "<ServiceDefinition name='x'><WorkerRole name='Worker'/></ServiceDefinition>")
    a = assess(tmp_path)
    c = next(c for c in a.components if c.name == "Worker")
    assert c.role == "worker"
    assert "host-cloud-services-classic" in ids(c)
    assert c.verdict == "rewrite" and a.rating == "C"
    assert "host-cloud-service-definition" in repo_ids(a)


def test_service_fabric_stateless_vs_stateful(tmp_path):
    sf = '<PackageReference Include="Microsoft.ServiceFabric.Services" Version="6.0.0" />'
    for name, base in (("Api", "StatelessService"), ("Cart", "StatefulService")):
        write(tmp_path, f"src/{name}/{name}.csproj", f"""
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup>
              <ItemGroup>{sf}</ItemGroup>
            </Project>""")
        write(tmp_path, f"src/{name}/Program.cs", f"""
            ServiceRuntime.RegisterServiceAsync("{name}Type", ctx => new {name}(ctx)).GetAwaiter().GetResult();
            internal sealed class {name} : {base} {{ }}""")
    a = assess(tmp_path)
    by = {c.name: c for c in a.components}
    assert by["Api"].role == "worker" and by["Cart"].role == "worker"
    assert "host-service-fabric-stateless" in ids(by["Api"]) and by["Api"].verdict == "refactor"
    assert "host-service-fabric-stateful" in ids(by["Cart"]) and by["Cart"].verdict == "rewrite"
    assert "host-service-fabric-stateless" not in ids(by["Cart"])


# ---------------------------------------------------------------- App Service / Lambda

def test_app_service_coupling_and_easy_auth(tmp_path):
    web_app(tmp_path, """
        class Who { string M(HttpRequest r) {
          var p = r.Headers["X-MS-CLIENT-PRINCIPAL"];
          return Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") + @"D:\\home\\data"; } }""")
    c = assess(tmp_path).components[0]
    assert {"host-app-service-coupling", "host-app-service-easyauth"} <= ids(c)
    assert c.verdict == "refactor"


def test_website_word_in_text_does_not_trigger(tmp_path):
    web_app(tmp_path, 'class X { string Url = "https://example.com/website_home"; string S = "WEBSITE"; }')
    c = assess(tmp_path).components[0]
    assert "host-app-service-coupling" not in ids(c)
    assert "host-app-service-easyauth" not in ids(c)


def test_lambda_handler_vs_aspnetcore_lambda(tmp_path):
    lib_project(tmp_path, "src/Fn/Fn.csproj", '<PackageReference Include="Amazon.Lambda.Core" Version="2.2.0" />'
                '<PackageReference Include="Amazon.Lambda.SQSEvents" Version="2.2.0" />')
    write(tmp_path, "src/Fn/Function.cs", """
        [assembly: LambdaSerializer(typeof(DefaultLambdaJsonSerializer))]
        public class Function { public Task Handle(SQSEvent e, ILambdaContext context) => Task.CompletedTask; }""")
    a = assess(tmp_path)
    c = a.components[0]
    assert c.role == "worker" and "host-aws-lambda-handler" in ids(c) and c.verdict == "refactor"
    assert not c.uncertain

    other = tmp_path / "other"
    web_app(other, packages='<PackageReference Include="Amazon.Lambda.AspNetCoreServer.Hosting" Version="1.7.0" />')
    c2 = assess(other).components[0]
    assert "host-aws-lambda-aspnetcore" in ids(c2) and "host-aws-lambda-handler" not in ids(c2)
    assert c2.verdict == "config"


# ---------------------------------------------------------------- Blazor / gRPC / proxy

def test_blazor_server_and_grpc(tmp_path):
    web_app(tmp_path, """
        builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        builder.Services.AddGrpc();
        app.MapGrpcService<GreeterService>();""")
    c = assess(tmp_path).components[0]
    assert {"host-blazor-server", "host-grpc-server"} <= ids(c)
    assert c.verdict == "config"


def test_grpc_client_only_is_not_server(tmp_path):
    web_app(tmp_path, 'builder.Services.AddGrpcClient<Greeter.GreeterClient>(o => o.Address = new Uri("http://x"));')
    assert "host-grpc-server" not in ids(assess(tmp_path).components[0])


def test_blazor_wasm_standalone(tmp_path):
    write(tmp_path, "src/Client/Client.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.BlazorWebAssembly">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup>
        </Project>""")
    write(tmp_path, "src/Client/Program.cs", "var b = WebAssemblyHostBuilder.CreateDefault(args); await b.Build().RunAsync();")
    assert "host-blazor-wasm-standalone" in ids(assess(tmp_path).components[0])


def test_hosted_blazor_client_does_not_flag_server(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><ProjectReference Include="../Client/Client.csproj" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Client/Client.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.BlazorWebAssembly">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
        </Project>""")
    web = next(c for c in assess(tmp_path).components if c.name == "Web")
    assert "host-blazor-wasm-standalone" not in ids(web)


def test_forwarded_headers(tmp_path):
    web_app(tmp_path, "builder.Services.AddAuthentication().AddOpenIdConnect(o => {});")
    assert "host-forwarded-headers-missing" in ids(assess(tmp_path).components[0])

    ok = tmp_path / "ok"
    web_app(ok, "builder.Services.AddAuthentication().AddOpenIdConnect(o => {}); app.UseForwardedHeaders();")
    assert "host-forwarded-headers-missing" not in ids(assess(ok).components[0])

    plain = tmp_path / "plain"      # template-style HTTPS redirection alone is not flagged
    web_app(plain, "app.UseHsts(); app.UseHttpsRedirection();")
    assert "host-forwarded-headers-missing" not in ids(assess(plain).components[0])


def test_kestrel_https_in_code_not_redirection(tmp_path):
    web_app(tmp_path, 'builder.WebHost.ConfigureKestrel(k => k.ListenAnyIP(5001, l => l.UseHttps("cert.pfx", "pw")));')
    assert "host-kestrel-https-code" in ids(assess(tmp_path).components[0])
    other = tmp_path / "o"
    web_app(other, "app.UseHttpsRedirection(); var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = null };")
    assert "host-kestrel-https-code" not in ids(assess(other).components[0])


def test_ancm_web_config_and_timeouts(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/web.config", """
        <configuration><system.webServer>
          <aspNetCore processPath="dotnet" arguments=".\\Web.dll" hostingModel="outofprocess" requestTimeout="00:20:00">
            <environmentVariables><environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Staging" /><environmentVariable name="Api__BaseUrl" value="http://x" /></environmentVariables>
          </aspNetCore></system.webServer></configuration>""")
    c = assess(tmp_path).components[0]
    assert {"host-ancm-env-vars", "host-long-request-timeout"} <= ids(c)
    assert "host-ancm-webconfig" not in ids(c)

    short = tmp_path / "short"
    web_app(short)
    write(short, "src/Web/web.config", '<configuration><aspNetCore processPath="dotnet" requestTimeout="00:02:00"><environmentVariables><environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production" /></environmentVariables></aspNetCore></configuration>')
    c2 = assess(short).components[0]
    assert "host-ancm-webconfig" in ids(c2) and "host-long-request-timeout" not in ids(c2)
    assert c2.verdict in ("info", "config")


# ---------------------------------------------------------------- clustering / discovery

def test_orleans_localhost_vs_kubernetes(tmp_path):
    web_app(tmp_path, "builder.Host.UseOrleans(s => s.UseLocalhostClustering());",
            packages='<PackageReference Include="Microsoft.Orleans.Server" Version="8.2.0" />')
    c = assess(tmp_path).components[0]
    assert {"host-orleans-cluster", "host-orleans-localhost-clustering"} <= ids(c)
    assert c.verdict == "refactor"

    good = tmp_path / "good"
    web_app(good, """builder.Host.UseOrleans(s => {
        if (builder.Environment.IsDevelopment()) s.UseLocalhostClustering();
        else { s.UseKubernetesHosting(); s.UseAdoNetClustering(o => {}); } });""",
            packages='<PackageReference Include="Microsoft.Orleans.Server" Version="8.2.0" />')
    ids2 = ids(assess(good).components[0])
    assert "host-orleans-cluster" not in ids2 and "host-orleans-localhost-clustering" not in ids2


def test_akka_dapr_discovery(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Akka.Cluster.Hosting" Version="1.5.0" />'
                               '<PackageReference Include="Dapr.AspNetCore" Version="1.14.0" />'
                               '<PackageReference Include="Steeltoe.Discovery.Eureka" Version="3.2.0" />')
    c = assess(tmp_path).components[0]
    assert {"host-akka-cluster", "host-dapr", "host-service-discovery"} <= ids(c)
    assert not c.uncertain

    k8s = tmp_path / "k8s"
    web_app(k8s, packages='<PackageReference Include="Akka.Cluster.Hosting" Version="1.5.0" />'
                          '<PackageReference Include="Akka.Discovery.KubernetesApi" Version="1.5.0" />')
    assert "host-akka-cluster" not in ids(assess(k8s).components[0])


# ---------------------------------------------------------------- publish settings / info rules

def test_functions_new_msbuild_sdk_library_output(tmp_path):
    write(tmp_path, "src/Fn/Fn.csproj", """
        <Project Sdk="Azure.Functions.Sdk/1.0.0">
          <PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="Microsoft.Azure.Functions.Worker" Version="2.52.0" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Fn/host.json", '{"version": "2.0"}')
    a = assess(tmp_path)
    assert a.components and a.components[0].role == "worker"
    assert "host-azure-functions-isolated" in ids(a.components[0])


def test_conditional_aot_is_not_flagged(tmp_path):
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework>
            <PublishAot Condition="'$(EnableAot)' == 'true'">true</PublishAot></PropertyGroup>
        </Project>""")
    write(tmp_path, "src/Web/Program.cs", 'var app = WebApplication.CreateBuilder(args).Build(); app.MapDefaultEndpoints(); app.Run();')
    found = ids(assess(tmp_path).components[0])
    assert "host-publish-aot" not in found and "host-no-health-endpoint" not in found


def test_publish_settings(tmp_path):
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework><PublishAot>true</PublishAot>
            <PublishSingleFile>true</PublishSingleFile></PropertyGroup>
        </Project>""")
    write(tmp_path, "src/Web/Program.cs", 'var app = WebApplication.CreateSlimBuilder(args).Build(); app.MapGet("/healthz", () => "ok"); app.Run();')
    c = assess(tmp_path).components[0]
    assert {"host-publish-aot", "host-publish-singlefile"} <= ids(c)


def test_info_rules_never_change_verdict(tmp_path):
    """Info-only hosting signals leave a plain web app ready (verdict info, rating A)."""
    web_app(tmp_path, packages='<PackageReference Include="Microsoft.ApplicationInsights.AspNetCore" Version="2.22.0" />'
                               '<PackageReference Include="Dapr.AspNetCore" Version="1.14.0" />')
    write(tmp_path, "src/Web/web.config", '<configuration><aspNetCore processPath="dotnet" /></configuration>')
    write(tmp_path, "Dockerfile", "FROM mcr.microsoft.com/dotnet/aspnet:8.0\nCOPY . /app\n")
    write(tmp_path, "docker-compose.yml", "services:\n  web:\n    build: .\n")
    write(tmp_path, "deploy/chart/Chart.yaml", "apiVersion: v2\nname: web\n")
    write(tmp_path, "setup/Product.wxs", "<Wix/>")
    a = assess(tmp_path)
    c = a.components[0]
    found = ids(c)
    assert {"host-application-insights", "host-dapr", "host-ancm-webconfig"} <= found
    assert all(f.severity == "info" for f in c.findings if f.rule.id.startswith("host-"))
    assert c.verdict == "info" and a.rating == "A"
    assert {"host-linux-container-present", "host-docker-compose-present",
            "host-kubernetes-manifests-present", "host-installer-project"} <= repo_ids(a)
    assert "host-windows-container-present" not in repo_ids(a)


def test_windows_dockerfile_is_not_linux(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "Dockerfile", "FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8.1-windowsservercore-ltsc2022 AS base\nFROM base AS final\n")
    write(tmp_path, "wwwroot/js/dockerfile.4db8cf4d.js", "FROM ubuntu:22.04")   # editor syntax bundle, not a Dockerfile
    r = repo_ids(assess(tmp_path))
    assert "host-windows-container-present" in r and "host-linux-container-present" not in r


def test_multi_os_dockerfile_reports_both(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "Dockerfile", "FROM mcr.microsoft.com/dotnet/aspnet:10.0-nanoserver-ltsc2025 AS w\n"
                                  "FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS l\n")
    r = repo_ids(assess(tmp_path))
    assert {"host-windows-container-present", "host-linux-container-present"} <= r


def test_no_health_endpoint_and_filesystemwatcher(tmp_path):
    write(tmp_path, "src/Web/Web.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>""")
    write(tmp_path, "src/Web/Program.cs", """
        var app = WebApplication.CreateBuilder(args).Build();
        var w = new FileSystemWatcher(@"/drop") { EnableRaisingEvents = true };
        app.Run();""")
    c = assess(tmp_path).components[0]
    assert {"host-no-health-endpoint", "host-filesystemwatcher"} <= ids(c)
    other = tmp_path / "o"
    web_app(other)       # has /healthz
    assert "host-no-health-endpoint" not in ids(assess(other).components[0])
