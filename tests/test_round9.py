"""Round 9: Sitecore modules, catch-all handler web apps, message-bus endpoints, node test
harnesses, 32-bit build flags and uncalled P/Invoke declarations."""
from containerizer.assess import assess, classify_role
from containerizer.scan import scan
from tests.test_engine import write
from tests.test_round7 import RULES, rating, sev

WEB_GUID = "{349c5851-65df-11da-9384-00065b846f21};{fae04ec0-301f-11d3-bf4b-00c04f79efbc}"


def role_of(root, name):
    repo = scan(root)
    p = next(p for p in repo.projects if p.name == name)
    return classify_role(repo, p, RULES)[0]


def netfx_proj(root, rel, body="", guid=WEB_GUID, output="Library", props=""):
    write(root, rel, f"""\
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup>
            <ProjectTypeGuids>{guid}</ProjectTypeGuids>
            <OutputType>{output}</OutputType>
            <TargetFrameworkVersion>v4.7.1</TargetFrameworkVersion>
            {props}
          </PropertyGroup>
          <ItemGroup>{body}</ItemGroup>
        </Project>
        """)


# ------------------------------------------------------------------ Sitecore XP modules (Habitat)

def sitecore_module(root, name="Sitecore.Feature.News"):
    netfx_proj(root, f"src/Feature/News/code/{name}.csproj",
               '<PackageReference Include="Sitecore.Kernel" Version="9.2.0" />'
               '<PackageReference Include="Sitecore.Mvc" Version="9.2.0" />')
    write(root, "src/Feature/News/code/App_Config/Include/Feature/Feature.News.config", """\
        <configuration xmlns:patch="http://www.sitecore.net/xmlconfig/">
          <sitecore><pipelines /></sitecore>
        </configuration>
        """)
    write(root, "src/Feature/News/code/Controllers/NewsController.cs",
          "using Sitecore.Mvc.Controllers; public class NewsController : SitecoreController { }")


def test_sitecore_module_is_a_platform_component_and_not_feasible(tmp_path):
    sitecore_module(tmp_path)
    a = assess(tmp_path, RULES)
    c = a.components[0]
    assert c.role == "sitecore" and c.tier == "platform"
    assert sev(tmp_path, "sitecore-xp") == "blocker"
    assert sev(tmp_path, "netfx-target") is None      # no .NET 10 Sitecore to port onto
    assert a.rating == "E"


def test_sitecore_rendering_host_on_core_is_a_web_app(tmp_path):
    write(tmp_path, "src/Rendering/Rendering.csproj", """\
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="Sitecore.AspNet.RenderingEngine" Version="21.0.0" /></ItemGroup>
        </Project>
        """)
    write(tmp_path, "src/Rendering/Program.cs", "var app = WebApplication.CreateBuilder(args).Build(); app.Run();")
    assert role_of(tmp_path, "Rendering") == "web"
    assert rating(tmp_path) == "A"


# ------------------------------------------------------------------ catch-all IHttpHandler (Nancy on ASP.NET)

def handler_site(root, handler_type):
    netfx_proj(root, "src/Site/Site.csproj", '<Reference Include="System.Web" />')
    write(root, "src/Site/Web.config", f"""\
        <configuration>
          <system.webServer><handlers>
            <add name="App" verb="*" type="{handler_type}" path="*" />
          </handlers></system.webServer>
        </configuration>
        """)
    write(root, "src/Site/Home.cs", "public class Home { }")


def test_nancy_aspnet_host_without_global_asax_is_web(tmp_path):
    handler_site(tmp_path, "Nancy.Hosting.Aspnet.NancyHttpRequestHandler")
    assert role_of(tmp_path, "Site") == "web"
    assert rating(tmp_path) == "C"


def test_builtin_catch_all_handler_does_not_make_a_web_app(tmp_path):
    handler_site(tmp_path, "System.Web.HttpNotFoundHandler")
    assert role_of(tmp_path, "Site") == "library"


# ------------------------------------------------------------------ message-bus endpoints

def bus_console(root, extra=""):
    write(root, "src/Domain/Domain.csproj", """\
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
        </Project>
        """)
    write(root, "src/Domain/Program.cs", f"""\
        class Program {{
            static readonly ManualResetEvent Quit = new ManualResetEvent(false);
            static async Task Main() {{
                var config = new EndpointConfiguration("Domain");
                {extra}
                var endpoint = await Endpoint.Start(config);
                Console.CancelKeyPress += (s, e) => Quit.Set();
                Quit.WaitOne();
                await endpoint.Stop();
            }}
        }}
        """)


def test_nservicebus_endpoint_that_waits_is_a_worker(tmp_path):
    bus_console(tmp_path)
    assert role_of(tmp_path, "Domain") == "worker"


def test_send_only_endpoint_stays_console(tmp_path):
    bus_console(tmp_path, "config.SendOnly();")
    assert role_of(tmp_path, "Domain") == "console"


# ------------------------------------------------------------------ node test harness

def test_node_package_with_only_test_scripts_is_a_test(tmp_path):
    write(tmp_path, "tests/Web.ClientTests/package.json", """\
        {"name": "web-clienttests", "private": true,
         "scripts": {"test": "node --test ./submit.test.js"},
         "devDependencies": {"jsdom": "^29.1.1"}}
        """)
    write(tmp_path, "ui/package.json", """\
        {"name": "ui", "scripts": {"build": "vite build", "test": "vitest"},
         "dependencies": {"react": "^18.3.1"}}
        """)
    assert role_of(tmp_path, "web-clienttests") == "test"
    assert role_of(tmp_path, "ui") == "spa"


# ------------------------------------------------------------------ 32-bit build flags

def console_exe(root, props, code="class P { static void Main() { } }"):
    netfx_proj(root, "src/Tool/Tool.csproj", '<Reference Include="System" />',
               guid="{fae04ec0-301f-11d3-bf4b-00c04f79efbc}", output="Exe", props=props)
    write(root, "src/Tool/Program.cs", code)


def test_x86_default_without_native_dependency_is_config(tmp_path):
    console_exe(tmp_path, "<PlatformTarget>x86</PlatformTarget>")
    assert sev(tmp_path, "x86-only") is None
    assert sev(tmp_path, "x86-build-flag") == "config"


def test_prefer32bit_default_is_config(tmp_path):
    console_exe(tmp_path, "<PlatformTarget>AnyCPU</PlatformTarget><Prefer32Bit>true</Prefer32Bit>")
    assert sev(tmp_path, "x86-only") is None
    assert sev(tmp_path, "x86-build-flag") == "config"


def test_x86_with_called_pinvoke_is_blocker(tmp_path):
    console_exe(tmp_path, "<PlatformTarget>x86</PlatformTarget>", """\
        class P {
            [DllImport("vendor32.dll")] static extern int Init();
            static void Main() { Init(); }
        }
        """)
    assert sev(tmp_path, "x86-only") == "blocker"
    assert sev(tmp_path, "x86-build-flag") is None


# ------------------------------------------------------------------ uncalled P/Invoke declarations

def test_uncalled_pinvoke_declaration_is_not_reported(tmp_path):
    from tests.test_engine import web_app
    web_app(tmp_path, '''public static class NativeMethods {
        [DllImport("mqrt.dll", CharSet = CharSet.Unicode)]
        public static extern int MQOpenQueue(string formatName, int access, int shareMode, ref IntPtr hQueue);
    }''')
    assert sev(tmp_path, "pinvoke-vendor") is None


def test_called_pinvoke_declaration_is_reported(tmp_path):
    from tests.test_engine import web_app
    web_app(tmp_path, '''public static class NativeMethods {
        [DllImport("mqrt.dll", CharSet = CharSet.Unicode)]
        public static extern int MQOpenQueue(string formatName, int access, int shareMode, ref IntPtr hQueue);
    }
    class Q { int Open(IntPtr h) => NativeMethods.MQOpenQueue("q", 1, 0, ref h); }''')
    assert sev(tmp_path, "pinvoke-vendor") == "blocker"
