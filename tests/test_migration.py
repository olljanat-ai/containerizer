"""Tests for rules/35-migration.yaml (.NET Framework -> modern .NET migration signals)."""
from pathlib import Path

from containerizer.assess import assess
from tests.test_engine import web_app, write


def ids(root: Path, name: str | None = None) -> set[str]:
    comps = assess(root).components
    c = next(c for c in comps if name is None or c.name == name)
    return {f.rule.id for f in c.findings if not f.dormant}


def netfx_web(root: Path, web_config: str = "<configuration/>", code: str = "", extra: str = "") -> None:
    write(root, "src/Site/Site.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>
          <ItemGroup><Reference Include="System.Web" />{extra}</ItemGroup></Project>""")
    write(root, "src/Site/Web.config", web_config)
    write(root, "src/Site/Global.asax", "<%@ Application %>")
    write(root, "src/Site/Code.cs", code or "class C {}")


# ---------------------------------------------------------------- runtime PNSE APIs in net8 code
def test_binaryformatter_flagged_on_net8(tmp_path):
    web_app(tmp_path, "class S { object M(Stream s) => new BinaryFormatter().Deserialize(s); }")
    c = assess(tmp_path).components[0]
    assert "mig-binaryformatter" in {f.rule.id for f in c.findings}
    assert c.verdict == "refactor"


def test_binaryformatter_word_in_comment_or_other_type_ignored(tmp_path):
    web_app(tmp_path, "// we removed the BinaryFormatter here\nclass S { MyBinaryFormatterOptions o; }")
    assert "mig-binaryformatter" not in ids(tmp_path)


def test_thread_abort_and_begininvoke(tmp_path):
    web_app(tmp_path, """
        class W {
            Thread _workerThread;
            void Stop() { _workerThread.Abort(); }
            void Go(Func<int> f) { var r = f.BeginInvoke(null, null); f.EndInvoke(r); }
        }""")
    found = ids(tmp_path)
    assert {"mig-thread-abort", "mig-delegate-begininvoke"} <= found


def test_abort_on_non_thread_and_control_begininvoke_ignored(tmp_path):
    web_app(tmp_path, """
        class W {
            void M(HttpWebRequest request, CancellationTokenSource cts, Control c) {
                request.Abort(); transaction.Abort(); c.BeginInvoke(new Action(() => {}));
            }
        }""")
    found = ids(tmp_path)
    assert "mig-thread-abort" not in found and "mig-delegate-begininvoke" not in found


def test_codedom_reflectiononly_xslt_crypto(tmp_path):
    web_app(tmp_path, """
        class G {
            void A(CSharpCodeProvider p, CompilerParameters o) { p.CompileAssemblyFromSource(o, "class X{}"); }
            void B() { Assembly.ReflectionOnlyLoadFrom("x.dll"); }
            void C() { var s = new XsltSettings(false, true); }
            void D() { var cp = new CspParameters { KeyContainerName = "k" }; }
        }""")
    found = ids(tmp_path)
    assert {"mig-codedom-compile", "mig-reflection-only-load", "mig-xslt-script", "mig-crypto-pnse"} <= found


def test_msxsl_script_in_stylesheet(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Report.xslt", '<xsl:stylesheet><msxsl:script language="C#" implements-prefix="u"/></xsl:stylesheet>')
    assert "mig-xslt-script" in ids(tmp_path)


def test_codedom_generation_only_and_aes_ignored(tmp_path):
    web_app(tmp_path, """
        class G {
            void A(CSharpCodeProvider p, CodeCompileUnit u, TextWriter w) { p.GenerateCodeFromCompileUnit(u, w, null); }
            void B() { using var aes = Aes.Create(); aes.BlockSize = 128; }
        }""")
    found = ids(tmp_path)
    assert "mig-codedom-compile" not in found and "mig-crypto-pnse" not in found


def test_cas_is_info_only(tmp_path):
    web_app(tmp_path, '[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)] class P {}')
    c = assess(tmp_path).components[0]
    assert "mig-cas" in {f.rule.id for f in c.findings}
    assert c.verdict in ("info", "config")


def test_servicepointmanager_callback_on_core(tmp_path):
    web_app(tmp_path, "class T { void M() { ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true; } }")
    assert "mig-servicepointmanager-tls" in ids(tmp_path)


def test_custom_config_section_is_config(tmp_path):
    web_app(tmp_path, "public class EngineSection : ConfigurationSection { }")
    c = assess(tmp_path).components[0]
    assert "mig-custom-config-section" in {f.rule.id for f in c.findings}
    assert c.verdict in ("info", "config")


def test_extensions_configuration_section_usage_ignored(tmp_path):
    web_app(tmp_path, 'class X { void M(IConfiguration c) { var s = c.GetSection("A") as ConfigurationSection; } }')
    assert "mig-custom-config-section" not in ids(tmp_path)


# ---------------------------------------------------------------- System.Web port sizing
def test_netfx_web_port_sizing_signals(tmp_path):
    netfx_web(tmp_path, """
        <configuration>
          <system.web>
            <sessionState mode="SQLServer" sqlConnectionString="x" />
            <httpModules><add name="ErrorLog" type="Elmah.ErrorLogModule, Elmah" /></httpModules>
            <membership><providers><add name="M" type="System.Web.Security.SqlMembershipProvider" /></providers></membership>
            <outputCacheSettings />
          </system.web>
          <system.net><mailSettings><smtp from="a@b.c"><network host="smtp01" /></smtp></mailSettings></system.net>
          <system.identityModel><identityConfiguration /></system.identityModel>
        </configuration>""", code="""
        using System.Web.Caching;
        using Microsoft.AspNet.SignalR;
        class C {
            object Get() => HttpRuntime.Cache["k"];
            void Send() { using var s = new SmtpClient(); }
            string J(object o) => new JavaScriptSerializer().Serialize(o);
        }
        public class Ws : System.Web.Services.Protocols.SoapHttpClientProtocol {}""")
    a = assess(tmp_path)
    c = a.components[0]
    found = {f.rule.id for f in c.findings}
    assert {"mig-session-out-of-proc", "mig-http-modules-handlers", "mig-membership-providers",
            "mig-output-cache", "mig-smtp-mailsettings", "mig-wif", "mig-system-web-cache",
            "mig-aspnet-signalr", "mig-javascriptserializer", "mig-asmx-client"} <= found
    # port-sizing rules never escalate beyond the netfx rewrite
    assert c.verdict == "rewrite" and a.rating == "C"
    assert all(f.rule.severity in ("info", "config", "refactor") for f in c.findings if f.rule.id.startswith("mig-"))


def test_default_template_handlers_ignored(tmp_path):
    netfx_web(tmp_path, """
        <configuration><system.webServer>
          <modules><remove name="FormsAuthentication" /></modules>
          <handlers>
            <remove name="ExtensionlessUrlHandler-Integrated-4.0" />
            <add name="ExtensionlessUrlHandler-Integrated-4.0" path="*." verb="*" type="System.Web.Handlers.TransferRequestHandler" />
          </handlers>
        </system.webServer>
        <system.web><sessionState mode="InProc" /></system.web></configuration>""")
    found = ids(tmp_path)
    assert "mig-http-modules-handlers" not in found and "mig-session-out-of-proc" not in found


def test_aspnetcore_output_cache_and_signalr_core_ignored(tmp_path):
    web_app(tmp_path, """
        using Microsoft.AspNetCore.SignalR;
        class C { [OutputCache(Duration = 60)] public string Get() => ""; }""")
    found = ids(tmp_path)
    assert "mig-output-cache" not in found and "mig-aspnet-signalr" not in found


def test_signalr_client_only_is_info(tmp_path):
    web_app(tmp_path, "using Microsoft.AspNet.SignalR.Client;\nclass P {}")
    found = ids(tmp_path)
    assert "mig-aspnet-signalr-client" in found and "mig-aspnet-signalr" not in found


def test_wcf_message_security(tmp_path):
    netfx_web(tmp_path, """
        <configuration><system.serviceModel><bindings><wsHttpBinding><binding name="b">
          <security mode="Message"><message clientCredentialType="Windows" /></security>
        </binding></wsHttpBinding></bindings></system.serviceModel></configuration>""")
    assert "mig-wcf-message-security" in ids(tmp_path)


def test_wcf_transport_security_ignored(tmp_path):
    netfx_web(tmp_path, """
        <configuration><system.serviceModel><bindings><basicHttpBinding><binding name="b">
          <security mode="Transport" />
        </binding></basicHttpBinding></bindings></system.serviceModel></configuration>""")
    assert "mig-wcf-message-security" not in ids(tmp_path)


# ---------------------------------------------------------------- libraries / tooling
def test_enterprise_library_unity_vb(tmp_path):
    netfx_web(tmp_path, code="using Microsoft.Practices.Unity;\nclass C {}",
              extra='<Reference Include="Microsoft.Practices.EnterpriseLibrary.Data, Version=6.0.0.0" />'
                    '<Reference Include="Microsoft.VisualBasic.Compatibility" />')
    write(tmp_path, "src/Site/Module1.vb", "Module M\n Sub S()\n My.Application.Log.WriteEntry(\"x\")\n End Sub\nEnd Module")
    found = ids(tmp_path)
    assert {"mig-enterprise-library", "mig-unity-practices", "mig-vb-compatibility", "mig-vb-my-namespace"} <= found


def test_vb_my_settings_ignored(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Module1.vb", "Module M\n Dim x = My.Settings.Url\n Dim y = My.Computer.FileSystem.ReadAllText(\"a\")\nEnd Module")
    assert "mig-vb-my-namespace" not in ids(tmp_path)


def test_httpcontext_in_netfx_library(tmp_path):
    netfx_web(tmp_path)
    write(tmp_path, "src/Site/Site.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>
          <ItemGroup><Reference Include="System.Web" /><ProjectReference Include="../Lib/Lib.csproj" /></ItemGroup></Project>""")
    write(tmp_path, "src/Lib/Lib.csproj", """
        <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>""")
    write(tmp_path, "src/Lib/CurrentUser.cs", "public class CurrentUser { public string Name => HttpContext.Current.User.Identity.Name; }")
    c = assess(tmp_path).components[0]
    found = {f.rule.id for f in c.findings}
    assert "mig-httpcontext-in-library" in found


def test_build_artifacts_edmx_t4_packages_config_webdeploy(tmp_path):
    netfx_web(tmp_path)
    write(tmp_path, "src/Site/Model.edmx", "<edmx:Edmx/>")
    write(tmp_path, "src/Site/Model.tt", "<#@ template #>")
    write(tmp_path, "src/Site/packages.config", '<packages><package id="EntityFramework" version="6.4.4" /></packages>')
    write(tmp_path, "src/Site/Web.Release.config", "<configuration/>")
    found = ids(tmp_path)
    assert {"mig-ef6-edmx", "mig-t4-templates", "mig-packages-config", "mig-webdeploy-params"} <= found


def test_plain_net8_web_has_no_migration_findings(tmp_path):
    web_app(tmp_path, """
        class S {
            string J(object o) => System.Text.Json.JsonSerializer.Serialize(o);
            Task Run(Func<int> f) => Task.Run(f);
        }""")
    write(tmp_path, "src/Web/web.config", '<configuration><system.webServer><handlers>'
          '<add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" /></handlers></system.webServer></configuration>')
    assert not {i for i in ids(tmp_path) if i.startswith("mig-")}


def test_msajax_script_and_wcf_connected_service_ignored(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/Scripts/MicrosoftAjax.js", "Sys.Serialization.JavaScriptSerializer=function(){};")
    write(tmp_path, "src/Web/Connected Services/Svc/CatalogService.disco", "<discovery/>")
    found = ids(tmp_path)
    assert "mig-javascriptserializer" not in found and "mig-asmx-client" not in found
