"""WCF port plan (#267): CoreWCF packages chosen from the bindings found, shared contracts kept on
System.ServiceModel, WF4 workflow services recognised as WCF hosts, client-only netTcpBinding quiet."""
from pathlib import Path

from containerizer.assess import assess
from tests.test_engine import write

SERVICES = """
  <system.serviceModel>
    <services>
      <service name="Svc.Orders">
        <endpoint address="" binding="{binding}" contract="Svc.IOrders" />
      </service>
    </services>
  </system.serviceModel>"""


def netfx_exe(root: Path, name: str, code: str, config: str = "", refs=("System.ServiceModel",)) -> None:
    items = "".join(f'<Reference Include="{r}" />' for r in refs)
    write(root, f"src/{name}/{name}.csproj", f"""
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>
          <ItemGroup>{items}<Compile Include="Program.cs" /></ItemGroup>
        </Project>""")
    write(root, f"src/{name}/Program.cs", code)
    if config:
        write(root, f"src/{name}/App.config", f"<configuration>{config}</configuration>")


HOST = """using System.ServiceModel;
class Program { static void Main() { using (var h = new ServiceHost(typeof(Orders))) { h.Open(); System.Console.ReadLine(); } } }
[ServiceContract] public interface IOrders { [OperationContract] int Count(); }
public class Orders : IOrders { public int Count() => 1; }
"""


def _plan(root: Path, name: str) -> dict:
    a = assess(root)
    c = next(c for c in a.components if c.name == name)
    plan = a.migration_plans()[c.project.rel]
    return {"findings": {f.rule.id for f in c.findings},
            "wcf": next(i for i in plan["items"] if i["id"] == "port-wcf-server"), "plan": plan}


def test_nettcp_service_gets_corewcf_nettcp_and_keeps_its_config(tmp_path):
    netfx_exe(tmp_path, "Svc", HOST, SERVICES.format(binding="netTcpBinding"))
    wcf = _plan(tmp_path, "Svc")["wcf"]
    assert wcf["packages"]["add"] == ["CoreWCF.Primitives", "CoreWCF.NetTcp", "CoreWCF.ConfigurationManager"]
    steps = " ".join(wcf["steps"])
    assert "UseNetTcp" in steps and "AddServiceModelConfigurationManagerFile" in steps
    assert "change the using to CoreWCF" not in steps
    assert "clients also reference" in steps          # shared contract assemblies stay on System.ServiceModel


def test_http_and_webhttp_services(tmp_path):
    netfx_exe(tmp_path / "a", "Svc", HOST, SERVICES.format(binding="basicHttpBinding"))
    assert _plan(tmp_path / "a", "Svc")["wcf"]["packages"]["add"] == [
        "CoreWCF.Primitives", "CoreWCF.Http", "CoreWCF.ConfigurationManager"]
    rest = HOST.replace("[OperationContract] int", '[OperationContract, System.ServiceModel.Web.WebGet(UriTemplate = "n")] int')
    netfx_exe(tmp_path / "b", "Svc", rest, refs=("System.ServiceModel", "System.ServiceModel.Web"))
    wcf = _plan(tmp_path / "b", "Svc")["wcf"]
    assert wcf["packages"]["add"] == ["CoreWCF.Primitives", "CoreWCF.Http", "CoreWCF.WebHttp"]
    assert "AddServiceModelConfigurationManagerFile" not in " ".join(wcf["steps"])   # no config to keep


def test_workflow_service_host_is_a_wcf_server(tmp_path):
    netfx_exe(tmp_path, "WfHost", """using System.ServiceModel.Activities;
class Program { static void Main() {
    var host = new WorkflowServiceHost(new Onboard(), new System.Uri("http://localhost:8080/onboard"));
    host.AddServiceEndpoint("IOnboard", new System.ServiceModel.BasicHttpBinding(), "");
    host.Open(); } }
class Onboard : System.Activities.Activity { }
""", refs=("System.ServiceModel", "System.ServiceModel.Activities", "System.Activities"))
    r = _plan(tmp_path, "WfHost")
    assert "wcf-server" in r["findings"] and "wcf-client" not in r["findings"]
    assert r["wcf"]["packages"]["add"] == ["CoreWCF.Primitives", "CoreWCF.Http"]
    wf = next(i for i in r["plan"]["items"] if i["id"] == "port-wf")     # says the workflows are endpoints
    assert any("no workflow-service hosting" in s for s in wf["steps"])


def test_nettcp_client_on_netfx_is_not_a_windows_only_binding(tmp_path):
    client = """using System.ServiceModel;
class Program { static void Main() {
    var f = new ChannelFactory<IOrders>(new NetTcpBinding(), "net.tcp://orders:808/Orders"); f.CreateChannel().Count(); } }
"""
    netfx_exe(tmp_path / "c", "Client", client, """
  <system.serviceModel><bindings><netTcpBinding><binding name="tcp" /></netTcpBinding></bindings>
    <client><endpoint address="net.tcp://orders:808/Orders" binding="netTcpBinding" contract="IOrders" /></client>
  </system.serviceModel>""")
    a = assess(tmp_path / "c")
    ids = {f.rule.id for c in a.components for f in c.findings}
    assert "wcf-client" in ids and "wcf-nettcp-msmq" not in ids
    netfx_exe(tmp_path / "s", "Svc", HOST, SERVICES.format(binding="netTcpBinding"))   # the service still gets it
    assert "wcf-nettcp-msmq" in _plan(tmp_path / "s", "Svc")["findings"]
