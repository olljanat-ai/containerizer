"""Learned rules were folded into the curated set; these tests pin the curated replacements and
keep the learning path (verify --learn writing rules/learned/) working."""
import yaml

from containerizer import verify
from containerizer.assess import assess
from containerizer.generate import make_plan
from containerizer.rules import RULES_DIR, load_rules
from tests.test_engine import web_app, write
from tests.test_round7 import RULES, sev

NU1605 = """/w/src/Web/Web.csproj : error NU1605: Warning As Error: Detected package downgrade: System.IO.FileSystem from 4.3.0 to 4.0.1.
/w/src/Web/Web.csproj : error NU1605:  Web -> Integration -> SSH.NET 2016.1.0 -> System.Net.Sockets 4.1.0 -> runtime.unix.System.Net.Sockets 4.3.0 -> System.IO.FileSystem (>= 4.3.0)
"""


def worker(root, name="Jobs", refs="", packages=""):
    write(root, f"src/{name}/{name}.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk.Worker">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup>{refs}{packages}</ItemGroup>
        </Project>""")
    write(root, f"src/{name}/Program.cs", "Host.CreateDefaultBuilder(args).Build().Run();")


def lib(root, name, items):
    write(root, f"src/{name}/{name}.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup>{items}</ItemGroup>
        </Project>""")
    write(root, f"src/{name}/L.cs", "public class L { }")


def plan_of(root, name, rules=RULES):
    a = assess(root, rules)
    c = next(c for c in a.components if c.name == name)
    return make_plan(a, c, rules)


def test_learned_files_are_empty_but_loadable():
    for f in ("findings.yaml", "plan.yaml"):
        assert yaml.safe_load((RULES_DIR / "learned" / f).read_text())["rules"] == []


def test_worker_referencing_an_aspnetcore_library_gets_the_aspnet_image(tmp_path):
    lib(tmp_path, "Blocks", '<FrameworkReference Include="Microsoft.AspNetCore.App" />')
    worker(tmp_path, refs='<ProjectReference Include="../Blocks/Blocks.csproj" />')
    assert plan_of(tmp_path, "Jobs").get("aspnet_runtime") is True


def test_plain_worker_keeps_the_runtime_image(tmp_path):
    worker(tmp_path)
    assert not plan_of(tmp_path, "Jobs").get("aspnet_runtime")


def test_old_sshnet_in_the_closure_publishes_portable(tmp_path):
    lib(tmp_path, "Integration", '<PackageReference Include="SSH.NET" Version="2016.1.0" />')
    worker(tmp_path, refs='<ProjectReference Include="../Integration/Integration.csproj" />')
    assert plan_of(tmp_path, "Jobs").get("rid") == "portable"


def test_current_sshnet_keeps_the_linux_rid(tmp_path):
    worker(tmp_path, packages='<PackageReference Include="SSH.NET" Version="2024.2.0" />')
    assert plan_of(tmp_path, "Jobs").get("rid") in (None, "linux-x64")


def test_opening_localmachine_my_is_a_refactor(tmp_path):
    web_app(tmp_path, code="""
        class Certs { object Load() { var s = new X509Store(StoreName.My, StoreLocation.LocalMachine); s.Open(OpenFlags.ReadOnly); return s; } }""")
    assert sev(tmp_path, "cert-store-localmachine-code") == "refactor"


def test_localmachine_root_store_is_not_the_refactor(tmp_path):
    web_app(tmp_path, code="""
        class Certs { object Load() => new X509Store(StoreName.Root, StoreLocation.LocalMachine); }""")
    assert sev(tmp_path, "cert-store-localmachine-code") is None


def test_inproc_system_web_session_is_stateful(tmp_path):
    write(tmp_path, "src/Web/Web.config", '<configuration><system.web><sessionState mode="InProc" /></system.web></configuration>')
    web_app(tmp_path)
    a = assess(tmp_path, RULES)
    c = next(c for c in a.components if c.name == "Web")
    assert any(f.rule.id == "in-memory-session-scaleout" for f in c.state_findings)


def test_distributed_memory_cache_alone_is_not_session_state(tmp_path):
    web_app(tmp_path, code="builder.Services.AddDistributedMemoryCache();")
    assert sev(tmp_path, "in-memory-session-scaleout") is None


def test_route_paths_in_configuration_are_not_folders(tmp_path):
    worker(tmp_path)
    write(tmp_path, "src/Jobs/appsettings.json", """{"Jobs": [
        {"Name": "reindex", "Service": "Catalog", "Path": "api/search/reindex", "Cron": "0 0 1 ? * SUN"}],
        "Export": {"Path": "exports"}}""")
    a = assess(tmp_path, RULES)
    dirs = next(c for c in a.components if c.name == "Jobs").facts.get("writable_dirs", [])
    assert "api/search/reindex" not in dirs and "exports" in dirs


def test_nu1605_is_diagnosed_with_the_direct_package():
    fr, caps = verify.diagnose(NU1605, "build", verify.load_failures())
    assert fr["id"] == "build-rid-downgrade"
    assert caps["pkg"] == "SSH.NET" and caps["ver"] == "2016.1.0"


def test_learning_writes_a_general_rule_that_applies_to_other_components(tmp_path, monkeypatch):
    learned = tmp_path / "learned"
    monkeypatch.setattr(verify, "LEARNED", learned)
    app = tmp_path / "app"
    lib(app, "Integration", '<PackageReference Include="Renci.Old" Version="1.0.0" />')
    worker(app, refs='<ProjectReference Include="../Integration/Integration.csproj" />')
    worker(app, name="Feed", refs='<ProjectReference Include="../Integration/Integration.csproj" />')
    a = assess(app, RULES)
    c = next(c for c in a.components if c.name == "Jobs")
    log = NU1605.replace("SSH.NET 2016.1.0", "Renci.Old 1.0.0")
    fr, caps = verify.diagnose(log, "build", verify.load_failures())
    verify.persist_learning(a, c, make_plan(a, c, RULES), [(fr, caps, fr["fix"])])
    rules = yaml.safe_load((learned / "plan.yaml").read_text())["rules"]
    assert [r["id"] for r in rules] == ["learned-build-rid-downgrade-renci-old-1-0-0"]
    assert rules[0]["when"] == {"closure": {"package": "Renci.Old", "version": "1.0.0"}}
    both = load_rules(dirs=[RULES_DIR, learned])
    assert plan_of(app, "Feed", both).get("rid") == "portable"


def test_learning_falls_back_to_the_component_name_without_captures(tmp_path, monkeypatch):
    learned = tmp_path / "learned"
    monkeypatch.setattr(verify, "LEARNED", learned)
    worker(tmp_path / "app")
    a = assess(tmp_path / "app", RULES)
    c = a.components[0]
    fr, caps = verify.diagnose("error NU1605: Detected package downgrade", "build", verify.load_failures())
    verify.persist_learning(a, c, make_plan(a, c, RULES), [(fr, caps, fr["fix"])])
    rules = yaml.safe_load((learned / "plan.yaml").read_text())["rules"]
    assert rules[0]["when"] == {"name": "^Jobs$"}


def test_old_masstransit_service_bus_in_the_closure_publishes_portable(tmp_path):
    lib(tmp_path, "Blocks", '<PackageReference Include="MassTransit.Azure.ServiceBus.Core" Version="7.3.1" />')
    worker(tmp_path, refs='<ProjectReference Include="../Blocks/Blocks.csproj" />')
    assert plan_of(tmp_path, "Jobs").get("rid") == "portable"


def test_store_lookup_with_a_file_alternative_is_configuration(tmp_path):
    web_app(tmp_path, code="""
        class Certs {
            object Load(bool useStore, string path) {
                if (useStore) { var s = new X509Store(StoreName.My, StoreLocation.LocalMachine); s.Open(OpenFlags.ReadOnly); return s; }
                return X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(path), null);
            }
        }""")
    assert sev(tmp_path, "cert-store-localmachine-code") is None
    assert sev(tmp_path, "cert-store") == "config"
