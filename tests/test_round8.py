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
