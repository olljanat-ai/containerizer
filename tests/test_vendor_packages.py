"""Vendor / third-party package rules (rules/35-vendor-packages.yaml) and the
Linux-safe catalog (rules/packages-thirdparty.yaml)."""
import re
from pathlib import Path

import pytest
import yaml

from containerizer.assess import assess
from containerizer.rules import load_rules
from tests.test_engine import web_app, write

RULES = Path(__file__).resolve().parent.parent / "rules"
VENDOR = yaml.safe_load((RULES / "35-vendor-packages.yaml").read_text())
CATALOG = yaml.safe_load((RULES / "packages-thirdparty.yaml").read_text())


def pkg(*names: str) -> str:
    return "".join(f'<PackageReference Include="{n}" Version="1.0.0" />' for n in names)


def ids_of(tmp_path, code: str = "", packages: str = "") -> set[str]:
    web_app(tmp_path, code=code, packages=packages)
    return {f.rule.id for f in assess(tmp_path).components[0].findings}


def full(pattern: str, name: str) -> bool:
    return bool(re.match(f"^(?:{pattern})$", name, re.I))


# ------------------------------------------------------------------ rule set

def test_vendor_rules_are_complete():
    rules = [r for r in load_rules() if r.id.startswith("pkg-")]
    assert len(rules) >= 30
    for r in rules:
        assert r.title and r.why and r.fix and r.category and r.applies_to == ["dotnet"], r.id


# ------------------------------------------------------- package -> rule id

@pytest.mark.parametrize("package,rule", [
    ("CrystalDecisions.CrystalReports.Engine", "pkg-crystal-reports"),
    ("Stimulsoft.Reports.Web", "pkg-stimulsoft-netfx"),
    ("Telerik.Web.UI", "pkg-web-ui-suite-systemweb"),
    ("DevExpress.Web.Mvc5", "pkg-web-ui-suite-systemweb"),
    ("CefSharp.OffScreen.NETCore", "pkg-windows-browser-engine"),
    ("Microsoft.Web.WebView2", "pkg-windows-browser-engine"),
    ("EO.Pdf", "pkg-windows-browser-engine"),
    ("Syncfusion.HtmlToPdfConverter.Net.Windows", "pkg-syncfusion-htmltopdf-windows"),
    ("Microsoft.Office.Interop.Excel", "pkg-office-interop-package"),
    ("NetOfficeFw.Excel", "pkg-netoffice"),
    ("ExcelDna.AddIn", "pkg-office-addin"),
    ("Microsoft.Windows.Compatibility", "pkg-windows-compatibility-pack"),
    ("Microsoft.Windows.SDK.Contracts", "pkg-winrt-packages"),
    ("System.Speech", "pkg-system-speech"),
    ("Microsoft.Web.Administration", "pkg-web-administration"),
    ("TaskScheduler", "pkg-taskscheduler-api"),
    ("Microsoft.PowerShell.SDK", "pkg-powershell-sdk"),
    ("Microsoft.PowerShell.5.1.ReferenceAssemblies", "pkg-powershell-windows"),
    ("NAudio.WinMM", "pkg-naudio-windows"),
    ("NAudio.Lame", "pkg-naudio-windows"),
    ("DasMulli.Win32.ServiceUtils", "pkg-windows-service-hosts"),
    ("WinSCP", "pkg-winscp"),
    ("chilkat-x64", "pkg-chilkat-windows"),
    ("Microsoft.Exchange.WebServices", "pkg-ews-managed-api"),
    ("WindowsAzure.ServiceBus", "pkg-legacy-azure-servicebus"),
    ("Oracle.DataAccess.x64", "pkg-oracle-unmanaged"),
    ("Net.IBM.Data.Db2", "pkg-db2-windows-package"),
    ("IBM.Data.Informix", "pkg-informix"),
    ("PdfiumViewer", "pkg-pdfiumviewer"),
    ("Ghostscript.NET", "pkg-ghostscript-net"),
    ("Tesseract", "pkg-tesseract-native"),
    ("GdPicture", "pkg-imaging-sdk"),
    ("Aspose.Words", "pkg-document-engine-fonts"),
    ("Telerik.Windows.Documents.Fixed", "pkg-telerik-documents-netfx"),
    ("System.Windows.Forms.DataVisualization", "pkg-mschart"),
    ("Microsoft.Playwright", "pkg-headless-browser"),
])
def test_package_triggers_rule(tmp_path, package, rule):
    assert rule in ids_of(tmp_path, packages=pkg(package))


@pytest.mark.parametrize("code,rule", [
    ("using CrystalDecisions.CrystalReports.Engine;", "pkg-crystal-reports"),
    ("using Oracle.DataAccess.Client;", "pkg-oracle-unmanaged"),
    ("using Sybase.Data.AseClient;", "pkg-sybase-ase"),
    ("using IBM.Data.DB2;", "pkg-db2-netfx-provider"),
    ("using SAP.Middleware.Connector;", "pkg-sap-nco"),
    ("using Microsoft.Exchange.WebServices.Data;", "pkg-ews-managed-api"),
    ("using WinSCP;", "pkg-winscp"),
    ("using System.Speech.Synthesis;", "pkg-system-speech"),
    ("using Microsoft.Win32.TaskScheduler;", "pkg-taskscheduler-api"),
    ("using System.Web.UI.DataVisualization.Charting;", "pkg-mschart"),
    ("using NetOffice.ExcelApi;", "pkg-netoffice"),
])
def test_code_triggers_rule(tmp_path, code, rule):
    assert rule in ids_of(tmp_path, code=code)


def test_old_style_assembly_references(tmp_path):
    write(tmp_path, "src/Svc/Svc.csproj", """
        <Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>
          <ItemGroup>
            <Reference Include="sapnco, Version=3.0.0.42, Culture=neutral" />
            <Reference Include="Sybase.AdoNet4.AseClient" />
            <Reference Include="DevExpress.XtraGrid.v21.2, Version=21.2.5.0" />
            <Reference Include="System.Management.Automation" />
          </ItemGroup>
        </Project>""")
    write(tmp_path, "src/Svc/Program.cs", "class P { static void Main() {} }")
    ids = {f.rule.id for f in assess(tmp_path).components[0].findings}
    assert {"pkg-sap-nco", "pkg-sybase-ase", "pkg-desktop-ui-library-ref", "pkg-powershell-windows"} <= ids


# ------------------------------------------------------------- UI suites

def test_desktop_suite_used_in_server_code_blocks(tmp_path):
    web_app(tmp_path, code="using DevExpress.XtraGrid.Views.Grid;", packages=pkg("DevExpress.Win.Grid"))
    c = assess(tmp_path).components[0]
    ids = {f.rule.id for f in c.findings}
    assert "pkg-desktop-ui-library-code" in ids and "pkg-desktop-ui-library-ref" not in ids
    assert c.verdict == "blocker"


def test_desktop_suite_reference_only_is_refactor(tmp_path):
    c_ids = ids_of(tmp_path, packages=pkg("Syncfusion.Pdf.WinForms"))
    assert "pkg-desktop-ui-library-ref" in c_ids and "pkg-desktop-ui-library-code" not in c_ids


def test_cross_platform_devexpress_reporting_is_not_desktop(tmp_path):
    ids = ids_of(tmp_path, code="using DevExpress.XtraReports.UI;\nusing DevExpress.XtraPrinting;",
                 packages=pkg("DevExpress.AspNetCore.Reporting", "DevExpress.Reporting.Core"))
    assert not ids & {"pkg-desktop-ui-library-code", "pkg-desktop-ui-library-ref", "pkg-web-ui-suite-systemweb"}
    assert "pkg-document-engine-fonts" in ids


def test_desktop_app_packages_are_explained(tmp_path):
    write(tmp_path, "src/App/App.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>WinExe</OutputType><TargetFramework>net8.0-windows</TargetFramework><UseWPF>true</UseWPF></PropertyGroup>
          <ItemGroup><PackageReference Include="MahApps.Metro" Version="2.4.10" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/App/App.xaml.cs", "using MahApps.Metro.Controls; public partial class App {}")
    c = assess(tmp_path).components[0]
    ids = {f.rule.id for f in c.findings}
    assert "pkg-desktop-ui-package" in ids and "pkg-desktop-ui-library-code" not in ids
    assert not any("MahApps" in u for u in c.uncertain)


@pytest.mark.parametrize("name,matches", [
    ("DevExpress.XtraGrid.v21.2", True),
    ("DevExpress.Xpf.Core.v22.1", True),
    ("DevExpress.XtraCharts.v21.2.UI", True),
    ("Telerik.WinControls.UI", True),
    ("InfragisticsWPF4.Controls.Grids.XamDataGrid.v21.2", True),
    ("Infragistics4.Win.UltraWinGrid.v21.2", True),
    ("Syncfusion.SfDataGrid.WPF", True),
    ("C1.Win.C1FlexGrid.4", True),
    ("Hardcodet.NotifyIcon.Wpf", True),
    ("DevExpress.XtraScheduler.v21.2.Core", False),
    ("DevExpress.XtraReports.v21.2", False),
    ("DevExpress.XtraCharts.v21.2", False),
    ("DevExpress.Reporting.Core", False),
    ("Telerik.Windows.Documents.Core", False),
    ("Syncfusion.Pdf.Net.Core", False),
    ("Syncfusion.HtmlToPdfConverter.Net.Windows", False),
    ("CommunityToolkit.Mvvm", False),
    ("MaterialDesignThemes.MahApps", True),
])
def test_desktop_ui_pattern(name, matches):
    assert full(VENDOR["patterns"]["desktop_ui"], name) is matches


@pytest.mark.parametrize("name,matches", [
    ("DevExpress.Web", True),
    ("DevExpress.Web.v21.2", True),
    ("Telerik.UI.for.AspNet.Mvc5", True),
    ("Infragistics4.Web.v21.2", True),
    ("Syncfusion.EJ2.MVC5", True),
    ("Syncfusion.EJ2.AspNet.Core", False),
    ("Telerik.UI.for.AspNet.Core", False),
    ("Kendo.Mvc", False),
    ("DevExpress.AspNetCore.Reporting", False),
    ("Infragistics.Web.AspNetCore", False),
])
def test_web_ui_pattern(tmp_path, name, matches):
    rule = next(r for r in load_rules() if r.id == "pkg-web-ui-suite-systemweb")
    assert full(rule.when["any"][0]["package"], name) is matches


# ------------------------------------------------------ false-positive guards

@pytest.mark.parametrize("code,packages,rule", [
    # System.Threading.Tasks.TaskScheduler is not the Task Scheduler library
    ("class S { void M() { Task.Factory.StartNew(() => {}, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default); } }",
     "", "pkg-taskscheduler-api"),
    # Azure Speech SDK has a SpeechSynthesizer too
    ("using Microsoft.CognitiveServices.Speech;\nclass S { void M(SpeechConfig c) { var s = new SpeechSynthesizer(c); } }",
     pkg("Microsoft.CognitiveServices.Speech"), "pkg-system-speech"),
    # NAudio.Core file handling is cross-platform
    ("class A { void M() { using var r = new WaveFileReader(\"a.wav\"); } }", pkg("NAudio.Core"), "pkg-naudio-windows"),
    # device output behind an OS check
    ("class A { void M() { if (OperatingSystem.IsWindows()) { var o = new WaveOutEvent(); } } }", pkg("NAudio"), "pkg-naudio-windows"),
    ("using Oracle.ManagedDataAccess.Client;", pkg("Oracle.ManagedDataAccess.Core"), "pkg-oracle-unmanaged"),
    ("using IBM.Data.Db2;", pkg("Net.IBM.Data.Db2-lnx"), "pkg-db2-windows-package"),
    ("using IBM.Data.Db2;", pkg("Net.IBM.Data.Db2-lnx"), "pkg-db2-netfx-provider"),
    ("using AdoNetCore.AseClient;", pkg("AdoNetCore.AseClient"), "pkg-sybase-ase"),
    ("", pkg("FastReport.OpenSource", "FastReport.OpenSource.Skia"), "pkg-fastreport-gdi"),
    ("", pkg("Spire.PDFfor.NETStandard"), "pkg-spire-netfx"),
    ("", pkg("Syncfusion.HtmlToPdfConverter.Net.Linux"), "pkg-syncfusion-htmltopdf-windows"),
    ("", pkg("CommunityToolkit.Mvvm"), "pkg-winrt-packages"),
    ("", pkg("DotNetBrowser"), "pkg-windows-browser-engine"),
    ("", pkg("Magick.NET-Q16-AnyCPU"), "pkg-imaging-sdk"),
])
def test_no_false_positive(tmp_path, code, packages, rule):
    assert rule not in ids_of(tmp_path, code=code, packages=packages)


def test_naudio_device_output_is_flagged(tmp_path):
    assert "pkg-naudio-windows" in ids_of(tmp_path, code="class A { void M() { var o = new WaveOutEvent(); } }",
                                          packages=pkg("NAudio"))


def test_office_interop_used_in_code_is_reported_once(tmp_path):
    ids = ids_of(tmp_path, code="using Excel = Microsoft.Office.Interop.Excel;",
                 packages=pkg("Microsoft.Office.Interop.Excel"))
    assert "com-office-automation" in ids and "pkg-office-interop-package" not in ids


def test_winrt_code_is_left_to_winrt_rule(tmp_path):
    ids = ids_of(tmp_path, code="using Windows.Media.Ocr;", packages=pkg("Microsoft.Windows.SDK.Contracts"))
    assert "winrt-apis" in ids and "pkg-winrt-packages" not in ids


def test_headless_browser_in_tests_is_fine(tmp_path):
    write(tmp_path, "tests/E2E.Tests/E2E.Tests.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.0.0" />
                     <PackageReference Include="Microsoft.Playwright" Version="1.40.0" /></ItemGroup>
        </Project>""")
    write(tmp_path, "tests/E2E.Tests/T.cs", "public class T {}")
    a = assess(tmp_path)
    for c in a.components:
        assert "pkg-headless-browser" not in {f.rule.id for f in c.findings}


# ------------------------------------------------------------ Linux-safe catalog

def test_linux_safe_packages_raise_confidence(tmp_path):
    web_app(tmp_path, packages=pkg("OpenTelemetry.Extensions.Hosting", "Markdig", "Mapster", "Sentry.AspNetCore",
                                   "prometheus-net.AspNetCore", "HtmlAgilityPack", "BCrypt.Net-Next", "VaultSharp"))
    c = assess(tmp_path).components[0]
    assert not [u for u in c.uncertain if u.startswith("package:")]
    assert c.verdict in ("info", "config")


@pytest.mark.parametrize("name", [
    "Selenium.WebDriver.IEDriver", "Rebus.Msmq", "FluentMigrator.Runner.Jet", "NAudio.WinMM", "NAudio",
    "Serilog.Sinks.EventLog", "Magick.NET-Q16-x86", "Microsoft.Toolkit.Uwp.Notifications", "CefSharp.Wpf",
    "Spire.PDF", "Tesseract", "PdfiumViewer", "Microsoft.Web.Administration",
])
def test_catalog_excludes_windows_only_packages(name):
    assert not full("|".join(CATALOG["linux_ok"]), name)


def test_desktop_browser_packages_are_explained(tmp_path):
    write(tmp_path, "src/App/App.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>WinExe</OutputType><TargetFramework>net8.0-windows</TargetFramework><UseWindowsForms>true</UseWindowsForms></PropertyGroup>
          <ItemGroup><PackageReference Include="CefSharp.WinForms.NETCore" Version="120.1.110" />
                     <PackageReference Include="DevExpress.Win.Grid" Version="23.2.3" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/App/Program.cs", "class P { static void Main() { Application.Run(new MainForm()); } }")
    c = assess(tmp_path).components[0]
    ids = {f.rule.id for f in c.findings}
    assert {"pkg-desktop-ui-package", "pkg-desktop-windows-runtime-package"} <= ids
    assert "pkg-windows-browser-engine" not in ids
    assert not [u for u in c.uncertain if u.startswith("package:")]


def test_linux_html_to_pdf_packages_are_not_windows_browser(tmp_path):
    import re
    import yaml
    from pathlib import Path
    pat = yaml.safe_load(Path("rules/35-vendor-packages.yaml").read_text())["patterns"]["windows_browser"]
    rx = re.compile(f"^(?:{pat})$", re.I)
    assert rx.match("Winnovative.Pdf.Chromium") and rx.match("EvoPdf.Chromium")
    assert not rx.match("Winnovative.Pdf.Chromium.Linux") and not rx.match("EvoPdf.Next.Linux")
