"""SBOMs: CycloneDX parsing, licence policy, CVEs per package, source SBOMs, storage, UI, API.

The SQL Server tests need CONTAINERIZER_TEST_SQL (see tests/test_sqlstore.py); nothing here needs the network,
Syft or Docker: NuGet lookups and the registry tools are replaced.
"""
import json
import os
import re
import urllib.error
from datetime import date
from pathlib import Path

import pytest

from containerizer import api, api_sbom, imagescan, org, sbom, sbomui, sqlstore, webui
from containerizer.assess import assess
from containerizer.imagescan import Vuln

from test_engine import web_app, write

POLICY = {"licenses": {"deny": ["AGPL(-.*)?"], "warn": ["GPL(-.*)?", "SSPL(-.*)?"],
                       "allow": ["LicenseRef-public-domain"], "unknown": "report",
                       "accepted": [{"package": "Ghostscript\\.NET", "reason": "commercial licence"},
                                    {"package": "OldLib", "reason": "expired", "expires": "2020-01-01"}]},
          "os_packages": "report"}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(sbom, "nuget_license", lambda name, version, feed=None: "")


# ---------------------------------------------------------------------------
# licence policy

@pytest.mark.parametrize("expr, status", [
    ("MIT", "allowed"), ("mit", "allowed"), ("Apache 2.0", "allowed"),
    ("GPL-2.0-only", "warn"), ("GPL-2.0+", "warn"), ("GPL", "warn"), ("LGPL-2.1-only", "allowed"),
    ("AGPL-3.0-only", "denied"),
    ("MIT OR GPL-3.0-only", "allowed"), ("MIT AND GPL-3.0-only", "warn"),
    ("(MIT OR AGPL-3.0-only) AND GPL-2.0-only", "warn"), ("AGPL-3.0-only OR GPL-2.0-only", "warn"),
    ("GPL-2.0-only WITH Classpath-exception-2.0", "warn"),
    ("Artistic", "unknown"),                       # not an SPDX id
    ("Microsoft Software License", "unknown"), ("LicenseRef-url:https://example.com/eula", "unknown"),
    ("LicenseRef-public-domain", "allowed"), ("LicenseRef-something", "unknown"), ("MIT OR", "unknown"),
])
def test_expression_status(expr, status):
    assert sbom._Policy(POLICY).expression(sbom.normalize(expr)) == status


def test_unknown_policy_can_warn_or_deny():
    for mode, st in (("report", "unknown"), ("warn", "warn"), ("deny", "denied")):
        p = sbom._Policy({"licenses": {"unknown": mode}})
        assert p.expression("Some EULA") == st


def test_legacy_license_urls_map_to_spdx():
    assert sbom.normalize("LicenseRef-url:https://github.com/dotnet/corefx/blob/master/LICENSE.TXT") == "MIT"
    assert sbom.normalize("LicenseRef-url:http://logging.apache.org/log4net/license.html") == "Apache-2.0"
    assert sbom.normalize("LicenseRef-url:https://example.com/LICENSE").startswith("LicenseRef-url:")


def test_classify_scopes_and_exceptions():
    pk = [sbom.Package("libc6", "2.39", "deb", licenses=["GPL-2.0-only", "LGPL-2.1-only"]),
          sbom.Package("Shop.Web", "1.0.0", "nuget"),
          sbom.Package("Ghostscript.NET", "1.2", "nuget", licenses=["AGPL-3.0-only"]),
          sbom.Package("OldLib", "1.0", "nuget", licenses=["GPL-3.0-only"]),
          sbom.Package("Dual", "1.0", "nuget", licenses=["MIT OR GPL-3.0-only"]),
          sbom.Package("Nothing", "1.0", "npm")]
    sbom.classify(pk, POLICY, own_names=("Shop.Web",), today=date(2026, 10, 31))
    by = {p.name: p for p in pk}
    assert by["libc6"].license == "GPL-2.0-only AND LGPL-2.1-only"
    assert (by["libc6"].status, by["libc6"].scope, by["libc6"].applies) == ("warn", "os", False)
    assert (by["Shop.Web"].scope, by["Shop.Web"].applies, by["Shop.Web"].status) == ("self", False, "allowed")
    assert (by["Ghostscript.NET"].status, by["Ghostscript.NET"].applies, by["Ghostscript.NET"].accepted) == \
        ("denied", False, "commercial licence")
    assert (by["OldLib"].status, by["OldLib"].applies) == ("warn", True)        # the exception expired
    assert by["Dual"].status == "allowed" and by["Nothing"].status == "unknown"
    s = sbom.summarize(pk)
    assert s["licenses"] == {"allowed": 1, "unknown": 1, "warn": 1, "denied": 0} and not s["denied"]
    # os packages count when the policy says so
    pk2 = [sbom.Package("libc6", "2.39", "deb", licenses=["AGPL-3.0-only"])]
    sbom.classify(pk2, {**POLICY, "os_packages": "evaluate"})
    assert pk2[0].applies and sbom.summarize(pk2)["denied"] == ["libc6 2.39 (AGPL-3.0-only)"]


# ---------------------------------------------------------------------------
# CycloneDX documents and CVEs

SYFT_DOC = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "metadata": {"tools": {"components": [{"type": "application", "name": "syft", "version": "1.33.0"}]}},
    "components": [
        {"type": "library", "name": "Newtonsoft.Json", "version": "13.0.3", "purl": "pkg:nuget/Newtonsoft.Json@13.0.3"},
        {"type": "library", "name": "Newtonsoft.Json", "version": "13.0.3", "purl": "pkg:nuget/Newtonsoft.Json@13.0.3",
         "licenses": [{"license": {"id": "MIT"}}]},                           # same package seen twice: merged
        {"type": "library", "name": "Shop.Web", "version": "1.0.0", "purl": "pkg:nuget/Shop.Web@1.0.0"},
        {"type": "library", "name": "libc6", "version": "2.39-0ubuntu8.9",
         "purl": "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04",
         "licenses": [{"license": {"id": "GPL-2.0-only"}}, {"license": {"name": "LGPL"}}]},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
         "licenses": [{"expression": "WTFPL OR MIT"}]},
        {"type": "file", "name": "/usr/lib/x.so"},
        {"type": "operating-system", "name": "ubuntu", "version": "24.04"},
    ]}


def test_packages_from_cyclonedx():
    pk = {p.name: p for p in sbom.packages_from_cyclonedx(SYFT_DOC)}
    assert set(pk) == {"Newtonsoft.Json", "Shop.Web", "libc6", "left-pad"}
    assert pk["Newtonsoft.Json"].licenses == ["MIT"] and pk["libc6"].type == "deb"
    assert pk["left-pad"].licenses == ["WTFPL OR MIT"]
    assert sbom.os_name(SYFT_DOC) == "ubuntu 24.04" and sbom.syft_version(SYFT_DOC) == "syft 1.33.0"


def test_vulns_attach_by_purl_then_name():
    pkgs = sbom.packages_from_cyclonedx(SYFT_DOC)
    vulns = [Vuln("CVE-2026-1", "libc6", "2.39-0ubuntu8.9", "2.39-0ubuntu8.10", "HIGH", "ubuntu",
                  purl="pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04.1"),   # other qualifiers
             Vuln("CVE-2026-1", "libc6", "2.39-0ubuntu8.9", "", "HIGH", "ubuntu"),                # same CVE twice
             Vuln("GHSA-5crp-9r3c-p9vr", "newtonsoft.json", "13.0.3", "", "CRITICAL", "dotnet-core"),
             Vuln("CVE-2026-2", "System.Text.Json", "8.0.0", "8.0.5", "CRITICAL", "dotnet-core")]
    extra = sbom.attach_vulns(pkgs, vulns)
    by = {p.name: p for p in pkgs}
    assert extra == 1
    assert [v["id"] for v in by["libc6"].vulns] == ["CVE-2026-1"] and by["libc6"].counts()["HIGH"] == 1
    assert by["Newtonsoft.Json"].counts()["CRITICAL"] == 1
    assert by["System.Text.Json"].found_by == "scanner" and by["System.Text.Json"].type == "nuget"


def test_analyze_orders_by_what_needs_attention():
    doc = json.loads(json.dumps(SYFT_DOC))
    doc["components"].append({"type": "library", "name": "Gpl.Lib", "version": "2.0", "purl": "pkg:nuget/Gpl.Lib@2.0",
                              "licenses": [{"license": {"id": "GPL-3.0-only"}}]})
    pk = sbom.analyze(doc, [Vuln("CVE-1", "left-pad", "1.3.0", "1.3.1", "CRITICAL", "npm")], ("Shop.Web",), POLICY)
    assert [p.name for p in pk][:2] == ["Gpl.Lib", "left-pad"]
    assert pk[-1].name in ("Shop.Web", "libc6")


def test_nuget_licenses_from_nuspec():
    ns = b'<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>%s</metadata></package>'
    assert sbom._license_from_nuspec(ns % b'<license type="expression">MIT OR Apache-2.0</license>'
                                     b'<licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>') == "MIT OR Apache-2.0"
    assert sbom._license_from_nuspec(ns % b'<license type="file">LICENSE.txt</license>') == "LicenseRef-see-package-file"
    assert sbom._license_from_nuspec(ns % b"<licenseUrl>https://licenses.nuget.org/Apache-2.0</licenseUrl>") == "Apache-2.0"
    assert sbom._license_from_nuspec(ns % b"<licenseUrl>http://go.microsoft.com/fwlink/?LinkId=329770</licenseUrl>") == \
        "LicenseRef-Microsoft-NET-Library"
    assert sbom._license_from_nuspec(ns % b"<licenseUrl>https://example.com/l</licenseUrl>") == \
        "LicenseRef-url:https://example.com/l"
    assert sbom._license_from_nuspec(ns % b"") == ""


def test_nuget_lookup_uses_the_feed_and_caches(monkeypatch, tmp_path):
    monkeypatch.undo()                      # the real nuget_license, against a fake feed
    monkeypatch.setattr(sbom, "_nuget_cache_file", lambda: tmp_path / "cache.json")
    monkeypatch.setattr(sbom, "_NUGET", {"base": None, "cache": None})
    calls = []

    class R:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(url, timeout=0):
        calls.append(url)
        if url.endswith("index.json"):
            return R(json.dumps({"resources": [{"@type": "PackageBaseAddress/3.0.0", "@id": "https://feed.example/flat"}]}).encode())
        if "/private.lib/" in url:
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)
        return R(b'<package><metadata><license type="expression">MIT</license></metadata></package>')

    monkeypatch.setattr(sbom.urllib.request, "urlopen", urlopen)
    assert sbom.nuget_license("Newtonsoft.Json", "13.0.3", "https://feed.example/v3/index.json") == "MIT"
    assert calls[-1] == "https://feed.example/flat/newtonsoft.json/13.0.3/newtonsoft.json.nuspec"
    assert sbom.nuget_license("Private.Lib", "1.0.0") == ""
    assert sbom.nuget_license("Newtonsoft.Json", "8.*") == ""               # a range: not looked up
    n = len(calls)
    assert sbom.nuget_license("newtonsoft.json", "13.0.3") == "MIT" and sbom.nuget_license("Private.Lib", "1.0.0") == ""
    assert len(calls) == n                                                    # answered from the cache
    assert json.loads((tmp_path / "cache.json").read_text()) == {"newtonsoft.json/13.0.3": "MIT", "private.lib/1.0.0": ""}


def test_repository_of_a_reference():
    assert sbom.repository("registry:5000/app/web:1.2") == "registry:5000/app/web"
    assert sbom.repository("registry:5000/app/web@sha256:ab") == "registry:5000/app/web"
    assert sbom.repository("web:1") == "web"


# ---------------------------------------------------------------------------
# source SBOMs

def test_source_sbom_declared_and_locked(tmp_path):
    web_app(tmp_path, packages='<PackageReference Include="Serilog" Version="3.1.1" />'
                               '<PackageReference Include="Dapper" Version="2.*" />'
                               '<ProjectReference Include="../Lib/Lib.csproj" />')
    write(tmp_path, "src/Lib/Lib.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup><PackageReference Include="Polly" Version="[8.4.0]" /></ItemGroup>
        </Project>""")
    write(tmp_path, "src/Lib/C.cs", "public class C {}")
    write(tmp_path, "src/spa/package.json", json.dumps({"name": "spa", "scripts": {"build": "ng build"},
                                                       "dependencies": {"@angular/core": "^17.0.0"},
                                                       "devDependencies": {"karma": "6.0.0"}}))
    write(tmp_path, "src/spa/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "spa"},
        "node_modules/@angular/core": {"version": "17.3.1", "license": "MIT"},
        "node_modules/tslib": {"version": "2.6.2", "license": "0BSD"},
        "node_modules/karma": {"version": "6.0.0", "license": "MIT", "dev": True},
        "node_modules/a/node_modules/gpl-thing": {"version": "1.0.0", "license": "GPL-3.0-only"}}}))
    a = assess(tmp_path)
    comps = {c.name: c for c in a.components}
    doc, pk = sbom.source_component_sbom(comps["Web"], a.repo, POLICY)
    names = {p.name: p for p in pk}
    assert set(names) == {"Serilog", "Dapper", "Polly"}
    assert names["Serilog"].purl == "pkg:nuget/Serilog@3.1.1" and names["Polly"].version == "8.4.0"
    assert names["Dapper"].version == "" and names["Dapper"].purl == "pkg:nuget/Dapper"
    assert doc["bomFormat"] == "CycloneDX" and doc["metadata"]["component"]["name"] == "Web"
    spa = next(c for c in a.components if c.project.kind_hint == "node")
    doc, pk = sbom.source_component_sbom(spa, a.repo, POLICY)
    names = {p.name: p for p in pk}
    assert set(names) == {"@angular/core", "tslib", "gpl-thing"}                # dev packages left out
    assert names["@angular/core"].purl == "pkg:npm/%40angular/core@17.3.1"
    assert names["gpl-thing"].status == "warn" and names["tslib"].license == "0BSD"


def test_packages_lock_json(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/packages.lock.json", json.dumps({"version": 1, "dependencies": {"net8.0": {
        "Serilog": {"type": "Direct", "requested": "[3.1.1, )", "resolved": "3.1.1"},
        "System.Memory": {"type": "Transitive", "resolved": "4.5.5"},
        "Lib": {"type": "Project"}}}}))
    a = assess(tmp_path)
    doc, pk = sbom.source_component_sbom(a.components[0], a.repo, POLICY)
    assert {(p.name, p.version) for p in pk} == {("Serilog", "3.1.1"), ("System.Memory", "4.5.5")}


# ---------------------------------------------------------------------------
# security gate, org run, registry

def test_gate_entry_and_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom, "image_sbom", lambda ref, local=True: (json.loads(json.dumps(SYFT_DOC)), ""))
    monkeypatch.setattr(sbom, "config", lambda: {**POLICY, "licenses": {**POLICY["licenses"], "deny": ["GPL(-.*)?"]},
                                                 "os_packages": "evaluate"})
    e = sbom.component_sbom("local:gate", tmp_path, [], ("Shop.Web",), "reg/app/web:1")
    assert (tmp_path / "sbom.cdx.json").exists() and not e["passed"]
    assert e["summary"]["denied"] == ["libc6 2.39-0ubuntu8.9 (GPL-2.0-only AND LGPL)"]
    assert json.loads((tmp_path / "sbom.cdx.json").read_text())["metadata"]["component"]["name"] == "reg/app/web"
    assert org.gate_failure({"sbom": e}).startswith("licence denied by policy: libc6")
    md = imagescan.security_markdown({"app": "shop", "passed": False, "policy": {"fail_on": "CRITICAL", "ignore_unfixed": True},
                                      "lint": {}, "notes": [], "components": [{"component": "web", "scans": [], "lint": [],
                                                                               "sbom": e}]})
    assert "licence denied** by policy: libc6" in md and "SBOM: `sbom.cdx.json`" in md


def test_attach_with_cosign_or_oras(tmp_path, monkeypatch):
    f = tmp_path / "s.json"
    f.write_text("{}")
    runs = []

    def run(cmd, timeout=0, env=None):
        runs.append(cmd)
        return 0, "", ""

    def oras(cfg, target, d, env):
        runs.append(["oras", *cfg, target, sorted(os.listdir(d))])
        return 0, "", ""

    monkeypatch.setattr(sbom, "_run", run)
    monkeypatch.setattr(sbom, "_oras", oras)
    monkeypatch.setattr(sbom.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(sbom, "config", lambda: {"cosign_tlog_upload": False, "attach": True})
    assert sbom.attach("reg:5000/app/web:1", "sha256:ab", f, key="k.key") == "attested"
    assert runs[-1] == ["cosign", "attest", "--yes", "--tlog-upload=false", "--key", "k.key", "--type", "cyclonedx",
                        "--predicate", str(f), "reg:5000/app/web@sha256:ab"]
    assert sbom.attach("reg:5000/app/web:1", "sha256:ab", f, docker_config="/tmp/cfg") == "attached"
    assert runs[-1] == ["oras", "--registry-config", "/tmp/cfg/config.json", "reg:5000/app/web@sha256:ab", ["sbom.cdx.json"]]
    monkeypatch.setattr(sbom.shutil, "which", lambda b: None)
    assert "not installed" in sbom.attach("reg/app/web:1", "sha256:ab", f)


# ---------------------------------------------------------------------------
# schema

def test_schema_has_sbom_tables_and_least_privilege():
    text = "\n".join(sqlstore.schema_batches("shared_cz"))
    assert "[shared_cz].ComponentSbom" in text and "[shared_cz].vSbomPackageLatest" in text
    assert "${" not in text and not re.search(r"\bdbo\.\w", text)
    # readers get the views, never the tables; the scanner only inserts
    assert not re.search(r"GRANT [^;]*ON \[shared_cz\]\.(ComponentSbom|SbomPackage) TO \[shared_cz_reader\]", text)
    assert re.search(r"GRANT SELECT ON \[shared_cz\]\.vSbomDocumentLatest TO \[shared_cz_reader\]", text)
    assert not re.search(r"GRANT [^;]*(UPDATE|DELETE)[^;]*(ComponentSbom|SbomPackage)", text)
    # sbom.sql comes after schema.sql (it references its tables and views)
    assert text.index("CREATE TABLE [shared_cz].ApplicationAssessment") < text.index("CREATE TABLE [shared_cz].ComponentSbom")


# ---------------------------------------------------------------------------
# web UI and API with canned data

def _pkg(name, version="1.0", typ="nuget", lic="MIT", st="allowed", scope="app", applies=True, crit=0, high=0, vulns=None,
         **kw):
    return {"Name": name, "Version": version, "Type": typ, "Purl": f"pkg:{typ}/{name}@{version}", "License": lic,
            "LicenseSource": "sbom", "LicenseStatus": st, "Scope": scope, "PolicyApplies": applies, "Accepted": None,
            "FoundBy": "sbom", "Critical": crit, "High": high, "Medium": 0, "Low": 0,
            "Vulns": json.dumps(vulns) if vulns else None, **kw}


def component_data(kind="image"):
    return {"ApplicationId": 3, "ApplicationName": "shop", "ComponentId": 9, "ComponentName": "<b>Web</b>",
            "ProjectPath": "src/Web/Web.csproj", "Role": "web", "Verdict": "info", "ProductName": "Web shop",
            "ProductInfoUrl": None, "BusinessUnitId": 1, "BusinessUnitName": "Retail", "AssessedAt": date(2026, 10, 31),
            "sbom": {"SbomId": 1, "Kind": kind, "CreatedAt": date(2026, 10, 31), "ImageRef": "reg/shop/web:1",
                     "ImageDigest": "sha256:" + "a" * 64, "Format": "CycloneDX 1.6", "Tool": "syft 1.33.0",
                     "OperatingSystem": "ubuntu 24.04", "PackageCount": 3, "Attestation": "attested"},
            "packages": [_pkg("Gpl.Lib", lic="GPL-3.0-only", st="warn"),
                         _pkg("libc6", "2.39", "deb", "GPL-2.0-only", "warn", "os", False, high=1,
                              vulns=[{"id": "CVE-2026-12345", "severity": "HIGH", "fixed": "2.40", "title": "x"},
                                     {"id": "<script>", "severity": "LOW", "fixed": "", "title": "y"}]),
                         _pkg("Odd", lic="LicenseRef-url:javascript:alert(1)", st="unknown"),
                         _pkg("Fine")]}


def test_component_page():
    html = sbomui.render_component(component_data())
    assert "&lt;b&gt;Web&lt;/b&gt;" in html and "<b>Web</b>" not in html
    assert "style=" not in html and "<script" not in html.replace("<script src='/static/app.js'></script>", "")
    assert "href='https://nvd.nist.gov/vuln/detail/CVE-2026-12345'" in html and "fixed in 2.40" in html
    assert "href='javascript" not in html                       # only http(s) licence links
    assert "/app/3/component/9/sbom.cdx.json" in html and "Signed attestation" in html
    assert "OS package of the base image: reported, not counted" in html
    att = sbomui.render_component(component_data(), "attention")
    assert "Gpl.Lib" in att and "Odd" in att and "libc6" in att and ">Fine<" not in att
    src = sbomui.render_component(component_data("source"))
    assert "no vulnerability scan ran" in src and "not scanned" in src
    assert "No software bill of materials" in sbomui.render_component({**component_data(), "sbom": None})


def portfolio_data():
    return {"available": True,
            "apps_all": [{"ApplicationId": 3, "ApplicationName": "shop", "ProductId": 1, "ProductName": "Web shop",
                          "BusinessUnitId": 1, "BusinessUnitName": "Retail"},
                         {"ApplicationId": 4, "ApplicationName": "<i>ledger</i>", "ProductId": None, "ProductName": None,
                          "BusinessUnitId": None, "BusinessUnitName": None}],
            "components": {"image": 1, "source": 2}, "packages": {"Packages": 40, "Vulnerable": 2, "Critical": 1, "High": 3},
            "status": {"allowed": 30, "warn": 2, "denied": 1, "unknown": 7},
            "licenses": [{"License": "MIT", "LicenseStatus": "allowed", "N": 25},
                         {"License": "LicenseRef-url:", "LicenseStatus": "unknown", "N": 5},
                         {"License": "", "LicenseStatus": "unknown", "N": 2}],
            "per_app": [{"ApplicationId": 3, "ApplicationName": "<i>ledger</i>", "ProductName": "Web shop", "BusinessUnitName": "Retail",
                         "Components": 2, "Packages": 30, "Denied": 1, "Warn": 2, "Unknown": 3, "Critical": 1, "High": 3}],
            "attention": [{**_pkg("Agpl.Lib", lic="AGPL-3.0-only", st="denied"), "Apps": 2, "FirstApp": "shop", "FirstAppId": 3}],
            "vulnerable": [{**_pkg("libc6", "2.39", "deb", crit=1, vulns=[{"id": "CVE-1", "severity": "CRITICAL", "fixed": "2.40"}]),
                            "Apps": 1, "FirstApp": "shop", "FirstAppId": 3}]}


def test_portfolio_page():
    html = sbomui.render_portfolio(portfolio_data())
    assert "&lt;i&gt;ledger&lt;/i&gt;" in html and "style=" not in html
    assert "Only a link to a licence page" in html and "No licence found" in html
    assert "upgrade to 2.40" in html and "and 1 more" in html
    assert "Show as a table" in html and "role='img'" in html
    assert "href='/sbom?bu=1'" in html and "href='/sbom?bu=none'" in html
    filtered = sbomui.render_portfolio(portfolio_data(), bu="1")
    assert "All products" in filtered and "href='/sbom?bu=1&amp;product=1'" in filtered
    assert "db init" in sbomui.render_portfolio({"available": False, "apps_all": []})
    assert sbomui.parse_query({"bu": ["1;drop"], "product": ["2"]}) == (None, None)
    assert sbomui.parse_query({"bu": ["none"], "product": ["2"]}) == ("none", "2")


def test_license_bars_are_proportional():
    svg = sbomui.license_bars([{"License": "MIT", "LicenseStatus": "allowed", "N": 10},
                               {"License": "GPL-3.0-only", "LicenseStatus": "warn", "N": 5}])
    widths = [float(m) for m in re.findall(r"M300 [\d.]+h([\d.]+)", svg)]
    assert len(widths) == 2 and abs((widths[0] + 4) / (widths[1] + 4) - 2) < 0.01
    assert "gpl-3.0-only · review" in svg.lower()


class Cur:
    def __init__(self, log):
        self.log = log

    def execute(self, sql, params=None):
        self.log.append((sql, params))

    def fetchall(self):
        return [{"ApplicationId": 1, "Vulns": json.dumps([{"id": "CVE-1"}]), "PolicyApplies": 1}]


class Conn:
    def __init__(self):
        self.log = []

    def cursor(self, as_dict=False):
        return Cur(self.log)


def test_api_packages_filters_are_parameterised():
    c = Conn()
    out = api_sbom.packages(c, {"businessUnitId": ["none"], "productId": ["4"], "licenseStatus": ["warn,denied"],
                                "vulnerable": ["true"], "name": ["x'; drop"], "limit": ["50000"]})
    sql, params = c.log[-1]
    assert "TOP (10000)" in sql and "BusinessUnitId IS NULL" in sql and "x'; drop" not in sql
    assert params == (4, "warn", "denied", "x'; drop")
    assert out["items"][0]["vulns"] == [{"id": "CVE-1"}] and out["items"][0]["policyApplies"] is True
    for bad in ({"licenseStatus": ["evil"]}, {"businessUnitId": ["1 OR 1=1"]}, {"limit": ["x"]}):
        with pytest.raises(api.ApiError):
            api_sbom.packages(c, bad)
    a = api.Api(None, "aud", [], None)
    with pytest.raises(api.ApiError) as ei:
        a.route(c, "POST", "/api/v1/sbom/packages", {}, {})
    assert ei.value.status == 405
    with pytest.raises(api.ApiError) as ei:
        a.route(c, "GET", "/api/v1/applications/x/components/1/sbom", {}, None)
    assert ei.value.status == 404


def test_app_page_packages_column():
    from test_sqlstore import application_data
    d = application_data()
    d["sboms"] = {1: {"ComponentId": 1, "Kind": "image", "Packages": 12, "Denied": 1, "Warn": 0, "Critical": 2, "High": 0}}
    html = webui.render_application(d)
    assert "<th>Packages</th>" in html and "href='/app/7/component/1'" in html and "1 denied" in html
    assert "<th>Packages</th>" not in webui.render_application(application_data())


# ---------------------------------------------------------------------------
# SQL Server

ADMIN = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@pytest.fixture(scope="module")
def db():
    import uuid
    name = "cztest_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    for login, role in (("cz_s_reader", "reader"), ("cz_s_writer", "writer")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()
    yield cs
    m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
    m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
    m.close()


def _as(cs, login):
    return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)


@needs_sql
def test_store_and_read_sboms(db, tmp_path):
    web_app(tmp_path / "shop", packages='<PackageReference Include="Serilog" Version="3.1.1" />'
                                        '<PackageReference Include="Gpl.Lib" Version="1.0.0" />')
    a = assess(tmp_path / "shop")
    writer = _as(db, "cz_s_writer")
    aid = sqlstore.store_results(writer, [a], [tmp_path / "shop"], password="Test-Passw0rd!x")[0]
    pk = [sbom.Package("libc6", "2.39", "deb", "pkg:deb/ubuntu/libc6@2.39", ["GPL-2.0-only"],
                       vulns=[{"id": "CVE-2026-1", "severity": "CRITICAL", "fixed": "2.40", "title": "t"}]),
          sbom.Package("Agpl.Lib", "2.0", "nuget", "pkg:nuget/Agpl.Lib@2.0", ["AGPL-3.0-only"])]
    sbom.classify(pk, POLICY)
    w = sqlstore.connect(writer, password="Test-Passw0rd!x")
    try:
        n = sqlstore.store_image_sboms(w, aid, [{"project": a.components[0].project.rel, "document": SYFT_DOC,
                                                 "packages": [p.to_dict() for p in pk], "tool": "syft 1.33.0",
                                                 "os": "ubuntu 24.04", "image": "reg/shop/web:1", "digest": "sha256:" + "b" * 64,
                                                 "attestation": "attached"},
                                                {"project": "src/Missing/Missing.csproj", "document": SYFT_DOC, "packages": []}])
        assert n == 1
        with pytest.raises(Exception):
            w.cursor().execute("DELETE cz.SbomPackage")
    finally:
        w.close()
    rd = sqlstore.connect(_as(db, "cz_s_reader"), password="Test-Passw0rd!x")
    try:
        app_id = webui.load_overview(rd)["apps"][0]["ApplicationId"]
        comp_id = webui.load_application(rd, app_id)["components"][0]["ComponentId"]
        c = sbomui.load_component(rd, app_id, comp_id)
        assert c["sbom"]["Kind"] == "image"                            # the image SBOM wins over the source one
        assert [p["Name"] for p in c["packages"]] == ["libc6", "Agpl.Lib"]
        assert c["packages"][1]["LicenseStatus"] == "denied" and c["packages"][0]["Critical"] == 1
        assert json.loads(sbomui.load_document(rd, app_id, comp_id))["bomFormat"] == "CycloneDX"
        sb = webui.load_application(rd, app_id)["sboms"]
        assert sb[comp_id]["Packages"] == 2 and sb[comp_id]["Denied"] == 1
        d = sbomui.load_portfolio(rd)
        assert d["available"] and d["packages"]["Critical"] == 1 and d["status"].get("denied") == 1
        assert sbomui.load_portfolio(rd, "none")["per_app"] and not sbomui.load_portfolio(rd, "1")["per_app"]
        html = sbomui.render_portfolio(d)
        assert "Agpl.Lib" in html and "libc6" in html
        with pytest.raises(Exception):
            rd.cursor().execute("SELECT Document FROM cz.ComponentSbom")
    finally:
        rd.close()
    adm = sqlstore.connect(db)
    cur = adm.cursor(as_dict=True)
    cur.execute("SELECT Kind, PackageCount FROM cz.ComponentSbom WHERE AssessmentId = %s ORDER BY Kind", (aid,))
    rows = cur.fetchall()
    assert [r["Kind"] for r in rows] == ["image", "source"] and rows[1]["PackageCount"] == 2
    adm.close()
