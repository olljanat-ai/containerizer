"""Migration assistant: rules/migrations.yaml, migration plans and AI agent prompts."""
import json
import re
from pathlib import Path

import yaml

from containerizer import webui
from containerizer.assess import assess
from containerizer.migrate import KINDS, MIGRATIONS_FILE, load_migrations, migration_index
from containerizer.report import write_reports
from containerizer.rules import load_rules
from tests.test_engine import web_app, write

# NuGet ids, Maven groupId:artifactId, npm names (@scope/name)
PKG = re.compile(r"^@?[A-Za-z0-9_.:/-]+$")
PKG_GLOB = re.compile(r"^@?[A-Za-z0-9_.*:/-]+$")


def curated_findings():
    return [r for r in load_rules() if r.phase == "finding" and not r.file.startswith("rules/learned/")]


# ---------------------------------------------------------------- the catalogue
def test_catalogue_is_well_formed():
    raw = yaml.safe_load(MIGRATIONS_FILE.read_text())["migrations"]
    ids = [m["id"] for m in raw]
    assert len(ids) == len(set(ids))
    known = {r.id for r in curated_findings()}
    claimed: dict = {}
    for m in load_migrations():
        assert m.kind in KINDS
        assert m.replace and m.with_ and m.steps, m.id
        for rid in m.rules:
            assert rid in known, f"{m.id}: unknown finding rule {rid}"
            assert rid not in claimed, f"{rid} in both {claimed.get(rid)} and {m.id}"
            claimed[rid] = m.id
        assert all(PKG.match(p) for p in m.packages.get("add", [])), m.id
        assert all(PKG_GLOB.match(p) for p in m.packages.get("remove", [])), m.id
        assert set(m.packages) <= {"add", "remove"}, m.id
        assert all(u.startswith("https://") for u in m.refs), m.id


def test_every_blocker_and_rewrite_rule_has_a_migration():
    idx = migration_index()
    missing = [r.id for r in curated_findings() if r.severity in ("blocker", "rewrite") and r.id not in idx]
    assert not missing


def test_blocker_migrations_state_an_effort():
    # blocker rules carry effort 0 (not counted in the assessment): their migration must estimate one,
    # except "isolate" entries where nothing in the component can change
    idx = migration_index()
    for r in curated_findings():
        m = idx.get(r.id)
        if r.severity == "blocker" and m and m.kind != "isolate":
            assert m.effort is not None, m.id


def test_isolate_entries_only_for_rules_without_linux_option():
    for m in load_migrations():
        if m.kind == "isolate":
            rules = {r.id: r for r in curated_findings()}
            assert all(rules[rid].severity == "blocker" for rid in m.rules), m.id


# ---------------------------------------------------------------- plans
def _blocked_app(root: Path) -> None:
    web_app(root, '''class W { void M() {
        var b = new System.Drawing.Bitmap(10, 10);
        Microsoft.Win32.Registry.GetValue("HKEY_LOCAL_MACHINE\\\\Software\\\\X", "a", null);
        EventLog.WriteEntry("app", "started"); } }''',
            packages='<PackageReference Include="System.Drawing.Common" Version="8.0.0" />')


def test_plan_maps_findings_to_replacements(tmp_path):
    _blocked_app(tmp_path)
    a = assess(tmp_path)
    plans = a.migration_plans()
    plan = plans["src/Web/Web.csproj"]
    ids = [i["id"] for i in plan["items"]]
    assert {"replace-system-drawing", "replace-registry", "replace-eventlog"} <= set(ids)
    assert plan["outcome"] == "linux-container"
    drawing = next(i for i in plan["items"] if i["id"] == "replace-system-drawing")
    assert drawing["packages"]["remove"] == ["System.Drawing.Common"]     # only what the project references
    assert "SkiaSharp" in drawing["packages"]["add"]
    assert any("system-drawing-common-windows-only" in u for u in drawing["refs"])   # rule refs merged in
    assert drawing["findings"][0]["evidence"]
    ev = next(i for i in plan["items"] if i["id"] == "replace-eventlog")
    assert "packages" not in ev or "add" not in ev["packages"]     # Logging.Console is in the ASP.NET Core framework
    assert plan["effort_days"] == round(sum(i["effort_days"] for i in plan["items"]), 1)


def test_ready_component_has_no_plan(tmp_path):
    web_app(tmp_path)
    a = assess(tmp_path)
    assert a.migration_plans() == {}
    assert "migration" not in a.to_dict()["components"][0]


def test_prompt_is_self_contained_and_deterministic(tmp_path):
    _blocked_app(tmp_path)
    p1 = assess(tmp_path).migration_plans()["src/Web/Web.csproj"]["prompt"]
    p2 = assess(tmp_path).migration_plans()["src/Web/Web.csproj"]["prompt"]
    assert p1 == p2
    for part in ("# Task: make `Web` run in a Linux container", "## Migration plan", "## Constraints",
                 "## How to verify", "SkiaSharp", "src/Web/Program.cs:", "OperatingSystem.IsWindows()",
                 "Kubernetes Secrets", "dotnet test"):
        assert part in p1, part


def test_desktop_client_stays_on_windows_without_prompt(tmp_path):
    write(tmp_path, "src/App/App.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>WinExe</OutputType><TargetFramework>net8.0-windows</TargetFramework>
          <UseWindowsForms>true</UseWindowsForms></PropertyGroup>
        </Project>""")
    write(tmp_path, "src/App/Form1.cs", "class Form1 : System.Windows.Forms.Form { }")
    a = assess(tmp_path)
    plans = a.migration_plans()
    plan = next(iter(plans.values()))
    if all(i["kind"] == "isolate" for i in plan["items"]):
        assert plan["outcome"] == "stays-on-windows" and plan["prompt"] is None
    else:      # retargeting away from -windows is actionable; the UI itself is out of scope
        assert plan["outcome"] == "partial" and "Out of scope: keep on Windows" in plan["prompt"]


def test_reports_carry_plans_and_prompt_files(tmp_path):
    _blocked_app(tmp_path / "shop")
    a = assess(tmp_path / "shop")
    out = tmp_path / "out"
    write_reports([a], out)
    md = (out / "shop.md").read_text()
    assert "## Migration assistant" in md and "SkiaSharp" in md
    prompt = out / "agent-prompts" / "shop" / "Web.md"
    assert prompt.read_text().startswith("# Task: make `Web`")
    doc = json.loads((out / "assessment.json").read_text())[0]
    assert doc["components"][0]["migration"]["prompt"] == prompt.read_text()


# ---------------------------------------------------------------- web UI
def _ui_data(tmp_path):
    from tests.test_sqlstore import application_data
    _blocked_app(tmp_path)
    plan = assess(tmp_path).migration_plans()["src/Web/Web.csproj"]
    d = application_data()
    d["migrations"] = [{"ComponentId": 1, "ComponentName": "Web", "Outcome": plan["outcome"],
                        "EffortDays": plan["effort_days"], "ItemCount": len(plan["items"]),
                        "PlanJson": json.dumps({k: v for k, v in plan.items() if k != "prompt"}),
                        "AgentPrompt": plan["prompt"] + "</textarea><script>alert(1)</script>"}]
    return d


def test_application_page_shows_migration_and_prompt(tmp_path):
    html = webui.render_application(_ui_data(tmp_path))
    assert "Migration assistant" in html and "Prompt for an AI coding agent" in html
    assert "SkiaSharp" in html and "data-copy='pt1'" in html
    assert "/app/7/component/1/agent-prompt.md" in html
    assert "<script>alert" not in html and "&lt;/textarea&gt;" in html       # prompt text is escaped
    assert html.count("<script") == 1 and "<script src='/static/app.js'>" in html


def test_application_page_without_migrations(tmp_path):
    from tests.test_sqlstore import application_data
    html = webui.render_application(application_data())
    assert "Migration assistant" not in html


def test_load_migrations_tolerates_old_schema():
    class Boom:
        def cursor(self, as_dict=False):
            raise RuntimeError("Invalid object name 'cz.vComponentMigrationLatest'")
    assert webui.load_migrations(Boom(), 7) == []


def test_csp_allows_only_own_script():
    csp = webui.HEADERS["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
