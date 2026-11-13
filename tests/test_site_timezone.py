"""Organization time zone (containerizer/site.py, rule plan-local-timezone): components that use local time get
TZ=<zone> from the site setting, so the os-local-timezone finding is settled by configuration (#277)."""
import json

import pytest
import yaml

from containerizer import site
from containerizer.assess import assess
from containerizer.generate import generate_app
from tests.test_engine import web_app

LOCAL = 'class A { string D() => DateTime.Today.ToString("d"); }'


def _finding(root):
    return next(f for c in assess(root).components for f in c.findings if f.rule.id == "os-local-timezone")


def _env(manifest: str) -> dict:
    for d in yaml.safe_load_all(manifest):
        if d and d.get("kind") == "Deployment":
            return {e["name"]: e.get("value") for e in d["spec"]["template"]["spec"]["containers"][0].get("env") or []}
    raise AssertionError("no Deployment")


def test_no_setting_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv(site.TIMEZONE_ENV, raising=False)
    monkeypatch.setattr(site, "reviewed_dir", lambda: None)
    web_app(tmp_path / "app", LOCAL)
    f = _finding(tmp_path / "app")
    assert f.severity == "info" and not f.resolved_by
    assert "site setting" in f.rule.fix                 # points at the setting, not the code
    generate_app(assess(tmp_path / "app"), tmp_path / "out")
    comp = next(p for p in (tmp_path / "out").iterdir() if (p / "plan.json").exists())
    assert "TZ" not in (comp / "Dockerfile").read_text()
    assert "plan-local-timezone" not in json.loads((comp / "plan.json").read_text())["applied"]


def test_setting_sets_tz_in_dockerfile_and_pod(tmp_path, monkeypatch):
    monkeypatch.setenv(site.TIMEZONE_ENV, "Europe/Helsinki")
    web_app(tmp_path / "app", LOCAL)
    assert _finding(tmp_path / "app").resolved_by == "plan-local-timezone"
    generate_app(assess(tmp_path / "app"), tmp_path / "out")
    comp = next(p for p in (tmp_path / "out").iterdir() if (p / "plan.json").exists())
    plan = json.loads((comp / "plan.json").read_text())
    assert plan["env"]["TZ"] == "Europe/Helsinki"
    assert plan["resolved"]["plan-local-timezone"] == ["os-local-timezone"]
    why = next(r["why"] for r in plan["reasons"] if r["rule"] == "plan-local-timezone")
    assert "Runs in Europe/Helsinki (site setting)." in why
    df = (comp / "Dockerfile").read_text()
    assert "TZ=Europe/Helsinki" in df or 'TZ="Europe/Helsinki"' in df
    assert "# - plan-local-timezone:" in df
    k8s = next(comp.glob("k8s*.yaml")).read_text()
    assert _env(k8s).get("TZ") == "Europe/Helsinki"


def test_component_without_local_time_gets_no_tz(tmp_path, monkeypatch):
    monkeypatch.setenv(site.TIMEZONE_ENV, "Europe/Helsinki")
    web_app(tmp_path / "app", 'class A { int N = 1; }')
    generate_app(assess(tmp_path / "app"), tmp_path / "out")
    comp = next(p for p in (tmp_path / "out").iterdir() if (p / "plan.json").exists())
    assert "TZ" not in json.loads((comp / "plan.json").read_text())["env"]


def test_sources_in_order(tmp_path, monkeypatch):
    rd = tmp_path / "reviewed"
    rd.mkdir()
    (rd / "site.yaml").write_text("timezone: America/New_York\n")
    monkeypatch.setattr(site, "reviewed_dir", lambda: rd)
    assert site.timezone({}) == "America/New_York"
    assert site.timezone({site.TIMEZONE_ENV: "Europe/Helsinki"}) == "Europe/Helsinki"
    assert site.timezone({site.TIMEZONE_ENV: "  "}) == "America/New_York"
    monkeypatch.setattr(site, "reviewed_dir", lambda: None)
    assert site.timezone({}) == ""                       # rules/site.yaml: empty, UTC


@pytest.mark.parametrize("bad", ["FLE Standard Time", "../etc/passwd", "Europe/Helsinki\nX=1", "Europe//Helsinki"])
def test_invalid_zone_refused(bad):
    with pytest.raises(site.SiteError):
        site.valid_timezone(bad)


def test_valid_zones():
    for tz in ("Europe/Helsinki", "UTC", "America/Argentina/Buenos_Aires", "Etc/GMT-2"):
        assert site.valid_timezone(f" {tz} ") == tz
