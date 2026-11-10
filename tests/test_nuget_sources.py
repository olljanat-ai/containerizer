"""NuGet source names for packageSourceMapping keys a repository does not define (nugetsources.py)."""
from pathlib import Path

import pytest

from containerizer import feedproxy, nugetsources
from containerizer.assess import assess
from containerizer.generate import generate_app, k8s_name
from tests.test_engine import web_app, write

FEED = "https://pkgs.dev.azure.com/contoso/"
MAIN = "https://pkgs.dev.azure.com/contoso/_packaging/main/nuget/v3/index.json"

MAPPED = """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>{sources}</packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
    <packageSource key="Contoso"><package pattern="Contoso.*" /></packageSource>
    {more}
  </packageSourceMapping>
</configuration>"""


def test_parse_names_and_urls():
    got = nugetsources.parse(f"internal, Contoso = {MAIN}\n# a comment\n\nlegacy", FEED)
    assert got == [("internal", MAIN), ("Contoso", MAIN), ("legacy", FEED)]
    assert nugetsources.parse("", FEED) == []


@pytest.mark.parametrize("text,why", [
    ("x = https://other.example.com/index.json", "not under the feed's URL"),
    ("x = http://pkgs.dev.azure.com/contoso/a", "not a plain https://"),
    (f"x = {FEED}a?b=1", "not a plain https://"),
    ("a, A", "given twice"),
    ("bad<name>", "not a source name"),
    (", x", "not a source name"),
])
def test_parse_refuses(text, why):
    with pytest.raises(ValueError, match=why):
        nugetsources.parse(text, FEED)


def test_names_clash_case_insensitively():
    assert nugetsources.clashes([("Contoso", MAIN), ("new", MAIN)], [[("contoso", FEED)]]) == ["Contoso"]


def _repo(tmp_path, sources="", more="", at="NuGet.Config"):
    root = tmp_path / "app"
    web_app(root)
    write(root, at, MAPPED.format(sources=sources, more=more))
    return root


def test_plan_adds_registered_names_and_lists_unknown(tmp_path):
    root = _repo(tmp_path, more='<packageSource key="Shared"><package pattern="Shared.*" /></packageSource>')
    known = {"contoso": ("Contoso", MAIN)}
    got = nugetsources.plan_sources(root, "src/Web/Web.csproj", known)
    assert got == {"config": "NuGet.Config", "add": [["Contoso", MAIN]], "missing": ["Shared"],
                   "same": []}


def test_defined_sources_need_nothing(tmp_path):
    root = _repo(tmp_path, sources=f'<add key="contoso" value="{MAIN}" />')
    assert nugetsources.plan_sources(root, "src/Web/Web.csproj", {}) is None


def test_cleared_sources_get_nuget_org(tmp_path):
    root = _repo(tmp_path, sources=f'<clear /><add key="Contoso" value="{MAIN}" />')
    got = nugetsources.plan_sources(root, "src/Web/Web.csproj", {})
    assert got["add"] == [["nuget.org", "https://api.nuget.org/v3/index.json"]] and not got["missing"]


def test_a_url_is_added_once(tmp_path):
    # NuGet keeps one source per URL: a second name for it is listed, not added
    root = _repo(tmp_path, sources=f'<add key="corp" value="{MAIN}/" />',
                 more='<packageSource key="internal"><package pattern="Internal.*" /></packageSource>')
    got = nugetsources.plan_sources(root, "src/Web/Web.csproj", {"contoso": ("Contoso", MAIN),
                                                                  "internal": ("internal", MAIN)})
    assert got["add"] == [] and got["same"] == [["Contoso", "corp"], ["internal", "corp"]]
    md = nugetsources.migration_markdown({"web": got})
    assert "`Contoso`: **not added**: its URL is already the source `corp`" in md


def test_nearest_config_gets_the_sources(tmp_path):
    root = _repo(tmp_path)
    write(root, "src/nuget.config", "<configuration><packageSources /></configuration>")
    got = nugetsources.plan_sources(root, "src/Web/Web.csproj", {"contoso": ("Contoso", MAIN)})
    assert got["config"] == "src/nuget.config" and got["add"] == [["Contoso", MAIN]]


def test_broken_config_is_ignored(tmp_path):
    root = tmp_path / "app"
    web_app(root)
    write(root, "NuGet.Config", "<configuration><packageSourceMapping>")
    assert nugetsources.plan_sources(root, "src/Web/Web.csproj", {}) is None


def test_generated_dockerfile_and_migration(tmp_path, monkeypatch):
    root = _repo(tmp_path, more="<packageSource key=\"Old feed\"><package pattern=\"Old.*\" /></packageSource>")
    proxy = type("P", (), {"feeds": [feedproxy.Feed("nuget", FEED, "tok", "", None, [("Contoso", MAIN)]),
                                     feedproxy.Feed("npm", "https://npm.example.com/", "t2", "", None,
                                                    [("Old feed", "https://npm.example.com/x")])]})()
    monkeypatch.setattr(feedproxy, "active", lambda: proxy)
    a = assess(root)
    out = tmp_path / "out"
    generate_app(a, out)
    comp = k8s_name(a.components[0].name)
    df = (out / comp / "Dockerfile").read_text()
    add = f"RUN dotnet nuget add source {MAIN} -n Contoso --configfile NuGet.Config"
    assert add in df and df.index(add) < df.index("dotnet restore")
    assert "nuget-sources: NuGet.Config maps packages to Contoso" in df and "tok" not in df
    md = (out / "MIGRATION.md").read_text()
    assert "## NuGet package sources" in md and f"`Contoso`: added as {MAIN}" in md
    # an npm feed's names are not NuGet sources
    assert "`Old feed`: **not defined**" in md


def test_no_mapping_no_change(tmp_path, monkeypatch):
    root = tmp_path / "app"
    web_app(root)
    monkeypatch.setattr(feedproxy, "active", lambda: None)
    a = assess(root)
    out = tmp_path / "out"
    generate_app(a, out)
    assert "nuget add source" not in (out / k8s_name(a.components[0].name) / "Dockerfile").read_text()
    assert "NuGet package sources" not in (out / "MIGRATION.md").read_text()
