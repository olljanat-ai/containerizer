"""Tags of applications (containerizer/tags.py): parsing, the front page filter, the results page editor.
Saving them through the admin pages, by role, is in test_roles.py and test_admin.py."""
from datetime import datetime

from containerizer import webui
from containerizer.tags import parse_tags, split_tags


def test_parse_tags():
    assert parse_tags(" pci,  Customer   facing ,PCI,, wave 1 ") == (["pci", "Customer facing", "wave 1"], None)
    assert parse_tags("") == ([], None)
    assert parse_tags("Kärnsystem, C#, R&D, ops/infra, v1.2+") == (["Kärnsystem", "C#", "R&D", "ops/infra", "v1.2+"], None)
    for bad in ("<b>", "x" * 41, "a'b", "semi;colon"):
        assert parse_tags(bad) == (None, "bad"), bad
    assert parse_tags(",".join(f"t{i}" for i in range(21))) == (None, "many")
    assert split_tags(None) == [] and split_tags("a,b c") == ["a", "b c"]


def _app(i, name, bid, tags):
    return {"ApplicationId": i, "ApplicationName": name, "ProductId": 1, "ProductName": "P", "BusinessUnitId": bid,
            "BusinessUnitName": f"BU{bid}", "Rating": "B", "Score": 70, "Confidence": 0.9, "Summary": "s",
            "AssessedAt": datetime(2026, 11, 4), "Verified": False, "Components": 1, "MainObstacle": "", "Tags": tags}


DATA = {"apps": [_app(1, "billing", 1, "PCI,wave 1"), _app(2, "ledger", 1, "pci"), _app(3, "freight", 2, None)],
        "unmapped": {}}


def test_overview_tag_chips_and_filter():
    html = webui.render_overview(DATA)
    assert "aria-label='Filter by tag'" in html
    assert "href='/?tag=PCI'>PCI <span class='muted'>2</span>" in html       # one chip per tag regardless of case
    assert "href='/?tag=wave+1'>wave 1 <span class='muted'>1</span>" in html
    assert "<a class='tag' href='/?tag=PCI'>PCI</a>" in html                   # on the application's row
    html = webui.render_overview(DATA, tag_filter="pci")
    assert "/app/1" in html and "/app/2" in html and "/app/3" not in html
    assert "class='chip tagchip on' href='/'" in html                          # the chip on: a click clears it
    assert "Applications assessed</div><div class='value'>2<" in html
    # combined with a business unit: both kept in each other's links
    html = webui.render_overview(DATA, bu_filter="2", tag_filter="pci")
    assert "/app/3" not in html and "No applications in this business unit have the tag <b>pci</b>" in html
    assert "href='/?bu=1&amp;tag=pci'" in html and "href='/?bu=2'>Any</a>" in html
    # no tags anywhere: no tag row
    assert "Filter by tag" not in webui.render_overview({"apps": [_app(3, "freight", 2, None)], "unmapped": {}})


def test_application_page_tags_and_editor():
    app = {"ApplicationId": 5, "Tags": "pci,<x>"}
    assert "<a class='tag' href='/?tag=pci'>pci</a>" in webui._tags_section(app, {})
    assert "&lt;x&gt;" in webui._tags_section(app, {}) and "<form" not in webui._tags_section(app, {})
    html = webui._tags_section(app, {"tags_csrf": "<input type='hidden' name='csrf' value='t'>", "tags_notice": "saved"})
    assert "action='/admin/tags/5'" in html and "value='pci, &lt;x&gt;'" in html and "Tags saved." in html
    assert webui._tags_section({"ApplicationId": 5, "Tags": None}, {}) == ""     # nothing to show to readers
    assert "none" in webui._tags_section({"ApplicationId": 5, "Tags": None}, {"tags_csrf": "c"})


def test_unmapped_applications_are_for_administrators_only():
    """Applications not mapped to a product are left out of the front page for everyone but administrators (and
    where there is no sign-in at all), with a note for the administrators."""
    data = {"apps": [_app(1, "billing", 1, None), {**_app(2, "orphan", None, None), "ProductId": None,
                                                    "ProductName": None, "BusinessUnitName": None}], "unmapped": {"Application": 1}}
    html = webui.render_overview(data, admin=False, nav="<a href='/admin'>Admin</a>")
    assert "/app/1" in html and "/app/2" not in html and "not mapped" not in html
    assert "Applications assessed</div><div class='value'>1<" in html
    html = webui.render_overview(data, admin=True, nav="<a href='/admin'>Admin</a>")
    assert "/app/2" in html and "shown to administrators only" in html and "/admin/applications?show=unmapped" in html
    assert "/app/2" in webui.render_overview(data)                  # no sign-in: everything, as before


# --------------------------------------------------------------------------- automatic tags

def test_stateful_is_an_automatic_tag_nobody_edits():
    from containerizer.tags import with_auto
    assert parse_tags("pci, Stateful, wave 1") == (["pci", "wave 1"], None)       # the editor drops it
    assert with_auto("pci,stateful", ["stateful"]) == "stateful,pci"
    assert with_auto("pci", []) == "pci" and with_auto(None, []) is None


def test_overview_filters_by_the_stateful_tag():
    apps = [_app(1, "billing", 1, "stateful,PCI"), _app(2, "ledger", 1, "pci"), _app(3, "freight", 2, None)]
    apps[0]["AutoTags"] = ["stateful"]
    apps[0]["Rating"] = "A"
    html = webui.render_overview({"apps": apps, "unmapped": {}}, tag_filter="stateful")
    assert "/app/1" in html and "/app/2" not in html and "/app/3" not in html
    assert "<a class='tag auto' href='/?tag=stateful' title='Set automatically" in html
    assert "<span class='stateful-mark' title='Set automatically" in html


def test_results_page_shows_the_automatic_tag_outside_the_editor(monkeypatch):
    monkeypatch.setattr(webui, "_STATE_RULES", {"sqlite-local": "local"})
    app = {"ApplicationId": 5, "Tags": "pci",
           "components": [{"ComponentId": 1, "ComponentName": "Parts", "Tier": "server"}],
           "findings": [{"ComponentId": 1, "ComponentName": "Parts", "RuleId": "sqlite-local", "Title": "db",
                         "OnlyCommands": None}]}
    html = webui._tags_section(app, {"tags_csrf": "<input type='hidden'>"})
    assert "class='tag auto' href='/?tag=stateful'" in html and "value='pci'" in html
