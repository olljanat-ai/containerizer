"""Light or dark (theme.py): the stylesheet's dark rules also apply when dark is picked, and not when light is."""
from containerizer import theme, webui


def test_dark_rules_follow_the_system_unless_a_choice_is_made():
    css = ("a{color:blue}@media (prefers-color-scheme:dark){:root{--bg:#000}.x,.y b{color:#fff}}"
           ".z{margin:0}@media (prefers-color-scheme: dark){html{color-scheme:dark}}")
    t = theme.themed(css)
    assert ("@media (prefers-color-scheme:dark){html:not([data-theme=light]){--bg:#000}"
            "html:not([data-theme=light]) .x,html:not([data-theme=light]) .y b{color:#fff}}"
            "html[data-theme=dark]{--bg:#000}html[data-theme=dark] .x,html[data-theme=dark] .y b{color:#fff}") in t
    assert "html:not([data-theme=light]){color-scheme:dark}}html[data-theme=dark]{color-scheme:dark}" in t
    assert t.startswith("a{color:blue}") and ".z{margin:0}" in t
    assert theme.themed("p{x:1}").startswith("p{x:1}")                    # nothing to change


def test_every_page_loads_the_script_in_its_head_and_the_bar_has_the_button():
    html = webui.page("t", "x")
    assert "<script src='/static/theme.js'></script></head>" in html
    assert "data-theme-toggle hidden" in webui._nav("John Doe")            # shown by the script only
    assert "localStorage" in theme.JS and "cz-theme" in theme.JS
    # the whole stylesheet: every dark block has its picked-dark twin
    from containerizer.connectivityui import CSS as C2
    from containerizer.migrationplan import CSS as C3
    t = theme.themed(webui.CSS + C2 + C3 + theme.CSS)
    assert t.count("html[data-theme=dark]") == t.count("html:not([data-theme=light])") + 1   # + color-scheme
