"""Links between an application's results page and its admin pages, for people who may open both."""
from types import SimpleNamespace

from containerizer import webui


def _s(admin=False, operator=False, scopes=()):
    return SimpleNamespace(admin=admin, operator=operator, scopes=list(scopes))


APP = {"ApplicationId": 7, "ProductId": 3}


def test_admin_gets_settings_databases_and_refactoring():
    adm = SimpleNamespace(devdb=object(), system=None)
    links = webui.admin_links(adm, None, _s(admin=True), APP)
    assert links == [("Application settings", "/admin/applications/7"), ("Dev databases", "/admin/dev-databases/7"),
                     ("Refactoring orders", "/admin/refactoring")]
    html = webui._admin_links_html(links)
    assert "href='/admin/applications/7'>Application settings</a>" in html and html.count(" · ") == 2


def test_operator_has_no_application_settings():
    adm = SimpleNamespace(devdb=None, system=None)            # no dev databases here: no link either
    assert webui.admin_links(adm, None, _s(operator=True), APP) == [("Refactoring orders", "/admin/refactoring")]


def test_nothing_for_no_links():
    assert webui._admin_links_html([]) == "" and webui._admin_links_html(None) == ""


def test_brand_in_the_top_bar_on_every_results_page():
    """Containerizer's logo and name sit in the top bar's right corner (with or without sign-in links), not above
    the front page's title."""
    html = webui.render_overview({"apps": [], "unmapped": {}}, nav="")
    bar = html[html.index("<div class='topnav'>"):html.index("</div>", html.index("<div class='topnav'>"))]
    assert "class='brand' href='https://containerizer.eu/'" in bar
    assert "<header><h1>Containerization readiness</h1>" in html
    assert "class='brand'" in webui._nav("<a href='/admin'>Admin</a>") and webui._nav("x").index("class='brand'") < webui._nav("x").index("<span>x</span>")
