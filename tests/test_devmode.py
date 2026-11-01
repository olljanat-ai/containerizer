"""Development mode (CONTAINERIZER_DEV_NO_AUTH): the admin pages without sign-in, on a developer's own machine
or lab only. Refused on the appliance and next to a configured sign-in."""
import json

import pytest

from containerizer import admin as adminmod, webui
from containerizer.oidc import OidcError

BASE = {"CONTAINERIZER_DEV_NO_AUTH": "1", "CONTAINERIZER_ADMIN_SQL": "Server=127.0.0.1,1433;Database=Containerizer;User Id=cz_admin",
        "CONTAINERIZER_ADMIN_SQL_PASSWORD": "x"}


def test_off_unless_asked_for():
    for v in (None, "", "0", "false", "off"):
        assert adminmod.dev_identity({} if v is None else {"CONTAINERIZER_DEV_NO_AUTH": v}) is None
    with pytest.raises(OidcError, match="must be 1"):
        adminmod.dev_identity({"CONTAINERIZER_DEV_NO_AUTH": "please"})


def test_refused_on_the_appliance(tmp_path):
    with pytest.raises(OidcError, match="refused on the appliance"):
        adminmod.dev_identity({**BASE, "CONTAINERIZER_APPLIANCE": "1"})
    (tmp_path / "status.json").write_text(json.dumps({"version": "v0.2.0"}))   # the system agent's status: an appliance
    with pytest.raises(OidcError, match="refused on the appliance"):
        adminmod.dev_identity({**BASE, "CONTAINERIZER_SYSTEM_DIR": str(tmp_path)})


def test_refused_next_to_a_configured_sign_in():
    with pytest.raises(OidcError, match="cannot both be set"):
        adminmod.dev_identity({**BASE, "CONTAINERIZER_OIDC_ISSUER": "https://login.example.com"})


def test_identity_and_roles():
    d = adminmod.dev_identity(BASE)
    assert (d.user, d.name, d.admin, d.operator, d.viewer) == ("john.doe@example.com", "John Doe", True, False, True)
    d = adminmod.dev_identity({**BASE, "CONTAINERIZER_DEV_ROLES": "operator", "CONTAINERIZER_DEV_USER": "jane@example.com",
                               "CONTAINERIZER_DEV_NAME": "Jane Doe"})
    assert (d.user, d.name, d.admin, d.operator) == ("jane@example.com", "Jane Doe", False, True)
    with pytest.raises(OidcError, match="CONTAINERIZER_DEV_ROLES"):
        adminmod.dev_identity({**BASE, "CONTAINERIZER_DEV_ROLES": "root"})


def test_build_has_no_provider_and_no_api(capsys):
    adm = adminmod.build({**BASE, "CONTAINERIZER_PUBLIC_URL": "http://192.168.8.139:8080"})
    assert adm.dev and adm.api is None and adm.cfg.public_url == "http://192.168.8.139:8080"
    assert not adm.cfg.secure and adm.cookie == "cz_session"            # plain http: no Secure / __Host- cookie
    assert "NO SIGN-IN" in capsys.readouterr().err
    with pytest.raises(OidcError, match="PUBLIC_URL"):
        adminmod.build({**BASE, "CONTAINERIZER_PUBLIC_URL": "javascript:alert(1)"})
    assert adminmod.build({"CONTAINERIZER_ADMIN_SQL": "x", "CONTAINERIZER_ADMIN_SQL_PASSWORD": "x"}) is None   # off


def test_login_makes_a_session_and_forms_still_need_their_token():
    adm = adminmod.build({**BASE, "CONTAINERIZER_PUBLIC_URL": "http://127.0.0.1:8080"})
    adm.log_access = lambda *a, **k: None
    r = adm.handle("GET", "/admin/llm-queue", "", {}, b"")                  # no session: to the login
    assert r.status == 303 and dict(r.headers)["Location"].startswith("/login?")
    r = adm.handle("GET", "/login", "next=/admin/llm-queue", {}, b"")        # no provider: straight back, signed in
    h = dict(r.headers)
    assert r.status == 303 and h["Location"] == "/admin/llm-queue"
    sid = h["Set-Cookie"].split(";")[0].split("=", 1)[1]
    s = adm.session({"Cookie": f"cz_session={sid}"})
    assert s.user == "john.doe@example.com" and s.admin and s.csrf
    assert dict(adm.handle("GET", "/login", "next=//evil.example.com", {}, b"").headers)["Location"] == "/admin"
    # CSRF is still checked: a POST without the form's token is refused before anything changes
    r = adm.handle("POST", "/admin/llm-queue/settings", "", {"Cookie": f"cz_session={sid}",
                                                              "Origin": "http://127.0.0.1:8080"}, b"Paused=on")
    assert r.status == 403 and "expired" in r.body


def test_every_page_shows_the_banner(monkeypatch):
    monkeypatch.setattr(webui, "DEV_BANNER", "<div class='devmode'>Development mode: no sign-in.</div>")
    html = webui.page("x", "<p>y</p>")
    assert "<body><div class='devmode'>Development mode: no sign-in.</div><main>" in html
    monkeypatch.setattr(webui, "DEV_BANNER", "")
    assert "devmode" not in webui.page("x", "<p>y</p>")
