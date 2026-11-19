"""The built-in results database from the network (sqlaccess.py, sysagent, Admin -> System -> Results database
access): the read-only login cz_readonly and incoming connections on port 1433 from the listed networks."""
import json

import pytest

from containerizer import sqlaccess, sysagent
from test_appliance import ADMIN, page, requests_in, shell  # noqa: F401 - the page fixture

GOOD_PW = "Reports-2026-readonly"


def test_networks_and_passwords_are_checked():
    assert sqlaccess.networks("10.20.0.0/16, 192.0.2.15\n2001:db8::/32 10.20.0.0/16") == \
        ["10.20.0.0/16", "192.0.2.15/32", "2001:db8::/32"]
    for bad in ("10.0.0.0/33", "intranet", "127.0.0.0/8", "169.254.0.0/16"):
        with pytest.raises(sqlaccess.SqlAccessError):
            sqlaccess.networks(bad)
    sqlaccess.check_password(GOOD_PW)
    for bad in ("Short-1", "alllowercaseletters", "Has;semicolon-2026", "Quote'd-Password-1"):
        with pytest.raises(sqlaccess.SqlAccessError):
            sqlaccess.check_password(bad)


def test_the_firewall_accepts_1433_only_from_the_listed_networks_and_never_from_pods():
    on = {"incoming": True, "networks": ["10.20.0.0/16", "2001:db8::/32"]}
    nft, _ = sysagent.render(sysagent.system_rules(), {"mode": "enforce", "rules": []}, upstreams=["10.0.0.2"], sql_access=on)
    line4 = next(x for x in nft.splitlines() if "tcp dport 1433" in x and "ip saddr" in x)
    assert "ip saddr { 10.20.0.0/16 }" in line4 and line4.strip().startswith("iifname != {") and '"cni0"' in line4
    assert "ip6 saddr { 2001:db8::/32 } tcp dport 1433 accept" in nft
    assert nft.index("tcp dport 1433") < nft.index('log prefix "cz-in-drop: "')
    for off in (None, {"incoming": False, "networks": ["10.20.0.0/16"]}, {"incoming": True, "networks": []}):
        nft, _ = sysagent.render(sysagent.system_rules(), {"mode": "enforce", "rules": []}, upstreams=["10.0.0.2"],
                                 sql_access=off)
        assert "1433" not in nft


def test_the_proxy_listens_on_the_appliances_own_addresses():
    listen = sqlaccess.listen_addresses(["10.0.0.5/24", "fe80::1/64", "2001:db8::5/64"])
    assert listen == ["10.0.0.5:1433", "[2001:db8::5]:1433"]
    cmd = sqlaccess.proxy_command(listen)
    assert cmd[:2] == ["systemd-run", "--unit=containerizer-sql-proxy"] and cmd[-1] == "127.0.0.1:1433"
    assert "--socket-property=ListenStream=10.0.0.5:1433" in cmd and "--property=DynamicUser=yes" in cmd
    assert cmd[-3] == "/usr/lib/systemd/systemd-socket-proxyd"


def test_the_system_page(page):  # noqa: F811
    s = json.loads((page.status_dir / "status.json").read_text())
    s["sql_access"] = {"local": True, "login": False, "incoming": False, "networks": []}
    (page.status_dir / "status.json").write_text(json.dumps(s))
    _, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "Results database access" in body and "Turn on the read-only login" in body and "<b>off</b>" in body
    for form, why in (({"password": ["Reports-2026-x"], "password2": ["Reports-2026-y"]}, "differ"),
                      ({"password": ["weak"], "password2": ["weak"]}, "12+to+128")):
        _, _, loc = page.handle(ADMIN, "POST", ["system", "sql-readonly"], {}, form, shell)
        assert why in loc and loc.endswith("#sql-access")
    assert requests_in(page) == []
    page.handle(ADMIN, "POST", ["system", "sql-readonly"], {}, {"password": [GOOD_PW], "password2": [GOOD_PW]}, shell)
    req = requests_in(page)[-1]
    assert req["action"] == "sql-readonly" and req["enabled"] is True and req["password"] == GOOD_PW
    _, _, loc = page.handle(ADMIN, "POST", ["system", "sql-incoming"], {}, {"enabled": ["1"], "networks": [""]}, shell)
    assert "list+the+networks" in loc
    page.handle(ADMIN, "POST", ["system", "sql-incoming"], {}, {"enabled": ["1"], "networks": ["10.20.0.0/16\n192.0.2.15"]},
                shell)
    req = next(r for r in requests_in(page) if r["action"] == "sql-incoming")
    assert (req["action"], req["enabled"], req["networks"]) == ("sql-incoming", True, ["10.20.0.0/16", "192.0.2.15/32"])
    s["sql_access"] = {"local": True, "login": True, "login_set_at": "2026-11-19T10:00:00+00:00", "incoming": True,
                       "networks": ["10.20.0.0/16"], "listening": ["10.0.0.5:1433"]}
    (page.status_dir / "status.json").write_text(json.dumps(s))
    _, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "Set a new password" in body and "Turn off the read-only login" in body and "10.0.0.5:1433" in body
    assert GOOD_PW not in body
    # an external SQL Server: nothing to set here
    s["sql_access"] = {"local": False}
    (page.status_dir / "status.json").write_text(json.dumps(s))
    n = len(requests_in(page))
    _, _, loc = page.handle(ADMIN, "POST", ["system", "sql-incoming"], {}, {"enabled": ["1"], "networks": ["10.0.0.0/8"]}, shell)
    assert "external+SQL+Server" in loc and len(requests_in(page)) == n


@pytest.fixture
def agent(tmp_path, monkeypatch):
    p = sysagent.Paths(run=tmp_path / "run", conf=tmp_path / "appliance.conf", appliance_env=tmp_path / "appliance.env",
                       os_release=tmp_path / "os-release", snapshots=tmp_path / "snapshots",
                       elemental_run=tmp_path / "elemental", task=tmp_path / "task.json", plan=tmp_path / "plan.json",
                       drain=tmp_path / "drain.json", rules=tmp_path / "egress.json", system_rules=tmp_path / "sys.json",
                       history=tmp_path / "h.jsonl")
    monkeypatch.setattr(sysagent, "P", p)
    (p.run / "requests").mkdir(parents=True)
    p.conf.write_text("CZ_OS_IMAGE=x\nCZ_SIGNER_REPO=y\n")
    p.appliance_env.write_text("")
    monkeypatch.setattr(sqlaccess, "SETTINGS", tmp_path / "sql-access.json")
    monkeypatch.setattr(sysagent, "egress_status", lambda: {})
    monkeypatch.setattr(sysagent, "sandbox_https_status", lambda: {})
    monkeypatch.setattr(sysagent, "backup_status", lambda: None)
    calls, active = [], {"rc": 3}
    monkeypatch.setattr(sysagent, "run", lambda cmd, **kw: calls.append(cmd) or "")
    monkeypatch.setattr(sysagent.subprocess, "run", lambda cmd, **kw: type("R", (), {"returncode": active["rc"]})())
    monkeypatch.setattr(sysagent, "network_state", lambda: {"addresses": ["10.0.0.5/24"]})
    fw = []
    monkeypatch.setattr(sysagent, "apply_firewall", lambda reload_dns=True: fw.append(sqlaccess.load()))
    sql = []

    class Conn:
        def cursor(self):
            return self

        def execute(self, q, params=None):
            if "boom" in str(sql):
                raise RuntimeError(f"Password validation failed for {GOOD_PW}")
            sql.append(q)

        def commit(self):
            pass

        def close(self):
            pass
    monkeypatch.setattr(sysagent, "sql_owner", lambda: Conn())
    logins = []
    from containerizer import sqlstore
    monkeypatch.setattr(sqlstore, "create_login", lambda conn, login, pw, role: logins.append((login, pw, role)))

    def request(**body):
        (p.run / "requests" / f"{len(list((p.run / 'requests').iterdir()))}.json").write_text(json.dumps(body))
    return {"p": p, "calls": calls, "active": active, "fw": fw, "sql": sql, "logins": logins, "request": request}


def test_the_agent_sets_the_login_and_never_keeps_the_password(agent):
    agent["request"](action="sql-readonly", requested_by="alice@x", enabled=True, password=GOOD_PW)
    assert sysagent.process() == 0
    assert agent["logins"] == [("cz_readonly", GOOD_PW, "reader")] and "ALTER LOGIN [cz_readonly] ENABLE" in agent["sql"]
    st = json.loads((agent["p"].run / "status.json").read_text())["sql_access"]
    assert st["login"] and st["login_set_by"] == "alice@x" and st["local"]
    assert GOOD_PW not in sqlaccess.SETTINGS.read_text() and GOOD_PW not in json.dumps(st)
    agent["request"](action="sql-readonly", requested_by="alice@x", enabled=False)
    assert sysagent.process() == 0 and "DISABLE" in agent["sql"][-1] and not sqlaccess.load()["login"]
    # the database refuses: the reason on the page, without the password
    agent["sql"].append("boom")
    agent["request"](action="sql-readonly", requested_by="alice@x", enabled=True, password=GOOD_PW)
    assert sysagent.process() == 1
    err = sqlaccess.load()["error"]
    assert "refused" in err and GOOD_PW not in err and "***" in err
    # an external SQL Server: not here
    agent["p"].appliance_env.write_text("CZ_SQL_SERVER=sql01.example.com\nCZ_SQL_USER=owner\n")
    agent["request"](action="sql-incoming", requested_by="alice@x", enabled=True, networks=["10.0.0.0/8"])
    assert sysagent.process() == 1 and "external" in sqlaccess.load()["error"]


def test_the_agent_opens_and_closes_incoming_connections(agent, monkeypatch):
    agent["request"](action="sql-incoming", requested_by="alice@x", enabled=True, networks=["10.20.0.0/16"])
    assert sysagent.process() == 0
    assert agent["fw"][-1]["incoming"] and agent["fw"][-1]["networks"] == ["10.20.0.0/16"]
    start = next(c for c in agent["calls"] if c[0] == "systemd-run")
    assert "--socket-property=ListenStream=10.0.0.5:1433" in start
    assert sqlaccess.load()["listening"] == ["10.0.0.5:1433"]
    # every 5 minutes: running and the same address, nothing to do; a new address, started again
    agent["active"]["rc"] = 0
    assert sysagent.sql_access_reconcile() == "up to date"
    monkeypatch.setattr(sysagent, "network_state", lambda: {"addresses": ["10.0.0.9/24"]})
    assert sysagent.sql_access_reconcile() == "started" and sqlaccess.load()["listening"] == ["10.0.0.9:1433"]
    agent["request"](action="sql-incoming", requested_by="alice@x", enabled=False, networks=[])
    assert sysagent.process() == 0
    assert ["systemctl", "stop", "containerizer-sql-proxy.socket", "containerizer-sql-proxy.service"] in agent["calls"]
    assert sqlaccess.load()["listening"] == []
    assert not agent["fw"][-1]["incoming"]
