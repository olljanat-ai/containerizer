"""The appliance: the System and Firewall admin pages (appliance.py) and the root system agent
(sysagent.py): signed upgrades, roll back, the egress allow-list and its nftables/dnsmasq rendering."""
import io
import json
import re
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from containerizer import appliance, sysagent
from containerizer.sysagent import RuleError, render, validate_rules

DIGEST = "sha256:" + "ab" * 32
STATE = """date: "2026-10-30T10:00:00Z"
state:
  label: COS_STATE
  snapshots:
    1:
      source: dir:///run/rootfsbase
      digest: ""
      active: false
      date: "2026-10-01T10:00:00Z"
    2:
      source: oci://ghcr.io/olljanat-ai/containerizer-appliance@sha256:abab
      active: true
      labels:
        version: v1.1.0
      date: "2026-10-30T10:00:00Z"
"""


@pytest.fixture
def paths(tmp_path, monkeypatch):
    p = sysagent.Paths(conf=tmp_path / "appliance.conf", system_rules=tmp_path / "egress-system.json",
                       rules=tmp_path / "etc" / "egress.json", history=tmp_path / "var" / "history.jsonl",
                       task=tmp_path / "var" / "last-task.json", plan=tmp_path / "var" / "restart-plan.json",
                       drain=tmp_path / "var" / "llm-drain.json",
                       network=tmp_path / "etc" / "network", network_run=tmp_path / "run" / "systemd-network",
                       run=tmp_path / "run", dnsmasq=tmp_path / "run" / "dnsmasq.conf", nft=tmp_path / "run" / "fw.nft",
                       os_release=tmp_path / "os-release", snapshots=tmp_path / "snapshots",
                       appliance_env=tmp_path / "appliance.env", resolved=tmp_path / "resolv.conf",
                       elemental_run=tmp_path / "elemental")
    monkeypatch.setattr(sysagent, "P", p)
    (p.run / "requests").mkdir(parents=True)
    p.elemental_run.mkdir()
    (p.elemental_run / "active_mode").touch()
    p.os_release.write_text('NAME="Debian"\nIMAGE_TAG="v1.1.0"\n')
    p.conf.write_text("CZ_OS_IMAGE=ghcr.io/olljanat-ai/containerizer-appliance\nCZ_SIGNER_REPO=olljanat-ai/containerizer\n")
    p.system_rules.write_text(json.dumps({"rules": [{"host": "ghcr.io", "ports": "443", "note": "upgrades"},
                                                    {"host": "pkg-containers.githubusercontent.com", "ports": [443]}]}))
    for sid, ver in ((1, "v1.0.0"), (2, "v1.1.0")):
        d = p.snapshots / str(sid) / "snapshot" / "etc"
        d.mkdir(parents=True)
        (d / "os-release").write_text(f'IMAGE_TAG="{ver}"\n')
    return p


class FakeRun:
    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = outputs or {}

    def __call__(self, cmd, timeout=0, check=True, input=None):
        self.calls.append(cmd)
        for k, v in self.outputs.items():
            if cmd[:len(k)] == list(k):
                if isinstance(v, Exception):
                    raise v
                return v
        return ""


def fake_run(monkeypatch, **extra):
    outputs = {("elemental", "state"): STATE, ("elemental", "version"): "v2.3.5\n",
               ("cosign", "verify"): json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}}])}
    outputs.update({tuple(k.split()): v for k, v in extra.items()})
    r = FakeRun(outputs)
    monkeypatch.setattr(sysagent, "run", r)
    return r


# ------------------------------------------------------------------------------- versions, registry

def test_newer_versions_only_releases_newest_first():
    tags = ["latest", "v1.0.0", "v1.2.0", "v1.10.0", "v1.2.0-rc1", "sha-abc", "v0.9.9", "v1.1.0"]
    assert appliance.newer_versions(tags, "v1.1.0") == ["v1.10.0", "v1.2.0"]
    assert appliance.newer_versions(tags, "dev")[:2] == ["v1.10.0", "v1.2.0"]
    assert appliance.newer_versions(tags, "v1.10.0") == []


def test_ghcr_tags_anonymous_token_then_list():
    seen = []

    def opener(req, timeout=0):
        url = req if isinstance(req, str) else req.full_url
        seen.append((url, None if isinstance(req, str) else req.get_header("Authorization")))
        body = {"token": "t0k"} if "/token?" in url else {"name": "x", "tags": ["v1.0.0", 5, "v1.1.0"]}
        return io.BytesIO(json.dumps(body).encode())

    assert appliance.ghcr_tags("ghcr.io/olljanat-ai/containerizer-appliance", opener=opener) == ["v1.0.0", "v1.1.0"]
    assert "scope=repository%3Aolljanat-ai%2Fcontainerizer-appliance%3Apull" in seen[0][0]
    assert seen[1] == ("https://ghcr.io/v2/olljanat-ai/containerizer-appliance/tags/list?n=1000", "Bearer t0k")
    with pytest.raises(appliance.RegistryError):
        appliance.ghcr_tags("docker.io/library/debian", opener=opener)


# ------------------------------------------------------------------------------- allow-list

def test_validate_rules_normalizes_and_rejects():
    r = validate_rules({"rules": [{"host": "*.NuGet.org.", "ports": "443, 80"},
                                  {"host": "nuget.org", "ports": ["tcp/80", 443]},       # duplicate after normalizing
                                  {"cidr": "10.20.1.5/16", "ports": "udp/123", "note": "  ntp \n server "}]})
    assert r == {"mode": "enforce", "rules": [{"host": "nuget.org", "ports": ["tcp/80", "tcp/443"], "note": ""},
                                              {"cidr": "10.20.0.0/16", "ports": ["udp/123"], "note": "ntp server"}]}
    for bad in ({"host": "nuget"}, {"host": "a b.com"}, {"host": "x.com/path"}, {"host": "-x.com"},
                {"host": "x.com", "ports": "0"}, {"host": "x.com", "ports": "70000"}, {"host": "x.com", "ports": "icmp/1"},
                {"cidr": "0.0.0.0/0"}, {"cidr": "::/0"}, {"cidr": "10.0.0.300"}):
        with pytest.raises(RuleError):
            validate_rules({"rules": [bad]})
    with pytest.raises(RuleError):
        validate_rules({"mode": "off", "rules": []})
    assert validate_rules({"mode": None, "rules": None}) == {"mode": "enforce", "rules": []}
    assert validate_rules({"rules": [{"host": "bücher.example"}]})["rules"][0]["host"] == "xn--bcher-kva.example"


def test_render_dns_only_allowed_names_and_parent_sets():
    system = validate_rules({"rules": [{"host": "ghcr.io"}]})
    admin = validate_rules({"rules": [{"host": "github.com", "ports": "443"}, {"host": "ssh.github.com", "ports": "22"},
                                      {"cidr": "10.20.0.0/16", "ports": "1433"}, {"host": "pool.ntp.org", "ports": "udp/123"}]})
    nft, dns = render(system, admin, ["192.168.1.1", "1.1.1.1"])
    lines = dns.splitlines()
    assert "no-resolv" in lines                                    # everything else: REFUSED
    assert "server=/github.com/192.168.1.1" in lines and "server=/ghcr.io/1.1.1.1" in lines
    # a subdomain with its own rule still gets the parent's set (dnsmasq uses the longest match only)
    assert "nftset=/ssh.github.com/4#inet#cz_firewall#f4_tcp22,6#inet#cz_firewall#f6_tcp22," \
           "4#inet#cz_firewall#f4_tcp443,6#inet#cz_firewall#f6_tcp443" in lines
    assert "nftset=/github.com/4#inet#cz_firewall#f4_tcp443,6#inet#cz_firewall#f6_tcp443" in lines
    assert "ip daddr @f4_tcp443 tcp dport { 443 } accept" in nft
    assert "ip daddr @f4_udp123 udp dport { 123 } accept" in nft
    assert "ip daddr 10.20.0.0/16 tcp dport { 1433 } accept" in nft
    assert "tcp dport { 22, 443 } accept" in nft                   # inbound: SSH and HTTPS only
    assert "icmp type echo-request limit rate 20/second burst 50 packets accept" in nft      # and ping
    assert "icmpv6 type echo-request limit rate 20/second burst 50 packets accept" in nft
    assert "policy drop" in nft.split("chain input")[1].split("}")[0]
    def last(n):
        return [x.strip() for x in n.split("chain egress {")[1].splitlines() if x.strip() not in ("", "}")][-1]
    assert last(nft) == "drop"
    assert last(render(system, {**admin, "mode": "log"}, [])[0]) == "accept"


def test_upstream_servers(paths):
    paths.resolved.write_text("# from DHCP\nnameserver 192.168.1.1\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\n"
                              "nameserver 192.168.1.1\noptions edns0\n")
    assert sysagent.upstream_servers() == ["192.168.1.1", "fe80::1"]
    paths.appliance_env.write_text("CZ_DNS_SERVERS=9.9.9.9, 149.112.112.112 junk\n")
    assert sysagent.upstream_servers() == ["9.9.9.9", "149.112.112.112"]


def test_egress_status_parses_journal(paths):
    journal = "\n".join([
        "1 10.42.0.7/3301 query[A] api.github.com from 10.42.0.7",
        "1 10.42.0.7/3301 reply api.github.com is 140.82.112.5",
        "2 10.42.0.7/3302 query[A] api.nuget.org from 10.42.0.7",
        "3 172.17.0.2/4100 query[AAAA] api.nuget.org from 172.17.0.2",
        "3 172.17.0.2/4100 config error is REFUSED (EDE: not ready)",
        "2 10.42.0.7/3302 config error is REFUSED (EDE: not ready)",
        "4 10.42.0.7/3303 query[PTR] 7.0.42.10.in-addr.arpa from 10.42.0.7",
        "4 10.42.0.7/3303 config error is REFUSED",
        "5 127.0.0.1/999 query[A] registry.npmjs.org from 127.0.0.1",
        "5 127.0.0.1/999 config error is REFUSED",
        "cz-egress-drop: IN=cni0 OUT=eth0 SRC=10.42.0.7 DST=1.2.3.4 LEN=60 PROTO=TCP SPT=4000 DPT=8443 WINDOW=1",
    ])
    st = sysagent.egress_status(journal)
    assert st["denied_names"] == [{"name": "api.nuget.org", "count": 2}, {"name": "registry.npmjs.org", "count": 1}]
    assert st["dropped"] == [{"name": "1.2.3.4 tcp/8443", "count": 1}]
    assert [r["host"] for r in st["system_rules"]] == ["ghcr.io", "pkg-containers.githubusercontent.com"]


def test_save_rules_applies_and_records_history(paths, monkeypatch):
    r = fake_run(monkeypatch)
    sysagent.save_rules({"rules": [{"host": "api.nuget.org"}]}, "alice@x", "Alice")
    assert json.loads(paths.rules.read_text())["rules"] == [{"host": "api.nuget.org", "ports": ["tcp/443"], "note": ""}]
    assert ["nft", "-c", "-f", str(paths.nft)] in r.calls and ["nft", "-f", str(paths.nft)] in r.calls
    assert "nftset=/api.nuget.org/4#inet#cz_firewall#f4_tcp443,6#inet#cz_firewall#f6_tcp443" in paths.dnsmasq.read_text()
    h = json.loads(paths.history.read_text().splitlines()[-1])
    assert h["by"] == "alice@x" and h["added"][0]["host"] == "api.nuget.org" and h["removed"] == []


def test_save_rules_keeps_old_ruleset_when_nft_refuses(paths, monkeypatch):
    fake_run(monkeypatch)
    sysagent.save_rules({"rules": [{"host": "old.example"}]}, "a", "A")
    calls = {"n": 0}

    def flaky(cmd, timeout=0, check=True, input=None):
        if cmd[:2] == ["nft", "-c"]:
            calls["n"] += 1
            if calls["n"] == 1:
                raise sysagent.AgentError("syntax error")
        return ""
    monkeypatch.setattr(sysagent, "run", flaky)
    with pytest.raises(sysagent.AgentError):
        sysagent.save_rules({"rules": [{"host": "new.example"}]}, "a", "A")
    assert json.loads(paths.rules.read_text())["rules"][0]["host"] == "old.example"


def test_broken_admin_rules_fall_back_to_system_rules(paths):
    paths.rules.parent.mkdir(parents=True, exist_ok=True)
    paths.rules.write_text("{not json")
    nft, dns = render(sysagent.load_rules(paths.system_rules, system=True), sysagent.load_rules(paths.rules), ["10.0.0.1"])
    assert "server=/ghcr.io/10.0.0.1" in dns and "policy drop" in nft


# ------------------------------------------------------------------------------- upgrade, rollback

def test_snapshots_versions_from_snapshot_os_release(paths):
    s = sysagent.snapshots(STATE)
    assert [(x["id"], x["active"], x["version"]) for x in s] == [(2, True, "v1.1.0"), (1, False, "v1.0.0")]


def test_upgrade_verifies_signature_and_installs_by_digest(paths, monkeypatch):
    r = fake_run(monkeypatch)
    (paths.run / "requests" / "1-a.json").write_text(json.dumps({"action": "upgrade", "version": "v1.2.0",
                                                                 "requested_by": "alice@x"}))
    assert sysagent.process() == 0
    cosign = next(c for c in r.calls if c[0] == "cosign")
    assert cosign[-1] == "ghcr.io/olljanat-ai/containerizer-appliance:v1.2.0"
    ident = cosign[cosign.index("--certificate-identity-regexp") + 1]
    assert ident.startswith("^https://github\\.com/olljanat\\-ai/containerizer/\\.github/workflows/release\\.yml@refs/tags/v")
    assert cosign[cosign.index("--certificate-oidc-issuer") + 1] == "https://token.actions.githubusercontent.com"
    up = next(c for c in r.calls if c[:2] == ["elemental", "upgrade"])
    assert up[up.index("--system") + 1] == f"oci:ghcr.io/olljanat-ai/containerizer-appliance@{DIGEST}"
    assert ["systemctl", "reboot"] in r.calls
    assert not list((paths.run / "requests").glob("*.json"))
    task = json.loads((paths.run / "status.json").read_text())["task"]
    assert task["state"] == "rebooting" and task["requested_by"] == "alice@x"


@pytest.mark.parametrize("version", ["latest", "v1.2", "v1.2.0;reboot", "1.2.0", "v1.2.0-rc1"])
def test_upgrade_refuses_non_release_versions(paths, monkeypatch, version):
    r = fake_run(monkeypatch)
    (paths.run / "requests" / "1.json").write_text(json.dumps({"action": "upgrade", "version": version}))
    assert sysagent.process() == 1
    assert not [c for c in r.calls if c[0] in ("cosign", "elemental") and c[1] != "state" and c[1] != "version"]
    assert json.loads((paths.run / "status.json").read_text())["task"]["state"] == "failed"


def test_upgrade_stops_when_signature_does_not_verify(paths, monkeypatch):
    r = fake_run(monkeypatch, **{"cosign verify": sysagent.AgentError("no matching signatures")})
    (paths.run / "requests" / "1.json").write_text(json.dumps({"action": "upgrade", "version": "v9.9.9"}))
    assert sysagent.process() == 1
    assert not [c for c in r.calls if c[:2] == ["elemental", "upgrade"]]
    assert ["systemctl", "reboot"] not in r.calls


def test_upgrade_refuses_ambiguous_digests(paths, monkeypatch):
    two = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}},
                      {"critical": {"image": {"docker-manifest-digest": "sha256:" + "cd" * 32}}}])
    fake_run(monkeypatch, **{"cosign verify": two})
    with pytest.raises(sysagent.AgentError):
        sysagent.verify_signature("v1.2.0")


def test_rollback_installs_a_copy_of_an_earlier_snapshot(paths, monkeypatch):
    r = fake_run(monkeypatch)
    (paths.run / "requests" / "1.json").write_text(json.dumps({"action": "rollback", "snapshot": 1}))
    assert sysagent.process() == 0
    up = next(c for c in r.calls if c[:2] == ["elemental", "upgrade"])
    assert up[up.index("--system") + 1] == f"dir:{paths.snapshots / '1' / 'snapshot'}"
    assert "version=v1.0.0,rollback-of=1" in up


@pytest.mark.parametrize("sid", [2, 7, "1", True])
def test_rollback_refuses_active_unknown_or_malformed_snapshots(paths, monkeypatch, sid):
    r = fake_run(monkeypatch)
    (paths.run / "requests" / "1.json").write_text(json.dumps({"action": "rollback", "snapshot": sid}))
    assert sysagent.process() == 1
    assert not [c for c in r.calls if c[:2] == ["elemental", "upgrade"]]


# ------------------------------------------------------------------------------- admin pages

def shell(title, active, body, flash):
    return f"<title>{title}</title>[{active}]{flash}{body}"


@pytest.fixture
def page(tmp_path):
    d = tmp_path / "sys"
    (d / "requests").mkdir(parents=True)
    (d / "status.json").write_text(json.dumps({
        "version": "v1.1.0", "image": "ghcr.io/olljanat-ai/containerizer-appliance", "signer": "olljanat-ai/containerizer",
        "boot_mode": "active", "snapshots": [{"id": 2, "active": True, "version": "v1.1.0"},
                                             {"id": 1, "active": False, "version": "v1.0.0"}],
        "egress": {"mode": "enforce", "rules": [{"host": "api.nuget.org", "ports": ["tcp/443"], "note": ""}],
                   "system_rules": [{"host": "ghcr.io", "ports": ["tcp/443"]}],
                   "denied_names": [{"name": "registry.npmjs.org", "count": 3}], "dropped": [], "history": []}}))
    return appliance.SystemPage(status_dir=d, fetch_tags=lambda image: ["v1.0.0", "v1.1.0", "v1.2.0", "latest"])


ADMIN = SimpleNamespace(admin=True, user="alice@x", name="Alice", csrf="tok")
NOT_ADMIN = SimpleNamespace(admin=False, user="bob@x", name="Bob", csrf="tok")


def requests_in(page):
    return [json.loads(p.read_text()) for p in sorted((page.status_dir / "requests").glob("*.json"))]


def test_detect_only_on_the_appliance(tmp_path):
    assert appliance.SystemPage.detect({"CONTAINERIZER_SYSTEM_DIR": str(tmp_path)}) is None
    (tmp_path / "status.json").write_text("{}")
    assert appliance.SystemPage.detect({"CONTAINERIZER_SYSTEM_DIR": str(tmp_path)}) is not None


def test_system_page_admins_only(page):
    for kind in ("system", "firewall"):
        status, body, loc = page.handle(NOT_ADMIN, "GET", [kind], {}, {}, shell)
        assert status == 403 and "Only administrators" in body
        status, _, _ = page.handle(NOT_ADMIN, "POST", [kind, "upgrade"], {}, {"confirm": ["yes"], "version": ["v1.2.0"]}, shell)
        assert status == 403
    assert requests_in(page) == []


def test_system_page_shows_version_newer_release_and_snapshots(page):
    status, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert status == 200 and "v1.1.0" in body and "<option value='v1.2.0'>" in body
    assert "<option value='v1.0.0'>" not in body
    assert "<option value='1'>1: v1.0.0</option>" in body and "<option value='2'>" not in body


def test_upgrade_request_needs_confirmation_and_a_newer_release(page):
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.2.0"]}, shell)
    assert st == 303 and "confirm" in loc and requests_in(page) == []
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.0.0"], "confirm": ["yes"]}, shell)
    assert "not+a+newer+release" in loc and requests_in(page) == []
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.2.0"], "confirm": ["yes"]}, shell)
    assert st == 303 and requests_in(page)[0] | {"requested_at": None} == {
        "action": "plan", "then": "upgrade", "version": "v1.2.0", "at": None, "max_wait_minutes": 120,
        "requested_by": "alice@x", "requested_by_name": "Alice", "requested_at": None}
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.2.0"], "confirm": ["yes"]}, shell)
    assert "in+progress" in loc and len(requests_in(page)) == 1


def test_rollback_request_only_for_an_earlier_snapshot(page):
    for sid in ("2", "9", "1;x"):
        page.handle(ADMIN, "POST", ["system", "rollback"], {}, {"snapshot": [sid], "confirm": ["yes"]}, shell)
    assert requests_in(page) == []
    page.handle(ADMIN, "POST", ["system", "rollback"], {}, {"snapshot": ["1"], "confirm": ["yes"]}, shell)
    assert requests_in(page)[0] | {"requested_at": None} == {
        "action": "plan", "then": "rollback", "snapshot": 1, "at": None, "max_wait_minutes": 120,
        "requested_by": "alice@x", "requested_by_name": "Alice", "requested_at": None}


def test_firewall_page_and_changes(page):
    status, body, _ = page.handle(ADMIN, "GET", ["firewall"], {}, {}, shell)
    assert status == 200 and "api.nuget.org" in body and "registry.npmjs.org" in body and "ghcr.io" in body
    st, _, loc = page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["add"], "target": ["not a host"], "ports": ["443"]}, shell)
    assert "Not+saved" in loc and requests_in(page) == []
    page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["add"], "target": ["registry.npmjs.org"], "ports": ["443"],
                                                  "note": ["npm builds"]}, shell)
    req = requests_in(page)[0]
    assert req["action"] == "egress" and req["mode"] == "enforce"
    assert req["rules"][-1] == {"host": "registry.npmjs.org", "ports": ["tcp/443"], "note": "npm builds"}
    st, _, loc = page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["remove"], "rule": ["0"]}, shell)
    assert "still+being+applied" in loc                  # one change at a time


def test_firewall_log_mode_needs_confirmation(page):
    st, _, loc = page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["mode"], "mode": ["log"]}, shell)
    assert "confirm" in loc and requests_in(page) == []
    page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["mode"], "mode": ["log"], "confirm": ["yes"]}, shell)
    assert requests_in(page)[0]["mode"] == "log"


def test_firewall_remove_and_cidr(page):
    page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["add"], "target": ["10.20.0.0/16"], "ports": ["1433"]}, shell)
    assert requests_in(page)[0]["rules"][-1]["cidr"] == "10.20.0.0/16"
    for f in (page.status_dir / "requests").glob("*.json"):
        f.unlink()
    page.handle(ADMIN, "POST", ["firewall"], {}, {"do": ["remove"], "rule": ["0"]}, shell)
    assert requests_in(page)[0]["rules"] == []


def test_health(paths, monkeypatch):
    # k3s still starting: waited for until it is active
    seq = {"k3s.service": ["activating", "activating", "active"]}
    state = {}

    def r(cmd, timeout=0, check=True, input=None):
        if cmd[:2] == ["systemctl", "is-active"]:
            if seq.get(cmd[2]):
                return seq[cmd[2]].pop(0) + "\n"
            return state.get(cmd[2], "active") + "\n"
        return ""
    monkeypatch.setattr(sysagent, "run", r)
    monkeypatch.setattr(sysagent.time, "sleep", lambda s: None)
    assert sysagent.health() == 0
    assert seq["k3s.service"] == []
    # failed or not started: fails at once
    state["k3s.service"] = "failed"
    assert sysagent.health() == 1
    state["k3s.service"] = "inactive"
    assert sysagent.health() == 1
    # still starting after the wait
    state["k3s.service"] = "activating"
    monkeypatch.setattr(sysagent, "HEALTH_START_WAIT", 0)
    assert sysagent.health() == 1
    state.clear()
    assert sysagent.health() == 0

    def no_fw(cmd, timeout=0, check=True, input=None):
        if cmd[0] == "nft":
            raise sysagent.AgentError("No such file or directory")
        return "active\n"
    monkeypatch.setattr(sysagent, "run", no_fw)
    assert sysagent.health() == 1


def test_task_survives_the_restart(paths, monkeypatch):
    fake_run(monkeypatch)
    (paths.run / "requests" / "1.json").write_text(json.dumps({"action": "upgrade", "version": "v1.2.0"}))
    sysagent.process()
    (paths.run / "status.json").unlink()                     # /run is gone after the restart
    t = sysagent.publish()["task"]
    assert t["state"] == "done" and t["message"].endswith("; restarted") and "restarting" not in t["message"]
    assert sysagent.publish()["task"]["state"] == "done"


def test_task_failed_when_boot_fell_back(paths, monkeypatch):
    fake_run(monkeypatch)
    (paths.run / "requests" / "1.json").write_text(json.dumps({"action": "upgrade", "version": "v1.2.0"}))
    sysagent.process()
    (paths.elemental_run / "active_mode").unlink()
    (paths.elemental_run / "passive_mode").touch()
    t = sysagent.publish()["task"]
    assert t["state"] == "failed" and "previous snapshot" in t["message"]


# ---------------------------------------------------------------------------
# the image and its units: features that need something of the OS work out of the box

APPLIANCE = Path(__file__).resolve().parent.parent / "appliance"
UNITS = APPLIANCE / "rootfs" / "usr" / "lib" / "systemd" / "system"


def _unit(name: str) -> dict:
    out: dict = {}
    for line in (UNITS / name).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out.setdefault(k, []).append(v)
    return out


def test_dev_database_folder_is_shared_by_the_web_ui_and_the_worker():
    web, worker = _unit("containerizer-web.service"), _unit("containerizer-worker.service")
    d = "/var/lib/containerizer/devdb"
    assert f"CONTAINERIZER_DEV_DB_DIR={d}" in web["Environment"] and f"CONTAINERIZER_DEV_DB_DIR={d}" in worker["Environment"]
    assert d in web["ReadWritePaths"][0].split()        # the web UI's sandbox lets it write there, and nowhere else new
    assert worker["Group"] == ["containerizer"]           # reads the files through the folder's group
    firstboot = (APPLIANCE / "rootfs" / "usr" / "lib" / "containerizer" / "bin" / "cz-firstboot").read_text()
    assert f'install -d -m 2750 -o cz-web -g containerizer "$D/devdb"' in firstboot


def test_every_download_in_the_image_is_pinned():
    docker = (APPLIANCE / "Dockerfile").read_text()
    assert "oras" not in docker                           # no SBOM attachments: no ORAS
    assert docker.count("--checksum=sha256:") >= 4
    helm = docker[docker.index("https://get.helm.sh/helm-v"):]
    assert "--checksum=sha256:" in docker[:docker.index("https://get.helm.sh/helm-v")].rsplit("ADD", 1)[1]
    assert "/usr/bin/helm" in helm and "helm version" in helm
    assert "KUBECONFIG=/etc/rancher/k3s/k3s.yaml" in (APPLIANCE / "rootfs/etc/profile.d/kubeconfig.sh").read_text()


def test_root_password_default_is_expired_and_kept_and_ssh_takes_it():
    script = (APPLIANCE / "rootfs" / "usr" / "lib" / "containerizer" / "bin" / "cz-root-password").read_text()
    assert "echo 'root:containerizer' | chpasswd" in script and "chage -d 0 root" in script
    assert "F=/etc/containerizer/secrets/root-shadow" in script   # persistent partition: /etc itself is a tmpfs
    restore, path = _unit("containerizer-root-password.service"), _unit("containerizer-root-password.path")
    assert "ssh.service" in restore["Before"][0] and "systemd-user-sessions.service" in restore["Before"][0]
    assert "containerizer-firstboot.service" in restore["After"][0]           # secrets/ exists by then
    assert path["PathChanged"] == ["/etc/shadow"]
    docker = (APPLIANCE / "Dockerfile").read_text()
    assert "containerizer-root-password.service containerizer-root-password.path" in docker
    sshd = dict(line.split(None, 1) for line in (APPLIANCE / "rootfs" / "etc" / "ssh" / "sshd_config.d" /
                                                 "10-containerizer.conf").read_text().splitlines()
                if line.strip() and not line.startswith("#"))
    assert sshd["PermitRootLogin"] == "yes" and sshd["PasswordAuthentication"] == "yes"
    assert sshd["KbdInteractiveAuthentication"] == "yes" and sshd["UsePAM"] == "yes"
    assert "AuthenticationMethods" not in sshd


# ------------------------------------------------------------------------------- external results database

def test_sql_env_local_by_default(paths, tmp_path, monkeypatch):
    monkeypatch.setattr(sysagent.P, "sql_env", tmp_path / "run" / "sql.env")
    p = sysagent.P
    p.appliance_env.write_text("CZ_SQL_SERVER=\nCZ_SQL_DATABASE=Containerizer\n")
    out = sysagent.write_sql_env()
    assert out["CZ_SQL_LOCAL"] == "yes" and out["CZ_SQL_OWNER_SECRET"] == "mssql-sa"
    assert out["CZ_SQL_WEB_CS"] == "Server=127.0.0.1,1433;Database=Containerizer;TrustServerCertificate=yes;User Id=cz_web"
    assert "Database=master" in out["CZ_SQL_PROBE_CS"]
    assert 'CZ_SQL_SCANNER_CS="Server=127.0.0.1,1433;' in p.sql_env.read_text()
    assert [r["host"] for r in sysagent.system_rules()["rules"]] == ["ghcr.io", "pkg-containers.githubusercontent.com"]


def test_sql_env_external_server_and_its_firewall_rule(paths, tmp_path, monkeypatch):
    monkeypatch.setattr(sysagent.P, "sql_env", tmp_path / "run" / "sql.env")
    monkeypatch.setattr(sysagent.P, "sql_ca", tmp_path / "run" / "sql-ca.pem")
    p = sysagent.P
    (tmp_path / "ca.pem").write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    p.appliance_env.write_text(f'CZ_SQL_SERVER=SQL01.corp.example.com,14330\nCZ_SQL_DATABASE=Cz\nCZ_SQL_USER=cz_owner\n'
                               f'CZ_SQL_LOGINS=existing\nCZ_SQL_OPTIONS="Schema=cz2;Encrypt=yes"\nCZ_SQL_CA={tmp_path / "ca.pem"}\n')
    out = sysagent.write_sql_env()
    base = f"Server=tcp:sql01.corp.example.com,14330;Database=Cz;Schema=cz2;Encrypt=yes;CaFile={p.sql_ca}"
    assert out["CZ_SQL_LOCAL"] == "no" and out["CZ_SQL_LOGINS"] == "existing"
    assert out["CZ_SQL_OWNER_CS"] == out["CZ_SQL_PROBE_CS"] == base + ";User Id=cz_owner"
    assert out["CZ_SQL_ADMIN_CS"] == base + ";User Id=cz_admin" and out["CZ_SQL_OWNER_SECRET"] == "sql-owner"
    assert "BEGIN CERTIFICATE" in p.sql_ca.read_text()
    from containerizer.sqlstore import connect_args
    a = connect_args(out["CZ_SQL_WEB_CS"], password="x")
    assert (a["server"], a["port"], a["database"], a["user"], a["_ca"], a["_schema"]) == \
        ("sql01.corp.example.com", "14330", "Cz", "cz_web", str(p.sql_ca), "cz2")
    rule = sysagent.system_rules()["rules"][-1]
    assert rule["host"] == "sql01.corp.example.com" and rule["ports"] == ["tcp/14330"]
    nft, dns = render(sysagent.system_rules(), {"mode": "enforce", "rules": []}, upstreams=["10.0.0.2"])
    assert "server=/sql01.corp.example.com/10.0.0.2" in dns and "tcp dport { 14330 }" in nft

    p.appliance_env.write_text("CZ_SQL_SERVER=10.20.30.40\nCZ_SQL_USER=cz_owner\n")
    assert sysagent.sql_settings(sysagent.read_env(p.appliance_env))["CZ_SQL_WEB_CS"] == \
        "Server=tcp:10.20.30.40,1433;Database=Containerizer;User Id=cz_web"
    assert sysagent.system_rules()["rules"][-1] == {"cidr": "10.20.30.40/32", "ports": ["tcp/1433"],
                                                     "note": "results database (CZ_SQL_SERVER in appliance.env)"}


@pytest.mark.parametrize("env, msg", [
    ({"CZ_SQL_SERVER": "sql01.example.com"}, "CZ_SQL_USER"),
    ({"CZ_SQL_SERVER": "sql01\\inst", "CZ_SQL_USER": "o"}, "named instances"),
    ({"CZ_SQL_SERVER": "sql01.example.com,99999", "CZ_SQL_USER": "o"}, "port"),
    ({"CZ_SQL_SERVER": "sql01.example.com", "CZ_SQL_USER": "o", "CZ_SQL_DATABASE": "a;b"}, "CZ_SQL_DATABASE"),
    ({"CZ_SQL_SERVER": "sql01.example.com", "CZ_SQL_USER": "o", "CZ_SQL_LOGINS": "maybe"}, "CZ_SQL_LOGINS"),
    ({"CZ_SQL_SERVER": "sql01.example.com", "CZ_SQL_USER": "o", "CZ_SQL_OPTIONS": "Password=x"}, "must not set"),
    ({"CZ_SQL_SERVER": "sql01.example.com", "CZ_SQL_USER": "o", "CZ_SQL_OPTIONS": "App=$(id)"}, "quotes"),
])
def test_sql_env_rejects_bad_settings(paths, env, msg):
    with pytest.raises(RuleError, match=msg.replace("(", r"\(")):
        sysagent.sql_settings(env)


def test_bad_database_setting_does_not_break_the_firewall(paths):
    sysagent.P.appliance_env.write_text("CZ_SQL_SERVER=not a host\nCZ_SQL_USER=o\n")
    assert len(sysagent.system_rules()["rules"]) == 2


def test_local_sql_server_only_without_an_external_one():
    unit = (APPLIANCE / "rootfs/usr/lib/systemd/system/containerizer-mssql.service").read_text()
    assert "ConditionPathExists=!/run/containerizer/sql-external" in unit
    for svc in ("web", "worker"):
        u = (APPLIANCE / f"rootfs/usr/lib/systemd/system/containerizer-{svc}.service").read_text()
        assert "EnvironmentFile=/run/containerizer/sql.env" in u and "127.0.0.1,1433" not in u
    firstboot = (APPLIANCE / "rootfs/usr/lib/containerizer/bin/cz-firstboot").read_text()
    assert "touch /run/containerizer/sql-external" in firstboot and "sysagent sql-env" in firstboot
    defaults = sysagent.read_env(APPLIANCE / "rootfs/usr/lib/containerizer/defaults/appliance.env")
    assert sysagent.sql_settings(defaults)["CZ_SQL_LOCAL"] == "yes"


def test_llm_answer_cache_is_on_the_persistent_partition():
    # the default cache, next to the code, is the read-only OS image on the appliance
    worker = _unit("containerizer-worker.service")
    assert "CONTAINERIZER_AI_CACHE=/var/lib/containerizer/worker/ai-cache" in worker["Environment"]
    assert worker["WorkingDirectory"] == ["/var/lib/containerizer/worker"]


def test_llm_queue_runner_unit():
    """The LLM queue runner runs like the scan worker (same user, settings, database login, credential key)
    and writes its answers into the worker's answer cache, so the next scan finds them."""
    q, w = _unit("containerizer-llm-queue.service"), _unit("containerizer-worker.service")
    assert q["User"] == w["User"] == ["containerizer"]
    for f in ("/etc/containerizer/worker.env", "-/run/containerizer/llm.env", "/run/containerizer/sql.env"):
        assert f in q["EnvironmentFile"] and f in w["EnvironmentFile"]
    cache = "CONTAINERIZER_AI_CACHE=/var/lib/containerizer/worker/ai-cache"
    assert cache in q["Environment"] and cache in w["Environment"]
    assert set(q["LoadCredential"]) == {"sql-scanner:/etc/containerizer/secrets/cz-scanner",
                                        "credential-key:/etc/containerizer/secrets/credential-key"}
    assert q["ExecStart"] == ["/usr/lib/containerizer/bin/cz-llm-queue"]
    # refactoring patches: Docker to build and run them (as the scan worker), the worker's clones read only,
    # writes only to the answer cache and the refactoring scratch space
    # through the Docker socket guard, not in the root-equivalent docker group (docs/appliance.md)
    guard = "DOCKER_HOST=unix:///run/containerizer/docker-guard.sock"
    assert "SupplementaryGroups" not in q and "SupplementaryGroups" not in w
    assert guard in q["Environment"] and guard in w["Environment"]
    assert "containerizer-docker-guard.socket" in q["Wants"][0].split()
    assert "docker.service" in q["Wants"][0].split() and "docker.service" in q["After"][0].split()
    # "Make it A" variants: images to the appliance's registry, the lab services, read-only cluster access
    assert "containerizer-registry.service" in q["Wants"][0].split()
    assert "CONTAINERIZER_LAB_SERVICES=/var/lib/containerizer/system/lab-services.json" in q["Environment"]
    assert "CONTAINERIZER_SANDBOX_KUBECONFIG=/run/containerizer/sandbox-verifier.kubeconfig" in q["Environment"]
    assert q["ProtectSystem"] == ["strict"]
    assert q["ReadWritePaths"] == ["/var/lib/containerizer/worker/ai-cache /var/lib/containerizer/refactor"]
    for env in ("CONTAINERIZER_REFACTOR_SOURCES=/var/lib/containerizer/worker",
                "CONTAINERIZER_REFACTOR_WORK=/var/lib/containerizer/refactor",
                "CONTAINERIZER_WORK=/var/lib/containerizer/refactor/work",
                "DOCKER_CONFIG=/var/lib/containerizer/refactor/.docker"):
        assert env in q["Environment"]
    assert q["NoNewPrivileges"] == ["yes"] and q["WantedBy"] == ["multi-user.target"]
    script = (APPLIANCE / "rootfs/usr/lib/containerizer/bin/cz-llm-queue").read_text()
    assert "-m containerizer llm-queue --metrics-host 127.0.0.1 --metrics-port 9465" in script
    assert 'CONTAINERIZER_CREDENTIAL_KEY_FILE="$CREDENTIALS_DIRECTORY/credential-key"' in script
    firstboot = (APPLIANCE / "rootfs/usr/lib/containerizer/bin/cz-firstboot").read_text()
    assert 'install -d -m 0700 -o containerizer -g containerizer "$D/worker/ai-cache"' in firstboot
    assert 'install -d -m 0700 -o containerizer -g containerizer "$D/refactor"' in firstboot
    docker = (APPLIANCE / "Dockerfile").read_text()
    assert "containerizer-llm-queue.service" in docker.split("systemctl enable", 1)[1].split("\n\n", 1)[0]
    prom = (APPLIANCE / "rootfs/usr/lib/containerizer/prometheus/prometheus.yml").read_text()
    assert '"127.0.0.1:9465"' in prom and "job_name: containerizer-llm-queue" in prom


def test_sandbox_writes_the_read_only_verifier_kubeconfig_for_the_llm_queue():
    """cz-sandbox (root, every 2 minutes) grants the verifier ServiceAccount its read-only Role in each generated
    namespace (sandbox.verify_rbac: no Secrets, nothing cluster-wide, Flux only) and writes a kubeconfig
    with a 24-hour token of it, readable by the containerizer group only, where the LLM queue unit reads it."""
    script = (APPLIANCE / "rootfs/usr/lib/containerizer/bin/cz-sandbox").read_text()
    q = _unit("containerizer-llm-queue.service")
    path = next(e.split("=", 1)[1] for e in q["Environment"] if e.startswith("CONTAINERIZER_SANDBOX_KUBECONFIG="))
    assert f"VERIFIER_KUBECONFIG={path}" in script and path.startswith("/run/containerizer/")
    # the scan worker reads it too: its sandbox check at the end of a scan fills the results pages' Sandbox cluster
    w = _unit("containerizer-worker.service")
    assert f"CONTAINERIZER_SANDBOX_KUBECONFIG={path}" in w["Environment"] and w["Group"] == ["containerizer"]
    assert "verify_rbac(sys.argv[1:])" in script
    assert "-l app.kubernetes.io/managed-by=containerizer" in script
    assert "create token containerizer-verifier --duration=24h" in script
    assert 'chown root:containerizer "$tmp" && chmod 0640 "$tmp"' in script
    # before the steps that need the secret store or the output repository: it works without them
    assert script.index("verifier_access ||") < script.index("if ! cz_store_ready; then")
    from containerizer.sandbox import VERIFIER, VERIFIER_NS
    assert (VERIFIER, VERIFIER_NS) == ("containerizer-verifier", "containerizer-verify")


def test_reboot_does_not_wait_for_a_scan_and_the_screen_shows_why():
    """A reboot during a scan waited up to 2 hours for the worker, behind a black screen: systemd's status went to
    the serial console (the last console=)."""
    unit = (APPLIANCE / "rootfs/usr/lib/systemd/system/containerizer-worker.service").read_text()
    assert re.search(r"^TimeoutStopSec=2min$", unit, re.M)
    args = (APPLIANCE / "elemental/bootargs.cfg").read_text()
    cmds = re.findall(r'set kernelcmd="([^"]*)"', args)
    assert len(cmds) == 2 and all(re.findall(r"console=(\S+)", c)[-1] == "tty1" for c in cmds)


def test_k3s_and_flux_metrics_and_dashboards():
    """Grafana's k3s and Flux dashboards: Prometheus reads the cluster as a read-only ServiceAccount over verified TLS,
    keeps every metric the dashboards use, and kube-state-metrics (pinned by digest) reports Flux's objects."""
    import yaml
    root = APPLIANCE.parent
    docs = list(yaml.safe_load_all((APPLIANCE / "rootfs/var/lib/rancher/k3s/server/manifests/"
                                                 "containerizer-monitoring.yaml").read_text()))
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    ns = by[("Namespace", "cz-monitoring")]
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    image = by[("Deployment", "kube-state-metrics")]["spec"]["template"]["spec"]["containers"][0]["image"]
    assert re.fullmatch(r"docker\.io/rancher/mirrored-kube-state-metrics-kube-state-metrics:v[\d.]+@sha256:[0-9a-f]{64}", image)
    for role in ("cz-prometheus", "cz-kube-state-metrics"):
        verbs = {v for r in by[("ClusterRole", role)]["rules"] for v in r["verbs"]}
        assert verbs <= {"get", "list", "watch"}, role                 # read-only
    flux = yaml.safe_load(by[("ConfigMap", "kube-state-metrics-flux")]["data"]["flux.yaml"])
    kinds = {r["groupVersionKind"]["kind"] for r in flux["spec"]["resources"]}
    assert {"Kustomization", "GitRepository", "HelmRelease", "OCIRepository"} <= kinds
    assert by[("Secret", "cz-prometheus-token")]["type"] == "kubernetes.io/service-account-token"

    prom = yaml.safe_load((APPLIANCE / "rootfs/usr/lib/containerizer/prometheus/prometheus.yml").read_text())
    jobs = {j["job_name"]: j for j in prom["scrape_configs"]}
    keep = set()
    for name in ("k3s-apiserver", "kubelet", "kubelet-cadvisor"):
        j = jobs[name]
        assert j["tls_config"] == {"ca_file": "/etc/prometheus-k8s/ca.crt"}          # verified, never insecure
        assert j["authorization"] == {"credentials_file": "/etc/prometheus-k8s/token"}
        keep |= {re.compile(r["regex"]) for r in j["metric_relabel_configs"] if r.get("action") == "keep"}
    sd = jobs["kubernetes-pods"]["kubernetes_sd_configs"][0]
    assert sd["tls_config"]["ca_file"] == "/etc/prometheus-k8s/ca.crt" and "insecure_skip_verify" not in str(prom)
    unit = (APPLIANCE / "rootfs/usr/lib/systemd/system/containerizer-prometheus.service").read_text()
    assert "/run/containerizer/prometheus-k8s:/etc/prometheus-k8s:ro" in unit
    assert "containerizer-prometheus-k8s.service" in (APPLIANCE / "Dockerfile").read_text()

    uids = set()
    for f in ("containerizer-scans.json", "containerizer-k3s.json", "containerizer-flux.json"):
        d = json.loads((root / "monitoring/grafana" / f).read_text())
        assert d["uid"] not in uids
        uids.add(d["uid"])
        ids = [p["id"] for p in d["panels"]]
        assert len(ids) == len(set(ids)), f
        cells = set()
        for p in d["panels"]:
            g = p["gridPos"]
            mine = {(x, y) for x in range(g["x"], g["x"] + g["w"]) for y in range(g["y"], g["y"] + g["h"])}
            assert not mine & cells and g["x"] + g["w"] <= 24, (f, p["title"])
            cells |= mine
        if f == "containerizer-scans.json":
            continue
        for p in d["panels"]:
            for t in p.get("targets") or []:
                for m in re.findall(r"\b([a-z_:]+)\s*(?=\{|\[|\))", t["expr"]):
                    if m in ("sum", "by", "count", "max", "rate", "increase", "topk", "or", "vector", "histogram_quantile",
                             "le", "verb", "code", "namespace", "pod", "phase", "reason", "deployment", "controller",
                             "result", "name", "persistentvolumeclaim", "container"):
                        continue
                    ok = m in ("up", "time") or m.startswith(("kube_", "gotk_", "controller_runtime_", "workqueue_",
                                                              "containerizer_sandbox_")) or \
                        any(k.fullmatch(m) for k in keep)
                    assert ok, (f, p["title"], m)


def test_scratch_space_is_never_the_read_only_code(monkeypatch, tmp_path):
    """A scan with the security gate or Build and run on failed on the appliance with "Read-only file system:
    /usr/lib/containerizer/app/.work": the scratch space defaulted to the folder next to the code."""
    from containerizer import paths
    for unit in ("containerizer-worker.service", "containerizer-llm-queue.service"):
        text = (APPLIANCE / "rootfs/usr/lib/systemd/system" / unit).read_text()
        work = re.findall(r"^Environment=CONTAINERIZER_WORK=(\S+)$", text, re.M)
        assert len(work) == 1 and work[0].startswith("/var/lib/containerizer/"), unit
    assert paths.work_dir({"CONTAINERIZER_WORK": "/srv/w"}) == Path("/srv/w")
    monkeypatch.setattr(paths.os, "access", lambda p, mode: False)        # an installed, read-only package
    assert paths.work_dir({"XDG_CACHE_HOME": str(tmp_path)}) == tmp_path / "containerizer" / "work"
    monkeypatch.setattr(paths.os, "access", lambda p, mode: True)         # a checkout
    assert paths.work_dir({}) == Path(paths.__file__).resolve().parent.parent / ".work"


def test_sandbox_monitoring_images_come_from_allowed_registries():
    """Every image of the k3s monitoring manifest is pulled from a registry on the egress allow-list (registry.k8s.io
    is not: it redirects to regional hosts), pinned by digest."""
    import yaml
    allowed = {r["host"] for r in json.loads((APPLIANCE / "rootfs/usr/lib/containerizer/egress-system.json").read_text())["rules"]
               if r.get("host")}
    text = (APPLIANCE / "rootfs/var/lib/rancher/k3s/server/manifests/containerizer-monitoring.yaml").read_text()
    images = re.findall(r"^\s*image:\s*([a-z0-9.-]+\.[a-z]+/\S+)", text, re.M)
    assert images
    for img in images:
        host = img.split("/")[0]
        assert {"docker.io": "registry-1.docker.io"}.get(host, host) in allowed and "@sha256:" in img, img

# ------------------------------------------------------------------------------- planned restart

from datetime import datetime, timedelta, timezone  # noqa: E402

from containerizer import restartplan  # noqa: E402

T0 = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


def plan_request(paths, **kw):
    body = {"action": "plan", "then": "reboot", "requested_by": "alice@x", "requested_by_name": "Alice", **kw}
    (paths.run / "requests" / f"{len(list((paths.run / 'requests').glob('*')))}.json").write_text(json.dumps(body))
    return sysagent.process()


def test_a_planned_restart_is_kept_and_published(paths, monkeypatch):
    r = fake_run(monkeypatch)
    at = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat(timespec="seconds")
    assert plan_request(paths, at=at, max_wait_minutes=60) == 0
    plan = json.loads(paths.plan.read_text())
    assert plan["action"] == "reboot" and plan["at"] == at and plan["max_wait_minutes"] == 60
    assert json.loads((paths.run / "status.json").read_text())["restart"] == plan
    assert ["systemctl", "start", "--no-block", "containerizer-restart.service"] in r.calls
    assert ["systemctl", "reboot"] not in r.calls
    # one plan at a time; cancelling removes it
    assert plan_request(paths, then="upgrade", version="v1.2.0") == 1
    assert json.loads(paths.plan.read_text())["action"] == "reboot"
    (paths.run / "requests" / "c.json").write_text(json.dumps({"action": "plan-cancel", "requested_by": "bob@x"}))
    assert sysagent.process() == 0
    assert not paths.plan.exists() and json.loads((paths.run / "status.json").read_text())["restart"] is None


@pytest.mark.parametrize("bad", [{"then": "shutdown"}, {"then": "upgrade", "version": "latest"},
                                 {"then": "rollback", "snapshot": 2}, {"then": "rollback", "snapshot": "1"},
                                 {"at": "2099-01-01T00:00:00+00:00"}, {"at": "tomorrow"},
                                 {"max_wait_minutes": -1}, {"max_wait_minutes": "60"}, {"max_wait_minutes": True}])
def test_a_plan_is_checked_again_by_the_agent(paths, monkeypatch, bad):
    fake_run(monkeypatch)
    assert plan_request(paths, **bad) == 1
    assert not paths.plan.exists()


def test_the_restart_waits_for_the_work_in_progress(paths, monkeypatch):
    r = fake_run(monkeypatch)
    plan_request(paths, at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), max_wait_minutes=60)
    at = restartplan.starts(json.loads(paths.plan.read_text()))
    running = {"n": 2}
    monkeypatch.setattr(sysagent, "running_work", lambda llm=True: running["n"])
    assert sysagent.restart_check(at - timedelta(minutes=1)) == "scheduled"
    assert sysagent.restart_check(at + timedelta(minutes=1)) == "waiting for the work in progress"
    published = json.loads((paths.run / "status.json").read_text())["restart"]
    assert published["running"] == 2 and published["holding_since"]
    assert ["systemctl", "reboot"] not in r.calls
    # the worker and the LLM runner see it as due from `at` on
    assert restartplan.holding(at - timedelta(seconds=1), paths.run / "status.json") is None
    assert "no new work starts" in restartplan.holding(at, paths.run / "status.json")
    running["n"] = 0
    assert sysagent.restart_check(at + timedelta(minutes=2)) == "done"
    assert ["systemctl", "reboot"] in r.calls and not paths.plan.exists()
    task = json.loads((paths.run / "status.json").read_text())["task"]
    assert task["action"] == "reboot" and task["state"] == "rebooting" and task["requested_by"] == "alice@x"
    assert sysagent.restart_check(at + timedelta(minutes=3)) == "nothing planned"   # never repeated


def test_a_planned_upgrade_runs_when_the_wait_is_over(paths, monkeypatch):
    r = fake_run(monkeypatch)
    plan_request(paths, then="upgrade", version="v1.2.0", max_wait_minutes=30)
    at = restartplan.starts(json.loads(paths.plan.read_text()))
    monkeypatch.setattr(sysagent, "running_work", lambda llm=True: None)          # the database is away: counted as busy
    assert sysagent.restart_check(at + timedelta(minutes=29)) == "waiting for the work in progress"
    assert not [c for c in r.calls if c[:2] == ["elemental", "upgrade"]]
    assert sysagent.restart_check(at + timedelta(minutes=31)) == "done"
    assert [c for c in r.calls if c[:2] == ["elemental", "upgrade"]] and ["systemctl", "reboot"] in r.calls
    task = json.loads((paths.run / "status.json").read_text())["task"]
    assert task["action"] == "upgrade" and task["version"] == "v1.2.0" and "unknown work cut off" in task["planned"]


def test_until_the_work_is_done_never_cuts_it_off():
    plan = {"action": "reboot", "at": T0.isoformat(), "max_wait_minutes": None}
    assert restartplan.due(plan, T0 + timedelta(days=3), 1) == (False, "waiting for the work in progress")
    assert restartplan.due(plan, T0 + timedelta(days=3), 0)[0]
    assert restartplan.due({**plan, "max_wait_minutes": 0}, T0, 5)[0]


def test_the_system_page_plans_and_cancels_a_restart(page):
    status, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "action='/admin/system/restart'" in body and "Planned restart" not in body
    st, _, loc = page.handle(ADMIN, "POST", ["system", "restart"], {}, {"when": ["at"], "at": ["soon"],
                                                                         "confirm": ["yes"]}, shell)
    assert "time+of+the+restart" in loc and requests_in(page) == []
    later = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
    st, _, loc = page.handle(ADMIN, "POST", ["system", "restart"], {}, {"when": ["at"], "at": [later], "wait": ["done"],
                                                                         "confirm": ["yes"]}, shell)
    req = requests_in(page)[0]
    assert req["action"] == "plan" and req["then"] == "reboot" and req["max_wait_minutes"] is None
    assert req["at"].startswith(later) and req["at"].endswith("+00:00")
    assert "until+the+work+in+progress+is+done" in loc
    # the agent published it: the page shows it, refuses a second one and cancels it
    for f in (page.status_dir / "requests").glob("*.json"):
        f.unlink()
    st = json.loads((page.status_dir / "status.json").read_text())
    st["restart"] = {"action": "upgrade", "version": "v1.2.0", "at": req["at"], "max_wait_minutes": None,
                     "requested_by": "alice@x", "requested_by_name": "Alice"}
    (page.status_dir / "status.json").write_text(json.dumps(st))
    status, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "Planned restart" in body and "Upgrade to v1.2.0" in body and "Scheduled for" in body
    st_, _, loc = page.handle(ADMIN, "POST", ["system", "restart"], {}, {"confirm": ["yes"]}, shell)
    assert "already+planned" in loc and requests_in(page) == []
    page.handle(ADMIN, "POST", ["system", "cancel-restart"], {}, {}, shell)
    assert requests_in(page)[0]["action"] == "plan-cancel"


def test_new_work_waits_while_a_restart_is_due():
    from containerizer import llmqueue
    assert llmqueue.gate({}, T0, 0, 0.0, "waiting for the planned restart") == (False, "waiting for the planned restart")
    assert llmqueue.gate({"OnlyWhenIdle": False}, T0, 0, 0.0, None)[0]


def test_sandbox_says_why_nothing_deploys():
    """An appliance whose sandbox.env was never filled in deployed nothing, and cz-sandbox exited without a word.
    It now writes its state (no secret in it) for the worker's metrics and logs each change; the Flux dashboard and
    an alert show it."""
    script = (APPLIANCE / "rootfs/usr/lib/containerizer/bin/cz-sandbox").read_text()
    from containerizer.metrics import SANDBOX_STATES, SANDBOX_STATUS
    assert f"STATUS={SANDBOX_STATUS}" in script
    for state in SANDBOX_STATES:
        assert f"sandbox_status {state} " in script, state
    # every early exit after sandbox.env says why
    tail = script.split(". /etc/containerizer/sandbox.env", 1)[1].split("git_token() {", 1)[0]
    lines = tail.splitlines()
    exits = [i for i, l in enumerate(lines) if re.search(r"\bexit [01]\b", l)]
    assert len(exits) == 4 and all("sandbox_status" in lines[i] + lines[i - 1] for i in exits)
    assert "CZ_SANDBOX_GIT_TOKEN:-}" in script and "chmod 0644" in script
    alerts = (APPLIANCE.parent / "monitoring/prometheus/containerizer-alerts.yml").read_text()
    assert "ContainerizerSandboxNotConnected" in alerts and "ContainerizerSandboxRootSyncNotReady" in alerts
    flux = json.loads((APPLIANCE.parent / "monitoring/grafana/containerizer-flux.json").read_text())
    exprs = " ".join(t["expr"] for p in flux["panels"] for t in p.get("targets") or [])
    assert "containerizer_sandbox_connection" in exprs and 'name="containerizer-sandbox"' in exprs


def test_every_wired_nic_joins_one_active_backup_bond_with_the_bridge_on_it():
    """As olljanat/nomad-qemu-node's 05_network.yaml (netplan): every e* NIC in bond0, bond0 the port of br0, which
    has the address. Not a management controller's USB NIC (iDRAC: the bond chose it, 0.13.0 on a Dell server)."""
    net = Path(__file__).resolve().parent.parent / "appliance/rootfs/etc/systemd/network"
    nic = (net / "20-uplink.network").read_text()
    assert "Name=e*" in nic and "Bond=bond0" in nic and "LinkLocalAddressing=no" in nic and "\nDHCP=" not in nic
    assert "Driver=!cdc_ether rndis_host cdc_ncm cdc_eem" in nic
    assert "RequiredForOnline=no" in nic                    # a port without a cable does not hold up the boot
    bond = (net / "21-uplink-bond0.netdev").read_text()
    for line in ("Kind=bond", "Mode=active-backup", "MIIMonitorSec=100ms", "MinLinks=1",
                 "MACAddress=none"):                        # the first NIC's MAC: hypervisors drop a made-up one
        assert line in bond, line
    port = (net / "21-uplink-bond0.network").read_text()
    assert "Name=bond0" in port and "Bridge=br0" in port and "\nDHCP=" not in port
    br = (net / "22-uplink-br0.netdev").read_text()
    for line in ("Kind=bridge", "STP=no", "ForwardDelaySec=0", "VLANFiltering=yes", "DefaultPVID=1", "MACAddress=none"):
        assert line in br, line
    addr = (net / "22-uplink-br0.network").read_text()
    assert "Name=br0" in addr and "DHCP=ipv4" in addr


def test_dhcp_identity_survives_the_recovery_system_and_the_banner_shows_the_bridge():
    """The recovery system that installs the appliance and the installed system have different machine-ids: a
    DUID client ID gave the installed system a second DHCP address (the boot test could not reach it). The client
    ID is the bridge's MAC, its port's, the first NIC's (neither the bond nor the bridge gets a machine-id MAC); the
    console banner names br0, not the first interface (the DNS filter's dummy)."""
    root = Path(__file__).resolve().parent.parent
    net = (root / "appliance/rootfs/etc/systemd/network/22-uplink-br0.network").read_text()
    assert "\n[DHCPv4]\nClientIdentifier=mac\n" in net and "UseHostname=no" in net
    for name, orig in (("21-uplink-bond0.link", "bond0"), ("22-uplink-br0.link", "br0")):
        link = (root / f"appliance/rootfs/etc/systemd/network/{name}").read_text()
        assert f"OriginalName={orig}" in link and "MACAddressPolicy=none" in link   # not a machine-id MAC (99-default.link)
    for f in ("appliance/rootfs/etc/issue", "appliance/oem/03_branding.yaml"):
        text = (root / f).read_text()
        assert "\\4{br0}" in text and "https://\\4/" not in text, f


def test_system_page_says_the_llm_runner_finishes_its_jobs(page):
    st = json.loads((page.status_dir / "status.json").read_text())
    st["llm_drain"] = {"pid": 7, "since": "2026-11-05T10:00:00+00:00", "version": "v1.1.3",
                       "until": "2026-11-05T12:00:00+00:00"}
    (page.status_dir / "status.json").write_text(json.dumps(st))
    _, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "The LLM queue runner lets the LLM finish the answer it is working on, then restarts with " \
           "v1.1.3: at the latest at" in body and "go back to the queue" in body
    st["llm_drain"]["until"] = None
    (page.status_dir / "status.json").write_text(json.dumps(st))
    assert "restarts with v1.1.3: when it is answered" in page.handle(ADMIN, "GET", ["system"], {}, {}, shell)[1]



# ------------------------------------------------------------------------------- network: a static address

def test_static_address_is_checked():
    from containerizer.netconfig import NetworkError, render, validate
    cfg = validate("static", "192.0.2.10/24", "192.0.2.1", "192.0.2.53, 192.0.2.54")
    assert cfg == {"mode": "static", "address": "192.0.2.10/24", "gateway": "192.0.2.1",
                   "dns": ["192.0.2.53", "192.0.2.54"]}
    text = render(cfg)
    assert "[Match]\nName=br0" in text and "Address=192.0.2.10/24\nGateway=192.0.2.1\nDNS=192.0.2.53\nDNS=192.0.2.54" in text
    assert validate("static", "2001:db8::10/64", "fe80::1", ["2001:db8::53"])["gateway"] == "fe80::1"
    assert validate("DHCP") == {"mode": "dhcp"}
    for bad, why in ((("192.0.2.10", "192.0.2.1", "1.1.1.1"), "prefix length"),
                     (("192.0.2.0/24", "192.0.2.1", "1.1.1.1"), "network address"),
                     (("192.0.2.255/24", "192.0.2.1", "1.1.1.1"), "broadcast address"),
                     (("192.0.2.10/24", "198.51.100.1", "1.1.1.1"), "not in 192.0.2.0/24"),
                     (("192.0.2.10/24", "192.0.2.10", "1.1.1.1"), "own address"),
                     (("192.0.2.10/24", "2001:db8::1", "1.1.1.1"), "IP version"),
                     (("192.0.2.10/24", "192.0.2.1", ""), "at least one DNS"),
                     (("192.0.2.10/24", "192.0.2.1", "dns.example"), "DNS server"),
                     (("127.0.0.2/8", "127.0.0.1", "1.1.1.1"), "cannot be"),
                     (("192.0.2.10/24", "192.0.2.1", "1.1.1.1 1.0.0.1 8.8.8.8 9.9.9.9"), "at most 3")):
        with pytest.raises(NetworkError, match=why):
            validate("static", *bad[:2], bad[2])


def test_network_command_sets_a_static_address_and_back_to_dhcp(paths, monkeypatch, capsys):
    """On the console or over SSH (`cz network static ...`): writes the file where it is kept (and copied from at
    every boot by cz-firstboot) and where systemd-networkd reads it, configures br0 again at once and rebuilds the
    DNS filter with the new DNS servers."""
    monkeypatch.setattr(sysagent, "DNS_WAIT", 0)
    rebuilt = []
    monkeypatch.setattr(sysagent, "apply_firewall", lambda reload_dns=True: rebuilt.append(1))
    addr = json.dumps([{"ifname": "br0", "addr_info": [
        {"family": "inet", "local": "192.0.2.10", "prefixlen": 24, "scope": "global"},
        {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}])
    r = fake_run(monkeypatch, **{"ip -j addr": addr, "ip -j -4 route": json.dumps([{"dst": "default", "gateway": "192.0.2.1"}]),
                                 "ip -j -6 route": "[]", "resolvectl dns": "Link 3 (br0): 192.0.2.53\n"})
    assert sysagent.main(["network", "static", "192.0.2.10/24", "192.0.2.1", "192.0.2.53"]) == 0
    for d in (paths.network, paths.network_run):
        assert "Address=192.0.2.10/24" in (d / "10-static.network").read_text()
    assert ["networkctl", "reload"] in r.calls and ["networkctl", "reconfigure", "br0"] in r.calls
    assert ["systemctl", "restart", "--no-block", "containerizer-addresses.service"] in r.calls and rebuilt
    assert ["ip", "-j", "addr", "show", "dev", "br0"] in r.calls
    out = capsys.readouterr().out
    assert "mode:      static" in out and "addresses: 192.0.2.10/24" in out and "DNS:       192.0.2.53" in out
    st = sysagent.network_state()
    assert st["configured"]["gateway"] == "192.0.2.1" and st["gateways"] == ["192.0.2.1"]
    # a wrong one changes nothing
    n = len(r.calls)
    assert sysagent.main(["network", "static", "192.0.2.10/24", "198.51.100.1", "192.0.2.53"]) == 1
    assert len(r.calls) == n and "Address=192.0.2.10/24" in (paths.network / "10-static.network").read_text()
    assert sysagent.main(["network", "dhcp"]) == 0
    assert not (paths.network / "10-static.network").exists() and not (paths.network_run / "10-static.network").exists()
    assert "mode:      dhcp (the default)" in capsys.readouterr().out
    assert sysagent.main(["network", "static", "192.0.2.10/24"]) == 2          # the usage


def test_a_static_address_survives_a_restart(paths, monkeypatch):
    """0.13.0 on a Dell server: after a restart bond0 used DHCP: cz-firstboot copies the static file with `cp` under
    umask 077 (0600), and systemd-networkd (user systemd-network) cannot read it. restart-check (every minute) and
    status make the copy readable and configure bond0 again; nothing when it is fine."""
    import os
    r = fake_run(monkeypatch)
    monkeypatch.setattr(sysagent, "DNS_WAIT", 0)
    monkeypatch.setattr(sysagent, "apply_firewall", lambda reload_dns=True: None)
    paths.network.mkdir(parents=True)
    (paths.network / "10-static.network").write_text("[Match]\nName=bond0\n[Network]\nAddress=10.0.0.5/24\n")
    paths.network_run.mkdir(parents=True)
    copy = paths.network_run / "10-static.network"
    copy.write_text((paths.network / "10-static.network").read_text())
    os.chmod(copy, 0o600)                                   # as cz-firstboot leaves it
    assert sysagent.restart_check() == "nothing planned"
    assert (copy.stat().st_mode & 0o777) == 0o644
    assert ["networkctl", "reload"] in r.calls and ["networkctl", "reconfigure", "br0"] in r.calls
    r.calls.clear()
    assert sysagent.network_sync() == [] and ["networkctl", "reload"] not in r.calls     # fine now: nothing done
    (paths.network / "10-static.network").write_text("[Match]\nName=bond0\n[Network]\nAddress=10.0.0.6/24\n")
    assert sysagent.network_sync() == ["10-static.network"] and "10.0.0.6" in copy.read_text()



def test_br0_configured_before_the_static_file_was_copied_is_configured_again(paths, monkeypatch):
    """0.14.x on a Dell server: systemd-networkd read its files before cz-firstboot copied the static one, br0 got
    the DHCP default (no DHCP server: no address) and the copy was fine, so nothing was done. Now: firstboot runs
    before networkd, and network_sync reloads when br0 has a file of the image although the static one is there."""
    import configparser
    s = configparser.ConfigParser(strict=False)
    s.read(UNITS / "containerizer-firstboot.service")
    assert "systemd-networkd.service" in s["Unit"]["Before"].split()
    monkeypatch.setattr(sysagent, "DNS_WAIT", 0)
    monkeypatch.setattr(sysagent, "apply_firewall", lambda reload_dns=True: None)
    text = "[Match]\nName=br0\n[Network]\nAddress=10.0.0.5/24\n"
    for d in (paths.network, paths.network_run):
        d.mkdir(parents=True)
        (d / "10-static.network").write_text(text)
        (d / "10-static.network").chmod(0o644)
    r = fake_run(monkeypatch, **{"networkctl --json=short status br0":
                                 json.dumps({"NetworkFile": "/etc/systemd/network/22-uplink-br0.network"})})
    assert sysagent.network_sync() == ["10-static.network"]
    assert ["networkctl", "reload"] in r.calls and ["networkctl", "reconfigure", "br0"] in r.calls
    r = fake_run(monkeypatch, **{"networkctl --json=short status br0":
                                 json.dumps({"NetworkFile": str(paths.network_run / "10-static.network")})})
    assert sysagent.network_sync() == [] and ["networkctl", "reload"] not in r.calls


def test_a_static_address_of_0_13_moves_to_the_bridge(paths, monkeypatch):
    """0.14.0: the address is on br0 (bond0 is the bridge's port, as olljanat/nomad-qemu-node's netplan); a static
    file `network static` wrote in 0.13.x for bond0 is moved to br0 (cz-firstboot at boot, network_sync after);
    one written by hand is left as it is."""
    from containerizer import netconfig
    monkeypatch.setattr(sysagent, "DNS_WAIT", 0)
    monkeypatch.setattr(sysagent, "apply_firewall", lambda reload_dns=True: None)
    fake_run(monkeypatch)
    old = (netconfig.OLD_HEADER + "\n[Match]\nName=bond0\n\n[Network]\nAddress=10.0.0.5/24\nGateway=10.0.0.1\n"
           "DNS=10.0.0.53\n")
    paths.network.mkdir(parents=True)
    (paths.network / "10-static.network").write_text(old)
    (paths.network / "05-mine.network").write_text("[Match]\nName=bond0\n[Network]\nAddress=10.9.9.9/24\n")
    assert sysagent.network_sync() == ["05-mine.network", "10-static.network"]
    text = (paths.network / "10-static.network").read_text()
    assert text.startswith(netconfig.HEADER) and "\nName=br0\n" in text and "bond0" not in text
    assert netconfig.parse(text)["gateway"] == "10.0.0.1"
    assert "Name=bond0" in (paths.network / "05-mine.network").read_text()            # by hand: as it is
    assert netconfig.migrate(text) is None


def test_the_appliance_network_files_follow_the_bridge_example():
    """rootfs: every e* NIC (not a management controller's USB NIC) in bond0, bond0 the port of br0, which has the
    address (DHCP), as olljanat/nomad-qemu-node's 05_network.yaml."""
    import configparser
    from pathlib import Path as P_
    net = P_(__file__).resolve().parent.parent / "appliance" / "rootfs" / "etc" / "systemd" / "network"

    def ini(name):
        c = configparser.ConfigParser(strict=False, interpolation=None)
        c.optionxform = str
        c.read(net / name)
        return c
    ports = ini("20-uplink.network")
    assert ports["Match"]["Name"] == "e*" and "cdc_ether" in ports["Match"]["Driver"] and ports["Match"]["Driver"].startswith("!")
    assert ports["Network"]["Bond"] == "bond0" and ports["Network"]["LinkLocalAddressing"] == "no"
    bond = ini("21-uplink-bond0.network")
    assert bond["Network"]["Bridge"] == "br0" and "DHCP" not in bond["Network"]
    br = ini("22-uplink-br0.netdev")
    assert br["NetDev"]["Kind"] == "bridge" and br["Bridge"]["STP"] == "no" and br["Bridge"]["VLANFiltering"] == "yes"
    assert ini("22-uplink-br0.network")["Network"]["DHCP"] == "ipv4"
    assert ini("22-uplink-br0.network")["DHCPv4"]["UseHostname"] == "no"
    assert ini("22-uplink-br0.link")["Link"]["MACAddressPolicy"] == "none"
    issue = (net.parent.parent.parent / "etc" / "issue").read_text() if (net.parent.parent.parent / "etc" / "issue").is_file() else (net.parent.parent / "issue").read_text()
    assert "\\4{br0}" in issue and "cz network show" in issue


def test_the_llm_usage_dashboard_is_set_up_from_the_app_code(paths, monkeypatch):
    """An app update brings the LLM token usage dashboard (no OS change): the system agent makes the login
    cz_grafana (role usage) and, with Grafana's API, its data source and the dashboard; once, again only when one
    changed or Grafana lost it."""
    import io
    import urllib.error
    from containerizer import sqlstore
    paths.sql_secret = paths.run.parent / "secrets" / "cz-scanner"
    paths.sql_secret.parent.mkdir(parents=True)
    (paths.sql_secret.parent / "mssql-sa").write_text("sa-pw")
    (paths.sql_secret.parent / "grafana-admin").write_text("admin-pw")
    paths.plan.parent.mkdir(parents=True, exist_ok=True)
    logins, grafana = [], {"ds": None, "dash": None, "calls": []}
    monkeypatch.setattr(sqlstore, "create_login", lambda conn, login, pw, role: logins.append((login, role, pw)))

    class Conn:
        def commit(self):
            pass

        def close(self):
            pass

    class Resp(io.BytesIO):
        def __init__(self, status, body):
            super().__init__(json.dumps(body).encode())
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    def opener(req, timeout=0):
        path, method = req.full_url.split("/grafana", 1)[1], req.get_method()
        grafana["calls"].append((method, path))
        assert req.headers["Authorization"].startswith("Basic ")
        body = json.loads(req.data) if req.data else None

        def err(code):
            raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(b"{}"))
        if path == "/api/health":
            return Resp(200, {"database": "ok"})
        if path == "/api/datasources/uid/containerizer-sql":
            if method == "GET":
                return Resp(200, grafana["ds"]) if grafana["ds"] else err(404)
            grafana["ds"] = body
            return Resp(200, {})
        if path == "/api/datasources":
            grafana["ds"] = body
            return Resp(200, {})
        if path == "/api/dashboards/uid/containerizer-llm-usage":
            return Resp(200, {}) if grafana["dash"] else err(404)
        if path == "/api/folders":
            return Resp(200, [{"uid": "f1", "title": "containerizer"}])
        if path == "/api/dashboards/db":
            grafana["dash"] = body
            return Resp(200, {})
        raise AssertionError(path)
    assert sysagent.grafana_usage_sync(opener=opener, connect=lambda cs, pw: Conn()) == "login, data source, dashboard"
    pw = (paths.sql_secret.parent / "cz-grafana").read_text()
    assert logins == [("cz_grafana", "usage", pw)] and len(pw) >= 32
    assert grafana["ds"]["type"] == "mssql" and grafana["ds"]["user"] == "cz_grafana"
    assert grafana["ds"]["url"] == "127.0.0.1:1433" and grafana["ds"]["jsonData"]["database"] == "Containerizer"
    assert grafana["ds"]["secureJsonData"]["password"] == pw
    assert grafana["dash"]["folderUid"] == "f1" and grafana["dash"]["dashboard"]["uid"] == "containerizer-llm-usage"
    assert grafana["dash"]["overwrite"] is True and grafana["dash"]["dashboard"]["id"] is None
    # nothing again; a dashboard Grafana lost is saved again
    grafana["calls"].clear()
    assert sysagent.grafana_usage_sync(opener=opener, connect=lambda cs, pw: Conn()) == "up to date"
    assert not [c for c in grafana["calls"] if c[0] != "GET"] and len(logins) == 1
    grafana["dash"] = None
    assert sysagent.grafana_usage_sync(opener=opener, connect=lambda cs, pw: Conn()) == "dashboard"


def test_builds_and_pods_never_reach_the_appliances_ssh(paths):
    """The inbound ports (SSH, HTTPS) are for the network outside: the build bridges' drop comes before them (the
    boot test's probe from a build REACHED <appliance>:22), and pods may use HTTPS (the sandbox URLs) but not SSH."""
    nft, _ = sysagent.render(sysagent.system_rules(), {"mode": "enforce", "rules": []}, upstreams=["10.0.0.2"])
    chain = nft[nft.index("chain input"):nft.index("chain forward")]
    inbound = chain.index("tcp dport { 22, 443 } accept")
    assert chain.index('"br-*" } drop') < inbound
    assert chain.index("tcp dport 22 drop") < inbound
    if shutil.which("nft"):
        import subprocess
        p = subprocess.run(["nft", "-c", "-f", "-"], input=nft, capture_output=True, text=True)
        assert p.returncode == 0 or "Operation not permitted" in p.stderr, p.stderr
