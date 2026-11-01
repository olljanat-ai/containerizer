"""The appliance: the System and Firewall admin pages (appliance.py) and the root system agent
(sysagent.py): signed upgrades, roll back, the egress allow-list and its nftables/dnsmasq rendering."""
import io
import json
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
                       task=tmp_path / "var" / "last-task.json",
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
    assert "name='snapshot' value='1'" in body and "name='snapshot' value='2'" not in body


def test_upgrade_request_needs_confirmation_and_a_newer_release(page):
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.2.0"]}, shell)
    assert st == 303 and "confirm" in loc and requests_in(page) == []
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.0.0"], "confirm": ["yes"]}, shell)
    assert "not+a+newer+release" in loc and requests_in(page) == []
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.2.0"], "confirm": ["yes"]}, shell)
    assert st == 303 and requests_in(page)[0] | {"requested_at": None} == {
        "action": "upgrade", "version": "v1.2.0", "requested_by": "alice@x", "requested_by_name": "Alice", "requested_at": None}
    st, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"version": ["v1.2.0"], "confirm": ["yes"]}, shell)
    assert "already+in+progress" in loc and len(requests_in(page)) == 1


def test_rollback_request_only_for_an_earlier_snapshot(page):
    for sid in ("2", "9", "1;x"):
        page.handle(ADMIN, "POST", ["system", "rollback"], {}, {"snapshot": [sid], "confirm": ["yes"]}, shell)
    assert requests_in(page) == []
    page.handle(ADMIN, "POST", ["system", "rollback"], {}, {"snapshot": ["1"], "confirm": ["yes"]}, shell)
    assert requests_in(page)[0]["snapshot"] == 1


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


def test_sbom_attach_tool_is_in_the_image():
    docker = (APPLIANCE / "Dockerfile").read_text()
    assert "oras-project/oras/releases/download/" in docker and "-C /usr/bin --no-same-owner oras" in docker
    assert docker.count("--checksum=sha256:") >= 4        # every download is pinned


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
