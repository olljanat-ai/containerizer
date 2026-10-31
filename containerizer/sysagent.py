"""System agent of the containerizer appliance: `python -m containerizer.sysagent <command>`, as root.

The only part of the appliance that changes the OS. The web UI (unprivileged) reads what this agent
publishes in /run/containerizer/system/status.json and asks for changes by dropping a JSON file into
/run/containerizer/system/requests/; containerizer-sysagent.path starts `process`, which checks each
request again before acting on it:

- upgrade:  only a release tag (vX.Y.Z) of the one image repository this OS was built for
            (CZ_OS_IMAGE), only after `cosign verify` proved it was signed by this project's release
            workflow (keyless, GitHub OIDC), and installed by digest, so the tag cannot be moved between
            the check and the download. Elemental writes it as a new btrfs snapshot; the running system
            is not touched, and the boot assessment falls back to it when the new one fails to start.
- rollback: only a snapshot that is on the disk; Elemental installs a copy of it as the new active
            system (no download, no registry needed).
- egress:   the administrators' egress allow-list (validated here, not trusted from the web UI), then
            the firewall and the DNS filter are rebuilt from it.

Commands (also for an administrator on the console or over SSH):

    status                     publish status.json
    process                    handle the queued requests
    upgrade vX.Y.Z             verify, install and restart
    rollback <snapshot id>     install a copy of a snapshot and restart
    firewall apply             (re)build the nftables ruleset and the dnsmasq allow-list
    firewall show              print what `apply` would load
    health                     boot-assessment check (exit 1 when the appliance is not up)
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

VERSION_RE = re.compile(r"v\d{1,4}\.\d{1,4}\.\d{1,4}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
PORT_RE = re.compile(r"(?:(tcp|udp)/)?(\d{1,5})")
MAX_RULES = 500
MAX_PORTS = 16
NOTE_MAX = 200
TABLE = "cz_firewall"
DNS_ADDR = "169.254.53.53"        # dnsmasq: the one resolver of the host, Docker and k3s
INBOUND_TCP = (22, 443)           # SSH and HTTPS; nothing else is reachable from outside
# k3s pods and services, Docker bridges: traffic between them and the host stays allowed
INTERNAL4 = ("10.42.0.0/16", "10.43.0.0/16", "172.16.0.0/12")
INTERNAL_IFACES = ("cni0", "flannel.1", "docker0", "br-*", "veth*")


@dataclass
class Paths:
    conf: Path = Path("/usr/lib/containerizer/appliance.conf")
    system_rules: Path = Path("/usr/lib/containerizer/egress-system.json")
    rules: Path = Path("/etc/containerizer/egress.json")
    history: Path = Path("/var/lib/containerizer/system/egress-history.jsonl")
    run: Path = Path("/run/containerizer/system")
    dnsmasq: Path = Path("/run/containerizer/dnsmasq/egress.conf")
    nft: Path = Path("/run/containerizer/firewall.nft")
    os_release: Path = Path("/etc/os-release")
    snapshots: Path = Path("/.snapshots")
    elemental_run: Path = Path("/run/elemental")


P = Paths()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(cmd: list[str], timeout: int = 3600, check: bool = True, input: str | None = None) -> str:
    """Run a command (never through a shell); its output goes to the journal on failure."""
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input, errors="replace")
    if check and p.returncode:
        raise AgentError(f"{shlex.join(cmd[:3])} failed ({p.returncode}): {(p.stderr or p.stdout).strip()[-2000:]}")
    return p.stdout


class AgentError(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_env(path: Path) -> dict:
    out = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def conf() -> dict:
    c = read_env(P.conf)
    c.setdefault("CZ_OS_IMAGE", "ghcr.io/olljanat-ai/containerizer-appliance")
    c.setdefault("CZ_SIGNER_REPO", "olljanat-ai/containerizer")
    c.setdefault("CZ_SIGNER_ISSUER", "https://token.actions.githubusercontent.com")
    c.setdefault("CZ_SIGNER_IDENTITY_REGEXP", "^https://github\\.com/" + re.escape(c["CZ_SIGNER_REPO"])
                 + "/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$")
    return c


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)


# =============================================================================== status

def running_version() -> str | None:
    return read_env(P.os_release).get("IMAGE_TAG")


def boot_mode() -> str:
    for m in ("recovery", "passive", "active"):
        if (P.elemental_run / f"{m}_mode").exists():
            return m
    return "unknown"


def _scalar(v) -> str:
    return "" if v is None else str(v)


def snapshots(state_yaml: str | None = None) -> list[dict]:
    """The state partition's snapshots from `elemental state`, newest first, each with the version
    read from the snapshot's own /etc/os-release."""
    import yaml
    if state_yaml is None:
        try:
            state_yaml = run(["elemental", "state"], timeout=120)
        except (AgentError, OSError, subprocess.TimeoutExpired) as ex:
            log(f"elemental state: {ex}")
            return []
    try:
        st = yaml.safe_load(state_yaml) or {}
    except yaml.YAMLError:
        return []
    part = st.get("state") if isinstance(st, dict) else None
    snaps = (part or {}).get("snapshots") or {}
    out = []
    for sid, s in snaps.items():
        if not isinstance(s, dict) or not re.fullmatch(r"\d{1,6}", str(sid)):
            continue
        labels = s.get("labels") or {}
        version = read_env(P.snapshots / str(sid) / "snapshot" / "etc" / "os-release").get("IMAGE_TAG") \
            or labels.get("version")
        out.append({"id": int(sid), "active": bool(s.get("active")), "version": version,
                    "source": _scalar(s.get("source")), "digest": _scalar(s.get("digest")),
                    "date": _scalar(s.get("date")), "labels": {str(k): _scalar(v) for k, v in labels.items()}})
    return sorted(out, key=lambda x: x["id"], reverse=True)


def elemental_version() -> str:
    try:
        return run(["elemental", "version"], timeout=30).strip().splitlines()[0][:80]
    except (AgentError, OSError, subprocess.TimeoutExpired, IndexError):
        return ""


def publish(task: dict | None = None, egress_state: dict | None = None) -> dict:
    """Write status.json (world-readable: it holds no secrets)."""
    old = {}
    try:
        old = json.loads((P.run / "status.json").read_text())
    except (OSError, ValueError):
        pass
    c = conf()
    st = {"version": running_version(), "image": c["CZ_OS_IMAGE"], "signer": c["CZ_SIGNER_REPO"],
          "boot_mode": boot_mode(), "elemental": old.get("elemental") or elemental_version(),
          "hostname": socket.gethostname(), "snapshots": snapshots(), "updated": now(),
          "task": task if task is not None else old.get("task"),
          "egress": egress_state if egress_state is not None else (old.get("egress") or egress_status())}
    atomic_write(P.run / "status.json", json.dumps(st, indent=1), 0o644)
    return st


# =============================================================================== upgrade / rollback

def verify_signature(version: str, c: dict | None = None) -> str:
    """`cosign verify` the release tag against the release workflow's identity; the verified digest."""
    c = c or conf()
    if not VERSION_RE.fullmatch(version or ""):
        raise AgentError(f"not a release version: {version!r}")
    ref = f"{c['CZ_OS_IMAGE']}:{version}"
    out = run(["cosign", "verify", "--certificate-identity-regexp", c["CZ_SIGNER_IDENTITY_REGEXP"],
               "--certificate-oidc-issuer", c["CZ_SIGNER_ISSUER"], "--output", "json", ref], timeout=600)
    digests = set()
    try:
        for item in json.loads(out):
            digests.add(item["critical"]["image"]["docker-manifest-digest"])
    except (ValueError, KeyError, TypeError) as ex:
        raise AgentError(f"unexpected cosign output: {ex}") from None
    if len(digests) != 1 or not DIGEST_RE.fullmatch(next(iter(digests))):
        raise AgentError(f"cosign did not return exactly one digest for {ref}: {sorted(digests)}")
    return digests.pop()


def _snapshots_rw() -> None:
    # /.snapshots is mounted read-only on the running system; Elemental writes the new snapshot there
    if os.path.ismount(str(P.snapshots)):
        run(["mount", "-o", "remount,rw", str(P.snapshots)], timeout=60, check=False)


def upgrade(version: str, task: dict, reboot: bool = True) -> None:
    c = conf()
    task.update(state="running", started=now(), message="Verifying the image signature")
    publish(task)
    digest = verify_signature(version, c)
    task.update(message=f"Signature verified ({digest[:19]}…); installing")
    publish(task)
    _snapshots_rw()
    run(["elemental", "upgrade", "--system", f"oci:{c['CZ_OS_IMAGE']}@{digest}",
         "--snapshot-labels", f"version={version},digest={digest.replace(':', '-')}"], timeout=3 * 3600)
    _finish(task, f"Installed {version} ({digest[:19]}…)", reboot)


def rollback(snapshot: int, task: dict, reboot: bool = True) -> None:
    snaps = {s["id"]: s for s in snapshots()}
    s = snaps.get(snapshot)
    if not s or s["active"]:
        raise AgentError(f"snapshot {snapshot} is not an earlier snapshot on this disk")
    path = P.snapshots / str(snapshot) / "snapshot"
    if not (path / "etc" / "os-release").is_file():
        raise AgentError(f"{path} is not readable")
    task.update(state="running", started=now(), message=f"Installing a copy of snapshot {snapshot}")
    publish(task)
    _snapshots_rw()
    labels = f"version={s['version'] or 'unknown'},rollback-of={snapshot}"
    run(["elemental", "upgrade", "--system", f"dir:{path}", "--snapshot-labels", labels], timeout=3 * 3600)
    _finish(task, f"Rolled back to snapshot {snapshot} ({s['version'] or 'unknown version'})", reboot)


def _finish(task: dict, msg: str, reboot: bool) -> None:
    task.update(state="rebooting" if reboot else "done", finished=now(), message=msg + ("; restarting" if reboot else ""))
    publish(task)
    if reboot:
        run(["systemctl", "reboot"], timeout=60, check=False)


# =============================================================================== egress allow-list

class RuleError(ValueError):
    pass


def parse_ports(spec) -> list[str]:
    """'443', '80,443', 'udp/123', 'tcp/22' -> ['tcp/443', ...] (sorted, unique)."""
    items = spec if isinstance(spec, list) else re.split(r"[\s,]+", str(spec or "443").strip())
    out = set()
    for it in items:
        if not it:
            continue
        m = PORT_RE.fullmatch(str(it).strip().lower())
        if not m or not 1 <= int(m[2]) <= 65535:
            raise RuleError(f"not a port: {it!r} (use 443, 80,443 or udp/123)")
        out.add(f"{m[1] or 'tcp'}/{int(m[2])}")
    if not out or len(out) > MAX_PORTS:
        raise RuleError(f"between 1 and {MAX_PORTS} ports")
    return sorted(out, key=lambda p: (p.split("/")[0], int(p.split("/")[1])))


def normalize_host(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        raise RuleError(f"not a host name: {h!r}") from None
    if not HOST_RE.fullmatch(h):
        raise RuleError(f"not a host name: {h!r} (a DNS name such as api.nuget.org; it covers its subdomains)")
    return h


def validate_rules(data) -> dict:
    """The allow-list in its stored form, or RuleError. Entries: {host|cidr, ports, note}."""
    if not isinstance(data, dict):
        raise RuleError("expected an object")
    mode = data.get("mode") or "enforce"
    if mode not in ("enforce", "log"):
        raise RuleError("mode is enforce or log")
    raw = data.get("rules") or []
    if not isinstance(raw, list) or len(raw) > MAX_RULES:
        raise RuleError(f"at most {MAX_RULES} rules")
    rules, seen = [], set()
    for r in raw:
        if not isinstance(r, dict):
            raise RuleError("each rule is an object")
        note = " ".join(str(r.get("note") or "").split())[:NOTE_MAX]
        ports = parse_ports(r.get("ports"))
        if r.get("cidr"):
            try:
                net = ipaddress.ip_network(str(r["cidr"]).strip(), strict=False)
            except ValueError:
                raise RuleError(f"not an address or network: {r['cidr']!r}") from None
            if net.prefixlen == 0:
                raise RuleError("0.0.0.0/0 and ::/0 would open everything: turn the firewall to log mode instead")
            key = ("cidr", str(net), tuple(ports))
            entry = {"cidr": str(net), "ports": ports, "note": note}
        else:
            host = normalize_host(str(r.get("host") or ""))
            key = ("host", host, tuple(ports))
            entry = {"host": host, "ports": ports, "note": note}
        if key not in seen:
            seen.add(key)
            rules.append(entry)
    return {"mode": mode, "rules": rules}


def load_rules(path: Path, system: bool = False) -> dict:
    try:
        return validate_rules(json.loads(path.read_text()))
    except FileNotFoundError:
        return {"mode": "enforce", "rules": []}
    except (OSError, ValueError) as ex:
        # a broken admin file must not leave the appliance open, nor cut it off from its own updates
        log(f"{'system' if system else 'admin'} egress rules {path} ignored: {ex}")
        if system:
            raise
        return {"mode": "enforce", "rules": []}


def port_key(ports: list[str]) -> str:
    return "_".join(p.replace("/", "") for p in ports)


def _covers(parent: str, host: str) -> bool:
    return host == parent or host.endswith("." + parent)


def render(system: dict, admin: dict) -> tuple[str, str]:
    """(nftables ruleset, dnsmasq configuration) for the system and the administrators' rules."""
    rules = [dict(r, origin="system") for r in system["rules"]] + [dict(r, origin="admin") for r in admin["rules"]]
    enforce = admin.get("mode", "enforce") == "enforce"
    hosts = [r for r in rules if "host" in r]
    cidrs = [r for r in rules if "cidr" in r]
    groups = sorted({port_key(r["ports"]) for r in hosts})
    ports_of = {port_key(r["ports"]): r["ports"] for r in hosts}

    # dnsmasq: a name resolves only when a rule covers it, and its addresses go into the nftables set of
    # every rule that covers it (dnsmasq picks the longest matching domain, so a subdomain rule repeats
    # the sets of its parents)
    names = sorted({r["host"] for r in hosts}, key=lambda h: (h.count("."), h))
    dns = ["# generated by containerizer.sysagent from /usr/lib/containerizer/egress-system.json and",
           "# /etc/containerizer/egress.json; do not edit", "address=/#/"]
    for h in names:
        keys = sorted({port_key(r["ports"]) for r in hosts if _covers(r["host"], h)})
        sets = ",".join(f"4#inet#{TABLE}#f4_{k},6#inet#{TABLE}#f6_{k}" for k in keys)
        dns += [f"server=/{h}/#", f"nftset=/{h}/{sets}"]

    def portmatch(ports: list[str], proto: str) -> str | None:
        ps = [p.split("/")[1] for p in ports if p.startswith(proto + "/")]
        return f"{proto} dport {{ {', '.join(ps)} }}" if ps else None

    sets, allow = [], []
    for k in groups:
        sets += [f"  set f4_{k} {{ type ipv4_addr; flags timeout; timeout 1d; }}",
                 f"  set f6_{k} {{ type ipv6_addr; flags timeout; timeout 1d; }}"]
        for proto in ("tcp", "udp"):
            pm = portmatch(ports_of[k], proto)
            if pm:
                allow += [f"    ip daddr @f4_{k} {pm} accept", f"    ip6 daddr @f6_{k} {pm} accept"]
    for r in cidrs:
        fam = "ip" if ipaddress.ip_network(r["cidr"]).version == 4 else "ip6"
        for proto in ("tcp", "udp"):
            pm = portmatch(r["ports"], proto)
            if pm:
                allow.append(f"    {fam} daddr {r['cidr']} {pm} accept")
    internal4 = ", ".join(INTERNAL4)
    ifaces = ", ".join(f'"{i}"' for i in INTERNAL_IFACES)
    verdict = "drop" if enforce else "accept"
    allow_s = "\n".join(allow)
    nft = f"""# generated by containerizer.sysagent; do not edit (`python -m containerizer.sysagent firewall show`)
table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
{chr(10).join(sets)}

  chain input {{
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state invalid drop
    ct state established,related accept
    meta l4proto icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
    meta l4proto ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport {{ {", ".join(str(p) for p in INBOUND_TCP)} }} accept
    # containers and pods: the DNS filter, the k3s API and the kubelet only
    iifname {{ {ifaces} }} ip daddr {DNS_ADDR} meta l4proto {{ tcp, udp }} th dport 53 accept
    iifname {{ {ifaces} }} tcp dport {{ 6443, 10250 }} accept
    limit rate 10/minute burst 20 packets log prefix "cz-in-drop: " level info
  }}

  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    ip saddr {{ {internal4} }} ip daddr {{ {internal4} }} accept
    ip daddr {DNS_ADDR} meta l4proto {{ tcp, udp }} th dport 53 accept
    jump egress
  }}

  chain output {{
    type filter hook output priority filter; policy accept;
    oif "lo" accept
    ct state established,related accept
    ip daddr {{ {internal4}, {DNS_ADDR} }} accept
    meta l4proto ipv6-icmp accept
    meta l4proto icmp accept
    udp sport 68 udp dport 67 accept
    udp sport 546 udp dport 547 accept
    # upstream DNS for dnsmasq only, NTP for systemd-timesyncd only
    meta skuid "dnsmasq" meta l4proto {{ tcp, udp }} th dport 53 accept
    meta skuid "systemd-timesync" udp dport 123 accept
    jump egress
  }}

  chain egress {{
{allow_s}
    limit rate 30/minute burst 60 packets log prefix "cz-egress-drop: " level info
    {verdict}
  }}
}}
"""
    return nft, "\n".join(dns) + "\n"


def apply_firewall(reload_dns: bool = True) -> dict:
    """Load the ruleset (checked first; one transaction) and the DNS allow-list."""
    system = load_rules(P.system_rules, system=True)
    admin = load_rules(P.rules)
    nft, dns = render(system, admin)
    atomic_write(P.nft, nft, 0o600)
    run(["nft", "-c", "-f", str(P.nft)], timeout=60)
    run(["nft", "-f", str(P.nft)], timeout=60)
    atomic_write(P.dnsmasq, dns, 0o644)
    if reload_dns:
        run(["systemctl", "try-restart", "containerizer-dns.service"], timeout=120, check=False)
    log(f"firewall: {len(system['rules'])} system and {len(admin['rules'])} admin egress rules, mode {admin['mode']}")
    return admin


def save_rules(data: dict, user: str, name: str) -> dict:
    new = validate_rules(data)
    old = load_rules(P.rules)
    atomic_write(P.rules, json.dumps(new, indent=1), 0o644)
    try:
        apply_firewall()
    except AgentError:
        atomic_write(P.rules, json.dumps(old, indent=1), 0o644)   # keep the last ruleset that loaded
        apply_firewall()
        raise
    ok, nk = ({json.dumps(r, sort_keys=True) for r in x["rules"]} for x in (old, new))
    entry = {"at": now(), "by": user, "name": name, "mode": new["mode"], "old_mode": old["mode"],
             "added": [json.loads(x) for x in sorted(nk - ok)], "removed": [json.loads(x) for x in sorted(ok - nk)]}
    P.history.parent.mkdir(parents=True, exist_ok=True)
    with P.history.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    os.chmod(P.history, 0o644)
    return new


DENIED_DNS_RE = re.compile(r"config (\S+) is (?:NXDOMAIN|NODATA)")
DROP_RE = re.compile(r"cz-egress-drop: .*?\bDST=([0-9a-fA-F.:]+) .*?\bPROTO=(TCP|UDP)\b.*?\bDPT=(\d+)")


def egress_status(journal: str | None = None, history_lines: int = 50) -> dict:
    """Names the DNS filter refused and connections the firewall dropped in the last 24 hours, and the
    latest changes of the allow-list, for the admin page."""
    if journal is None:
        try:
            journal = run(["journalctl", "--since", "-24h", "--no-pager", "-o", "cat",
                           "-u", "containerizer-dns.service", "-k", "--grep", "is NXDOMAIN|is NODATA|cz-egress-drop"],
                          timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            journal = ""
    names: dict[str, int] = {}
    drops: dict[str, int] = {}
    for line in journal.splitlines():
        m = DENIED_DNS_RE.search(line)
        if m:
            n = m[1].lower().rstrip(".")
            if HOST_RE.fullmatch(n) and not n.endswith((".arpa", ".local", ".internal", ".localdomain")):
                names[n] = names.get(n, 0) + 1
            continue
        m = DROP_RE.search(line)
        if m:
            k = f"{m[1]} {m[2].lower()}/{m[3]}"
            drops[k] = drops.get(k, 0) + 1
    hist = []
    try:
        hist = [json.loads(x) for x in P.history.read_text().splitlines()[-history_lines:] if x.strip()]
    except (OSError, ValueError):
        pass
    top = lambda d: [{"name": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:50]]
    try:
        system = load_rules(P.system_rules, system=True)["rules"]
    except (OSError, ValueError):
        system = []
    admin = load_rules(P.rules)
    return {"mode": admin["mode"], "rules": admin["rules"], "system_rules": system,
            "denied_names": top(names), "dropped": top(drops), "history": hist[::-1], "updated": now()}


# =============================================================================== requests

def process() -> int:
    """Handle the queued requests, oldest first. A request is removed before it is acted on, so a
    request that restarts the appliance is never repeated."""
    d = P.run / "requests"
    rc = 0
    for f in sorted(d.glob("*.json")):
        try:
            req = json.loads(f.read_text())
        except (OSError, ValueError) as ex:
            log(f"request {f.name} ignored: {ex}")
            f.unlink(missing_ok=True)
            continue
        f.unlink(missing_ok=True)
        if not isinstance(req, dict):
            continue
        user = str(req.get("requested_by") or "?")[:256]
        name = str(req.get("requested_by_name") or "")[:256]
        action = req.get("action")
        log(f"request: {action} by {user}")
        task = {"action": action, "requested_by": user, "requested_by_name": name,
                "requested_at": str(req.get("requested_at") or "")[:40], "state": "queued"}
        try:
            if action == "upgrade":
                task["version"] = str(req.get("version") or "")[:40]
                upgrade(task["version"], task)
            elif action == "rollback":
                sid = req.get("snapshot")
                if not isinstance(sid, int) or isinstance(sid, bool):
                    raise AgentError("snapshot must be a number")
                task["snapshot"] = sid
                rollback(sid, task)
            elif action == "egress":
                save_rules({"mode": req.get("mode"), "rules": req.get("rules")}, user, name)
                publish(egress_state=egress_status())
            else:
                log(f"unknown action {action!r} ignored")
        except (AgentError, RuleError, OSError, subprocess.TimeoutExpired) as ex:
            rc = 1
            log(f"{action} failed: {ex}")
            if action in ("upgrade", "rollback"):
                task.update(state="failed", finished=now(), message=str(ex)[-1000:])
                publish(task)
            else:
                st = egress_status()
                st["error"] = f"{now()}: {ex}"[:1000]
                publish(egress_state=st)
    return rc


# =============================================================================== health

def health(url: str = "http://127.0.0.1:8080/healthz") -> int:
    """Boot assessment (elemental-boot-assessment runs it until it passes, at most 5 times 30 s apart,
    then restarts into the previous snapshot): the firewall is loaded and the web UI answers."""
    try:
        run(["nft", "list", "table", "inet", TABLE], timeout=30)
    except (AgentError, OSError) as ex:
        log(f"health: firewall not loaded: {ex}")
        return 1
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            if r.status == 200:
                return 0
    except OSError as ex:
        log(f"health: {url}: {ex}")
    return 1


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    try:
        if cmd == "status":
            publish()
            return 0
        if cmd == "process":
            return process()
        if cmd == "upgrade" and len(argv) == 2:
            upgrade(argv[1], {"action": "upgrade", "version": argv[1], "requested_by": "console"},
                    reboot="--no-reboot" not in argv)
            return 0
        if cmd == "rollback" and len(argv) == 2 and argv[1].isdigit():
            rollback(int(argv[1]), {"action": "rollback", "snapshot": int(argv[1]), "requested_by": "console"})
            return 0
        if cmd == "firewall" and argv[1:2] == ["apply"]:
            apply_firewall(reload_dns="--no-dns-reload" not in argv)
            return 0
        if cmd == "firewall" and argv[1:2] == ["show"]:
            nft, dns = render(load_rules(P.system_rules, system=True), load_rules(P.rules))
            print(nft)
            print(dns)
            return 0
        if cmd == "health":
            return health()
    except (AgentError, RuleError, subprocess.TimeoutExpired) as ex:
        log(f"error: {ex}")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
