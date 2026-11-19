"""Access to the built-in results database from the network (Admin -> System -> Results database access).

The built-in SQL Server (cz-mssql) listens on 127.0.0.1:1433 only. Two settings, each off by default:

- **Read-only login** `cz_readonly`: a SQL login in the database role reader (the results views, as the web UI
  reads them; nothing it can change). An administrator sets its password on the page; the system agent creates
  the login or sets the new password (sqlstore.create_login), or disables it. The password is never stored: it
  passes once through a request file only root and the web UI's user can read.
- **Incoming connections**: the agent runs the transient units containerizer-sql-proxy.socket/.service
  (systemd-run with systemd-socket-proxyd from the OS's systemd), listening on port 1433 of the appliance's own
  addresses (br0) and forwarding to 127.0.0.1:1433, and the firewall (sysagent.render) accepts TCP 1433 from the
  networks the administrator lists, never from the sandbox's pods or the builds. `status` (every 5 minutes) puts the
  units back after a restart and follows a changed address.

Settings: /var/lib/containerizer/system/sql-access.json. Only for the built-in SQL Server: with an external one
(CZ_SQL_SERVER) its DBA decides who connects.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SETTINGS = Path("/var/lib/containerizer/system/sql-access.json")
LOGIN = "cz_readonly"
ROLE = "reader"
PORT = 1433
UNIT = "containerizer-sql-proxy"
PROXYD = "/usr/lib/systemd/systemd-socket-proxyd"
MAX_NETWORKS = 20
DEFAULTS = {"login": False, "incoming": False, "networks": []}


class SqlAccessError(Exception):
    pass


def _read(path: Path) -> dict:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def load(path: Path | None = None) -> dict:
    d = _read(path or SETTINGS)
    return {**DEFAULTS, **{k: d[k] for k in d if k in DEFAULTS or k in ("changed_at", "changed_by", "error",
                                                                        "login_set_at", "login_set_by", "listening")}}


def save(settings: dict, path: Path | None = None) -> None:
    path = path or SETTINGS
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(settings, indent=1))
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def networks(text) -> list[str]:
    """The source networks (CIDRs or addresses, one per line, comma or space) as normalised CIDRs."""
    items = text if isinstance(text, list) else re.split(r"[\s,;]+", str(text or ""))
    out = []
    for x in items:
        x = str(x).strip()
        if not x:
            continue
        try:
            n = ipaddress.ip_network(x, strict=False)
        except ValueError:
            raise SqlAccessError(f"not a network or address: {x[:60]}") from None
        if n.is_loopback or n.is_link_local or n.is_multicast:
            raise SqlAccessError(f"not a network clients connect from: {n}")
        if str(n) not in out:
            out.append(str(n))
    if len(out) > MAX_NETWORKS:
        raise SqlAccessError(f"at most {MAX_NETWORKS} networks")
    return out


def check_password(pw: str) -> None:
    """SQL Server's password policy (CHECK_POLICY), a little stricter: 12 to 128 characters, three of upper case,
    lower case, digits and symbols, and nothing a connection string would split on."""
    if not isinstance(pw, str) or not 12 <= len(pw) <= 128:
        raise SqlAccessError("the password is 12 to 128 characters")
    kinds = sum(bool(re.search(rx, pw)) for rx in (r"[A-Z]", r"[a-z]", r"\d", r"[^A-Za-z0-9]"))
    if kinds < 3:
        raise SqlAccessError("the password needs three of: upper case, lower case, digits, symbols")
    if re.search(r"[;'\"{}\x00-\x1f]", pw):
        raise SqlAccessError("the password must not contain ; ' \" { } or control characters")


def nft_lines(settings: dict, exclude_ifaces: str) -> list[str]:
    """The firewall's input rules for incoming connections (none when they are off)."""
    if not settings.get("incoming") or not settings.get("networks"):
        return []
    v4 = [n for n in settings["networks"] if ipaddress.ip_network(n).version == 4]
    v6 = [n for n in settings["networks"] if ipaddress.ip_network(n).version == 6]
    out = ["    # the results database from the networks an administrator allowed (Admin -> System, sqlaccess.py)"]
    if v4:
        out.append(f"    iifname != {{ {exclude_ifaces} }} ip saddr {{ {', '.join(v4)} }} tcp dport {PORT} accept")
    if v6:
        out.append(f"    iifname != {{ {exclude_ifaces} }} ip6 saddr {{ {', '.join(v6)} }} tcp dport {PORT} accept")
    return out


def listen_addresses(addresses: list[str]) -> list[str]:
    """systemd ListenStream= values for the appliance's own addresses ("10.0.0.5/24" -> "10.0.0.5:1433")."""
    out = []
    for a in addresses:
        ip = ipaddress.ip_interface(a).ip
        if ip.is_loopback or ip.is_link_local:
            continue
        out.append(f"[{ip}]:{PORT}" if ip.version == 6 else f"{ip}:{PORT}")
    return sorted(out)


def proxy_command(listen: list[str]) -> list[str]:
    """The systemd-run command line of the proxy: a socket unit on the appliance's addresses, a hardened service."""
    cmd = ["systemd-run", f"--unit={UNIT}", "--collect", "--description=containerizer appliance: results database proxy"]
    cmd += [f"--socket-property=ListenStream={x}" for x in listen]
    cmd += ["--socket-property=FreeBind=yes", "--socket-property=Backlog=64",
            "--property=DynamicUser=yes", "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateDevices=yes",
            "--property=RestrictAddressFamilies=AF_INET AF_INET6", "--property=CapabilityBoundingSet=",
            "--property=MemoryMax=128M", "--property=TasksMax=64",
            PROXYD, "--connections-max=64", f"127.0.0.1:{PORT}"]
    return cmd


def status(settings: dict, local: bool, listening: list[str] | None = None) -> dict:
    """What the page shows (status.json, world-readable: no password)."""
    s = {k: settings.get(k) for k in ("login", "incoming", "networks", "changed_at", "changed_by", "error",
                                      "login_set_at", "login_set_by")}
    s.update({"local": local, "login_name": LOGIN, "port": PORT, "listening": listening or []})
    return s


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
