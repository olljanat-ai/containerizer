"""The appliance's network address (docs/appliance-admin.md#network): DHCP, the default, or a static address on
bond0, the bond of every wired interface. A static address is the systemd-networkd file
/etc/containerizer/network/10-static.network (cz-firstboot copies that folder to /run/systemd/network at every
boot, and it sorts before the DHCP default 21-uplink-bond0.network). Set on the console or over SSH with
`python -m containerizer.sysagent network ...`, which checks it here and applies it (sysagent.apply_network).

    python -m containerizer.netconfig render <address/prefix> <gateway> <dns> [<dns> ...]
        print the file for that static address, or why it is not valid (exit 1)
"""
from __future__ import annotations

import ipaddress
import re
import sys

STATIC_FILE = "10-static.network"
MAX_DNS = 3
HEADER = "# Containerizer: the appliance's static address (python -m containerizer.sysagent network static ...)."


class NetworkError(ValueError):
    pass


def _dns(values) -> list[str]:
    items = values if isinstance(values, (list, tuple)) else re.split(r"[\s,;]+", str(values or "").strip())
    out = []
    for v in items:
        v = str(v).strip()
        if not v:
            continue
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            raise NetworkError(f"not an IP address of a DNS server: {v!r}") from None
        if ip.is_unspecified or ip.is_multicast:
            raise NetworkError(f"not a DNS server's address: {v}")
        if str(ip) not in out:
            out.append(str(ip))
    if not out:
        raise NetworkError("give at least one DNS server: with a static address the appliance learns none")
    if len(out) > MAX_DNS:
        raise NetworkError(f"at most {MAX_DNS} DNS servers")
    return out


def validate(mode: str, address: str = "", gateway: str = "", dns=()) -> dict:
    """The setting in its stored form: {"mode": "dhcp"} or {"mode": "static", "address": "192.0.2.10/24",
    "gateway": "192.0.2.1", "dns": [...]}; NetworkError says what is wrong."""
    mode = (mode or "").strip().lower()
    if mode == "dhcp":
        return {"mode": "dhcp"}
    if mode != "static":
        raise NetworkError("the address comes from DHCP or is static")
    address = (address or "").strip()
    if "/" not in address:
        raise NetworkError("give the address with its prefix length, e.g. 192.0.2.10/24")
    try:
        iface = ipaddress.ip_interface(address)
    except ValueError:
        raise NetworkError(f"not an address with a prefix length: {address!r}") from None
    ip, net = iface.ip, iface.network
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise NetworkError(f"{ip} cannot be the appliance's address")
    if ip.version == 4 and net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address):
        raise NetworkError(f"{ip} is the {'network' if ip == net.network_address else 'broadcast'} address of {net}")
    try:
        gw = ipaddress.ip_address((gateway or "").strip())
    except ValueError:
        raise NetworkError(f"not a gateway address: {gateway!r}") from None
    if gw.version != ip.version:
        raise NetworkError("the gateway is not of the address's IP version")
    if gw == ip:
        raise NetworkError("the gateway is the appliance's own address")
    if gw not in net and not (gw.version == 6 and gw.is_link_local):
        raise NetworkError(f"the gateway {gw} is not in {net}")
    return {"mode": "static", "address": str(iface), "gateway": str(gw), "dns": _dns(dns)}


def render(cfg: dict) -> str:
    """The systemd-networkd file of a static setting (validate's form)."""
    lines = [HEADER, "[Match]", "Name=bond0", "", "[Network]", f"Address={cfg['address']}",
             f"Gateway={cfg['gateway']}"]
    lines += [f"DNS={d}" for d in cfg["dns"]]
    lines += ["IPv6AcceptRA=yes", "LLMNR=no", "MulticastDNS=no", ""]
    return "\n".join(lines)


def parse(text: str | None) -> dict | None:
    """A static setting read back from its file (render's, or one written by hand): None for none."""
    if not text:
        return None
    vals: dict = {}
    for line in text.splitlines():
        m = re.match(r"\s*(Address|Gateway|DNS)\s*=\s*(\S+)", line)
        if m:
            vals.setdefault(m[1], []).append(m[2])
    if not vals.get("Address"):
        return None
    return {"mode": "static", "address": vals["Address"][0], "gateway": (vals.get("Gateway") or [""])[0],
            "dns": vals.get("DNS") or []}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) >= 4 and argv[0] == "render":
        try:
            print(render(validate("static", argv[1], argv[2], argv[3:])), end="")
            return 0
        except NetworkError as ex:
            print(str(ex), file=sys.stderr)
            return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
