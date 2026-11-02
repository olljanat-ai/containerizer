"""A small NFLOG reader: the packets kube-router (k3s's network policy controller) logs when a NetworkPolicy
drops them (docs/egress.md#the-egress-observer).

kube-router puts an NFLOG rule in front of every DROP of a policy chain:

    -m limit --limit 10/min --limit-burst 10 -j NFLOG --nflog-prefix "DROP by policy <namespace>/<policy>" --nflog-group 100

so every dropped packet (at most 10 a minute per policy) reaches the netlink group 100 with its prefix and
its first bytes. This module binds to that group over a NETLINK_NETFILTER socket (the same protocol as
libnetfilter_log; no packages, no tcpdump), asks for the first COPY_RANGE bytes of each packet and parses the
IPv4 or IPv6 header and the TCP or UDP ports. Binding needs CAP_NET_ADMIN in the host's network namespace,
nothing else; the socket only reads.

`parse_messages(data)` turns what one recv() returns into Drop records and is what the unit tests feed with
captured and constructed messages; `Reader` is the socket.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET, NFULNL_MSG_CONFIG = 0, 1
NFULA_CFG_CMD, NFULA_CFG_MODE, NFULA_CFG_NLBUFSIZ, NFULA_CFG_TIMEOUT, NFULA_CFG_QTHRESH, NFULA_CFG_FLAGS = 1, 2, 3, 4, 5, 6
NFULNL_CFG_CMD_BIND, NFULNL_CFG_CMD_UNBIND = 1, 2
NFULNL_COPY_PACKET = 2
NFULA_PACKET_HDR, NFULA_PAYLOAD, NFULA_PREFIX = 1, 9, 10
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_ACK = 1, 4
NLA_TYPE_MASK = 0x3FFF                  # without NLA_F_NESTED / NLA_F_NET_BYTEORDER
GROUP = 100                             # kube-router's --nflog-group
COPY_RANGE = 128                        # bytes of each packet: the IP header and the ports are enough
PREFIX = "DROP by policy "
PROTOCOLS = {6: "TCP", 17: "UDP", 132: "SCTP"}
IPV6_EXTENSIONS = (0, 43, 44, 51, 60)   # hop-by-hop, routing, fragment, AH, destination options

_NLMSGHDR = struct.Struct("=IHHII")     # len, type, flags, seq, pid (host byte order)
_NFGENMSG = struct.Struct("!BBH")       # family, version, res_id (network byte order)
_NLATTR = struct.Struct("=HH")


@dataclass
class Drop:
    """One packet a NetworkPolicy dropped."""
    namespace: str
    policy: str
    family: int                         # socket.AF_INET or AF_INET6
    src: str
    dst: str
    protocol: str                       # TCP, UDP, ICMP, ...
    sport: int | None = None
    dport: int | None = None
    syn: bool = False                   # a TCP SYN without ACK: a new connection

    def to_dict(self) -> dict:
        return {"namespace": self.namespace, "policy": self.policy, "src": self.src, "dst": self.dst,
                "protocol": self.protocol, "sport": self.sport, "dport": self.dport, "syn": self.syn}


def _align(n: int) -> int:
    return (n + 3) & ~3


def attributes(data: bytes) -> dict[int, bytes]:
    """The netlink attributes of a message body: {type: value} (the first of each type)."""
    out: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(data):
        ln, typ = _NLATTR.unpack_from(data, i)
        if ln < 4 or i + ln > len(data):
            break
        out.setdefault(typ & NLA_TYPE_MASK, data[i + 4:i + ln])
        i += _align(ln)
    return out


def parse_prefix(raw: bytes) -> tuple[str, str] | None:
    """(namespace, policy) of a kube-router prefix 'DROP by policy <namespace>/<policy>', else None."""
    text = raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()
    if not text.startswith(PREFIX):
        return None
    rest = text[len(PREFIX):].strip()
    ns, sep, pol = rest.partition("/")
    if not sep or not ns:
        return None
    return ns, pol


def parse_packet(family: int, payload: bytes) -> tuple[str, str, str, int | None, int | None, bool] | None:
    """(src, dst, protocol, sport, dport, syn) of the first bytes of an IPv4 or IPv6 packet."""
    if family not in (socket.AF_INET, socket.AF_INET6) and payload:
        family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(payload[0] >> 4, family)
    if family == socket.AF_INET:
        if len(payload) < 20 or payload[0] >> 4 != 4:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20:
            return None
        proto = payload[9]
        src, dst = str(ipaddress.IPv4Address(payload[12:16])), str(ipaddress.IPv4Address(payload[16:20]))
        frag = struct.unpack_from("!H", payload, 6)[0] & 0x1FFF
        l4 = payload[ihl:] if not frag else b""
    elif family == socket.AF_INET6:
        if len(payload) < 40 or payload[0] >> 4 != 6:
            return None
        proto = payload[6]
        src, dst = str(ipaddress.IPv6Address(payload[8:24])), str(ipaddress.IPv6Address(payload[24:40]))
        i = 40
        while proto in IPV6_EXTENSIONS and i + 8 <= len(payload):
            nxt = payload[i]
            if proto == 44:                 # fragment header: fixed 8 bytes; only the first fragment has ports
                if struct.unpack_from("!H", payload, i + 2)[0] & 0xFFF8:
                    i = len(payload)
                    proto = nxt
                    break
                hl = 8
            elif proto == 51:               # AH: length in 4-byte units, plus 2
                hl = (payload[i + 1] + 2) * 4
            else:
                hl = (payload[i + 1] + 1) * 8
            proto, i = nxt, i + hl
        l4 = payload[i:]
    else:
        return None
    name = PROTOCOLS.get(proto) or {1: "ICMP", 58: "ICMPv6"}.get(proto) or str(proto)
    sport = dport = None
    syn = False
    if proto in PROTOCOLS and len(l4) >= 4:
        sport, dport = struct.unpack_from("!HH", l4, 0)
        if proto == 6 and len(l4) >= 14:
            flags = l4[13]
            syn = bool(flags & 0x02) and not flags & 0x10
    return src, dst, name, sport, dport, syn


def parse_messages(data: bytes) -> list[Drop]:
    """Every NFLOG packet message in one netlink datagram, as Drops (other messages and prefixes ignored)."""
    out: list[Drop] = []
    i = 0
    while i + _NLMSGHDR.size <= len(data):
        ln, typ, _flags, _seq, _pid = _NLMSGHDR.unpack_from(data, i)
        if ln < _NLMSGHDR.size or i + ln > len(data):
            break
        body = data[i + _NLMSGHDR.size:i + ln]
        i += _align(ln)
        if typ != (NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET) or len(body) < _NFGENMSG.size:
            continue
        family = body[0]
        attrs = attributes(body[_NFGENMSG.size:])
        pre = parse_prefix(attrs.get(NFULA_PREFIX, b""))
        payload = attrs.get(NFULA_PAYLOAD)
        if pre is None or not payload:
            continue
        pkt = parse_packet(family, payload)
        if pkt is None:
            continue
        src, dst, proto, sport, dport, syn = pkt
        out.append(Drop(pre[0], pre[1], socket.AF_INET6 if ":" in src else socket.AF_INET, src, dst, proto,
                        sport, dport, syn))
    return out


# --------------------------------------------------------------------------- building messages

def nlattr(typ: int, value: bytes) -> bytes:
    a = _NLATTR.pack(4 + len(value), typ) + value
    return a + b"\0" * (_align(len(a)) - len(a))


def config_message(group: int, attrs: bytes, family: int = 0, seq: int = 1, ack: bool = True) -> bytes:
    """An NFULNL_MSG_CONFIG request for `group` (res_id) with the given attributes."""
    body = _NFGENMSG.pack(family, 0, group) + attrs
    return _NLMSGHDR.pack(_NLMSGHDR.size + len(body), NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_CONFIG,
                          NLM_F_REQUEST | (NLM_F_ACK if ack else 0), seq, 0) + body


def packet_message(family: int, prefix: str, payload: bytes, group: int = GROUP, hw_protocol: int = 0x0800) -> bytes:
    """An NFULNL_MSG_PACKET message as the kernel sends it (for tests and `egress-observe --selftest`)."""
    attrs = (nlattr(NFULA_PACKET_HDR, struct.pack("!HBB", hw_protocol, 3, 0))
             + nlattr(NFULA_PREFIX, prefix.encode() + b"\0") + nlattr(NFULA_PAYLOAD, payload))
    body = _NFGENMSG.pack(family, 0, group) + attrs
    return _NLMSGHDR.pack(_NLMSGHDR.size + len(body), NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET, 0, 0, 0) + body


def ipv4_tcp(src: str, dst: str, sport: int, dport: int, flags: int = 0x02) -> bytes:
    """The first 40 bytes of an IPv4 TCP packet (checksums left 0)."""
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, ipaddress.IPv4Address(src).packed,
                     ipaddress.IPv4Address(dst).packed)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 64240, 0, 0)
    return ip + tcp


def ipv6_udp(src: str, dst: str, sport: int, dport: int) -> bytes:
    ip = struct.pack("!IHBB16s16s", 6 << 28, 8, 17, 64, ipaddress.IPv6Address(src).packed,
                     ipaddress.IPv6Address(dst).packed)
    return ip + struct.pack("!HHHH", sport, dport, 8, 0)


class NflogError(OSError):
    pass


class Reader:
    """A socket bound to an NFLOG group. Needs CAP_NET_ADMIN; one process per group (EBUSY otherwise)."""

    def __init__(self, group: int = GROUP, copy_range: int = COPY_RANGE, rcvbuf: int = 1 << 20):
        self.group = group
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            self.sock.bind((0, 0))
            self._request(config_message(group, nlattr(NFULA_CFG_CMD, bytes([NFULNL_CFG_CMD_BIND])), seq=1))
            mode = struct.pack("!IBB", copy_range, NFULNL_COPY_PACKET, 0)
            self._request(config_message(group, nlattr(NFULA_CFG_MODE, mode), seq=2))
            # hand packets over at once (no batching): the observer is a reader, not a high-volume logger
            self._request(config_message(group, nlattr(NFULA_CFG_QTHRESH, struct.pack("!I", 1)), seq=3))
        except Exception:
            self.sock.close()
            raise

    def _request(self, msg: bytes) -> None:
        self.sock.send(msg)
        data = self.sock.recv(65536)
        if len(data) >= _NLMSGHDR.size + 4:
            _ln, typ, _f, _s, _p = _NLMSGHDR.unpack_from(data, 0)
            if typ == NLMSG_ERROR:
                err = struct.unpack_from("=i", data, _NLMSGHDR.size)[0]
                if err:
                    raise NflogError(-err, f"NFLOG group {self.group}: {os.strerror(-err)}"
                                     + (" (another process reads this group)" if -err == 16 else "")
                                     + (" (needs CAP_NET_ADMIN)" if -err == 1 else ""))

    def read(self, timeout: float | None = None) -> list[Drop]:
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return []
        except OSError as ex:
            if ex.errno == 105:            # ENOBUFS: the kernel dropped messages; keep reading
                return []
            raise
        return parse_messages(data)

    def close(self) -> None:
        try:
            self.sock.send(config_message(self.group, nlattr(NFULA_CFG_CMD, bytes([NFULNL_CFG_CMD_UNBIND])), ack=False))
        except OSError:
            pass
        self.sock.close()
