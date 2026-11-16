"""The DNS filter's refuser (dnsrefuse.py): REFUSED for every name it is asked, each name counted for Admin ->
Firewall -> Refused names (sysagent.egress_status), instead of dnsmasq logging every query into the journal."""
import json
import socket
import struct
import time
from pathlib import Path

from containerizer import dnsrefuse, sysagent


def query(name: str, qid: int = 0x1234, qtype: int = 1) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q


def test_answer_is_refused_with_the_question():
    c = dnsrefuse.Counts(None)
    msg = query("dl-cdn.alpinelinux.org")
    out = dnsrefuse.answer(msg, c)
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", out[:12])
    assert qid == 0x1234 and flags & 0x8000 and flags & 0x0100 and flags & 0xF == 5 and (qd, an, ns, ar) == (1, 0, 0, 0)
    assert out[12:] == msg[12:]
    assert c.names["dl-cdn.alpinelinux.org"]["count"] == 1
    # not a query, a response, garbage, a compressed name: no answer, nothing counted
    assert dnsrefuse.answer(b"\x00" * 5, c) is None
    assert dnsrefuse.answer(out, c) is None
    assert dnsrefuse.answer(msg[:12] + b"\xc0\x0c", c) is None
    dnsrefuse.answer(query("1.0.0.10.in-addr.arpa", qtype=12), c)
    assert list(c.names) == ["dl-cdn.alpinelinux.org"]


def test_counts_window_cap_and_state(tmp_path, monkeypatch):
    st = tmp_path / "refused.json"
    c = dnsrefuse.Counts(st)
    now = 1_800_000_000
    c.add("old.example.org", now - 25 * 3600)
    c.add("pypi.org", now - 60)
    c.add("pypi.org", now)
    c.flush(now)
    data = json.loads(st.read_text())
    assert data["names"] == {"pypi.org": {"count": 2, "first": now - 60, "last": now}}       # older than 24 h: gone
    assert dnsrefuse.Counts(st).names["pypi.org"]["count"] == 2                          # kept over a restart
    monkeypatch.setattr(dnsrefuse, "MAX_NAMES", 2)
    c.add("a.example.org", now + 1)
    c.add("b.example.org", now + 2)
    assert set(c.names) == {"a.example.org", "b.example.org"}                           # the least recent dropped


def test_udp_and_tcp(tmp_path):
    c = dnsrefuse.Counts(tmp_path / "s.json")
    u, t = dnsrefuse.start("127.0.0.1", 0, c)
    port = u.getsockname()[1]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(query("registry.npmjs.org", 7), ("127.0.0.1", port))
        out, _ = s.recvfrom(512)
        assert struct.unpack(">H", out[:2])[0] == 7 and out[3] & 0xF == 5
        with socket.create_connection(("127.0.0.1", port), timeout=3) as k:
            m = query("proxy.golang.org", 8)
            k.sendall(struct.pack(">H", len(m)) + m)
            n, = struct.unpack(">H", k.recv(2))
            out = k.recv(n)
        assert struct.unpack(">H", out[:2])[0] == 8 and out[3] & 0xF == 5
        assert set(c.names) == {"registry.npmjs.org", "proxy.golang.org"}
    finally:
        u.close()
        t.close()


def test_status_reads_the_counts_newest_first(monkeypatch, tmp_path):
    monkeypatch.setattr(sysagent.P, "history", tmp_path / "h.jsonl")
    monkeypatch.setattr(sysagent.P, "rules", tmp_path / "rules.json")
    now = int(time.time())
    refused = {"names": {"sandbox-app-target.example.com": {"count": 90000, "first": now - 3600, "last": now - 300},
                         "dl-cdn.alpinelinux.org": {"count": 6, "first": now - 30, "last": now - 20},
                         "yesterday.example.org": {"count": 1, "first": now - 90000, "last": now - 90000},
                         "x.local": {"count": 1, "first": now, "last": now}}}
    journal = "cz-egress-drop: IN=cni0 OUT=eth0 SRC=10.42.0.7 DST=1.2.3.4 LEN=60 PROTO=TCP SPT=4000 DPT=8443 WINDOW=1"
    monkeypatch.setattr(sysagent, "system_rules", lambda: {"rules": []})
    st = sysagent.egress_status(journal, refused=refused)
    assert st["denied_names"] == [{"name": "dl-cdn.alpinelinux.org", "count": 6},
                                  {"name": "sandbox-app-target.example.com", "count": 90000}]
    assert st["dropped"] == [{"name": "1.2.3.4 tcp/8443", "count": 1}]
