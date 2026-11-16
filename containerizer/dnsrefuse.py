"""The appliance DNS filter's refuser (containerizer-dns-refused.service): dnsmasq forwards every name no egress rule
allows here (its default server), and this answers REFUSED, as dnsmasq did by itself before, and counts the name.
Admin -> Firewall -> Refused names reads the counts (sysagent.egress_status), so dnsmasq no longer logs every query:
with log-queries the journal took some 900 000 lines an hour on a busy appliance, its 2 GB held only hours, and the
refused names of a build were gone before anyone looked.

    python -m containerizer.dnsrefuse --listen 127.0.0.1:5354 --state /run/containerizer-dns-refused/refused.json

The state file: {"updated": epoch, "names": {name: {"count": n, "first": epoch, "last": epoch}}}, the names asked
for in the last 24 hours (at most MAX_NAMES, the least recent dropped first), written every FLUSH seconds."""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

FLUSH = 15
WINDOW = 24 * 3600
MAX_NAMES = 5000
REFUSED = 5


def parse_query(msg: bytes) -> tuple[int, int, str, bytes] | None:
    """(id, flags, name, question section) of a DNS query, or None when it is not one."""
    if len(msg) < 12:
        return None
    qid, flags, qd = struct.unpack(">HHH", msg[:6])
    if flags & 0x8000 or qd < 1:                    # a response, or no question
        return None
    i, labels = 12, []
    while True:
        if i >= len(msg):
            return None
        n = msg[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 or i + 1 + n > len(msg) or len(labels) > 127:   # no compression in a question
            return None
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    if i + 4 > len(msg):
        return None
    return qid, flags, ".".join(labels).lower(), msg[12:i + 4]


def refused(qid: int, flags: int, question: bytes) -> bytes:
    """The REFUSED answer: the query's id, opcode and RD bit, its question, no records."""
    out_flags = 0x8000 | (flags & 0x7800) | (flags & 0x0100) | REFUSED
    return struct.pack(">HHHHHH", qid, out_flags, 1, 0, 0, 0) + question


class Counts:
    def __init__(self, state: Path | None):
        self.state = state
        self.lock = threading.Lock()
        self.names: dict[str, dict] = {}
        if state is not None:
            try:
                self.names = {k: v for k, v in json.loads(state.read_text()).get("names", {}).items()
                              if isinstance(v, dict)}
            except (OSError, ValueError):
                pass
        self.dirty = False

    def add(self, name: str, now: float | None = None) -> None:
        if not name or name.endswith(".arpa"):
            return
        now = time.time() if now is None else now
        with self.lock:
            e = self.names.get(name)
            if e is None:
                if len(self.names) >= MAX_NAMES:
                    del self.names[min(self.names, key=lambda k: self.names[k]["last"])]
                e = self.names[name] = {"count": 0, "first": int(now), "last": int(now)}
            e["count"] += 1
            e["last"] = int(now)
            self.dirty = True

    def snapshot(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self.lock:
            for k in [k for k, v in self.names.items() if v["last"] < now - WINDOW]:
                del self.names[k]
            self.dirty = False
            return {"updated": int(now), "names": {k: dict(v) for k, v in self.names.items()}}

    def flush(self, now: float | None = None) -> None:
        if self.state is None:
            return
        data = json.dumps(self.snapshot(now), separators=(",", ":"))
        tmp = self.state.with_name(self.state.name + ".tmp")
        tmp.write_text(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.state)


def answer(msg: bytes, counts: Counts) -> bytes | None:
    q = parse_query(msg)
    if q is None:
        return None
    qid, flags, name, question = q
    counts.add(name)
    return refused(qid, flags, question)


def serve_udp(sock: socket.socket, counts: Counts) -> None:
    while True:
        try:
            msg, addr = sock.recvfrom(4096)
        except OSError:
            return
        out = answer(msg, counts)
        if out is not None:
            try:
                sock.sendto(out, addr)
            except OSError:
                pass


def _tcp_client(conn: socket.socket, counts: Counts) -> None:
    with conn:
        conn.settimeout(5)
        try:
            while True:
                head = conn.recv(2)
                if len(head) < 2:
                    return
                n, = struct.unpack(">H", head)
                msg = b""
                while len(msg) < n:
                    part = conn.recv(n - len(msg))
                    if not part:
                        return
                    msg += part
                out = answer(msg, counts)
                if out is None:
                    return
                conn.sendall(struct.pack(">H", len(out)) + out)
        except OSError:
            return


def serve_tcp(sock: socket.socket, counts: Counts) -> None:
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        threading.Thread(target=_tcp_client, args=(conn, counts), daemon=True).start()


def start(host: str, port: int, counts: Counts) -> tuple[socket.socket, socket.socket]:
    """Listen on UDP and TCP; returns the sockets (port 0: any free one, the same for both)."""
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    u = socket.socket(fam, socket.SOCK_DGRAM)
    u.bind((host, port))
    port = u.getsockname()[1]
    t = socket.socket(fam, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind((host, port))
    t.listen(64)
    threading.Thread(target=serve_udp, args=(u, counts), daemon=True).start()
    threading.Thread(target=serve_tcp, args=(t, counts), daemon=True).start()
    return u, t


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m containerizer.dnsrefuse", description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:5354", help="address:port (UDP and TCP)")
    ap.add_argument("--state", required=True, help="the counts, for Admin -> Firewall -> Refused names")
    a = ap.parse_args(argv)
    host, _, port = a.listen.rpartition(":")
    counts = Counts(Path(a.state))
    start(host.strip("[]"), int(port), counts)
    print(f"refusing on {a.listen}; counts in {a.state}", file=sys.stderr, flush=True)
    while True:
        time.sleep(FLUSH)
        try:
            counts.flush()
        except OSError as ex:
            print(f"state not written: {ex}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    sys.exit(main())
