"""Prometheus metrics of the scan worker: the scans, the worker process and the machine it runs on.

Plain text exposition format 0.0.4 (https://prometheus.io/docs/instrumenting/exposition_formats/),
no client library needed. Process metrics use the standard `process_*` names; machine metrics are
read from /proc and named `containerizer_host_*`, so they do not clash with node_exporter when both
are scraped (docs/scheduled-scans.md#metrics).
"""
from __future__ import annotations

import hmac
import math
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")


def _esc(v) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _num(v: float) -> str:
    if v is None:
        return "NaN"
    if isinstance(v, float):
        if math.isinf(v):
            return "+Inf" if v > 0 else "-Inf"
        if math.isnan(v):
            return "NaN"
        return repr(v)
    return str(v)


def _labels(names: tuple, values: tuple, extra: str = "") -> str:
    parts = [f'{n}="{_esc(v)}"' for n, v in zip(names, values)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


class _Metric:
    kind = "untyped"

    def __init__(self, name: str, help: str, labels: tuple = ()):
        if not _NAME.fullmatch(name):
            raise ValueError(name)
        self.name, self.help, self.labelnames = name, help, tuple(labels)
        self._values: dict = {}
        self._lock = threading.Lock()

    def _key(self, labels: dict) -> tuple:
        if set(labels) != set(self.labelnames):
            raise ValueError(f"{self.name}: labels {sorted(labels)} != {sorted(self.labelnames)}")
        return tuple(str(labels[n]) for n in self.labelnames)

    def header(self) -> list[str]:
        return [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]

    def lines(self) -> list[str]:
        with self._lock:
            items = sorted(self._values.items())
        return [f"{self.name}{_labels(self.labelnames, k)} {_num(v)}" for k, v in items]

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


class Counter(_Metric):
    kind = "counter"

    def inc(self, amount: float = 1, **labels) -> None:
        k = self._key(labels)
        with self._lock:
            self._values[k] = self._values.get(k, 0) + amount


class Gauge(_Metric):
    kind = "gauge"

    def set(self, value: float, **labels) -> None:
        k = self._key(labels)
        with self._lock:
            self._values[k] = value

    def remove(self, **labels) -> None:
        with self._lock:
            self._values.pop(self._key(labels), None)

    def replace(self, rows: dict) -> None:
        """Set every series at once (label tuple -> value); series not in `rows` disappear."""
        with self._lock:
            self._values = {tuple(str(x) for x in k): v for k, v in rows.items()}


class Histogram(_Metric):
    kind = "histogram"

    def __init__(self, name: str, help: str, labels: tuple = (), buckets: tuple = ()):
        super().__init__(name, help, labels)
        self.buckets = tuple(sorted(buckets))

    def observe(self, value: float, **labels) -> None:
        k = self._key(labels)
        with self._lock:
            counts, total = self._values.get(k, ([0] * len(self.buckets), [0, 0.0]))
            for i, b in enumerate(self.buckets):
                if value <= b:
                    counts[i] += 1
            total[0] += 1
            total[1] += value
            self._values[k] = (counts, total)

    def lines(self) -> list[str]:
        with self._lock:
            items = sorted((k, (list(c), list(t))) for k, (c, t) in self._values.items())
        out = []
        for k, (counts, (n, s)) in items:
            for b, c in zip(self.buckets, counts):
                le = 'le="' + _num(float(b)) + '"'
                out.append(f"{self.name}_bucket{_labels(self.labelnames, k, le)} {c}")
            inf = 'le="+Inf"'
            out.append(f"{self.name}_bucket{_labels(self.labelnames, k, inf)} {n}")
            out.append(f"{self.name}_sum{_labels(self.labelnames, k)} {_num(float(s))}")
            out.append(f"{self.name}_count{_labels(self.labelnames, k)} {n}")
        return out


class Registry:
    def __init__(self):
        self.metrics: list[_Metric] = []
        self.collectors: list = []          # () -> list[_Metric] made fresh at every scrape

    def add(self, m: _Metric) -> _Metric:
        self.metrics.append(m)
        return m

    def counter(self, name, help, labels=()) -> Counter:
        return self.add(Counter(name, help, labels))

    def gauge(self, name, help, labels=()) -> Gauge:
        return self.add(Gauge(name, help, labels))

    def histogram(self, name, help, labels=(), buckets=()) -> Histogram:
        return self.add(Histogram(name, help, labels, buckets))

    def render(self) -> str:
        out = []
        ms = list(self.metrics)
        for c in self.collectors:
            try:
                ms += c()
            except Exception as ex:          # a broken collector must not take the endpoint down
                print(f"metrics: collector failed: {type(ex).__name__}: {ex}", file=sys.stderr)
        for m in ms:
            out += m.header() + m.lines()
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- process and host

def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def process_metrics() -> list[_Metric]:
    """The standard process_* metrics (as the official client libraries export them)."""
    out = []
    t = os.times()
    g = Counter("process_cpu_seconds_total", "Total user and system CPU time spent in seconds.")
    g.inc(t.user + t.system)
    out.append(g)
    ch = Counter("containerizer_process_children_cpu_seconds_total",
                 "CPU time of finished child processes (git, docker CLI, scanners) in seconds.")
    ch.inc(t.children_user + t.children_system)
    out.append(ch)
    stat = _read("/proc/self/stat")
    if stat:
        f = stat.rsplit(")", 1)[1].split()
        page = os.sysconf("SC_PAGE_SIZE")
        tick = os.sysconf("SC_CLK_TCK")
        vm = Gauge("process_virtual_memory_bytes", "Virtual memory size in bytes.")
        vm.set(int(f[20]))
        rss = Gauge("process_resident_memory_bytes", "Resident memory size in bytes.")
        rss.set(int(f[21]) * page)
        btime = next((int(x.split()[1]) for x in _read("/proc/stat").splitlines() if x.startswith("btime ")), 0)
        st = Gauge("process_start_time_seconds", "Start time of the process since unix epoch in seconds.")
        st.set(btime + int(f[19]) / tick)
        th = Gauge("process_threads", "Number of OS threads in the process.")
        th.set(int(f[17]))
        out += [vm, rss, st, th]
        try:
            fds = Gauge("process_open_fds", "Number of open file descriptors.")
            fds.set(len(os.listdir("/proc/self/fd")))
            out.append(fds)
        except OSError:
            pass
        for line in _read("/proc/self/limits").splitlines():
            if line.startswith("Max open files"):
                mx = Gauge("process_max_fds", "Maximum number of open file descriptors.")
                mx.set(int(line.split()[3]) if line.split()[3].isdigit() else float("inf"))
                out.append(mx)
    return out


CPU_MODES = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
_DISK = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)$")
_VIRTUAL_NIC = re.compile(r"^(lo|veth|docker|br-|virbr|cni|flannel|cali|vxlan|tun|tap|ifb)")


def host_metrics(paths: dict | None = None) -> list[_Metric]:
    """The machine the worker runs on, from /proc (inside a container /proc shows the host's CPU,
    memory, disks and network, which is what a build VM needs watching for). `paths`: name -> folder
    whose file system is reported (work and cache folder, Docker's data root)."""
    out = []
    cpus = Gauge("containerizer_host_cpus", "Number of logical CPUs.")
    cpus.set(os.cpu_count() or 0)
    out.append(cpus)
    stat = _read("/proc/stat")
    tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    if stat:
        line = next((x for x in stat.splitlines() if x.startswith("cpu ")), "")
        vals = line.split()[1:]
        c = Counter("containerizer_host_cpu_seconds_total", "CPU time of all CPUs by mode, in seconds.", ("mode",))
        for mode, v in zip(CPU_MODES, vals):
            c.inc(int(v) / tick, mode=mode)
        out.append(c)
        bt = next((int(x.split()[1]) for x in stat.splitlines() if x.startswith("btime ")), None)
        if bt:
            b = Gauge("containerizer_host_boot_time_seconds", "Boot time of the machine, unix epoch seconds.")
            b.set(bt)
            out.append(b)
    try:
        l1, l5, l15 = os.getloadavg()
        for n, v in (("1", l1), ("5", l5), ("15", l15)):
            g = Gauge(f"containerizer_host_load{n}", f"{n}-minute load average.")
            g.set(v)
            out.append(g)
    except OSError:
        pass
    mem = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, rest = line.partition(":")
        p = rest.split()
        if p and p[0].isdigit():
            mem[k] = int(p[0]) * (1024 if len(p) > 1 and p[1] == "kB" else 1)
    for key, name, help in (("MemTotal", "memory_total_bytes", "Total memory."),
                            ("MemAvailable", "memory_available_bytes", "Memory available for new work, without swapping."),
                            ("SwapTotal", "swap_total_bytes", "Total swap."), ("SwapFree", "swap_free_bytes", "Free swap.")):
        if key in mem:
            g = Gauge(f"containerizer_host_{name}", help + " In bytes.")
            g.set(mem[key])
            out.append(g)
    if paths:
        size = Gauge("containerizer_host_filesystem_size_bytes", "Size of the file system holding the folder.", ("path", "use"))
        avail = Gauge("containerizer_host_filesystem_avail_bytes", "Space available to the worker on that file system.",
                      ("path", "use"))
        files = Gauge("containerizer_host_filesystem_files_free", "Free inodes on that file system.", ("path", "use"))
        for use, p in paths.items():
            try:
                s = os.statvfs(p)
            except OSError:
                continue
            size.set(s.f_blocks * s.f_frsize, path=p, use=use)
            avail.set(s.f_bavail * s.f_frsize, path=p, use=use)
            files.set(s.f_favail, path=p, use=use)
        out += [size, avail, files]
    rd = Counter("containerizer_host_disk_read_bytes_total", "Bytes read from the disk.", ("device",))
    wr = Counter("containerizer_host_disk_written_bytes_total", "Bytes written to the disk.", ("device",))
    io = Counter("containerizer_host_disk_io_time_seconds_total", "Time the disk was busy, in seconds.", ("device",))
    for line in _read("/proc/diskstats").splitlines():
        f = line.split()
        if len(f) >= 14 and _DISK.match(f[2]):
            rd.inc(int(f[5]) * 512, device=f[2])
            wr.inc(int(f[9]) * 512, device=f[2])
            io.inc(int(f[12]) / 1000, device=f[2])
    out += [rd, wr, io]
    rx = Counter("containerizer_host_network_receive_bytes_total", "Bytes received by the network interface.", ("device",))
    tx = Counter("containerizer_host_network_transmit_bytes_total", "Bytes sent by the network interface.", ("device",))
    for line in _read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name, f = name.strip(), rest.split()
        if len(f) >= 9 and not _VIRTUAL_NIC.match(name):
            rx.inc(int(f[0]), device=name)
            tx.inc(int(f[8]), device=name)
    out += [rx, tx]
    return out


# --------------------------------------------------------------------------- endpoint

def serve(registry: Registry, host: str = "127.0.0.1", port: int = 9464, token: str | None = None):
    """GET /metrics (and /healthz) in a background thread. With `token`, scrapes must send
    `Authorization: Bearer <token>` (Prometheus: `authorization: {credentials_file: ...}`)."""

    class H(BaseHTTPRequestHandler):
        def version_string(self):
            return "containerizer"

        def log_message(self, *a):
            pass

        def _send(self, status: int, body: str, ctype: str = "text/plain; charset=utf-8", extra=()):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                return self._send(200, "ok\n")
            if path != "/metrics":
                return self._send(404, "not found\n")
            if token:
                got = self.headers.get("Authorization", "")
                if not hmac.compare_digest(got.encode(), f"Bearer {token}".encode()):
                    return self._send(401, "unauthorized\n", extra=[("WWW-Authenticate", "Bearer")])
            return self._send(200, registry.render(), CONTENT_TYPE)

        do_HEAD = do_GET

    httpd = ThreadingHTTPServer((host, port), H)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, name="metrics", daemon=True).start()
    return httpd


def now() -> float:
    return time.time()
