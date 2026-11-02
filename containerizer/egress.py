"""Egress: what the sandbox's NetworkPolicies block, reviewed, approved by people, written to the output
repository (docs/egress.md).

The generator writes a default-deny NetworkPolicy per component that opens egress only on ports it can infer
(harden.egress_for). A dependency it cannot infer, an HTTPS API from a configured URL for example, is blocked
in the sandbox: the call times out. Three parts close that gap; agents only propose, people approve.

1. **The observer** (`containerizer egress-observe`, `Observer`; deterministic, on the sandbox node). kube-router
   logs every packet a NetworkPolicy drops to NFLOG group 100 (nflog.py), at most 10 a minute per policy. The
   observer reads them, keeps the drops whose source is a pod of the namespace (egress; a drop of a pod's
   incoming traffic is not an application's dependency), names the destination with the FQDN a pod of that
   namespace looked up just before (CoreDNS query log, `log` in the coredns-custom ConfigMap, matched by
   resolving the names it saw), and adds them up per namespace, component, destination, port and protocol in
   cz.EgressFlow (RecordEgressFlow) every minute. A destination without a name stays an IP address.
2. **The egress review** (LLM queue kind `egress`, `handler`). The queue runner (`housekeep`) looks for new flows
   of applications rated A that run in the sandbox (and of "Make it A" variants). A deterministic pre-filter
   (`prefilter`) decides first and is never overruled: IP addresses without a name, metadata endpoints and the
   blocked ranges, wildcards, paste, file-sharing and tunnelling services, the cloud platform's own services and
   the platform's namespaces are reported or suspicious, never proposed. The rest is one job per application
   (the approval policy of the queue applies): the LLM sees each destination with its flows and the lines of the
   assessed commit's source that name it (the source is loaded as refactor.py loads it), and answers per
   destination: propose, report or suspicious, with the file and line that names it and why. The quoted line is
   checked against the source; an answer that quotes nothing real proposes only a steady flow.
3. **Approval and delivery.** Administrators, operators and the application's product owners approve or reject a
   proposal (results page, Admin → Egress). The runner, which holds the output repository's write token, writes
   the application's connectivity.yaml, CONNECTIVITY.md and connectivity.svg (connectivity.py) and opens the
   approved port in the component's NetworkPolicy, in one commit; Flux applies it. Later scans keep the approved
   entries (org.deploy_app). A NetworkPolicy cannot name an FQDN: the port opens to every address but the blocked
   ranges; the FQDN in connectivity.yaml is for the production firewall.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time as _time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

KIND = "egress"
FEATURE = "egress-queued"
PRIORITY = 900                          # after people's refactoring orders, before second-opinion reviews
FLUSH_SECONDS = 60
DNS_WINDOW = 600                        # seconds a looked-up name may explain a later connection
RESOLVE_TTL = 120
PODS_TTL = 30
MAX_PER_CALL = 10                       # destinations per LLM call
MAX_HITS = 6                            # source lines per destination
REQUEUE_DAYS = 7                        # a review that failed or was skipped is not queued again for this long
OUTPUT_REPO_ENV = "CONTAINERIZER_EGRESS_OUTPUT_REPO"        # lab / command line: the output repository
OUTPUT_USER_ENV = "CONTAINERIZER_EGRESS_OUTPUT_USERNAME"
OUTPUT_BRANCH_ENV = "CONTAINERIZER_EGRESS_OUTPUT_BRANCH"
OUTPUT_TOKEN_ENV = "CONTAINERIZER_EGRESS_OUTPUT_TOKEN_ENV"  # the variable that holds its token (OUTPUT_GIT_TOKEN)
LOCAL_SOURCES_ENV = "CONTAINERIZER_EGRESS_SOURCES"          # lab only: folders of checkouts named after the apps
VERDICTS = ("propose", "report", "suspicious", "platform", "unnamed", "in-cluster")
VERDICT_STATUS = {"propose": "proposed", "report": "reported", "suspicious": "suspicious", "platform": "reported",
                  "unnamed": "reported", "in-cluster": "reported"}
STATUS_TEXT = {"proposed": "Proposed", "reported": "Reported", "suspicious": "Suspicious", "approved": "Approved",
               "rejected": "Rejected"}
CATEGORY_TEXT = {"ip-literal": "an IP address no pod looked up by name", "metadata": "a metadata endpoint or blocked range",
                 "wildcard": "a wildcard name", "file-sharing": "a paste, file-sharing, tunnelling or request-capture service",
                 "platform-service": "a service of the cloud platform", "platform-namespace": "the platform's own namespace",
                 "in-cluster": "an address inside the cluster", "unusual-port": "a port the review does not propose",
                 "no-port": "a packet without a port"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def review_settings() -> dict:
    from .harden import security
    net = security()["network"]
    cfg = dict(net.get("egress_review") or {})
    cfg["blocked_cidrs"] = list(net.get("blocked_cidrs") or [])
    return cfg


def _rx_list(xs) -> re.Pattern | None:
    xs = [x for x in xs or [] if x]
    return re.compile(r"(?i)^(?:.*\.)?(?:" + "|".join(f"(?:{x})" for x in xs) + r")\.?$") if xs else None


def _in(ip: str, cidrs) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if a in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def platform_namespace(ns: str, cfg: dict | None = None) -> bool:
    cfg = cfg if cfg is not None else review_settings()
    return any(re.fullmatch(p, ns or "") for p in cfg.get("platform_namespaces") or [])


# --------------------------------------------------------------------------- the deterministic pre-filter

def prefilter(flow: dict, cfg: dict | None = None) -> tuple[str, str, str] | None:
    """(verdict, category, reason) for a flow the review never proposes, else None (the LLM is asked).
    `flow`: Namespace, Destination, Named, DestinationIp, Port, Protocol."""
    cfg = cfg if cfg is not None else review_settings()
    dest = str(flow.get("Destination") or "").lower().rstrip(".")
    ip = str(flow.get("DestinationIp") or (dest if not flow.get("Named") else "") or "")
    port = int(flow.get("Port") or 0)
    if platform_namespace(flow.get("Namespace") or "", cfg):
        return "platform", "platform-namespace", f"{flow.get('Namespace')} is a namespace of the platform, not of an application"
    blocked = list(cfg.get("blocked_cidrs") or []) + ["169.254.0.0/16", "fe80::/10"]
    if ip and _in(ip, blocked):
        return "suspicious", "metadata", f"{ip} is a metadata endpoint or a blocked range: never reachable from applications"
    if not flow.get("Named"):
        if _in(ip or dest, cfg.get("cluster_cidrs")):
            return "in-cluster", "in-cluster", (f"{dest} is a pod or service address of the cluster: a call to another "
                                                "namespace, not egress (allow it with a NetworkPolicy to that namespace)")
        return "unnamed", "ip-literal", (f"{dest} was not looked up by name by a pod of this namespace: an IP address "
                                         "gets no rule (name it in the configuration)")
    if "*" in dest:
        return "suspicious", "wildcard", f"{dest} is a wildcard"
    if dest.endswith(".cluster.local") or dest.endswith(".svc"):
        return "in-cluster", "in-cluster", (f"{dest} is a component inside the cluster: link it (links between "
                                            "applications), it is not egress")
    sus = _rx_list(cfg.get("suspicious_domains"))
    if sus and sus.match(dest):
        return "suspicious", "file-sharing", (f"{dest} is a paste, file-sharing, tunnelling or request-capture service: "
                                              "data can leave through it")
    plat = _rx_list(cfg.get("platform_domains"))
    if plat and plat.match(dest):
        return "platform", "platform-service", f"{dest} is a service of the cloud platform: the platform team decides"
    if not port:
        return "unnamed", "no-port", f"{flow.get('Protocol')} to {dest} has no port"
    if cfg.get("ports") and port not in [int(p) for p in cfg["ports"]]:
        return "report", "unusual-port", f"port {port} is not one the review proposes: a person decides"
    return None


# --------------------------------------------------------------------------- the observer: CoreDNS

DNS_LOG_RE = re.compile(r"\[INFO\]\s+(?P<ip>\[[0-9a-fA-F:.]+\]|[0-9.]+):\d+\s+-\s+\d+\s+\""
                        r"(?P<type>[A-Z0-9]+)\s+IN\s+(?P<name>\S+?)\.?\s+(?:udp|tcp)\b[^\"]*\"\s+(?P<rcode>[A-Z]+)")


def parse_dns_line(line: str) -> tuple[str, str, str, str] | None:
    """(client IP, name, type, rcode) of a CoreDNS `log` line, e.g.
    `[INFO] 10.42.0.15:43210 - 12345 "A IN api.github.com. udp 32 false 512" NOERROR qr,rd,ra 98 0.012s`."""
    m = DNS_LOG_RE.search(line)
    if not m:
        return None
    return m["ip"].strip("[]"), m["name"].lower().rstrip("."), m["type"], m["rcode"]


def external_name(name: str) -> bool:
    """A name a pod looked up that can be a destination outside the cluster."""
    return bool(name) and "." in name and not re.search(r"(\.cluster\.local|\.svc|\.in-addr\.arpa|\.ip6\.arpa|\.local)$", name)


def dns_query(server: str, name: str, qtype: int = 1, timeout: float = 2.0) -> list[str]:
    """Addresses of `name` (A: 1, AAAA: 28) from one DNS server over UDP: a small client, so the observer asks the
    cluster's DNS (what the pods were answered) rather than the host's resolver."""
    qid = int.from_bytes(os.urandom(2), "big")
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode("idna")
    q += b"\0" + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        data = s.recv(4096)
    return parse_dns_answer(data, qid)


def parse_dns_answer(data: bytes, qid: int | None = None) -> list[str]:
    if len(data) < 12:
        return []
    rid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    if (qid is not None and rid != qid) or flags & 0x000F:
        return []

    def skip_name(i):
        while i < len(data):
            n = data[i]
            if n == 0:
                return i + 1
            if n & 0xC0 == 0xC0:
                return i + 2
            i += n + 1
        return i
    i = 12
    for _ in range(qd):
        i = skip_name(i) + 4
    out = []
    for _ in range(an):
        i = skip_name(i)
        if i + 10 > len(data):
            break
        typ, _cls, _ttl, ln = struct.unpack_from("!HHIH", data, i)
        i += 10
        rd = data[i:i + ln]
        i += ln
        if typ == 1 and ln == 4:
            out.append(str(ipaddress.IPv4Address(rd)))
        elif typ == 28 and ln == 16:
            out.append(str(ipaddress.IPv6Address(rd)))
    return out


class Resolver:
    """Names to addresses, cached for RESOLVE_TTL: the cluster's DNS server when given, else the host's."""

    def __init__(self, server: str | None = None, ttl: int = RESOLVE_TTL, clock=_time.monotonic):
        self.server, self.ttl, self.clock = server, ttl, clock
        self.cache: dict[str, tuple[float, set]] = {}

    def lookup(self, name: str) -> set:
        hit = self.cache.get(name)
        if hit and self.clock() - hit[0] < self.ttl:
            return hit[1]
        ips: set = set()
        try:
            if self.server:
                for t in (1, 28):
                    ips |= set(dns_query(self.server, name, t))
            else:
                ips = {ai[4][0] for ai in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)}
        except (OSError, UnicodeError):
            ips = set()
        if len(self.cache) > 5000:
            self.cache.clear()
        self.cache[name] = (self.clock(), ips)
        return ips


class DnsMemory:
    """The external names each pod address looked up lately."""

    def __init__(self, window: int = DNS_WINDOW, clock=_time.monotonic):
        self.window, self.clock = window, clock
        self.by_client: dict[str, deque] = {}
        self.lock = threading.Lock()

    def add(self, client: str, name: str) -> None:
        now = self.clock()
        with self.lock:
            q = self.by_client.setdefault(client, deque(maxlen=200))
            q.append((now, name))
            if len(self.by_client) > 20000:
                self.by_client.clear()

    def names(self, clients) -> list[str]:
        """Names the given client addresses looked up within the window, newest first, without duplicates."""
        now = self.clock()
        out: list[str] = []
        with self.lock:
            for c in clients:
                for t, n in reversed(self.by_client.get(c, ())):
                    if now - t <= self.window and n not in out:
                        out.append(n)
        return out


def name_for(dst: str, src: str, namespace_ips, memory: DnsMemory, resolver: Resolver) -> str | None:
    """The FQDN that a pod of the namespace looked up shortly before and that resolves to `dst`: the source pod's
    own lookups first, then the namespace's other pods'."""
    for clients in ([src], [ip for ip in namespace_ips if ip != src]):
        for n in memory.names(clients):
            if dst in resolver.lookup(n):
                return n
    return None


# --------------------------------------------------------------------------- the observer: pods, flows

class Pods:
    """Pod addresses of a namespace -> (pod, component), from the Kubernetes API (namespace-scoped list)."""

    def __init__(self, kube, ttl: int = PODS_TTL, clock=_time.monotonic):
        self.kube, self.ttl, self.clock = kube, ttl, clock
        self.cache: dict[str, tuple[float, dict]] = {}

    def of(self, ns: str, need: str | None = None) -> dict:
        hit = self.cache.get(ns)
        now = self.clock()
        if hit and (now - hit[0] < self.ttl) and (need is None or need in hit[1] or now - hit[0] < 5):
            return hit[1]
        ips: dict = {}
        try:
            for p in self.kube.get("pods", ns).get("items") or []:
                meta, st = p.get("metadata") or {}, p.get("status") or {}
                if (p.get("spec") or {}).get("hostNetwork"):
                    continue            # its address is the node's: the drop cannot name an application
                comp = (meta.get("labels") or {}).get("app.kubernetes.io/name") or ""
                for a in [st.get("podIP")] + [x.get("ip") for x in st.get("podIPs") or []]:
                    if a:
                        ips[a] = (meta.get("name") or "", comp)
        except Exception:  # noqa: BLE001 - the API was away: keep the last answer
            ips = hit[1] if hit else {}
        self.cache[ns] = (now, ips)
        return ips


@dataclass
class Flow:
    namespace: str
    component: str
    destination: str
    named: bool
    port: int
    protocol: str
    packets: int = 0
    first: datetime | None = None
    last: datetime | None = None
    ip: str | None = None
    pods: dict = field(default_factory=dict)
    policy: str | None = None

    def key(self) -> tuple:
        return (self.namespace, self.component, self.destination, self.port, self.protocol)


class Aggregator:
    def __init__(self):
        self.flows: dict[tuple, Flow] = {}
        self.lock = threading.Lock()
        self.stats = {"drops": 0, "egress": 0, "ingress": 0, "named": 0, "platform": 0}

    def add(self, ns, comp, dest, named, port, proto, ip, pod, src, policy, when: datetime) -> Flow:
        k = (ns, comp, dest, int(port or 0), proto)
        with self.lock:
            f = self.flows.get(k)
            if f is None:
                f = self.flows[k] = Flow(ns, comp, dest, named, int(port or 0), proto, first=when)
            f.packets += 1
            f.last = when
            f.ip = ip
            f.policy = policy
            if pod and pod not in f.pods and len(f.pods) < 5:
                f.pods[pod] = src
            return f

    def take(self) -> list[Flow]:
        with self.lock:
            out = list(self.flows.values())
            self.flows.clear()
        return out


def record(conn, flows: list[Flow], observer: str) -> int:
    """Add flows to cz.EgressFlow (RecordEgressFlow adds the counts up)."""
    cur = conn.cursor()
    n = 0
    for f in flows:
        cur.execute("EXEC cz.RecordEgressFlow @Namespace = %s, @Component = %s, @Destination = %s, @Named = %s, "
                    "@DestinationIp = %s, @Port = %s, @Protocol = %s, @Packets = %s, @FirstSeen = %s, @LastSeen = %s, "
                    "@Pods = %s, @Policy = %s, @Observer = %s",
                    (f.namespace[:63], (f.component or "")[:63], f.destination[:253], 1 if f.named else 0,
                     (f.ip or None) and f.ip[:45], f.port, f.protocol[:10], f.packets,
                     f.first.replace(tzinfo=None), f.last.replace(tzinfo=None),
                     json.dumps([{"pod": p, "ip": ip} for p, ip in f.pods.items()])[:2000] if f.pods else None,
                     (f.policy or None) and f.policy[:253], observer[:256]))
        n += 1
    conn.commit()
    return n


class Observer:
    """`containerizer egress-observe`: NFLOG drops + CoreDNS lookups -> cz.EgressFlow."""

    def __init__(self, kube, connect=None, resolver: Resolver | None = None, name: str | None = None,
                 log=None, flush: int = FLUSH_SECONDS, cfg: dict | None = None, out=None):
        self.kube = kube
        self.connect = connect                  # () -> sqlstore connection of a writer; None: print only
        self.resolver = resolver or Resolver()
        self.memory = DnsMemory()
        self.pods = Pods(kube)
        self.agg = Aggregator()
        self.name = name or f"{socket.gethostname()}-egress-observer"
        self.log = log or (lambda m: print(f"egress-observe: {m}", file=sys.stderr, flush=True))
        self.flush_every = flush
        self.cfg = cfg if cfg is not None else review_settings()
        self.out = out                          # dry run: print each flow here
        self.stopping = threading.Event()
        self._namespaces: tuple[float, list] = (-1e9, [])

    def app_namespaces(self) -> list[str]:
        """The sandbox namespaces of applications (cz.vSandboxNamespace, refreshed every 5 minutes): where an
        in-cluster destination address is looked for."""
        if self.connect is None or _time.monotonic() - self._namespaces[0] < 300:
            return self._namespaces[1] or list(self.pods.cache)
        try:
            conn = self.connect()
            try:
                cur = conn.cursor()
                cur.execute("SELECT DISTINCT Namespace FROM cz.vSandboxNamespace")
                nss = [r[0] for r in cur.fetchall() if r[0]]
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - keep the last list
            nss = self._namespaces[1]
        self._namespaces = (_time.monotonic(), nss)
        return nss

    def in_cluster_name(self, dst: str, own: str) -> str | None:
        """`<component>.<namespace>.svc.cluster.local` when `dst` is a pod of another application's namespace (a
        call to another application, links.py), else None."""
        if not _in(dst, self.cfg.get("cluster_cidrs")):
            return None
        for ns in self.app_namespaces():
            if ns == own or platform_namespace(ns, self.cfg):
                continue
            hit = self.pods.of(ns, dst).get(dst)
            if hit and hit[1]:
                return f"{hit[1]}.{ns}.svc.cluster.local"
        return None

    # CoreDNS
    def dns_line(self, line: str) -> None:
        q = parse_dns_line(line)
        if q and q[3] == "NOERROR" and q[2] in ("A", "AAAA") and external_name(q[1]):
            self.memory.add(q[0], q[1])

    def follow_dns(self) -> None:
        """kubectl logs -f of CoreDNS (read-only, kube-system); reconnects when the stream ends."""
        while not self.stopping.is_set():
            # a stream: without kubectl's request timeout, which would end it after 20 seconds
            base = [x for x in self.kube._base() if not x.startswith("--request-timeout")]
            cmd = base + ["logs", "-n", "kube-system", "-l", "k8s-app=kube-dns", "-f", "--tail=0",
                          "--max-log-requests=5", "--since=10s", "--ignore-errors"]
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
                                     stdin=subprocess.DEVNULL)
            except OSError as ex:
                self.log(f"CoreDNS log: {ex}")
                self.stopping.wait(30)
                continue
            for line in p.stdout:
                self.dns_line(line)
                if self.stopping.is_set():
                    break
            p.kill()
            err = (p.stderr.read() or "").strip()[-300:]
            if err:
                self.log(f"CoreDNS log stream ended: {err}")
            self.stopping.wait(5)

    # NFLOG
    def drop(self, d, when: datetime | None = None) -> Flow | None:
        """One dropped packet; returns the flow it was added to (None: not an application's egress)."""
        when = when or utcnow()
        self.agg.stats["drops"] += 1
        if platform_namespace(d.namespace, self.cfg):
            self.agg.stats["platform"] += 1
            return None
        if (d.dport or 0) == 53 and _in(d.dst, self.cfg.get("cluster_cidrs")):
            # cluster DNS: every generated NetworkPolicy allows it, so a drop is kube-router's ipsets catching up
            # with a pod that just started (seen in the lab), not something the application needs
            self.agg.stats["dns"] = self.agg.stats.get("dns", 0) + 1
            return None
        pods = self.pods.of(d.namespace, d.src)
        if d.src not in pods:
            self.agg.stats["ingress"] += 1      # the pod is the destination: incoming traffic, not egress
            return None
        pod, comp = pods[d.src]
        name = self.in_cluster_name(d.dst, d.namespace) or name_for(d.dst, d.src, list(pods), self.memory, self.resolver)
        if name:
            self.agg.stats["named"] += 1
        self.agg.stats["egress"] += 1
        f = self.agg.add(d.namespace, comp, name or d.dst, bool(name), d.dport or 0, d.protocol, d.dst, pod, d.src,
                         f"{d.namespace}/{d.policy}", when)
        if self.out:
            print(json.dumps({"namespace": d.namespace, "component": comp, "pod": pod, "destination": name or d.dst,
                              "ip": d.dst, "port": d.dport, "protocol": d.protocol}), file=self.out, flush=True)
        return f

    def flush(self) -> int:
        flows = self.agg.take()
        if not flows or self.connect is None:
            return 0
        try:
            conn = self.connect()
            try:
                n = record(conn, flows, self.name)
            finally:
                conn.close()
        except Exception as ex:  # noqa: BLE001 - the database was away: keep the counts for the next flush
            with self.agg.lock:
                for f in flows:
                    self.agg.flows.setdefault(f.key(), f)
            self.log(f"flows not recorded ({len(flows)} kept for the next try): {type(ex).__name__}: {str(ex)[:200]}")
            return 0
        self.log(f"{n} flow(s) recorded; {self.agg.stats}")
        return n

    def run(self, reader) -> None:
        t = threading.Thread(target=self.follow_dns, name="coredns-log", daemon=True)
        t.start()
        last = _time.monotonic()
        try:
            while not self.stopping.is_set():
                for d in reader.read(timeout=5):
                    try:
                        self.drop(d)
                    except Exception as ex:  # noqa: BLE001 - one bad packet must not stop the observer
                        self.log(f"drop not recorded: {type(ex).__name__}: {ex}")
                if _time.monotonic() - last >= self.flush_every:
                    self.flush()
                    last = _time.monotonic()
        finally:
            self.flush()


def observe(args) -> int:
    """The command line: `containerizer egress-observe`."""
    import signal
    from .nflog import GROUP, NflogError, Reader
    from .sandbox import Kube, KubeOptions
    kube = Kube(KubeOptions(kubeconfig=args.kubeconfig or os.environ.get("CONTAINERIZER_EGRESS_KUBECONFIG"),
                            context=args.context))
    connect = None
    if not args.dry_run:
        from .sqlstore import connect as sql_connect
        cs = args.sql or os.environ.get("CONTAINERIZER_SQL")
        if not cs:
            print("error: --sql or CONTAINERIZER_SQL (a writer login), or --dry-run", file=sys.stderr)
            return 2
        connect = lambda: sql_connect(cs)  # noqa: E731
        connect().close()
    obs = Observer(kube, connect, Resolver(args.dns_server or None), name=args.name, flush=args.flush,
                   out=sys.stdout if args.dry_run else None)
    try:
        reader = Reader(args.group or GROUP)
    except (NflogError, PermissionError, OSError) as ex:
        print(f"error: cannot read NFLOG group {args.group or GROUP}: {ex} (needs CAP_NET_ADMIN)", file=sys.stderr)
        return 3

    def stop(signum, frame):
        obs.stopping.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    obs.log(f"reading NFLOG group {reader.group} (NetworkPolicy drops) and the CoreDNS query log"
            + (" (dry run: nothing is stored)" if args.dry_run else ""))
    try:
        if args.seconds:
            threading.Timer(args.seconds, obs.stopping.set).start()
        obs.run(reader)
    finally:
        reader.close()
    return 0


def observer_rbac(namespaces: list[str]) -> list[dict]:
    """What the observer may read: CoreDNS's pods and logs in kube-system, and the pods of the namespaces
    containerizer generated (to tell which pod a source address is). A ServiceAccount of its own in the
    verifier's namespace; no Secrets, no write verbs, nothing cluster-wide."""
    from .sandbox import VERIFIER_NS
    name = "containerizer-egress-observer"
    labels = {"app.kubernetes.io/part-of": "containerizer-sandbox", "app.kubernetes.io/managed-by": "containerizer"}
    subject = [{"kind": "ServiceAccount", "name": name, "namespace": VERIFIER_NS}]
    docs: list[dict] = [{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name, "namespace": VERIFIER_NS,
                                                                                    "labels": labels},
                         "automountServiceAccountToken": False}]
    for ns, rules in [("kube-system", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
                                       {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]}])] + \
            [(ns, [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]) for ns in namespaces]:
        docs += [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                  "metadata": {"name": name, "namespace": ns, "labels": labels}, "rules": rules},
                 {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                  "metadata": {"name": name, "namespace": ns, "labels": labels},
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}, "subjects": subject}]
    return docs


COREDNS_LOG = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "coredns-custom", "namespace": "kube-system"},
               "data": {"log.override": "log\n"}}


# --------------------------------------------------------------------------- the review (LLM queue kind `egress`)

SYSTEM = """You are a platform security engineer who reviews the outbound connections an application's sandbox
blocked. You decide for each destination whether a rule should be proposed to the people who approve egress. You
only propose: people approve. You answer only with JSON matching the requested schema."""

SCHEMA = {
    "type": "object", "required": ["destinations"],
    "properties": {"destinations": {"type": "array", "items": {
        "type": "object", "required": ["destination", "port", "verdict", "reason", "file", "line", "quote"],
        "properties": {
            "destination": {"type": "string"}, "port": {"type": "number"},
            "verdict": {"type": "string", "enum": ["propose", "report", "suspicious"]},
            "reason": {"type": "string", "description": "why the application needs it (or why not), one or two sentences"},
            "file": {"type": "string", "description": "the file that names the destination, or empty"},
            "line": {"type": "number", "description": "its line number, or 0"},
            "quote": {"type": "string", "description": "the line exactly as shown, or empty"}}}}},
}


def _text_files(root: Path, limit: int = 4000):
    skip = re.compile(r"(^|/)(\.git|bin|obj|node_modules|dist|build|target|packages|\.vs|wwwroot/lib)(/|$)")
    n = 0
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if skip.search(rel) or not p.is_file() or p.stat().st_size > 300_000:
            continue
        if p.suffix.lower() in (".png", ".jpg", ".gif", ".ico", ".dll", ".exe", ".pdf", ".zip", ".pfx", ".snk", ".woff",
                                ".woff2", ".ttf", ".svg", ".lock"):
            continue
        n += 1
        if n > limit:
            return
        yield p, rel


def source_hits(app_root: Path | None, names: list[str], limit: int = MAX_HITS) -> dict[str, list[dict]]:
    """{name: [{file, line, quote}]}: the lines of the source that name each destination (the full name, else its
    registrable part, e.g. github.com for api.github.com)."""
    out: dict[str, list[dict]] = {n: [] for n in names}
    if app_root is None or not names:
        return out
    pats = {n: [re.compile(re.escape(n), re.I)] + ([re.compile(r"\b" + re.escape(".".join(n.split(".")[-2:])) + r"\b", re.I)]
                                                   if n.count(".") >= 2 else []) for n in names}
    for p, rel in _text_files(app_root):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        low = text.lower()
        for n in names:
            if len(out[n]) >= limit or not any(rx.search(low) for rx in pats[n]):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if any(rx.search(line) for rx in pats[n]):
                    out[n].append({"file": rel, "line": i, "quote": line.strip()[:240]})
                    if len(out[n]) >= limit:
                        break
    return out


def prompt(payload: dict, dests: list[dict], hits: dict, source_note: str) -> str:
    items = []
    for d in dests:
        items.append({"destination": d["destination"], "port": d["port"], "protocol": d["protocol"],
                      "component": d["component"], "dropped_packets": d.get("packets"), "first_seen": d.get("first_seen"),
                      "last_seen": d.get("last_seen"), "pods": d.get("pods") or [],
                      "named_in_source": hits.get(d["destination"]) or []})
    return "\n".join([
        f"Application: {payload.get('app')} (rated A, running in a Kubernetes sandbox with a default-deny "
        "NetworkPolicy per component). These outbound connections were blocked (dropped) in the sandbox. The "
        "destination name is the one a pod of the application looked up just before.",
        source_note,
        "For each destination decide:",
        "- propose: the application's configuration or code names it (quote the file, the line number and the line "
        "exactly as shown under named_in_source), or it is an ordinary public API the application plainly uses and "
        "the flow is steady; say why the application needs it;",
        "- report: nothing explains it, or a person should decide (say what is missing);",
        "- suspicious: it looks like data exfiltration, command and control, a paste or file-sharing site, a tunnel, "
        "or a hard-coded destination unrelated to what the application does.",
        "Never propose something only because it is blocked. A destination named only in code, unrelated to the "
        "application's configured dependencies, is suspicious. Answer for every destination, with file empty, line "
        "0 and quote empty when nothing names it.",
        "Destinations (JSON):",
        json.dumps(items, indent=1, default=str)])


def _verify(answer: dict, hits: list[dict], app_root: Path | None) -> list[dict]:
    """The evidence of an answer when the quoted line is really in the source (the line as it is), else []."""
    f, line, quote = str(answer.get("file") or "").strip(), int(answer.get("line") or 0), str(answer.get("quote") or "")
    norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()  # noqa: E731
    if not f and not quote:
        return []
    for h in hits:
        if (h["file"] == f or h["file"].endswith("/" + f) or f.endswith(h["file"])) and \
                (abs(h["line"] - line) <= 2 or (quote and norm(quote) in norm(h["quote"]) or norm(h["quote"]) in norm(quote))):
            return [{**h, "verified": True}]
    if app_root is not None and f:
        from .refactor import safe_rel
        rel = safe_rel(f)
        p = (app_root / rel) if rel else None
        if p and p.is_file():
            lines = p.read_text(errors="replace").splitlines()
            for i in range(max(1, line - 2), min(len(lines), line + 2) + 1):
                if quote and norm(quote) and norm(quote) in norm(lines[i - 1]):
                    return [{"file": rel, "line": i, "quote": lines[i - 1].strip()[:240], "verified": True}]
    return []


def decide(answers: list[dict], dests: list[dict], hits: dict, app_root: Path | None, min_packets: int = 3) -> list[dict]:
    """One decision per destination from the LLM's answers, checked: a quoted line must be in the source; a
    proposal without such a line needs a steady flow (at least `min_packets` dropped), else it is reported."""
    by = {(str(a.get("destination") or "").lower().rstrip("."), int(a.get("port") or 0)): a for a in answers
          if isinstance(a, dict)}
    out = []
    for d in dests:
        a = by.get((d["destination"].lower(), int(d["port"]))) or by.get((d["destination"].lower(), 0))
        if a is None:
            out.append({**d, "verdict": "report", "reason": "the LLM gave no answer for it: a person decides",
                        "evidence": []})
            continue
        verdict = a.get("verdict") if a.get("verdict") in ("propose", "report", "suspicious") else "report"
        reason = str(a.get("reason") or "").strip()[:900]
        ev = _verify(a, hits.get(d["destination"]) or [], app_root)
        if (a.get("file") or a.get("quote")) and not ev:
            reason += " (the quoted line is not in the assessed source)"
        if verdict == "propose" and not ev and int(d.get("packets") or 0) < min_packets:
            verdict = "report"
            reason += " Not proposed: nothing in the source names it and the flow is not steady."
        if not ev:
            ev = [{**h, "verified": True} for h in (hits.get(d["destination"]) or [])[:1]] if verdict == "propose" else []
        out.append({**d, "verdict": verdict, "reason": reason.strip()[:1000], "evidence": ev})
    return out


def insert_decisions(conn, app_id: int, rows: list[dict], job_id: int | None) -> int:
    """New EgressDecision rows (an existing one for the same destination stays as it is)."""
    cur = conn.cursor()
    n = 0
    for r in rows:
        cur.execute("IF NOT EXISTS (SELECT 1 FROM cz.EgressDecision WHERE ApplicationId = %s AND Component = %s AND "
                    "Destination = %s AND Port = %s AND Protocol = %s) "
                    "INSERT cz.EgressDecision (ApplicationId, Namespace, Component, Destination, Port, Protocol, Verdict, "
                    "Status, Category, Reason, Evidence, Flows, JobId) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (app_id, r["component"], r["destination"][:253], int(r["port"]), r["protocol"],
                     app_id, r.get("namespace", "")[:63], r["component"][:63], r["destination"][:253], int(r["port"]),
                     r["protocol"][:10], r["verdict"], VERDICT_STATUS[r["verdict"]], r.get("category"),
                     (r.get("reason") or "")[:1000], json.dumps(r.get("evidence") or []),
                     json.dumps({k: r.get(k) for k in ("packets", "first_seen", "last_seen", "pods", "ips", "namespace")},
                                default=str), job_id))
        n += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    conn.commit()
    return n


def load_source(payload: dict, work: Path) -> tuple[Path | None, str]:
    """The application's folder at the assessed commit (as refactor.py loads it), or None with why not."""
    from . import refactor as rf
    src = payload.get("source")
    if not src:
        return None, ("The application's source is not available here: judge from the destination, the flows and the "
                      "lines the assessment recorded (named_in_source).")
    try:
        _, app_root = rf.checkout(src, payload.get("commit"), work / "src")
        return app_root, "The lines under named_in_source are from the application's source at the assessed commit."
    except rf.RefactorError as ex:
        return None, f"The source could not be loaded ({str(ex)[:200]}): judge from the lines the assessment recorded."


def handler(job: dict, ask=None) -> dict:
    """The LLM queue's handler of `egress` jobs: one call per MAX_PER_CALL destinations; the decisions are
    written to cz.EgressDecision (when the job came from the database)."""
    from . import ai
    pl = job["Payload"]
    ask = ask or (lambda p: ai.ask_json(p, SCHEMA, feature=FEATURE, system=SYSTEM, max_tokens=ai.SHORT_ANSWER_TOKENS))
    progress = job.get("_progress") or (lambda text: None)
    base = Path(os.environ.get("CONTAINERIZER_REFACTOR_WORK") or tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"egress-{int(job.get('JobId') or 0)}-", dir=base))
    try:
        app_root, note = load_source(pl, work)
        dests = list(pl.get("destinations") or [])
        hits = source_hits(app_root, sorted({d["destination"] for d in dests}))
        for d in dests:                         # what the assessment recorded, when the source is not here
            if not hits.get(d["destination"]):
                hits[d["destination"]] = [x for x in pl.get("named") or [] if x.get("host") == d["destination"]][:MAX_HITS]
        decisions, calls = [], 0
        for i in range(0, len(dests), MAX_PER_CALL):
            chunk = dests[i:i + MAX_PER_CALL]
            progress(f"reviewing destinations {i + 1}-{i + len(chunk)} of {len(dests)}")
            ans = ask(prompt(pl, chunk, hits, note))
            calls += 1
            decisions += decide(ans.get("destinations") or [], chunk, hits, app_root)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    written = 0
    if job.get("_connect") and pl.get("application_id"):
        conn = job["_connect"]()
        try:
            written = insert_decisions(conn, int(pl["application_id"]), decisions, int(job.get("JobId") or 0) or None)
        finally:
            conn.close()
    counts: dict[str, int] = {}
    for d in decisions:
        counts[VERDICT_STATUS[d["verdict"]]] = counts.get(VERDICT_STATUS[d["verdict"]], 0) + 1
    summary = f"{len(decisions)} destination(s): " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    return {"result": {"decisions": decisions, "calls": calls, "written": written, "source": "checkout" if app_root else "assessment"},
            "summary": summary, "note": None if app_root else note[:400]}


# --------------------------------------------------------------------------- queueing (the runner's housekeeping)

def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def new_flows(conn) -> list[dict]:
    """Flows of applications rated A (or "Make it A" variants) running in the sandbox, without a decision."""
    return _rows(conn, "SELECT f.*, a.ApplicationName, a.Rating, a.AssessmentId, a.SourceCommit, a.RepositoryUrl, "
                       "a.SourcePath, n.Status AS NamespaceStatus FROM cz.vEgressFlow f "
                       "JOIN cz.vSandboxNamespace n ON n.Namespace = f.Namespace "
                       "JOIN cz.vApplicationLatest a ON a.ApplicationId = f.ApplicationId "
                       "WHERE NOT EXISTS (SELECT 1 FROM cz.EgressDecision d WHERE d.ApplicationId = f.ApplicationId "
                       "AND d.Component = f.Component AND d.Destination = f.Destination AND d.Port = f.Port "
                       "AND d.Protocol = f.Protocol) ORDER BY f.ApplicationId, f.FirstSeen")


def eligible(row: dict) -> bool:
    return (row.get("Rating") == "A" or bool(row.get("Variant"))) and row.get("NamespaceStatus") == "healthy"


def flow_item(f: dict) -> dict:
    pods = []
    try:
        pods = [p.get("pod") for p in json.loads(f.get("Pods") or "[]") if isinstance(p, dict)]
    except ValueError:
        pass
    return {"component": f.get("Component") or "", "destination": f["Destination"], "port": int(f["Port"]),
            "protocol": f["Protocol"], "packets": int(f.get("Packets") or 0), "namespace": f["Namespace"],
            "first_seen": str(f.get("FirstSeen") or ""), "last_seen": str(f.get("LastSeen") or ""), "pods": pods,
            "ips": [f["DestinationIp"]] if f.get("DestinationIp") else []}


def job_source(conn, app: dict) -> dict | None:
    """Where the runner finds the application's source, as for a refactoring order: the scan worker's clone, an
    https repository the runner may clone (lab: CONTAINERIZER_REFACTOR_CLONE=1), or (lab) a local checkout."""
    from . import refactor as rf
    url = app.get("RepositoryUrl") or ""
    if url:
        r = _rows(conn, "SELECT TOP (1) ScanId, AppName FROM cz.OrgRepository WHERE RepositoryUrl = %s AND RemovedAt IS NULL "
                        "AND AppName IS NOT NULL ORDER BY LastScannedAt DESC, RepositoryId DESC", (url,))
        if r and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", str(r[0]["AppName"] or "")):
            sid = int(r[0]["ScanId"])
            return {"type": "org-clone", "scan_id": sid, "dir": f"scan-{sid}/repos/{r[0]['AppName']}",
                    "subdir": app.get("SourcePath") or "."}
        if os.environ.get(rf.CLONE_ENV) == "1" and url.startswith("https://"):
            return {"type": "git-url", "url": url, "subdir": app.get("SourcePath") or "."}
    base = os.environ.get(LOCAL_SOURCES_ENV)
    name = str(app.get("ApplicationName") or "")
    if base and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name) and (Path(base) / name).is_dir():
        p = Path(base) / name
        return {"type": "local", "path": str(p), "git": (p / ".git").exists(), "subdir": "."}
    return None


def dedupe_key(app_id: int, items: list[dict]) -> str:
    basis = json.dumps([app_id, sorted((i["component"], i["destination"], i["port"], i["protocol"]) for i in items)])
    return hashlib.sha256(basis.encode()).hexdigest()


def queue_reviews(conn, log=print, cfg: dict | None = None) -> dict:
    """New flows: the pre-filter's decisions written at once, the rest one egress job per application."""
    cfg = cfg if cfg is not None else review_settings()
    # an address a named flow had is explained by it (the name was learned later), also once that one is decided
    named = {(f["Namespace"], f["Component"], int(f["Port"]), f["DestinationIp"])
             for f in _rows(conn, "SELECT Namespace, Component, Port, DestinationIp FROM cz.EgressFlow "
                                  "WHERE Named = 1 AND DestinationIp IS NOT NULL")}
    by_app: dict[int, list[dict]] = {}
    for f in new_flows(conn):
        if not f.get("Named") and (f["Namespace"], f["Component"], int(f["Port"]), f.get("DestinationIp")) in named:
            continue
        if eligible(f):
            by_app.setdefault(int(f["ApplicationId"]), []).append(f)
    out = {"prefiltered": 0, "queued": 0}
    from .llmqueue import SqlJobQueue
    for app_id, flows in by_app.items():
        pre, ask = [], []
        for f in flows:
            p = prefilter(f, cfg)
            item = flow_item(f)
            if p:
                pre.append({**item, "verdict": p[0], "category": p[1], "reason": p[2], "evidence": []})
            else:
                ask.append(item)
        if pre:
            out["prefiltered"] += insert_decisions(conn, app_id, pre, None)
        if not ask:
            continue
        key = dedupe_key(app_id, ask)
        last = _rows(conn, "SELECT TOP (1) Status, QueuedAt FROM cz.LlmJob WHERE Kind = N'egress' AND DedupeKey = %s "
                           "ORDER BY JobId DESC", (key,))
        if last and (last[0]["Status"] in ("approval", "queued", "running", "answered") or
                     (last[0]["QueuedAt"] and last[0]["QueuedAt"] > utcnow().replace(tzinfo=None) - timedelta(days=REQUEUE_DAYS))):
            continue
        app = flows[0]
        named = []
        net = _rows(conn, "SELECT NetworkJson FROM cz.vNetworkLatest WHERE ApplicationId = %s", (app_id,))
        try:
            for c in (json.loads(net[0]["NetworkJson"]) if net and net[0]["NetworkJson"] else {}).get("components") or []:
                named += [{"host": d["host"], "file": d["file"], "line": d["line"], "quote": d["quote"]}
                          for d in c.get("destinations") or []]
        except (ValueError, KeyError, TypeError):
            named = []
        payload = {"version": 1, "app": app["ApplicationName"], "application_id": app_id,
                   "assessment_id": app.get("AssessmentId"), "commit": app.get("SourceCommit"),
                   "source": job_source(conn, app), "destinations": ask, "named": named}
        job = {"Kind": KIND, "App": app["ApplicationName"], "Repository": app["ApplicationName"], "ApplicationId": app_id,
               "AssessmentId": app.get("AssessmentId"), "Priority": PRIORITY, "DedupeKey": key,
               "RequestedBy": "egress observer", "InputChars": 2500 + 600 * len(ask), "Payload": payload}
        jid = SqlJobQueue(None, requested_by="egress observer").add_with(conn, job)
        if jid:
            out["queued"] += 1
            log(f"egress review #{jid} queued for {app['ApplicationName']}: {len(ask)} destination(s)")
    return out


# --------------------------------------------------------------------------- delivery to the output repository

_FAILED: dict[int, float] = {}          # application -> when its commit last failed (tried again after 10 minutes)


def output_target(conn, key, app: dict) -> dict | None:
    """The output repository the application is deployed from, with its write token: the organization scan that
    assessed it (its registered write credential), else CONTAINERIZER_EGRESS_OUTPUT_REPO (lab, command line)."""
    from .credentials import CredentialError, load, private_key_from_env
    from .orgsource import REDACT
    creds = None
    try:
        k = key if key is not None else (private_key_from_env() if os.environ.get("CONTAINERIZER_CREDENTIAL_KEY_FILE") else None)
        creds = load(conn, k) if k is not None else None
    except CredentialError:
        creds = None
    url = branch = None
    if app.get("RepositoryUrl"):
        r = _rows(conn, "SELECT TOP (1) s.OutputRepo, s.OutputBranch FROM cz.OrgRepository r JOIN cz.OrgScan s "
                        "ON s.ScanId = r.ScanId WHERE r.RepositoryUrl = %s AND r.RemovedAt IS NULL AND s.OutputRepo IS NOT NULL "
                        "ORDER BY r.LastScannedAt DESC", (app["RepositoryUrl"],))
        if r:
            url, branch = r[0]["OutputRepo"], r[0].get("OutputBranch") or "main"
    if not url and os.environ.get(OUTPUT_REPO_ENV):
        url, branch = os.environ[OUTPUT_REPO_ENV], os.environ.get(OUTPUT_BRANCH_ENV) or "main"
    if not url:
        return None
    write = creds.write_for(url) if creds else None
    token = write.token if write and write.token else os.environ.get(os.environ.get(OUTPUT_TOKEN_ENV) or "OUTPUT_GIT_TOKEN")
    user = (write.username if write and write.token else None) or os.environ.get(OUTPUT_USER_ENV) or "x-access-token"
    if not token:
        return {"url": url, "error": "no write token for the output repository (Admin → Source control)"}
    REDACT.add(token, user)
    return {"url": url, "branch": branch, "token": token, "username": user}


def patch_policies(folder: Path, entries: list[dict]) -> list[str]:
    """Open the approved ports in the components' NetworkPolicies (<folder>/<component>/k8s.yaml); returns the
    files changed."""
    import yaml
    from .generate import _yaml_docs
    from .harden import approved_ports, open_approved
    changed = []
    for comp in sorted({e.get("component") for e in entries if e.get("component")}):
        f = folder / comp / "k8s.yaml"
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", comp) or not f.is_file():
            continue
        docs = [d for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]
        ports = approved_ports([e for e in entries if e.get("component") == comp])
        if any(open_approved(d, ports) for d in docs if d.get("kind") == "NetworkPolicy"
               and (d.get("metadata") or {}).get("name") == comp):
            f.write_text(_yaml_docs(docs))
            changed.append(f"{comp}/k8s.yaml")
    return changed


def refresh_folder(conn, app_id: int, folder: Path, namespace: str) -> tuple[dict, list[str]]:
    """connectivity.yaml (+ .md, .svg) of one deployed folder of the application, and its NetworkPolicies."""
    from . import connectivity
    net = _rows(conn, "SELECT NetworkJson FROM cz.vNetworkLatest WHERE ApplicationId = %s", (app_id,))
    network = json.loads(net[0]["NetworkJson"]) if net and net[0].get("NetworkJson") else {}
    flows = _rows(conn, "SELECT * FROM cz.vEgressFlow WHERE ApplicationId = %s AND Namespace = %s", (app_id, namespace))
    decisions = _rows(conn, "SELECT * FROM cz.vEgressDecision WHERE ApplicationId = %s", (app_id,))
    sandbox = _rows(conn, "SELECT ComponentName, Url, Namespace FROM cz.vSandboxLatest WHERE ApplicationId = %s", (app_id,))
    existing = connectivity.read(folder)
    try:                                    # links to and from other applications (schema 25)
        links_out = _rows(conn, "SELECT * FROM cz.vComponentLink WHERE FromApplicationId = %s", (app_id,))
        links_in = _rows(conn, "SELECT * FROM cz.vComponentLink WHERE ToApplicationId = %s AND Status = N'confirmed'",
                         (app_id,))
    except Exception:  # noqa: BLE001
        conn.rollback()
        links_out, links_in = [], []
    doc = connectivity.model(namespace, network, flows, decisions, existing,
                             [s for s in sandbox if s.get("Namespace") == namespace], namespace,
                             links_out=links_out, links_in=links_in)
    connectivity.write_files(folder, doc)
    return doc, patch_policies(folder, connectivity.approved_entries(doc)) + patch_links(folder, doc)


def patch_links(folder: Path, doc: dict) -> list[str]:
    """Open the confirmed links of connectivity.yaml in the components' NetworkPolicies."""
    import yaml
    from .generate import _yaml_docs
    from .links import apply_links
    from . import connectivity
    out, inn = connectivity.linked_entries(doc)
    changed = []
    for comp in sorted({e.get("component") for e in out} | {i.get("component") for i in inn}):
        f = folder / str(comp) / "k8s.yaml"
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", str(comp)) or not f.is_file():
            continue
        docs = [d for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]
        if apply_links(docs, comp, out, inn):
            f.write_text(_yaml_docs(docs))
            changed.append(f"{comp}/k8s.yaml")
    return changed


def commit_pending(connect, key, work: Path, log=print, now: float | None = None) -> int:
    """Decisions not in the output repository yet (new, approved, rejected): each application's connectivity
    files and NetworkPolicies, one commit per output repository. Returns how many applications were written."""
    from .org import OrgOptions, Output
    from .orgsource import REDACT
    from .sandbox import deployed_apps
    now = now if now is not None else _time.monotonic()
    conn = connect()
    try:
        pend = _rows(conn, "SELECT d.DecisionId, d.ApplicationId, d.Destination, d.Port, d.Protocol, d.Status, "
                           "a.ApplicationName, a.RepositoryUrl FROM cz.vEgressDecision d "
                           "JOIN cz.vApplicationLatest a ON a.ApplicationId = d.ApplicationId WHERE d.CommittedAt IS NULL")
        apps: dict[int, dict] = {}
        for r in pend:
            if now - _FAILED.get(int(r["ApplicationId"]), -1e9) < 600:
                continue
            apps.setdefault(int(r["ApplicationId"]), {"app": r, "ids": [], "links": []})["ids"].append(int(r["DecisionId"]))
        try:                                # links (schema 25): both sides of a confirmed one are written
            lp = _rows(conn, "SELECT l.LinkId, l.FromApplicationId, l.ToApplicationId, l.Status, l.FromComponent, "
                             "l.ToApplication, l.ToComponent FROM cz.vComponentLink l WHERE l.CommittedAt IS NULL "
                             "AND l.Status IN (N'proposed', N'confirmed', N'rejected')")
        except Exception:  # noqa: BLE001
            conn.rollback()
            lp = []
        for r in lp:
            sides = [r["FromApplicationId"]] + ([r["ToApplicationId"]] if r["Status"] == "confirmed" and r["ToApplicationId"] else [])
            for aid in sides:
                aid = int(aid)
                if now - _FAILED.get(aid, -1e9) < 600:
                    continue
                if aid not in apps:
                    a = _rows(conn, "SELECT ApplicationId, ApplicationName, RepositoryUrl FROM cz.vApplicationLatest "
                                    "WHERE ApplicationId = %s", (aid,))
                    if not a:
                        continue
                    apps[aid] = {"app": a[0], "ids": [], "links": []}
                apps[aid]["links"].append(r)
        targets: dict[str, dict] = {}
        for app_id, x in apps.items():
            t = output_target(conn, key, x["app"])
            if t is None:
                continue                    # not deployed through an output repository this machine writes
            x["target"] = t
            targets.setdefault(t["url"], {"target": t, "apps": []})["apps"].append(app_id)
    finally:
        conn.close()
    done = 0
    for url, g in targets.items():
        t = g["target"]
        wdir = work / f"egress-{hashlib.sha256(url.encode()).hexdigest()[:12]}"
        try:
            if t.get("error"):
                raise RuntimeError(t["error"])
            o = OrgOptions(provider="git", org="", registry="", token="", output_repo=url, output_branch=t["branch"],
                           output_token=t["token"], output_username=t["username"], work_dir=str(wdir))
            wdir.mkdir(parents=True, exist_ok=True)
            out = Output(o, wdir)
            conn = connect()
            try:
                msgs, written = [], {}
                for app_id in g["apps"]:
                    nss = [r["Namespace"] for r in _rows(conn, "SELECT Namespace FROM cz.vSandboxNamespace WHERE "
                                                               "ApplicationId = %s", (app_id,))]
                    folders = deployed_apps(out.root, set(nss))
                    if not folders:
                        _mark(conn, apps[app_id]["ids"], None, "the application is not in the output repository")
                        _mark_links(conn, [l["LinkId"] for l in apps[app_id]["links"]
                                           if int(l["FromApplicationId"]) == app_id], None,
                                    "the application is not in the output repository")
                        continue
                    for f in folders:
                        doc, pol = refresh_folder(conn, app_id, out.root / f["rel"], f["app"])
                    appr = [d for d in _rows(conn, "SELECT Destination, Port, Status FROM cz.vEgressDecision WHERE "
                                                   "DecisionId IN (" + ",".join(str(i) for i in apps[app_id]["ids"]) + ")")] \
                        if apps[app_id]["ids"] else []
                    what = ", ".join(sorted({f"{d['Destination']}:{d['Port']}" for d in appr if d["Status"] == "approved"}))
                    lk = ", ".join(sorted({f"{l['FromComponent']} -> {l['ToApplication']}/{l['ToComponent']}"
                                           for l in apps[app_id]["links"] if l["Status"] == "confirmed"}))
                    msgs.append(f"{apps[app_id]['app']['ApplicationName']}" + (f": approved {what}" if what else "")
                                + (f": linked {lk}" if lk else ""))
                    written[app_id] = apps[app_id]["ids"]
                if written:
                    out.commit("containerizer: connectivity of " + "; ".join(msgs)[:300])
                    from .variant import _head
                    rev = _head(out.root)
                    for app_id, ids in written.items():
                        _mark(conn, ids, rev, None)
                        _FAILED.pop(app_id, None)
                    # a link is written when every side of it that is in this repository is
                    done_links = {int(l["LinkId"]) for a in written for l in apps[a]["links"]}
                    _mark_links(conn, sorted(done_links), rev, None)
                    done += len(written)
                    log(f"connectivity committed ({rev[:12]}): {'; '.join(msgs)[:300]}")
            finally:
                conn.close()
        except Exception as ex:  # noqa: BLE001 - tried again in 10 minutes
            err = REDACT(f"{type(ex).__name__}: {ex}")[:600]
            log(f"connectivity not committed to {REDACT(url)}: {err}")
            conn = connect()
            try:
                for app_id in g["apps"]:
                    _FAILED[app_id] = now
                    _mark(conn, apps[app_id]["ids"], None, err, keep_open=True)
            finally:
                conn.close()
        finally:
            shutil.rmtree(wdir, ignore_errors=True)
    return done


def _mark_links(conn, ids: list[int], revision: str | None, error: str | None) -> None:
    if not ids:
        return
    cur = conn.cursor()
    cur.execute(f"UPDATE cz.ComponentLink SET CommittedAt = SYSUTCDATETIME(), CommitRevision = %s, CommitError = %s "
                f"WHERE LinkId IN ({', '.join(['%s'] * len(ids))})", (revision, error, *ids))
    conn.commit()


def _mark(conn, ids: list[int], revision: str | None, error: str | None, keep_open: bool = False) -> None:
    if not ids:
        return
    cur = conn.cursor()
    marks = ", ".join(["%s"] * len(ids))
    if keep_open:
        cur.execute(f"UPDATE cz.EgressDecision SET CommitError = %s WHERE DecisionId IN ({marks})", (error, *ids))
    else:
        cur.execute(f"UPDATE cz.EgressDecision SET CommittedAt = SYSUTCDATETIME(), CommitRevision = %s, CommitError = %s "
                    f"WHERE DecisionId IN ({marks})", (revision, error, *ids))
    conn.commit()


def housekeep(connect, key, work: Path, log=print) -> dict:
    """The queue runner's periodic egress step: queue reviews of new flows, then write what is pending to the
    output repositories."""
    conn = connect()
    try:
        q = queue_reviews(conn, log)
        try:                                # links between applications (schema 25)
            from .links import housekeep as link_housekeep
            q["links"] = link_housekeep(conn, log)
        except Exception as ex:  # noqa: BLE001 - a database from before schema 25: next time
            conn.rollback()
            log(f"links: {type(ex).__name__}: {ex}"[:300])
    finally:
        conn.close()
    q["committed"] = commit_pending(connect, key, work, log)
    return q
