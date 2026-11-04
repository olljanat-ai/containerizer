"""Egress (docs/egress.md): the NFLOG reader, the observer, the pre-filter, the egress review, approval, the
delivery to the output repository, network connectivity (connectivity.yaml, the diagram, the results page), and
that later scans keep approved egress (documented for the real environment: approval opens nothing in the
sandbox), and the appliance's own signals and egress rules."""
import json
import os
import re
import shutil
import socket
import subprocess
import struct
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
import yaml

from containerizer import connectivity as cy
from containerizer import egress as eg
from containerizer import llmqueue as lq
from containerizer import nflog

from test_llm_queue import FakeConn

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "egress-demo"


# --------------------------------------------------------------------------- NFLOG

def test_parses_a_kube_router_drop_of_a_tcp_syn():
    pkt = nflog.ipv4_tcp("10.42.0.25", "140.82.121.6", 43120, 443)
    msg = nflog.packet_message(socket.AF_INET, "DROP by policy egress-demo/egress-demo", pkt)
    d, = nflog.parse_messages(msg)
    assert (d.namespace, d.policy, d.src, d.dst, d.protocol, d.sport, d.dport, d.syn) == \
        ("egress-demo", "egress-demo", "10.42.0.25", "140.82.121.6", "TCP", 43120, 443, True)


def test_parses_several_messages_ipv6_and_ignores_other_prefixes():
    a = nflog.packet_message(socket.AF_INET6, "DROP by policy shop/web",
                             nflog.ipv6_udp("fd00:10:42::5", "2001:db8::1", 5353, 53), hw_protocol=0x86DD)
    b = nflog.packet_message(socket.AF_INET, "some other log", nflog.ipv4_tcp("1.2.3.4", "5.6.7.8", 1, 2))
    c = nflog.packet_message(socket.AF_INET, "DROP by policy shop/web",
                             nflog.ipv4_tcp("10.42.0.9", "10.43.0.1", 5000, 80, flags=0x12))     # SYN-ACK
    drops = nflog.parse_messages(a + b + c)
    assert [(d.src, d.dst, d.protocol, d.dport, d.syn) for d in drops] == \
        [("fd00:10:42::5", "2001:db8::1", "UDP", 53, False), ("10.42.0.9", "10.43.0.1", "TCP", 80, False)]
    assert nflog.parse_messages(b"\x00" * 7) == [] and nflog.parse_messages(a[:30]) == []


def test_ipv6_extension_headers_and_fragments():
    hop = struct.pack("!BB6x", 6, 0)                    # hop-by-hop, next: TCP
    ip = struct.pack("!IHBB16s16s", 6 << 28, 28, 0, 64, socket.inet_pton(socket.AF_INET6, "fd00::1"),
                     socket.inet_pton(socket.AF_INET6, "2001:db8::2"))
    tcp = struct.pack("!HHIIBBHHH", 40000, 443, 0, 0, 0x50, 0x02, 0, 0, 0)
    src, dst, proto, sport, dport, syn = nflog.parse_packet(socket.AF_INET6, ip + hop + tcp)
    assert (proto, sport, dport, syn) == ("TCP", 40000, 443, True)
    # a later IPv4 fragment carries no ports
    frag = bytearray(nflog.ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 2))
    frag[6:8] = struct.pack("!H", 0x0010)
    assert nflog.parse_packet(socket.AF_INET, bytes(frag))[3:5] == (None, None)
    assert nflog.parse_prefix(b"DROP by policy ns-only\0") is None


def test_config_messages_bind_the_group_and_copy_128_bytes():
    m = nflog.config_message(100, nflog.nlattr(nflog.NFULA_CFG_CMD, bytes([nflog.NFULNL_CFG_CMD_BIND])))
    ln, typ, flags, _seq, _pid = struct.unpack_from("=IHHII", m)
    assert ln == len(m) and typ == (4 << 8 | 1) and flags & 1 and flags & 4
    assert struct.unpack_from("!BBH", m, 16) == (0, 0, 100)
    assert nflog.attributes(m[20:]) == {1: bytes([1])}


# --------------------------------------------------------------------------- the observer

def test_coredns_log_lines():
    line = '[INFO] 10.42.0.25:43210 - 12345 "A IN api.github.com. udp 32 false 512" NOERROR qr,rd,ra 98 0.012s'
    assert eg.parse_dns_line(line) == ("10.42.0.25", "api.github.com", "A", "NOERROR")
    six = '[INFO] [fd00:10:42::5]:5353 - 1 "AAAA IN Example.ORG. tcp 40 false 65535" NXDOMAIN qr 10 0.1s'
    assert eg.parse_dns_line(six) == ("fd00:10:42::5", "example.org", "AAAA", "NXDOMAIN")
    assert eg.parse_dns_line("[INFO] plugin/reload: Running configuration") is None
    assert eg.external_name("api.github.com") and not eg.external_name("db.shop.svc.cluster.local")
    assert not eg.external_name("localhost") and not eg.external_name("5.0.42.10.in-addr.arpa")


def test_dns_answers():
    qid = 0x1234
    q = struct.pack("!HHHHHH", qid, 0x8180, 1, 2, 0, 0) + b"\x03api\x06github\x03com\x00" + struct.pack("!HH", 1, 1)
    a1 = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c"                     # CNAME: skipped
    a2 = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([140, 82, 121, 6])
    assert eg.parse_dns_answer(q + a1 + a2, qid) == ["140.82.121.6"]
    assert eg.parse_dns_answer(q + a1 + a2, 1) == []                                       # another query's answer


class FakeResolver:
    def __init__(self, table):
        self.table = table

    def lookup(self, name):
        return set(self.table.get(name, ()))


def test_name_for_prefers_the_pods_own_lookups_and_then_the_namespace():
    mem = eg.DnsMemory()
    mem.add("10.42.0.25", "api.github.com")
    mem.add("10.42.0.26", "cdn.example.net")
    r = FakeResolver({"api.github.com": {"140.82.121.6"}, "cdn.example.net": {"1.1.1.1", "140.82.121.6"}})
    assert eg.name_for("140.82.121.6", "10.42.0.25", ["10.42.0.25", "10.42.0.26"], mem, r) == "api.github.com"
    assert eg.name_for("1.1.1.1", "10.42.0.25", ["10.42.0.25", "10.42.0.26"], mem, r) == "cdn.example.net"
    assert eg.name_for("9.9.9.9", "10.42.0.25", ["10.42.0.25"], mem, r) is None
    # a lookup outside the window explains nothing
    now = [1000.0]
    old = eg.DnsMemory(window=600, clock=lambda: now[0])
    old.add("10.42.0.25", "api.github.com")
    now[0] += 601
    assert eg.name_for("140.82.121.6", "10.42.0.25", ["10.42.0.25"], old, r) is None


class FakeKube:
    def __init__(self, pods):
        self.pods = pods

    def get(self, resource, ns=None, name=None, selector=None):
        return {"items": [{"metadata": {"name": p, "labels": {"app.kubernetes.io/name": c}},
                           "status": {"podIP": ip}, "spec": {}} for ip, (p, c) in self.pods.get(ns, {}).items()]}


def test_observer_keeps_egress_of_app_pods_and_names_it():
    kube = FakeKube({"shop": {"10.42.0.25": ("web-1", "web")}})
    obs = eg.Observer(kube, None, FakeResolver({"api.github.com": {"140.82.121.6"}}), name="t", log=lambda m: None)
    obs.dns_line('[INFO] 10.42.0.25:1 - 2 "A IN api.github.com. udp 32 false 512" NOERROR qr 98 0.01s')
    obs.dns_line('[INFO] 10.42.0.25:1 - 2 "A IN nope.example. udp 32 false 512" NXDOMAIN qr 98 0.01s')
    D = nflog.Drop
    out = nflog.socket.AF_INET
    f = obs.drop(D("shop", "web", out, "10.42.0.25", "140.82.121.6", "TCP", 4000, 443, True))
    obs.drop(D("shop", "web", out, "10.42.0.25", "140.82.121.6", "TCP", 4001, 443, True))
    assert (f.destination, f.named, f.component, f.packets, f.pods) == ("api.github.com", True, "web", 2, {"web-1": "10.42.0.25"})
    assert obs.drop(D("shop", "web", out, "10.42.0.99", "10.42.0.25", "TCP", 4000, 8080, True)) is None   # incoming
    assert obs.drop(D("kube-system", "x", out, "10.42.0.3", "8.8.8.8", "UDP", 1, 53, False)) is None      # platform
    assert obs.drop(D("shop", "web", out, "10.42.0.25", "10.42.0.9", "UDP", 5000, 53, False)) is None      # cluster DNS
    g = obs.drop(D("shop", "web", out, "10.42.0.25", "203.0.113.9", "TCP", 4002, 8443, True))
    assert (g.destination, g.named) == ("203.0.113.9", False)
    assert obs.agg.stats == {"drops": 6, "egress": 3, "ingress": 1, "named": 2, "platform": 1, "dns": 1}
    conn = FakeConn()
    assert eg.record(conn, obs.agg.take(), "obs") == 2
    (sql, p), _ = conn.sql(r"EXEC cz.RecordEgressFlow")
    assert p[:8] == ("shop", "web", "api.github.com", 1, "140.82.121.6", 443, "TCP", 2)
    assert json.loads(p[10]) == [{"pod": "web-1", "ip": "10.42.0.25"}] and p[12] == "obs"


def test_a_failed_flush_keeps_the_counts():
    obs = eg.Observer(FakeKube({}), lambda: (_ for _ in ()).throw(RuntimeError("db away")), FakeResolver({}),
                      log=lambda m: None)
    now = datetime.now(timezone.utc)
    obs.agg.add("shop", "web", "a.example", True, 443, "TCP", "1.2.3.4", "p", "10.0.0.1", "shop/web", now)
    assert obs.flush() == 0 and len(obs.agg.flows) == 1


def test_observer_rbac_is_read_only_and_namespaced():
    docs = eg.observer_rbac(["shop", "egress-demo"])
    roles = [d for d in docs if d["kind"] == "Role"]
    assert {r["metadata"]["namespace"] for r in roles} == {"kube-system", "shop", "egress-demo"}
    verbs = {v for r in roles for rule in r["rules"] for v in rule["verbs"]}
    resources = {x for r in roles for rule in r["rules"] for x in rule["resources"]}
    assert verbs == {"get", "list"} and resources == {"pods", "pods/log"}
    assert not any(d["kind"].startswith("Cluster") for d in docs)
    assert next(r for r in roles if r["metadata"]["namespace"] == "shop")["rules"] == \
        [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]


# --------------------------------------------------------------------------- the pre-filter

@pytest.mark.parametrize("flow, verdict, category", [
    ({"Namespace": "shop", "Destination": "pastebin.com", "Named": True, "Port": 443}, "suspicious", "file-sharing"),
    ({"Namespace": "shop", "Destination": "x.ngrok-free.app", "Named": True, "Port": 443}, "suspicious", "file-sharing"),
    ({"Namespace": "shop", "Destination": "169.254.169.254", "Named": False, "Port": 80}, "suspicious", "metadata"),
    ({"Namespace": "shop", "Destination": "evil.example", "Named": True, "DestinationIp": "169.254.169.254", "Port": 80},
     "suspicious", "metadata"),
    ({"Namespace": "shop", "Destination": "*.example.com", "Named": True, "Port": 443}, "suspicious", "wildcard"),
    ({"Namespace": "shop", "Destination": "203.0.113.9", "Named": False, "Port": 443}, "unnamed", "ip-literal"),
    ({"Namespace": "shop", "Destination": "10.43.0.12", "Named": False, "Port": 5432}, "in-cluster", "in-cluster"),
    ({"Namespace": "kube-system", "Destination": "api.github.com", "Named": True, "Port": 443}, "platform",
     "platform-namespace"),
    ({"Namespace": "shop", "Destination": "kv1.vault.azure.net", "Named": True, "Port": 443}, "platform", "platform-service"),
    ({"Namespace": "shop", "Destination": "api.example.com", "Named": True, "Port": 31337}, "report", "unusual-port"),
])
def test_prefilter_never_proposes(flow, verdict, category):
    assert eg.prefilter(flow)[:2] == (verdict, category)


def test_prefilter_leaves_ordinary_names_to_the_llm():
    assert eg.prefilter({"Namespace": "shop", "Destination": "api.github.com", "Named": True, "Port": 443,
                         "DestinationIp": "140.82.121.6"}) is None
    assert eg.prefilter({"Namespace": "shop", "Destination": "notpastebin.com", "Named": True, "Port": 443}) is None


# --------------------------------------------------------------------------- the review

DEST = {"component": "egress-demo", "destination": "api.github.com", "port": 443, "protocol": "TCP", "packets": 3,
        "namespace": "egress-demo", "pods": ["p1"], "ips": ["140.82.121.6"]}


def test_source_hits_and_checked_quotes():
    hits = eg.source_hits(DEMO, ["api.github.com"])["api.github.com"]
    assert {(h["file"], h["line"]) for h in hits} >= {("src/Egress.Demo/appsettings.json", 4), ("src/Egress.Demo/Program.cs", 8)}
    ok = {"destination": "api.github.com", "port": 443, "verdict": "propose", "reason": "configured upstream",
          "file": "src/Egress.Demo/appsettings.json", "line": 4, "quote": '"Upstream": { "Url": "https://api.github.com/zen" }'}
    d, = eg.decide([ok], [DEST], {"api.github.com": hits}, DEMO)
    assert d["verdict"] == "propose" and d["evidence"][0]["file"] == "src/Egress.Demo/appsettings.json"
    # a quote that is not in the source: the evidence is dropped and the reason says so
    bad = {**ok, "file": "src/Egress.Demo/Secret.cs", "line": 1, "quote": "var u = \"https://api.github.com\";"}
    d, = eg.decide([bad], [DEST], {"api.github.com": []}, DEMO)
    assert d["evidence"] == [] and "not in the assessed source" in d["reason"] and d["verdict"] == "propose"
    # ... and without a steady flow it is only reported
    d, = eg.decide([bad], [{**DEST, "packets": 1}], {"api.github.com": []}, DEMO)
    assert d["verdict"] == "report" and "not steady" in d["reason"]
    # no answer for a destination: a person decides
    d, = eg.decide([], [DEST], {}, DEMO)
    assert d["verdict"] == "report"
    # an answer outside the schema's verdicts is not trusted
    d, = eg.decide([{**ok, "verdict": "approve"}], [DEST], {"api.github.com": hits}, DEMO)
    assert d["verdict"] == "report"


def test_handler_asks_once_per_ten_destinations_and_writes_the_decisions(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINERIZER_REFACTOR_WORK", str(tmp_path))
    dests = [{**DEST, "destination": f"api{i}.example.com"} for i in range(12)]
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return {"destinations": [{"destination": d["destination"], "port": 443, "verdict": "report", "reason": "r",
                                  "file": "", "line": 0, "quote": ""} for d in dests]}
    conn = FakeConn()
    job = {"JobId": 5, "Payload": {"app": "shop", "application_id": 7, "destinations": dests, "source": None},
           "_connect": lambda: conn}
    out = eg.handler(job, ask=ask)
    assert len(asked) == 2 and "api0.example.com" in asked[0] and "api11.example.com" in asked[1]
    assert "not available here" in asked[0] and out["result"]["source"] == "assessment"
    assert out["summary"] == "12 destination(s): 12 reported"
    ins = conn.sql(r"INSERT cz.EgressDecision")
    assert len(ins) == 12 and ins[0][1][12] == "reported" and ins[0][1][-1] == 5


def test_handler_reads_the_assessed_commit(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    shutil.copytree(DEMO, repo)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com"}
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", *cmd], cwd=repo, check=True, env=env)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    (repo / "src" / "Egress.Demo" / "appsettings.json").write_text("{}")   # after the commit: not what was assessed
    monkeypatch.setenv("CONTAINERIZER_REFACTOR_WORK", str(tmp_path / "w"))
    monkeypatch.delenv("CONTAINERIZER_REFACTOR_SOURCES", raising=False)
    seen = []

    def ask(prompt):
        seen.append(prompt)
        return {"destinations": [{"destination": "api.github.com", "port": 443, "verdict": "propose", "reason": "upstream",
                                  "file": "src/Egress.Demo/appsettings.json", "line": 4,
                                  "quote": '"Upstream": { "Url": "https://api.github.com/zen" }'}]}
    out = eg.handler({"JobId": 1, "Payload": {"app": "egress-demo", "commit": commit, "destinations": [DEST],
                                               "source": {"type": "local", "path": str(repo), "git": True}}}, ask=ask)
    d, = out["result"]["decisions"]
    assert d["verdict"] == "propose" and d["evidence"][0]["verified"] and "src/Egress.Demo/appsettings.json" in seen[0]


def _flow(**kw):
    base = {"FlowId": 1, "ApplicationId": 7, "Variant": False, "Namespace": "shop", "Component": "web",
            "Destination": "api.github.com", "Named": True, "DestinationIp": "140.82.121.6", "Port": 443,
            "Protocol": "TCP", "Packets": 4, "FirstSeen": datetime(2026, 11, 1, 10), "LastSeen": datetime(2026, 11, 1, 11),
            "Pods": json.dumps([{"pod": "web-1", "ip": "10.42.0.25"}]), "Policy": "shop/web", "ApplicationName": "shop",
            "Rating": "A", "AssessmentId": 70, "SourceCommit": "a" * 40, "RepositoryUrl": None, "SourcePath": ".",
            "NamespaceStatus": "healthy"}
    return {**base, **kw}


def test_queue_reviews_prefilters_and_queues_one_job_per_application():
    flows = [_flow(), _flow(FlowId=2, Destination="pastebin.com", DestinationIp="172.66.171.73"),
             _flow(FlowId=3, Destination="140.82.121.6", Named=False),            # explained by api.github.com
             _flow(FlowId=4, Destination="203.0.113.9", Named=False, DestinationIp="203.0.113.9"),
             _flow(FlowId=5, ApplicationId=8, ApplicationName="b-app", Rating="B"),          # not A: not reviewed
             _flow(FlowId=6, ApplicationId=9, ApplicationName="sick", NamespaceStatus="failing")]
    conn = FakeConn({r"FROM cz.vEgressFlow f": flows,
                     r"FROM cz.EgressFlow WHERE Named = 1": [{"Namespace": "shop", "Component": "web", "Port": 443,
                                                             "DestinationIp": "140.82.121.6"}],
                     r"FROM cz.LlmJob WHERE Kind = N'egress' AND DedupeKey": [],
                     r"EXEC cz.QueueLlmJob": [{"JobId": 11}]})
    logs = []
    assert eg.queue_reviews(conn, logs.append) == {"prefiltered": 2, "queued": 1}
    ins = [p for _, p in conn.sql(r"INSERT cz.EgressDecision")]
    assert sorted((p[8], p[12]) for p in ins) == [("203.0.113.9", "reported"), ("pastebin.com", "suspicious")]
    (sql, params), = conn.sql(r"EXEC cz.QueueLlmJob")
    payload = json.loads(params[-1])
    assert params[0] == "egress" and [d["destination"] for d in payload["destinations"]] == ["api.github.com"]
    assert payload["application_id"] == 7 and payload["destinations"][0]["pods"] == ["web-1"]
    assert "egress review #11 queued for shop" in logs[0]


def test_a_review_that_failed_or_waits_is_not_queued_again():
    for st, ago in (("queued", 0), ("failed", 1), ("answered", 30)):
        conn = FakeConn({r"FROM cz.vEgressFlow f": [_flow()],
                         r"FROM cz.LlmJob WHERE Kind = N'egress' AND DedupeKey":
                             [{"Status": st, "QueuedAt": datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) -
                               __import__("datetime").timedelta(days=ago)}]})
        assert eg.queue_reviews(conn, lambda m: None)["queued"] == 0 and not conn.sql("QueueLlmJob")


def test_the_runner_takes_the_egress_kind_only_when_asked():
    assert lq.JOB_KINDS["egress"].title == "Egress review" and lq.JOB_KINDS["egress"].feature == "egress-queued"
    r = lq.Runner(lambda: None, name="r", kinds=["egress"], metrics=object.__new__(lq.QueueMetrics), log=lambda m: None)
    conn = FakeConn({r"SELECT TOP \(1\) j\.\*": []})
    r.claim(conn)
    (sql, params), = conn.sql(r"SELECT TOP \(1\) j\.\*")
    assert params == ("egress",)


# --------------------------------------------------------------------------- NetworkPolicy and delivery

def _policy():
    from containerizer.harden import network_policy
    return network_policy("web", {"app.kubernetes.io/name": "web", "app.kubernetes.io/part-of": "shop"}, 8080, [])


def test_output_target_from_the_environment(monkeypatch):
    monkeypatch.setenv(eg.OUTPUT_REPO_ENV, "https://git.example.com/platform/sandbox.git")
    monkeypatch.setenv("OUTPUT_GIT_TOKEN", "tok")
    monkeypatch.delenv("CONTAINERIZER_CREDENTIAL_KEY_FILE", raising=False)
    t = eg.output_target(FakeConn(), None, {"RepositoryUrl": None})
    assert t == {"url": "https://git.example.com/platform/sandbox.git", "branch": "main", "token": "tok",
                 "username": "x-access-token"}
    monkeypatch.delenv("OUTPUT_GIT_TOKEN")
    assert "no write token" in eg.output_target(FakeConn(), None, {"RepositoryUrl": None})["error"]
    monkeypatch.delenv(eg.OUTPUT_REPO_ENV)
    assert eg.output_target(FakeConn(), None, {"RepositoryUrl": None}) is None


def _git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com"}
    return subprocess.run(["git", *args], cwd=cwd, check=True, env=env, capture_output=True, text=True).stdout


def test_commit_pending_writes_connectivity_and_the_policy_to_the_output_repository(tmp_path, monkeypatch):
    from containerizer.generate import _yaml_docs
    bare = tmp_path / "out.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _git(tmp_path, "clone", "-q", str(bare), str(seed))
    app = seed / "lab" / "_" / "shop"
    (app / "web").mkdir(parents=True)
    (app / "web" / "k8s.yaml").write_text(_yaml_docs([_policy()]))
    (app / "containerizer.json").write_text(json.dumps({"app": "shop", "components": [{"component": "Web", "folder": "web"}]}))
    (app / "gitops" / "flux").mkdir(parents=True)
    (app / "gitops" / "flux" / "kustomization.yaml").write_text("resources: []\n")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-q", "-m", "seed")
    _git(seed, "push", "-q", "origin", "HEAD:main")
    monkeypatch.setenv(eg.OUTPUT_REPO_ENV, "https://git.example.com/x.git")
    monkeypatch.setenv("OUTPUT_GIT_TOKEN", "tok")
    import containerizer.org as orgmod

    def clone(url, dest, branch, header):
        _git(tmp_path, "clone", "-q", "-b", branch or "main", str(bare), str(dest))
    monkeypatch.setattr(orgmod, "clone", clone)
    real_git = orgmod.git

    def git(args, cwd=None, url=None, header=None, check=True):
        if args[0] == "push":
            args = ["push", "-q", str(bare), args[-1]]
        return real_git(args, cwd=cwd, check=check)
    monkeypatch.setattr(orgmod, "git", git)
    dec = {"DecisionId": 3, "ApplicationId": 7, "Namespace": "shop", "Component": "web", "Destination": "api.github.com",
           "Port": 443, "Protocol": "TCP", "Verdict": "propose", "Status": "approved", "Reason": "configured upstream",
           "Evidence": json.dumps([{"file": "appsettings.json", "line": 4, "quote": "x", "verified": True}]),
           "DecidedBy": "john.doe@example.com", "DecidedAt": datetime(2026, 11, 2, 3, 43), "CommittedAt": None,
           "ApplicationName": "shop", "RepositoryUrl": None}
    conn = FakeConn({r"WHERE d.CommittedAt IS NULL": [dec],
                     r"FROM cz.vSandboxNamespace WHERE": [{"Namespace": "shop"}],
                     r"FROM cz.vEgressDecision WHERE ApplicationId": [dec],
                     r"FROM cz.vEgressDecision WHERE DecisionId IN": [dec],
                     r"FROM cz.vEgressFlow WHERE": [_flow(Component="web", Namespace="shop")]})
    logs = []
    n = eg.commit_pending(lambda: conn, None, tmp_path / "work", logs.append)
    assert n == 1, logs
    assert "approved api.github.com:443" in logs[0]
    check = tmp_path / "check"
    _git(tmp_path, "clone", "-q", str(bare), str(check))
    doc = yaml.safe_load((check / "lab/_/shop/connectivity.yaml").read_text())
    e, = [x for x in doc["outbound"] if x["destination"] == "api.github.com"]
    assert (e["status"], e["approved_by"], e["port"]) == ("approved", "john.doe@example.com", 443)
    pol = list(yaml.safe_load_all((check / "lab/_/shop/web/k8s.yaml").read_text()))[0]
    assert pol == _policy()                                     # approval documents; the sandbox stays as it was
    assert (check / "lab/_/shop/CONNECTIVITY.md").is_file() and (check / "lab/_/shop/connectivity.svg").is_file()
    (sql, params), = conn.sql(r"UPDATE cz.EgressDecision SET CommittedAt")
    assert len(params[0]) == 40 and params[-1] == 3


# --------------------------------------------------------------------------- connectivity

def test_infer_names_the_configured_and_hard_coded_destinations():
    from containerizer.assess import assess
    a = assess(DEMO)
    net = a.to_dict()["network"]
    c, = net["components"]
    assert (c["k8s"], c["port"], c["service_port"], c["egress"]) == ("egress-demo", 8080, 80, [])
    got = {(d["host"], d["port"], d["source"], d["file"], d["line"]) for d in c["destinations"]}
    assert ("api.github.com", 443, "config", "src/Egress.Demo/appsettings.json", 4) in got
    assert ("pastebin.com", 443, "code", "src/Egress.Demo/Program.cs", 32) in got
    assert ("orders-demo.orders-demo", 80, "config", "src/Egress.Demo/appsettings.json", 5) in got


def test_scan_destinations_skips_noise(tmp_path):
    from containerizer.assess import assess
    p = tmp_path / "app" / "src" / "Api"
    p.mkdir(parents=True)
    (p / "Api.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0'
                                  '</TargetFramework></PropertyGroup></Project>')
    (p / "Program.cs").write_text('// see https://docs.example.org/x\nvar x = "http://localhost:5000";\n'
                                  'var app = WebApplication.CreateBuilder(args).Build(); app.Run();\n')
    (p / "appsettings.json").write_text(json.dumps({"ConnectionStrings": {"Db": "Server=sql.corp.local,14330;Database=x"},
                                                    "Schema": "http://www.w3.org/2001/XMLSchema",
                                                    "Orders": "https://{host}/api", "Rabbit": "amqps://mq.corp.local"}))
    (p / "appsettings.Development.json").write_text(json.dumps({"Api": "https://dev-only.corp.local"}))
    c, = assess(tmp_path / "app").to_dict()["network"]["components"]
    assert {(d["host"], d["port"]) for d in c["destinations"]} == {("sql.corp.local", 14330), ("mq.corp.local", 5671)}


NET = {"components": [{"name": "Web", "k8s": "web", "role": "web", "port": 8080, "service_port": 80,
                       "egress": [{"id": "sql-server", "ports": [{"port": 1433, "protocol": "TCP"}]}],
                       "destinations": [
                           {"host": "api.github.com", "port": 443, "protocol": "TCP", "source": "config",
                            "file": "appsettings.json", "line": 4, "quote": "\"Url\": \"https://api.github.com\""},
                           {"host": "worker", "port": 80, "protocol": "TCP", "source": "config", "file": "appsettings.json",
                            "line": 5, "quote": "\"Worker\": \"http://worker\""}],
                       "lab_services": {}},
                      {"name": "Worker", "k8s": "worker", "role": "worker", "egress": [], "destinations": [],
                       "lab_services": {"sqlserver": ["package"]}}]}


def test_model_marks_every_source_and_the_findings():
    doc = cy.model("shop", NET, sandbox=[{"ComponentName": "Web", "Url": "https://web-shop.sandbox.example/"}])
    assert doc["observed"] is False and doc["namespace"] == "shop"
    out = {(e["component"], e["destination"], e["port"]): e for e in doc["outbound"]}
    assert out[("web", "api.github.com", 443)]["status"] == "not-allowed"
    assert out[("web", "any address", 1433)]["status"] == "allowed" and out[("web", "any address", 1433)]["type"] == "any"
    assert {i["from"] for i in doc["inbound"]} == {"https://web-shop.sandbox.example/", "any namespace (Service)"}
    assert {(i["from"], i["to"], i["port"]) for i in doc["internal"]} == {("web", "worker", 80), ("worker", "lab SQL Server", 1433)}
    kinds = sorted(f["kind"] for f in doc["findings"])
    assert kinds == ["missing", "unexplained"]
    # observed and approved
    flows = [{"Namespace": "shop", "Component": "web", "Destination": "api.github.com", "Named": True,
              "DestinationIp": "140.82.121.6", "Port": 443, "Protocol": "TCP", "Packets": 3,
              "FirstSeen": datetime(2026, 11, 2, 3, 38), "LastSeen": datetime(2026, 11, 2, 3, 39), "Pods": "[]"},
             {"Namespace": "shop", "Component": "web", "Destination": "140.82.121.6", "Named": False,
              "DestinationIp": "140.82.121.6", "Port": 443, "Protocol": "TCP", "Packets": 2,
              "FirstSeen": datetime(2026, 11, 2, 3, 37), "LastSeen": datetime(2026, 11, 2, 3, 37), "Pods": "[]"}]
    dec = [{"DecisionId": 3, "Component": "web", "Destination": "api.github.com", "Port": 443, "Protocol": "TCP",
            "Verdict": "propose", "Status": "approved", "Reason": "upstream", "Evidence": "[]",
            "DecidedBy": "john.doe@example.com", "DecidedAt": datetime(2026, 11, 2, 3, 43)}]
    doc = cy.model("shop", NET, flows, dec)
    e, = [x for x in doc["outbound"] if x["destination"] == "api.github.com"]
    assert e["status"] == "approved" and set(e["sources"]) == {"config", "observed", "approved"}
    assert e["sandbox"]["reachable"] is False and e["sandbox"]["blocked_by"] == "network-policy"
    assert e["observed"]["packets"] == 3 and e["approved_by"] == "john.doe@example.com"
    assert not any(x["destination"] == "140.82.121.6" for x in doc["outbound"])         # explained by the name
    assert doc["observed"] is True and not [f for f in doc["findings"] if f["kind"] == "missing"]


def test_merge_keeps_approved_entries_verbatim_and_decisions_over_inference():
    approved = {"component": "web", "destination": "api.github.com", "port": 443, "protocol": "TCP", "status": "approved",
                "sources": ["observed", "approved"], "reason": "hand-written note", "approved_by": "john.doe@example.com"}
    sus = {"component": "web", "destination": "pastebin.com", "port": 443, "protocol": "TCP", "status": "suspicious",
           "sources": ["observed"], "category": "file-sharing"}
    new = [{"component": "web", "destination": "api.github.com", "port": 443, "protocol": "TCP", "status": "allowed",
            "sources": ["config"], "reason": "scan"},
           {"component": "web", "destination": "pastebin.com", "port": 443, "protocol": "TCP", "status": "allowed",
            "sources": ["code"], "evidence": [{"file": "Program.cs", "line": 29}]}]
    out = {e["destination"]: e for e in cy.merge_outbound([approved, sus], new)}
    assert out["api.github.com"] == {**approved, "sources": ["observed", "approved", "config"]}
    assert out["pastebin.com"]["status"] == "suspicious" and set(out["pastebin.com"]["sources"]) == {"observed", "code"}
    assert out["pastebin.com"]["evidence"] == [{"file": "Program.cs", "line": 29}]
    # an approved entry the new model does not know at all stays too
    assert cy.merge_outbound([approved], []) == [approved]


def test_yaml_markdown_and_svg(tmp_path):
    doc = cy.model("shop", NET)
    files = cy.write_files(tmp_path, doc)
    assert [f.name for f in files] == ["connectivity.yaml", "CONNECTIVITY.md", "connectivity.svg"]
    back = cy.read(tmp_path)
    assert back["kind"] == "Connectivity" and back["apiVersion"] == "containerizer.eu/v1"
    assert "decision" not in (tmp_path / "connectivity.yaml").read_text()
    md = (tmp_path / "CONNECTIVITY.md").read_text()
    assert "![Network connectivity of shop](connectivity.svg)" in md and "| web | api.github.com | 443/TCP |" in md
    page = cy.svg(doc)
    assert "<script" not in page and "style=" not in page and "<style" not in page and "cf-missing" in page
    assert "Not observed in the sandbox" in page
    file = (tmp_path / "connectivity.svg").read_text()
    assert "<style>" in file and "prefers-color-scheme:dark" in file
    # names are escaped
    evil = cy.model("<x>", {"components": [{"name": "W", "k8s": "w", "role": "worker", "egress": [], "lab_services": {},
                                             "destinations": [{"host": "a.example", "port": 443, "source": "config",
                                                               "file": "f", "line": 1, "quote": "<script>"}]}]})
    assert "<x>" not in cy.svg(evil) and "&lt;x&gt;" in cy.svg(evil)


def test_generate_keeps_approved_entries_and_opens_nothing(tmp_path):
    from containerizer.assess import assess
    from containerizer.generate import generate_app
    a = assess(DEMO)
    out = tmp_path / "gen"
    generate_app(a, out, approved_egress=[{"component": "egress-demo", "destination": "api.github.com", "port": 443,
                                           "protocol": "TCP", "status": "approved"}])
    doc = cy.read(out)
    e, = [x for x in doc["outbound"] if x["destination"] == "api.github.com"]
    assert e["status"] == "approved" and e["sandbox"]["reachable"] is False and e["sandbox"]["blocked_by"] == "network-policy"
    p, = [x for x in doc["outbound"] if x["destination"] == "pastebin.com"]
    assert p["status"] == "not-allowed"
    generate_app(a, tmp_path / "plain")
    assert (out / "egress-demo" / "k8s.yaml").read_text() == (tmp_path / "plain" / "egress-demo" / "k8s.yaml").read_text()


def test_a_later_scan_keeps_approved_egress(tmp_path, monkeypatch):
    """org.deploy_app (every organization scan, and the sandbox variants) reads the application's connectivity.yaml
    from the output repository: the approved entries stay as written; the NetworkPolicy stays as inferred."""
    import dataclasses
    from containerizer import org as orgmod
    from containerizer.assess import assess
    from containerizer.gitops import GitOpsOptions
    src = tmp_path / "egress-demo"
    shutil.copytree(DEMO, src)
    a = assess(src)
    a.verification = [{"component": "Egress.Demo", "status": "ok"}]
    o = orgmod.OrgOptions(provider="github", org="lab", registry="localhost/lab", output_dir=str(tmp_path / "out"),
                          push_images=False, gate=False, verify=False, local_images=False)
    out = orgmod.Output(o, tmp_path / "w")
    rel = "lab/_/egress-demo"
    approved = {"component": "egress-demo", "destination": "api.github.com", "type": "fqdn", "port": 443,
                "protocol": "TCP", "status": "approved", "sources": ["config", "observed", "approved"],
                "approved_by": "john.doe@example.com", "approved_at": "2026-11-02T03:43:46Z", "reason": "upstream"}
    sus = {"component": "egress-demo", "destination": "pastebin.com", "type": "fqdn", "port": 443, "protocol": "TCP",
           "status": "suspicious", "sources": ["code", "observed"], "category": "file-sharing"}
    (out.root / rel).mkdir(parents=True)
    (out.root / rel / "connectivity.yaml").write_text(yaml.safe_dump({"outbound": [approved, sus]}))

    def deploy(name):
        res = orgmod.RepoResult(provider="github", org="lab", project="_", repo="egress-demo", status="error")
        return orgmod.deploy_app(dataclasses.replace(a), src, name, o, out, None, "1.0.0", GitOpsOptions(path=name), res,
                                 tmp_path / f"work-{name.replace('/', '-')}", "egress-demo")
    assert deploy(rel).status == "deployed"
    pol = [d for d in yaml.safe_load_all((out.root / rel / "egress-demo" / "k8s.yaml").read_text())
           if d and d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "egress-demo"][0]
    assert not any({"port": 443, "protocol": "TCP"} in (r.get("ports") or []) for r in pol["spec"]["egress"])
    assert pol["metadata"]["annotations"]["containerizer.io/egress"] == "none"
    doc = cy.read(out.root / rel)
    got = {e["destination"]: e for e in doc["outbound"]}

    def plain(e):
        return {k: v for k, v in e.items() if k != "sandbox"}     # computed again on every write
    assert plain(got["api.github.com"]) == approved           # as written, nothing rewritten
    assert got["api.github.com"]["sandbox"]["reachable"] is False
    assert got["pastebin.com"]["status"] == "suspicious"
    # and again: still there after a second scan
    assert deploy(rel).status == "deployed" and cy.read(out.root / rel)["outbound"][0]
    assert plain({e["destination"]: e for e in cy.read(out.root / rel)["outbound"]}["api.github.com"]) == approved
    # a sandbox variant takes the original's approved egress
    res = orgmod.RepoResult(provider="github", org="lab", project="_", repo="v", status="error")
    orgmod.deploy_app(dataclasses.replace(a), src, "lab/_/egress-demo-refactor-4", o, out, None, "1.0.0-refactor.4",
                      GitOpsOptions(path="lab/_/egress-demo-refactor-4"), res, tmp_path / "wv", "egress-demo-refactor-4",
                      connectivity_from=out.root / rel)
    v = {e["destination"]: e for e in cy.read(out.root / "lab/_/egress-demo-refactor-4")["outbound"]}
    assert v["api.github.com"]["status"] == "approved"


# --------------------------------------------------------------------------- approving

@pytest.fixture
def adm():
    pytest.importorskip("jwt")
    from containerizer import admin as adminmod
    from containerizer.oidc import OidcConfig
    c = OidcConfig(issuer="https://idp.example.com", client_id="cz", client_secret="s", public_url="https://cz.example.com",
                   admins=["group:a"])
    conn = FakeConn()
    a = adminmod.Admin(c, lambda: conn, provider=object())
    a.conn = conn
    return a


def _post(adm, sid, path, csrf=None, **form):
    s = adm.sessions.get(sid)
    return adm.handle("POST", path, "", {"Cookie": f"{adm.cookie}={sid}"},
                      urlencode({"csrf": csrf if csrf is not None else s.csrf, **form}, doseq=True).encode())


def _loc(r):
    return dict(r.headers)["Location"]


def test_approve_and_reject_need_the_role_the_product_and_the_csrf_token(adm):
    rows = {3: {"DecisionId": 3, "ApplicationId": 7, "Verdict": "propose", "Status": "proposed", "Destination": "api.github.com"},
            4: {"DecisionId": 4, "ApplicationId": 7, "Verdict": "suspicious", "Status": "suspicious", "Destination": "pastebin.com"},
            5: {"DecisionId": 5, "ApplicationId": 8, "Verdict": "propose", "Status": "proposed", "Destination": "x.example"}}
    adm.conn.answers = {r"FROM cz.EgressDecision WHERE DecisionId": lambda p: [rows[p[0]]] if p[0] in rows else [],
                        r"SELECT ProductId FROM cz.Application": lambda p: [{"ProductId": 1 if p[0] == 7 else 2}],
                        r"FROM cz.BusinessUnit": [], r"FROM cz.Product": [{"Id": 1, "Name": "Shop", "BusinessUnitId": None}]}
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    assert _post(adm, viewer, "/admin/egress/3/approve").status == 403
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _post(adm, op, "/admin/egress/3/approve", csrf="wrong").status == 403
    assert not adm.conn.sql("UPDATE cz.EgressDecision")
    r = _post(adm, op, "/admin/egress/3/approve", back="app")
    assert _loc(r) == "/app/7?egress=approved#connectivity"
    (sql, params), = adm.conn.sql("UPDATE cz.EgressDecision")
    assert params[:3] == ("approved", "o@example.com", "O") and params[3] == 3 and "CommittedAt = NULL" in sql
    # a suspicious destination is never approved; it can be rejected
    assert _loc(_post(adm, op, "/admin/egress/4/approve")) == "/admin/egress?notice=not-allowed"
    _post(adm, op, "/admin/egress/4/reject")
    assert adm.conn.sql("UPDATE cz.EgressDecision")[-1][1][0] == "rejected"
    # product owners: their products only
    owner = adm.sessions.create("p@example.com", "P", False, True, False, ["product:Shop"])
    assert _loc(_post(adm, owner, "/admin/egress/5/approve", back="app")) == "/app/8?egress=not-yours#connectivity"
    n = len(adm.conn.sql("UPDATE cz.EgressDecision"))
    _post(adm, owner, "/admin/egress/3/approve")
    assert len(adm.conn.sql("UPDATE cz.EgressDecision")) == n + 1
    assert _post(adm, op, "/admin/egress/99/approve").status == 404


def test_notices_are_fixed_texts():
    from containerizer.admin_egress import notice_html
    from containerizer.connectivityui import notice_code
    assert "approval opens nothing" in notice_html("approved") and notice_html("<script>") == ""
    assert notice_code({"egress": ["<script>"]}) == "" and notice_code({"egress": ["approved"]}) == "approved"


def test_results_page_section():
    from containerizer.connectivityui import section
    app = {"ApplicationName": "shop", "sandbox": [{"ComponentName": "Web", "Namespace": "shop", "Url": "https://web-shop.x/"}],
           "connectivity": {"available": True, "network": NET, "flows": [],
                            "decisions": [{"DecisionId": 3, "Component": "web", "Destination": "api.github.com", "Port": 443,
                                           "Protocol": "TCP", "Verdict": "propose", "Status": "proposed",
                                           "Reason": "<b>upstream</b>", "Evidence": "[]"}]}}
    html = section(app, {"csrf": "<input type='hidden' name='csrf' value='t'>", "egress_notice": "approved"})
    assert "id='connectivity'" in html and "<svg" in html and "&lt;b&gt;upstream&lt;/b&gt;" in html
    assert "action='/admin/egress/3/approve'" in html and "name='back' value='app'" in html
    assert "Missing" in html and "Approved for the real environment" in html and "<th>Sandbox</th>" in html
    anon = section(app, {})
    assert "/admin/egress/" not in anon and "approved by" not in anon
    assert section({**app, "connectivity": {"available": False}}, {}) == ""
    old = section({**app, "connectivity": {"available": True, "network": None, "flows": [], "decisions": []}}, {})
    assert "Scan the application again" in old


# --------------------------------------------------------------------------- the appliance's signals and rules

# as the appliance's kernel logs them (sysagent.render: the egress chain's `log prefix "cz-egress-drop: "`), from
# /dev/kmsg ("<prio>,<seq>,<usec>,<flags>;<text>") and from the journal (-o cat)
KMSG_DROP = ("6,48211,9184322113,-;cz-egress-drop: IN=cni0 OUT=eth0 PHYSIN=veth3c1f2a7e MAC=ce:7d:1a:2b:3c:4d:"
             "6a:11:22:33:44:55:08:00 SRC=10.42.0.25 DST=140.82.121.6 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=50731 DF "
             "PROTO=TCP SPT=43120 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 \n")
JOURNAL_DROP_UDP = ("cz-egress-drop: IN=cni0 OUT=eth0 MAC=ce:7d:1a:2b:3c:4d:6a:11:22:33:44:55:08:00 SRC=10.42.0.26 "
                    "DST=203.0.113.9 LEN=76 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=UDP SPT=40000 DPT=123 LEN=56")
HOST_DROP = ("cz-egress-drop: IN= OUT=eth0 SRC=192.168.8.10 DST=198.51.100.7 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=7 DF "
             "PROTO=TCP SPT=50000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0")
COREDNS_REFUSED = '[INFO] 10.42.0.25:51515 - 7781 "A IN pastebin.com. udp 41 false 1232" REFUSED qr,rd 41 0.0004s'


def test_parses_the_appliance_firewall_drops():
    assert eg.parse_firewall_drop(KMSG_DROP) == ("10.42.0.25", "140.82.121.6", "TCP", 443)
    assert eg.parse_firewall_drop(JOURNAL_DROP_UDP) == ("10.42.0.26", "203.0.113.9", "UDP", 123)
    assert eg.parse_firewall_drop("cz-in-drop: IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22") is None
    assert eg.parse_firewall_drop("") is None


def _observer(pods=None):
    import time
    kube = FakeKube(pods or {"shop": {"10.42.0.25": ("web-1", "web"), "10.42.0.26": ("worker-1", "worker")}})
    obs = eg.Observer(kube, None, FakeResolver({"api.github.com": {"140.82.121.6"}}), name="t", log=lambda m: None)
    obs._namespaces = (time.monotonic(), ["shop", "kube-system"])
    return obs


def test_firewall_drops_of_application_pods_are_flows_named_from_dns():
    obs = _observer()
    obs.dns_line('[INFO] 10.42.0.25:1 - 2 "A IN api.github.com. udp 32 false 512" NOERROR qr 98 0.01s')
    f = obs.kernel_line(KMSG_DROP.split(";", 1)[1])
    assert (f.namespace, f.component, f.destination, f.named, f.port, f.protocol, f.layer) == \
        ("shop", "web", "api.github.com", True, 443, "TCP", "appliance-firewall")
    g = obs.kernel_line(JOURNAL_DROP_UDP)
    assert (g.destination, g.named, g.port, g.protocol, g.component) == ("203.0.113.9", False, 123, "UDP", "worker")
    assert obs.kernel_line(HOST_DROP) is None                  # the appliance itself, not an application
    conn = FakeConn()
    eg.record(conn, obs.agg.take(), "obs")
    assert {p[-1] for _, p in conn.sql(r"EXEC cz.RecordEgressFlow")} == {"appliance-firewall"}


def test_names_the_dns_filter_refused_are_flows_without_a_port():
    obs = _observer()
    f = obs.dns_line(COREDNS_REFUSED)
    assert (f.namespace, f.component, f.destination, f.named, f.port, f.protocol, f.layer, f.pods) == \
        ("shop", "web", "pastebin.com", True, 0, "ANY", "dns-filter", {"web-1": "10.42.0.25"})
    # the host's own lookups, NXDOMAIN and cluster names are not
    assert obs.dns_line(COREDNS_REFUSED.replace("10.42.0.25", "192.168.8.10")) is None
    assert obs.dns_line(COREDNS_REFUSED.replace("REFUSED", "NXDOMAIN")) is None
    assert obs.dns_line(COREDNS_REFUSED.replace("pastebin.com.", "db.shop.svc.cluster.local.")) is None
    # reviewed by name (no port); a flow without a name and a port is not
    assert eg.prefilter({"Namespace": "shop", "Destination": "api.example.com", "Named": True, "Port": 0,
                         "Protocol": "ANY", "Layer": "dns-filter"}) is None
    assert eg.prefilter({"Namespace": "shop", "Destination": "pastebin.com", "Named": True, "Port": 0,
                         "Protocol": "ANY", "Layer": "dns-filter"})[0] == "suspicious"
    assert eg.prefilter({"Namespace": "shop", "Destination": "x.example", "Named": True, "Port": 0,
                         "Protocol": "ICMP"})[1] == "no-port"


def test_kernel_log_sources(tmp_path):
    assert eg.kernel_source("none") is None and eg.kernel_source("journal") == "journal"
    assert eg.kernel_source(str(tmp_path / "k.log")) == str(tmp_path / "k.log")


def _rules(tmp_path, admin=None, mode="enforce"):
    (tmp_path / "egress-system.json").write_text(json.dumps({"rules": [
        {"host": "ghcr.io", "ports": ["tcp/443"], "note": "appliance upgrades"}]}))
    if admin is not None:
        (tmp_path / "egress.json").write_text(json.dumps({"mode": mode, "rules": admin}))
    return {eg.SYSTEM_RULES_ENV: str(tmp_path / "egress-system.json"), eg.ADMIN_RULES_ENV: str(tmp_path / "egress.json")}


def test_appliance_rules_are_read_as_sysagent_reads_them(tmp_path):
    assert eg.appliance_rules({eg.SYSTEM_RULES_ENV: str(tmp_path / "none.json")}) is None          # a lab
    env = _rules(tmp_path, [{"host": "github.com", "ports": "443", "note": "upstream API"},
                            {"cidr": "203.0.113.0/24", "ports": ["udp/123"]}])
    r = eg.appliance_rules(env)
    assert [x["origin"] for x in r["rules"]] == ["system", "admin", "admin"] and r["rules"][1]["ports"] == ["tcp/443"]
    v = eg.appliance_verdict("api.github.com", "140.82.121.6", 443, "TCP", r)        # a rule covers its subdomains
    assert v["allowed"] and "github.com tcp/443 (upstream API), administrators rule" in v["text"]
    assert eg.appliance_verdict("api.github.com", None, 0, "ANY", r)["allowed"]        # port unknown: the name
    v = eg.appliance_verdict("api.github.com", None, 8443, "TCP", r)
    assert v["allowed"] is False and v["blocked_by"] == "appliance-firewall" and "not port 8443" in v["text"]
    v = eg.appliance_verdict("pastebin.com", "172.66.171.73", 443, "TCP", r)
    assert v["allowed"] is False and v["blocked_by"] == "dns-filter"
    assert eg.appliance_verdict("203.0.113.9", None, 123, "UDP", r)["allowed"]
    v = eg.appliance_verdict("198.51.100.7", None, 443, "TCP", r)
    assert v["allowed"] is False and v["blocked_by"] == "appliance-firewall"
    assert eg.appliance_verdict("x.example", None, 443, "TCP", None)["text"] == "no appliance firewall (lab)"
    env = _rules(tmp_path, [], mode="log")
    assert eg.appliance_verdict("x.example", None, 443, "TCP", eg.appliance_rules(env))["allowed"]
    # a broken administrators' file allows nothing of it (as sysagent ignores it)
    (tmp_path / "egress.json").write_text("{not json")
    assert [x["origin"] for x in eg.appliance_rules(env)["rules"]] == ["system"]


def test_sandbox_status_and_port_unknown_entries(tmp_path):
    rules = eg.appliance_rules(_rules(tmp_path, [{"host": "github.com", "ports": "443"}]))
    net = {"components": [{"name": "Web", "k8s": "web", "role": "web", "port": 8080, "service_port": 80, "lab_services": {},
                           "egress": [{"id": "http-apis", "ports": [{"port": 443, "protocol": "TCP"}]}],
                           "destinations": [{"host": "api.github.com", "port": 443, "protocol": "TCP", "source": "config",
                                             "file": "a.json", "line": 4, "quote": "q"}]}]}
    refused = {"Namespace": "shop", "Component": "web", "Destination": "pastebin.com", "Named": True, "DestinationIp": None,
               "Port": 0, "Protocol": "ANY", "Packets": 2, "FirstSeen": datetime(2026, 11, 2, 4), "Layer": "dns-filter",
               "LastSeen": datetime(2026, 11, 2, 4), "Pods": "[]"}
    named_refused = {**refused, "Destination": "api.github.com"}
    doc = cy.model("shop", net, [refused, named_refused], appliance=rules)
    out = {e["destination"]: e for e in doc["outbound"]}
    gh = out["api.github.com"]
    assert gh["port"] == 443 and "observed" in gh["sources"] and gh["blocked_by"] == ["dns-filter"]   # the inferred port
    assert gh["sandbox"]["reachable"] is True and "github.com tcp/443" in gh["sandbox"]["rule"]
    pb = out["pastebin.com"]
    assert pb["port"] == 0 and pb["port_unknown"] and pb["sandbox"]["blocked_by"] == "network-policy"
    assert "pastebin.com (port unknown)" in cy.svg(doc) and "| shop | pastebin.com | unknown |" not in cy.markdown(doc)
    assert "| web | pastebin.com | unknown |" in cy.markdown(doc)
    # a decision on the port-unknown flow of a destination the configuration names lands on its entry
    dec = [{"DecisionId": 9, "Component": "web", "Destination": "api.github.com", "Port": 0, "Protocol": "ANY",
            "Verdict": "propose", "Status": "approved", "Reason": "r", "Evidence": "[]", "DecidedBy": "john.doe@example.com",
            "DecidedAt": datetime(2026, 11, 2, 5)}]
    doc = cy.model("shop", net, [named_refused], dec, appliance=rules)
    gh, = [e for e in doc["outbound"] if e["destination"] == "api.github.com"]
    assert (gh["port"], gh["status"], gh["approved_by"]) == (443, "approved", "john.doe@example.com")
    # in the lab: no appliance firewall; an approved destination the NetworkPolicy does not open stays unreachable
    net["components"][0]["egress"] = []
    doc = cy.model("shop", net, [named_refused], dec, appliance=None)
    gh, = [e for e in doc["outbound"] if e["destination"] == "api.github.com"]
    assert gh["sandbox"] == {"network_policy": "blocks port 443", "appliance": "no appliance firewall (lab)",
                             "reachable": False, "blocked_by": "network-policy"}
    assert "cf-approved cf-unreachable" in cy.svg(doc)
    assert yaml.safe_load(cy.to_yaml(doc))["outbound"][0]["sandbox"]["reachable"] is False


# --------------------------------------------------------------------------- SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_schema_24_flows_decisions_and_the_logins():
    """The writer records flows (adding up) and decisions, the namespace maps to the application through its sandbox
    check, the admin login approves through its column grants (audited), the reader sees the views only."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czegress_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT MAX(Version) FROM cz.SchemaVersion")
    assert cur.fetchone()[0] >= 24
    cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'k', N'shop')")
    cur.execute("SELECT ApplicationId FROM cz.Application WHERE SourceKey = N'k'")
    app_id = cur.fetchone()[0]
    cur.execute("INSERT cz.ApplicationAssessment (ApplicationId, Rating, Score, Confidence, Summary, Verified, ReportJson) "
                "VALUES (%s, N'A', 95, 0.9, N's', 1, %s)", (app_id, json.dumps({"network": NET})))
    cur.execute("INSERT cz.SandboxCheck (ApplicationId, Status, Namespace) VALUES (%s, N'healthy', N'shop')", (app_id,))
    conn.commit()
    for login, role in (("cz_eg_admin", "admin"), ("cz_eg_reader", "reader"), ("cz_eg_writer", "writer")):
        sqlstore.create_login(conn, login, pw, role)
    conn.close()

    def as_(login):
        return sqlstore.connect(re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs), pw)
    w = as_("cz_eg_writer")
    t = datetime(2026, 11, 2, 3, 38)
    f = eg.Flow("shop", "web", "api.github.com", True, 443, "TCP", packets=2, first=t, last=t, ip="140.82.121.6",
                pods={"web-1": "10.42.0.25"}, policy="shop/web")
    eg.record(w, [f], "t")
    f.packets, f.last = 3, datetime(2026, 11, 2, 3, 40)
    eg.record(w, [f], "t")
    flows = eg.new_flows(w)
    assert len(flows) == 1 and flows[0]["Packets"] == 5 and flows[0]["ApplicationId"] == app_id and eg.eligible(flows[0])
    eg.insert_decisions(w, app_id, [{**eg.flow_item(flows[0]), "verdict": "propose", "reason": "upstream",
                                     "evidence": [{"file": "a", "line": 1, "quote": "q", "verified": True}]}], None)
    eg.insert_decisions(w, app_id, [{**eg.flow_item(flows[0]), "verdict": "report", "reason": "again"}], None)
    assert eg.new_flows(w) == []
    c = w.cursor(as_dict=True)
    c.execute("SELECT DecisionId, Status, Reason FROM cz.vEgressDecision")
    d, = c.fetchall()
    assert (d["Status"], d["Reason"]) == ("proposed", "upstream")            # the first decision stays
    with pytest.raises(Exception):
        c.execute("UPDATE cz.EgressDecision SET Status = N'approved' WHERE DecisionId = %s", (d["DecisionId"],))
    w.rollback()
    # the admin login approves (its column grants), audited; it cannot write flows
    adm = as_("cz_eg_admin")
    adm.set_user("john.doe@example.com", "John Doe", role="operator")
    ac = adm.cursor()
    ac.execute("UPDATE cz.EgressDecision SET Status = N'approved', DecidedBy = %s, DecidedByName = %s, "
               "DecidedAt = SYSUTCDATETIME(), CommittedAt = NULL WHERE DecisionId = %s AND Status IN (N'proposed')",
               ("john.doe@example.com", "John Doe", d["DecisionId"]))
    assert ac.rowcount == 1
    adm.commit()
    with pytest.raises(Exception):
        ac.execute("EXEC cz.RecordEgressFlow @Namespace = N'x', @Component = N'', @Destination = N'y', @Named = 0, "
                   "@Port = 1, @Protocol = N'TCP', @Packets = 1, @FirstSeen = '2026-01-01', @LastSeen = '2026-01-01'")
    adm.rollback()
    ac2 = adm.cursor(as_dict=True)
    ac2.execute("SELECT TOP (1) ChangedBy, TableName, NewValues FROM cz.AuditLog ORDER BY AuditId DESC")
    log = ac2.fetchone()
    assert log["ChangedBy"] == "john.doe@example.com" and log["TableName"] == "EgressDecision"
    # the writer records the commit
    eg._mark(w, [d["DecisionId"]], "a" * 40, None)
    rd = as_("cz_eg_reader")
    rc = rd.cursor(as_dict=True)
    rc.execute("SELECT Status, DecidedBy, CommitRevision FROM cz.vEgressDecision")
    assert rc.fetchone() == {"Status": "approved", "DecidedBy": "john.doe@example.com", "CommitRevision": "a" * 40}
    rc.execute("SELECT NetworkJson FROM cz.vNetworkLatest WHERE ApplicationId = %s", (app_id,))
    assert json.loads(rc.fetchone()["NetworkJson"])["components"][0]["k8s"] == "web"
    rc.execute("SELECT Packets, Layer FROM cz.vEgressFlow")
    assert rc.fetchone() == {"Packets": 5, "Layer": "network-policy"}
    # a name the appliance's DNS filter refused: no port, the layer that blocked it
    eg.record(w, [eg.Flow("shop", "web", "pastebin.com", True, 0, "ANY", packets=1, first=t, last=t, layer="dns-filter")], "t")
    rc.execute("SELECT Port, Protocol, Layer FROM cz.vEgressFlow WHERE Destination = N'pastebin.com'")
    assert rc.fetchone() == {"Port": 0, "Protocol": "ANY", "Layer": "dns-filter"}
    with pytest.raises(Exception):
        rc.execute("SELECT * FROM cz.EgressFlow")
    for x in (w, adm, rd):
        x.close()


def test_cluster_dns_drops_are_no_destination():
    """A drop to port 53 of a cluster address is kube-router catching up with a new pod: neither the observer nor
    the model makes it a destination (it was in the lab's data before the observer left them out)."""
    dns = {"Namespace": "shop", "Component": "web", "Destination": "10.42.0.9", "Named": False, "DestinationIp": "10.42.0.9",
           "Port": 53, "Protocol": "UDP", "Packets": 31, "FirstSeen": datetime(2026, 11, 2, 4),
           "LastSeen": datetime(2026, 11, 2, 4), "Pods": "[]"}
    dec = {"DecisionId": 5, "Component": "web", "Destination": "10.42.0.9", "Port": 53, "Protocol": "UDP",
           "Verdict": "in-cluster", "Status": "reported", "Reason": "r", "Evidence": "[]"}
    doc = cy.model("shop", NET, [dns, {**dns, "Destination": "8.8.8.8", "DestinationIp": "8.8.8.8"}], [dec], appliance=None)
    assert [e["destination"] for e in doc["outbound"] if e["port"] == 53] == ["8.8.8.8"]
