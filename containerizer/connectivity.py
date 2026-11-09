"""The network connectivity an application needs (docs/egress.md#network-connectivity), from every source
Containerizer has, each entry marked by where it comes from:

- **inferred** by the assessment (`infer`, assessment.json "network"): the components' service ports, the
  destinations their configuration and code name (URLs and connection strings, with file and line), the
  dependencies the generated NetworkPolicy opens a port for (harden.egress_for: packages, code, configured
  ports) and the lab services they need;
- **policy**: what the generated NetworkPolicy allows (those ports to any address but the blocked ranges, the
  application's own pods, DNS);
- **observed** in the sandbox: the connections a NetworkPolicy dropped (egress.py, the observer);
- **approved**: egress a person approved after the egress review (cz.EgressDecision), kept in the output
  repository's connectivity.yaml.

`model()` merges them into one document: inbound (Ingress hosts, service ports), internal (component to
component, lab services), outbound (every destination with its port, protocol, sources, status, reason,
evidence and who approved it) and the findings: *missing* (the configuration names a destination nothing
allows: it will time out) and *unexplained* (a port the NetworkPolicy opens that no configuration names, or an
approved destination the configuration no longer names). The same document is the results page's section
(webui), and connectivity.yaml / CONNECTIVITY.md / connectivity.svg next to the application's manifests in the
output repository (write_files), for the platform or firewall team that writes the real environment's rules.

Approved entries are never rewritten or dropped: `merge_outbound` keeps every approved entry of the existing
connectivity.yaml exactly as it is (only its computed sandbox status changes), and org.deploy_app passes them to the
generator, so later scans keep them. Approval documents a destination for the real environment and opens nothing
in the sandbox; `sandbox_status` says whether the sandbox can reach each destination (its NetworkPolicy, and on the
appliance its egress rules).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import yaml

API_VERSION = "containerizer.eu/v1"
FILE = "connectivity.yaml"
MARKDOWN = "CONNECTIVITY.md"
SVG = "connectivity.svg"
MAX_DESTINATIONS = 40                   # per component, inferred from configuration and code
MAX_LINE = 200
SCHEME_PORTS = {"https": 443, "http": 80, "wss": 443, "ws": 80, "amqps": 5671, "amqp": 5672, "redis": 6379,
                "rediss": 6380, "mongodb": 27017, "mongodb+srv": 27017, "ldaps": 636, "ldap": 389, "smtps": 465,
                "smtp": 587, "sftp": 22, "ftp": 21, "ftps": 990, "grpc": 443, "nats": 4222, "mqtt": 1883,
                "mqtts": 8883, "kafka": 9092, "postgres": 5432, "postgresql": 5432, "mysql": 3306,
                "sqlserver": 1433, "jdbc:sqlserver": 1433}
URL_RE = re.compile(r"\b(?P<scheme>https?|wss?|amqps?|rediss?|mongodb(?:\+srv)?|ldaps?|smtps?|sftp|ftps?|grpc|nats|"
                    r"mqtts?|kafka|postgres(?:ql)?|mysql|jdbc:sqlserver)://(?:[^@/\s\"'<>]*@)?"
                    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)"
                    r"(?::(?P<port>\d{1,5}))?", re.I)
# connection strings: "Server=db.example.com,1433", "Data Source=tcp:db,1433", "Host=pg;Port=5433"
CONN_RE = re.compile(r"(?i)\b(?:Server|Data Source|Address|Addr|Network Address)\s*=\s*(?:tcp:)?"
                     r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?:\\[\w$]+)?(?:\s*,\s*(?P<port>\d{1,5}))?")
HOSTPORT_RE = re.compile(r"(?i)\bHost\s*=\s*(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)\s*;"
                         r"(?:[^;\"]*;)*?\s*Port\s*=\s*(?P<port>\d{1,5})")
# names in configuration that are documentation, schemas or placeholders, not destinations
NOISE_HOSTS = re.compile(r"(?i)^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1?\]|\*|\+|\.|"
                         r"(?:[\w-]+\.)*(?:w3\.org|xmlsoap\.org|schemas\.microsoft\.com|schemas\.openxmlformats\.org|"
                         r"json-schema\.org|schema\.org|aka\.ms|go\.microsoft\.com|learn\.microsoft\.com|"
                         r"docs\.microsoft\.com|msdn\.microsoft\.com|xmlns\.oracle\.com|apache\.org|"
                         r"example\.(?:com|org|net)|tempuri\.org|purl\.org|opensource\.org|spdx\.org))$")
CODE_COMMENT = re.compile(r"^\s*(?://|/\*|\*|#|<!--|'|--|REM\b)")
SKIP_FILE = re.compile(r"(?i)(\.Development\.|launchSettings|(^|/)\.vscode/|(^|/)\.idea/|(^|/)(bin|obj|node_modules|"
                       r"dist|build|target|wwwroot/lib)/|\.min\.js$|swagger|openapi|package(-lock)?\.json$)")
STATUSES = ("allowed", "approved", "proposed", "blocked", "not-allowed", "suspicious", "rejected", "reported", "linked",
            "link-proposed")
STATUS_TEXT = {"allowed": "Allowed", "approved": "Approved (documented)", "proposed": "Proposed", "blocked": "Blocked",
               "not-allowed": "Not allowed (will time out)", "suspicious": "Suspicious", "rejected": "Rejected",
               "reported": "Blocked (reported)", "linked": "Linked", "link-proposed": "Link proposed"}
SOURCE_TEXT = {"config": "configuration", "code": "code", "package": "package", "policy": "NetworkPolicy",
               "observed": "observed in the sandbox", "approved": "approved", "lab-service": "lab service",
               "ingress": "Ingress", "service": "service port", "sibling": "sibling component",
               "link": "linked application", "link-config": "configuration matches", "link-observed": "observed call",
               "link-llm": "LLM", "link-manual": "linked by hand"}
INFERRED = ("allowed", "not-allowed")                # what a scan alone can say about a destination
DECIDED = ("approved", "rejected", "proposed", "suspicious", "reported", "linked", "link-proposed")
KEPT = ("approved", "linked")                         # never rewritten or dropped by a scan
DEC_STATUS = {"proposed": "proposed", "reported": "reported", "suspicious": "suspicious", "approved": "approved",
              "rejected": "rejected"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _k8s(name: str) -> str:
    from .generate import k8s_name
    return k8s_name(name)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def _placeholder(host: str) -> bool:
    return bool(re.search(r"[{}$%]", host) or re.match(r"(?:your|my|some)[-.]|xxx", host, re.I))


# --------------------------------------------------------------------------- inferred at assessment time

def line_hosts(line: str) -> list[tuple[str, int | None, str]]:
    """(host, port or None, scheme) of every URL and connection string on one line."""
    hits = []
    for m in URL_RE.finditer(line):
        sch = m["scheme"].lower()
        hits.append((m["host"], int(m["port"]) if m["port"] else SCHEME_PORTS.get(sch), sch))
    for rx in (CONN_RE, HOSTPORT_RE):
        for m in rx.finditer(line):
            hits.append((m["host"], int(m["port"]) if m["port"] else None, "connection-string"))
    return hits


def _scan_destinations(repo, c, any_port: bool = False) -> list[dict]:
    """Destinations the component's configuration and code name: {host, port, protocol, scheme, source, file,
    line, quote}. Development settings, comments, documentation and schema URLs are left out. `any_port` keeps
    names without a known port too ("Server=db;Database=x"; port None)."""
    from .harden import _projects
    from .rules import Context, _candidate_files
    out: list[dict] = []
    seen: set = set()
    for kind in ("config", "code"):
        for p in _projects(repo, c):
            ctx = Context(repo, p, c.role)
            for f in _candidate_files(ctx, kind, None):
                rel = repo.rel(f).replace("\\", "/")
                if SKIP_FILE.search(rel):
                    continue
                try:
                    text = ctx.text(f, False)
                except Exception:  # noqa: BLE001 - unreadable file: nothing to infer
                    continue
                for n, line in enumerate(text.splitlines(), 1):
                    if len(line) > 2000 or (kind == "code" and CODE_COMMENT.match(line)):
                        continue
                    for host, port, sch in line_hosts(line):
                        host = host.lower().rstrip(".")
                        if NOISE_HOSTS.match(host) or _placeholder(host) or \
                                (port is None and not any_port) or port is not None and not 0 < port < 65536:
                            continue
                        key = (host, port)
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append({"host": host, "port": port, "protocol": "TCP", "scheme": sch, "source": kind,
                                    "file": rel, "line": n, "quote": line.strip()[:MAX_LINE]})
                        if len(out) >= MAX_DESTINATIONS:
                            return out
    return out


def infer(a) -> dict:
    """assessment.json "network": per server component its role, container and service port, the dependencies
    the generated NetworkPolicy opens (egress_for), the destinations configuration and code name, and the lab
    services it needs. Never raises: a component that cannot be read has an "error"."""
    from .generate import CONTAINER_PORT, buildable
    comps = []
    for c in a.components:
        if c.tier not in ("server", "platform"):
            continue
        d = {"name": c.name, "k8s": _k8s(c.name), "role": c.role, "buildable": bool(buildable(c))}
        if c.role in ("web", "spa"):
            d.update(port=CONTAINER_PORT, service_port=80)
        try:
            from .harden import egress_for
            d["egress"] = egress_for(a.repo, c)
        except Exception as ex:  # noqa: BLE001
            d["egress"], d["error"] = [], f"{type(ex).__name__}: {ex}"[:200]
        try:
            d["destinations"] = _scan_destinations(a.repo, c) if c.role != "spa" else []
        except Exception as ex:  # noqa: BLE001
            d["destinations"], d["error"] = [], f"{type(ex).__name__}: {ex}"[:200]
        try:
            from .labservices import needs
            d["lab_services"] = needs(a.repo, c)
        except Exception:  # noqa: BLE001
            d["lab_services"] = {}
        comps.append(d)
    return {"version": 1, "components": comps}


# --------------------------------------------------------------------------- the model

def _key(comp: str, dest: str, port, proto: str) -> tuple:
    return (str(comp or ""), str(dest or "").lower(), int(port or 0), str(proto or "TCP").upper())


def entry_key(e: dict) -> tuple:
    return _key(e.get("component"), e.get("destination"), e.get("port"), e.get("protocol"))


def _iso(t) -> str | None:
    if t is None:
        return None
    if isinstance(t, str):
        return t
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(s, default):
    import json
    if s is None or s == "":
        return default
    if isinstance(s, (list, dict)):
        return s
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return default


LAYER_TEXT = {"network-policy": "the NetworkPolicy", "appliance-firewall": "the appliance firewall",
              "dns-filter": "the appliance's DNS filter"}


def sandbox_status(entries: list[dict], comps: list[dict], appliance="auto") -> None:
    """Whether the sandbox can reach each outbound destination (entry["sandbox"]): its NetworkPolicy must allow the
    port (inferred dependencies only: approval never opens one) and, on the appliance, an administrators' or system
    egress rule must allow the destination (the firewall and the DNS filter let nothing else out)."""
    if appliance == "auto":
        from .egress import appliance_rules
        try:
            appliance = appliance_rules()
        except Exception:  # noqa: BLE001 - no status rather than no page
            appliance = None
    from .egress import appliance_verdict
    by = {c.get("k8s"): c for c in comps}
    for e in entries:
        if e.get("type") == "component":
            e["sandbox"] = {"reachable": e.get("status") == "linked", "network_policy":
                            "allows (confirmed link)" if e.get("status") == "linked" else "blocks until the link is confirmed",
                            "appliance": "inside the sandbox cluster"}
            continue
        port = int(e.get("port") or 0)
        proto = str(e.get("protocol") or "TCP").upper()
        open_ports = policy_ports(by.get(e.get("component")) or {})
        policy_ok = e.get("type") == "any" or (port, proto) in open_ports
        ips = ((e.get("observed") or {}).get("ips") or [None])
        if e.get("type") == "any":
            ap = {"allowed": None, "text": "only the destinations the appliance's egress rules allow"} if appliance \
                else {"allowed": None, "text": "no appliance firewall (lab)"}
        else:
            ap = appliance_verdict(str(e.get("destination") or ""), ips[0], port, proto, appliance)
        st = {"network_policy": ("allows" if policy_ok else "blocks") + (f" port {port}" if port else ""),
              "appliance": ap["text"]}
        if ap.get("rule"):
            st["rule"] = ap["rule"]
        if not policy_ok:
            st["reachable"], st["blocked_by"] = False, "network-policy"
        elif ap.get("allowed") is False:
            st["reachable"], st["blocked_by"] = False, ap.get("blocked_by")
        else:
            st["reachable"] = True if ap.get("allowed") or appliance is None else None
        e["sandbox"] = st


def cluster_dns(f: dict) -> bool:
    """A drop to port 53 of a cluster address: kube-router catching up with a pod that just started (every generated
    NetworkPolicy allows the cluster's DNS), not an outbound need (egress.Observer leaves them out too)."""
    if int(f.get("Port") or 0) != 53:
        return False
    from .egress import _in, review_settings
    return _in(str(f.get("DestinationIp") or f.get("Destination") or ""), review_settings().get("cluster_cidrs"))


def fold_unnamed(flows: list[dict]) -> list[dict]:
    """Flows without a name whose address a named flow of the same namespace, component and port had (the
    observer learned the name later): the named flow explains them, so they are left out; so are cluster DNS
    drops (cluster_dns)."""
    flows = [f for f in flows if not cluster_dns(f)]
    named = {(f.get("Namespace"), f.get("Component"), int(f.get("Port") or 0), f.get("DestinationIp"))
             for f in flows if f.get("Named") and f.get("DestinationIp")}
    return [f for f in flows if f.get("Named") or
            (f.get("Namespace"), f.get("Component"), int(f.get("Port") or 0), f.get("DestinationIp")) not in named]


def policy_ports(comp: dict) -> set[tuple[int, str]]:
    """(port, protocol) the component's NetworkPolicy opens to any address: the inferred dependencies only
    (approved egress is documented for the real environment, never opened in the sandbox)."""
    return {(int(p["port"]), str(p.get("protocol") or "TCP").upper()) for d in comp.get("egress") or []
            for p in d.get("ports") or []}


def model(app: str, network: dict | None, flows: list[dict] | None = None, decisions: list[dict] | None = None,
          existing: dict | None = None, sandbox: list[dict] | None = None, namespace: str | None = None,
          now: datetime | None = None,
          links_out: list[dict] | None = None, links_in: list[dict] | None = None, appliance="auto") -> dict:
    """The connectivity document of one application (the shape of connectivity.yaml). `appliance`: the appliance
    firewall's egress rules (egress.appliance_rules; "auto": read them here, None: no appliance firewall)."""
    now = now or utcnow()
    network = network or {}
    comps = [c for c in network.get("components") or []]
    for c in comps:
        c.setdefault("k8s", _k8s(c.get("name") or ""))
    by_k8s = {c["k8s"]: c for c in comps}
    flows = fold_unnamed(list(flows or []))
    decisions = [d for d in decisions or [] if not cluster_dns(d)]
    old = [e for e in (existing or {}).get("outbound") or [] if isinstance(e, dict)]
    approved = [e for e in old if e.get("status") == "approved"]
    approved += [{"component": d["Component"], "destination": d["Destination"], "port": d["Port"],
                  "protocol": d["Protocol"]} for d in decisions if d.get("Status") == "approved"]
    out: dict[tuple, dict] = {}

    def add(comp, dest, port, proto, kind, status, source, **kw):
        k = _key(comp, dest, port, proto)
        e = out.get(k)
        if e is None:
            e = out[k] = {"component": comp, "destination": dest, "type": kind, "port": int(port or 0),
                          "protocol": (proto or "TCP").upper(), "status": status, "sources": []}
        if source not in e["sources"]:
            e["sources"].append(source)
        for x, v in kw.items():
            if v not in (None, "", [], {}):
                if x == "evidence":
                    e.setdefault("evidence", [])
                    e["evidence"] += [ev for ev in v if ev not in e["evidence"]]
                else:
                    e.setdefault(x, v)
        return e

    internal, inbound, findings = [], [], []
    siblings = {c["k8s"] for c in comps}
    urls = {}
    for s in sandbox or []:
        if s.get("ComponentName"):
            urls[_k8s(s["ComponentName"])] = s.get("Url")
    for c in comps:
        k = c["k8s"]
        open_ports = policy_ports(c)
        if c.get("port"):
            if urls.get(k):
                inbound.append({"component": k, "from": urls[k], "port": c.get("service_port") or 80,
                                "protocol": "TCP", "source": "ingress", "target_port": c["port"]})
            inbound.append({"component": k, "from": "any namespace (Service)", "port": c.get("service_port") or 80,
                            "protocol": "TCP", "source": "service", "target_port": c["port"]})
        for d in c.get("destinations") or []:
            host, port = d["host"], int(d["port"])
            target = _k8s(host.split(".")[0]) if "." not in host or host.endswith(".svc.cluster.local") else None
            if target and target in siblings and target != k:
                internal.append({"from": k, "to": target, "port": port, "protocol": "TCP", "source": d.get("source"),
                                 "evidence": [{"file": d["file"], "line": d["line"], "quote": d["quote"]}]})
                continue
            ok = (port, "TCP") in open_ports
            e = add(k, host, port, "TCP", "ip" if _is_ip(host) else "fqdn", "allowed" if ok else "not-allowed",
                    d.get("source") or "config",
                    evidence=[{"file": d["file"], "line": d["line"], "quote": d["quote"]}])
            if ok:
                e.setdefault("allowed_by", next((x["id"] for x in c.get("egress") or []
                                                 if any(int(p["port"]) == port for p in x.get("ports") or [])), None))
        for svc, why in (c.get("lab_services") or {}).items():
            from .labservices import LAB_NS, SERVICES
            if svc in SERVICES:
                internal.append({"from": k, "to": f"lab {SERVICES[svc].title}", "port": SERVICES[svc].svc_port,
                                 "protocol": "TCP", "source": "lab-service", "namespace": LAB_NS,
                                 "reason": "; ".join(why)[:300]})
        named_ports = {(e["port"], e["protocol"]) for e in out.values() if e["component"] == k}
        for dep in c.get("egress") or []:
            ports = [(int(p["port"]), str(p.get("protocol") or "TCP").upper()) for p in dep.get("ports") or []]
            if any(p in named_ports for p in ports):
                continue
            for port, proto in ports:
                add(k, "any address", port, proto, "any", "allowed", "policy", allowed_by=dep["id"],
                    reason=f"the NetworkPolicy opens port {port} for {dep['id']} (inferred from packages or code)")
            findings.append({"kind": "unexplained", "component": k,
                             "text": f"{k}: port {', '.join(str(p) for p, _ in ports)} is open to any address for "
                                     f"{dep['id']}, but no configuration names a destination on it: keep it only if the "
                                     "application needs it, and name the destination for the production firewall"})
    # links to components of other applications (links.py): the destination is that component
    link_svc: dict[tuple, tuple] = {}           # (component, service name) -> the link entry's key
    for lo in links_out or []:
        st = lo.get("Status")
        if st not in ("confirmed", "proposed", "unresolved"):
            continue
        comp, dest = lo["FromComponent"], lo["Destination"]
        base = out.get(_key(comp, dest, lo["Port"], lo.get("Protocol")))
        if st == "unresolved":
            if base is not None:
                base["link"] = {"id": int(lo["LinkId"]), "status": "unresolved", "reason": lo.get("Reason")}
            continue
        ns = lo.get("ToNamespace") or _k8s(lo.get("ToApplication") or "")
        target = {"application": lo.get("ToApplication"), "application_id": lo.get("ToApplicationId"),
                  "component": lo.get("ToComponent"), "namespace": ns,
                  "service": f"{lo.get('ToComponent')}.{ns}.svc.cluster.local", "port": int(lo.get("ToPort") or 8080)}
        e = add(comp, dest, lo["Port"], lo.get("Protocol"), "component", "linked" if st == "confirmed" else "link-proposed",
                f"link-{lo.get('Method')}", evidence=[x for x in _json(lo.get("Evidence"), []) if x.get("file")])
        e.update(type="component", target=target, status="linked" if st == "confirmed" else "link-proposed",
                 link={"id": int(lo["LinkId"]), "status": st, "method": lo.get("Method"),
                       "confidence": float(lo["Confidence"]) if lo.get("Confidence") is not None else None,
                       "reason": lo.get("Reason")})
        e.pop("allowed_by", None)
        if st == "confirmed":
            e["linked_by"], e["linked_at"] = lo.get("DecidedBy"), _iso(lo.get("DecidedAt"))
        link_svc[(comp, target["service"])] = entry_key(e)
    for li in links_in or []:
        if li.get("Status") != "confirmed":
            continue
        inbound.append({"component": li["ToComponent"], "from": f"{li.get('FromApplication')}/{li['FromComponent']}",
                        "port": int(li.get("ToPort") or 8080), "protocol": li.get("Protocol") or "TCP", "source": "link",
                        "application": li.get("FromApplication"), "application_id": li.get("FromApplicationId"),
                        "from_component": li["FromComponent"],
                        "namespace": li.get("FromNamespace") or _k8s(li.get("FromApplication") or ""),
                        "target_port": int(li.get("ToPort") or 8080), "link": int(li["LinkId"])})
    for e in (existing or {}).get("inbound") or []:            # confirmed callers stay, as approved egress does
        if isinstance(e, dict) and e.get("source") == "link" and not any(
                i.get("source") == "link" and i.get("from") == e.get("from") and i.get("component") == e.get("component")
                for i in inbound):
            inbound.append(e)
    # a blocked call to a linked component is the link's evidence, not a destination of its own; so is a call to
    # another pod address on the same port that the observer could not name (a replica it did not know yet)
    linked = set(link_svc)
    linked_ports, folded_ips = set(), set()
    kept = []
    for f in flows:
        k = (f.get("Component") or "", str(f.get("Destination") or "").lower())
        if k in linked:
            e = out[link_svc[k]]
            ob = e.setdefault("observed", {"packets": 0, "last_seen": None})
            ob["packets"] = int(ob.get("packets") or 0) + int(f.get("Packets") or 0)
            ob["last_seen"] = max(x for x in (ob.get("last_seen"), _iso(f.get("LastSeen"))) if x) if \
                (ob.get("last_seen") or f.get("LastSeen")) else None
            linked_ports.add((k[0], int(f.get("Port") or 0)))
        else:
            kept.append(f)
    from .egress import review_settings, _in
    cluster = review_settings().get("cluster_cidrs") or []
    flows = []
    for f in kept:
        if not f.get("Named") and (f.get("Component") or "", int(f.get("Port") or 0)) in linked_ports \
                and _in(str(f.get("DestinationIp") or f.get("Destination") or ""), cluster):
            folded_ips.add((f.get("Component") or "", str(f.get("Destination") or "").lower(), int(f.get("Port") or 0)))
            continue
        flows.append(f)
    decisions = [d for d in decisions if (d.get("Component"), str(d.get("Destination") or "").lower()) not in linked
                 and (d.get("Component"), str(d.get("Destination") or "").lower(), int(d.get("Port") or 0)) not in folded_ips]
    for f in flows:
        comp = f.get("Component") or ""
        e = None
        if not int(f.get("Port") or 0):
            # the DNS filter refused the name, so no port is known: the destination the configuration names, if any
            e = next((x for x in out.values() if x["component"] == comp
                      and str(x["destination"]).lower() == str(f["Destination"]).lower()), None)
            if e is not None and "observed" not in e["sources"]:
                e["sources"].append("observed")
        if e is None:
            e = add(comp, f["Destination"], f["Port"], f["Protocol"], "fqdn" if f.get("Named") else "ip", "blocked",
                    "observed")
            if not int(f.get("Port") or 0):
                e["port_unknown"] = True
        layers = e.setdefault("blocked_by", [])
        if (f.get("Layer") or "network-policy") not in layers:
            layers.append(f.get("Layer") or "network-policy")
        ob = e.setdefault("observed", {"packets": 0, "first_seen": None, "last_seen": None, "pods": [], "ips": []})
        ob["packets"] += int(f.get("Packets") or 0)
        fs, ls = _iso(f.get("FirstSeen")), _iso(f.get("LastSeen"))
        if fs and (not ob["first_seen"] or fs < ob["first_seen"]):
            ob["first_seen"] = fs
        if ls and (not ob["last_seen"] or ls > ob["last_seen"]):
            ob["last_seen"] = ls
        for p in _json(f.get("Pods"), []):
            if isinstance(p, dict) and p.get("pod") and p["pod"] not in ob["pods"] and len(ob["pods"]) < 5:
                ob["pods"].append(p["pod"])
        if f.get("DestinationIp") and f["DestinationIp"] not in ob["ips"] and len(ob["ips"]) < 5:
            ob["ips"].append(f["DestinationIp"])
        if f.get("Namespace"):
            e.setdefault("namespace", f["Namespace"])
        if e["status"] in ("allowed",):
            e["status"] = "blocked"             # inferred as allowed, but the sandbox dropped it
    for d in decisions:
        if not int(d.get("Port") or 0):
            e0 = next((x for x in out.values() if x["component"] == d["Component"]
                       and str(x["destination"]).lower() == str(d["Destination"]).lower() and x["port"]), None)
            if e0 is not None:
                d = {**d, "Port": e0["port"], "Protocol": e0["protocol"]}
                out.pop(_key(d["Component"], d["Destination"], 0, "ANY"), None)
        e = add(d["Component"], d["Destination"], d["Port"], d["Protocol"],
                "fqdn" if d.get("Verdict") not in ("unnamed",) and not _is_ip(d["Destination"]) else "ip",
                DEC_STATUS.get(d["Status"], "reported"), "observed",
                reason=d.get("Reason"), evidence=[ev for ev in _json(d.get("Evidence"), []) if ev.get("verified", True)])
        e["status"] = DEC_STATUS.get(d["Status"], "reported")
        e["verdict"] = d.get("Verdict")
        if d.get("Category"):
            e["category"] = d["Category"]
        if d.get("Reason"):
            e["reason"] = d["Reason"]
        e["decision"] = int(d["DecisionId"]) if d.get("DecisionId") is not None else None
        if d["Status"] in ("approved", "rejected"):
            e["approved_by" if d["Status"] == "approved" else "rejected_by"] = d.get("DecidedBy")
            e["approved_at" if d["Status"] == "approved" else "rejected_at"] = _iso(d.get("DecidedAt"))
            if "approved" not in e["sources"] and d["Status"] == "approved":
                e["sources"].append("approved")
    entries = merge_outbound(old, list(out.values()))
    sandbox_status(entries, comps, appliance)
    # approved entries the configuration no longer names: they stay; say so
    for e in entries:
        if e.get("status") == "link-proposed":
            findings.append({"kind": "link", "component": e.get("component"),
                             "text": f"{e.get('component')}: {e.get('destination')} looks like "
                                     f"{(e.get('target') or {}).get('application')}/{(e.get('target') or {}).get('component')}"
                                     ": confirm the link so both NetworkPolicies allow it"})
        if (e.get("link") or {}).get("status") == "unresolved":
            findings.append({"kind": "link", "component": e.get("component"),
                             "text": f"{e.get('component')}: {e.get('destination')} looks internal, but it is not linked to "
                                     "a component assessed here: link it by hand, or it is outside Containerizer"})
        if e.get("status") == "approved" and not set(e.get("sources") or []) & {"config", "code"}:
            findings.append({"kind": "unexplained", "component": e.get("component"),
                             "text": f"{e.get('component')}: {e.get('destination')}:{e.get('port')} is approved, but no "
                                     "configuration or code of the assessed commit names it: check it is still needed"})
        named_by = set(e.get("sources") or []) & {"config", "code"}
        if named_by and e.get("status") in ("not-allowed", "blocked", "proposed", "reported"):
            what = "configuration" if "config" in named_by else "code"
            state = {"proposed": " (proposed: approve it to document it for the real environment)",
                     "blocked": " (blocked in the sandbox)"}.get(e.get("status"), "")
            findings.append({"kind": "missing", "component": e.get("component"),
                             "text": f"{e.get('component')}: the {what} names {e.get('destination')}:{e.get('port')}, but "
                                     "nothing allows it: the connection fails in the sandbox and behind a default-deny "
                                     f"firewall{state}"})
    ns = namespace or next((f.get("Namespace") for f in flows if f.get("Namespace")), None) or _k8s(app)
    return {"apiVersion": API_VERSION, "kind": "Connectivity", "application": app, "namespace": ns,
            "generatedAt": _iso(now),
            "observed": bool(flows) or bool(decisions) or any("observed" in (e.get("sources") or []) for e in entries),
            "note": ("Approved destinations are documented for the real environment: use them (FQDN, port, protocol) "
                     "for its firewall rules. Approval opens nothing in the sandbox: it stays isolated, its "
                     "NetworkPolicies allow only what was inferred and confirmed links between applications, and on "
                     "the appliance only the administrators' egress rules let anything out."),
            "components": [{"name": c["k8s"], "component": c.get("name"), "role": c.get("role"),
                            "port": c.get("port"), "service_port": c.get("service_port")} for c in comps],
            "inbound": inbound, "internal": internal, "outbound": sorted(entries, key=_sort_key),
            "findings": findings}


def _sort_key(e: dict):
    order = {"suspicious": 0, "not-allowed": 1, "proposed": 2, "blocked": 3, "reported": 4, "approved": 5,
             "allowed": 6, "rejected": 7}
    return (str(e.get("component") or ""), order.get(e.get("status"), 9), str(e.get("destination") or ""),
            int(e.get("port") or 0))


def merge_outbound(existing: list[dict], new: list[dict]) -> list[dict]:
    """Outbound entries: every approved entry of the existing file exactly as it is (never rewritten or dropped:
    what the scan knows now only adds its sources), decided and observed entries carried over (a scan that only
    infers a destination keeps the decision about it: a suspicious one does not become "allowed" because an
    inferred port is open), then the new ones."""
    keep: dict[tuple, dict] = {}
    for e in existing:
        if not isinstance(e, dict) or not e.get("destination"):
            continue
        if e.get("status") in DECIDED or "observed" in (e.get("sources") or []):
            keep[entry_key(e)] = e
    out = dict(keep)
    for e in new:
        k = entry_key(e)
        old = keep.get(k)
        if old is not None and old.get("status") in KEPT:
            # the approved entry stays as written (its sandbox status is computed again); the scan's sources
            # (config, code) are only added to it
            add = [s for s in e.get("sources") or [] if s in ("config", "code") and s not in (old.get("sources") or [])]
            if add:
                keep[k] = out[k] = {**old, "sources": list(old.get("sources") or []) + add}
            continue
        if old is not None and e.get("status") in INFERRED and old.get("status") not in INFERRED:
            merged = {**e, **{x: v for x, v in old.items() if x not in ("sources", "evidence", "allowed_by")}}
            merged["sources"] = list(dict.fromkeys(list(old.get("sources") or []) + list(e.get("sources") or [])))
            ev = list(old.get("evidence") or [])
            merged["evidence"] = ev + [x for x in e.get("evidence") or [] if x not in ev]
            out[k] = merged
            continue
        out[k] = e
    return list(out.values())


def linked_entries(doc: dict | None) -> tuple[list[dict], list[dict]]:
    """The confirmed links of a connectivity.yaml: (outbound to other applications' components, inbound callers);
    the generator opens them in the NetworkPolicies."""
    doc = doc or {}
    out = [e for e in doc.get("outbound") or [] if isinstance(e, dict) and e.get("status") == "linked" and e.get("target")]
    inn = [i for i in doc.get("inbound") or [] if isinstance(i, dict) and i.get("source") == "link"]
    return out, inn


def approved_entries(doc: dict | None) -> list[dict]:
    """The approved outbound entries of a connectivity.yaml (kept by the generator, documented; nothing is opened)."""
    return [e for e in (doc or {}).get("outbound") or [] if isinstance(e, dict) and e.get("status") == "approved"
            and e.get("port")]


def read(folder: Path) -> dict | None:
    f = Path(folder) / FILE
    if not f.is_file():
        return None
    try:
        doc = yaml.safe_load(f.read_text())
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


# --------------------------------------------------------------------------- files

def to_yaml(doc: dict) -> str:
    head = (f"# Network connectivity of {doc.get('application')}: generated by Containerizer (docs/egress.md#connectivityyaml).\n"
            "# Approved outbound entries are kept as they are by every later scan and egress review: to take one\n"
            "# back, remove it here in a commit of your own (and the port from the component's NetworkPolicy).\n")
    clean = _strip(doc)
    return head + yaml.safe_dump(clean, sort_keys=False, allow_unicode=True, width=120)


def _strip(x):
    if isinstance(x, dict):
        return {k: _strip(v) for k, v in x.items() if v not in (None, [], {}) and k != "decision"}
    if isinstance(x, list):
        return [_strip(v) for v in x]
    return x


def markdown(doc: dict) -> str:
    rows = []
    for e in doc.get("outbound") or []:
        ev = "; ".join(f"`{x.get('file')}:{x.get('line')}`" for x in e.get("evidence") or [] if x.get("file"))
        ob = e.get("observed") or {}
        seen = f"{ob.get('packets')} dropped, last {ob.get('last_seen')}" if ob else ""
        who = f"{e.get('approved_by')} {e.get('approved_at') or ''}".strip() if e.get("approved_by") else ""
        sb = e.get("sandbox") or {}
        sbt = ("reachable" if sb.get("reachable") else "not reachable" if sb.get("reachable") is False else "unknown") + \
            (f": {sb.get('appliance')}" if sb else "")
        rows.append(f"| {e.get('component')} | {e.get('destination')} | {_port(e)} | "
                    f"{STATUS_TEXT.get(e.get('status'), e.get('status'))} | "
                    f"{', '.join(SOURCE_TEXT.get(s, s) for s in e.get('sources') or [])} | "
                    f"{_md(e.get('reason') or e.get('allowed_by') or '')} | {ev} | {seen} | {who} | {_md(sbt)} |")
    inbound = [f"| {i['component']} | {i['from']} | {i['port']}/{i['protocol']} → {i.get('target_port')} |"
               for i in doc.get("inbound") or []]
    internal = [f"| {i['from']} | {i['to']} | {i['port']}/{i['protocol']} | {SOURCE_TEXT.get(i.get('source'), i.get('source'))} |"
                for i in doc.get("internal") or []]
    lines = [f"# Network connectivity: {doc.get('application')}", "",
             f"Generated by Containerizer at {doc.get('generatedAt')}. The machine-readable form is "
             f"[{FILE}]({FILE}); the platform or firewall team can write the real environment's rules from it.", "",
             f"![Network connectivity of {doc.get('application')}]({SVG})", "",
             "> " + doc.get("note", ""), ""]
    if not doc.get("observed"):
        lines += ["Not observed in the sandbox yet: everything below is inferred from the code, the configuration "
                  "and the generated NetworkPolicy.", ""]
    lines += ["## Inbound", "", "| Component | From | Port |", "| --- | --- | --- |", *inbound, ""] if inbound else []
    lines += ["## Between components and lab services", "", "| From | To | Port | Source |", "| --- | --- | --- | --- |",
              *internal, ""] if internal else []
    lines += ["## Outbound", "", "| Component | Destination | Port | Status | Sources | Reason | Evidence | Observed | Approved | Sandbox |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |", *rows, ""] if rows else ["## Outbound", "", "None.", ""]
    if doc.get("findings"):
        lines += ["## Findings", ""] + [f"- **{f['kind']}**: {_md(f['text'])}" for f in doc["findings"]] + [""]
    return "\n".join(lines)


def _port(e: dict) -> str:
    return f"{e.get('port')}/{e.get('protocol')}" if int(e.get("port") or 0) else "unknown"


def _md(s: str) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def write_files(folder: Path, doc: dict) -> list[Path]:
    """connectivity.yaml, CONNECTIVITY.md and connectivity.svg in the application's folder."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / FILE).write_text(to_yaml(doc))
    (folder / MARKDOWN).write_text(markdown(doc))
    (folder / SVG).write_text(svg(doc, standalone=True))
    return [folder / FILE, folder / MARKDOWN, folder / SVG]


# --------------------------------------------------------------------------- the diagram

ROW, BOX_H, PAD = 40, 30, 16
COLS = {"in": (10, 230), "comp": (330, 560), "out": (690, 990)}
WIDTH = 1000
LINE_CLASS = {"allowed": "cf-allowed", "approved": "cf-approved", "proposed": "cf-proposed", "blocked": "cf-blocked",
              "not-allowed": "cf-missing", "suspicious": "cf-suspicious", "rejected": "cf-rejected",
              "reported": "cf-blocked", "internal": "cf-internal", "inbound": "cf-inbound", "linked": "cf-linked",
              "link-proposed": "cf-link-proposed", "unreachable": "cf-allowed cf-unreachable"}
LEGEND = (("allowed", "Allowed by the NetworkPolicy"), ("approved", "Approved for the real environment"),
          ("proposed", "Proposed"),
          ("blocked", "Blocked in the sandbox"), ("not-allowed", "Named by configuration, not allowed"),
          ("suspicious", "Suspicious"), ("linked", "Linked application"), ("link-proposed", "Link proposed"),
          ("unreachable", "Dotted: the sandbox cannot reach it"))
SVG_STYLE = """
.cf-bg{fill:#fff}.cf-box{fill:#f4f4f1;stroke:#8a8983;stroke-width:1}.cf-comp{fill:#e8f0fe;stroke:#1f5fbf}
.cf-t{font:13px system-ui,-apple-system,"Segoe UI",sans-serif;fill:#0b0b0b}.cf-s{font:11px system-ui,sans-serif;fill:#5f5e58}
.cf-h{font:600 12px system-ui,sans-serif;fill:#5f5e58;letter-spacing:.04em}
path{fill:none;stroke-width:2}.cf-allowed{stroke:#2e7d32}.cf-approved{stroke:#1565c0}.cf-proposed{stroke:#c98a00;stroke-dasharray:6 4}
.cf-blocked{stroke:#c62828;stroke-dasharray:6 4}.cf-missing{stroke:#e65100;stroke-dasharray:2 4}.cf-suspicious{stroke:#8e24aa;stroke-width:3;stroke-dasharray:2 3}
.cf-rejected{stroke:#8a8983;stroke-dasharray:1 5}.cf-internal{stroke:#5f5e58;stroke-dasharray:4 3}.cf-inbound{stroke:#5f5e58}
.cf-linked{stroke:#00897b}.cf-link-proposed{stroke:#00897b;stroke-dasharray:6 4}.cf-app{fill:#e0f2f1;stroke:#00897b}
path.cf-unreachable{stroke-width:1.2;stroke-dasharray:1 3}
@media (prefers-color-scheme:dark){.cf-bg{fill:#1a1a19}.cf-box{fill:#232321;stroke:#6f6e68}.cf-comp{fill:#16263f;stroke:#7fb0ff}
.cf-t{fill:#f0efe9}.cf-s,.cf-h{fill:#a8a69c}.cf-allowed{stroke:#66bb6a}.cf-approved{stroke:#64b5f6}.cf-proposed{stroke:#ffc857}
.cf-blocked{stroke:#ef5350}.cf-missing{stroke:#ff9800}.cf-suspicious{stroke:#ce93d8}.cf-internal,.cf-inbound{stroke:#a8a69c}
.cf-linked,.cf-link-proposed{stroke:#4db6ac}.cf-app{fill:#10302d;stroke:#4db6ac}}
"""


def _trim(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def _curve(x1, y1, x2, y2, cls, title=""):
    mx = (x1 + x2) / 2
    t = f"<title>{escape(title)}</title>" if title else ""
    return f"<path class='{cls}' d='M{x1:.0f},{y1:.0f} C{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}'>{t}</path>"


def svg(doc: dict, standalone: bool = False) -> str:
    """The connectivity diagram: inbound on the left, the components in the middle, the destinations on the
    right, one line per connection styled by its status. No script and no inline style attributes (the results
    page's Content-Security-Policy): the page's stylesheet colours the classes; `standalone` adds a <style> for
    the file in the output repository (light and dark)."""
    comps = [c["name"] for c in doc.get("components") or []]
    for e in doc.get("outbound") or []:
        if e.get("component") and e["component"] not in comps:
            comps.append(e["component"])
    inbound = []
    for i in doc.get("inbound") or []:
        if i["from"] not in inbound:
            inbound.append(i["from"])
    dests, app_nodes = [], set()
    for e in doc.get("outbound") or []:
        lbl = label(e)
        if lbl not in dests:
            dests.append(lbl)
        if e.get("type") == "component":
            app_nodes.add(lbl)
    for i in doc.get("internal") or []:
        if i["to"] not in comps:
            lbl = f"{i['to']} :{i['port']}/{i['protocol']}"
            if lbl not in dests:
                dests.append(lbl)
    rows = max(len(comps), len(inbound), len(dests), 1)
    top = 34
    height = top + rows * ROW + 70

    def y(i, n):
        span = rows * ROW
        return top + (span - n * ROW) / 2 + i * ROW + BOX_H / 2

    parts = [f"<svg xmlns='http://www.w3.org/2000/svg' class='cf' viewBox='0 0 {WIDTH} {height}' width='{WIDTH}' "
             f"height='{height}' role='img' aria-label='Network connectivity of {escape(str(doc.get('application')))}'>"]
    if standalone:
        parts.append(f"<style>{SVG_STYLE}</style><rect class='cf-bg' width='{WIDTH}' height='{height}'/>")
    parts += [f"<text class='cf-h' x='{COLS['in'][0]}' y='18'>INBOUND</text>",
              f"<text class='cf-h' x='{COLS['comp'][0]}' y='18'>COMPONENTS</text>",
              f"<text class='cf-h' x='{COLS['out'][0]}' y='18'>OUTBOUND AND IN-CLUSTER</text>"]
    cy = {c: y(i, len(comps)) for i, c in enumerate(comps)}
    iy = {s: y(i, len(inbound)) for i, s in enumerate(inbound)}
    dy = {s: y(i, len(dests)) for i, s in enumerate(dests)}
    lines = []
    for i in doc.get("inbound") or []:
        if i["from"] in iy and i["component"] in cy:
            lines.append(_curve(COLS["in"][1], iy[i["from"]], COLS["comp"][0], cy[i["component"]], "cf-inbound",
                                f"{i['from']} → {i['component']} :{i['port']}"))
    for e in doc.get("outbound") or []:
        lbl = label(e)
        if e.get("component") in cy and lbl in dy:
            cls = LINE_CLASS.get(e.get("status"), "cf-blocked")
            if e.get("status") in ("approved", "allowed") and (e.get("sandbox") or {}).get("reachable") is False:
                cls += " cf-unreachable"
            lines.append(_curve(COLS["comp"][1], cy[e["component"]], COLS["out"][0], dy[lbl], cls,
                                f"{e['component']} → {lbl}: {STATUS_TEXT.get(e.get('status'), e.get('status'))}"))
    for i in doc.get("internal") or []:
        if i["from"] not in cy:
            continue
        if i["to"] in cy:                   # component to component: an arc on the right of the column
            y1, y2 = cy[i["from"]], cy[i["to"]]
            x = COLS["comp"][1]
            lines.append(f"<path class='cf-internal' d='M{x},{y1:.0f} C{x + 60},{y1:.0f} {x + 60},{y2:.0f} {x},{y2:.0f}'>"
                         f"<title>{escape(i['from'])} → {escape(i['to'])} :{i['port']}</title></path>")
        else:
            lbl = f"{i['to']} :{i['port']}/{i['protocol']}"
            lines.append(_curve(COLS["comp"][1], cy[i["from"]], COLS["out"][0], dy[lbl], "cf-internal",
                                f"{i['from']} → {lbl}"))
    parts += lines
    for s, yy in iy.items():
        parts.append(_box(COLS["in"], yy, s, "cf-box", 30))
    for c, yy in cy.items():
        parts.append(_box(COLS["comp"], yy, c, "cf-box cf-comp", 30))
    for s, yy in dy.items():
        parts.append(_box(COLS["out"], yy, s, "cf-box cf-app" if s in app_nodes else "cf-box", 42))
    ly = top + rows * ROW + 24
    x = 10
    for st, text in LEGEND:
        parts.append(f"<path class='{LINE_CLASS[st]}' d='M{x},{ly} L{x + 28},{ly}'/>"
                     f"<text class='cf-s' x='{x + 34}' y='{ly + 4}'>{escape(text)}</text>")
        x += 34 + 7 * len(text) + 18
        if x > WIDTH - 200:
            x, ly = 10, ly + 20
    if not doc.get("observed"):
        parts.append(f"<text class='cf-s' x='10' y='{height - 8}'>Not observed in the sandbox: inferred from code, "
                     "configuration and the generated NetworkPolicy only.</text>")
    parts.append("</svg>")
    return "".join(parts)


def _box(col, yy, label, cls, n):
    x1, x2 = col
    return (f"<g><title>{escape(str(label))}</title><rect class='{cls}' x='{x1}' y='{yy - BOX_H / 2:.0f}' "
            f"width='{x2 - x1}' height='{BOX_H}' rx='6'/>"
            f"<text class='cf-t' x='{x1 + 8}' y='{yy + 4:.0f}'>{escape(_trim(label, n))}</text></g>")


def label(e: dict) -> str:
    """How the diagram names an outbound destination."""
    t = e.get("target") or {}
    if e.get("type") == "component" and t:
        return f"{t.get('application')} / {t.get('component')} :{t.get('port')}"
    if not int(e.get("port") or 0):
        return f"{e.get('destination')} (port unknown)"
    return f"{e.get('destination')} :{e.get('port')}/{e.get('protocol')}"
