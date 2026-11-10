"""Links between components of different applications (docs/egress.md#links-between-applications).

A real application is often several Containerizer applications: components in different repositories, owned by
different teams or products, calling each other. An outbound destination of a component can then be **another
component assessed here**. A link (cz.ComponentLink) records it, from the caller's component and the destination
as its configuration (or the sandbox) names it, to the component it reaches, with how it was found:

- **config** (deterministic): a configured host matches another component's identity: its Kubernetes service
  (`<component>`, `<component>.<namespace>`, `...svc`, `...svc.cluster.local`) or its sandbox Ingress host;
- **observed**: the sandbox blocked a connection from one application's pod to another application's pod (the
  egress observer names such a destination `<component>.<namespace>.svc.cluster.local`);
- **llm**: a destination that looks internal (no dot, `.local`, `.internal`, `.corp`, ..., or one of the
  organization's internal domains: `network.internal_domains`) and that nothing matched
  is shown to the LLM with its configuration line and a shortlist of candidate components (names, application,
  product, repository); it answers with the best match and its confidence, or none (LLM queue kind `link`);
- **manual**: a person links it (Link manually).

Links are proposals until a person confirms them (administrators, operators and the calling application's product
owners). A confirmed link is written by the queue runner to both applications' connectivity.yaml (the caller's
outbound, the callee's inbound) and NetworkPolicies (the caller's egress to the callee's namespace and pods on its
port, the callee's ingress from the caller's namespace); later scans keep them (generate_app reads them back).
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

KIND = "link"
FEATURE = "link-queued"
PRIORITY = 800
SHORTLIST = 15
METHOD_TEXT = {"config": "configuration matches", "observed": "observed in the sandbox", "llm": "proposed by the LLM",
               "manual": "linked by hand"}
STATUS_TEXT = {"proposed": "Link proposed", "confirmed": "Linked", "rejected": "Link rejected",
               "unresolved": "Looks internal, not linked"}
INTERNAL_SUFFIX = re.compile(r"(?i)(\.local|\.internal|\.intranet|\.corp|\.lan|\.svc|\.cluster\.local|\.home\.arpa|"
                             r"\.localdomain|\.private|\.intra|\.ad)$")


def _k8s(s: str) -> str:
    from .generate import k8s_name
    return k8s_name(s)


INTERNAL_ENV = "CONTAINERIZER_INTERNAL_DOMAINS"


def internal_domains() -> tuple[str, ...]:
    """The organization's own internal DNS domains (corp.contoso.com, ad.company.net): hosts under them are
    internal although the domain is a registered one. A site setting: CONTAINERIZER_INTERNAL_DOMAINS (comma or
    space separated), else `network.internal_domains` of rules/60-security.yaml."""
    import os
    raw = os.environ.get(INTERNAL_ENV)
    if raw is None:
        from .harden import security
        raw = security()["network"].get("internal_domains") or []
    items = re.split(r"[,\s]+", raw) if isinstance(raw, str) else [str(x) for x in raw]
    return tuple(d for d in (re.sub(r"^\*?\.", "", x.strip().lower()).rstrip(".") for x in items)
                 if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d))


def internal_looking(host: str, domains: tuple[str, ...] | None = None) -> bool:
    """A destination that is probably not on the internet: one label, an internal suffix, or a host of one of the
    organization's internal domains (internal_domains(); `domains` for many calls)."""
    h = (host or "").lower().rstrip(".")
    if not h or h in ("localhost",) or re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", h):
        return False
    if "." not in h or INTERNAL_SUFFIX.search(h):
        return True
    return any(h == d or h.endswith("." + d) for d in (internal_domains() if domains is None else domains))


def identities(comp: str, namespace: str, url: str | None = None) -> set[str]:
    """The names other components reach a component by."""
    out = {f"{comp}.{namespace}", f"{comp}.{namespace}.svc", f"{comp}.{namespace}.svc.cluster.local"}
    if url:
        host = (urlsplit(url).hostname or "").lower()
        if host:
            out.add(host)
    return out


def identity_map(apps: list[dict]) -> dict[str, dict]:
    """name -> {application_id, application, component, namespace, port}: every deployed or assessed component.
    `apps`: [{ApplicationId, ApplicationName, Namespace, network, urls: {k8s component: url}}]."""
    out: dict[str, dict] = {}
    for a in apps:
        ns = a.get("Namespace") or _k8s(a.get("ApplicationName") or "")
        for c in (a.get("network") or {}).get("components") or []:
            k = c.get("k8s") or _k8s(c.get("name") or "")
            t = {"application_id": int(a["ApplicationId"]), "application": a.get("ApplicationName"), "component": k,
                 "namespace": ns, "port": c.get("port") or 8080, "service_port": c.get("service_port") or 80}
            for name in identities(k, ns, (a.get("urls") or {}).get(k)):
                out.setdefault(name, t)
    return out


def match(host: str, ids: dict[str, dict], app_id: int) -> dict | None:
    """The component of another application a configured host names, else None."""
    t = ids.get((host or "").lower().rstrip("."))
    return t if t and t["application_id"] != int(app_id) else None


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def load_apps(conn) -> list[dict]:
    """Every application's latest network needs, sandbox namespace and Ingress URLs."""
    rows = _rows(conn, "SELECT n.ApplicationId, a.ApplicationName, a.ProductName, a.RepositoryUrl, n.NetworkJson "
                       "FROM cz.vNetworkLatest n JOIN cz.vApplicationLatest a ON a.ApplicationId = n.ApplicationId")
    ns = {}
    try:        # the application's own namespace (schema 42: also when a Make it A patch runs in it, in place)
        own = _rows(conn, "SELECT Namespace, ApplicationId FROM cz.vSandboxNamespace WHERE Own = 1")
    except Exception:  # noqa: BLE001 - before schema 42
        conn.rollback()
        own = _rows(conn, "SELECT Namespace, ApplicationId FROM cz.vSandboxNamespace WHERE Variant = 0")
    for r in own:
        ns.setdefault(int(r["ApplicationId"]), r["Namespace"])
    urls: dict[int, dict] = {}
    for r in _rows(conn, "SELECT ApplicationId, ComponentName, Url FROM cz.vSandboxLatest WHERE Url IS NOT NULL"):
        urls.setdefault(int(r["ApplicationId"]), {})[_k8s(r["ComponentName"] or "")] = r["Url"]
    out = []
    for r in rows:
        try:
            net = json.loads(r["NetworkJson"]) if r.get("NetworkJson") else {}
        except ValueError:
            net = {}
        out.append({**r, "network": net, "Namespace": ns.get(int(r["ApplicationId"])), "urls": urls.get(int(r["ApplicationId"]), {})})
    return out


def insert(conn, row: dict) -> int:
    cur = conn.cursor()
    cur.execute("IF NOT EXISTS (SELECT 1 FROM cz.ComponentLink WHERE FromApplicationId = %s AND FromComponent = %s AND "
                "Destination = %s AND Port = %s AND Protocol = %s) "
                "INSERT cz.ComponentLink (FromApplicationId, FromComponent, Destination, Port, Protocol, ToApplicationId, "
                "ToComponent, Method, Status, Confidence, Reason, Evidence, JobId) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (row["from_app"], row["from"], row["destination"], int(row["port"]), row.get("protocol") or "TCP",
                 row["from_app"], row["from"][:63], row["destination"][:253], int(row["port"]), row.get("protocol") or "TCP",
                 row.get("to_app"), row.get("to"), row["method"], row["status"], row.get("confidence"),
                 (row.get("reason") or "")[:1000] or None, json.dumps(row.get("evidence") or []), row.get("job")))
    n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    conn.commit()
    return n


def find_links(conn, log=print) -> dict:
    """The deterministic step (the queue runner's housekeeping): configured destinations that name another
    application's component, and sandbox flows to another application's pods, become proposed links; configured
    destinations that look internal and match nothing are recorded as unresolved (for the LLM and for people)."""
    apps = load_apps(conn)
    ids = identity_map(apps)
    have = {(int(r["FromApplicationId"]), r["FromComponent"], r["Destination"].lower(), int(r["Port"]))
            for r in _rows(conn, "SELECT FromApplicationId, FromComponent, Destination, Port FROM cz.ComponentLink")}
    out = {"config": 0, "observed": 0, "unresolved": 0}
    for a in apps:
        aid = int(a["ApplicationId"])
        for c in (a.get("network") or {}).get("components") or []:
            k = c.get("k8s") or _k8s(c.get("name") or "")
            for d in c.get("destinations") or []:
                key = (aid, k, d["host"].lower(), int(d["port"]))
                if key in have:
                    continue
                ev = [{"file": d.get("file"), "line": d.get("line"), "quote": d.get("quote")}]
                t = match(d["host"], ids, aid)
                if t:
                    n = insert(conn, {"from_app": aid, "from": k, "destination": d["host"], "port": d["port"],
                                      "to_app": t["application_id"], "to": t["component"], "method": "config",
                                      "status": "proposed", "confidence": 0.95, "evidence": ev,
                                      "reason": f"the configuration names {d['host']}, the service of {t['application']}/"
                                                f"{t['component']} in namespace {t['namespace']}"})
                    out["config"] += n
                elif internal_looking(d["host"]) and not _sibling(d["host"], a):
                    out["unresolved"] += insert(conn, {"from_app": aid, "from": k, "destination": d["host"],
                                                       "port": d["port"], "method": "config", "status": "unresolved",
                                                       "evidence": ev, "reason": "looks internal; no component matched"})
                have.add(key)
    # sandbox flows to another application's pods (the observer names them <component>.<namespace>.svc.cluster.local)
    for f in _rows(conn, "SELECT f.ApplicationId, f.Component, f.Destination, f.Port, f.Protocol, f.Packets, f.LastSeen "
                         "FROM cz.vEgressFlow f WHERE f.ApplicationId IS NOT NULL AND f.Named = 1 "
                         "AND f.Destination LIKE N'%.svc.cluster.local'"):
        aid = int(f["ApplicationId"])
        t = match(f["Destination"], ids, aid)
        if not t:
            continue
        if any(k[0] == aid and k[1] == f["Component"] and (k[2] == f["Destination"].lower() or
                                                            ids.get(k[2]) is t) for k in have):
            continue            # already linked from the configuration
        key = (aid, f["Component"], f["Destination"].lower(), int(f["Port"]))
        n = insert(conn, {"from_app": aid, "from": f["Component"], "destination": f["Destination"], "port": f["Port"],
                          "protocol": f["Protocol"], "to_app": t["application_id"], "to": t["component"],
                          "method": "observed", "status": "proposed", "confidence": 0.9,
                          "evidence": [{"packets": f.get("Packets"), "last_seen": str(f.get("LastSeen") or "")}],
                          "reason": f"the sandbox blocked connections from {f['Component']} to {t['application']}/"
                                    f"{t['component']}"})
        out["observed"] += n
        have.add(key)
    if any(out.values()):
        log(f"links: {out}")
    return out


def _sibling(host: str, app: dict) -> bool:
    names = {c.get("k8s") for c in (app.get("network") or {}).get("components") or []}
    return host.lower().split(".")[0] in names and "." not in host


# --------------------------------------------------------------------------- the LLM (kind `link`)

SYSTEM = """You are a platform architect who maps how an organization's applications call each other. You match a
destination a component's configuration names to the component of another application that it most likely is.
You answer only with JSON matching the requested schema."""

SCHEMA = {"type": "object", "required": ["links"], "properties": {"links": {"type": "array", "items": {
    "type": "object", "required": ["destination", "port", "candidate", "confidence", "reasoning"],
    "properties": {"destination": {"type": "string"}, "port": {"type": "number"},
                   "candidate": {"type": "number", "description": "the number of the matching candidate, or 0 for none"},
                   "confidence": {"type": "number", "description": "0 to 1"},
                   "reasoning": {"type": "string"}}}}}}


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if len(t) > 2 and t not in ("api", "svc", "local", "internal",
                                                                                             "corp", "http", "https", "www")}


def shortlist(dest: dict, candidates: list[dict], n: int = SHORTLIST) -> list[dict]:
    """The candidate components most alike the destination (its host and its configuration line), by shared words."""
    words = _tokens(dest.get("destination", "")) | _tokens(dest.get("quote", ""))

    def score(c):
        return len(words & (_tokens(c.get("ComponentName", "")) | _tokens(c.get("ApplicationName", "")) |
                            _tokens(c.get("ProjectPath", "")) | _tokens(c.get("ProductName", ""))))
    ranked = sorted(candidates, key=lambda c: (-score(c), str(c.get("ApplicationName")), str(c.get("ComponentName"))))
    return ranked[:n]


def prompt(payload: dict) -> str:
    items = []
    for d in payload["destinations"]:
        items.append({"destination": d["destination"], "port": d["port"], "component": d["from"],
                      "configuration": [{"file": e.get("file"), "line": e.get("line"), "quote": e.get("quote")}
                                        for e in d.get("evidence") or []],
                      "candidates": [{"number": i + 1, "application": c["ApplicationName"], "component": c["ComponentName"],
                                      "project": c.get("ProjectPath"), "role": c.get("Role"), "product": c.get("ProductName"),
                                      "repository": c.get("RepositoryUrl")} for i, c in enumerate(d["candidates"])]})
    return "\n".join([
        f"Application {payload['app']} calls these destinations that look internal (inside the organization) and that "
        "no component's service name matched. For each, pick the candidate component of another application it most "
        "likely is, by the names, the configuration key and what the components are, with your confidence from 0 to 1 "
        "and why; answer candidate 0 when none fits. Never guess from a single shared word like 'api'.",
        json.dumps(items, indent=1)])


def handler(job: dict, ask=None) -> dict:
    """The LLM queue's handler of `link` jobs: the answers become proposed links (method llm)."""
    from . import ai
    pl = job["Payload"]
    ask = ask or (lambda p: ai.ask_json(p, SCHEMA, feature=FEATURE, system=SYSTEM, max_tokens=ai.SHORT_ANSWER_TOKENS))
    ans = ask(prompt(pl)).get("links") or []
    by = {(str(a.get("destination") or "").lower(), int(a.get("port") or 0)): a for a in ans if isinstance(a, dict)}
    results = []
    for d in pl["destinations"]:
        a = by.get((d["destination"].lower(), int(d["port"])))
        i = int((a or {}).get("candidate") or 0)
        conf = max(0.0, min(1.0, float((a or {}).get("confidence") or 0)))
        if a and 0 < i <= len(d["candidates"]) and conf >= 0.5:
            c = d["candidates"][i - 1]
            results.append({**d, "to_app": int(c["ApplicationId"]), "to": _k8s(c["ComponentName"]), "confidence": round(conf, 2),
                            "reason": str(a.get("reasoning") or "")[:900], "to_name": f"{c['ApplicationName']}/{c['ComponentName']}"})
        else:
            results.append({**d, "to_app": None, "confidence": round(conf, 2) if a else None,
                            "reason": ("the LLM found no matching component" + (f": {a.get('reasoning')}" if a else ""))[:900]})
    if job.get("_connect"):
        conn = job["_connect"]()
        try:
            cur = conn.cursor()
            for r in results:
                if r["to_app"]:
                    cur.execute("UPDATE cz.ComponentLink SET ToApplicationId = %s, ToComponent = %s, Method = N'llm', "
                                "Status = N'proposed', Confidence = %s, Reason = %s, JobId = %s WHERE LinkId = %s "
                                "AND Status = N'unresolved'", (r["to_app"], r["to"], r["confidence"], r["reason"],
                                                               int(job.get("JobId") or 0) or None, int(r["link_id"])))
                else:
                    cur.execute("UPDATE cz.ComponentLink SET Reason = %s, JobId = %s WHERE LinkId = %s AND Status = N'unresolved'",
                                (r["reason"], int(job.get("JobId") or 0) or None, int(r["link_id"])))
            conn.commit()
        finally:
            conn.close()
    found = sum(1 for r in results if r["to_app"])
    return {"result": {"links": [{k: v for k, v in r.items() if k != "candidates"} for r in results]},
            "summary": f"{len(results)} destination(s): {found} linked, {len(results) - found} not matched", "note": None}


def queue_reviews(conn, log=print) -> int:
    """One `link` job per application with unresolved destinations not asked about yet."""
    from .llmqueue import SqlJobQueue
    rows = _rows(conn, "SELECT * FROM cz.vComponentLink WHERE Status = N'unresolved' AND JobId IS NULL")
    if not rows:
        return 0
    cands = [c for c in _rows(conn, "SELECT * FROM cz.vLinkCandidate") if c.get("Role") not in ("library", "test", "client")]
    by_app: dict[int, list[dict]] = {}
    for r in rows:
        by_app.setdefault(int(r["FromApplicationId"]), []).append(r)
    n = 0
    for aid, links in by_app.items():
        others = [c for c in cands if int(c["ApplicationId"]) != aid]
        if not others:
            continue
        dests = []
        for r in links:
            ev = json.loads(r["Evidence"]) if r.get("Evidence") else []
            d = {"link_id": int(r["LinkId"]), "from": r["FromComponent"], "destination": r["Destination"], "port": int(r["Port"]),
                 "evidence": ev, "quote": " ".join(str(e.get("quote") or "") for e in ev)}
            d["candidates"] = shortlist(d, others)
            dests.append(d)
        key = hashlib.sha256(json.dumps([aid, sorted(d["link_id"] for d in dests)]).encode()).hexdigest()
        if _rows(conn, "SELECT TOP (1) JobId FROM cz.LlmJob WHERE Kind = N'link' AND DedupeKey = %s", (key,)):
            continue
        payload = {"version": 1, "app": links[0]["FromApplication"], "application_id": aid, "destinations": dests}
        job = {"Kind": KIND, "App": payload["app"], "Repository": payload["app"], "ApplicationId": aid,
               "Priority": PRIORITY, "DedupeKey": key, "RequestedBy": "link review", "Payload": payload,
               "InputChars": len(json.dumps(payload, default=str))}
        jid = SqlJobQueue(None, requested_by="link review").add_with(conn, job)
        if jid:
            n += 1
            log(f"link review #{jid} queued for {payload['app']}: {len(dests)} destination(s)")
    return n


def housekeep(conn, log=print) -> dict:
    out = find_links(conn, log)
    out["queued"] = queue_reviews(conn, log)
    return out


# --------------------------------------------------------------------------- NetworkPolicies

def open_link_egress(doc: dict, namespace: str, component: str, port: int) -> bool:
    """The caller's NetworkPolicy: egress to the callee's pods in its namespace on its container port."""
    if doc.get("kind") != "NetworkPolicy":
        return False
    rule = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": component}}}],
            "ports": [{"port": int(port), "protocol": "TCP"}]}
    rules = doc.setdefault("spec", {}).setdefault("egress", [])
    if rule in rules:
        return False
    rules.append(rule)
    if "Egress" not in doc["spec"].setdefault("policyTypes", []):
        doc["spec"]["policyTypes"].append("Egress")
    return True


def open_link_ingress(doc: dict, namespace: str, component: str, port: int) -> bool:
    """The callee's NetworkPolicy: ingress from the caller's pods in its namespace on the container port."""
    if doc.get("kind") != "NetworkPolicy":
        return False
    rule = {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
                      "podSelector": {"matchLabels": {"app.kubernetes.io/name": component}}}],
            "ports": [{"port": int(port), "protocol": "TCP"}]}
    rules = doc.setdefault("spec", {}).setdefault("ingress", [])
    if rule in rules:
        return False
    rules.append(rule)
    return True


def apply_links(docs: list[dict], component: str, outbound: list[dict], inbound: list[dict]) -> bool:
    """Open a component's confirmed links in its NetworkPolicy (connectivity.yaml entries: outbound
    type component with its target, inbound source link)."""
    changed = False
    for d in docs:
        if d.get("kind") != "NetworkPolicy" or (d.get("metadata") or {}).get("name") != component:
            continue
        for e in outbound:
            t = e.get("target") or {}
            if e.get("component") == component and t.get("namespace") and t.get("component"):
                changed |= open_link_egress(d, t["namespace"], t["component"], int(t.get("port") or 8080))
        for i in inbound:
            if i.get("component") == component and i.get("namespace") and i.get("from_component"):
                changed |= open_link_ingress(d, i["namespace"], i["from_component"], int(i.get("target_port") or i.get("port") or 8080))
    return changed
