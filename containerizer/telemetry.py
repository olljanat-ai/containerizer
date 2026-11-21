"""Make it A+: OpenTelemetry for an application rated A, without a code change (docs/telemetry.md).

An administrator turns it on for an application (the results page's **Make it A+**, or Admin → Telemetry for every A
application at once: Application.Telemetry, schema 63). Nothing is built again and nothing in the application's
folder changes. As debug mode (sandboxdebug.py), it is a set of patches on the sandbox's copy of the application's
Flux Kustomization (org.sandbox_wait_patch), which the queue runner writes within a few minutes
(variant.sync_sandbox):

- each workload of a component whose runtime has an OpenTelemetry auto-instrumentation agent (.NET, Java, Node.js,
  Python: rules/65-telemetry.yaml) gets an init container that copies the agent into an emptyDir, and the
  environment that loads it (what the OpenTelemetry Operator injects, written out, so the cluster needs no operator
  and no admission webhook);
- every instrumented workload is told where to send (OTLP over HTTP to the sandbox's collector), under which
  service name (the component) and namespace (the application's);
- the component's NetworkPolicy may reach the collector, and nothing else new.

A component that brings the OpenTelemetry SDK in its own code (`otel_sdk` in containerizer.json) gets the settings
and the NetworkPolicy rule only. A runtime without an agent (Go, a static site) is left as it is and reported.

The application is **A+** when it rates A, every component that runs code is instrumented, and its telemetry arrives:
the queue runner asks Prometheus which services of the namespace sent anything (`check`, TelemetryState).

Pure functions here; the callers do the I/O (org.py writes the patches, variant.py and llmqueue.py store the state).
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "65-telemetry.yaml"
ENDPOINT_ENV = "CONTAINERIZER_OTLP_ENDPOINT"            # the collector the sandbox's applications send to
PROMETHEUS_ENV = "CONTAINERIZER_TELEMETRY_PROMETHEUS"   # where the queue runner asks whether telemetry arrives
ANNOTATION = "containerizer.io/telemetry"
VOLUME = "otel-auto-instrumentation"
INIT = "otel-auto-instrumentation"
UID = 65532
WORKLOADS = ("Deployment", "StatefulSet", "CronJob")
RECEIVING, WAITING, SILENT, PARTIAL, NOTHING, NOT_DEPLOYED = ("receiving", "waiting", "silent", "partial", "nothing",
                                                              "not-deployed")
STATUS_TEXT = {
    RECEIVING: "telemetry arrives",
    WAITING: "instrumented; nothing received yet",
    SILENT: "instrumented, but its telemetry stopped arriving",
    PARTIAL: "not every component can be instrumented",
    NOTHING: "no component can be instrumented",
    NOT_DEPLOYED: "not in the sandbox: there is nothing to instrument",
}


@lru_cache(maxsize=1)
def settings() -> dict:
    return (yaml.safe_load(RULES_FILE.read_text()) or {}).get("telemetry") or {}


def endpoint(env=None) -> str:
    """Where the instrumented workloads send (OTLP over HTTP): CONTAINERIZER_OTLP_ENDPOINT, else the sandbox's
    collector of rules/65-telemetry.yaml."""
    env = os.environ if env is None else env
    return (env.get(ENDPOINT_ENV) or "").strip().rstrip("/") or str(settings()["collector"]["endpoint"]).rstrip("/")


def on(doc: dict, switches) -> bool:
    """An app folder (its containerizer.json) of an application with telemetry turned on: by its SourceKey, or by the
    application id of the Make it A patch it runs."""
    tel = getattr(switches, "telemetry", None)
    if not tel:
        return False
    return doc.get("source_key") in tel or any((doc.get(k) or {}).get("application_id") in tel
                                               for k in ("patched", "variant"))


# --------------------------------------------------------------------------- what runs in a component

_FROM = re.compile(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)")
_ENV = re.compile(r"(?im)^\s*ENV\s+(.+)$")


def final_image(dockerfile: str | None) -> str:
    """The image the component runs on: the last FROM of its Dockerfile, without a digest."""
    found = _FROM.findall(dockerfile or "")
    return found[-1].split("@", 1)[0] if found else ""


def image_env(dockerfile: str | None) -> dict[str, str]:
    """ENV of the Dockerfile's last stage (`ENV A=b C="d e"` and `ENV A b`): the pod's environment replaces these,
    so an option list the agent adds to (JAVA_TOOL_OPTIONS, NODE_OPTIONS, PYTHONPATH) has to start from them."""
    text = re.sub(r"\\[ \t]*\r?\n", " ", dockerfile or "")      # continuation lines
    starts = [m.start() for m in _FROM.finditer(text)]
    out: dict[str, str] = {}
    for line in _ENV.findall(text[starts[-1]:] if starts else text):
        line = line.strip()
        if "=" not in line.split(None, 1)[0]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                out[parts[0]] = parts[1].strip().strip('"')
            continue
        for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S*)', line):
            v = m.group(2)
            out[m.group(1)] = v[1:-1].replace('\\"', '"') if v.startswith('"') else v
    return out


def runtime_of(dockerfile: str | None) -> tuple[str | None, str, str]:
    """(agent id, runtime version, what it is) from the image the component runs on: the `match` patterns of
    rules/65-telemetry.yaml. No agent: (None, "", why)."""
    image = final_image(dockerfile)
    if not image:
        return None, "", "its Dockerfile names no image"
    cfg = settings()
    for rid, a in (cfg.get("agents") or {}).items():
        for pat in a.get("match") or []:
            m = re.search(pat, image)
            if m:
                return rid, (m.group("version") if "version" in m.groupdict() else "") or "", a.get("title") or rid
    for u in cfg.get("unsupported") or []:
        if re.search(u["match"], image):
            return None, "", u["reason"]
    return None, "", f"no OpenTelemetry agent for its image ({image})"


def has_sdk(repo, c) -> bool:
    """The component's code brings the OpenTelemetry SDK itself (a package of it or of the projects it references:
    `sdk_packages` of rules/65-telemetry.yaml): it needs the collector's address, not an agent."""
    pats = [re.compile(p) for p in settings().get("sdk_packages") or []]
    try:
        from .harden import _projects
        projects = _projects(repo, c)
    except Exception:  # noqa: BLE001 - a component without a project graph: its own project
        projects = [c.project]
    for p in projects:
        dev = set(getattr(p, "dev_packages", None) or {})
        for name in getattr(p, "packages", None) or {}:
            if name not in dev and any(x.search(str(name)) for x in pats):
                return True
    return False


def _version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:2])


def plan(entry: dict, dockerfile: str | None) -> dict:
    """What Make it A+ does with one deployed component (an entry of containerizer.json's components):
    {component, folder, mode: agent | sdk | none, runtime, version, reason, blocking}. `blocking`: the component
    runs code that could send telemetry but gets none, so the application is not A+."""
    out = {"component": entry.get("component") or entry.get("folder"), "folder": entry.get("folder")}
    if entry.get("otel_sdk"):
        return {**out, "mode": "sdk", "runtime": "", "version": "",
                "reason": "its code has the OpenTelemetry SDK: it gets the collector's address, no agent"}
    rid, version, title = runtime_of(dockerfile)
    if rid is None:
        static = any(re.search(u["match"], final_image(dockerfile)) and u.get("static")
                     for u in settings().get("unsupported") or [])
        return {**out, "mode": "none", "runtime": "", "version": "", "reason": title, "blocking": not static}
    a = settings()["agents"][rid]
    lo = str(a.get("min_version") or "")
    if lo and version and _version(version) < _version(lo):
        return {**out, "mode": "none", "runtime": rid, "version": version, "blocking": True,
                "reason": f"{title} {version}: the agent needs {title} {lo} or later"}
    hi = str(a.get("max_version") or "")
    if hi and version and _version(version) > _version(hi):
        return {**out, "mode": "none", "runtime": rid, "version": version, "blocking": True,
                "reason": f"{title} {version}: the agent of this Containerizer version supports up to {title} {hi}"}
    return {**out, "mode": "agent", "runtime": rid, "version": version, "reason": f"{title} {version} agent".replace("  ", " ")}


# --------------------------------------------------------------------------- the patches

def _pod(doc: dict) -> dict:
    spec = doc.get("spec") or {}
    if doc.get("kind") == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    return ((spec.get("template") or {}).get("spec") or {})


def _wrap(doc: dict, template: dict) -> dict:
    """A strategic merge patch of the workload with `template` as its pod template."""
    spec = {"template": template}
    if doc["kind"] == "CronJob":
        spec = {"jobTemplate": {"spec": spec}}
    return {"apiVersion": doc.get("apiVersion") or ("batch/v1" if doc["kind"] == "CronJob" else "apps/v1"),
            "kind": doc["kind"], "metadata": {"name": doc["metadata"]["name"]}, "spec": spec}


def common_env(ns: str, service: str, container: str) -> list[dict]:
    """What every instrumented workload is told, agent or SDK: the service it is, and where to send."""
    cfg = settings()
    attrs = {"service.namespace": ns, "k8s.namespace.name": ns, "k8s.container.name": container,
             "k8s.pod.name": "$(OTEL_K8S_POD_NAME)", **(cfg.get("resource_attributes") or {})}
    return [{"name": "OTEL_K8S_POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
            {"name": "OTEL_SERVICE_NAME", "value": service},
            {"name": "OTEL_RESOURCE_ATTRIBUTES", "value": ",".join(f"{k}={v}" for k, v in attrs.items())},
            {"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": endpoint()},
            {"name": "OTEL_EXPORTER_OTLP_PROTOCOL", "value": str(cfg["collector"].get("protocol") or "http/protobuf")}] \
        + [{"name": k, "value": str(v)} for k, v in (cfg.get("env") or {}).items()]


def agent_env(rid: str, have: dict[str, str]) -> list[dict]:
    """The environment that loads the agent `rid`. `have`: the values the container has already (the image's ENV,
    then the pod's): a list the agent adds to (`append`, `prepend`) keeps what was there."""
    a = settings()["agents"][rid]
    d = a["mount"]
    out = []
    for k, v in (a.get("env") or {}).items():
        out.append({"name": k, "value": str(v).replace("{dir}", d)})
    for how, sep_default in (("append", " "), ("prepend", ":")):
        for k, spec in (a.get(how) or {}).items():
            value, sep = (spec, sep_default) if isinstance(spec, str) else (spec["value"], spec.get("separator", sep_default))
            value = value.replace("{dir}", d)
            old = (have.get(k) or "").strip()
            if value in old:
                value = old
            elif old:
                value = f"{old}{sep}{value}" if how == "append" else f"{value}{sep}{old}"
            out.append({"name": k, "value": value})
    return out


def init_container(rid: str) -> dict:
    a = settings()["agents"][rid]
    return {"name": INIT, "image": a["image"], "imagePullPolicy": "IfNotPresent",
            "command": [str(x).replace("{dir}", "/target") for x in a["copy"]],
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "runAsGroup": UID,
                                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}},
            "volumeMounts": [{"name": VOLUME, "mountPath": "/target"}]}


def egress_rule() -> dict:
    """NetworkPolicy egress to the collector's pods."""
    c = settings()["collector"]
    return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": c["namespace"]}},
                    "podSelector": {"matchLabels": dict(c["pod_labels"])}}],
            "ports": [{"port": int(c["port"]), "protocol": "TCP"}]}


def workload_patches(docs: list[dict], ns: str, pl: dict, dockerfile: str | None) -> list[dict]:
    """The kustomize patches of one component: its workloads instrumented (`pl`, from plan), its NetworkPolicies
    opened towards the collector. Nothing for a component that is left as it is."""
    if pl.get("mode") not in ("agent", "sdk"):
        return []
    rid = pl["runtime"] if pl["mode"] == "agent" else None
    patches = []
    for d in docs:
        pod = _pod(d)
        containers = pod.get("containers") or []
        if d.get("kind") not in WORKLOADS or not containers or not (d.get("metadata") or {}).get("name"):
            continue
        c = containers[0]
        have = {**image_env(dockerfile), **{e["name"]: e["value"] for e in c.get("env") or []
                                           if isinstance(e.get("value"), str)}}
        env = common_env(ns, str(pl.get("folder") or d["metadata"]["name"]), str(c.get("name") or ""))
        main: dict = {"name": c.get("name"), "env": env}
        spec: dict = {"containers": [main]}
        if rid:
            a = settings()["agents"][rid]
            main["env"] = env + agent_env(rid, have)
            main["volumeMounts"] = [{"name": VOLUME, "mountPath": a["mount"], "readOnly": True}]
            spec = {"initContainers": [init_container(rid)], "containers": [main],
                    "volumes": [{"name": VOLUME, "emptyDir": {"sizeLimit": str(a.get("size") or "200Mi")}}]}
        mark = {ANNOTATION: rid or "sdk"}
        patch = _wrap(d, {"metadata": {"annotations": mark}, "spec": spec})
        patch["metadata"]["annotations"] = dict(mark)
        patches.append({"target": {"group": patch["apiVersion"].split("/")[0], "kind": d["kind"],
                                   "name": d["metadata"]["name"]},
                        "patch": yaml.safe_dump(patch, sort_keys=False)})
    if not patches:
        return []
    rule = egress_rule()
    for d in docs:
        spec = d.get("spec") or {}
        if d.get("kind") != "NetworkPolicy" or "Egress" not in (spec.get("policyTypes") or []):
            continue
        if rule in (spec.get("egress") or []):
            continue
        op = ({"op": "add", "path": "/spec/egress/-", "value": rule} if isinstance(spec.get("egress"), list)
              else {"op": "add", "path": "/spec/egress", "value": [rule]})
        patches.append({"target": {"group": "networking.k8s.io", "kind": "NetworkPolicy", "name": d["metadata"]["name"]},
                        "patch": json.dumps([op])})
    return patches


def ops(folder: Path, doc: dict) -> tuple[list[dict], list[dict]]:
    """(JSON patch operations on the sandbox's copy of the application's Flux Kustomization, the plan of each
    component) for an app folder with telemetry on."""
    from .manifests import component_docs
    ns = str(doc.get("app") or doc.get("namespace") or "")
    out, plans = [], []
    for c in doc.get("components") or []:
        cdir = folder / str(c.get("folder") or "")
        if not c.get("folder") or not cdir.is_dir():
            continue
        try:
            dockerfile = (cdir / "Dockerfile").read_text()
        except OSError:
            dockerfile = None
        pl = plan(c, dockerfile)
        patches = workload_patches(component_docs(cdir), ns, pl, dockerfile)
        if not patches and pl["mode"] != "none":
            pl = {**pl, "mode": "none", "blocking": True, "reason": "it has no workload to instrument"}
        plans.append(pl)
        out += [{"op": "add", "path": "/spec/patches/-", "value": p} for p in patches]
    return out, plans


# --------------------------------------------------------------------------- the state (Application.TelemetryState)

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def applied_status(plans: list[dict]) -> str:
    """The status of an application right after its patches were written, before anything was received."""
    if not plans:
        return NOT_DEPLOYED
    done = [p for p in plans if p.get("mode") in ("agent", "sdk")]
    if not done:
        return NOTHING
    return PARTIAL if any(p.get("mode") == "none" and p.get("blocking") for p in plans) else WAITING


def new_state(namespace: str, plans: list[dict], old: dict | None = None) -> dict:
    """The state after the patches were written. What was known of the same components' telemetry is kept."""
    old = old if isinstance(old, dict) else {}
    seen = {c.get("folder"): c.get("seen_at") for c in old.get("components") or [] if c.get("seen_at")}
    comps = [{**p, **({"seen_at": seen[p["folder"]]} if p.get("mode") != "none" and p.get("folder") in seen else {})}
             for p in plans]
    st = {"namespace": namespace, "components": comps, "applied_at": old.get("applied_at") or _now(),
          "status": old.get("status") if old.get("status") in (RECEIVING, SILENT) else applied_status(plans)}
    if [(c.get("folder"), c.get("mode"), c.get("runtime")) for c in old.get("components") or []] != \
            [(c.get("folder"), c.get("mode"), c.get("runtime")) for c in comps]:
        st["applied_at"] = _now()
    for k in ("seen_at", "checked_at", "check", "plus_at"):
        if old.get(k):
            st[k] = old[k]
    return with_seen(st, None)


def with_seen(state: dict, seen: set | None, now: str | None = None) -> dict:
    """The state after a look at what arrived. `seen`: the service names of the namespace that sent something in the
    last minutes (None: not asked; the status follows what was known)."""
    st = copy.deepcopy(state)
    comps = st.get("components") or []
    base = applied_status(comps)
    if seen is not None:
        now = now or _now()
        st["checked_at"], st["check"] = now, "prometheus"
        for c in comps:
            if c.get("mode") != "none" and c.get("folder") in seen:
                c["seen_at"] = now
        if any(c.get("mode") != "none" and c.get("folder") in seen for c in comps):
            st["seen_at"] = now
    if base == WAITING:
        if seen is None:
            base = st.get("status") if st.get("status") in (RECEIVING, SILENT) and st.get("seen_at") else WAITING
        elif any(c.get("mode") != "none" and c.get("folder") in seen for c in comps):
            base = RECEIVING
        elif st.get("seen_at"):
            base = SILENT
    st["status"] = base
    if base == RECEIVING and not st.get("plus_at"):
        st["plus_at"] = st.get("seen_at") or now or _now()      # since when it is A+ (the trends page)
    return st


def _shape(st: dict) -> tuple:
    """What a check can change besides the times: the status and which components were ever seen."""
    return (st.get("status"), st.get("check"),
            tuple((c.get("folder"), bool(c.get("seen_at"))) for c in st.get("components") or []))


def parse_state(raw) -> dict:
    try:
        st = json.loads(raw) if isinstance(raw, str) and raw else None
    except ValueError:
        st = None
    return st if isinstance(st, dict) else {}


def is_plus(rating, telemetry, state) -> bool:
    """A+: rated A, telemetry on, every component that runs code instrumented and its telemetry arriving. Where
    nobody can ask whether it arrives (no Prometheus for the queue runner), instrumented is as far as it goes."""
    st = state if isinstance(state, dict) else parse_state(state)
    if str(rating or "").strip() != "A" or not telemetry:
        return False
    return st.get("status") == RECEIVING or (st.get("status") == WAITING and st.get("check") == "none")


def summary(state: dict) -> str:
    """One line for a list: what the state is."""
    st = state or {}
    if not st:
        return "requested: the queue runner instruments it within a few minutes"
    comps = st.get("components") or []
    done = sum(1 for c in comps if c.get("mode") in ("agent", "sdk"))
    text = STATUS_TEXT.get(st.get("status"), str(st.get("status") or ""))
    if st.get("status") == WAITING and st.get("check") == "none":
        text = "instrumented (whether its telemetry arrives is not checked here)"
    return f"{text} ({done} of {len(comps)} component{'' if len(comps) == 1 else 's'} instrumented)" if comps else text


# --------------------------------------------------------------------------- storing and checking (the queue runner)

def store_plans(conn, reports: dict, log=print) -> int:
    """After sandbox/ was written (variant.sync_sandbox): the state of every application with telemetry on, from the
    plans of its app folder (`reports`: {SourceKey or ApplicationId: (namespace, plans)}); an application that is on
    but has no folder is not in the sandbox. (Turning it off clears the state: admin_telemetry.turn_off.) Returns
    rows written."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ApplicationId, SourceKey, TelemetryState FROM cz.Application WHERE Telemetry = 1")
    rows = cur.fetchall()
    n = 0
    cur = conn.cursor()
    for r in rows:
        ns, plans = reports.get(int(r["ApplicationId"])) or reports.get(str(r["SourceKey"])) or ("", [])
        st = new_state(ns, plans, parse_state(r["TelemetryState"]))
        st["check"] = "prometheus" if prometheus_url() else "none"
        new = json.dumps(st, sort_keys=True)
        if new != r["TelemetryState"]:
            cur.execute("UPDATE cz.Application SET TelemetryState = %s WHERE ApplicationId = %s",
                        (new, int(r["ApplicationId"])))
            n += 1
    conn.commit()
    if n:
        log(f"telemetry: the state of {n} application(s) written")
    return n


def prometheus_url(env=None) -> str:
    env = os.environ if env is None else env
    return (env.get(PROMETHEUS_ENV) or "").strip().rstrip("/")


def query_seen(url: str, opener=None, timeout: float = 10) -> dict[str, set]:
    """{namespace: {service names}} that sent telemetry lately (the `seen_query` of rules/65-telemetry.yaml: every
    series the collector exports carries the namespace and the service). Raises when Prometheus does not answer."""
    c = settings()["collector"]
    q = urllib.parse.urlencode({"query": c["seen_query"]})
    req = urllib.request.Request(f"{url}/api/v1/query?{q}", headers={"Accept": "application/json"})
    with (opener or urllib.request.urlopen)(req, timeout=timeout) as resp:
        doc = json.loads(resp.read().decode("utf-8", "replace"))
    if doc.get("status") != "success":
        raise ValueError(f"Prometheus: {str(doc.get('error') or doc.get('status'))[:200]}")
    out: dict[str, set] = {}
    for s in (doc.get("data") or {}).get("result") or []:
        m = s.get("metric") or {}
        ns, svc = m.get(c["namespace_label"]), m.get(c["service_label"])
        if ns and svc:
            out.setdefault(str(ns), set()).add(str(svc))
    return out


def check(connect, log=print, opener=None, env=None) -> int:
    """The queue runner's periodic look: which instrumented applications' telemetry arrives. Without a Prometheus
    to ask (CONTAINERIZER_TELEMETRY_PROMETHEUS), or when it does not answer, the states stay. Returns the states that
    changed status."""
    url = prometheus_url(env)
    if not url:
        return 0
    conn = connect()
    try:
        cur = conn.cursor(as_dict=True)
        try:
            cur.execute("SELECT ApplicationId, TelemetryState FROM cz.Application "
                        "WHERE Telemetry = 1 AND TelemetryState IS NOT NULL")
            rows = cur.fetchall()
        except Exception:  # noqa: BLE001 - before schema 63
            return 0
        if not rows:
            return 0
        try:
            seen = query_seen(url, opener)
        except Exception as ex:  # noqa: BLE001 - Prometheus is away: what was known stays
            print(f"telemetry: Prometheus not asked: {type(ex).__name__}: {str(ex)[:200]}", file=sys.stderr)
            return 0
        n = 0
        cur = conn.cursor()
        now = _now()
        for r in rows:
            old = parse_state(r["TelemetryState"])
            if not old.get("components"):
                continue
            new = with_seen(old, seen.get(str(old.get("namespace") or ""), set()), now)
            if _shape(new) == _shape(old) and str(old.get("checked_at") or "")[:13] == now[:13]:
                continue                                # nothing new: the times are written once an hour
            cur.execute("UPDATE cz.Application SET TelemetryState = %s WHERE ApplicationId = %s",
                        (json.dumps(new, sort_keys=True), int(r["ApplicationId"])))
            if new.get("status") != old.get("status"):
                n += 1
                log(f"telemetry: {old.get('namespace')}: {STATUS_TEXT.get(new['status'], new['status'])}")
        conn.commit()
        return n
    finally:
        conn.close()
