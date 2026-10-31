"""Sandbox verification: read back what Argo CD or Flux deployed from the output repository.

After `containerizer org` has committed and pushed, the sandbox cluster syncs the new commit. This
step waits for that sync per app, then reads the rollout of every deployed component (Deployment
rollout, pod readiness, restarts, Warning events, and on failure a short, redacted log tail) and
records one status per component:

    healthy     deployed and healthy: rolled out, every replica ready, no restarts while watched
    failing     deployed but failing (reason): crash loop, image pull, probe, scheduling, sync error
    pending     the GitOps tool did not sync the commit (or the rollout did not finish) in time
    scheduled   a CronJob that is deployed but has not run yet (no Job to judge)
    not-found   the app's Argo CD Application / Flux Kustomization or workload does not exist
    error       the read-back itself failed (e.g. forbidden: apply sandbox/verify-rbac.yaml)
    skipped     no cluster access (no kubectl, no kubeconfig or the API server is unreachable)

The cluster is only read, with the least-privilege Role/RoleBinding that `write_sandbox` generates in
`sandbox/verify-rbac.yaml`. Nothing is written to the cluster.

Failures are matched against rules/50-failures.yaml (stage `cluster` for Kubernetes states and
events, stage `run` for the application's own log). Code and platform failures become learned
findings with their evidence (rules/learned/findings.yaml), retry fixes with a `learn` section become
learned plan rules, so the next run rates and generates the component with what the cluster showed.
External-service and environment failures are reported but never learned: they are not the app's.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

HEALTHY, FAILING, PENDING, SCHEDULED, NOT_FOUND, ERROR, SKIPPED = (
    "healthy", "failing", "pending", "scheduled", "not-found", "error", "skipped")
STATUS_TEXT = {
    HEALTHY: "deployed and healthy", FAILING: "deployed but failing", PENDING: "not synced or rolled out in time",
    SCHEDULED: "deployed, scheduled job has not run yet", NOT_FOUND: "not deployed", ERROR: "could not be checked",
    SKIPPED: "not checked (no cluster access)"}
ARGO_APP = "applications.argoproj.io"
FLUX_KS = "kustomizations.kustomize.toolkit.fluxcd.io"
VERIFIER = "containerizer-verifier"
VERIFIER_NS = "containerizer-verify"
LOG_LINES = 80
LOG_CHARS = 4000
# definitive pod states: waiting longer will not help
BAD_WAITING = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CreateContainerConfigError",
               "CreateContainerError", "RunContainerError"}
SHA = re.compile(r"\b[0-9a-f]{40}\b")


class KubeError(Exception):
    def __init__(self, msg: str, kind: str = "error"):
        super().__init__(msg)
        self.kind = kind            # error | not-found | forbidden | unreachable


# --------------------------------------------------------------------------- redaction

_SECRETS = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|sharedaccesskey|client[_-]?secret)"
                r"(\s*[=:]\s*|\"\s*:\s*\")([^\s;,\"']+)"), r"\1\2***"),
    (re.compile(r"(?i)\b(authorization:\s*(bearer|basic))\s+\S+"), r"\1 ***"),
    (re.compile(r"(?i)(\w+://)[^/\s:@]+:[^/\s@]+@"), r"\1***:***@"),
    (re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}"), "***jwt***"),
]


def redact(text: str) -> str:
    """Logs can carry connection strings and tokens: mask the usual shapes before anything is stored."""
    for rx, repl in _SECRETS:
        text = rx.sub(repl, text)
    return text


# --------------------------------------------------------------------------- kubectl

@dataclass
class KubeOptions:
    kubeconfig: str | None = None     # default: KUBECONFIG, ~/.kube/config, or in-cluster service account
    context: str | None = None
    request_timeout: int = 20


class Kube:
    """Read-only kubectl wrapper (get, logs). Credentials stay in the kubeconfig, never in arguments."""

    def __init__(self, o: KubeOptions | None = None, kubectl: str | None = "auto"):
        self.o = o or KubeOptions()
        self.kubectl = shutil.which("kubectl") if kubectl == "auto" else kubectl     # None: no kubectl

    def _base(self) -> list[str]:
        cmd = [self.kubectl or "kubectl", f"--request-timeout={self.o.request_timeout}s"]
        if self.o.kubeconfig:
            cmd.append(f"--kubeconfig={self.o.kubeconfig}")
        if self.o.context:
            cmd.append(f"--context={self.o.context}")
        return cmd

    def run(self, args: list[str]) -> str:
        try:
            p = subprocess.run(self._base() + args, capture_output=True, text=True, errors="replace",
                               timeout=self.o.request_timeout + 15, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise KubeError(f"kubectl {args[0]}: timed out", "unreachable") from None
        except OSError as e:
            raise KubeError(f"kubectl: {e}", "unreachable") from None
        if p.returncode:
            err = redact((p.stderr or p.stdout).strip())[-500:]
            if "NotFound" in err or "not found" in err:
                kind = "not-found"
            elif "Forbidden" in err or "forbidden" in err:
                kind = "forbidden"
            elif re.search(r"Unable to connect|connection refused|was refused|no such host|i/o timeout|dial tcp|"
                           r"no configuration has been provided|context .* does not exist|"
                           r"the server has asked for the client to provide credentials|Unauthorized", err):
                kind = "unreachable"
            else:
                kind = "error"
            raise KubeError(err or f"kubectl {args[0]} failed ({p.returncode})", kind)
        return p.stdout

    def get(self, resource: str, ns: str | None = None, name: str | None = None, selector: str | None = None) -> dict:
        args = ["get", resource] + ([name] if name else []) + (["-n", ns] if ns else []) \
            + (["-l", selector] if selector else []) + ["-o", "json"]
        return json.loads(self.run(args) or "{}")

    def logs(self, ns: str, pod: str, container: str, previous: bool = False, tail: int = LOG_LINES) -> str:
        args = ["logs", pod, "-n", ns, "-c", container, f"--tail={tail}"] + (["--previous"] if previous else [])
        try:
            return self.run(args)
        except KubeError as e:
            return f"[logs unavailable: {e}]"

    def version(self) -> dict:
        return json.loads(self.run(["version", "-o", "json"]) or "{}")


def _kubeconfig_present(o: KubeOptions) -> bool:
    if o.kubeconfig:
        return Path(o.kubeconfig).is_file()
    if os.environ.get("KUBECONFIG"):
        return any(Path(p).is_file() for p in os.environ["KUBECONFIG"].split(os.pathsep) if p)
    if (Path.home() / ".kube" / "config").is_file():
        return True
    # in-cluster: kubectl uses the pod's service account
    return bool(os.environ.get("KUBERNETES_SERVICE_HOST")) and \
        Path("/var/run/secrets/kubernetes.io/serviceaccount/token").is_file()


def cluster_access(kube: Kube) -> tuple[bool, str]:
    """(usable, reason). Every 'no' is a reason to skip the step, not an error of the run."""
    if not kube.kubectl:
        return False, "kubectl is not installed (https://kubernetes.io/docs/tasks/tools/)"
    if not _kubeconfig_present(kube.o):
        return False, "no kubeconfig: pass --kubeconfig, set KUBECONFIG or run in the cluster"
    try:
        v = kube.version()
    except KubeError as e:
        return False, f"the sandbox cluster is not reachable: {e}"
    server = (v.get("serverVersion") or {}).get("gitVersion")
    if not server:
        return False, "the sandbox cluster is not reachable (no server version)"
    return True, f"Kubernetes {server}"


# --------------------------------------------------------------------------- what was deployed

def _rev_of(s: str | None) -> str:
    m = SHA.search(s or "")
    return m.group(0) if m else ""


def deployed_apps(root: Path) -> list[dict]:
    """Every app in the output repository with its components and their workloads (from k8s.yaml)."""
    from .org import _apps_in
    apps = []
    for rel, d, doc in _apps_in(root):
        comps = []
        for c in doc.get("components") or []:
            folder = d / (c.get("folder") or "")
            workloads = []
            k8s = folder / "k8s.yaml"
            if c.get("folder") and k8s.is_file():
                try:
                    docs = [x for x in yaml.safe_load_all(k8s.read_text()) if isinstance(x, dict)]
                except yaml.YAMLError:
                    docs = []
                workloads = [(x["kind"], x["metadata"]["name"]) for x in docs
                             if x.get("kind") in ("Deployment", "StatefulSet", "CronJob") and x.get("metadata", {}).get("name")]
            comps.append({**c, "workloads": workloads})
        apps.append({"rel": rel, "app": doc.get("app") or "", "doc": doc, "components": comps})
    return [a for a in apps if a["app"]]


# --------------------------------------------------------------------------- GitOps sync

def _cond(obj: dict, typ: str) -> dict:
    return next((c for c in (obj.get("status") or {}).get("conditions") or [] if c.get("type") == typ), {})


def is_ours(revision: str, ours: str, root: Path | None) -> bool:
    """The cluster runs our commit, or one that already contains it (someone pushed after us)."""
    if not ours:
        return bool(revision)
    if not revision:
        return False
    if revision == ours:
        return True
    if root and (root / ".git").exists():
        r = subprocess.run(["git", "merge-base", "--is-ancestor", ours, revision], cwd=root, capture_output=True)
        return r.returncode == 0
    return False


def argo_state(app: dict, ours: str, root: Path | None) -> tuple[str, str]:
    """('synced'|'waiting'|'failed', detail) of an Argo CD Application."""
    st = app.get("status") or {}
    sync, health = st.get("sync") or {}, (st.get("health") or {}).get("status", "")
    op = st.get("operationState") or {}
    conds = [c for c in st.get("conditions") or [] if c.get("type", "").endswith("Error") and c["type"] != "SyncError"]
    for c in conds:
        if c["type"] == "InvalidSpecError":
            return "failed", f"Argo CD {c['type']}: {c.get('message', '')[:500]}"
    op_rev = _rev_of((op.get("syncResult") or {}).get("revision") or (op.get("operation") or {}).get("sync", {}).get("revision"))
    if op.get("phase") in ("Failed", "Error") and is_ours(op_rev, ours, root):
        return "failed", f"Argo CD sync {op['phase'].lower()}: {op.get('message', '')}"
    rev = _rev_of(sync.get("revision"))
    if sync.get("status") == "Synced" and is_ours(rev, ours, root) and op.get("phase") not in ("Running", "Terminating"):
        return "synced", f"Argo CD synced {rev[:12]} (health {health or 'unknown'})"
    return "waiting", f"Argo CD at {rev[:12] or 'no revision'}, sync {sync.get('status', 'unknown')}, " \
                      f"operation {op.get('phase', 'none')}" + \
        "".join(f"; {c['type']}: {c.get('message', '')[:300]}" for c in conds)


def flux_state(ks: dict, ours: str, root: Path | None) -> tuple[str, str]:
    """('synced'|'waiting'|'failed', detail) of a Flux Kustomization. HealthCheckFailed counts as
    synced: the manifests were applied and the workload inspection says what is wrong."""
    st = ks.get("status") or {}
    ready = _cond(ks, "Ready")
    applied, attempted = _rev_of(st.get("lastAppliedRevision")), _rev_of(st.get("lastAttemptedRevision"))
    if ready.get("status") == "True" and is_ours(applied, ours, root):
        return "synced", f"Flux applied {applied[:12]}"
    if ready.get("status") == "False" and is_ours(attempted, ours, root):
        if ready.get("reason") == "HealthCheckFailed":     # applied; lastAppliedRevision only moves when healthy
            return "synced", f"Flux applied {attempted[:12]}, health check: {ready.get('message', '')[:300]}"
        if ready.get("reason") not in ("Progressing", "DependencyNotReady"):
            return "failed", f"Flux {ready.get('reason', 'not ready')}: {ready.get('message', '')[:500]}"
    if (ks.get("spec") or {}).get("suspend"):
        return "failed", "Flux Kustomization is suspended"
    return "waiting", f"Flux at {applied[:12] or 'no revision'}, Ready {ready.get('status', 'unknown')} " \
                      f"({ready.get('reason', '')})"


def gitops_object(kube: Kube, app: str, gitops: str) -> tuple[str, dict]:
    """('argocd'|'flux', object). gitops 'auto' tries Argo CD first, then Flux."""
    from .gitops import ARGO_NS
    errors = []
    for tool in (["argocd", "flux"] if gitops == "auto" else [gitops]):
        try:
            if tool == "argocd":
                return tool, kube.get(ARGO_APP, ARGO_NS, app)
            return tool, kube.get(FLUX_KS, app, app)
        except KubeError as e:
            if e.kind in ("unreachable",):
                raise
            errors.append((tool, e))
    forbidden = [t for t, e in errors if e.kind == "forbidden"]
    if forbidden:
        raise KubeError(f"forbidden to read the {' / '.join(forbidden)} object of {app}: apply sandbox/verify-rbac.yaml",
                        "forbidden")
    raise KubeError("; ".join(f"{t}: {e}" for t, e in errors), "not-found")


# --------------------------------------------------------------------------- workloads

@dataclass
class Observation:
    status: str = PENDING
    reason: str = ""
    ready: str = ""
    restarts: int = 0
    states: list = field(default_factory=list)     # container states: "CrashLoopBackOff", "OOMKilled (exit 137)"
    events: list = field(default_factory=list)     # Warning events: {reason, message, count, object}
    log: str = ""
    pod: str = ""
    final: bool = False                            # definitive: waiting longer will not change it


def _selector(match_labels: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted((match_labels or {}).items()))


def _events(kube: Kube, ns: str, names: list[str]) -> list[dict]:
    try:
        items = kube.get("events", ns).get("items") or []
    except KubeError:
        return []
    out = []
    for ev in items:
        obj = (ev.get("involvedObject") or {}).get("name", "")
        if ev.get("type") != "Warning" or not any(obj == n or obj.startswith(n + "-") for n in names):
            continue
        out.append({"reason": ev.get("reason", ""), "message": redact(" ".join(str(ev.get("message", "")).split()))[:400],
                    "count": int(ev.get("count") or (ev.get("series") or {}).get("count") or 1), "object": obj,
                    "last": ev.get("lastTimestamp") or ev.get("eventTime") or ""})
    out.sort(key=lambda e: e["last"] or "", reverse=True)
    return out[:10]


def _pods(kube: Kube, ns: str, selector: str, ob: Observation) -> list[dict]:
    pods = kube.get("pods", ns, selector=selector).get("items") or []
    worst = None
    for p in pods:
        for cs in (p.get("status") or {}).get("containerStatuses") or []:
            ob.restarts += int(cs.get("restartCount") or 0)
            waiting = (cs.get("state") or {}).get("waiting") or {}
            last = (cs.get("lastState") or {}).get("terminated") or {}
            if waiting.get("reason"):
                ob.states.append(waiting["reason"] + (f": {waiting['message'][:200]}" if waiting.get("message") else ""))
                if waiting["reason"] in BAD_WAITING:
                    worst = worst or (p, cs)
            if last.get("reason"):
                ob.states.append(f"last exit {last['reason']} (exit {last.get('exitCode')})")
            if not cs.get("ready") and (cs.get("restartCount") or waiting.get("reason") in BAD_WAITING):
                worst = worst or (p, cs)
        for c in (p.get("status") or {}).get("conditions") or []:
            if c.get("type") == "PodScheduled" and c.get("status") == "False":
                ob.states.append(f"Unschedulable: {c.get('message', '')[:200]}")
    if worst:
        p, cs = worst
        ob.pod = p["metadata"]["name"]
        reason = ((cs.get("state") or {}).get("waiting") or {}).get("reason", "")
        if reason not in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CreateContainerConfigError"):
            ob.log = redact(kube.logs(ns, ob.pod, cs.get("name", ""), previous=bool(cs.get("restartCount"))))[-LOG_CHARS:]
    ob.states = list(dict.fromkeys(ob.states))[:10]
    return pods


def _definitive(bad: list[str], restarts: int) -> bool:
    """Waiting longer will not help: the image or its configuration is missing, or it keeps crashing.
    Unschedulable pods are not definitive (an autoscaler may add a node)."""
    kinds = {s.split(":")[0] for s in bad}
    if kinds & (BAD_WAITING - {"CrashLoopBackOff", "RunContainerError"}):
        return True
    return bool(kinds & {"CrashLoopBackOff", "RunContainerError"}) and restarts >= 3


def observe_deployment(kube: Kube, ns: str, name: str) -> Observation:
    ob = Observation()
    try:
        d = kube.get("deployments.apps", ns, name)
    except KubeError as e:
        return Observation(NOT_FOUND if e.kind == "not-found" else ERROR,
                           f"Deployment {name}: {e}", final=True)
    spec, st = d.get("spec") or {}, d.get("status") or {}
    want = int(spec.get("replicas", 1))
    ready, updated, avail = (int(st.get(k) or 0) for k in ("readyReplicas", "updatedReplicas", "availableReplicas"))
    ob.ready = f"{ready}/{want}"
    _pods(kube, ns, _selector((spec.get("selector") or {}).get("matchLabels")), ob)
    progressing = _cond(d, "Progressing")
    rolled = (int(st.get("observedGeneration") or 0) >= int((d.get("metadata") or {}).get("generation") or 0)
              and updated == want and ready == want and avail == want and int(st.get("replicas") or 0) == want)
    if rolled:
        ob.status = HEALTHY
        return ob
    ob.events = _events(kube, ns, [name])
    bad = [s for s in ob.states if s.split(":")[0] in BAD_WAITING or s.startswith("Unschedulable")]
    if progressing.get("reason") == "ProgressDeadlineExceeded":
        ob.status, ob.final = FAILING, True
        ob.reason = f"rollout did not finish: {progressing.get('message', '')[:300]}"
        ob.reason += f" ({bad[0]})" if bad else ""
    elif bad:
        ob.status, ob.reason, ob.final = FAILING, bad[0], _definitive(bad, ob.restarts)
    elif _cond(d, "ReplicaFailure").get("status") == "True":
        ob.status, ob.final = FAILING, True
        ob.reason = f"pods cannot be created: {_cond(d, 'ReplicaFailure').get('message', '')[:300]}"
    else:
        ob.status = PENDING
        ob.reason = f"rollout in progress: {ready}/{want} ready, {updated} updated"
    return ob


def observe_statefulset(kube: Kube, ns: str, name: str) -> Observation:
    ob = Observation()
    try:
        s = kube.get("statefulsets.apps", ns, name)
    except KubeError as e:
        return Observation(NOT_FOUND if e.kind == "not-found" else ERROR, f"StatefulSet {name}: {e}", final=True)
    want, st = int((s.get("spec") or {}).get("replicas", 1)), s.get("status") or {}
    ready = int(st.get("readyReplicas") or 0)
    ob.ready = f"{ready}/{want}"
    _pods(kube, ns, _selector(((s.get("spec") or {}).get("selector") or {}).get("matchLabels")), ob)
    if ready == want and int(st.get("updatedReplicas") or want) == want:
        ob.status = HEALTHY
        return ob
    ob.events = _events(kube, ns, [name])
    bad = [x for x in ob.states if x.split(":")[0] in BAD_WAITING]
    ob.status, ob.reason = (FAILING, bad[0]) if bad else (PENDING, f"{ready}/{want} ready")
    ob.final = bool(bad) and _definitive(bad, ob.restarts)
    return ob


def observe_cronjob(kube: Kube, ns: str, name: str) -> Observation:
    try:
        kube.get("cronjobs.batch", ns, name)
    except KubeError as e:
        return Observation(NOT_FOUND if e.kind == "not-found" else ERROR, f"CronJob {name}: {e}", final=True)
    try:
        jobs = [j for j in kube.get("jobs.batch", ns).get("items") or []
                if any(o.get("kind") == "CronJob" and o.get("name") == name
                       for o in (j.get("metadata") or {}).get("ownerReferences") or [])]
    except KubeError:
        jobs = []
    if not jobs:
        return Observation(SCHEDULED, "no run yet (the schedule is a placeholder: see HARDENING.md)", final=True)
    last = max(jobs, key=lambda j: (j.get("status") or {}).get("startTime") or "")
    st = last.get("status") or {}
    ob = Observation(final=True)
    if int(st.get("succeeded") or 0):
        ob.status, ob.reason = HEALTHY, f"last run {last['metadata']['name']} succeeded"
        return ob
    if _cond(last, "Failed").get("status") == "True" or int(st.get("failed") or 0):
        ob.status = FAILING
        ob.reason = f"last run {last['metadata']['name']} failed: " \
                    f"{_cond(last, 'Failed').get('reason') or 'pod failed'}"
        _pods(kube, ns, f"job-name={last['metadata']['name']}", ob)
        ob.events = _events(kube, ns, [last["metadata"]["name"]])
        return ob
    return Observation(PENDING, f"run {last['metadata']['name']} in progress")


OBSERVE = {"Deployment": observe_deployment, "StatefulSet": observe_statefulset, "CronJob": observe_cronjob}
RANK = {HEALTHY: 0, SCHEDULED: 1, PENDING: 2, NOT_FOUND: 3, FAILING: 4, ERROR: 5}


def observe_component(kube: Kube, ns: str, workloads: list[tuple[str, str]]) -> Observation:
    """The worst observation over the component's workloads (a console app can have several CronJobs)."""
    if not workloads:
        return Observation(NOT_FOUND, "no workload in the generated k8s.yaml", final=True)
    obs = [OBSERVE[k](kube, ns, n) for k, n in workloads]
    worst = max(obs, key=lambda o: RANK.get(o.status, 9))
    worst.restarts = sum(o.restarts for o in obs)
    if worst.status == HEALTHY:
        worst.final = all(o.final for o in obs)       # Deployments still have to stay up while watched
    return worst


# --------------------------------------------------------------------------- diagnosis

def diagnose_observation(ob: Observation, failures: list[dict] | None = None) -> dict | None:
    """Cluster-stage rules on the pod states and events first (image pull, scheduling, OOM ...), then
    the run-stage rules on the application's log (the same rules as the local build-and-run)."""
    from .verify import _fmt, _messages, diagnose, load_failures
    failures = load_failures() if failures is None else failures
    cluster = [f for f in failures if f.get("stage") == "cluster"]
    run = [f for f in failures if f.get("stage") == "run"]
    state_text = "\n".join([ob.reason, *ob.states, *(f"{e['reason']}: {e['message']}" for e in ob.events)])
    log = _messages(ob.log or "")
    for rules, text, stage in ((cluster, state_text, "cluster"), (run, log, "run"), (cluster, log, "cluster")):
        if not text.strip():
            continue
        d = diagnose(text[-60000:], stage, rules)
        if d:
            fr, caps = d
            out = {"rule": fr["id"], "outcome": fr["outcome"], "stage": stage,
                   "diagnosis": " ".join(str(_fmt(fr.get("diagnosis", ""), caps)).split()),
                   "refs": list(fr.get("refs") or [])}
            if fr["outcome"] in ("code", "platform"):
                f = _fmt(fr.get("finding") or {}, caps)
                f.setdefault("why", out["diagnosis"])
                if fr.get("refs"):
                    f.setdefault("refs", list(fr["refs"]))
                out["finding"] = f
            if fr["outcome"] == "retry":
                out["fix"] = _fmt(fr.get("fix") or {}, caps)
                out["learn"] = _fmt(fr.get("learn"), caps) if fr.get("learn") is not None else None
            return out
    return None


# --------------------------------------------------------------------------- the step

@dataclass
class SandboxOptions:
    kube: KubeOptions = field(default_factory=KubeOptions)
    gitops: str = "auto"              # auto | argocd | flux
    timeout: int = 900                # seconds for sync + rollout of all apps together
    settle: int = 60                  # healthy only when no restart appears while watched this long
    interval: int = 10
    revision: str = ""                # output repository commit to wait for (default: its HEAD)
    learn: bool = True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _result(app: dict, c: dict, status: str, reason: str, **kw) -> dict:
    return {"app": app["app"], "folder": app["rel"], "source_key": app["doc"].get("source_key", ""),
            "clone_url": app["doc"].get("clone_url", ""), "component": c.get("component", ""),
            "project": c.get("project", ""), "project_name": c.get("project_name", ""), "image": c.get("image", ""),
            "workloads": [f"{k}/{n}" for k, n in c.get("workloads") or []],
            "status": status, "status_text": STATUS_TEXT[status], "reason": reason, "checked_at": _now(), **kw}


def verify_sandbox(root: Path, o: SandboxOptions | None = None, kube: Kube | None = None, log=print,
                   sleep=time.sleep, clock=time.monotonic) -> dict:
    """Wait for the sync of every deployed app, then read back each component. Returns the health
    document written to sandbox/health.json (also when the step is skipped)."""
    o = o or SandboxOptions()
    root = Path(root)
    kube = kube or Kube(o.kube)
    apps = deployed_apps(root)
    ours = o.revision
    if not ours and (root / ".git").exists():
        ours = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
    doc = {"checked_at": _now(), "revision": ours, "gitops": o.gitops, "cluster": "", "skipped": "", "components": []}
    if not apps:
        doc["skipped"] = "nothing is deployed"
        return doc
    ok, why = cluster_access(kube)
    if not ok:
        doc["skipped"] = why
        doc["components"] = [_result(a, c, SKIPPED, why) for a in apps for c in a["components"]]
        log(f"sandbox verification skipped: {why}")
        return doc
    doc["cluster"] = why
    log(f"sandbox verification: {len(apps)} apps on {why}, waiting for commit {ours[:12] or '(any)'}")
    deadline = clock() + o.timeout

    # 1) GitOps sync of our commit, all apps polled together
    state: dict[str, tuple[str, str, str]] = {}          # app -> (tool, state, detail)
    while True:
        for a in apps:
            if a["app"] in state and state[a["app"]][1] in ("synced", "failed", "not-found", "error"):
                continue
            try:
                tool, obj = gitops_object(kube, a["app"], o.gitops)
                st, detail = (argo_state if tool == "argocd" else flux_state)(obj, ours, root)
                state[a["app"]] = (tool, st, detail)
            except KubeError as e:
                if e.kind == "unreachable":
                    state[a["app"]] = ("", "error", f"cluster unreachable: {e}")
                elif e.kind == "not-found":                 # maybe not created yet: keep waiting
                    state[a["app"]] = ("", "waiting", f"no Argo CD Application or Flux Kustomization named {a['app']} yet")
                else:
                    state[a["app"]] = ("", "error", str(e))
        if all(s[1] != "waiting" for s in state.values()) or clock() >= deadline:
            break
        sleep(o.interval)
    for k, (tool, st, detail) in state.items():
        if st == "waiting" and not tool:                    # never found within the timeout
            state[k] = (tool, "not-found", detail.replace(" yet", f" within {o.timeout}s (bootstrap applied?)"))

    # 2) rollout of every component of the synced apps
    results: dict[tuple[str, str], dict] = {}
    pending: list[tuple[dict, dict]] = []
    for a in apps:
        tool, st, detail = state.get(a["app"], ("", "waiting", ""))
        for c in a["components"]:
            if st == "synced":
                pending.append((a, c))
            else:
                status = {"waiting": PENDING, "failed": FAILING, "not-found": NOT_FOUND}.get(st, ERROR)
                results[(a["app"], c["component"])] = _result(a, c, status, detail, gitops=tool, sync=detail)
    obs: dict[tuple[str, str], Observation] = {}
    first_healthy: dict[tuple[str, str], tuple[float, int]] = {}
    while pending:
        still = []
        for a, c in pending:
            key = (a["app"], c["component"])
            try:
                ob = observe_component(kube, a["app"], c["workloads"])
            except KubeError as e:
                ob = Observation(ERROR, str(e), final=True)
            obs[key] = ob
            if ob.status == HEALTHY and not ob.final:
                t0, r0 = first_healthy.setdefault(key, (clock(), ob.restarts))
                if ob.restarts > r0:                       # restarted while watched: not stable
                    first_healthy[key] = (clock(), ob.restarts)
                    still.append((a, c))
                elif clock() - t0 < o.settle and clock() < deadline:
                    still.append((a, c))
            elif not ob.final and ob.status != HEALTHY and clock() < deadline:
                first_healthy.pop(key, None)
                still.append((a, c))
        pending = still
        if pending:
            sleep(o.interval)

    failures = None
    for (app_name, comp), ob in obs.items():
        a = next(x for x in apps if x["app"] == app_name)
        c = next(x for x in a["components"] if x["component"] == comp)
        tool, _, detail = state[app_name]
        reason = ob.reason
        if ob.status == HEALTHY:
            reason = reason or f"{ob.ready} ready" + (f", {ob.restarts} restart(s) before it became stable"
                                                       if ob.restarts else "")
        elif ob.status == PENDING:
            reason = f"not ready within {o.timeout}s: {ob.reason}"
            if ob.events:                                   # the newest warning usually says why
                reason += f"; last warning {ob.events[0]['reason']}: {ob.events[0]['message'][:300]}"
        r = _result(a, c, ob.status, reason, gitops=tool, sync=detail, ready=ob.ready, restarts=ob.restarts,
                    states=ob.states, events=ob.events, pod=ob.pod)
        if ob.status in (FAILING, PENDING) and (ob.log or ob.states or ob.events):
            if failures is None:
                from .verify import load_failures
                failures = load_failures()
            d = diagnose_observation(ob, failures)
            if d:
                r["diagnosis"] = d
                r["reason"] = f"{r['reason']} - {d['diagnosis']}" if r["reason"] else d["diagnosis"]
        r["log_tail"] = ob.log            # redacted; kept out of the output repository (see write_health)
        results[(app_name, comp)] = r
    doc["components"] = [results[(a["app"], c["component"])] for a in apps for c in a["components"]]
    if o.learn:
        doc["learned"] = learn_from_cluster(doc["components"])
    return doc


# --------------------------------------------------------------------------- learning loop

def learn_from_cluster(results: list[dict], learned_dir: Path | None = None) -> list[str]:
    """Code/platform failures seen in the cluster become learned findings (with their evidence);
    retry fixes with a `learn` section become learned plan rules. Returns the new rule ids."""
    from .generate import k8s_name
    from .verify import LEARNED, _load, _save
    learned_dir = learned_dir or LEARNED
    new: list[str] = []
    for r in results:
        d = r.get("diagnosis") or {}
        if r.get("status") not in (FAILING, PENDING) or d.get("outcome") not in ("code", "platform", "retry"):
            continue
        pname = r.get("project_name") or Path(r.get("project") or r["component"]).stem
        when = {"name": f"^{re.escape(pname)}$"}
        evidence = [f"sandbox cluster {r.get('checked_at', '')[:10]}: {r['app']}/{r['component']} {r['status']}",
                    *[s for s in (r.get("states") or [])[:3]],
                    *[f"event {e['reason']}: {e['message'][:200]}" for e in (r.get("events") or [])[:3]],
                    f"matched {d['rule']} ({d['stage']} stage)"]
        src = f"{r['app']}/{r['component']}"
        if d["outcome"] in ("code", "platform"):
            f = d.get("finding") or {}
            path = learned_dir / "findings.yaml"
            doc = _load(path, "rules")
            title = f.get("title") or d["diagnosis"][:120] or "Fails in the sandbox cluster"
            if any(x.get("title") == title and x.get("learned_from") == src for x in doc["rules"]):
                continue
            rid = f"learned-cluster-{k8s_name(pname)}-{len(doc['rules']) + 1}"
            doc["rules"].append({"id": rid, "source": "learned", "severity": f.get("severity", "refactor"),
                                 "category": "runtime-observed", "title": title,
                                 "why": " ".join(str(f.get("why") or d["diagnosis"]).split()),
                                 "fix": f.get("fix") or "See the pod log in the sandbox cluster; fix and run the "
                                                        "organization scan again.",
                                 **({"refs": f["refs"]} if f.get("refs") else {}),
                                 "when": when, "learned_from": src, "observed_in": "sandbox-cluster",
                                 "evidence": evidence,
                                 "learned_at": datetime.now(timezone.utc).date().isoformat()})
            _save(path, doc, "# Findings observed at runtime by `containerizer verify --learn`.\n")
            new.append(rid)
        elif d.get("learn") is not None and d.get("fix"):
            path = learned_dir / "plan.yaml"
            doc = _load(path, "rules")
            w = d["learn"].get("when") or when
            rid = f"learned-{d['rule']}-{k8s_name(pname)}" if "name" in w else f"learned-{d['rule']}"
            if rid in {x["id"] for x in doc["rules"]}:
                continue
            doc["rules"].append({"id": rid, "phase": "plan", "source": "learned", "when": w, "plan": d["fix"],
                                 "why": d["diagnosis"], **({"refs": d["refs"]} if d.get("refs") else {}),
                                 **({"scope": d["learn"]["scope"]} if d["learn"].get("scope") else {}),
                                 "learned_from": src, "observed_in": "sandbox-cluster", "evidence": evidence,
                                 "learned_at": datetime.now(timezone.utc).date().isoformat()})
            _save(path, doc, "# Plan rules learned by `containerizer verify --learn`. Safe to edit or delete.\n")
            new.append(rid)
    if new:
        from .confidence import reset_cache
        reset_cache()
    return new


# --------------------------------------------------------------------------- report

PUBLIC = ("app", "folder", "component", "project", "image", "workloads", "status", "status_text", "reason",
          "checked_at", "gitops", "ready", "restarts", "states", "events", "diagnosis")


def public(r: dict) -> dict:
    """What may go to the output repository: no log tails (they can carry data the app printed)."""
    out = {k: r[k] for k in PUBLIC if k in r and r[k] not in (None, "", [])}
    if "diagnosis" in out:
        out["diagnosis"] = {k: v for k, v in out["diagnosis"].items() if k in ("rule", "outcome", "stage", "diagnosis", "refs")}
    return out


ICON = {HEALTHY: "healthy", FAILING: "**failing**", PENDING: "pending", SCHEDULED: "scheduled",
        NOT_FOUND: "**not found**", ERROR: "error", SKIPPED: "not checked"}


def write_health(root: Path, doc: dict) -> None:
    from .org import SANDBOX
    sb = Path(root) / SANDBOX
    sb.mkdir(parents=True, exist_ok=True)
    comps = [public(r) for r in doc.get("components", [])]
    (sb / "health.json").write_text(json.dumps({**{k: v for k, v in doc.items() if k != "components"},
                                                "components": comps}, indent=2, default=str) + "\n")
    counts: dict[str, int] = {}
    for r in comps:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    lines = ["# Sandbox health", "",
             f"Checked {doc['checked_at']} against commit `{(doc.get('revision') or '')[:12] or '(any)'}`"
             + (f" on {doc['cluster']}" if doc.get("cluster") else "") + ". Generated by `containerizer org "
             "--verify-sandbox` / `containerizer sandbox verify`; do not edit.", ""]
    if doc.get("skipped"):
        lines += [f"Not checked: {doc['skipped']}.", ""]
    lines += [" · ".join(f"{k}: {v}" for k, v in sorted(counts.items())), "",
              "| Namespace | Component | Status | Ready | Restarts | Reason |", "| --- | --- | --- | --- | --- | --- |"]
    for r in comps:
        reason = (r.get("reason") or "").replace("|", "/").replace("\n", " ")
        lines.append(f"| `{r['app']}` | [{r['component']}](../{r['folder'].replace(' ', '%20')}/) | "
                     f"{ICON.get(r['status'], r['status'])} | {r.get('ready', '')} | {r.get('restarts', '')} | {reason[:300]} |")
    (sb / "HEALTH.md").write_text("\n".join(lines) + "\n")


def summary(doc: dict) -> str:
    counts: dict[str, int] = {}
    for r in doc.get("components", []):
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return " ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing deployed"


# --------------------------------------------------------------------------- RBAC

def verify_rbac(namespaces: list[str], flux: bool = True, argocd_apps: list[str] | None = None) -> list[dict]:
    """Least-privilege read-back: a ServiceAccount in its own namespace, a Role per app namespace
    (get/list workloads, pods, pod logs and events; no Secrets, no write verbs), and a Role in argocd
    that can only get the generated Applications by name. Nothing cluster-wide."""
    from .gitops import ARGO_NS
    labels = {"app.kubernetes.io/part-of": "containerizer-sandbox", "app.kubernetes.io/managed-by": "containerizer"}
    subject = [{"kind": "ServiceAccount", "name": VERIFIER, "namespace": VERIFIER_NS}]
    docs: list[dict] = [
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": VERIFIER_NS, "labels": {**labels, "pod-security.kubernetes.io/enforce": "restricted"}}},
        {"apiVersion": "v1", "kind": "ServiceAccount",
         "metadata": {"name": VERIFIER, "namespace": VERIFIER_NS, "labels": labels},
         "automountServiceAccountToken": False},
    ]
    rules = [
        {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets"], "verbs": ["get", "list"]},
        {"apiGroups": ["batch"], "resources": ["cronjobs", "jobs"], "verbs": ["get", "list"]},
        {"apiGroups": [""], "resources": ["pods", "events"], "verbs": ["get", "list"]},
        {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
    ]
    for ns in namespaces:
        r = list(rules)
        if flux:
            r.append({"apiGroups": ["kustomize.toolkit.fluxcd.io"], "resources": ["kustomizations"],
                      "resourceNames": [ns], "verbs": ["get"]})
        docs += [
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
             "metadata": {"name": VERIFIER, "namespace": ns, "labels": labels}, "rules": r},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": VERIFIER, "namespace": ns, "labels": labels},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": VERIFIER},
             "subjects": subject},
        ]
    apps = sorted(argocd_apps if argocd_apps is not None else namespaces)
    if apps:
        docs += [
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
             "metadata": {"name": VERIFIER, "namespace": ARGO_NS, "labels": labels},
             "rules": [{"apiGroups": ["argoproj.io"], "resources": ["applications"], "resourceNames": apps,
                        "verbs": ["get"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": VERIFIER, "namespace": ARGO_NS, "labels": labels},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": VERIFIER},
             "subjects": subject},
        ]
    return docs
