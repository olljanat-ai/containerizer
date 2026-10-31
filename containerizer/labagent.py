"""Lab agent of the appliance: runs the lab services in the k3s sandbox (labservices.py), as root.

    python -m containerizer.labagent reconcile     apply lab-services.json to the cluster (timer, every 2 min)
    python -m containerizer.labagent status        print the last status

What `reconcile` does, every time (idempotent):

1. the namespace `containerizer-lab` (Pod Security restricted, default deny, no API tokens);
2. finds the apps that asked for a lab service: ExternalSecrets labelled `containerizer.io/lab-service`
   in their own namespace, reading remote key `<namespace>--cz-lab-<service>` (any other key is ignored,
   so a namespace can only ever ask for its own credentials);
3. for each service that is on and asked for: runs it (shared server, or one instance per app), creates
   the app's credentials once and keeps them in the secret store (namespace containerizer-secrets, field
   manager containerizer-lab), creates the app's database and login, and lets only that namespace in;
4. for each service that is off: stops its servers and instances, keeps their volumes, admin passwords
   and the apps' credentials, so turning it on again brings everything back;
5. writes /run/containerizer/system/lab-status.json for the web UI (no secrets).

Secrets never appear on a command line: values go to kubectl on stdin, provisioning scripts go to the
server's own client on stdin, and admin passwords stay in the server's environment.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import labservices as L

STATUS_PATH = Path("/run/containerizer/system/lab-status.json")
STATE_PATH = Path("/var/lib/containerizer/lab/state.json")
IMAGES_ENV = Path("/usr/lib/containerizer/images.env")
MANAGER = "containerizer-lab"
ES_CRD = "externalsecrets.external-secrets.io"
COREDNS_KEY = "containerizer-lab-s3.override"
# S3 clients that address buckets as <bucket>.<endpoint host> (virtual-hosted style, the AWS SDK default):
# the bucket's name resolves to the app's S3 instance. CoreDNS in k3s imports coredns-custom/*.override.
COREDNS_REWRITE = (r"rewrite stop name regex ^[a-z0-9][a-z0-9.-]*\.(s3-[a-z0-9-]+)\.containerizer-lab\.svc\.cluster\.local\.$ "
                   r"{1}.containerizer-lab.svc.cluster.local. answer auto" + "\n")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class KubeError(Exception):
    pass


class Kubectl:
    """kubectl as the cluster admin (k3s.yaml). Values are passed on stdin only."""

    def __init__(self, cmd: str | None = None, kubeconfig: str | None = None, timeout: int = 60):
        self.cmd = shlex.split(cmd or os.environ.get("CZ_KUBECTL") or "kubectl")
        self.kubeconfig = kubeconfig or os.environ.get("KUBECONFIG")
        self.timeout = timeout

    def run(self, args: list[str], input: str | None = None, check: bool = True, timeout: int | None = None,
            redact: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
        cmd = self.cmd + ([f"--kubeconfig={self.kubeconfig}"] if self.kubeconfig else []) + args
        try:
            p = subprocess.run(cmd, input=input, capture_output=True, text=True, errors="replace",
                               timeout=timeout or self.timeout, stdin=None if input is not None else subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise KubeError(f"kubectl {args[0]}: timed out") from None
        except OSError as ex:
            raise KubeError(f"kubectl: {ex}") from None
        if check and p.returncode:
            err = (p.stderr or p.stdout).strip()
            for r in redact:
                if r:
                    err = err.replace(r, "***")
            raise KubeError(f"kubectl {args[0]} {' '.join(a for a in args[1:3] if not a.startswith('-'))}: {err[-600:]}")
        return p

    def get(self, args: list[str]) -> dict | None:
        p = self.run(["get", *args, "-o", "json"], check=False)
        if p.returncode:
            if "NotFound" in p.stderr or "not found" in p.stderr:
                return None
            raise KubeError(f"kubectl get {' '.join(args)}: {p.stderr.strip()[-400:]}")
        return json.loads(p.stdout or "{}")

    def apply(self, docs: list[dict], force: bool = True) -> None:
        if not docs:
            return
        # JSON, not YAML: kubectl reads YAML 1.1, where a plain Y (ACCEPT_EULA) is a boolean.
        body = json.dumps({"apiVersion": "v1", "kind": "List", "items": docs})
        self.run(["apply", "--server-side", f"--field-manager={MANAGER}", *(["--force-conflicts"] if force else []),
                  "-f", "-"], input=body, timeout=120)

    def delete(self, kinds: str, selector: str, ns: str = L.LAB_NS) -> None:
        self.run(["-n", ns, "delete", kinds, "-l", selector, "--ignore-not-found", "--wait=false"], timeout=120)

    def exec(self, ns: str, pod: str, container: str, cmd: list[str], script: str, timeout: int = 300,
             redact: tuple[str, ...] = ()) -> str:
        p = self.run(["-n", ns, "exec", "-i", pod, "-c", container, "--", *cmd], input=script, check=True,
                     timeout=timeout, redact=redact)
        return p.stdout


# --------------------------------------------------------------------------- inputs

def load_images(path: Path = IMAGES_ENV, env=None) -> dict:
    """The pinned images of the lab services: images.env, overridden by the environment."""
    env = os.environ if env is None else env
    out: dict = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    for s in L.SERVICES.values():
        if env.get(s.image_var):
            out[s.image_var] = env[s.image_var]
    return out


def requests(kube: Kubectl) -> tuple[dict[str, list[str]], list[str]]:
    """{service: [namespaces]} that asked for credentials, and why others were ignored."""
    data = kube.get([ES_CRD, "-A", "-l", L.LABEL]) or {}
    out: dict[str, set] = {}
    ignored = []
    for es in data.get("items") or []:
        meta = es.get("metadata") or {}
        ns, svc = meta.get("namespace", ""), (meta.get("labels") or {}).get(L.LABEL, "")
        spec = es.get("spec") or {}
        keys = {(x.get("extract") or {}).get("key") for x in spec.get("dataFrom") or []} | \
               {(x.get("remoteRef") or {}).get("key") for x in spec.get("data") or []}
        try:
            L.check_namespace(ns)
            if svc not in L.SERVICES:
                raise L.LabError(f"unknown service {svc!r}")
            if keys != {L.remote_key(ns, svc)}:
                raise L.LabError(f"reads {sorted(k for k in keys if k)}, not its own key {L.remote_key(ns, svc)}")
        except L.LabError as ex:
            ignored.append(f"{ns}/{meta.get('name')}: {ex}")
            continue
        out.setdefault(svc, set()).add(ns)
    return {k: sorted(v) for k, v in out.items()}, ignored


# --------------------------------------------------------------------------- the secret store

def _store_ns() -> str:
    from . import eso
    return eso.remote_namespace()


def read_store(kube: Kubectl, key: str) -> dict:
    d = kube.get(["-n", _store_ns(), "secret", key])
    if not d:
        return {}
    return {k: base64.b64decode(v).decode() for k, v in (d.get("data") or {}).items()}


def write_store(kube: Kubectl, key: str, svc: str, ns: str, cred: dict) -> None:
    kube.apply([{"apiVersion": "v1", "kind": "Secret",
                 "metadata": {"name": key, "namespace": _store_ns(),
                              "labels": {**L.MANAGED, L.LABEL: svc, L.APP_LABEL: ns}},
                 "type": "Opaque",
                 "data": {k: base64.b64encode(v.encode()).decode() for k, v in sorted(cred.items())}}])


def admin_password(kube: Kubectl, svc: str) -> str:
    """The server's admin password: Secret <svc>-admin in the lab namespace, created once."""
    name = L.admin_secret_name(svc)
    d = kube.get(["-n", L.LAB_NS, "secret", name])
    if d and (d.get("data") or {}).get("password"):
        return base64.b64decode(d["data"]["password"]).decode()
    pw = L.new_password()
    kube.apply([{"apiVersion": "v1", "kind": "Secret",
                 "metadata": {"name": name, "namespace": L.LAB_NS, "labels": {**L.MANAGED, L.LABEL: svc}},
                 "type": "Opaque", "data": {"password": base64.b64encode(pw.encode()).decode()}}], force=False)
    return pw


# --------------------------------------------------------------------------- state

def load_state(path: Path) -> dict:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_json(path: Path, data: dict, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def ready_pod(kube: Kubectl, svc: str, name: str) -> dict | None:
    data = kube.get(["-n", L.LAB_NS, "pods", "-l", f"{L.LABEL}={svc},app.kubernetes.io/name={name}"]) or {}
    for p in data.get("items") or []:
        if (p.get("metadata") or {}).get("deletionTimestamp"):
            continue
        conds = {c.get("type"): c.get("status") for c in (p.get("status") or {}).get("conditions") or []}
        if conds.get("Ready") == "True":
            return p
    return None


READY_GRACE = 180       # seconds after a server turns ready during which a failed provisioning is retried


def _ready_for(pod: dict) -> float:
    """Seconds since the pod's Ready condition last turned true (a large number if unknown)."""
    for c in (pod.get("status") or {}).get("conditions") or []:
        if c.get("type") == "Ready" and c.get("lastTransitionTime"):
            try:
                t = datetime.strptime(c["lastTransitionTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                break
            return (datetime.now(timezone.utc) - t).total_seconds()
    return 1e9


def _pod_problem(kube: Kubectl, svc: str, name: str) -> str:
    data = kube.get(["-n", L.LAB_NS, "pods", "-l", f"{L.LABEL}={svc},app.kubernetes.io/name={name}"]) or {}
    for p in data.get("items") or []:
        for cs in (p.get("status") or {}).get("containerStatuses") or []:
            w = (cs.get("state") or {}).get("waiting") or {}
            if w.get("reason"):
                msg = f"{w['reason']}: {str(w.get('message') or '')[:200]}".rstrip(": ")
                if w["reason"] == "CrashLoopBackOff":       # why it crashed: the end of its last log
                    try:
                        last = kube.run(["-n", L.LAB_NS, "logs", "--previous", "--tail=5", p["metadata"]["name"],
                                         "-c", cs.get("name") or name], check=False).stdout.strip()
                    except KubeError:
                        last = ""
                    if last:
                        msg += " - last log: " + " | ".join(last.splitlines())[-400:]
                return msg
        status = p.get("status") or {}
        if status.get("reason"):        # e.g. Evicted: The node was low on resource: ephemeral-storage
            return f"{status.get('phase') or 'Failed'} ({status['reason']}): {str(status.get('message') or '')[:200]}".rstrip(": ")
        return status.get("phase") or "starting"
    return "starting"


# --------------------------------------------------------------------------- reconcile

def coredns_override(kube: Kubectl) -> None:
    """Virtual-hosted S3 names (<bucket>.s3-<app>...) resolve to the app's instance. Only where CoreDNS
    imports coredns-custom (k3s); restarts CoreDNS when the rule changes."""
    dep = kube.get(["-n", "kube-system", "deployment", "coredns"])
    vols = (((dep or {}).get("spec") or {}).get("template") or {}).get("spec", {}).get("volumes") or []
    if not any((v.get("configMap") or {}).get("name") == "coredns-custom" for v in vols):
        return
    cm = kube.get(["-n", "kube-system", "configmap", "coredns-custom"]) or {}
    if (cm.get("data") or {}).get(COREDNS_KEY) == COREDNS_REWRITE:
        return
    kube.apply([{"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "coredns-custom", "namespace": "kube-system"},
                 "data": {COREDNS_KEY: COREDNS_REWRITE}}])
    kube.run(["-n", "kube-system", "rollout", "restart", "deployment/coredns"], check=False)


def stop(kube: Kubectl, svc: str, keep_apps: list[str] | None = None) -> None:
    """Stop a service, or (keep_apps) only the instances and policies of apps that no longer ask.
    Volumes, admin passwords and the apps' credentials stay."""
    if keep_apps is None:
        kube.delete("deployment,service,networkpolicy", f"{L.LABEL}={svc}")
        kube.delete("secret", f"{L.LABEL}={svc},{L.APP_LABEL}")
        return
    sel = f"{L.LABEL}={svc},{L.APP_LABEL}" + (f",{L.APP_LABEL} notin ({','.join(keep_apps)})" if keep_apps else "")
    kube.delete("deployment,service,networkpolicy", sel)
    kube.delete("secret", sel)


def force_sync(kube: Kubectl, ns: str, svc: str) -> None:
    kube.run(["-n", ns, "annotate", "--overwrite", f"{ES_CRD}/{L.secret_name(svc)}", f"force-sync={int(time.time())}"],
             check=False)


def credentials(kube: Kubectl, svc: str, ns: str) -> tuple[dict, bool]:
    """The app's credentials from the store (created and stored on first use): (cred, new)."""
    key = L.remote_key(ns, svc)
    cred = read_store(kube, key)
    if L.complete(svc, ns, cred):
        return cred, False
    cred = L.new_credentials(svc, ns, cred)
    write_store(kube, key, svc, ns, cred)
    return cred, True


def reconcile(kube: Kubectl, config: dict, images: dict, state_path: Path = STATE_PATH,
              status_path: Path | None = STATUS_PATH, provision_timeout: int = 300) -> dict:
    enabled = config["services"]
    status = {"checked_at": now(), "config": {"services": enabled, "changed_by": config.get("changed_by"),
                                              "changed_at": config.get("changed_at")},
              "services": {}, "ignored": [], "error": None}

    def done() -> dict:
        if status_path:
            save_json(status_path, status, 0o644)
        return status
    try:
        if kube.run(["get", "crd", ES_CRD], check=False).returncode:
            status["error"] = "External Secrets Operator is not installed or not ready yet; lab services wait for it."
            return done()
        kube.apply(L.namespace_docs())
        try:
            coredns_override(kube)
        except KubeError as ex:
            log(f"coredns: {ex}")
        asked, status["ignored"] = requests(kube)
    except KubeError as ex:
        status["error"] = str(ex)[:800]
        return done()
    state = load_state(state_path)
    for svc in L.ORDER:
        s = L.SERVICES[svc]
        apps = asked.get(svc, [])
        st = {"enabled": bool(enabled.get(svc)), "apps": apps, "state": "", "message": "", "ready": []}
        status["services"][svc] = st
        try:
            if not enabled.get(svc):
                stop(kube, svc)
                st["state"] = "off"
                if apps:
                    st["message"] = f"{len(apps)} app(s) ask for it while it is off"
                continue
            if not apps:
                stop(kube, svc)
                st["state"] = "idle"
                continue
            image = images.get(s.image_var)
            if not image:
                raise L.LabError(f"no image: set {s.image_var} in images.env")
            if s.shared:
                _shared(kube, svc, apps, image, state, st, provision_timeout)
            else:
                _per_app(kube, svc, apps, image, st)
        except (KubeError, L.LabError) as ex:
            st["state"], st["message"] = "error", str(ex)[:800]
            log(f"{svc}: {ex}")
    save_json(state_path, state, 0o600)
    return done()


def _shared(kube: Kubectl, svc: str, apps: list[str], image: str, state: dict, st: dict, timeout: int) -> None:
    if svc in L.ADMIN_PASSWORD:
        admin_password(kube, svc)
    kube.apply(L.shared_manifests(svc, image) + [L.ingress_policy(svc, ns) for ns in apps])
    stop(kube, svc, keep_apps=apps)         # policies of apps that left
    creds = {}
    for ns in apps:
        creds[ns], new = credentials(kube, svc, ns)
        if new:
            force_sync(kube, ns, svc)
    pod = ready_pod(kube, svc, svc)
    if not pod:
        st["state"], st["message"] = "starting", _pod_problem(kube, svc, svc)
        return
    uid = pod["metadata"]["uid"]
    done = state.setdefault(svc, {})
    failed = []
    for ns in apps:
        mark = f"{uid}:{hashlib.sha256(creds[ns]['password'].encode()).hexdigest()[:16]}"
        if done.get(ns) == mark:
            st["ready"].append(ns)
            continue
        try:
            kube.exec(L.LAB_NS, pod["metadata"]["name"], svc, L.provision_command(svc),
                      L.provision_sql(svc, ns, creds[ns]), timeout=timeout, redact=(creds[ns]["password"],))
            done[ns] = mark
            st["ready"].append(ns)
        except KubeError as ex:
            failed.append(f"{ns}: {ex}")
    for ns in [n for n in done if n not in apps]:
        done.pop(ns)          # the database stays; a new pod or password provisions it again
    # a server that only just turned ready may still be finishing its first start (MySQL's entry point
    # restarts it): retry on the next round before calling it an error
    young = _ready_for(pod) < READY_GRACE
    st["state"] = ("starting" if young else "error") if failed else "running"
    st["message"] = "; ".join(failed)[:800]


def _per_app(kube: Kubectl, svc: str, apps: list[str], image: str, st: dict) -> None:
    docs = []
    new_apps = []
    for ns in apps:
        cred, new = credentials(kube, svc, ns)
        docs += L.per_app_manifests(svc, ns, image, cred)
        if new:
            new_apps.append(ns)
    kube.apply(docs)
    stop(kube, svc, keep_apps=apps)
    for ns in new_apps:
        force_sync(kube, ns, svc)
    waiting = []
    for ns in apps:
        if ready_pod(kube, svc, L.instance(svc, ns)):
            st["ready"].append(ns)
        else:
            waiting.append(f"{ns}: {_pod_problem(kube, svc, L.instance(svc, ns))}")
    st["state"] = "running" if not waiting else "starting"
    st["message"] = "; ".join(waiting)[:800]


# --------------------------------------------------------------------------- the system agent's request

def apply_request(req: dict, config_path: Path = L.CONFIG_PATH) -> dict:
    """Admin -> Lab services: validated here again (the web UI is not trusted), then written to
    lab-services.json; the lab agent applies it and the next scans use it."""
    services = L.validate(req.get("services"))
    data = {"services": services, "changed_by": str(req.get("requested_by") or "?")[:256],
            "changed_by_name": str(req.get("requested_by_name") or "")[:256], "changed_at": now()}
    save_json(config_path, data, 0o644)
    return data


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else ""
    if cmd == "reconcile":
        cfg = L.load_config(Path(os.environ.get(L.CONFIG_ENV) or L.CONFIG_PATH))
        st = reconcile(Kubectl(), cfg, load_images())
        for svc, x in st["services"].items():
            log(f"{svc}: {x['state']}{(' - ' + x['message']) if x['message'] else ''}")
        if st.get("error"):
            log(f"error: {st['error']}")
        return 1 if st.get("error") or any(x["state"] == "error" for x in st["services"].values()) else 0
    if cmd == "status":
        try:
            print(STATUS_PATH.read_text())
        except OSError as ex:
            log(str(ex))
            return 1
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
