"""System agent of the containerizer appliance: `python -m containerizer.sysagent <command>`, as root.

The only part of the appliance that changes the OS. The web UI (unprivileged) reads what this agent
publishes in /run/containerizer/system/status.json and asks for changes by dropping a JSON file into
/run/containerizer/system/requests/; containerizer-sysagent.path starts `process`, which checks each
request again before acting on it:

- upgrade:  only a release tag (vX.Y.Z) of the one image repository this OS was built for
            (CZ_OS_IMAGE), only after `cosign verify` proved it was signed by this project's release
            workflow (keyless, GitHub OIDC), and installed by digest, so the tag cannot be moved between
            the check and the download. Elemental writes it as a new btrfs snapshot; the running system
            is not touched, and the boot assessment falls back to it when the new one fails to start.
            A newer patch release of the running OS's series (vX.Y.*) is an app update instead
            (apppatch.py): the signed application image of that release (CZ_APP_IMAGE, the same signer)
            is unpacked on the persistent partition and mounted over the code, and only the containerizer
            services restart; the OS does not. If they do not come up, the previous code is put back.
- app-patch-remove: the app update off again: the OS image's own code runs, the services restart.
- rollback: only a snapshot that is on the disk; Elemental installs a copy of it as the new active
            system (no download, no registry needed).
- egress:   the administrators' egress allow-list (validated here, not trusted from the web UI), then
            the firewall and the DNS filter are rebuilt from it.
- sandbox-https: the wildcard domain, certificate and key for the apps in the k3s sandbox (checked
            again here, sandbox_https.py): Caddy answers for *.<domain> with it and passes the requests to
            Traefik in k3s, whose default certificate becomes the same one. The key is written for root
            and Caddy only and is never published; the web UI cannot read it back.
- plan / plan-cancel: a planned restart (restartplan.py): a plain restart, an upgrade or a roll back, now or
            at a set time; from then on no new scan run or LLM job starts, and `restart-check` restarts
            once the work in progress is done or the longest wait allowed is over. Kept on the persistent
            partition and published in status.json (`restart`), where the worker and the LLM runner read it.
- dbquery / dbdelete: the database browser of Admin -> Dev databases (dbbrowse.py): a statement run as an
            application's own database login in its own sandbox database, or that database dropped and created
            again; the answer goes to answers/<id>.json, readable by the web UI's group only.
- local-llm: the built-in LLM on or off (local_llm.py checks the RAM and the disk again); while its model
            downloads, huggingface.co and hf.co are on the egress allow-list.

Commands (also for an administrator on the console or over SSH):

    status                     publish status.json (and start or stop the built-in LLM as set)
    process                    handle the queued requests
    upgrade vX.Y.Z [--full]    verify, install and restart (an app update for a patch release of the
                               running series, unless --full)
    app-patch select           mount the active app update when it fits the running OS (at start-up)
    app-patch remove           back to the OS image's own code; the services restart
    rollback <snapshot id>     install a copy of a snapshot and restart
    restart-check              carry out the planned restart when it is due (containerizer-restart.timer)
    firewall apply             (re)build the nftables ruleset and the dnsmasq allow-list
    firewall show              print what `apply` would load
    sandbox-https sync         install the sandbox certificate in k3s (containerizer-sandbox runs it)
    health                     boot-assessment check (exit 1 when the appliance is not up)
    sql-env                    write the results database settings from appliance.env (cz-firstboot)
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import apppatch, local_llm, restartplan
from .apppatch import PatchError
from .local_llm import LocalLlmError

VERSION_RE = re.compile(r"v\d{1,4}\.\d{1,4}\.\d{1,4}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
PORT_RE = re.compile(r"(?:(tcp|udp)/)?(\d{1,5})")
MAX_RULES = 500
MAX_PORTS = 16
NOTE_MAX = 200
TABLE = "cz_firewall"
DNS_ADDR = "169.254.53.53"        # dnsmasq: the one resolver of the host, Docker and k3s
INBOUND_TCP = (22, 443)           # SSH and HTTPS; nothing else is reachable from outside
# k3s pods and services, Docker bridges: traffic between them and the host stays allowed
INTERNAL4 = ("10.42.0.0/16", "10.43.0.0/16", "172.16.0.0/12")
INTERNAL_IFACES = ("cni0", "flannel.1", "docker0", "br-*", "veth*")


@dataclass
class Paths:
    conf: Path = Path("/usr/lib/containerizer/appliance.conf")
    system_rules: Path = Path("/usr/lib/containerizer/egress-system.json")
    rules: Path = Path("/etc/containerizer/egress.json")
    history: Path = Path("/var/lib/containerizer/system/egress-history.jsonl")
    task: Path = Path("/var/lib/containerizer/system/last-task.json")
    plan: Path = Path("/var/lib/containerizer/system/restart-plan.json")
    sql_secret: Path = Path("/etc/containerizer/secrets/cz-scanner")
    run: Path = Path("/run/containerizer/system")
    dnsmasq: Path = Path("/run/containerizer/dnsmasq/egress.conf")
    nft: Path = Path("/run/containerizer/firewall.nft")
    os_release: Path = Path("/etc/os-release")
    appliance_env: Path = Path("/etc/containerizer/appliance.env")
    resolved: Path = Path("/run/systemd/resolve/resolv.conf")
    snapshots: Path = Path("/.snapshots")
    elemental_run: Path = Path("/run/elemental")
    https_dir: Path = Path("/var/lib/containerizer/system")    # sandbox-https.{json,crt,key,caddy}, -history.jsonl
    caddyfile: Path = Path("/etc/caddy/Caddyfile")
    caddy_env: Path = Path("/run/containerizer/caddy.env")
    web_env: Path = Path("/etc/containerizer/web.env")
    kubeconfig: Path = Path("/etc/rancher/k3s/k3s.yaml")
    sql_env: Path = Path("/run/containerizer/sql.env")
    sql_ca: Path = Path("/run/containerizer/sql-ca.pem")
    patches: Path = Path("/var/lib/containerizer/app-patches")          # app updates, <version>/ and `active`
    patch_mount: Path = Path("/run/containerizer/app-patch")            # the active one, read-only
    requirements_sha: Path = Path("/usr/lib/containerizer/requirements.sha256")
    learned: Path = Path("/var/lib/containerizer/learned")

    def https(self, ext: str) -> Path:
        return self.https_dir / f"sandbox-https{ext}"


P = Paths()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(cmd: list[str], timeout: int = 3600, check: bool = True, input: str | None = None) -> str:
    """Run a command (never through a shell); its output goes to the journal on failure."""
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input, errors="replace")
    if check and p.returncode:
        raise AgentError(f"{shlex.join(cmd[:3])} failed ({p.returncode}): {(p.stderr or p.stdout).strip()[-2000:]}")
    return p.stdout


class AgentError(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_env(path: Path) -> dict:
    out = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def conf() -> dict:
    c = read_env(P.conf)
    c.setdefault("CZ_OS_IMAGE", "ghcr.io/olljanat-ai/containerizer-appliance")
    c.setdefault("CZ_SIGNER_REPO", "olljanat-ai/containerizer")
    c.setdefault("CZ_APP_IMAGE", apppatch.app_image(c["CZ_OS_IMAGE"]))
    c.setdefault("CZ_SIGNER_ISSUER", "https://token.actions.githubusercontent.com")
    c.setdefault("CZ_SIGNER_IDENTITY_REGEXP", "^https://github\\.com/" + re.escape(c["CZ_SIGNER_REPO"])
                 + "/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$")
    return c


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)


# =============================================================================== status

def running_version() -> str | None:
    return read_env(P.os_release).get("IMAGE_TAG")


def boot_mode() -> str:
    for m in ("recovery", "passive", "active"):
        if (P.elemental_run / f"{m}_mode").exists():
            return m
    return "unknown"


def _scalar(v) -> str:
    return "" if v is None else str(v)


def snapshots(state_yaml: str | None = None) -> list[dict]:
    """The state partition's snapshots from `elemental state`, newest first, each with the version
    read from the snapshot's own /etc/os-release."""
    import yaml
    if state_yaml is None:
        try:
            state_yaml = run(["elemental", "state"], timeout=120)
        except (AgentError, OSError, subprocess.TimeoutExpired) as ex:
            log(f"elemental state: {ex}")
            return []
    try:
        st = yaml.safe_load(state_yaml) or {}
    except yaml.YAMLError:
        return []
    part = st.get("state") if isinstance(st, dict) else None
    snaps = (part or {}).get("snapshots") or {}
    out = []
    for sid, s in snaps.items():
        if not isinstance(s, dict) or not re.fullmatch(r"\d{1,6}", str(sid)):
            continue
        labels = s.get("labels") or {}
        version = read_env(P.snapshots / str(sid) / "snapshot" / "etc" / "os-release").get("IMAGE_TAG") \
            or labels.get("version")
        out.append({"id": int(sid), "active": bool(s.get("active")), "version": version,
                    "source": _scalar(s.get("source")), "digest": _scalar(s.get("digest")),
                    "date": _scalar(s.get("date")), "labels": {str(k): _scalar(v) for k, v in labels.items()}})
    return sorted(out, key=lambda x: x["id"], reverse=True)


def elemental_version() -> str:
    try:
        return run(["elemental", "version"], timeout=30).strip().splitlines()[0][:80]
    except (AgentError, OSError, subprocess.TimeoutExpired, IndexError):
        return ""


def last_task() -> dict | None:
    """The last upgrade or roll back, kept on the persistent partition so the System page still shows it
    after the restart. A task that was restarting into its new snapshot is finished now: done when this
    boot is the active snapshot, failed when the boot assessment fell back to the previous one."""
    try:
        t = json.loads(P.task.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(t, dict):
        return None
    if t.get("state") == "rebooting":
        if boot_mode() == "passive":
            t.update(state="failed", message=(t.get("message") or "") + ". The new system did not pass its start-up "
                     "check; the appliance went back to the previous snapshot.")
        else:
            t.update(state="done", message=(t.get("message") or "").removesuffix("; restarting") + "; restarted")
        save_task(t)
    return t


def save_task(task: dict) -> None:
    try:
        atomic_write(P.task, json.dumps(task), 0o644)
    except OSError as ex:
        log(f"could not keep the task state: {ex}")


def publish(task: dict | None = None, egress_state: dict | None = None, https_state: dict | None = None) -> dict:
    """Write status.json (world-readable: it holds no secrets)."""
    old = {}
    try:
        old = json.loads((P.run / "status.json").read_text())
    except (OSError, ValueError):
        pass
    if task is not None:
        save_task(task)
    c = conf()
    patch = mounted_patch()
    st = {"version": (patch or {}).get("version") or running_version(), "os_version": running_version(),
          "app_patch": patch, "app_updates": bool(requirements_sha()),
          "image": c["CZ_OS_IMAGE"], "signer": c["CZ_SIGNER_REPO"],
          "boot_mode": boot_mode(), "elemental": old.get("elemental") or elemental_version(),
          "hostname": socket.gethostname(), "snapshots": snapshots(), "updated": now(),
          "task": task if task is not None else last_task(), "restart": load_plan(),
          "egress": egress_state if egress_state is not None else (old.get("egress") or egress_status()),
          "sandbox_https": https_state if https_state is not None else (old.get("sandbox_https") or sandbox_https_status())}
    atomic_write(P.run / "status.json", json.dumps(st, indent=1), 0o644)
    return st


# =============================================================================== upgrade / rollback

def verify_signature(version: str, c: dict | None = None, image: str | None = None) -> str:
    """`cosign verify` the release tag against the release workflow's identity; the verified digest."""
    c = c or conf()
    if not VERSION_RE.fullmatch(version or ""):
        raise AgentError(f"not a release version: {version!r}")
    ref = f"{image or c['CZ_OS_IMAGE']}:{version}"
    out = run(["cosign", "verify", "--certificate-identity-regexp", c["CZ_SIGNER_IDENTITY_REGEXP"],
               "--certificate-oidc-issuer", c["CZ_SIGNER_ISSUER"], "--output", "json", ref], timeout=600)
    digests = set()
    try:
        for item in json.loads(out):
            digests.add(item["critical"]["image"]["docker-manifest-digest"])
    except (ValueError, KeyError, TypeError) as ex:
        raise AgentError(f"unexpected cosign output: {ex}") from None
    if len(digests) != 1 or not DIGEST_RE.fullmatch(next(iter(digests))):
        raise AgentError(f"cosign did not return exactly one digest for {ref}: {sorted(digests)}")
    return digests.pop()


def _snapshots_rw() -> None:
    # /.snapshots is mounted read-only on the running system; Elemental writes the new snapshot there
    if os.path.ismount(str(P.snapshots)):
        run(["mount", "-o", "remount,rw", str(P.snapshots)], timeout=60, check=False)


def upgrade(version: str, task: dict, reboot: bool = True, full: bool = False) -> None:
    """A newer patch release of the running OS's series is an app update (no OS restart) when this OS image
    supports them; anything else, or `full`, is a new OS snapshot and a restart."""
    if not full and requirements_sha() and apppatch.is_patch_of(version, running_version()):
        install_patch(version, task)
        return
    c = conf()
    task.update(state="running", started=now(), message="Verifying the image signature")
    publish(task)
    digest = verify_signature(version, c)
    task.update(message=f"Signature verified ({digest[:19]}…); installing")
    publish(task)
    _snapshots_rw()
    run(["elemental", "upgrade", "--system", f"oci:{c['CZ_OS_IMAGE']}@{digest}",
         "--snapshot-labels", f"version={version},digest={digest.replace(':', '-')}"], timeout=3 * 3600)
    _finish(task, f"Installed {version} ({digest[:19]}…)", reboot)


def rollback(snapshot: int, task: dict, reboot: bool = True) -> None:
    snaps = {s["id"]: s for s in snapshots()}
    s = snaps.get(snapshot)
    if not s or s["active"]:
        raise AgentError(f"snapshot {snapshot} is not an earlier snapshot on this disk")
    path = P.snapshots / str(snapshot) / "snapshot"
    if not (path / "etc" / "os-release").is_file():
        raise AgentError(f"{path} is not readable")
    task.update(state="running", started=now(), message=f"Installing a copy of snapshot {snapshot}")
    publish(task)
    _snapshots_rw()
    labels = f"version={s['version'] or 'unknown'},rollback-of={snapshot}"
    run(["elemental", "upgrade", "--system", f"dir:{path}", "--snapshot-labels", labels], timeout=3 * 3600)
    set_active_patch(None)          # the snapshot as it was: its own code, without the app update
    _finish(task, f"Rolled back to snapshot {snapshot} ({s['version'] or 'unknown version'})", reboot)


def _finish(task: dict, msg: str, reboot: bool) -> None:
    task.update(state="rebooting" if reboot else "done", finished=now(), message=msg + ("; restarting" if reboot else ""))
    publish(task)
    if reboot:
        run(["systemctl", "reboot"], timeout=60, check=False)


# =============================================================================== app updates

# the long-running services that run the containerizer code; the one-shot ones take the new code at their next run
PATCH_SERVICES = ("containerizer-web.service", "containerizer-worker.service", "containerizer-llm-queue.service",
                  "containerizer-egress-observer.service")
PATCH_START_WAIT = 120      # seconds the services may take to come up with the new code
PATCH_SETTLE = 10           # seconds they must keep running (a crash loop restarts them)
HEALTHZ = "http://127.0.0.1:8080/healthz"


def requirements_sha() -> str | None:
    """The hash of the Python packages' lock this OS image was built with; None for an image without app updates."""
    try:
        v = P.requirements_sha.read_text().split()[0]
    except (OSError, IndexError):
        return None
    return v if apppatch.SHA_RE.fullmatch(v) else None


def active_patch() -> str | None:
    try:
        v = (P.patches / "active").read_text().strip()
    except OSError:
        return None
    return v if VERSION_RE.fullmatch(v) else None


def set_active_patch(version: str | None) -> None:
    if version is None:
        (P.patches / "active").unlink(missing_ok=True)
    else:
        atomic_write(P.patches / "active", version + "\n", 0o644)


def mounted_patch() -> dict | None:
    """The app update the code runs from now: its manifest, or None (the OS image's own code)."""
    try:
        m = json.loads((P.patch_mount / "manifest.json").read_text())
    except (OSError, ValueError):
        return None
    return {"version": m.get("version"), "series": m.get("series")} if isinstance(m, dict) else None


def check_patch(version: str) -> Path:
    """The installed update `version`, checked against the running OS: its folder."""
    root = P.patches / version
    apppatch.check_manifest(apppatch.read_manifest(root), version, running_version(), requirements_sha())
    apppatch.check_tree(root, version)
    return root


def mount_patch(version: str | None) -> None:
    """Mount the update read-only on P.patch_mount (listed before the OS image's code in containerizer.pth), or
    nothing there. Lazily unmounted: a process still running reads its files until it restarts. Only in the
    host's mount namespace (containerizer-app-patch.service): the agent's own units have a private one."""
    P.patch_mount.mkdir(parents=True, exist_ok=True)
    if os.path.ismount(str(P.patch_mount)):
        run(["umount", "--lazy", str(P.patch_mount)], timeout=60)
    if version:
        run(["mount", "--bind", "-o", "ro", str(P.patches / version), str(P.patch_mount)], timeout=60)


def select_patch() -> str:
    """At start-up, before the containerizer services: mount the active update if it still fits the running OS
    (after a full upgrade to another series, or another set of Python packages, it does not)."""
    v = active_patch()
    if not v:
        mount_patch(None)
        return "no app update: the OS image's own code"
    try:
        check_patch(v)
    except PatchError as ex:
        mount_patch(None)
        return f"app update {v} not used: {ex}"
    mount_patch(v)
    return f"app update {v} mounted"


def reselect(expect: str | None) -> None:
    """Have containerizer-app-patch.service (the host's mount namespace, the OS image's own code) mount the active
    update again, and check that `expect` (None: none) is what the code now runs from."""
    run(["systemctl", "restart", "containerizer-app-patch.service"], timeout=120)
    got = (mounted_patch() or {}).get("version")
    if got != expect:
        raise AgentError(f"the code runs from {got or 'the OS image'}, not from {expect or 'the OS image'}: "
                         f"see journalctl -u containerizer-app-patch")


def restart_services() -> None:
    run(["systemctl", "try-restart", *PATCH_SERVICES], timeout=300, check=False)


def services_up(wait: int | None = None) -> str | None:
    """None when the restarted services run and the web UI answers; else what is wrong."""
    deadline = time.monotonic() + (PATCH_START_WAIT if wait is None else wait)
    problem = "not checked"
    while True:
        states = {u: run(["systemctl", "is-active", u], timeout=30, check=False).strip() for u in PATCH_SERVICES[:3]}
        down = [f"{u} is {s or 'unknown'}" for u, s in states.items() if s != "active"]
        problem = "; ".join(down) or web_answers()
        if problem is None:
            time.sleep(PATCH_SETTLE)
            again = [u for u in states if run(["systemctl", "is-active", u], timeout=30, check=False).strip() != "active"]
            if not again:
                return None
            problem = f"{', '.join(again)} stopped again"
        if time.monotonic() >= deadline:
            return problem
        time.sleep(HEALTH_POLL)


def web_answers() -> str | None:
    import urllib.request
    try:
        with urllib.request.urlopen(HEALTHZ, timeout=10) as r:
            return None if r.status == 200 else f"the web UI answers {r.status}"
    except OSError as ex:
        return f"the web UI does not answer: {ex}"


def install_patch(version: str, task: dict) -> None:
    """An app update: verified, fetched by digest, checked, made active; the services restart with it. When they
    do not come up, the code that ran before is put back."""
    c = conf()
    image = c["CZ_APP_IMAGE"]
    task.update(state="running", started=now(), kind="app update",
                message=f"Verifying the signature of the app update {image}:{version}")
    publish(task)
    if not VERSION_RE.fullmatch(version or ""):
        raise AgentError(f"not a release version: {version!r}")
    digest = verify_signature(version, c, image)
    task.update(message=f"Signature verified ({digest[:19]}…); downloading")
    publish(task)
    P.patches.mkdir(parents=True, exist_ok=True)
    previous = active_patch() if mounted_patch() else None
    if previous == version:
        previous = None
    staging = P.patches / f".{version}.{os.getpid()}"
    apppatch.remove_tree(staging)
    try:
        apppatch.fetch(image, digest, staging)
        apppatch.check_manifest(apppatch.read_manifest(staging), version, running_version(), requirements_sha())
        apppatch.check_tree(staging, version)
        learned = staging / "rules" / "learned"
        if not learned.exists() and not learned.is_symlink():
            learned.symlink_to(P.learned)
        run([sys.executable, "-I", "-m", "compileall", "-q", str(staging / "containerizer")], timeout=600)
        # the update's code imports, from its own folder, with this OS image's Python packages
        run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import containerizer, "
             "containerizer.webui, containerizer.admin, containerizer.cli, containerizer.worker, containerizer.sysagent; "
             "assert containerizer.__file__.startswith(sys.argv[1]), containerizer.__file__", str(staging)], timeout=300)
        final = P.patches / version
        if (mounted_patch() or {}).get("version") == version:
            set_active_patch(None)  # the same version again: its folder is replaced
            reselect(None)
        apppatch.remove_tree(final)
        staging.rename(final)
    except (PatchError, AgentError, OSError, subprocess.TimeoutExpired):
        apppatch.remove_tree(staging)
        raise
    task.update(message=f"Installed {version} ({digest[:19]}…); restarting the services")
    publish(task)
    set_active_patch(version)
    try:
        reselect(version)
        restart_services()
        problem = services_up()
    except AgentError as ex:
        problem = str(ex)
    if problem:
        set_active_patch(previous)
        try:
            reselect(previous)
        except AgentError as ex:
            log(str(ex))
        restart_services()
        raise AgentError(f"the services did not come up with {version} ({problem}); back to "
                         f"{previous or 'the OS image code ' + (running_version() or '')}")
    prune_patches(keep={version, previous})
    task.update(state="done", finished=now(), message=f"App update {version} ({digest[:19]}…) installed; the "
                f"containerizer services restarted, the OS did not")
    publish(task)


def remove_patch(task: dict) -> None:
    """Back to the OS image's own code; the services restart."""
    v = active_patch()
    if not v and not mounted_patch():
        raise AgentError("no app update is installed")
    task.update(state="running", started=now(), message=f"Removing the app update {v or ''}".strip())
    publish(task)
    set_active_patch(None)
    reselect(None)
    restart_services()
    problem = services_up()
    task.update(state="failed" if problem else "done", finished=now(),
                message=f"Back to {running_version() or 'the OS image code'}" + (f", but {problem}" if problem else
                                                                                 "; the services restarted"))
    publish(task)


def prune_patches(keep: set) -> None:
    for d in P.patches.iterdir() if P.patches.is_dir() else ():
        # older updates, and the staging folders of downloads that were cut off
        if d.is_dir() and d.name not in keep and (VERSION_RE.fullmatch(d.name) or d.name.startswith(".v")):
            apppatch.remove_tree(d)


# =============================================================================== planned restart

def load_plan() -> dict | None:
    try:
        p = json.loads(P.plan.read_text())
    except (OSError, ValueError):
        return None
    return p if isinstance(p, dict) and p.get("action") in restartplan.ACTIONS else None


def save_plan(plan: dict | None) -> None:
    if plan is None:
        P.plan.unlink(missing_ok=True)
    else:
        atomic_write(P.plan, json.dumps(plan), 0o644)


def validate_plan(req: dict, current: datetime | None = None) -> dict:
    """The plan of a request from the web UI, checked again: what (a restart, a release tag, an earlier snapshot
    on the disk), when (now or within MAX_AHEAD) and the longest wait for the work in progress."""
    current = current or datetime.now(timezone.utc)
    action = req.get("then")
    plan = {"action": action, "requested_by": str(req.get("requested_by") or "?")[:256],
            "requested_by_name": str(req.get("requested_by_name") or "")[:256],
            "requested_at": str(req.get("requested_at") or "")[:40]}
    if action == "upgrade":
        if not VERSION_RE.fullmatch(str(req.get("version") or "")):
            raise AgentError(f"not a release version: {req.get('version')!r}")
        plan["version"] = req["version"]
    elif action == "rollback":
        sid = req.get("snapshot")
        if not isinstance(sid, int) or isinstance(sid, bool) or sid not in {s["id"] for s in snapshots() if not s["active"]}:
            raise AgentError(f"snapshot {sid!r} is not an earlier snapshot on this disk")
        plan["snapshot"] = sid
    elif action != "reboot":
        raise AgentError(f"nothing to plan: {action!r}")
    at = restartplan.parse_time(req.get("at")) if req.get("at") else current
    if at is None or at > current + restartplan.MAX_AHEAD:
        raise AgentError(f"not a time within {restartplan.MAX_AHEAD.days} days: {req.get('at')!r}")
    plan["at"] = max(at, current).isoformat(timespec="seconds")
    wait = req.get("max_wait_minutes")
    if wait is not None and (not isinstance(wait, int) or isinstance(wait, bool) or not 0 <= wait <= 7 * 24 * 60):
        raise AgentError(f"not a number of minutes to wait: {wait!r}")
    plan["max_wait_minutes"] = wait
    return plan


def running_work() -> int | None:
    """Scan runs and LLM jobs in progress, from the results database (the scan worker's login); None when it
    cannot be asked."""
    try:
        from .sqlstore import connect
        cs = read_env(P.sql_env).get("CZ_SQL_SCANNER_CS")
        conn = connect(cs, P.sql_secret.read_text().strip())
        try:
            cur = conn.cursor()
            cur.execute("SELECT (SELECT COUNT(*) FROM cz.OrgScanRun WHERE Status = N'running') + "
                        "(SELECT COUNT(*) FROM cz.LlmJob WHERE Status = N'running')")
            return int(cur.fetchone()[0])
        finally:
            conn.close()
    except Exception as ex:                 # noqa: BLE001 - the database may be away: wait as if busy
        log(f"restart: could not count the work in progress: {type(ex).__name__}: {ex}")
        return None


def restart_check(current: datetime | None = None) -> str:
    """Carry out the planned restart when it is due; what happened."""
    plan = load_plan()
    if not plan:
        return "nothing planned"
    current = current or datetime.now(timezone.utc)
    at = restartplan.starts(plan)
    if at is not None and current < at:
        return "scheduled"
    running = running_work()
    go, why = restartplan.due(plan, current, running)
    if not go:
        if plan.get("running") != running or not plan.get("holding_since"):
            plan.update(running=running, holding_since=plan.get("holding_since") or now(), checked=now())
            save_plan(plan)
            publish()
        return why
    save_plan(None)                         # removed first: a restart is never repeated
    task = {k: plan.get(k) for k in ("action", "version", "snapshot", "requested_by", "requested_by_name",
                                     "requested_at") if plan.get(k) is not None}
    task["planned"] = f"{plan.get('at')}, restarted {why}"
    log(f"restart: {restartplan.describe(plan)} ({why})")
    try:
        if plan["action"] == "upgrade":
            upgrade(plan["version"], task)
        elif plan["action"] == "rollback":
            rollback(int(plan["snapshot"]), task)
        else:
            task.update(started=now())
            _finish(task, "Restart as planned", True)
    except (AgentError, PatchError, OSError, subprocess.TimeoutExpired, ValueError) as ex:
        task.update(state="failed", finished=now(), message=str(ex)[-1000:])
        publish(task)
        raise
    return "done"


# =============================================================================== egress allow-list

class RuleError(ValueError):
    pass


def parse_ports(spec) -> list[str]:
    """'443', '80,443', 'udp/123', 'tcp/22' -> ['tcp/443', ...] (sorted, unique)."""
    items = spec if isinstance(spec, list) else re.split(r"[\s,]+", str(spec or "443").strip())
    out = set()
    for it in items:
        if not it:
            continue
        m = PORT_RE.fullmatch(str(it).strip().lower())
        if not m or not 1 <= int(m[2]) <= 65535:
            raise RuleError(f"not a port: {it!r} (use 443, 80,443 or udp/123)")
        out.add(f"{m[1] or 'tcp'}/{int(m[2])}")
    if not out or len(out) > MAX_PORTS:
        raise RuleError(f"between 1 and {MAX_PORTS} ports")
    return sorted(out, key=lambda p: (p.split("/")[0], int(p.split("/")[1])))


def normalize_host(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        raise RuleError(f"not a host name: {h!r}") from None
    if not HOST_RE.fullmatch(h):
        raise RuleError(f"not a host name: {h!r} (a DNS name such as api.nuget.org; it covers its subdomains)")
    return h


def validate_rules(data) -> dict:
    """The allow-list in its stored form, or RuleError. Entries: {host|cidr, ports, note}."""
    if not isinstance(data, dict):
        raise RuleError("expected an object")
    mode = data.get("mode") or "enforce"
    if mode not in ("enforce", "log"):
        raise RuleError("mode is enforce or log")
    raw = data.get("rules") or []
    if not isinstance(raw, list) or len(raw) > MAX_RULES:
        raise RuleError(f"at most {MAX_RULES} rules")
    rules, seen = [], set()
    for r in raw:
        if not isinstance(r, dict):
            raise RuleError("each rule is an object")
        note = " ".join(str(r.get("note") or "").split())[:NOTE_MAX]
        ports = parse_ports(r.get("ports"))
        if r.get("cidr"):
            try:
                net = ipaddress.ip_network(str(r["cidr"]).strip(), strict=False)
            except ValueError:
                raise RuleError(f"not an address or network: {r['cidr']!r}") from None
            if net.prefixlen == 0:
                raise RuleError("0.0.0.0/0 and ::/0 would open everything: turn the firewall to log mode instead")
            key = ("cidr", str(net), tuple(ports))
            entry = {"cidr": str(net), "ports": ports, "note": note}
        else:
            host = normalize_host(str(r.get("host") or ""))
            key = ("host", host, tuple(ports))
            entry = {"host": host, "ports": ports, "note": note}
        if key not in seen:
            seen.add(key)
            rules.append(entry)
    return {"mode": mode, "rules": rules}


def load_rules(path: Path, system: bool = False) -> dict:
    try:
        return validate_rules(json.loads(path.read_text()))
    except FileNotFoundError:
        return {"mode": "enforce", "rules": []}
    except (OSError, ValueError) as ex:
        # a broken admin file must not leave the appliance open, nor cut it off from its own updates
        log(f"{'system' if system else 'admin'} egress rules {path} ignored: {ex}")
        if system:
            raise
        return {"mode": "enforce", "rules": []}


def system_rules() -> dict:
    """The rules of the OS image, plus the external results database of appliance.env (CZ_SQL_SERVER): the
    appliance cannot start its web UI without it, so it cannot wait for a rule on the Firewall page. And
    Hugging Face while the built-in LLM's model downloads (local_llm.egress_rules), never otherwise."""
    rules = load_rules(P.system_rules, system=True)
    rules["rules"] += validate_rules({"rules": local_llm.egress_rules()})["rules"]
    try:
        db = external_sql(read_env(P.appliance_env))
    except RuleError as ex:
        log(f"CZ_SQL_SERVER in {P.appliance_env} ignored by the firewall: {ex}")
        db = None
    if db:
        host, port = db
        try:
            entry = {"cidr": str(ipaddress.ip_network(host)), "ports": [f"tcp/{port}"]}
        except ValueError:
            entry = {"host": normalize_host(host), "ports": [f"tcp/{port}"]}
        rules["rules"].append(dict(entry, note="results database (CZ_SQL_SERVER in appliance.env)"))
    return rules


def port_key(ports: list[str]) -> str:
    return "_".join(p.replace("/", "") for p in ports)


def _covers(parent: str, host: str) -> bool:
    return host == parent or host.endswith("." + parent)


def upstream_servers() -> list[str]:
    """The DNS servers dnsmasq forwards allowed names to: CZ_DNS_SERVERS in /etc/containerizer/appliance.env,
    else the ones systemd-networkd learned from DHCP (systemd-resolved runs without its stub listener only to
    publish them)."""
    env = read_env(P.appliance_env)
    if env.get("CZ_DNS_SERVERS"):
        src = re.split(r"[\s,]+", env["CZ_DNS_SERVERS"])
    else:
        try:
            src = [ln.split()[1] for ln in P.resolved.read_text().splitlines() if ln.startswith("nameserver ") and len(ln.split()) > 1]
        except OSError:
            src = []
    out = []
    for x in src:
        try:
            ip = ipaddress.ip_address(x.split("%")[0])
        except ValueError:
            continue
        if not ip.is_loopback and str(ip) != DNS_ADDR and str(ip) not in out:
            out.append(str(ip))
    return out[:4]


def render(system: dict, admin: dict, upstreams: list[str] | None = None) -> tuple[str, str]:
    """(nftables ruleset, dnsmasq configuration) for the system and the administrators' rules."""
    upstreams = upstream_servers() if upstreams is None else upstreams
    rules = [dict(r, origin="system") for r in system["rules"]] + [dict(r, origin="admin") for r in admin["rules"]]
    enforce = admin.get("mode", "enforce") == "enforce"
    hosts = [r for r in rules if "host" in r]
    cidrs = [r for r in rules if "cidr" in r]
    groups = sorted({port_key(r["ports"]) for r in hosts})
    ports_of = {port_key(r["ports"]): r["ports"] for r in hosts}

    # dnsmasq: a name resolves only when a rule covers it (no default server: every other name is
    # REFUSED), and its addresses go into the nftables set of every rule that covers it (dnsmasq picks
    # the longest matching domain, so a subdomain rule repeats the sets of its parents)
    names = sorted({r["host"] for r in hosts}, key=lambda h: (h.count("."), h))
    dns = ["# generated by containerizer.sysagent from /usr/lib/containerizer/egress-system.json and",
           "# /etc/containerizer/egress.json; do not edit", "no-resolv"]
    if not upstreams:
        dns.append("# no upstream DNS server known (DHCP or CZ_DNS_SERVERS): every name is refused")
    for h in names:
        keys = sorted({port_key(r["ports"]) for r in hosts if _covers(r["host"], h)})
        sets = ",".join(f"4#inet#{TABLE}#f4_{k},6#inet#{TABLE}#f6_{k}" for k in keys)
        dns += [f"server=/{h}/{u}" for u in upstreams] + [f"nftset=/{h}/{sets}"]

    def portmatch(ports: list[str], proto: str) -> str | None:
        ps = [p.split("/")[1] for p in ports if p.startswith(proto + "/")]
        return f"{proto} dport {{ {', '.join(ps)} }}" if ps else None

    sets, allow = [], []
    for k in groups:
        sets += [f"  set f4_{k} {{ type ipv4_addr; flags timeout; timeout 1d; }}",
                 f"  set f6_{k} {{ type ipv6_addr; flags timeout; timeout 1d; }}"]
        for proto in ("tcp", "udp"):
            pm = portmatch(ports_of[k], proto)
            if pm:
                allow += [f"    ip daddr @f4_{k} {pm} accept", f"    ip6 daddr @f6_{k} {pm} accept"]
    for r in cidrs:
        fam = "ip" if ipaddress.ip_network(r["cidr"]).version == 4 else "ip6"
        for proto in ("tcp", "udp"):
            pm = portmatch(r["ports"], proto)
            if pm:
                allow.append(f"    {fam} daddr {r['cidr']} {pm} accept")
    internal4 = ", ".join(INTERNAL4)
    ifaces = ", ".join(f'"{i}"' for i in INTERNAL_IFACES)
    verdict = "drop" if enforce else "accept"
    allow_s = "\n".join(allow)
    nft = f"""# generated by containerizer.sysagent; do not edit (`python -m containerizer.sysagent firewall show`)
table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
{chr(10).join(sets)}

  chain input {{
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state invalid drop
    ct state established,related accept
    meta l4proto icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
    meta l4proto ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept
    # ping from anywhere (rate limited; above it the drop below applies)
    meta l4proto icmp icmp type echo-request limit rate 20/second burst 50 packets accept
    meta l4proto ipv6-icmp icmpv6 type echo-request limit rate 20/second burst 50 packets accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport {{ {", ".join(str(p) for p in INBOUND_TCP)} }} accept
    # containers and pods: the DNS filter, the k3s API and the kubelet only
    iifname {{ {ifaces} }} ip daddr {DNS_ADDR} meta l4proto {{ tcp, udp }} th dport 53 accept
    iifname {{ {ifaces} }} tcp dport {{ 6443, 10250 }} accept
    limit rate 10/minute burst 20 packets log prefix "cz-in-drop: " level info
  }}

  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    ip saddr {{ {internal4} }} ip daddr {{ {internal4} }} accept
    ip daddr {DNS_ADDR} meta l4proto {{ tcp, udp }} th dport 53 accept
    jump egress
  }}

  chain output {{
    type filter hook output priority filter; policy accept;
    oif "lo" accept
    ct state established,related accept
    ip daddr {{ {internal4}, {DNS_ADDR} }} accept
    meta l4proto ipv6-icmp accept
    meta l4proto icmp accept
    udp sport 68 udp dport 67 accept
    udp sport 546 udp dport 547 accept
    # upstream DNS for dnsmasq only, NTP for systemd-timesyncd only
    meta skuid "dnsmasq" meta l4proto {{ tcp, udp }} th dport 53 accept
    meta skuid "systemd-timesync" udp dport 123 accept
    jump egress
  }}

  chain egress {{
{allow_s}
    limit rate 30/minute burst 60 packets log prefix "cz-egress-drop: " level info
    {verdict}
  }}
}}
"""
    return nft, "\n".join(dns) + "\n"


def apply_firewall(reload_dns: bool = True) -> dict:
    """Load the ruleset (checked first; one transaction) and the DNS allow-list."""
    system = system_rules()
    admin = load_rules(P.rules)
    nft, dns = render(system, admin)
    atomic_write(P.nft, nft, 0o600)
    run(["nft", "-c", "-f", str(P.nft)], timeout=60)
    run(["nft", "-f", str(P.nft)], timeout=60)
    atomic_write(P.dnsmasq, dns, 0o644)
    if reload_dns:
        run(["systemctl", "try-restart", "containerizer-dns.service"], timeout=120, check=False)
    log(f"firewall: {len(system['rules'])} system and {len(admin['rules'])} admin egress rules, mode {admin['mode']}")
    return admin


def save_rules(data: dict, user: str, name: str) -> dict:
    new = validate_rules(data)
    old = load_rules(P.rules)
    atomic_write(P.rules, json.dumps(new, indent=1), 0o644)
    try:
        apply_firewall()
    except AgentError:
        atomic_write(P.rules, json.dumps(old, indent=1), 0o644)   # keep the last ruleset that loaded
        apply_firewall()
        raise
    ok, nk = ({json.dumps(r, sort_keys=True) for r in x["rules"]} for x in (old, new))
    entry = {"at": now(), "by": user, "name": name, "mode": new["mode"], "old_mode": old["mode"],
             "added": [json.loads(x) for x in sorted(nk - ok)], "removed": [json.loads(x) for x in sorted(ok - nk)]}
    P.history.parent.mkdir(parents=True, exist_ok=True)
    with P.history.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    os.chmod(P.history, 0o644)
    return new


QUERY_RE = re.compile(r"\b(\d+) (\S+) query\[[A-Z0-9]+\] (\S+) from ")
REFUSED_RE = re.compile(r"\b(\d+) (\S+) config error is REFUSED")
DROP_RE = re.compile(r"cz-egress-drop: .*?\bDST=([0-9a-fA-F.:]+) .*?\bPROTO=(TCP|UDP)\b.*?\bDPT=(\d+)")


def egress_status(journal: str | None = None, history_lines: int = 50) -> dict:
    """Names the DNS filter refused and connections the firewall dropped in the last 24 hours, and the
    latest changes of the allow-list, for the admin page."""
    if journal is None:
        try:
            # the DNS filter's log or (+) the kernel's: "-u ... -k" would ask for entries that are both
            journal = run(["journalctl", "--since", "-24h", "--no-pager", "-o", "cat",
                           "_SYSTEMD_UNIT=containerizer-dns.service", "+", "_TRANSPORT=kernel",
                           "--grep", "query\\[|is REFUSED|cz-egress-drop"],
                          timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            journal = ""
    names: dict[str, int] = {}
    drops: dict[str, int] = {}
    asked: dict[tuple[str, str], str] = {}        # (serial, client) -> name (dnsmasq --log-queries=extra)
    for line in journal.splitlines():
        m = QUERY_RE.search(line)
        if m:
            asked[(m[1], m[2])] = m[3]
            if len(asked) > 10000:
                asked.pop(next(iter(asked)))
            continue
        m = REFUSED_RE.search(line)
        if m:
            n = asked.pop((m[1], m[2]), "").lower().rstrip(".")
            if HOST_RE.fullmatch(n) and not n.endswith((".arpa", ".local", ".internal", ".localdomain", ".lan")):
                names[n] = names.get(n, 0) + 1
            continue
        m = DROP_RE.search(line)
        if m:
            k = f"{m[1]} {m[2].lower()}/{m[3]}"
            drops[k] = drops.get(k, 0) + 1
    hist = []
    try:
        hist = [json.loads(x) for x in P.history.read_text().splitlines()[-history_lines:] if x.strip()]
    except (OSError, ValueError):
        pass
    top = lambda d: [{"name": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:50]]
    try:
        system = system_rules()["rules"]
    except (OSError, ValueError):
        system = []
    admin = load_rules(P.rules)
    return {"mode": admin["mode"], "rules": admin["rules"], "system_rules": system,
            "denied_names": top(names), "dropped": top(drops), "history": hist[::-1], "updated": now()}


# =============================================================================== results database

SQL_LOGINS = (("cz_scanner", "writer", "SCANNER"), ("cz_web", "reader", "WEB"), ("cz_admin", "admin", "ADMIN"))
_SQL_SET = ("server", "datasource", "address", "addr", "networkaddress", "database", "initialcatalog",
            "userid", "uid", "user", "username", "password", "pwd", "cafile", "servercertificate")
_SQL_SAFE = re.compile(r'[^"$`\\\n\r]*')


def external_sql(env: dict) -> tuple[str, int] | None:
    """(host, port) of CZ_SQL_SERVER (host, host,port or tcp:host,port), None for the appliance's own."""
    server = (env.get("CZ_SQL_SERVER") or "").strip()
    if not server:
        return None
    host, _, port = re.sub(r"^tcp:", "", server, flags=re.I).partition(",")
    host, port = host.strip().strip("[]"), (port.strip() or "1433")
    if "\\" in host:
        raise RuleError("named instances (host\\instance) are not supported: give the port, e.g. sql01,1433")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise RuleError(f"CZ_SQL_SERVER: not a port: {port!r}")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = normalize_host(host)
    return host, int(port)


def sql_settings(env: dict) -> dict:
    """The connection strings of cz-db-init, the web UI and the scan worker (written to /run/containerizer/sql.env
    as CZ_SQL_*). Passwords are never in them: the services read them from /etc/containerizer/secrets."""
    from .sqlstore import SqlError, parse_connection_string
    db = external_sql(env)
    if not db:
        base = "Server=127.0.0.1,1433;Database=Containerizer;TrustServerCertificate=yes"
        out = {"CZ_SQL_LOCAL": "yes", "CZ_SQL_LOGINS": "create", "CZ_SQL_OWNER_SECRET": "mssql-sa",
               "CZ_SQL_OWNER_CS": base + ";User Id=sa",
               "CZ_SQL_PROBE_CS": base.replace("Database=Containerizer", "Database=master") + ";User Id=sa"}
    else:
        host, port = db
        database = (env.get("CZ_SQL_DATABASE") or "Containerizer").strip()
        user = (env.get("CZ_SQL_USER") or "").strip()
        logins = (env.get("CZ_SQL_LOGINS") or "create").strip().lower()
        options = (env.get("CZ_SQL_OPTIONS") or "").strip().strip(";")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", database):
            raise RuleError(f"CZ_SQL_DATABASE must be a plain identifier: {database!r}")
        if not re.fullmatch(r"[^;={}\s]{1,128}", user):
            raise RuleError("CZ_SQL_USER: the login that owns the database (db_owner) is required with CZ_SQL_SERVER")
        if logins not in ("create", "existing"):
            raise RuleError(f"CZ_SQL_LOGINS is create or existing: {logins!r}")
        try:
            keys = set(parse_connection_string(options))
        except SqlError as ex:
            raise RuleError(f"CZ_SQL_OPTIONS: {ex}") from None
        if keys & set(_SQL_SET):
            raise RuleError("CZ_SQL_OPTIONS must not set the server, database, user, password or CA file: "
                            "use CZ_SQL_SERVER, CZ_SQL_DATABASE, CZ_SQL_USER, secrets/sql-owner and CZ_SQL_CA")
        if env.get("CZ_SQL_CA"):
            options += (";" if options else "") + f"CaFile={P.sql_ca}"
        h = f"[{host}]" if ":" in host else host
        base = f"Server=tcp:{h},{port};Database={database}" + (f";{options}" if options else "")
        out = {"CZ_SQL_LOCAL": "no", "CZ_SQL_LOGINS": logins, "CZ_SQL_OWNER_SECRET": "sql-owner",
               "CZ_SQL_OWNER_CS": f"{base};User Id={user}", "CZ_SQL_PROBE_CS": f"{base};User Id={user}"}
    for login, _, name in SQL_LOGINS:
        out[f"CZ_SQL_{name}_CS"] = f"{base};User Id={login}"
    for k, v in out.items():
        if not _SQL_SAFE.fullmatch(v):
            raise RuleError(f"{k}: the database settings must not contain quotes, $, ` or backslashes")
    return out


def write_sql_env() -> dict:
    """/run/containerizer/sql.env (and the CA file of CZ_SQL_CA, readable by the services) from appliance.env."""
    env = read_env(P.appliance_env)
    out = sql_settings(env)
    if env.get("CZ_SQL_CA"):
        try:
            ca = Path(env["CZ_SQL_CA"]).read_text()
        except OSError as ex:
            raise RuleError(f"CZ_SQL_CA: {ex}") from None
        if "-----BEGIN CERTIFICATE-----" not in ca:
            raise RuleError(f"CZ_SQL_CA: {env['CZ_SQL_CA']} is not a PEM certificate")
        atomic_write(P.sql_ca, ca, 0o644)
    atomic_write(P.sql_env, "".join(f'{k}="{v}"\n' for k, v in out.items()), 0o644)
    return out


# =============================================================================== sandbox HTTPS

CADDY_GROUP = "caddy"
HTTPS_KINDS = ("set", "remove")


def appliance_host() -> str:
    """The web UI's host name (CONTAINERIZER_PUBLIC_URL, else CZ_HOSTNAME, else the machine's name)."""
    from urllib.parse import urlsplit
    url = read_env(P.web_env).get("CONTAINERIZER_PUBLIC_URL") or ""
    return (urlsplit(url).hostname or read_env(P.appliance_env).get("CZ_HOSTNAME") or socket.gethostname() or "").lower()


def _write_key(path: Path, text: str) -> None:
    """The private key: root and Caddy (group) may read it, nobody else; written under a new name and
    renamed, so a reader never sees half a key."""
    import grp
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            os.chown(tmp, 0, grp.getgrnam(CADDY_GROUP).gr_gid)
            os.chmod(tmp, 0o640)
        except (KeyError, PermissionError):
            pass                                    # tests, or no Caddy: root only
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _caddy(check_only: bool) -> None:
    """Check the Caddyfile with the imported site; then restart Caddy (its admin API is off, so no reload)."""
    import tempfile
    # Caddy keeps its data (the internal CA) under $XDG_DATA_HOME or $HOME/.local/share; this service has no
    # HOME, so it would use ./caddy on the read-only root. Validation provisions the internal CA too: give it a
    # throwaway directory, never Caddy's own (/var/lib/caddy, owned by the caddy user).
    with tempfile.TemporaryDirectory(prefix="cz-caddy-validate-") as scratch:
        env = {**os.environ, **read_env(P.appliance_env), **read_env(P.caddy_env),
               "HOME": scratch, "XDG_DATA_HOME": scratch, "XDG_CONFIG_HOME": scratch}
        p = subprocess.run(["caddy", "validate", "--config", str(P.caddyfile), "--adapter", "caddyfile"],
                           capture_output=True, text=True, timeout=120, env=env, errors="replace", cwd=scratch)
    if p.returncode:
        raise AgentError("Caddy does not accept the configuration: " + (p.stderr or p.stdout).strip()[-600:])
    if not check_only:
        run(["systemctl", "restart", "caddy.service"], timeout=120)


def _https_history(entry: dict) -> None:
    h = P.https("-history.jsonl")
    h.parent.mkdir(parents=True, exist_ok=True)
    with h.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    os.chmod(h, 0o644)


def sandbox_https_status(history_lines: int = 50) -> dict:
    """For the admin page: what is set up (no key, no certificate text) and the change history."""
    try:
        st = json.loads(P.https(".json").read_text())
        st = st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        st = {}
    hist = []
    try:
        hist = [json.loads(x) for x in P.https("-history.jsonl").read_text().splitlines()[-history_lines:] if x.strip()]
    except (OSError, ValueError):
        pass
    return {**{k: v for k, v in st.items() if k in ("enabled", "domain", "cert", "set_by", "set_by_name", "set_at", "edge")},
            "history": hist[::-1], "updated": now()}


def save_sandbox_https(req: dict, user: str, name: str) -> dict:
    """Set or remove the sandbox's wildcard domain and certificate (a request from the admin page)."""
    from .sandbox_https import SandboxHttpsError, caddy_site, check
    kind = req.get("do")
    if kind not in HTTPS_KINDS:
        raise AgentError("unknown sandbox-https request")
    files = {ext: P.https(ext) for ext in (".crt", ".key", ".caddy", ".json")}
    old = {ext: (f.read_bytes() if f.exists() else None) for ext, f in files.items()}
    entry = {"at": now(), "by": user, "name": name, "action": kind}
    try:
        if kind == "set":
            try:
                ok = check(str(req.get("domain") or ""), str(req.get("cert") or ""), str(req.get("key") or ""),
                           appliance_host=appliance_host())
            except SandboxHttpsError as ex:
                raise AgentError(str(ex)) from None
            info = ok.info.to_dict()
            atomic_write(files[".crt"], ok.cert_pem, 0o644)
            _write_key(files[".key"], ok.key_pem)
            atomic_write(files[".caddy"], caddy_site(ok.info.domain, str(files[".crt"]), str(files[".key"]),
                                                     str(files[".crt"])), 0o644)
            _caddy(check_only=True)
            settings = {"enabled": True, "domain": ok.info.domain, "cert": info, "cert_file": str(files[".crt"]),
                        "edge": "127.0.0.1:443", "set_by": user, "set_by_name": name, "set_at": now()}
            entry.update(domain=ok.info.domain, fingerprint=info["fingerprint"], subject=info["subject"],
                         issuer=info["issuer"], not_after=info["not_after"])
        else:
            for ext in (".crt", ".key", ".caddy"):
                files[ext].unlink(missing_ok=True)
            prev = sandbox_https_status()
            settings = {"enabled": False, "set_by": user, "set_by_name": name, "set_at": now()}
            entry.update(domain=prev.get("domain") or "", fingerprint=(prev.get("cert") or {}).get("fingerprint", ""))
        atomic_write(files[".json"], json.dumps(settings, indent=1), 0o644)
        _caddy(check_only=False)
    except BaseException:
        for ext, data in old.items():           # back to what worked before
            if data is None:
                files[ext].unlink(missing_ok=True)
            elif ext == ".key":
                _write_key(files[ext], data.decode())
            else:
                atomic_write(files[ext], data.decode(), 0o644)
        try:
            _caddy(check_only=False)            # whatever Caddy had loaded, it serves the old files again
        except (AgentError, OSError, subprocess.TimeoutExpired) as ex:
            log(f"sandbox-https: Caddy not restarted with the previous configuration: {ex}")
        raise
    _https_history(entry)
    try:
        sync_sandbox_https()
    except (AgentError, OSError, subprocess.TimeoutExpired) as ex:     # containerizer-sandbox retries every 2 minutes
        log(f"sandbox-https: k3s not updated yet: {ex}")
    return settings


def _kubectl(args: list[str], input: str | None = None, check: bool = True) -> str:
    return run(["k3s", "kubectl", "--kubeconfig", str(P.kubeconfig), *args], timeout=120, input=input, check=check)


ESO_CRD = "externalsecrets.external-secrets.io"
STORE = "app-secrets"                       # the ClusterSecretStore of the sandbox (kubernetes provider)
STORE_NS = "containerizer-secrets"          # where that store keeps the values
STORE_READER = "app-secrets-reader"         # ServiceAccount the store authenticates as, in the reading namespace
APPLIANCE_LABELS = {"app.kubernetes.io/managed-by": "containerizer-appliance",
                    "app.kubernetes.io/part-of": "containerizer-sandbox"}


def tls_manifests(cert_pem: str, key_pem: str, eso: bool) -> str:
    """What makes the wildcard certificate Traefik's default one (kube-system: Secret
    containerizer-sandbox-tls named by the default TLSStore).

    With External Secrets Operator (eso): the value goes into the sandbox's secret store (namespace
    containerizer-secrets), kube-system may read that one key only, and an ExternalSecret materialises the
    TLS Secret. Without it (before ESO is installed) the Secret is written directly."""
    import base64
    from .sandbox_https import SECRET_NAME, SECRET_NAMESPACE
    b = lambda t: base64.b64encode(t.encode()).decode()
    data = {"tls.crt": b(cert_pem), "tls.key": b(key_pem)}
    store = {"apiVersion": "traefik.io/v1alpha1", "kind": "TLSStore",
             "metadata": {"name": "default", "namespace": SECRET_NAMESPACE, "labels": APPLIANCE_LABELS},
             "spec": {"defaultCertificate": {"secretName": SECRET_NAME}}}
    if not eso:
        items = [{"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
                  "metadata": {"name": SECRET_NAME, "namespace": SECRET_NAMESPACE, "labels": APPLIANCE_LABELS},
                  "data": data}, store]
        return json.dumps({"apiVersion": "v1", "kind": "List", "items": items})
    grant = f"{STORE_READER}-{SECRET_NAMESPACE}"
    items = [
        {"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
         "metadata": {"name": SECRET_NAME, "namespace": STORE_NS, "labels": APPLIANCE_LABELS}, "data": data},
        {"apiVersion": "v1", "kind": "ServiceAccount", "automountServiceAccountToken": False,
         "metadata": {"name": STORE_READER, "namespace": SECRET_NAMESPACE, "labels": APPLIANCE_LABELS}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": {"name": grant, "namespace": STORE_NS, "labels": APPLIANCE_LABELS},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [SECRET_NAME], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": grant, "namespace": STORE_NS, "labels": APPLIANCE_LABELS},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": grant},
         "subjects": [{"kind": "ServiceAccount", "name": STORE_READER, "namespace": SECRET_NAMESPACE}]},
        {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
         "metadata": {"name": SECRET_NAME, "namespace": SECRET_NAMESPACE, "labels": APPLIANCE_LABELS},
         "spec": {"refreshInterval": "5m", "secretStoreRef": {"kind": "ClusterSecretStore", "name": STORE},
                  "target": {"name": SECRET_NAME, "creationPolicy": "Owner", "deletionPolicy": "Delete",
                             "template": {"type": "kubernetes.io/tls"}},
                  "data": [{"secretKey": k, "remoteRef": {"key": SECRET_NAME, "property": k}}
                           for k in ("tls.crt", "tls.key")]}},
        store,
    ]
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": items})


def _has_crd(name: str) -> bool:
    return bool(_kubectl(["get", "crd", name, "-o", "name", "--ignore-not-found"], check=False).strip())


def sync_sandbox_https() -> str:
    """Make k3s match the settings: the certificate as Traefik's default when Sandbox HTTPS is on, none of
    it when it is off. Idempotent; containerizer-sandbox runs it every 2 minutes."""
    from .sandbox_https import SECRET_NAME, SECRET_NAMESPACE
    if not P.https(".json").exists():
        return "not set up"                     # never configured: nothing to install or remove
    try:
        on = bool(json.loads(P.https(".json").read_text()).get("enabled"))
    except (OSError, ValueError, AttributeError):
        on = False
    eso = _has_crd(ESO_CRD)
    if not on:
        from .idp import NAMESPACE as IDP_NS
        from .sandbox_https import CA_CONFIGMAP
        _kubectl(["-n", IDP_NS, "delete", f"configmap/{CA_CONFIGMAP}", "--ignore-not-found"], check=False)
        if eso:
            _kubectl(["-n", SECRET_NAMESPACE, "delete", f"externalsecrets.external-secrets.io/{SECRET_NAME}",
                      "--ignore-not-found"], check=False)
        _kubectl(["-n", SECRET_NAMESPACE, "delete", "tlsstores.traefik.io/default", f"secret/{SECRET_NAME}",
                  "--ignore-not-found"], check=False)
        _kubectl(["-n", STORE_NS, "delete", f"secret/{SECRET_NAME}", f"role/{STORE_READER}-{SECRET_NAMESPACE}",
                  f"rolebinding/{STORE_READER}-{SECRET_NAMESPACE}", "--ignore-not-found"], check=False)
        return "off"
    if not _has_crd("tlsstores.traefik.io"):
        raise AgentError("Traefik is not running in k3s yet (no TLSStore CRD)")
    if eso and not _kubectl(["get", "namespace", STORE_NS, "-o", "name", "--ignore-not-found"], check=False).strip():
        eso = False                             # ESO without the sandbox's store yet: write the Secret directly
    cert = P.https(".crt").read_text()
    key = P.https(".key").read_text()
    if eso:   # the directly written Secret of an earlier sync would stop the ExternalSecret from owning it
        owner = _kubectl(["-n", SECRET_NAMESPACE, "get", f"secret/{SECRET_NAME}", "--ignore-not-found", "-o",
                          "jsonpath={.metadata.ownerReferences[0].kind}"], check=False).strip()
        exists = _kubectl(["-n", SECRET_NAMESPACE, "get", f"secret/{SECRET_NAME}", "--ignore-not-found", "-o", "name"],
                          check=False).strip()
        if exists and owner != "ExternalSecret":
            _kubectl(["-n", SECRET_NAMESPACE, "delete", f"secret/{SECRET_NAME}", "--ignore-not-found"], check=False)
    publish_sandbox_ca(cert)
    _kubectl(["apply", "--server-side", "--field-manager", "containerizer-appliance", "--force-conflicts", "-f", "-"],
             input=tls_manifests(cert, key, eso))
    return "on (external secrets)" if eso else "on"


def publish_sandbox_ca(cert_pem: str) -> None:
    """The certificate chain (public) as ConfigMap containerizer-sandbox-ca in the IdP's namespace, once Flux made
    it: the IdP's sync job calls https://containerizer-idp.<domain> through Traefik, and trusts this certificate
    as Caddy does, whoever issued it (an internal CA, or self-signed in a lab)."""
    from .idp import NAMESPACE as IDP_NS
    from .sandbox_https import CA_CONFIGMAP, public_chain
    if not _kubectl(["get", "namespace", IDP_NS, "-o", "name", "--ignore-not-found"], check=False).strip():
        return                                  # no sandbox IdP (yet): the next sync, every 2 minutes
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": CA_CONFIGMAP, "namespace": IDP_NS, "labels": APPLIANCE_LABELS},
          "data": {"ca.crt": public_chain(cert_pem)}}
    _kubectl(["apply", "--server-side", "--field-manager", "containerizer-appliance", "--force-conflicts", "-f", "-"],
             input=json.dumps(cm))


# =============================================================================== requests

def process() -> int:
    """Handle the queued requests, oldest first. A request is removed before it is acted on, so a
    request that restarts the appliance is never repeated."""
    d = P.run / "requests"
    rc = 0
    for f in sorted(d.glob("*.json")):
        try:
            req = json.loads(f.read_text())
        except (OSError, ValueError) as ex:
            log(f"request {f.name} ignored: {ex}")
            f.unlink(missing_ok=True)
            continue
        f.unlink(missing_ok=True)
        if not isinstance(req, dict):
            continue
        user = str(req.get("requested_by") or "?")[:256]
        name = str(req.get("requested_by_name") or "")[:256]
        action = req.get("action")
        log(f"request: {action} by {user}")
        task = {"action": action, "requested_by": user, "requested_by_name": name,
                "requested_at": str(req.get("requested_at") or "")[:40], "state": "queued"}
        try:
            if action == "upgrade":
                task["version"] = str(req.get("version") or "")[:40]
                upgrade(task["version"], task)
            elif action == "rollback":
                sid = req.get("snapshot")
                if not isinstance(sid, int) or isinstance(sid, bool):
                    raise AgentError("snapshot must be a number")
                task["snapshot"] = sid
                rollback(sid, task)
            elif action == "app-patch-remove":  # Admin -> System: back to the OS image's own code
                remove_patch(task)
            elif action == "plan":              # Admin -> System: a planned restart, upgrade or roll back
                if load_plan():
                    raise AgentError("a restart is already planned: cancel it first")
                save_plan(validate_plan(req))
                publish()
                run(["systemctl", "start", "--no-block", "containerizer-restart.service"], timeout=60, check=False)
            elif action == "plan-cancel":
                if load_plan():
                    log(f"restart plan cancelled by {user}")
                save_plan(None)
                publish()
            elif action == "egress":
                save_rules({"mode": req.get("mode"), "rules": req.get("rules")}, user, name)
                publish(egress_state=egress_status())
            elif action == "lab":               # Admin -> Lab services (labagent.py checks it again)
                from .labagent import apply_request
                apply_request(req)
                run(["systemctl", "start", "--no-block", "containerizer-lab.service"], timeout=60)
            elif action == "local-llm":         # Admin -> Source control & LLM: the built-in LLM
                local_llm.apply_request(req)
            elif action in ("dbquery", "dbdelete"):     # Admin -> Dev databases: the database browser
                from .dbbrowse import Agent, agent_request
                from .labagent import Kubectl
                agent_request(req, P.run / "answers", Agent(kube=Kubectl("k3s kubectl", str(P.kubeconfig))))
            elif action == "sandbox-https":
                save_sandbox_https(req, user, name)
                publish(https_state=sandbox_https_status())
            else:
                log(f"unknown action {action!r} ignored")
        except (AgentError, RuleError, LocalLlmError, PatchError, OSError, subprocess.TimeoutExpired, ValueError) as ex:
            rc = 1
            log(f"{action} failed: {ex}")
            if action in ("lab", "local-llm", "dbquery", "dbdelete"):
                continue                        # their pages show their own status (or wait for an answer)
            if action in ("plan", "plan-cancel"):
                task.update(state="failed", finished=now(), message=f"Not planned: {ex}"[:1000])
                publish(task)
            elif action in ("upgrade", "rollback", "app-patch-remove"):
                task.update(state="failed", finished=now(), message=str(ex)[-1000:])
                publish(task)
            elif action == "sandbox-https":
                st = sandbox_https_status()
                st["error"] = f"{now()}: {ex}"[:1000]
                publish(https_state=st)
            else:
                st = egress_status()
                st["error"] = f"{now()}: {ex}"[:1000]
                publish(egress_state=st)
    return rc


# =============================================================================== health

HEALTH_START_WAIT = 900     # seconds a unit may take to start
HEALTH_POLL = 10


def health() -> int:
    """Boot assessment (elemental-boot-assessment runs it until it passes, at most 5 times 30 s apart,
    then restarts into the previous snapshot): the firewall is loaded, the DNS filter, Docker and k3s
    are running (each may take HEALTH_START_WAIT seconds to finish starting), and the web UI's code imports. Image downloads and the database are not waited for:
    on a slow network they take longer than the assessment allows."""
    try:
        run(["nft", "list", "table", "inet", TABLE], timeout=30)
    except (AgentError, OSError) as ex:
        log(f"health: firewall not loaded: {ex}")
        return 1
    # k3s takes minutes to report ready on a first boot; a unit still starting is waited for (the
    # checker runs as a oneshot without a start timeout), one that failed or is not started fails now
    deadline = time.monotonic() + HEALTH_START_WAIT
    for unit in ("containerizer-dns.service", "docker.service", "k3s.service"):
        while True:
            state = run(["systemctl", "is-active", unit], timeout=30, check=False).strip()
            if state == "active":
                break
            if state not in ("activating", "reloading") or time.monotonic() >= deadline:
                log(f"health: {unit} is {state or 'unknown'}")
                return 1
            time.sleep(HEALTH_POLL)
    try:
        import importlib
        for m in ("containerizer.webui", "containerizer.admin", "containerizer.cli"):
            importlib.import_module(m)
    except Exception as ex:          # noqa: BLE001 - any import failure means a broken image
        log(f"health: {type(ex).__name__}: {ex}")
        return 1
    return 0


def main(argv=None) -> int:
    from . import sqlstore
    sqlstore.APP_ROLE = "sysagent"            # its SQL Server sessions (sqlstore.app_name)
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    try:
        if cmd == "status":
            publish(egress_state=egress_status())
            try:
                local_llm.reconcile()
            except (AgentError, LocalLlmError, OSError, subprocess.TimeoutExpired) as ex:
                log(f"built-in LLM: {ex}")
            return 0
        if cmd == "process":
            return process()
        if cmd == "upgrade" and len(argv) >= 2 and set(argv[2:]) <= {"--full", "--no-reboot"}:
            upgrade(argv[1], {"action": "upgrade", "version": argv[1], "requested_by": "console"},
                    reboot="--no-reboot" not in argv, full="--full" in argv)
            return 0
        if cmd == "app-patch" and argv[1:] == ["select"]:
            log(select_patch())
            return 0
        if cmd == "app-patch" and argv[1:] == ["remove"]:
            remove_patch({"action": "app-patch-remove", "requested_by": "console"})
            return 0
        if cmd == "rollback" and len(argv) == 2 and argv[1].isdigit():
            rollback(int(argv[1]), {"action": "rollback", "snapshot": int(argv[1]), "requested_by": "console"})
            return 0
        if cmd == "firewall" and argv[1:2] == ["apply"]:
            apply_firewall(reload_dns="--no-dns-reload" not in argv)
            return 0
        if cmd == "firewall" and argv[1:2] == ["show"]:
            nft, dns = render(system_rules(), load_rules(P.rules))
            print(nft)
            print(dns)
            return 0
        if cmd == "health":
            return health()
        if cmd == "restart-check":
            log(f"restart: {restart_check()}")
            return 0
        if cmd == "sql-env":
            write_sql_env()
            return 0
        if cmd == "sandbox-https" and argv[1:2] == ["sync"]:
            print(sync_sandbox_https())
            return 0
    except (AgentError, RuleError, PatchError, OSError, subprocess.TimeoutExpired) as ex:
        log(f"error: {ex}")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
