"""Debug mode of an application in the sandbox (docs/scheduled-scans.md#debug-mode).

A container that crashes at start cannot be looked into: `kubectl exec` has nothing to run in, the images have no
shell (chiseled, distroless), and an ephemeral debug container only shares a running container's processes. An
administrator turns debug mode on for the application (Admin → Applications → Sandbox, Application.SandboxDebug):
its pods then stay running without starting the application, with Bash and the usual tools in them:

- the pod's command is `/cz-debug/bin/sleep infinity` (the arguments and the probes are taken off), so the container
  runs with the application's own image, user, environment, mounts, security context and network: what the
  application would have started in;
- `/cz-debug` is an emptyDir an init container fills from the tools image: a static Bash, a static BusyBox with its
  applets (`ls`, `cat`, `vi`, `ps`, `wget`, `nc`, `nslookup`, ...) in `/cz-debug/bin`, `/cz-debug/shell` (Bash with
  the tools on PATH) and `/cz-debug/start` (the application's own start command, `CZ_DEBUG_START`);
- nothing is built again and nothing in the application's folder changes: the patch is on the sandbox's copy of the
  application's Flux Kustomization (org.write_sandbox, as the sandbox's wait patch), so the other clusters of the
  output repository never see it, and turning it off brings the application back as it was.

The tools image is `<registry>/cz-debug-tools:<hash>`, made here from the static binaries of the machine
(`bash-static` and `busybox`, in the appliance's OS image) with a `FROM scratch` build, and pushed by the queue runner
when an application's debug mode is turned on (variant.sync_sandbox). A machine without them has no debug mode.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import yaml

DIR = "/cz-debug"
VOLUME = "cz-debug"
INIT = "cz-debug-tools"
IMAGE = "cz-debug-tools"
UID = 65532
FORMAT = "2"                     # of the tools image (part of its tag): 2 = readable by every user, whatever the umask
BINARIES = {"bash": ("bash-static",), "busybox": ("busybox-static", "busybox")}
KINDS = ("Deployment", "StatefulSet")
SLEEP = [f"{DIR}/bin/sleep", "infinity"]
SHELL = """#!/cz-debug/busybox sh
# Bash with the debug tools on PATH (after the image's own)
export PATH="$PATH:/cz-debug/bin"
if [ -n "$CZ_DEBUG_START" ]; then
  echo "Debug mode: the application is not started. Its start command (run it with /cz-debug/start):"
  echo "  $CZ_DEBUG_START"
fi
exec /cz-debug/bash "$@"
"""
START = """#!/cz-debug/busybox sh
# The application's own start command, in the foreground
if [ -z "$CZ_DEBUG_START" ]; then
  echo "The start command is not known: see ENTRYPOINT and CMD of the component's Dockerfile" >&2
  exit 2
fi
eval "exec $CZ_DEBUG_START"
"""


class Switches(set):
    """The applications whose sandbox is turned off (the set itself: SourceKeys and ApplicationIds), and in `debug`
    the ones in debug mode. One object, so every writer of sandbox/ that knows the first knows the second."""

    def __init__(self, off=(), debug=()):
        super().__init__(off)
        self.debug = set(debug)

    def __bool__(self) -> bool:
        return bool(len(self) or self.debug)


def debug_of(off) -> set:
    return getattr(off, "debug", None) or set()


def is_static(path: Path) -> bool:
    """An ELF program without a program interpreter (it runs in an image that has no libc)."""
    try:
        head = path.read_bytes()[:4096]
    except OSError:
        return False
    return head[:4] == b"\x7fELF" and b"/ld-" not in head and b"ld.so" not in head


@lru_cache(maxsize=1)
def binaries() -> dict | None:
    """{name in the image: path on this machine} of the static Bash and BusyBox, or None without them."""
    out = {}
    for name, cands in BINARIES.items():
        p = next((Path(w) for c in cands if (w := shutil.which(c)) and is_static(Path(w))), None)
        if p is None:
            return None
        out[name] = p
    return out


@lru_cache(maxsize=1)
def _hash() -> str:
    h = hashlib.sha256((FORMAT + SHELL + START).encode())
    for _, p in sorted((binaries() or {}).items()):
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


def tools_ref(registry: str) -> str | None:
    """The tools image of a registry (`<registry>/cz-debug-tools:<hash of its content>`), None without the binaries."""
    if not registry or binaries() is None:
        return None
    return f"{registry.rstrip('/')}/{IMAGE}:{_hash()}"


def registry_of(doc: dict) -> str:
    """The registry an application's images are in, from its containerizer.json (`<registry>/<app>/<component>:tag`)."""
    for c in doc.get("components") or []:
        parts = str(c.get("image") or "").rsplit("/", 2)
        if len(parts) == 3:
            return parts[0]
    return ""


def build_context(ctx: Path) -> None:
    """The tools image's build context: the binaries, the applets as links, the two scripts."""
    bins = binaries()
    if bins is None:
        raise RuntimeError("no static bash-static and busybox on this machine")
    if ctx.exists():
        shutil.rmtree(ctx)
    root = ctx / "cz-debug"
    (root / "bin").mkdir(parents=True)
    for name, p in bins.items():
        shutil.copyfile(p, root / name)
        (root / name).chmod(0o755)
    applets = subprocess.run([str(root / "busybox"), "--list"], capture_output=True, text=True, timeout=30).stdout.split()
    for a in applets:
        if re.fullmatch(r"[A-Za-z0-9_.\[-]+", a) and a not in ("bash", "busybox"):
            (root / "bin" / a).symlink_to("../busybox")
    (root / "bin" / "bash").symlink_to("../bash")
    for name, text in (("shell", SHELL), ("start", START)):
        (root / name).write_text(text)
        (root / name).chmod(0o755)
    # the application's user reads it, whatever umask this process runs with (the services': 077)
    for q in (ctx, root, root / "bin"):
        q.chmod(0o755)
    (ctx / "Dockerfile").write_text(f"FROM scratch\nCOPY --chown={UID}:{UID} --chmod=0755 cz-debug /cz-debug\n"
                                    f"USER {UID}:{UID}\nENTRYPOINT [\"/cz-debug/busybox\"]\n")


def ensure_tools(registry: str, work: Path, log=print) -> str | None:
    """Build the tools image and push it to the registry (a few megabytes, no network: FROM scratch). The reference,
    or None when this machine cannot make it (the reason is logged)."""
    ref = tools_ref(registry)
    if ref is None:
        log("debug mode: no static bash-static and busybox on this machine: the tools image is not made")
        return None
    ctx = work / "debug-tools"
    try:
        build_context(ctx)
        local = f"containerizer/{IMAGE}:{_hash()}"
        p = subprocess.run(["docker", "build", "-q", "-t", local, str(ctx)], capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            raise RuntimeError(f"docker build: {(p.stderr or p.stdout).strip()[-300:]}")
        from .org import Registry
        Registry(registry).push(local, ref)
        return ref
    except Exception as ex:  # noqa: BLE001 - the switch is tried again at the next step
        log(f"debug mode: tools image {ref} not pushed: {type(ex).__name__}: {str(ex)[:300]}")
        return None
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


# --------------------------------------------------------------------------- the start command

def _exec_form(line: str) -> list[str] | None:
    line = line.strip()
    if line.startswith("["):
        try:
            v = json.loads(line)
        except ValueError:
            return None
        return [str(x) for x in v] if isinstance(v, list) else None
    return ["/bin/sh", "-c", line] if line else None


def image_command(dockerfile: str) -> tuple[list[str], list[str]]:
    """(ENTRYPOINT, CMD) of the Dockerfile's last stage, each as a list (empty: not set there)."""
    stage = re.split(r"(?im)^FROM\s", dockerfile)[-1]
    stage = re.sub(r"\\\r?\n", " ", stage)
    ep = cmd = None
    for m in re.finditer(r"(?im)^\s*(ENTRYPOINT|CMD)\s+(.*)$", stage):
        if m.group(1).upper() == "ENTRYPOINT":
            ep, cmd = _exec_form(m.group(2)), None      # ENTRYPOINT resets an earlier CMD of the same stage
        else:
            cmd = _exec_form(m.group(2))
    return ep or [], cmd or []


def start_command(container: dict, dockerfile: str | None) -> str:
    """What the container would have run, as one shell command line ('' when it cannot be told)."""
    ep, cmd = image_command(dockerfile) if dockerfile else ([], [])
    command = [str(x) for x in container.get("command") or []]
    args = container.get("args")
    if command:
        full = command + [str(x) for x in args or []]
    else:
        full = ep + ([str(x) for x in args] if args is not None else cmd)
    if not full or (not command and not ep and dockerfile is None):
        return ""
    return shlex.join(full)


# --------------------------------------------------------------------------- the patches

def workload_patch(doc: dict, tools: str, start: str = "") -> str | None:
    """Strategic merge patch that puts a Deployment or StatefulSet in debug mode; None when it has no container."""
    pod = (((doc.get("spec") or {}).get("template") or {}).get("spec") or {})
    containers = pod.get("containers") or []
    if doc.get("kind") not in KINDS or not containers:
        return None
    c = containers[0]
    env = [{"name": "CZ_DEBUG", "value": "1"}] + ([{"name": "CZ_DEBUG_START", "value": start}] if start else [])
    init = {"name": INIT, "image": tools, "imagePullPolicy": "IfNotPresent",
            "command": [f"{DIR}/busybox", "sh", "-c", f"umask 022 && {DIR}/busybox cp -dR {DIR}/. /target/ && "
                        f"{DIR}/busybox chmod -R a+rX /target/*"],
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "runAsGroup": UID, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}},
            "volumeMounts": [{"name": VOLUME, "mountPath": "/target"}]}
    main = {"name": c.get("name"), "command": SLEEP, "args": None, "livenessProbe": None, "readinessProbe": None,
            "startupProbe": None, "env": env, "volumeMounts": [{"name": VOLUME, "mountPath": DIR, "readOnly": True}]}
    # the crashing pod goes first: a rolling update would wait for room in the namespace's quota next to it
    strategy = {"strategy": {"type": "Recreate", "rollingUpdate": None}} if doc["kind"] == "Deployment" else {}
    patch = {"apiVersion": doc.get("apiVersion") or "apps/v1", "kind": doc["kind"],
             "metadata": {"name": (doc.get("metadata") or {}).get("name"),
                          "annotations": {"containerizer.io/debug": "true"}},
             "spec": {"replicas": 1, **strategy, "template": {
                 "metadata": {"annotations": {"containerizer.io/debug": "true"}},
                 "spec": {"initContainers": [init], "containers": [main],
                          "volumes": [{"name": VOLUME, "emptyDir": {"sizeLimit": "64Mi"}}]}}}}
    return yaml.safe_dump(patch, sort_keys=False)


def _component_docs(cdir: Path) -> tuple[list[dict], str | None]:
    """(the component's objects, the name of its HelmRelease or None when it is plain manifests)."""
    from .helmchart import HELMRELEASE, MANIFESTS, component_docs
    hr = cdir / HELMRELEASE
    if hr.is_file():
        try:
            raw = [d for d in yaml.safe_load_all(hr.read_text()) if isinstance(d, dict) and d.get("kind") == "HelmRelease"]
        except yaml.YAMLError:
            raw = []
        return component_docs(cdir), ((raw[0].get("metadata") or {}).get("name") if raw else None)
    try:
        return [d for d in yaml.safe_load_all((cdir / MANIFESTS).read_text()) if isinstance(d, dict)], None
    except (OSError, yaml.YAMLError):
        return [], None


def ops(folder: Path, doc: dict, tools: str) -> list[dict]:
    """JSON patch operations on the sandbox's copy of the application's Flux Kustomization: one kustomize patch per
    Deployment and StatefulSet of its components; for a component of the shared chart, on its HelmRelease as a
    post-renderer (the chart's own values are left alone)."""
    from .helmchart import HELM_API
    out = []
    for c in doc.get("components") or []:
        cdir = folder / str(c.get("folder") or "")
        if not c.get("folder") or not cdir.is_dir():
            continue
        docs, release = _component_docs(cdir)
        try:
            dockerfile = (cdir / "Dockerfile").read_text()
        except OSError:
            dockerfile = None
        patches = []
        for d in docs:
            pod = (((d.get("spec") or {}).get("template") or {}).get("spec") or {})
            if d.get("kind") not in KINDS or not pod.get("containers"):
                continue
            p = workload_patch(d, tools, start_command(pod["containers"][0], dockerfile))
            if p:
                patches.append({"target": {"group": "apps", "kind": d["kind"], "name": d["metadata"]["name"]}, "patch": p})
        if not patches:
            continue
        if release:
            out.append({"op": "add", "path": "/spec/patches/-", "value": {
                "target": {"group": HELM_API.split("/")[0], "kind": "HelmRelease", "name": release},
                "patch": json.dumps([{"op": "add", "path": "/spec/postRenderers",
                                      "value": [{"kustomize": {"patches": patches}}]}])}})
        else:
            out += [{"op": "add", "path": "/spec/patches/-", "value": p} for p in patches]
    return out


def in_debug(doc: dict, debug) -> bool:
    """An app folder (its containerizer.json) of an application in debug mode: by its SourceKey, or by the
    application id of the Make it A patch it runs."""
    if not debug:
        return False
    return doc.get("source_key") in debug or any((doc.get(k) or {}).get("application_id") in debug
                                                 for k in ("patched", "variant"))


def exec_command(namespace: str, workload: str) -> str:
    return f"kubectl -n {namespace} exec -it {workload} -- {DIR}/shell"
