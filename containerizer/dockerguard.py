"""Docker socket guard: the scan worker's only way to Docker on the appliance
(docs/appliance-admin.md#builds-of-scanned-code; issue #255).

The worker builds and runs the scanned repositories' images. Docker's own socket is root on the host: whoever can
call it can start a privileged container, mount `/`, join the host's network namespace or `docker exec` into the
appliance's SQL Server. So the worker is not in the `docker` group; it talks to this proxy
(DOCKER_HOST=unix:///run/containerizer/docker-guard.sock), which forwards what builds, verification runs, the
security gate and the image scanner need and refuses the rest:

- containers: no privileged mode, no host network/PID/IPC/UTS/user/cgroup namespace, no devices, only Docker's
  default capabilities, namespaced sysctls only, no seccomp/AppArmor/SELinux opt-out, no `no-new-privileges=false`,
  bind mounts only from the worker's own folder (and the CA bundle, and this socket for the image scanner), ports
  published on loopback only. Each container it creates gets the label `io.containerizer.owner=worker`, and every
  call on a single container (inspect, logs, exec, archive, stop, remove, commit, ...) needs that label: the
  appliance's own containers (SQL Server, registry, Grafana, kubemg) are out of reach.
- builds: no host network (also refused by the daemon, `builder.entitlements` in /etc/docker/daemon.json, for
  BuildKit's own API), no cgroup parent.
- no plugins, swarm, network creation, volumes with driver options, or container prune.

The policy (`decide`, `check_create`, ...) is plain functions, tested in tests/test_build_isolation.py; `serve` is the
small HTTP/1.1 proxy around them (one request per upstream connection; upgraded connections such as BuildKit's
`/session` and `/grpc` are spliced after Docker answers 101).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, unquote, urlsplit

UPSTREAM = "/var/run/docker.sock"
LISTEN = "/run/containerizer/docker-guard.sock"
OWNER_LABEL = "io.containerizer.owner"
OWNER = "worker"
MAX_HEAD = 64 * 1024
MAX_BODY = 4 * 1024 * 1024
# Docker's default capability set: a container gets these unless dropped, so adding them back grants nothing new
DEFAULT_CAPS = {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
                "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
NAMESPACED_SYSCTL = re.compile(r"^(net\.|kernel\.(shm|msg|sem)|fs\.mqueue\.)")
SAFE_NETWORK = {"", "default", "bridge", "none"}
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
VERSION = re.compile(r"^/v\d+(\.\d+)*(?=/)")
DENIED_PREFIXES = ("/plugins", "/swarm", "/services", "/nodes", "/tasks", "/secrets", "/configs", "/distribution")


class Denied(Exception):
    pass


@dataclass
class Config:
    bind_roots: list[str] = field(default_factory=lambda: ["/var/lib/containerizer/worker"])
    bind_files: list[str] = field(default_factory=list)       # single files: the CA bundle, this socket


@dataclass
class Decision:
    body: str = ""            # "": forward as is; "create" | "exec" | "volume": inspect the JSON body
    owned: str | None = None  # a container reference that must carry the owner label
    upgrade: bool = False     # may be upgraded (BuildKit sessions, attach, exec start)


# --------------------------------------------------------------------------- policy

def _dup_check(pairs):
    seen = set()
    for k, _ in pairs:
        if k.lower() in seen:     # Go's JSON decoder matches field names case-insensitively, last one wins
            raise Denied(f"duplicate field {k!r}")
        seen.add(k.lower())
    return dict(pairs)


def parse_json(raw: bytes) -> dict:
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw, object_pairs_hook=_dup_check)
    except ValueError as e:
        raise Denied(f"unreadable JSON body: {e}") from None
    if not isinstance(obj, dict):
        raise Denied("the body is not a JSON object")
    return obj


def _get(d, key, default=None):
    if not isinstance(d, dict):
        return default
    for k, v in d.items():
        if k.lower() == key.lower():
            return default if v is None else v
    return default


def _key(d: dict, key: str) -> str:
    return next((k for k in d if k.lower() == key.lower()), key)


def decide(method: str, target: str) -> Decision:
    """What a request needs before it may be forwarded; raises Denied for what is never allowed."""
    split = urlsplit(target)
    path = unquote(split.path)
    if not path.startswith("/") or "//" in path or "\x00" in path or "\\" in path or any(
            seg in (".", "..") for seg in path.split("/")):
        raise Denied("unusual request path")
    path = VERSION.sub("", path)
    query = parse_qs(split.query, keep_blank_values=True)
    m = method.upper()
    if path.startswith(DENIED_PREFIXES):
        raise Denied(f"{path.split('/')[1]} are not available to the scan worker")
    if path in ("/session", "/grpc"):
        return Decision(upgrade=True)
    if path == "/build":
        for v in query.get("networkmode", []):
            if v.lower() not in SAFE_NETWORK:
                raise Denied(f"builds run without the host network (networkmode={v})")
        if any(query.get("cgroupparent", [])):
            raise Denied("builds keep Docker's cgroup parent")
        return Decision()
    if path == "/commit":
        ref = (query.get("container") or [""])[0]
        if not ref:
            raise Denied("commit needs a container")
        return Decision(owned=ref)
    if path.startswith("/networks"):
        if m in ("GET", "HEAD"):
            return Decision()
        raise Denied("networks are managed by the appliance")
    if path == "/volumes/create":
        return Decision(body="volume")
    if path == "/containers/create":
        return Decision(body="create")
    if path == "/containers/prune":
        raise Denied("container prune would remove the appliance's own stopped containers")
    if path == "/containers/json":
        return Decision()
    mc = re.match(r"^/containers/([^/]+)(/.*)?$", path)
    if mc:
        sub = mc.group(2) or ""
        if sub == "/exec":
            return Decision(body="exec", owned=mc.group(1))
        return Decision(owned=mc.group(1), upgrade=sub == "/attach")
    if re.match(r"^/exec/[^/]+/start$", path):
        return Decision(upgrade=True)
    return Decision()


def _source_ok(src: str, cfg: Config) -> bool:
    if not src.startswith("/"):
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", src))      # a named volume (plain local driver)
    try:
        real = os.path.realpath(src, strict=True)    # symbolic links resolved: no way out through a link
    except OSError:
        return False
    files = {os.path.realpath(f) for f in cfg.bind_files if f}
    if real in files:
        return True
    for root in cfg.bind_roots:
        r = os.path.realpath(root).rstrip("/")
        if real == r or real.startswith(r + "/"):
            return True
    return False


def _ns_mode(name: str, v) -> None:
    v = str(v or "").lower()
    if v == "host" or v.startswith("container:"):
        raise Denied(f"{name}={v}: containers keep their own namespaces")


def check_create(body: dict, cfg: Config) -> dict:
    """Refuse a container that could reach the host; returns the body with the owner label added."""
    hc = _get(body, "HostConfig", {})
    if not isinstance(hc, dict):
        raise Denied("HostConfig is not an object")
    if _get(hc, "Privileged", False):
        raise Denied("privileged containers are not allowed")
    net = str(_get(hc, "NetworkMode", "")).lower()
    if net == "host" or net.startswith("container:"):
        raise Denied(f"NetworkMode={net}: builds and verification runs never get the host network")
    for name in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
        _ns_mode(name, _get(hc, name, ""))
    eps = _get(_get(body, "NetworkingConfig", {}), "EndpointsConfig", {}) or {}
    for n in eps:
        if n.lower() == "host" or n.lower().startswith("container:"):
            raise Denied(f"network {n} is not allowed")
    for name in ("Devices", "DeviceRequests", "DeviceCgroupRules", "VolumesFrom"):
        if _get(hc, name):
            raise Denied(f"{name} is not allowed")
    for name in ("CgroupParent", "Cgroup"):
        if _get(hc, name):
            raise Denied(f"{name} is not allowed")
    if str(_get(hc, "Runtime", "")).lower() not in ("", "runc"):
        raise Denied("only the default runtime")
    for name in ("MaskedPaths", "ReadonlyPaths"):
        if hc.get(_key(hc, name)) is not None:       # unset (null) keeps Docker's masked /proc paths
            raise Denied(f"{name} keeps Docker's default")
    for cap in _get(hc, "CapAdd", []) or []:
        c = str(cap).upper().removeprefix("CAP_")
        if c not in DEFAULT_CAPS:
            raise Denied(f"capability {cap} is not allowed (only Docker's default set)")
    for k in (_get(hc, "Sysctls", {}) or {}):
        if not NAMESPACED_SYSCTL.match(k):
            raise Denied(f"sysctl {k} is not allowed")
    for opt in _get(hc, "SecurityOpt", []) or []:
        o = str(opt).lower().replace(":", "=").replace(" ", "")
        if "unconfined" in o or o in ("label=disable", "no-new-privileges=false") or o.startswith("seccomp="):
            raise Denied(f"security option {opt} is not allowed")
    for b in _get(hc, "Binds", []) or []:
        src = str(b).split(":", 1)[0]
        if not _source_ok(src, cfg):
            raise Denied(f"bind mount {src}: only the worker's own folder")
    for mnt in _get(hc, "Mounts", []) or []:
        t = str(_get(mnt, "Type", "volume")).lower()
        if t == "bind":
            if not _source_ok(str(_get(mnt, "Source", "")), cfg):
                raise Denied(f"bind mount {_get(mnt, 'Source', '')}: only the worker's own folder")
            if str(_get(_get(mnt, "BindOptions", {}), "Propagation", "")).lower() not in ("", "rprivate", "private"):
                raise Denied("bind propagation is not allowed")
        elif t == "volume":
            src = str(_get(mnt, "Source", ""))
            if src and not _source_ok(src, cfg) or _get(_get(mnt, "VolumeOptions", {}), "DriverConfig"):
                raise Denied("volumes with a driver configuration are not allowed")
        elif t != "tmpfs":
            raise Denied(f"mount type {t} is not allowed")
    if _get(hc, "PublishAllPorts", False):
        raise Denied("ports are published on loopback only")
    for bindings in (_get(hc, "PortBindings", {}) or {}).values():
        for pb in bindings or []:
            if str(_get(pb, "HostIp", "")) not in LOOPBACK:
                raise Denied("ports are published on loopback only (127.0.0.1)")
    labels_key = _key(body, "Labels")
    labels = body.get(labels_key) or {}
    if not isinstance(labels, dict):
        raise Denied("Labels is not an object")
    body[labels_key] = {**labels, OWNER_LABEL: OWNER}
    return body


def check_exec(body: dict) -> dict:
    if _get(body, "Privileged", False):
        raise Denied("privileged exec is not allowed")
    return body


def check_volume(body: dict) -> dict:
    if str(_get(body, "Driver", "local")).lower() not in ("", "local") or _get(body, "DriverOpts"):
        raise Denied("volumes with a driver or driver options are not allowed")
    return body


def check_body(kind: str, raw: bytes, cfg: Config) -> bytes:
    body = parse_json(raw)
    out = {"create": lambda b: check_create(b, cfg), "exec": check_exec, "volume": check_volume}[kind](body)
    return json.dumps(out).encode()


def owned(inspect: dict) -> bool:
    labels = _get(_get(inspect, "Config", {}), "Labels", {}) or {}
    return labels.get(OWNER_LABEL) == OWNER


# --------------------------------------------------------------------------- HTTP plumbing

HOP = {"connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer"}


def _parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    lines = head.decode("latin-1").split("\r\n")
    start, headers = lines[0], []
    for ln in lines[1:]:
        if not ln:
            continue
        if ln[0] in " \t" or ":" not in ln:
            raise Denied("malformed header")
        k, v = ln.split(":", 1)
        if k != k.strip() or not k:
            raise Denied("malformed header")
        headers.append((k, v.strip()))
    return start, headers


def _hget(headers, name) -> list[str]:
    return [v for k, v in headers if k.lower() == name]


def _response(status: int, reason: str, message: str) -> bytes:
    body = json.dumps({"message": f"containerizer docker guard: {message}"}).encode()
    return (f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode() + body


async def _read_body(r: asyncio.StreamReader, headers) -> bytes:
    te, cl = _hget(headers, "transfer-encoding"), _hget(headers, "content-length")
    if te:
        if cl or len(te) != 1 or te[0].lower() != "chunked":
            raise Denied("unsupported transfer encoding")
        out = b""
        while True:
            size = int((await r.readuntil(b"\r\n")).split(b";")[0].strip(), 16)
            if size == 0:
                while (await r.readuntil(b"\r\n")) != b"\r\n":
                    pass
                return out
            if len(out) + size > MAX_BODY:
                raise Denied("body too large")
            out += await r.readexactly(size)
            await r.readexactly(2)
    if len(cl) > 1 or (cl and not cl[0].isdigit()):
        raise Denied("bad Content-Length")
    n = int(cl[0]) if cl else 0
    if n > MAX_BODY:
        raise Denied("body too large")
    return await r.readexactly(n)


async def _pump(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            if w.can_write_eof():
                w.write_eof()
        except (OSError, RuntimeError):
            pass


async def _linger(r: asyncio.StreamReader, limit: int = 1 << 30, idle: float = 5.0) -> None:
    """Read and drop what the client still sends (a refused build's context), so that it reads the refusal
    instead of a connection reset."""
    seen = 0
    try:
        while seen < limit:
            data = await asyncio.wait_for(r.read(65536), idle)
            if not data:
                return
            seen += len(data)
    except (asyncio.TimeoutError, ConnectionError):
        pass


async def _inspect(upstream: str, ref: str) -> dict | None:
    r, w = await asyncio.open_unix_connection(upstream)
    try:
        w.write(f"GET /containers/{quote(ref, safe='')}/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode())
        await w.drain()
        status, headers = _parse_head((await r.readuntil(b"\r\n\r\n"))[:-4])
        if status.split(" ")[1] != "200":
            return None
        return json.loads(await _read_body(r, headers) if _hget(headers, "transfer-encoding") or
                          _hget(headers, "content-length") else await r.read())
    finally:
        w.close()


class Guard:
    def __init__(self, upstream: str, cfg: Config):
        self.upstream, self.cfg = upstream, cfg
        self.tasks: set[asyncio.Task] = set()   # asyncio keeps only weak references to running connections

    async def handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            await self._handle(cr, cw)
        finally:
            self.tasks.discard(task)

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        uw = None
        try:
            try:
                head = await cr.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                return
            try:
                start, headers = _parse_head(head[:-4])
                parts = start.split(" ")
                if len(parts) != 3 or parts[2] != "HTTP/1.1":
                    raise Denied("HTTP/1.1 only")
                method, target = parts[0], parts[1]
                d = decide(method, target)
                upgrade = any("upgrade" in v.lower() for v in _hget(headers, "connection")) or bool(_hget(headers, "upgrade"))
                if upgrade and not d.upgrade:
                    raise Denied("this call cannot be upgraded")
                body = None
                if d.body or upgrade:
                    body = await _read_body(cr, headers)
                    if d.body:
                        body = check_body(d.body, body, self.cfg)
                if d.owned is not None:
                    info = await _inspect(self.upstream, d.owned)
                    if info is not None and not owned(info):
                        raise Denied(f"container {d.owned} is not one of the scan worker's")
            except Denied as e:
                cw.write(_response(403, "Forbidden", str(e)))
                await cw.drain()
                await _linger(cr)
                return
            ur, uw = await asyncio.open_unix_connection(self.upstream)
            keep = [(k, v) for k, v in headers if k.lower() not in HOP | ({"content-length", "transfer-encoding"}
                                                                          if body is not None else set())]
            if upgrade:
                keep += [(k, v) for k, v in headers if k.lower() in ("connection", "upgrade")]
            else:
                keep.append(("Connection", "close"))
            if body is not None:
                keep.append(("Content-Length", str(len(body))))
            uw.write((f"{method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in keep) + "\r\n").encode("latin-1"))
            if body:
                uw.write(body)
            await uw.drain()
            if upgrade:
                rhead = await ur.readuntil(b"\r\n\r\n")
                cw.write(rhead)
                await cw.drain()
                rstart, rheaders = _parse_head(rhead[:-4])
                if rstart.split(" ")[1] == "101":
                    await asyncio.gather(_pump(cr, uw), _pump(ur, cw))
                else:       # not upgraded: relay the answer and close, so no second request skips the checks
                    cl = _hget(rheaders, "content-length")
                    cw.write(await ur.readexactly(int(cl[0])) if cl and cl[0].isdigit() else
                             await asyncio.wait_for(ur.read(MAX_BODY), 10))
                    await cw.drain()
                return
            if body is None:
                await asyncio.gather(_pump(cr, uw), _pump(ur, cw))
            else:
                await _pump(ur, cw)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        finally:
            for w in (uw, cw):
                if w is not None:
                    w.close()


async def serve(listen: str, upstream: str, cfg: Config) -> None:
    guard = Guard(upstream, cfg)
    if os.environ.get("LISTEN_FDS") == "1" and os.environ.get("LISTEN_PID") == str(os.getpid()):
        sock = socket.socket(fileno=3)          # socket activation (containerizer-docker-guard.socket)
        server = await asyncio.start_unix_server(guard.handle, sock=sock, limit=MAX_HEAD)
    else:
        if os.path.exists(listen):
            os.unlink(listen)
        server = await asyncio.start_unix_server(guard.handle, path=listen, limit=MAX_HEAD)
        os.chmod(listen, 0o660)
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m containerizer.dockerguard", description=__doc__.split("\n")[0])
    ap.add_argument("--listen", default=LISTEN)
    ap.add_argument("--upstream", default=UPSTREAM)
    ap.add_argument("--bind-root", action="append", default=None,
                    help="a folder whose files containers may bind-mount (repeatable; default the worker's folder)")
    ap.add_argument("--bind-file", action="append", default=[], help="a single file containers may bind-mount")
    a = ap.parse_args(argv)
    ca = os.environ.get("CONTAINERIZER_CA_BUNDLE", "")      # the scanners mount it (imagescan._docker_tool_args)
    cfg = Config(bind_roots=a.bind_root or Config().bind_roots, bind_files=[*a.bind_file, a.listen, ca])
    try:
        asyncio.run(serve(a.listen, a.upstream, cfg))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
