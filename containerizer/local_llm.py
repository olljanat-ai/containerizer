"""The appliance's built-in LLM: llama.cpp's server with a CPU-friendly Qwen3-Coder build, off by default.

For sites without an external (GPU-backed) LLM. An administrator turns it on under Admin -> Source
control & LLM; the web UI only drops a request (action `local-llm`), and the system agent (root) checks
it again here before it changes anything:

- enable: the machine must have the RAM for it (MIN_RAM) and, unless the model file is already on the disk
  and verified, the free space for the download. The model is downloaded once from Hugging Face, pinned by
  commit and sha256 (MODEL): containerizer-local-llm-download.service runs `download`, and huggingface.co
  and hf.co are on the egress allow-list only while it runs (egress_rules). Then
  containerizer-local-llm.service runs the server on 127.0.0.1:8082, sized from the RAM (plan).
- disable: stops the server (or the download); the model file stays, so turning it on again is quick.
- remove-model: deletes the model file (only while off) to free its 16 GB.

The settings live in /var/lib/containerizer/system/local-llm.json (persistent), the model in
/var/lib/containerizer/llm (persistent, never part of the OS image). What the web UI and the scan worker
read is /run/containerizer/system/local-llm-status.json (no secrets). The scan worker uses the built-in
LLM when it is on and no LLM is registered on Admin -> Source control & LLM (credentials.llm_for_run).
It is never part of the boot assessment: a slow or missing model must not roll the OS back.

    python -m containerizer.local_llm download      (the download unit) fetch, check and install the model
    python -m containerizer.local_llm reconcile     start or stop what the settings say (sysagent status runs it)
    python -m containerizer.local_llm status        print the status
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

GiB = 1024 ** 3


@dataclass(frozen=True)
class Model:
    file: str
    url: str
    sha256: str
    size: int
    alias: str


MODEL = Model(
    file="Qwen3-Coder-30B-A3B-Instruct-IQ4_XS-4.20bpw.gguf",
    url="https://huggingface.co/byteshape/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/"
        "0436a5b1e12e051e8a8568d56a1526734d3ed572/Qwen3-Coder-30B-A3B-Instruct-IQ4_XS-4.20bpw.gguf",
    sha256="618f0a45a5a85f099106c80e44e0eb8ce9ee094b6268395b84e8b5b729f865dd",
    size=16_018_452_000,
    alias="qwen3-coder-30b-a3b",
)
PORT = 8082                         # 8081 is Caddy's http_port on the appliance
BASE_URL = f"http://127.0.0.1:{PORT}/v1"
TIMEOUT = 3600                      # seconds per LLM call: prompts of 5-15K tokens take minutes on a CPU
HF_HOSTS = ("huggingface.co", "hf.co")      # hf.co covers the CDN the resolve URL redirects to
MIN_RAM = 39 * GiB                  # MemTotal of a 40 GiB machine (the kernel keeps some): OS 16 GiB + LLM
DISK_MARGIN = 4 * GiB               # free space left on the persistent partition after the download
CTX_PER_SLOT = 22016                # tokens per answer slot (a multiple of 256, above the 15K evidence packs)
UNIT = "containerizer-local-llm.service"
DOWNLOAD_UNIT = "containerizer-local-llm-download.service"
ACTIONS = ("enable", "disable", "remove-model")
STATES = ("off", "refused", "downloading", "verifying", "download-failed", "starting", "running", "error")
USABLE = ("starting", "running")    # the scan worker may use it (requests wait while the model loads)
HISTORY = 30


@dataclass
class Paths:
    config: Path = Path("/var/lib/containerizer/system/local-llm.json")
    status: Path = Path("/run/containerizer/system/local-llm-status.json")
    env: Path = Path("/run/containerizer/local-llm.env")       # the server unit runs only while it exists
    models: Path = Path("/var/lib/containerizer/llm")
    meminfo: Path = Path("/proc/meminfo")

    @property
    def model(self) -> Path:
        return self.models / MODEL.file

    @property
    def part(self) -> Path:
        return self.models / (MODEL.file + ".part")

    @property
    def lock(self) -> Path:
        return self.config.with_name(".local-llm.lock")


P = Paths()


class LocalLlmError(Exception):
    pass


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run(cmd: list[str], timeout: int = 120, check: bool = True) -> str:
    from . import sysagent              # one place runs commands (and the tests replace it)
    return sysagent.run(cmd, timeout=timeout, check=check)


def _atomic(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)


# --------------------------------------------------------------------------- requirements

def mem_total(paths: Paths | None = None) -> int:
    """Bytes of RAM (MemTotal), 0 when unknown."""
    try:
        for line in (paths or P).meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def free_disk(path: Path) -> int:
    """Free bytes on the file system of `path` (or of its nearest folder that exists)."""
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        return shutil.disk_usage(p).free
    except OSError:
        return 0


def plan(ram: int) -> dict:
    """How the server is sized for the machine: answer slots (requests decoded together, for about the cost of
    one) and the container's memory limit. The pinned model is 15.6 GB; each slot adds about 2 GB of context and
    compute buffers. The rest of the appliance needs about 16 GiB."""
    slots = 1 if ram < 47 * GiB else 2 if ram < 63 * GiB else 3
    memory = 21 + 3 * slots                             # GiB: 24, 27, 30
    return {"slots": slots, "ctx_size": CTX_PER_SLOT * slots, "memory": f"{memory}g", "memory_bytes": memory * GiB}


def requirements(cfg: dict | None = None, paths: Paths | None = None) -> dict:
    """What the machine has and what the built-in LLM needs, with the reasons it cannot be turned on."""
    paths = paths or P
    cfg = load_config(paths) if cfg is None else cfg
    ram = mem_total(paths)
    ready = model_ready(cfg, paths)
    part = _size(paths.part)
    need_disk = 0 if ready else max(MODEL.size - part, 0) + DISK_MARGIN
    free = free_disk(paths.models)
    problems = []
    if ram < MIN_RAM:
        problems.append(f"the appliance has {ram / GiB:.1f} GiB of RAM; the built-in LLM needs a machine with at "
                        f"least 40 GiB (16 GiB for the appliance, about 24 GiB for the model and its context)")
    if free < need_disk:
        problems.append(f"{free / GiB:.1f} GiB free on the persistent partition; the model download needs "
                        f"{need_disk / GiB:.1f} GiB ({MODEL.size / 1e9:.1f} GB plus {DISK_MARGIN // GiB} GiB to spare)")
    return {"ram": ram, "min_ram": MIN_RAM, "free_disk": free, "need_disk": need_disk, "model_ready": ready,
            "plan": plan(ram), "problems": problems}


# --------------------------------------------------------------------------- settings and status

def load_config(paths: Paths | None = None) -> dict:
    try:
        d = json.loads((paths or P).config.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict, paths: Paths | None = None) -> None:
    _atomic((paths or P).config, json.dumps(cfg, indent=1, sort_keys=True), 0o644)


@contextlib.contextmanager
def locked(paths: Paths | None = None):
    """The system agent and the download unit both change the settings: one at a time."""
    import fcntl
    paths = paths or P
    paths.lock.parent.mkdir(parents=True, exist_ok=True)
    with open(paths.lock, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _stamp(p: Path) -> dict | None:
    try:
        st = p.stat()
    except OSError:
        return None
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "sha256": MODEL.sha256}


def model_ready(cfg: dict, paths: Paths | None = None) -> bool:
    """The model file is there, and is the one that was checked (same size, time and pinned checksum)."""
    paths = paths or P
    st = _stamp(paths.model)
    return bool(st) and st["size"] == MODEL.size and cfg.get("verified") == st


def egress_rules(cfg: dict | None = None) -> list[dict]:
    """Rules the firewall adds while the model is being downloaded (sysagent.system_rules), none otherwise."""
    cfg = load_config() if cfg is None else cfg
    if not (cfg.get("enabled") and cfg.get("phase") == "download"):
        return []
    return [{"host": h, "ports": ["tcp/443"], "note": "built-in LLM: model download from Hugging Face (only while it runs)"}
            for h in HF_HOSTS]


def _history(cfg: dict, entry: dict) -> None:
    cfg["history"] = ([dict(entry, at=now())] + list(cfg.get("history") or []))[:HISTORY]


def _unit_state(unit: str) -> str:
    try:
        return _run(["systemctl", "is-active", unit], timeout=30, check=False).strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired, Exception):          # noqa: BLE001 - status only
        return "unknown"


def server_health(timeout: float = 2.0) -> bool:
    """llama.cpp answers /health with 200 once the model is loaded (503 while it loads)."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:                       # noqa: BLE001 - not listening, loading, or anything else: not ready
        return False


def _restarts(unit: str) -> int:
    """Automatic restarts since the unit was last started on purpose (Restart=always hides a crash loop)."""
    try:
        return int(_run(["systemctl", "show", "-p", "NRestarts", "--value", unit], timeout=30, check=False).strip() or 0)
    except (OSError, subprocess.TimeoutExpired, ValueError, Exception):   # noqa: BLE001 - status only
        return 0


CRASH_LOOP_RESTARTS = 3


def status(cfg: dict | None = None, paths: Paths | None = None, unit_state=None, health=None, restarts=None,
           **extra) -> dict:
    """The status the web UI and the scan worker read."""
    paths = paths or P
    cfg = load_config(paths) if cfg is None else cfg
    unit_state = unit_state or _unit_state
    health = health or server_health
    restarts = restarts or _restarts
    req = requirements(cfg, paths)
    on = bool(cfg.get("enabled"))
    phase = cfg.get("phase")
    state, message = "off", ""
    if not on:
        if cfg.get("refused"):
            state, message = "refused", cfg["refused"]
    elif phase == "download":
        state = "downloading"
    elif phase == "failed":
        state, message = "download-failed", cfg.get("error") or "the download failed"
    elif not model_ready(cfg, paths):
        state, message = "error", "the model file is missing or changed; turn the built-in LLM off and on to download it again"
    elif req["ram"] and req["ram"] < MIN_RAM:
        state, message = "refused", req["problems"][0]
    else:
        u = unit_state(UNIT)
        if u in ("active", "activating", "reloading"):
            if health():
                state = "running"
            elif (n := restarts(UNIT)) >= CRASH_LOOP_RESTARTS:
                state, message = "error", (f"the server keeps restarting ({n} restarts, e.g. not enough memory to "
                                           f"lock the model): see journalctl -u {UNIT}")
            else:
                state = "starting"
        elif u == "failed":
            state, message = "error", f"{UNIT} failed: see journalctl -u {UNIT}"
        else:
            state = "starting"
    st = {"enabled": on, "state": state, "message": message, "model": {"file": MODEL.file, "alias": MODEL.alias,
          "size": MODEL.size, "sha256": MODEL.sha256, "url": MODEL.url, "on_disk": _size(paths.model),
          "verified": model_ready(cfg, paths)},
          "download": {"bytes": _size(paths.part) if state in ("downloading", "verifying", "download-failed") else 0,
                       "total": MODEL.size},
          "requirements": req, "plan": cfg.get("plan") or req["plan"], "base_url": BASE_URL, "port": PORT,
          "changed_by": cfg.get("changed_by"), "changed_by_name": cfg.get("changed_by_name"),
          "changed_at": cfg.get("changed_at"), "history": cfg.get("history") or [], "updated": now()}
    st.update(extra)
    return st


def publish(st: dict | None = None, paths: Paths | None = None) -> dict:
    paths = paths or P
    st = status(paths=paths) if st is None else st
    _atomic(paths.status, json.dumps(st, indent=1), 0o644)
    return st


# --------------------------------------------------------------------------- the scan worker's side

STATUS_ENV = "CONTAINERIZER_LOCAL_LLM"      # the status file (set on the appliance's worker unit)


def worker_settings(env=None) -> dict | None:
    """ai.configured() settings for the built-in LLM when it is on (starting or running), else None.
    Only the on/off state comes from the file; the address and model are this module's constants."""
    env = os.environ if env is None else env
    path = env.get(STATUS_ENV)
    if not path:
        return None
    try:
        st = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(st, dict) or not st.get("enabled") or st.get("state") not in USABLE:
        return None
    return {"CONTAINERIZER_AI_BACKEND": "openai", "CONTAINERIZER_LLM_BASE_URL": BASE_URL, "CONTAINERIZER_LLM_API_KEY": "",
            "CONTAINERIZER_MODEL": MODEL.alias, "CONTAINERIZER_LLM_TIMEOUT": str(TIMEOUT)}


# --------------------------------------------------------------------------- the system agent's side

def server_env(p: dict) -> str:
    return (f"CZ_LLM_MODEL_FILE={MODEL.file}\nCZ_LLM_ALIAS={MODEL.alias}\nCZ_LLM_PORT={PORT}\n"
            f"CZ_LLM_SLOTS={int(p['slots'])}\nCZ_LLM_CTX={int(p['ctx_size'])}\nCZ_LLM_MEMORY={p['memory']}\n")


def _start_server(cfg: dict, paths: Paths) -> None:
    p = plan(mem_total(paths))
    cfg["plan"] = p
    text = server_env(p)
    old = paths.env.read_text() if paths.env.exists() else None
    _atomic(paths.env, text, 0o644)
    if old is not None and old != text:
        _run(["systemctl", "try-restart", "--no-block", UNIT], timeout=60, check=False)
    _run(["systemctl", "start", "--no-block", UNIT], timeout=60)


def _stop_server(paths: Paths) -> None:
    paths.env.unlink(missing_ok=True)
    _run(["systemctl", "stop", "--no-block", UNIT, DOWNLOAD_UNIT], timeout=60, check=False)


def _firewall() -> None:
    from . import sysagent
    sysagent.apply_firewall()


def apply_request(req: dict, paths: Paths | None = None) -> dict:
    """A request from the admin page, checked again here (the web UI is not trusted)."""
    paths = paths or P
    do = req.get("do")
    if do not in ACTIONS:
        raise LocalLlmError(f"unknown built-in LLM request {do!r}")
    who = {"by": str(req.get("requested_by") or "?")[:256], "name": str(req.get("requested_by_name") or "")[:256]}
    firewall = False
    with locked(paths):
        cfg = load_config(paths)
        was_downloading = bool(egress_rules(cfg))
        if do == "enable":
            req_ = requirements(cfg, paths)
            if req_["problems"]:
                cfg["refused"] = "Not turned on: " + "; ".join(req_["problems"])
                _history(cfg, {**who, "action": "enable", "result": cfg["refused"]})
                save_config(cfg, paths)
                log(f"built-in LLM: {cfg['refused']}")
                return publish(status(cfg, paths), paths)   # an answer, not a failure of the agent
            cfg.update(enabled=True, refused=None, error=None, changed_by=who["by"], changed_by_name=who["name"],
                       changed_at=now())
            if model_ready(cfg, paths):
                cfg["phase"] = "ready"
                _start_server(cfg, paths)
                result = "turned on"
            else:
                cfg["phase"] = "download"
                firewall = True
                result = "turned on; downloading the model"
        elif do == "disable":
            cfg.update(enabled=False, refused=None, changed_by=who["by"], changed_by_name=who["name"], changed_at=now(),
                       phase="ready" if model_ready(cfg, paths) else None)
            _stop_server(paths)
            firewall = was_downloading
            result = "turned off"
        else:
            if cfg.get("enabled"):
                raise LocalLlmError("turn the built-in LLM off before removing its model file")
            for f in (paths.model, paths.part):
                f.unlink(missing_ok=True)
            cfg.update(verified=None, phase=None, error=None, refused=None)
            result = "model file removed"
        _history(cfg, {**who, "action": do, "result": result})
        save_config(cfg, paths)
    if firewall:
        _firewall()                     # huggingface.co and hf.co in (download) or out (off) of the allow-list
    if do == "enable" and cfg.get("phase") == "download":
        _run(["systemctl", "start", "--no-block", DOWNLOAD_UNIT], timeout=60)
    return publish(status(cfg, paths), paths)


def reconcile(paths: Paths | None = None) -> dict:
    """Make the services match the settings (at boot and every 5 minutes, from `sysagent status`): start the
    server or resume an interrupted download when on, stop them when off. A download that failed is not
    retried by itself: turning the LLM on again does that."""
    paths = paths or P
    firewall = False
    with locked(paths):
        cfg = load_config(paths)
        if not cfg.get("enabled"):
            if paths.env.exists():
                _stop_server(paths)
            return publish(status(cfg, paths), paths)
        if cfg.get("phase") == "download":
            u = _unit_state(DOWNLOAD_UNIT)
            if u == "failed":
                cfg.update(phase="failed", error=f"{DOWNLOAD_UNIT} failed: see journalctl -u {DOWNLOAD_UNIT}")
                save_config(cfg, paths)
                firewall = True
            elif u not in ("active", "activating"):
                _run(["systemctl", "start", "--no-block", DOWNLOAD_UNIT], timeout=60, check=False)
        elif cfg.get("phase") == "ready" or model_ready(cfg, paths):
            if not model_ready(cfg, paths):
                pass                                    # status() reports it; the admin turns it off and on
            elif mem_total(paths) < MIN_RAM:
                if paths.env.exists():
                    _stop_server(paths)
            else:
                _start_server(cfg, paths)
                save_config(cfg, paths)
    if firewall:
        _firewall()
    return publish(status(cfg, paths), paths)


# --------------------------------------------------------------------------- the download unit

def sha256_of(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def curl_command(part: Path, url: str = MODEL.url) -> list[str]:
    """Resumable (-C -), https only (also after redirects), giving up on a stalled connection."""
    return ["curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https", "--retry", "5", "--retry-delay", "15",
            "--connect-timeout", "30", "--speed-limit", "10240", "--speed-time", "300", "-C", "-", "-o", str(part), url]


def download(paths: Paths | None = None, fetch=None, poll: float = 10.0, model: Model = MODEL) -> int:
    """Fetch the model to <file>.part (resuming a partial one), check its size and sha256, then rename it into
    place. Expected failures (network, checksum, space) are recorded in the settings and the unit still exits
    0; the page shows them and turning the LLM on again retries."""
    paths = paths or P
    cfg = load_config(paths)
    if not (cfg.get("enabled") and cfg.get("phase") == "download"):
        log("built-in LLM: nothing to download")
        return 0
    old_term = signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))     # turned off meanwhile: clean up below
    error = None
    state = "download-failed"
    proc = None
    try:
        paths.models.mkdir(parents=True, exist_ok=True)
        os.chmod(paths.models, 0o755)
        if _size(paths.part) > model.size:
            paths.part.unlink()
        if paths.model.exists() and not paths.part.exists():
            paths.model.replace(paths.part)          # there but not verified (settings lost): check it again
        need = model.size - _size(paths.part) + DISK_MARGIN
        if free_disk(paths.models) < need:
            raise LocalLlmError(f"not enough free space: {free_disk(paths.models) / GiB:.1f} GiB free, "
                                f"{need / GiB:.1f} GiB needed")
        if _size(paths.part) < model.size:
            proc = (fetch or (lambda part: subprocess.Popen(curl_command(part, model.url), stdin=subprocess.DEVNULL,
                                                            stderr=subprocess.PIPE, text=True)))(paths.part)
            while proc.poll() is None:
                publish(status(load_config(paths), paths, state="downloading"), paths)
                time.sleep(poll)
            if proc.returncode:
                err = (proc.stderr.read() if getattr(proc, "stderr", None) else "") or ""
                raise LocalLlmError(f"download failed (curl exit {proc.returncode}): {err.strip()[-400:]}; "
                                    "turn the built-in LLM on again to resume it")
        if _size(paths.part) != model.size:
            raise LocalLlmError(f"the download has {_size(paths.part)} bytes, not {model.size}; "
                                "turn the built-in LLM on again to resume it")
        publish(status(load_config(paths), paths, state="verifying"), paths)
        got = sha256_of(paths.part)
        if got != model.sha256:
            paths.part.unlink(missing_ok=True)
            raise LocalLlmError(f"checksum mismatch (sha256 {got}, expected {model.sha256}): the file was deleted; "
                                "turn the built-in LLM on again to download it again")
        os.chmod(paths.part, 0o644)
        paths.part.replace(paths.model)
        state = "ready"
    except LocalLlmError as ex:
        error = str(ex)
    except OSError as ex:
        error = f"{type(ex).__name__}: {ex}"
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        with locked(paths):
            cfg = load_config(paths)
            if cfg.get("phase") == "download":         # not turned off meanwhile
                if state == "ready":
                    cfg.update(phase="ready", verified=_stamp(paths.model), error=None)
                    _history(cfg, {"by": "system", "name": "", "action": "download", "result": "model downloaded and verified"})
                else:
                    cfg.update(phase="failed", error=error or "the download was stopped")
                    _history(cfg, {"by": "system", "name": "", "action": "download", "result": cfg["error"]})
            elif state == "ready":
                cfg["verified"] = _stamp(paths.model)
            if cfg.get("enabled") and cfg.get("phase") == "ready" and model_ready(cfg, paths):
                try:
                    _start_server(cfg, paths)
                except Exception as ex:            # noqa: BLE001 - reconcile tries again in 5 minutes
                    log(f"built-in LLM: server not started: {ex}")
            save_config(cfg, paths)
        try:
            _firewall()                            # huggingface.co and hf.co are no longer allowed
        except Exception as ex:                    # noqa: BLE001
            log(f"built-in LLM: firewall not rebuilt: {ex}")
        publish(status(cfg, paths), paths)
        signal.signal(signal.SIGTERM, old_term)
    if error:
        log(f"built-in LLM: {error}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else ""
    if cmd == "download":
        return download()
    if cmd == "reconcile":
        st = reconcile()
        log(f"built-in LLM: {st['state']}{(' - ' + st['message']) if st['message'] else ''}")
        return 0
    if cmd == "status":
        print(json.dumps(status(), indent=1))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
