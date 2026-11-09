"""Build-and-run verification with a self-learning loop.

For each buildable component:
  1. generate a Dockerfile from the build plan and `docker build` it with the
     application folder as context;
  2. run it hardened (read-only root FS, non-root, no capabilities, tmpfs for
     the writable folders) and probe it over HTTP;
  3. match failures against rules/50-failures.yaml (+ learned ones). A `retry`
     outcome patches the plan and loops; `external` means the container works
     but lacks the real environment; `platform`/`code` produce findings;
  4. when nothing matches and --ai is on, ask Claude for a diagnosis + patch;
  5. with --learn, persist what worked: plan patches become plan rules,
     AI diagnoses become failure rules, and packages of components that ran
     become known Linux-safe packages.
"""
from __future__ import annotations

import json
import os
import secrets
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .assess import AppAssessment, Component
from .generate import (CONTAINER_PORT, DOCKERIGNORE, add_reason, _writable_abs, hides_app, writable_dirs, buildable, dockerfile_dotnet, dockerfile_for, dockerfile_spa,
                       images, k8s_name, app_ns, make_plan, merge_plan)
from .rules import RULES_DIR, load_rules
from .paths import work_dir

LEARNED = RULES_DIR / "learned"
WORK = work_dir()  # CONTAINERIZER_WORK (the appliance's services set it); never the read-only code
MAX_ATTEMPTS = 5


def load_failures() -> list[dict]:
    out = []
    from .rules import reviewed_dir
    rd = reviewed_dir()     # failure rules approved in the rule review, from your internal rules repository
    for f in [RULES_DIR / "50-failures.yaml", *([rd / "55-reviewed-failures.yaml"] if rd else []), LEARNED / "failures.yaml"]:
        if f.exists():
            out += (yaml.safe_load(f.read_text()) or {}).get("failures", []) or []
    # learned failure rules first: they are more specific
    return sorted(out, key=lambda r: 0 if r.get("source") in ("learned", "ai") else 1)


def _messages(log: str) -> str:
    """Run logs: exception messages say what went wrong, not the stack frames under them. Only the
    frame that threw is kept, as "thrown at ...", because it names the library that failed."""
    out, prev_frame = [], True
    for line in log.splitlines():
        frame = line.lstrip().startswith("at ")
        if not frame:
            out.append(line)
        elif not prev_frame:
            out.append("   thrown " + line.lstrip())
        prev_frame = frame
    return "\n".join(out)


def diagnose(log: str, stage: str, failures: list[dict]) -> tuple[dict, dict] | None:
    for fr in failures:
        if fr.get("stage", stage) != stage:
            continue
        m = re.search(fr["match"], log, re.I | re.M)
        if m:
            caps = {re.sub(r"\d+$", "", k): v for k, v in m.groupdict().items() if v}
            if "path" in caps:
                p = caps["path"]
                caps["dir"] = p if not re.search(r"\.\w{1,5}$", p) else str(Path(p).parent)
            return fr, caps
    return None


def _fmt(obj, caps: dict):
    if isinstance(obj, str):
        try:
            return obj.format(**caps)
        except (KeyError, IndexError, ValueError):
            return obj
    if isinstance(obj, list):
        return [_fmt(x, caps) for x in obj]
    if isinstance(obj, dict):
        return {k: _fmt(v, caps) for k, v in obj.items()}
    return obj


class DockerUnavailable(RuntimeError):
    """The Docker daemon is not reachable: no verification result would mean anything."""


DOCKER_DOWN = "Cannot connect to the Docker daemon"


def readable_context(root: Path) -> None:
    """Make a build context readable for everyone (files a+r, folders a+rx). The appliance's services run with
    UMask=0077, so their clones are 0600; `docker build` keeps the modes, and an image's root-owned 0600 files
    (appsettings.json copied by dotnet publish) cannot be read by the app's own non-root user: "Access to the path
    '/app/appsettings.json' is denied". The clones are under 0700 work folders, so nobody else on the host sees
    more. Symbolic links and other users' files are left alone."""
    import stat
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name, bits in [(d, 0o555) for d in dirnames] + [(f, 0o444) for f in filenames] + [(".", 0o555)]:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
                if stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & bits) == bits:
                    continue
                os.chmod(path, stat.S_IMODE(st.st_mode) | bits)
            except OSError:
                continue


def _run(cmd: list[str], timeout: int, cwd: Path | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           timeout=timeout, errors="replace")
        if cmd[0] == "docker" and p.returncode and DOCKER_DOWN in p.stdout:
            # never record an infrastructure outage as a build failure of the app
            raise DockerUnavailable(f"{DOCKER_DOWN}; start it and run verify again")
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") + "\n[timeout]"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(url: str, timeout: float = 3.0) -> int | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def host_network_allowed() -> bool:
    """Builds and scanner containers never get the host's network namespace (it would let a repository's `RUN`
    step reach the results database, the k3s API and every service on the host's loopback), unless a developer
    opts in with CONTAINERIZER_BUILD_HOST_NETWORK=1 for a proxy that listens only on 127.0.0.1. The appliance's
    worker forces it off (cz-worker)."""
    return os.environ.get("CONTAINERIZER_BUILD_HOST_NETWORK", "").strip().lower() in ("1", "true", "yes")


def _build_env_args() -> list[str]:
    """Pass the host's proxy and extra CA bundle to builds (corporate proxies). With registered package feeds the
    builds' HTTPS goes through the feed proxy (feedproxy.py), which adds the feeds' credentials and passes the rest on
    (through the corporate proxy, if any); its CA comes in the `ca` bundle."""
    from . import feedproxy
    args: list[str] = []
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    no = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    feeds = feedproxy.build_proxy_env(no)
    build_proxy = feeds["proxy"] if feeds else proxy
    if build_proxy:
        args += ["--build-arg", f"HTTPS_PROXY={build_proxy}", "--build-arg", f"https_proxy={build_proxy}"]
    if feeds:
        no = feeds["no_proxy"]
    if (build_proxy or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")) and no:
        args += ["--build-arg", f"NO_PROXY={no}", "--build-arg", f"no_proxy={no}"]
    http = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if http:        # apt (Debian/Ubuntu package sources) uses plain HTTP
        args += ["--build-arg", f"HTTP_PROXY={http}", "--build-arg", f"http_proxy={http}"]
        local = proxy or http
        if ("127.0.0.1" in local or "localhost" in local) and host_network_allowed():
            args += ["--network", "host"]
    ca = (feeds or {}).get("ca") or os.environ.get("CONTAINERIZER_CA_BUNDLE") or next(
        (p for p in ("/root/.ccr/ca-bundle.crt",) if os.path.isfile(p)), None)
    if ca:
        args += ["--secret", f"id=ca,src={ca}"]
    return args


MIRROR = os.environ.get("CONTAINERIZER_REGISTRY_MIRROR", "mirror.gcr.io")


def _ensure_images(dockerfile: str) -> None:
    """Pre-pull Docker Hub base images; when Docker Hub rate-limits (429), pull them through a
    mirror and tag them with the canonical name, so the generated Dockerfile stays unchanged."""
    if not MIRROR:
        return
    refs = set(re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", dockerfile, re.M))
    refs |= set(re.findall(r"COPY\s+--from=([\w./:-]+:[\w.-]+)", dockerfile))
    for ref in refs:
        first = ref.split("/")[0]
        if "/" in ref and ("." in first or ":" in first or first == "localhost"):   # not Docker Hub
            continue
        if _run(["docker", "image", "inspect", ref], 30)[0] == 0:
            continue
        if _run(["docker", "pull", "-q", ref], 300)[0] == 0:
            continue
        src = f"{MIRROR}/{ref if '/' in ref else 'library/' + ref}"
        if _run(["docker", "pull", "-q", src], 300)[0] == 0:
            _run(["docker", "tag", src, ref], 30)


def _free_disk(min_gb: float = 15.0) -> None:
    """Drop old BuildKit cache when the Docker disk runs low (keeps the recent, reusable layers)."""
    import shutil
    try:
        root = _run(["docker", "info", "-f", "{{.DockerRootDir}}"], 30)[1].strip() or "/var/lib/docker"
        if shutil.disk_usage(root).free / 1e9 < min_gb:
            _run(["docker", "builder", "prune", "-af", "--filter", "until=1h"], 600)
    except OSError:
        pass


# a name `docker run --add-host` may map: DNS labels, the last starting with a letter (never an address)
HOST_NAME = re.compile(r"(?=[a-z0-9.-]{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                       r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _mappable(hits, into: dict | None = None) -> dict:
    """{host: [ports]} of the (host, port) pairs that are host names and not well-known public services."""
    from .connectivity import NOISE_HOSTS, _placeholder
    from .harden import security
    public = security()["network"].get("public_hosts") or "$^"
    out = dict(into or {})
    for host, port in hits:
        host = str(host).lower().rstrip(".")
        if not HOST_NAME.fullmatch(host) or NOISE_HOSTS.match(host) or _placeholder(host) or re.search(public, host, re.I):
            continue
        ports = out[host] = list(out.get(host, []))
        if port and port not in ports:
            ports.append(port)
    return out


def hosts_to_map(a: AppAssessment, c: Component) -> dict:
    """{host: [ports]}: the names the component's configuration and code connect to (connection strings and URLs,
    as the connectivity model reads them), resolved to 127.0.0.1 in the verification run, so a missing service
    fails fast with "connection refused" (an external service) instead of a DNS lookup that hangs."""
    if c.role == "spa":
        return {}
    from .connectivity import _scan_destinations
    try:
        found = _scan_destinations(a.repo, c, any_port=True)
    except Exception:  # noqa: BLE001 - unreadable configuration: nothing to map
        return {}
    return _mappable((d["host"], d["port"]) for d in found)


def build(a: AppAssessment, c: Component, plan: dict, workdir: Path, timeout: int) -> tuple[bool, str, str]:
    workdir.mkdir(parents=True, exist_ok=True)
    df = dockerfile_for(plan, c)
    _ensure_images(df)
    (workdir / "Dockerfile").write_text(df)
    from .generate import dockerignore
    (workdir / "Dockerfile.dockerignore").write_text(dockerignore(a.repo))
    tag = f"containerizer/{app_ns(a.name)}-{k8s_name(c.name)}:verify"
    readable_context(a.repo.root)
    rc, log = _run(["docker", "build", "--progress=plain", *_build_env_args(), "-f", str(workdir / "Dockerfile"),
                    "-t", tag, str(a.repo.root)], timeout)
    (workdir / "build.log").write_text(log)
    return rc == 0, log, tag


RUN_MEMORY_MIB = 768           # --memory of the verification run
PEAK_ROUNDS = 2                # probe-and-sample rounds after the app first answers
_SIZE = {"b": 1, "kib": 2**10, "mib": 2**20, "gib": 2**30, "kb": 1e3, "mb": 1e6, "gb": 1e9}


def _sample(name: str) -> tuple[float, float] | None:
    """(memory in MiB, CPU %) of a running container from `docker stats --no-stream`, None when unreadable."""
    rc, out = _run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}|{{.CPUPerc}}", name], 20)
    m = re.search(r"([\d.]+)\s*([KMG]i?B|B)\s*/[^|]*\|\s*([\d.]+)%", out or "", re.I)
    if rc != 0 or not m:
        return None
    return float(m.group(1)) * _SIZE[m.group(2).lower()] / 2**20, float(m.group(3))


def _track(usage: dict, name: str) -> None:
    """Keep the peak memory and CPU of the container seen so far (generate.measured_memory sizes from it)."""
    s = _sample(name)
    if s is None:
        return
    usage["samples"] = usage.get("samples", 0) + 1
    usage["memory_peak_mib"] = round(max(usage.get("memory_peak_mib", 0.0), s[0]), 1)
    usage["cpu_peak_percent"] = round(max(usage.get("cpu_peak_percent", 0.0), s[1]), 1)
    usage["run_limit_mib"] = RUN_MEMORY_MIB


def run(c: Component, plan: dict, tag: str, workdir: Path, env_override: dict | None = None,
        wait: int = 90, hosts: dict | None = None) -> tuple[str, str, dict]:
    """Returns (status, log, details). status: ok | exited | unhealthy. `hosts` (hosts_to_map) resolve to
    127.0.0.1; details["mapped_hosts"] names them."""
    name = f"cz-verify-{os.getpid()}-{int(time.time())}-{secrets.token_hex(3)}"   # unique: jobs run at once
    uid = 101 if c.role == "spa" else plan.get("uid") or images()["dotnet"]["app_uid"]
    cmd = ["docker", "run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--memory", f"{RUN_MEMORY_MIB}m"]
    # writable folders are host directories during verification, so log files the app writes
    # (apps that log only to files print nothing to stdout) can be read for the diagnosis
    import shutil
    fsroot = workdir / "fs"
    shutil.rmtree(fsroot, ignore_errors=True)
    for w in writable_dirs(plan):
        host = fsroot / k8s_name(w)
        host.mkdir(parents=True, exist_ok=True)
        host.chmod(0o777)
        cmd += ["-v", f"{host.resolve()}:{w}:rw"]
    if c.role == "spa":
        for d in ("/tmp", "/var/cache/nginx", "/var/run"):
            if not any(x.endswith(f":{d}:rw") for x in cmd):
                cmd += ["--tmpfs", f"{d}:rw,mode=1777"]
    hp = None
    if plan.get("port"):
        hp = _free_port()
        cmd += ["-p", f"127.0.0.1:{hp}:{plan['port']}"]
    for k, v in (env_override or {}).items():
        cmd += ["-e", f"{k}={v}"]
    if (env_override or {}).get("ASPNETCORE_ENVIRONMENT") == "Development" and c.role != "spa":
        # smoke mode only: the image excludes development settings, mount them read-only for the test run
        dev = c.project.dir / "appsettings.Development.json"
        if dev.exists():
            cmd += ["-v", f"{dev.resolve()}:/app/appsettings.Development.json:ro"]
            from .connectivity import line_hosts      # a stray production host there fails fast too
            hosts = _mappable(((h, p) for line in dev.read_text(errors="replace").splitlines()
                               for h, p, _ in line_hosts(line)), hosts)
            # dev settings often point at ../../App_Data etc.; give those folders a scratch tmpfs
            from .facts import _flatten, _load_json
            for key, val in _flatten(_load_json(dev)):
                if isinstance(val, str) and key.startswith("ConnectionStrings:"):
                    # SQLite resolves relative paths differently from .NET; make them absolute
                    m = re.search(r"(Data Source|Filename)\s*=\s*([^;/:|][^;]*\.(db|sqlite3?|litedb))", val, re.I)
                    if m:
                        absp = os.path.normpath(os.path.join("/app", m.group(2).replace("\\", "/")))
                        cmd += ["-e", key.replace(":", "__") + "=" + val.replace(m.group(2), absp)]
                        folder = os.path.dirname(absp)
                        if not any(f":{folder}:" in x or x.startswith(folder + ":") for x in cmd):
                            cmd += ["--tmpfs", f"{folder}:rw,exec,uid={uid},gid={uid},mode=1777"]
                if isinstance(val, str):
                    for m in re.finditer(r"((?:\.\./)+\.?[\w\-]+)(/[\w\-./]+\.\w{1,5})?", val.replace("\\", "/")):
                        target = os.path.normpath(os.path.join("/app", m.group(1)))
                        if any(target in x for x in cmd):
                            continue
                        src = (c.project.dir / m.group(1)).resolve()
                        if m.group(2) and (c.project.dir / (m.group(1) + m.group(2))).exists():
                            cmd += ["-v", f"{src}:{target}:ro"]       # sample input files from the repo
                        else:
                            cmd += ["--tmpfs", f"{target}:rw,exec,uid={uid},gid={uid},mode=1777"]
    mapped = sorted(h for h in (hosts or {}) if HOST_NAME.fullmatch(h))
    for h in mapped:
        cmd += ["--add-host", f"{h}:127.0.0.1"]
    cmd.append(tag)
    if c.role == "console":
        first = c.facts.get("oneshot_arg") or (c.facts.get("commands") or [None])[0]
        if first:
            cmd.append(first)
    rc, out = _run(cmd, 60)
    if rc != 0:
        (workdir / "run.log").write_text(out)
        return "exited", out, {"mapped_hosts": mapped} if mapped else {}
    details: dict = {"mapped_hosts": mapped} if mapped else {}
    usage: dict = {}
    status = "unhealthy"
    deadline = time.time() + wait
    try:
        while time.time() < deadline:
            time.sleep(3)
            _, st = _run(["docker", "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", name], 20)
            running = st.strip().startswith("true")
            if not running:
                status = "exited"
                details["exit_code"] = st.strip().split()[-1] if st.strip() else "?"
                break
            if hp:
                for path in [plan.get("health"), "/", "/swagger/index.html"]:
                    if not path:
                        continue
                    code = _http(f"http://127.0.0.1:{hp}{path}")
                    if code is not None:
                        details.setdefault("http", {})[path] = code
                        if code < 500:
                            status = "ok"
                            break
                _track(usage, name)     # after the probes were answered: what serving them took
                if status == "ok":
                    for _ in range(PEAK_ROUNDS):    # a few more requests: one sample right at start-up is thin
                        for path in details.get("http") or {}:
                            _http(f"http://127.0.0.1:{hp}{path}")
                        _track(usage, name)
                    break
            else:
                _track(usage, name)
                if time.time() > deadline - wait + 20:
                    status = "ok"           # worker stayed up for 20 s
                    details["note"] = "worker running"
                    break
    finally:
        if usage:
            details["usage"] = usage
        _, log = _run(["docker", "logs", name], 30)
        _run(["docker", "rm", "-f", name], 30)
        for f in sorted(fsroot.rglob("*")) if fsroot.exists() else []:
            if f.is_file() and re.search(r"(log|txt)$", f.name, re.I) and f.stat().st_size:
                details.setdefault("log_files", []).append(f.name)
                log += f"\n--- {f.name} ---\n" + f.read_text(errors="replace")[-20000:]
    (workdir / "run.log").write_text(log)
    return status, log, details


def verify_component(a: AppAssessment, c: Component, rules, learn: bool = False, ai: bool = False,
                     model: str | None = None, timeout: int = 900, work: Path | None = None) -> dict:
    """Build and run one component; `work` replaces WORK (the refactoring runner's scratch space)."""
    failures = load_failures()
    plan = make_plan(a, c, rules)
    workdir = (work or WORK) / "verify" / a.name / k8s_name(c.name)
    history = []
    result = {"app": a.name, "component": c.name, "status": "failed", "attempts": history,
              "predicted": c.verdict, "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    env_override: dict = {}
    learned_patches: list[tuple[dict, dict, dict]] = []
    hosts = hosts_to_map(a, c)
    pruned = False
    t0 = time.time()
    for attempt in range(1, MAX_ATTEMPTS + 1):
        ok, log, tag = build(a, c, plan, workdir, timeout)
        stage, details = "build", {}
        if ok:
            stage = "run"
            status, log, details = run(c, plan, tag, workdir, env_override, hosts=hosts)
            if status == "exited" and c.role == "console" and details.get("exit_code") == "0":
                status = "ok"                    # a batch job that ran to completion
                details["note"] = "job completed"
            if status == "ok":
                history.append({"attempt": attempt, "stage": "run", "status": "ok", **details})
                result["status"] = "ok"
                if details.get("usage"):
                    result["usage"] = details["usage"]   # sizes the memory requests and limits (generate.py)
                if env_override:
                    result["mode"] = "smoke"     # proven without the production services
                break
        msgs = _messages(log) if stage == "run" else log
        # deep stack traces would push the exception message itself out of a raw tail
        tail = "\n".join(msgs.splitlines()[-200:])
        d = diagnose(msgs[-60000:], stage, failures)
        if d is None and ai:
            from .ai import diagnose_failure
            d = diagnose_failure(a, c, plan, stage, tail, model=model)
        if d is None and stage == "run" and status == "unhealthy" and not details.get("http") \
                and not env_override and c.project.kind_hint == "dotnet":
            # never answered HTTP and logged nothing useful: most likely still waiting on its database
            history.append({"attempt": attempt, "stage": stage, "status": "no-response", **details,
                            "note": "no HTTP answer; retrying in Development mode without external services"})
            env_override = {"ASPNETCORE_ENVIRONMENT": "Development", "DOTNET_ENVIRONMENT": "Development"}
            continue
        if d is None:
            history.append({"attempt": attempt, "stage": stage, "status": "unexplained", **details,
                            "log_tail": tail[-1500:]})
            result["status"] = f"{stage}-failed"
            break
        fr, caps = d
        caps.setdefault("tfm", plan.get("tfm") or "")
        entry = {"attempt": attempt, "stage": stage, "rule": fr["id"], "outcome": fr["outcome"],
                 "diagnosis": _fmt(fr.get("diagnosis", ""), caps), **{k: v for k, v in details.items() if k in ("exit_code", "mapped_hosts")},
                 "log_tail": tail[-1500:]}                    # evidence for the rule review of what is learned
        history.append(entry)
        if fr["outcome"] == "retry":
            patch = _fmt(fr.get("fix", {}), caps)
            if patch.pop("prune_cache", None):
                if pruned:
                    result["status"] = f"{stage}-failed"
                    entry["note"] = "disk still full after pruning; free space on the Docker host"
                    break
                _free_disk(min_gb=float("inf"))
                pruned = True
                continue
            before = json.dumps(plan, sort_keys=True)
            merge_plan(plan, patch)
            if json.dumps(plan, sort_keys=True) != before:
                add_reason(plan, fr["id"], _fmt(fr.get("diagnosis", ""), caps), fr.get("refs"))
            if json.dumps(plan, sort_keys=True) == before:
                inside = [w for w in patch.get("add_writable") or [] if hides_app(w)]
                entry["note"] = (f"the app writes into its own folder ({', '.join(inside)}): a writable mount there "
                                 "would hide the app itself; it must write elsewhere (a setting, /tmp or a volume)"
                                 if inside else "fix already applied; giving up")
                result["status"] = f"{stage}-failed"
                break
            learned_patches.append((fr, caps, patch))
            continue
        if fr["outcome"] == "external":
            if stage == "run" and not env_override.get("ASPNETCORE_ENVIRONMENT") and c.project.kind_hint == "dotnet":
                # dependency-free smoke mode: many apps fall back to SQLite/simulators in Development
                env_override = {"ASPNETCORE_ENVIRONMENT": "Development", "DOTNET_ENVIRONMENT": "Development"}
                entry["note"] = "retrying in Development mode to smoke-test without external services"
                continue
            result["status"] = "ok-external"
            break
        # platform / code findings
        finding = _fmt(fr.get("finding", {}), caps)
        finding.setdefault("why", _fmt(fr.get("diagnosis", ""), caps))
        if fr.get("refs"):
            finding.setdefault("refs", list(fr["refs"]))
        if env_override and not result.get("finding") and finding.get("severity") == "config":
            # the production run only lacked external services; a config gap of the smoke setup
            # (e.g. a local database file) says nothing about the production container
            entry["note"] = "smoke-mode configuration gap; production run was blocked only by external services"
            result["status"] = "ok-external"
            break
        result["finding"] = finding
        if stage == "run" and not env_override and c.project.kind_hint == "dotnet":
            # still find out whether the rest of the app works (Development often swaps in simulators)
            env_override = {"ASPNETCORE_ENVIRONMENT": "Development", "DOTNET_ENVIRONMENT": "Development"}
            entry["note"] = "finding recorded; smoke-testing the rest in Development mode"
            continue
        break
    if hosts and (result.get("mode") == "smoke" or result["status"] == "ok-external" or result.get("finding")):
        # what the real environment must provide: these names resolved to loopback in the sandbox
        result["needs"] = [f"{h}:{p}" for h, ps in hosts.items() for p in ps] + [h for h, ps in hosts.items() if not ps]
    if result.get("finding"):
        result["smoke"] = result["status"]
        result["status"] = "finding"
    result["plan"] = plan
    if not os.environ.get("CONTAINERIZER_KEEP_IMAGES"):
        # verification images are throw-away; large portfolios would otherwise fill the disk
        _run(["docker", "rmi", "-f", f"containerizer/{app_ns(a.name)}-{k8s_name(c.name)}:verify"], 120)
    result["seconds"] = round(time.time() - t0)
    if learn and result["status"] in ("ok", "ok-external"):
        persist_learning(a, c, plan, learned_patches)
    if learn and result.get("finding"):
        persist_finding(a, c, result)
    return result


# --------------------------------------------------------------------------- learning

def _load(path: Path, key: str) -> dict:
    if path.exists():
        d = yaml.safe_load(path.read_text()) or {}
    else:
        d = {}
    d.setdefault(key, [])
    return d


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):      # learned files are read by people: no &id001 anchors
        return True


def _save(path: Path, d: dict, header: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + yaml.dump(d, Dumper=_NoAliases, sort_keys=False, allow_unicode=True, width=120))


def persist_learning(a: AppAssessment, c: Component, plan: dict, patches) -> None:
    from .confidence import reset_cache, unknowns

    # 1) plan patches that led to a working container become plan rules
    path = LEARNED / "plan.yaml"
    d = _load(path, "rules")
    ids = {r["id"] for r in d["rules"]}
    for fr, caps, patch in patches:
        learn = fr.get("learn")
        if learn is None:
            continue
        when = _fmt(learn.get("when") or {}, caps)
        if re.search(r"\{\w+\}", json.dumps(when)):
            when = {}                    # the log did not give what the general condition needs
        if not when:
            when = {"name": f"^{re.escape(c.project.name)}$"}
        # a general condition (a package, a TFM...) is its own rule, shared by every component it matches
        rid = f"learned-{fr['id']}-{k8s_name(c.project.name)}" if "name" in when else \
            f"learned-{fr['id']}" + (f"-{k8s_name('-'.join(str(v) for v in caps.values()))}" if caps else "")
        if rid in ids:
            continue
        rule = {"id": rid, "phase": "plan", "source": fr.get("source", "learned"), "when": when, "plan": patch,
                "why": " ".join(str(_fmt(fr.get("diagnosis", ""), caps)).split()),
                **({"refs": list(fr["refs"])} if fr.get("refs") else {}),
                "learned_from": f"{a.name}/{c.name}", "learned_at": datetime.now(timezone.utc).date().isoformat()}
        if learn.get("scope"):
            rule["scope"] = learn["scope"]
        d["rules"].append(rule)
        ids.add(rid)
    _save(path, d, "# Plan rules learned by `containerizer verify --learn`. Safe to edit or delete.\n")

    # 2) AI-made failure rules that worked are kept for next time
    for fr, _, _ in patches:
        if fr.get("source") == "ai" and fr.get("_new"):
            fpath = LEARNED / "failures.yaml"
            fd = _load(fpath, "failures")
            if fr["id"] not in {x["id"] for x in fd["failures"]}:
                fd["failures"].append({k: v for k, v in fr.items() if not k.startswith("_")})
                _save(fpath, fd, "# Failure rules learned during verification (source: ai = proposed by Claude, confirmed by a successful run).\n")

    # 3) packages of a component that ran are evidence of Linux safety
    unk = [u.split(":", 1)[1] for u in unknowns(c) if u.startswith("package:")]
    if unk:
        ppath = LEARNED / "packages.yaml"
        pd = yaml.safe_load(ppath.read_text()) if ppath.exists() else {}
        pd = pd or {}
        cur = pd.setdefault("linux_ok", [])
        for n in unk:
            rx = re.escape(n)
            if rx not in cur:
                cur.append(rx)
        _save(ppath, pd, "# Packages observed working in a verified Linux container.\n")
        reset_cache()


def persist_finding(a: AppAssessment, c: Component, result: dict) -> None:
    f = result["finding"]
    path = LEARNED / "findings.yaml"
    d = _load(path, "rules")
    rid = f"learned-runtime-{k8s_name(c.project.name)}-{len(d['rules']) + 1}"
    title = f.get("title", "Runtime failure")
    if any(r.get("title") == title and r.get("learned_from") == f"{a.name}/{c.name}" for r in d["rules"]):
        return
    d["rules"].append({"id": rid, "source": "learned", "severity": f.get("severity", "refactor"),
                       "category": "runtime-observed", "title": title,
                       "why": " ".join(str(f.get("why") or result["attempts"][-1].get("diagnosis", "")).split()),
                       "fix": f.get("fix") or "See the verification log; fix and re-run `containerizer verify`.",
                       **({"refs": f["refs"]} if f.get("refs") else {}),
                       "when": {"name": f"^{re.escape(c.project.name)}$"},
                       "learned_from": f"{a.name}/{c.name}",
                       "learned_at": datetime.now(timezone.utc).date().isoformat()})
    _save(path, d, "# Findings observed at runtime by `containerizer verify --learn`.\n")


def verify_app(a: AppAssessment, out: Path | None = None, learn: bool = False, only: str | None = None,
               ai: bool = False, model: str | None = None, timeout: int = 900) -> list[dict]:
    rules = load_rules()
    results = []
    _run(["docker", "info"], 60)              # fails fast with DockerUnavailable
    for c in a.components:
        if only and only not in (c.name, c.project.name):
            continue
        if not buildable(c):
            results.append({"app": a.name, "component": c.name, "status": "skipped",
                            "detail": f"verdict {c.verdict}, role {c.role}", "predicted": c.verdict})
            continue
        r = verify_component(a, c, rules, learn=learn, ai=ai, model=model, timeout=timeout)
        r["detail"] = "; ".join(f"{h.get('rule', h.get('status'))}" for h in r["attempts"])
        results.append(r)
    _free_disk()
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{a.name}.verify.json").write_text(json.dumps(results, indent=2, default=str))
    return results
