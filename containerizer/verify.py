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
from .generate import (CONTAINER_PORT, DOCKERIGNORE, _writable_abs, buildable, dockerfile_dotnet, dockerfile_spa,
                       images, k8s_name, make_plan, merge_plan)
from .rules import RULES_DIR, load_rules

LEARNED = RULES_DIR / "learned"
WORK = Path(os.environ.get("CONTAINERIZER_WORK", Path(__file__).resolve().parent.parent / ".work"))
MAX_ATTEMPTS = 5


def load_failures() -> list[dict]:
    out = []
    for f in [RULES_DIR / "50-failures.yaml", LEARNED / "failures.yaml"]:
        if f.exists():
            out += (yaml.safe_load(f.read_text()) or {}).get("failures", []) or []
    # learned failure rules first: they are more specific
    return sorted(out, key=lambda r: 0 if r.get("source") in ("learned", "ai") else 1)


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


def _run(cmd: list[str], timeout: int, cwd: Path | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           timeout=timeout, errors="replace")
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


def _build_env_args() -> list[str]:
    """Pass the host's proxy and extra CA bundle to builds (corporate proxies)."""
    args: list[str] = []
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        args += ["--build-arg", f"HTTPS_PROXY={proxy}", "--build-arg", f"https_proxy={proxy}"]
        if "127.0.0.1" in proxy or "localhost" in proxy:
            args += ["--network", "host"]
    ca = os.environ.get("CONTAINERIZER_CA_BUNDLE") or next(
        (p for p in ("/root/.ccr/ca-bundle.crt",) if Path(p).exists()), None)
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


def build(a: AppAssessment, c: Component, plan: dict, workdir: Path, timeout: int) -> tuple[bool, str, str]:
    workdir.mkdir(parents=True, exist_ok=True)
    df = dockerfile_spa(plan, c.facts) if c.role == "spa" else dockerfile_dotnet(plan)
    _ensure_images(df)
    (workdir / "Dockerfile").write_text(df)
    (workdir / "Dockerfile.dockerignore").write_text(DOCKERIGNORE)
    tag = f"containerizer/{k8s_name(a.name)}-{k8s_name(c.name)}:verify"
    rc, log = _run(["docker", "build", "--progress=plain", *_build_env_args(), "-f", str(workdir / "Dockerfile"),
                    "-t", tag, str(a.repo.root)], timeout)
    (workdir / "build.log").write_text(log)
    return rc == 0, log, tag


def run(c: Component, plan: dict, tag: str, workdir: Path, env_override: dict | None = None,
        wait: int = 45) -> tuple[str, str, dict]:
    """Returns (status, log, details). status: ok | exited | unhealthy"""
    name = f"cz-verify-{os.getpid()}-{int(time.time())}"
    uid = images()["dotnet"]["app_uid"] if c.role != "spa" else 101
    cmd = ["docker", "run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--memory", "768m", "--add-host", "sql01.corp.local:203.0.113.1"]
    # writable folders are host directories during verification, so log files the app writes
    # (apps that log only to files print nothing to stdout) can be read for the diagnosis
    import shutil
    fsroot = workdir / "fs"
    shutil.rmtree(fsroot, ignore_errors=True)
    for w in sorted({_writable_abs(w) for w in plan["add_writable"]}):
        host = fsroot / k8s_name(w)
        host.mkdir(parents=True, exist_ok=True)
        host.chmod(0o777)
        cmd += ["-v", f"{host.resolve()}:{w}:rw"]
    if c.role == "spa":
        cmd += ["--tmpfs", "/tmp:rw,mode=1777", "--tmpfs", "/var/cache/nginx:rw,mode=1777", "--tmpfs", "/var/run:rw,mode=1777"]
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
    cmd.append(tag)
    rc, out = _run(cmd, 60)
    if rc != 0:
        return "exited", out, {}
    details: dict = {}
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
                if status == "ok":
                    break
            elif time.time() > deadline - wait + 20:
                status = "ok"           # worker stayed up for 20 s
                details["note"] = "worker running"
                break
    finally:
        _, log = _run(["docker", "logs", name], 30)
        _run(["docker", "rm", "-f", name], 30)
        for f in sorted(fsroot.rglob("*")) if fsroot.exists() else []:
            if f.is_file() and re.search(r"(log|txt)$", f.name, re.I) and f.stat().st_size:
                details.setdefault("log_files", []).append(f.name)
                log += f"\n--- {f.name} ---\n" + f.read_text(errors="replace")[-20000:]
    (workdir / "run.log").write_text(log)
    return status, log, details


def verify_component(a: AppAssessment, c: Component, rules, learn: bool = False, ai: bool = False,
                     model: str | None = None, timeout: int = 900) -> dict:
    failures = load_failures()
    plan = make_plan(a, c, rules)
    workdir = WORK / "verify" / a.name / k8s_name(c.name)
    history = []
    result = {"app": a.name, "component": c.name, "status": "failed", "attempts": history,
              "predicted": c.verdict, "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    env_override: dict = {}
    learned_patches: list[tuple[dict, dict, dict]] = []
    t0 = time.time()
    for attempt in range(1, MAX_ATTEMPTS + 1):
        ok, log, tag = build(a, c, plan, workdir, timeout)
        stage, details = "build", {}
        if ok:
            stage = "run"
            status, log, details = run(c, plan, tag, workdir, env_override)
            if status == "ok":
                history.append({"attempt": attempt, "stage": "run", "status": "ok", **details})
                result["status"] = "ok"
                break
        tail = "\n".join(log.splitlines()[-200:])
        # run logs: exception messages, not the stack frames under them, say what went wrong
        msgs = "\n".join(l for l in log.splitlines() if not l.lstrip().startswith("at ")) if stage == "run" else log
        d = diagnose(msgs[-60000:], stage, failures)
        if d is None and ai:
            from .ai import diagnose_failure
            d = diagnose_failure(a, c, plan, stage, tail, model=model)
        if d is None:
            history.append({"attempt": attempt, "stage": stage, "status": "unexplained", **details,
                            "log_tail": tail[-1500:]})
            result["status"] = f"{stage}-failed"
            break
        fr, caps = d
        caps.setdefault("tfm", plan.get("tfm") or "")
        entry = {"attempt": attempt, "stage": stage, "rule": fr["id"], "outcome": fr["outcome"],
                 "diagnosis": _fmt(fr.get("diagnosis", ""), caps)}
        history.append(entry)
        if fr["outcome"] == "retry":
            patch = _fmt(fr.get("fix", {}), caps)
            before = json.dumps(plan, sort_keys=True)
            merge_plan(plan, patch)
            if json.dumps(plan, sort_keys=True) == before:
                entry["note"] = "fix already applied; giving up"
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
        result["finding"] = _fmt(fr.get("finding", {}), caps)
        if stage == "run" and not env_override and c.project.kind_hint == "dotnet":
            # still find out whether the rest of the app works (Development often swaps in simulators)
            env_override = {"ASPNETCORE_ENVIRONMENT": "Development", "DOTNET_ENVIRONMENT": "Development"}
            entry["note"] = "finding recorded; smoke-testing the rest in Development mode"
            continue
        break
    if result.get("finding"):
        result["smoke"] = result["status"]
        result["status"] = "finding"
    result["plan"] = plan
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


def _save(path: Path, d: dict, header: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + yaml.safe_dump(d, sort_keys=False, allow_unicode=True, width=120))


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
        if not when:
            when = {"name": f"^{re.escape(c.project.name)}$"}
        rid = f"learned-{fr['id']}-{k8s_name(c.project.name)}" if "name" in when else f"learned-{fr['id']}"
        if rid in ids:
            continue
        rule = {"id": rid, "phase": "plan", "source": fr.get("source", "learned"), "when": when, "plan": patch,
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
                       "why": result["attempts"][-1].get("diagnosis", ""),
                       "fix": "See the verification log; fix and re-run `containerizer verify`.",
                       "when": {"name": f"^{re.escape(c.project.name)}$"},
                       "learned_from": f"{a.name}/{c.name}",
                       "learned_at": datetime.now(timezone.utc).date().isoformat()})
    _save(path, d, "# Findings observed at runtime by `containerizer verify --learn`.\n")


def verify_app(a: AppAssessment, out: Path | None = None, learn: bool = False, only: str | None = None,
               ai: bool = False, model: str | None = None, timeout: int = 900) -> list[dict]:
    rules = load_rules()
    results = []
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
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{a.name}.verify.json").write_text(json.dumps(results, indent=2, default=str))
    return results
