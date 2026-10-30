"""Security gate for generated images: vulnerability scans and base image bumps.

`gate_app` generates an application's containers, lints the Dockerfiles and
Kubernetes manifests (`harden.py`), scans the final base images (and, with
`build`, the built images) with Trivy or Grype, and fails when a vulnerability
at or above the configured severity has a fix (`rules/60-security.yaml`
`scan`). Vulnerabilities found in a built image but not in its base are
attributed to the application's own packages.

`update_images` lists registry tags for every base image line in
`rules/images.yaml`, picks the newest patch (or, where the bump policy allows,
the newest line), optionally scans the candidates, and writes the choice to
`rules/images.lock.yaml`, which the generator then uses.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from .harden import lifecycle, lint_dockerfile, lint_manifests, load_yaml_docs, security, summarize

LEVELS = ["UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {s: i for i, s in enumerate(LEVELS)}
WORK = Path(os.environ.get("CONTAINERIZER_WORK", Path(__file__).resolve().parent.parent / ".work"))


@dataclass
class Vuln:
    id: str
    package: str
    installed: str
    fixed: str
    severity: str
    type: str = ""
    title: str = ""
    origin: str = ""                # base | app (when a base scan is available)

    @property
    def key(self) -> tuple:
        return (self.id, self.package, self.installed)


@dataclass
class ScanResult:
    image: str
    scanner: str = ""
    vulns: list[Vuln] = field(default_factory=list)
    error: str = ""
    os: str = ""

    def counts(self, fixed_only: bool = False) -> dict:
        out = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        for v in self.vulns:
            if v.severity in out and (v.fixed or not fixed_only):
                out[v.severity] += 1
        return out


# --------------------------------------------------------------------------- scanners

def _run(cmd: list[str], timeout: int = 900) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _ca_bundle() -> str | None:
    return os.environ.get("CONTAINERIZER_CA_BUNDLE") or next(
        (p for p in ("/root/.ccr/ca-bundle.crt",) if Path(p).exists()), None)


def _docker_tool_args() -> list[str]:
    """Proxy, CA bundle and Docker socket for a scanner that runs as a container."""
    args = ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        args += ["-e", f"HTTPS_PROXY={proxy}", "-e", f"NO_PROXY={os.environ.get('NO_PROXY', '')}"]
        if "127.0.0.1" in proxy or "localhost" in proxy:
            args += ["--network", "host"]
    ca = _ca_bundle()
    if ca:
        args += ["-v", f"{ca}:/etc/ssl/certs/ca-certificates.crt:ro", "-e", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"]
    return args


def _tool_image(image: str) -> str | None:
    """Pull a scanner image, through the registry mirror when Docker Hub rate-limits."""
    from .verify import _ensure_images
    _ensure_images(f"FROM {image}\n")
    return image if _run(["docker", "image", "inspect", image], 30)[0] == 0 else None


def scanner_command(name: str = "auto") -> tuple[str, list[str]] | None:
    """(scanner name, command prefix) for the first available scanner."""
    for s in security()["scan"]["scanners"]:
        if name not in ("auto", s["name"]):
            continue
        if shutil.which(s["binary"]):
            return s["name"], [s["binary"]]
    for s in security()["scan"]["scanners"]:
        if name not in ("auto", s["name"]) or not shutil.which("docker"):
            continue
        img = _tool_image(s["image"])
        if not img:
            continue
        cache = WORK / "scanner-cache" / s["name"]
        cache.mkdir(parents=True, exist_ok=True)
        mount = {"trivy": "/root/.cache/trivy", "grype": "/.cache/grype"}[s["name"]]
        return s["name"], ["docker", "run", "--rm", *_docker_tool_args(), "-v", f"{cache.resolve()}:{mount}", img]
    return None


def parse_trivy(data: dict) -> list[Vuln]:
    out = []
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out.append(Vuln(v.get("VulnerabilityID", ""), v.get("PkgName", ""), v.get("InstalledVersion", ""),
                            v.get("FixedVersion", "") or "", (v.get("Severity") or "UNKNOWN").upper(),
                            r.get("Type", ""), (v.get("Title") or "")[:160]))
    return out


def parse_grype(data: dict) -> list[Vuln]:
    out = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        fix = v.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or []) if fix.get("state") == "fixed" else ""
        out.append(Vuln(v.get("id", ""), a.get("name", ""), a.get("version", ""), fixed,
                        (v.get("severity") or "UNKNOWN").upper(), a.get("type", ""), (v.get("description") or "")[:160]))
    return out


def scan_image(ref: str, scanner: str = "auto", local: bool = False) -> ScanResult:
    sc = scanner_command(scanner)
    if not sc:
        return ScanResult(ref, error="no scanner: install trivy or grype, or make docker available")
    name, cmd = sc
    if name == "trivy":
        rc, out, err = _run(cmd + ["image", "--quiet", "--format", "json", "--scanners", "vuln",
                                   *(["--image-src", "docker"] if local else []), ref])
        parse = parse_trivy
    else:
        rc, out, err = _run(cmd + [("docker:" if local else "registry:") + ref, "-o", "json"])
        parse = parse_grype
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return ScanResult(ref, name, error=(err or out).strip()[-600:] or f"{name} exited with {rc}")
    os_ = (data.get("Metadata") or {}).get("OS") or (data.get("distro") or {})
    return ScanResult(ref, name, parse(data), os=f"{os_.get('Family', os_.get('name', ''))} {os_.get('Name', os_.get('version', ''))}".strip())


# --------------------------------------------------------------------------- policy

def policy(fail_on: str | None = None, ignore_unfixed: bool | None = None) -> dict:
    p = dict(security()["scan"])
    if fail_on:
        p["fail_on"] = fail_on.upper()
    if ignore_unfixed is not None:
        p["ignore_unfixed"] = ignore_unfixed
    return p


def evaluate(res: ScanResult, pol: dict, today: date | None = None) -> dict:
    """Which vulnerabilities block, which are accepted, and which allowlist entries expired."""
    today = today or date.today()
    floor = RANK[pol["fail_on"].upper()]
    blocking, accepted, expired = [], [], set()
    for v in res.vulns:
        if RANK.get(v.severity, 0) < floor or (pol.get("ignore_unfixed", True) and not v.fixed):
            continue
        entry = next((a for a in pol.get("allowlist") or [] if a["id"] == v.id
                      and re.search(a.get("images", ".*"), res.image)), None)
        if entry:
            exp = entry.get("expires")
            exp = exp if isinstance(exp, date) or exp is None else date.fromisoformat(str(exp))
            if exp is None or exp >= today:
                accepted.append({"id": v.id, "reason": entry.get("reason", "")})
                continue
            expired.add(f"{v.id} (expired {exp})")
        blocking.append(v)
    return {"image": res.image, "passed": not blocking and not res.error, "blocking": blocking,
            "accepted": accepted, "expired_allowlist": sorted(expired), "error": res.error}


# --------------------------------------------------------------------------- registry tags and bumps

def split_ref(ref: str) -> tuple[str, str, str]:
    """(registry, repository, tag) of an image reference; Docker Hub is registry-1.docker.io."""
    ref = ref.split("@")[0]
    name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "latest")
    first = name.split("/")[0]
    if "/" in name and ("." in first or ":" in first or first == "localhost"):
        reg, repo = first, name.split("/", 1)[1]
    else:
        reg, repo = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    return reg, repo, tag


def _registry_get(url: str, headers: dict | None = None, method: str = "GET"):
    """GET/HEAD against a registry, answering an anonymous Bearer challenge once."""
    hdrs = dict(headers or {})
    for _ in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdrs, method=method), timeout=60) as r:
                return r.headers, r.read() if method == "GET" else b""
        except urllib.error.HTTPError as e:
            ch = e.headers.get("WWW-Authenticate", "")
            if e.code != 401 or "Authorization" in hdrs or not ch.lower().startswith("bearer"):
                raise
            params = dict(re.findall(r'(\w+)="([^"]*)"', ch))
            q = "&".join(f"{k}={params[k]}" for k in ("service", "scope") if k in params)
            with urllib.request.urlopen(f"{params['realm']}?{q}", timeout=60) as r:
                tok = json.loads(r.read())
            hdrs["Authorization"] = "Bearer " + (tok.get("token") or tok.get("access_token"))
    raise RuntimeError("registry authentication failed")


def list_tags(ref: str) -> list[str]:
    reg, repo, _ = split_ref(ref)
    url = f"https://{reg}/v2/{repo}/tags/list?n=100000"
    tags: list[str] = []
    while url:
        headers, body = _registry_get(url)
        tags += json.loads(body).get("tags") or []
        link = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", ""))
        url = (link.group(1) if link.group(1).startswith("http") else f"https://{reg}{link.group(1)}") if link else ""
    return tags


def manifest_digest(ref: str) -> str | None:
    reg, repo, tag = split_ref(ref)
    accept = ", ".join(["application/vnd.oci.image.index.v1+json",
                        "application/vnd.docker.distribution.manifest.list.v2+json",
                        "application/vnd.oci.image.manifest.v1+json",
                        "application/vnd.docker.distribution.manifest.v2+json"])
    try:
        headers, _ = _registry_get(f"https://{reg}/v2/{repo}/manifests/{tag}", {"Accept": accept}, method="HEAD")
        return headers.get("Docker-Content-Digest")
    except (urllib.error.URLError, RuntimeError, KeyError):
        return None


def _ver(s: str) -> tuple:
    return tuple(int(x) for x in re.split(r"[._]", s) if x.isdigit())


def bump_policy(ref: str) -> dict:
    return next((b for b in security()["images"]["bump"] if re.search(b["match"], ref)), {"policy": "patch"})


def candidates(ref: str, tags: list[str]) -> list[str]:
    """Newer tags of the same line (or newer lines when the bump policy allows), newest first."""
    name = ref.split("@")[0].rsplit(":", 1)[0]
    tag = split_ref(ref)[2]
    m = re.fullmatch(r"(\d+(?:\.\d+)*)(.*)", tag)
    if not m:
        return []
    line, suffix = m.group(1), m.group(2)
    bp = bump_policy(ref)
    lines = [line]
    if bp.get("policy") == "minor":
        major, depth = line.split(".")[0], len(line.split("."))
        rx = re.compile(re.escape(major) + r"(?:\.\d+){%d}" % (depth - 1) + re.escape(suffix))
        newer = {t[:-len(suffix)] if suffix else t for t in tags if rx.fullmatch(t)}
        newer = {x for x in newer if _ver(x) >= _ver(line) and re.search(bp.get("line_filter", ".*"), x)}
        lines = sorted(newer | {line}, key=_ver, reverse=True)
    out = []
    for ln in lines:
        rx = re.compile(re.escape(ln) + r"(?:\.\d+)+(?:_\d+)?" + re.escape(suffix))
        out += sorted((t for t in tags if rx.fullmatch(t)), key=lambda t: _ver(t[:len(t) - len(suffix)] if suffix else t),
                      reverse=True)[:5]
    return [f"{name}:{t}" for t in out]


def image_refs(include_windows: bool = False) -> list[tuple[str, str]]:
    """(slot, reference) of every base image in rules/images.yaml (without the lock)."""
    from .rules import RULES_DIR
    data = yaml.safe_load((RULES_DIR / "images.yaml").read_text())
    out = []
    for group, d in data.items():
        if not isinstance(d, dict) or (group == "windows" and not include_windows):
            continue
        for k, v in d.items():
            if isinstance(v, str) and ":" in v:
                out.append((f"{group}.{k}", v))
    return out


def update_images(scan: bool = True, scanner: str = "auto", write: bool = True, max_scans: int = 3,
                  log=print) -> dict:
    """Pick a patched tag for every base image line; write rules/images.lock.yaml."""
    from .generate import IMAGES_LOCK, images
    pol = policy()
    old = (yaml.safe_load(IMAGES_LOCK.read_text()) or {}).get("images", {}) if IMAGES_LOCK.exists() else {}
    lock: dict = {}
    for slot, ref in image_refs():
        if ref in lock:
            continue
        try:
            cands = candidates(ref, list_tags(ref))
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            log(f"{slot:22s} {ref}: cannot list tags ({e}); keeping the previous choice")
            if ref in old:
                lock[ref] = old[ref]
            continue
        if not cands:
            cands = [ref]       # no versioned tags (e.g. distroless :nonroot): pin the digest only
        chosen, best, results = None, None, []
        for c in cands[:max_scans if scan else 1]:
            if not scan:
                chosen = c
                break
            res = scan_image(c, scanner)
            ev = evaluate(res, pol)
            results.append({"tag": c, "counts": res.counts(fixed_only=True), "blocking": len(ev["blocking"]),
                            "error": res.error})
            if res.error:
                continue
            if best is None or len(ev["blocking"]) < best[1]:
                best = (c, len(ev["blocking"]), res)
            if ev["passed"]:
                chosen = c
                break
        chosen = chosen or (best[0] if best else cands[0])
        entry = {"tag": chosen, "slot": slot, "digest": manifest_digest(chosen)}
        lc = lifecycle(chosen)
        if lc:
            entry["eol"] = lc["eol"]
        r = next((x for x in results if x["tag"] == chosen), None)
        if r:
            entry["scan"] = {"scanner": scanner, "fixable": r["counts"], "blocking": r["blocking"]}
        lock[ref] = entry
        why = f"{r['blocking']} blocking" if r else "not scanned"
        log(f"{slot:22s} {ref} -> {chosen.rsplit(':', 1)[-1]} ({why})")
    out = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "policy": {"fail_on": pol["fail_on"], "ignore_unfixed": pol.get("ignore_unfixed", True)},
           "images": lock}
    if write:
        IMAGES_LOCK.write_text("# Base image tags chosen by `containerizer images --update` (newest patched tag\n"
                               "# per line, scanned against rules/60-security.yaml). The generator uses `tag`;\n"
                               "# `generate --pin-digests` uses `digest`. Delete this file to float on the lines\n"
                               "# in images.yaml again.\n" + yaml.safe_dump(out, sort_keys=False, width=120))
        images.cache_clear()
    return out


def lock_age_days() -> int | None:
    from .generate import IMAGES_LOCK
    if not IMAGES_LOCK.exists():
        return None
    ts = (yaml.safe_load(IMAGES_LOCK.read_text()) or {}).get("generated_at")
    if not ts:
        return None
    return (datetime.now(timezone.utc) - datetime.fromisoformat(str(ts))).days


# --------------------------------------------------------------------------- gate

def final_base(dockerfile: str) -> str | None:
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", dockerfile, re.M)
    return froms[-1] if froms else None


def build_image(app_root: Path, cdir: Path, tag: str, timeout: int = 1800) -> tuple[bool, str]:
    from .verify import _build_env_args, _ensure_images
    _ensure_images((cdir / "Dockerfile").read_text())
    rc, out, err = _run(["docker", "build", "--progress=plain", *_build_env_args(), "-f", str(cdir / "Dockerfile"),
                         "-t", tag, str(app_root)], timeout)
    (cdir / "build.log").write_text(out + err)
    return rc == 0, (out + err)[-2000:]


def gate_app(a, out: Path, build: bool = False, scan: bool = True, scanner: str = "auto",
             fail_on: str | None = None, registry: str = "registry.local", pin: bool = False,
             base_cache: dict | None = None) -> dict:
    from .generate import generate_app, k8s_name

    generate_app(a, out, registry=registry, pin=pin)
    pol = policy(fail_on)
    base_cache = base_cache if base_cache is not None else {}
    comps = []
    lint_all = []
    for cdir in sorted(d for d in out.iterdir() if (d / "Dockerfile").exists()):
        df = (cdir / "Dockerfile").read_text()
        lint = lint_dockerfile(df, f"{cdir.name}/Dockerfile")
        if (cdir / "k8s.yaml").exists():
            lint += lint_manifests(load_yaml_docs((cdir / "k8s.yaml").read_text()), f"{cdir.name}/k8s.yaml: ")
        lint_all += lint
        comp = {"component": cdir.name, "base": final_base(df), "lint": [v.to_dict() for v in lint], "scans": []}
        if scan and comp["base"]:
            base = comp["base"]
            if base not in base_cache:
                base_cache[base] = scan_image(base, scanner)
            bres = base_cache[base]
            comp["scans"].append(_scan_entry(bres, evaluate(bres, pol), "base"))
            if build:
                tag = f"containerizer/{k8s_name(a.name)}-{cdir.name}:gate"
                ok, log = build_image(a.repo.root, cdir, tag)
                if not ok:
                    comp["build_error"] = log[-800:]
                else:
                    res = scan_image(tag, scanner, local=True)
                    base_keys = {v.key for v in bres.vulns}
                    for v in res.vulns:
                        v.origin = "base" if v.key in base_keys else "app"
                    comp["scans"].append(_scan_entry(res, evaluate(res, pol), "image"))
        comps.append(comp)
    lint_errors = [v for v in lint_all if v.severity == "error"]
    scan_fail = [s for c in comps for s in c["scans"] if not s["passed"]]
    age = lock_age_days()
    notes = []
    if age is not None and age > security()["images"].get("lock_max_age_days", 14):
        notes.append(f"rules/images.lock.yaml is {age} days old; run `containerizer images --update`")
    result = {"app": a.name, "policy": {"fail_on": pol["fail_on"], "ignore_unfixed": pol.get("ignore_unfixed", True)},
              "passed": not lint_errors and not scan_fail and not any(c.get("build_error") for c in comps),
              "lint": summarize(lint_all), "components": comps, "notes": notes}
    (out / "security.json").write_text(json.dumps(result, indent=2, default=str))
    (out / "SECURITY.md").write_text(security_markdown(result))
    return result


def _scan_entry(res: ScanResult, ev: dict, kind: str) -> dict:
    return {"kind": kind, "image": res.image, "scanner": res.scanner, "os": res.os, "error": res.error,
            "passed": ev["passed"], "counts": res.counts(), "fixable": res.counts(fixed_only=True),
            "blocking": [asdict(v) for v in ev["blocking"]], "accepted": ev["accepted"],
            "expired_allowlist": ev["expired_allowlist"],
            "app_fixable": sorted({f"{v.package} {v.installed} -> {v.fixed}" for v in res.vulns
                                   if v.origin == "app" and v.fixed and RANK.get(v.severity, 0) >= RANK["HIGH"]})}


def security_markdown(r: dict) -> str:
    p = r["policy"]
    lines = [f"# Security gate: {r['app']}", "",
             f"**{'PASSED' if r['passed'] else 'FAILED'}**: fails on fixable {p['fail_on']} or worse "
             f"vulnerabilities{'' if p['ignore_unfixed'] else ' (including unfixed)'} and on lint errors.", "",
             f"Lint: {r['lint'].get('error', 0)} errors, {r['lint'].get('warning', 0)} warnings.", ""]
    for n in r.get("notes") or []:
        lines.append(f"> {n}")
    lines += ["", "| Component | Image | Scanner | Critical | High | Medium | Low | Gate |",
              "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |"]
    for c in r["components"]:
        for s in c["scans"]:
            k = s["counts"]
            fx = s["fixable"]
            gate = "pass" if s["passed"] else ("error" if s["error"] else f"{len(s['blocking'])} blocking")
            lines.append(f"| {c['component']} | {s['kind']}: `{s['image']}` | {s['scanner']} | "
                         f"{k['CRITICAL']} ({fx['CRITICAL']} fixable) | {k['HIGH']} ({fx['HIGH']}) | {k['MEDIUM']} | "
                         f"{k['LOW']} | {gate} |")
        if c.get("build_error"):
            lines.append(f"| {c['component']} | build failed | | | | | | error |")
    for c in r["components"]:
        block = [b for s in c["scans"] for b in s["blocking"]]
        errs = [v for v in c["lint"] if v["severity"] != "info"]
        app_fix = sorted({x for s in c["scans"] for x in s["app_fixable"]})
        if not (block or errs or app_fix):
            continue
        lines += ["", f"## {c['component']}", ""]
        for b in block:
            where = {"base": "base image: rebuild or `containerizer images --update`",
                     "app": "application package: upgrade it"}.get(b["origin"], "")
            lines.append(f"- **{b['severity']}** {b['id']} in {b['package']} {b['installed']}, fixed in {b['fixed']}"
                         + (f" ({where})" if where else ""))
        for x in app_fix:
            lines.append(f"- application package with a fixable HIGH/CRITICAL vulnerability: {x}")
        for v in errs:
            lines.append(f"- [{v['severity']}] {v['check']}: {v['message']} ({v['target']})")
        for s in c["scans"]:
            if s["error"]:
                lines.append(f"- scan error for `{s['image']}`: {s['error'][:300]}")
    return "\n".join(lines) + "\n"
