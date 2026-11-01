"""An LLM as a fallback: only consulted when the rules are unsure.

Three backends:
  api    - Claude through the Anthropic Python SDK with structured outputs (needs
           credentials: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile)
  cli    - Claude through the `claude` CLI in print mode (`claude -p --model ...`)
  openai - a self-hosted LLM behind an OpenAI-compatible chat completions API
           (Ollama, vLLM, LM Studio, llama.cpp server, LocalAI, ...). Configure with
           CONTAINERIZER_LLM_BASE_URL (e.g. http://localhost:11434/v1), the model with
           --model or CONTAINERIZER_MODEL, and optionally CONTAINERIZER_LLM_API_KEY.
Select with CONTAINERIZER_AI_BACKEND=api|cli|openai (default: openai if
CONTAINERIZER_LLM_BASE_URL is set, else api if the SDK and a key are available,
else cli). The model is configurable per call, via --model or CONTAINERIZER_MODEL;
default claude-opus-5-5 for the Claude backends (the openai backend needs one set).

Every answer is validated before use, and anything learned from it is written
to rules/learned/ with `source: ai` and the model name, so it can be reviewed.
"""
from __future__ import annotations

import contextvars
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .rules import RULES_DIR, SEV_RANK, Rule, evaluate, Context

CLAUDE_DEFAULT_MODEL = "claude-opus-5-5"
MODELS = ["claude-fable-5-1", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]
# $ per 1M tokens (input, output)
PRICING = {"claude-fable-5-1": (10.0, 50.0), "claude-opus-5-5": (4.0, 20.0),
           "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50)}
LEARNED = RULES_DIR / "learned"
USAGE_LOG: list[dict] = []
# called with every usage entry (worker.ScanMetrics exports them as Prometheus metrics)
LISTENERS: list = []
# what an LLM call is for: feature (assessment, build-diagnosis, dev-database, platform-migration,
# sandbox-tester, ...) and the repository being scanned; set with `with usage_scope(...)`
_SCOPE: contextvars.ContextVar = contextvars.ContextVar("containerizer_llm_scope", default={})
HEAVY_ENV = "CONTAINERIZER_LLM_HEAVY"


class usage_scope:
    """`with usage_scope(feature="platform-migration", repo="team/api"):` tags the LLM calls inside it."""

    def __init__(self, **tags):
        self.tags = {k: v for k, v in tags.items() if v is not None}

    def __enter__(self):
        self.token = _SCOPE.set({**_SCOPE.get(), **self.tags})
        return self

    def __exit__(self, *exc):
        _SCOPE.reset(self.token)


def heavy_allowed(env=None) -> bool:
    """LLM-heavy mode (platform migrations and the sandbox tester ask the LLM as often as they need) is
    off unless the appliance or the environment turns it on: CONTAINERIZER_LLM_HEAVY=true. A scan also
    needs its own "LLM-heavy" setting (Admin → Organization scans), so both must say yes."""
    env = os.environ if env is None else env
    return str(env.get(HEAVY_ENV, "")).strip().lower() in ("1", "true", "yes", "on")


def _price(model: str, backend: str) -> tuple[float, float] | None:
    """$ per 1M tokens (input, output): the Claude list price, or for a self-hosted server what the
    operator set (CONTAINERIZER_LLM_PRICE_INPUT / _OUTPUT); None when not known."""
    if model in PRICING and backend in ("api", "cli"):
        return PRICING[model]
    pin, pout = _env("CONTAINERIZER_LLM_PRICE_INPUT"), _env("CONTAINERIZER_LLM_PRICE_OUTPUT")
    try:
        return (float(pin or 0), float(pout or 0)) if (pin or pout) else None
    except ValueError:
        return None


USAGE_LOG_MAX = 20000           # a long-running worker keeps only the newest entries (metrics count them all)


def record_usage(entry: dict) -> None:
    USAGE_LOG.append(entry)
    if len(USAGE_LOG) > USAGE_LOG_MAX:
        del USAGE_LOG[:len(USAGE_LOG) - USAGE_LOG_MAX // 2]
    for fn in list(LISTENERS):
        try:
            fn(entry)
        except Exception:                   # metrics must never break a scan
            pass


def usage_summary(entries: list[dict]) -> dict:
    """Totals of usage entries by feature: {feature: {calls, cached, errors, input_tokens, output_tokens, cost_usd}}."""
    out: dict[str, dict] = {}
    for u in entries:
        f = out.setdefault(u.get("feature") or "other", {"calls": 0, "cached": 0, "errors": 0, "input_tokens": 0,
                                                          "output_tokens": 0, "cost_usd": 0.0})
        f["calls"] += 1
        f["cached"] += 1 if u.get("cached") else 0
        f["errors"] += 1 if u.get("error") else 0
        if not u.get("cached"):
            f["input_tokens"] += int(u.get("input_tokens") or 0)
            f["output_tokens"] += int(u.get("output_tokens") or 0)
            f["cost_usd"] = round(f["cost_usd"] + float(u.get("cost_usd") or 0), 5)
    return out

SYSTEM = """You are a senior platform engineer who moves Windows-hosted applications (.NET, Java, Node.js) to Linux
containers on Kubernetes.
You are called by a rule-based assessment tool only where its rules are unsure. Judge from the evidence given,
prefer concrete technical reasons, and answer only with JSON matching the requested schema.
Severity scale: info (no impact), config (works with configuration/infra changes only), refactor (targeted code
changes), rewrite (port of the component, e.g. .NET Framework to .NET 8, or replacing a Windows-only native or COM
library a Java/Node.js component is built on), blocker (cannot run in a Linux container;
needs Windows, a desktop session, hardware, or a Windows-only vendor product)."""


# --------------------------------------------------------------------------- backends

BACKENDS = ("api", "cli", "openai")

# Settings that override the environment for the current run: the scan worker puts the LLM an
# administrator registered (Admin → Source control & LLM) here, so its key never enters os.environ and
# so never reaches the processes a scan starts (git, docker builds of the scanned code).
_OVERRIDE: dict[str, str] = {}


def _env(name: str, default: str = "") -> str:
    return _OVERRIDE[name] if name in _OVERRIDE else os.environ.get(name, default)


class configured:
    """`with configured({...}):` the given settings replace the environment's AI settings (all of
    them: what is not given counts as unset)."""
    KEYS = ("CONTAINERIZER_AI_BACKEND", "CONTAINERIZER_LLM_BASE_URL", "CONTAINERIZER_LLM_API_KEY", "CONTAINERIZER_MODEL",
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")

    def __init__(self, values: dict | None):
        self.values = values

    def __enter__(self):
        self.saved = dict(_OVERRIDE)
        if self.values is not None:
            _OVERRIDE.update({k: "" for k in self.KEYS})
            _OVERRIDE.update({k: v for k, v in self.values.items() if v is not None})
        return self

    def __exit__(self, *exc):
        _OVERRIDE.clear()
        _OVERRIDE.update(self.saved)


def _backend() -> str:
    b = _env("CONTAINERIZER_AI_BACKEND", "").strip().lower()
    if b:
        if b not in BACKENDS:
            raise RuntimeError(f"CONTAINERIZER_AI_BACKEND must be one of {', '.join(BACKENDS)}, not {b!r}")
        return b
    if _env("CONTAINERIZER_LLM_BASE_URL"):
        return "openai"
    try:
        import anthropic  # noqa: F401
        if _env("ANTHROPIC_API_KEY") or _env("ANTHROPIC_AUTH_TOKEN"):
            return "api"
    except ImportError:
        pass
    return "cli" if shutil.which("claude") else "none"


def model_name(model: str | None = None) -> str:
    """The model a call uses: --model, else CONTAINERIZER_MODEL, else the Claude default.
    A self-hosted server has no sensible default, so the openai backend needs one set."""
    if model:
        return model
    env = _env("CONTAINERIZER_MODEL")
    if env:
        return env
    if _backend() == "openai":
        raise RuntimeError("the openai backend needs a model: pass --model or set CONTAINERIZER_MODEL "
                           "(the name your server knows, e.g. qwen3:32b on Ollama)")
    return CLAUDE_DEFAULT_MODEL


CACHE = Path(os.environ.get("CONTAINERIZER_AI_CACHE", Path(__file__).resolve().parent.parent / ".work" / "ai-cache"))


def ask_json(prompt: str, schema: dict, model: str | None = None, effort: str = "medium", feature: str | None = None,
             system: str | None = None) -> dict:
    """One structured LLM call. Every call (answered, cached or failed) is recorded with its feature and
    repository (usage_scope) in USAGE_LOG and sent to LISTENERS."""
    import hashlib

    system = system or SYSTEM
    scope = {**_SCOPE.get(), **({"feature": feature} if feature else {})}
    tags = {"feature": scope.get("feature") or "other", "repo": scope.get("repo") or ""}
    model = model_name(model)
    backend = _backend()
    parts = [system, prompt, schema, model, effort]
    if backend == "openai":
        parts.append(_llm_base_url())     # same model name on another server is another model
    key = hashlib.sha256(json.dumps(parts).encode()).hexdigest()[:24]
    cf = CACHE / f"{key}.json"
    if cf.exists():
        cached = json.loads(cf.read_text())
        record_usage({**cached["usage"], **tags, "cached": True})
        return cached["data"]
    t0 = time.time()
    try:
        if backend == "api":
            data, usage = _ask_api(prompt, schema, model, effort, system)
        elif backend == "cli":
            data, usage = _ask_cli(prompt, schema, model, system=system)
        elif backend == "openai":
            data, usage = _ask_openai(prompt, schema, model, system=system)
        else:
            raise RuntimeError("No LLM backend available (install `anthropic` and set credentials, install the claude "
                               "CLI, or set CONTAINERIZER_LLM_BASE_URL to a self-hosted OpenAI-compatible server)")
    except Exception:
        record_usage({"model": model, "backend": backend, "seconds": round(time.time() - t0, 1), "input_tokens": 0,
                      "output_tokens": 0, "cost_usd": 0.0, **tags, "error": True})
        raise
    usage.update({"model": model, "backend": backend, "seconds": round(time.time() - t0, 1)})
    price = _price(model, backend)
    if usage.get("cost_usd") is None:
        pin, pout = price or (0, 0)
        usage["cost_usd"] = round((usage.get("input_tokens", 0) * pin + usage.get("output_tokens", 0) * pout) / 1e6, 5)
        usage["cost_known"] = price is not None
    record_usage({**usage, **tags})
    try:            # the answer is paid for: a cache that cannot be written must not lose it
        CACHE.mkdir(parents=True, exist_ok=True)
        cf.write_text(json.dumps({"data": data, "usage": usage}))
    except OSError as e:
        print(f"[ai] cannot cache the answer in {CACHE} (set CONTAINERIZER_AI_CACHE): {e}", file=sys.stderr)
    return data


def _ask_api(prompt: str, schema: dict, model: str, effort: str, system: str = SYSTEM):
    import anthropic

    client = anthropic.Anthropic(api_key=_env("ANTHROPIC_API_KEY") or None, base_url=_env("ANTHROPIC_BASE_URL") or None) \
        if _OVERRIDE else anthropic.Anthropic()
    kwargs = dict(model=model, max_tokens=16000, system=system,
                  messages=[{"role": "user", "content": prompt}],
                  output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}})
    if model != "claude-haiku-5-5":
        # server-side fallback when a safety classifier declines (routes by refusal category)
        resp = client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
    else:
        resp = client.messages.create(**kwargs)
    if resp.stop_reason == "refusal":
        raise RuntimeError(f"model declined: {getattr(resp.stop_details, 'category', None)}")
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text), {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}


def _first_json(text: str):
    """The first JSON object in a model answer (tolerates prose or code fences around it)."""
    # reasoning models served locally (DeepSeek-R1, Qwen3, ...) may think out loud before answering
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text, m.start())
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def _ask_cli(prompt: str, schema: dict, model: str, _retry: bool = False, system: str = SYSTEM):
    full = (f"{system}\n\n{prompt}\n\nRespond with ONLY a JSON object (no prose, no code fences) that validates "
            f"against this JSON schema:\n{json.dumps(schema)}")
    p = subprocess.run(["claude", "-p", "--model", model, "--output-format", "json", "--max-turns", "1",
                        "--disallowedTools", "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch,Agent"],
                       input=full, capture_output=True, text=True, timeout=900, cwd="/tmp")
    try:
        env = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"claude CLI failed: {p.stderr[-500:] or p.stdout[-500:]}")
    text = env.get("result", "")
    data = _first_json(text)
    if data is not None and _schema_errors(data, schema):
        data = None                      # the CLI cannot enforce the schema; check it here
    if data is None:
        if not _retry:
            return _ask_cli(prompt + "\n\nYour previous answer was not valid JSON. Answer with the JSON object only.",
                            schema, model, _retry=True, system=system)
        raise RuntimeError(f"no valid JSON in answer: {text[:300]}")
    u = env.get("usage") or {}
    return data, {"input_tokens": (u.get("input_tokens") or 0) + (u.get("cache_read_input_tokens") or 0)
                  + (u.get("cache_creation_input_tokens") or 0),
                  "output_tokens": u.get("output_tokens") or 0, "cost_usd": env.get("total_cost_usd")}


def _schema_errors(value, schema: dict, path: str = "$") -> list[str]:
    """Check an answer against the subset of JSON schema used here (object, array, string, number,
    boolean, enum, required). Backends that cannot enforce a schema are checked with this, so a
    weaker model's answer never reaches code that trusts its shape."""
    t = schema.get("type")
    errs: list[str] = []
    if t == "object":
        if not isinstance(value, dict):
            return [f"{path}: expected object"]
        for k in schema.get("required", []):
            if k not in value:
                errs.append(f"{path}.{k}: missing")
        for k, sub in schema.get("properties", {}).items():
            if k in value:
                errs += _schema_errors(value[k], sub, f"{path}.{k}")
    elif t == "array":
        if not isinstance(value, list):
            return [f"{path}: expected array"]
        for i, v in enumerate(value):
            errs += _schema_errors(v, schema.get("items", {}), f"{path}[{i}]")
    elif t == "string" and not isinstance(value, str):
        errs.append(f"{path}: expected string")
    elif t == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        errs.append(f"{path}: expected number")
    elif t == "boolean" and not isinstance(value, bool):
        errs.append(f"{path}: expected boolean")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not in {schema['enum']}")
    return errs


def _llm_base_url() -> str:
    url = _env("CONTAINERIZER_LLM_BASE_URL", "").strip().rstrip("/")
    if not url:
        raise RuntimeError("the openai backend needs CONTAINERIZER_LLM_BASE_URL, e.g. http://localhost:11434/v1 "
                           "(Ollama), http://localhost:8000/v1 (vLLM) or http://localhost:1234/v1 (LM Studio)")
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise RuntimeError(f"CONTAINERIZER_LLM_BASE_URL must be an http(s) URL, not {url!r}")
    if u.username or u.password:
        raise RuntimeError("put credentials in CONTAINERIZER_LLM_API_KEY, not in CONTAINERIZER_LLM_BASE_URL")
    return url


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _post_json(url: str, body: dict, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - scheme checked in _llm_base_url
        return json.loads(r.read().decode("utf-8", "replace"))


# Structured output modes, strongest first. Servers differ in what they support; on a 400/422 the next
# one is tried. The schema is always in the prompt too, and every answer is validated here.
JSON_MODES = ("json_schema", "json_object", "none")


def _ask_openai(prompt: str, schema: dict, model: str, _retry: bool = False, system: str = SYSTEM):
    """A self-hosted LLM behind an OpenAI-compatible /chat/completions endpoint."""
    base = _llm_base_url()
    key = _env("CONTAINERIZER_LLM_API_KEY", "")
    host = urllib.parse.urlsplit(base).hostname or ""
    if key and base.startswith("http://") and not _is_loopback(host) \
            and _env("CONTAINERIZER_LLM_ALLOW_HTTP") != "1":
        raise RuntimeError("refusing to send CONTAINERIZER_LLM_API_KEY over plain http to a remote host; use https, "
                           "or set CONTAINERIZER_LLM_ALLOW_HTTP=1 if the network path is trusted")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    timeout = float(_env("CONTAINERIZER_LLM_TIMEOUT", "900"))
    mode = _env("CONTAINERIZER_LLM_JSON_MODE", "json_schema")
    if mode not in JSON_MODES:
        raise RuntimeError(f"CONTAINERIZER_LLM_JSON_MODE must be one of {', '.join(JSON_MODES)}, not {mode!r}")
    user = (f"{prompt}\n\nRespond with ONLY a JSON object (no prose, no code fences) that validates "
            f"against this JSON schema:\n{json.dumps(schema)}")
    body = {"model": model, "temperature": 0, "stream": False,
            "max_tokens": int(_env("CONTAINERIZER_LLM_MAX_TOKENS", "16000")),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    resp = None
    for m in JSON_MODES[JSON_MODES.index(mode):]:
        b = dict(body)
        if m == "json_schema":
            b["response_format"] = {"type": "json_schema",
                                    "json_schema": {"name": "answer", "strict": True, "schema": schema}}
        elif m == "json_object":
            b["response_format"] = {"type": "json_object"}
        try:
            resp = _post_json(base + "/chat/completions", b, headers, timeout)
            break
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            if e.code in (400, 422) and m != "none":
                continue                 # server does not support this structured output mode
            raise RuntimeError(f"LLM server {base} answered HTTP {e.code}: {detail}") from None
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"cannot reach LLM server {base}: {getattr(e, 'reason', e)}") from None
    try:
        choice = resp["choices"][0]
        text = choice["message"].get("content") or ""
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"unexpected answer from LLM server {base}: {json.dumps(resp)[:300]}") from None
    data = _first_json(text)
    errs = _schema_errors(data, schema) if data is not None else ["no JSON object"]
    if errs:
        if not _retry:
            return _ask_openai(prompt + "\n\nYour previous answer did not match the schema (" + "; ".join(errs[:5])
                               + "). Answer with the JSON object only.", schema, model, _retry=True,
                               system=system)
        hint = " (answer cut off: raise CONTAINERIZER_LLM_MAX_TOKENS)" if choice.get("finish_reason") == "length" else ""
        raise RuntimeError(f"no valid JSON in answer{hint}: {'; '.join(errs[:3])}: {text[:300]}")
    u = resp.get("usage") or {}
    return data, {"input_tokens": u.get("prompt_tokens") or 0, "output_tokens": u.get("completion_tokens") or 0}


# --------------------------------------------------------------------------- evidence packs

def _snippet(path: Path, line: int, ctx: int = 6) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    s, e = max(0, line - ctx - 1), min(len(lines), line + ctx)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(s, e))


LANG = {"dotnet": "C#", "java": "Java/Kotlin", "node": "JavaScript/TypeScript"}


def _platform_lines(p) -> list[str]:
    pr = p.properties or {}
    if p.kind_hint == "java":
        return [f"Language: Java {pr.get('JavaVersion') or '(version not declared)'}; build: {pr.get('BuildTool', '-')}; "
                f"packaging: {pr.get('Packaging', 'jar')}; Spring Boot: {pr.get('SpringBootVersion') or 'no'}; "
                f"main class: {pr.get('MainClass') or '-'}"]
    if p.kind_hint == "node":
        return [f"Language: Node.js (engines: {pr.get('NodeEngine') or 'any'}); package manager: {pr.get('PackageManager', 'npm')}; "
                f"start: {pr.get('StartScript') or '-'}; native addons: {pr.get('LockNativeBuild') or 'none'}; "
                f"Windows-only packages: {pr.get('LockWindowsOnly') or 'none'}"]
    return [f"Target frameworks: {', '.join(p.tfms) or p.kind_hint}", f"SDK: {p.sdk or '-'}  OutputType: {p.output_type}"]


def _entry_files(p) -> list[Path]:
    """The files that start the component: Program.cs/Startup.cs, the Java main class, the Node.js start file."""
    if p.kind_hint == "dotnet":
        return [p.dir / n for n in ("Program.cs", "Startup.cs", "Global.asax.cs")]
    if p.kind_hint == "node":
        out = [p.path]
        for n in ((p.manifest or {}).get("main"), "server.js", "index.js", "app.js", "src/main.ts", "src/index.ts", "src/server.ts"):
            if isinstance(n, str) and (p.dir / n).is_file():
                out.append(p.dir / n)
                break
        return out
    main = ((p.properties or {}).get("MainClass") or "").split(".")[-1]
    for f in p.source_files():
        if f.suffix in (".java", ".kt") and (main and f.stem == main or not main and re.search(
                r"@SpringBootApplication|@QuarkusMain|public static void main", p.text(f))):
            return [p.path, f]
    return [p.path]


def evidence_pack(a, c, max_chars: int = 24000) -> str:
    p = c.project
    out = [f"Application: {a.name}", f"Component: {c.name} (project {p.rel})", f"Role (from rules): {c.role}",
           *_platform_lines(p),
           f"Packages: {', '.join(f'{k} {v}'.strip() for k, v in sorted(p.packages.items())) or '-'}",
           f"Framework references: {', '.join(sorted(set(p.references))) or '-'}",
           f"Rule verdict: {c.verdict}; unknown to the rules: {', '.join(c.uncertain) or 'none'}", "", "Rule findings:"]
    for f in c.findings:
        out.append(f"- [{f.severity}] {f.rule.title}{' (via ' + f.via + ')' if f.via else ''}"
                   f"{' [library code not referenced by this component]' if f.dormant else ''}: "
                   + "; ".join(str(e) for e in f.evidence[:2]))
    out.append("")
    seen = set()
    for f in sorted(c.findings, key=lambda f: -SEV_RANK[f.rule.severity]):
        for e in f.evidence[:2]:
            if e.line and (e.file, e.line) not in seen:
                seen.add((e.file, e.line))
                out.append(f"--- {e.file} around line {e.line} ---\n{_snippet(a.repo.root / e.file, e.line)}")
    for f in _entry_files(p):
        if f.exists():
            out.append(f"--- {a.repo.rel(f)} ---\n{f.read_text(errors='replace')[:4000]}")
    readme = a.repo.readme
    if readme:
        out.append("--- application README (excerpt) ---\n" + readme[:5000])
    text = "\n".join(out)
    return text[:max_chars]


# --------------------------------------------------------------------------- component review

REVIEW_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "confidence", "reasoning", "findings", "packages"],
    "properties": {
        "verdict": {"type": "string", "enum": ["info", "config", "refactor", "rewrite", "blocker"]},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
        "findings": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["severity", "title", "why", "fix", "evidence_regex", "agrees_with_rule"],
            "properties": {
                "severity": {"type": "string", "enum": ["info", "config", "refactor", "rewrite", "blocker"]},
                "title": {"type": "string"}, "why": {"type": "string"}, "fix": {"type": "string"},
                "evidence_regex": {"type": "string",
                                   "description": "regex over source code that detects this issue in other apps, or empty"},
                "agrees_with_rule": {"type": "boolean"}}}},
        "packages": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["name", "linux_ok", "note"],
            "properties": {"name": {"type": "string"}, "linux_ok": {"type": "boolean"}, "note": {"type": "string"}}}},
    },
}


def ai_review_component(a, c, model: str | None = None) -> dict:
    prompt = (evidence_pack(a, c) + "\n\nTask: decide whether this component can run in a Linux container on Kubernetes. "
              "Check each rule finding (is it real? is the code actually used on the component's main path, or only in an "
              "optional/legacy command?), classify every package listed as unknown, and add findings the rules missed. "
              f"For new findings give a regex over {LANG.get(c.project.kind_hint, 'source')} source that would detect the "
              "same issue elsewhere (or empty).")
    res = ask_json(prompt, REVIEW_SCHEMA, model=model, feature="assessment")
    res["model"] = model_name(model)
    return res


def ai_review_app(a, model: str | None = None, learn: bool = False, force: bool = False,
                  threshold: float = 0.85) -> dict:
    out = {"app": a.name, "model": model_name(model), "components": []}
    for c in a.components:
        if c.tier not in ("server", "platform"):
            continue
        if not force and c.confidence >= threshold:
            continue
        try:
            r = ai_review_component(a, c, model)
        except Exception as e:  # noqa: BLE001 - report and continue with the rules' answer
            out["components"].append({"component": c.name, "error": str(e)})
            continue
        r["component"] = c.name
        r["rule_verdict"] = c.verdict
        out["components"].append(r)
        if learn:
            learn_from_review(a, c, r)
    out["usage"] = USAGE_LOG[-len(out["components"]):] if out["components"] else []
    return out


def _valid_regex(rx: str) -> bool:
    if not rx or len(rx) > 300:
        return False
    try:
        re.compile(rx)
    except re.error:
        return False
    # reject regexes that match almost anything
    return not any(re.search(rx, s) for s in (
        "class Foo { void Bar() { var x = 1; } }", "public class Foo { public static void main(String[] a) { int x = 1; } }",
        "const x = require('y'); function f() { return 1; } export default f;"))


def learn_from_review(a, c, r: dict) -> None:
    """Persist AI knowledge that can be checked: package classifications and detectable findings."""
    stamp = datetime.now(timezone.utc).date().isoformat()
    ok = [p["name"] for p in r.get("packages", []) if p.get("linux_ok") and p.get("name") in c.project.packages]
    if ok:
        path = LEARNED / "packages.yaml"
        d = (yaml.safe_load(path.read_text()) if path.exists() else {}) or {}
        cur = d.setdefault("linux_ok", [])
        for n in ok:
            if re.escape(n) not in cur:
                cur.append(re.escape(n))
        path.write_text("# Packages observed working in a verified Linux container, or classified by the AI fallback (see ai-rules.yaml).\n"
                        + yaml.safe_dump(d, sort_keys=False))
    new_rules = []
    for f in r.get("findings", []):
        if f.get("agrees_with_rule") or f["severity"] == "info":
            continue
        rx = f.get("evidence_regex", "")
        if not _valid_regex(rx):
            continue
        rule = {"id": "ai-" + re.sub(r"[^a-z0-9]+", "-", f["title"].lower()).strip("-")[:50],
                "source": "ai", "confidence": 0.7, "model": r.get("model"), "learned_from": f"{a.name}/{c.name}",
                "learned_at": stamp, "applies_to": [c.project.kind_hint or "dotnet"], "when": {"code": rx},
                "severity": f["severity"], "category": "ai", "effort": 1, "title": f["title"], "why": f["why"],
                "fix": f["fix"]}
        # only keep a rule that actually fires on the component it was learned from
        if evaluate(rule["when"], Context(a.repo, c.project, c.role))[0]:
            new_rules.append(rule)
    if new_rules:
        path = LEARNED / "ai-rules.yaml"
        d = (yaml.safe_load(path.read_text()) if path.exists() else {}) or {}
        d.setdefault("rules", [])
        ids = {x["id"] for x in d["rules"]}
        for nr in new_rules:
            if nr["id"] not in ids:
                d["rules"].append(nr)
        path.write_text("# Finding rules proposed by the AI fallback (model in each rule) and validated against the code they were learned from.\n"
                        "# confidence 0.7: components they decide are re-checked by verification. Review before trusting.\n"
                        + yaml.safe_dump(d, sort_keys=False, width=120))


# --------------------------------------------------------------------------- failure diagnosis

DIAG_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["outcome", "diagnosis", "match", "fix_json"],
    "properties": {
        "outcome": {"type": "string", "enum": ["retry", "external", "platform", "code"]},
        "diagnosis": {"type": "string"},
        "match": {"type": "string", "description": "regex that matches this failure in the log and similar failures elsewhere"},
        "fix_json": {"type": "string", "description": "JSON object: build-plan patch for outcome=retry, else {}"},
    },
}

PLAN_HELP = {
    "dotnet": """Build-plan patch keys you may use (JSON): base ("chiseled"|"full"), add_packages [apt packages for Ubuntu 24.04,
forces base full], env {NAME: value}, add_writable [absolute folders that must be writable], publish_args [extra
`dotnet publish` args], remove_files [file names deleted in the build stage], strategy ("rollforward"|"retarget" to the supported runtime line).""",
    "java": """Build-plan patch keys you may use (JSON): java (LTS line to build and run on: 8, 11, 17, 21 or 25), env {NAME: value}
(runtime environment, e.g. Spring relaxed-binding overrides), build_env {NAME: value} (build stage only), add_writable [absolute
folders that must be writable], publish_args [extra Maven or Gradle arguments], remove_files [file names deleted in the build
stage], maven_wrapper (true: build with the repository's mvnw).""",
    "node": """Build-plan patch keys you may use (JSON): env {NAME: value} (runtime environment), build_env {NAME: value} (build stage
only, e.g. NODE_OPTIONS), add_writable [absolute folders that must be writable], remove_files [file names deleted in the
build stage], native_build (true: build on the full image with Python, make and g++), prune (false: keep devDependencies),
lockfile (false: resolve dependencies again instead of installing from the lockfile).""",
}
PLAN_KEYS = {"dotnet": {"base", "add_packages", "env", "add_writable", "publish_args", "remove_files", "strategy"},
             "java": {"java", "env", "build_env", "add_writable", "publish_args", "remove_files", "maven_wrapper"},
             "node": {"env", "build_env", "add_writable", "remove_files", "native_build", "prune", "lockfile"}}
PLAN_RULES = "Never change application source code. Never run as root or disable security settings."


def diagnose_failure(a, c, plan: dict, stage: str, log_tail: str, model: str | None = None):
    kind = c.project.kind_hint if c.project.kind_hint in PLAN_KEYS and c.role != "spa" else "dotnet"
    prompt = (f"A generated container for {a.name}/{c.name} failed at the {stage} stage.\n\nBuild plan:\n"
              f"{json.dumps({k: v for k, v in plan.items() if k != 'applied'}, indent=1)}\n\n"
              f"{PLAN_HELP.get(kind, PLAN_HELP['dotnet'])}\n{PLAN_RULES}\n\n"
              f"Log tail:\n{log_tail[-8000:]}\n\nDiagnose the failure. outcome=retry if a plan patch can fix it, "
              "external if the container itself is fine and only an external service/config is missing, platform if "
              "a Windows-only API/library is needed, code if the application code must change.")
    try:
        r = ask_json(prompt, DIAG_SCHEMA, model=model, feature="build-diagnosis")
        fix = json.loads(r.get("fix_json") or "{}")
        if not isinstance(fix, dict):
            fix = {}
        fix = {k: v for k, v in fix.items() if k in PLAN_KEYS[kind]}
        if not re.search(r["match"], log_tail, re.I | re.M):
            r["match"] = re.escape(log_tail.strip().splitlines()[-1][:120]) if log_tail.strip() else "$^"
    except Exception:  # noqa: BLE001
        return None
    fr = {"id": "ai-" + re.sub(r"[^a-z0-9]+", "-", r["diagnosis"].lower())[:40].strip("-"), "stage": stage,
          "match": r["match"], "outcome": r["outcome"], "diagnosis": r["diagnosis"], "fix": fix,
          "source": "ai", "model": model_name(model), "learn": {"when": {}}, "_new": True}
    if r["outcome"] in ("platform", "code"):
        fr["finding"] = {"severity": "blocker" if r["outcome"] == "platform" else "refactor", "title": r["diagnosis"][:120]}
    return fr, {}


# --------------------------------------------------------------------------- AI-only baseline

APP_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["rating", "reasoning", "components"],
    "properties": {
        "rating": {"type": "string", "enum": ["A", "B", "C", "D", "E"]},
        "reasoning": {"type": "string"},
        "components": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["name", "verdict", "reason"],
            "properties": {"name": {"type": "string"},
                           "verdict": {"type": "string", "enum": ["info", "config", "refactor", "rewrite", "blocker"]},
                           "reason": {"type": "string"}}}},
    },
}
RATING_HELP = ("Ratings: A container-ready (modern stack: all server components run in Linux containers with "
               "configuration only, no code changes); "
               "B minor refactoring; C major refactoring (framework port, e.g. .NET Framework to .NET 8, or a Java EE "
               "server application to an embedded server); "
               "D partial (some server components cannot run in Linux containers and must stay on Windows, at least a "
               "quarter of them can); E not feasible (three quarters or more of the server components cannot, or there is "
               "no server component). Desktop clients, test tools and database-tier code (SQL CLR, SSIS) do not count "
               "as server components.")


def app_inventory(a, with_rules: bool) -> str:
    out = [f"Application: {a.name}", "", "Projects:"]
    for c in a.components + a.libraries:
        p = c.project
        line = (f"- {c.name} [{p.rel}] tfm={';'.join(p.tfms) or p.kind_hint} sdk={p.sdk or '-'} output={p.output_type} "
                f"packages={', '.join(sorted(p.packages))[:400]} refs={', '.join(sorted(set(p.references)))[:300]}")
        if with_rules:
            line += f" | rules: role={c.role} verdict={c.verdict} " + "; ".join(
                f.rule.title for f in c.findings if f.severity in ("blocker", "rewrite"))[:300]
        out.append(line)
    out += ["", "README:", a.repo.readme[:12000]]
    return "\n".join(out)


def ai_only_assess(a, model: str | None = None, with_rules: bool = False) -> dict:
    prompt = (app_inventory(a, with_rules) + "\n\n" + RATING_HELP +
              "\n\nTask: rate this application and give a verdict for every deployable server component "
              "(use the project names above).")
    r = ask_json(prompt, APP_SCHEMA, model=model, feature="assessment")
    r["usage"] = USAGE_LOG[-1]
    return r
