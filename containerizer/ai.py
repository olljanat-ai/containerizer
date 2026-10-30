"""Claude as a fallback: only consulted when the rules are unsure.

Two backends:
  api - the Anthropic Python SDK with structured outputs (needs credentials:
        ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile)
  cli - the `claude` CLI in print mode (`claude -p --model ...`)
Select with CONTAINERIZER_AI_BACKEND=api|cli (default: api if the SDK and a
key are available, else cli). The model is configurable per call, via
--model or CONTAINERIZER_MODEL; default claude-opus-5-5.

Every answer is validated before use, and anything learned from it is written
to rules/learned/ with `source: ai` and the model name, so it can be reviewed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .rules import RULES_DIR, SEV_RANK, Rule, evaluate, Context

DEFAULT_MODEL = os.environ.get("CONTAINERIZER_MODEL", "claude-opus-5-5")
MODELS = ["claude-fable-5-1", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]
# $ per 1M tokens (input, output)
PRICING = {"claude-fable-5-1": (10.0, 50.0), "claude-opus-5-5": (4.0, 20.0),
           "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50)}
LEARNED = RULES_DIR / "learned"
USAGE_LOG: list[dict] = []

SYSTEM = """You are a senior platform engineer who moves Windows/.NET applications to Linux containers on Kubernetes.
You are called by a rule-based assessment tool only where its rules are unsure. Judge from the evidence given,
prefer concrete technical reasons, and answer only with JSON matching the requested schema.
Severity scale: info (no impact), config (works with configuration/infra changes only), refactor (targeted code
changes), rewrite (port of the component, e.g. .NET Framework to .NET 8), blocker (cannot run in a Linux container;
needs Windows, a desktop session, hardware, or a Windows-only vendor product)."""


# --------------------------------------------------------------------------- backends

def _backend() -> str:
    b = os.environ.get("CONTAINERIZER_AI_BACKEND")
    if b:
        return b
    try:
        import anthropic  # noqa: F401
        if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            return "api"
    except ImportError:
        pass
    return "cli" if shutil.which("claude") else "none"


CACHE = Path(os.environ.get("CONTAINERIZER_AI_CACHE", Path(__file__).resolve().parent.parent / ".work" / "ai-cache"))


def ask_json(prompt: str, schema: dict, model: str | None = None, effort: str = "medium") -> dict:
    import hashlib

    model = model or DEFAULT_MODEL
    key = hashlib.sha256(json.dumps([SYSTEM, prompt, schema, model, effort]).encode()).hexdigest()[:24]
    cf = CACHE / f"{key}.json"
    if cf.exists():
        cached = json.loads(cf.read_text())
        USAGE_LOG.append({**cached["usage"], "cached": True})
        return cached["data"]
    backend = _backend()
    t0 = time.time()
    if backend == "api":
        data, usage = _ask_api(prompt, schema, model, effort)
    elif backend == "cli":
        data, usage = _ask_cli(prompt, schema, model)
    else:
        raise RuntimeError("No Claude backend available (install `anthropic` and set credentials, or install the claude CLI)")
    usage.update({"model": model, "backend": backend, "seconds": round(time.time() - t0, 1)})
    pin, pout = PRICING.get(model, (0, 0))
    if usage.get("cost_usd") is None:
        usage["cost_usd"] = round((usage.get("input_tokens", 0) * pin + usage.get("output_tokens", 0) * pout) / 1e6, 5)
    USAGE_LOG.append(usage)
    CACHE.mkdir(parents=True, exist_ok=True)
    cf.write_text(json.dumps({"data": data, "usage": usage}))
    return data


def _ask_api(prompt: str, schema: dict, model: str, effort: str):
    import anthropic

    client = anthropic.Anthropic()
    kwargs = dict(model=model, max_tokens=16000, system=SYSTEM,
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
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text, m.start())
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def _ask_cli(prompt: str, schema: dict, model: str, _retry: bool = False):
    full = (f"{SYSTEM}\n\n{prompt}\n\nRespond with ONLY a JSON object (no prose, no code fences) that validates "
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
    if data is not None and any(k not in data for k in schema.get("required", [])):
        data = None                      # the CLI cannot enforce the schema; check required keys
    if data is None:
        if not _retry:
            return _ask_cli(prompt + "\n\nYour previous answer was not valid JSON. Answer with the JSON object only.",
                            schema, model, _retry=True)
        raise RuntimeError(f"no valid JSON in answer: {text[:300]}")
    u = env.get("usage") or {}
    return data, {"input_tokens": (u.get("input_tokens") or 0) + (u.get("cache_read_input_tokens") or 0)
                  + (u.get("cache_creation_input_tokens") or 0),
                  "output_tokens": u.get("output_tokens") or 0, "cost_usd": env.get("total_cost_usd")}


# --------------------------------------------------------------------------- evidence packs

def _snippet(path: Path, line: int, ctx: int = 6) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    s, e = max(0, line - ctx - 1), min(len(lines), line + ctx)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(s, e))


def evidence_pack(a, c, max_chars: int = 24000) -> str:
    p = c.project
    out = [f"Application: {a.name}", f"Component: {c.name} (project {p.rel})", f"Role (from rules): {c.role}",
           f"Target frameworks: {', '.join(p.tfms) or p.kind_hint}", f"SDK: {p.sdk or '-'}  OutputType: {p.output_type}",
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
    for name in ("Program.cs", "Startup.cs", "Global.asax.cs"):
        f = p.dir / name
        if f.exists():
            out.append(f"--- {p.rel_dir}/{name} ---\n{f.read_text(errors='replace')[:4000]}")
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
              "For new findings give a regex over C# source that would detect the same issue elsewhere (or empty).")
    res = ask_json(prompt, REVIEW_SCHEMA, model=model)
    res["model"] = model or DEFAULT_MODEL
    return res


def ai_review_app(a, model: str | None = None, learn: bool = False, force: bool = False,
                  threshold: float = 0.85) -> dict:
    out = {"app": a.name, "model": model or DEFAULT_MODEL, "components": []}
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
    return not re.search(rx, "class Foo { void Bar() { var x = 1; } }")


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
        path.write_text("# Packages observed working in a verified Linux container, or classified by Claude (see ai-rules.yaml).\n"
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
                "learned_at": stamp, "applies_to": ["dotnet"], "when": {"code": rx},
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
        path.write_text("# Finding rules proposed by Claude and validated against the code they were learned from.\n"
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

PLAN_HELP = """Build-plan patch keys you may use (JSON): base ("chiseled"|"full"), add_packages [apt packages for Ubuntu 24.04,
forces base full], env {NAME: value}, add_writable [absolute folders that must be writable], publish_args [extra
`dotnet publish` args], remove_files [file names deleted in the build stage], strategy ("rollforward"|"retarget" to net8.0).
Never change application source code. Never run as root or disable security settings."""


def diagnose_failure(a, c, plan: dict, stage: str, log_tail: str, model: str | None = None):
    prompt = (f"A generated container for {a.name}/{c.name} failed at the {stage} stage.\n\nBuild plan:\n"
              f"{json.dumps({k: v for k, v in plan.items() if k != 'applied'}, indent=1)}\n\n{PLAN_HELP}\n\n"
              f"Log tail:\n{log_tail[-8000:]}\n\nDiagnose the failure. outcome=retry if a plan patch can fix it, "
              "external if the container itself is fine and only an external service/config is missing, platform if "
              "a Windows-only API/library is needed, code if the application code must change.")
    try:
        r = ask_json(prompt, DIAG_SCHEMA, model=model)
        fix = json.loads(r.get("fix_json") or "{}")
        if not isinstance(fix, dict):
            fix = {}
        allowed = {"base", "add_packages", "env", "add_writable", "publish_args", "remove_files", "strategy"}
        fix = {k: v for k, v in fix.items() if k in allowed}
        if not re.search(r["match"], log_tail, re.I | re.M):
            r["match"] = re.escape(log_tail.strip().splitlines()[-1][:120]) if log_tail.strip() else "$^"
    except Exception:  # noqa: BLE001
        return None
    fr = {"id": "ai-" + re.sub(r"[^a-z0-9]+", "-", r["diagnosis"].lower())[:40].strip("-"), "stage": stage,
          "match": r["match"], "outcome": r["outcome"], "diagnosis": r["diagnosis"], "fix": fix,
          "source": "ai", "model": model or DEFAULT_MODEL, "learn": {"when": {}}, "_new": True}
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
RATING_HELP = ("Ratings: A lift and shift (all server components run in Linux containers with configuration only); "
               "B minor refactoring; C major refactoring (framework port, e.g. .NET Framework to .NET 8); "
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
    r = ask_json(prompt, APP_SCHEMA, model=model)
    r["usage"] = USAGE_LOG[-1]
    return r
