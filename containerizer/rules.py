"""Data-driven rule engine.

Rules live in YAML files under `rules/` (curated) and `rules/learned/` (written
by the self-learning loop). A rule has a condition tree (`when`) evaluated
against one project (scope: project) or the whole repository (scope: repo), and
an effect: a finding with severity, a role assignment, or extracted facts.

Condition primitives (all values are case-insensitive regular expressions
unless noted):

  sdk, tfm, package, reference, framework_ref, output_type, kind, role, name
  property: {Name: regex}
  file: glob              file name (or relative path when the glob has '/')
  code: regex             source files, comments stripped; optional `in: glob`
  config: regex           configuration files; optional `in: glob`
  text: regex             any text file; optional `in: glob`
  readme: regex           repository README (repo scope)
  unguarded: true         (with code) ignore hits right after an OperatingSystem.IsWindows() check
  any: [...], all: [...], not: {...}

`code`, `config` and `text` may use named groups; with `set` on a facts rule the
captured groups become facts (e.g. `(?P<port>\\d+)`).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .scan import Project, Repo, read_text

SEVERITIES = ["info", "config", "refactor", "rewrite", "blocker"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass
class Rule:
    id: str
    when: dict
    scope: str = "project"
    phase: str = "finding"          # role | facts | finding | plan
    applies_to: list[str] = field(default_factory=list)
    severity: str = "info"
    category: str = "general"
    effort: float = 0.0
    title: str = ""
    why: str = ""
    fix: str = ""
    role: str = ""
    priority: int = 0
    set: dict = field(default_factory=dict)
    plan: dict = field(default_factory=dict)
    windows_container: bool | None = None
    tags: list[str] = field(default_factory=list)
    source: str = "curated"
    confidence: float = 1.0
    file: str = ""
    meta: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict, file: str = "") -> "Rule":
        known = {k: d[k] for k in cls.__dataclass_fields__ if k in d and k not in ("file", "meta")}
        meta = {k: v for k, v in d.items() if k not in cls.__dataclass_fields__}
        r = cls(**known, file=file, meta=meta)
        if r.severity not in SEV_RANK:
            raise ValueError(f"rule {r.id}: unknown severity {r.severity}")
        return r


@dataclass
class Evidence:
    file: str
    line: int = 0
    snippet: str = ""

    def __str__(self) -> str:
        loc = f"{self.file}:{self.line}" if self.line else self.file
        return f"{loc}: {self.snippet}" if self.snippet else loc


@dataclass
class Match:
    rule: Rule
    evidence: list[Evidence]
    captures: dict = field(default_factory=dict)


def load_rules(dirs: list[Path] | None = None) -> list[Rule]:
    dirs = dirs or [RULES_DIR, RULES_DIR / "learned"]
    rules: list[Rule] = []
    seen: dict[str, Rule] = {}
    for d in dirs:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            data = yaml.safe_load(f.read_text()) or {}
            for item in data.get("rules", []):
                r = Rule.from_dict(item, file=str(f.relative_to(RULES_DIR.parent)))
                if r.id in seen:
                    # later (learned) definitions override curated ones with the same id
                    rules.remove(seen[r.id])
                seen[r.id] = r
                rules.append(r)
    return rules


@lru_cache(maxsize=4096)
def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.I | re.M)


def _glob_match(rel: str, name: str, pattern: str) -> bool:
    pattern = pattern.lower()
    if "/" in pattern:
        return fnmatch.fnmatch(rel.lower(), pattern) or fnmatch.fnmatch(rel.lower(), "*/" + pattern)
    return fnmatch.fnmatch(name.lower(), pattern)


class Context:
    """What a condition is evaluated against: a project, or the repository."""

    def __init__(self, repo: Repo, project: Project | None, role: str = ""):
        self.repo = repo
        self.project = project
        self.role = role

    def files(self) -> list[Path]:
        return self.project.files if self.project else self.repo.files

    def text(self, p: Path, strip: bool) -> str:
        if self.project:
            return self.project.text(p, strip)
        return _repo_text(p, strip)


@lru_cache(maxsize=20000)
def _repo_text(p: Path, strip: bool) -> str:
    return read_text(p, strip)


def _line_of(txt: str, pos: int) -> int:
    return txt.count("\n", 0, pos) + 1


def _snip(txt: str, m: re.Match) -> str:
    s = txt.rfind("\n", 0, m.start()) + 1
    e = txt.find("\n", m.end())
    line = txt[s:(e if e >= 0 else len(txt))].strip()
    return line[:160]


GUARD_RE = re.compile(r"OperatingSystem\.IsWindows\(\)|IsOSPlatform\(\s*OSPlatform\.Windows\s*\)|"
                      r"Environment\.OSVersion\.Platform\s*==\s*PlatformID\.Win32NT")


def _guarded(txt: str, pos: int) -> bool:
    """True when the match sits within a few lines after an OS check for Windows."""
    start = pos
    for _ in range(6):
        start = txt.rfind("\n", 0, start - 1)
        if start <= 0:
            start = 0
            break
    return bool(GUARD_RE.search(txt, start, txt.find("\n", pos) if txt.find("\n", pos) > 0 else len(txt)))


def _search_files(ctx: Context, pattern: str, files: list[Path], strip: bool, max_hits: int = 3,
                  skip_guarded: bool = False):
    rx = _rx(pattern)
    hits: list[Evidence] = []
    caps: dict = {}
    for f in files:
        txt = ctx.text(f, strip)
        if not txt:
            continue
        m = None
        for cand in rx.finditer(txt):
            if skip_guarded and _guarded(txt, cand.start()):
                continue
            m = cand
            break
        if m:
            hits.append(Evidence(ctx.repo.rel(f), _line_of(txt, m.start()), _snip(txt, m)))
            if not caps:
                caps = {k: v for k, v in m.groupdict().items() if v is not None}
            if len(hits) >= max_hits:
                break
    return hits, caps


SOURCE_EXT = {".cs", ".vb", ".fs", ".cshtml", ".vbhtml", ".razor", ".aspx", ".ascx", ".asmx", ".svc",
              ".asax", ".master", ".ashx", ".ts", ".js", ".py", ".java", ".go", ".xaml", ".tsx", ".jsx", ".mjs"}
CONFIG_EXT = {".config", ".json", ".xml", ".yaml", ".yml", ".ini", ".properties", ".settings", ".env", ".toml"}


def evaluate(cond, ctx: Context) -> tuple[bool, list[Evidence], dict]:
    """Return (matched, evidence, captures) for a condition tree."""
    if cond is None:
        return True, [], {}
    if isinstance(cond, list):
        cond = {"all": cond}
    ev: list[Evidence] = []
    caps: dict = {}
    keys = [k for k in cond.keys() if k not in ("in", "max", "unguarded")]
    if not keys:
        return True, [], {}
    for key in keys:
        val = cond[key]
        ok, e, c = _eval_one(key, val, cond, ctx)
        if not ok:
            return False, [], {}
        ev.extend(e)
        for k, v in c.items():
            caps.setdefault(k, v)
    return True, ev, caps


def _eval_one(key: str, val, cond: dict, ctx: Context):
    p = ctx.project
    proj_file = ctx.repo.rel(p.path) if p else ""
    if key == "any":
        for sub in val:
            ok, e, c = evaluate(sub, ctx)
            if ok:
                return True, e, c
        return False, [], {}
    if key == "all":
        ev, caps = [], {}
        for sub in val:
            ok, e, c = evaluate(sub, ctx)
            if not ok:
                return False, [], {}
            ev.extend(e)
            caps.update({k: v for k, v in c.items() if k not in caps})
        return True, ev, caps
    if key == "not":
        ok, _, _ = evaluate(val, ctx)
        return (not ok), [], {}
    if key == "readme":
        m = _rx(val).search(ctx.repo.readme)
        return (bool(m), [Evidence("README.md", _line_of(ctx.repo.readme, m.start()), _snip(ctx.repo.readme, m))] if m else [], {})
    if key in ("code", "config", "text"):
        glob = cond.get("in")
        files = ctx.files()
        if key == "code":
            files = [f for f in files if f.suffix.lower() in SOURCE_EXT]
        elif key == "config":
            files = [f for f in files if f.suffix.lower() in CONFIG_EXT and not f.name.lower().endswith(("proj", ".sln"))
                     and f.name.lower() not in ("package-lock.json", "packages.lock.json")]
        if glob:
            globs = glob if isinstance(glob, list) else [glob]
            files = [f for f in files if any(_glob_match(ctx.repo.rel(f), f.name, g) for g in globs)]
        hits, caps = _search_files(ctx, val, files, strip=(key == "code"), skip_guarded=bool(cond.get("unguarded")))
        return bool(hits), hits, caps
    if key == "file":
        globs = val if isinstance(val, list) else [val]
        hits = [Evidence(ctx.repo.rel(f)) for f in ctx.files()
                if any(_glob_match(ctx.repo.rel(f), f.name, g) for g in globs)]
        return bool(hits), hits[:3], {}
    if key == "role":
        return bool(_rx(f"^(?:{val})$").search(ctx.role or "")), [], {}
    if p is None:
        # project primitives on repo scope: true if any project matches
        for proj in ctx.repo.projects:
            ok, e, c = _eval_one(key, val, cond, Context(ctx.repo, proj))
            if ok:
                return ok, e, c
        return False, [], {}
    if key == "sdk":
        return bool(p.sdk and _rx(val).search(p.sdk)), [Evidence(proj_file, 0, f"Sdk={p.sdk}")], {}
    if key == "tfm":
        hits = [t for t in p.tfms if _rx(f"^(?:{val})$").search(t)]
        return bool(hits), [Evidence(proj_file, 0, f"TargetFramework={';'.join(p.tfms)}")], {}
    if key == "package":
        hits = [n for n in p.packages if _rx(f"^(?:{val})$").search(n)]
        return bool(hits), [Evidence(proj_file, 0, f"package {n} {p.packages[n]}".strip()) for n in hits[:3]], {}
    if key == "reference":
        hits = [n for n in p.references if _rx(f"^(?:{val})$").search(n)]
        return bool(hits), [Evidence(proj_file, 0, f"reference {n}") for n in hits[:3]], {}
    if key == "framework_ref":
        hits = [n for n in p.framework_refs if _rx(f"^(?:{val})$").search(n)]
        return bool(hits), [Evidence(proj_file, 0, f"FrameworkReference {n}") for n in hits[:3]], {}
    if key == "output_type":
        return bool(_rx(f"^(?:{val})$").search(p.output_type or "")), [], {}
    if key == "kind":
        return bool(_rx(f"^(?:{val})$").search(p.kind_hint)), [], {}
    if key == "name":
        return bool(_rx(val).search(p.name)), [], {}
    if key == "property":
        ev = []
        for name, rx in val.items():
            v = p.properties.get(name)
            if v is None or not _rx(f"^(?:{rx})$").search(v):
                return False, [], {}
            ev.append(Evidence(proj_file, 0, f"{name}={v}"))
        return True, ev, {}
    if key == "type_guid":
        return any(_rx(val).search(g) for g in p.type_guids), [Evidence(proj_file, 0, "ProjectTypeGuids")], {}
    raise ValueError(f"unknown condition key: {key}")


def applies(rule: Rule, ctx: Context) -> bool:
    if rule.applies_to and ctx.project is not None and ctx.project.kind_hint not in rule.applies_to:
        return False
    return True


def run_rule(rule: Rule, ctx: Context) -> Match | None:
    if not applies(rule, ctx):
        return None
    ok, ev, caps = evaluate(rule.when, ctx)
    if not ok:
        return None
    return Match(rule, ev, caps)
