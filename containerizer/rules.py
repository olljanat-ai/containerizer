"""Data-driven rule engine.

Rules live in YAML files under `rules/` (curated) and `rules/learned/` (written
by the self-learning loop). A rule has a condition tree (`when`) evaluated
against one project (scope: project) or the whole repository (scope: repo), and
an effect: a finding with severity, a role assignment, or extracted facts.

Condition primitives (all values are case-insensitive regular expressions
unless noted):

  sdk, tfm, package, reference, framework_ref, output_type, kind, role, name
  path: regex             the project file's path relative to the repository root ('/' separators)
  property: {Name: regex}
  file: glob              file name (or relative path when the glob has '/')
  code: regex             source files, comments stripped; optional `in: glob`
  config: regex           configuration files; optional `in: glob`
  text: regex             any text file; optional `in: glob`
  readme: regex           repository README (repo scope)
  unguarded: true         (with code) ignore hits right after an OS check (OperatingSystem.IsWindows(),
                          IsLinux(), IsMacOS(), IsOSPlatform(...)) or inside a method/type marked
                          [SupportedOSPlatform("windows"|"macos"|"linux"...)]
  any: [...], all: [...], not: {...}
  same_file: true         (next to `all`) the code/config/text conditions directly under the
                          `all` must all match in one and the same file

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
    refs: list[str] = field(default_factory=list)   # documentation / issue links backing why and fix
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


# An explicit platform check means the authors branch per OS: code right after it is
# platform-specific (the Windows branch, or a macOS/Linux branch that is not Windows code
# either), and a Linux container takes the branch written for it.
GUARD_RE = re.compile(r"OperatingSystem\.Is(Windows|MacOS|Linux|FreeBSD|MacCatalyst|IOS|Android)\(\)|"
                      r"IsOSPlatform\(\s*OSPlatform\.(Windows|OSX|Linux|FreeBSD)\s*\)|"
                      r"Environment\.OSVersion\.Platform\s*==\s*PlatformID\.Win32NT")


# members/types the authors marked as running on one specific OS (CA1416 makes callers guard them)
SUPPORTED_WIN_RE = re.compile(r'\[\s*SupportedOSPlatform\(\s*"(windows|macos|osx|linux|freebsd|maccatalyst|ios|android)'
                              r'[^"]*"\s*\)\s*\]', re.I)


def _in_windows_only_member(txt: str, pos: int) -> bool:
    """True when pos is inside (or in the signature of) a method/type marked [SupportedOSPlatform("windows")].

    Cheap brace counting from the attribute; braces inside strings may confuse it, which
    only ever makes a hit count as unguarded."""
    if "SupportedOSPlatform" not in txt:
        return False
    # the attribute may follow the hit in the same attribute list:
    # [DllImport("kernel32.dll")] [SupportedOSPlatform("windows")] static extern ...;
    decl_end = min((i for i in (txt.find(";", pos), txt.find("{", pos)) if i >= 0), default=len(txt))
    if SUPPORTED_WIN_RE.search(txt, pos, decl_end):
        return True
    for m in SUPPORTED_WIN_RE.finditer(txt, 0, pos):
        end = m.end()
        brace = txt.find("{", end, pos + 1)
        semi = txt.find(";", end, brace if brace >= 0 else pos)
        if semi >= 0:              # expression-bodied member / declaration ends before pos
            continue
        if brace < 0:              # still in the signature
            return True
        depth = 0
        for ch in txt[brace:pos]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
        else:
            if depth > 0:
                return True
    return False


def _block_end(txt: str, brace: int) -> int:
    """Index just after the brace that closes the block opened at txt[brace] (len(txt) if unclosed)."""
    depth = 0
    for i in range(brace, len(txt)):
        ch = txt[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(txt)


PRIVATE_TYPE_RE = re.compile(r"\bprivate\s+(?:(?:static|sealed|partial|unsafe|abstract)\s+)*(?:class|struct)\s+(\w+)[^{;]*\{")


def _in_guarded_private_type(txt: str, pos: int) -> bool:
    """True when pos is inside a private nested type (usable only from its own file) and every
    use of that type outside its body is itself OS-guarded, e.g. a `private class PrivilegeChecker`
    holding advapi32 P/Invokes that is only called after `if (OperatingSystem.IsWindows())`."""
    if "private" not in txt:
        return False
    for m in PRIVATE_TYPE_RE.finditer(txt, 0, pos):
        body_start, body_end = m.end() - 1, _block_end(txt, m.end() - 1)
        if not body_start < pos < body_end:
            continue
        uses = [u.start() for u in re.finditer(rf"\b{re.escape(m.group(1))}\b", txt)
                if not (m.start() <= u.start() < body_end)]
        if uses and all(_guarded(txt, u, nested=False) for u in uses):
            return True
    return False


# `if (!OperatingSystem.IsWindows()) return ...;` (or throw): the rest of the block is Windows-only,
# the pattern the CA1416 platform analyzer recognises
EARLY_EXIT_RE = re.compile(r"if\s*\(\s*!\s*(OperatingSystem\.IsWindows\(\)|RuntimeInformation\.IsOSPlatform\(\s*OSPlatform\.Windows\s*\))"
                           r"\s*\)\s*(\{\s*(return|throw)\b[^;{}]*;\s*\}|(return|throw)\b[^;{}]*;)")


def _after_early_exit(txt: str, pos: int, window: int = 4000) -> bool:
    if "IsWindows" not in txt and "OSPlatform.Windows" not in txt:
        return False
    lo = max(0, pos - window)
    for m in EARLY_EXIT_RE.finditer(txt, lo, pos):
        depth = 0
        for ch in txt[m.end():pos]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth < 0:        # left the block that held the check
                    break
        else:
            return True
    return False


def _guarded(txt: str, pos: int, nested: bool = True) -> bool:
    """True when the match sits within a few lines after an OS check, inside a member the
    authors marked [SupportedOSPlatform(...)] (callers must guard it), or inside a private
    helper type that is only used from guarded code."""
    start = pos
    for _ in range(6):
        start = txt.rfind("\n", 0, start - 1)
        if start <= 0:
            start = 0
            break
    if GUARD_RE.search(txt, start, txt.find("\n", pos) if txt.find("\n", pos) > 0 else len(txt)):
        return True
    if _in_windows_only_member(txt, pos) or _after_early_exit(txt, pos):
        return True
    return nested and _in_guarded_private_type(txt, pos)


def _search_files(ctx: Context, pattern: str, files: list[Path], strip: bool, max_hits: int | None = 3,
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
            if max_hits is not None and len(hits) >= max_hits:
                break
    return hits, caps


SOURCE_EXT = {".cs", ".vb", ".fs", ".cshtml", ".vbhtml", ".razor", ".aspx", ".ascx", ".asmx", ".svc",
              ".asax", ".master", ".ashx", ".ts", ".js", ".py", ".java", ".go", ".xaml", ".tsx", ".jsx", ".mjs"}
CONFIG_EXT = {".config", ".json", ".xml", ".yaml", ".yml", ".ini", ".properties", ".settings", ".env", ".toml"}


DOTNET_SOURCE_EXT = {".cs", ".vb", ".fs", ".cshtml", ".vbhtml", ".razor", ".aspx", ".ascx", ".asmx", ".svc",
                     ".asax", ".master", ".ashx", ".xaml"}
# third-party bundles (minified JS, editor grammars, vendored client libraries) are not application code
VENDORED_RE = re.compile(r"\.min\.(js|css)$|(^|/)(wwwroot/lib|monaco[^/]*|node_modules|bower_components)/", re.I)
_FILES_CACHE: dict = {}


def _candidate_files(ctx: Context, key: str, glob) -> list[Path]:
    """Files a code/config/text condition searches; cached per project, key and glob."""
    globs = tuple(glob if isinstance(glob, list) else [glob]) if glob else ()
    owner = ctx.project if ctx.project is not None else ctx.repo
    ck = (id(owner), key, globs)
    hit = _FILES_CACHE.get(ck)
    if hit is not None and hit[0] is owner:
        return hit[1]
    files = [f for f in ctx.files() if not VENDORED_RE.search(ctx.repo.rel(f).replace("\\", "/"))]
    if key == "code":
        # .NET projects: only .NET source, unless the rule names the files itself
        ext = DOTNET_SOURCE_EXT if (ctx.project is not None and ctx.project.kind_hint == "dotnet" and not globs) \
            else SOURCE_EXT
        files = [f for f in files if f.suffix.lower() in ext]
    elif key == "config":
        files = [f for f in files if f.suffix.lower() in CONFIG_EXT and not f.name.lower().endswith(("proj", ".sln"))
                 and f.name.lower() not in ("package-lock.json", "packages.lock.json")]
    if globs:
        files = [f for f in files if any(_glob_match(ctx.repo.rel(f), f.name, g) for g in globs)]
    if len(_FILES_CACHE) > 20000:
        _FILES_CACHE.clear()
    _FILES_CACHE[ck] = (owner, files)
    return files


def evaluate(cond, ctx: Context) -> tuple[bool, list[Evidence], dict]:
    """Return (matched, evidence, captures) for a condition tree."""
    if cond is None:
        return True, [], {}
    if isinstance(cond, list):
        cond = {"all": cond}
    ev: list[Evidence] = []
    caps: dict = {}
    keys = [k for k in cond.keys() if k not in ("in", "max", "unguarded", "same_file")]
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
        if cond.get("same_file"):
            return _eval_all_same_file(val, ctx)
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
        files = _candidate_files(ctx, key, cond.get("in"))
        hits, caps = _search_files(ctx, val, files, strip=(key in ("code", "config")),
                                   skip_guarded=bool(cond.get("unguarded")))
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
    if key == "path":
        rel = p.rel.replace("\\", "/")
        return bool(_rx(val).search(rel)), [Evidence(rel)], {}
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


TEXT_KEYS = ("code", "config", "text")


def _eval_all_same_file(subs: list, ctx: Context):
    """`all` with same_file: every code/config/text leaf must hit one common file."""
    ev, caps = [], {}
    per_leaf: list[dict[str, Evidence]] = []
    for sub in subs:
        leaf = isinstance(sub, dict) and [k for k in sub if k in TEXT_KEYS]
        if leaf and len([k for k in sub if k not in ("in", "max", "unguarded")]) == 1:
            key = leaf[0]
            files = _candidate_files(ctx, key, sub.get("in"))
            hits, _ = _search_files(ctx, sub[key], files, strip=(key in ("code", "config")), max_hits=None,
                                    skip_guarded=bool(sub.get("unguarded")))
            if not hits:
                return False, [], {}
            by_file: dict[str, Evidence] = {}
            for h in hits:
                by_file.setdefault(h.file, h)
            per_leaf.append(by_file)
            continue
        ok, e, c = evaluate(sub, ctx)
        if not ok:
            return False, [], {}
        ev.extend(e)
        caps.update({k: v for k, v in c.items() if k not in caps})
    if per_leaf:
        common = set(per_leaf[0])
        for d in per_leaf[1:]:
            common &= set(d)
        if not common:
            return False, [], {}
        for f in sorted(common)[:3]:
            ev.extend(d[f] for d in per_leaf)
    return True, ev, caps


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
