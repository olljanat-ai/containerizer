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
  package: regex          package name; optional `version: regex` on its version (full match)
  file: glob              file name (or relative path when the glob has '/'); `skip_portable: true`
                          leaves out IL-only .NET Standard/.NET (Core) assemblies
  code: regex             source files, comments stripped; optional `in: glob`
  config: regex           configuration files; optional `in: glob`
  text: regex             any text file; optional `in: glob`
  readme: regex           repository README (repo scope)
  unguarded: true         (with code) ignore hits right after an OS check (OperatingSystem.IsWindows(),
                          IsLinux(), IsMacOS(), IsOSPlatform(...)) or a project helper whose body is
                          one, inside `if (<OS check>) {...}` / the `else` of a negated check, after
                          `if (!<OS check>) return/throw`, inside a method/type marked
                          [SupportedOSPlatform("windows"|"macos"|"linux"...)], or in a member/type
                          whose every caller (in the project and the projects referencing it) is
                          guarded, or on a P/Invoke (extern) declaration that nothing calls, or in
                          the `case <Option>.Windows:` section of a switch on a configured option;
                          a private member's callers are its calls inside its own (non-partial) type
  unguarded: callers      only the last check (for annotations on the member/type itself)
  any: [...], all: [...], not: {...}
  same_file: true         (next to `all`) the code/config/text conditions directly under the
                          `all` must all match in one and the same file; a `not: {code: ...}`
                          directly under it leaves out the files where that matches
  closure: {...}          the condition holds for the project or a project it references
  references: {...}       the condition holds for a project this one references directly
  other_project: {...}    the condition holds for some other project of the repository

`code`, `config` and `text` may use named groups; with `set` on a facts rule the
captured groups become facts (e.g. `(?P<port>\\d+)`).
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .scan import Project, Repo, read_text

SEVERITIES = ["info", "config", "refactor", "rewrite", "blocker"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
# Where learned rules are read from. A learning run points this (and verify.LEARNED, ai.LEARNED) at a
# staging copy, so what it learns waits for review instead of entering the ruleset (rulereview.py).
LEARNED_DIR = RULES_DIR / "learned"


def reviewed_dir() -> Path | None:
    """Learned rules approved in the rule review live in your own internal rules repository, never in
    this tool's: CONTAINERIZER_REVIEWED_RULES is a checkout of its rules folder, loaded with the curated rules."""
    v = (os.environ.get("CONTAINERIZER_REVIEWED_RULES") or "").strip()
    return Path(v).expanduser().resolve() if v else None


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
    dirs = dirs or [RULES_DIR, *filter(None, [reviewed_dir()]), LEARNED_DIR]
    rules: list[Rule] = []
    seen: dict[str, Rule] = {}
    for d in dirs:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            data = yaml.safe_load(f.read_text()) or {}
            for item in data.get("rules", []):
                r = Rule.from_dict(item, file=_rel(f))
                if r.id in seen:
                    # later (learned) definitions override curated ones with the same id
                    rules.remove(seen[r.id])
                seen[r.id] = r
                rules.append(r)
    return rules


def _rel(f: Path) -> str:
    try:
        return str(f.relative_to(RULES_DIR.parent))
    except ValueError:
        rd = reviewed_dir()
        if rd and f.parent == rd:       # approved rules from the internal rules repository
            return "reviewed/" + f.name
        return "rules/learned/" + f.name    # a staging copy of the learned rules (rulereview.LearningSession)


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
# (also written fully qualified, [System.Runtime.Versioning.SupportedOSPlatform("windows")], or as
# SupportedOSPlatformAttribute)
_OS_NAMES = r'(windows|macos|osx|linux|freebsd|maccatalyst|ios|android)'
SUPPORTED_WIN_RE = re.compile(r'\[\s*(?:global::)?(?:System\.Runtime\.Versioning\.)?SupportedOSPlatform(?:Attribute)?\(\s*"'
                              + _OS_NAMES + r'[^"]*"\s*\)\s*\]', re.I)
# the same attribute in Visual Basic: <SupportedOSPlatform("windows")> on the line(s) before the member
VB_SUPPORTED_WIN_RE = re.compile(r'<\s*(?:Global\.)?(?:System\.Runtime\.Versioning\.)?SupportedOSPlatform(?:Attribute)?\(\s*"'
                                 + _OS_NAMES + r'[^"]*"\s*\)\s*>\s*_?\s*', re.I)
_VB_DECL_RE = re.compile(r'(?:<[^<>\n]*>\s*_?\s*)*(?:(?:Public|Private|Friend|Protected|Shared|Overrides|Overridable|NotOverridable|MustOverride|'
                         r'Overloads|Shadows|Async|Iterator|Partial|NotInheritable|MustInherit|ReadOnly|WriteOnly|Default)\s+)*'
                         r'(Sub|Function|Property|Class|Module|Structure|Interface|Declare)\b', re.I)


def _in_vb_windows_only_member(txt: str, pos: int) -> bool:
    """VB form of _in_windows_only_member: the member or type right after <SupportedOSPlatform(...)>
    runs up to its first `End Sub` / `End Function` / `End Class` ... (a Declare statement is one
    line). Nested blocks of the same kind (a multi-line lambda) end it early, which only ever makes
    a hit count as unguarded."""
    for m in VB_SUPPORTED_WIN_RE.finditer(txt, 0, pos + 1):
        d = _VB_DECL_RE.match(txt, m.end())
        if not d:
            continue
        kind = d.group(1).lower()
        if kind == "declare":
            end = txt.find("\n", d.end())
            end = len(txt) if end < 0 else end
        else:
            e = re.compile(rf"^\s*End\s+{kind}\b", re.I | re.M).search(txt, d.end())
            end = e.end() if e else len(txt)
        if m.start() <= pos < end:
            return True
    return False


def _in_windows_only_member(txt: str, pos: int) -> bool:
    """True when pos is inside (or in the signature of) a method/type marked [SupportedOSPlatform("windows")].

    Cheap brace counting from the attribute; braces inside strings may confuse it, which
    only ever makes a hit count as unguarded."""
    if "SupportedOSPlatform" not in txt:
        return False
    if VB_SUPPORTED_WIN_RE.search(txt) and _in_vb_windows_only_member(txt, pos):
        return True
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


def _after_early_exit(txt: str, pos: int, window: int = 4000, helpers: re.Pattern | None = None) -> bool:
    if "IsWindows" not in txt and "OSPlatform.Windows" not in txt and helpers is None:
        return False
    lo = max(0, pos - window)
    rxs = [EARLY_EXIT_RE]
    if helpers is not None:
        rxs.append(re.compile(r"if\s*\(\s*!\s*(?:[\w.]+\.)?(?:" + helpers.pattern + r")(?:\s*\(\s*\))?\s*\)\s*"
                              r"(\{\s*(return|throw)\b[^;{}]*;\s*\}|(return|throw)\b[^;{}]*;)"))
    for rx in rxs:
        for m in rx.finditer(txt, lo, pos):
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


def _guarded(txt: str, pos: int, nested: bool = True, scope: "GuardScope | None" = None, file: Path | None = None) -> bool:
    """True when the match sits within a few lines after an OS check (or a call of a project
    helper whose body is one), inside the block of an `if` on an OS check (or the `else` of a
    negated one), after an early exit on a negated check, inside a member the authors marked
    [SupportedOSPlatform(...)] (callers must guard it), inside a private helper type that is only
    used from guarded code, or in a member/type whose every caller in the project and its
    dependents is guarded (see GuardScope)."""
    helpers = scope.helpers if scope is not None else None
    start = pos
    for _ in range(6):
        start = txt.rfind("\n", 0, start - 1)
        if start <= 0:
            start = 0
            break
    end = txt.find("\n", pos) if txt.find("\n", pos) > 0 else len(txt)
    if GUARD_RE.search(txt, start, end) or (helpers is not None and helpers.search(txt, start, end)):
        return True
    if _in_windows_only_member(txt, pos) or _after_early_exit(txt, pos, helpers=helpers):
        return True
    if nested and _in_guarded_private_type(txt, pos):
        return True
    if scope is None:
        return False
    if _in_guarded_block(txt, pos, helpers) or _in_unbraced_os_if(txt, pos, helpers) or _in_windows_option_case(txt, pos):
        return True
    return file is not None and scope.callers_guarded(file, txt, pos)


# --------------------------------------------------------------------------- indirect guards
#
# A Windows-only call is also guarded when
# * the check goes through a helper: `if (NativeMethods.IsAspNetCoreModuleLoaded())` where the helper
#   is a bool member of the project (or a project it references) whose body is an OS check
#   (`=> OperatingSystem.IsWindows() && ...`, `bool IsWindows { get; } = RuntimeInformation.IsOSPlatform(...)`);
# * it sits in the block of `if (<OS check> && ...) { ... }` or in the `else` of `if (!<OS check>)`;
# * every caller of the member (or every construction of the type) that holds it is guarded, e.g. a
#   DllImport whose only caller runs after `if (IsAspNetCoreModuleLoaded())`, or a class with a named
#   Semaphore that is only constructed after `if (!IsOSPlatform(Windows)) throw`. Callers are
#   searched in the project and the projects that reference it, two levels deep; a member that is
#   virtual/override, used as a method group, or a type created through DI/reflection
#   (typeof, generic arguments, a subclass) has callers we cannot see and stays unguarded.

_HELPER_DEF_RES = [
    # bool IsX => expr;  bool IsX() => expr;
    re.compile(r"\bbool\s+(\w+)\s*(?:\(\s*\))?\s*=>\s*([^;{}]{1,300});"),
    # bool IsX { get; } = expr;   static readonly bool IsX = expr;
    re.compile(r"\bbool\s+(\w+)\s*(?:\{\s*get;\s*(?:(?:private\s+|protected\s+)?(?:set|init);\s*)?\}\s*)?=\s*([^;{}=][^;{}]{0,300});"),
    # bool IsX() { return expr; }   bool IsX { get { return expr; } }   bool IsX { get => expr; }
    re.compile(r"\bbool\s+(\w+)\s*(?:\(\s*\))?\s*\{\s*(?:get\s*\{\s*)?return\s+([^;{}]{1,300});\s*\}"),
    re.compile(r"\bbool\s+(\w+)\s*\{\s*get\s*=>\s*([^;{}]{1,300});\s*\}"),
]


def _split_top(expr: str, op: str) -> list[str]:
    """Split a C# boolean expression at top-level `op` (&& or ||)."""
    parts, depth, cur, i = [], 0, "", 0
    while i < len(expr):
        ch = expr[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and expr.startswith(op, i):
            parts.append(cur)
            cur, i = "", i + 2
            continue
        cur += ch
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts]


def _strip_parens(e: str) -> str:
    e = e.strip()
    while e.startswith("(") and e.endswith(")") and _block_end_paren(e) == len(e):
        e = e[1:-1].strip()
    return e


def _block_end_paren(e: str) -> int:
    depth = 0
    for i, ch in enumerate(e):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


OS_CHECK_RE = re.compile(
    r"(?:global::)?(?:System\.)?(?:OperatingSystem\.Is(?:Windows|MacOS|Linux|FreeBSD|MacCatalyst|IOS|Android)(?:VersionAtLeast)?\([^()]*\)"
    r"|(?:(?:System\.)?(?:Runtime\.InteropServices\.)?RuntimeInformation\.)?IsOSPlatform\(\s*(?:System\.Runtime\.InteropServices\.)?OSPlatform\.(?:Windows|OSX|Linux|FreeBSD)\s*\)"
    r"|Environment\.OSVersion\.Platform\s*==\s*PlatformID\.Win32NT)")


# A branch that only runs in development (`if (env.IsDevelopment()) {...}`, the `else` of
# `if (!Debugger.IsAttached)`) is not reached by the production container either, so in the block
# form it counts like an OS check. Proximity alone (GUARD_RE) does not: `if (!env.IsDevelopment())`
# right before a hit is the production path.
DEV_CHECK_RE = re.compile(r"(?:[\w.]+\.)?(?:IsDevelopment\(\s*\)|IsDevEnvironment\b(?:\(\s*\))?)|(?:System\.Diagnostics\.)?Debugger\.IsAttached")


def _is_os_check(e: str, helpers: re.Pattern | None) -> bool:
    """`e` (one conjunct) is a positive OS check: OperatingSystem.IsWindows(), a known helper
    (or a development-only check, see DEV_CHECK_RE)."""
    e = _strip_parens(e)
    if e.startswith("!"):
        return False
    if OS_CHECK_RE.fullmatch(e) or DEV_CHECK_RE.fullmatch(e):
        return True
    return bool(helpers is not None and re.fullmatch(r"(?:[\w.]+\.)?(?:" + helpers.pattern + r")(?:\s*\(\s*\))?", e))


def _cond_implies_os(cond: str, helpers: re.Pattern | None) -> bool:
    """Every way `cond` can be true includes a positive OS check (each || part has one && part that is)."""
    return all(any(_is_os_check(c, helpers) for c in _split_top(_strip_parens(d), "&&"))
               for d in _split_top(_strip_parens(cond), "||"))


def _cond_false_implies_os(cond: str, helpers: re.Pattern | None) -> bool:
    """When `cond` is false an OS check holds: some || part is exactly `!<OS check>`."""
    for d in _split_top(_strip_parens(cond), "||"):
        d = _strip_parens(d)
        if d.startswith("!") and len(_split_top(d, "&&")) == 1 and _is_os_check(d[1:], helpers):
            return True
    return False


def _os_helper_defs(txt: str) -> dict[str, str]:
    if "bool" not in txt:
        return {}
    out = {}
    for rx in _HELPER_DEF_RES:
        for m in rx.finditer(txt):
            out.setdefault(m.group(1), m.group(2))
    return out


def _resolve_helpers(defs: dict[str, str]) -> set[str]:
    """Names whose body is an OS check, also through other helpers (`IsWin10 => IsWindows && ...`)."""
    names: set[str] = set()
    for _ in range(3):
        rx = re.compile("|".join(map(re.escape, sorted(names)))) if names else None
        new = {n for n, body in defs.items() if n not in names and
               (OS_CHECK_RE.search(body) or (rx is not None and rx.search(body))) and _cond_implies_os(body, rx)}
        if not new:
            break
        names |= new
    return names


_OPEN_HEADER_STOP = re.compile(r"[;{}]")
_CONTROL_RE = re.compile(r"^(?:else\s+)?(?:if|for|foreach|while|switch|using|lock|fixed|catch)\s*\(|^(?:else|try|finally|do|unsafe|checked|unchecked|get|set|init|add|remove)$")
_MODS = r"(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|extern|unsafe|new|partial|readonly|required|file)"
_MEMBER_HEADER_RE = re.compile(
    rf"(?:\[[^\]]*\]\s*)*(?P<mods>(?:{_MODS}\s+)*)(?:(?P<type>[\w<>\[\],.?() ]+?)\s+)?(?P<name>\w+)\s*(?:<[^<>(){{}};]*>)?\s*"
    r"(?:\((?P<params>[^;{}]*)\))?\s*(?:where\b[^{;]*)?(?::\s*(?:base|this)\s*\([^;{}]*\))?\s*(?:=>)?\s*$", re.S)
_TYPE_HEADER_RE = re.compile(rf"(?P<mods>(?:{_MODS}\s+)*)(?:class|struct|record(?:\s+(?:class|struct))?|interface)\s+(?P<name>\w+)")
_KEYWORDS = {"if", "for", "foreach", "while", "switch", "using", "lock", "fixed", "catch", "return", "new", "typeof",
             "nameof", "sizeof", "default", "when", "else", "await", "throw", "yield", "case", "in", "is", "as",
             "and", "or", "not", "out", "ref", "var", "get", "set", "init", "add", "remove", "base", "this"}


def _openers(txt: str, pos: int, limit: int = 60000) -> list[int]:
    """Positions of the unclosed '{' that enclose pos, innermost first."""
    out, depth = [], 0
    lo = max(0, pos - limit)
    i = pos - 1
    while i >= lo:
        ch = txt[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                out.append(i)
            else:
                depth -= 1
        i -= 1
    return out


def _header(txt: str, brace: int) -> tuple[str, int]:
    """The text between the previous ; { } and the '{' at `brace` (attributes and all)."""
    j = brace - 1
    depth = 0
    while j >= 0:
        ch = txt[j]
        if ch in ")]":
            depth += 1
        elif ch in "([":
            depth -= 1
        elif depth <= 0 and ch in ";{}":
            break
        j -= 1
    return txt[j + 1:brace].strip(), j + 1


@dataclass
class _Member:
    name: str
    kind: str            # method | ctor | property | type | extern
    static: bool
    type_name: str       # enclosing (or declared) type
    overridable: bool
    start: int           # declaration span in its file
    end: int
    private: bool = False  # declared `private` (not `private protected`): callable only inside its type


def _is_private(mods: str) -> bool:
    return bool(re.search(r"\bprivate\b", mods)) and not re.search(r"\bprotected\b", mods)


def _enclosing_type(txt: str, pos: int) -> tuple[str, int, int] | None:
    for b in _openers(txt, pos):
        h, hs = _header(txt, b)
        m = _TYPE_HEADER_RE.search(h)
        if m and not re.search(r"\bnew\b", h[:m.start()]):
            return m.group("name"), hs, _block_end(txt, b)
    return None


def _enclosing_member(txt: str, pos: int) -> _Member | None:
    """The method/constructor/property (or the type, for an attribute on a type) that holds pos."""
    # an attribute on a declaration: [DllImport(...)] static extern ..., [SupportedOSPlatform] class X
    stmt_end = min((i for i in (txt.find(";", pos), txt.find("{", pos)) if i >= 0), default=len(txt))
    line_start = txt.rfind("\n", 0, pos) + 1
    prefix = txt[line_start:pos].strip()
    if (prefix.startswith("[") or (not prefix and txt.startswith("[", pos))) and \
            not re.match(r"\[\s*(?:assembly|module)\s*:", (prefix or txt[pos:pos + 20]).lstrip()):
        decl = txt[pos:stmt_end]
        decl = re.sub(r"^[^\]]*\]", "", decl, count=1)
        decl = re.sub(r"^\s*(?:\[[^\]]*\]\s*)*", "", decl)
        tm = _TYPE_HEADER_RE.match(decl)
        if tm:
            body = txt.find("{", pos)
            return _Member(tm.group("name"), "type", "static" in tm.group("mods"), tm.group("name"), False,
                           pos, _block_end(txt, body) if body >= 0 else len(txt))
        mm = re.match(rf"(?P<mods>(?:{_MODS}\s+)*)[\w<>\[\],.?() ]+?\s+(?P<name>\w+)\s*\(", decl)
        if mm:
            enc = _enclosing_type(txt, pos)
            mods = mm.group("mods")
            return _Member(mm.group("name"), "extern" if "extern" in mods else "method", "static" in mods or "extern" in mods,
                           enc[0] if enc else "", bool(re.search(r"\b(virtual|override|abstract)\b", mods)), pos, stmt_end,
                           _is_private(mods))
    # expression-bodied member: ... Name(...) => <pos>
    prev = max(txt.rfind(";", 0, pos), txt.rfind("}", 0, pos), txt.rfind("{", 0, pos))
    seg = txt[prev + 1:pos]
    # inside a P/Invoke declaration itself: [DllImport("advapi32.dll")] private static extern bool LogonUser(...);
    if "extern" in txt[prev + 1:stmt_end]:
        decl = re.sub(r"^\s*(?:\[[^\]]*\]\s*)*", "", txt[prev + 1:stmt_end])
        xm = re.match(rf"(?P<mods>(?:{_MODS}\s+)*)[\w<>\[\],.?() ]+?\s+(?P<name>\w+)\s*\(", decl)
        if xm and re.search(r"\bextern\b", xm.group("mods")):
            enc = _enclosing_type(txt, pos)
            return _Member(xm.group("name"), "extern", True, enc[0] if enc else "", False, prev + 1, stmt_end,
                           _is_private(xm.group("mods")))
    em = re.search(rf"(?P<mods>(?:{_MODS}\s+)*)[\w<>\[\],.?]+\s+(?P<name>\w+)\s*(?:\((?P<params>[^;{{}}]*)\))?\s*=>", seg)
    if em and em.group("name") not in _KEYWORDS:
        enc = _enclosing_type(txt, pos)
        mods = em.group("mods")
        return _Member(em.group("name"), "method" if em.group("params") is not None else "property", "static" in mods,
                       enc[0] if enc else "", bool(re.search(r"\b(virtual|override|abstract)\b", mods)),
                       prev + 1, txt.find(";", pos) if txt.find(";", pos) >= 0 else len(txt), _is_private(mods))
    found = None
    for b in _openers(txt, pos):
        h, hs = _header(txt, b)
        flat = re.sub(r"\s+", " ", h)
        bare = flat
        for _ in range(4):
            bare = re.sub(r"\([^()]*\)", "()", bare)
        if _TYPE_HEADER_RE.search(flat) and "=" not in bare.replace("=>", ""):
            break                                    # reached the type: the outermost member found wins
        if not flat or _CONTROL_RE.search(flat) or "=" in bare.replace("=>", "") or re.search(r"\bnew\b|=>\s*$|^\(", flat):
            continue
        m = _MEMBER_HEADER_RE.fullmatch(flat)
        if not m or m.group("name") in _KEYWORDS:
            continue
        enc = _enclosing_type(txt, b)
        tname = enc[0] if enc else ""
        mods = m.group("mods") or ""
        kind = "ctor" if m.group("name") == tname and m.group("params") is not None else \
            ("method" if m.group("params") is not None else "property")
        # a local function or accessor inside a member: keep looking for the member that holds it
        found = _Member(m.group("name"), kind, "static" in mods, tname,
                        bool(re.search(r"\b(virtual|override|abstract)\b", mods)), hs, _block_end(txt, b), _is_private(mods))
    return found


# a type (or modifier) right before the name: `int Name(`, `List<T> Name(`, `T[] Name(`. The `>` of
# an expression body's `=>` is not the end of a generic type: `private int Load() => Open();` calls Open
_DECL_BEFORE_RE = re.compile(rf"(?:\b{_MODS}|[\w\]?]|(?<!=)>)\s+$")


class GuardScope:
    """What an `unguarded` check may look at beyond the file: the OS-check helpers of the project
    and the projects it references, and the source of the project and of the projects that
    reference it (where callers live)."""

    @classmethod
    def of(cls, ctx: "Context") -> "GuardScope":
        owner = ctx.project if ctx.project is not None else ctx.repo
        key = ("scope", id(owner))
        hit = _SCOPE_CACHE.get(key)
        if hit is None or hit[0] is not owner:
            if len(_SCOPE_CACHE) > 5000:
                _SCOPE_CACHE.clear()
            hit = _SCOPE_CACHE[key] = (owner, cls(ctx))
        return hit[1]

    def __init__(self, ctx: "Context"):
        self.ctx = ctx
        self.repo = ctx.repo
        self.project = ctx.project
        self._helpers: re.Pattern | None | bool = False
        self._sites: dict[str, list] = {}
        self._memo: dict = {}
        self.depth = 0

    # ---- helpers
    @property
    def helpers(self) -> re.Pattern | None:
        if self._helpers is False:
            names: set[str] = set()
            if self.project is not None:
                defs: dict[str, str] = {}
                for p in [self.project] + _ref_closure(self.repo, self.project):
                    defs.update(_project_helper_defs(p))
                names = _resolve_helpers(defs)
            self._helpers = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(names))) + r")\b") if names else None
        return self._helpers

    # ---- callers
    def _files(self) -> list[tuple[Project, Path]]:
        if self.project is None:
            return []
        key = ("files", id(self.project))
        hit = _SCOPE_CACHE.get(key)
        if hit is None or hit[0] is not self.project:
            # test projects exercise Windows-only types on Windows CI; they are not a production caller
            projs = [self.project] + [q for q in _dependents(self.repo, self.project) if not _looks_like_test(q)]
            files = [(p, f) for p in projs for f in p.files if f.suffix.lower() == ".cs"]
            hit = _SCOPE_CACHE[key] = (self.project, files)
        return hit[1]

    def sites(self, member: _Member, decl_file: Path) -> list[tuple[Project, Path, str, int]] | None:
        """Where `member` runs from: calls of a static member, constructions of the type of an
        instance member. None when some use cannot be followed."""
        construct = member.kind in ("ctor", "type") and not member.static or \
            member.kind in ("method", "property") and not member.static
        # a private method/property runs only from its own type: follow its calls in the declaring
        # file instead of the constructions of the type (a private GetImpersonatedToken() called
        # from the Windows branch of RunImpersonated: BLAZAM WindowsImpersonation.cs:29/155)
        own_file_only = False
        if member.private and member.kind in ("method", "property") and not member.overridable:
            construct, own_file_only = False, not self._in_partial_type(member, decl_file)
        name = member.type_name if construct or member.kind == "type" else member.name
        if not name:
            return None
        if member.overridable and not construct:
            return None
        out = []
        word = re.compile(rf"\b{re.escape(name)}\b")
        consts: set[str] = set()
        decl_ns, decl_types = "", set()
        # a private nested type cannot be handed out by name: every mention is inside its outer type
        private_type = False
        if construct or member.kind == "type":
            for p, f in self._files():
                if f == decl_file:
                    dtxt = p.text(f, True)
                    consts = set(re.findall(r"\bconst\s+[\w.<>\[\]?]+\s+(\w+)\s*=", dtxt))
                    ns = re.search(r"\bnamespace\s+([\w.]+)", dtxt)
                    decl_ns = ns.group(1) if ns else ""
                    decl_types = set(re.findall(r"\b(?:class|struct|record|interface)\s+(\w+)", dtxt))
                    private_type = member.kind == "type" and bool(
                        re.match(r"(?:\[[^\]]*\]\s*)*(?:\w+\s+)*?private\b", dtxt[member.start:member.start + 300]))
                    break
        for p, f in self._files():
            if own_file_only and f != decl_file:
                continue
            txt = p.text(f, True)
            if name not in txt:
                continue
            own = (member.start, member.end) if f == decl_file else None
            for m in word.finditer(txt):
                s = m.start()
                if own and own[0] <= s < own[1]:
                    continue
                before = txt[max(0, s - 80):s]
                after = txt[m.end():m.end() + 200]
                if re.search(r"\b(?:class|struct|record|interface|enum|namespace)\s+$|~\s*$", before) or \
                        re.search(r"nameof\s*\(\s*$|<see\s+cref=\"$|cref=\"[\w.]*$", before):
                    continue
                if construct or member.kind == "type":
                    q = re.search(r"([\w.]*\w)\.$", before)
                    # qualified by a namespace that is not the type's own (and not an enclosing type):
                    # another symbol of that name (Microsoft.Win32.Registry next to a Win32 class)
                    if q and not (decl_ns + ".").endswith("." + q.group(1) + ".") and decl_ns != q.group(1) \
                            and not decl_types & set(q.group(1).split(".")) \
                            or re.search(r"(?:^|\n)\s*(?:global\s+)?using\s+(?:static\s+)?(?:\w+\s*=\s*)?[\w.]*\Z", before):
                        continue
                    if re.match(r"\s*\.\s*\w+(?:\s*<[^<>;()]*>)?\s*(?:\[\s*\]\s*)?\??\s+\w+\s*[;=,)]", after):
                        continue                              # a field/local/parameter of a nested type
                    if re.search(r"\bnew\s+(?:[\w.]+\.)?$", before) and re.match(r"\s*[({]", after):
                        out.append((p, f, txt, s))            # new T(...)
                    elif (mm := re.match(r"\s*\.\s*(\w+)", after)):
                        if mm.group(1) in consts:
                            continue                          # a constant is compiled into the caller
                        out.append((p, f, txt, s))            # static member access T.Member
                    elif re.search(r"\b\w*Log\w*\s*\(\s*typeof\s*\(\s*(?:[\w.]+\.)?$", before):
                        continue                              # a logger category/tag: names the type only
                    elif re.search(r"typeof\s*\(\s*(?:[\w.]+\.)?$", before) or \
                            re.search(r"\b(?:class|struct|record)\s+\w+[^{;]*:\s*(?:[^{;]*,\s*)?(?:[\w.]+\.)?$", before):
                        return None                           # used through reflection, or subclassed
                    elif re.search(r"[<,]\s*(?:[\w.]+\.)?$", before) and re.match(r"[^<>;(){}]*>\s*\(", after) and \
                            not re.search(r"\bnew\s+[\w.]+\s*<[^<>;]*$", before):
                        if private_type:
                            out.append((p, f, txt, s))        # Deserialize<T[]>(...) inside the outer type
                            continue
                        return None                           # a generic method's type argument: AddSingleton<I, T>()
                    # other mentions (field/parameter/local types) do not run anything
                    continue
                if _DECL_BEFORE_RE.search(before) and not re.search(r"\b(?:return|await|throw|yield|else|case|in|is|as|new)\s+$", before) \
                        and re.match(r"\s*(?:<[^<>()]*>)?\s*\(", after):
                    continue                                  # another declaration (overload)
                if member.kind in ("method", "extern") and not re.match(r"\s*(?:<[^<>()]*>)?\s*\(", after):
                    if re.match(r"\s*[),;]", after) and re.search(r"(?:[(,=]|\+=)\s*(?:[\w.]+\.)?$", before):
                        return None                           # method group: the delegate's callers are unknown
                    continue                                  # a type or namespace of the same name
                out.append((p, f, txt, s))
        return out

    def _in_partial_type(self, member: _Member, decl_file: Path) -> bool:
        """The member's type is `partial` (other parts, in other files, may call its private members)."""
        for p, f in self._files():
            if f == decl_file:
                txt = p.text(f, True)
                enc = _enclosing_type(txt, member.start)
                if enc is None:
                    return True
                brace = txt.find("{", enc[1])
                return bool(re.search(r"\bpartial\b", txt[enc[1]:brace if brace >= 0 else enc[1] + 300]))
        return True

    def _mentioned_elsewhere(self, member: _Member, decl_file: Path) -> bool:
        """Whether the member's name appears anywhere outside its own declaration (a plain word
        search, so any call form `sites` does not follow still counts as a possible call)."""
        word = re.compile(rf"\b{re.escape(member.name)}\b")
        for p, f in self._files():
            txt = p.text(f, True)
            if member.name not in txt:
                continue
            for m in word.finditer(txt):
                if f == decl_file and member.start <= m.start() < member.end:
                    continue
                return True
        return False

    def callers_guarded(self, f: Path, txt: str, pos: int) -> bool:
        if self.project is None or self.depth >= 2:
            return False
        member = _enclosing_member(txt, pos)
        if member is None:
            return False
        key = (f, member.name, member.kind, member.start)
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = False                       # recursion guard
        sites = self.sites(member, f)
        ok = False
        if sites == [] and member.kind == "extern" and not self._mentioned_elsewhere(member, f):
            # a P/Invoke declaration nothing calls (NativeMethods copied in with unused entries):
            # the runtime binds the native library on the first call, so it is never loaded
            ok = True
        elif sites:
            self.depth += 1
            try:
                ok = all(_guarded(t, s, scope=self, file=sf) for _, sf, t, s in sites)
            finally:
                self.depth -= 1
        self._memo[key] = ok
        return ok


_SCOPE_CACHE: dict = {}
_HELPER_CACHE: dict = {}


def _project_helper_defs(p: Project) -> dict[str, str]:
    hit = _HELPER_CACHE.get(id(p))
    if hit is not None and hit[0] is p:
        return hit[1]
    defs: dict[str, str] = {}
    for f in p.files:
        if f.suffix.lower() == ".cs":
            t = p.text(f, True)
            if GUARD_RE.search(t):
                defs.update(_os_helper_defs(t))
    if len(_HELPER_CACHE) > 5000:
        _HELPER_CACHE.clear()
    _HELPER_CACHE[id(p)] = (p, defs)
    return defs


def _ref_closure(repo: Repo, p: Project) -> list[Project]:
    out, stack, seen = [], list(p.project_refs), set()
    while stack:
        r = stack.pop()
        if r in seen:
            continue
        seen.add(r)
        q = repo.project_by_path(r)
        if q is not None:
            out.append(q)
            stack.extend(q.project_refs)
    return out


_TEST_PKG_RE = re.compile(r"^(Microsoft\.NET\.Test\.Sdk|xunit(\.v3)?|nunit|MSTest(\.TestFramework)?|NUnit3TestAdapter|TUnit)$", re.I)
# runners/adapters: only a project that runs tests adds them (a bare xunit/nunit package may be copy-paste)
_TEST_RUNNER_PKG_RE = re.compile(r"^(Microsoft\.NET\.Test\.Sdk|xunit\.v3(\.[\w.\-]+)?|xunit\.runner\.visualstudio|MSTest(\.TestAdapter)?|NUnit3TestAdapter|TUnit(\.\w+)?)$", re.I)
_TEST_NAME_RE = re.compile(r"[.\-](Tests?|UnitTests|IntegrationTests|FunctionalTests|E2ETests|EndToEndTests|AcceptanceTests|Specs|TestAutomation)$|^(Unit)?Tests?$", re.I)


_TEST_REF_RE = re.compile(r"^(Microsoft\.VisualStudio\.QualityTools\.UnitTestFramework|Microsoft\.VisualStudio\.TestPlatform\.TestFramework"
                          r"|xunit(\.core|\.assert)?|nunit\.framework)$", re.I)
_TEST_GUID = "3ac096d0-a1c2-e12c-1390-a8335801fdab"


# test attributes (C#, VB, F#) and Gherkin feature files: the project really holds tests (see role-test)
_TEST_CODE_RE = re.compile(r"[\[<]{1,2}\s*(?:Xunit\.|NUnit\.Framework\.|Microsoft\.VisualStudio\.TestTools\.UnitTesting\.)?"
                           r"(?:Fact|Theory|Test|Tests|TestMethod|DataTestMethod|TestCase|TestCaseSource|TestClass|TestFixture|SetUp|"
                           r"OneTimeSetUp|ClassInitialize|AssemblyInitialize|Scenario)(?:Attribute)?\s*[\(\]>,]")


def _has_test_code(p: Project) -> bool:
    hit = _HELPER_CACHE.get(("testcode", id(p)))
    if hit is not None and hit[0] is p:
        return hit[1]
    ok = any(f.suffix.lower() == ".feature" for f in p.files) or any(
        f.suffix.lower() in (".cs", ".vb", ".fs") and _TEST_CODE_RE.search(p.text(f, True)) for f in p.files)
    _HELPER_CACHE[("testcode", id(p))] = (p, ok)
    return ok


def _looks_like_test(p: Project) -> bool:
    """The role-test signals (packages, assembly references, test-project GUID, IsTestProject, name),
    without running the role rules. A test framework package or assembly counts only when the
    project holds tests or is a library nothing references (role-test)."""
    if _TEST_GUID in p.type_guids or p.properties.get("IsTestProject", "").lower() == "true" or _TEST_NAME_RE.search(p.name):
        return True
    if any(_TEST_RUNNER_PKG_RE.match(n) for n in p.packages):
        return True
    if not (any(_TEST_PKG_RE.match(n) for n in p.packages) or any(_TEST_REF_RE.match(r) for r in p.references)):
        return False
    if _has_test_code(p):
        return True
    host = (p.output_type or "").lower() in ("exe", "winexe") or bool(p.sdk and re.search(r"Sdk\.(Web|Worker|Razor|BlazorWebAssembly)", p.sdk)) \
        or "349c5851-65df-11da-9384-00065b846f21" in [g.lower() for g in p.type_guids]
    return not host and not p.properties.get("ReferencedBy")


def _dependents(repo: Repo, p: Project) -> list[Project]:
    """Projects that reference p, directly or indirectly."""
    key = ("dependents", id(repo))
    hit = _SCOPE_CACHE.get(key)
    if hit is None or hit[0] is not repo:
        rev: dict[Path, list[Project]] = {}
        for q in repo.projects:
            for r in q.project_refs:
                rev.setdefault(r.resolve(), []).append(q)
        hit = _SCOPE_CACHE[key] = (repo, rev)
    rev = hit[1]
    out, stack, seen = [], [p.path.resolve()], set()
    while stack:
        k = stack.pop()
        for q in rev.get(k, []):
            if q.path.resolve() not in seen:
                seen.add(q.path.resolve())
                out.append(q)
                stack.append(q.path.resolve())
    return out


def _in_guarded_block(txt: str, pos: int, helpers: re.Pattern | None) -> bool:
    """pos is inside `if (<OS check> ...) { }` or inside the `else { }` of `if (!<OS check>) { }`."""
    for b in _openers(txt, pos, 20000):
        h, _ = _header(txt, b)
        flat = re.sub(r"\s+", " ", h)
        m = re.fullmatch(r"(?:else )?if ?\((.*)\)", flat)
        if m and _cond_implies_os(m.group(1), helpers):
            return True
        if flat == "else":
            # the if-block that this else belongs to ends right before it
            k = txt.rfind("}", 0, b)
            if k >= 0 and txt[k + 1:b].strip() == "else":
                ob = _matching_open(txt, k)
                if ob is not None:
                    h2 = re.sub(r"\s+", " ", _header(txt, ob)[0])
                    m2 = re.fullmatch(r"(?:else )?if ?\((.*)\)", h2)
                    if m2 and _cond_false_implies_os(m2.group(1), helpers):
                        return True
        if _TYPE_HEADER_RE.search(flat):
            break
    return False


_IF_RE = re.compile(r"\bif\s*\(")
_SWITCH_LABEL_RE = re.compile(r"\b(?:case\s+(?P<label>[^:;{}]+?)|default)\s*:(?!:)")
_WINDOWS_OPTION_RE = re.compile(r"(?:[\w.]+\.)?Windows\w*")


def _in_windows_option_case(txt: str, pos: int) -> bool:
    """pos is in the `case <Enum>.Windows...:` section of a switch: an option the deployment picks
    in configuration (`case DataProtectionProtectionType.Windows: ProtectKeysWithDpapi()` next to
    Certificate/None choices, financial-app AppBuilderExtensions.cs:46). A Linux deployment
    configures one of the other choices, as with an OS check; cfg-windows-option-switch notes it."""
    if "case" not in txt or "Windows" not in txt:
        return False
    for b in _openers(txt, pos, 20000):
        h, _ = _header(txt, b)
        flat = re.sub(r"\s+", " ", h)
        if re.fullmatch(r"switch ?\(.*\)", flat):
            last = None
            for m in _SWITCH_LABEL_RE.finditer(txt, b, pos):
                seg = txt[b + 1:m.start()]
                if seg.count("{") - seg.count("}") == 0:      # a label of this switch, not a nested one
                    last = m
            return bool(last and last.group("label") and _WINDOWS_OPTION_RE.fullmatch(last.group("label").strip()))
        if _TYPE_HEADER_RE.search(flat):
            break
    return False


def _in_unbraced_os_if(txt: str, pos: int, helpers: re.Pattern | None, window: int = 3000) -> bool:
    """pos is inside the single statement of a brace-less `if (<OS check>) statement;` that spans
    more lines than the proximity check covers (`if (IsWindows()) return mode switch { ... };`)."""
    for m in _IF_RE.finditer(txt, max(0, pos - window), pos):
        depth, i = 1, m.end()
        while i < pos and depth:
            depth += {"(": 1, ")": -1}.get(txt[i], 0)
            i += 1
        if depth or not _cond_implies_os(txt[m.end():i - 1], helpers):
            continue
        j = i
        while j < pos and txt[j].isspace():
            j += 1
        if j >= pos or txt[j] == "{":
            continue
        depth = 0                                     # the statement ends at its first top-level ';'
        for k in range(j, pos):
            c = txt[k]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif c == ";" and depth == 0:
                break
        else:
            return True
    return False


def _matching_open(txt: str, close: int) -> int | None:
    depth = 0
    for i in range(close, -1, -1):
        if txt[i] == "}":
            depth += 1
        elif txt[i] == "{":
            depth -= 1
            if depth == 0:
                return i
    return None


def _search_files(ctx: Context, pattern: str, files: list[Path], strip: bool, max_hits: int | None = 3,
                  skip_guarded: bool | str = False):
    """skip_guarded: True skips hits that _guarded() accepts; "callers" skips only hits whose
    member/type is used exclusively from guarded code (for an annotation such as
    [SupportedOSPlatform("windows")] on a type, which is trivially "inside" itself)."""
    rx = _rx(pattern)
    hits: list[Evidence] = []
    caps: dict = {}
    scope = GuardScope.of(ctx) if skip_guarded else None
    for f in files:
        txt = ctx.text(f, strip)
        if not txt:
            continue
        m = None
        for cand in rx.finditer(txt):
            if skip_guarded == "callers":
                if f.suffix.lower() == ".cs" and scope.callers_guarded(f, txt, cand.start()):
                    continue
            elif skip_guarded and _guarded(txt, cand.start(), scope=scope, file=f if f.suffix.lower() == ".cs" else None):
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
    keys = [k for k in cond.keys() if k not in ("in", "max", "unguarded", "same_file", "skip_portable", "version")]
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
                                   skip_guarded=_unguarded_mode(cond))
        return bool(hits), hits, caps
    if key == "file":
        globs = val if isinstance(val, list) else [val]
        hits = [Evidence(ctx.repo.rel(f)) for f in ctx.files()
                if any(_glob_match(ctx.repo.rel(f), f.name, g) for g in globs)
                and not (cond.get("skip_portable") and _portable_assembly(f))]
        return bool(hits), hits[:3], {}
    if key == "role":
        return bool(_rx(f"^(?:{val})$").search(ctx.role or "")), [], {}
    if key == "references":
        # the condition holds for a project this one references directly (ProjectReference)
        if p is None:
            return False, [], {}
        for r in p.project_refs:
            q = ctx.repo.project_by_path(r)
            if q is not None and q is not p:
                ok, e, c = evaluate(val, Context(ctx.repo, q, ""))
                if ok:
                    return True, e, c
        return False, [], {}
    if key == "closure":
        # the condition holds for the project or for a project it references (directly or not)
        if p is None:
            return False, [], {}
        for q in [p] + _ref_closure(ctx.repo, p):
            ok, e, c = evaluate(val, ctx if q is p else Context(ctx.repo, q, "library"))
            if ok:
                return True, e, c
        return False, [], {}
    if key == "other_project":
        # the condition holds for another project of the repository (keep it to cheap
        # project-file primitives: it is evaluated against every project)
        for q in ctx.repo.projects:
            if q is not p:
                ok, e, c = evaluate(val, Context(ctx.repo, q, ""))
                if ok:
                    return True, e, c
        return False, [], {}
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
        if cond.get("version"):
            hits = [n for n in hits if _rx(f"^(?:{cond['version']})$").search(p.packages[n] or "")]
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


@lru_cache(maxsize=4096)
def _portable_assembly(f: Path) -> bool:
    """A checked-in .dll that is an IL-only managed assembly (CLI header with COMIMAGE_FLAGS_ILONLY,
    no 32BITREQUIRED) built for .NET Standard or .NET (Core): it loads on Linux like a NuGet package
    would (Pleasanter App_Data/Licenses/Implem.License.dll, .NETStandard 2.0). Native, mixed-mode
    (C++/CLI), x86-only and .NET Framework assemblies are not portable."""
    import struct
    try:
        data = f.read_bytes()
        if len(data) < 0x200 or data[:2] != b"MZ":
            return False
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return False
        nsec, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        dirs = opt + (96 if magic == 0x10B else 112)
        clr_rva, clr_size = struct.unpack_from("<II", data, dirs + 14 * 8)
        if not clr_rva or not clr_size:
            return False
        off = None
        for i in range(nsec):
            sh = opt + opt_size + i * 40
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, sh + 8)
            if va <= clr_rva < va + max(vsize, rawsize):
                off = clr_rva - va + raw
                break
        if off is None:
            return False
        flags = struct.unpack_from("<I", data, off + 16)[0]
        if not flags & 0x1 or flags & 0x2:
            return False
        return b".NETStandard,Version=" in data or b".NETCoreApp,Version=" in data
    except (OSError, struct.error):
        return False


def _unguarded_mode(cond: dict) -> bool | str:
    v = cond.get("unguarded")
    return "callers" if v == "callers" else bool(v)


def _eval_all_same_file(subs: list, ctx: Context):
    """`all` with same_file: every code/config/text leaf must hit one common file."""
    ev, caps = [], {}
    per_leaf: list[dict[str, Evidence]] = []
    excluded: set[str] = set()
    for sub in subs:
        neg = isinstance(sub, dict) and list(sub) == ["not"] and isinstance(sub["not"], dict) and \
            [k for k in sub["not"] if k in TEXT_KEYS]
        if neg and len([k for k in sub["not"] if k not in ("in", "max", "unguarded")]) == 1:
            # `not: {code: ...}` under same_file: leave out the files where it matches
            key, n = neg[0], sub["not"]
            hits, _ = _search_files(ctx, n[key], _candidate_files(ctx, key, n.get("in")),
                                    strip=(key in ("code", "config")), max_hits=None)
            excluded |= {h.file for h in hits}
            continue
        leaf = isinstance(sub, dict) and [k for k in sub if k in TEXT_KEYS]
        if leaf and len([k for k in sub if k not in ("in", "max", "unguarded")]) == 1:
            key = leaf[0]
            files = _candidate_files(ctx, key, sub.get("in"))
            hits, _ = _search_files(ctx, sub[key], files, strip=(key in ("code", "config")), max_hits=None,
                                    skip_guarded=_unguarded_mode(sub))
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
        common -= excluded
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
