"""Repository scanner: turns a source tree into structured facts.

The scanner never executes anything from the scanned repository. It only reads
files and builds a `Repo` with one `Project` per buildable unit (.NET project
files, Node packages, Python/Java/Go modules) plus repository-wide facts.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "bin", "obj", "packages", ".vs", "dist", "__pycache__",
             ".venv", "venv", "target", ".idea", "TestResults"}
SOURCE_EXT = {".cs", ".vb", ".fs", ".cshtml", ".vbhtml", ".razor", ".aspx", ".ascx", ".asmx",
              ".svc", ".asax", ".master", ".ashx", ".ts", ".js", ".py", ".java", ".go", ".ps1",
              ".psm1", ".xaml", ".tt"}
CONFIG_PATTERNS = ["*.config", "appsettings*.json", "launchSettings.json", "*.settings",
                   "hosting.json", "*.xml", "*.json", "*.yaml", "*.yml", "*.ini", "*.properties"]
MAX_FILE_BYTES = 512 * 1024
WEB_APP_GUID = "349c5851-65df-11da-9384-00065b846f21"
DOTNET_PROJ_EXT = (".csproj", ".vbproj", ".fsproj")
OTHER_PROJ_EXT = (".btproj", ".sqlproj", ".dtproj", ".wixproj", ".rptproj", ".ccproj", ".sfproj")


@dataclass
class Project:
    path: Path                      # project file (or manifest) path
    root: Path                      # repository root
    kind_hint: str = "dotnet"       # dotnet | node | python | java | go | biztalk | sql | ...
    name: str = ""
    sdk: str = ""
    tfms: list[str] = field(default_factory=list)
    output_type: str = ""
    assembly_name: str = ""
    sdk_style: bool = True
    packages: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    framework_refs: list[str] = field(default_factory=list)
    project_refs: list[Path] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)
    type_guids: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)          # all files that belong to the project
    manifest: dict = field(default_factory=dict)             # package.json etc.
    # items that only some target frameworks get (a Condition on '$(TargetFramework)'):
    # ("package"|"reference"|"framework"|"project", name or resolved path) -> those TFMs
    tfm_items: dict = field(default_factory=dict, repr=False)
    defines: set = field(default_factory=set, repr=False)    # DefineConstants symbols (any configuration)
    tfm_files: dict = field(default_factory=dict, repr=False)  # .cs file -> the TFMs that compile it (when not all)
    compile_items: list = field(default_factory=list, repr=False)  # (Include|Remove, glob, condition chain)
    tfm_props: dict = field(default_factory=dict, repr=False)  # properties that name TFMs (for conditions)
    view_of: object = field(default=None, repr=False, compare=False)   # the full project of a per-TFM view
    _text_cache: dict = field(default_factory=dict, repr=False)

    @property
    def dir(self) -> Path:
        return self.path.parent

    @property
    def rel(self) -> str:
        return str(self.path.relative_to(self.root))

    @property
    def rel_dir(self) -> str:
        r = str(self.dir.relative_to(self.root))
        return "." if r == "" else r

    def rel_file(self, p: Path) -> str:
        return str(p.relative_to(self.root))

    def text(self, p: Path, strip_comments: bool = False) -> str:
        """File text; with strip_comments, C# code also loses the `#if` branches that none of
        the project's target frameworks compile."""
        key = (p, strip_comments, tuple(self.tfms))
        if key not in self._text_cache:
            txt = read_text(p, strip_comments)
            if strip_comments and self.kind_hint == "dotnet" and p.suffix.lower() == ".cs":
                txt = strip_inactive_branches(txt, self.tfms, self.sdk_style, self.defines)
            self._text_cache[key] = txt
        return self._text_cache[key]

    def view(self, tfms: list[str]) -> "Project":
        """This project as compiled for a subset of its target frameworks: only the packages,
        references and project references those TFMs get (a consumer on net8.0 of a
        net472;net8.0 library does not get its net472-only System.Web reference)."""
        tfms = [t for t in self.tfms if t in tfms]
        if not tfms or tfms == self.tfms:
            return self
        keep = lambda kind, key: (s := self.tfm_items.get((kind, key))) is None or bool(s & set(tfms))
        return replace(self, tfms=tfms, view_of=self, _text_cache=self._text_cache,
                       files=[f for f in self.files if (s := self.tfm_files.get(f)) is None or bool(s & set(tfms))],
                       packages={k: v for k, v in self.packages.items() if keep("package", k)},
                       references=[r for r in self.references if keep("reference", r)],
                       framework_refs=[r for r in self.framework_refs if keep("framework", r)],
                       project_refs=[r for r in self.project_refs if keep("project", r)])

    def refs_for(self, tfms: list[str]) -> list[Path]:
        """Project references that at least one of `tfms` gets."""
        return [r for r in self.project_refs
                if (s := self.tfm_items.get(("project", r))) is None or bool(s & set(tfms))]

    def source_files(self) -> list[Path]:
        return [f for f in self.files if f.suffix.lower() in SOURCE_EXT]

    def config_files(self) -> list[Path]:
        return [f for f in self.files if any(fnmatch.fnmatch(f.name.lower(), pat.lower()) for pat in CONFIG_PATTERNS)
                and f.suffix.lower() not in DOTNET_PROJ_EXT]

    @property
    def is_netfx(self) -> bool:
        return any(is_netfx_tfm(t) for t in self.tfms) and not any(is_core_tfm(t) for t in self.tfms)

    @property
    def is_core(self) -> bool:
        return any(is_core_tfm(t) for t in self.tfms)

    def best_core_tfm(self) -> str | None:
        cores = [t for t in self.tfms if is_core_tfm(t) and not t.startswith("netstandard")]
        if not cores:
            return None
        return max(cores, key=tfm_version)


@dataclass
class Repo:
    root: Path
    name: str
    projects: list[Project]
    files: list[Path]
    readme: str
    solution_files: list[Path]
    _by_path: dict = field(default_factory=dict, repr=False)
    _rel_cache: dict = field(default_factory=dict, repr=False)

    def project_by_path(self, p: Path) -> Project | None:
        if not self._by_path:
            self._by_path = {pr.path.resolve(): pr for pr in self.projects}
        return self._by_path.get(p.resolve())

    def rel(self, p: Path) -> str:
        r = self._rel_cache.get(p)
        if r is None:
            r = self._rel_cache[p] = str(p.relative_to(self.root))
        return r


# ---------------------------------------------------------------------------
# helpers

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def read_text(p: Path, strip_comments: bool = False) -> str:
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return ""
        data = p.read_bytes()
    except OSError:
        return ""
    if b"\0" in data[:4096]:
        return ""
    txt = data.decode("utf-8", errors="replace").lstrip("﻿")
    if strip_comments:
        ext = p.suffix.lower()
        if ext in (".cs", ".fs", ".java", ".go", ".ts", ".js"):
            # keep string literals containing // (urls) mostly intact: only strip when
            # the // is not inside a quote on that line - cheap heuristic
            txt = _strip_c_comments(txt)
        elif ext in (".config", ".xml", ".csproj", ".vbproj", ".aspx", ".ascx", ".master", ".cshtml"):
            txt = _XML_COMMENT_RE.sub("", txt)
        elif ext == ".vb":
            txt = re.sub(r"(?m)^\s*'[^\n]*", "", txt)
        elif ext in (".py", ".ps1", ".psm1", ".ini", ".yaml", ".yml", ".properties"):
            txt = re.sub(r"(?m)^\s*#[^\n]*", "", txt)
        elif ext == ".json":
            # JSON with comments (appsettings): only whole-line comments, so URLs stay intact
            txt = re.sub(r"(?m)^\s*//[^\n]*", "", txt)
    return txt


def _strip_c_comments(txt: str) -> str:
    out = []
    i, n = 0, len(txt)
    in_str: str | None = None
    verbatim = False
    while i < n:
        c = txt[i]
        if in_str:
            out.append(c)
            if c == "\\" and not verbatim and i + 1 < n:
                out.append(txt[i + 1])
                i += 2
                continue
            if c == in_str:
                if verbatim and i + 1 < n and txt[i + 1] == '"':
                    out.append('"')
                    i += 2
                    continue
                in_str = None
            elif c == "\n" and not verbatim:
                in_str = None
            i += 1
            continue
        if c == "/" and i + 1 < n and txt[i + 1] == "/":
            j = txt.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and txt[i + 1] == "*":
            j = txt.find("*/", i + 2)
            seg = txt[i:(n if j < 0 else j + 2)]
            out.append("\n" * seg.count("\n"))
            i = n if j < 0 else j + 2
            continue
        if c in "\"'":
            verbatim = c == '"' and i > 0 and txt[i - 1] == "@" or (i > 1 and txt[i - 2:i] in ("@$", "$@"))
            in_str = c
        out.append(c)
        i += 1
    return "".join(out)


def is_netfx_tfm(t: str) -> bool:
    t = t.lower()
    return bool(re.fullmatch(r"net[1-4]\d{1,2}(-.*)?", t)) or t.startswith("v") and t[1:2] in "1234"


def is_core_tfm(t: str) -> bool:
    t = t.lower()
    return t.startswith("netcoreapp") or t.startswith("netstandard") or bool(re.fullmatch(r"net([5-9]|\d\d)\.\d+(-.*)?", t))


def tfm_version(t: str) -> float:
    m = re.search(r"(\d+)\.(\d+)", t)
    if m:
        return float(f"{m.group(1)}.{m.group(2)}")
    m = re.fullmatch(r"net(\d)(\d)(\d)?", t)
    if m:
        return float(f"{m.group(1)}.{m.group(2)}{m.group(3) or ''}")
    return 0.0


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _framework_version_to_tfm(v: str) -> str:
    v = v.strip().lstrip("vV")
    return "net" + v.replace(".", "")


XAMARIN_ANDROID_GUID = "efba0ad7-5a72-4c68-af49-83d382785dcf"


def _legacy_tfm(props: dict[str, str], type_guids: list[str]) -> str:
    """TFM of an old-style project from TargetFrameworkVersion. Xamarin.Android projects use it for
    the Android API level (v9.0 = MonoAndroid9.0), which is not a .NET Framework version: v4.4
    must not read as net44."""
    v = props["TargetFrameworkVersion"].strip().lstrip("vV")
    ident = props.get("TargetFrameworkIdentifier", "")
    if ident.lower() == "monoandroid" or XAMARIN_ANDROID_GUID in type_guids or \
            props.get("AndroidApplication", "").lower() == "true":
        return "monoandroid" + v
    return _framework_version_to_tfm(v)


# --------------------------------------------------------------------------- target-framework evaluation

def tfm_info(t: str) -> tuple[str, tuple, str]:
    """(family, version, platform) of a TFM: family fx (.NET Framework), core (.NET Core / .NET 5+),
    std (.NET Standard) or '' when unknown; platform is the OS suffix of net5.0-windows etc."""
    t = t.lower().strip()
    base, _, plat = t.partition("-")
    plat = re.sub(r"[\d.]+$", "", plat)
    m = re.fullmatch(r"netcoreapp(\d+)\.(\d+)", base)
    if m:
        return "core", (int(m.group(1)), int(m.group(2))), plat
    m = re.fullmatch(r"netstandard(\d+)\.(\d+)", base)
    if m:
        return "std", (int(m.group(1)), int(m.group(2))), plat
    m = re.fullmatch(r"net(\d+)\.(\d+)", base)
    if m:
        return "core", (int(m.group(1)), int(m.group(2))), plat
    m = re.fullmatch(r"net([1-4])(\d)(\d)?", base)
    if m:
        return "fx", tuple(int(g) for g in m.groups() if g is not None), plat
    m = re.fullmatch(r"v([1-4])\.(\d)(?:\.(\d))?", base)
    if m:
        return "fx", tuple(int(g) for g in m.groups() if g is not None), plat
    return "", (), plat


def tfm_compatible(consumer: str, lib: str) -> bool | None:
    """Whether a project targeting `consumer` can reference one built for `lib` (None: unknown TFM)."""
    fam, ver, plat = tfm_info(consumer)
    f, v, p = tfm_info(lib)
    if not fam or not f:
        return None
    if p and p != plat:
        return False
    if fam == "core":
        return (f == "core" and v <= ver) or (f == "std" and v <= ((2, 1) if ver >= (3, 0) else (2, 0)))
    if fam == "fx":
        return (f == "fx" and v <= ver) or (f == "std" and v <= ((2, 0) if ver >= (4, 6, 1) else (1, 6)))
    return f == "std" and v <= ver


def nearest_tfms(consumer: list[str], lib: list[str]) -> list[str]:
    """The target frameworks of a multi-targeted library that a consumer with `consumer` TFMs
    compiles against (NuGet's nearest-framework choice, simplified: same framework family first,
    then the highest compatible version). Unknown or incompatible combinations give all of the
    library's TFMs, so nothing is dropped by mistake."""
    if len(lib) <= 1 or not consumer:
        return list(lib)
    out: list[str] = []
    for c in consumer:
        cands = [t for t in lib if tfm_compatible(c, t)]
        if not cands or any(tfm_compatible(c, t) is None for t in lib):
            return list(lib)
        fam = tfm_info(c)[0]
        out.append(max(cands, key=lambda t: (tfm_info(t)[0] == fam, tfm_info(t)[1], bool(tfm_info(t)[2]))))
    return list(dict.fromkeys(out))


def _tfm_vars(t: str, sdk_style: bool) -> dict[str, str]:
    """MSBuild properties derived from one target framework (only what is certain)."""
    fam, ver, plat = tfm_info(t)
    v: dict[str, str] = {}
    if sdk_style:
        v["TargetFramework"] = t
        v["TargetPlatformIdentifier"] = plat
    if fam:
        v["TargetFrameworkIdentifier"] = {"fx": ".NETFramework", "core": ".NETCoreApp", "std": ".NETStandard"}[fam]
        v["TargetFrameworkVersion"] = "v" + ".".join(str(x) for x in ver)
    return v


def _split_balanced(s: str, i: int) -> int:
    """Index just after the ')' matching the '(' at s[i] (quotes inside are skipped)."""
    depth, q = 0, None
    while i < len(s):
        ch = s[i]
        if q:
            if ch == q:
                q = None
        elif ch in "'\"`":
            q = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(s)


def _args(s: str) -> list[str]:
    out, cur, depth, q = [], "", 0, None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "'\"`":
            q = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _unquote(s: str) -> str:
    s = s.strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"`" else s


def _expand_cond(s: str, tv: dict[str, str]) -> str | None:
    """Expand $(...) in a condition operand with the TFM-derived properties; None when anything
    else (another property, an item list, an unknown function) is involved."""
    out, i = [], 0
    while i < len(s):
        if s.startswith("$(", i):
            j = _split_balanced(s, i + 1)
            val = _eval_prop(s[i + 2:j - 1], tv)
            if val is None:
                return None
            out.append(val)
            i = j
        elif s.startswith(("@(", "%("), i):
            return None
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _eval_prop(body: str, tv: dict[str, str]) -> str | None:
    body = body.strip()
    m = re.fullmatch(r"(\w+)", body)
    if m:
        return tv.get(m.group(1))
    m = re.fullmatch(r"(\w+)\.(\w+)\((.*)\)", body, re.S)
    if m:                                    # $(TargetFramework.StartsWith('net4'))
        base = tv.get(m.group(1))
        args = [_expand_cond(_unquote(a), tv) for a in _args(m.group(3))]
        if base is None or any(a is None for a in args):
            return None
        fn, b = m.group(2).lower(), base.lower()
        if fn in ("startswith", "endswith", "contains") and len(args) == 1:
            a = args[0].lower()
            return str({"startswith": b.startswith, "endswith": b.endswith, "contains": b.__contains__}[fn](a)).lower()
        if fn in ("tolower", "tolowerinvariant"):
            return b
        return None
    m = re.fullmatch(r"\[MSBuild\]::(\w+)\((.*)\)", body, re.S | re.I)
    if m:
        args = [_expand_cond(_unquote(a), tv) for a in _args(m.group(2))]
        if any(a is None for a in args):
            return None
        fn = m.group(1).lower()
        if fn in ("gettargetframeworkidentifier", "gettargetplatformidentifier", "gettargetframeworkversion") and args:
            v = _tfm_vars(args[0], True)
            if fn == "gettargetplatformidentifier":
                return v.get("TargetPlatformIdentifier")
            if fn == "gettargetframeworkidentifier":
                return v.get("TargetFrameworkIdentifier")
            fv = v.get("TargetFrameworkVersion")
            return fv[1:] if fv else None
        if fn == "istargetframeworkcompatible" and len(args) == 2:
            r = tfm_compatible(args[0], args[1])
            return None if r is None else str(r).lower()
        return None
    return None


_COND_TOKEN_RE = re.compile(r"\s*(==|!=|<=|>=|<|>|!|\(|\)|(?i:and|or)\b)")


def _tokens(s: str) -> list[tuple[str, str]] | None:
    toks, i = [], 0
    while i < len(s):
        if s[i].isspace():
            i += 1
            continue
        if s[i] in "'\"`":
            j, depth = i + 1, 0
            while j < len(s):
                if s.startswith("$(", j) or s.startswith("@(", j) or s.startswith("%(", j):
                    j = _split_balanced(s, j + 1)
                    continue
                if s[j] == s[i]:
                    break
                j += 1
            toks.append(("str", s[i + 1:j]))
            i = j + 1
            continue
        m = _COND_TOKEN_RE.match(s, i)
        if m and m.start(1) == i:
            toks.append(("op", m.group(1).lower()))
            i = m.end()
            continue
        if s.startswith("$(", i):
            j = _split_balanced(s, i + 1)
            toks.append(("str", s[i:j]))
            i = j
            continue
        m = re.match(r"[\w.\-]+", s[i:])
        if not m:
            return None
        j = i + m.end()
        if j < len(s) and s[j] == "(":         # Exists('...'), HasTrailingSlash(...)
            j = _split_balanced(s, j)
            toks.append(("fn", s[i:j]))
        else:
            toks.append(("str", m.group(0)))
        i = j
    return toks


def _version(s: str):
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", s.strip(), re.I)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _kleene_not(a):
    return None if a is None else not a


def _kleene_and(a, b):
    if a is False or b is False:
        return False
    return None if a is None or b is None else True


def _kleene_or(a, b):
    if a is True or b is True:
        return True
    return None if a is None or b is None else False


def eval_condition(cond: str, tv: dict[str, str]):
    """Evaluate an MSBuild Condition with only the target-framework properties known:
    True, False, or None when it depends on anything else (Configuration, Exists(), ...)."""
    toks = _tokens(cond)
    if toks is None:
        return None
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else ("", "")

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def operand():
        kind, val = take()
        if kind == "fn":
            return ("unknown", None)
        if kind == "str":
            return ("val", _expand_cond(val, tv))
        raise ValueError("operand")

    def primary():
        k, v = peek()
        if (k, v) == ("op", "!"):
            take()
            return _kleene_not(primary())
        if (k, v) == ("op", "("):
            take()
            r = disj()
            if take() != ("op", ")"):
                raise ValueError(")")
            return r
        kind, a = operand()
        k2, op = peek()
        if k2 == "op" and op in ("==", "!=", "<", ">", "<=", ">="):
            take()
            _, b = operand()
            if kind == "unknown" or a is None or b is None:
                return None
            if op in ("==", "!="):
                return (a.strip().lower() == b.strip().lower()) == (op == "==")
            va, vb = _version(a), _version(b)
            if va is None or vb is None:
                return None
            return {"<": va < vb, ">": va > vb, "<=": va <= vb, ">=": va >= vb}[op]
        if kind == "unknown" or a is None:
            return None
        return {"true": True, "false": False}.get(a.strip().lower())

    def conj():
        r = primary()
        while peek() == ("op", "and"):
            take()
            r = _kleene_and(r, primary())
        return r

    def disj():
        r = conj()
        while peek() == ("op", "or"):
            take()
            r = _kleene_or(r, conj())
        return r

    try:
        r = disj()
        return r if pos == len(toks) else None
    except (ValueError, IndexError):
        return None


def tfm_valued_props(props: dict[str, str], fixed: set) -> dict[str, str]:
    """Unconditionally set properties whose value names target frameworks (SAMPLES_TFM=net10.0,
    DefaultTargetFramework=net8.0): conditions compare $(TargetFramework) with them. Other
    properties (Configuration, Platform, RuntimeIdentifier) are set per build and stay unknown."""
    return {k: v for k, v in props.items() if k in fixed and "$(" not in v
            and re.fullmatch(r"\s*(?:net[\w.\-]*)(?:\s*;\s*net[\w.\-]*)*\s*", v, re.I)}


def applies_to_tfms(chain: tuple, tfms: list[str], sdk_style: bool, known: dict | None = None) -> set[str] | None:
    """The TFMs for which every condition in `chain` can hold (None: all of them)."""
    conds = [c for c in chain if c and re.search(r"TargetFramework|TargetPlatform", c, re.I)]
    if not conds or not tfms:
        return None
    ok = set()
    for t in tfms:
        tv = {**(known or {}), **_tfm_vars(t, sdk_style)}
        r = True
        for c in conds:
            r = _kleene_and(r, eval_condition(c, tv))
        if r is not False:
            ok.add(t)
    return None if ok == set(tfms) else ok


# --------------------------------------------------------------------------- C# preprocessor

# symbols of platforms that no current SDK defines implicitly: inactive unless a project defines them
_LEGACY_SYMBOL_RE = re.compile(r"NETCF(_\w+)?|MONO(_\w+)?|SSCLI|CLI_1_0|SILVERLIGHT(_\w+)?|WINDOWS_PHONE(_APP)?|WINDOWS_UWP|NETFX_CORE")
_PLATFORM_SYMBOLS = {"WINDOWS", "ANDROID", "IOS", "MACCATALYST", "MACOS", "TVOS", "BROWSER", "WASI"}


def preprocessor_symbol(sym: str, t: str, sdk_style: bool, defines: set[str]):
    """Whether a C# preprocessor symbol is defined when building for TFM `t`: True, False, or
    None (unknown: a configuration-specific DefineConstants, or a symbol we know nothing about)."""
    if sym in defines:
        return None
    fam, ver, plat = tfm_info(t)
    if _LEGACY_SYMBOL_RE.fullmatch(sym):
        return False
    if not fam:
        return None
    m = re.fullmatch(r"(NETCOREAPP|NETSTANDARD|NET|NETFRAMEWORK)(?:(\d+)(?:_(\d+))?)?(_OR_GREATER)?", sym)
    if m:
        kind, a, b, ge = m.groups()
        if a is None and ge:
            return None
        if fam != "fx" and not sdk_style:
            return None
        if fam == "fx" and not sdk_style:
            # old-style projects define no implicit symbols, but some import props that do
            return False if kind in ("NETCOREAPP", "NETSTANDARD") or (kind == "NET" and (a is None or b is not None)) else None
        if a is None:
            return {"NETFRAMEWORK": fam == "fx", "NETSTANDARD": fam == "std", "NETCOREAPP": fam == "core",
                    "NET": fam == "core" and ver >= (5, 0)}[kind]
        if kind == "NETFRAMEWORK":
            return None
        if kind == "NET" and b is None and len(a) >= 2 and a[0] in "1234":
            want_fam, want = "fx", tuple(int(x) for x in a)            # NET48, NET472
        elif kind == "NET" and b is None:
            return None
        elif kind == "NET":
            want_fam, want = "core5", (int(a), int(b or 0))            # NET8_0
        elif kind == "NETCOREAPP":
            want_fam, want = "coreapp", (int(a), int(b or 0))
        else:
            want_fam, want = "std", (int(a), int(b or 0))
        if want_fam == "fx":
            return fam == "fx" and (ver >= want if ge else ver == want)
        if want_fam == "std":
            return fam == "std" and (ver >= want if ge else ver == want)
        if want_fam == "coreapp":     # .NET 5+ also defines NETCOREAPPx_y_OR_GREATER
            return fam == "core" and (ver >= want if ge else ver == want and ver < (5, 0))
        return fam == "core" and ver >= (5, 0) and (ver >= want if ge else ver == want)
    if sym in _PLATFORM_SYMBOLS:
        return plat == sym.lower() if sdk_style or plat else False
    m = re.fullmatch(r"([A-Z]+)\d+(_\d+)*(_OR_GREATER)?", sym)
    if m and m.group(1) in _PLATFORM_SYMBOLS:
        return False if plat != m.group(1).lower() else None
    return None


_PP_TOKEN_RE = re.compile(r"\s*(\|\||&&|==|!=|!|\(|\)|[A-Za-z_]\w*)")


def _eval_pp(expr: str, value) -> object:
    expr = re.sub(r"//.*$", "", expr).strip()
    toks, i = [], 0
    while i < len(expr):
        m = _PP_TOKEN_RE.match(expr, i)
        if not m:
            if expr[i:].strip() == "":
                break
            return None
        toks.append(m.group(1))
        i = m.end()
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else ""

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def primary():
        t = take()
        if t == "!":
            return _kleene_not(primary())
        if t == "(":
            r = disj()
            if take() != ")":
                raise ValueError
            return r
        if t in ("true", "false"):
            return t == "true"
        if re.fullmatch(r"[A-Za-z_]\w*", t):
            return value(t)
        raise ValueError

    def eq():
        r = primary()
        while peek() in ("==", "!="):
            op = take()
            b = primary()
            r = None if r is None or b is None else ((r == b) == (op == "=="))
        return r

    def conj():
        r = eq()
        while peek() == "&&":
            take()
            r = _kleene_and(r, eq())
        return r

    def disj():
        r = conj()
        while peek() == "||":
            take()
            r = _kleene_or(r, conj())
        return r

    try:
        r = disj()
        return r if pos == len(toks) else None
    except (ValueError, IndexError):
        return None


_PP_LINE_RE = re.compile(r"^[ \t]*#[ \t]*(if|elif|else|endif|define|undef)\b(.*)$")


def strip_inactive_branches(txt: str, tfms: list[str], sdk_style: bool, defines: set[str]) -> str:
    """Blank the lines of `#if` branches that no target framework of the project compiles, so a
    `#if NETCF` P/Invoke into CoreDll.dll does not count for a net48 build. Unknown symbols and
    configuration-specific DefineConstants count as possibly defined (the branch stays). Line
    numbers are preserved; unbalanced directives leave the text unchanged."""
    if "#" not in txt or not tfms or not re.search(r"^[ \t]*#[ \t]*if\b", txt, re.M):
        return txt
    lines = txt.split("\n")
    local = {}                    # #define / #undef in the file itself make a symbol unknown
    for ln in lines:
        m = _PP_LINE_RE.match(ln)
        if m and m.group(1) in ("define", "undef"):
            local[m.group(2).strip().split()[0] if m.group(2).strip() else ""] = True
    out = list(lines)
    # per TFM a stack of [branch condition, some earlier branch taken] (Kleene values)
    stacks: dict[str, list] = {t: [] for t in tfms}
    values = {t: (lambda s, t=t: None if s in local else preprocessor_symbol(s, t, sdk_style, defines)) for t in tfms}
    for n, ln in enumerate(lines):
        m = _PP_LINE_RE.match(ln)
        if m and m.group(1) in ("if", "elif", "else", "endif"):
            d = m.group(1)
            for t in tfms:
                st = stacks[t]
                if d == "if":
                    c = _eval_pp(m.group(2), values[t])
                    st.append([c, c])
                elif not st:
                    return txt
                elif d == "elif":
                    taken = st[-1][1]
                    c = _kleene_and(_kleene_not(taken), _eval_pp(m.group(2), values[t]))
                    st[-1] = [c, _kleene_or(taken, c)]
                elif d == "else":
                    st[-1] = [_kleene_not(st[-1][1]), True]
                else:
                    st.pop()
            continue
        if stacks[tfms[0]]:
            live = False
            for t in tfms:
                act = True
                for frame in stacks[t]:
                    act = _kleene_and(act, frame[0])
                if act is not False:
                    live = True
                    break
            if not live:
                out[n] = ""
    if any(stacks[t] for t in tfms):
        return txt
    return "\n".join(out)


# ---------------------------------------------------------------------------

def walk(root: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            out.append(Path(dirpath) / f)
    return out


_PROP_REF_RE = re.compile(r"\$\((\w+)\)")
_DEFAULT_IF_EMPTY_RE = re.compile(r"^\s*'\$\((\w+)\)'\s*==\s*''\s*$")


def _expand(v: str, props: dict[str, str]) -> str:
    """Expand simple $(Name) references; unknown names and property functions stay as they are."""
    return _PROP_REF_RE.sub(lambda m: props.get(m.group(1), m.group(0)), v)


def _msbuild_elements(path: Path, root: Path, seen: set | None = None, outer: tuple = ()):
    """Yield (element, condition, chain) for an MSBuild file in document order, with local
    <Import>s inlined where they appear. `condition` is the nearest Condition on the element or an
    enclosing group within its own file ("" when unconditional); `chain` is every Condition that
    applies to it, including those on enclosing groups and on the <Import> that brought it in."""
    seen = seen if seen is not None else set()
    rp = path.resolve()
    if rp in seen:
        return
    seen.add(rp)
    try:
        top = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return
    this_dir = str(path.parent).replace("\\", "/") + "/"

    def rec(el, cond, chain):
        for c in el:
            if not isinstance(c.tag, str):
                continue
            tag = _strip_ns(c.tag)
            own = c.attrib.get("Condition", "").strip()
            ccond = own or cond
            cchain = chain + (own,) if own else chain
            if tag == "Import":
                inc = c.attrib.get("Project", "").replace("\\", "/")
                inc = inc.replace("$(MSBuildThisFileDirectory)", this_dir)
                if inc and "$(" not in inc:
                    ip = (path.parent / inc).resolve()
                    if ip.is_file() and root in ip.parents:
                        yield from _msbuild_elements(ip, root, seen, cchain)
                continue
            yield c, ccond, cchain
            yield from rec(c, ccond, cchain)

    yield from rec(top, "", outer)


def _set_prop(props: dict[str, str], fixed: set, tag: str, value: str, cond: str) -> None:
    """MSBuild-ish property assignment. A conditional value never overrides an
    unconditional one (the build runs on Linux, where e.g. IsOSPlatform('windows') is
    false), and a default-if-empty condition only applies while the property is unset
    (and then counts as unconditional)."""
    default = False
    if cond:
        m = _DEFAULT_IF_EMPTY_RE.match(cond)
        default = bool(m and m.group(1) == tag)
        if tag in fixed or (default and props.get(tag)):
            return
    props[tag] = _expand(value, props)
    if not cond or default:
        fixed.add(tag)


def _load_props(root: Path, proj_dir: Path, fixed: set | None = None, defines: set | None = None) -> dict[str, str]:
    """Read Directory.Build.props up the tree (common place for TFMs/packages)."""
    props: dict[str, str] = {}
    fixed = fixed if fixed is not None else set()
    d = proj_dir
    chain = []
    while True:
        p = d / "Directory.Build.props"
        if p.exists():
            chain.append(p)
        if d == root or d.parent == d:
            break
        d = d.parent
    for p in reversed(chain):
        for el, cond, _ in _msbuild_elements(p, root):
            tag = _strip_ns(el.tag)
            if el.text and el.text.strip() and len(list(el)) == 0 and tag not in ("PackageReference",):
                _set_prop(props, fixed, tag, el.text.strip(), cond)
                if tag == "DefineConstants" and defines is not None:
                    defines |= _define_symbols(el.text)
    return props


def _define_symbols(v: str) -> set[str]:
    return {x for x in re.split(r"[;,\s]+", v or "") if re.fullmatch(r"[A-Za-z_]\w*", x)}


def reference_name(include: str) -> str:
    """The assembly name of a <Reference Include="...">: the simple name of an assembly identity
    ("System.Web, Version=4.0.0.0, ..."), or the file name without .dll/.exe when the reference is
    a path ("..\\References\\$(SharePointVersion)\\Microsoft.SharePoint.dll", "../tools/xunit/xunit.dll")."""
    name = include.split(",")[0].strip()
    if re.search(r"[\\/]", name) or re.search(r"\.(dll|exe)$", name, re.I):
        name = re.split(r"[\\/]", name)[-1]
        name = re.sub(r"\.(dll|exe)$", "", name, flags=re.I)
    return name


def _packages_config(proj_path: Path) -> dict[str, str]:
    """NuGet packages.config of an old-style project, or Paket paket.references (id -> version)."""
    out: dict[str, str] = {}
    for cand in (proj_path.parent / "packages.config", proj_path.parent / f"packages.{proj_path.stem}.config"):
        if not cand.is_file():
            continue
        try:
            for el in ET.parse(cand).getroot().iter():
                if _strip_ns(el.tag) == "package" and el.attrib.get("id"):
                    out.setdefault(el.attrib["id"], el.attrib.get("version", ""))
        except (ET.ParseError, OSError):
            continue
    for name in _paket_references(proj_path.parent / "paket.references"):
        out.setdefault(name, _paket_lock(proj_path.parent).get(name.lower(), ""))
    return out


_WIN_TOKEN_RE = re.compile(r"Windows|Win(?=[A-Z.\-_]|$)")


def _mark_platform_twins(projects: list[Project]) -> None:
    """PlatformTwin: for a project named with a Windows token (Duplicati.WindowsService,
    Contoso.Win.Agent), the cross-platform executable of the same name without it
    (Duplicati.Service): the Windows project is the Windows packaging of that program."""
    exes = {}
    for q in projects:
        if q.kind_hint == "dotnet" and re.fullmatch(r"(?i)exe", q.properties.get("OutputType", "")) \
                and not any("-windows" in t for t in q.tfms):
            exes.setdefault(q.name.lower(), q)
    for p in projects:
        if p.kind_hint != "dotnet" or not _WIN_TOKEN_RE.search(p.name):
            continue
        twin = re.sub(r"\.{2,}", ".", _WIN_TOKEN_RE.sub("", p.name)).strip(".-_")
        q = exes.get(twin.lower())
        if twin and q is not None and q is not p:
            p.properties.setdefault("PlatformTwin", q.rel)


def _paket_references(path: Path) -> list[str]:
    """Package ids from a Paket paket.references file (one id per line, `group` headers)."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    out = []
    tooling = False  # build/docs/analyzer groups are not shipped with the app
    for line in lines:
        line = line.strip()
        g = re.match(r"(?i)group\s+(\S+)", line)
        if g:
            tooling = bool(re.search(r"(?i)build|docs|fake|analy[sz]er", g.group(1)))
            continue
        if tooling or not line or line.startswith(("//", "#")) or re.match(r"(?i)file:", line):
            continue
        m = re.match(r"([A-Za-z0-9_][\w.\-]*)", line)
        if m:
            out.append(m.group(1))
    return out


_PAKET_LOCKS: dict[Path, dict[str, str]] = {}


def _paket_lock(folder: Path) -> dict[str, str]:
    """Resolved versions (lower-case id -> version) from the nearest paket.lock above folder."""
    for d in (folder, *folder.parents):
        lock = d / "paket.lock"
        if lock in _PAKET_LOCKS:
            return _PAKET_LOCKS[lock]
        if lock.is_file():
            try:
                text = lock.read_text(errors="replace")
            except OSError:
                text = ""
            vers: dict[str, str] = {}
            for m in re.finditer(r"(?m)^    ([A-Za-z0-9_][\w.\-]*) \(([^)\s]+)", text):
                vers.setdefault(m.group(1).lower(), m.group(2))
            _PAKET_LOCKS[lock] = vers
            return vers
    return {}


def parse_dotnet_project(path: Path, root: Path) -> Project:
    pr = Project(path=path, root=root, kind_hint="dotnet", name=path.stem)
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return pr
    proj = tree.getroot()
    pr.sdk = proj.attrib.get("Sdk", "")
    pr.sdk_style = bool(pr.sdk) or any(_strip_ns(e.tag) == "Sdk" for e in proj)
    if not pr.sdk:
        for e in proj:
            if _strip_ns(e.tag) == "Sdk":
                pr.sdk = e.attrib.get("Name", "")
    fixed: set = set()
    defines: set = set()
    props = _load_props(root, path.parent, fixed, defines)
    items: list[tuple[str, object, tuple]] = []      # (kind, key, condition chain)
    # project file in document order, local <Import Project="..."> files inlined
    for el, cond, chain in _msbuild_elements(path, root):
        tag = _strip_ns(el.tag)
        if tag == "PackageReference" or tag == "PackageVersion":
            name = el.attrib.get("Include") or el.attrib.get("Update")
            if name and tag == "PackageReference":
                ver = el.attrib.get("Version") or ""
                if not ver:
                    for c in el:
                        if _strip_ns(c.tag) == "Version" and c.text:
                            ver = c.text.strip()
                pr.packages[name] = ver
                items.append(("package", name, chain))
        elif tag == "Reference":
            inc = el.attrib.get("Include", "")
            if inc:
                pr.references.append(reference_name(inc))
                items.append(("reference", pr.references[-1], chain))
        elif tag == "COMReference":
            pr.references.append("COM:" + el.attrib.get("Include", ""))
            items.append(("reference", pr.references[-1], chain))
        elif tag == "FrameworkReference":
            pr.framework_refs.append(el.attrib.get("Include", ""))
            items.append(("framework", pr.framework_refs[-1], chain))
        elif tag == "ProjectReference":
            inc = el.attrib.get("Include", "").replace("\\", "/")
            if inc:
                pr.project_refs.append((path.parent / inc).resolve())
                items.append(("project", pr.project_refs[-1], chain))
        elif tag == "ProjectTypeGuids" and el.text:
            pr.type_guids = [g.strip("{} ").lower() for g in el.text.split(";") if g.strip()]
        elif tag == "Compile" and (el.attrib.get("Remove") or el.attrib.get("Include")):
            op = "Remove" if el.attrib.get("Remove") else "Include"
            pr.compile_items.append((op, el.attrib[op], chain))
        elif len(list(el)) == 0 and el.text and el.text.strip():
            _set_prop(props, fixed, tag, el.text.strip(), cond)
            if tag == "DefineConstants":
                defines |= _define_symbols(el.text)
    for name, ver in _packages_config(path).items():
        pr.packages.setdefault(name, ver)
    pr.properties = props
    pr.defines = defines
    tfm = props.get("TargetFramework") or props.get("TargetFrameworks") or ""
    if tfm:
        pr.tfms = list(dict.fromkeys(t.strip() for t in _expand(tfm, props).split(";")
                                     if t.strip() and "$(" not in t))
    elif props.get("TargetFrameworkVersion"):
        pr.tfms = [_legacy_tfm(props, pr.type_guids)]
    pr.tfm_props = tfm_valued_props(props, fixed)
    _apply_item_conditions(pr, items)
    default_ot = "Exe" if re.search(r"Sdk\.(Web|Worker)$", pr.sdk or "") else ("Library" if pr.sdk_style else "")
    pr.output_type = props.get("OutputType", default_ot)
    pr.assembly_name = props.get("AssemblyName", path.stem)
    return pr


def _apply_item_conditions(pr: Project, items: list[tuple[str, object, tuple]]) -> None:
    """Evaluate the target-framework part of each item's conditions against the project's TFMs.
    An item no TFM gets is dropped (a net472-only `<Reference Include="System.Web" />` in a net8.0
    project); one only some TFMs get is recorded in tfm_items for per-TFM views. Conditions on
    anything else (Configuration, Exists(), OS) count as possibly true."""
    seen: dict[tuple, set | None] = {}
    for kind, key, chain in items:
        ok = applies_to_tfms(chain, pr.tfms, pr.sdk_style, pr.tfm_props)
        k = (kind, key)
        if k in seen and seen[k] is None:
            continue
        seen[k] = None if ok is None else (seen.get(k) or set()) | ok
    for k, ok in seen.items():
        if ok is None:
            continue
        if ok:
            pr.tfm_items[k] = frozenset(ok)
            continue
        kind, key = k
        if kind == "package":
            if key not in _packages_config(pr.path):
                pr.packages.pop(key, None)
        elif kind == "reference":
            pr.references = [r for r in pr.references if r != key]
        elif kind == "framework":
            pr.framework_refs = [r for r in pr.framework_refs if r != key]
        else:
            pr.project_refs = [r for r in pr.project_refs if r != key]


def _msbuild_glob_rx(globs: str) -> re.Pattern:
    parts = []
    for g in globs.replace("\\", "/").split(";"):
        g = g.strip().lstrip("./") if not g.strip().startswith("../") else g.strip()
        if not g or "$(" in g or "@(" in g:
            continue
        rx = ""
        i = 0
        while i < len(g):
            if g.startswith("**/", i):
                rx += "(?:.*/)?"
                i += 3
            elif g.startswith("**", i):
                rx += ".*"
                i += 2
            elif g[i] == "*":
                rx += "[^/]*"
                i += 1
            elif g[i] == "?":
                rx += "[^/]"
                i += 1
            else:
                rx += re.escape(g[i])
                i += 1
        parts.append(rx)
    return re.compile("^(?:" + "|".join(parts) + ")$" if parts else "(?!)", re.I)


def _apply_compile_items(pr: Project) -> None:
    """SDK-style projects compile **/*.cs by default; `<Compile Remove>` / `<Compile Include>`
    items (often per target framework: `Compile Remove="Framework/**"` for the .NET Core build)
    change that. Files no TFM compiles leave the project; files only some TFMs compile are
    recorded in tfm_files for per-TFM views. Items whose condition depends on anything but the
    target framework are not applied (the file stays)."""
    if not pr.sdk_style or not pr.compile_items or not pr.tfms:
        return
    cs = [f for f in pr.files if f.suffix.lower() == ".cs"]
    rel = {f: str(f.relative_to(pr.dir)).replace("\\", "/") for f in cs if pr.dir in f.parents}
    default = pr.properties.get("EnableDefaultCompileItems", "true").lower() != "false"
    compiled_by: dict[Path, set] = {f: set() for f in cs}
    for t in pr.tfms:
        tv = {**pr.tfm_props, **_tfm_vars(t, True)}
        on = {f: default for f in cs}
        for op, globs, chain in pr.compile_items:
            r = True
            for c in chain:
                if c:
                    r = _kleene_and(r, eval_condition(c, tv))
            if r is False or (r is None and op == "Remove"):
                continue
            rx = _msbuild_glob_rx(globs)
            for f, rp in rel.items():
                if rx.match(rp):
                    on[f] = op == "Include"
        for f, v in on.items():
            if v or f not in rel:
                compiled_by[f].add(t)
    drop = {f for f, ts in compiled_by.items() if not ts}
    if drop:
        pr.files = [f for f in pr.files if f not in drop]
    pr.tfm_files = {f: frozenset(ts) for f, ts in compiled_by.items() if ts and len(ts) < len(pr.tfms)}


def parse_node_project(path: Path, root: Path) -> Project:
    pr = Project(path=path, root=root, kind_hint="node", name=path.parent.name)
    try:
        pr.manifest = json.loads(read_text(path) or "{}")
    except json.JSONDecodeError:
        pr.manifest = {}
    deps = {}
    deps.update(pr.manifest.get("dependencies", {}) or {})
    deps.update(pr.manifest.get("devDependencies", {}) or {})
    pr.packages = deps
    pr.name = pr.manifest.get("name", pr.name)
    pr.assembly_name = pr.name
    scripts = pr.manifest.get("scripts") if isinstance(pr.manifest.get("scripts"), dict) else {}
    # npm script names (comma-separated, sorted) so role rules can tell a test harness from an app
    pr.properties["NpmScripts"] = ",".join(sorted(scripts))
    return pr


def parse_generic(path: Path, root: Path, kind: str) -> Project:
    pr = Project(path=path, root=root, kind_hint=kind, name=path.parent.name if kind in ("python", "go", "java") else path.stem)
    pr.assembly_name = pr.name
    txt = read_text(path)
    if kind == "python":
        for line in txt.splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-\[\]]+)\s*([=<>~!]=?.*)?$", line)
            if path.name == "requirements.txt" and m and not line.strip().startswith("#"):
                pr.packages[m.group(1).split("[")[0].lower()] = (m.group(2) or "").strip()
        if path.name == "pyproject.toml":
            for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*([<>=~!][^"]*)?"', txt):
                pr.packages[m.group(1).lower()] = m.group(2) or ""
    elif kind == "go":
        for m in re.finditer(r"^\s*([\w./\-]+)\s+(v[\w.\-+]+)", txt, re.M):
            pr.packages[m.group(1)] = m.group(2)
        m = re.search(r"^go\s+(\d+\.\d+)", txt, re.M)
        if m:
            pr.properties["GoVersion"] = m.group(1)
    elif kind == "java":
        for m in re.finditer(r"<artifactId>([^<]+)</artifactId>", txt):
            pr.packages[m.group(1)] = ""
        for m in re.finditer(r"['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]", txt):
            pr.packages[m.group(2)] = m.group(3)
        m = re.search(r"<java.version>([^<]+)<|sourceCompatibility\s*=\s*['\"]?([\d.]+)", txt)
        if m:
            pr.properties["JavaVersion"] = m.group(1) or m.group(2)
    return pr


# --------------------------------------------------------------------------- build-time executables

MSBUILD_FILE_EXT = (".proj", ".targets", ".props") + DOTNET_PROJ_EXT
SCRIPT_FILE_EXT = (".sh", ".ps1", ".psm1", ".cmd", ".bat")
_EXEC_TAG_RE = re.compile(r"<Exec\b([^>]*)>", re.S)
_ATTR_RE = r"""\b{}\s*=\s*(?:"([^"]*)"|'([^']*)')"""
# the executable of one command segment: `dotnet [exec] path/Name.dll`, `"path\Name.exe" args`
_RUN_DLL_RE = re.compile(r'^\s*(?:call\s+|&\s*)?"?dotnet(?:\.exe)?"?\s+(?:exec\s+)?"?(?:[^"\s]*[\\/])?([\w.\-]+)\.dll"?(?:\s|$)', re.I)
_RUN_EXE_RE = re.compile(r'^\s*(?:call\s+|&\s*)?"?(?:[^"\s]*[\\/])?([\w.\-]+)\.exe"?(?:\s|$)', re.I)
_DOTNET_RUN_RE = re.compile(r'^\s*(?:&\s*|exec\s+)?"?(?:[^"\s]*[\\/])?dotnet(?:\.exe)?"?\s+run\b(.*)$', re.I)
_RUN_PROJECT_RE = re.compile(r'(?:--project|-p)\s+(?:"([^"]+)"|\'([^\']+)\'|(\S+))')
_CD_RE = re.compile(r"^\s*(?:cd|chdir|pushd|Push-Location|Set-Location)\b\s*(.*)$", re.I)


def _resolve_dir(base: Path | None, arg: str) -> Path | None:
    """Directory a script's `cd`/`--project` argument points at, or None when it cannot be known."""
    if base is None:
        return None
    a = re.sub(r"\bJoin-Path\b|\$PSScriptRoot|%~dp0|\$\(dirname\s+\"?\$0\"?\)|\$\(MSBuildThisFileDirectory\)|"
               r"\$\(MSBuildProjectDirectory\)|\$\(ProjectDir\)|-Path\b|/d\b", " ", arg)
    toks = [t for t in re.split(r"[\s()\"';]+", a) if t]
    if not toks:
        return None
    t = toks[-1].replace("\\", "/")
    if "$" in t or "%" in t or t.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", t):
        return None
    return (base / t).resolve()


def _projects_at(path: Path | None, by_path: dict, by_dir: dict) -> list:
    if path is None:
        return []
    if path in by_path:
        return [by_path[path]]
    return by_dir.get(path, [])


def _mark_build_time_runs(projects: list[Project], files: list[Path], root: Path) -> None:
    """Mark .NET executables that the repository's own build or developer scripts run.

    * RunByBuild: an MSBuild <Exec> in another project/targets file runs the built program
      (`dotnet Name.dll`, `Name.exe`, `dotnet run --project ...`), so it is a build-time helper
      (a post-build cleaner, a module packer, a schema generator), not a deployable.
    * RunFromSourceBy: a repository script starts it with `dotnet run`, i.e. compiled from a
      source checkout with the SDK, the way developer utilities are run; deployed programs are
      published and started from binaries. (Only `dotnet run`: `dotnet Name.dll` in a script is
      how a deployed program is started.)
    The value is the file that runs it, so the role rule can show its evidence."""
    exes = [p for p in projects if p.kind_hint == "dotnet" and (p.output_type or "").lower() in ("exe", "winexe")]
    if not exes:
        return
    by_name: dict[str, list[Project]] = {}
    for p in exes:
        by_name.setdefault((p.assembly_name or p.name).lower(), []).append(p)
    by_path = {p.path.resolve(): p for p in exes}
    by_dir: dict[Path, list[Project]] = {}
    for p in exes:
        by_dir.setdefault(p.dir.resolve(), []).append(p)

    def mark(ps, key, f):
        for p in ps:
            if p.path.resolve() != f.resolve():
                p.properties.setdefault(key, str(f.relative_to(root)))

    import html
    for f in files:
        n = f.name.lower()
        if n.endswith(MSBUILD_FILE_EXT):
            txt = read_text(f, strip_comments=f.suffix.lower() in (".csproj", ".vbproj"))
            if "<Exec" not in txt:
                continue
            txt = _XML_COMMENT_RE.sub("", txt)
            for m in _EXEC_TAG_RE.finditer(txt):
                attrs = m.group(1)
                cm = re.search(_ATTR_RE.format("Command"), attrs)
                if not cm:
                    continue
                cmd = html.unescape(cm.group(1) if cm.group(1) is not None else cm.group(2))
                wm = re.search(_ATTR_RE.format("WorkingDirectory"), attrs)
                cwd = _resolve_dir(f.parent, html.unescape(wm.group(1) or wm.group(2) or "")) if wm else f.parent.resolve()
                for seg in re.split(r"&&|\|\||\r?\n", cmd):
                    hit = _RUN_DLL_RE.match(seg) or _RUN_EXE_RE.match(seg)
                    if hit:
                        mark(by_name.get(hit.group(1).lower(), []), "RunByBuild", f)
                        continue
                    run = _DOTNET_RUN_RE.match(seg)
                    if run:
                        pm = _RUN_PROJECT_RE.search(re.split(r"\s--(?:\s|$)", run.group(1))[0])
                        target = _resolve_dir(cwd, next(g for g in pm.groups() if g)) if pm else cwd
                        mark(_projects_at(target, by_path, by_dir), "RunByBuild", f)
        elif n.endswith(SCRIPT_FILE_EXT):
            txt = read_text(f)
            if not re.search(r"dotnet(\.exe)?\"?\s+run\b", txt, re.I):
                continue
            cwd: Path | None = f.parent.resolve()
            for line in txt.splitlines():
                s = line.strip()
                if not s or s.startswith(("#", "::", "REM ", "rem ")):
                    continue
                cdm = _CD_RE.match(s)
                if cdm:
                    cwd = _resolve_dir(cwd, cdm.group(1))
                    if cwd is not None and not cwd.is_dir():
                        cwd = None
                    continue
                run = _DOTNET_RUN_RE.match(s)
                if run:
                    pm = _RUN_PROJECT_RE.search(re.split(r"\s--(?:\s|$)", run.group(1))[0])
                    target = _resolve_dir(cwd, next(g for g in pm.groups() if g)) if pm else cwd
                    mark(_projects_at(target, by_path, by_dir), "RunFromSourceBy", f)


_BUILD_CONFIG_RE = re.compile(r"^(?:package\.json|angular\.json|gulpfile\.[cm]?js|gruntfile\.js|webpack[\w.\-]*\.[cm]?[jt]s|"
                              r"[\w.\-]+\.config\.(?:[cm]?[jt]s|json))$", re.I)
# where a build config names its output: webpack output.path, vite build.outDir, "destination": ...
_OUTPUT_PATH_RE = re.compile(r"\b(?:out(?:put)?(?:Dir|Path|File|Directory)?|dest(?:ination)?|path|dist\w*)[\"']?\s*[:=]\s*"
                             r"(?:path\.(?:resolve|join)\s*\(\s*__dirname\s*,\s*)?[\"'`](\.\.[\\/][^\"'`]+)[\"'`]", re.I)
# npm scripts that copy or emit into a folder
_SCRIPT_OUTPUT_RE = re.compile(r"\b(?:copyfiles|cpx|cpy|cp|xcopy|copy|robocopy|ncp|--out-?dir|--output(?:-path)?|--dest)\b"
                               r"[^&|;]*?(\.\.[\\/][^\s\"'&|;\\]*(?:[\\/][^\s\"'&|;\\]*)*)", re.I)


def _asset_output_host(p: Project, dotnet_dirs: list[Path]) -> Path | None:
    """The .NET project folder (outside p's own folder) that p's build configuration writes into."""
    own = p.dir.resolve()
    for f in sorted(p.dir.iterdir()) if p.dir.is_dir() else []:
        if not f.is_file() or not _BUILD_CONFIG_RE.match(f.name):
            continue
        txt = read_text(f)
        if ".." not in txt:
            continue
        rx = [_OUTPUT_PATH_RE] + ([_SCRIPT_OUTPUT_RE] if f.name.lower() == "package.json" else [])
        for r in rx:
            for m in r.finditer(txt):
                target = (f.parent / m.group(1).replace("\\", "/")).resolve()
                if own == target or own in target.parents:
                    continue
                for d in dotnet_dirs:
                    if d == target or d in target.parents:
                        if d not in own.parents:
                            return d
                        break
    return None


WEB_SITE_GUID = "e24c65dc-7377-472b-9aba-bc803b73c61a"
_SLN_PROJECT_RE = re.compile(r'^Project\("\{([0-9A-Fa-f\-]+)\}"\)\s*=\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"\{([0-9A-Fa-f\-]+)\}"'
                             r'(.*?)^EndProject\b', re.M | re.S)


def _web_site_projects(sln_files: list[Path], root: Path, projects: list[Project]) -> list[Project]:
    """ASP.NET Web Site projects (Visual Studio "File > New Web Site") have no project file: the
    solution lists the folder with project type {E24C65DC-...} and its WebsiteProperties
    (TargetFrameworkMoniker, ProjectReferences). Each becomes a .NET project for that folder,
    named after the solution entry; its `path` is `<folder>/<name>.website` (no such file exists)
    and property WebSiteProject names the solution. Referenced and dependent projects of the
    entry become its project references (the web site compiles against their Bin/ copies)."""
    out: list[Project] = []
    have = {p.dir.resolve() for p in projects if p.kind_hint == "dotnet"}
    for sln in sln_files:
        if sln.suffix.lower() != ".sln":
            continue
        txt = read_text(sln)
        if WEB_SITE_GUID not in txt.lower():
            continue
        entries = list(_SLN_PROJECT_RE.finditer(txt))
        by_guid = {m.group(4).lower(): (sln.parent / m.group(3).replace("\\", "/")).resolve()
                   for m in entries if m.group(1).lower() != WEB_SITE_GUID}
        for m in entries:
            if m.group(1).lower() != WEB_SITE_GUID:
                continue
            rel = m.group(3).replace("\\", "/").rstrip("/")
            if re.match(r"^[a-z]+://", rel, re.I):
                continue                            # an IIS/FTP web site, not a folder
            folder = (sln.parent / rel).resolve()
            if not folder.is_dir() or root not in (folder, *folder.parents) or folder in have:
                continue
            body = m.group(5)
            name = m.group(2) or folder.name
            pr = Project(path=folder / f"{name}.website", root=root, kind_hint="dotnet", name=name,
                         assembly_name=name, sdk_style=False, output_type="Library")
            pr.type_guids = [WEB_SITE_GUID]
            pr.properties["WebSiteProject"] = str(sln.relative_to(root))
            tfm = re.search(r'TargetFrameworkMoniker\s*=\s*"([^"]*)"', body)
            if tfm:
                mon = tfm.group(1).replace("%3D", "=")
                v = re.search(r"Version\s*=\s*v?([\d.]+)", mon)
                if v and ".NETFramework" in mon:
                    pr.tfms = [_framework_version_to_tfm(v.group(1))]
                    pr.properties["TargetFrameworkVersion"] = "v" + v.group(1)
            guids = re.findall(r"\{([0-9A-Fa-f\-]+)\}\|", re.search(r'ProjectReferences\s*=\s*"([^"]*)"', body).group(1)) \
                if re.search(r'ProjectReferences\s*=\s*"([^"]*)"', body) else []
            sec = re.search(r"ProjectSection\(ProjectDependencies\)(.*?)EndProjectSection", body, re.S)
            if sec:
                guids += re.findall(r"\{([0-9A-Fa-f\-]+)\}\s*=", sec.group(1))
            for g in dict.fromkeys(x.lower() for x in guids):
                if g in by_guid:
                    pr.project_refs.append(by_guid[g])
            pr.packages.update(_packages_config(pr.path))
            out.append(pr)
            have.add(folder)
    return out


def scan(root: str | Path) -> Repo:
    root = Path(root).resolve()
    files = walk(root)
    projects: list[Project] = []
    for f in files:
        n = f.name.lower()
        if n.endswith(DOTNET_PROJ_EXT):
            projects.append(parse_dotnet_project(f, root))
        elif n.endswith(OTHER_PROJ_EXT):
            kind = {"btproj": "biztalk", "sqlproj": "sqldb", "dtproj": "ssis", "wixproj": "installer",
                    "rptproj": "ssrs", "ccproj": "azure-cloud-service", "sfproj": "service-fabric"}[n.rsplit(".", 1)[1]]
            p = Project(path=f, root=root, kind_hint=kind, name=f.stem, assembly_name=f.stem)
            projects.append(p)
        elif n == "package.json":
            projects.append(parse_node_project(f, root))
        elif n in ("requirements.txt", "pyproject.toml") and not any(p.kind_hint == "python" and p.dir == f.parent for p in projects):
            projects.append(parse_generic(f, root, "python"))
        elif n == "go.mod":
            projects.append(parse_generic(f, root, "go"))
        elif n in ("pom.xml", "build.gradle", "build.gradle.kts"):
            projects.append(parse_generic(f, root, "java"))

    sln = [f for f in files if f.suffix.lower() in (".sln", ".slnx")]
    projects += _web_site_projects(sln, root, projects)

    # Assign every file to the deepest project directory that contains it.
    dirs = sorted({p.dir for p in projects}, key=lambda d: len(d.parts), reverse=True)
    by_dir: dict[Path, list[Project]] = {}
    for p in projects:
        by_dir.setdefault(p.dir, []).append(p)
    for f in files:
        for d in dirs:
            if d == f.parent or d in f.parents:
                for p in by_dir[d]:
                    p.files.append(f)
                break
    # Node projects nested inside a .NET web project (ClientApp) are front-end
    # builds of that project, not deployables of their own.
    for p in projects:
        if p.kind_hint == "node":
            parent = next((q for q in projects if q.kind_hint == "dotnet" and q.dir in p.dir.parents), None)
            if parent is not None:
                p.properties["HostedBy"] = parent.rel
                parent.properties.setdefault("SpaRoot", str(p.dir.relative_to(parent.dir)))
    # A front-end build next to a .NET project that writes its bundles into that project's folder
    # (webpack `output.path: "../Web/Scripts"`, `"destination": "../Web/Styles"`, a `copyfiles ...
    # ../Web/dist` script; Visual Studio .esproj JavaScript projects) produces static assets the
    # .NET web app serves, not a single-page app of its own.
    dotnet_dirs = sorted({q.dir.resolve() for q in projects if q.kind_hint == "dotnet"}, key=lambda d: -len(d.parts))
    for p in projects:
        if p.kind_hint == "node" and "HostedBy" not in p.properties:
            host = _asset_output_host(p, dotnet_dirs)
            if host is not None:
                q = next(q for q in projects if q.kind_hint == "dotnet" and q.dir.resolve() == host)
                p.properties["HostedBy"] = q.rel
    # A Blazor WebAssembly client referenced by a server project is served by that
    # project (static web assets), not deployed on its own.
    for p in projects:
        if p.kind_hint == "dotnet" and "BlazorWebAssembly" in (p.sdk or ""):
            host = next((q for q in projects if q.kind_hint == "dotnet" and q is not p
                         and p.path.resolve() in q.project_refs), None)
            if host is not None:
                p.properties["HostedBy"] = host.rel

    for p in projects:
        if p.kind_hint == "dotnet":
            _apply_compile_items(p)
    # ReferencedBy: the first project that references this one (a library some deployable compiles in)
    by_proj = {p.path.resolve(): p for p in projects}
    for q in projects:
        for r in q.project_refs:
            t = by_proj.get(r)
            if t is not None and t is not q:
                t.properties.setdefault("ReferencedBy", q.rel)
    _mark_platform_twins(projects)
    _mark_build_time_runs(projects, files, root)

    readme = ""
    for cand in ("README.md", "readme.md", "README.txt", "README"):
        if (root / cand).exists():
            readme = read_text(root / cand)
            break
    return Repo(root=root, name=root.name, projects=projects, files=files, readme=readme, solution_files=sln)
