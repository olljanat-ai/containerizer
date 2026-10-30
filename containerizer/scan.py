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
from dataclasses import dataclass, field
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
        key = (p, strip_comments)
        if key not in self._text_cache:
            self._text_cache[key] = read_text(p, strip_comments)
        return self._text_cache[key]

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


def _msbuild_elements(path: Path, root: Path, seen: set | None = None):
    """Yield (element, condition) for an MSBuild file in document order, with local
    <Import>s inlined where they appear. `condition` is the nearest Condition on the
    element or an enclosing group ("" when unconditional)."""
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

    def rec(el, cond):
        for c in el:
            if not isinstance(c.tag, str):
                continue
            tag = _strip_ns(c.tag)
            ccond = c.attrib.get("Condition", "").strip() or cond
            if tag == "Import":
                inc = c.attrib.get("Project", "").replace("\\", "/")
                inc = inc.replace("$(MSBuildThisFileDirectory)", this_dir)
                if inc and "$(" not in inc:
                    ip = (path.parent / inc).resolve()
                    if ip.is_file() and root in ip.parents:
                        yield from _msbuild_elements(ip, root, seen)
                continue
            yield c, ccond
            yield from rec(c, ccond)

    yield from rec(top, "")


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


def _load_props(root: Path, proj_dir: Path, fixed: set | None = None) -> dict[str, str]:
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
        for el, cond in _msbuild_elements(p, root):
            tag = _strip_ns(el.tag)
            if el.text and el.text.strip() and len(list(el)) == 0 and tag not in ("PackageReference",):
                _set_prop(props, fixed, tag, el.text.strip(), cond)
    return props


def _packages_config(proj_path: Path) -> dict[str, str]:
    """NuGet packages.config of an old-style project (id -> version)."""
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
    return out


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
    props = _load_props(root, path.parent, fixed)
    # project file in document order, local <Import Project="..."> files inlined
    for el, cond in _msbuild_elements(path, root):
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
        elif tag == "Reference":
            inc = el.attrib.get("Include", "")
            if inc:
                pr.references.append(inc.split(",")[0].strip())
        elif tag == "COMReference":
            pr.references.append("COM:" + el.attrib.get("Include", ""))
        elif tag == "FrameworkReference":
            pr.framework_refs.append(el.attrib.get("Include", ""))
        elif tag == "ProjectReference":
            inc = el.attrib.get("Include", "").replace("\\", "/")
            if inc:
                pr.project_refs.append((path.parent / inc).resolve())
        elif tag == "ProjectTypeGuids" and el.text:
            pr.type_guids = [g.strip("{} ").lower() for g in el.text.split(";") if g.strip()]
        elif len(list(el)) == 0 and el.text and el.text.strip():
            _set_prop(props, fixed, tag, el.text.strip(), cond)
    for name, ver in _packages_config(path).items():
        pr.packages.setdefault(name, ver)
    pr.properties = props
    tfm = props.get("TargetFramework") or props.get("TargetFrameworks") or ""
    if tfm:
        pr.tfms = list(dict.fromkeys(t.strip() for t in _expand(tfm, props).split(";")
                                     if t.strip() and "$(" not in t))
    elif props.get("TargetFrameworkVersion"):
        pr.tfms = [_framework_version_to_tfm(props["TargetFrameworkVersion"])]
    default_ot = "Exe" if re.search(r"Sdk\.(Web|Worker)$", pr.sdk or "") else ("Library" if pr.sdk_style else "")
    pr.output_type = props.get("OutputType", default_ot)
    pr.assembly_name = props.get("AssemblyName", path.stem)
    return pr


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
    # A Blazor WebAssembly client referenced by a server project is served by that
    # project (static web assets), not deployed on its own.
    for p in projects:
        if p.kind_hint == "dotnet" and "BlazorWebAssembly" in (p.sdk or ""):
            host = next((q for q in projects if q.kind_hint == "dotnet" and q is not p
                         and p.path.resolve() in q.project_refs), None)
            if host is not None:
                p.properties["HostedBy"] = host.rel

    _mark_build_time_runs(projects, files, root)

    readme = ""
    for cand in ("README.md", "readme.md", "README.txt", "README"):
        if (root / cand).exists():
            readme = read_text(root / cand)
            break
    sln = [f for f in files if f.suffix.lower() in (".sln", ".slnx")]
    return Repo(root=root, name=root.name, projects=projects, files=files, readme=readme, solution_files=sln)
