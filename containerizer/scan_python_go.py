"""Python and Go projects: dependencies, language version, package manager and (Go) main packages.

Python: one project per folder with requirements.txt, pyproject.toml, Pipfile or setup.py; every manifest of
the folder adds its packages (PEP 503 names). Go: one project per main package of a module (`cmd/*` give one
each); a module without a main package is one project, a library. Nothing is executed or changed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

PY_MANIFESTS = ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py")
PY_LOCKS = {"uv.lock": "uv", "poetry.lock": "poetry", "Pipfile.lock": "pipenv"}
# a requirement line: name, extras, the rest (version specifiers, markers)
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _toml(path: Path) -> dict:
    import tomllib
    try:
        return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}


def _requirement(spec: str) -> tuple[str, str] | None:
    """('flask', '>=3') from a PEP 508 string; None for options, URLs and paths."""
    spec = spec.split("#", 1)[0].strip() if " #" in spec or spec.startswith("#") else spec.strip()
    if not spec or spec.startswith(("-", ".", "/", "git+", "http:", "https:", "file:")):
        return None
    m = _REQ_RE.match(spec)
    if not m or "://" in m.group(3).split(";")[0] and "@" in m.group(3):
        return (pep503(m.group(1)), "") if m else None
    return pep503(m.group(1)), m.group(3).split(";")[0].strip()


def read_requirements(path: Path, seen: set | None = None) -> dict[str, str]:
    """Packages of a pip requirements file and the files it includes (-r other.txt)."""
    seen = seen if seen is not None else set()
    if path in seen or not path.is_file():
        return {}
    seen.add(path)
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        m = re.match(r"^(?:-r|--requirement)\s*=?\s*(\S+)", line)
        if m:
            out.update(read_requirements((path.parent / m.group(1)).resolve(), seen))
            continue
        r = _requirement(line)
        if r:
            out[r[0]] = r[1]
    return out


def _poetry_deps(d: dict) -> dict[str, str]:
    return {pep503(k): (v if isinstance(v, str) else str((v or {}).get("version", "")) if isinstance(v, dict) else "")
            for k, v in (d or {}).items() if k.lower() != "python"}


def parse_python_project(path: Path, root: Path):
    """The Python project of the manifest's folder (all its manifests)."""
    from .scan import Project
    d = path.parent
    pr = Project(path=path, root=root, kind_hint="python", name=d.name if d != root else root.name)
    pr.assembly_name = pr.name
    props = pr.properties
    pk, dev = pr.packages, pr.dev_packages
    req = d / "requirements.txt"
    if req.is_file():
        pk.update(read_requirements(req))
        props["Requirements"] = "requirements.txt"
    for n in ("requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt", "requirements-test.txt",
              "test-requirements.txt"):
        if (d / n).is_file():
            for k, v in read_requirements(d / n).items():
                if k not in pk:
                    dev[k] = v
    pp = d / "pyproject.toml"
    if pp.is_file():
        t = _toml(pp)
        proj = t.get("project") or {}
        poetry = (t.get("tool") or {}).get("poetry") or {}
        for s in proj.get("dependencies") or []:
            r = _requirement(str(s))
            if r:
                pk.setdefault(*r)
        pk.update({k: v for k, v in _poetry_deps(poetry.get("dependencies")).items() if k not in pk})
        devs = dict(_poetry_deps(poetry.get("dev-dependencies")))
        for g in (poetry.get("group") or {}).values():
            if isinstance(g, dict):
                devs.update(_poetry_deps(g.get("dependencies")))
        for grp in list((t.get("dependency-groups") or {}).values()) + [((t.get("tool") or {}).get("uv") or {}).get("dev-dependencies") or []]:
            for s in grp if isinstance(grp, list) else []:
                r = _requirement(str(s)) if isinstance(s, str) else None
                if r:
                    devs.setdefault(*r)
        for k, v in devs.items():
            if k not in pk:
                dev[k] = v
        rp = proj.get("requires-python") or (poetry.get("dependencies") or {}).get("python")
        if isinstance(rp, str):
            props["PythonRequires"] = rp
        scripts = dict(poetry.get("scripts") or {})
        scripts.update(proj.get("scripts") or {})
        scripts = {k: v for k, v in scripts.items() if isinstance(v, str)}
        if scripts:
            props["Scripts"] = json.dumps(scripts)
        if proj.get("dependencies") is not None or poetry.get("dependencies"):
            props["PyprojectDeps"] = "true"
        if poetry:
            props["Poetry"] = "true"
    pf = d / "Pipfile"
    if pf.is_file():
        t = _toml(pf)
        for k, v in (t.get("packages") or {}).items():
            pk.setdefault(pep503(k), v if isinstance(v, str) and v != "*" else "")
        for k, v in (t.get("dev-packages") or {}).items():
            if pep503(k) not in pk:
                dev[pep503(k)] = v if isinstance(v, str) and v != "*" else ""
        pv = (t.get("requires") or {}).get("python_version") or (t.get("requires") or {}).get("python_full_version")
        if pv:
            props.setdefault("PythonVersion", str(pv))
        props["Pipfile"] = "true"
    sp = d / "setup.py"
    if sp.is_file():
        try:
            txt = sp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        m = re.search(r"install_requires\s*=\s*\[([^\]]*)\]", txt, re.S)
        if m:
            for s in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                r = _requirement(s)
                if r:
                    pk.setdefault(*r)
            props["SetupDeps"] = "true"
    for k in list(dev):
        pk.setdefault(k, dev[k])            # `packages` holds every package; `dev_packages` marks the dev ones
    # the Python version the app is run with: .python-version, runtime.txt (Heroku), then the manifests
    for n, rx in ((".python-version", r"^\s*(?:python-|cpython-)?(\d+\.\d+)"), ("runtime.txt", r"^\s*python-(\d+\.\d+)")):
        f = d / n
        if f.is_file():
            try:
                m = re.search(rx, f.read_text(errors="replace"), re.M)
            except OSError:
                m = None
            if m:
                props["PythonVersion"] = m.group(1)
                break
    for lock, pm in PY_LOCKS.items():
        if (d / lock).is_file():
            props["Lockfile"] = lock
            props.setdefault("PackageManager", pm)
            break
    props.setdefault("PackageManager", "pip")
    if (d / "manage.py").is_file():
        props["Django"] = "true"
    return pr


# --------------------------------------------------------------------------- Go

_GO_PKG_RE = re.compile(r"^\s*package\s+(\w+)", re.M)
_GO_IMPORT_BLOCK_RE = re.compile(r"^import\s*\(([^)]*)\)", re.M | re.S)
_GO_IMPORT_ONE_RE = re.compile(r'^import\s+(?:[\w.]+\s+)?"([^"]+)"', re.M)
# a server: net/http listening, or a web framework's Run/Start/Listen
GO_SERVER_RE = re.compile(r"\bListenAndServe(TLS)?\s*\(|\bhttp\.Server\s*\{|\.Serve\s*\(\s*\w*[lL]is|"
                          r"\b(e|r|router|engine|app|srv|server|echo|g)\.(Run|Start|Listen)\s*\(\s*(\"[^\"]*:\d+\"|[\w.]*[Aa]ddr|[\w.]*[Pp]ort|fmt\.Sprintf|\":\"\s*\+)|"
                          r"\bgrpc\.NewServer\s*\(")
_GO_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _go_files(d: Path) -> list[Path]:
    try:
        return sorted(f for f in d.iterdir() if f.suffix == ".go" and not f.name.endswith("_test.go") and f.is_file())
    except OSError:
        return []


def _go_text(f: Path) -> str:
    try:
        if f.stat().st_size > 512 * 1024:
            return ""
        return f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _go_build_ignored(txt: str) -> bool:
    m = re.search(r"^//go:build\s+(.+)$", txt, re.M)
    return bool(m and re.fullmatch(r"\s*ignore\s*", m.group(1)))


def go_imports(txt: str) -> list[str]:
    out = []
    for blk in _GO_IMPORT_BLOCK_RE.findall(txt):
        out += re.findall(r'"([^"]+)"', blk)
    out += _GO_IMPORT_ONE_RE.findall(txt)
    return out


def _go_package(files: list[Path]) -> tuple[str, list[tuple[Path, str]]]:
    texts = [(f, t) for f in files if (t := _go_text(f)) and not _go_build_ignored(t)]
    names = [m.group(1) for _, t in texts if (m := _GO_PKG_RE.search(_GO_COMMENT_RE.sub("", t)))]
    return (names[0] if names else ""), texts


def _reachable(mod_dir: Path, module: str, start: Path) -> tuple[list[Path], set[str], str]:
    """The module's packages a main package imports (transitively): their .go files, the outside import
    paths and their code (comments removed)."""
    files, ext, code, seen, stack = [], set(), [], set(), [start]
    while stack:
        d = stack.pop()
        if d in seen:
            continue
        seen.add(d)
        _, texts = _go_package(_go_files(d))
        for f, t in texts:
            files.append(f)
            code.append(_GO_COMMENT_RE.sub("", t))
            for imp in go_imports(t):
                if module and (imp == module or imp.startswith(module + "/")):
                    stack.append(mod_dir / imp[len(module):].lstrip("/"))
                else:
                    ext.add(imp)
    return files, ext, "\n".join(code)


def parse_go_projects(path: Path, root: Path, files: list[Path]):
    """One project per main package of the module of `path` (go.mod), or one library project."""
    from .scan import Project, read_text
    mod_dir = path.parent
    txt = read_text(path)
    m = re.search(r"^module\s+(\S+)", txt, re.M)
    module = m.group(1).strip('"') if m else ""
    requires = {mm.group(1): mm.group(2) for mm in re.finditer(r"^\s*(?:require\s+)?([\w./\-~]+)\s+(v[\w.\-+]+)", txt, re.M)}
    props = {"GoModule": module}
    m = re.search(r"^go\s+(\d+\.\d+)", txt, re.M)
    if m:
        props["GoVersion"] = m.group(1)
    m = re.search(r"^toolchain\s+go(\d+\.\d+)", txt, re.M)
    if m:
        props["GoToolchain"] = m.group(1)
    if (mod_dir / "vendor" / "modules.txt").is_file():
        props["GoVendor"] = "true"
    # folders of this module (not of a nested module, not vendored or test data) with Go files
    nested = {f.parent for f in files if f.name == "go.mod" and f.parent != mod_dir and f.parent.is_relative_to(mod_dir)}
    dirs = sorted({f.parent for f in files if f.suffix == ".go" and f.parent.is_relative_to(mod_dir)
                   and not any(p in ("vendor", "testdata", "examples", "example", "_examples", "hack", "tools")
                               or p.startswith((".", "_")) for p in f.parent.relative_to(mod_dir).parts)
                   and not any(f.parent.is_relative_to(n) for n in nested)})
    mains = [d for d in dirs if _go_package(_go_files(d))[0] == "main"]
    out = []
    for d in mains:
        fs, ext, code = _reachable(mod_dir, module, d)
        p = Project(path=path if d == mod_dir else d / ("main.go" if (d / "main.go").is_file() else _go_files(d)[0].name),
                    root=root, kind_hint="go", name=d.name if d != root else root.name)
        p.assembly_name = p.name
        p.properties.update(props)
        rel = str(d.relative_to(mod_dir)).replace("\\", "/")
        p.properties["GoMain"] = "true"
        p.properties["GoPackage"] = "." if rel == "." else "./" + rel
        p.properties["GoModDir"] = str(mod_dir.relative_to(root)).replace("\\", "/") if mod_dir != root else "."
        p.packages = {k: v for k, v in requires.items() if any(i == k or i.startswith(k + "/") for i in ext)}
        if GO_SERVER_RE.search(code):
            p.properties["GoServer"] = "true"
        if re.search(r'^\s*import\s+"C"|^\s*"C"\s*$', code, re.M):
            p.properties["GoCgo"] = "true"
        p.properties["GoImports"] = ",".join(sorted(ext))
        out.append(p)
    if not mains:
        p = Project(path=path, root=root, kind_hint="go", name=mod_dir.name if mod_dir != root else root.name)
        p.assembly_name = p.name
        p.properties.update(props)
        p.properties["GoMain"] = "false"
        p.packages = dict(requires)
        out.append(p)
    return out
