"""Node.js packages: package.json, the workspace layout and the lockfile.

Nothing is executed and nothing is installed: the manifest and the lockfile are read as data.
Each package.json becomes a `Project` (kind "node") with:

  packages        dependencies, devDependencies and optionalDependencies -> version range
  dev_packages    devDependencies that are not also runtime dependencies
  project_refs    workspace packages of the same repository it depends on
  properties      NpmScripts (sorted names), StartScript (the start command), PackageManager
                  (npm|pnpm|yarn|bun), Lockfile (path), NodeEngine (engines.node), Main, Bin ("true"),
                  ModuleType (module|commonjs), Private, Workspaces (globs: a monorepo root),
                  WorkspaceRoot (the root package of a workspace member), TypeScript ("true"),
                  LockWindowsOnly / LockNativeBuild: runtime packages (the package's own and their
                  dependencies, from package-lock.json or pnpm-lock.yaml) that install only on
                  Windows, or that compile a native addon at install time
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from .scan import Project, read_text

LOCKFILES = (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("package-lock.json", "npm"),
             ("npm-shrinkwrap.json", "npm"), ("bun.lock", "bun"), ("bun.lockb", "bun"))


MAX_LOCK_BYTES = 64 * 1024 * 1024


def _read_lock(path: Path) -> str:
    """Lockfiles are often larger than the scanner's source-file limit."""
    try:
        if path.stat().st_size > MAX_LOCK_BYTES:
            return ""
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _json(path: Path, lock: bool = False) -> dict:
    try:
        d = json.loads((_read_lock(path) if lock else read_text(path)) or "{}")
    except (json.JSONDecodeError, RecursionError):
        return {}
    return d if isinstance(d, dict) else {}


def _deps(m: dict, key: str) -> dict:
    d = m.get(key)
    return {str(k): str(v) for k, v in d.items()} if isinstance(d, dict) else {}


def parse_node_project(path: Path, root: Path) -> Project:
    pr = Project(path=path, root=root, kind_hint="node", name=path.parent.name)
    pr.manifest = _json(path)
    m = pr.manifest
    runtime = {**_deps(m, "dependencies"), **_deps(m, "optionalDependencies")}
    dev = _deps(m, "devDependencies")
    pr.packages = {**dev, **runtime}
    pr.dev_packages = {k: v for k, v in dev.items() if k not in runtime}
    pr.name = str(m.get("name") or pr.name)
    pr.assembly_name = pr.name
    scripts = m.get("scripts") if isinstance(m.get("scripts"), dict) else {}
    # npm script names (comma-separated, sorted) so role rules can tell a test harness from an app
    pr.properties["NpmScripts"] = ",".join(sorted(scripts))
    for name in ("start", "serve", "start:prod", "prod"):
        if isinstance(scripts.get(name), str):
            pr.properties["StartScript"] = scripts[name]
            break
    if isinstance(scripts.get("build"), str):
        pr.properties["BuildScript"] = scripts["build"]
    if isinstance(m.get("main"), str):
        pr.properties["Main"] = m["main"]
    if m.get("bin"):
        pr.properties["Bin"] = "true"
    pr.properties["ModuleType"] = "module" if m.get("type") == "module" else "commonjs"
    if m.get("private") is True:
        pr.properties["Private"] = "true"
    eng = m.get("engines") if isinstance(m.get("engines"), dict) else {}
    if isinstance(eng.get("node"), str):
        pr.properties["NodeEngine"] = eng["node"]
        top = engine_max_major(eng["node"])
        if top is not None:
            pr.properties["NodeEngineMax"] = str(top)
    ws = m.get("workspaces")
    globs = ws if isinstance(ws, list) else (ws.get("packages") if isinstance(ws, dict) else None) or []
    pnpm_ws = path.parent / "pnpm-workspace.yaml"
    if pnpm_ws.is_file():
        import yaml
        try:
            globs = list(globs) + list((yaml.safe_load(read_text(pnpm_ws)) or {}).get("packages") or [])
        except yaml.YAMLError:
            pass
    if globs:
        pr.properties["Workspaces"] = ",".join(str(g) for g in globs)
    # published-library markers: an entry for importers, a files allow-list, peer dependencies
    if any(m.get(k) for k in ("exports", "module", "types", "typings", "files", "peerDependencies")):
        pr.properties["LibraryManifest"] = "true"
    if any((path.parent / d / "index.html").is_file() for d in (".", "public", "src", "app")):
        pr.properties["IndexHtml"] = "true"
    if (path.parent / "tsconfig.json").is_file() or "typescript" in pr.packages:
        pr.properties["TypeScript"] = "true"
    pm = m.get("packageManager")
    if isinstance(pm, str) and pm:
        pr.properties["PackageManager"] = pm.split("@")[0]
        pr.properties["PackageManagerVersion"] = pm.split("@", 1)[1].split("+")[0] if "@" in pm else ""
    return pr


def engine_max_major(rng: str) -> int | None:
    """The newest Node.js major version a semver range (engines.node) allows; None when it has no
    upper bound (">=18", "*") or cannot be read. "^14" -> 14, "12.x || 14.x" -> 14, ">=10 <15" -> 14."""
    best = -1
    for alt in str(rng).split("||"):
        alt = alt.strip()
        if not alt or alt in ("*", "x", "latest"):
            return None
        alt = re.sub(r"\s+-\s+", " <=", alt)           # "12 - 14" -> "12 <=14"
        top = None
        for tok in re.findall(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", alt):
            op, major = tok[0], int(tok[1])
            minor_set = tok[2] not in ("", "x", "*")
            patch_set = tok[3] not in ("", "x", "*")
            if op in (">", ">="):
                continue
            if op == "<":
                cap = major - 1 if not minor_set or (tok[2] == "0" and (not patch_set or tok[3] == "0")) else major
            else:                                       # ^ ~ = <= or a bare version
                cap = major
            top = cap if top is None else min(top, cap)
        if top is None:
            return None                                 # only lower bounds
        best = max(best, top)
    return best if best >= 0 else None


def _find_lockfile(d: Path, root: Path) -> tuple[Path, str] | None:
    for cand in [d, *d.parents]:
        for name, pm in LOCKFILES:
            if (cand / name).is_file():
                return cand / name, pm
        if cand == root:
            break
    return None


def _ws_members(rootp: Project, projects: list[Project]) -> list[Project]:
    globs = [g for g in (rootp.properties.get("Workspaces") or "").split(",") if g]
    if not globs:
        return []
    inc = [g.rstrip("/") for g in globs if not g.startswith("!")]
    exc = [g[1:].rstrip("/") for g in globs if g.startswith("!")]
    out = []
    for q in projects:
        if q is rootp or q.kind_hint != "node":
            continue
        try:
            rel = str(q.dir.relative_to(rootp.dir)).replace("\\", "/")
        except ValueError:
            continue
        match = lambda g: fnmatch.fnmatch(rel, g) or (g.endswith("/**") and (rel == g[:-3] or rel.startswith(g[:-2])))
        if any(match(g) for g in inc) and not any(match(g) for g in exc):
            out.append(q)
    return out


def link_node_projects(projects: list[Project], root: Path) -> None:
    node = [p for p in projects if p.kind_hint == "node"]
    if not node:
        return
    by_name: dict[str, Project] = {}
    for p in node:
        by_name.setdefault(p.name, p)
    for p in node:
        for q in _ws_members(p, node):
            q.properties.setdefault("WorkspaceRoot", p.rel)
    for p in node:
        for dep, ver in p.packages.items():
            q = by_name.get(dep)
            if q is None or q is p or dep in p.dev_packages:
                continue
            same_ws = q.properties.get("WorkspaceRoot") and q.properties.get("WorkspaceRoot") == p.properties.get("WorkspaceRoot")
            if same_ws or ver.startswith(("workspace:", "file:", "link:", "portal:")) or ver == "*":
                if q.path.resolve() not in p.project_refs:
                    p.project_refs.append(q.path.resolve())
    for p in node:
        lf = _find_lockfile(p.dir, root)
        if lf is None:
            continue
        lock, pm = lf
        p.properties["Lockfile"] = str(lock.relative_to(root))
        p.properties.setdefault("PackageManager", pm)
        try:
            win, native = lock_facts(p, lock, pm)
        except Exception:     # noqa: BLE001 - a lockfile that cannot be read only loses these facts
            continue
        if win:
            p.properties["LockWindowsOnly"] = ",".join(sorted(win))
        if native:
            p.properties["LockNativeBuild"] = ",".join(sorted(native))


# --------------------------------------------------------------------------- lockfiles

def _windows_only(os_list) -> bool:
    if not isinstance(os_list, list) or not os_list:
        return False
    allowed = [str(x) for x in os_list if not str(x).startswith("!")]
    denied = [str(x)[1:] for x in os_list if str(x).startswith("!")]
    if allowed:
        return "linux" not in allowed
    return "linux" in denied


def lock_facts(p: Project, lock: Path, pm: str) -> tuple[set[str], set[str]]:
    """(Windows-only packages, packages with an install script) among p's runtime dependencies and
    everything they pull in. Optional dependencies that are Windows-only are fine (npm skips them)."""
    runtime = [d for d in p.packages if d not in p.dev_packages]
    if pm == "npm":
        return _npm_lock(p, lock, runtime)
    if pm == "pnpm":
        return _pnpm_lock(p, lock, runtime)
    return set(), set()


def _npm_lock(p: Project, lock: Path, runtime: list[str]) -> tuple[set[str], set[str]]:
    data = _json(lock, lock=True)
    pk = data.get("packages")
    if not isinstance(pk, dict) or not pk:
        return set(), set()          # lockfileVersion 1: no per-package os / install script data
    base = str(p.dir.relative_to(lock.parent)).replace("\\", "/")
    base = "" if base == "." else base

    def resolve(frm: str, name: str) -> str | None:
        # node's lookup: <frm>/node_modules/<name>, then each enclosing node_modules up to the root
        cur = frm
        while True:
            key = f"{cur}/node_modules/{name}" if cur else f"node_modules/{name}"
            if key in pk:
                return key
            if not cur:
                return None
            i = cur.rfind("/node_modules/")
            cur = cur[:i] if i >= 0 else ""

    win, native, seen = set(), set(), set()
    stack = [(base, n, False) for n in runtime]
    while stack:
        frm, name, optional = stack.pop()
        key = resolve(frm, name)
        if key is None or key in seen:
            continue
        seen.add(key)
        e = pk.get(key) or {}
        if e.get("link") and isinstance(e.get("resolved"), str):
            continue                                    # a workspace package: its own project
        opt = optional or bool(e.get("optional"))
        if _windows_only(e.get("os")) and not opt:
            win.add(name)
        if e.get("hasInstallScript") and not opt:
            native.add(name)
        for n in (e.get("dependencies") or {}):
            stack.append((key, n, opt))
        for n in (e.get("optionalDependencies") or {}):
            stack.append((key, n, True))
    return win, native


def _pnpm_lock(p: Project, lock: Path, runtime: list[str]) -> tuple[set[str], set[str]]:
    import yaml
    try:
        data = yaml.load(_read_lock(lock), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)) or {}
    except yaml.YAMLError:
        return set(), set()
    importers = data.get("importers") or {".": data}
    rel = str(p.dir.relative_to(lock.parent)).replace("\\", "/") or "."
    imp = importers.get(rel) or {}
    pkgs = data.get("packages") or {}
    snaps = data.get("snapshots") or pkgs          # lockfile v9 splits metadata and dependency graph

    def ver_of(spec):
        return spec.get("version") if isinstance(spec, dict) else spec

    def key_of(name, ver):
        ver = str(ver or "")
        for k in (f"{name}@{ver}", f"/{name}@{ver}", f"/{name}/{ver}"):
            if k in snaps or k in pkgs:
                return k
        return None

    def meta(k):
        base = re.sub(r"\(.*$", "", k)               # peer suffixes: name@1.0.0(react@18.0.0)
        return pkgs.get(k) or pkgs.get(base) or {}

    win, native, seen = set(), set(), set()
    stack = []
    for sect in ("dependencies", "optionalDependencies"):
        for n, spec in (imp.get(sect) or {}).items():
            if n in runtime:
                stack.append((n, ver_of(spec), sect == "optionalDependencies"))
    while stack:
        name, ver, optional = stack.pop()
        if str(ver or "").startswith("link:"):
            continue
        k = key_of(name, ver)
        if k is None or k in seen:
            continue
        seen.add(k)
        md, sn = meta(k), snaps.get(k) or {}
        opt = optional or bool(md.get("optional") or sn.get("optional"))
        if _windows_only(md.get("os")) and not opt:
            win.add(name)
        if (md.get("requiresBuild") or sn.get("requiresBuild")) and not opt:
            native.add(name)          # optional ones (platform binaries such as @esbuild/*) may fail to build
        for n, v in (sn.get("dependencies") or md.get("dependencies") or {}).items():
            stack.append((n, v, opt))
        for n, v in (sn.get("optionalDependencies") or md.get("optionalDependencies") or {}).items():
            stack.append((n, v, True))
    return win, native
