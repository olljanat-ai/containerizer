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
    if isinstance(eng.get("npm"), str) and eng["npm"].strip():
        pr.properties["NpmEngine"] = eng["npm"].strip()         # each Node.js line brings its own npm (images.yaml)
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


def engine_bounds(rng: str) -> list[tuple[int, int | None]] | None:
    """The Node.js major versions a semver range (engines.node) allows: (lowest, highest) per `||` alternative,
    highest None without an upper bound; None when the range allows anything or cannot be read.
    "^14" -> [(14, 14)], "12.x || 14.x" -> [(12, 12), (14, 14)], ">=10 <15" -> [(10, 14)], ">=18" -> [(18, None)]."""
    out = []
    for alt in str(rng).split("||"):
        alt = alt.strip()
        if not alt or alt in ("*", "x", "latest"):
            return None
        alt = re.sub(r"(\d\S*)\s+-\s+", r">=\1 <=", alt)       # "12 - 14" -> ">=12 <=14"
        low, top = 0, None
        for tok in re.findall(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", alt):
            op, major = tok[0], int(tok[1])
            minor_set = tok[2] not in ("", "x", "*")
            patch_set = tok[3] not in ("", "x", "*")
            if op in (">", ">="):
                # ">14" is 15 and up; ">14.2" still allows 14
                low = max(low, major + 1 if op == ">" and not minor_set else major)
                continue
            if op == "<":
                cap = major - 1 if not minor_set or (tok[2] == "0" and (not patch_set or tok[3] == "0")) else major
            else:                                       # ^ ~ = <= or a bare version
                cap = major
                if op != "<=":
                    low = max(low, major)
            top = cap if top is None else min(top, cap)
        out.append((low, top))
    return out or None


def engine_max_major(rng: str) -> int | None:
    """The newest Node.js major version a semver range (engines.node) allows; None when it has no
    upper bound (">=18", "*") or cannot be read. "^14" -> 14, "12.x || 14.x" -> 14, ">=10 <15" -> 14."""
    bounds = engine_bounds(rng)
    if not bounds or any(top is None for _, top in bounds):
        return None
    return max(top for _, top in bounds)


def engine_allows(rng: str, major: int) -> bool:
    """Whether the range allows this Node.js major version (a range that cannot be read allows any)."""
    bounds = engine_bounds(rng)
    return not bounds or any(low <= major and (top is None or major <= top) for low, top in bounds)


def version_allows(rng: str, version: str) -> bool:
    """Whether a semver range (engines.npm: ">=10.9.0 <11", "^10 || ^11", "10.x") allows a full version ("10.9.4").
    A range that cannot be read allows any."""
    try:
        ver = tuple(int(x) for x in (version.split(".") + ["0", "0"])[:3])
    except ValueError:
        return True
    read = False
    for alt in str(rng).split("||"):
        alt = re.sub(r"(\d\S*)\s+-\s+", r">=\1 <=", alt.strip())
        if alt in ("", "*", "x", "latest"):
            return True
        toks = re.findall(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", alt)
        ok = bool(toks)
        for op, a, b, c in toks:
            read = True
            given = [int(a)] + [int(x) for x in (b, c) if x not in ("", "x", "*")]
            low = tuple(given + [0] * (3 - len(given)))
            if len(given) == 3 and op in ("", "="):
                ok &= ver == low
            elif op in ("", "=", "~", "^"):             # 10 / 10.9 / ~10.9.1 / ^10.9: from there to the next step
                keep = 1 if op == "^" and given[0] > 0 else max(1, len(given) - (1 if op == "~" and len(given) == 3 else 0))
                ok &= ver >= low and ver[:keep] == low[:keep]
            elif op == ">=":
                ok &= ver >= low
            elif op == ">":
                ok &= ver[:len(given)] > tuple(given)
            elif op == "<":
                ok &= ver < low
            elif op == "<=":
                ok &= ver[:len(given)] <= tuple(given)
        if ok:
            return True
    return not read


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


def angular_apps(projects: list[Project], root: Path) -> list[Project]:
    """The applications of an Angular workspace that has several (angular.json `projects` with a build target, not
    libraries): each becomes a project of its own, built from the workspace with `ng build <name>`. The workspace's
    package.json builds no application itself then (AngularWorkspace -> role library). A workspace with one
    application stays one project, as before.

    An application's project file is a file of its own folder (tsconfig.app.json, ...): the workspace's package.json
    gives it its packages, lockfile and package manager. Properties: AngularProject (the name), AngularOutput (its
    outputPath, in the workspace), AngularBuild (the package.json script that builds it, if one does),
    WorkspaceRoot (the workspace's package.json)."""
    from dataclasses import replace
    out, taken = [], {q.path.resolve() for q in projects}
    for p in [q for q in projects if q.kind_hint == "node"]:
        ws = _json(p.dir / "angular.json").get("projects")
        apps = []
        for name, cfg in (ws.items() if isinstance(ws, dict) else []):
            targets = (cfg.get("architect") or cfg.get("targets")) if isinstance(cfg, dict) else None
            build = targets.get("build") if isinstance(targets, dict) else None
            if isinstance(build, dict) and cfg.get("projectType", "application") == "application" \
                    and re.fullmatch(r"[\w@][\w.@/-]{0,99}", str(name)):
                apps.append((str(name), cfg, build))
        if len(apps) < 2:
            continue
        scripts = {k: v for k, v in (p.manifest.get("scripts") or {}).items() if isinstance(v, str)}
        made = []
        for name, cfg, build in apps:
            opts = build.get("options") if isinstance(build.get("options"), dict) else {}
            base = (p.dir / str(cfg.get("root") or "")).resolve()
            if not base.is_dir() or not base.is_relative_to(p.dir.resolve()):
                continue
            named = [p.dir / str(opts[k]) for k in ("tsConfig", "index", "browser", "main") if isinstance(opts.get(k), str)]
            cands = [base / "tsconfig.app.json", base / "project.json", *named, base / "src" / "main.ts",
                     base / "src" / "index.html"]
            path = next((f for f in cands if f.is_file() and f.resolve() not in taken
                         and f.resolve().is_relative_to(root.resolve())), None)
            if path is None:
                continue
            taken.add(path.resolve())
            op = opts.get("outputPath")
            op = op if isinstance(op, str) else (op.get("base") if isinstance(op, dict) else None)
            script = next((k for k, v in sorted(scripts.items()) if re.search(
                r"\bng\s+build\b(?!.*--watch).*?(--project[=\s]+|\s)['\"]?" + re.escape(name) + r"['\"]?(\s|$)", v)
                and "&&" not in v), "")
            props = {k: v for k, v in p.properties.items() if k not in ("Workspaces", "StartScript", "BuildScript", "Bin",
                                                                        "Main", "LibraryManifest")}
            props.update(AngularProject=name, AngularOutput=str(op or f"dist/{name}").strip("/"), AngularBuild=script,
                         AngularConfiguration="production" if "production" in (build.get("configurations") or {}) else "",
                         WorkspaceRoot=p.rel, IndexHtml="true")
            made.append(replace(p, path=path, name=name, assembly_name=name, properties=props, files=[],
                                project_refs=list(p.project_refs), manifest={**p.manifest, "name": name, "scripts": {}},
                                _text_cache={}))
        if len(made) >= 2:
            p.properties["AngularWorkspace"] = "true"
            out += made
    return out


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
