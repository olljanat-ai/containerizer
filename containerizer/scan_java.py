"""Java (JVM) build files: Maven pom.xml and Gradle build.gradle(.kts).

Nothing is executed: the build files are read as text, so values computed by build logic are not
seen. Each module becomes a `Project` (kind "java") with:

  packages        "groupId:artifactId" -> version (every scope; test scope also in dev_packages)
  dev_packages    test-only dependencies (Maven scope test, Gradle test*/androidTest* configurations)
  project_refs    the in-repository modules it depends on (Maven coordinates, Gradle project(':x'))
  properties      BuildTool (maven|gradle), Packaging (jar|war|ear|pom|...), JavaVersion,
                  SpringBootVersion, MainClass, Plugins (comma list: Maven plugin artifactIds or
                  Gradle plugin ids), Modules (aggregator), Wrapper (mvnw|gradlew),
                  GroupId, ArtifactId
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .scan import Project, _strip_ns, read_text

TEST_CONFIGS = re.compile(r"^(test\w*|androidTest\w*|integrationTest\w*|\w*[Tt]est(Implementation|CompileOnly|RuntimeOnly|Compile|Runtime|AnnotationProcessor))$")
GRADLE_CONFIGS = ("implementation|api|compile|runtime|runtimeOnly|compileOnly|compileOnlyApi|providedCompile|providedRuntime|"
                  "annotationProcessor|kapt|ksp|developmentOnly|testAndDevelopmentOnly|"
                  r"test\w*|androidTest\w*|integrationTest\w*|\w+Implementation|\w+Api|\w+CompileOnly|\w+RuntimeOnly")


# --------------------------------------------------------------------------- Maven

def _children(el, name):
    return [c for c in el if isinstance(c.tag, str) and _strip_ns(c.tag) == name] if el is not None else []


def _child(el, name):
    c = _children(el, name)
    return c[0] if c else None


def _txt(el, name, default=""):
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else default


def _parse_xml(path: Path):
    try:
        return ET.fromstring(read_text(path) or "<project/>")
    except ET.ParseError:
        return None


_PROP_RE = re.compile(r"\$\{([\w.\-]+)\}")


def _expand(v: str, props: dict) -> str:
    for _ in range(5):
        n = _PROP_RE.sub(lambda m: props.get(m.group(1), m.group(0)), v)
        if n == v:
            break
        v = n
    return v


def _pom_chain(path: Path, root: Path) -> list:
    """The pom and its in-repository parents (nearest first): <parent><relativePath> (default ../pom.xml)."""
    out, seen = [], set()
    cur = path
    while cur is not None and cur.resolve() not in seen:
        seen.add(cur.resolve())
        top = _parse_xml(cur)
        if top is None:
            break
        out.append((cur, top))
        par = _child(top, "parent")
        if par is None:
            break
        rel = _txt(par, "relativePath", "../pom.xml")
        if rel == "":                    # <relativePath/>: look up the parent in the repositories only
            break
        cand = (cur.parent / rel).resolve()
        if cand.is_dir():
            cand = cand / "pom.xml"
        if not cand.is_file() or root not in cand.parents:
            break
        ptop = _parse_xml(cand)
        if ptop is None or _txt(ptop, "artifactId") != _txt(par, "artifactId"):
            break
        cur = cand
    return out


def _java_version(props: dict) -> str:
    for k in ("maven.compiler.release", "java.version", "maven.compiler.source", "maven.compiler.target",
              "jdk.version", "java.release", "javaVersion", "jdkVersion", "java.source.version", "source.version"):
        v = props.get(k)
        if v and not v.startswith("${"):
            return _norm_java(v)
    return ""


def _norm_java(v: str) -> str:
    v = str(v).strip().strip("'\"")
    m = re.match(r"^(?:JavaVersion\.VERSION_)?1[._](\d+)$", v) or re.match(r"^(?:JavaVersion\.VERSION_)?(\d+)", v)
    return m.group(1) if m else ""


def parse_maven_project(path: Path, root: Path) -> Project:
    chain = _pom_chain(path, root)
    top = chain[0][1] if chain else None
    pr = Project(path=path, root=root, kind_hint="java", name=path.parent.name)
    pr.properties["BuildTool"] = "maven"
    if top is None:
        return pr
    # properties: parents first, so the module's own values win
    props: dict[str, str] = {}
    for _, el in reversed(chain):
        pe = _child(el, "properties")
        for p in (list(pe) if pe is not None else []):
            if isinstance(p.tag, str):
                props[_strip_ns(p.tag)] = (p.text or "").strip()
    par = _child(top, "parent")
    group = _txt(top, "groupId") or _txt(par, "groupId")
    artifact = _txt(top, "artifactId")
    version = _txt(top, "version") or _txt(par, "version")
    props.update({"project.groupId": group, "project.artifactId": artifact, "project.version": version,
                  "pom.groupId": group, "pom.artifactId": artifact, "pom.version": version,
                  "project.parent.version": _txt(par, "version"), "revision": props.get("revision", version)})
    pr.name = _expand(artifact, props) or pr.name
    pr.assembly_name = pr.name
    pr.properties["GroupId"] = _expand(group, props)
    pr.properties["ArtifactId"] = pr.name
    pr.properties["Packaging"] = _txt(top, "packaging", "jar").lower()
    # managed versions from in-repository parents (BOMs from repositories are not resolved)
    managed: dict[str, str] = {}
    for _, el in reversed(chain):
        for d in _children(_child(_child(el, "dependencyManagement"), "dependencies"), "dependency"):
            managed[f"{_expand(_txt(d, 'groupId'), props)}:{_expand(_txt(d, 'artifactId'), props)}"] = \
                _expand(_txt(d, "version"), props)
    # the Spring Boot line: starter parent (anywhere up the chain), the BOM import or the plugin version
    boot = ""
    for _, el in chain:
        p = _child(el, "parent")
        if p is not None and _txt(p, "groupId") == "org.springframework.boot":
            boot = _txt(p, "version")
            break
    if not boot:
        boot = managed.get("org.springframework.boot:spring-boot-dependencies", "")
    # dependencies: the module's own, its profiles' (mysql/postgres variants) and those inherited from
    # in-repository parents (Maven inherits <dependencies>, not <dependencyManagement>)
    deps_parents = []
    for _, el in chain:
        deps_parents.append(_child(el, "dependencies"))
        if el is top:
            deps_parents += [_child(prof, "dependencies") for prof in _children(_child(top, "profiles"), "profile")]
    for dp in deps_parents:
        for d in _children(dp, "dependency"):
            g, a = _expand(_txt(d, "groupId"), props), _expand(_txt(d, "artifactId"), props)
            if not a:
                continue
            key = f"{g}:{a}" if g else a
            v = _expand(_txt(d, "version"), props) or managed.get(key, "")
            _add_dep(pr, _txt(d, "scope").lower() or "compile", key, v)
    # build plugins: the module's own, and those inherited from in-repository parents (Maven inherits
    # <build><plugins>; <pluginManagement> only configures)
    plugins: list[str] = []
    inherited: list[str] = []
    main = ""
    for _, el in chain:
        builds = [_child(el, "build")] + [_child(pf, "build") for pf in _children(_child(el, "profiles"), "profile")]
        for pl in [x for b in builds for x in _children(_child(b, "plugins"), "plugin")]:
            aid = _txt(pl, "artifactId")
            if not aid:
                continue
            (plugins if el is top else inherited).append(aid)
            if aid == "spring-boot-maven-plugin" and not boot:
                boot = _expand(_txt(pl, "version"), props)
            if el is top and not main:
                m = re.search(r"<(?:\w+:)?(?:mainClass|main-class|Main-Class)>\s*([\w.${}]+)\s*<",
                              ET.tostring(pl, encoding="unicode"))
                if m:
                    main = m.group(1)
    main = main or props.get("start-class") or props.get("main.class") or props.get("mainClass") or ""
    if main:
        pr.properties["MainClass"] = _expand(main, props)
    pr.properties["Plugins"] = ",".join(dict.fromkeys(plugins))
    pr.properties["ParentPlugins"] = ",".join(dict.fromkeys(x for x in inherited if x not in plugins))
    if boot and not boot.startswith("${"):
        pr.properties["SpringBootVersion"] = boot
    elif boot or any(k.startswith("org.springframework.boot:") for k in pr.packages):
        pr.properties["SpringBootVersion"] = _expand(boot, props) if boot and "${" not in _expand(boot, props) else "unknown"
    jv = _java_version(props)
    if not jv:
        for _, el in chain:
            for pl in _children(_child(_child(el, "build"), "plugins"), "plugin") + \
                    _children(_child(_child(_child(el, "build"), "pluginManagement"), "plugins"), "plugin"):
                if _txt(pl, "artifactId") == "maven-compiler-plugin":
                    c = _child(pl, "configuration")
                    jv = _norm_java(_expand(_txt(c, "release") or _txt(c, "source"), props))
                    if jv:
                        break
            if jv:
                break
    if jv:
        pr.properties["JavaVersion"] = jv
    mods = [(m.text or "").strip() for m in _children(_child(top, "modules"), "module")]
    for prof in _children(_child(top, "profiles"), "profile"):
        mods += [(m.text or "").strip() for m in _children(_child(prof, "modules"), "module")]
    mods = list(dict.fromkeys(m for m in mods if m))
    if mods:
        pr.properties["Modules"] = ",".join(mods)
    _wrapper(pr, "mvnw")
    return pr


# --------------------------------------------------------------------------- Gradle

def _strip_gradle_comments(txt: str) -> str:
    from .scan import _strip_c_comments
    return _strip_c_comments(txt)


def _block(txt: str, name: str) -> list[tuple[int, int]]:
    """(start, end) spans of the bodies of top-level-ish `name { ... }` blocks."""
    out = []
    for m in re.finditer(rf"(?<![\w.]){name}\s*(?:\([^)]*\))?\s*\{{", txt):
        i, depth = m.end(), 1
        while i < len(txt) and depth:
            if txt[i] == "{":
                depth += 1
            elif txt[i] == "}":
                depth -= 1
            i += 1
        out.append((m.end(), i - 1))
    return out


def _cut(txt: str, spans: list[tuple[int, int]]) -> str:
    for s, e in sorted(spans, reverse=True):
        txt = txt[:s] + txt[e:]
    return txt


def version_catalog(root: Path) -> dict:
    """gradle/libs.versions.toml: alias -> "group:artifact:version", plugin alias -> id, bundles."""
    f = root / "gradle" / "libs.versions.toml"
    out = {"libraries": {}, "plugins": {}, "bundles": {}}
    if not f.is_file():
        return out
    try:
        import tomllib
        data = tomllib.loads(read_text(f))
    except Exception:     # noqa: BLE001 - a broken catalog only loses dependency names
        return out
    versions = data.get("versions") or {}

    def ver(v):
        if isinstance(v, dict):
            ref = v.get("ref")
            return str(versions.get(ref, "")) if ref else str(v.get("strictly") or v.get("require") or v.get("prefer") or "")
        return str(v or "")

    for alias, v in (data.get("libraries") or {}).items():
        if isinstance(v, str):
            parts = v.split(":")
            out["libraries"][alias] = (f"{parts[0]}:{parts[1]}" if len(parts) > 1 else v, parts[2] if len(parts) > 2 else "")
        elif isinstance(v, dict):
            mod = v.get("module") or (f"{v.get('group')}:{v.get('name')}" if v.get("group") else "")
            if mod:
                out["libraries"][alias] = (mod, ver(v.get("version")) if "version" in v else "")
    for alias, v in (data.get("plugins") or {}).items():
        pid = v if isinstance(v, str) else (v or {}).get("id", "")
        out["plugins"][alias] = pid.split(":")[0]
    out["bundles"] = {k: list(v) for k, v in (data.get("bundles") or {}).items() if isinstance(v, list)}
    return out


def _accessor(alias: str) -> str:
    return re.sub(r"[-_.]", ".", alias).lower()


_DEP_RE = re.compile(rf"^\s*(?P<conf>{GRADLE_CONFIGS})\s*(?:\(\s*)?(?P<rest>.+)$", re.M)


def _gradle_deps(txt: str, catalog: dict) -> list[tuple[str, str, str]]:
    """(configuration, "group:artifact" or "project::path", version) per dependency line."""
    libs = {_accessor(a): v for a, v in catalog["libraries"].items()}
    bundles = {_accessor(a): v for a, v in catalog["bundles"].items()}
    out = []
    for blk_s, blk_e in _block(txt, "dependencies"):
        body = txt[blk_s:blk_e]
        for m in _DEP_RE.finditer(body):
            conf, rest = m.group("conf"), m.group("rest")
            if conf in ("project", "platform"):
                continue
            for pm in re.finditer(r"project\s*\(\s*(?:path\s*[:=]\s*)?['\"](:?[\w\-.:]+)['\"]", rest):
                out.append((conf, "project:" + pm.group(1), ""))
            for gm in re.finditer(r"['\"]([\w.\-]+):([\w.\-]+)(?::([\w.\-+\[\]()]+))?(?::[\w\-]+)?(?:@\w+)?['\"]", rest):
                out.append((conf, f"{gm.group(1)}:{gm.group(2)}", gm.group(3) or ""))
            gm = re.search(r"group\s*[:=]\s*['\"]([\w.\-]+)['\"]\s*,\s*name\s*[:=]\s*['\"]([\w.\-]+)['\"]"
                           r"(?:\s*,\s*version\s*[:=]\s*['\"]([^'\"]+)['\"])?", rest)
            if gm:
                out.append((conf, f"{gm.group(1)}:{gm.group(2)}", gm.group(3) or ""))
            for lm in re.finditer(r"\blibs\.((?:bundles\.)?[\w.]+)", rest):
                acc = lm.group(1).lower()
                if acc.startswith("bundles."):
                    for a in bundles.get(acc[8:], []):
                        if _accessor(a) in libs:
                            mod, v = libs[_accessor(a)]
                            out.append((conf, mod, v))
                elif acc in libs:
                    mod, v = libs[acc]
                    out.append((conf, mod, v))
    return out


_PLUGIN_ID_RE = re.compile(r"""(?:^|\s|;)id\s*\(?\s*['"]([\w.\-]+)['"]|apply\s+plugin\s*:\s*['"]([\w.\-]+)['"]|"""
                           r"""^\s*(java|application|war|ear|java-library|java-platform|groovy|scala|`java-library`|`java-platform`)\s*$|"""
                           r"""kotlin\s*\(\s*['"]([\w.\-]+)['"]\s*\)|alias\s*\(\s*libs\.plugins\.([\w.]+)\s*\)""", re.M)


def _gradle_plugins(txt: str, catalog: dict) -> list[str]:
    plugins = {_accessor(a): v for a, v in catalog["plugins"].items()}
    out = []
    for m in _PLUGIN_ID_RE.finditer(txt):
        if m.group(5):
            pid = plugins.get(m.group(5).lower(), "")
        elif m.group(4):
            pid = "org.jetbrains.kotlin." + m.group(4)
        else:
            pid = (m.group(1) or m.group(2) or m.group(3) or "").strip("`")
        if pid and pid not in out:
            out.append(pid)
    return out


def gradle_settings(root_dir: Path) -> dict[str, Path]:
    """settings.gradle(.kts) next to a root build file: project path (':a:b') -> directory."""
    s = next((root_dir / n for n in ("settings.gradle", "settings.gradle.kts") if (root_dir / n).is_file()), None)
    if s is None:
        return {}
    txt = _strip_gradle_comments(read_text(s))
    out: dict[str, Path] = {}
    for m in re.finditer(r"^\s*include\s*\(?([^\n]+)", txt, re.M):
        for pm in re.finditer(r"['\"](:?[\w\-.:]+)['\"]", m.group(1)):
            p = ":" + pm.group(1).lstrip(":")
            out[p] = root_dir.joinpath(*p.strip(":").split(":"))
    for m in re.finditer(r"project\s*\(\s*['\"](:?[\w\-.:]+)['\"]\s*\)\s*\.projectDir\s*=\s*(?:file\s*\(\s*)?(?:new\s+File\s*\([^,]+,\s*)?['\"]([^'\"]+)['\"]", txt):
        out[":" + m.group(1).lstrip(":")] = (root_dir / m.group(2)).resolve()
    return out


def parse_gradle_project(path: Path, root: Path, inherited: dict | None = None) -> Project:
    """`inherited`: what a parent build applies to this module through subprojects {} / allprojects {}
    ({"deps": [...], "plugins": [...], "java": "17"})."""
    pr = Project(path=path, root=root, kind_hint="java", name=path.parent.name)
    pr.assembly_name = pr.name
    pr.properties["BuildTool"] = "gradle"
    txt = _strip_gradle_comments(read_text(path))
    catalog = version_catalog(_gradle_root(path.parent, root))
    shared = _block(txt, "subprojects") + _block(txt, "allprojects")
    own = _cut(txt, _block(txt, "subprojects"))       # allprojects {} applies to this project as well
    deps = _gradle_deps(own, catalog) + list((inherited or {}).get("deps") or [])
    plugins = _gradle_plugins(_cut(own, [s for s in _block(own, "buildscript")]), catalog) + \
        [p for p in (inherited or {}).get("plugins") or []]
    for conf, key, v in deps:
        if key.startswith("project:"):
            continue
        _add_dep(pr, conf, key, v)
    pr.properties["GradleProjectRefs"] = ",".join(sorted({k[8:] for c, k, _ in deps if k.startswith("project:")
                                                          and not TEST_CONFIGS.match(c)}))
    pr.properties["Plugins"] = ",".join(dict.fromkeys(plugins))
    packaging = "jar"
    if any(p in ("war", "org.gretty") for p in plugins):
        packaging = "war"
    elif "ear" in plugins:
        packaging = "ear"
    elif "java-platform" in plugins:
        packaging = "pom"
    pr.properties["Packaging"] = packaging
    boot = next((m.group(1) for m in re.finditer(r"id\s*\(?\s*['\"]org\.springframework\.boot['\"]\s*\)?\s*version\s*\(?\s*['\"]([\w.\-]+)['\"]", txt)), "")
    if not boot:
        boot = "unknown" if "org.springframework.boot" in plugins else ""
        m = re.search(r"org\.springframework\.boot:spring-boot-(?:gradle-plugin|dependencies):([\w.\-]+)", txt)
        boot = m.group(1) if m else boot
    if boot or "org.springframework.boot" in plugins or any(k.startswith("org.springframework.boot:") for k in pr.packages):
        pr.properties["SpringBootVersion"] = boot or "unknown"
    m = re.search(r"mainClass(?:Name)?\s*(?:\.set\s*\(|=|\()\s*['\"]([\w.$]+)['\"]", txt)
    if m:
        pr.properties["MainClass"] = m.group(1)
    jv = ""
    for rx in (r"JavaLanguageVersion\.of\s*\(\s*(\d+)", r"jvmToolchain\s*\(\s*(\d+)", r"options\.release\s*(?:=|\.set\s*\()\s*(\d+)",
               r"(?:source|target)Compatibility\s*=\s*(?:JavaVersion\.VERSION_)?['\"]?([\d._]+)", r"release\s*=\s*(\d+)"):
        mm = re.search(rx, txt)
        if mm:
            jv = _norm_java(mm.group(1))
            break
    jv = jv or (inherited or {}).get("java", "")
    if jv:
        pr.properties["JavaVersion"] = jv
    # what this build applies to its subprojects
    sub_txt = "\n".join(txt[s:e] for s, e in shared)
    pr.properties["_SubprojectDeps"] = repr(_gradle_deps(sub_txt, catalog)) if sub_txt else ""
    pr.properties["_SubprojectPlugins"] = ",".join(_gradle_plugins(sub_txt, catalog)) if sub_txt else ""
    m = re.search(r"(?:JavaLanguageVersion\.of\s*\(\s*(\d+)|(?:source|target)Compatibility\s*=\s*(?:JavaVersion\.VERSION_)?['\"]?([\d._]+))", sub_txt)
    pr.properties["_SubprojectJava"] = _norm_java(m.group(1) or m.group(2)) if m else ""
    _wrapper(pr, "gradlew")
    return pr


def _add_dep(pr: Project, conf: str, key: str, v: str) -> None:
    """A dependency is test-only (dev_packages) until a non-test configuration also declares it."""
    test = bool(TEST_CONFIGS.match(conf))
    if key not in pr.packages:
        pr.packages[key] = v
        if test:
            pr.dev_packages[key] = v
    elif not test:
        pr.dev_packages.pop(key, None)
        pr.packages[key] = pr.packages[key] or v


def _gradle_root(d: Path, root: Path) -> Path:
    """The Gradle build root of a module: the nearest folder up to the repository root with settings.gradle."""
    for cand in [d, *d.parents]:
        if any((cand / n).is_file() for n in ("settings.gradle", "settings.gradle.kts")):
            return cand
        if cand == root:
            break
    return d


def _wrapper(pr: Project, name: str) -> None:
    for cand in [pr.dir, *pr.dir.parents]:
        if (cand / name).is_file():
            pr.properties["Wrapper"] = name
            pr.properties["WrapperDir"] = str(cand.relative_to(pr.root)) if cand != pr.root else "."
            return
        if cand == pr.root:
            return


# --------------------------------------------------------------------------- linking modules

def link_java_projects(projects: list[Project], root: Path) -> None:
    """Module dependencies inside the repository become project references; Gradle subprojects {}
    configuration is applied to the modules it covers."""
    java = [p for p in projects if p.kind_hint == "java"]
    if not java:
        return
    by_coord = {}
    for p in java:
        if p.properties.get("BuildTool") == "maven" and p.properties.get("ArtifactId"):
            by_coord[f"{p.properties.get('GroupId', '')}:{p.properties['ArtifactId']}"] = p
            by_coord.setdefault(p.properties["ArtifactId"], p)
    for p in java:
        if p.properties.get("BuildTool") != "maven":
            continue
        for key in p.packages:
            q = by_coord.get(key) or (by_coord.get(key.split(":", 1)[-1]) if ":" not in key else None)
            if q is not None and q is not p:
                p.properties["InRepoDeps"] = ",".join(filter(None, [p.properties.get("InRepoDeps"), key]))
                if q.path.resolve() not in p.project_refs and key not in p.dev_packages:
                    p.project_refs.append(q.path.resolve())
    gradle = [p for p in java if p.properties.get("BuildTool") == "gradle"]
    by_dir = {p.dir.resolve(): p for p in gradle}
    for p in gradle:
        # subprojects {} / allprojects {} of every ancestor build apply to this module
        for anc in p.dir.resolve().parents:
            q = by_dir.get(anc)
            if q is None:
                if anc == root:
                    break
                continue
            sub = q.properties.get("_SubprojectDeps")
            if sub:
                import ast
                for conf, key, v in ast.literal_eval(sub):
                    if key.startswith("project:"):
                        continue
                    _add_dep(p, conf, key, v)
            plug = [x for x in (q.properties.get("_SubprojectPlugins") or "").split(",") if x]
            if plug:
                have = [x for x in (p.properties.get("Plugins") or "").split(",") if x]
                p.properties["Plugins"] = ",".join(dict.fromkeys(have + plug))
                if "war" in plug and p.properties.get("Packaging") == "jar":
                    p.properties["Packaging"] = "war"
            if not p.properties.get("JavaVersion") and q.properties.get("_SubprojectJava"):
                p.properties["JavaVersion"] = q.properties["_SubprojectJava"]
            if anc == root:
                break
        settings_root = _gradle_root(p.dir, root)
        modules = gradle_settings(settings_root)
        for ref in [x for x in (p.properties.get("GradleProjectRefs") or "").split(",") if x]:
            d = modules.get(":" + ref.lstrip(":")) or settings_root.joinpath(*ref.strip(":").split(":"))
            q = by_dir.get(Path(d).resolve())
            if q is not None and q is not p and q.path.resolve() not in p.project_refs:
                p.project_refs.append(q.path.resolve())
        if p.dir.resolve() == settings_root.resolve() and modules:
            p.properties["Modules"] = ",".join(m.strip(":") for m in modules)
    for p in gradle:
        for k in ("_SubprojectDeps", "_SubprojectPlugins", "_SubprojectJava"):
            p.properties.pop(k, None)
    for p in java:
        p.properties["SpringBoot"] = "true" if p.properties.get("SpringBootVersion") or any(
            k.startswith("org.springframework.boot:") for k in p.packages if k not in p.dev_packages) else "false"
