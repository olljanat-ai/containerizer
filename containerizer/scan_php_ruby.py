"""PHP and Ruby applications: composer.json / Gemfile, their lockfiles, and PHP sites without Composer.

Nothing is executed and nothing is installed: the manifests and lockfiles are read as data. Each
becomes a `Project` (kind "php" or "ruby") with:

  packages        Composer require / require-dev, Gemfile gems (versions from the lockfile when there is one)
  dev_packages    require-dev; gems only in development/test groups
  properties      PHP:  PhpVersion (the newest major.minor `require.php` allows, or the lock's platform),
                        PhpExtensions (ext-* the app and its locked packages require, comma-separated),
                        Framework (laravel|symfony|wordpress|drupal|slim|cakephp|codeigniter|yii|plain),
                        DocRoot (the web root under the project folder, "" for the folder itself),
                        ComposerType (library|project|...), ComposerBin ("true"), Lockfile
                  Ruby: RubyVersion (.ruby-version, Gemfile `ruby`, Gemfile.lock RUBY VERSION),
                        BundlerVersion (BUNDLED WITH), Framework (rails|sinatra|hanami|roda|rack),
                        ConfigRu ("true"), Gemspec ("true": a gem), Lockfile
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .scan import Project, read_text

MAX_LOCK_BYTES = 32 * 1024 * 1024


def _read_big(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > MAX_LOCK_BYTES:
            return ""
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _json(path: Path, big: bool = False) -> dict:
    try:
        d = json.loads((_read_big(path) if big else read_text(path)) or "{}")
    except (json.JSONDecodeError, RecursionError):
        return {}
    return d if isinstance(d, dict) else {}


# --------------------------------------------------------------------------- PHP

PHP_FRAMEWORKS = (   # (framework, composer package that marks it), first match wins
    ("laravel", "laravel/framework"), ("laravel", "laravel/lumen-framework"),
    ("wordpress", "johnpbloch/wordpress"), ("wordpress", "roots/wordpress"), ("wordpress", "johnpbloch/wordpress-core"),
    ("drupal", "drupal/core"), ("drupal", "drupal/core-recommended"),
    ("symfony", "symfony/framework-bundle"), ("cakephp", "cakephp/cakephp"),
    ("codeigniter", "codeigniter4/framework"), ("yii", "yiisoft/yii2"), ("slim", "slim/slim"),
)


def php_range(constraint: str) -> tuple[str | None, str | None]:
    """(lowest, highest) PHP version a Composer constraint allows, as major.minor; the highest is a bare
    major ("8": any 8.x) for ^ and ~X.Y, and None when there is no upper bound.
    "^7.4|^8.0" -> ("7.4", "8"), ">=7.2" -> ("7.2", None), "~8.2.0" -> ("8.2", "8.2"), "7.4.*" -> ("7.4", "7.4")."""
    lows, highs, open_top = [], [], False
    for alt in re.split(r"\s*\|\|?\s*", str(constraint or "").strip()):
        if not alt:
            continue
        lo = hi = None
        unbounded = True
        for op, major, minor, patch in re.findall(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|\*|x))?(?:\.(\d+|\*|x))?", alt):
            mi = minor if minor.isdigit() else None
            if op in ("<", "<="):
                unbounded = False
                if op == "<" and (mi in (None, "0")):
                    top = (int(major) - 1, None)
                elif op == "<":
                    top = (int(major), int(mi) - 1)
                else:
                    top = (int(major), int(mi) if mi else None)
                hi = top if hi is None else min(hi, top, key=lambda t: (t[0], t[1] if t[1] is not None else 99))
                continue
            here = (int(major), int(mi) if mi else 0)
            lo = here if lo is None else max(lo, here)
            if op in (">", ">="):
                continue
            unbounded = False
            if op == "^" or op == "~" and not patch or not mi:
                top = (int(major), None)
            else:                                   # ~X.Y.Z, X.Y.*, X.Y.Z
                top = (int(major), int(mi))
            hi = top if hi is None else min(hi, top, key=lambda t: (t[0], t[1] if t[1] is not None else 99))
        if lo is not None:
            lows.append(lo)
        if unbounded:
            open_top = True
        elif hi is not None:
            highs.append(hi)
    low = f"{min(lows)[0]}.{min(lows)[1]}" if lows else None
    if open_top or not highs:
        return low, None
    top = max(highs, key=lambda t: (t[0], t[1] if t[1] is not None else 99))
    return low, (str(top[0]) if top[1] is None else f"{top[0]}.{top[1]}")


def _plain_php_framework(d: Path) -> str:
    if (d / "wp-includes").is_dir() or (d / "wp-config.php").is_file() or (d / "wp-config-sample.php").is_file():
        return "wordpress"
    if (d / "core" / "lib" / "Drupal.php").is_file():
        return "drupal"
    return "plain"


def parse_php_project(path: Path, root: Path) -> Project:
    """composer.json, or (a site without Composer) the index.php of its web root."""
    pr = Project(path=path, root=root, kind_hint="php", name=path.parent.name)
    props = pr.properties
    d = path.parent
    exts: set[str] = set()
    if path.name == "composer.json":
        m = pr.manifest = _json(path)
        req = m.get("require") if isinstance(m.get("require"), dict) else {}
        dev = m.get("require-dev") if isinstance(m.get("require-dev"), dict) else {}
        pr.packages = {str(k).lower(): str(v) for k, v in {**dev, **req}.items()}
        pr.dev_packages = {str(k).lower(): str(v) for k, v in dev.items() if k not in req}
        if isinstance(m.get("name"), str) and m["name"]:
            pr.name = m["name"].split("/")[-1]
        props["ComposerType"] = str(m.get("type") or "project")
        if m.get("bin"):
            props["ComposerBin"] = "true"
        lo, hi = php_range(req.get("php", ""))
        plat = ((m.get("config") or {}).get("platform") or {}) if isinstance(m.get("config"), dict) else {}
        if isinstance(plat, dict) and isinstance(plat.get("php"), str):
            # config.platform.php: the PHP version the dependencies were resolved for
            lo, hi = php_range(plat["php"])[0], ".".join(plat["php"].split(".")[:2])
        exts |= {k[4:].lower() for k in req if str(k).lower().startswith("ext-")}
        lock = d / "composer.lock"
        if lock.is_file():
            props["Lockfile"] = str(lock.relative_to(root)).replace("\\", "/")
            data = _json(lock, big=True)
            for pk in data.get("packages") or []:
                if not isinstance(pk, dict):
                    continue
                name = str(pk.get("name") or "").lower()
                if name and name in pr.packages:
                    pr.packages[name] = str(pk.get("version") or pr.packages[name])
                for k in (pk.get("require") or {}):
                    if str(k).lower().startswith("ext-"):
                        exts.add(str(k)[4:].lower())
        if lo:
            props["PhpVersion"] = lo
        if hi:
            props["PhpVersionMax"] = hi
        fw = next((f for f, pkg in PHP_FRAMEWORKS if pkg in pr.packages and pkg not in pr.dev_packages), None)
        if fw is None and "symfony/http-kernel" in pr.packages and (d / "public" / "index.php").is_file():
            fw = "symfony"
        props["Framework"] = fw or _plain_php_framework(d)
    else:
        props["Framework"] = _plain_php_framework(d)
        pr.name = d.name if d != root else root.name
    pr.assembly_name = pr.name
    if exts:
        props["PhpExtensions"] = ",".join(sorted(exts))
    # the web root: public/ (Laravel, Symfony, Slim, CakePHP webroot), web/ (Drupal composer projects), else the folder
    for cand in ("public", "web", "webroot", "htdocs", "public_html", "www"):
        if (d / cand / "index.php").is_file():
            props["DocRoot"] = cand
            break
    else:
        props["DocRoot"] = ""
    if (d / "index.php").is_file() or props["DocRoot"]:
        props["IndexPhp"] = "true"
    return pr


def plain_php_sites(files: list[Path], root: Path, projects: list[Project]) -> list[Project]:
    """Sites without composer.json: the shallowest folder with an index.php that no other project contains
    (WordPress core has an index.php in wp-admin/ and wp-content/ too: they are part of the site)."""
    taken = [p.dir.resolve() for p in projects]
    out: list[Project] = []
    for f in sorted((f for f in files if f.name.lower() == "index.php"), key=lambda f: len(f.parts)):
        d = f.parent.resolve()
        if any(d == t or t in d.parents for t in taken):
            continue
        p = parse_php_project(f, root)
        out.append(p)
        taken.append(d)
    return out


# --------------------------------------------------------------------------- Ruby

RUBY_FRAMEWORKS = (("rails", "rails"), ("rails", "railties"), ("hanami", "hanami"), ("sinatra", "sinatra"),
                   ("roda", "roda"), ("grape", "grape"))
GEM_RE = re.compile(r"""^\s*gem\s+['"]([\w.\-]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""")
GROUP_RE = re.compile(r"^\s*group\s+(.+?)\s+do\b")


def ruby_version(txt: str) -> str | None:
    m = re.search(r"(\d+)\.(\d+)(?:\.\d+)?", txt or "")
    return f"{m.group(1)}.{m.group(2)}" if m else None


def parse_gemfile(txt: str) -> tuple[dict[str, str], set[str]]:
    """(gem -> version requirement, gems only in development/test groups)."""
    gems: dict[str, str] = {}
    dev: set[str] = set()
    runtime: set[str] = set()
    stack: list[bool] = []                      # for each open `do` block: is it a dev/test-only group
    for line in txt.splitlines():
        s = line.split("#", 1)[0]
        g = GROUP_RE.match(s)
        if g:
            names = {a or b for a, b in re.findall(r":(\w+)|['\"](\w+)['\"]", g.group(1))}
            stack.append(bool(names) and names <= {"development", "test"})
            continue
        if re.match(r"^\s*(platforms?|source|install_if|path|git|github)\b.*\bdo\b", s):
            stack.append(any(stack))
            continue
        if re.match(r"^\s*end\b", s) and stack:
            stack.pop()
            continue
        m = GEM_RE.match(s)
        if m:
            name = m.group(1)
            gems.setdefault(name, m.group(2) or "")
            only = re.search(r"\bgroups?:\s*\[?\s*((?::\w+\s*,?\s*)+)\]?", s)
            in_dev = any(stack) or bool(only and set(re.findall(r":(\w+)", only.group(1))) <= {"development", "test"})
            (dev if in_dev else runtime).add(name)
    return gems, dev - runtime


def parse_gemfile_lock(txt: str) -> tuple[dict[str, str], str | None, str | None]:
    """(locked gem -> version, RUBY VERSION, BUNDLED WITH)."""
    specs: dict[str, str] = {}
    section = ""
    ruby = bundler = None
    lines = txt.splitlines()
    for i, line in enumerate(lines):
        if line and not line.startswith(" "):
            section = line.strip()
            continue
        if section in ("GEM", "PATH", "GIT"):
            m = re.match(r"^ {4}([\w.\-]+) \(([^)]+)\)$", line)
            if m:
                specs.setdefault(m.group(1), m.group(2).split("-")[0])
        elif section == "RUBY VERSION" and line.strip():
            ruby = ruby or ruby_version(line)
        elif section == "BUNDLED WITH" and line.strip():
            bundler = bundler or line.strip()
    return specs, ruby, bundler


def parse_ruby_project(path: Path, root: Path) -> Project:
    pr = Project(path=path, root=root, kind_hint="ruby", name=path.parent.name)
    d = path.parent
    props = pr.properties
    txt = read_text(path)
    gems, dev = parse_gemfile(txt)
    lock = d / "Gemfile.lock"
    locked, lruby, bundler = parse_gemfile_lock(_read_big(lock)) if lock.is_file() else ({}, None, None)
    if lock.is_file():
        props["Lockfile"] = str(lock.relative_to(root)).replace("\\", "/")
    pr.packages = {g: locked.get(g) or v for g, v in gems.items()}
    # gems the bundle pulls in (rails -> actionpack, ...) count for rules too, as runtime unless only dev ones need them
    for g, v in locked.items():
        pr.packages.setdefault(g, v)
    pr.dev_packages = {g: pr.packages[g] for g in dev}
    rv = None
    # Bundler refuses to run on another Ruby than an exact `ruby "3.2.2"` in the Gemfile (also through
    # `ruby file: ".ruby-version"`): the image must be that exact version
    m = re.search(r"""^\s*ruby\s+(?:['"]=?\s*(\d+\.\d+\.\d+)['"]|file:\s*['"]([^'"]+)['"])""", txt, re.M)
    if m:
        exact = m.group(1)
        if m.group(2) and (d / m.group(2)).is_file():
            mm = re.search(r"(\d+\.\d+\.\d+)", read_text(d / m.group(2)))
            exact = mm.group(1) if mm else None
        if exact:
            props["RubyExact"] = exact
    if (d / ".ruby-version").is_file():
        rv = ruby_version(read_text(d / ".ruby-version").replace("ruby-", ""))
    if rv is None:
        m = re.search(r"""^\s*ruby\s+['"]([^'"]+)['"]""", txt, re.M)
        rv = ruby_version(m.group(1)) if m else None
    if rv is None and (d / ".tool-versions").is_file():
        m = re.search(r"^ruby\s+(\S+)", read_text(d / ".tool-versions"), re.M)
        rv = ruby_version(m.group(1)) if m else None
    rv = rv or lruby
    if rv:
        props["RubyVersion"] = rv
    if bundler:
        props["BundlerVersion"] = bundler
    runtime = {g for g in gems if g not in dev}
    fw = next((f for f, g in RUBY_FRAMEWORKS if g in runtime), None)
    if fw is None and (d / "config" / "application.rb").is_file() and "rails" in pr.packages:
        fw = "rails"
    if (d / "config.ru").is_file():
        props["ConfigRu"] = "true"
        fw = fw or "rack"
    if fw:
        props["Framework"] = fw
    if any(f.suffix == ".gemspec" for f in d.glob("*.gemspec")) or re.search(r"^\s*gemspec\b", txt, re.M):
        props["Gemspec"] = "true"
    pr.assembly_name = pr.name
    return pr
