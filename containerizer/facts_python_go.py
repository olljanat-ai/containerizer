"""Run facts of Python and Go components: how the application starts, the port it listens on, its health
route and the environment variables that carry credentials.

As for the other stacks nothing here changes the application: the generator starts the server the app
declares (Procfile, gunicorn/uvicorn/waitress on the app object it finds), binds it with command-line options
or the PORT variable, and turns credentials into Kubernetes Secret references.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

from .facts_jvm_node import ENV_SECRET

PREFERRED = ("app", "main", "wsgi", "asgi", "server", "application", "run", "api", "web", "manage", "__main__")
_ENV_READ_PY = re.compile(r"""os\.(?:environ\.get|getenv|environ\.setdefault)\(\s*['"]([A-Z][A-Z0-9_]*)['"]|"""
                          r"""os\.environ\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\]|"""
                          r"""\benv(?:\.\w+)?\(\s*['"]([A-Z][A-Z0-9_]*)['"]|config\(\s*['"]([A-Z][A-Z0-9_]*)['"]""")
_ENV_READ_GO = re.compile(r"""os\.(?:Getenv|LookupEnv)\(\s*"([A-Z][A-Z0-9_]*)"\s*\)""")
_MAIN_GUARD = re.compile(r"""^if\s+__name__\s*==\s*['"]__main__['"]\s*:""", re.M)
ASGI_RE = re.compile(r"^(\w+)\s*(?::\s*[\w.]+\s*)?=\s*(?:[\w.]+\.)?(FastAPI|Starlette|Quart|Litestar)\(", re.M)
WSGI_RE = re.compile(r"^(\w+)\s*(?::\s*[\w.]+\s*)?=\s*(?:[\w.]+\.)?(Flask|Bottle|App|API|make_wsgi_app)\(", re.M)
FACTORY_RE = re.compile(r"^def\s+(create_app|make_app|app_factory)\s*\(\s*\)", re.M)
SERVERS = {"gunicorn", "uvicorn", "waitress", "hypercorn", "daphne", "granian", "uwsgi"}


def _strip_py(txt: str) -> str:
    return re.sub(r"(?m)^\s*#.*$", "", txt)


def _py_files(c) -> list[Path]:
    from .rules import TEST_PATH_RE
    p = c.project
    out = []
    for f in p.files:
        if f.suffix != ".py":
            continue
        rel = str(f.relative_to(p.dir)).replace("\\", "/")
        if TEST_PATH_RE["python"].search(rel) or "/migrations/" in "/" + rel:
            continue
        out.append(f)

    def key(f):
        rel = f.relative_to(p.dir)
        parts = rel.parts[1:] if rel.parts[0] == "src" else rel.parts
        return (len(parts), PREFERRED.index(f.stem) if f.stem in PREFERRED else len(PREFERRED), str(rel))
    return sorted(out, key=key)


def py_module(p, f: Path) -> tuple[str, str]:
    """(dotted module, sys.path folder) of a source file: src/ layouts import from src."""
    rel = f.relative_to(p.dir).with_suffix("")
    parts = list(rel.parts)
    base = ""
    if parts[0] == "src" and len(parts) > 1:
        parts, base = parts[1:], "src"
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts), base


def procfile(p) -> dict[str, str]:
    f = p.dir / "Procfile"
    out = {}
    if f.is_file():
        for line in f.read_text(errors="replace").splitlines():
            m = re.match(r"^\s*([\w-]+)\s*:\s*(.+?)\s*$", line)
            if m:
                out[m.group(1)] = m.group(2)
    return out


def _port_facts(code: str, facts: dict, lang: str) -> None:
    if lang == "py":
        if re.search(r"""(environ\.get|getenv|environ\[)\(?\s*['"]PORT['"]""", code):
            facts["port_env"] = True
        m = re.search(r"\.run\([^)]*\bport\s*=\s*(\d{2,5})\b", code) or re.search(r"\bport\s*=\s*(\d{4,5})\b", code)
    else:
        if re.search(r'Getenv\(\s*"PORT"\s*\)|LookupEnv\(\s*"PORT"\s*\)', code):
            facts["port_env"] = True
        m = re.search(r'(?:ListenAndServe(?:TLS)?|\.Run|\.Start|\.Listen|Addr:)\s*\(?\s*"(?:[\w.\-]*|\[::\]|0\.0\.0\.0):(\d{2,5})"', code) \
            or re.search(r'"(?:0\.0\.0\.0)?:(\d{4,5})"', code)
    if m and "port" not in facts:
        facts["port"] = int(m.group(1))
        facts["port_source"] = "code"


def _secret_env(code: str, rx: re.Pattern, facts: dict) -> None:
    names = {n for m in rx.finditer(code) for n in m.groups() if n and ENV_SECRET.search(n)}
    if names:
        facts["secret_settings"] = sorted(names | set(facts.get("secret_settings") or []))
        facts["secret_env_style"] = "env"


def _env_examples(p, facts: dict) -> None:
    secrets = []
    for n in (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", ".env.defaults"):
        f = p.dir / n
        if f.is_file():
            for line in f.read_text(errors="replace").splitlines():
                mm = re.match(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=", line)
                if mm and ENV_SECRET.search(mm.group(1)):
                    secrets.append(mm.group(1))
    if secrets:
        facts["secret_settings"] = sorted(set(secrets) | set(facts.get("secret_settings") or []))
        facts["secret_env_style"] = "env"


def python_facts(repo, c, facts: dict) -> None:
    p = c.project
    files = _py_files(c)
    texts = {f: _strip_py(p.text(f)) for f in files}
    st: dict = {}
    proc = procfile(p)
    cmd = proc.get("web") if c.role == "web" else proc.get("worker") or proc.get("web")
    if cmd:
        st = {"kind": "procfile", "cmd": cmd}
    if not st and p.properties.get("Django") == "true":
        mg = p.text(p.dir / "manage.py")
        m = re.search(r"""DJANGO_SETTINGS_MODULE['"]\s*,\s*['"]([\w.]+)['"]""", mg)
        settings = m.group(1) if m else ""
        pkg = settings.rsplit(".", 1)[0] if "." in settings else ""
        if pkg:
            pdir = p.dir / Path(*pkg.split("."))
            if not pdir.is_dir() and (p.dir / "src" / Path(*pkg.split("."))).is_dir():
                pdir, st_base = p.dir / "src" / Path(*pkg.split(".")), "src"
            else:
                st_base = ""
            st = {"kind": "django", "settings": settings, "base": st_base,
                  "wsgi": f"{pkg}.wsgi:application" if (pdir / "wsgi.py").is_file() else "",
                  "asgi": f"{pkg}.asgi:application" if (pdir / "asgi.py").is_file() else ""}
            stx = p.text(pdir / "settings.py") if (pdir / "settings.py").is_file() else ""
            if re.search(r"^\s*STATIC_ROOT\s*=", stx, re.M):
                st["collectstatic"] = True
    if not st:
        for kind, rx in (("asgi", ASGI_RE), ("wsgi", WSGI_RE)):
            for f, t in texts.items():
                m = rx.search(t)
                if m and (rx is not WSGI_RE or m.group(2) not in ("App", "API") or "falcon" in t):
                    mod, base = py_module(p, f)
                    st = {"kind": kind, "app": f"{mod}:{m.group(1)}", "base": base, "file": p.rel_file(f).replace("\\", "/"),
                          "framework": m.group(2).lower(), "main": bool(_MAIN_GUARD.search(t))}
                    break
            if st:
                break
    if not st:
        for f, t in texts.items():
            m = FACTORY_RE.search(t)
            if m and "flask" in t.lower():
                mod, base = py_module(p, f)
                st = {"kind": "wsgi", "app": f"{mod}:{m.group(1)}()", "base": base, "framework": "flask",
                      "file": p.rel_file(f).replace("\\", "/")}
                break
    if not st:
        scripts = p.properties.get("Scripts")
        if scripts:
            import json
            name, target = next(iter(json.loads(scripts).items()))
            mod, _, fn = target.partition(":")
            base = "src" if (p.dir / "src").is_dir() and not (p.dir / mod.split(".")[0]).exists() else ""
            st = {"kind": "entry", "script": name, "module": mod.strip(), "func": fn.strip(), "base": base}
    if not st:
        for f, t in texts.items():
            if f.name == "__main__.py" and f.parent != p.dir:
                mod, base = py_module(p, f.parent / "__init__.py")
                st = {"kind": "module", "module": mod, "base": base}
                break
            if _MAIN_GUARD.search(t) and f.stem not in ("setup", "manage", "conftest") and f.parent == p.dir:
                st = {"kind": "script", "file": p.rel_file(f).replace("\\", "/"), "rel": str(f.relative_to(p.dir)).replace("\\", "/")}
                break
    if st:
        facts["python_start"] = st
    code = "\n".join(texts.values())
    _port_facts(code, facts, "py")
    _secret_env(code, _ENV_READ_PY, facts)
    _env_examples(p, facts)


def go_facts(repo, c, facts: dict) -> None:
    from .scan_python_go import _GO_COMMENT_RE, _reachable
    p = c.project
    props = p.properties
    if props.get("GoMain") != "true":
        return
    mod_dir = (repo.root / props.get("GoModDir", ".")).resolve()
    start = (mod_dir / props.get("GoPackage", ".")).resolve()
    _, _, code = _reachable(mod_dir, props.get("GoModule", ""), start)
    code = _GO_COMMENT_RE.sub("", code)
    _port_facts(code, facts, "go")
    m = re.search(r'(?:HandleFunc|Handle|\.GET|\.Get|\.HEAD|\.Any|\.Handle)\(\s*"(?:GET\s+)?(/(?:api/)?(?:health|healthz|healthcheck|ping|livez|readyz|alive|status))/?"', code)
    if m and "health" not in facts:
        facts["health"] = m.group(1)
    _secret_env(code, _ENV_READ_GO, facts)
    _env_examples(p, facts)


def start_argv(cmd: str) -> list[str] | None:
    """A Procfile command as an argv, or None when it needs a shell (&&, pipes, redirects)."""
    if re.search(r"&&|\|\||[|;<>`]|\$\(", cmd):
        return None
    try:
        return shlex.split(cmd)
    except ValueError:
        return None
