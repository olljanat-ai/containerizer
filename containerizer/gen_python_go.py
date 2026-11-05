"""Build plans and Dockerfiles for Python and Go components.

Python: the dependencies install into a virtual environment in the build stage, with the package manager
the repository uses (pip requirements, Poetry, uv or Pipenv lockfiles; the manifest's dependency list when
there is no lockfile). The slim image of the same Python line runs the server the app declares (Procfile,
gunicorn, uvicorn, waitress, ...) on the application object found in the code, as uid 65532. Only when the app
declares no production server does the image add gunicorn (WSGI) or uvicorn (ASGI); the app's files are
never changed.

Go: a static build (CGO_ENABLED=0) of the main package on the newest Go toolchain, run on distroless static as
uid 65532; an app that uses cgo runs on distroless base (glibc).
"""
from __future__ import annotations

import json
import re

from .gen_jvm_node import _q, _rel

PY_CA_ENV = ("if [ -f /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca SSL_CERT_FILE=/run/secrets/ca "
             "REQUESTS_CA_BUNDLE=/run/secrets/ca; fi")
GUNICORN_DOCS = "https://docs.gunicorn.org/en/stable/deploy.html"
UVICORN_DOCS = "https://www.uvicorn.org/deployment/"
DJANGO_DOCS = "https://docs.djangoproject.com/en/stable/howto/deployment/wsgi/gunicorn/"


def _images():
    from .generate import images
    return images()


def _reason(plan, rule, why, refs=None):
    from .generate import add_reason
    add_reason(plan, rule, why, refs)


# --------------------------------------------------------------------------- Python version

def _ver(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def _satisfies(line: str, spec: str) -> bool:
    """Does a Python line (3.12) satisfy a requires-python / Poetry constraint (>=3.9,<3.13; ^3.10; ~=3.8)?"""
    lv = _ver(line)
    for clause in re.split(r"\s*,\s*|\s+(?=[<>=!~^])", spec.strip()):
        clause = clause.strip()
        if not clause or clause == "*":
            continue
        m = re.fullmatch(r"(>=|<=|==|!=|~=|>|<|\^|~)?\s*([\d.*]+)", clause)
        if not m:
            continue
        op, v = m.group(1) or "==", m.group(2)
        vv = _ver(v.replace("*", ""))
        if not vv:
            continue
        mm = vv[:2] if len(vv) >= 2 else (vv[0], 0)
        if op in ("==",) and ("*" in v or len(vv) <= 2):
            ok = lv[:2] == mm if len(vv) >= 2 else lv[0] == vv[0]
        elif op == "==":
            ok = lv[:2] == mm
        elif op == "!=":
            ok = not (lv[:2] == mm and ("*" in v or len(vv) <= 2))
        elif op == ">=":
            ok = lv[:2] >= mm
        elif op == ">":
            ok = lv[:2] > mm or (lv[:2] == mm and len(vv) > 2)
        elif op == "<=":
            ok = lv[:2] <= mm
        elif op == "<":
            ok = lv[:2] < mm
        elif op == "~=":
            ok = lv[:2] >= mm and (lv[0] == vv[0] if len(vv) == 2 else lv[:2] == mm)
        elif op == "^":
            ok = lv[:2] >= mm and lv[0] == vv[0]
        else:                                   # Poetry ~3.10: >=3.10,<3.11
            ok = lv[:2] == mm if len(vv) >= 2 else lv[0] == vv[0]
        if not ok:
            return False
    return True


def python_line(props: dict) -> tuple[str, str]:
    """(line, why) for the project: the declared version's line (or the next one above an older line), the
    default line within requires-python, or the default."""
    im = _images()["python"]
    lines = sorted((str(x) for x in im.get("lines", ["3.12"])), key=_ver)
    default = str(im.get("default", lines[-1]))
    pv = props.get("PythonVersion")
    if pv and _ver(pv):
        want = _ver(pv)[:2]
        line = next((x for x in lines if _ver(x) >= want), lines[-1])
        return line, "" if _ver(line) == want else f"declares Python {pv}, whose line has no supported image"
    rp = props.get("PythonRequires")
    if rp:
        ok = [x for x in lines if _satisfies(x, rp)]
        if default in ok:
            return default, ""
        if ok:
            return ok[-1], ""
        return lines[0], f"requires Python {rp}, which no supported line satisfies"
    return default, ""


# --------------------------------------------------------------------------- Python plan

def _runtime_packages(p) -> set[str]:
    return {n for n in p.packages if n not in p.dev_packages}


def _caret(spec: str) -> str:
    """A Poetry constraint as a PEP 440 specifier (^1.2 -> >=1.2,<2; ~1.2 -> ~=1.2; * -> none)."""
    spec = (spec or "").strip()
    if spec in ("", "*"):
        return ""
    m = re.fullmatch(r"\^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", spec)
    if m:
        major = int(m.group(1))
        if major == 0 and m.group(2):
            return f">={spec[1:].strip()},<0.{int(m.group(2)) + 1}"
        return f">={spec[1:].strip()},<{major + 1}"
    m = re.fullmatch(r"~\s*(\d+\.\d+(?:\.\d+)?)", spec)
    if m:
        return f"~={m.group(1)}" if m.group(1).count(".") == 2 else f">={m.group(1)},<{m.group(1).split('.')[0]}.{int(m.group(1).split('.')[1]) + 1}"
    if re.fullmatch(r"\d[\w.]*", spec):
        return f"=={spec}"
    return spec


def _dep_list(p) -> list[str]:
    out = []
    for n in sorted(_runtime_packages(p)):
        v = p.packages.get(n) or ""
        v = _caret(v) if isinstance(v, str) else ""
        if v and not re.match(r"^[<>=!~]", v):
            v = ""
        out.append(n + v)
    return out


def _outside_refs(p) -> bool:
    """Requirements with local paths outside the project folder (-e ../shared): the build needs the repository."""
    for n in ("requirements.txt",):
        f = p.dir / n
        if f.is_file() and re.search(r"(^|\s)(-e\s+)?\.\./", f.read_text(errors="replace"), re.M):
            return True
    return False


def _server_cmd(server: str, app: str, kind: str) -> list[str]:
    if server == "gunicorn":
        return ["gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", app]
    if server == "uvicorn":
        return ["uvicorn", app, "--host", "0.0.0.0", "--port", "8080"]
    if server == "hypercorn":
        return ["hypercorn", "--bind", "0.0.0.0:8080", app]
    if server == "daphne":
        return ["daphne", "-b", "0.0.0.0", "-p", "8080", app]
    if server == "granian":
        return ["granian", "--interface", kind, "--host", "0.0.0.0", "--port", "8080", app]
    if server == "waitress":
        if app.endswith("()"):
            return ["waitress-serve", "--listen=0.0.0.0:8080", "--call", app[:-2]]
        return ["waitress-serve", "--listen=0.0.0.0:8080", app]
    if server == "uwsgi":
        return ["uwsgi", "--http", "0.0.0.0:8080", "--master", "--module", app]
    raise ValueError(server)


def _pick_server(runtime: set[str], kind: str) -> str | None:
    order = (["uvicorn", "hypercorn", "granian", "daphne"] if kind == "asgi"
             else ["gunicorn", "waitress", "uwsgi", "granian"])
    return next((s for s in order if s in runtime), None)


def python_plan(a, c, plan: dict) -> None:
    p, f = c.project, c.facts
    props = p.properties or {}
    im = _images()["python"]
    line, why = python_line(props)
    runtime = _runtime_packages(p)
    native = sorted(runtime & set(im.get("native_build") or []))
    apt = sorted({x for n in runtime for x in (im.get("native_runtime") or {}).get(n, [])})
    pm = props.get("PackageManager") or "pip"
    lock = props.get("Lockfile") or ""
    if pm in ("uv", "poetry", "pipenv") and lock:
        install = pm
    elif props.get("Requirements"):
        install = "requirements"
    elif runtime:
        install = "deps"
    else:
        install = "none"
    root = a.repo.root
    build_root = root if _outside_refs(p) else p.dir
    plan.update({"python": line, "pm": pm, "install": install, "uid": im["app_uid"], "base": "slim",
                 "native_build": native, "apt_packages": apt, "build_root": _rel(build_root, root),
                 "module": _rel(p.dir, build_root), "add_python_packages": [], "deps": _dep_list(p) if install == "deps" else []})
    if why:
        _reason(plan, "python-line", f"The project {why}; it runs on Python {line}.",
                ["https://devguide.python.org/versions/"])
    if install == "deps":
        _reason(plan, "python-no-lockfile", "There is no requirements.txt or lockfile: the image installs the "
                "dependencies listed in the project's manifest, resolved at build time. Commit a lockfile (or a "
                "pinned requirements.txt) for repeatable builds.")
    if native:
        _reason(plan, "python-native-build", f"{', '.join(native)} compile{'s' if len(native) == 1 else ''} against "
                "system libraries: the build stage uses the full Python image (gcc and -dev headers); the slim "
                f"runtime gets only the shared libraries ({', '.join(apt) or 'none'}).")
    env = plan["env"]
    env.update({"PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp"})
    st = f.get("python_start") or {}
    base = st.get("base") or ""
    if base:
        mod = plan["module"]
        env["PYTHONPATH"] = "/app/" + "/".join(x for x in (mod, base) if x)
    web = c.role == "web"
    argv: list[str] = []
    kind = st.get("kind")
    if kind == "procfile":
        from .facts_python_go import start_argv
        cmd = st["cmd"]
        env["PORT"] = "8080"
        sub = re.sub(r"\$\{PORT(?::?-[^}]*)?\}|\$PORT\b", "8080", cmd)
        argv = start_argv(sub) or ["sh", "-c", cmd]
        _reason(plan, "python-procfile", f"The Procfile starts the app with `{cmd}`; the image runs that command "
                "with PORT=8080.", ["https://devcenter.heroku.com/articles/procfile"])
        if not web:
            plan["port"] = None
    elif kind == "django" and web:
        app_kind = "wsgi" if st.get("wsgi") else "asgi"
        server = _pick_server(runtime, "wsgi") if st.get("wsgi") else None
        if not server and st.get("asgi"):
            server, app_kind = _pick_server(runtime, "asgi"), "asgi"
        if not server:
            server, app_kind = ("gunicorn", "wsgi") if st.get("wsgi") else ("uvicorn", "asgi")
            plan["add_python_packages"].append(im["servers"][server])
            _reason(plan, "python-add-server", f"The project declares no production server: the image adds {server} "
                    "and runs the Django project with it (the development server is not for production).", [DJANGO_DOCS])
        argv = _server_cmd(server, st.get(app_kind) or "", app_kind)
        _reason(plan, "python-django", "Django runs with `" + " ".join(argv) + "`. Set ALLOWED_HOSTS, "
                "SECRET_KEY and the database through the environment variables the settings read; static files are "
                "served only if the project serves them itself (WhiteNoise) or a proxy does.", [DJANGO_DOCS])
        if st.get("collectstatic"):
            plan["collectstatic"] = True
        if not st.get(app_kind):
            argv = []
    elif kind in ("asgi", "wsgi") and web:
        server = _pick_server(runtime, kind)
        if not server:
            server = "uvicorn" if kind == "asgi" else "gunicorn"
            plan["add_python_packages"].append(im["servers"][server])
            _reason(plan, "python-add-server", f"The project declares no production {kind.upper()} server: the image "
                    f"adds {server} to run `{st['app']}` (from {st.get('file')}).",
                    [UVICORN_DOCS if server == "uvicorn" else GUNICORN_DOCS])
        argv = _server_cmd(server, st["app"], kind)
    elif kind in ("asgi", "wsgi"):
        argv = ["python", st["file"].split("/", 1)[-1]] if st.get("main") else []
    elif kind == "entry":
        call = f"import sys; from {st['module']} import {st['func']} as m; sys.exit(m())" if st.get("func") \
            else f"import runpy; runpy.run_module({st['module']!r}, run_name='__main__')"
        argv = ["python", "-c", call]
        _reason(plan, "python-console-script", f"The project's script `{st['script']}` ({st['module']}:{st.get('func')}) "
                "is started with python -c, without installing the project itself.")
    elif kind == "module":
        argv = ["python", "-m", st["module"]]
    elif kind == "script":
        argv = ["python", st["rel"]]
    plan["python_argv"] = argv
    if web and kind not in ("procfile", "django", "asgi", "wsgi"):
        # the script listens itself: on $PORT if it reads it, else on the port in its code
        if f.get("port_env") or not f.get("port"):
            env["PORT"] = "8080"
        else:
            plan["port"] = int(f["port"])
    if web:
        h = f.get("health")
        plan["health"] = ("/" + h.lstrip("/")) if h else None
    else:
        plan["port"] = None


def python_buildable(c) -> bool:
    return bool((c.facts.get("python_start") or {}))


# --------------------------------------------------------------------------- Python Dockerfile

def _python_install(plan: dict) -> list[str]:
    tools = _images()["python"]["tools"]
    inst = plan["install"]
    tool = f"python -m venv /opt/tools && /opt/tools/bin/pip install {_q(tools.get(inst, inst))} && "
    cmds = []
    if inst == "requirements":
        cmds.append("pip install -r requirements.txt")
    elif inst == "deps":
        cmds.append("pip install -r /tmp/cz-requirements.txt")
    elif inst == "poetry":
        cmds.append(tool + "/opt/tools/bin/poetry install --only main --no-root --no-interaction")
    elif inst == "uv":
        cmds.append(tool + "/opt/tools/bin/uv sync --frozen --no-dev --no-install-project")
    elif inst == "pipenv":
        cmds.append(tool + "/opt/tools/bin/pipenv requirements > /tmp/cz-requirements.txt && pip install -r /tmp/cz-requirements.txt")
    if plan.get("add_python_packages"):
        cmds.append("pip install " + " ".join(_q(x) for x in plan["add_python_packages"]))
    return cmds


def dockerfile_python(plan: dict) -> str:
    from .generate import reason_comments, writable_dirs
    im = _images()["python"]
    line, uid = plan["python"], im["app_uid"]
    root, mod = plan.get("build_root") or "", plan.get("module") or ""
    build = im[f"build_native_{line}" if plan.get("native_build") else f"build_{line}"]
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, Python {line}, {plan['install']})",
             *reason_comments(plan),
             f"FROM {build} AS build",
             "ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PYTHONDONTWRITEBYTECODE=1 VIRTUAL_ENV=/opt/venv "
             "PATH=/opt/venv/bin:$PATH POETRY_VIRTUALENVS_CREATE=false UV_PROJECT_ENVIRONMENT=/opt/venv "
             "UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy",
             "WORKDIR /app", f"COPY {root + '/' if root else '.'} ."]
    for fn in plan["remove_files"]:
        lines.append(f"RUN find . -name '{fn}' -delete")
    if plan.get("build_env"):
        lines.append("ENV " + " ".join(f"{k}={json.dumps(str(v))}" for k, v in sorted(plan["build_env"].items())))
    if plan.get("deps"):
        lines.append("COPY <<'EOF' /tmp/cz-requirements.txt\n" + "\n".join(plan["deps"]) + "\nEOF")
    cd = f"cd {_q(mod)} && " if mod else ""
    cmds = _python_install(plan)
    lines += ["RUN python -m venv /opt/venv",
              "# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies (build stage only)",
              "RUN --mount=type=cache,target=/root/.cache --mount=type=secret,id=ca,required=false \\",
              f"    {PY_CA_ENV}; \\", "    " + cd + (" \\\n && ".join(cmds) if cmds else "true")]
    if plan.get("collectstatic"):
        lines.append(f"RUN {cd}python manage.py collectstatic --noinput \\\n || echo 'containerizer: collectstatic did not run "
                     "(the settings need environment variables at build time); static files are not collected' >&2")
    writable = writable_dirs(plan)
    if writable:
        lines.append("RUN mkdir -p " + " ".join("/writable" + w for w in writable))
    lines += ["", f"FROM {im[f'runtime_{line}']} AS final"]
    if plan.get("apt_packages"):
        lines.append("RUN apt-get update && apt-get install -y --no-install-recommends "
                     + " ".join(plan["apt_packages"]) + " && rm -rf /var/lib/apt/lists/*")
    lines += [f"WORKDIR /app{'/' + mod if mod else ''}", "# application files stay owned by root: read-only for the app user",
              "COPY --from=build /opt/venv /opt/venv", "COPY --from=build /app /app"]
    for w in writable:
        lines.append(f"COPY --from=build --chown={uid}:{uid} /writable{w} {w}")
    env = dict(plan["env"])
    env.update({"VIRTUAL_ENV": "/opt/venv", "PATH": "/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
    lines.append("ENV " + " \\\n    ".join(f"{k}={json.dumps(v)}" for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    lines.append("ENTRYPOINT " + json.dumps(list(plan.get("python_argv") or []) + plan["args"]))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- Go plan

_ASSET_RE = re.compile(r"\b(ParseGlob|ParseFiles|http\.Dir|os\.ReadFile|os\.Open|ioutil\.ReadFile|LoadHTMLGlob|"
                       r"LoadHTMLFiles|\.Static\(|StaticFS|viper\.ReadInConfig|godotenv\.Load)\b")


def go_plan(a, c, plan: dict) -> None:
    from .scan_python_go import _GO_COMMENT_RE, _reachable
    p, f = c.project, c.facts
    props = p.properties or {}
    im = _images()["go"]
    root = a.repo.root
    mod_dir = (root / props.get("GoModDir", ".")).resolve()
    gomod = (mod_dir / "go.mod").read_text(errors="replace") if (mod_dir / "go.mod").is_file() else ""
    build_root = root.resolve() if re.search(r"=>\s*\.\./", gomod) else mod_dir
    cgo = props.get("GoCgo") == "true"
    _, _, code = _reachable(mod_dir, props.get("GoModule", ""), (mod_dir / props.get("GoPackage", ".")).resolve())
    code = _GO_COMMENT_RE.sub("", code)
    assets = bool(_ASSET_RE.search(code))
    plan.update({"go": props.get("GoVersion") or "", "uid": im["app_uid"], "base": "distroless-base" if cgo else "distroless-static",
                 "cgo": cgo, "build_root": _rel(build_root, root), "module": _rel(mod_dir, build_root),
                 "package": props.get("GoPackage", "."), "binary": re.sub(r"[^\w.-]", "-", p.name) or "app",
                 "go_assets": assets})
    if cgo:
        _reason(plan, "go-cgo", "The code uses cgo (import \"C\"): it is built with CGO_ENABLED=1 and runs on distroless "
                "base (glibc) instead of distroless static.", ["https://github.com/GoogleContainerTools/distroless"])
    if assets:
        _reason(plan, "go-runtime-files", "The code reads files at run time (templates, static files or configuration "
                "by relative path): the module's files other than Go sources are copied to /app, the working folder.")
    if build_root != mod_dir:
        _reason(plan, "go-replace-outside", "go.mod replaces modules with folders outside the module (=> ../): the "
                "build context is the repository.")
    if c.role == "web":
        if f.get("port_env") or not f.get("port"):
            plan["env"]["PORT"] = "8080"
        if f.get("port") and not f.get("port_env"):
            plan["port"] = int(f["port"])
        h = f.get("health")
        plan["health"] = ("/" + h.lstrip("/")) if h else None
    else:
        plan["port"] = None


def go_buildable(c) -> bool:
    return (c.project.properties or {}).get("GoMain") == "true"


def dockerfile_go(plan: dict) -> str:
    from .generate import reason_comments, writable_dirs
    im = _images()["go"]
    uid = im["app_uid"]
    root, mod = plan.get("build_root") or "", plan.get("module") or ""
    cd = f"cd {_q(mod)} && " if mod else ""
    pkg = plan.get("package") or "."
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, Go{' ' + plan['go'] if plan.get('go') else ''}"
             f"{', cgo' if plan.get('cgo') else ''})",
             *reason_comments(plan),
             f"FROM {im['build']} AS build", "WORKDIR /src", f"COPY {root + '/' if root else '.'} ."]
    for fn in plan["remove_files"]:
        lines.append(f"RUN find . -name '{fn}' -not -path '*/vendor/*' -delete")
    envb = [f"CGO_ENABLED={1 if plan.get('cgo') else 0}"] + \
        [f"{k}={json.dumps(str(v))}" for k, v in sorted((plan.get("build_env") or {}).items())]
    lines.append("ENV " + " ".join(envb))
    lines += ["# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies (module downloads)",
              "RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build "
              "--mount=type=secret,id=ca,required=false \\",
              "    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi; \\",
              f"    {cd}go build -trimpath -ldflags='-s -w' {' '.join(plan['publish_args'])} -o /out/{plan['binary']} {_q(pkg)}"
              .replace("  ", " ")]
    if plan.get("go_assets"):
        lines.append(f"RUN mkdir -p /out/files && cp -a {_q(mod) if mod else '.'}/. /out/files/ \\\n"
                     " && find /out/files \\( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name '.git*' \\) -delete \\\n"
                     " && rm -rf /out/files/vendor")
    writable = writable_dirs(plan)
    if writable:
        lines.append("RUN mkdir -p " + " ".join("/writable" + w for w in writable))
    lines += ["", f"FROM {im['runtime_cgo' if plan.get('cgo') else 'runtime']} AS final", "WORKDIR /app",
              "# application files stay owned by root: read-only for the app user"]
    if plan.get("go_assets"):
        lines.append("COPY --from=build /out/files/ /app/")
    lines.append(f"COPY --from=build /out/{plan['binary']} /usr/local/bin/{plan['binary']}")
    for w in writable:
        lines.append(f"COPY --from=build --chown={uid}:{uid} /writable{w} {w}")
    env = dict(plan["env"])
    if env:
        lines.append("ENV " + " \\\n    ".join(f"{k}={json.dumps(v)}" for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    lines.append("ENTRYPOINT " + json.dumps([f"/usr/local/bin/{plan['binary']}"] + plan["args"]))
    return "\n".join(lines) + "\n"
