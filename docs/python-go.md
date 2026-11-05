# Python and Go

Python and Go components get the same output as .NET, Java and Node.js components: a `Dockerfile`
(with its `Dockerfile.dockerignore`), `k8s.yaml` and `plan.json`, with the same hardening baseline
(uid 65532, read-only root file system, all capabilities dropped, seccomp `RuntimeDefault`, a
NetworkPolicy, credentials as ExternalSecret references). Organization scans deploy them like any other
A-rated component. Nothing in the application's repository is changed: the server, port and
configuration are set from the outside, with command-line options and environment variables.

## What is read

**Python** (`containerizer/scan_python_go.py`)

- One project per folder with `requirements.txt`, `pyproject.toml`, `Pipfile` or `setup.py`; every
  manifest of the folder adds its packages: pip requirements (with `-r` includes), PEP 621
  `[project]` dependencies, Poetry dependencies, `Pipfile` packages and `setup.py` `install_requires`.
  Development dependencies (Poetry groups, `[dependency-groups]`, `requirements-dev.txt`,
  `[dev-packages]`) are kept apart. Package names are normalized (PEP 503).
- The Python version: `.python-version`, `runtime.txt` (`python-3.11.9`), the `Pipfile`'s
  `python_version`, or `requires-python` (Poetry's `python` constraint).
- The package manager: `uv.lock`, `poetry.lock` or `Pipfile.lock`, else pip.
- A folder with a manifest but no Python code (`docs/requirements.txt`) is a tool, not a component.
- Tests (`tests/`, `test_*.py`, `conftest.py`) and Django migrations are not searched by code rules.

**Go**

- `go.mod`: the module path, the `go` and `toolchain` lines, requirements, `replace` directives and a
  `vendor/` folder.
- Every `package main` folder of the module is a component of its own (`cmd/api`, `cmd/worker`);
  the module's packages it imports are followed, so a server started in `internal/server` makes the
  `cmd/api` component a web component, and the component's packages are only the modules that binary
  imports. A module without a main package is a library.

## How the app starts (Python)

The first of these that applies:

1. A `Procfile` (`web:` for web components, `worker:` otherwise): that command, with `$PORT` set to 8080.
2. Django (`manage.py`): the project's `wsgi.py` (or `asgi.py`) application from `DJANGO_SETTINGS_MODULE`.
   `collectstatic` runs at build time when the settings define `STATIC_ROOT` (if the settings need
   environment variables to load, the build says so and goes on).
3. An ASGI app object (`FastAPI(`, `Starlette(`, `Quart(`, `Litestar(`) or a WSGI one (`Flask(`,
   `Bottle(`, Falcon, Pyramid's `make_wsgi_app()`), or a Flask app factory (`create_app()`).
4. A script of `[project.scripts]` / `[tool.poetry.scripts]`, started with `python -c` (the project
   itself is not installed).
5. A package's `__main__.py` (`python -m`), or a top-level script with `if __name__ == "__main__":`.

The server is the one the app declares: gunicorn, waitress, uWSGI or granian for WSGI; uvicorn,
hypercorn, granian or daphne for ASGI. Only when the app declares none does the image add gunicorn
(WSGI) or uvicorn (ASGI), and the Dockerfile says why (`python-add-server`). The server binds
`0.0.0.0:8080`; a script that listens itself gets `PORT=8080` when it reads `PORT`, or keeps the port
in its code. A `src/` layout is put on `PYTHONPATH`.

## How the app starts (Go)

`go build -trimpath -ldflags='-s -w'` of the main package (`./cmd/api`) on the newest Go toolchain
(Go 1 compatibility: `go.mod`'s `go` line is a minimum), static (`CGO_ENABLED=0`) on distroless
`static`, or with cgo (`import "C"`) on distroless `base`. The port is `PORT=8080` when the code reads
`PORT` (or no port is found), otherwise the port in the code (`ListenAndServe(":3000", ...)`,
`r.Run(":8080")`). When the code reads files at run time (templates with `ParseGlob`, `http.Dir`,
`os.ReadFile`, Viper), the module's non-Go files are copied to `/app`, the working folder.

## Containers

**Python**: the build stage installs the dependencies into `/opt/venv` with the repository's package
manager: `pip install -r requirements.txt`, `poetry install --only main --no-root`,
`uv sync --frozen --no-dev --no-install-project`, `pipenv requirements` from `Pipfile.lock`, or (no
lockfile) the dependency list of the manifest, which the Dockerfile writes out. Packages that compile
against system libraries (`psycopg2`, `mysqlclient`, `python-ldap`, `pyodbc`, ...) build on the full
Python image; the slim runtime image then gets only their shared libraries (`libpq5`, ...). The final
stage is the slim image of the same Python line with the virtual environment and the application,
owned by root and read-only for uid 65532, `PYTHONDONTWRITEBYTECODE=1`, `HOME=/tmp` (the only
writable folder).

**Go**: the binary at `/usr/local/bin/<name>` on distroless, uid 65532, no shell.

Both take an optional build secret `ca` (a CA bundle for TLS-inspecting proxies), used in the build
stage only. Base images are in `rules/images.yaml` (`python.*`, `go.*`) and get patched tags from
`rules/images.lock.yaml` like the others; the lifecycle entries of `rules/60-security.yaml` move an
out-of-support Python or Go line on.

Health probes use a health route found in the code (`@app.get("/healthz")`, Django's root URLconf
`path("health/", ...)`, `mux.HandleFunc("/healthz", ...)`, `r.GET("/ping", ...)`), otherwise a TCP
probe. Environment variables the code reads with credential names (`os.environ["DB_PASSWORD"]`,
`os.Getenv("DATABASE_URL")`) and those in `.env.example` become Secret references.

## Examples

`examples/python-go/` holds a Flask, a FastAPI, a Django and a Go `net/http` application (two main
packages: an API and a command run as a CronJob):

```sh
containerizer generate examples/python-go/django --out out
containerizer gate examples/python-go/django
```
