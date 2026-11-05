"""Python and Go: scanning, run facts, build plans, Dockerfiles and manifests (#248)."""
import hashlib
import shutil
from pathlib import Path

import yaml

from containerizer.assess import assess
from containerizer.gen_python_go import _caret, _satisfies, python_line
from containerizer.generate import buildable, dockerfile_for, generate_app, k8s_manifests, make_plan
from tests.test_engine import write

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python-go"


def comp(a, name):
    return next(c for c in a.components if c.name == name)


def plan_and_df(root, name):
    a = assess(root)
    c = comp(a, name)
    plan = make_plan(a, c)
    return a, c, plan, dockerfile_for(plan, c)


def hardened(a, c, plan):
    docs = k8s_manifests(a, c, plan, "registry.local/x/y:1")
    work = next(d for d in docs if d["kind"] in ("Deployment", "CronJob"))
    spec = work["spec"]["template"]["spec"] if work["kind"] == "Deployment" else \
        work["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    ct = spec["containers"][0]
    sc = ct["securityContext"]
    assert sc["runAsNonRoot"] and sc["readOnlyRootFilesystem"] and not sc["allowPrivilegeEscalation"]
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert spec["securityContext"]["runAsUser"] == 65532
    assert any(d["kind"] == "NetworkPolicy" for d in docs)
    return docs, ct


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(root.rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(root)).encode() + f.read_bytes())
    return h.hexdigest()


# ------------------------------------------------------------------ examples (acceptance criteria)

def test_examples_get_full_output_and_stay_unchanged(tmp_path):
    for name, comps in (("flask", ["flask"]), ("fastapi", ["fastapi"]), ("django", ["django"]),
                        ("go-http", ["api", "cleanup"])):
        src = tmp_path / "src" / name
        shutil.copytree(EXAMPLES / name, src)
        before = tree_hash(src)
        a = assess(src)
        out = tmp_path / "out" / name
        generate_app(a, out)
        for cn in comps:
            c = comp(a, cn)
            assert buildable(c), cn
            assert c.verdict == "info", cn
            for f in ("Dockerfile", "Dockerfile.dockerignore", "k8s.yaml", "plan.json"):
                assert (out / cn / f).is_file(), (name, cn, f)
        assert tree_hash(src) == before          # no file of the application changes


def test_flask_runs_its_declared_gunicorn():
    a, c, plan, df = plan_and_df(EXAMPLES / "flask", "flask")
    assert c.role == "web" and plan["install"] == "requirements" and plan["add_python_packages"] == []
    assert "FROM python:3.12" in df and "-slim-bookworm AS build" in df and "pip install -r requirements.txt" in df
    assert 'ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "app:app"]' in df
    assert "USER 65532" in df and "COPY --from=build /opt/venv /opt/venv" in df
    assert plan["health"] == "/health"
    docs, ct = hardened(a, c, plan)
    assert ct["readinessProbe"]["httpGet"]["path"] == "/health"
    assert {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"} in ct["env"]


def test_fastapi_without_server_gets_uvicorn_and_secret_refs():
    a, c, plan, df = plan_and_df(EXAMPLES / "fastapi", "fastapi")
    assert plan["install"] == "deps" and "fastapi>=0.110" in plan["deps"] and "pytest>=8" not in plan["deps"]
    assert plan["add_python_packages"] == ["uvicorn>=0.30"]
    assert "COPY <<'EOF' /tmp/cz-requirements.txt" in df and "pip install 'uvicorn>=0.30'" in df
    assert '"uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"' in df
    assert "python-add-server" in df
    docs, ct = hardened(a, c, plan)
    assert any(e["name"] == "DATABASE_URL" and "valueFrom" in e for e in ct["env"])
    assert any(d["kind"] == "ExternalSecret" for d in docs)


def test_django_wsgi_with_declared_gunicorn():
    a, c, plan, df = plan_and_df(EXAMPLES / "django", "django")
    assert c.role == "web" and plan["add_python_packages"] == []
    assert '"gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "mysite.wsgi:application"' in df
    assert "python manage.py collectstatic --noinput" in df
    assert plan["health"] == "/health/"
    hardened(a, c, plan)


def test_go_main_packages_are_components():
    a, c, plan, df = plan_and_df(EXAMPLES / "go-http", "api")
    assert {x.name for x in a.components} == {"api", "cleanup"}    # the module root is a library, not deployed
    assert c.role == "web" and comp(a, "cleanup").role == "console"
    assert "CGO_ENABLED=0" in df and "go build -trimpath" in df and "-o /out/api './cmd/api'" in df
    assert "FROM gcr.io/distroless/static-debian12:nonroot AS final" in df
    assert 'ENTRYPOINT ["/usr/local/bin/api"]' in df and "USER 65532" in df
    assert plan["env"]["PORT"] == "8080" and plan["health"] == "/healthz"
    docs, ct = hardened(a, c, plan)
    assert any(e["name"] == "DB_PASSWORD" and "valueFrom" in e for e in ct["env"])
    cl = comp(a, "cleanup")
    cplan = make_plan(a, cl)
    assert cplan["port"] is None
    docs, _ = hardened(a, cl, cplan)
    assert any(d["kind"] == "CronJob" for d in docs)


# ------------------------------------------------------------------ Python details

def test_python_manifests_merge_and_dev_packages(tmp_path):
    write(tmp_path, "requirements.txt", "-r base.txt\nflask[async]==3.0.0  # web\n-e ./lib\n")
    write(tmp_path, "base.txt", "SQLAlchemy>=2\n")
    write(tmp_path, "requirements-dev.txt", "pytest\n")
    write(tmp_path, "pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.11"\nRequests = "^2.31"\n')
    write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n")
    a = assess(tmp_path)
    p = a.components[0].project
    assert {"flask", "sqlalchemy", "requests", "pytest"} <= set(p.packages)
    assert set(p.dev_packages) == {"pytest"}
    assert p.properties["PythonRequires"] == "^3.11"


def test_python_lockfiles_choose_the_package_manager(tmp_path):
    for lock, cmd in (("poetry.lock", "poetry install --only main --no-root"),
                      ("uv.lock", "uv sync --frozen --no-dev --no-install-project"),
                      ("Pipfile.lock", "pipenv requirements")):
        root = tmp_path / lock
        write(root, "pyproject.toml", '[project]\nname="x"\ndependencies=["flask", "gunicorn"]\n')
        write(root, lock, "")
        write(root, "wsgi.py", "import flask\napp = flask.Flask(__name__)\n")
        _, _, plan, df = plan_and_df(root, lock)
        assert cmd in df, lock
        assert '"gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "wsgi:app"' in df


def test_procfile_wins_and_port_is_substituted(tmp_path):
    write(tmp_path, "requirements.txt", "flask\nwaitress\n")
    write(tmp_path, "Procfile", "web: waitress-serve --port=$PORT shop:create_app\n")
    write(tmp_path, "shop.py", "from flask import Flask\ndef create_app():\n    return Flask(__name__)\n")
    _, _, plan, df = plan_and_df(tmp_path, tmp_path.name)
    assert 'ENTRYPOINT ["waitress-serve", "--port=8080", "shop:create_app"]' in df
    assert plan["env"]["PORT"] == "8080"


def test_flask_factory_with_waitress(tmp_path):
    write(tmp_path, "requirements.txt", "flask\nwaitress\n")
    write(tmp_path, "src/shop/__init__.py", "from flask import Flask\n\ndef create_app():\n    return Flask(__name__)\n")
    _, _, plan, df = plan_and_df(tmp_path, tmp_path.name)
    assert '"waitress-serve", "--listen=0.0.0.0:8080", "--call", "shop:create_app"' in df
    assert plan["env"]["PYTHONPATH"] == "/app/src"


def test_script_that_listens_itself_keeps_its_port(tmp_path):
    write(tmp_path, "requirements.txt", "aiohttp\n")
    write(tmp_path, "server.py", "from aiohttp import web\napp = web.Application()\n"
          "if __name__ == '__main__':\n    web.run_app(app, port=8085)\n")
    _, c, plan, df = plan_and_df(tmp_path, tmp_path.name)
    assert c.role == "web" and plan["port"] == 8085 and "EXPOSE 8085" in df
    assert 'ENTRYPOINT ["python", "server.py"]' in df


def test_console_script_and_native_packages(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname="etl"\nrequires-python=">=3.9,<3.12"\n'
          'dependencies=["psycopg2>=2.9"]\n[project.scripts]\netl = "etl.cli:main"\n')
    write(tmp_path, "etl/__init__.py", "")
    write(tmp_path, "etl/cli.py", "def main():\n    return 0\n")
    _, c, plan, df = plan_and_df(tmp_path, tmp_path.name)
    assert c.role == "console" and plan["python"] == "3.11"
    assert "FROM python:3.11" in df and "-bookworm AS build" in df and "slim-bookworm AS build" not in df
    assert "apt-get install -y --no-install-recommends libpq5" in df
    assert "from etl.cli import main as m; sys.exit(m())" in df


def test_docs_requirements_are_not_a_component(tmp_path):
    write(tmp_path, "docs/requirements.txt", "mkdocs\n")
    a = assess(tmp_path)
    assert a.components == []


def test_python_version_choice():
    assert python_line({"PythonVersion": "3.11.4"})[0] == "3.11"
    assert python_line({"PythonVersion": "3.8"}) [0] == "3.11"      # next supported line, with a reason
    assert python_line({"PythonRequires": ">=3.9,<3.12"})[0] == "3.11"
    assert python_line({"PythonRequires": "^3.10"})[0] == "3.12"
    assert python_line({})[0] == "3.12"
    assert _satisfies("3.13", ">=3.10") and not _satisfies("3.13", "<3.13") and _satisfies("3.12", "~=3.10")
    assert _caret("^2.31") == ">=2.31,<3" and _caret("*") == "" and _caret("1.2.3") == "==1.2.3"


# ------------------------------------------------------------------ Go details

def test_go_cgo_and_runtime_files(tmp_path):
    write(tmp_path, "go.mod", "module example.com/web\n\ngo 1.21\n\nrequire github.com/mattn/go-sqlite3 v1.14.22\n")
    write(tmp_path, "main.go", 'package main\n\n// #include <stdlib.h>\nimport "C"\n\nimport (\n\t"html/template"\n\t"net/http"\n\t'
          '_ "github.com/mattn/go-sqlite3"\n)\n\nfunc main() {\n\tt := template.Must(template.ParseGlob("templates/*"))\n'
          '\t_ = t\n\thttp.ListenAndServe(":3000", nil)\n}\n')
    _, c, plan, df = plan_and_df(tmp_path, tmp_path.name)
    assert c.role == "web" and plan["cgo"] and plan["port"] == 3000
    assert "CGO_ENABLED=1" in df and "gcr.io/distroless/base-debian12:nonroot AS final" in df
    assert "COPY --from=build /out/files/ /app/" in df
    assert set(c.project.packages) == {"github.com/mattn/go-sqlite3"}


def test_go_library_module_is_not_deployed(tmp_path):
    write(tmp_path, "go.mod", "module example.com/lib\n\ngo 1.22\n")
    write(tmp_path, "lib.go", "package lib\n\nfunc Add(a, b int) int { return a + b }\n")
    a = assess(tmp_path)
    assert a.components == [] and [x.role for x in a.libraries] == ["library"]


def test_go_gin_server_in_internal_package(tmp_path):
    write(tmp_path, "go.mod", "module example.com/svc\n\ngo 1.23\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n"
          "\tgithub.com/spf13/cobra v1.8.0\n)\n")
    write(tmp_path, "cmd/svc/main.go", 'package main\n\nimport "example.com/svc/internal/web"\n\nfunc main() { web.Start() }\n')
    write(tmp_path, "internal/web/web.go", 'package web\n\nimport "github.com/gin-gonic/gin"\n\nfunc Start() {\n\tr := gin.Default()\n'
          '\tr.GET("/ping", func(c *gin.Context) {})\n\tr.Run(":8080")\n}\n')
    a, c, plan, df = plan_and_df(tmp_path, "svc")
    assert c.role == "web" and plan["health"] == "/ping"
    assert set(c.project.packages) == {"github.com/gin-gonic/gin"}    # cobra is not imported by this binary
    assert "-o /out/svc './cmd/svc'" in df
    yaml.safe_dump(make_plan(a, c))
