"""Dev database backups: upload parsing, the sandbox database manifests and the app's settings."""
import gzip
import io
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))

from containerizer import devdb, generate
from containerizer.assess import assess
from containerizer.harden import lint_manifests
from test_engine import web_app


def _db(engine="sqlserver", env=None):
    return devdb.SandboxDb(engine=engine, database="Shop", image="registry.local/app/devdb:t1",
                           env=env if env is not None else {})


# -- sniffing -------------------------------------------------------------------------------------

def test_sniff_recognises_backup_formats():
    assert devdb.sniff(b"TAPE\x00\x00rest", "x.bak") == "sqlserver"
    assert devdb.sniff(b"PGDMP\x01\x0e", "x.dump") == "postgresql"
    assert devdb.sniff(b"-- MySQL dump 10.13\nCREATE TABLE t (id int);\n", "x.sql") == "sql"
    assert devdb.sniff(gzip.compress(b"CREATE TABLE t (id int);\n"), "x.sql.gz") == "sql"
    assert devdb.sniff(b"\x7fELF\x02\x01", "x.bak") is None


def test_check_engine_rejects_mismatch():
    devdb.check_engine("sqlserver", "sqlserver")
    with pytest.raises(devdb.UploadError):
        devdb.check_engine("sqlserver", "postgresql")
    with pytest.raises(devdb.UploadError):
        devdb.check_engine("postgresql", None)


# -- multipart ------------------------------------------------------------------------------------

def _multipart(fields, file_name, data, boundary="----czb0undary"):
    out = io.BytesIO()
    for k, v in fields:
        out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"backup\"; filename=\"{file_name}\"\r\n"
              f"Content-Type: application/octet-stream\r\n\r\n".encode() + data + b"\r\n")
    out.write(f"--{boundary}--\r\n".encode())
    body = out.getvalue()
    return io.BytesIO(body), len(body), f"multipart/form-data; boundary={boundary}"


def test_parse_multipart_streams_the_file(tmp_path):
    data = b"TAPE" + bytes(range(256)) * 2000 + b"\r\n--not-the-boundary\r\n" + b"x" * 70000
    rfile, n, ctype = _multipart([("csrf", "tok"), ("engine", "sqlserver"), ("prompt", "use it")], "shop.bak", data)
    seen = {}
    up = devdb.parse_multipart(rfile, n, ctype, tmp_path, 10 << 20, before_file=lambda f: seen.update(f))
    assert seen["csrf"] == ["tok"]                      # checked before a byte of the file is written
    assert up.fields["prompt"] == ["use it"] and up.filename == "shop.bak"
    assert up.size == len(data) and Path(up.path).read_bytes() == data
    import hashlib
    assert up.sha256 == hashlib.sha256(data).hexdigest()
    assert oct(Path(up.path).stat().st_mode & 0o777) == "0o600"


def test_parse_multipart_limits_and_hook(tmp_path):
    rfile, n, ctype = _multipart([("csrf", "tok")], "shop.bak", b"TAPE" + b"x" * 5000)
    with pytest.raises(devdb.UploadError):
        devdb.parse_multipart(rfile, n, ctype, tmp_path, 1000)
    rfile, n, ctype = _multipart([("csrf", "bad")], "shop.bak", b"TAPE")

    def deny(f):
        raise devdb.UploadError("csrf")
    with pytest.raises(devdb.UploadError):
        devdb.parse_multipart(rfile, n, ctype, tmp_path, 1000, before_file=deny)
    assert not list(tmp_path.glob(".upload-*"))        # nothing left behind


# -- the sandbox database -------------------------------------------------------------------------

@pytest.mark.parametrize("engine", ["sqlserver", "postgresql", "mysql"])
def test_manifests_are_hardened(engine):
    docs = devdb.manifests("shop", _db(engine))
    kinds = [d["kind"] for d in docs]
    assert kinds[:4] == ["ServiceAccount", "Deployment", "Service", "NetworkPolicy"]
    assert "ExternalSecret" in kinds and "Password" in kinds
    errors = [v for v in lint_manifests(docs, "devdb: ") if v.severity == "error"]
    assert errors == []
    pod = docs[1]["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert pod["automountServiceAccountToken"] is False
    assert all(e.get("valueFrom") or "PASSWORD" not in e["name"] for e in c["env"])
    pol = docs[3]["spec"]
    assert pol["ingress"][0]["from"] == [{"podSelector": {"matchLabels": {"app.kubernetes.io/part-of": "shop"}}}]
    assert pol["ingress"][0]["ports"] == [{"port": devdb.PORTS[engine], "protocol": "TCP"}]


def test_render_env_keeps_password_out():
    db = _db(env={"Web": devdb.default_env("sqlserver", ["Shop"])})
    env = devdb.render_env(db, db.env["Web"])
    assert env[0] == {"name": "CZ_DEVDB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "devdb", "key": "password"}}}
    assert env[1]["name"] == "ConnectionStrings__Shop"
    assert "Server=devdb,1433;Database=Shop;User Id=app;Password=$(CZ_DEVDB_PASSWORD)" in env[1]["value"]


def test_inject_replaces_same_named_setting_and_orders_password_first():
    docs = [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
        {"name": "web", "env": [{"name": "ConnectionStrings__Shop", "valueFrom": {"secretKeyRef": {"name": "web", "key": "x"}}},
                                {"name": "OTHER", "value": "1"}]}]}}}}]
    devdb.inject(docs, _db(env={"Web": devdb.default_env("sqlserver", ["Shop"])}), "Web")
    env = docs[0]["spec"]["template"]["spec"]["containers"][0]["env"]
    assert [e["name"] for e in env] == ["CZ_DEVDB_PASSWORD", "OTHER", "ConnectionStrings__Shop"]


def test_generate_app_adds_the_database(tmp_path):
    web_app(tmp_path / "app")
    a = assess(tmp_path / "app")
    comp = next(c for c in a.components if generate.buildable(c))
    out = tmp_path / "out"
    generate.generate_app(a, out, devdb=_db(env={comp.name: devdb.default_env("sqlserver", [])}))
    kz = yaml.safe_load((out / "kustomization.yaml").read_text())
    assert "devdb/k8s.yaml" in kz["resources"]
    assert any(i["name"] == "registry.local/app/devdb" for i in kz["images"])
    app_docs = list(yaml.safe_load_all((out / generate.k8s_name(comp.name) / "k8s.yaml").read_text()))
    dep = next(d for d in app_docs if d and d["kind"] == "Deployment")
    names = [e["name"] for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]]
    assert names[0] == "CZ_DEVDB_PASSWORD" and "ConnectionStrings__DefaultConnection" in names
    sec = list(yaml.safe_load_all((out / "security.yaml").read_text()))
    quota = next(d for d in sec if d and d["kind"] == "ResourceQuota")
    assert quota["spec"]["hard"]["limits.memory"] != "2048Mi"   # the database counts towards the quota
    proj = (out / "gitops" / "argocd").rglob("*.yaml")
    text = "".join(p.read_text() for p in proj)
    assert "Password" in text and "ExternalSecret" in text       # the AppProject allows the generator


# -- the LLM's answer -----------------------------------------------------------------------------

class _C:
    def __init__(self, name):
        self.name, self.role, self.facts = name, "web", {}
        self.project = type("P", (), {"rel": "src/Web/Web.csproj"})()


def test_ai_env_validates_the_answer(monkeypatch):
    answer = {"components": [
        {"component": "Web", "env": [
            {"name": "ConnectionStrings__Shop", "value": "Server={host},{port};Database={database};User Id={user};Password={password}"},
            {"name": "Leak", "value": "Server=x;Password=hunter2"},
            {"name": "Expand", "value": "$(HOME)"},
            {"name": "Odd", "value": "{secret}"},
            {"name": "CZ_DEVDB_PASSWORD", "value": "x"},
            {"name": "bad name", "value": "x"}]},
        {"component": "Nope", "env": [{"name": "A", "value": "b"}]}], "notes": ["set Shop"]}
    seen = {}

    def ask(q, schema, model=None):
        seen["q"] = q
        return answer
    monkeypatch.setattr("containerizer.ai.ask_json", ask)
    env, notes = devdb.ai_env(None, [_C("Web")], "sqlserver", "Shop", "Set ConnectionStrings:Shop", None)
    assert list(env) == ["Web"] and [e["name"] for e in env["Web"]] == ["ConnectionStrings__Shop"]
    assert notes == ["set Shop"] and "Set ConnectionStrings:Shop" in seen["q"]
