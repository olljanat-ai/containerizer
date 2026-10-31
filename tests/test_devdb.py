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
from test_admin import idp  # noqa: F401,E402


def _db(engine="sqlserver", env=None):
    return devdb.SandboxDb(engine=engine, database="Shop", image="registry.local/app/devdb:t1",
                           env=env if env is not None else {})


# -- sniffing -------------------------------------------------------------------------------------

def test_sniff_recognises_backup_formats():
    assert devdb.sniff(b"TAPE\x00\x00rest", "x.bak") == "sqlserver"
    assert devdb.sniff(b"MSSQLBAK\x02\x00", "x.bak") == "sqlserver"      # WITH COMPRESSION (SQL Server 2022)
    assert devdb.file_format(b"PGDMP\x01\x0e") == ("postgres", "dump")
    pg = b"--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n"
    assert devdb.file_format(pg) == ("postgres", "sql")
    assert devdb.file_format(gzip.compress(pg)) == ("postgres", "sql.gz")
    my = b"-- MySQL dump 10.13  Distrib 8.4.3, for Linux (x86_64)\n--\n-- Host: localhost\n"
    assert devdb.file_format(my) == ("mysql", "sql")
    assert devdb.file_format(b"\xef\xbb\xbf-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB\n") == ("mysql", "sql")
    assert devdb.file_format(gzip.compress(my)[:200]) == ("mysql", "sql.gz")      # only the first bytes are kept
    assert devdb.sniff(b"CREATE TABLE t (id int);\n", "x.sql") is None
    assert devdb.sniff(b"\x7fELF\x02\x01", "x.bak") is None
    assert devdb.sniff(gzip.compress(b"hello"), "x.gz") is None


def test_check_engine_rejects_mismatch():
    devdb.check_engine("sqlserver", "sqlserver")
    with pytest.raises(devdb.UploadError):
        devdb.check_engine("sqlserver", None)
    with pytest.raises(devdb.UploadError):
        devdb.check_engine("postgresql", "sqlserver")


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

@pytest.mark.parametrize("engine", ["sqlserver", "postgres", "mysql"])
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


# -- end to end: the upload page against SQL Server ----------------------------------------------

import os  # noqa: E402
import re  # noqa: E402
import threading  # noqa: E402
import urllib.request  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


def _post_multipart(browser, path, fields, file_name, data):
    rfile, n, ctype = _multipart(fields, file_name, data)
    req = urllib.request.Request(browser.base + path, data=rfile.getvalue(), headers={"Content-Type": ctype})
    try:
        r = browser.opener.open(req, timeout=20)
        status, h = r.status, dict(r.headers)
    except urllib.error.HTTPError as ex:
        status, h = ex.code, dict(ex.headers)
    if status == 303:
        return browser.follow(h["Location"])
    return status, h, ""


@needs_sql
def test_upload_end_to_end(tmp_path, idp):
    pytest.importorskip("jwt")
    import uuid
    from containerizer import admin as adminmod
    from containerizer import sqlstore, webui
    from containerizer.roles import parse_owners
    from test_admin import Browser, cfg, free_port
    name = "czdevdb_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_d_reader", "reader"), ("cz_d_writer", "writer"), ("cz_d_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    web_app(tmp_path / "shop")
    sqlstore.store_results(as_("cz_d_writer"), [assess(tmp_path / "shop")], [tmp_path / "shop"], password="Test-Passw0rd!x")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    c = cfg(idp, base)
    c.operators = ["role:Ops"]
    c.owners = parse_owners("role:Owner=bu:Nothing")
    adm = adminmod.Admin(c, lambda: sqlstore.connect(as_("cz_d_admin"), "Test-Passw0rd!x"))
    adm.devdb = devdb.Settings(tmp_path / "store", 1 << 20)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(
        lambda: sqlstore.connect(as_("cz_d_reader"), "Test-Passw0rd!x"), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    backup = b"TAPE" + os.urandom(200_000)
    try:
        # a product owner has no dev database pages
        po = Browser(base, idp)
        idp.claims = {"email": "pat@example.com", "roles": ["Owner"]}
        s, _, body = po.follow("/admin/dev-databases")
        assert s == 403
        assert _post_multipart(po, "/admin/dev-databases/1/upload", [("csrf", po.csrf(body) if "csrf" in body else "x")],
                               "a.bak", backup)[0] == 403
        # operator
        op = Browser(base, idp)
        idp.claims = {"email": "olga@example.com", "name": "Olga Ops", "roles": ["Ops"]}
        s, _, body = op.follow("/admin/dev-databases")
        assert s == 200 and "Dev databases" in body
        app_id = re.search(r"<option value='(\d+)'>", body)[1]
        csrf = op.csrf(body)
        s, _, body = op.follow(f"/admin/dev-databases/{app_id}")
        assert "enctype='multipart/form-data'" in body and "The development database of" in body
        # wrong CSRF token: refused before the file is written
        s, _, body = _post_multipart(op, f"/admin/dev-databases/{app_id}/upload", [("csrf", "nope")], "shop.bak", backup)
        assert "Not uploaded: The form expired" in body
        assert not [p for p in (tmp_path / "store").iterdir()] if (tmp_path / "store").exists() else True
        # not a backup
        s, _, body = _post_multipart(op, f"/admin/dev-databases/{app_id}/upload",
                                     [("csrf", csrf), ("Engine", "sqlserver"), ("DatabaseName", "Shop"), ("Prompt", "x")],
                                     "shop.bak", b"MZ\x90\x00" + backup)
        assert "not a SQL Server backup" in body
        # too large
        s, _, body = _post_multipart(op, f"/admin/dev-databases/{app_id}/upload",
                                     [("csrf", csrf), ("Engine", "sqlserver"), ("DatabaseName", "Shop"), ("Prompt", "x")],
                                     "shop.bak", b"TAPE" + b"x" * (2 << 20))
        assert "larger than" in body
        # a good one
        s, _, body = _post_multipart(op, f"/admin/dev-databases/{app_id}/upload",
                                     [("csrf", csrf), ("Engine", "sqlserver"), ("DatabaseName", "Shop"),
                                      ("Prompt", "Use ConnectionStrings:Shop.")], "shop.bak", backup)
        assert "Uploaded 195.3 KB" in body and "Olga Ops" in body and "as operator" in body
        import hashlib
        sha = hashlib.sha256(backup).hexdigest()
        stored = tmp_path / "store" / f"{sha}.bak"
        assert stored.read_bytes() == backup and oct(stored.stat().st_mode & 0o777) == "0o640"
        assert [p.name for p in (tmp_path / "store").iterdir()] == [stored.name]     # no temporary files left
        # edit the instructions, then replace the file: the old one is removed
        s, _, body = op.follow(f"/admin/dev-databases/{app_id}", {"csrf": csrf, "DatabaseName": "ShopDev",
                                                                  "Prompt": "Use ConnectionStrings:Shop and seed users."})
        assert "Saved." in body and "ShopDev" in body
        row = devdb.lookup(as_("cz_d_writer"), _source_key(as_("cz_d_writer"), app_id), "Test-Passw0rd!x")   # what the scan reads
        assert row["DatabaseName"] == "ShopDev" and row["Sha256"] == sha and "seed users" in row["Prompt"]
        backup2 = b"MSSQLBAK" + os.urandom(1000)
        s, _, body = _post_multipart(op, f"/admin/dev-databases/{app_id}/upload",
                                     [("csrf", csrf), ("Engine", "sqlserver"), ("DatabaseName", "Shop"), ("Prompt", "p")],
                                     "shop2.bak", backup2)
        assert "Uploaded" in body and not stored.exists()
        # history, and removal
        body = op.follow("/admin/audit?table=DevDatabase")[2]
        assert "Dev database" in body and "shop2.bak" in body and "as operator" in body
        s, _, body = op.follow(f"/admin/dev-databases/{app_id}/delete", {"csrf": csrf})
        assert "Removed." in body and not list((tmp_path / "store").iterdir())
        # without CONTAINERIZER_DEV_DB_DIR the pages are not there
        adm.devdb = None
        assert op.follow("/admin/dev-databases")[0] == 403
    finally:
        idp.claims = {}
        httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()


def _source_key(cs, app_id):
    from containerizer import sqlstore
    c = sqlstore.connect(cs, "Test-Passw0rd!x")
    cur = c.cursor()
    cur.execute("SELECT SourceKey FROM cz.Application WHERE ApplicationId = %s", (int(app_id),))
    k = cur.fetchone()[0]
    c.close()
    return k


def test_org_scan_reports_a_missing_backup(tmp_path, monkeypatch):
    from containerizer import org
    monkeypatch.setenv("CONTAINERIZER_DEV_DB_DIR", str(tmp_path))
    monkeypatch.setenv("CONTAINERIZER_SQL", "Server=x,1433;Database=d;User Id=u")
    row = {"Engine": "sqlserver", "DatabaseName": "Shop", "FileName": "shop.bak", "SizeBytes": 4, "Sha256": "0" * 64,
           "StoredAs": "0" * 64 + ".bak", "Prompt": "", "UploadedAt": "2026-10-31", "UploadedBy": "olga"}
    monkeypatch.setattr(devdb, "lookup", lambda cs, key, password=None: row)
    o = org.OrgOptions(provider="github", org="acme", output_repo="x", registry="registry.local")
    res = org.RepoResult(provider="github", org="acme", project="", repo="shop", status="error", source_key="k")
    db, r = org._dev_database(o, res, type("A", (), {"name": "shop"})(), [], tmp_path, None, "t1")
    assert db is None and res.dev_database["status"] == "error" and "missing" in res.dev_database["reason"]
    monkeypatch.setattr(devdb, "lookup", lambda cs, key, password=None: None)
    res.dev_database = {}
    assert org._dev_database(o, res, None, [], tmp_path, None, "t1") == (None, None) and res.dev_database == {}


@pytest.mark.skipif(not os.environ.get("CONTAINERIZER_TEST_DEVDB_BACKUP"),
                    reason="set CONTAINERIZER_TEST_DEVDB_BACKUP to a SQL Server .bak to restore it in docker")
def test_restore_in_docker_with_the_pod_settings(tmp_path):
    """The generated image restores a real backup under the pod's securityContext (read-only root,
    uid 10001, ALL capabilities dropped, no-new-privileges, emptyDir mounts)."""
    import hashlib
    import shutil
    import subprocess
    import time
    src = Path(os.environ["CONTAINERIZER_TEST_DEVDB_BACKUP"])
    stored = tmp_path / (hashlib.sha256(src.read_bytes()).hexdigest() + ".bak")
    shutil.copyfile(src, stored)
    devdb.build_context(stored, "sqlserver", "Shop", tmp_path / "ctx")
    subprocess.run(["docker", "build", "-q", "-t", "cz-devdb-test:pytest", str(tmp_path / "ctx")], check=True)
    docs = devdb.manifests("shop", _db(env={}))
    pod = docs[1]["spec"]["template"]["spec"]
    c = pod["containers"][0]
    uid = pod["securityContext"].get("runAsUser") or c["securityContext"]["runAsUser"]
    assert c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    args = ["docker", "run", "-d", "--name", "cz-devdb-pytest", "--read-only", "--user", f"{uid}:{uid}", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "-e", "DEVDB_ADMIN_PASSWORD=Admin1234567890abcdefXYZ",
            "-e", "DEVDB_PASSWORD=App1234567890abcdefXYZ"]
    for m in c["volumeMounts"]:
        args += ["--tmpfs", f"{m['mountPath']}:rw,uid={uid},gid={uid},mode=0700"]
    subprocess.run(["docker", "rm", "-f", "cz-devdb-pytest"], capture_output=True)
    subprocess.run(args + ["cz-devdb-test:pytest"], check=True, capture_output=True)
    try:
        for _ in range(60):
            if subprocess.run(["docker", "exec", "cz-devdb-pytest", *c["readinessProbe"]["exec"]["command"]]).returncode == 0:
                break
            time.sleep(3)
        else:
            raise AssertionError(subprocess.run(["docker", "logs", "cz-devdb-pytest"], capture_output=True, text=True).stdout[-2000:])
        r = subprocess.run(["docker", "exec", "cz-devdb-pytest", "/opt/mssql-tools18/bin/sqlcmd", "-C", "-S", "localhost", "-U", "app",
                            "-P", "App1234567890abcdefXYZ", "-d", "Shop", "-h", "-1", "-b", "-Q",
                            "SET NOCOUNT ON; SELECT IS_MEMBER('db_owner'), IS_SRVROLEMEMBER('sysadmin')"],
                           capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout.split() == ["1", "0"], r.stdout + r.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", "cz-devdb-pytest"], capture_output=True)


@pytest.mark.parametrize("engine,ext", [("postgres", "dump"), ("postgres", "sql.gz"), ("mysql", "sql")])
def test_build_context_restores_with_the_image_entry_point(tmp_path, engine, ext):
    stored = tmp_path / f"{'a' * 64}.{ext}"
    stored.write_bytes(b"x")
    ctx = devdb.build_context(stored, engine, "Shop", tmp_path / "ctx")
    df = (ctx / "Dockerfile").read_text()
    assert df.startswith(f"FROM {devdb.BASE_IMAGES[engine]}")
    assert f"/devdb/backup.{ext}" in df and "/docker-entrypoint-initdb.d/10-devdb-restore.sh" in df
    assert f"USER {devdb.UIDS[engine]}" in df and "DEVDB_NAME=Shop" in df
    script = (ctx / "restore.sh").read_text()
    assert "DEVDB_PASSWORD" in script and (ctx / f"backup.{ext}").exists()
    assert not any(w in script for w in (" -p\"", " -p$", "--password"))       # admin passwords stay in the environment


def test_store_names_the_file_by_its_format(tmp_path):
    settings = devdb.Settings(tmp_path, 10 ** 6)
    f = tmp_path / ".upload-x"
    f.write_bytes(gzip.compress(b"-- MySQL dump 10.13\n"))
    up = devdb.Upload(path=f, sha256="b" * 64, head=f.read_bytes()[:4096], size=10)
    assert devdb.store(settings, up, "mysql") == "b" * 64 + ".sql.gz"
    up.head = b"PGDMP"
    with pytest.raises(devdb.UploadError):
        devdb.store(settings, up, "mysql")


def test_lab_engine_off_turns_its_dev_database_off(tmp_path, monkeypatch):
    from containerizer import org
    monkeypatch.setenv("CONTAINERIZER_DEV_DB_DIR", str(tmp_path))
    monkeypatch.setattr(devdb, "lookup", lambda cs, key, password=None: {
        "Engine": "postgres", "DatabaseName": "Shop", "FileName": "shop.dump"})
    monkeypatch.setenv("CONTAINERIZER_SQL", "Server=x,1433;Database=d;User Id=u")
    o = org.OrgOptions(provider="github", org="acme", output_repo="x", registry="registry.local")
    res = org.RepoResult(provider="github", org="acme", project="", repo="shop", status="error", source_key="k")
    assert org._dev_database(o, res, None, [], tmp_path, None, "t1", lab={"sqlserver"}) == (None, None)
    assert res.dev_database["status"] == "disabled" and "PostgreSQL" in res.dev_database["reason"]


PG_DUMP = """--
-- PostgreSQL database dump
--
SET client_encoding = 'UTF8';
\\connect original
CREATE DATABASE original;
CREATE TABLE public.product (id integer, name text);
ALTER TABLE public.product OWNER TO someone_else;
INSERT INTO public.product VALUES (42, 'tea');
"""
MYSQL_DUMP = """-- MySQL dump 10.13  Distrib 8.4.3, for Linux (x86_64)
/*!40101 SET NAMES utf8mb4 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/ `original` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
USE `original`;
CREATE TABLE `product` (`id` int, `name` varchar(20));
INSERT INTO `product` VALUES (42,'tea');
"""


@pytest.mark.skipif(not os.environ.get("CONTAINERIZER_TEST_DOCKER"),
                    reason="set CONTAINERIZER_TEST_DOCKER=1 to restore PostgreSQL and MySQL dumps in docker")
@pytest.mark.parametrize("engine,dump,gz", [("postgres", PG_DUMP, False), ("postgres", PG_DUMP, True), ("mysql", MYSQL_DUMP, True)])
def test_restore_dumps_in_docker_with_the_pod_settings(tmp_path, engine, dump, gz):
    """A plain dump made from another database name lands in DatabaseName, owned by the app's user,
    under the pod's securityContext (read-only root, non-root, ALL capabilities dropped)."""
    import hashlib
    import subprocess
    import time
    data = gzip.compress(dump.encode()) if gz else dump.encode()
    assert devdb.file_format(data[:4096])[0] == engine
    stored = tmp_path / f"{hashlib.sha256(data).hexdigest()}.{devdb.file_format(data[:4096])[1]}"
    stored.write_bytes(data)
    devdb.build_context(stored, engine, "Shop", tmp_path / "ctx")
    tag = f"cz-devdb-test:{engine}"
    subprocess.run(["docker", "build", "-q", "-t", tag, str(tmp_path / "ctx")], check=True)
    docs = devdb.manifests("shop", _db(engine, env={}))
    pod = docs[1]["spec"]["template"]["spec"]
    c = pod["containers"][0]
    uid = pod["securityContext"].get("runAsUser") or c["securityContext"]["runAsUser"]
    name = f"cz-devdb-pytest-{engine}"
    env = {e["name"]: e.get("value") for e in c["env"]}
    for k in env:
        if env[k] is None:
            env[k] = "Admin1234567890abcdefXYZ" if k != "DEVDB_PASSWORD" else "App1234567890abcdefXYZ"
    args = ["docker", "run", "-d", "--name", name, "--read-only", "--user", f"{uid}:{uid}", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges"]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    for m in c["volumeMounts"]:
        args += ["--tmpfs", f"{m['mountPath']}:rw,uid={uid},gid={uid},mode=0700"]
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(args + [tag], check=True, capture_output=True)
    try:
        for _ in range(60):
            if subprocess.run(["docker", "exec", name, *c["readinessProbe"]["exec"]["command"]], capture_output=True).returncode == 0:
                break
            time.sleep(3)
        else:
            raise AssertionError(subprocess.run(["docker", "logs", name], capture_output=True, text=True).stderr[-3000:])
        if engine == "postgres":
            q = ["docker", "exec", "-e", "PGPASSWORD=App1234567890abcdefXYZ", name, "psql", "-h", "127.0.0.1", "-U", "app",
                 "-d", "Shop", "-tAc", "SELECT name FROM product WHERE id = 42"]
        else:
            q = ["docker", "exec", "-e", "MYSQL_PWD=App1234567890abcdefXYZ", name, "mysql", "-h", "127.0.0.1", "-uapp",
                 "--ssl-mode=REQUIRED", "-N", "Shop", "-e", "SELECT name FROM product WHERE id = 42"]
        r = subprocess.run(q, capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout.strip() == "tea", r.stdout + r.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
