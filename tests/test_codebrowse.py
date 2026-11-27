"""The code browser of a refactoring order (codebrowse.py): the snapshot and the pages."""
import io
import os
import re
import subprocess
import uuid
import zipfile

import pytest

from containerizer import codebrowse

BASE = "/admin/refactoring/7/code"
OLD = ('<log4net>\n  <appender name="File">\n    <file value="d:\\logs\\a.log" />\n  </appender>\n  <root>\n'
       '    <appender-ref ref="File" />\n  </root>\n</log4net>\n')
NEW = OLD.replace('d:\\logs\\a.log', '/app/logs/a.log').replace('  <root>', '  <appender name="Console" />\n  <root>')


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=repo, check=True,
                   capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    for d in ("src/Svc/Properties", "src/Svc/Handlers", "docs"):
        (r / d).mkdir(parents=True)
    git(r, "init", "-q")
    (r / "src/Svc/log4net.config").write_text(OLD)
    (r / "src/Svc/Program.cs").write_text("class Program {\n  static void Main() { }\n}\n")
    (r / "src/Svc/Properties/AssemblyInfo.cs").write_text('[assembly: SupportedOSPlatform("windows")]\n')
    (r / "src/Svc/Handlers/Order.cs").write_text("class Order { }\n<script>alert(1)</script>\n")
    (r / "src/Svc/logo.png").write_bytes(b"\x89PNG\0\0\0binary")
    (r / "src/Svc/big.txt").write_text("x" * (codebrowse.MAX_FILE + 1))
    (r / "docs/README.md").write_text("# outside the application\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "as assessed")
    (r / "src/Svc/log4net.config").write_text(NEW)
    (r / "src/Svc/Properties/AssemblyInfo.cs").unlink()
    (r / "src/Svc/Dockerfile.notes").write_text("new\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "patched")
    return r


def test_the_snapshot_keeps_both_sides_of_the_applications_folder(repo):
    data = codebrowse.build(repo, repo / "src/Svc")
    snap = codebrowse.Snapshot(data)
    assert snap.root == "src/Svc" and "README.md" not in " ".join(snap.files)          # the application's folder only
    assert {p: f["st"] for p, f in snap.files.items()} == {
        "Dockerfile.notes": "A", "Handlers/Order.cs": "", "Program.cs": "", "Properties/AssemblyInfo.cs": "D",
        "big.txt": "", "log4net.config": "M", "logo.png": ""}
    assert snap.text("log4net.config", "original") == OLD and snap.text("log4net.config", "patched") == NEW
    assert snap.text("Program.cs", "patched") == snap.text("Program.cs", "original")
    assert snap.text("Dockerfile.notes", "original") is None and snap.text("Dockerfile.notes", "patched") == "new\n"
    assert snap.text("Properties/AssemblyInfo.cs", "patched") is None and not snap.has("Properties/AssemblyInfo.cs", "patched")
    assert snap.why("logo.png", "patched") == "binary" and snap.why("big.txt", "original") == "large"
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert "o/log4net.config" in names and "n/log4net.config" in names and "n/Program.cs" not in names
    # the whole repository when the application is its top folder
    assert "docs/README.md" in codebrowse.Snapshot(codebrowse.build(repo, repo)).files
    # the size limit: the patch's files first, the rest listed without their text
    small = codebrowse.Snapshot(codebrowse.build(repo, repo / "src/Svc", total=420))
    assert small.text("log4net.config", "patched") == NEW and small.why("Program.cs", "original") == "limit"


def test_the_pages(repo):
    snap = codebrowse.Snapshot(codebrowse.build(repo, repo / "src/Svc"))
    page = lambda **q: codebrowse.page_html(snap, BASE, "order-agent", {k: [v] for k, v in q.items()})  # noqa: E731
    top = page()
    assert "▸ Handlers" in top and "log4net.config<span class='cb-st cb-M'" in top and "AssemblyInfo" not in top
    assert "📁" in top and f"href='{BASE}?path=Handlers'" in top
    f = page(path="log4net.config")
    assert f.count("<tr class='add'>") == 2 and "/app/logs/a.log" in f and "d:\\logs" not in f and "Side by side" in f
    o = page(path="log4net.config", side="original")
    assert o.count("<tr class='del'>") == 1 and "d:\\logs\\a.log" in o
    s = page(path="log4net.config", view="split")
    assert "cb-split" in s and s.count("class='del'>") == 1 and s.count("class='add'>") == 2 and s.count("class='pad'>") == 1
    gone = page(path="Properties/AssemblyInfo.cs")              # only in the original: shown there
    assert "SupportedOSPlatform" in gone and "· original" in gone and "<tr class='del'>" in gone
    assert "▾ Handlers" in page(path="Handlers/Order.cs") and "&lt;script&gt;alert(1)" in page(path="Handlers/Order.cs")
    assert "<script>" not in page(path="Handlers/Order.cs")
    assert "not kept: a binary file" in page(path="logo.png") and "larger than 512 KiB" in page(path="big.txt")
    found = page(find="ORDER")
    assert f"href='{BASE}?path=Handlers%2FOrder.cs'" in found and "Program.cs" not in found.split("cb-main")[1]
    ch = page(changed="1")
    tree = ch.split("cb-tree")[1].split("cb-main")[0]
    assert "Properties/AssemblyInfo.cs" in tree and "Program.cs" not in tree and "☑ changed files only" in ch
    assert "No such folder" in page(path="../../etc") or "📁" in page(path="../../etc")
    assert codebrowse.clean_path("../../etc/passwd") == "etc/passwd" and codebrowse.clean_path("a\\b/./c") == "a/b/c"


def test_the_handler_makes_a_snapshot(tmp_path, monkeypatch, repo):
    from containerizer import refactor as rf
    patch = subprocess.run(["git", "format-patch", "-1", "--stdout", "HEAD"], cwd=repo, capture_output=True, check=True).stdout
    commit = subprocess.run(["git", "rev-parse", "HEAD~1"], cwd=repo, capture_output=True, check=True).stdout.decode().strip()
    pl = {"source": {"type": "local", "path": str(repo), "subdir": "src/Svc"}, "commit": commit}
    res = {"status": "applies-only", "patch": patch.decode(), "commit": commit}
    snap = codebrowse.Snapshot(rf.code_snapshot(pl, res, tmp_path / "work"))
    assert snap.root == "src/Svc" and snap.text("log4net.config", "patched") == NEW
    assert rf.code_snapshot(pl, {**res, "status": "failed"}, tmp_path / "w2") is None
    assert rf.code_snapshot(pl, {**res, "patch": "not a patch"}, tmp_path / "w3") is None


def test_the_snapshot_in_sql_server(repo, monkeypatch):
    """Schema 64 with the roles' real grants: the writer (the queue runner) stores the snapshot in parts and keeps
    the newest three per application; the administrator reads it; the reader does not. Needs CONTAINERIZER_TEST_SQL."""
    from containerizer import sqlstore
    admin_sql = os.environ.get("CONTAINERIZER_TEST_SQL")
    if not admin_sql:
        pytest.skip("set CONTAINERIZER_TEST_SQL to run against SQL Server")
    name = "czcb_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", admin_sql)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    for login, role in (("cz_cb_reader", "reader"), ("cz_cb_writer", "writer"), ("cz_cb_admin", "admin")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.commit()
    as_ = lambda login: sqlstore.connect(re.sub(r"(?i)(user id|uid)\s*=[^;]*", f"User Id={login}", cs), "Test-Passw0rd!x")  # noqa: E731
    data = codebrowse.build(repo, repo / "src/Svc")
    monkeypatch.setattr(codebrowse, "PART", 500)                 # several parts
    w = as_("cz_cb_writer")
    for job in (1, 2, 3, 4):
        codebrowse.store(w, job, 9, data)
    codebrowse.store(w, 5, None, data)
    codebrowse.store(w, 4, 9, data)                              # stored again: replaced
    w.commit()
    adm = as_("cz_cb_admin")
    assert not codebrowse.exists(adm, 1) and all(codebrowse.exists(adm, j) for j in (2, 3, 4, 5))
    assert codebrowse.load(adm, 1) is None
    snap = codebrowse.load(adm, 4)
    assert snap.text("log4net.config", "patched") == NEW and codebrowse.load(adm, 4) is snap
    cur = adm.cursor()
    cur.execute("SELECT COUNT(*) FROM cz.LlmJobSource WHERE JobId = 4")
    assert cur.fetchone()[0] == -(-len(data) // 500)
    assert not codebrowse.exists(as_("cz_cb_reader"), 4)         # source code: not for the reader role


def test_the_admin_pages(repo):
    pytest.importorskip("jwt")
    from test_refactor import RESULT, _get, _job
    from test_refactor import adm as adm_fixture
    adm = adm_fixture.__wrapped__()
    data = codebrowse.build(repo, repo / "src/Svc")
    parts = [{"Data": data[i:i + 700]} for i in range(0, len(data), 700)]
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [_job(result=RESULT)],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}],
                        r"SELECT TOP \(1\) 1 FROM cz.LlmJobSource": [{"x": 1}],
                        r"SELECT Data FROM cz.LlmJobSource": parts}
    codebrowse._CACHE.clear()
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    order = _get(adm, op, "/admin/refactoring/42").body
    assert "href='/admin/refactoring/42/code'>Browse the code</a>" in order
    r = _get(adm, op, "/admin/refactoring/42/code")
    assert r.status == 200 and "Code of refactoring #42: shop" in r.body and "log4net.config" in r.body
    r = adm.handle("GET", "/admin/refactoring/42/code", "path=log4net.config&view=split", {"Cookie": f"{adm.cookie}={op}"}, b"")
    assert "cb-split" in r.body
    r = adm.handle("GET", "/admin/refactoring/42/code", "path=log4net.config&raw=1&side=original",
                   {"Cookie": f"{adm.cookie}={op}"}, b"")
    assert r.status == 200 and r.body == OLD.encode() and ("X-Content-Type-Options", "nosniff") in r.headers
    assert adm.handle("GET", "/admin/refactoring/42/code", "path=logo.png&raw=1", {"Cookie": f"{adm.cookie}={op}"}, b"").status == 404
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    assert _get(adm, viewer, "/admin/refactoring/42/code").status == 403
    # an order without a snapshot: no button, and the page says so
    codebrowse._CACHE.clear()
    adm.conn.answers = {r"FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'": [_job(result=RESULT)],
                        r"SELECT RemoveRequestedAt FROM cz.LlmJob": [{"RemoveRequestedAt": None}]}
    assert "Browse the code" not in _get(adm, op, "/admin/refactoring/42").body
    assert _get(adm, op, "/admin/refactoring/42/code").status == 404
