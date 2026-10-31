"""Scheduled organization scans: schedule maths, configuration checks, metrics, and end to end against
SQL Server (CONTAINERIZER_TEST_SQL): an administrator adds a scan and presses Run now, the worker runs
it, skipped repositories show as disabled with the reason, enable/disable is honoured and audited, new
and removed repositories are detected, and the metrics follow."""
import os
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from containerizer import admin as adminmod
from containerizer import admin_scans, metrics, sqlstore, webui, worker
from containerizer import org as orgmod
from containerizer.orgsource import NO_PROJECT, SourceRepo

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "ci-demo"
UTC = timezone.utc


# --------------------------------------------------------------------------- schedule

def test_next_run():
    sat = 1 << 5
    # Friday 2026-10-30 10:00 UTC -> Saturday 02:00
    assert worker.next_run(sat, 120, datetime(2026, 10, 30, 10, 0, tzinfo=UTC)) == datetime(2026, 10, 31, 2, 0, tzinfo=UTC)
    # exactly at the time: the next one, a week later
    assert worker.next_run(sat, 120, datetime(2026, 10, 31, 2, 0, tzinfo=UTC)) == datetime(2026, 11, 7, 2, 0, tzinfo=UTC)
    # every day, later today
    assert worker.next_run(127, 23 * 60 + 30, datetime(2026, 10, 31, 7, 0, tzinfo=UTC)) == datetime(2026, 10, 31, 23, 30, tzinfo=UTC)
    # Mondays and Thursdays from Thursday evening
    assert worker.next_run(1 | 8, 60, datetime(2026, 10, 29, 22, 0, tzinfo=UTC)) == datetime(2026, 11, 2, 1, 0, tzinfo=UTC)
    assert worker.next_run(0, 60, datetime(2026, 10, 29, tzinfo=UTC)) is None
    # naive times are UTC (as SQL Server returns them)
    assert worker.next_run(sat, 120, datetime(2026, 10, 30, 10, 0)) == datetime(2026, 10, 31, 2, 0, tzinfo=UTC)


def test_schedule_text():
    assert worker.schedule_text(0, 0) == "On demand only"
    assert worker.schedule_text(127, 90) == "Every day at 01:30 UTC"
    assert worker.schedule_text(31, 0) == "Mondays to Fridays at 00:00 UTC"
    assert worker.schedule_text(1 | 32, 120) == "Mon, Sat at 02:00 UTC"


# --------------------------------------------------------------------------- configuration checks

SCAN = {"Provider": "github", "Organization": "acme", "ApiUrl": None, "TokenEnv": None, "Registry": "reg.example.com/sb",
        "OutputRepo": None, "OutputTokenEnv": None, "PushImages": False, "IncludeRegex": None, "ExcludeRegex": None}


def test_check_scan_refuses_foreign_secrets_and_hosts():
    hosts = worker.allowed_hosts({"CONTAINERIZER_WORKER_HOSTS": "ghe.example.com, reg.example.com"})
    assert worker.check_scan(SCAN, hosts) == []
    assert "CZ_TOKEN_" in worker.check_scan({**SCAN, "TokenEnv": "CONTAINERIZER_SQL_PASSWORD"}, hosts)[0]
    assert worker.check_scan({**SCAN, "OutputTokenEnv": "REGISTRY_PASSWORD"}, hosts)
    assert worker.check_scan({**SCAN, "TokenEnv": "CZ_TOKEN_ACME"}, hosts) == []
    assert "evil.example" in worker.check_scan({**SCAN, "ApiUrl": "https://evil.example/api"}, hosts)[0]
    assert worker.check_scan({**SCAN, "ApiUrl": "https://ghe.example.com/api/v3"}, hosts) == []
    assert worker.check_scan({**SCAN, "OutputRepo": "https://evil.example/x.git"}, hosts)
    assert worker.check_scan({**SCAN, "PushImages": True, "Registry": "other.example/x"}, hosts)
    assert worker.check_scan({**SCAN, "PushImages": True}, hosts) == []
    assert worker.check_scan({**SCAN, "IncludeRegex": "("}, hosts)


def _form(**kw):
    f = {"Name": ["Acme"], "Provider": ["github"], "Organization": ["acme"], "Registry": ["reg.example.com/sandbox"],
         "OutputBranch": ["main"], "StaleDays": ["183"], "At": ["02:30"], "day": ["5", "6"], "Enabled": ["1"],
         "Verify": ["1"]}
    f.update({k: [v] if isinstance(v, str) else v for k, v in kw.items()})
    return f


def test_scan_form_validation():
    v, errors = admin_scans.validate_scan(_form())
    assert errors == [] and v["ScheduleDays"] == (1 << 5) | (1 << 6) and v["ScheduleMinute"] == 150
    assert v["Enabled"] is True and v["Gate"] is False and v["OutputBranch"] == "main"
    for bad, msg in [({"TokenEnv": "CONTAINERIZER_SQL_PASSWORD"}, "Token variable"),
                     ({"ApiUrl": "javascript:alert(1)"}, "https"), ({"OutputRepo": "http://x.example/r"}, "https"),
                     ({"Registry": "Reg Example"}, "registry"), ({"OutputBranch": "-x"}, "branch"),
                     ({"OutputBranch": "a..b"}, "branch"), ({"ImagePullSecret": "Bad_Name"}, "secret"),
                     ({"IncludeRegex": "(["}, "matching"), ({"StaleDays": "99999"}, "3650"), ({"At": "25:00"}, "HH:MM"),
                     ({"Provider": "svn"}, "provider"), ({"Name": ""}, "Name is required")]:
        _, errors = admin_scans.validate_scan(_form(**bad))
        assert any(msg.lower() in x.lower() for x in errors), (bad, errors)


def test_repo_state_texts():
    base = {"RemovedAt": None, "AdminState": None, "AdminNote": None, "SkipStatus": None, "SkipReason": None,
            "LastStatus": "deployed"}
    assert admin_scans.repo_state(base) == ("Enabled", "automatic", "")
    assert admin_scans.repo_state({**base, "LastStatus": None})[2] == "new: not scanned yet"
    st = admin_scans.repo_state({**base, "SkipStatus": "skipped-dockerfile", "SkipReason": "already has Dockerfile"})
    assert st == ("Disabled", "automatic", "Has a Dockerfile: already has Dockerfile")
    st = admin_scans.repo_state({**base, "AdminState": "enabled", "SkipStatus": "skipped-no-code", "SkipReason": "x"})
    assert st[0] == "Enabled" and st[1] == "administrator" and "overrides the automatic skip: No application code" in st[2]
    st = admin_scans.repo_state({**base, "AdminState": "disabled", "AdminNote": "legacy"})
    assert st == ("Disabled", "administrator", "disabled by an administrator (legacy)")


# --------------------------------------------------------------------------- metrics

def test_metrics_exposition_and_auth():
    m = worker.ScanMetrics({"data": "/"}, "w1")
    m.runs.inc(scan='Acme "prod"', status="succeeded")
    m.repo_seconds.observe(42, scan="Acme")
    m.repo_seconds.observe(4000, scan="Acme")
    text = m.registry.render()
    assert 'containerizer_scan_runs_total{scan="Acme \\"prod\\"",status="succeeded"} 1' in text
    assert 'containerizer_scan_repository_duration_seconds_bucket{scan="Acme",le="60.0"} 1' in text
    assert 'containerizer_scan_repository_duration_seconds_bucket{scan="Acme",le="+Inf"} 2' in text
    assert 'containerizer_scan_repository_duration_seconds_count{scan="Acme"} 2' in text
    assert "# TYPE process_cpu_seconds_total counter" in text and "process_resident_memory_bytes " in text
    assert 'containerizer_host_cpu_seconds_total{mode="idle"}' in text
    assert "containerizer_host_memory_available_bytes " in text
    assert 'containerizer_host_filesystem_avail_bytes{path="/",use="data"}' in text
    assert 'containerizer_worker_info{worker="w1",version=' in text
    # every sample line is name{labels} value
    for line in text.splitlines():
        if line and not line.startswith("#"):
            assert re.fullmatch(r'[a-zA-Z_:][\w:]*(\{.*\})? (-?[\d.e+-]+|NaN|\+Inf|-Inf)', line), line
    srv = metrics.serve(m.registry, "127.0.0.1", 0, token="s3cret-token")
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as ex:
            urllib.request.urlopen(url + "/metrics", timeout=5)
        assert ex.value.code == 401
        req = urllib.request.Request(url + "/metrics", headers={"Authorization": "Bearer s3cret-token"})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.headers["Content-Type"].startswith("text/plain; version=0.0.4")
            assert "containerizer_scan_runs_total" in r.read().decode()
        assert urllib.request.urlopen(url + "/healthz", timeout=5).read() == b"ok\n"
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- end to end with SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")
PW = "Test-Passw0rd!x"


def _commit(path: Path):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"], cwd=path, check=True)


class _Provider:
    def __init__(self, repos):
        self.list = repos

    def repos(self):
        return iter(list(self.list))

    def last_commit(self, r):
        return None

    def git_header(self):
        return ""


@needs_sql
def test_scheduled_org_scan_end_to_end(tmp_path, monkeypatch):
    from test_admin import Browser, MockIdP, cfg, free_port
    import uuid
    sa_pw = os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czwrk_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    for login, role in (("cz_w_reader", "reader"), ("cz_w_writer", "writer"), ("cz_w_admin", "admin")):
        sqlstore.create_login(conn, login, PW, role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    writer = as_("cz_w_writer")

    # the organization: an app, one with a Dockerfile, docs only, and one to be disabled
    sources = {}
    for n in ("shop", "dockerized", "handbook", "legacy", "newcomer"):
        d = tmp_path / "src" / n
        if n == "handbook":
            d.mkdir(parents=True)
            (d / "README.md").write_text("# Handbook\n")
            (d / "onboarding.md").write_text("# Onboarding\n")
        else:
            shutil.copytree(DEMO, d)
        if n == "dockerized":
            (d / "Dockerfile").write_text("FROM scratch\n")
        _commit(d)
        sources[n] = d

    def repo(n, i):
        return SourceRepo("github", "acme", NO_PROJECT, n, f"https://github.com/acme/{n}.git", default_branch="main",
                          web_url=f"https://github.com/acme/{n}", id=str(i))
    prov = _Provider([repo(n, i) for i, n in enumerate(("shop", "dockerized", "handbook", "legacy"))])
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: prov)
    fetched = []

    def fake_update(url, dest, branch="", header=""):
        n = url.rsplit("/", 1)[1].removesuffix(".git")
        fetched.append(n)
        if dest.exists():
            return "pulled"
        shutil.copytree(sources[n], dest)
        subprocess.run(["git", "remote", "add", "origin", url], cwd=dest, check=True)
        return "cloned"
    monkeypatch.setattr(orgmod, "update_clone", fake_update)
    monkeypatch.setenv("CONTAINERIZER_SQL_PASSWORD", PW)        # the worker stores assessments as the writer

    idp = MockIdP()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    adm = adminmod.Admin(cfg(idp, base), lambda: sqlstore.connect(as_("cz_w_admin"), PW))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(lambda: sqlstore.connect(as_("cz_w_reader"), PW), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    idp.claims = {"email": "jane@example.com", "name": "Jane Doe", "groups": ["cz-admins"]}
    logs = []
    w = worker.Worker(lambda: sqlstore.connect(writer, PW), tmp_path / "data", sql=writer, poll=1, name="test-worker",
                      hosts=worker.allowed_hosts({}), log=logs.append)
    try:
        b = Browser(base, idp)
        s, _, body = b.follow("/admin/scans")
        assert s == 200 and "No organization scans yet" in body and "Organization scans" in body
        csrf = b.csrf(body)
        # a token variable that names the database password is refused
        s, _, body = b.follow("/admin/scans/new", {"csrf": csrf, **_form(TokenEnv="CONTAINERIZER_SQL_PASSWORD")})
        assert "Token variable: CZ_TOKEN_" in body
        s, h, body = b.follow("/admin/scans/new", {"csrf": csrf, **_form(Name="Acme GitHub", TokenEnv="CZ_TOKEN_ACME",
                                                                         Gate="", day=["5"])})
        assert s == 200 and "Saved." in body and "Sat at 02:30 UTC" in body
        scan_id = int(re.search(r"/admin/scans/(\d+)/run", body)[1])
        # no worker has run yet: it computes the next run
        w.queue_due()
        c = sqlstore.connect(writer, PW)
        cur = c.cursor(as_dict=True)
        cur.execute("SELECT NextRunAt FROM cz.OrgScan WHERE ScanId = %s", (scan_id,))
        nxt = cur.fetchone()["NextRunAt"]
        assert nxt.weekday() == 5 and (nxt.hour, nxt.minute) == (2, 30)
        c.close()

        # Run now (the same scan cannot be queued twice)
        s, _, body = b.follow(f"/admin/scans/{scan_id}/run", {"csrf": csrf})
        assert "queued" in body and "Run now by jane@example.com" in body
        s, _, body = b.follow(f"/admin/scans/{scan_id}/run", {"csrf": csrf})
        assert "already queued or running" in body

        # the worker settings for this test: no build, gate or push (no Docker here)
        real_options = w.options

        def options(scan, store, hooks):
            o = real_options(scan, store, hooks)
            o.verify, o.gate, o.push_images = False, False, False
            return o
        w.options = options
        assert w.tick() is True
        assert w.tick() is False                         # nothing more queued

        s, _, body = b.follow(f"/admin/scans/{scan_id}")
        assert "Finished" in body and "4 of 4" in body and "2 deployed" in body and "4 new" in body, body
        s, _, body = b.follow(f"/admin/repositories?scan={scan_id}")
        assert s == 200
        page_rows = re.findall(r"<tr><td><input type='checkbox' name='repo' value='(\d+)' aria-label='Select ([^']+)'>"
                               r"(.*?)</tr>", body, re.S)
        rows = {n: (int(i), html) for i, n, html in page_rows}
        assert set(rows) == {"shop", "dockerized", "handbook", "legacy"}
        assert "Enabled" in rows["shop"][1] and "Deployed to the sandbox" in rows["shop"][1]
        assert "Disabled" in rows["dockerized"][1] and "Has a Dockerfile: already has Dockerfile" in rows["dockerized"][1]
        assert "Disabled" in rows["handbook"][1] and "No application code: 2 files (.md 2), no source code" in rows["handbook"][1]
        assert "New" in rows["shop"][1]
        disabled = b.follow(f"/admin/repositories?scan={scan_id}&show=disabled")[2]
        assert "dockerized" in disabled and "handbook" in disabled and ">shop<" not in disabled

        # the deployed app links to its results
        s, _, body = b.follow(f"/admin/repositories/{rows['shop'][0]}")
        assert "Demo.Web" in body and "/app/" in body and "Found by a scan" in body

        # an administrator disables legacy and enables the dockerized one anyway
        s, _, body = b.follow("/admin/repositories/bulk", {"csrf": csrf, "repo": [str(rows["legacy"][0])],
                                                           "action": "disable", "Note": "replaced by shop"})
        assert "1 repository disabled" in body
        s, _, body = b.follow(f"/admin/repositories/{rows['dockerized'][0]}", {"csrf": csrf, "Setting": "enabled",
                                                                                "Note": "assess anyway"})
        assert "Saved." in body and "overrides the automatic skip: Has a Dockerfile" in body
        assert "Jane Doe" in body and "<del>automatic</del> → <ins>enabled</ins>" in body
        # missing CSRF token: refused
        assert b.go("/admin/repositories/bulk", {"repo": [str(rows["shop"][0])], "action": "disable"})[0] == 403

        # the organization changes: a new repository, and handbook is deleted
        prov.list = [repo(n, i) for i, n in enumerate(("shop", "dockerized", "legacy", "newcomer"))]
        fetched.clear()
        s, _, body = b.follow(f"/admin/scans/{scan_id}/run", {"csrf": csrf})
        assert w.tick() is True
        assert "legacy" not in fetched and fetched.count("shop") == 1          # disabled: not fetched
        body = b.follow(f"/admin/repositories?scan={scan_id}")[2]
        page_rows = re.findall(r"<tr><td><input type='checkbox' name='repo' value='(\d+)' aria-label='Select ([^']+)'>"
                               r"(.*?)</tr>", body, re.S)
        rows2 = {n: html for _, n, html in page_rows}
        assert set(rows2) == {"shop", "dockerized", "legacy", "newcomer"}
        assert "Deployed to the sandbox" in rows2["dockerized"] and "administrator" in rows2["dockerized"]
        assert "disabled by an administrator (replaced by shop)" in rows2["legacy"]
        assert "Not processed (disabled)" in rows2["legacy"]
        assert "Deployed to the sandbox" in rows2["newcomer"]
        removed = b.follow(f"/admin/repositories?scan={scan_id}&show=removed")[2]
        assert "handbook" in removed and "no longer in the organization" in removed
        s, _, body = b.follow(f"/admin/scans/{scan_id}")
        assert "1 new" in body and "3 deployed" in body

        # the audit trail: who changed what
        body = b.follow("/admin/audit?table=OrgRepository")[2]
        assert "Found by a scan" in body and "Jane Doe" in body and "replaced by shop" in body
        assert "<del>no</del> → <ins>yes</ins>" in body                         # handbook removed
        body = b.follow("/admin/audit?table=OrgScan")[2]
        assert "Acme GitHub" in body and "Sat" in body and "02:30" in body

        # the generated sandbox output on the worker: the disabled repository is not deployed
        out = tmp_path / "data" / f"scan-{scan_id}" / "output" / "acme" / "_"
        assert (out / "shop").is_dir() and (out / "dockerized").is_dir() and not (out / "legacy").exists()
        assert (tmp_path / "data" / f"scan-{scan_id}" / "repos" / "shop").is_dir()
        assert not (tmp_path / "data" / f"scan-{scan_id}" / "repos" / "handbook").exists()   # pruned

        # metrics
        c = sqlstore.connect(writer, PW)
        w.metrics.refresh(c)
        c.close()
        text = w.metrics.registry.render()
        assert 'containerizer_scan_runs_total{scan="Acme GitHub",status="succeeded"} 2' in text
        assert 'containerizer_scan_repositories{scan="Acme GitHub",state="disabled_admin"} 1' in text
        assert 'containerizer_scan_repositories{scan="Acme GitHub",state="removed"} 1' in text
        assert 'containerizer_scan_repositories{scan="Acme GitHub",state="enabled"} 3' in text
        assert 'containerizer_scan_new_repositories_total{scan="Acme GitHub"} 5' in text
        assert 'containerizer_scan_repositories_processed_total{scan="Acme GitHub",status="skipped-no-code"} 1' in text
        assert 'containerizer_scan_git_operations_total{scan="Acme GitHub",operation="clone",result="ok"} 5' in text
        assert 'containerizer_scan_git_operations_total{scan="Acme GitHub",operation="pull",result="ok"} 2' in text

        # cancel: a queued run is cancelled at once and the worker never starts it
        s, _, body = b.follow(f"/admin/scans/{scan_id}/run", {"csrf": csrf})
        rid = re.search(r"Run #(\d+) queued", body)[1]
        s, _, body = b.follow(f"/admin/scans/{scan_id}/cancel", {"csrf": csrf, "RunId": rid})
        assert f"Run #{rid}: cancelled." in body
        assert w.tick() is False

        # a run whose worker died is marked failed after the heartbeat timeout
        c = sqlstore.connect(as_("cz_w_admin"), PW)
        c.set_user("jane@example.com")
        cur = c.cursor()
        cur.execute("EXEC cz.QueueOrgScanRun @ScanId = %s, @TriggeredBy = N'manual'", (scan_id,))
        cur.fetchone()
        c.commit()
        c.close()
        run = w.claim()
        c = sqlstore.connect(cs, sa_pw)
        c.cursor().execute("UPDATE cz.OrgScanRun SET HeartbeatAt = DATEADD(minute, -30, SYSUTCDATETIME()) WHERE RunId = %s",
                           (run["RunId"],))
        c.commit()
        c.close()
        w.recover()
        body = b.follow(f"/admin/scans/{scan_id}")[2]
        assert "the worker stopped during the run" in body

        # least privilege: the admin login cannot write the scan's columns, the writer cannot enable
        a = sqlstore.connect(as_("cz_w_admin"), PW)
        with pytest.raises(Exception, match="(?i)permission"):
            a.cursor().execute("UPDATE cz.OrgRepository SET SkipStatus = NULL")
        a.close()
        wr = sqlstore.connect(writer, PW)
        with pytest.raises(Exception, match="(?i)permission"):
            wr.cursor().execute("UPDATE cz.OrgRepository SET AdminState = N'enabled'")
        with pytest.raises(Exception, match="(?i)permission"):
            wr.cursor().execute("UPDATE cz.OrgScan SET TokenEnv = N'CZ_TOKEN_X'")
        wr.close()
        r = sqlstore.connect(as_("cz_w_reader"), PW)
        with pytest.raises(Exception, match="(?i)permission"):
            r.cursor().execute("SELECT * FROM cz.OrgScan")
        r.close()
    finally:
        idp.claims = {}
        httpd.shutdown()
        idp.httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()
