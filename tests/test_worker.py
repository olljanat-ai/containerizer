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

SCAN = {"Provider": "github", "Organization": "acme", "ApiUrl": None, "Registry": "reg.example.com/sb",
        "OutputRepo": None, "PushImages": False, "IncludeRegex": None, "ExcludeRegex": None}


def _creds(*items):
    from containerizer.credentials import Credential, Credentials
    return Credentials([Credential(id=i, purpose=p, provider=pr, api_url=api, scope=sc, token=tok)
                        for i, (p, pr, api, sc, tok) in enumerate(items, 1)])


def test_check_scan_needs_registered_tokens_and_allowed_registry():
    hosts = worker.allowed_hosts({"CONTAINERIZER_WORKER_HOSTS": "reg.example.com"})
    acme = ("read", "github", None, "Acme", "ro-token")
    assert worker.check_scan(SCAN, hosts) == []
    # no token for the organization: refused (no anonymous access)
    assert "no read-only token is registered for GitHub organization acme" in worker.check_scan(SCAN, hosts, _creds())[0]
    assert worker.check_scan(SCAN, hosts, _creds(acme)) == []
    # a token of another organization, or of the same name on another server, does not count
    assert worker.check_scan(SCAN, hosts, _creds(("read", "github", None, "acme-labs", "t")))
    assert worker.check_scan(SCAN, hosts, _creds(("read", "github", "https://ghe.example.com/api/v3", "acme", "t")))
    assert worker.check_scan({**SCAN, "ApiUrl": "https://ghe.example.com/api/v3"}, hosts, _creds(acme))
    assert worker.check_scan({**SCAN, "ApiUrl": "https://api.github.com"}, hosts, _creds(acme)) == []
    assert worker.check_scan({**SCAN, "ApiUrl": "https://ghe.example.com/api/v3/"}, hosts,
                             _creds(("read", "github", "https://GHE.example.com/api/v3", "acme", "t"))) == []
    # the output repository needs its own write token, matched by URL, and not the read-only one
    out = {**SCAN, "OutputRepo": "https://github.com/acme/sandbox.git"}
    assert "no write token is registered for the output repository" in worker.check_scan(out, hosts, _creds(acme))[0]
    wr = ("write", "github", None, "https://github.com/Acme/sandbox", "rw-token")
    assert worker.check_scan(out, hosts, _creds(acme, wr)) == []
    same = ("write", "github", None, "https://github.com/acme/sandbox.git", "ro-token")
    assert "separate read-only token" in worker.check_scan(out, hosts, _creds(acme, same))[0]
    assert worker.check_scan(out, hosts, _creds(acme, ("write", "github", None, "https://github.com/acme/sandbox2", "x")))
    # registry hosts
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
    for bad, msg in [({"ApiUrl": "javascript:alert(1)"}, "https"), ({"OutputRepo": "http://x.example/r"}, "https"),
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
    st = admin_scans.repo_state({**base, "SkipStatus": "skipped-dockerfile", "SkipReason": "found Dockerfile"})
    assert st == ("Disabled", "automatic", "Has a Dockerfile: found Dockerfile")
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
    tokens_used = []

    def make_provider(name, org, token="", api_url=None):
        tokens_used.append((name, org, token))
        return prov
    monkeypatch.setattr(orgmod, "provider", make_provider)
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
    from containerizer import credentials as cr
    cr.keygen(tmp_path / "worker.key", tmp_path / "worker.pub")
    adm = adminmod.Admin(cfg(idp, base), lambda: sqlstore.connect(as_("cz_w_admin"), PW))
    adm.credential_key = cr.load_public(tmp_path / "worker.pub")
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(lambda: sqlstore.connect(as_("cz_w_reader"), PW), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    idp.claims = {"email": "jane@example.com", "name": "Jane Doe", "groups": ["cz-admins"]}
    logs = []
    w = worker.Worker(lambda: sqlstore.connect(writer, PW), tmp_path / "data", sql=writer, poll=1, name="test-worker",
                      hosts=worker.allowed_hosts({}), log=logs.append, key=cr.load_private(tmp_path / "worker.key"))
    try:
        b = Browser(base, idp)
        s, _, body = b.follow("/admin/scans")
        assert s == 200 and "No organization scans yet" in body and "Organization scans" in body
        csrf = b.csrf(body)
        s, h, body = b.follow("/admin/scans/new", {"csrf": csrf, **_form(Name="Acme GitHub", Gate="", day=["5"])})
        assert s == 200 and "Saved." in body and "Sat at 02:30 UTC" in body
        # no read-only token for the organization: the scan cannot run, and says why
        assert "no read-only token is registered for GitHub organization acme" in body and "/run'" not in body
        scan_id = int(re.search(r"/admin/repositories\?scan=(\d+)", body)[1])
        assert "Token missing" in b.follow("/admin/scans")[2]
        # an administrator registers one; the page never shows it again
        secret = "github_pat_readonly_0123456789abcdef"
        s, _, body = b.follow("/admin/source-control", None)
        assert s == 200 and "Contents: Read-only" in body and "fine-grained" in body
        s, _, body = b.follow("/admin/source-control/read", {"csrf": csrf, "Provider": "github", "Organization": "acme",
                                                             "ApiUrl": "", "Token": secret, "ExpiresOn": "2099-01-01",
                                                             "Note": "made by Jane"})
        assert s == 200 and "Read-only token saved for acme" in body and secret not in body and "Acme GitHub" in body
        cred_id = int(re.search(r"/admin/source-control/(\d+)/token", body)[1])
        # the same organization twice is refused; a bad token text too; nothing echoes the token
        s, _, body = b.follow("/admin/source-control/read", {"csrf": csrf, "Provider": "github", "Organization": "ACME",
                                                             "Token": secret})
        assert "already has a token" in body and secret not in body
        s, _, body = b.follow("/admin/source-control/write", {"csrf": csrf, "Provider": "gitlab",
                                                              "Scope": "https://github.com/acme/sandbox", "Token": "x y"})
        assert "is on GitHub, not GitLab" in body and "without spaces" in body
        assert secret not in b.follow("/admin/source-control")[2]
        assert secret not in b.follow("/admin/audit?table=SourceCredential")[2]
        s, _, body = b.follow(f"/admin/scans/{scan_id}")
        assert "Run full scan" in body and "Read-only token" in body and f"/admin/source-control/{cred_id}" in body
        # the LLM on the same page: set once, key never shown, model can change, a second one is refused
        llm_key = "sk-llm-secret-0123456789"
        s, _, body = b.follow("/admin/source-control/llm", {"csrf": csrf, "Provider": "openai", "ApiUrl": "https://llm.example/v1",
                                                            "Model": "qwen3:32b", "Token": llm_key})
        assert s == 200 and "LLM saved" in body and llm_key not in body and "qwen3:32b" in body
        llm_id = int(re.search(r"/admin/source-control/(\d+)/token", body)[1])
        s, _, body = b.follow("/admin/source-control/llm", {"csrf": csrf, "Provider": "anthropic", "Model": "x",
                                                            "Token": "sk-ant-0123456789"})
        assert "already set" in body
        s, _, body = b.follow(f"/admin/source-control/{llm_id}", {"csrf": csrf, "Model": "qwen3:235b", "Enabled": "1"})
        assert "Saved." in body and "<del>qwen3:32b</del> → <ins>qwen3:235b</ins>" in body and llm_key not in body
        body = b.follow("/admin/source-control")[2]
        assert "Source control and LLM" in body and "qwen3:235b" in body and llm_key not in body
        c = sqlstore.connect(writer, PW)
        from containerizer import credentials as crm
        got = crm.load(c, cr.load_private(tmp_path / "worker.key")).llm()
        c.close()
        assert got.token == llm_key and got.ai_settings()["CONTAINERIZER_LLM_BASE_URL"] == "https://llm.example/v1"
        s, _, body = b.follow(f"/admin/source-control/{llm_id}/delete", {"csrf": csrf})
        assert "removed" in body
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

        def options(scan, store, hooks, creds=None):
            o = real_options(scan, store, hooks, creds)
            o.verify, o.gate, o.push_images = False, False, False
            return o
        w.options = options
        assert w.tick() is True
        assert w.tick() is False                         # nothing more queued
        assert tokens_used == [("github", "acme", secret)], logs   # opened by the worker, for this organization only
        body = b.follow(f"/admin/source-control/{cred_id}")[2]
        assert "ok: 4 repositories listed" in body and "Working" in body and secret not in body, logs

        s, _, body = b.follow(f"/admin/scans/{scan_id}")
        assert "Finished" in body and "4 of 4" in body and "2 deployed" in body and "4 new" in body, body
        s, _, body = b.follow(f"/admin/repositories?scan={scan_id}")
        assert s == 200
        page_rows = re.findall(r"<tr><td><input type='checkbox' name='repo' value='(\d+)' aria-label='Select ([^']+)'>"
                               r"(.*?)</tr>", body, re.S)
        rows = {n: (int(i), html) for i, n, html in page_rows}
        assert set(rows) == {"shop", "dockerized", "handbook", "legacy"}
        assert "Enabled" in rows["shop"][1] and "Deployed to the sandbox" in rows["shop"][1]
        assert "Disabled" in rows["dockerized"][1] and "Has a Dockerfile: found Dockerfile" in rows["dockerized"][1]
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
            wr.cursor().execute("UPDATE cz.OrgScan SET Organization = N'other'")
        with pytest.raises(Exception, match="(?i)permission"):
            wr.cursor().execute("UPDATE cz.SourceCredential SET Scope = N'other'")
        wr.close()
        # the admin login can replace a token but cannot read the sealed value back
        a = sqlstore.connect(as_("cz_w_admin"), PW)
        with pytest.raises(Exception, match="(?i)permission"):
            a.cursor().execute("SELECT TokenSealed FROM cz.SourceCredential")
        a.close()
        c = sqlstore.connect(cs, sa_pw)
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM cz.AuditLog WHERE OldValues LIKE %s OR NewValues LIKE %s OR "
                    "NewValues LIKE N'%%TokenSealed%%'", (f"%{secret}%", f"%{secret}%"))
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT TokenSealed FROM cz.SourceCredential WHERE CredentialId = %s", (cred_id,))
        assert secret not in cur.fetchone()[0]
        c.close()
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


class _AzureProvider(_Provider):
    """An Azure DevOps organization with projects; counts the latest-commit API calls."""

    def __init__(self, repos, commits):
        super().__init__(repos)
        self.commits = commits
        self.asked = []

    def last_commit(self, r):
        self.asked.append(r.key)
        return self.commits.get(r.key)


@needs_sql
def test_discovery_then_full_scan_with_disabled_projects(tmp_path, monkeypatch):
    """Discover lists projects, repositories and latest commits without cloning; an administrator disables
    a deprecated project and a repository (audited); the full scan leaves them out, and their results
    disappear from the results pages."""
    from test_admin import Browser, MockIdP, cfg, free_port
    import uuid
    sa_pw = os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czdisc_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    for login, role in (("cz_d_reader", "reader"), ("cz_d_writer", "writer"), ("cz_d_admin", "admin")):
        sqlstore.create_login(conn, login, PW, role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    writer, reader = as_("cz_d_writer"), as_("cz_d_reader")

    sources = {}
    for key in ("Billing/api", "Billing/web", "Legacy/old-app"):
        d = tmp_path / "src" / key.replace("/", "--")
        shutil.copytree(DEMO, d)
        _commit(d)
        sources[key] = d

    def repo(key, i):
        proj, n = key.split("/")
        return SourceRepo("azure-devops", "contoso", proj, n, f"https://dev.azure.com/contoso/{proj}/_git/{n}",
                          default_branch="main", web_url=f"https://dev.azure.com/contoso/{proj}/_git/{n}", id=f"id{i}")
    keys = ("Billing/api", "Billing/web", "Legacy/old-app")
    prov = _AzureProvider([repo(k, i) for i, k in enumerate(keys)],
                          {"Billing/api": datetime(2026, 10, 20, 8, 0, tzinfo=UTC),
                           "Billing/web": datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
                           "Legacy/old-app": datetime(2019, 5, 4, 3, 2, tzinfo=UTC)})
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: prov)
    fetched = []

    def fake_update(url, dest, branch="", header=""):
        proj, n = url.split("/contoso/")[1].split("/_git/")
        fetched.append(f"{proj}/{n}")
        if dest.exists():
            return "pulled"
        shutil.copytree(sources[f"{proj}/{n}"], dest)
        subprocess.run(["git", "remote", "add", "origin", url], cwd=dest, check=True)
        return "cloned"
    monkeypatch.setattr(orgmod, "update_clone", fake_update)
    monkeypatch.setenv("CONTAINERIZER_SQL_PASSWORD", PW)

    idp = MockIdP()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    from containerizer import credentials as cr
    cr.keygen(tmp_path / "worker.key", tmp_path / "worker.pub")
    adm = adminmod.Admin(cfg(idp, base), lambda: sqlstore.connect(as_("cz_d_admin"), PW))
    adm.credential_key = cr.load_public(tmp_path / "worker.pub")
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webui.make_handler(lambda: sqlstore.connect(reader, PW), adm))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    idp.claims = {"email": "jane@example.com", "name": "Jane Doe", "groups": ["cz-admins"]}
    logs = []
    w = worker.Worker(lambda: sqlstore.connect(writer, PW), tmp_path / "data", sql=writer, poll=1, name="test-worker",
                      hosts=worker.allowed_hosts({}), log=logs.append, key=cr.load_private(tmp_path / "worker.key"))
    real_options = w.options

    def options(scan, store, hooks, creds=None):
        o = real_options(scan, store, hooks, creds)
        o.verify, o.gate, o.push_images = False, False, False
        return o
    w.options = options

    def visible():
        c = sqlstore.connect(reader, PW)
        cur = c.cursor(as_dict=True)
        cur.execute("SELECT ApplicationId, RepositoryUrl FROM cz.vApplicationLatest")
        apps = {r["RepositoryUrl"].rsplit("/", 1)[1]: r["ApplicationId"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(DISTINCT ApplicationId) AS N FROM cz.vAssessmentHistory")
        hist = cur.fetchone()["N"]
        c.close()
        return apps, hist

    try:
        b = Browser(base, idp)
        body = b.follow("/admin/scans")[2]
        csrf = b.csrf(body)
        s, _, body = b.follow("/admin/scans/new", {"csrf": csrf, **_form(Name="Contoso", Provider="azure-devops",
                                                                         Organization="contoso", Gate="", day=[])})
        scan_id = int(re.search(r"/admin/repositories\?scan=(\d+)", body)[1])
        b.follow("/admin/source-control/read", {"csrf": csrf, "Provider": "azure-devops", "Organization": "contoso",
                                                "ApiUrl": "", "Token": "ado_readonly_pat_0123456789abcdef"})
        body = b.follow(f"/admin/scans/{scan_id}")[2]
        assert "Discover" in body and "Run full scan" in body and "press Discover first" in body

        # phase one: discovery lists projects, repositories and latest commits; nothing is cloned
        s, _, body = b.follow(f"/admin/scans/{scan_id}/discover", {"csrf": csrf})
        assert "Discovery #" in body and "queued" in body
        assert w.tick() is True, logs
        assert fetched == [] and sorted(prov.asked) == sorted(keys), logs
        assert not (tmp_path / "data" / f"scan-{scan_id}" / "repos").exists()
        body = b.follow(f"/admin/scans/{scan_id}")[2]
        assert "Finished" in body and "Discovery" in body and "3 repositories in 2 projects" in body, body
        assert "nothing cloned" in body and "1 would be skipped" in body and "press Discover first" not in body
        body = b.follow(f"/admin/repositories?scan={scan_id}")[2]
        rows = dict(re.findall(r"aria-label='Select ([^']+)'>(.*?)</tr>", body, re.S))
        assert set(rows) == set(keys)
        assert "2026-10-20 08:00 UTC" in rows["Billing/api"] and "discovered: not scanned yet" in rows["Billing/api"]
        assert "2019-05-04 03:02 UTC" in rows["Legacy/old-app"] and "Not updated recently" in rows["Legacy/old-app"]
        body = b.follow(f"/admin/repositories?scan={scan_id}&show=inactive")[2]
        assert "old-app" in body and ">api<" not in body
        body = b.follow(f"/admin/repositories?scan={scan_id}&sort=commit")[2]
        assert body.index("old-app") < body.index(">web<") < body.index(">api<")
        body = b.follow(f"/admin/repositories/projects?scan={scan_id}")[2]
        projects = dict((n, int(i)) for i, n in re.findall(r"name='project' value='(\d+)' aria-label='Select ([^']+)'", body))
        assert set(projects) == {"Billing", "Legacy"} and "2026-10-20 08:00 UTC" in body

        # the full scan with everything enabled (the stale one too) puts all three on the results pages
        b.follow(f"/admin/repositories/{int(re.search(r'/admin/repositories/(\d+)', rows['Legacy/old-app'])[1])}",
                 {"csrf": csrf, "Setting": "enabled", "Note": "still in use"})
        b.follow(f"/admin/scans/{scan_id}/run", {"csrf": csrf})
        assert w.tick() is True
        assert sorted(fetched) == sorted(keys), logs
        apps, hist = visible()
        assert set(apps) == {"api", "web", "old-app"} and hist == 3

        # phase two: the administrator disables the deprecated project and one repository
        s, _, body = b.follow("/admin/repositories/projects/bulk", {"csrf": csrf, "project": [str(projects["Legacy"])],
                                                                    "action": "disable", "Note": "deprecated"})
        assert "1 project disabled" in body and "deprecated" in body
        web_id = int(re.search(r"/admin/repositories/(\d+)", rows["Billing/web"])[1])
        s, _, body = b.follow(f"/admin/repositories/{web_id}", {"csrf": csrf, "Setting": "disabled", "Note": "retired"})
        assert "Saved." in body and "hides its results" in body
        body = b.follow(f"/admin/repositories/projects/{projects['Legacy']}")[2]
        assert "Jane Doe" in body and "<del>enabled</del> → <ins>disabled</ins>" in body and "deprecated" in body
        body = b.follow("/admin/audit?table=OrgProject")[2]
        assert "Legacy" in body and "Found by a scan" in body and "Jane Doe" in body
        body = b.follow(f"/admin/repositories?scan={scan_id}&show=disabled")[2]
        assert "project Legacy disabled by an administrator (deprecated)" in body and "retired" in body
        assert ">api<" not in body
        body = b.follow(f"/admin/repositories/{int(re.search(r'/admin/repositories/(\d+)', rows['Legacy/old-app'])[1])}")[2]
        assert "Its project Legacy is disabled" in body

        # hidden from the results pages (the views the reader login reads), still on the admin pages
        apps, hist = visible()
        assert set(apps) == {"api"} and hist == 1
        overview = b.follow("/")[2]
        assert f"/app/{apps['api']}'" in overview or f'/app/{apps["api"]}"' in overview
        r = sqlstore.connect(cs, sa_pw)
        cur = r.cursor()
        cur.execute("SELECT ApplicationId FROM cz.Application WHERE RepositoryUrl LIKE N'%/web'")
        web_app = cur.fetchone()[0]
        r.close()
        assert f"/app/{web_app}'" not in overview and f'/app/{web_app}"' not in overview
        assert b.go(f"/app/{web_app}")[0] == 404
        assert b.go(f"/app/{apps['api']}")[0] == 200

        # the next full scan only fetches what is enabled
        fetched.clear()
        b.follow(f"/admin/scans/{scan_id}/run", {"csrf": csrf})
        assert w.tick() is True
        assert fetched == ["Billing/api"], logs
        body = b.follow(f"/admin/repositories?scan={scan_id}")[2]
        rows = dict(re.findall(r"aria-label='Select ([^']+)'>(.*?)</tr>", body, re.S))
        assert "Not processed (disabled)" in rows["Legacy/old-app"] and "Not processed (disabled)" in rows["Billing/web"]
        out = tmp_path / "data" / f"scan-{scan_id}" / "output" / "contoso"
        assert (out / "Billing" / "api").is_dir() and not (out / "Legacy" / "old-app").exists() and not (out / "Billing" / "web").exists()
        body = b.follow("/admin/scans")[2]
        assert f"show=enabled'>1</a>" in body and f"show=disabled'>2</a>" in body
        c = sqlstore.connect(writer, PW)
        w.metrics.refresh(c)
        c.close()
        text = w.metrics.registry.render()
        assert 'containerizer_scan_repositories{scan="Contoso",state="disabled_admin"} 2' in text

        # enabling the project again brings its results back; only administrators may change projects
        b.follow(f"/admin/repositories/projects/{projects['Legacy']}", {"csrf": csrf, "Setting": "enabled", "Note": ""})
        apps, _ = visible()
        assert set(apps) == {"api", "old-app"}
        wr = sqlstore.connect(writer, PW)
        with pytest.raises(Exception, match="(?i)permission"):
            wr.cursor().execute("UPDATE cz.OrgProject SET AdminState = N'disabled'")
        wr.close()
        rd = sqlstore.connect(reader, PW)
        with pytest.raises(Exception, match="(?i)permission"):
            rd.cursor().execute("SELECT * FROM cz.OrgProject")
        rd.close()
    finally:
        idp.claims = {}
        httpd.shutdown()
        idp.httpd.shutdown()
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()
