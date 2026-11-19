"""Scheduled backups of the appliance (backup.py, sysagent backup, Admin -> System -> Scheduled backup)."""
import json
import tarfile
from datetime import datetime, timedelta, timezone

import pytest

from containerizer import backup
from test_appliance import ADMIN, page, requests_in, shell  # noqa: F401 - the page fixture

UTC = timezone.utc
ON = {"enabled": True, "time": "02:30", "days": ["mon", "wed", "fri"], "keep_days": 7}


def test_validate_checks_every_field():
    assert backup.validate(ON) == ON
    for bad in ({"time": "24:00"}, {"time": "2:30"}, {"days": []}, {"days": ["mon", "funday"]}, {"keep_days": 0},
                {"keep_days": 366}, {"keep_days": "7"}, {"keep_days": True}):
        with pytest.raises(backup.BackupError):
            backup.validate({**ON, **bad})
    assert backup.validate({**ON, "days": ["fri", "mon"]})["days"] == ["mon", "fri"]       # week order


def test_due_at_the_scheduled_time_once_and_not_for_times_before_the_schedule():
    s = {**ON, "changed_at": "2026-11-16T10:00:00+00:00"}                 # set on a Monday, after 02:30
    mon = datetime(2026, 11, 16, 12, tzinfo=UTC)
    assert not backup.due(s, {}, mon)                                      # Monday 02:30 was before the schedule
    wed = datetime(2026, 11, 18, 2, 31, tzinfo=UTC)
    assert backup.due(s, {}, wed)
    assert not backup.due(s, {"last": {"started": "2026-11-18T02:31:00+00:00",
                                       "finished": "2026-11-18T02:40:00+00:00"}}, wed + timedelta(hours=1))
    assert not backup.due(s, {"last": {"started": "2026-11-18T02:31:00+00:00", "finished": "2026-11-18T02:40:00+00:00"}},
                          datetime(2026, 11, 19, 12, tzinfo=UTC))         # Thursday is not scheduled
    assert backup.due(s, {}, datetime(2026, 11, 20, 3, 0, tzinfo=UTC))    # Friday's run, missed until 03:00
    assert not backup.due(s, {}, datetime(2026, 11, 21, 4, 0, tzinfo=UTC))  # Friday's, more than a day late: skipped
    assert not backup.due({**s, "enabled": False}, {}, wed)
    running = {"last": {"started": "2026-11-20T02:30:10+00:00"}}           # started, not finished yet
    assert not backup.due(s, running, datetime(2026, 11, 20, 2, 31, tzinfo=UTC))
    assert backup.next_slot(s, wed) == datetime(2026, 11, 20, 2, 30, tzinfo=UTC)


def test_prune_keeps_the_days_asked_and_always_the_newest(tmp_path):
    for stamp in ("20261101T023000Z", "20261110T023000Z", "20261117T023000Z", "notes"):
        (tmp_path / f"containerizer-{stamp}.tgz").write_bytes(b"x")
    now = datetime(2026, 11, 18, 3, tzinfo=UTC)
    assert backup.prune(7, now, tmp_path) == ["containerizer-20261110T023000Z.tgz", "containerizer-20261101T023000Z.tgz"]
    assert [a["name"] for a in backup.archives(tmp_path)] == ["containerizer-20261117T023000Z.tgz"]
    assert backup.prune(1, now + timedelta(days=60), tmp_path) == []      # the newest one stays
    assert (tmp_path / "containerizer-notes.tgz").exists()                 # not one of ours


def test_run_backup_archives_the_folders_and_records_the_outcome(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "etc/containerizer/secrets").mkdir(parents=True)
    (root / "etc/containerizer/secrets/credential-key").write_text("k")
    (root / "var/lib/containerizer/system").mkdir(parents=True)
    (root / "var/lib/containerizer/system/sandbox-https.json").write_text("{}")
    dest, state = tmp_path / "backups", tmp_path / "state.json"
    monkeypatch.setattr(backup, "DB_BACKUP_DIR", tmp_path / "mssql-backup")
    asked = []
    last = backup.run_backup({"CZ_SQL_DATABASE": "Containerizer"}, {**ON, "keep_days": 3}, state, log=lambda *_: None,
                             database=asked.append, archive=lambda now: backup.make_archive(now, root, dest))
    assert last["ok"] and asked == ["Containerizer"] and last["database"] == "included"
    f = dest / last["file"]
    assert oct(f.stat().st_mode & 0o777) == "0o600" and oct(dest.stat().st_mode & 0o777) == "0o700"
    with tarfile.open(f) as t:
        assert {"etc/containerizer/secrets/credential-key", "var/lib/containerizer/system/sandbox-https.json"} <= set(t.getnames())
    assert json.loads(state.read_text())["last"]["finished"]
    # an external database: not backed up here, said so
    last = backup.run_backup({"CZ_SQL_SERVER": "sql01,1433"}, ON, state, log=lambda *_: None,
                             database=lambda db: pytest.fail("no BACKUP DATABASE"),
                             archive=lambda now: backup.make_archive(now + timedelta(seconds=1), root, dest))
    assert last["ok"] and last["database"].startswith("external")
    # a failure is recorded with its reason, and nothing is pruned

    def broken(db):
        raise backup.BackupError("BACKUP DATABASE failed: disk full")
    last = backup.run_backup({}, ON, state, log=lambda *_: None, database=broken)
    assert last["ok"] is False and "disk full" in last["message"] and last["finished"]


def test_the_system_page_saves_the_schedule_and_starts_a_backup(page):  # noqa: F811
    status, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "Scheduled backup" in body and "action='/admin/system/backup'" in body and "No backup has run yet" in body
    form = {"enabled": ["1"], "time": ["01:15"], "days": ["mon", "tue", "evil"], "keep_days": ["14"]}
    st, _, loc = page.handle(ADMIN, "POST", ["system", "backup"], {}, form, shell)
    assert st == 303 and loc.endswith("#backup") and "01%3A15+UTC+on+Mon%2C+Tue" in loc
    req = requests_in(page)[0]
    assert {k: req[k] for k in ("action", "enabled", "time", "days", "keep_days")} == {
        "action": "backup-settings", "enabled": True, "time": "01:15", "days": ["mon", "tue"], "keep_days": 14}
    for bad, why in (({"time": ["1:15"]}, "HH%3AMM"), ({"keep_days": ["0"]}, "1+to+365"), ({"days": []}, "one+day")):
        _, _, loc = page.handle(ADMIN, "POST", ["system", "backup"], {}, {**form, **bad}, shell)
        assert why in loc
    assert len(requests_in(page)) == 1
    st, _, loc = page.handle(ADMIN, "POST", ["system", "backup-now"], {}, {}, shell)
    assert "Backup+started" in loc and requests_in(page)[-1]["action"] == "backup-now"
    _, _, loc = page.handle(ADMIN, "POST", ["system", "backup-now"], {}, {}, shell)
    assert "running+already" in loc and len(requests_in(page)) == 2
    # what the agent published: the last backup, the next time and the archives
    s = json.loads((page.status_dir / "status.json").read_text())
    s["backup"] = {"settings": {**ON, "time": "01:15"}, "next": "2026-11-20T01:15:00+00:00", "running": False,
                   "last": {"started": "2026-11-18T01:15:00+00:00", "finished": "2026-11-18T01:17:00+00:00", "ok": True,
                            "file": "containerizer-20261118T011500Z.tgz", "bytes": 52_428_800, "seconds": 95.2,
                            "database": "included"},
                   "archives": [{"name": "containerizer-20261118T011500Z.tgz", "bytes": 52_428_800,
                                 "at": "2026-11-18T01:15:00+00:00"}], "folder": "/var/lib/containerizer/backups"}
    (page.status_dir / "status.json").write_text(json.dumps(s))
    _, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "Last backup: <b class='good'>done</b>" in body and "50.0 MB" in body and "Next: 2026-11-20 01:15 UTC" in body
    assert "value='01:15'" in body and "name='days' value='wed' checked" in body and "value='7'" in body


def test_the_agent_saves_the_schedule_and_starts_backups_as_their_own_unit(tmp_path, monkeypatch):
    from containerizer import sysagent
    from test_appliance import paths as _paths  # noqa: F401
    p = sysagent.Paths(run=tmp_path / "run", conf=tmp_path / "appliance.conf", appliance_env=tmp_path / "appliance.env",
                       os_release=tmp_path / "os-release", snapshots=tmp_path / "snapshots",
                       elemental_run=tmp_path / "elemental", task=tmp_path / "task.json", plan=tmp_path / "plan.json",
                       drain=tmp_path / "drain.json", rules=tmp_path / "egress.json", system_rules=tmp_path / "sys.json",
                       history=tmp_path / "h.jsonl")
    monkeypatch.setattr(sysagent, "P", p)
    (p.run / "requests").mkdir(parents=True)
    p.conf.write_text("CZ_OS_IMAGE=x\nCZ_SIGNER_REPO=y\n")
    monkeypatch.setattr(backup, "SETTINGS", tmp_path / "backup.json")
    monkeypatch.setattr(backup, "STATE", tmp_path / "backup-state.json")
    monkeypatch.setattr(backup, "DEST", tmp_path / "backups")
    monkeypatch.setattr(sysagent, "egress_status", lambda: {})
    monkeypatch.setattr(sysagent, "sandbox_https_status", lambda: {})
    calls, active = [], {"rc": 3}
    monkeypatch.setattr(sysagent, "run", lambda cmd, **kw: calls.append(cmd) or "")
    monkeypatch.setattr(sysagent.subprocess, "run", lambda cmd, **kw: type("R", (), {"returncode": active["rc"]})())

    def request(**body):
        (p.run / "requests" / f"{len(list((p.run / 'requests').iterdir()))}.json").write_text(json.dumps(body))
    request(action="backup-settings", requested_by="alice@x", **ON)
    request(action="backup-settings", requested_by="mallory@x", **{**ON, "time": "25:00"})     # checked again
    assert sysagent.process() == 1
    saved = json.loads(backup.SETTINGS.read_text())
    assert saved["time"] == "02:30" and saved["changed_by"] == "alice@x"
    assert "not a time of day" in json.loads(backup.STATE.read_text())["error"]
    st = json.loads((p.run / "status.json").read_text())["backup"]
    assert st["settings"]["enabled"] and st["next"] and "not a time of day" in st["error"]
    request(action="backup-settings", requested_by="alice@x", **ON)
    assert sysagent.process() == 0 and "error" not in json.loads(backup.STATE.read_text())
    request(action="backup-now", requested_by="alice@x")
    assert sysagent.process() == 0
    run_cmd = next(c for c in calls if c[0] == "systemd-run")
    assert "--unit=containerizer-backup" in run_cmd and run_cmd[-3:] == ["containerizer.sysagent", "backup", "run"]
    assert json.loads(backup.STATE.read_text())["requested"]["by"] == "alice@x"
    calls.clear()
    active["rc"] = 0                                           # one is running: not a second one
    request(action="backup-now", requested_by="alice@x")
    sysagent.process()
    assert not [c for c in calls if c[0] == "systemd-run"]


def test_database_backup_without_compression_on_express_edition(tmp_path, monkeypatch):
    """SQL Server Express refuses BACKUP ... WITH COMPRESSION (Msg 1844): the backup is made without it."""
    from types import SimpleNamespace
    monkeypatch.setattr(backup, "DB_BACKUP_DIR", tmp_path / "mssql-backup")
    monkeypatch.setattr(backup, "SA_SECRET", tmp_path / "sa")
    monkeypatch.setattr(backup.os, "chown", lambda *a, **k: None)
    (tmp_path / "sa").write_text("pw\n")
    express = ("Msg 1844, Level 16, State 1, Server b4df72d6c955, Line 1\nBACKUP DATABASE WITH COMPRESSION is not "
               "supported on Express Edition (64-bit).\nMsg 3013, Level 16, State 1\nBACKUP DATABASE is terminating abnormally.")
    asked = []

    def run(cmd, **kw):
        asked.append(cmd[-1])
        assert kw["env"]["SQLCMDPASSWORD"] == "pw" and "pw" not in " ".join(cmd)
        return SimpleNamespace(returncode=1, stdout=express, stderr="") if "COMPRESSION" in cmd[-1] else \
            SimpleNamespace(returncode=0, stdout="", stderr="")
    backup.backup_database("Containerizer", run=run)
    assert len(asked) == 2 and asked[0].endswith("WITH COMPRESSION, INIT") and asked[1].endswith("WITH INIT")
    # another edition: one statement; another error: not tried again
    asked.clear()
    backup.backup_database("Containerizer", run=lambda cmd, **kw: asked.append(cmd[-1]) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    assert len(asked) == 1
    asked.clear()
    with pytest.raises(backup.BackupError, match="disk full"):
        backup.backup_database("Containerizer", run=lambda cmd, **kw: asked.append(cmd[-1]) or SimpleNamespace(
            returncode=1, stdout="Msg 3202: disk full", stderr=""))
    assert len(asked) == 1
