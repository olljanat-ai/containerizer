"""Scheduled backups of the appliance (Admin -> System -> Scheduled backup; docs/appliance-admin.md#backup).

An administrator sets the schedule on the System page: on or off, the time of day (UTC), the days of the week and
how many days the archives are kept. The web UI only drops a request; the system agent (sysagent.py, root) checks it
again and keeps it in /var/lib/containerizer/system/backup.json. Every 5 minutes (`sysagent status`) the agent asks
`due()`; a due backup, or **Back up now**, starts `sysagent backup run` as the transient unit containerizer-backup, so
a long backup holds up nothing else and never runs twice at a time.

A backup is what the Backup section of the docs lists, in one archive on the persistent partition
(/var/lib/containerizer/backups/containerizer-<UTC time>.tgz, root only): a `BACKUP DATABASE` of the results database
(not with an external database: your SQL Server backs that up), /etc/containerizer with its secrets, the dev database
uploads, the appliance settings, the learned rules, Caddy's CA, and OpenBao and kubemg when they are there. Archives
older than the days to keep are deleted after a backup that worked; the newest one is always kept.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

SETTINGS = Path("/var/lib/containerizer/system/backup.json")
STATE = Path("/var/lib/containerizer/system/backup-state.json")
DEST = Path("/var/lib/containerizer/backups")
DB_BACKUP_DIR = Path("/var/lib/containerizer/mssql/backup")     # /var/opt/mssql/backup in the cz-mssql container
DB_BACKUP_FILE = "containerizer.bak"
MSSQL_UID = 10001
SA_SECRET = Path("/etc/containerizer/secrets/mssql-sa")
# what a rebuilt appliance needs (docs: Backup); missing ones are left out. Not: the built-in LLM's model file, the
# clones, images and sandbox data, which scans make again, nor the metrics
FOLDERS = ("etc/containerizer", "var/lib/containerizer/mssql/backup", "var/lib/containerizer/devdb",
           "var/lib/containerizer/system", "var/lib/containerizer/learned", "var/lib/caddy",
           "var/lib/containerizer/openbao", "var/lib/containerizer/kubemg")
NAME_RE = re.compile(r"containerizer-(\d{8}T\d{6}Z)\.tgz")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DEFAULTS = {"enabled": False, "time": "02:30", "days": list(DAYS), "keep_days": 7}
MAX_KEEP = 365
UNIT = "containerizer-backup"
STALE = timedelta(hours=12)           # a backup "running" this long without finishing is taken as cut off


class BackupError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(v) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _read(path: Path) -> dict:
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _write(path: Path, data: dict, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=1))
    os.chmod(tmp, mode)
    tmp.replace(path)


# ------------------------------------------------------------------ settings

def validate(req: dict) -> dict:
    """The schedule of a request from the web UI, checked again."""
    t = str(req.get("time") or "")
    m = re.fullmatch(r"([01]\d|2[0-3]):([0-5]\d)", t)
    if not m:
        raise BackupError(f"not a time of day (HH:MM): {t!r}")
    days = req.get("days")
    if not isinstance(days, list) or not days or any(d not in DAYS for d in days):
        raise BackupError("pick at least one day of the week")
    keep = req.get("keep_days")
    if not isinstance(keep, int) or isinstance(keep, bool) or not 1 <= keep <= MAX_KEEP:
        raise BackupError(f"days to keep: a number from 1 to {MAX_KEEP}")
    return {"enabled": bool(req.get("enabled")), "time": t, "days": [d for d in DAYS if d in days],
            "keep_days": keep}


def load_settings(path: Path | None = None) -> dict:
    d = _read(path or SETTINGS)
    try:
        return {**validate({**DEFAULTS, **d}), **{k: d[k] for k in ("changed_at", "changed_by", "changed_by_name")
                                                  if k in d}}
    except BackupError:
        return dict(DEFAULTS)


def save_settings(req: dict, user: str, name: str, path: Path | None = None) -> dict:
    s = validate(req)
    s.update(changed_at=_iso(_now()), changed_by=user[:256], changed_by_name=name[:256])
    _write(path or SETTINGS, s)
    return s


# ------------------------------------------------------------------ schedule

def last_slot(settings: dict, now: datetime) -> datetime | None:
    """The latest scheduled time at or before `now` (within the last 8 days)."""
    hh, mm = (int(x) for x in settings["time"].split(":"))
    for back in range(0, 8):
        day = (now - timedelta(days=back)).date()
        slot = datetime(day.year, day.month, day.day, hh, mm, tzinfo=timezone.utc)
        if slot <= now and DAYS[slot.weekday()] in settings["days"]:
            return slot
    return None


def next_slot(settings: dict, now: datetime) -> datetime | None:
    if not settings.get("enabled"):
        return None
    hh, mm = (int(x) for x in settings["time"].split(":"))
    for ahead in range(0, 8):
        day = (now + timedelta(days=ahead)).date()
        slot = datetime(day.year, day.month, day.day, hh, mm, tzinfo=timezone.utc)
        if slot > now and DAYS[slot.weekday()] in settings["days"]:
            return slot
    return None


def due(settings: dict, state: dict, now: datetime) -> bool:
    """A scheduled backup is due when the latest scheduled time has passed and no backup started since it (nor
    since the schedule was set: a new schedule does not make up for times before it). One that was missed while
    the appliance was off runs when it is back, within a day."""
    if not settings.get("enabled") or running(state, now):
        return False
    slot = last_slot(settings, now)
    if slot is None or now - slot > timedelta(days=1):
        return False
    since = [d for d in (_parse((state.get("last") or {}).get("started")), _parse(settings.get("changed_at"))) if d]
    return not since or slot > max(since)


def running(state: dict, now: datetime) -> bool:
    last = state.get("last") or {}
    started = _parse(last.get("started"))
    return bool(started and not last.get("finished") and now - started < STALE)


# ------------------------------------------------------------------ the backup

def archives(dest: Path | None = None) -> list[dict]:
    dest = dest or DEST
    out = []
    for p in sorted(dest.glob("containerizer-*.tgz")) if dest.is_dir() else []:
        m = NAME_RE.fullmatch(p.name)
        if not m:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({"name": p.name, "bytes": st.st_size,
                    "at": _iso(datetime.strptime(m[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc))})
    return sorted(out, key=lambda a: a["name"], reverse=True)


def prune(keep_days: int, now: datetime, dest: Path | None = None) -> list[str]:
    """Delete the archives older than `keep_days`, but never the newest one."""
    dest = dest or DEST
    gone = []
    for a in archives(dest)[1:]:
        if now - _parse(a["at"]) > timedelta(days=keep_days):
            (dest / a["name"]).unlink(missing_ok=True)
            gone.append(a["name"])
    return gone


def external_database(appliance_env: dict) -> bool:
    return bool((appliance_env.get("CZ_SQL_SERVER") or "").strip())


def backup_database(database: str, run=subprocess.run) -> None:
    """BACKUP DATABASE of the appliance's own SQL Server into its backup folder (bind-mounted from the host). The sa
    password goes in the environment of the exec, not on a command line. Compressed where the edition can (Developer,
    Standard, Enterprise); SQL Server Express cannot, and is backed up without."""
    DB_BACKUP_DIR.mkdir(mode=0o770, exist_ok=True)
    os.chown(DB_BACKUP_DIR, MSSQL_UID, 0)
    if not re.fullmatch(r"[A-Za-z_][\w$#@]{0,127}", database):
        raise BackupError(f"not a database name: {database!r}")
    env = dict(os.environ, SQLCMDPASSWORD=SA_SECRET.read_text().strip())

    def backup(options: str):
        sql = f"BACKUP DATABASE [{database}] TO DISK = N'/var/opt/mssql/backup/{DB_BACKUP_FILE}' WITH {options}"
        return run(["docker", "exec", "-e", "SQLCMDPASSWORD", "cz-mssql", "/opt/mssql-tools18/bin/sqlcmd", "-C", "-S",
                    "localhost", "-U", "sa", "-b", "-Q", sql], env=env, capture_output=True, text=True, timeout=3 * 3600)
    p = backup("COMPRESSION, INIT")
    if p.returncode != 0 and re.search(r"Msg 1844\b|COMPRESSION is not supported", (p.stdout or "") + (p.stderr or "")):
        # Express edition has no backup compression (Msg 1844): the archive the file goes into is gzip anyway
        p = backup("INIT")
    if p.returncode != 0:
        raise BackupError(f"BACKUP DATABASE failed: {(p.stdout + p.stderr).strip()[-600:]}")


def make_archive(now: datetime, root: Path = Path("/"), dest: Path | None = None) -> Path:
    dest = dest or DEST
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    target = dest / f"containerizer-{now.strftime('%Y%m%dT%H%M%SZ')}.tgz"
    part = target.with_name(f".{target.name}.part")
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w:gz") as tar:
            for rel in FOLDERS:
                if (root / rel).exists():
                    tar.add(str(root / rel), arcname=rel)
        part.replace(target)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return target


def run_backup(appliance_env: dict, settings: dict | None = None, state_path: Path | None = None, log=print,
               database=backup_database, archive=make_archive) -> dict:
    """One backup: the database (unless it is external), the archive, then the old archives pruned. The outcome is
    kept in backup-state.json for the System page."""
    settings = settings or load_settings()
    state_path = state_path or STATE
    state = _read(state_path)
    state.pop("error", None)
    started = _now()
    last = {"started": _iso(started), "requested_by": (state.get("last") or {}).get("requested_by")}
    state["last"] = last
    _write(state_path, state)
    t0 = time.monotonic()
    try:
        if external_database(appliance_env):
            last["database"] = "external: back it up with your SQL Server"
        else:
            database(appliance_env.get("CZ_SQL_DATABASE") or "Containerizer")
            last["database"] = "included"
        path = archive(started)
        (DB_BACKUP_DIR / DB_BACKUP_FILE).unlink(missing_ok=True)   # it is in the archive now
        last.update(ok=True, file=path.name, bytes=path.stat().st_size)
        last["pruned"] = prune(int(settings.get("keep_days") or DEFAULTS["keep_days"]), started, path.parent)
        log(f"backup: {path} ({last['bytes']:,} bytes)" + (f", deleted {len(last['pruned'])} old" if last["pruned"] else ""))
    except (BackupError, OSError, subprocess.SubprocessError, tarfile.TarError) as ex:
        last.update(ok=False, message=str(ex)[-1000:])
        log(f"backup failed: {ex}")
    last.update(finished=_iso(_now()), seconds=round(time.monotonic() - t0, 1))
    _write(state_path, state)
    return last


def status(now: datetime | None = None) -> dict:
    """What the System page shows: the schedule, the next time, the last backup and the archives."""
    now = now or _now()
    s = load_settings()
    state = _read(STATE)
    nxt = next_slot(s, now)
    return {"settings": s, "next": _iso(nxt) if nxt else None, "last": state.get("last"),
            "running": running(state, now), "archives": archives(), "folder": str(DEST),
            **({"error": state["error"]} if state.get("error") else {})}


def mark_requested(user: str, name: str, state_path: Path | None = None) -> None:
    state_path = state_path or STATE
    state = _read(state_path)
    state["requested"] = {"by": user[:256], "by_name": name[:256], "at": _iso(_now())}
    _write(state_path, state)


def clear_error(state_path: Path | None = None) -> None:
    """A request that worked: the error of an earlier one goes."""
    state_path = state_path or STATE
    state = _read(state_path)
    if state.pop("error", None) is not None:
        _write(state_path, state)
