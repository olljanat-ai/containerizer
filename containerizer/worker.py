"""Scheduled organization scans: `python -m containerizer worker`.

Administrators define organization scans on the admin pages (admin_scans.py): which organization,
where the generated files and images go, and on which days and at what time (UTC) to run. The worker
is a separate, long-running process on a build machine with Docker. It

- queues a run when a scan is due (or an administrator pressed "Run full scan" or "Discover"), claims it, and runs
  `containerizer org` for it (org.run_org) with the repository list kept in SQL Server;
- keeps every repository's clone in its data folder and only fetches the newest commit on later runs;
- adds repositories the organization did not have before, marks the ones it no longer lists, records
  why a repository was skipped (it then shows as disabled, with the reason, on the admin pages) and
  honours what administrators enabled or disabled;
- reports progress and a heartbeat to the run, so the admin pages show it and a crashed worker's run is
  marked failed; and
- serves Prometheus metrics about the scans, itself and the machine (metrics.py).

Source control tokens are registered by administrators (Admin → Source control, credentials.py): a
read-only token per organization and a write token per output repository, sealed for this worker's
public key. The web UI can seal them but never open them; the worker opens them with its private key
(CONTAINERIZER_CREDENTIAL_KEY_FILE) at the start of a run. A scan whose organization has no
registered read-only token does not run (no anonymous access), the output repository's token is
picked by its URL and only used to push there, and each token is only sent with the URLs of its own
organization or repository. The registry's credentials stay with the worker as environment
variables, and images are only pushed to the providers' hosts and CONTAINERIZER_WORKER_HOSTS.

The worker also does what needs the internal rules repository's write token (rule review, rulereview.py):
it opens the pull request of each rule a reviewer approved on the admin pages (a thread of its own, so
approvals do not wait for a long scan), and before each run it fetches the approved rules for the scan.
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import sys
import threading
import time as _time
import urllib.parse
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
DEFAULT_HOSTS = {"api.github.com", "github.com", "gitlab.com", "dev.azure.com", "*.visualstudio.com"}
HEARTBEAT = 30              # seconds between heartbeats of a running run
STALE_MINUTES = 10          # a running run without a heartbeat for this long has lost its worker
APPROVAL_POLL = 15          # seconds between looks for rules a reviewer approved
ACTIVE = ("queued", "running")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def naive(d: datetime | None) -> datetime | None:
    """SQL Server datetime2 columns hold UTC without a zone."""
    return d.astimezone(timezone.utc).replace(tzinfo=None) if d else None


def aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d and d.tzinfo is None else d


# --------------------------------------------------------------------------- schedule

def next_run(days: int, minute: int, after: datetime) -> datetime | None:
    """The first scheduled time strictly after `after`: `days` is a bit mask (Mon=1 ... Sun=64), `minute`
    the minutes after midnight UTC. None when the scan only runs on demand."""
    if not days:
        return None
    after = aware(after).astimezone(timezone.utc)
    for d in range(8):
        day = (after + timedelta(days=d)).date()
        if days & (1 << day.weekday()):
            t = datetime.combine(day, time(minute // 60, minute % 60), tzinfo=timezone.utc)
            if t > after:
                return t
    return None


def schedule_text(days: int, minute: int) -> str:
    if not days:
        return "On demand only"
    at = f"at {minute // 60:02d}:{minute % 60:02d} UTC"
    if days == 127:
        return f"Every day {at}"
    if days == 31:
        return f"Mondays to Fridays {at}"
    return ", ".join(DAYS[i] for i in range(7) if days & (1 << i)) + f" {at}"


# --------------------------------------------------------------------------- configuration checks

def allowed_hosts(env=None) -> set[str]:
    env = os.environ if env is None else env
    extra = {h.strip().lower() for h in (env.get("CONTAINERIZER_WORKER_HOSTS") or "").split(",") if h.strip()}
    return DEFAULT_HOSTS | extra


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url if "://" in url else "https://" + url).hostname or "").lower()


def check_scan(scan: dict, hosts: set[str] | None = None, creds=None, key_id: str | None = None) -> list[str]:
    """What keeps a scan from running safely on this worker (empty when it can run). `creds`
    (credentials.Credentials) checks that the organization and the output repository have their
    registered tokens; `hosts` that the registry may receive the worker's registry credentials."""
    from .org import host_allowed
    from .orgsource import PROVIDERS
    problems = []
    if scan.get("Provider") not in PROVIDERS:
        problems.append(f"unknown provider {scan.get('Provider')!r}")
    if creds is not None:
        problems += creds.problems(scan, key_id)
    if hosts is not None:
        url = scan.get("Registry") if scan.get("PushImages") else None
        if url and not host_allowed(url, hosts | (creds.hosts() if creds is not None else set())):
            problems.append(f"registry host {_host(url)} is not allowed on this worker: add it to "
                            "CONTAINERIZER_WORKER_HOSTS")
    for k in ("IncludeRegex", "ExcludeRegex"):
        if scan.get(k):
            try:
                re.compile(scan[k])
            except re.error as ex:
                problems.append(f"{k}: {ex}")
    return problems


# --------------------------------------------------------------------------- repository list in SQL

def _cut(s, n: int):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def _parse_time(s: str) -> datetime | None:
    from .orgsource import parse_time
    return naive(parse_time(s)) if s else None


class SqlRepoStore:
    """org.run_org's view of the repository list in cz.OrgRepository (see OrgOptions.state)."""

    def __init__(self, conn, scan_id: int, run_id: int):
        self.conn, self.scan_id, self.run_id = conn, scan_id, run_id
        self.new: list[str] = []
        self.listed = 0
        self.projects = 0

    def sync_projects(self, listed) -> set[str]:
        """Add the projects the organization lists, mark the ones it no longer lists as removed. Returns
        the names of the projects an administrator disabled."""
        from .orgsource import NO_PROJECT
        cur = self.conn.cursor(as_dict=True)
        cur.execute("SELECT ProjectId, Name, AdminState, RemovedAt FROM cz.OrgProject WHERE ScanId = %s", (self.scan_id,))
        rows = {r["Name"]: r for r in cur.fetchall()}
        names = {_cut(r.project, 200) for r in listed if r.project != NO_PROJECT}
        c = self.conn.cursor()
        for n in sorted(names):
            if n in rows:
                c.execute("UPDATE cz.OrgProject SET LastSeenAt = SYSUTCDATETIME(), RemovedAt = NULL WHERE ProjectId = %s",
                          (rows[n]["ProjectId"],))
            else:
                c.execute("INSERT cz.OrgProject (ScanId, Name) VALUES (%s, %s)", (self.scan_id, n))
        gone = [r["ProjectId"] for n, r in rows.items() if n not in names and r["RemovedAt"] is None]
        for i in range(0, len(gone), 500):
            part = gone[i:i + 500]
            c.execute(f"UPDATE cz.OrgProject SET RemovedAt = SYSUTCDATETIME() WHERE ProjectId IN "
                      f"({', '.join(['%s'] * len(part))})", tuple(part))
        self.projects = len(names)
        return {n for n, r in rows.items() if n in names and r["AdminState"] == "disabled"}

    def sync(self, listed, names: dict) -> dict:
        """Add new projects and repositories, update the known ones (renames follow the provider's id),
        mark the ones no longer listed as removed. Returns key -> the administrator's decision for the
        listed ones: "enabled", "disabled", "project-disabled" (its project is disabled) or None."""
        from .sqlstore import clean_remote
        try:
            off = self.sync_projects(listed)
        except Exception:
            self.conn.rollback()
            raise
        cur = self.conn.cursor(as_dict=True)
        cur.execute("SELECT RepositoryId, ProjectName, Name, ExternalId, AdminState FROM cz.OrgRepository WHERE ScanId = %s",
                    (self.scan_id,))
        rows = cur.fetchall()
        by_name = {(r["ProjectName"], r["Name"]): r for r in rows}
        by_id = {r["ExternalId"]: r for r in rows if r["ExternalId"]}
        seen, admin = set(), {}
        c = self.conn.cursor()
        try:
            for r in listed:
                row = by_name.get((r.project, r.name)) or (by_id.get(r.id) if r.id else None)
                vals = (_cut(r.id or None, 100), _cut(r.clone_url, 400), _cut(r.web_url or None, 400),
                        _cut(clean_remote(r.clone_url), 400), _cut(r.default_branch or None, 200),
                        _cut(names.get(r.key), 63), naive(r.last_activity))
                if row and row["RepositoryId"] not in seen:
                    c.execute("UPDATE cz.OrgRepository SET ProjectName = %s, Name = %s, ExternalId = %s, CloneUrl = %s, "
                              "WebUrl = %s, RepositoryUrl = %s, DefaultBranch = %s, AppName = %s, LastActivityAt = %s, "
                              "LastSeenAt = SYSUTCDATETIME(), RemovedAt = NULL WHERE RepositoryId = %s",
                              (_cut(r.project, 200), _cut(r.name, 200), *vals, row["RepositoryId"]))
                    seen.add(row["RepositoryId"])
                    admin[r.key] = row["AdminState"]
                else:
                    c.execute("INSERT cz.OrgRepository (ScanId, ProjectName, Name, ExternalId, CloneUrl, WebUrl, RepositoryUrl, "
                              "DefaultBranch, AppName, LastActivityAt, FirstRunId) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                              (self.scan_id, _cut(r.project, 200), _cut(r.name, 200), *vals, self.run_id))
                    self.new.append(r.key)
                    admin[r.key] = None
            gone = [r["RepositoryId"] for r in rows if r["RepositoryId"] not in seen]
            for i in range(0, len(gone), 500):
                part = gone[i:i + 500]
                c.execute(f"UPDATE cz.OrgRepository SET RemovedAt = SYSUTCDATETIME() WHERE RemovedAt IS NULL AND "
                          f"RepositoryId IN ({', '.join(['%s'] * len(part))})", tuple(part))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        self.listed = len(listed)
        for r in listed:
            if _cut(r.project, 200) in off:
                admin[r.key] = "project-disabled"
        return admin

    def discovered(self, d) -> None:
        """What a discovery run learned about one repository: its latest commit, and the automatic skips
        the provider's API alone shows (archived, empty, fork, stale, filter). Skips that need the clone
        (Dockerfile, no application code) and the latest result of the full scan stay as they are."""
        from .org import META_SKIPS
        skip = d.skip if d.skip and d.skip[0] in META_SKIPS else (None, None)
        marks = ", ".join(["%s"] * len(META_SKIPS))
        cur = self.conn.cursor()
        cur.execute("UPDATE cz.OrgRepository SET LastCommitAt = COALESCE(%s, LastCommitAt), "
                    f"SkipStatus = CASE WHEN %s IS NOT NULL THEN %s WHEN SkipStatus IN ({marks}) THEN NULL ELSE SkipStatus END, "
                    f"SkipReason = CASE WHEN %s IS NOT NULL THEN %s WHEN SkipStatus IN ({marks}) THEN NULL ELSE SkipReason END "
                    "WHERE ScanId = %s AND ProjectName = %s AND Name = %s",
                    (naive(d.last_commit), skip[0], skip[0], *META_SKIPS, skip[0], _cut(skip[1], 1000), *META_SKIPS,
                     self.scan_id, _cut(d.repo.project, 200), _cut(d.repo.name, 200)))
        self.conn.commit()

    def record(self, r, res) -> None:
        """The outcome of one repository: last result, and the automatic skip (if any) that decides
        whether it shows as enabled. An administrator's decision is never changed here."""
        if res.status.startswith("skipped-"):
            skip = (res.status, res.reason)
        elif res.status in ("deployed", "no-a-components"):
            o = res.overridden[0] if res.overridden else None
            skip = (o["status"], o["reason"]) if o else (None, None)
        else:
            skip = None                     # disabled by an administrator, or an error: not re-evaluated
        detail = json.dumps({"app": res.app, "path": res.path, "components": res.components, "excluded": res.excluded,
                             "overridden": res.overridden, "lab_services": getattr(res, "lab_services", None) or {}},
                            default=str)
        sets = ("LastStatus = %s, LastReason = %s, LastCommit = COALESCE(%s, LastCommit), "
                "LastCommitAt = COALESCE(%s, LastCommitAt), LastRating = COALESCE(%s, LastRating), "
                "LastScannedAt = SYSUTCDATETIME(), LastRunId = %s, LastSeconds = %s, LastDetail = %s")
        params = [_cut(res.status, 40), _cut(res.reason or None, 1000), _cut(res.commit or None, 64),
                  _parse_time(res.last_commit), res.rating[:1] if res.rating else None, self.run_id,
                  float(res.seconds or 0), detail]
        if skip is not None:
            sets += ", SkipStatus = %s, SkipReason = %s"
            params += [_cut(skip[0], 40), _cut(skip[1], 1000)]
        cur = self.conn.cursor()
        cur.execute(f"UPDATE cz.OrgRepository SET {sets} WHERE ScanId = %s AND ProjectName = %s AND Name = %s",
                    (*params, self.scan_id, _cut(r.project, 200), _cut(r.name, 200)))
        self.conn.commit()


# --------------------------------------------------------------------------- metrics

class ScanMetrics:
    def __init__(self, paths: dict | None = None, worker: str = ""):
        from . import metrics as m
        r = self.registry = m.Registry()
        L = ("scan",)
        self.info = r.gauge("containerizer_worker_info", "The scan worker: name and tool version.", ("worker", "version"))
        self.poll = r.gauge("containerizer_worker_last_poll_timestamp_seconds", "When the worker last checked for due scans.")
        self.poll_errors = r.counter("containerizer_worker_poll_errors_total", "Failed checks for due scans (database errors).")
        self.busy = r.gauge("containerizer_worker_busy", "1 while the worker runs a scan.")
        self.runs = r.counter("containerizer_scan_runs_total", "Finished runs by result.", ("scan", "status"))
        self.running = r.gauge("containerizer_scan_running", "1 while a run of the scan is in progress.", L)
        self.started = r.gauge("containerizer_scan_last_start_timestamp_seconds", "Start of the latest run.", L)
        self.ended = r.gauge("containerizer_scan_last_end_timestamp_seconds", "End of the latest run.", L)
        self.success = r.gauge("containerizer_scan_last_success_timestamp_seconds", "End of the latest successful run.", L)
        self.duration = r.gauge("containerizer_scan_last_duration_seconds", "Duration of the latest run.", L)
        self.total = r.gauge("containerizer_scan_run_repositories", "Repositories to process in the current or latest run.", L)
        self.done = r.gauge("containerizer_scan_run_repositories_done", "Repositories processed so far in the current or latest run.", L)
        self.processed = r.counter("containerizer_scan_repositories_processed_total", "Repositories processed, by result.",
                                   ("scan", "status"))
        self.repo_seconds = r.histogram("containerizer_scan_repository_duration_seconds",
                                        "Time to process one repository (fetch, analyze, build, gate, push).", L,
                                        (5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200))
        self.new = r.counter("containerizer_scan_new_repositories_total", "Repositories found for the first time.", L)
        self.git_ops = r.counter("containerizer_scan_git_operations_total", "Clones and pulls, by result.",
                                 ("scan", "operation", "result"))
        self.git_seconds = r.counter("containerizer_scan_git_seconds_total", "Time spent cloning and pulling.",
                                     ("scan", "operation"))
        self.images = r.counter("containerizer_scan_images_pushed_total", "Component images pushed to the registry.", L)
        self.repos = r.gauge("containerizer_scan_repositories", "Repositories of the scan by state: enabled, "
                             "disabled_automatic (skipped, with a reason), disabled_admin, removed.", ("scan", "state"))
        self.last_status = r.gauge("containerizer_scan_repositories_last_status", "Repositories by their latest result.",
                                   ("scan", "status"))
        self.next = r.gauge("containerizer_scan_next_run_timestamp_seconds", "Next scheduled run.", L)
        self.queued = r.gauge("containerizer_scan_queued_runs", "Runs waiting for a worker.")
        self.scan_info = r.gauge("containerizer_scan_info", "Organization scans defined on the admin pages.",
                                 ("scan", "provider", "organization", "enabled"))
        from .sqlstore import tool_version
        self.info.set(1, worker=worker, version=tool_version() or "unknown")
        r.collectors += [m.process_metrics, lambda: m.host_metrics(paths)]

    def refresh(self, conn) -> None:
        """Gauges that come from the database: repository states, schedules, the queue."""
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT ScanId, Name, Provider, Organization, Enabled, NextRunAt FROM cz.OrgScan")
        scans = cur.fetchall()
        names = {s["ScanId"]: s["Name"] for s in scans}
        self.scan_info.replace({(s["Name"], s["Provider"], s["Organization"], "1" if s["Enabled"] else "0"): 1 for s in scans})
        self.next.replace({(s["Name"],): aware(s["NextRunAt"]).timestamp() for s in scans if s["NextRunAt"] and s["Enabled"]})
        state = """CASE WHEN RemovedAt IS NOT NULL THEN 'removed'
                        WHEN AdminState = N'disabled' OR ProjectState = N'disabled' THEN 'disabled_admin'
                        WHEN Enabled = 0 THEN 'disabled_automatic' ELSE 'enabled' END"""
        cur.execute(f"SELECT ScanId, {state} AS State, COUNT(*) AS N FROM cz.vOrgRepository GROUP BY ScanId, {state}")
        rows = {}
        for s in scans:
            for st in ("enabled", "disabled_automatic", "disabled_admin", "removed"):
                rows[(s["Name"], st)] = 0
        for r in cur.fetchall():
            if r["ScanId"] in names:
                rows[(names[r["ScanId"]], r["State"])] = r["N"]
        self.repos.replace(rows)
        cur.execute("SELECT ScanId, COALESCE(LastStatus, 'not scanned') AS S, COUNT(*) AS N FROM cz.OrgRepository "
                    "WHERE RemovedAt IS NULL GROUP BY ScanId, COALESCE(LastStatus, 'not scanned')")
        self.last_status.replace({(names[r["ScanId"]], r["S"]): r["N"] for r in cur.fetchall() if r["ScanId"] in names})
        cur.execute("SELECT COUNT(*) AS N FROM cz.OrgScanRun WHERE Status = N'queued'")
        self.queued.set(cur.fetchone()["N"])


class RunHooks:
    """Progress of one run into cz.OrgScanRun and the metrics (OrgOptions.hooks)."""

    def __init__(self, worker: "Worker", conn, run_id: int, scan: str, store: SqlRepoStore):
        self.w, self.conn, self.run_id, self.scan, self.store = worker, conn, run_id, scan, store
        self.counts = {"done": 0, "deployed": 0, "skipped": 0, "errors": 0}
        self.total = 0

    def _update(self, **cols) -> None:
        sets = ", ".join(f"{k} = %s" for k in cols)
        self.conn.cursor().execute(f"UPDATE cz.OrgScanRun SET {sets}, HeartbeatAt = SYSUTCDATETIME() WHERE RunId = %s",
                                   (*cols.values(), self.run_id))
        self.conn.commit()

    def start(self, total: int) -> None:
        self.total = total
        m = self.w.metrics
        m.total.set(total, scan=self.scan)
        m.done.set(0, scan=self.scan)
        if self.store.new:
            m.new.inc(len(self.store.new), scan=self.scan)
        self._update(ReposListed=self.store.listed, ReposTotal=total, ReposDone=0, ReposNew=len(self.store.new),
                     ReposDeployed=0, ReposSkipped=0, ReposErrors=0)

    def discovered(self, i: int, d) -> None:
        self.counts["done"] = i
        if d.skip:
            self.counts["skipped"] += 1
        if d.error:
            self.counts["errors"] += 1
        self.w.metrics.done.set(i, scan=self.scan)
        if i % 25 == 0 or i == self.total:          # many quick repositories: do not write a row for each
            self._update(ReposDone=i, ReposSkipped=self.counts["skipped"], ReposErrors=self.counts["errors"])

    def repo_start(self, i: int, r) -> None:
        self._update(CurrentRepo=_cut(f"{r.project}/{r.name}" if r.project != "_" else r.name, 400))

    def repo_done(self, i: int, r, res) -> None:
        c = self.counts
        c["done"] = i
        if res.status == "deployed":
            c["deployed"] += 1
        elif res.status.startswith("skipped-") or res.status == "disabled":
            c["skipped"] += 1
        elif res.status == "error":
            c["errors"] += 1
        m = self.w.metrics
        m.done.set(i, scan=self.scan)
        m.processed.inc(scan=self.scan, status=res.status)
        m.repo_seconds.observe(res.seconds or 0, scan=self.scan)
        pushed = sum(1 for x in res.components if x.get("digest"))
        if pushed:
            m.images.inc(pushed, scan=self.scan)
        self._update(ReposDone=i, ReposDeployed=c["deployed"], ReposSkipped=c["skipped"], ReposErrors=c["errors"])

    def git(self, op: str, seconds: float, ok: bool) -> None:
        m = self.w.metrics
        m.git_ops.inc(scan=self.scan, operation=op, result="ok" if ok else "failed")
        m.git_seconds.inc(seconds, scan=self.scan, operation=op)

    def should_stop(self) -> bool:
        return self.w.stopping.is_set() or self.w.cancel.is_set()


# --------------------------------------------------------------------------- the worker

class Worker:
    def __init__(self, connect, data_dir: str | Path, sql: str | None = None, poll: int = 30, name: str | None = None,
                 metrics: ScanMetrics | None = None, hosts: set[str] | None = None, log=None, key=None):
        self.connect = connect              # () -> sqlstore.Connection of a writer login
        self.key = key                      # X25519 private key that opens the registered tokens (None: from the env)
        self.sql = sql
        self.data = Path(data_dir).resolve()
        self.poll = poll
        self.name = (name or f"{socket.gethostname()}")[:256]
        self.hosts = allowed_hosts() if hosts is None else hosts
        self.metrics = metrics or ScanMetrics({"data": str(self.data)}, self.name)
        self.stopping = threading.Event()
        self.cancel = threading.Event()
        self.log = log or (lambda msg: print(f"worker: {msg}", file=sys.stderr, flush=True))

    # -- the loop ------------------------------------------------------------------------------

    def run_forever(self) -> None:
        self.data.mkdir(parents=True, exist_ok=True)
        os.chmod(self.data, 0o700)
        self.recover(own=True)
        threading.Thread(target=self.approvals_forever, name="rule-approvals", daemon=True).start()
        while not self.stopping.is_set():
            ran = False
            try:
                ran = self.tick()
            except Exception as ex:          # the database may be away for a while: keep trying
                self.metrics.poll_errors.inc()
                self.log(f"error: {type(ex).__name__}: {ex}")
            if not ran:
                self.stopping.wait(self.poll)

    def tick(self) -> bool:
        """One round: recover lost runs, queue due scans, run the oldest queued run. True if one ran."""
        self.recover()
        self.queue_due()
        conn = self.connect()
        try:
            self.metrics.refresh(conn)
        finally:
            conn.close()
        self.metrics.poll.set(_time.time())
        run = self.claim()
        if not run:
            return False
        self.execute(run)
        return True

    # -- rule review: approvals and the approved rules ---------------------------------------

    def approvals_forever(self) -> None:
        while not self.stopping.wait(APPROVAL_POLL):
            try:
                while self.approve_next() and not self.stopping.is_set():
                    pass
            except Exception as ex:          # the database may be away for a while: keep trying
                self.log(f"rule review: {type(ex).__name__}: {ex}")

    def approve_next(self) -> bool:
        """Open the pull request of the oldest rule a reviewer approved. False when none was waiting."""
        from . import rulereview as rr
        from .credentials import Credentials, CredentialError
        conn = self.connect()
        try:
            try:
                creds = self.credentials(conn)
            except CredentialError as ex:
                self.log(f"rule review: {ex}")
                creds = Credentials([])
            return rr.process_approval(conn, creds, self.data / "rule-review", log=self.log)
        finally:
            conn.close()

    def sync_reviewed_rules(self, conn, creds) -> None:
        """The approved rules for the scan: a fresh checkout of the internal rules repository, if one is set
        (CONTAINERIZER_REVIEWED_RULES of this process points at its rules folder)."""
        from . import rulereview as rr
        try:
            path = rr.sync_reviewed(conn, creds, self.data / "reviewed-rules", log=self.log)
        except Exception as ex:
            self.log(f"rule review: approved rules not updated: {type(ex).__name__}: {ex}")
            return
        if path is not None:
            os.environ["CONTAINERIZER_REVIEWED_RULES"] = str(path)
        elif str(self.data / "reviewed-rules") in os.environ.get("CONTAINERIZER_REVIEWED_RULES", ""):
            os.environ.pop("CONTAINERIZER_REVIEWED_RULES", None)

    def recover(self, own: bool = False) -> None:
        """Runs whose worker stopped: no heartbeat for STALE_MINUTES, or (at start) left running by this worker."""
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.OrgScanRun SET Status = CASE WHEN CancelRequested = 1 THEN N'cancelled' ELSE N'failed' END, "
                        "FinishedAt = SYSUTCDATETIME(), CurrentRepo = NULL, Message = %s "
                        "WHERE Status = N'running' AND (HeartbeatAt < DATEADD(minute, %s, SYSUTCDATETIME()) "
                        "OR (%s = 1 AND Worker = %s))",
                        ("the worker stopped during the run (no heartbeat); the next run continues with every repository",
                         -STALE_MINUTES, 1 if own else 0, self.name))
            if cur.rowcount:
                self.log(f"marked {cur.rowcount} run(s) without a worker as failed")
            conn.commit()
        finally:
            conn.close()

    def queue_due(self) -> None:
        now = utcnow()
        conn = self.connect()
        try:
            cur = conn.cursor(as_dict=True)
            cur.execute("SELECT ScanId, Name, ScheduleDays, ScheduleMinute, NextRunAt FROM cz.OrgScan WHERE Enabled = 1")
            for s in cur.fetchall():
                nxt = naive(next_run(s["ScheduleDays"], s["ScheduleMinute"], now))
                old = s["NextRunAt"]
                if old is not None and aware(old) <= now:
                    # due: whoever moves NextRunAt on (compare-and-set) queues the run
                    c = conn.cursor()
                    c.execute("UPDATE cz.OrgScan SET NextRunAt = %s WHERE ScanId = %s AND NextRunAt = %s",
                              (nxt, s["ScanId"], old))
                    conn.commit()
                    if c.rowcount == 1:
                        c.execute("EXEC cz.QueueOrgScanRun @ScanId = %s, @TriggeredBy = N'schedule'", (s["ScanId"],))
                        rid = c.fetchone()[0]
                        conn.commit()
                        self.log(f"{s['Name']}: scheduled run " + (f"#{rid} queued" if rid else "skipped, one is already "
                                                                    "queued or running"))
                elif old is None and nxt is not None or old is not None and nxt is None:
                    c = conn.cursor()
                    c.execute("UPDATE cz.OrgScan SET NextRunAt = %s WHERE ScanId = %s AND "
                              "(NextRunAt IS NULL OR NextRunAt = %s)", (nxt, s["ScanId"], old))
                    conn.commit()
        finally:
            conn.close()

    def claim(self) -> dict | None:
        conn = self.connect()
        try:
            cur = conn.cursor(as_dict=True)
            # one transaction: lock the oldest queued run (skipping ones another worker holds), then take it
            cur.execute("SELECT TOP (1) RunId, ScanId, TriggeredBy, RequestedBy, Kind, Scope FROM cz.OrgScanRun "
                        "WITH (UPDLOCK, READPAST, ROWLOCK) WHERE Status = N'queued' ORDER BY RunId")
            run = cur.fetchone()
            if run:
                cur.execute("UPDATE cz.OrgScanRun SET Status = N'running', Worker = %s, StartedAt = SYSUTCDATETIME(), "
                            "HeartbeatAt = SYSUTCDATETIME() WHERE RunId = %s AND Status = N'queued'",
                            (self.name, run["RunId"]))
                if cur.rowcount != 1:
                    run = None
            conn.commit()
            return run
        finally:
            conn.close()

    # -- one run -------------------------------------------------------------------------------

    def _heartbeat(self, run_id: int, done: threading.Event) -> None:
        while not done.wait(HEARTBEAT):
            try:
                conn = self.connect()
                try:
                    cur = conn.cursor()
                    cur.execute("UPDATE cz.OrgScanRun SET HeartbeatAt = SYSUTCDATETIME() WHERE RunId = %s", (run_id,))
                    cur.execute("SELECT CancelRequested FROM cz.OrgScanRun WHERE RunId = %s", (run_id,))
                    row = cur.fetchone()
                    conn.commit()
                finally:
                    conn.close()
                if row and row[0]:
                    self.cancel.set()
            except Exception as ex:
                self.log(f"heartbeat: {type(ex).__name__}: {ex}")

    def private_key(self):
        if self.key is None:
            from .credentials import private_key_from_env
            self.key = private_key_from_env()
        return self.key

    def credentials(self, conn):
        """The registered credentials, opened with this worker's key."""
        from .credentials import load
        return load(conn, self.private_key())

    def options(self, scan: dict, store, hooks, creds=None):
        from .org import OrgOptions
        base = self.data / f"scan-{int(scan['ScanId'])}"
        read = creds.read_for(scan["Provider"], scan["ApiUrl"], scan["Organization"]) if creds else None
        write = creds.write_for(scan["OutputRepo"]) if creds else None
        return OrgOptions(
            provider=scan["Provider"], org=scan["Organization"], registry=scan["Registry"], api_url=scan["ApiUrl"],
            token=(read.token or "") if read else "", output_repo=scan["OutputRepo"],
            output_dir=None if scan["OutputRepo"] else str(base / "output"), output_branch=scan["OutputBranch"],
            output_token=(write.token or "") if write else "",
            output_username=write.username if write else "x-access-token", push_images=bool(scan["PushImages"]),
            image_pull_secret=scan["ImagePullSecret"], include=scan["IncludeRegex"], exclude=scan["ExcludeRegex"],
            skip_forks=bool(scan["SkipForks"]), stale_days=int(scan["StaleDays"]), ai=bool(scan["UseAi"]),
            verify=bool(scan["Verify"]), gate=bool(scan["Gate"]), sql=self.sql, work_dir=str(base / "work"),
            cache_dir=str(base / "repos"), state=store, hooks=hooks,
            allowed_hosts=self.hosts | (creds.hosts() if creds else set()))

    def execute(self, run: dict) -> str:
        from .orgsource import REDACT, SourceError
        from .org import default_tag
        run_id = run["RunId"]
        conn = self.connect()
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT * FROM cz.OrgScan WHERE ScanId = %s", (run["ScanId"],))
        scan = cur.fetchone()
        name = scan["Name"]
        m = self.metrics
        self.cancel.clear()
        t0 = _time.time()
        m.busy.set(1)
        m.running.set(1, scan=name)
        m.started.set(t0, scan=name)
        done = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(run_id, done), daemon=True)
        beat.start()
        status, message = "failed", ""
        tag = default_tag(utcnow())
        store = SqlRepoStore(conn, scan["ScanId"], run_id)
        hooks = RunHooks(self, conn, run_id, name, store)
        discovery = run.get("Kind") == "discovery"
        self.log(f"{name}: {'discovery' if discovery else 'run'} #{run_id} started ({run['TriggeredBy']}"
                 + (f" by {run['RequestedBy']}" if run.get("RequestedBy") else "") + ")")
        read = write = None
        try:
            from .credentials import CredentialError
            try:
                creds = self.credentials(conn)
            except CredentialError as ex:
                raise SourceError(str(ex)) from None
            from .credentials import key_id
            problems = check_scan(scan, self.hosts, creds, key_id(self.private_key().public_key()))
            if problems:
                raise SourceError("; ".join(problems))
            read = creds.read_for(scan["Provider"], scan["ApiUrl"], scan["Organization"])
            if discovery:                   # only the organization's read-only token: nothing is pushed
                if read and read.token:
                    REDACT.add(read.token, read.username)
                status, message = self.discover(scan, store, hooks, creds, read, name)
                return status
            write = creds.write_for(scan["OutputRepo"])
            llm = creds.llm() if scan["UseAi"] else None
            for c in (read, write, llm):
                if c and c.token:
                    REDACT.add(c.token, c.username)
            self.sync_reviewed_rules(conn, creds)
            hooks._update(ImageTag=tag)
            o = self.options(scan, store, hooks, creds)
            o.tag = tag
            if run.get("Scope"):                # "Scan now" of chosen projects and repositories
                scope = json.loads(run["Scope"])
                o.only_projects = set(scope.get("projects") or [])
                o.only_repos = set(scope.get("repositories") or [])
            o.on_listed = lambda prov, n: self._listed(read, prov, n)
            (self.data / f"scan-{int(scan['ScanId'])}").mkdir(parents=True, exist_ok=True)
            from .org import run_org
            from .ai import configured
            if llm:
                o.model = llm.model
            # the registered LLM for this run only, never through os.environ (the scan's processes inherit it)
            with configured(llm.ai_settings() if llm else None):
                results = run_org(o, log=lambda msg: self.log(f"{name}: {msg}"))
            if write:
                self._mark(write, "ok: pushed the generated files" if o.push else "ok")
            c = hooks.counts
            stopped = len(results) < hooks.total
            if stopped:
                status = "cancelled"
                message = ("cancelled by an administrator" if self.cancel.is_set() else "the worker was stopped") + \
                    f" after {len(results)} of {hooks.total} repositories"
            else:
                status = "succeeded"
                message = (f"{hooks.total} repositories: {c['deployed']} deployed, {c['skipped']} skipped or disabled, "
                           f"{c['errors']} failed" + (f"; {len(store.new)} new" if store.new else ""))
        except SourceError as ex:
            message = REDACT(str(ex))
        except Exception as ex:
            message = REDACT(f"{type(ex).__name__}: {ex}")
        finally:
            if status == "failed" and read and ("HTTP 401" in message or "HTTP 403" in message):
                self._mark(read, f"failed: {message[:400]}")
            done.set()
            try:
                hooks._update(Status=status, FinishedAt=naive(utcnow()), CurrentRepo=None, Message=_cut(message, 2000))
            except Exception as ex:
                self.log(f"{name}: could not record the end of run #{run_id}: {type(ex).__name__}: {ex}")
            conn.close()
            end = _time.time()
            m.busy.set(0)
            m.running.set(0, scan=name)
            m.ended.set(end, scan=name)
            m.duration.set(round(end - t0, 1), scan=name)
            m.runs.inc(scan=name, status=status)
            if status == "succeeded":
                m.success.set(end, scan=name)
            self.log(f"{name}: run #{run_id} {status}: {message}")
        return status


    def discover(self, scan: dict, store, hooks, creds, read, name: str) -> tuple[str, str]:
        """A discovery run: projects, repositories and their latest commits, nothing cloned."""
        from .org import discover_org
        o = self.options(scan, store, hooks, creds)
        o.on_listed = lambda prov, n: self._listed(read, prov, n)
        found = discover_org(o, log=lambda msg: self.log(f"{name}: {msg}"))
        c = hooks.counts
        hooks._update(ReposDone=len(found), ReposSkipped=c["skipped"], ReposErrors=c["errors"])
        projects = f" in {store.projects} projects" if store.projects else ""
        if len(found) < hooks.total:
            return "cancelled", (("cancelled by an administrator" if self.cancel.is_set() else "the worker was stopped")
                                 + f" after {len(found)} of {hooks.total} repositories")
        return "succeeded", (f"discovery: {hooks.total} repositories{projects}"
                             + (f", {len(store.new)} new" if store.new else "")
                             + f"; {c['skipped']} would be skipped (archived, empty, fork, stale or filtered)"
                             + (f"; latest commit not available for {c['errors']}" if c["errors"] else "")
                             + "; nothing cloned")

    def _listed(self, cred, prov, n: int) -> None:
        """The organization's token worked: record it, with any sign that it can do more than read."""
        try:
            warnings = getattr(prov, "token_warnings", lambda: [])()
        except Exception:                       # best effort only
            warnings = []
        for w in warnings:
            self.log(f"warning: the read-only token for {cred.scope}: {w}")
        self._mark(cred, f"ok: {n} repositories listed" + "".join(f"; warning: {w}" for w in warnings))

    def _mark(self, cred, result: str) -> None:
        if not cred:
            return
        from .credentials import mark
        try:
            conn = self.connect()
            try:
                mark(conn, cred.id, result)
            finally:
                conn.close()
        except Exception as ex:                 # bookkeeping only
            self.log(f"could not record the use of credential {cred.id}: {type(ex).__name__}")


def build(args) -> int:
    """`containerizer worker` from the command line."""
    from . import metrics as mm
    from .sqlstore import SqlError, connect
    cs = args.sql or os.environ.get("CONTAINERIZER_SQL")
    try:
        connect(cs).close()
    except SqlError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 3
    data = Path(args.data_dir).resolve()
    paths = {"data": str(data)}
    if os.path.isdir("/var/lib/docker"):
        paths["docker"] = "/var/lib/docker"
    w = Worker(lambda: connect(cs), data, sql=cs, poll=args.poll, name=args.name,
               metrics=ScanMetrics(paths, (args.name or socket.gethostname())[:256]))
    data.mkdir(parents=True, exist_ok=True)
    if not args.no_metrics:
        token = os.environ.get("CONTAINERIZER_METRICS_TOKEN") or None
        mm.serve(w.metrics.registry, args.metrics_host, args.metrics_port, token)
        w.log(f"metrics on http://{args.metrics_host}:{args.metrics_port}/metrics"
              + (" (bearer token required)" if token else ""))

    def stop(signum, frame):
        w.log("stopping after the current repository")
        w.stopping.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if args.once:
        w.data.mkdir(parents=True, exist_ok=True)
        w.recover(own=True)
        while w.tick() and not w.stopping.is_set():
            pass
        return 0
    w.log(f"{w.name}: checking for due organization scans every {args.poll}s; data in {data}")
    w.run_forever()
    return 0
