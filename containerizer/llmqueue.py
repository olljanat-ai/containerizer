"""The LLM queue: LLM jobs that do not hold up the scans (docs/source-control.md#queued-llm-reviews).

A self-hosted LLM on CPUs can take minutes per answer. The queue (cz.LlmJob) holds LLM jobs of any kind,
and its runner (`containerizer llm-queue`, a process of its own) works through them when the settings let
it (Admin → LLM queue: paused, days and hours in UTC, only when the machine is idle, parallel requests,
jobs at once). A job takes an LLM request only while one of its LLM calls is answered (Slots), so jobs that build,
verify or deploy do not hold an LLM.

Job kinds (JOB_KINDS, `register`): `review`, a component review, `refactor`, a refactoring patch a
person ordered for a B-rated application (refactor.py, docs/refactoring.md), and `egress`, the review of the
connections the sandbox blocked for an A-rated application (egress.py, docs/egress.md). A scan with queued LLM reviews
(OrgScan.LlmMode 'queued', `--ai-queue` on the command line) asks the LLM nothing while it runs: the rules
decide, and the component reviews the LLM would have been asked are queued with a priority instead
(queue_reviews):

- *uncertain* components (server or platform tier, confidence below 0.85: the components an inline scan
  asks about) come first;
- components the rules rate *blocker* or *rewrite* with confidence follow at low priority, as a *second
  opinion*;
- every other component of an application or component an administrator put in an *LLM-heavy window*
  (cz.LlmHeavyWindow, Admin -> Applications) is reviewed too (reason `heavy`). Until the window ends, every job
  of it needs no approval and goes before all other jobs (cz.fnLlmJobHeavy, HEAVY_FIRST).

A review job keeps the exact question (prompt) and its answer cache key in its payload. The runner asks
the stored question through ai.ask_json with the same model, so the answer lands in the answer cache under
the same key. The next scan of the repository asks the same question, finds the answer (in the cache, or
in the queue) and applies it like an inline answer. Assessments stay insert-only: nothing stored is
changed; "Re-scan now" on the queue page scans a repository whose reviews are all answered.

Adding a kind: write `handler(job) -> {"result": dict, "summary": str, "note": str | None}`, call
`register("refactor", "Refactoring", handler)`, add the kind to CK_LlmJob_Kind in schema.sql, and queue jobs
with JobQueue.add({"Kind": "refactor", "Priority": ..., "DedupeKey": ..., "Payload": {...}, ...}). The
runner, the queue page (order, skip, requeue, the kind filter) and the metrics (label `kind`) need nothing
else.

Without SQL Server the command line keeps the queue in a JSON file (FileJobQueue), which
`containerizer llm-queue --file` works through.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import signal
import socket
import sys
import threading
import time as _time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from . import restartplan

REASONS = ("uncertain", "second-opinion", "heavy")          # why a component review is queued
REASON_TEXT = {"uncertain": "Uncertain", "second-opinion": "Second opinion", "heavy": "LLM-heavy"}
STATUSES = ("queued", "running", "answered", "failed", "skipped")
PENDING = ("queued", "running")
FEATURE = "assessment-queued"           # LLM usage feature of the reviews the runner asks
DRAINED_EXIT = 75                       # drained for an app update (SIGUSR1): systemd restarts it with the new code
MAX_ATTEMPTS = 3                        # a job that failed this often stays failed (requeue on the page)
RETRY_MINUTES = 5                       # wait before the next attempt: this times the attempts so far
HEARTBEAT = 30                          # seconds between heartbeats of the running jobs
CANCEL_CHECK = 5                        # seconds between looks for Cancel on the running jobs
STALE_MINUTES = 10                      # a running job without a heartbeat for this long lost its runner
SECOND_OPINION = ("blocker", "rewrite")
# How sure the LLM must be to change the verdict: as inline for uncertain components; a second opinion
# goes against rules that were sure, so it must be as sure as they were.
OVERRIDE_CONFIDENCE = {"uncertain": 0.6, "second-opinion": 0.85, "heavy": 0.85}
HEAVY_CACHE = 60                        # seconds a scan keeps the LLM-heavy windows it read (SqlJobQueue.heavy)
DEFAULTS = {"Paused": False, "WindowDays": 0, "WindowStart": None, "WindowEnd": None, "OnlyWhenIdle": True,
            "MaxLoadPerCpu": 0.5, "Parallel": 1, "ApproveKinds": "egress,link,refactor,review", "ApproveMinTokens": 0,
            "ApproveMaxQueued": 0, "RejectAfterHours": 0, "LocalOrder": None, "LocalMaxTokens": 0, "JobsAtOnce": 0}
JOBS_AT_ONCE_MAX = 32                   # LlmQueueSettings.JobsAtOnce (0: automatic, jobs_at_once)
RESERVE_SECONDS = 120                   # a job just started keeps an LLM request for its first call this long at most


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- token estimates

CHARS_PER_TOKEN = 3.5                   # before anything is learned: code-heavy English, roughly 3 to 4 characters a token
OUTPUT_TOKENS = 1500                    # before anything is learned: answer length of a job
ALPHA = 0.2                             # weight of the newest answer in every learned figure (EWMA)
ENDPOINT_ROW = "*"                      # LlmSpeed.Kind of an endpoint's own figures (the others: per job kind)


def estimate_tokens(text: str, chars_per_token: float = CHARS_PER_TOKEN) -> int:
    """A rough token count of text sent to the LLM: its length over `chars_per_token`. No tokenizer is
    asked (the scan that queues a job must not depend on the LLM server); the queue page recomputes it
    with the characters per token learned from the endpoint's real counts (Estimator)."""
    return int(-(-len(text or "") // chars_per_token)) if text else 0


def ewma(old: float | None, new: float, alpha: float = ALPHA) -> float:
    """Exponentially weighted moving average: the first observation as is, then `alpha` of each new one."""
    return float(new) if old is None else float(old) + alpha * (float(new) - float(old))


def observe(endpoint_row: dict | None, kind_row: dict | None, chars: int | None, input_tokens: int | None,
            output_tokens: int | None, seconds: float, prompt_seconds: float | None = None,
            generate_seconds: float | None = None, parallel: int = 1,
            prompt_read: int | None = None) -> tuple[dict, dict]:
    """What one answered job teaches, folded into the endpoint's figures (characters per input token, prompt
    and generation speed, or overall tokens per second when the server reports no timings) and its kind's
    (output tokens). Rows are LlmSpeed columns; returns the new (endpoint row, kind row). Speeds are as
    observed with `parallel` jobs sharing the server."""
    e, k = dict(endpoint_row or {}), dict(kind_row or {})
    tin, tout = int(input_tokens or 0), int(output_tokens or 0)
    if chars and tin:
        e["CharsPerToken"] = ewma(e.get("CharsPerToken"), chars / tin)
    if prompt_seconds and generate_seconds and tin and tout:
        e["PromptTokensPerSecond"] = ewma(e.get("PromptTokensPerSecond"), (prompt_read or tin) / prompt_seconds)
        e["GenTokensPerSecond"] = ewma(e.get("GenTokensPerSecond"), tout / generate_seconds)
    if seconds and (tin or tout):
        e["TokensPerSecond"] = ewma(e.get("TokensPerSecond"), (tin + tout) / seconds)
    if tout:
        k["OutputTokens"] = ewma(k.get("OutputTokens"), tout)
    for r in (e, k):
        r["Samples"] = int(r.get("Samples") or 0) + 1
        r["Parallel"] = parallel
    return e, k


class Estimator:
    """Token and time estimates of queued jobs from the learned figures (cz.LlmSpeed rows): the figures of the
    endpoint that serves the job's model (newest first), else the newest of any endpoint, else the defaults."""

    def __init__(self, rows: list[dict]):
        newest = sorted(rows, key=lambda r: str(r.get("UpdatedAt") or ""), reverse=True)
        self.endpoints = [r for r in newest if r.get("Kind") == ENDPOINT_ROW]
        self.kinds = [r for r in newest if r.get("Kind") != ENDPOINT_ROW]

    def endpoint(self, model: str | None) -> dict | None:
        return next((r for r in self.endpoints if model and r.get("Model") == model), None) or \
            (self.endpoints[0] if self.endpoints else None)

    def output(self, kind: str, endpoint: dict | None) -> float:
        ep = endpoint.get("Endpoint") if endpoint else None
        r = next((r for r in self.kinds if r["Kind"] == kind and r["Endpoint"] == ep), None) or \
            next((r for r in self.kinds if r["Kind"] == kind), None)
        return float(r["OutputTokens"]) if r and r.get("OutputTokens") else OUTPUT_TOKENS

    def job(self, job: dict) -> dict:
        """{"in", "out" (tokens), "seconds" (None: no speed learned yet), "basis" (the endpoint's row or None)}."""
        ep = self.endpoint(job.get("Model"))
        cpt = float(ep["CharsPerToken"]) if ep and ep.get("CharsPerToken") else CHARS_PER_TOKEN
        tin = round(job["InputChars"] / cpt) if job.get("InputChars") else int(job.get("EstInputTokens") or 0)
        tout = round(self.output(job.get("Kind") or "", ep))
        secs = None
        if ep and ep.get("PromptTokensPerSecond") and ep.get("GenTokensPerSecond"):
            secs = tin / float(ep["PromptTokensPerSecond"]) + tout / float(ep["GenTokensPerSecond"])
        elif ep and ep.get("TokensPerSecond"):
            secs = (tin + tout) / float(ep["TokensPerSecond"])
        return {"in": tin, "out": tout, "seconds": secs, "basis": ep}

    def queue(self, jobs: list[dict], parallel: int = 1) -> dict:
        """Totals of the queued jobs: tokens, and the time at the learned speed. Each job's time was learned as
        observed with the parallelism of its day, so the sum over `parallel` slots is an approximation; waiting
        for the window or for the machine to be idle is not included. seconds None: not learned yet."""
        est = [self.job(j) for j in jobs]
        known = [x["seconds"] for x in est if x["seconds"] is not None]
        return {"jobs": len(est), "in": sum(x["in"] for x in est), "out": sum(x["out"] for x in est),
                "seconds": sum(known) / max(1, int(parallel or 1)) if est and len(known) == len(est) else None,
                "basis": next((x["basis"] for x in est if x["basis"]), None)}


def load_speed(conn) -> Estimator:
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT * FROM cz.LlmSpeed")
        return Estimator(cur.fetchall())
    except Exception:                       # a database from before the queue
        try:
            conn.rollback()
        except Exception:
            pass
        return Estimator([])


SPEED_COLS = ("Model", "CharsPerToken", "PromptTokensPerSecond", "GenTokensPerSecond", "TokensPerSecond", "OutputTokens",
              "Parallel", "Samples")


def save_speed(conn, endpoint: str, model: str, kind: str, obs: dict) -> None:
    """Fold one answered job into cz.LlmSpeed (rows of the endpoint and of the job's kind)."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT * FROM cz.LlmSpeed WITH (UPDLOCK, HOLDLOCK) WHERE Endpoint = %s AND Kind IN (%s, %s)",
                (endpoint, ENDPOINT_ROW, kind))
    rows = {r["Kind"]: r for r in cur.fetchall()}
    e, k = observe(rows.get(ENDPOINT_ROW), rows.get(kind), **obs)
    for kd, r in ((ENDPOINT_ROW, e), (kind, k)):
        vals = [model if c == "Model" else r.get(c) for c in SPEED_COLS]
        if kd in rows:
            cur.execute("UPDATE cz.LlmSpeed SET " + ", ".join(f"{c} = %s" for c in SPEED_COLS)
                        + ", UpdatedAt = SYSUTCDATETIME() WHERE Endpoint = %s AND Kind = %s", (*vals, endpoint, kd))
        else:
            cur.execute(f"INSERT cz.LlmSpeed (Endpoint, Kind, {', '.join(SPEED_COLS)}) VALUES "
                        f"(%s, %s, {', '.join(['%s'] * len(SPEED_COLS))})", (endpoint, kd, *vals))
    conn.commit()


def duration_long(seconds: float) -> str:
    """"7 h 20 min", "45 min", "under a minute"."""
    m = round(seconds / 60)
    if m < 1:
        return "under a minute"
    h, m = divmod(m, 60)
    return f"{h} h {m} min" if h and m else f"{h} h" if h else f"{m} min"


def next_open(settings: dict, now: datetime) -> datetime | None:
    """When the window next lets the runner start (now, if it is open; None when paused or never). Only the
    days and hours: whether a scan runs or the machine is busy then is not known in advance."""
    from datetime import timedelta
    s = {**DEFAULTS, **(settings or {})}
    if s["Paused"]:
        return None
    t = (now if now.tzinfo else now.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).replace(second=0, microsecond=0)
    for i in range(8 * 24 * 60):
        x = t + timedelta(minutes=i)
        if window_open(int(s["WindowDays"] or 0), s["WindowStart"], s["WindowEnd"], x):
            return x
    return None


def duration_text(seconds: float | None) -> str:
    if seconds is None:
        return "time: learning"
    if seconds < 90:
        return f"~{max(1, round(seconds))} s"
    if seconds < 5400:
        return f"~{round(seconds / 60)} min"
    return f"~{seconds / 3600:.1f} h"


# --------------------------------------------------------------------------- job kinds

class JobKind:
    """A kind of LLM job: `handler(job) -> {"result": dict, "summary": str, "note": str | None}`.

    `job` is the queue row (cz.LlmJob columns, or a FileJobQueue entry) with "Payload" parsed from JSON:
    whatever the side that queued it put there. The handler asks the LLM (ai.ask_json; the runner sets the
    usage scope with the kind's feature and the repository) and returns the result (stored as JSON in
    Result), a one-line summary for the queue page (at most 400 characters) and an optional note. An
    exception is a failed attempt: tried again after RETRY_MINUTES x attempts, failed after MAX_ATTEMPTS."""

    def __init__(self, name: str, title: str, handler, feature: str):
        self.name, self.title, self.handler, self.feature = name, title, handler, feature


JOB_KINDS: dict[str, JobKind] = {}


def register(name: str, title: str, handler, feature: str | None = None) -> JobKind:
    """Add a job kind (the kind must also be in CK_LlmJob_Kind of schema.sql)."""
    JOB_KINDS[name] = k = JobKind(name, title, handler, feature or f"{name}-queued")
    return k


def kind_title(name: str) -> str:
    return JOB_KINDS[name].title if name in JOB_KINDS else name


def review_handler(job: dict) -> dict:
    """A component review: the stored question asked again with the same model, so the answer lands in the
    answer cache under the key the next scan looks up."""
    from . import ai
    pl = job["Payload"]
    model = pl.get("model") or None
    data = ai.ask_json(pl["prompt"], ai.REVIEW_SCHEMA, model=model, feature=FEATURE, max_tokens=ai.SHORT_ANSWER_TOKENS)
    note = None
    try:            # the key of the LLM that answered (the queue runner picks one per call)
        if (ai.last_cache_key() or ai.cache_key(pl["prompt"], ai.REVIEW_SCHEMA, model)) != pl.get("cache_key"):
            note = ("the LLM settings changed since it was queued: the next scan asks again, unless it finds "
                    "this answer in the queue")
    except Exception:
        pass
    return {"result": data, "note": note,
            "summary": f"{data.get('verdict')} ({float(data.get('confidence') or 0):.2f})"}


REVIEW = "review"
register(REVIEW, "Component review", review_handler, FEATURE)
REFACTOR = "refactor"


def refactor_handler(job: dict) -> dict:
    """A refactoring patch (refactor.handler; imported when a job runs)."""
    from .refactor import handler
    return handler(job)


register(REFACTOR, "Refactoring", refactor_handler, "refactor-queued")
EGRESS = "egress"


def egress_handler(job: dict) -> dict:
    """An egress review of the blocked connections of an application in the sandbox (egress.handler)."""
    from .egress import handler
    return handler(job)


register(EGRESS, "Egress review", egress_handler, "egress-queued")
LINK = "link"


def link_handler(job: dict) -> dict:
    """A link review: the component of another application an internal-looking destination is (links.handler)."""
    from .links import handler
    return handler(job)


register(LINK, "Link review", link_handler, "link-queued")


# --------------------------------------------------------------------------- component reviews: what, how urgent

def review_kind(c, threshold: float = 0.85) -> str | None:
    """Why a component review is queued: 'uncertain' (what an inline scan asks the LLM about),
    'second-opinion' (a confident blocker or rewrite verdict of the rules), or None (not queued)."""
    if c.tier not in ("server", "platform"):
        return None
    if c.confidence < threshold:
        return "uncertain"
    if c.rule_verdict in SECOND_OPINION:
        return "second-opinion"
    return None


def a_candidate(c) -> bool:
    """A server component that only its verdict keeps from rating A: it keeps no state of its own, so a
    verdict of info or config would deploy it to the sandbox."""
    return c.tier == "server" and c.stateless and c.verdict not in ("info", "config")


def heavy_covers(heavy, path: str | None) -> bool:
    """Whether an LLM-heavy window (SqlJobQueue.heavy: None, ALL or a set of ProjectPaths) covers a component."""
    return heavy is ALL or (bool(heavy) and path in heavy)


def priority(c, reason: str) -> int:
    """The queue order of a component review (higher first), as docs/source-control.md#queued-llm-reviews
    describes:

        uncertain:      1000 + 400 x (1 - confidence) + 300 if an A candidate + 100 if a server component
        second opinion:    0 + the same

    Uncertain reviews (1000 to 1720) always come before second opinions (0 to 720); within a reason, the
    less sure the rules, the sooner, and an answer that may let a component be deployed comes first."""
    p = (1000 if reason == "uncertain" else 0) + round(400 * (1 - min(max(float(c.confidence), 0.0), 1.0)))
    if a_candidate(c):
        p += 300
    if c.tier == "server":
        p += 100
    return p


def _source_key(a) -> str:
    from .sqlstore import source_info
    try:
        return source_info(a.repo.root, a.name)["key"]
    except Exception:                       # no git: the app name, as the results database does
        return a.name


def queue_reviews(a, queue, model: str | None = None, threshold: float = 0.85, learn: bool = False,
                  enqueue: bool = True) -> list[dict]:
    """assess.apply_ai in queued mode: never asks the LLM. For each component to review, an answer to its
    exact question (the answer cache, else the queue) applies at once; otherwise the question is queued
    (when `enqueue`) and c.ai says so. Returns the answers applied."""
    from . import ai
    from .assess import apply_review
    applied, key_of_app, heavy = [], None, None
    for c in a.components:
        reason = review_kind(c, threshold)
        if reason is None and enqueue and hasattr(queue, "heavy"):
            if heavy is None:
                key_of_app = key_of_app or _source_key(a)
                try:
                    heavy = queue.heavy(key_of_app) or set()
                except Exception as e:  # noqa: BLE001 - the queue's database may be away
                    print(f"warning: LLM-heavy windows not read: {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
                    heavy = set()
            if heavy_covers(heavy, c.project.rel):
                reason = "heavy"            # an administrator's LLM-heavy window: every component is reviewed
        if reason is None:
            continue
        try:
            prompt = ai.review_prompt(a, c)
            key = ai.cache_key(prompt, ai.REVIEW_SCHEMA, model)
            used = ai.model_name(model)
        except Exception as e:  # noqa: BLE001 - e.g. a self-hosted server without a model set
            c.ai = {"error": str(e)}
            continue
        r = ai.cached_answer(prompt, ai.REVIEW_SCHEMA, model, feature="assessment")
        if r is None:
            try:
                r = queue.result(REVIEW, key)
            except Exception as e:  # noqa: BLE001 - the queue's database may be away: the rules decide
                print(f"warning: LLM queue not read: {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
            if r is not None:
                ai.store_answer(key, r)
        if r is not None:
            r = {**r, "model": r.get("model") or used}
            apply_review(c, r, OVERRIDE_CONFIDENCE[reason])
            c.ai.update({"queue": "answered", "reason": reason})
            if learn:
                ai.learn_from_review(a, c, r)
            applied.append(r)
            continue
        p = priority(c, reason)
        c.ai = {"queue": "queued" if enqueue else "not asked", "reason": reason, "priority": p}
        if not enqueue:
            continue
        key_of_app = key_of_app or _source_key(a)
        job = {"Kind": REVIEW, "Reason": reason, "App": a.name, "SourceKey": key_of_app, "Component": c.name,
               "ProjectPath": c.project.rel, "RuleVerdict": c.rule_verdict, "Confidence": round(float(c.confidence), 2),
               "Priority": p, "DedupeKey": key, "Model": used,
               "InputChars": len(ai.SYSTEM + prompt + json.dumps(ai.REVIEW_SCHEMA)),
               "Payload": {"prompt": prompt, "model": used, "cache_key": key, "uncertain": list(c.uncertain)}}
        try:
            queue.add(job)
        except Exception as e:  # noqa: BLE001
            c.ai = {"error": f"not queued: {type(e).__name__}: {str(e)[:200]}", "reason": reason}
            print(f"warning: LLM review of {a.name}/{c.name} not queued: {type(e).__name__}: {str(e)[:200]}",
                  file=sys.stderr)
    return applied


# --------------------------------------------------------------------------- where the queue is kept

ALL = frozenset({"*"})                  # an LLM-heavy window of the whole application (SqlJobQueue.heavy)

# the queue order: jobs in an LLM-heavy window first (cz.fnLlmJobHeavy as h), then by position or priority
HEAVY_APPLY = "OUTER APPLY cz.fnLlmJobHeavy(j.ApplicationId, j.SourceKey, j.ProjectPath) h"
HEAVY_FIRST = "CASE WHEN h.WindowId IS NULL THEN 1 ELSE 0 END, COALESCE(j.AdminRank, CAST(j.Priority AS float)) DESC, j.JobId"


class JobQueue:
    """Where jobs are queued; a scan in queued mode binds it to one repository with `for_repo`."""

    def __init__(self, scan_id: int | None = None, scan_name: str | None = None, requested_by: str | None = None):
        self.scan_id, self.scan_name = scan_id, scan_name
        self.requested_by = requested_by or (f"scan {scan_name}" if scan_name else "command line")
        self.project = self.repo = self.label = None

    def for_repo(self, project: str, name: str, label: str | None = None) -> "JobQueue":
        q = copy.copy(self)
        q.project, q.repo, q.label = project, name, label or name
        return q

    def _job(self, job: dict) -> dict:
        """The job with the columns it does not set (and the estimated input tokens from InputChars: the
        characters of everything sent to the LLM)."""
        j = {"ScanId": self.scan_id, "ProjectName": self.project, "RepoName": self.repo,
                "Repository": self.label or job.get("App"), "RequestedBy": self.requested_by, "Reason": None,
                "App": None, "SourceKey": None, "Component": None, "ProjectPath": None, "RuleVerdict": None,
                "Confidence": None, "Model": None, "ApplicationId": None, "AssessmentId": None,
                "InputChars": len(json.dumps(job.get("Payload") or {})), **job}
        j["EstInputTokens"] = estimate_tokens("x" * int(j["InputChars"] or 0))
        return j

    def add(self, job: dict) -> int:
        """Queue a job (Kind, Priority, DedupeKey, Payload, and what it is about); 0 when one of the same
        kind and DedupeKey is already waiting."""
        raise NotImplementedError

    def result(self, kind: str, dedupe_key: str) -> dict | None:
        """The result of the latest answered job of this kind and DedupeKey, when the queue has one."""
        raise NotImplementedError


def heavy_windows(conn) -> dict[str, list[str]]:
    """The LLM-heavy windows open now (cz.vLlmHeavyActive) by Application.SourceKey: ["*"] for the whole
    application, else the ProjectPaths of its components in one (plain data: a scan's options go to the processes
    of its repositories)."""
    cur = conn.cursor()
    cur.execute("SELECT SourceKey, ProjectPath FROM cz.vLlmHeavyActive")
    by: dict[str, list[str]] = {}
    for key, path in cur.fetchall():
        paths = by.setdefault(key, [])
        if "*" in paths:
            continue
        if path is None:
            by[key] = ["*"]
        elif path not in paths:
            paths.append(path)
    return by


def _cut(s, n: int):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


class SqlJobQueue(JobQueue):
    """cz.LlmJob in the results database (cz.QueueLlmJob dedupes by kind and DedupeKey)."""

    def __init__(self, connect, scan_id: int | None = None, scan_name: str | None = None,
                 requested_by: str | None = None):
        super().__init__(scan_id, scan_name, requested_by)
        self.connect = connect              # () -> sqlstore.Connection of a writer (or admin) login

    def add(self, job: dict) -> int:
        conn = self.connect()
        try:
            return self.add_with(conn, job)
        finally:
            conn.close()

    def add_with(self, conn, job: dict) -> int:
        """Queue on an open connection (the admin pages': RequestedBy None is the signed-in person)."""
        j = self._job(job)
        cur = conn.cursor()
        cur.execute("EXEC cz.QueueLlmJob @Kind = %s, @Reason = %s, @ScanId = %s, @ProjectName = %s, @RepoName = %s, "
                    "@Repository = %s, @App = %s, @SourceKey = %s, @ApplicationId = %s, @AssessmentId = %s, "
                    "@Component = %s, @ProjectPath = %s, @RuleVerdict = %s, @Confidence = %s, @Priority = %s, "
                    "@DedupeKey = %s, @Model = %s, @RequestedBy = %s, @InputChars = %s, @EstInputTokens = %s, "
                    "@Payload = %s",
                    (j["Kind"], j["Reason"], j["ScanId"], _cut(j["ProjectName"], 200), _cut(j["RepoName"], 200),
                     _cut(j["Repository"], 400), _cut(j["App"], 200), _cut(j["SourceKey"], 400),
                     j["ApplicationId"], j["AssessmentId"], _cut(j["Component"], 200), _cut(j["ProjectPath"], 400),
                     j["RuleVerdict"], j["Confidence"], int(j["Priority"]), j["DedupeKey"], _cut(j["Model"], 200),
                     _cut(j["RequestedBy"], 256), j["InputChars"], j["EstInputTokens"], json.dumps(j["Payload"])))
        rid = cur.fetchone()[0]
        conn.commit()
        return int(rid or 0)

    def heavy(self, source_key: str):
        """The LLM-heavy windows of an application now (cz.vLlmHeavyActive, read again after HEAVY_CACHE seconds):
        None (none), ALL (the whole application) or the ProjectPaths of its components in one."""
        now = _time.monotonic()
        cache = self.__dict__.setdefault("_heavy", {})
        if cache.get("at") is None or now - cache["at"] > HEAVY_CACHE:
            conn = self.connect()
            try:
                by = heavy_windows(conn)
            finally:
                conn.close()
            cache.update(at=now, by=by)
        found = cache["by"].get(source_key)
        return None if found is None else ALL if "*" in found else set(found)

    def result(self, kind: str, dedupe_key: str) -> dict | None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT TOP (1) Result FROM cz.LlmJob WHERE Kind = %s AND DedupeKey = %s AND Status = N'answered' "
                        "AND Result IS NOT NULL ORDER BY FinishedAt DESC, JobId DESC", (kind, dedupe_key))
            row = cur.fetchone()
            return json.loads(row[0]) if row else None
        finally:
            conn.close()


class FileJobQueue(JobQueue):
    """The queue in a JSON file, for the command line without SQL Server (`containerizer llm-queue --file`)."""

    def __init__(self, path: str | Path):
        super().__init__()
        self.path = Path(path)

    def load(self) -> list[dict]:
        try:
            return json.loads(self.path.read_text()).get("jobs", [])
        except FileNotFoundError:
            return []

    def save(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"jobs": items}, indent=1, default=str) + "\n")
        tmp.replace(self.path)

    def add(self, job: dict) -> int:
        items = self.load()
        j = self._job(job)
        if any(x["Kind"] == j["Kind"] and x["DedupeKey"] == j["DedupeKey"] and x["Status"] in PENDING for x in items):
            return 0
        now = utcnow().isoformat(timespec="seconds")
        if j["ProjectPath"]:
            for x in items:          # superseded: the component's code or the rules changed since
                if x["Status"] == "queued" and x["Kind"] == j["Kind"] and x.get("SourceKey") == j["SourceKey"] \
                        and x.get("ProjectPath") == j["ProjectPath"]:
                    x.update(Status="skipped", Note="superseded by a newer scan", FinishedAt=now)
        rid = max((x["JobId"] for x in items), default=0) + 1
        items.append({"JobId": rid, **j, "Status": "queued", "AdminRank": None, "Attempts": 0, "QueuedAt": now})
        self.save(items)
        return rid

    def result(self, kind: str, dedupe_key: str) -> dict | None:
        done = [x for x in self.load() if x["Kind"] == kind and x["DedupeKey"] == dedupe_key
                and x["Status"] == "answered" and x.get("Result")]
        return done[-1]["Result"] if done else None


# --------------------------------------------------------------------------- order

STEP = 1e-6
ACTIONS = ("top", "up", "down", "bottom")


def effective(r: dict) -> float:
    """The queue order of a job: an administrator's position if set, else its computed priority."""
    return float(r["AdminRank"]) if r.get("AdminRank") is not None else float(r["Priority"])


def ordered(rows: list[dict]) -> list[dict]:
    """Queued jobs in the order the runner takes them (as HEAVY_FIRST in Runner.claim): those in an LLM-heavy
    window (HeavyUntil) first."""
    return sorted(rows, key=lambda r: (r.get("HeavyUntil") is None, -effective(r), r["JobId"]))


def reorder(rows: list[dict], job_id: int, action: str) -> dict[int, float]:
    """An administrator moves a queued job: top, up (one place), down (one place) or bottom, among all
    queued jobs of every kind. Returns the new AdminRank of each job that changes. Jobs with equal values
    are first spread apart (by less than one priority point, in their current order), so that up and down
    move exactly one place. New jobs still go in by their priority."""
    if action not in ACTIONS:
        raise ValueError(action)
    rows = ordered(rows)
    ids = [r["JobId"] for r in rows]
    i = ids.index(job_id)
    if (i == 0 and action in ("top", "up")) or (i == len(rows) - 1 and action in ("bottom", "down")):
        return {}
    vals, prev = [], float("inf")
    for r in rows:
        v = effective(r)
        if v >= prev:
            v = prev - STEP
        vals.append(v)
        prev = v
    if action == "top" and i > 0:
        vals[i] = vals[0] + 1
    elif action == "bottom" and i < len(rows) - 1:
        vals[i] = vals[-1] - 1
    elif action == "up" and i > 0:
        vals[i], vals[i - 1] = vals[i - 1], vals[i]
    elif action == "down" and i < len(rows) - 1:
        vals[i], vals[i + 1] = vals[i + 1], vals[i]
    return {r["JobId"]: v for r, v in zip(rows, vals) if v != effective(r)}


# --------------------------------------------------------------------------- when the queue may run

def window_open(days: int, start: int | None, end: int | None, now: datetime) -> bool:
    """Whether `now` (UTC) is inside the window: `days` a bit mask (Mon=1 ... Sun=64; 0: every day), `start`
    and `end` minutes after midnight UTC (None, or equal: all day). A window that ends before it starts
    wraps midnight, and the hours after midnight belong to the day it started: Mon 22:00-06:00 includes
    Tuesday 03:00, not Monday 03:00."""
    now = (now if now.tzinfo else now.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    minute, wd = now.hour * 60 + now.minute, now.weekday()

    def day(d: int) -> bool:
        return not days or bool(days & (1 << d))
    if start is None or end is None or start == end:
        return day(wd)
    if start < end:
        return day(wd) and start <= minute < end
    if minute >= start:
        return day(wd)
    return minute < end and day((wd - 1) % 7)


def load_per_cpu() -> float:
    """The 1-minute load average per CPU."""
    try:
        return os.getloadavg()[0] / (os.cpu_count() or 1)
    except OSError:
        return 0.0


def gate(settings: dict, now: datetime, scans_running: int, load: float, hold: str | None = None) -> tuple[bool, str]:
    """(may start a job now, why not). `hold`: why a planned restart of the appliance holds new work."""
    s = {**DEFAULTS, **(settings or {})}
    if hold:
        return False, hold
    if s["Paused"]:
        return False, "paused"
    if not window_open(int(s["WindowDays"] or 0), s["WindowStart"], s["WindowEnd"], now):
        return False, "outside the hours set for it"
    if s["OnlyWhenIdle"]:
        if scans_running:
            return False, "waiting for the running scan to finish"
        limit = float(s["MaxLoadPerCpu"] or 0)
        if limit > 0 and load > limit:
            return False, f"the machine is busy (load {load:.2f} per CPU, limit {limit:.2f})"
    return True, ""


def _hhmm(m) -> str:
    return f"{int(m) // 60:02d}:{int(m) % 60:02d}"


def settings_text(settings: dict) -> str:
    """E.g. "Mondays to Fridays 22:00-06:00 UTC, only when idle (...), 1 request at a time"."""
    from .worker import DAYS
    s = {**DEFAULTS, **(settings or {})}
    if s["Paused"]:
        return "Paused"
    days = int(s["WindowDays"] or 0)
    when = "every day" if days in (0, 127) else "Mondays to Fridays" if days == 31 else \
        ", ".join(DAYS[i] for i in range(7) if days & (1 << i))
    hours = ", all day" if s["WindowStart"] is None or s["WindowEnd"] is None or s["WindowStart"] == s["WindowEnd"] \
        else f" {_hhmm(s['WindowStart'])}-{_hhmm(s['WindowEnd'])} UTC"
    idle = f", only when idle (no scan running, load below {float(s['MaxLoadPerCpu'] or 0):.2f} per CPU)" \
        if s["OnlyWhenIdle"] else ""
    n = int(s["Parallel"] or 1)
    return f"{when[:1].upper()}{when[1:]}{hours}{idle}, {n} request{'s' if n != 1 else ''} at a time"


def load_settings(conn) -> dict:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT * FROM cz.LlmQueueSettings WHERE SettingsId = 1")
    row = cur.fetchone()
    return {**DEFAULTS, **{k: row[k] for k in DEFAULTS if k in row}} if row else dict(DEFAULTS)


def _exec_count(conn, proc: str) -> int:
    try:
        cur = conn.cursor()
        cur.execute(f"EXEC cz.{proc}")
        row = cur.fetchone()
        conn.commit()
        return int(row[0]) if row else 0
    except Exception as ex:  # noqa: BLE001 - an older schema, or a database that is away: nothing changes
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        print(f"warning: {proc}: {type(ex).__name__}: {str(ex)[:200]}", file=sys.stderr)
        return 0


def auto_reject(conn) -> int:
    """Reject the jobs that waited longer than the settings allow (cz.AutoRejectLlmJobs). Returns how many."""
    return _exec_count(conn, "AutoRejectLlmJobs")


def auto_approve(conn) -> int:
    """Approve the waiting jobs the approval rules let start by themselves (cz.AutoApproveLlmJobs): kinds that need
    no approval, and jobs under the size limit while the queue has room. Returns how many."""
    return _exec_count(conn, "AutoApproveLlmJobs")


def apply_rules(conn) -> tuple[int, int]:
    """The queue's rules, in order: reject what waited too long, then approve what the rules let start.
    Returns (approved, rejected)."""
    rejected = auto_reject(conn)
    return auto_approve(conn), rejected


def scans_running(conn) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cz.OrgScanRun WHERE Status = N'running'")
    return int(cur.fetchone()[0])


# --------------------------------------------------------------------------- metrics

class QueueGauges:
    """The queue's state from SQL: jobs by status, kind and reason, the oldest waiting one."""

    def __init__(self, r):
        self.items = r.gauge("containerizer_llm_queue_jobs", "LLM queue jobs by status (queued, running, answered, "
                             "failed, skipped), kind (review, ...) and reason (reviews: uncertain, second-opinion).",
                             ("status", "kind", "reason"))
        self.oldest = r.gauge("containerizer_llm_queue_oldest_waiting_seconds", "Age of the oldest queued job, by kind.",
                              ("kind",))
        self.tokens = r.gauge("containerizer_llm_queue_estimated_tokens", "Estimated tokens of the queued jobs: in "
                              "(from their prompts) and out (the average answer of the kind so far).",
                              ("kind", "direction"))
        self.seconds = r.gauge("containerizer_llm_queue_estimated_seconds", "Estimated LLM time of all queued jobs at "
                               "the learned speed and the parallel requests set (waiting for the hours or an idle "
                               "machine not included); absent until a speed has been learned.")

    def refresh(self, conn) -> None:
        try:
            cur = conn.cursor(as_dict=True)
            cur.execute("SELECT Status, Kind, COALESCE(Reason, N'') AS Reason, COUNT(*) AS N FROM cz.LlmJob "
                        "GROUP BY Status, Kind, COALESCE(Reason, N'')")
            rows = {(st, REVIEW, r): 0 for st in STATUSES for r in REASONS}
            for r in cur.fetchall():
                rows[(r["Status"], r["Kind"], r["Reason"])] = r["N"]
            cur.execute("SELECT Kind, DATEDIFF(second, MIN(QueuedAt), SYSUTCDATETIME()) AS Age FROM cz.LlmJob "
                        "WHERE Status = N'queued' GROUP BY Kind")
            ages = {(r["Kind"],): float(r["Age"] or 0) for r in cur.fetchall()}
            cur.execute("SELECT Kind, Model, InputChars, EstInputTokens FROM cz.LlmJob WHERE Status = N'queued'")
            waiting = cur.fetchall()
            speed = load_speed(conn)
            parallel = int(load_settings(conn)["Parallel"] or 1)
        except Exception:                   # a database from before the queue (schema version 19)
            try:
                conn.rollback()
            except Exception:
                pass
            return
        self.items.replace(rows)
        self.oldest.replace({**{(k,): 0.0 for k in JOB_KINDS}, **ages})
        est = {(k, d): 0 for k in JOB_KINDS for d in ("in", "out")}
        for r in waiting:
            x = speed.job(r)
            est[(r["Kind"], "in")] = est.get((r["Kind"], "in"), 0) + x["in"]
            est[(r["Kind"], "out")] = est.get((r["Kind"], "out"), 0) + x["out"]
        self.tokens.replace(est)
        tot = speed.queue(waiting, parallel)
        self.seconds.replace({(): tot["seconds"]} if tot["seconds"] is not None else {})


class QueueMetrics:
    def __init__(self, runner: str = ""):
        from . import metrics as m
        from .ai import LISTENERS
        from .sqlstore import tool_version
        from .worker import LlmUsage
        r = self.registry = m.Registry()
        self.info = r.gauge("containerizer_llm_queue_runner_info", "The LLM queue runner: name and tool version.",
                            ("runner", "version"))
        self.poll = r.gauge("containerizer_llm_queue_last_poll_timestamp_seconds", "When the runner last looked at the queue.")
        self.poll_errors = r.counter("containerizer_llm_queue_poll_errors_total", "Failed looks at the queue (database errors).")
        self.open = r.gauge("containerizer_llm_queue_open", "1 when the queue settings let the runner start a job now.")
        self.paused = r.gauge("containerizer_llm_queue_paused", "1 when an administrator paused the queue.")
        self.active = r.gauge("containerizer_llm_queue_active_jobs", "Jobs the runner works on now: asking an LLM, "
                              "waiting for one, or building, verifying or deploying (at most the jobs at once set).")
        self.llm_jobs = r.gauge("containerizer_llm_queue_llm_jobs", "LLM requests in progress now (one per job asking), "
                                "by LLM in the order: llm-<id> a registered LLM, built-in-<n> a server of the built-in "
                                "LLM (one per NUMA node).", ("llm", "label"))
        self.llm_waiting = r.gauge("containerizer_llm_queue_llm_waiting", "LLM calls of running jobs waiting for a free "
                                   "request of an LLM that takes their size.")
        self.jobs = r.counter("containerizer_llm_queue_jobs_finished_total", "Jobs the runner finished, by kind and "
                              "result: answered, failed (no attempts left) or retried (tried again later).",
                              ("kind", "result"))
        self.seconds = r.histogram("containerizer_llm_queue_job_duration_seconds", "Time to answer one job.",
                                   ("kind",), (10, 30, 60, 120, 300, 600, 900, 1800, 3600))
        self.queue = QueueGauges(r)
        self.usage = LlmUsage(r)
        LISTENERS.append(self.llm)
        self.info.set(1, runner=runner, version=tool_version() or "unknown")
        r.collectors += [m.process_metrics]      # the machine: the scan worker exports it (same instance label)

    def llm(self, u: dict) -> None:
        self.usage.record(u)


# --------------------------------------------------------------------------- the runner

def _payload(row: dict) -> dict:
    pl = row.get("Payload")
    return json.loads(pl) if isinstance(pl, str) else (pl or {})


class _usage:
    """`with _usage() as u:` the LLM calls this thread makes inside it (ai.record_usage); u.tokens() sums
    the tokens of the ones really answered (a cached answer cost nothing now)."""

    def __enter__(self):
        from .ai import LISTENERS
        self.thread, self.entries = threading.get_ident(), []
        self.fn = lambda u: self.entries.append(u) if threading.get_ident() == self.thread else None
        LISTENERS.append(self.fn)
        return self

    def __exit__(self, *exc):
        from .ai import LISTENERS
        LISTENERS.remove(self.fn)

    def tokens(self) -> tuple[int | None, int | None]:
        done = [u for u in self.entries if not u.get("cached") and not u.get("error")]
        if not done:
            return None, None
        return sum(int(u.get("input_tokens") or 0) for u in done), sum(int(u.get("output_tokens") or 0) for u in done)

    def timings(self) -> tuple[float | None, float | None]:
        """Prompt and generation seconds when the server reported them for every answered call."""
        done = [u for u in self.entries if not u.get("cached") and not u.get("error")]
        if not done or not all(u.get("prompt_seconds") and u.get("generate_seconds") for u in done):
            return None, None
        return sum(float(u["prompt_seconds"]) for u in done), sum(float(u["generate_seconds"]) for u in done)

    def prompt_read(self) -> int | None:
        """The prompt tokens the server really read (llama.cpp reuses a cached prefix: its prompt time covers only
        the rest), when it said so for every answered call."""
        done = [u for u in self.entries if not u.get("cached") and not u.get("error")]
        if not done or not all(u.get("prompt_read_tokens") is not None for u in done):
            return None
        return sum(int(u["prompt_read_tokens"]) for u in done)

    def partly_cached(self) -> bool:
        return any(u.get("cached") for u in self.entries)


def plan_lanes(registered: list, builtin: list | None, settings: dict) -> list[dict]:
    """The LLMs the queue runner asks at once, in their order: each registered LLM (credentials.Credential, key
    opened) with its biggest LLM call (LlmMaxTokens, estimated input tokens of one call; 0: any) and requests at once
    (LlmParallel); each server of the appliance's built-in LLM (local_llm.server_lanes: one per NUMA node) as an LLM
    of its own, one request at once (alone: Parallel shared out), beside them when it has a place in the order
    (LocalOrder, LocalMaxTokens) or alone when none is registered; a server still loading its model takes no call yet;
    else the environment's LLM (settings None) with Parallel. Each LLM call of a job goes to the first lane with a
    free request that takes its size (Slots); a job starts when one with a spare request takes its estimate."""
    s = {**DEFAULTS, **(settings or {})}
    lanes = [{"name": f"llm-{c.id}", "label": c.label, "settings": c.ai_settings(), "max_tokens": int(c.llm_max_tokens or 0),
              "parallel": max(1, int(c.llm_parallel or 1)), "order": int(c.llm_order)} for c in registered]
    builtin = builtin or []
    if builtin and (not lanes or s.get("LocalOrder") is not None):
        alone = not lanes
        each = max(1, -(-int(s["Parallel"] or 1) // len(builtin))) if alone else 1
        for sv in builtin:
            where = (f", server {int(sv['index'])}" + (f" (NUMA node {int(sv['node'])})" if sv.get("node") is not None else "")
                     if len(builtin) > 1 else "")
            lanes.append({"name": f"built-in-{int(sv['index'])}",
                          "label": f"built-in LLM ({sv['settings'].get('CONTAINERIZER_MODEL')}){where}"
                                   + ("" if sv.get("ready") else ", loading its model"),
                          "settings": sv["settings"], "max_tokens": 0 if alone else int(s.get("LocalMaxTokens") or 0),
                          "parallel": each if sv.get("ready") else 0, "order": 0 if alone else int(s["LocalOrder"])})
    if not lanes:
        lanes.append({"name": "environment", "label": "the worker's own LLM settings", "settings": None,
                      "max_tokens": 0, "parallel": max(1, int(s["Parallel"] or 1)), "order": 0})
    return sorted(lanes, key=lambda ln: (ln["order"], not ln["name"].startswith("built-in"), ln["name"]))


def jobs_at_once(settings: dict, lanes: list[dict]) -> int:
    """How many jobs the runner works on at once (LlmQueueSettings.JobsAtOnce): the number set, or with 0 (automatic)
    every LLM request at once of the LLMs in the order plus one, so that a job building or verifying does not keep
    another from asking while an LLM is free. Builds are heavy on CPU and memory, and compete with a CPU-only
    built-in LLM: the automatic number stays modest."""
    n = int((settings or {}).get("JobsAtOnce") or 0)
    if n > 0:
        return min(n, JOBS_AT_ONCE_MAX)
    return min(JOBS_AT_ONCE_MAX, max(1, sum(max(0, int(ln["parallel"])) for ln in lanes)) + 1)


def call_tokens(chars: int) -> int:
    """The estimated input tokens of one LLM call of `chars` characters (as a job's EstInputTokens)."""
    return int(-(-int(chars or 0) // CHARS_PER_TOKEN)) if chars else 0


class Slots:
    """The LLM request slots of the runner: each LLM in the order (a lane of plan_lanes) answers `parallel` requests
    at once. A job's LLM call takes one for the call only (Runner via ai.llm_slots), not the job for its lifetime: a
    job that builds, verifies or deploys holds none. A call goes to the first LLM in the order that takes its size
    (max_tokens per call; 0: any) and has a free request; a call bigger than every limit goes to the LLM(s) with the
    biggest. Calls that wait are served in the order their jobs started (the queue's order); a call that only a busy
    LLM takes does not hold up a later one that a free LLM takes."""

    def __init__(self, on_change=None):
        self.cond = threading.Condition()
        self.lanes: list[dict] = []
        self.busy: dict[str, int] = {}          # lane name -> requests in progress
        self.waiting: list[list] = []           # [order, tokens] of the calls waiting, oldest job first
        self.on_change = on_change or (lambda: None)

    def update(self, lanes: list[dict]) -> None:
        with self.cond:
            self.lanes = list(lanes)
            self.cond.notify_all()

    def candidates(self, tokens: int, lanes: list[dict] | None = None) -> list[dict]:
        """The LLMs that take a call of `tokens`, in their order (those with a request at all)."""
        ls = [ln for ln in (self.lanes if lanes is None else lanes) if int(ln["parallel"]) > 0]
        fit = [ln for ln in ls if not ln["max_tokens"] or tokens <= int(ln["max_tokens"])]
        if fit or not ls:
            return fit
        top = max(int(ln["max_tokens"]) for ln in ls)
        return [ln for ln in ls if int(ln["max_tokens"]) == top]

    def _free(self) -> dict[str, int]:
        return {ln["name"]: int(ln["parallel"]) - self.busy.get(ln["name"], 0) for ln in self.lanes}

    def _assign(self, free: dict[str, int]) -> dict[int, dict]:
        """Which waiting call gets which free request now (id of the waiter -> lane); `free` is what is left."""
        out = {}
        for w in self.waiting:
            for ln in self.candidates(w[1]):
                if free.get(ln["name"], 0) > 0:
                    free[ln["name"]] -= 1
                    out[id(w)] = ln
                    break
        return out

    def spare(self, reserved: list[int] = ()) -> dict[str, int]:
        """The requests of each LLM that no waiting call and no job just started (`reserved`: their estimated
        tokens, each keeping a request of the first LLM that takes it) will take: room for another job."""
        with self.cond:
            free = self._free()
            self._assign(free)
            for tokens in reserved:
                for ln in self.candidates(tokens):
                    if free.get(ln["name"], 0) > 0:
                        free[ln["name"]] -= 1
                        break
            return free

    def in_progress(self) -> dict[str, int]:
        with self.cond:
            return dict(self.busy)

    def waiting_calls(self) -> int:
        with self.cond:
            return len(self.waiting)

    def acquire(self, order, tokens: int, check=None, on_wait=None) -> dict:
        """Wait for a request of an LLM that takes a call of `tokens` (`order`: the job's place, oldest first) and
        take it. `check()` raises to give up (Cancel, the runner stopping); `on_wait()` once when the call waits."""
        w = [order, int(tokens or 0)]
        with self.cond:
            self.waiting.append(w)
            self.waiting.sort(key=lambda x: x[0])
        told = False
        try:
            while True:
                with self.cond:
                    lane = self._assign(self._free()).get(id(w))
                    if lane is not None:
                        self.busy[lane["name"]] = self.busy.get(lane["name"], 0) + 1
                        break
                    if told:
                        self.cond.wait(1.0)
                if not told:
                    told = True
                    if on_wait:
                        on_wait()
                if check:
                    check()
        finally:
            with self.cond:
                self.waiting.remove(w)
                self.cond.notify_all()
        self.on_change()
        return lane

    def release(self, lane: dict) -> None:
        with self.cond:
            self.busy[lane["name"]] = max(0, self.busy.get(lane["name"], 0) - 1)
            self.cond.notify_all()
        self.on_change()


class _JobCalls:
    """The LLM calls of one job (ai.llm_slots in its thread): each takes a request slot for the call only, and is
    recorded (row["_calls"]: the LLM, its endpoint, the requests at once on it, the call's size, time and usage) for
    the speed statistics and the job's Endpoint and Parallel. While a call waits or asks, the job's row says so
    (CallState, CallLlm, CallSince) for the queue page."""

    def __init__(self, runner: "Runner", row: dict):
        self.runner, self.row = runner, row

    def choices(self, chars: int) -> list:
        return [ln.get("settings") for ln in self.runner.slots.candidates(call_tokens(chars))]

    @contextlib.contextmanager
    def take(self, chars: int):
        from . import ai
        r, row = self.runner, self.row

        def check():
            if r.stopping.is_set():
                raise ai.Cancelled("the queue runner is stopping")
            ai._raise_if_cancelled()
        lane = r.slots.acquire(row.get("_order", row["JobId"]), call_tokens(chars), check,
                               on_wait=lambda: r.call_state(row, "waiting"))
        row.pop("_reserve_until", None)
        try:
            parallel = r.slots.in_progress().get(lane["name"], 1)
            settings = lane.get("settings")
            try:
                with ai.configured(settings, local=True) if settings else contextlib.nullcontext():
                    ep = ai.endpoint(None if settings else row.get("Model"))
            except Exception:  # noqa: BLE001
                ep = None
            r.call_state(row, "asking", lane.get("label") or lane["name"])
            t0 = _time.monotonic()
            with _usage() as used:
                try:
                    yield settings
                finally:
                    row.setdefault("_calls", []).append(
                        {"lane": lane["name"], "endpoint": ep, "parallel": parallel, "chars": int(chars),
                         "seconds": _time.monotonic() - t0, "entries": list(used.entries)})
        finally:
            r.slots.release(lane)
            r.call_state(row, None)


class Runner:
    """`containerizer llm-queue`: works through cz.LlmJob when the settings let it."""

    def __init__(self, connect, name: str | None = None, poll: int = 30, metrics: QueueMetrics | None = None,
                 log=None, key=None, load=load_per_cpu, kinds=None):
        self.connect = connect              # () -> sqlstore.Connection of a writer login
        # the job kinds this runner takes (default: all); housekeeping follows them (variants: refactor, egress)
        self.kinds = [k for k in (kinds or JOB_KINDS) if k in JOB_KINDS]
        self.name = (name or f"{socket.gethostname()}-llm-queue")[:256]
        self.poll = poll
        self.metrics = metrics or QueueMetrics(self.name)
        self.log = log or (lambda msg: print(f"llm-queue: {msg}", file=sys.stderr, flush=True))
        self.key = key                      # X25519 private key that opens the LLM credential (None: from the env)
        self.load = load
        self.stopping = threading.Event()
        self.draining = threading.Event()   # an app update (SIGUSR1): no new job; leave when the running ones are done
        self.active: dict[int, dict] = {}   # JobId -> row of a job being worked on
        self.cancelling: dict[int, str] = {}  # JobId -> who pressed Cancel (cz.LlmJob.CancelRequestedBy)
        self.lock = threading.Lock()
        self._ctx = None                    # ai.configured() of the jobs being worked on
        self.wake = threading.Event()       # a job finished or an LLM request came free: look at the queue again
        self.slots = Slots(self._slots_changed)  # the LLM requests: taken per call (_JobCalls), not per job
        self._order = 0                     # the jobs in the order they started: their calls wait in this order
        self._call_state = True             # False: a database from before schema 41 (no CallState)
        self.status = None
        self._housekept = None              # when expired or removed sandbox variants were last looked for

    # -- the LLM ---------------------------------------------------------------------------------

    def llm_settings(self, conn) -> dict | None:
        """The LLM a scan would use (credentials.llm_for_run): the one registered under Admin → Source control &
        LLM, opened with the worker's credential key, else the appliance's built-in LLM while it is on and
        healthy, else None: the environment's settings."""
        from .credentials import CredentialError, PRIVATE_KEY_ENV, llm_for_run, load, private_key_from_env
        from .orgsource import REDACT
        llm = None
        try:
            if self.key is None and os.environ.get(PRIVATE_KEY_ENV):
                self.key = private_key_from_env()
            if self.key is not None:
                llm = load(conn, self.key).llm()
        except CredentialError as ex:
            self.log(f"the registered LLM cannot be opened ({ex}); using the built-in or the environment's LLM")
        if llm is not None and llm.token:
            REDACT.add(llm.token, llm.username)
        return llm_for_run(llm).settings

    # -- the queue -------------------------------------------------------------------------------

    def recover(self, own: bool = False) -> None:
        """Jobs whose runner stopped (no heartbeat for STALE_MINUTES, or at start: left running by this one)."""
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET Status = CASE WHEN Attempts >= %s THEN N'failed' ELSE N'queued' END, "
                        "FinishedAt = CASE WHEN Attempts >= %s THEN SYSUTCDATETIME() END, Runner = NULL, HeartbeatAt = NULL, "
                        "Error = N'the queue runner stopped while asking the LLM' "
                        "WHERE Status = N'running' AND (HeartbeatAt < DATEADD(minute, %s, SYSUTCDATETIME()) "
                        "OR (%s = 1 AND Runner = %s))",
                        (MAX_ATTEMPTS, MAX_ATTEMPTS, -STALE_MINUTES, 1 if own else 0, self.name))
            if cur.rowcount:
                self.log(f"{cur.rowcount} job(s) without a runner queued again")
            conn.commit()
        finally:
            conn.close()

    def claim(self, conn, max_tokens: int | None = None, min_tokens: int | None = None) -> dict | None:
        """Take the next queued job of a kind this runner knows (the page's order), skipping ones another
        runner holds; with max_tokens/min_tokens, only one of that estimated size (input tokens)."""
        kinds = list(self.kinds)
        size, args = "", tuple(kinds)
        if max_tokens is not None:
            size, args = size + " AND COALESCE(j.EstInputTokens, 0) <= %s", args + (int(max_tokens),)
        if min_tokens is not None:
            size, args = size + " AND COALESCE(j.EstInputTokens, 0) >= %s", args + (int(min_tokens),)
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT TOP (1) j.*, s.Name AS ScanName, h.EndsAt AS HeavyUntil FROM cz.LlmJob j "
                    f"WITH (UPDLOCK, READPAST, ROWLOCK) LEFT JOIN cz.OrgScan s ON s.ScanId = j.ScanId {HEAVY_APPLY} "
                    "WHERE j.Status = N'queued' AND (j.NotBefore IS NULL OR j.NotBefore <= SYSUTCDATETIME()) "
                    f"AND j.Kind IN ({', '.join(['%s'] * len(kinds))}){size} "
                    f"ORDER BY {HEAVY_FIRST}", args)
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE cz.LlmJob SET Status = N'running', Runner = %s, StartedAt = SYSUTCDATETIME(), "
                        "HeartbeatAt = SYSUTCDATETIME(), Attempts = Attempts + 1 WHERE JobId = %s AND Status = N'queued'",
                        (self.name, row["JobId"]))
            if cur.rowcount != 1:
                row = None
            else:
                row["Attempts"] = int(row["Attempts"] or 0) + 1
        conn.commit()
        return row

    def process(self, row: dict) -> str:
        """One job: its kind's handler, and the result (or the failure) recorded. Returns the result. A job someone
        cancelled (Admin → LLM queue → Cancel) is recorded as skipped, whatever its handler did."""
        from . import ai
        from .orgsource import REDACT
        t0 = _time.monotonic()
        kind = JOB_KINDS[row["Kind"]]
        if row.get("CancelRequestedAt"):
            return self.cancelled(row, row.get("CancelRequestedBy"))
        try:
            with ai.usage_scope(feature=kind.feature, repo=row.get("Repository") or row.get("App"),
                                scan=row.get("ScanName")), _usage() as used:
                # a refactoring that deploys a sandbox variant reads its organization scan's settings and opens the
                # output repository's write token (variant.py): the runner's connection and credential key
                out = kind.handler({**row, "Payload": _payload(row), "_progress": lambda text: self.progress(row, text),
                                    "_connect": self.connect, "_key": self.key})
        except Exception as ex:  # noqa: BLE001
            if row["JobId"] in self.cancelling:
                result = self.cancelled(row, self.cancelling.get(row["JobId"]))
            elif self.stopping.is_set() and isinstance(ex, ai.Cancelled):
                self.release([row["JobId"]])    # stopped while waiting for an LLM: back in the queue, no attempt
                return "released"
            else:
                result = self.failed(row, REDACT(f"{type(ex).__name__}: {ex}")[:1000])
        else:
            if row["JobId"] in self.cancelling:
                result = self.cancelled(row, self.cancelling.get(row["JobId"]))
                self.metrics.jobs.inc(kind=kind.name, result=result)
                return result
            out = {**out, "tokens": used.tokens()}
            row = {**row, **self.answered_by(row)}
            result = self.answered(row, out, _time.monotonic() - t0)
            self.learn(row, used, _time.monotonic() - t0)
        self.metrics.jobs.inc(kind=kind.name, result=result)
        if result == "answered":
            self.metrics.seconds.observe(_time.monotonic() - t0, kind=kind.name)
        return result

    def _slots_changed(self) -> None:
        self.wake.set()
        try:
            busy = self.slots.in_progress()
            self.metrics.llm_jobs.replace({(ln["name"], ln.get("label") or ln["name"]): busy.get(ln["name"], 0)
                                           for ln in self.slots.lanes})
            self.metrics.llm_waiting.set(self.slots.waiting_calls())
        except Exception:  # noqa: BLE001 - metrics only
            pass

    def call_state(self, row: dict, state: str | None, llm: str | None = None) -> None:
        """What the job's LLM call does now, for the queue page: 'waiting' for a request, 'asking' `llm`, or None
        (no call: the job builds, verifies, deploys or prepares)."""
        if not self._call_state:
            return
        try:
            conn = self.connect()
            try:
                cur = conn.cursor()
                cur.execute("UPDATE cz.LlmJob SET CallState = %s, CallLlm = %s, CallSince = CASE WHEN %s IS NULL THEN NULL "
                            "ELSE SYSUTCDATETIME() END WHERE JobId = %s AND Status = N'running' AND Runner = %s",
                            (state, _cut(llm, 400), state, row["JobId"], self.name))
                conn.commit()
            finally:
                conn.close()
        except Exception as ex:                 # the page only
            if "CallState" in str(ex):
                self._call_state = False        # schema 41 not applied yet
            self.log(f"#{row['JobId']}: LLM call state not recorded: {type(ex).__name__}: {ex}"[:400])

    def cancelled(self, row: dict, by: str | None) -> str:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET Status = N'skipped', Runner = NULL, HeartbeatAt = NULL, "
                        "FinishedAt = SYSUTCDATETIME(), Note = %s WHERE JobId = %s AND Status = N'running' AND Runner = %s",
                        (_cut(f"cancelled by {by or 'an administrator'}", 400), row["JobId"], self.name))
            conn.commit()
        finally:
            conn.close()
        with self.lock:
            self.cancelling.pop(row["JobId"], None)
        self.log(f"#{row['JobId']} {row['Kind']} {row.get('Repository')}: cancelled by {by or 'an administrator'}")
        return "skipped"

    def check_cancel(self) -> None:
        """The running jobs someone cancelled: their LLM calls stop (ai.cancel_thread_when in _run)."""
        with self.lock:
            ids = list(self.active)
        if not ids:
            return
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT JobId, CancelRequestedBy FROM cz.LlmJob WHERE CancelRequestedAt IS NOT NULL "
                        f"AND JobId IN ({', '.join(['%s'] * len(ids))})", tuple(ids))
            rows = cur.fetchall()
        finally:
            conn.close()
        with self.lock:
            for jid, by in rows:
                if jid in self.active and jid not in self.cancelling:
                    self.cancelling[jid] = by or ""
                    self.log(f"#{jid}: cancelled by {by or 'an administrator'}: stopping its LLM calls")

    def answered(self, row: dict, out: dict, seconds: float) -> str:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET Status = N'answered', FinishedAt = SYSUTCDATETIME(), HeartbeatAt = NULL, "
                        "Result = %s, Summary = %s, Error = NULL, Note = %s, Seconds = %s, InputTokens = %s, "
                        "OutputTokens = %s, Endpoint = %s, Parallel = %s WHERE JobId = %s AND Status = N'running' "
                        "AND Runner = %s",
                        (json.dumps(out.get("result")), _cut(out.get("summary"), 400), _cut(out.get("note"), 400),
                         round(seconds, 1), *(out.get("tokens") or (None, None)), _cut(row.get("_endpoint"), 400),
                         row.get("_parallel") or 1, row["JobId"], self.name))
            conn.commit()
        finally:
            conn.close()
        self.log(f"#{row['JobId']} {row['Kind']} {row.get('Repository')}/{row.get('Component') or ''}: "
                 f"{out.get('summary')} in {seconds:.0f} s")
        return "answered"

    @staticmethod
    def answered_by(row: dict) -> dict:
        """The job's Endpoint and Parallel from its LLM calls (row["_calls"]): the endpoint that answered most of
        them, and the most requests at once on it during one; no call (answered from the cache, or no LLM work):
        no endpoint. A row without the record (a job not run by _run) keeps its own."""
        calls = row.get("_calls")
        if calls is None:
            return {}
        asked = [c for c in calls if c.get("endpoint")]
        if not asked:
            return {"_endpoint": None, "_parallel": 1}
        n: dict[str, int] = {}
        for c in asked:
            n[c["endpoint"]] = n.get(c["endpoint"], 0) + 1
        ep = max(n, key=lambda k: n[k])
        return {"_endpoint": ep, "_parallel": max(int(c.get("parallel") or 1) for c in asked if c["endpoint"] == ep)}

    def learn(self, row: dict, used: "_usage", seconds: float) -> None:
        """The speed and size figures of each endpoint that answered (cz.LlmSpeed), from the job's LLM calls on it:
        their characters, tokens and time (the calls only: building or verifying in between is not LLM time) and
        the most requests at once on it; a job partly answered from the cache teaches nothing."""
        if used.partly_cached():                # the job's size counts answers that cost nothing now: no lesson
            return
        calls = row.get("_calls")
        if calls is None:                       # a job not run by _run: the job as one call on its endpoint
            groups = {row.get("_endpoint"): ({"chars": row.get("InputChars"), "seconds": seconds,
                                              "parallel": row.get("_parallel") or 1}, used.entries)}
        else:
            groups = {}
            for c in calls:
                if not c.get("endpoint"):
                    continue
                g, entries = groups.setdefault(c["endpoint"], ({"chars": 0, "seconds": 0.0, "parallel": 1}, []))
                g["chars"] += int(c.get("chars") or 0)
                g["seconds"] += float(c.get("seconds") or 0)
                g["parallel"] = max(g["parallel"], int(c.get("parallel") or 1))
                entries += list(c.get("entries") or [])
        for ep, (g, entries) in groups.items():
            u = _usage()
            u.entries = entries
            tin, tout = u.tokens()
            if not tin and not tout or not ep:
                continue
            ps, gs = u.timings()
            try:
                conn = self.connect()
                try:
                    save_speed(conn, ep, row.get("Model") or "", row["Kind"],
                               {"chars": g["chars"] or None, "input_tokens": tin, "output_tokens": tout,
                                "seconds": g["seconds"], "prompt_seconds": ps, "generate_seconds": gs,
                                "prompt_read": u.prompt_read(), "parallel": g["parallel"]})
                finally:
                    conn.close()
            except Exception as ex:                 # statistics only
                self.log(f"speed statistics not updated: {type(ex).__name__}: {ex}")

    def progress(self, row: dict, text: str) -> None:
        """A long job's progress while it runs (a refactoring: generating, verifying), in Summary."""
        try:
            conn = self.connect()
            try:
                cur = conn.cursor()
                cur.execute("UPDATE cz.LlmJob SET Summary = %s, HeartbeatAt = SYSUTCDATETIME() WHERE JobId = %s "
                            "AND Status = N'running' AND Runner = %s", (_cut(text, 400), row["JobId"], self.name))
                conn.commit()
            finally:
                conn.close()
        except Exception as ex:                 # progress only
            self.log(f"#{row['JobId']}: progress not recorded: {type(ex).__name__}: {ex}")

    def failed(self, row: dict, error: str) -> str:
        last = int(row.get("Attempts") or 1) >= MAX_ATTEMPTS
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET Status = %s, Runner = NULL, HeartbeatAt = NULL, Error = %s, Summary = NULL, "
                        "FinishedAt = CASE WHEN %s = 1 THEN SYSUTCDATETIME() END, "
                        "NotBefore = CASE WHEN %s = 1 THEN NULL ELSE DATEADD(minute, %s, SYSUTCDATETIME()) END "
                        "WHERE JobId = %s AND Status = N'running' AND Runner = %s",
                        ("failed" if last else "queued", error, 1 if last else 0, 1 if last else 0,
                         RETRY_MINUTES * int(row.get("Attempts") or 1), row["JobId"], self.name))
            conn.commit()
        finally:
            conn.close()
        self.log(f"#{row['JobId']} {row['Kind']} {row.get('Repository')}/{row.get('Component') or ''}: "
                 + ("failed" if last else "failed, tried again later") + f": {error[:300]}")
        return "failed" if last else "retried"

    def release(self, ids: list[int]) -> None:
        """Jobs still running at shutdown go back to the queue; the attempt does not count."""
        if not ids:
            return
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET Status = N'queued', Runner = NULL, HeartbeatAt = NULL, StartedAt = NULL, "
                        "Attempts = CASE WHEN Attempts > 0 THEN Attempts - 1 ELSE 0 END WHERE Status = N'running' "
                        f"AND Runner = %s AND JobId IN ({', '.join(['%s'] * len(ids))})", (self.name, *ids))
            conn.commit()
        finally:
            conn.close()

    def heartbeat(self) -> None:
        with self.lock:
            ids = list(self.active)
        if not ids:
            return
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE cz.LlmJob SET HeartbeatAt = SYSUTCDATETIME() WHERE Runner = %s AND Status = N'running' "
                        f"AND JobId IN ({', '.join(['%s'] * len(ids))})", (self.name, *ids))
            conn.commit()
        finally:
            conn.close()

    def _heartbeats(self) -> None:
        n = 0
        while not self.stopping.wait(CANCEL_CHECK):
            n += 1
            try:
                self.check_cancel()
            except Exception as ex:
                self.log(f"cancel check: {type(ex).__name__}: {ex}")
            if n * CANCEL_CHECK < HEARTBEAT:
                continue
            n = 0
            try:
                self.heartbeat()
            except Exception as ex:
                self.log(f"heartbeat: {type(ex).__name__}: {ex}")

    def housekeep(self, force: bool = False) -> int:
        """Sandbox variants of "Make it A" orders that expired or that someone asked to remove (variant.py):
        taken out of the output repository. At most every minute; independent of the queue's window."""
        if not force and self._housekept is not None and _time.monotonic() - self._housekept < 60:
            return 0
        self._housekept = _time.monotonic()
        import tempfile
        from . import refactor, variant
        n = 0
        try:
            if self.key is None and os.environ.get("CONTAINERIZER_CREDENTIAL_KEY_FILE"):
                from .credentials import private_key_from_env
                self.key = private_key_from_env()
        except Exception as ex:  # noqa: BLE001
            self.log(f"credential key: {type(ex).__name__}: {ex}"[:400])
        if REFACTOR in self.kinds:
            try:
                base = Path(os.environ.get(refactor.WORK_ENV) or tempfile.gettempdir()) / "variants"
                n += variant.housekeep(self.connect, self.key, base, log=self.log)
                n += variant.sync_sandbox(self.connect, self.key, base, log=self.log)
            except Exception as ex:             # a database from before schema 23, the output repository away: next time
                self.log(f"sandbox variants: {type(ex).__name__}: {ex}"[:400])
            try:                                # their state as the cluster and the output repository say now
                base = Path(os.environ.get(refactor.WORK_ENV) or tempfile.gettempdir()) / "variants"
                n += variant.refresh(self.connect, self.key, base, log=self.log)
            except Exception as ex:             # a database from before schema 23, the cluster away: next time
                self.log(f"sandbox variant state: {type(ex).__name__}: {ex}"[:400])
            try:                                # /etc/containerizer without secrets, once per change (at boot)
                from . import configbackup
                base = Path(os.environ.get(refactor.WORK_ENV) or tempfile.gettempdir()) / "config-backup"
                n += configbackup.sync(self.connect, self.key, base, log=self.log)
            except Exception as ex:             # no output repository yet, or it is away: next time
                self.log(f"configuration backup: {type(ex).__name__}: {ex}"[:400])
            try:                                # applications moved to an output repository of their own (once)
                from . import appoutput
                base = Path(os.environ.get(refactor.WORK_ENV) or tempfile.gettempdir()) / "app-output"
                n += appoutput.housekeep(self.connect, self.key, base, log=self.log)
            except Exception as ex:             # a database from before schema 36, a repository away: next time
                self.log(f"application output repositories: {type(ex).__name__}: {ex}"[:400])
        if EGRESS in self.kinds or LINK in self.kinds:
            # blocked connections: reviews queued for new ones; decisions written to the output repository
            from . import egress
            try:
                base = Path(os.environ.get(refactor.WORK_ENV) or tempfile.gettempdir()) / "egress"
                r = egress.housekeep(self.connect, self.key, base, log=self.log)
                n += r.get("committed", 0)
            except Exception as ex:             # a database from before schema 24: next time
                self.log(f"egress: {type(ex).__name__}: {ex}"[:400])
        return n

    # -- the loop --------------------------------------------------------------------------------

    def registered_llms(self, conn) -> list:
        """The registered LLMs in their order, with their keys opened; looked up at most once a minute."""
        now = _time.monotonic()
        cached = getattr(self, "_llms", None)
        if cached is not None and now - cached[0] <= 60:
            return cached[1]
        from .credentials import CredentialError, PRIVATE_KEY_ENV, load, private_key_from_env
        from .orgsource import REDACT
        out = []
        try:
            if self.key is None and os.environ.get(PRIVATE_KEY_ENV):
                self.key = private_key_from_env()
            if self.key is not None:
                for c in load(conn, self.key).llms():
                    if c.error:
                        self.log(f"LLM {c.label} cannot be opened ({c.error}): not used")
                        continue
                    if c.token:
                        REDACT.add(c.token, c.username)
                    out.append(c)
        except CredentialError as ex:
            self.log(f"the registered LLMs cannot be opened ({ex}); using the built-in or the environment's LLM")
        self._llms = (now, out)
        return out

    def lanes(self, conn, settings: dict) -> list[dict]:
        from . import local_llm
        return plan_lanes(self.registered_llms(conn), local_llm.server_lanes(), settings)

    def _enter_llm(self, conn) -> None:
        """The LLM settings for the jobs about to be asked; changed only when none is in progress
        (ai.configured is process-wide)."""
        from .ai import configured
        if self._ctx is None:
            self._ctx = configured(self.llm_settings(conn))
            self._ctx.__enter__()

    def _leave_llm(self) -> None:
        if self._ctx is not None:
            self._ctx.__exit__(None, None, None)
            self._ctx = None

    def fill(self, pool) -> list:
        """Start jobs while the settings allow and job slots are free (jobs_at_once), in the queue's order. A job
        needs no LLM request to start: its calls take one each (Slots). Only a job estimated to need the LLM waits
        in the queue while every LLM request that would take it is in use or wanted (by calls waiting, or by jobs
        just started that have not asked yet): the jobs after it that need no LLM start meanwhile. Returns the
        futures started."""
        started = []
        conn = self.connect()
        try:
            approved, rejected = apply_rules(conn)
            if rejected:
                self.log(f"rejected {rejected} job(s) that waited too long")
            if approved:
                self.log(f"approved {approved} job(s) by the approval rules")
            self.metrics.queue.refresh(conn)
            settings = load_settings(conn)
            self.metrics.paused.set(1 if settings["Paused"] else 0)
            lanes = self.lanes(conn, settings)      # each LLM in its order, with its size limit and requests at once
            self.slots.update(lanes)
            room = jobs_at_once(settings, lanes)
            now = _time.monotonic()
            with self.lock:
                busy = len(self.active)
                reserved = [int(r.get("EstInputTokens") or 0) for r in self.active.values()
                            if r.get("_reserve_until", 0) > now]
            spare = self.slots.spare(reserved)
            # "only when idle" is checked before the first job: the runner's own work loads the machine
            ok, why = gate(settings, utcnow(), scans_running(conn), self.load() if not busy else 0.0,
                            restartplan.holding(llm=True))
            if self.draining.is_set():
                ok, why = False, (f"app update: finishing {busy} job(s) on this code, then restarting with the new one"
                                  if busy else "app update: restarting with the new code")
            self.metrics.open.set(1 if ok else 0)
            if why != self.status:
                self.log(why or "open: taking jobs")
                self.status = why
            while ok and not self.stopping.is_set() and busy < room:
                free = [ln for ln in lanes if spare.get(ln["name"], 0) > 0]
                # an LLM with a spare request takes the next job of a size it takes; none: only jobs without LLM work
                limit = 0 if not free else None if any(not ln["max_tokens"] for ln in free) else \
                    max(int(ln["max_tokens"]) for ln in free)
                row = self.claim(conn, max_tokens=limit)
                if not row:
                    break
                est = int(row.get("EstInputTokens") or 0)
                home = next(iter(self.slots.candidates(est, free if est else lanes)), None) or \
                    (lanes[0] if lanes else {"name": "environment", "settings": None})
                if est:                         # its first call is expected soon: that request is not spare
                    spare[home["name"]] = spare.get(home["name"], 0) - 1
                    row["_reserve_until"] = now + RESERVE_SECONDS
                self._enter_llm(conn)
                busy += 1
                self._order += 1
                # the job's own LLM (the first in the order that takes its size) for what it does outside its calls
                # (the model name in its result); each call picks its LLM again (Slots)
                row["_lane"], row["_llm"], row["_order"], row["_calls"] = home["name"], home.get("settings"), self._order, []
                try:
                    from .ai import configured, endpoint
                    with configured(row["_llm"], local=True) if row["_llm"] else contextlib.nullcontext():
                        row["_endpoint"] = endpoint(row.get("Model") if not row["_llm"] else None)
                except Exception:
                    row["_endpoint"] = None
                row["_parallel"] = 1
                with self.lock:
                    self.active[row["JobId"]] = row
                self.call_state(row, None)      # nothing left over from an earlier attempt
                f = pool.submit(self._run, row)
                if hasattr(f, "add_done_callback"):
                    f.add_done_callback(lambda _f: self.wake.set())
                started.append(f)
            self._slots_changed()
        finally:
            conn.close()
        self.metrics.active.set(len(self.active))
        self.metrics.poll.set(_time.time())
        return started

    def _run(self, row: dict) -> str:
        from .ai import cancel_thread_when, llm_slots
        try:
            with cancel_thread_when(lambda: row["JobId"] in self.cancelling), llm_slots(_JobCalls(self, row)):
                if row.get("_llm"):                 # the job's own LLM, for this job's thread only
                    from .ai import configured
                    with configured(row["_llm"], local=True):
                        return self.process({**row, "Model": None})
                return self.process(row)
        finally:
            with self.lock:
                self.active.pop(row["JobId"], None)

    def run(self, once: bool = False, grace: float = 20.0) -> int:
        """Until stopped (or, with `once`, until nothing more can start). Returns the jobs finished."""
        self.recover(own=True)
        threading.Thread(target=self._heartbeats, name="llm-queue-heartbeat", daemon=True).start()
        pool = ThreadPoolExecutor(max_workers=JOBS_AT_ONCE_MAX, thread_name_prefix="llm-job")
        futures: set = set()
        finished = 0
        try:
            while not self.stopping.is_set():
                if self.draining.is_set() and not futures:
                    self.log("app update: no job left on this code: restarting with the new one")
                    break
                started = []
                try:
                    self.recover()
                    if not self.draining.is_set():      # an app update: the new code housekeeps
                        self.housekeep()
                    started = self.fill(pool)
                except Exception as ex:          # the database may be away for a while: keep trying
                    self.metrics.poll_errors.inc()
                    self.log(f"error: {type(ex).__name__}: {ex}")
                futures |= set(started)
                if once and not futures:
                    break
                if futures:
                    # until a job finishes, an LLM request comes free (another job may start) or the next poll
                    self.wake.wait(self.poll)
                    self.wake.clear()
                    done = {f for f in futures if f.done()}
                    finished += len(done)
                    futures -= done
                else:
                    self.wake.wait(self.poll)           # also woken by a drain (SIGUSR1) or a stop
                    self.wake.clear()
                if not futures:
                    self._leave_llm()
            if futures:
                self.log(f"stopping: waiting up to {grace:.0f} s for {len(futures)} job(s)")
                done, _ = wait(futures, timeout=grace)
                finished += len(done)
        finally:
            with self.lock:
                left = list(self.active)
            if left:
                try:
                    self.release(left)
                    self.log(f"{len(left)} job(s) not finished: back in the queue")
                except Exception as ex:
                    self.log(f"could not put {len(left)} job(s) back in the queue: {type(ex).__name__}: {ex}")
            pool.shutdown(wait=False, cancel_futures=True)
            self._leave_llm()
        return finished


# --------------------------------------------------------------------------- the file queue

def run_file(path: str | Path, log=print) -> int:
    """`containerizer llm-queue --file`: every queued job of a file queue, once each, in queue order. Review
    answers go to the answer cache (and the file), so the next `--ai-queue` run of the app applies them."""
    from . import ai
    q = FileJobQueue(path)
    failed = 0
    while True:
        waiting = ordered([x for x in q.load() if x["Status"] == "queued" and x["Kind"] in JOB_KINDS])
        if not waiting:
            break
        x = waiting[0]
        kind = JOB_KINDS[x["Kind"]]
        t0 = _time.monotonic()
        try:
            with ai.usage_scope(feature=kind.feature, repo=x.get("Repository") or x.get("App")), _usage() as used:
                out = kind.handler({**x, "Payload": _payload(x)})
            tin, tout = used.tokens()
            upd = {"Status": "answered", "Result": out.get("result"), "Summary": out.get("summary"),
                   "Note": out.get("note"), "Seconds": round(_time.monotonic() - t0, 1), "InputTokens": tin,
                   "OutputTokens": tout}
            log(f"#{x['JobId']} {x['Kind']} {x.get('Repository')}/{x.get('Component') or ''}: {out.get('summary')}")
        except Exception as ex:  # noqa: BLE001 - one try per run on the command line
            upd = {"Status": "failed", "Error": f"{type(ex).__name__}: {ex}"[:1000]}
            failed += 1
            log(f"#{x['JobId']} {x['Kind']} {x.get('Repository')}/{x.get('Component') or ''}: failed: {upd['Error'][:300]}")
        items = q.load()
        for y in items:
            if y["JobId"] == x["JobId"]:
                y.update(upd, FinishedAt=utcnow().isoformat(timespec="seconds"), Attempts=int(y.get("Attempts") or 0) + 1)
        q.save(items)
    return 1 if failed else 0


def preload() -> int:
    """Import every module of containerizer now. A job imports many of them when it first needs them, and an app
    update changes the code under a runner that finishes its jobs (SIGUSR1): from then on its imports take what is
    already loaded, its own version, instead of the new version's files. Returns how many were imported."""
    import importlib
    import pkgutil
    import containerizer
    n = 0
    for m in pkgutil.walk_packages(containerizer.__path__, "containerizer."):
        if m.name.endswith("__main__"):
            continue
        try:
            importlib.import_module(m.name)
            n += 1
        except Exception:  # noqa: BLE001 - an optional dependency missing: that module is imported when used, as before
            pass
    return n

def build(args) -> int:
    """`containerizer llm-queue` from the command line."""
    if args.file:
        return run_file(args.file, log=lambda m: print(m, file=sys.stderr, flush=True))
    from . import metrics as mm
    from .sqlstore import SqlError, connect
    cs = args.sql or os.environ.get("CONTAINERIZER_SQL")
    if not cs:
        print("error: the LLM queue is in SQL Server: set --sql or CONTAINERIZER_SQL (or --file for a queue "
              "written by --ai-queue without SQL Server)", file=sys.stderr)
        return 2
    try:
        connect(cs).close()
    except SqlError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 3
    name = (args.name or f"{socket.gethostname()}-llm-queue")[:256]
    kinds = [k.strip() for k in (getattr(args, "kinds", None) or "").split(",") if k.strip()] or None
    unknown = [k for k in kinds or [] if k not in JOB_KINDS]
    if unknown:
        print(f"error: unknown job kind(s) {', '.join(unknown)} (known: {', '.join(JOB_KINDS)})", file=sys.stderr)
        return 2
    preload()
    r = Runner(lambda: connect(cs), name=name, poll=args.poll, metrics=QueueMetrics(name), kinds=kinds)
    if not args.no_metrics:
        token = os.environ.get("CONTAINERIZER_METRICS_TOKEN") or None
        mm.serve(r.metrics.registry, args.metrics_host, args.metrics_port, token)
        r.log(f"metrics on http://{args.metrics_host}:{args.metrics_port}/metrics"
              + (" (bearer token required)" if token else ""))

    def stop(signum, frame):
        r.log("stopping")
        r.stopping.set()
        r.wake.set()

    def drain(signum, frame):
        r.log("app update: no new job; the jobs in progress finish on this code, then the runner restarts")
        r.draining.set()
        r.wake.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGUSR1, drain)
    r.log(f"{r.name}: looking at the LLM queue every {args.poll}s (kinds: {', '.join(r.kinds)})")
    r.run(once=args.once)
    if r.draining.is_set() and not r.stopping.is_set():
        # drained for an app update: a failure exit, so that systemd (Restart=on-failure) starts the new code
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(DRAINED_EXIT)
    if r.stopping.is_set():
        # Stopped by a signal: unfinished jobs are back in the queue (run's finally), but their threads may still
        # wait for the LLM, and Python waits for pool threads at exit, up to an hour on a CPU LLM. Leave now:
        # closing the connection also makes llama.cpp cancel the answer and free the slot.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
    return 0
