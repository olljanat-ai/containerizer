"""The LLM queue: LLM jobs that do not hold up the scans (docs/source-control.md#queued-llm-reviews).

A self-hosted LLM on CPUs can take minutes per answer. The queue (cz.LlmJob) holds LLM jobs of any kind,
and its runner (`containerizer llm-queue`, a process of its own) works through them when the settings let
it (Admin → LLM queue: paused, days and hours in UTC, only when the machine is idle, parallel requests).

Job kinds (JOB_KINDS, `register`): `review`, a component review, and `refactor`, a refactoring patch a
person ordered for a B-rated application (refactor.py, docs/refactoring.md). A scan with queued LLM reviews
(OrgScan.LlmMode 'queued', `--ai-queue` on the command line) asks the LLM nothing while it runs: the rules
decide, and the component reviews the LLM would have been asked are queued with a priority instead
(queue_reviews):

- *uncertain* components (server or platform tier, confidence below 0.85: the components an inline scan
  asks about) come first;
- components the rules rate *blocker* or *rewrite* with confidence follow at low priority, as a *second
  opinion*.

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

import copy
import json
import os
import signal
import socket
import sys
import threading
import time as _time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

REASONS = ("uncertain", "second-opinion")          # why a component review is queued
REASON_TEXT = {"uncertain": "Uncertain", "second-opinion": "Second opinion"}
STATUSES = ("queued", "running", "answered", "failed", "skipped")
PENDING = ("queued", "running")
FEATURE = "assessment-queued"           # LLM usage feature of the reviews the runner asks
MAX_ATTEMPTS = 3                        # a job that failed this often stays failed (requeue on the page)
RETRY_MINUTES = 5                       # wait before the next attempt: this times the attempts so far
HEARTBEAT = 30                          # seconds between heartbeats of the jobs being asked
STALE_MINUTES = 10                      # a running job without a heartbeat for this long lost its runner
SECOND_OPINION = ("blocker", "rewrite")
# How sure the LLM must be to change the verdict: as inline for uncertain components; a second opinion
# goes against rules that were sure, so it must be as sure as they were.
OVERRIDE_CONFIDENCE = {"uncertain": 0.6, "second-opinion": 0.85}
DEFAULTS = {"Paused": False, "WindowDays": 0, "WindowStart": None, "WindowEnd": None, "OnlyWhenIdle": True,
            "MaxLoadPerCpu": 0.5, "Parallel": 1}


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
            generate_seconds: float | None = None, parallel: int = 1) -> tuple[dict, dict]:
    """What one answered job teaches, folded into the endpoint's figures (characters per input token, prompt
    and generation speed, or overall tokens per second when the server reports no timings) and its kind's
    (output tokens). Rows are LlmSpeed columns; returns the new (endpoint row, kind row). Speeds are as
    observed with `parallel` jobs sharing the server."""
    e, k = dict(endpoint_row or {}), dict(kind_row or {})
    tin, tout = int(input_tokens or 0), int(output_tokens or 0)
    if chars and tin:
        e["CharsPerToken"] = ewma(e.get("CharsPerToken"), chars / tin)
    if prompt_seconds and generate_seconds and tin and tout:
        e["PromptTokensPerSecond"] = ewma(e.get("PromptTokensPerSecond"), tin / prompt_seconds)
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
    data = ai.ask_json(pl["prompt"], ai.REVIEW_SCHEMA, model=model, feature=FEATURE)
    note = None
    try:
        if ai.cache_key(pl["prompt"], ai.REVIEW_SCHEMA, model) != pl.get("cache_key"):
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
    applied, key_of_app = [], None
    for c in a.components:
        reason = review_kind(c, threshold)
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
    """Queued jobs in the order the runner takes them (as ORDER BY in Runner.claim)."""
    return sorted(rows, key=lambda r: (-effective(r), r["JobId"]))


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


def gate(settings: dict, now: datetime, scans_running: int, load: float) -> tuple[bool, str]:
    """(may start a job now, why not)."""
    s = {**DEFAULTS, **(settings or {})}
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
        self.active = r.gauge("containerizer_llm_queue_active_jobs", "Jobs the runner is asking the LLM about now.")
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


class Runner:
    """`containerizer llm-queue`: works through cz.LlmJob when the settings let it."""

    def __init__(self, connect, name: str | None = None, poll: int = 30, metrics: QueueMetrics | None = None,
                 log=None, key=None, load=load_per_cpu):
        self.connect = connect              # () -> sqlstore.Connection of a writer login
        self.name = (name or f"{socket.gethostname()}-llm-queue")[:256]
        self.poll = poll
        self.metrics = metrics or QueueMetrics(self.name)
        self.log = log or (lambda msg: print(f"llm-queue: {msg}", file=sys.stderr, flush=True))
        self.key = key                      # X25519 private key that opens the LLM credential (None: from the env)
        self.load = load
        self.stopping = threading.Event()
        self.active: dict[int, dict] = {}   # JobId -> row being asked
        self.lock = threading.Lock()
        self._ctx = None                    # ai.configured() of the jobs being asked
        self.status = None

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

    def claim(self, conn) -> dict | None:
        """Take the next queued job of a kind this runner knows (the page's order), skipping ones another
        runner holds."""
        kinds = list(JOB_KINDS)
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT TOP (1) j.*, s.Name AS ScanName FROM cz.LlmJob j WITH (UPDLOCK, READPAST, ROWLOCK) "
                    "LEFT JOIN cz.OrgScan s ON s.ScanId = j.ScanId "
                    "WHERE j.Status = N'queued' AND (j.NotBefore IS NULL OR j.NotBefore <= SYSUTCDATETIME()) "
                    f"AND j.Kind IN ({', '.join(['%s'] * len(kinds))}) "
                    "ORDER BY COALESCE(j.AdminRank, CAST(j.Priority AS float)) DESC, j.JobId", tuple(kinds))
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
        """One job: its kind's handler, and the result (or the failure) recorded. Returns the result."""
        from . import ai
        from .orgsource import REDACT
        t0 = _time.monotonic()
        kind = JOB_KINDS[row["Kind"]]
        try:
            with ai.usage_scope(feature=kind.feature, repo=row.get("Repository") or row.get("App"),
                                scan=row.get("ScanName")), _usage() as used:
                out = kind.handler({**row, "Payload": _payload(row), "_progress": lambda text: self.progress(row, text)})
        except Exception as ex:  # noqa: BLE001
            result = self.failed(row, REDACT(f"{type(ex).__name__}: {ex}")[:1000])
        else:
            out = {**out, "tokens": used.tokens()}
            result = self.answered(row, out, _time.monotonic() - t0)
            self.learn(row, used, _time.monotonic() - t0)
        self.metrics.jobs.inc(kind=kind.name, result=result)
        if result == "answered":
            self.metrics.seconds.observe(_time.monotonic() - t0, kind=kind.name)
        return result

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

    def learn(self, row: dict, used: "_usage", seconds: float) -> None:
        """The speed and size figures of the endpoint that answered (cz.LlmSpeed); a cached answer teaches nothing."""
        tin, tout = used.tokens()
        if not tin and not tout or not row.get("_endpoint"):
            return
        ps, gs = used.timings()
        try:
            conn = self.connect()
            try:
                save_speed(conn, row["_endpoint"], row.get("Model") or "", row["Kind"],
                           {"chars": row.get("InputChars"), "input_tokens": tin, "output_tokens": tout,
                            "seconds": seconds, "prompt_seconds": ps, "generate_seconds": gs,
                            "parallel": row.get("_parallel") or 1})
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
        """Jobs still being asked at shutdown go back to the queue; the attempt does not count."""
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
        while not self.stopping.wait(HEARTBEAT):
            try:
                self.heartbeat()
            except Exception as ex:
                self.log(f"heartbeat: {type(ex).__name__}: {ex}")

    # -- the loop --------------------------------------------------------------------------------

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
        """Start jobs while the settings allow and slots are free. Returns the futures started."""
        started = []
        conn = self.connect()
        try:
            self.metrics.queue.refresh(conn)
            settings = load_settings(conn)
            self.metrics.paused.set(1 if settings["Paused"] else 0)
            parallel = max(1, int(settings["Parallel"] or 1))
            with self.lock:
                busy = len(self.active)
            # "only when idle" is checked before the first request: the runner's own requests load the machine
            ok, why = gate(settings, utcnow(), scans_running(conn), self.load() if not busy else 0.0)
            self.metrics.open.set(1 if ok else 0)
            if why != self.status:
                self.log(why or "open: taking jobs")
                self.status = why
            while ok and busy < parallel and not self.stopping.is_set():
                row = self.claim(conn)
                if not row:
                    break
                self._enter_llm(conn)
                busy += 1
                try:
                    from .ai import endpoint
                    row["_endpoint"] = endpoint(row.get("Model") or None)
                except Exception:
                    row["_endpoint"] = None
                row["_parallel"] = busy             # jobs sharing the server while this one is asked
                with self.lock:
                    self.active[row["JobId"]] = row
                started.append(pool.submit(self._run, row))
        finally:
            conn.close()
        self.metrics.active.set(len(self.active))
        self.metrics.poll.set(_time.time())
        return started

    def _run(self, row: dict) -> str:
        try:
            return self.process(row)
        finally:
            with self.lock:
                self.active.pop(row["JobId"], None)

    def run(self, once: bool = False, grace: float = 20.0) -> int:
        """Until stopped (or, with `once`, until nothing more can start). Returns the jobs finished."""
        self.recover(own=True)
        threading.Thread(target=self._heartbeats, name="llm-queue-heartbeat", daemon=True).start()
        pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="llm-job")
        futures: set = set()
        finished = 0
        try:
            while not self.stopping.is_set():
                started = []
                try:
                    self.recover()
                    started = self.fill(pool)
                except Exception as ex:          # the database may be away for a while: keep trying
                    self.metrics.poll_errors.inc()
                    self.log(f"error: {type(ex).__name__}: {ex}")
                futures |= set(started)
                if once and not futures:
                    break
                if futures:
                    done, pending = wait(futures, timeout=self.poll, return_when=FIRST_COMPLETED)
                    finished += len(done)
                    futures = set(pending)
                else:
                    self.stopping.wait(self.poll)
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
    r = Runner(lambda: connect(cs), name=name, poll=args.poll, metrics=QueueMetrics(name))
    if not args.no_metrics:
        token = os.environ.get("CONTAINERIZER_METRICS_TOKEN") or None
        mm.serve(r.metrics.registry, args.metrics_host, args.metrics_port, token)
        r.log(f"metrics on http://{args.metrics_host}:{args.metrics_port}/metrics"
              + (" (bearer token required)" if token else ""))

    def stop(signum, frame):
        r.log("stopping")
        r.stopping.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    r.log(f"{r.name}: looking at the LLM queue every {args.poll}s")
    r.run(once=args.once)
    return 0
