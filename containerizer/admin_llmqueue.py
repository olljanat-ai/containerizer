"""Admin page of the LLM queue (llmqueue.py, docs/scheduled-scans.md#the-llm-queue): administrators and operators.

- The queue: running and queued jobs of every kind in the order the runner takes them, with their estimated
  tokens and time; Top, Up, Down, Bottom and Skip on each queued job.
- Finished jobs: answers (with the reasoning), failures and skipped jobs; Requeue on failed and skipped ones.
- Repositories whose reviews are all answered since their last scan: Re-scan now (a full scan of only that
  repository), so the answers apply without waiting for the schedule.
- The settings: paused, days and hours (UTC) the runner may work, only when the machine is idle, parallel
  requests.

Same conventions as admin.py: plain HTML forms with the session's CSRF token, no JavaScript, everything
escaped, changes audited by triggers (cz.LlmJob, cz.LlmQueueSettings).
"""
from __future__ import annotations

import json
import re
from datetime import timedelta

from .admin import Response, _d, e
from .admin_scans import TIME_RE, _back, _nf
from . import llmqueue as lq

BASE = "/admin/llm-queue"
STATUS_TEXT = {"approval": "Waiting for approval", "queued": "Queued", "running": "Asking", "answered": "Answered", "failed": "Failed", "skipped": "Skipped"}
STATUS_CSS = {"approval": "st-wait", "queued": "st-run", "running": "st-run", "answered": "st-ok", "failed": "st-bad", "skipped": "st-off"}
JOB_COLS = ("JobId, Kind, Reason, Status, Priority, AdminRank, ScanId, RepositoryId, Repository, App, Component, ProjectPath, "
            "RuleVerdict, Confidence, Model, RequestedBy, InputChars, EstInputTokens, InputTokens, OutputTokens, Endpoint, "
            "Parallel, Summary, Error, Note, Attempts, NotBefore, QueuedAt, StartedAt, FinishedAt, Runner, Seconds")
ORDER = "COALESCE(AdminRank, CAST(Priority AS float)) DESC, JobId"


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict, flash: str) -> Response:
    ident = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"\d{1,9}", parts[1]) else None
    if len(parts) == 1 and method == "GET":
        return show(adm, conn, s, a, q, flash)
    if len(parts) == 2 and parts[1] == "settings" and method == "POST":
        return save_settings(conn, form)
    if len(parts) == 2 and parts[1] == "rescan" and method == "POST":
        return rescan(conn, form)
    if ident is not None and len(parts) == 2 and method == "GET":
        return show_job(adm, conn, s, a, ident, flash)
    if ident is not None and len(parts) == 3 and method == "POST":
        if parts[2] in lq.ACTIONS:
            return move(conn, ident, parts[2])
        if parts[2] == "skip":
            return skip(conn, ident)
        if parts[2] == "requeue":
            return requeue(conn, ident)
        if parts[2] in ("approve", "reject"):
            if not a.admin:
                return _back(BASE, "Only administrators approve LLM jobs.")
            return approve(conn, ident, s.user) if parts[2] == "approve" else reject(conn, ident, s.user)
    return _nf()


# --------------------------------------------------------------------------- text helpers

def chip(status: str) -> str:
    return f"<span class='st {STATUS_CSS.get(status, '')}'>{e(STATUS_TEXT.get(status, status))}</span>"


def _n(x) -> str:
    return f"{int(round(x or 0)):,}"


def what(r: dict) -> str:
    """The job: its kind, and for a review the component, the reason and the rules' verdict."""
    title = lq.kind_title(r["Kind"])
    target = " / ".join(x for x in (r.get("Repository") or r.get("App"), r.get("Component")) if x)
    href = f"/admin/refactoring/{int(r['JobId'])}" if r["Kind"] == lq.REFACTOR else f"{BASE}/{int(r['JobId'])}"
    out = f"<a href='{href}'>{e(target or title)}</a><div class='muted small'>{e(title)}"
    if r.get("Reason"):
        out += f" · {e(lq.REASON_TEXT.get(r['Reason'], r['Reason']))}"
    if r.get("RuleVerdict"):
        conf = f", confidence {float(r['Confidence']):.2f}" if r.get("Confidence") is not None else ""
        out += f" · rules: {e(r['RuleVerdict'])}{conf}"
    return out + "</div>"


def estimate(est: dict) -> str:
    return f"~{_n(est['in'])} in / ~{_n(est['out'])} out tokens · {lq.duration_text(est['seconds'])}"


def actual(r: dict, est: dict | None = None) -> str:
    """Actual tokens and time of a finished job, next to the estimate it had."""
    if r.get("InputTokens") is None and r.get("OutputTokens") is None:
        took = f"{lq.duration_text(float(r['Seconds']))[1:]}" if r.get("Seconds") else ""
        return f"no tokens used (answered from the cache){' · ' + took if took else ''}" if r["Status"] == "answered" else ""
    took = lq.duration_text(float(r["Seconds"] or 0))[1:] if r.get("Seconds") else "?"
    out = f"{_n(r['InputTokens'])} in / {_n(r['OutputTokens'])} out tokens in {took}"
    if r.get("EstInputTokens"):
        out += f" (estimated ~{_n(r['EstInputTokens'])} in)"
    return out


def totals(active: list[dict], speed, settings: dict, now) -> dict:
    """The queue's summary: jobs waiting and running by kind (reviews by reason), the estimated tokens and
    LLM time of everything waiting at the learned speed and the parallel requests set, when it would all be
    done if the queue ran without a pause, what the estimate is based on, and when the hours next allow it."""
    queued = [r for r in active if r["Status"] == "queued"]
    parallel = int(settings.get("Parallel") or 1)
    by: dict[str, int] = {}
    for r in queued:
        label = lq.REASON_TEXT.get(r["Reason"], r["Reason"]) if r["Kind"] == lq.REVIEW and r.get("Reason") \
            else lq.kind_title(r["Kind"])
        by[label] = by.get(label, 0) + 1
    tot = speed.queue(queued, parallel)
    b = tot.get("basis")
    return {"waiting": len(queued), "running": sum(1 for r in active if r["Status"] == "running"), "by": by,
            "in": tot["in"], "out": tot["out"], "seconds": tot["seconds"], "parallel": parallel,
            "done": now + timedelta(seconds=tot["seconds"]) if tot["seconds"] is not None else None,
            "basis": (f"learned from {int(b.get('Samples') or 0)} answers on {b.get('Model') or b.get('Endpoint')} "
                      "(the newest weigh most)") if b else "learning: no answers yet",
            "next_open": lq.next_open(settings, now)}


def summary_html(t: dict, now) -> str:
    """The block at the top of the queue page."""
    if not t["waiting"] and not t["running"]:
        return "<div class='note'><b>Nothing is waiting.</b></div>"
    kinds = ", ".join(f"{n} {k.lower()}" for k, n in sorted(t["by"].items(), key=lambda kv: -kv[1]))
    lines = [f"<b>{t['waiting']} job{'s' if t['waiting'] != 1 else ''} waiting</b>" + (f" ({e(kinds)})" if kinds else "")
             + (f" · {t['running']} being asked now" if t["running"] else ""),
             f"~{_n(t['in'])} tokens in, ~{_n(t['out'])} tokens out"]
    if t["seconds"] is None:
        lines.append("Time: learning (estimated once the runner has answered on this LLM)")
    else:
        lines.append(f"<b>~{e(lq.duration_long(t['seconds']))} of LLM time</b> ({t['parallel']} in parallel)"
                     f" · all done around {_d(t['done'].replace(tzinfo=None))} if the queue ran without a pause")
    lines.append(e(t["basis"][:1].upper() + t["basis"][1:]))
    small = "An estimate. Waiting for the hours set below or for an idle machine is not included."
    if t["next_open"] is None:
        small += " The queue is paused."
    elif t["next_open"] > now + timedelta(minutes=1):
        small += f" The hours next allow it from {_d(t['next_open'].replace(tzinfo=None))}."
    return "<div class='note'>" + "<br>".join(lines) + f"<div class='muted small'>{e(small)}</div></div>"


# --------------------------------------------------------------------------- the page

def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def rescan_candidates(conn) -> list[dict]:
    """Repositories of organization scans with answered reviews newer than their last scan, and none waiting."""
    return _rows(conn, """SELECT r.RepositoryId, MAX(j.Repository) AS Repository, COUNT(*) AS Answered,
                                 MAX(j.FinishedAt) AS LastAnswer, MAX(r.LastScannedAt) AS LastScannedAt
                          FROM cz.LlmJob j JOIN cz.OrgRepository r ON r.RepositoryId = j.RepositoryId
                          WHERE j.Kind = N'review' AND j.Status = N'answered' AND r.RemovedAt IS NULL
                            AND (r.LastScannedAt IS NULL OR j.FinishedAt > r.LastScannedAt)
                            AND NOT EXISTS (SELECT 1 FROM cz.LlmJob p WHERE p.RepositoryId = j.RepositoryId
                                            AND p.Kind = N'review' AND p.Status IN (N'queued', N'running'))
                          GROUP BY r.RepositoryId ORDER BY MAX(j.FinishedAt) DESC""")


def _buttons(adm, s, r: dict, first: bool, last: bool) -> str:
    jid = int(r["JobId"])
    out = []
    for act, label, off in (("top", "Top", first), ("up", "Up", first), ("down", "Down", last), ("bottom", "Bottom", last),
                            ("skip", "Skip", False)):
        if not off:
            out.append(f"<form method='post' action='{BASE}/{jid}/{act}' class='inline'>{adm._csrf(s)}"
                       f"<button class='link'>{label}</button></form>")
    return " ".join(out)


def show(adm, conn, s, a, q: dict, flash: str) -> Response:
    kind = q.get("kind", [""])[0]
    kind = kind if kind in lq.JOB_KINDS else ""
    where, params = ("", ()) if not kind else (" AND Kind = %s", (kind,))
    settings = lq.load_settings(conn)
    speed = lq.load_speed(conn)
    active = _rows(conn, f"SELECT {JOB_COLS} FROM cz.LlmJob WHERE Status IN (N'approval', N'queued', N'running'){where} "
                         f"ORDER BY CASE Status WHEN N'running' THEN 0 WHEN N'approval' THEN 1 ELSE 2 END, {ORDER}", params)
    done = _rows(conn, f"SELECT TOP (50) {JOB_COLS} FROM cz.LlmJob WHERE Status IN (N'answered', N'failed', N'skipped')"
                       f"{where} ORDER BY COALESCE(FinishedAt, QueuedAt) DESC, JobId DESC", params)
    queued = [r for r in active if r["Status"] == "queued"]
    parallel = int(settings["Parallel"] or 1)
    now = lq.utcnow()
    ok, why = lq.gate(settings, now, lq.scans_running(conn), lq.load_per_cpu())
    state = "<span class='st st-ok'>Open</span>" if ok else f"<span class='st st-off'>Waiting</span> {e(why)}"
    waiting = sum(1 for r in active if r["Status"] == "approval")
    if waiting:
        state += f" · <span class='st st-wait'>{waiting} waiting for approval</span>"

    rows = []
    for i, r in enumerate(active):
        est = speed.job(r)
        when = (f"asking since {_d(r['StartedAt'])}" + (f" · {e(r['Runner'])}" if r.get("Runner") else "")) \
            if r["Status"] == "running" else f"queued {_d(r['QueuedAt'])}"
        if r.get("NotBefore") and r["Status"] == "queued":
            when += f" · next try after {_d(r['NotBefore'])}"
        moved = " <span class='muted small'>(moved)</span>" if r.get("AdminRank") is not None and \
            abs(float(r["AdminRank"]) - float(r["Priority"])) >= 0.01 else ""
        acts = _buttons(adm, s, r, r is queued[0] if queued else True, r is queued[-1] if queued else True) \
            if r["Status"] == "queued" and not kind else (_buttons(adm, s, r, True, True) if r["Status"] == "queued" else "")
        if r["Status"] == "approval":
            acts = (f"<form method='post' action='{BASE}/{int(r['JobId'])}/approve' class='inline'>{adm._csrf(s)}"
                    f"<button>Approve</button></form> <form method='post' action='{BASE}/{int(r['JobId'])}/reject' "
                    f"class='inline'>{adm._csrf(s)}<button class='secondary'>Reject</button></form>") if a.admin \
                else "<span class='muted small'>an administrator approves it</span>"
        err = f"<div class='muted small'>last try: {e(r['Error'])}</div>" if r.get("Error") else ""
        rows.append(f"<tr><td class='num'>{i + 1}</td><td>{chip(r['Status'])}</td><td>{what(r)}{err}</td>"
                    f"<td class='num'>{int(r['Priority'])}{moved}</td><td class='small'>{estimate(est)}</td>"
                    f"<td class='small'>{when}<div class='muted'>{e(r.get('RequestedBy') or '')}</div></td>"
                    f"<td class='nowrap'>{acts}</td></tr>")
    finished = []
    for r in done:
        if r["Status"] == "answered":
            res = f"<b>{e(r['Summary'] or '')}</b><div class='muted small'>{e(actual(r))}</div>"
        else:
            res = e(r.get("Error") or r.get("Note") or "")
        again = (f"<form method='post' action='{BASE}/{int(r['JobId'])}/requeue' class='inline'>{adm._csrf(s)}"
                 f"<button class='link'>Requeue</button></form>") if r["Status"] in ("failed", "skipped") else ""
        finished.append(f"<tr><td>{chip(r['Status'])}</td><td>{what(r)}</td><td class='small'>{res}</td>"
                        f"<td class='nowrap small'>{_d(r['FinishedAt'] or r['QueuedAt'])}</td><td>{again}</td></tr>")
    ready = []
    for r in rescan_candidates(conn):
        ready.append(f"<tr><td>{e(r['Repository'] or '')}</td><td class='num'>{int(r['Answered'])}</td>"
                     f"<td class='small'>{_d(r['LastAnswer'])}</td><td class='small'>{_d(r['LastScannedAt']) or 'never'}</td>"
                     f"<td><form method='post' action='{BASE}/rescan' class='inline'>{adm._csrf(s)}"
                     f"<input type='hidden' name='RepositoryId' value='{int(r['RepositoryId'])}'>"
                     f"<button>Re-scan now</button></form></td></tr>")
    chips = " ".join(f"<a class='chip{' on' if k == kind else ''}' href='{BASE}{('?kind=' + k) if k else ''}'>{e(t)}</a>"
                     for k, t in (("", "All kinds"), *((k, v.title) for k, v in lq.JOB_KINDS.items())))
    body = (f"<p class='muted'>LLM jobs that do not hold up the scans. Scans set to <b>queued</b> LLM reviews (Organization "
            f"scans → LLM reviews) put the component reviews here: uncertain components first, then a second opinion on "
            f"blockers and rewrites. The queue runner (<code>containerizer llm-queue</code>) asks them one after another "
            f"when the settings below allow it. An answer shows here at once and is used by the next scan of its "
            f"repository; <b>Re-scan now</b> scans it without waiting for the schedule. Assessments already stored do not "
            f"change.</p>"
            f"<div class='formrow'><span>{state}</span> · <span>{e(lq.settings_text(settings))}</span></div>"
            f"{summary_html(totals(active, speed, settings, now), now)}"
            f"<nav class='chips'>{chips}</nav>"
            f"<h2>Queue</h2><table><thead><tr><th class='num'>#</th><th>Status</th><th>Job</th><th class='num'>Priority</th>"
            f"<th>Estimate</th><th>Queued</th><th>Order</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=7 class=muted>Nothing waiting.</td></tr>'}</tbody></table>"
            + ("<p class='muted small'>Show all kinds to move jobs up or down.</p>" if kind and queued else "")
            + (f"<h2>Answered: scan again</h2><p class='muted small'>Repositories whose reviews are all answered since "
               f"their last scan.</p><table><thead><tr><th>Repository</th><th class='num'>Answers</th><th>Last answer</th>"
               f"<th>Last scan</th><th></th></tr></thead><tbody>{''.join(ready)}</tbody></table>" if ready else "")
            + f"<h2>Finished</h2><table><thead><tr><th>Status</th><th>Job</th><th>Result</th><th>When</th><th></th></tr>"
              f"</thead><tbody>{''.join(finished) or '<tr><td colspan=5 class=muted>None yet.</td></tr>'}</tbody></table>"
            + f"<h2>Settings</h2>{settings_form(adm, s, settings)}"
            + f"<h2>Changes</h2>{adm._history(conn, 'LlmQueueSettings', 1)}")
    return Response(200, adm._shell(s, a, "LLM queue", "llm-queue", body, flash))


def show_job(adm, conn, s, a, ident: int, flash: str) -> Response:
    rows = _rows(conn, f"SELECT {JOB_COLS}, Payload, Result FROM cz.LlmJob WHERE JobId = %s", (ident,))
    if not rows:
        return _nf()
    r = rows[0]
    try:
        pl = json.loads(r["Payload"] or "{}")
    except ValueError:
        pl = {}
    try:
        res = json.loads(r["Result"]) if r.get("Result") else None
    except ValueError:
        res = None
    est = lq.load_speed(conn).job(r)
    meta = [("Kind", lq.kind_title(r["Kind"])), ("Status", STATUS_TEXT.get(r["Status"], r["Status"])),
            ("Why queued", lq.REASON_TEXT.get(r.get("Reason"), r.get("Reason"))), ("Repository", r.get("Repository")),
            ("Component", r.get("Component")), ("Project", r.get("ProjectPath")),
            ("Rules", f"{r['RuleVerdict']} (confidence {float(r['Confidence']):.2f})" if r.get("RuleVerdict") else None),
            ("Requested by", r.get("RequestedBy")), ("Model", r.get("Model")), ("Priority", r.get("Priority")),
            ("Estimate", estimate(est)), ("Actual", actual(r) or None), ("Answered by", r.get("Endpoint")),
            ("Attempts", r.get("Attempts")), ("Note", r.get("Note")), ("Error", r.get("Error"))]
    out = "".join(f"<div><span class='label'>{e(k)}</span> {e(str(v))}</div>" for k, v in meta if v not in (None, ""))
    answer = ""
    if res and r["Kind"] == lq.REVIEW:
        finds = "".join(f"<li>[{e(str(f.get('severity')))}] <b>{e(str(f.get('title')))}</b>: {e(str(f.get('why')))}"
                        f"{' <span class=muted>(agrees with the rules)</span>' if f.get('agrees_with_rule') else ''}</li>"
                        for f in res.get("findings") or [] if isinstance(f, dict))
        answer = (f"<h2>Answer</h2><p><b>{e(str(res.get('verdict')))}</b> (confidence "
                  f"{float(res.get('confidence') or 0):.2f})</p><p>{e(str(res.get('reasoning') or ''))}</p>"
                  + (f"<ul>{finds}</ul>" if finds else "")
                  + "<p class='muted small'>Used by the next scan of the repository: it changes the verdict when the LLM is "
                    "sure enough (0.6 for an uncertain component, 0.85 for a second opinion) and disagrees with the rules."
                    "</p>")
    elif r["Kind"] == lq.REFACTOR:
        answer = (f"<p><a class='button' href='/admin/refactoring/{ident}'>Open the refactoring patch</a> "
                  f"<span class='muted small'>the patch, what it fixed and how it was verified</span></p>")
    elif res is not None:
        answer = f"<h2>Result</h2><pre>{e(json.dumps(res, indent=1)[:20000])}</pre>"
    question = ""
    if pl.get("prompt"):
        question = f"<details><summary>Question sent to the LLM</summary><pre>{e(pl['prompt'][:30000])}</pre></details>"
    body = (f"<p><a href='{BASE}'>← LLM queue</a></p><div class='meta'>{out}</div>{answer}{question}"
            f"<h2>Changes</h2>{adm._history(conn, 'LlmJob', ident)}")
    return Response(200, adm._shell(s, a, f"LLM queue job #{ident}", "llm-queue", body, flash))


# --------------------------------------------------------------------------- actions

def move(conn, ident: int, action: str) -> Response:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT JobId, Priority, AdminRank FROM cz.LlmJob WITH (UPDLOCK, HOLDLOCK) WHERE Status = N'queued'")
    rows = cur.fetchall()
    if ident not in {r["JobId"] for r in rows}:
        conn.rollback()
        return _back(BASE, f"Job #{ident} is no longer queued.")
    c = conn.cursor()
    for jid, rank in lq.reorder(rows, ident, action).items():
        c.execute("UPDATE cz.LlmJob SET AdminRank = %s WHERE JobId = %s AND Status = N'queued'", (rank, jid))
    conn.commit()
    return _back(BASE, f"Job #{ident} moved {'to the ' if action in ('top', 'bottom') else ''}{action}.")


def skip(conn, ident: int) -> Response:
    cur = conn.cursor()
    cur.execute("UPDATE cz.LlmJob SET Status = N'skipped', FinishedAt = SYSUTCDATETIME(), Note = N'skipped by a person' "
                "WHERE JobId = %s AND Status = N'queued'", (ident,))
    n = cur.rowcount
    conn.commit()
    return _back(BASE, f"Job #{ident} skipped." if n else f"Job #{ident} is not queued (the runner may have taken it).")


def approve(conn, ident: int, user: str) -> Response:
    cur = conn.cursor()
    cur.execute("UPDATE cz.LlmJob SET Status = N'queued', ApprovedBy = %s, ApprovedAt = SYSUTCDATETIME() "
                "WHERE JobId = %s AND Status = N'approval'", (user, ident))
    n = cur.rowcount
    conn.commit()
    return _back(BASE, f"Job #{ident} approved: it is queued." if n else f"Job #{ident} does not wait for approval.")


def reject(conn, ident: int, user: str) -> Response:
    cur = conn.cursor()
    cur.execute("UPDATE cz.LlmJob SET Status = N'skipped', FinishedAt = SYSUTCDATETIME(), Note = %s "
                "WHERE JobId = %s AND Status = N'approval'", (f"rejected by {user}"[:400], ident))
    n = cur.rowcount
    conn.commit()
    return _back(BASE, f"Job #{ident} rejected." if n else f"Job #{ident} does not wait for approval.")


def requeue(conn, ident: int) -> Response:
    cur = conn.cursor()
    cur.execute("UPDATE cz.LlmJob SET Status = N'queued', Attempts = 0, NotBefore = NULL, Error = NULL, Note = NULL, "
                "FinishedAt = NULL WHERE JobId = %s AND Status IN (N'failed', N'skipped')", (ident,))
    n = cur.rowcount
    conn.commit()
    return _back(BASE, f"Job #{ident} queued again." if n else f"Job #{ident} is not failed or skipped.")


def rescan(conn, form: dict) -> Response:
    from .admin_scans import scan_now
    rid = form.get("RepositoryId", [""])[0]
    if not re.fullmatch(r"\d{1,9}", rid):
        return _back(BASE, "No repository selected.")
    return scan_now(conn, [], [int(rid)], BASE)


# --------------------------------------------------------------------------- settings

def settings_form(adm, s, v: dict) -> str:
    from .worker import DAYS
    days = "".join(f"<label class='check day'><input type='checkbox' name='day' value='{i}'"
                   f"{' checked' if int(v['WindowDays'] or 0) & (1 << i) else ''}> {d}</label>" for i, d in enumerate(DAYS))

    def t(m):
        return "" if m is None else f"{int(m) // 60:02d}:{int(m) % 60:02d}"

    def chk(name, label):
        return f"<label class='check'><input type='checkbox' name='{name}' value='1'{' checked' if v[name] else ''}> {label}</label>"
    return f"""<form method='post' action='{BASE}/settings' class='edit'>{adm._csrf(s)}
{chk('Paused', 'Paused (the runner starts no job; the one it is asking finishes)')}
<div class='days'>{days}</div>
<p class='muted small'>No day selected: every day.</p>
<label for='From'>From <span class='muted'>(UTC; both empty: all day; a window that ends before it starts runs past
midnight, e.g. 22:00 to 06:00)</span></label><input id='From' name='From' type='time' value='{t(v['WindowStart'])}'>
<label for='To'>To <span class='muted'>(UTC)</span></label><input id='To' name='To' type='time' value='{t(v['WindowEnd'])}'>
{chk('OnlyWhenIdle', 'Only when idle: no organization scan running and the machine not busy')}
<label for='MaxLoadPerCpu'>Busy above <span class='muted'>(1-minute load average per CPU; 0: do not look at the
load)</span></label><input id='MaxLoadPerCpu' name='MaxLoadPerCpu' type='number' min='0' max='16' step='0.05'
value='{float(v['MaxLoadPerCpu'] or 0):.2f}'>
<label for='Parallel'>Parallel requests <span class='muted'>(as many as the LLM server answers at once, e.g. its
slots; 1 for a CPU server)</span></label><input id='Parallel' name='Parallel' type='number' min='1' max='16'
value='{int(v['Parallel'] or 1)}'>
<h3>Approval</h3>
<p class='muted small'>Jobs of the kinds ticked here wait for an administrator to approve them before the runner
takes them, from the size given (estimated tokens the LLM must read; 0: all of them).</p>
<label class='check'><input type='checkbox' name='ApproveKind' value='refactor'{' checked' if 'refactor' in (v.get('ApproveKinds') or '') else ''}> Refactoring orders</label>
<label class='check'><input type='checkbox' name='ApproveKind' value='review'{' checked' if 'review' in (v.get('ApproveKinds') or '') else ''}> Component reviews from scans</label>
<label for='ApproveMinTokens'>From <span class='muted'>(estimated input tokens; 0: every job of those kinds)</span></label>
<input id='ApproveMinTokens' name='ApproveMinTokens' type='number' min='0' max='10000000' step='1000'
value='{int(v.get('ApproveMinTokens') or 0)}'>
<div><button>Save</button></div></form>"""


def validate_settings(form: dict) -> tuple[dict, list[str]]:
    errors, v = [], {}
    v["Paused"] = form.get("Paused", [""])[0] == "1"
    v["OnlyWhenIdle"] = form.get("OnlyWhenIdle", [""])[0] == "1"
    v["WindowDays"] = sum(1 << int(d) for d in set(form.get("day", [])) if re.fullmatch(r"[0-6]", d))
    times = []
    for k, label in (("From", "From"), ("To", "To")):
        raw = form.get(k, [""])[0].strip()
        m = TIME_RE.fullmatch(raw) if raw else None
        if raw and not m:
            errors.append(f"{label}: a time as HH:MM")
        times.append(int(m[1]) * 60 + int(m[2]) if m else None)
    if (times[0] is None) != (times[1] is None) and not errors:
        errors.append("Give both From and To, or leave both empty for all day")
    if times[0] is not None and times[0] == times[1]:
        errors.append("From and To are the same: leave both empty for all day")
    v["WindowStart"], v["WindowEnd"] = (times if None not in times else (None, None))
    try:
        load = float(form.get("MaxLoadPerCpu", ["0.5"])[0] or 0)
        if not 0 <= load <= 16:
            raise ValueError
    except ValueError:
        errors.append("Busy above: a number from 0 to 16")
        load = 0.5
    v["MaxLoadPerCpu"] = round(load, 2)
    p = form.get("Parallel", ["1"])[0].strip() or "1"
    if not re.fullmatch(r"\d{1,2}", p) or not 1 <= int(p) <= 16:
        errors.append("Parallel requests: 1 to 16")
        p = "1"
    v["Parallel"] = int(p)
    kinds = sorted({k for k in form.get("ApproveKind", []) if k in ("refactor", "review")})
    v["ApproveKinds"] = ",".join(kinds) or None
    m = form.get("ApproveMinTokens", ["0"])[0].strip() or "0"
    if not re.fullmatch(r"\d{1,8}", m) or int(m) > 10_000_000:
        errors.append("Approval from: a number of tokens, 0 to 10,000,000")
        m = "0"
    v["ApproveMinTokens"] = int(m)
    return v, errors


SETTING_COLS = ("Paused", "WindowDays", "WindowStart", "WindowEnd", "OnlyWhenIdle", "MaxLoadPerCpu", "Parallel",
                "ApproveKinds", "ApproveMinTokens")


def save_settings(conn, form: dict) -> Response:
    v, errors = validate_settings(form)
    if errors:
        return _back(BASE, "; ".join(errors))
    cur = conn.cursor()
    cur.execute("UPDATE cz.LlmQueueSettings SET " + ", ".join(f"{k} = %s" for k in SETTING_COLS)
                + ", ChangedAt = SYSUTCDATETIME() WHERE SettingsId = 1", tuple(v[k] for k in SETTING_COLS))
    conn.commit()
    return _back(BASE, "Saved. The runner uses the new settings before it starts its next job.")
