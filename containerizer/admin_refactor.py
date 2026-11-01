"""Admin → Refactoring (refactor.py, docs/refactoring.md): administrators and operators.

- POST /admin/refactoring/new: order a refactoring patch of a B-rated application (all the components that
  need changes, or one), from the results page's Refactoring box. The order goes into the LLM queue as a
  job of kind `refactor`, with the findings of the latest assessment, its commit and where the scan
  worker keeps the repository's clone.
- /admin/refactoring: the orders and their status (queued, generating, verifying, verified, applies only,
  failed, cancelled).
- /admin/refactoring/<id>: one order: what was fixed and what not, the verification (with the build and run
  log tail), the patch as a coloured diff per file, Download .patch and how to apply it.
- /admin/refactoring/<id>.patch: the patch (`git am` applies it).

Same conventions as admin.py: plain HTML forms with the session's CSRF token, no JavaScript, everything
escaped. Patches contain source code: they are shown to administrators and operators only; the results
page shows everyone else an order's status.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from urllib.parse import urlencode

from .admin import Response, _d, e, redirect
from .admin_scans import _back, _nf
from . import refactor as rf

BASE = "/admin/refactoring"
STATUS_CSS = {"queued": "st-run", "generating": "st-run", "verifying": "st-run", "verified": "st-ok",
              "applies-only": "st-warn", "failed": "st-bad", "cancelled": "st-off"}
FINDING_TEXT = {"fixed": "Fixed", "not-fixed": "Not fixed", "llm-error": "LLM error", "skipped": "Not attempted"}
FINDING_CSS = {"fixed": "st-ok", "not-fixed": "st-off", "llm-error": "st-bad", "skipped": "st-off"}
AFTER_TEXT = {"resolved": "gone from this file", "partly": "fewer places", "still found": "still found"}
VERIFY_TEXT = {"ok": "Builds and runs", "ok-external": "Builds and runs (without its external services)",
               "build-failed": "Build failed", "run-failed": "Run failed", "finding": "Runs into a finding",
               "not-built": "Not built", "error": "Could not verify", "failed": "Failed"}
COLS = ("JobId, Status, Summary, Error, Note, App, Repository, Component, ProjectPath, ApplicationId, AssessmentId, "
        "SourceKey, RequestedBy, Model, Endpoint, InputTokens, OutputTokens, EstInputTokens, Seconds, Attempts, "
        "QueuedAt, StartedAt, FinishedAt")


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict, flash: str) -> Response:
    if not (a.admin or a.operator):                 # the tab is theirs only; checked here too
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    if len(parts) == 1 and method == "GET":
        return show_list(adm, conn, s, a, flash)
    if len(parts) == 2 and parts[1] == "new" and method == "POST":
        return order(adm, conn, s, a, form)
    if len(parts) == 2 and method == "GET":
        m = re.fullmatch(r"(\d{1,9})(\.patch)?", parts[1])
        if m:
            return download(conn, int(m[1])) if m[2] else show_order(adm, conn, s, a, int(m[1]), flash)
    return _nf()


# --------------------------------------------------------------------------- helpers

def chip(status: str) -> str:
    return f"<span class='st {STATUS_CSS.get(status, '')}'>{e(rf.STATUS_TEXT.get(status, status))}</span>"


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def _json(s) -> dict:
    try:
        return json.loads(s) if s else {}
    except (TypeError, ValueError):
        return {}


def status_of(r: dict, res: dict | None = None) -> str:
    st = r.get("PatchStatus")
    if st is None and res is not None:
        st = res.get("status")
    return rf.order_status(r["Status"], r.get("Summary"), st)


def load_order(conn, ident: int) -> dict | None:
    rows = _rows(conn, f"SELECT {COLS}, Payload, Result FROM cz.LlmJob WHERE JobId = %s AND Kind = N'refactor'", (ident,))
    return rows[0] if rows else None


# --------------------------------------------------------------------------- the diff

def render_diff(text: str, max_lines: int = 4000) -> str:
    """A unified diff (format-patch) as HTML: per file a header (name, status, +added -removed) and a table
    of its hunks with old and new line numbers; added, removed and context lines have their own classes.
    Everything is escaped."""
    p = rf.parse_patch(text or "")
    if not p["files"]:
        return "<p class='muted'>No changes.</p>"
    out, shown = [], 0
    for f in p["files"]:
        name = f["new"] if f["status"] != "deleted" else f["old"]
        status = {"added": "new file", "deleted": "deleted", "renamed": f"renamed from {f['old']}"}.get(f["status"], "")
        head = (f"<div class='diff-file'><b>{e(name)}</b>"
                + (f" <span class='muted small'>{e(status)}</span>" if status else "")
                + f" <span class='diff-stat'><span class='diff-add'>+{int(f['added'])}</span> "
                  f"<span class='diff-del'>-{int(f['removed'])}</span></span></div>")
        if f["binary"]:
            out.append(f"<section class='diff'>{head}<p class='muted small'>Binary file (in the patch).</p></section>")
            continue
        rows = []
        for h in f["hunks"]:
            rows.append(f"<tr class='hunk'><td class='ln'></td><td class='ln'></td><td>{e(h['head'])}</td></tr>")
            for kind, old, new, t in h["lines"]:
                shown += 1
                if shown > max_lines:
                    break
                sign = {"add": "+", "del": "-", "ctx": " ", "note": ""}[kind]
                rows.append(f"<tr class='{kind}'><td class='ln'>{'' if old is None else int(old)}</td>"
                            f"<td class='ln'>{'' if new is None else int(new)}</td>"
                            f"<td><span class='sign'>{sign}</span>{e(t)}</td></tr>")
        out.append(f"<section class='diff'>{head}<table class='diff'><tbody>{''.join(rows)}</tbody></table></section>")
    if shown > max_lines:
        out.append(f"<p class='muted small'>The patch has more lines than shown here ({max_lines}): download it to see "
                   f"all of it.</p>")
    return "".join(out)


def how_to_apply(commit: str | None, filename: str) -> str:
    c = e(str(commit or "<commit>")[:12])
    f = e(filename)
    return (f"<h2>How to apply</h2><ol class='steps'>"
            f"<li>In a checkout of the repository, start a branch at the assessed commit:"
            f"<pre class='code'>git checkout -b containerizer-refactor {c}</pre></li>"
            f"<li>Apply the patch as a commit (it keeps Windows line endings as they are):"
            f"<pre class='code'>git am --keep-cr &lt; {f}</pre>"
            f"If your branch has moved on since that commit, apply it to your branch with a three-way merge "
            f"instead:<pre class='code'>git apply --3way {f}</pre></li>"
            f"<li>Review every change. The patch was written by an LLM: it may be wrong in ways the build does not show.</li>"
            f"<li>Build and run your tests, and set the configuration the notes mention (paths, certificates, "
            f"credentials) in the deployment.</li>"
            f"<li>Push the branch and open a pull request yourself: Containerizer never writes to your repository.</li>"
            f"</ol>")


# --------------------------------------------------------------------------- pages

def show_list(adm, conn, s, a, flash: str) -> Response:
    rows = _rows(conn, f"SELECT TOP (200) {COLS}, JSON_VALUE(Result, '$.status') AS PatchStatus FROM cz.LlmJob "
                       "WHERE Kind = N'refactor' ORDER BY JobId DESC")
    out = []
    for r in rows:
        st = status_of(r)
        target = " / ".join(x for x in (r.get("App"), r.get("Component") or "all components") if x)
        when = _d(r["FinishedAt"]) if r.get("FinishedAt") else f"queued {_d(r['QueuedAt'])}"
        dl = (f"<a href='{BASE}/{int(r['JobId'])}.patch'>.patch</a>"
              if st in ("verified", "applies-only") else "")
        out.append(f"<tr><td class='num'>{int(r['JobId'])}</td><td><a href='{BASE}/{int(r['JobId'])}'>{e(target)}</a></td>"
                   f"<td>{chip(st)}</td><td class='small'>{e(r.get('Summary') or r.get('Error') or '')}</td>"
                   f"<td class='small'>{e(r.get('RequestedBy') or '')}</td><td class='small nowrap'>{when}</td>"
                   f"<td>{dl}</td></tr>")
    body = ("<p class='muted'>Refactoring patches for B-rated applications: the LLM changes the code for the findings "
            "that need targeted code changes, and the patch is applied, checked with the rules and built and run "
            "before it is offered. Order one on the application's results page (<b>Refactoring</b>). Orders wait in "
            "the <a href='/admin/llm-queue?kind=refactor'>LLM queue</a>.</p>"
            "<table><thead><tr><th class='num'>#</th><th>Application / component</th><th>Status</th><th>Result</th>"
            "<th>Requested by</th><th>When</th><th></th></tr></thead>"
            f"<tbody>{''.join(out) or '<tr><td colspan=7 class=muted>No orders yet.</td></tr>'}</tbody></table>")
    return Response(200, adm._shell(s, a, "Refactoring", "refactoring", body, flash))


def _findings_table(res: dict) -> str:
    rows = []
    for f in res.get("findings") or []:
        st = f.get("status") or "not-fixed"
        after = AFTER_TEXT.get(f.get("rules_after"), "")
        rows.append(f"<tr><td><span class='st {FINDING_CSS.get(st, '')}'>{e(FINDING_TEXT.get(st, st))}</span></td>"
                    f"<td><b>{e(f.get('rule'))}</b> <span class='sev s-{e(f.get('severity') or '')}'>{e(f.get('severity') or '')}</span>"
                    f"<div class='small'>{e(f.get('title') or '')}</div></td>"
                    f"<td class='small'><code>{e(f.get('file') or '')}</code><div class='muted'>{e(f.get('component') or '')}</div></td>"
                    f"<td class='small'>{e(after) or '<span class=muted>-</span>'}</td>"
                    f"<td class='small'>{e(f.get('reason') or '')}"
                    + ("<span class='muted'>the LLM did not name it; the rules confirm it is gone</span>"
                       if f.get("confirmed_by") == "rules" else "") + "</td></tr>")
    if not rows:
        return ""
    return ("<h2>Findings</h2><table><thead><tr><th>Result</th><th>Finding</th><th>File</th><th>Rules on the patched "
            "copy</th><th>Why not</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _verification(res: dict, st: str) -> str:
    if not res.get("patch") and st == "failed":
        log = res.get("apply_log")
        return (f"<h2>Verification</h2><p><b>No patch:</b> {e(res.get('reason') or 'no usable edits')}</p>"
                + (f"<pre class='code'>{e(log)}</pre>" if log else ""))
    parts = ["<h2>Verification</h2><ul class='checks'><li><b>Applies cleanly</b> to commit "
             f"<code>{e(str(res.get('commit') or '')[:12])}</code> (<code>git apply --check</code>, then <code>git am</code>)</li>"]
    if not res.get("verify", True):
        parts.append("<li>Not built: verification was off for this order.</li>")
    for v in res.get("verification") or []:
        ok = v.get("status") in ("ok", "ok-external")
        parts.append(f"<li><span class='st {'st-ok' if ok else 'st-bad'}'>{e(VERIFY_TEXT.get(v.get('status'), v.get('status')))}</span> "
                     f"<b>{e(v.get('component'))}</b>"
                     + (f" <span class='muted small'>{e(v.get('detail'))}</span>" if v.get("detail") else "")
                     + (f" <span class='muted small'>(smoke test without production services)</span>" if v.get("mode") == "smoke" else "")
                     + (f"<details><summary>Log tail</summary><pre class='code'>{e(v['log_tail'])}</pre></details>"
                        if v.get("log_tail") else "") + "</li>")
    parts.append("</ul>")
    new = res.get("new_findings") or []
    if new:
        parts.append("<p class='note'><b>New findings on the patched copy:</b> "
                     + ", ".join(f"{e(n.get('component'))}: <code>{e(n.get('rule'))}</code>" for n in new)
                     + ". Check whether the patch caused them.</p>")
    return "".join(parts)


def show_order(adm, conn, s, a, ident: int, flash: str) -> Response:
    r = load_order(conn, ident)
    if r is None:
        return _nf()
    pl, res = _json(r.get("Payload")), _json(r.get("Result"))
    st = status_of(r, res)
    took = f"{float(r['Seconds']) / 60:.0f} min" if r.get("Seconds") else None
    tokens = (f"{int(r['InputTokens'] or 0):,} in / {int(r['OutputTokens'] or 0):,} out"
              if r.get("InputTokens") is not None or r.get("OutputTokens") is not None else
              (f"~{int(r['EstInputTokens']):,} in (estimated)" if r.get("EstInputTokens") else None))
    app = (f"<a href='/app/{int(r['ApplicationId'])}'>{e(r.get('App') or '')}</a>" if r.get("ApplicationId")
           else e(r.get("App") or ""))
    meta = [("Application", app), ("Component", e(r.get("Component") or "all components that need changes")),
            ("Commit", f"<code>{e(str(pl.get('commit') or '')[:12])}</code>" if pl.get("commit") else None),
            ("Status", chip(st)), ("Requested by", e(r.get("RequestedBy") or "")),
            ("LLM", e(res.get("model") or r.get("Endpoint") or "")), ("LLM calls", e(str(res.get("calls"))) if res else None),
            ("Tokens", e(tokens) if tokens else None), ("Time", e(took) if took else None),
            ("Queued", _d(r["QueuedAt"])), ("Finished", _d(r["FinishedAt"]) if r.get("FinishedAt") else None),
            ("Queue job", f"<a href='/admin/llm-queue/{ident}'>#{ident}</a>")]
    head = "".join(f"<div><span class='label'>{e(k)}</span> {v}</div>" for k, v in meta if v)
    body = [f"<p><a href='{BASE}'>← Refactoring</a></p><div class='meta'>{head}</div>"]
    if st in ("queued", "generating", "verifying"):
        body.append(f"<p class='note'><b>{e(rf.STATUS_TEXT[st])}.</b> "
                    + (e(r.get("Summary") or "") if st != "queued" else
                       "The queue runner takes it when the LLM queue's settings let it (Admin → LLM queue). A CPU-only "
                       "LLM takes several minutes per file.")
                    + (f"<br><span class='muted small'>last try: {e(r['Error'])}</span>" if r.get("Error") else "")
                    + " Reload the page to see how far it is.</p>")
    elif st == "cancelled":
        body.append(f"<p class='note'>Cancelled: {e(r.get('Note') or 'skipped on the LLM queue page')}.</p>")
    elif r["Status"] == "failed":
        body.append(f"<p class='note'><b>Failed:</b> {e(r.get('Error') or '')}</p>")
    if res.get("patch") and st in ("verified", "applies-only"):
        label = "Verified: it applies, builds and runs." if st == "verified" else \
            f"Applies only: {res.get('reason') or 'the build or the run did not succeed'}."
        body.append(f"<div class='formrow'><a class='button' href='{BASE}/{ident}.patch' download>Download .patch</a>"
                    f"<span class='muted small'>{e(res.get('filename') or '')} · {e(label)}</span></div>")
    if res:
        body.append(_findings_table(res))
        if res.get("notes"):
            body.append("<h3>Notes from the LLM</h3><ul>" + "".join(f"<li class='small'>{e(n)}</li>" for n in res["notes"]) + "</ul>")
        body.append(_verification(res, st))
        if res.get("patch") and st in ("verified", "applies-only"):
            files = res.get("files") or []
            body.append(f"<h2>Changes</h2><p class='muted small'>{len(files)} file{'s' if len(files) != 1 else ''}: "
                        f"+{sum(int(f.get('added') or 0) for f in files)} "
                        f"-{sum(int(f.get('removed') or 0) for f in files)} lines</p>{render_diff(res['patch'])}")
            body.append(how_to_apply(res.get("commit") or pl.get("commit"), res.get("filename") or "containerizer.patch"))
        skipped = res.get("skipped") or pl.get("skipped") or []
    else:
        skipped = pl.get("skipped") or []
        tasks = pl.get("tasks") or []
        if tasks:
            body.append("<h2>What it will change</h2><ul>" + "".join(
                f"<li><code>{e(t.get('file'))}</code>: " + ", ".join(e(f.get("rule")) for f in t.get("findings") or [])
                + "</li>" for t in tasks) + "</ul>")
    if skipped:
        body.append("<details><summary>Findings not sent to the LLM</summary><ul>" + "".join(
            f"<li class='small'><b>{e(x.get('rule'))}</b> ({e(x.get('component'))}): {e(x.get('reason'))}</li>" for x in skipped)
            + "</ul></details>")
    body.append(f"<h2>History</h2>{adm._history(conn, 'LlmJob', ident)}")
    title = f"Refactoring #{ident}: {r.get('App') or ''}" + (f" / {r['Component']}" if r.get("Component") else "")
    return Response(200, adm._shell(s, a, title, "refactoring", "".join(body), flash))


def download(conn, ident: int) -> Response:
    r = load_order(conn, ident)
    res = _json(r.get("Result")) if r else {}
    if not r or not res.get("patch") or status_of(r, res) not in ("verified", "applies-only"):
        return Response(404, "No patch for this order.\n", ctype="text/plain; charset=utf-8")
    data = base64.b64decode(res["patch_b64"]) if res.get("patch_b64") else res["patch"].encode("utf-8")
    name = rf.patch_filename(res.get("app") or r.get("App"), res.get("component") or r.get("Component"))
    return Response(200, data, [("Content-Disposition", f'attachment; filename="{name}"')],
                    ctype="text/x-diff; charset=utf-8")


# --------------------------------------------------------------------------- ordering

def order_source(conn, app: dict) -> dict | None:
    """Where the runner finds the application's source: the scan worker's clone of the repository the
    organization scan that assessed it keeps (None: no organization scan here has it)."""
    if not app.get("RepositoryUrl"):
        return None
    rows = _rows(conn, "SELECT TOP (1) ScanId, AppName FROM cz.OrgRepository WHERE RepositoryUrl = %s AND RemovedAt IS NULL "
                       "AND AppName IS NOT NULL ORDER BY LastScannedAt DESC, RepositoryId DESC", (app["RepositoryUrl"],))
    if not rows or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", str(rows[0]["AppName"] or "")):
        return None
    sid = int(rows[0]["ScanId"])
    return {"type": "org-clone", "scan_id": sid, "dir": f"scan-{sid}/repos/{rows[0]['AppName']}",
            "subdir": app.get("SourcePath") or "."}


def _to_app(app_id: int, code: str, **extra) -> Response:
    """Back to the application's results page, where the order was placed: a status code, which the page turns
    into one of its own fixed messages (webui.REFACTOR_NOTICES), so a link cannot make it show any text."""
    q = urlencode({"refactor": code, **{k: int(v) for k, v in extra.items()}})
    return redirect(f"/app/{int(app_id)}?{q}#refactoring")


def order(adm, conn, s, a, form: dict) -> Response:
    from .llmqueue import SqlJobQueue
    app_id = adm._id(form, "ApplicationId")
    if app_id is None:
        return _back(BASE, "No application selected.")
    rows = _rows(conn, "SELECT ApplicationId, ApplicationName, ScanName, AssessmentId, Rating, SourceCommit, RepositoryUrl, "
                       "SourcePath FROM cz.vApplicationLatest WHERE ApplicationId = %s", (app_id,))
    if not rows:
        return _back(BASE, "No such application.")
    app = rows[0]
    if app["Rating"] != "B":
        return _to_app(app_id, "not-b")
    comp_raw = form.get("Component", [""])[0]
    component = None
    if comp_raw:
        if not re.fullmatch(r"\d{1,9}", comp_raw):
            return _to_app(app_id, "no-component")
        c = _rows(conn, "SELECT ProjectPath FROM cz.Component WHERE ComponentId = %s AND ApplicationId = %s",
                  (int(comp_raw), app_id))
        if not c:
            return _to_app(app_id, "no-component")
        component = c[0]["ProjectPath"]
    if not app.get("SourceCommit"):
        return _to_app(app_id, "no-commit")
    source = order_source(conn, app)
    if source is None:
        return _to_app(app_id, "no-source")
    rep = _rows(conn, "SELECT ReportJson FROM cz.ApplicationAssessment WHERE AssessmentId = %s", (app["AssessmentId"],))
    doc = _json(rep[0]["ReportJson"]) if rep else {}
    key = _rows(conn, "SELECT SourceKey FROM cz.Application WHERE ApplicationId = %s", (app_id,))
    try:
        payload = rf.build_payload(doc, source, app["SourceCommit"], component=component,
                                   include_config=form.get("IncludeConfig", [""])[0] == "1", application_id=app_id,
                                   assessment_id=int(app["AssessmentId"]),
                                   source_key=key[0]["SourceKey"] if key else None)
    except rf.RefactorError as ex:
        print(f"refactoring order for application {app_id} refused: {ex}", file=sys.stderr)
        return _to_app(app_id, "nothing" if "nothing" in str(ex).lower() else "failed")
    payload["app"] = app.get("ScanName") or payload.get("app")
    job = rf.queue_job(payload, rf.estimate_chars(payload), requested_by=None)     # None: the signed-in person
    job["Repository"] = app["ApplicationName"]
    jid = SqlJobQueue(None).add_with(conn, job)
    if not jid:
        same = _rows(conn, "SELECT TOP (1) JobId FROM cz.LlmJob WHERE Kind = N'refactor' AND DedupeKey = %s "
                           "AND Status IN (N'queued', N'running') ORDER BY JobId DESC", (job["DedupeKey"],))
        return _to_app(app_id, "exists", **({"job": int(same[0]["JobId"])} if same else {}))
    n = min(len(payload["tasks"]), payload["max_calls"])
    return _to_app(app_id, "ordered", job=int(jid), files=n)
