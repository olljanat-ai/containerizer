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
- "Make it A" (goal rating-a, docs/refactoring.md#make-it-a): the order page shows the loop (passes, repair
  rounds), the rating before and after, and the sandbox variant (variant.py) with its URL and
  POST /admin/refactoring/<id>/remove ("Remove from the sandbox": administrators, operators and the
  application's product owners; the queue runner removes it).
- /admin/refactoring/make-all-a (administrators): "Make all B apps A": a confirmation page with every B-rated
  application, its estimate and the total, and how many orders will wait for approval; POST queues one order
  per application.

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
STATUS_CSS = {"queued": "st-run", "generating": "st-run", "verifying": "st-run", "deploying": "st-run",
              "verified": "st-ok", "applies-only": "st-warn", "failed": "st-bad", "cancelled": "st-off",
              "approval": "st-wait"}
SANDBOX_CSS = {"deploying": "st-run", "running": "st-ok", "failing": "st-bad", "deployed": "st-warn",
               "skipped": "st-off", "error": "st-bad", "removed": "st-off", "expired": "st-off"}
URL_RE = re.compile(r"https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::\d{1,5})?/[A-Za-z0-9._~/-]{0,200}")
# what the order page says after an action: fixed texts chosen by a code in the URL
ORDER_NOTICES = {"remove-requested": "Removal requested: the LLM queue runner takes the variant out of the sandbox "
                                     "within a few minutes (its folder is deleted from the output repository).",
                 "remove-not-active": "This order has nothing running in the sandbox.",
                 "remove-unavailable": "Removal needs the database schema of this version: run `containerizer db init`."}
# what the Refactoring list says after "Make all B apps A": {q}, {w}, {x}, {n} are numbers
BULK_NOTICES = {"queued": "\"Make it A\" requested for {q} application(s): {w} wait for an administrator's approval; "
                          "{x} already had one waiting; {n} could not be ordered.",
                "none": "No B-rated application could be ordered."}
FINDING_TEXT = {"fixed": "Fixed", "not-fixed": "Not fixed", "llm-error": "LLM error", "skipped": "Not attempted"}
FINDING_CSS = {"fixed": "st-ok", "not-fixed": "st-off", "llm-error": "st-bad", "skipped": "st-off"}
AFTER_TEXT = {"resolved": "gone from this file", "partly": "fewer places", "still found": "still found"}
VERIFY_TEXT = {"ok": "Builds and runs", "ok-external": "Builds and runs (without its external services)",
               "build-failed": "Build failed", "run-failed": "Run failed", "finding": "Runs into a finding",
               "not-built": "Not built", "error": "Could not verify", "failed": "Failed"}
COLS = ("JobId, Status, Summary, Error, Note, App, Repository, Component, ProjectPath, ApplicationId, AssessmentId, "
        "SourceKey, RequestedBy, Model, Endpoint, InputChars, InputTokens, OutputTokens, EstInputTokens, Seconds, Attempts, "
        "QueuedAt, StartedAt, FinishedAt, JSON_VALUE(Result, '$.verification[0].status') AS VerifyStatus")


def allowed_app(a, conn, app_id) -> bool:
    """Administrators and operators: every application; product owners: the ones of their products."""
    if a.admin or a.operator:
        return True
    if not a.owner or app_id is None:
        return False
    r = _rows(conn, "SELECT ProductId FROM cz.Application WHERE ApplicationId = %s", (int(app_id),))
    return bool(r) and r[0]["ProductId"] in a.products


def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict, flash: str) -> Response:
    if not (a.admin or a.operator or a.owner):      # product owners: their products' applications only
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    if len(parts) == 1 and method == "GET":
        return show_list(adm, conn, s, a, bulk_notice(q) or flash)
    if len(parts) == 2 and parts[1] == "new" and method == "POST":
        return order(adm, conn, s, a, form)
    if len(parts) == 2 and parts[1] == "make-all-a":
        if not a.admin:
            return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Only administrators order \"Make it A\" for every "
                                                                      "application.</p>"))
        return make_all_a(adm, conn, s, a) if method == "GET" else make_all_a_post(adm, conn, s, a) \
            if method == "POST" else _nf()
    m = re.fullmatch(r"(\d{1,9})(\.patch)?", parts[1]) if len(parts) >= 2 else None
    if m:
        r = load_order(conn, int(m[1]))
        if r is None or not allowed_app(a, conn, r.get("ApplicationId")):
            return _nf()
        if len(parts) == 2 and method == "GET":
            code = (q.get("notice") or [""])[0]
            return download(conn, int(m[1])) if m[2] else show_order(adm, conn, s, a, int(m[1]),
                                                                     ORDER_NOTICES.get(code, flash))
        if len(parts) == 3 and parts[2] == "repair" and method == "POST" and not m[2]:
            return repair(adm, conn, s, a, r)
        if len(parts) == 3 and parts[2] == "remove" and method == "POST" and not m[2]:
            return remove_variant(adm, conn, s, a, r)
    return _nf()


def repairable(st: str, res: dict) -> bool:
    """A patch that applies but did not build or run: the LLM can be asked to fix it."""
    return st == "applies-only" and bool(res.get("patch")) and any(
        v.get("status") in ("build-failed", "run-failed") for v in res.get("verification") or [])


def repair(adm, conn, s, a, r: dict) -> Response:
    from .llmqueue import SqlJobQueue
    pl, res = _json(r.get("Payload")), _json(r.get("Result"))
    if not repairable(status_of(r, res), res):
        return _back(f"{BASE}/{int(r['JobId'])}", "Only a patch that applies but does not build or run can be fixed.")
    try:
        payload = rf.repair_payload(pl, res, int(r["JobId"]))
    except rf.RefactorError as ex:
        return _back(f"{BASE}/{int(r['JobId'])}", str(ex))
    chars = len(payload["base_patch"]) + 6000 * max(1, len({x["file"] for x in payload["errors"]}))
    job = rf.queue_job(payload, chars, requested_by=None)
    job["Repository"] = r.get("Repository") or r.get("App")
    jid = SqlJobQueue(None).add_with(conn, job)
    if not jid:
        return _back(f"{BASE}/{int(r['JobId'])}", "A fix of this patch is already requested.")
    st = _rows(conn, "SELECT Status FROM cz.LlmJob WHERE JobId = %s", (jid,))
    wait = st and st[0]["Status"] == "approval"
    return _back(f"{BASE}/{jid}", "Fix requested: " + ("it waits for an administrator's approval."
                                                       if wait else "it waits in the LLM queue."))


def remove_variant(adm, conn, s, a, r: dict) -> Response:
    """"Remove from the sandbox": the request is recorded (RemoveRequestedAt); the queue runner, which holds the
    output repository's write token, removes the variant (variant.housekeep)."""
    from .variant import ACTIVE
    jid = int(r["JobId"])
    sb = (_json(r.get("Result")).get("sandbox") or {})
    if sb.get("status") not in ACTIVE or sb.get("removed_at"):
        return redirect(f"{BASE}/{jid}?notice=remove-not-active")
    try:
        cur = conn.cursor()
        cur.execute("UPDATE cz.LlmJob SET RemoveRequestedAt = SYSUTCDATETIME(), RemoveRequestedBy = %s "
                    "WHERE JobId = %s AND Kind = N'refactor' AND RemoveRequestedAt IS NULL", (s.user, jid))
        conn.commit()
    except Exception as ex:  # noqa: BLE001 - a database from before schema 23
        print(f"refactoring #{jid}: removal not recorded: {type(ex).__name__}: {ex}", file=sys.stderr)
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return redirect(f"{BASE}/{jid}?notice=remove-unavailable")
    return redirect(f"{BASE}/{jid}?notice=remove-requested")


def bulk_notice(q: dict) -> str:
    code = (q.get("bulk") or [""])[0]
    if code not in BULK_NOTICES:
        return ""
    text = BULK_NOTICES[code]
    for k in ("q", "w", "x", "n"):
        v = (q.get(k) or [""])[0]
        text = text.replace("{" + k + "}", str(int(v)) if re.fullmatch(r"\d{1,6}", v or "") else "0")
    return text


# --------------------------------------------------------------------------- helpers

def chip(status: str, verify=()) -> str:
    """The status chip; a patch that applies but is not verified says why, with the explanation as a tooltip."""
    label, why = rf.status_label(status, verify)
    tip = f" title='{e(why)}'" if why else ""
    return f"<span class='st {STATUS_CSS.get(status, '')}'{tip}>{e(label)}</span>"


def verify_of(r: dict, res: dict | None = None) -> list:
    if res and res.get("verification"):
        return [v.get("status") for v in res["verification"]]
    return [r.get("VerifyStatus")] if r.get("VerifyStatus") else []


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

def sandbox_chip(sb: dict | None, requested: bool = False) -> str:
    """The sandbox variant's state as a chip (fixed texts)."""
    from .variant import STATUS_TEXT
    if not sb or not sb.get("status"):
        return ""
    st = sb["status"]
    label = STATUS_TEXT.get(st, st)
    if requested and st in ("running", "failing", "deployed"):
        label += " (removal requested)"
    return f"<span class='st {SANDBOX_CSS.get(st, '')}'>{e(label)}</span>"


def safe_url(u) -> str | None:
    return u if isinstance(u, str) and URL_RE.fullmatch(u) else None


def show_list(adm, conn, s, a, flash: str) -> Response:
    rows = _rows(conn, f"SELECT TOP (200) {COLS}, JSON_VALUE(Result, '$.status') AS PatchStatus, "
                       "JSON_VALUE(Payload, '$.goal') AS Goal, JSON_VALUE(Result, '$.sandbox.status') AS SandboxStatus "
                       "FROM cz.LlmJob WHERE Kind = N'refactor' ORDER BY JobId DESC")
    if not (a.admin or a.operator):
        rows = [r for r in rows if allowed_app(a, conn, r.get("ApplicationId"))]
    out = []
    for r in rows:
        st = status_of(r)
        target = " / ".join(x for x in (r.get("App"), r.get("Component") or "all components") if x)
        if r.get("Goal") == "rating-a":
            target = f"{r.get('App') or ''}: Make it A"
        when = _d(r["FinishedAt"]) if r.get("FinishedAt") else f"queued {_d(r['QueuedAt'])}"
        dl = (f"<a href='{BASE}/{int(r['JobId'])}.patch'>.patch</a>"
              if st in ("verified", "applies-only") else "")
        out.append(f"<tr><td class='num'>{int(r['JobId'])}</td><td><a href='{BASE}/{int(r['JobId'])}'>{e(target)}</a></td>"
                   f"<td>{chip(st, verify_of(r))} {sandbox_chip({'status': r.get('SandboxStatus')})}</td>"
                   f"<td class='small'>{e(r.get('Summary') or r.get('Error') or '')}</td>"
                   f"<td class='small'>{e(r.get('RequestedBy') or '')}</td><td class='small nowrap'>{when}</td>"
                   f"<td>{dl}</td></tr>")
    bulk = (f"<p><a class='button' href='{BASE}/make-all-a'>Make all B apps A…</a> <span class='muted small'>A "
            f"confirmation page lists every B-rated application with its estimate first.</span></p>" if a.admin else "")
    body = (bulk + "<p class='muted'>Refactoring patches for B-rated applications: the LLM changes the code for the findings "
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


KIND_TEXT = {"generate": "Changes for the findings", "repair": "Repair of the build or run"}


def _make_it_a(res: dict, pl: dict, st: str) -> str:
    """The "Make it A" loop: the rating before and after, each pass and repair round, and what is left."""
    from .webui import badge
    before = res.get("rating_before") or pl.get("rating") or "B"
    after = res.get("rating_after")
    out = ["<h2>Make it A</h2>"]
    if res:
        reached = bool(res.get("rating_reached"))
        out.append(f"<p class='rating-change'>{badge(before)} → {badge(after) if after else '<span class=muted>?</span>'} "
                   + ("<b>Rating A reached.</b>" if reached else
                      "<b>Still " + e(after) + ".</b>" if after else "<b>Not assessed again.</b>") + "</p>")
        lim = res.get("limits") or {}
        rows = "".join(
            f"<tr><td class='num'>{int(x.get('pass') or 0)}</td><td class='num'>{int(x.get('round') or 0)}</td>"
            f"<td>{e(KIND_TEXT.get(x.get('kind'), x.get('kind') or ''))}</td><td class='num'>{int(x.get('files') or 0)}</td>"
            f"<td class='num'>{int(x.get('calls') or 0)}</td><td class='num'>{int(x.get('changes') or 0)}</td>"
            f"<td class='small'>{e(', '.join(str(v.get('component')) + ': ' + VERIFY_TEXT.get(v.get('status'), str(v.get('status'))) for v in x.get('verification') or []))}</td>"
            f"<td>{badge(x['rating']) if x.get('rating') else ''}</td></tr>" for x in res.get("loop") or [])
        if rows:
            out.append("<table><thead><tr><th class='num'>Pass</th><th class='num'>Round</th><th>Step</th>"
                       "<th class='num'>Files</th><th class='num'>LLM calls</th><th class='num'>Changes</th>"
                       "<th>Build and run</th><th>Rating</th></tr></thead><tbody>" + rows + "</tbody></table>")
        if lim:
            out.append(f"<p class='muted small'>Limits: {int(lim.get('max_calls') or 0)} LLM calls, "
                       f"{int(lim.get('max_passes') or 0)} passes, {int(lim.get('max_repairs') or 0)} repair rounds a pass; "
                       f"{int(res.get('calls') or 0)} calls made.</p>")
        if not reached and res.get("still_state"):
            out.append("<p class='note'><b>Still keeps its own data:</b> " + "; ".join(
                f"{e(x.get('component'))} ({e(', '.join(x.get('state') or []))})" for x in res["still_state"]) + "</p>")
        if not reached and res.get("remaining"):
            out.append("<p class='note'><b>Still found:</b> " + ", ".join(
                f"{e(x.get('component'))}: <code>{e(x.get('rule'))}</code>" for x in res["remaining"][:30]) + "</p>")
    else:
        lim = f"at most {int(pl.get('max_calls') or rf.MAX_CALLS_A)} LLM calls, {int(pl.get('max_passes') or rf.MAX_PASSES_A)} passes"
        out.append(f"<p class='muted'>The LLM changes the code for every finding that keeps the application from A and "
                   f"moves the data of the components that keep their own; the patch is verified and repaired, and the "
                   f"patched copy assessed again ({e(lim)}). A copy that rates A and runs is deployed to the sandbox "
                   f"beside the original.</p>")
    return "".join(out)


def _sandbox_section(adm, s, ident: int, sb: dict, requested) -> str:
    """The sandbox variant: its state, namespace, URL (opens in a new tab), expiry and Remove."""
    from .variant import ACTIVE, STATUS_TEXT
    if not sb:
        return ""
    st = sb.get("status") or ""
    out = [f"<h2>Sandbox</h2><div class='meta'><div><span class='label'>State</span> {sandbox_chip(sb, bool(requested))}</div>"]
    for label, key in (("Namespace", "namespace"), ("Folder", "folder"), ("Beside", "of"), ("Image tag", "tag")):
        if sb.get(key):
            out.append(f"<div><span class='label'>{label}</span> <code>{e(sb[key])}</code></div>")
    url = safe_url(sb.get("url"))
    if url and st in ACTIVE:
        out.append(f"<div><span class='label'>URL</span> <a href='{e(url)}' target='_blank' rel='noopener noreferrer'>"
                   f"{e(url)} ↗</a></div>")
    for label, key in (("Deployed", "deployed_at"), ("Checked", "checked_at"), ("Expires", "expires_at"),
                       ("Removed", "removed_at")):
        if sb.get(key):
            out.append(f"<div><span class='label'>{label}</span> {e(str(sb[key]).replace('T', ' ')[:16])} UTC</div>")
    out.append("</div>")
    if sb.get("reason"):
        out.append(f"<p class='small'>{e(sb['reason'])}</p>")
    if sb.get("url_check"):
        out.append(f"<p class='muted small'>URL check: {e(sb['url_check'])}</p>")
    if sb.get("local_images"):
        out.append("<p class='muted small'>The images were not pushed: the sandbox cluster runs them from the "
                   "builder's own image store.</p>")
    if st in ACTIVE and not sb.get("removed_at"):
        if requested:
            out.append("<p class='note'>Removal requested: the LLM queue runner takes it out within a few minutes.</p>")
        else:
            out.append(f"<form method='post' action='{BASE}/{ident}/remove' class='inline'>{adm._csrf(s)}"
                       f"<button>Remove from the sandbox</button></form> <span class='muted small'>Deletes its folder from "
                       f"the output repository; the cluster removes the namespace. The original application stays.</span>")
    return "".join(out)


def show_order(adm, conn, s, a, ident: int, flash: str) -> Response:
    r = load_order(conn, ident)
    if r is None:
        return _nf()
    pl, res = _json(r.get("Payload")), _json(r.get("Result"))
    st = status_of(r, res)
    took = f"{float(r['Seconds']) / 60:.0f} min" if r.get("Seconds") else None
    from .llmqueue import load_speed
    from .webui import est_text, order_effort
    try:
        est = load_speed(conn).job({"Kind": rf.KIND, "InputChars": r.get("InputChars"),
                                    "EstInputTokens": r.get("EstInputTokens"), "Model": None})
    except Exception:  # noqa: BLE001
        est = None
    tokens = (f"{int(r['InputTokens'] or 0):,} in / {int(r['OutputTokens'] or 0):,} out"
              if r.get("InputTokens") is not None or r.get("OutputTokens") is not None else None)
    app = (f"<a href='/app/{int(r['ApplicationId'])}'>{e(r.get('App') or '')}</a>" if r.get("ApplicationId")
           else e(r.get("App") or ""))
    meta = [("Application", app), ("Component", e(r.get("Component") or "all components that need changes")),
            ("Commit", f"<code>{e(str(pl.get('commit') or '')[:12])}</code>" if pl.get("commit") else None),
            ("Status", chip(st, verify_of(r, res)) + (f" <span class='small'>{e(rf.status_label(st, verify_of(r, res))[1])}</span>"
                                                      if st == "applies-only" else "")),
            ("Requested by", e(r.get("RequestedBy") or "")),
            ("LLM", e(res.get("model") or r.get("Endpoint") or "")), ("LLM calls", e(str(res.get("calls"))) if res else None),
            ("Estimate", e(est_text(est)) if est else None),
            ("Time left", e(left.split(" · about ")[-1].removesuffix(" left")) if " · about " in (left := (
                order_effort({**r, "Status": st}, load_speed(conn)) if st == "generating" else "")) else None),
            ("Tokens", e(tokens) if tokens else None), ("Time", e(took) if took else None),
            ("Queued", _d(r["QueuedAt"])), ("Finished", _d(r["FinishedAt"]) if r.get("FinishedAt") else None),
            ("Queue job", f"<a href='/admin/llm-queue/{ident}'>#{ident}</a>")]
    head = "".join(f"<div><span class='label'>{e(k)}</span> {v}</div>" for k, v in meta if v)
    body = [f"<p><a href='{BASE}'>← Refactoring</a></p><div class='meta'>{head}</div>"]
    if repairable(st, res):
        fails = "build" if any(v.get("status") == "build-failed" for v in res.get("verification") or []) else "run"
        body.append(f"<div class='note'><b>The patch applies but does not {fails}.</b> The LLM can fix it: it gets the errors below, "
                    f"the files they are in and this patch, and the result is one patch with both changes, verified again."
                    f"<form method='post' action='{BASE}/{ident}/repair' class='inline'>{adm._csrf(s)}"
                    f"<button>Fix it with the LLM</button></form></div>")
    if pl.get("goal") == "rating-a":
        body.append(_make_it_a(res, pl, st))
        requested = None
        try:
            rq = _rows(conn, "SELECT RemoveRequestedAt FROM cz.LlmJob WHERE JobId = %s", (ident,))
            requested = rq[0]["RemoveRequestedAt"] if rq else None
        except Exception:  # noqa: BLE001 - a database from before schema 23
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
        body.append(_sandbox_section(adm, s, ident, res.get("sandbox") or {}, requested))
    if pl.get("goal") == "repair" and pl.get("base_job"):
        body.append(f"<p class='muted small'>Repairs the patch of order <a href='{BASE}/{int(pl['base_job'])}'>"
                    f"#{int(pl['base_job'])}</a>.</p>")
    if st in ("queued", "generating", "verifying", "deploying"):
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
    title = (f"Make it A #{ident}: {r.get('App') or ''}" if pl.get("goal") == "rating-a" else
             f"Refactoring #{ident}: {r.get('App') or ''}" + (f" / {r['Component']}" if r.get("Component") else ""))
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


APP_COLS = ("ApplicationId, ApplicationName, ScanName, AssessmentId, Rating, SourceCommit, RepositoryUrl, SourcePath")


def make_payload(adm, conn, app: dict, goal: str = "fix", component: str | None = None,
                 include_config: bool = False) -> tuple[dict | None, str]:
    """The order of one application (a vApplicationLatest row): (payload, "") or (None, the notice code)."""
    if app["Rating"] != "B":
        return None, "not-b"
    if not app.get("SourceCommit"):
        return None, "no-commit"
    source = order_source(conn, app)
    url = app.get("RepositoryUrl") or ""
    if source is None and adm.dev and url.startswith("https://"):
        # development mode (a lab): the runner clones the repository itself if it is allowed to (rf.CLONE_ENV)
        source = {"type": "git-url", "url": url, "subdir": app.get("SourcePath") or "."}
    if source is None:
        return None, "no-source"
    rep = _rows(conn, "SELECT ReportJson FROM cz.ApplicationAssessment WHERE AssessmentId = %s", (app["AssessmentId"],))
    doc = _json(rep[0]["ReportJson"]) if rep else {}
    key = _rows(conn, "SELECT SourceKey FROM cz.Application WHERE ApplicationId = %s", (int(app["ApplicationId"]),))
    try:
        payload = rf.build_payload(doc, source, app["SourceCommit"], component=component, include_config=include_config,
                                   application_id=int(app["ApplicationId"]), goal=goal,
                                   assessment_id=int(app["AssessmentId"]),
                                   source_key=key[0]["SourceKey"] if key else None)
    except rf.RefactorError as ex:
        print(f"refactoring order for application {app['ApplicationId']} refused: {ex}", file=sys.stderr)
        return None, "nothing" if "nothing" in str(ex).lower() else "failed"
    payload["app"] = app.get("ScanName") or payload.get("app")
    return payload, ""


def queue_order(conn, app: dict, payload: dict) -> tuple[int, dict]:
    """(job id or 0 when the same order already waits, the job)."""
    from .llmqueue import SqlJobQueue
    job = rf.queue_job(payload, rf.order_chars(payload), requested_by=None)     # None: the signed-in person
    job["Repository"] = app["ApplicationName"]
    return SqlJobQueue(None).add_with(conn, job), job


def order(adm, conn, s, a, form: dict) -> Response:
    app_id = adm._id(form, "ApplicationId")
    if app_id is None:
        return _back(BASE, "No application selected.")
    if not allowed_app(a, conn, app_id):
        return _to_app(app_id, "not-yours")
    rows = _rows(conn, f"SELECT {APP_COLS} FROM cz.vApplicationLatest WHERE ApplicationId = %s", (app_id,))
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
        c = _rows(conn, "SELECT ProjectPath FROM cz.vComponentLatest WHERE ComponentId = %s AND ApplicationId = %s",
                  (int(comp_raw), app_id))
        if not c:
            return _to_app(app_id, "no-component")
        component = c[0]["ProjectPath"]
    goal = form.get("Goal", ["fix"])[0] if form.get("Goal", ["fix"])[0] in rf.GOALS else "fix"
    if goal == "repair":
        goal = "fix"                                       # a repair is ordered from the earlier order's page
    payload, code = make_payload(adm, conn, app, goal, component, form.get("IncludeConfig", [""])[0] == "1")
    if payload is None:
        return _to_app(app_id, code)
    jid, job = queue_order(conn, app, payload)
    if not jid:
        same = _rows(conn, "SELECT TOP (1) JobId FROM cz.LlmJob WHERE Kind = N'refactor' AND DedupeKey = %s "
                           "AND Status IN (N'approval', N'queued', N'running') ORDER BY JobId DESC", (job["DedupeKey"],))
        return _to_app(app_id, "exists", **({"job": int(same[0]["JobId"])} if same else {}))
    n = min(len(payload["tasks"]), payload["max_calls"])
    st = _rows(conn, "SELECT Status FROM cz.LlmJob WHERE JobId = %s", (jid,))
    wait = st and st[0]["Status"] == "approval"
    if goal == "rating-a":
        return _to_app(app_id, "approval-a" if wait else "ordered-a", job=int(jid), files=n)
    return _to_app(app_id, "approval" if wait else "ordered", job=int(jid), files=n)


# --------------------------------------------------------------------------- "Make all B apps A"

def bulk_plan(adm, conn) -> dict:
    """Every B-rated application with its "Make it A" order (or why there is none), the queue's estimate of
    each and of all, and how many will wait for approval under the current policy."""
    from .llmqueue import estimate_tokens, load_settings, load_speed
    speed = load_speed(conn)
    try:
        settings = load_settings(conn)
    except Exception:  # noqa: BLE001
        settings = {}
    kinds = {k.strip() for k in str(settings.get("ApproveKinds") or "").split(",") if k.strip()}
    least = int(settings.get("ApproveMinTokens") or 0)
    apps = _rows(conn, f"SELECT {APP_COLS} FROM cz.vApplicationLatest WHERE Rating = 'B' ORDER BY ApplicationName")
    items, jobs = [], []
    for app in apps:
        payload, code = make_payload(adm, conn, app, "rating-a")
        item = {"app": app, "payload": payload, "code": code}
        if payload is not None:
            chars = rf.order_chars(payload)
            job = {"Kind": rf.KIND, "InputChars": chars, "Model": None}
            item["est"] = speed.job(job)
            item["approval"] = rf.KIND in kinds and estimate_tokens("x" * chars) >= least
            jobs.append(job)
        items.append(item)
    total = speed.queue(jobs, int(settings.get("Parallel") or 1)) if jobs else None
    return {"items": items, "total": total, "approval": sum(1 for x in items if x.get("approval")),
            "policy": bool(rf.KIND in kinds)}


SKIP_TEXT = {"no-commit": "the assessment recorded no commit", "no-source": "its source is not kept on this machine",
             "nothing": "nothing to change in code", "failed": "the order could not be made (see the web UI's log)",
             "not-b": "not rated B"}


def make_all_a(adm, conn, s, a) -> Response:
    from .webui import est_text
    plan = bulk_plan(adm, conn)
    rows = []
    for x in plan["items"]:
        app = x["app"]
        name = f"<a href='/app/{int(app['ApplicationId'])}'>{e(app['ApplicationName'])}</a>"
        if x["payload"] is None:
            rows.append(f"<tr><td>{name}</td><td class='muted small' colspan=3>not ordered: "
                        f"{e(SKIP_TEXT.get(x['code'], x['code']))}</td></tr>")
            continue
        pl = x["payload"]
        what = f"{len(pl['tasks'])} file(s)" + (f", data of {len(pl.get('state') or [])} component(s) to move"
                                                if pl.get("state") else "")
        rows.append(f"<tr><td>{name}</td><td class='small'>{e(what)}</td><td class='small nowrap'>{e(est_text(x['est']))}</td>"
                    f"<td class='small'>{'waits for approval' if x.get('approval') else 'queued'}</td></tr>")
    n = sum(1 for x in plan["items"] if x["payload"] is not None)
    total = plan["total"]
    tot = (f"<p><b>{n} order(s)</b>: {e(est_text(total))} for the first pass of all of them at the speed the queue "
           f"learned (repair rounds and a second pass can take up to {rf.MAX_CALLS_A} LLM calls per order); "
           f"<b>{int(plan['approval'])}</b> will wait for an administrator's approval under the current policy.</p>"
           if total else "<p>No B-rated application can be ordered.</p>")
    form = (f"<form method='post' action='{BASE}/make-all-a' class='formrow'>{adm._csrf(s)}"
            f"<button>Queue {n} \"Make it A\" order(s)</button> <a href='{BASE}'>Cancel</a></form>" if n else "")
    body = (f"<p><a href='{BASE}'>← Refactoring</a></p>"
            "<p class='muted'>One \"Make it A\" order per B-rated application: the LLM changes the code for every "
            "finding that keeps it from A (and moves the data of components that keep their own), the patch is "
            "verified and repaired, the patched copy assessed again; one that rates A and runs is deployed to the "
            "sandbox beside the original. Orders run one after another in the LLM queue.</p>" + tot + form
            + "<table><thead><tr><th>Application</th><th>What changes</th><th>Estimate</th><th>Approval</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=4 class=muted>No B-rated applications.</td></tr>'}</tbody></table>")
    return Response(200, adm._shell(s, a, "Make all B apps A", "refactoring", body))


def make_all_a_post(adm, conn, s, a) -> Response:
    queued = waiting = exists = skipped = 0
    for x in bulk_plan(adm, conn)["items"]:
        if x["payload"] is None:
            skipped += 1
            continue
        jid, _ = queue_order(conn, x["app"], x["payload"])
        if not jid:
            exists += 1
            continue
        queued += 1
        st = _rows(conn, "SELECT Status FROM cz.LlmJob WHERE JobId = %s", (jid,))
        waiting += 1 if st and st[0]["Status"] == "approval" else 0
    code = "queued" if queued or exists else "none"
    return redirect(f"{BASE}?" + urlencode({"bulk": code, "q": queued, "w": waiting, "x": exists, "n": skipped}))
