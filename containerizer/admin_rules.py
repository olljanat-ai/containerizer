"""Rule review admin pages: rules the learning loop learned, with their evidence; approve (optionally
after editing), or reject. Behind the rule review gate (Admin.may_review_rules), which lets in the
administrators and any other role listed in admin.RULE_REVIEW_ROLES. See rulereview.py and
docs/rule-review.md."""
from __future__ import annotations

import html
import re
from urllib.parse import urlencode

from . import rulereview as rr
from .admin import URL_RE, Response, _d, page, redirect

e = html.escape
STATUS_TEXT = {"pending": "Waiting for review", "approved": "Approved", "rejected": "Rejected"}
KIND_TEXT = {"rule": "Rule", "failure": "Failure rule", "package": "Package"}


def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict, flash: str) -> Response:
    store = rr.SqlStore(conn)
    if len(parts) == 1:
        if method != "GET":
            return Response(405, "", [("Allow", "GET, HEAD")])
        return list_page(adm, store, s, a, q.get("status", ["pending"])[0], flash)
    if not re.fullmatch(r"\d{1,9}", parts[1]):
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    cid = int(parts[1])
    if len(parts) == 2 and method == "GET":
        return detail_page(adm, conn, store, s, a, cid, flash)
    if len(parts) == 3 and method == "POST" and parts[2] in ("approve", "reject"):
        return decide(adm, store, s, cid, parts[2], form)
    return Response(404, page("Not found", "<h1>Not found</h1>"))


def _status(st: str) -> str:
    cls = {"pending": "st-run", "approved": "st-ok", "rejected": "st-off"}.get(st, "st-off")
    return f"<span class='st {cls}'>{e(STATUS_TEXT.get(st, st))}</span>"


def _pr_link(url) -> str:
    if url and URL_RE.fullmatch(str(url)):
        return f"<a class='ext' href='{e(url)}' rel='noopener noreferrer' target='_blank'>pull request ↗</a>"
    return ""


def list_page(adm, store, s, a, status: str, flash: str) -> Response:
    status = status if status in (*rr.STATUSES, "all") else "pending"
    counts = store.counts()
    rows = store.list(status)
    chips = " ".join(f"<a class='chip{' on' if k == status else ''}' href='/admin/rules?status={k}'>{t}"
                     f"{' (' + str(counts.get(k, 0)) + ')' if k != 'all' else ''}</a>"
                     for k, t in (("pending", "Waiting for review"), ("approved", "Approved"), ("rejected", "Rejected"),
                                  ("all", "All")))
    body_rows = []
    for c in rows:
        decided = ""
        if c["Status"] != "pending":
            decided = (f"<div class='muted small'>{e(c.get('ReviewedByName') or c.get('ReviewedBy') or '')}, "
                       f"{_d(c.get('ReviewedAt'))} {_pr_link(c.get('PullRequestUrl'))}</div>")
        model = f" · LLM {e(c['Model'])}" if c.get("Model") else ""
        body_rows.append(
            f"<tr><td><a href='/admin/rules/{int(c['CandidateId'])}'>{e(c['Title'])}</a>"
            f"<div class='muted small'>{e(KIND_TEXT.get(c['Kind'], c['Kind']))} <code>{e(c['RuleId'])}</code>{model}</div></td>"
            f"<td>{e(c.get('LearnedFrom') or '-')}</td><td class='num'>{float(c['Confidence']):.2f}</td>"
            f"<td class='num'>{int(c['SeenCount'])}</td><td class='nowrap'>{_d(c['LastSeenAt'])}</td>"
            f"<td>{_status(c['Status'])}{decided}</td></tr>")
    empty = {"pending": "Nothing is waiting for review."}.get(status, "Nothing here.")
    body = (f"<p class='muted'>Rules the learning loop learned from building and running applications (and, with the LLM "
            f"on, rules it proposed). They are used only by the run that learned them until someone approves them here. "
            f"Approved rules are {e(adm.rule_apply.describe())}. A rejected rule is not proposed again.</p>"
            + (f"<p class='note'>Approving is not available: {e(adm.rule_apply_error)}</p>" if adm.rule_apply_error else "")
            + f"<nav class='chips'>{chips}</nav>"
            f"<table><thead><tr><th>Learned rule</th><th>Learned from</th><th class='num'>Confidence</th>"
            f"<th class='num'>Seen</th><th>Last seen</th><th>Status</th></tr></thead>"
            f"<tbody>{''.join(body_rows) or f'<tr><td colspan=6 class=muted>{empty}</td></tr>'}</tbody></table>")
    return Response(200, adm._shell(s, a, "Rule review", "rules", body, flash))


def _diff(text: str | None) -> str:
    if not text:
        return "<p class='muted'>No diff.</p>"
    out = []
    for line in text.splitlines():
        cls = "add" if line.startswith("+") and not line.startswith("+++") else \
            "del" if line.startswith("-") and not line.startswith("---") else "hunk" if line.startswith("@@") else ""
        out.append(f"<span class='{cls}'>{e(line)}</span>" if cls else e(line))
    return f"<pre class='code diff'>{chr(10).join(out)}</pre>"


def _evidence(ev: dict, i: int) -> str:
    where = "/".join(x for x in (ev.get("Application"), ev.get("Component")) if x) or "unknown component"
    repo = ev.get("RepositoryUrl") or ""
    repo_html = (f"<a class='ext' href='{e(repo)}' rel='noopener noreferrer' target='_blank'>{e(repo)} ↗</a>"
                 if URL_RE.fullmatch(repo) else e(repo or "a folder without a git remote"))
    meta = [f"<b>Source:</b> {repo_html}" + (f" at <code>{e(ev['SourceCommit'][:12])}</code>" if ev.get("SourceCommit") else "")]
    if ev.get("Outcome"):
        meta.append(f"<b>Final outcome:</b> {e(ev['Outcome'])}"
                    + (f" · learned from a failure in the {e(ev['Stage'])} stage" if ev.get("Stage") else ""))
    if ev.get("Model"):
        meta.append(f"<b>LLM:</b> {e(ev['Model'])}")
    reason = f"<p><b>What happened</b></p><pre class='code'>{e(ev['ExitReason'])}</pre>" if ev.get("ExitReason") else ""
    log = (f"<p><b>Log excerpt</b> <span class='muted small'>(credentials masked)</span></p>"
           f"<pre class='code log'>{e(ev['LogExcerpt'])}</pre>") if ev.get("LogExcerpt") else ""
    return (f"<details{' open' if i == 0 else ''}><summary>{_d(ev.get('SeenAt'))} · {e(where)}"
            f"{' · ' + e(ev['Outcome']) if ev.get('Outcome') else ''}</summary>"
            f"<div class='meta'>{''.join(f'<div>{m}</div>' for m in meta)}</div>{reason}{log}</details>")


def detail_page(adm, conn, store, s, a, cid: int, flash: str) -> Response:
    c = store.get(cid)
    if not c:
        return Response(404, page("Not found", "<h1>Learned rule not found</h1>"))
    kind = c["Kind"]
    facts = [f"{e(KIND_TEXT.get(kind, kind))} <code>{e(c['RuleId'])}</code>, added to <code>{e(c['TargetFile'])}</code> in the internal rules repository",
             f"Confidence {float(c['Confidence']):.2f} · seen {int(c['SeenCount'])} time(s), first {_d(c['FirstSeenAt'])}, "
             f"last {_d(c['LastSeenAt'])}",
             f"Learned from {e(c.get('LearnedFrom') or '-')} · source: "
             + ("proposed by the LLM " + e(c.get("Model") or "") if c.get("Source") == "ai" else "build and run")]
    decision = ""
    if c["Status"] != "pending":
        decision = (f"<p class='note'>{_status(c['Status'])} by {e(c.get('ReviewedByName') or c.get('ReviewedBy') or '')} "
                    f"on {_d(c.get('ReviewedAt'))}" + (f": {e(c['ReviewNote'])}" if c.get("ReviewNote") else "")
                    + (f" · {_pr_link(c.get('PullRequestUrl'))}" if c.get("PullRequestUrl") else "")
                    + (" · written to the ruleset files" if c.get("AppliedAs") == "direct" else "") + "</p>")
    try:
        problems = rr.validate(kind, rr.parse_entry(kind, c["RuleYaml"]),
                               adm.rule_apply.rules_dir if adm.rule_apply.mode == "direct" else None)
    except rr.ReviewError as ex:
        problems = [str(ex)]
    shown = c.get("FinalYaml") if c["Status"] == "approved" and c.get("FinalYaml") else c["RuleYaml"]
    body = [f"<div class='meta'>{''.join(f'<div>{x}</div>' for x in facts)}</div>{decision}",
            f"<h2>{'Approved rule' if c['Status'] == 'approved' else 'Proposed rule'}</h2><pre class='code'>{e(shown)}</pre>",
            f"<h2>Change to the ruleset</h2><p class='muted small'>As it was proposed; approving checks it against the "
            f"ruleset again.</p>{_diff(c.get('Diff'))}"]
    ev = c.get("evidence") or []
    body.append("<h2>Evidence</h2><p class='muted'>Each run that learned this rule (the latest 20).</p>"
                + ("".join(_evidence(x, i) for i, x in enumerate(ev)) or "<p class='muted'>No evidence recorded.</p>"))
    if c["Status"] == "pending":
        need = ("<div class='note'><b>Edit it before approving:</b><ul class='changes'>"
                + "".join(f"<li>{e(p)}</li>" for p in problems) + "</ul></div>") if problems else ""
        disabled = " disabled" if adm.rule_apply_error else ""
        unavailable = f"<p class='note'>Approving is not available: {e(adm.rule_apply_error)}</p>" if adm.rule_apply_error else ""
        body.append(
            f"<h2>Decide</h2>{unavailable}"
            f"<form method='post' action='/admin/rules/{cid}/approve' class='edit wide'>{adm._csrf(s)}"
            f"<label for='Yaml'>Rule <span class='muted'>(edit before approving if needed; YAML)</span></label>{need}"
            f"<textarea id='Yaml' name='Yaml' rows='{min(30, max(8, c['RuleYaml'].count(chr(10)) + 2))}' spellcheck='false' "
            f"maxlength='{rr.MAX_YAML}' class='code'>{e(c['RuleYaml'])}</textarea>"
            f"<label for='ApproveNote'>Note <span class='muted'>(optional, kept in the change history)</span></label>"
            f"<input id='ApproveNote' name='Note' maxlength='1000'>"
            f"<div><button{disabled}>Approve</button> <span class='muted small'>The rule will be "
            f"{e(adm.rule_apply.describe())}.</span></div></form>"
            f"<form method='post' action='/admin/rules/{cid}/reject' class='edit wide reject'>{adm._csrf(s)}"
            f"<label for='RejectNote'>Why reject it? <span class='muted'>(kept in the change history)</span></label>"
            f"<input id='RejectNote' name='Note' maxlength='1000'>"
            f"<div><button class='secondary'>Reject</button> <span class='muted small'>The same rule will not be "
            f"proposed again.</span></div></form>")
    body.append(f"<h2>Changes</h2>{adm._history(conn, 'RuleCandidate', cid)}")
    return Response(200, adm._shell(s, a, c["Title"][:120], "rules", "".join(body), flash))


def decide(adm, store, s, cid: int, action: str, form: dict) -> Response:
    back = f"/admin/rules/{cid}"
    note = " ".join(form.get("Note", [""])[0].split())[:1000] or None
    try:
        if action == "reject":
            rr.reject(store, cid, s.user, s.name, note)
            return redirect("/admin/rules?" + urlencode({"msg": "Rejected; it will not be proposed again."}))
        if adm.rule_apply_error:
            raise rr.ReviewError(adm.rule_apply_error)
        text = form.get("Yaml", [""])[0].replace("\r\n", "\n")
        r = rr.approve(store, cid, s.user, s.name, note, text, adm.rule_apply)
    except rr.ReviewError as ex:
        return redirect(back + "?" + urlencode({"msg": f"Not saved: {ex}"[:300]}))
    what = "a pull request was opened" if r["applied"] == "pr" else "it was written to the ruleset files"
    return redirect(back + "?" + urlencode({"msg": f"Approved{' with your edits' if r['edited'] else ''}; {what}."}))
