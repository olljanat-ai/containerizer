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
from .roles import role_label

e = html.escape
STATUS_TEXT = {"pending": "Waiting for review", "approved": "Approved", "rejected": "Rejected"}
KIND_TEXT = {"rule": "Rule", "failure": "Failure rule", "package": "Package"}


class Approving:
    """How approving works right now: through the scan worker, with the internal rules repository set on
    this page and its write token under Source control (the appliance); or, without that, as the web UI's
    environment says (CONTAINERIZER_RULES_*: the web UI itself opens the pull request or writes the files)."""

    def __init__(self, adm, conn):
        self.repo = None
        try:
            self.repo = rr.load_repository(conn)
        except Exception:               # a database without the table yet: as before
            try:
                conn.rollback()
            except Exception:
                pass
        self.worker = self.repo is not None or not (adm.rule_apply.repo or adm.rule_apply.mode == "direct")
        self.cfg = rr.repository_config(self.repo) if self.repo else adm.rule_apply
        self.error = adm.rule_apply_error if not self.worker else ""
        if self.worker and not self.repo:
            self.error = "no internal rules repository is set: an administrator sets it under Internal rules repository"
        elif self.repo:
            from . import credentials as cr
            try:
                self.cfg.check()
                if not cr.load(conn).write_for(self.cfg.repo):
                    self.error = (f"no write token is registered for {self.cfg.repo}: an administrator adds one under "
                                  "Source control")
            except rr.ReviewError as ex:
                self.error = str(ex)

    def describe(self) -> str:
        if self.worker and self.repo:
            return (f"proposed in a pull request to the internal rules repository {self.cfg.repo} ({self.cfg.branch}), "
                    "opened by the scan worker")
        return self.cfg.describe()


def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict, flash: str) -> Response:
    store = rr.SqlStore(conn)
    if len(parts) == 1:
        if method != "GET":
            return Response(405, "", [("Allow", "GET, HEAD")])
        return list_page(adm, conn, store, s, a, q.get("status", ["pending"])[0], flash)
    if parts[1] == "repository" and len(parts) in (2, 3):
        if not a.admin:
            return Response(403, page("Forbidden", "<h1>Only administrators set the rules repository</h1>"))
        if method != "POST" or (len(parts) == 3 and parts[2] != "delete"):
            return Response(405, "", [("Allow", "POST")])
        return save_repository(conn, form, delete=len(parts) == 3)
    if not re.fullmatch(r"\d{1,9}", parts[1]):
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    cid = int(parts[1])
    if len(parts) == 2 and method == "GET":
        return detail_page(adm, conn, store, s, a, cid, flash)
    if len(parts) == 3 and method == "POST" and parts[2] in ("approve", "reject"):
        return decide(adm, conn, store, s, cid, parts[2], form)
    return Response(404, page("Not found", "<h1>Not found</h1>"))


def _status(st: str) -> str:
    cls = {"pending": "st-run", "approved": "st-ok", "rejected": "st-off"}.get(st, "st-off")
    return f"<span class='st {cls}'>{e(STATUS_TEXT.get(st, st))}</span>"


def _pr_link(url) -> str:
    if url and URL_RE.fullmatch(str(url)):
        return f"<a class='ext' href='{e(url)}' rel='noopener noreferrer' target='_blank'>pull request ↗</a>"
    return ""


def list_page(adm, conn, store, s, a, status: str, flash: str) -> Response:
    ap = Approving(adm, conn)
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
        if c["Status"] == "pending" and c.get("ApproveRequestedAt"):
            decided = (f"<div class='muted small'>approved by {e(c.get('ApproveByName') or c.get('ApproveBy') or '')}; "
                       f"the pull request is being opened</div>")
        elif c["Status"] == "pending" and c.get("ApplyError"):
            decided = "<div class='muted small'>the last approval did not go through</div>"
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
            f"Approved rules are {e(ap.describe())}. A rejected rule is not proposed again.</p>"
            + (f"<p class='note'>Approving is not available: {e(ap.error)}</p>" if ap.error else "")
            + f"<nav class='chips'>{chips}</nav>"
            f"<table><thead><tr><th>Learned rule</th><th>Learned from</th><th class='num'>Confidence</th>"
            f"<th class='num'>Seen</th><th>Last seen</th><th>Status</th></tr></thead>"
            f"<tbody>{''.join(body_rows) or f'<tr><td colspan=6 class=muted>{empty}</td></tr>'}</tbody></table>")
    if a.admin and ap.worker:
        body += repository_form(adm, s, ap)
    return Response(200, adm._shell(s, a, "Rule review", "rules", body, flash))


PROVIDERS = (("", "Work it out from the URL"), ("github", "GitHub"), ("gitlab", "GitLab"), ("azure-devops", "Azure DevOps"))


def repository_form(adm, s, ap: Approving) -> str:
    r = ap.repo or {}
    v = {k: r.get(k) or "" for k in ("RepoUrl", "Provider", "ApiUrl", "Branch", "Path")}
    opts = "".join(f"<option value='{k}'{' selected' if k == v['Provider'] else ''}>{t}</option>" for k, t in PROVIDERS)
    remove = (f"<form method='post' action='/admin/rules/repository/delete' class='danger'>{adm._csrf(s)}"
              f"<button class='secondary'>Remove</button> <span class='muted small'>Approving stops; approved rules stay in "
              f"the repository, and scans stop loading them.</span></form>") if ap.repo else ""
    return f"""<h2 id='repository'>Internal rules repository</h2>
<p class='muted'>Approved rules go to a private or internal Git repository of your own, never into this tool's rules: what
your applications taught it stays inside your organization. Create the repository (it needs one commit, a README is
enough), then add a <b>write token</b> for its URL under <a href='/admin/source-control'>Source control</a> that can push
a branch and open a pull request there: GitHub <b>Contents</b> and <b>Pull requests: Read and write</b>, GitLab
<b>Developer</b> with <b>api</b> and <b>write_repository</b>, Azure DevOps <b>Code: Read &amp; write</b>. Only the scan
worker can use that token: it opens the pull request of each approval, and before every scan it fetches the approved
rules, so the scans use them as soon as the pull request is merged. Allow the Git server on the Firewall page.</p>
<form method='post' action='/admin/rules/repository' class='edit'>{adm._csrf(s)}
<label for='RepoUrl'>Repository URL <span class='muted'>(https)</span></label>
<input id='RepoUrl' name='RepoUrl' type='url' required maxlength='400' value='{e(v["RepoUrl"])}' placeholder='https://github.com/contoso/containerizer-rules'>
<label for='Branch'>Branch <span class='muted'>(the pull requests target it)</span></label>
<input id='Branch' name='Branch' maxlength='200' value='{e(v["Branch"] or "main")}'>
<label for='Path'>Folder of the rules in the repository</label>
<input id='Path' name='Path' maxlength='200' value='{e(v["Path"] or "rules")}'>
<label for='Provider'>Provider</label><select id='Provider' name='Provider'>{opts}</select>
<label for='ApiUrl'>API URL <span class='muted'>(only for a self-hosted GitHub Enterprise Server or GitLab whose API is not at
the usual address)</span></label>
<input id='ApiUrl' name='ApiUrl' type='url' maxlength='400' value='{e(v["ApiUrl"])}' placeholder='https://'>
<div><button>Save</button></div></form>{remove}"""


def save_repository(conn, form: dict, delete: bool) -> Response:
    back = "/admin/rules?"
    if delete:
        rr.delete_repository(conn)
        return redirect(back + urlencode({"msg": "The internal rules repository was removed; approving is off."}))
    f = {k: form.get(k, [""])[0] for k in ("RepoUrl", "Provider", "ApiUrl", "Branch", "Path")}
    cfg, errors = rr.check_repository(f["RepoUrl"], f["Provider"], f["ApiUrl"], f["Branch"], f["Path"])
    if errors:
        return redirect(back + urlencode({"msg": ("Not saved: " + "; ".join(errors))[:300]}) + "#repository")
    rr.save_repository(conn, cfg)
    return redirect(back + urlencode({"msg": "Saved. Approved rules now go to " + cfg.repo}) + "#repository")


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
    ap = Approving(adm, conn)
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
    elif c.get("ApproveRequestedAt"):
        decision = (f"<p class='note'>Approved by {e(c.get('ApproveByName') or c.get('ApproveBy') or '')} on "
                    f"{_d(c['ApproveRequestedAt'])}: the scan worker is opening the pull request. Reload the page in a "
                    f"minute.</p>")
    elif c.get("ApplyError"):
        decision = f"<p class='note'>The last approval did not go through: {e(c['ApplyError'])}</p>"
    try:
        problems = rr.validate(kind, rr.parse_entry(kind, c["RuleYaml"]),
                               ap.cfg.rules_dir if ap.cfg.mode == "direct" else None)
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
    if c["Status"] == "pending" and not c.get("ApproveRequestedAt"):
        need = ("<div class='note'><b>Edit it before approving:</b><ul class='changes'>"
                + "".join(f"<li>{e(p)}</li>" for p in problems) + "</ul></div>") if problems else ""
        disabled = " disabled" if ap.error else ""
        unavailable = f"<p class='note'>Approving is not available: {e(ap.error)}</p>" if ap.error else ""
        body.append(
            f"<h2>Decide</h2>{unavailable}"
            f"<form method='post' action='/admin/rules/{cid}/approve' class='edit wide'>{adm._csrf(s)}"
            f"<label for='Yaml'>Rule <span class='muted'>(edit before approving if needed; YAML)</span></label>{need}"
            f"<textarea id='Yaml' name='Yaml' rows='{min(30, max(8, c['RuleYaml'].count(chr(10)) + 2))}' spellcheck='false' "
            f"maxlength='{rr.MAX_YAML}' class='code'>{e(c['RuleYaml'])}</textarea>"
            f"<label for='ApproveNote'>Note <span class='muted'>(optional, kept in the change history)</span></label>"
            f"<input id='ApproveNote' name='Note' maxlength='1000'>"
            f"<div><button{disabled}>Approve</button> <span class='muted small'>The rule will be "
            f"{e(ap.describe())}.</span></div></form>"
            f"<form method='post' action='/admin/rules/{cid}/reject' class='edit wide reject'>{adm._csrf(s)}"
            f"<label for='RejectNote'>Why reject it? <span class='muted'>(kept in the change history)</span></label>"
            f"<input id='RejectNote' name='Note' maxlength='1000'>"
            f"<div><button class='secondary'>Reject</button> <span class='muted small'>The same rule will not be "
            f"proposed again.</span></div></form>")
    body.append(f"<h2>Changes</h2>{adm._history(conn, 'RuleCandidate', cid)}")
    return Response(200, adm._shell(s, a, c["Title"][:120], "rules", "".join(body), flash))


def decide(adm, conn, store, s, cid: int, action: str, form: dict) -> Response:
    back = f"/admin/rules/{cid}"
    note = " ".join(form.get("Note", [""])[0].split())[:1000] or None
    try:
        if action == "reject":
            rr.reject(store, cid, s.user, s.name, note)
            return redirect("/admin/rules?" + urlencode({"msg": "Rejected; it will not be proposed again."}))
        ap = Approving(adm, conn)
        if ap.error:
            raise rr.ReviewError(ap.error)
        text = form.get("Yaml", [""])[0].replace("\r\n", "\n")
        if ap.worker:
            return request_approval(store, s, cid, note, text)
        r = rr.approve(store, cid, s.user, s.name, note, text, ap.cfg)
    except rr.ReviewError as ex:
        return redirect(back + "?" + urlencode({"msg": f"Not saved: {ex}"[:300]}))
    what = "a pull request was opened" if r["applied"] == "pr" else "it was written to the ruleset files"
    return redirect(back + "?" + urlencode({"msg": f"Approved{' with your edits' if r['edited'] else ''}; {what}."}))


def request_approval(store, s, cid: int, note: str | None, text: str) -> Response:
    """Check the rule now, and leave the pull request to the scan worker (it holds the token)."""
    back = f"/admin/rules/{cid}"
    c = store.get(cid)
    if not c:
        raise rr.ReviewError(f"no candidate {cid}")
    if c["Status"] != "pending":
        raise rr.ReviewError(f"candidate {cid} is already {c['Status']}")
    kind = c["Kind"]
    entry = rr.parse_entry(kind, text if text.strip() else c["RuleYaml"])
    problems = rr.validate(kind, entry, None)
    if problems:
        raise rr.ReviewError("; ".join(problems))
    if not store.request_approval(cid, s.user, s.name, role_label(s.admin, s.operator, s.scopes), rr.to_yaml(entry), note):
        raise rr.ReviewError(f"candidate {cid} is already being approved or decided")
    edited = rr.to_yaml(entry) != rr.to_yaml(rr.parse_entry(kind, c["RuleYaml"]))
    return redirect(back + "?" + urlencode({"msg": f"Approved{' with your edits' if edited else ''}; the scan worker opens "
                                                   "the pull request within a minute."}))
