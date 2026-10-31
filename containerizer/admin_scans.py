"""Admin pages for scheduled organization scans and their repositories (docs/scheduled-scans.md).

- Organization scans: what to scan (provider, organization), where the results go (registry, output
  repository), the filters, and the schedule (days and time, UTC); "Run now", cancel, and the runs with
  their progress. Tokens are not entered here: a scan names the worker's environment variables.
- Repositories: every repository the scans have found, enabled or disabled, with the reason when a
  scan skipped it (Dockerfile, no application code, stale, ...). Administrators enable or disable them
  one by one or in bulk; "Automatic" hands the decision back to the scan.

The worker (worker.py) does the scanning. Same conventions as admin.py: plain HTML forms with the
session's CSRF token, everything escaped, changes audited by triggers.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from .admin import URL_RE, Response, _code, _d, e, page, redirect

PROVIDERS = {"azure-devops": "Azure DevOps", "github": "GitHub", "gitlab": "GitLab"}
SKIP_TEXT = {"skipped-dockerfile": "Has a Dockerfile", "skipped-no-code": "No application code",
             "skipped-unsupported": "Language not supported", "skipped-no-app": "Nothing to deploy",
             "skipped-stale": "Not updated recently", "skipped-archived": "Archived", "skipped-empty": "Empty",
             "skipped-fork": "Fork", "skipped-filter": "Left out by the filter"}
LAST_TEXT = {"deployed": "Deployed to the sandbox", "no-a-components": "Assessed: no component rated A",
             "error": "Failed", "disabled": "Not processed (disabled)", **{k: "Skipped" for k in SKIP_TEXT}}
RUN_TEXT = {"queued": "Queued", "running": "Running", "succeeded": "Finished", "failed": "Failed",
            "cancelled": "Cancelled"}
REGISTRY_RE = re.compile(r"[A-Za-z0-9.-]+(:\d{1,5})?(/[a-z0-9._/-]+)?")
BRANCH_RE = re.compile(r"(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,200}")
SECRET_RE = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
ORG_RE = re.compile(r"[\w .\-/]{1,200}")
TIME_RE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
SCAN_COLS = ("Name", "Provider", "Organization", "ApiUrl", "TokenEnv", "Registry", "OutputRepo", "OutputBranch",
             "OutputTokenEnv", "ImagePullSecret", "IncludeRegex", "ExcludeRegex", "SkipForks", "StaleDays", "Verify",
             "Gate", "PushImages", "UseAi", "ScheduleDays", "ScheduleMinute", "Enabled")
FLAGS = ("SkipForks", "Verify", "Gate", "PushImages", "UseAi", "Enabled")
NEW_DAYS = 7
PAUSED = " <span class='st st-off'>Paused</span>"
NEW_CHIP = " <span class='st st-run'>New</span>"


def _q(q: dict, k: str, default: str = "") -> str:
    return q.get(k, [default])[0][:200]


def _back(url: str, msg: str) -> Response:
    return redirect(url + ("&" if "?" in url else "?") + urlencode({"msg": msg}))


def _repo_name(r: dict) -> str:
    return r["Name"] if r["ProjectName"] == "_" else f"{r['ProjectName']}/{r['Name']}"


def _secs(n) -> str:
    n = int(n or 0)
    if n < 90:
        return f"{n} s"
    if n < 5400:
        return f"{round(n / 60)} min"
    return f"{n / 3600:.1f} h"


def repo_state(r: dict) -> tuple[str, str, str]:
    """(state, who decides, reason) as the repository list shows them."""
    if r.get("RemovedAt"):
        return "Removed", "", f"no longer in the organization (since {_d(r['RemovedAt'])})"
    note = f" ({r['AdminNote']})" if r.get("AdminNote") else ""
    if r.get("AdminState") == "disabled":
        return "Disabled", "administrator", "disabled by an administrator" + note
    if r.get("AdminState") == "enabled":
        over = f"; overrides the automatic skip: {SKIP_TEXT.get(r['SkipStatus'], r['SkipStatus'])}: {r['SkipReason']}" \
            if r.get("SkipStatus") else ""
        return "Enabled", "administrator", "enabled by an administrator" + note + over
    if r.get("SkipStatus"):
        return "Disabled", "automatic", f"{SKIP_TEXT.get(r['SkipStatus'], r['SkipStatus'])}: {r.get('SkipReason') or ''}"
    if not r.get("LastStatus"):
        return "Enabled", "automatic", "new: not scanned yet"
    return "Enabled", "automatic", ""


def state_chip(state: str, who: str) -> str:
    css = {"Enabled": "st-ok", "Disabled": "st-off", "Removed": "st-off"}.get(state, "")
    return f"<span class='st {css}'>{e(state)}</span>" + (f"<div class='muted small'>{e(who)}</div>" if who else "")


def run_chip(status: str) -> str:
    css = {"succeeded": "st-ok", "failed": "st-bad", "cancelled": "st-off", "running": "st-run", "queued": "st-run"}
    return f"<span class='st {css.get(status, '')}'>{e(RUN_TEXT.get(status, status))}</span>"


# --------------------------------------------------------------------------- routing

def route(adm, conn, s, a, method: str, kind: str, parts: list, q: dict, form: dict, flash: str) -> Response:
    ident = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"\d{1,9}", parts[1]) else None
    action = parts[2] if len(parts) > 2 else ""
    if kind == "scans":
        if len(parts) > 1 and parts[1] == "new":
            return save_scan(conn, None, form) if method == "POST" else edit_scan(adm, conn, s, a, None, flash, q)
        if ident is None:
            return list_scans(adm, conn, s, a, flash) if method == "GET" and len(parts) == 1 else _nf()
        if method == "POST":
            if action == "run":
                return run_now(conn, ident)
            if action == "cancel":
                return cancel_run(conn, ident, form)
            if action == "delete":
                return delete_scan(conn, ident)
            if not action:
                return save_scan(conn, ident, form)
            return _nf()
        return edit_scan(adm, conn, s, a, ident, flash, q) if not action else _nf()
    if kind == "repositories":
        if method == "POST" and len(parts) > 1 and parts[1] == "bulk":
            return bulk_repos(conn, form)
        if ident is not None and not action:
            return save_repo(conn, ident, form) if method == "POST" else edit_repo(adm, conn, s, a, ident, flash)
        if len(parts) == 1 and method == "GET":
            return list_repos(adm, conn, s, a, q, flash)
    return _nf()


def _grafana(adm) -> str:
    url = getattr(adm, "grafana_url", "")
    return (f" Progress, results over time and the worker's machine: <a href='{e(url)}' rel='noopener noreferrer'"
            f" target='_blank'>Grafana dashboard ↗</a>.") if url else ""


def _nf() -> Response:
    return Response(404, page("Not found", "<h1>Not found</h1>"))


# --------------------------------------------------------------------------- organization scans

def _scans(conn) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("""SELECT s.*, x.RunId, x.Status AS RunStatus, x.StartedAt, x.FinishedAt, x.RequestedAt, x.Message,
                          x.ReposDone, x.ReposTotal,
                          (SELECT COUNT(*) FROM cz.OrgRepository r WHERE r.ScanId = s.ScanId AND r.RemovedAt IS NULL AND r.Enabled = 1) AS ReposOn,
                          (SELECT COUNT(*) FROM cz.OrgRepository r WHERE r.ScanId = s.ScanId AND r.RemovedAt IS NULL AND r.Enabled = 0) AS ReposOff
                   FROM cz.OrgScan s
                   OUTER APPLY (SELECT TOP (1) * FROM cz.OrgScanRun r WHERE r.ScanId = s.ScanId ORDER BY r.RunId DESC) x
                   ORDER BY s.Name""")
    return cur.fetchall()


def _next(scan: dict) -> str:
    from .worker import aware, next_run, utcnow
    if not scan["Enabled"]:
        return "paused"
    n = aware(scan["NextRunAt"]) if scan.get("NextRunAt") else next_run(scan["ScheduleDays"], scan["ScheduleMinute"], utcnow())
    return f"next {_d(n.replace(tzinfo=None))}" if n else ""


def list_scans(adm, conn, s, a, flash: str) -> Response:
    from .worker import schedule_text
    rows = []
    for r in _scans(conn):
        last = "<span class='muted'>never run</span>"
        if r["RunId"]:
            when = r["FinishedAt"] or r["StartedAt"] or r["RequestedAt"]
            prog = f" {int(r['ReposDone'] or 0)}/{int(r['ReposTotal'] or 0)}" if r["RunStatus"] == "running" else ""
            last = f"{run_chip(r['RunStatus'])}{e(prog)} <span class='muted small'>{_d(when)}</span>" \
                   f"<div class='muted small'>{e(r['Message'] or '')}</div>"
        rows.append(
            f"<tr><td><a href='/admin/scans/{int(r['ScanId'])}'>{e(r['Name'])}</a>{'' if r['Enabled'] else PAUSED}</td>"
            f"<td>{e(PROVIDERS.get(r['Provider'], r['Provider']))}: <b>{e(r['Organization'])}</b>"
            f"<div class='muted small'>{e(r['ApiUrl'] or '')}</div></td>"
            f"<td>{e(schedule_text(r['ScheduleDays'], r['ScheduleMinute']))}<div class='muted small'>{e(_next(r))}</div></td>"
            f"<td>{last}</td>"
            f"<td class='num'><a href='/admin/repositories?scan={int(r['ScanId'])}&amp;show=enabled'>{int(r['ReposOn'])}</a> / "
            f"<a href='/admin/repositories?scan={int(r['ScanId'])}&amp;show=disabled'>{int(r['ReposOff'])}</a></td></tr>")
    body = (f"<p class='muted'>Organization scans run <code>containerizer org</code> on every repository of an Azure DevOps "
            f"organization, GitHub organization or GitLab group, on the days and at the time you choose. The scan worker "
            f"(<code>containerizer worker</code>) runs them and keeps the repositories' clones between runs.{_grafana(adm)}</p>"
            f"<p><a class='chip' href='/admin/scans/new'>+ Add an organization scan</a></p>"
            f"<table><thead><tr><th>Scan</th><th>Organization</th><th>Schedule</th><th>Latest run</th>"
            f"<th class='num'>Repositories<div class='small'>enabled / disabled</div></th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=5 class=muted>No organization scans yet.</td></tr>'}</tbody></table>")
    return Response(200, adm._shell(s, a, "Organization scans", "scans", body, flash))


def _scan_form(adm, s, scan: dict, ident) -> str:
    from .worker import DAYS
    v = {k: ("" if scan.get(k) is None else scan.get(k)) for k in SCAN_COLS}

    def inp(name, label, help="", required=False, ph="", maxlen=400, typ="text"):
        return (f"<label for='{name}'>{label}{f' <span class=muted>({help})</span>' if help else ''}</label>"
                f"<input id='{name}' name='{name}' type='{typ}' maxlength='{maxlen}'{' required' if required else ''}"
                f" placeholder='{e(ph)}' value='{e(str(v[name]))}'>")

    def chk(name, label):
        return f"<label class='check'><input type='checkbox' name='{name}' value='1'{' checked' if v[name] else ''}> {label}</label>"
    prov = "".join(f"<option value='{k}'{' selected' if v['Provider'] == k else ''}>{t}</option>" for k, t in PROVIDERS.items())
    days = "".join(f"<label class='check day'><input type='checkbox' name='day' value='{i}'"
                   f"{' checked' if int(v['ScheduleDays'] or 0) & (1 << i) else ''}> {d}</label>" for i, d in enumerate(DAYS))
    minute = int(v["ScheduleMinute"] if v["ScheduleMinute"] != "" else 120)
    action = f"/admin/scans/{ident}" if ident else "/admin/scans/new"
    return f"""<form method='post' action='{action}' class='edit'>{adm._csrf(s)}
<label for='Name'>Name</label><input id='Name' name='Name' required maxlength='200' value='{e(str(v['Name']))}'>
<h3>Organization</h3>
<label for='Provider'>Provider</label><select id='Provider' name='Provider'>{prov}</select>
{inp('Organization', 'Organization', 'Azure DevOps organization or collection, GitHub organization, GitLab group path', True, 'contoso', 200)}
{inp('ApiUrl', 'Server', 'self-hosted only: https://ghe.example.com/api/v3, https://gitlab.example.com, https://tfs.example.com/tfs', ph='https://', typ='url')}
{inp('TokenEnv', 'Token variable', "name of the worker's environment variable with a read-only token; empty: the provider's usual one (GITHUB_TOKEN, GITLAB_TOKEN, AZURE_DEVOPS_TOKEN)", ph='CZ_TOKEN_CONTOSO', maxlen=64)}
{inp('IncludeRegex', 'Only repositories matching', 'regular expression on project/repository; empty: all', ph='^Billing/')}
{inp('ExcludeRegex', 'Leave out repositories matching', 'regular expression on project/repository', ph='(^|/)(sandbox|playground)')}
{chk('SkipForks', 'Skip forks')}
{inp('StaleDays', 'Skip repositories not updated for', 'days; 0 keeps all', maxlen=4, typ='number')}
<h3>Results</h3>
{inp('Registry', 'Image registry', 'host and path the images are pushed to; the worker has the credentials', True, 'acmeregistry.azurecr.io/sandbox')}
{chk('PushImages', 'Push images')}
{inp('OutputRepo', 'Output repository', 'https Git repository the Dockerfiles, manifests and Argo CD / Flux files are committed to; empty: kept on the worker', ph='https://', typ='url')}
{inp('OutputBranch', 'Output branch', '', maxlen=200)}
{inp('OutputTokenEnv', 'Output token variable', 'environment variable with a token that can push to the output repository; empty: OUTPUT_GIT_TOKEN', ph='CZ_TOKEN_SANDBOX_REPO', maxlen=64)}
{inp('ImagePullSecret', 'Image pull secret', 'added to every generated workload', ph='regcred', maxlen=253)}
{chk('Verify', 'Build and run every component before rating it (recommended)')}
{chk('Gate', 'Security gate: lint, image vulnerability scan, hardened run (recommended)')}
{chk('UseAi', 'Ask the LLM about uncertain components and unexplained failures')}
<h3>Schedule</h3>
<div class='days'>{days}</div>
<label for='At'>At <span class='muted'>(UTC; no day selected: only with Run now)</span></label>
<input id='At' name='At' type='time' value='{minute // 60:02d}:{minute % 60:02d}'>
{chk('Enabled', 'Enabled (unchecked: paused, no runs)')}
<div><button>{'Save' if ident else 'Add'}</button> <a href='/admin/scans'>Cancel</a></div></form>"""


def edit_scan(adm, conn, s, a, ident, flash: str, q: dict) -> Response:
    from .worker import check_scan, schedule_text
    if ident is None:
        scan = {"Provider": "github", "OutputBranch": "main", "SkipForks": True, "StaleDays": 183, "Verify": True,
                "Gate": True, "PushImages": True, "UseAi": False, "ScheduleDays": 32, "ScheduleMinute": 120, "Enabled": True}
        return Response(200, adm._shell(s, a, "New organization scan", "scans", _scan_form(adm, s, scan, None), flash))
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT * FROM cz.OrgScan WHERE ScanId = %s", (ident,))
    scan = cur.fetchone()
    if not scan:
        return _nf()
    cur.execute("SELECT TOP (30) * FROM cz.OrgScanRun WHERE ScanId = %s ORDER BY RunId DESC", (ident,))
    runs = cur.fetchall()
    active = next((r for r in runs if r["Status"] in ("queued", "running")), None)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    notes = []
    problems = check_scan(scan)
    if problems:
        notes.append("This scan cannot run: " + "; ".join(problems))
    if active and active["Status"] == "queued" and active["RequestedAt"] < now - timedelta(minutes=3):
        notes.append("The queued run has not been picked up for a few minutes: is the scan worker "
                     "(containerizer worker) running?")
    if active and active["Status"] == "running" and active["HeartbeatAt"] and active["HeartbeatAt"] < now - timedelta(minutes=3):
        notes.append(f"The worker running it has not reported since {_d(active['HeartbeatAt'])}.")
    rows = []
    for r in runs:
        who = "schedule" if r["TriggeredBy"] == "schedule" else f"Run now by {r['RequestedBy'] or '?'}"
        took = ""
        if r["StartedAt"]:
            took = _secs(((r["FinishedAt"] or now) - r["StartedAt"]).total_seconds())
        counts = ""
        if r["ReposTotal"] is not None:
            counts = (f"{int(r['ReposDone'] or 0)} of {int(r['ReposTotal'])}<div class='muted small'>"
                      f"{int(r['ReposDeployed'] or 0)} deployed · {int(r['ReposSkipped'] or 0)} skipped · "
                      f"{int(r['ReposErrors'] or 0)} failed · {int(r['ReposNew'] or 0)} new</div>")
        cancel = ""
        if r["Status"] in ("queued", "running") and not r["CancelRequested"]:
            cancel = (f"<form method='post' action='/admin/scans/{ident}/cancel' class='inline'>{adm._csrf(s)}"
                      f"<input type='hidden' name='RunId' value='{int(r['RunId'])}'><button class='link'>Cancel</button></form>")
        elif r["CancelRequested"] and r["Status"] == "running":
            cancel = "<div class='muted small'>cancelling after the current repository</div>"
        current = f"<div class='muted small'>now: {e(r['CurrentRepo'])}</div>" if r["Status"] == "running" and r["CurrentRepo"] else ""
        rows.append(f"<tr><td class='num'>{int(r['RunId'])}</td><td>{run_chip(r['Status'])}{current}{cancel}</td>"
                    f"<td class='nowrap'>{_d(r['StartedAt'] or r['RequestedAt'])}<div class='muted small'>{e(who)}"
                    f"{' · ' + e(r['Worker']) if r['Worker'] else ''}</div></td><td class='num'>{took}</td>"
                    f"<td>{counts}</td><td class='small'>{e(r['Message'] or '')}</td></tr>")
    runbtn = ""
    if scan["Enabled"] and not active and not problems:
        runbtn = (f"<form method='post' action='/admin/scans/{ident}/run' class='inline'>{adm._csrf(s)}"
                  f"<button>Run now</button></form>")
    delete = (f"<form method='post' action='/admin/scans/{ident}/delete' class='danger'>{adm._csrf(s)}"
              f"<button>Delete {e(scan['Name'])}</button></form>" if not runs else
              "<p class='muted small'>A scan that has run is kept with its history: pause it instead (uncheck Enabled).</p>")
    body = (f"{''.join(f'<p class=note>{e(n)}</p>' for n in notes)}"
            f"<div class='formrow'>{runbtn}<span>{e(schedule_text(scan['ScheduleDays'], scan['ScheduleMinute']))} · "
            f"{e(_next(scan))}</span> · <a href='/admin/repositories?scan={ident}'>Repositories</a></div>"
            f"<h2>Runs</h2><table><thead><tr><th class='num'>#</th><th>Status</th><th>Started</th><th class='num'>Took</th>"
            f"<th>Repositories</th><th>Result</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=6 class=muted>Not run yet.</td></tr>'}</tbody></table>"
            f"<h2>Settings</h2>{_scan_form(adm, s, scan, ident)}{delete}"
            f"<h2>Changes</h2>{adm._history(conn, 'OrgScan', ident)}")
    return Response(200, adm._shell(s, a, scan["Name"], "scans", body, flash))


def validate_scan(form: dict) -> tuple[dict, list[str]]:
    from .worker import TOKEN_ENV_RE
    errors, v = [], {}

    def text(k, label, required=False, n=400, rx=None, msg=""):
        val = " ".join(form.get(k, [""])[0].split())
        if not val:
            if required:
                errors.append(f"{label} is required")
            v[k] = None
            return
        if len(val) > n:
            errors.append(f"{label} is longer than {n} characters")
        elif rx is not None and not rx.fullmatch(val):
            errors.append(msg or f"{label} is not valid")
        v[k] = val
    text("Name", "Name", True, 200)
    v["Provider"] = form.get("Provider", [""])[0]
    if v["Provider"] not in PROVIDERS:
        errors.append("Choose a provider")
    text("Organization", "Organization", True, 200, ORG_RE, "Organization: letters, digits, space, . _ - and / only")
    text("ApiUrl", "Server", n=400, rx=URL_RE, msg="Server must be a plain https:// address")
    text("TokenEnv", "Token variable", n=64, rx=TOKEN_ENV_RE,
         msg="Token variable: CZ_TOKEN_<NAME> (capitals, digits, _), or GITHUB_TOKEN, GITLAB_TOKEN, AZURE_DEVOPS_TOKEN")
    text("Registry", "Image registry", True, 400, REGISTRY_RE, "Image registry: host[:port]/path in lower case")
    text("OutputRepo", "Output repository", n=400, rx=URL_RE, msg="Output repository must be a plain https:// address")
    text("OutputBranch", "Output branch", n=200, rx=BRANCH_RE, msg="Output branch is not a valid branch name")
    v["OutputBranch"] = v["OutputBranch"] or "main"
    text("OutputTokenEnv", "Output token variable", n=64, rx=TOKEN_ENV_RE,
         msg="Output token variable: CZ_TOKEN_<NAME> or OUTPUT_GIT_TOKEN")
    text("ImagePullSecret", "Image pull secret", n=253, rx=SECRET_RE, msg="Image pull secret: a Kubernetes secret name")
    for k, label in (("IncludeRegex", "Only repositories matching"), ("ExcludeRegex", "Leave out repositories matching")):
        text(k, label, n=400)
        if v[k]:
            try:
                re.compile(v[k])
            except re.error as ex:
                errors.append(f"{label}: {ex}")
    sd = form.get("StaleDays", ["183"])[0].strip() or "0"
    if not re.fullmatch(r"\d{1,4}", sd) or int(sd) > 3650:
        errors.append("Skip repositories not updated for: 0 to 3650 days")
        sd = "0"
    v["StaleDays"] = int(sd)
    for k in FLAGS:
        v[k] = form.get(k, [""])[0] == "1"
    v["ScheduleDays"] = sum(1 << int(d) for d in set(form.get("day", [])) if re.fullmatch(r"[0-6]", d))
    m = TIME_RE.fullmatch(form.get("At", ["02:00"])[0].strip())
    if not m:
        errors.append("At: a time as HH:MM")
    v["ScheduleMinute"] = int(m[1]) * 60 + int(m[2]) if m else 120
    return v, errors


def save_scan(conn, ident, form: dict) -> Response:
    v, errors = validate_scan(form)
    back = f"/admin/scans/{ident}" if ident else "/admin/scans/new"
    if errors:
        return _back(back, "; ".join(errors))
    cur = conn.cursor()
    try:
        if ident:
            cur.execute("UPDATE cz.OrgScan SET " + ", ".join(f"{k} = %s" for k in SCAN_COLS) + ", NextRunAt = NULL "
                        "WHERE ScanId = %s", (*(v[k] for k in SCAN_COLS), ident))
            if cur.rowcount == 0:
                conn.rollback()
                return _nf()
        else:
            cur.execute(f"INSERT cz.OrgScan ({', '.join(SCAN_COLS)}) VALUES ({', '.join(['%s'] * len(SCAN_COLS))}); "
                        "SELECT CAST(SCOPE_IDENTITY() AS int)", tuple(v[k] for k in SCAN_COLS))
            ident = cur.fetchone()[0]
        conn.commit()
    except Exception as ex:
        conn.rollback()
        if _code(ex) in (2601, 2627):
            return _back(back, f"There already is a scan named {v['Name']}.")
        raise
    return _back(f"/admin/scans/{ident}", "Saved. The worker picks up the new settings at the next run.")


def run_now(conn, ident: int) -> Response:
    cur = conn.cursor()
    cur.execute("EXEC cz.QueueOrgScanRun @ScanId = %s, @TriggeredBy = N'manual'", (ident,))
    rid = cur.fetchone()[0]
    conn.commit()
    if not rid:
        return _back(f"/admin/scans/{ident}", "Not queued: the scan is paused, or a run is already queued or running.")
    return _back(f"/admin/scans/{ident}", f"Run #{rid} queued. The worker starts it within a minute.")


def cancel_run(conn, ident: int, form: dict) -> Response:
    rid = form.get("RunId", [""])[0]
    if not re.fullmatch(r"\d{1,9}", rid):
        return _back(f"/admin/scans/{ident}", "No run selected.")
    cur = conn.cursor()
    cur.execute("SELECT ScanId FROM cz.OrgScanRun WHERE RunId = %s", (int(rid),))
    row = cur.fetchone()
    if not row or row[0] != ident:
        return _nf()
    cur.execute("EXEC cz.CancelOrgScanRun @RunId = %s", (int(rid),))
    n = cur.fetchone()[0]
    conn.commit()
    return _back(f"/admin/scans/{ident}", f"Run #{rid}: cancelled." if n else f"Run #{rid} had already finished.")


def delete_scan(conn, ident: int) -> Response:
    try:
        conn.cursor().execute("DELETE cz.OrgScan WHERE ScanId = %s", (ident,))
        conn.commit()
    except Exception as ex:
        conn.rollback()
        if _code(ex) == 547:
            return _back(f"/admin/scans/{ident}", "It has runs or repositories: pause it instead.")
        raise
    return _back("/admin/scans", "Deleted.")


# --------------------------------------------------------------------------- repositories

REPO_SHOW = {"all": ("All", "r.RemovedAt IS NULL"), "enabled": ("Enabled", "r.RemovedAt IS NULL AND r.Enabled = 1"),
             "disabled": ("Disabled", "r.RemovedAt IS NULL AND r.Enabled = 0"),
             "new": ("New", f"r.RemovedAt IS NULL AND r.FirstSeenAt > DATEADD(day, -{NEW_DAYS}, SYSUTCDATETIME())"),
             "failed": ("Failed", "r.RemovedAt IS NULL AND r.LastStatus = N'error'"),
             "removed": ("Removed", "r.RemovedAt IS NOT NULL")}


def list_repos(adm, conn, s, a, q: dict, flash: str) -> Response:
    show = _q(q, "show", "all")
    show = show if show in REPO_SHOW else "all"
    scan = _q(q, "scan")
    scan_id = int(scan) if re.fullmatch(r"\d{1,9}", scan) else None
    text = " ".join(_q(q, "q").split())
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ScanId, Name FROM cz.OrgScan ORDER BY Name")
    scans = cur.fetchall()
    where, params = [REPO_SHOW[show][1]], []
    if scan_id is not None:
        where.append("r.ScanId = %s")
        params.append(scan_id)
    if text:
        where.append("(r.Name LIKE %s ESCAPE '\\' OR r.ProjectName LIKE %s ESCAPE '\\')")
        like = "%" + re.sub(r"([%_\[\\])", r"\\\1", text) + "%"
        params += [like, like]
    cur.execute(f"""SELECT TOP (2000) r.*, s.Name AS ScanName FROM cz.OrgRepository r JOIN cz.OrgScan s ON s.ScanId = r.ScanId
                    WHERE {' AND '.join(where)} ORDER BY s.Name, r.ProjectName, r.Name""", tuple(params) or None)
    repos = cur.fetchall()
    base = {"scan": scan_id} if scan_id is not None else {}
    if text:
        base["q"] = text
    chips = " ".join(f"<a class='chip{' on' if k == show else ''}' href='/admin/repositories?"
                     f"{e(urlencode({**base, 'show': k}))}'>{t}</a>" for k, (t, _) in REPO_SHOW.items())
    scan_opts = "<option value=''>All scans</option>" + "".join(
        f"<option value='{int(x['ScanId'])}'{' selected' if x['ScanId'] == scan_id else ''}>{e(x['Name'])}</option>"
        for x in scans)
    search = (f"<form method='get' action='/admin/repositories' class='formrow'><select name='scan' aria-label='Scan'>"
              f"{scan_opts}</select><input type='hidden' name='show' value='{e(show)}'>"
              f"<input name='q' value='{e(text)}' placeholder='Repository or project' aria-label='Search'>"
              f"<button>Filter</button></form>")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = []
    for r in repos:
        state, who, reason = repo_state(r)
        new = r["FirstSeenAt"] > now - timedelta(days=NEW_DAYS) and not r["RemovedAt"]
        link = (f" <a class='ext small' href='{e(r['WebUrl'])}' rel='noopener noreferrer' target='_blank'>open ↗</a>"
                if r["WebUrl"] and URL_RE.fullmatch(r["WebUrl"]) else "")
        last = ""
        if r["LastStatus"]:
            rating = f" · rated {e(r['LastRating'])}" if r["LastRating"] else ""
            last = (f"{e(LAST_TEXT.get(r['LastStatus'], r['LastStatus']))}{rating}"
                    f"<div class='muted small'>{_d(r['LastScannedAt'])}</div>")
            if r["LastStatus"] == "error":
                last += f"<div class='small'>{e((r['LastReason'] or '')[:300])}</div>"
        rid = int(r["RepositoryId"])
        rows.append(
            f"<tr><td><input type='checkbox' name='repo' value='{rid}' aria-label='Select {e(_repo_name(r))}'></td>"
            f"<td><a href='/admin/repositories/{rid}'>{e(r['Name'])}</a>{NEW_CHIP if new else ''}"
            f"{link}<div class='muted small'>{e(r['ScanName'])}{' · ' + e(r['ProjectName']) if r['ProjectName'] != '_' else ''}</div></td>"
            f"<td>{state_chip(state, who)}</td><td class='small'>{e(reason)}</td><td>{last}</td></tr>")
    actions = ("<div class='formrow'><span>With the selected:</span>"
               "<button name='action' value='enable'>Enable</button>"
               "<button name='action' value='disable'>Disable</button>"
               "<button name='action' value='auto' class='secondary'>Automatic</button>"
               "<input name='Note' maxlength='400' placeholder='Note (optional), e.g. why' aria-label='Note'></div>")
    body = (f"<p class='muted'>Every repository the organization scans have found. A scan skips repositories that "
            f"already have a Dockerfile, have no application code, have not been updated recently, are archived, empty "
            f"or forks: they show as <b>disabled</b> with the reason, and are checked again at every run. Enable one to "
            f"process it anyway, disable one to leave it out, or set it back to automatic.</p>{search}"
            f"<nav class='chips'>{chips}</nav>"
            f"<form method='post' action='/admin/repositories/bulk'>{adm._csrf(s)}{actions}"
            f"<table><thead><tr><th></th><th>Repository</th><th>State</th><th>Reason</th><th>Latest result</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=5 class=muted>Nothing here.</td></tr>'}</tbody></table></form>"
            + ("<p class='muted small'>Showing the first 2000.</p>" if len(repos) == 2000 else ""))
    return Response(200, adm._shell(s, a, "Repositories", "repositories", body, flash))


ACTIONS = {"enable": "enabled", "disable": "disabled", "auto": None}


def bulk_repos(conn, form: dict) -> Response:
    ids = [int(x) for x in form.get("repo", []) if re.fullmatch(r"\d{1,9}", x)][:2000]
    action = form.get("action", [""])[0]
    if action not in ACTIONS:
        return _back("/admin/repositories", "Choose Enable, Disable or Automatic.")
    if not ids:
        return _back("/admin/repositories", "Select at least one repository.")
    note = " ".join(form.get("Note", [""])[0].split())[:400] or None
    cur = conn.cursor()
    n = 0
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        cur.execute(f"UPDATE cz.OrgRepository SET AdminState = %s, AdminNote = %s WHERE RepositoryId IN "
                    f"({', '.join(['%s'] * len(part))})", (ACTIONS[action], note if action != "auto" else None, *part))
        n += cur.rowcount
    conn.commit()
    what = {"enable": "enabled", "disable": "disabled", "auto": "set back to automatic"}[action]
    return _back("/admin/repositories", f"{n} repositor{'y' if n == 1 else 'ies'} {what}. The next run follows it.")


def edit_repo(adm, conn, s, a, ident: int, flash: str) -> Response:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT r.*, s.Name AS ScanName FROM cz.OrgRepository r JOIN cz.OrgScan s ON s.ScanId = r.ScanId "
                "WHERE r.RepositoryId = %s", (ident,))
    r = cur.fetchone()
    if not r:
        return _nf()
    apps = []
    if r["RepositoryUrl"]:
        cur.execute("SELECT ApplicationId, COALESCE(DisplayName, Name) AS N FROM cz.Application WHERE RepositoryUrl = %s "
                    "ORDER BY 2", (r["RepositoryUrl"],))
        apps = cur.fetchall()
    state, who, reason = repo_state(r)
    import json
    try:
        detail = json.loads(r["LastDetail"]) if r["LastDetail"] else {}
    except ValueError:
        detail = {}
    comps = "".join(f"<li><b>{e(c.get('component', ''))}</b> <span class='muted small'>{e(c.get('image', ''))}</span></li>"
                    for c in detail.get("components") or [])
    excl = "".join(f"<li>{e(x.get('component', ''))}: {e(x.get('reason', ''))}</li>" for x in detail.get("excluded") or [])
    link = (f"<a href='{e(r['WebUrl'])}' rel='noopener noreferrer' target='_blank'>{e(r['WebUrl'])}</a>"
            if r["WebUrl"] and URL_RE.fullmatch(r["WebUrl"]) else e(r["CloneUrl"]))
    facts = [("Scan", f"<a href='/admin/scans/{int(r['ScanId'])}'>{e(r['ScanName'])}</a>"), ("Repository", link),
             ("Default branch", e(r["DefaultBranch"] or "")), ("Sandbox app", e(r["AppName"] or "")),
             ("First seen", _d(r["FirstSeenAt"])), ("Last activity", _d(r["LastActivityAt"]) if r["LastActivityAt"] else "")]
    if r["LastStatus"]:
        facts += [("Latest result", f"{e(LAST_TEXT.get(r['LastStatus'], r['LastStatus']))}"
                   f"{' · rated ' + e(r['LastRating']) if r['LastRating'] else ''} · {_d(r['LastScannedAt'])}"
                   f"{' · ' + _secs(r['LastSeconds']) if r['LastSeconds'] else ''}"),
                  ("Commit", e((r["LastCommit"] or "")[:12]))]
        if r["LastReason"]:
            facts.append(("Detail", e(r["LastReason"])))
    if apps:
        facts.append(("Results", ", ".join(f"<a href='/app/{int(a['ApplicationId'])}'>{e(a['N'])}</a>" for a in apps)))
    meta = "".join(f"<div><span class='label'>{k}</span> {v}</div>" for k, v in facts if v)
    cur_setting = r["AdminState"] or "auto"
    opts = "".join(f"<label class='check'><input type='radio' name='Setting' value='{k}'{' checked' if k == cur_setting else ''}> "
                   f"{t}</label>" for k, t in (("auto", "Automatic: the scan decides (skips repositories with a Dockerfile, "
                                                         "without application code, not updated recently, ...)"),
                                              ("enabled", "Enabled: always process it, even when the scan would skip it"),
                                              ("disabled", "Disabled: never process it (stops deploying it to the sandbox)")))
    form = (f"<form method='post' action='/admin/repositories/{ident}' class='edit'>{adm._csrf(s)}{opts}"
            f"<label for='Note'>Note <span class='muted'>(why; shown in the list)</span></label>"
            f"<input id='Note' name='Note' maxlength='400' value='{e(r['AdminNote'] or '')}'>"
            f"<div><button>Save</button> <a href='/admin/repositories?scan={int(r['ScanId'])}'>Back</a></div></form>")
    body = (f"<div class='formrow'>{state_chip(state, who)}<span>{e(reason)}</span></div><div class='meta'>{meta}</div>"
            + (f"<h2>Deployed components</h2><ul>{comps}</ul>" if comps else "")
            + (f"<h2>Not deployed</h2><ul>{excl}</ul>" if excl else "")
            + f"<h2>Enabled or disabled</h2>{form}<h2>Changes</h2>{adm._history(conn, 'OrgRepository', ident)}")
    return Response(200, adm._shell(s, a, _repo_name(r), "repositories", body, flash))


def save_repo(conn, ident: int, form: dict) -> Response:
    setting = form.get("Setting", [""])[0]
    if setting not in ("auto", "enabled", "disabled"):
        return _back(f"/admin/repositories/{ident}", "Choose automatic, enabled or disabled.")
    note = " ".join(form.get("Note", [""])[0].split())[:400] or None
    cur = conn.cursor()
    cur.execute("UPDATE cz.OrgRepository SET AdminState = %s, AdminNote = %s WHERE RepositoryId = %s",
                (None if setting == "auto" else setting, note, ident))
    n = cur.rowcount
    conn.commit()
    if not n:
        return _nf()
    return _back(f"/admin/repositories/{ident}", "Saved. The next run follows it.")
