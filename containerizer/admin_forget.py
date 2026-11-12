"""Forget application (Admin -> Applications -> the application, administrators): everything Containerizer recorded
about it goes, and its repository is disabled, so no scan assesses it again until an administrator enables it.

The database rows go at once (cz.ForgetApplication: assessments, findings, components, sandbox checks, LLM jobs and
usage, egress and link decisions, dev database, sandbox database edits; the change history keeps the deletion itself).
The files go with the scan this queues for the repository (a disabled repository's folder is removed from the output
repository, and the sandbox prunes its namespace), or with the next run of its scan when one is running.
"""
from __future__ import annotations

import html
import json
import sys
from urllib.parse import urlencode

e = html.escape


def section(adm, s, r: dict) -> str:
    name = r["Name"]
    return (f"<h2>Forget this application</h2><p>Deletes everything recorded about <b>{e(r['DisplayName'] or name)}</b>: "
            "its assessments and findings, components, sandbox checks, LLM jobs and Make it A orders, egress and link "
            "decisions, dev database and sandbox database edits. Its repository is <b>disabled</b>, so the next scan removes "
            "its files from the output repository and the sandbox, and no scan assesses it again until you enable it on "
            "<a href='/admin/repositories'>Repositories</a>; then it is assessed as new. The change history keeps the deletion. "
            "Secret values in OpenBao stay.</p>"
            f"<form method='post' action='/admin/applications/{int(r['ApplicationId'])}/forget' class='edit danger'>{adm._csrf(s)}"
            f"<label for='confirm'>Type <b>{e(name)}</b> to confirm</label>"
            f"<input id='confirm' name='confirm' autocomplete='off' required maxlength='200'>"
            "<div><button>Forget application</button></div></form>")


def forget(adm, conn, s, app_id: int, form: dict):
    from .admin import redirect
    from .generate import app_ns
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT a.ApplicationId, a.Name, a.RepositoryUrl, d.StoredAs FROM cz.Application a "
                "LEFT JOIN cz.DevDatabase d ON d.ApplicationId = a.ApplicationId WHERE a.ApplicationId = %s", (app_id,))
    r = cur.fetchone()
    if not r:
        return redirect("/admin/applications?" + urlencode({"msg": "That application is gone already."}))
    if form.get("confirm", [""])[0].strip() != r["Name"]:
        return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": f"Not forgotten: type {r['Name']} to confirm."}))
    repos = []
    try:
        if r["RepositoryUrl"]:
            cur.execute("SELECT ScanId, ProjectName, Name FROM cz.OrgRepository WHERE RepositoryUrl = %s AND RemovedAt IS NULL",
                        (r["RepositoryUrl"],))
            repos = cur.fetchall()
        note = f"application {r['Name']} forgotten by {s.user}"[:400]
        conn.cursor().execute("EXEC cz.ForgetApplication @ApplicationId = %s, @Namespace = %s, @Note = %s",
                              (app_id, app_ns(r["Name"]), note))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    if r.get("StoredAs") and getattr(adm, "devdb", None) is not None:
        try:
            from . import devdb
            devdb.remove_unused(adm.devdb, conn, r["StoredAs"])
        except Exception as ex:  # noqa: BLE001 - the file only; the rows are gone
            print(f"forget {app_id}: dev database file not removed: {type(ex).__name__}: {ex}", file=sys.stderr)
    queued = 0
    by_scan: dict = {}
    for x in repos:
        by_scan.setdefault(x["ScanId"], []).append(f"{x['ProjectName']}/{x['Name']}")
    for scan_id, names in sorted(by_scan.items()):
        try:
            c = conn.cursor()
            c.execute("EXEC cz.QueueOrgScanRun @ScanId = %s, @TriggeredBy = N'manual', @Kind = N'full', @Scope = %s",
                      (scan_id, json.dumps({"projects": [], "repositories": sorted(set(names))})))
            queued += 1 if (c.fetchone() or [0])[0] else 0
            conn.commit()
        except Exception as ex:  # noqa: BLE001 - the next run of the scan removes the files
            conn.rollback()
            print(f"forget {app_id}: scan not queued: {type(ex).__name__}: {ex}", file=sys.stderr)
    files = ("A scan of its repository is queued: it removes its files from the output repository and the sandbox."
             if queued else "Its files go from the output repository and the sandbox at the next run of its scan.")
    if not repos:
        files = "No organization scan lists its repository: its files, if any, stay."
    return redirect("/admin/applications?" + urlencode({"show": "all", "msg": f"{r['Name']} forgotten; its repository "
                                                         f"is disabled. {files}"}))
