"""Admin pages for dev database backups (/admin/dev-databases), for admins and operators.

An operator picks an application, uploads a backup of its development database and writes the
instructions (the AI prompt) for pointing the application at it. The next scan of the application
restores the backup into a database next to it in the sandbox (devdb.py, org.py). The upload form is
multipart: webui.py streams it here (`upload`) instead of reading it into memory, after the session,
the role and the Origin header were checked, and the CSRF field (the first in the form) is checked
before a byte of the file is written.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlencode

from . import devdb
from .admin import Response, page, redirect

e = html.escape
TAB = ("dev-databases", "Dev databases")


def enabled(adm, a) -> bool:
    return adm.devdb is not None and (a.admin or a.operator)


def _app(conn, app_id: int) -> dict | None:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ApplicationId, Name, DisplayName, RepositoryUrl, SourcePath FROM cz.Application WHERE ApplicationId = %s",
                (app_id,))
    return cur.fetchone()


def _row(conn, app_id: int, lock: bool = False) -> dict | None:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT DevDatabaseId, ApplicationId, Engine, DatabaseName, FileName, SizeBytes, Sha256, StoredAs, Prompt, "
                f"UploadedAt, UploadedBy FROM cz.DevDatabase {'WITH (UPDLOCK, HOLDLOCK) ' if lock else ''}"
                "WHERE ApplicationId = %s", (app_id,))
    return cur.fetchone()


def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict) -> Response:
    flash = q.get("msg", [""])[0][:200]
    ident = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"\d{1,9}", parts[1]) else None
    if len(parts) > 1 and ident is None:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    if method == "POST":
        if ident is None:                              # the application picker
            pick = adm._id(form, "ApplicationId")
            return redirect(f"/admin/dev-databases/{pick}" if pick else "/admin/dev-databases")
        if len(parts) > 2 and parts[2] == "delete":
            return delete(adm, conn, ident)
        if len(parts) == 2:
            return save_prompt(conn, ident, form)
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    if len(parts) > 2:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    if ident is not None:
        return edit(adm, conn, s, a, ident, flash)
    return listing(adm, conn, s, a, flash)


def listing(adm, conn, s, a, flash: str) -> Response:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT d.ApplicationId, d.Engine, d.DatabaseName, d.FileName, d.SizeBytes, d.UploadedAt, d.UploadedBy, "
                "COALESCE(x.DisplayName, x.Name) AS AppName FROM cz.DevDatabase d "
                "JOIN cz.Application x ON x.ApplicationId = d.ApplicationId ORDER BY AppName")
    rows = "".join(
        f"<tr><td><a href='/admin/dev-databases/{int(r['ApplicationId'])}'>{e(r['AppName'])}</a></td>"
        f"<td>{e(devdb.ENGINES.get(r['Engine'], (r['Engine'],))[0])}</td><td>{e(r['DatabaseName'])}</td>"
        f"<td>{e(r['FileName'])} <span class='muted small'>{e(devdb.human_size(r['SizeBytes']))}</span></td>"
        f"<td class='nowrap'>{_d(r['UploadedAt'])}<div class='muted small'>{e(r['UploadedBy'])}</div></td></tr>"
        for r in cur.fetchall())
    cur.execute("SELECT ApplicationId, COALESCE(DisplayName, Name) AS AppName FROM cz.Application WHERE Retired = 0 "
                "AND ApplicationId NOT IN (SELECT ApplicationId FROM cz.DevDatabase) ORDER BY AppName")
    opts = "".join(f"<option value='{int(r['ApplicationId'])}'>{e(r['AppName'])}</option>" for r in cur.fetchall())
    picker = (f"<form method='post' action='/admin/dev-databases' class='edit'>{adm._csrf(s)}"
              f"<label for='ApplicationId'>Add a backup for</label><select id='ApplicationId' name='ApplicationId'>{opts}</select>"
              "<div><button>Continue</button></div></form>") if opts else ""
    body = (f"<p class='muted'>A backup of an application's development database, restored into a database next to the "
            f"application in the sandbox at its next scan. The instructions you write tell the AI which settings point the "
            f"application at it. Files up to {e(devdb.human_size(adm.devdb.max_bytes))}; they are kept on the server, "
            f"never in Git, and never offered for download.</p>"
            f"<table class='audit'><thead><tr><th>Application</th><th>Engine</th><th>Database</th><th>File</th>"
            f"<th>Uploaded</th></tr></thead><tbody>{rows or '<tr><td colspan=5 class=muted>None yet.</td></tr>'}</tbody></table>"
            f"{picker}")
    return Response(200, adm._shell(s, a, "Dev databases", TAB[0], body, flash))


def edit(adm, conn, s, a, app_id: int, flash: str) -> Response:
    app = _app(conn, app_id)
    if not app:
        return Response(404, page("Not found", "<h1>Application not found</h1>"))
    r = _row(conn, app_id)
    name = app["DisplayName"] or app["Name"]
    engine = r["Engine"] if r else "sqlserver"
    dbname = r["DatabaseName"] if r else re.sub(r"\W", "", name.title())[:128] or "AppDb"
    if not devdb.NAME_RE.fullmatch(dbname):
        dbname = "AppDb"
    prompt = r["Prompt"] if r and r["Prompt"] else devdb.default_prompt(app, engine, dbname)
    engines = "".join(f"<option value='{k}'{' selected' if k == engine else ''}>{e(t)}: {e(fmt)}</option>"
                      for k, (t, fmt) in devdb.ENGINES.items())
    current = ""
    if r:
        current = (f"<dl class='facts'><dt>Engine</dt><dd>{e(devdb.ENGINES[r['Engine']][0])}</dd>"
                   f"<dt>Database</dt><dd>{e(r['DatabaseName'])}</dd>"
                   f"<dt>File</dt><dd>{e(r['FileName'])} ({e(devdb.human_size(r['SizeBytes']))})</dd>"
                   f"<dt>SHA-256</dt><dd class='small'>{e(r['Sha256'])}</dd>"
                   f"<dt>Uploaded</dt><dd>{_d(r['UploadedAt'])} by {e(r['UploadedBy'])}</dd></dl>"
                   f"<form method='post' action='/admin/dev-databases/{app_id}' class='edit'>{adm._csrf(s)}"
                   f"<label for='DatabaseName'>Database name</label>"
                   f"<input id='DatabaseName' name='DatabaseName' maxlength='128' value='{e(r['DatabaseName'])}' required "
                   f"pattern='[A-Za-z_][A-Za-z0-9_]*'>"
                   f"<label for='Prompt'>Instructions for the AI</label>"
                   f"<textarea id='Prompt' name='Prompt' maxlength='{devdb.PROMPT_MAX}' rows='10'>{e(prompt)}</textarea>"
                   f"<div><button>Save the instructions</button></div></form>"
                   f"<form method='post' action='/admin/dev-databases/{app_id}/delete' class='inline'>{adm._csrf(s)}"
                   f"<button class='danger'>Remove the backup</button></form>"
                   f"<h2>Replace the backup</h2>")
    # csrf is the first field: the server checks it before it writes any of the file
    upload = (f"<form method='post' action='/admin/dev-databases/{app_id}/upload' enctype='multipart/form-data' class='edit'>"
              f"{adm._csrf(s)}"
              f"<label for='Engine'>Engine</label><select id='Engine' name='Engine'>{engines}</select>"
              f"<label for='UpDatabaseName'>Database name <span class='muted'>(the name the application expects)</span></label>"
              f"<input id='UpDatabaseName' name='DatabaseName' maxlength='128' value='{e(dbname)}' required pattern='[A-Za-z_][A-Za-z0-9_]*'>"
              f"<label for='UpPrompt'>Instructions for the AI <span class='muted'>(which setting holds the connection "
              f"string, test users, anything to run after the restore; never a password)</span></label>"
              f"<textarea id='UpPrompt' name='Prompt' maxlength='{devdb.PROMPT_MAX}' rows='10'>{e(prompt)}</textarea>"
              f"<label for='backup'>Backup file <span class='muted'>(up to {e(devdb.human_size(adm.devdb.max_bytes))})</span></label>"
              f"<input id='backup' name='backup' type='file' required accept='{devdb.ACCEPT}'>"
              f"<div><button>Upload</button> <a href='/admin/dev-databases'>Cancel</a></div></form>")
    body = (f"<p class='muted'>Scanned as <b>{e(app['Name'])}</b>. <a href='/app/{app_id}'>View results</a></p>"
            f"{current}{upload}<h2>Changes</h2>{adm._history(conn, 'DevDatabase', app_id)}")
    return Response(200, adm._shell(s, a, f"Dev database: {name}", TAB[0], body, flash))


def _fields(form: dict) -> tuple[dict, list[str]]:
    errors = []
    dbname = (form.get("DatabaseName", [""])[0] or "").strip()
    if not devdb.NAME_RE.fullmatch(dbname):
        errors.append("The database name may have letters, digits and _ (and not start with a digit)")
    prompt = (form.get("Prompt", [""])[0] or "").replace("\r\n", "\n").strip()
    if len(prompt) > devdb.PROMPT_MAX:
        errors.append(f"The instructions are longer than {devdb.PROMPT_MAX} characters")
    return {"DatabaseName": dbname, "Prompt": prompt or None}, errors


def save_prompt(conn, app_id: int, form: dict) -> Response:
    vals, errors = _fields(form)
    if errors:
        return redirect(f"/admin/dev-databases/{app_id}?" + urlencode({"msg": "; ".join(errors)}))
    cur = conn.cursor()
    try:
        cur.execute("UPDATE cz.DevDatabase SET DatabaseName = %s, Prompt = %s WHERE ApplicationId = %s",
                    (vals["DatabaseName"], vals["Prompt"], app_id))
        n = cur.rowcount
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return redirect(f"/admin/dev-databases/{app_id}?" + urlencode({"msg": "Saved." if n else "There is no backup to change."}))


def delete(adm, conn, app_id: int) -> Response:
    try:
        old = _row(conn, app_id, lock=True)
        cur = conn.cursor()
        cur.execute("DELETE FROM cz.DevDatabase WHERE ApplicationId = %s", (app_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    if old:
        devdb.remove_unused(adm.devdb, conn, old["StoredAs"])
    return redirect(f"/admin/dev-databases/{app_id}?" + urlencode({"msg": "Removed. The next scan deploys the application without it."}))


def upload(adm, s, app_id: int, headers, rfile, length: int) -> Response:
    """The multipart upload, streamed from the request. The caller checked the session, the role
    and the Origin header; the CSRF token is checked here before the file is written."""
    import secrets
    from .roles import role_label

    def csrf(fields):
        if not secrets.compare_digest((fields.get("csrf") or [""])[0], s.csrf):
            raise devdb.UploadError("The form expired. Go back, reload the page and try again.")
    back = f"/admin/dev-databases/{app_id}?"
    try:
        up = devdb.parse_multipart(rfile, length, headers.get("Content-Type") or "", adm.devdb.directory,
                                   adm.devdb.max_bytes, before_file=csrf)
    except devdb.UploadError as ex:
        return redirect(back + urlencode({"msg": f"Not uploaded: {ex}"}))
    try:
        if up.path is None:
            raise devdb.UploadError("Choose a backup file.")
        if up.size == 0:
            raise devdb.UploadError("The file is empty.")
        engine = (up.fields.get("Engine") or [""])[0]
        devdb.check_engine(engine, devdb.sniff(up.head, up.filename or ""))
        vals, errors = _fields(up.fields)
        if errors:
            raise devdb.UploadError("; ".join(errors))
        fname = (up.filename or "backup")[-200:]
        conn = adm.connect_admin()
        try:
            conn.set_user(s.user, s.name, role=role_label(s.admin, s.operator, s.scopes))
            if not _app(conn, app_id):
                raise devdb.UploadError("That application no longer exists.")
            stored = devdb.store(adm.devdb, up, engine)
            up.path = None
            try:
                old = _row(conn, app_id, lock=True)
                cur = conn.cursor()
                vals_t = (engine, vals["DatabaseName"], fname, up.size, up.sha256, stored, vals["Prompt"], s.user)
                if old:
                    cur.execute("UPDATE cz.DevDatabase SET Engine = %s, DatabaseName = %s, FileName = %s, SizeBytes = %s, "
                                "Sha256 = %s, StoredAs = %s, Prompt = %s, UploadedBy = %s, UploadedAt = SYSUTCDATETIME() "
                                "WHERE ApplicationId = %s", vals_t + (app_id,))
                else:
                    cur.execute("INSERT cz.DevDatabase (Engine, DatabaseName, FileName, SizeBytes, Sha256, StoredAs, Prompt, "
                                "UploadedBy, ApplicationId) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", vals_t + (app_id,))
                conn.commit()
            except Exception:
                conn.rollback()
                devdb.remove_unused(adm.devdb, conn, stored)
                raise
            if old and old["StoredAs"] != stored:
                devdb.remove_unused(adm.devdb, conn, old["StoredAs"])
        finally:
            conn.close()
    except devdb.UploadError as ex:
        return redirect(back + urlencode({"msg": f"Not uploaded: {ex}"}))
    finally:
        if up.path is not None:
            up.path.unlink(missing_ok=True)
    return redirect(back + urlencode({"msg": f"Uploaded {devdb.human_size(up.size)}. The next scan restores it in the sandbox."}))


def _d(d) -> str:
    from .admin import _d as fmt
    return fmt(d)
