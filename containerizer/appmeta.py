"""External application IDs: a repository names the application it belongs to in another system (a CMDB, a portfolio
tool) in `metadata.json` at its root:

    {"applicationId": "3f2b8c1e-5d6a-4b7c-9e0f-1a2b3c4d5e6f"}

The organization scan reads it after the clone (read_metadata) into cz.OrgRepository.ExternalAppId. Administrators keep
each application's ID in cz.Application.ExternalId (Admin -> Applications -> the application). Admin -> Applications
-> External IDs lists the IDs repositories declare that no application has yet, and proposes linking each to the
repository's application, or adding an application for a repository no scan assessed.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from urllib.parse import urlencode

FILE = "metadata.json"
KEY = "applicationId"
MAX_BYTES = 64 * 1024
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
e = html.escape


def clean_id(v) -> str | None:
    """An external ID as stored: trimmed, without GUID braces; None when it is not one."""
    if not isinstance(v, (str, int)):
        return None
    v = str(v).strip().strip("{}").strip()
    return v if ID_RE.fullmatch(v) else None


def read_metadata(src: Path) -> str:
    """The applicationId of `metadata.json` at the repository's root; "" when there is none (no file, not JSON, no or
    an invalid ID)."""
    f = Path(src) / FILE
    try:
        if not f.is_file() or f.is_symlink() or f.stat().st_size > MAX_BYTES:
            return ""
        doc = json.loads(f.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return ""
    if not isinstance(doc, dict):
        return ""
    v = doc.get(KEY)
    if v is None:                                   # tolerate other spellings of the key
        v = next((x for k, x in doc.items() if isinstance(k, str) and k.lower() in ("applicationid", "application_id")), None)
    return clean_id(v) or ""


# -- Admin -> Applications -> External IDs ---------------------------------------------------------------------------

def proposals(conn) -> list[dict]:
    """The repositories that declare an ID no application has, with their applications."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT r.RepositoryId, r.ProjectName, r.Name, r.WebUrl, r.RepositoryUrl, r.ExternalAppId, s.Name AS ScanName "
                "FROM cz.OrgRepository r JOIN cz.OrgScan s ON s.ScanId = r.ScanId "
                "WHERE r.RemovedAt IS NULL AND r.ExternalAppId IS NOT NULL "
                "AND NOT EXISTS (SELECT 1 FROM cz.Application a WHERE a.ExternalId = r.ExternalAppId) "
                "ORDER BY r.ProjectName, r.Name")
    repos = cur.fetchall()
    if not repos:
        return []
    cur.execute("SELECT a.ApplicationId, COALESCE(a.DisplayName, a.Name) AS AppName, a.RepositoryUrl, a.SourcePath, "
                "a.ExternalId, a.Retired FROM cz.Application a WHERE a.RepositoryUrl IS NOT NULL")
    by_url: dict = {}
    for a in cur.fetchall():
        by_url.setdefault(a["RepositoryUrl"], []).append(a)
    for r in repos:
        r["apps"] = sorted(by_url.get(r["RepositoryUrl"], []), key=lambda a: (a["SourcePath"] or "", a["ApplicationId"]))
    return repos


def view(adm, s, conn) -> str:
    rows = proposals(conn)
    trs = []
    single = 0
    for r in rows:
        name = r["Name"] if r["ProjectName"] == "_" else f"{r['ProjectName']}/{r['Name']}"
        repo = (f"<a href='{e(r['WebUrl'])}' rel='noopener noreferrer' target='_blank'>{e(name)}</a>"
                if str(r.get("WebUrl") or "").startswith("https://") else e(name))
        apps = r["apps"]
        if len([a for a in apps if not a["ExternalId"]]) == 1 and len(apps) == 1:
            single += 1
        if apps:
            acts = "".join(
                f"<form method='post' action='/admin/applications/external-link' class='inline-form'>{adm._csrf(s)}"
                f"<input type='hidden' name='ApplicationId' value='{int(a['ApplicationId'])}'>"
                f"<input type='hidden' name='ExternalId' value='{e(r['ExternalAppId'])}'>"
                f"<button class='secondary'>Link to {e(a['AppName'])}</button>"
                + (f" <span class='muted small'>replaces {e(a['ExternalId'])}</span>" if a["ExternalId"] else "")
                + "</form>" for a in apps)
        else:
            acts = (f"<form method='post' action='/admin/applications/external-add' class='inline-form'>{adm._csrf(s)}"
                    f"<input type='hidden' name='RepositoryId' value='{int(r['RepositoryId'])}'>"
                    f"<button class='secondary'>Add application</button> <span class='muted small'>not assessed: an "
                    "application for the whole repository, which the next scan of it fills</span></form>")
        trs.append(f"<tr><td>{repo}<div class='muted small'>{e(r['ScanName'])}</div></td><td><code>{e(r['ExternalAppId'])}</code></td>"
                   f"<td>{acts}</td></tr>")
    intro = ("<p class='muted'>A repository names the application it belongs to in another system in <code>metadata.json</code> "
             "at its root (<code>{\"applicationId\": \"&lt;id&gt;\"}</code>); the organization scan reads it. These IDs no "
             "application has yet: link each to the repository's application, or add one. An application's ID can also be set "
             "on its page.</p>")
    bulk = ""
    if single:
        bulk = (f"<form method='post' action='/admin/applications/external-link' class='formrow'>{adm._csrf(s)}"
                f"<input type='hidden' name='all' value='1'><button>Link {single} proposal{'s' if single != 1 else ''}</button>"
                "<span class='muted small'>the repositories with one application that has no ID yet</span></form>")
    table = (f"<table><thead><tr><th>Repository</th><th>Declared ID</th><th>Proposal</th></tr></thead><tbody>"
             f"{''.join(trs) or '<tr><td colspan=3 class=muted>Every declared ID belongs to an application.</td></tr>'}"
             "</tbody></table>")
    return intro + bulk + table


def _back(msg: str) -> "object":
    from .admin import redirect
    return redirect("/admin/applications?" + urlencode({"show": "external", "msg": msg}))


def link(conn, form: dict):
    """Set an application's external ID (one, or every single-application proposal)."""
    c = conn.cursor()
    try:
        if form.get("all", [""])[0] == "1":
            n = 0
            for r in proposals(conn):
                apps = r["apps"]
                if len(apps) == 1 and not apps[0]["ExternalId"]:
                    c.execute("UPDATE cz.Application SET ExternalId = %s WHERE ApplicationId = %s AND ExternalId IS NULL",
                              (r["ExternalAppId"], apps[0]["ApplicationId"]))
                    n += 1
            conn.commit()
            return _back(f"Linked {n} application{'s' if n != 1 else ''}.")
        app = form.get("ApplicationId", [""])[0]
        ext = clean_id(form.get("ExternalId", [""])[0])
        if not re.fullmatch(r"\d{1,9}", app) or not ext:
            return _back("Not linked: not a valid ID.")
        c.execute("UPDATE cz.Application SET ExternalId = %s WHERE ApplicationId = %s", (ext, int(app)))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _back("Linked.")


def add(conn, form: dict):
    rid = form.get("RepositoryId", [""])[0]
    if not re.fullmatch(r"\d{1,9}", rid):
        return _back("Not added.")
    cur = conn.cursor(as_dict=True)
    try:
        cur.execute("SELECT ExternalAppId FROM cz.OrgRepository WHERE RepositoryId = %s", (int(rid),))
        row = cur.fetchone()
        if not row or not row["ExternalAppId"]:
            conn.rollback()
            return _back("Not added: the repository declares no ID (any more).")
        cur.execute("EXEC cz.AddRepositoryApplication @RepositoryId = %s, @ExternalId = %s", (int(rid), row["ExternalAppId"]))
        got = cur.fetchone() or {}
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    if not got.get("ApplicationId"):
        return _back("Not added: the repository is gone.")
    from .admin import redirect
    return redirect(f"/admin/applications/{int(got['ApplicationId'])}?" + urlencode({"msg": "Added: map it to a product."}))


def save_id(conn, app_id: int, form: dict):
    """The external ID on the application's page (empty: none)."""
    from .admin import redirect
    raw = form.get("ExternalId", [""])[0].strip()
    ext = clean_id(raw) if raw else None
    if raw and not ext:
        return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "Not saved: letters, digits and . _ : - only, "
                                                                        "at most 100."}))
    try:
        conn.cursor().execute("UPDATE cz.Application SET ExternalId = %s WHERE ApplicationId = %s", (ext, app_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "Saved."}))
