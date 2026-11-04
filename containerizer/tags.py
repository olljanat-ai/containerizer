"""Tags of applications: administrators and operators add them on an application's results page, and
everyone filters the front page by them (docs/sign-in.md#application-tags).

A tag is 1-40 letters, digits, spaces and `- _ . + / & #`, compared without regard to case. An application
has up to 20, stored comma-separated in Application.Tags (schema 37; the change history records them).

- POST /admin/tags/<application id>: Tags = "pci, customer-facing" replaces the application's tags
  (empty: none). Plain HTML form with the session's CSRF token (admin.py checks every POST), fixed notice
  texts, back to the results page.
"""
from __future__ import annotations

import re
import sys
from html import escape

TAG_RE = re.compile(r"[\w .+/&#-]{1,40}")
MAX_TAGS = 20
NOTICES = {"saved": ("ok", "Tags saved."),
           "bad": ("bad", "Not saved: a tag is 1-40 letters, digits, spaces and - _ . + / & #, separated by commas."),
           "many": ("bad", f"Not saved: at most {MAX_TAGS} tags."),
           "unavailable": ("bad", "Tags need the database schema of this version: run `containerizer db init`.")}


def split_tags(stored) -> list[str]:
    """Application.Tags as a list (empty for NULL)."""
    return [t for t in (str(stored or "")).split(",") if t]


def parse_tags(text: str) -> tuple[list[str] | None, str | None]:
    """The form's comma-separated tags, cleaned (spaces collapsed, duplicates dropped regardless of case), or
    (None, notice code) when one is not a tag."""
    out: list[str] = []
    for raw in (text or "").split(","):
        t = " ".join(raw.split())
        if not t:
            continue
        if not TAG_RE.fullmatch(t):
            return None, "bad"
        if t.casefold() not in {x.casefold() for x in out}:
            out.append(t)
    if len(out) > MAX_TAGS:
        return None, "many"
    return out, None


def has_tag(stored, tag: str) -> bool:
    return tag.casefold() in {t.casefold() for t in split_tags(stored)}


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{escape(text)}</div>"


def may_edit(s) -> bool:
    """Administrators and operators (not product owners or viewers)."""
    return bool(s and (s.admin or s.operator))


def route(adm, conn, s, a, method: str, parts: list, form: dict):
    from .admin import Response, page, redirect
    if not (a.admin or a.operator):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    if len(parts) != 2 or method != "POST" or not re.fullmatch(r"\d{1,9}", parts[1]):
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    app_id = int(parts[1])

    def back(code: str):
        return redirect(f"/app/{app_id}?tags={code}#tags")
    tags, err = parse_tags(form.get("Tags", [""])[0])
    if err:
        return back(err)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE cz.Application SET Tags = %s WHERE ApplicationId = %s", (",".join(tags) or None, app_id))
        n = cur.rowcount
        conn.commit()
    except Exception as ex:  # noqa: BLE001 - a database from before schema 37
        conn.rollback()
        print(f"tags of application {app_id}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return back("unavailable")
    if not n:
        return Response(404, page("Not found", "<h1>Application not found</h1>"))
    return back("saved")
