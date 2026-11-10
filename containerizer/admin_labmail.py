"""Admin -> Lab mail (/admin/lab-mail): the mail the applications in the sandbox sent, for administrators and operators.

The lab's Mail (SMTP) service (labservices.py, `smtp`) gives each application that sends mail its own catch-all
mailbox; nothing is sent on. This page is one inbox over all of them, the newest first, with the application
each message came from:

- GET /admin/lab-mail[?ns=<namespace>]        the inbox (one application's mailbox with ns);
- GET /admin/lab-mail/<namespace>/<message>   one message: its addresses, its text (or its HTML as text and as
                                              source) and the names of its attachments.

Everything is read through the system agent (labmail.py), which checks the namespace and the message id again.
HTML is never rendered (the page's Content-Security-Policy allows no frames, and a message is untrusted): it is
shown as text with its tags removed, and as escaped source. Reads are logged like other results views when
CONTAINERIZER_VIEW_AUDIT is on.
"""
from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from urllib.parse import urlencode

from . import labservices as L
from .admin import Response, page

e = html.escape
TAB = ("lab-mail", "Lab mail")
WAIT = 45
CLIP = " <span class='muted small'>(attachment)</span>"


def enabled(adm, a) -> bool:
    return bool(adm.system) and bool(a.admin or a.operator)


def _apps(conn) -> dict[str, dict]:
    """{namespace: {id, name}} from cz.vSandboxNamespace (the latest check of each namespace)."""
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT v.Namespace, v.ApplicationId, COALESCE(a.DisplayName, a.Name) AS Name, v.CheckedAt "
                    "FROM cz.vSandboxNamespace v JOIN cz.Application a ON a.ApplicationId = v.ApplicationId "
                    "ORDER BY v.CheckedAt")
        return {r["Namespace"]: {"id": r["ApplicationId"], "name": r["Name"]} for r in cur.fetchall()}
    except Exception:  # noqa: BLE001 - a database from before schema 38: namespaces only
        conn.rollback()
        return {}


def _ask(adm, s, **args) -> tuple[dict | None, str | None]:
    ans = adm.system.ask("labmail", s.user, s.name, wait=WAIT, **args)
    if ans is None:
        return None, (f"The appliance did not answer within {WAIT} seconds. The system agent may be busy (an upgrade, "
                      "another request); try again in a moment.")
    if ans.get("error"):
        return None, str(ans["error"])
    return ans, None


def _who(a: dict) -> str:
    name, addr = a.get("name") or "", a.get("address") or ""
    return f"{name} <{addr}>" if name and addr else (addr or name)


def _list(xs: list[dict]) -> str:
    return ", ".join(_who(x) for x in xs or [])


def _when(v: str) -> str:
    return v.replace("T", " ")[:19] if v else ""


def _app_cell(apps: dict, ns: str) -> str:
    app = apps.get(ns)
    if app:
        return (f"<a href='/results/{int(app['id'])}'>{e(str(app['name']))}</a>"
                f"<div class='muted small'>{e(ns)}</div>")
    return e(ns)


class _Text(HTMLParser):
    """The text of an HTML message: no tags, no scripts or styles, paragraphs as new lines."""
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "title"):
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n")
        elif tag == "a":
            href = dict(attrs).get("href") or ""
            if href.startswith(("http://", "https://", "mailto:")):
                self.out.append("")
                self._href = href
                return
        self._href = None

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self.skip = max(0, self.skip - 1)
        elif tag == "a" and getattr(self, "_href", None):
            self.out.append(f" [{self._href}]")
            self._href = None
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_text(src: str) -> str:
    p = _Text()
    try:
        p.feed(src)
        p.close()
    except Exception:  # noqa: BLE001 - broken HTML: what was read so far
        pass
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.out))
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict) -> Response:
    if method != "GET":
        return Response(405, page("Not allowed", "<h1>Not allowed</h1>"))
    if len(parts) == 1:
        return inbox(adm, conn, s, a, (q.get("ns", [""])[0] or "").strip())
    if len(parts) == 3 and L.NS_RE.fullmatch(parts[1]) and re.fullmatch(r"[A-Za-z0-9]{8,40}", parts[2]):
        return show(adm, conn, s, a, parts[1], parts[2])
    return Response(404, page("Not found", "<h1>Not found</h1>"))


def inbox(adm, conn, s, a, ns: str) -> Response:
    if ns and not L.NS_RE.fullmatch(ns):
        ns = ""
    adm.log_access(s.user, s.name, "view", "/admin/lab-mail" + (f"?ns={ns}" if ns else ""))
    apps = _apps(conn)
    ans, err = _ask(adm, s, op="list", **({"namespace": ns} if ns else {}))
    intro = ("<p class='muted'>Mail the applications in the sandbox sent. The lab's <b>Mail (SMTP)</b> service "
             "(Admin -> Lab services) gives each application that sends mail its own mailbox, and the scan points the "
             "application's SMTP settings at it, so every message lands here and none leaves the appliance. Each mailbox "
             f"keeps the newest {L.MAIL_MAX:,} messages, for at most {L.MAIL_MAX_AGE.replace('d', ' days')}. "
             "<a href='https://containerizer.eu/lab-services/#mail' rel='noopener noreferrer' target='_blank'>How it works ↗</a></p>")
    if err:
        body = intro + f"<p class='note'>{e(err)}</p>"
        return Response(200, adm._shell(s, a, "Lab mail", TAB[0], body))
    boxes = ans.get("mailboxes") or []
    msgs = ans.get("messages") or []
    chips = "".join(
        f"<a class='chip{' on' if b['namespace'] == ns else ''}' href='/admin/lab-mail?{urlencode({'ns': b['namespace']})}'>"
        f"{e(str((apps.get(b['namespace']) or {}).get('name') or b['namespace']))} ({int(b.get('total') or 0)})</a>"
        for b in boxes)
    if ns:
        chips = "<a class='chip' href='/admin/lab-mail'>All</a>" + chips
    problems = "".join(f"<li>{e(b['namespace'])}: {e(str(b['error']))}</li>" for b in boxes if b.get("error"))
    rows = "".join(
        f"<tr><td class='small'>{e(_when(m.get('created') or ''))}</td><td>{_app_cell(apps, m['namespace'])}</td>"
        f"<td class='small'>{e(_who(m.get('from') or {}))}</td><td class='small'>{e(_list(m.get('to')))}</td>"
        f"<td><a href='/admin/lab-mail/{e(m['namespace'])}/{e(m['id'])}'>{e(m.get('subject') or '(no subject)')}</a>"
        f"{CLIP if m.get('attachments') else ''}<div class='muted small'>{e(m.get('snippet') or '')}</div></td></tr>"
        for m in msgs if L.NS_RE.fullmatch(m.get("namespace") or "") and re.fullmatch(r"[A-Za-z0-9]{8,40}", m.get("id") or ""))
    if not boxes:
        body = intro + ("<p>No application has a mailbox in the lab yet. A mailbox starts when the scan of an application "
                        "that sends mail deploys it to the sandbox with the Mail (SMTP) service on.</p>")
    else:
        body = (intro + f"<div class='chips'>{chips}</div>"
                + (f"<p class='note'>Some mailboxes could not be read:</p><ul>{problems}</ul>" if problems else "")
                + ("<table class='audit'><thead><tr><th>Received</th><th>Application</th><th>From</th><th>To</th>"
                   f"<th>Subject</th></tr></thead><tbody>{rows}</tbody></table>" if rows else "<p>No mail yet.</p>")
                + f"<p class='muted small'>The newest {100} messages of each mailbox.</p>")
    return Response(200, adm._shell(s, a, "Lab mail", TAB[0], body))


def show(adm, conn, s, a, ns: str, ident: str) -> Response:
    path = f"/admin/lab-mail/{ns}/{ident}"
    apps = _apps(conn)
    app = apps.get(ns) or {}
    adm.log_access(s.user, s.name, "view", path, app.get("id"))
    ans, err = _ask(adm, s, op="show", namespace=ns, message=ident)
    back = f"<p><a href='/admin/lab-mail?{urlencode({'ns': ns})}'>← {e(str(app.get('name') or ns))}: all mail</a></p>"
    if err:
        return Response(200, adm._shell(s, a, "Lab mail", TAB[0], back + f"<p class='note'>{e(err)}</p>"))
    m = ans.get("message") or {}
    head = [("From", _who(m.get("from") or {})), ("To", _list(m.get("to"))), ("Cc", _list(m.get("cc"))),
            ("Bcc", _list(m.get("bcc"))), ("Reply to", _list(m.get("reply_to"))), ("Received", _when(m.get("created") or "")),
            ("SMTP login", m.get("username") or ""), ("Message-ID", m.get("message_id") or "")]
    dl = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in head if v)
    dl += f"<tr><th>Application</th><td>{_app_cell(apps, ns)}</td></tr>"
    text, src = m.get("text") or "", m.get("html") or ""
    if text.strip():
        bodytxt = f"<pre class='mail-body'>{e(text)}</pre>"
    elif src.strip():
        bodytxt = ("<p class='muted small'>An HTML message, shown as text (it is never rendered here).</p>"
                   f"<pre class='mail-body'>{e(html_text(src))}</pre>")
    else:
        bodytxt = "<p class='muted'>(no text)</p>"
    if src.strip():
        bodytxt += f"<details><summary>HTML source</summary><pre class='mail-body'>{e(src)}</pre></details>"
    if m.get("truncated"):
        bodytxt += "<p class='muted small'>The message is longer; this is its beginning.</p>"
    files = "".join(f"<li>{e(f.get('name') or '(no name)')} <span class='muted small'>{e(f.get('type') or '')}, "
                    f"{int(f.get('size') or 0):,} bytes</span></li>" for f in m.get("files") or [])
    body = (back + f"<h2>{e(m.get('subject') or '(no subject)')}</h2><table class='audit'><tbody>{dl}</tbody></table>"
            + bodytxt + (f"<h3>Attachments</h3><ul>{files}</ul>" if files else ""))
    return Response(200, adm._shell(s, a, "Lab mail", TAB[0], body))
