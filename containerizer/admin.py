"""Admin pages of the web UI: business units, products, the application mapping, and the audit log.

Behind OpenID Connect sign-in (oidc.py); only users on the CONTAINERIZER_ADMINS allow-list get in.
Every change goes through a separate database login in the <schema>_admin role, with the signed-in
user put in the connection's SESSION_CONTEXT, so the audit triggers record who made it. Forms are
plain HTML posts protected by a per-session CSRF token and an Origin check; no JavaScript.
"""
from __future__ import annotations

import html
import json
import re
import secrets
import sys
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from .oidc import OidcConfig, OidcError, Provider, Session, Sessions, allowed, identity

e = html.escape
MAX_BODY = 64 * 1024
LIMITS = {"Name": 200, "DisplayName": 200, "Description": 1000, "Owner": 200, "InfoUrl": 400}
URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s<>\"'`]*)?")
TABLE_TEXT = {"BusinessUnit": "Business unit", "Product": "Product", "Application": "Application"}
FIELD_TEXT = {"Name": "Name", "DisplayName": "Display name", "Description": "Description", "Owner": "Owner",
              "Retired": "Hidden", "Product": "Product", "BusinessUnit": "Business unit", "InfoUrl": "Product page link"}


@dataclass
class Response:
    status: int
    body: str = ""
    headers: list = field(default_factory=list)
    ctype: str = "text/html; charset=utf-8"


def redirect(url: str, headers: list | None = None) -> Response:
    return Response(303, "", [("Location", url)] + (headers or []))


class Admin:
    def __init__(self, cfg: OidcConfig, connect_admin, provider: Provider | None = None):
        self.cfg = cfg
        self.connect_admin = connect_admin          # () -> sqlstore.Connection in the admin role
        self.provider = provider or Provider(cfg)
        self.sessions = Sessions()
        self.api = None                             # api.Api when the JSON API is configured
        self.cookie = ("__Host-" if cfg.secure else "") + "cz_session"
        self.login_cookie = ("__Host-" if cfg.secure else "") + "cz_login"

    # -- cookies --------------------------------------------------------------------------------

    def _set_cookie(self, name: str, value: str, max_age: int) -> tuple[str, str]:
        attrs = f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        return ("Set-Cookie", attrs + ("; Secure" if self.cfg.secure else ""))

    @staticmethod
    def _cookies(header: str | None) -> dict:
        c = SimpleCookie()
        try:
            c.load(header or "")
        except Exception:
            return {}
        return {k: v.value for k, v in c.items()}

    def session(self, headers) -> Session | None:
        return self.sessions.get(self._cookies(headers.get("Cookie")).get(self.cookie))

    def nav(self, headers) -> str:
        s = self.session(headers)
        if s and s.admin:
            return f"<a href='/admin'>Admin</a> · {e(s.name)}"
        return "<a href='/login'>Sign in</a>"

    # -- routing --------------------------------------------------------------------------------

    def handles(self, path: str) -> bool:
        return path in ("/login", "/logout", "/auth/callback") or path == "/admin" or path.startswith("/admin/")

    def handle(self, method: str, path: str, query: str, headers, body: bytes) -> Response:
        if path == "/login" and method == "GET":
            return self.login(parse_qs(query).get("next", ["/admin"])[0])
        if path == "/auth/callback" and method == "GET":
            return self.callback(headers, parse_qs(query))
        s = self.session(headers)
        if path == "/logout" and method == "POST":
            form = self._form(body)
            if s and self._csrf_ok(s, form, headers):
                self.sessions.end(self._cookies(headers.get("Cookie")).get(self.cookie))
            return redirect("/", [self._set_cookie(self.cookie, "", 0)])
        if not s:
            return redirect("/login?" + urlencode({"next": path + (("?" + query) if query else "")}))
        if not s.admin:
            return Response(403, page("Not allowed", f"<h1>Not allowed</h1><p>You are signed in as {e(s.user)}, "
                                      "but you are not an administrator of the containerization results. Ask an "
                                      "administrator to add you.</p>" + self._logout_form(s)))
        form = {}
        if method == "POST":
            if len(body) > MAX_BODY:
                return Response(413, page("Too large", "<h1>Request too large</h1>"))
            form = self._form(body)
            if not self._csrf_ok(s, form, headers):
                return Response(403, page("Expired", "<h1>The form expired</h1><p>Go back, reload the page and try again.</p>"))
        elif method != "GET":
            return Response(405, "", [("Allow", "GET, HEAD, POST")])
        conn = self.connect_admin()
        try:
            conn.set_user(s.user, s.name)
            return self.route(conn, s, method, path, parse_qs(query), form)
        finally:
            conn.close()

    def route(self, conn, s: Session, method: str, path: str, q: dict, form: dict) -> Response:
        parts = path.strip("/").split("/")[1:]
        flash = q.get("msg", [""])[0][:200]
        if not parts:
            return redirect("/admin/applications")
        kind = parts[0]
        ident = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"\d{1,9}", parts[1]) else None
        if len(parts) > 1 and ident is None and parts[1] not in ("new", "bulk"):
            return Response(404, page("Not found", "<h1>Not found</h1>"))
        if kind == "applications":
            if method == "POST" and len(parts) > 1 and parts[1] == "bulk":
                return self.bulk_map(conn, form)
            if ident is not None:
                return self.save_application(conn, ident, form) if method == "POST" else \
                    self.edit_application(conn, s, ident, flash)
            return self.list_applications(conn, s, q.get("show", ["unmapped"])[0], flash)
        if kind in ("products", "business-units"):
            table = "Product" if kind == "products" else "BusinessUnit"
            if method == "POST":
                if len(parts) > 2 and parts[2] == "delete" and ident is not None:
                    return self.delete(conn, table, ident)
                return self.save_named(conn, table, ident, form)
            if ident is not None:
                return self.edit_named(conn, s, table, ident, flash)
            return self.list_named(conn, s, table, flash)
        if kind == "audit" and method == "GET":
            return self.audit(conn, s, q)
        return Response(404, page("Not found", "<h1>Not found</h1>"))

    # -- sign-in --------------------------------------------------------------------------------

    def login(self, next_url: str) -> Response:
        if not next_url.startswith("/") or next_url.startswith("//") or "\\" in next_url:
            next_url = "/admin"
        try:
            key, p = self.sessions.begin(next_url)
            url = self.provider.authorize_url(p["state"], p["nonce"], p["verifier"])
        except OidcError as ex:
            print(f"error: sign-in: {ex}", file=sys.stderr)
            return Response(502, page("Sign-in unavailable", "<h1>Sign-in is not available</h1>"
                                      "<p>The identity provider could not be reached. The details are in the server log.</p>"))
        return redirect(url, [self._set_cookie(self.login_cookie, key, 600)])

    def callback(self, headers, q: dict) -> Response:
        clear = self._set_cookie(self.login_cookie, "", 0)
        pending = self.sessions.finish(self._cookies(headers.get("Cookie")).get(self.login_cookie))
        state = q.get("state", [""])[0]
        if not pending or not secrets.compare_digest(state, pending["state"]):
            return Response(400, page("Sign-in failed", "<h1>Sign-in failed</h1><p>The sign-in took too long or was "
                                      "started elsewhere. <a href='/login'>Try again</a>.</p>"), [clear])
        if "error" in q:
            print(f"sign-in refused by the provider: {q.get('error')} {q.get('error_description')}", file=sys.stderr)
            return Response(401, page("Sign-in failed", "<h1>Sign-in was not completed</h1>"
                                      "<p><a href='/login'>Try again</a></p>"), [clear])
        try:
            tok = self.provider.exchange(q.get("code", [""])[0], pending["verifier"])
            claims = self.provider.validate(tok["id_token"], pending["nonce"])
        except OidcError as ex:
            print(f"error: sign-in: {ex}", file=sys.stderr)
            return Response(401, page("Sign-in failed", "<h1>Sign-in failed</h1><p>The details are in the server log. "
                                      "<a href='/login'>Try again</a></p>"), [clear])
        user, name = identity(claims)
        admin = allowed(claims, self.cfg.admins)
        print(f"sign-in: {user} admin={admin}", file=sys.stderr)
        sid = self.sessions.create(user, name, admin)       # a new id at every sign-in (no fixation)
        return redirect(pending["next"], [clear, self._set_cookie(self.cookie, sid, 8 * 3600)])

    # -- forms ----------------------------------------------------------------------------------

    @staticmethod
    def _form(body: bytes) -> dict:
        try:
            return parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=2000)
        except (UnicodeDecodeError, ValueError):
            return {}

    def _csrf_ok(self, s: Session, form: dict, headers) -> bool:
        origin = headers.get("Origin")
        own = "/".join(self.cfg.public_url.split("/")[:3])          # scheme://host[:port]
        if origin and origin.rstrip("/") != own:
            return False
        return secrets.compare_digest(form.get("csrf", [""])[0], s.csrf)

    @staticmethod
    def _csrf(s: Session) -> str:
        return f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"

    def _logout_form(self, s: Session) -> str:
        return f"<form method='post' action='/logout' class='inline'>{self._csrf(s)}<button class='link'>Sign out</button></form>"

    @staticmethod
    def _text(form: dict, key: str, required: bool = False) -> tuple[str | None, str | None]:
        v = " ".join(form.get(key, [""])[0].split())
        if not v:
            return None, (f"{FIELD_TEXT[key]} is required" if required else None)
        if len(v) > LIMITS[key]:
            return None, f"{FIELD_TEXT[key]} is longer than {LIMITS[key]} characters"
        return v, None

    @staticmethod
    def _id(form: dict, key: str) -> int | None:
        v = form.get(key, [""])[0]
        return int(v) if re.fullmatch(r"\d{1,9}", v) else None

    def _shell(self, s: Session, title: str, active: str, body: str, flash: str = "") -> str:
        tabs = "".join(f"<a class='chip{' on' if k == active else ''}' href='/admin/{k}'>{t}</a>"
                       for k, t in (("applications", "Applications"), ("products", "Products"),
                                    ("business-units", "Business units"), ("audit", "Change history")))
        msg = f"<p class='note'>{e(flash)}</p>" if flash else ""
        return page(title, f"""<div class='topnav'><a href='/'>← Results</a><span>Signed in as <b>{e(s.name)}</b>
<span class='muted'>({e(s.user)})</span> {self._logout_form(s)}</span></div>
<header><h1>{e(title)}</h1></header><nav class='chips'>{tabs}</nav>{msg}{body}""")

    # -- applications ---------------------------------------------------------------------------

    def _products(self, conn) -> list[dict]:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT p.ProductId, p.Name, b.Name AS BusinessUnitName FROM cz.Product p "
                    "LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId ORDER BY p.Name")
        return cur.fetchall()

    def _product_select(self, products: list[dict], selected, name: str = "ProductId", blank: str = "(not assigned)") -> str:
        opts = [f"<option value=''>{e(blank)}</option>"] + [
            f"<option value='{int(p['ProductId'])}'{' selected' if p['ProductId'] == selected else ''}>"
            f"{e(p['Name'])}{' · ' + e(p['BusinessUnitName']) if p['BusinessUnitName'] else ''}</option>" for p in products]
        return f"<select name='{name}' id='{name}'>{''.join(opts)}</select>"

    def list_applications(self, conn, s: Session, show: str, flash: str) -> Response:
        where = {"unmapped": "a.ProductId IS NULL AND a.Retired = 0", "hidden": "a.Retired = 1"}.get(show, "a.Retired = 0")
        show = show if show in ("unmapped", "hidden") else "all"
        cur = conn.cursor(as_dict=True)
        cur.execute(f"""SELECT a.ApplicationId, COALESCE(a.DisplayName, a.Name) AS AppName, a.Name, a.RepositoryUrl, a.SourcePath,
                   p.Name AS ProductName, b.Name AS BusinessUnitName, x.Rating
            FROM cz.Application a
            LEFT JOIN cz.Product p ON p.ProductId = a.ProductId
            LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId
            OUTER APPLY (SELECT TOP (1) aa.Rating FROM cz.ApplicationAssessment aa WHERE aa.ApplicationId = a.ApplicationId
                         ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x
            WHERE {where} ORDER BY COALESCE(a.DisplayName, a.Name)""")
        apps = cur.fetchall()
        products = self._products(conn)
        filters = " ".join(f"<a class='chip{' on' if k == show else ''}' href='/admin/applications?show={k}'>{t}</a>"
                           for k, t in (("unmapped", "Not mapped"), ("all", "All"), ("hidden", "Hidden")))
        rows = "".join(
            f"<tr><td><input type='checkbox' name='app' value='{int(a['ApplicationId'])}' id='a{int(a['ApplicationId'])}' "
            f"aria-label='Select {e(a['AppName'])}'></td>"
            f"<td><a href='/admin/applications/{int(a['ApplicationId'])}'>{e(a['AppName'])}</a>"
            f"<div class='muted small'>{e(_source(a))}</div></td>"
            f"<td>{e(a['Rating'] or '-')}</td><td>{e(a['ProductName'] or '-')}</td><td>{e(a['BusinessUnitName'] or '-')}</td></tr>"
            for a in apps)
        if not products:
            assign = "<p class='muted'>Create a <a href='/admin/products'>product</a> first, then map applications to it.</p>"
        else:
            assign = (f"<div class='formrow'><label for='ProductId'>Map the selected applications to</label>"
                      f"{self._product_select(products, None, blank='(remove mapping)')}<button>Save</button></div>")
        body = (f"<p class='muted'>Applications appear here after their first scan. Select some and map them to a product, "
                f"or open one to edit its details.</p><nav class='chips'>{filters}</nav>"
                f"<form method='post' action='/admin/applications/bulk'>{self._csrf(s)}{assign}"
                f"<table><thead><tr><th></th><th>Application</th><th>Rating</th><th>Product</th><th>Business unit</th></tr></thead>"
                f"<tbody>{rows or '<tr><td colspan=5 class=muted>Nothing here.</td></tr>'}</tbody></table></form>")
        return Response(200, self._shell(s, "Application mapping", "applications", body, flash))

    def bulk_map(self, conn, form: dict) -> Response:
        ids = [int(v) for v in form.get("app", []) if re.fullmatch(r"\d{1,9}", v)][:1000]
        pid = self._id(form, "ProductId")
        if not ids:
            return redirect("/admin/applications?" + urlencode({"msg": "Select at least one application."}))
        cur = conn.cursor()
        marks = ", ".join(["%s"] * len(ids))
        cur.execute(f"UPDATE cz.Application SET ProductId = %s WHERE ApplicationId IN ({marks})", (pid, *ids))
        n = cur.rowcount
        conn.commit()
        return redirect("/admin/applications?" + urlencode({"msg": f"{n} application(s) updated."}))

    def edit_application(self, conn, s: Session, app_id: int, flash: str) -> Response:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT ApplicationId, Name, DisplayName, Description, Owner, ProductId, Retired, RepositoryUrl, SourcePath, "
                    "FirstSeenAt, LastSeenAt FROM cz.Application WHERE ApplicationId = %s", (app_id,))
        a = cur.fetchone()
        if not a:
            return Response(404, page("Not found", "<h1>Application not found</h1>"))
        products = self._products(conn)
        body = f"""<p class='muted'>Scanned as <b>{e(a['Name'])}</b> from {e(_source(a))}. First seen {_d(a['FirstSeenAt'])},
last scanned {_d(a['LastSeenAt'])}. <a href='/app/{app_id}'>View results</a></p>
<form method='post' action='/admin/applications/{app_id}' class='edit'>{self._csrf(s)}
<label for='ProductId'>Product</label>{self._product_select(products, a['ProductId'])}
<label for='DisplayName'>Display name <span class='muted'>(shown instead of {e(a['Name'])})</span></label>
<input id='DisplayName' name='DisplayName' maxlength='200' value='{e(a['DisplayName'] or '')}'>
<label for='Owner'>Owner</label><input id='Owner' name='Owner' maxlength='200' value='{e(a['Owner'] or '')}'>
<label for='Description'>Description</label><textarea id='Description' name='Description' maxlength='1000' rows='3'>{e(a['Description'] or '')}</textarea>
<label class='check'><input type='checkbox' name='Retired' value='1'{' checked' if a['Retired'] else ''}> Hide from the results
(retired or not relevant; its history is kept)</label>
<div><button>Save</button> <a href='/admin/applications'>Cancel</a></div></form>
<h2>Changes</h2>{self._history(conn, 'Application', app_id)}"""
        return Response(200, self._shell(s, a["DisplayName"] or a["Name"], "applications", body, flash))

    def save_application(self, conn, app_id: int, form: dict) -> Response:
        vals, errors = {}, []
        for k in ("DisplayName", "Owner", "Description"):
            vals[k], err = self._text(form, k)
            errors += [err] if err else []
        if errors:
            return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "; ".join(errors)}))
        cur = conn.cursor()
        cur.execute("UPDATE cz.Application SET ProductId = %s, DisplayName = %s, Owner = %s, Description = %s, Retired = %s "
                    "WHERE ApplicationId = %s", (self._id(form, "ProductId"), vals["DisplayName"], vals["Owner"],
                                                  vals["Description"], form.get("Retired", [""])[0] == "1", app_id))
        conn.commit()
        return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "Saved."}))

    # -- products and business units ------------------------------------------------------------

    def list_named(self, conn, s: Session, table: str, flash: str) -> Response:
        cur = conn.cursor(as_dict=True)
        if table == "Product":
            cur.execute("SELECT p.ProductId AS Id, p.Name, p.Owner, p.InfoUrl, b.Name AS Parent, "
                        "(SELECT COUNT(*) FROM cz.Application a WHERE a.ProductId = p.ProductId AND a.Retired = 0) AS N "
                        "FROM cz.Product p LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId ORDER BY p.Name")
            cols, kind, title = "<th>Product</th><th>Business unit</th><th>Owner</th><th class='num'>Applications</th>", "products", "Products"
        else:
            cur.execute("SELECT b.BusinessUnitId AS Id, b.Name, b.Owner, NULL AS InfoUrl, NULL AS Parent, "
                        "(SELECT COUNT(*) FROM cz.Product p WHERE p.BusinessUnitId = b.BusinessUnitId) AS N "
                        "FROM cz.BusinessUnit b ORDER BY b.Name")
            cols, kind, title = "<th>Business unit</th><th>Owner</th><th class='num'>Products</th>", "business-units", "Business units"
        rows = "".join(
            f"<tr><td><a href='/admin/{kind}/{int(r['Id'])}'>{e(r['Name'])}</a>{info_link(r['InfoUrl'])}</td>"
            + (f"<td>{e(r['Parent'] or '-')}</td>" if table == "Product" else "")
            + f"<td>{e(r['Owner'] or '-')}</td><td class='num'>{int(r['N'])}</td></tr>" for r in cur.fetchall())
        span = 4 if table == "Product" else 3
        body = (f"<table><thead><tr>{cols}</tr></thead><tbody>{rows or f'<tr><td colspan={span} class=muted>None yet.</td></tr>'}"
                f"</tbody></table><h2>Add</h2>{self._named_form(conn, s, table, None, {})}")
        return Response(200, self._shell(s, title, kind, body, flash))

    def _named_form(self, conn, s: Session, table: str, ident, r: dict) -> str:
        kind = "products" if table == "Product" else "business-units"
        parent = ""
        if table == "Product":
            cur = conn.cursor(as_dict=True)
            cur.execute("SELECT BusinessUnitId, Name FROM cz.BusinessUnit ORDER BY Name")
            opts = "".join(f"<option value='{int(b['BusinessUnitId'])}'{' selected' if b['BusinessUnitId'] == r.get('BusinessUnitId') else ''}>"
                           f"{e(b['Name'])}</option>" for b in cur.fetchall())
            parent = (f"<label for='BusinessUnitId'>Business unit</label><select id='BusinessUnitId' name='BusinessUnitId'>"
                      f"<option value=''>(not assigned)</option>{opts}</select>")
        info = ("<label for='InfoUrl'>Product page link <span class='muted'>(https link to the product in another tool, "
                f"e.g. the CMDB or product catalogue)</span></label><input id='InfoUrl' name='InfoUrl' type='url' "
                f"maxlength='400' placeholder='https://' value='{e(r.get('InfoUrl') or '')}'>") if table == "Product" else ""
        action = f"/admin/{kind}/{ident}" if ident else f"/admin/{kind}/new"
        return f"""<form method='post' action='{action}' class='edit'>{self._csrf(s)}
<label for='Name'>Name</label><input id='Name' name='Name' required maxlength='200' value='{e(r.get('Name') or '')}'>
{parent}{info}<label for='Owner'>Owner</label><input id='Owner' name='Owner' maxlength='200' value='{e(r.get('Owner') or '')}'>
<label for='Description'>Description</label><textarea id='Description' name='Description' maxlength='1000' rows='2'>{e(r.get('Description') or '')}</textarea>
<div><button>{'Save' if ident else 'Add'}</button></div></form>"""

    def edit_named(self, conn, s: Session, table: str, ident: int, flash: str) -> Response:
        cur = conn.cursor(as_dict=True)
        key = "ProductId" if table == "Product" else "BusinessUnitId"
        cur.execute(f"SELECT * FROM cz.{table} WHERE {key} = %s", (ident,))
        r = cur.fetchone()
        if not r:
            return Response(404, page("Not found", "<h1>Not found</h1>"))
        kind = "products" if table == "Product" else "business-units"
        if table == "Product":
            cur.execute("SELECT ApplicationId, COALESCE(DisplayName, Name) AS N FROM cz.Application WHERE ProductId = %s "
                        "AND Retired = 0 ORDER BY 2", (ident,))
            members = ", ".join(f"<a href='/admin/applications/{int(a['ApplicationId'])}'>{e(a['N'])}</a>" for a in cur.fetchall())
            what = "Applications"
        else:
            cur.execute("SELECT ProductId, Name FROM cz.Product WHERE BusinessUnitId = %s ORDER BY Name", (ident,))
            members = ", ".join(f"<a href='/admin/products/{int(p['ProductId'])}'>{e(p['Name'])}</a>" for p in cur.fetchall())
            what = "Products"
        delete = (f"<form method='post' action='/admin/{kind}/{ident}/delete' class='danger'>{self._csrf(s)}"
                  f"<button>Delete {e(r['Name'])}</button></form>" if not members else
                  f"<p class='muted small'>To delete it, first move its {what.lower()} elsewhere.</p>")
        body = (f"{self._named_form(conn, s, table, ident, r)}<h2>{what}</h2><p>{members or '<span class=muted>None</span>'}</p>"
                f"{delete}<h2>Changes</h2>{self._history(conn, table, ident)}")
        return Response(200, self._shell(s, r["Name"], kind, body, flash))

    def save_named(self, conn, table: str, ident: int | None, form: dict) -> Response:
        kind = "products" if table == "Product" else "business-units"
        back = f"/admin/{kind}/{ident}" if ident else f"/admin/{kind}"
        name, err1 = self._text(form, "Name", required=True)
        owner, err2 = self._text(form, "Owner")
        desc, err3 = self._text(form, "Description")
        errors = [x for x in (err1, err2, err3) if x]
        url = None
        if table == "Product":
            url, err = self._text(form, "InfoUrl")
            if url and not URL_RE.fullmatch(url):
                err = "The product page link must be a plain https:// address"
            errors += [err] if err else []
        if errors:
            return redirect(back + "?" + urlencode({"msg": "; ".join(errors)}))
        cur = conn.cursor()
        cols, vals = ["Name", "Owner", "Description"], [name, owner, desc]
        if table == "Product":
            cols += ["BusinessUnitId", "InfoUrl"]
            vals += [self._id(form, "BusinessUnitId"), url]
        key = "ProductId" if table == "Product" else "BusinessUnitId"
        try:
            if ident:
                cur.execute(f"UPDATE cz.{table} SET " + ", ".join(f"{c} = %s" for c in cols) + f" WHERE {key} = %s",
                            (*vals, ident))
            else:
                cur.execute(f"INSERT cz.{table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}); "
                            "SELECT CAST(SCOPE_IDENTITY() AS int)", tuple(vals))
                ident = cur.fetchone()[0]
            conn.commit()
        except Exception as ex:
            conn.rollback()
            if _code(ex) in (2601, 2627):
                return redirect(back + "?" + urlencode({"msg": f"There already is one named {name}."}))
            if _code(ex) == 547:
                return redirect(back + "?" + urlencode({"msg": "That business unit no longer exists."}))
            raise
        return redirect(f"/admin/{kind}/{ident}?" + urlencode({"msg": "Saved."}))

    def delete(self, conn, table: str, ident: int) -> Response:
        kind = "products" if table == "Product" else "business-units"
        key = "ProductId" if table == "Product" else "BusinessUnitId"
        try:
            conn.cursor().execute(f"DELETE cz.{table} WHERE {key} = %s", (ident,))
            conn.commit()
        except Exception as ex:
            conn.rollback()
            if _code(ex) == 547:
                return redirect(f"/admin/{kind}/{ident}?" + urlencode({"msg": "It is still in use; move what is mapped to it first."}))
            raise
        return redirect(f"/admin/{kind}?" + urlencode({"msg": "Deleted."}))

    # -- audit ----------------------------------------------------------------------------------

    def _audit_rows(self, conn, table: str | None = None, row: int | None = None, limit: int = 200) -> list[dict]:
        cur = conn.cursor(as_dict=True)
        where, params = [], []
        if table:
            where.append("TableName = %s")
            params.append(table)
        if row is not None:
            where.append("RowId = %s")
            params.append(row)
        cur.execute(f"SELECT TOP ({int(limit)}) ChangedAt, ChangedBy, ChangedByName, DbLogin, Via, TableName, RowId, RowName, "
                    f"Action, OldValues, NewValues FROM cz.AuditLog {('WHERE ' + ' AND '.join(where)) if where else ''} "
                    f"ORDER BY ChangedAt DESC, AuditId DESC", tuple(params) or None)
        return cur.fetchall()

    def _history(self, conn, table: str, row: int) -> str:
        return render_audit(self._audit_rows(conn, table, row, 50), show_target=False)

    def audit(self, conn, s: Session, q: dict) -> Response:
        table = q.get("table", [""])[0]
        table = table if table in TABLE_TEXT else None
        chips = " ".join(f"<a class='chip{' on' if (k or None) == table else ''}' href='/admin/audit{('?table=' + k) if k else ''}'>{t}</a>"
                         for k, t in (("", "All"), ("Application", "Applications"), ("Product", "Products"),
                                      ("BusinessUnit", "Business units")))
        body = (f"<p class='muted'>Every change to business units, products and the application mapping: who made it, when, "
                f"and what changed. Changes made directly in the database are recorded too, under the database login. "
                f"Latest 200.</p><nav class='chips'>{chips}</nav>{render_audit(self._audit_rows(conn, table))}")
        return Response(200, self._shell(s, "Change history", "audit", body))


def info_link(url) -> str:
    """Small external link to a product's page in another tool (only plain https URLs are ever rendered)."""
    if not url or not URL_RE.fullmatch(str(url)):
        return ""
    return f" <a class='ext small' href='{e(url)}' rel='noopener noreferrer' target='_blank'>product page ↗</a>"


def _code(ex) -> int | None:
    a = getattr(ex, "args", ())
    return a[0] if a and isinstance(a[0], int) else None


def _d(d) -> str:
    return d.strftime("%Y-%m-%d %H:%M") + " UTC" if hasattr(d, "strftime") else e(str(d or ""))


def _source(a: dict) -> str:
    if not a.get("RepositoryUrl"):
        return "a folder without a git remote"
    return a["RepositoryUrl"] + ("" if a.get("SourcePath") in (None, ".") else " / " + a["SourcePath"])


def _fmt(v) -> str:
    if v is None or v == "":
        return "(empty)"
    if v is True:
        return "yes"
    if v is False:
        return "no"
    return str(v)


def render_audit(rows: list[dict], show_target: bool = True) -> str:
    if not rows:
        return "<p class='muted'>No changes recorded.</p>"
    out = []
    for r in rows:
        try:
            old = json.loads(r["OldValues"]) if r["OldValues"] else {}
            new = json.loads(r["NewValues"]) if r["NewValues"] else {}
        except ValueError:
            old, new = {}, {}
        if r["Action"] == "update":
            changes = "".join(f"<li>{e(FIELD_TEXT.get(k, k))}: <del>{e(_fmt(old.get(k)))}</del> → <ins>{e(_fmt(new.get(k)))}</ins></li>"
                              for k in new if old.get(k) != new.get(k))
        else:
            vals = new if r["Action"] == "insert" else old
            changes = "".join(f"<li>{e(FIELD_TEXT.get(k, k))}: {e(_fmt(v))}</li>" for k, v in vals.items() if v not in (None, "", False))
        action = {"insert": "Added", "update": "Changed", "delete": "Deleted"}.get(r["Action"], r["Action"])
        if r["Action"] == "insert" and r["Via"] == "scan":
            action = "Found by a scan"
        who = e(r["ChangedByName"] or r["ChangedBy"])
        if r["ChangedByName"] and r["ChangedByName"] != r["ChangedBy"]:
            who += f" <span class='muted'>({e(r['ChangedBy'])})</span>"
        via = f"{e(r['Via'])}" + (f", database login {e(r['DbLogin'])}" if r["DbLogin"] != r["ChangedBy"] else "")
        target = f"<td>{e(TABLE_TEXT.get(r['TableName'], r['TableName']))}: <b>{e(r['RowName'] or str(r['RowId']))}</b></td>" \
            if show_target else ""
        out.append(f"<tr><td class='nowrap'>{_d(r['ChangedAt'])}</td><td>{who}<div class='muted small'>{via}</div></td>{target}"
                   f"<td>{e(action)}<ul class='changes'>{changes}</ul></td></tr>")
    head = "<th>When</th><th>Who</th>" + ("<th>What</th>" if show_target else "") + "<th>Change</th>"
    return f"<table class='audit'><thead><tr>{head}</tr></thead><tbody>{''.join(out)}</tbody></table>"


def page(title: str, body: str) -> str:
    from .webui import page as _page
    return _page(title, body)


def build(env=None) -> Admin | None:
    """The admin pages when sign-in is configured (CONTAINERIZER_OIDC_*), else None."""
    import os
    from .sqlstore import connect
    env = os.environ if env is None else env
    cfg = OidcConfig.from_env(env)
    if cfg is None:
        return None
    cs = env.get("CONTAINERIZER_ADMIN_SQL")
    pw = env.get("CONTAINERIZER_ADMIN_SQL_PASSWORD")
    if not cs or not pw:
        raise OidcError("sign-in is configured: also set CONTAINERIZER_ADMIN_SQL and CONTAINERIZER_ADMIN_SQL_PASSWORD "
                        "(a login in the <schema>_admin role)")
    from . import api
    adm = Admin(cfg, lambda: connect(cs, pw))
    adm.api = api.build(env, adm.provider, adm.connect_admin)
    return adm
