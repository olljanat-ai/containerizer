"""Admin pages of the web UI: business units, products, the application mapping, the audit log and,
when CONTAINERIZER_VIEW_AUDIT is on, the access log. Also the optional sign-in gate of the results pages.

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
from .roles import Access, owner_scopes, role_label

e = html.escape
MAX_BODY = 64 * 1024
LIMITS = {"Name": 200, "DisplayName": 200, "Description": 1000, "Owner": 200, "InfoUrl": 400}
URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s<>\"'`]*)?")
# a Grafana link from the environment: https, or plain http to this machine only (a local demo)
LINK_RE = re.compile(r"(https://[A-Za-z0-9.-]+|http://(localhost|127\.0\.0\.1|\[::1\]))(:\d{1,5})?(/[^\s<>\"'`]*)?")
TABLE_TEXT = {"BusinessUnit": "Business unit", "Product": "Product", "Application": "Application",
              "OrgScan": "Organization scan", "OrgRepository": "Repository",
              "DevDatabase": "Dev database", "RuleCandidate": "Learned rule"}
FIELD_TEXT = {"Name": "Name", "DisplayName": "Display name", "Description": "Description", "Owner": "Owner",
              "Retired": "Hidden", "Product": "Product", "BusinessUnit": "Business unit", "InfoUrl": "Product page link",
              # organization scans
              "Provider": "Provider", "Organization": "Organization", "ApiUrl": "Server", "TokenEnv": "Token variable",
              "Registry": "Image registry", "OutputRepo": "Output repository", "OutputBranch": "Output branch",
              "OutputTokenEnv": "Output token variable", "ImagePullSecret": "Image pull secret",
              "IncludeRegex": "Only repositories matching", "ExcludeRegex": "Leave out repositories matching",
              "SkipForks": "Skip forks", "StaleDays": "Skip when not updated for (days)", "Verify": "Build and run",
              "Gate": "Security gate", "PushImages": "Push images", "UseAi": "Ask the LLM", "ScheduleDays": "Days",
              "ScheduleMinute": "Time (UTC)", "Enabled": "Enabled",
              # repositories
              "Setting": "Setting", "Note": "Note", "Skipped": "Skipped by the scan", "Removed": "Removed from the organization",
              "OrgScan": "Scan",
              # dev databases
              "Engine": "Engine", "DatabaseName": "Database name", "FileName": "File", "SizeBytes": "Size (bytes)",
              "Sha256": "SHA-256", "PromptSha256": "Instructions (SHA-256)",
              # rule review
              "Kind": "Kind", "Title": "Rule", "Status": "Status", "ReviewNote": "Note", "AppliedAs": "Applied as",
              "PullRequestUrl": "Pull request", "Edited": "Edited by the reviewer"}
# Who may use the rule review pages: Session attributes, any of which lets a signed-in user in.
RULE_REVIEW_ROLES = ("admin", "operator")
UPLOAD_RE = re.compile(r"/admin/dev-databases/(\d{1,9})/upload")


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
        self.devdb = None                           # devdb.Settings when dev database uploads are on
        self.grafana_url = ""                       # CONTAINERIZER_GRAFANA_URL: link on the admin pages
        self.system = None                          # appliance.SystemPage on the appliance (System, Firewall)
        from .rulereview import ApplyConfig
        self.rule_apply = ApplyConfig()             # where approved rules go (CONTAINERIZER_RULES_*)
        self.rule_apply_error = ""                  # why approving is unavailable, shown on the rule review pages
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

    @staticmethod
    def may_review_rules(s: Session | None) -> bool:
        """The single gate of the rule review pages (RULE_REVIEW_ROLES)."""
        return bool(s) and any(getattr(s, role, False) is True for role in RULE_REVIEW_ROLES)

    def nav(self, headers) -> str:
        s = self.session(headers)
        if s and (s.admin or s.operator or s.scopes):
            return f"<a href='/admin'>Admin</a> · {e(s.name)} {self._logout_form(s)}"
        if s:
            return f"{e(s.name)} {self._logout_form(s)}"
        return "<a href='/login'>Sign in</a>"

    # -- sign-in for the results pages (CONTAINERIZER_VIEWERS) ----------------------------------

    @property
    def viewers_required(self) -> bool:
        return bool(self.cfg.viewers)

    def gate(self, headers, path: str, query: str) -> tuple[Response | None, Session | None]:
        """For a results page: (response to send instead, None) or (None, the session if any)."""
        s = self.session(headers)
        if not self.viewers_required:
            return None, s
        if not s:                           # straight to the identity provider, no sign-in page in between
            return self.login(path + (("?" + query) if query else "")), None
        if not s.viewer:
            return Response(403, page("Not allowed", f"<h1>Not allowed</h1><p>You are signed in as {e(s.user)}, "
                                      "but you have not been given access to the containerization results. Ask an "
                                      "administrator to add you.</p>" + self._logout_form(s))), None
        return None, s

    def log_access(self, user: str, name: str | None, event: str, path: str | None = None,
                   app_id: int | None = None, addr: str | None = None) -> None:
        """One row in AccessLog when CONTAINERIZER_VIEW_AUDIT is on. Errors propagate: if the access
        cannot be recorded, the page is not shown (fail closed)."""
        if not self.cfg.view_audit:
            return
        conn = self.connect_admin()
        try:
            conn.cursor().execute("INSERT cz.AccessLog (UserName, DisplayName, Event, Path, ApplicationId, ClientAddress) "
                                  "VALUES (%s, %s, %s, %s, %s, %s)",
                                  (user[:256], (name or "")[:256] or None, event, (path or "")[:400] or None, app_id,
                                   (addr or "")[:64] or None))
            conn.commit()
        finally:
            conn.close()

    # -- routing --------------------------------------------------------------------------------

    def handles(self, path: str) -> bool:
        return path in ("/login", "/logout", "/auth/callback") or path == "/admin" or path.startswith("/admin/")

    def handle(self, method: str, path: str, query: str, headers, body: bytes, addr: str | None = None) -> Response:
        if path == "/login" and method == "GET":
            return self.login(parse_qs(query).get("next", ["/admin"])[0])
        if path == "/auth/callback" and method == "GET":
            return self.callback(headers, parse_qs(query), addr)
        s = self.session(headers)
        if path == "/logout" and method == "POST":
            form = self._form(body)
            if s and self._csrf_ok(s, form, headers):
                self.sessions.end(self._cookies(headers.get("Cookie")).get(self.cookie))
                self.log_access(s.user, s.name, "sign-out", addr=addr)
                if self.viewers_required:   # "/" would send them straight back to the provider
                    return Response(200, page("Signed out", "<h1>You are signed out</h1><p><a href='/'>Sign in again</a></p>"),
                                    [self._set_cookie(self.cookie, "", 0)])
            return redirect("/", [self._set_cookie(self.cookie, "", 0)])
        if not s:
            return redirect("/login?" + urlencode({"next": path + (("?" + query) if query else "")}))
        if not (s.admin or s.operator or s.scopes):
            return Response(403, page("Not allowed", f"<h1>Not allowed</h1><p>You are signed in as {e(s.user)}, "
                                      "but you are not an administrator, operator or product owner of the "
                                      "containerization results. Ask an administrator to add you.</p>" + self._logout_form(s)))
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
            conn.set_user(s.user, s.name, role=role_label(s.admin, s.operator, s.scopes))
            return self.route(conn, s, method, path, parse_qs(query), form)
        finally:
            conn.close()

    def route(self, conn, s: Session, method: str, path: str, q: dict, form: dict) -> Response:
        parts = path.strip("/").split("/")[1:]
        flash = q.get("msg", [""])[0][:200]
        a = Access.resolve(conn, s.admin, s.operator, s.scopes)
        tabs = self._tabs(s, a)
        if not parts:
            return redirect(f"/admin/{tabs[0][0]}")
        kind = parts[0]
        if kind not in {k for k, _ in tabs}:
            known = kind in ("applications", "products", "business-units", "audit", "access", "scans", "repositories",
                             "dev-databases", "system", "firewall")
            return Response(403 if known else 404, self._shell(s, a, "Not allowed" if known else "Not found", "",
                            "<p>Your role does not include this page.</p>" if known else ""))
        if kind in ("scans", "repositories"):
            return self.route_scans(conn, s, a, method, path, q, form)
        if kind == "rules":
            from . import admin_rules
            return admin_rules.route(self, conn, s, a, method, parts, q, form, q.get("msg", [""])[0][:300])
        if kind in ("system", "firewall"):           # the appliance only; administrators only (see _tabs)
            status, body, location = self.system.handle(
                s, method, parts, q, form, lambda title, active, b, f: self._shell(s, a, title, active, b, f))
            return redirect(location) if location else Response(status, body)
        if kind == "dev-databases":
            from . import admin_devdb
            return admin_devdb.route(self, conn, s, a, method, parts, q, form)
        ident = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"\d{1,9}", parts[1]) else None
        if len(parts) > 1 and ident is None and parts[1] not in ("new", "bulk"):
            return Response(404, page("Not found", "<h1>Not found</h1>"))
        if kind == "applications":
            if method == "POST" and len(parts) > 1 and parts[1] == "bulk":
                return self.bulk_map(conn, a, form)
            if ident is not None:
                return self.save_application(conn, a, ident, form) if method == "POST" else \
                    self.edit_application(conn, s, a, ident, flash)
            return self.list_applications(conn, s, a, q.get("show", ["unmapped"])[0], flash)
        if kind in ("products", "business-units"):
            table = "Product" if kind == "products" else "BusinessUnit"
            if method == "POST":
                if len(parts) > 2 and parts[2] == "delete" and ident is not None:
                    return self.delete(conn, a, table, ident)
                return self.save_named(conn, a, table, ident, form)
            if ident is not None:
                return self.edit_named(conn, s, a, table, ident, flash)
            return self.list_named(conn, s, a, table, flash)
        if kind == "audit" and method == "GET":
            return self.audit(conn, s, a, q)
        if kind == "access" and method == "GET":
            return self.access(conn, s, a, q)
        return Response(404, page("Not found", "<h1>Not found</h1>"))

    def route_scans(self, conn, s: Session, a: Access, method: str, path: str, q: dict, form: dict) -> Response:
        from . import admin_scans
        parts = path.strip("/").split("/")[1:]
        return admin_scans.route(self, conn, s, a, method, parts[0], parts, q, form, q.get("msg", [""])[0][:300])

    def _tabs(self, s: Session, a: Access) -> list[tuple[str, str]]:
        """The admin pages this role may open, in menu order."""
        tabs = []
        if a.maps:
            tabs += [("applications", "Applications"), ("products", "Products")]
        if a.admin:
            tabs += [("business-units", "Business units")]
        if (a.admin or a.operator) and hasattr(self, "route_scans"):     # scheduled organization scans
            tabs += [("scans", "Organization scans"), ("repositories", "Repositories")]
        if self.devdb is not None and (a.admin or a.operator):           # dev database backups (admin_devdb.py)
            tabs += [("dev-databases", "Dev databases")]
        if self.may_review_rules(s):                                     # learned rules waiting for review
            tabs += [("rules", "Rule review")]
        tabs += [("audit", "Change history")]
        if a.admin and self.cfg.view_audit:
            tabs += [("access", "Access log")]
        if a.admin and self.system:                  # on the appliance: upgrade, roll back, egress firewall
            tabs += [("system", "System"), ("firewall", "Firewall")]
        return tabs

    # -- streamed uploads -----------------------------------------------------------------------

    def is_upload(self, path: str) -> bool:
        return self.devdb is not None and bool(UPLOAD_RE.fullmatch(path))

    def handle_upload(self, path: str, headers, rfile, length: int) -> Response:
        """POST /admin/dev-databases/<id>/upload, streamed from `rfile` (webui.py). Everything that
        does not need the body is checked before any of it is read."""
        s = self.session(headers)
        if not s:
            return redirect("/login?" + urlencode({"next": "/admin/dev-databases"}))
        if not (s.admin or s.operator):
            return Response(403, page("Not allowed", "<h1>Not allowed</h1><p>Only administrators and operators can "
                                      "upload dev database backups.</p>"))
        origin = headers.get("Origin")
        if origin and origin.rstrip("/") != "/".join(self.cfg.public_url.split("/")[:3]):
            return Response(403, page("Expired", "<h1>The form expired</h1><p>Go back, reload the page and try again.</p>"))
        if length <= 0:
            return Response(411, page("Length required", "<h1>Length required</h1>"))
        from . import admin_devdb
        return admin_devdb.upload(self, s, int(UPLOAD_RE.fullmatch(path).group(1)), headers, rfile, length)

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

    def callback(self, headers, q: dict, addr: str | None = None) -> Response:
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
        operator = bool(self.cfg.operators) and allowed(claims, self.cfg.operators)
        scopes = owner_scopes(claims, self.cfg.owners)
        viewer = admin or operator or bool(scopes) or (self.viewers_required and allowed(claims, self.cfg.viewers))
        print(f"sign-in: {user} role={role_label(admin, operator, scopes) or ('viewer' if viewer else '-')} "
              f"scopes={scopes if not admin else []}", file=sys.stderr)
        self.log_access(user, name, "sign-in" if viewer or not self.viewers_required else "sign-in refused", addr=addr)
        sid = self.sessions.create(user, name, admin, viewer, operator, scopes)   # a new id at every sign-in (no fixation)
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

    def _shell(self, s: Session, a: Access, title: str, active: str, body: str, flash: str = "") -> str:
        tabs = "".join(f"<a class='chip{' on' if k == active else ''}' href='/admin/{k}'>{t}</a>" for k, t in self._tabs(s, a))
        if self.grafana_url and (a.admin or a.operator):
            tabs += (f"<a class='chip' href='{e(self.grafana_url)}' rel='noopener noreferrer' target='_blank'"
                     f" title='Metrics of the scans and the scan worker'>Grafana ↗</a>")
        msg = f"<p class='note'>{e(flash)}</p>" if flash else ""
        role = role_label(s.admin, s.operator, s.scopes)
        scope = f": {e(', '.join(s.scopes))}" if s.scopes and not s.admin else ""
        return page(title, f"""<div class='topnav'><a href='/'>← Results</a><span>Signed in as <b>{e(s.name)}</b>
<span class='muted'>({e(s.user)}) · {e(role)}{scope}</span> {self._logout_form(s)}</span></div>
<header><h1>{e(title)}</h1></header><nav class='chips'>{tabs}</nav>{msg}{body}""")

    # -- applications ---------------------------------------------------------------------------

    def _products(self, conn) -> list[dict]:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT p.ProductId, p.Name, p.BusinessUnitId, b.Name AS BusinessUnitName FROM cz.Product p "
                    "LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId ORDER BY p.Name")
        return cur.fetchall()

    def _product_select(self, products: list[dict], selected, name: str = "ProductId", blank: str = "(not assigned)") -> str:
        opts = [f"<option value=''>{e(blank)}</option>"] + [
            f"<option value='{int(p['ProductId'])}'{' selected' if p['ProductId'] == selected else ''}>"
            f"{e(p['Name'])}{' · ' + e(p['BusinessUnitName']) if p['BusinessUnitName'] else ''}</option>" for p in products]
        return f"<select name='{name}' id='{name}'>{''.join(opts)}</select>"

    def list_applications(self, conn, s: Session, a: Access, show: str, flash: str) -> Response:
        where = {"unmapped": "a.ProductId IS NULL AND a.Retired = 0", "hidden": "a.Retired = 1"}.get(show, "a.Retired = 0")
        show = show if show in ("unmapped", "hidden") else "all"
        cur = conn.cursor(as_dict=True)
        cur.execute(f"""SELECT a.ApplicationId, COALESCE(a.DisplayName, a.Name) AS AppName, a.Name, a.RepositoryUrl, a.SourcePath,
                   a.ProductId, p.Name AS ProductName, b.Name AS BusinessUnitName, x.Rating
            FROM cz.Application a
            LEFT JOIN cz.Product p ON p.ProductId = a.ProductId
            LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId
            OUTER APPLY (SELECT TOP (1) aa.Rating FROM cz.ApplicationAssessment aa WHERE aa.ApplicationId = a.ApplicationId
                         ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x
            WHERE {where} ORDER BY COALESCE(a.DisplayName, a.Name)""")
        apps = cur.fetchall()
        products = [p for p in self._products(conn) if a.admin or p["ProductId"] in a.products]
        filters = " ".join(f"<a class='chip{' on' if k == show else ''}' href='/admin/applications?show={k}'>{t}</a>"
                           for k, t in (("unmapped", "Not mapped"), ("all", "All"), ("hidden", "Hidden")))

        def pick(r) -> str:
            if not a.can_map(r["ProductId"], None) and not a.admin:
                return "<span class='muted small' title='Outside your products'>-</span>"
            return (f"<input type='checkbox' name='app' value='{int(r['ApplicationId'])}' id='a{int(r['ApplicationId'])}' "
                    f"aria-label='Select {e(r['AppName'])}'>")
        rows = "".join(
            f"<tr><td>{pick(r)}</td>"
            f"<td><a href='/admin/applications/{int(r['ApplicationId'])}'>{e(r['AppName'])}</a>"
            f"<div class='muted small'>{e(_source(r))}</div></td>"
            f"<td>{e(r['Rating'] or '-')}</td><td>{e(r['ProductName'] or '-')}</td><td>{e(r['BusinessUnitName'] or '-')}</td></tr>"
            for r in apps)
        if not products:
            assign = ("<p class='muted'>Create a <a href='/admin/products'>product</a> first, then map applications to it.</p>"
                      if a.admin or a.bus else "<p class='muted'>None of your products exists yet. Ask an administrator.</p>")
        else:
            assign = (f"<div class='formrow'><label for='ProductId'>Map the selected applications to</label>"
                      f"{self._product_select(products, None, blank='(remove mapping)')}<button>Save</button></div>")
        intro = ("Applications appear here after their first scan. Select some and map them to a product, "
                 "or open one to edit its details.")
        if not a.admin:
            intro += (" As a product owner you can map applications that are not mapped yet, or are in your products, "
                      "to your products.")
        body = (f"<p class='muted'>{intro}</p><nav class='chips'>{filters}</nav>"
                f"<form method='post' action='/admin/applications/bulk'>{self._csrf(s)}{assign}"
                f"<table><thead><tr><th></th><th>Application</th><th>Rating</th><th>Product</th><th>Business unit</th></tr></thead>"
                f"<tbody>{rows or '<tr><td colspan=5 class=muted>Nothing here.</td></tr>'}</tbody></table></form>")
        return Response(200, self._shell(s, a, "Application mapping", "applications", body, flash))

    def _locked_apps(self, conn, ids: list[int]) -> list[dict]:
        """The applications' current product, locked until the end of the transaction, so the permission
        check and the update see the same data."""
        cur = conn.cursor(as_dict=True)
        cur.execute(f"SELECT ApplicationId, ProductId, COALESCE(DisplayName, Name) AS AppName FROM cz.Application "
                    f"WITH (UPDLOCK, HOLDLOCK) WHERE ApplicationId IN ({', '.join(['%s'] * len(ids))})", tuple(ids))
        return cur.fetchall()

    def bulk_map(self, conn, a: Access, form: dict) -> Response:
        ids = [int(v) for v in form.get("app", []) if re.fullmatch(r"\d{1,9}", v)][:1000]
        pid = self._id(form, "ProductId")
        if not ids:
            return redirect("/admin/applications?" + urlencode({"msg": "Select at least one application."}))
        try:
            refused = [r["AppName"] for r in self._locked_apps(conn, ids) if not a.can_map(r["ProductId"], pid)]
            if refused:
                conn.rollback()
                return redirect("/admin/applications?" + urlencode({"msg": "Not saved: outside your products: "
                                                                     + ", ".join(refused[:10])}))
            cur = conn.cursor()
            cur.execute(f"UPDATE cz.Application SET ProductId = %s WHERE ApplicationId IN ({', '.join(['%s'] * len(ids))})",
                        (pid, *ids))
            n = cur.rowcount
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return redirect("/admin/applications?" + urlencode({"msg": f"{n} application(s) updated."}))

    def edit_application(self, conn, s: Session, a: Access, app_id: int, flash: str) -> Response:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT x.ApplicationId, x.Name, x.DisplayName, x.Description, x.Owner, x.ProductId, x.Retired, x.RepositoryUrl, "
                    "x.SourcePath, x.FirstSeenAt, x.LastSeenAt, p.Name AS ProductName FROM cz.Application x "
                    "LEFT JOIN cz.Product p ON p.ProductId = x.ProductId WHERE x.ApplicationId = %s", (app_id,))
        r = cur.fetchone()
        if not r:
            return Response(404, page("Not found", "<h1>Application not found</h1>"))
        head = f"""<p class='muted'>Scanned as <b>{e(r['Name'])}</b> from {e(_source(r))}. First seen {_d(r['FirstSeenAt'])},
last scanned {_d(r['LastSeenAt'])}. <a href='/app/{app_id}'>View results</a></p>"""
        if a.can_map(r["ProductId"], r["ProductId"]):
            products = [p for p in self._products(conn) if a.admin or p["ProductId"] in a.products]
            note = "" if a.admin or r["ProductId"] is not None else \
                "<p class='muted small'>Not mapped yet: map it to one of your products to take it over.</p>"
            form = f"""{note}<form method='post' action='/admin/applications/{app_id}' class='edit'>{self._csrf(s)}
<label for='ProductId'>Product</label>{self._product_select(products, r['ProductId'])}
<label for='DisplayName'>Display name <span class='muted'>(shown instead of {e(r['Name'])})</span></label>
<input id='DisplayName' name='DisplayName' maxlength='200' value='{e(r['DisplayName'] or '')}'>
<label for='Owner'>Owner</label><input id='Owner' name='Owner' maxlength='200' value='{e(r['Owner'] or '')}'>
<label for='Description'>Description</label><textarea id='Description' name='Description' maxlength='1000' rows='3'>{e(r['Description'] or '')}</textarea>
<label class='check'><input type='checkbox' name='Retired' value='1'{' checked' if r['Retired'] else ''}> Hide from the results
(retired or not relevant; its history is kept)</label>
<div><button>Save</button> <a href='/admin/applications'>Cancel</a></div></form>"""
        else:
            form = (f"<p class='note'>This application belongs to <b>{e(r['ProductName'] or '')}</b>, which is not one of your "
                    f"products, so you can only look at it.</p><dl class='facts'><dt>Display name</dt><dd>{e(r['DisplayName'] or '-')}</dd>"
                    f"<dt>Owner</dt><dd>{e(r['Owner'] or '-')}</dd><dt>Description</dt><dd>{e(r['Description'] or '-')}</dd>"
                    f"<dt>Hidden</dt><dd>{'yes' if r['Retired'] else 'no'}</dd></dl>")
        body = f"{head}{form}<h2>Changes</h2>{self._history(conn, 'Application', app_id)}"
        return Response(200, self._shell(s, a, r["DisplayName"] or r["Name"], "applications", body, flash))

    def save_application(self, conn, a: Access, app_id: int, form: dict) -> Response:
        vals, errors = {}, []
        for k in ("DisplayName", "Owner", "Description"):
            vals[k], err = self._text(form, k)
            errors += [err] if err else []
        if errors:
            return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "; ".join(errors)}))
        pid = self._id(form, "ProductId")
        try:
            cur_rows = self._locked_apps(conn, [app_id])
            if not cur_rows:
                conn.rollback()
                return Response(404, page("Not found", "<h1>Application not found</h1>"))
            old = cur_rows[0]["ProductId"]
            # product owners: an application of theirs, or an unmapped one they map to one of their products
            if not (a.can_map(old, pid) and (a.admin or old is not None or pid is not None)):
                conn.rollback()
                return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "Not saved: that is outside your products."}))
            cur = conn.cursor()
            cur.execute("UPDATE cz.Application SET ProductId = %s, DisplayName = %s, Owner = %s, Description = %s, Retired = %s "
                        "WHERE ApplicationId = %s", (pid, vals["DisplayName"], vals["Owner"],
                                                      vals["Description"], form.get("Retired", [""])[0] == "1", app_id))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return redirect(f"/admin/applications/{app_id}?" + urlencode({"msg": "Saved."}))

    # -- products and business units ------------------------------------------------------------

    def list_named(self, conn, s: Session, a: Access, table: str, flash: str) -> Response:
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
        view_only = " <span class='muted small'>(view only)</span>"
        mine = (lambda r: True) if a.admin or table != "Product" else (lambda r: r["Id"] in a.products)
        rows = "".join(
            f"<tr><td><a href='/admin/{kind}/{int(r['Id'])}'>{e(r['Name'])}</a>{info_link(r['InfoUrl'])}"
            f"{'' if mine(r) else view_only}</td>"
            + (f"<td>{e(r['Parent'] or '-')}</td>" if table == "Product" else "")
            + f"<td>{e(r['Owner'] or '-')}</td><td class='num'>{int(r['N'])}</td></tr>" for r in cur.fetchall())
        span = 4 if table == "Product" else 3
        add = (f"<h2>Add</h2>{self._named_form(conn, s, a, table, None, {})}"
               if a.admin or (table == "Product" and a.bus) else "")
        body = (f"<table><thead><tr>{cols}</tr></thead><tbody>{rows or f'<tr><td colspan={span} class=muted>None yet.</td></tr>'}"
                f"</tbody></table>{add}")
        return Response(200, self._shell(s, a, title, kind, body, flash))

    def _named_form(self, conn, s: Session, a: Access, table: str, ident, r: dict) -> str:
        kind = "products" if table == "Product" else "business-units"
        parent = ""
        if table == "Product":
            cur = conn.cursor(as_dict=True)
            cur.execute("SELECT BusinessUnitId, Name FROM cz.BusinessUnit ORDER BY Name")
            current = r.get("BusinessUnitId")
            bus = [b for b in cur.fetchall() if a.admin or b["BusinessUnitId"] in a.bus or b["BusinessUnitId"] == current]
            opts = "".join(f"<option value='{int(b['BusinessUnitId'])}'{' selected' if b['BusinessUnitId'] == current else ''}>"
                           f"{e(b['Name'])}</option>" for b in bus)
            blank = "<option value=''>(not assigned)</option>" if a.admin or current is None and ident else ""
            parent = (f"<label for='BusinessUnitId'>Business unit</label><select id='BusinessUnitId' name='BusinessUnitId'>"
                      f"{blank}{opts}</select>")
        info = ("<label for='InfoUrl'>Product page link <span class='muted'>(https link to the product in another tool, "
                f"e.g. the CMDB or product catalogue)</span></label><input id='InfoUrl' name='InfoUrl' type='url' "
                f"maxlength='400' placeholder='https://' value='{e(r.get('InfoUrl') or '')}'>") if table == "Product" else ""
        action = f"/admin/{kind}/{ident}" if ident else f"/admin/{kind}/new"
        return f"""<form method='post' action='{action}' class='edit'>{self._csrf(s)}
<label for='Name'>Name</label><input id='Name' name='Name' required maxlength='200' value='{e(r.get('Name') or '')}'>
{parent}{info}<label for='Owner'>Owner</label><input id='Owner' name='Owner' maxlength='200' value='{e(r.get('Owner') or '')}'>
<label for='Description'>Description</label><textarea id='Description' name='Description' maxlength='1000' rows='2'>{e(r.get('Description') or '')}</textarea>
<div><button>{'Save' if ident else 'Add'}</button></div></form>"""

    def edit_named(self, conn, s: Session, a: Access, table: str, ident: int, flash: str) -> Response:
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
            members = ", ".join(f"<a href='/admin/applications/{int(x['ApplicationId'])}'>{e(x['N'])}</a>" for x in cur.fetchall())
            what = "Applications"
            editable = a.can_edit_product(ident)
            deletable = a.can_delete_product(r["BusinessUnitId"])
        else:
            cur.execute("SELECT ProductId, Name FROM cz.Product WHERE BusinessUnitId = %s ORDER BY Name", (ident,))
            members = ", ".join(f"<a href='/admin/products/{int(p['ProductId'])}'>{e(p['Name'])}</a>" for p in cur.fetchall())
            what = "Products"
            editable = deletable = a.can_edit_bu()
        if not deletable:
            delete = ""
        elif members:
            delete = f"<p class='muted small'>To delete it, first move its {what.lower()} elsewhere.</p>"
        else:
            delete = (f"<form method='post' action='/admin/{kind}/{ident}/delete' class='danger'>{self._csrf(s)}"
                      f"<button>Delete {e(r['Name'])}</button></form>")
        if editable:
            details = self._named_form(conn, s, a, table, ident, r)
        else:
            details = (f"<p class='note'>This is not one of your products, so you can only look at it.</p>"
                       f"<dl class='facts'><dt>Owner</dt><dd>{e(r.get('Owner') or '-')}</dd><dt>Product page</dt>"
                       f"<dd>{info_link(r.get('InfoUrl')) or '-'}</dd><dt>Description</dt><dd>{e(r.get('Description') or '-')}</dd></dl>")
        body = (f"{details}<h2>{what}</h2><p>{members or '<span class=muted>None</span>'}</p>"
                f"{delete}<h2>Changes</h2>{self._history(conn, table, ident)}")
        return Response(200, self._shell(s, a, r["Name"], kind, body, flash))

    def save_named(self, conn, a: Access, table: str, ident: int | None, form: dict) -> Response:
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
        bu = None
        if table == "Product":
            bu = self._id(form, "BusinessUnitId")
            cols += ["BusinessUnitId", "InfoUrl"]
            vals += [bu, url]
        key = "ProductId" if table == "Product" else "BusinessUnitId"
        denied = redirect(back + "?" + urlencode({"msg": "Not saved: that is outside your business units and products."}))
        try:
            if table == "BusinessUnit" and not a.can_edit_bu():
                return denied
            if ident:
                if table == "Product":
                    c = conn.cursor(as_dict=True)
                    c.execute("SELECT BusinessUnitId FROM cz.Product WITH (UPDLOCK, HOLDLOCK) WHERE ProductId = %s", (ident,))
                    row = c.fetchone()
                    if row and not (a.can_edit_product(ident) and a.can_set_bu(row["BusinessUnitId"], bu)):
                        conn.rollback()
                        return denied
                cur.execute(f"UPDATE cz.{table} SET " + ", ".join(f"{c} = %s" for c in cols) + f" WHERE {key} = %s",
                            (*vals, ident))
            else:
                if table == "Product" and not a.can_create_product(bu):
                    return redirect(back + "?" + urlencode({"msg": "Not saved: pick one of your business units."}))
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

    def delete(self, conn, a: Access, table: str, ident: int) -> Response:
        kind = "products" if table == "Product" else "business-units"
        key = "ProductId" if table == "Product" else "BusinessUnitId"
        try:
            if table == "Product":
                c = conn.cursor(as_dict=True)
                c.execute("SELECT BusinessUnitId FROM cz.Product WITH (UPDLOCK, HOLDLOCK) WHERE ProductId = %s", (ident,))
                row = c.fetchone()
                allowed_ = row is None or a.can_delete_product(row["BusinessUnitId"])
            else:
                allowed_ = a.can_edit_bu()
            if not allowed_:
                conn.rollback()
                return redirect(f"/admin/{kind}/{ident}?" + urlencode({"msg": "Not deleted: that is outside your business units."}))
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
        cur.execute(f"SELECT TOP ({int(limit)}) ChangedAt, ChangedBy, ChangedByName, ChangedByRole, DbLogin, Via, TableName, RowId, RowName, "
                    f"Action, OldValues, NewValues FROM cz.AuditLog {('WHERE ' + ' AND '.join(where)) if where else ''} "
                    f"ORDER BY ChangedAt DESC, AuditId DESC", tuple(params) or None)
        return cur.fetchall()

    def _history(self, conn, table: str, row: int) -> str:
        return render_audit(self._audit_rows(conn, table, row, 50), show_target=False)

    def audit(self, conn, s: Session, a: Access, q: dict) -> Response:
        table = q.get("table", [""])[0]
        table = table if table in TABLE_TEXT else None
        chips = " ".join(f"<a class='chip{' on' if (k or None) == table else ''}' href='/admin/audit{('?table=' + k) if k else ''}'>{t}</a>"
                         for k, t in (("", "All"), ("Application", "Applications"), ("Product", "Products"),
                                      ("BusinessUnit", "Business units"), ("OrgScan", "Organization scans"),
                                      ("OrgRepository", "Repositories"), ("DevDatabase", "Dev databases"),
                                      ("RuleCandidate", "Rule review")))
        body = (f"<p class='muted'>Every change to business units, products, the application mapping, organization scans, "
                f"repositories (found by a scan, enabled or disabled, skipped), dev database uploads and the rule review "
                f"(learned rules proposed, approved or rejected): who made it, when, "
                f"and what changed. Changes made directly in the database are recorded too, under the database login. "
                f"Latest 200.</p><nav class='chips'>{chips}</nav>{render_audit(self._audit_rows(conn, table))}")
        return Response(200, self._shell(s, a, "Change history", "audit", body))

    def access(self, conn, s: Session, a: Access, q: dict) -> Response:
        user = q.get("user", [""])[0][:256]
        app = q.get("app", [""])[0]
        app = int(app) if re.fullmatch(r"\d{1,9}", app) else None
        where, params = [], []
        if user:
            where.append("l.UserName = %s")
            params.append(user)
        if app is not None:
            where.append("l.ApplicationId = %s")
            params.append(app)
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT TOP (200) l.At, l.UserName, l.DisplayName, l.Event, l.Path, l.ApplicationId, l.ClientAddress, "
                    "COALESCE(a.DisplayName, a.Name) AS AppName FROM cz.AccessLog l "
                    "LEFT JOIN cz.Application a ON a.ApplicationId = l.ApplicationId "
                    f"{('WHERE ' + ' AND '.join(where)) if where else ''} ORDER BY l.At DESC, l.AccessId DESC",
                    tuple(params) or None)
        rows = []
        for r in cur.fetchall():
            who = e(r["DisplayName"] or r["UserName"])
            if r["DisplayName"] and r["DisplayName"] != r["UserName"]:
                who += f" <span class='muted'>({e(r['UserName'])})</span>"
            who = f"<a href='/admin/access?{urlencode({'user': r['UserName']})}'>{who}</a>"
            if r["ApplicationId"] is not None:
                what = (f"<a href='/app/{int(r['ApplicationId'])}'>{e(r['AppName'] or 'application ' + str(r['ApplicationId']))}</a>"
                        f" <a class='small' href='/admin/access?app={int(r['ApplicationId'])}'>(who else)</a>")
            elif r["Path"] and r["Path"].startswith("/?bu="):
                what = "Overview, one business unit"
            elif r["Path"] == "/":
                what = "Overview"
            elif r["Path"] and r["Path"].startswith("/trends"):
                what = "Trends"
            else:
                what = e(r["Path"] or "")
            event = {"view": "Viewed", "sign-in": "Signed in", "sign-out": "Signed out",
                     "sign-in refused": "Sign-in refused (not on the viewer list)"}.get(r["Event"], r["Event"])
            rows.append(f"<tr><td class='nowrap'>{_d(r['At'])}</td><td>{who}<div class='muted small'>{e(r['ClientAddress'] or '')}"
                        f"</div></td><td>{e(event)}</td><td>{what}</td></tr>")
        shown = ""
        if user or app is not None:
            shown = (" Showing " + (f"<b>{e(user)}</b>" if user else "") + (" and " if user and app is not None else "")
                     + (f"application {app}" if app is not None else "") + ". <a href='/admin/access'>Show everyone</a>.")
        body = (f"<p class='muted'>Who signed in to the results pages and which pages they opened. Latest 200.{shown}</p>"
                f"<table class='audit'><thead><tr><th>When</th><th>Who</th><th>What happened</th><th>Page</th></tr></thead>"
                f"<tbody>{''.join(rows) or '<tr><td colspan=4 class=muted>Nothing recorded.</td></tr>'}</tbody></table>")
        return Response(200, self._shell(s, a, "Access log", "access", body))


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


def _fmt(v, key: str = "") -> str:
    if key == "ScheduleDays" and isinstance(v, int):
        from .worker import DAYS
        return ", ".join(DAYS[i] for i in range(7) if v & (1 << i)) or "none (on demand only)"
    if key == "ScheduleMinute" and isinstance(v, int):
        return f"{v // 60:02d}:{v % 60:02d}"
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
            changes = "".join(f"<li>{e(FIELD_TEXT.get(k, k))}: <del>{e(_fmt(old.get(k), k))}</del> → <ins>{e(_fmt(new.get(k), k))}</ins></li>"
                              for k in new if old.get(k) != new.get(k))
        else:
            vals = new if r["Action"] == "insert" else old
            changes = "".join(f"<li>{e(FIELD_TEXT.get(k, k))}: {e(_fmt(v, k))}</li>" for k, v in vals.items() if v not in (None, "", False))
        action = {"insert": "Added", "update": "Changed", "delete": "Deleted"}.get(r["Action"], r["Action"])
        if r["Action"] == "insert" and r["Via"] == "scan":
            action = "Proposed by the learning loop" if r["TableName"] == "RuleCandidate" else "Found by a scan"
        who = e(r["ChangedByName"] or r["ChangedBy"])
        if r["ChangedByName"] and r["ChangedByName"] != r["ChangedBy"]:
            who += f" <span class='muted'>({e(r['ChangedBy'])})</span>"
        via = f"{e(r['Via'])}" + (f" as {e(r['ChangedByRole'])}" if r.get("ChangedByRole") else "") + \
            (f", database login {e(r['DbLogin'])}" if r["DbLogin"] != r["ChangedBy"] else "")
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
    grafana = (env.get("CONTAINERIZER_GRAFANA_URL") or "").strip()
    if grafana and not LINK_RE.fullmatch(grafana):
        raise OidcError("CONTAINERIZER_GRAFANA_URL must be an https:// link (http:// only to localhost)")
    from . import api
    from .rulereview import ApplyConfig, ReviewError
    adm = Admin(cfg, lambda: connect(cs, pw))
    adm.rule_apply = ApplyConfig.from_env(env)
    try:
        adm.rule_apply.check()
    except ReviewError as ex:          # the rest of the admin pages work; the rule review says why it cannot approve
        adm.rule_apply_error = str(ex)
        print(f"warning: rule review: {ex}", file=sys.stderr)
    adm.grafana_url = grafana
    adm.api = api.build(env, adm.provider, adm.connect_admin, cfg)
    from .appliance import SystemPage
    adm.system = SystemPage.detect(env)
    from . import devdb
    adm.devdb = devdb.Settings.from_env(env)
    if adm.devdb:
        adm.devdb.directory.mkdir(parents=True, exist_ok=True)
    return adm
