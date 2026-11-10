"""Admin -> Users and roles (/admin/users), administrators only.

With CONTAINERIZER_ROLE_SOURCE=ui: the people who have signed in, their roles, and the forms that give or take a
viewer, operator or product owner role (scoped to business units or products), to a known user or to the e-mail
address of someone who has not signed in yet (userroles.py). Administrators come from CONTAINERIZER_ADMINS only:
they show as "admin (from configuration)" and nothing here makes anyone an administrator (the table refuses it
too). Every change goes through the admin login with the administrator in SESSION_CONTEXT, so the change history
records who made it. With CONTAINERIZER_ROLE_SOURCE=env (the default) the page is read-only: it lists the
allow-list rules of the environment.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlencode

from .admin import Response, _code, _d, page, redirect, render_audit
from .userroles import EMAIL_RE, ROLE_TEXT, ROLES

e = html.escape
TAB = "users"
SCOPE_RE = re.compile(r"(bu|product):(\d{1,9})")
NOTE_MAX = 400


def route(adm, conn, s, a, method: str, parts: list[str], q: dict, form: dict) -> Response:
    if not a.admin:
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Only administrators manage users and roles.</p>"))
    if method == "POST" and len(parts) == 2 and parts[1] in ("assign", "remove"):
        if not adm.cfg.ui_roles:
            return _back("Not saved: the roles come from the environment (CONTAINERIZER_ROLE_SOURCE=env).")
        return assign(conn, form) if parts[1] == "assign" else remove(conn, form)
    if method != "GET" or len(parts) > 1:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    body = listing(adm, conn, s) if adm.cfg.ui_roles else env_listing(adm)
    return Response(200, adm._shell(s, a, "Users and roles", TAB, body, q.get("msg", [""])[0][:300]))


def _back(msg: str) -> Response:
    return redirect("/admin/users?" + urlencode({"msg": msg}))


# -- reading --------------------------------------------------------------------------------------

def _assignments(conn) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT r.RoleAssignmentId, r.UserAccountId, r.PendingEmail, r.Role, r.BusinessUnitId, r.ProductId, r.Note, "
                "r.AssignedBy, r.AssignedAt, b.Name AS BusinessUnitName, p.Name AS ProductName FROM cz.RoleAssignment r "
                "LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = r.BusinessUnitId "
                "LEFT JOIN cz.Product p ON p.ProductId = r.ProductId "
                "ORDER BY r.Role, b.Name, p.Name, r.RoleAssignmentId")
    return cur.fetchall()


def _users(conn) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT UserAccountId, Email, DisplayName, AdminAtSignIn, FirstSeenAt, LastSignInAt FROM cz.UserAccount "
                "ORDER BY COALESCE(DisplayName, Email), UserAccountId")
    return cur.fetchall()


def _scope_options(conn) -> str:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT BusinessUnitId, Name FROM cz.BusinessUnit ORDER BY Name")
    bus = cur.fetchall()
    cur.execute("SELECT p.ProductId, p.Name, b.Name AS BusinessUnitName FROM cz.Product p "
                "LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId ORDER BY p.Name")
    products = cur.fetchall()
    out = ""
    if bus:
        out += "<optgroup label='Business units (and all their products)'>" + "".join(
            f"<option value='bu:{int(b['BusinessUnitId'])}'>{e(b['Name'])}</option>" for b in bus) + "</optgroup>"
    if products:
        out += "<optgroup label='Products'>" + "".join(
            f"<option value='product:{int(p['ProductId'])}'>{e(p['Name'])}"
            f"{' · ' + e(p['BusinessUnitName']) if p['BusinessUnitName'] else ''}</option>" for p in products) + "</optgroup>"
    return out


def _role_chip(adm, s, r: dict) -> str:
    text = ROLE_TEXT.get(r["Role"], r["Role"])
    if r["BusinessUnitId"] is not None:
        text += f": {r['BusinessUnitName'] or '#' + str(r['BusinessUnitId'])} (business unit)"
    elif r["ProductId"] is not None:
        text += f": {r['ProductName'] or '#' + str(r['ProductId'])}"
    title = f"Given by {r['AssignedBy']}, {_d(r['AssignedAt'])}" + (f": {r['Note']}" if r["Note"] else "")
    rid = int(r["RoleAssignmentId"])
    return (f"<span class='role' title='{e(title)}'>{e(text)}<form method='post' action='/admin/users/remove' class='inline'>"
            f"{adm._csrf(s)}<input type='hidden' name='RoleAssignmentId' value='{rid}'>"
            f"<button class='link' aria-label='Remove {e(text)}' title='Remove'>×</button></form></span>")


def listing(adm, conn, s) -> str:
    users = _users(conn)
    rows = _assignments(conn)
    by_user: dict = {}
    pending: dict = {}
    for r in rows:
        if r["UserAccountId"] is not None:
            by_user.setdefault(r["UserAccountId"], []).append(r)
        else:
            pending.setdefault(r["PendingEmail"], []).append(r)
    admin_chip = ("<span class='role admin' title='CONTAINERIZER_ADMINS matched at the last sign-in; change it in the "
                  "configuration'>admin (from configuration)</span>")
    trs = []
    for u in users:
        chips = (admin_chip if u["AdminAtSignIn"] else "") + "".join(_role_chip(adm, s, r) for r in by_user.get(u["UserAccountId"], []))
        trs.append(f"<tr><td><b>{e(u['DisplayName'] or u['Email'] or '-')}</b><div class='muted small'>{e(u['Email'] or '')}</div></td>"
                   f"<td class='nowrap'>{_d(u['LastSignInAt'])}</td><td>{chips or '<span class=muted>none</span>'}</td></tr>")
    table = (f"<table><thead><tr><th>User</th><th>Last sign-in</th><th>Roles</th></tr></thead><tbody>"
             f"{''.join(trs) or '<tr><td colspan=3 class=muted>Nobody has signed in yet.</td></tr>'}</tbody></table>")
    waiting = ""
    if pending:
        waiting = ("<h2>Waiting for a first sign-in</h2><p class='muted'>These roles apply once someone signs in with the "
                   "address, verified by the identity provider; from then on they follow that person's account, not the address.</p>"
                   "<table><thead><tr><th>E-mail</th><th>Roles</th></tr></thead><tbody>"
                   + "".join(f"<tr><td>{e(addr)}</td><td>{''.join(_role_chip(adm, s, r) for r in rs)}</td></tr>"
                             for addr, rs in sorted(pending.items())) + "</tbody></table>")
    people = "".join(f"<option value='{int(u['UserAccountId'])}'>{e(u['DisplayName'] or u['Email'] or '-')}"
                     f"{' · ' + e(u['Email']) if u['Email'] and u['DisplayName'] else ''}</option>"
                     for u in users if not u["AdminAtSignIn"])
    roles = "".join(f"<option value='{r}'>{e(ROLE_TEXT[r])}</option>" for r in ROLES)
    scopes = _scope_options(conn)
    scope_field = (f"<select id='Scope' name='Scope' multiple size='8'>{scopes}</select>" if scopes else
                   "<p class='muted small'>No business units or products yet: add them first to give a product owner role.</p>")
    form = f"""<h2>Give a role</h2><form method='post' action='/admin/users/assign' class='edit'>{adm._csrf(s)}
<label for='UserAccountId'>Person</label><select id='UserAccountId' name='UserAccountId'><option value=''>(choose someone who has signed in)</option>{people}</select>
<label for='Email'>or the e-mail address of someone who has not signed in yet</label>
<input id='Email' name='Email' type='email' maxlength='256' placeholder='jane.doe@example.com'>
<label for='Role'>Role</label><select id='Role' name='Role'>{roles}</select>
<label for='Scope'>Products and business units <span class='muted'>(product owners only; select several with Ctrl or ⌘)</span></label>
{scope_field}
<label for='Note'>Note <span class='muted'>(why; shown in the change history)</span></label>
<input id='Note' name='Note' maxlength='{NOTE_MAX}'>
<div><button>Give the role</button></div></form>"""
    intro = (f"<p class='muted'>Viewers, operators and product owners are given here (<code>CONTAINERIZER_ROLE_SOURCE=ui</code>); "
             f"a change applies at the person's next request. Administrators come only from <code>CONTAINERIZER_ADMINS</code> "
             f"({e(', '.join(adm.cfg.admins))}), and nobody can be made one here. The results pages "
             + ("need sign-in and a role (<code>CONTAINERIZER_VIEWERS_REQUIRED=true</code>)." if adm.cfg.viewers_required
                else "are readable without sign-in (<code>CONTAINERIZER_VIEWERS_REQUIRED</code> is off).") + "</p>")
    return (f"{intro}{table}{waiting}{form}<h2>Changes</h2>"
            f"{render_audit(adm._audit_rows(conn, 'RoleAssignment', None, 50))}")


def env_listing(adm) -> str:
    c = adm.cfg

    def rules(rs) -> str:
        return ", ".join(f"<code>{e(r)}</code>" for r in rs) or "<span class='muted'>not set</span>"
    owners = "<br>".join(f"{rules(rs)} → {', '.join(f'<code>{e(x)}</code>' for x in sc)}" for rs, sc in c.owners) \
        or "<span class='muted'>not set</span>"
    viewers = rules(c.viewers) if c.viewers else "<span class='muted'>not set: the results pages are readable without sign-in</span>"
    return (f"<p class='note'>The roles come from the environment (<code>CONTAINERIZER_ROLE_SOURCE=env</code>), so this page "
            f"only shows them. To give viewer, operator and product owner roles here instead, set "
            f"<code>CONTAINERIZER_ROLE_SOURCE=ui</code> and remove <code>CONTAINERIZER_OPERATORS</code>, "
            f"<code>CONTAINERIZER_PRODUCT_OWNERS</code> and <code>CONTAINERIZER_VIEWERS</code> "
            f"(<code>CONTAINERIZER_VIEWERS_REQUIRED=true</code> then keeps the results pages behind sign-in).</p>"
            f"<table><thead><tr><th>Role</th><th>Variable</th><th>Rules</th></tr></thead><tbody>"
            f"<tr><td>Admin</td><td><code>CONTAINERIZER_ADMINS</code></td><td>{rules(c.admins)}</td></tr>"
            f"<tr><td>Operator</td><td><code>CONTAINERIZER_OPERATORS</code></td><td>{rules(c.operators)}</td></tr>"
            f"<tr><td>Product owner</td><td><code>CONTAINERIZER_PRODUCT_OWNERS</code></td><td>{owners}</td></tr>"
            f"<tr><td>Viewer</td><td><code>CONTAINERIZER_VIEWERS</code></td><td>{viewers}</td></tr></tbody></table>")


# -- changes --------------------------------------------------------------------------------------

def assign(conn, form: dict) -> Response:
    uid = form.get("UserAccountId", [""])[0].strip()
    email = form.get("Email", [""])[0].strip().lower()
    role = form.get("Role", [""])[0]
    note = " ".join(form.get("Note", [""])[0].split()) or None
    if role == "admin":
        return _back("Not saved: administrators come from CONTAINERIZER_ADMINS only.")
    if role not in ROLES:
        return _back("Not saved: choose a role.")
    if bool(uid) == bool(email):
        return _back("Not saved: choose a person or type an e-mail address (one of them).")
    if uid and not re.fullmatch(r"\d{1,9}", uid):
        return _back("Not saved: choose a person from the list.")
    if email and (len(email) > 256 or not EMAIL_RE.fullmatch(email)):
        return _back("Not saved: that is not an e-mail address.")
    if note and len(note) > NOTE_MAX:
        return _back(f"Not saved: the note is longer than {NOTE_MAX} characters.")
    scopes = [(m[1], int(m[2])) for v in form.get("Scope", []) if (m := SCOPE_RE.fullmatch(v))][:200]
    if role == "product-owner" and not scopes:
        return _back("Not saved: a product owner needs at least one product or business unit.")
    if role != "product-owner":
        scopes = [(None, None)]
    cur = conn.cursor()
    try:
        who = email
        if uid:
            cur.execute("SELECT COALESCE(DisplayName, Email), AdminAtSignIn FROM cz.UserAccount WHERE UserAccountId = %s", (int(uid),))
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return _back("Not saved: that user no longer exists.")
            if row[1]:
                conn.rollback()
                return _back(f"Not saved: {row[0]} is an administrator (from the configuration).")
            who = row[0]
        added = 0
        for kind, ident in scopes:
            bu, product = (ident, None) if kind == "bu" else (None, ident) if kind == "product" else (None, None)
            cur.execute("INSERT cz.RoleAssignment (UserAccountId, PendingEmail, Role, BusinessUnitId, ProductId, Note) "
                        "SELECT %s, %s, %s, %s, %s, %s WHERE NOT EXISTS (SELECT 1 FROM cz.RoleAssignment x WHERE "
                        "(x.UserAccountId = %s OR x.PendingEmail = %s) AND x.Role = %s "
                        "AND ISNULL(x.BusinessUnitId, 0) = ISNULL(%s, 0) AND ISNULL(x.ProductId, 0) = ISNULL(%s, 0))",
                        (int(uid) if uid else None, email or None, role, bu, product, note,
                         int(uid) if uid else None, email or None, role, bu, product))
            added += max(cur.rowcount, 0)
        conn.commit()
    except Exception as ex:
        conn.rollback()
        if _code(ex) == 547:
            return _back("Not saved: a product or business unit chosen no longer exists.")
        if _code(ex) in (2601, 2627):
            return _back("Not saved: that role was given at the same moment by someone else.")
        raise
    if not added:
        return _back(f"Nothing to do: {who} has that role already.")
    return _back(f"Saved: {who} is {'now ' if uid else 'to be '}{ROLE_TEXT[role]}"
                 + (f" of {added} product(s) or business unit(s)" if role == "product-owner" else "")
                 + ("." if uid else " from their first sign-in."))


def remove(conn, form: dict) -> Response:
    rid = form.get("RoleAssignmentId", [""])[0]
    if not re.fullmatch(r"\d{1,9}", rid):
        return _back("Not removed: no role chosen.")
    cur = conn.cursor()
    try:
        cur.execute("DELETE cz.RoleAssignment WHERE RoleAssignmentId = %s", (int(rid),))
        n = cur.rowcount
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _back("Removed: it applies at the person's next request." if n else "Already removed.")
