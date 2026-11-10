"""Roles given on the admin pages (CONTAINERIZER_ROLE_SOURCE=ui): who has which, read from the database.

Everyone who signs in gets a UserAccount row, keyed by the provider's issuer and stable subject (`sub`). An
administrator gives a viewer, operator or product owner role (scoped to business units or products by id) to
a known user, or to an e-mail address of someone who has not signed in yet. Such a pending assignment is bound
to the subject at that person's first sign-in with a matching address the provider vouches for (see
binding_addresses), and from then on matched by the subject only: whoever gets the address later does not
inherit the role. There is no admin role here: administrators come from CONTAINERIZER_ADMINS only, and the
table's CHECK constraint refuses one.

The roles are read again on every request (Admin.session), so a removed role is gone at the person's next request.
"""
from __future__ import annotations

import re

ROLES = ("viewer", "operator", "product-owner")
ROLE_TEXT = {"viewer": "viewer", "operator": "operator", "product-owner": "product owner"}
EMAIL_RE = re.compile(r"[^@\s<>\"'`,;]{1,128}@[A-Za-z0-9.-]{1,120}\.[A-Za-z0-9-]{2,63}")


def binding_addresses(claims: dict) -> list[str]:
    """The addresses a pending assignment may bind to at this sign-in, lower case. When the provider says
    whether the e-mail is verified (email_verified), only a verified e-mail counts; otherwise (Entra ID sends
    no email_verified) the address the audit log uses for the person (oidc.identity: email, preferred_username
    or upn)."""
    if "email_verified" in claims:
        email = str(claims.get("email") or "").strip().lower()
        return [email] if email and claims.get("email_verified") in (True, "true") and EMAIL_RE.fullmatch(email) else []
    for k in ("email", "preferred_username", "upn"):
        v = str(claims.get(k) or "").strip().lower()
        if v:
            return [v] if EMAIL_RE.fullmatch(v) else []
    return []


def sign_in(conn, claims: dict, admin: bool) -> int:
    """Record the sign-in (UserAccount, by issuer and subject) and bind the pending assignments of the person's
    address to it. Commits; returns the UserAccountId. `conn` is the admin login, set_user'd to the person."""
    from .oidc import identity
    user, name = identity(claims)
    email = None if user.startswith("sub:") else user[:256]
    issuer, subject = str(claims.get("iss") or "")[:300], str(claims["sub"])[:255]
    cur = conn.cursor()
    try:
        cur.execute("SELECT UserAccountId FROM cz.UserAccount WITH (UPDLOCK, HOLDLOCK) WHERE Issuer = %s AND Subject = %s",
                    (issuer, subject))
        row = cur.fetchone()
        if row:
            account = int(row[0])
            cur.execute("UPDATE cz.UserAccount SET Email = %s, DisplayName = %s, AdminAtSignIn = %s, "
                        "LastSignInAt = SYSUTCDATETIME() WHERE UserAccountId = %s", (email, name[:256], admin, account))
        else:
            cur.execute("INSERT cz.UserAccount (Issuer, Subject, Email, DisplayName, AdminAtSignIn) VALUES (%s, %s, %s, %s, %s); "
                        "SELECT CAST(SCOPE_IDENTITY() AS int)", (issuer, subject, email, name[:256], admin))
            account = int(cur.fetchone()[0])
        addrs = binding_addresses(claims)
        if addrs:
            marks = ", ".join(["%s"] * len(addrs))
            # a pending role the person has already: drop the pending copy instead of binding a duplicate
            cur.execute(f"""DELETE p FROM cz.RoleAssignment p WHERE p.UserAccountId IS NULL AND p.PendingEmail IN ({marks})
                AND EXISTS (SELECT 1 FROM cz.RoleAssignment x WHERE x.UserAccountId = %s AND x.Role = p.Role
                            AND ISNULL(x.BusinessUnitId, 0) = ISNULL(p.BusinessUnitId, 0) AND ISNULL(x.ProductId, 0) = ISNULL(p.ProductId, 0))""",
                        (*addrs, account))
            cur.execute(f"UPDATE cz.RoleAssignment SET UserAccountId = %s, PendingEmail = NULL "
                        f"WHERE UserAccountId IS NULL AND PendingEmail IN ({marks})", (account, *addrs))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return account


def find_account(conn, issuer: str, subject: str) -> int | None:
    """A known user by issuer and subject (the API's access tokens), or None. Never binds pending assignments."""
    cur = conn.cursor()
    cur.execute("SELECT UserAccountId FROM cz.UserAccount WHERE Issuer = %s AND Subject = %s", (issuer[:300], subject[:255]))
    row = cur.fetchone()
    return int(row[0]) if row else None


def load(conn, account: int | None) -> tuple[bool, bool, list[str], list[str]]:
    """(operator, viewer, product owner scopes, the scopes by name) of a user. The scopes are by id
    (bu:#3, product:#12), for roles.Access.resolve."""
    if account is None:
        return False, False, [], []
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT r.Role, r.BusinessUnitId, r.ProductId, b.Name AS BusinessUnitName, p.Name AS ProductName "
                "FROM cz.RoleAssignment r LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = r.BusinessUnitId "
                "LEFT JOIN cz.Product p ON p.ProductId = r.ProductId WHERE r.UserAccountId = %s "
                "ORDER BY r.Role, b.Name, p.Name", (account,))
    operator = viewer = False
    scopes, names = [], []
    for r in cur.fetchall():
        if r["Role"] == "operator":
            operator = True
        elif r["Role"] == "viewer":
            viewer = True
        elif r["BusinessUnitId"] is not None:
            scopes.append(f"bu:#{int(r['BusinessUnitId'])}")
            names.append(f"bu:{r['BusinessUnitName']}")
        elif r["ProductId"] is not None:
            scopes.append(f"product:#{int(r['ProductId'])}")
            names.append(f"product:{r['ProductName']}")
    return operator, viewer, scopes, names
