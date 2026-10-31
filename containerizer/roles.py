"""Who may do what on the admin pages and the API.

    viewer          read the results pages (only matters when CONTAINERIZER_VIEWERS is set)
    product owner   read everything; change the mapping, names, owners and product links of the
                    applications and products in their scope (business units or products)
    operator        read everything; organization scans, repositories and the Grafana link
    admin           everything, including business units and the access log

Admins, operators and product owners can all read the results pages. The roles come from the sign-in
(or the API access token) through allow-list rules in the environment:

    CONTAINERIZER_ADMINS=group:<id>,role:Containerizer.Admin
    CONTAINERIZER_OPERATORS=role:Containerizer.Operator
    CONTAINERIZER_PRODUCT_OWNERS=role:Finance.Owner=bu:Finance; group:<id>=product:Billing,product:#12

A product owner entry is `<rules>=<scopes>`; entries are separated by `;`, rules and scopes by `,`.
A scope is `bu:<name>` or `product:<name>` (matched without regard to case), or `bu:#<id>` /
`product:#<id>`, which survive renames. A business unit scope covers all its products, and lets the
owner add products to it and delete empty ones; a product scope covers that product's applications
and details only. Scopes are resolved against the database on every request, so a renamed product
drops out of a name scope at once.

The checks are in the application: all writes use the one admin database login, so the database
cannot tell roles apart. The role is recorded with every change (AuditLog.ChangedByRole).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .oidc import OidcError, allowed, check_rules

SCOPE_RE = re.compile(r"(bu|product):(#\d{1,9}|[^,;=#][^,;=]{0,199})")


def parse_owners(value: str | None) -> list[tuple[list[str], list[str]]]:
    """CONTAINERIZER_PRODUCT_OWNERS into [(rules, scopes)]; raises OidcError with the reason."""
    out = []
    for entry in (value or "").split(";"):
        if not entry.strip():
            continue
        rules_s, sep, scopes_s = entry.partition("=")
        rules = [r.strip() for r in rules_s.split(",") if r.strip()]
        scopes = [" ".join(s.split()) for s in scopes_s.split(",") if s.strip()]
        if not sep or not rules or not scopes:
            raise OidcError(f"CONTAINERIZER_PRODUCT_OWNERS: {entry.strip()!r} is not <rules>=<scopes> "
                            "(e.g. role:Finance.Owner=bu:Finance)")
        check_rules(rules, name="CONTAINERIZER_PRODUCT_OWNERS")
        for sc in scopes:
            if not SCOPE_RE.fullmatch(sc):
                raise OidcError(f"CONTAINERIZER_PRODUCT_OWNERS: unknown scope {sc!r} "
                                "(bu:<name>, product:<name>, bu:#<id> or product:#<id>)")
        out.append((rules, scopes))
    return out


def owner_scopes(claims: dict, owners: list[tuple[list[str], list[str]]]) -> list[str]:
    """The scopes of every product owner entry these claims match."""
    scopes: list[str] = []
    for rules, sc in owners:
        if allowed(claims, rules):
            scopes += [s for s in sc if s not in scopes]
    return scopes


def role_label(admin: bool, operator: bool, scopes: list[str]) -> str:
    if admin:
        return "admin"
    return ", ".join(r for r, on in (("operator", operator), ("product owner", bool(scopes))) if on)


@dataclass
class Access:
    """What one signed-in user or API caller may change, resolved against the database."""
    admin: bool
    operator: bool = False
    bus: set = field(default_factory=set)          # business unit ids in scope
    products: set = field(default_factory=set)     # product ids in scope (including those of `bus`)

    @property
    def owner(self) -> bool:
        return bool(self.bus or self.products)

    @property
    def maps(self) -> bool:
        """May use the mapping pages at all."""
        return self.admin or self.owner

    @classmethod
    def resolve(cls, conn, admin: bool, operator: bool, scopes: list[str]) -> "Access":
        a = cls(admin, operator)
        if admin or not scopes:
            return a
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT BusinessUnitId AS Id, Name FROM cz.BusinessUnit")
        bus = cur.fetchall()
        cur.execute("SELECT ProductId AS Id, Name, BusinessUnitId FROM cz.Product")
        products = cur.fetchall()

        def match(rows, value):
            if value.startswith("#"):
                return {r["Id"] for r in rows if r["Id"] == int(value[1:])}
            return {r["Id"] for r in rows if str(r["Name"]).casefold() == value.casefold()}
        for sc in scopes:
            kind, _, value = sc.partition(":")
            if kind == "bu":
                a.bus |= match(bus, value)
            else:
                a.products |= match(products, value)
        a.products |= {p["Id"] for p in products if p["BusinessUnitId"] in a.bus}
        return a

    # -- applications ---------------------------------------------------------------------------

    def can_edit_app(self, product_id) -> bool:
        """Display name, owner, description, hidden: the application's product must be in scope."""
        return self.admin or (product_id is not None and product_id in self.products)

    def can_map(self, old_product, new_product) -> bool:
        """Move an application from old_product to new_product (None: not mapped). Product owners
        may pick up unmapped applications, and move or unmap their own, within their scope."""
        if self.admin:
            return True
        return (old_product is None or old_product in self.products) and \
               (new_product is None or new_product in self.products) and self.owner

    # -- products and business units ------------------------------------------------------------

    def can_edit_product(self, product_id) -> bool:
        return self.admin or product_id in self.products

    def can_set_bu(self, old_bu, new_bu) -> bool:
        """A product's business unit: only between business units in scope (or unchanged)."""
        return self.admin or old_bu == new_bu or (new_bu in self.bus and (old_bu is None or old_bu in self.bus))

    def can_create_product(self, bu) -> bool:
        return self.admin or (bu is not None and bu in self.bus)

    def can_delete_product(self, bu) -> bool:
        return self.admin or (bu is not None and bu in self.bus)

    def can_edit_bu(self) -> bool:
        return self.admin
