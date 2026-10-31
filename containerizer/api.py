"""JSON API for the mapping: business units, products, applications, and the change history.

    GET    /api/v1/business-units            POST   /api/v1/business-units
    GET    /api/v1/business-units/{id}       PATCH  /api/v1/business-units/{id}     DELETE ...
    GET    /api/v1/products[?businessUnitId=] POST  /api/v1/products
    GET    /api/v1/products/{id}             PATCH  /api/v1/products/{id}           DELETE ...
    GET    /api/v1/applications[?unmapped=true&productId=&name=]
    GET    /api/v1/applications/{id}         PATCH  /api/v1/applications/{id}
    GET    /api/v1/audit[?table=&rowId=&limit=]

Callers send `Authorization: Bearer <access token>` issued by the same OpenID provider as the admin
sign-in for this API's audience (CONTAINERIZER_API_AUDIENCE); the token's signature, issuer, audience
and expiry are checked, and only callers on CONTAINERIZER_API_CLIENTS get in. Changes go through the
admin database login with the caller in SESSION_CONTEXT, so the audit log shows them as "API" with the
client or user that made them. No cookies are read, so there is no CSRF surface.
"""
from __future__ import annotations

import json
import re
import sys

from .admin import LIMITS, URL_RE, Response
from .oidc import OidcError, Provider, allowed_client

MAX_BODY = 64 * 1024
FIELDS = {
    "BusinessUnit": {"name": "Name", "owner": "Owner", "description": "Description"},
    "Product": {"name": "Name", "owner": "Owner", "description": "Description", "infoUrl": "InfoUrl",
                "businessUnitId": "BusinessUnitId"},
    "Application": {"displayName": "DisplayName", "owner": "Owner", "description": "Description",
                    "productId": "ProductId", "retired": "Retired"},
}
KEYS = {"BusinessUnit": "BusinessUnitId", "Product": "ProductId", "Application": "ApplicationId"}
PATHS = {"business-units": "BusinessUnit", "products": "Product", "applications": "Application"}


class ApiError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


def _json(status: int, obj) -> Response:
    return Response(status, json.dumps(obj, default=_default, ensure_ascii=False), ctype="application/json; charset=utf-8")


def _default(o):
    if hasattr(o, "isoformat"):
        return o.isoformat() + ("Z" if getattr(o, "tzinfo", None) is None else "")
    return float(o) if o.__class__.__name__ == "Decimal" else str(o)


def _camel(row: dict) -> dict:
    return {k[:1].lower() + k[1:]: v for k, v in row.items()}


class Api:
    def __init__(self, provider: Provider, audience: str, clients: list[str], connect_admin):
        self.provider, self.audience, self.clients, self.connect_admin = provider, audience, clients, connect_admin

    @staticmethod
    def handles(path: str) -> bool:
        return path == "/api/v1" or path.startswith("/api/v1/")

    def handle(self, method: str, path: str, query: dict, headers, body: bytes) -> Response:
        try:
            claims = self._authenticate(headers)
            data = None
            if method in ("POST", "PATCH", "PUT"):
                if not (headers.get("Content-Type") or "").split(";")[0].strip().lower() == "application/json":
                    raise ApiError(415, "unsupported_media_type", "send the body as application/json")
                if len(body) > MAX_BODY:
                    raise ApiError(413, "too_large", "request body is larger than 64 KiB")
                try:
                    data = json.loads(body or b"{}")
                except ValueError:
                    raise ApiError(400, "invalid_json", "the body is not valid JSON") from None
                if not isinstance(data, dict):
                    raise ApiError(400, "invalid_json", "the body must be a JSON object")
            conn = self.connect_admin()
            try:
                user = str(claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "")
                client = str(claims.get("azp") or claims.get("appid") or claims.get("client_id") or claims["sub"])
                who = user or f"client:{client}"
                conn.set_user(who, str(claims.get("name") or claims.get("app_displayname") or who), via="API")
                return self.route(conn, method, path, query, data)
            finally:
                conn.close()
        except ApiError as e:
            r = _json(e.status, {"error": e.error, "message": e.message})
            if e.status == 401:
                r.headers.append(("WWW-Authenticate", f'Bearer error="{e.error}"'))
            return r

    def _authenticate(self, headers) -> dict:
        auth = headers.get("Authorization") or ""
        if not auth.lower().startswith("bearer ") or not auth[7:].strip():
            raise ApiError(401, "invalid_request", "send Authorization: Bearer <access token>")
        try:
            claims = self.provider.validate_access(auth[7:].strip(), self.audience)
        except OidcError as e:
            print(f"api: {e}", file=sys.stderr)
            raise ApiError(401, "invalid_token", "the access token is not valid for this API") from None
        if not allowed_client(claims, self.clients):
            raise ApiError(403, "insufficient_scope", "this client is not allowed to use the API")
        return claims

    # -- routing --------------------------------------------------------------------------------

    def route(self, conn, method: str, path: str, q: dict, data: dict | None) -> Response:
        parts = path.strip("/").split("/")[2:]
        if parts == ["audit"] and method == "GET":
            return _json(200, self.audit(conn, q))
        if not parts or parts[0] not in PATHS or len(parts) > 2:
            raise ApiError(404, "not_found", "no such resource")
        table = PATHS[parts[0]]
        if len(parts) == 1:
            if method == "GET":
                return _json(200, self.list(conn, table, q))
            if method == "POST" and table != "Application":
                return _json(201, self.create(conn, table, data))
            raise ApiError(405, "method_not_allowed", "applications are created by scans")
        if not re.fullmatch(r"\d{1,9}", parts[1]):
            raise ApiError(404, "not_found", "ids are numbers")
        ident = int(parts[1])
        if method == "GET":
            return _json(200, self.get(conn, table, ident))
        if method in ("PATCH", "PUT"):
            return _json(200, self.update(conn, table, ident, data, replace=method == "PUT"))
        if method == "DELETE" and table != "Application":
            self.delete(conn, table, ident)
            return Response(204, "", ctype="application/json; charset=utf-8")
        raise ApiError(405, "method_not_allowed", "use GET, PATCH" + ("" if table == "Application" else ", PUT or DELETE"))

    # -- reads ----------------------------------------------------------------------------------

    SELECT = {
        "BusinessUnit": "SELECT b.BusinessUnitId AS Id, b.Name, b.Owner, b.Description, b.CreatedAt FROM cz.BusinessUnit b",
        "Product": "SELECT p.ProductId AS Id, p.Name, p.Owner, p.Description, p.InfoUrl, p.BusinessUnitId, "
                   "b.Name AS BusinessUnitName, p.CreatedAt FROM cz.Product p "
                   "LEFT JOIN cz.BusinessUnit b ON b.BusinessUnitId = p.BusinessUnitId",
        "Application": "SELECT a.ApplicationId AS Id, a.Name, a.DisplayName, a.Owner, a.Description, a.ProductId, "
                       "p.Name AS ProductName, a.Retired, a.RepositoryUrl, a.SourcePath, a.FirstSeenAt, a.LastSeenAt, "
                       "x.Rating, x.Score, x.EffortDays, x.AssessedAt FROM cz.Application a "
                       "LEFT JOIN cz.Product p ON p.ProductId = a.ProductId "
                       "OUTER APPLY (SELECT TOP (1) aa.Rating, aa.Score, aa.EffortDays, aa.AssessedAt "
                       "FROM cz.ApplicationAssessment aa WHERE aa.ApplicationId = a.ApplicationId "
                       "ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x",
    }
    ALIAS = {"BusinessUnit": "b", "Product": "p", "Application": "a"}

    def list(self, conn, table: str, q: dict) -> dict:
        where, params = [], []
        al = self.ALIAS[table]
        name = q.get("name", [None])[0]
        if name:
            where.append(f"{al}.Name = %s")
            params.append(name[:200])
        if table == "Product" and q.get("businessUnitId"):
            where.append("p.BusinessUnitId = %s")
            params.append(_int(q["businessUnitId"][0], "businessUnitId"))
        if table == "Application":
            if q.get("unmapped", [""])[0].lower() == "true":
                where.append("a.ProductId IS NULL")
            if q.get("productId"):
                where.append("a.ProductId = %s")
                params.append(_int(q["productId"][0], "productId"))
            if q.get("retired", ["false"])[0].lower() != "true":
                where.append("a.Retired = 0")
        sql = self.SELECT[table] + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY {al}.Name"
        cur = conn.cursor(as_dict=True)
        cur.execute(sql, tuple(params) or None)
        return {"items": [_camel(r) for r in cur.fetchall()]}

    def get(self, conn, table: str, ident: int) -> dict:
        cur = conn.cursor(as_dict=True)
        cur.execute(self.SELECT[table] + f" WHERE {self.ALIAS[table]}.{KEYS[table]} = %s", (ident,))
        r = cur.fetchone()
        if not r:
            raise ApiError(404, "not_found", f"no {table} with id {ident}")
        return _camel(r)

    def audit(self, conn, q: dict) -> dict:
        where, params = [], []
        table = q.get("table", [None])[0]
        if table:
            if table not in KEYS:
                raise ApiError(400, "invalid_parameter", "table is BusinessUnit, Product or Application")
            where.append("TableName = %s")
            params.append(table)
        if q.get("rowId"):
            where.append("RowId = %s")
            params.append(_int(q["rowId"][0], "rowId"))
        limit = min(_int(q.get("limit", ["100"])[0], "limit"), 1000)
        cur = conn.cursor(as_dict=True)
        cur.execute(f"SELECT TOP ({limit}) AuditId, ChangedAt, ChangedBy, ChangedByName, DbLogin, Via, TableName, RowId, "
                    f"RowName, Action, OldValues, NewValues FROM cz.AuditLog {('WHERE ' + ' AND '.join(where)) if where else ''} "
                    f"ORDER BY ChangedAt DESC, AuditId DESC", tuple(params) or None)
        rows = []
        for r in cur.fetchall():
            r = _camel(r)
            for k in ("oldValues", "newValues"):
                r[k] = json.loads(r[k]) if r[k] else None
            rows.append(r)
        return {"items": rows}

    # -- writes ---------------------------------------------------------------------------------

    def _values(self, table: str, data: dict, replace: bool) -> dict:
        fields = FIELDS[table]
        unknown = sorted(set(data) - set(fields))
        if unknown:
            raise ApiError(400, "invalid_field", f"unknown or read-only field(s): {', '.join(unknown)}")
        out = {}
        for k, col in fields.items():
            if k not in data:
                if replace and col != "Retired":
                    out[col] = None
                continue
            v = data[k]
            if col in ("ProductId", "BusinessUnitId"):
                if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 1):
                    raise ApiError(400, "invalid_field", f"{k} must be an id or null")
            elif col == "Retired":
                if not isinstance(v, bool):
                    raise ApiError(400, "invalid_field", "retired must be true or false")
            else:
                if v is not None and not isinstance(v, str):
                    raise ApiError(400, "invalid_field", f"{k} must be a string or null")
                v = " ".join(v.split()) if v else None
                if v and len(v) > LIMITS[col]:
                    raise ApiError(400, "invalid_field", f"{k} is longer than {LIMITS[col]} characters")
                if col == "InfoUrl" and v and not URL_RE.fullmatch(v):
                    raise ApiError(400, "invalid_field", "infoUrl must be a plain https:// address")
            out[col] = v
        if "Name" in out and not out["Name"] or (replace and table != "Application" and not out.get("Name")):
            raise ApiError(400, "invalid_field", "name is required")
        return out

    def _write(self, conn, sql: str, params: tuple):
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
            res = cur.fetchone() if "SCOPE_IDENTITY" in sql else cur.rowcount
            conn.commit()
            return res
        except Exception as ex:
            conn.rollback()
            code = ex.args[0] if ex.args and isinstance(ex.args[0], int) else None
            if code in (2601, 2627):
                raise ApiError(409, "conflict", "the name is already used") from None
            if code == 547:
                raise ApiError(409, "conflict", "a referenced row does not exist, or the row is still in use") from None
            raise

    def create(self, conn, table: str, data: dict) -> dict:
        vals = self._values(table, data, replace=True)
        cols = list(vals)
        ident = self._write(conn, f"INSERT cz.{table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}); "
                                  "SELECT CAST(SCOPE_IDENTITY() AS int)", tuple(vals.values()))[0]
        return self.get(conn, table, ident)

    def update(self, conn, table: str, ident: int, data: dict, replace: bool = False) -> dict:
        if table == "Application" and replace:
            raise ApiError(405, "method_not_allowed", "use PATCH for applications")
        vals = self._values(table, data, replace)
        if not vals:
            return self.get(conn, table, ident)
        n = self._write(conn, f"UPDATE cz.{table} SET " + ", ".join(f"{c} = %s" for c in vals) + f" WHERE {KEYS[table]} = %s",
                        (*vals.values(), ident))
        if not n:
            raise ApiError(404, "not_found", f"no {table} with id {ident}")
        return self.get(conn, table, ident)

    def delete(self, conn, table: str, ident: int) -> None:
        if not self._write(conn, f"DELETE cz.{table} WHERE {KEYS[table]} = %s", (ident,)):
            raise ApiError(404, "not_found", f"no {table} with id {ident}")


def _int(v: str, name: str) -> int:
    if not re.fullmatch(r"\d{1,9}", v or ""):
        raise ApiError(400, "invalid_parameter", f"{name} must be a number")
    return int(v)


def build(env, provider: Provider, connect_admin) -> Api | None:
    """The API when CONTAINERIZER_API_AUDIENCE is set (needs the sign-in settings too)."""
    from .oidc import check_rules
    audience = env.get("CONTAINERIZER_API_AUDIENCE")
    if not audience:
        return None
    clients = [r.strip() for r in (env.get("CONTAINERIZER_API_CLIENTS") or "").split(",") if r.strip()]
    check_rules(clients, ("client", "email", "domain", "group", "role", "sub"), "CONTAINERIZER_API_CLIENTS")
    return Api(provider, audience, clients, connect_admin)
