"""SBOM routes of the JSON API (read-only; same bearer-token authentication as the rest of /api/v1).

    GET /api/v1/applications/{id}/components/{cid}/sbom[?format=cyclonedx]
        the latest SBOM of a component: metadata and packages (licence, policy status, CVEs),
        or the CycloneDX document itself
    GET /api/v1/sbom/packages[?businessUnitId=&productId=&applicationId=&licenseStatus=&vulnerable=true&name=&limit=]
        packages across the portfolio (latest SBOM per component), one row per component and package
    GET /api/v1/sbom/summary[?businessUnitId=&productId=]
        the numbers of the portfolio page: package and licence counts, top licences, per application

businessUnitId and productId take an id or `none` (not assigned).
"""
from __future__ import annotations

import json
import re

from .admin import Response

PKG_COLS = ("ApplicationId, ApplicationName, ProductId, ProductName, BusinessUnitId, BusinessUnitName, ComponentId, "
            "ComponentName, Kind, Name, Version, Type, Purl, License, LicenseSource, LicenseStatus, Scope, PolicyApplies, "
            "Accepted, FoundBy, Critical, High, Medium, Low, Vulns")


def handles(parts: list[str]) -> bool:
    return (bool(parts) and parts[0] == "sbom") or (
        len(parts) == 5 and parts[0] == "applications" and parts[2] == "components" and parts[4] == "sbom")


def route(api, conn, method: str, parts: list[str], q: dict) -> Response:
    from .api import ApiError, _json
    if method != "GET":
        raise ApiError(405, "method_not_allowed", "SBOMs are read-only: use GET")
    if parts[0] == "applications":
        if not (re.fullmatch(r"\d{1,9}", parts[1]) and re.fullmatch(r"\d{1,9}", parts[3])):
            raise ApiError(404, "not_found", "ids are numbers")
        return component(conn, int(parts[1]), int(parts[3]), q)
    if parts == ["sbom", "packages"]:
        return _json(200, packages(conn, q))
    if parts == ["sbom", "summary"]:
        return _json(200, summary(conn, q))
    raise ApiError(404, "not_found", "no such resource")


def _id_or_none(q: dict, name: str) -> str | None:
    from .api import ApiError
    v = q.get(name, [None])[0]
    if v is None or v == "":
        return None
    if not re.fullmatch(r"\d{1,9}|none", v):
        raise ApiError(400, "invalid_parameter", f"{name} must be a number or none")
    return v


def _camel(row: dict) -> dict:
    out = {k[:1].lower() + k[1:]: v for k, v in row.items()}
    if "vulns" in out:
        out["vulns"] = json.loads(out["vulns"]) if out["vulns"] else []
    if "policyApplies" in out:
        out["policyApplies"] = bool(out["policyApplies"])
    return out


def component(conn, app_id: int, comp_id: int, q: dict) -> Response:
    from .api import ApiError, _json
    from .sbomui import load_component, load_document
    fmt = q.get("format", ["json"])[0]
    if fmt == "cyclonedx":
        doc = load_document(conn, app_id, comp_id)
        if doc is None:
            raise ApiError(404, "not_found", "no SBOM for this component")
        return Response(200, doc, ctype="application/vnd.cyclonedx+json")
    if fmt != "json":
        raise ApiError(400, "invalid_parameter", "format is json or cyclonedx")
    c = load_component(conn, app_id, comp_id)
    if c is None or not c.get("sbom"):
        raise ApiError(404, "not_found", "no SBOM for this component")
    sb = c["sbom"]
    return _json(200, {"applicationId": app_id, "applicationName": c["ApplicationName"], "componentId": comp_id,
                       "componentName": c["ComponentName"], "projectPath": c["ProjectPath"],
                       "sbom": _camel({k: v for k, v in sb.items() if k != "SbomId"}),
                       "packages": [_camel(p) for p in c["packages"]]})


def packages(conn, q: dict) -> dict:
    from .api import ApiError, _int
    where, params = [], []
    for col, name in (("BusinessUnitId", "businessUnitId"), ("ProductId", "productId")):
        v = _id_or_none(q, name)
        if v == "none":
            where.append(f"{col} IS NULL")
        elif v is not None:
            where.append(f"{col} = %s")
            params.append(int(v))
    if q.get("applicationId"):
        where.append("ApplicationId = %s")
        params.append(_int(q["applicationId"][0], "applicationId"))
    st = q.get("licenseStatus", [None])[0]
    if st:
        sts = st.split(",")
        if not all(s in ("allowed", "warn", "denied", "unknown") for s in sts):
            raise ApiError(400, "invalid_parameter", "licenseStatus is allowed, warn, denied or unknown (comma-separated)")
        where.append("PolicyApplies = 1 AND LicenseStatus IN (" + ", ".join(["%s"] * len(sts)) + ")")
        params += sts
    if q.get("vulnerable", [""])[0].lower() == "true":
        where.append("Critical + High + Medium + Low > 0")
    name = q.get("name", [None])[0]
    if name:
        where.append("Name = %s")
        params.append(name[:400])
    limit = min(_int(q.get("limit", ["1000"])[0], "limit"), 10000)
    cur = conn.cursor(as_dict=True)
    cur.execute(f"SELECT TOP ({limit}) {PKG_COLS} FROM cz.vSbomPackageLatest"
                + (" WHERE " + " AND ".join(where) if where else "")
                + " ORDER BY ApplicationName, ComponentName, PackageNo", tuple(params) or None)
    return {"items": [_camel(r) for r in cur.fetchall()]}


def summary(conn, q: dict) -> dict:
    from .api import ApiError
    from .sbomui import load_portfolio
    bu, product = _id_or_none(q, "businessUnitId"), _id_or_none(q, "productId")
    d = load_portfolio(conn, bu, product)
    if not d.get("available"):
        raise ApiError(503, "unavailable", "the SBOM tables do not exist yet: run containerizer db init")
    pk = d["packages"]
    return {"components": d["components"],
            "packages": {"distinct": int(pk["Packages"] or 0), "vulnerable": int(pk["Vulnerable"] or 0)},
            "vulnerabilities": {"critical": int(pk["Critical"] or 0), "high": int(pk["High"] or 0)},
            "licenses": {s: d["status"].get(s, 0) for s in ("allowed", "warn", "denied", "unknown")},
            "topLicenses": [{"license": r["License"] or None, "status": r["LicenseStatus"], "packages": int(r["N"])}
                            for r in d["licenses"]],
            "applications": [_camel(r) for r in d["per_app"]]}
