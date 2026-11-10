"""Gateway API routes for the generated web components: an HTTPRoute per component that serves HTTP.

The platform owns the Gateway (`gateway.parent` in rules/60-security.yaml, `--gateway`): its HTTPS listener and
certificate (TLS terminates at the Gateway, the pod stays on plain HTTP) and an HTTP listener that only redirects
to HTTPS. Each route attaches to the HTTPS listener only (`sectionName`) at `<component>.<app>.<domain>`
(`--ingress-domain`, else the placeholder domain), and carries what IIS or App Service did for the app, in
standard Gateway API fields, from the findings and web.config (all of it data in `gateway:`):

- raised IIS request timeouts (`host-long-request-timeout`) -> `rules[].timeouts` (the pod's stop grace period
  is raised by generate.workload_lifecycle);
- in-memory session, ARR affinity, SignalR, Blazor Server -> a cookie `sessionPersistence` on the rule;
- simple `<rewrite>` rules and `<httpRedirect>` -> `RequestRedirect` / `URLRewrite` filters; HTTP -> HTTPS rules
  are what the Gateway's HTTP listener does already; `<httpProtocol><customHeaders>` and HSTS ->
  `ResponseHeaderModifier`.

Gateway API has no standard field for request body limits or client IP allow lists: those become settings of
the Gateway implementation (`Route.gateway_settings`), and rules that do not translate are listed with their XML
(`Route.untranslated`); both go to MIGRATION.md and HARDENING.md. The `web-config-rewrite` finding is marked
`resolved_by` only when everything in the component's IIS configuration translated (`resolve`).
"""
from __future__ import annotations

import copy
import hashlib
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ROUTE_API = "gateway.networking.k8s.io/v1"
GATEWAY_ENV = "CONTAINERIZER_GATEWAY"                 # <namespace>/<name> of the platform's Gateway (--gateway)
LISTENER_ENV = "CONTAINERIZER_GATEWAY_LISTENER"       # its HTTPS listener (--gateway-listener)
RESOLVED_BY = "gateway-httproute"
REWRITE_FINDING = "web-config-rewrite"
LABEL_MAX = 63
NAME_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
HEADER_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,256}")
STATUS = {"permanent": 301, "found": 302}             # the standard channel's redirect codes


def settings() -> dict:
    from .harden import security
    return security().get("gateway") or {}


def parent() -> dict:
    """The Gateway the routes attach to: {namespace, name, section}."""
    p = dict(settings().get("parent") or {})
    env = (os.environ.get(GATEWAY_ENV) or "").strip()
    if env:
        ns, _, name = env.partition("/")
        if not name:
            ns, name = p.get("namespace") or "", ns
        p.update(namespace=ns.strip(), name=name.strip())
    if (os.environ.get(LISTENER_ENV) or "").strip():
        p["section"] = os.environ[LISTENER_ENV].strip()
    for k in ("namespace", "name", "section"):
        if not NAME_RE.fullmatch(str(p.get(k) or "")):
            raise ValueError(f"gateway {k} {p.get(k)!r} is not a Kubernetes name (--gateway <namespace>/<name>, "
                             "--gateway-listener <listener>)")
    return {k: p[k] for k in ("namespace", "name", "section")}


def proxy_namespace() -> str:
    """The namespace the Gateway's proxy pods call the app from (the NetworkPolicy lets it in)."""
    try:
        return str(settings().get("proxy_namespace") or "") or parent()["namespace"]
    except ValueError:
        return ""


def _label(s: str, key: str) -> str:
    if len(s) <= LABEL_MAX:
        return s
    return s[:LABEL_MAX - 9].rstrip("-") + "-" + hashlib.sha256(key.encode()).hexdigest()[:8]


def host(domain: str, app: str, component: str) -> str:
    """`<component>.<app>.<domain>` (`gateway.host`; `gateway.host_app` when the component has the app's name)."""
    g = settings()
    domain = domain or g.get("placeholder_domain") or "example.invalid"
    tpl = g.get("host_app" if component == app else "host") or "{component}.{app}.{domain}"
    h = tpl.format(component="\0c", app="\0a", domain="\0d")
    labels = []
    for part in h.split("."):
        part = part.replace("\0c", component).replace("\0a", app)
        labels.append(part if part == "\0d" else _label(part, f"{app}/{component}/{part}"))
    return ".".join(labels).replace("\0d", domain)


# --------------------------------------------------------------------------- IIS configuration

@dataclass
class Route:
    """What a component's IIS configuration (web.config) becomes at the Gateway."""
    rules: list[dict] = field(default_factory=list)            # HTTPRoute rules before the app's own rule
    host_redirects: list[tuple[str, dict]] = field(default_factory=list)   # (old host, redirect filter)
    headers_set: dict[str, str] = field(default_factory=dict)
    headers_remove: list[str] = field(default_factory=list)
    translated: list[str] = field(default_factory=list)        # one line per translated item
    gateway_settings: list[str] = field(default_factory=list)  # set at the Gateway implementation (no standard field)
    untranslated: list[dict] = field(default_factory=list)     # {file, what, why, xml}

    @property
    def complete(self) -> bool:
        return not self.untranslated and not self.gateway_settings


def _xml(el) -> str:
    try:
        return ET.tostring(el, encoding="unicode").strip()[:4000]
    except Exception:  # noqa: BLE001
        return f"<{el.tag} ...>"


_LIT_RX = re.compile(r"(?:[A-Za-z0-9_~\-/]|\\[./\-_~])+")
_CATCH_ALL = {"(.*)", "^(.*)$", "^(.*)", "(.*)$", ".*", "^.*$", "^.*", ".*$"}
_HTTPS_TARGET = re.compile(r"https://\{(HTTP_HOST|SERVER_NAME)\}(/?\{R:[01]\}|\{REQUEST_URI\}|/\{R:1\}|/)?", re.I)
_ABS_TARGET = re.compile(r"(?P<scheme>https?)://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)"
                         r"(?::(?P<port>\d{1,5}))?(?P<path>/[^{}?#]*)?(?P<r1>\{R:1\})?", re.I)
_HOST_COND = re.compile(r"\^?(?P<host>(?:[A-Za-z0-9-]|\\\.)+)\$?")


def _literal(rx: str) -> str | None:
    """The text a regex matches when it is a plain literal (letters, digits, `-_~/`, escaped `.`), else None."""
    if rx == "" or _LIT_RX.fullmatch(rx):
        return rx.replace("\\", "")
    return None


def _https_condition(add) -> bool:
    """A condition that is true only for plain-HTTP requests ({HTTPS} off, X-Forwarded-Proto http, port 80)."""
    inp = (add.get("input") or "").strip().upper()
    pat = (add.get("pattern") or "").strip().strip("^$").lower()
    neg = (add.get("negate") or "").lower() == "true"
    on, off = {"{HTTPS}": ("on", "off"), "{HTTP_X_FORWARDED_PROTO}": ("https", "http"),
               "{SERVER_PORT}": ("443", "80")}.get(inp, (None, None))
    return on is not None and ((pat == off and not neg) or (pat == on and neg))


def _status(kind: str, default: str = "Permanent") -> int | None:
    return STATUS.get((kind or default).strip().lower())


def _prefix(p: str) -> str:
    p = "/" + p.strip("/")
    return p


class _Untranslatable(Exception):
    pass


def _rewrite_rule(el, n: int) -> tuple[str, dict | tuple | None]:
    """One <rule>: ("https", None) | ("rule", HTTPRoute rule) | ("host", (old host, filter)); raises
    _Untranslatable with the reason."""
    if el.find("serverVariables") is not None and len(el.find("serverVariables")):
        raise _Untranslatable("sets server variables")
    if (el.get("patternSyntax") or "ECMAScript").lower() != "ecmascript":
        raise _Untranslatable(f"patternSyntax {el.get('patternSyntax')}")
    m, a = el.find("match"), el.find("action")
    if m is None or a is None:
        raise _Untranslatable("no <match> or <action>")
    url, atype = m.get("url") or "", (a.get("type") or "").strip()
    aurl = (a.get("url") or "").strip()
    if (m.get("negate") or "").lower() == "true":
        raise _Untranslatable("negated match")
    conds = el.find("conditions")
    adds = list(conds.findall("add")) if conds is not None else []
    if conds is not None and conds.get("logicalGrouping", "MatchAll").lower() not in ("matchall", "matchany"):
        raise _Untranslatable("condition grouping")
    if conds is not None and (conds.get("trackAllCaptures") or "").lower() == "true":
        raise _Untranslatable("trackAllCaptures")
    if atype.lower() not in ("redirect", "rewrite"):
        raise _Untranslatable(f"action {atype or '(none)'}")
    # HTTP -> HTTPS: what the Gateway's HTTP listener does for every request
    if atype.lower() == "redirect" and adds and all(_https_condition(x) for x in adds) and url in _CATCH_ALL \
            and _HTTPS_TARGET.fullmatch(aurl):
        return "https", None
    host_cond = None
    if adds:
        if len(adds) == 1 and (adds[0].get("input") or "").strip().upper() == "{HTTP_HOST}" \
                and (adds[0].get("negate") or "").lower() != "true" \
                and (adds[0].get("matchType") or "Pattern").lower() == "pattern" \
                and _HOST_COND.fullmatch(adds[0].get("pattern") or "") \
                and (adds[0].get("pattern") or "").startswith("^") and (adds[0].get("pattern") or "").endswith("$"):
            host_cond = _HOST_COND.fullmatch(adds[0].get("pattern")).group("host").replace("\\", "").lower()
        else:
            inputs = sorted({x.get("input") or "?" for x in adds})
            raise _Untranslatable(f"conditions on {', '.join(inputs)}")
    if "{" in aurl.replace("{R:1}", ""):
        raise _Untranslatable("action URL uses server variables, back-references or rewrite maps")
    status = _status(a.get("redirectType") or "Permanent")
    if atype.lower() == "redirect" and status is None:
        raise _Untranslatable(f"redirectType {a.get('redirectType')} (the standard channel has 301 and 302)")
    if (a.get("appendQueryString") or "true").lower() == "false":
        raise _Untranslatable("appendQueryString false")
    name = f"iis-{n}"
    absolute = _ABS_TARGET.fullmatch(aurl)
    # a redirect to another host: the whole site (url catch-all), keeping the path when the target ends in {R:1}
    if atype.lower() == "redirect" and absolute and url in _CATCH_ALL:
        rd = {"scheme": absolute["scheme"].lower(), "hostname": absolute["host"].lower(), "statusCode": status}
        if absolute["port"]:
            rd["port"] = int(absolute["port"])
        path = absolute["path"] or "/"
        if absolute["r1"]:
            if path != "/":
                rd["path"] = {"type": "ReplacePrefixMatch", "replacePrefixMatch": _prefix(path)}
        else:
            rd["path"] = {"type": "ReplaceFullPath", "replaceFullPath": path}
        f = {"type": "RequestRedirect", "requestRedirect": rd}
        if host_cond:
            return "host", (host_cond, f)
        return "rule", {"name": name, "matches": [{"path": {"type": "PathPrefix", "value": "/"}}], "filters": [f]}
    if host_cond:
        raise _Untranslatable("a condition on {HTTP_HOST} with a rule that is not a whole-site redirect")
    if absolute:
        raise _Untranslatable("a redirect to another host for part of the site")
    target = aurl.lstrip("/") if aurl.startswith("/") or not aurl.startswith(("http:", "https:")) else None
    if target is None:
        raise _Untranslatable("action URL")
    # prefix: ^old/(.*)$ -> new/{R:1}
    pm = re.fullmatch(r"\^(?P<p>.+?)(?:/\(\.\*\)|\(/\.\*\)\?)\$?", url)
    if pm and _literal(pm["p"]) is not None and target.endswith("{R:1}"):
        src = _prefix(_literal(pm["p"]))
        dst = target[:-len("{R:1}")]
        if "{" in dst or not re.fullmatch(r"[A-Za-z0-9_~\-/.]*", dst):
            raise _Untranslatable("action URL")
        dst = _prefix(dst) if dst.strip("/") else "/"
        path = {"type": "ReplacePrefixMatch", "replacePrefixMatch": dst}
        match = [{"path": {"type": "PathPrefix", "value": src}}]
    else:
        em = re.fullmatch(r"\^(?P<p>.*)\$", url)
        lit = _literal(em["p"]) if em else None
        if lit is None or "{" in target or not re.fullmatch(r"[A-Za-z0-9_~\-/.]*", target):
            raise _Untranslatable("the pattern is not a literal path or path prefix")
        path = {"type": "ReplaceFullPath", "replaceFullPath": "/" + target}
        match = [{"path": {"type": "Exact", "value": "/" + lit}}]
    if atype.lower() == "redirect":
        f = {"type": "RequestRedirect", "requestRedirect": {"path": path, "statusCode": status}}
    else:
        f = {"type": "URLRewrite", "urlRewrite": {"path": path}}
    return "rule", {"name": name, "matches": match, "filters": [f]}


def _http_redirect(el, n: int) -> dict:
    dest = (el.get("destination") or "").strip()
    if (el.get("exactDestination") or "").lower() == "true" or (el.get("childOnly") or "").lower() == "true":
        raise _Untranslatable("exactDestination/childOnly")
    if "$" in dest:
        raise _Untranslatable("wildcard destination ($S, $Q, $V)")
    status = _status(el.get("httpResponseStatus") or "Found", "Found")
    if status is None:
        raise _Untranslatable(f"httpResponseStatus {el.get('httpResponseStatus')} (the standard channel has 301 and 302)")
    rd: dict = {"statusCode": status}
    m = _ABS_TARGET.fullmatch(dest)
    if m:
        rd.update(scheme=m["scheme"].lower(), hostname=m["host"].lower())
        if m["port"]:
            rd["port"] = int(m["port"])
        path = m["path"] or "/"
    elif re.fullmatch(r"/[A-Za-z0-9_~\-/.]*", dest):
        path = dest
    else:
        raise _Untranslatable("destination")
    if path.strip("/"):
        rd["path"] = {"type": "ReplacePrefixMatch", "replacePrefixMatch": _prefix(path)}
    return {"name": f"iis-{n}", "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
            "filters": [{"type": "RequestRedirect", "requestRedirect": rd}]}


def _scoped(el, parents) -> str:
    """The <location path> an element is under ("" for the site)."""
    p = parents.get(el)
    while p is not None:
        if p.tag == "location" and (p.get("path") or "").strip() not in ("", "."):
            return p.get("path").strip()
        p = parents.get(p)
    return ""


def _cidr(add) -> str:
    """An <ipSecurity><add> entry as a CIDR (ipAddress + subnetMask), or its domain name."""
    import ipaddress
    addr, mask = (add.get("ipAddress") or "").strip(), (add.get("subnetMask") or "").strip()
    if not addr:
        return add.get("domainName") or "?"
    try:
        return str(ipaddress.ip_network(f"{addr}/{mask}" if mask else addr, strict=False))
    except ValueError:
        return f"{addr}/{mask}" if mask else addr


def _bytes(n: int) -> str:
    return f"{n:,} bytes ({n / 2**20:.0f} MiB)" if n >= 2**20 else f"{n:,} bytes"


def parse_config(files: list[tuple[str, str]], max_rules: int = 15) -> Route:
    """Translate the IIS modules configured in these web.config files ((rel path, text) pairs)."""
    r = Route()
    n = 0

    def skip(rel, what, why, el):
        r.untranslated.append({"file": rel, "what": what, "why": why, "xml": _xml(el) if el is not None else ""})

    for rel, text in files:
        if "<!ENTITY" in text or "<!DOCTYPE" in text:
            skip(rel, "web.config", "has a DOCTYPE; not read", None)
            continue
        try:
            root = ET.fromstring(text.lstrip("﻿"))
        except ET.ParseError as ex:
            skip(rel, "web.config", f"not well-formed XML ({ex})", None)
            continue
        parents = {ch: p for p in root.iter() for ch in p}
        for rw in root.iter("rewrite"):
            if _scoped(rw, parents):
                skip(rel, "<rewrite>", f"scoped to <location path=\"{_scoped(rw, parents)}\">", rw)
                continue
            for sect in list(rw):
                if sect.tag not in ("rules", "globalRules"):
                    if sect.tag == "rewriteMaps" and not len(sect):
                        continue
                    skip(rel, f"<{sect.tag}>", "outbound rules, rewrite maps and providers have no Gateway API "
                         "equivalent", sect)
                    continue
                for rule in sect.findall("rule"):
                    rname = rule.get("name") or "?"
                    if (rule.get("enabled") or "true").lower() == "false":
                        continue
                    try:
                        if n >= max_rules:
                            raise _Untranslatable(f"more than {max_rules} rules")
                        kind, val = _rewrite_rule(rule, n + 1)
                    except _Untranslatable as ex:
                        skip(rel, f"rewrite rule \"{rname}\"", str(ex), rule)
                        continue
                    if kind == "https":
                        r.translated.append(f"rewrite rule \"{rname}\" (HTTP to HTTPS): the Gateway's HTTP listener "
                                            "redirects every request to HTTPS")
                        continue
                    n += 1
                    if kind == "host":
                        r.host_redirects.append(val)
                        r.translated.append(f"rewrite rule \"{rname}\": host {val[0]} redirects (its own HTTPRoute; "
                                            "the Gateway needs a listener and certificate for that host)")
                    else:
                        r.rules.append(val)
                        r.translated.append(f"rewrite rule \"{rname}\": {val['filters'][0]['type']} on "
                                            f"{val['matches'][0]['path']['type']} {val['matches'][0]['path']['value']}")
        for hr in root.iter("httpRedirect"):
            if (hr.get("enabled") or "false").lower() != "true":
                continue
            if _scoped(hr, parents):
                skip(rel, "<httpRedirect>", f"scoped to <location path=\"{_scoped(hr, parents)}\">", hr)
                continue
            try:
                r.rules.append(_http_redirect(hr, n + 1))
                n += 1
                r.translated.append(f"<httpRedirect> to {hr.get('destination')}: RequestRedirect")
            except _Untranslatable as ex:
                skip(rel, "<httpRedirect>", str(ex), hr)
        for ip in root.iter("ipSecurity"):
            allowed = [_cidr(x) for x in ip.findall("add") if (x.get("allowed") or "false").lower() == "true"]
            denied = [_cidr(x) for x in ip.findall("add") if (x.get("allowed") or "false").lower() != "true"]
            where = f" for {_scoped(ip, parents)}" if _scoped(ip, parents) else ""
            if (ip.get("allowUnlisted") or "true").lower() == "false":
                r.gateway_settings.append(f"client IP allow list{where}: only {', '.join(allowed) or 'none'} "
                                          f"(`<ipSecurity allowUnlisted=\"false\">` in {rel})")
            if denied:
                r.gateway_settings.append(f"client IP deny list{where}: {', '.join(denied)} (`<ipSecurity>` in {rel})")
            if ip.get("enableReverseDns") or ip.find("dynamicIpSecurity") is not None:
                skip(rel, "<ipSecurity>", "reverse DNS / dynamic IP restrictions", ip)
        for rf in root.iter("requestFiltering"):
            where = f" for {_scoped(rf, parents)}" if _scoped(rf, parents) else ""
            for ch in rf:
                if ch.tag == "requestLimits":
                    for attr, what in (("maxAllowedContentLength", "request body"), ("maxUrl", "URL length"),
                                       ("maxQueryString", "query string length")):
                        if (ch.get(attr) or "").isdigit():
                            v = int(ch.get(attr))
                            r.gateway_settings.append(f"{what} limit{where}: "
                                                      f"{_bytes(v) if attr == 'maxAllowedContentLength' else v} "
                                                      f"(`<requestLimits {attr}>` in {rel})")
                    if len(ch):
                        skip(rel, "<requestLimits> header limits", "no Gateway API field", ch)
                else:
                    skip(rel, f"<requestFiltering><{ch.tag}>", "no Gateway API field (request filtering is the "
                         "Gateway implementation's, or a WAF's)", ch)
        for hp in root.iter("httpProtocol"):
            if _scoped(hp, parents):
                skip(rel, "<httpProtocol>", f"scoped to <location path=\"{_scoped(hp, parents)}\">", hp)
                continue
            for ch in hp:
                if ch.tag != "customHeaders":
                    skip(rel, f"<httpProtocol><{ch.tag}>", "no Gateway API field", ch)
                    continue
                for h in ch:
                    name = h.get("name") or ""
                    if h.tag == "clear":
                        continue
                    if not HEADER_RE.fullmatch(name):
                        skip(rel, f"custom header {name!r}", "not a header name", h)
                    elif h.tag == "add":
                        r.headers_set[name] = h.get("value") or ""
                        r.translated.append(f"custom header {name}: ResponseHeaderModifier set")
                    elif h.tag == "remove":
                        r.headers_remove.append(name)
                        r.translated.append(f"custom header {name}: ResponseHeaderModifier remove")
        for hr in root.iter("httpRuntime"):
            if (hr.get("maxRequestLength") or "").isdigit():
                r.gateway_settings.append(f"request body limit: {_bytes(int(hr.get('maxRequestLength')) * 1024)} "
                                          f"(`<httpRuntime maxRequestLength>` in {rel})")
    return r


def config_files(repo_root: Path, c) -> list[tuple[str, str]]:
    """(rel path, text) of the component's web.config files: the ones the `web-config-rewrite` finding has
    evidence in, and the web.config next to the project."""
    rels = []
    for f in c.findings:
        if f.rule.id == REWRITE_FINDING and not f.dormant:
            rels += [getattr(e, "file", "") for e in f.evidence]
    try:
        pdir = Path(c.project.path).parent
        for p in sorted(pdir.iterdir()):
            if p.name.lower() == "web.config":
                rels.append(str(p.relative_to(repo_root)))
    except (OSError, ValueError, AttributeError):
        pass
    out, seen = [], set()
    for rel in rels:
        if not rel or rel in seen:
            continue
        seen.add(rel)
        p = Path(repo_root) / rel
        try:
            if p.is_file() and p.stat().st_size < 2_000_000:
                out.append((rel.replace("\\", "/"), p.read_text(errors="replace")))
        except OSError:
            pass
    return out


def serves_http(c) -> bool:
    return c.role in ("web", "spa")


def resolve(repo, c) -> None:
    """Mark `web-config-rewrite` resolved by the HTTPRoute when every rule of the component's IIS configuration
    translated and nothing is left for the Gateway implementation."""
    if not serves_http(c):
        return
    found = [f for f in c.findings if f.rule.id == REWRITE_FINDING and not f.dormant and not f.resolved_by]
    if not found:
        return
    r = parse_config(config_files(repo.root, c), int(settings().get("max_rules") or 15))
    if r.complete and r.translated:
        for f in found:
            f.resolved_by = RESOLVED_BY


# --------------------------------------------------------------------------- the route

def _ids(c) -> set[str]:
    return {f.rule.id for f in c.findings if not f.dormant}


def _duration(s: int) -> str:
    return f"{int(s)}s"


def route_docs(c, app: str, component: str, labels: dict, domain: str, repo_root: Path,
               plan: dict | None = None) -> tuple[list[dict], dict]:
    """The HTTPRoute(s) of one web component and what they do (for MIGRATION.md and HARDENING.md)."""
    from .generate import _timeout_seconds
    g = settings()
    ref = parent()
    hostname = host(domain, app, component)
    ids = _ids(c)
    r = parse_config(config_files(repo_root, c), int(g.get("max_rules") or 15))
    notes: dict = {"host": hostname, "placeholder": not domain, "parent": ref, "translated": list(r.translated),
                   "gateway_settings": list(r.gateway_settings), "untranslated": list(r.untranslated),
                   "fields": [], "routes": [component]}
    timeout = 0
    to = g.get("timeouts") or {}
    found = [f for f in c.findings if f.rule.id == to.get("finding") and not f.dormant]
    if found:
        longest = max((_timeout_seconds(str(e)) or 0 for f in found for e in f.evidence), default=0)
        if longest:
            timeout = min(longest, int(to.get("max_seconds") or 3600))
            notes["fields"].append(f"timeouts.request/backendRequest {timeout}s: IIS let requests run for "
                                   f"{longest} s (web.config)" + (" (capped)" if timeout < longest else ""))
    ll = g.get("long_lived") or {}
    if ids & set(ll.get("findings") or ()) and int(ll.get("seconds") or 0) > timeout:
        timeout = int(ll["seconds"])
        notes["fields"].append(f"timeouts.request/backendRequest {timeout}s: SignalR / Blazor Server keep "
                               "connections open")
    sp = g.get("session_persistence") or {}
    persistence = None
    if ids & set(sp.get("findings") or ()) and sp.get("value"):
        persistence = copy.deepcopy(sp["value"])
        why = ", ".join(sorted(ids & set(sp["findings"])))
        notes["fields"].append(f"sessionPersistence {persistence.get('type', 'Cookie')} "
                               f"{persistence.get('sessionName', '')}: per-user state in memory ({why})")
        notes["session_persistence"] = True
    uploads = any(e.get("id") == "file-uploads" for e in (plan or {}).get("hardening_exceptions") or [])
    if uploads and not any("request body" in s for s in r.gateway_settings):
        b = int(g.get("default_body_bytes") or 30_000_000)
        notes["gateway_settings"].append(f"request body limit: at least {_bytes(b)}, what IIS and Kestrel "
                                         "accept by default (the component takes file uploads, IFormFile)")
    headers = dict(g.get("response_headers") or {})
    headers.update(r.headers_set)
    hmod = {}
    if headers:
        hmod["set"] = [{"name": k, "value": str(v)} for k, v in headers.items()][:16]
    if r.headers_remove:
        hmod["remove"] = [h for h in r.headers_remove if h not in headers][:16]
    if hmod.get("set"):
        notes["fields"].append("ResponseHeaderModifier: " + ", ".join(h["name"] for h in hmod["set"]))
    backend = [{"name": component, "port": 80}]

    def backend_rule(rule: dict) -> dict:
        rule = copy.deepcopy(rule)
        if hmod:
            rule.setdefault("filters", []).append({"type": "ResponseHeaderModifier", "responseHeaderModifier": hmod})
        rule["backendRefs"] = copy.deepcopy(backend)
        if timeout:
            rule["timeouts"] = {"request": _duration(timeout), "backendRequest": _duration(timeout)}
        if persistence:
            rule["sessionPersistence"] = copy.deepcopy(persistence)
        return rule

    rules = []
    for x in r.rules:
        redirect = any(f["type"] == "RequestRedirect" for f in x.get("filters") or [])
        rules.append(copy.deepcopy(x) if redirect else backend_rule(x))
    rules.append(backend_rule({"name": "app", "matches": [{"path": {"type": "PathPrefix", "value": "/"}}]}))
    pref = {"group": "gateway.networking.k8s.io", "kind": "Gateway", "namespace": ref["namespace"],
            "name": ref["name"], "sectionName": ref["section"]}
    docs = [{"apiVersion": ROUTE_API, "kind": "HTTPRoute", "metadata": {"name": component, "labels": dict(labels)},
             "spec": {"parentRefs": [dict(pref)], "hostnames": [hostname], "rules": rules}}]
    for i, (old, f) in enumerate(r.host_redirects, 1):
        name = _label(f"{component}-redirect-{i}", f"{component}/{old}")
        docs.append({"apiVersion": ROUTE_API, "kind": "HTTPRoute", "metadata": {"name": name, "labels": dict(labels)},
                     "spec": {"parentRefs": [dict(pref)], "hostnames": [old],
                              "rules": [{"name": "iis-redirect", "filters": [copy.deepcopy(f)]}]}})
        notes["routes"].append(name)
    return docs, notes


# --------------------------------------------------------------------------- reports

def _gw(ref: dict) -> str:
    return f"`{ref['namespace']}/{ref['name']}` listener `{ref['section']}`"


def migration_markdown(notes: dict[str, dict]) -> str:
    """The MIGRATION.md section: per web component its host, what translated, and what is left."""
    if not notes:
        return ""
    L = ["", "## Gateway API routes", "",
         "Every web component has an HTTPRoute in its `k8s.yaml` (docs/gateway-api.md). The platform owns the "
         "Gateway, its HTTPS listener and certificate: TLS terminates there, its HTTP listener only redirects to "
         "HTTPS, and the pods stay on plain HTTP.", ""]
    for comp, n in sorted(notes.items()):
        L += [f"### {comp}", "", f"- Host `{n['host']}`" + (" (placeholder domain: generate with `--ingress-domain`)"
                                                            if n["placeholder"] else "")
              + f", attached to Gateway {_gw(n['parent'])}"]
        L += [f"- {x}" for x in n["fields"]]
        L += [f"- {x}" for x in n["translated"]]
        if n.get("session_persistence"):
            L.append("- `sessionPersistence` is in Gateway API's experimental channel: with only the standard-channel "
                     "CRDs installed, server-side apply (Flux) rejects the route (`field not declared in schema`). "
                     "Install the experimental CRDs, or set `gateway.session_persistence.value: null` in "
                     "`rules/60-security.yaml` and keep users on one pod with the implementation's own policy")
        if n["gateway_settings"]:
            L += ["", "Set at the Gateway implementation (Gateway API has no standard field for these):", ""]
            L += [f"- {x}" for x in n["gateway_settings"]]
        if n["untranslated"]:
            L += ["", "Not translated: re-create these at the Gateway (or with ASP.NET Core middleware, "
                  "`UseRewriter` reads IIS rules):", ""]
            for u in n["untranslated"]:
                L += [f"- {u['what']} in `{u['file']}`: {u['why']}"]
                if u["xml"]:
                    L += ["", "  ```xml", *["  " + ln for ln in u["xml"].splitlines()], "  ```"]
        L.append("")
    return "\n".join(L) + "\n"


def hardening_markdown(notes: dict[str, dict]) -> str:
    """The HARDENING.md section: TLS at the Gateway, headers, and the settings to make there."""
    if not notes:
        return ""
    L = ["## Gateway API routes", "",
         "TLS terminates at the platform's Gateway; each HTTPRoute attaches to its HTTPS listener only, and the "
         "Gateway's HTTP listener only redirects to HTTPS. The service ports accept connections from the Gateway's "
         "namespace (NetworkPolicy).", "",
         "| Component | Host | Gateway | Route fields | Set at the Gateway implementation |", "| --- | --- | --- | --- | --- |"]
    for comp, n in sorted(notes.items()):
        L.append(f"| {comp} | `{n['host']}` | {_gw(n['parent'])} | {'; '.join(n['fields']) or 'defaults'} | "
                 f"{'; '.join(n['gateway_settings']) or 'nothing'} |")
    return "\n".join(L) + "\n\n"
