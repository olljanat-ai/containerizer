#!/usr/bin/env python3
"""Record what an application's production URL serves, to find the Git repository it is built from.

A first version, to see whether the data is useful: it only collects. Nothing is sent anywhere; the result is one
JSON file. One file, the standard library only (Python 3.9 or later), so it runs on a workstation or a jump host
that reaches production.

    python3 appfingerprint.py apps.csv -o fingerprints.json
    python3 appfingerprint.py https://orders.example.com/ https://hr.example.com/portal/

`apps.csv` has a header line with a `url` column, and optionally `id` and `name` (`,` or `;` between the columns).

What it does for each URL, with GET requests only (no sign-in, no forms, 60 requests at most by default):

- follows the redirects and stops at a sign-in (OpenID Connect, SAML, WS-Federation): the client ID, the redirect
  URI and the SAML issuer are recorded, the identity provider's page is not fetched;
- reads the page: title, meta tags, scripts, style sheets, forms, hidden fields, custom elements, comments;
- reads the page's own scripts (the same host only): webpack's global, API paths, routes, host names, client IDs,
  .NET assembly names, and the source map's list of source files when one is published;
- asks for a few well-known files: Blazor's assembly list, the OpenAPI description, the web manifest, robots.txt,
  Spring's /actuator/info and the favicon (its SHA-256). `--no-probes` leaves these out.

Response headers (Server, X-Powered-By, ...) and cookie names are recorded, never cookie values.

An application behind single sign-on shows little without a session: `--header 'Cookie: ...'` sends a header of
your own to the application's host (not to other hosts). `--insecure` accepts a certificate of an internal CA.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import http.client
import http.cookiejar
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit

VERSION = 1
USER_AGENT = f"containerizer-appfingerprint/{VERSION}"
MAX_BODY = 5 * 1024 * 1024
MAX_MAP = 20 * 1024 * 1024
MAX_HOPS = 8
MAX_SCRIPTS = 12
MAX_BLIND_MAPS = 4            # scripts without a sourceMappingURL comment whose `<script>.map` is tried
CAP = 200                     # values kept per list

HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-application-context",
           "x-frame-options", "www-authenticate", "via", "x-drupal-cache", "x-runtime", "x-version", "x-app-version")
IDP_HOSTS = re.compile(r"(?i)(^|\.)(login\.microsoftonline\.com|login\.windows\.net|b2clogin\.com|okta\.com|"
                       r"oktapreview\.com|auth0\.com|accounts\.google\.com|onelogin\.com|pingidentity\.com)$")
IDP_PATHS = re.compile(r"(?i)/(adfs/|oauth2/|connect/authorize|openid-connect/auth|saml2?/|simplesaml/|idp/|"
                       r"realms/[^/]+/protocol/)")
IDP_PARAMS = ("client_id", "SAMLRequest", "wtrealm", "wa")
FRAMEWORK_ASSEMBLY = re.compile(r"(?i)^(System(\.|$)|Microsoft\.|netstandard|mscorlib|dotnet(\.|$)|icudt|WindowsBase|"
                                r"blazor\.|emcc|libmono|libSystem)")
PUBLIC_HOSTS = {"www.w3.org", "reactjs.org", "react.dev", "angular.io", "angular.dev", "vuejs.org", "github.com",
                "fb.me", "momentjs.com", "jquery.com", "getbootstrap.com", "npms.io", "feross.org", "mths.be",
                "developer.mozilla.org", "stackoverflow.com", "schema.org", "localhost", "example.com"}

RE_GLOBAL = re.compile(r"\b(webpackChunk[A-Za-z0-9_$]+|webpackJsonp[A-Za-z0-9_$]+)")
RE_API = re.compile(r"""["'`](/?(?:api|odata|graphql|rest|services|hubs?|signalr)/[A-Za-z0-9_\-./{}:]{1,120})["'`]""")
RE_ROUTE = re.compile(r"""\bpath:\s*["']([A-Za-z0-9_\-./:*]{1,80})["']""")
RE_HOST = re.compile(r"""https?://([A-Za-z0-9](?:[A-Za-z0-9.-]{0,200}[A-Za-z0-9])?)(?=[/:"'`?#\\\s]|$)""")
RE_CLIENT = re.compile(r"""(?i)\bclient_?id["']?\s*[:=]\s*["']([A-Za-z0-9._:/\-]{6,120})["']""")
RE_ASSEMBLY = re.compile(r"""["'/]([A-Za-z][A-Za-z0-9_.\-]{1,120})\.(?:dll|wasm|pdb)\b""")
RE_MAP = re.compile(r"[#@]\s*sourceMappingURL=(\S+)\s*(?:\*/)?\s*$")
RE_HASH = re.compile(r"[.-]([A-Za-z0-9_]{8,})(?=\.)")


class Budget(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Resp:
    def __init__(self, url, status, headers, body, truncated):
        self.url, self.status, self.headers, self.body, self.truncated = url, status, headers, body, truncated

    @property
    def text(self) -> str:
        cs = self.headers.get_content_charset() if self.headers else None
        try:
            return self.body.decode(cs or "utf-8", "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    @property
    def ctype(self) -> str:
        return (self.headers.get_content_type() if self.headers else "") or ""


class Client:
    """The requests of one application: its own cookie jar, a request budget, no automatic redirects."""

    def __init__(self, a, host: str):
        self.a, self.count, self.errors, self.cookies, self.headers = a, 0, [], set(), {}
        self.own_hosts = {host.lower()}
        handlers = [_NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if a.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def get(self, url: str, limit: int = MAX_BODY) -> Resp | None:
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            return None
        if self.count >= self.a.max_requests:
            raise Budget()
        self.count += 1
        if self.a.delay:
            time.sleep(self.a.delay)
        own = u.hostname.lower() in self.own_hosts
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if own:
            headers.update(self.a.extra_headers)
        try:
            r = self.opener.open(urllib.request.Request(url, headers=headers), timeout=self.a.timeout)
        except urllib.error.HTTPError as ex:
            r = ex
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as ex:
            self.errors.append(f"{url}: {getattr(ex, 'reason', ex)}")
            return None
        try:
            body = r.read(limit + 1)
        except (OSError, http.client.HTTPException):
            body = b""
        finally:
            r.close()
        if own:
            for k in HEADERS:
                if r.headers.get(k):
                    self.headers.setdefault(k, r.headers.get(k)[:200])
            for c in r.headers.get_all("set-cookie") or []:
                name = c.split("=", 1)[0].strip()
                if name:
                    self.cookies.add(name[:100])
        return Resp(url, getattr(r, "code", 0) or 0, r.headers, body[:limit], len(body) > limit)


# ------------------------------------------------------------------ the page

class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.base, self.meta, self.attrs = "", "", {}, {}
        self.scripts, self.styles, self.icons, self.manifests, self.forms = [], [], [], [], []
        self.hidden, self.elements, self.ids, self.comments, self.inline = [], [], [], [], []
        self._in = ""

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("title", "script"):
            self._in = tag if tag == "title" or not a.get("src") else ""
        if tag == "base" and a.get("href"):
            self.base = a["href"]
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name in ("generator", "application-name", "description", "author", "og:site_name", "og:title",
                        "apple-mobile-web-app-title") and a.get("content"):
                self.meta[name] = a["content"][:300]
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel:
                self.styles.append(a["href"])
            elif "icon" in rel:
                self.icons.append(a["href"])
            elif "manifest" in rel:
                self.manifests.append(a["href"])
            elif "modulepreload" in rel or (rel == "preload" and a.get("as") == "script"):
                self.scripts.append(a["href"])
        elif tag == "form":
            self.forms.append({"action": a.get("action", "").split("?")[0][:200], "method": a.get("method", "get").lower(),
                               "id": a.get("id", "")[:100]})
        elif tag == "input" and a.get("type", "").lower() == "hidden" and a.get("name"):
            self.hidden.append(a["name"][:100])
        if "-" in tag:
            self.elements.append(tag[:100])
        if a.get("id") and len(self.ids) < 60:
            self.ids.append(a["id"][:100])
        for k in ("ng-version", "ng-app", "data-reactroot", "data-server-rendered", "data-turbo-track"):
            if k in a:
                self.attrs[k] = a[k][:100]

    def handle_endtag(self, tag):
        if tag in ("title", "script"):
            self._in = ""

    def handle_data(self, data):
        if self._in == "title":
            self.title += data
        elif self._in == "script" and sum(map(len, self.inline)) < 500_000:
            self.inline.append(data)

    def handle_comment(self, data):
        d = " ".join(data.split())
        if len(d) > 3 and not d.startswith("[if") and len(self.comments) < 15:
            self.comments.append(d[:200])


def uniq(items, cap: int = CAP) -> list:
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out[:cap]


def asset_name(ref: str) -> str:
    """A script's or style sheet's file name without its content hash: main.3f2a1b9c.js -> main.js."""
    name = urlsplit(ref).path.rsplit("/", 1)[-1]

    def drop(m):
        s = m.group(1)
        hexish = re.fullmatch(r"[0-9a-f]+", s) and re.search(r"\d", s)
        mixed = re.search(r"[A-Z]", s) and re.search(r"[a-z0-9]", s)
        return "" if hexish or mixed else m.group(0)
    name = RE_HASH.sub(drop, name)
    stem = name.rsplit(".", 1)[0]
    return "" if "." not in name or re.fullmatch(r"[0-9a-f]{8,}|\d+", stem) else name      # only a hash or a number


def ref_of(ref: str, base: str, own_hosts: set) -> str:
    """How an asset is recorded: its path on the application's host, host and path elsewhere. No query."""
    u = urlsplit(urljoin(base, ref))
    if u.scheme not in ("http", "https"):
        return ""
    return u.path if (u.hostname or "").lower() in own_hosts else f"{u.hostname}{u.path}"


# ------------------------------------------------------------------ redirects and sign-in

def is_signin(url: str) -> bool:
    u = urlsplit(url)
    q = parse_qs(u.query)
    return bool(any(p in q for p in IDP_PARAMS) or IDP_HOSTS.search(u.hostname or "") or IDP_PATHS.search(u.path))


def signin(url: str) -> dict:
    u = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    out = {"host": u.hostname, "path": u.path, "clientId": q.get("client_id"),
           "redirectUri": q.get("redirect_uri") or q.get("wreply"), "realm": q.get("wtrealm"),
           "resource": q.get("resource"), "scope": q.get("scope"), "params": sorted(q)}
    if q.get("SAMLRequest"):
        try:
            raw = base64.b64decode(q["SAMLRequest"] + "===")
            try:
                xml = zlib.decompress(raw, -15).decode("utf-8", "replace")
            except zlib.error:
                xml = raw.decode("utf-8", "replace")
            m = re.search(r"<(?:\w+:)?Issuer[^>]*>([^<]+)<", xml)
            out["samlIssuer"] = m.group(1).strip() if m else None
            m = re.search(r'AssertionConsumerServiceURL="([^"]+)"', xml)
            out["samlAcsUrl"] = m.group(1) if m else None
        except (ValueError, TypeError):
            pass
    return out


def landing(c: Client, url: str, out: dict) -> Resp | None:
    """Follow the redirects from `url` to the application's page. A redirect to a sign-in is recorded, not followed."""
    hops = []
    for _ in range(MAX_HOPS):
        r = c.get(url)
        if r is None:
            break
        loc = r.headers.get("location") if 300 <= r.status < 400 else None
        if not loc:
            out["redirects"] = hops
            out["status"] = r.status
            return r
        to = urljoin(url, loc)
        t = urlsplit(to)
        hops.append({"status": r.status, "from": urlsplit(url).path or "/", "toHost": t.hostname, "toPath": t.path,
                     "params": sorted(parse_qs(t.query))})
        if is_signin(to):
            out["signIn"] = signin(to)
            break
        if t.hostname and (t.hostname.lower().endswith("." + urlsplit(url).hostname.lower())
                           or urlsplit(url).hostname.lower().endswith("." + t.hostname.lower())):
            c.own_hosts.add(t.hostname.lower())           # www.example.com <-> example.com
        url = to
    out["redirects"] = hops
    return None


# ------------------------------------------------------------------ scripts and source maps

def scan_script(text: str, into: dict) -> None:
    into["globals"] += RE_GLOBAL.findall(text)
    into["apiPaths"] += RE_API.findall(text)
    into["routes"] += [p for p in RE_ROUTE.findall(text) if p not in ("", "/", "*", "**")]
    into["hosts"] += [h.lower() for h in RE_HOST.findall(text) if "." in h and h.lower() not in PUBLIC_HOSTS]
    into["clientIds"] += RE_CLIENT.findall(text)
    for name in RE_ASSEMBLY.findall(text):
        m = re.search(r"\.([a-z0-9]{8,})$", name)                 # .NET 10 file names carry a fingerprint
        if m and re.search(r"\d", m.group(1)):
            name = name[:m.start()]
        into["frameworkAssemblies" if FRAMEWORK_ASSEMBLY.search(name) else "assemblies"].append(name)


def map_sources(body: bytes) -> dict | None:
    """The `sources` of a source map; a map cut off at the size limit still gives them when they come first."""
    text = body.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError:
        m = re.search(r'"sources"\s*:\s*(\[[^\]]*\])', text)
        if not m:
            return None
        try:
            doc = {"sources": json.loads(m.group(1))}
        except ValueError:
            return None
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), list):
        return None
    own, packages = [], set()
    for s in doc["sources"]:
        if not isinstance(s, str):
            continue
        s = re.sub(r"^(webpack|ng|vite|file)://(/)?", "", s).lstrip("./").replace("/./", "/")
        m = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)", s)
        if m:
            packages.add(m.group(1))
        elif s and not s.startswith("webpack/"):
            own.append(s[:300])
    return {"file": doc.get("file") if isinstance(doc.get("file"), str) else None,
            "sourceRoot": doc.get("sourceRoot") or None, "sources": uniq(own, 400), "sourceCount": len(own),
            "packageCount": len(packages)}


def scripts(c: Client, refs: list, base: str, out: dict) -> None:
    b = {k: [] for k in ("globals", "apiPaths", "routes", "hosts", "clientIds", "assemblies", "frameworkAssemblies")}
    maps, blind = [], 0
    own = [u for u in uniq(urljoin(base, r) for r in refs) if (urlsplit(u).hostname or "").lower() in c.own_hosts]
    for url in own[:MAX_SCRIPTS]:
        r = c.get(url)
        if r is None or r.status != 200 or "html" in r.ctype:
            continue
        text = r.text
        scan_script(text, b)
        m = RE_MAP.search(text[-600:])
        ref = m.group(1) if m else r.headers.get("sourcemap") or r.headers.get("x-sourcemap")
        doc = None
        if ref and ref.startswith("data:"):
            try:
                doc = map_sources(base64.b64decode(ref.split(",", 1)[1] + "==="))
            except (ValueError, IndexError):
                doc = None
            where = urlsplit(url).path + " (inline)"
        else:
            if not ref:
                if blind >= MAX_BLIND_MAPS:
                    continue
                blind += 1
                ref = url.split("?")[0] + ".map"
            mu = urljoin(url, ref)
            where = urlsplit(mu).path
            if (urlsplit(mu).hostname or "").lower() in c.own_hosts:
                mr = c.get(mu, MAX_MAP)
                if mr is not None and mr.status == 200 and "html" not in mr.ctype:
                    doc = map_sources(mr.body)
        if doc:
            maps.append({"url": where, **doc})
    out["bundles"] = {k: uniq(v) for k, v in b.items()}
    out["bundles"]["frameworkAssemblies"] = len(set(b["frameworkAssemblies"])) or None
    out["sourceMaps"] = maps


# ------------------------------------------------------------------ well-known files

def as_json(r: Resp | None):
    if r is None or r.status != 200:
        return None
    try:
        return json.loads(r.text.lstrip("﻿"))
    except ValueError:
        return None


def assembly_keys(doc, found: list) -> None:
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(k, str) and re.search(r"\.(dll|wasm)$", k):
                found.append(re.sub(r"\.(dll|wasm)$", "", k))
            assembly_keys(v, found)
    elif isinstance(doc, list):
        for v in doc:
            assembly_keys(v, found)


def probes(c: Client, bases: list, page: Page | None, page_url: str, out: dict) -> None:
    def first(paths, check):
        for base in bases:
            for p in paths:
                v = check(c.get(urljoin(base, p)), urljoin(base, p))
                if v:
                    return v
        return None

    def blazor(r, url):
        doc = as_json(r)
        if not isinstance(doc, dict) or "resources" not in doc:
            return None
        names = []
        assembly_keys(doc, names)
        own = [n for n in names if not FRAMEWORK_ASSEMBLY.search(n)]
        return {"url": urlsplit(url).path, "entryAssembly": doc.get("entryAssembly") or doc.get("mainAssemblyName"),
                "assemblies": uniq(own), "frameworkAssemblies": len(set(names)) - len(set(own))}

    def openapi(r, url):
        doc = as_json(r)
        if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
            return None
        info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
        tags = [t.get("name") for t in doc.get("tags") or [] if isinstance(t, dict)]
        return {"url": urlsplit(url).path, "title": info.get("title"), "version": info.get("version"),
                "paths": uniq(doc["paths"]), "pathCount": len(doc["paths"]), "tags": uniq(tags, 60)}

    def manifest(r, url):
        doc = as_json(r)
        if not isinstance(doc, dict):
            return None
        if "files" in doc or "entrypoints" in doc:                       # create-react-app's asset-manifest.json
            files = doc.get("files") if isinstance(doc.get("files"), dict) else {}
            return {"url": urlsplit(url).path, "files": uniq(asset_name(k) for k in files)}
        if doc.get("name") or doc.get("short_name"):
            return {"url": urlsplit(url).path, "name": doc.get("name"), "shortName": doc.get("short_name"),
                    "startUrl": doc.get("start_url")}
        return None

    def actuator(r, url):
        doc = as_json(r)
        if not isinstance(doc, dict) or not (isinstance(doc.get("build"), dict) or isinstance(doc.get("git"), dict)
                                             or isinstance(doc.get("app"), dict)):
            return None
        return {"url": urlsplit(url).path, **{k: doc[k] for k in ("build", "git", "app") if isinstance(doc.get(k), dict)}}

    def robots(r, url):
        if r is None or r.status != 200 or "html" in r.ctype or "<html" in r.text[:500].lower():
            return None
        rules = re.findall(r"(?im)^\s*(?:dis)?allow:\s*(\S+)", r.text)
        return {"paths": uniq(rules, 60)} if rules else None

    def icon(r, url):
        if r is None or r.status != 200 or not r.body or "html" in r.ctype or r.body.lstrip()[:1] == b"<" and b"<svg" not in r.body[:300]:
            return None
        return {"url": urlsplit(url).path, "sha256": hashlib.sha256(r.body).hexdigest(), "bytes": len(r.body)}

    out["blazor"] = first(["_framework/blazor.boot.json"], blazor)
    out["openapi"] = first(["swagger/v1/swagger.json", "openapi.json", "v3/api-docs", "swagger/docs/v1"], openapi)
    linked = [urljoin(page_url, m) for m in page.manifests] if page else []
    out["manifest"] = first(linked[:1] + ["asset-manifest.json", "manifest.json"], manifest)
    out["actuator"] = first(["actuator/info"], actuator)
    out["robots"] = first(["robots.txt"], robots)
    icons = [urljoin(page_url, i) for i in page.icons] if page else []
    out["favicon"] = first(icons[:1] + ["favicon.ico"], icon)


# ------------------------------------------------------------------ one application

def prune(v):
    if isinstance(v, dict):
        d = {k: prune(x) for k, x in v.items()}
        return {k: x for k, x in d.items() if x not in (None, "", [], {})}
    if isinstance(v, list):
        return [prune(x) for x in v]
    return v


def collect(app: dict, a) -> dict:
    url = app["url"] if "://" in app["url"] else "https://" + app["url"]
    u = urlsplit(url)
    out = {"id": app.get("id"), "name": app.get("name"), "url": url, "host": u.hostname}
    if u.scheme not in ("http", "https") or not u.hostname:
        return prune({**out, "errors": ["not an http(s) URL"]})
    c = Client(a, u.hostname)
    page, page_url = None, url
    try:
        r = landing(c, url, out)
        if r is not None:
            page_url = r.url
            out["contentType"] = r.ctype
            if "html" in r.ctype or r.body.lstrip()[:1] == b"<":
                page = Page()
                try:
                    page.feed(r.text)
                except Exception as ex:                                  # a page the parser gives up on
                    c.errors.append(f"{r.url}: HTML: {ex}")
                base = urljoin(page_url, page.base) if page.base else page_url
                refs = page.scripts + page.styles
                out["page"] = {
                    "path": urlsplit(page_url).path, "title": " ".join(page.title.split())[:300], "meta": page.meta,
                    "baseHref": page.base, "attributes": page.attrs,
                    "scripts": uniq(ref_of(s, base, c.own_hosts) for s in page.scripts),
                    "styles": uniq(ref_of(s, base, c.own_hosts) for s in page.styles),
                    "assetNames": uniq(asset_name(urljoin(base, s)) for s in refs),
                    "forms": page.forms[:30], "hiddenFields": uniq(page.hidden, 60),
                    "customElements": uniq(page.elements, 60), "ids": uniq(page.ids, 60), "comments": page.comments}
                inline = {k: [] for k in ("globals", "apiPaths", "routes", "hosts", "clientIds", "assemblies",
                                          "frameworkAssemblies")}
                scan_script("\n".join(page.inline), inline)
                inline.pop("frameworkAssemblies")
                out["inline"] = {k: uniq(v) for k, v in inline.items()}
                scripts(c, page.scripts, base, out)
        if not a.no_probes:
            pu = urlsplit(page_url if (urlsplit(page_url).hostname or "").lower() in c.own_hosts else url)
            root = f"{pu.scheme}://{pu.netloc}/"
            folder = urljoin(root, pu.path if pu.path.endswith("/") else pu.path.rsplit("/", 1)[0] + "/")
            last = pu.path.rsplit("/", 1)[-1]
            sub = urljoin(root, pu.path + "/") if last and "." not in last else None
            bases = uniq([urljoin(page_url, page.base) if page and page.base else None, sub, folder, root])
            probes(c, bases, page, page_url, out)
    except Budget:
        c.errors.append(f"stopped at {a.max_requests} requests (--max-requests)")
    out.update(headers=c.headers, cookies=sorted(c.cookies), requests=c.count, errors=c.errors[:20])
    return prune(out)


def summary(d: dict) -> str:
    parts = []
    if d.get("signIn"):
        s = d["signIn"]
        parts.append("sign-in at " + str(s.get("host")) + (f" (client {s['clientId']})" if s.get("clientId") else "")
                     + (f" (SAML issuer {s['samlIssuer']})" if s.get("samlIssuer") else ""))
    if d.get("page"):
        p = d["page"]
        parts.append(f"page \"{p.get('title', '')}\", {len(p.get('scripts', []))} scripts")
    b = d.get("bundles", {})
    for key, label in (("globals", "bundle globals"), ("apiPaths", "API paths"), ("routes", "routes"),
                       ("clientIds", "client IDs"), ("assemblies", "assemblies")):
        if b.get(key):
            parts.append(f"{len(b[key])} {label}")
    if d.get("sourceMaps"):
        parts.append(f"{len(d['sourceMaps'])} source maps ({sum(m.get('sourceCount', 0) for m in d['sourceMaps'])} files)")
    if d.get("blazor"):
        parts.append(f"Blazor: {len(d['blazor'].get('assemblies', []))} assemblies")
    if d.get("openapi"):
        parts.append(f"OpenAPI \"{d['openapi'].get('title', '')}\": {d['openapi'].get('pathCount', 0)} paths")
    for key in ("manifest", "actuator", "robots", "favicon"):
        if d.get(key):
            parts.append(key)
    if d.get("cookies"):
        parts.append(f"{len(d['cookies'])} cookies")
    if not parts:
        parts.append("nothing" + (f": {d['errors'][0]}" if d.get("errors") else f" (HTTP {d.get('status', '?')})"))
    return f"{d.get('id') or d.get('name') or d.get('host')}: " + ", ".join(parts) + f" [{d.get('requests', 0)} requests]"


# ------------------------------------------------------------------ input and main

def read_apps(inputs: list) -> list:
    apps = []
    for item in inputs:
        if re.match(r"(?i)^https?://", item):
            apps.append({"url": item})
            continue
        with open(item, encoding="utf-8-sig", newline="") as f:
            text = f.read()
        head = text.splitlines()[0] if text.strip() else ""
        rows = list(csv.reader(text.splitlines(), delimiter=";" if head.count(";") > head.count(",") else ","))
        cols = [h.strip().lower().replace(" ", "").replace("_", "") for h in rows[0]] if rows else []
        if "url" not in cols:
            if all(len(r) == 1 for r in rows if r):                       # a plain list of URLs
                apps += [{"url": r[0].strip()} for r in rows if r and r[0].strip()]
                continue
            raise SystemExit(f"{item}: no `url` column in the header line ({', '.join(rows[0]) if rows else 'empty'})")
        pick = {k: next((cols.index(n) for n in names if n in cols), None)
                for k, names in (("url", ["url"]), ("id", ["id", "applicationid", "appid"]),
                                 ("name", ["name", "application", "applicationname"]))}
        for r in rows[1:]:
            get = lambda k: r[pick[k]].strip() if pick[k] is not None and pick[k] < len(r) else ""
            if get("url"):
                apps.append({"url": get("url"), "id": get("id"), "name": get("name")})
    return apps


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Record what applications' production URLs serve (GET only), as JSON.")
    p.add_argument("inputs", nargs="+", help="URLs, or CSV files with a `url` column (and `id`, `name`)")
    p.add_argument("-o", "--output", help="the JSON file to write (default: standard output)")
    p.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                   help="a request header for the application's own host, such as a session cookie (repeatable)")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--no-probes", action="store_true", help="only the page and its scripts, no well-known files")
    p.add_argument("--max-requests", type=int, default=60, help="requests per application (default 60)")
    p.add_argument("--timeout", type=float, default=15, help="seconds per request (default 15)")
    p.add_argument("--delay", type=float, default=0.1, help="seconds between requests (default 0.1)")
    a = p.parse_args(argv)
    a.extra_headers = {}
    for h in a.header:
        name, sep, value = h.partition(":")
        if not sep or not name.strip():
            p.error(f"--header needs 'Name: value': {h}")
        a.extra_headers[name.strip()] = value.strip()
    apps = read_apps(a.inputs)
    results = []
    for n, app in enumerate(apps, 1):
        d = collect(app, a)
        results.append(d)
        print(f"[{n}/{len(apps)}] {summary(d)}", file=sys.stderr, flush=True)
    doc = {"collector": USER_AGENT, "collectedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "applications": results}
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"{len(results)} applications -> {a.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
