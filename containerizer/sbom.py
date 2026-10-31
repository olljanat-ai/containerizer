"""Software bills of materials (CycloneDX), licence policy and CVEs per package.

- `image_sbom` runs Syft on a built image (`docker:` when it is local, `registry:` otherwise) and returns
  its CycloneDX JSON document.
- `source_sbom` builds a CycloneDX document from the project files containerizer already read (direct
  package references of the component and of the projects it references), for components that are not
  built: nothing from the repository is executed, and transitive packages appear only in image SBOMs.
- `analyze` turns a document into a package list: licences normalised to SPDX expressions where the
  data allows it, NuGet licences looked up from the package feed when the SBOM has none (Syft does not
  read them), every package classified against the licence policy in `rules/60-security.yaml` (`sbom`),
  and the vulnerabilities of the gate's image scan (Trivy, Grype) attached to the package they are in.
- `attach` pushes the SBOM to the registry next to the image: a signed in-toto attestation with cosign
  when a key is configured (`cosign attest --type cyclonedx`), else an OCI referrer artifact with ORAS.

Licence status of a package: allowed, warn, denied or unknown (no licence found, or only a name that is
not an SPDX identifier). An SPDX expression is evaluated as written: `A OR B` takes the better of the
two, `A AND B` the worse; several licences listed on one package count as AND (a Debian package lists
the licence of every file it ships). OS packages of the base image are reported with their status but
do not count against the policy unless `os_packages: evaluate`.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

STATUSES = ("allowed", "unknown", "warn", "denied")          # better -> worse
STATUS_RANK = {s: i for i, s in enumerate(STATUSES)}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
OS_TYPES = {"deb", "apk", "rpm", "alpm", "portage"}
CDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"
PURL_TYPES = {"dotnet": "nuget", "node": "npm", "python": "pypi", "java": "maven", "go": "golang"}

# Licence names that tools write instead of SPDX identifiers (Debian copyright files, nuspec, npm).
ALIASES = {
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache2": "Apache-2.0", "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0", "apache software license": "Apache-2.0",
    "mit license": "MIT", "the mit license": "MIT", "expat": "MIT",
    "bsd": "BSD-3-Clause", "new bsd license": "BSD-3-Clause", "bsd-3": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause", "bsd-2": "BSD-2-Clause",
    "isc license": "ISC", "zlib license": "Zlib", "public-domain": "LicenseRef-public-domain",
    "public domain": "LicenseRef-public-domain", "mpl 2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
    "ms-pl": "MS-PL", "microsoft public license": "MS-PL",
}
# License URLs of older NuGet packages (nuspec <licenseUrl>) that name one licence unambiguously.
LICENSE_URLS = [
    (r"https?://(www\.)?opensource\.org/licenses/(mit|MIT)(-license)?(\.php|\.html)?/?$", "MIT"),
    (r"https?://(www\.)?apache\.org/licenses/LICENSE-2\.0(\.txt|\.html)?/?$", "Apache-2.0"),
    (r"https?://(www\.)?opensource\.org/licenses/(Apache-2\.0|apache2\.0)(\.php)?/?$", "Apache-2.0"),
    (r"https?://(www\.)?opensource\.org/licenses/(BSD-3-Clause|bsd-license)(\.php)?/?$", "BSD-3-Clause"),
    (r"https?://(www\.)?opensource\.org/licenses/(ms-pl|MS-PL)(\.html)?/?$", "MS-PL"),
    (r"https?://(www\.)?gnu\.org/licenses/lgpl(-3\.0)?(\.html|\.txt)?$", "LGPL-3.0-only"),
    (r"https?://(www\.)?gnu\.org/licenses/gpl(-3\.0)?(\.html|\.txt)?$", "GPL-3.0-only"),
    # Microsoft .NET Library License (older System.* and Microsoft.* packages): proprietary, redistributable
    (r"https?://go\.microsoft\.com/fwlink/\?LinkId=329770$", "LicenseRef-Microsoft-NET-Library"),
    (r"https?://dotnet\.microsoft\.com/(en-us/)?dotnet_library_license\.htm$", "LicenseRef-Microsoft-NET-Library"),
    (r"https?://(www\.)?microsoft\.com/web/webpi/eula/net_library_eula_enu\.htm$", "LicenseRef-Microsoft-NET-Library"),
    # repositories whose licence file has always been the same licence
    (r"https?://github\.com/dotnet/(corefx|runtime|extensions|aspnetcore|efcore)/blob/(master|main)/LICENSE(\.txt)?$", "MIT"),
    (r"https?://github\.com/microsoft/dotnet/blob/(master|main)/LICENSE$", "MIT"),
    (r"https?://raw\.github(usercontent)?\.com/JamesNK/Newtonsoft\.Json/(master|main)/LICENSE\.md$", "MIT"),
    (r"https?://logging\.apache\.org/log4net/license\.html$", "Apache-2.0"),
]


def config() -> dict:
    from .harden import security
    return security().get("sbom") or {}


# --------------------------------------------------------------------------- the document

@dataclass
class Package:
    name: str
    version: str = ""
    type: str = ""                   # purl type: nuget, npm, deb, apk, ... ("" when the SBOM has no purl)
    purl: str = ""
    licenses: list = field(default_factory=list)     # as found: SPDX ids, expressions, names
    license: str = ""                # one expression for display ("A AND B")
    license_source: str = ""         # sbom, nuget, scanner
    status: str = "unknown"          # allowed | unknown | warn | denied
    scope: str = "app"               # app | os | self (the application's own assembly)
    applies: bool = True             # counts against the licence policy
    accepted: str = ""               # reason of an accepted exception
    found_by: str = "sbom"           # sbom | scanner (a vulnerable package the SBOM did not list)
    vulns: list = field(default_factory=list)         # {id, severity, fixed, title}

    def counts(self) -> dict:
        out = {s: 0 for s in SEVERITIES}
        for v in self.vulns:
            if v["severity"] in out:
                out[v["severity"]] += 1
        return out

    def to_dict(self) -> dict:
        return {**asdict(self), "counts": self.counts()}


def purl_type(purl: str) -> str:
    m = re.match(r"pkg:([a-z0-9.+-]+)/", purl or "")
    return m.group(1) if m else ""


def purl_key(purl: str) -> str:
    """A purl without qualifiers and subpath, lower case (NuGet ids and most types compare case-insensitively)."""
    p = (purl or "").split("#")[0].split("?")[0]
    return urllib.parse.unquote(p).lower()


def packages_from_cyclonedx(doc: dict) -> list[Package]:
    """Library and application components of a CycloneDX document, one per package (merged by purl, or
    by name, version and type when there is none). Files and the operating system entry are left out."""
    out: dict = {}
    for c in doc.get("components") or []:
        if c.get("type") not in ("library", "application", "framework", None) or not c.get("name"):
            continue
        purl = c.get("purl") or ""
        typ = purl_type(purl) or next((p.get("value") for p in c.get("properties") or []
                                       if p.get("name") == "syft:package:type"), "")
        lic = []
        for x in c.get("licenses") or []:
            if x.get("expression"):
                lic.append(str(x["expression"]).strip())
            elif isinstance(x.get("license"), dict):
                v = x["license"].get("id") or x["license"].get("name")
                if v:
                    lic.append(str(v).strip())
        key = purl_key(purl) or f"{typ}|{c['name'].lower()}|{c.get('version', '')}"
        if key in out:
            for v in lic:
                if v not in out[key].licenses:
                    out[key].licenses.append(v)
            continue
        out[key] = Package(c["name"], str(c.get("version") or ""), typ, purl, lic, license_source="sbom" if lic else "")
    return list(out.values())


def os_name(doc: dict) -> str:
    c = next((c for c in doc.get("components") or [] if c.get("type") == "operating-system"), None)
    return f"{c.get('name', '')} {c.get('version', '')}".strip() if c else ""


def new_document(name: str, version: str = "", kind: str = "application") -> dict:
    """An empty CycloneDX 1.6 document made by containerizer."""
    from .sqlstore import tool_version
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                         "tools": {"components": [{"type": "application", "name": "containerizer",
                                                   "version": tool_version() or "dev"}]},
                         "component": {"type": kind, "name": name, **({"version": version} if version else {}),
                                       "bom-ref": f"containerizer:{name}"}},
            "components": []}


# --------------------------------------------------------------------------- generating

def _run(cmd: list[str], timeout: int = 900, env: dict | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", env=env)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def syft_command() -> list[str] | None:
    """The Syft binary, or Syft as a container (with the Docker socket, proxy and CA bundle)."""
    g = config().get("generator") or {}
    binary, image = g.get("binary", "syft"), g.get("image", "anchore/syft:v1.33.0")
    if shutil.which(binary):
        return [binary]
    if not shutil.which("docker"):
        return None
    from .imagescan import _docker_tool_args, _tool_image
    img = _tool_image(image)
    if not img:
        return None
    return ["docker", "run", "--rm", "-e", "SYFT_CHECK_FOR_APP_UPDATE=false", *_docker_tool_args(), img]


def syft_version(doc: dict) -> str:
    tools = (doc.get("metadata") or {}).get("tools") or {}
    comps = tools.get("components") if isinstance(tools, dict) else tools
    t = next((t for t in comps or [] if t.get("name") == "syft"), None)
    return f"syft {t.get('version', '')}".strip() if t else ""


def image_sbom(ref: str, local: bool = True) -> tuple[dict | None, str]:
    """(CycloneDX document, error) for an image: from the local Docker daemon, or pulled from its registry."""
    cmd = syft_command()
    if not cmd:
        return None, "no SBOM generator: install syft, or make docker available"
    env = {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"}
    rc, out, err = _run(cmd + ["scan", "-q", ("docker:" if local else "registry:") + ref, "-o", "cyclonedx-json"],
                        env=env)
    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        return None, (err or out).strip()[-600:] or f"syft exited with {rc}"
    if doc.get("bomFormat") != "CycloneDX":
        return None, "syft did not return a CycloneDX document"
    return doc, ""


_CONCRETE = re.compile(r"^v?\d+(\.\d+)*([-.+][0-9A-Za-z.\-+]+)?$")


def _concrete(v: str) -> str:
    """A concrete version from a reference: "8.0.11", "[8.0.11]", "==2.31.0", "^1.2.3" stays a range -> ""."""
    v = (v or "").strip()
    v = re.sub(r"^\[([^,\]]+)\]$", r"\1", v)
    v = re.sub(r"^==\s*", "", v)
    return v if _CONCRETE.match(v) else ""


def _purl(typ: str, name: str, version: str) -> str:
    if typ == "maven" and ":" in name:
        g, a = name.split(":", 1)
        base = f"pkg:maven/{urllib.parse.quote(g)}/{urllib.parse.quote(a)}"
    elif typ == "npm" and name.startswith("@") and "/" in name:
        scope, n = name.split("/", 1)
        base = f"pkg:npm/{urllib.parse.quote(scope)}/{urllib.parse.quote(n)}"
    elif typ == "golang":
        base = "pkg:golang/" + "/".join(urllib.parse.quote(x) for x in name.split("/"))
    else:
        base = f"pkg:{typ}/{urllib.parse.quote(name)}"
    return base + (f"@{urllib.parse.quote(version)}" if version else "")


def source_sbom(component, repo=None) -> dict:
    """CycloneDX document of a component's declared dependencies: its own package references and those of
    the projects it references (transitively). Ranges and floating versions are kept as written in a
    property and left out of the purl; development-only npm packages are left out."""
    p = component.project
    projects = [p]
    if repo is not None:
        from .rules import _ref_closure
        projects += _ref_closure(repo, p)
    typ = PURL_TYPES.get(p.kind_hint, "")
    doc = new_document(component.name)
    seen = set()
    for q in projects:
        qt = PURL_TYPES.get(q.kind_hint, typ)
        if not qt:
            continue
        locked = _locked_packages(q)
        if locked is not None:
            for name, ver, lic in locked:
                if (qt, name.lower(), ver) in seen:
                    continue
                seen.add((qt, name.lower(), ver))
                purl = _purl(qt, name, ver)
                c = {"type": "library", "name": name, "version": ver, "bom-ref": purl, "purl": purl,
                     "properties": [{"name": "containerizer:declared-in", "value": q.rel},
                                    {"name": "containerizer:source", "value": "lock file"}]}
                if lic:
                    c["licenses"] = [{"expression": lic}] if re.search(r"\s(AND|OR|WITH)\s", lic) else \
                        [{"license": {"id": spdx_id(lic)} if _is_spdx(lic) else {"name": lic}}]
                doc["components"].append(c)
            continue
        deps = ((q.manifest or {}).get("dependencies") or {}) if q.kind_hint == "node" else (q.packages or {})
        for name, spec in sorted(deps.items(), key=lambda kv: kv[0].lower()):
            spec = str(spec or "")
            ver = _concrete(spec)
            if any(k[:2] == (qt, name.lower()) for k in seen):
                continue
            seen.add((qt, name.lower(), ver))
            purl = _purl(qt, name, ver)
            c = {"type": "library", "name": name, "bom-ref": purl, "purl": purl,
                 "properties": [{"name": "containerizer:declared-in", "value": q.rel}]}
            if ver:
                c["version"] = ver
            elif spec:
                c["properties"].append({"name": "containerizer:version-range", "value": spec})
            doc["components"].append(c)
    return doc


def _locked_packages(q) -> list[tuple[str, str, str]] | None:
    """(name, version, licence) of every runtime package in a project's lock file, or None without one:
    package-lock.json (npm, dev packages left out; v2+ records licences) or packages.lock.json (NuGet)."""
    d = q.dir
    try:
        if q.kind_hint == "node" and (d / "package-lock.json").is_file():
            lock = json.loads((d / "package-lock.json").read_text(errors="replace"))
            out = []
            if isinstance(lock.get("packages"), dict):                # lockfile v2, v3
                for k, v in lock["packages"].items():
                    if not k or v.get("dev") or v.get("link") or not v.get("version"):
                        continue
                    name = v.get("name") or k.rsplit("node_modules/", 1)[-1]
                    lic = v.get("license")
                    lic = lic.get("type", "") if isinstance(lic, dict) else str(lic or "")
                    out.append((name, str(v["version"]), lic))
            else:                                                       # lockfile v1: no licences
                stack = list((lock.get("dependencies") or {}).items())
                while stack:
                    name, v = stack.pop()
                    if not v.get("dev") and v.get("version"):
                        out.append((name, str(v["version"]), ""))
                    stack += list((v.get("dependencies") or {}).items())
            return sorted(set(out), key=lambda x: (x[0].lower(), x[1]))
        if q.kind_hint == "dotnet" and (d / "packages.lock.json").is_file():
            lock = json.loads((d / "packages.lock.json").read_text(errors="replace"))
            out = set()
            for tfm in (lock.get("dependencies") or {}).values():
                for name, v in (tfm or {}).items():
                    if (v or {}).get("type") != "Project" and (v or {}).get("resolved"):
                        out.add((name, str(v["resolved"]), ""))
            return sorted(out, key=lambda x: (x[0].lower(), x[1]))
    except (OSError, ValueError, AttributeError):
        return None
    return None


# --------------------------------------------------------------------------- NuGet licences

def _nuget_cache_file() -> Path:
    from .imagescan import WORK
    return WORK / "sbom-cache" / "nuget-licenses.json"


_NUGET: dict = {"base": None, "cache": None}


def _nuget_base(feed: str) -> str | None:
    """PackageBaseAddress (flat container) of a NuGet v3 feed, from its service index."""
    if _NUGET["base"] is None:
        try:
            with urllib.request.urlopen(feed, timeout=30) as r:
                idx = json.loads(r.read())
            base = next((x["@id"] for x in idx.get("resources") or []
                         if str(x.get("@type", "")).startswith("PackageBaseAddress/3.0.0")), "")
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            base = ""
        _NUGET["base"] = base.rstrip("/") + "/" if base else ""
    return _NUGET["base"] or None


def _license_from_nuspec(xml: bytes) -> str:
    root = ET.fromstring(xml)
    lic = url = None
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "license" and lic is None:
            lic = el
        elif tag == "licenseUrl" and url is None:
            url = (el.text or "").strip()
    if lic is not None and (lic.get("type") or "expression") == "expression" and (lic.text or "").strip():
        return lic.text.strip()
    if lic is not None and lic.get("type") == "file":
        return "LicenseRef-see-package-file"
    if url:
        m = re.match(r"https?://licenses\.nuget\.org/(.+)$", url)
        if m:
            return urllib.parse.unquote(m.group(1))
        for rx, spdx in LICENSE_URLS:
            if re.match(rx, url, re.I):
                return spdx
        return "LicenseRef-url:" + url[:200]
    return ""


def nuget_license(name: str, version: str, feed: str | None = None) -> str:
    """The licence a NuGet package declares in its nuspec (expression, or a mapped licence URL); "" when
    the feed does not have the package or cannot be reached. Answers are cached on disk."""
    if not name or not _concrete(version):
        return ""
    cache_file = _nuget_cache_file()
    if _NUGET["cache"] is None:
        try:
            _NUGET["cache"] = json.loads(cache_file.read_text())
        except (OSError, ValueError):
            _NUGET["cache"] = {}
    key = f"{name.lower()}/{version.lower()}"
    if key in _NUGET["cache"]:
        return _NUGET["cache"][key]
    base = _nuget_base(feed or config().get("nuget_feed") or "https://api.nuget.org/v3/index.json")
    if not base:
        return ""
    n, v = urllib.parse.quote(name.lower()), urllib.parse.quote(version.lower())
    try:
        with urllib.request.urlopen(f"{base}{n}/{v}/{n}.nuspec", timeout=30) as r:
            lic = _license_from_nuspec(r.read())
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return ""
        lic = ""                      # not on this feed (a private package): remember it
    except (urllib.error.URLError, OSError, ET.ParseError):
        return ""
    _NUGET["cache"][key] = lic
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(_NUGET["cache"], sort_keys=True))
        tmp.replace(cache_file)
    except OSError:
        pass
    return lic


# --------------------------------------------------------------------------- licence policy

def normalize(lic: str) -> str:
    """An SPDX identifier or expression for a licence string; known names map to their identifier."""
    s = " ".join(str(lic or "").split())
    return ALIASES.get(s.lower(), s)


_SPDX: dict = {}


def spdx_ids() -> tuple[dict, dict]:
    """({lower-case id: id} of SPDX licences, same for exceptions), from rules/spdx-licenses.yaml."""
    if not _SPDX:
        import yaml
        from .rules import RULES_DIR
        d = yaml.safe_load((RULES_DIR / "spdx-licenses.yaml").read_text())
        _SPDX["l"] = {x.lower(): x for x in d["licenses"]}
        _SPDX["e"] = {x.lower(): x for x in d["exceptions"]}
    return set(_SPDX["l"].values()), _SPDX["l"]


def spdx_id(lic: str) -> str:
    """The canonical spelling of an SPDX identifier (ids compare case-insensitively); "GPL-2.0+" keeps its +."""
    base, plus = (lic[:-1], "+") if lic.endswith("+") else (lic, "")
    return spdx_ids()[1].get(base.lower(), base) + plus if base.lower() in spdx_ids()[1] else lic


def _tokens(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expr)


def _is_spdx(token: str) -> bool:
    return spdx_id(token.rstrip("+")) in spdx_ids()[0]


class _Policy:
    def __init__(self, pol: dict, today: date | None = None):
        lic = pol.get("licenses") or {}
        self.deny = [re.compile(x, re.I) for x in lic.get("deny") or []]
        self.warn = [re.compile(x, re.I) for x in lic.get("warn") or []]
        self.allow = [re.compile(x, re.I) for x in lic.get("allow") or []]
        self.unknown = {"report": "unknown", "warn": "warn", "deny": "denied"}.get(lic.get("unknown", "report"), "unknown")
        self.exceptions = lic.get("accepted") or []
        self.today = today or date.today()

    def one(self, lic: str) -> str:
        lic = spdx_id(lic)
        for rx in self.deny:
            if rx.fullmatch(lic):
                return "denied"
        for rx in self.warn:
            if rx.fullmatch(lic):
                return "warn"
        for rx in self.allow:
            if rx.fullmatch(lic):
                return "allowed"
        # an SPDX licence the lists do not name is allowed; anything else (free text, a URL, a LicenseRef
        # nobody allowed) cannot be judged
        return "allowed" if lic in spdx_ids()[0] else self.unknown

    def expression(self, expr: str) -> str:
        """Status of an SPDX expression: OR takes the better side, AND the worse, WITH keeps the licence."""
        toks = _tokens(expr)
        if not toks:
            return self.unknown
        pos = 0

        def primary() -> str:
            nonlocal pos
            if pos >= len(toks):
                return self.unknown
            t = toks[pos]
            pos += 1
            if t == "(":
                v = disj()
                if pos < len(toks) and toks[pos] == ")":
                    pos += 1
                return v
            v = self.one(normalize(t))
            if pos < len(toks) and toks[pos].upper() == "WITH":
                pos += 2                  # an exception only grants more; judge the licence it modifies
            return v

        def conj() -> str:
            nonlocal pos
            v = primary()
            while pos < len(toks) and toks[pos].upper() == "AND":
                pos += 1
                w = primary()
                v = v if STATUS_RANK[v] >= STATUS_RANK[w] else w
            return v

        def disj() -> str:
            nonlocal pos
            v = conj()
            while pos < len(toks) and toks[pos].upper() == "OR":
                pos += 1
                w = conj()
                v = v if STATUS_RANK[v] <= STATUS_RANK[w] else w
            return v

        # a free-text licence name ("Microsoft Software License") is one licence, not an expression
        if not re.search(r"\s(AND|OR|WITH)\s", expr, re.I) and " " in expr.strip():
            return self.one(normalize(expr))
        v = disj()
        return v if pos == len(toks) else self.one(normalize(expr))      # not a well-formed expression

    def accepted(self, p: Package) -> str:
        for x in self.exceptions:
            if not re.fullmatch(str(x.get("package", "$^")), p.name, re.I):
                continue
            if x.get("version") and not re.fullmatch(str(x["version"]), p.version):
                continue
            exp = x.get("expires")
            exp = exp if isinstance(exp, date) or exp is None else date.fromisoformat(str(exp))
            if exp is not None and exp < self.today:
                continue
            return str(x.get("reason") or "accepted")
        return ""


def classify(packages: list[Package], pol: dict | None = None, own_names: tuple = (), today: date | None = None) -> None:
    """Set license, status, scope and applies on each package."""
    pol = pol if pol is not None else config()
    P = _Policy(pol, today)
    evaluate_os = pol.get("os_packages", "report") == "evaluate"
    own = {n.lower() for n in own_names if n}
    for p in packages:
        lic = [normalize(x) for x in p.licenses if x]
        p.license = " AND ".join(f"({x})" if re.search(r"\s(OR|AND)\s", x, re.I) and len(lic) > 1 else x for x in lic)
        # several licences on one package: all of them apply (AND)
        p.status = max((P.expression(x) for x in lic), key=STATUS_RANK.get) if lic else P.unknown
        if p.type in OS_TYPES:
            p.scope, p.applies = "os", evaluate_os
        elif p.name.lower() in own:
            p.scope, p.applies, p.status = "self", False, "allowed"
        reason = P.accepted(p) if p.status in ("warn", "denied", "unknown") else ""
        if reason:
            p.accepted, p.applies = reason, False


# --------------------------------------------------------------------------- CVEs per package

def attach_vulns(packages: list[Package], vulns: list) -> int:
    """Attach scanner findings (imagescan.Vuln) to packages: by purl, else by name and version. A finding
    whose package the SBOM does not list becomes its own package (found_by=scanner), so no CVE is lost.
    Returns the number of such packages."""
    by_purl = {purl_key(p.purl): p for p in packages if p.purl}
    by_name: dict = {}
    for p in packages:
        by_name.setdefault((p.name.lower(), p.version), p)
    extra: dict = {}
    for v in vulns:
        p = by_purl.get(purl_key(getattr(v, "purl", ""))) if getattr(v, "purl", "") else None
        p = p or by_name.get((v.package.lower(), v.installed))
        if p is None:
            k = (v.package.lower(), v.installed)
            p = extra.get(k)
            if p is None:
                p = extra[k] = Package(v.package, v.installed, purl_type(getattr(v, "purl", "")) or _scanner_type(v.type),
                                       getattr(v, "purl", ""), found_by="scanner")
                p.scope = "os" if p.type in OS_TYPES else "app"
        if any(x["id"] == v.id for x in p.vulns):
            continue
        p.vulns.append({"id": v.id, "severity": v.severity, "fixed": v.fixed, "title": v.title})
    packages.extend(extra.values())
    return len(extra)


def _scanner_type(t: str) -> str:
    t = (t or "").lower()
    return {"dotnet-core": "nuget", "nuget": "nuget", "dotnet-deps": "nuget", "npm": "npm", "node-pkg": "npm",
            "debian": "deb", "ubuntu": "deb", "deb": "deb", "alpine": "apk", "apk": "apk", "redhat": "rpm", "rpm": "rpm",
            "python-pkg": "pypi", "pip": "pypi", "jar": "maven", "java-archive": "maven", "gobinary": "golang",
            "go-module": "golang"}.get(t, t)


# --------------------------------------------------------------------------- one SBOM, analysed

def enrich_licenses(doc: dict, packages: list[Package]) -> int:
    """Look up NuGet licences missing from the SBOM and write them into the document too. Returns how many."""
    cfg = config()
    if not cfg.get("nuget_licenses", True):
        return 0
    found = {}
    for p in packages:
        if p.type == "nuget" and not p.licenses and p.scope != "self" and p.found_by == "sbom":
            lic = nuget_license(p.name, p.version, cfg.get("nuget_feed"))
            if lic:
                p.licenses, p.license_source = [lic], "nuget"
                found[purl_key(p.purl)] = lic
    for c in doc.get("components") or []:
        lic = found.get(purl_key(c.get("purl") or ""))
        if lic and not c.get("licenses"):
            if re.search(r"\s(AND|OR|WITH)\s", lic):
                c["licenses"] = [{"expression": lic}]
            elif _is_spdx(lic):
                c["licenses"] = [{"license": {"id": spdx_id(lic)}}]
            else:
                c["licenses"] = [{"license": {"name": lic}}]
    return len(found)


def analyze(doc: dict, vulns: list = (), own_names: tuple = (), pol: dict | None = None) -> list[Package]:
    """Package list of a CycloneDX document with licences (looked up where missing), policy status and CVEs."""
    pkgs = packages_from_cyclonedx(doc)
    for p in pkgs:
        if p.name.lower() in {n.lower() for n in own_names if n}:
            p.scope = "self"
    enrich_licenses(doc, pkgs)
    attach_vulns(pkgs, list(vulns))
    classify(pkgs, pol, own_names)
    return sorted(pkgs, key=sort_key)


def sort_key(p: Package):
    c = p.counts()
    return (not p.applies, -STATUS_RANK[p.status] if p.applies else 0, -c["CRITICAL"], -c["HIGH"], -c["MEDIUM"],
            p.scope != "app", p.name.lower())


def summarize(packages: list[Package]) -> dict:
    """Counts for reports: packages, licence findings (only packages the policy applies to), CVEs."""
    lic = {s: 0 for s in STATUSES}
    for p in packages:
        if p.applies:
            lic[p.status] += 1
    vul = {s: 0 for s in SEVERITIES}
    for p in packages:
        for k, n in p.counts().items():
            vul[k] += n
    return {"packages": len(packages), "licenses": lic, "vulnerabilities": vul,
            "vulnerable_packages": sum(1 for p in packages if p.vulns),
            "denied": sorted({f"{p.name} {p.version} ({p.license or 'no licence'})" for p in packages
                              if p.applies and p.status == "denied"}),
            "warn": sorted({f"{p.name} {p.version} ({p.license or 'no licence'})" for p in packages
                            if p.applies and p.status == "warn"})}


def component_sbom(tag: str, cdir: Path, vulns: list, own_names: tuple, image_ref: str = "") -> dict:
    """Generate, analyse and write `<cdir>/sbom.cdx.json` for a built image. Returns the gate entry."""
    doc, err = image_sbom(tag, local=True)
    if doc is None:
        return {"kind": "image", "error": err, "passed": True}
    if image_ref:
        doc.setdefault("metadata", {}).setdefault("component", {})["name"] = image_ref.rsplit(":", 1)[0]
    pkgs = analyze(doc, vulns, own_names)
    (cdir / "sbom.cdx.json").write_text(json.dumps(doc, indent=2) + "\n")
    s = summarize(pkgs)
    return {"kind": "image", "file": "sbom.cdx.json", "format": f"CycloneDX {doc.get('specVersion', '')}".strip(),
            "tool": syft_version(doc), "os": os_name(doc), "summary": s, "passed": not s["denied"], "error": "",
            "packages": [p.to_dict() for p in pkgs]}


def source_component_sbom(component, repo=None, pol: dict | None = None) -> tuple[dict, list[Package]]:
    """Source SBOM of a component with licences and policy status (no CVEs: nothing was scanned)."""
    doc = source_sbom(component, repo)
    own = (component.name, component.project.name)
    pkgs = packages_from_cyclonedx(doc)
    enrich_licenses(doc, pkgs)
    classify(pkgs, pol, own)
    return doc, sorted(pkgs, key=sort_key)


# --------------------------------------------------------------------------- registry

def repository(ref: str) -> str:
    """`registry:5000/app/web:1.2@sha256:..` -> `registry:5000/app/web` (a port is not a tag)."""
    ref = ref.split("@")[0]
    head, _, last = ref.rpartition("/")
    return f"{head}/{last.split(':')[0]}" if head else last.split(":")[0]


def attach(ref: str, digest: str, sbom_file: Path, key: str | None = None, docker_config: str | None = None) -> str:
    """Put the SBOM next to the pushed image `<repo>@<digest>`. With a cosign key: a signed CycloneDX
    attestation (cosign attest --type cyclonedx). Without: an OCI referrer artifact (oras attach).
    Returns a short status: attested, attached, or why not."""
    target = f"{repository(ref)}@{digest}"
    env = {**os.environ, **({"DOCKER_CONFIG": docker_config} if docker_config else {})}
    from .orgsource import REDACT
    if key:
        if not shutil.which("cosign"):
            return "not attested: cosign not installed"
        tlog = [] if config().get("cosign_tlog_upload", True) else ["--tlog-upload=false"]
        rc, out, err = _run(["cosign", "attest", "--yes", *tlog, "--key", key, "--type", "cyclonedx",
                             "--predicate", str(sbom_file), target], 600, env)
        return "attested" if rc == 0 else f"cosign attest failed: {REDACT(err.strip())[-200:]}"
    if not config().get("attach", True):
        return "not attached (sbom.attach is off)"
    if not shutil.which("oras"):
        return "not attached: oras not installed (or configure a cosign key to attest)"
    cfg = ["--registry-config", str(Path(docker_config) / "config.json")] if docker_config else []
    with tempfile.TemporaryDirectory(prefix="cz-sbom-") as d:
        # oras names the layer after the file path it is given: a stable name, no local path
        shutil.copyfile(sbom_file, Path(d) / "sbom.cdx.json")
        rc, out, err = _oras(cfg, target, d, env)
    return "attached" if rc == 0 else f"oras attach failed: {REDACT((err or out).strip())[-200:]}"


def _oras(cfg: list, target: str, workdir: str, env: dict) -> tuple[int, str, str]:
    try:
        p = subprocess.run(["oras", "attach", *cfg, "--artifact-type", CDX_MEDIA_TYPE, target,
                            f"sbom.cdx.json:{CDX_MEDIA_TYPE}"], capture_output=True, text=True, timeout=600,
                           errors="replace", env=env, cwd=workdir)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


# --------------------------------------------------------------------------- markdown

def markdown(name: str, entry: dict, limit: int = 40) -> str:
    """Licence and CVE section of SECURITY.md for one component."""
    if entry.get("error"):
        return f"- SBOM not generated: {entry['error'][:300]}\n"
    s = entry["summary"]
    lic, vul = s["licenses"], s["vulnerabilities"]
    lines = [f"- SBOM: `{entry['file']}` ({entry['format']}, {entry['tool']}), {s['packages']} packages; "
             f"licences: {lic['denied']} denied, {lic['warn']} to review, {lic['unknown']} unknown; "
             f"CVEs: {vul['CRITICAL']} critical, {vul['HIGH']} high in {s['vulnerable_packages']} packages"]
    for x in s["denied"][:limit]:
        lines.append(f"- **licence denied** by policy: {x}")
    for x in s["warn"][:limit]:
        lines.append(f"- licence to review: {x}")
    return "\n".join(lines) + "\n"
