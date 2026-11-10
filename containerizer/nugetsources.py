"""NuGet source names for the package source mapping of scanned code (docs/source-control.md#nuget-source-names).

A repository's NuGet.Config may map packages to a source by its key (`<packageSourceMapping><packageSource
key="internal">`) that the repository never defines: on the developers' machines and build agents the source comes
from their own user or machine NuGet.Config. A container build has no such file, so the mapped packages cannot be
found. Administrators give a NuGet feed (Admin → Source control → Package feeds) the names projects use for it,
`name[, name...] = source URL` per line (a line of names alone means the feed's URL itself); the source URL must be
under the feed's URL, so the feed proxy adds the token to its requests.

For each .NET component, the NuGet.Config files of its folder and the folders above it (to the repository's root)
are read; a mapped key no `<packageSources>` defines gets the registered source of that name, added before restore
by the generated Dockerfile (`dotnet nuget add source`, into the config nearest to the project, which NuGet applies
last), and MIGRATION.md lists it. A key no feed has a name for is listed as missing.
"""
from __future__ import annotations

import re
import shlex
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

CONFIG_NAMES = {"nuget.config"}           # NuGet.Config, NuGet.config, nuget.config (case folded)
NUGET_ORG = ("nuget.org", "https://api.nuget.org/v3/index.json")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._@+()-]{0,99}")
DOCS = "https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping"
MAX_TEXT = 2000


def parse(text: str, feed_url: str) -> list[tuple[str, str]]:
    """(name, source URL) of a feed's "NuGet source names" text; ValueError says what is wrong."""
    text = (text or "").strip()
    if len(text) > MAX_TEXT:
        raise ValueError(f"NuGet source names: at most {MAX_TEXT} characters")
    base = feed_url.rstrip("/")
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names, _, url = line.partition("=")
        url = url.strip() or feed_url
        p = urllib.parse.urlsplit(url)
        if p.scheme != "https" or not p.hostname or "@" in p.netloc or p.query or p.fragment \
                or re.search(r"[<>\"'\s]", url):
            raise ValueError(f"NuGet source names: {url!r} is not a plain https:// URL")
        if not (url.rstrip("/").casefold() == base.casefold() or url.casefold().startswith(base.casefold() + "/")):
            raise ValueError(f"NuGet source names: {url} is not under the feed's URL {feed_url}")
        for n in (x.strip() for x in names.split(",")):
            if not NAME_RE.fullmatch(n or ""):
                raise ValueError(f"NuGet source names: {n!r} is not a source name (letters, digits, spaces and "
                                 ". _ @ + ( ) -)")
            if any(n.casefold() == m.casefold() for m, _ in out):
                raise ValueError(f"NuGet source names: {n} is given twice")
            out.append((n, url))
    return out


def clashes(mine: list[tuple[str, str]], others: list[list[tuple[str, str]]]) -> list[str]:
    """The names of `mine` another feed already has (names are case-insensitive, as NuGet's keys)."""
    taken = {n.casefold() for o in others for n, _ in o}
    return [n for n, _ in mine if n.casefold() in taken]


def registered() -> dict[str, tuple[str, str]]:
    """casefolded name -> (name, URL) of the NuGet feeds the builds of this process go through (feedproxy.py)."""
    from . import feedproxy
    p = feedproxy.active()
    out: dict[str, tuple[str, str]] = {}
    for f in (p.feeds if p is not None else []):
        if f.kind == "nuget":
            for n, u in f.sources:
                out.setdefault(n.casefold(), (n, u))
    return out


def _configs(root: Path, project: Path) -> list[Path]:
    """The NuGet.Config files restore reads in the repository, nearest to the project first."""
    root = root.resolve()
    d = project.resolve().parent
    out = []
    while True:
        try:
            out += sorted(f for f in d.iterdir() if f.is_file() and f.name.casefold() in CONFIG_NAMES)
        except OSError:
            pass
        if d == root or root not in d.parents:
            break
        d = d.parent
    return out


def _read(path: Path) -> tuple[dict[str, str], set[str], bool]:
    """(defined source key -> URL, mapped source keys, has <clear/> in packageSources), keys as written."""
    try:
        doc = ET.fromstring(path.read_bytes())
    except (ET.ParseError, OSError):
        return {}, set(), False
    defined, mapped, clear = {}, set(), False
    for sec in doc:
        tag = sec.tag.casefold()
        if tag == "packagesources":
            for el in sec:
                if el.tag.casefold() == "add" and el.get("key"):
                    defined[el.get("key")] = el.get("value") or ""
                elif el.tag.casefold() == "clear":
                    clear = True
        elif tag == "packagesourcemapping":
            mapped |= {el.get("key") for el in sec if el.tag.casefold() == "packagesource" and el.get("key")}
    return defined, mapped, clear


def plan_sources(root: Path, project_rel: str, known: dict[str, tuple[str, str]] | None = None) -> dict | None:
    """What the build adds for the mapped sources the repository does not define: {"config": path in the repository,
    "add": [[name, url], ...], "missing": [names], "same": [[name, the other name]]}; None when nothing is missing.

    NuGet takes a URL once: of two sources with the same URL, restore keeps the first, and packages mapped to the
    other's name are not found. A name whose URL is already a source is not added but listed in "same"."""
    root = Path(root)
    configs = _configs(root, root / project_rel)
    if not configs:
        return None
    defined, urls, mapped, clear = set(), {}, {}, False
    for f in configs:
        d, m, c = _read(f)
        defined |= {k.casefold() for k in d}
        for k, u in d.items():
            urls.setdefault(u.rstrip("/").casefold(), k)
        for k in m:
            mapped.setdefault(k.casefold(), k)
        clear = clear or c
    if not clear:                     # the SDK's own NuGet.Config defines nuget.org
        defined.add(NUGET_ORG[0])
        urls.setdefault(NUGET_ORG[1].casefold(), NUGET_ORG[0])
    known = registered() if known is None else known
    add, missing, same = [], [], []
    # nuget.org first: the other names then never take its URL from it
    for key, name in sorted(mapped.items(), key=lambda kv: (kv[0] != NUGET_ORG[0], kv[0])):
        if key in defined:
            continue
        url = known[key][1] if key in known else NUGET_ORG[1] if key == NUGET_ORG[0] else None
        if url is None:
            missing.append(name)
        elif url.rstrip("/").casefold() in urls:
            same.append([name, urls[url.rstrip("/").casefold()]])
        else:
            add.append([name, url])
            urls[url.rstrip("/").casefold()] = name
    if not add and not missing and not same:
        return None
    return {"config": configs[0].relative_to(root.resolve()).as_posix(), "add": add, "missing": missing,
            "same": same}


def dockerfile_lines(plan: dict) -> list[str]:
    """RUN lines that add the plan's sources to the repository's NuGet.Config before restore."""
    ns = plan.get("nuget_sources") or {}
    if not ns.get("add"):
        return []
    cfg = shlex.quote(ns["config"])
    cmds = [f"dotnet nuget add source {shlex.quote(u)} -n {shlex.quote(n)} --configfile {cfg}" for n, u in ns["add"]]
    return ["# package sources the NuGet.Config's packageSourceMapping names but does not define (MIGRATION.md)",
            "RUN " + " \\\n && ".join(cmds)]


def reason(plan: dict) -> None:
    """The plan's reason for the added sources (Dockerfile header and plan.json)."""
    from .generate import add_reason
    ns = plan.get("nuget_sources") or {}
    if ns.get("add"):
        add_reason(plan, "nuget-sources", f"{ns['config']} maps packages to "
                   + ", ".join(n for n, _ in ns["add"]) + " but does not define them (on the developers' machines "
                   "they come from their own NuGet.Config): the build adds them with the URLs of the registered NuGet "
                   "feeds that have those names (nuget.org: its own).", [DOCS])


def migration_markdown(notes: dict[str, dict]) -> str:
    """The MIGRATION.md section: per component the sources added for its build, and the ones no feed names."""
    if not notes:
        return ""
    L = ["", "## NuGet package sources", "",
         "The packageSourceMapping of these components' NuGet.Config names sources the repository does not define "
         "(they come from the developers' and build agents' own NuGet.Config). The Dockerfile adds the ones a "
         "registered feed has a name for before restore; add them to the repository's NuGet.Config to drop that "
         f"step. See {DOCS}.", ""]
    for comp, n in sorted(notes.items()):
        L += [f"### {comp}", "", f"`{n['config']}`:", ""]
        L += [f"- `{name}`: added as {url}" for name, url in n["add"]]
        L += [f"- `{name}`: **not added**: its URL is already the source `{other}`, and NuGet uses a URL once (the "
              f"packages mapped to `{name}` are not found): map them to `{other}`" for name, other in n.get("same") or []]
        L += [f"- `{name}`: **not defined**, and no registered NuGet feed has this name: restore cannot find the "
              "packages mapped to it (add the name to the feed on Admin → Source control → Package feeds, or define "
              "the source in the repository's NuGet.Config)" for name in n["missing"]]
        L.append("")
    return "\n".join(L)
