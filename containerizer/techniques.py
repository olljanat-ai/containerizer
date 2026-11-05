"""Platform techniques: configuration that lets unchanged code pass a finding.

A plan rule (rules/40-plan.yaml) with `resolves: [finding ids]` names findings that the generated container and
manifests satisfy without touching the application: a pod `hostname:`, a certificate mounted where .NET's
X509Store looks for it, a volume at the folder a Windows-only path turns into on Linux. When such a rule applies
to a component, its findings are marked `resolved_by` the rule (assess.Finding), count as `config` in the rating,
and the generator applies the rule's plan patch and records its reason in plan.json and the Dockerfile header.

A rule can name a `technique` (a function here) when the patch depends on the code: it gets the findings and
returns the plan patch, or None when the code does something configuration cannot reach (the finding then stays
as it is).
"""
from __future__ import annotations

import re
from .rules import Context, Rule, run_rule

def _evidence_texts(repo, findings) -> list[tuple[str, str]]:
    """(file, text) of every file a finding has evidence in."""
    out, seen = [], set()
    for f in findings:
        for e in f.evidence:
            rel = getattr(e, "file", "")
            if not rel or rel in seen:
                continue
            seen.add(rel)
            p = repo.root / rel
            if p.is_file():
                try:
                    out.append((rel, p.read_text(errors="replace")))
                except OSError:
                    pass
    return out


# ------------------------------------------------------------------ machine name

_MN = r"Environment\.MachineName"
_MN_RX = [
    # Environment.MachineName[.ToUpper()] == "X"   /   "X" == Environment.MachineName
    re.compile(_MN + r"(?P<fold>\.To(Upper|Lower)(Invariant)?\(\))?\s*(==|!=)\s*@?\"(?P<name>[^\"]*)\""),
    re.compile(r"@?\"(?P<name>[^\"]*)\"\s*(==|!=)\s*" + _MN + r"(?P<fold>\.To(Upper|Lower)(Invariant)?\(\))?"),
    # Environment.MachineName.Equals("X"[, StringComparison.OrdinalIgnoreCase]) / StartsWith / EndsWith / Contains
    re.compile(_MN + r"(?P<fold>\.To(Upper|Lower)(Invariant)?\(\))?\.(?P<op>Equals|StartsWith|EndsWith|Contains)"
               r"\(\s*@?\"(?P<name>[^\"]*)\"(?P<rest>[^)]*)\)"),
    re.compile(r"Equals\(\s*" + _MN + r"\s*,\s*@?\"(?P<name>[^\"]*)\"(?P<rest>[^)]*)\)"),
]
_MN_SWITCH = re.compile(r"switch\s*\(\s*" + _MN + r"(?P<fold>\.To(Upper|Lower)(Invariant)?\(\))?\s*\)\s*\{")
_CASE = re.compile(r"\bcase\s+@?\"(?P<name>[^\"]*)\"\s*:")
_DNS_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_PROD = re.compile(r"prod|prd|live|\bp\d|-p\d", re.I)


def machine_names(texts: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """Host names the code compares Environment.MachineName with, as a pod can carry them, and the names it
    cannot: Kubernetes host names are lower-case DNS labels, so a case-sensitive comparison with an upper-case
    name ("PRODWEB01") can never match in a pod."""
    ok, bad = [], []

    def take(name: str, folded: bool):
        target = name.lower() if (folded or name == name.lower()) else None
        if target is not None and _DNS_LABEL.fullmatch(target):
            ok.append(target)
        else:
            bad.append(name)

    for _, txt in texts:
        for rx in _MN_RX:
            for m in rx.finditer(txt):
                gd = m.groupdict()
                folded = bool(gd.get("fold")) or "IgnoreCase" in (gd.get("rest") or "")
                # StartsWith/EndsWith/Contains("X"): a host name that is exactly X matches too
                take(gd["name"], folded)
        for m in _MN_SWITCH.finditer(txt):
            end = txt.find("}", m.end())
            body = txt[m.end(): end if end > 0 else m.end() + 4000]
            for cm in _CASE.finditer(body):
                take(cm.group("name"), bool(m.group("fold")))
    dedup = lambda xs: list(dict.fromkeys(xs))   # noqa: E731
    return dedup(ok), dedup(bad)


def technique_machine_hostname(repo, c, findings) -> dict | None:
    names, bad = machine_names(_evidence_texts(repo, findings))
    if not names:
        return None
    # the production host when one is recognizable by name, else the first one the code knows
    pick = next((n for n in names if _PROD.search(n)), names[0])
    others = [n for n in names if n != pick]
    note = f"The pod's host name is set to \"{pick}\""
    if others:
        note += f" (the code also knows {', '.join(repr(n) for n in others)}: set hostname to the one of this environment)"
    if bad:
        note += (f"; case-sensitive comparisons with {', '.join(repr(b) for b in bad)} cannot match a Kubernetes host "
                 "name (lower-case only)")
    return {"hostname": pick, "_note": note + "."}


# ------------------------------------------------------------------ certificate store

_LOCAL_MACHINE = re.compile(r"StoreLocation\.LocalMachine|\"(Store)?Location\"\s*:\s*\"LocalMachine\"|"
                            r"storeLocation\s*=\s*\"LocalMachine\"")


def technique_x509_user_store(repo, c, findings) -> dict | None:
    """CurrentUser stores are folders of .pfx files under HOME on Linux: the store gets an (optional) Secret
    mounted there. LocalMachine\\My does not exist on Linux (cert-store-localmachine-code), so a store opened in
    LocalMachine (outside an OS check) is out of reach."""
    if any(f.rule.id == "cert-store-localmachine-code" and not f.dormant for f in c.findings):
        return None
    for _, txt in _evidence_texts(repo, findings):
        if _LOCAL_MACHINE.search(txt) and not re.search(r"StoreName\.(Root|CertificateAuthority)", txt):
            return None
    return {"x509_stores": ["my"]}


# ------------------------------------------------------------------ Windows special folders

_WIN_FOLDERS = (r"ProgramFiles|ProgramFilesX86|CommonProgramFiles|CommonProgramFilesX86|Windows|System|SystemX86|"
                r"AdminTools|CommonAdminTools|StartMenu|CommonStartMenu|Programs|CommonPrograms|Startup|"
                r"CommonStartup|SendTo|Recent|Cookies|History|InternetCache|Resources|LocalizedResources|"
                r"CDBurning|PrinterShortcuts|NetworkShortcuts")
_GFP = r"(?:Environment\.)?GetFolderPath\(\s*(?:System\.)?(?:Environment\.)?SpecialFolder\.(?:" + _WIN_FOLDERS + r")\s*\)"
_COMBINE = re.compile(r"Path\.Combine\(\s*" + _GFP + r"\s*,\s*@?\"(?P<first>[^\"]*)\"")
_ANY = re.compile(r"SpecialFolder\.(?:" + _WIN_FOLDERS + r")\b")
_SAFE_SEG = re.compile(r"[A-Za-z0-9][\w .-]{0,62}")


def special_folder_dirs(texts: list[tuple[str, str]]) -> tuple[list[str], int]:
    """First folder names that Path.Combine(GetFolderPath(<Windows folder>), "Name", ...) puts under the working
    directory on Linux (GetFolderPath returns "" there), and how many uses could not be resolved (the folder kept
    in a variable, joined with "\\", a file name directly under it)."""
    dirs, unresolved = [], 0
    for _, txt in texts:
        total = len(_ANY.findall(txt))
        found = 0
        for m in _COMBINE.finditer(txt):
            first = m.group("first")
            tail = txt[m.end(): m.end() + 1].strip()
            if "\\" in first or "/" in first or not _SAFE_SEG.fullmatch(first):
                continue
            # "Name" must be a folder: another argument follows, or it has no extension
            if tail != "," and re.search(r"\.[A-Za-z]\w{0,7}$", first):
                continue
            found += 1
            dirs.append(first)
        unresolved += max(0, total - found)
    return list(dict.fromkeys(dirs)), unresolved


def technique_special_folder_workdir(repo, c, findings) -> dict | None:
    from .generate import APP_DIR
    dirs, unresolved = special_folder_dirs(_evidence_texts(repo, findings))
    if not dirs or unresolved:
        return None
    pdir = c.project.dir
    # a folder that ships with the app would be hidden by a mount; leave those to the code change
    if any((pdir / d).exists() for d in dirs):
        return None
    mounts = [f"{APP_DIR}/{d}" for d in dirs]
    return {"add_writable": mounts,
            "_note": "Folders mounted: " + ", ".join(mounts) + " (put the files the app expects there, e.g. from a "
                     "ConfigMap or an init container)."}


TECHNIQUES = {
    "machine-hostname": technique_machine_hostname,
    "x509-user-store": technique_x509_user_store,
    "special-folder-workdir": technique_special_folder_workdir,
}


# ------------------------------------------------------------------ resolution

def technique_patch(r: Rule, repo, c) -> dict | None:
    """The plan patch of a `resolves` rule for this component, or None when it does not apply: none of the
    findings it resolves is active, its `when` does not match, or its technique cannot reach the code."""
    if not r.resolves:
        return None
    findings = [f for f in c.findings if f.rule.id in r.resolves and not f.dormant]
    if not findings:
        return None
    if r.when and not run_rule(r, Context(repo, None if r.scope == "repo" else c.project, c.role)):
        return None
    patch = dict(r.plan or {})
    if r.technique:
        fn = TECHNIQUES.get(r.technique)
        if fn is None:
            raise ValueError(f"rule {r.id}: unknown technique {r.technique}")
        extra = fn(repo, c, findings)
        if extra is None:
            return None
        for k, v in extra.items():
            if isinstance(v, list):
                patch[k] = list(patch.get(k) or []) + [x for x in v if x not in (patch.get(k) or [])]
            else:
                patch[k] = v
    return patch


def resolve_findings(repo, c, rules: list[Rule]) -> None:
    """Mark the component's findings that a platform technique satisfies (Finding.resolved_by)."""
    for r in rules:
        if r.phase != "plan" or not r.resolves:
            continue
        if technique_patch(r, repo, c) is None:
            continue
        for f in c.findings:
            if f.rule.id in r.resolves and not f.dormant and not f.resolved_by:
                f.resolved_by = r.id
