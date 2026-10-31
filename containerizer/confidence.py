"""Confidence scoring: how sure the rule set is about a component.

Each package or assembly reference that is neither known to be Linux-safe nor
explained by a finding rule is an "unknown". Unknowns, native binaries and
vendor-looking namespaces lower confidence; low confidence triggers the verify
loop and, if that cannot settle it, the AI fallback.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

from . import rules as _rules
from .rules import RULES_DIR

@lru_cache(maxsize=4)
def _catalog(key: str = "linux_ok"):
    ok, neutral = [], []
    rd = _rules.reviewed_dir()            # approved in the rule review (internal rules repository)
    learned = (sorted(rd.glob("packages*.yaml")) if rd else []) + [_rules.LEARNED_DIR / "packages.yaml"]
    for f in sorted(RULES_DIR.glob("packages*.yaml")) + learned:
        if f.exists():
            d = yaml.safe_load(f.read_text()) or {}
            ok += d.get(key, []) or []
            if key != "linux_ok" and f in learned:
                # packages proven by a verify run (or approved in the rule review) are listed under
                # linux_ok whatever their ecosystem; Java and npm names cannot collide with NuGet ids
                ok += [x for x in d.get("linux_ok", []) or [] if (":" in x) == (key == "java_ok")]
            neutral += d.get("neutral_references", []) or [] if key == "linux_ok" else []
    return (re.compile("^(?:" + "|".join(ok) + ")$", re.I) if ok else None,
            re.compile("^(?:" + "|".join(neutral) + ")$", re.I) if neutral else None)


def reset_cache():
    _catalog.cache_clear()


# native addons that build at install time; a package not in node_ok is an unknown
NODE_NATIVE = {"bcrypt", "sqlite3", "better-sqlite3", "canvas", "argon2", "re2", "libxmljs", "libxmljs2", "kerberos",
               "node-pty", "serialport", "usb", "leveldown", "classic-level", "grpc", "zeromq", "cpu-features", "ssh2",
               "deasync", "fibers", "iconv", "ref-napi", "ffi-napi", "sharp", "node-sass", "edge-js", "winax",
               "msnodesqlv8", "oracledb", "pg-native", "isolated-vm", "node-expose-sspi", "node-sspi"}


def _jvm_node_unknowns(p) -> list[str]:
    """Java: runtime dependencies the catalog does not know (a pure-Java library is portable, but
    an unknown one may wrap native code). Node: native addons and Windows-only packages the catalog
    does not know; pure JavaScript packages are portable and do not count."""
    if p.kind_hint == "java":
        ok, _ = _catalog("java_ok")
        own = set((p.properties.get("InRepoDeps") or "").split(","))       # modules of this repository
        return [f"package:{n}" for n in p.packages
                if n not in p.dev_packages and n not in own and (ok is None or not ok.match(n))]
    ok, _ = _catalog("node_ok")
    props = p.properties or {}
    native = {x for x in (props.get("LockNativeBuild") or "").split(",") if x}
    native |= {n for n in p.packages if n in NODE_NATIVE and n not in p.dev_packages}
    out = [f"package:{n}" for n in sorted(native) if ok is None or not ok.match(n)]
    out += [f"package:{n}" for n in sorted(x for x in (props.get("LockWindowsOnly") or "").split(",") if x)]
    return list(dict.fromkeys(out))


def unknowns(comp) -> list[str]:
    p = comp.project
    if p.kind_hint in ("java", "node"):
        return _jvm_node_unknowns(p)
    ok, neutral = _catalog()
    out = []
    if p.kind_hint != "dotnet":
        return out
    for name in p.packages:
        if ok is None or not ok.match(name):
            out.append(f"package:{name}")
    for ref in p.references:
        if ref.startswith("COM:"):
            continue  # always covered by com-interop rule
        # old-style projects reference NuGet assemblies by name (HintPath), so the package catalog applies too
        if (neutral is None or not neutral.match(ref)) and (ok is None or not ok.match(ref)):
            out.append(f"reference:{ref}")
    for f in p.files:
        if f.suffix.lower() in (".dll", ".ocx", ".exe") and "packages" not in f.parts:
            out.append(f"binary:{f.name}")
    return out


def score_confidence(repo, comp) -> None:
    u = unknowns(comp)
    # unknowns that a finding already explains do not count
    explained = set()
    for f in comp.findings:
        for e in f.evidence:
            s = str(e)
            for x in u:
                if x.split(":", 1)[1] in s:
                    explained.add(x)
    u = [x for x in u if x not in explained]
    comp.uncertain = u
    conf = 1.0 - 0.1 * len(u)
    # a decisive finding from a rule that is itself unsure caps the confidence
    for f in comp.findings:
        if f.severity in ("blocker", "rewrite"):
            conf = min(conf, f.rule.confidence)
    if comp.role == "library" and not comp.project.files:
        conf -= 0.2
    comp.confidence = max(0.2, round(conf, 2))
