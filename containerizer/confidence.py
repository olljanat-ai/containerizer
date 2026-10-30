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

from .rules import RULES_DIR

@lru_cache(maxsize=1)
def _catalog():
    ok, neutral = [], []
    for f in [RULES_DIR / "packages.yaml", RULES_DIR / "learned" / "packages.yaml"]:
        if f.exists():
            d = yaml.safe_load(f.read_text()) or {}
            ok += d.get("linux_ok", []) or []
            neutral += d.get("neutral_references", []) or []
    return (re.compile("^(?:" + "|".join(ok) + ")$", re.I) if ok else None,
            re.compile("^(?:" + "|".join(neutral) + ")$", re.I) if neutral else None)


def reset_cache():
    _catalog.cache_clear()


def unknowns(comp) -> list[str]:
    p = comp.project
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
        if neutral is None or not neutral.match(ref):
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
    if comp.role == "library" and not comp.project.files:
        conf -= 0.2
    comp.confidence = max(0.2, round(conf, 2))
