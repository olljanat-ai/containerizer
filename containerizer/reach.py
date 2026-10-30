"""Cheap reachability analysis between a deployable and its libraries.

A library file is considered reachable from a component when one of the types
or public static methods it declares is mentioned by the component's own code
or configuration, or by another reachable library file. This lets a blocker in
an optional corner of a shared library (e.g. a legacy import command) stay
attached to the components that actually use it.
"""
from __future__ import annotations

import re
from pathlib import Path

DECL_RE = re.compile(r"\b(?:class|record|struct|interface|enum|delegate\s+\w+)\s+([A-Z]\w*)")
STATIC_METHOD_RE = re.compile(r"\bpublic\s+static\s+(?:async\s+)?[\w<>\[\],.? ]+?\s+([A-Z]\w*)\s*[<(]")
IDENT_RE = re.compile(r"\b[A-Z]\w{2,}\b")
CODE_EXT = {".cs", ".vb", ".cshtml", ".razor", ".aspx", ".ascx", ".asax", ".master", ".svc", ".asmx"}
CFG_EXT = {".config", ".json", ".xml"}


def _declared(text: str) -> set[str]:
    return set(DECL_RE.findall(text)) | set(STATIC_METHOD_RE.findall(text))


def reachable_files(comp_project, libs) -> set[Path]:
    """Return the set of library source files reachable from comp_project."""
    seeds = [f for f in comp_project.files if f.suffix.lower() in CODE_EXT | CFG_EXT]
    tokens: set[str] = set()
    for f in seeds:
        tokens |= set(IDENT_RE.findall(comp_project.text(f, f.suffix.lower() in CODE_EXT)))
    lib_files: dict[Path, tuple[set[str], object]] = {}
    for lib in libs:
        for f in lib.files:
            if f.suffix.lower() in CODE_EXT:
                txt = lib.text(f, True)
                lib_files[f] = (_declared(txt), lib)
    reached: set[Path] = set()
    changed = True
    while changed:
        changed = False
        for f, (decl, lib) in lib_files.items():
            if f in reached or not decl:
                continue
            if decl & tokens:
                reached.add(f)
                tokens |= set(IDENT_RE.findall(lib.text(f, True)))
                changed = True
    return reached
