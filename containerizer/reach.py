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


CASE_RE = re.compile(r'^[ \t]*case\s+"(?P<label>-{0,2}[\w][\w-]*)"\s*:', re.M)
DEFAULT_RE = re.compile(r"^[ \t]*default\s*:", re.M)


def _closure(seed_text: str, nodes: dict[Path, tuple[set[str], str]]) -> set[Path]:
    tokens = set(IDENT_RE.findall(seed_text))
    reached: set[Path] = set()
    changed = True
    while changed:
        changed = False
        for f, (decl, txt) in nodes.items():
            if f not in reached and decl and decl & tokens:
                reached.add(f)
                tokens |= set(IDENT_RE.findall(txt))
                changed = True
    return reached


EXT_METHOD_RE = re.compile(r"\bpublic\s+static\s+(?:async\s+)?[\w<>\[\],.? ]+?\s+([A-Z]\w*)\s*(?:<[^>]*>)?\(\s*this\s")


def _declared_strict(text: str) -> set[str]:
    """Types, plus extension methods (called without their type name). Plain static methods
    are reached through their type, and short names like Run would connect everything."""
    return set(DECL_RE.findall(text)) | set(EXT_METHOD_RE.findall(text))


def mode_reachability(comp_project, libs) -> tuple[set[Path], dict[str, set[Path]]] | None:
    """For command-line tools whose entry point dispatches on a verb (`case "--import":`),
    which code is reached by every run (shared code) and which only by one command.

    A Windows-only dependency used by one optional command does not stop the
    other commands from running in a Linux container."""
    entry = next((f for f in comp_project.files if f.name == "Program.cs" and f.parent == comp_project.dir), None)
    if entry is None:
        return None
    txt = comp_project.text(entry, True)
    cases = list(CASE_RE.finditer(txt))
    if len(cases) < 2:
        return None
    sections: dict[str, str] = {}
    cut = []
    for i, m in enumerate(cases):
        end = cases[i + 1].start() if i + 1 < len(cases) else len(txt)
        d = DEFAULT_RE.search(txt, m.end(), end)
        end = d.start() if d else end
        sections[m.group("label")] = txt[m.end():end]
        cut.append((m.start(), end))
    base = "".join(txt[a:b] for a, b in zip([0] + [e for _, e in cut], [s for s, _ in cut] + [len(txt)]))
    nodes: dict[Path, tuple[set[str], str]] = {}
    for proj in [comp_project, *libs]:
        for f in proj.files:
            if f.suffix.lower() in CODE_EXT and f != entry:
                t = proj.text(f, True)
                nodes[f] = (_declared_strict(t), t)
    # own files that declare nothing addressable (top-level code, partials) are always part of the run
    for f, (decl, t) in list(nodes.items()):
        if not decl and f.is_relative_to(comp_project.dir):
            base += "\n" + t
    shared = _closure(base, nodes)
    return shared, {label: _closure(sec, nodes) - shared for label, sec in sections.items()}
