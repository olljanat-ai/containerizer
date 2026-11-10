"""Cheap reachability analysis between a deployable and its libraries.

A library file is considered reachable from a component when one of the types
or extension methods it declares is mentioned by the component's own code or
configuration, or by another reachable library file (reachable_files has the
details). This lets a blocker in
an optional corner of a shared library (e.g. a legacy import command) stay
attached to the components that actually use it.
"""
from __future__ import annotations

import re
from pathlib import Path

DECL_RE = re.compile(r"\b(?:class|record|struct|interface|enum|delegate\s+\w+)\s+([A-Z]\w*)")
EXT_METHOD_RE = re.compile(r"\bpublic\s+static\s+(?:async\s+)?[\w<>\[\],.? ]+?\s+([A-Z]\w*)\s*(?:<[^>]*>)?\(\s*this\s")
IDENT_RE = re.compile(r"\b[A-Z]\w{2,}\b")
CODE_EXT = {".cs", ".vb", ".cshtml", ".razor", ".aspx", ".ascx", ".asax", ".master", ".svc", ".asmx"}
CFG_EXT = {".config", ".json", ".xml"}


def _extension_spans(text: str) -> list[tuple[str, int, int]] | None:
    """The extension methods of a file with the extent of each (signature and body), or None
    when one cannot be delimited (the caller then treats the file as a whole)."""
    out = []
    for m in EXT_METHOD_RE.finditer(text):
        i, depth, opened = m.end(1), 0, False
        while i < len(text):                      # the parameter list (and any generic arguments)
            ch = text[i]
            if ch == "(":
                depth, opened = depth + 1, True
            elif ch == ")":
                depth -= 1
                if opened and depth == 0:
                    break
            elif ch in "{;" and depth == 0 and not opened:
                return None
            i += 1
        else:
            return None
        body = re.compile(r"\{|=>|;").search(text, i + 1)
        if body is None:
            return None
        if body.group() == ";":                   # no body (partial/extern declaration)
            end = body.end()
        elif body.group() == "=>":
            semi = text.find(";", body.end())
            if semi < 0:
                return None
            end = semi + 1
        else:
            depth, j = 0, body.start()
            while j < len(text):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            else:
                return None
            end = j + 1
        out.append((m.group(1), m.start(), end))
    return out


def reachable_files(comp_project, libs) -> set[Path]:
    """Return the set of library source files reachable from comp_project.

    A file is reached through the types it declares or its extension methods (called without a
    type name; a plain static method is called through its type, and its bare name would match
    unrelated members such as a property of the same name). A file reached through one of its
    types brings in every name it mentions; one reached only through some of its extension
    methods brings in the names those methods mention and the rest of the file, but not the bodies
    of its other extension methods: a registration class whose AddDocuments(services) and
    AddSearchIndex(services) sit side by side does not make a component that calls only
    AddDocuments reach the index."""
    seeds = [f for f in comp_project.files if f.suffix.lower() in CODE_EXT | CFG_EXT]
    tokens: set[str] = set()
    for f in seeds:
        tokens |= set(IDENT_RE.findall(comp_project.text(f, f.suffix.lower() in CODE_EXT)))
    lib_files: dict[Path, tuple[set[str], set[str], list | None, str]] = {}
    for lib in libs:
        for f in lib.files:
            if f.suffix.lower() in CODE_EXT:
                txt = lib.text(f, True)
                spans = _extension_spans(txt) if f.suffix.lower() == ".cs" else None
                lib_files[f] = (set(DECL_RE.findall(txt)), set(EXT_METHOD_RE.findall(txt)), spans, txt)
    reached: set[Path] = set()
    whole: set[Path] = set()
    members: dict[Path, set[str]] = {}
    changed = True
    while changed:
        changed = False
        for f, (types, exts, spans, txt) in lib_files.items():
            if f in whole:
                continue
            if types & tokens or spans is None and exts & tokens:
                reached.add(f)
                whole.add(f)
                tokens |= set(IDENT_RE.findall(txt))
                changed = True
                continue
            hit = (exts & tokens) - members.get(f, set())
            if not hit:
                continue
            reached.add(f)
            got = members.setdefault(f, set())
            got |= hit
            # the file without the bodies of the extension methods not reached yet
            parts, pos = [], 0
            for name, a, b in spans:
                if name not in got and a >= pos:
                    parts.append(txt[pos:a])
                    pos = b
            parts.append(txt[pos:])
            # (its own type names are not a mention: they would bring in the whole file)
            tokens |= set(IDENT_RE.findall("".join(parts))) - types
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
