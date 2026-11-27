"""The code browser of a refactoring order (docs/refactoring.md#browse-the-code): the application's files at the
assessed commit and with the patch applied, kept with the order so the page works after the clone moved on.

The queue runner makes a *snapshot* when an order has a patch (`build`, from a scratch copy whose HEAD is the
patched commit and HEAD~1 the assessed one): a zip with `index.json` (every file of the application's folder: path,
sizes, how the patch changes it, whether its text is kept), `o/<path>` (the text as assessed) and `n/<path>` (the
text with the patch, for the files it adds or changes). Binary files, files over MAX_FILE and whatever comes after
MAX_TOTAL are listed without their text; the files the patch changes are kept first. The runner stores the zip
in cz.LlmJobSource in parts (`store`), newest KEEP per application; the admin site reads it (`load`) and renders
the tree, a file, both sides next to each other, or the raw text.

Nothing here writes to the application's repository, and the snapshot holds source code: it is shown to the roles
that see the patch (admin_refactor.route).
"""
from __future__ import annotations

import difflib
import io
import json
import posixpath
import subprocess
import threading
import urllib.parse
import zipfile
from html import escape as e
from pathlib import Path

MAX_FILE = 512 * 1024              # a file's text is kept up to this size
MAX_TOTAL = 64 * 1024 * 1024       # the texts kept, together (before compression)
MAX_ENTRIES = 30000                # files listed
MAX_ZIP = 24 * 1024 * 1024         # the snapshot itself; over this it is made again with half the texts
PART = 512 * 1024                  # bytes per row of cz.LlmJobSource
KEEP = 3                           # snapshots kept per application (the newest orders')
MAX_DIFF_LINES = 20000             # a longer file is shown without marking its changed lines
WHY = {"binary": "a binary file", "large": f"larger than {MAX_FILE // 1024} KiB", "limit": "over the snapshot's size limit",
       "link": "a symbolic link", "module": "a git submodule"}


# --------------------------------------------------------------------------- the snapshot (queue runner)

def _git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    p = subprocess.run(["git", "-c", f"safe.directory={repo}", "-c", "core.quotepath=off", *args], cwd=repo, input=data,
                       capture_output=True, check=False)
    if p.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {p.stderr.decode(errors='replace')[:300]}")
    return p.stdout


def _tree(repo: Path, rev: str, sub: str) -> dict[str, tuple[str, str, int]]:
    """path (relative to the application's folder) -> (mode, blob id, size) of a commit's files there."""
    out = {}
    raw = _git(repo, "ls-tree", "-r", "-l", "-z", rev, *(["--", sub] if sub else []))
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, kind, sha, size = meta.decode().split()
        p = path.decode("utf-8", errors="replace")
        p = p[len(sub) + 1:] if sub else p
        out[p] = (mode if kind == "blob" else "module", sha, int(size) if size.isdigit() else 0)
    return out


def _blobs(repo: Path, shas: list[str]) -> dict[str, bytes]:
    """The contents of blobs, in one git process."""
    if not shas:
        return {}
    raw = _git(repo, "cat-file", "--batch", data=("\n".join(shas) + "\n").encode())
    out, i = {}, 0
    for sha in shas:
        nl = raw.index(b"\n", i)
        head = raw[i:nl].split()
        if len(head) != 3:                      # "<id> missing"
            i = nl + 1
            continue
        n = int(head[2])
        out[sha] = raw[nl + 1:nl + 1 + n]
        i = nl + 1 + n + 1
    return out


def build(repo: Path, app: Path, total: int = MAX_TOTAL) -> bytes | None:
    """The snapshot of a scratch repository whose HEAD is the patched commit and HEAD~1 the assessed one, for the
    application's folder `app`. None when there is nothing to show."""
    repo, app = Path(repo).resolve(), Path(app).resolve()
    sub = "" if app == repo else app.relative_to(repo).as_posix()
    old, new = _tree(repo, "HEAD~1", sub), _tree(repo, "HEAD", sub)
    paths = sorted(set(old) | set(new))
    if not paths:
        return None

    def status(p: str) -> str:
        if p not in old:
            return "A"
        if p not in new:
            return "D"
        return "M" if old[p][1] != new[p][1] else ""
    changed = [p for p in paths if status(p)]
    order = changed + [p for p in paths if not status(p)]          # the patch's files are kept first
    listed = set(order[:MAX_ENTRIES])
    files, want, used = [], [], 0
    for p in order[:MAX_ENTRIES]:
        st = status(p)
        ent = {"p": p, "st": st}
        for side, tree in (("o", old), ("n", new)):
            if p not in tree or (side == "n" and not st):
                continue
            mode, sha, size = tree[p]
            ent["s" if side == "o" else "ns"] = size
            why = "module" if mode == "module" else "link" if mode == "120000" else "large" if size > MAX_FILE else \
                "limit" if used + size > total else ""
            if why:
                ent["why" if side == "o" else "nwhy"] = why
            else:
                used += size
                want.append((side, p, sha, ent))
        files.append(ent)
    blobs = _blobs(repo, sorted({sha for _, _, sha, _ in want}))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for side, p, sha, ent in want:
            data = blobs.get(sha)
            if data is None or b"\0" in data[:8000]:
                ent["why" if side == "o" else "nwhy"] = "binary"
                continue
            z.writestr(f"{side}/{p}", data)
        files.sort(key=lambda f: f["p"])
        z.writestr("index.json", json.dumps({"v": 1, "root": sub, "files": files, "more": len(paths) - len(listed)},
                                            separators=(",", ":")))
    data = buf.getvalue()
    if len(data) > MAX_ZIP and total > 1024 * 1024:
        return build(repo, app, total // 2)
    return data


def store(conn, job_id: int, application_id: int | None, data: bytes) -> None:
    """The snapshot of an order in cz.LlmJobSource (in parts), and only the newest KEEP per application kept."""
    cur = conn.cursor()
    cur.execute("DELETE FROM cz.LlmJobSource WHERE JobId = %s", (int(job_id),))
    for i in range(0, len(data), PART):
        cur.execute("INSERT cz.LlmJobSource (JobId, Seq, ApplicationId, Data) VALUES (%s, %s, %s, %s)",
                    (int(job_id), i // PART, application_id, data[i:i + PART]))
    if application_id is not None:
        cur.execute("DELETE FROM cz.LlmJobSource WHERE ApplicationId = %s AND JobId NOT IN (SELECT TOP (%s) JobId FROM "
                    "(SELECT DISTINCT JobId FROM cz.LlmJobSource WHERE ApplicationId = %s) x ORDER BY JobId DESC)",
                    (int(application_id), KEEP, int(application_id)))


# --------------------------------------------------------------------------- reading (admin site)

class Snapshot:
    def __init__(self, data: bytes):
        self.zip = zipfile.ZipFile(io.BytesIO(data))
        idx = json.loads(self.zip.read("index.json"))
        self.root = idx.get("root") or ""
        self.more = int(idx.get("more") or 0)
        self.files = {f["p"]: f for f in idx["files"]}
        self._lock = threading.Lock()

    def has(self, path: str, side: str) -> bool:
        f = self.files.get(path)
        return bool(f) and not (side == "patched" and f["st"] == "D") and not (side == "original" and f["st"] == "A")

    def paths(self, side: str) -> list[str]:
        return [p for p in self.files if self.has(p, side)]

    def size(self, path: str, side: str) -> int:
        f = self.files[path]
        return int(f.get("ns", f.get("s", 0)) if side == "patched" and f["st"] else f.get("s", 0))

    def why(self, path: str, side: str) -> str:
        """Why the file's text is not kept ("" when it is)."""
        f = self.files[path]
        return f.get("nwhy", "") if side == "patched" and f["st"] else f.get("why", "")

    def text(self, path: str, side: str) -> str | None:
        """The file's text on a side (None: not on that side, or not kept)."""
        if not self.has(path, side) or self.why(path, side):
            return None
        name = ("n/" if side == "patched" and self.files[path]["st"] else "o/") + path
        try:
            with self._lock:
                raw = self.zip.read(name)
        except KeyError:
            return None
        return raw.decode("utf-8-sig", errors="replace")


_CACHE: dict[int, Snapshot] = {}
_CACHE_LOCK = threading.Lock()


def exists(conn, job_id: int) -> bool:
    try:
        cur = conn.cursor()
        cur.execute("SELECT TOP (1) 1 FROM cz.LlmJobSource WHERE JobId = %s", (int(job_id),))
        return cur.fetchone() is not None
    except Exception:  # noqa: BLE001      a database from before schema 64
        return False


def load(conn, job_id: int) -> Snapshot | None:
    """An order's snapshot (the last few stay in memory: a snapshot never changes), or None."""
    with _CACHE_LOCK:
        if job_id in _CACHE:
            return _CACHE[job_id]
    try:
        cur = conn.cursor()
        cur.execute("SELECT Data FROM cz.LlmJobSource WHERE JobId = %s ORDER BY Seq", (int(job_id),))
        parts = [bytes(r[0] if not isinstance(r, dict) else r["Data"]) for r in cur.fetchall()]
    except Exception:  # noqa: BLE001      a database from before schema 64
        return None
    if not parts:
        return None
    try:
        snap = Snapshot(b"".join(parts))
    except (zipfile.BadZipFile, KeyError, ValueError):
        return None
    with _CACHE_LOCK:
        _CACHE[job_id] = snap
        while len(_CACHE) > 3:
            _CACHE.pop(next(iter(_CACHE)))
    return snap


# --------------------------------------------------------------------------- the page

def clean_path(raw: str) -> str:
    """A path of the request as the snapshot names them ("" for the top folder; no "..")."""
    p = posixpath.normpath("/" + (raw or "").replace("\\", "/")).lstrip("/")
    return "" if p in (".", "") else p


def _url(base: str, **q) -> str:
    q = {k: v for k, v in q.items() if v not in (None, "", False)}
    return base + ("?" + urllib.parse.urlencode(q) if q else "")


def _mark(st: str) -> str:
    title = {"A": "added by the patch", "M": "changed by the patch", "D": "removed by the patch"}.get(st, "")
    return f"<span class='cb-st cb-{st}' title='{title}'>{st}</span>" if st else ""


def _dir_status(snap: Snapshot, d: str) -> str:
    return "M" if any(f["st"] and p.startswith(d + "/") for p, f in snap.files.items()) else ""


def _children(paths: list[str], d: str) -> tuple[list[str], list[str]]:
    """(folders, files) directly in folder `d`."""
    pre = d + "/" if d else ""
    dirs, files = set(), []
    for p in paths:
        if not p.startswith(pre):
            continue
        rest = p[len(pre):]
        if "/" in rest:
            dirs.add(pre + rest.split("/", 1)[0])
        else:
            files.append(p)
    return sorted(dirs, key=str.casefold), sorted(files, key=str.casefold)


def tree_html(snap: Snapshot, base: str, side: str, current: str, changed_only: bool) -> str:
    """The folder tree: the folders on the way to `current` are open, the others are links that open them."""
    paths = snap.paths(side)
    link = lambda p: _url(base, path=p, side=side if side != "patched" else None, changed=changed_only and "1")  # noqa: E731
    if changed_only:
        rows = [f"<a class='cb-row{' on' if p == current else ''}' href='{e(link(p))}'>{e(p)}{_mark(snap.files[p]['st'])}</a>"
                for p in sorted((p for p in snap.files if snap.files[p]["st"]), key=str.casefold)]
        return "".join(rows) or "<p class='muted small'>The patch changes no file here.</p>"
    out: list[str] = []

    def walk(d: str, depth: int) -> None:
        dirs, files = _children(paths, d)
        pad = f"style='padding-left:{12 + depth * 14}px'"
        for x in dirs:
            is_open = current == x or current.startswith(x + "/")
            out.append(f"<a class='cb-row cb-dir{' on' if current == x else ''}' {pad} href='{e(link(x))}'>"
                       f"{'▾' if is_open else '▸'} {e(posixpath.basename(x))}{_mark(_dir_status(snap, x))}</a>")
            if is_open:
                walk(x, depth + 1)
        for p in files:
            out.append(f"<a class='cb-row{' on' if p == current else ''}' {pad} href='{e(link(p))}'>"
                       f"{e(posixpath.basename(p))}{_mark(snap.files[p]['st'])}</a>")
    walk("", 0)
    return "".join(out)


def crumbs_html(base: str, side: str, app: str, path: str, changed_only: bool) -> str:
    q = {"side": side if side != "patched" else None, "changed": changed_only and "1"}
    out = [f"<a href='{e(_url(base, **q))}'>{e(app or 'application')}</a>"]
    parts = path.split("/") if path else []
    for i, part in enumerate(parts):
        p = "/".join(parts[:i + 1])
        out.append(f"<b>{e(part)}</b>" if i == len(parts) - 1 else f"<a href='{e(_url(base, path=p, **q))}'>{e(part)}</a>")
    return " / ".join(out)


def _rows(lines: list[tuple[str, int, str]]) -> str:
    return "".join(f"<tr class='{k}'><td class='ln' id='L{n}'>{n}</td><td>{e(t)}</td></tr>" for k, n, t in lines)


def file_html(snap: Snapshot, path: str, side: str) -> str:
    """One file on one side, its lines numbered; the lines the patch adds (patched) or removes (original) marked."""
    text = snap.text(path, side)
    if text is None:
        return (f"<p class='muted cb-none'>The text of this file is not kept: {e(WHY.get(snap.why(path, side), 'not kept'))}"
                f" ({snap.size(path, side):,} bytes).</p>")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    marked: set[int] = set()
    st = snap.files[path]["st"]
    if st == "M" and len(lines) <= MAX_DIFF_LINES:
        other = snap.text(path, "original" if side == "patched" else "patched")
        if other is not None:
            o = other.split("\n")
            a, b = (o, lines) if side == "patched" else (lines, o)
            for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
                if tag != "equal":
                    marked.update(range(j1, j2) if side == "patched" else range(i1, i2))
    elif st in ("A", "D"):
        marked = set(range(len(lines)))
    kind = "add" if side == "patched" else "del"
    return ("<table class='diff cb-code'><tbody>"
            + _rows([(kind if i in marked else "ctx", i + 1, t.rstrip("\r")) for i, t in enumerate(lines)])
            + "</tbody></table>")


def split_html(snap: Snapshot, path: str) -> str:
    """Both sides of a file next to each other, the lines aligned."""
    old = snap.text(path, "original") if snap.has(path, "original") else ""
    new = snap.text(path, "patched") if snap.has(path, "patched") else ""
    if old is None or new is None:
        return "<p class='muted cb-none'>The text of this file is not kept on both sides.</p>"
    a, b = old.split("\n"), new.split("\n")
    for x in (a, b):
        if x and x[-1] == "":
            x.pop()
    if len(a) + len(b) > 2 * MAX_DIFF_LINES:
        return "<p class='muted cb-none'>The file is too long to show both sides next to each other.</p>"
    rows = []

    def cell(kind: str, n, t) -> str:
        return (f"<td class='ln {kind}'>{'' if n is None else n}</td>"
                f"<td class='{kind}'>{'' if t is None else e(t.rstrip(chr(13)))}</td>")
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            rows += [f"<tr>{cell('ctx', i1 + k + 1, a[i1 + k])}{cell('ctx', j1 + k + 1, b[j1 + k])}</tr>" for k in range(i2 - i1)]
            continue
        for k in range(max(i2 - i1, j2 - j1)):
            left = cell("del", i1 + k + 1, a[i1 + k]) if i1 + k < i2 else cell("pad", None, None)
            right = cell("add", j1 + k + 1, b[j1 + k]) if j1 + k < j2 else cell("pad", None, None)
            rows.append(f"<tr>{left}{right}</tr>")
    return ("<table class='diff cb-code cb-split'><thead><tr><th colspan='2'>Original</th><th colspan='2'>Patched</th></tr>"
            f"</thead><tbody>{''.join(rows)}</tbody></table>")


def folder_html(snap: Snapshot, base: str, side: str, d: str, changed_only: bool) -> str:
    dirs, files = _children(snap.paths(side), d)
    q = {"side": side if side != "patched" else None, "changed": changed_only and "1"}
    rows = [f"<tr><td>📁 <a href='{e(_url(base, path=x, **q))}'>{e(posixpath.basename(x))}</a></td><td></td>"
            f"<td>{_mark(_dir_status(snap, x))}</td></tr>" for x in dirs]
    rows += [f"<tr><td><a href='{e(_url(base, path=p, **q))}'>{e(posixpath.basename(p))}</a></td>"
             f"<td class='num muted small'>{snap.size(p, side):,}</td><td>{_mark(snap.files[p]['st'])}</td></tr>" for p in files]
    if not rows:
        return "<p class='muted cb-none'>No such folder on this side.</p>"
    return f"<table class='cb-list'><thead><tr><th>Name</th><th class='num'>Bytes</th><th></th></tr></thead><tbody>{''.join(rows)}</tbody></table>"


def find_html(snap: Snapshot, base: str, side: str, text: str) -> str:
    needle = text.casefold()
    hits = [p for p in sorted(snap.paths(side), key=str.casefold) if needle in p.casefold()][:200]
    if not hits:
        return f"<p class='muted cb-none'>No file name contains “{e(text)}”.</p>"
    q = {"side": side if side != "patched" else None}
    return ("<table class='cb-list'><tbody>" + "".join(
        f"<tr><td><a href='{e(_url(base, path=p, **q))}'>{e(p)}</a></td><td>{_mark(snap.files[p]['st'])}</td></tr>" for p in hits)
        + "</tbody></table>" + ("<p class='muted small'>The first 200 are shown.</p>" if len(hits) == 200 else ""))


def page_html(snap: Snapshot, base: str, app: str, q: dict) -> str:
    """The browser: the side switch, the path, the tree and the folder or file. `q`: the request's parameters."""
    get = lambda k: (q.get(k) or [""])[0]  # noqa: E731
    side = "original" if get("side") == "original" else "patched"
    view = get("view") if get("view") in ("split",) else "file"
    changed_only = get("changed") == "1"
    path, find = clean_path(get("path")), get("find").strip()[:200]
    is_file = path in snap.files
    if is_file and not snap.has(path, side):           # the file is only on the other side: show it there
        side = "original" if side == "patched" else "patched"
    keep = {"path": path, "changed": changed_only and "1", "view": view if view != "file" else None}
    seg = lambda label, on, **kw: f"<a class='{'on' if on else ''}' href='{e(_url(base, **{**keep, **kw}))}'>{label}</a>"  # noqa: E731
    sides = (f"<span class='cb-seg'>{seg('Original', side == 'original', side='original')}"
             f"{seg('Patched', side == 'patched', side=None)}</span>")
    form = (f"<form class='cb-find' method='get' action='{e(base)}'>"
            + (f"<input type='hidden' name='side' value='original'>" if side == "original" else "")
            + f"<input name='find' value='{e(find)}' placeholder='Go to file…' aria-label='Go to file'></form>"
            f"<a class='small' href='{e(_url(base, path=path, side=side if side != 'patched' else None, changed=None if changed_only else '1'))}'>"
            f"{'☑' if changed_only else '☐'} changed files only</a>")
    bar = (f"<div class='cb-bar'>{sides}<span class='cb-path'>{crumbs_html(base, side, app, path, changed_only)}</span>"
           f"<span class='cb-right'>{form}</span></div>")
    if find:
        head, main = f"Files named like “{e(find)}”", find_html(snap, base, side, find)
    elif is_file:
        f = snap.files[path]
        st = f["st"]
        views = ""
        if st == "M":
            sq = {"side": side if side != "patched" else None}
            views = (f"<span class='cb-seg'>{seg('File', view == 'file', view=None, **sq)}"
                     f"{seg('Side by side', view == 'split', view='split', **sq)}</span> ")
        raw = _url(base, path=path, side=side if side != "patched" else None, raw="1")
        head = (f"<span>{e(posixpath.basename(path))} {_mark(st)} <span class='muted small'>{snap.size(path, side):,} bytes"
                f" · {side}</span></span><span>{views}<a class='small' href='{e(raw)}'>Raw</a></span>")
        main = split_html(snap, path) if view == "split" and st == "M" else file_html(snap, path, side)
    else:
        head, main = e(path or "/"), folder_html(snap, base, side, path, changed_only)
    note = (f"<p class='muted small'>The application's folder{' <code>' + e(snap.root) + '</code>' if snap.root else ''} at "
            "the assessed commit, with the patch or without it. A, M and D mark what the patch adds, changes and removes."
            + (f" {snap.more:,} more files are not listed." if snap.more else "") + "</p>")
    return (f"{bar}<div class='cb'><nav class='cb-tree'>{tree_html(snap, base, side, path, changed_only)}</nav>"
            f"<div class='cb-main'><div class='cb-head'>{head}</div>{main}</div></div>{note}")
