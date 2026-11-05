"""The lab SQL Server database of an app set up from the repository's own SQL scripts (docs/lab-services.md).

In production a DBA runs an app's setup scripts (the lab's expense-claims: db/01-create-database.sql ...
04-reference-data.sql, run by deploy/install-database.ps1 with Invoke-Sqlcmd); the lab gives each app an empty
database, so an app that does not create its tables itself fails there (Quartz: "Invalid object name
'quartz.QRTZ_JOB_DETAILS'").

- The scan (generate.py, when the app uses the lab's SQL Server) finds the scripts: in the order a deploy script
  runs them (`-InputFile ... 'x.sql'`, `sqlcmd ... -i x.sql`, `Get-Content x.sql`), else every .sql file of a
  folder named db, database, sql, sqlscripts, scripts/sql or schema, by name. It prepares them (prepare): the
  sqlcmd directives (`:on error exit`, `:setvar`, `:r`) and the batches that need server-wide rights (a database,
  a login, the server's configuration, another database) are left out, as the lab makes the database and the login
  itself; the rest goes into the ConfigMap `cz-lab-sqlserver-init` of the app's namespace (lab/k8s.yaml).
- The lab agent (labagent.py), once the app's database is there, runs them in order as the app's own login, the
  owner of its database only (never sa), with sqlcmd's variables off (`-x`). An error is recorded and the rest
  goes on, as a DBA would read through it. The scripts' hash is kept as an extended property of the database
  (containerizer.lab-init): they run again when they change or when the database was made again (Admin -> Dev
  databases -> Delete), not otherwise.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

CONFIGMAP = "cz-lab-sqlserver-init"
INIT_LABEL = "containerizer.io/lab-init"
MARKER = "containerizer.lab-init"           # the database's extended property: the hash of the scripts it ran
MAX_BYTES = 900_000                         # a ConfigMap holds at most 1 MiB
MAX_FILES = 200
FOLDERS = re.compile(r"(?i)^(db|database|databases|sql|sqlscripts|schema|scripts[/\\]sql|database[/\\]scripts)$")
SKIP_DIRS = {".git", "node_modules", "bin", "obj", "packages", ".vs", "test", "tests", "testdata", "samples",
             "sample", "examples", "docs", "migrations"}
DEPLOY_EXT = {".ps1", ".psm1", ".sh", ".cmd", ".bat"}
# a deploy script running a .sql file: Invoke-Sqlcmd -InputFile (Join-Path $db '02-x.sql'), sqlcmd -i x.sql, ...
RUNS_SQL = re.compile(r"""(?i)(?:-InputFile\b|\bsqlcmd\b[^\n]*\s-i\s|Get-Content\b|Join-Path\b)[^\n]*?["']?"""
                      r"""(?P<file>[\w.\-/\\$()]+?\.sql)\b""")
TX_ONLY = re.compile(r"(?is)^\s*(?:(?:BEGIN\s+TRAN(?:SACTION)?|COMMIT(?:\s+TRAN(?:SACTION)?)?|"
                     r"ROLLBACK(?:\s+TRAN(?:SACTION)?)?|SET\s+XACT_ABORT\s+ON)\s*;?\s*)+$")
GO = re.compile(r"(?im)^[ \t]*GO(?:[ \t]+\d+)?[ \t]*;?[ \t]*$")
# what needs server-wide rights, or reaches past the app's own database: the lab does its part itself
SERVER_LEVEL = re.compile(
    r"(?is)\b(?:CREATE|ALTER|DROP)\s+(?:DATABASE|LOGIN|SERVER\s+ROLE|ENDPOINT|CREDENTIAL|AVAILABILITY\s+GROUP)\b"
    r"|\bALTER\s+SERVER\b|\bALTER\s+AUTHORIZATION\s+ON\s+DATABASE\b|\bUSE\s+\[?[\w$()]+\]?\s*;?\s*$|\bUSE\s+\["
    r"|\bsp_configure\b|\bRECONFIGURE\b|\bxp_cmdshell\b|\bsp_addsrvrolemember\b|\bsp_addlinkedserver\b"
    r"|\b(?:BACKUP|RESTORE)\s+(?:DATABASE|LOG)\b|\bSHUTDOWN\b|\bDBCC\b|\bsp_add_job\b|\bmsdb\.\.")


def _natural(name: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def _read(f: Path) -> str | None:
    try:
        b = f.read_bytes()
    except OSError:
        return None
    for enc in ("utf-8-sig", "utf-16") if not b.startswith((b"\xff\xfe", b"\xfe\xff")) else ("utf-16",):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("latin-1")


def _walk(root: Path, depth: int = 4):
    stack = [(root, 0)]
    while stack:
        d, n = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name.lower() not in SKIP_DIRS and not p.name.startswith(".") and n < depth:
                    stack.append((p, n + 1))
            else:
                yield p


def find(root: Path) -> tuple[list[tuple[str, str]], str]:
    """The app's SQL setup scripts, in the order they are run: [(path relative to root, text)], and how the order
    was found. Empty when there are none."""
    root = Path(root)
    files = list(_walk(root))
    sql = [f for f in files if f.suffix.lower() == ".sql"]
    if not sql:
        return [], ""
    by_name: dict[str, list[Path]] = {}
    for f in sql:
        by_name.setdefault(f.name.lower(), []).append(f)
    # 1. the order a deploy script runs them in
    for d in sorted((f for f in files if f.suffix.lower() in DEPLOY_EXT), key=lambda f: str(f)):
        text = _read(d) or ""
        order: list[Path] = []
        for m in RUNS_SQL.finditer(text):
            name = re.split(r"[/\\]", m["file"])[-1].lower()
            cands = by_name.get(name) or []
            if len(cands) == 1 and cands[0] not in order:
                order.append(cands[0])
        if order:
            return _texts(root, order), f"in the order {d.relative_to(root).as_posix()} runs them"
    # 2. a folder of scripts, by name
    for d in sorted({f.parent for f in sql}, key=lambda p: (len(p.relative_to(root).parts), str(p))):
        rel = d.relative_to(root).as_posix()
        if FOLDERS.match(rel) or FOLDERS.match(d.name):
            mine = sorted((f for f in sql if f.parent == d), key=lambda f: _natural(f.name))
            return _texts(root, mine), f"every .sql file of {rel}/, by name"
    return [], ""


def _texts(root: Path, files: list[Path]) -> list[tuple[str, str]]:
    out = []
    for f in files[:MAX_FILES]:
        t = _read(f)
        if t is not None:
            out.append((f.relative_to(root).as_posix(), t))
    return out


def prepare(text: str) -> tuple[str, list[str]]:
    """A script as the lab runs it: sqlcmd directives and server-level batches left out. Returns (script, the first
    line of each batch left out)."""
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if not re.match(r"^\s*:[A-Za-z]", ln)]
    kept, dropped = [], []
    for batch in GO.split("\n".join(lines)):
        body = re.sub(r"(?s)/\*.*?\*/", "", batch)
        body = "\n".join(re.sub(r"--.*$", "", ln) for ln in body.split("\n"))
        if not body.strip():
            continue
        if TX_ONLY.match(body):
            continue            # each batch commits on its own (an EF Core script's BEGIN TRANSACTION ... COMMIT)
        if SERVER_LEVEL.search(body):
            first = next((ln.strip() for ln in body.split("\n") if ln.strip()), "")
            dropped.append(first[:120])
            continue
        kept.append(batch.strip("\n"))
    return "".join(b + "\nGO\n" for b in kept), dropped


def configmap(ns: str, scripts: list[tuple[str, str]]) -> tuple[dict | None, list[str]]:
    """The ConfigMap of the prepared scripts (keys in run order) and notes for lab/README.md; None when nothing is
    left to run or it would not fit."""
    data, notes, size = {}, [], 0
    for i, (rel, text) in enumerate(scripts, 1):
        body, dropped = prepare(text)
        if dropped:
            notes.append(f"{rel}: left out (the lab makes the database and the login itself, or it needs server-wide "
                         f"rights): " + "; ".join(f"`{d}`" for d in dropped[:5]) + (" ..." if len(dropped) > 5 else ""))
        if not body:
            continue
        key = f"{i:03d}-" + re.sub(r"[^A-Za-z0-9._-]", "_", rel.split("/")[-1])
        size += len(body.encode())
        data[key] = body
    if not data:
        return None, notes
    if size > MAX_BYTES:
        return None, notes + [f"the scripts are {size // 1024} KB, more than a ConfigMap holds: run them yourself"]
    doc = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": CONFIGMAP, "namespace": ns,
                        "labels": {"app.kubernetes.io/part-of": ns, "app.kubernetes.io/managed-by": "containerizer",
                                   INIT_LABEL: "sqlserver"},
                        "annotations": {"containerizer.io/scripts": ", ".join(r for r, _ in scripts)[:2000]}},
           "data": data}
    return doc, notes


def digest(data: dict) -> str:
    """The hash of a ConfigMap's scripts, in run order (the marker the lab agent keeps in the database)."""
    h = hashlib.sha256()
    for k in sorted(data):
        h.update(k.encode() + b"\0" + str(data[k]).encode() + b"\0")
    return h.hexdigest()[:32]


ERROR_TAG = "CZ-LAB-INIT-ERROR: "


def script(data: dict, mark: str) -> str:
    """What the lab agent runs as the app's login: every batch of the scripts in order, each in its own EXEC inside
    TRY/CATCH, so that an error is printed (ERROR_TAG) and the next batch runs. (sqlcmd itself cannot go on after an
    error in a batch of several statements: every later batch fails with "Invalid cursor state", ODBC 18.) Then
    the marker."""
    out = []
    for k in sorted(data):
        out.append(f"PRINT N'--- {k}';\nGO\n")
        for i, batch in enumerate(b for b in GO.split(data[k]) if b.strip()):
            body = batch.strip("\n").replace("'", "''")
            out.append(f"BEGIN TRY\n    EXEC (N'{body}');\nEND TRY\nBEGIN CATCH\n"
                       f"    PRINT N'{ERROR_TAG}{k} batch {i + 1}: ' + ERROR_MESSAGE();\nEND CATCH;\nGO\n")
    out.append(f"IF EXISTS (SELECT 1 FROM sys.extended_properties WHERE class = 0 AND name = N'{MARKER}')\n"
               f"    EXEC sys.sp_updateextendedproperty @name = N'{MARKER}', @value = N'{mark}';\n"
               f"ELSE EXEC sys.sp_addextendedproperty @name = N'{MARKER}', @value = N'{mark}';\nGO\n")
    return "".join(out)


MARK_QUERY = (f"SET NOCOUNT ON; SELECT CAST(value AS nvarchar(100)) FROM sys.extended_properties "
              f"WHERE class = 0 AND name = N'{MARKER}'")
