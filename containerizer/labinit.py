"""The lab SQL Server database of an app set up from the repository's own SQL scripts (docs/lab-services.md).

In production a DBA runs an app's setup scripts (db/01-create-database.sql ... 04-reference-data.sql, run by a
deploy script with Invoke-Sqlcmd, or a folder of numbered or Flyway-style migrations); the lab gives each app an
empty database, so an app that does not create its tables itself fails there (Quartz: "Invalid object name
'quartz.QRTZ_JOB_DETAILS'").

- The scan (generate.py, when the app uses the lab's SQL Server) finds the scripts: in the order the deploy
  scripts run them (`-InputFile ... 'x.sql'`, `sqlcmd ... -i x.sql`, `Get-Content x.sql`; every deploy script
  that runs any, so each application of a repository of several gets its own), else every .sql file of a folder
  named db, database, sql, sqlscripts, scripts/sql, schema or migrations (Flyway's db/migration: versions in
  order, repeatable ones last, undo and down scripts never), by name; of several such folders side by side
  (billing/db, crm/db) all of them. It prepares them (prepare): sqlcmd's variables get the values the script
  itself sets (`:setvar Schema "app"`; the database's name becomes the lab database), the sqlcmd directives
  (`:on error exit`, `:setvar`, `:r`) and the batches that need server-wide rights (a database, a login, the
  server's configuration, another database) are left out, as the lab makes the database and the login itself; the
  rest goes into the ConfigMap `cz-lab-sqlserver-init` of the app's namespace (lab/k8s.yaml).
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
FOLDERS = re.compile(r"(?i)^(db|database|databases|sql|sqlscripts|schema|scripts[/\\]sql|database[/\\]scripts"
                     r"|migrations?)$")
SKIP_DIRS = {".git", "node_modules", "bin", "obj", "packages", ".vs", "test", "tests", "testdata", "samples",
             "sample", "examples", "docs", "target", "build", "dist"}
# what takes a migration back: Flyway's undo scripts (U2__x.sql), x.down.sql, down/ and rollback folders
UNDO = re.compile(r"(?i)^U\d[\w.]*__|[._-](down|undo|rollback)\.sql$")
UNDO_DIRS = {"down", "undo", "rollback", "rollbacks"}
# sqlcmd scripting variables: `:setvar Name "value"` and `$(Name)`; these names mean the database itself
SETVAR = re.compile(r"""(?im)^[ \t]*:setvar[ \t]+(\w+)[ \t]+(?:"([^"\n]*)"|(\S+))[ \t]*$""")
VARIABLE = re.compile(r"\$\((\w+)\)")
DB_VARIABLE = re.compile(r"(?i)^(db|database|catalog)_?(name)?$")
LAB_DATABASE = "$(CZ_LAB_DATABASE)"      # replaced by the lab agent, which knows the database's name (script())
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


def _walk(root: Path, depth: int = 6):
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
                if p.name.lower() not in SKIP_DIRS | UNDO_DIRS and not p.name.startswith(".") and n < depth:
                    stack.append((p, n + 1))
            else:
                yield p


def find(root: Path) -> tuple[list[tuple[str, str]], str]:
    """The app's SQL setup scripts, in the order they are run: [(path relative to root, text)], and how the order
    was found. Empty when there are none."""
    root = Path(root)
    files = list(_walk(root))
    sql = [f for f in files if f.suffix.lower() == ".sql" and not UNDO.search(f.name)]
    if not sql:
        return [], ""
    by_name: dict[str, list[Path]] = {}
    for f in sql:
        by_name.setdefault(f.name.lower(), []).append(f)
    # 1. the order the deploy scripts run them in (a repository of several applications has one per application)
    order: list[Path] = []
    ran: list[str] = []
    for d in sorted((f for f in files if f.suffix.lower() in DEPLOY_EXT), key=lambda f: str(f)):
        text = _read(d) or ""
        before = len(order)
        for m in RUNS_SQL.finditer(text):
            name = re.split(r"[/\\]", m["file"])[-1].lower()
            cands = by_name.get(name) or []
            if len(cands) > 1:          # the same name in several folders: the one nearest to this deploy script
                near = [f for f in cands if d.parent.parent in f.parents]
                cands = near if len(near) == 1 else []
            if len(cands) == 1 and cands[0] not in order:
                order.append(cands[0])
        if len(order) > before:
            ran.append(d.relative_to(root).as_posix())
    if order:
        return _texts(root, order), f"in the order {', '.join(ran)} run{'s' if len(ran) == 1 else ''} them"
    # 2. a folder of scripts, by name: the one nearest to the root, and the ones beside it under other folders
    # (billing/db and crm/db: the applications of one repository)
    folders = [d for d in sorted({f.parent for f in sql}, key=lambda p: (len(p.relative_to(root).parts), str(p)))
               if FOLDERS.match(d.relative_to(root).as_posix()) or FOLDERS.match(d.name)]
    if folders:
        depth = len(folders[0].relative_to(root).parts)
        mine = [d for d in folders if len(d.relative_to(root).parts) == depth and (d.name == folders[0].name)]
        files_ = [f for d in mine for f in sorted((f for f in sql if f.parent == d), key=lambda f: _order(f.name))]
        return _texts(root, files_), "every .sql file of " + ", ".join(
            d.relative_to(root).as_posix() + "/" for d in mine) + ", by name"
    return [], ""


def _order(name: str):
    """By name, numbers as numbers (10 after 9); Flyway's repeatable migrations (R__x.sql) after the versions."""
    return (name[:3].lower() == "r__", _natural(name))


def _texts(root: Path, files: list[Path]) -> list[tuple[str, str]]:
    out = []
    for f in files[:MAX_FILES]:
        t = _read(f)
        if t is not None:
            out.append((f.relative_to(root).as_posix(), t))
    return out


def prepare(text: str) -> tuple[str, list[str]]:
    """A script as the lab runs it: sqlcmd directives and server-level batches left out, sqlcmd's variables given
    the values the script sets with :setvar (sqlcmd itself runs with variables off; a database-name variable becomes
    LAB_DATABASE, which script() fills in; one without a value stays as written). Returns (script, the first line
    of each batch left out)."""
    values = {m[1].lower(): m[2] if m[2] is not None else m[3] for m in SETVAR.finditer(text.replace("\r\n", "\n"))}

    def value(m):
        name = m[1].lower()
        return LAB_DATABASE if DB_VARIABLE.match(name) else values.get(name, m[0])
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
        kept.append(VARIABLE.sub(value, batch.strip("\n")))
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


def script(data: dict, mark: str, database: str = "") -> str:
    """What the lab agent runs as the app's login: every batch of the scripts in order, each in its own EXEC inside
    TRY/CATCH, so that an error is printed (ERROR_TAG) and the next batch runs. (sqlcmd itself cannot go on after an
    error in a batch of several statements: every later batch fails with "Invalid cursor state", ODBC 18.) Then
    the marker. `database`: the app's lab database, for the scripts' database-name variable (LAB_DATABASE)."""
    out = []
    for k in sorted(data):
        out.append(f"PRINT N'--- {k}';\nGO\n")
        for i, batch in enumerate(b for b in GO.split(data[k]) if b.strip()):
            body = batch.strip("\n").replace(LAB_DATABASE, database or LAB_DATABASE).replace("'", "''")
            out.append(f"BEGIN TRY\n    EXEC (N'{body}');\nEND TRY\nBEGIN CATCH\n"
                       f"    PRINT N'{ERROR_TAG}{k} batch {i + 1}: ' + ERROR_MESSAGE();\nEND CATCH;\nGO\n")
    out.append(f"IF EXISTS (SELECT 1 FROM sys.extended_properties WHERE class = 0 AND name = N'{MARKER}')\n"
               f"    EXEC sys.sp_updateextendedproperty @name = N'{MARKER}', @value = N'{mark}';\n"
               f"ELSE EXEC sys.sp_addextendedproperty @name = N'{MARKER}', @value = N'{mark}';\nGO\n")
    return "".join(out)


MARK_QUERY = (f"SET NOCOUNT ON; SELECT CAST(value AS nvarchar(100)) FROM sys.extended_properties "
              f"WHERE class = 0 AND name = N'{MARKER}'")
