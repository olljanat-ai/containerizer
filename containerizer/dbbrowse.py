"""The database browser of Admin -> Dev databases: the statements, the clients and the system agent's side.

Administrators and operators look at and fix the rows of an application's database in the sandbox: a
lab-service database (SQL Server, PostgreSQL or MySQL on the shared server in `containerizer-lab`,
labservices.py) or a restored dev database (devdb.py: the `devdb` Deployment in the application's own
namespace). The pages are admin_dbbrowse.py; this module is everything they and the agent share.

The web UI has no cluster access. For each step it hands the system agent (sysagent.py, root) a request
`{"action": "dbquery", "id", "application_id", "source", "engine", "namespace", "statements", ...}` and waits
for the answer the agent writes to /run/containerizer/system/answers/<id>.json (appliance.py
SystemPage.ask). The agent trusts nothing in the request:

- the namespace must be a valid, non-system namespace that the results database maps to that application
  (cz.vSandboxNamespace, the scan worker's login);
- lab service: the namespace must be one the lab agent provisioned for that service (lab-status.json),
  and the login, password and database are the app's own, read from the secret store
  (`containerizer-secrets/<ns>--cz-lab-<service>`), with user and database checked against the names the
  agent derives itself (<ns> with underscores);
- dev database: the ready `devdb` pod in that namespace, its engine and database from the pod's own
  annotation, the password from the namespace's `devdb` Secret, user `app`.

The statement then runs through the engine's own client inside the server's container (`kubectl exec -i`),
logged in as the application's own login, against its own database. The password is the first line of
the client's stdin, read by a fixed shell script into the client's environment; it is never on a command
line, never in a request or an answer file, and never sent to the web UI. So whatever SQL a request holds,
it can only do what the application itself can do in its own database.

Client output is machine-readable: psql `--csv` (with a per-request NULL marker and the row count through
`\\echo :ROW_COUNT`), mysql `--xml` (`--binary-mode`: no client commands; the row count from ROW_COUNT()),
and SQL Server through a fixed T-SQL wrapper: the statement travels hex-encoded and runs with
sp_executesql, its first result set is described (sys.dm_exec_describe_first_result_set), captured with
INSERT ... EXEC and returned as JSON (FOR JSON PATH, INCLUDE_NULL_VALUES); what cannot be captured that way
falls back to sqlcmd's text output. Results are capped (MAX_ROWS rows, MAX_BYTES of client output) and
every statement has a server-side timeout.

Deleting a database (`dbdelete`): lab service, the agent drops the app's database as the server's admin
(the server's own environment, as for provisioning), forgets that it provisioned it, runs the lab agent
(containerizer-lab.service, the timer's code path), which creates it again empty with the same login and
password, then restarts the application's Deployments so it creates its schema again. Dev database: the
`devdb` Deployment restarts, and the restored copy (on an emptyDir) is restored again from the uploaded
backup.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ENGINES = {"sqlserver": "SQL Server", "postgres": "PostgreSQL", "mysql": "MySQL"}
SOURCES = ("lab", "devdb")
MAX_ROWS = 500                  # rows in one answer
MAX_BYTES = 1024 * 1024         # client output read per statement
STATEMENT_TIMEOUT = 15          # seconds, enforced by the server (and the client)
EXEC_TIMEOUT = 20               # seconds, then the client is killed
ANSWER_WAIT = 45                # seconds the web UI waits for an answer
MAX_STATEMENT = 60_000          # characters of one statement
MAX_STATEMENTS = 3              # statements in one request
PAGE = 50                       # rows per page of the table browser
ID_RE = re.compile(r"[0-9a-f]{32}")
NS_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
DB_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
PASSWORD_RE = re.compile(r"[A-Za-z0-9]{8,128}")
SQLCMD = "/opt/mssql-tools18/bin/sqlcmd"
DEVDB_USER = "app"
DEVDB_NAME = "devdb"            # Deployment, container and Secret of a restored dev database (devdb.py)
DEVDB_ANNOTATION = "containerizer.io/devdb"
ANSWERS_DIR = Path("/run/containerizer/system/answers")
LAB_STATUS = Path("/run/containerizer/system/lab-status.json")
CLR_TYPES = ("geography", "geometry", "hierarchyid")


class DbError(Exception):
    """A refusal or a failure whose message is safe to show to the administrator."""


# =============================================================================== quoting

def ident(engine: str, name) -> str:
    """A quoted identifier (table, column, schema)."""
    name = str(name if name is not None else "")
    if not name or "\x00" in name or len(name) > 128:
        raise DbError("Not a valid name.")
    if engine == "sqlserver":
        return "[" + name.replace("]", "]]") + "]"
    if engine == "mysql":
        return "`" + name.replace("`", "``") + "`"
    return '"' + name.replace('"', '""') + '"'


def table_ref(engine: str, schema: str, table: str) -> str:
    """schema.table; on MySQL the table only: the schema is the app's own database (DATABASE())."""
    if engine == "mysql":
        return ident(engine, table)
    return ident(engine, schema) + "." + ident(engine, table)


def literal(engine: str, value) -> str:
    """A string literal the server converts to the column's type; NULL for None. Never pasted raw:
    SQL Server N'' and PostgreSQL '' with quotes doubled (E'' with backslashes doubled when there is one,
    whatever standard_conforming_strings says), MySQL a hex literal with a character set introducer, so
    neither quotes nor backslashes nor the sql_mode matter."""
    if value is None:
        return "NULL"
    s = str(value)
    if "\x00" in s:
        raise DbError("A value cannot hold a NUL character.")
    if engine == "sqlserver":
        return "N'" + s.replace("'", "''") + "'"
    if engine == "mysql":
        return "_utf8mb4 X'" + s.encode("utf-8").hex() + "'" if s else "''"
    if "\\" in s:
        return "E'" + s.replace("\\", "\\\\").replace("'", "''") + "'"
    return "'" + s.replace("'", "''") + "'"


def contains(engine: str, col: str, text: str) -> str:
    """`col` (quoted) contains `text`, as text, ignoring case where the engine can; ! escapes the wildcards."""
    esc = str(text).replace("!", "!!").replace("%", "!%").replace("_", "!_")
    if engine == "sqlserver":
        esc = esc.replace("[", "![")
    pat = literal(engine, "%" + esc + "%")
    if engine == "postgres":
        return f"CAST({col} AS text) ILIKE {pat} ESCAPE '!'"
    if engine == "mysql":
        return f"CAST({col} AS CHAR) LIKE {pat} ESCAPE '!'"
    return f"CAST({col} AS nvarchar(max)) LIKE {pat} ESCAPE '!'"


# =============================================================================== generated statements

def tables_sql(engine: str) -> str:
    """Tables and views of the app's database: schema, name, kind, rows (approximate, may be NULL)."""
    if engine == "postgres":
        return ("SELECT n.nspname AS \"schema\", c.relname AS \"name\", "
                "CASE WHEN c.relkind IN ('v', 'm') THEN 'view' ELSE 'table' END AS \"kind\", "
                "CASE WHEN c.reltuples < 0 THEN NULL ELSE CAST(c.reltuples AS bigint) END AS \"rows\" "
                "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname <> 'information_schema' "
                "AND left(n.nspname, 3) <> 'pg_' ORDER BY 1, 2")
    if engine == "mysql":
        return ("SELECT TABLE_SCHEMA AS `schema`, TABLE_NAME AS `name`, "
                "CASE WHEN TABLE_TYPE = 'VIEW' THEN 'view' ELSE 'table' END AS `kind`, TABLE_ROWS AS `rows` "
                "FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME")
    return ("SELECT s.name AS [schema], o.name AS [name], CASE o.type WHEN 'V' THEN 'view' ELSE 'table' END AS [kind], "
            "(SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = o.object_id AND p.index_id IN (0, 1)) AS [rows] "
            "FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id "
            "WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0 ORDER BY s.name, o.name")


def columns_sql(engine: str, schema: str, table: str) -> str:
    """Columns of a table in order: name, type, nullable, default, auto, generated, pk (key ordinal)."""
    if engine == "postgres":
        return ("SELECT a.attname AS \"name\", format_type(a.atttypid, a.atttypmod) AS \"type\", "
                "CASE WHEN a.attnotnull THEN 0 ELSE 1 END AS \"nullable\", pg_get_expr(d.adbin, d.adrelid) AS \"default\", "
                "CASE WHEN a.attidentity <> '' OR pg_get_expr(d.adbin, d.adrelid) LIKE 'nextval(%' THEN 1 ELSE 0 END AS \"auto\", "
                "CASE WHEN a.attgenerated <> '' THEN 1 ELSE 0 END AS \"generated\", "
                "(SELECT k.ord FROM pg_catalog.pg_index i CROSS JOIN LATERAL unnest(CAST(i.indkey AS int2[])) "
                "WITH ORDINALITY AS k(attnum, ord) WHERE i.indrelid = c.oid AND i.indisprimary AND k.attnum = a.attnum) AS \"pk\" "
                "FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
                f"WHERE n.nspname = {literal(engine, schema)} AND c.relname = {literal(engine, table)} "
                "AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum")
    if engine == "mysql":
        return ("SELECT c.COLUMN_NAME AS `name`, c.COLUMN_TYPE AS `type`, "
                "CASE WHEN c.IS_NULLABLE = 'YES' THEN 1 ELSE 0 END AS `nullable`, c.COLUMN_DEFAULT AS `default`, "
                "CASE WHEN c.EXTRA LIKE '%auto_increment%' THEN 1 ELSE 0 END AS `auto`, "
                "CASE WHEN c.EXTRA LIKE '%VIRTUAL GENERATED%' OR c.EXTRA LIKE '%STORED GENERATED%' THEN 1 ELSE 0 END AS `generated`, "
                "k.ORDINAL_POSITION AS `pk` FROM information_schema.COLUMNS c "
                "LEFT JOIN information_schema.KEY_COLUMN_USAGE k ON k.TABLE_SCHEMA = c.TABLE_SCHEMA "
                "AND k.TABLE_NAME = c.TABLE_NAME AND k.COLUMN_NAME = c.COLUMN_NAME AND k.CONSTRAINT_NAME = 'PRIMARY' "
                f"WHERE c.TABLE_SCHEMA = DATABASE() AND c.TABLE_NAME = {literal(engine, table)} ORDER BY c.ORDINAL_POSITION")
    ref = literal(engine, table_ref(engine, schema, table))
    return ("SELECT c.name AS [name], t.name + CASE "
            "WHEN t.name IN ('varchar', 'char', 'varbinary', 'binary') THEN '(' + CASE WHEN c.max_length = -1 THEN 'max' "
            "ELSE CAST(c.max_length AS varchar(10)) END + ')' "
            "WHEN t.name IN ('nvarchar', 'nchar') THEN '(' + CASE WHEN c.max_length = -1 THEN 'max' "
            "ELSE CAST(c.max_length / 2 AS varchar(10)) END + ')' "
            "WHEN t.name IN ('decimal', 'numeric') THEN '(' + CAST(c.precision AS varchar(5)) + ',' + CAST(c.scale AS varchar(5)) + ')' "
            "WHEN t.name IN ('datetime2', 'time', 'datetimeoffset') THEN '(' + CAST(c.scale AS varchar(5)) + ')' ELSE '' END AS [type], "
            "CAST(c.is_nullable AS int) AS [nullable], OBJECT_DEFINITION(c.default_object_id) AS [default], "
            "CAST(c.is_identity AS int) AS [auto], "
            "CASE WHEN c.is_computed = 1 OR t.name = 'timestamp' THEN 1 ELSE 0 END AS [generated], ic.key_ordinal AS [pk] "
            "FROM sys.columns c JOIN sys.types t ON t.user_type_id = c.user_type_id "
            "LEFT JOIN sys.indexes i ON i.object_id = c.object_id AND i.is_primary_key = 1 "
            "LEFT JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.column_id = c.column_id "
            f"WHERE c.object_id = OBJECT_ID({ref}) ORDER BY c.column_id")


@dataclass
class Column:
    name: str
    type: str
    nullable: bool = True
    default: str | None = None
    auto: bool = False                  # identity, serial, auto_increment
    generated: bool = False             # computed, generated, rowversion: never written
    pk: int | None = None               # position in the primary key

    @property
    def editable(self) -> bool:
        return not self.generated and not is_binary(self.type)

    def to_dict(self) -> dict:
        return {"name": self.name, "type": self.type, "nullable": self.nullable, "default": self.default,
                "auto": self.auto, "generated": self.generated, "pk": self.pk}


def is_binary(type_name: str) -> bool:
    """Binary columns are shown as hex and not edited here."""
    t = (type_name or "").lower().split("(")[0].strip()
    return t in ("binary", "varbinary", "bytea", "blob", "tinyblob", "mediumblob", "longblob", "image", "rowversion") \
        or t.endswith(" binary")


def _flag(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "t", "yes")


def parse_columns(result: dict) -> list[Column]:
    """The answer to columns_sql as Columns."""
    names = result.get("columns") or []
    out = []
    for r in result.get("rows") or []:
        d = dict(zip(names, r))
        pk = d.get("pk")
        out.append(Column(name=str(d.get("name")), type=str(d.get("type") or ""), nullable=_flag(d.get("nullable")),
                          default=d.get("default"), auto=_flag(d.get("auto")), generated=_flag(d.get("generated")),
                          pk=int(pk) if pk not in (None, "") and str(pk).isdigit() else None))
    return out


def primary_key(cols: list[Column]) -> list[Column]:
    return sorted((c for c in cols if c.pk), key=lambda c: c.pk)


def read_only_reason(cols: list[Column], kind: str = "table") -> str | None:
    """Why rows of this table cannot be changed here, or None."""
    if kind == "view":
        return "It is a view: change the tables behind it."
    pk = primary_key(cols)
    if not pk:
        return "It has no primary key, so a row cannot be picked out safely: use SQL."
    if any(is_binary(c.type) for c in pk):
        return "Its primary key is binary: use SQL."
    return None


def _select_expr(engine: str, c: Column) -> str:
    q = ident(engine, c.name)
    base = c.type.lower().split("(")[0]
    if engine == "sqlserver":
        if base in CLR_TYPES:
            return f"{q}.ToString() AS {q}"
        if base in ("xml", "sql_variant", "text", "ntext"):
            return f"CAST({q} AS nvarchar(max)) AS {q}"
    if engine == "mysql" and base in ("geometry", "point", "linestring", "polygon", "multipoint", "multilinestring",
                                      "multipolygon", "geometrycollection", "geomcollection"):
        return f"ST_AsText({q}) AS {q}"
    return q


FILTER_OPS = {"eq": "equals", "contains": "contains", "null": "is NULL", "notnull": "is not NULL"}


def rows_sql(engine: str, schema: str, table: str, cols: list[Column], filt: tuple[str, str, str] | None = None,
             sort: str | None = None, desc: bool = False, offset: int = 0, limit: int = PAGE + 1) -> str:
    """One page of a table: the columns in order, a filter on one column, sorted by a column (else the primary
    key), `limit` rows from `offset`."""
    names = {c.name for c in cols}
    if not cols:
        raise DbError("The table has no columns that can be read.")
    sel = ", ".join(_select_expr(engine, c) for c in cols)
    sql = f"SELECT {sel} FROM {table_ref(engine, schema, table)}"
    if filt:
        col, op, val = filt
        if col not in names or op not in FILTER_OPS:
            raise DbError("Filter on a column of the table.")
        q = ident(engine, col)
        sql += " WHERE " + {"eq": lambda: f"{q} = {literal(engine, val)}", "contains": lambda: contains(engine, q, val),
                            "null": lambda: f"{q} IS NULL", "notnull": lambda: f"{q} IS NOT NULL"}[op]()
    order = [ident(engine, sort) + (" DESC" if desc else "")] if sort in names else \
        [ident(engine, c.name) for c in primary_key(cols)]
    offset, limit = max(0, int(offset)), max(1, min(int(limit), MAX_ROWS))
    if engine == "sqlserver":
        sql += " ORDER BY " + (", ".join(order) or "(SELECT NULL)")
        return sql + f" OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
    if order:
        sql += " ORDER BY " + ", ".join(order)
    return sql + f" LIMIT {limit} OFFSET {offset}"


def _pk_where(engine: str, cols: list[Column], key: dict) -> str:
    pk = primary_key(cols)
    if not pk or set(key) != {c.name for c in pk}:
        raise DbError("The row is picked out by its whole primary key.")
    return " AND ".join(f"{ident(engine, c.name)} = {literal(engine, key[c.name])}" if key[c.name] is not None
                        else f"{ident(engine, c.name)} IS NULL" for c in pk)


def row_sql(engine: str, schema: str, table: str, cols: list[Column], key: dict) -> str:
    sel = ", ".join(_select_expr(engine, c) for c in cols)
    return f"SELECT {sel} FROM {table_ref(engine, schema, table)} WHERE {_pk_where(engine, cols, key)}"


def update_sql(engine: str, schema: str, table: str, cols: list[Column], key: dict, values: dict) -> str:
    """UPDATE one row by its primary key: values {column: text or None (NULL)}."""
    by = {c.name: c for c in cols}
    if not values:
        raise DbError("Nothing changed.")
    for k in values:
        if k not in by or not by[k].editable:
            raise DbError(f"Column {k} cannot be changed here.")
    sets = ", ".join(f"{ident(engine, k)} = {literal(engine, v)}" for k, v in values.items())
    return f"UPDATE {table_ref(engine, schema, table)} SET {sets} WHERE {_pk_where(engine, cols, key)}"


def insert_sql(engine: str, schema: str, table: str, cols: list[Column], values: dict) -> str:
    """INSERT one row: values {column: text or None}; columns left out get their default."""
    by = {c.name: c for c in cols}
    for k in values:
        if k not in by or not by[k].editable:
            raise DbError(f"Column {k} cannot be set here.")
    t = table_ref(engine, schema, table)
    if not values:
        return f"INSERT INTO {t} () VALUES ()" if engine == "mysql" else f"INSERT INTO {t} DEFAULT VALUES"
    names = ", ".join(ident(engine, k) for k in values)
    vals = ", ".join(literal(engine, v) for v in values.values())
    return f"INSERT INTO {t} ({names}) VALUES ({vals})"


def delete_sql(engine: str, schema: str, table: str, cols: list[Column], key: dict) -> str:
    return f"DELETE FROM {table_ref(engine, schema, table)} WHERE {_pk_where(engine, cols, key)}"


# =============================================================================== the clients

def _check_login(user: str, database: str, password: str) -> None:
    if not DB_RE.fullmatch(user or "") or not DB_RE.fullmatch(database or ""):
        raise DbError("The database's login or name is not what was expected.")
    if not PASSWORD_RE.fullmatch(password or ""):
        raise DbError("The database's password is not in the expected form.")


def client_command(engine: str, user: str, database: str, marker: str, null: str = "", text: bool = False) -> list[str]:
    """What runs in the server's container. A fixed script reads the password (first line of stdin) into the
    client's environment; user, database and markers are positional arguments, never part of the script."""
    if engine == "postgres":
        script = (r'IFS= read -r PGPASSWORD; export PGPASSWORD PGAPPNAME=containerizer-db-browser; '
                  f'PGOPTIONS="-c statement_timeout={STATEMENT_TIMEOUT * 1000}"; export PGOPTIONS; '
                  r'PGCONNECT_TIMEOUT=10; export PGCONNECT_TIMEOUT; SQL=$(cat); '
                  r'exec psql -X -q -w --csv -v ON_ERROR_STOP=1 -v SHOW_ALL_RESULTS=off -P "null=$3" '
                  r'-h 127.0.0.1 -U "$1" -d "$2" -c "$SQL" -c "\\echo $4 :ROW_COUNT"')
        return ["/bin/sh", "-c", script, "cz", user, database, null, marker]
    if engine == "mysql":
        script = (r'IFS= read -r MYSQL_PWD; export MYSQL_PWD; '
                  r'exec mysql --no-defaults --protocol=tcp -h 127.0.0.1 -u "$1" -D "$2" --xml --binary-mode '
                  r'--binary-as-hex --local-infile=0 --system-command=OFF --connect-timeout=10 '
                  r'--default-character-set=utf8mb4')
        return ["/bin/sh", "-c", script, "cz", user, database]
    if engine == "sqlserver":
        out = '-y 0' if not text else '-W -s "|"'
        script = (r'IFS= read -r SQLCMDPASSWORD; export SQLCMDPASSWORD; '
                  f'exec {SQLCMD} -C -S localhost -U "$1" -d "$2" -b -r1 -x -X -I -t {STATEMENT_TIMEOUT} -l 10 '
                  f'{out} -f 65001 -i /dev/stdin')
        return ["/bin/sh", "-c", script, "cz", user, database]
    raise DbError(f"Unknown engine {engine}.")


def _mssql_hex(statement: str) -> str:
    return "0x" + statement.encode("utf-16-le").hex().upper()


def client_input(engine: str, password: str, statement: str, marker: str, max_rows: int = MAX_ROWS,
                 text: bool = False) -> str:
    """The client's stdin: the password line, then the script around the statement."""
    if engine == "postgres":
        # psql -c: sent to the server as it is; the leading newline keeps a backslash from ever being first
        body = "\n" + statement
    elif engine == "mysql":
        stmt = statement.strip().rstrip(";").rstrip()
        body = (f"SET SESSION max_execution_time = {STATEMENT_TIMEOUT * 1000};\n{stmt}\n;\n"
                f"SELECT ROW_COUNT() AS `{marker}`;\n")
    elif engine == "sqlserver":
        h = _mssql_hex(statement)
        if text:
            body = f"SET NOCOUNT OFF;\nDECLARE @s nvarchar(max) = CAST({h} AS nvarchar(max));\nEXEC sp_executesql @s;\n"
        else:
            body = MSSQL_WRAPPER.replace("{HEX}", h).replace("{M}", marker).replace("{TOP}", str(int(max_rows) + 1))
    else:
        raise DbError(f"Unknown engine {engine}.")
    return password + "\n" + body


# The statement is hex (nothing in it reaches sqlcmd's own parser: no :commands, no $(variables)); its
# first result set is described, captured into #r with INSERT ... EXEC and returned as JSON with the
# column names and types; a statement without a result set returns its row count.
MSSQL_WRAPPER = """SET NOCOUNT ON;
DECLARE @s nvarchar(max) = CAST({HEX} AS nvarchar(max));
DECLARE @d TABLE (o int NOT NULL, name sysname NULL, t nvarchar(256) NULL, e int NULL);
INSERT @d SELECT ISNULL(column_ordinal, 0), name, system_type_name, error_number
FROM sys.dm_exec_describe_first_result_set(@s, NULL, 0);
IF EXISTS (SELECT 1 FROM @d WHERE e IS NOT NULL OR t IS NULL OR t IN (N'geography', N'geometry', N'hierarchyid'))
    SELECT N'{M}:TEXT';
ELSE IF NOT EXISTS (SELECT 1 FROM @d)
BEGIN
    DECLARE @n bigint;
    EXEC sp_executesql @s;
    SET @n = @@ROWCOUNT;
    SELECT N'{M}:COUNT:' + CAST(@n AS nvarchar(20));
END
ELSE
BEGIN
    CREATE TABLE #r (cz__ int NULL);
    DECLARE @a nvarchar(max) = (SELECT N'ALTER TABLE #r ADD ' + STRING_AGG(CAST(N'c' + CAST(o AS nvarchar(10)) + N' '
        + CASE WHEN t IN (N'timestamp', N'rowversion') THEN N'binary(8)' ELSE t END + N' NULL' AS nvarchar(max)), N', ')
        WITHIN GROUP (ORDER BY o) FROM @d);
    EXEC sp_executesql @a;
    ALTER TABLE #r DROP COLUMN cz__;
    EXEC sp_executesql N'INSERT #r EXEC sp_executesql @s', N'@s nvarchar(max)', @s;
    DECLARE @total bigint = (SELECT COUNT_BIG(*) FROM #r);
    SELECT N'{M}:COLS:' + (SELECT o, name, t FROM @d ORDER BY o FOR JSON PATH, INCLUDE_NULL_VALUES);
    DECLARE @q nvarchar(max) = N'SELECT @j = (SELECT TOP ({TOP}) ' + (SELECT STRING_AGG(CAST(N'c' + CAST(o AS nvarchar(10))
        AS nvarchar(max)), N', ') WITHIN GROUP (ORDER BY o) FROM @d) + N' FROM #r FOR JSON PATH, INCLUDE_NULL_VALUES)';
    DECLARE @j nvarchar(max);
    EXEC sp_executesql @q, N'@j nvarchar(max) OUTPUT', @j OUTPUT;
    SELECT N'{M}:ROWS:' + CAST(@total AS nvarchar(20)) + N':' + COALESCE(@j, N'[]');
END
"""


# =============================================================================== output parsing

def _rows_result(columns: list[str], rows: list[list], max_rows: int, types: list | None = None,
                 total: int | None = None) -> dict:
    return {"kind": "rows", "columns": columns, "types": types or [None] * len(columns), "rows": rows[:max_rows],
            "truncated": len(rows) > max_rows or (total is not None and total > max_rows),
            "total": total if total is not None else (len(rows) if len(rows) <= max_rows else None)}


def parse_postgres(out: str, marker: str, null: str, max_rows: int = MAX_ROWS) -> dict:
    """psql --csv output, then `<marker> <row count>`."""
    idx = out.rfind(marker + " ")
    if idx < 0 or (idx and out[idx - 1] != "\n"):
        raise DbError("The database's answer could not be read.")
    tail = out[idx + len(marker) + 1:].split("\n", 1)[0].strip()
    n = int(tail) if tail.lstrip("-").isdigit() else 0
    body = out[:idx]
    if not body.strip():
        return {"kind": "count", "rowcount": n}
    rows = list(csv.reader(io.StringIO(body)))
    header, data = rows[0], rows[1:]
    data = [[None if v == null else v for v in r] for r in data]
    return _rows_result(header, data, max_rows)


_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
XSI_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"


def parse_mysql(out: str, marker: str, max_rows: int = MAX_ROWS) -> dict:
    """mysql --xml output: one document per result set; the last is our ROW_COUNT() (-1 after a SELECT)."""
    if re.search(r"<!(DOCTYPE|ENTITY)", out):
        raise DbError("The database's answer could not be read.")
    sets = []
    for doc in re.split(r"<\?xml[^>]*\?>", out):
        if not doc.strip():
            continue
        try:
            # a raw CR is data (mysql writes its own markup with LF): kept as a character reference, which
            # XML's end-of-line normalisation leaves alone
            root = ET.fromstring(_XML_BAD.sub("\ufffd", doc.strip()).replace("\r", "&#13;"))
        except ET.ParseError:
            raise DbError("The database's answer could not be read.") from None
        cols, rows = [], []
        for row in root.findall("row"):
            r = []
            for f in row.findall("field"):
                if not rows:
                    cols.append(f.get("name") or "")
                r.append(None if f.get(XSI_NIL) == "true" else (f.text or ""))
            rows.append(r)
        sets.append((cols, rows))
    if not sets or sets[-1][0] != [marker]:
        raise DbError("The database's answer could not be read.")
    n = int(sets[-1][1][0][0]) if sets[-1][1] and str(sets[-1][1][0][0]).lstrip("-").isdigit() else 0
    if n == -1 and len(sets) > 1:
        cols, rows = sets[-2]
        return _rows_result(cols, rows, max_rows)
    return {"kind": "count", "rowcount": max(n, 0)}


def _json_value(v, type_name: str | None):
    if v is None:
        return None
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    if type_name and is_binary(type_name.replace("timestamp", "rowversion")) and isinstance(v, str):
        try:
            return "0x" + base64.b64decode(v).hex().upper()
        except ValueError:
            return v
    return str(v)


def parse_sqlserver(out: str, marker: str, max_rows: int = MAX_ROWS) -> dict:
    """The wrapper's lines `<marker>:COUNT:n`, `<marker>:COLS:json` + `<marker>:ROWS:total:json`, or `<marker>:TEXT`
    (the statement was not run: run it again in text mode)."""
    lines = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(marker + ":"):
            kind, _, rest = line[len(marker) + 1:].partition(":")
            lines[kind] = rest
    if "TEXT" in lines:
        return {"kind": "needs-text"}
    if "COUNT" in lines:
        return {"kind": "count", "rowcount": int(lines["COUNT"]) if lines["COUNT"].isdigit() else 0}
    if "COLS" not in lines or "ROWS" not in lines:
        raise DbError("The database's answer could not be read (it may be larger than 1 MB: ask for fewer rows "
                      "or columns).")
    try:
        cols = json.loads(lines["COLS"])
        total, _, j = lines["ROWS"].partition(":")
        data = json.loads(j, parse_float=str, parse_int=str)
    except ValueError:
        raise DbError("The database's answer could not be read (it may be larger than 1 MB: ask for fewer rows "
                      "or columns).") from None
    names = [c.get("name") or f"column{c.get('o')}" for c in cols]
    types = [c.get("t") for c in cols]
    keys = [f"c{c.get('o')}" for c in cols]
    rows = [[_json_value(r.get(k), t) for k, t in zip(keys, types)] for r in data]
    return _rows_result(names, rows, max_rows, types, int(total) if total.isdigit() else None)


# =============================================================================== running a statement

def run_capped(argv: list[str], stdin: str, timeout: float = EXEC_TIMEOUT, cap: int = MAX_BYTES) -> tuple[int, str, str, str]:
    """Run argv with stdin; (exit code, stdout, stderr, problem) where problem is "", "timeout" or "too large".
    Reads at most `cap` bytes of stdout, then kills the process."""
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as ex:
        raise DbError(f"The database client could not be started: {ex.strerror or ex}") from None
    problem = []

    def kill():
        problem.append("timeout")
        p.kill()
    timer = threading.Timer(timeout, kill)
    timer.start()
    err = bytearray()

    def write():
        try:
            p.stdin.write(stdin.encode("utf-8"))
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    def read_err():
        while True:
            chunk = p.stderr.read(8192)
            if not chunk:
                break
            if len(err) < 64 * 1024:
                err.extend(chunk)
    tw, te = threading.Thread(target=write, daemon=True), threading.Thread(target=read_err, daemon=True)
    tw.start()
    te.start()
    out = bytearray()
    try:
        while True:
            chunk = p.stdout.read(65536)
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > cap:
                problem.append("too large")
                p.kill()
                break
        rc = p.wait()
    finally:
        timer.cancel()
        te.join(timeout=5)
        tw.join(timeout=5)
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), (problem[0] if problem else "")


@dataclass
class Target:
    """Where and as whom a statement runs: the exec prefix (`kubectl ... exec -i <pod> -c <container> --`, or
    `docker exec -i <container>` in the tests), the engine, and the app's login."""
    engine: str
    exec_prefix: list[str]
    user: str
    database: str
    password: str = field(repr=False)
    namespace: str = ""
    source: str = "lab"


def _clean_error(text: str, password: str) -> str:
    text = (text or "").replace(password, "***") if password else (text or "")
    lines = [ln for ln in text.strip().splitlines() if ln.strip() and "Warning: Using a password" not in ln]
    return "\n".join(lines)[-1500:] or "The statement failed."


def run_statement(target: Target, statement: str, max_rows: int = MAX_ROWS, runner=run_capped) -> dict:
    """Run one statement as the target's login; the parsed result, or DbError with the server's message."""
    _check_login(target.user, target.database, target.password)
    if not isinstance(statement, str) or not statement.strip():
        raise DbError("Write a statement.")
    if len(statement) > MAX_STATEMENT or "\x00" in statement:
        raise DbError(f"A statement is at most {MAX_STATEMENT} characters, without NUL characters.")
    max_rows = max(1, min(int(max_rows), MAX_ROWS))
    marker = "CZ" + secrets.token_hex(8)
    null = "CZNULL" + secrets.token_hex(8)
    eng = target.engine

    def go(text: bool = False) -> tuple[str, str]:
        argv = target.exec_prefix + client_command(eng, target.user, target.database, marker, null, text)
        rc, out, err, problem = runner(argv, client_input(eng, target.password, statement, marker, max_rows, text))
        if problem == "timeout":
            raise DbError(f"No answer within {EXEC_TIMEOUT} seconds: the statement was stopped.")
        if problem == "too large":
            raise DbError(f"The answer is larger than {MAX_BYTES // (1024 * 1024)} MB: ask for fewer rows or columns.")
        if rc:
            raise DbError(_clean_error(err or out, target.password))
        return out, err
    out, err = go()
    try:
        if eng == "postgres":
            return parse_postgres(out, marker, null, max_rows)
        if eng == "mysql":
            return parse_mysql(out, marker, max_rows)
        res = parse_sqlserver(out, marker, max_rows)
    except DbError:
        if marker not in out and err.strip():       # sqlcmd ends a timed-out statement with exit code 0
            raise DbError(_clean_error(err, target.password)) from None
        raise
    if res["kind"] == "needs-text":
        text, _ = go(text=True)
        return {"kind": "text", "text": text[:MAX_BYTES]}
    return res


# =============================================================================== dropping a database

def drop_script(engine: str, database: str) -> str:
    """Drop the app's database as the server's admin, closing its connections first (stdin of
    labservices.provision_command)."""
    if not DB_RE.fullmatch(database or ""):
        raise DbError("Not a database name.")
    if engine == "sqlserver":
        return (f"SET NOCOUNT ON;\nIF DB_ID(N'{database}') IS NOT NULL\nBEGIN\n"
                f"    ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;\n"
                f"    DROP DATABASE [{database}];\nEND\nGO\n")
    if engine == "postgres":
        return (f"\\set ON_ERROR_STOP on\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database}' AND pid <> pg_backend_pid();\n"
                f"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE);\n")
    if engine == "mysql":
        return f"DROP DATABASE IF EXISTS `{database}`;\n"
    raise DbError(f"Unknown engine {engine}.")


# =============================================================================== the system agent's side

@dataclass
class Agent:
    """What the agent needs from the outside, replaceable in the tests."""
    kube: object = None                                   # labagent.Kubectl
    lab_status: Path = LAB_STATUS
    owner_check: object = None                            # (namespace, application id) -> bool
    runner: object = run_capped
    systemctl: object = None                              # (args) -> None
    lab_state: Path | None = None                         # labagent.STATE_PATH

    def _kube(self):
        if self.kube is None:
            from .labagent import Kubectl
            self.kube = Kubectl()
        return self.kube

    def exec_prefix(self, ns: str, pod: str, container: str) -> list[str]:
        k = self._kube()
        return list(k.cmd) + ([f"--kubeconfig={k.kubeconfig}"] if k.kubeconfig else []) + \
            ["-n", ns, "exec", "-i", pod, "-c", container, "--"]

    # -- checks -------------------------------------------------------------------------------

    def check_request(self, req: dict) -> tuple[str, str, str, int]:
        """(source, engine, namespace, application id) of a request, checked again here."""
        from . import labservices as L
        source, engine, ns = req.get("source"), req.get("engine"), req.get("namespace")
        app_id = req.get("application_id")
        if source not in SOURCES:
            raise DbError("Unknown kind of database.")
        if engine not in ENGINES:
            raise DbError("Unknown engine.")
        if not isinstance(ns, str) or not NS_RE.fullmatch(ns) or L.reserved(ns):
            raise DbError("Not an application's namespace.")
        if not isinstance(app_id, int) or isinstance(app_id, bool) or app_id <= 0:
            raise DbError("Unknown application.")
        try:
            owned = (self.owner_check or results_owner_check)(ns, app_id)
        except Exception as ex:  # noqa: BLE001 - fail closed
            log(f"dbquery: could not check namespace {ns}: {type(ex).__name__}: {ex}")
            raise DbError("The appliance could not check that the namespace belongs to the application.") from None
        if not owned:
            raise DbError(f"Namespace {ns} is not one of this application's sandbox namespaces.")
        return source, engine, ns, app_id

    def _ready_pod(self, ns: str, selector: str) -> dict | None:
        data = self._kube().get(["-n", ns, "pods", "-l", selector]) or {}
        for p in data.get("items") or []:
            if (p.get("metadata") or {}).get("deletionTimestamp"):
                continue
            conds = {c.get("type"): c.get("status") for c in (p.get("status") or {}).get("conditions") or []}
            if conds.get("Ready") == "True":
                return p
        return None

    def lab_target(self, engine: str, ns: str) -> Target:
        from . import labagent
        from . import labservices as L
        try:
            st = json.loads(self.lab_status.read_text())
        except (OSError, ValueError):
            st = {}
        svc = (st.get("services") or {}).get(engine) or {}
        if ns not in (svc.get("ready") or []):
            raise DbError(f"The lab's {ENGINES[engine]} has no database for {ns} (yet).")
        cred = labagent.read_store(self._kube(), L.remote_key(ns, engine))
        name = L.db_name(ns)
        if cred.get("username") != name or cred.get("database") != name:
            raise DbError("The stored credentials are not this application's.")
        pod = self._ready_pod(L.LAB_NS, f"{L.LABEL}={engine},app.kubernetes.io/name={engine}")
        if not pod:
            raise DbError(f"The lab's {ENGINES[engine]} is not running.")
        return Target(engine, self.exec_prefix(L.LAB_NS, pod["metadata"]["name"], engine), name, name,
                      str(cred.get("password") or ""), ns, "lab")

    def devdb_pod(self, engine: str, ns: str) -> tuple[dict, str]:
        pod = self._ready_pod(ns, f"app.kubernetes.io/name={DEVDB_NAME},app.kubernetes.io/managed-by=containerizer")
        if not pod:
            raise DbError(f"There is no running restored dev database in {ns}.")
        ann = ((pod.get("metadata") or {}).get("annotations") or {}).get(DEVDB_ANNOTATION) or ""
        eng, _, database = ann.partition(":")
        if eng != engine or not DB_RE.fullmatch(database):
            raise DbError(f"The restored dev database in {ns} is not {ENGINES[engine]}.")
        return pod, database

    def devdb_target(self, engine: str, ns: str) -> Target:
        pod, database = self.devdb_pod(engine, ns)
        sec = self._kube().get(["-n", ns, "secret", DEVDB_NAME]) or {}
        try:
            pw = base64.b64decode(((sec.get("data") or {}).get("password") or "")).decode()
        except ValueError:
            pw = ""
        return Target(engine, self.exec_prefix(ns, pod["metadata"]["name"], DEVDB_NAME), DEVDB_USER, database, pw, ns,
                      "devdb")

    # -- requests -----------------------------------------------------------------------------

    def query(self, req: dict) -> dict:
        source, engine, ns, _ = self.check_request(req)
        stmts = req.get("statements")
        if not isinstance(stmts, list) or not 1 <= len(stmts) <= MAX_STATEMENTS or \
                not all(isinstance(s, str) and s.strip() and len(s) <= MAX_STATEMENT and "\x00" not in s for s in stmts):
            raise DbError(f"Give 1 to {MAX_STATEMENTS} statements of at most {MAX_STATEMENT} characters.")
        max_rows = req.get("max_rows", MAX_ROWS)
        if not isinstance(max_rows, int) or isinstance(max_rows, bool):
            max_rows = MAX_ROWS
        deadline = _deadline(req)
        target = self.lab_target(engine, ns) if source == "lab" else self.devdb_target(engine, ns)
        results = []
        for s in stmts:
            if time.time() + EXEC_TIMEOUT > deadline:
                results.append({"ok": False, "error": "Not run: the page would no longer be waiting for the answer."})
                break
            try:
                results.append({"ok": True, "result": run_statement(target, s, max_rows, self.runner)})
            except DbError as ex:
                results.append({"ok": False, "error": str(ex)})
                break
        return {"results": results}

    def delete(self, req: dict) -> tuple[dict, object]:
        """Drop (lab) or reset (dev database) the app's database; (answer, what to do after answering)."""
        from . import labservices as L
        source, engine, ns, _ = self.check_request(req)
        _deadline(req)
        kube = self._kube()
        if source == "lab":
            name = L.db_name(ns)                       # derived here, never from the request
            if req.get("confirm") != name:
                raise DbError("Type the database's name to confirm.")
            try:
                st = json.loads(self.lab_status.read_text())
            except (OSError, ValueError):
                st = {}
            if ns not in (((st.get("services") or {}).get(engine) or {}).get("apps") or []):
                raise DbError(f"The lab's {ENGINES[engine]} has no database for {ns}.")
            pod = self._ready_pod(L.LAB_NS, f"{L.LABEL}={engine},app.kubernetes.io/name={engine}")
            if not pod:
                raise DbError(f"The lab's {ENGINES[engine]} is not running.")
            rc, out, err, problem = self.runner(self.exec_prefix(L.LAB_NS, pod["metadata"]["name"], engine) +
                                                L.provision_command(engine), drop_script(engine, name), timeout=120)
            if rc or problem:
                raise DbError("The database could not be dropped: " + _clean_error(err or out or problem, ""))
            self.forget_provisioned(engine, ns)
            log(f"dbdelete: {req.get('requested_by')} dropped {name} on the lab's {engine} ({ns})")
            return ({"deleted": name, "message": "recreate"}, lambda: self.recreate(engine, ns))
        pod, database = self.devdb_pod(engine, ns)
        if req.get("confirm") != database:
            raise DbError("Type the database's name to confirm.")
        kube.run(["-n", ns, "rollout", "restart", f"deployment/{DEVDB_NAME}"], timeout=60)
        log(f"dbdelete: {req.get('requested_by')} reset the restored dev database {database} in {ns}")
        return {"deleted": database, "message": "restore"}, None

    def forget_provisioned(self, engine: str, ns: str) -> None:
        """The lab agent provisions again only what it has not marked done (labagent._shared)."""
        from . import labagent
        path = self.lab_state or labagent.STATE_PATH
        state = labagent.load_state(path)
        if ns in (state.get(engine) or {}):
            state[engine].pop(ns)
            labagent.save_json(path, state, 0o600)

    def recreate(self, engine: str, ns: str) -> None:
        """After the answer: the lab agent's reconcile (its own unit, as on the timer) creates the database again
        empty with the same login; then the application's Deployments restart and create their schema."""
        # A run the timer started before the drop may write the old "provisioned" mark back when it ends, and
        # `systemctl start` only waits for such a run: forget the mark again and run once more.
        for again in (False, True):
            try:
                if again:
                    self.forget_provisioned(engine, ns)
                (self.systemctl or _systemctl)(["start", "containerizer-lab.service"])
            except Exception as ex:  # noqa: BLE001 - the timer tries again within 2 minutes
                log(f"dbdelete: lab agent: {type(ex).__name__}: {ex}")
        kube = self._kube()
        data = kube.get(["-n", ns, "deployments"]) or {}
        for d in data.get("items") or []:
            name = (d.get("metadata") or {}).get("name")
            if name and name != DEVDB_NAME:
                kube.run(["-n", ns, "rollout", "restart", f"deployment/{name}"], check=False, timeout=60)


def _deadline(req: dict) -> float:
    exp = req.get("expires_at")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool) or time.time() > exp:
        raise DbError("The request expired before the appliance got to it.")
    return float(exp)


def _systemctl(args: list[str]) -> None:
    subprocess.run(["systemctl", *args], capture_output=True, timeout=600, check=False)


def results_owner_check(ns: str, app_id: int) -> bool:
    """Whether the results database maps the namespace to the application (cz.vSandboxNamespace), asked with
    the scan worker's login, as the system agent does for the restart plan."""
    from . import sysagent
    from .sqlstore import connect
    cs = sysagent.read_env(sysagent.P.sql_env).get("CZ_SQL_SCANNER_CS")
    conn = connect(cs, sysagent.P.sql_secret.read_text().strip())
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cz.vSandboxNamespace WHERE Namespace = %s AND ApplicationId = %s", (ns, app_id))
        return int(cur.fetchone()[0]) > 0
    finally:
        conn.close()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def write_answer(directory: Path, ident_: str, answer: dict) -> None:
    """answers/<id>.json, for root and the web UI's group only (it may hold the database's rows)."""
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / f".{ident_}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        json.dump(answer, f)
    try:
        import grp
        os.chown(tmp, 0, grp.getgrnam("cz-web").gr_gid)
    except (KeyError, PermissionError, OSError):
        pass
    os.replace(tmp, directory / f"{ident_}.json")


def clean_answers(directory: Path, older_than: float = 300) -> None:
    """Answers nobody picked up (the page stopped waiting)."""
    now = time.time()
    try:
        for p in directory.glob("*.json"):
            try:
                if now - p.stat().st_mtime > older_than:
                    p.unlink()
            except OSError:
                pass
    except OSError:
        pass


def agent_request(req: dict, answers: Path = ANSWERS_DIR, agent: Agent | None = None) -> None:
    """The system agent's handling of `dbquery` and `dbdelete`: always answers (a refusal too) when the id is
    well-formed; nothing in the request is trusted."""
    ident_ = req.get("id")
    if not isinstance(ident_, str) or not ID_RE.fullmatch(ident_):
        log("dbquery: request without a valid id ignored")
        return
    agent = agent or Agent()
    clean_answers(answers)
    after = None
    action = req.get("action")
    try:
        if action == "dbquery":
            answer = agent.query(req)
            log(f"dbquery: {str(req.get('requested_by'))[:256]} ran {len(req.get('statements') or [])} statement(s) "
                f"in {req.get('namespace')} ({req.get('source')} {req.get('engine')})")
        elif action == "dbdelete":
            answer, after = agent.delete(req)
        else:
            raise DbError("Unknown request.")
    except DbError as ex:
        answer = {"error": str(ex)}
    except Exception as ex:  # noqa: BLE001 - the page gets a plain answer, the journal the details
        log(f"{action}: {type(ex).__name__}: {ex}")
        answer = {"error": "The appliance could not run it; the details are in the system agent's journal."}
    answer["id"] = ident_
    write_answer(answers, ident_, answer)
    if after:
        after()
