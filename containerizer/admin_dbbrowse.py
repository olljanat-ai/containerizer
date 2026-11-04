"""Admin -> Dev databases: the database browser of an application's sandbox databases (administrators and operators).

Under /admin/dev-databases/<application id>:

- GET  browse?d=<source>-<engine>@<namespace>[&schema=&table=[&row=<key json>|&new=1][&f=&op=&v=&sort=&desc=1&page=]]
       the tables, one table's rows (50 a page, filter, sort), a row's editor, a new row's form;
- POST row   (do=update|insert|delete) one row by its primary key;
- POST sql   one statement (the result table, the rows affected or the error);
- POST drop  the database deleted (typed confirmation): a lab-service database is created again empty and the
       application restarts; a restored dev database is restored again from its backup.

`d` names one of the application's databases: a lab-service database (SQL Server, PostgreSQL or MySQL in
containerizer-lab, lab-status.json) or the restored dev database (cz.DevDatabase), in one of the
application's sandbox namespaces (cz.vSandboxNamespace: its own and its Make it A variants, the latest first).
Everything runs through the system agent (dbbrowse.py), which checks it all again. Every change is recorded
in cz.DatabaseEdit before it runs (copied to the change history by a trigger); if it cannot be recorded, it
does not run. Reads are logged like other results views when CONTAINERIZER_VIEW_AUDIT is on.
"""
from __future__ import annotations

import html
import json
import re
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from . import dbbrowse as D
from .admin import Response, page, redirect

e = html.escape
TAB = "dev-databases"
SOURCE_TEXT = {"lab": "lab service", "devdb": "restored dev database"}
NOTICES = {"saved": ("ok", "Row saved."), "added": ("ok", "Row added."), "deleted": ("ok", "Row deleted."),
           "nochange": ("info", "Nothing changed, so nothing was saved."),
           "nomatch": ("bad", "No row matched: it was changed or deleted in the meantime. Nothing was saved."),
           "confirm": ("bad", "Not deleted: tick the box to confirm."),
           "dropconfirm": ("bad", "Not deleted: type the database's name exactly to confirm."),
           "dropped-lab": ("ok", "Database deleted. The lab agent creates it again empty, with the same login and "
                                 "password, and the application restarts so it can create its tables again. Give it a "
                                 "minute."),
           "dropped-devdb": ("ok", "Database deleted. The restored dev database restarts and restores the uploaded backup "
                                   "again; it is back once the restore is done (as long as the first restore took)."),
           "unknown": ("bad", "That database is not one of this application's databases in the sandbox (any more)."),
           "norecord": ("bad", "Not run: the change history could not record it. Run `containerizer db init` "
                               "(schema 38).")}
CACHE_TTL = 60
_cache: dict = {}
_lock = threading.Lock()


@dataclass
class Db:
    source: str                 # lab, devdb
    engine: str                 # sqlserver, postgres, mysql
    namespace: str
    variant: bool = False       # a Make it A variant's namespace
    database: str = ""          # the database's name (what the agent derives too)
    ready: bool = True

    @property
    def key(self) -> str:
        return f"{self.source}-{self.engine}@{self.namespace}"

    @property
    def title(self) -> str:
        return f"{D.ENGINES[self.engine]} ({SOURCE_TEXT[self.source]})"


def may_use(a) -> bool:
    return bool(a.admin or a.operator)


def _rows(conn, sql: str, params=None) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def namespaces(conn, app_id: int) -> list[dict] | None:
    """The application's sandbox namespaces, the latest first; None before schema 38 (no access to the view)."""
    try:
        return _rows(conn, "SELECT Namespace, Variant, CheckedAt FROM cz.vSandboxNamespace WHERE ApplicationId = %s "
                           "ORDER BY CheckedAt DESC, Namespace", (app_id,))
    except Exception as ex:  # noqa: BLE001 - a database from before schema 38
        conn.rollback()
        print(f"database browser: sandbox namespaces of {app_id}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return None


def lab_status(adm) -> dict:
    from .admin_lab import lab_status as read
    return read(adm)


def _devdb_row(conn, app_id: int) -> dict | None:
    try:
        r = _rows(conn, "SELECT Engine, DatabaseName, FileName FROM cz.DevDatabase WHERE ApplicationId = %s", (app_id,))
    except Exception:  # noqa: BLE001
        conn.rollback()
        return None
    return r[0] if r else None


def databases(adm, conn, app_id: int, nss: list[dict] | None = None) -> list[Db]:
    """The application's databases in the sandbox: per namespace (the latest first), its lab-service databases
    and its restored dev database."""
    from . import labservices as L
    nss = namespaces(conn, app_id) if nss is None else nss
    if not nss:
        return []
    services = lab_status(adm).get("services") or {}
    dev = _devdb_row(conn, app_id)
    out = []
    for n in nss:
        ns = n["Namespace"]
        for eng in D.ENGINES:
            st = services.get(eng) or {}
            if ns in (st.get("apps") or []):
                out.append(Db("lab", eng, ns, bool(n["Variant"]), L.db_name(ns), ns in (st.get("ready") or [])))
        if dev and dev["Engine"] in D.ENGINES:
            out.append(Db("devdb", dev["Engine"], ns, bool(n["Variant"]), dev["DatabaseName"]))
    return out


def find(dbs: list[Db], key: str) -> Db | None:
    return next((d for d in dbs if d.key == key), None)


def notice_html(code: str) -> str:
    if code not in NOTICES:
        return ""
    kind, text = NOTICES[code]
    return f"<div class='notice notice-{kind}' role='status'>{e(text)}</div>"


# =============================================================================== talking to the agent

def ask(adm, s, app_id: int, db: Db, statements: list[str], max_rows: int = D.PAGE + 1) -> tuple[list | None, str | None]:
    """(results, None) or (None, why not)."""
    ans = adm.system.ask("dbquery", s.user, s.name, wait=D.ANSWER_WAIT, application_id=app_id, source=db.source,
                         engine=db.engine, namespace=db.namespace, statements=statements, max_rows=max_rows)
    if ans is None:
        return None, (f"The appliance did not answer within {D.ANSWER_WAIT} seconds. The system agent may be busy "
                      "(an upgrade, another request); try again in a moment.")
    if ans.get("error"):
        return None, str(ans["error"])
    return list(ans.get("results") or []), None


def ask_one(adm, s, app_id, db, statement, max_rows=D.PAGE + 1) -> tuple[dict | None, str | None]:
    res, err = ask(adm, s, app_id, db, [statement], max_rows)
    if err:
        return None, err
    if not res:
        return None, "The appliance gave no answer."
    if not res[0].get("ok"):
        return None, str(res[0].get("error") or "The statement failed.")
    return res[0].get("result") or {}, None


def columns(adm, s, app_id, db: Db, schema: str, table: str, fresh: bool = False) -> tuple[list[D.Column] | None, str | None]:
    k = (app_id, db.key, schema, table)
    with _lock:
        hit = _cache.get(k)
    if hit and not fresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1], None
    res, err = ask_one(adm, s, app_id, db, D.columns_sql(db.engine, schema, table), D.MAX_ROWS)
    if err:
        return None, err
    cols = D.parse_columns(res)
    with _lock:
        _cache[k] = (time.time(), cols)
    return cols, None


def forget(db: Db) -> None:
    with _lock:
        for k in [k for k in _cache if k[1] == db.key]:
            _cache.pop(k, None)


def record(conn, app_id: int, db: Db, kind: str, table: str | None, statement: str) -> int | None:
    """cz.DatabaseEdit before the statement runs (the trigger copies it to the change history); None when it
    could not be recorded: then it does not run."""
    try:
        cur = conn.cursor()
        # (no OUTPUT clause: the table has a trigger)
        cur.execute("INSERT cz.DatabaseEdit (ApplicationId, Namespace, Source, Engine, Kind, TableName, Statement) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s); SELECT CAST(SCOPE_IDENTITY() AS int)",
                    (app_id, db.namespace, db.source, db.engine, kind, (table or "")[:300] or None, statement))
        row = cur.fetchone()
        conn.commit()
        return int(row[0]) if row else None
    except Exception as ex:  # noqa: BLE001 - a database from before schema 38: fail closed
        conn.rollback()
        print(f"database browser: could not record a change of {app_id}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return None


def outcome(conn, ident: int, text: str) -> None:
    try:
        conn.cursor().execute("UPDATE cz.DatabaseEdit SET Outcome = %s WHERE DatabaseEditId = %s", (text[:1000], ident))
        conn.commit()
    except Exception as ex:  # noqa: BLE001 - the statement is recorded already
        conn.rollback()
        print(f"database browser: outcome of {ident}: {type(ex).__name__}: {ex}", file=sys.stderr)


def _result_outcome(res: dict | None, err: str | None) -> str:
    if err:
        return "error: " + err
    if res.get("kind") == "count":
        return f"{res.get('rowcount', 0)} row(s) affected"
    if res.get("kind") == "rows":
        return f"{len(res.get('rows') or [])} row(s) returned" + (" (more not shown)" if res.get("truncated") else "")
    return "done"


# =============================================================================== links and small pieces

def _href(app_id: int, db: Db, **q) -> str:
    params = {"d": db.key, **{k: v for k, v in q.items() if v not in (None, "", False)}}
    return f"/admin/dev-databases/{app_id}/browse?" + urlencode(params)


def _cell(v, limit: int = 160) -> str:
    if v is None:
        return "<span class='null'>NULL</span>"
    v = str(v)
    return e(v if len(v) <= limit else v[:limit] + "…")


def _crumbs(app_id: int, app_name: str, db: Db, schema: str = "", table: str = "", last: str = "") -> str:
    parts = ["<a href='/admin/dev-databases'>Dev databases</a>", f"<a href='/admin/dev-databases/{app_id}'>{e(app_name)}</a>",
             f"<a href='{e(_href(app_id, db))}'>{e(db.title)} · {e(db.namespace)}</a>"]
    if table:
        parts.append(f"<a href='{e(_href(app_id, db, schema=schema, table=table))}'>{e(_tname(db, schema, table))}</a>")
    if last:
        parts.append(e(last))
    return f"<p class='crumbs'>{' › '.join(parts)}</p>"


def _tname(db: Db, schema: str, table: str) -> str:
    return table if db.engine == "mysql" or not schema else f"{schema}.{table}"


def _hidden(**kv) -> str:
    return "".join(f"<input type='hidden' name='{e(k)}' value='{e(str(v))}'>" for k, v in kv.items() if v is not None)


def picker(app_id: int, dbs: list[Db], current: Db | None) -> str:
    """Which database: each lab-service and dev database in each namespace, the latest namespace first."""
    opts = "".join(f"<option value='{e(d.key)}'{' selected' if current and d.key == current.key else ''}>"
                   f"{e(d.title)} · {e(d.namespace)}{' (Make it A variant)' if d.variant else ''}"
                   f"{'' if d.ready else ' (not ready yet)'}</option>" for d in dbs)
    return (f"<form method='get' action='/admin/dev-databases/{app_id}/browse' class='formrow dbpick'>"
            f"<label for='d'>Database</label><select id='d' name='d'>{opts}</select>"
            f"<button class='secondary'>Open</button></form>")


def section(adm, conn, s, app_id: int) -> str:
    """The per-application page's list of its sandbox databases, each a link to the browser."""
    if not adm.system:
        return ""
    nss = namespaces(conn, app_id)
    if nss is None:
        return ("<h2>Databases in the sandbox</h2><p class='muted'>The database browser needs the database schema of "
                "this version: run <code>containerizer db init</code> (schema 38).</p>")
    dbs = databases(adm, conn, app_id, nss)
    if not dbs:
        why = ("It has no namespace in the sandbox yet." if not nss else
               "It uses no lab-service database (SQL Server, PostgreSQL or MySQL) and has no restored dev database.")
        return (f"<h2>Databases in the sandbox</h2><p class='muted'>{e(why)} MongoDB, Redis and the other lab "
                "services are not browsed here.</p>")
    rows = "".join(f"<tr><td><a href='{e(_href(app_id, d))}'>{e(d.title)}</a></td><td>{e(d.namespace)}"
                   f"{' <span class=muted>(Make it A variant)</span>' if d.variant else ''}</td><td>{e(d.database)}</td>"
                   f"<td>{'' if d.ready else '<span class=muted>not ready yet</span>'}</td></tr>" for d in dbs)
    return ("<h2>Databases in the sandbox</h2><p class='muted'>Look at and fix the application's data: tables, rows, "
            "SQL. Statements run as the application's own database login, in its own database only, and every change "
            "is recorded in the change history.</p>"
            f"<table class='audit'><thead><tr><th>Database</th><th>Namespace</th><th>Name</th><th></th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")


def apps_with_databases(adm, conn) -> list[dict]:
    """For the listing: applications with a lab-service database or a dev database backup."""
    services = lab_status(adm).get("services") or {}
    lab_ns = {ns: eng for eng in D.ENGINES for ns in ((services.get(eng) or {}).get("apps") or [])}
    out: dict[int, dict] = {}
    try:
        for r in _rows(conn, "SELECT n.Namespace, n.ApplicationId, COALESCE(a.DisplayName, a.Name) AS AppName "
                             "FROM cz.vSandboxNamespace n JOIN cz.Application a ON a.ApplicationId = n.ApplicationId "
                             "WHERE a.Retired = 0"):
            if r["Namespace"] in lab_ns:
                x = out.setdefault(r["ApplicationId"], {"id": r["ApplicationId"], "name": r["AppName"], "dbs": set(), "ns": set()})
                x["dbs"].add(f"{D.ENGINES[lab_ns[r['Namespace']]]} (lab service)")
                x["ns"].add(r["Namespace"])
    except Exception:  # noqa: BLE001 - before schema 38
        conn.rollback()
    try:
        for r in _rows(conn, "SELECT d.ApplicationId, d.Engine, COALESCE(a.DisplayName, a.Name) AS AppName FROM cz.DevDatabase d "
                             "JOIN cz.Application a ON a.ApplicationId = d.ApplicationId"):
            x = out.setdefault(r["ApplicationId"], {"id": r["ApplicationId"], "name": r["AppName"], "dbs": set(), "ns": set()})
            x["dbs"].add(f"{D.ENGINES.get(r['Engine'], r['Engine'])} (restored dev database)")
    except Exception:  # noqa: BLE001 - dev databases not configured
        conn.rollback()
    return sorted(out.values(), key=lambda x: str(x["name"]).lower())


# =============================================================================== pages

def _app_name(conn, app_id: int) -> str | None:
    r = _rows(conn, "SELECT COALESCE(DisplayName, Name) AS N FROM cz.Application WHERE ApplicationId = %s", (app_id,))
    return r[0]["N"] if r else None


def _error_box(text: str) -> str:
    return f"<div class='notice notice-bad' role='alert'><b>The database said:</b><pre class='code'>{e(text)}</pre></div>"


def _context(adm, conn, s, a, app_id: int, key: str):
    """(application name, its databases, the chosen one) or a Response."""
    if not adm.system:
        return Response(404, adm._shell(s, a, "Not available", TAB, "<p>The database browser runs on the appliance.</p>"))
    name = _app_name(conn, app_id)
    if name is None:
        return Response(404, page("Not found", "<h1>Application not found</h1>"))
    dbs = databases(adm, conn, app_id)
    db = find(dbs, key) if key else (dbs[0] if dbs else None)
    if db is None:
        body = notice_html("unknown") + section(adm, conn, s, app_id)
        return Response(404 if key else 200, adm._shell(s, a, f"Databases: {name}", TAB, body))
    return name, dbs, db


def browse(adm, conn, s, a, app_id: int, q: dict, path: str) -> Response:
    if not may_use(a):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    g = lambda k: q.get(k, [""])[0]    # noqa: E731
    ctx = _context(adm, conn, s, a, app_id, g("d"))
    if isinstance(ctx, Response):
        return ctx
    name, dbs, db = ctx
    adm.log_access(s.user, s.name, "view", path[:400], app_id)
    schema, table = g("schema")[:128], g("table")[:128]
    flash = notice_html(g("notice"))
    if not table:
        return _tables(adm, conn, s, a, app_id, name, dbs, db, flash)
    if g("row") or g("new"):
        return _editor(adm, s, a, app_id, name, db, schema, table, g("row"), flash)
    return _table(adm, s, a, app_id, name, db, schema, table, q, flash)


def _tables(adm, conn, s, a, app_id, name, dbs, db: Db, flash: str, sql: str = "", result: str = "") -> Response:
    res, err = ask_one(adm, s, app_id, db, D.tables_sql(db.engine), D.MAX_ROWS)
    if err:
        listing = _error_box(err)
    elif not res.get("rows"):
        listing = "<p class='muted'>No tables yet. An application that creates its own (EnsureCreated, migrations) does so when it starts.</p>"
    else:
        cols = res["columns"]
        rows = []
        for r in res["rows"]:
            d = dict(zip(cols, r))
            label = _tname(db, d.get("schema") or "", d.get("name") or "")
            rows.append(f"<tr><td><a href='{e(_href(app_id, db, schema=d.get('schema'), table=d.get('name')))}'>{e(label)}</a></td>"
                        f"<td>{e(d.get('kind') or '')}</td><td class='num'>{e(str(d.get('rows'))) if d.get('rows') not in (None, '') else '-'}</td></tr>")
        listing = ("<table class='audit'><thead><tr><th>Table</th><th>Kind</th><th class='num'>Rows (about)</th></tr></thead>"
                   f"<tbody>{''.join(rows)}</tbody></table>")
    body = (_crumbs(app_id, name, db) + picker(app_id, dbs, db) + flash +
            f"<p class='muted'>Database <b>{e(db.database)}</b> in namespace <b>{e(db.namespace)}</b>. Statements run as the "
            "application's own login, in this database only.</p>"
            f"<h2>Tables</h2>{listing}{sql_form(adm, s, app_id, db, sql)}{result}"
            f"{drop_form(adm, s, app_id, db)}{recent(conn, app_id, db)}")
    return Response(200, adm._shell(s, a, f"Database: {name}", TAB, body))


def sql_form(adm, s, app_id: int, db: Db, sql: str = "") -> str:
    batch = " One batch: no <code>GO</code>." if db.engine == "sqlserver" else ""
    return (f"<h2 id='sql'>SQL</h2><form method='post' action='/admin/dev-databases/{app_id}/sql' class='edit wide'>"
            f"{adm._csrf(s)}{_hidden(d=db.key)}<label for='sqltext'>Statement <span class='muted'>(recorded in the change "
            f"history, with its values; at most {D.MAX_ROWS} rows are shown)</span></label>"
            f"<textarea id='sqltext' name='sql' class='code' rows='6' maxlength='{D.MAX_STATEMENT}' spellcheck='false'>{e(sql)}</textarea>"
            f"<div><button>Run</button> <span class='muted small'>Stopped after {D.STATEMENT_TIMEOUT} seconds.{batch}</span></div></form>")


def drop_form(adm, s, app_id: int, db: Db) -> str:
    if db.source == "lab":
        what = (f"Drops database <b>{e(db.database)}</b> on the lab's {e(D.ENGINES[db.engine])}, with everything in it. The lab "
                f"agent creates it again straight away, empty, with the same login and password, and the application's "
                f"Deployments in <b>{e(db.namespace)}</b> restart, so an application that creates its own tables (EnsureCreated, "
                f"migrations, seed data) fills it again. No other application's database is touched.")
    else:
        what = (f"Restarts the restored dev database in <b>{e(db.namespace)}</b>. It keeps its data inside its pod only, so it "
                f"is restored again from the uploaded backup: every change made since the last restore is gone, and it is "
                f"back once the restore is done (as long as the first restore took). To stop restoring the backup at all, "
                f"remove the backup on the application's Dev databases page.")
    return (f"<h2>Delete the database</h2><p>{what}</p>"
            f"<form method='post' action='/admin/dev-databases/{app_id}/drop' class='edit danger'>{adm._csrf(s)}{_hidden(d=db.key)}"
            f"<label for='confirmname'>Type <code>{e(db.database)}</code> to confirm</label>"
            f"<input id='confirmname' name='confirm' autocomplete='off' required>"
            f"<div><button>Delete database</button></div></form>")


def recent(conn, app_id: int, db: Db) -> str:
    try:
        rows = _rows(conn, "SELECT TOP (20) ChangedAt, ChangedBy, Kind, TableName, Statement, Outcome FROM cz.DatabaseEdit "
                           "WHERE ApplicationId = %s AND Namespace = %s ORDER BY ChangedAt DESC, DatabaseEditId DESC",
                     (app_id, db.namespace))
    except Exception:  # noqa: BLE001 - before schema 38
        conn.rollback()
        return ""
    if not rows:
        return ""
    from .admin import _d
    trs = "".join(f"<tr><td class='nowrap'>{_d(r['ChangedAt'])}</td><td>{e(r['ChangedBy'])}</td><td>{e(r['Kind'])}</td>"
                  f"<td><pre class='code'>{e(r['Statement'][:2000])}</pre></td><td class='small'>{e(r['Outcome'] or '')}</td></tr>"
                  for r in rows)
    return (f"<h2>Recent changes in {e(db.namespace)}</h2><table class='audit'><thead><tr><th>When</th><th>Who</th><th>What</th>"
            f"<th>Statement</th><th>Outcome</th></tr></thead><tbody>{trs}</tbody></table>"
            f"<p class='muted small'>All of them are in the <a href='/admin/audit?table=DatabaseEdit'>change history</a>.</p>")


def _kind(db: Db, adm, s, app_id, schema, table) -> str:
    """table or view (for the read-only note); asked only when the table has no primary key."""
    res, err = ask_one(adm, s, app_id, db, D.tables_sql(db.engine), D.MAX_ROWS)
    for r in (res or {}).get("rows") or []:
        d = dict(zip(res["columns"], r))
        if d.get("name") == table and (db.engine == "mysql" or d.get("schema") == schema):
            return d.get("kind") or "table"
    return "table"


def _table(adm, s, a, app_id, name, db: Db, schema, table, q, flash) -> Response:
    g = lambda k: q.get(k, [""])[0]    # noqa: E731
    cols, err = columns(adm, s, app_id, db, schema, table)
    crumbs = _crumbs(app_id, name, db, schema, table)
    if err or not cols:
        body = crumbs + flash + (_error_box(err) if err else "<p class='muted'>There is no such table (any more).</p>")
        return Response(200, adm._shell(s, a, f"Database: {name}", TAB, body))
    names = [c.name for c in cols]
    f, op, v = g("f"), g("op"), g("v")
    filt = (f, op, v) if f in names and op in D.FILTER_OPS else None
    sort = g("sort") if g("sort") in names else None
    desc = g("desc") == "1"
    pg = int(g("page")) if g("page").isdigit() and int(g("page")) < 100000 else 0
    try:
        stmt = D.rows_sql(db.engine, schema, table, cols, filt, sort, desc, pg * D.PAGE, D.PAGE + 1)
    except D.DbError as ex:
        stmt, err = None, str(ex)
    res = None
    if stmt:
        res, err = ask_one(adm, s, app_id, db, stmt, D.PAGE + 1)
    ro = D.read_only_reason(cols)
    if ro and "primary key" in ro and _kind(db, adm, s, app_id, schema, table) == "view":
        ro = D.read_only_reason(cols, "view")
    base = {"schema": schema, "table": table, "f": f if filt else None, "op": op if filt else None,
            "v": v if filt and op in ("eq", "contains") else None}
    heads = []
    for c in cols:
        nd = "1" if sort == c.name and not desc else None
        arrow = (" ▼" if desc else " ▲") if sort == c.name else ""
        mark = " <span class='dbkey'>key</span>" if c.pk else ""
        heads.append(f"<th><a href='{e(_href(app_id, db, **base, sort=c.name, desc=nd))}'>{e(c.name)}{arrow}</a>{mark}"
                     f"<span class='dbtype'>{e(c.type)}</span></th>")
    pk = D.primary_key(cols)
    trs = []
    data = (res or {}).get("rows") or []
    for r in data[:D.PAGE]:
        edit = ""
        if not ro:
            key = {c.name: r[names.index(c.name)] for c in pk}
            edit = f"<td class='nowrap'><a href='{e(_href(app_id, db, schema=schema, table=table, row=json.dumps(key)))}'>Edit</a></td>"
        trs.append(f"<tr>{edit}{''.join(f'<td>{_cell(x, 60)}</td>' for x in r)}</tr>")
    if res is not None and not data:
        trs.append(f"<tr><td colspan='{len(cols) + (0 if ro else 1)}' class='muted'>No rows{' match' if filt else ''}.</td></tr>")
    grid = (f"<div class='dbwrap'><table class='dbrows'><thead><tr>{'' if ro else '<th></th>'}{''.join(heads)}</tr></thead>"
            f"<tbody>{''.join(trs)}</tbody></table></div>") if res is not None else ""
    nav = []
    if pg > 0:
        nav.append(f"<a href='{e(_href(app_id, db, **base, sort=sort, desc='1' if desc else None, page=pg - 1 or None))}'>← Previous</a>")
    nav.append(f"<span class='muted'>Rows {pg * D.PAGE + 1 if data else 0}-{pg * D.PAGE + min(len(data), D.PAGE)}</span>")
    if len(data) > D.PAGE:
        nav.append(f"<a href='{e(_href(app_id, db, **base, sort=sort, desc='1' if desc else None, page=pg + 1))}'>Next →</a>")
    opts = "".join(f"<option value='{e(n)}'{' selected' if filt and n == f else ''}>{e(n)}</option>" for n in names)
    ops = "".join(f"<option value='{k}'{' selected' if filt and k == op else ''}>{e(t)}</option>" for k, t in D.FILTER_OPS.items())
    filt_form = (f"<form method='get' action='/admin/dev-databases/{app_id}/browse' class='formrow dbfilter'>"
                 f"{_hidden(d=db.key, schema=schema, table=table)}<label for='f'>Where</label>"
                 f"<select id='f' name='f' aria-label='Column'>{opts}</select><select name='op' aria-label='Condition'>{ops}</select>"
                 f"<input name='v' value='{e(v if filt else '')}' aria-label='Value' placeholder='value'>"
                 f"<button class='secondary'>Filter</button>"
                 + (f" <a href='{e(_href(app_id, db, schema=schema, table=table))}'>Clear</a>" if filt else "") + "</form>")
    add = "" if ro else f"<p><a class='button' href='{e(_href(app_id, db, schema=schema, table=table, new=1))}'>Add a row</a></p>"
    note = f"<p class='muted'>Read-only here. {e(ro)}</p>" if ro else ""
    body = (crumbs + flash + note + filt_form + (_error_box(err) if err else "") + grid +
            f"<div class='pager'>{' '.join(nav)}</div>" + add)
    return Response(200, adm._shell(s, a, f"{_tname(db, schema, table)}: {name}", TAB, body))


def _field(i: int, c: D.Column, value, new: bool) -> str:
    """One column of the row editor: its value (a text box, a textarea for long or multi-line text), NULL and,
    for a new row, its default."""
    tags = ", ".join(x for x in (c.type, "key" if c.pk else "", "automatic" if c.auto else "",
                                 "computed" if c.generated else "", "not NULL" if not c.nullable else "") if x)
    label = f"<label for='v{i}'>{e(c.name)}<span class='dbtype'>{e(tags)}</span></label>"
    if not c.editable:
        why = "computed by the database" if c.generated else "binary: change it with SQL"
        shown = "" if new else _cell(value, 400)
        return (f"<div class='dbfield'>{label}<div class='dbval'>{shown} <span class='muted small'>({e(why)})</span></div>"
                f"<div></div></div>")
    text = "" if value is None else str(value)
    long = "\n" in text or len(text) > 80
    box = (f"<textarea id='v{i}' name='v{i}' rows='{min(12, text.count(chr(10)) + 2)}' class='code'>{e(text)}</textarea>"
           if long else f"<input id='v{i}' name='v{i}' value='{e(text)}'>")
    opts = []
    if c.nullable:
        opts.append(f"<label class='check'><input type='checkbox' name='n{i}' value='1'{' checked' if value is None and not new else ''}> NULL</label>")
    if new:
        dflt = c.auto or c.default is not None
        opts.append(f"<label class='check'><input type='checkbox' name='x{i}' value='1'{' checked' if dflt else ''}> default</label>")
    orig = "" if new else _hidden(**{f"o{i}": text}) + (_hidden(**{f"on{i}": "1"}) if value is None else "")
    return (f"<div class='dbfield'>{label}<div>{box}{_hidden(**{f'c{i}': c.name})}{orig}</div>"
            f"<div class='opts'>{''.join(opts)}</div></div>")


def _editor(adm, s, a, app_id, name, db: Db, schema, table, row: str, flash: str) -> Response:
    cols, err = columns(adm, s, app_id, db, schema, table)
    new = not row
    crumbs = _crumbs(app_id, name, db, schema, table, "New row" if new else "Edit row")
    ro = D.read_only_reason(cols or [])
    if err or not cols or ro:
        body = crumbs + (_error_box(err) if err else f"<p class='muted'>{e(ro or 'There is no such table (any more).')}</p>")
        return Response(200, adm._shell(s, a, f"Database: {name}", TAB, body))
    values = [None] * len(cols)
    key = None
    if not new:
        try:
            key = json.loads(row)
            if not isinstance(key, dict) or not all(v is None or isinstance(v, str) for v in key.values()):
                raise ValueError
            stmt = D.row_sql(db.engine, schema, table, cols, key)
        except (ValueError, D.DbError):
            return Response(400, adm._shell(s, a, "Not found", TAB, crumbs + "<p>That row cannot be picked out.</p>"))
        res, err = ask_one(adm, s, app_id, db, stmt, 2)
        if err:
            return Response(200, adm._shell(s, a, f"Database: {name}", TAB, crumbs + _error_box(err)))
        if not res.get("rows"):
            return Response(200, adm._shell(s, a, f"Database: {name}", TAB, crumbs + notice_html("nomatch")))
        values = res["rows"][0]
    fields = "".join(_field(i, c, values[i] if i < len(values) else None, new) for i, c in enumerate(cols))
    hidden = _hidden(d=db.key, schema=schema, table=table, key=json.dumps(key) if key is not None else None,
                     do="insert" if new else "update")
    form = (f"<form method='post' action='/admin/dev-databases/{app_id}/row' class='edit wide'>{adm._csrf(s)}{hidden}"
            f"{fields}<div><button>{'Add the row' if new else 'Save'}</button> "
            f"<a href='{e(_href(app_id, db, schema=schema, table=table))}'>Cancel</a></div></form>")
    delete = "" if new else (
        f"<form method='post' action='/admin/dev-databases/{app_id}/row' class='edit danger'>{adm._csrf(s)}"
        f"{_hidden(d=db.key, schema=schema, table=table, key=json.dumps(key), do='delete')}"
        f"<label class='check'><input type='checkbox' name='confirm' value='yes' required> Delete this row</label>"
        f"<div><button>Delete the row</button></div></form>")
    intro = ("<p class='muted'>Only the values you change are saved. A value is passed to the database as text, "
             "which converts it to the column's type; tick NULL for no value.</p>")
    body = crumbs + flash + intro + form + delete
    return Response(200, adm._shell(s, a, f"{'New row' if new else 'Edit row'}: {_tname(db, schema, table)}", TAB, body))


def _nl(v: str) -> str:
    return v.replace("\r\n", "\n")


def save_row(adm, conn, s, a, app_id: int, form: dict) -> Response:
    if not may_use(a):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    g = lambda k: form.get(k, [""])[0]    # noqa: E731
    ctx = _context(adm, conn, s, a, app_id, g("d"))
    if isinstance(ctx, Response):
        return ctx
    name, _, db = ctx
    schema, table, do = g("schema")[:128], g("table")[:128], g("do")
    back = lambda code, **kw: redirect(_href(app_id, db, schema=schema, table=table, notice=code, **kw))   # noqa: E731
    cols, err = columns(adm, s, app_id, db, schema, table, fresh=True)
    if err or not cols:
        body = _crumbs(app_id, name, db, schema, table) + _error_box(err or "There is no such table (any more).")
        return Response(200, adm._shell(s, a, f"Database: {name}", TAB, body))
    by = {c.name: c for c in cols}
    try:
        if do in ("update", "delete"):
            key = json.loads(g("key") or "null")
            if not isinstance(key, dict) or not all(v is None or isinstance(v, str) for v in key.values()):
                raise D.DbError("The row is picked out by its whole primary key.")
        if do == "delete":
            if g("confirm") != "yes":
                return back("confirm", row=g("key"))
            stmt = D.delete_sql(db.engine, schema, table, cols, key)
        elif do in ("update", "insert"):
            values = {}
            for k in form:
                m = re.fullmatch(r"c(\d{1,4})", k)
                if not m:
                    continue
                i, col = m[1], g(k)
                if col not in by or not by[col].editable:
                    continue
                new = None if g(f"n{i}") == "1" else _nl(g(f"v{i}"))
                if do == "insert":
                    if g(f"x{i}") != "1":
                        values[col] = new
                    continue
                orig = None if g(f"on{i}") == "1" else _nl(g(f"o{i}"))
                if new != orig:
                    values[col] = new
            if do == "update" and not values:
                return back("nochange", row=g("key"))
            stmt = D.update_sql(db.engine, schema, table, cols, key, values) if do == "update" else \
                D.insert_sql(db.engine, schema, table, cols, values)
        else:
            return Response(400, page("Bad request", "<h1>Bad request</h1>"))
    except (ValueError, D.DbError) as ex:
        body = _crumbs(app_id, name, db, schema, table) + _error_box(str(ex) if isinstance(ex, D.DbError) else "Not a row.")
        return Response(200, adm._shell(s, a, f"Database: {name}", TAB, body))
    rid = record(conn, app_id, db, do, _tname(db, schema, table), stmt)
    if rid is None:
        return back("norecord")
    res, err = ask_one(adm, s, app_id, db, stmt, 1)
    outcome(conn, rid, _result_outcome(res, err))
    if err:
        body = (_crumbs(app_id, name, db, schema, table, "Not saved") + _error_box(err) +
                f"<p>The statement, as recorded in the change history:</p><pre class='code'>{e(stmt)}</pre>"
                f"<p><a href='{e(_href(app_id, db, schema=schema, table=table))}'>Back to the table</a></p>")
        return Response(200, adm._shell(s, a, f"Not saved: {_tname(db, schema, table)}", TAB, body))
    if do != "insert" and res.get("kind") == "count" and not res.get("rowcount"):
        return back("nomatch")
    return back({"update": "saved", "insert": "added", "delete": "deleted"}[do])


def run_sql(adm, conn, s, a, app_id: int, form: dict) -> Response:
    if not may_use(a):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    g = lambda k: form.get(k, [""])[0]    # noqa: E731
    ctx = _context(adm, conn, s, a, app_id, g("d"))
    if isinstance(ctx, Response):
        return ctx
    name, dbs, db = ctx
    sql = _nl(g("sql")).strip()
    if not sql:
        return redirect(_href(app_id, db) + "#sql")
    if len(sql) > D.MAX_STATEMENT:
        return _tables(adm, conn, s, a, app_id, name, dbs, db, "", sql, _error_box(f"At most {D.MAX_STATEMENT} characters."))
    rid = record(conn, app_id, db, "sql", None, sql)
    if rid is None:
        return _tables(adm, conn, s, a, app_id, name, dbs, db, notice_html("norecord"), sql)
    res, err = ask_one(adm, s, app_id, db, sql, D.MAX_ROWS)
    outcome(conn, rid, _result_outcome(res, err))
    forget(db)
    return _tables(adm, conn, s, a, app_id, name, dbs, db, "", sql, render_result(res, err))


def render_result(res: dict | None, err: str | None) -> str:
    if err:
        return "<h2 id='result'>Result</h2>" + _error_box(err)
    kind = res.get("kind")
    if kind == "count":
        return f"<h2 id='result'>Result</h2><div class='notice notice-ok' role='status'>{int(res.get('rowcount') or 0)} row(s) affected.</div>"
    if kind == "text":
        return f"<h2 id='result'>Result</h2><pre class='code'>{e(res.get('text') or '')}</pre>"
    cols, rows = res.get("columns") or [], res.get("rows") or []
    more = (f"<p class='muted'>Only the first {len(rows)} rows are shown"
            + (f" of {int(res['total'])}" if res.get("total") else "") + ".</p>") if res.get("truncated") else ""
    head = "".join(f"<th>{e(str(c))}</th>" for c in cols)
    body = "".join(f"<tr>{''.join(f'<td>{_cell(x, 400)}</td>' for x in r)}</tr>" for r in rows) or \
        f"<tr><td colspan='{max(1, len(cols))}' class='muted'>No rows.</td></tr>"
    return (f"<h2 id='result'>Result</h2><p class='muted'>{len(rows)} row(s).</p>{more}<div class='dbwrap'><table class='dbrows'>"
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>")


def drop(adm, conn, s, a, app_id: int, form: dict) -> Response:
    if not may_use(a):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    g = lambda k: form.get(k, [""])[0]    # noqa: E731
    ctx = _context(adm, conn, s, a, app_id, g("d"))
    if isinstance(ctx, Response):
        return ctx
    name, dbs, db = ctx
    typed = g("confirm").strip()
    if typed != db.database:
        return redirect(_href(app_id, db, notice="dropconfirm"))
    what = (f"DROP DATABASE {db.database} (the lab agent creates it again empty; the application restarts)" if db.source == "lab"
            else f"restart the restored dev database {db.database} (restored again from the uploaded backup)")
    rid = record(conn, app_id, db, "drop", None, what)
    if rid is None:
        return redirect(_href(app_id, db, notice="norecord"))
    ans = adm.system.ask("dbdelete", s.user, s.name, wait=D.ANSWER_WAIT, application_id=app_id, source=db.source,
                         engine=db.engine, namespace=db.namespace, confirm=typed)
    if ans is None or ans.get("error"):
        err = (ans or {}).get("error") or (f"The appliance did not answer within {D.ANSWER_WAIT} seconds; it may still "
                                           "delete the database. Look again in a minute.")
        outcome(conn, rid, "error: " + err)
        return _tables(adm, conn, s, a, app_id, name, dbs, db, "", "", _error_box(err))
    outcome(conn, rid, "deleted")
    forget(db)
    return redirect(f"/admin/dev-databases/{app_id}?" + urlencode({"notice": "dropped-" + db.source}) + "#databases")
