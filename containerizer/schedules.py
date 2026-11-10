"""Windows Task Scheduler jobs of the repository: their schedules in cron syntax, for the CronJobs of console components.

Three common shapes (rules/20-platform.yaml `task_scheduler:` says which files are read):

- PowerShell's ScheduledTasks module: `New-ScheduledTaskTrigger -Daily|-Weekly [-DaysOfWeek ...] -At HH:mm` (and a
  repetition: `-RepetitionInterval`/`-RepetitionDuration`, or `$t.Repetition = (New-ScheduledTaskTrigger -Once ...
  ).Repetition`) with the `New-ScheduledTaskAction -Execute ... -Argument ...` that `Register-ScheduledTask` pairs it
  with, also when a table (`$tasks = @(@{ Name = ..; Verb = ..; Trigger = .. })`) and a `foreach` register them;
- `schtasks /create /sc DAILY|WEEKLY|MONTHLY|MINUTE|HOURLY /st HH:mm [/d MON,TUE] [/mo n] [/ri n /du HH:mm] /tr ...`,
  in .cmd/.bat files or PowerShell, also splatted (`schtasks.exe @taskArgs`);
- Task Scheduler XML exports (`CalendarTrigger`/`StartBoundary`, `ScheduleByDay|Week|Month`, `Repetition`,
  `Exec`/`Command`/`Arguments`).

find() lists one job per trigger; cronjobs() matches them to a console component (its executable name, then its
`commands`/`oneshot_arg` facts) for generate.k8s_manifests; report() says what each job became. Task Scheduler runs at
the server's local time: the CronJob schedule keeps the same hours (no time zone is set on it).
"""
from __future__ import annotations

import fnmatch
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from functools import lru_cache

import yaml

from .rules import RULES_DIR

MAX_BYTES = 512 * 1024


@lru_cache(maxsize=1)
def settings() -> dict:
    return (yaml.safe_load((RULES_DIR / "20-platform.yaml").read_text()) or {}).get("task_scheduler") or {}


def placeholder() -> str:
    return settings().get("placeholder") or "0 2 * * *"


DAYS = {d: i for i, d in enumerate(("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"))}
DAY3 = {k[:3]: v for k, v in DAYS.items()}
DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


@dataclass
class Trigger:
    kind: str                                   # daily weekly monthly once logon startup event other
    at: tuple[int, int] | None = None           # start time (hour, minute)
    days: list[int] = field(default_factory=list)       # weekly: cron day numbers, 0 = Sunday
    monthdays: list[int] = field(default_factory=list)  # monthly
    every: int = 1                              # days (daily) or weeks (weekly) between runs
    repeat: int | None = None                   # minutes between repetitions
    duration: int | None = None                 # minutes the repetition lasts; None: all day


def _ranges(nums: list[int]) -> str:
    out, run = [], []
    for n in sorted(set(nums)):
        if run and n == run[-1] + 1:
            run.append(n)
            continue
        if run:
            out.append(f"{run[0]}-{run[-1]}" if len(run) > 2 else ",".join(map(str, run)))
        run = [n]
    if run:
        out.append(f"{run[0]}-{run[-1]}" if len(run) > 2 else ",".join(map(str, run)))
    return ",".join(out)


def schedule(t: Trigger) -> tuple[str | None, str]:
    """The cron schedule of a trigger and a note (what it could not express); None for a trigger that is no
    schedule (logon, startup, once, an event: the note says what it is)."""
    ns = settings().get("not_scheduled") or {}
    if t.kind in ("logon", "startup", "event", "other") or t.kind == "once" and not t.repeat:
        return None, ns.get(t.kind, "not a time schedule")
    if t.at is None:
        return None, "no start time found"
    h, m = t.at
    notes = []
    dom, dow = "*", "*"
    if t.kind == "weekly":
        if not t.days:
            return None, "no days of the week found"
        dow = _ranges(t.days)
        if t.every > 1:
            notes.append(f"every {t.every} weeks in Task Scheduler: every week here")
    elif t.kind == "monthly":
        if not t.monthdays:
            return None, "no days of the month found"
        dom = _ranges(t.monthdays)
    elif t.every > 1:
        dom = f"*/{t.every}"
        notes.append(f"every {t.every} days: counted from the 1st of each month in cron")
    if not t.repeat:
        return f"{m} {h} {dom} * {dow}", "; ".join(notes)
    r = t.repeat
    if not (r < 60 and 60 % r == 0 or r >= 60 and r % 60 == 0 and 1440 % r == 0):
        return None, f"repeats every {r} minutes: no cron schedule does that"
    start = h * 60 + m
    window = t.duration is not None and t.duration < 1440
    runs = -(-t.duration // r) if window else 1440 // r          # the runs that start inside the window
    hours = sorted({(start + k * r) // 60 % 24 for k in range(max(1, runs))})
    if window and start + t.duration > 1440 and dow != "*":
        notes.append("the window passes midnight: the hours after it run on the same days of the week")
    hour = "*" if len(hours) == 24 else _ranges(hours)
    minute = (f"*/{r}" if m % r == 0 else f"{m % r}-59/{r}") if r < 60 else str(m)
    return f"{minute} {hour} {dom} * {dow}", "; ".join(notes)


def describe(t: Trigger) -> str:
    at = f"{t.at[0]:02d}:{t.at[1]:02d}" if t.at else "?"
    if t.kind == "weekly":
        s = f"weekly {_day_names(t.days)} {at}" + (f" (every {t.every} weeks)" if t.every > 1 else "")
    elif t.kind == "monthly":
        s = f"monthly on day {_ranges(t.monthdays)} {at}"
    elif t.kind == "daily":
        s = f"daily {at}" if t.every == 1 else f"every {t.every} days {at}"
    elif t.kind == "once":
        s = f"once {at}"
    else:
        s = {"logon": "at logon", "startup": "at startup", "event": "on an event"}.get(t.kind, t.kind)
    if t.repeat:
        s += f", every {t.repeat} min" + (f" for {_span_text(t.duration)}" if t.duration else "")
    return s


def _span_text(minutes: int) -> str:
    return f"{minutes // 60} h" + (f" {minutes % 60} min" if minutes % 60 else "") if minutes >= 60 else f"{minutes} min"


def _day_names(days: list[int]) -> str:
    d = sorted(set(days))
    if len(d) > 2 and d == list(range(d[0], d[-1] + 1)):
        return f"{DOW[d[0]]}-{DOW[d[-1]]}"
    return ",".join(DOW[x] for x in d)


def _day_list(v) -> list[int]:
    out = []
    for w in re.findall(r"[A-Za-z]+|\d+", _s(v)):
        lw = w.lower()
        if lw in DAYS or lw in DAY3:
            out.append(DAYS.get(lw, DAY3.get(lw)))
        elif w.isdigit() and int(w) < 7:
            out.append(int(w))
    return out


def _time(v) -> tuple[int, int] | None:
    t = _s(v)
    m = re.search(r"(?<!\d)(\d{1,2}):(\d{2})(?::\d{2})?\s*([AaPp])?\.?[Mm]?\b", t)
    if m:
        h, mi, ap = int(m[1]), int(m[2]), (m[3] or "").lower()
    else:
        m = re.search(r"(?<![\d:])(\d{1,2})\s*([AaPp])\.?[Mm]\b", t)
        if not m:
            return (0, 0) if re.search(r"\.Date\b|\b(today|midnight)\b", t, re.I) else None
        h, mi, ap = int(m[1]), 0, m[2].lower()
    if ap == "p" and h < 12:
        h += 12
    elif ap == "a" and h == 12:
        h = 0
    return (h, mi) if h < 24 and mi < 60 else None


def _iso_minutes(v: str | None) -> int | None:
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", (v or "").strip())
    if not m or not any(m.groups()):
        return None
    d, h, mi, _ = (int(x or 0) for x in m.groups())
    return d * 1440 + h * 60 + mi


def _hhmm_minutes(v: str | None) -> int | None:
    m = re.fullmatch(r"(?:(\d+)\.)?(\d{1,4}):(\d{2})(?::\d{2})?", (v or "").strip())
    return None if not m else int(m[1] or 0) * 1440 + int(m[2]) * 60 + int(m[3])


# ---------------------------------------------------------------------------- PowerShell text scanning

def _s(v) -> str:
    """A value as text: lists joined with spaces, an unresolved expression as its reference."""
    if v is None or isinstance(v, dict):
        return ""
    if isinstance(v, list):
        return " ".join(_s(x) for x in v)
    return getattr(v, "ref", None) or str(v)


class _Expr(str):
    """An expression the scanner does not evaluate (a command, a call): its text, and `ref`, the variable that held it."""
    ref = ""


def _str_end(s: str, i: int) -> int:
    q, j, n = s[i], i + 1, len(s)
    while j < n:
        if s[j] == "`" and q == '"':
            j += 2
            continue
        if s[j] == q:
            if j + 1 < n and s[j + 1] == q:
                j += 2
                continue
            return j + 1
        j += 1
    return n


def _close(s: str, i: int) -> int:
    """The index after the bracket that closes the one at s[i]."""
    depth, j, n = 0, i, len(s)
    while j < n:
        c = s[j]
        if c in "'\"":
            j = _str_end(s, j)
            continue
        if c == "`":
            j += 2
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _strip_comments(s: str) -> str:
    out, i, n = list(s), 0, len(s)

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "
    while i < n:
        c = s[i]
        if c in "'\"":
            i = _str_end(s, i)
        elif s.startswith("<#", i):
            j = s.find("#>", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == "#" and (i == 0 or s[i - 1] in " \t\r\n;({"):
            j = s.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


def _extent(s: str, i: int, commas: bool = False) -> int:
    """The end of the statement (or value) that starts at i: `;`, a line end, `|`, or a bracket it does not open."""
    j, n = i, len(s)
    while j < n:
        c = s[j]
        if c in "'\"":
            j = _str_end(s, j)
            continue
        if c == "`":
            j += 2
            continue
        if c in "([{":
            j = _close(s, j)
            continue
        if c in ";\n|)}]" or commas and c == ",":
            return j
        j += 1
    return n


def _ws(s: str, i: int, newlines: bool = False) -> int:
    n = len(s)
    while i < n:
        if s[i] in " \t\r" or newlines and s[i] == "\n":
            i += 1
        elif s[i] == "`" and i + 1 < n and s[i + 1] in "\r\n":
            i += 2
        else:
            break
    return i


BARE = re.compile(r"[^\s,;(){}\[\]|'\"]+")
MEMBER = re.compile(r"(?:\.|::)\w+")


def _primary(s: str, i: int) -> int:
    n = len(s)
    if i >= n:
        return i
    c = s[i]
    if c in "'\"":
        j = _str_end(s, i)
    elif c in "@$" and i + 1 < n and s[i + 1] in "({":
        j = _close(s, i + 1)
    elif c in "([{":
        j = _close(s, i)
    else:
        m = BARE.match(s, i)
        j = m.end() if m else i + 1
        if j < n and s[j] == "(" and re.search(r"[\w.]$", s[i:j]) and "$" in s[i:j]:
            j = _close(s, j)                    # a method call: $x.Method(...)
    while j < n:
        m = MEMBER.match(s, j)
        if m:
            j = m.end()
            if j < n and s[j] == "(":
                j = _close(s, j)
            continue
        if s[j] == "[" and j > i:
            j = _close(s, j)
            continue
        break
    return j


def _arg(s: str, i: int) -> tuple[str, int]:
    """One argument (a value, or values separated by commas) at i."""
    start = j = _ws(s, i)
    j = _primary(s, j)
    while True:
        k = _ws(s, j)
        if k < len(s) and s[k] == ",":
            j = _primary(s, _ws(s, k + 1, True))
        else:
            break
    return s[start:j], j


SWITCHES = {"daily", "weekly", "once", "atlogon", "atstartup", "force"}
PARAM = re.compile(r"-([A-Za-z]\w*)(:?)")


def _params(stmt: str) -> tuple[dict, list]:
    """The named (lower-case) and positional arguments of a command invocation."""
    named, pos = {}, []
    m = re.match(r"\s*&?\s*['\"]?[\w.\\:-]+['\"]?", stmt)
    i, n = (m.end() if m else 0), len(stmt)
    while i < n:
        i = _ws(stmt, i, True)
        if i >= n:
            break
        m = PARAM.match(stmt, i)
        if m and stmt[i - 1] in " \t\n`(":
            name, i = m[1].lower(), m.end()
            if not m[2]:
                j = _ws(stmt, i, True)
                if name in SWITCHES or j >= n or PARAM.match(stmt, j) and stmt[j - 1] in " \t\n`":
                    named[name], i = True, j
                    continue
            named[name], i = _arg(stmt, i)
            continue
        v, j = _arg(stmt, i)
        if j == i:
            i += 1
            continue
        pos.append(v)
        i = j
    return named, pos


def _items(body: str, newlines: bool = True) -> list[str]:
    """Top-level items of an array or hashtable body: split at commas (and line ends and `;`)."""
    out, start, j, n = [], 0, 0, len(body)
    while j < n:
        c = body[j]
        if c in "'\"":
            j = _str_end(body, j)
            continue
        if c == "`":
            j += 2
            continue
        if c in "([{":
            j = _close(body, j)
            continue
        if c == "," or newlines and c in ";\n":
            out.append(body[start:j])
            start = j + 1
        j += 1
    out.append(body[start:])
    return [x.strip() for x in out if x.strip()]


def _hashtable(body: str) -> dict:
    out = {}
    for item in _items(body):
        m = re.match(r"['\"]?([\w-]+)['\"]?\s*=\s*", item)
        if m:
            out[m[1].lower()] = item[m.end():]
    return out


def _get(d: dict, key: str):
    return d.get(key.lower())


def _unwrap(e: str) -> str:
    e = e.strip()
    while e.startswith("(") and _close(e, 0) == len(e):
        e = e[1:-1].strip()
    return e


VAR_ASSIGN = re.compile(r"(?<![\w$.:])\$(\w+)((?:\.\w+)?)\s*(\+?=)(?!=)")


class _PS:
    """One PowerShell file: its assignments, loops, ifs and functions, and evaluation of the simple expressions
    scheduled-task scripts are made of (strings, variables, table entries, Join-Path)."""

    def __init__(self, text: str, rel: str, tables=None):
        self.raw, self.s, self.rel = text, _strip_comments(text), rel
        self.tables = tables or (lambda key: None)
        s = self.s
        self.params = [(m.end() - 1, _close(s, m.end() - 1)) for m in re.finditer(r"\bparam\s*\(", s, re.I)]
        self.ifs = []
        for m in re.finditer(r"\bif\s*\(", s, re.I):
            ce = _close(s, m.end() - 1)
            b = _ws(s, ce, True)
            if b < len(s) and s[b] == "{":
                self.ifs.append((s[m.end():ce - 1], b, _close(s, b)))
        self.vars: dict[str, list] = {}
        self.members: dict[tuple, list] = {}
        self.appends: dict[str, list] = {}
        for m in VAR_ASSIGN.finditer(s):
            start = m.end()
            in_param = any(a < m.start() < b for a, b in self.params)
            end = _extent(s, start, commas=in_param)
            expr = s[start:end].strip().rstrip(",").strip()
            name, cond = m[1].lower(), self._cond(m.start())
            if m[2]:
                self.members.setdefault((name, m[2][1:].lower()), []).append((m.start(), expr, cond))
            elif m[3] == "+=":
                self.appends.setdefault(name, []).append((m.start(), expr, cond))
            else:
                self.vars.setdefault(name, []).append((m.start(), expr))
        self.loops = []
        for m in re.finditer(r"\bforeach\s*\(\s*\$(\w+)\s+in\s+", s, re.I):
            pe = _close(s, s.index("(", m.start()))
            b = _ws(s, pe, True)
            if b < len(s) and s[b] == "{":
                self.loops.append((m[1].lower(), s[m.end():pe - 1], b, _close(s, b)))
        for m in re.finditer(r"\|\s*(?:ForEach-Object|%)\s*\{", s, re.I):
            st = max(s.rfind("\n", 0, m.start()), s.rfind(";", 0, m.start())) + 1
            b = m.end() - 1
            for v in ("_", "psitem"):
                self.loops.append((v, s[st:m.start()], b, _close(s, b)))
        self.funcs = {m[1].lower(): (m.end() - 1, _close(s, m.end() - 1))
                      for m in re.finditer(r"\bfunction\s+([\w-]+)[^{]*\{", s, re.I)}

    def _cond(self, pos: int) -> str | None:
        inner = [c for c, a, b in self.ifs if a < pos < b]
        return inner[-1] if inner else None

    def line(self, pos: int) -> int:
        return self.raw.count("\n", 0, max(0, pos)) + 1

    def var(self, name: str, pos: int):
        vs = self.vars.get(name.lower()) or []
        before = [v for v in vs if v[0] < pos]
        return (before or vs or [None])[-1]

    def _true(self, cond: str | None, env: dict, pos: int) -> bool:
        if not cond:
            return True
        m = re.fullmatch(r"\s*\$(\w+)\.(\w+)\s*", cond)
        if m and m[1].lower() in env and isinstance(env[m[1].lower()], dict):
            v = _get(env[m[1].lower()], m[2])
            return v is not None and v.strip().lower() not in ("$false", "0", "''", '""', "$null")
        m = re.fullmatch(r"\s*\$(\w+)\.ContainsKey\(\s*['\"](\w+)['\"]\s*\)\s*", cond, re.I)
        if m and m[1].lower() in env and isinstance(env[m[1].lower()], dict):
            return _get(env[m[1].lower()], m[2]) is not None
        return True

    # --- values
    def ev(self, e, env: dict, pos: int, d: int = 0):
        if e is None or d > 14:
            return None
        if not isinstance(e, str) or isinstance(e, _Expr):
            return e
        e = _unwrap(e)
        if not e:
            return ""
        if e.startswith("@(") and _close(e, 1) == len(e):
            return [self.ev(x, env, pos, d + 1) for x in _items(e[2:-1])]
        if e.startswith("@{") and _close(e, 1) == len(e):
            return _hashtable(e[2:-1])
        items = _items(e, newlines=False)
        if len(items) > 1:
            return [self.ev(x, env, pos, d + 1) for x in items]
        if e[0] == "'" and _str_end(e, 0) == len(e):
            return e[1:-1].replace("''", "'")
        if e[0] == '"' and _str_end(e, 0) == len(e):
            return self.expand(e[1:-1], env, pos, d)
        m = re.fullmatch(r"\$(\w+)((?:\.\w+)*)", e)
        if m:
            base = m[1].lower()
            if base in env:
                val = env[base]
            else:
                v = self.var(base, pos)
                if v is None:
                    return _ref(e, e)
                val = self.ev(v[1], env, v[0], d + 1)
                if isinstance(val, _Expr):
                    return _ref(e, e) if m[2] else _ref(val, "$" + m[1])
            for mem in [x for x in m[2].split(".") if x]:
                if not isinstance(val, dict):
                    return None if base in env else _ref(e, e)
                val = self.ev(_get(val, mem), env, pos, d + 1)
            return val
        m = re.match(r"Join-Path\b", e, re.I)
        if m:
            named, pos_args = _params(e)
            parts = [named.get("path")] + [named.get("childpath")] + pos_args
            vals = [_s(self.ev(p, env, pos, d + 1)) for p in parts if p not in (None, True)]
            return "\\".join(v.rstrip("\\") for v in vals if v)
        if re.fullmatch(r"-?\d+(\.\d+)?|\$true|\$false|\$null", e, re.I):
            return e
        return _Expr(e)

    def expand(self, body: str, env: dict, pos: int, d: int) -> str:
        out, i, n = [], 0, len(body)
        while i < n:
            c = body[i]
            if c == "`" and i + 1 < n:
                out.append({"t": "\t", "n": "\n", "r": "\r", "0": ""}.get(body[i + 1], body[i + 1]))
                i += 2
                continue
            if c == '"' and i + 1 < n and body[i + 1] == '"':
                out.append('"')
                i += 2
                continue
            if c == "$" and i + 1 < n and body[i + 1] == "(":
                j = _close(body, i + 1)
                out.append(_s(self.ev(body[i + 2:j - 1], env, pos, d + 1)))
                i = j
                continue
            m = re.compile(r"\$\{(\w+)\}|\$(\w+)(?!:)").match(body, i)
            if m:
                out.append(_s(self.ev("$" + (m[1] or m[2]), env, pos, d + 1)))
                i = m.end()
                continue
            out.append(c)
            i += 1
        return "".join(out)

    # --- loops
    def envs(self, pos: int) -> list[dict]:
        envs = [{}]
        for var, coll, a, b in sorted((x for x in self.loops if x[2] < pos < x[3]), key=lambda x: x[2]):
            nxt = []
            for env in envs:
                for entry in self.entries(coll, env, a):
                    nxt.append({**env, var: entry})
            envs = nxt or envs
        return envs

    def entries(self, coll: str, env: dict, pos: int) -> list:
        v = self.ev(coll, env, pos)
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            return [v]
        # a table kept in another file ($settings.Tasks: Tasks = @(...) in the settings script)
        m = re.search(r"\.(\w+)\s*$|^\s*\$(\w+)\s*$", coll)
        found = self.tables((m[1] or m[2]).lower()) if m else None
        return found or []

    # --- scheduled tasks
    def triggers(self, e, env: dict, pos: int, d: int = 0) -> list[tuple[Trigger, int]]:
        if e is None or e is True or d > 10:
            return []
        e = _unwrap(e)
        if re.match(r"New-ScheduledTaskTrigger\b", e, re.I):
            return [self._trigger(e, env, pos)]
        m = re.fullmatch(r"\((.*)\)\.Repetition", e, re.S)
        if m:
            return self.triggers(m[1], env, pos, d + 1)
        if e.startswith("@(") and _close(e, 1) == len(e):
            return [t for x in _items(e[2:-1]) for t in self.triggers(x, env, pos, d + 1)]
        items = _items(e, newlines=False)
        if len(items) > 1:
            return [t for x in items for t in self.triggers(x, env, pos, d + 1)]
        m = re.fullmatch(r"\$(\w+)((?:\.\w+)*)", e)
        if not m:
            return []
        base, mems = m[1].lower(), [x for x in m[2].split(".") if x]
        if base in env:
            val = env[base]
            for mem in mems[:-1]:
                val = self.ev(_get(val, mem), env, pos, d + 1) if isinstance(val, dict) else None
            raw = _get(val, mems[-1]) if mems and isinstance(val, dict) else None
            return self.triggers(raw, env, pos, d + 1) if raw else []
        v = self.var(base, pos)
        if v is None:
            return []
        ts = self.triggers(v[1], env, v[0], d + 1)
        if not mems:                   # $t.Repetition = (New-ScheduledTaskTrigger -Once ... -RepetitionInterval ...)
            reps = [x for x in self.members.get((base, "repetition"), []) if x[0] < pos and self._true(x[2], env, pos)]
            if reps:
                src = self.triggers(reps[-1][1], env, reps[-1][0], d + 1)
                if src and src[0][0].repeat:
                    ts = [(replace(t, repeat=src[0][0].repeat, duration=src[0][0].duration), p) for t, p in ts]
        return ts

    def _trigger(self, stmt: str, env: dict, pos: int) -> tuple[Trigger, int]:
        p, _ = _params(stmt)
        kind = next((k for k, s in (("daily", "daily"), ("weekly", "weekly"), ("once", "once"), ("logon", "atlogon"),
                                    ("startup", "atstartup")) if p.get(s) is True), "event")
        ev = lambda k: self.ev(p.get(k), env, pos) if p.get(k) not in (None, True) else None  # noqa: E731
        every = re.match(r"\d+", _s(ev("daysinterval") or ev("weeksinterval")) or "1")
        t = Trigger(kind=kind, at=_time(ev("at")), days=_day_list(ev("daysofweek")),
                    every=max(1, int(every[0])) if every else 1,
                    repeat=self.minutes(p.get("repetitioninterval"), env, pos),
                    duration=self.minutes(p.get("repetitionduration"), env, pos))
        at = self.s.find(stmt.strip())
        return t, (at if at >= 0 else pos)

    def minutes(self, e, env: dict, pos: int, d: int = 0) -> int | None:
        if e in (None, True) or d > 8:
            return None
        e = _unwrap(e)
        if re.search(r"MaxValue|::Zero\b", e):
            return None
        m = re.match(r"New-TimeSpan\b", e, re.I)
        if m:
            p, _ = _params(e)
            f = {"days": 1440, "hours": 60, "minutes": 1}
            total = 0
            for k, mul in f.items():
                v = re.match(r"\d+", _s(self.ev(p.get(k), env, pos)) if p.get(k) not in (None, True) else "")
                total += int(v[0]) * mul if v else 0
            return total or None
        m = re.search(r"From(Days|Hours|Minutes)\(\s*(\d+)", e)
        if m:
            return int(m[2]) * {"Days": 1440, "Hours": 60, "Minutes": 1}[m[1]]
        if e.startswith("$"):
            v = self.ev(e, env, pos)
            if isinstance(v, _Expr):
                v = self.var(e[1:].split(".")[0], pos)
                return self.minutes(v[1], env, v[0], d + 1) if v else None
            e = _s(v)
        e = e.strip("'\"")
        return _iso_minutes(e) or _hhmm_minutes(e)

    def action(self, e, env: dict, pos: int, d: int = 0) -> tuple[str, str] | None:
        if e in (None, True) or d > 10:
            return None
        e = _unwrap(e)
        if re.match(r"New-ScheduledTaskAction\b", e, re.I):
            p, _ = _params(e)
            ev = lambda k: _s(self.ev(p.get(k), env, pos)) if p.get(k) not in (None, True) else ""  # noqa: E731
            return ev("execute"), ev("argument")
        items = _items(e[2:-1]) if e.startswith("@(") and _close(e, 1) == len(e) else _items(e, newlines=False)
        if len(items) > 1:
            return next((a for x in items if (a := self.action(x, env, pos, d + 1))), None)
        m = re.fullmatch(r"\$(\w+)((?:\.\w+)*)", e)
        if m:
            base, mems = m[1].lower(), [x for x in m[2].split(".") if x]
            if base in env:
                val = env[base]
                for mem in mems[:-1]:
                    val = self.ev(_get(val, mem), env, pos, d + 1) if isinstance(val, dict) else None
                raw = _get(val, mems[-1]) if mems and isinstance(val, dict) else None
                return self.action(raw, env, pos, d + 1) if raw else None
            v = self.var(base, pos)
            return self.action(v[1], env, v[0], d + 1) if v else None
        m = re.match(r"([A-Za-z]+-\w+)\b", e)
        if m and m[1].lower() in self.funcs:           # a helper that builds the action
            a, b = self.funcs[m[1].lower()]
            for x in re.finditer(r"\bNew-ScheduledTaskAction\b", self.s[a:b], re.I):
                return self.action(self.s[a + x.start():_extent(self.s, a + x.start())], env, a + x.start(), d + 1)
        return None

    def tasks(self) -> list[dict]:
        out = []
        s = self.s
        for m in re.finditer(r"\bRegister-ScheduledTask\b", s, re.I):
            p, _ = _params(s[m.start():_extent(s, m.start())])
            if p.get("inputobject") not in (None, True):     # -InputObject (New-ScheduledTask -Action .. -Trigger ..)
                e = _unwrap(p["inputobject"])
                v = self.var(e[1:], m.start()) if re.fullmatch(r"\$\w+", e) else None
                inner = _unwrap(v[1]) if v else e
                if re.match(r"New-ScheduledTask\b", inner, re.I):
                    p = {**_params(inner)[0], **{k: x for k, x in p.items() if k != "inputobject"}}
            if p.get("trigger") in (None, True):
                continue
            for env in self.envs(m.start()):
                act = self.action(p.get("action"), env, m.start()) or ("", "")
                name = _s(self.ev(p.get("taskname"), env, m.start())) if p.get("taskname") not in (None, True) else ""
                for t, tpos in self.triggers(p["trigger"], env, m.start()):
                    out.append(_task(name, self.rel, self.line(tpos), t, act[0], _split_cmdline(act[1]),
                                     self.raw[tpos:_extent(s, tpos)].strip()))
        for m in re.finditer(r"\bschtasks(?:\.exe)?['\"]?(?=\s)", s, re.I):
            stmt = s[m.end():_extent(s, m.end())]
            for env in self.envs(m.start()):
                sp = re.match(r"\s*@(\w+)", stmt)
                if sp:
                    v = self.var(sp[1], m.start())
                    toks = self.ev(v[1], env, v[0]) if v else None
                    toks = list(toks) if isinstance(toks, list) else []
                    for apos, expr, cond in self.appends.get(sp[1].lower(), []):
                        if apos < m.start() and self._true(cond, env, apos):
                            add = self.ev(expr, env, apos)
                            add = add if isinstance(add, list) else [add]
                            if all(x is not None for x in add):
                                toks += add
                else:
                    toks, i = [], 0
                    while i < len(stmt):
                        i = _ws(stmt, i, True)
                        j = _primary(stmt, i)
                        if j <= i:
                            break
                        toks.append(self.ev(stmt[i:j], env, m.start()))
                        i = j
                toks = [_s(x) for x in toks if x is not None]
                t = _schtasks(toks, self.rel, self.line(m.start()), self.raw[m.start():_extent(s, m.end())].strip())
                if t:
                    out.append(t)
        return out


def _ref(v, ref: str) -> _Expr:
    x = _Expr(v)
    x.ref = ref
    return x


def _split_cmdline(s: str) -> list[str]:
    """A Windows command line split into arguments (double quotes group, \\" is a quote)."""
    out, i, n = [], 0, len(s or "")
    while i < n:
        while i < n and s[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        cur, quoted = [], False
        while i < n and (quoted or s[i] not in " \t\r\n"):
            if s[i] == "\\" and i + 1 < n and s[i + 1] == '"':
                cur.append('"')
                i += 2
                continue
            if s[i] == '"':
                quoted = not quoted
            else:
                cur.append(s[i])
            i += 1
        out.append("".join(cur))
    return out


def _task(name: str, rel: str, line: int, t: Trigger, program: str, args: list[str], quote: str = "") -> dict:
    cron, note = schedule(t)
    return {"name": name, "file": rel, "line": line, "trigger": describe(t), "kind": t.kind, "schedule": cron,
            "note": note, "program": program, "arguments": args, "quote": " ".join(quote.split())[:200]}


def _schtasks(toks: list[str], rel: str, line: int, quote: str = "") -> dict | None:
    if not any(t.lower() == "/create" for t in toks):
        return None
    opts, i = {}, 0
    while i < len(toks):
        t = toks[i]
        if re.fullmatch(r"/[A-Za-z]+", t):
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            if nxt is not None and not re.fullmatch(r"/[A-Za-z]+", nxt):
                opts[t[1:].lower()], i = nxt, i + 2
                continue
            opts[t[1:].lower()] = True
        i += 1
    sc = str(opts.get("sc") or "").upper()
    st = _time(opts.get("st")) if isinstance(opts.get("st"), str) else None
    mo = opts.get("mo") if isinstance(opts.get("mo"), str) else ""
    n = int(mo) if mo.isdigit() else 1
    dur = _hhmm_minutes(opts.get("du")) if isinstance(opts.get("du"), str) else None
    et = _time(opts.get("et")) if isinstance(opts.get("et"), str) else None
    if dur is None and et and st:
        dur = (et[0] * 60 + et[1] - st[0] * 60 - st[1]) % 1440 or None
    ri = int(opts["ri"]) if isinstance(opts.get("ri"), str) and opts["ri"].isdigit() else None
    d = opts.get("d") if isinstance(opts.get("d"), str) else ""
    if sc in ("MINUTE", "HOURLY"):
        t = Trigger("daily", at=st or (0, 0), repeat=n * (60 if sc == "HOURLY" else 1), duration=dur)
    elif sc == "DAILY":
        t = Trigger("daily", at=st, every=n, repeat=ri, duration=dur if ri else None)
    elif sc == "WEEKLY":
        days = list(range(7)) if d == "*" else _day_list(d or "MON")
        t = Trigger("weekly", at=st, days=days, every=n, repeat=ri, duration=dur if ri else None)
    elif sc == "MONTHLY" and not re.fullmatch(r"FIRST|SECOND|THIRD|FOURTH|LAST|LASTDAY", mo, re.I):
        t = Trigger("monthly", at=st, monthdays=[int(x) for x in re.findall(r"\d+", d or "1") if 0 < int(x) < 32],
                    repeat=ri, duration=dur if ri else None)
    elif sc == "ONCE":
        t = Trigger("once", at=st, repeat=ri, duration=dur if ri else None)
    else:
        t = Trigger({"ONLOGON": "logon", "ONSTART": "startup", "ONIDLE": "event", "ONEVENT": "event"}.get(sc, "other"))
    tr = _split_cmdline(opts["tr"]) if isinstance(opts.get("tr"), str) else []
    name = opts["tn"] if isinstance(opts.get("tn"), str) else ""
    return _task(name, rel, line, t, tr[0] if tr else "", tr[1:], quote)


def _cmd_tasks(text: str, rel: str) -> list[dict]:
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start, cur = i, lines[i]
        while cur.rstrip().endswith("^") and i + 1 < len(lines):
            i += 1
            cur = cur.rstrip()[:-1] + " " + lines[i]
        m = re.search(r"\bschtasks(?:\.exe)?\s+(.*)", cur, re.I)
        if m and not re.match(r"\s*(rem\b|::)", cur, re.I):
            t = _schtasks(_split_cmdline(m[1]), rel, start + 1, cur.strip())
            if t:
                out.append(t)
        i += 1
    return out


def _xml_tasks(data: bytes, rel: str, stem: str) -> list[dict]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return []
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = el.tag.rsplit("}", 1)[-1]
    if root.tag != "Task":
        return []
    text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8", "replace")
    uri = (root.findtext("RegistrationInfo/URI") or "").strip()
    name = uri.rsplit("\\", 1)[-1] if uri else stem
    exe = root.find("Actions/Exec")
    program = (exe.findtext("Command") or "").strip() if exe is not None else ""
    args = _split_cmdline((exe.findtext("Arguments") or "").strip()) if exe is not None else []
    out, at = [], 0
    for tr in root.findall("Triggers/*"):
        tag = tr.tag
        k = text.find(f"<{tag}", at)
        at = k + 1 if k >= 0 else at
        line = text.count("\n", 0, max(0, k)) + 1
        rep = tr.find("Repetition")
        repeat = _iso_minutes(rep.findtext("Interval")) if rep is not None else None
        duration = _iso_minutes(rep.findtext("Duration")) if rep is not None else None
        start = _time(tr.findtext("StartBoundary") or "")
        if tag == "CalendarTrigger":
            if tr.find("ScheduleByWeek") is not None:
                w = tr.find("ScheduleByWeek")
                days = [DAYS[x.tag.lower()] for x in w.findall("DaysOfWeek/*") if x.tag.lower() in DAYS]
                n = re.match(r"\d+", w.findtext("WeeksInterval") or "1")
                t = Trigger("weekly", at=start, days=days, every=int(n[0]) if n else 1)
            elif tr.find("ScheduleByMonth") is not None:
                mdays = [int(x.text) for x in tr.findall("ScheduleByMonth/DaysOfMonth/Day") if (x.text or "").isdigit()]
                t = Trigger("monthly", at=start, monthdays=mdays)
            elif tr.find("ScheduleByDay") is not None:
                n = re.match(r"\d+", tr.findtext("ScheduleByDay/DaysInterval") or "1")
                t = Trigger("daily", at=start, every=int(n[0]) if n else 1)
            else:
                t = Trigger("other")
        elif tag == "TimeTrigger":
            t = Trigger("once", at=start)
        else:
            t = Trigger({"LogonTrigger": "logon", "BootTrigger": "startup"}.get(tag, "event"))
        t.repeat, t.duration = repeat, duration if repeat else None
        out.append(_task(name, rel, line, t, program, args, f"<{tag}> in {rel}"))
    return out


def find(repo) -> list[dict]:
    """The Task Scheduler jobs of the repository, one per trigger (computed once per repository)."""
    cached = getattr(repo, "_scheduled_tasks", None)
    if cached is not None:
        return cached
    pats = [p.lower() for p in settings().get("files") or ["*.ps1", "*.psm1", "*.psd1", "*.cmd", "*.bat", "*.xml"]]
    files = [f for f in getattr(repo, "files", []) or [] if any(fnmatch.fnmatch(f.name.lower(), p) for p in pats)]
    texts: dict = {}

    def read(f) -> bytes:
        if f not in texts:
            try:
                texts[f] = f.read_bytes() if f.stat().st_size <= MAX_BYTES else b""
            except OSError:
                texts[f] = b""
        return texts[f]

    ps = [f for f in files if f.suffix.lower() in (".ps1", ".psm1", ".psd1")]
    tables_cache: dict = {}

    def tables(key: str):
        if key not in tables_cache:
            tables_cache[key] = None
            for f in ps:
                txt = _strip_comments(read(f).decode("utf-8", "replace").lstrip("﻿"))
                m = re.search(rf"(?<![\w$.]){re.escape(key)}\s*=\s*@\(", txt, re.I)
                if m:
                    body = txt[m.end() - 2:_close(txt, m.end() - 1)]
                    ctx = _PS(txt, repo.rel(f))
                    v = ctx.ev(body, {}, m.start())
                    if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                        tables_cache[key] = v
                        break
        return tables_cache[key]

    out: list[dict] = []
    for f in files:
        data = read(f)
        if not data:
            continue
        rel, ext = repo.rel(f), f.suffix.lower()
        if ext == ".xml":
            if b"mit/task" in data or b"m\x00i\x00t\x00/\x00t\x00a\x00s\x00k" in data:
                out += _xml_tasks(data, rel, f.stem)
            continue
        text = data.decode("utf-8", "replace").lstrip("﻿")
        if not re.search(r"ScheduledTask|schtasks", text, re.I):
            continue
        if ext in (".cmd", ".bat"):
            out += _cmd_tasks(text, rel)
        else:
            try:
                out += _PS(text, rel, tables).tasks()
            except (RecursionError, ValueError, IndexError):
                continue
    seen, uniq = set(), []
    for t in out:
        key = (t["file"], t["line"], t["name"], t["program"], tuple(t["arguments"]), t["trigger"])
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    try:
        repo._scheduled_tasks = uniq
    except AttributeError:
        pass
    return uniq


# ---------------------------------------------------------------------------- matching to components

def _names(c) -> set[str]:
    p = c.project
    names = {(getattr(p, "assembly_name", "") or "").lower(), (getattr(p, "name", "") or "").lower()}
    entry = (c.facts or {}).get("entry") or ""
    names.add(re.sub(r"\.(dll|exe|jar)$", "", entry.lower()))
    return {n for n in names if n}


def match_args(task: dict, c) -> list[str] | None:
    """The arguments the job passes to component c (after its executable), or None when it starts something else."""
    names = _names(c)
    seq = [task.get("program") or ""] + list(task.get("arguments") or [])
    for i, tok in enumerate(seq):
        stem = re.split(r"[\\/]", tok.strip().strip("\"'"))[-1].lower()
        stem = re.sub(r"\.(exe|dll)$", "", stem)
        if stem and stem in names:
            return seq[i + 1:]
    return None


def _concrete(args: list[str]) -> bool:
    return all(not re.search(r"\$\w|%\w+%", a) for a in args)


def cronjobs(repo, c, name: str) -> list[dict]:
    """The CronJobs of console component c, named from `name`: one per sub-command (its `commands` fact, or one for
    its `oneshot_arg`), each with the schedule and arguments of the Task Scheduler job that starts it; several jobs
    of one command become several CronJobs (`-2`, `-3`); jobs with arguments that name no command become their own
    CronJobs, named after their first argument (so do the jobs of a tool without commands that pass it different
    arguments). A command no job starts keeps the placeholder schedule (`placeholder: True`)."""
    from .generate import k8s_name
    facts = c.facts or {}
    oneshot = facts.get("oneshot_arg") or ""
    commands = list(facts.get("commands") or [])
    low = [x.lower() for x in commands]
    tasks = find(repo)
    assigned: dict[str, list] = {}
    rest = []
    for i, t in enumerate(tasks):
        args = match_args(t, c)
        if args is None:
            continue
        if commands:
            k = next((low.index(a.lower()) for a in args if a.lower() in low), None)
            if k is None:
                rest.append((i, t, args))
            else:
                assigned.setdefault(commands[k], []).append((i, t, args))
        else:
            assigned.setdefault(oneshot, []).append((i, t, args))
    jobs, used = [], set()

    def add(jname: str, cmd: str, args, sched: str | None, task: int | None):
        base, k = jname, 2
        while jname in used:
            jname, k = k8s_name(f"{base}-{k}"), k + 1
        used.add(jname)
        jobs.append({"name": jname, "command": cmd, "args": args, "schedule": sched or placeholder(),
                     "placeholder": sched is None, "task": task})

    for cmd in commands or [oneshot]:
        base = name if cmd == oneshot else k8s_name(f"{name}-{cmd}")
        default = [cmd] if cmd else None
        sel, seen = [], set()
        for i, t, args in assigned.get(cmd, []):
            key = (t["schedule"], tuple(args))
            if t["schedule"] and key not in seen:
                seen.add(key)
                sel.append((i, t, args))
        if not sel:
            add(base, cmd, default, None, None)
        named = not commands and len({tuple(a) for _, _, a in sel}) > 1     # one tool, jobs with other arguments
        for i, t, args in sel:
            concrete = bool(args) and _concrete(args)
            jname = k8s_name(f"{base}-{args[0].lstrip('-/')}") if named and concrete and args[0] != cmd else base
            add(jname, cmd, args if concrete else default, t["schedule"], i)
    for i, t, args in rest:
        if t["schedule"] and args and _concrete(args):
            add(k8s_name(f"{name}-{args[0]}"), args[0], args, t["schedule"], i)
    return jobs


def report(a) -> list[dict]:
    """Each Task Scheduler job of the application with what it became: the component that runs it and its CronJob(s),
    or why there is none (a logon job, a component that is not a console tool, nothing that matched)."""
    from .generate import buildable, k8s_name
    if getattr(a, "repo", None) is None:
        return []
    tasks = find(a.repo)
    if not tasks:
        return []
    became: dict[int, list] = {}
    owner: dict[int, str] = {}
    for c in a.components:
        for i, t in enumerate(tasks):
            if i not in owner and match_args(t, c) is not None:
                owner[i] = c.name
        if c.role == "console" and buildable(c):
            for j in cronjobs(a.repo, c, k8s_name(c.name)):
                if j["task"] is not None:
                    became.setdefault(j["task"], []).append(j["name"])
    out = []
    for i, t in enumerate(tasks):
        x = {k: t[k] for k in ("name", "file", "line", "trigger", "schedule", "note", "program", "arguments")}
        x["component"] = owner.get(i)
        x["cronjobs"] = became.get(i, [])
        if not x["cronjobs"]:
            comp = next((c for c in a.components if c.name == owner.get(i)), None)
            x["why_not"] = (t["note"] if not t["schedule"] else
                            "no component of the application runs it" if comp is None else
                            f"{comp.name} is a {comp.role} component: it runs as a Deployment" if comp.role != "console"
                            else "its arguments are not concrete" if not _concrete(match_args(t, comp) or [])
                            else f"{comp.name} gets no manifests yet ({comp.verdict}): its CronJob takes this schedule "
                                 "once it does" if not buildable(comp) else "not generated")
        out.append(x)
    return out
