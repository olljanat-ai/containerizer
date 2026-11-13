"""Developers: who commits to which repository, and what that says about the repositories nobody mapped.

Every organization scan run (full and discovery, worker.py) reads the commit authors of the last six months of each
repository from the provider's API (a disabled one only while its latest commit is in those six months) (orgsource.Provider.commits), and keeps them in cz.Developer and
cz.DeveloperRepository: one developer per e-mail address, the repositories they committed to, how many commits in
the six months, and their newest commit there (it only moves forward). A repository is read again when it has a
newer commit than the last time, or after REFRESH_DAYS, so most runs ask the API for few repositories.

Administrators map developers to business units on Admin -> Developers (admin_developers.py). The page suggests:

- a developer's business unit, from the business units of the products of the repositories they commit to;
- the business unit of a repository or product nobody mapped, from the business units of its developers.

Both weigh by commits. At the end of every run the worker also calls cz.AutoMapProjects: one product per Azure
DevOps project (GitLab subgroup) as a starting point, and the project's applications nobody mapped get it.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

HISTORY_DAYS = 183          # six months
REFRESH_DAYS = 7            # read a repository again after this long even without new commits (the counts age)
SUGGEST_SHARE = 0.6         # "apply suggestions" applies only those at least this sure
EMAIL_RE = re.compile(r"[^@\s<>\"']{1,128}@[^@\s<>\"']{1,120}\.[^@\s<>\"']{2,}")
# automation, not people: left out when collected (administrators can ignore others on the page)
BOT_RE = re.compile(r"\[bot\]|^(no-?reply|noreply|dependabot|renovate|github-actions|azure-pipelines|gitlab-bot|"
                    r"project_\d+_bot|group_\d+_bot)\b|^noreply@github\.com$", re.I)


def is_person(email: str) -> bool:
    return bool(EMAIL_RE.fullmatch(email or "")) and not BOT_RE.search(email)


@dataclass
class Authors:
    """The commit authors of one repository: e-mail -> [commits, newest commit, author name of the newest]."""
    by_email: dict = field(default_factory=dict)
    newest: datetime | None = None

    def add(self, email: str, name: str, when: datetime | None) -> None:
        if when and (self.newest is None or when > self.newest):
            self.newest = when
        email = (email or "").strip().lower()
        if not is_person(email) or len(email) > 256:
            return
        a = self.by_email.setdefault(email, [0, None, ""])
        a[0] += 1
        if when and (a[1] is None or when > a[1]):
            a[1], a[2] = when, (name or "").strip()[:200]
        elif not a[2]:
            a[2] = (name or "").strip()[:200]


def authors(prov, repo, since: datetime) -> Authors:
    out = Authors()
    for email, name, when in prov.commits(repo, since):
        out.add(email, name, when)
    return out


def _naive(d: datetime | None) -> datetime | None:
    return d.astimezone(timezone.utc).replace(tzinfo=None) if d and d.tzinfo else d


def due(row: dict, now: datetime, cutoff: datetime) -> bool:
    """Whether a repository's authors should be read in this run (naive UTC datetimes from the database)."""
    if row.get("RemovedAt"):
        return False
    latest = row.get("LatestCommitAt")
    if (row.get("AdminState") == "disabled" or row.get("ProjectState") == "disabled") and not (latest and latest >= cutoff):
        # disabled (new repositories may start so): read only while someone commits there, which says who to ask
        # before enabling it; a deprecated one nobody touched in six months costs nothing
        return False
    if latest and latest < cutoff and not row.get("HistoryAt"):
        return False                               # nobody committed in six months, and nothing to age out
    if not row.get("HistoryAt"):
        return True
    if latest and (row.get("HistoryCommitAt") is None or latest > row["HistoryCommitAt"]):
        return True                                # a newer commit than the last read
    return now - row["HistoryAt"] >= timedelta(days=REFRESH_DAYS)


def collect(conn, scan_id: int, prov, listed, now: datetime | None = None, log=print, should_stop=None,
            workers: int = 8) -> dict:
    """Read and store the commit authors of the scan's repositories that are due. Returns counts."""
    now_aware = now or datetime.now(timezone.utc)
    now_n = _naive(now_aware)
    since = now_aware - timedelta(days=HISTORY_DAYS)
    cutoff = _naive(since)
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT v.RepositoryId, v.ProjectName, v.Name, v.AdminState, v.ProjectState, v.RemovedAt, v.LatestCommitAt, "
                "r.HistoryAt, r.HistoryCommitAt FROM cz.vOrgRepository v JOIN cz.OrgRepository r ON r.RepositoryId = v.RepositoryId "
                "WHERE v.ScanId = %s", (scan_id,))
    rows = {(r["ProjectName"], r["Name"]): r for r in cur.fetchall()}
    todo = []
    for r in listed:
        row = rows.get((r.project[:200], r.name[:200]))
        if row is None or r.empty or r.archived:
            continue
        if due(row, now_n, cutoff):
            todo.append((r, row))
    counts = {"repositories": 0, "errors": 0, "developers": 0}
    if not todo:
        return counts
    log(f"reading the commit authors of {len(todo)} repositories (last {HISTORY_DAYS} days)")

    def read(item):
        r, _ = item
        if should_stop and should_stop():
            return None, "stopped"
        try:
            return authors(prov, r, since), ""
        except Exception as ex:                    # one repository must not stop the others
            from .orgsource import REDACT
            return None, REDACT(f"{type(ex).__name__}: {ex}")[:400]

    devs = _developers(conn)
    seen: set = set()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for (r, row), (found, err) in zip(todo, pool.map(read, todo)):
            if err == "stopped":
                break
            try:
                if found is None:
                    conn.cursor().execute("UPDATE cz.OrgRepository SET HistoryError = %s WHERE RepositoryId = %s",
                                          (err, row["RepositoryId"]))
                    conn.commit()
                    counts["errors"] += 1
                    continue
                store(conn, row["RepositoryId"], found, now_n, devs)
                seen |= set(found.by_email)
                counts["repositories"] += 1
            except Exception:
                conn.rollback()
                raise
    counts["developers"] = len(seen)
    return counts


def _developers(conn) -> dict:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT DeveloperId, Email, LastCommitAt FROM cz.Developer")
    return {r["Email"].lower(): {"id": r["DeveloperId"], "last": r["LastCommitAt"]} for r in cur.fetchall()}


def store(conn, repo_id: int, found: Authors, now, devs: dict) -> None:
    """One repository's authors: developers added or brought up to date, the repository's rows replaced (commit counts)
    or moved forward (newest commit), the authors no longer in the six months counted 0 (the row stays)."""
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT DeveloperId, Commits, LastCommitAt FROM cz.DeveloperRepository WHERE RepositoryId = %s", (repo_id,))
    have = {r["DeveloperId"]: r for r in cur.fetchall()}
    c = conn.cursor()
    touched = set()
    for email, (n, when, name) in sorted(found.by_email.items()):
        when = _naive(when) or now
        d = devs.get(email)
        if d is None:
            c.execute("INSERT cz.Developer (Email, Name, LastCommitAt) OUTPUT INSERTED.DeveloperId VALUES (%s, %s, %s)",
                      (email, name or None, when))
            d = devs[email] = {"id": int(c.fetchone()[0]), "last": when}
        elif d["last"] is None or when > d["last"]:
            c.execute("UPDATE cz.Developer SET LastCommitAt = %s, Name = COALESCE(%s, Name) WHERE DeveloperId = %s",
                      (when, name or None, d["id"]))
            d["last"] = when
        touched.add(d["id"])
        old = have.get(d["id"])
        if old is None:
            c.execute("INSERT cz.DeveloperRepository (DeveloperId, RepositoryId, Commits, LastCommitAt) VALUES (%s, %s, %s, %s)",
                      (d["id"], repo_id, n, when))
        elif old["Commits"] != n or when > old["LastCommitAt"]:
            c.execute("UPDATE cz.DeveloperRepository SET Commits = %s, LastCommitAt = %s WHERE DeveloperId = %s AND RepositoryId = %s",
                      (n, max(when, old["LastCommitAt"]), d["id"], repo_id))
    for dev_id, old in have.items():
        if dev_id not in touched and old["Commits"]:
            c.execute("UPDATE cz.DeveloperRepository SET Commits = 0 WHERE DeveloperId = %s AND RepositoryId = %s",
                      (dev_id, repo_id))
    c.execute("UPDATE cz.OrgRepository SET HistoryAt = %s, HistoryCommitAt = COALESCE(%s, HistoryCommitAt), "
              "HistoryError = NULL WHERE RepositoryId = %s", (now, _naive(found.newest), repo_id))
    conn.commit()


def auto_map(conn, log=print) -> None:
    """One product per project to start with (cz.AutoMapProjects); bookkeeping: a failure is logged only."""
    try:
        conn.cursor().execute("EXEC cz.AutoMapProjects")
        conn.commit()
    except Exception as ex:
        conn.rollback()
        log(f"could not map projects to products: {type(ex).__name__}: {ex}")


# -- suggestions --------------------------------------------------------------------------------------------------

@dataclass
class Suggestion:
    bu: int
    share: float                # of the commits that have a business unit
    weight: int                 # those commits
    voters: int                 # developers (or repositories) behind it

    @property
    def sure(self) -> bool:
        return self.share >= SUGGEST_SHARE


def suggest(votes) -> Suggestion | None:
    """votes: (business unit id, weight) pairs, one per voter. The business unit with the most weight."""
    total, by_bu, voters = 0, {}, {}
    for bu, w in votes:
        if bu is None or w <= 0:
            continue
        total += w
        by_bu[bu] = by_bu.get(bu, 0) + w
        voters[bu] = voters.get(bu, 0) + 1
    if not total:
        return None
    bu = max(by_bu, key=lambda b: (by_bu[b], voters[b], -b))
    return Suggestion(bu, by_bu[bu] / total, by_bu[bu], voters[bu])
