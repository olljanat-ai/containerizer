"""Review of learned rules: nothing the learning loop learns enters the ruleset until a person approves it.

The learning loop (verify --learn, analyze, org runs, ai --learn) writes what it learns into the learned
rule files. A learning run wraps that in a LearningSession: the learned folder is pointed at a staging
copy for the run, so the run itself benefits from what it learns (the re-assessment and the generated
Dockerfile use it), but the real ruleset is never touched. When the run ends, every entry that is new
in the staging copy becomes a *candidate*, stored as pending with its evidence trail:

  - the source repository, commit, application and component it was learned from,
  - the build or run outcome and the exit reason (which failure rule matched, exit code),
  - an excerpt of the failing build or run log (with secrets masked),
  - the proposed rule as YAML and as a diff of the ruleset file it would be added to,
  - a confidence and the LLM, if one proposed it.

Candidates are kept in the results database (tables RuleCandidate and RuleEvidence, written through
the ProposeRuleCandidate procedure) or, without a database, in a JSON file (FileStore). The same rule
learned again adds evidence to its candidate; a rejected rule is remembered by its fingerprint and is
not proposed again; an approved one is in the ruleset.

People review candidates on the "Rule review" admin page or with `containerizer rules`. Approving
(optionally after editing the YAML) validates the rule like the curated rules are validated, then
either opens a pull request in your internal rules repository (CONTAINERIZER_RULES_APPLY=pr, the
default; a public repository is refused) or appends it to a local checkout of it
(CONTAINERIZER_RULES_APPLY=direct). Approved rules never go into this tool's own rules folder: what
your applications taught it stays yours. The tool loads them from CONTAINERIZER_REVIEWED_RULES (a
checkout of that repository's rules folder), in tool-maintained files:

  70-reviewed.yaml            finding and plan rules (rules:)
  55-reviewed-failures.yaml   failure rules of the build-and-run loop (failures:)
  packages-reviewed.yaml      packages proven to work on Linux (linux_ok:)

See docs/rule-review.md.
"""
from __future__ import annotations

import difflib
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .rules import RULES_DIR, SEV_RANK, Rule, reviewed_dir

KINDS = {   # kind -> (file of approved entries, list key)
    "rule": ("70-reviewed.yaml", "rules"),
    "failure": ("55-reviewed-failures.yaml", "failures"),
    "package": ("packages-reviewed.yaml", "linux_ok"),
}
KEY_KIND = {key: kind for kind, (_, key) in KINDS.items()}
HEADERS = {
    "rule": "# Finding and plan rules learned by containerizer and approved in the rule review (docs/rule-review.md).\n"
            "# Maintained by the rule review: new rules are appended. Editing or deleting a rule by hand is fine.\n",
    "failure": "# Failure rules of the build-and-run loop, learned by containerizer and approved in the rule review.\n"
               "# Maintained by the rule review: new rules are appended. Editing or deleting a rule by hand is fine.\n",
    "package": "# Packages proven to work in a verified Linux container, approved in the rule review.\n"
               "# Maintained by the rule review: new entries are appended. Editing or deleting one by hand is fine.\n",
}
STATUSES = ("pending", "approved", "rejected")
# bookkeeping of the learning loop: not part of what a rule does, so not part of its fingerprint
META_KEYS = {"id", "learned_at", "learned_from", "model", "confidence", "source", "why", "fix", "refs", "reviewed"}
MAX_YAML = 20000
MAX_LOG = 6000
MIN_WHY = 60                      # as tests/test_rule_docs.py asks of the curated rules
SERIOUS = {"refactor", "rewrite", "blocker"}
REGEX_KEYS = {"sdk", "tfm", "package", "reference", "framework_ref", "output_type", "kind", "role", "name", "path",
              "code", "config", "text", "readme", "version"}
PLAN_KEYS = {"strategy", "base", "add_packages", "env", "add_writable", "publish_args", "remove_files", "single_replica",
             "port", "health", "entry", "spa_root", "args", "rid", "runtime", "tfm", "sdk_image", "runtime_image",
             "user", "workdir", "smoke_env"}
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,150}")


class ReviewError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)


def _cut(s, n: int):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


# --------------------------------------------------------------------------- rules as data

class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):      # read by people: no &id001 anchors
        return True


def to_yaml(entry) -> str:
    return yaml.dump(entry, Dumper=_NoAliases, sort_keys=False, allow_unicode=True, width=120)


def fingerprint(kind: str, entry) -> str:
    """What the rule does, independent of when and where it was learned and of its wording."""
    core = entry if not isinstance(entry, dict) else {k: v for k, v in entry.items() if k not in META_KEYS}
    return hashlib.sha256(json.dumps([kind, core], sort_keys=True, default=str).encode()).hexdigest()


def entries(folder: Path) -> list[tuple[str, object]]:
    """(kind, entry) of every rule, failure rule and package in the learned files of a folder."""
    out = []
    for f in sorted(Path(folder).glob("*.yaml")) if Path(folder).exists() else []:
        try:
            d = yaml.safe_load(f.read_text()) or {}
        except yaml.YAMLError as e:
            print(f"warning: {f.name}: {e}", file=sys.stderr)
            continue
        if not isinstance(d, dict):
            continue
        for key, kind in KEY_KIND.items():
            for e in d.get(key) or []:
                out.append((kind, e))
    return out


def rule_id(kind: str, entry) -> str:
    return str(entry) if kind == "package" else str(entry.get("id") or "")


def title_of(kind: str, entry) -> str:
    if kind == "package":
        return f"Package works on Linux: {entry}"
    if kind == "failure":
        return " ".join(str(entry.get("diagnosis") or entry.get("id") or "").split())
    if entry.get("phase") == "plan":
        return "Build plan: " + (" ".join(str(entry.get("why") or "").split()) or entry.get("id", ""))
    return " ".join(str(entry.get("title") or entry.get("id") or "").split())


def target_file(kind: str) -> str:
    """The file in the internal rules repository's rules folder."""
    return KINDS[kind][0]


def appended_text(kind: str, entry, current: str | None) -> str:
    """The ruleset file after appending the entry (the file is created when it does not exist)."""
    key = KINDS[kind][1]
    if not current or not current.strip():
        current = HEADERS[kind] + f"{key}:\n"
    elif re.search(rf"^{key}:\s*\[\]\s*$", current, re.M):
        current = re.sub(rf"^{key}:\s*\[\]\s*$", f"{key}:", current, count=1, flags=re.M)
    if not current.endswith("\n"):
        current += "\n"
    # same indentation as the list's existing items (hand-edited files may indent them)
    m = re.search(rf"^{key}:[ \t]*\n(?:[ \t]*(?:#.*)?\n)*([ \t]*)- ", current, re.M)
    pad = m.group(1) if m else ""
    new = current + "".join(pad + line if line.strip() else line for line in to_yaml([entry]).splitlines(True))
    try:
        d = yaml.safe_load(new) or {}
    except yaml.YAMLError:
        d = {}
    items = d.get(key) if isinstance(d, dict) else None
    if not items or items[-1] != entry:
        raise ReviewError(f"{target_file(kind)}: cannot append safely (`{key}:` must be the file's last list); "
                          "fix the file by hand first")
    return new


def diff_for(kind: str, entry, rules_dir: Path | None = None) -> str:
    rules_dir = rules_dir or reviewed_dir()
    path = Path(rules_dir) / KINDS[kind][0] if rules_dir else None
    cur = path.read_text() if path and path.exists() else ""
    try:
        new = appended_text(kind, entry, cur)
    except ReviewError as e:
        return str(e)
    return "".join(difflib.unified_diff(cur.splitlines(True), new.splitlines(True),
                                        fromfile="a/" + target_file(kind), tofile="b/" + target_file(kind), n=2))


def parse_entry(kind: str, text: str):
    if len(text) > MAX_YAML:
        raise ReviewError(f"the rule is longer than {MAX_YAML} characters")
    try:
        v = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ReviewError(f"not valid YAML: {str(e).splitlines()[0]}") from None
    if isinstance(v, list) and len(v) == 1:
        v = v[0]
    return v


def _walk_regex(node, problems: list, path: str = "when") -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k in REGEX_KEYS and isinstance(v, str):
                try:
                    re.compile(v)
                except re.error as e:
                    problems.append(f"{path}.{k}: not a valid regular expression ({e})")
            elif isinstance(v, (dict, list)):
                _walk_regex(v, problems, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk_regex(v, problems, f"{path}[{i}]")


def existing_ids(*dirs: Path | None) -> dict[str, set]:
    """Ids already in the ruleset files (not the learned folder), per list key."""
    out = {"rules": set(), "failures": set(), "linux_ok": set()}
    for f in [f for d in dirs if d and Path(d).is_dir() for f in sorted(Path(d).glob("*.yaml"))]:
        try:
            d = yaml.safe_load(f.read_text()) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(d, dict):
            continue
        for item in d.get("rules") or []:
            if isinstance(item, dict) and item.get("id"):
                out["rules"].add(str(item["id"]))
        for item in d.get("failures") or []:
            if isinstance(item, dict) and item.get("id"):
                out["failures"].add(str(item["id"]))
        for item in d.get("linux_ok") or []:
            out["linux_ok"].add(str(item))
    return out


def validate(kind: str, entry, rules_dir: Path | None = None) -> list[str]:
    """Problems that keep the rule out of the ruleset; the same bar as the curated rules. Ids must be
    new to the curated rules and to the approved ones (`rules_dir`, default CONTAINERIZER_REVIEWED_RULES)."""
    p: list[str] = []
    ids = existing_ids(RULES_DIR, rules_dir or reviewed_dir())
    if kind == "package":
        if not isinstance(entry, str) or not entry.strip():
            return ["a package entry is one regular expression (a YAML string)"]
        if len(entry) > 300:
            p.append("the package expression is longer than 300 characters")
        try:
            rx = re.compile(f"^(?:{entry})$", re.I)
        except re.error as e:
            return [f"not a valid regular expression ({e})"]
        if rx.match("") or rx.match("Some.Unrelated.Package.Name"):
            p.append("the expression matches (almost) any package name")
        if entry in ids["linux_ok"]:
            p.append("already in the ruleset")
        return p
    if not isinstance(entry, dict):
        return ["a rule is a YAML mapping (id: ..., when: ...)"]
    rid = str(entry.get("id") or "")
    if not ID_RE.fullmatch(rid):
        p.append("id: lower-case letters, digits, '.', '-' and '_' only (2-150 characters)")
    if kind == "failure":
        if rid in ids["failures"]:
            p.append(f"id {rid} is already used in the ruleset; choose another id")
        if entry.get("stage") not in ("build", "run"):
            p.append("stage: build or run")
        if entry.get("outcome") not in ("retry", "external", "platform", "code"):
            p.append("outcome: retry, external, platform or code")
        m = entry.get("match")
        if not isinstance(m, str) or not m:
            p.append("match: a regular expression for the log is required")
        else:
            try:
                rx = re.compile(m)
                if rx.search("") is not None:
                    p.append("match: the expression matches an empty log")
            except re.error as e:
                p.append(f"match: not a valid regular expression ({e})")
        if not str(entry.get("diagnosis") or "").strip():
            p.append("diagnosis: say what the failure means")
        fix = entry.get("fix")
        if entry.get("outcome") == "retry":
            if not isinstance(fix, dict) or not fix:
                p.append("fix: a build-plan patch is required for outcome retry")
            elif set(fix) - PLAN_KEYS - {"prune_cache"}:
                p.append("fix: unknown build-plan keys " + ", ".join(sorted(set(fix) - PLAN_KEYS - {"prune_cache"})))
        for u in entry.get("refs") or []:
            if not (isinstance(u, str) and u.startswith("https://") and " " not in u):
                p.append(f"refs: not an https URL: {u!r}")
        return p
    # finding and plan rules
    if rid in ids["rules"]:
        p.append(f"id {rid} is already used in the ruleset; choose another id")
    try:
        r = Rule.from_dict(entry)
    except (TypeError, ValueError) as e:
        return p + [f"not a valid rule: {e}"]
    if not isinstance(r.when, dict) or not r.when:
        p.append("when: a condition is required")
    else:
        _walk_regex(r.when, p)
    if r.scope not in ("project", "repo"):
        p.append("scope: project or repo")
    if r.phase == "plan":
        if not isinstance(r.plan, dict) or not r.plan:
            p.append("plan: a build-plan patch is required")
        elif set(r.plan) - PLAN_KEYS:
            p.append("plan: unknown build-plan keys " + ", ".join(sorted(set(r.plan) - PLAN_KEYS)))
        if not " ".join(str(r.why).split()):
            p.append("why: say why the build plan needs this")
    elif r.phase == "finding":
        why = " ".join(str(r.why).split())
        if not r.title.strip():
            p.append("title: required")
        if len(why) < MIN_WHY:
            p.append(f"why: explain the finding in at least {MIN_WHY} characters ({len(why)} now)")
        if not str(r.fix).strip():
            p.append("fix: say how to fix it")
        if r.severity in SERIOUS and not r.refs:
            p.append(f"refs: a {r.severity} finding needs at least one verified https reference")
        if r.severity not in SEV_RANK:
            p.append("severity: info, config, refactor, rewrite or blocker")
    else:
        p.append("phase: finding or plan (role and facts rules are curated by hand)")
    for u in r.refs:
        if not (isinstance(u, str) and u.startswith("https://") and " " not in u):
            p.append(f"refs: not an https URL: {u!r}")
    return p


# --------------------------------------------------------------------------- evidence

_SECRETS = [
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:basic|bearer|negotiate|ntlm))\s+\S+"), r"\1 ***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|client_secret|token|access_token|api[_-]?key|accountkey|"
                r"sharedaccesskey|sharedaccesssignature|sig)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;,&\"']+)"), r"\1\2***"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1***@"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "***"),
]


def redact(text: str) -> str:
    """Masks credentials that applications commonly print (connection strings, tokens, keys)."""
    for rx, rep in _SECRETS:
        text = rx.sub(rep, text)
    return text


def _attempt_line(h: dict) -> str:
    what = h.get("rule") or h.get("status") or ""
    bits = [f"attempt {h.get('attempt')}", str(h.get("stage") or ""), what]
    if h.get("outcome"):
        bits.append(f"({h['outcome']})")
    if h.get("exit_code") not in (None, ""):
        bits.append(f"exit code {h['exit_code']}")
    line = " ".join(b for b in bits if b)
    if h.get("diagnosis"):
        line += ": " + " ".join(str(h["diagnosis"]).split())
    if h.get("note"):
        line += f" [{h['note']}]"
    return line


def evidence_for(kind: str, entry, results: list[dict], source: dict, ai: bool, model: str | None) -> dict:
    """The evidence trail of one learned entry, from the verification results of the run."""
    learned_from = str(entry.get("learned_from") or "") if isinstance(entry, dict) else ""
    app, _, comp = learned_from.partition("/")
    r = None
    for x in results:
        if learned_from and f"{x.get('app')}/{x.get('component')}" == learned_from:
            r = x
            break
    if r is None and kind == "package" and len([x for x in results if x.get("status") in ("ok", "ok-external")]) == 1:
        r = next(x for x in results if x.get("status") in ("ok", "ok-external"))     # packages carry no learned_from
    used_model = entry.get("model") if isinstance(entry, dict) else None
    if not used_model and ai and isinstance(entry, dict) and entry.get("source") == "ai":
        try:
            from .ai import model_name
            used_model = model_name(model)
        except Exception:  # noqa: BLE001 - only a label
            used_model = model
    ev = {"Application": _cut(app or (r or {}).get("app") or source.get("app"), 200),
          "Component": _cut(comp or (r or {}).get("component"), 200),
          "RepositoryUrl": _cut(source.get("repository_url"), 400), "SourceCommit": _cut(source.get("commit"), 64),
          "Stage": None, "Outcome": None, "ExitReason": None, "LogExcerpt": None, "Model": _cut(used_model, 200),
          "AttemptsJson": None}
    if r:
        attempts = r.get("attempts") or []
        ev["Outcome"] = _cut(r.get("status"), 40)
        failing = [h for h in attempts if h.get("status") != "ok"]
        rid = entry.get("id", "") if isinstance(entry, dict) else ""
        # the attempt behind this entry: the failure rule a learned plan rule came from, else the last failure
        hit = next((h for h in failing if h.get("rule") and (h["rule"] == rid or f"-{h['rule']}-" in f"-{rid}-")), None)
        hit = hit or (failing[-1] if failing else None)
        if hit:
            ev["Stage"] = _cut(hit.get("stage"), 20)
            ev["LogExcerpt"] = _cut(redact(str(hit.get("log_tail") or "")), MAX_LOG) or None
        ev["ExitReason"] = _cut("\n".join(_attempt_line(h) for h in attempts), 2000) or None
        if r.get("finding"):
            ev["ExitReason"] = _cut(f"finding: {r['finding'].get('title', '')}\n" + (ev["ExitReason"] or ""), 2000)
        ev["AttemptsJson"] = json.dumps([{k: v for k, v in h.items() if k != "log_tail"} for h in attempts], default=str)
    elif isinstance(entry, dict) and entry.get("source") == "ai":
        ev["Outcome"] = "ai-review"
        ev["ExitReason"] = ("Proposed by the LLM review of an uncertain component; its condition was checked to match "
                            "the code it was learned from. Not confirmed by a build and run.")
    return ev


def confidence_for(kind: str, entry, ev: dict) -> float:
    """The rule's own confidence when it has one; else how strongly the run backs it."""
    if isinstance(entry, dict) and isinstance(entry.get("confidence"), (int, float)):
        return float(entry["confidence"])
    if ev.get("Outcome") in ("ok", "ok-external"):
        return 0.9            # the container built and ran with it
    if ev.get("Outcome") == "finding":
        return 0.8            # the failure was observed at runtime
    return 0.6


def candidate_from(kind: str, entry, ev: dict) -> dict:
    return {"Kind": kind, "Fingerprint": fingerprint(kind, entry), "RuleId": _cut(rule_id(kind, entry), 200),
            "Title": _cut(title_of(kind, entry), 400) or rule_id(kind, entry),
            "Source": _cut((entry.get("source") if isinstance(entry, dict) else None) or "learned", 40),
            "TargetFile": target_file(kind), "RuleYaml": to_yaml(entry), "Diff": diff_for(kind, entry),
            "Confidence": round(confidence_for(kind, entry, ev), 2), "Model": ev.get("Model"),
            "LearnedFrom": _cut(entry.get("learned_from") if isinstance(entry, dict) else
                                "/".join(x for x in (ev.get("Application"), ev.get("Component")) if x), 400)}


# --------------------------------------------------------------------------- stores

class FileStore:
    """Candidates in one JSON file, for use without the results database (single machine)."""

    def __init__(self, folder: Path | str):
        self.folder = Path(folder)
        self.path = self.folder / "candidates.json"

    @contextmanager
    def _locked(self, write: bool):
        self.folder.mkdir(parents=True, exist_ok=True)
        with open(self.folder / ".lock", "a+") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            data = json.loads(self.path.read_text()) if self.path.exists() else {"next": 1, "candidates": []}
            yield data
            if write:
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, indent=1, default=str))
                os.chmod(tmp, 0o600)
                tmp.replace(self.path)

    def propose(self, cand: dict, ev: dict) -> tuple[int, str]:
        now = _now().isoformat()
        with self._locked(True) as d:
            c = next((x for x in d["candidates"] if x["Fingerprint"] == cand["Fingerprint"]), None)
            if c and c["Status"] in ("rejected", "approved"):
                return c["CandidateId"], c["Status"]
            if c:
                c["SeenCount"] += 1
                c["LastSeenAt"] = now
                outcome = "seen"
            else:
                c = {**cand, "CandidateId": d["next"], "Status": "pending", "SeenCount": 1, "FirstSeenAt": now,
                     "LastSeenAt": now, "ReviewedBy": None, "ReviewedByName": None, "ReviewedAt": None,
                     "ReviewNote": None, "FinalYaml": None, "AppliedAs": None, "PullRequestUrl": None,
                     "ClaimedBy": None, "ClaimedAt": None, "evidence": [], "history": []}
                d["next"] += 1
                d["candidates"].append(c)
                c["history"].append({"At": now, "By": "learning loop", "Action": "proposed"})
                outcome = "new"
            c["evidence"] = (c["evidence"] + [{**ev, "SeenAt": now}])[-20:]
            return c["CandidateId"], outcome

    def list(self, status: str | None = "pending", limit: int = 500) -> list[dict]:
        with self._locked(False) as d:
            rows = [{k: v for k, v in c.items() if k not in ("evidence", "history")} for c in d["candidates"]
                    if status in (None, "", "all") or c["Status"] == status]
        return sorted(rows, key=lambda c: c["LastSeenAt"], reverse=True)[:limit]

    def get(self, cid: int) -> dict | None:
        with self._locked(False) as d:
            c = next((x for x in d["candidates"] if x["CandidateId"] == cid), None)
            if not c:
                return None
            return {**c, "evidence": list(reversed(c["evidence"]))}

    def counts(self) -> dict:
        out = dict.fromkeys(STATUSES, 0)
        for c in self.list(None, 100000):
            out[c["Status"]] = out.get(c["Status"], 0) + 1
        return out

    def claim(self, cid: int, user: str) -> bool:
        with self._locked(True) as d:
            c = next((x for x in d["candidates"] if x["CandidateId"] == cid), None)
            if not c or c["Status"] != "pending":
                return False
            if c.get("ClaimedAt") and (_now() - datetime.fromisoformat(c["ClaimedAt"])).total_seconds() < 600:
                return False
            c["ClaimedBy"], c["ClaimedAt"] = user, _now().isoformat()
            return True

    def release(self, cid: int) -> None:
        with self._locked(True) as d:
            for c in d["candidates"]:
                if c["CandidateId"] == cid:
                    c["ClaimedBy"] = c["ClaimedAt"] = None

    def decide(self, cid: int, status: str, user: str, name: str | None, note: str | None, final_yaml: str | None = None,
               applied_as: str | None = None, pr_url: str | None = None) -> bool:
        now = _now().isoformat()
        with self._locked(True) as d:
            c = next((x for x in d["candidates"] if x["CandidateId"] == cid), None)
            if not c or c["Status"] != "pending":
                return False
            c.update(Status=status, ReviewedBy=user, ReviewedByName=name, ReviewedAt=now, ReviewNote=note,
                     FinalYaml=final_yaml, AppliedAs=applied_as, PullRequestUrl=pr_url, ClaimedBy=None, ClaimedAt=None)
            c["history"].append({"At": now, "By": name or user, "Action": status, "Note": note,
                                 "Edited": bool(final_yaml and final_yaml != c["RuleYaml"]), "PullRequestUrl": pr_url})
            return True


_COLS = ("CandidateId, Kind, Fingerprint, RuleId, Title, Source, TargetFile, RuleYaml, Diff, Confidence, Model, LearnedFrom, "
         "Status, SeenCount, FirstSeenAt, LastSeenAt, ReviewedBy, ReviewedByName, ReviewedAt, ReviewNote, FinalYaml, "
         "AppliedAs, PullRequestUrl, ClaimedBy, ClaimedAt, ApproveRequestedAt, ApproveByName, ApproveBy, ApproveStartedAt, "
         "ApplyError")


class SqlStore:
    """Candidates in the results database. Proposing needs a writer login (it may only run the
    ProposeRuleCandidate procedure); reviewing needs an admin login, with the reviewer put in the
    connection's SESSION_CONTEXT (Connection.set_user) so the change history names them."""

    def __init__(self, conn, close: bool = False):
        self.conn = conn
        self._close = close

    @classmethod
    def connect(cls, cs: str | None = None, password: str | None = None) -> "SqlStore":
        from .sqlstore import connect
        return cls(connect(cs, password), close=True)

    def close(self) -> None:
        if self._close:
            self.conn.close()

    def propose(self, cand: dict, ev: dict) -> tuple[int, str]:
        cur = self.conn.cursor()
        try:
            cur.execute("EXEC cz.ProposeRuleCandidate @Kind = %s, @Fingerprint = %s, @RuleId = %s, @Title = %s, @Source = %s, "
                        "@TargetFile = %s, @RuleYaml = %s, @Diff = %s, @Confidence = %s, @Model = %s, @LearnedFrom = %s, "
                        "@Application = %s, @Component = %s, @RepositoryUrl = %s, @SourceCommit = %s, @Stage = %s, "
                        "@Outcome = %s, @ExitReason = %s, @LogExcerpt = %s, @EvidenceModel = %s, @AttemptsJson = %s",
                        (cand["Kind"], cand["Fingerprint"], cand["RuleId"], cand["Title"], cand["Source"], cand["TargetFile"],
                         cand["RuleYaml"], cand["Diff"], cand["Confidence"], cand["Model"], cand["LearnedFrom"],
                         ev.get("Application"), ev.get("Component"), ev.get("RepositoryUrl"), ev.get("SourceCommit"),
                         ev.get("Stage"), ev.get("Outcome"), ev.get("ExitReason"), ev.get("LogExcerpt"), ev.get("Model"),
                         ev.get("AttemptsJson")))
            row = cur.fetchone()
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return int(row[0]), str(row[1])

    def list(self, status: str | None = "pending", limit: int = 500) -> list[dict]:
        cur = self.conn.cursor(as_dict=True)
        where = "" if status in (None, "", "all") else "WHERE Status = %s"
        cur.execute(f"SELECT TOP ({int(limit)}) {_COLS} FROM cz.RuleCandidate {where} ORDER BY LastSeenAt DESC, CandidateId DESC",
                    (status,) if where else None)
        return cur.fetchall()

    def get(self, cid: int) -> dict | None:
        cur = self.conn.cursor(as_dict=True)
        cur.execute(f"SELECT {_COLS} FROM cz.RuleCandidate WHERE CandidateId = %s", (cid,))
        c = cur.fetchone()
        if not c:
            return None
        cur.execute("SELECT TOP (20) SeenAt, Application, Component, RepositoryUrl, SourceCommit, Stage, Outcome, ExitReason, "
                    "LogExcerpt, Model, AttemptsJson FROM cz.RuleEvidence WHERE CandidateId = %s "
                    "ORDER BY SeenAt DESC, EvidenceId DESC", (cid,))
        c["evidence"] = cur.fetchall()
        return c

    def counts(self) -> dict:
        cur = self.conn.cursor()
        cur.execute("SELECT Status, COUNT(*) FROM cz.RuleCandidate GROUP BY Status")
        out = dict.fromkeys(STATUSES, 0)
        out.update({s: int(n) for s, n in cur.fetchall()})
        return out

    def claim(self, cid: int, user: str) -> bool:
        """Only one reviewer applies a candidate at a time (a claim expires after 10 minutes)."""
        cur = self.conn.cursor()
        cur.execute("UPDATE cz.RuleCandidate SET ClaimedBy = %s, ClaimedAt = SYSUTCDATETIME() WHERE CandidateId = %s "
                    "AND Status = N'pending' AND (ClaimedAt IS NULL OR ClaimedAt < DATEADD(minute, -10, SYSUTCDATETIME()))",
                    (_cut(user, 256), cid))
        n = cur.rowcount
        self.conn.commit()
        return n == 1

    def release(self, cid: int) -> None:
        self.conn.cursor().execute("UPDATE cz.RuleCandidate SET ClaimedBy = NULL, ClaimedAt = NULL WHERE CandidateId = %s", (cid,))
        self.conn.commit()

    def decide(self, cid: int, status: str, user: str, name: str | None, note: str | None, final_yaml: str | None = None,
               applied_as: str | None = None, pr_url: str | None = None) -> bool:
        """Not while the scan worker is opening the pull request of an approval (unless it stopped on it)."""
        cur = self.conn.cursor()
        cur.execute("UPDATE cz.RuleCandidate SET Status = %s, ReviewedBy = %s, ReviewedByName = %s, ReviewedAt = SYSUTCDATETIME(), "
                    "ReviewNote = %s, FinalYaml = %s, AppliedAs = %s, PullRequestUrl = %s, ClaimedBy = NULL, ClaimedAt = NULL, "
                    "ApproveRequestedAt = NULL, ApproveStartedAt = NULL, ApplyError = NULL "
                    "WHERE CandidateId = %s AND Status = N'pending' "
                    "AND (ApproveStartedAt IS NULL OR ApproveStartedAt < DATEADD(minute, -15, SYSUTCDATETIME()))",
                    (status, _cut(user, 256), _cut(name, 256), _cut(note, 1000), final_yaml, applied_as, _cut(pr_url, 400), cid))
        n = cur.rowcount
        self.conn.commit()
        return n == 1

    def request_approval(self, cid: int, user: str, name: str | None, role: str | None, yaml_text: str,
                         note: str | None) -> bool:
        """Approve through the scan worker, which holds the rules repository's token: it opens the pull
        request and records the decision in this reviewer's name (FinishRuleApproval)."""
        cur = self.conn.cursor()
        cur.execute("UPDATE cz.RuleCandidate SET ApproveRequestedAt = SYSUTCDATETIME(), ApproveBy = %s, ApproveByName = %s, "
                    "ApproveRole = %s, ApproveYaml = %s, ApproveNote = %s, ApproveStartedAt = NULL, ApplyError = NULL "
                    "WHERE CandidateId = %s AND Status = N'pending' AND ApproveRequestedAt IS NULL "
                    "AND (ClaimedAt IS NULL OR ClaimedAt < DATEADD(minute, -10, SYSUTCDATETIME()))",
                    (_cut(user, 256), _cut(name, 256), _cut(role, 40), yaml_text, _cut(note, 1000), cid))
        n = cur.rowcount
        self.conn.commit()
        return n == 1


def default_dir() -> Path:
    from .verify import WORK
    return Path(os.environ.get("CONTAINERIZER_REVIEW_DIR") or (WORK / "rule-review"))


def open_store(sql: str | None = None, password: str | None = None, folder: str | None = None):
    """The results database when one is configured (--sql or CONTAINERIZER_SQL), else the JSON file."""
    if folder:
        return FileStore(folder)
    if sql or os.environ.get("CONTAINERIZER_SQL"):
        return SqlStore.connect(sql, password)
    return FileStore(default_dir())


# --------------------------------------------------------------------------- the learning run

def review_enabled(env=os.environ) -> bool:
    return (env.get("CONTAINERIZER_RULE_REVIEW") or "on").strip().lower() not in ("off", "0", "false", "no")


def _point_learned(path: Path) -> list:
    """Point every reader and writer of the learned rules at `path`; returns what to restore."""
    from . import ai, confidence, rules, verify
    saved = [(rules, "LEARNED_DIR", rules.LEARNED_DIR), (verify, "LEARNED", verify.LEARNED), (ai, "LEARNED", ai.LEARNED)]
    rules.LEARNED_DIR = verify.LEARNED = ai.LEARNED = Path(path)
    confidence.reset_cache()
    return saved


def _restore(saved: list) -> None:
    from . import confidence
    for mod, name, val in saved:
        setattr(mod, name, val)
    confidence.reset_cache()


class LearningSession:
    """Wrap a learning run: what it learns is staged, then proposed for review.

        with LearningSession(source_path=path) as ls:
            results = verify_app(a, learn=True)
            ls.add_results(results)

    Not thread-safe: one learning run per process at a time (the CLI, the org runner and the scan
    worker run one at a time)."""

    def __init__(self, store=None, *, source_path: Path | None = None, app: str | None = None, ai: bool = False,
                 model: str | None = None, sql: str | None = None, enabled: bool | None = None, log=None):
        self.enabled = review_enabled() if enabled is None else enabled
        self._store, self.sql = store, sql
        self.source_path, self.app, self.ai, self.model = source_path, app, ai, model
        self.results: list[dict] = []
        self.proposed: list[tuple[int, str, str]] = []           # (candidate id, outcome, rule id)
        self.log = log or (lambda m: print(m, file=sys.stderr))
        self._saved = None
        self._staging: Path | None = None

    def add_results(self, results) -> None:
        self.results += [r for r in results or [] if isinstance(r, dict)]

    def __enter__(self) -> "LearningSession":
        if not self.enabled:
            return self
        from . import rules
        self._staging = Path(tempfile.mkdtemp(prefix="cz-learned-"))
        if rules.LEARNED_DIR.exists():
            shutil.copytree(rules.LEARNED_DIR, self._staging, dirs_exist_ok=True)
        self._before = {fingerprint(k, e) for k, e in entries(self._staging)}
        self._saved = _point_learned(self._staging)
        return self

    def __exit__(self, *exc) -> None:
        if not self.enabled or self._saved is None:
            return
        _restore(self._saved)
        self._saved = None
        try:
            new = [(k, e) for k, e in entries(self._staging) if fingerprint(k, e) not in self._before]
            if new:
                self._propose(new)
        except Exception as e:  # noqa: BLE001 - never hide the run's own result or error
            self.log(f"warning: rule review: could not store what was learned: {type(e).__name__}: {e}")
        finally:
            shutil.rmtree(self._staging, ignore_errors=True)

    def _propose(self, new: list) -> None:
        source = {"app": self.app}
        if self.source_path:
            from .sqlstore import source_info
            source.update(source_info(Path(self.source_path), self.app or Path(self.source_path).name))
        store = self._store or open_store(self.sql)
        try:
            seen = set()
            for kind, entry in new:
                fp = fingerprint(kind, entry)
                if fp in seen:
                    continue
                seen.add(fp)
                ev = evidence_for(kind, entry, self.results, source, self.ai, self.model)
                cid, outcome = store.propose(candidate_from(kind, entry, ev), ev)
                self.proposed.append((cid, outcome, rule_id(kind, entry)))
        finally:
            if store is not self._store and hasattr(store, "close"):
                store.close()
        by = {}
        for _, o, _ in self.proposed:
            by[o] = by.get(o, 0) + 1
        parts = [f"{by[o]} {t}" for o, t in (("new", "new"), ("seen", "seen before"), ("rejected", "rejected before"),
                                              ("approved", "already approved")) if by.get(o)]
        self.log(f"rule review: {len(self.proposed)} learned rule(s): {', '.join(parts)}; "
                 "review them on the admin page or with `containerizer rules list`")


# --------------------------------------------------------------------------- approving

@dataclass
class ApplyConfig:
    """Where approved rules go: always your internal rules repository, never this tool's rules folder.
    CONTAINERIZER_RULES_APPLY=pr (default) opens a pull request in CONTAINERIZER_RULES_REPO (refused when
    the repository is public); =direct appends to the checkout in CONTAINERIZER_REVIEWED_RULES."""
    mode: str = "pr"
    repo: str = ""
    branch: str = "main"
    provider: str = ""
    api_url: str = ""
    token_env: str = "CONTAINERIZER_RULES_TOKEN"
    path: str = "rules"
    rules_dir: Path | None = None

    @classmethod
    def from_env(cls, env=os.environ) -> "ApplyConfig":
        from .orgsource import strip_userinfo
        c = cls(mode=(env.get("CONTAINERIZER_RULES_APPLY") or "pr").strip().lower(),
                repo=strip_userinfo((env.get("CONTAINERIZER_RULES_REPO") or "").strip()),
                branch=(env.get("CONTAINERIZER_RULES_BRANCH") or "main").strip(),
                provider=(env.get("CONTAINERIZER_RULES_PROVIDER") or "").strip().lower(),
                api_url=(env.get("CONTAINERIZER_RULES_API_URL") or "").strip().rstrip("/"),
                token_env=(env.get("CONTAINERIZER_RULES_TOKEN_ENV") or "CONTAINERIZER_RULES_TOKEN").strip(),
                path=(env.get("CONTAINERIZER_RULES_PATH") or "rules").strip().strip("/"),
                rules_dir=Path(env["CONTAINERIZER_REVIEWED_RULES"]).expanduser().resolve()
                if (env.get("CONTAINERIZER_REVIEWED_RULES") or "").strip() else None)
        if c.repo and not c.provider:
            c.provider = infer_provider(c.repo)
        return c

    def check(self) -> None:
        if self.mode not in ("pr", "direct"):
            raise ReviewError("CONTAINERIZER_RULES_APPLY must be pr or direct")
        if self.mode == "direct":
            if not self.rules_dir:
                raise ReviewError("CONTAINERIZER_RULES_APPLY=direct writes to a checkout of your internal rules "
                                  "repository: set CONTAINERIZER_REVIEWED_RULES to its rules folder")
            tool = RULES_DIR.parent.resolve()
            if Path(self.rules_dir).resolve() == tool or tool in Path(self.rules_dir).resolve().parents:
                raise ReviewError("CONTAINERIZER_REVIEWED_RULES points into this tool's own folder; approved rules "
                                  "belong in your internal rules repository")
            return
        if not self.repo:
            raise ReviewError("approving opens a pull request in your internal rules repository: set "
                              "CONTAINERIZER_RULES_REPO (its https URL) and a token in CONTAINERIZER_RULES_TOKEN, or "
                              "CONTAINERIZER_RULES_APPLY=direct with CONTAINERIZER_REVIEWED_RULES")
        if not self.repo.startswith("https://"):
            raise ReviewError("CONTAINERIZER_RULES_REPO must be an https:// URL")
        if self.provider not in ("github", "gitlab", "azure-devops"):
            raise ReviewError("cannot tell the provider of CONTAINERIZER_RULES_REPO: set CONTAINERIZER_RULES_PROVIDER "
                              "to github, gitlab or azure-devops")
        if self.api_url and not self.api_url.startswith("https://"):
            raise ReviewError("CONTAINERIZER_RULES_API_URL must be an https:// URL")
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", self.branch) or ".." in self.branch:
            raise ReviewError("CONTAINERIZER_RULES_BRANCH: not a valid branch name")
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", self.path) or ".." in self.path.split("/"):
            raise ReviewError("CONTAINERIZER_RULES_PATH: a plain folder inside the repository")

    def describe(self) -> str:
        if self.mode == "direct":
            return f"appended to the internal rules in {self.rules_dir}"
        return (f"proposed in a pull request to the internal rules repository {self.repo} ({self.branch})"
                if self.repo else "pull request (not configured)")


# --------------------------------------------------------------------------- the internal rules repository
# set on the admin pages (one RulesRepository row); its token is the write token registered for its URL under
# Source control, which only the scan worker can open. The worker opens the pull requests of approvals and
# keeps a checkout of the approved rules for the scans.

REPO_COLS = "RepoUrl, Provider, ApiUrl, Branch, Path, ChangedAt"


def load_repository(conn) -> dict | None:
    cur = conn.cursor(as_dict=True)
    cur.execute(f"SELECT {REPO_COLS} FROM cz.RulesRepository WHERE RulesRepositoryId = 1")
    return cur.fetchone()


def repository_config(row: dict) -> ApplyConfig:
    return ApplyConfig(mode="pr", repo=row["RepoUrl"], provider=row["Provider"], api_url=row.get("ApiUrl") or "",
                       branch=row.get("Branch") or "main", path=(row.get("Path") or "rules").strip("/"))


def check_repository(url: str, provider: str, api_url: str, branch: str, path: str) -> tuple[ApplyConfig, list[str]]:
    """The settings an administrator entered, checked like the environment settings are."""
    from .orgsource import strip_userinfo
    url = (url or "").strip()
    errors = []
    if url != strip_userinfo(url):
        errors.append("the repository URL must not contain a user name or token: register the token under Source control")
    cfg = ApplyConfig(mode="pr", repo=url, provider=(provider or "").strip().lower() or infer_provider(url),
                      api_url=(api_url or "").strip().rstrip("/"), branch=(branch or "").strip() or "main",
                      path=(path or "").strip().strip("/") or "rules")
    if re.search(r"[<>\"' ]", url + cfg.api_url):
        errors.append("the URLs must not contain spaces, quotes or angle brackets")
    try:
        cfg.check()
    except ReviewError as ex:
        errors.append(str(ex).replace("CONTAINERIZER_RULES_REPO", "the repository URL")
                      .replace("CONTAINERIZER_RULES_PROVIDER", "the provider").replace("CONTAINERIZER_RULES_API_URL", "the API URL")
                      .replace("CONTAINERIZER_RULES_BRANCH", "branch").replace("CONTAINERIZER_RULES_PATH", "folder"))
    if len(url) > 400 or len(cfg.api_url) > 400:
        errors.append("the URLs can be at most 400 characters")
    return cfg, errors


def save_repository(conn, cfg: ApplyConfig) -> None:
    cur = conn.cursor()
    cur.execute("UPDATE cz.RulesRepository SET RepoUrl = %s, Provider = %s, ApiUrl = %s, Branch = %s, Path = %s, "
                "ChangedAt = SYSUTCDATETIME() WHERE RulesRepositoryId = 1",
                (cfg.repo, cfg.provider, cfg.api_url or None, cfg.branch, cfg.path))
    if cur.rowcount == 0:
        cur.execute("INSERT cz.RulesRepository (RulesRepositoryId, RepoUrl, Provider, ApiUrl, Branch, Path) "
                    "VALUES (1, %s, %s, %s, %s, %s)", (cfg.repo, cfg.provider, cfg.api_url or None, cfg.branch, cfg.path))
    conn.commit()


def delete_repository(conn) -> None:
    conn.cursor().execute("DELETE cz.RulesRepository WHERE RulesRepositoryId = 1")
    conn.commit()


def next_approval(conn) -> dict | None:
    """The oldest approval waiting for the scan worker (taken: no other worker gets it for 15 minutes)."""
    cur = conn.cursor(as_dict=True)
    cur.execute("EXEC cz.NextRuleApproval")
    row = cur.fetchone()
    conn.commit()
    return row


def finish_approval(conn, cid: int, final_yaml: str | None, pr_url: str | None, error: str | None) -> bool:
    cur = conn.cursor()
    cur.execute("EXEC cz.FinishRuleApproval @CandidateId = %s, @FinalYaml = %s, @PullRequestUrl = %s, @Error = %s",
                (cid, final_yaml, _cut(pr_url, 400), _cut(error, 1000)))
    row = cur.fetchone()
    conn.commit()
    return bool(row and row[0])


def process_approval(conn, creds, work: Path, log=print) -> bool:
    """The scan worker: open the pull request of the oldest waiting approval and record the result.
    `creds` is the registered credentials opened with the worker's key. False when none was waiting."""
    from .orgsource import REDACT
    c = next_approval(conn)
    if not c:
        return False
    cid = int(c["CandidateId"])
    final_yaml = url = error = None
    cred = None
    try:
        repo = load_repository(conn)
        if not repo:
            raise ReviewError("no internal rules repository is set (Admin -> Rule review)")
        cfg = repository_config(repo)
        cred = creds.write_for(cfg.repo)
        if not cred:
            raise ReviewError(f"no write token is registered for {cfg.repo} under Source control")
        if cred.error or not cred.token:
            raise ReviewError(f"the write token for {cfg.repo}: {cred.error or 'it does not open'}")
        REDACT.add(cred.token, cred.username)
        kind = c["Kind"]
        entry = parse_entry(kind, c["ApproveYaml"] or c["RuleYaml"])
        problems = validate(kind, entry, None)
        if problems:
            raise ReviewError("; ".join(problems))
        who = c.get("ApproveByName") or c["ApproveBy"]
        final = reviewed_entry(kind, entry, cid, who, c.get("ApproveNote"))
        title, body = pr_text(c, final, who, c.get("ApproveNote"), cfg.path)
        work.mkdir(parents=True, exist_ok=True)
        url = open_pull_request(cfg, kind, final, cid, title, body, Path(tempfile.mkdtemp(prefix="cz-review-", dir=work)),
                                token=cred.token)
        final_yaml = to_yaml(final)
    except Exception as ex:                  # recorded on the candidate; it waits for the next decision
        error = REDACT(str(ex) if isinstance(ex, ReviewError) else f"{type(ex).__name__}: {ex}")
    if cred is not None:
        try:
            from .credentials import mark
            mark(conn, cred.id, f"ok: rule review pull request {url}" if url else f"failed: {error}"[:1000])
        except Exception:
            pass
    done = finish_approval(conn, cid, final_yaml, url, error)
    log(f"rule review: candidate {cid}: " + (f"approved, pull request {url}" if url else f"not approved: {error}")
        + ("" if done else " (the candidate changed meanwhile; nothing recorded)"))
    return True


def sync_reviewed(conn, creds, dest: Path, log=print) -> Path | None:
    """A fresh checkout of the internal rules repository's rules folder for the scans (None: not set up).
    On failure the previous checkout, if any, stays in use."""
    from .orgsource import REDACT, SourceError, clone, provider as make_provider
    repo = load_repository(conn)
    if not repo:
        return None
    cfg = repository_config(repo)
    cred = creds.write_for(cfg.repo)
    prev = dest / cfg.path
    if not cred or not cred.token:
        log(f"rule review: no usable write token for {cfg.repo}: the scans run without the approved rules")
        return prev if prev.is_dir() else None
    REDACT.add(cred.token, cred.username)
    tmp = dest.with_name(dest.name + ".new")
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        clone(cfg.repo, tmp, cfg.branch, make_provider(cfg.provider, "-", cred.token, None).git_header(), depth=1)
    except SourceError as ex:
        shutil.rmtree(tmp, ignore_errors=True)
        log(f"rule review: could not update the approved rules from {cfg.repo}: {REDACT(str(ex))[:300]}")
        return prev if prev.is_dir() else None
    shutil.rmtree(dest, ignore_errors=True)
    tmp.rename(dest)
    return prev if prev.is_dir() else None


def infer_provider(url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host == "github.com" or host.endswith(".github.com") or host.endswith(".ghe.com"):
        return "github"
    if host == "dev.azure.com" or host.endswith(".visualstudio.com") or "/_git/" in url:
        return "azure-devops"
    if host == "gitlab.com" or host.startswith("gitlab."):
        return "gitlab"
    return ""


def reviewed_entry(kind: str, entry, cid: int, user: str, note: str | None):
    """The rule as it goes into the ruleset: who approved it and from which candidate."""
    if not isinstance(entry, dict):
        return entry
    e = {k: v for k, v in entry.items() if k != "reviewed"}
    e["reviewed"] = {"candidate": cid, "by": user, "at": _now().date().isoformat()}
    return e


def append_rule(rules_dir: Path, kind: str, entry) -> Path:
    path = Path(rules_dir) / KINDS[kind][0]
    new = appended_text(kind, entry, path.read_text() if path.exists() else "")
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(new)
    tmp.replace(path)
    return path


def _http(method: str, url: str, headers: dict, body: dict | None = None, timeout: int = 60):
    from .orgsource import REDACT
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json", "User-Agent": "containerizer", **({"Content-Type": "application/json"} if data else {}),
        **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        detail = REDACT(e.read()[:400].decode(errors="replace")) if e.fp else ""
        return e.code, {"_error": f"HTTP {e.code} {e.reason} {detail}".strip()}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ReviewError(f"{method} {url}: {REDACT(str(e))}") from None


def _pr_api(cfg: ApplyConfig) -> tuple[str, dict]:
    """(API base for pull requests of the repository, provider-specific fields)."""
    u = urllib.parse.urlsplit(cfg.repo)
    path = re.sub(r"\.git$", "", u.path.strip("/"))
    if cfg.provider == "github":
        api = cfg.api_url or ("https://api.github.com" if u.hostname == "github.com" else f"https://{u.netloc}/api/v3")
        owner_repo = "/".join(path.split("/")[:2])
        return f"{api}/repos/{owner_repo}", {"owner": owner_repo.split("/")[0]}
    if cfg.provider == "gitlab":
        api = cfg.api_url or f"https://{u.netloc}"
        return f"{api}/api/v4/projects/{urllib.parse.quote(path, safe='')}", {}
    # azure-devops: <collection URL>/<project>/_git/<repo>
    if "/_git/" not in "/" + path + "/":
        raise ReviewError("CONTAINERIZER_RULES_REPO: an Azure DevOps URL looks like https://dev.azure.com/org/project/_git/repo")
    before, _, repo = path.partition("_git/")
    base = cfg.api_url or f"https://{u.netloc}"
    return f"{base}/{before.strip('/')}/_apis/git/repositories/{repo.split('/')[0]}", {}


def ensure_private(cfg: ApplyConfig, headers: dict) -> None:
    """Approved rules describe your applications: refuse a repository anyone can read."""
    api, _ = _pr_api(cfg)
    vis = None
    if cfg.provider == "github":
        st, d = _http("GET", api, headers)
        if st == 200 and isinstance(d, dict):
            vis = d.get("visibility") or ("private" if d.get("private") else "public")
    elif cfg.provider == "gitlab":
        st, d = _http("GET", api, headers)
        if st == 200 and isinstance(d, dict):
            vis = d.get("visibility")
    else:
        proj = api.split("/_apis/")[0]              # <collection URL>/<project>
        coll, _, name = proj.rpartition("/")
        st, d = _http("GET", f"{coll}/_apis/projects/{name}?api-version=7.1", headers)
        if st == 200 and isinstance(d, dict):
            vis = d.get("visibility")
    if vis is None:
        raise ReviewError(f"cannot read the visibility of {cfg.repo} with the token (HTTP {st}); approved rules only go "
                          "to a repository known to be private or internal")
    if str(vis).lower() not in ("private", "internal", "organization"):
        raise ReviewError(f"{cfg.repo} is {vis}: approved rules only go to a private or internal repository")


def open_pull_request(cfg: ApplyConfig, kind: str, entry, cid: int, title: str, body: str, work: Path,
                      token: str | None = None) -> str:
    """Clone the rules repository, append the rule on a branch of its own, push, open (or find) the PR.
    The token: `token` (the scan worker, from Source control), else the environment (cfg.token_env)."""
    from .orgsource import REDACT, SourceError, clone, git, provider as make_provider, read_token
    cfg.check()
    token = token or read_token("", cfg.token_env)
    if not token:
        raise ReviewError(f"no token for the rules repository: set {cfg.token_env}")
    prov = make_provider(cfg.provider, "-", token, None)
    REDACT.add(token, prov.git_username)
    header = prov.git_header()
    ensure_private(cfg, prov.headers())
    branch = f"containerizer/rule-review-{cid}"
    dest = work / f"rules-repo-{cid}"
    if dest.exists():
        shutil.rmtree(dest)
    try:
        clone(cfg.repo, dest, cfg.branch, header, depth=1)
        git(["checkout", "-q", "-B", branch], cwd=dest)
        rules_dir = dest / cfg.path
        rules_dir.mkdir(parents=True, exist_ok=True)       # the first approved rule creates the folder
        problems = validate(kind, entry, rules_dir)
        if problems:
            raise ReviewError("against the rules repository: " + "; ".join(problems))
        append_rule(rules_dir, kind, entry)
        git(["add", "--", f"{cfg.path}/{KINDS[kind][0]}"], cwd=dest)
        name = os.environ.get("GIT_AUTHOR_NAME") or "containerizer rule review"
        email = os.environ.get("GIT_AUTHOR_EMAIL") or "containerizer@localhost"
        git(["-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-q", "-m", title, "-m", body[:4000]], cwd=dest)
        git(["push", "-q", "--force", "origin", f"HEAD:refs/heads/{branch}"], cwd=dest, url=cfg.repo, header=header)
    except SourceError as e:
        raise ReviewError(str(e)) from None
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    api, extra = _pr_api(cfg)
    h = prov.headers()
    if cfg.provider == "github":
        st, d = _http("POST", f"{api}/pulls", h, {"title": title, "head": branch, "base": cfg.branch, "body": body})
        if st == 422:          # already open for this branch (a retried approval)
            st, d = _http("GET", f"{api}/pulls?state=open&head={urllib.parse.quote(extra['owner'] + ':' + branch)}", h)
            d = d[0] if isinstance(d, list) and d else d
        url = (d or {}).get("html_url") if isinstance(d, dict) else None
    elif cfg.provider == "gitlab":
        st, d = _http("POST", f"{api}/merge_requests", h, {"source_branch": branch, "target_branch": cfg.branch,
                                                            "title": title, "description": body,
                                                            "remove_source_branch": True})
        if st == 409:
            st, d = _http("GET", f"{api}/merge_requests?state=opened&source_branch={urllib.parse.quote(branch)}", h)
            d = d[0] if isinstance(d, list) and d else d
        url = (d or {}).get("web_url") if isinstance(d, dict) else None
    else:
        q = "api-version=7.1"
        st, d = _http("POST", f"{api}/pullrequests?{q}", h, {"sourceRefName": f"refs/heads/{branch}",
                                                              "targetRefName": f"refs/heads/{cfg.branch}",
                                                              "title": title, "description": body[:3900]})
        if st == 409:
            st, d = _http("GET", f"{api}/pullrequests?searchCriteria.status=active&searchCriteria.sourceRefName="
                          f"{urllib.parse.quote('refs/heads/' + branch, safe='')}&{q}", h)
            v = (d or {}).get("value") if isinstance(d, dict) else None
            d = v[0] if v else d
        url = None
        if isinstance(d, dict) and d.get("pullRequestId"):
            repo_web = cfg.repo.rstrip("/")
            url = f"{repo_web}/pullrequest/{d['pullRequestId']}"
    if not url:
        err = (d or {}).get("_error") if isinstance(d, dict) else None
        raise ReviewError(f"the branch {branch} was pushed, but the pull request could not be opened: {err or st}")
    return url


def pr_text(c: dict, entry, user: str, note: str | None, folder: str = "rules") -> tuple[str, str]:
    title = f"Rule review: add {c['Kind']} {rule_id(c['Kind'], entry)}"[:200]
    body = (f"Learned by containerizer and approved in the rule review by {user} (candidate {c['CandidateId']}).\n\n"
            f"- Learned from: {c.get('LearnedFrom') or '-'}\n- Seen {c.get('SeenCount') or 1} time(s); confidence "
            f"{c.get('Confidence')}\n" + (f"- Proposed by the LLM {c['Model']}\n" if c.get("Model") else "")
            + (f"- Reviewer's note: {note}\n" if note else "")
            + f"\nAdds to `{folder}/{c['TargetFile']}`:\n\n```yaml\n{to_yaml(entry)}```\n"
            "\nThe evidence (build and run logs) is on the Rule review admin page.\n")
    return title, body


def approve(store, cid: int, user: str, name: str | None = None, note: str | None = None, edited_yaml: str | None = None,
            cfg: ApplyConfig | None = None) -> dict:
    """Validate, apply (pull request or direct) and record the approval. Raises ReviewError with
    the reason when the rule is not accepted; the candidate then stays pending."""
    cfg = cfg or ApplyConfig.from_env()
    cfg.check()
    c = store.get(cid)
    if not c:
        raise ReviewError(f"no candidate {cid}")
    if c["Status"] != "pending":
        raise ReviewError(f"candidate {cid} is already {c['Status']}")
    kind = c["Kind"]
    text = edited_yaml if edited_yaml is not None and edited_yaml.strip() else c["RuleYaml"]
    entry = parse_entry(kind, text)
    problems = validate(kind, entry, cfg.rules_dir if cfg.mode == "direct" else None)
    if problems:
        raise ReviewError("; ".join(problems))
    edited = to_yaml(entry) != to_yaml(parse_entry(kind, c["RuleYaml"]))
    final = reviewed_entry(kind, entry, cid, name or user, note)
    if not store.claim(cid, user):
        raise ReviewError(f"candidate {cid} is being decided by someone else, or was already decided")
    try:
        if cfg.mode == "direct":
            path = append_rule(cfg.rules_dir, kind, final)
            from .confidence import reset_cache
            reset_cache()
            applied, url = "direct", None
            where = str(path)
        else:
            title, body = pr_text(c, final, name or user, note, cfg.path)
            work = Path(tempfile.mkdtemp(prefix="cz-review-"))
            try:
                url = open_pull_request(cfg, kind, final, cid, title, body, work)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            applied, where = "pr", url
    except Exception:
        store.release(cid)
        raise
    if not store.decide(cid, "approved", user, name, _cut(note, 1000), to_yaml(final), applied, url):
        raise ReviewError(f"candidate {cid} was applied ({where}) but could not be marked approved; check it")
    return {"candidate": cid, "applied": applied, "where": where, "edited": edited}


def reject(store, cid: int, user: str, name: str | None = None, note: str | None = None) -> None:
    c = store.get(cid)
    if not c:
        raise ReviewError(f"no candidate {cid}")
    if not store.decide(cid, "rejected", user, name, _cut(note, 1000)):
        raise ReviewError(f"candidate {cid} is already {c['Status']}")
