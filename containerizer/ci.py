"""CI gate: compare an assessment with a baseline (a git ref or a saved snapshot), write a PR comment,
SARIF and annotations, and fail when a change makes an application harder to containerize."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .assess import APP_RATINGS, VERDICT_TEXT, AppAssessment, assess
from .rules import SEV_RANK, load_rules
from .report import refs_md, refs_of

MARKER = "<!-- containerizer-check -->"
SNAPSHOT_VERSION = 1
SARIF_LEVEL = {"blocker": "error", "rewrite": "error", "refactor": "warning", "config": "note", "info": "note"}
RATING_ICON = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "E": "🔴"}


# ---------------------------------------------------------------------------
# snapshots: the part of an assessment the gate compares

def _git(cwd: Path, *args: str, binary: bool = False):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)
    return r.stdout if binary else r.stdout.decode().strip()


def git_root(path: Path) -> Path | None:
    try:
        return Path(_git(path if path.is_dir() else path.parent, "rev-parse", "--show-toplevel"))
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def snapshot_app(a: AppAssessment, prefix: str = "") -> dict:
    """Effective (reachability-aware) findings of every deployable component, keyed by component and rule."""
    findings = []
    for c in a.components:
        for f in c.findings:
            if f.severity == "info":
                continue
            findings.append(_item(c.name, f, prefix, verdict=c.verdict))
    for f in a.repo_findings:
        if f.severity != "info":
            findings.append(_item("(repository)", f, prefix))
    return {"name": a.name, "path": prefix, "rating": a.rating, "rating_text": APP_RATINGS[a.rating],
            "score": a.score, "effort_days": a.effort, "confidence": a.confidence, "summary": a.summary(),
            "components": {c.name: {"verdict": c.verdict, "role": c.role, "tier": c.tier} for c in a.components},
            "findings": findings}


def _item(component: str, f, prefix: str, verdict: str = "") -> dict:
    r = f.rule
    loc = [{"file": _join(prefix, e.file), "line": e.line, "snippet": (e.snippet or "")[:200]} for e in f.evidence[:3]]
    return {"key": f"{component}::{r.id}", "component": component, "rule": r.id, "severity": f.severity,
            "category": r.category, "title": r.title, "why": " ".join(r.why.split()), "fix": " ".join(r.fix.split()),
            "refs": list(getattr(r, "refs", None) or []),
            "via": f.via, "only_commands": list(f.modes), "windows_container": r.windows_container,
            "effort_days": r.effort, "evidence": loc}


def _join(prefix: str, rel: str) -> str:
    return f"{prefix.rstrip('/')}/{rel}" if prefix and prefix != "." else rel


def snapshot(paths: list[Path], rules=None, root: Path | None = None) -> dict:
    """Assess each app; file paths in the snapshot are relative to `root` (the git checkout) when given."""
    rules = rules if rules is not None else load_rules()
    apps = []
    for p in paths:
        a = assess(p, rules)
        prefix = os.path.relpath(p.resolve(), root.resolve()) if root else ""
        apps.append(snapshot_app(a, "" if prefix == "." else prefix))
    return {"version": SNAPSHOT_VERSION, "apps": apps}


def snapshot_at_ref(paths: list[Path], ref: str, rules=None) -> dict:
    """Assess the same app folders as they were at a git ref, without touching the working tree."""
    root = git_root(paths[0])
    if root is None:
        raise SystemExit(f"--base-ref needs a git checkout: {paths[0]} is not in one")
    try:
        _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except subprocess.CalledProcessError:
        raise SystemExit(f"base ref {ref!r} not found; fetch it first (actions/checkout with fetch-depth: 0)")
    rels = [os.path.relpath(p.resolve(), root.resolve()) for p in paths]
    with tempfile.TemporaryDirectory(prefix="containerizer-base-") as tmp:
        tmp_root = Path(tmp)
        present = []
        for rel in rels:
            spec = [] if rel == "." else ["--", rel]
            try:
                data = _git(root, "archive", "--format=tar", ref, *spec, binary=True)
            except subprocess.CalledProcessError:
                continue            # folder did not exist at the base ref: everything is new
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                t.extractall(tmp_root, filter="data")
            present.append(tmp_root / rel)
        snap = snapshot(present, rules, tmp_root) if present else {"version": SNAPSHOT_VERSION, "apps": []}
    snap["ref"] = ref
    return snap


# ---------------------------------------------------------------------------
# diff and gate

def diff(head: dict, base: dict | None, fail_on: str = "rewrite", fail_on_rating_drop: bool = True,
         max_rating: str | None = None) -> dict:
    """Per app: new / resolved / worsened findings and whether the gate fails."""
    threshold = None if fail_on == "none" else SEV_RANK[fail_on]
    base_apps = {a["path"] or a["name"]: a for a in (base or {}).get("apps", [])}
    out = []
    for h in head["apps"]:
        b = base_apps.get(h["path"] or h["name"]) if base is not None else None
        hf = {f["key"]: f for f in h["findings"]}
        bf = {f["key"]: f for f in b["findings"]} if b else {}
        new, worse = [], []
        if base is not None:
            for k, f in hf.items():
                if k not in bf:
                    new.append(f)
                elif SEV_RANK[f["severity"]] > SEV_RANK[bf[k]["severity"]]:
                    worse.append({**f, "was": bf[k]["severity"]})
        resolved = [f for k, f in bf.items() if k not in hf]
        reasons = []
        if threshold is not None:
            for f in new + worse:
                if SEV_RANK[f["severity"]] >= threshold:
                    reasons.append(f"{'new' if 'was' not in f else 'worse'} {f['severity']}: {f['title']} in {f['component']}")
        if fail_on_rating_drop and b and h["rating"] > b["rating"]:
            reasons.append(f"rating dropped from {b['rating']} to {h['rating']}")
        if max_rating and h["rating"] > max_rating:
            reasons.append(f"rating {h['rating']} is worse than the allowed {max_rating}")
        out.append({"app": h, "base": b, "new": new, "worse": worse, "resolved": resolved,
                    "failed": bool(reasons), "reasons": reasons, "is_new_app": base is not None and b is None})
    return {"apps": out, "failed": any(a["failed"] for a in out), "fail_on": fail_on,
            "base_ref": (base or {}).get("ref"), "has_base": base is not None}


# ---------------------------------------------------------------------------
# outputs

def _loc(f: dict, link: str | None = None) -> str:
    if not f["evidence"]:
        return ""
    e = f["evidence"][0]
    text = f"{e['file']}:{e['line']}" if e["line"] else e["file"]
    if link:
        anchor = f"#L{e['line']}" if e["line"] else ""
        return f"[`{text}`]({link}/{e['file']}{anchor})"
    return f"`{text}`"


def _row(f: dict, link: str | None) -> str:
    sev = f["severity"] if "was" not in f else f"{f['was']} → {f['severity']}"
    note = f" (via {f['via']})" if f["via"] else ""
    why = f"<br>{f['why']}" if f.get("why") else ""
    refs = f"<br>Learn more: {refs_md(refs_of(f))}" if refs_of(f) else ""
    return f"| {sev} | {f['component']} | **{f['title']}**{note}{why}<br>**Fix:** {f['fix']}{refs} | {_loc(f, link)} |"


def markdown(d: dict, link: str | None = None) -> str:
    """PR comment / job summary. `link` is a URL prefix for files, e.g. https://github.com/o/r/blob/<sha>."""
    L = [MARKER, "## Containerization check", ""]
    if d["failed"]:
        L += ["❌ **This change makes the application harder to containerize.**", ""]
    elif d["has_base"]:
        L += ["✅ No new Windows-only dependencies or blockers.", ""]
    for a in d["apps"]:
        h, b = a["app"], a["base"]
        rating = f"{RATING_ICON[h['rating']]} **{h['rating']}** {h['rating_text']}"
        if b and b["rating"] != h["rating"]:
            rating += f" (was **{b['rating']}**)"
        title = h["path"] or h["name"]
        L += [f"### {title}: {rating}", "",
              f"Score {h['score']}/100{_delta(h, b, 'score')} · effort {h['effort_days']} d{_delta(h, b, 'effort_days')}"
              f" · confidence {h['confidence']}", "", h["summary"], ""]
        if a["reasons"]:
            L += ["**Gate failed:**", ""] + [f"- {r}" for r in a["reasons"]] + [""]
        if a["is_new_app"]:
            L += ["_New application: no baseline to compare with._", ""]
        changed = a["worse"] + a["new"]
        if changed:
            L += ["#### New in this change", "", "| Severity | Component | Finding | Where |", "| --- | --- | --- | --- |"]
            L += [_row(f, link) for f in sorted(changed, key=lambda f: -SEV_RANK[f["severity"]])] + [""]
        if a["resolved"]:
            L += ["#### Resolved", ""] + [f"- ~~{f['title']}~~ in {f['component']}" for f in a["resolved"]] + [""]
        blockers = [f for f in h["findings"] if f["severity"] in ("blocker", "rewrite")]
        if blockers:
            L += ["<details><summary>All blockers and rewrites "
                  f"({len(blockers)})</summary>", "", "| Severity | Component | Finding | Where |", "| --- | --- | --- | --- |"]
            L += [_row(f, link) for f in sorted(blockers, key=lambda f: (-SEV_RANK[f["severity"]], f["component"]))]
            L += ["", "</details>", ""]
        comps = h["components"]
        if comps:
            L += ["<details><summary>Components</summary>", "", "| Component | Role | Verdict |", "| --- | --- | --- |"]
            for name, c in comps.items():
                was = b["components"].get(name, {}).get("verdict") if b else None
                v = VERDICT_TEXT[c["verdict"]] + (f" (was: {VERDICT_TEXT[was].lower()})" if was and was != c["verdict"] else "")
                L.append(f"| {name} | {c['role']} | {v} |")
            L += ["", "</details>", ""]
    base = f" against `{d['base_ref']}`" if d["base_ref"] else ""
    L.append(f"<sub>Gate: fail on new findings of severity `{d['fail_on']}` or worse{base}. "
             "Generated by [containerizer](https://github.com/olljanat-ai/containerizer).</sub>")
    return "\n".join(L) + "\n"


def _delta(h: dict, b: dict | None, key: str) -> str:
    if not b or b[key] == h[key]:
        return ""
    dv = round(h[key] - b[key], 1)
    return f" ({'+' if dv > 0 else ''}{dv})"


def sarif(d: dict) -> dict:
    """SARIF 2.1.0 for code scanning. New findings are marked with baselineState so reviewers see them first."""
    rules: dict[str, dict] = {}
    results = []
    for a in d["apps"]:
        new = {f["key"] for f in a["new"]} | {f["key"] for f in a["worse"]}
        for f in a["app"]["findings"]:
            rules.setdefault(f["rule"], {
                "id": f["rule"], "name": f["rule"], "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["why"] or f["title"]},
                "help": {"text": f"{f['why']}\nFix: {f['fix']}".strip() + "".join(f"\n{u}" for u in refs_of(f)),
                         "markdown": f"{f['why']}\n\n**Fix:** {f['fix']}"
                         + (f"\n\nLearn more: {refs_md(refs_of(f))}" if refs_of(f) else "")},
                **({"helpUri": refs_of(f)[0]} if refs_of(f) else {}),
                "defaultConfiguration": {"level": SARIF_LEVEL[f["severity"]]},
                "properties": {"tags": ["containerization", f["category"] or "general"]}})
            locs = [{"physicalLocation": {"artifactLocation": {"uri": e["file"]},
                                          **({"region": {"startLine": e["line"]}} if e["line"] else {})}}
                    for e in f["evidence"]]
            res = {"ruleId": f["rule"], "level": SARIF_LEVEL[f["severity"]],
                   "message": {"text": f"{f['title']} ({f['severity']}) in {f['component']}: {f['fix']}"},
                   "locations": locs or [{"physicalLocation": {"artifactLocation": {"uri": a["app"]["path"] or "."}}}],
                   "partialFingerprints": {"containerizer/v1": f"{a['app']['name']}::{f['key']}"},
                   "properties": {"component": f["component"], "severity": f["severity"], "app": a["app"]["name"]}}
            if d["has_base"]:
                res["baselineState"] = "new" if f["key"] in new else "unchanged"
            results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "containerizer", "informationUri":
                                          "https://github.com/olljanat-ai/containerizer", "rules": list(rules.values())}},
                      "results": results}]}


def annotations(d: dict, style: str) -> list[str]:
    """Inline annotations for the findings that failed the gate (and warnings for the other new ones)."""
    out = []
    threshold = None if d["fail_on"] == "none" else SEV_RANK[d["fail_on"]]
    for a in d["apps"]:
        for f in a["worse"] + a["new"]:
            err = threshold is not None and SEV_RANK[f["severity"]] >= threshold
            msg = f"{f['title']} ({f['severity']}) in {f['component']}: {f['fix']}".replace("\n", " ")
            e = f["evidence"][0] if f["evidence"] else {"file": a["app"]["path"], "line": 0}
            if style == "github":
                loc = f"file={e['file']}" + (f",line={e['line']}" if e["line"] else "")
                out.append(f"::{'error' if err else 'warning'} {loc},title=containerizer::{msg}")
            elif style == "azure":
                loc = f"sourcepath={e['file']}" + (f";linenumber={e['line']}" if e["line"] else "")
                out.append(f"##vso[task.logissue type={'error' if err else 'warning'};{loc}]{msg}")
    return out


def run_check(args) -> int:
    from .cli import _apps

    paths = [p.resolve() for p in _apps(args.paths)]
    root = git_root(paths[0])
    rules = load_rules()
    head = snapshot(paths, rules, root)
    base = None
    if args.baseline:
        base = json.loads(Path(args.baseline).read_text())
        base = base.get("snapshot", base)
    elif args.base_ref:
        base = snapshot_at_ref(paths, args.base_ref, rules)
    d = diff(head, base, fail_on=args.fail_on, fail_on_rating_drop=not args.allow_rating_drop,
             max_rating=args.max_rating)
    md = markdown(d, args.link)
    if args.markdown:
        Path(args.markdown).write_text(md)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(sarif(d), indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps({"snapshot": head, "diff": d}, indent=2, default=str))
    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(head, indent=2, default=str))
    if args.annotations != "none":
        for line in annotations(d, args.annotations):
            print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY") if args.annotations == "github" else None
    if summary:
        with open(summary, "a") as fh:
            fh.write(md.replace(MARKER + "\n", ""))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as fh:
            worst = max((a["app"]["rating"] for a in d["apps"]), default="")
            fh.write(f"rating={worst}\nfailed={'true' if d['failed'] else 'false'}\n"
                     f"new-findings={sum(len(a['new']) + len(a['worse']) for a in d['apps'])}\n")
    for a in d["apps"]:
        h = a["app"]
        status = "FAIL" if a["failed"] else "ok"
        print(f"{status:4s} {h['path'] or h['name']}: rating {h['rating']}"
              f"{' (was ' + a['base']['rating'] + ')' if a['base'] and a['base']['rating'] != h['rating'] else ''}"
              f", {len(a['new']) + len(a['worse'])} new, {len(a['resolved'])} resolved")
        for r in a["reasons"]:
            print(f"     - {r}")
    return 1 if d["failed"] else 0


# ---------------------------------------------------------------------------
# one-shot assessment summary (assess + generate + verify in a pipeline)

VERIFY_TEXT = {"ok": "✅ builds and serves requests", "ok-external": "✅ builds and starts; needs its external services",
               "finding": "⚠️ runs only in smoke mode; runtime finding", "build-failed": "❌ build failed",
               "run-failed": "❌ container failed at run time", "skipped": "· not built"}
READY = ("info", "config")


def verify_markdown(results: list[dict]) -> str:
    """Table of build-and-run results, flagging every place where the run contradicts the static verdict."""
    if not results:
        return ""
    L = ["## Build and run verification", "",
         "| App | Component | Predicted | Result | Notes |", "| --- | --- | --- | --- | --- |"]
    mismatches = 0
    for r in results:
        st = r.get("status", "")
        pred = r.get("predicted", "")
        note = ""
        if st != "skipped" and pred in READY and not st.startswith("ok"):
            note, mismatches = "**static verdict not confirmed**", mismatches + 1
        elif st.startswith("ok") and pred not in READY:
            note = "runs, but the static findings still apply"
        detail = (r.get("detail") or "").replace("|", "\\|")
        if detail and st != "skipped":
            note = (note + "; " if note else "") + f"attempts: {detail}"
        L.append(f"| {r.get('app', '')} | {r.get('component', '')} | {VERDICT_TEXT.get(pred, pred)} | "
                 f"{VERIFY_TEXT.get(st, st)} | {note} |")
    L.append("")
    if mismatches:
        L += [f"⚠️ {mismatches} component(s) predicted ready did not run. Treat their rating as unconfirmed "
              "and check the build log in the report artifact.", ""]
    return "\n".join(L)


def verification_results(report_dir: Path) -> list[dict]:
    """Build-and-run results of an `analyze` run (in assessment.json), or of `verify --out` files."""
    aj = report_dir / "assessment.json"
    if aj.exists():
        results = [{"app": a["name"], **r} for a in json.loads(aj.read_text()) for r in a.get("verification") or []]
        if results:
            return results
    results = []
    for f in sorted(report_dir.rglob("*.verify.json")):
        results += json.loads(f.read_text())
    return results


def unconfirmed(results: list[dict]) -> int:
    """Components rated ready whose generated container did not build or run."""
    return sum(1 for r in results if r.get("status") != "skipped" and r.get("predicted") in READY
               and not str(r.get("status", "")).startswith("ok"))


def assessment_summary(report_dir: Path) -> str:
    """Job summary for a one-shot run: portfolio, per-app details folded, and verification results."""
    L = []
    pf = report_dir / "portfolio.md"
    if pf.exists():
        L.append(pf.read_text())
    results = verification_results(report_dir)
    if results:
        L.append(verify_markdown(results))
    for f in sorted(report_dir.glob("*.md")):
        if f.name == "portfolio.md":
            continue
        L += [f"<details><summary>{f.stem}</summary>", "", f.read_text(), "", "</details>", ""]
    text = "\n".join(L)
    limit = 900_000           # GitHub job summaries are capped at 1 MiB
    if len(text.encode()) > limit:
        text = text.encode()[:limit].decode(errors="ignore") + "\n\n_Truncated: see the report artifact._\n"
    return text


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "summary":
        print(assessment_summary(Path(sys.argv[2])))
    elif len(sys.argv) == 3 and sys.argv[1] == "unconfirmed":
        print(unconfirmed(verification_results(Path(sys.argv[2]))))
    else:
        sys.exit("usage: python -m containerizer.ci summary|unconfirmed <report-dir>")
