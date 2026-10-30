"""Benchmark: compare assessments with hand-made labels (bench/labels.yaml)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import yaml

from .assess import assess
from .rules import load_rules


def _names(c) -> set[str]:
    return {c.name, c.project.name, c.project.path.stem}


def run_bench(args) -> int:
    labels = yaml.safe_load(Path(args.labels).read_text())["apps"]
    root = Path(args.challenge) / "scenarios"
    rules = load_rules()
    t0 = time.time()
    rows, tp, fp, fn, ok_correct, ok_total = [], 0, 0, 0, 0, 0
    rating_hits = hard_hits = 0
    for app, lab in sorted(labels.items()):
        a = assess(root / app, rules)
        comps = a.components
        blocked_pred = {n for c in comps if c.verdict == "blocker" for n in _names(c)}
        exp_b = set(lab.get("blocked", []))
        exp_ok = set(lab.get("not_blocked", []))
        b_tp = len(exp_b & blocked_pred)
        b_fn = len(exp_b - blocked_pred)
        b_fp = len(exp_ok & blocked_pred)
        tp, fn, fp = tp + b_tp, fn + b_fn, fp + b_fp
        ok_total += len(exp_ok)
        ok_correct += len(exp_ok - blocked_pred)
        r_ok = a.rating in lab["rating"]
        hard_exp = any(r in "DE" for r in lab["rating"])
        hard_ok = (a.rating in "DE") == hard_exp
        rating_hits += r_ok
        hard_hits += hard_ok
        rows.append({"app": app, "rating": a.rating, "expected": "/".join(lab["rating"]), "rating_ok": r_ok,
                     "hard_ok": hard_ok, "missed_blockers": sorted(exp_b - blocked_pred),
                     "false_blockers": sorted(exp_ok & blocked_pred), "confidence": a.confidence})
    n = len(rows)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    summary = {"apps": n, "rating_accuracy": round(rating_hits / n, 3), "hard_vs_easy_accuracy": round(hard_hits / n, 3),
               "blocker_precision": round(prec, 3), "blocker_recall": round(rec, 3),
               "feasible_component_accuracy": round(ok_correct / ok_total, 3) if ok_total else 1.0,
               "seconds": round(time.time() - t0, 1)}
    for r in rows:
        if args.verbose or not r["rating_ok"] or r["missed_blockers"] or r["false_blockers"]:
            flag = "OK " if r["rating_ok"] else "BAD"
            extra = ""
            if r["missed_blockers"]:
                extra += f" missed={r['missed_blockers']}"
            if r["false_blockers"]:
                extra += f" false={r['false_blockers']}"
            print(f"{flag} {r['app']:22s} got {r['rating']} want {r['expected']:4s}{extra}")
    print(json.dumps(summary, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "apps": rows}, indent=2))
    return 0
