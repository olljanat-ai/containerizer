"""Real-world regression check: assess pinned public repositories (bench/realworld.yaml)
and compare the rating and component roles with hand-judged expectations.

    python -m containerizer.realworld [--root ../validation] [--clone] [name ...]

Repositories are cloned shallow at the pinned commit with --clone; nothing from
them is built or executed.
"""
from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
import time
from pathlib import Path

import yaml

from .assess import assess, classify_role
from .rules import load_rules
from .scan import scan

MANIFEST = Path(__file__).resolve().parent.parent / "bench" / "realworld.yaml"


def _clone(entry: dict, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(["git", "-C", str(dest), *a], check=True, capture_output=True)
    run("init", "-q")
    run("remote", "add", "origin", entry["url"])
    run("fetch", "-q", "--depth", "1", "origin", entry["commit"])
    run("checkout", "-q", "FETCH_HEAD")


def _role_misses(a, repo, rules, expected: dict) -> list[str]:
    # assess() drops tests, tools and libraries from components, so classify every project
    by_name = {}
    for c in a.components:
        for n in (c.name, c.project.name):
            by_name.setdefault(n, c.role)
    for p in repo.projects:
        role = classify_role(repo, p, rules)[0]
        for n in (p.name, p.path.stem, p.assembly_name, p.rel_dir):
            if n:
                by_name.setdefault(n, role)
    misses = []
    for role, names in (expected or {}).items():
        for pat in names:
            hits = [n for n in by_name if fnmatch.fnmatch(n, pat)]
            if not hits:
                misses.append(f"{pat}: not found")
            misses += [f"{n}: {by_name[n]} != {role}" for n in dict.fromkeys(hits) if by_name[n] != role]
    return misses


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="containerizer.realworld")
    ap.add_argument("names", nargs="*")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent.parent / "validation"))
    ap.add_argument("--clone", action="store_true", help="clone missing repositories at the pinned commit")
    args = ap.parse_args(argv)
    repos = yaml.safe_load(MANIFEST.read_text())["repos"]
    if args.names:
        repos = [r for r in repos if r["name"] in args.names]
    rules = load_rules()
    root = Path(args.root)
    ok = total = 0
    for r in repos:
        path = root / r["name"]
        if not path.exists():
            if not args.clone:
                print(f"{r['name']:<45} SKIP (not cloned; use --clone)")
                continue
            _clone(r, path)
        t0 = time.time()
        repo = scan(path)
        a = assess(path, rules, repo=repo)
        misses = _role_misses(a, repo, rules, r.get("expected_roles"))
        good = a.rating == r["expected_rating"] and not misses
        total += 1
        ok += good
        print(f"{r['name']:<45} {a.rating} (expected {r['expected_rating']}) "
              f"{'OK' if good else 'FAIL'} {time.time() - t0:.0f}s")
        for m in misses:
            print(f"    role {m}")
        if a.rating != r["expected_rating"]:
            for b in a.top_blockers(5):
                print(f"    {b['severity']:<8} {b['id']}: {', '.join(b['components'][:4])}")
    print(f"\n{ok}/{total} repositories match")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
