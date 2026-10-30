"""Command line interface: `python -m containerizer <command> ...`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .assess import assess
from .rules import load_rules


def _apps(paths: list[str]) -> list[Path]:
    """A path is an app, or a folder of apps when it has no project files of its own at top level."""
    out = []
    for p in map(Path, paths):
        if (p / "scenarios").is_dir():
            out += sorted(d for d in (p / "scenarios").iterdir() if d.is_dir())
        else:
            out.append(p)
    return out


def cmd_assess(args) -> int:
    from .report import write_reports

    rules = load_rules()
    results = []
    for app in _apps(args.paths):
        a = assess(app, rules)
        if args.ai:
            from .assess import apply_ai
            apply_ai(a, args.model)
        results.append(a)
        if not args.quiet:
            print(f"{a.name:24s} {a.rating} score={a.score:3d} effort={a.effort:5.1f}d conf={a.confidence:.2f}  {a.summary()}")
            if args.verbose:
                for c in a.components:
                    print(f"    {c.verdict:8s} {c.role:8s} {c.name:45s} {','.join(c.project.tfms)}")
                    for f in c.findings:
                        if f.severity != "info" or args.verbose > 1:
                            via = (f" (via {f.via})" if f.via else "") + (f" (only {', '.join(f.modes)})" if f.modes else "")
                            print(f"        - [{f.severity}] {f.rule.title}{via}")
    if args.out:
        write_reports(results, Path(args.out), fmt=args.format)
        print(f"reports written to {args.out}")
    if args.json:
        print(json.dumps([a.to_dict() for a in results], indent=2, default=str))
    return 0


def cmd_generate(args) -> int:
    from .generate import generate_app

    rules = load_rules()
    for app in _apps(args.paths):
        a = assess(app, rules)
        out = Path(args.out) / a.name if args.out else Path(app) / "containerize"
        files = generate_app(a, out, registry=args.registry, pin=args.pin_digests)
        print(f"{a.name}: {len(files)} files -> {out}")
    return 0


def cmd_verify(args) -> int:
    from .verify import verify_app

    rules = load_rules()
    rc = 0
    for app in _apps(args.paths):
        a = assess(app, rules)
        res = verify_app(a, Path(args.out) if args.out else None, learn=args.learn, only=args.component,
                         ai=args.ai, model=args.model, timeout=args.timeout)
        for r in res:
            print(f"{a.name}/{r['component']}: {r['status']} {r.get('detail', '')}")
            if r["status"] not in ("ok", "skipped"):
                rc = 1
    return rc


def cmd_bench(args) -> int:
    from .bench import run_bench

    return run_bench(args)


def cmd_ai(args) -> int:
    from .ai import ai_review_app

    rules = load_rules()
    for app in _apps(args.paths):
        a = assess(app, rules)
        res = ai_review_app(a, model=args.model, learn=args.learn, force=args.force)
        print(json.dumps(res, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="containerizer", description="Rule-based containerization assessment and generator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("assess", help="assess one or more applications")
    s.add_argument("paths", nargs="+")
    s.add_argument("-v", "--verbose", action="count", default=0)
    s.add_argument("-q", "--quiet", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("--out", help="write reports to this folder")
    s.add_argument("--format", default="md,html,json")
    s.add_argument("--ai", action="store_true", help="ask Claude about low-confidence components")
    s.add_argument("--model", default=None)
    s.set_defaults(fn=cmd_assess)

    s = sub.add_parser("generate", help="generate Dockerfiles and Kubernetes manifests")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out")
    s.add_argument("--registry", default="registry.local", help="image registry used in the manifests")
    s.add_argument("--pin-digests", action="store_true", help="pin base images to their current digests")
    s.set_defaults(fn=cmd_generate)

    s = sub.add_parser("verify", help="build and run generated containers; learn from failures")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out")
    s.add_argument("--component")
    s.add_argument("--learn", action="store_true", help="persist learned rules")
    s.add_argument("--ai", action="store_true", help="ask Claude when no failure rule explains a failure")
    s.add_argument("--model", default=None)
    s.add_argument("--timeout", type=int, default=900)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("ai", help="ask Claude to review uncertain parts of an assessment")
    s.add_argument("paths", nargs="+")
    s.add_argument("--model", default=None)
    s.add_argument("--learn", action="store_true")
    s.add_argument("--force", action="store_true", help="review even when confidence is high")
    s.set_defaults(fn=cmd_ai)

    s = sub.add_parser("bench", help="score assessments against labelled expectations")
    s.add_argument("--challenge", default="../containerization-challenge")
    s.add_argument("--labels", default=str(Path(__file__).resolve().parent.parent / "bench" / "labels.yaml"))
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--json")
    s.add_argument("--technique", default="rules", choices=["rules", "hybrid", "ai-only", "ai+rules"])
    s.add_argument("--model", default=None)
    s.set_defaults(fn=cmd_bench)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
