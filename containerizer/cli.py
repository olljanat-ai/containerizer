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
    apps = _apps(args.paths)
    for app in apps:
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
    return _store(args, results, apps)


def _store(args, results, apps) -> int:
    """Write results to SQL Server when --sql or CONTAINERIZER_SQL is set."""
    import os
    if not (args.sql or os.environ.get("CONTAINERIZER_SQL")):
        return 0
    from .sqlstore import SqlError, store_results
    try:
        ids = store_results(args.sql, results, apps)
    except SqlError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    print(f"{len(ids)} assessment(s) written to SQL Server")
    return 0


def cmd_db(args) -> int:
    import os
    from .sqlstore import SqlError, connect, create_database, create_login, import_json, init_schema
    try:
        if args.db_cmd == "init":
            if args.create_database:
                create_database(args.sql)
            conn = connect(args.sql)
            try:
                init_schema(conn)
                for spec in args.login or []:
                    login, _, role = spec.partition(":")
                    env = f"CZ_{login.upper()}_PASSWORD"
                    if not os.environ.get(env):
                        raise SqlError(f"--login {spec}: set the password in {env}")
                    create_login(conn, login, os.environ[env], role or "reader")
            finally:
                conn.close()
            print("schema is up to date")
        elif args.db_cmd == "import":
            ids = import_json(args.sql, [Path(f) for f in args.files], key_prefix=args.key_prefix)
            print(f"{len(ids)} assessment(s) imported")
    except SqlError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    return 0


def cmd_web(args) -> int:
    from .webui import serve
    return serve(args.sql, args.host, args.port)


def _gitops(args):
    from .gitops import GitOpsOptions
    return GitOpsOptions(git_url=args.git_url, branch=args.git_branch, path=args.git_path or "",
                         verify_commits=args.verify_commits)


def _gitops_args(s) -> None:
    g = s.add_argument_group("GitOps (Argo CD and Flux examples under <app>/gitops)")
    g.add_argument("--git-url", default="https://git.example.com/platform/deployments.git",
                   help="repository the generated app folder is committed to")
    g.add_argument("--git-branch", default="main")
    g.add_argument("--git-path", help="folder of the app in that repository (default deploy/<app>)")
    g.add_argument("--verify-commits", action="store_true", help="Flux: only apply signed commits")


def cmd_generate(args) -> int:
    from .generate import generate_app

    rules = load_rules()
    for app in _apps(args.paths):
        a = assess(app, rules)
        out = Path(args.out) / a.name if args.out else Path(app) / "containerize"
        files = generate_app(a, out, registry=args.registry, pin=args.pin_digests, gitops=_gitops(args))
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


def cmd_gate(args) -> int:
    from .imagescan import gate_app

    rules = load_rules()
    from .harden import security
    scanner = args.scanner or security()["scan"].get("default_scanner", "auto")
    rc = 0
    base_cache: dict = {}
    for app in _apps(args.paths):
        a = assess(app, rules)
        out = Path(args.out) / a.name if args.out else Path(app) / "containerize"
        r = gate_app(a, out, build=not args.no_build, scan=not args.no_scan, scanner=scanner, fail_on=args.fail_on,
                     registry=args.registry, pin=args.pin_digests, base_cache=base_cache,
                     run=not args.no_build and not args.no_run, refresh=not args.no_refresh)
        blocking = sum(len(s["blocking"]) for c in r["components"] for s in c["scans"])
        print(f"{a.name:24s} {'PASS' if r['passed'] else 'FAIL'}  lint errors={r['lint'].get('error', 0)} "
              f"warnings={r['lint'].get('warning', 0)}  blocking vulns={blocking}  -> {out / 'SECURITY.md'}")
        if not r["passed"]:
            rc = 1
    return rc


def cmd_images(args) -> int:
    from .harden import lifecycle
    from .imagescan import image_refs, update_images

    if args.update:
        update_images(scan=not args.no_scan, scanner=args.scanner)
        return 0
    from .generate import images_lock
    lock = images_lock()
    for slot, ref in image_refs():
        cur = lock.get(ref, {}).get("tag", ref)
        lc = lifecycle(cur)
        eol = "" if not lc else (f"  EOL {lc['eol']}" + (" (passed)" if lc["days_left"] < 0 else f" ({lc['days_left']} days)"))
        print(f"{slot:22s} {cur}{eol}")
    return 0


def cmd_check(args) -> int:
    from .ci import run_check

    return run_check(args)


def cmd_analyze(args) -> int:
    from .analyze import analyze_app
    from .report import write_reports

    out = Path(args.out)
    results = []
    apps = _apps(args.paths)
    for app in apps:
        a = analyze_app(app, out, ai=args.ai, model=args.model, verify=not args.no_verify,
                        registry=args.registry, pin=args.pin_digests, timeout=args.timeout, gitops=_gitops(args))
        ver = a.verification
        results.append(a)
        print(f"{a.name:24s} {a.rating} score={a.score:3d}  verified: "
              f"{sum(r['status'] in ('ok', 'ok-external') for r in ver)} run, "
              f"{sum(r['status'] == 'finding' for r in ver)} runtime findings, "
              f"{sum(r['status'] in ('build-failed', 'run-failed') for r in ver)} failed")
    write_reports(results, out)
    print(f"reports written to {out}")
    return _store(args, results, apps)


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


def _run_cmd(args) -> int:
    from .verify import DockerUnavailable
    try:
        return args.fn(args)
    except DockerUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


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
    s.add_argument("--sql", help="also write the results to SQL Server: an ADO.NET-style connection string "
                   "(default CONTAINERIZER_SQL; password in CONTAINERIZER_SQL_PASSWORD)")
    s.set_defaults(fn=cmd_assess)

    s = sub.add_parser("generate", help="generate Dockerfiles and Kubernetes manifests")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out")
    s.add_argument("--registry", default="registry.local", help="image registry used in the manifests")
    s.add_argument("--pin-digests", action="store_true", help="pin base images to their current digests")
    _gitops_args(s)
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

    s = sub.add_parser("analyze", help="one-shot: assess, build+run every feasible component, learn, report, generate")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out", default="containerizer-out")
    s.add_argument("--ai", action="store_true", help="ask Claude about uncertain components and unexplained failures")
    s.add_argument("--model", default=None)
    s.add_argument("--no-verify", action="store_true", help="skip building and running (static analysis only)")
    s.add_argument("--registry", default="registry.local")
    s.add_argument("--pin-digests", action="store_true")
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--sql", help="also write the results to SQL Server: an ADO.NET-style connection string "
                   "(default CONTAINERIZER_SQL; password in CONTAINERIZER_SQL_PASSWORD)")
    _gitops_args(s)
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("db", help="results database on SQL Server: create or upgrade the schema, import reports")
    dsub = s.add_subparsers(dest="db_cmd", required=True)
    d = dsub.add_parser("init", help="create or upgrade the results schema, its roles and audit triggers (needs db_owner)")
    d.add_argument("--sql", help="connection string (default CONTAINERIZER_SQL)")
    d.add_argument("--create-database", action="store_true", help="CREATE DATABASE first when it does not exist")
    d.add_argument("--login", action="append", metavar="LOGIN:ROLE",
                   help="development only: create a SQL login in role writer, reader or admin; "
                        "password from CZ_<LOGIN>_PASSWORD")
    d.set_defaults(fn=cmd_db)
    d = dsub.add_parser("import", help="load assessment.json files written by assess --out, analyze or the Action")
    d.add_argument("files", nargs="+")
    d.add_argument("--sql", help="connection string (default CONTAINERIZER_SQL)")
    d.add_argument("--key-prefix", default="", help="prefix for the application key, e.g. the repository URL + '#'")
    d.set_defaults(fn=cmd_db)

    s = sub.add_parser("web", help="read-only results web UI for management (reads the SQL Server results database)")
    s.add_argument("--sql", help="connection string of a reader login (default CONTAINERIZER_SQL)")
    s.add_argument("--host", default="127.0.0.1", help="listen address (0.0.0.0 inside a container)")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_web)

    s = sub.add_parser("ai", help="ask Claude to review uncertain parts of an assessment")
    s.add_argument("paths", nargs="+")
    s.add_argument("--model", default=None)
    s.add_argument("--learn", action="store_true")
    s.add_argument("--force", action="store_true", help="review even when confidence is high")
    s.set_defaults(fn=cmd_ai)

    s = sub.add_parser("gate", help="security gate: lint generated manifests and scan images for vulnerabilities")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out")
    s.add_argument("--no-build", action="store_true", help="scan only the base images, do not build the app images")
    s.add_argument("--no-run", action="store_true", help="do not start the built images with their manifests' "
                   "security context")
    s.add_argument("--no-scan", action="store_true", help="lint only")
    s.add_argument("--no-refresh", action="store_true", help="use rules/images.lock.yaml even when it is stale")
    s.add_argument("--scanner", default=None, choices=["all", "auto", "trivy", "grype"],
                   help="default from rules/60-security.yaml (all: every available scanner, merged)")
    s.add_argument("--fail-on", default=None, help="lowest failing severity (default from rules/60-security.yaml)")
    s.add_argument("--registry", default="registry.local")
    s.add_argument("--pin-digests", action="store_true")
    s.set_defaults(fn=cmd_gate)

    s = sub.add_parser("images", help="show base images, or pick patched tags with --update")
    s.add_argument("--update", action="store_true", help="choose the newest patched tags and write rules/images.lock.yaml")
    s.add_argument("--no-scan", action="store_true", help="choose the newest tags without scanning them")
    s.add_argument("--scanner", default="all", choices=["all", "auto", "trivy", "grype"])
    s.set_defaults(fn=cmd_images)

    s = sub.add_parser("check", help="CI gate: compare with a base ref or baseline, write PR comment and SARIF")
    s.add_argument("paths", nargs="+")
    s.add_argument("--base-ref", help="git ref to compare with, e.g. origin/main (the working tree is not touched)")
    s.add_argument("--baseline", help="snapshot JSON written earlier with --save-baseline (instead of --base-ref)")
    s.add_argument("--fail-on", default="rewrite", choices=["none", "config", "refactor", "rewrite", "blocker"],
                   help="fail on new findings of this severity or worse (default: rewrite)")
    s.add_argument("--allow-rating-drop", action="store_true", help="do not fail when the rating gets worse")
    s.add_argument("--max-rating", choices=list("ABCDE"), help="fail when an app is rated worse than this")
    s.add_argument("--markdown", help="write the PR comment / summary here")
    s.add_argument("--sarif", help="write SARIF 2.1.0 here")
    s.add_argument("--json", help="write snapshot and diff here")
    s.add_argument("--save-baseline", help="write the current snapshot here, for a later --baseline")
    s.add_argument("--annotations", default="none", choices=["none", "github", "azure"],
                   help="print inline annotations; github also writes the job summary and step outputs")
    s.add_argument("--link", help="URL prefix for file links in the markdown, e.g. https://github.com/o/r/blob/SHA")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("bench", help="score assessments against labelled expectations")
    s.add_argument("--challenge", default="../containerization-challenge")
    s.add_argument("--labels", default=str(Path(__file__).resolve().parent.parent / "bench" / "labels.yaml"))
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--json")
    s.add_argument("--technique", default="rules", choices=["rules", "hybrid", "ai-only", "ai+rules"])
    s.add_argument("--model", default=None)
    s.set_defaults(fn=cmd_bench)

    args = ap.parse_args(argv)
    return _run_cmd(args)


if __name__ == "__main__":
    sys.exit(main())
