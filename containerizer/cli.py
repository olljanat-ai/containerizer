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
    from .rulereview import LearningSession
    from .verify import verify_app

    rc = 0
    for app in _apps(args.paths):
        with LearningSession(source_path=Path(app), ai=args.ai, model=args.model, enabled=None if args.learn else False) as ls:
            a = assess(app, load_rules())
            ls.app = a.name
            res = verify_app(a, Path(args.out) if args.out else None, learn=args.learn, only=args.component,
                             ai=args.ai, model=args.model, timeout=args.timeout)
            ls.add_results(res)
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
                        registry=args.registry, pin=args.pin_digests, timeout=args.timeout, gitops=_gitops(args),
                        sql=args.sql)
        ver = a.verification
        results.append(a)
        print(f"{a.name:24s} {a.rating} score={a.score:3d}  verified: "
              f"{sum(r['status'] in ('ok', 'ok-external') for r in ver)} run, "
              f"{sum(r['status'] == 'finding' for r in ver)} runtime findings, "
              f"{sum(r['status'] in ('build-failed', 'run-failed') for r in ver)} failed")
    write_reports(results, out)
    print(f"reports written to {out}")
    return _store(args, results, apps)


def cmd_org(args) -> int:
    from .org import OrgOptions, run_org
    from .orgsource import SourceError

    o = OrgOptions(
        provider=args.provider, org=args.org, registry=args.registry, api_url=args.api_url, token_env=args.token_env,
        output_repo=args.output_repo, output_dir=args.output_dir, output_branch=args.output_branch,
        output_token_env=args.output_token_env, output_username=args.output_username, push=not args.no_push,
        push_images=not args.no_push_images, tag=args.tag, image_pull_secret=args.image_pull_secret,
        cosign_key=args.cosign_key, include=args.include, exclude=args.exclude, skip_forks=args.skip_forks,
        stale_days=args.stale_days, max_repos=args.max_repos, ai=args.ai, model=args.model,
        verify=not args.no_verify, gate=not args.no_gate, scanner=args.scanner, fail_on=args.fail_on,
        timeout=args.timeout, pin=args.pin_digests, verify_commits=args.verify_commits, sql=args.sql,
        work_dir=args.work_dir, keep_work=args.keep_work, cache_dir=args.cache_dir,
        skip_no_code=not args.include_no_code, dry_run=args.dry_run,
        verify_sandbox=args.verify_sandbox, kubeconfig=args.kubeconfig, kube_context=args.kube_context,
        gitops=args.gitops, sandbox_timeout=args.sandbox_timeout)
    try:
        results = run_org(o)
    except SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    by = {}
    for r in results:
        by[r.status] = by.get(r.status, 0) + 1
    print(" ".join(f"{k}={v}" for k, v in sorted(by.items())))
    return 1 if by.get("error") else 0


def cmd_worker(args) -> int:
    from .worker import build

    return build(args)


def cmd_sandbox(args) -> int:
    import os
    from .sandbox import (HEALTHY, SCHEDULED, SKIPPED, KubeOptions, SandboxOptions, summary,
                          verify_sandbox, write_health)
    root = Path(args.output_dir)
    if not (root / "sandbox").is_dir():
        print(f"error: {root} has no sandbox/ folder: point --output-dir at a checkout of the output repository "
              "of `containerizer org`", file=sys.stderr)
        return 2
    o = SandboxOptions(kube=KubeOptions(kubeconfig=args.kubeconfig, context=args.kube_context), gitops=args.gitops,
                       timeout=args.timeout, settle=args.settle, revision=args.revision or "", learn=not args.no_learn)
    doc = verify_sandbox(root, o)
    write_health(root, doc)
    for r in doc["components"]:
        print(f"{r['app']}/{r['component']}: {r['status']}" + (f" - {r['reason']}" if r.get("reason") else ""))
    print(f"sandbox health: {summary(doc)} -> {root / 'sandbox' / 'HEALTH.md'}")
    if doc.get("learned"):
        print(f"learned from the cluster: {', '.join(doc['learned'])}")
    if (args.sql or os.environ.get("CONTAINERIZER_SQL")) and doc["components"] and not doc.get("skipped"):
        from .sqlstore import SqlError, store_sandbox
        try:
            n, missing = store_sandbox(args.sql, doc)
        except SqlError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
        print(f"{n} sandbox check(s) written to SQL Server" + (f"; {missing} not matched to an assessed component"
                                                             if missing else ""))
    bad = [r for r in doc["components"] if r["status"] not in (HEALTHY, SCHEDULED, SKIPPED)]
    return 1 if bad and args.fail_on_unhealthy else 0


def _kube_args(s) -> None:
    s.add_argument("--kubeconfig", help="kubeconfig of the sandbox cluster (default KUBECONFIG, ~/.kube/config or "
                   "the in-cluster service account); use a read-only identity, see sandbox/verify-rbac.yaml")
    s.add_argument("--kube-context", help="context in the kubeconfig (default: its current context)")
    s.add_argument("--gitops", default="auto", choices=["auto", "argocd", "flux"],
                   help="which GitOps tool deploys the sandbox (auto: Argo CD Application, else Flux Kustomization)")


def cmd_bench(args) -> int:
    from .bench import run_bench

    return run_bench(args)


def cmd_ai(args) -> int:
    from .ai import ai_review_app
    from .rulereview import LearningSession

    for app in _apps(args.paths):
        with LearningSession(source_path=Path(app), ai=True, model=args.model, enabled=None if args.learn else False) as ls:
            a = assess(app, load_rules())
            ls.app = a.name
            res = ai_review_app(a, model=args.model, learn=args.learn, force=args.force)
        print(json.dumps(res, indent=2))
    return 0


def _review_store(args):
    """The rule review store for `containerizer rules`: --dir (JSON file), else the results database
    through an admin login (--sql, CONTAINERIZER_ADMIN_SQL or CONTAINERIZER_SQL), else the JSON file."""
    import getpass
    import os
    from .rulereview import FileStore, SqlStore, default_dir
    user = args.reviewer or os.environ.get("CONTAINERIZER_REVIEWER") or getpass.getuser()
    if args.dir:
        return FileStore(args.dir), user
    cs, pw = args.sql, None
    if not cs and os.environ.get("CONTAINERIZER_ADMIN_SQL"):
        cs, pw = os.environ["CONTAINERIZER_ADMIN_SQL"], os.environ.get("CONTAINERIZER_ADMIN_SQL_PASSWORD")
    cs = cs or os.environ.get("CONTAINERIZER_SQL")
    if not cs:
        return FileStore(default_dir()), user
    st = SqlStore.connect(cs, pw)
    st.conn.set_user(user, args.reviewer_name, via="CLI")
    return st, user


def cmd_rules(args) -> int:
    from .rulereview import ReviewError, approve, reject
    from .sqlstore import SqlError
    try:
        store, user = _review_store(args)
    except SqlError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    try:
        if args.rules_cmd == "list":
            rows = store.list(args.status)
            if args.json:
                print(json.dumps(rows, indent=2, default=str))
                return 0
            if not rows:
                print(f"no {args.status if args.status != 'all' else ''} candidates".replace("  ", " "))
            for c in rows:
                print(f"{c['CandidateId']:>5}  {c['Status']:<8} {c['Kind']:<8} conf {float(c['Confidence']):.2f}  "
                      f"seen {c['SeenCount']}x  {c['RuleId']}\n       {c['Title']}"
                      + (f"\n       learned from {c['LearnedFrom']}" if c.get("LearnedFrom") else "")
                      + (f" · LLM {c['Model']}" if c.get("Model") else ""))
            return 0
        c = store.get(args.id)
        if not c:
            print(f"error: no candidate {args.id}", file=sys.stderr)
            return 1
        if args.rules_cmd == "show":
            if args.json:
                print(json.dumps(c, indent=2, default=str))
                return 0
            print(f"Candidate {c['CandidateId']} ({c['Status']}): {c['Title']}\nKind {c['Kind']}, source {c['Source']}, "
                  f"confidence {float(c['Confidence']):.2f}, seen {c['SeenCount']} time(s), learned from "
                  f"{c.get('LearnedFrom') or '-'}" + (f", LLM {c['Model']}" if c.get("Model") else ""))
            if c["Status"] != "pending":
                print(f"{c['Status'].capitalize()} by {c.get('ReviewedByName') or c.get('ReviewedBy')} at {c.get('ReviewedAt')}"
                      + (f": {c['ReviewNote']}" if c.get("ReviewNote") else "")
                      + (f"\nPull request: {c['PullRequestUrl']}" if c.get("PullRequestUrl") else ""))
            print(f"\n--- proposed rule ({c['TargetFile']}) ---\n{c.get('FinalYaml') or c['RuleYaml']}")
            if c.get("Diff"):
                print(f"--- diff ---\n{c['Diff']}")
            for ev in c.get("evidence") or []:
                print(f"--- evidence {ev.get('SeenAt')}: {ev.get('Application') or ''}/{ev.get('Component') or ''} "
                      f"{ev.get('RepositoryUrl') or ''} {ev.get('SourceCommit') or ''}\n"
                      f"outcome {ev.get('Outcome') or '-'}, stage {ev.get('Stage') or '-'}"
                      + (f", LLM {ev['Model']}" if ev.get("Model") else ""))
                if ev.get("ExitReason"):
                    print(ev["ExitReason"])
                if ev.get("LogExcerpt"):
                    print("log:\n" + ev["LogExcerpt"])
            return 0
        if args.rules_cmd == "approve":
            edited = None
            if args.edit:
                edited = sys.stdin.read() if args.edit == "-" else Path(args.edit).read_text()
            r = approve(store, args.id, user, args.reviewer_name, args.note, edited)
            print(f"candidate {args.id} approved{' (edited)' if r['edited'] else ''}: "
                  + ("pull request " if r["applied"] == "pr" else "written to ") + str(r["where"]))
            return 0
        if args.rules_cmd == "reject":
            reject(store, args.id, user, args.reviewer_name, args.note)
            print(f"candidate {args.id} rejected; it will not be proposed again")
            return 0
    except ReviewError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except SqlError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    finally:
        if hasattr(store, "close"):
            store.close()
    return 2


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
    s.add_argument("--ai", action="store_true", help="ask the LLM (Claude or self-hosted) about low-confidence components")
    s.add_argument("--model", default=None, help="LLM model (default CONTAINERIZER_MODEL, else claude-opus-5-5)")
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
    s.add_argument("--learn", action="store_true", help="propose what is learned for review (docs/rule-review.md)")
    s.add_argument("--ai", action="store_true", help="ask the LLM when no failure rule explains a failure")
    s.add_argument("--model", default=None, help="LLM model (default CONTAINERIZER_MODEL, else claude-opus-5-5)")
    s.add_argument("--timeout", type=int, default=900)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("analyze", help="one-shot: assess, build+run every feasible component, learn, report, generate")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out", default="containerizer-out")
    s.add_argument("--ai", action="store_true", help="ask the LLM about uncertain components and unexplained failures")
    s.add_argument("--model", default=None, help="LLM model (default CONTAINERIZER_MODEL, else claude-opus-5-5)")
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

    s = sub.add_parser("ai", help="ask the LLM (Claude or self-hosted) to review uncertain parts of an assessment")
    s.add_argument("paths", nargs="+")
    s.add_argument("--model", default=None, help="LLM model (default CONTAINERIZER_MODEL, else claude-opus-5-5)")
    s.add_argument("--learn", action="store_true")
    s.add_argument("--force", action="store_true", help="review even when confidence is high")
    s.set_defaults(fn=cmd_ai)

    s = sub.add_parser("rules", help="review learned rules: list, show the evidence, approve (optionally edited) "
                       "or reject (docs/rule-review.md)")
    rsub = s.add_subparsers(dest="rules_cmd", required=True)

    def _review_args(p):
        p.add_argument("--sql", help="connection string of an admin login (default CONTAINERIZER_ADMIN_SQL, else "
                       "CONTAINERIZER_SQL); without one, the local file store")
        p.add_argument("--dir", help="use the file store in this folder (default CONTAINERIZER_REVIEW_DIR or .work/rule-review)")
        p.add_argument("--as", dest="reviewer", help="who decides, for the change history (default CONTAINERIZER_REVIEWER, "
                       "else the OS user)")
        p.add_argument("--name", dest="reviewer_name", help="display name of the reviewer")
        p.set_defaults(fn=cmd_rules)
    r = rsub.add_parser("list", help="candidates (default: pending)")
    r.add_argument("--status", default="pending", choices=["pending", "approved", "rejected", "all"])
    r.add_argument("--json", action="store_true")
    _review_args(r)
    r = rsub.add_parser("show", help="one candidate with its rule, diff and evidence")
    r.add_argument("id", type=int)
    r.add_argument("--json", action="store_true")
    _review_args(r)
    r = rsub.add_parser("approve", help="validate and apply: a pull request (CONTAINERIZER_RULES_APPLY=pr) or the "
                        "local ruleset files (=direct)")
    r.add_argument("id", type=int)
    r.add_argument("--edit", metavar="FILE", help="approve this YAML instead of the rule as learned ('-' reads stdin)")
    r.add_argument("--note", help="why (kept in the change history)")
    _review_args(r)
    r = rsub.add_parser("reject", help="reject; the same rule is not proposed again")
    r.add_argument("id", type=int)
    r.add_argument("--note", help="why (kept in the change history)")
    _review_args(r)

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

    s = sub.add_parser("org", help="run analyze on every Git repository of an Azure DevOps, GitHub or GitLab "
                       "organization; deploy the A-rated components (images, manifests, Argo CD + Flux)")
    s.add_argument("--provider", required=True, choices=["azure-devops", "github", "gitlab"])
    s.add_argument("--org", required=True, help="organization (Azure DevOps organization or collection, GitHub "
                   "organization, GitLab group path)")
    s.add_argument("--api-url", help="self-hosted server: https://ghe.example.com/api/v3, https://gitlab.example.com, "
                   "https://tfs.example.com/tfs")
    s.add_argument("--token-env", help="environment variable with the read token (default AZURE_DEVOPS_TOKEN / "
                   "SYSTEM_ACCESSTOKEN, GITHUB_TOKEN / GH_TOKEN, GITLAB_TOKEN)")
    s.add_argument("--registry", required=True, help="image registry and path, e.g. myacr.azurecr.io/sandbox; "
                   "credentials from REGISTRY_USERNAME / REGISTRY_PASSWORD or an existing docker login")
    s.add_argument("--tag", help="image tag (default 1.<yyyymmdd>.<hhmm> of the run, semver for image automation)")
    s.add_argument("--no-push-images", action="store_true", help="build and gate, but do not push images")
    s.add_argument("--image-pull-secret", help="add this imagePullSecret to every generated workload")
    s.add_argument("--cosign-key", help="sign pushed images with cosign (key file, env://VAR or KMS URI)")
    s.add_argument("--output-repo", help="Git repository (https) the generated files are committed to")
    s.add_argument("--output-dir", help="local folder instead of --output-repo (committed when it is a Git checkout)")
    s.add_argument("--output-branch", default="main")
    s.add_argument("--output-token-env", default="OUTPUT_GIT_TOKEN",
                   help="environment variable with a token that can push to the output repository")
    s.add_argument("--output-username", default="x-access-token", help="user name sent with that token")
    s.add_argument("--no-push", action="store_true", help="commit to the output repository but do not push")
    s.add_argument("--include", help="regex on <project>/<repository> to process")
    s.add_argument("--exclude", help="regex on <project>/<repository> to skip")
    s.add_argument("--skip-forks", action="store_true")
    s.add_argument("--stale-days", type=int, default=183,
                   help="skip repositories with no commit for this many days (default 183, about 6 months; 0: off)")
    s.add_argument("--max-repos", type=int, default=0)
    s.add_argument("--ai", action="store_true", help="ask the LLM about uncertain components and unexplained failures")
    s.add_argument("--model", default=None)
    s.add_argument("--no-verify", action="store_true", help="do not build and run before rating (less accurate)")
    s.add_argument("--no-gate", action="store_true", help="skip the security gate (lint, image scan, hardened run)")
    s.add_argument("--scanner", default=None, choices=["all", "auto", "trivy", "grype"])
    s.add_argument("--fail-on", default=None)
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--pin-digests", action="store_true")
    s.add_argument("--verify-commits", action="store_true", help="Flux: only apply signed commits")
    s.add_argument("--sql", help="also write every assessment to SQL Server (default CONTAINERIZER_SQL)")
    s.add_argument("--work-dir", default=".work/org")
    s.add_argument("--keep-work", action="store_true", help="keep the clones")
    s.add_argument("--cache-dir", help="keep the clones in this folder (one per organization) and only pull the "
                   "newest commit on later runs; clones of repositories the organization no longer has are removed")
    s.add_argument("--include-no-code", action="store_true", help="do not skip repositories without application "
                   "code (only documentation, configuration, scripts, or only libraries and tests)")
    s.add_argument("--dry-run", action="store_true", help="list the repositories and the API-level skips only")
    g = s.add_argument_group("sandbox verification (read back pod health after Argo CD / Flux synced the push)")
    g.add_argument("--verify-sandbox", action="store_true", help="at the end, wait for the sandbox cluster to sync "
                   "the pushed commit and record per component: deployed and healthy / deployed but failing (reason); "
                   "skipped with a message when there is no cluster access")
    _kube_args(g)
    g.add_argument("--sandbox-timeout", type=int, default=900, help="seconds to wait for sync and rollout (default 900)")
    s.set_defaults(fn=cmd_org)

    s = sub.add_parser("sandbox", help="sandbox cluster deployed by `org`: read back health of every component")
    ssub = s.add_subparsers(dest="sandbox_cmd", required=True)
    v = ssub.add_parser("verify", help="wait for the Argo CD / Flux sync, read rollout, readiness, restarts and events; "
                        "write sandbox/HEALTH.md + health.json, the results database and learned rules")
    v.add_argument("--output-dir", default=".", help="checkout of the output repository (default: current folder)")
    _kube_args(v)
    v.add_argument("--revision", help="commit to wait for (default: HEAD of --output-dir)")
    v.add_argument("--timeout", type=int, default=900, help="seconds to wait for sync and rollout (default 900)")
    v.add_argument("--settle", type=int, default=60,
                   help="a component is healthy only when it stays ready without restarts this long (default 60)")
    v.add_argument("--no-learn", action="store_true", help="do not turn code/platform failures into learned rules")
    v.add_argument("--fail-on-unhealthy", action="store_true", help="exit 1 when a component is not healthy")
    v.add_argument("--sql", help="also write the checks to SQL Server (default CONTAINERIZER_SQL)")
    v.set_defaults(fn=cmd_sandbox)

    s = sub.add_parser("worker", help="run the organization scans scheduled on the admin pages (needs Docker); "
                       "serves Prometheus metrics")
    s.add_argument("--sql", help="connection string of a writer login (default CONTAINERIZER_SQL; password in "
                   "CONTAINERIZER_SQL_PASSWORD)")
    s.add_argument("--data-dir", default="/var/lib/containerizer",
                   help="clones (kept between runs), work folders and local output, one folder per scan")
    s.add_argument("--poll", type=int, default=30, help="seconds between checks for due scans")
    s.add_argument("--name", help="worker name shown on the runs (default: the host name)")
    s.add_argument("--metrics-host", default="127.0.0.1", help="listen address of the metrics endpoint")
    s.add_argument("--metrics-port", type=int, default=9464)
    s.add_argument("--no-metrics", action="store_true")
    s.add_argument("--once", action="store_true", help="run what is due or queued, then exit")
    s.set_defaults(fn=cmd_worker)

    s = sub.add_parser("bench", help="score assessments against labelled expectations")
    s.add_argument("--challenge", default="../containerization-challenge")
    s.add_argument("--labels", default=str(Path(__file__).resolve().parent.parent / "bench" / "labels.yaml"))
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--json")
    s.add_argument("--technique", default="rules", choices=["rules", "hybrid", "ai-only", "ai+rules"])
    s.add_argument("--model", default=None, help="LLM model (default CONTAINERIZER_MODEL, else claude-opus-5-5)")
    s.set_defaults(fn=cmd_bench)

    args = ap.parse_args(argv)
    return _run_cmd(args)


if __name__ == "__main__":
    sys.exit(main())
