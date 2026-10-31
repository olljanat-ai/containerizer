"""Migration assistant: concrete replacements for what keeps a component out of a Linux container.

For every component that is not ready (verdict refactor, rewrite or blocker, or one that keeps local
state), each serious finding is mapped to a migration from rules/migrations.yaml (what to replace with
what, packages, steps, verification, references). Findings without an entry get an item built
from their own rule. The plan is rendered as Markdown for the reports and as a self-contained prompt that
can be handed to an AI coding agent (Claude Code, GitHub Copilot, ...) to carry out the migration.

Everything here is rule data and deterministic text: no AI is involved, and the same scan gives the same
prompt, so it can be stored with the assessment and compared between scans.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .rules import RULES_DIR, SEV_RANK

MIGRATIONS_FILE = RULES_DIR / "migrations.yaml"
KINDS = ("replace", "port", "externalize", "isolate")
SERIOUS = ("refactor", "rewrite", "blocker")
NOT_READY = set(SERIOUS)
# in the ASP.NET Core shared framework: nothing to add for web projects
ASPNETCORE_SHARED = {"Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging.Console"}
KIND_TEXT = {"replace": "Replace", "port": "Port", "externalize": "Move out of the process",
             "isolate": "Keep on Windows / isolate"}


@dataclass
class Migration:
    id: str
    rules: list[str]
    kind: str
    replace: str
    with_: str
    packages: dict = field(default_factory=dict)
    steps: list[str] = field(default_factory=list)
    verify: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Migration":
        m = cls(id=d["id"], rules=list(d.get("for") or []), kind=d.get("kind", "replace"),
                replace=str(d.get("replace", "")).strip(), with_=str(d.get("with", "")).strip(),
                packages={k: list(v or []) for k, v in (d.get("packages") or {}).items()},
                steps=[" ".join(str(s).split()) for s in d.get("steps") or []],
                verify=[" ".join(str(s).split()) for s in d.get("verify") or []],
                refs=list(d.get("refs") or []))
        if m.kind not in KINDS:
            raise ValueError(f"migration {m.id}: unknown kind {m.kind}")
        return m


@lru_cache(maxsize=4)
def _load(path: str) -> tuple[Migration, ...]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return tuple(Migration.from_dict(d) for d in data.get("migrations") or [])


def load_migrations(path: Path | None = None) -> list[Migration]:
    return list(_load(str(path or MIGRATIONS_FILE)))


def migration_index(migrations: list[Migration] | None = None) -> dict[str, Migration]:
    """Finding rule id -> migration."""
    idx: dict[str, Migration] = {}
    for m in migrations if migrations is not None else load_migrations():
        for rid in m.rules:
            idx.setdefault(rid, m)
    return idx


def _ws(s) -> str:
    return " ".join(str(s or "").split())


def _refs(*lists) -> list[str]:
    out: list[str] = []
    for lst in lists:
        for u in lst or []:
            if isinstance(u, str) and u.startswith(("https://", "http://")) and u not in out:
                out.append(u)
    return out


def _packages(m: Migration, c) -> dict:
    """Packages to add, and those of the listed removals the project actually references."""
    import fnmatch
    have = [*c.project.packages, *c.project.references]
    have = {h.split(",")[0].strip() for h in have}
    out = {}
    if m.packages.get("add"):
        shared = ASPNETCORE_SHARED if "Microsoft.AspNetCore.App" in c.project.framework_refs or \
            (c.project.sdk or "").endswith(".Web") else set()
        out["add"] = [p for p in m.packages["add"] if p not in have and p not in shared]
    rm = [p for p in m.packages.get("remove") or [] if any(fnmatch.fnmatchcase(h.lower(), p.lower()) for h in have)]
    if rm:
        out["remove"] = rm
    return {k: v for k, v in out.items() if v}


def needs_plan(c) -> bool:
    return c.verdict in NOT_READY or getattr(c, "stateless", None) is False


def component_plan(a, c, index: dict[str, Migration] | None = None) -> dict | None:
    """The migration plan of one component as a JSON-ready dict, or None when it is ready as is."""
    if not needs_plan(c):
        return None
    index = index if index is not None else migration_index()
    items: dict[str, dict] = {}
    for f in sorted(c.findings, key=lambda f: -SEV_RANK[f.severity]):
        if f.severity not in SERIOUS or f.dormant:
            continue
        r = f.rule
        m = index.get(r.id)
        key = m.id if m else f"rule:{r.id}"
        it = items.get(key)
        finding = {"rule": r.id, "title": r.title, "severity": f.severity, "why": _ws(r.why), "fix": _ws(r.fix),
                   "via": f.via, "only_commands": list(f.modes), "evidence": [str(e) for e in f.evidence[:3]]}
        if it is None:
            if m:
                it = {"id": m.id, "kind": m.kind, "replace": m.replace, "with": m.with_,
                      "packages": _packages(m, c), "steps": list(m.steps),
                      "verify": list(m.verify), "refs": _refs(m.refs, r.refs), "curated": True, "findings": []}
            else:
                it = {"id": key, "kind": "isolate" if r.severity == "blocker" and r.windows_container is False
                      and r.effort == 0 else "replace",
                      "replace": r.title, "with": _ws(r.fix), "packages": {},
                      "steps": [_ws(r.fix)] if r.fix else [], "verify": [], "refs": _refs(r.refs),
                      "curated": False, "findings": []}
            items[key] = it
        else:
            it["refs"] = _refs(it["refs"], r.refs)
        it["findings"].append(finding)
        if f.modes:
            it["only_commands"] = sorted(set(it.get("only_commands", [])) | set(f.modes))
    state = None
    if getattr(c, "stateless", None) is False or (c.facts or {}).get("writable_dirs"):
        dirs = list((c.facts or {}).get("writable_dirs") or [])
        state = {"writable_dirs": dirs, "stateless": getattr(c, "stateless", None)}
    ordered = sorted(items.values(), key=lambda i: (i["kind"] == "isolate",
                                                    -max(SEV_RANK[f["severity"]] for f in i["findings"])))
    actionable = [i for i in ordered if i["kind"] != "isolate"]
    isolate = [i for i in ordered if i["kind"] == "isolate"]
    plan = {
        "component": c.name, "project": c.project.rel, "role": c.role, "verdict": c.verdict,
        "items": ordered, "state": state,
        "outcome": ("stays-on-windows" if isolate and not actionable else
                    "partial" if isolate else "linux-container"),
    }
    plan["prompt"] = agent_prompt(a, c, plan) if actionable or state else None
    return plan


def app_plans(a) -> dict[str, dict]:
    """Project path -> plan for every component of the application that needs one."""
    idx = migration_index()
    out = {}
    for c in a.components:
        p = component_plan(a, c, idx)
        if p:
            out[c.project.rel] = p
    return out


# ---------------------------------------------------------------------------
# rendering

def _bullets(lines, indent: str = "") -> list[str]:
    return [f"{indent}- {x}" for x in lines]


def _item_md(n: int, it: dict, for_agent: bool) -> list[str]:
    head = f"### {n}. {it['replace']} → {it['with']}" if it["with"] != it["replace"] else f"### {n}. {it['replace']}"
    L = [head, ""]
    sev = sorted({f["severity"] for f in it["findings"]}, key=lambda s: -SEV_RANK[s])
    L.append(f"Kind: {KIND_TEXT[it['kind']]} · severity: {', '.join(sev)}")
    if it.get("only_commands"):
        L.append(f"Only the {', '.join('`' + m + '`' for m in it['only_commands'])} command(s) are affected; "
                 "the other commands already run on Linux.")
    L += ["", "Findings:"]
    for f in it["findings"]:
        via = f" (in shared library {f['via']})" if f["via"] else ""
        L.append(f"- **{f['title']}**{via}: {f['why']}")
        for ev in f["evidence"]:
            L.append(f"  - evidence: `{ev}`")
    pk = it.get("packages") or {}
    if pk.get("add") or pk.get("remove"):
        L += [""]
        if pk.get("add"):
            L.append("Packages to add: " + ", ".join(f"`{p}`" for p in pk["add"]))
        if pk.get("remove"):
            L.append("Packages/references to remove: " + ", ".join(f"`{p}`" for p in pk["remove"]))
    if it["steps"]:
        L += ["", "Steps:"] + [f"{i}. {s}" for i, s in enumerate(it["steps"], 1)]
    if it["verify"]:
        L += ["", "Check:"] + _bullets(it["verify"])
    if it["refs"]:
        L += ["", "References: " + ", ".join(it["refs"] if for_agent else (f"<{u}>" for u in it["refs"]))]
    return L + [""]


def _lang(c) -> dict:
    """Wording and commands of the prompt for the component's platform."""
    p = c.project
    pr = p.properties or {}
    rel = p.rel_dir if hasattr(p, "rel_dir") else p.rel
    if p.kind_hint == "java":
        gradle = pr.get("BuildTool") == "gradle"
        build = "`./gradlew build`" if pr.get("Wrapper") == "gradlew" else "`gradle build`" if gradle else \
            ("`./mvnw verify`" if pr.get("Wrapper") == "mvnw" else "`mvn verify`")
        return {
            "platform": f"Java {pr.get('JavaVersion') or '(version not declared)'}, {pr.get('BuildTool', 'maven')}",
            "config": "configuration properties (Spring `@ConfigurationProperties` / `application.properties`, or the "
                      "framework's equivalent) that environment variables can override",
            "logs": "Logs go to stdout through the logging framework (no file appenders); temp files go to "
                    "`java.io.tmpdir`.",
            "packages": "Use only maintained artifacts from Maven Central at their latest stable version without known "
                        "vulnerabilities (check with the OWASP dependency-check plugin or `mvn versions:display-dependency-updates`).",
            "port": "Listen on the port from configuration (`server.port` / `SERVER_PORT` for Spring Boot, "
                    "`quarkus.http.port`, or `PORT`).",
            "guard": "guard it with an operating-system check (`System.getProperty(\"os.name\")`, or "
                     "`SystemUtils.IS_OS_WINDOWS` from Apache Commons Lang)",
            "build": f"1. {build} of `{rel}` succeeds, including its tests.",
            "test": "2. All existing tests pass; add unit or integration tests for every replaced API.",
        }
    if p.kind_hint == "node":
        pm = pr.get("PackageManager") or "npm"
        return {
            "platform": f"Node.js (engines: {pr.get('NodeEngine') or 'any'}), {pm}",
            "config": "configuration read from environment variables (`process.env`, with defaults under a mounted path)",
            "logs": "Logs go to stdout (console or a logger with a stdout transport), not to files; temp files go to "
                    "`os.tmpdir()`.",
            "packages": f"Use only maintained packages from the npm registry at their latest stable version without "
                        f"known vulnerabilities (check with `{pm} audit`), and keep the lockfile committed.",
            "port": "Listen on the port from the `PORT` environment variable, on all interfaces.",
            "guard": "guard it with `process.platform === 'win32'`",
            "build": f"1. `{pm} install` from the lockfile and the build script of `{rel}` succeed.",
            "test": f"2. All existing tests pass (`{pm} test`); add tests for every replaced API.",
        }
    return {
        "platform": "target framework: " + (";".join(p.tfms) or p.kind_hint),
        "config": "configurable (IConfiguration / options) with a default under a mounted path",
        "logs": "Logs go to stdout through ILogger, not to files; temp files go to the system temp folder.",
        "packages": "Use only maintained packages from nuget.org at their latest stable version without known "
                    "vulnerabilities (check with `dotnet list package --vulnerable`).",
        "port": "Listen on the port from configuration (ASPNETCORE_HTTP_PORTS / Kestrel settings).",
        "guard": "guard it with `OperatingSystem.IsWindows()`",
        "build": f"1. `dotnet build` of `{p.rel}` succeeds with no new warnings, including no CA1416 "
                 "(platform compatibility) warnings for the changed code.",
        "test": "2. All existing tests pass (`dotnet test`); add unit or integration tests for every replaced API.",
    }


def agent_prompt(a, c, plan: dict) -> str:
    """A self-contained task description for an AI coding agent working in the component's repository."""
    actionable = [i for i in plan["items"] if i["kind"] != "isolate"]
    isolate = [i for i in plan["items"] if i["kind"] == "isolate"]
    lang = _lang(c)
    L = [f"# Task: make `{c.name}` run in a Linux container", "",
         "You are a coding agent working in this repository. Change the code of the component below so that it "
         "builds and runs in a Linux container on Kubernetes, by carrying out the migration plan in this prompt. "
         "The plan comes from a rule-based containerization assessment (containerizer); each item names the "
         "findings it resolves and the evidence where they were found.", "",
         "## Component", "",
         f"- Application: {a.name}",
         f"- Project: `{c.project.rel}`",
         f"- Kind: {c.role}; {lang['platform']}",
         f"- Current verdict: {c.verdict} ({_verdict_text(c.verdict)})", ""]
    if actionable:
        L += ["## Migration plan", "",
              "Do the items in this order; each is independent enough to be its own commit.", ""]
        for n, it in enumerate(actionable, 1):
            L += _item_md(n, it, True)
    st = plan.get("state")
    if st:
        L += ["## Local state", ""]
        if st.get("writable_dirs"):
            L.append("The component writes to these folders: " + ", ".join(f"`{d}`" for d in st["writable_dirs"]) + ".")
        L += ["In Kubernetes the container's file system is read-only and pods are replaced at any time, so:",
              f"- Make every such folder part of the {lang['config']}." if c.project.kind_hint in ("java", "node") else
              f"- Make every such folder {lang['config']}.",
              "- Data that must survive a restart or be shared between replicas (uploads, generated documents, "
              "queues, SQLite/LiteDB files) belongs in an external store: the database, object storage "
              "(S3/Azure Blob) or a cache (Redis). Change the code to use it.",
              "- " + lang["logs"], ""]
    if isolate:
        L += ["## Out of scope: keep on Windows", "",
              "These findings have no Linux replacement inside this component. Do not try to remove them by "
              "deleting functionality. If the steps below ask for it, move the affected calls behind an interface "
              "so they can later be served by a separate Windows-hosted service; otherwise leave them as they "
              "are and list them in your summary.", ""]
        for it in isolate:
            L.append(f"- **{it['replace']}** ({', '.join(f['title'] for f in it['findings'])}): {it['with']}")
            L += _bullets(it["steps"], "  ")
        L.append("")
    L += ["## Constraints", "",
          "- Keep the change minimal: touch only what the plan needs. Do not refactor, rename or reformat unrelated "
          "code, and keep public contracts (HTTP routes, message and file formats, database schema) unchanged "
          "unless a step says otherwise.",
          "- Keep behaviour identical for users; when a replacement library behaves differently (formats, "
          "rounding, encoding, culture), match the old behaviour and add a test for it.",
          "- Security: no secrets, connection strings or credentials in code or committed configuration; read "
          "them from configuration supplied by environment variables or mounted Kubernetes Secrets. Do not "
          "disable TLS certificate validation. " + lang["packages"],
          "- Container readiness: the app must run as a non-root user with a read-only root file system; write only "
          "to configured, mounted folders or the temp folder. Log to stdout. " + lang["port"] + " Handle SIGTERM by "
          "stopping gracefully.",
          f"- Where Windows-only code must stay for an existing Windows deployment, {lang['guard']} and give Linux a "
          "working path instead of deleting it.",
          "- Do not add a Dockerfile or Kubernetes manifests: containerizer generates hardened ones from the code.",
          ""]
    L += ["## How to verify", "",
          lang["build"], lang["test"],
          "3. Every \"Check\" step in the plan above passes.",
          "4. If the containerizer tool is available, re-run the assessment from the repository root: "
          "`python -m containerizer assess . -v`. The findings "
          "listed in this plan no longer appear for this component and its verdict is `config` or `info` (ready)"
          + (" except for the out-of-scope items." if isolate else "."),
          "5. If Docker is available, build and run the generated container: "
          "`python -m containerizer verify . --learn` builds the image and runs it hardened (read-only, non-root, "
          "no capabilities) and reports any runtime failure.", "",
          "## Deliverable", "",
          "A pull request (or patch) with one commit per plan item where practical, and a summary listing for each "
          "item what was changed, how it was verified, and anything that could not be done and why."]
    return "\n".join(L).rstrip() + "\n"


def _verdict_text(v: str) -> str:
    from .assess import VERDICT_TEXT
    return VERDICT_TEXT.get(v, v)


def plan_markdown(plan: dict, heading: str = "###") -> list[str]:
    """Short human-readable form of a plan for the migration report."""
    L = [f"{heading} {plan['component']}: {_outcome_text(plan['outcome'])}", "",
         "| # | Replace | With | Kind |", "| --- | --- | --- | --- |"]
    for n, it in enumerate(plan["items"], 1):
        L.append(f"| {n} | {it['replace']} | {it['with']} | {KIND_TEXT[it['kind']]} |")
    L.append("")
    if plan.get("state") and plan["state"].get("writable_dirs"):
        L += [f"Local state: writes to {', '.join('`' + d + '`' for d in plan['state']['writable_dirs'])}; "
              "move what must persist to an external store.", ""]
    return L


def _outcome_text(o: str) -> str:
    return {"linux-container": "can move to a Linux container", "partial": "can move once Windows-only parts are isolated",
            "stays-on-windows": "stays on Windows"}.get(o, o)


def prompt_filename(component: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "-", component).strip("-") + ".md"
