"""Turns scanned facts + rules into an assessment per component and per application."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .rules import SEV_RANK, SEVERITIES, Context, Match, Rule, load_rules, run_rule
from .reach import CODE_EXT, mode_reachability, reachable_files
from .scan import Project, Repo, nearest_tfms, scan

SERVER_ROLES = {"web", "worker", "console", "spa"}
PLATFORM_ROLES = {"biztalk", "sharepoint", "sitecore"}  # deployables that need a Windows product
DB_TIER_ROLES = {"sqlclr", "ssis", "sqldb"}         # live with the database, not containers
CLIENT_ROLES = {"desktop"}
NON_DEPLOYABLE = {"library", "test", "spa-assets", "tool"}

VERDICT_TEXT = {
    "info": "Ready: containerize as is",
    "config": "Ready with configuration (no code changes)",
    "refactor": "Needs targeted code changes",
    "rewrite": "Needs a port/rewrite of the component",
    "blocker": "Not feasible in a Linux container",
}
APP_RATINGS = {
    "A": "Lift and shift - stateless containers with configuration only",
    "B": "Minor refactoring - small code changes",
    "C": "Major refactoring - framework port needed",
    "D": "Partial - some components must stay on Windows",
    "E": "Not feasible - core depends on Windows-only technology",
}


@dataclass
class Finding:
    rule: Rule
    evidence: list
    via: str = ""             # library project the finding was inherited from
    dormant: bool = False     # library code that this component never references
    modes: list = field(default_factory=list)   # only reached by these optional commands

    @property
    def severity(self) -> str:
        if self.dormant:
            return "info"
        if self.modes and self.rule.severity in ("blocker", "rewrite"):
            return "refactor"     # the other commands run; split this one off or keep it on Windows
        return self.rule.severity

    def to_dict(self) -> dict:
        r = self.rule
        return {"id": r.id, "severity": r.severity, "category": r.category, "title": r.title,
                "why": " ".join(r.why.split()), "fix": " ".join(r.fix.split()), "refs": list(r.refs),
                "via": self.via, "dormant": self.dormant, "only_commands": self.modes, "evidence": [str(e) for e in self.evidence[:3]], "source": r.source,
                "windows_container": r.windows_container}


@dataclass
class Component:
    project: Project
    role: str
    findings: list[Finding] = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    role_rule: str = ""
    confidence: float = 1.0
    uncertain: list[str] = field(default_factory=list)
    override: str = ""          # verdict decided by AI review (hybrid mode)
    ai: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.project.assembly_name or self.project.name

    @property
    def verdict(self) -> str:
        if self.override:
            return self.override
        return self.rule_verdict

    @property
    def rule_verdict(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=lambda s: SEV_RANK[s])

    @property
    def state_findings(self) -> list[Finding]:
        """Findings that say the component keeps its own data (on local disk or in memory)."""
        return [f for f in self.findings if f.rule.state and not f.dormant]

    @property
    def stateless(self) -> bool:
        return not self.state_findings

    @property
    def weight(self) -> float:
        """Sum of the rule weights (`effort` in the rules), which lowers the readiness score. Internal only:
        it is not a work estimate and is not shown or stored."""
        seen, total = set(), 0.0
        for f in self.findings:
            if f.rule.id not in seen:
                seen.add(f.rule.id)
                total += f.rule.effort
        return round(total, 2)

    @property
    def windows_container_ok(self) -> bool:
        if self.verdict != "blocker" and self.verdict != "rewrite":
            return True
        return all(f.rule.windows_container is not False for f in self.findings if f.severity in ("rewrite", "blocker"))

    @property
    def score(self) -> int:
        base = {"info": 100, "config": 90, "refactor": 70, "rewrite": 40, "blocker": 0}[self.verdict]
        if self.verdict in ("config", "refactor", "rewrite"):
            base -= min(25, int(self.weight * 1.5))
        return max(base, 0 if self.verdict == "blocker" else 5)

    @property
    def tier(self) -> str:
        if self.role in SERVER_ROLES:
            return "server"
        if self.role in PLATFORM_ROLES:
            return "platform"
        if self.role in DB_TIER_ROLES:
            return "database"
        if self.role in CLIENT_ROLES:
            return "client"
        return "other"

    def to_dict(self) -> dict:
        return {"name": self.name, "project": self.project.rel, "role": self.role, "tier": self.tier,
                "tfm": self.project.tfms, "verdict": self.verdict, "verdict_text": VERDICT_TEXT[self.verdict],
                "score": self.score, "windows_container_ok": self.windows_container_ok,
                "confidence": round(self.confidence, 2), "uncertain": self.uncertain,
                "rule_verdict": self.rule_verdict, "ai": self.ai, "stateless": self.stateless,
                "state": [{"id": f.rule.id, "title": f.rule.title, "state": f.rule.state}
                          for f in {f.rule.id: f for f in self.state_findings}.values()],
                "facts": self.facts, "findings": [f.to_dict() for f in sorted(
                    self.findings, key=lambda f: -SEV_RANK[f.severity])]}


@dataclass
class AppAssessment:
    repo: Repo
    components: list[Component]
    libraries: list[Component]
    tests: list[Component]
    repo_findings: list[Finding]

    @property
    def name(self) -> str:
        return self.repo.name

    def server(self) -> list[Component]:
        return [c for c in self.components if c.tier in ("server", "platform")]

    @property
    def rating(self) -> str:
        server = self.server()
        if not server:
            return "E"
        blocked = [c for c in server if c.verdict == "blocker"]
        if blocked:
            return "E" if len(blocked) * 4 >= len(server) * 3 else "D"
        worst = max((c.verdict for c in server), key=lambda s: SEV_RANK[s])
        rating = {"info": "A", "config": "A", "refactor": "B", "rewrite": "C"}[worst]
        # A means stateless: data only in external services (SQL, Redis, blob storage, queues),
        # none on a component's own disk or in its memory, so replicas can come and go
        if rating == "A" and any(not c.stateless for c in server):
            return "B"
        return rating

    def stateful(self) -> list[Component]:
        return [c for c in self.server() if not c.stateless]

    @property
    def score(self) -> int:
        server = self.server()
        if not server:
            return 0
        return round(sum(c.score for c in server) / len(server))

    @property
    def confidence(self) -> float:
        server = self.server() or self.components
        return round(min((c.confidence for c in server), default=0.5), 2)

    def summary(self) -> str:
        server = self.server()
        n = len(server)
        by = {}
        for c in server:
            by.setdefault(c.verdict, []).append(c.name)
        parts = []
        ok = len(by.get("info", [])) + len(by.get("config", []))
        if ok:
            parts.append(f"{ok}/{n} server components can run in Linux containers with configuration only")
        if by.get("refactor"):
            parts.append(f"{len(by['refactor'])} need targeted code changes")
        if by.get("rewrite"):
            parts.append(f"{len(by['rewrite'])} need a framework port or a rewrite")
        if by.get("blocker"):
            parts.append(f"{len(by['blocker'])} cannot run in Linux containers ({', '.join(by['blocker'])})")
        stateful = self.stateful()
        if stateful:
            what = "; ".join(f"{c.name}: " + ", ".join(dict.fromkeys(f.rule.title for f in c.state_findings))
                             for c in stateful)
            parts.append(f"{len(stateful)} keep their own data, so the app is not stateless ({what})")
        clients = [c.name for c in self.components if c.tier == "client"]
        if clients:
            parts.append(f"desktop clients stay on PCs ({', '.join(clients)})")
        db = [c.name for c in self.components if c.tier == "database"]
        if db:
            parts.append(f"database-tier code stays with SQL Server ({', '.join(db)})")
        if not server:
            parts.insert(0, "no server-side component to containerize")
        return "; ".join(parts) + "."

    def top_blockers(self, n: int = 5) -> list[dict]:
        seen: dict[str, dict] = {}
        for c in self.server() + [c for c in self.components if c.tier == "client"]:
            for f in c.findings:
                if f.severity in ("blocker", "rewrite"):
                    d = seen.setdefault(f.rule.id, {"id": f.rule.id, "title": f.rule.title, "severity": f.severity,
                                                     "components": []})
                    if c.name not in d["components"]:
                        d["components"].append(c.name)
        return sorted(seen.values(), key=lambda d: (-SEV_RANK[d["severity"]], -len(d["components"])))[:n]

    def migration_plans(self) -> dict[str, dict]:
        """Project path -> migration plan (migrate.py) for the components that are not ready."""
        from .migrate import app_plans
        return app_plans(self)

    def to_dict(self) -> dict:
        plans = self.migration_plans()
        return {"name": self.name, "rating": self.rating, "rating_text": APP_RATINGS[self.rating],
                "stateless": not self.stateful(), "score": self.score, "confidence": self.confidence,
                "summary": self.summary(), "top_blockers": self.top_blockers(),
                "components": [{**c.to_dict(), **({"migration": plans[c.project.rel]} if c.project.rel in plans else {})}
                               for c in self.components],
                "libraries": [{"name": c.name, "project": c.project.rel, "tfm": c.project.tfms,
                               "findings": [f.to_dict() for f in c.findings]} for c in self.libraries],
                "tests": [c.project.rel for c in self.tests],
                "repo_findings": [f.to_dict() for f in self.repo_findings]}


def classify_role(repo: Repo, p: Project, rules: list[Rule]) -> tuple[str, str]:
    best: tuple[int, str, str] | None = None
    for r in rules:
        if r.phase != "role":
            continue
        if best is not None and r.priority <= best[0]:
            continue
        m = run_rule(r, Context(repo, p))
        if m:
            best = (r.priority, r.role, r.id)
    if best is None:
        return "library", ""
    return best[1], best[2]


WEB_HOST_RE = re.compile(r"WebApplication\.Create(Builder|SlimBuilder)?\s*\(|WebHost\.CreateDefaultBuilder|"
                         r"ConfigureWebHostDefaults|\.UseKestrel\s*\(")
DELEGATED_MAIN_RE = re.compile(r"\b((?:[A-Za-z_]\w*\.)+)Program\.Main(?:Async)?\s*\(")
TYPE_DECL_RE = re.compile(r"\b(?:class|record|struct)\s+([A-Z]\w*)")


def _is_aspnetcore(p: Project) -> bool:
    return bool(re.search(r"Microsoft\.NET\.Sdk\.Web$", p.sdk or "")) or "Microsoft.AspNetCore.App" in p.framework_refs


def hosts_web_via_library(repo: Repo, p: Project) -> bool:
    """A console Exe that starts a Kestrel web host built in a referenced ASP.NET Core library.

    Common shape: a thin launcher (`Executables/X/Program.cs` -> `X.Program.Main(args)` in a
    library) whose library starts `WebApplication.CreateBuilder(...)` in a web-host class from an
    Sdk.Web library. Only the launcher's own code and the library Program it delegates to are
    followed, so a CLI that merely uses DTOs of the web library stays a console app."""
    if p.kind_hint != "dotnet" or (p.output_type or "").lower() != "exe":
        return False
    libs = _closure(repo, p)
    hosts: set[str] = set()
    for lib in libs:
        if not _is_aspnetcore(lib):
            continue
        for f in lib.files:
            if f.suffix.lower() == ".cs":
                t = lib.text(f, True)
                if WEB_HOST_RE.search(t):
                    hosts |= set(TYPE_DECL_RE.findall(t))
    if not hosts:
        return False
    seeds = [p.text(f, True) for f in p.files if f.suffix.lower() == ".cs"]
    for ns in {m.group(1).rstrip(".") for t in list(seeds) for m in DELEGATED_MAIN_RE.finditer(t)}:
        ns_rx = re.compile(rf"\bnamespace\s+{re.escape(ns)}\s*[;{{]")
        for lib in libs:
            for f in lib.files:
                if f.suffix.lower() == ".cs":
                    t = lib.text(f, True)
                    if ns_rx.search(t) and re.search(r"\bclass\s+Program\b", t):
                        seeds.append(t)
    rx = re.compile(r"\b(" + "|".join(sorted(map(re.escape, hosts))) + r")\b")
    return any(rx.search(t) for t in seeds)


def _closure(repo: Repo, p: Project) -> list[Project]:
    """Projects that p references, directly or through other projects, each as compiled for p:
    a multi-targeted library is followed only along the target frameworks its consumer picks
    (NuGet's nearest framework), so a net8.0 app does not inherit the net472-only references or
    project references of a net472;net8.0 library. Libraries used with fewer TFMs than they have
    are returned as per-TFM views (Project.view)."""
    order: list[Path] = []
    active: dict[Path, set[str]] = {}
    projects: dict[Path, Project] = {}
    stack = [(ref, p.tfms) for ref in p.refs_for(p.tfms)]
    while stack:
        ref, consumer = stack.pop()
        q = repo.project_by_path(ref)
        if q is None:
            continue
        key = q.path.resolve()
        tf = set(nearest_tfms(consumer, q.tfms)) if q.kind_hint == "dotnet" else set(q.tfms)
        if key in active:
            if tf <= active[key]:
                continue
            tf |= active[key]
        else:
            order.append(key)
            projects[key] = q
        active[key] = tf
        stack.extend((r, [t for t in q.tfms if t in tf]) for r in q.refs_for(list(tf)))
    return [projects[k].view(list(active[k])) if active[k] else projects[k] for k in order]


def _view_findings(repo: Repo, lib: Project, finding_rules: list[Rule], cache: dict) -> list[Finding]:
    """Findings of a library as compiled for some of its target frameworks (see _closure)."""
    key = (lib.path.resolve(), tuple(lib.tfms))
    if key not in cache:
        ctx = Context(repo, lib, "library")
        cache[key] = [Finding(r, m.evidence) for r in finding_rules
                      if r.scope == "project" and (m := run_rule(r, ctx))]
    return cache[key]


def assess(path: str | Path, rules: list[Rule] | None = None, repo: Repo | None = None) -> AppAssessment:
    from .facts import extract_facts

    rules = rules if rules is not None else load_rules()
    repo = repo or scan(path)
    finding_rules = [r for r in rules if r.phase == "finding"]
    comps: dict[Path, Component] = {}
    for p in repo.projects:
        role, rid = classify_role(repo, p, rules)
        if role == "console" and hosts_web_via_library(repo, p):
            role, rid = "web", "role-web-hosted-library"
        c = Component(project=p, role=role, role_rule=rid)
        ctx = Context(repo, p, role)
        for r in finding_rules:
            if r.scope != "project":
                continue
            m = run_rule(r, ctx)
            if m:
                c.findings.append(Finding(r, m.evidence))
        comps[p.path.resolve()] = c

    # Propagate library findings to the deployables that reference them, but
    # only when the library code that triggered them is reachable.
    view_cache: dict = {}
    for c in comps.values():
        if c.role in NON_DEPLOYABLE:
            continue
        own = {f.rule.id for f in c.findings}
        libs = [lib for lib in _closure(repo, c.project)
                if (lc := comps.get(lib.path.resolve())) is not None and lc.role == "library"]
        reached = {repo.rel(f) for f in reachable_files(c.project, libs)}
        for lib in libs:
            lc = comps[lib.path.resolve()]
            lib_findings = lc.findings if lib.view_of is None else _view_findings(repo, lib, finding_rules, view_cache)
            for f in lib_findings:
                if f.rule.id in own or f.rule.id == "netfx-library" and c.project.is_netfx:
                    continue
                code_ev = [e for e in f.evidence if e.line and Path(e.file).suffix.lower() in CODE_EXT]
                dormant = bool(code_ev) and len(code_ev) == len(f.evidence) and not any(e.file in reached for e in code_ev)
                if not dormant:
                    own.add(f.rule.id)
                c.findings.append(Finding(f.rule, f.evidence, via=lc.name, dormant=dormant))
        # Windows-only code reached only by an optional command of a multi-command tool
        if c.role in ("console", "worker") and any(f.rule.severity in ("blocker", "rewrite") for f in c.findings):
            mr = mode_reachability(c.project, libs)
            if mr:
                shared, per_mode = mr
                for f in c.findings:
                    code_ev = [e for e in f.evidence if e.line and Path(e.file).suffix.lower() in CODE_EXT]
                    if f.dormant or not code_ev or len(code_ev) != len(f.evidence):
                        continue
                    files = {(repo.root / e.file).resolve() for e in code_ev}
                    if files & {x.resolve() for x in shared}:
                        continue
                    modes = [m for m, fs in per_mode.items() if files & {x.resolve() for x in fs}]
                    if modes and len(modes) < len(per_mode):
                        f.modes = modes
        # if the same rule was found both dormant and active, keep the active one
        active = {f.rule.id for f in c.findings if not f.dormant}
        c.findings = [f for f in c.findings if not (f.dormant and f.rule.id in active)]

    for c in comps.values():
        if c.role not in NON_DEPLOYABLE:
            c.facts = extract_facts(repo, c, rules)

    repo_findings = []
    ctx = Context(repo, None)
    for r in finding_rules:
        if r.scope == "repo":
            m = run_rule(r, ctx)
            if m:
                repo_findings.append(Finding(r, m.evidence))

    from .confidence import score_confidence
    for c in comps.values():
        score_confidence(repo, c)

    all_c = sorted(comps.values(), key=lambda c: c.project.rel)
    return AppAssessment(
        repo=repo,
        components=[c for c in all_c if c.role not in NON_DEPLOYABLE],
        libraries=[c for c in all_c if c.role == "library"],
        tests=[c for c in all_c if c.role in ("test", "tool")],
        repo_findings=repo_findings,
    )


def apply_ai(a: AppAssessment, model: str | None = None, threshold: float = 0.85, learn: bool = False) -> list[dict]:
    """Hybrid mode: ask the LLM about the components the rules are unsure of."""
    from .ai import ai_review_component, learn_from_review

    usage = []
    for c in a.components:
        if c.tier not in ("server", "platform") or c.confidence >= threshold:
            continue
        try:
            r = ai_review_component(a, c, model)
        except Exception as e:  # noqa: BLE001
            c.ai = {"error": str(e)}
            continue
        c.ai = {k: r[k] for k in ("verdict", "confidence", "reasoning", "model")}
        if r.get("confidence", 0) >= 0.6 and r["verdict"] != c.rule_verdict:
            c.override = r["verdict"]
        if learn:
            learn_from_review(a, c, r)
        usage.append(r)
    return usage
