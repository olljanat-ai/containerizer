"""Turns scanned facts + rules into an assessment per component and per application."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .rules import SEV_RANK, SEVERITIES, Context, Match, Rule, load_rules, run_rule
from .reach import CODE_EXT, reachable_files
from .scan import Project, Repo, scan

SERVER_ROLES = {"web", "worker", "console", "spa"}
PLATFORM_ROLES = {"biztalk", "sharepoint"}          # deployables that need a Windows product
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
    "A": "Lift and shift - containers with configuration only",
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

    @property
    def severity(self) -> str:
        return "info" if self.dormant else self.rule.severity

    def to_dict(self) -> dict:
        r = self.rule
        return {"id": r.id, "severity": r.severity, "category": r.category, "title": r.title,
                "why": " ".join(r.why.split()), "fix": " ".join(r.fix.split()), "effort_days": r.effort,
                "via": self.via, "dormant": self.dormant, "evidence": [str(e) for e in self.evidence[:3]], "source": r.source,
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

    @property
    def name(self) -> str:
        return self.project.assembly_name or self.project.name

    @property
    def verdict(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=lambda s: SEV_RANK[s])

    @property
    def effort(self) -> float:
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
            base -= min(25, int(self.effort * 1.5))
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
                "score": self.score, "effort_days": self.effort, "windows_container_ok": self.windows_container_ok,
                "confidence": round(self.confidence, 2), "uncertain": self.uncertain,
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
        return {"info": "A", "config": "A", "refactor": "B", "rewrite": "C"}[worst]

    @property
    def score(self) -> int:
        server = self.server()
        if not server:
            return 0
        return round(sum(c.score for c in server) / len(server))

    @property
    def effort(self) -> float:
        return round(sum(c.effort for c in self.server() if c.verdict != "blocker"), 1)

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
            parts.append(f"{len(by['rewrite'])} need a port to .NET 8 or a rewrite")
        if by.get("blocker"):
            parts.append(f"{len(by['blocker'])} cannot run in Linux containers ({', '.join(by['blocker'])})")
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

    def to_dict(self) -> dict:
        return {"name": self.name, "rating": self.rating, "rating_text": APP_RATINGS[self.rating],
                "score": self.score, "effort_days": self.effort, "confidence": self.confidence,
                "summary": self.summary(), "top_blockers": self.top_blockers(),
                "components": [c.to_dict() for c in self.components],
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


def _closure(repo: Repo, p: Project) -> list[Project]:
    out, stack, seen = [], list(p.project_refs), set()
    while stack:
        ref = stack.pop()
        if ref in seen:
            continue
        seen.add(ref)
        q = repo.project_by_path(ref)
        if q is not None:
            out.append(q)
            stack.extend(q.project_refs)
    return out


def assess(path: str | Path, rules: list[Rule] | None = None, repo: Repo | None = None) -> AppAssessment:
    from .facts import extract_facts

    rules = rules if rules is not None else load_rules()
    repo = repo or scan(path)
    finding_rules = [r for r in rules if r.phase == "finding"]
    comps: dict[Path, Component] = {}
    for p in repo.projects:
        role, rid = classify_role(repo, p, rules)
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
    for c in comps.values():
        if c.role in NON_DEPLOYABLE:
            continue
        own = {f.rule.id for f in c.findings}
        libs = [lib for lib in _closure(repo, c.project)
                if (lc := comps.get(lib.path.resolve())) is not None and lc.role == "library"]
        reached = {repo.rel(f) for f in reachable_files(c.project, libs)}
        for lib in libs:
            lc = comps[lib.path.resolve()]
            for f in lc.findings:
                if f.rule.id in own or f.rule.id == "netfx-library" and c.project.is_netfx:
                    continue
                code_ev = [e for e in f.evidence if e.line and Path(e.file).suffix.lower() in CODE_EXT]
                dormant = bool(code_ev) and len(code_ev) == len(f.evidence) and not any(e.file in reached for e in code_ev)
                if not dormant:
                    own.add(f.rule.id)
                c.findings.append(Finding(f.rule, f.evidence, via=lc.name, dormant=dormant))
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
