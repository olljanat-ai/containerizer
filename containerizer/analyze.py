"""One-shot analysis of a repository, for runs where accuracy matters more than time:
assess -> (Claude for uncertain parts) -> build and run every feasible component ->
learn -> re-assess with what was learned -> write deliverables.

What the run learns is used by this run only and proposed for review (rulereview.LearningSession);
it enters the ruleset when a person approves it."""
from __future__ import annotations

from pathlib import Path

from .assess import AppAssessment, apply_ai, assess
from .rules import load_rules


def analyze_app(path: Path, out: Path, ai: bool = False, model: str | None = None, verify: bool = True,
                registry: str = "registry.local", pin: bool = False, timeout: int = 1800, gitops=None,
                sql: str | None = None) -> AppAssessment:
    from .confidence import reset_cache
    from .generate import generate_app
    from .rulereview import LearningSession
    from .verify import verify_app

    with LearningSession(source_path=path, ai=ai, model=model, sql=sql) as learning:
        a = assess(path, load_rules())
        if ai:
            apply_ai(a, model)
        ver = verify_app(a, out / a.name / "verify", learn=True, ai=ai, model=model, timeout=timeout) if verify else []
        learning.app = a.name
        learning.add_results(ver)
        # runtime findings and learned plan rules feed back into the final assessment
        reset_cache()
        rules = load_rules()
        a = assess(path, rules)
        if ai:
            apply_ai(a, model)
        a.verification = ver
        generate_app(a, out / a.name, rules, registry=registry, pin=pin, gitops=gitops)
    return a
