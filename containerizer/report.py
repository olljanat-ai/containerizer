"""Markdown, HTML and JSON reports."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .assess import APP_RATINGS, VERDICT_TEXT, AppAssessment

SEV_ICON = {"info": "·", "config": "⚙", "refactor": "✎", "rewrite": "⟲", "blocker": "⛔"}


def migration_markdown(a: AppAssessment) -> str:
    L = [f"# {a.name}: containerization assessment", "",
         f"**Rating {a.rating}** - {APP_RATINGS[a.rating]}  ",
         f"Readiness score {a.score}/100 · estimated effort {a.effort} person-days · confidence {a.confidence}", "",
         a.summary(), ""]
    tb = a.top_blockers()
    if tb:
        L += ["## Main obstacles", ""]
        for b in tb:
            L.append(f"- **{b['title']}** ({b['severity']}): {', '.join(b['components'])}")
        L.append("")
    L += ["## Components", "", "| Component | Role | Target | Verdict | Score | Effort (d) | Windows container stop-gap |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for c in a.components:
        L.append(f"| {c.name} | {c.role} | {';'.join(c.project.tfms) or c.project.kind_hint} | {VERDICT_TEXT[c.verdict]} | "
                 f"{c.score} | {c.effort} | {'yes' if c.windows_container_ok and c.project.is_netfx else '-'} |")
    L.append("")
    for c in a.components:
        L += [f"### {c.name}", "", f"`{c.project.rel}` · {c.role} · {VERDICT_TEXT[c.verdict]}", ""]
        facts = {k: v for k, v in c.facts.items() if k in ("port", "health", "entry", "writable_dirs", "connection_strings")}
        if facts:
            L.append("Facts: " + "; ".join(f"{k}={v}" for k, v in facts.items()))
            L.append("")
        for f in sorted(c.findings, key=lambda f: ["blocker", "rewrite", "refactor", "config", "info"].index(f.severity)):
            if f.severity == "info" and not f.dormant:
                continue
            via = f" (in library {f.via}{', not referenced by this component' if f.dormant else ''})" if f.via else ""
            L.append(f"- {SEV_ICON[f.severity]} **{f.rule.title}** [{f.severity}]{via}")
            L.append(f"  - Why: {' '.join(f.rule.why.split())}")
            L.append(f"  - Fix: {' '.join(f.rule.fix.split())}")
            if f.evidence:
                L.append(f"  - Evidence: `{f.evidence[0]}`")
        if c.uncertain:
            L.append(f"- ? Unknown to the rule set: {', '.join(c.uncertain[:8])}")
        L.append("")
    other = [c for c in a.libraries if any(f.severity in ("blocker", "rewrite") for f in c.findings)]
    if other:
        L += ["## Libraries with notable findings", ""]
        for c in other:
            L.append(f"- {c.name}: " + ", ".join(sorted({f.rule.title for f in c.findings if f.severity in ('blocker', 'rewrite', 'refactor')})))
        L.append("")
    return "\n".join(L)


def portfolio_markdown(results: list[AppAssessment]) -> str:
    L = ["# Containerization portfolio", "",
         "| App | Rating | Score | Effort (d) | Confidence | Summary |", "| --- | --- | --- | --- | --- | --- |"]
    for a in sorted(results, key=lambda a: (a.rating, -a.score)):
        L.append(f"| {a.name} | {a.rating} | {a.score} | {a.effort} | {a.confidence} | {a.summary()} |")
    L += ["", "Ratings: " + "; ".join(f"**{k}** {v}" for k, v in APP_RATINGS.items())]
    return "\n".join(L) + "\n"


def portfolio_html(results: list[AppAssessment]) -> str:
    e = html.escape
    rows = []
    for a in sorted(results, key=lambda a: (a.rating, -a.score)):
        comps = []
        for c in a.components:
            items = "".join(
                f"<li class='{f.severity}'><b>{e(f.rule.title)}</b> <span class='sev'>{f.severity}</span>"
                f"{' <i>via ' + e(f.via) + '</i>' if f.via else ''}<br><small>{e(' '.join(f.rule.why.split()))}</small>"
                f"<br><small class='fix'>Fix: {e(' '.join(f.rule.fix.split()))}</small></li>"
                for f in c.findings if f.severity != "info")
            comps.append(f"<tr><td>{e(c.name)}</td><td>{c.role}</td><td>{e(';'.join(c.project.tfms))}</td>"
                         f"<td class='v-{c.verdict}'>{e(VERDICT_TEXT[c.verdict])}</td><td>{c.score}</td>"
                         f"<td><details><summary>{sum(1 for f in c.findings if f.severity != 'info')} findings</summary><ul>{items}</ul></details></td></tr>")
        rows.append(f"""<details class='app'><summary><span class='r r{a.rating}'>{a.rating}</span> <b>{e(a.name)}</b>
<span class='meta'>score {a.score} · {a.effort} d · confidence {a.confidence}</span><br><small>{e(a.summary())}</small></summary>
<table><tr><th>Component</th><th>Role</th><th>Target</th><th>Verdict</th><th>Score</th><th>Findings</th></tr>{''.join(comps)}</table></details>""")
    legend = "".join(f"<li><span class='r r{k}'>{k}</span> {e(v)}</li>" for k, v in APP_RATINGS.items())
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Containerization portfolio</title><style>
:root{{--bg:#fff;--fg:#1d1d1f;--muted:#666;--line:#e3e3e3}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16171a;--fg:#e8e8ea;--muted:#a0a0a8;--line:#33343a}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px}}
.app{{border-bottom:1px solid var(--line);padding:10px 0}} summary{{cursor:pointer}} .meta,small{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;margin-top:8px;font-size:14px}} td,th{{border-top:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}}
.r{{display:inline-block;width:1.6em;text-align:center;border-radius:4px;color:#fff;font-weight:700}}
.rA{{background:#2e7d32}}.rB{{background:#689f38}}.rC{{background:#f9a825}}.rD{{background:#ef6c00}}.rE{{background:#c62828}}
.v-blocker{{color:#c62828}}.v-rewrite{{color:#ef6c00}}.v-refactor{{color:#b28704}}.v-config,.v-info{{color:#2e7d32}}
li.blocker b{{color:#c62828}} .sev{{font-size:12px;color:var(--muted)}} ul{{padding-left:18px}} .fix{{display:block}}
</style></head><body><h1>Containerization portfolio</h1><ul>{legend}</ul>{''.join(rows)}</body></html>"""


def write_reports(results: list[AppAssessment], out: Path, fmt: str = "md,html,json") -> None:
    out.mkdir(parents=True, exist_ok=True)
    fmts = set(fmt.split(","))
    if "md" in fmts:
        (out / "portfolio.md").write_text(portfolio_markdown(results))
        for a in results:
            (out / f"{a.name}.md").write_text(migration_markdown(a))
    if "html" in fmts:
        (out / "portfolio.html").write_text(portfolio_html(results))
    if "json" in fmts:
        (out / "assessment.json").write_text(json.dumps([a.to_dict() for a in results], indent=2, default=str))
