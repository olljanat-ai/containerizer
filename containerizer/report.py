"""Markdown, HTML and JSON reports."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

from .assess import APP_RATINGS, VERDICT_TEXT, AppAssessment

SEV_ICON = {"info": "·", "config": "⚙", "refactor": "✎", "rewrite": "⟲", "blocker": "⛔"}


def ref_label(url: str) -> str:
    """Short link text: "dotnet/runtime#123", "learn.microsoft.com: Kestrel endpoints"."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/(?:issues|pull|discussions)/(\d+)", url)
    if m:
        return f"{m[1]}#{m[2]}"
    m = re.match(r"https?://(?:www\.)?([^/]+)(/[^?#]*)?", url)
    if not m:
        return url
    tail = [p for p in (m[2] or "").split("/") if p and not re.fullmatch(r"[a-z]{2}-[a-z]{2}|\d[\d.]*", p)]
    return m[1] + (": " + tail[-1].replace("-", " ").removesuffix(".md").removesuffix(".html") if tail else "")


def refs_of(f) -> list[str]:
    """References of a finding (rule object) or of a finding dict."""
    r = f.get("refs") if isinstance(f, dict) else getattr(getattr(f, "rule", f), "refs", None)
    return [u for u in (r or []) if isinstance(u, str) and u.startswith(("http://", "https://"))]


def refs_md(refs: list[str]) -> str:
    return ", ".join(f"[{ref_label(u)}]({u})" for u in refs)


def migration_markdown(a: AppAssessment) -> str:
    L = [f"# {a.name}: containerization assessment", "",
         f"**Rating {a.rating}** - {APP_RATINGS[a.rating]}  ",
         f"Readiness score {a.score}/100 · estimated effort {a.effort} person-days · confidence {a.confidence}  ",
         "Stateless: " + ("yes" if not a.stateful() else "no - " + "; ".join(
             f"{c.name}: {', '.join(sorted({f.rule.title for f in c.state_findings}))}" for c in a.stateful())), "",
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
            if f.modes:
                via += f" (only the {', '.join('`' + m + '`' for m in f.modes)} command; other commands run on Linux)"
            L.append(f"- {SEV_ICON[f.severity]} **{f.rule.title}** [{f.severity}]{via}")
            L.append(f"  - Why: {' '.join(f.rule.why.split())}")
            L.append(f"  - Fix: {' '.join(f.rule.fix.split())}")
            if refs_of(f):
                L.append(f"  - Learn more: {refs_md(refs_of(f))}")
            if f.evidence:
                L.append(f"  - Evidence: `{f.evidence[0]}`")
        if c.uncertain:
            L.append(f"- ? Unknown to the rule set: {', '.join(c.uncertain[:8])}")
        L.append("")
    ver = getattr(a, "verification", None)
    if ver:
        L += ["## Build-and-run verification", "",
              "Each feasible component was built from the generated Dockerfile and run hardened "
              "(read-only root filesystem, non-root, no capabilities).", "",
              "| Component | Result | Attempts |", "| --- | --- | --- |"]
        text = {"ok": "runs", "ok-external": "runs; stops only at missing external services",
                "finding": "runtime finding", "build-failed": "build failed", "run-failed": "run failed"}
        for r in ver:
            if r["status"] == "skipped":
                continue
            res = text.get(r["status"], r["status"])
            if r.get("mode") == "smoke" or r.get("smoke") == "ok":
                res += " (proven in Development mode without production services)"
            if r.get("finding"):
                res += f": {r['finding'].get('title', '')}"
            L.append(f"| {r['component']} | {res} | {r.get('detail', '')} |")
        L.append("")
        for r in ver:
            f = r.get("finding")
            if not f:
                continue
            L.append(f"- **{r['component']}: {f.get('title', '')}** [{f.get('severity', '')}]")
            if f.get("why"):
                L.append(f"  - Why: {' '.join(f['why'].split())}")
            if f.get("fix"):
                L.append(f"  - Fix: {' '.join(f['fix'].split())}")
            if refs_of(f):
                L.append(f"  - Learn more: {refs_md(refs_of(f))}")
        if any(r.get("finding") for r in ver):
            L.append("")
    plans = a.migration_plans()
    if plans:
        from .migrate import plan_markdown, prompt_filename
        L += ["## Migration assistant", "",
              "Concrete replacements for what keeps each component out of a Linux container, with effort estimates "
              "(rules/migrations.yaml). Each component that can be changed also gets a ready-to-use prompt for an "
              f"AI coding agent: `agent-prompts/{prompt_dir(a.name)}/<component>.md` next to this report.", ""]
        for plan in plans.values():
            L += plan_markdown(plan)
            if plan.get("prompt"):
                L += [f"AI agent prompt: `agent-prompts/{prompt_dir(a.name)}/{prompt_filename(plan['component'])}`", ""]
    other = [c for c in a.libraries if any(f.severity in ("blocker", "rewrite") for f in c.findings)]
    if other:
        L += ["## Libraries with notable findings", ""]
        for c in other:
            L.append(f"- {c.name}: " + ", ".join(sorted({f.rule.title for f in c.findings if f.severity in ('blocker', 'rewrite', 'refactor')})))
        L.append("")
    return "\n".join(L)


def prompt_dir(app: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", app).strip("-") or "app"


def write_agent_prompts(a: AppAssessment, out: Path) -> list[Path]:
    """agent-prompts/<app>/<component>.md: the AI coding agent prompt of every component that has one."""
    from .migrate import prompt_filename
    written = []
    for plan in a.migration_plans().values():
        if plan.get("prompt"):
            f = out / "agent-prompts" / prompt_dir(a.name) / prompt_filename(plan["component"])
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(plan["prompt"])
            written.append(f)
    return written


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
                f"<br><small class='fix'>Fix: {e(' '.join(f.rule.fix.split()))}</small>"
                + ("<br><small>Learn more: " + ", ".join(f"<a href='{e(u)}'>{e(ref_label(u))}</a>" for u in refs_of(f))
                   + "</small>" if refs_of(f) else "") + "</li>"
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
            write_agent_prompts(a, out)
    if "html" in fmts:
        (out / "portfolio.html").write_text(portfolio_html(results))
    if "json" in fmts:
        docs = [{**a.to_dict(), **({"verification": a.verification} if getattr(a, "verification", None) else {})}
                for a in results]
        (out / "assessment.json").write_text(json.dumps(docs, indent=2, default=str))
