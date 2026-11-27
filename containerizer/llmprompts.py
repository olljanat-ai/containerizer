"""The system prompts Containerizer sends to the LLM, shown to administrators and replaceable by them
(docs/bug-reports.md#system-prompts; Admin → Bug reports).

A system prompt says who the LLM is and how it answers, for one kind of question (PROMPTS). An administrator who
sees the LLM go wrong in a repeatable way (it removes what it should keep, it reads a rule too strictly) can
replace a prompt's text: cz.LlmPrompt (schema 65) keeps the replacement, the scan worker and the LLM queue runner
load it before they ask (`apply`, ai.set_system_overrides), and the bug report export carries the replaced prompts,
so the maintainers see what worked better.

The question itself (the evidence, the file, the answer's JSON schema) is not part of a system prompt and cannot
be changed here: an answer must still match its schema.
"""
from __future__ import annotations

MAX_TEXT = 12000


def prompts() -> dict:
    """name -> (title, what it is used for, the built-in text)."""
    from . import ai, egress, links, refactor, replatform
    return {
        "assessment": ("Assessment and build diagnosis", "Component reviews where the rules are unsure, proposals of new "
                       "rules, the diagnosis of a failed build or run, and the tries of bug reports.", ai.SYSTEM),
        "refactor": ("Refactoring patches and Make it A", "Every code change the LLM makes for a refactoring order.",
                     refactor.SYSTEM),
        "egress": ("Egress reviews", "The review of the connections the sandbox blocked.", egress.SYSTEM),
        "links": ("Link reviews", "Which application an internal-looking destination is.", links.SYSTEM),
        "replatform": ("Platform migrations", "Moving containerized applications from another platform, and the "
                       "sandbox tester.", replatform.SYSTEM),
    }


def load(conn) -> dict[str, dict]:
    """name -> {"text", "by", "at"} of the replaced prompts ({} on a database before schema 65)."""
    try:
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT Name, Text, UpdatedBy, UpdatedAt FROM cz.LlmPrompt")
        known = prompts()
        return {r["Name"]: {"text": r["Text"], "by": r.get("UpdatedBy"), "at": r.get("UpdatedAt")}
                for r in cur.fetchall() if r["Name"] in known and (r.get("Text") or "").strip()}
    except Exception:  # noqa: BLE001
        return {}


def apply(conn) -> int:
    """Put the replaced prompts into effect in this process (the scan worker, the queue runner). How many."""
    from . import ai
    known = prompts()
    over = {known[name][2]: o["text"] for name, o in load(conn).items()}
    ai.set_system_overrides(over)
    return len(over)


def save(conn, name: str, text: str, user: str) -> str:
    """Replace a prompt (or, with an empty text or the built-in one, go back to it): "saved", "default" or "bad"."""
    known = prompts()
    if name not in known:
        return "bad"
    text = (text or "").replace("\r\n", "\n").strip()[:MAX_TEXT]
    cur = conn.cursor()
    cur.execute("DELETE FROM cz.LlmPrompt WHERE Name = %s", (name,))
    if not text or text == known[name][2].strip():
        return "default"
    cur.execute("INSERT cz.LlmPrompt (Name, Text, UpdatedBy) VALUES (%s, %s, %s)", (name, text, (user or "")[:200]))
    return "saved"


def section_html(conn, csrf: str, base: str) -> str:
    """The System prompts section of the Bug reports page."""
    from html import escape as e
    over = load(conn)
    out = ["<h2 id='prompts'>System prompts</h2><p class='small'>What Containerizer tells the LLM about its role, for each "
           "kind of question. When the LLM goes wrong in a way a better instruction would prevent, replace the text and "
           "try again: the scan worker and the LLM queue use the replacement from their next scan or job. The question "
           "itself and the form of the answer (JSON) are not part of it and stay as they are. Replaced prompts go into "
           "the bug report export.</p>"]
    for name, (title, used, default) in prompts().items():
        o = over.get(name)
        when = o["at"].strftime("%Y-%m-%d %H:%M") + " UTC" if o and o.get("at") else ""
        state = (f"<b>replaced</b> <span class='muted small'>by {e(o.get('by') or '')} {when}</span>" if o
                 else "<span class='muted small'>built-in</span>")
        back = "<button class='link' name='Reset' value='1'>Back to the built-in text</button>" if o else ""
        builtin = (f"<details><summary class='small'>The built-in text</summary><pre class='code'>{e(default)}</pre></details>"
                   if o else "")
        out.append(f"<details id='prompt-{name}'{' open' if o else ''}><summary><b>{e(title)}</b> {state}</summary>"
                   f"<p class='small muted'>{e(used)}</p>"
                   f"<form method='post' action='{base}/prompts/{name}'>{csrf}"
                   f"<textarea name='Text' rows='10' maxlength='{MAX_TEXT}' spellcheck='false' aria-label='{e(title)}'>"
                   f"{e(o['text'] if o else default)}</textarea><p><button>Save</button> {back}</p></form>{builtin}</details>")
    return "".join(out)
