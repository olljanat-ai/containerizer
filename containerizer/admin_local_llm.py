"""The built-in LLM section of Admin → Source control & LLM: administrators only, on the appliance only.

Shows what the system agent last published (/run/containerizer/system/local-llm-status.json: state, download
progress, the machine's RAM and free disk, how the server is sized) and turns the built-in LLM on or off by
dropping a request (action `local-llm`) for the agent, which checks everything again (local_llm.py). Plain
POST forms with the session's CSRF token, post/redirect/get with ?msg=.
"""
from __future__ import annotations

import json
from urllib.parse import urlencode

from . import local_llm as L
from .admin import Response, e, page, redirect

GiB = L.GiB
BACK = "/admin/source-control"
STATE_TEXT = {"off": ("Off", "st-off"), "refused": ("Off: not enough resources", "st-bad"),
              "downloading": ("Downloading the model", "st-run"), "verifying": ("Checking the download", "st-run"),
              "download-failed": ("Download failed", "st-bad"), "starting": ("Loading the model", "st-run"),
              "running": ("Running", "st-ok"), "error": ("Problem", "st-bad")}


def available(adm, a) -> bool:
    return bool(getattr(a, "admin", False) and getattr(adm, "system", None))


def load_status(adm) -> dict:
    try:
        d = json.loads((adm.system.status_dir / "local-llm-status.json").read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def pending(adm) -> bool:
    return any(r.get("action") == "local-llm" for r in adm.system.pending())


def _back(msg: str) -> Response:
    return redirect(BACK + "?" + urlencode({"msg": msg}) + "#built-in-llm")


def post(adm, s, a, form: dict) -> Response:
    """POST /admin/source-control/local-llm: do=enable|disable|remove-model."""
    if not available(adm, a):
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    do = form.get("do", [""])[0]
    if do not in L.ACTIONS:
        return _back("Choose to turn the built-in LLM on or off.")
    if pending(adm):
        return _back("The previous change of the built-in LLM is still being applied. Try again in a moment.")
    st = load_status(adm)
    if do == "remove-model":
        if st.get("enabled"):
            return _back("Turn the built-in LLM off before removing its model file.")
        if form.get("confirm", [""])[0] != "yes":
            return _back("Tick the box to confirm: turning the built-in LLM on again downloads 16 GB.")
    adm.system.request("local-llm", s.user, s.name, do=do)
    return _back({"enable": "Built-in LLM: turning on. The appliance checks its RAM and disk, downloads the model if it is "
                            "not there yet (16 GB, from Hugging Face) and starts it; this page shows the progress.",
                  "disable": "Built-in LLM: turning off. The model file stays, so turning it on again is quick.",
                  "remove-model": "Built-in LLM: removing the model file."}[do])


def _gb(n) -> str:
    return f"{(n or 0) / 1e9:.1f} GB"


def _gib(n) -> str:
    return f"{(n or 0) / GiB:.1f} GiB"


def section(adm, s, a, registered: bool) -> str:
    """The HTML of the section ('' off the appliance or for anyone but an administrator)."""
    if not available(adm, a):
        return ""
    st = load_status(adm)
    on = bool(st.get("enabled"))
    state = st.get("state") or ("off" if not st else "error")
    if state == "starting" and L.server_health(timeout=1.0):
        state = "running"                       # loaded since the agent last looked
    busy = pending(adm)
    text, css = ("Applying the change", "st-run") if busy else STATE_TEXT.get(state, ("Unknown", "st-off"))
    req = st.get("requirements") or {}
    plan = st.get("plan") or req.get("plan") or {}
    model = st.get("model") or {}
    lines = [f"<div><span class='label'>State</span> <span class='st {css}'>{e(text)}</span>"
             + (f" <span class='muted small'>{e(st['message'])}</span>" if st.get("message") else "") + "</div>"]
    if not st:
        lines.append("<div class='muted small'>The system agent has not reported yet (it does within 5 minutes of a "
                     "start).</div>")
    if state in ("downloading", "verifying"):
        d = st.get("download") or {}
        got, total = int(d.get("bytes") or 0), int(d.get("total") or L.MODEL.size)
        lines.append(f"<div><span class='label'>Download</span> <progress max='{total}' value='{min(got, total)}'></progress> "
                     f"{_gb(got)} of {_gb(total)} ({100 * got // max(total, 1)}%)</div>")
    lines.append(f"<div><span class='label'>Model</span> {e(L.MODEL.alias)} <span class='muted small'>{e(L.MODEL.file)}, "
                 f"{_gb(L.MODEL.size)}, sha256 {e(L.MODEL.sha256[:16])}…"
                 + (", on the disk and checked" if model.get("verified") else "") + "</span></div>")
    if req:
        lines.append(f"<div><span class='label'>This machine</span> {_gib(req.get('ram'))} RAM (needs 40 GiB), "
                     f"{_gib(req.get('free_disk'))} free on the persistent partition"
                     + (f" (the download needs {_gib(req.get('need_disk'))})" if req.get("need_disk") else "") + "</div>")
    if plan:
        lines.append(f"<div><span class='label'>Sized as</span> {int(plan.get('slots') or 1)} answer slot(s) of "
                     f"{L.CTX_PER_SLOT:,} tokens, memory limit {e(str(plan.get('memory') or ''))}</div>")
    if on and registered:
        lines.append("<div class='note'>Not used while an LLM is set above: scans ask that one. Remove it to use the "
                     "built-in LLM.</div>")
    elif on and state in L.USABLE:
        lines.append(f"<div><span class='label'>Used by</span> scans with <i>Ask the LLM</i> on (model "
                     f"<code>{e(L.MODEL.alias)}</code> at <code>{e(L.BASE_URL)}</code>)</div>")
    problems = req.get("problems") or []
    if not on and problems:
        lines.append("<div class='note'>Cannot be turned on: " + e("; ".join(problems)) + ".</div>")
    csrf = adm._csrf(s)
    if on:
        buttons = (f"<form method='post' action='{BACK}/local-llm' class='inline'>{csrf}"
                   "<input type='hidden' name='do' value='disable'><button class='secondary'>Turn off</button></form>")
        if state == "download-failed":
            buttons += (f" <form method='post' action='{BACK}/local-llm' class='inline'>{csrf}"
                        "<input type='hidden' name='do' value='enable'><button>Try again</button></form>")
    else:
        dis = " disabled" if problems or busy else ""
        buttons = (f"<form method='post' action='{BACK}/local-llm' class='inline'>{csrf}"
                   f"<input type='hidden' name='do' value='enable'><button{dis}>Turn on</button></form>")
        if model.get("on_disk"):
            buttons += (f" <form method='post' action='{BACK}/local-llm' class='inline'>{csrf}"
                        "<input type='hidden' name='do' value='remove-model'><label class='check small'>"
                        "<input type='checkbox' name='confirm' value='yes'> remove the model file "
                        f"({_gb(model['on_disk'])})</label><button class='secondary'>Remove</button></form>")
    hist = st.get("history") or []
    hist_html = ("<details><summary>Changes</summary><table class='audit'><thead><tr><th>When</th><th>Who</th><th>What</th>"
                 "</tr></thead><tbody>" + "".join(
                     f"<tr><td class='small'>{e(str(h.get('at') or ''))}</td><td>{e(h.get('name') or h.get('by') or '')}</td>"
                     f"<td class='small'>{e(str(h.get('action') or ''))}: {e(str(h.get('result') or ''))}</td></tr>"
                     for h in hist[:30]) + "</tbody></table></details>") if hist else ""
    return f"""<h2 id='built-in-llm'>Built-in LLM (this appliance)</h2>
<p class='muted'>For sites without an LLM server of their own: the appliance runs Qwen3-Coder 30B-A3B (a 16 GB
CPU-friendly build) with llama.cpp on its own CPU, on <code>127.0.0.1:{L.PORT}</code> only. Scans with <i>Ask the LLM</i>
use it when no LLM is set above. It is slow: about 7 to 12 tokens per second on a 22-core server, a few minutes per
answer, so use the queued LLM mode for organization scans where it is offered, and leave LLM-heavy mode off. It needs a
machine with at least 40 GiB of RAM and about 20 GB of free disk. Turning it on downloads the model once from Hugging
Face, pinned by commit and checksum; huggingface.co and hf.co are allowed on the Firewall page only while it downloads.
Off by default.</p>
<div class='meta'>{''.join(lines)}</div><p>{buttons}</p>{hist_html}"""
