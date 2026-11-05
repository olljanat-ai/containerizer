"""Light or dark: the web UI follows the system setting (prefers-color-scheme) until a person picks one with the
button in the top right corner; the choice is kept in that browser (localStorage `cz-theme`).

The stylesheet keeps its dark rules in `@media (prefers-color-scheme:dark)` blocks; `themed` turns each into the
same rules for `html:not([data-theme=light])` inside the media query (the system's choice, unless light was picked)
and for `html[data-theme=dark]` outside it (dark picked). /static/theme.js sets `data-theme` on <html> from the
head, before the page is drawn, and flips it on a click. With no script, the pages follow the system as before.
"""
import re

DARK_MEDIA = re.compile(r"@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)\s*\{")
FOLLOW, CHOSEN = "html:not([data-theme=light])", "html[data-theme=dark]"


def _block(css: str, start: int) -> int:
    """The index just after the brace that closes the block opened at css[start - 1]."""
    depth = 1
    i = start
    while depth and i < len(css):
        depth += {"{": 1, "}": -1}.get(css[i], 0)
        i += 1
    return i


def _scoped(rules: str, prefix: str) -> str:
    out, i = [], 0
    while i < len(rules):
        j = rules.find("{", i)
        if j < 0:
            break
        end = _block(rules, j + 1)
        sels = []
        for sel in rules[i:j].split(","):
            sel = sel.strip()
            m = re.match(r"(:root|html)\b", sel)
            sels.append(prefix + sel[m.end():] if m else f"{prefix} {sel}")
        out.append(",".join(sels) + rules[j:end])
        i = end
    return "".join(out)


def themed(css: str) -> str:
    out, i = [], 0
    for m in DARK_MEDIA.finditer(css):
        if m.start() < i:
            continue
        end = _block(css, m.end())
        rules = css[m.end():end - 1]
        out.append(css[i:m.start()])
        out.append(m.group(0) + _scoped(rules, FOLLOW) + "}" + _scoped(rules, CHOSEN))
        i = end
    out.append(css[i:])
    return "".join(out) + "\nhtml[data-theme=light]{color-scheme:light}html[data-theme=dark]{color-scheme:dark}\n"


JS = """// light or dark: theme.py (loaded in <head>: applies the stored choice before the page is drawn)
(function () {
  var KEY = 'cz-theme', d = document.documentElement, mq = window.matchMedia('(prefers-color-scheme: dark)');
  try { var t = localStorage.getItem(KEY); if (t === 'light' || t === 'dark') d.setAttribute('data-theme', t); } catch (e) {}
  function dark() { var t = d.getAttribute('data-theme'); return t ? t === 'dark' : mq.matches; }
  function label() {
    var x = dark();
    document.querySelectorAll('[data-theme-toggle]').forEach(function (b) {
      b.hidden = false;
      b.textContent = x ? '\u2600' : '\u263E';
      b.title = x ? 'Switch to light mode' : 'Switch to dark mode';
      b.setAttribute('aria-label', b.title);
    });
  }
  document.addEventListener('click', function (ev) {
    var b = ev.target.closest && ev.target.closest('[data-theme-toggle]');
    if (!b) return;
    var t = dark() ? 'light' : 'dark';
    d.setAttribute('data-theme', t);
    try { localStorage.setItem(KEY, t); } catch (e) {}
    label();
  });
  document.addEventListener('DOMContentLoaded', label);
  if (mq.addEventListener) mq.addEventListener('change', label);
})();
"""

# hidden until the script shows it (a page without the script follows the system)
BUTTON = "<button type='button' class='theme-toggle' data-theme-toggle hidden aria-label='Light or dark mode'>&#9790;</button>"
CSS = (".theme-toggle{background:none;border:1px solid var(--line);color:var(--fg);border-radius:999px;width:30px;"
       "height:30px;padding:0;font-size:15px;line-height:28px;cursor:pointer;vertical-align:middle;margin-left:8px}"
       ".theme-toggle:hover{border-color:var(--muted)}\n")
