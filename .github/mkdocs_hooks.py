"""MkDocs hooks for the GitHub Pages site.

Links that point outside docs/ (rules, examples, source files) are rewritten to the repository on GitHub so they
work on the published site as they do when browsing the repository. The site name in the header links
to the front page on every page.
"""

import base64
import hashlib
import posixpath
import re
from pathlib import Path

REPO = "https://github.com/olljanat-ai/containerizer"
ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(\]\()([^)\s]+)(\))")


def _rewrite(target, page_dir):
    if re.match(r"^[a-z][a-z0-9+.-]*:|^#|^/", target):
        return target
    path, _, anchor = target.partition("#")
    repo_path = posixpath.normpath(posixpath.join(page_dir, path))
    if repo_path.startswith("docs/"):
        new = repo_path[len("docs/"):]
    else:
        kind = "tree" if (ROOT / repo_path).is_dir() else "blob"
        return f"{REPO}/{kind}/main/{repo_path}" + (f"#{anchor}" if anchor else "")
    return new + (f"#{anchor}" if anchor else "")


def on_page_markdown(markdown, page, config, files):
    return LINK.sub(lambda m: m.group(1) + _rewrite(m.group(2), "docs") + m.group(3), markdown)


HEADER_NAME = re.compile(r'(<div class="md-header__topic">\s*<span class="md-ellipsis">)\s*([^<]+?)\s*(</span>)')


EXTERNAL_A = re.compile(r'<a\b(?P<pre>[^>]*?)\bhref="(?P<url>https?://[^"]*)"(?P<post>[^>]*)>', re.I)


def _external_links(html, site):
    """Links to other sites open in a new tab or window (noopener); links to this site stay in it."""
    def add(m):
        if (site and m["url"].startswith(site)) or re.search(r"\btarget=", m["pre"] + m["post"], re.I):
            return m[0]
        rel = "" if re.search(r"\brel=", m["pre"] + m["post"], re.I) else ' rel="noopener noreferrer"'
        return f'<a{m["pre"]}href="{m["url"]}"{m["post"]} target="_blank"{rel}>'
    return EXTERNAL_A.sub(add, html)


def _esc(text):
    return (str(text or "").replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;"))


def _preview(page, config):
    """Open Graph and Twitter card tags: a link pasted into an e-mail, Teams or Slack shows "Containerizer" (the
    front page) or "<page> - Containerizer" and the page's description, rather than whatever the client guesses."""
    site = config.get("site_name") or ""
    title = site if page.is_homepage else f"{page.title} - {site}"
    desc = (page.meta or {}).get("description") or config.get("site_description") or ""
    url = (config.get("site_url") or "").rstrip("/") + "/" + (page.url or "")
    tags = [("property", "og:type", "website"), ("property", "og:site_name", site), ("property", "og:title", title),
            ("property", "og:description", desc), ("property", "og:url", url),
            ("name", "twitter:card", "summary"), ("name", "twitter:title", title),
            ("name", "twitter:description", desc)]
    return "".join(f'<meta {k}="{n}" content="{_esc(v)}">' for k, n, v in tags if v)


INLINE_SCRIPT = re.compile(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", re.S | re.I)
INLINE_STYLE = re.compile(r"<style[^>]*>(?P<body>.*?)</style>", re.S | re.I)
# Everything the pages load is the site's own (the privacy plugin self-hosts the fonts); the only other origin is
# the GitHub API, from which the header's repository link reads the star and fork counts. Material's few inline
# scripts (colour scheme, base URL) and its font <style> are allowed by their hashes, so nothing injected runs.
CSP = ("default-src 'none'; script-src 'self' {scripts}; style-src 'self' {styles}; font-src 'self'; img-src 'self' data:; "
       "connect-src 'self' https://api.github.com; worker-src 'self'; manifest-src 'self'; base-uri 'self'; "
       "form-action 'none'; object-src 'none'; upgrade-insecure-requests")


def _hashes(bodies):
    out = dict.fromkeys("'sha256-" + base64.b64encode(hashlib.sha256(b.encode()).digest()).decode() + "'" for b in bodies)
    return " ".join(out)


def _csp(html):
    """A Content-Security-Policy <meta> as the first element of <head>. GitHub Pages sets no response headers of
    our choosing, so the policy travels in the page; frame-ancestors (clickjacking) and HSTS cannot be set this
    way: they need a CDN or host in front of the site that can set response headers."""
    scripts = [m["body"] for m in INLINE_SCRIPT.finditer(html)
               # not external, and not data (the __config JSON) that never runs
               if "src=" not in m["attrs"].lower() and not re.search(r'type="(?!text/javascript|module)', m["attrs"], re.I)]
    styles = [m["body"] for m in INLINE_STYLE.finditer(html)]
    meta = (f'<meta http-equiv="Content-Security-Policy" '
            f'content="{CSP.format(scripts=_hashes(scripts), styles=_hashes(styles))}">')
    return re.sub(r"<head>", lambda m: m[0] + meta, html, count=1, flags=re.I)


def on_post_page(output, page, config):
    # Material shows the site name in the header as plain text; make it a link to the front page.
    home = page.url.count("/") * "../" or "./"
    output = output.replace("</head>", _preview(page, config) + "</head>", 1)
    output = _external_links(output, (config.get("site_url") or "").rstrip("/"))
    output = HEADER_NAME.sub(lambda m: f'{m.group(1)}<a href="{home}" class="cz-home-link">{m.group(2)}</a>{m.group(3)}',
                             output, count=1)
    return _csp(output)


def on_post_template(output, template_name, config):
    # 404.html is served at any path, so it links to the site root.
    if template_name != "404.html":
        return output
    output = HEADER_NAME.sub(lambda m: f'{m.group(1)}<a href="/" class="cz-home-link">{m.group(2)}</a>{m.group(3)}',
                             output, count=1)
    return _csp(output)
