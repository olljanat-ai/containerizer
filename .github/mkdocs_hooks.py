"""MkDocs hooks for the GitHub Pages site.

The README is the Overview page (generated as overview.md, so it is not duplicated under docs/), and links that
point outside docs/ (rules, examples, source files) are rewritten to the repository on GitHub so they
work on the published site as they do when browsing the repository. The site name in the header links
to the front page on every page.
"""

import posixpath
import re
from pathlib import Path

from mkdocs.structure.files import File

REPO = "https://github.com/olljanat-ai/containerizer"
ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(\]\()([^)\s]+)(\))")


def on_files(files, config):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    files.append(File.generated(config, "overview.md", content=readme))
    return files


def _rewrite(target, page_dir):
    if re.match(r"^[a-z][a-z0-9+.-]*:|^#|^/", target):
        return target
    path, _, anchor = target.partition("#")
    repo_path = posixpath.normpath(posixpath.join(page_dir, path))
    if repo_path == "README.md":
        new = "overview.md"
    elif repo_path.startswith("docs/"):
        new = repo_path[len("docs/"):]
    else:
        kind = "tree" if (ROOT / repo_path).is_dir() else "blob"
        return f"{REPO}/{kind}/main/{repo_path}" + (f"#{anchor}" if anchor else "")
    return new + (f"#{anchor}" if anchor else "")


def on_page_markdown(markdown, page, config, files):
    # README lives at the repository root, the other pages under docs/.
    page_dir = "" if page.file.src_uri == "overview.md" else "docs"
    if not page_dir:
        page.edit_url = f"{REPO}/edit/main/README.md"
    return LINK.sub(lambda m: m.group(1) + _rewrite(m.group(2), page_dir) + m.group(3), markdown)


HEADER_NAME = re.compile(r'(<div class="md-header__topic">\s*<span class="md-ellipsis">)\s*([^<]+?)\s*(</span>)')


def on_post_page(output, page, config):
    # Material shows the site name in the header as plain text; make it a link to the front page.
    home = page.url.count("/") * "../" or "./"
    return HEADER_NAME.sub(lambda m: f'{m.group(1)}<a href="{home}" class="cz-home-link">{m.group(2)}</a>{m.group(3)}',
                           output, count=1)


def on_post_template(output, template_name, config):
    # 404.html is served at any path, so it links to the site root.
    if template_name != "404.html":
        return output
    return HEADER_NAME.sub(lambda m: f'{m.group(1)}<a href="/" class="cz-home-link">{m.group(2)}</a>{m.group(3)}',
                           output, count=1)
