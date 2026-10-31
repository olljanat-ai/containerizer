"""MkDocs hooks for the GitHub Pages site.

The README is the home page (generated as index.md, so it is not duplicated under docs/), and links that
point outside docs/ (rules, examples, source files) are rewritten to the repository on GitHub so they
work on the published site as they do when browsing the repository.
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
    files.append(File.generated(config, "index.md", content=readme))
    return files


def _rewrite(target, page_dir):
    if re.match(r"^[a-z][a-z0-9+.-]*:|^#|^/", target):
        return target
    path, _, anchor = target.partition("#")
    repo_path = posixpath.normpath(posixpath.join(page_dir, path))
    if repo_path == "README.md":
        new = "index.md"
    elif repo_path.startswith("docs/"):
        new = repo_path[len("docs/"):]
    else:
        kind = "tree" if (ROOT / repo_path).is_dir() else "blob"
        return f"{REPO}/{kind}/main/{repo_path}" + (f"#{anchor}" if anchor else "")
    return new + (f"#{anchor}" if anchor else "")


def on_page_markdown(markdown, page, config, files):
    # README lives at the repository root, the other pages under docs/.
    page_dir = "" if page.file.src_uri == "index.md" else "docs"
    if not page_dir:
        page.edit_url = f"{REPO}/edit/main/README.md"
    return LINK.sub(lambda m: m.group(1) + _rewrite(m.group(2), page_dir) + m.group(3), markdown)
