"""Where containerizer keeps its scratch space (builds, verification runs, the image scanner's cache)."""
from __future__ import annotations

import os
from pathlib import Path


def work_dir(env: dict | None = None) -> Path:
    """CONTAINERIZER_WORK; else .work next to the code when that is writable (a checkout); else the user's cache
    (~/.cache/containerizer/work, or $XDG_CACHE_HOME). The code of an installed package, such as the appliance's
    read-only OS image, is never written to."""
    env = os.environ if env is None else env
    if env.get("CONTAINERIZER_WORK"):
        return Path(env["CONTAINERIZER_WORK"])
    repo = Path(__file__).resolve().parent.parent
    if os.access(repo, os.W_OK) and (not (repo / ".work").exists() or os.access(repo / ".work", os.W_OK)):
        return repo / ".work"
    return Path(env.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "containerizer" / "work"
