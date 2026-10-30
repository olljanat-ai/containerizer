"""Facts needed to build and run a component: entrypoint, ports, health path,
configuration keys to externalize and folders it writes to."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .rules import Context, Rule, run_rule

FOLDER_KEY = re.compile(r"(folder|path|dir|directory|root|location|store|share|inbox|outbox|archive)$", re.I)
SECRET_KEY = re.compile(r"(password|secret|apikey|api_key|clientsecret|token|connectionstring|key)$", re.I)


def _load_json(p: Path) -> dict:
    try:
        txt = p.read_text(encoding="utf-8-sig", errors="replace")
        txt = re.sub(r"^\s*//.*$", "", txt, flags=re.M)        # appsettings allow comments
        txt = re.sub(r",(\s*[}\]])", r"\1", txt)                # and trailing commas
        return json.loads(txt)
    except (OSError, ValueError):
        return {}


def _flatten(d, prefix=""):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _flatten(v, f"{prefix}{k}:" if prefix or True else k)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            yield from _flatten(v, f"{prefix}{i}:")
    else:
        yield prefix.rstrip(":"), d


def extract_facts(repo, comp, rules: list[Rule]) -> dict:
    p = comp.project
    facts: dict = {}
    ctx = Context(repo, p, comp.role)
    for r in sorted((r for r in rules if r.phase == "facts"), key=lambda r: -r.priority):
        m = run_rule(r, ctx)
        if not m:
            continue
        caps = {re.sub(r"\d+$", "", k): v for k, v in m.captures.items()}
        for k, v in list(caps.items()) + list(r.set.items()):
            facts.setdefault(k, v)
    if "port" in facts:
        facts["port"] = int(facts["port"])

    facts["entry"] = (p.assembly_name or p.name) + ".dll" if p.kind_hint == "dotnet" else p.name
    # appsettings.json: connection strings, Kestrel endpoints, folders, secrets
    appsettings = next((f for f in p.files if f.name.lower() == "appsettings.json" and f.parent == p.dir), None)
    if appsettings:
        cfg = _load_json(appsettings)
        cs = cfg.get("ConnectionStrings") or {}
        if isinstance(cs, dict) and cs:
            facts["connection_strings"] = sorted(cs.keys())
        ep = ((cfg.get("Kestrel") or {}).get("Endpoints") or {}) if isinstance(cfg.get("Kestrel"), dict) else {}
        if ep:
            facts["kestrel_endpoints"] = sorted(ep.keys())
        folders, secrets = {}, []
        for key, val in _flatten(cfg):
            leaf = key.split(":")[-1]
            if isinstance(val, str) and FOLDER_KEY.search(leaf) and not val.startswith(("http", "~/")) \
                    and ("/" in val or "\\" in val or re.fullmatch(r"[\w\-. ]+", val or "")) and val \
                    and not re.search(r"\.(dll|exe|json|xml|pfx|cer|pem)$", val, re.I) \
                    and not leaf.lower().endswith(("key", "store")) and len(val) < 200:
                folders[key] = val
            if SECRET_KEY.search(leaf) and not key.startswith("ConnectionStrings") and isinstance(val, str):
                secrets.append(key)
        if folders:
            facts["folder_settings"] = folders
        if secrets:
            facts["secret_settings"] = sorted(secrets)
    # Folders written relative to the content root
    writable = set()
    for f in p.source_files():
        if f.suffix.lower() not in (".cs", ".vb"):
            continue
        txt = p.text(f, True)
        for m in re.finditer(r'Path\.Combine\([^,()]*(ContentRootPath|BaseDirectory|AppContext\.BaseDirectory|CurrentDirectory)[^,()]*,\s*"([\w\-./]+)"', txt):
            writable.add(m.group(2))
        for m in re.finditer(r'\?\?\s*"(App_Data|logs?|Logs|data|Data|temp|tmp|uploads|Uploads)"', txt):
            writable.add(m.group(1))
    for key, val in (facts.get("folder_settings") or {}).items():
        if re.fullmatch(r"[\w\-./]+", val) and not val.startswith("/"):
            writable.add(val.strip("./"))
    if any(n.startswith("Microsoft.EntityFrameworkCore.Sqlite") or n == "Microsoft.Data.Sqlite" for n in p.packages):
        for key, val in _flatten(_load_json(appsettings) if appsettings else {}):
            if isinstance(val, str):
                m = re.search(r"Data Source=([\w\-./]+)/[\w\-.]+\.(db|sqlite)", val, re.I)
                if m:
                    writable.add(m.group(1))
    if writable:
        facts["writable_dirs"] = sorted(w for w in writable if w and len(w) < 80)
    spa = p.properties.get("SpaRoot")
    if spa:
        facts["spa_root"] = spa.replace("\\", "/").strip("/")
    if p.kind_hint == "node":
        scripts = (p.manifest.get("scripts") or {})
        facts["build_script"] = "build" if "build" in scripts else ""
        facts["start_script"] = "start" if "start" in scripts else ""
        ang = p.dir / "angular.json"
        if ang.exists():
            a = _load_json(ang)
            for proj in (a.get("projects") or {}).values():
                op = (((proj.get("architect") or {}).get("build") or {}).get("options") or {}).get("outputPath")
                if op:
                    facts["dist_dir"] = op if isinstance(op, str) else op.get("base", "dist")
                    break
    return facts
