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
        names = set(ep.keys()) if isinstance(ep, dict) else set()
        for f in p.files:   # appsettings.<Environment>.json may add endpoints, override those too
            if f.parent == p.dir and re.fullmatch(r"appsettings\.[\w-]+\.json", f.name, re.I):
                k = _load_json(f).get("Kestrel")
                if isinstance(k, dict) and isinstance(k.get("Endpoints"), dict):
                    names |= set(k["Endpoints"].keys())
        if names:
            facts["kestrel_endpoints"] = sorted(names)
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
        # Serilog sinks that write only to files: containers should log to stdout
        wt = (cfg.get("Serilog") or {}).get("WriteTo") if isinstance(cfg.get("Serilog"), dict) else None
        if isinstance(wt, list):
            idx = [i for i, x in enumerate(wt) if isinstance(x, dict) and x.get("Name") in ("File", "RollingFile")]
            if idx and not any(isinstance(x, dict) and x.get("Name") == "Console" for x in wt):
                facts["serilog_file_sinks"] = idx
        # Windows absolute paths (D:\..., \\server\share) must be re-pointed to Linux mounts
        win = {}
        for key, val in _flatten(cfg):
            if isinstance(val, str) and re.match(r"^([A-Za-z]:\\|\\\\[\w.-]+\\)", val) and len(val) < 260:
                win[key] = val
        if win:
            facts["windows_paths"] = win
        # custom listen-address settings ("WebhookUrls": "http://*:8085" read by UseUrls)
        listen = [k for k, v in _flatten(cfg) if isinstance(v, str) and not k.startswith("Kestrel:")
                  and re.fullmatch(r"(https?://(\*|\+|0\.0\.0\.0|\[::\]):\d+;?)+", v.strip())]
        if listen:
            facts["listen_url_settings"] = listen
        if secrets:
            facts["secret_settings"] = sorted(secrets)
    # NLog folders taken from configuration with a Windows default:
    #   ${configsetting:item=Logging.Folder:default=D\:\\Logs\\App}
    nlog = next((f for f in p.files if f.name.lower() == "nlog.config" and f.parent == p.dir), None)
    if nlog:
        txt = p.text(nlog)
        items = [m.group(1) for m in re.finditer(r"\$\{configsetting:item=([\w.]+):default=([A-Za-z]\\?:|\\\\)", txt)]
        if items:
            facts["nlog_folder_settings"] = sorted(set(items))
        # ${environment:LOG_DIR:whenEmpty=D\:/App/Logs} -> the variable can re-point it
        envs = [m.group(1) for m in re.finditer(
            r"\$\{environment:(?:variable=)?(\w+):(?:whenEmpty|default)=([A-Za-z]\\?:|\\\\)", txt)]
        if envs:
            facts["nlog_env_folders"] = sorted(set(envs))
        if re.search(r'xsi:type="(File|Database|EventLog)"', txt) and not re.search(r'xsi:type="(Console|ColoredConsole)"', txt):
            facts["nlog_no_console"] = True
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
    # not folders: file names (XML docs, databases) and enum-like values (StoreLocation: LocalMachine)
    writable = {w for w in writable if w and len(w) < 80 and not re.search(r"\.[A-Za-z]\w{0,7}$", w)
                and w not in ("LocalMachine", "CurrentUser", "My", "Root", "None", "Default")}
    if writable:
        facts["writable_dirs"] = sorted(writable)
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
