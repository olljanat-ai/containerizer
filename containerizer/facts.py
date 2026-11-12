"""Facts needed to build and run a component: entrypoint, ports, health path,
configuration keys to externalize and folders it writes to."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .rules import Context, Rule, run_rule

# sub-commands declared with a command-line library: System.CommandLine `new Command("import", ...)`,
# CommandLineParser `[Verb("import")]`, Spectre.Console.Cli `AddCommand<T>("import")` / `AddBranch("import", ...)`,
# McMaster.Extensions.CommandLineUtils `[Command("import")]` / `app.Command("import", ...)`
CLI_VERB_RE = re.compile(r'(?:\bnew\s+Command\s*\(|\[\s*(?:Verb|Command)\s*\((?:\s*Name\s*[=:])?'
                         r'|\.AddCommand\s*<[\w.<>, ]+>\s*\(|\.AddBranch\s*(?:<[\w.<>, ]+>)?\s*\(|\.Command\s*\()'
                         r'\s*"([a-z][\w-]*)"')

# certificates with their private key, which the image leaves out (generate.DOCKERIGNORE): they come from the secret
# store. Public certificates (.crt, .cer, .pem CA bundles) stay in the image.
CERT_EXT = (".pfx", ".p12")
CERT_SKIP = re.compile(r"(?i)(^|/)(bin|obj|node_modules|tests?|testdata|fixtures?)/")
FOLDER_KEY = re.compile(r"(folder|path|dir|directory|root|location|store|share|inbox|outbox|archive)$", re.I)
# a connection string that is only an embedded database file in the app folder (no folder, no password)
EMBEDDED_DB = re.compile(r"(Data\s*Source|DataSource|Filename)\s*=\s*[\w\-.]+\.(db|sqlite3?|litedb)\s*;?\s*"
                         r"(;\s*(Cache|Mode|Pooling|Foreign\s*Keys|Connection)\s*=\s*[\w]+\s*)*;?", re.I)
EMBEDDED_PKGS = re.compile(r"Microsoft\.EntityFrameworkCore\.Sqlite|Microsoft\.Data\.Sqlite|System\.Data\.SQLite|LiteDB",
                           re.I)
# deployment-time tokens a release pipeline replaces in appsettings.json (Azure DevOps Replace Tokens, Octopus):
# "#{Example.Variable}#" and "__Example.Variable__"
TOKEN_RE = re.compile(r"#\{\s*[A-Za-z_][\w.\-]*\s*\}#|(?<![\w])__[A-Za-z][A-Za-z0-9.\-]*(?:_[A-Za-z0-9.\-]+)*__(?![\w])")
# the last part of a configuration key that names a secret ("Pass" alone: Bypass, Compass are no passwords)
SECRET_KEY = re.compile(r"(password|passwd|pwd|secret|apikey|api_key|clientsecret|token|connectionstring|key)$|^pass$", re.I)


def _settings_rank(name: str) -> tuple:
    """Where a token's starting value is looked for first: appsettings.json (its value under the Production
    override), then the development and test environments' files, then the others."""
    env = name.lower()[len("appsettings"):-len(".json")].strip(".")
    order = ["", "development", "dev", "local", "test", "testing", "acc", "acceptance", "qa", "uat", "staging", "stage"]
    return (order.index(env) if env in order else len(order), env)


def secret_starts(p, keys: list[str]) -> dict[str, str]:
    """The values the component's own settings files give its secret settings (`keys`, configuration form
    `Section:Name`): appsettings.json, then the development and test environments' files, a value without tokens.
    {environment variable name: value}. For the appliance's OpenBao only (openbao.py seeds its empty placeholders
    with them); never written to the output repository."""
    files = sorted((f for f in p.files if f.parent == p.dir and re.fullmatch(r"appsettings(\.[\w-]+)?\.json", f.name, re.I)),
                   key=lambda f: _settings_rank(f.name))
    flat = [dict(_flatten(_load_json(f))) for f in files]
    out = {}
    for key in keys:
        low = key.lower()
        for f in flat:
            v = next((v for k, v in f.items() if k.lower() == low), None)
            if isinstance(v, (int, float)) and not isinstance(v, bool) or isinstance(v, str) and v.strip() \
                    and not TOKEN_RE.search(v):
                out[key.replace(":", "__")] = str(v)
                break
    return out


def token_defaults(settings: dict, files: list[tuple[str, dict]]) -> dict:
    """A starting value for each setting with release-pipeline tokens (`settings`: {key: value}), from the
    component's other settings files (`files`: [(name, flattened settings)] in the order to look): the same key with
    a value without tokens; else each token by its name as a key (`#{Auth.Authority}#` -> Auth:Authority); else
    another setting with the same last name part (`Jwt:Authority` for `Auth:Authority`) when all of those have one
    and the same value. A value that looks secret is never taken (it would be in Git). {key: {"value", "from"}}."""
    from .platforms import classify_env

    def clean(v) -> bool:
        """A real value: not empty, no token, not an object."""
        return bool(v.strip()) and not TOKEN_RE.search(v) if isinstance(v, str) else isinstance(v, (int, float, bool))

    def text(v) -> str:
        return ("true" if v else "false") if isinstance(v, bool) else str(v)

    def safe(k: str, v: str) -> bool:
        return not classify_env({k.replace(":", "__"): v})[1]
    out = {}
    for key, value in settings.items():
        hit = next(((n, f[key]) for n, f in files if key in f and clean(f[key])), None)
        if hit and safe(key, text(hit[1])):
            out[key] = {"value": text(hit[1]), "from": f"{hit[0]} ({key})"}
            continue
        resolved, why = str(value), []
        for tok in TOKEN_RE.findall(str(value)):
            name = tok.strip("#{}_ ")
            cand = [name.replace(".", ":"), name.replace("__", ":"), name]
            hit = next(((n, k, f[k]) for c in cand for n, f in files for k in f
                        if k.lower() == c.lower() and clean(f[k])), None)
            if not hit:
                break
            resolved = resolved.replace(tok, text(hit[2]))
            why.append(f"{tok} = {hit[0]} ({hit[1]})")
        else:
            if why and safe(key, resolved):
                out[key] = {"value": resolved, "from": "; ".join(why)}
                continue
        leaf = key.rsplit(":", 1)[-1].lower()
        same = [(n, k, text(f[k])) for n, f in files for k in f
                if k != key and k.rsplit(":", 1)[-1].lower() == leaf and clean(f[k])]
        if same and len({v for _, _, v in same}) == 1 and safe(key, same[0][2]):
            out[key] = {"value": same[0][2], "from": f"{same[0][0]} ({same[0][1]}, the same name)"}
    return out


def lenient_json(txt: str, bare: set | None = None) -> str:
    """JSON as .NET's configuration reads it, made strict: `//` and `/* */` comments anywhere outside strings and
    trailing commas go, and a release-pipeline token where a value goes (`"Port": #{Api.Port}#`, unquoted because the
    pipeline puts a number or a boolean there) becomes that token as a string. Strings are left exactly as they are
    (a URL's `//`, a `,}` inside a value). The unquoted tokens are added to `bare`."""
    out: list[str] = []
    i, n = 0, len(txt)
    while i < n:
        ch = txt[i]
        if ch == '"':                                   # a string, with its escapes, as it is
            j = i + 1
            while j < n and txt[j] != '"':
                j += 2 if txt[j] == "\\" else 1
            out.append(txt[i:j + 1])
            i = j + 1
        elif txt.startswith("//", i):
            while i < n and txt[i] not in "\r\n":
                i += 1
        elif txt.startswith("/*", i):
            end = txt.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif ch == "," and re.match(r"(?:\s|//[^\r\n]*|/\*.*?\*/)*[}\]]", txt[i + 1:], re.S):
            i += 1                                      # a trailing comma
        elif (m := TOKEN_RE.match(txt, i)):
            out.append(json.dumps(m.group(0)))
            if bare is not None:
                bare.add(m.group(0))
            i = m.end()
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def bare_tokens(txt: str) -> set[str]:
    """The release-pipeline tokens that stand unquoted where a value goes (`"Port": #{Api.Port}#`)."""
    bare: set[str] = set()
    lenient_json(txt, bare)
    return bare


def _load_json(p: Path) -> dict:
    try:
        return json.loads(lenient_json(p.read_text(encoding="utf-8-sig", errors="replace")))
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


def _merge(base, over):
    """.NET configuration semantics: objects merge by key, arrays merge by index."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = _merge(base[k], v) if k in base else v
        return out
    if isinstance(base, list) and isinstance(over, list):
        return [_merge(base[i], v) if i < len(base) else v for i, v in enumerate(over)] + base[len(over):]
    return over


# a settings file the build transforms appsettings.json with (SlowCheetah, `dotnet publish -c Release`):
# <None Include="appsettings.Release.json"><IsTransformFile>true</IsTransformFile></None> in the project file
# (an item that closes itself, <None Include="x" />, has no body: it must not swallow the next item's)
TRANSFORM_ITEM = re.compile(r'<(None|Content)\s+(?:Include|Update)\s*=\s*"([^"]*)"[^>]*(?<!/)>(.*?)</\1\s*>',
                            re.S | re.I)


def release_transform(p) -> Path | None:
    """appsettings.Release.json when the project file marks it as the build's transform of appsettings.json: its
    values (often release-pipeline tokens) are in the published appsettings.json."""
    try:
        text = p.path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    for _, inc, body in TRANSFORM_ITEM.findall(text):
        name = inc.replace("\\", "/").rsplit("/", 1)[-1]
        if name.lower() == "appsettings.release.json" and re.search(r"<IsTransformFile>\s*true\s*<", body, re.I):
            f = p.dir / inc.replace("\\", "/")
            return f if f.is_file() else None
    return None


def _no_jdt(d):
    """A JSON Document Transform without its @jdt.* directives (merged like a settings file)."""
    if isinstance(d, dict):
        return {k: _no_jdt(v) for k, v in d.items() if not k.lower().startswith("@jdt.")}
    return [_no_jdt(v) for v in d] if isinstance(d, list) else d


# PersistKeysToFileSystem(new DirectoryInfo(<folder>)): where the code keeps the Data Protection key ring
PERSIST_KEYS_FS = re.compile(r"PersistKeysToFileSystem\(\s*new\s+(?:System\.IO\.)?DirectoryInfo\(\s*(.+?)\)\s*\)", re.S)
CONFIG_READ = re.compile(r'\[\s*"([\w:.\-]+)"\s*\]|GetValue<string\??>\(\s*"([\w:.\-]+)"')


def dataprotection_folder(repo, p, cfg: dict) -> dict:
    """Where code in the project or a library it references (a shared hosting project) keeps the Data Protection
    key ring with PersistKeysToFileSystem: the configuration keys it reads the folder from, directly or through a
    variable (configuration["DataProtection:KeyFolder"]), with their values ("" when unset), or else the settings
    whose name says they are a key ring folder (rules/60-security.yaml lint.keyring_names);
    dataprotection_key_literal when the folder is a string literal in code. The generator mounts the key Secret
    there (generate.dataprotection_plan)."""
    from .harden import security
    from .rules import _ref_closure
    settings: dict[str, str] = {}
    literal = None
    persists = False
    for q in [p] + _ref_closure(repo, p):
        for f in q.source_files():
            if f.suffix.lower() != ".cs":
                continue
            txt = q.text(f, True)
            for m in PERSIST_KEYS_FS.finditer(txt):
                persists = True
                arg = m.group(1).strip()
                v = re.fullmatch(r"[A-Za-z_]\w*", arg)
                if v:       # a variable: the expression it was assigned from
                    a = re.search(rf"\b{arg}\s*=\s*([^;=][^;]*);", txt)
                    arg = a.group(1).strip() if a else arg
                keys = [x or y for x, y in CONFIG_READ.findall(arg)]
                for k in keys:
                    settings.setdefault(k, "")
                lit = re.fullmatch(r'@?"([^"]+)"', arg)
                if not keys and lit:
                    literal = lit.group(1)
    if not persists:
        return {}
    flat = {k.lower(): v for k, v in _flatten(cfg)}        # .NET configuration keys ignore case
    if not settings:
        names = re.compile(security()["lint"]["keyring_names"])
        settings = {k: "" for k, v in _flatten(cfg) if isinstance(v, str) and v and names.search(k)}
    for k in settings:
        v = flat.get(k.lower())
        settings[k] = v if isinstance(v, str) else ""
    if settings:
        return {"dataprotection_key_settings": settings}
    return {"dataprotection_key_literal": literal} if literal else {}


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
    cfg: dict = {}
    if appsettings:
        # the container runs as Production: appsettings.Production.json overrides appsettings.json
        cfg = _load_json(appsettings)
        # the build's transform (appsettings.Release.json) is in the published appsettings.json
        transform = release_transform(p)
        if transform:
            cfg = _merge(cfg, _no_jdt(_load_json(transform)))
            facts["settings_transform"] = p.rel_file(transform)
        prod = appsettings.with_name("appsettings.Production.json")
        if prod.exists():
            cfg = _merge(cfg, _load_json(prod))
        cs = cfg.get("ConnectionStrings") or {}
        if isinstance(cs, dict) and cs:
            facts["connection_strings"] = sorted(cs.keys())
            # embedded databases (SQLite, LiteDB) whose file is in the app folder: "Data Source=app.db". The
            # generator re-points them to a persistent volume with an environment variable (generate.state_plan)
            files = {k: v for k, v in cs.items() if isinstance(v, str) and EMBEDDED_DB.fullmatch(v.strip())}
            if files and any(EMBEDDED_PKGS.match(n) for n in p.packages):
                facts["embedded_db_files"] = files
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
        flat = list(_flatten(cfg))
        # objects that describe an HTTP call ({"Service": "Catalog", "Path": "api/search/reindex"}):
        # their Path is a URL route, not a folder
        routes = {k.rsplit(":", 1)[0] for k, _ in flat if ":" in k and re.fullmatch(
            r"(Service|Url|Uri|BaseUrl|Endpoint|Method|HttpMethod|Route|Cron|Verb)", k.rsplit(":", 1)[1], re.I)}
        for key, val in flat:
            leaf = key.split(":")[-1]
            if ":" in key and key.rsplit(":", 1)[0] in routes or isinstance(val, str) and re.match(r"/?api/", val):
                continue
            if isinstance(val, str) and FOLDER_KEY.search(leaf) and not val.startswith(("http", "~/")) \
                    and ("/" in val or "\\" in val or re.fullmatch(r"[\w\-. ]+", val or "")) and val \
                    and not re.search(r"\.(dll|exe|json|xml|pfx|cer|pem)$", val, re.I) \
                    and not leaf.lower().endswith(("key", "store")) and len(val) < 200:
                folders[key] = val
            if SECRET_KEY.search(leaf) and not key.startswith("ConnectionStrings") and isinstance(val, str):
                secrets.append(key)
        if folders:
            facts["folder_settings"] = folders
        # connection strings and settings of services the appliance can run in the lab (labservices.py)
        from .labservices import settings_facts
        lab = settings_facts(flat)
        if lab:
            facts["lab_settings"] = lab
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
        # settings full of release-pipeline tokens: the image blanks the tokens, the deployment sets the values
        tokens = {k: sorted(set(TOKEN_RE.findall(v))) for k, v in flat if isinstance(v, str) and TOKEN_RE.search(v)}
        if tokens:
            facts["token_settings"] = tokens
            # unquoted where a value goes ("Port": #{Api.Port}#): the image makes them null, not empty (invalid JSON)
            bare = set()
            for f in (appsettings, transform, appsettings.with_name("appsettings.Production.json")):
                if f is None:
                    continue
                try:
                    bare |= bare_tokens(f.read_text(encoding="utf-8-sig", errors="replace"))
                except OSError:
                    pass
            if bare:
                facts["token_bare"] = sorted(bare)
            # secret by its name, a token's name or its value (a password in it): from the secret store, the rest
            # from a ConfigMap (platforms.classify_env, as for the settings of a replatformed service)
            from .platforms import classify_env
            vals = dict(flat)
            secret = {k for k, toks in tokens.items()
                      if classify_env({k.replace(":", "__"): vals[k], **{t.strip("#{}_ "): "" for t in toks}})[1]}
            if secret:
                facts["token_secret_settings"] = sorted(secret)
            files = sorted((f for f in p.files if f.parent == p.dir and re.fullmatch(r"appsettings(\.[\w-]+)?\.json", f.name, re.I)),
                           key=lambda f: _settings_rank(f.name))
            starts = token_defaults({k: vals[k] for k in tokens if k not in secret},
                                    [(f.name, dict(_flatten(_load_json(f)))) for f in files])
            if starts:
                facts["token_defaults"] = starts
        # sign-in settings (OIDC, WS-Federation, SAML) the sandbox IdP overrides (idp.py)
        if any(facts.get(f"auth_{x}") for x in ("oidc", "wsfed", "saml")):
            from .idp import find_sections
            sections = find_sections(cfg)
            if sections:
                facts["auth_sections"] = sections
    # certificate and key files next to the code (Dockerfile.dockerignore keeps them out of the image): the
    # manifests mount each from the secret store where the app expects it (generate.cert_files)
    certs = sorted(f.relative_to(p.dir).as_posix() for f in p.files
                   if f.suffix.lower() in CERT_EXT and p.dir in f.parents
                   and not CERT_SKIP.search(f.relative_to(p.dir).as_posix()))
    if certs:
        facts["cert_files"] = certs[:20]
    # sub-commands of a console tool: "Usage: Tool <import|export|purge>", an array of verbs, case "import": in
    # Program.cs, or the commands declared with a command-line library
    if comp.role == "console" and "oneshot_arg" not in facts:
        cmds: list[str] = []
        declared: list[str] = []
        for f in p.source_files():
            if f.suffix.lower() != ".cs":
                continue
            txt = p.text(f)
            declared += [m.group(1) for m in CLI_VERB_RE.finditer(txt)]
            m = re.search(r"Usage:[^\"\n]*?[<\[]((?:[\w-]+\|)+[\w-]+)[>\]]", txt)
            if m:
                cmds = m.group(1).split("|")
                break
            m = re.search(r"\b(?:Verbs|Commands|Jobs|Tasks|Modes)\s*=\s*(?:new\s*(?:string)?\s*\[\]\s*)?[\{\[]\s*((?:\"[\w-]+\"\s*,\s*)+\"[\w-]+\")", txt)
            if m:
                cmds = re.findall(r'"([\w-]+)"', m.group(1))
                break
            if f.name == "Program.cs":
                cmds = [x for x in re.findall(r'^\s*case\s+"([a-z][\w-]*)"\s*:', txt, re.M)]
        if len(cmds) < 2:
            own = {str(x).lower() for x in (p.name, p.assembly_name, p.path.stem) if x}   # the tool's own name
            cmds = [x for x in dict.fromkeys(declared) if x.lower() not in own]
        if len(cmds) >= 2:
            facts["commands"] = cmds
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
        for m in re.finditer(r"\$\{basedir\}[\\/]+([\w\-]+)[\\/]", txt):
            facts.setdefault("nlog_basedir_dirs", []).append(m.group(1))
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
        # files saved under the web root: Path.Combine(env.WebRootPath, "uploads", name)
        for m in re.finditer(r'Path\.Combine\([^,()]*WebRootPath[^,()]*,\s*"([\w\-]+)"', txt):
            writable.add("wwwroot/" + m.group(1))
    if p.kind_hint == "dotnet":
        facts.update(dataprotection_folder(repo, p, cfg))
    writable |= set(facts.get("nlog_basedir_dirs") or [])
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
    if p.kind_hint in ("java", "node"):
        from .facts_jvm_node import java_facts, node_facts
        (java_facts if p.kind_hint == "java" else node_facts)(repo, comp, facts)
    if p.kind_hint in ("python", "go"):
        from .facts_python_go import go_facts, python_facts
        (python_facts if p.kind_hint == "python" else go_facts)(repo, comp, facts)
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
        if "dist_dir" not in facts:
            # the bundler's output folder: Create React App writes build/, Vite and Vue CLI dist/
            # unless the config names another (build.outDir / outputDir)
            for n in ("vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.mjs", "vue.config.js"):
                f = p.dir / n
                if f.exists():
                    m = re.search(r"\b(outDir|outputDir)\s*:\s*['\"`]([\w./-]+)['\"`]", p.text(f))
                    if m:
                        facts["dist_dir"] = m.group(2).strip("./") or "dist"
                    break
            if "dist_dir" not in facts and "react-scripts" in p.packages:
                facts["dist_dir"] = "build"
    return facts
