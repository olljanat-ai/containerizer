"""Build and run facts of Java and Node.js components: the framework, the start command, where the
configuration lives and which of its settings must be overridden or kept secret in a container.

Like the .NET facts, nothing here changes the application: the generator turns these facts into
environment variables (which take precedence over the application's configuration files in Spring
Boot, Quarkus, Micronaut and node-config) and Kubernetes Secret references.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

WIN_PATH = re.compile(r"^([A-Za-z]:[\\/]|\\\\[\w.-]+\\)")
# configuration keys whose values are credentials or carry them (JDBC URLs, Mongo URIs)
SECRET_LEAF = re.compile(r"(password|passwd|secret|apikey|token|credentials?|privatekey|signingkey|"
                         r"clientsecret|accesskey|secretkey|connectionstring)$", re.I)
SECRET_KEY = re.compile(r"(datasource\.(url|jdbcurl|username|password)|jdbc[.-]?url|mongodb\.uri|redis\.url|"
                        r"\.dsn|r2dbc\.url|r2dbc\.username|r2dbc\.password)$", re.I)
ENV_SECRET = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?|"
                        r"(DATABASE|DB|MONGO(DB)?|REDIS|POSTGRES|MYSQL|AMQP|RABBITMQ)_(URL|URI|DSN)|DSN)$")


def _ref_closure(repo, p):
    from .rules import _ref_closure as rc
    return rc(repo, p)


def closure_packages(repo, p) -> set[str]:
    """Runtime packages of the project and of the in-repository projects it uses."""
    out = set()
    for q in [p] + _ref_closure(repo, p):
        out |= {n for n in q.packages if n not in q.dev_packages}
    return out


# --------------------------------------------------------------------------- configuration files

def _flatten(d, prefix=""):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _flatten(v, f"{prefix}{k}.")
    elif isinstance(d, list):
        for i, v in enumerate(d):
            yield from _flatten(v, f"{prefix[:-1]}[{i}].")
    elif d is not None:
        yield prefix[:-1], d if isinstance(d, str) else json.dumps(d) if not isinstance(d, (int, float)) else str(d)


def _properties(txt: str) -> dict[str, str]:
    """java.util.Properties: key=value or key: value, continuation lines, # and ! comments."""
    out: dict[str, str] = {}
    lines = txt.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].lstrip()
        i += 1
        if not line or line[0] in "#!":
            continue
        while line.endswith("\\") and not line.endswith("\\\\") and i < len(lines):
            line = line[:-1] + lines[i].lstrip()
            i += 1
        m = re.match(r"((?:\\.|[^=:\s\\])+)\s*[=:\s]\s*(.*)$", line)
        if m:
            key = re.sub(r"\\(.)", r"\1", m.group(1))
            out[key] = m.group(2).replace("\\\\", "\\").strip()
    return out


def _yaml_docs(txt: str) -> list[dict]:
    import yaml
    try:
        return [d for d in yaml.safe_load_all(txt) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []


def java_config(p) -> dict[str, str]:
    """application.properties / application.yml (and the prod profile) of a Java module, flattened.
    Spring Boot reads profile files over the base file; multi-document YAML with an
    `on-profile`/`profiles` key belongs to that profile and is left out unless it is prod."""
    res = p.dir / "src" / "main" / "resources"
    cfg: dict[str, str] = {}
    for stem in ("bootstrap", "application", "application-prod", "application-production"):
        for ext in ("properties", "yml", "yaml"):
            f = res / f"{stem}.{ext}"
            if not f.exists():
                continue
            txt = f.read_text(errors="replace")
            if ext == "properties":
                vals = _properties(txt)
                # Quarkus profile keys: %prod.quarkus.datasource.url applies in production, %dev. never
                for k in list(vals):
                    if k.startswith("%"):
                        prof, _, rest = k[1:].partition(".")
                        v = vals.pop(k)
                        if prof == "prod":
                            vals[rest] = v
                cfg.update(vals)
            else:
                for doc in _yaml_docs(txt):
                    prof = ((doc.get("spring") or {}).get("config") or {}).get("activate", {}) if isinstance(doc.get("spring"), dict) else {}
                    on = (prof or {}).get("on-profile") if isinstance(prof, dict) else None
                    on = on or (doc.get("spring") or {}).get("profiles") if isinstance(doc.get("spring"), dict) else on
                    if on and not re.search(r"\bprod(uction)?\b", str(on)):
                        continue
                    cfg.update(dict(_flatten(doc)))
    return cfg


def java_framework(repo, p) -> str:
    pk = closure_packages(repo, p)
    if (p.properties or {}).get("SpringBoot") == "true" or any(n.startswith("org.springframework.boot:") for n in pk):
        return "spring"
    if any(n.startswith("io.quarkus:") for n in pk):
        return "quarkus"
    if any(n.startswith("io.micronaut:") for n in pk):
        return "micronaut"
    if any(n.startswith("io.helidon") for n in pk):
        return "helidon"
    return "plain"


def env_name(key: str, framework: str) -> str:
    """The environment variable that overrides a configuration key.
    Spring relaxed binding: dots and [n] become _, dashes are removed, upper case
    (spring.datasource.url -> SPRING_DATASOURCE_URL, my.list[0] -> MY_LIST_0_).
    MicroProfile Config (Quarkus, Helidon) and Micronaut: every non-alphanumeric character becomes _."""
    if framework == "spring":
        k = re.sub(r"\[(\d+)\]", r"_\1_", key).replace("-", "").replace(".", "_")
        return re.sub(r"[^A-Za-z0-9_]", "_", k).upper()
    return re.sub(r"[^A-Za-z0-9]", "_", key).upper()


def _placeholder_env(val: str) -> list[str]:
    """${DB_PASSWORD} / ${DB_PASSWORD:default}: the value is read from that variable."""
    return re.findall(r"\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}", val or "")


def java_facts(repo, c, facts: dict) -> None:
    p = c.project
    fw = java_framework(repo, p)
    facts["java_framework"] = fw
    cfg = java_config(p)
    pk = closure_packages(repo, p)
    ctx = (cfg.get("server.servlet.context-path") or cfg.get("server.servlet.contextPath") or cfg.get("server.context-path")
           or cfg.get("spring.webflux.base-path") or cfg.get("quarkus.http.root-path")
           or cfg.get("micronaut.server.context-path") or "")
    ctx = "" if "${" in ctx else "/" + ctx.strip("/") if ctx.strip("/") else ""
    if ctx:
        facts["context_path"] = ctx
    if cfg.get("management.server.port"):
        facts["management_port"] = cfg["management.server.port"]
    # health endpoints the framework serves
    code_permits_health = any(re.search(r'"/actuator/health|EndpointRequest\.to\(\s*HealthEndpoint|'
                                        r'EndpointRequest\.toAnyEndpoint', p.text(f))
                              for f in p.source_files() if f.suffix in (".java", ".kt"))
    secured = any(n == "org.springframework.boot:spring-boot-starter-security" or n.startswith("org.springframework.security:")
                  for n in pk)
    if fw == "spring" and "org.springframework.boot:spring-boot-starter-actuator" in pk and not facts.get("management_port"):
        base = cfg.get("management.endpoints.web.base-path", "/actuator")
        if "${" not in base and (not secured or code_permits_health):
            base = "/" + base.strip("/") if base.strip("/") else ""
            facts["health"] = f"{ctx}{base}/health/liveness"
            facts["readiness"] = f"{ctx}{base}/health/readiness"
    elif fw == "quarkus" and "io.quarkus:quarkus-smallrye-health" in pk:
        root = cfg.get("quarkus.http.non-application-root-path", "q").strip("/")
        if "${" not in root:
            pre = f"/{root}" if not root.startswith("/") else root
            facts["health"], facts["readiness"] = f"{ctx}{pre}/health/live", f"{ctx}{pre}/health/ready"
    elif fw == "micronaut" and "io.micronaut:micronaut-management" in pk:
        facts["health"], facts["readiness"] = f"{ctx}/health/liveness", f"{ctx}/health/readiness"
    # settings to override or keep secret
    win, secrets, writable = {}, [], set()
    for key, val in cfg.items():
        leaf = key.split(".")[-1].replace("-", "").replace("_", "")
        refs = _placeholder_env(val)
        if SECRET_LEAF.search(leaf) or SECRET_KEY.search(key.replace("-", "")):
            if refs:
                secrets += refs                               # the app already reads it from a variable
            elif val and not val.startswith("${"):
                secrets.append(env_name(key, fw))
            continue
        if WIN_PATH.match(val or "") and len(val) < 260:
            win[key] = val
    for key in ("logging.file.path", "logging.path", "logging.file.name", "logging.file", "quarkus.log.file.path"):
        v = cfg.get(key, "")
        if not v or "${" in v or WIN_PATH.match(v) or v.startswith("/"):
            continue
        d = v if key in ("logging.file.path", "logging.path") else str(Path(v).parent)
        if d.strip("./"):
            writable.add(d.strip("./"))
    if win:
        facts["windows_paths"] = win
        facts["config_env_style"] = fw
    if secrets:
        facts["secret_settings"] = sorted(set(secrets))
        facts["secret_env_style"] = "env"
    if writable:
        facts["writable_dirs"] = sorted(set(facts.get("writable_dirs") or []) | writable)
    # servlet API generation decides the Tomcat line for a WAR without an embedded server
    api = None
    for f in p.source_files():
        if f.suffix in (".java", ".kt"):
            m = re.search(r"^import\s+(jakarta|javax)\.servlet\.", p.text(f), re.M)
            if m:
                api = m.group(1)
                break
    if api is None:
        if any(n.startswith("jakarta.servlet:") or n.startswith("jakarta.platform:") for n in pk):
            api = "jakarta"
        elif any(n.startswith("javax.servlet:") or n.startswith("javax:javaee") for n in pk):
            api = "javax"
    if api:
        facts["servlet_api"] = api
    if any(re.search(r'System\.getenv\(\s*"PORT"\s*\)', p.text(f)) for f in p.source_files() if f.suffix in (".java", ".kt")):
        facts["port_env"] = True


# --------------------------------------------------------------------------- Node.js

START_SCRIPTS = ("start:prod", "start:production", "prod", "production", "start", "serve")
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
DEV_COMMANDS = {"nodemon", "ts-node-dev", "webpack-dev-server", "vite", "concurrently", "npm-run-all", "run-p", "run-s",
                "react-scripts", "ng", "vue-cli-service", "parcel", "browser-sync", "live-server", "next-dev",
                "turbo", "lerna"}


def _segments(cmd: str) -> list[str]:
    """`a && b && c` -> the commands; `;` and `&&` only (a pipe or `||` is shell logic)."""
    return [s.strip() for s in re.split(r"&&|;", cmd) if s.strip()]


def node_start(manifest: dict, depth: int = 0) -> dict | None:
    """The production start command of a package.json as argv for `node`, or None.

    Returns {"script": name, "env": {...}, "argv": [...]} where argv is either
    ["node", <node args>...] or [<bin>, args...] (a package's command line, resolved at build time),
    or {"script": name, "shell": command} when the command needs a shell."""
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    name = next((n for n in START_SCRIPTS if isinstance(scripts.get(n), str)), None)
    if name is None:
        if isinstance(manifest.get("main"), str):
            return {"script": "", "env": {}, "argv": ["node", manifest["main"]]}
        return None
    return _parse_start(scripts, name, scripts[name], depth)


def _parse_start(scripts: dict, name: str, cmd: str, depth: int) -> dict:
    segs = _segments(cmd)
    if not segs or re.search(r"\|\||\||`|\$\(|[<>]|\bif\b|&\s*$|\s&\s", cmd):
        return {"script": name, "shell": cmd}
    pre = segs[:-1]
    # the last command is the server; build/migrate steps before it run at start in the original
    seg = segs[-1]
    try:
        argv = shlex.split(seg)
    except ValueError:
        return {"script": name, "shell": cmd}
    env: dict[str, str] = {}
    while argv and (argv[0] in ("cross-env", "env", "dotenv", "--") or ENV_ASSIGN.match(argv[0])):
        a = argv.pop(0)
        if ENV_ASSIGN.match(a):
            k, v = a.split("=", 1)
            env[k] = v
        elif a == "dotenv":          # dotenv-cli: `dotenv -e .env -- node x`
            while argv and argv[0] != "--" and argv[0].startswith("-"):
                argv.pop(0)
                if argv and not argv[0].startswith("-") and argv[0] != "--":
                    argv.pop(0)
    if not argv:
        return {"script": name, "shell": cmd}
    head = argv[0]
    if head == "node" and len(argv) > 2 and argv[1] == "--run":
        argv = ["npm", "run"] + argv[2:]               # Node.js 22+: `node --run <script>`
        head = "npm"
    if head in ("npm", "pnpm", "yarn", "bun") and depth < 3:
        rest = argv[1:]
        if rest and rest[0] in ("run", "run-script"):
            rest = rest[1:]
        if head == "npm" and rest and rest[0] == "start":
            target = "start"
        else:
            target = rest[0] if rest else ""
        if target in scripts and target != name:
            sub = _parse_start(scripts, target, scripts[target], depth + 1)
            sub["env"] = {**env, **sub.get("env", {})}
            if pre:
                sub["pre"] = pre + sub.get("pre", [])
            return sub
        return {"script": name, "shell": cmd}
    if head in DEV_COMMANDS or "--watch" in argv or head == "node" and "--watch" in argv:
        return {"script": name, "shell": cmd, "dev": True}
    out = {"script": name, "env": env, "argv": argv}
    if pre:
        out["pre"] = pre
    return out


def nest_entry(p) -> str:
    """`nest start` runs node on the compiled entry file (nest-cli.json: sourceRoot, entryFile)."""
    try:
        cfg = json.loads((p.dir / "nest-cli.json").read_text())
    except (OSError, ValueError):
        cfg = {}
    if cfg.get("monorepo"):
        return ""
    entry = cfg.get("entryFile") or "main"
    return f"dist/{entry}.js"


def nx_entry(p, argv: list[str]) -> str:
    """`nx serve` runs the build output with @nx/js:node; production runs that file with node.
    The file is <outputPath>/<main name>.js (esbuild, webpack, rollup) or keeps main's folder
    below the project root (tsc, swc), as the executor computes it."""
    if argv[1:2] not in (["serve"], ["start"]) and not (len(argv) > 2 and argv[1] == "run" and argv[2].endswith(":serve")):
        return ""
    try:
        proj = json.loads((p.dir / "project.json").read_text())
    except (OSError, ValueError):
        return ""
    targets = proj.get("targets") or {}
    serve = targets.get("serve") or {}
    if not re.search(r"@(nx|nrwl)/(js|node):node", str(serve.get("executor", ""))):
        return ""
    bt = str((serve.get("options") or {}).get("buildTarget") or "build").split(":")
    build = targets.get(bt[1] if len(bt) > 1 else bt[0]) or {}
    opts = build.get("options") or {}
    out, main = opts.get("outputPath"), opts.get("main")
    if not out or not main:
        return ""
    if opts.get("outputFileName"):
        name = opts["outputFileName"]
    else:
        name = Path(main).stem + ".js"
        if re.search(r":(tsc|swc)$", str(build.get("executor", ""))):
            rel = Path(main).parent
            root = Path(proj.get("root") or ".")
            try:
                rel = rel.relative_to(root)
            except ValueError:
                pass
            name = str(rel / name) if str(rel) != "." else name
    root = Path(proj.get("root") or ".")
    out = out.replace("{workspaceRoot}/", "").replace("{projectRoot}", str(root))
    # the output path is relative to the workspace root, the start command runs in the package
    return str(Path(out) / name).replace("\\", "/")


def node_facts(repo, c, facts: dict) -> None:
    p = c.project
    m = p.manifest or {}
    st = node_start(m)
    if st and st.get("argv") and st["argv"][0] == "nest":
        rest = st["argv"][1:]
        entry = nest_entry(p)
        if rest[:1] == ["start"] and entry and not any(a in ("--watch", "-w", "--debug") for a in rest):
            st = {**st, "argv": ["node", entry]}
        else:
            st = {"script": st["script"], "shell": " ".join(st["argv"])}
    if st is None or st.get("dev"):
        # npm's default start command is `node server.js`; a package without one runs its main file
        # (index.js by default), which is also what a nodemon dev script watches
        dev = next((v for k, v in (m.get("scripts") or {}).items() if k == "dev" and isinstance(v, str)), "")
        mm = re.fullmatch(r"\s*nodemon\s+([\w./-]+\.[cm]?js)\s*", dev)
        for cand in ["server.js", m.get("main") if isinstance(m.get("main"), str) else None, "index.js",
                     mm.group(1) if mm else None]:
            if cand and (p.dir / cand).is_file():
                st = {"script": "", "env": {}, "argv": ["node", cand], "default": True}
                break
    if st and st.get("argv") and st["argv"][0] == "nx":
        entry = nx_entry(p, st["argv"])
        st = {**st, "argv": ["node", entry]} if entry else {"script": st["script"], "shell": " ".join(st["argv"])}
    if st:
        facts["node_start"] = st
    pk = closure_packages(repo, p)
    if pk & {"next", "nuxt", "@remix-run/serve", "@react-router/serve", "@sveltejs/adapter-node", "astro", "@nestjs/core",
             "strapi", "@strapi/strapi", "sails"}:
        facts["port_env"] = True              # these listen on $PORT
    # environment the app documents in .env.example: credentials become Secret references
    secrets = []
    for n in (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", ".env.defaults"):
        f = p.dir / n
        if f.exists():
            for line in f.read_text(errors="replace").splitlines():
                mm = re.match(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=", line)
                if mm and ENV_SECRET.search(mm.group(1)):
                    secrets.append(mm.group(1))
    if secrets:
        facts["secret_settings"] = sorted(set(secrets) | set(facts.get("secret_settings") or []))
        facts["secret_env_style"] = "env"
    # node-config (config/default.json, config/production.json): Windows paths are re-pointed through
    # NODE_CONFIG, which the package merges over the files
    if "config" in pk:
        merged: dict = {}
        for n in ("default.json", "production.json"):
            f = p.dir / "config" / n
            try:
                d = json.loads(f.read_text()) if f.exists() else {}
            except (OSError, ValueError):
                d = {}
            merged.update(dict(_flatten(d)) if isinstance(d, dict) else {})
        win = {k: v for k, v in merged.items() if isinstance(v, str) and WIN_PATH.match(v) and "[" not in k}
        if win:
            facts["windows_paths"] = win
            facts["config_env_style"] = "node-config"
        sec = [k for k in merged if SECRET_LEAF.search(k.split(".")[-1].replace("_", ""))]
        if sec:
            facts["node_config_secrets"] = sorted(sec)
    dbs = node_db_files(p)
    if dbs:
        facts["node_db_files"] = dbs          # where the embedded database's file is (generate.node_db_places)


# --------------------------------------------------------------------------- Node.js: the embedded database's file

# Packages that keep the data in a file (or folder) the code names when it opens the database. SQLite opens its
# file through a symbolic link and keeps its journal beside the real file; the others (LowDB writes a temporary
# file and renames it over the path, LevelDB wants a folder) need the folder itself on the volume.
NODE_DB_PKG = re.compile(r"^((@[\w.-]+/)?sqlite3|better-sqlite3|sqlite|@journeyapps/sqlcipher|lowdb|nedb|@seald-io/nedb|"
                         r"nedb-promises|node-json-db|lokijs|level|classic-level|duckdb|typeorm|sequelize|knex)$")
NODE_SQLITE_PKG = re.compile(r"^((@[\w.-]+/)?sqlite3|better-sqlite3|sqlite|@journeyapps/sqlcipher)$")
NODE_DB_EXT = re.compile(r"\.(db3?|sqlite3?|nedb|duckdb)$", re.I)
NODE_SQLITE_EXT = re.compile(r"\.(db3?|sqlite3?)$", re.I)
# new Database(<path>), new sqlite3.Database(<path>), require('better-sqlite3')(<path>), new Datastore({filename:
# <path>}), new JSONFile(<path>), new Level(<path>); and the settings of sqlite's open(), TypeORM, Sequelize and
# knex (filename:, storage:, database:), which count only with a database file's extension
NODE_DB_OPEN = re.compile(r"""new\s+(?:[\w$]+\.)?(?P<ctor>Database|JSONFile(?:Sync)?|Level|ClassicLevel)\s*\(\s*
                              |require\(\s*['"](?P<req>better-sqlite3|level|classic-level)['"]\s*\)\s*\(\s*
                              |\bJSONFile(?:Sync)?Preset\s*\(\s*
                              |\b(?P<key>filename|storage|database)\s*:\s*""", re.X)
NODE_ENV = re.compile(r"process\.env\.([A-Za-z_]\w*)|process\.env\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]")
NODE_SRC = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts")
NODE_SKIP = {"node_modules", ".git", "dist", "build", "out", "coverage", "test", "tests", "__tests__", "spec", ".next",
             "public", "static", "migrations"}
NODE_DB_MAX_FILES = 1500


def _js_arg(text: str, start: int, limit: int = 400) -> str:
    """The expression that starts at `start`, up to the `,`, `)` or `}` that ends it (strings and brackets kept
    whole)."""
    depth, quote, i = 0, "", start
    end = min(len(text), start + limit)
    while i < end:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in ",;\n" and depth == 0:
            break
        i += 1
    return text[start:i].strip()


_JS_STR = r"""(?:'([^'\\$]*)'|"([^"\\$]*)"|`([^`\\$]*)`)"""
_JS_BASE = r"(?P<base>__dirname|import\.meta\.dirname|process\.cwd\(\))"


def _js_const(text: str, name: str) -> str | None:
    m = re.search(r"\b(?:const|let|var)\s+" + re.escape(name) + r"\s*(?::[^=\n]+)?=\s*", text)
    return _js_arg(text, m.end()) if m else None


def _js_path(expr: str, text: str = "", depth: int = 0) -> tuple[str, str] | None:
    """(base, path) of a path expression: base 'cwd' or 'dir' (the folder of the file it is written in). A string,
    path.join/resolve of strings (from __dirname, process.cwd() or a constant of the file that is such a path),
    __dirname + '/x', `${__dirname}/x`."""
    expr = expr.strip()
    m = re.fullmatch(_JS_STR, expr)
    if m:
        return "cwd", next(g for g in m.groups() if g is not None)
    if re.fullmatch(_JS_BASE, expr):
        return ("cwd" if expr.startswith("process") else "dir"), "."
    if re.fullmatch(r"[A-Za-z_$][\w$]*", expr) and depth < 3:
        val = _js_const(text, expr)
        return _js_path(val, text, depth + 1) if val else None
    m = re.fullmatch(r"(?:path\.)?(?:join|resolve)\s*\((.*)\)", expr, re.S)
    if m:
        parts = [_js_path(x, text, depth + 1) for x in re.split(r",(?![^(]*\))", m.group(1))]
        if not parts or not all(parts) or any(b == "dir" for b, _ in parts[1:]):
            return None
        return parts[0][0], "/".join(v for _, v in parts)
    m = re.fullmatch(_JS_BASE + r"\s*\+\s*" + _JS_STR, expr)
    if m:
        return ("cwd" if m.group("base").startswith("process") else "dir"), "." + "/" + next(
            g for g in m.groups()[1:] if g is not None).lstrip("/")
    m = re.fullmatch(r"`\$\{" + _JS_BASE + r"\}/([^`$\\]+)`", expr)
    if m:
        return ("cwd" if m.group("base").startswith("process") else "dir"), m.group(2)
    return None


def _js_db_expr(text: str, expr: str, depth: int = 0) -> tuple[str | None, tuple[str, str] | None]:
    """(environment variable, path) a database path expression names: process.env.X, process.env.X || <path>, a
    path, or a constant of the same file that is one of those."""
    expr = expr.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", expr) and depth < 2:
        val = _js_const(text, expr)
        return _js_db_expr(text, val, depth + 1) if val else (None, None)
    env = NODE_ENV.match(expr)
    if env:
        rest = re.match(r"\s*(?:\|\||\?\?)\s*(.+)$", expr[env.end():], re.S)
        return env.group(1) or env.group(2), _js_path(rest.group(1), text) if rest else None
    return None, _js_path(expr, text)


def node_db_files(p) -> list[dict]:
    """Where a Node.js project's code opens its embedded database: one entry per file it names, {"rel": the path
    from the project folder (absolute: as written), "env": the environment variable that sets it (when the code
    reads one), "sqlite": a SQLite file, "exists": the repository has that file, "shared": its folder holds other
    files of the repository}. Empty when the project has no such package or the code names no file this reads."""
    import posixpath
    pkgs = {n for n in p.packages if n not in p.dev_packages}
    if not any(NODE_DB_PKG.match(n) for n in pkgs):
        return []
    sqlite_pkg = any(NODE_SQLITE_PKG.match(n) for n in pkgs)
    out: dict[tuple, dict] = {}
    seen = 0
    for path in sorted(p.dir.rglob("*")):
        rel_parts = path.relative_to(p.dir).parts
        if path.suffix.lower() not in NODE_SRC or any(x in NODE_SKIP for x in rel_parts[:-1]) \
                or re.search(r"\.(test|spec|d)\.[cm]?[jt]s$", path.name) or path.is_symlink() or not path.is_file():
            continue
        seen += 1
        if seen > NODE_DB_MAX_FILES:
            break
        try:
            if path.stat().st_size > 400_000:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for m in NODE_DB_OPEN.finditer(text):
            env, where = _js_db_expr(text, _js_arg(text, m.end()))
            if where is None and not env:
                continue
            raw = where[1] if where else ""
            if raw in (":memory:", "") and not env or raw.startswith(("file:", "http")):
                continue
            if m.group("key") and not (NODE_DB_EXT.search(raw) or (env and re.search(r"DB|SQLITE|DATABASE", env))):
                continue                    # filename: 'error.log' of a logger, database: 'shop' of a server
            if raw.startswith("/") or not where:
                rel = raw
            else:
                base = "" if where[0] == "cwd" else "/".join(rel_parts[:-1])
                rel = posixpath.normpath(posixpath.join(base, raw))
            ctor = m.group("ctor") or ""
            sqlite = bool(NODE_SQLITE_EXT.search(raw)) or (sqlite_pkg and (ctor == "Database" or m.group("req") == "better-sqlite3")
                                                             and not re.search(r"\.(json|duckdb)$", raw, re.I))
            target = p.dir / rel if rel and not rel.startswith(("/", "..")) else None
            folder = target.parent if target else None
            shared = bool(folder and folder.is_dir() and any(x for x in folder.iterdir() if x != target
                                                             and x.name not in (".gitkeep", ".gitignore")))
            out.setdefault((rel, env), {"rel": rel, **({"env": env} if env else {}), "sqlite": sqlite,
                                        "exists": bool(target and target.exists()), "shared": shared})
    return list(out.values())[:8]
