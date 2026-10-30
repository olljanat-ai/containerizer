"""Generates container build files and Kubernetes manifests from an assessment.

Nothing is written into the application's source tree: Dockerfiles use the
application folder as build context and carry their own
`<Dockerfile>.dockerignore` (BuildKit), so the application needs no changes.
"""
from __future__ import annotations

import copy
import json
import os
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath

import yaml

from .assess import AppAssessment, Component
from .harden import harden_manifests, namespace_manifest, write_app_security
from .rules import RULES_DIR, Context, Rule, load_rules, run_rule

CONTAINER_PORT = 8080
SAFE_NAME = re.compile(r"[^a-z0-9-]+")


IMAGES_LOCK = RULES_DIR / "images.lock.yaml"


def images_lock() -> dict:
    """Patched base image tags chosen by `containerizer images --update` (CONTAINERIZER_IMAGES_LOCK=0 ignores it)."""
    if os.environ.get("CONTAINERIZER_IMAGES_LOCK", "1") == "0" or not IMAGES_LOCK.exists():
        return {}
    return (yaml.safe_load(IMAGES_LOCK.read_text()) or {}).get("images") or {}


@lru_cache(maxsize=1)
def images() -> dict:
    lock = images_lock()

    def sub(v):
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        if isinstance(v, str) and v in lock:
            return lock[v]["tag"]
        return v
    return sub(yaml.safe_load((RULES_DIR / "images.yaml").read_text()))


_DIGESTS: dict[str, str | None] = {}


def resolve_digest(ref: str) -> str | None:
    """Registry digest of an image tag (multi-arch index digest), via docker buildx."""
    import subprocess
    locked = {e["tag"]: e.get("digest") for e in images_lock().values()}
    if ref not in _DIGESTS and locked.get(ref):
        _DIGESTS[ref] = locked[ref]
    if ref not in _DIGESTS:
        try:
            p = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest.Digest}}"],
                               capture_output=True, text=True, timeout=120)
            d = p.stdout.strip().strip('"')
            _DIGESTS[ref] = d if p.returncode == 0 and d.startswith("sha256:") else None
        except (OSError, subprocess.TimeoutExpired):
            _DIGESTS[ref] = None
    return _DIGESTS[ref]


def pin_digests(dockerfile: str) -> str:
    """Pin every base image to an immutable digest, keeping the tag for readability."""
    def sub(m):
        ref = m.group(2)
        if "@" in ref or ref.lower() in ("scratch",) or re.fullmatch(r"[a-z][\w-]*", ref):   # stage names
            return m.group(0)
        d = resolve_digest(ref)
        return f"{m.group(1)}{ref}@{d}" if d else m.group(0)
    return re.sub(r"^((?:FROM\s+(?:--platform=\S+\s+)?)|(?:COPY\s+(?:--\w+=\S+\s+)*?--from=))(\S+)", sub,
                  dockerfile, flags=re.M)


def target_tfm() -> str:
    """TFM of the runtime line the images run (images.yaml dotnet.version)."""
    return "net" + str(images()["dotnet"].get("version", "10.0"))


def _tfm_major(tfm: str) -> int:
    """net10.0 -> 10, netcoreapp3.1 -> 3, net6.0-windows -> 6; .NET Framework (net48) -> 0."""
    m = re.match(r"net(?:coreapp)?(\d+)\.\d", tfm or "")
    return int(m.group(1)) if m else 0


def k8s_name(s: str) -> str:
    s = SAFE_NAME.sub("-", s.lower().replace(".", "-")).strip("-")
    return s[:63].rstrip("-") or "app"


def buildable(c: Component) -> bool:
    """Can we produce a Linux container for this component (perhaps after code changes)?"""
    if c.tier != "server":
        return False
    if c.verdict == "blocker":
        return False
    if c.project.kind_hint == "dotnet":
        return c.project.is_core and bool(c.project.best_core_tfm())
    return c.project.kind_hint in ("node", "python", "go", "java")


# --------------------------------------------------------------------------- plan

def default_plan(c: Component) -> dict:
    p = c.project
    tfm = p.best_core_tfm() if p.kind_hint == "dotnet" else None
    plan = {
        "component": c.name,
        "kind": p.kind_hint,
        "role": c.role,
        "project": p.rel.replace("\\", "/"),
        "tfm": tfm,
        "multi_target": len(p.tfms) > 1,
        "strategy": "rollforward",
        "base": "chiseled",
        "add_packages": [],
        "env": {},
        "add_writable": ["/tmp"],
        "publish_args": [],
        "remove_files": [],
        "single_replica": False,
        "port": CONTAINER_PORT if c.role in ("web", "spa") else None,
        "health": c.facts.get("health"),
        "entry": c.facts.get("entry"),
        "spa_root": c.facts.get("spa_root"),
        "args": [],
        "applied": [],
    }
    for d in c.facts.get("writable_dirs", []) or []:
        plan["add_writable"].append(d)
    if c.role == "web" and p.kind_hint == "dotnet":
        plan["env"]["ASPNETCORE_HTTP_PORTS"] = str(CONTAINER_PORT)
        for i, ep in enumerate(c.facts.get("kestrel_endpoints", []) or []):
            # Kestrel endpoints from appsettings win over ASPNETCORE_HTTP_PORTS; re-point them
            plan["env"][f"Kestrel__Endpoints__{ep}__Url"] = f"http://+:{CONTAINER_PORT + i}"
    if p.kind_hint == "dotnet":
        _repoint_config(plan, c.facts)
        plan["env"]["DOTNET_ENVIRONMENT"] = "Production"
        if c.role == "web":
            plan["env"]["ASPNETCORE_ENVIRONMENT"] = "Production"
        if tfm and _tfm_major(tfm) < _tfm_major(target_tfm()):
            plan["env"]["DOTNET_ROLL_FORWARD"] = "Major"     # run on the supported runtime line
    return plan


def reason_comments(plan: dict) -> list[str]:
    """Dockerfile header lines that explain each non-default build or run decision."""
    import textwrap
    out = []
    for r in plan.get("reasons") or []:
        out += textwrap.wrap(f"{r['rule']}: {r['why']}", 100, initial_indent="# - ", subsequent_indent="#   ")
        out += [f"#   see {u}" for u in r.get("refs") or []]
    return (["#", "# Why this differs from a default build:"] + out) if out else []


def add_reason(plan: dict, rule: str, why: str, refs: list[str] | None = None) -> None:
    """Record why the build or run setup differs from the default, for the Dockerfile and plan.json."""
    why = " ".join((why or "").split())
    rs = plan.setdefault("reasons", [])
    if why and not any(r["rule"] == rule for r in rs):
        rs.append({"rule": rule, "why": why, **({"refs": list(refs)} if refs else {})})


CONFIG_DOCS = "https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/"


def _repoint_config(plan: dict, facts: dict) -> None:
    """Override configuration through environment variables instead of editing the app:
    file-only Serilog sinks log to stdout, Windows paths move under /data (a volume)."""
    for key in facts.get("listen_url_settings") or []:
        plan["env"][key.replace(":", "__")] = f"http://+:{CONTAINER_PORT}"
        add_reason(plan, "config-listen-url", f"Listen addresses from configuration are overridden to port "
                   f"{CONTAINER_PORT} with environment variables (they take precedence over appsettings.json).",
                   ["https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints"])
    for var in facts.get("nlog_env_folders") or []:
        plan["env"][var] = "/app/logs"
        if "logs" not in plan["add_writable"]:
            plan["add_writable"].append("logs")
    sinks = set(facts.get("serilog_file_sinks") or [])
    for i in sorted(sinks):
        plan["env"][f"Serilog__WriteTo__{i}__Name"] = "Console"
        add_reason(plan, "config-serilog-console", "Serilog file sinks are switched to the console with an "
                   "environment variable, so the cluster collects the logs from stdout.",
                   ["https://github.com/serilog/serilog-sinks-console", CONFIG_DOCS])
    for key, val in sorted((facts.get("windows_paths") or {}).items()):
        parts = key.split(":")
        if parts[:2] == ["Serilog", "WriteTo"] and len(parts) > 2 and parts[2].isdigit() and int(parts[2]) in sinks:
            continue
        segs = [s for s in re.split(r"[\\/]+", val) if s]
        segs = segs[1:] if re.fullmatch(r"[A-Za-z]:", segs[0]) else segs[2:]   # drop drive or \\server\share
        is_file = bool(re.search(r"\.[A-Za-z]\w{0,7}$", segs[-1])) if segs else False
        if any(x.lower() in ("program files", "program files (x86)") for x in segs[:1]) or val.lower().endswith(".exe"):
            # an installed tool: use the Linux binary of the same name from PATH (see native packages)
            if is_file:
                name = segs[-1]
                if name.lower().endswith(".dll"):     # native library: Linux naming
                    name = "lib" + name[:-4] + ".so"
                plan["env"]["__".join(parts)] = re.sub(r"\.exe$", "", name, flags=re.I)
            continue
        if is_file and re.search(r"\.(pem|pfx|p12|key|crt|cer|snk|jks|keytab)$", segs[-1], re.I):
            # keys and certificates come from a Kubernetes Secret volume, never from the image
            plan["env"]["__".join(parts)] = f"/secrets/{segs[-1]}"
            if segs[-1] not in plan.setdefault("secret_files", []):
                plan["secret_files"].append(segs[-1])
            continue
        folder = "/data/" + "/".join(k8s_name(s) for s in (segs[:-1] if is_file else segs)) if segs else "/data"
        folder = folder.rstrip("/") or "/data"
        plan["env"]["__".join(parts)] = f"{folder}/{segs[-1]}" if is_file else folder
        add_reason(plan, "config-windows-paths", "Windows paths in configuration (drive letters, UNC shares) are "
                   "overridden with environment variables to folders under /data, which the manifests mount as "
                   "volumes; the application code is not changed.", [CONFIG_DOCS])
        if folder not in plan["add_writable"]:
            plan["add_writable"].append(folder)
    for item in facts.get("nlog_folder_settings") or []:
        # trailing slash: NLog targets append "\\file.log", which on Linux then stays inside the folder
        key = item.replace(".", "__")
        plan["env"][key] = plan["env"].get(key, "/app/logs").rstrip("/") + "/"
        add_reason(plan, "config-nlog-folder", "NLog log folders get a trailing '/' so that file names the config "
                   "joins with a backslash still land inside the folder on Linux.",
                   ["https://github.com/NLog/NLog/wiki/File-target"])
        if plan["env"][key] == "/app/logs/" and "logs" not in plan["add_writable"]:
            plan["add_writable"].append("logs")


def apply_plan_rules(plan: dict, repo, c: Component, rules: list[Rule]) -> dict:
    for r in rules:
        if r.phase != "plan":
            continue
        ctx = Context(repo, None if r.scope == "repo" else c.project, c.role)
        if run_rule(r, ctx):
            merge_plan(plan, r.plan)
            plan["applied"].append(r.id)
            add_reason(plan, r.id, r.why, getattr(r, "refs", None))
    return plan


def merge_plan(plan: dict, patch: dict) -> dict:
    for k, v in (patch or {}).items():
        if k in ("add_packages", "add_writable", "publish_args", "remove_files", "args"):
            for x in v:
                if x not in plan[k]:
                    plan[k].append(x)
        elif k == "env":
            plan["env"].update({kk: str(vv) for kk, vv in v.items()})
        else:
            plan[k] = v
    if plan["add_packages"]:
        plan["base"] = "full"
    return plan


def make_plan(a: AppAssessment, c: Component, rules: list[Rule] | None = None, extra: dict | None = None) -> dict:
    rules = rules if rules is not None else load_rules()
    plan = apply_plan_rules(default_plan(c), a.repo, c, rules)
    if extra:
        merge_plan(plan, extra)
    return plan


# --------------------------------------------------------------------------- Dockerfiles

DOCKERIGNORE = """# generated by containerizer - build context is the application root
**/bin/
**/obj/
**/node_modules/
**/.vs/
**/.git
**/TestResults/
**/*.user
**/*.pfx
**/*.snk.private
**/secrets*.json
**/appsettings.Development.json
**/.env
**/*.ps1
!**/ClientApp/**/*.ps1
"""


def _writable_abs(w: str) -> str:
    return w if w.startswith("/") else "/app/" + w.strip("/")


def dockerfile_dotnet(plan: dict) -> str:
    im = images()["dotnet"]
    uid = im["app_uid"]
    worker = plan["role"] != "web" and not plan.get("aspnet_runtime")
    full = plan["base"] == "full"
    base = im[("runtime" if worker else "aspnet") + ("_full" if full else "")]
    proj = plan["project"]
    tfm = plan["tfm"]
    # RID-specific publish keeps the image lean; "portable" avoids RID restore graphs that old
    # netstandard1.x packages break (NU1605) and works for any CPU architecture
    rid = plan.get("rid") or "linux-x64"
    rid_arg = "" if rid == "portable" else f" -p:RuntimeIdentifier={rid}"
    pub = ["-c Release", "-o /out", "-p:UseAppHost=false"] + ([rid_arg.strip(), "--self-contained false"] if rid_arg else [])
    target = target_tfm()
    retarget = plan["strategy"] == "retarget" and tfm and _tfm_major(tfm) != _tfm_major(target)
    if retarget:
        # the entry project is retargeted in the build stage's copy of its .csproj; a global
        # -p:TargetFramework would also retarget its netstandard libraries and break their restore.
        # Only when the TFM is not in the .csproj (Directory.Build.props) is the global property used.
        pub.append("$TFP")
    elif plan["multi_target"] or (tfm and "-" in tfm):
        pub.append(f"-f {tfm}")
    pub += plan["publish_args"]
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, {tfm})",
             *reason_comments(plan),
             f"FROM {im['sdk']} AS build"]
    if plan.get("spa_root"):
        node = images()["node"]["build"]
        lines += [f"COPY --from={node} /usr/local/bin/node /usr/local/bin/node",
                  f"COPY --from={node} /usr/local/lib/node_modules /usr/local/lib/node_modules",
                  "RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \\",
                  " && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx"]
    lines += ["WORKDIR /src", "COPY . ."]
    for f in plan["remove_files"]:
        lines.append(f"RUN find . -name '{f}' -not -path '*/node_modules/*' -delete")
    if plan.get("spa_root"):
        spa = str(PurePosixPath(proj).parent / plan["spa_root"])
        # build the front end once before dotnet publish: publish snapshots wwwroot (static web
        # assets) before the project's own npm target runs, and a bundler that renames hashed files
        # would otherwise leave publish copying files that no longer exist. During publish, npm is
        # then a no-op shim so the project's npm target cannot rebuild under new file names.
        lines += ["RUN --mount=type=secret,id=ca,required=false \\",
                  "    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \\",
                  f'    if grep -qs \'"build"\' "{spa}/package.json"; then cd "{spa}" && \\',
                  "      if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm run build && \\",
                  "      mkdir -p /opt/npm-prebuilt && printf '#!/bin/sh\\necho \"npm $*: skipped, the front end was built before dotnet publish\" >&2\\n' \\",
                  "        > /opt/npm-prebuilt/npm && chmod +x /opt/npm-prebuilt/npm; fi"]
    restore_tfm = " $TFP" if retarget else ""
    lines += ["# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies",
              'RUN --mount=type=cache,target=/root/.nuget/packages --mount=type=secret,id=ca,required=false \\',
              '    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \\',
              *([f"    TFP=''; if grep -qE '<TargetFrameworks?[ >]' \"{proj}\"; then \\",
                 f"      sed -i -E 's#<TargetFrameworks?([^>]*)>[^<]*</TargetFrameworks?>#<TargetFramework\\1>{target}</TargetFramework>#' \"{proj}\"; \\",
                 f"    else TFP='-p:TargetFramework={target} -p:TargetFrameworks={target}'; fi; \\"] if retarget else []),
              *(["    export PATH=/opt/npm-prebuilt:$PATH; \\"] if plan.get("spa_root") else []),
              f'    dotnet restore "{proj}"{rid_arg}{restore_tfm} \\',
              f' && dotnet publish "{proj}" --no-restore {" ".join(pub)}']
    writable = sorted({_writable_abs(w) for w in plan["add_writable"]})
    if writable:
        lines.append("RUN mkdir -p " + " ".join("/writable" + w for w in writable))
    lines += ["", f"FROM {base} AS final"]
    if full:
        pk = " ".join(sorted(plan["add_packages"]))
        lines += ["RUN apt-get update \\",
                  f" && apt-get install -y --no-install-recommends {pk} \\",
                  " && rm -rf /var/lib/apt/lists/*"] if pk else []
    lines += ["WORKDIR /app",
              "# application files stay owned by root: read-only for the app user",
              "COPY --from=build /out ."]
    for w in writable:
        lines.append(f"COPY --from=build --chown={uid}:{uid} /writable{w} {w}")
    env = dict(plan["env"])
    if env:
        lines.append("ENV " + " \\\n    ".join(f'{k}="{v}"' for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    entry = json.dumps(["dotnet", plan["entry"]] + plan["args"])
    lines.append(f"ENTRYPOINT {entry}")
    return "\n".join(lines) + "\n"


def dockerfile_spa(plan: dict, facts: dict) -> str:
    n = images()["node"]
    dist = facts.get("dist_dir") or "dist"
    proj_dir = str(Path(plan["project"]).parent)
    return "\n".join([
        "# syntax=docker/dockerfile:1.7",
        f"# Generated by containerizer for {plan['component']} (single-page app)",
        f"FROM {n['build']} AS build",
        "WORKDIR /src",
        f"COPY {proj_dir}/package*.json ./",
        "RUN --mount=type=cache,target=/root/.npm --mount=type=secret,id=ca,required=false \\",
        "    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca npm_config_cafile=/run/secrets/ca; fi; \\",
        "    npm ci --no-audit --no-fund || npm install --no-audit --no-fund",
        f"COPY {proj_dir}/ .",
        "RUN npm run build",
        f"RUN if [ -d '{dist}/browser' ]; then cp -r '{dist}/browser' /site; else cp -r '{dist}' /site; fi",
        "",
    ] + _static_site_stage("/site")) + "\n"


def _static_site_stage(site: str, extra: str = "") -> list[str]:
    n = images()["node"]
    return [
        f"FROM {n['static']} AS final",
        "# nginx-unprivileged runs as uid 101 and listens on 8080",
        f"COPY --from=build {site} /usr/share/nginx/html",
        "RUN printf 'server {\\n listen 8080;\\n root /usr/share/nginx/html;\\n" + extra
        + " location / { try_files $uri $uri/ /index.html; }\\n location = /healthz { return 200 \"ok\"; }\\n}\\n' > /etc/nginx/conf.d/default.conf",
        "EXPOSE 8080",
    ]


def dockerfile_blazor_wasm(plan: dict) -> str:
    """Standalone Blazor WebAssembly: static files after `dotnet publish`, served by nginx."""
    im = images()["dotnet"]
    proj = plan["project"]
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} (Blazor WebAssembly, static files)",
             f"FROM {im['sdk']} AS build", "WORKDIR /src", "COPY . ."]
    for f in plan["remove_files"]:
        lines.append(f"RUN find . -name '{f}' -not -path '*/node_modules/*' -delete")
    lines += ["RUN --mount=type=cache,target=/root/.nuget/packages --mount=type=secret,id=ca,required=false \\",
              "    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi; \\",
              f'    dotnet publish "{proj}" -c Release -o /out {" ".join(plan["publish_args"])}'.rstrip(), ""]
    # framework files: precompressed variants, and a real 404 instead of the SPA fallback
    extra = " gzip_static on;\\n location /_framework/ { try_files $uri =404; }\\n"
    return "\n".join(lines + _static_site_stage("/out/wwwroot", extra)) + "\n"


def dockerfile_for(plan: dict, c: Component) -> str:
    if c.role == "spa":
        return dockerfile_blazor_wasm(plan) if c.project.kind_hint == "dotnet" else dockerfile_spa(plan, c.facts)
    return dockerfile_dotnet(plan)


def dockerfile_windows(c: Component) -> str:
    w = images()["windows"]
    p = c.project
    web = c.role == "web"
    proj = p.rel.replace("/", "\\")
    lines = ["# escape=`",
             f"# Generated by containerizer: Windows Server Core stop-gap for {c.name} (.NET Framework)",
             "# Runs on Windows nodes only. Prefer porting to modern .NET for Linux.",
             f"FROM {w['framework_sdk']} AS build",
             "WORKDIR C:\\src", "COPY . ."]
    sln = (p.properties or {}).get("WebSiteProject")
    if sln:
        # ASP.NET Web Site (no .csproj): building the solution fills the site's Bin with its project
        # references, then aspnet_compiler precompiles the folder (as "Publish Web Site" does)
        site = str(PurePosixPath(p.rel).parent).replace("/", "\\")
        sln = sln.replace("/", "\\")
        lines += [f'RUN nuget restore "{sln}" ; msbuild "{sln}" /p:Configuration=Release /m',
                  f'RUN C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe -v / '
                  f'-p "C:\\src\\{site}" -u -fixednames C:\\out']
    else:
        lines.append(f'RUN nuget restore "{proj}" ; msbuild "{proj}" /p:Configuration=Release /p:DeployOnBuild={str(web).lower()} '
                     f'/p:WebPublishMethod=FileSystem /p:PublishUrl=C:\\out /p:OutDir=C:\\out\\ /m')
    lines += ["", f"FROM {w['framework_aspnet' if web else 'framework_runtime']}"]
    if web:
        lines += ["WORKDIR C:\\inetpub\\wwwroot", "COPY --from=build C:\\out .", "EXPOSE 80"]
    else:
        lines += ["WORKDIR C:\\app", "COPY --from=build C:\\out .",
                  f'ENTRYPOINT ["C:\\\\app\\\\{p.assembly_name}.exe"]']
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- Kubernetes

def k8s_manifests(a: AppAssessment, c: Component, plan: dict, image: str) -> list[dict]:
    name = k8s_name(c.name)
    labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": k8s_name(a.name)}
    env = [{"name": k, "value": v} for k, v in sorted(plan["env"].items())]
    secret_name = f"{name}-secrets"
    secret_keys = []
    for cs in c.facts.get("connection_strings", []) or []:
        key = f"ConnectionStrings__{cs}"
        secret_keys.append(key)
        env.append({"name": key, "valueFrom": {"secretKeyRef": {"name": secret_name, "key": key, "optional": True}}})
    for s in c.facts.get("secret_settings", []) or []:
        key = s.replace(":", "__")
        secret_keys.append(key)
        env.append({"name": key, "valueFrom": {"secretKeyRef": {"name": secret_name, "key": key, "optional": True}}})
    volumes, mounts = [], []
    for i, w in enumerate(sorted({_writable_abs(w) for w in plan["add_writable"]})):
        vname = f"w{i}-" + k8s_name(w.split("/")[-1] or "root")[:40]
        persistent = any(x in w.lower() for x in ("app_data", "data", "keys", "archive", "store", "uploads", "documents"))
        if persistent and plan.get("single_replica"):
            volumes.append({"name": vname, "persistentVolumeClaim": {"claimName": f"{name}-{vname}"}})
        else:
            volumes.append({"name": vname, "emptyDir": {}})
        mounts.append({"name": vname, "mountPath": w})
    if plan.get("secret_files"):
        volumes.append({"name": "secret-files", "secret": {"secretName": f"{name}-files", "optional": True,
                                                           "defaultMode": 0o440}})
        mounts.append({"name": "secret-files", "mountPath": "/secrets", "readOnly": True})
    container = {
        "name": name, "image": image, "imagePullPolicy": "IfNotPresent", "env": env,
        "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"memory": "512Mi"}},
        "volumeMounts": mounts,
    }
    if plan.get("port"):
        container["ports"] = [{"name": "http", "containerPort": plan["port"]}]
        probe = {"httpGet": {"path": plan["health"], "port": "http"}} if plan.get("health") else {"tcpSocket": {"port": "http"}}
        container["readinessProbe"] = {**probe, "periodSeconds": 10}
        container["livenessProbe"] = {**probe, "periodSeconds": 20, "initialDelaySeconds": 20}
        container["startupProbe"] = {**probe, "periodSeconds": 5, "failureThreshold": 30}
    pod = {"securityContext": {"runAsNonRoot": True, "fsGroup": images()["dotnet"]["app_uid"],
                               "seccompProfile": {"type": "RuntimeDefault"}},
           "automountServiceAccountToken": False, "containers": [container], "volumes": volumes}
    docs: list[dict] = []
    oneshot = c.facts.get("oneshot_arg") if c.role == "console" else None
    if c.role == "console" and not oneshot:
        oneshot = ""
    if c.role == "console":
        pod["restartPolicy"] = "OnFailure"
        # one CronJob per sub-command (schedules are placeholders: take them from the old Task Scheduler)
        for cmd in (c.facts.get("commands") or [oneshot]):
            jpod = copy.deepcopy(pod)
            if cmd:
                jpod["containers"][0]["args"] = [cmd]
            jname = name if cmd == oneshot else k8s_name(f"{name}-{cmd}")
            docs.append({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": jname, "labels": labels},
                         "spec": {"schedule": "0 2 * * *", "concurrencyPolicy": "Forbid",
                                  "jobTemplate": {"spec": {"template": {"metadata": {"labels": labels}, "spec": jpod}}}}})
    else:
        docs.append({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "labels": labels},
                     "spec": {"replicas": 1 if plan.get("single_replica") or c.role != "web" else 2,
                              "strategy": {"type": "Recreate"} if plan.get("single_replica") else {"type": "RollingUpdate"},
                              "selector": {"matchLabels": labels},
                              "template": {"metadata": {"labels": labels}, "spec": pod}}})
    if plan.get("port"):
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "labels": labels},
                     "spec": {"selector": labels, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}})
    for v in volumes:
        if "persistentVolumeClaim" in v:
            docs.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                         "metadata": {"name": v["persistentVolumeClaim"]["claimName"], "labels": labels},
                         "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}})
    if secret_keys:
        docs.append({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret_name, "labels": labels},
                     "type": "Opaque", "stringData": {k: "" for k in secret_keys},
                     "_comment": "fill in values out of band (sealed-secrets / external-secrets); never commit real values"})
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                 "metadata": {"name": f"{name}-ingress", "labels": labels},
                 "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress"],
                          "ingress": [{"ports": [{"port": plan["port"]}]}] if plan.get("port") else []}})
    # security baseline + the exceptions this component needs (rules/60-security.yaml)
    plan["hardening_exceptions"] = harden_manifests(docs, a.repo, c, plan, name)
    return docs


class _NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _yaml_docs(docs: list[dict]) -> str:
    out = []
    for d in docs:
        d = dict(d)
        comment = d.pop("_comment", None)
        s = yaml.dump(d, Dumper=_NoAlias, sort_keys=False, default_flow_style=False)
        out.append((f"# {comment}\n" if comment else "") + s)
    return "---\n".join(out)


# --------------------------------------------------------------------------- app

def generate_app(a: AppAssessment, out: Path, rules: list[Rule] | None = None, registry: str = "registry.local",
                 plans: dict | None = None, pin: bool = False, gitops=None) -> list[Path]:
    from .gitops import gitops_manifests, image_setters, readme
    from .report import migration_markdown

    rules = rules if rules is not None else load_rules()
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    all_k8s = []
    images: list[tuple[str, str]] = []
    comp_docs: dict[str, list[dict]] = {}
    for c in a.components:
        cdir = out / k8s_name(c.name)
        if buildable(c):
            plan = (plans or {}).get(c.name) or make_plan(a, c, rules)
            cdir.mkdir(parents=True, exist_ok=True)
            if c.role == "spa":
                plan["port"], plan["health"] = 8080, "/healthz"
            elif c.project.kind_hint != "dotnet":
                continue
            df = dockerfile_for(plan, c)
            if pin:
                df = pin_digests(df)
            (cdir / "Dockerfile").write_text(df)
            (cdir / "Dockerfile.dockerignore").write_text(DOCKERIGNORE)
            image = f"{registry}/{k8s_name(a.name)}/{k8s_name(c.name)}:latest"
            docs = k8s_manifests(a, c, plan, image)
            images.append((c.name, image))
            all_k8s += docs
            comp_docs[k8s_name(c.name)] = docs
            (cdir / "k8s.yaml").write_text(_yaml_docs(docs))
            (cdir / "plan.json").write_text(json.dumps(plan, indent=2))
            written += [cdir / "Dockerfile", cdir / "Dockerfile.dockerignore", cdir / "k8s.yaml", cdir / "plan.json"]
        elif c.tier == "server" and c.project.is_netfx and c.windows_container_ok and c.verdict != "blocker":
            cdir.mkdir(parents=True, exist_ok=True)
            (cdir / "Dockerfile.windows").write_text(dockerfile_windows(c))
            (cdir / "Dockerfile.windows.dockerignore").write_text(DOCKERIGNORE)
            written += [cdir / "Dockerfile.windows"]
    if all_k8s:
        ns_doc = namespace_manifest(k8s_name(a.name))
        (out / "namespace.yaml").write_text(_yaml_docs([ns_doc]))
        # namespace-level security (default deny, quota, limits), HARDENING.md and the cluster/ kit
        sec, sec_docs = write_app_security(out, k8s_name(a.name), comp_docs, registry, _yaml_docs)
        (out / "kustomization.yaml").write_text(yaml.safe_dump(
            {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
             "namespace": k8s_name(a.name),
             "resources": ["namespace.yaml"] + sec + sorted(f"{d.name}/k8s.yaml" for d in out.iterdir() if (d / "k8s.yaml").exists())},
            sort_keys=False) + image_setters(k8s_name(a.name), images))
        written += [out / "namespace.yaml", out / "kustomization.yaml", out / "HARDENING.md"] + [out / r for r in sec]
        kinds = sorted({(d["apiVersion"], d["kind"]) for d in all_k8s + sec_docs if isinstance(d, dict) and d.get("kind")})
        for rel, docs in gitops_manifests(a, kinds, images, ns_doc, gitops, registry).items():
            f = out / "gitops" / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(_yaml_docs(docs))
            written.append(f)
        (out / "gitops" / "README.md").write_text(readme(a, gitops))
        written.append(out / "gitops" / "README.md")
    (out / "MIGRATION.md").write_text(migration_markdown(a))
    written.append(out / "MIGRATION.md")
    return written
