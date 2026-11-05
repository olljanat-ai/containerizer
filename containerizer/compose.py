"""Docker Compose output: `compose.yaml` per application, next to `kustomization.yaml`.

For teams that run their first containers on one Docker or Podman host, a PaaS that takes Compose, or a
developer's machine. It is made from the same hardened pod specs as the components' `k8s.yaml` (after
harden.harden_manifests), so the security baseline and each component's hardening exceptions carry over
where Compose has an equivalent:

  runAsUser/runAsGroup        -> user
  readOnlyRootFilesystem      -> read_only
  capabilities drop/add       -> cap_drop / cap_add
  allowPrivilegeEscalation    -> security_opt no-new-privileges:true
  seccomp/AppArmor RuntimeDefault -> Docker's defaults (nothing to set; the lint refuses "unconfined")
  emptyDir (sizeLimit)        -> tmpfs with size
  PersistentVolumeClaim       -> named volume
  Secret volume               -> read-only bind of <component>/secrets/<volume>/ (the Data Protection key
                                 ring: a named volume the app keeps its own keys in)
  secretKeyRef env            -> env_file <component>/secrets.env (not committed; secrets.env.example
                                 lists the keys, no values)
  memory request/limit, cpu   -> mem_reservation / mem_limit / cpus
  probes                      -> healthcheck where the image has a program to run it (rules/compose.yaml)
  Service                     -> published port, on BIND_ADDRESS (loopback by default)
  NetworkPolicy egress none   -> only on the internal network (no route out)
  CronJob                     -> a service under the "jobs" profile, run with `docker compose run --rm`

The application's code is not touched: everything is configuration around the same image.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from .rules import RULES_DIR

RULES_FILE = RULES_DIR / "compose.yaml"
COMPONENT_LABEL = "containerizer.io/component"
WAIVES_LABEL = "containerizer.io/waives"
LAB_PROFILE = "lab"
JOBS_PROFILE = "jobs"
SECRETS_ENV = "secrets.env"
INTERNAL_NET = "internal"
EDGE_NET = "edge"


def rules() -> dict:
    return yaml.safe_load(RULES_FILE.read_text()) or {}


def _qty_bytes(q) -> int | None:
    """Kubernetes quantity (512Mi, 1Gi, 256M, 1000) -> bytes."""
    if q in (None, ""):
        return None
    m = re.fullmatch(r"\s*([0-9.]+)\s*([KMGTE]i?|k)?\s*", str(q))
    if not m:
        return None
    n, unit = float(m.group(1)), m.group(2) or ""
    mult = {"": 1, "k": 1000, "K": 1000, "M": 1000 ** 2, "G": 1000 ** 3, "T": 1000 ** 4, "E": 1000 ** 6,
            "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3, "Ti": 1024 ** 4, "Ei": 1024 ** 6}[unit]
    return int(n * mult)


def _mem(q) -> str | None:
    """Kubernetes memory quantity -> Compose byte value (512m, 1g)."""
    b = _qty_bytes(q)
    if b is None:
        return None
    for unit, size in (("g", 1024 ** 3), ("m", 1024 ** 2), ("k", 1024)):
        if b % size == 0:
            return f"{b // size}{unit}"
    return f"{b}b"


def _cpus(q) -> str | None:
    if q in (None, ""):
        return None
    s = str(q)
    v = float(s[:-1]) / 1000 if s.endswith("m") else float(s)
    return f"{v:g}"


def final_base(dockerfile: str) -> str:
    froms = re.findall(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", dockerfile or "")
    return froms[-1] if froms else ""


def _healthcheck(container: dict, base: str, cfg: dict) -> tuple[dict | None, dict | None]:
    """(healthcheck, x-containerizer-probe) from the container's probes."""
    ready = container.get("readinessProbe") or container.get("livenessProbe")
    if not ready:
        return None, None
    http = ready.get("httpGet")
    port = None
    for p in container.get("ports") or []:
        if http and http.get("port") in (p.get("name"), p.get("containerPort")):
            port = p.get("containerPort")
    port = port or ((container.get("ports") or [{}])[0].get("containerPort"))
    probe = {"http": http.get("path", "/"), "port": port} if http else {"tcp": port}
    if not http or not port:
        return None, probe
    url = f"http://127.0.0.1:{port}{http.get('path', '/')}"
    test = None
    for h in cfg.get("healthchecks") or []:
        if re.search(h["image"], base or ""):
            test = [str(x).replace("{url}", url) for x in h["test"]]
            break
    if not test:
        return None, probe
    start = container.get("startupProbe") or {}
    hc = {"test": test, "interval": f"{int(ready.get('periodSeconds', 10))}s",
          "timeout": f"{int(ready.get('timeoutSeconds', 5))}s", "retries": int(ready.get("failureThreshold", 3))}
    if start:
        hc["start_period"] = f"{int(start.get('periodSeconds', 5)) * int(start.get('failureThreshold', 30))}s"
    return hc, None


def _env_name(component: str) -> str:
    return re.sub(r"[^A-Z0-9]", "_", component.upper())


def _workloads(docs: list[dict]) -> list[tuple[dict, dict, str | None]]:
    """(document, pod template, schedule) of the component's Deployments and CronJobs."""
    out = []
    for d in docs:
        if d.get("kind") in ("Deployment", "StatefulSet"):
            out.append((d, d["spec"]["template"], None))
        elif d.get("kind") == "CronJob":
            out.append((d, d["spec"]["jobTemplate"]["spec"]["template"], d["spec"].get("schedule")))
    return out


def component_services(component: str, docs: list[dict], *, base: str = "", build: dict | None = None,
                       ingress: bool = False, host_port: int | None = None) -> tuple[dict, dict, dict]:
    """(services, named volumes, files) for one component's hardened Kubernetes documents.
    `files`: {relative path: text} written next to compose.yaml (secrets.env.example)."""
    cfg = rules()
    services: dict = {}
    volumes: dict = {}
    secret_keys: list[str] = []
    egress = True
    for d in docs:
        if d.get("kind") == "NetworkPolicy" and "Egress" in ((d.get("spec") or {}).get("policyTypes") or []):
            egress = ((d.get("metadata") or {}).get("annotations") or {}).get("containerizer.io/egress") != "none"
    for doc, tpl, schedule in _workloads(docs):
        pod = tpl.get("spec") or {}
        meta = tpl.get("metadata") or {}
        psc = pod.get("securityContext") or {}
        c = pod["containers"][0]
        sc = c.get("securityContext") or {}
        name = doc["metadata"]["name"]
        svc: dict = {"image": c["image"]}
        if build:
            svc["build"] = dict(build)
        if c.get("command"):
            svc["entrypoint"] = list(c["command"])
        if c.get("args"):
            svc["command"] = list(c["args"])
        uid = sc.get("runAsUser", psc.get("runAsUser"))
        gid = sc.get("runAsGroup", psc.get("runAsGroup"))
        if uid is not None:
            svc["user"] = f"{uid}:{gid}" if gid is not None else str(uid)
        svc["read_only"] = sc.get("readOnlyRootFilesystem") is True
        caps = sc.get("capabilities") or {}
        svc["cap_drop"] = list(caps.get("drop") or [])
        if caps.get("add"):
            svc["cap_add"] = list(caps["add"])
        sec = []
        if sc.get("allowPrivilegeEscalation") is False:
            sec.append("no-new-privileges:true")
        svc["security_opt"] = sec
        env, refs = {}, []
        for e in c.get("env") or []:
            if "value" in e:
                env[e["name"]] = str(e["value"])
            elif ((e.get("valueFrom") or {}).get("secretKeyRef")):
                refs.append(e["name"])
        if env:
            svc["environment"] = env
        if refs:
            svc["env_file"] = [{"path": f"{component}/{SECRETS_ENV}", "required": False}]
            secret_keys += [k for k in refs if k not in secret_keys]
        # volumes
        vols = {v["name"]: v for v in pod.get("volumes") or []}
        tmpfs, mounts = [], []
        for m in c.get("volumeMounts") or []:
            v = vols.get(m["name"]) or {}
            path = m["mountPath"]
            if "emptyDir" in v:
                size = _mem((v["emptyDir"] or {}).get("sizeLimit"))
                tmpfs.append(path + ":" + ",".join(([f"size={size}"] if size else []) + ["mode=1777"]))
            elif "persistentVolumeClaim" in v:
                vn = v["persistentVolumeClaim"]["claimName"]
                volumes[vn] = {}
                mounts.append({"type": "volume", "source": vn, "target": path})
            elif "secret" in v and (v["secret"].get("secretName") or "").endswith("-dataprotection"):
                # one host, one replica: the app keeps the key ring it makes itself, across restarts
                vn = f"{component}-dataprotection"
                volumes[vn] = {}
                mounts.append({"type": "volume", "source": vn, "target": path})
            elif "secret" in v or "configMap" in v:
                mounts.append({"type": "bind", "source": f"./{component}/secrets/{m['name']}", "target": path,
                               "read_only": True, "bind": {"create_host_path": True}})
            else:
                vn = f"{component}-{m['name']}"
                volumes[vn] = {}
                mounts.append({"type": "volume", "source": vn, "target": path})
        if tmpfs:
            svc["tmpfs"] = tmpfs
        if mounts:
            svc["volumes"] = mounts
        res = c.get("resources") or {}
        lim, req = res.get("limits") or {}, res.get("requests") or {}
        if _mem(lim.get("memory")):
            svc["mem_limit"] = _mem(lim["memory"])
        if _mem(req.get("memory")):
            svc["mem_reservation"] = _mem(req["memory"])
        if _cpus(lim.get("cpu")):
            svc["cpus"] = _cpus(lim["cpu"])
        if cfg.get("pids_limit"):
            svc["pids_limit"] = int(cfg["pids_limit"])
        hc, probe = _healthcheck(c, base, cfg)
        if hc:
            svc["healthcheck"] = hc
        elif probe:
            svc["x-containerizer-probe"] = probe
        if ingress and c.get("ports") and schedule is None:
            cp = c["ports"][0]["containerPort"]
            var = f"{_env_name(component)}_PORT"
            svc["ports"] = [f"${{BIND_ADDRESS:-{cfg.get('bind_address', '127.0.0.1')}}}:${{{var}:-{host_port or cp}}}:{cp}"]
        svc["networks"] = [INTERNAL_NET] + ([EDGE_NET] if (egress or svc.get("ports")) else [])
        labels = {COMPONENT_LABEL: component}
        waives = (meta.get("annotations") or {}).get(WAIVES_LABEL)
        if waives:
            labels[WAIVES_LABEL] = waives
        svc["labels"] = labels
        if schedule is not None:
            svc["profiles"] = [JOBS_PROFILE]
            svc["restart"] = "no"
            svc["x-containerizer-schedule"] = schedule
        else:
            svc["restart"] = "unless-stopped"
        services[name] = svc
    files = {}
    if secret_keys:
        files[f"{component}/{SECRETS_ENV}.example"] = secrets_example(component, secret_keys)
    return services, volumes, files


def secrets_example(component: str, keys: list[str], hints: dict[str, str] | None = None) -> str:
    lines = [f"# {component}: the secret settings, the keys of its ExternalSecret in k8s.yaml.",
             f"# Copy to {SECRETS_ENV} (never commit it) and fill in the values; unset keys are left out.", ""]
    for k in keys:
        if hints and k in hints:
            lines.append(f"# with --profile lab: {hints[k]}")
        lines.append(f"{k}=")
    return "\n".join(lines) + "\n"


def lab_services(needed: list[str]) -> tuple[dict, dict, list[str]]:
    """(services, volumes, skipped) for the lab dependencies under the "lab" profile."""
    defs = rules().get("lab") or {}
    services, volumes, skipped = {}, {}, []
    for svc in needed:
        d = defs.get(svc)
        if not d:
            skipped.append(svc)
            continue
        vn = f"lab-{svc}-data"
        s = {"image": d["image"], "profiles": [LAB_PROFILE], "restart": "unless-stopped"}
        for k in ("entrypoint", "command"):
            if k in d:
                s[k] = d[k]
        if d.get("environment"):
            s["environment"] = {k: str(v) for k, v in d["environment"].items()}
        s["volumes"] = [{"type": "volume", "source": vn, "target": d["data"]}]
        s["security_opt"] = ["no-new-privileges:true"]
        if d.get("memory"):
            s["mem_limit"] = d["memory"]
        s["networks"] = [INTERNAL_NET]
        s["labels"] = {COMPONENT_LABEL: f"lab-{svc}"}
        services[svc] = s
        volumes[vn] = {}
    return services, volumes, skipped


def lab_hints(c, svc: str) -> dict[str, str]:
    """{env key: connection hint} for component `c` and lab service `svc` (secrets.env.example comments)."""
    from .labservices import _env_key, connection_keys
    d = (rules().get("lab") or {}).get(svc) or {}
    if not d.get("connection"):
        return {}
    conn = d["connection"].replace("{password}", "<LAB_PASSWORD>")
    return {_env_key(k): f"{_env_key(k)}={conn}" for k in connection_keys(c, svc, {svc: []})}


def compose_doc(app: str, services: dict, volumes: dict) -> dict:
    doc = {"name": app, "services": services}
    if volumes:
        doc["volumes"] = {k: volumes[k] or {} for k in sorted(volumes)}
    nets = {n for s in services.values() for n in s.get("networks") or []}
    doc["networks"] = {INTERNAL_NET: {"internal": True}}
    if EDGE_NET in nets:
        doc["networks"][EDGE_NET] = {}
    return doc


HEADER = """\
# Docker Compose for {app}, generated by containerizer from the same hardened specs as k8s.yaml.
# For one Docker or Podman host, a PaaS that runs Compose, or a local run (docs/compose.md):
#   cp .env.example .env              # and each <component>/secrets.env.example to secrets.env
#   docker compose up -d --build      # build from the application's source and start
#   docker compose --profile lab up   # with the lab dependencies (development only)
#   docker compose run --rm <job>     # a scheduled job (profile "jobs"): run it from cron / a timer
# Published ports listen on BIND_ADDRESS (127.0.0.1 by default): put a TLS reverse proxy in front.
"""


def env_example(services: dict, lab: bool) -> str:
    lines = ["# Settings for compose.yaml: copy to .env (never commit it).", "",
             "# Address the published ports listen on; 0.0.0.0 to serve the network (behind a TLS proxy)",
             f"BIND_ADDRESS={rules().get('bind_address', '127.0.0.1')}"]
    for name, s in services.items():
        for p in s.get("ports") or []:
            m = re.search(r"\$\{(\w+_PORT):-(\d+)\}", p)
            if m:
                lines.append(f"# host port of {name}")
                lines.append(f"{m.group(1)}={m.group(2)}")
    if lab:
        lines += ["", "# Password of the lab dependencies (--profile lab; SQL Server wants 8+ characters with",
                  "# upper case, lower case and digits)", "LAB_PASSWORD="]
    return "\n".join(lines) + "\n"


def write(out: Path, app: str, parts: list[dict], lab_needed: list[str]) -> list[Path]:
    """`parts`: per component {component, docs, base, build, ingress, hints}. Writes compose.yaml,
    .env.example, <component>/secrets.env.example and .gitignore (keeps the filled-in env files out of Git)."""
    services, volumes, files = {}, {}, {}
    port = int(rules().get("first_host_port", 8080))
    for p in parts:
        ingress = bool(p.get("ingress"))
        s, v, f = component_services(p["component"], p["docs"], base=p.get("base", ""), build=p.get("build"),
                                     ingress=ingress, host_port=port)
        if any(x.get("ports") for x in s.values()):
            port += 1
        if p.get("hints"):
            for rel in list(f):
                keys = [ln.split("=", 1)[0] for ln in f[rel].splitlines() if ln and not ln.startswith("#")]
                f[rel] = secrets_example(p["component"], keys, p["hints"])
        clash = set(s) & set(services)
        if clash:
            raise ValueError(f"compose service names used twice: {sorted(clash)}")
        services.update(s)
        volumes.update(v)
        files.update(f)
    if not services:
        return []
    lab_s, lab_v, _ = lab_services([x for x in lab_needed if x not in services])
    services.update(lab_s)
    volumes.update(lab_v)
    doc = compose_doc(app, services, volumes)
    written = []
    text = HEADER.format(app=app) + yaml.dump(doc, Dumper=_NoAlias, sort_keys=False, default_flow_style=False, width=120)
    (out / "compose.yaml").write_text(text)
    written.append(out / "compose.yaml")
    (out / ".env.example").write_text(env_example(services, bool(lab_s)))
    written.append(out / ".env.example")
    for rel, txt in files.items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_text(txt)
        written.append(out / rel)
    gi = out / ".gitignore"
    keep = gi.read_text().splitlines() if gi.exists() else []
    want = [".env", f"*/{SECRETS_ENV}", "*/secrets/"]
    if any(w not in keep for w in want):
        gi.write_text("\n".join(keep + [w for w in want if w not in keep]) + "\n")
        written.append(gi)
    return written


def build_context(repo_root: Path, out: Path, component_dir: Path) -> dict:
    """build: for compose.yaml, relative to the output folder (Compose resolves `dockerfile` from the
    context): the same build as the pipeline, the application folder as context."""
    ctx = os.path.relpath(repo_root, out)
    df = os.path.relpath(component_dir / "Dockerfile", repo_root)
    return {"context": ctx, "dockerfile": df}


class _NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def lint(doc: dict, where: str = "compose.yaml: ", component: str | None = None) -> list:
    """Gate lint of a compose file: the same checks as lint_manifests where Compose has them. Services under
    the lab profile (development dependencies) are not linted. `component`: only that component's services."""
    from .harden import _Lint, _looks_like_path, _secret_name
    L = _Lint()
    cfg = L.cfg
    for name, s in ((doc or {}).get("services") or {}).items():
        s = s or {}
        labels = s.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(x.split("=", 1) for x in labels if "=" in x)
        if LAB_PROFILE in (s.get("profiles") or []):
            continue
        if component is not None and labels.get(COMPONENT_LABEL, name) != component:
            continue
        waived = {w.strip() for w in str(labels.get(WAIVES_LABEL) or "").split(",") if w.strip()}
        tgt = f"{where}service/{name}"
        if s.get("privileged"):
            L.add("privileged", tgt, "privileged is true", waived)
        if s.get("devices"):
            L.add("privileged", tgt, "maps host devices", waived)
        for k in ("network_mode", "pid", "ipc", "userns_mode", "uts"):
            if str(s.get(k) or "") == "host":
                L.add("host-namespaces", tgt, f"{k} is host", waived)
        if "ALL" not in [str(x).upper() for x in s.get("cap_drop") or []]:
            L.add("capabilities", tgt, "cap_drop does not include ALL", waived)
        extra = [x for x in s.get("cap_add") or [] if str(x).upper().removeprefix("CAP_") not in cfg["allowed_capabilities"]]
        if extra:
            L.add("capabilities", tgt, f"adds capabilities {', '.join(map(str, extra))}", waived)
        opts = [str(x).replace("=", ":") for x in s.get("security_opt") or []]
        if not any(o in ("no-new-privileges", "no-new-privileges:true") for o in opts):
            L.add("privilege-escalation", tgt, "security_opt has no no-new-privileges:true", waived)
        if any(o.startswith("seccomp:") and o.split(":", 1)[1] == "unconfined" for o in opts):
            L.add("seccomp", tgt, "seccomp is unconfined", waived)
        if any(o.startswith("apparmor:") and o.split(":", 1)[1] == "unconfined" for o in opts):
            L.add("apparmor", tgt, "AppArmor is unconfined", waived)
        user = str(s.get("user") or "")
        if not user or user.split(":")[0] in ("0", "root"):
            L.add("run-as-non-root", tgt, "user is not set to a non-root user", waived)
        if s.get("read_only") is not True:
            L.add("readonly-rootfs", tgt, "read_only is not true", waived)
        lim = ((s.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        if not (s.get("mem_limit") or lim.get("memory")):
            L.add("resources", tgt, "needs a memory limit (mem_limit)", waived)
        for v in s.get("volumes") or []:
            src = v.get("source") if isinstance(v, dict) else str(v).split(":")[0]
            if str(src or "").rstrip("/") in ("", "/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock") \
                    and (not isinstance(v, dict) or v.get("type") == "bind"):
                L.add("volume-types", tgt, f"mounts the host's {src or '/'}", waived)
            elif str(src or "").startswith("/") and (not isinstance(v, dict) or v.get("type") == "bind"):
                L.add("volume-types", tgt, f"binds host path {src}", waived)
        env = s.get("environment") or {}
        if isinstance(env, list):
            env = dict((x.split("=", 1) + [""])[:2] for x in env)
        for k, v in env.items():
            if v not in ("", None) and _secret_name(k) and not str(v).startswith("${") \
                    and not _looks_like_path(str(v)):
                L.add("secret-literals", tgt, f"environment {k} carries a value; use env_file or secrets", waived)
    return L.out


def lint_file(path: Path, component: str | None = None) -> list:
    return lint(yaml.safe_load(path.read_text()) or {}, f"{path.name}: ", component)

