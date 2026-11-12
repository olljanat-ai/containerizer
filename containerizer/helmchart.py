"""The shared Helm chart of 0.33.0 to 0.42.x, kept only to convert the applications deployed with it back to plain
manifests (manifests.py). Chart mode was dropped in 0.43.0: kustomize alone is simpler to read and to change.

A component folder with <component>/helmrelease.yaml (a Flux HelmRelease of charts/containerizer-app/<version>/ in the
output repository) is rendered here once more, as the chart rendered it (`render`, the chart's own values.yaml), and
written as one file per kind (`unchart_component`); its image goes back to the app's kustomization.yaml `images:`
with the Flux image automation markers. `unchart_repository` does that for every application of an output
repository and then removes charts/. Every organization scan runs it (org.write_sandbox).
"""
from __future__ import annotations

import copy
import json
import os
import re
import shutil
from functools import lru_cache
from pathlib import Path

import yaml

from . import __version__

CHART = "containerizer-app"
CHARTS_DIR = "charts"
PACKAGED = Path(__file__).resolve().parent / "chart" / CHART
HELM_API = "helm.toolkit.fluxcd.io/v2"
HELMRELEASE = "helmrelease.yaml"


def _settings_docs(cdir: Path) -> list[dict]:
    from .manifests import SETTINGS
    try:
        return [d for d in yaml.safe_load_all((cdir / SETTINGS).read_text()) if isinstance(d, dict)]
    except (OSError, yaml.YAMLError):
        return []


UNSET = "~unset"
WORKLOADS = {"Deployment": ("spec", "template"), "CronJob": ("spec", "jobTemplate", "spec", "template")}
MAX_INT = 10 ** 6                # Helm keeps numbers as float64 and prints 1000000 as 1e+06


# --------------------------------------------------------------------------- the chart

@lru_cache(maxsize=16)
def _chart_values(chart_dir: str) -> dict:
    return yaml.safe_load((Path(chart_dir) / "values.yaml").read_text()) or {}


def chart_values(chart_dir: Path | None = None) -> dict:
    return copy.deepcopy(_chart_values(str(chart_dir or PACKAGED)))


def merge(dst: dict, src: dict) -> dict:
    """Merge `src` into `dst` in place, as the chart's cz.merge: maps key by key, anything else replaces, the string
    "~unset" removes the key."""
    for k, v in src.items():
        if v == UNSET:
            dst.pop(k, None)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def _subst(x, component: str, part_of: str):
    """A copy of `x` with ${component} and ${partOf} filled in (the chart's cz.subst, which goes through JSON)."""
    if isinstance(x, dict):
        return {_subst(k, component, part_of): _subst(v, component, part_of) for k, v in x.items()}
    if isinstance(x, list):
        return [_subst(v, component, part_of) for v in x]
    if isinstance(x, str):
        return x.replace("${component}", component).replace("${partOf}", part_of)
    return x


def _resolve(x: dict, frags: dict) -> None:
    """The chart's cz.resolve: list items and map values "@<name>" become fragment <name>, in place."""
    for k, v in list(x.items()):
        if isinstance(v, str) and v.startswith("@") and v[1:] in frags:
            x[k] = copy.deepcopy(frags[v[1:]])
        elif isinstance(v, dict):
            _resolve(v, frags)
        elif isinstance(v, list):
            out = []
            for item in v:
                if isinstance(item, str) and item.startswith("@") and item[1:] in frags:
                    out.append(copy.deepcopy(frags[item[1:]]))
                else:
                    if isinstance(item, dict):
                        _resolve(item, frags)
                    out.append(item)
            x[k] = out


def _at(d: dict, path: tuple):
    for p in path:
        d = d[p]
    return d


def coalesce(defaults: dict, user: dict) -> dict:
    """Helm's values: the chart's values.yaml under the user's (maps merge, the user's value wins, null removes)."""
    out = copy.deepcopy(defaults)
    for k, v in (user or {}).items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = coalesce(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _image(values: dict) -> str:
    img = values.get("image") or {}
    if not img.get("repository"):
        return ""
    ref = f"{img['repository']}:{img.get('tag') or ''}"
    return f"{ref}@{img['digest']}" if img.get("digest") else ref


def _base(v: dict, kind: str, component: str, part_of: str, name: str | None = None) -> dict:
    """An object of `kind` named `name` before its entry: the defaults, and the pod defaults of a workload."""
    defs = _subst(v.get("defaults") or {}, component, part_of)
    obj: dict = {}
    if kind in (v.get("apiVersions") or {}):
        obj["apiVersion"] = v["apiVersions"][kind]
    merge(obj, defs.get("*") or {})
    if kind in defs:
        merge(obj, defs[kind])
    if f"{kind}/{name or component}" in defs:
        merge(obj, defs[f"{kind}/{name or component}"])
    if kind in WORKLOADS:
        tpl = _at(obj, WORKLOADS[kind])
        tpl["spec"] = merge(_subst(v.get("pod") or {}, component, part_of), tpl.get("spec") or {})
    return obj


def _container_base(v: dict, component: str, part_of: str) -> dict:
    c0 = _subst(v.get("container") or {}, component, part_of)
    if _image(v):
        c0["image"] = _image(v)
    return c0


SAFE_SYSCTLS = ("kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.ip_unprivileged_port_start",
                "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range", "net.ipv4.ip_local_reserved_ports",
                "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_intvl",
                "net.ipv4.tcp_keepalive_probes")
ALLOWED_CAPS = ("NET_BIND_SERVICE",)


class Refused(ValueError):
    """The chart refuses to render a pod that asks for what its hardening forbids."""


def harden(pod: dict, where: str) -> None:
    """The chart's cz.harden: the hardening every pod gets after its values, which no value can change (a pod that asks
    for what it forbids is refused)."""
    for k in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(k):
            raise Refused(f"{where}: {k} is not allowed by the shared chart")
    pod["hostUsers"] = False
    pod["automountServiceAccountToken"] = False
    psc = pod.get("securityContext") if isinstance(pod.get("securityContext"), dict) else {}
    psc["runAsNonRoot"] = True
    psc["seccompProfile"] = {"type": "RuntimeDefault"}
    for sc in psc.get("sysctls") or []:
        if sc.get("name") not in SAFE_SYSCTLS:
            raise Refused(f"{where}: sysctl {sc.get('name')} is not allowed by the shared chart")
    pod["securityContext"] = psc
    for v in pod.get("volumes") or []:
        if "hostPath" in v:
            raise Refused(f"{where}: hostPath volume {v.get('name')} is not allowed by the shared chart")
    for c in list(pod.get("containers") or []) + list(pod.get("initContainers") or []):
        sc = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}
        sc.update({"runAsNonRoot": True, "privileged": False, "allowPrivilegeEscalation": False,
                   "readOnlyRootFilesystem": True, "seccompProfile": {"type": "RuntimeDefault"}})
        caps = sc.get("capabilities") if isinstance(sc.get("capabilities"), dict) else {}
        for a in caps.get("add") or []:
            if a not in ALLOWED_CAPS:
                raise Refused(f"{where}: capability {a} is not allowed by the shared chart")
        caps["drop"] = ["ALL"]
        sc["capabilities"] = caps
        c["securityContext"] = sc
        for p in c.get("ports") or []:
            if p.get("hostPort"):
                raise Refused(f"{where}: hostPort {p['hostPort']} is not allowed by the shared chart")
        if not ((c.get("resources") or {}).get("limits") or {}).get("memory"):
            raise Refused(f"{where}: container {c.get('name')} has no memory limit")


def render(user_values: dict, chart_dir: Path | None = None) -> list[dict]:
    """The objects the chart renders for a HelmRelease's values (what `helm template` prints: tests/test_helm_chart.py
    checks the two agree)."""
    v = coalesce(chart_values(chart_dir), user_values)
    component, part_of = str(v.get("component") or ""), str(v.get("partOf") or "")
    frags = _subst(v.get("fragments") or {}, component, part_of)
    out = []
    for o in copy.deepcopy(v.get("objects") or []):
        kind = o.get("kind")
        if kind in (v.get("skipKinds") or []):
            continue
        name = (o.get("metadata") or {}).get("name") if isinstance(o.get("metadata"), dict) else None
        obj = merge(_base(v, kind, component, part_of, name if isinstance(name, str) and name else None), o)
        if kind in WORKLOADS:
            spec = _at(obj, WORKLOADS[kind])["spec"]
            cs = spec.get("containers") or [{}]
            spec["containers"] = [merge(_container_base(v, component, part_of), cs[0])] + cs[1:]
        _resolve(obj, frags)
        if kind in WORKLOADS:
            harden(_at(obj, WORKLOADS[kind])["spec"], f"{kind}/{(obj.get('metadata') or {}).get('name')}")
        if kind == "ServiceAccount":
            obj["automountServiceAccountToken"] = False
        out.append(obj)
    return out


def read_helmrelease(path: Path) -> dict | None:
    try:
        doc = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return None
    return doc if isinstance(doc, dict) and doc.get("kind") == "HelmRelease" else None


def find_chart(start: Path, rel: str) -> Path | None:
    """The chart a HelmRelease names (`rel`, from the repository root), looked for above `start`."""
    rel = rel.removeprefix("./")
    for p in [start, *start.parents]:
        if (p / rel / "Chart.yaml").is_file():
            return p / rel
    return None


# --------------------------------------------------------------------------- converting back to manifests

def rendered_docs(cdir: Path) -> list[dict]:
    """The objects a component's HelmRelease renders (the chart version it names in the repository, else the one
    packaged here) and its settings.yaml."""
    hr = read_helmrelease(cdir / HELMRELEASE)
    if hr is None:
        return []
    spec = (hr.get("spec") or {}).get("chart", {}).get("spec") or {}
    chart = find_chart(cdir, str(spec.get("chart") or "")) if spec.get("chart") else None
    try:
        return render((hr.get("spec") or {}).get("values") or {}, chart) + _settings_docs(cdir)
    except (KeyError, TypeError, AttributeError):
        return []


def unchart_component(cdir: Path) -> bool:
    """A component deployed as a HelmRelease of the shared chart, as one file per kind (manifests.write_split): the
    app's kustomization.yaml lists its folder, and its image (tag and digest) is an `images:` entry with the Flux
    image automation markers again. False when the folder has no HelmRelease or it cannot be rendered."""
    from .gitops import image_setters
    from .manifests import SETTINGS, drop_resource, set_resources, write_split
    hr = read_helmrelease(cdir / HELMRELEASE)
    docs = rendered_docs(cdir) if hr else []
    if not docs:
        return False
    vals = (hr.get("spec") or {}).get("values") or {}
    image = dict(vals.get("image") or {})
    for d in docs:
        if d.get("kind") in WORKLOADS:
            for c in _at(d, WORKLOADS[d["kind"]])["spec"].get("containers") or []:
                if image.get("repository") and str(c.get("image") or "").startswith(image["repository"]):
                    c["image"] = f"{image['repository']}:{image.get('tag') or ''}"
    app_dir = cdir.parent
    (cdir / HELMRELEASE).unlink()
    if (cdir / SETTINGS).is_file():
        drop_resource(app_dir, f"{cdir.name}/{SETTINGS}")
    write_split(cdir, docs)
    set_resources(app_dir, {f"{cdir.name}/{HELMRELEASE}": cdir.name})
    k = app_dir / "kustomization.yaml"
    if image.get("repository") and k.is_file():
        ktext = k.read_text()
        block = image_setters(str(vals.get("partOf") or ""), [(cdir.name, f"{image['repository']}:{image.get('tag')}")],
                              {image["repository"]: image.get("digest") or ""})
        if re.search(r"(?m)^images:", ktext):
            block = block.split("\n", 1)[1]
            ktext = re.sub(r"(?m)^images:\n", "images:\n" + block.replace("\\", "\\\\"), ktext, count=1)
        else:
            ktext = ktext.rstrip("\n") + "\n" + block
        k.write_text(ktext)
    return True


def unchart_app(app_dir: Path) -> list[str]:
    """Every chart component of an application folder converted (unchart_component); containerizer.json says
    manifests. Returns the components converted."""
    done = [f.parent.name for f in sorted(app_dir.glob(f"*/{HELMRELEASE}")) if unchart_component(f.parent)]
    meta = app_dir / "containerizer.json"
    if done and meta.is_file():
        try:
            doc = json.loads(meta.read_text())
        except ValueError:
            return done
        doc.pop("deploy_mode", None)
        doc.pop("deploy_mode_reason", None)
        for c in doc.get("components") or []:
            if isinstance(c, dict):
                c.pop("deploy_mode", None)
                c.pop("deploy_mode_reason", None)
        meta.write_text(json.dumps(doc, indent=2, default=str) + "\n")
    readme = app_dir / "gitops" / "README.md"
    if done and readme.is_file():
        readme.write_text(re.sub(r"Components .*? set the application's deploy mode to manifests\.",
                                 "No Helm chart is generated, so there is no `HelmRelease`: the app is plain Kustomize.",
                                 readme.read_text(), flags=re.S))
    return done


def unchart_repository(root: Path, apps) -> list[str]:
    """unchart_app for every application folder (`apps`: org._apps_in), then charts/ removed once no HelmRelease
    names it. Returns "<app>/<component>" converted."""
    out = []
    for rel, folder, _doc in apps:
        try:
            out += [f"{rel}/{c}" for c in unchart_app(folder)]
        except (OSError, ValueError, KeyError, TypeError) as ex:
            import sys
            print(f"warning: {rel}: not converted from the Helm chart: {type(ex).__name__}: {ex}", file=sys.stderr)
    charts = root / CHARTS_DIR / CHART
    if charts.is_dir() and not any(".git" not in f.parts for f in root.glob(f"**/{HELMRELEASE}")):
        shutil.rmtree(charts)
        if not any((root / CHARTS_DIR).iterdir()):
            (root / CHARTS_DIR).rmdir()
    return out

