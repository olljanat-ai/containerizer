"""How the generated components are deployed: from the shared Helm chart (the default) or as plain manifests.

The generator always builds each component's Kubernetes objects first (generate.k8s_manifests, hardened, linted,
scanned and run by the security gate). Only when an application is written to the output repository does this
module decide their form:

    chart       <component>/helmrelease.yaml: a Flux HelmRelease of the shared chart charts/containerizer-app/<version>/
                (copied into the output repository), whose values hold only what the component's objects have
                beyond the chart's hardened baseline
    manifests   <component>/k8s.yaml: the objects themselves, applied by kustomize

The chart never changes what runs: a component becomes a HelmRelease only when the chart renders exactly the objects
the generator made (`render(to_values(docs)) == docs`). It stays plain manifests when the chart would not save much
(`deploy.min_saving`), or the objects hold something the chart's values cannot carry faithfully (numbers Helm would
print in exponent form, floats, the "~unset" marker itself). The chart covers one main container per pod; anything
more (sidecars, init containers, kinds it has no defaults for) is carried as it is, so the saving decides.

Which mode an application gets (`app_mode`):
  1. the administrators' choice for the application (Admin -> Applications, Application.DeployMode)
  2. else the mode its folder in the output repository already has: switching recreates its objects (helm-controller
     takes them over from kustomize: the pods restart, PersistentVolumeClaims are made again, empty), so changing the
     default does not switch deployed applications unless `deploy.switch_existing` says so
  3. else the system default: `deploy.mode` in rules/60-security.yaml, or CONTAINERIZER_DEPLOY_MODE

docs/helm-chart.md has the why and the trade-offs.
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
SETTINGS = "settings.yaml"      # chart mode: the component's settings ConfigMap, in a file of its own


def is_settings(d: dict) -> bool:
    """The ConfigMap <component>-settings (generate.k8s_manifests): values a person sets per environment."""
    return d.get("kind") == "ConfigMap" and str((d.get("metadata") or {}).get("name") or "").endswith("-settings")


def settings_text(doc: dict) -> str:
    from .generate import _yaml_docs
    return _yaml_docs([doc])


def _settings_docs(cdir: Path) -> list[dict]:
    try:
        return [d for d in yaml.safe_load_all((cdir / SETTINGS).read_text()) if isinstance(d, dict)]
    except (OSError, yaml.YAMLError):
        return []
MANIFESTS = "k8s.yaml"
MODES = ("chart", "manifests")
MODE_ENV = "CONTAINERIZER_DEPLOY_MODE"
UNSET = "~unset"
WORKLOADS = {"Deployment": ("spec", "template"), "CronJob": ("spec", "jobTemplate", "spec", "template")}
MAX_INT = 10 ** 6                # Helm keeps numbers as float64 and prints 1000000 as 1e+06
TOP_KEYS = ("component", "partOf", "image", "skipKinds", "objects")
_IMAGE_LINE = re.compile(r"^(\s*)(repository|tag|digest):(.*)$")


# --------------------------------------------------------------------------- settings

def settings() -> dict:
    """{mode, switch_existing, min_saving}: `deploy:` of rules/60-security.yaml, the mode overridden by
    CONTAINERIZER_DEPLOY_MODE (a site setting)."""
    from .harden import security
    cfg = security().get("deploy") or {}
    mode = str(os.environ.get(MODE_ENV) or cfg.get("mode") or "chart").strip().lower()
    if mode not in MODES:
        raise ValueError(f"deploy mode {mode!r}: use one of {', '.join(MODES)} ({MODE_ENV} or deploy.mode in "
                         "rules/60-security.yaml)")
    try:
        saving = float(cfg.get("min_saving", 0.3))
    except (TypeError, ValueError):
        saving = 0.3
    return {"mode": mode, "switch_existing": bool(cfg.get("switch_existing", False)),
            "min_saving": min(max(saving, 0.0), 0.95)}


def clean_mode(v) -> str | None:
    """A stored mode ('chart', 'manifests'), None for the system default (or anything else)."""
    v = str(v or "").strip().lower()
    return v if v in MODES else None


def folder_mode(folder: Path) -> str | None:
    """The mode an application folder in the output repository has: containerizer.json `deploy_mode`, else from its
    files (made before 0.33.0: manifests). None when there is no deployed application there."""
    try:
        doc = json.loads((folder / "containerizer.json").read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("status") != "deployed":
        return None
    if clean_mode(doc.get("deploy_mode")):
        return doc["deploy_mode"]
    folders = [c.get("folder") for c in doc.get("components") or [] if isinstance(c, dict) and c.get("folder")]
    return "chart" if any((folder / f / HELMRELEASE).is_file() for f in folders) else "manifests"


def app_mode(override=None, existing: str | None = None, cfg: dict | None = None) -> tuple[str, str]:
    """(mode, why) of one application: the administrators' choice, else the one it is deployed with, else the default."""
    cfg = cfg or settings()
    if clean_mode(override):
        return override.strip().lower(), "set for this application"
    if existing in MODES and not cfg["switch_existing"]:
        return existing, "the mode it is deployed with (changing the default does not switch deployed applications)"
    return cfg["mode"], "the system default"


# --------------------------------------------------------------------------- the chart

@lru_cache(maxsize=16)
def _chart_values(chart_dir: str) -> dict:
    return yaml.safe_load((Path(chart_dir) / "values.yaml").read_text()) or {}


def chart_values(chart_dir: Path | None = None) -> dict:
    return copy.deepcopy(_chart_values(str(chart_dir or PACKAGED)))


def chart_rel(version: str = __version__) -> str:
    """Where the chart of a version is in an output repository (from its root)."""
    return f"{CHARTS_DIR}/{CHART}/{version}"


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


# --------------------------------------------------------------------------- objects -> values

def _diff(base, target):
    """The entry that turns `base` into `target` under `merge`."""
    out = {}
    for k in base:
        if k not in target:
            out[k] = UNSET
    for k, t in target.items():
        if k not in base:
            out[k] = copy.deepcopy(t)
        elif base[k] == t:
            continue
        elif isinstance(base[k], dict) and isinstance(t, dict):
            out[k] = _diff(base[k], t)
        else:
            out[k] = copy.deepcopy(t)
    return out


def _use_fragments(x, frags: dict):
    """List items and map values equal to a fragment become "@<name>"."""
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            name = next((n for n, f in frags.items() if f == v), None) if isinstance(v, dict) else None
            out[k] = f"@{name}" if name else _use_fragments(v, frags)
        return out
    if isinstance(x, list):
        out = []
        for item in x:
            name = next((n for n, f in frags.items() if f == item), None) if isinstance(item, dict) else None
            out.append(f"@{name}" if name else (_use_fragments(item, frags) if isinstance(item, dict) else item))
        return out
    return x


def _unfaithful(x) -> str | None:
    """Why Helm would not give `x` back as it is (None: it would)."""
    if isinstance(x, dict):
        return next((r for r in map(_unfaithful, x.values()) if r), None)
    if isinstance(x, list):
        return next((r for r in map(_unfaithful, x) if r), None)
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, float):
        return f"the number {x} (Helm keeps numbers as floats)"
    if isinstance(x, int) and abs(x) >= MAX_INT:
        return f"the number {x} (Helm would write it as {float(x):.0e})"
    if isinstance(x, str) and (x == UNSET or x.startswith("@")):
        return f"the value {x!r} (the chart's own markers)"
    return None


def to_values(docs: list[dict], component: str, part_of: str, image: dict | None = None,
              chart_dir: Path | None = None) -> tuple[dict | None, str]:
    """(HelmRelease values, "") that make the chart render exactly `docs`, or (None, why not)."""
    docs = [d for d in docs if isinstance(d, dict)]
    if not docs:
        return None, "no objects"
    if why := _unfaithful(docs):
        return None, f"the objects hold {why}"
    for d in docs:
        if not d.get("kind"):
            return None, "an object without a kind"
        if d["kind"] in WORKLOADS:
            try:
                cs = _at(d, WORKLOADS[d["kind"]])["spec"]["containers"]
            except (KeyError, TypeError):
                return None, f"{d['kind']} {d.get('metadata', {}).get('name')} has no pod template"
            if not cs:
                return None, f"{d['kind']} {d.get('metadata', {}).get('name')} has no container"
    user = {"component": component, "partOf": part_of, "image": dict(image or {}), "objects": []}
    v = coalesce(chart_values(chart_dir), user)
    frags = _subst(v.get("fragments") or {}, component, part_of)
    for d in docs:
        kind = d["kind"]
        entry = _diff(_base(v, kind, component, part_of, (d.get("metadata") or {}).get("name")), d)
        entry.pop("kind", None)
        entry = {"kind": kind, **entry}
        if kind in WORKLOADS:
            cs = _at(d, WORKLOADS[kind])["spec"]["containers"]
            first = _diff(_container_base(v, component, part_of), cs[0])
            # the pod's containers in the entry: the first one as its difference from the container defaults
            node = entry
            for p in WORKLOADS[kind]:
                node = node.setdefault(p, {})
            node.setdefault("spec", {})["containers"] = [first] + copy.deepcopy(cs[1:])
        user["objects"].append(_use_fragments(entry, frags))
    if not user["image"].get("digest"):
        user["image"].pop("digest", None)
    try:
        got = render(user, chart_dir)
    except Refused as ex:
        return None, f"it needs what the shared chart's hardening forbids ({ex})"
    if got != docs:
        hardened = next((d for g, d in zip(got, docs) if g != d and _hardening_only(g, d)), None)
        if hardened is not None:
            name = f"{hardened['kind']}/{(hardened.get('metadata') or {}).get('name')}"
            return None, (f"{name} has a hardening exception (its own user, token, capability or security context "
                          "setting), which the shared chart's hardening does not allow")
        bad = next(((g, d) for g, d in zip(got, docs) if g != d), (None, None))
        name = (bad[1] or {}).get("kind", "?") + "/" + str(((bad[1] or {}).get("metadata") or {}).get("name", "?"))
        return None, f"the chart does not render {name} as generated"
    return user, ""


def _hardening_only(got: dict, doc: dict) -> bool:
    """Do `got` and `doc` differ only where the chart enforces its hardening (`doc` with it applied is `got`)?"""
    d = copy.deepcopy(doc)
    try:
        if d.get("kind") in WORKLOADS:
            harden(_at(d, WORKLOADS[d["kind"]])["spec"], "")
        if d.get("kind") == "ServiceAccount":
            d["automountServiceAccountToken"] = False
    except (Refused, KeyError, TypeError):
        return False
    return d == got


# --------------------------------------------------------------------------- files

def _dump(d) -> str:
    from .generate import _NoAlias
    return yaml.dump(d, Dumper=_NoAlias, sort_keys=False, default_flow_style=False, width=120)


def load_docs_with_comments(text: str) -> list[dict]:
    """The documents of a k8s.yaml, each with its leading comment as `_comment` (generate._yaml_docs writes them)."""
    out = []
    for chunk in re.split(r"(?m)^---\s*$", text):
        lines = chunk.strip("\n").splitlines()
        comment = []
        while lines and lines[0].startswith("#"):
            comment.append(lines.pop(0)[1:].strip())
        try:
            d = yaml.safe_load("\n".join(lines))
        except yaml.YAMLError:
            continue
        if isinstance(d, dict):
            if comment:
                d["_comment"] = " ".join(comment)
            out.append(d)
    return out


def helmrelease_text(component: str, ns: str, values: dict, version: str = __version__,
                     comments: list[str] | None = None, setters: bool = True) -> str:
    """<component>/helmrelease.yaml: the HelmRelease, with Flux image automation markers on values.image."""
    labels = {"app.kubernetes.io/name": component, "app.kubernetes.io/part-of": ns}
    doc = {"apiVersion": HELM_API, "kind": "HelmRelease", "metadata": {"name": component, "labels": labels},
           "spec": {"interval": "10m",
                    "chart": {"spec": {"chart": f"./{chart_rel(version)}", "version": version,
                                       "reconcileStrategy": "ChartVersion",
                                       "sourceRef": {"kind": "GitRepository", "name": ns}}},
                    "serviceAccountName": f"{ns}-reconciler",
                    # the first install takes over objects kustomize applied before (a switch from manifests)
                    "install": {"remediation": {"retries": 3}},
                    "upgrade": {"remediation": {"retries": 3}},
                    "values": {k: values[k] for k in TOP_KEYS if k in values}}}
    head = [f"# Component {component}: the shared chart {chart_rel(version)} (from the root of the repository) with "
            "the values below,", "# which hold only what its objects have beyond the chart's values.yaml "
            "(docs/helm-chart.md)."]
    for c in comments or []:
        head.append(f"# {c}")
    lines = _dump(doc).splitlines()
    if setters and values.get("image", {}).get("repository"):
        marker = f'{{"$imagepolicy": "{ns}:{component}'
        out, in_image = [], False
        for ln in lines:
            if re.match(r"^\s{4}image:\s*$", ln):
                in_image = True
            elif in_image and not re.match(r"^\s{6}\S", ln):
                in_image = False
            m = _IMAGE_LINE.match(ln) if in_image else None
            if m and m.group(1) == " " * 6:
                key = {"repository": "name"}.get(m.group(2), m.group(2))
                val = m.group(3).strip() or "''"
                ln = f'{m.group(1)}{m.group(2)}: {val} # {marker}:{key}"}}'
            out.append(ln)
        if values["image"].get("digest") is None:
            # no digest yet: the image automation fills it in (digestReflectionPolicy), as in kustomization.yaml
            idx = next(i for i, ln in enumerate(out) if re.match(r"^\s{6}tag:", ln))
            out.insert(idx + 1, f'      digest: "" # {marker}:digest"}}')
        lines = out
    return "\n".join(head + lines) + "\n"


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


def component_docs(cdir: Path) -> list[dict]:
    """A component folder's objects: its k8s.yaml, or what its HelmRelease renders (from the chart version it
    names in the repository, else this version's). Empty when it has neither."""
    if (cdir / MANIFESTS).is_file():
        try:
            return [d for d in yaml.safe_load_all((cdir / MANIFESTS).read_text()) if isinstance(d, dict)]
        except yaml.YAMLError:
            return []
    hr = read_helmrelease(cdir / HELMRELEASE)
    if hr is None:
        return []
    spec = (hr.get("spec") or {}).get("chart", {}).get("spec") or {}
    chart = find_chart(cdir, str(spec.get("chart") or "")) if spec.get("chart") else None
    try:
        return render((hr.get("spec") or {}).get("values") or {}, chart) + _settings_docs(cdir)
    except (KeyError, TypeError, AttributeError):
        return []


def component_text(cdir: Path) -> str:
    """The component's objects as YAML (what an LLM or a person reads)."""
    if (cdir / MANIFESTS).is_file():
        return (cdir / MANIFESTS).read_text()
    docs = component_docs(cdir)
    return "---\n".join(_dump(d) for d in docs)


# --------------------------------------------------------------------------- an application folder

def _drop_images(text: str, repos: set[str]) -> str:
    """kustomization.yaml without the `images:` entries of `repos` (and without `images:` once it is empty)."""
    from .gitops import _image_entries
    lines = text.splitlines()
    drop = set()
    for name, a, b in _image_entries(text):
        if name in repos:
            drop |= set(range(a, b))
    lines = [ln for i, ln in enumerate(lines) if i not in drop]
    i = next((i for i, ln in enumerate(lines) if ln.startswith("images:")), None)
    if i is not None and (i + 1 >= len(lines) or re.match(r"^\S", lines[i + 1])):
        lines.pop(i)
    return "\n".join(lines) + "\n"


def _set_resources(app_dir: Path, swap: dict[str, str]) -> None:
    """kustomization.yaml `resources:`: `<old>` -> `<new>` for each entry of `swap`, keeping the rest of the text."""
    k = app_dir / "kustomization.yaml"
    text = k.read_text()
    for old, new in swap.items():
        text = re.sub(rf"(?m)^(-\s+){re.escape(old)}\s*$", rf"\g<1>{new}", text)
    k.write_text(text)


def _image_values(docs: list[dict], digests: dict[str, str]) -> dict:
    for d in docs:
        if d.get("kind") in WORKLOADS:
            img = str(_at(d, WORKLOADS[d["kind"]])["spec"]["containers"][0].get("image") or "")
            ref = img.split("@", 1)[0]
            if ":" in ref.rsplit("/", 1)[-1]:
                repo, tag = ref.rsplit(":", 1)
                return {"repository": repo, "tag": tag, "digest": digests.get(repo) or None}
    return {}


def _as_kustomize_builds(docs: list[dict], image: dict, pull_secret: str | None) -> list[dict]:
    """The objects as the app's kustomization would apply them: the image with the digest its `images:` entry pins,
    and the pull secret its patches add (org.add_pull_secret)."""
    docs = copy.deepcopy(docs)
    for d in docs:
        if d.get("kind") not in WORKLOADS:
            continue
        spec = _at(d, WORKLOADS[d["kind"]])["spec"]
        for c in spec.get("containers") or []:
            ref = str(c.get("image") or "")
            if image.get("repository") and ref.rsplit(":", 1)[0] == image["repository"] and "@" not in ref:
                c["image"] = _image({"image": image})
        if pull_secret:
            spec["imagePullSecrets"] = [{"name": pull_secret}]
    return docs


def _lines(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))


def convert_app(app_dir: Path, ns: str, folders: list[str], mode: str, digests: dict[str, str] | None = None,
                pull_secret: str | None = None, min_saving: float | None = None) -> dict[str, dict]:
    """Write the components of a generated application folder in `mode`: {folder: {mode, reason}}. In chart mode a
    component whose objects the chart renders exactly, with at least `min_saving` fewer lines, gets
    <folder>/helmrelease.yaml in place of <folder>/k8s.yaml, and its image moves from kustomization.yaml `images:`
    into the HelmRelease's values (with the Flux image automation markers). The rest stays as it is."""
    out: dict[str, dict] = {}
    if mode != "chart":
        return {f: {"mode": "manifests"} for f in folders if (app_dir / f / MANIFESTS).is_file()}
    saving = settings()["min_saving"] if min_saving is None else min_saving
    moved, repos = {}, set()
    for f in folders:
        cdir = app_dir / f
        if not (cdir / MANIFESTS).is_file():
            continue
        raw = (cdir / MANIFESTS).read_text()
        docs = load_docs_with_comments(raw)
        own = [d for d in docs if is_settings(d)]
        docs = [d for d in docs if not is_settings(d)]
        comments = [f"{d.get('kind')}/{(d.get('metadata') or {}).get('name')}: {d.pop('_comment')}"
                    for d in docs if d.get("_comment")]
        image = _image_values(docs, digests or {})
        built = _as_kustomize_builds(docs, image, pull_secret)
        values, why = to_values(built, f, ns, image)
        if values is None:
            out[f] = {"mode": "manifests", "reason": why}
            continue
        text = helmrelease_text(f, ns, values, comments=comments)
        small, big = _lines(text), _lines(raw)
        if big and small > (1 - saving) * big:
            out[f] = {"mode": "manifests",
                      "reason": f"the chart saves only {round(100 * (1 - small / big))}% of its {big} lines"}
            continue
        (cdir / HELMRELEASE).write_text(text)
        (cdir / MANIFESTS).unlink()
        moved[f"{f}/{MANIFESTS}"] = f"{f}/{HELMRELEASE}"
        if own:
            (cdir / SETTINGS).write_text(settings_text(own[0]))
            moved[f"{f}/{MANIFESTS}"] += f"\n- {f}/{SETTINGS}"
        if image.get("repository"):
            repos.add(image["repository"])
        out[f] = {"mode": "chart"}
    if moved:
        _set_resources(app_dir, moved)
        k = app_dir / "kustomization.yaml"
        k.write_text(_drop_images(k.read_text(), repos))
        readme = app_dir / "gitops" / "README.md"
        if readme.is_file():
            readme.write_text(readme.read_text().replace(
                "No Helm chart is generated, so there is no `HelmRelease`: the app is plain Kustomize.",
                gitops_note(ns, sorted(f.split("/")[0] for f in moved))))
    return out


def gitops_note(ns: str, comps: list[str]) -> str:
    return (f"Components {', '.join(f'`{c}`' for c in comps)} are `HelmRelease`s of the shared chart "
            f"`{chart_rel()}` (at the root of this repository; docs/helm-chart.md): Flux's helm-controller installs "
            f"them as ServiceAccount `{ns}-reconciler`, from the same `GitRepository`. Their image setters are in "
            "their `helmrelease.yaml`, not in `kustomization.yaml`. The OCI delivery (`oci/sync.yaml`) does not carry "
            "the chart: deploy these from Git, or set the application's deploy mode to manifests.")


def write_component_docs(cdir: Path, docs: list[dict]) -> str:
    """Write changed objects back to a component folder in the form it has; returns the file written. A HelmRelease
    whose new objects the chart cannot render exactly becomes k8s.yaml again (kustomization.yaml follows)."""
    from .generate import _yaml_docs
    hr = read_helmrelease(cdir / HELMRELEASE) if not (cdir / MANIFESTS).is_file() else None
    if hr is None:
        (cdir / MANIFESTS).write_text(_yaml_docs(docs))
        return MANIFESTS
    if (cdir / SETTINGS).is_file():
        own = [d for d in docs if is_settings(d)]
        docs = [d for d in docs if not is_settings(d)]
        if own and own != _settings_docs(cdir):
            (cdir / SETTINGS).write_text(settings_text(own[0]))
    spec = hr.get("spec") or {}
    vals = spec.get("values") or {}
    chart_spec = (spec.get("chart") or {}).get("spec") or {}
    version = str(chart_spec.get("version") or __version__)
    chart = find_chart(cdir, str(chart_spec.get("chart") or chart_rel(version)))
    image = dict(vals.get("image") or {})
    values, _why = to_values(docs, str(vals.get("component") or cdir.name), str(vals.get("partOf") or ""), image,
                             chart)
    text = (cdir / HELMRELEASE).read_text()
    comments = [ln[2:] for ln in text.splitlines()[2:] if ln.startswith("# ")]
    if values is not None:
        (cdir / HELMRELEASE).write_text(helmrelease_text(cdir.name, str(vals.get("partOf") or ""), values,
                                                         version=version, comments=comments))
        return HELMRELEASE
    # back to manifests: the image by tag and digest through kustomization.yaml, as generate writes it
    from .gitops import image_setters
    app_dir = cdir.parent
    for d in docs:
        if d.get("kind") in WORKLOADS:
            for c in _at(d, WORKLOADS[d["kind"]])["spec"].get("containers") or []:
                if image.get("repository") and str(c.get("image") or "").startswith(image["repository"]):
                    c["image"] = f"{image['repository']}:{image.get('tag') or ''}"
    (cdir / MANIFESTS).write_text(_yaml_docs(docs))
    (cdir / HELMRELEASE).unlink()
    _set_resources(app_dir, {f"{cdir.name}/{HELMRELEASE}": f"{cdir.name}/{MANIFESTS}"})
    if image.get("repository"):
        k = app_dir / "kustomization.yaml"
        ktext = k.read_text()
        block = image_setters(str(vals.get("partOf") or ""), [(cdir.name, f"{image['repository']}:{image.get('tag')}")],
                              {image["repository"]: image.get("digest") or ""})
        if re.search(r"(?m)^images:", ktext):
            block = block.split("\n", 1)[1]
            ktext = re.sub(r"(?m)^images:\n", "images:\n" + block.replace("\\", "\\\\"), ktext, count=1)
        else:
            ktext = ktext.rstrip("\n") + "\n" + block
        k.write_text(ktext)
    return MANIFESTS


# --------------------------------------------------------------------------- the output repository

def referenced_charts(root: Path) -> set[str]:
    """The chart folders (from the root) the HelmReleases in the repository name."""
    refs = set()
    for f in root.glob(f"**/{HELMRELEASE}"):
        if ".git" in f.parts:
            continue
        hr = read_helmrelease(f)
        rel = str(((hr or {}).get("spec") or {}).get("chart", {}).get("spec", {}).get("chart") or "")
        if rel.startswith(f"./{CHARTS_DIR}/{CHART}/"):
            refs.add(rel.removeprefix("./"))
    return refs


def write_chart(root: Path, version: str = __version__) -> Path:
    """This version's chart at charts/containerizer-app/<version>/ of an output repository."""
    dst = root / chart_rel(version)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(PACKAGED, dst)
    chart = dst / "Chart.yaml"
    chart.write_text(re.sub(r"(?m)^version: .*$", f"version: {version}", chart.read_text()))
    (root / CHARTS_DIR / CHART / "README.md").write_text(
        "# containerizer-app\n\nThe shared Helm chart of the components Containerizer generated as `HelmRelease`s "
        "(docs/helm-chart.md), one folder per Containerizer version. Each `helmrelease.yaml` names the version it was "
        "generated with, so a new version changes nothing that runs until an application is generated again. "
        "Generated by `containerizer org`: versions no HelmRelease names any more are removed.\n")
    return dst


def sync_charts(root: Path) -> list[str]:
    """The charts the repository's HelmReleases name: this version's written (when named), the ones nothing names
    removed. Returns the chart folders kept."""
    refs = referenced_charts(root)
    if chart_rel() in refs:
        write_chart(root)
    base = root / CHARTS_DIR / CHART
    if base.is_dir():
        for d in base.iterdir():
            if d.is_dir() and f"{CHARTS_DIR}/{CHART}/{d.name}" not in refs:
                shutil.rmtree(d)
        if not any(base.iterdir()) or not any(p.is_dir() for p in base.iterdir()):
            shutil.rmtree(base)
            if (root / CHARTS_DIR).is_dir() and not any((root / CHARTS_DIR).iterdir()):
                (root / CHARTS_DIR).rmdir()
    return sorted(refs)


def copy_charts(app_dir: Path, dst_root: Path) -> list[str]:
    """The charts an application folder's HelmReleases name, copied (from the repository it is in, else this
    version's) to the same place in `dst_root` (a move to the application's own repository: appoutput.copy_app)."""
    done = []
    for rel in sorted(referenced_charts(app_dir)):
        src = find_chart(app_dir, rel)
        dst = dst_root / rel
        if src is not None and src.resolve() == dst.resolve():
            continue
        if dst.exists():
            shutil.rmtree(dst)
        if src is not None:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst)
        else:
            write_chart(dst_root, rel.rsplit("/", 1)[-1])
        done.append(rel)
    return done
