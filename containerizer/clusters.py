"""`clusters/<name>/` in the output repository: the same apps for the real clusters next to the sandbox.

The sandbox (`clusters/sandbox/`, org.write_sandbox) is one cluster of the output repository; `clusters/` holds the others,
by default development, acceptance and production (CONTAINERIZER_CLUSTERS="development,acceptance,production"
changes the names). Every cluster deploys the same app folders, and the same images;
what differs per cluster lives in the cluster's own folder:

    clusters/<name>/
      cluster.yaml                    which apps the cluster runs and the registry it pulls from   (yours)
      README.md                       how to bootstrap it                                          (generated)
      flux/bootstrap.yaml             the root GitRepository + Kustomization                       (generated)
      flux/apps/kustomization.yaml    each app's gitops/flux, pointed at the overlay below          (generated)
      apps/<namespace>/
        kustomization.yaml            the app folder + the cluster's registry                       (generated)
        custom/kustomization.yaml     image promotion, replicas, hosts: a kustomize
                                      Component                                                     (yours)

"Yours": written once, when the cluster or the app first appears, and never rewritten, so the settings of a cluster
survive every scan. Development runs every app and follows each new build; acceptance and production run only the
apps listed in their `cluster.yaml`, pinned to the images the app had when the cluster first ran it: promoting a
build is a commit that changes the tag in its `custom/`.

Unlike the sandbox, the clusters keep each app Kustomization's `wait: true`, the Gateway API HTTPRoutes and no
sandbox identity provider; the read-back (`containerizer sandbox verify`) is for the sandbox only.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml

CLUSTERS_DIR = "clusters"
DEFAULT_CLUSTERS = ("development", "acceptance", "production")
FOLLOWS = ("development",)          # clusters that run every app and follow new builds by default
K_API = "kustomize.config.k8s.io/v1beta1"
COMPONENT_API = "kustomize.config.k8s.io/v1alpha1"


def names() -> list[str]:
    """The clusters next to the sandbox: CONTAINERIZER_CLUSTERS (comma separated; "none" or empty: no clusters/),
    else development, acceptance and production."""
    raw = os.environ.get("CONTAINERIZER_CLUSTERS")
    if raw is None:
        return list(DEFAULT_CLUSTERS)
    from .generate import k8s_name
    out = []
    for n in raw.split(","):
        n = n.strip()
        if n and n.lower() != "none" and n != "sandbox":
            n = k8s_name(n)
            if n not in out:
                out.append(n)
    return out


def _dump(docs) -> str:
    return "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)


def _load(p: Path) -> dict:
    try:
        d = yaml.safe_load(p.read_text())
    except (OSError, yaml.YAMLError):
        return {}
    return d if isinstance(d, dict) else {}


def settings(cdir: Path, name: str) -> dict:
    """The cluster's cluster.yaml, written with its defaults the first time."""
    f = cdir / "cluster.yaml"
    if not f.exists():
        follows = name in FOLLOWS
        cdir.mkdir(parents=True, exist_ok=True)
        f.write_text(f"""# Cluster "{name}". Containerizer writes this file once and never rewrites it: it is yours.
#
# deploy: all     every app in this repository, new ones as soon as a scan writes them
#         listed  only the app namespaces under `apps` (see the namespaces in clusters/sandbox/namespaces.txt)
deploy: {"all" if follows else "listed"}
apps: []
#  - containerization-challenge-shop

# The registry this cluster pulls from, e.g. registry.example.com/apps: images become
# <registry>/<namespace>/<component> (where the generated CI pipelines push). Empty: the images as built.
registry: ""
""")
    d = _load(f)
    deploy = str(d.get("deploy") or "listed").strip().lower()
    apps = d.get("apps") or []
    return {"deploy": deploy if deploy in ("all", "listed") else "listed",
            "apps": {str(a).strip() for a in apps} if isinstance(apps, list) else set(),
            "registry": str(d.get("registry") or "").strip().rstrip("/")}


def _app_resources(folder: Path) -> list[tuple[str, list[dict]]]:
    """(resource file, its documents) of every file the app folder's kustomization.yaml lists."""
    k = _load(folder / "kustomization.yaml")
    out = []
    for r in k.get("resources") or []:
        f = folder / str(r)
        if f.is_file() and f.suffix in (".yaml", ".yml"):
            try:
                out.append((str(r), [d for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]))
            except yaml.YAMLError:
                continue
    return out


def app_images(folder: Path) -> list[dict]:
    """The images of an app folder: {name, tag, digest?}, from its kustomization's `images` (name + newTag)."""
    pushed = {}                     # the digests the scan pushed (containerizer.json), by image without its tag
    try:
        for c in json.loads((folder / "containerizer.json").read_text()).get("components") or []:
            if isinstance(c, dict) and c.get("image") and c.get("digest"):
                pushed[str(c["image"]).rsplit("@", 1)[0].rsplit(":", 1)[0]] = str(c["digest"])
    except (OSError, ValueError, AttributeError):
        pass
    out = []
    for i in _load(folder / "kustomization.yaml").get("images") or []:
        if isinstance(i, dict) and i.get("name"):
            out.append({"name": str(i["name"]), "tag": str(i.get("newTag") or ""),
                        "digest": str(i.get("digest") or pushed.get(str(i["name"])) or "")})
    return out


def moved_name(image: str, ns: str, registry: str) -> str:
    """<registry>/<namespace>/<component> of a built image (its last path segment is the component)."""
    return f"{registry}/{ns}/{image.rsplit('/', 1)[-1]}"


def unchart_custom(path: Path, images: list[dict]) -> bool:
    """A cluster's custom/kustomization.yaml written for an app of the shared Helm chart (before 0.43.0): its patches
    that pinned a HelmRelease's image tag and digest become `images:` entries (the app is plain manifests now, its
    images are kustomize images); the rest of the file stays. True when it changed."""
    import yaml
    try:
        c = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return False
    pins, keep = [], []
    for p in c.get("patches") or []:
        t = (p.get("target") or {}) if isinstance(p, dict) else {}
        if t.get("kind") != "HelmRelease":
            keep.append(p)
            continue
        try:
            ops = {o["path"]: o.get("value") for o in (json.loads(p["patch"]) if isinstance(p.get("patch"), str)
                                                        and p["patch"].lstrip().startswith("[") else yaml.safe_load(p["patch"]))}
        except (ValueError, KeyError, TypeError, yaml.YAMLError):
            keep.append(p)
            continue
        img = next((i for i in images if i["name"].rsplit("/", 1)[-1] == t.get("name")), None)
        if img and ops.get("/spec/values/image/tag"):
            pins.append({"name": img["name"], "newTag": str(ops["/spec/values/image/tag"]),
                         **({"digest": str(ops["/spec/values/image/digest"])} if ops.get("/spec/values/image/digest") else {})})
    if not pins and len(keep) == len(c.get("patches") or []):
        return False
    head = "".join(ln + "\n" for ln in path.read_text().splitlines() if ln.startswith("#"))
    if keep:
        c["patches"] = keep
    else:
        c.pop("patches", None)
    if pins:
        c["images"] = [i for i in c.get("images") or [] if i.get("name") not in {x["name"] for x in pins}] + pins
    from .org import readable_patches, readable_yaml
    path.write_text(head + readable_yaml(readable_patches(c)))
    return True


def overlay(rel: str, ns: str, images: list[dict], registry: str) -> dict:
    """apps/<namespace>/kustomization.yaml: the app folder, the cluster's Component and its registry."""
    k = {"apiVersion": K_API, "kind": "Kustomization", "resources": [f"../../../../{rel}"], "components": ["custom"]}
    if registry:
        plain = [{"name": i["name"], "newName": moved_name(i["name"], ns, registry)} for i in images]
        if plain:
            k["images"] = plain
    return k


def custom_text(name: str, ns: str, images: list[dict], pin: bool) -> str:
    """apps/<namespace>/custom/kustomization.yaml: the cluster's own settings of one app, written once."""
    c = {"apiVersion": COMPONENT_API, "kind": "Component"}
    plain = images
    if pin and plain:
        # with the digest: a later build's digest in the app folder cannot override the pinned tag
        c["images"] = [{"name": i["name"], "newTag": i["tag"], **({"digest": i["digest"]} if i["digest"] else {})}
                       for i in plain if i["tag"]]
    if pin:
        head = (f"# {ns} in cluster \"{name}\": pinned to the images the app had when the\n"
                f"# cluster first ran it. Promote a build by changing its tag and digest here (the scan's\n"
                f"# digests: containerizer.json of the app folder; empty digest: by tag).\n")
    else:
        head = (f"# {ns} in cluster \"{name}\": follows every new build of the app folder.\n# Pin an image with\n"
                f"#   images: [{{name: <image>, newTag: <tag>}}]\n")
    head += ("# Containerizer writes this file once and never rewrites it: it is yours. Other per-cluster settings go\n"
             "# here too, as kustomize patches, e.g. replicas of a Deployment or an Ingress host:\n"
             "#   patches:\n"
             "#   - target: {kind: Deployment, name: <component>}\n"
             "#     patch: '[{\"op\": \"replace\", \"path\": \"/spec/replicas\", \"value\": 3}]'\n")
    from .org import readable_patches, readable_yaml
    return head + readable_yaml(readable_patches(c))


def write_cluster(root: Path, name: str, git_url: str, branch: str, apps) -> list[str]:
    """clusters/<name>/ for the apps (org._apps_in rows). Returns the namespaces the cluster runs."""
    from .gitops import FLUX_NS, KUSTOMIZE_API, SOURCE_API
    from .org import sandbox_credentials
    cdir = root / CLUSTERS_DIR / name
    s = settings(cdir, name)
    pin = name not in FOLLOWS
    chosen = [(rel, d, doc) for rel, d, doc in apps if doc.get("app") and (s["deploy"] == "all" or doc["app"] in s["apps"])]
    adir = cdir / "apps"
    known = {doc["app"] for _, _, doc in apps if doc.get("app")}
    running = {doc["app"] for _, _, doc in chosen}
    for old in sorted(adir.glob("*/kustomization.yaml")) if adir.is_dir() else []:
        if old.parent.name not in running:         # left the cluster (or the repository): its custom/ stays
            old.unlink()
    from .org import readable_patches, readable_yaml
    patches = []
    group, version = KUSTOMIZE_API.split("/")
    for rel, d, doc in chosen:
        ns = doc["app"]
        images = app_images(d)
        o = adir / ns
        (o / "custom").mkdir(parents=True, exist_ok=True)
        (o / "kustomization.yaml").write_text(
            f"# Generated by `containerizer org`; the next run rewrites it. Your settings: custom/ and ../../cluster.yaml\n"
            + readable_yaml(readable_patches(overlay(rel, ns, images, s["registry"]))))
        if not (o / "custom" / "kustomization.yaml").exists():   # the first time the cluster runs the app
            (o / "custom" / "kustomization.yaml").write_text(custom_text(name, ns, images, pin))
        else:                                                     # its chart image pins, as kustomize images
            unchart_custom(o / "custom" / "kustomization.yaml", images)
        patches.append({"target": {"group": group, "version": version, "kind": "Kustomization", "name": ns,
                                   "namespace": ns},
                        "patch": json.dumps([{"op": "replace", "path": "/spec/path",
                                              "value": f"./{CLUSTERS_DIR}/{name}/apps/{ns}"}])})
    (cdir / "flux" / "apps").mkdir(parents=True, exist_ok=True)
    (cdir / "flux" / "apps" / "kustomization.yaml").write_text(readable_yaml(
        {"apiVersion": K_API, "kind": "Kustomization",
         "resources": [f"../../../../{rel}/gitops/flux" for rel, _, _ in chosen],
         **({"patches": readable_patches(patches)} if patches else {})}))
    root_name = f"containerizer-{name}"
    labels = {"app.kubernetes.io/part-of": root_name, "app.kubernetes.io/managed-by": "containerizer"}
    (cdir / "flux" / "bootstrap.yaml").write_text(_dump(sandbox_credentials(FLUX_NS, root_name, labels) + [
        {"apiVersion": SOURCE_API, "kind": "GitRepository",
         "metadata": {"name": root_name, "namespace": FLUX_NS, "labels": labels},
         "spec": {"interval": "5m", "url": git_url, "ref": {"branch": branch}, "secretRef": {"name": f"{root_name}-git"}}},
        {"apiVersion": KUSTOMIZE_API, "kind": "Kustomization",
         "metadata": {"name": root_name, "namespace": FLUX_NS, "labels": labels},
         "spec": {"interval": "10m", "retryInterval": "2m", "timeout": "5m", "prune": True, "wait": False,
                  "sourceRef": {"kind": "GitRepository", "name": root_name},
                  "path": f"./{CLUSTERS_DIR}/{name}/flux/apps"}},
    ]))
    missing = sorted(s["apps"] - known) if s["deploy"] == "listed" else []
    if missing:
        print(f"warning: {CLUSTERS_DIR}/{name}/cluster.yaml lists apps this repository does not have: "
              f"{', '.join(missing)}", file=sys.stderr)
    namespaces = sorted(doc["app"] for _, _, doc in chosen)
    (cdir / "README.md").write_text(readme(name, s, chosen, pin, missing))
    return namespaces


def write_clusters(root: Path, git_url: str, branch: str, apps) -> dict[str, list[str]]:
    """clusters/<name>/ for every cluster of names(), and clusters/README.md. Folders of clusters no longer named
    stay as they are."""
    out = {n: write_cluster(root, n, git_url, branch, apps) for n in names()}
    if out:
        (root / CLUSTERS_DIR / "README.md").write_text(index(out))
    return out


def index(clusters: dict[str, list[str]]) -> str:
    rows = "\n".join(f"| [{n}]({n}/) | {len(ns)} |" for n, ns in clusters.items())
    return f"""# Clusters

The sandbox (`sandbox/`, next to these) and the clusters below deploy the same app folders and images with
Flux. Each cluster's own settings are in its folder: `cluster.yaml` (which apps, the registry it pulls from) and
`apps/<namespace>/custom/` (image promotion, replicas, hosts). Containerizer writes those once and
never rewrites them; everything else here is generated by `containerizer org` and rewritten by every run.

| Cluster | Apps |
| --- | --- |
| [sandbox](sandbox/) | every app rated A, every build (the appliance's own cluster) |
{rows}

Names: CONTAINERIZER_CLUSTERS (default `development,acceptance,production`).
"""


def readme(name: str, s: dict, chosen, pin: bool, missing: list[str]) -> str:
    rows = "\n".join(f"| `{doc['app']}` | [{rel}](../../{rel.replace(' ', '%20')}/) | [custom](apps/{doc['app']}/custom/kustomization.yaml) |"
                     for rel, _, doc in chosen) or "| | | |"
    which = ("every app in this repository (`deploy: all`)" if s["deploy"] == "all"
             else "the apps listed in `cluster.yaml` (`deploy: listed`)")
    follows = ("Its apps are pinned to the images they had when this cluster first ran them (their "
               "`custom/kustomization.yaml`): promote a build by changing its tag and digest there." if pin else
               "Its apps follow every new build of the app folders; pin one in its `custom/kustomization.yaml`.")
    warn = (f"\n**Not in this repository** (listed in `cluster.yaml`): {', '.join(f'`{m}`' for m in missing)}\n"
            if missing else "")
    return f"""# Cluster: {name}

This cluster runs {which}. {follows}
Images come from {f"`{s['registry']}/<namespace>/<component>`" if s['registry'] else "the registry they were built in"}
(`registry` in `cluster.yaml`). Generated by `containerizer org`; your settings are `cluster.yaml` and each app's
`apps/<namespace>/custom/`, which no run rewrites.

| Namespace | App folder | Settings |
| --- | --- | --- |
{rows}
{warn}
## Bootstrap

Prerequisites as for the sandbox (`clusters/sandbox/README.md`): Flux, External Secrets Operator with the `ClusterSecretStore`
`app-secrets` (`cluster/secret-store.yaml`), and this repository's read-only token in the store under
`flux-system--cz-git` and `<namespace>--cz-git` of every app. The cluster kit in `cluster/` (signed images,
audit policy) is meant for this cluster. Then:

```sh
kubectl apply -f {CLUSTERS_DIR}/{name}/flux/bootstrap.yaml
```

Each app's Flux Kustomization (`gitops/flux/git/sync.yaml` of its folder) is pointed at `apps/<namespace>/` here,
which builds the app folder with this cluster's registry and `custom/` Component. Unlike the sandbox it keeps
`wait: true` (a secret missing from the store stops the rollout) and the Gateway API HTTPRoutes. The secrets of the
app's settings and of the lab services it used in the sandbox (`<namespace>--cz-lab-*`) are remote keys in this
cluster's secret store: put the real values there.
"""
