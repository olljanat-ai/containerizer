"""A component's objects in the output repository (manifests.py): one file per kind with a kustomization.yaml, read
and written back in that form; the applications deployed with the shared Helm chart before 0.43.0 converted back to
manifests (helmchart.py), with their image pins; user namespaces of the generated pods."""
import json
import shutil
import subprocess
from pathlib import Path

import yaml

from containerizer import clusters, helmchart, manifests as m, org as orgmod
from containerizer.assess import assess
from containerizer.generate import generate_app
from containerizer.gitops import GitOpsOptions

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "chart-0.42"     # written by 0.42.0 in chart mode
WORKLOADS = {"Deployment": ("spec", "template"), "CronJob": ("spec", "jobTemplate", "spec", "template")}


def _generated(tmp_path, domain="apps.example.com"):
    """The ci-demo app generated: {component folder: its objects} (each in its k8s.yaml)."""
    out = tmp_path / "gen"
    generate_app(assess(ROOT / "examples" / "ci-demo"), out, gitops=GitOpsOptions(ingress_domain=domain))
    ns = yaml.safe_load((out / "kustomization.yaml").read_text())["namespace"]
    comps = {f.parent.name: [d for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]
             for f in sorted(out.glob("*/k8s.yaml")) if f.parent.name not in ("lab", "devdb")}
    return out, ns, comps


def _build(path: Path) -> str | None:
    if not shutil.which("kubectl"):
        return None
    p = subprocess.run(["kubectl", "kustomize", str(path)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout


def test_a_file_per_kind_with_a_kustomization(tmp_path):
    """Each component folder holds one file per kind and a kustomization.yaml listing them, the app's kustomization.yaml
    lists the folder. What kustomize builds is what k8s.yaml held; reading and writing back keep the form."""
    out, ns, comps = _generated(tmp_path)
    before = {c: list(docs) for c, docs in comps.items()}
    assert m.split_app(out, list(comps)) == list(comps)
    comp = next(iter(comps))
    cdir = out / comp
    assert not (cdir / "k8s.yaml").exists() and m.component_form(cdir) == "split"
    files = yaml.safe_load((cdir / "kustomization.yaml").read_text())["resources"]
    assert "deployment.yaml" in files and "service.yaml" in files and "networkpolicy.yaml" in files
    assert all((cdir / f).is_file() for f in files)
    assert {d["kind"] for d in yaml.safe_load_all((cdir / "networkpolicy.yaml").read_text())} == {"NetworkPolicy"}
    assert sorted(map(json.dumps, m.component_docs(cdir))) == sorted(map(json.dumps, before[comp]))
    res = yaml.safe_load((out / "kustomization.yaml").read_text())["resources"]
    assert comp in res and f"{comp}/k8s.yaml" not in res
    docs = m.component_docs(cdir)
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")
    pol["spec"].setdefault("egress", []).append({"to": [{"podSelector": {"matchLabels": {"app": "x"}}}]})
    assert m.write_component_docs(cdir, docs) == "kustomization.yaml"
    assert m.component_docs(cdir) == docs
    built = _build(out)
    assert built is None or "kind: Deployment" in built


def test_the_settings_configmap_is_settings_yaml(tmp_path):
    out, ns, comps = _generated(tmp_path)
    comp = next(iter(comps))
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{comp}-settings"}, "data": {"Api__Url": ""}}
    (out / comp / "k8s.yaml").write_text((out / comp / "k8s.yaml").read_text() + "---\n" + yaml.safe_dump(cm))
    m.split_app(out, [comp])
    assert yaml.safe_load((out / comp / "settings.yaml").read_text()) == cm
    assert "settings.yaml" in yaml.safe_load((out / comp / "kustomization.yaml").read_text())["resources"]


def test_a_chart_application_is_converted_back_to_manifests(tmp_path):
    """An application written in chart mode by 0.42.0: each HelmRelease becomes a file per kind (what the chart
    rendered), its image an `images:` entry with the image automation markers, settings.yaml part of the folder;
    containerizer.json says nothing about deploy modes any more and charts/ goes."""
    root = tmp_path / "out"
    shutil.copytree(FIXTURE, root)
    app = root / "acme/_/shop"
    rendered = helmchart.rendered_docs(app / "demo-web")
    assert {d["kind"] for d in rendered} >= {"Deployment", "Service", "ConfigMap"}
    assert orgmod._apps_in(root)
    assert helmchart.unchart_repository(root, orgmod._apps_in(root)) == ["acme/_/shop/demo-web"]
    cdir = app / "demo-web"
    assert m.component_form(cdir) == "split" and not (cdir / "helmrelease.yaml").exists()
    docs = m.component_docs(cdir)
    assert [d["kind"] for d in docs if d["kind"] != "Deployment"] == [d["kind"] for d in rendered if d["kind"] != "Deployment"]
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["containers"][0]["image"] == "registry.local/ci-demo/demo-web:latest"
    k = (app / "kustomization.yaml").read_text()
    res = yaml.safe_load(k)["resources"]
    assert "demo-web" in res and "demo-web/helmrelease.yaml" not in res and "demo-web/settings.yaml" not in res
    assert '{"$imagepolicy": "ci-demo:demo-web:tag"}' in k
    assert yaml.safe_load(k)["images"][0]["name"] == "registry.local/ci-demo/demo-web"
    doc = json.loads((app / "containerizer.json").read_text())
    assert "deploy_mode" not in doc and "deploy_mode" not in doc["components"][0]
    assert not (root / "charts").exists()
    assert helmchart.unchart_repository(root, orgmod._apps_in(root)) == []        # once
    built = _build(app)
    assert built is None or ("kind: Deployment" in built and "HelmRelease" not in built)


def test_a_clusters_chart_image_pin_becomes_an_images_entry(tmp_path):
    f = tmp_path / "kustomization.yaml"
    f.write_text("# ci-demo in cluster \"production\": pinned\napiVersion: kustomize.config.k8s.io/v1alpha1\n"
                 "kind: Component\npatches:\n"
                 "- target: {group: helm.toolkit.fluxcd.io, version: v2, kind: HelmRelease, name: demo-web}\n"
                 "  patch: '[{\"op\": \"add\", \"path\": \"/spec/values/image/tag\", \"value\": \"1.2\"}, "
                 "{\"op\": \"add\", \"path\": \"/spec/values/image/digest\", \"value\": \"sha256:aa\"}]'\n"
                 "- target: {kind: Deployment, name: demo-web}\n"
                 "  patch: '[{\"op\": \"replace\", \"path\": \"/spec/replicas\", \"value\": 3}]'\n")
    images = [{"name": "registry.local/ci-demo/demo-web", "tag": "1.3", "digest": ""}]
    assert clusters.unchart_custom(f, images)
    c = yaml.safe_load(f.read_text())
    assert c["images"] == [{"name": "registry.local/ci-demo/demo-web", "newTag": "1.2", "digest": "sha256:aa"}]
    assert [p["target"]["kind"] for p in c["patches"]] == ["Deployment"]
    assert f.read_text().startswith("# ci-demo in cluster")
    assert not clusters.unchart_custom(f, images)


# --------------------------------------------------------------------------- user namespaces

def _pods(docs):
    for d in docs:
        if d["kind"] in WORKLOADS:
            x = d
            for k in WORKLOADS[d["kind"]]:
                x = x[k]
            yield x["spec"]


def test_generated_pods_get_their_own_user_namespace(tmp_path, monkeypatch):
    from containerizer.harden import USER_NAMESPACES_ENV, lint_manifests
    monkeypatch.delenv(USER_NAMESPACES_ENV, raising=False)
    _out, ns, comps = _generated(tmp_path)
    for comp, docs in comps.items():
        assert all(p["hostUsers"] is False for p in _pods(docs))
        assert not [v for v in lint_manifests(docs) if v.check == "user-namespace"]
    monkeypatch.setenv(USER_NAMESPACES_ENV, "false")               # a cluster whose runtime cannot do it
    _out, ns, comps = _generated(tmp_path / "off")
    for docs in comps.values():
        assert all("hostUsers" not in p for p in _pods(docs))


def test_an_exception_keeps_the_nodes_user_namespace(monkeypatch):
    from containerizer.harden import USER_NAMESPACES_ENV, harden_pod, lint_manifests
    monkeypatch.delenv(USER_NAMESPACES_ENV, raising=False)
    pod = {"containers": [{"name": "c", "image": "x:1"}]}
    harden_pod({}, pod, 1000, "c", [{"id": "needs-host-ids", "patch": {"host_users": True}}])
    assert "hostUsers" not in pod
    dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "c"},
           "spec": {"template": {"metadata": {}, "spec": pod}}}
    assert [v for v in lint_manifests([dep]) if v.check == "user-namespace"]
