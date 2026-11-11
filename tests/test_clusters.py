"""clusters/<name>/: the real clusters of the output repository next to the sandbox (clusters.py)."""
import json
from pathlib import Path

import yaml

from containerizer import clusters, org

URL, BRANCH = "https://git/out.git", "main"


def app(root: Path, rel: str, ns: str, helm: bool = False) -> Path:
    d = root / rel
    (d / "gitops" / "flux").mkdir(parents=True)
    (d / "gitops" / "flux" / "kustomization.yaml").write_text("resources: []\n")
    (d / "containerizer.json").write_text(json.dumps({"app": ns, "namespace": ns, "components": []}))
    k = {"resources": []}
    if helm:
        (d / "web").mkdir()
        (d / "web" / "helmrelease.yaml").write_text(yaml.safe_dump({
            "apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": {"name": "web"},
            "spec": {"values": {"image": {"repository": f"localhost:5000/sandbox/{ns}/web", "tag": "1.1",
                                          "digest": "sha256:aa"}}}}))
        k["resources"] = ["web/helmrelease.yaml"]
    else:
        k["images"] = [{"name": f"localhost:5000/sandbox/{ns}/api", "newTag": "1.1"}]
    (d / "kustomization.yaml").write_text(yaml.safe_dump(k))
    return d


def load(p: Path):
    return yaml.safe_load(p.read_text())


def test_development_runs_every_app_and_production_only_listed_ones_pinned(tmp_path, monkeypatch):
    monkeypatch.delenv("CONTAINERIZER_CLUSTERS", raising=False)
    root = tmp_path / "out"
    app(root, "acme/p/shop", "p-shop")
    app(root, "acme/p/billing", "p-billing", helm=True)
    org.write_sandbox(root, URL, BRANCH)
    c = root / "clusters"
    assert sorted(x.name for x in c.iterdir() if x.is_dir()) == ["acceptance", "development", "production"]

    dev = load(c / "development" / "flux" / "apps" / "kustomization.yaml")
    assert dev["resources"] == ["../../../../acme/p/billing/gitops/flux", "../../../../acme/p/shop/gitops/flux"]
    paths = {p["target"]["name"]: json.loads(p["patch"])[0]["value"] for p in dev["patches"]}
    assert paths == {"p-shop": "./clusters/development/apps/p-shop", "p-billing": "./clusters/development/apps/p-billing"}
    ov = load(c / "development" / "apps" / "p-shop" / "kustomization.yaml")
    assert ov["resources"] == ["../../../../acme/p/shop"] and ov["components"] == ["custom"] and "images" not in ov
    assert "images" not in load(c / "development" / "apps" / "p-shop" / "custom" / "kustomization.yaml")
    boot = list(yaml.safe_load_all((c / "development" / "flux" / "bootstrap.yaml").read_text()))
    ks = [d for d in boot if d["kind"] == "Kustomization"][0]
    assert ks["spec"]["path"] == "./clusters/development/flux/apps" and ks["metadata"]["name"] == "containerizer-development"

    prod = c / "production"
    assert load(prod / "flux" / "apps" / "kustomization.yaml")["resources"] == []
    assert not (prod / "apps").exists()
    cfg = (prod / "cluster.yaml").read_text().replace("apps: []", "apps: [p-shop, p-billing]").replace(
        'registry: ""', "registry: registry.example.com/apps/")
    (prod / "cluster.yaml").write_text(cfg)
    org.write_sandbox(root, URL, BRANCH)
    assert len(load(prod / "flux" / "apps" / "kustomization.yaml")["resources"]) == 2
    custom = load(prod / "apps" / "p-shop" / "custom" / "kustomization.yaml")
    assert custom["kind"] == "Component" and custom["images"] == [
        {"name": "localhost:5000/sandbox/p-shop/api", "newTag": "1.1"}]
    assert load(prod / "apps" / "p-shop" / "kustomization.yaml")["images"] == [
        {"name": "localhost:5000/sandbox/p-shop/api", "newName": "registry.example.com/apps/p-shop/api"}]
    hc = load(prod / "apps" / "p-billing" / "custom" / "kustomization.yaml")["patches"][0]
    assert hc["target"]["kind"] == "HelmRelease" and hc["target"]["name"] == "web"
    assert json.loads(hc["patch"]) == [{"op": "add", "path": "/spec/values/image/tag", "value": "1.1"},
                                       {"op": "add", "path": "/spec/values/image/digest", "value": "sha256:aa"}]
    hr = load(prod / "apps" / "p-billing" / "kustomization.yaml")["patches"][0]
    assert json.loads(hr["patch"])[0]["value"] == "registry.example.com/apps/p-billing/web"

    # yours: a newer build and a promotion edit survive the next run
    (root / "acme/p/shop/kustomization.yaml").write_text(yaml.safe_dump(
        {"resources": [], "images": [{"name": "localhost:5000/sandbox/p-shop/api", "newTag": "1.2"}]}))
    f = prod / "apps" / "p-shop" / "custom" / "kustomization.yaml"
    f.write_text(f.read_text() + "# promoted\n")
    org.write_sandbox(root, URL, BRANCH)
    assert f.read_text().endswith("# promoted\n") and "newTag: '1.1'" in f.read_text()
    assert "registry: registry.example.com/apps/" in (prod / "cluster.yaml").read_text()

    # taken off the list: the cluster prunes it, its settings stay
    (prod / "cluster.yaml").write_text(cfg.replace("apps: [p-shop, p-billing]", "apps: [p-billing]"))
    org.write_sandbox(root, URL, BRANCH)
    assert not (prod / "apps" / "p-shop" / "kustomization.yaml").exists() and f.exists()
    assert load(prod / "flux" / "apps" / "kustomization.yaml")["resources"] == ["../../../../acme/p/billing/gitops/flux"]


def test_a_pinned_image_takes_the_digest_the_scan_pushed(tmp_path):
    d = app(tmp_path, "acme/p/shop", "p-shop")
    (d / "containerizer.json").write_text(json.dumps({"app": "p-shop", "components": [
        {"image": "localhost:5000/sandbox/p-shop/api:1.1", "digest": "sha256:bb"}]}))
    imgs = clusters.app_images(d)
    assert imgs == [{"name": "localhost:5000/sandbox/p-shop/api", "tag": "1.1", "digest": "sha256:bb"}]
    c = yaml.safe_load(clusters.custom_text("production", "p-shop", imgs, True))
    assert c["images"] == [{"name": "localhost:5000/sandbox/p-shop/api", "newTag": "1.1", "digest": "sha256:bb"}]
    assert "images" not in yaml.safe_load(clusters.custom_text("development", "p-shop", imgs, False))


def test_cluster_names_and_the_sandbox_index_are_unchanged(tmp_path, monkeypatch):
    root = tmp_path / "out"
    app(root, "acme/p/shop", "p-shop")
    monkeypatch.setenv("CONTAINERIZER_CLUSTERS", "Dev, sandbox, qa,dev")
    assert clusters.names() == ["dev", "qa"]
    org.write_sandbox(root, URL, BRANCH)
    assert sorted(x.name for x in (root / "clusters").iterdir() if x.is_dir()) == ["dev", "qa"]
    assert load(root / "sandbox" / "flux" / "apps" / "kustomization.yaml")["resources"] == [
        "../../../acme/p/shop/gitops/flux"]
    assert [x[0] for x in org._apps_in(root)] == ["acme/p/shop"]
    monkeypatch.setenv("CONTAINERIZER_CLUSTERS", "none")
    assert clusters.names() == []
