"""No application gets a namespace of the cluster, the platform or Containerizer itself: its namespace gets a Flux
tenant with the admin role, default-deny NetworkPolicies and Pod Security labels, and is deleted with it."""
import json

import pytest

from containerizer import labservices, org
from containerizer.generate import app_ns, reserved_namespace
from containerizer.orgsource import NO_PROJECT


@pytest.mark.parametrize("project,repo,want", [
    (NO_PROJECT, "kube-system", "app-kube-system"),
    (NO_PROJECT, "external-secrets", "app-external-secrets"),          # a fork of ESO in a GitHub organization
    (NO_PROJECT, "containerizer-secrets", "app-containerizer-secrets"),
    (NO_PROJECT, "containerizer-lab", "app-containerizer-lab"),
    ("containerizer", "secrets", "app-containerizer-secrets"),           # Azure DevOps project + repository
    ("kube", "system", "app-kube-system"),
    (NO_PROJECT, "flux-system", "app-flux-system"),
    (NO_PROJECT, "Default", "app-default"),
    (NO_PROJECT, "shop", "shop"),
    ("contoso", "shop", "contoso-shop"),
    (NO_PROJECT, "cz-portal", "cz-portal"),                               # not reserved: no rename
])
def test_app_names_never_take_a_reserved_namespace(project, repo, want):
    assert org.app_name(project, repo) == want
    assert app_ns(want) == want                                          # idempotent


def test_split_folders_and_the_cli_are_guarded():
    assert org.split_app_name("flux", "system") == "app-flux-system"
    assert org.split_app_name("external", "secrets") == "app-external-secrets"
    assert org.split_app_name("shop", "api") == "shop-api"
    assert app_ns("kube-system") == "app-kube-system" and app_ns("Containerizer.Secrets") == "app-containerizer-secrets"
    assert app_ns("my-app") == "my-app"


def test_reserved_namespaces():
    for ns in ("kube-system", "kube-public", "default", "flux-system", "external-secrets", "containerizer-secrets",
               "containerizer-lab", "containerizer-idp", "containerizer-verify", "openshift-x", "local-path-storage"):
        assert reserved_namespace(ns) and labservices.reserved(ns), ns
    assert not reserved_namespace("app-kube-system") and not reserved_namespace("shop")


def test_the_sandbox_never_deploys_into_a_reserved_namespace(tmp_path, capsys):
    """Defence in depth: an app folder that names a reserved namespace (made by an older version, or by hand)
    is left out of sandbox/."""
    for rel, ns in (("org/p/shop", "shop"), ("org/p/evil", "external-secrets")):
        d = tmp_path / rel
        (d / "gitops" / "flux").mkdir(parents=True)
        (d / "gitops" / "flux" / "kustomization.yaml").write_text("resources: []\n")
        (d / "containerizer.json").write_text(json.dumps({"namespace": ns, "app": ns}))
    org.write_sandbox(tmp_path, "https://git.example.com/out.git", "main")
    text = "".join(p.read_text() for p in (tmp_path / "clusters" / "sandbox").rglob("*.yaml"))
    assert "org/p/shop" in text and "org/p/evil" not in text
    assert "namespace external-secrets is reserved" in capsys.readouterr().err


def test_one_cluster_kit_in_each_cluster(tmp_path, monkeypatch):
    """The cluster-level kit (secret store, one image policy for every managed namespace with each app's image path,
    audit policy) is in each real cluster's platform/; the app folders' copies go."""
    monkeypatch.delenv("CONTAINERIZER_CLUSTERS", raising=False)
    import yaml
    for rel, ns in (("org/p/shop", "shop"), ("org/p/billing", "billing")):
        d = tmp_path / rel
        (d / "gitops" / "flux").mkdir(parents=True)
        (d / "gitops" / "flux" / "kustomization.yaml").write_text("resources: []\n")
        (d / "containerizer.json").write_text(json.dumps({"namespace": ns, "app": ns}))
        (d / "web").mkdir()
        (d / "web" / "k8s.yaml").write_text(f"kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
                                            f"      - image: registry.local/{ns}/web:1.2\n")
        (d / "cluster").mkdir()
        (d / "cluster" / "audit-policy.yaml").write_text("old\n")
    org.write_sandbox(tmp_path, "https://git.example.com/out.git", "main")
    assert not (tmp_path / "org/p/shop/cluster").exists() and not (tmp_path / "org/p/billing/cluster").exists()
    assert not (tmp_path / "cluster").exists()
    kit = tmp_path / "clusters" / "production" / "platform"
    assert sorted(p.name for p in kit.iterdir()) == ["README.md", "audit-policy.yaml", "secret-store.yaml",
                                                      "verify-images.yaml"]
    pol = yaml.safe_load((kit / "verify-images.yaml").read_text())
    rule = pol["spec"]["rules"][0]
    assert pol["metadata"]["name"] == "verify-images-containerizer"
    assert rule["verifyImages"][0]["imageReferences"] == ["registry.local/billing/*", "registry.local/shop/*"]
    assert rule["match"]["any"][0]["resources"]["namespaceSelector"]["matchLabels"] == {
        "app.kubernetes.io/managed-by": "containerizer"}
    assert any(d["kind"] == "ClusterSecretStore" for d in yaml.safe_load_all((kit / "secret-store.yaml").read_text()) if d)
