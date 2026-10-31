"""Sandbox verification against a real Kubernetes cluster (kind in CI).

Set CONTAINERIZER_TEST_KUBE to an admin kubeconfig of a disposable cluster; kubectl must be on PATH.
The test creates its own namespaces, minimal Argo CD Application / Flux Kustomization CRDs (no
controllers: the test writes the sync status itself, as the controllers would), deploys four kinds of
component (healthy web, crash loop, image that cannot be pulled, CronJob), applies the generated
least-privilege RBAC and runs the read-back with a short-lived token of the verifier ServiceAccount.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from containerizer import sandbox as sb

ADMIN = os.environ.get("CONTAINERIZER_TEST_KUBE")
pytestmark = pytest.mark.skipif(not ADMIN, reason="set CONTAINERIZER_TEST_KUBE to an admin kubeconfig of a test cluster")
SHA = "c" * 40
ARGO_APP, FLUX_APP = "cz-e2e-shop", "cz-e2e-flux"
LABEL = {"containerizer-e2e": "true"}


def kubectl(*args, input=None, check=True):
    p = subprocess.run(["kubectl", f"--kubeconfig={ADMIN}", *args], input=input, capture_output=True, text=True,
                       timeout=180)
    if check and p.returncode:
        raise AssertionError(f"kubectl {' '.join(args)}: {p.stderr}")
    return p.stdout


def apply(docs):
    kubectl("apply", "-f", "-", input="---\n".join(yaml.safe_dump(d) for d in docs))


def crd(group, kind, plural):
    return {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
            "metadata": {"name": f"{plural}.{group}", "labels": LABEL},
            "spec": {"group": group, "scope": "Namespaced",
                     "names": {"kind": kind, "plural": plural, "singular": kind.lower()},
                     "versions": [{"name": "v1" if "flux" in group else "v1alpha1", "served": True, "storage": True,
                                   "schema": {"openAPIV3Schema": {"type": "object",
                                                                  "x-kubernetes-preserve-unknown-fields": True}}}]}}


# images from mcr.microsoft.com: no Docker Hub pull limits in CI
WEB_IMAGE = "mcr.microsoft.com/dotnet/samples:aspnetapp"        # ASP.NET Core on 8080, non-root (uid 1654)
SHELL_IMAGE = "mcr.microsoft.com/cbl-mariner/busybox:2.0"
SEC = {"runAsNonRoot": True, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
       "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}


def deployment(name, image, command=None, port=None, replicas=1):
    c = {"name": name, "image": image, "securityContext": {**SEC, **({"runAsUser": 65534} if image == SHELL_IMAGE else {})},
         "resources": {"requests": {"cpu": "10m", "memory": "64Mi"}, "limits": {"memory": "256Mi"}},
         "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}
    if command:
        c["command"] = command
    if port:
        c["ports"] = [{"name": "http", "containerPort": port}]
        c["readinessProbe"] = {"httpGet": {"path": "/", "port": "http"}, "periodSeconds": 2}
    labels = {"app.kubernetes.io/name": name}
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "labels": labels},
            "spec": {"replicas": replicas, "selector": {"matchLabels": labels},
                     "template": {"metadata": {"labels": labels},
                                  "spec": {"automountServiceAccountToken": False, "containers": [c],
                                           "volumes": [{"name": "tmp", "emptyDir": {}}]}}}}


def cronjob(name):
    return {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": name},
            "spec": {"schedule": "0 2 1 1 *", "jobTemplate": {"spec": {"template": {"spec": {
                "restartPolicy": "OnFailure", "automountServiceAccountToken": False,
                "containers": [{"name": name, "image": SHELL_IMAGE, "command": ["true"],
                                "securityContext": {**SEC, "runAsUser": 65534}}]}}}}}}


def write_app(root: Path, rel: str, app: str, comps: dict) -> None:
    d = root / rel
    (d / "gitops" / "argocd").mkdir(parents=True)
    (d / "gitops" / "argocd" / "kustomization.yaml").write_text("resources: []\n")
    meta = []
    for folder, docs in comps.items():
        (d / folder).mkdir()
        (d / folder / "k8s.yaml").write_text("---\n".join(yaml.safe_dump(x) for x in docs))
        meta.append({"component": f"Shop.{folder.title()}", "folder": folder, "project": f"src/{folder}/{folder}.csproj",
                     "project_name": f"Shop.{folder.title()}", "image": docs[0].get("spec", {}).get("template", {})
                    .get("spec", {}).get("containers", [{}])[0].get("image", "")})
    (d / "containerizer.json").write_text(json.dumps({"app": app, "components": meta, "source_key": f"{app}#"}))


@pytest.fixture(scope="module")
def cluster():
    ns_meta = lambda n: {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": n, "labels": {
        **LABEL, "pod-security.kubernetes.io/enforce": "restricted"}}}
    apply([crd("argoproj.io", "Application", "applications"),
           crd("kustomize.toolkit.fluxcd.io", "Kustomization", "kustomizations"),
           ns_meta(ARGO_APP), ns_meta(FLUX_APP),
           {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "argocd", "labels": LABEL}}])
    kubectl("wait", "--for=condition=Established", "crd/applications.argoproj.io",
            "crd/kustomizations.kustomize.toolkit.fluxcd.io", "--timeout=60s")
    yield
    kubectl("delete", "namespace", ARGO_APP, FLUX_APP, sb.VERIFIER_NS, "--wait=false", check=False)
    kubectl("delete", "-n", "argocd", "role,rolebinding", sb.VERIFIER, check=False)
    kubectl("delete", "crd", "applications.argoproj.io", "kustomizations.kustomize.toolkit.fluxcd.io", check=False)


def verifier_kubeconfig(tmp_path: Path) -> Path:
    """A kubeconfig for the verifier ServiceAccount with a 10 minute token (what the docs tell admins to do)."""
    token = kubectl("-n", sb.VERIFIER_NS, "create", "token", sb.VERIFIER, "--duration=10m").strip()
    cfg = json.loads(kubectl("config", "view", "--raw", "--minify", "-o", "json"))
    cluster = cfg["clusters"][0]
    out = {"apiVersion": "v1", "kind": "Config", "clusters": [cluster],
           "users": [{"name": "verifier", "user": {"token": token}}],
           "contexts": [{"name": "verifier", "context": {"cluster": cluster["name"], "user": "verifier"}}],
           "current-context": "verifier"}
    p = tmp_path / "verifier.kubeconfig"
    p.write_text(yaml.safe_dump(out))
    p.chmod(0o600)
    return p


def test_read_back_on_a_real_cluster(cluster, tmp_path):
    root = tmp_path / "out"
    (root / "sandbox").mkdir(parents=True)
    crash = ["sh", "-c", "echo 'Unhandled exception. System.PlatformNotSupportedException: System.Drawing.Common is "
                         "not supported on this platform.'; echo 'Password=hunter2'; exit 1"]
    shop = {"web": [deployment("web", WEB_IMAGE, port=8080, replicas=2)],
            "crash": [deployment("crash", SHELL_IMAGE, command=crash)],
            "pull": [deployment("pull", "registry.invalid/containerizer/nope:1.0.0")],
            "report": [cronjob("report")]}
    write_app(root, "Acme/_/shop", ARGO_APP, shop)
    flux = {"api": [deployment("api", WEB_IMAGE, port=8080)]}
    write_app(root, "Acme/_/flux", FLUX_APP, flux)
    for ns, comps in ((ARGO_APP, shop), (FLUX_APP, flux)):
        for docs in comps.values():
            kubectl("apply", "-n", ns, "-f", "-", input="---\n".join(yaml.safe_dump(x) for x in docs))
    # what Argo CD and Flux would report once they synced our commit
    apply([{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": {"name": ARGO_APP, "namespace": "argocd"},
            "spec": {}, "status": {"sync": {"status": "Synced", "revision": SHA}, "health": {"status": "Progressing"},
                                   "operationState": {"phase": "Succeeded", "syncResult": {"revision": SHA}}}},
           {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
            "metadata": {"name": FLUX_APP, "namespace": FLUX_APP}, "spec": {},
            "status": {"lastAppliedRevision": f"main@sha1:{SHA}", "lastAttemptedRevision": f"main@sha1:{SHA}",
                       "conditions": [{"type": "Ready", "status": "True", "reason": "ReconciliationSucceeded"}]}}])
    apply(sb.verify_rbac([ARGO_APP, FLUX_APP]))
    cfg = verifier_kubeconfig(tmp_path)

    # least privilege, as the API server sees it
    def can(*args):
        return subprocess.run(["kubectl", f"--kubeconfig={cfg}", "auth", "can-i", *args], capture_output=True,
                              text=True).stdout.strip()
    assert can("get", "pods", "-n", ARGO_APP) == "yes" and can("get", "pods/log", "-n", ARGO_APP) == "yes"
    for denied in (("get", "secrets", "-n", ARGO_APP), ("list", "pods", "-n", "default"), ("delete", "pods", "-n", ARGO_APP),
                   ("patch", "deployments", "-n", ARGO_APP), ("list", "namespaces"), ("get", "configmaps", "-n", ARGO_APP),
                   ("list", "applications.argoproj.io", "-n", "argocd"), ("get", "applications.argoproj.io/other", "-n", "argocd"),
                   ("create", "pods/exec", "-n", ARGO_APP)):
        assert can(*denied) == "no", denied
    assert can("get", f"applications.argoproj.io/{ARGO_APP}", "-n", "argocd") == "yes"

    o = sb.SandboxOptions(kube=sb.KubeOptions(kubeconfig=str(cfg)), timeout=300, settle=15, interval=5,
                          revision=SHA, learn=False)
    doc = sb.verify_sandbox(root, o, log=print)
    by = {r["component"]: r for r in doc["components"]}
    print(json.dumps({k: {x: v.get(x) for x in ("status", "reason", "ready", "restarts")} for k, v in by.items()}, indent=1))
    assert doc["cluster"].startswith("Kubernetes v")
    assert by["Shop.Web"]["status"] == "healthy" and by["Shop.Web"]["ready"] == "2/2" and by["Shop.Web"]["gitops"] == "argocd"
    assert by["Shop.Api"]["status"] == "healthy" and by["Shop.Api"]["gitops"] == "flux"
    assert by["Shop.Report"]["status"] == "scheduled"
    c = by["Shop.Crash"]
    assert c["status"] == "failing" and c["restarts"] >= 1 and c["diagnosis"]["rule"] == "run-platform-not-supported"
    assert "PlatformNotSupportedException" in c["log_tail"] and "hunter2" not in c["log_tail"]
    p = by["Shop.Pull"]
    assert p["status"] == "failing" and p["diagnosis"]["rule"] == "cluster-image-pull", p
    assert p["diagnosis"]["outcome"] == "environment"
    ids = sb.learn_from_cluster(doc["components"], tmp_path / "learned")
    assert len(ids) == 1 and "cluster-shop-crash" in ids[0]
    sb.write_health(root, doc)
    assert "hunter2" not in (root / "sandbox" / "health.json").read_text()
