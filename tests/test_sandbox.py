"""Sandbox verification: GitOps sync state, workload read-back, diagnosis, learning, report, RBAC.

The cluster is faked at the kubectl boundary (Kube.get / logs / version); tests/test_sandbox_kind.py
runs the same code against a real kind cluster when CONTAINERIZER_TEST_KUBE is set (CI)."""
import json
import shutil
import subprocess
from datetime import datetime, timezone

import pytest
import yaml

from containerizer import sandbox as sb
from containerizer.sandbox import (FAILING, HEALTHY, NOT_FOUND, PENDING, SCHEDULED, SKIPPED, Kube, KubeError,
                                   KubeOptions, SandboxOptions, argo_state, flux_state, verify_sandbox)

SHA = "a" * 40
OLD = "b" * 40


# --------------------------------------------------------------------------- fakes

@pytest.fixture(autouse=True)
def kubeconfig(tmp_path, monkeypatch):
    cfg = tmp_path / "kubeconfig"
    cfg.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv("KUBECONFIG", str(cfg))
    return cfg


class FakeKube(Kube):
    """kubectl answers from a dict: (resource, ns, name or selector) -> object, or a KubeError."""

    def __init__(self, objects=None, logs=None, version=True):
        super().__init__(KubeOptions(), kubectl="/bin/false")
        self.objects, self.log_text, self.calls = objects or {}, logs or {}, []
        self._version = version

    def version(self):
        if self._version is True:
            return {"serverVersion": {"gitVersion": "v1.31.0"}}
        raise KubeError("dial tcp 10.0.0.1:6443: i/o timeout", "unreachable")

    def get(self, resource, ns=None, name=None, selector=None):
        key = (resource, ns, name or selector)
        self.calls.append(("get",) + key)
        v = self.objects.get(key)
        if v is None:
            raise KubeError(f'{resource} "{name}" not found', "not-found")
        if isinstance(v, KubeError):
            raise v
        return v() if callable(v) else v

    def logs(self, ns, pod, container, previous=False, tail=80):
        self.calls.append(("logs", ns, pod, container, previous))
        return self.log_text.get(pod, "")


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def argo_app(rev=SHA, status="Synced", health="Healthy", phase="Succeeded", conditions=None, message=""):
    return {"status": {"sync": {"status": status, "revision": rev}, "health": {"status": health},
                       "operationState": {"phase": phase, "message": message, "syncResult": {"revision": rev}},
                       "conditions": conditions or []}}


def flux_ks(applied=SHA, attempted=SHA, ready="True", reason="ReconciliationSucceeded", message=""):
    return {"spec": {}, "status": {"lastAppliedRevision": f"main@sha1:{applied}" if applied else "",
                                   "lastAttemptedRevision": f"main@sha1:{attempted}",
                                   "conditions": [{"type": "Ready", "status": ready, "reason": reason,
                                                   "message": message}]}}


def deployment(name, want=2, ready=2, updated=None, generation=1, observed=1, conditions=None):
    updated = want if updated is None else updated
    return {"metadata": {"name": name, "generation": generation},
            "spec": {"replicas": want, "selector": {"matchLabels": {"app.kubernetes.io/name": name}}},
            "status": {"observedGeneration": observed, "replicas": want, "readyReplicas": ready,
                       "updatedReplicas": updated, "availableReplicas": ready, "conditions": conditions or []}}


def pod(name, ready=True, restarts=0, waiting=None, last=None, unschedulable=None, container="web"):
    cs = {"name": container, "ready": ready, "restartCount": restarts, "state": {"running": {}} if ready else {}}
    if waiting:
        cs["state"] = {"waiting": {"reason": waiting, "message": f"{waiting} details"}}
    if last:
        cs["lastState"] = {"terminated": {"reason": last[0], "exitCode": last[1]}}
    conds = [{"type": "PodScheduled", "status": "False", "message": unschedulable}] if unschedulable else []
    return {"metadata": {"name": name}, "status": {"containerStatuses": [] if unschedulable else [cs],
                                                    "conditions": conds}}


def output_repo(tmp_path, components=(("web", "Deployment"),), app="shop-web", source_key="https://git.example/shop#"):
    """A minimal output repository as `containerizer org` writes it."""
    root = tmp_path / "out"
    d = root / "Contoso" / "_" / "shop"
    (d / "gitops" / "argocd").mkdir(parents=True)
    (d / "gitops" / "argocd" / "kustomization.yaml").write_text("resources: []\n")
    comps = []
    for name, kind in components:
        (d / name).mkdir()
        docs = [{"apiVersion": "apps/v1" if kind == "Deployment" else "batch/v1", "kind": kind,
                 "metadata": {"name": name}}, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}}]
        (d / name / "k8s.yaml").write_text("---\n".join(yaml.safe_dump(x) for x in docs))
        comps.append({"component": f"Shop.{name.title()}", "folder": name, "project": f"src/{name}/{name}.csproj",
                      "project_name": f"Shop.{name.title()}", "image": f"reg/{app}/{name}:1.0.0"})
    (d / "containerizer.json").write_text(json.dumps({"app": app, "components": comps, "source_key": source_key,
                                                      "clone_url": "https://git.example/shop.git"}))
    (root / "sandbox").mkdir()
    return root


def run(root, kube, **kw):
    clock = Clock()
    o = SandboxOptions(timeout=kw.pop("timeout", 300), settle=kw.pop("settle", 30), interval=10, revision=SHA,
                       learn=kw.pop("learn", False), **kw)
    return verify_sandbox(root, o, kube=kube, log=lambda *a: None, sleep=clock.sleep, clock=clock), clock


# --------------------------------------------------------------------------- no cluster

def test_no_kubectl_skips_with_a_clear_message(tmp_path):
    root = output_repo(tmp_path)
    doc = verify_sandbox(root, SandboxOptions(), kube=Kube(KubeOptions(), kubectl=None), log=lambda *a: None)
    assert "kubectl is not installed" in doc["skipped"]
    assert [r["status"] for r in doc["components"]] == [SKIPPED]


def test_no_kubeconfig_skips(tmp_path, monkeypatch):
    monkeypatch.delenv("KUBECONFIG", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    ok, why = sb.cluster_access(Kube(KubeOptions(), kubectl="/bin/true"))
    assert not ok and "no kubeconfig" in why
    ok, why = sb.cluster_access(Kube(KubeOptions(kubeconfig=str(tmp_path / "missing")), kubectl="/bin/true"))
    assert not ok and "no kubeconfig" in why


def test_unreachable_cluster_skips(tmp_path, monkeypatch):
    cfg = tmp_path / "kubeconfig"
    cfg.write_text("apiVersion: v1\n")
    k = FakeKube(version=False)
    k.o = KubeOptions(kubeconfig=str(cfg))
    doc, _ = run(output_repo(tmp_path), k)
    assert "not reachable" in doc["skipped"] and doc["components"][0]["status"] == SKIPPED


def test_real_kubectl_errors_are_classified_and_redacted(tmp_path):
    fake = tmp_path / "kubectl"
    fake.write_text("#!/bin/sh\necho 'Error from server (Forbidden): pods is forbidden: token=abc123secret' >&2\nexit 1\n")
    fake.chmod(0o755)
    with pytest.raises(KubeError) as e:
        Kube(KubeOptions(), kubectl=str(fake)).get("pods", "ns")
    assert e.value.kind == "forbidden" and "abc123secret" not in str(e.value)
    fake.write_text("#!/bin/sh\necho 'Unable to connect to the server: dial tcp: lookup k8s: no such host' >&2\nexit 1\n")
    with pytest.raises(KubeError) as e:
        Kube(KubeOptions(), kubectl=str(fake)).version()
    assert e.value.kind == "unreachable"


def test_kubectl_arguments_carry_no_credentials(tmp_path):
    fake = tmp_path / "kubectl"
    fake.write_text(f"#!/bin/sh\necho \"$@\" > {tmp_path}/args\necho '{{}}'\n")
    fake.chmod(0o755)
    Kube(KubeOptions(kubeconfig="/k/config", context="sandbox"), kubectl=str(fake)).get("pods", "ns", selector="a=b")
    args = (tmp_path / "args").read_text().split()
    assert args[:3] == ["--request-timeout=20s", "--kubeconfig=/k/config", "--context=sandbox"]
    assert args[3:] == ["get", "pods", "-n", "ns", "-l", "a=b", "-o", "json"]


# --------------------------------------------------------------------------- GitOps state

def test_argo_states():
    assert argo_state(argo_app(), SHA, None)[0] == "synced"
    assert argo_state(argo_app(rev=OLD), SHA, None)[0] == "waiting"
    assert argo_state(argo_app(phase="Running"), SHA, None)[0] == "waiting"
    st, why = argo_state(argo_app(status="OutOfSync", phase="Failed", message="one or more objects failed"), SHA, None)
    assert st == "failed" and "objects failed" in why
    # a failed sync of an older commit says nothing about ours
    assert argo_state(argo_app(rev=OLD, phase="Failed"), SHA, None)[0] == "waiting"
    st, why = argo_state(argo_app(conditions=[{"type": "InvalidSpecError", "message": "bad path"}]), SHA, None)
    assert st == "failed" and "bad path" in why
    st, why = argo_state(argo_app(rev=OLD, conditions=[{"type": "ComparisonError", "message": "repo down"}]), SHA, None)
    assert st == "waiting" and "repo down" in why            # transient: keep waiting


def test_flux_states():
    assert flux_state(flux_ks(), SHA, None)[0] == "synced"
    assert flux_state(flux_ks(applied=OLD, attempted=OLD), SHA, None)[0] == "waiting"
    assert flux_state(flux_ks(applied=OLD, ready="Unknown", reason="Progressing"), SHA, None)[0] == "waiting"
    # applied, but the health check failed: the workload inspection says why
    st, _ = flux_state(flux_ks(applied=OLD, ready="False", reason="HealthCheckFailed"), SHA, None)
    assert st == "synced"
    st, why = flux_state(flux_ks(applied=OLD, ready="False", reason="BuildFailed", message="kustomize build failed"),
                         SHA, None)
    assert st == "failed" and "kustomize build failed" in why


def test_newer_commit_containing_ours_counts(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q"], cwd=r, check=True)
    subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "1"], cwd=r, check=True)
    ours = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()
    subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "2"], cwd=r, check=True)
    newer = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()
    assert sb.is_ours(newer, ours, r) and not sb.is_ours(ours, newer, r) and not sb.is_ours(OLD, ours, r)


# --------------------------------------------------------------------------- end to end on a fake cluster

SEL = "app.kubernetes.io/name=web"


def test_healthy_after_settle(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(),
                  ("deployments.apps", "shop-web", "web"): deployment("web"),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1"), pod("web-2")]}})
    doc, clock = run(output_repo(tmp_path), k)
    r = doc["components"][0]
    assert r["status"] == HEALTHY and r["status_text"] == "deployed and healthy" and r["ready"] == "2/2"
    assert r["gitops"] == "argocd" and clock.t >= 30            # watched for the settle window
    assert not any(c[0] == "logs" for c in k.calls)


def test_restart_while_watched_is_not_healthy_yet(tmp_path):
    n = {"i": 0}

    def pods():
        n["i"] += 1
        return {"items": [pod("web-1", restarts=min(n["i"], 2))]}
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=1, ready=1),
                  ("pods", "shop-web", SEL): pods})
    doc, clock = run(output_repo(tmp_path), k, settle=30)
    r = doc["components"][0]
    # restarts grew from 1 to 2, then stayed: healthy only after a full quiet window, restarts noted
    assert r["status"] == HEALTHY and clock.t >= 40 and "2 restart(s)" in r["reason"]


def test_crash_loop_is_failing_with_log_diagnosis_and_learned(tmp_path):
    log = ("Unhandled exception. System.PlatformNotSupportedException: System.Drawing.Common is not supported "
           "on this platform.\n   at System.Drawing.Image.FromFile(String)\nPassword=hunter2;")
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): KubeError("forbidden", "forbidden"),
                  (sb.FLUX_KS, "shop-web", "shop-web"): flux_ks(applied=OLD, ready="False", reason="HealthCheckFailed"),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=1, ready=0),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1", ready=False, restarts=4, waiting="CrashLoopBackOff",
                                                            last=("Error", 134))]},
                  ("events", "shop-web", None): {"items": [
                      {"type": "Warning", "reason": "BackOff", "message": "Back-off restarting failed container",
                       "count": 7, "involvedObject": {"name": "web-1"}, "lastTimestamp": "2026-10-31T08:00:00Z"},
                      {"type": "Warning", "reason": "Other", "message": "unrelated", "involvedObject": {"name": "db-0"}},
                      {"type": "Normal", "reason": "Pulled", "involvedObject": {"name": "web-1"}}]}},
                 logs={"web-1": log})
    learned = tmp_path / "learned"
    doc, clock = run(output_repo(tmp_path), k)
    r = doc["components"][0]
    assert r["status"] == FAILING and r["gitops"] == "flux" and clock.t < 300   # definitive: no need to wait
    assert r["reason"].startswith("CrashLoopBackOff") and "Windows-only" in r["reason"]
    assert r["diagnosis"]["rule"] == "run-platform-not-supported" and r["diagnosis"]["outcome"] == "platform"
    assert [e["reason"] for e in r["events"]] == ["BackOff"]
    assert "hunter2" not in r["log_tail"] and "PlatformNotSupportedException" in r["log_tail"]
    assert ("logs", "shop-web", "web-1", "web", True) in k.calls            # the crashed container's log
    ids = sb.learn_from_cluster(doc["components"], learned)
    rules = yaml.safe_load((learned / "findings.yaml").read_text())["rules"]
    assert ids == [rules[0]["id"]] and rules[0]["when"] == {"name": r"^Shop\.Web$"}
    assert rules[0]["observed_in"] == "sandbox-cluster" and rules[0]["category"] == "runtime-observed"
    assert any("CrashLoopBackOff" in e for e in rules[0]["evidence"]) and "hunter2" not in json.dumps(rules)
    assert sb.learn_from_cluster(doc["components"], learned) == []          # not twice
    # the learned rule loads like any learned finding
    from containerizer.rules import Rule
    assert Rule.from_dict(rules[0]).severity == "refactor"


def test_image_pull_is_environment_and_never_learned(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(health="Degraded"),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=1, ready=0),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1", ready=False, waiting="ImagePullBackOff")]},
                  ("events", "shop-web", None): {"items": [
                      {"type": "Warning", "reason": "Failed", "message": 'Failed to pull image "reg/x": unauthorized',
                       "involvedObject": {"name": "web-1"}}]}})
    doc, _ = run(output_repo(tmp_path), k)
    r = doc["components"][0]
    assert r["status"] == FAILING and r["diagnosis"]["rule"] == "cluster-image-pull"
    assert r["diagnosis"]["outcome"] == "environment" and "pull secret" in r["reason"]
    assert not any(c[0] == "logs" for c in k.calls)              # no log to read for an image never pulled
    assert sb.learn_from_cluster(doc["components"], tmp_path / "learned") == []


def test_missing_database_is_external(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=1, ready=0),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1", ready=False, restarts=5, waiting="CrashLoopBackOff")]}},
                 logs={"web-1": "Microsoft.Data.SqlClient.SqlException (0x80131904): A network-related or "
                                "instance-specific error occurred"})
    doc, _ = run(output_repo(tmp_path), k)
    d = doc["components"][0]["diagnosis"]
    assert d["outcome"] == "external" and d["rule"] == "run-sql-unreachable"


def test_oom_becomes_a_config_finding(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=1, ready=0),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1", ready=False, restarts=3, waiting="CrashLoopBackOff",
                                                            last=("OOMKilled", 137))]}})
    doc, _ = run(output_repo(tmp_path), k)
    r = doc["components"][0]
    assert r["diagnosis"]["rule"] == "cluster-oom" and r["diagnosis"]["finding"]["severity"] == "config"


def test_read_only_filesystem_becomes_a_plan_rule(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=1, ready=0),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1", ready=False, restarts=3, waiting="CrashLoopBackOff")]}},
                 logs={"web-1": "System.UnauthorizedAccessException: Access to the path '/app/cache/x.bin' is denied."})
    doc, _ = run(output_repo(tmp_path), k)
    d = doc["components"][0]["diagnosis"]
    assert d["outcome"] == "retry" and d["fix"] == {"add_writable": ["/app/cache"]}
    ids = sb.learn_from_cluster(doc["components"], tmp_path / "learned")
    rule = yaml.safe_load((tmp_path / "learned" / "plan.yaml").read_text())["rules"][0]
    assert ids == [rule["id"]] and rule["plan"] == {"add_writable": ["/app/cache"]} and rule["phase"] == "plan"


def test_rollout_that_never_finishes_is_pending(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(health="Progressing"),
                  ("deployments.apps", "shop-web", "web"): deployment("web", want=2, ready=1),
                  ("pods", "shop-web", SEL): {"items": [pod("web-1"), pod("web-2", ready=False,
                                                                          unschedulable="0/3 nodes: Insufficient memory")]}})
    doc, clock = run(output_repo(tmp_path), k, timeout=120)
    r = doc["components"][0]
    assert r["status"] == FAILING and r["reason"].startswith("Unschedulable") and clock.t >= 120
    assert r["diagnosis"]["rule"] == "cluster-unschedulable"
    k.objects[("pods", "shop-web", SEL)] = {"items": [pod("web-1")]}
    doc, _ = run(output_repo(tmp_path / "2"), k, timeout=60)
    assert doc["components"][0]["status"] == PENDING and "not ready within 60s" in doc["components"][0]["reason"]
    # pods that never start: the newest warning event says why, and the rule says whose problem it is
    k.objects[("pods", "shop-web", SEL)] = {"items": [pod("web-1", ready=False, waiting="ContainerCreating")]}
    k.objects[("events", "shop-web", None)] = {"items": [
        {"type": "Warning", "reason": "FailedCreatePodSandBox", "message": "Failed to create pod sandbox: runc create failed",
         "involvedObject": {"name": "web-1"}, "lastTimestamp": "2026-10-31T08:00:00Z"}]}
    doc, _ = run(output_repo(tmp_path / "3"), k, timeout=60)
    r = doc["components"][0]
    assert r["status"] == PENDING and "last warning FailedCreatePodSandBox" in r["reason"]
    assert r["diagnosis"]["rule"] == "cluster-pod-sandbox" and r["diagnosis"]["outcome"] == "environment"


def test_sync_never_reaches_our_commit(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(rev=OLD)})
    doc, clock = run(output_repo(tmp_path), k, timeout=60)
    r = doc["components"][0]
    assert r["status"] == PENDING and OLD[:12] in r["reason"] and clock.t >= 60
    assert not any(c[1] == "deployments.apps" for c in k.calls if c[0] == "get")


def test_app_not_found_and_sync_failure(tmp_path):
    doc, _ = run(output_repo(tmp_path), FakeKube({}), timeout=30)
    r = doc["components"][0]
    assert r["status"] == NOT_FOUND and "bootstrap applied?" in r["reason"]
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app(phase="Failed", status="OutOfSync",
                                                                message="namespaces forbidden")})
    doc, _ = run(output_repo(tmp_path / "2"), k)
    assert doc["components"][0]["status"] == FAILING and "namespaces forbidden" in doc["components"][0]["reason"]


def test_forbidden_points_at_the_rbac_file(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): KubeError("forbidden", "forbidden"),
                  (sb.FLUX_KS, "shop-web", "shop-web"): KubeError("forbidden", "forbidden")})
    doc, _ = run(output_repo(tmp_path), k)
    assert doc["components"][0]["status"] == "error" and "verify-rbac.yaml" in doc["components"][0]["reason"]


def test_cronjob_scheduled_and_last_run(tmp_path):
    root = output_repo(tmp_path, components=(("report", "CronJob"),))
    objs = {(sb.ARGO_APP, "argocd", "shop-web"): argo_app(), ("cronjobs.batch", "shop-web", "report"): {},
            ("jobs.batch", "shop-web", None): {"items": []}}
    doc, clock = run(root, FakeKube(objs))
    assert doc["components"][0]["status"] == SCHEDULED and clock.t == 0
    objs[("jobs.batch", "shop-web", None)] = {"items": [
        {"metadata": {"name": "report-1", "ownerReferences": [{"kind": "CronJob", "name": "report"}]},
         "status": {"startTime": "2026-10-31T02:00:00Z", "failed": 1,
                    "conditions": [{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}]}}]}
    objs[("pods", "shop-web", "job-name=report-1")] = {"items": [pod("report-1-x", ready=False, restarts=0,
                                                                     last=("Error", 1), container="report")]}
    doc, _ = run(root, FakeKube(objs))
    assert doc["components"][0]["status"] == FAILING and "BackoffLimitExceeded" in doc["components"][0]["reason"]


def test_missing_workload_is_not_found(tmp_path):
    k = FakeKube({(sb.ARGO_APP, "argocd", "shop-web"): argo_app()})
    doc, _ = run(output_repo(tmp_path), k)
    assert doc["components"][0]["status"] == NOT_FOUND and "Deployment web" in doc["components"][0]["reason"]


# --------------------------------------------------------------------------- report and RBAC

def test_health_report_keeps_logs_out_of_the_repository(tmp_path):
    root = output_repo(tmp_path)
    doc = {"checked_at": "2026-10-31T08:00:00+00:00", "revision": SHA, "cluster": "Kubernetes v1.31.0",
           "components": [{"app": "shop-web", "folder": "Contoso/_/shop", "component": "Shop.Web", "status": FAILING,
                           "status_text": "deployed but failing", "reason": "CrashLoopBackOff | x", "ready": "0/1",
                           "restarts": 4, "log_tail": "secret stuff", "diagnosis": {"rule": "r", "outcome": "code",
                                                                                    "finding": {"title": "t"}}}]}
    sb.write_health(root, doc)
    h = json.loads((root / "sandbox" / "health.json").read_text())
    assert "log_tail" not in h["components"][0] and "finding" not in h["components"][0]["diagnosis"]
    md = (root / "sandbox" / "HEALTH.md").read_text()
    assert "**failing**" in md and "CrashLoopBackOff / x" in md and "secret stuff" not in md
    assert "(../Contoso/_/shop/)" in md


def test_redaction():
    s = sb.redact("Server=db;User Id=sa;Password=Sup3r!;\nAuthorization: Bearer abc.def\n"
                  "amqp://user:pa55@rabbit:5672 api_key: XYZ \"client_secret\":\"s3\" eyJabcdefghijk.eyJabcdefghijk.sigsigsigsig")
    for leak in ("Sup3r!", "abc.def", "pa55", "XYZ", "s3\"", "eyJabcdefghijk.eyJ"):
        assert leak not in s, leak
    assert "Server=db" in s


def test_verify_rbac_is_least_privilege():
    docs = sb.verify_rbac(["shop-web", "billing"])
    roles = [d for d in docs if d["kind"] == "Role"]
    assert not [d for d in docs if d["kind"].startswith("Cluster")]
    verbs = {v for r in roles for rule in r["rules"] for v in rule["verbs"]}
    assert verbs == {"get", "list"}                                        # read only, not even watch
    resources = {res for r in roles for rule in r["rules"] for res in rule["resources"]}
    assert "secrets" not in resources and "configmaps" not in resources
    argo = next(r for r in roles if r["metadata"]["namespace"] == "argocd")
    assert argo["rules"] == [{"apiGroups": ["argoproj.io"], "resources": ["applications"],
                              "resourceNames": ["billing", "shop-web"], "verbs": ["get"]}]
    shop = next(r for r in roles if r["metadata"]["namespace"] == "shop-web")
    flux = [x for x in shop["rules"] if x["apiGroups"] == ["kustomize.toolkit.fluxcd.io"]][0]
    assert flux["resourceNames"] == ["shop-web"]
    binds = [d for d in docs if d["kind"] == "RoleBinding"]
    assert len(binds) == 3 and all(b["subjects"] == [{"kind": "ServiceAccount", "name": sb.VERIFIER,
                                                      "namespace": sb.VERIFIER_NS}] for b in binds)
    sa = next(d for d in docs if d["kind"] == "ServiceAccount")
    assert sa["automountServiceAccountToken"] is False


def test_cluster_rules_do_not_affect_local_verification():
    from containerizer.verify import diagnose, load_failures
    # stage "cluster" rules must never match a local build or run log
    assert diagnose("Back-off pulling image: ImagePullBackOff", "run", load_failures()) is None


# --------------------------------------------------------------------------- org integration

def test_org_run_with_verify_sandbox_and_no_cluster(tmp_path, monkeypatch):
    from containerizer import org as orgmod
    from containerizer.org import OrgOptions, run_org
    from containerizer.orgsource import SourceRepo
    from test_org import DEMO, _commit, _FakeProvider

    src = tmp_path / "src" / "ci-demo"
    shutil.copytree(DEMO, src)
    _commit(src, None)
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/acme/ci-demo.git"], cwd=src, check=True)
    repos = [SourceRepo("github", "acme", "_", "ci-demo", "https://github.com/acme/ci-demo.git", default_branch="main",
                        web_url="https://github.com/acme/ci-demo")]
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: _FakeProvider(repos))
    monkeypatch.setattr(orgmod, "clone", lambda url, dest, branch="", header="", depth=1: shutil.copytree(src, dest))
    monkeypatch.setattr(sb.shutil, "which", lambda name: None)              # no kubectl on this agent
    out = tmp_path / "out"
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
    subprocess.run(["git", "clone", "-q", str(bare), str(out)], check=True, capture_output=True)
    logs = []
    o = OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", output_dir=str(out), verify=False,
                   token="t", gate=False, push_images=False, tag="1.2.3", work_dir=str(tmp_path / "work"),
                   now=datetime(2026, 10, 31, tzinfo=timezone.utc), verify_sandbox=True)
    res = run_org(o, log=lambda *a, **k: logs.append(" ".join(map(str, a))))
    assert res[0].status == "deployed" and res[0].source_key == "https://github.com/acme/ci-demo#"
    meta = json.loads((out / "acme" / "_" / "ci-demo" / "containerizer.json").read_text())
    assert meta["components"][0]["project_name"] and meta["source_key"] == res[0].source_key
    assert any("sandbox verification skipped: kubectl is not installed" in x for x in logs)
    h = json.loads((out / "sandbox" / "health.json").read_text())
    assert "kubectl is not installed" in h["skipped"] and h["components"][0]["status"] == SKIPPED
    assert "Not checked: kubectl is not installed" in (out / "sandbox" / "HEALTH.md").read_text()
    rbac = list(yaml.safe_load_all((out / "sandbox" / "verify-rbac.yaml").read_text()))
    assert any(d["kind"] == "Role" and d["metadata"]["namespace"] == meta["app"] for d in rbac)
    log = subprocess.run(["git", "log", "--format=%s"], cwd=out, capture_output=True, text=True).stdout
    assert log.splitlines()[0].startswith("containerizer: sandbox health skipped=1")
    pushed = subprocess.run(["git", "log", "--format=%s", "main"], cwd=bare, capture_output=True, text=True).stdout
    assert pushed.splitlines()[0] == log.splitlines()[0]


def test_org_without_push_skips_the_check(tmp_path):
    from containerizer.org import OrgOptions, sandbox_step

    class Out:
        git, push, root = True, False, output_repo(tmp_path)
        commits = []

        def commit(self, m):
            self.commits.append(m)
    logs = []
    doc = sandbox_step(OrgOptions(provider="github", org="acme", registry="r", verify_sandbox=True), Out(),
                       log=logs.append)
    assert "not pushed" in doc["skipped"] and "not pushed" in logs[0]


def test_cli_sandbox_verify_needs_an_output_repo(tmp_path, capsys):
    from containerizer.cli import main
    assert main(["sandbox", "verify", "--output-dir", str(tmp_path)]) == 2
    assert "no sandbox/ folder" in capsys.readouterr().err


# --------------------------------------------------------------------------- web UI

def test_application_page_shows_sandbox_health():
    from containerizer import webui
    from test_sqlstore import application_data
    app = application_data()
    cid = app["components"][0]["ComponentId"]
    app["sandbox"] = [{"ComponentId": cid, "ComponentName": "Web", "CheckedAt": datetime(2026, 10, 31, 8),
                       "Status": "failing", "Reason": "CrashLoopBackOff: back-off <script>", "GitOps": "flux",
                       "Namespace": "shop-web", "Workloads": "Deployment/web", "Ready": "0/2", "Restarts": 4,
                       "RuleId": "run-sql-unreachable", "Outcome": "external", "Diagnosis": "db down",
                       "Events": json.dumps([{"reason": "BackOff", "message": "Back-off restarting", "count": 7}])}]
    html = webui.render_application(app)
    assert "<th>Sandbox cluster</th>" in html and "Deployed but failing" in html
    assert "CrashLoopBackOff: back-off &lt;script&gt;" in html and "<script>" not in html
    assert "a missing external service" in html and "BackOff" in html and "(7×)" in html and "Flux" in html
    app["sandbox"][0].update(Status="healthy", Reason="2/2 ready", Restarts=0, Outcome=None, Events=None)
    html = webui.render_application(app)
    assert "Deployed and healthy" in html and "2/2" in html and "Caused by" not in html
    app["sandbox"] = []
    assert "Sandbox cluster" not in webui.render_application(app)       # never deployed: no column at all


# --------------------------------------------------------------------------- SQL Server

ADMIN_SQL = __import__("os").environ.get("CONTAINERIZER_TEST_SQL")


@pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")
def test_sandbox_checks_in_sql(tmp_path):
    import re
    import uuid
    from containerizer import sqlstore, webui
    from containerizer.assess import assess
    from test_engine import web_app

    name = "czsbx_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs)
    conn = sqlstore.connect(cs)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    for login, role in (("cz_s_reader", "reader"), ("cz_s_writer", "writer")):
        sqlstore.create_login(conn, login, "Test-Passw0rd!x", role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    try:
        web_app(tmp_path / "shop")
        a = assess(tmp_path / "shop")
        sqlstore.store_results(as_("cz_s_writer"), [a], [tmp_path / "shop"], password="Test-Passw0rd!x")
        comp = a.components[0]

        def doc(when, status, **kw):
            return {"checked_at": when, "revision": SHA, "components": [
                {"app": "shop", "source_key": "shop", "component": comp.name, "project": comp.project.rel,
                 "status": status, "reason": kw.get("reason", ""), "gitops": "argocd", "ready": kw.get("ready", ""),
                 "restarts": kw.get("restarts", 0), "workloads": ["Deployment/web"], "image": "reg/shop/web:1",
                 "events": kw.get("events", []), "diagnosis": kw.get("diagnosis"), "log_tail": kw.get("log", "")},
                {"app": "shop", "source_key": "unknown-app", "component": "x", "project": "x", "status": "healthy"}]}
        n, missing = sqlstore.store_sandbox(as_("cz_s_writer"), doc("2026-10-30T08:00:00+00:00", "healthy",
                                                                     ready="1/1"), password="Test-Passw0rd!x")
        assert (n, missing) == (1, 1)
        sqlstore.store_sandbox(as_("cz_s_writer"), doc(
            "2026-10-31T08:00:00+00:00", "failing", reason="CrashLoopBackOff", restarts=4, log="Password=***",
            events=[{"reason": "BackOff", "message": "Back-off", "count": 3, "object": "web-1"}],
            diagnosis={"rule": "run-sql-unreachable", "outcome": "external", "diagnosis": "db"}), password="Test-Passw0rd!x")
        rd = sqlstore.connect(as_("cz_s_reader"), password="Test-Passw0rd!x")
        try:
            cur = rd.cursor(as_dict=True)
            cur.execute("SELECT ApplicationId FROM cz.vApplicationLatest")
            app_id = cur.fetchone()["ApplicationId"]
            detail = webui.load_application(rd, app_id)
            assert [(s["Status"], s["Restarts"], s["Outcome"]) for s in detail["sandbox"]] == [("failing", 4, "external")]
            assert json.loads(detail["sandbox"][0]["Events"])[0]["reason"] == "BackOff"
            assert "Deployed but failing" in webui.render_application(detail)
            with pytest.raises(Exception, match="(?i)permission"):
                rd.cursor().execute("SELECT LogTail FROM cz.SandboxCheck")
            with pytest.raises(Exception, match="(?i)permission"):
                rd.cursor().execute("INSERT cz.SandboxCheck (ApplicationId, Status, Namespace) VALUES (1, N'healthy', N'x')")
        finally:
            rd.close()
        wr = sqlstore.connect(as_("cz_s_writer"), password="Test-Passw0rd!x")
        with pytest.raises(Exception, match="(?i)permission"):
            wr.cursor().execute("UPDATE cz.SandboxCheck SET Status = N'healthy'")
        wr.close()
    finally:
        m = sqlstore.connect(re.sub(r"Database=\w+", "Database=master", cs), autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()
