"""The shared Helm chart (helmchart.py, containerizer/chart/containerizer-app, docs/helm-chart.md): the chart renders
exactly the objects the generator made (Python and `helm template` agree), a component stays plain manifests when the
chart cannot carry it faithfully or saves little, the mode of an application (the administrators' choice, the mode
it is deployed with, the system default), the HelmRelease and its image setters, reading and writing a component
in either form, the chart versions in the output repository, and an organization scan's deploy in both modes."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from containerizer import __version__, helmchart as h, org as orgmod
from containerizer.assess import assess
from containerizer.generate import generate_app
from containerizer.gitops import GitOpsOptions

ROOT = Path(__file__).resolve().parent.parent
NS = "shop"
HARDENED = {"securityContext": {"runAsNonRoot": True, "privileged": False, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "seccompProfile": {"type": "RuntimeDefault"},
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"limits": {"memory": "64Mi"}}}


def _generated(tmp_path, domain="apps.example.com"):
    """The ci-demo app generated as manifests: {component folder: its objects}."""
    out = tmp_path / "gen"
    generate_app(assess(ROOT / "examples" / "ci-demo"), out, gitops=GitOpsOptions(ingress_domain=domain))
    ns = yaml.safe_load((out / "kustomization.yaml").read_text())["namespace"]
    comps = {f.parent.name: [d for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]
             for f in sorted(out.glob("*/k8s.yaml")) if f.parent.name not in ("lab", "devdb")}
    return out, ns, comps


def _image(docs):
    return h._image_values(docs, {})


def _values(docs, comp, ns):
    img = _image(docs)
    return h.to_values(h._as_kustomize_builds(docs, img, None), comp, ns, img)


# --------------------------------------------------------------------------- the round trip

def test_the_chart_renders_every_generated_component_exactly(tmp_path):
    _out, ns, comps = _generated(tmp_path)
    assert comps
    for comp, docs in comps.items():
        values, why = _values(docs, comp, ns)
        assert values is not None, (comp, why)
        assert h.render(values) == h._as_kustomize_builds(docs, _image(docs), None)
        kinds = [o["kind"] for o in values["objects"]]
        assert kinds == [d["kind"] for d in docs]
        # the baseline is in the chart, not in the values
        text = yaml.safe_dump(values)
        assert "seccompProfile" not in text and "allowPrivilegeEscalation" not in text
        assert "kube-dns" not in text


def test_merge_unset_and_fragments():
    dst = {"a": {"b": 1, "c": 2}, "d": [1], "e": 3}
    assert h.merge(dst, {"a": {"b": h.UNSET, "x": 9}, "d": [2], "e": h.UNSET}) == {"a": {"c": 2, "x": 9}, "d": [2]}
    x = {"l": ["@one", "@nope", {"m": "@one"}], "v": "@one"}
    h._resolve(x, {"one": {"k": 1}})
    assert x == {"l": [{"k": 1}, "@nope", {"m": {"k": 1}}], "v": {"k": 1}}


def test_a_component_the_chart_cannot_carry_faithfully_stays_manifests(tmp_path):
    _out, ns, comps = _generated(tmp_path)
    comp, docs = next(iter(comps.items()))
    big = json.loads(json.dumps(docs))
    next(d for d in big if d["kind"] == "Deployment")["spec"]["progressDeadlineSeconds"] = 10 ** 7
    values, why = _values(big, comp, ns)
    assert values is None and "1e+07" in why                   # Helm keeps numbers as floats
    marker = json.loads(json.dumps(docs))
    next(d for d in marker if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["args"] = ["@dns"]
    assert _values(marker, comp, ns)[0] is None                # the chart's own fragment marker


def test_sidecars_init_containers_and_unknown_kinds_are_carried_as_they_are(tmp_path):
    _out, ns, comps = _generated(tmp_path)
    comp, docs = next(iter(comps.items()))
    docs = json.loads(json.dumps(docs))
    pod = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]
    pod["containers"].append({"name": "proxy", "image": "envoyproxy/envoy:v1.31", **HARDENED})
    pod["initContainers"] = [{"name": "migrate", "image": "flyway/flyway:10", **HARDENED}]
    docs.append({"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor",
                 "metadata": {"name": comp, "labels": {"app.kubernetes.io/name": comp}}, "spec": {"endpoints": []}})
    values, why = _values(docs, comp, ns)
    assert values is not None, why
    assert h.render(values) == h._as_kustomize_builds(docs, _image(docs), None)
    sm = values["objects"][-1]
    assert sm["apiVersion"] == "monitoring.coreos.com/v1" and sm["kind"] == "ServiceMonitor"


# --------------------------------------------------------------------------- the hardening is not a value

def _deployment(docs):
    return next(d for d in docs if d["kind"] == "Deployment")


def test_values_cannot_loosen_the_hardening(tmp_path):
    _out, ns, comps = _generated(tmp_path)
    comp, docs = next(iter(comps.items()))
    values, _ = _values(docs, comp, ns)
    dep = next(o for o in values["objects"] if o["kind"] == "Deployment")
    pod = dep.setdefault("spec", {}).setdefault("template", {}).setdefault("spec", {})
    pod.update({"hostUsers": True, "automountServiceAccountToken": True,
                "securityContext": {"runAsNonRoot": False, "seccompProfile": h.UNSET}})
    c0 = pod["containers"][0]
    c0["securityContext"] = {"privileged": True, "allowPrivilegeEscalation": True, "readOnlyRootFilesystem": False,
                             "runAsNonRoot": h.UNSET, "capabilities": {"drop": []}}
    sa = next(o for o in values["objects"] if o["kind"] == "ServiceAccount")
    sa["automountServiceAccountToken"] = True
    got = h.render(values)
    p = h._at(_deployment(got), h.WORKLOADS["Deployment"])["spec"]
    assert p["hostUsers"] is False and p["automountServiceAccountToken"] is False
    assert p["securityContext"]["runAsNonRoot"] is True and p["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    sc = p["containers"][0]["securityContext"]
    assert sc["privileged"] is False and sc["allowPrivilegeEscalation"] is False and sc["readOnlyRootFilesystem"] is True
    assert sc["runAsNonRoot"] is True and sc["capabilities"]["drop"] == ["ALL"]
    assert next(d for d in got if d["kind"] == "ServiceAccount")["automountServiceAccountToken"] is False


@pytest.mark.parametrize("change, why", [
    (lambda p: p.update(hostNetwork=True), "hostNetwork"),
    (lambda p: p["volumes"].append({"name": "h", "hostPath": {"path": "/"}}), "hostPath"),
    (lambda p: p["containers"][0]["securityContext"]["capabilities"].update(add=["NET_ADMIN"]), "NET_ADMIN"),
    (lambda p: p["containers"][0].update(ports=[{"containerPort": 80, "hostPort": 80}]), "hostPort"),
    (lambda p: p["securityContext"].update(sysctls=[{"name": "kernel.msgmax", "value": "1"}]), "kernel.msgmax"),
    (lambda p: p["containers"][0]["resources"]["limits"].pop("memory"), "memory limit"),
])
def test_the_chart_refuses_what_its_hardening_forbids(tmp_path, change, why):
    _out, ns, comps = _generated(tmp_path)
    comp, docs = next(iter(comps.items()))
    docs = json.loads(json.dumps(docs))
    change(h._at(_deployment(docs), h.WORKLOADS["Deployment"])["spec"])
    values, reason = _values(docs, comp, ns)
    assert values is None and why in reason and "hardening forbids" in reason


def test_a_component_with_a_hardening_exception_stays_manifests(tmp_path):
    _out, ns, comps = _generated(tmp_path)
    comp, docs = next(iter(comps.items()))
    docs = json.loads(json.dumps(docs))
    h._at(_deployment(docs), h.WORKLOADS["Deployment"])["spec"]["automountServiceAccountToken"] = True  # an API client
    values, reason = _values(docs, comp, ns)
    assert values is None and "hardening exception" in reason


# --------------------------------------------------------------------------- helm template agrees

@pytest.mark.skipif(not shutil.which("helm"), reason="helm is not installed (the CI runners have it)")
def test_helm_template_renders_what_python_renders(tmp_path):
    _out, ns, comps = _generated(tmp_path)
    comp0, docs0 = next(iter(comps.items()))
    extra = json.loads(json.dumps(docs0))                       # sidecar, unset keys, an unknown kind
    pod = next(d for d in extra if d["kind"] == "Deployment")["spec"]["template"]["spec"]
    pod["containers"].append({"name": "proxy", "image": "envoyproxy/envoy:v1.31", **HARDENED})
    pod.pop("enableServiceLinks", None)
    extra.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{comp0}-x"}, "data": {"a": "1"}})
    cases = list(comps.items()) + [(comp0, extra)]
    chart = tmp_path / "chart"
    shutil.copytree(h.PACKAGED, chart)
    for i, (comp, docs) in enumerate(cases):
        img = _image(docs)
        img["digest"] = "sha256:" + "a" * 64
        built = h._as_kustomize_builds(docs, img, "regcred")
        values, why = h.to_values(built, comp, ns, img)
        assert values is not None, why
        vf = tmp_path / f"values-{i}.yaml"
        vf.write_text(yaml.safe_dump(values))
        for skip in ([], ["HTTPRoute"]):
            args = ["helm", "template", comp, str(chart), "--namespace", ns, "-f", str(vf)]
            if skip:
                args += ["--set-json", f"skipKinds={json.dumps(skip)}"]
            p = subprocess.run(args, capture_output=True, text=True)
            assert p.returncode == 0, p.stderr
            def key(d):                                     # helm prints the objects in its install order
                return d["kind"], d["metadata"]["name"]
            got = sorted((d for d in yaml.safe_load_all(p.stdout) if d), key=key)
            assert got == sorted(h.render({**values, "skipKinds": skip}), key=key), (comp, skip)
            assert len(got) == len(built) - (sum(d["kind"] == "HTTPRoute" for d in built) if skip else 0)
    # values cannot loosen the hardening in helm either, and what it forbids fails the render
    values, _ = h.to_values(h._as_kustomize_builds(docs0, _image(docs0), None), comp0, ns, _image(docs0))
    dep = next(o for o in values["objects"] if o["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    pod["hostUsers"] = True
    pod["containers"][0]["securityContext"] = {"privileged": True, "readOnlyRootFilesystem": False}
    vf = tmp_path / "loose.yaml"
    vf.write_text(yaml.safe_dump(values))
    p = subprocess.run(["helm", "template", comp0, str(chart), "--namespace", ns, "-f", str(vf)],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    got = [d for d in yaml.safe_load_all(p.stdout) if d]
    def canon(d):
        return json.dumps(d, sort_keys=True)
    assert sorted(map(canon, got)) == sorted(map(canon, h.render(values)))
    gp = _deployment(got)["spec"]["template"]["spec"]
    assert gp["hostUsers"] is False and gp["containers"][0]["securityContext"]["privileged"] is False
    pod["volumes"].append({"name": "h", "hostPath": {"path": "/"}})
    vf.write_text(yaml.safe_dump(values))
    p = subprocess.run(["helm", "template", comp0, str(chart), "--namespace", ns, "-f", str(vf)],
                       capture_output=True, text=True)
    assert p.returncode != 0 and "hostPath volume h is not allowed by the shared chart" in p.stderr


# --------------------------------------------------------------------------- settings and the mode of an application

def test_settings_default_env_and_invalid(monkeypatch):
    monkeypatch.delenv(h.MODE_ENV, raising=False)
    s = h.settings()
    assert s["mode"] == "chart" and s["switch_existing"] is False and s["min_saving"] == 0.3
    monkeypatch.setenv(h.MODE_ENV, "Manifests")
    assert h.settings()["mode"] == "manifests"
    monkeypatch.setenv(h.MODE_ENV, "kustomize")
    with pytest.raises(ValueError, match="deploy mode"):
        h.settings()


def test_app_mode_override_then_deployed_mode_then_default():
    cfg = {"mode": "chart", "switch_existing": False, "min_saving": 0.3}
    assert h.app_mode(None, None, cfg)[0] == "chart"
    assert h.app_mode(None, "manifests", cfg) == ("manifests", h.app_mode(None, "manifests", cfg)[1])
    assert "deployed with" in h.app_mode(None, "manifests", cfg)[1]
    assert h.app_mode("manifests", "chart", cfg)[0] == "manifests"
    assert h.app_mode("bogus", "chart", cfg)[0] == "chart"
    assert h.app_mode(None, "manifests", {**cfg, "switch_existing": True})[0] == "chart"


def test_folder_mode(tmp_path):
    d = tmp_path / "app"
    assert h.folder_mode(d) is None
    d.mkdir()
    (d / "containerizer.json").write_text(json.dumps({"status": "deployed", "components": [{"folder": "web"}]}))
    assert h.folder_mode(d) == "manifests"                     # made before 0.33.0
    (d / "web").mkdir()
    (d / "web" / "helmrelease.yaml").write_text("kind: HelmRelease\n")
    assert h.folder_mode(d) == "chart"
    (d / "containerizer.json").write_text(json.dumps({"status": "deployed", "deploy_mode": "manifests"}))
    assert h.folder_mode(d) == "manifests"
    (d / "containerizer.json").write_text(json.dumps({"status": "no-a-components"}))
    assert h.folder_mode(d) is None


# --------------------------------------------------------------------------- an application folder

def test_convert_app_writes_helmreleases_and_moves_the_image_setters(tmp_path):
    out, ns, comps = _generated(tmp_path)
    before = {c: h.component_docs(out / c) for c in comps}
    repos = {_image(d)["repository"] for d in before.values()}
    digest = "sha256:" + "b" * 64
    first = sorted(repos)[0]
    forms = h.convert_app(out, ns, list(comps), "chart", digests={first: digest}, pull_secret=None)
    assert all(f["mode"] == "chart" for f in forms.values()), forms
    k = (out / "kustomization.yaml").read_text()
    assert "k8s.yaml" not in "".join(ln for ln in k.splitlines() if any(c in ln for c in comps))
    assert all(f"{c}/helmrelease.yaml" in k for c in comps) and "images:" not in k
    for c in comps:
        assert not (out / c / "k8s.yaml").exists()
        text = (out / c / "helmrelease.yaml").read_text()
        assert f'{{"$imagepolicy": "{ns}:{c}:tag"}}' in text and f'{{"$imagepolicy": "{ns}:{c}:digest"}}' in text
        hr = yaml.safe_load(text)
        assert hr["spec"]["chart"]["spec"]["chart"] == f"./charts/containerizer-app/{__version__}"
        assert hr["spec"]["chart"]["spec"]["sourceRef"] == {"kind": "GitRepository", "name": ns}
        assert hr["spec"]["serviceAccountName"] == f"{ns}-reconciler"
        got = h.component_docs(out / c)                         # the packaged chart: not copied into gen/ yet
        img = _image(before[c])
        if img["repository"] == first:
            img["digest"] = digest
            assert f'digest: "{digest}"' in text or f"digest: {digest}" in text
        assert got == h._as_kustomize_builds(before[c], img, None)
    assert "HelmRelease" in (out / "gitops" / "README.md").read_text()


def test_convert_app_keeps_manifests_when_the_chart_saves_little(tmp_path):
    out, ns, comps = _generated(tmp_path)
    forms = h.convert_app(out, ns, list(comps), "chart", min_saving=0.95)
    assert all(f["mode"] == "manifests" and "saves only" in f["reason"] for f in forms.values())
    assert all((out / c / "k8s.yaml").exists() for c in comps)
    assert "images:" in (out / "kustomization.yaml").read_text()
    assert h.convert_app(out, ns, list(comps), "manifests") == {c: {"mode": "manifests"} for c in comps}


def test_write_component_docs_keeps_the_form_and_falls_back_to_manifests(tmp_path):
    out, ns, comps = _generated(tmp_path)
    comp = next(iter(comps))
    h.convert_app(out, ns, [comp], "chart")
    docs = h.component_docs(out / comp)
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")
    pol["spec"]["egress"].append({"to": [{"podSelector": {"matchLabels": {"app": "x"}}}]})
    assert h.write_component_docs(out / comp, docs) == "helmrelease.yaml"
    assert h.component_docs(out / comp) == docs
    assert '"$imagepolicy"' in (out / comp / "helmrelease.yaml").read_text()
    # something the chart cannot carry: k8s.yaml again, with its image setter back in kustomization.yaml
    next(d for d in docs if d["kind"] == "Deployment")["spec"]["progressDeadlineSeconds"] = 10 ** 7
    assert h.write_component_docs(out / comp, docs) == "k8s.yaml"
    assert not (out / comp / "helmrelease.yaml").exists()
    k = (out / "kustomization.yaml").read_text()
    assert f"{comp}/k8s.yaml" in k and f'"{ns}:{comp}:tag"' in k
    assert yaml.safe_load(k)["images"]


# --------------------------------------------------------------------------- the output repository

def test_sync_charts_keeps_the_versions_named_and_removes_the_rest(tmp_path):
    root = tmp_path / "repo"
    app = root / "acme" / "_" / "shop" / "web"
    app.mkdir(parents=True)
    old = root / "charts" / "containerizer-app" / "0.1.0"
    stale = root / "charts" / "containerizer-app" / "0.0.9"
    for d in (old, stale):
        d.mkdir(parents=True)
        (d / "Chart.yaml").write_text("name: containerizer-app\n")
    hr = h.helmrelease_text("web", NS, {"component": "web", "partOf": NS, "image": {}, "objects": []})
    (app / "helmrelease.yaml").write_text(hr)
    assert h.sync_charts(root) == [h.chart_rel()]
    assert (root / h.chart_rel() / "templates" / "objects.yaml").is_file()
    assert not old.exists() and not stale.exists()
    (app / "helmrelease.yaml").write_text(hr.replace(__version__, "0.1.0"))
    old.mkdir(parents=True)
    (old / "Chart.yaml").write_text("name: containerizer-app\n")
    assert h.sync_charts(root) == [f"charts/containerizer-app/0.1.0"]
    assert old.exists() and not (root / h.chart_rel()).exists()  # an older app keeps the chart it was made with
    (app / "helmrelease.yaml").unlink()
    h.sync_charts(root)
    assert not (root / "charts").exists()


def test_copy_charts_to_the_applications_own_repository(tmp_path):
    root = tmp_path / "scan"
    app = root / "acme" / "_" / "shop"
    (app / "web").mkdir(parents=True)
    (app / "web" / "helmrelease.yaml").write_text(
        h.helmrelease_text("web", NS, {"component": "web", "partOf": NS, "image": {}, "objects": []}))
    h.sync_charts(root)
    dst = tmp_path / "own"
    assert h.copy_charts(app, dst) == [h.chart_rel()]
    assert (dst / h.chart_rel() / "values.yaml").read_text() == (root / h.chart_rel() / "values.yaml").read_text()


def test_sandbox_leaves_out_the_httproutes_of_the_charts_components(tmp_path):
    out, ns, comps = _generated(tmp_path, domain="apps.example.com")
    h.convert_app(out, ns, list(comps), "chart")
    assert any(d["kind"] == "HTTPRoute" for d in orgmod._app_docs(out))      # rendered from the HelmReleases
    patch = orgmod.sandbox_wait_patch(out, {"app": ns})
    ops = json.loads(patch["patch"])
    helm = [op for op in ops if op["path"] == "/spec/patches/-" and op["value"]["target"].get("kind") == "HelmRelease"]
    assert helm and json.loads(helm[0]["value"]["patch"]) == [
        {"op": "add", "path": "/spec/values/skipKinds", "value": ["HTTPRoute"]}]
    checks = next(op for op in ops if op["path"] == "/spec/healthChecks")["value"]
    assert any(c["kind"] == "Deployment" for c in checks)


# --------------------------------------------------------------------------- an organization scan's deploy

def test_deploy_app_follows_the_override_and_keeps_the_deployed_mode(tmp_path, monkeypatch):
    from tests.test_make_it_a import _a_app, _Out
    from containerizer import imagescan
    monkeypatch.setattr(imagescan, "build_image", lambda src, cdir, tag, timeout=1800: (True, ""))
    monkeypatch.delenv(h.MODE_ENV, raising=False)
    src, a = _a_app(tmp_path, "shop-web")
    out = _Out(tmp_path / "out")
    rel = "acme/_/shop"

    def deploy(n, **kw):
        o = orgmod.OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", verify=True, gate=False,
                              push_images=False, **kw)
        res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error",
                                app="shop-web", source_key="k1")
        return orgmod.deploy_app(a, src, rel, o, out, None, "1.2.3", GitOpsOptions(path=rel), res,
                                 tmp_path / f"work{n}", "shop-web")
    dest = out.root / rel
    r = deploy(1, deploy_mode="manifests")                    # a run whose default is manifests
    assert r.deploy_mode == "manifests" and (dest / "demo-web" / "k8s.yaml").exists()
    r = deploy(2)                                             # the default (chart) does not switch it
    assert r.deploy_mode == "manifests" and "deployed with" in r.deploy_mode_reason
    assert json.loads((dest / "containerizer.json").read_text())["deploy_mode"] == "manifests"
    r = deploy(3, deploy_modes={"k1": "chart"})               # the administrators' choice does
    assert r.deploy_mode == "chart" and r.deploy_mode_reason == "set for this application"
    assert (dest / "demo-web" / "helmrelease.yaml").exists() and not (dest / "demo-web" / "k8s.yaml").exists()
    assert r.components[0]["deploy_mode"] == "chart"
    r = deploy(4)                                             # and it stays
    assert r.deploy_mode == "chart"
    orgmod.write_sandbox(out.root, out.url, "main")
    assert (out.root / h.chart_rel() / "Chart.yaml").is_file()
    assert orgmod.published_urls(dest, a.components) == []    # no ingress domain: nothing published


def test_load_deploy_modes():
    class Cur:
        def execute(self, sql, *a):
            assert "DeployMode IS NOT NULL" in sql

        def fetchall(self):
            return [("k1", "chart"), ("k2", "manifests"), ("k3", "nope")]

    class Conn:
        def cursor(self):
            return Cur()
    assert orgmod.load_deploy_modes(Conn()) == {"k1": "chart", "k2": "manifests"}

    class Old(Conn):
        def cursor(self):
            raise RuntimeError("Invalid column name 'DeployMode'")

        def rollback(self):
            pass
    assert orgmod.load_deploy_modes(Old()) == {}


# --------------------------------------------------------------------------- user namespaces

def _pods(docs):
    for d in docs:
        if d["kind"] in h.WORKLOADS:
            yield h._at(d, h.WORKLOADS[d["kind"]])["spec"]


def test_generated_pods_get_their_own_user_namespace(tmp_path, monkeypatch):
    from containerizer.harden import USER_NAMESPACES_ENV, lint_manifests
    monkeypatch.delenv(USER_NAMESPACES_ENV, raising=False)
    _out, ns, comps = _generated(tmp_path)
    for comp, docs in comps.items():
        assert all(p["hostUsers"] is False for p in _pods(docs))
        assert not [v for v in lint_manifests(docs) if v.check == "user-namespace"]
        values, _ = _values(docs, comp, ns)
        assert "hostUsers" not in yaml.safe_dump(values)          # the chart's baseline has it
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
