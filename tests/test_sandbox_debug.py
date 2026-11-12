"""Debug mode of an application in the sandbox (sandboxdebug.py; docs/scheduled-scans.md#debug-mode): the switch,
the start command, the workload patch, and sandbox/ with and without it in both deploy modes."""
import json

import pytest
import yaml

from containerizer import helmchart as h
from containerizer import org as orgmod
from containerizer import sandboxdebug as d
from containerizer.gitops import GitOpsOptions


def test_switches_carry_debug_through_or_none():
    s = d.Switches(set(), {"k1", 7})
    assert s and not len(s) and d.debug_of(s) == {"k1", 7}          # `load_sandbox_off(conn) or None` keeps it
    assert not d.Switches() and d.debug_of(set()) == set() and d.debug_of(None) == set()
    assert "k" in d.Switches({"k"}) and not orgmod.sandbox_excluded({"source_key": "k1"}, s)
    assert d.in_debug({"source_key": "k1"}, s.debug) and d.in_debug({"patched": {"application_id": 7}}, s.debug)
    assert not d.in_debug({"source_key": "other"}, s.debug)


def test_load_sandbox_off_reads_debug_and_survives_an_older_schema():
    class Cur:
        def __init__(self, old):
            self.old = old

        def execute(self, sql, params=()):
            self.sql = sql
            if self.old and "SandboxDebug" in sql:
                raise RuntimeError("Invalid column name 'SandboxDebug'")

        def fetchall(self):
            return [(3, "k3")] if "SandboxDebug" in self.sql else [(1, "k1")]

    class Conn:
        def __init__(self, old=False):
            self.old = old

        def cursor(self):
            return Cur(self.old)

        def rollback(self):
            pass

    got = orgmod.load_sandbox_off(Conn())
    assert set(got) == {1, "k1"} and got.debug == {3, "k3"}
    got = orgmod.load_sandbox_off(Conn(old=True))
    assert set(got) == {1, "k1"} and got.debug == set()


def test_start_command_from_the_dockerfile_and_the_manifest():
    df = ('FROM sdk AS build\nENTRYPOINT ["nope"]\nFROM runtime\nWORKDIR /app\n'
          'ENTRYPOINT ["dotnet", "Shop.Web.dll"]\nCMD ["--urls", "http://+:8080"]\n')
    assert d.image_command(df) == (["dotnet", "Shop.Web.dll"], ["--urls", "http://+:8080"])
    assert d.start_command({}, df) == "dotnet Shop.Web.dll --urls http://+:8080"
    assert d.start_command({"args": ["run", "it's"]}, df) == "dotnet Shop.Web.dll run 'it'\"'\"'s'"   # args replace CMD
    assert d.start_command({"command": ["/app/x"], "args": ["a"]}, df) == "/app/x a"                  # command: all
    assert d.start_command({"args": ["a"]}, None) == ""                # no Dockerfile: the entrypoint is not known
    assert d.image_command("FROM x\nCMD python app.py\n") == ([], ["/bin/sh", "-c", "python app.py"])


def test_workload_patch_sleeps_with_the_tools_and_without_probes():
    doc = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
           "spec": {"replicas": 3, "template": {"spec": {"containers": [{"name": "web", "image": "i", "args": ["x"]}]}}}}
    p = yaml.safe_load(d.workload_patch(doc, "reg/cz-debug-tools:1", "dotnet X.dll"))
    pod = p["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert p["spec"]["replicas"] == 1 and c["name"] == "web" and c["command"] == ["/cz-debug/bin/sleep", "infinity"]
    # the crashing pod goes first: no second pod has to fit in the namespace's quota. Not type Recreate, which a
    # server-side apply cannot set over the defaulted rollingUpdate (spec.strategy.rollingUpdate: Forbidden)
    assert p["spec"]["strategy"] == {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}}
    assert c["args"] is None and c["livenessProbe"] is None and c["readinessProbe"] is None and c["startupProbe"] is None
    assert {"name": "CZ_DEBUG_START", "value": "dotnet X.dll"} in c["env"]
    init = pod["initContainers"][0]
    sc = init["securityContext"]                                   # Pod Security "restricted"
    assert init["image"] == "reg/cz-debug-tools:1" and sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"] == {"drop": ["ALL"]} and sc["runAsNonRoot"] and sc["runAsUser"] == d.UID
    assert pod["volumes"] == [{"name": "cz-debug", "emptyDir": {"sizeLimit": "64Mi"}}]
    assert d.workload_patch({"kind": "CronJob", "spec": {}}, "t") is None


def test_tools_image_context(tmp_path, monkeypatch):
    import shutil
    bb = next((p for n in ("busybox-static", "busybox") if (p := shutil.which(n))), None)
    if not bb:
        pytest.skip("no busybox on this machine")
    from pathlib import Path
    monkeypatch.setattr(d, "binaries", lambda: {"bash": Path(bb), "busybox": Path(bb)})
    import os
    old = os.umask(0o077)                                          # the appliance's services run with it
    try:
        d.build_context(tmp_path / "ctx")
    finally:
        os.umask(old)
    for q in (tmp_path / "ctx" / "cz-debug", tmp_path / "ctx" / "cz-debug" / "bin", tmp_path / "ctx" / "cz-debug" / "busybox"):
        assert q.stat().st_mode & 0o777 == 0o755                   # the application's user gets in
    assert "--chmod=0755" in (tmp_path / "ctx" / "Dockerfile").read_text()
    root = tmp_path / "ctx" / "cz-debug"
    assert (root / "bin" / "sleep").is_symlink() and (root / "bin" / "bash").resolve() == root / "bash"
    assert (root / "shell").read_text().startswith("#!/cz-debug/busybox sh")
    assert "FROM scratch" in (tmp_path / "ctx" / "Dockerfile").read_text()


def test_no_tools_without_the_binaries(monkeypatch):
    monkeypatch.setattr(d, "binaries", lambda: None)
    assert d.tools_ref("reg/sandbox") is None and d.ensure_tools("reg/sandbox", None, log=lambda m: None) is None


@pytest.mark.parametrize("mode", ["manifests", "chart"])
def test_sandbox_patches_the_application_in_debug_mode(tmp_path, monkeypatch, mode):
    from tests.test_make_it_a import _a_app, _Out
    from containerizer import imagescan
    monkeypatch.setattr(imagescan, "build_image", lambda src, cdir, tag, timeout=1800: (True, ""))
    monkeypatch.delenv(h.MODE_ENV, raising=False)
    monkeypatch.setattr(d, "tools_ref", lambda registry: f"{registry}/cz-debug-tools:abc" if registry else None)
    src, a = _a_app(tmp_path, "shop-web")
    out = _Out(tmp_path / "out")
    rel = "acme/_/shop"
    o = orgmod.OrgOptions(provider="github", org="acme", registry="reg.example/sandbox", verify=True, gate=False,
                          push_images=False, deploy_mode=mode)
    res = orgmod.RepoResult(provider="github", org="acme", project="_", repo="shop", status="error", app="shop-web",
                            source_key="k1")
    r = orgmod.deploy_app(a, src, rel, o, out, None, "1.2.3", GitOpsOptions(path=rel), res, tmp_path / "work", "shop-web")
    assert r.deploy_mode == mode
    kfile = out.root / "clusters" / "sandbox" / "flux" / "apps" / "kustomization.yaml"

    def ops():
        k = yaml.safe_load(kfile.read_text())
        return [op for p in k.get("patches") or [] for op in yaml.safe_load(p["patch"])]

    orgmod.write_sandbox(out.root, out.url, "main", d.Switches())
    assert "cz-debug" not in kfile.read_text()
    before = {p: p.read_bytes() for p in (out.root / rel).rglob("*") if p.is_file()}
    orgmod.write_sandbox(out.root, out.url, "main", d.Switches(debug={"k1"}))
    added = [op["value"] for op in ops() if op["path"] == "/spec/patches/-" and "cz-debug" in op["value"]["patch"]]
    assert len(added) == 1
    if mode == "chart":
        assert added[0]["target"]["kind"] == "HelmRelease" and added[0]["target"]["name"]
        post = yaml.safe_load(added[0]["patch"])
        assert post[0]["path"] == "/spec/postRenderers"
        workload = post[0]["value"][0]["kustomize"]["patches"][0]
    else:
        workload = added[0]
    assert workload["target"]["kind"] == "Deployment" and workload["target"]["group"] == "apps"
    patch = yaml.safe_load(workload["patch"])
    pod = patch["spec"]["template"]["spec"]
    assert pod["initContainers"][0]["image"] == "reg.example/sandbox/cz-debug-tools:abc"
    assert pod["containers"][0]["command"] == d.SLEEP
    start = next(e["value"] for e in pod["containers"][0]["env"] if e["name"] == "CZ_DEBUG_START")
    assert "dotnet" in start
    assert "(debug mode)" in (out.root / "clusters" / "sandbox" / "README.md").read_text()
    # the application's own folder (what the other clusters deploy) is untouched
    assert before == {p: p.read_bytes() for p in (out.root / rel).rglob("*") if p.is_file()}
    assert "cz-debug" not in "".join(p.read_text() for p in (out.root / "clusters").rglob("*.yaml") if "sandbox" not in p.parts)
    orgmod.write_sandbox(out.root, out.url, "main", d.Switches(debug={"other"}))
    assert "cz-debug" not in kfile.read_text()


def test_the_runner_pushes_the_tools_and_regenerates_sandbox_when_debug_changes(tmp_path, monkeypatch):
    from containerizer import credentials, variant, worker as wk
    state = {"sw": d.Switches()}
    written, pushed, logs = [], [], []

    class Conn:
        def close(self):
            pass

    class Write:
        token, username = "t", "x-access-token"

    class Creds:
        def write_for(self, repo):
            return Write()

        def hosts(self):
            return {"git.example.com"}

    class Out:
        def __init__(self, o, dd):
            self.root, self.url = dd, o.output_repo

        def commit(self, msg):
            return True
    ok = {"push": False}
    monkeypatch.setattr(orgmod, "load_sandbox_off", lambda conn: state["sw"])
    monkeypatch.setattr(orgmod, "Output", Out)
    monkeypatch.setattr(orgmod, "write_sandbox", lambda root, url, branch, o=None: written.append(d.debug_of(o)))
    monkeypatch.setattr(credentials, "load", lambda conn, key=None: Creds())
    monkeypatch.setattr(wk, "allowed_hosts", lambda: set())
    monkeypatch.setattr(d, "binaries", lambda: {"bash": tmp_path, "busybox": tmp_path})
    monkeypatch.setattr(d, "tools_ref", lambda registry: f"{registry}/cz-debug-tools:abc")
    monkeypatch.setattr(d, "ensure_tools", lambda registry, work, log=print: (
        pushed.append(registry), f"{registry}/cz-debug-tools:abc" if ok["push"] else None)[1])
    scan = {"ScanId": 1, "Provider": "github", "Organization": "acme", "OutputRepo": "https://git.example.com/out",
            "OutputBranch": "main", "Gate": False, "PushImages": True, "ImagePullSecret": None, "Registry": "reg/sandbox"}
    monkeypatch.setattr(variant, "_rows", lambda conn, sql, params=(): [scan, {**scan, "ScanId": 2}])
    work = tmp_path / "w"
    assert variant.sync_sandbox(Conn, "key", work, log=logs.append) == 1 and not pushed      # no debug: no tools image
    state["sw"] = d.Switches(debug={"k1", 4})
    assert variant.sync_sandbox(Conn, "key", work, log=logs.append) == 1
    assert pushed == ["reg/sandbox"] and written[-1] == {"k1", 4}                   # once per registry
    assert variant.sync_sandbox(Conn, "key", work, log=logs.append) == 1 and len(pushed) == 2   # the push failed: again
    ok["push"] = True
    assert variant.sync_sandbox(Conn, "key", work, log=logs.append) == 1 and len(pushed) == 3
    assert variant.sync_sandbox(Conn, "key", work, log=logs.append) == 0 and len(pushed) == 3   # done
    state["sw"] = d.Switches()
    assert variant.sync_sandbox(Conn, "key", work, log=logs.append) == 1 and written[-1] == set()


def test_a_running_scan_writes_the_switches_of_now():
    # a scan read the switches at its start; debug mode turned on meanwhile stays in the sandbox/ it writes
    now = d.Switches((), {"k"})
    o = orgmod.OrgOptions(provider="github", org="acme", registry="r", sandbox_switches=lambda: now)
    assert orgmod.sandbox_switches(o) is now

    def away():
        raise OSError("database away")
    o = orgmod.OrgOptions(provider="github", org="acme", registry="r", sandbox_off={"x"}, sandbox_switches=away)
    assert orgmod.sandbox_switches(o) == {"x"}
    assert orgmod.sandbox_switches(orgmod.OrgOptions(provider="github", org="a", registry="r", sandbox_off={"y"})) == {"y"}
