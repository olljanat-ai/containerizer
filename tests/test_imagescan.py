

def test_the_hardened_run_gives_a_cluster_made_key_ring_its_folder(monkeypatch):
    """trade-rebates: the Data Protection key ring is a Secret the cluster makes (an ExternalSecret template).
    Mounted empty and read-only, the app wrote a key, was denied and the gate dropped it as a hardening failure;
    now that folder is writable in the run. Other Secrets stay empty and read-only."""
    import yaml as _yaml
    from containerizer import imagescan as isc
    docs = list(_yaml.safe_load_all("""
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      securityContext: {runAsUser: 1654, runAsGroup: 1654, fsGroup: 1654}
      containers:
      - name: api
        image: x
        securityContext: {readOnlyRootFilesystem: true}
        volumeMounts:
        - {name: w0-dataprotection-keys, mountPath: /home/app/.aspnet/DataProtection-Keys}
        - {name: app-secrets, mountPath: /run/secrets/app}
      volumes:
      - name: w0-dataprotection-keys
        secret: {secretName: api-dataprotection}
      - name: app-secrets
        secret: {secretName: api-secrets, optional: true}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: api-dataprotection}
spec:
  target:
    name: api-dataprotection
    template:
      data: {key-1.xml: "<key>{{ .password | b64enc }}</key>"}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: api-secrets}
spec:
  target: {name: api-secrets}
"""))
    assert isc.cluster_filled_secrets(docs) == {"api-dataprotection"}
    cmds = []

    def run(cmd, timeout):
        cmds.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            return 0, "id", ""
        if cmd[:2] == ["docker", "inspect"]:
            return 0, "true", ""
        return 0, "", ""
    monkeypatch.setattr(isc, "_run", run)
    clock = iter(range(0, 10 ** 6, 5))
    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr("time.time", lambda: next(clock))
    isc.run_as_manifest("img:gate", docs, wait=21)
    cmd = cmds[0]
    mounts = [cmd[i + 1] for i, x in enumerate(cmd) if x == "--tmpfs"]
    assert "/home/app/.aspnet/DataProtection-Keys:rw,exec,uid=1654,gid=1654,mode=1777" in mounts
    assert "/run/secrets/app:ro,mode=0550" in mounts


def test_a_vulnerability_stop_names_the_packages_to_upgrade():
    """The lab's retail-backoffice: wave-1 components were "not deployed: security gate: 2 fixable vulnerabilities at
    or above the gate threshold (image)"; the packages were the application's own, so the reason names them."""
    from containerizer.org import gate_failure

    def v(pkg, inst, fixed, origin="app"):
        return {"id": "CVE-x", "package": pkg, "installed": inst, "fixed": fixed, "origin": origin, "severity": "CRITICAL"}
    comp = {"scans": [{"kind": "image", "passed": False, "blocking": [
        v("Refit", "6.3.2", "7.2.22"), v("System.Drawing.Common", "5.0.0", "4.7.2, 5.0.3"), v("Refit", "6.3.2", "7.2.22")]}]}
    assert gate_failure(comp) == "" and gate_failure(comp, vulnerabilities=True) == ("3 fixable vulnerabilities at or above the gate threshold in the application's packages: "
                                  "Refit 6.3.2 (fixed in 7.2.22), System.Drawing.Common 5.0.0 (fixed in 4.7.2, 5.0.3)")
    comp["scans"][0]["blocking"] = [v("openssl", "3.0.2", "3.0.15", "base")]
    assert gate_failure(comp, vulnerabilities=True).endswith("in the base image: openssl 3.0.2 (fixed in 3.0.15)")
    comp["scans"][0]["blocking"] = [v(f"Pkg.Number{i}", "1.0.0", "2.0.0", "base" if i % 2 else "app") for i in range(20)]
    r = gate_failure(comp, vulnerabilities=True)
    assert r.startswith("20 fixable vulnerabilities at or above the gate threshold (image): Pkg.Number0 1.0.0")
    assert len(r) <= 320 and r.endswith("more")


def test_vulnerabilities_do_not_keep_a_component_out_by_default(monkeypatch):
    """Getting the application running in containers is the aim; its developers fix vulnerable packages there.
    scan.block_deploy: true keeps such components out; a build failure always does."""
    from containerizer import org
    comp = {"scans": [{"kind": "image", "passed": False, "blocking": [
        {"package": "Refit", "installed": "6.3.2", "fixed": "7.2.22", "origin": "app"}]}]}
    assert org.vulnerabilities_block() is False and org.gate_failure(comp) == ""
    monkeypatch.setattr("containerizer.harden.security", lambda: {"scan": {"block_deploy": True}})
    assert org.vulnerabilities_block() is True and org.gate_failure(comp).startswith("1 fixable vulnerabilities")
    monkeypatch.setattr("containerizer.harden.security", lambda: {"scan": {}})
    assert org.gate_failure({**comp, "build_error": "x"}) == "image build failed"


def test_verification_containers_get_unique_names(monkeypatch, tmp_path):
    """Jobs of one LLM queue runner verify at once: two runs in the same second got the same container name
    ("Conflict. The container name /cz-verify-833680-1793882057 is already in use", Make it A of control-tower)."""
    from types import SimpleNamespace
    from containerizer import imagescan as isc, verify as vf
    names = []

    def run(cmd, timeout=0):
        if cmd[:2] == ["docker", "run"]:
            names.append(cmd[cmd.index("--name") + 1])
            return (1, "boom") if len(cmd) else (0, "")
        return 0, ""
    monkeypatch.setattr(vf, "_run", run)
    monkeypatch.setattr("time.time", lambda: 1793882057)
    c = SimpleNamespace(role="web", facts={}, project=SimpleNamespace(dir=tmp_path))
    for _ in range(2):
        vf.run(c, {"uid": 1654, "add_writable": [], "port": None}, "img", tmp_path)
    monkeypatch.setattr(isc, "_run", lambda cmd, timeout=0: (names.append(cmd[cmd.index("--name") + 1]) or (1, "", "x"))
                        if cmd[:2] == ["docker", "run"] else (0, "", ""))
    docs = [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [{"name": "a", "image": "x"}]}}}}]
    for _ in range(2):
        isc.run_as_manifest("img", docs)
    assert len(names) == 4 and len(set(names)) == 4 and all("-1793882057-" in n for n in names)


def test_scans_are_off_by_default_but_the_build_and_the_hardened_run_stay(tmp_path, monkeypatch):
    """Vulnerability scans took long and are outside Containerizer's aim: off unless scan.enabled (or block_deploy).
    The gate still lints, builds and runs each image with the hardened security context."""
    from containerizer import imagescan as isc
    from test_engine import web_app
    from containerizer.assess import assess
    assert isc.scans_enabled() is False
    monkeypatch.setattr(isc, "scan_image", lambda *a, **k: (_ for _ in ()).throw(AssertionError("scanned")))
    monkeypatch.setattr(isc, "update_images", lambda *a, **k: (_ for _ in ()).throw(AssertionError("refreshed")))
    built, ran = [], []
    monkeypatch.setattr(isc, "_build_with_retries", lambda a, cdir, tag, comp, pin, post: built.append(tag) or (True, ""))
    monkeypatch.setattr(isc, "run_as_manifest", lambda tag, docs: ran.append(tag) or {"status": "ok"})
    web_app(tmp_path / "app")
    a = assess(tmp_path / "app")
    r = isc.gate_app(a, tmp_path / "out", build=True, scan=False, run=True)
    assert built and ran == built and r["passed"] and r["scanned"] is False
    assert all(c["scans"] == [] for c in r["components"])
    md = (tmp_path / "out" / "SECURITY.md").read_text()
    assert "Vulnerability scans are off (`scan.enabled`" in md and "fixable CRITICAL" not in md
    monkeypatch.setattr("containerizer.imagescan.security", lambda: {"scan": {"enabled": True}})
    assert isc.scans_enabled() is True
    monkeypatch.setattr("containerizer.imagescan.security", lambda: {"scan": {"block_deploy": True}})
    assert isc.scans_enabled() is True
