

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
