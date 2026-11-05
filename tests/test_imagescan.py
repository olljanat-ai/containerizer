

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
