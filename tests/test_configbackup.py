"""The appliance's configuration, without secrets, in the output repositories (configbackup.py)."""
import json

from containerizer import configbackup as cb


def _config(tmp_path):
    c = tmp_path / "etc"
    (c / "secrets").mkdir(parents=True)
    (c / "network").mkdir()
    (c / "tls").mkdir()
    (c / "appliance.env").write_text("# the appliance\nCZ_HOSTNAME=CZ.Example.com\nCZ_MSSQL_MEMORY=4g\n"
                                     "CZ_SQL_OPTIONS=Encrypt=yes;Password=hunter22;\n")
    (c / "sandbox.env").write_text("CZ_SANDBOX_GIT_URL=https://john:ghp_abc123@github.com/acme/out.git\n"
                                   "CZ_SANDBOX_GIT_USERNAME=git\nCZ_SANDBOX_GIT_TOKEN=ghp_secret\n")
    (c / "web.env").write_text("CONTAINERIZER_OIDC_CLIENT_ID=abc\nCONTAINERIZER_OIDC_CLIENT_SECRET=\"s3cr3t\"\n"
                               "CONTAINERIZER_ADMINS=group:1\n")
    (c / "worker.env").write_text("REGISTRY_USERNAME=bot\nREGISTRY_PASSWORD=\nCONTAINERIZER_WORKER_HOSTS=\n")
    (c / "grafana.env").write_text("GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=x\nGF_SERVER_ROOT_URL=https://cz/grafana/\n")
    (c / "egress.json").write_text(json.dumps({"mode": "enforce", "rules": [{"host": "github.com", "ports": ["tcp/443"]}]}))
    (c / "network" / "10-lan.network").write_text("[Match]\nName=eth0\n[Network]\nAddress=10.0.0.5/24\n")
    (c / "network" / "20-wg.network").write_text("[WireGuard]\nPrivateKey=AAAAsecret=\n")
    (c / "secrets" / "mssql-sa").write_text("Topsecret1!")
    (c / "tls" / "key.pem").write_text("-----BEGIN PRIVATE KEY-----")
    return c


def test_collect_copies_the_settings_and_never_a_secret(tmp_path):
    c = _config(tmp_path)
    stage = tmp_path / "run" / "config-backup"
    files = cb.collect(c, stage)
    assert sorted(files) == ["README.md", "appliance.env", "egress.json", "grafana.env", "network/10-lan.network",
                             "network/20-wg.network", "sandbox.env", "web.env", "worker.env"]
    name, staged = cb.staged(stage)
    assert name == "cz.example.com"
    text = "\n".join(staged.values())
    for secret in ("hunter22", "ghp_abc123", "ghp_secret", "s3cr3t", "AAAAsecret", "Topsecret1!", "PRIVATE KEY"):
        assert secret not in text, secret
    assert "CZ_MSSQL_MEMORY=4g" in staged["appliance.env"] and "# the appliance" in staged["appliance.env"]
    assert "Password=<redacted>" in staged["appliance.env"]
    assert "CZ_SANDBOX_GIT_URL=https://<redacted>@github.com/acme/out.git" in staged["sandbox.env"]
    assert f"CZ_SANDBOX_GIT_TOKEN={cb.SET}" in staged["sandbox.env"] and "CZ_SANDBOX_GIT_USERNAME=git" in staged["sandbox.env"]
    assert "REGISTRY_PASSWORD=\n" in staged["worker.env"]                      # empty: says it is not set
    assert "GF_SERVER_ROOT_URL=https://cz/grafana/" in staged["grafana.env"]
    assert "Address=10.0.0.5/24" in staged["network/10-lan.network"]
    assert json.loads(staged["egress.json"])["rules"][0]["host"] == "github.com"
    assert not any(p.startswith(("secrets", "tls")) for p in staged)
    assert all(oct(p.stat().st_mode)[-3:] == "644" for p in stage.rglob("*") if p.is_file())


def test_sync_commits_once_per_change_to_every_output_repository(tmp_path, monkeypatch):
    from containerizer import credentials, org, variant
    from containerizer import worker as wk
    stage = tmp_path / "stage"
    cb.collect(_config(tmp_path), stage)
    commits, roots = [], []

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
        def __init__(self, o, d):
            self.root, self.url = d, o.output_repo
            d.mkdir(parents=True, exist_ok=True)
            roots.append(d)

        def commit(self, msg):
            commits.append((msg, sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())))
            return True
    monkeypatch.setattr(org, "Output", Out)
    monkeypatch.setattr(credentials, "load", lambda conn, key=None: Creds())
    monkeypatch.setattr(wk, "allowed_hosts", lambda: set())
    scan = {"ScanId": 1, "Provider": "github", "Organization": "acme", "OutputRepo": "https://git.example.com/out",
            "OutputBranch": "main", "Gate": False, "PushImages": True, "ImagePullSecret": None, "Registry": "x"}
    monkeypatch.setattr(variant, "_rows", lambda conn, sql, params=(): [scan, {**scan, "ScanId": 2}])
    work = tmp_path / "w"
    assert cb.sync(Conn, "key", work, stage, log=lambda s: None) == 1             # once per repository
    msg, files = commits[0]
    assert "cz.example.com" in msg and ".appliance/cz.example.com/config/sandbox.env" in files
    assert ".appliance/cz.example.com/config/README.md" in files
    assert cb.sync(Conn, "key", work, stage, log=lambda s: None) == 0             # nothing changed since
    (stage / "worker.env").write_text("CONTAINERIZER_WORKER_HOSTS=registry.example.com\n")
    assert cb.sync(Conn, "key", work, stage, log=lambda s: None) == 1             # changed (the next boot)
    assert cb.sync(Conn, "key", work, tmp_path / "none", log=lambda s: None) == 0  # nothing staged: not an appliance


def test_firstboot_stages_and_the_queue_runner_commits():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    fb = (root / "appliance/rootfs/usr/lib/containerizer/bin/cz-firstboot").read_text()
    assert "-m containerizer.configbackup collect" in fb
    assert "configbackup.sync(" in (root / "containerizer/llmqueue.py").read_text()
