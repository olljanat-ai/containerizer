"""Flux webhook (containerizer/fluxhook.py): the sandbox reconciles right after containerizer pushed."""
from __future__ import annotations

import io
import subprocess
import urllib.error
from pathlib import Path

import pytest

from containerizer import fluxhook
from containerizer import org as orgmod

ROOT = Path(__file__).resolve().parents[1]
CZ_SANDBOX = ROOT / "appliance/rootfs/usr/lib/containerizer/bin/cz-sandbox"
UNITS = ROOT / "appliance/rootfs/usr/lib/systemd/system"


@pytest.fixture(autouse=True)
def _fresh():
    fluxhook._seen.clear()


def test_the_receiver_names_the_root_sync_and_the_generated_sources_of_every_app_namespace():
    es, rcv = fluxhook.receiver_manifests(["shop", "flux-system", "ledger", "shop", ""])
    assert es["kind"] == "ExternalSecret" and es["metadata"] == {
        "name": "containerizer-sandbox-webhook", "namespace": "flux-system", "labels": fluxhook._LABELS}
    assert es["spec"]["dataFrom"] == [{"extract": {"key": "flux-system--cz-webhook"}}]
    assert es["spec"]["secretStoreRef"] == {"kind": "ClusterSecretStore", "name": "app-secrets"}
    assert rcv["apiVersion"] == "notification.toolkit.fluxcd.io/v1" and rcv["kind"] == "Receiver"
    assert rcv["metadata"]["namespace"] == "flux-system" and rcv["metadata"]["name"] == "containerizer-sandbox"
    spec = rcv["spec"]
    assert spec["type"] == "generic" and spec["secretRef"] == {"name": es["spec"]["target"]["name"]}
    root, *apps = spec["resources"]
    assert root == {"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository", "name": "containerizer-sandbox"}
    assert [a["namespace"] for a in apps] == ["ledger", "shop"]          # sorted, once each, not flux-system
    assert all(a["name"] == "*" and a["matchLabels"] == {"app.kubernetes.io/managed-by": "containerizer"}
               and a["kind"] == "GitRepository" for a in apps)
    assert len(fluxhook.receiver_manifests()[1]["spec"]["resources"]) == 1


class _Resp:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _conf(tmp_path, text="http://10.43.0.9/hook/abc123\n"):
    f = tmp_path / "flux-webhook"
    f.write_text(text)
    return {fluxhook.ENV: str(f)}


def test_notify_posts_to_the_url_from_the_file_with_a_short_timeout(tmp_path):
    seen = []

    def opener(req, timeout):
        seen.append((req.full_url, req.get_method(), timeout, req.data))
        return _Resp()
    assert fluxhook.notify("containerizer: acme/shop deployed\n\nmore", env=_conf(tmp_path), opener=opener) is True
    (u, method, timeout, data), = seen
    assert (u, method, timeout) == ("http://10.43.0.9/hook/abc123", "POST", 5) and b"acme/shop" in data


def test_notify_is_a_no_op_without_configuration(tmp_path):
    never = lambda *a, **k: pytest.fail("no request")        # noqa: E731
    assert fluxhook.notify("x", env={}, opener=never) is False
    assert fluxhook.notify("x", env={fluxhook.ENV: str(tmp_path / "missing")}, opener=never) is False
    assert fluxhook.notify("x", env=_conf(tmp_path, ""), opener=never) is False
    assert fluxhook.notify("x", env=_conf(tmp_path, "file:///etc/passwd\n"), opener=never) is False


def test_notify_never_raises_and_logs_each_kind_of_failure_once_without_the_url(tmp_path, capsys):
    env = _conf(tmp_path)

    def down(req, timeout):
        raise urllib.error.URLError(f"timed out {req.full_url}")

    def missing(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO())
    assert fluxhook.notify("a", env=env, opener=down) is False
    assert fluxhook.notify("b", env=env, opener=down) is False
    assert fluxhook.notify("c", env=env, opener=missing) is False
    assert fluxhook.notify("d", env=env, opener=lambda r, timeout: _Resp(500)) is False
    err = capsys.readouterr().err
    assert err.count("flux webhook:") == 3 and "HTTP 404" in err and "HTTP 500" in err
    assert "abc123" not in err


def _git(*a, cwd=None):
    subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)


def test_every_successful_push_of_the_output_repository_calls_the_webhook(tmp_path, monkeypatch):
    bare, clone = tmp_path / "out.git", tmp_path / "out"
    _git("init", "-q", "--bare", "-b", "main", str(bare))
    _git("clone", "-q", str(bare), str(clone))
    calls = []
    monkeypatch.setattr(fluxhook, "notify", lambda reason="": calls.append(reason))
    o = orgmod.OrgOptions(provider="github", org="acme", registry="r", output_dir=str(clone))
    out = orgmod.Output(o, tmp_path / "w")
    assert out.git and out.push
    (clone / "a.txt").write_text("1\n")
    assert out.commit("containerizer: acme/shop deployed\n\ndetails")
    assert calls == ["containerizer: acme/shop deployed"]
    assert not out.commit("nothing changed") and len(calls) == 1          # no commit, no push: no call
    o.push = False
    out = orgmod.Output(o, tmp_path / "w")
    (clone / "b.txt").write_text("2\n")
    assert out.commit("local only") and len(calls) == 1                   # not pushed: no call


def test_the_appliance_keeps_the_receiver_and_gives_the_url_to_the_worker_and_the_runner():
    s = CZ_SANDBOX.read_text()
    assert "containerizer.fluxhook" in s and "flux-system--cz-webhook" in s
    assert "cz_store_grant flux-system flux-system--cz-git flux-system--cz-webhook" in s
    assert "/run/containerizer/flux-webhook" in s and "webhookPath" in s and "chmod 0640" in s
    for unit in ("containerizer-worker.service", "containerizer-llm-queue.service"):
        assert "Environment=CONTAINERIZER_FLUX_WEBHOOK=/run/containerizer/flux-webhook" in (UNITS / unit).read_text()
