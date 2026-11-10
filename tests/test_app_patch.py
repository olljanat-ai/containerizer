"""App updates of the appliance (apppatch.py, sysagent.py): a patch release of the running OS's series is installed
as the signed application image alone, mounted over the code, and only the services restart; a minor or major
release stays a full OS upgrade."""
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from containerizer import apppatch, sysagent
from containerizer.apppatch import PatchError

from test_appliance import ADMIN, STATE, page, paths, shell  # noqa: F401 - fixtures

DIGEST = "sha256:" + "ab" * 32
APP_DIGEST = "sha256:" + "cd" * 32
LOCK = "12" * 32
REPO = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------------------- versions and manifests

def test_patch_only_within_the_series_and_newer():
    assert apppatch.is_patch_of("v1.1.3", "v1.1.0")
    assert apppatch.is_patch_of("v1.1.3", "v1.1.2")
    assert not apppatch.is_patch_of("v1.2.0", "v1.1.0")        # minor: an OS upgrade
    assert not apppatch.is_patch_of("v2.1.1", "v1.1.0")        # major
    assert not apppatch.is_patch_of("v1.1.0", "v1.1.0")
    assert not apppatch.is_patch_of("v1.1.1", "dev")
    assert apppatch.app_image("ghcr.io/o/containerizer-appliance") == "ghcr.io/o/containerizer-app"


def manifest(version="v1.1.3", **kw):
    return {"version": version, "series": apppatch.series(version), "requirements_sha256": LOCK, **kw}


def test_manifest_must_fit_the_running_os():
    apppatch.check_manifest(manifest(), "v1.1.3", "v1.1.0", LOCK)
    for m, v, os_v, lock in [(manifest(), "v1.1.4", "v1.1.0", LOCK),                  # not the version asked for
                             (manifest("v1.2.1"), "v1.2.1", "v1.1.0", LOCK),          # another series
                             (manifest(series="1.2"), "v1.1.3", "v1.1.0", LOCK),
                             (manifest(), "v1.1.3", "v1.1.0", "34" * 32),             # other Python packages
                             (manifest(), "v1.1.3", "v1.1.0", None),                  # an OS without app updates
                             (manifest("v1.1.0"), "v1.1.0", "v1.1.2", LOCK)]:         # older than the OS
        with pytest.raises(PatchError):
            apppatch.check_manifest(m, v, os_v, lock)


# ------------------------------------------------------------------------------- unpacking

def layer(files: dict, links: dict | None = None, prefix="app/") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(prefix + name if not name.startswith(("/", "..", "etc/")) else name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for name, target in (links or {}).items():
            ti = tarfile.TarInfo(prefix + name)
            ti.type, ti.linkname = tarfile.SYMTYPE, target
            tf.addfile(ti)
    return buf.getvalue()


def bundle_files(version="v1.1.3", **kw):
    return {"manifest.json": json.dumps(manifest(version, **kw)),
            "containerizer/__init__.py": f'__version__ = "{version[1:]}"\n',
            "rules/10-runtime.yaml": "rules: []\n"}


def test_unpack_takes_the_app_folder_in_layer_order(tmp_path):
    dest = tmp_path / "out"
    apppatch.unpack_layers([layer(bundle_files()), layer({"rules/10-runtime.yaml": "rules: [x]\n", "etc/passwd": "x"})],
                           dest)
    assert (dest / "rules" / "10-runtime.yaml").read_text() == "rules: [x]\n"
    assert not (dest / "etc").exists() and not (tmp_path / "etc").exists()
    apppatch.check_tree(dest, "v1.1.3")
    with pytest.raises(PatchError):
        apppatch.check_tree(dest, "v1.1.4")


@pytest.mark.parametrize("bad", [
    layer({}, links={"rules/learned": "/var/lib/containerizer/learned"}),     # a link out of the folder
    layer({}, links={"x": "../../etc/shadow"}),
    layer({"rules/.wh.10-runtime.yaml": ""}),                                  # a whiteout
    layer({"x/../../../escape": "x"}),
], ids=["absolute-link", "parent-link", "whiteout", "parent-path"])
def test_unpack_refuses_what_leaves_the_folder(tmp_path, bad):
    with pytest.raises(PatchError):
        apppatch.unpack_layers([bad], tmp_path / "out")
    assert not (tmp_path / "escape").exists()


# ------------------------------------------------------------------------------- the registry

class Resp(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(url, code, headers):
    h = Message()
    for k, v in headers.items():
        h[k] = v
    return urllib.error.HTTPError(url, code, "x", h, io.BytesIO(b""))


def fake_registry(blobs: dict, seen: list):
    """ghcr.io: a 401 with the token challenge, then manifests and blobs; blobs redirect to the blob store."""
    def opener(req, timeout):
        url, auth = req.full_url, req.get_header("Authorization")
        seen.append((url, auth))
        if url.startswith("https://ghcr.io/token?"):
            return Resp(json.dumps({"token": "T"}).encode())
        if url.startswith("https://ghcr.io/v2/") and auth != "Bearer T":
            raise http_error(url, 401, {"WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'})
        if url.startswith("https://store.example/"):
            return Resp(blobs[url.rsplit("/", 1)[1]])
        digest = url.rsplit("/", 1)[1]
        if "/blobs/" in url:
            raise http_error(url, 307, {"Location": f"https://store.example/{digest}"})
        return Resp(blobs[digest])
    return opener


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def image(layers: list[bytes]) -> tuple[str, dict]:
    blobs = {sha(b): b for b in layers}
    m = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "layers": [{"digest": sha(b), "size": len(b)} for b in layers]}).encode()
    blobs[sha(m)] = m
    return sha(m), blobs


def test_fetch_by_digest_with_an_anonymous_token(tmp_path):
    digest, blobs = image([layer(bundle_files())])
    seen = []
    apppatch.fetch("ghcr.io/o/containerizer-app", digest, tmp_path / "out",
                   apppatch.Registry("ghcr.io/o/containerizer-app", opener=fake_registry(blobs, seen)))
    apppatch.check_tree(tmp_path / "out", "v1.1.3")
    store = [a for u, a in seen if u.startswith("https://store.example/")]
    assert store and all(a is None for a in store)          # the registry's token stays with the registry


def test_fetch_refuses_content_that_does_not_match_its_digest(tmp_path):
    digest, blobs = image([layer(bundle_files())])
    for k in list(blobs):
        if k != digest:
            blobs[k] = layer(bundle_files("v6.6.6"))         # another layer than the manifest names
    with pytest.raises(PatchError, match="does not match"):
        apppatch.fetch("ghcr.io/o/containerizer-app", digest, tmp_path / "out",
                       apppatch.Registry("ghcr.io/o/containerizer-app", opener=fake_registry(blobs, [])))
    with pytest.raises(PatchError, match="does not match"):
        apppatch.Registry("ghcr.io/o/containerizer-app", opener=fake_registry({DIGEST: b"{}"}, [])).manifest(DIGEST)


# ------------------------------------------------------------------------------- the system agent

class Runner:
    """sysagent.run: the commands, with the app-patch unit doing what it does on the appliance."""

    def __init__(self, p, states=None, fail_import=False):
        self.p, self.calls, self.states, self.fail_import = p, [], states or {}, fail_import
        self.pids = {}

    def __call__(self, cmd, timeout=0, check=True, input=None):
        self.calls.append(cmd)
        if cmd[:2] == ["elemental", "state"]:
            return STATE
        if cmd[:2] == ["cosign", "verify"]:
            d = APP_DIGEST if cmd[-1].startswith("ghcr.io/olljanat-ai/containerizer-app:") else DIGEST
            return json.dumps([{"critical": {"image": {"docker-manifest-digest": d}}}])
        if cmd == ["systemctl", "restart", "containerizer-app-patch.service"]:
            m = self.p.patch_mount / "manifest.json"
            m.unlink(missing_ok=True)
            v = sysagent.active_patch()
            if v:
                try:
                    sysagent.check_patch(v)
                    m.write_text((self.p.patches / v / "manifest.json").read_text())
                except PatchError:
                    pass
            return ""
        if cmd[:2] == ["systemctl", "is-active"]:
            return self.states.get(cmd[2], "active") + "\n"
        if cmd[:3] == ["systemctl", "show", "-p"] and cmd[3] == "MainPID":
            return f"{self.pids.get(cmd[-1], 0)}\n"
        if len(cmd) > 2 and cmd[1] == "-I" and cmd[2] == "-c" and self.fail_import:
            raise sysagent.AgentError("ImportError: broken")
        return ""


@pytest.fixture
def agent(paths, tmp_path, monkeypatch):  # noqa: F811
    paths.patches = tmp_path / "var" / "app-patches"
    paths.patch_mount = tmp_path / "run" / "app-patch"
    paths.patch_mount.mkdir(parents=True)
    paths.requirements_sha = tmp_path / "requirements.sha256"
    paths.requirements_sha.write_text(LOCK + "\n")
    paths.learned = tmp_path / "var" / "learned"
    monkeypatch.setattr(sysagent, "PATCH_SETTLE", 0)
    monkeypatch.setattr(sysagent, "HEALTH_POLL", 0)
    monkeypatch.setattr(sysagent, "web_answers", lambda: None)
    fetched = []

    def fetch(image, digest, dest, registry=None):
        fetched.append((image, digest))
        v = getattr(fetch, "version", None)
        apppatch.unpack_layers([layer(bundle_files(v or fetch.want))], dest)
    monkeypatch.setattr(sysagent.apppatch, "fetch", fetch)
    return paths, fetch, fetched


OTHERS = [u for u in sysagent.PATCH_SERVICES if u != sysagent.LLM_QUEUE]


def request(p, **body):
    (p.run / "requests" / f"{len(list((p.run / 'requests').iterdir()))}.json").write_text(json.dumps(body))


def status(p):
    return json.loads((p.run / "status.json").read_text())


def test_patch_release_is_an_app_update_without_os_restart(agent, monkeypatch):
    p, fetch, fetched = agent
    r = Runner(p)
    monkeypatch.setattr(sysagent, "run", r)
    fetch.want = "v1.1.3"
    request(p, action="upgrade", version="v1.1.3", requested_by="alice@x")
    assert sysagent.process() == 0
    cosign = next(c for c in r.calls if c[0] == "cosign")
    assert cosign[-1] == "ghcr.io/olljanat-ai/containerizer-app:v1.1.3"       # the app image, same signer
    assert fetched == [("ghcr.io/olljanat-ai/containerizer-app", APP_DIGEST)]   # by the verified digest
    assert not [c for c in r.calls if c[:2] == ["elemental", "upgrade"]]
    assert ["systemctl", "reboot"] not in r.calls
    assert ["systemctl", "try-restart", *OTHERS] in r.calls
    assert ["systemctl", "try-restart", sysagent.LLM_QUEUE] in r.calls             # it did not run: started
    # the schema is upgraded by the new code before the services restart, in a unit of its own (restarting
    # containerizer-db-init.service would restart the services that Require= it, the LLM queue undrained)
    db = next(i for i, c in enumerate(r.calls) if c[0] == "systemd-run")
    assert r.calls[db][-1] == "/usr/lib/containerizer/bin/cz-db-init" and "--wait" in r.calls[db]
    assert db < r.calls.index(["systemctl", "try-restart", *OTHERS])
    assert ["systemctl", "restart", "containerizer-db-init.service"] not in r.calls
    assert (p.patches / "active").read_text().strip() == "v1.1.3"
    assert (p.patches / "v1.1.3" / "rules" / "learned").resolve() == p.learned.resolve()
    assert not [d for d in p.patches.iterdir() if d.name.startswith(".")]      # no staging left
    st = status(p)
    assert st["task"]["state"] == "done" and st["task"]["kind"] == "app update"
    assert st["version"] == "v1.1.3" and st["os_version"] == "v1.1.0" and st["app_patch"]["version"] == "v1.1.3"


def test_minor_release_or_full_is_an_os_upgrade(agent, monkeypatch):
    p, fetch, fetched = agent
    r = Runner(p)
    monkeypatch.setattr(sysagent, "run", r)
    request(p, action="upgrade", version="v1.2.0")
    assert sysagent.process() == 0
    sysagent.upgrade("v1.1.3", {"action": "upgrade"}, full=True)
    ups = [c for c in r.calls if c[:2] == ["elemental", "upgrade"]]
    assert len(ups) == 2 and not fetched
    assert ups[0][ups[0].index("--system") + 1] == f"oci:ghcr.io/olljanat-ai/containerizer-appliance@{DIGEST}"


def test_os_image_without_app_updates_upgrades_the_os(agent, monkeypatch):
    p, fetch, fetched = agent
    p.requirements_sha.unlink()                     # an OS image from before app updates
    r = Runner(p)
    monkeypatch.setattr(sysagent, "run", r)
    request(p, action="upgrade", version="v1.1.3")
    assert sysagent.process() == 0
    assert [c for c in r.calls if c[:2] == ["elemental", "upgrade"]] and not fetched
    assert status(p)["app_updates"] is False


def test_update_that_does_not_import_is_not_made_active(agent, monkeypatch):
    p, fetch, fetched = agent
    r = Runner(p, fail_import=True)
    monkeypatch.setattr(sysagent, "run", r)
    fetch.want = "v1.1.3"
    request(p, action="upgrade", version="v1.1.3")
    assert sysagent.process() == 1
    assert sysagent.active_patch() is None and not (p.patches / "v1.1.3").exists()
    assert not [c for c in r.calls if c[:2] == ["systemctl", "try-restart"]]
    assert status(p)["task"]["state"] == "failed"


def test_update_for_another_lock_is_refused(agent, monkeypatch):
    p, fetch, fetched = agent
    monkeypatch.setattr(sysagent, "run", Runner(p))
    fetch.want = "v1.1.3"
    p.requirements_sha.write_text("34" * 32)
    request(p, action="upgrade", version="v1.1.3")
    assert sysagent.process() == 1
    assert "other Python packages" in status(p)["task"]["message"]


def test_services_that_do_not_come_up_put_the_previous_code_back(agent, monkeypatch):
    p, fetch, fetched = agent
    monkeypatch.setattr(sysagent, "run", Runner(p))
    fetch.want = "v1.1.2"
    sysagent.upgrade("v1.1.2", {"action": "upgrade"})
    assert status(p)["app_patch"]["version"] == "v1.1.2"
    r = Runner(p, states={"containerizer-web.service": "failed"})
    monkeypatch.setattr(sysagent, "run", r)
    monkeypatch.setattr(sysagent, "PATCH_START_WAIT", 0)
    fetch.want = "v1.1.3"
    request(p, action="upgrade", version="v1.1.3")
    assert sysagent.process() == 1
    assert sysagent.active_patch() == "v1.1.2" and sysagent.mounted_patch()["version"] == "v1.1.2"
    assert r.calls.count(["systemctl", "try-restart", *OTHERS]) == 2
    t = status(p)["task"]
    assert t["state"] == "failed" and "back to v1.1.2" in t["message"]


def test_remove_and_rollback_go_back_to_the_os_code(agent, monkeypatch):
    p, fetch, fetched = agent
    monkeypatch.setattr(sysagent, "run", Runner(p))
    fetch.want = "v1.1.3"
    sysagent.upgrade("v1.1.3", {"action": "upgrade"})
    request(p, action="app-patch-remove", requested_by="alice@x")
    assert sysagent.process() == 0
    assert sysagent.active_patch() is None and sysagent.mounted_patch() is None
    st = status(p)
    assert st["version"] == "v1.1.0" and st["task"]["state"] == "done"
    request(p, action="app-patch-remove")
    assert sysagent.process() == 1                      # nothing to remove
    sysagent.upgrade("v1.1.3", {"action": "upgrade"})
    request(p, action="rollback", snapshot=1)
    assert sysagent.process() == 0
    assert sysagent.active_patch() is None


def test_select_at_start_up_only_when_the_update_fits_the_os(agent, monkeypatch):
    p, fetch, fetched = agent
    r = Runner(p)
    monkeypatch.setattr(sysagent, "run", r)
    fetch.want = "v1.1.3"
    sysagent.upgrade("v1.1.3", {"action": "upgrade"})
    assert "v1.1.3 mounted" in sysagent.select_patch()
    assert ["mount", "--bind", "-o", "ro", str(p.patches / "v1.1.3"), str(p.patch_mount)] in r.calls
    p.os_release.write_text('IMAGE_TAG="v1.2.0"\n')    # a full upgrade to the next minor version
    r.calls.clear()
    assert "not used" in sysagent.select_patch()
    assert not [c for c in r.calls if c[0] == "mount"]


def test_console_commands(agent, monkeypatch):
    p, fetch, fetched = agent
    r = Runner(p)
    monkeypatch.setattr(sysagent, "run", r)
    fetch.want = "v1.1.3"
    assert sysagent.main(["upgrade", "v1.1.3"]) == 0 and sysagent.active_patch() == "v1.1.3"
    assert sysagent.main(["app-patch", "remove"]) == 0 and sysagent.active_patch() is None
    assert sysagent.main(["app-patch", "select"]) == 0
    assert sysagent.main(["upgrade", "v1.1.3", "--full", "--no-reboot"]) == 0
    assert [c for c in r.calls if c[:2] == ["elemental", "upgrade"]] and ["systemctl", "reboot"] not in r.calls
    assert sysagent.main(["upgrade", "v1.1.3", "--bogus"]) == 2


# ------------------------------------------------------------------------------- the System page

def test_system_page_labels_app_updates_and_offers_removal(page):  # noqa: F811
    st = page.status()
    st.update(app_updates=True, os_version="v1.1.0", version="v1.1.1", app_patch={"version": "v1.1.1", "series": "1.1"})
    (page.status_dir / "status.json").write_text(json.dumps(st))
    page.fetch_tags = lambda image: ["v1.1.0", "v1.1.1", "v1.1.2", "v1.2.0"]
    code, body, _ = page.handle(ADMIN, "GET", ["system"], {}, {}, shell)
    assert "v1.1.2: app update, the OS does not restart" in body and "v1.2.0: OS upgrade" in body
    assert ">v1.1.1:" not in body                         # the running version is not newer
    assert "app update on OS v1.1.0" in body and "/admin/system/app-patch-remove" in body
    code, _, loc = page.handle(ADMIN, "POST", ["system", "app-patch-remove"], {}, {}, shell)
    assert "confirm" in loc and not page.pending()
    code, _, loc = page.handle(ADMIN, "POST", ["system", "app-patch-remove"], {}, {"confirm": ["yes"]}, shell)
    assert [x["action"] for x in page.pending()] == ["app-patch-remove"]
    code, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {},
                               {"confirm": ["yes"], "version": ["v1.1.2"]}, shell)
    assert "already+planned" in loc                       # one change at a time


def test_system_page_upgrade_of_an_app_update_says_services_restart(page):  # noqa: F811
    st = page.status()
    st.update(app_updates=True, os_version="v1.1.0")
    (page.status_dir / "status.json").write_text(json.dumps(st))
    page.fetch_tags = lambda image: ["v1.1.0", "v1.1.2"]
    code, _, loc = page.handle(ADMIN, "POST", ["system", "upgrade"], {}, {"confirm": ["yes"], "version": ["v1.1.2"]}, shell)
    assert "its+services+restart" in loc
    assert page.pending()[0]["version"] == "v1.1.2"


# ------------------------------------------------------------------------------- the image and the release

def test_os_image_mounts_the_update_before_its_own_code():
    df = (REPO / "appliance/Dockerfile").read_text()
    assert "printf '/run/containerizer/app-patch\\n/usr/lib/containerizer/app\\n'" in df
    assert "/usr/lib/containerizer/requirements.sha256" in df and "containerizer-app-patch.service" in df
    unit = (REPO / "appliance/rootfs/usr/lib/systemd/system/containerizer-app-patch.service").read_text()
    assert "Environment=PYTHONPATH=/usr/lib/containerizer/app" in unit      # the OS image's own code selects
    assert "sysagent app-patch select" in unit and "Before=sysinit.target" in unit
    for u in sysagent.PATCH_SERVICES:
        assert (REPO / "appliance/rootfs/usr/lib/systemd/system" / u).is_file()
    wf = (REPO / ".github/workflows/release.yml").read_text()
    assert wf.count('appliance/ci/patch-release-check.sh "') == 2
    assert 'cosign sign --yes "$APP_IMAGE@$app_digest"' in wf


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "tag.gpgSign=false",
                    "-c", "commit.gpgSign=false", *args], cwd=cwd, check=True, capture_output=True)


def test_patch_release_check_refuses_os_changes(tmp_path):
    script = REPO / "appliance/ci/patch-release-check.sh"
    for d in ("appliance/rootfs", "appliance/ci", "containerizer"):
        (tmp_path / d).mkdir(parents=True)
    (tmp_path / "appliance/Dockerfile").write_text("FROM x\n")
    (tmp_path / "containerizer/a.py").write_text("x = 1\n")
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    git(tmp_path, "tag", "v1.1.0")

    def check(v):
        return subprocess.run([str(script), v], cwd=tmp_path, capture_output=True, text=True).returncode

    (tmp_path / "containerizer/a.py").write_text("x = 2\n")
    (tmp_path / "appliance/ci/t.sh").write_text("true\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "code fix")
    assert check("v1.1.1") == 0
    assert check("v1.2.1") == 1                            # no v1.2.0 to patch
    (tmp_path / "appliance/rootfs/x.conf").write_text("y\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "os change")
    assert check("v1.1.1") == 1
    assert check("v1.2.0") == 0                            # a minor release may change the OS


def test_an_app_update_drains_the_llm_runner_instead_of_restarting_it(agent, monkeypatch):
    """A planned app update does not wait for the LLM jobs: the runner is told to drain (SIGUSR1) and finishes them
    on its code; the plan's wait, counted from its start, cuts them off (restarted: back in the queue)."""
    from datetime import datetime, timedelta, timezone
    from containerizer import restartplan
    p, fetch, fetched = agent
    r = Runner(p)
    r.pids[sysagent.LLM_QUEUE] = 4242
    monkeypatch.setattr(sysagent, "run", r)
    asked = []
    monkeypatch.setattr(sysagent, "running_work", lambda llm=True: asked.append(llm) or 0)
    fetch.want = "v1.1.3"
    request(p, action="plan", then="upgrade", version="v1.1.3", max_wait_minutes=60, requested_by="alice@x")
    assert sysagent.process() == 0
    plan = json.loads(p.plan.read_text())
    assert plan["app_update"] is True
    # the LLM runner is not held by it (the scan worker is)
    st = p.run / "status.json"
    assert restartplan.holding(path=st, llm=True) is None and restartplan.holding(path=st)
    at = restartplan.starts(plan)
    assert sysagent.restart_check(at + timedelta(minutes=10)) == "done"
    assert asked == [False]                                      # scans only: the LLM jobs do not hold it
    assert ["systemctl", "try-restart", *OTHERS] in r.calls
    assert ["systemctl", "kill", "--kill-whom=main", "-s", "SIGUSR1", sysagent.LLM_QUEUE] in r.calls
    assert ["systemctl", "try-restart", sysagent.LLM_QUEUE] not in r.calls
    d = status(p)["llm_drain"]
    assert d["pid"] == 4242 and d["version"] == "v1.1.3"
    assert restartplan.parse_time(d["until"]) == at + timedelta(minutes=60)
    assert status(p)["task"]["state"] == "done"
    # still draining; then the unit runs another process (the new code): done
    assert sysagent.restart_check(at + timedelta(minutes=20)) == "the LLM queue runner finishes its LLM call"
    r.pids[sysagent.LLM_QUEUE] = 5000
    assert sysagent.restart_check(at + timedelta(minutes=21)) == "the LLM queue runner runs the new code"
    assert status(p)["llm_drain"] is None and not p.drain.exists()
    # another drain whose wait runs out: restarted, the jobs go back to the queue
    sysagent.save_drain({"pid": 5000, "since": "x", "version": "v1.1.4",
                         "until": (at + timedelta(minutes=30)).isoformat()})
    assert sysagent.restart_check(at + timedelta(minutes=31)) == "the LLM queue runner restarted (its wait was over)"
    assert ["systemctl", "try-restart", sysagent.LLM_QUEUE] in r.calls and not p.drain.exists()
    # without waiting: restarted at once, as before
    r.calls.clear()
    sysagent.restart_services(datetime.now(timezone.utc) - timedelta(seconds=1), "v1.1.4")
    assert ["systemctl", "try-restart", sysagent.LLM_QUEUE] in r.calls and not p.drain.exists()
    # the drained runner waiting for its restart does not fail the update's check
    assert sysagent._up(sysagent.LLM_QUEUE, "activating") and not sysagent._up("containerizer-web.service", "activating")
