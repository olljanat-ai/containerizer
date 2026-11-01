"""The appliance's built-in LLM (local_llm.py): requirements and sizing, the system agent's requests, the
Hugging Face egress only while the model downloads, the checked download, the units, the scan worker's
choice of LLM, monitoring, and the section on Admin -> Source control & LLM."""
import hashlib
import inspect
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from containerizer import admin_local_llm, appliance, credentials, local_llm, sysagent
from containerizer.local_llm import GiB
from tests.test_appliance import ADMIN, APPLIANCE, NOT_ADMIN, _unit, fake_run, paths  # noqa: F401 (fixture)

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def llm(tmp_path, monkeypatch, paths):  # noqa: F811
    p = local_llm.Paths(config=tmp_path / "var" / "system" / "local-llm.json", status=paths.run / "local-llm-status.json",
                        env=tmp_path / "run" / "local-llm.env", models=tmp_path / "var" / "llm",
                        meminfo=tmp_path / "meminfo")
    monkeypatch.setattr(local_llm, "P", p)
    monkeypatch.setattr(local_llm, "server_health", lambda timeout=2.0: False)
    monkeypatch.setattr(local_llm, "free_disk", lambda path: 200 * GiB)
    ram(p, 64)
    return p


def ram(p, gib: float):
    p.meminfo.write_text(f"MemTotal:       {int(gib * 1024 * 1024)} kB\nMemFree:  1000 kB\n")


def request(paths, **body):  # noqa: F811
    (paths.run / "requests" / f"{len(list((paths.run / 'requests').iterdir()))}.json").write_text(
        json.dumps({"action": "local-llm", "requested_by": "alice@x", "requested_by_name": "Alice", **body}))


def starts(r, unit):
    return [c for c in r.calls if c[:2] == ["systemctl", "start"] and unit in c]


def hf_hosts():
    return {x.get("host") for x in sysagent.system_rules()["rules"]} & set(local_llm.HF_HOSTS)


# ------------------------------------------------------------------------------- requirements, sizing

def test_plan_sizes_slots_and_memory_from_the_ram():
    assert local_llm.plan(40 * GiB) == {"slots": 1, "ctx_size": 22016, "memory": "24g", "memory_bytes": 24 * GiB}
    assert local_llm.plan(56 * GiB)["slots"] == 2 and local_llm.plan(56 * GiB)["memory"] == "27g"
    assert local_llm.plan(128 * GiB)["slots"] == 3 and local_llm.plan(128 * GiB)["memory"] == "30g"
    for gib in (40, 48, 64, 512):
        p = local_llm.plan(gib * GiB)
        assert p["ctx_size"] % (256 * p["slots"]) == 0 and p["ctx_size"] // p["slots"] > 20000
        assert 16 * GiB + p["memory_bytes"] <= gib * GiB        # the appliance's own 16 GiB still fit


def test_requirements_ram_and_disk(llm, monkeypatch):
    assert local_llm.requirements({}, llm)["problems"] == []
    ram(llm, 11)
    r = local_llm.requirements({}, llm)
    assert len(r["problems"]) == 1 and "11.0 GiB of RAM" in r["problems"][0] and "40 GiB" in r["problems"][0]
    ram(llm, 64)
    monkeypatch.setattr(local_llm, "free_disk", lambda path: 10 * GiB)
    r = local_llm.requirements({}, llm)
    assert r["need_disk"] == local_llm.MODEL.size + local_llm.DISK_MARGIN and "free on the persistent partition" in r["problems"][0]
    # a partial download counts; a verified model needs no space
    llm.models.mkdir(parents=True)
    llm.part.write_bytes(b"x" * 1000)
    assert local_llm.requirements({}, llm)["need_disk"] == local_llm.MODEL.size - 1000 + local_llm.DISK_MARGIN


# ------------------------------------------------------------------------------- requests

def test_off_by_default(llm):
    st = local_llm.status(paths=llm)
    assert st["enabled"] is False and st["state"] == "off"
    assert hf_hosts() == set()
    assert local_llm.worker_settings({local_llm.STATUS_ENV: str(llm.status)}) is None


def test_enable_refused_without_the_ram_starts_nothing(llm, paths, monkeypatch):  # noqa: F811
    r = fake_run(monkeypatch)
    ram(llm, 11)
    request(paths, do="enable")
    assert sysagent.process() == 0                       # an answer, not a failure (the unit must not fail)
    st = json.loads(llm.status.read_text())
    assert st["state"] == "refused" and "RAM" in st["message"] and st["enabled"] is False
    assert not [c for c in r.calls if c[0] in ("systemctl", "nft")]
    assert not llm.env.exists() and hf_hosts() == set()
    assert local_llm.load_config(llm)["history"][0]["by"] == "alice@x"


def test_unknown_request_is_rejected(llm, paths, monkeypatch):  # noqa: F811
    r = fake_run(monkeypatch)
    request(paths, do="download-anything", url="https://evil.example/x.gguf")
    assert sysagent.process() == 1
    assert not r.calls and not local_llm.load_config(llm)


def test_enable_downloads_with_hugging_face_allowed_only_meanwhile(llm, paths, monkeypatch):  # noqa: F811
    r = fake_run(monkeypatch)
    request(paths, do="enable")
    assert sysagent.process() == 0
    cfg = local_llm.load_config(llm)
    assert cfg["enabled"] and cfg["phase"] == "download"
    assert hf_hosts() == {"huggingface.co", "hf.co"}
    assert "nftset=/huggingface.co/" in paths.dnsmasq.read_text() and "nftset=/hf.co/" in paths.dnsmasq.read_text()
    assert starts(r, local_llm.DOWNLOAD_UNIT) and not starts(r, local_llm.UNIT)
    assert json.loads(llm.status.read_text())["state"] == "downloading"
    # the Firewall page lists them as system rules while the download runs
    assert {"huggingface.co", "hf.co"} <= {x.get("host") for x in sysagent.egress_status(journal="")["system_rules"]}
    # turned off meanwhile: out of the allow-list again, the download stopped
    request(paths, do="disable")
    sysagent.process()
    assert hf_hosts() == set() and "huggingface.co" not in paths.dnsmasq.read_text()
    assert any(c[:2] == ["systemctl", "stop"] and local_llm.DOWNLOAD_UNIT in c for c in r.calls)
    assert json.loads(llm.status.read_text())["state"] == "off"


def tiny(data: bytes) -> local_llm.Model:
    return local_llm.Model(file=local_llm.MODEL.file, url=local_llm.MODEL.url, sha256=hashlib.sha256(data).hexdigest(),
                           size=len(data), alias=local_llm.MODEL.alias)


class Done:
    def __init__(self, rc=0, err=""):
        self.returncode, self._err = rc, err
        self.stderr = SimpleNamespace(read=lambda: err)

    def poll(self):
        return self.returncode


def _downloading(llm, paths, monkeypatch, model):  # noqa: F811
    monkeypatch.setattr(local_llm, "MODEL", model)
    r = fake_run(monkeypatch)
    request(paths, do="enable")
    sysagent.process()
    assert hf_hosts()
    return r


def test_download_resumes_checks_and_starts_the_server(llm, paths, monkeypatch):  # noqa: F811
    data = b"GGUF" + bytes(range(256)) * 40
    model = tiny(data)
    r = _downloading(llm, paths, monkeypatch, model)
    llm.models.mkdir(parents=True, exist_ok=True)
    llm.part.write_bytes(data[:100])                     # an interrupted download

    def fetch(part):
        assert part.read_bytes() == data[:100]           # resumed, not started over
        with part.open("ab") as f:
            f.write(data[100:])
        return Done()
    assert local_llm.download(llm, fetch=fetch, poll=0, model=model) == 0
    assert llm.model.read_bytes() == data and not llm.part.exists()
    assert oct(llm.model.stat().st_mode & 0o777) == "0o644" and oct(llm.models.stat().st_mode & 0o777) == "0o755"
    cfg = local_llm.load_config(llm)
    assert cfg["phase"] == "ready" and local_llm.model_ready(cfg, llm)
    assert hf_hosts() == set() and "huggingface.co" not in paths.dnsmasq.read_text()
    env = llm.env.read_text()
    assert f"CZ_LLM_MODEL_FILE={model.file}" in env and "CZ_LLM_SLOTS=3" in env and "CZ_LLM_CTX=66048" in env
    assert "CZ_LLM_MEMORY=30g" in env and "CZ_LLM_PORT=8082" in env
    assert starts(r, local_llm.UNIT)
    st = json.loads(llm.status.read_text())
    assert st["state"] == "starting" and st["model"]["verified"]
    # used by the worker while it is on
    assert local_llm.worker_settings({local_llm.STATUS_ENV: str(llm.status)})["CONTAINERIZER_LLM_BASE_URL"] == \
        "http://127.0.0.1:8082/v1"
    # off and on again: no new download, the server starts at once
    request(paths, do="disable")
    sysagent.process()
    assert not llm.env.exists() and llm.model.exists()
    r.calls.clear()
    request(paths, do="enable")
    sysagent.process()
    assert starts(r, local_llm.UNIT) and not starts(r, local_llm.DOWNLOAD_UNIT) and hf_hosts() == set()


def test_download_checksum_mismatch_deletes_the_file(llm, paths, monkeypatch):  # noqa: F811
    data = b"the real model" * 100
    model = tiny(data)
    r = _downloading(llm, paths, monkeypatch, model)

    def fetch(part):
        part.write_bytes(b"X" * len(data))               # right size, wrong content
        return Done()
    assert local_llm.download(llm, fetch=fetch, poll=0, model=model) == 0     # the unit does not fail
    assert not llm.part.exists() and not llm.model.exists()
    cfg = local_llm.load_config(llm)
    assert cfg["phase"] == "failed" and "checksum mismatch" in cfg["error"]
    st = json.loads(llm.status.read_text())
    assert st["state"] == "download-failed" and "checksum" in st["message"]
    assert hf_hosts() == set() and not llm.env.exists() and not starts(r, local_llm.UNIT)
    assert local_llm.worker_settings({local_llm.STATUS_ENV: str(llm.status)}) is None
    # not retried by itself
    r.calls.clear()
    local_llm.reconcile(llm)
    assert not starts(r, local_llm.DOWNLOAD_UNIT)


def test_download_network_error_keeps_the_partial_file(llm, paths, monkeypatch):  # noqa: F811
    data = b"0123456789" * 100
    model = tiny(data)
    _downloading(llm, paths, monkeypatch, model)

    def fetch(part):
        part.write_bytes(data[:300])
        return Done(rc=56, err="curl: (56) Recv failure: Connection reset by peer")
    local_llm.download(llm, fetch=fetch, poll=0, model=model)
    assert llm.part.read_bytes() == data[:300]
    cfg = local_llm.load_config(llm)
    assert cfg["phase"] == "failed" and "curl exit 56" in cfg["error"] and "resume" in cfg["error"]
    assert hf_hosts() == set()


def test_download_needs_free_space(llm, paths, monkeypatch):  # noqa: F811
    _downloading(llm, paths, monkeypatch, local_llm.MODEL)
    monkeypatch.setattr(local_llm, "free_disk", lambda path: 5 * GiB)
    called = []
    local_llm.download(llm, fetch=lambda part: called.append(part), poll=0)
    assert not called and "not enough free space" in local_llm.load_config(llm)["error"]


def test_download_does_nothing_when_off(llm):
    assert local_llm.download(llm, fetch=lambda part: pytest.fail("no download while off"), poll=0) == 0


def test_curl_is_https_only_and_resumable():
    cmd = local_llm.curl_command(Path("/x/m.part"))
    assert cmd[0] == "curl" and ["-C", "-"] == cmd[cmd.index("-C"):cmd.index("-C") + 2]
    assert cmd[cmd.index("--proto") + 1] == "=https" and cmd[cmd.index("--proto-redir") + 1] == "=https"
    assert cmd[-1] == local_llm.MODEL.url and "/resolve/0436a5b1e12e051e8a8568d56a1526734d3ed572/" in cmd[-1]
    assert re.fullmatch(r"[0-9a-f]{64}", local_llm.MODEL.sha256)


def test_reconcile_at_boot(llm, paths, monkeypatch):  # noqa: F811
    data = b"model" * 50
    model = tiny(data)
    monkeypatch.setattr(local_llm, "MODEL", model)
    llm.models.mkdir(parents=True)
    llm.model.write_bytes(data)
    local_llm.save_config({"enabled": True, "phase": "ready", "verified": local_llm._stamp(llm.model)}, llm)
    r = fake_run(monkeypatch)
    assert local_llm.reconcile(llm)["state"] == "starting"       # /run is empty after a restart
    assert llm.env.exists() and starts(r, local_llm.UNIT)
    # the machine lost RAM: not started
    llm.env.unlink()
    r.calls.clear()
    ram(llm, 32)
    assert local_llm.reconcile(llm)["state"] == "refused" and not starts(r, local_llm.UNIT)
    # an interrupted download is resumed; one whose unit failed is reported and Hugging Face closed again
    ram(llm, 64)
    local_llm.save_config({"enabled": True, "phase": "download"}, llm)
    local_llm.reconcile(llm)
    assert starts(r, local_llm.DOWNLOAD_UNIT)
    fake_run(monkeypatch, **{f"systemctl is-active {local_llm.DOWNLOAD_UNIT}": "failed\n"})
    assert local_llm.reconcile(llm)["state"] == "download-failed" and hf_hosts() == set()
    # off: the server's environment goes, so the unit cannot start
    llm.env.write_text("x")
    local_llm.save_config({"enabled": False}, llm)
    local_llm.reconcile(llm)
    assert not llm.env.exists()


def test_status_command_reconciles(llm, paths, monkeypatch):  # noqa: F811
    fake_run(monkeypatch)
    assert sysagent.main(["status"]) == 0
    assert json.loads(llm.status.read_text())["state"] == "off"


def test_remove_model_only_while_off(llm, paths, monkeypatch):  # noqa: F811
    fake_run(monkeypatch)
    llm.models.mkdir(parents=True)
    llm.model.write_bytes(b"m")
    local_llm.save_config({"enabled": True, "phase": "ready"}, llm)
    request(paths, do="remove-model")
    assert sysagent.process() == 1 and llm.model.exists()
    local_llm.save_config({"enabled": False}, llm)
    request(paths, do="remove-model")
    assert sysagent.process() == 0 and not llm.model.exists()


def test_never_part_of_the_boot_assessment():
    src = inspect.getsource(sysagent.health)
    assert "llm" not in src.lower() and "8082" not in src


# ------------------------------------------------------------------------------- the scan worker

def test_llm_for_run_prefers_the_registered_llm_then_the_built_in_one(tmp_path):
    f = tmp_path / "local-llm-status.json"
    env = {local_llm.STATUS_ENV: str(f)}
    assert credentials.llm_for_run(None, env=env) == credentials.RunLlm(None, None, "environment")
    f.write_text(json.dumps({"enabled": True, "state": "downloading"}))
    assert credentials.llm_for_run(None, env=env).source == "environment"
    for state in ("starting", "running"):
        f.write_text(json.dumps({"enabled": True, "state": state, "base_url": "http://evil.example/v1"}))
        c = credentials.llm_for_run(None, env=env)
        assert c.source == "built-in" and c.model == "qwen3-coder-30b-a3b"
        assert c.settings == {"CONTAINERIZER_AI_BACKEND": "openai", "CONTAINERIZER_LLM_BASE_URL": "http://127.0.0.1:8082/v1",
                              "CONTAINERIZER_LLM_API_KEY": "", "CONTAINERIZER_MODEL": "qwen3-coder-30b-a3b",
                              "CONTAINERIZER_LLM_TIMEOUT": "3600"}
    reg = credentials.Credential(id=1, purpose="llm", provider="openai", api_url="https://gpu.example/v1", scope="llm",
                                 model="big", token="k")
    c = credentials.llm_for_run(reg, env=env)
    assert c.source == "registered" and c.model == "big" and c.settings["CONTAINERIZER_LLM_BASE_URL"] == "https://gpu.example/v1"
    f.write_text("{not json")
    assert credentials.llm_for_run(None, env=env).source == "environment"


def test_built_in_settings_reach_the_openai_backend(tmp_path, monkeypatch):
    from containerizer import ai
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"enabled": True, "state": "running"}))
    monkeypatch.delenv("CONTAINERIZER_LLM_TIMEOUT", raising=False)
    with ai.configured(credentials.llm_for_run(None, env={local_llm.STATUS_ENV: str(f)}).settings):
        assert ai._backend() == "openai" and ai._env("CONTAINERIZER_LLM_TIMEOUT") == "3600"
    assert ai._env("CONTAINERIZER_LLM_TIMEOUT") == ""


def test_worker_uses_the_helper():
    src = (ROOT / "containerizer" / "worker.py").read_text()
    assert "llm_for_run(llm)" in src and "llm.ai_settings()" not in src


# ------------------------------------------------------------------------------- units, image, monitoring

def test_units_are_off_by_default_and_condition_skipped():
    docker = (APPLIANCE / "Dockerfile").read_text()
    enable = docker[docker.index("systemctl enable"):docker.index("# Elemental")]
    assert "local-llm" not in enable
    srv = _unit("containerizer-local-llm.service")
    assert "/run/containerizer/local-llm.env" in srv["ConditionPathExists"]
    assert "WantedBy" not in srv and "/run/containerizer/local-llm.env" in srv["EnvironmentFile"]
    run = " ".join(srv["ExecStart"])
    text = (APPLIANCE / "rootfs/usr/lib/systemd/system/containerizer-local-llm.service").read_text()
    for flag in ("--network host", "/var/lib/containerizer/llm:/models:ro", "--memory ${CZ_LLM_MEMORY}", "--cpu-shares 256",
                 "--user 65534:65534", "--read-only", "--cap-drop ALL", "--cap-add IPC_LOCK", "--ulimit memlock=-1:-1",
                 "--security-opt no-new-privileges", "LLAMA_ARG_HOST=127.0.0.1", "--load-mode mmap+mlock",
                 "--lazy-mode off", "--metrics", "--jinja", "${CZ_IMAGE_LLAMA_CPP}"):
        assert flag in text, flag
    assert "--mlock " not in text and "8081" not in run
    dl = _unit("containerizer-local-llm-download.service")
    assert dl["Type"] == ["oneshot"] and "WantedBy" not in dl and "containerizer.local_llm download" in dl["ExecStart"][0]
    worker = _unit("containerizer-worker.service")
    assert "CONTAINERIZER_LOCAL_LLM=/run/containerizer/system/local-llm-status.json" in worker["Environment"]
    images = (APPLIANCE / "rootfs/usr/lib/containerizer/images.env").read_text()
    assert re.search(r"^CZ_IMAGE_LLAMA_CPP=ghcr\.io/ggml-org/llama\.cpp:server-b12030@sha256:e67d88af[0-9a-f]{56}$", images, re.M)
    # 8081 is Caddy's; the server's port is the module's
    assert "http_port 8081" in (APPLIANCE / "rootfs/etc/caddy/Caddyfile").read_text() and local_llm.PORT == 8082
    assert local_llm.server_env(local_llm.plan(40 * GiB)).count("\n") == 6


def test_ci_boot_test_checks_it_is_off():
    checks = (APPLIANCE / "ci" / "vm-checks.sh").read_text()
    for s in ("containerizer-local-llm.service", "127.0.0.1:8082", "huggingface.co", "CONTAINERIZER_LLM_BASE_URL",
              '"do": "enable"', "ConditionResult"):
        assert s in checks
    assert "containerizer-local-llm containerizer-local-llm-download" in (APPLIANCE / "ci" / "boot-test.sh").read_text()


def test_prometheus_scrapes_it_and_grafana_shows_it():
    import yaml
    prom = yaml.safe_load((APPLIANCE / "rootfs/usr/lib/containerizer/prometheus/prometheus.yml").read_text())
    job = next(j for j in prom["scrape_configs"] if j["job_name"] == "local-llm")
    assert job["static_configs"][0]["targets"] == ["127.0.0.1:8082"]
    d = json.loads((ROOT / "monitoring/grafana/containerizer-scans.json").read_text())
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids))
    mine = [p for p in d["panels"] if p["id"] >= 200]
    assert mine[0]["type"] == "row" and mine[0]["title"].startswith("Built-in LLM")
    bottom = max(p["gridPos"]["y"] + p["gridPos"]["h"] for p in d["panels"] if p["id"] < 200)
    assert min(p["gridPos"]["y"] for p in mine) >= bottom
    exprs = " ".join(t["expr"] for p in mine for t in p.get("targets") or [])
    assert "rate(llamacpp:n_decode_total" in exprs and "llamacpp:n_busy_slots_per_decode" in exprs
    assert "llamacpp:requests_processing" in exprs and "llamacpp:requests_deferred" in exprs
    for p in mine:
        refs = [t["refId"] for t in p.get("targets") or []]
        assert len(refs) == len(set(refs)), p["title"]
        if p["type"] == "timeseries":
            assert not any(t.get("instant") for t in p["targets"]), p["title"]


# ------------------------------------------------------------------------------- the admin page

class Adm:
    def __init__(self, system):
        self.system = system

    @staticmethod
    def _csrf(s):
        return "<input type='hidden' name='csrf' value='tok'>"


@pytest.fixture
def adm(tmp_path):
    d = tmp_path / "sys"
    (d / "requests").mkdir(parents=True)
    (d / "status.json").write_text("{}")
    return Adm(appliance.SystemPage(status_dir=d))


def page_status(adm, **st):
    (adm.system.status_dir / "local-llm-status.json").write_text(json.dumps(st))


def reqs(adm):
    return [json.loads(p.read_text()) for p in sorted((adm.system.status_dir / "requests").glob("*.json"))]


A_ADMIN, A_OPERATOR = SimpleNamespace(admin=True), SimpleNamespace(admin=False)
GOOD = {"ram": 64 * GiB, "free_disk": 100 * GiB, "need_disk": 20 * GiB, "problems": [],
        "plan": {"slots": 3, "memory": "30g"}}


def test_section_only_for_admins_on_the_appliance(adm):
    assert admin_local_llm.section(Adm(None), ADMIN, A_ADMIN, False) == ""
    assert admin_local_llm.section(adm, NOT_ADMIN, A_OPERATOR, False) == ""
    r = admin_local_llm.post(adm, NOT_ADMIN, A_OPERATOR, {"do": ["enable"]})
    assert r.status == 404 and reqs(adm) == []
    assert admin_local_llm.post(Adm(None), ADMIN, A_ADMIN, {"do": ["enable"]}).status == 404


def test_section_off_by_default(adm):
    page_status(adm, enabled=False, state="off", requirements=GOOD, model={"on_disk": 0}, history=[])
    html = admin_local_llm.section(adm, ADMIN, A_ADMIN, False)
    assert "Built-in LLM" in html and ">Off<" in html and "value='enable'" in html and "<button>Turn on" in html
    assert "queued LLM mode" in html and "40 GiB" in html and "huggingface.co" in html
    assert "value='remove-model'" not in html and "<script" not in html and "style=" not in html


def test_section_without_the_resources_cannot_be_turned_on(adm):
    page_status(adm, enabled=False, state="refused", message="Not turned on: the appliance has 11.0 GiB of RAM",
                requirements=dict(GOOD, ram=11 * GiB, problems=["the appliance has 11.0 GiB of RAM; ..."]))
    html = admin_local_llm.section(adm, ADMIN, A_ADMIN, False)
    assert "<button disabled>Turn on" in html and "11.0 GiB of RAM" in html and "not enough resources" in html


def test_section_shows_the_download_and_the_running_server(adm, monkeypatch):
    page_status(adm, enabled=True, state="downloading", download={"bytes": 4_000_000_000, "total": local_llm.MODEL.size},
                requirements=GOOD, plan={"slots": 3, "memory": "30g"},
                history=[{"at": "2026-11-01T10:00:00+00:00", "by": "alice@x", "name": "Alice <b>", "action": "enable",
                          "result": "turned on; downloading the model"}])
    html = admin_local_llm.section(adm, ADMIN, A_ADMIN, False)
    assert "<progress max='16018452000' value='4000000000'>" in html and "4.0 GB of 16.0 GB (24%)" in html
    assert "value='disable'" in html and "Alice &lt;b&gt;" in html and "3 answer slot(s)" in html
    monkeypatch.setattr(local_llm, "server_health", lambda timeout=2.0: True)
    page_status(adm, enabled=True, state="starting", requirements=GOOD, model={"verified": True, "on_disk": 1})
    html = admin_local_llm.section(adm, ADMIN, A_ADMIN, False)
    assert ">Running<" in html and "http://127.0.0.1:8082/v1" in html
    html = admin_local_llm.section(adm, ADMIN, A_ADMIN, True)
    assert "Not used while an LLM is set above" in html


def test_post_requests_for_the_agent(adm):
    page_status(adm, enabled=False, state="off", model={"on_disk": 5})
    assert admin_local_llm.post(adm, ADMIN, A_ADMIN, {"do": ["download-from-elsewhere"]}).status == 303 and reqs(adm) == []
    r = admin_local_llm.post(adm, ADMIN, A_ADMIN, {"do": ["enable"]})
    assert r.status == 303 and "#built-in-llm" in dict(r.headers)["Location"]
    assert reqs(adm)[0] | {"requested_at": None} == {"action": "local-llm", "do": "enable", "requested_by": "alice@x",
                                                     "requested_by_name": "Alice", "requested_at": None}
    r = admin_local_llm.post(adm, ADMIN, A_ADMIN, {"do": ["disable"]})
    assert "still+being+applied" in dict(r.headers)["Location"] and len(reqs(adm)) == 1
    for f in (adm.system.status_dir / "requests").glob("*.json"):
        f.unlink()
    r = admin_local_llm.post(adm, ADMIN, A_ADMIN, {"do": ["remove-model"]})
    assert "Tick+the+box" in dict(r.headers)["Location"] and reqs(adm) == []
    admin_local_llm.post(adm, ADMIN, A_ADMIN, {"do": ["remove-model"], "confirm": ["yes"]})
    assert reqs(adm)[0]["do"] == "remove-model"
    for f in (adm.system.status_dir / "requests").glob("*.json"):
        f.unlink()
    page_status(adm, enabled=True, state="running")
    r = admin_local_llm.post(adm, ADMIN, A_ADMIN, {"do": ["remove-model"], "confirm": ["yes"]})
    assert "off+before" in dict(r.headers)["Location"] and reqs(adm) == []


class Cur:
    def execute(self, *a):
        pass

    def fetchall(self):
        return []


def test_source_control_page_has_the_section_on_the_appliance_only(adm):
    from containerizer import admin_credentials
    conn = SimpleNamespace(cursor=lambda as_dict=False: Cur())
    page_status(adm, enabled=False, state="off", requirements=GOOD)

    def shell(s, a, title, active, body, flash=""):
        return body
    adm._shell = shell
    adm.credential_key = None
    body = admin_credentials.list_page(adm, conn, ADMIN, A_ADMIN, "").body
    assert "id='built-in-llm'" in body and "built-in LLM below" in body
    off = Adm(None)
    off._shell, off.credential_key = shell, None
    body = admin_credentials.list_page(off, conn, ADMIN, A_ADMIN, "").body
    assert "built-in-llm" not in body
    # the route
    r = admin_credentials.route(adm, conn, ADMIN, A_ADMIN, "POST", ["source-control", "local-llm"], {}, {"do": ["enable"]})
    assert r.status == 303 and reqs(adm)[0]["action"] == "local-llm"


def test_a_crash_looping_server_is_an_error_not_starting(llm, monkeypatch):
    monkeypatch.setattr(local_llm, "model_ready", lambda cfg, paths: True)
    cfg = {"enabled": True, "phase": "ready"}

    def st(restarts, healthy=False):
        return local_llm.status(cfg, llm, unit_state=lambda u: "active", health=lambda: healthy,
                                restarts=lambda u: restarts)
    assert st(0)["state"] == "starting"                  # loading the model
    assert st(2)["state"] == "starting"
    s = st(3)
    assert s["state"] == "error" and "keeps restarting (3 restarts" in s["message"]
    assert st(7, healthy=True)["state"] == "running"     # it recovered
    # the worker does not use a server in error
    llm.status.parent.mkdir(parents=True, exist_ok=True)
    llm.status.write_text(json.dumps(s))
    assert not local_llm.worker_settings({local_llm.STATUS_ENV: str(llm.status)})


def test_server_unit_caps_the_prompt_cache():
    unit = (Path(__file__).resolve().parent.parent / "appliance" / "rootfs" / "usr" / "lib" / "systemd" / "system"
            / "containerizer-local-llm.service").read_text()
    assert "--cache-ram 1024" in unit
