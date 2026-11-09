"""Memory requests and limits sized from what the verification run measured (issue #297)."""
import json
from types import SimpleNamespace

import yaml

from containerizer import verify as vf
from containerizer.assess import assess
from containerizer.generate import generate_app, k8s_name
from test_engine import web_app


def test_verification_run_records_peak_memory_and_cpu(monkeypatch, tmp_path):
    stats = iter(["120.5MiB / 768MiB|3.20%", "0.30GiB / 768MiB|45.00%", "200MiB / 768MiB|1.00%",
                  "250MiB / 768MiB|2.00%", "210MiB / 768MiB|1.00%"])
    calls = []

    def run(cmd, timeout=0, cwd=None):
        calls.append(cmd[:2])
        if cmd[:2] == ["docker", "run"]:
            assert "768m" in cmd
            return 0, "cid"
        if cmd[:2] == ["docker", "inspect"]:
            return 0, "true 0"
        if cmd[:2] == ["docker", "stats"]:
            assert "--no-stream" in cmd
            return 0, next(stats)
        return 0, ""
    answers = iter([None, None, 200])       # the app answers its health probe on the third round
    monkeypatch.setattr(vf, "_run", run)
    monkeypatch.setattr(vf, "_http", lambda url, timeout=3.0: next(answers, 200) if url.endswith("/healthz") else None)
    monkeypatch.setattr(vf.time, "sleep", lambda s: None)
    c = SimpleNamespace(role="web", facts={}, project=SimpleNamespace(dir=tmp_path))
    status, _, details = vf.run(c, {"uid": 1654, "add_writable": [], "port": 8080, "health": "/healthz"}, "img", tmp_path)
    assert status == "ok"
    u = details["usage"]
    assert u["memory_peak_mib"] == round(0.30 * 1024, 1) and u["cpu_peak_percent"] == 45.0
    assert u["samples"] == 5 and u["run_limit_mib"] == 768
    assert calls.count(["docker", "stats"]) == 5


def test_unreadable_stats_record_nothing(monkeypatch):
    monkeypatch.setattr(vf, "_run", lambda cmd, timeout=0: (1, "Error: No such container: x"))
    usage: dict = {}
    vf._track(usage, "x")
    assert usage == {}


def _generated(tmp_path, peak, packages="", name="app"):
    root = tmp_path / name
    web_app(root, packages=packages)
    a = assess(root)
    c = a.components[0]
    if peak is not None:
        a.verification = [{"component": c.name, "status": "ok", "usage": {"memory_peak_mib": peak, "samples": 4}}]
    out = tmp_path / f"out-{name}"
    generate_app(a, out)
    cdir = out / k8s_name(c.name)
    dep = next(d for d in yaml.safe_load_all((cdir / "k8s.yaml").read_text()) if d and d.get("kind") == "Deployment")
    res = dep["spec"]["template"]["spec"]["containers"][0]["resources"]
    return res["requests"]["memory"], res["limits"]["memory"], json.loads((cdir / "plan.json").read_text())


def test_generate_sizes_memory_from_the_measured_peak(tmp_path):
    req, lim, plan = _generated(tmp_path, 310)
    assert (req, lim) == ("448Mi", "640Mi")         # 310 x 1.25 and 310 x 2, rounded up to 64Mi
    why = next(r["why"] for r in plan["reasons"] if r["rule"] == "measured-memory")
    assert "measured 310Mi peak in the verification run" in why


def test_measured_memory_stays_within_the_floor_and_the_limit_range_max(tmp_path):
    assert _generated(tmp_path, 20, name="tiny")[:2] == ("128Mi", "512Mi")          # request floor; the limit never below the baseline
    req, lim, _ = _generated(tmp_path, 3000, name="big")
    assert (req, lim) == ("3776Mi", "4096Mi")                                        # LimitRange max 4Gi


def test_without_a_measurement_the_baseline_stays(tmp_path):
    req, lim, plan = _generated(tmp_path, None)
    assert (req, lim) == ("256Mi", "512Mi")
    assert not any(r["rule"] == "measured-memory" for r in plan.get("reasons") or [])


def test_exceptions_only_raise_a_measured_size(tmp_path):
    pdf = '<PackageReference Include="QuestPDF" Version="2024.3.0" />'
    assert _generated(tmp_path, 310, pdf, name="small")[:2] == ("512Mi", "1Gi")     # native-rendering-memory raises
    assert _generated(tmp_path, 900, pdf, name="large")[:2] == ("1152Mi", "1856Mi")  # never lowered to 1Gi
