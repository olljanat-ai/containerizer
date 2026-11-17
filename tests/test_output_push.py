"""Runs of different organization scans pushing to one output repository (worker.py runs them side by side): a
rejected push takes the other run's commits, keeps this run's version of a file both changed, regenerates the shared
index from the combined tree, and pushes again; on one worker the pushes go one at a time."""
import subprocess
import threading

from containerizer import fluxhook
from containerizer import org as orgmod


def _git(*a, cwd=None):
    return subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True).stdout


def _clone(tmp_path, bare, name):
    d = tmp_path / name
    _git("clone", "-q", str(bare), str(d))
    o = orgmod.OrgOptions(provider="github", org=name, registry="r", output_dir=str(d))
    out = orgmod.Output(o, tmp_path / f"w-{name}")
    # the shared index every run regenerates from the tree (as write_sandbox does for sandbox/)
    out.refresh = lambda: (d / "index.txt").write_text(
        "".join(f"{p.name}\n" for p in sorted(d.iterdir()) if p.is_dir() and p.name != ".git"))
    return d, out


def test_parallel_runs_push_to_one_output_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(fluxhook, "notify", lambda reason="": None)
    bare = tmp_path / "out.git"
    _git("init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _git("clone", "-q", str(bare), str(seed))
    (seed / "index.txt").write_text("")
    _git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init", cwd=seed)
    _git("add", "-A", cwd=seed)
    _git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "index", cwd=seed)
    _git("push", "-q", "origin", "HEAD:main", cwd=seed)
    a, out_a = _clone(tmp_path, bare, "acme")
    b, out_b = _clone(tmp_path, bare, "contoso")

    # one after the other, the second clone behind: its push is rejected, it takes acme's commit and the index lists both
    (a / "acme").mkdir()
    (a / "acme" / "app.yaml").write_text("a\n")
    out_a.refresh()
    assert out_a.commit("containerizer: acme/shop deployed")
    (b / "contoso").mkdir()
    (b / "contoso" / "app.yaml").write_text("c\n")
    out_b.refresh()                                     # its index lists only contoso: a conflict with acme's
    assert out_b.commit("containerizer: contoso/web deployed")
    head = tmp_path / "check"
    _git("clone", "-q", str(bare), str(head))
    assert (head / "acme" / "app.yaml").exists() and (head / "contoso" / "app.yaml").exists()
    assert (head / "index.txt").read_text() == "acme\ncontoso\n"
    log = _git("log", "--format=%s", cwd=head).splitlines()
    assert log[:2] == ["containerizer: contoso/web deployed", "containerizer: acme/shop deployed"]

    # side by side: many commits from two threads, none lost
    errors = []

    def run(d, out, name):
        try:
            for i in range(6):
                (d / name).mkdir(exist_ok=True)
                (d / name / f"r{i}.yaml").write_text(f"{i}\n")
                out.refresh()
                out.commit(f"{name} {i}")
        except Exception as ex:  # noqa: BLE001
            errors.append(ex)
    ts = [threading.Thread(target=run, args=(a, out_a, "acme")), threading.Thread(target=run, args=(b, out_b, "contoso"))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    assert not errors
    _git("pull", "-q", cwd=head)
    assert sorted(p.name for p in (head / "acme").iterdir()) == ["app.yaml"] + [f"r{i}.yaml" for i in range(6)]
    assert sorted(p.name for p in (head / "contoso").iterdir()) == ["app.yaml"] + [f"r{i}.yaml" for i in range(6)]
    assert (head / "index.txt").read_text() == "acme\ncontoso\n"


def test_a_rejected_push_from_another_worker_is_retried(tmp_path, monkeypatch):
    """Not serialized by the lock (another process): the push is rejected, and the run combines and pushes again."""
    monkeypatch.setattr(fluxhook, "notify", lambda reason="": None)
    bare = tmp_path / "out.git"
    _git("init", "-q", "--bare", "-b", "main", str(bare))
    a, out_a = _clone(tmp_path, bare, "acme")
    (a / "x.txt").write_text("1\n")
    assert out_a.commit("first")
    b, out_b = _clone(tmp_path, bare, "contoso")
    (a / "y.txt").write_text("2\n")
    assert out_a.commit("second")                       # b is behind now
    (b / "x.txt").write_text("from contoso\n")          # both changed x.txt: this side's version wins
    assert out_b.commit("third")
    head = tmp_path / "check"
    _git("clone", "-q", str(bare), str(head))
    assert (head / "x.txt").read_text() == "from contoso\n" and (head / "y.txt").read_text() == "2\n"


def test_a_change_the_other_run_already_pushed_is_not_an_empty_amend(tmp_path, monkeypatch):
    """Two runs scanned the same repository (Scan now next to a full run) and wrote the same files: the second
    push's commit becomes empty on top of the first; it is dropped, never amended into the other run's commit."""
    monkeypatch.setattr(fluxhook, "notify", lambda reason="": None)
    bare = tmp_path / "out.git"
    _git("init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _git("clone", "-q", str(bare), str(seed))
    (seed / "index.txt").write_text("")
    _git("add", "-A", cwd=seed)
    _git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "index", cwd=seed)
    _git("push", "-q", "origin", "HEAD:main", cwd=seed)
    a, out_a = _clone(tmp_path, bare, "one")
    b, out_b = _clone(tmp_path, bare, "two")
    for d in (a, b):
        (d / "acme").mkdir()
        (d / "acme" / "app.yaml").write_text("same\n")
    (a / "other").mkdir()                                # run 1 also deployed another app: run 2's index is stale
    (a / "other" / "app.yaml").write_text("o\n")
    out_a.refresh()
    assert out_a.commit("containerizer: acme/shop deployed (run 1)")
    out_b.refresh()
    assert out_b.commit("containerizer: acme/shop deployed (run 2)")       # no error: nothing left to push
    head = tmp_path / "check"
    _git("clone", "-q", str(bare), str(head))
    assert _git("log", "--format=%s", cwd=head).splitlines() == ["containerizer: acme/shop deployed (run 1)", "index"]
    assert (head / "index.txt").read_text() == "acme\nother\n"


def test_a_file_one_run_deleted_and_the_other_changed_is_kept(tmp_path, monkeypatch):
    """A scan pushed next to a sandbox health run (which rewrote HEALTH.md): the scan's commit no longer has it.
    -X cannot resolve a modify/delete conflict; the changed file is kept and the push goes through."""
    monkeypatch.setattr(fluxhook, "notify", lambda reason="": None)
    bare = tmp_path / "out.git"
    _git("init", "-q", "--bare", "-b", "main", str(bare))
    a, out_a = _clone(tmp_path, bare, "health")
    (a / "HEALTH.md").write_text("old\n")
    (a / "app.yaml").write_text("1\n")
    assert out_a.commit("first")
    b, out_b = _clone(tmp_path, bare, "scan")
    (a / "HEALTH.md").write_text("new\n")
    assert out_a.commit("containerizer: sandbox health")
    (b / "HEALTH.md").unlink()
    (b / "app.yaml").write_text("2\n")
    assert out_b.commit("containerizer: scan")
    head = tmp_path / "check"
    _git("clone", "-q", str(bare), str(head))
    assert (head / "HEALTH.md").read_text() == "new\n" and (head / "app.yaml").read_text() == "2\n"


def test_write_sandbox_keeps_the_health_report(tmp_path):
    sb = tmp_path / orgmod.SANDBOX
    sb.mkdir(parents=True)
    (sb / "HEALTH.md").write_text("# health\n")
    (sb / "health.json").write_text("{}\n")
    (sb / "stale.yaml").write_text("x\n")
    orgmod.write_sandbox(tmp_path, "https://git.example.com/out.git", "main")
    assert (sb / "HEALTH.md").read_text() == "# health\n" and (sb / "health.json").read_text() == "{}\n"
    assert not (sb / "stale.yaml").exists()
