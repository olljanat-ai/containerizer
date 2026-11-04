"""The worker's metrics (metrics.py)."""
from containerizer import metrics as m


def test_sandbox_connection_from_the_status_file(tmp_path):
    f = tmp_path / "sandbox-status"
    assert m.sandbox_metrics(str(f)) == []                       # not an appliance
    f.write_text("state=no-repository\nat=1793787000\ndetail=CZ_SANDBOX_GIT_URL is empty in /etc/containerizer/sandbox.env\n")
    r = m.Registry()
    r.collectors.append(lambda: m.sandbox_metrics(str(f)))
    out = r.render()
    assert 'containerizer_sandbox_connection{state="no-repository",detail="CZ_SANDBOX_GIT_URL is empty in ' \
           '/etc/containerizer/sandbox.env"} 1' in out
    assert 'containerizer_sandbox_connection{state="connected",detail=""} 0' in out
    assert "containerizer_sandbox_connection_checked_timestamp_seconds 1793787000" in out
