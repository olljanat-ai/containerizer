"""Builds and runs of scanned repositories are isolated from the appliance (issue #255,
docs/appliance-admin.md#builds-of-scanned-code): no host network for builds and scanner containers, and the firewall keeps Docker's
bridges (where builds and verification runs live) away from the appliance's own services and the k3s networks."""
from containerizer import imagescan, verify


def _clear(monkeypatch):
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
              "CONTAINERIZER_BUILD_HOST_NETWORK", "CONTAINERIZER_CA_BUNDLE"):
        monkeypatch.delenv(k, raising=False)


def test_builds_never_get_the_host_network_by_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:3128")
    args = verify._build_env_args()
    assert "--network" not in args and "host" not in args
    assert "HTTPS_PROXY=http://127.0.0.1:3128" in args          # the proxy is still passed on
    assert "--network" not in imagescan._docker_tool_args()


def test_host_network_only_when_a_developer_opts_in(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://localhost:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://localhost:3128")
    monkeypatch.setenv("CONTAINERIZER_BUILD_HOST_NETWORK", "1")
    args = verify._build_env_args()
    assert args[args.index("--network") + 1] == "host"
    assert "host" in imagescan._docker_tool_args()
    monkeypatch.setenv("CONTAINERIZER_BUILD_HOST_NETWORK", "0")
    assert "--network" not in verify._build_env_args()


def test_plain_http_proxy_alone_does_not_break_the_build_args(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:3128")
    args = verify._build_env_args()
    assert "HTTP_PROXY=http://127.0.0.1:3128" in args and "--network" not in args


def _rendered():
    from containerizer.sysagent import render
    system = {"rules": [{"host": "api.nuget.org", "ports": ["tcp/443"]}]}
    return render(system, {"mode": "enforce", "rules": []}, ["10.0.0.1"])[0]


def _chain(nft: str, name: str) -> list[str]:
    body = nft.split(f"chain {name} {{")[1].split("\n  }")[0]
    return [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_docker_bridges_reach_only_dns_on_the_host():
    rules = _chain(_rendered(), "input")
    drop = rules.index('iifname { "docker0", "br-*" } drop')
    dns = next(i for i, r in enumerate(rules) if "th dport 53 accept" in r)
    api = next(i for i, r in enumerate(rules) if "6443" in r)
    assert dns < drop < api                         # DNS before the drop, the k3s API after it
    assert '"docker0"' not in rules[api] and '"cni0"' in rules[api]
    assert not any("1433" in r or "5000" in r or "3000" in r for r in rules)   # no appliance service is opened


def test_docker_bridges_never_reach_the_k3s_networks():
    rules = _chain(_rendered(), "forward")
    assert "ip saddr { 172.16.0.0/12 } ip daddr { 10.42.0.0/16, 10.43.0.0/16 } drop" in rules
    assert "ip saddr { 10.42.0.0/16, 10.43.0.0/16 } ip daddr { 172.16.0.0/12 } drop" in rules
    # no blanket accept between the k3s and the Docker networks any more
    assert not any("ip saddr { 10.42.0.0/16, 10.43.0.0/16, 172.16.0.0/12 }" in r for r in rules)
    # and what is left goes through the egress allow-list
    assert rules[-1] == "jump egress"


def test_docker_daemon_defaults_to_no_new_privileges():
    import json
    from pathlib import Path
    cfg = json.loads((Path(__file__).resolve().parent.parent / "appliance/rootfs/etc/docker/daemon.json").read_text())
    assert cfg["no-new-privileges"] is True


# --------------------------------------------------------------------------- Docker socket guard

import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from containerizer import dockerguard as dg  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
UNITS = ROOT / "appliance/rootfs/usr/lib/systemd/system"


def _cfg(tmp_path):
    (tmp_path / "work").mkdir(exist_ok=True)
    return dg.Config(bind_roots=[str(tmp_path / "work")], bind_files=[])


def _create(hc: dict, tmp_path, **top):
    body = json.dumps({"Image": "busybox", "HostConfig": hc, **top}).encode()
    return json.loads(dg.check_body("create", body, _cfg(tmp_path)))


@pytest.mark.parametrize("hc", [
    {"Privileged": True}, {"privileged": True},                 # Go matches JSON names case-insensitively
    {"NetworkMode": "host"}, {"NetworkMode": "container:cz-mssql"}, {"PidMode": "host"}, {"IpcMode": "host"},
    {"UTSMode": "host"}, {"UsernsMode": "host"}, {"CgroupnsMode": "host"},
    {"CapAdd": ["SYS_ADMIN"]}, {"CapAdd": ["CAP_NET_ADMIN"]}, {"CapAdd": ["ALL"]},
    {"Devices": [{"PathOnHost": "/dev/kmsg"}]}, {"DeviceRequests": [{"Count": -1}]}, {"VolumesFrom": ["cz-mssql"]},
    {"SecurityOpt": ["seccomp=unconfined"]}, {"SecurityOpt": ["apparmor:unconfined"]},
    {"SecurityOpt": ["label=disable"]}, {"SecurityOpt": ["no-new-privileges=false"]},
    {"MaskedPaths": []}, {"Sysctls": {"kernel.core_pattern": "|/bin/sh"}}, {"CgroupParent": "/"},
    {"Runtime": "nvidia"}, {"Binds": ["/:/host"]}, {"Binds": ["/var/run/docker.sock:/s"]},
    {"Mounts": [{"Type": "bind", "Source": "/etc", "Target": "/e"}]},
    {"Mounts": [{"Type": "volume", "Target": "/v", "VolumeOptions": {"DriverConfig": {"Name": "local",
                 "Options": {"device": "/", "o": "bind"}}}}]},
    {"PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}}, {"PublishAllPorts": True},
])
def test_guard_refuses_containers_that_reach_the_host(hc, tmp_path):
    with pytest.raises(dg.Denied):
        _create(hc, tmp_path)


def test_guard_refuses_duplicate_fields_and_host_endpoints(tmp_path):
    raw = b'{"Image":"busybox","HostConfig":{"Privileged":false,"privileged":true}}'
    with pytest.raises(dg.Denied):
        dg.check_body("create", raw, _cfg(tmp_path))
    with pytest.raises(dg.Denied):
        _create({}, tmp_path, NetworkingConfig={"EndpointsConfig": {"host": {}}})


def test_guard_allows_what_verification_and_the_gate_use_and_labels_it(tmp_path):
    work = tmp_path / "work" / "fs"
    work.mkdir(parents=True)
    out = _create({"CapDrop": ["ALL"], "CapAdd": ["NET_BIND_SERVICE"], "SecurityOpt": ["no-new-privileges"],
                   "ReadonlyRootfs": True, "Binds": [f"{work}:/app/data:rw"], "Memory": 768 << 20,
                   "Tmpfs": {"/tmp": "rw,mode=1777"}, "Sysctls": {"net.ipv4.ip_unprivileged_port_start": "0"},
                   "ExtraHosts": ["sql01.corp.local:127.0.0.1"], "MaskedPaths": None,
                   "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "40001"}]}},
                  tmp_path, Labels={"a": "b"})
    assert out["Labels"] == {"a": "b", dg.OWNER_LABEL: dg.OWNER}


def test_guard_resolves_symbolic_links_out_of_the_worker_folder(tmp_path):
    cfg = _cfg(tmp_path)
    (tmp_path / "work" / "escape").symlink_to("/")
    assert not dg._source_ok(str(tmp_path / "work" / "escape"), cfg)
    assert not dg._source_ok(str(tmp_path / "work" / ".." / "x"), cfg)
    assert not dg._source_ok(str(tmp_path / "work" / "missing"), cfg)
    assert dg._source_ok(str(tmp_path / "work"), cfg) and dg._source_ok("named-volume", cfg)


@pytest.mark.parametrize("method,target", [
    ("POST", "/v1.47/build?networkmode=host"), ("POST", "/build?networkmode=default&networkmode=host"),
    ("POST", "/build?cgroupparent=/"), ("POST", "/plugins/pull?remote=x"), ("POST", "/v1.47/swarm/init"),
    ("POST", "/services/create"), ("POST", "/networks/create"), ("POST", "/networks/bridge/connect"),
    ("POST", "/containers/prune"), ("POST", "/v1.47/containers%2Fcreate/../create"),
    ("POST", "/containers//create"), ("POST", "/commit"),
])
def test_guard_refuses_calls(method, target):
    with pytest.raises(dg.Denied):
        dg.decide(method, target)


def test_guard_routes_calls_on_one_container_through_the_owner_check():
    assert dg.decide("GET", "/v1.47/containers/cz-mssql/json").owned == "cz-mssql"
    assert dg.decide("POST", "/containers/abc/exec").body == "exec"
    assert dg.decide("GET", "/containers/abc/archive?path=/etc").owned == "abc"
    assert dg.decide("POST", "/commit?container=cz-mssql&repo=x").owned == "cz-mssql"
    assert dg.decide("POST", "/v1.47/containers/create?name=x").body == "create"
    assert dg.decide("POST", "/build?networkmode=default").owned is None
    assert dg.decide("POST", "/session").upgrade and dg.decide("POST", "/grpc").upgrade
    assert dg.decide("GET", "/containers/json").owned is None
    assert dg.owned({"Config": {"Labels": {dg.OWNER_LABEL: dg.OWNER}}})
    assert not dg.owned({"Config": {"Labels": None}})


def test_appliance_wires_the_worker_to_the_guard():
    sock = (UNITS / "containerizer-docker-guard.socket").read_text()
    assert "ListenStream=/run/containerizer/docker-guard.sock" in sock and "SocketGroup=containerizer" in sock
    assert "SocketMode=0660" in sock
    svc = (UNITS / "containerizer-docker-guard.service").read_text()
    assert "User=cz-dockerguard" in svc and "SupplementaryGroups=docker" in svc and "PrivateNetwork=yes" in svc
    assert "--bind-root /var/lib/containerizer/worker --bind-root /var/lib/containerizer/refactor" in svc
    sysusers = (ROOT / "appliance/rootfs/usr/lib/sysusers.d/containerizer.conf").read_text()
    assert "m containerizer docker" not in sysusers and "m cz-dockerguard docker" in sysusers
    dockerfile = (ROOT / "appliance/Dockerfile").read_text()
    assert "containerizer-docker-guard.socket" in dockerfile.split("systemctl enable", 1)[1].split("\n\n", 1)[0]
    for f in ("cz-worker", "cz-llm-queue"):
        assert "export CONTAINERIZER_BUILD_HOST_NETWORK=0" in (ROOT / "appliance/rootfs/usr/lib/containerizer/bin" / f).read_text()
    cfg = json.loads((ROOT / "appliance/rootfs/etc/docker/daemon.json").read_text())
    assert cfg["builder"]["entitlements"] == {"network-host": False, "security-insecure": False}


def test_image_scanner_mounts_the_socket_the_worker_uses(monkeypatch):
    from containerizer import imagescan
    monkeypatch.setenv("DOCKER_HOST", "unix:///run/containerizer/docker-guard.sock")
    assert "/run/containerizer/docker-guard.sock:/var/run/docker.sock" in imagescan._docker_tool_args()
    monkeypatch.delenv("DOCKER_HOST")
    assert "/var/run/docker.sock:/var/run/docker.sock" in imagescan._docker_tool_args()


def _docker_up() -> bool:
    return bool(shutil.which("docker")) and subprocess.run(
        ["docker", "info"], capture_output=True, env={k: v for k, v in os.environ.items() if k != "DOCKER_HOST"}).returncode == 0


@pytest.mark.skipif(not _docker_up(), reason="needs a Docker daemon")
def test_guard_in_front_of_a_real_docker(tmp_path):
    """The real Docker CLI through the guard: builds and hardened runs work, escapes and other containers do not."""
    sock, work = tmp_path / "g.sock", tmp_path / "work"
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "DOCKER_HOST"}
    p = subprocess.Popen(["python", "-m", "containerizer.dockerguard", "--listen", str(sock), "--bind-root", str(work)],
                         cwd=ROOT, env=env)
    other = f"cz-guard-test-{os.getpid()}"
    try:
        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.1)
        g = {**env, "DOCKER_HOST": f"unix://{sock}"}
        if subprocess.run(["docker", "image", "inspect", "busybox"], env=env, capture_output=True).returncode:
            if subprocess.run(["docker", "pull", "-q", "busybox"], env=env, capture_output=True).returncode:
                pytest.skip("busybox cannot be pulled")
        subprocess.run(["docker", "run", "-d", "--name", other, "busybox", "sleep", "60"], env=env, check=True,
                       capture_output=True)

        def run(*a):
            return subprocess.run(["docker", *a], env=g, capture_output=True, text=True, timeout=120)
        ok = run("run", "--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                 "-v", f"{work}:/w", "-p", "127.0.0.1::80", "busybox", "echo", "verified")
        assert ok.returncode == 0 and "verified" in ok.stdout, ok.stderr
        for bad in (["run", "--rm", "--privileged", "busybox", "true"], ["run", "--rm", "--network", "host", "busybox", "true"],
                    ["run", "--rm", "-v", "/:/h", "busybox", "true"], ["exec", other, "env"], ["inspect", other],
                    ["rm", "-f", other]):
            r = run(*bad)
            assert r.returncode != 0 and "containerizer docker guard" in r.stderr, (bad, r.stderr)
        ctx = tmp_path / "ctx"
        ctx.mkdir()
        (ctx / "Dockerfile").write_text("FROM busybox\nRUN echo built\n")
        b = run("build", "-q", str(ctx))
        assert b.returncode == 0, b.stderr
        legacy = subprocess.run(["docker", "build", "--network", "host", "-q", str(ctx)], env={**g, "DOCKER_BUILDKIT": "0"},
                                capture_output=True, text=True, timeout=120)
        assert legacy.returncode != 0 and "host network" in legacy.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", other], env=env, capture_output=True)
        p.terminate()
        p.wait(10)


def test_docker_daemon_itself_fetches_nothing_from_the_appliance():
    """ADD <url> and remote build contexts are fetched by dockerd on the host's network: its own nftables table."""
    dropin = (ROOT / "appliance/rootfs/etc/systemd/system/docker.service.d/10-containerizer.conf").read_text()
    assert "ExecStartPost=-/usr/lib/containerizer/bin/cz-docker-egress" in dropin
    script = (ROOT / "appliance/rootfs/usr/lib/containerizer/bin/cz-docker-egress").read_text()
    assert 'socket cgroupv2 level 2 "$cg" fib daddr type local tcp dport != { 53, 5000 } drop' in script
    assert 'cg="system.slice/docker.service"' in script and "10.43.0.0/16" in script
    assert os.access(ROOT / "appliance/rootfs/usr/lib/containerizer/bin/cz-docker-egress", os.X_OK)
