"""Builds and runs of scanned repositories are isolated from the appliance (issue #255, docs/appliance.md
"Builds of scanned code"): no host network for builds and scanner containers, and the firewall keeps Docker's
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
