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
