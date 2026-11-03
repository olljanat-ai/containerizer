"""kubemg on the appliance (optional, CZ_KUBEMG=true; docs/appliance-admin.md#kubemg): connect the k3s sandbox cluster.

kubemg (https://kubemg.readthedocs.io/) is an audited console and kubectl gateway for Kubernetes clusters. On the
appliance it runs as a container behind Caddy at https://kubemg.<CZ_HOSTNAME>/ (containerizer-kubemg.service), and
its agent runs in the sandbox cluster (namespace kubemg-system) and dials back to that URL; no port is opened.

`sandbox()` (containerizer-kubemg-sandbox.service, after kubemg and k3s) registers the sandbox cluster through kubemg's
API in agent mode and applies the agent's manifest to k3s, with a host alias that sends the kubemg name to the node
(the sandbox's DNS filter does not resolve it; pods reach the appliance on 443 like any client). It signs in as the
bootstrap administrator with the generated password, which kubemg's setup wizard has the administrator change at
the first sign-in: so it registers once, on the first start, and later only checks that the agent is there.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

API = "http://127.0.0.1:8444/api/v1"
CLUSTER = "sandbox"
NAMESPACE = "kubemg-system"
KUBECTL = ["/usr/bin/k3s", "kubectl"]


class KubemgError(Exception):
    pass


def _call(method: str, path: str, token: str | None = None, body: dict | None = None, raw: bool = False,
          timeout: int = 30):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        raise KubemgError(f"{method} {path}: HTTP {e.code}: {e.read()[:300].decode(errors='replace')}") from None
    return data.decode() if raw else json.loads(data or b"{}")


def wait_up(seconds: int = 600, call=_call) -> None:
    end = time.monotonic() + seconds
    while True:
        try:
            call("POST", "/auth/login", body={"username": "", "password": ""})
            return
        except KubemgError:
            return                      # it answers (401): up
        except OSError:
            if time.monotonic() > end:
                raise KubemgError(f"kubemg did not answer on {API} in {seconds} s") from None
            time.sleep(5)


def login(username: str, password: str, call=_call) -> str | None:
    """A session token, or None when the password no longer works (changed in kubemg's setup wizard)."""
    try:
        out = call("POST", "/auth/login", body={"username": username, "password": password})
    except KubemgError as e:
        if "HTTP 401" in str(e):
            return None
        raise
    if not out.get("token"):           # a second factor is owed: not for an automated sign-in
        return None
    return out["token"]


def ensure_cluster(token: str, call=_call) -> dict:
    """The sandbox cluster in kubemg (agent mode), created when missing."""
    for c in call("GET", "/clusters", token).get("clusters") or []:
        if c.get("name") == CLUSTER:
            return c
    return call("POST", "/clusters", token, {"name": CLUSTER, "environment": "dev", "connection_mode": "agent"})


def with_host_alias(manifest: str, host: str, ip: str) -> str:
    """The agent's manifest with hostAliases on its Deployment: <host> is the node's address."""
    docs = [d for d in yaml.safe_load_all(manifest) if d]
    found = False
    for d in docs:
        if d.get("kind") == "Deployment" and d.get("metadata", {}).get("name") == "kubemg-agent":
            spec = d["spec"]["template"]["spec"]
            spec["hostAliases"] = [a for a in spec.get("hostAliases") or [] if host not in a.get("hostnames", [])] + [
                {"ip": ip, "hostnames": [host]}]
            found = True
    if not found:
        raise KubemgError("the agent manifest has no kubemg-agent Deployment")
    return yaml.safe_dump_all(docs, sort_keys=False)


def _kubectl(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([*KUBECTL, *args], input=stdin, capture_output=True, text=True, timeout=300)


def agent_installed() -> bool:
    return _kubectl("-n", NAMESPACE, "get", "deployment", "kubemg-agent").returncode == 0


def node_ip() -> str:
    r = _kubectl("get", "nodes", "-o", "jsonpath={.items[0].status.addresses[?(@.type==\"InternalIP\")].address}")
    ip = r.stdout.strip().split()[0] if r.returncode == 0 and r.stdout.strip() else ""
    if not ip:
        raise KubemgError(f"the sandbox node's address is not known yet: {r.stderr.strip()[:200]}")
    return ip


def sandbox(host: str, password: str, username: str = "admin", call=_call, installed=agent_installed,
            apply=None, ip=node_ip, log=print) -> str:
    """Register the sandbox cluster and install kubemg's agent in it. Returns what it did."""
    if installed():
        return "the kubemg agent is installed in the sandbox cluster"
    wait_up(call=call)
    token = login(username, password, call)
    if token is None:
        return ("kubemg's administrator password was changed (its setup wizard asks for that): the sandbox cluster was "
                "not registered by the appliance. Register it in kubemg (Admin → Clusters → Add, agent mode) and apply "
                "its manifest with `k3s kubectl apply -f`")
    c = ensure_cluster(token, call)
    manifest = call("GET", f"/clusters/{int(c['id'])}/kustomize?format=yaml", token, raw=True)
    doc = with_host_alias(manifest, host, ip())
    if apply is None:
        r = _kubectl("apply", "-f", "-", stdin=doc)
        if r.returncode != 0:
            raise KubemgError(f"kubectl apply: {r.stderr.strip()[:500]}")
    else:
        apply(doc)
    log(f"kubemg: cluster {CLUSTER} (#{int(c['id'])}) registered; its agent dials https://{host}")
    return f"the sandbox cluster is registered in kubemg as {CLUSTER} and its agent is installed"


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="python -m containerizer.kubemg")
    p.add_argument("command", choices=["sandbox"])
    p.add_argument("--host", required=True, help="kubemg's DNS name (the agent dials https://<host>)")
    p.add_argument("--password-file", required=True)
    a = p.parse_args(argv)
    try:
        with open(a.password_file) as f:
            pw = f.read().strip()
        print(sandbox(a.host, pw))
        return 0
    except (KubemgError, OSError) as e:
        print(f"kubemg: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
