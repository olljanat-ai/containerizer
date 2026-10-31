#!/bin/bash
# Runs inside the booted appliance (as root, over SSH) in CI: the firewall, the DNS filter, the services,
# the sandbox cluster, the local registry and a change of the egress allow-list through the system agent.
set -euo pipefail
PY=/usr/lib/containerizer/venv/bin/python
step() { echo; echo "=== $*"; }
wait_for() {  # seconds, description, command...
  local t=$1 what=$2; shift 2
  local end=$((SECONDS + t))
  until "$@" >/dev/null 2>&1; do
    [ $SECONDS -lt $end ] || { echo "timed out after ${t}s: $what" >&2; return 1; }
    sleep 10
  done
  echo "ok: $what"
}

step "OS"
. /etc/os-release; echo "IMAGE_TAG=$IMAGE_TAG"
ls /run/elemental/
test -f /run/elemental/active_mode

step "firewall"
nft list table inet cz_firewall > /tmp/fw.txt
grep -q 'tcp dport { 22, 443 } accept' /tmp/fw.txt
wait_for 120 "DNS filter" systemctl is-active --quiet containerizer-dns.service

step "DNS filter: allowed names resolve, others are refused"
if ! wait_for 120 "ghcr.io resolves" getent ahostsv4 ghcr.io; then
  ls -l /etc/resolv.conf; cat /etc/resolv.conf; ip addr show cz-dns; ss -lunp 'sport = :53'
  cat /run/systemd/resolve/resolv.conf; journalctl -b -u containerizer-dns --no-pager | tail -20
  ls -la /etc/tmpfiles.d /usr/lib/tmpfiles.d | grep -i resolv; journalctl -b -u systemd-tmpfiles-setup --no-pager | tail -20
  exit 1
fi
getent ahostsv4 ghcr.io
if getent ahostsv4 example.com; then echo "example.com must not resolve" >&2; exit 1; fi
step "egress: allowed name on 443 goes out, anything else does not"
test "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 https://ghcr.io/v2/)" = 401
if curl -sS -o /dev/null --max-time 8 https://1.1.1.1/; then echo "1.1.1.1 must be blocked" >&2; exit 1; fi
if curl -sS -o /dev/null --max-time 8 http://ghcr.io/; then echo "ghcr.io:80 must be blocked" >&2; exit 1; fi

step "services"
wait_for 2400 "SQL Server, schema and web UI" curl -fsS http://127.0.0.1:8080/healthz
wait_for 600 "registry" curl -fsS http://127.0.0.1:5000/v2/
wait_for 900 "Prometheus" curl -fsS http://127.0.0.1:9090/-/ready
wait_for 900 "Grafana" curl -fsS http://127.0.0.1:3000/grafana/api/health
wait_for 300 "Caddy" curl -fsSk https://127.0.0.1/healthz --resolve "$(hostname):443:127.0.0.1" -H "Host: $(hostname)"
systemctl is-active containerizer-db-init.service containerizer-web.service containerizer-mssql.service \
  containerizer-registry.service containerizer-prometheus.service containerizer-grafana.service caddy.service \
  docker.service k3s.service ssh.service

step "web UI runs as its own user without privileges"
test "$(ps -o user= -p "$(systemctl show -p MainPID --value containerizer-web.service)")" = cz-web
step "secrets are root-only"
test "$(stat -c %a /etc/containerizer/secrets)" = 700

step "sandbox cluster"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
wait_for 900 "k3s node Ready" sh -c 'k3s kubectl get nodes --no-headers | grep -qw Ready'
wait_for 900 "Flux controllers" k3s kubectl -n flux-system wait --for=condition=Available deploy --all --timeout=10s
wait_for 600 "CoreDNS resolves through the filter" k3s kubectl -n kube-system wait --for=condition=Available deploy/coredns --timeout=10s

step "local registry: push from Docker, pull from k3s"
docker image ls
src=$(docker image ls --format '{{.ID}}' docker.io/library/registry | head -1)
docker tag "$src" localhost:5000/ci/registry:1
docker push localhost:5000/ci/registry:1
k3s crictl pull localhost:5000/ci/registry:1
k3s kubectl run ci-registry --image=localhost:5000/ci/registry:1 --restart=Never --command -- /bin/registry --version
wait_for 300 "pod from the local registry" sh -c 'k3s kubectl get pod ci-registry -o jsonpath={.status.phase} | grep -q Succeeded'
k3s kubectl logs ci-registry
k3s kubectl delete pod ci-registry --wait=false

step "egress change through the system agent (as the Firewall page does it)"
$PY - <<'PY'
import json, time, pathlib
d = pathlib.Path("/run/containerizer/system")
st = json.loads((d / "status.json").read_text())
rules = st["egress"]["rules"] + [{"host": "example.com", "ports": ["tcp/443"], "note": "ci"}]
(d / "requests" / ".ci.tmp").write_text(json.dumps({"action": "egress", "mode": "enforce", "rules": rules,
                                                     "requested_by": "ci", "requested_by_name": "CI"}))
(d / "requests" / ".ci.tmp").rename(d / "requests" / f"{int(time.time()*1000)}-ci.json")
PY
wait_for 120 "example.com allowed" getent ahostsv4 example.com
wait_for 60 "example.com reachable on 443" curl -sS -o /dev/null --max-time 15 https://example.com/
grep -q '"by": "ci"' /var/lib/containerizer/system/egress-history.jsonl
step "refused names are reported"
getent ahostsv4 not-allowed.example.org || true
$PY -m containerizer.sysagent status
$PY -c "import json; e=json.load(open('/run/containerizer/system/status.json'))['egress']; print(e['denied_names'][:5]); assert any(d['name']=='not-allowed.example.org' for d in e['denied_names'])"

step "boot assessment"
systemctl status elemental-boot-assessment.service --no-pager || true
$PY -m containerizer.sysagent health

step "no failed units"
systemctl --failed --no-legend
test -z "$(systemctl --failed --no-legend)"
echo "ALL CHECKS PASSED"
