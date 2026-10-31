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

step "secret store: External Secrets Operator, per-namespace access"
wait_for 900 "External Secrets Operator" k3s kubectl -n external-secrets wait --for=condition=Available deploy --all --timeout=10s
systemctl start containerizer-sandbox.service
wait_for 300 "ClusterSecretStore app-secrets" k3s kubectl get clustersecretstore app-secrets
test "$(k3s kubectl get ns containerizer-secrets -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" = restricted
k() { k3s kubectl "$@"; }
. /usr/lib/containerizer/lib/secret-store.sh
cz_store_put ci-a--web 'ConnectionStrings__Db=Server=db;Password=ci-only'
cz_store_put ci-a--web --manager ci-other Extra=1          # a second writer keeps the first one's keys
for ns in ci-a ci-b; do k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null; done
cz_store_grant ci-a ci-a--web
cz_store_grant ci-b ci-b--web
for ns in ci-a ci-b; do k apply -f - >/dev/null <<YAML
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: web-secrets, namespace: $ns}
spec:
  refreshInterval: 1m
  secretStoreRef: {kind: ClusterSecretStore, name: app-secrets}
  target: {name: web-secrets}
  data:
    - {secretKey: ConnectionStrings__Db, remoteRef: {key: ci-a--web, property: ConnectionStrings__Db}}
YAML
done
wait_for 300 "ci-a reads its own key" sh -c 'k3s kubectl -n ci-a get secret web-secrets -o jsonpath={.data.ConnectionStrings__Db} | base64 -d | grep -q ci-only'
test "$(k3s kubectl -n containerizer-secrets get secret ci-a--web -o jsonpath={.data.Extra} | base64 -d)" = 1
sleep 30
if k3s kubectl -n ci-b get secret web-secrets >/dev/null 2>&1; then echo "ci-b must not read ci-a's key" >&2; exit 1; fi
k3s kubectl -n ci-b get externalsecret web-secrets -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' \
  | grep -q SecretSyncedError
k delete namespace ci-a ci-b --wait=false
k -n containerizer-secrets delete secret/ci-a--web role/app-secrets-reader-ci-a rolebinding/app-secrets-reader-ci-a \
  role/app-secrets-reader-ci-b rolebinding/app-secrets-reader-ci-b >/dev/null 2>&1 || true

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

step "SBOM attached to a pushed image with ORAS (as the scan worker does it)"
oras version
digest=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' localhost:5000/ci/registry:1 \
  | sed -n 's#^localhost:5000/ci/registry@##p' | head -1)
test -n "$digest"
install -d -m 0700 -o containerizer -g containerizer /var/lib/containerizer/worker/ci
runuser -u containerizer -- env HOME=/var/lib/containerizer/worker $PY - "$digest" <<'PY'
import json, sys, pathlib
from containerizer import sbom
f = pathlib.Path("/var/lib/containerizer/worker/ci/sbom.cdx.json")
f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}))
r = sbom.attach("localhost:5000/ci/registry:1", sys.argv[1], f)
print(r)
assert r == "attached", r
PY
oras discover --format json "localhost:5000/ci/registry@$digest" | grep -q 'application/vnd.cyclonedx+json'
rm -rf /var/lib/containerizer/worker/ci

step "dev database uploads: the web UI stores them, the scan worker reads them"
test "$(stat -c '%U:%G %a' /var/lib/containerizer/devdb)" = "cz-web:containerizer 2750"
for u in containerizer-web containerizer-worker; do
  tr '\0' '\n' < "/proc/$(systemctl show -p MainPID --value $u.service)/environ" \
    | grep -qx CONTAINERIZER_DEV_DB_DIR=/var/lib/containerizer/devdb
done
# as the web UI, inside its sandbox (ProtectSystem=strict: only this folder and the request folder are writable)
web=$(systemctl show -p MainPID --value containerizer-web.service)
nsenter --target "$web" --mount --setuid 901 --setgid 901 -- $PY -c '
import os, pathlib
from containerizer import devdb
s = devdb.Settings.from_env(os.environ | {"CONTAINERIZER_DEV_DB_DIR": "/var/lib/containerizer/devdb"})
up = devdb.Upload(); up.path = s.directory / ".upload-ci"; up.path.write_bytes(b"TAPE ci"); up.sha256 = "0" * 64
print(devdb.store(s, up, "sqlserver"))'
runuser -u containerizer -- grep -q TAPE "/var/lib/containerizer/devdb/$(printf '0%.0s' $(seq 64)).bak"
rm -f /var/lib/containerizer/devdb/0*.bak

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
