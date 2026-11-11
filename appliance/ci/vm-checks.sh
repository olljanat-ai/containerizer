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
# by name, so the TLS handshake carries the SNI Caddy has a certificate for (none for 127.0.0.1)
wait_for 300 "Caddy" curl -fsSk "https://$(hostname)/healthz" --resolve "$(hostname):443:127.0.0.1"
systemctl is-active containerizer-db-init.service containerizer-web.service containerizer-mssql.service \
  containerizer-registry.service containerizer-prometheus.service containerizer-grafana.service caddy.service \
  containerizer-openbao.service docker.service k3s.service ssh.service containerizer-root-password.service containerizer-root-password.path

step "web UI runs as its own user without privileges"
test "$(ps -o user= -p "$(systemctl show -p MainPID --value containerizer-web.service)")" = cz-web
step "root's password was changed and is kept on the persistent partition"
if chage -l root | grep -qi "must be changed"; then echo "root's password is still expired" >&2; exit 1; fi
grep -q '^root:[^!*:]' /etc/containerizer/secrets/root-shadow
test "$(stat -c %a /etc/containerizer/secrets/root-shadow)" = 600
step "secrets are root-only"
test "$(stat -c %a /etc/containerizer/secrets)" = 700

step "sandbox cluster"
# shellcheck disable=SC1091
test "$(. /etc/profile.d/kubeconfig.sh; echo "$KUBECONFIG")" = /etc/rancher/k3s/k3s.yaml
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
wait_for 900 "k3s node Ready" sh -c 'k3s kubectl get nodes --no-headers | grep -qw Ready'
wait_for 900 "Flux controllers" k3s kubectl -n flux-system wait --for=condition=Available deploy --all --timeout=10s
helm version --short
helm list -A >/dev/null   # reaches the cluster with the same kubeconfig
# Grafana's k3s and Flux dashboards: Prometheus reads the cluster with its read-only token (docs/appliance-admin.md#metrics)
wait_for 900 "kube-state-metrics" k3s kubectl -n cz-monitoring wait --for=condition=Available deploy/kube-state-metrics --timeout=10s
wait_for 900 "Prometheus reads k3s and Flux" sh -c 'curl -fsS http://127.0.0.1:9090/api/v1/targets?state=active | python3 -c "
import json, sys
up = {t[\"labels\"][\"job\"] for t in json.load(sys.stdin)[\"data\"][\"activeTargets\"] if t[\"health\"] == \"up\"}
sys.exit(0 if {\"k3s-apiserver\", \"kubelet\", \"kubelet-cadvisor\", \"kube-state-metrics\", \"flux\"} <= up else 1)"'
for d in containerizer-k3s containerizer-flux; do
  curl -fsS "http://127.0.0.1:3000/grafana/api/dashboards/uid/$d" -u "admin:$(cat /etc/containerizer/secrets/grafana-admin)" >/dev/null \
    || { echo "Grafana has no dashboard $d" >&2; exit 1; }
done
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

step "OpenBao: unsealed, admin sign-in on 443, placeholders, values into the store"
# the sandbox job initialises OpenBao (once it has pulled its image and listens), then syncs
wait_for 900 "OpenBao initialised by the sandbox job" sh -c \
  'systemctl start containerizer-sandbox.service; test -s /etc/containerizer/secrets/openbao-sync-token'
test ! -e /etc/containerizer/secrets/openbao-root-token     # revoked and removed once setup is done
$PY -m containerizer.openbao status | grep -q '"sealed": false'
test "$(stat -c '%U %a' /etc/containerizer/secrets/openbao-sync-token)" = "root 400"
url="https://$(hostname)"
login=$(printf '{"password": "%s"}' "$(cat /etc/containerizer/secrets/openbao-admin)" \
  | curl -fsSk --resolve "$(hostname):443:127.0.0.1" -d @- "$url/v1/auth/userpass/login/admin")
tok=$(printf %s "$login" | $PY -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])')
bao() { curl -fsSk --resolve "$(hostname):443:127.0.0.1" -H @<(printf 'X-Vault-Token: %s\n' "$tok") "$@"; }
curl -fsSk --resolve "$(hostname):443:127.0.0.1" "$url/ui/" | grep -q OpenBao
# the value put in the store before is the placeholder's value
bao "$url/v1/apps/data/ci-a/web" | grep -q 'Server=db;Password=ci-only'
printf '{"data": {"ConnectionStrings__Db": "Server=db;Password=from-openbao"}}' | bao -d @- "$url/v1/apps/data/ci-a/web" >/dev/null
systemctl start containerizer-sandbox.service
wait_for 300 "a value saved in OpenBao reaches the app" sh -c \
  'k3s kubectl -n ci-a get secret web-secrets -o jsonpath={.data.ConnectionStrings__Db} | base64 -d | grep -q from-openbao'
bao "$url/v1/sys/policies/acl/app-ci-a" | grep -q 'apps/data/ci-a/'

k delete namespace ci-a ci-b --wait=false
k -n containerizer-secrets delete secret/ci-a--web role/app-secrets-reader-ci-a rolebinding/app-secrets-reader-ci-a \
  role/app-secrets-reader-ci-b rolebinding/app-secrets-reader-ci-b >/dev/null 2>&1 || true

step "local registry: push from Docker, pull from k3s"
docker image ls
# pulled by digest, so listed as "registry" with no tag
src=$(docker image ls --format '{{.Repository}} {{.ID}}' | awk '$1 == "registry" || $1 == "docker.io/library/registry" {print $2; exit}')
[ -n "$src" ] || { echo "no registry image to push" >&2; exit 1; }
docker tag "$src" localhost:5000/ci/registry:1
docker push localhost:5000/ci/registry:1
k3s crictl pull localhost:5000/ci/registry:1
k3s kubectl run ci-registry --image=localhost:5000/ci/registry:1 --restart=Never --command -- /bin/registry --version
wait_for 300 "pod from the local registry" sh -c 'k3s kubectl get pod ci-registry -o jsonpath={.status.phase} | grep -q Succeeded'
k3s kubectl logs ci-registry
k3s kubectl delete pod ci-registry --wait=false

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
up = devdb.Upload(head=b"TAPE ci"); up.path = s.directory / ".upload-ci"; up.path.write_bytes(up.head); up.sha256 = "0" * 64
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
# the refusal reaches the journal a moment after the answer: ask again until the status shows it
refused() {
  getent ahostsv4 not-allowed.example.org || true
  $PY -m containerizer.sysagent status
  $PY -c "import json; e=json.load(open('/run/containerizer/system/status.json'))['egress']; assert any(d['name']=='not-allowed.example.org' for d in e['denied_names'])"
}
wait_for 60 "not-allowed.example.org reported" refused || {
  journalctl -u containerizer-dns.service --no-pager -o cat --grep 'not-allowed|REFUSED' | tail -20
  $PY -c "import json; print(json.load(open('/run/containerizer/system/status.json'))['egress']['denied_names'][:5])"
  exit 1
}

step "built-in LLM: off by default, nothing runs, Hugging Face is not reachable"
fail() { echo "$*" >&2; exit 1; }
if [ "$(systemctl is-enabled containerizer-local-llm@0.service 2>/dev/null)" = enabled ]; then fail "containerizer-local-llm@0 must not be enabled"; fi
for u in containerizer-local-llm@0.service containerizer-local-llm-download.service; do
  if systemctl is-active --quiet "$u"; then fail "$u must not run while the built-in LLM is off"; fi
done
test -z "$(docker ps -aq --filter name='^cz-llm$')" || fail "no cz-llm container while the built-in LLM is off"
if curl -sS -o /dev/null --max-time 5 http://127.0.0.1:8090/health; then fail "nothing may listen on 127.0.0.1:8090"; fi
if getent ahostsv4 huggingface.co; then fail "huggingface.co must not resolve while no model download runs"; fi
worker_env() { tr '\0' '\n' < "/proc/$(systemctl show -p MainPID --value containerizer-worker.service)/environ"; }
worker_env | grep -qx CONTAINERIZER_LOCAL_LLM=/run/containerizer/system/local-llm-status.json
if worker_env | grep -q '^CONTAINERIZER_LLM_BASE_URL='; then fail "the worker must not get an LLM URL from its environment"; fi
$PY -m containerizer.sysagent status
$PY -c "
import json, os
from containerizer import local_llm
s = json.load(open('/run/containerizer/system/local-llm-status.json'))
assert s['enabled'] is False and s['state'] == 'off', s
assert local_llm.worker_settings({'CONTAINERIZER_LOCAL_LLM': '/run/containerizer/system/local-llm-status.json'}) is None"
test ! -e /run/containerizer/local-llm-0.env
# a start while it is off is skipped by its condition, not failed
systemctl start containerizer-local-llm@0.service
test "$(systemctl show -p ConditionResult --value containerizer-local-llm@0.service)" = no
if systemctl is-failed --quiet containerizer-local-llm@0.service; then fail "a skipped start must not fail the unit"; fi
step "built-in LLM: turning it on here is refused by the RAM check (this VM is far below 40 GiB)"
$PY - <<'PY'
import json, time, pathlib
d = pathlib.Path("/run/containerizer/system/requests")
(d / ".ci-llm.tmp").write_text(json.dumps({"action": "local-llm", "do": "enable", "requested_by": "ci", "requested_by_name": "CI"}))
(d / ".ci-llm.tmp").rename(d / f"{int(time.time()*1000)}-ci-llm.json")
PY
llm_refused() {
  $PY -c "import json; s=json.load(open('/run/containerizer/system/local-llm-status.json')); assert s['state'] == 'refused' and 'RAM' in s['message'] and not s['enabled'], s"
}
wait_for 120 "enable request refused" llm_refused
test ! -e /run/containerizer/local-llm-0.env
test ! -e /var/lib/containerizer/llm/Qwen3-Coder-30B-A3B-Instruct-IQ4_XS-4.20bpw.gguf.part
for u in containerizer-local-llm@0.service containerizer-local-llm-download.service; do
  if systemctl is-active --quiet "$u"; then fail "$u started although the request was refused"; fi
done
if getent ahostsv4 huggingface.co; then fail "huggingface.co must stay refused after a refused request"; fi

step "boot assessment"
systemctl status elemental-boot-assessment.service --no-pager || true
$PY -m containerizer.sysagent health

step "egress observer: not root, CAP_NET_ADMIN and CAP_SYSLOG only, reads NFLOG and the kernel log"
observer_up() {
  journalctl -b -u containerizer-egress-observer --no-pager -o cat | grep -q "reading NFLOG group 100"
}
if ! wait_for 900 "egress observer started" observer_up; then
  systemctl status containerizer-egress-observer --no-pager || true
  journalctl -b -u containerizer-egress-observer --no-pager | tail -30
  exit 1
fi
pid=$(systemctl show -p MainPID --value containerizer-egress-observer)
test "$pid" -gt 0
test "$(stat -c %U "/proc/$pid")" = containerizer
grep -E '^Cap(Eff|Prm):' "/proc/$pid/status"
test "$(capsh --decode="$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")" 2>/dev/null | sed 's/.*=//')" = "cap_net_admin,cap_syslog" \
  || test "$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")" = "0000000400001000"
kmsg_open() { ls -l "/proc/$pid/fd" | grep -q /dev/kmsg; }
wait_for 60 "the appliance firewall's drop log (/dev/kmsg) is open" kmsg_open
if journalctl -b -u containerizer-egress-observer --no-pager -o cat | grep -E "kernel log .*(Error|denied)|not readable"; then
  exit 1
fi
echo "ok: egress observer reads the kernel log"
# the drop log (level info) stays off the console
test "$(awk '{print $1}' /proc/sys/kernel/printk)" -le 4
echo "ok: console log level $(cat /proc/sys/kernel/printk)"

step "builds of scanned code: the worker has no Docker socket of its own, builds and runs reach nothing on the host"
# docs/appliance-admin.md#builds-of-scanned-code (issue #255)
if id -nG containerizer | grep -qw docker; then fail "containerizer must not be in the docker group"; fi
systemctl is-active --quiet containerizer-docker-guard.socket || fail "containerizer-docker-guard.socket is not listening"
wpid=$(systemctl show -p MainPID --value containerizer-worker.service)
dgid=$(getent group docker | cut -d: -f3)
if [ "$wpid" -gt 0 ] && awk '/^Groups:/' "/proc/$wpid/status" | grep -qw "$dgid"; then fail "the scan worker runs in the docker group"; fi
tr '\0' '\n' < "/proc/$wpid/environ" | grep -qx DOCKER_HOST=unix:///run/containerizer/docker-guard.sock
ctx=$(mktemp -d); export ctx; chown containerizer "$ctx"
asworker() { runuser -u containerizer -- env HOME="$ctx" DOCKER_CONFIG="$ctx/.docker" DOCKER_HOST=unix:///run/containerizer/docker-guard.sock "$@"; }
if runuser -u containerizer -- docker -H unix:///var/run/docker.sock ps >/dev/null 2>&1; then fail "the worker user reaches Docker's own socket"; fi
for bad in "run --rm --privileged $CZ_IMAGE_MSSQL true" "run --rm --network host $CZ_IMAGE_MSSQL true" \
           "run --rm -v /:/host $CZ_IMAGE_MSSQL true" "exec cz-mssql true" "inspect cz-mssql"; do
  # shellcheck disable=SC2086
  if asworker docker $bad >/dev/null 2>&1; then fail "the guard let 'docker $bad' through"; fi
done
echo "ok: the guard refuses privileged, host-network, host-mount and appliance-container calls"
. /usr/lib/containerizer/images.env
host_ip=$(ip -4 -o addr show scope global | awk '$2 !~ /^(docker|br-|cni|flannel|veth|cz-)/ {sub(/\/.*/, "", $4); print $4; exit}')
gw=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
# the results database, the k3s API (node and service address), the kubelet, the registry, Grafana, Prometheus, the web UI
targets="$host_ip:1433 $gw:1433 $host_ip:6443 $gw:6443 10.43.0.1:443 $host_ip:10250 $gw:5000 $gw:3000 $gw:9090 $gw:8080 $host_ip:22"
cat > "$ctx/probe.sh" <<'SH'
#!/bin/bash
# DNS works (the positive control), every appliance port is closed
getent hosts ghcr.io >/dev/null || { echo "no DNS from the build"; exit 2; }
for t in "$@"; do
  if timeout 4 bash -c "</dev/tcp/${t%:*}/${t##*:}" 2>/dev/null; then echo "REACHED $t"; exit 1; fi
  echo "closed: $t"
done
SH
printf 'FROM %s\nCOPY probe.sh /probe.sh\nUSER 0\nRUN bash /probe.sh %s\n' "$CZ_IMAGE_MSSQL" "$targets" > "$ctx/Dockerfile"
chown -R containerizer "$ctx"
if ! asworker docker build --no-cache --progress=plain -t cz-ci/probe:1 "$ctx" > "$ctx/build.log" 2>&1; then
  tail -30 "$ctx/build.log"; fail "a build step reached an appliance service (see REACHED above)"
fi
grep -E "closed:|REACHED" "$ctx/build.log" || true
echo "ok: a build's RUN step reaches no appliance service"
# shellcheck disable=SC2086
asworker docker run --rm --cap-drop ALL --security-opt no-new-privileges cz-ci/probe:1 bash /probe.sh $targets \
  || fail "a verification run reached an appliance service"
echo "ok: a verification run reaches no appliance service"
if asworker env DOCKER_BUILDKIT=0 docker build --network host -q "$ctx" >/dev/null 2>&1; then fail "a build got the host network"; fi
if asworker docker build --network host -q "$ctx" >/dev/null 2>&1; then fail "a BuildKit build got the host network"; fi
echo "ok: builds never get the host network"
nft list table inet cz_dockerd | grep -q 'system.slice/docker.service' || fail "Docker's own egress table is not loaded"
for url in http://127.0.0.1:9090/-/ready http://127.0.0.1:3000/grafana/api/health "http://$host_ip:8080/healthz"; do
  printf 'FROM %s\nADD %s /x\n' "$CZ_IMAGE_MSSQL" "$url" > "$ctx/Dockerfile.add"; chown containerizer "$ctx/Dockerfile.add"
  if asworker docker build --no-cache -q -f "$ctx/Dockerfile.add" "$ctx" >/dev/null 2>&1; then fail "a build fetched $url"; fi
done
echo "ok: Docker fetches no URL of the appliance's own services for a build"
asworker docker rmi cz-ci/probe:1 >/dev/null || true
rm -rf "$ctx"

step "no failed units"
systemctl --failed --no-legend
test -z "$(systemctl --failed --no-legend)"
echo "ALL CHECKS PASSED"
