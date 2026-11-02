#!/bin/bash
# The egress observer for the lab sandbox (docs/egress.md#the-egress-observer), as the appliance runs it
# (containerizer-egress-observer.service): `containerizer egress-observe` as this user with CAP_NET_ADMIN only,
# its own read-only ServiceAccount (CoreDNS's log in kube-system, the pods of the app namespaces), the CoreDNS
# query log on (coredns-custom, log.override), flows into the lab's results database (writer login).
#   egress-observer.sh install    RBAC, kubeconfig, CoreDNS log, systemd unit lab-egress-observer (needs sudo)
#   egress-observer.sh rbac       the observer's Roles in every app namespace and a fresh token (sync.sh runs it)
#   egress-observer.sh remove     stop and remove the unit, the RBAC and the CoreDNS log
# The database: CZ_RESULTS_ENV (default /home/dev/containerizer/results/.env, its CZ_SCANNER_PASSWORD) on
# 127.0.0.1:1433, or CONTAINERIZER_SQL / CONTAINERIZER_SQL_PASSWORD when set.
. "$(dirname "$0")/lib.sh"
UNIT=lab-egress-observer
OKC=$LAB_DIR/egress-observer.kubeconfig
OENV=$LAB_DIR/egress-observer.env
SA=containerizer-egress-observer
SANS=containerizer-verify

rbac() {
  have_cluster || { echo "lab sandbox: the cluster is not up (up.sh)" >&2; return 0; }
  k get ns "$SANS" >/dev/null 2>&1 || k create ns "$SANS" >/dev/null
  local nss
  nss=$(k get namespaces -l app.kubernetes.io/managed-by=containerizer -o jsonpath='{.items[*].metadata.name}')
  # shellcheck disable=SC2086 # one argument per namespace
  "$PY" -c 'import sys, yaml
from containerizer.egress import observer_rbac
print("---\n".join(yaml.safe_dump(d, sort_keys=False) for d in observer_rbac(sys.argv[1:])))' $nss | k apply -f - >/dev/null
  if [ -s "$OKC" ] && [ -z "$(find "$OKC" -mmin +720)" ] && [ "${1:-}" != --token ]; then return 0; fi
  local tok server ca
  tok=$(k -n "$SANS" create token "$SA" --duration=24h)
  server=$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  ca=$(k config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  umask 077
  cat > "$OKC.tmp" <<YAML
apiVersion: v1
kind: Config
clusters: [{name: lab, cluster: {server: "$server", certificate-authority-data: "$ca"}}]
users: [{name: $SA, user: {token: "$tok"}}]
contexts: [{name: observer, context: {cluster: lab, user: $SA}}]
current-context: observer
YAML
  mv "$OKC.tmp" "$OKC"
}

coredns_log() {   # on: the lab's coredns-custom (k3s addon manifest) gets log.override
  local f=$K3S_MANIFESTS/lab-coredns.yaml
  sudo test -f "$f" || { echo "no $f (up.sh)" >&2; return 1; }
  if ! sudo grep -q 'log.override' "$f"; then
    printf '  log.override: |\n    log\n' | sudo tee -a "$f" >/dev/null
  fi
  for _ in $(seq 30); do
    k -n kube-system get cm coredns-custom -o jsonpath='{.data.log\.override}' 2>/dev/null | grep -qx log && return 0
    sleep 2
  done
  echo "coredns-custom has no log.override yet (k3s applies the manifest within a minute)" >&2
}

case "${1:-install}" in
  rbac) rbac "${2:-}" ;;
  install)
    say "1. the observer's read-only ServiceAccount and kubeconfig ($OKC)"
    rbac --token
    say "2. the CoreDNS query log (coredns-custom: log.override)"
    coredns_log
    say "3. the results database ($OENV)"
    if [ -z "${CONTAINERIZER_SQL:-}" ]; then
      envf=${CZ_RESULTS_ENV:-/home/dev/containerizer/results/.env}
      pw=$(sed -n 's/^CZ_SCANNER_PASSWORD=//p' "$envf")
      [ -n "$pw" ] || { echo "no CZ_SCANNER_PASSWORD in $envf" >&2; exit 1; }
      CONTAINERIZER_SQL="Server=127.0.0.1,1433;Database=Containerizer;User Id=cz_scanner;TrustServerCertificate=yes"
      CONTAINERIZER_SQL_PASSWORD=$pw
    fi
    umask 077
    printf 'CONTAINERIZER_SQL="%s"\nCONTAINERIZER_SQL_PASSWORD="%s"\nCONTAINERIZER_EGRESS_KUBECONFIG="%s"\nPYTHONPATH="%s"\n' \
      "$CONTAINERIZER_SQL" "$CONTAINERIZER_SQL_PASSWORD" "$OKC" "$CZ_REPO" > "$OENV"
    say "4. systemd unit $UNIT (as $(id -un), CAP_NET_ADMIN only)"
    sudo tee "/etc/systemd/system/$UNIT.service" >/dev/null <<UNIT
[Unit]
Description=containerizer lab sandbox: egress observer (docs/egress.md)
After=$K3S_UNIT.service
Wants=$K3S_UNIT.service

[Service]
User=$(id -un)
Group=$(id -gn)
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
EnvironmentFile=$OENV
Environment=PATH=/usr/local/bin:/usr/bin:/bin
WorkingDirectory=$CZ_REPO
# a fresh token and the Roles of new namespaces at every start; the unit restarts itself every 12 hours
ExecStartPre=$LAB_SCRIPTS/egress-observer.sh rbac --token
ExecStart=$PY -m containerizer egress-observe --name lab-egress-observer
RuntimeMaxSec=12h
Restart=always
RestartSec=20
ProtectSystem=full
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$UNIT.service" >/dev/null 2>&1
    sudo systemctl restart "$UNIT.service"
    sleep 3
    systemctl --no-pager --lines=5 status "$UNIT.service" | sed -n '1,12p'
    ;;
  remove)
    sudo systemctl disable --now "$UNIT.service" >/dev/null 2>&1 || true
    sudo rm -f "/etc/systemd/system/$UNIT.service" && sudo systemctl daemon-reload
    for ns in $(k get rolebindings -A --field-selector metadata.name=$SA -o jsonpath='{.items[*].metadata.namespace}'); do
      k -n "$ns" delete rolebinding,role "$SA" --ignore-not-found >/dev/null
    done
    k -n "$SANS" delete sa "$SA" --ignore-not-found >/dev/null
    f=$K3S_MANIFESTS/lab-coredns.yaml
    sudo sed -i '/^  log.override: |$/,/^    log$/d' "$f" 2>/dev/null || true
    rm -f "$OKC" "$OENV"
    echo "removed $UNIT"
    ;;
  *) echo "usage: $0 install | rbac | remove" >&2; exit 2 ;;
esac
