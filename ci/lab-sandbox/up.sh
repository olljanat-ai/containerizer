#!/bin/bash
# Lab sandbox: k3s (the appliance's version, with Docker's image store), Flux, External Secrets with the
# appliance's ClusterSecretStore app-secrets, Gitea as the output repository, and the cz-sandbox
# bootstrap. Idempotent: run it again after a reboot or a change. README.md says what runs where.
. "$(dirname "$0")/lib.sh"
command -v docker >/dev/null && command -v kubectl >/dev/null && [ -x "$PY" ] || { echo "needs docker, kubectl and $PY" >&2; exit 1; }
sudo -n true || { echo "needs sudo (k3s runs as a system service)" >&2; exit 1; }
umask 077
mkdir -p "$STATE"/{dl,pki,gitea/data,gitea/config}

# ------------------------------------------------------------------ downloads, verified by checksum
fetch() {  # url sha256 file
  [ -f "$3" ] && echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null && return 0
  curl -fsSLo "$3.tmp" "$1" && echo "$2  $3.tmp" | sha256sum -c --quiet - && mv "$3.tmp" "$3"
}
fetch "$K3S_URL" "$K3S_SHA" "$STATE/dl/k3s"
fetch "$FLUX_URL" "$FLUX_SHA" "$STATE/dl/flux-install.yaml"
chart=$STATE/dl/external-secrets-2.14.0.tgz
if ! echo "${ESO_CHART_DIGEST#sha256:}  $chart" | sha256sum -c --quiet - 2>/dev/null; then
  token=$(curl -fsS "https://ghcr.io/token?scope=repository:${ESO_CHART}:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  curl -fsSL -H "Authorization: Bearer $token" -o "$chart" "https://ghcr.io/v2/${ESO_CHART}/blobs/${ESO_CHART_DIGEST}"
  echo "${ESO_CHART_DIGEST#sha256:}  $chart" | sha256sum -c --quiet -
fi

# ------------------------------------------------------------------ PKI: lab CA, Gitea and wildcard certificates
pki=$STATE/pki
if [ ! -s "$pki/ca.crt" ]; then
  say "creating the lab CA"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=containerizer lab CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$pki/ca.key" -out "$pki/ca.crt" 2>/dev/null
fi
leaf() {  # name "san entries" (DNS:x,IP:y)
  [ -s "$pki/$1/tls.crt" ] && openssl x509 -in "$pki/$1/tls.crt" -noout -checkend 2592000 >/dev/null && return 0
  mkdir -p "$pki/$1"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$3" -keyout "$pki/$1/tls.key" 2>/dev/null \
  | openssl x509 -req -in /dev/stdin -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial -CAserial "$pki/ca.srl" \
      -days 825 -out "$pki/$1/tls.crt" -extfile <(printf '%s\n' "subjectAltName=$2" extendedKeyUsage=serverAuth \
      keyUsage=critical,digitalSignature basicConstraints=CA:FALSE subjectKeyIdentifier=hash authorityKeyIdentifier=keyid) 2>/dev/null
}
leaf git "DNS:$GIT_HOST,DNS:localhost,IP:127.0.0.1,IP:$GIT_ADDR" "$GIT_HOST"
leaf sandbox "DNS:*.$SANDBOX_DOMAIN,DNS:$SANDBOX_DOMAIN" "*.$SANDBOX_DOMAIN"
chmod 0644 "$pki/ca.crt"

# ------------------------------------------------------------------ host: name and trust for the Git server
if ! grep -qE "^[0-9.]+[[:space:]]+$GIT_HOST([[:space:]]|\$)" /etc/hosts; then
  say "adding $GIT_HOST ($GIT_ADDR) to /etc/hosts"
  echo "$GIT_ADDR $GIT_HOST   # lab sandbox Git server ($LAB_DIR/README.md)" | sudo tee -a /etc/hosts >/dev/null
fi
# git trusts the lab CA for this one URL only (containerizer's git keeps reading ~/.gitconfig)
git config --global "http.$GIT_BASE/.sslCAInfo" "$CA"

# ------------------------------------------------------------------ Gitea
secrets
if [ -z "${LAB_GIT_ADMIN_PASSWORD:-}" ]; then
  LAB_GIT_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
  printf 'LAB_GIT_ADMIN_PASSWORD=%s\n' "$LAB_GIT_ADMIN_PASSWORD" >> "$SECRETS"
fi
chmod 600 "$SECRETS"
if ! docker inspect "$GIT_CTR" >/dev/null 2>&1; then
  say "starting Gitea ($GIT_CTR on 127.0.0.1:$GIT_PORT and $GIT_ADDR:$GIT_PORT)"
  docker run -d --name "$GIT_CTR" --restart unless-stopped --user "$(id -u):$(id -g)" \
    --memory 512m --cap-drop ALL --security-opt no-new-privileges \
    -p "127.0.0.1:$GIT_PORT:$GIT_PORT" -p "$GIT_ADDR:$GIT_PORT:$GIT_PORT" \
    -v "$STATE/gitea/data:/var/lib/gitea" -v "$STATE/gitea/config:/etc/gitea" -v "$pki/git:/certs:ro" \
    -e GITEA__server__PROTOCOL=https -e GITEA__server__HTTP_PORT="$GIT_PORT" \
    -e GITEA__server__DOMAIN="$GIT_HOST" -e GITEA__server__ROOT_URL="$GIT_BASE/" \
    -e GITEA__server__CERT_FILE=/certs/tls.crt -e GITEA__server__KEY_FILE=/certs/tls.key \
    -e GITEA__server__DISABLE_SSH=true -e GITEA__server__START_SSH_SERVER=false \
    -e GITEA__security__INSTALL_LOCK=true -e GITEA__database__DB_TYPE=sqlite3 \
    -e GITEA__service__DISABLE_REGISTRATION=true -e GITEA__service__REQUIRE_SIGNIN_VIEW=true \
    -e GITEA__repository__DEFAULT_BRANCH=main -e GITEA__log__LEVEL=Warn \
    -e USER=git `# the uid has no passwd entry in the image: Gitea checks RUN_USER (git) against $USER` \
    "$GITEA_IMAGE" >/dev/null
fi
docker start "$GIT_CTR" >/dev/null
for _ in $(seq 60); do curl -fsS --cacert "$CA" "$GIT_BASE/api/healthz" >/dev/null 2>&1 && break; sleep 2; done
if ! docker exec "$GIT_CTR" gitea admin user list --admin 2>/dev/null | awk '{print $2}' | grep -qx "$GIT_ADMIN"; then
  say "creating the Gitea admin $GIT_ADMIN"
  docker exec "$GIT_CTR" gitea admin user create --admin --username "$GIT_ADMIN" --email "$GIT_ADMIN@lab.invalid" \
    --password "$LAB_GIT_ADMIN_PASSWORD" --must-change-password=false >/dev/null
fi
gitea_api GET "/orgs/$GIT_ORG" >/dev/null 2>&1 || gitea_api POST /orgs "{\"username\":\"$GIT_ORG\",\"visibility\":\"private\"}" >/dev/null
gitea_api GET "/repos/$GIT_ORG/$GIT_REPO" >/dev/null 2>&1 || gitea_api POST "/orgs/$GIT_ORG/repos" \
  "{\"name\":\"$GIT_REPO\",\"private\":true,\"auto_init\":true,\"default_branch\":\"main\",\"description\":\"lab sandbox output repository\"}" >/dev/null
token() {  # VAR name scopes-json
  [ -n "${!1:-}" ] && return 0
  gitea_api DELETE "/users/$GIT_ADMIN/tokens/$2" >/dev/null 2>&1 || true
  local t; t=$(gitea_api POST "/users/$GIT_ADMIN/tokens" "{\"name\":\"$2\",\"scopes\":$3}" | jq -r .sha1)
  printf '%s=%s\n' "$1" "$t" >> "$SECRETS"; printf -v "$1" %s "$t"
}
token LAB_GIT_WRITE_TOKEN lab-output-write '["write:repository"]'
token LAB_GIT_READ_TOKEN lab-sandbox-read '["read:repository","read:organization"]'

# ------------------------------------------------------------------ host firewall: pods and services reach the host
# The live rules are added without reloading /etc/nftables.conf: its `flush ruleset` would also drop
# Docker's and k3s's tables (the file says to restart Docker after loading it).
if ! grep -q 'iifname { "cni0", "flannel.1" } accept' /etc/nftables.conf; then
  say "adding the k3s accept rules to /etc/nftables.conf (input chain)"
  sudo cp -p /etc/nftables.conf /etc/nftables.conf.bak-lab-sandbox
  sudo sed -i '/^    ip saddr \$LAB tcp dport/a\    # k3s-lab (docs/local-dev-server.md, Lab sandbox): its pods and services reach the host\n    iifname { "cni0", "flannel.1" } accept\n    ip saddr { 10.42.0.0/16, 10.43.0.0/16 } accept' /etc/nftables.conf
  sudo nft -c -f /etc/nftables.conf
fi
if ! sudo nft list chain inet filter input | grep -q 'iifname { "cni0", "flannel.1" } accept'; then
  sudo nft add rule inet filter input iifname '{ "cni0", "flannel.1" }' accept
  sudo nft add rule inet filter input ip saddr '{ 10.42.0.0/16, 10.43.0.0/16 }' accept
fi

# ------------------------------------------------------------------ k3s with Docker's image store
sudo install -m 0755 "$STATE/dl/k3s" /usr/local/bin/k3s
sudo install -d -m 0755 /etc/rancher/k3s-lab "$K3S_MANIFESTS"
sudo tee "$K3S_CONF" >/dev/null <<YAML
# lab sandbox ($LAB_DIR/README.md): the appliance's k3s settings (appliance/rootfs/etc/rancher/k3s/config.yaml)
# with Docker as the container runtime, so pods run the images \`docker build\` made (no registry)
docker: true
node-name: lab
write-kubeconfig: /etc/rancher/k3s/k3s.yaml
write-kubeconfig-mode: "0600"
disable:
  - servicelb
secrets-encryption: true
kube-apiserver-arg:
  - "anonymous-auth=false"
kubelet-arg:
  - "streaming-connection-idle-timeout=5m"
  - "make-iptables-util-chains=true"
  # Docker's image store is shared with the builds and CI: the kubelet never garbage-collects it
  - "image-gc-high-threshold=100"
  - "image-gc-low-threshold=99"
kube-proxy-arg:
  # NodePorts (Traefik $TRAEFIK_HTTP/$TRAEFIK_HTTPS) answer on loopback only
  - "nodeport-addresses=127.0.0.1/32"
YAML
sudo tee "$K3S_MANIFESTS/lab-traefik.yaml" >/dev/null <<YAML
# lab sandbox: Traefik as on the appliance (containerizer-traefik.yaml), on NodePorts $TRAEFIK_HTTP/$TRAEFIK_HTTPS
# (loopback only) instead of behind Caddy; no HTTP->HTTPS redirect (there is no port 443 in front of it)
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    service:
      spec:
        type: NodePort
    ports:
      web:
        nodePort: $TRAEFIK_HTTP
      websecure:
        nodePort: $TRAEFIK_HTTPS
    providers:
      kubernetesIngress:
        publishedService:
          enabled: false
    ingressRoute:
      dashboard:
        enabled: false
    logs:
      access:
        enabled: true
YAML
sudo tee "$K3S_MANIFESTS/lab-coredns.yaml" >/dev/null <<YAML
# lab sandbox: pods resolve the Git server's name to the address the host uses too
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  lab-git.server: |
    $GIT_HOST:53 {
      hosts {
        $GIT_ADDR $GIT_HOST
      }
    }
YAML
sudo tee "/etc/systemd/system/$K3S_UNIT.service" >/dev/null <<UNIT
[Unit]
Description=k3s for the containerizer lab sandbox ($LAB_DIR/README.md)
Wants=network-online.target
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=notify
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s server --config $K3S_CONF
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable -q "$K3S_UNIT"
if ! systemctl is-active -q "$K3S_UNIT"; then say "starting k3s ($K3S_UNIT)"; sudo systemctl start "$K3S_UNIT"; fi
for _ in $(seq 60); do sudo test -s /etc/rancher/k3s/k3s.yaml && break; sleep 2; done
sudo cat /etc/rancher/k3s/k3s.yaml > "$KUBECONFIG.tmp" && chmod 600 "$KUBECONFIG.tmp" && mv "$KUBECONFIG.tmp" "$KUBECONFIG"
for _ in $(seq 90); do have_cluster && k get node lab >/dev/null 2>&1 && break; sleep 2; done
k wait --for=condition=Ready node/lab --timeout=180s >/dev/null

# ------------------------------------------------------------------ Flux v2.10.0, images pinned by digest
say "Flux v2.10.0"
flux=$STATE/flux-install.pinned.yaml
cp "$STATE/dl/flux-install.yaml" "$flux"
for ref in $FLUX_DIGESTS; do sed -i "s#image: ${ref%@*}\$#image: $ref#" "$flux"; done
if grep -qE 'image: ghcr.io/fluxcd/[^@]*$' "$flux"; then echo "a Flux image is not pinned by digest" >&2; exit 1; fi
k apply --server-side --force-conflicts -f "$flux" >/dev/null

# ------------------------------------------------------------------ External Secrets Operator 2.14.0, the appliance's values
say "External Secrets Operator 2.14.0"
"$PY" -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["spec"]["valuesContent"])' "$ESO_MANIFEST" > "$STATE/eso-values.yaml"
docker run --rm --network none -v "$STATE/dl:/charts:ro" -v "$STATE/eso-values.yaml:/values.yaml:ro" "$HELM_IMAGE" \
  template external-secrets /charts/external-secrets-2.14.0.tgz --namespace external-secrets -f /values.yaml \
  > "$STATE/eso.yaml"
k create namespace external-secrets --dry-run=client -o yaml | k apply -f - >/dev/null
k apply --server-side --force-conflicts -n external-secrets -f "$STATE/eso.yaml" >/dev/null
k -n external-secrets rollout status deploy --timeout=300s >/dev/null
k -n flux-system rollout status deploy --timeout=300s >/dev/null
# the webhook must answer before the ClusterSecretStore can be created
for _ in $(seq 60); do cz_store_setup 2>/dev/null && break; sleep 5; done
cz_store_setup

# ------------------------------------------------------------------ Traefik's default certificate: *.sandbox.lab.test
for _ in $(seq 60); do k get crd tlsstores.traefik.io >/dev/null 2>&1 && break; sleep 5; done
k -n kube-system create secret tls lab-sandbox-tls --cert "$pki/sandbox/tls.crt" --key "$pki/sandbox/tls.key" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: traefik.io/v1alpha1
kind: TLSStore
metadata: {name: default, namespace: kube-system}
spec:
  defaultCertificate: {secretName: lab-sandbox-tls}
YAML

# ------------------------------------------------------------------ the cz-sandbox bootstrap, then every 2 minutes
"$LAB_SCRIPTS/sync.sh"
sudo tee "/etc/systemd/system/$SYNC_UNIT.service" >/dev/null <<UNIT
[Unit]
Description=lab sandbox: what the appliance's cz-sandbox does (Git credentials in the secret store, verifier)
After=$K3S_UNIT.service

[Service]
Type=oneshot
User=$(id -un)
Environment=LAB_DIR=$LAB_DIR CZ_REPO=$CZ_REPO
ExecStart=$LAB_SCRIPTS/sync.sh
UNIT
sudo tee "/etc/systemd/system/$SYNC_UNIT.timer" >/dev/null <<UNIT
[Unit]
Description=lab sandbox sync every 2 minutes, as the appliance's containerizer-sandbox.timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable -q --now "$SYNC_UNIT.timer"
"$LAB_SCRIPTS/status.sh"
