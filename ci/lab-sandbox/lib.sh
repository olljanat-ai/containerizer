# shellcheck shell=bash
# Shared settings of the lab sandbox (README.md). Sourced by the other scripts.
set -euo pipefail
LAB_SCRIPTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAB_DIR=${LAB_DIR:-/home/dev/lab-sandbox}           # state: kubeconfig, secrets.env, PKI, Gitea data
STATE=$LAB_DIR/state
CZ_REPO=${CZ_REPO:-$(cd "$LAB_SCRIPTS/../.." 2>/dev/null && [ -f containerizer/org.py ] && pwd || echo /home/dev/containerizer)}
PY=${PY:-$CZ_REPO/.venv-ci/bin/python}
export PYTHONPATH=$CZ_REPO${PYTHONPATH:+:$PYTHONPATH}
export KUBECONFIG=$LAB_DIR/kubeconfig

# --- pinned versions (the appliance's, appliance/Dockerfile and its k3s manifests) ---------------------
K3S_URL=https://github.com/k3s-io/k3s/releases/download/v1.37.1%2Bk3s1/k3s
K3S_SHA=92b94582eb7b34a8cf532e6006842b9ed215a6783cf56a3dd6271fd35243b2c0
FLUX_URL=https://github.com/fluxcd/flux2/releases/download/v2.10.0/install.yaml
FLUX_SHA=a8c838ccd9be5d30eba9df87cd229b7c4eb80c0049fba1bc3b9840829f267f28
# the images install.yaml names by tag, pinned here by digest (resolved 2026-11-01)
FLUX_DIGESTS="
ghcr.io/fluxcd/helm-controller:v1.7.1@sha256:54526cc6ed1202d71d44c310676448065664f3255ad671d9a69ac26f904e617a
ghcr.io/fluxcd/image-automation-controller:v1.3.0@sha256:6ec488320def72fecfd01ab1289cc6c881d76b984fbbcf69b174e1e10886029e
ghcr.io/fluxcd/image-reflector-controller:v1.3.0@sha256:b4d2cbdc1b7a046c53786628fe900b72b31a95c4cec219478777e3f97c453635
ghcr.io/fluxcd/kustomize-controller:v1.10.1@sha256:37db29b25dae35b881a5e064acedb0cc954442da453a39eaa0eab7a90dbecc4e
ghcr.io/fluxcd/notification-controller:v1.10.0@sha256:9f58b9532ec9d3ccf539cd3ccdf283477a5dcb7777b922db5477d8bbd4d3767c
ghcr.io/fluxcd/source-controller:v1.10.1@sha256:611b6bca3eae95bcff471414d1fb14a4ab83d7f14e609cccef2bd389c121f37e
ghcr.io/fluxcd/source-watcher:v2.3.1@sha256:cb94a51b0f7a433fd5610b5f3cd8eb06ba7d70c656a3594dfe19f656ee996d96"
ESO_CHART=external-secrets/charts/external-secrets
ESO_CHART_DIGEST=sha256:0a6d9e91b1ff50adfdbf24b50b582babfa7c5b7df42b21974ca4b3fb88ee5e34
ESO_MANIFEST=$CZ_REPO/appliance/rootfs/var/lib/rancher/k3s/server/manifests/external-secrets.yaml
HELM_IMAGE=alpine/helm:3.19.0@sha256:aef9b56f64e866207d9591d0abd8f6d767b36aadd12edf68f8a719716d9d29c9
GITEA_IMAGE=gitea/gitea:28.3.0-rootless@sha256:40c5a68a0463c0940e1ae32626c8300dd0572f3558e390073ad8379ca67c0e1d
SMOKE_BASE=nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03

# --- names, addresses ----------------------------------------------------------------------------------
K3S_UNIT=k3s-lab
K3S_CONF=/etc/rancher/k3s-lab/config.yaml
K3S_MANIFESTS=/var/lib/rancher/k3s/server/manifests
SYNC_UNIT=lab-sandbox-sync
GIT_CTR=lab-git
GIT_HOST=lab-git
GIT_PORT=3001
# the Docker bridge's address: the host reaches Gitea there (and on 127.0.0.1), and so do the pods
GIT_ADDR=${GIT_ADDR:-$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo 172.17.0.1)}
GIT_BASE=https://$GIT_HOST:$GIT_PORT
GIT_ORG=lab
GIT_REPO=sandbox-deployments
GIT_URL=$GIT_BASE/$GIT_ORG/$GIT_REPO.git
GIT_ADMIN=lab-admin
SANDBOX_DOMAIN=sandbox.lab.test       # wildcard *.sandbox.lab.test, certificate from the lab CA
TRAEFIK_HTTP=30080
TRAEFIK_HTTPS=30443
SECRETS=$LAB_DIR/secrets.env
CA=$STATE/pki/ca.crt

say() { printf '\033[1m[lab] %s\033[0m\n' "$*" >&2; }
k() { kubectl --kubeconfig "$KUBECONFIG" "$@"; }
have_cluster() { [ -s "$KUBECONFIG" ] && k get --raw /readyz >/dev/null 2>&1; }
secrets() { [ -f "$SECRETS" ] && . "$SECRETS"; return 0; }
# the appliance's own secret store functions (cz_store_setup, cz_store_put, cz_store_grant)
. "$CZ_REPO/appliance/rootfs/usr/lib/containerizer/lib/secret-store.sh"
CZ_STORE_LABEL=app.kubernetes.io/managed-by=containerizer-appliance
gitea_api() {  # METHOD PATH [JSON]: as the admin user
  secrets
  curl -fsS --cacert "$CA" -u "$GIT_ADMIN:$LAB_GIT_ADMIN_PASSWORD" -X "$1" -H 'Content-Type: application/json' \
    ${3:+--data "$3"} "$GIT_BASE/api/v1$2"
}
git_header() {  # Basic auth header for a token, as containerizer sends it
  printf 'Authorization: Basic %s' "$(printf '%s:%s' "$GIT_ADMIN" "$1" | base64 -w0)"
}
