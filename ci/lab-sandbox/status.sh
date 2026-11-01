#!/bin/bash
# What runs, and whether it is healthy.
. "$(dirname "$0")/lib.sh"
set +e
row() { printf '%-28s %s\n' "$1" "$2"; }
row "k3s ($K3S_UNIT)" "$(systemctl is-active "$K3S_UNIT" 2>/dev/null) $(k get node lab -o jsonpath='{.status.nodeInfo.kubeletVersion} {.status.nodeInfo.containerRuntimeVersion}' 2>/dev/null)"
row "sync ($SYNC_UNIT.timer)" "$(systemctl is-active "$SYNC_UNIT.timer" 2>/dev/null), last run: $(systemctl show "$SYNC_UNIT.service" -p ExecMainExitTimestamp --value 2>/dev/null) result $(systemctl show "$SYNC_UNIT.service" -p Result --value 2>/dev/null)"
row "Gitea ($GIT_CTR)" "$(docker inspect -f '{{.State.Status}}' "$GIT_CTR" 2>/dev/null) $GIT_BASE (127.0.0.1:$GIT_PORT, $GIT_ADDR:$GIT_PORT) health: $(curl -fsS --cacert "$CA" "$GIT_BASE/api/healthz" 2>/dev/null | jq -r .status 2>/dev/null)"
row "output repository" "$GIT_URL"
row "Traefik" "http://127.0.0.1:$TRAEFIK_HTTP https://127.0.0.1:$TRAEFIK_HTTPS (*.$SANDBOX_DOMAIN)"
row "kubeconfig (admin)" "$KUBECONFIG"
row "kubeconfig (verifier)" "$LAB_DIR/verifier.kubeconfig $( [ -s "$LAB_DIR/verifier.kubeconfig" ] && echo present || echo 'not yet: no sandbox/verify-rbac.yaml or namespaces')"
have_cluster || exit 0
echo
k get deploy -n flux-system -o custom-columns='FLUX:.metadata.name,READY:.status.readyReplicas' --no-headers 2>/dev/null | paste -sd' ' | sed 's/^/flux: /'
k get deploy -n external-secrets -o custom-columns='ESO:.metadata.name,READY:.status.readyReplicas' --no-headers 2>/dev/null | paste -sd' ' | sed 's/^/eso:  /'
k get clustersecretstore app-secrets -o jsonpath='store app-secrets: {.status.conditions[0].reason}{"\n"}' 2>/dev/null
echo
k get gitrepositories.source.toolkit.fluxcd.io,kustomizations.kustomize.toolkit.fluxcd.io -A 2>/dev/null
echo
k get externalsecrets.external-secrets.io -A 2>/dev/null
