#!/bin/bash
# Stop the lab sandbox: the sync timer, k3s and its pods (Docker containers k8s_*), Gitea. The data stays:
# up.sh starts it all again.
#   down.sh --purge   also deletes the cluster's data (/var/lib/rancher/k3s), the k3s units and config, the
#                     Gitea container and data, the PKI, the kubeconfigs and secrets.env.
. "$(dirname "$0")/lib.sh"
set +e
purge=; [ "${1:-}" = --purge ] && purge=1
sudo systemctl disable -q --now "$SYNC_UNIT.timer" 2>/dev/null
sudo systemctl stop "$K3S_UNIT" 2>/dev/null
# KillMode=process leaves the pods running: with --docker they are Docker containers of cri-dockerd
ids=$(docker ps -aq --filter label=io.kubernetes.pod.namespace)
[ -z "$ids" ] || docker rm -f $ids >/dev/null
docker stop "$GIT_CTR" >/dev/null 2>&1
if [ -n "$purge" ]; then
  sudo systemctl disable -q "$K3S_UNIT" 2>/dev/null
  sudo find "/etc/systemd/system" -maxdepth 1 \( -name "$K3S_UNIT.service" -o -name "$SYNC_UNIT.service" -o -name "$SYNC_UNIT.timer" \) -delete
  sudo systemctl daemon-reload
  # the k3s data, its config and the links k3s made; the binary /usr/local/bin/k3s stays
  for d in /var/lib/rancher/k3s /etc/rancher/k3s /etc/rancher/k3s-lab /var/lib/kubelet /run/k3s /run/flannel /var/lib/cni; do
    [ -e "$d" ] && sudo rm -rf --one-file-system "${d:?}"
  done
  for l in cni0 flannel.1; do sudo ip link delete "$l" 2>/dev/null; done
  docker rm -f "$GIT_CTR" >/dev/null 2>&1
  # Gitea's files belong to this user (the container runs as it)
  [ -d "$STATE" ] && rm -rf --one-file-system "${STATE:?}"
  rm -f "$LAB_DIR/kubeconfig" "$LAB_DIR/verifier.kubeconfig" "$SECRETS"
  git config --global --unset "http.$GIT_BASE/.sslCAInfo"
  echo "purged. Left in place on purpose: /usr/local/bin/k3s, the $GIT_HOST line in /etc/hosts, the k3s accept rules in"
  echo "/etc/nftables.conf (backup /etc/nftables.conf.bak-lab-sandbox) and k3s's KUBE-*/CNI-*/FLANNEL-* iptables chains"
  echo "(gone after the next reboot)."
else
  echo "stopped (data kept; up.sh starts it again)"
fi
