# helm (and other Kubernetes clients) in root's shell use the sandbox cluster, as kubectl (k3s) does by itself
[ -r /etc/rancher/k3s/k3s.yaml ] && export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
