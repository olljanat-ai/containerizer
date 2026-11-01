# shellcheck shell=bash
# Source this (`. /home/dev/lab-sandbox/env.sh`) before a scan, a runner or `containerizer sandbox verify`
# against the lab sandbox. It sets what `containerizer org` / the worker take for the output repository,
# the registry prefix of the local images and the sandbox cluster.
_lab_dir=${LAB_DIR:-/home/dev/lab-sandbox}
# shellcheck disable=SC1091
[ -f "$_lab_dir/secrets.env" ] && . "$_lab_dir/secrets.env"
export LAB_DIR=$_lab_dir

# the cluster: admin (kubectl, Flux) and the read-only verifier (containerizer sandbox verify)
export KUBECONFIG=$_lab_dir/kubeconfig
export LAB_VERIFIER_KUBECONFIG=$_lab_dir/verifier.kubeconfig

# the output repository (Gitea): the same URL works on the host and in the cluster
export LAB_OUTPUT_REPO=https://lab-git:3001/lab/sandbox-deployments.git
export LAB_OUTPUT_USERNAME=lab-admin                  # --output-username
export OUTPUT_GIT_TOKEN=${LAB_GIT_WRITE_TOKEN:-}      # --output-token-env default: write:repository
export CZ_SANDBOX_GIT_URL=$LAB_OUTPUT_REPO            # sandbox.env names, as on the appliance
export CZ_SANDBOX_GIT_USERNAME=lab-admin
export CZ_SANDBOX_GIT_TOKEN=${LAB_GIT_READ_TOKEN:-}   # read-only: what Flux uses (sync.sh fills the store)

# images: k3s runs on Docker's image store, so a locally built image with this prefix is deployable as is
# (imagePullPolicy IfNotPresent); nothing is pushed. The appliance pushes to localhost:5000/<path> instead.
export LAB_REGISTRY=localhost/lab

# Traefik: NodePorts on loopback; Ingress hosts <component>-<app>.sandbox.lab.test, certificate from the lab CA
export LAB_INGRESS_DOMAIN=sandbox.lab.test
export LAB_INGRESS_ADDRESS=127.0.0.1:30443            # containerizer sandbox verify --ingress-address
export LAB_CA=$_lab_dir/state/pki/ca.crt              # --ingress-ca; git trusts it for lab-git (~/.gitconfig)
unset _lab_dir
