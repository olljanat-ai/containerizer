# shellcheck shell=bash
# The sandbox cluster's secret store (docs/external-secrets.md). External Secrets Operator reads remote
# Secrets in namespace containerizer-secrets through ClusterSecretStore "app-secrets"; each namespace
# authenticates as its own ServiceAccount app-secrets-reader and can get only the remote Secrets its Role
# names. Generated configurations hold ExternalSecrets only; the appliance puts the values here.
# Sourced by cz-sandbox (and other appliance scripts); needs KUBECONFIG and a k() kubectl wrapper.

CZ_STORE_NS=containerizer-secrets
CZ_STORE_NAME=app-secrets
CZ_STORE_READER=app-secrets-reader
CZ_STORE_LABEL=app.kubernetes.io/managed-by=containerizer-appliance

cz_store_ready() {  # ESO's CRDs are installed (k3s HelmChart external-secrets)
  k get crd externalsecrets.external-secrets.io clustersecretstores.external-secrets.io >/dev/null 2>&1
}

cz_store_setup() {  # the locked-down namespace and the store; idempotent
  k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${CZ_STORE_NS}
  labels:
    app.kubernetes.io/managed-by: containerizer-appliance
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
---
# values only: nothing may run here
apiVersion: v1
kind: ResourceQuota
metadata: {name: no-workloads, namespace: ${CZ_STORE_NS}, labels: {app.kubernetes.io/managed-by: containerizer-appliance}}
spec: {hard: {pods: "0"}}
---
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: ${CZ_STORE_NAME}
  labels: {app.kubernetes.io/managed-by: containerizer-appliance}
spec:
  provider:
    kubernetes:
      remoteNamespace: ${CZ_STORE_NS}
      server:
        url: https://kubernetes.default.svc
        caProvider: {type: ConfigMap, name: kube-root-ca.crt, key: ca.crt, namespace: ${CZ_STORE_NS}}
      auth:
        # no namespace: ESO uses the ServiceAccount of this name in the ExternalSecret's own namespace
        serviceAccount: {name: ${CZ_STORE_READER}}
YAML
}

# cz_store_put KEY [--manager NAME] [--type TYPE] key=value|key=@file ...
# Writes the given keys of remote Secret KEY. Server-side apply with its own field manager: writers that
# use different managers own different keys of the same Secret and never remove each other's.
cz_store_put() {
  local name=$1 manager=containerizer-appliance type=Opaque kv k v data=""
  shift
  [[ "$name" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo "cz_store_put: bad remote key" >&2; return 1; }
  while [ $# -gt 0 ]; do
    case "$1" in
      --manager) manager=$2; shift 2;;
      --type) type=$2; shift 2;;
      *) kv=$1; shift
         k=${kv%%=*}; v=${kv#*=}
         [[ "$k" =~ ^[-._a-zA-Z0-9]+$ ]] || { echo "cz_store_put: bad key name" >&2; return 1; }
         if [ "${v:0:1}" = @ ]; then v=$(base64 -w0 < "${v:1}"); else v=$(printf %s "$v" | base64 -w0); fi
         data+="  ${k}: ${v}"$'\n';;
    esac
  done
  [ -n "$data" ] || { echo "cz_store_put: no keys" >&2; return 1; }
  # stdin, never arguments: the values do not show up in the process list
  k apply --server-side --force-conflicts --field-manager="$manager" -f - >/dev/null <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: ${name}
  namespace: ${CZ_STORE_NS}
  labels: {app.kubernetes.io/managed-by: containerizer-appliance}
type: ${type}
data:
${data}
YAML
}

# cz_store_grant NAMESPACE KEY... : NAMESPACE's reader may get exactly these remote Secrets.
# Only for namespaces the appliance owns; app namespaces get theirs from the generated flux/tenant.yaml.
cz_store_grant() {
  local ns=$1 names
  shift
  names=$(printf '"%s",' "$@")
  k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${CZ_STORE_READER}
  namespace: ${ns}
  labels: {app.kubernetes.io/managed-by: containerizer-appliance}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${CZ_STORE_READER}-${ns}
  namespace: ${CZ_STORE_NS}
  labels: {app.kubernetes.io/managed-by: containerizer-appliance}
rules:
  - {apiGroups: [""], resources: [secrets], verbs: [get], resourceNames: [${names%,}]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${CZ_STORE_READER}-${ns}
  namespace: ${CZ_STORE_NS}
  labels: {app.kubernetes.io/managed-by: containerizer-appliance}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ${CZ_STORE_READER}-${ns}}
subjects:
  - {kind: ServiceAccount, name: ${CZ_STORE_READER}, namespace: ${ns}}
YAML
}
