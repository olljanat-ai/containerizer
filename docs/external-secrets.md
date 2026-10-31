# Secrets: External Secrets Operator

Nothing containerizer generates is a Kubernetes `Secret`, and no generated file holds a secret value.
Every Secret a workload, a Flux source or an image pull needs is an
[External Secrets Operator](https://external-secrets.io) (ESO) `ExternalSecret`. ESO reads the value from
a secret store and creates the Secret in the cluster. The store can be a vault, a cloud secret manager, or
on the appliance a locked-down namespace of the same cluster. Git only holds the references.

| What | ExternalSecret | Remote key | Properties |
| --- | --- | --- | --- |
| Connection strings and secret settings of a component | `<component>-secrets` | `<namespace>--<component>` | one per environment variable, e.g. `ConnectionStrings__Main` |
| Key and certificate files (mounted under `/secrets`), Kerberos keytab | `<component>-files`, `<component>-keytab` | `<namespace>--<component>` | the file names |
| Flux `GitRepository` credential | `<namespace>-git` | `<namespace>--cz-git` | `username` + `password`, or `identity` + `known_hosts` |
| Flux commit verification keys | `<namespace>-git-gpg` | `<namespace>--cz-git-gpg` | the public keys |
| Registry read credential (Flux `OCIRepository`/`ImageRepository`; the image pull secret of an organization scan) | `<namespace>-registry`, the pull secret's name | `<namespace>--cz-registry` | `.dockerconfigjson` |
| cosign public key for signed OCI artifacts | `<namespace>-cosign-pub` | `<namespace>--cz-cosign-pub` | `cosign.pub` |
| Sandbox root sync (`sandbox/flux/bootstrap.yaml`, `sandbox/argocd/bootstrap.yaml`) | `containerizer-sandbox-git`, `containerizer-sandbox-repo` | `flux-system--cz-git`, `argocd--cz-git` | `username` + `password` |
| Dev database passwords ([dev-databases.md](dev-databases.md)) | `devdb`, `devdb-admin` | none: ESO's Password generator creates them in the cluster | |

`<namespace>` is the app's namespace. Each app's `HARDENING.md` lists the exact remote keys and
properties under **Secret store keys**. The `<namespace>--<name>` form is valid as a Kubernetes Secret
name, an Azure Key Vault secret name, an AWS Secrets Manager name and a Vault path, so the same generated
files work with every store below.

## Isolation: each namespace reads only its own keys

All ExternalSecrets use one `ClusterSecretStore`, `app-secrets`. The store names its identity, the
ServiceAccount `app-secrets-reader`, **without a namespace**. ESO then authenticates as
`app-secrets-reader` *in the namespace of the ExternalSecret* ("referent" authentication). So namespace
`shop` reads the store as `shop:app-secrets-reader` and can get only what that identity is granted:

- **kubernetes provider** (appliance, default): a Role in `containerizer-secrets` with `get` on exactly the
  remote Secrets of `shop` (`resourceNames`, no `list`, no `watch`). It is generated in
  `cluster/secret-store.yaml` and, for Flux, in `gitops/flux/tenant.yaml`.
- **Vault / OpenBao**: a policy that allows `<mount>/data/<namespace>--*` for the namespace of the caller.
- **AWS Secrets Manager**: an IAM role per namespace (IRSA) limited to `secret:<namespace>--*`.
- **Azure Key Vault**: a workload identity per namespace with *Key Vault Secrets User* on its own secrets.

The reader ServiceAccount runs no pod and mounts no token. ESO asks the API server for a short-lived
token of it (TokenRequest, one hour) each time it reads. Every app namespace gets the ServiceAccount from
the generated `security.yaml`; on Flux it is in the platform-owned `tenant.yaml` instead, because the
Git source's own ExternalSecret needs it before the first sync.

The rules behind this are in [`rules/60-security.yaml`](../rules/60-security.yaml) (`secrets`): store
name and kind, refresh interval, key format, reader name and annotations, and the provider
definitions. `CONTAINERIZER_SECRET_STORE=kubernetes|vault|azurekv|aws` in `/etc/containerizer/worker.env`
chooses which store the scans write into `cluster/secret-store.yaml` (default `kubernetes`, the
appliance's own store).

## Hardening checks

The security gate and `HARDENING.md` (NSA/CISA "Secrets", CIS 5.4.2 and 5.1.2) check:

| Check | Severity | Fails when |
| --- | --- | --- |
| `plain-secret` | error | a `Secret` object is in the manifests |
| `secret-literals` | error | a Secret, an env variable with a secret-looking name, or an ExternalSecret template carries a literal value |
| `secret-source` | error | a workload references a Secret (env, envFrom, volume, projected volume, imagePullSecrets) that no ExternalSecret of the app produces |
| `external-secret-store` | error | an ExternalSecret names no SecretStore/ClusterSecretStore (generators excepted), or the app ships its own store |

The Argo CD `AppProject` does not allow the `Secret` kind, so a Secret added to the app repository later
fails to sync. A component that needs a different Secret source declares a waiver in its exception
(`containerizer.io/waives`), and the waiver appears in the report.

## The appliance sandbox

The appliance installs ESO 2.14.0 in its k3s cluster at boot. The chart is part of the OS image, checked
against its digest, and the images are pinned by digest. PushSecret, ClusterExternalSecret and
ClusterGenerator are switched off. Every 2 minutes `cz-sandbox`:

1. creates namespace `containerizer-secrets` (Pod Security "restricted", a ResourceQuota of zero pods, so
   nothing can run next to the values) and `ClusterSecretStore` `app-secrets` (kubernetes provider over
   that namespace, referent ServiceAccount `app-secrets-reader`);
2. puts the read-only Git token of `sandbox.env` there as `flux-system--cz-git` and as
   `<namespace>--cz-git` for every app that the output repository deploys. Flux reads them through the
   generated ExternalSecrets.

Other appliance scripts write values with the helpers in `/usr/lib/containerizer/lib/secret-store.sh`:

```sh
k() { k3s kubectl "$@"; }; . /usr/lib/containerizer/lib/secret-store.sh
cz_store_put shop--web ConnectionStrings__Main='Server=db;...'   # or key=@file
cz_store_grant some-platform-namespace some-key                  # app namespaces get theirs from tenant.yaml
```

`cz_store_put` uses server-side apply with its own field manager (`--manager NAME`), so two writers can
own different keys of the same remote Secret without removing each other's. The values reach `kubectl`
on standard input, never on a command line. To set a component's secret settings by hand on the
appliance, as root:

```sh
kubectl -n containerizer-secrets create secret generic shop--web \
  --from-literal=ConnectionStrings__Main='Server=...' --dry-run=client -o yaml | kubectl apply -f -
```

k3s encrypts Secrets at rest (`secrets-encryption: true`), and the audit policy logs Secret access at
metadata level only.

## Real clusters

Install ESO (the [Helm chart](https://external-secrets.io/latest/introduction/getting-started/)), apply
one app's `cluster/secret-store.yaml` (the store is the same for every app; the Role in it is per app), and
put the remote keys from `HARDENING.md` in the store. Then deploy as usual. To use another backend, set
`CONTAINERIZER_SECRET_STORE` for the scans, or edit the store. The app manifests stay the same.

### HashiCorp Vault or OpenBao

`secrets.providers.vault` in the rules (KV version 2 at `secret/`, Kubernetes auth at `kubernetes/`):

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata: {name: app-secrets}
spec:
  provider:
    vault:
      server: https://vault.example.com:8200
      path: secret
      version: v2
      auth:
        kubernetes:
          mountPath: kubernetes
          role: app-secrets
          serviceAccountRef: {name: app-secrets-reader, audiences: [vault]}   # no namespace: the caller's
```

On the Vault side, one role for every namespace, and a policy templated on the caller's namespace so
`shop` reads only `secret/data/shop--*`:

```sh
ACCESSOR=$(vault auth list -format=json | jq -r '."kubernetes/".accessor')
vault policy write app-secrets - <<EOF
path "secret/data/{{identity.entity.aliases.$ACCESSOR.metadata.service_account_namespace}}--*" {
  capabilities = ["read"]
}
EOF
vault write auth/kubernetes/role/app-secrets bound_service_account_names=app-secrets-reader \
  bound_service_account_namespaces='*' audience=vault policies=app-secrets token_ttl=10m
vault kv put secret/shop--web ConnectionStrings__Main='Server=...'
```

Vault must be able to call the cluster's TokenReview API (Vault's Kubernetes auth documentation covers
`kubernetes_host` and the `system:auth-delegator` binding). OpenBao uses the same `vault` provider.

### Azure Key Vault

`secrets.providers.azurekv` (workload identity of each namespace's reader):

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata: {name: app-secrets}
spec:
  provider:
    azurekv:
      authType: WorkloadIdentity
      vaultUrl: https://contoso-apps.vault.azure.net
      serviceAccountRef: {name: app-secrets-reader}     # no namespace: the caller's
```

- Store each remote key as one secret whose value is a JSON object, e.g. secret `shop--web` with value
  `{"ConnectionStrings__Main": "Server=..."}`. ESO reads the properties from the JSON.
- Give each app namespace its own user-assigned managed identity. Add a federated credential for subject
  `system:serviceaccount:<namespace>:app-secrets-reader`, and set the identity's client id on that
  namespace's reader. `secrets.reader.annotations` / `readerAnnotations` in the rules set one client id for
  all namespaces; use a kustomize patch per app for one identity each.
- Grant *Key Vault Secrets User* to each identity **on its own secrets only** (role assignments scoped
  to `.../vaults/<vault>/secrets/<namespace>--<name>`), or give each app its own vault. A vault-wide
  assignment lets every namespace read every key.

### AWS Secrets Manager

`secrets.providers.aws` (IRSA role of each namespace's reader):

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata: {name: app-secrets}
spec:
  provider:
    aws:
      service: SecretsManager
      region: eu-north-1
      auth:
        jwt:
          serviceAccountRef: {name: app-secrets-reader}  # no namespace: the caller's
```

- The reader of each namespace carries `eks.amazonaws.com/role-arn`. The rules template it as
  `arn:aws:iam::<account>:role/app-secrets-{namespace}`, so create one IAM role per app namespace,
  trusted by the cluster's OIDC provider for `system:serviceaccount:<namespace>:app-secrets-reader`.
- Allow that role `secretsmanager:GetSecretValue` (and `DescribeSecret`) on
  `arn:aws:secretsmanager:<region>:<account>:secret:<namespace>--*` only.
- Store each remote key as a JSON secret (`shop--web` → `{"ConnectionStrings__Main": "..."}`).

### Other stores

Any [ESO provider](https://external-secrets.io/latest/provider/aws-secrets-manager/) works: add it under
`secrets.providers`, keep the store named `app-secrets`, and, where the provider supports it, name
`app-secrets-reader` without a namespace so each namespace keeps its own identity. A namespaced
`SecretStore` per app (`secrets.store.kind: SecretStore`) is the alternative when a provider has no
referent authentication. Apply it in each app namespace, and drop the namespaces from its references
(a namespaced store may only refer to its own namespace).
