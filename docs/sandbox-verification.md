# Sandbox verification: did it really deploy?

`containerizer org` builds, runs and gates every component on the build agent, then commits Argo CD
and Flux configuration so the sandbox cluster deploys them. Sandbox verification closes the loop: it
waits until the GitOps tool has synced the pushed commit, reads back what Kubernetes did with each
component and records one status per component.

| Status | Meaning |
| --- | --- |
| `healthy` | **Deployed and healthy**: the rollout finished, every replica is ready, and no container restarted while it was watched (`--settle`, default 60 s). |
| `failing` | **Deployed but failing (reason)**: crash loop, image cannot be pulled, missing Secret, pods cannot be scheduled, Pod Security rejected them, the rollout hit its deadline, a failed CronJob run, or the Argo CD / Flux sync itself failed. |
| `pending` | Argo CD / Flux did not sync the commit, or the rollout did not finish, within `--sandbox-timeout` / `--timeout` (default 900 s). |
| `scheduled` | A CronJob that is deployed but has not run yet: there is no run to judge. |
| `not-found` | No Argo CD Application or Flux Kustomization for the app (bootstrap not applied), or the workload does not exist. |
| `error` | The read-back itself failed, for example *forbidden* because `sandbox/verify-rbac.yaml` was not applied. |
| `skipped` | No cluster access: no `kubectl`, no kubeconfig, or the API server is unreachable. The run goes on and says why. |

```sh
# at the end of an organization run
python -m containerizer org --provider github --org acme --registry myacr.azurecr.io/sandbox \
  --output-repo https://github.com/acme/sandbox-deployments.git \
  --verify-sandbox --kubeconfig ~/.kube/sandbox-verifier --sql "$CONTAINERIZER_SQL"

# or later, on a checkout of the output repository (e.g. after the bootstrap was applied)
python -m containerizer sandbox verify --output-dir sandbox-deployments --kubeconfig ~/.kube/sandbox-verifier
```

Without a cluster nothing breaks: the step prints `sandbox verification skipped: <why>` and the
report says *not checked*. `sandbox verify` exits 0 unless `--fail-on-unhealthy` is given and a component
is not `healthy` or `scheduled`; the organization run's exit code does not depend on it.

## What is checked

1. **Sync**: for each app, the Argo CD Application `argocd/<app>` (`status.sync.revision` is the pushed
   commit, or a later commit that contains it, and `Synced`; a failed sync of that commit is `failing`),
   or, when there is none, the Flux Kustomization `<app>/<app>` (`lastAppliedRevision` is the commit and
   `Ready`; `HealthCheckFailed` counts as applied, so the workloads say what is wrong). `--gitops argocd`
   or `flux` picks one. All apps are polled together until synced or the timeout.
2. **Rollout** of each component's workloads, taken from its generated `k8s.yaml`: Deployment and
   StatefulSet replicas updated, ready and available; `ProgressDeadlineExceeded` and `ReplicaFailure`;
   container states (`CrashLoopBackOff`, `ImagePullBackOff`, `CreateContainerConfigError`, `OOMKilled`, ...),
   restart counts and unschedulable pods. A CronJob is judged by its newest Job.
3. **On failure**: the newest Warning events of the workload, its ReplicaSets and pods, and the last
   80 lines of the failing container's log (the previous container's, after a restart). Logs are
   redacted (passwords, tokens, keys, credentials in URLs, JWTs) and never written to the output
   repository; only the database keeps them, out of the reader role's reach.
4. **Diagnosis** with [`rules/50-failures.yaml`](../rules/50-failures.yaml): rules with
   `stage: cluster` read the pod states and events (image pull, unsigned image, missing Secret,
   Pod Security, quota, scheduling, out of memory, read-only file system), the `run` rules that the local
   build-and-run uses read the app's log (Windows-only APIs, missing database, missing settings, ...).

## Where the results go

- **Output repository**: `sandbox/HEALTH.md` (a table per component) and `sandbox/health.json`, committed
  and pushed by the organization run. `write_sandbox` rewrites `sandbox/` on every run, so an old report
  never outlives the deployment it describes.
- **Results database** (with `--sql` or `CONTAINERIZER_SQL`): one row per component and check in
  `containerizer.SandboxCheck` (status, reason, ready/desired, restarts, the rule and outcome that explained
  it, the Warning events, the redacted log tail), schema version 5. `vSandboxLatest` has the newest check of
  every application without the log tail; the reader role can read only the view. Components are matched
  to their application by the source key recorded at deploy time (`containerizer.json`) and their
  project path. Run `db init` after upgrading.
- **Web UI**: the application page gets a *Sandbox cluster* column in the component table, and each
  component's section says what the cluster showed: status, why, what caused it (the application, a
  missing external service or a setting of the sandbox cluster) and the Warning events.

## Learning from the cluster

A failure the build agent did not see is evidence for the learning loop, so the next run knows it:

| Outcome of the matching rule | What is learned |
| --- | --- |
| `code`, `platform` (e.g. `PlatformNotSupportedException`, out of memory) | a finding in `rules/learned/findings.yaml` for that project, `category: runtime-observed`, `observed_in: sandbox-cluster`, with an `evidence` list (date, app/component, pod states, events, the rule that matched). The next assessment shows it; a blocker or rewrite keeps the component from A and so out of the sandbox. |
| `retry` with a `learn` section (e.g. a read-only folder) | a plan rule in `rules/learned/plan.yaml`, so the next generated manifest has the fix |
| `external` (database, broker, identity provider), `environment` (pull secret, signature, quota, scheduling) | nothing: these are not the application's fault. They are reported, with the reason. |

Unexplained failures are reported but not learned. `--no-learn` turns learning off for `sandbox verify`.
Learned rules are plain YAML: review them like any learned rule.

## Least-privilege access

The verifier only reads. `containerizer org` writes `sandbox/verify-rbac.yaml` with:

- Namespace `containerizer-verify` and ServiceAccount `containerizer-verifier` (no token mounted);
- in every app namespace a Role and RoleBinding: `get`, `list` on Deployments, StatefulSets, CronJobs,
  Jobs, Pods and Events, `get` on `pods/log`, and `get` on the app's own Flux Kustomization by name;
- in `argocd` a Role and RoleBinding: `get` on the generated Applications, by name.

There is no ClusterRole, no write verb, no `watch`, and no access to Secrets or ConfigMaps. `kubectl
version`, which the step uses to see whether the cluster is reachable, is allowed for every
authenticated identity by default. Pod logs can contain what an application printed, which is why they
are redacted and kept out of the repository and out of the reader role.

```yaml
# one app namespace (sandbox/verify-rbac.yaml has one pair per namespace in namespaces.txt)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: containerizer-verifier, namespace: shop-floor-ci-demo}
rules:
  - {apiGroups: [apps], resources: [deployments, statefulsets], verbs: [get, list]}
  - {apiGroups: [batch], resources: [cronjobs, jobs], verbs: [get, list]}
  - {apiGroups: [""], resources: [pods, events], verbs: [get, list]}
  - {apiGroups: [""], resources: [pods/log], verbs: [get]}
  - {apiGroups: [kustomize.toolkit.fluxcd.io], resources: [kustomizations], resourceNames: [shop-floor-ci-demo], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: containerizer-verifier, namespace: shop-floor-ci-demo}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: containerizer-verifier}
subjects: [{kind: ServiceAccount, name: containerizer-verifier, namespace: containerizer-verify}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: containerizer-verifier, namespace: argocd}
rules:
  - {apiGroups: [argoproj.io], resources: [applications], resourceNames: [shop-floor-ci-demo], verbs: [get]}
```

Apply it as a cluster administrator once the app namespaces exist (after the first sync), and again when
apps are added. Then give the pipeline a short-lived token instead of a long-lived Secret:

```sh
kubectl apply -f sandbox/verify-rbac.yaml
TOKEN=$(kubectl -n containerizer-verify create token containerizer-verifier --duration=2h)
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt
kubectl --kubeconfig verifier.kubeconfig config set-cluster sandbox --server=https://<api-server> \
  --certificate-authority=ca.crt --embed-certs
kubectl --kubeconfig verifier.kubeconfig config set-credentials verifier --token="$TOKEN"
kubectl --kubeconfig verifier.kubeconfig config set-context sandbox --cluster=sandbox --user=verifier
kubectl --kubeconfig verifier.kubeconfig config use-context sandbox
```

In a pipeline, keep that kubeconfig in the secret store (GitHub Actions secret, Azure DevOps secure file)
and pass its path with `--kubeconfig`; better still, use the cloud's workload identity (AKS: Entra ID
with Kubernetes RBAC, EKS: access entries, GKE: Workload Identity Federation) mapped to the same Roles,
so there is no token to store. When the tool runs inside the cluster, run it as the
`containerizer-verifier` ServiceAccount with `automountServiceAccountToken: true` on that pod only.
The token in a kubeconfig is never passed on the command line or written to the output.

## Testing

`tests/test_sandbox.py` fakes the cluster at the `kubectl` boundary (sync states, rollouts, crash loops,
image pulls, CronJobs, diagnosis, learning, redaction, report, RBAC). `tests/test_sandbox_cluster.py`
runs against a real cluster when `CONTAINERIZER_TEST_KUBE` points at an admin kubeconfig of a disposable
one: CI creates a kind cluster, deploys a healthy web app, a crash loop, an image that cannot be pulled
and a CronJob, applies the generated RBAC, checks with `kubectl auth can-i` that the verifier can read
nothing else, and runs the read-back with a short-lived ServiceAccount token.
