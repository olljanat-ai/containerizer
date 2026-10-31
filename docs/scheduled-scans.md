# Organization scans

An organization scan reads every Git repository of one Azure DevOps organization (or Azure DevOps
Server collection), GitHub organization or GitLab group, assesses them, and deploys the ones that are
ready to the sandbox cluster. Administrators and operators define scans under
**Admin → Organization scans**: the organization, filters, where images and generated files go, and the
days and time (UTC) to run, or **Run now**. The scan worker on the appliance runs them. Before the first
scan, an administrator registers a read-only token for the organization and a write token for the output
repository ([source control tokens](source-control.md)), and allows the hosts on **Admin → Firewall**.

![An organization scan: runs, settings and change history](images/admin-scan-edit.png)

## What happens to each repository

1. **Listed** through the provider's API, including private and internal repositories the token can
   read. Every run lists the organization again: new repositories are added and processed in that run,
   renamed ones are followed by the provider's id, and ones that are gone are marked **removed**.
2. **Skipped automatically** when there is nothing to do, with the reason shown on **Admin →
   Repositories** ([automatic skips](#automatic-skips)).
3. **Cloned** shallow (default branch only, no tags, submodules, symlinks or LFS objects). Clones are
   kept on the appliance, and later runs only fetch the newest commit and reset the work tree to it.
4. **Assessed, built and run**: every feasible component is built and run hardened, failures are matched
   and fixed where a rule knows how, and the application is assessed again ([how it works](overview.md#how-it-works)).
   With **Ask the LLM** on, the LLM is consulted about what the rules are unsure of. Every assessment is
   stored, A or not, so the results pages and trends cover the whole organization.
5. **Selected**: a component is deployed only when it is a server component (web, worker, console, SPA)
   rated **A** on its own (including the stateless requirement), a Linux image can be generated for it,
   and it built and ran in the verification (or ran and only lacked its database or broker).
6. **Security gate**: lint, image build, vulnerability scan, licence policy and a run with the pod's
   security context ([security gate](overview.md#security-gate)). A component that fails is dropped, and
   the rest are gated again so the namespace, network policies and GitOps files cover only what is
   deployed.
7. **Images pushed** as `<registry>/<app>/<component>:<tag>` and `:git-<commit>`. The tag is `1.<yyyymmdd>.<hhmm>` of the run (semver, so Flux image automation can
   follow it). With the registry set to `localhost:5000/<path>`, images go to the appliance's own
   registry and need no credentials; an external registry needs push credentials in `worker.env`.
8. **Committed** to the output repository after every repository, so a long run can be followed and
   survives interruptions.

A repository that is skipped or has no A component loses its folder in the output repository, so the
sandbox stops deploying it. A repository that fails keeps its previous folder and is reported as failed.

A scan runs at most once at a time, and a paused scan does not run at all. If the worker was down at the
scheduled time, the scan runs once when it is back. **Cancel** stops a running scan after the repository
it is on. A scan that has run cannot be deleted (its history is kept): pause it.

## Automatic skips

| Automatic skip | Reason shown, for example |
| --- | --- |
| Has a Dockerfile | `found src/Api/Dockerfile`: the team already containerizes it |
| No application code | `14 files (.md 9, .yml 3, .json 2), no source code`: documentation, configuration, pipelines, SQL or scripts |
| Language not supported | `Ruby (32 files), but no project the tool can build (...)` |
| Nothing to deploy | `only library, test: 3 projects, nothing that runs on its own` |
| Not updated recently | `no update since 2026-01-07`: no commit on the default branch for the scan's *skip repositories not updated for* days (default 183) |
| Archived, Empty, Fork | as the provider reports (forks only with *skip forks*) |
| Left out by the filter | the scan's include/exclude regular expressions on `project/repository` |

Automatic skips are checked again at every run, so a repository that gets new commits or loses its
Dockerfile is processed again by itself. Archived, empty, filtered and stale repositories are decided
from the provider's API without fetching anything. An administrator can **Enable** a repository
(process it even though a skip applies), **Disable** it (never fetch it; it also leaves the sandbox at
the next run) or set it back to **Automatic**, with a note in the change history.

## Output repository layout

```
<Organization>/
  README.md                  every repository: status, rating, deployed and excluded components with reasons
  org-run.json               the same as data (merged across runs)
  <Project>/<Repository>/    one application (namespace <app>)
    kustomization.yaml       namespace, security policies, components, image tags
    namespace.yaml security.yaml HARDENING.md SECURITY.md MIGRATION.md cluster/
    containerizer.json       source URL, commit, images, digests, verification
    gitops/argocd/           AppProject + Application for this app
    gitops/flux/             tenant.yaml, git/sync.yaml, oci/, image automation
    <component>/             Dockerfile, Dockerfile.dockerignore, k8s.yaml, plan.json, sbom.cdx.json
sandbox/
  README.md namespaces.txt
  argocd/bootstrap.yaml      app-of-apps
  flux/bootstrap.yaml        GitRepository + root Kustomization
  idp/                       sandbox identity provider, when a component signs users in
```

The project folder is the Azure DevOps project, `_` for GitHub (no projects), or the GitLab subgroup
path with `--` for `/`. The **app name** (Kubernetes namespace and image path) is
`<project>-<repository>` in DNS form, prefixed with `app-` when it would be a system namespace, shortened
with a hash past 63 characters, and given a hash suffix when two repositories would map to the same name.

## The sandbox cluster

The appliance's k3s cluster deploys what the scans commit. Fill in `/etc/containerizer/sandbox.env`
(output repository URL, branch and a **read-only** token for it, separate from the scan's write token)
and allow the Git server on **Admin → Firewall**. Every 2 minutes the appliance then:

- puts the read-only token in the secret store for Flux's root sync and for every app namespace listed
  in `sandbox/namespaces.txt`;
- creates the root `GitRepository` and `Kustomization` of `sandbox/flux/`. The root creates each tenant
  (namespace with Pod Security "restricted", ServiceAccounts, a namespace-only RoleBinding, read access to
  its own secret store keys), and each app then reconciles as its own ServiceAccount.

Nothing in the output repository is a Secret: credentials are ExternalSecrets ([secrets](external-secrets.md)).
Apps that need a database, cache or object storage get one from the [lab services](lab-services.md), or a
restored copy of their [development database](dev-databases.md). Apps that sign users in with OpenID
Connect, SAML 2.0 or WS-Federation are pointed at the [sandbox identity provider](sandbox-idp.md). `kubectl` as root on the appliance shows
the result. To deploy the same output repository to another cluster, follow `sandbox/README.md` in it
(Argo CD or Flux).

## Security

- Each token is only sent where it belongs: the read-only token to its own server's API and its own
  organization's clone URLs, the write token only to push the output repository, which is never scanned
  ([how the tokens are protected](source-control.md#how-the-tokens-are-protected)). Git gets each token
  scoped to one repository URL, not in `.git/config`, the process list or clone URLs.
- Clones are made with symlinks off, no submodules, and the `file`/`ext` transports disabled. The
  scanner never executes scanned code, but building and running the images does execute the
  repositories' build steps. That is why the appliance is a dedicated machine with an outbound
  allow-list for every build.
- Registry credentials are written only to a temporary Docker config (mode 700) for the run.
- Nothing secret is written to the output repository, and build logs are not copied there.

## Metrics and Grafana

The worker exports Prometheus metrics about the scans, the worker process and the machine, and the
appliance's Grafana (`https://<appliance>/grafana/`, linked as **Grafana ↗** on the admin pages) has a
dashboard of them: scans running and waiting, time since the last successful run, progress of the
current run, repositories by state and latest result, time per repository, clones and pulls, pushed
images, and the machine's CPU, memory, disk and network.

![Grafana dashboard: scans, the machine running the worker, and the worker process](images/grafana-scans-dashboard.png)

Alert rules are included ([`monitoring/prometheus/containerizer-alerts.yml`](../monitoring/prometheus/containerizer-alerts.yml)):
worker down, run failed, no successful run for 8 days, runs not starting, repositories failing, disk
over 90 %, memory low. The metric names are listed in [`containerizer/metrics.py`](../containerizer/metrics.py).
