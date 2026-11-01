# Organization scans

An organization scan reads every Git repository of one Azure DevOps organization (or Azure DevOps
Server collection), GitHub organization or GitLab group, assesses them, and deploys the ones that are
ready to the sandbox cluster. Administrators and operators define scans under
**Admin → Organization scans**: the organization, filters, where images and generated files go, and the
days and time (UTC) to run, or **Run full scan**. The scan worker on the appliance runs them. Before the first
scan, an administrator registers a read-only token for the organization and a write token for the output
repository ([source control tokens](source-control.md)), and allows the hosts on **Admin → Firewall**.

![An organization scan: runs, settings and change history](images/admin-scan-edit.png#only-light)
![An organization scan: runs, settings and change history](images/admin-scan-edit-dark.png#only-dark)

## Discover first, then scan

A scan runs in two phases, so time is not spent on repositories nobody uses any more:

1. **Discover** (on the scan's page) lists the projects, every Git repository in them and each
   repository's latest commit on its default branch, through the provider's API only. Nothing is cloned,
   assessed, built or pushed, and the output repository is not touched, so even a large organization is
   listed in minutes. Discovery also marks the [automatic skips](#automatic-skips) the API alone shows
   (archived, empty, fork, not updated recently, left out by the filter).
2. An administrator or operator reviews the result and **disables** what is deprecated:
   - **Admin → Repositories** shows each repository's latest commit. **No commit for a year** and
     **Oldest commit first** bring the old ones to the top; select them and **Disable**, with a note.
   - **Admin → Repositories → Projects** lists the projects (Azure DevOps projects, GitLab subgroups)
     with their number of repositories and latest commit. Disabling a project disables all its
     repositories, including ones added to it later. GitHub organizations have no project level:
     disable the repositories, or pause the scan.
   ![Repositories after discovery, oldest commit first: a disabled project and a disabled repository](images/admin-repositories-discovered.png#only-light)
   ![Repositories after discovery, oldest commit first: a disabled project and a disabled repository](images/admin-repositories-discovered-dark.png#only-dark)

   ![Projects of an Azure DevOps organization with their latest commits, one disabled](images/admin-projects.png#only-light)
   ![Projects of an Azure DevOps organization with their latest commits, one disabled](images/admin-projects-dark.png#only-dark)

3. **Run full scan** (or the schedule) then processes only the enabled repositories. Disabled ones are
   never cloned, and one that was deployed before leaves the sandbox at that run.

Disabled repositories and projects are also **hidden from the results pages**: the overview, the
trends, the SBOM pages and the application pages leave out the applications that come from them (they
stay on the admin pages). Enabling them again brings their results back at once. Repositories the scan
skips automatically are not hidden. Every change to a project or repository, with who made it and the
note, is in **Admin → Change history** (Projects, Repositories) and on the project's or repository's own
page.

**Scan now**, on a project's or repository's page or for the ones selected in the lists, runs a full
scan of only those, outside the schedule, for example after a fix was pushed. The other repositories
keep their results from the last full run. Disabled ones stay disabled; a run of the scan that is
already queued or running has to finish first.

Discovery can be run again at any time, for example before a scheduled run, to see the new projects and
repositories first. Scheduled runs are always full scans; new repositories found by them are processed
in that run unless their project is disabled.

## What happens to each repository

1. **Listed** through the provider's API, including private and internal repositories the token can
   read. Every run (discovery or full) lists the organization again: new projects and repositories are
   added (a full run processes the new repositories in that run), renamed ones are followed by the
   provider's id, and ones that are gone are marked **removed**. Repositories an administrator disabled,
   or whose project is disabled, stop here.
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
| Has a Dockerfile | `found src/Api/Dockerfile`: the team already containerizes it. Enabled, it is moved from Docker Swarm, Compose, Nomad, Azure Container Apps or ECS to Kubernetes ([platform migrations](platform-migration.md)) |
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
the next run and its results are hidden from the results pages) or set it back to **Automatic**, with a
note in the change history. A disabled project overrides the settings of its repositories.

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

## The LLM queue

With **Ask the LLM** on, **LLM reviews** chooses when the LLM is asked:

- **Inline** (the default): during the scan, as before.
- **Queued**: the scan asks the LLM nothing and the rules decide; the component reviews wait in the
  LLM queue and their answers are used by the next scan of each repository
  ([queued LLM reviews](source-control.md#queued-llm-reviews): what is queued, in what order, and how an
  answer takes effect). Use it with a slow self-hosted LLM. LLM-heavy mode needs inline reviews.

**Admin → LLM queue** (administrators and operators) shows:

- the jobs waiting, in the order the runner takes them: the repository and component, why it is queued
  (uncertain, or a second opinion on the rules' blocker or rewrite verdict) and the estimated tokens and
  time. **Top**, **Up**, **Down** and **Bottom** move a job; new jobs still go in by their priority.
  **Skip** takes one out of the queue;
- at the top, the totals: jobs waiting and being asked, by kind (uncertain, second opinion); their
  estimated tokens in and out; the LLM time they need at the measured speed with the parallel requests
  set, for example *~7 h 20 min of LLM time (3 in parallel)*, and when they would all be done if the
  queue ran without a pause; what the estimate is learned from; and, outside the hours, when they next
  start;
- the finished jobs: each answer (verdict and confidence, the reasoning and the question on the job's
  page), with the tokens and time it really took, failures (a job is tried three times, five minutes
  apart and more, before it fails) and skipped jobs. **Requeue** puts a failed or skipped one back;
- repositories whose reviews are all answered since their last scan, with **Re-scan now**: a full scan of
  only that repository, so the answers apply without waiting for the schedule;
- the settings: **Paused**; the days and hours (UTC) the runner may start jobs (no day selected: every
  day; From and To empty: all day; 22:00 to 06:00 runs past midnight, and the night belongs to the day it
  started); **Only when idle**: no organization scan running and the machine's 1-minute load average per
  CPU below the limit (0: the load is not looked at); and **Parallel requests**, as many as the LLM
  server answers at once (1 for a CPU server). The runner looks at them before each job; a job it has
  started finishes.

Every change to a job (queued, moved, skipped, requeued, answered, failed) and to the settings is in
**Admin → Change history**.

**Estimates.** Each queued job's input tokens are estimated from the length of its question (3.5
characters a token to begin with) and its output from the answers before it (1,500 tokens to begin
with). From every answer the runner learns, separately for each LLM (server and model): the characters
per token of its tokenizer, the answer length of each kind of job, and its speed (prompt and generation
tokens per second when the server reports its timings, as llama.cpp does, otherwise tokens per second
from the time each answer took). Each figure is a moving average that gives the newest answer a weight
of 0.2. The queue's time is the sum of the jobs' times divided by the parallel requests; the speeds are
as measured with the parallel requests of the time, so this is a rough estimate. It does not include
waiting for the hours or for the machine to be idle. Until an LLM has answered once, the page says
*time: learning*.

**The runner** is `containerizer llm-queue`, a process of its own next to the scan worker
(`containerizer-llm-queue` on the appliance). It uses the worker's database login, opens the LLM
registered under Source control & LLM with the worker's key (or uses the worker's environment
settings), writes into the worker's answer cache, and serves its metrics on port 9465: the jobs by
status, kind and reason, the oldest waiting job, the estimated tokens and LLM time waiting, jobs finished, and the
LLM usage of its answers (feature `assessment-queued`). On another machine, give it the worker's
settings and the same `CONTAINERIZER_AI_CACHE` (shared), or rely on the next scan finding the answer in
the queue; [`monitoring/systemd/containerizer-llm-queue.service`](../monitoring/systemd/containerizer-llm-queue.service)
is a unit for it. A job it is asking when it stops goes back to the queue.

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
current run, repositories by state (`disabled_admin` counts repositories disabled directly or through
their project) and latest result, time per repository, clones and pulls, pushed images, LLM usage
(calls, tokens and estimated cost by repository and feature, [platform migrations](platform-migration.md#llm-usage)),
the [LLM queue](#the-llm-queue) (jobs waiting, the oldest one, the runner open or waiting, jobs answered
and failed), and the machine's CPU, memory, disk and network.

![Grafana dashboard: scans, the machine running the worker, and the worker process](images/grafana-scans-dashboard.png#only-light)
![Grafana dashboard: scans, the machine running the worker, and the worker process](images/grafana-scans-dashboard-dark.png#only-dark)

Alert rules are included ([`monitoring/prometheus/containerizer-alerts.yml`](../monitoring/prometheus/containerizer-alerts.yml)):
worker down, run failed, no successful run for 8 days, runs not starting, repositories failing, disk
over 90 %, memory low. The metric names are listed in [`containerizer/metrics.py`](../containerizer/metrics.py).
