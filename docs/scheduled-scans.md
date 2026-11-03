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
     **Oldest commit first** bring the old ones to the top; select them (the box in the header selects every
     repository listed) and **Disable**, with a note.
   - **Admin → Repositories → Projects** lists the projects (Azure DevOps projects, GitLab subgroups)
     with their number of repositories and latest commit. Disabling a project disables all its
     repositories, including ones added to it later. GitHub organizations have no project level:
     disable the repositories, or pause the scan.
   ![Repositories after discovery, oldest commit first: a disabled project and a disabled repository](images/admin-repositories-discovered.png#only-light)
   ![Repositories after discovery, oldest commit first: a disabled project and a disabled repository](images/admin-repositories-discovered-dark.png#only-dark)

   ![Projects of an Azure DevOps organization with their latest commits, one disabled](images/admin-projects.png#only-light)
   ![Projects of an Azure DevOps organization with their latest commits, one disabled](images/admin-projects-dark.png#only-dark)

   Or work the other way round: set the scan's **New repositories** to **Disabled by default** before the first
   discovery. Every repository it finds then starts disabled (note *new repository: disabled by default*), and you
   enable only the ones to process. The setting also applies to repositories added to the organization later;
   repositories already found keep theirs.
3. **Run full scan** (or the schedule) then processes only the enabled repositories. Disabled ones are
   never cloned, and one that was deployed before leaves the sandbox at that run.

Disabled repositories and projects are also **hidden from the results pages**: the overview, the
trends and the application pages leave out the applications that come from them (they
stay on the admin pages). Enabling them again brings their results back at once. Repositories the scan
skips automatically are not hidden. Every change to a project or repository, with who made it and the
note, is in **Admin → Change history** (Projects, Repositories) and on the project's or repository's own
page.

<a id="sandbox-per-application"></a>**The sandbox of one application** can be turned off without disabling its
repository: **Admin → Applications** → the application → **Sandbox** → **Disable the sandbox** (administrators,
and the product owners of its product). It is on by default.

- **Off:** nothing of the application runs in the sandbox cluster. That includes its original components and its
  Make it A copies. The scans still assess it, so its results stay current, but they build and deploy nothing of it.
  New Make it A patches for it are made and verified, but not deployed.
- **The files stay:** its folders in the output repository and its images in the appliance's registry are kept.
  `sandbox/` leaves them out, so Flux removes them from the cluster.
- **On again:** `sandbox/` lists them again, and Flux deploys the same manifests with the same images (the
  patched ones of a Make it A copy too), without a build. The next scan of its repository then builds the original
  as usual.

The LLM queue runner applies a change within a few minutes: it regenerates `sandbox/` in every output repository
and commits it. A scan also leaves the application out when it writes `sandbox/`. The change history records who
switched it and when. A Make it A copy still expires after its 7 days, also while the sandbox is off.

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
6. **Security gate**: lint, image build, vulnerability scan and a run with the pod's
   security context ([security gate](overview.md#security-gate)). A component that fails is dropped, and
   the rest are gated again so the namespace, network policies and GitOps files cover only what is
   deployed.
7. **Images pushed** to the appliance's own registry as `localhost:5000/sandbox/<app>/<component>:<tag>` and
   `:git-<commit>`, which the sandbox cluster pulls from without credentials. The tag is `1.<yyyymmdd>.<hhmm>` of
   the run (semver, so Flux image automation can follow it). Scans have no registry setting: an external
   registry is for the [build pipelines](build-pipelines.md) generated for your real environment, not for the sandbox.
8. **Committed** to the output repository (chosen in the scan's settings among the repositories with a write
   token under **Source control**; none: the results stay on the worker) after every repository, so a long run can be followed and
   survives interruptions.

A repository that is skipped or has no A component loses its folder in the output repository, so the
sandbox stops deploying it. A repository that fails keeps its previous folder and is reported as failed.

A scan runs at most once at a time, and a paused scan does not run at all. If the worker was down at the
scheduled time, the scan runs once when it is back. **Cancel** stops a running scan: no further repository
is started, its LLM calls stop at once (the connection to the LLM server is closed, so a self-hosted LLM stops
generating), and the repositories in progress end after the step they are on. A scan that has run cannot be
deleted (its history is kept): pause it.

**Repositories in parallel** (the scan's settings, 1 to 8, default 1): how many repositories a full scan or
**Scan now** processes at the same time. The assessment is CPU-bound, so each repository gets its own process
and the scan uses that many CPU cores. Results are committed to the output repository one at a time, in the
order the repositories finish. Each one also needs its own memory (about 1 GB, more with **Build and run**)
and disk space, and with **Ask the LLM** each asks the LLM on its own, so a self-hosted LLM gets up to that
many requests at once (give llama.cpp that many slots, `--parallel`). Start with the number of CPU cores minus
one, and lower it if the machine runs short of memory.

## Progress of a run

Each full run has a **Progress** page (the link under its status in the scan's **Runs** table, or next to the
progress count in the scan list). It reloads itself every 10 seconds while the run is in progress, and shows:

- **In progress**: each repository being scanned, the step it is on (Cloning or Pulling, Looking for application
  code, Assessing (rules), LLM review, Verifying: build and run, Assessing again, Generating files, Development
  database, Security gate: build, scan, run, Building images, Pushing images, Writing the output files), how long it
  has been on that step and on the repository, and what it waits for inside the step (the LLM call, the components
  in the security gate). A step that has taken more than 15 minutes is marked **slow**.
- The pace (the average time a repository has taken so far) and an **estimated end** at that pace, and what the run
  as a whole does between repositories (listing the repositories, committing to the output repository, checking
  the sandbox).
- **Where the time goes**: each step's total time over the repositories of the run, its share, and its average per
  repository, so you can see whether a slow scan waits for the LLM, for builds and verification, for the security
  gate or for git. With **Repositories in parallel** above 1, the times are summed over the processes.
- **Finished most recently** and **Slowest**: the repositories of the run with their result and how long each took.

![Progress of a running organization scan: repositories in progress and where the time goes](images/admin-scan-run-progress.png#only-light){ .cz-shot }
![Progress of a running organization scan: repositories in progress and where the time goes](images/admin-scan-run-progress-dark.png#only-dark){ .cz-shot }

Typical fixes when one step dominates: **LLM review** — queue the LLM reviews ([**LLM reviews**: Queued](#the-llm-queue)) so the
scan uses the rules only, or give a self-hosted LLM more slots; **Verifying** and **Security gate** — scan more
repositories in parallel if the machine has the cores and memory; **Cloning** — the first run clones everything,
later runs only pull. The [Grafana dashboard](#metrics-and-grafana) has the same run over time.

## Repositories with several applications

A scan assesses each repository as one application. A mono-repo that holds several applications, for example
one folder per application under `apps/` or `scenarios/`, would then get one rating for all of them. On the
repository's page (**Admin → Repositories → the repository**), **Applications in this repository** →
**One application per folder matching** a folder pattern relative to the repository (`scenarios/*`,
`services/*`, `teams/*/apps/*`) makes each matching folder its own application:

- its own assessment, rating and results page (the application's source path is the folder), owner and
  product mapping;
- its own sandbox namespace `<repository app>-<folder>` and its own folder in the output repository,
  `<Organization>/<Project>/<Repository>@<folder>`;
- the repository's row sums them up: deployed when one of them is, the best rating, and a table of the
  folders with their results on the repository's page.

![A repository split into one application per folder: the folders with their results, and the setting](images/admin-repository-split.png#only-light)
![A repository split into one application per folder: the folders with their results, and the setting](images/admin-repository-split-dark.png#only-dark)

The repository is still cloned once, and enabling or disabling it applies to all its applications. Folders
that stop matching leave the sandbox at the next scan, and switching back to **The whole repository is one
application** removes the per-folder ones. The applications assessed before the change stay in the
history: hide the old whole-repository one on its application page. Who changed the setting, and when, is in
the change history.

A repository assessed as one application that looks like several (at least three folders at the same level
that each have their own solution, `package.json`, `pom.xml`, `build.gradle`, `go.mod` or `pyproject.toml`, and
hold nearly all of the repository's) gets a note on its page with the pattern filled in. Nothing is split
automatically: it changes the applications' identities in the results, so an administrator decides.

![A repository that looks like 33 applications: the note, and the pattern filled in](images/admin-repository-split-hint.png#only-light)
![A repository that looks like 33 applications: the note, and the pattern filled in](images/admin-repository-split-hint-dark.png#only-dark)

The command line does the same with `containerizer org ... --split '<project>/<repository>=<pattern>'`
(GitHub has no projects: `_/<repository>`).

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
    <component>/             Dockerfile, Dockerfile.dockerignore, k8s.yaml, plan.json
    pipeline/<provider>/     the image build pipeline for the application's own repository (build-pipelines.md)
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

![Organization scan settings: Ask the LLM with queued LLM reviews](images/admin-scan-llm-mode.png#only-light){ .cz-shot }
![Organization scan settings: Ask the LLM with queued LLM reviews](images/admin-scan-llm-mode-dark.png#only-dark){ .cz-shot }

**Admin → LLM queue** (administrators and operators) shows:

- the jobs waiting, in the order the runner takes them: the repository and component, why it is queued
  (uncertain, or a second opinion on the rules' blocker or rewrite verdict) and the estimated tokens and
  time. **Top**, **Up**, **Down** and **Bottom** move a job; new jobs still go in by their priority.
  **Skip** takes one out of the queue. **Cancel** stops a job that is being asked: the runner sees it within a
  few seconds, its LLM calls stop at once (the connection is closed, so a self-hosted LLM stops generating), a
  refactoring order does not go on to its build, the sandbox or the next order of an LLM-heavy chain, and the job
  is recorded as skipped (*cancelled by …*); **Requeue** starts it again;
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
  CPU below the limit (0: the load is not looked at); **Parallel requests**, as many as the worker's own
  LLM answers at once (a registered LLM has its own, see [several LLMs at once](source-control.md#the-llm)); and
  the **built-in LLM's order** and **jobs up to** beside the registered LLMs (the appliance only). The page lists
  the LLMs in their order, and each job goes to the first that takes its size and has a free request. The runner
  looks at them before each job; a job it has started finishes.
- **Approval**: which kinds of job wait for an administrator's approval (component reviews, refactoring orders,
  egress reviews and link reviews; all of them by default), and the rules that approve some by themselves:
  **Approve automatically under** a number of estimated input tokens (0: none, every job of the ticked kinds
  waits), **while fewer jobs are queued or running than** a number (0: any length of the queue). A small job that
  arrives when the queue is full waits, and is approved by itself, highest priority first, as the queue gets
  shorter; a big one always waits for an administrator. Each automatic approval says so on the job
  (*automatic: estimated under 2,000 tokens and the queue had room*). **Approve all** approves every waiting job.
- **Reject automatically after** a number of hours (0: never): a job waiting for approval or queued that long
  (counted from its approval when it had one) is skipped, with the reason. **Requeue** starts its wait again.

After a button on a job (move, skip, approve, reject, requeue) the page opens at that job, or at the one that takes
its place, not at the top.

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
