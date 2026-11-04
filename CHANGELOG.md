# Changelog

Releases are tagged `vX.Y.Z`: bump `containerizer/__init__.py` and this file, then run the **release** workflow
by hand on `main` with the version, and it tags the commit and releases from the tag (or push the tag `vX.Y.Z` on `main`
yourself: a tag push starts the release too). Each release publishes the appliance OS image to
`ghcr.io/olljanat-ai/containerizer-appliance` (signed with cosign by the release workflow) and the ISO,
qcow2 and VHDX images as release assets.

## Unreleased

- Grafana's **Flux** dashboard starts with whether the sandbox is connected to the output repository at all: what
  `cz-sandbox` last found (connected, or `sandbox.env` without a repository URL or token, the secret store or Flux
  not ready) and when, the root sync's GitRepository and Kustomization (missing, not ready with the reason, or
  ready), and the applications' containers that do not start or restart. `cz-sandbox` used to stop without a word
  when `sandbox.env` was empty: it now logs each change of its state and writes it for the worker's metrics
  (`containerizer_sandbox_connection`). New alerts: `ContainerizerSandboxNotConnected`,
  `ContainerizerSandboxRootSyncNotReady`.
- Refactoring: a package reference to a part of ASP.NET Core (`Microsoft.AspNetCore.HttpOverrides` and the like)
  in a .NET Core 3.0+ project is removed without the LLM when NuGet cannot find it (NU1101, NU1102). Those parts
  ship with the shared framework and their packages end at 2.x. The LLM's answers no longer add them, and a
  repair may now remove a package the earlier change added when it does not exist. Before, the repair rounds kept
  the reference and the patched copy never built.

## 0.9.2 (2026-11-04)

- An application can get an **output repository of its own**: **Admin → Applications** → the application →
  **Output repository** (administrators): a repository with a write token, a branch and a folder (`deploy` by
  default). Its files are moved there once, with their Flux files pointed at it, as the starting point of its
  real deployment; the sandbox keeps deploying it, from there. The scans then assess it only and leave its files
  to its team. **Back to the scan's output repository** undoes it. Schema 36.
- A Make it A copy's folder in the output repository holds the order's patch, `make-it-a.patch`.
- **Build again (no LLM)** on a Make it A order: the same patch is built, run, assessed and deployed to the
  sandbox again without an LLM call, for a build that failed outside the code (a firewall rule, a package mirror).
- A Make it A order for newer code starts from the application's earlier working patch: the files it still
  applies to are kept without asking the LLM, and only the rest are edited again. When the newer code did not touch
  the patched files, the order makes no LLM call. The order page says which patch it started from.
- *Made A by a patch* (front page, bulk Make it A) counts only a patch made for the commit the latest scan
  assessed. Before, an application whose code had changed since stayed marked and was not ordered again.
- An organization scan writes the build pipeline of its own provider only (GitHub Actions, GitLab CI/CD or Azure
  Pipelines) into `pipeline/`. Before, a repository whose URL did not name the provider (a self-hosted server)
  got all three.
- Argo CD support is removed: Flux is the only GitOps tool, in the output repository and in the sandbox. Each
  application folder gets `gitops/flux/` only, and `sandbox/` only `flux/`. The `gitops/argocd/` folders and
  `sandbox/argocd/` of earlier runs are removed at the next scan. `containerizer sandbox verify` reads Flux
  Kustomizations only, and `sandbox/verify-rbac.yaml` no longer has a Role in `argocd`.

## 0.9.1 (2026-11-04)

- A Make it A copy, or an application in a scan, that is not deployed because no component qualifies now says why
  for each component: the rating, the build and run, or the security gate. The order page lists them, also for
  orders made before.
- Make it A copies in the sandbox no longer expire after 7 days (`CONTAINERIZER_SANDBOX_VARIANT_DAYS` is gone).
  A copy stays until a scan assesses another commit of its application, so its patch no longer matches, or until
  someone removes it. The order page then says *Replaced by newer code*, with both commits.
- The sandbox can be turned off per application: **Admin → Applications** → the application → **Sandbox**. It is
  on by default, and administrators and the application's product owners can switch it. Off: the scans
  still assess the application but build and deploy nothing of it, and new Make it A patches are not deployed.
  Its folders in the output repository and its images in the registry stay, only out of `sandbox/`. On again
  brings the same manifests and images back, Make it A copies included, without a build. The LLM queue runner
  applies a switch within a few minutes. Schema 35 adds `Application.SandboxEnabled`.
- Make it A: the front page, the refactoring pages and the docs no longer say the patched copy runs "beside the
  original". It runs as its own application, and an organization scan has only the original's A-rated components
  in the sandbox, often none.

## 0.9.0 (2026-11-03)

- The *Dependencies and licences* page and the software bills of materials behind it are gone:
  - the component package pages and the application page's Packages column;
  - the `/api/v1/.../sbom` endpoints and the `containerizer sbom` command;
  - the security gate's licence policy, which no longer fails a component;
  - the SBOM attached to each pushed image, and ORAS in the appliance image.
  Schema 34 drops their tables. The build pipelines generated for the applications' own repositories still make
  an SBOM with Syft in their CI: its version is now `pipelines.syft_image` in `rules/60-security.yaml`.
- Build pipelines are only in the output repository now (`<organization>/<project>/<repository>/pipeline/`, written
  by every organization scan) and from `containerizer pipeline` on a checkout. The application page's *Build
  pipeline* box and its `.patch` and `.tar.gz` downloads are gone, and the assessment no longer stores the
  pipeline's spec. A pipeline never pushes to the appliance's own registry (`localhost:5000`): without
  `--registry` it uses its provider's registry.
- Organization scans and Make it A variants always push to the appliance's own registry
  (`localhost:5000/sandbox`). The scan form no longer has *Image registry*, *Push images* or *Image pull secret*,
  and a registry stored by an older scan is ignored. This also fixes Make it A variants that were not deployed
  with "the registry host is not allowed on this machine (CONTAINERIZER_WORKER_HOSTS)": the LLM queue runner did
  not allow `localhost`. External registries remain for the build pipelines generated for the real environment.
- kubemg on the appliance serves HTTPS on loopback too (`KUBEMG_TLS_ENABLED=true`). Its setup checklist blocked on
  "HTTPS is off" (kubectl will not send a token over plain HTTP, so generated kubeconfigs and exec would not
  work). Its certificate is issued by a local CA that only Caddy trusts, made on the first start in
  `/var/lib/containerizer/kubemg/tls`, and the setup check now says `ok`.
- Make it A: every B application: an application that a verified patch makes A already links to that patch and
  is not queued again from the page.
- Releases no longer have the VHDX image or the SPDX SBOM file (`.spdx.json`), and the SBOM is no longer
  attested to the appliance image. On Hyper-V, install from the ISO (generation 2, Secure Boot template
  Microsoft UEFI Certificate Authority).

## 0.8.4 (2026-11-03)

- Verification on the appliance: the build context is made readable before `docker build`. The appliance's
  services run with `UMask=0077`, so their clones were `0600`. `dotnet publish` kept that mode, and the image's
  non-root user could not read the app's own `appsettings.json` ("Access to the path '/app/appsettings.json' is
  denied"). This affected every .NET component verified on the appliance, scans included. The clones stay under
  `0700` work folders.
- Refactoring: a NuGet downgrade is also found from the dependency paths NuGet lists ("App -> Lib 8.0.11 ->
  P (>= 5.1.6)" and "App -> P (>= 5.1.1)"). A failed build's log, on the order page and for the repair, keeps the
  error lines before Docker's own report. Before this, only the last 1,500 characters were kept, which cut off
  NuGet's "Detected package downgrade" line, so the downgrade was not raised.

## 0.8.3 (2026-11-03)

- Refactoring: NuGet package downgrades (NU1605) are fixed without the LLM. A package reference the LLM adds below
  the version a referenced project uses is raised to it, and a downgrade the build reports is raised to the
  version NuGet names. The prompt lists the packages of the referenced projects. Before this, a Make it A chain
  could repeat the same build error until it reached the 30-order limit, as seen with field-service.
- Refactoring instructions: never remove a feature to make a finding go away (folders, file writes, state, the
  app's own database setup), never write a user name or password into a file, and for Windows integrated security
  leave the setting for Windows and let the container's connection string come from a secret. The local model had
  removed `Directory.CreateDirectory` for photo folders and the nightly job's state write, and written
  `User ID=sa;Password=…` into `appsettings.json`.
- Refactoring: an edit that removes a `Directory.CreateDirectory` or a file write, or writes a credential into a
  file, is refused and asked again once with the reason. The folder of an embedded database file may still go.
- LLM-heavy chains: after 3 orders in a row that fail with the same errors, the next order starts over from the
  original code, with those errors in its prompt and no reuse of the stuck attempt's answers. A chain starts over
  at most twice, and the order page says when an order is a fresh start.
- Verification and generation: a writable folder is never mounted on the app folder (`/app`) or above it, which
  would hide the application ("The application 'X.dll' does not exist"). The attempt's note says that the app
  writes into its own folder.

## 0.8.2 (2026-11-03)

- kubemg on the appliance: where its `admin` password is is now said in its journal at each start
  (`journalctl -u containerizer-kubemg`), and `/usr/lib/containerizer/bin/cz-kubemg password` prints it. kubemg's
  sign-in page points to its log, which has no password, because the appliance sets it.
- kubemg: the six public Helm chart repositories kubemg adds on its first start are deleted while the generated
  `admin` password works. The outbound allow-list blocks them, so their hourly sync logged a warning for each.
- docs: what kubemg's log has in it (audit lines, no level to set).

## 0.8.1 (2026-11-03)

0.8.0 was not published (its image push to GHCR failed): 0.8.1 includes it (kubemg, below).

### Refactoring
- Repairs (**Fix it with the LLM**, Make it A's repair rounds, LLM-heavy chains) now see a project's own build
  errors, which have no line: NuGet's (e.g. NU1605, a package downgrade between two projects) and MSBuild's. Before,
  only compiler errors with a line counted, so the repair asked about the patch's files instead of the project,
  with the end of the log, which is Docker's report of the failed step, not the error. Without any such error, a
  repair now gets the log's error lines.
- Repairs and orders that continue an earlier patch (Fix it with the LLM, Make it A from a patch, LLM-heavy chains)
  were not built: verification built only the components of the order's own findings, and these orders have none,
  so they ended *Not built* although Docker was there. Verification now builds every component whose files the
  patch changes.
- **Cancel** on a job that is being asked (Admin → LLM queue): its LLM calls stop within a few seconds, a refactoring
  order does not go on to its build, the sandbox or the next order of an LLM-heavy chain, and it is recorded as
  skipped, *cancelled by …* (**Requeue** starts it again). Before, only queued jobs could be skipped. Turning
  LLM-heavy mode off does not stop the orders already being asked: cancel them. Schema 33:
  `LlmJob.CancelRequestedAt/By`.
- An LLM-heavy chain that stops says why in the result line (*LLM-heavy: stopped: …*), not only on the order's page.

## 0.8.0 (2026-11-03)

### Appliance
- **kubemg** (optional, off by default: `CZ_KUBEMG=true` in `appliance.env`): [kubemg](https://kubemg.readthedocs.io/)
  0.17.0, an audited console and kubectl gateway, for the k3s sandbox cluster at `https://kubemg.<CZ_HOSTNAME>/`
  (`CZ_KUBEMG_HOSTNAME`). It runs as containers (kubemg and PostgreSQL 16) behind Caddy, with the appliance's
  certificate settings. The sandbox cluster is registered at the first start, with its agent in `kubemg-system`.
  The agent connects out to kubemg and trusts the CA of the appliance's certificate. The admin pages link it as
  **kubemg ↗**.

## 0.7.3 (2026-11-03)

### Refactoring
- Make it A and **Fix it with the LLM** repaired nothing for an application in a folder of its repository (a split
  mono-repo, e.g. `scenarios/field-service`): the patch names its files from the repository's root, the repair
  looked for them in the application's folder, so a build or run failure without a compiler error line found no
  file to fix (*nothing to change: no file of the component uses an embedded database or names a finding*), and
  an LLM-heavy chain stopped after two orders that changed nothing.
- **Fix it with the LLM** on a Make it A order now queues a Make it A order that continues from its patch: its own
  repair rounds (with the LLM-heavy limits in a window), the sandbox, and in an LLM-heavy window the chain until
  it runs there. Before, it queued a plain repair, which never deployed to the sandbox.

## 0.7.2 (2026-11-03)

### Refactoring
- **LLM-heavy refactoring orders**: in an LLM-heavy window on the whole application, or on the component of an order
  of one component, a refactoring order of chosen findings makes up to 40 LLM calls (files) instead of 8, and makes
  no LLM call after the window ends. An order that leaves findings or whose patch does not build or run queues the
  next one at once: a repair of its build or run, or the findings left, continuing from its patch (one patch with
  every change). The chain ends when every finding is fixed and it builds and runs, the window ends, after 30
  orders, or two orders in a row that changed nothing. Before, LLM-heavy mode only changed Make it A orders, so a
  refactoring order stopped at 8 files with *not attempted: call limit*.

## 0.7.1 (2026-11-03)

### Organization scans
- **Progress of a run** (Admin → Organization scans → the scan → a run's **Progress**, or the progress link in the
  scan list): the repositories in progress and the step each one is on (cloning, assessing, LLM review, verifying,
  the security gate, pushing images, ...), how long it has been on it (marked **slow** after 15 minutes), the LLM
  call it waits for, the pace and an estimated end, **Where the time goes** (each step's total and average over the
  repositories of the run), and the slowest and the latest finished repositories. It reloads itself every 10
  seconds while the run is in progress; the scan's Runs table shows the repositories in progress and their steps
  too. Repositories scanned in parallel report their steps from their own processes. Schema 32:
  `OrgScanRun.Activity`.
- The SBOM chart's colours no longer leak onto other pages' amber status chips (unreadable in dark mode).

## 0.7.0 (2026-11-03)

### Refactoring
- Make it A: the order page said `B → A Still A.` for a patched copy the rules rate A but that does not build or
  run. It now says **A by the rules, but the patched copy does not build or run** (not A yet, not deployed), and
  lists the findings left as ones that do not keep it from A.
- Make it A: each pass leaves a quarter of the LLM calls (at most 4) for its repair rounds; a first pass over many
  files could use all 16 and leave a patch that does not build without a repair.
- Make it A in an LLM-heavy window (whole application): 40 calls, 4 passes and 4 repair rounds a pass, no LLM call
  after the window ends, and an order whose copy does not end up running in the sandbox queues the next one, which
  continues from its patch with the build or run errors, or the sandbox's state and log of the failing components
  (the failing variant is taken out first). Until a variant runs in the sandbox, the window ends, 30 orders, or two
  orders that changed nothing.

### Results
- Front page: **Made A by a patch**, the applications a verified Make it A patch makes A and whether their variant
  runs in the sandbox (with its link), running ones first; a tile with their count, and → A next to their rating.

## 0.6.0 (2026-11-03)

### LLM
- **LLM-heavy for a while**, per application or component (Admin → Applications → the application → LLM-heavy mode,
  administrators): for 1 hour to 7 days its LLM jobs need no approval (those waiting are approved at once) and go
  before every other job in the LLM queue; scans with queued LLM reviews queue a review of each of its components
  (reason *LLM-heavy*); and scans run LLM-heavy mode for it (migrations, the sandbox tester) where the appliance
  allows it (`CZ_LLM_HEAVY`), even with queued reviews. The windows open now are on the application's page and the
  LLM queue page, with End now (schema 31: `LlmHeavyWindow`, `vLlmHeavyActive`, `fnLlmJobHeavy`).

## 0.5.1 (2026-11-03)

### Appliance
- Built-in LLM: 0.5.0's front (`containerizer-local-llm.service`, a Caddy on 127.0.0.1:8082) never started: its
  config set `persist_config`, which the appliance's Caddy (2.6.2) does not know. It restarted every 10 seconds and
  took the llama.cpp servers with it, so none stayed up. The front is gone: the LLM queue now asks each server as an
  LLM of its own, like the registered LLMs (`built-in-0`, `built-in-1`, ... on the LLM queue page, one job at a time
  each; a server still loading its model takes none yet), and scans that ask directly use the first server that is
  up, on `127.0.0.1:8090+n`.
- Grafana, **Built-in LLM** row: each server's state, tokens per second and requests on lines of their own (label
  `server`), and a new panel **LLM queue: jobs per LLM** (metric `containerizer_llm_queue_llm_jobs`, label `llm`).

## 0.5.0 (2026-11-03)

### Appliance
- Admin → System: **planned restart**. A restart (new **Restart** form), an upgrade and a roll back run now or at a
  set time (UTC), and wait for the work in progress: from that time on no new scan run or LLM job starts, and the
  appliance restarts once nothing runs any more or after the longest wait chosen (not at all, 30 minutes to 8 hours,
  or until done; 2 hours by default). The page shows the plan and what it waits for, and can cancel it. The upgrade
  and roll back forms use it too (they restarted at once, cutting off running scans). Roll back is one form with a
  snapshot list. The system agent keeps the plan on the persistent partition and checks it every minute
  (`containerizer-restart.timer`).
- Grafana's k3s and Flux dashboards were partly empty since 0.3.11: kube-state-metrics was pulled from registry.k8s.io,
  which is not on the egress allow-list (it redirects to regional hosts the list cannot name), so the pod never
  started. It now comes from Rancher's mirror on Docker Hub (v2.17.0, pinned by digest), like k3s's own images; a test
  checks that every monitoring image is on an allowed registry.
- Built-in LLM: NUMA aware. On a machine with several NUMA nodes (CPU sockets) and the RAM for a copy of the model on
  each, one llama.cpp server runs per node, pinned to its CPUs and memory, behind a front on 127.0.0.1:8082 that
  sends each request to the least busy server; the LLM queue asks one job per server at once. One node, or not
  enough RAM: one server, as before. Prometheus reads each server (labels `server`, `numa_node`). The server unit is
  now `containerizer-local-llm@<n>.service` (container `cz-llm-<n>`); `containerizer-local-llm.service` is the front.

### LLM
- Several LLMs at once: more than one LLM can be registered (Admin → Source control & LLM), each with an order, the
  biggest job it takes (estimated input tokens; 0: any) and its requests at once. The LLM queue gives each job to the
  first LLM in the order that takes its size and has a free request, so a GPU server, CPU servers and the appliance's
  built-in LLM (its order and size limit under LLM queue → Settings) answer at the same time. The LLM queue page lists
  them and warns when no LLM takes the biggest jobs. Scans that ask directly use the first LLM. The registered LLM
  keeps the LLM queue's Parallel requests as its own (schema 30).

## 0.4.0 (2026-11-02)

0.3.13 was tagged but not released (signing failed at Sigstore's transparency log, a 502); its changes are listed
under 0.3.13 below and are in this release.

### Refactoring
- The same code is changed by the LLM once: an answer that fixed everything in a file is kept under a key of the
  file's text, its findings and the component's settings, language, target framework and packages (not the
  application or the path), and a later order, of any application or repository, with the same file gets that change
  without an LLM call (moved to where the file is; the LLM is asked when it does not apply). Libraries shared by
  several applications are refactored once. The order page notes each reused change.

## 0.3.13 (2026-11-02)

### Web UI
- Admin → Refactoring → **Make it A: every B application** (was "Make all B apps A"): the orders sorted by their
  estimated tokens, smallest first, with the running total of LLM time; **Queue every order under N tokens** places
  those, approved at once (they do not wait for approval). Applications with an order in the queue already are
  shown and not ordered again.
- Admin → LLM queue, approval: link reviews and egress reviews can wait for approval too (they always started by
  themselves, because the policy only knew component reviews and refactoring orders). Settings still at the old
  default (every job waits) now cover them as well.
- Admin → LLM queue, automatic approval by size and queue length: jobs estimated under a number of tokens start by
  themselves only while fewer than a number of jobs are queued or running; the others wait and are approved by
  themselves, highest priority first, as the queue gets shorter. Big jobs always wait for an administrator.
- Admin → LLM queue: **Reject automatically after** a number of hours: jobs that waited that long for approval or in
  the queue are skipped, with the reason. Requeue starts the wait again.
- Admin → LLM queue: after a button on a job (skip, move, approve, reject, requeue) the page opens at that job, or at the
  one taking its place, instead of jumping back to the top.
- Admin → LLM queue: the jobs waiting for approval are listed after the queued ones (the order the runner takes them:
  asking now, queued, then waiting for approval), not between the running and the queued ones.

## 0.3.12 (2026-11-02)

### Appliance
- Organization scans with the security gate or **Build and run** failed with "Read-only file system:
  '/usr/lib/containerizer/app/.work'": the scan worker's scratch space defaulted to the folder next to the code, which
  is the read-only OS image. It is `/var/lib/containerizer/worker/work` now (`CONTAINERIZER_WORK`), and without the
  variable the code no longer writes next to an installed, read-only package.

## 0.3.11 (2026-11-02)

### Organization scans
- **Applications in this repository** (Admin → Repositories → the repository): a mono-repo can be assessed as one
  application per folder matching a pattern (`scenarios/*`), each with its own rating, results page, sandbox
  namespace and output folder (`<repo>@<folder>`). A repository that looks like several applications (three or more
  folders with their own solution or project root) gets a note with the pattern filled in; nothing is split
  automatically. `containerizer org --split 'project/repo=pattern'`.
- Admin pages: radio buttons sat on their own line above their label; they are beside it again.
- **Repositories in parallel** (the scan's settings, 1 to 8, default 1; `containerizer org --parallel N`): a full scan
  processes that many repositories at the same time, each in its own process, so it uses that many CPU cores
  (the assessment is CPU-bound Python, so threads would not help). Results are committed one at a time.

### Appliance
- Grafana: two more dashboards, **Containerizer: k3s sandbox cluster** (API server and kubelet up, pods not running,
  containers waiting, restarts, deployments short of replicas, CPU, memory and network by namespace, top pods, volumes,
  API server requests and latency) and **Containerizer: Flux** (every Flux object with its Ready state, reason,
  revision and suspend flag; reconciliations, errors, reconcile time, work queues and the controllers' CPU and memory).
  Prometheus reads k3s and Flux as a read-only ServiceAccount, and kube-state-metrics runs in the sandbox cluster
  (namespace `cz-monitoring`).

## 0.3.10 (2026-11-02)

### Appliance
- A reboot during an organization scan could sit on a black screen for a long time: the scan worker had up to 2 hours
  to finish the repository it was on. It now stops within 2 minutes (its LLM calls at once); the run is marked failed
  and the next one processes every repository again.
- The screen is the main console now (`console=ttyS0 console=tty1`), so a slow boot or shutdown shows what it is waiting
  for ("A stop job is running for ...") on the Hyper-V or Proxmox console instead of a black screen.

### Organization scans
- A full scan no longer walks through the disabled repositories: they are left out before it starts, so they are not
  in its progress ("N of M"), its log or the output repository's history one commit each. They still show "Not
  processed (disabled)", and the files of one deployed before are removed in a single commit.
- Cancelling a run now stops its LLM calls: a call not started yet is not made, and one the LLM server is still
  answering has its connection closed (llama.cpp, vLLM and Ollama then stop generating; the claude CLI is
  killed). Before, the repository in progress kept the self-hosted LLM busy until it was done.
- New scans start with **Build and run every component before rating it** off: it is slow, more so with "Ask the
  LLM". Existing scans keep their setting.

## 0.3.9 (2026-11-02)

### Web UI
- Admin → Repositories and Projects: a box in the list header selects every row listed, for the bulk actions.
- Organization scans: **New repositories** enabled by default (the scan decides, as before) or disabled by default
  (every repository found from then on, the first discovery too, starts disabled until an administrator enables it).

## 0.3.8 (2026-11-02)

### Appliance
- Organization scans and the LLM queue failed with "credential key /run/credentials/...: readable by others": systemd
  hands the services their key as `0440` in their private credentials directory, which the check refused. Group
  read is accepted there now (nowhere else; others still never).

## 0.3.7 (2026-11-02)

0.3.6 was tagged but not released (its run was stopped); its changes are in 0.3.7.

### Web UI
- Organization scans: the output repository is chosen from the repositories with a write token under **Source
  control** (or none), not typed in. A saved URL without a token stays selectable, marked.
- On the appliance, a scan's image registry may stay empty: it is then the appliance's own registry,
  `localhost:5000/sandbox` (no credentials; the sandbox cluster pulls from it). New scans start with it.

### Appliance
- **Admin → Sandbox HTTPS** changes were refused with "Caddy does not accept the configuration: ... mkdir caddy:
  read-only file system": the system agent's check of the Caddy configuration ran without a home directory, so Caddy
  tried to create its internal CA on the read-only root. The check now gets a throwaway directory.

## 0.3.5 (2026-11-02)

### Appliance
- The firewall answers ping from outside: ICMP and ICMPv6 echo requests are allowed in (at most 20 a second).
- Full `vim` in place of `vim-tiny`, with the mouse off and paste mode on (`/etc/vim/vimrc.local`; a `~/.vimrc`
  of root's own wins and is kept).
- `CZ_HOSTNAME` is only the web UI's name (usually the FQDN: the HTTPS certificate and the sign-in redirect). It no
  longer renames the machine: the sandbox cluster's k3s node is named after the machine, and a rename made k3s
  register a second node.
- Your own HTTPS certificate for the web UI (for example from your company's CA): `cert.pem` (with its chain) and
  `key.pem` in `/etc/containerizer/tls/`. It wins over Let's Encrypt and the appliance's own CA
  (docs/appliance-admin.md#https-certificate).
- Grafana opens on the **Containerizer: organization scans** dashboard. With an identity provider enabled in
  `grafana.env`, its user name and password form is hidden and sign-in goes straight to the provider.

## 0.3.4 (2026-11-02)

0.3.3 was tagged but not released (its boot test was stopped); its changes are in 0.3.4.

### Appliance
- Temporarily, root's default password `containerizer` is not expired: no sign-in is forced to change it. Change
  it with `passwd` after the first sign-in; the change is kept on the persistent partition as before. The first
  sign-in's forced change failed on Hyper-V ("Authentication token manipulation error"); `EXPIRE_DEFAULT` in
  `cz-root-password` turns it back on once that is fixed.

### CI
- The `ci` and `security` workflows run only by hand (Actions → Run workflow) for now: no pull request, push or
  schedule triggers. The release's QEMU boot test is optional (`boot_test` input of a manual run); a pushed tag
  releases without it.

## 0.3.2 (2026-11-02)

### Appliance
- The console no longer shows Elemental's branding (host name `elemental`, "Login with user: root, password:
  elemental"): `/system/oem/03_branding.yaml` and `04_accounting.yaml` replace the Elemental defaults. The host
  name is `containerizer` (CZ_HOSTNAME replaces it), the installed system shows its own `/etc/issue`, recovery,
  the previous snapshot and the installer ISO say what they are, and root's password is `containerizer`
  everywhere (the installer ISO included). The banner sent people to `elemental` as the current password at the
  first sign-in's password change, which fails with "Authentication token manipulation error".

## 0.3.1 (2026-11-02)

### Appliance
- Hyper-V: the release has a 64 GB dynamic VHDX (`containerizer-vX.Y.Z.vhdx`) in place of the fixed VHD
  (`.vhd.zst`). Generation 2 VMs boot only VHDX. The qcow2 is 64 GB too. The 1 GB images had to be grown by hand
  before the first boot; otherwise the install on first boot failed and the next boot stopped at
  `no such device: COS_STATE`.
- The firewall's drop log (`cz-in-drop`, `cz-egress-drop`) no longer floods the console: `kernel.printk` sends only
  errors to tty1/ttyS0. The kernel log, and the egress observer that reads it, still get every line.

## 0.3.0 (2026-11-02)

Results database schema version 25 (`containerizer db init` upgrades it; the appliance does at start).

### Egress and network connectivity
- The appliance's sandbox stays isolated: nothing leaves it but what an administrators' (or system) egress rule
  allows (Admin → Firewall), whatever a NetworkPolicy says. Containerizer finds out and documents what applications
  need from the network; approving documents a destination for the real environment and opens nothing.
- **Egress observer** (docs/egress.md#the-egress-observer): `containerizer egress-observe` records what the sandbox
  blocks at every layer: the packets its NetworkPolicies drop (kube-router's NFLOG group 100, a small netlink reader,
  no packages), the appliance firewall's drops (`cz-egress-drop` in the kernel log, `/dev/kmsg`) and the names the
  appliance's DNS filter refused (the CoreDNS query log; no port). It keeps the egress of application pods, names
  each destination with the FQDN a pod of the namespace looked up just before (the CoreDNS query log,
  `log.override` in `coredns-custom`) and adds the flows up per namespace, component, destination, port and
  protocol, with the layer that blocked them, in `cz.EgressFlow`. On the appliance:
  `containerizer-egress-observer.service`, the `containerizer` user with CAP_NET_ADMIN (NFLOG) and CAP_SYSLOG (the
  kernel log) only and a read-only Kubernetes account of its own (pods, CoreDNS's log); in the lab:
  `ci/lab-sandbox/egress-observer.sh`.
- **Egress review** (LLM queue kind `egress`, with the approval policy): for applications rated A that run in the
  sandbox (and "Make it A" variants), a deterministic pre-filter first (IP addresses without a name, metadata
  endpoints and blocked ranges, wildcards, paste, file-sharing and tunnelling services, the platform's services and
  namespaces: reported or suspicious, never proposed), then the LLM per destination: propose, report or suspicious,
  with the file and line of the assessed commit that names it (checked against the source) and why.
- **Approve / Reject** per destination (results page, Admin → Egress) for administrators, operators and the
  application's product owners: approval documents the destination for the real environment. The LLM queue runner
  commits it to the application's `connectivity.yaml` (FQDN, port, protocol, why, evidence, who approved); the
  sandbox's NetworkPolicies and firewall stay as they are. Later scans keep the approved entries (the generator
  reads the output repository's `connectivity.yaml`; sandbox variants take the original's).
- **Sandbox status** of every outbound destination: whether the sandbox can reach it: its NetworkPolicy, and on the
  appliance the egress rule that allows it, or the firewall or DNS filter that blocks it (read from the same rule
  files as the firewall, read only), or "no appliance firewall (lab)".
- **Network connectivity**: on every results page, a server-side SVG diagram (no script, light and dark) and a
  table of what the application needs from the network, each entry marked by its source (configuration and code
  with file and line, packages, the NetworkPolicy, lab services, observed in the sandbox, approved) and status
  (allowed, approved (documented), proposed, blocked, not allowed, suspicious, rejected) and sandbox status, with the
  findings *missing* (named by
  the configuration, nothing allows it) and *unexplained* (open, but nothing names it). Applications not in the
  sandbox show what was inferred. The same as `connectivity.yaml`, `CONNECTIVITY.md` and `connectivity.svg` next to
  the manifests in the output repository, written by every scan and refreshed by the runner. Assessments record
  the inferred network needs (assessment.json `network`).
- **Links between applications** (docs/egress.md#links-between-applications): an outbound destination can be
  another application's component (another repository or product). Links (`cz.ComponentLink`) are found by a
  configured host matching the other component's service or Ingress host, by a blocked call to another
  application's pod in the sandbox, by the LLM (queue kind `link`: a destination that looks internal, a shortlist of
  candidate components, the best match with its confidence) or by hand; a person confirms them (Confirm, Reject,
  Link manually on the results page). The runner writes a confirmed link to both applications' connectivity.yaml
  (`type: component` with its target; the callee's `inbound` callers) and NetworkPolicies (the caller's egress to the
  callee's pods, the callee's ingress from the caller), and later scans keep them. `/connectivity` shows how the
  applications of a product, a business unit or all connect.
- `containerizer llm-queue --kinds` (the job kinds a runner takes; its housekeeping follows them).
- `examples/egress-demo` (an A-rated app that calls a configured API, another application and a hard-coded paste
  site) and `examples/orders-demo` (the other application).

### Build pipelines
- Container image build pipelines for the application's own repository (docs/build-pipelines.md), for the
  provider its code lives on: GitHub Actions (`.github/workflows/containerizer-images.yml`), GitLab CI/CD
  (`.gitlab-ci.yml`, or `containerizer.gitlab-ci.yml` to include when the repository has one) or Azure
  Pipelines (`azure-pipelines.containerizer.yml`), with the generated Dockerfiles under
  `containerizer/<component>/` (and `Dockerfile.dockerignore`, the context filter BuildKit reads next to
  them). The provider comes from the organization scan (also GitHub Enterprise, GitLab self-managed and
  Azure DevOps Server) or the repository URL; when neither tells, all three are offered. Deterministic, no
  LLM.
- Pull/merge requests build each changed component (monorepos: one job per component, rebuilt when its
  project folder, referenced projects, shared build files or Dockerfile change), make an SBOM (Syft) and
  scan it (Trivy, failing on the security gate's severities), and push nothing. The default branch also
  pushes `<registry>/<app>/<component>` tagged `1.<yyyymmdd>.<hhmm>` (the scans' semver scheme, which the
  generated Flux / Argo CD image automation follows into the sandbox) and `sha-<commit>`, optionally signed
  with cosign (keyless with GitHub/GitLab OIDC, or with a key) with the SBOM attested. Least privilege:
  per-job GitHub `permissions`, protected-branch-only pushes on GitLab, a service connection on Azure; the
  scanners pinned by version and digest, GitHub actions by commit SHA, cosign by checksum.
- Delivery: `pipeline/<provider>/` in the generated output (organization scans: the output repository), the
  results page's **Build pipeline** box (administrators, operators and the application's product owners:
  the files, Download .patch for `git am`, a `.tar.gz`, how to apply and what to set up; everyone else sees
  that it exists), and `containerizer pipeline <app-path> [--provider] [--registry] [--sign] [--out]
  [--patch]`. Assessments record what the pipeline is made from (assessment.json `build_pipeline`).

### Make it A
- **Make it A** for B-rated applications (docs/refactoring.md#make-it-a): one refactoring order (goal
  `rating-a`) for every refactor finding, the configuration findings with a file and the move of a stateful
  component's data, that loops in the queue runner: generate, apply, verify, an automatic repair round when
  the build or run fails (at most 2 a pass), the patched copy assessed again with every rule, and one more
  pass on what remains while it is still B (at most 2 passes, 16 LLM calls in all). The result says the
  rating before and after (`B → A: Rating A reached`, or what still keeps it B), with one combined patch,
  the result per finding and the verification. On the results page (with the queue's estimate) and, for
  administrators, **Make all B apps A** on Admin → Refactoring: a confirmation page with every B app's
  estimate, the total and how many will wait for approval, then one order per app. `containerizer refactor
  --goal rating-a` on the command line.
- **Sandbox variants** (docs/refactoring.md#the-sandbox-variant): a Make it A order whose patched copy rates
  A and runs is deployed to the sandbox **beside** the original, in its own namespace `<app>-refactor-<job>`
  (its own images, Ingress hosts, IdP clients and a new, empty lab database), through the output
  repository of the organization scan that assessed it (`<Org>/<Project>/<Repo>-refactor-<job>/`). Its
  health is read back for its namespace only (`CONTAINERIZER_SANDBOX_KUBECONFIG`) and kept in the order, so
  the original's sandbox results stay as they are; it expires after 7 days
  (`CONTAINERIZER_SANDBOX_VARIANT_DAYS`) and **Remove from the sandbox** takes it out sooner (administrators,
  operators, the app's product owners; the queue runner removes it). The orders show the variant's state
  (deploying, running in the sandbox, failing in the sandbox, removed, expired) and its URL.
- The organization scan and the variants deploy with the same code (`org.deploy_app`); the scan's
  behaviour is unchanged.
- The clean copy a refactoring is verified in is named after the order (`<app>-refactor-<job>`), so the
  verify step's image tags of orders that run in parallel no longer collide.
- **Local images**: with *Push images* off and `CONTAINERIZER_LOCAL_IMAGES=1` (a sandbox cluster that shares
  the builder's Docker image store, such as k3s with `--docker`), the scan and the variants tag each image
  with its deploy reference instead of pushing it; the manifests pull with `IfNotPresent`.
- Appliance: the LLM queue runner gets the lab services and the read-only verifier kubeconfig that
  `cz-sandbox` now writes (`/run/containerizer/sandbox-verifier.kubeconfig`: the verifier's Role in every
  generated namespace, a 24-hour token).

### LLM queue and refactoring
- **Approval**: every LLM job waits for an administrator by default (Admin → LLM queue → Settings:
  `ApproveKinds`, `ApproveMinTokens`), with Approve, Reject and **Approve all** with the total estimate. Give
  the queue more freedom once you trust it. Results database schema version 22.
- Refactoring goals: **targeted code changes**, **make it stateless** (move a component's own data to SQL
  Server: the database library and its configuration, with notes on moving the data) and **repair** (feed the
  build errors of a patch back to the LLM: **Fix it with the LLM** on the order page).
- The guidance keeps patched code working on both Windows and Linux (no hard-coded Linux paths, portable
  defaults, `Path.Combine`, `OperatingSystem.IsWindows` guards).
- Clearer order statuses (Waiting for approval, Does not build, Does not start, Not built) with an
  explanation; operators and the application's product owners may order refactorings for their products.
- Tokens and time on the orders: the queue's estimate while an order waits or runs (with the time left while
  it generates), what it took once done. The learned LLM speed ignores jobs with cached answers and counts
  only the prompt tokens the server really read (llama.cpp reuses a cached prefix): estimates were too low.
- The results page offers an order that already exists (its status, the patch, the commit it was made for)
  instead of a new one, with **Request a new one** for changed code.

### Web UI
- API keys for the JSON API: administrators make them on **Admin → API** (read only or full, optional
  expiry), shown once and stored as SHA-256 only, revocable, last use recorded; the page explains the API
  with examples for the server. The API is on whenever the admin pages are; OpenID access tokens still
  work when `CONTAINERIZER_API_AUDIENCE` is set. Results database schema version 21.
- Why an application is rated B, in one line on its page; a single **How to fix** link per mitigation.
- External links open in a new tab; a favicon; the source control page shows how to make a token before
  asking for it.
- Development mode for the admin pages: `CONTAINERIZER_DEV_NO_AUTH=1` signs everyone in as a configured
  person (default John Doe, administrator; `CONTAINERIZER_DEV_USER`, `_NAME`, `_ROLES`), for development and
  labs without an identity provider. It is refused on the appliance and next to a configured sign-in; a red
  banner shows on every page, the JSON API takes API keys (not access tokens), and CSRF tokens, roles and the
  change history work as
  with sign-in (docs/local-dev-server.md).

### Lab and appliance
- A lab sandbox on the dev server (docs/local-dev-server.md, `ci/lab-sandbox/`): the appliance's k3s with
  Docker as its runtime (pods run the images `docker build` made, no registry), Flux, External Secrets and a
  Gitea output repository, with a smoke test.
- Appliance: `cz_store_put` quotes secret key names, so keys such as `n`, `yes` or `on` no longer become
  YAML booleans.

## 0.2.0 (2026-11-01)

Results database schema version 20 (`containerizer db init` upgrades it; the appliance does at start).

### Refactoring patches
- Refactoring patches for B-rated applications: an operator or administrator orders one on the
  application's results page (**Refactoring** box: all components that need changes, or one; optionally
  configuration findings too). The order is a `refactor` job in the LLM queue. The runner asks the LLM once
  per affected file, with the rule's fix, the evidence and the file, for structured edits (not a diff),
  applies them deterministically (each search text exactly once; one retry with the errors), and makes a
  `git format-patch` commit. The patch is then applied to a clean copy at the assessed commit
  (`git apply --check`, `git am`), the rules run again on it (which findings are gone, which remain, any
  new ones), and the changed components are built and run with the verify step: the patch is **verified**,
  **applies only** (with the build or run log tail) or **failed** (never offered). **Admin → Refactoring**
  lists the orders; each has the findings fixed and not fixed, the verification, a coloured diff per file,
  **Download .patch** and how to apply it with `git am`. Download only: nothing is written to the
  repositories. Product owners and viewers see an order's status on the results page, not the patch.
  Command line: `containerizer refactor <app> [--component] [--out] [--queue]`. Schema 20 adds the kind to
  `CK_LlmJob_Kind` and the view `vRefactorOrder`. See [refactoring patches](docs/refactoring.md)
- Appliance: the LLM queue runner is now in the docker group (to build and run the patches, as the scan
  worker does), reads the scan worker's clones and writes only its answer cache and
  `/var/lib/containerizer/refactor`

### Organization scans
- Queued LLM reviews, for a slow self-hosted LLM: with **LLM reviews: Queued** on a scan, the scan asks
  the LLM nothing (no component reviews, failure diagnosis, dev database questions or LLM-heavy mode) and
  the rules decide. The component reviews go to the new **LLM queue**: uncertain components first, then a
  second opinion on the rules' blocker and rewrite verdicts, by a documented priority. The queue runner
  (`containerizer llm-queue`, a service of its own on the appliance) answers them on the days and hours
  set on **Admin → LLM queue**, optionally only while no scan runs and the machine is idle, with as many
  parallel requests as the LLM serves. Administrators and operators reorder, skip and requeue jobs there.
  Each answer shows at once on the queue page and on the component's results page, and the next scan of
  the repository applies it from the answer cache; **Re-scan now** scans a repository whose reviews are
  answered. The page estimates the tokens and time of the waiting jobs from what the runner learned on
  each LLM. The queue takes other kinds of LLM jobs later without a schema change. The command line has
  `--ai-queue` on `assess`, `analyze` and `org` (a queue file without SQL Server). Metrics and an
  **LLM queue** row on the Grafana dashboard. See
  [queued LLM reviews](docs/source-control.md#queued-llm-reviews)
- Fix: the Grafana panel **LLM tokens by feature** had two queries with the same id, and its output
  tokens were an instant query, so they did not show over time
- Discovery first: **Discover** on a scan's page lists the projects, repositories and each repository's
  latest commit through the provider's API, without cloning or assessing anything, so administrators can
  disable deprecated projects and repositories before the full scan. **Run now** is now **Run full scan**,
  and the runs show which kind they were
- Projects (Azure DevOps projects, GitLab subgroups) on **Admin → Repositories → Projects**: disabling one
  leaves all its repositories out of the full scan; changes are in the change history
- **Scan now** on projects and repositories (their pages, or the selected ones in the lists): a full scan
  of only those, outside the schedule
- The repository list shows the latest commit, with **No commit for a year** and **Oldest commit first**
- Disabled repositories and projects are hidden from the results pages (overview, trends, SBOM,
  application pages); the admin pages still show them

### Appliance
- Built-in LLM, off by default, for sites without an LLM server of their own: **Admin → Source control & LLM
  → Built-in LLM** runs Qwen3-Coder 30B-A3B (ByteShape's 16 GB `IQ4_XS` build) with llama.cpp on the
  appliance's CPU, on `127.0.0.1:8082`. Scans with **Ask the LLM** use it when no LLM is set on that page.
  Turning it on checks the memory (40 GB or more) and the free disk (about 20 GB), downloads the model
  once from Hugging Face, pinned by commit and SHA-256 (`huggingface.co` and `hf.co` are allowed only while
  it downloads), and sizes the server from the memory (one to three answer slots). It is slow, a few minutes
  per answer, so use the queued LLM mode where it is offered. Its metrics are on the Grafana dashboard
  ([built-in LLM](docs/appliance-admin.md#built-in-llm))
- External results database: `CZ_SQL_SERVER`, `CZ_SQL_DATABASE`, `CZ_SQL_USER` (password in
  `secrets/sql-owner`) and `CZ_SQL_LOGINS` in `appliance.env` point the appliance at a SQL Server you run and
  back up, so the appliance needs no database backup of its own (its files still do). SQL Server then does not run on the appliance, the
  schema is created and upgraded on that server at every start, the firewall allows it by itself, and the
  connection is encrypted with the certificate checked (`CZ_SQL_CA` for a private CA). The logins
  `cz_scanner`, `cz_web` and `cz_admin` are created by the owner login, or by your DBA
  (`CZ_SQL_LOGINS=existing`; new `containerizer db init --member LOGIN:ROLE`). Database users of a restored
  backup are mapped to the logins of the new server ([external database](docs/appliance-admin.md#external-database))
- `root` signs in with the password `containerizer` on the console and over SSH, and the first sign-in
  asks for a new one. The changed password is kept on the persistent partition, so it survives restarts,
  upgrades and roll backs. The SSH key is now optional in the installer, the first-time key prompt on the
  console of a disk image is gone, and SSH accepts passwords as well as keys (`passwd -l root` for keys
  only). An appliance upgraded from 0.1.0 starts with the default password too: sign in and change it
  right after the upgrade. See [Running the appliance](docs/appliance-admin.md#root-password-and-ssh).
- Fix: the scan worker kept its LLM answer cache next to the code, on the read-only OS image, so every
  answer was paid for and then lost when it could not be saved. It is now in
  `/var/lib/containerizer/worker/ai-cache`, and an answer that cannot be cached is still used
- Backup: the documentation lists everything that scans do not rebuild (dev database uploads, Sandbox
  HTTPS certificate, firewall and Sandbox HTTPS change history, learned rules, the appliance's CA), with a
  backup and restore procedure. `db init` links the database users of a database restored on another
  server to that server's logins again

### Scans
- Platform migrations: a repository with a Dockerfile that an administrator enables is moved to
  Kubernetes from Docker Swarm, Docker Compose, HashiCorp Nomad (HCL and JSON jobs), Azure Container Apps
  (YAML, ARM and Bicep) or Amazon ECS instead of being skipped. The app's own image (built from its
  Dockerfile or mirrored) goes through the security gate; the generated output is the same as for
  containerized apps: hardened manifests, External Secrets, HTTPS Ingress, sandbox IdP registration,
  GitOps files, and `MIGRATION.md` with what was and was not carried over. `containerizer replatform`
  does the same for one checkout, `containerizer org --migrate-containerized` for a whole organization.
  See [docs/platform-migration.md](docs/platform-migration.md).
- LLM-heavy mode, off by default (`CZ_LLM_HEAVY` in `appliance.env` and **LLM-heavy mode** on the scan):
  the LLM translates descriptors the rules cannot read (Fly.io, Cloud Foundry, App Engine, ...), reviews
  migrated services, fixes containers that fail the hardened run, and the sandbox tester diagnoses and
  fixes failing components.
- LLM usage statistics: calls, tokens in and out and estimated cost by scan, repository, feature and
  model as Prometheus metrics, an **LLM usage** row on the Grafana dashboard, and per repository on its
  admin page. `CONTAINERIZER_LLM_PRICE_INPUT`/`_OUTPUT` price a self-hosted LLM.
- Schema version 18 adds `OrgScan.LlmHeavy`; version 19 adds `OrgScan.LlmMode` and the LLM queue
  (`LlmJob`, `LlmSpeed`, `LlmQueueSettings`, `vLlmReviewLatest`).

## 0.1.0 (2026-10-31)

The first release: the assessor, the GitHub Action and Azure DevOps gate, the results database with its web
UI and admin pages, and the appliance. Results database schema version 16.

### Appliance
- Immutable VM image and installer ISO built with the Elemental toolkit (Debian 13): signed upgrades and
  roll back from **Admin → System**, local container registry, k3s sandbox cluster with Flux, and an
  egress firewall with a DNS filter (#37)
- Source control tokens and the LLM settings on the admin pages: read-only tokens per Azure DevOps,
  GitHub or GitLab organization (sealed at rest), access only to organizations with a token, and a
  separate write token for the repository that receives generated files (#44). The scan worker no
  longer reads organization or output tokens from its environment; see
  [docs/source-control.md](docs/source-control.md).
- Sandbox lab services next to the scanned apps: SQL Server 2025, PostgreSQL, MySQL, MongoDB, Redis,
  RabbitMQ, Kafka, SFTP, S3 and Azure Blob (#51, #54, #59), with dev database uploads for SQL Server,
  PostgreSQL and MySQL (#59, #61)
- Sandbox HTTPS with a wildcard domain and certificate (#46) and an identity provider, WSO2 Identity
  Server, for OIDC, SAML 2.0 and WS-Federation (#55)
- External Secrets Operator for every secret in generated configs (#47)
- Rule approval from the admin UI and SBOMs attached to sandbox images with ORAS (#61)
- Release workflow, started by hand with the version: tags the commit, then the OS image on GHCR signed
  with cosign and its SBOM attested; ISO, qcow2 and VHD as release assets with signed checksums

### Web UI, admin pages and API
- SQL Server results database and read-only results web UI (#23)
- Admin pages behind OpenID Connect SSO, JSON API, audit log, dedicated schema (#24)
- Trends page with rating and obstacle history over scans (#29)
- Optional sign-in for the results pages and an access log (#30)
- Migration assistant: concrete replacements for blockers and a copyable AI agent prompt (#31)
- Scheduled organization scans from the admin UI, repository enable/disable, Prometheus metrics and a
  Grafana dashboard (#32)
- Roles: scoped product owners and operators for the admin pages and the API (#34)
- SBOM and licence reporting: CycloneDX per image, licence policy, CVEs per package (#38)
- Dev database backups: operators upload a SQL Server `.bak`, the sandbox restores it next to the app (#39)
- Rule review: learned rules wait for approval, with their evidence (#36)
- Work estimates removed from the web UI, admin API, reports, agent prompts and the CI comment; schema
  version 16 drops the EffortDays columns (#62)
- Screenshots of the results and admin pages in the docs (#27)
- Documentation published to GitHub Pages at containerizer.eu (#42), an appliance Getting started
  guide (#45), how to run the CI suite on a local Debian 13 server (#43), a landing page and trimmed
  docs (#49, #50, #57, #60)

### Assessment and rules
- Java and Node.js: build-file parsing, roles, findings, statelessness and confidence (#48), Dockerfiles,
  hardened manifests and verification (#53), org runs and a validation corpus (#56), and app home
  directories and locally installed themes detected as state (#58)
- `containerizer org`: run across a whole Azure DevOps, GitHub or GitLab organization (#26)
- AI fallback supports self-hosted LLMs through an OpenAI-compatible API (#25)
- Rules round 11: ABP Zero, ATSPM, CoreWCF, WF4, AD/LDAP tools, QRCoder, Elsa (#28)
- Rate A only for stateless apps (#33)
- Sandbox verification reads back pod health after the Argo CD / Flux deploy (#35)
- Learned rules folded into the curated rule set; learning now writes general rules (#40)
- Earlier work (#1–#22): rule-based assessor with a self-learning loop, generated Dockerfiles and Kubernetes
  manifests verified by building and running them, the pull request gate (GitHub Action and Azure DevOps
  template), NSA/CISA hardening, image CVE scans, GitOps examples and a real-world corpus of .NET apps

### CI
- Full CI, security and release workflows are skipped for documentation-only changes (#52)
- The action takes a `report-name` input, so one job can run it more than once
- The appliance boot test waits for the active system after the first-boot deployment
- Appliance fixes found by the boot test: the Docker CLI is installed (`docker-cli` on Debian 13), the
  boot health check waits for k3s to finish starting instead of rolling back, and the egress
  allow-list includes all of Docker Hub's layer hosts (Cloudflare, CloudFront, R2); the appliance's
  runtime folders, `/etc/resolv.conf` and kernel settings are set up even when early boot misses them
- The image ships `/etc/hosts` (a container build leaves none; first-boot setup and k3s pods need it), and
  the DNS filter watches for the DHCP DNS servers from early boot
- Lab services: MySQL is provisioned over TCP inside its pod; the lab cluster test runs on ubuntu-22.04
  because MongoDB 8.0 does not start on Linux 6.19 and newer

### Development
- The local development server guide shows how to run Qwen3-Coder 30B-A3B on CPU only (ByteShape's
  CPU builds with llama.cpp's server, pinned by digest and SHA-256) as the self-hosted LLM for testing,
  with the memory it needs and how slow it is. Real environments use an external LLM

