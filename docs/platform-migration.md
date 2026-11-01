# Platform migrations

Organization scans skip repositories that already have a Dockerfile: the team containerizes them
already. Many of those applications still run on Docker Swarm, HashiCorp Nomad, Azure Container Apps or a
similar platform. When an administrator **enables** such a repository, the scan moves it to Kubernetes
instead of skipping it, with the same output as for applications it containerizes itself: hardened
manifests, External Secrets, an HTTPS Ingress, sandbox identity provider registration, GitOps files, and a
health check in the sandbox cluster.

## Turning it on for a repository

1. Open **Admin → Repositories** and pick a repository the scan skipped with **Has a Dockerfile**.
2. Choose **Enabled** and save, with a note if you like. The next run of the scan migrates it.

A repository that has a Dockerfile but no deployment descriptor the scan can read is containerized from
its source code, as before. The repository page shows **Platform migration** with the platform and the
files it was read from once a run has migrated it.

From the command line, `containerizer org --migrate-containerized` migrates every repository with a
Dockerfile, and `containerizer replatform <checkout> --out <folder>` migrates one checkout without a scan
(`--build` builds the images and runs the security gate).

## What is read

| Platform | Files |
| --- | --- |
| Docker Swarm, Docker Compose | `docker-compose*.yml`, `compose*.yaml`, `*stack*.yml` with `services:` |
| HashiCorp Nomad | `*.nomad`, `*.nomad.hcl`, `*.hcl` with a `job` block, Nomad job JSON (`{"Job": ...}`) |
| Azure Container Apps | `az containerapp --yaml` files, ARM templates and Bicep files with `Microsoft.App/containerApps` or `Microsoft.App/jobs` |
| Amazon ECS | task definitions (`containerDefinitions`) |
| Fly.io, Cloud Foundry, Google App Engine, Render, Marathon, Heroku, Kamal | recognised; translated only in [LLM-heavy mode](#llm-heavy-mode) |

From each service or task: the image or the Dockerfile and build context it is built from, command and
arguments, settings, secrets and secret files, ports and whether they are published, replicas, CPU and
memory, the health check, volumes, the schedule of batch and periodic jobs, and `depends_on`.

| Becomes | From |
| --- | --- |
| Deployment, or a CronJob for scheduled jobs (Nomad periodic batch jobs, Container Apps jobs; a batch job without a schedule gets a placeholder one) | the service or task |
| Service, and an HTTPS Ingress when the app was reachable from outside (published port, external ingress, Traefik or Fabio tags) | the ports |
| ExternalSecret, remote key `<namespace>--<component>` | settings whose name or value is a secret (passwords, tokens, keys, connection strings, URLs with a password), Swarm secrets and configs, Container Apps secret references, Nomad Vault templates, ECS `secrets` |
| PersistentVolumeClaim (and one replica) | named volumes, Nomad volume mounts, Azure Files mounts, ECS mount points |
| emptyDir | anonymous volumes, tmpfs, bind mounts (noted), `/tmp` |
| Probes | the health check: an HTTP probe when it calls `curl`/`wget` on localhost or is an HTTP check, else TCP or exec |
| NetworkPolicy | the ports in the settings' URLs and connection strings, HTTPS, the app's own namespace |
| Sandbox IdP client | sign-in settings in the environment, e.g. `OpenIdConnect__Authority` and `OpenIdConnect__ClientId` |

Databases, caches and brokers in a compose file or Nomad job (PostgreSQL, Redis, RabbitMQ, ...) are not
migrated as apps: use a managed service or the appliance's [lab services](lab-services.md). What cannot be
carried over (placement constraints, scale rules, Dapr, privileged mode, the Docker socket, variables set
where the stack is deployed) is listed in the app's `MIGRATION.md`.

## Images and the security gate

The image is the application's own. A service with a build section, or whose image name matches a folder
with a Dockerfile, is built from the repository's Dockerfile; any other is pulled from where the platform
runs it and mirrored to the scan's registry (the worker needs access to that registry; allow its host on
the Firewall page). Then the same gate as for generated images runs: manifest lint, image vulnerability
scan, SBOM, and a run with the hardened security context (non-root user, read-only root file system, all
capabilities dropped). Findings in the repository's own Dockerfile are reported as warnings to fix there.

When the hardened run fails because the app writes to a folder, the folder the error names becomes a
writable emptyDir and the run is repeated. A component that still fails is not deployed, with the
reason on the repository page.

## LLM-heavy mode

Off by default. When it is on, platform migrations and the sandbox tester ask the LLM as often as they
need:

- descriptors the rules cannot read (other platforms, files that do not parse) are translated by the LLM;
- every service is reviewed by the LLM before the manifests are generated: settings that are secrets,
  health check paths, ports, writable folders;
- a container that fails the hardened run gets an LLM fix, for up to `CONTAINERIZER_LLM_HEAVY_ROUNDS`
  rounds (default 3);
- with sandbox verification (`containerizer org --verify-sandbox --llm-heavy`), a component that is
  failing in the cluster gets an LLM diagnosis in `sandbox/HEALTH.md`. For migrated apps its fix is
  applied, committed and checked again, and kept in the app's `sandbox-fixes.json` so later scans
  generate it too.

Every answer is validated before use: unknown keys, names and paths that do not fit, and secret values
in settings are dropped, and what the LLM changed is marked in `MIGRATION.md`. It needs three switches:

1. `CZ_LLM_HEAVY=true` in `/etc/containerizer/appliance.env` (then reboot). Outside the appliance, set
   `CONTAINERIZER_LLM_HEAVY=true` for the worker.
2. **Ask the LLM** on the organization scan, and an LLM under **Admin → Source control & LLM**.
3. **LLM-heavy mode** on the organization scan.

## LLM usage

Every LLM call is counted, by scan, repository, feature (`assessment`, `build-diagnosis`, `dev-database`,
`platform-migration`, `sandbox-tester`) and model, and shown in the **LLM usage** row of the Grafana
dashboard: calls, tokens in and out, the estimated cost, which scans have LLM-heavy mode on, and the
repositories that cost the most. The repository page shows the calls of its latest scan.

| Metric | Labels |
| --- | --- |
| `containerizer_llm_calls_total` | scan, repository, feature, backend, model, result (`answered`, `cached`, `failed`) |
| `containerizer_llm_input_tokens_total`, `containerizer_llm_output_tokens_total` | scan, repository, feature, model |
| `containerizer_llm_cost_usd_total` | scan, repository, feature, model |
| `containerizer_llm_seconds_total` | scan, feature, model |
| `containerizer_llm_heavy_mode` | scan |
| `containerizer_llm_heavy_allowed` | |

The cost is an estimate from the list prices of the Claude models. For a self-hosted LLM set
`CONTAINERIZER_LLM_PRICE_INPUT` and `CONTAINERIZER_LLM_PRICE_OUTPUT` (US dollars per million tokens) in
`worker.env` to count what it costs you; without them its cost shows as 0. Cached answers use no tokens.
