# Changelog

Releases are tagged `vX.Y.Z`: bump `containerizer/__init__.py` and this file, then run the **release** workflow
by hand on `main` with the version, and it tags the commit and releases from the tag. Each release publishes the appliance OS image to
`ghcr.io/olljanat-ai/containerizer-appliance` (signed with cosign by the release workflow) and the ISO,
qcow2 and VHD images as release assets.

## Unreleased

Results database schema version 19 (`containerizer db init` upgrades it; the appliance does at start).

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

