# Changelog

Releases are tagged `vX.Y.Z`. Each release publishes the appliance OS image to
`ghcr.io/olljanat-ai/containerizer-appliance` (signed with cosign by the release workflow) and the ISO,
qcow2 and VHD images as release assets.

## 0.1.0 (2026-10-31)

The first release: the assessor, the GitHub Action and Azure DevOps gate, the results database with its web
UI and admin pages, and the appliance.

### Appliance
- Immutable VM image and installer ISO built with the Elemental toolkit (Debian 13): signed upgrades and
  roll back from **Admin → System**, local container registry, k3s sandbox cluster with Flux, and an
  egress firewall with a DNS filter (#37)
- Source control tokens and the LLM settings on the admin pages: read-only tokens per Azure DevOps,
  GitHub or GitLab organization (sealed at rest), access only to organizations with a token, and a
  separate write token for the repository that receives generated files (#44). The scan worker no
  longer reads organization or output tokens from its environment; see
  [docs/source-control.md](docs/source-control.md). Results database schema version 10.
- Sandbox lab services next to the scanned apps: SQL Server 2025, PostgreSQL, MySQL, MongoDB, Redis,
  RabbitMQ, Kafka, SFTP, S3 and Azure Blob (#51, #54, #59), with dev database uploads for SQL Server,
  PostgreSQL and MySQL (#59, #61)
- Sandbox HTTPS with a wildcard domain and certificate (#46) and an identity provider, WSO2 Identity
  Server, for OIDC, SAML 2.0 and WS-Federation (#55)
- External Secrets Operator for every secret in generated configs (#47)
- Rule approval from the admin UI and SBOMs attached to sandbox images with ORAS (#61)
- Release workflow: OS image on GHCR signed with cosign and its SBOM attested; ISO, qcow2 and VHD as
  release assets with signed checksums

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
