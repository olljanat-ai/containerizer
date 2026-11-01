# Running the appliance

The appliance is an immutable OS image built with the
[Elemental toolkit](https://github.com/rancher/elemental-toolkit) (as in
[Firewall4AI](https://github.com/olljanat-ai/Firewall4AI)), installed from an ISO or started from a disk
image, and upgraded from the admin pages. To install it, see [Getting started](appliance.md).

## What it runs

| Part | How | Reached at |
| --- | --- | --- |
| Web UI and API (results, admin pages, System, Firewall and Sandbox HTTPS pages) | systemd service, user `cz-web`, no privileges | `https://<appliance>/` |
| Scan worker ([organization scans](scheduled-scans.md)) | systemd service, user `containerizer` + Docker | - |
| SQL Server 2025 (results database) | container, non-root, data on the persistent partition | `127.0.0.1:1433` only |
| Sandbox cluster: k3s (single node) with Flux and Traefik | systemd service | `kubectl` on the appliance; apps at `https://<component>-<app>.<domain>/` with [Sandbox HTTPS](sandbox-https.md) |
| [Lab services](lab-services.md) for the sandboxed apps: SQL Server, PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ, Kafka, S3, Azure Blob storage, SFTP (each optional) | k3s, namespace `containerizer-lab`, data on the persistent partition | Admin → Lab services; inside the cluster only |
| Local container registry | container | `127.0.0.1:5000` only (Docker and k3s) |
| Prometheus and Grafana, with the scan worker's metrics, alerts and dashboard | containers | `https://<appliance>/grafana/` |
| HTTPS (Caddy), SSH | systemd services | ports 443 and 22: the only open ports |
| Firewall and DNS filter: every outgoing connection is blocked unless an allow-list rule covers it | nftables + dnsmasq | Admin → Firewall |

```
                 443 (HTTPS)                                  22 (SSH, root)    
                     │                                              │
 ┌───────────────────┼──────────────────────────────────────────────┼─────────────────────────────────┐
 │ Caddy ──► web UI + API ──(status, requests)──► system agent (root): upgrade, roll back, firewall    │
 │   │        │                                                                                       │
 │   │        └──► SQL Server ◄── scan worker ──► Docker (builds, scans) ──push──► registry :5000      │
 │   └──► Grafana ──► Prometheus ──scrape──┘                                           │ pull         │
 │                                                         k3s + Flux ◄── output repo ─┘              │
 │ nftables: in 22/443 only · out: only to addresses of allowed names (dnsmasq fills the sets)        │
 └────────────────────────────────────────────────────────────────────────────────────────────────────┘
   OS: read-only btrfs snapshot (A/B with fallback)      data: COS_PERSISTENT partition (rest of the disk)
```

The OS is a read-only snapshot of the container image `ghcr.io/olljanat-ai/containerizer-appliance`.
Everything that has to survive a restart or an upgrade is on the persistent partition: the database,
`/etc/containerizer` (configuration and generated secrets), Docker and k3s data, the registry, clones,
learned rules, logs. An upgrade writes the new version as a new snapshot next to the running one; if it
does not start properly, the appliance goes back to the previous snapshot by itself.

## Root password and SSH

`root` is the only administrator account on the OS. It signs in on the console or over SSH with its
password, or over SSH with a key in `/root/.ssh/authorized_keys`. The password is `containerizer` and
expired on a new appliance, so the first sign-in, on the console or over SSH, asks for a new one (until
then PAM may refuse an SSH key as well). `/etc` is rebuilt at every boot, so the appliance keeps root's
password entry in `/etc/containerizer/secrets/root-shadow` (persistent partition) and puts it back at every
start; changes with `passwd` are saved there by themselves (`containerizer-root-password.path`).

- **Keys only**: after adding your key, `passwd -l root` locks the password: password sign-in stops
  working on SSH and the console, keys keep working. `passwd -u root` unlocks it.
- **Forgotten password**: start the recovery system from the GRUB menu (it always starts with the default
  password, expired), mount the persistent partition (label `COS_PERSISTENT`) and delete
  `root-shadow` from the `secrets` folder of `/etc/containerizer` there; the next start of the
  appliance goes back to the default password.
- The recovery system does not keep a changed password: each start asks for a new one again.

## Unattended installs

Pass an Elemental cloud-config with the key, e.g.
`elemental install --cloud-init my.yaml /dev/sda` from the ISO, or put the file into the OEM partition:

```yaml
stages:
  fs:
    - name: "SSH key of the administrator"
      authorized_keys:
        root:
          - "ssh-ed25519 AAAA... you@example.com"
```

The root password is the default (`containerizer`) and expired on unattended installs too.

## Configuration files

The first boot creates `/etc/containerizer/` (mode 700) with:

| File | What to set |
| --- | --- |
| `appliance.env` | `CZ_HOSTNAME` (the name in the HTTPS certificate and the sign-in redirect), `CZ_ACME_EMAIL` (Let's Encrypt instead of the appliance's own CA), `CZ_DNS_SERVERS`, `CZ_MSSQL_EDITION`, `CZ_MSSQL_MEMORY`, `CZ_LLM_HEAVY` ([LLM-heavy mode](platform-migration.md#llm-heavy-mode), off by default) |
| `web.env` | Sign-in for the web UI: `CONTAINERIZER_OIDC_*`, `CONTAINERIZER_ADMINS`, roles, viewers, API ([sign-in and roles](sign-in.md)) |
| `worker.env` | Push credentials for an external image registry, and extra registry hosts the worker may push to. Scans that push to the appliance's own registry need none; source control tokens are registered on the admin pages ([source-control.md](source-control.md)) |
| `sandbox.env` | The output repository the sandbox cluster deploys from ([the sandbox cluster](scheduled-scans.md#the-sandbox-cluster)) |
| `grafana.env` | Optional Grafana settings, e.g. sign-in with your identity provider |
| `egress.json` | The egress allow-list: change it on the Firewall page, not here |
| `secrets/` | Generated passwords (SQL Server logins, Grafana `admin`) and the key pair that seals source control tokens (`credential-key` for the worker only, `credential-key.pub` for the web UI): root-only, never shown in the web UI. Keep `credential-key` when restoring a backup: the registered tokens open only with it |
| `network/` | Optional `systemd-networkd` `.network` files for static addresses (default: DHCP on every NIC) |

## Firewall

**Inbound**: only TCP 22 (SSH) and 443 (HTTPS). The k3s API, SQL Server, the registry,
Prometheus and Grafana listen on the loopback interface or are not reachable from outside; NodePorts of
the sandbox cluster are blocked too (use `ssh -L` to reach anything else).

**Outbound**: blocked, except to the names and networks on the allow-list. This holds for the appliance
itself, the scan worker, every container Docker builds or runs, and every pod in the sandbox cluster.

How it works: the host, Docker and k3s resolve names only through the appliance's DNS filter (dnsmasq on
169.254.53.53). It answers only names an allow-list rule covers (anything else gets REFUSED), and puts the
addresses of the answer into nftables sets of that rule's ports. The firewall lets connections out only
to addresses in those sets (and to the networks of network rules), on the rule's ports. A connection to an
address nobody resolved through the filter, an address of a name that is not allowed, or another port is
dropped and logged.

**Admin → Firewall** (administrators only):

- **Allow** a name (it covers its subdomains: `nuget.org` also allows `api.nuget.org`) or a network
  (`10.20.0.0/16`), with ports (`443`, `80,443`, `udp/123`) and a note.
- **Refused names, last 24 hours**: what something on the appliance tried to resolve and was refused,
  with an **Allow** button. Run a scan, then allow what it needs.
- **Blocked connections**: addresses and ports the firewall dropped.
- **Log only mode** lets everything out but still lists what would have been refused, to build the list.
  Turn blocking back on when you are done.
- **Always allowed**: what the appliance needs itself (GHCR and Sigstore for upgrades and their signatures,
  Docker Hub and the Microsoft registry for its own service images). Part of the OS image.
- **Change history**: who changed what, kept on the persistent partition.

The web UI does not change the firewall itself: it asks the system agent (root), which checks the rules
again, loads the new ruleset in one transaction (checked with `nft -c` first, and the previous ruleset is
kept if the new one does not load) and restarts the DNS filter. On the console:
`/usr/lib/containerizer/venv/bin/python -m containerizer.sysagent firewall show`.

## Local registry and the sandbox cluster

The registry at `localhost:5000` is for images of the sandbox: in an organization scan, set the registry
to `localhost:5000/<path>` and turn pushing on; the scan worker pushes there without credentials, and k3s
pulls from it (`/etc/rancher/k3s/registries.yaml`) without pull secrets. It is not reachable from outside
the appliance. Deleted tags free their space after a garbage collection:
`docker exec cz-registry registry garbage-collect --delete-untagged /etc/distribution/config.yml`
(stop the worker first).

k3s also runs External Secrets Operator, and the generated configurations get every secret through it
([external-secrets.md](external-secrets.md#the-appliance-sandbox)). The values live in namespace
`containerizer-secrets`, which runs no pods, and each namespace can read only its own keys.

To deploy what the scans generate, set `sandbox.env` (output repository URL, branch, read-only token).
Every 2 minutes `cz-sandbox` puts the read-only token in the secret store for Flux's root sync and for
every app namespace, and creates the root `GitRepository` + `Kustomization` of the output repository's
`sandbox/flux/`. Each app reconciles as its own ServiceAccount with its own copy of the token
([the sandbox cluster](scheduled-scans.md#the-sandbox-cluster)). Allow the Git server on
the Firewall page. `kubectl` (as root on the appliance) shows the result. Argo CD is not installed; Flux
is the supported path on the appliance.

To reach the deployed apps over HTTPS, set up a wildcard domain and certificate on **Admin → Sandbox
HTTPS**: Caddy answers for `*.<domain>` on the same port 443 and passes the requests to Traefik in k3s,
and every web component gets `https://<component>-<app>.<domain>/` ([sandbox-https.md](sandbox-https.md)).

Components that sign users in get the sandbox identity provider, WSO2 Identity Server at
`https://containerizer-idp.<sandbox domain>/` ([sandbox-idp.md](sandbox-idp.md)). `cz-sandbox` creates its
passwords and client secrets in the secret store once Flux has deployed it.
`containerizer idp users` (as root) prints the test users and their passwords. Its images come from
Docker Hub, which the default firewall rules allow.

## Upgrade and roll back

**Admin → System** (administrators only) shows the running version, the snapshots on the disk and the
last upgrade or roll back with its outcome, and checks GHCR for newer releases.

- **Upgrade**: pick a newer release and confirm. The system agent checks with cosign that the image was
  signed by this repository's release workflow (keyless signature, GitHub's OIDC identity of
  `.github/workflows/release.yml` on a `vX.Y.Z` tag), then installs exactly the verified digest as a new
  snapshot and restarts. Only release tags of the appliance's own image repository are accepted, whatever
  the web UI sends.
- **Automatic fallback**: after an upgrade the boot assessment checks that the firewall is loaded and
  the DNS filter, Docker and k3s run and the application starts. If that fails 5 times, the appliance
  restarts into the previous snapshot, and the System page shows the upgrade as failed.
- **Roll back**: pick an earlier snapshot. It is installed as a new active snapshot (no download) and the
  appliance restarts. Data on the persistent partition is not rolled back: the database keeps its schema
  (newer versions only add to it, and older code reads it).
- The GRUB menu at start-up also lists the snapshots, and a recovery system.

On the console: `python -m containerizer.sysagent upgrade vX.Y.Z` or `... rollback <snapshot>` (with
`/usr/lib/containerizer/venv/bin/python`). The appliance checks GHCR anonymously, so the
`containerizer-appliance` package must be public.

## Backup

Back up the database (from the appliance):

```sh
docker exec cz-mssql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$(cat /etc/containerizer/secrets/mssql-sa)" \
  -Q "BACKUP DATABASE Containerizer TO DISK = N'/var/opt/mssql/backup/containerizer.bak' WITH COMPRESSION, INIT"
# the file is /var/lib/containerizer/mssql/backup/containerizer.bak
```

and `/etc/containerizer` (configuration and secrets). Everything else is rebuilt by the next scans.

## Security notes

- OS: read-only, signed upgrades only, no package manager in use, kernel and network hardening sysctls,
  root's default password must be changed at the first sign-in (`passwd -l root` for SSH keys only), no service but SSH and HTTPS reachable, outbound allow-list for everything.
- Web UI: no privileges (systemd sandbox: read-only system, no capabilities, system call filter); its
  database passwords come as systemd credentials. It cannot change the OS: upgrades, roll backs and the
  firewall go through the system agent, which checks every request again.
- SQL Server: non-root, every capability dropped except binding its port, loopback only.
  Edition: Express by default (free, 10 GB per database); Developer is not licensed for production.
- The scan worker is in the `docker` group, which is equivalent to root: it builds and runs the scanned
  repositories' images. That is why the appliance is a dedicated machine, and why the egress allow-list
  applies to every build. Give it no credentials beyond the scans' tokens.
- k3s: secrets encrypted at rest, delivered by External Secrets Operator from a namespace without pods, audit log (`/var/lib/rancher/k3s/server/logs/audit.log`), kernel
  defaults protected, API reachable only from the appliance and its pods. Each app's namespace runs
  under Pod Security "restricted".
- Containers of the appliance's own services are pinned by digest in the OS image
  (`/usr/lib/containerizer/images.env`); each release has an SPDX SBOM attested to the image with cosign.

## Troubleshooting

| | |
| --- | --- |
| Something does not start | `systemctl --failed`, `journalctl -b -u <unit>`; units are `containerizer-*`, `k3s`, `caddy`, `docker` |
| A scan cannot reach a host | Admin → Firewall → Refused names; or `journalctl -u containerizer-dns \| grep REFUSED` |
| The firewall did not load | the SSH-only fallback ruleset is active; `systemctl status containerizer-firewall` shows why |
| Status of the system agent | `/run/containerizer/system/status.json`, `journalctl -u containerizer-sysagent` |
| Locked out of SSH | the console of the VM: GRUB menu → recovery, or a previous snapshot |
