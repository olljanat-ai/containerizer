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
| LLM queue runner ([queued LLM reviews](scheduled-scans.md#the-llm-queue), [refactoring patches](refactoring.md)) | systemd service `containerizer-llm-queue`, user `containerizer` + Docker (to build and run refactoring patches), reads the scan worker's clones, writes only its answer cache and `/var/lib/containerizer/refactor` | Admin → LLM queue, Admin → Refactoring |
| [Egress observer](egress.md#the-egress-observer): what the sandbox blocks (its NetworkPolicies, the firewall, the DNS filter) | systemd service `containerizer-egress-observer`, user `containerizer` with CAP_NET_ADMIN (the NFLOG drop log) and CAP_SYSLOG (the kernel log, for the firewall's drops) only, its own read-only Kubernetes account | Admin → Egress, the results pages' Network connectivity |
| SQL Server 2025 (results database), or your own SQL Server ([external database](#external-database)) | container, non-root, data on the persistent partition | `127.0.0.1:1433` only |
| Sandbox cluster: k3s (single node) with Flux and Traefik | systemd service | `kubectl` on the appliance; apps at `https://<component>-<app>.<domain>/` with [Sandbox HTTPS](sandbox-https.md) |
| [Lab services](lab-services.md) for the sandboxed apps: SQL Server, PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ, Kafka, S3, Azure Blob storage, SFTP (each optional) | k3s, namespace `containerizer-lab`, data on the persistent partition | Admin → Lab services; inside the cluster only |
| Local container registry | container | `127.0.0.1:5000` only (Docker and k3s) |
| Prometheus and Grafana, with the scan worker's, k3s' and Flux's metrics, alerts and dashboards ([metrics](#metrics)) | containers | `https://<appliance>/grafana/` |
| HTTPS (Caddy), SSH | systemd services | ports 443 and 22: the only open ports |
| Firewall and DNS filter: every outgoing connection is blocked unless an allow-list rule covers it | nftables + dnsmasq | Admin → Firewall |
| [Built-in LLM](#built-in-llm) (optional, off by default): llama.cpp with Qwen3-Coder 30B-A3B on the CPU | container, non-root, read-only model | `127.0.0.1:8090` (and up, one port per server) only; Admin → Source control & LLM |
| [kubemg](#kubemg) (optional, off by default): audited console and kubectl access to the sandbox cluster | containers (kubemg and its PostgreSQL), non-root, read-only; its agent in the sandbox cluster | `https://kubemg.<appliance>/` (its own name on 443) |

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
(except in 0.3.4, where you change it yourself with `passwd`) expired on a new appliance, so the first sign-in, on the console or over SSH, asks for a new one (until
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
| `appliance.env` | `CZ_HOSTNAME` (the DNS name users open, usually the FQDN: the name in the HTTPS certificate and the sign-in redirect; it does not rename the machine), `CZ_ACME_EMAIL` (Let's Encrypt instead of the appliance's own CA; your own certificate: [HTTPS certificate](#https-certificate)), `CZ_DNS_SERVERS`, `CZ_MSSQL_EDITION`, `CZ_MSSQL_MEMORY`, `CZ_SQL_*` ([external database](#external-database)), `CZ_LLM_HEAVY` ([LLM-heavy mode](platform-migration.md#llm-heavy-mode), off by default) |
| `web.env` | Sign-in for the web UI: `CONTAINERIZER_OIDC_*`, `CONTAINERIZER_ADMINS`, roles, viewers, API ([sign-in and roles](sign-in.md)) |
| `worker.env` | Push credentials for an external image registry, and extra registry hosts the worker may push to. Scans that push to the appliance's own registry need none; source control tokens are registered on the admin pages ([source-control.md](source-control.md)) |
| `sandbox.env` | The output repository the sandbox cluster deploys from ([the sandbox cluster](scheduled-scans.md#the-sandbox-cluster)) |
| `grafana.env` | Optional Grafana settings, e.g. sign-in with your identity provider |
| `egress.json` | The egress allow-list: change it on the Firewall page, not here |
| `secrets/` | Generated passwords (SQL Server logins, Grafana `admin`), the root password (`root-shadow`), `sql-owner` for an [external database](#external-database) and the key pair that seals source control tokens (`credential-key` for the worker only, `credential-key.pub` for the web UI): root-only, never shown in the web UI. Keep `credential-key` when restoring a backup: the registered tokens open only with it |
| `network/` | Optional `systemd-networkd` `.network` files for static addresses (default: every NIC in one bond, DHCP on it: [Network](#network)) |

## Network

Every wired interface (`e*`) joins one bond, `bond0`, in active-backup mode, and the appliance takes its
address on `bond0` by DHCP (IPv4 and IPv6). On a physical server, cable every NIC you want to use: when the
active one loses its link (a cable, a NIC or a switch port), another takes over within a fraction of a second, on
the same address. Connect them to the same network (VLAN); no switch configuration is needed (no LACP). On a VM
with one NIC the bond is just that NIC.

- **MAC address:** the bond uses the MAC of its first interface, so a hypervisor that allows only the MAC it
  assigned (Hyper-V, vSphere port groups that reject forged transmits) still passes its traffic.
- **DHCP reservation:** the DHCP client ID comes from the appliance's machine-id, so the lease stays the same
  whichever NIC is active. Reserve the address by that client ID (`networkctl status bond0` shows the lease), or
  set a static address.
- **Static address:** a `.network` file for `bond0` in `/etc/containerizer/network/`, named so it sorts before
  `21-uplink-bond0.network`, then reboot:

    ```ini
    # /etc/containerizer/network/10-static.network
    [Match]
    Name=bond0

    [Network]
    Address=192.0.2.10/24
    Gateway=192.0.2.1
    DNS=192.0.2.53
    ```

  A file that matches a NIC by name (`Name=eno1`) instead keeps that NIC out of the bond.
- **Switches:** the appliance sends and receives LLDP on every port, so the switch shows which port it is on, and
  `networkctl lldp` shows the switch and port of each NIC.
- `cat /proc/net/bonding/bond0` shows the active interface and each port's link.

## HTTPS certificate

The web UI and Grafana are served over HTTPS for `CZ_HOSTNAME` (`appliance.env`) with one of three
certificates, the first that applies:

1. **Your own**, for example from your company's CA: put the certificate in
   `/etc/containerizer/tls/cert.pem`, followed by its intermediate CA certificates (PEM, server certificate
   first; the root is not needed), and its private key, unencrypted, in `/etc/containerizer/tls/key.pem`
   (`chmod 600`). It must name `CZ_HOSTNAME` (subject alternative name). Then `systemctl reboot`. Renew it the
   same way: replace both files and restart. It wins over `CZ_ACME_EMAIL`.
2. **Let's Encrypt**, with `CZ_ACME_EMAIL` set: the name must resolve to the appliance from the internet
   (TLS-ALPN challenge on 443), and `acme-v02.api.letsencrypt.org` must be allowed on the Firewall page.
3. **The appliance's own CA** (default): browsers warn until you trust its root,
   `/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt`.

Only the internal CA's certificate also covers the appliance's IP addresses. If the web UI does not answer after
a change, `journalctl -b -u caddy -u containerizer-firstboot` says why (for example a key that does not match
the certificate).

## External database

By default the results database runs on the appliance, and you back it up ([Backup](#backup)). To keep it
on a SQL Server you already run and back up (SQL Server 2019 or later, or Azure SQL Managed Instance), point
the appliance at it in `appliance.env`. SQL Server then does not run on the appliance, and the database is
backed up with your server; the appliance's files still need their backup ([Backup](#backup)).

1. On your server, create the database and a login that owns it (`db_owner`). With
   `CZ_SQL_LOGINS=create` (the default) the login also needs `ALTER ANY LOGIN` (e.g. `securityadmin`): it
   creates the logins `cz_scanner`, `cz_web` and `cz_admin` with generated passwords. If your DBA creates
   logins instead, create those three yourself and set `CZ_SQL_LOGINS=existing`.
2. In `/etc/containerizer/appliance.env`:

    ```sh
    CZ_SQL_SERVER=sql01.example.com,1433
    CZ_SQL_DATABASE=Containerizer
    CZ_SQL_USER=containerizer_owner
    CZ_SQL_LOGINS=create
    # optional: more connection string options, in quotes
    CZ_SQL_OPTIONS="Schema=containerizer"
    # optional: the CA of the server's certificate when the system CAs do not cover it
    CZ_SQL_CA=/etc/containerizer/sql-ca.pem
    ```

3. Put the passwords in place (root only):

    ```sh
    install -m 0400 /dev/stdin /etc/containerizer/secrets/sql-owner      # the password of CZ_SQL_USER, then Ctrl-D
    # only with CZ_SQL_LOGINS=existing: the three logins' passwords, the same way, into
    # secrets/cz-scanner, secrets/cz-web and secrets/cz-admin
    ```

4. Reboot.

At every start `containerizer-db-init` creates or upgrades the schema on that server as `CZ_SQL_USER`
(the same as on the appliance's own SQL Server), so an upgrade of the appliance upgrades the database.
The connection is encrypted and the server certificate is checked (the system CAs, or `CZ_SQL_CA`);
`TrustServerCertificate=yes` in `CZ_SQL_OPTIONS` turns the check off, for test servers only. The firewall
allows the server and port by itself (Firewall page → Always allowed); a DNS name must resolve through the
appliance's DNS servers (`CZ_DNS_SERVERS`). Named instances (`host\instance`) are not supported: give the
port. The login names are fixed, so one SQL Server instance serves one appliance with
`CZ_SQL_LOGINS=create`.

To move the data of an appliance that already ran scans: back up its database ([Backup](#backup)), restore
the `.bak` on your server, then set it up as above: the restored database users `cz_scanner`, `cz_web` and
`cz_admin` are mapped to the logins of that server by themselves. The appliance no longer uses
`/var/lib/containerizer/mssql`; keep it until a scan has written to the external database, then delete it. To go
back to the appliance's own SQL Server, empty `CZ_SQL_SERVER` and reboot (it starts with what that folder
holds).

If the settings are not valid, the web UI and the scan worker do not start:
`journalctl -b -u containerizer-firstboot -u containerizer-db-init` says why.

## Firewall

**Inbound**: only TCP 22 (SSH) and 443 (HTTPS), and ping (ICMP and ICMPv6 echo requests, at most 20 a second). The k3s API, SQL Server, the registry,
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
  Docker Hub and the Microsoft registry for its own service images). Part of the OS image. While the
  [built-in LLM](#built-in-llm)'s model downloads, `huggingface.co` and `hf.co` are listed here too.
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
`sandbox/flux/`. Until `sandbox.env` names the repository nothing is deployed, even when the scans and Make it A
write to it with the write token of **Admin → Source control**: the two are set separately. What `cz-sandbox` last
found is at the top of Grafana's Flux dashboard and in `journalctl -u containerizer-sandbox` (each change), and the
alert `ContainerizerSandboxNotConnected` fires after 15 minutes without a connection. Each app reconciles as its own ServiceAccount with its own copy of the token
([the sandbox cluster](scheduled-scans.md#the-sandbox-cluster)). Allow the Git server on
the Firewall page. `kubectl` (as root on the appliance) shows the result. Flux is the only GitOps tool.
An application moved to an [output repository of its own](scheduled-scans.md#own-output-repository) is
deployed from that repository, with its token: the LLM queue runner writes it to
`/var/lib/containerizer/refactor/sandbox-git/<namespace>` (0600, its own user) and `cz-sandbox` puts it in that
namespace's key.

Flux polls the output repository every 5 minutes; after each push the scan worker and the LLM queue runner also
call a Flux webhook (Receiver `flux-system/containerizer-sandbox`, which `cz-sandbox` keeps up to date) so the
commit deploys at once. Its URL, the secret, is in `/run/containerizer/flux-webhook` (root:containerizer 0640) and
reachable from the appliance only ([polling and the webhook](scheduled-scans.md#flux-webhook)).

To reach the deployed apps over HTTPS, set up a wildcard domain and certificate on **Admin → Sandbox
HTTPS**: Caddy answers for `*.<domain>` on the same port 443 and passes the requests to Traefik in k3s,
and every web component gets `https://<component>-<app>.<domain>/` ([sandbox-https.md](sandbox-https.md)).

Components that sign users in get the sandbox identity provider, WSO2 Identity Server at
`https://containerizer-idp.<sandbox domain>/` ([sandbox-idp.md](sandbox-idp.md)). `cz-sandbox` creates its
passwords and client secrets in the secret store once Flux has deployed it.
`containerizer idp users` (as root) prints the test users and their passwords. Its images come from
Docker Hub, which the default firewall rules allow.

## Metrics

Grafana (`https://<appliance>/grafana/`, **Grafana ↗** on the admin pages) has three dashboards, in the
**containerizer** folder (the dashboard list at the top of each links to the others):

| Dashboard | Shows |
| --- | --- |
| **Containerizer: organization scans** (the home page) | Scans, the scan worker, LLM usage, the LLM queue and the built-in LLM ([scheduled-scans.md](scheduled-scans.md#metrics-and-grafana)) |
| **Containerizer: k3s sandbox cluster** | Whether the API server and kubelet answer, pods running and not running, containers waiting (CrashLoopBackOff, ImagePullBackOff, ...), restarts, deployments short of replicas, CPU, memory and network by namespace and the top pods, volume usage, and the API server's requests and latency |
| **Containerizer: Flux** | First, whether the sandbox is connected to the output repository at all: what `cz-sandbox` last found (connected, or why not: `sandbox.env` without a repository URL, no token, the secret store or Flux not ready) and when, and the root sync's GitRepository and Kustomization (`flux-system/containerizer-sandbox`: missing, not ready with the reason, or ready at a revision); the applications' containers that do not start (ImagePullBackOff, CrashLoopBackOff, ...) and restart. Then every Flux object (Kustomizations, Git, OCI and Helm sources, Helm releases, image automation) with its Ready state, reason, revision and suspend flag; the ones not ready first; the controllers' reconciliations, errors, reconcile time, work queues, CPU and memory |

![Grafana: the k3s sandbox cluster dashboard](images/grafana-k3s-dashboard.png#only-light)
![Grafana: the k3s sandbox cluster dashboard](images/grafana-k3s-dashboard-dark.png#only-dark)

![Grafana: the Flux dashboard, every Flux object with its state](images/grafana-flux-dashboard.png#only-light)
![Grafana: the Flux dashboard, every Flux object with its state](images/grafana-flux-dashboard-dark.png#only-dark)

Prometheus keeps 90 days. What it reads from the sandbox cluster:

- **kube-state-metrics** (namespace `cz-monitoring`, from `/var/lib/rancher/k3s/server/manifests/containerizer-monitoring.yaml`):
  the state of the cluster's objects and, through its custom resource configuration, of Flux's objects
  (`gotk_resource_info`).
- **Flux's controllers** (namespace `flux-system`, their `http-prom` port) and kube-state-metrics, found through
  the API server.
- **The API server and the kubelet** (`127.0.0.1:6443`, `127.0.0.1:10250`; CPU and memory per pod from
  cAdvisor), only the metrics the dashboards use.

It reads them as the read-only ServiceAccount `cz-monitoring/cz-prometheus` (pods, nodes, endpoints and services
listed; node and API server metrics), whose token `containerizer-prometheus-k8s.service` copies to
`/run/containerizer/prometheus-k8s` with the cluster's CA when k3s is up; the TLS certificates are verified. Until
then, and while k3s is down, those targets are down (`up{job=~"k3s-apiserver|kubelet.*|flux|kube-state-metrics"}`).

## Upgrade, roll back and restart

**Admin → System** (administrators only) shows the running version, the snapshots on the disk and the
last upgrade or roll back with its outcome, and checks GHCR for newer releases.

- **Planned restart**: a restart, an upgrade and a roll back are planned the same way: **now** or **at** a time (UTC,
  within 30 days), and how long to **wait for running scans and LLM jobs** (not at all, at most 30 minutes to 8 hours,
  or until they are done; 2 hours by default). From the planned time on, the scan worker starts no new scan run
  and the LLM queue runner no new job (its page says why); queued runs and jobs keep their place. The appliance
  restarts, or upgrades or rolls back and then restarts, as soon as nothing runs any more, or when the wait is over:
  a scan cut off then is marked failed and the next run processes every repository again, an LLM job cut off goes
  back to the queue. The page shows the plan, how much work it still waits for and when it restarts at the latest;
  **Cancel the planned restart** lets everything go on. One plan at a time; it survives an unplanned restart
  (`containerizer-restart.timer` checks it every minute, as root).
- **Upgrade**: pick a newer release and confirm. The system agent checks with cosign that the image was
  signed by this repository's release workflow (keyless signature, GitHub's OIDC identity of
  `.github/workflows/release.yml` on a `vX.Y.Z` tag), then installs exactly the verified digest as a new
  snapshot and restarts. Only release tags of the appliance's own image repository are accepted, whatever
  the web UI sends.
- **App updates (patch releases)**: a newer patch release of the running series (for example 0.12.3 on an
  appliance of 0.12.0 to 0.12.2) is installed as an **app update**, not as a new OS: the list marks each release
  "app update, the OS does not restart" or "OS upgrade". A patch release changes only the application (the code
  and the rules; the release workflow refuses one that changes the OS image), so the system agent downloads just
  that, a few MB: the signed image `ghcr.io/olljanat-ai/containerizer-app:vX.Y.Z`, checked with cosign against
  the same release workflow identity and fetched by its verified digest. It is unpacked on the persistent
  partition (`/var/lib/containerizer/app-patches/`), its code must import with the OS's Python packages, and it is
  mounted read-only on `/run/containerizer/app-patch`, which Python reads before the OS image's own code. Only the
  containerizer services (web UI, scan worker, LLM queue runner, egress observer) restart; when they do not come
  up within 2 minutes, the code that ran before is put back. Planning and waiting for the work in progress work as
  for an OS upgrade. A minor or major release is always an OS upgrade, and the app update is not used any more
  on its new OS (it was built for the previous series). **Remove the app update** on the System page goes back to
  the OS image's own code; a roll back to a snapshot removes it too. Appliances whose OS image predates app
  updates (0.11.x and older) take one OS upgrade first.
- **Automatic fallback**: after an upgrade the boot assessment checks that the firewall is loaded and
  the DNS filter, Docker and k3s run and the application starts. If that fails 5 times, the appliance
  restarts into the previous snapshot, and the System page shows the upgrade as failed.
- **Roll back**: pick an earlier snapshot. It is installed as a new active snapshot (no download) and the
  appliance restarts. Data on the persistent partition is not rolled back: the database keeps its schema
  (newer versions only add to it, and older code reads it).
- The GRUB menu at start-up also lists the snapshots, and a recovery system.

![Admin → System: a planned upgrade waiting for the scan runs and LLM jobs in progress, the Restart and Upgrade forms](images/admin-system-restart.png#only-light){ .cz-shot }
![Admin → System: a planned upgrade waiting for the scan runs and LLM jobs in progress, the Restart and Upgrade forms](images/admin-system-restart-dark.png#only-dark){ .cz-shot }

On the console: `python -m containerizer.sysagent upgrade vX.Y.Z` or `... rollback <snapshot>` (with
`/usr/lib/containerizer/venv/bin/python`) do it at once, without waiting for the work in progress; `upgrade vX.Y.Z
--full` installs a patch release as a whole OS instead of an app update, and `app-patch remove` removes the app
update. Should an app update break the agent itself, run the OS image's own code:
`PYTHONPATH=/usr/lib/containerizer/app /usr/lib/containerizer/venv/bin/python -m containerizer.sysagent app-patch remove`.
The appliance checks GHCR anonymously, so the `containerizer-appliance` and `containerizer-app` packages must be
public.

## Built-in LLM

For sites without an LLM server of their own (a GPU server, or the Claude API), the appliance can run
one itself, on its CPU. It is off by default and is turned on under **Admin → Source control & LLM**
(administrators only). Scans with **Ask the LLM** use it when no LLM is set on that page; an LLM set
there always wins. See [the LLM](source-control.md#the-llm) for what it is asked.

![Built-in LLM running: the model checked on the disk, the machine's memory and the sizing](images/admin-built-in-llm-running.png#only-light){ .cz-shot }
![Built-in LLM running: the model checked on the disk, the machine's memory and the sizing](images/admin-built-in-llm-running-dark.png#only-dark){ .cz-shot }

| | |
| --- | --- |
| Model | Qwen3-Coder 30B-A3B Instruct, ByteShape's `IQ4_XS-4.20bpw` GGUF build (16 GB, Apache 2.0), served as `qwen3-coder-30b-a3b` |
| Server | llama.cpp `llama-server` (image `CZ_IMAGE_LLAMA_CPP` in `images.env`, pinned by digest): one per NUMA node (see below), `containerizer-local-llm@<n>.service`, container `cz-llm-<n>`, on `127.0.0.1:8090+n` |
| Listens on | `127.0.0.1:8090+n` only. The LLM queue asks each server as an LLM of its own, one request at a time each, taken per LLM call (a server still loading its model takes none yet); scans that ask directly use the first server that is up. Prometheus reads each server's metrics |
| Memory | at least 40 GB on the machine. The model (15.6 GB) is locked in RAM, so builds cannot push it out; each answer slot adds about 2 GB |
| Disk | about 20 GB free on the persistent partition for the download (16 GB plus 4 GB to spare) |
| Speed | about 7 to 12 tokens per second on a 22-core server; reading a 5,000 to 15,000 token evidence pack takes 1.5 to 5 minutes, so an answer takes about 5 minutes. Calls may take up to an hour (`CONTAINERIZER_LLM_TIMEOUT=3600` is set for it) |

**Turning it on.** The system agent checks the memory and the free space again (the page shows both), then
downloads the model once from Hugging Face, from a fixed commit of the repository, resuming a partial
download, and checks its size and SHA-256 before it is used. `huggingface.co` and `hf.co` (which covers
the download servers it redirects to) are on the allow-list only while the download runs, as system rules
on the Firewall page; then they are removed again. If the download is refused anyway, the refused names are
listed on **Admin → Firewall**. The page shows the progress; after the download the server loads the model,
which takes a minute or two, and the state turns to **Running**. A failed download (network, checksum) is
not retried by itself: **Try again** resumes it. A file that fails the checksum is deleted.

![Built-in LLM downloading its model, with the progress](images/admin-built-in-llm-downloading.png#only-light){ .cz-shot }
![Built-in LLM downloading its model, with the progress](images/admin-built-in-llm-downloading-dark.png#only-dark){ .cz-shot }

**Sizing.** The answer slots (requests answered together, for about the cost of one, since speed follows
memory bandwidth) and the container's memory limit follow the machine's memory:

| Memory | Slots | Context per slot | Memory limit of `cz-llm` |
| --- | --- | --- | --- |
| 40 to 47 GB | 1 | 22,016 tokens | 24 GB |
| 48 to 63 GB | 2 | 22,016 tokens | 27 GB |
| 64 GB or more | 3 | 22,016 tokens | 30 GB |

**Two CPU sockets (NUMA).** On a CPU the speed follows memory bandwidth, and each socket has its own memory.
When the machine has several NUMA nodes and the RAM for a copy of the model on each (16 GB for the appliance
plus at least 23 GB per copy, and each node's own memory at least its server's limit), the appliance runs one
server per node, pinned to that node's CPUs and memory (`docker run --cpuset-cpus --cpuset-mems`, as many
threads as the node has CPUs). Each answers at full speed, so two sockets answer about twice as many jobs per
hour. The LLM queue lists each server as an LLM of its own (`built-in-0`, `built-in-1`, ... on the LLM queue page)
and sends one request per server at once (a higher **Parallel requests** setting is shared out between them); a
job holds a server only while one of its LLM calls is answered, not while it builds or verifies. The LLM queue's
**Jobs at once** (automatic: the servers' requests plus one) keeps the builds of refactoring orders from crowding
the CPUs the built-in LLM needs. One server on both sockets instead would read half of its weights across the
link between them. With one node, or not enough RAM, it is one server on the whole machine, as before. The
page shows how it is sized and each server's state. The RAM is shared out between the servers before the slots
are sized (the table above, per server): 128 GB with two nodes gives two servers of 3 slots.

In a **Hyper-V** VM the guest sees the host's sockets only when Dynamic Memory is off and the VM has more vCPUs
and memory than one node (VM settings → Processor → NUMA: **Use Hardware Topology**; NUMA spanning allowed in the
host's Hyper-V settings). Check on the appliance with `lscpu | grep -i numa`: `NUMA node(s): 2`. The servers are
sized again every 5 minutes and when the built-in LLM is turned on.

It gets a quarter of the CPU's weight (`--cpu-shares 256`), so the scans' builds go first when both want
the CPU. Use the queued LLM mode for organization scans where it is offered, and leave LLM-heavy mode off:
it makes many calls, and on a CPU that turns a scan into hours or days.

**Turning it off** stops the server (or the download) at once; the model file stays, so turning it on
again starts the server without a new download. **Remove** next to **Turn on** deletes the model file to
free its 16 GB.

Files:

| What | Where |
| --- | --- |
| On or off, the download's state and the change history | `/var/lib/containerizer/system/local-llm.json` |
| The model file (re-downloadable) | `/var/lib/containerizer/llm/` |
| What the page and the scan worker read | `/run/containerizer/system/local-llm-status.json` |
| Each server's settings (slots, context, memory, NUMA node) | `/run/containerizer/local-llm-<n>.env` |

On the console: `systemctl status 'containerizer-local-llm*'`, `docker logs cz-llm-0`, and `curl -s http://127.0.0.1:8090/health` (8091 for the second server). It is not part of the start-up check of an
upgrade: a missing or slow model never makes the appliance go back to the previous snapshot. The
Grafana dashboard has a **Built-in LLM** row: whether each server is up, requests in progress and waiting, the
tokens per second it generates (each per server, label `server`), and the LLM queue's requests in progress on each
LLM now (`built-in-<n>` for the built-in LLM's servers).

## kubemg

[kubemg](https://kubemg.readthedocs.io/) is an audited console and kubectl gateway for Kubernetes clusters:
people sign in, browse the sandbox cluster's resources, read logs, open a shell, scale and restart, or take a
short-lived kubeconfig for their own `kubectl`. The cluster's RBAC decides what each one may do, and every call is
on the record (with recorded shell sessions). It is off by default. To turn it on, set this in
`/etc/containerizer/appliance.env` and reboot:

```sh
CZ_KUBEMG=true
# its own name, on port 443 (it cannot run under a path such as /kubemg/). Empty: kubemg.<CZ_HOSTNAME>
CZ_KUBEMG_HOSTNAME=
```

Then:

1. **DNS**: point the name (`kubemg.containerizer.example.com`) at the appliance.
2. **Certificate**: it must cover that name. With [your own certificate](#https-certificate), add the name (or a
   wildcard) to it. Let's Encrypt (`CZ_ACME_EMAIL`) issues one for it by itself when the name is public. Caddy's
   own CA issues one too, and browsers warn until they trust that CA, as for the web UI.
3. **Sign in** at `https://kubemg.<appliance>/` as `admin` with the password in
   `/etc/containerizer/secrets/kubemg-admin` (root only; `/usr/lib/containerizer/bin/cz-kubemg password` prints
   it). The appliance generates it, so kubemg does not print one to its log as its sign-in page says, and
   `journalctl -u containerizer-kubemg` says where it is. kubemg's setup wizard asks you to change it, and offers
   SSO: OIDC (the identity provider the web UI uses works, with the redirect URI
   `https://kubemg.<appliance>/api/v1/auth/sso/providers/<id>/callback`), SAML or LDAP. **Admin →
   Settings → SSO** in kubemg sets it up, with group mappings to kubemg roles.

**The sandbox cluster** is registered at the first start, as `sandbox` in agent mode. Its agent runs in the
namespace `kubemg-system` and connects out to `https://kubemg.<appliance>/`. Nothing listens for it, and the
firewall allows it as it allows any HTTPS client (the agent resolves the name to the appliance by itself). The
agent trusts the CA of the appliance's certificate: your own (`/etc/containerizer/tls/ca.pem`, else the chain in
`cert.pem`), Caddy's own CA, or the public CAs for Let's Encrypt. The appliance registers the cluster with the
generated `admin` password, so this works only before you change that password. If the agent is removed after
that, register the cluster again in kubemg (**Admin → Clusters → Add**, agent mode) and apply its manifest with
`k3s kubectl apply -f`.

**Its log** (`docker logs cz-kubemg`, also in `journalctl -u containerizer-kubemg`) has no level to set. Its audit
trail is always in it, one JSON line per call, among them kubemg's own look for shell pods every 2 minutes
(`kubemg:shell-runner`). A `record not found` line with its SQL at the start is a setting not made yet, not an
error. **Helm chart repositories**: kubemg adds six public ones on its first start (argo, bitnami, grafana,
ingress-nginx, jetstack, prometheus-community), and the appliance's outbound allow-list blocks them, so each
hourly sync would log `server misbehaving` for them. The appliance deletes them while the generated `admin`
password still works; after that, delete them in kubemg (**Admin → Settings → Helm**, Chart repositories). To use charts, add a
repository the allow-list lets through (your mirror), or put the repositories' hosts on the allow-list.

| | |
| --- | --- |
| Services | `containerizer-kubemg.service` (kubemg, HTTPS on `127.0.0.1:8444` behind Caddy, with a certificate of a local CA that only Caddy trusts, in `/var/lib/containerizer/kubemg/tls`), `containerizer-kubemg-db.service` (PostgreSQL 16, `127.0.0.1:5434`), `containerizer-kubemg-sandbox.service` (the registration) |
| Data | `/var/lib/containerizer/kubemg` (the database and the recorded sessions) |
| Secrets | `/etc/containerizer/secrets/kubemg-*`. `kubemg-secret-key` encrypts the credentials in kubemg's database: keep it with the database, which is unreadable without it |
| Images | pinned by digest in `/usr/lib/containerizer/images.env` (`CZ_IMAGE_KUBEMG*`); the agent and the browser shell are pulled by k3s from `ghcr.io` |
| License | kubemg's server is AGPL-3.0 and its agent Apache-2.0: the appliance runs the published images unmodified |

Turning it off (`CZ_KUBEMG=false`, reboot) stops kubemg and keeps its data and secrets. The agent stays in the
sandbox cluster, trying to reconnect, until you delete it: `k3s kubectl delete namespace kubemg-system`.

## Backup

The OS is rebuilt from the image; what has to be backed up is on the persistent partition. Scans rebuild
the clones, images in the local registry and the sandbox apps, but not the rest:

| What | Where | Why it matters |
| --- | --- | --- |
| Results database | SQL Server, `/var/lib/containerizer/mssql` (back it up with `BACKUP DATABASE`, below) | Results, history, mapping, scan settings, sealed tokens, rule review |
| Configuration and secrets | `/etc/containerizer` | `.env` files, firewall allow-list, SQL Server and Grafana passwords, the root password, and `secrets/credential-key`: the tokens in the database open only with it |
| Dev database uploads | `/var/lib/containerizer/devdb` | The uploaded backups. The database keeps only their name and SHA-256, so without the files the next scan of those apps has no backup to restore |
| Appliance settings and their history | `/var/lib/containerizer/system` | Sandbox HTTPS certificate, key and settings, the lab service switches, and the change history of the firewall and Sandbox HTTPS (these two are files here, not in the database) |
| Learned rules | `/var/lib/containerizer/learned` | Rules the learning loop added on this appliance. Rules approved in the rule review are in your rules repository |
| HTTPS certificate authority | `/var/lib/caddy` | Without `CZ_ACME_EMAIL`, the appliance's own CA: a new one means every browser has to trust a new root |
| Metrics (optional) | `/var/lib/containerizer/prometheus`, `/var/lib/containerizer/grafana` | 90 days of scan and LLM usage metrics, and changes made in Grafana |
| kubemg (optional) | `/var/lib/containerizer/kubemg` (with `secrets/kubemg-secret-key`) | kubemg's users, SSO settings, audit trail and recorded sessions |

**The configuration without its secrets is also in the output repository.** At every boot the appliance copies
`appliance.env`, `web.env`, `worker.env`, `sandbox.env`, `grafana.env`, `egress.json` and `network/*.network` to
`.appliance/<CZ_HOSTNAME>/config/` of every output repository it has a write token for (Admin → Source control), in
one commit and only when something changed. A setting whose value is a secret (its name has TOKEN, PASSWORD,
SECRET, KEY, ...) keeps its name and says only whether it is set; passwords inside values (connection strings,
`user:password@` in URLs) are cut out, and `secrets/` and `tls/` are never copied. So the history of the settings is in
Git, and a rebuilt appliance can be set up from it, with the secrets from your own backup. The files change only by
hand and a reboot applies them, so the boot is when they are copied (`cz-firstboot` stages them in
`/run/containerizer/config-backup`; the LLM queue runner commits them).

The [built-in LLM](#built-in-llm)'s model file (`/var/lib/containerizer/llm`, 16 GB) can be downloaded
again: leave it out of backups (the archive below does). Its on/off setting is in `/var/lib/containerizer/system`.

Lab service data and restored dev databases in the sandbox cluster (`/var/lib/rancher`) are test data:
a new cluster starts them empty, or restores the uploaded backups again, and creates new credentials.

With an [external database](#external-database) the results database is backed up with your SQL Server:
skip its row and the `BACKUP DATABASE` step below. The files are still needed.

Back up the database (from the appliance):

```sh
docker exec cz-mssql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$(cat /etc/containerizer/secrets/mssql-sa)" \
  -Q "BACKUP DATABASE Containerizer TO DISK = N'/var/opt/mssql/backup/containerizer.bak' WITH COMPRESSION, INIT"
# the file is /var/lib/containerizer/mssql/backup/containerizer.bak
```

and the folders (the database backup above included):

```sh
tar -C / -czf /root/containerizer-backup.tgz etc/containerizer var/lib/containerizer/mssql/backup \
  var/lib/containerizer/devdb var/lib/containerizer/system var/lib/containerizer/learned var/lib/caddy
```

With [kubemg](#kubemg) on, dump its database too, and add the dump and its recordings (the secret key is in
`etc/containerizer` already):

```sh
docker exec cz-kubemg-db pg_dump -p 5434 -U kubemg -Fc kubemg > /var/lib/containerizer/kubemg/kubemg.dump
tar -C / -czf /root/containerizer-kubemg.tgz var/lib/containerizer/kubemg/kubemg.dump var/lib/containerizer/kubemg/recordings
```

Copy the archive off the appliance (`scp root@<appliance>:/root/containerizer-backup.tgz .`): it holds
every secret of the appliance, so keep it like one.

To restore on a new appliance, after its first start (with its own `sa` password, which you keep):

```sh
systemctl stop containerizer-web containerizer-worker
tar -C / -xzf /root/containerizer-backup.tgz \
  --exclude=etc/containerizer/secrets/mssql-sa --exclude=etc/containerizer/secrets/mssql.env
docker exec cz-mssql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$(cat /etc/containerizer/secrets/mssql-sa)" \
  -Q "RESTORE DATABASE Containerizer FROM DISK = N'/var/opt/mssql/backup/containerizer.bak' WITH REPLACE"
systemctl reboot
```

At the next start the schema is upgraded if the backup is older, and the logins of the web UI and the
scan worker get the passwords of the backup and are linked to their users in the restored database again.

## Security notes

- OS: read-only, signed upgrades only, no package manager in use, kernel and network hardening sysctls,
  root's default password must be changed at the first sign-in (`passwd -l root` for SSH keys only), no service but SSH and HTTPS reachable, outbound allow-list for everything.
- Web UI: no privileges (systemd sandbox: read-only system, no capabilities, system call filter); its
  database passwords come as systemd credentials. It cannot change the OS: upgrades, roll backs and the
  firewall go through the system agent, which checks every request again.
- SQL Server: non-root, every capability dropped except binding its port, loopback only. An external
  database is reached encrypted, with the server certificate checked, and with the same three logins.
  Edition: Express by default (free, 10 GB per database); Developer is not licensed for production.
- The scan worker is in the `docker` group, which is equivalent to root: it builds and runs the scanned
  repositories' images. That is why the appliance is a dedicated machine, and why the egress allow-list
  applies to every build. Give it no credentials beyond the scans' tokens.
- k3s: secrets encrypted at rest, delivered by External Secrets Operator from a namespace without pods, audit log (`/var/lib/rancher/k3s/server/logs/audit.log`), kernel
  defaults protected, API reachable only from the appliance and its pods. Each app's namespace runs
  under Pod Security "restricted".
- The sandbox is isolated: its applications reach nothing outside the appliance but what an egress rule on the
  Firewall page allows (the firewall's forward chain drops the rest, and the DNS filter refuses every other name),
  whatever their NetworkPolicies say. Approving egress on the results pages or Admin → Egress only documents a
  destination for the real environment (connectivity.yaml); it changes no rule here.
- Egress observer ([egress](egress.md#on-the-appliance)): not root; the `containerizer` user with two capabilities:
  CAP_NET_ADMIN, to read kube-router's drop log (NFLOG group 100: the first 128 bytes of each dropped packet,
  addresses and ports, at most 10 packets a minute per policy), and CAP_SYSLOG, to read the firewall's
  `cz-egress-drop` lines from the kernel log (`/dev/kmsg`, the only device it sees; at most 30 a minute). Its
  Kubernetes account reads pods and the CoreDNS query log (names pods look up, and the ones the DNS filter refused),
  nothing else; the query log is on for that reason (`coredns-custom`). It changes no firewall rule.
- Containers of the appliance's own services are pinned by digest in the OS image
  (`/usr/lib/containerizer/images.env`).

## Troubleshooting

| | |
| --- | --- |
| Something does not start | `systemctl --failed`, `journalctl -b -u <unit>`; units are `containerizer-*`, `k3s`, `caddy`, `docker` |
| A scan cannot reach a host | Admin → Firewall → Refused names; or `journalctl -u containerizer-dns \| grep REFUSED` |
| The firewall did not load | the SSH-only fallback ruleset is active; `systemctl status containerizer-firewall` shows why |
| Status of the system agent | `/run/containerizer/system/status.json`, `journalctl -u containerizer-sysagent` |
| Planned restart (Admin → System) | `/var/lib/containerizer/system/restart-plan.json`, `journalctl -u containerizer-restart` |
| Locked out of SSH | the console of the VM: GRUB menu → recovery, or a previous snapshot |
