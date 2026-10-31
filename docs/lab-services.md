# Lab services

Many applications need a database, a cache or object storage before they start. On the
[appliance](appliance.md), administrators can turn on **lab services**: backing services that run in
the sandbox cluster next to the apps that the [organization scans](organization-run.md) deploy. When an
app depends on a service that is on, the generated manifests point the app at it. The app's code does
not change: only its configuration, through environment variables.

| Service | What runs | What each app gets | On by default |
| --- | --- | --- | --- |
| SQL Server | SQL Server 2022, Developer edition (the appliance's own pinned image) | Its own database and login, owner of that database only | yes |
| PostgreSQL | PostgreSQL 18 | Its own database and role, owner of that database only | no |
| Redis | Redis 8.8 | Its own instance and password | no |
| S3 object storage | [Versity S3 Gateway](https://github.com/versity/versitygw) (Apache 2.0) | Its own S3 endpoint and access key | no |
| Azure Blob storage | [Azurite](https://github.com/Azure/Azurite), blob service | Its own Azurite endpoint and account key | no |

SQL Server is on by default because the appliance already ran SQL Server for
[dev database restores](dev-databases.md). An app with an uploaded backup still gets that backup restored
next to it, and the lab SQL Server is not used for it. Turning SQL Server off stops those restores too.

**Why not MinIO?** MinIO stopped publishing community images and binaries, so there is no maintained
image to pin. Versity S3 Gateway serves the S3 API over plain files on a volume. It is a single small
binary, licensed Apache 2.0, and published on Docker Hub.

## Turn a service on or off

**Admin → Lab services** is for administrators, on the appliance only.

- **Turn on** / **Turn off** each service, with an optional note that says why. The change is saved
  first, so the **change history** records who made it, when, and the note. You can see the history on
  the same page and on the Change history page, under *Lab services*.
- The system agent checks the change again and writes it to `/var/lib/containerizer/system/lab-services.json`.
  The lab agent applies it within seconds. After that it checks again every 2 minutes.
- **State** shows what the lab agent saw last:
    - *Running*: the service is running.
    - *Starting*: the image is still downloading or the server is starting. The reason is shown.
    - *On, not in use*: no app has asked for the service yet, so nothing runs.
    - *Off*: the service is turned off.
    - *Problem*: something is wrong. The message says what.

  **Apps using it** lists the app namespaces that asked for the service.
- If you turn off a service that apps use, the page asks you to confirm. Those apps lose the service at
  once. The next scan generates them without it.
- **Needed but off** lists the apps whose latest scan found that they need a service that is off. The
  repository page (Admin → Repositories → a repository) shows the same warning. Turn the service on, then
  scan again. Until then, the app keeps its own settings, which usually point at a server the sandbox
  cannot reach.

A service that is on starts only when the first app asks for it, so a service nobody uses costs nothing.

## What the scan changes in an app

The scan decides, for each component, which services the component needs:

- **Packages**, the component's own or those of the projects it references (`rules/lab-services.yaml`):
    - SQL Server: `Microsoft.Data.SqlClient`, `System.Data.SqlClient`, `Microsoft.EntityFrameworkCore.SqlServer`, `Hangfire.SqlServer`, `dbup-sqlserver`
    - PostgreSQL: `Npgsql*`, `Hangfire.PostgreSql`, `dbup-postgresql`
    - Redis: `StackExchange.Redis`, `Microsoft.Extensions.Caching.StackExchangeRedis`, the SignalR and Data Protection Redis packages
    - S3: `AWSSDK.S3`, `Minio`
    - Azure Blob storage: `Azure.Storage.Blobs`, `Microsoft.Azure.Storage.Blob`, `WindowsAzure.Storage`

  The Aspire client packages for these services count too.
- **Settings in `appsettings.json`** (with `appsettings.Production.json` on top). Each connection string
  and setting is classified by its value:
    - `Initial Catalog=` or `Server=host,1433` means SQL Server;
    - `Host=...;Username=` means PostgreSQL;
    - `host:6379,abortConnect=false` means Redis;
    - `UseDevelopmentStorage=true` or `AccountName=...;AccountKey=` means Azure Storage;
    - `ServiceURL`, `AccessKey` and similar keys under an `AWS`, `S3` or `Minio` section mean S3.

For each service that the component needs and that is on, the scan writes the following.

- **Environment variables** that override the component's configuration:

  | Service | Settings that are overridden |
  | --- | --- |
  | SQL Server, PostgreSQL | Each connection string of that engine, from the Secret `lab-<service>` (key `connection-string`). If no connection string says which engine it is and the component needs only this database, the unclassified ones are used. If there are no connection strings at all, `ConnectionStrings__DefaultConnection` is set. |
  | Redis | Each Redis connection string or setting (`Redis:Configuration`, `ConnectionStrings:Cache`, ...). If none is found, `ConnectionStrings__Redis` is set. |
  | S3 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and `AWS_ENDPOINT_URL_S3`, which AWSSDK.S3 3.7.300 and later read. The `ServiceURL`, access key, secret key and region settings that were found are overridden too. |
  | Azure Blob storage | Each Azure Storage connection string, from the Secret (key `connection-string`). |

  The whole connection string comes from the Secret, so no password appears in a manifest. Entries with the
  same name that the generator made before (references to the component's own secrets) are replaced.
- **`lab/k8s.yaml`**: an `ExternalSecret lab-<service>` for each service. It reads remote key
  `<namespace>--cz-lab-<service>` from the store `app-secrets` ([External Secrets](external-secrets.md)).
  The namespace's reader Role grants exactly these keys, like every other key of the app.
- **NetworkPolicy egress** from the component to the service's port. Only the service's pods are allowed
  (for a per-app service, only the app's own instance), in namespace `containerizer-lab`.
- **`lab/README.md`** lists the host names, the Secrets, which settings were overridden, and the services
  that were needed but off. The scan result has the same, as `lab_services` in `containerizer.json`.

Off the appliance (`containerizer org` or `generate` without `CONTAINERIZER_LAB_SERVICES`), nothing changes.

### Things the scan cannot see

- **Settings made in code.** An S3 client built with `new AmazonS3Client(new AmazonS3Config { ServiceURL = "..." })`
  uses the URL in the code. The AWS SDK reads `AWS_ENDPOINT_URL_S3` only when the code does not set an
  endpoint. The same is true for Azure clients created from a `serviceUri` with managed identity: the lab
  gives each app a connection string, not an identity. `lab/README.md` says when no setting was found.
- **Database schema.** The databases start empty. Run the app's migrations at start-up, as most EF Core
  apps do, or upload a [dev database backup](dev-databases.md) for SQL Server.

## How it works

```
Admin -> Lab services --(cz.LabService, audited)--> system agent --> lab-services.json
                                                                      │            │
           scan worker: needs + overrides + ExternalSecret <──────────┘            │
                                                                                   ▼
app namespace: ExternalSecret lab-<service> ──ESO──> containerizer-secrets/<ns>--cz-lab-<service>
                                                                                   ▲
lab agent (root, every 2 min) ──finds the ExternalSecrets──> creates database/login or instance,
                                                             writes the credentials ─┘
containerizer-lab: sqlserver, postgres (shared) · redis-<ns>, s3-<ns>, azure-blob-<ns> (per app)
```

The lab agent (`python -m containerizer.labagent reconcile`, `containerizer-lab.timer`) runs as root with
the k3s admin kubeconfig. Each time it runs, it does the following.

1. It applies namespace `containerizer-lab` with Pod Security `restricted`, a default-deny NetworkPolicy, a
   LimitRange and a ServiceAccount without a token.
2. It finds the apps that asked for a service: every ExternalSecret labelled `containerizer.io/lab-service`.
   It accepts one only if it reads its own namespace's key, `<namespace>--cz-lab-<service>`. A namespace
   therefore can never ask for another app's credentials, and system namespaces cannot ask at all.
3. For each service that is on and asked for:
    - **Shared server** (SQL Server, PostgreSQL). It runs one Deployment with a data volume. The admin
      password is created once, in the Secret `<service>-admin` in `containerizer-lab`. For each app, it
      creates the app's credentials once and stores them in the secret store. Then it runs the
      provisioning script in the server's container (`kubectl exec`, script on stdin). The script is
      idempotent:
        - **SQL Server**: login `<ns>` (hyphens become underscores) with `CHECK_POLICY = ON`, database
          `<ns>` owned by that login, `DENY VIEW ANY DATABASE` and `DENY VIEW SERVER STATE`.
        - **PostgreSQL**: role `<ns>` with `NOSUPERUSER NOCREATEDB NOCREATEROLE`, database `<ns>` owned by
          it, `CONNECT` revoked from `PUBLIC` on every database (including `postgres` and `template1`),
          and schema `public` owned by the app.

      The script runs again only when the server's pod or the password changes.
    - **Per-app instance** (Redis, S3, Azure Blob). It runs a Deployment, a Service and a data volume
      named `<service>-<ns>`. Their config Secret is built from the app's credentials:
        - **Redis** keeps only the SHA-256 of the password in its ACL. Commands in `@admin` are denied,
          and the append-only file is on.
        - **Azurite**'s `AZURITE_ACCOUNTS` holds only the app's account, so the emulator's well-known
          `devstoreaccount1` key does not work. Telemetry is off.
        - **Versity S3 Gateway** runs with the app's root key. Objects are under `/data/buckets`, and their
          metadata is in a sidecar folder.
    - A **NetworkPolicy per app** lets in only that app's pods (`app.kubernetes.io/part-of: <ns>` in
      namespace `<ns>`), on the service's port.
    - When the store gets new credentials, the agent annotates the app's ExternalSecret, so ESO syncs it
      straight away.
4. For each service that is off, it deletes the Deployments, Services, NetworkPolicies and config Secrets.
   It keeps the volumes, the admin passwords and the apps' credentials in the store. Turning the service on
   again brings back the same data with the same passwords. Instances of apps that no longer ask are
   stopped the same way.
5. It writes `/run/containerizer/system/lab-status.json` for the page. The file holds no secrets.

Secret values never appear on a command line. They reach kubectl on stdin, the provisioning scripts reach
the server's own client on stdin, and the admin passwords stay in the servers' environment (`SQLCMDPASSWORD`
for `sqlcmd`; `psql` connects over the local socket with peer authentication).

## Hardening

The lab follows the same baseline as the generated apps (NSA/CISA Kubernetes Hardening Guide,
`rules/60-security.yaml`):

- **Pods.** They run as non-root users: SQL Server as `10001`, PostgreSQL as `70`, Redis as `999`, Azurite
  as `1000`, the S3 gateway as `10001`. The root file system is read-only, with `emptyDir` folders (size
  limited) where the server needs to write. All capabilities are dropped, privilege escalation is off,
  seccomp and AppArmor use `RuntimeDefault`, no service account token is mounted, and service links are
  off. There are memory requests and limits and ephemeral-storage limits. SQL Server keeps
  `NET_BIND_SERVICE` in its bounding set, the only capability Pod Security `restricted` allows, because
  its binary carries that file capability. With `no_new_privs` the capability is never raised.
- **Network.** Default deny, in and out. Each app gets an ingress rule to its own service, and lab pods
  make no outgoing connections. The apps' own NetworkPolicies allow only the service's pods and port.
- **Secrets.** Credentials are in the secret store only, read by each namespace's own reader. The store
  namespace runs no pods. The admin passwords are in `containerizer-lab` Secrets. k3s encrypts Secrets at
  rest (`secrets-encryption: true`).
- **Images.** They are pinned by digest in `/usr/lib/containerizer/images.env`, and an OS upgrade brings
  new pins. SQL Server uses the same pinned image as the results database.
- **Least privilege in the data.** Each app is the owner of its own database only, and on SQL Server
  cannot even list the others. An app cannot reach another app's Redis, S3 or Azurite instance on the
  network.

**Encryption in transit.** SQL Server connections are encrypted (`Encrypt=True`) with the server's own
certificate (`TrustServerCertificate=True`, as for the dev databases). PostgreSQL, Redis, S3 and Azurite
use plain connections. The sandbox is a single-node cluster, so lab traffic never leaves the appliance:
it stays on the node's pod network, and the NetworkPolicies limit who can open a connection.

## Storage

Each service keeps its data on a PersistentVolumeClaim of the default StorageClass. On the appliance, this
is k3s `local-path`, under `/var/lib/rancher/k3s/storage` on the persistent partition, so the data survives
restarts and OS upgrades. The requested sizes are 20 GiB for SQL Server, 10 GiB for PostgreSQL, 1 GiB for
each Redis and 5 GiB for each S3 or Azurite instance. `local-path` does not enforce these sizes: the
appliance's disk is the limit.

To delete an app's data for good, delete its volume and its credentials:

```sh
k3s kubectl -n containerizer-lab delete pvc -l containerizer.io/lab-app=<namespace>
k3s kubectl -n containerizer-secrets delete secret -l containerizer.io/lab-app=<namespace>
```

On a shared server, drop the app's database and login with the server's tools.

## Resources

When it is in use, SQL Server takes 2 to 3 GiB of memory, on top of the appliance's own SQL Server.
PostgreSQL takes up to 1 GiB. Each Redis, S3 or Azurite instance takes 32 to 512 MiB. Size the VM for the
services you turn on.

## Licences

- **SQL Server Developer edition** is free for development and test, and not licensed for production.
  The lab is a sandbox.
- **PostgreSQL**: PostgreSQL License.
- **Redis 8**: AGPLv3, RSALv2 or SSPLv1, at your choice. It runs unmodified as a service.
- **Versity S3 Gateway**: Apache 2.0.
- **Azurite**: MIT.

The appliance downloads each image from its publisher when the service is first used. Nothing is
redistributed in the OS image.
