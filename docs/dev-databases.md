# Dev database backups for the sandbox

Many applications don't start without their database. Operators can upload a **SQL Server backup** of
an application's development database on the admin pages, together with instructions for the AI on how
to point the application at it. The next scan of the application (`containerizer worker` or
`containerizer org`) restores the backup into a database that runs next to the application in the
sandbox namespace, and sets the application's connection settings. The application's code is not
changed: only the generated Kubernetes manifests are.

Only SQL Server is supported for now (`.bak` made with `BACKUP DATABASE ... TO DISK`, compressed or
not).

## How it works

```
operator ──upload .bak + instructions──> web UI ──> CONTAINERIZER_DEV_DB_DIR/<sha256>.bak
                                           └──> DevDatabase row (name, size, SHA-256, instructions, who)
scan worker ──reads DevDatabase──> builds <registry>/<app>/devdb:<tag> (backup inside) ──push──> registry
            └──> generated manifests: devdb Deployment + Service + NetworkPolicy, app env → devdb
```

1. **Upload** (`/admin/dev-databases`, admins and operators). The file is streamed to disk, so it is
   never held in memory. The page checks the session, the role and the `Origin` header before it reads
   the request body. It checks the form's CSRF token, which is the first field, before it writes any
   of the file. The file must start with a SQL Server backup signature (`TAPE`, or `MSSQLBAK` for a
   compressed backup). It is stored under its SHA-256 with mode 0600, and the web UI never serves it
   back. The size limit is `CONTAINERIZER_DEV_DB_MAX_MB` (default 2048).
2. **Instructions.** The form starts from a template. Name the setting that holds the connection
   string (for example `ConnectionStrings:Shop`), test users, and anything else the AI needs. Never put
   a password here. You can edit the instructions later without uploading the file again.
3. **The scan.** When an application has a backup, the scan:
   - checks the file against its SHA-256;
   - builds an image `FROM mcr.microsoft.com/mssql/server:2022-latest` (override it with `devdb:
     sqlserver:` in `rules/images.yaml`) that contains the backup;
   - pushes the image as `<registry>/<app>/devdb:<tag>`, also tagged `sha-<first 12 of the SHA-256>`.

   Each time the database pod starts, it:
   - restores the backup, moving every data and log file into its data volume;
   - creates the login `app`, a member of `db_owner` in the restored database (not `sysadmin`);
   - only then reports ready.

   Nothing is kept on a persistent volume. The database is a disposable copy, and it is restored again
   whenever its pod starts.
4. **The application's settings.**
   - **With the LLM** (`UseAi` on the scan, or `--ai`): the AI reads the instructions and the
     configuration the scan found. It answers with environment variables written as templates (only
     `{host} {port} {database} {user} {password}`). Every answer is validated, and anything that
     contains a literal password, a `$(...)` reference or an unknown placeholder is dropped.
   - **Without the LLM** (or when its answer has nothing usable): every connection string the scan
     found in `appsettings*.json` points at the database. If it found none, the scan sets
     `ConnectionStrings__DefaultConnection`.

   The password is never written into a manifest. The container gets `CZ_DEVDB_PASSWORD` from the
   Secret `devdb`, and the connection string refers to it with Kubernetes' `$(CZ_DEVDB_PASSWORD)`
   expansion.

   These settings replace any secret reference with the same name that the generator made for the
   connection string. `devdb/README.md` in the generated folder lists what was set, and why.

## What runs in the sandbox

| Object | What it does |
| --- | --- |
| `Deployment devdb` | One replica, `Recreate` strategy. Pod Security "restricted": runs as uid 10001, read-only root filesystem, all capabilities dropped, no privilege escalation, RuntimeDefault seccomp, no service account token. `emptyDir` volumes for `/var/opt/mssql` (4 GiB) and `/tmp`. Memory 2 GiB request, 3 GiB limit (fits the namespace LimitRange; the ResourceQuota counts it). |
| `Service devdb` | Port 1433, so the application connects to `devdb,1433`. |
| `NetworkPolicy devdb` | Ingress on 1433 only from the application's own pods (`app.kubernetes.io/part-of`); egress to DNS only. |
| `Password` + `ExternalSecret` `devdb`, `devdb-admin` | External Secrets Operator's [Password generator](https://external-secrets.io/latest/api/generator/password/) creates the `app` and `sa` passwords in the cluster, once (`refreshInterval: "0"`). They never leave the cluster and need nothing in the secret store ([external-secrets.md](external-secrets.md)). |

The Argo CD AppProject allows exactly these kinds, because they are part of the generated set.

Two details of the image:

- **`setcap -r /opt/mssql/bin/sqlservr`.** The SQL Server binary carries the file capability
  `cap_net_bind_service`. Linux refuses to start a binary like that in a container that drops all
  capabilities ("Operation not permitted"). The server listens on 1433, so it doesn't need the
  capability, and the image removes it instead of adding the capability back to the pod.
- **`MSSQL_PID=Developer`.** SQL Server Developer edition is free for development and test use, and not
  licensed for production. These databases only run in the sandbox.

## Setting it up

- **Web UI:** set `CONTAINERIZER_DEV_DB_DIR` to a writable folder. `results/compose.yaml` uses the named
  volume `dev-databases`, and the results image creates the folder owned by its user. The
  **Dev databases** tab appears for admins and operators only when the folder is set.
- **Scan worker:** set the same `CONTAINERIZER_DEV_DB_DIR`, pointing at the same files. Use a shared
  file system (NFS, an Azure Files share), or run the worker on the same host. The worker reads the
  `DevDatabase` table with its writer login, which needs only `SELECT` (granted by `db init`, schema
  version 8). It needs Docker to build the image, and write access to the registry.
- **Cluster:** External Secrets Operator with the generators API, or create the Secrets yourself, as
  described above.

## Security notes

- **The backup is data.** It is stored on the web UI's volume and in the registry, inside the
  `devdb` image. Use backups with test data only. Treat the registry repository
  `<registry>/<app>/devdb` like the database itself, and restrict who can pull it.
- **What the audit log records.** Uploads, instruction edits and removals go to the change history
  (`AuditLog`, table `DevDatabase`): engine, database name, file name, size, SHA-256 and a SHA-256 of
  the instructions, with who made the change and in which role. The instructions themselves stay only
  in `DevDatabase.Prompt`.
- **No security gate on this image.** The security gate does not scan the database image. Its base is
  Microsoft's SQL Server image, which you can pin and update through `rules/images.yaml`.
- **Removing a backup** deletes the stored file once no application refers to it. The next scan
  deploys the application without the database.
