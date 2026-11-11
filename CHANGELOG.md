# Changelog

Releases are tagged `vX.Y.Z`: bump `containerizer/__init__.py` and this file, then run the **release** workflow
by hand on `main` with the version, and it tags the commit and releases from the tag (or push the tag `vX.Y.Z` on `main`
yourself: a tag push starts the release too). Each release publishes the appliance OS image to
`ghcr.io/olljanat-ai/containerizer-appliance` and its application alone to `ghcr.io/olljanat-ai/containerizer-app`
(both signed with cosign by the release workflow) and the installer ISO as a release asset. A patch
release (X.Y.Z, Z > 0) must not change the OS image (`appliance/`, `monitoring/`) since X.Y.0: appliances install
it as an app update, without an OS upgrade. OS changes go into a minor or major release.

## Unreleased

## 0.36.0 (2026-11-11)

- **OpenBao for the sandbox apps' secret values** ([Secret values in OpenBao](docs/openbao.md)). The appliance runs
  OpenBao 2.7.2 (`containerizer-openbao.service`; its own user, read-only, loopback only). Caddy serves it on the
  appliance's HTTPS port at `https://<appliance>/ui/` (**Secrets ↗** on the admin pages). It unseals itself with a
  static key made at first boot.
  - **Placeholders.** Every two minutes the appliance gives each component's settings ExternalSecret an entry
    `apps/<namespace>/<component>` with every key empty, or with the value already in the store. Administrators
    only fill in values.
  - **Values reach the apps.** Filled values go into the existing store (`containerizer-secrets`, own field
    manager; an emptied key is removed); the ExternalSecret syncs at once and the workloads that read it restart.
  - **Sign-in and delegation.** The user `admin` (password in `secrets/openbao-admin`). Each app namespace gets
    the policy `app-<namespace>` for operators, given to a user or to a group of an identity provider. The guide
    covers sign-in with OIDC/OAuth 2.0 (Entra ID, Keycloak, Okta) and group-to-policy mapping.
  - **The sandbox's ExternalSecrets.** A component's settings ExternalSecret now reads every key its remote Secret
    has (`dataFrom: extract`, sandbox only): a value nobody filled yet is not set, instead of keeping all of that
    Secret's values away.
  - **Only a namespace's own key.** An ExternalSecret that names another namespace's remote key gets no entry, so
    one namespace's operators cannot write another's values.
## 0.35.7 (2026-11-11)

- **Fix: an appsettings.json with comments or unquoted tokens was read as empty.** The scan understood only
  comments on a line of their own. A comment at the end of a line or a `/* */` block (.NET reads both), or a
  release-pipeline token where a number or boolean goes (`"Port": #{Api.Port}#`), made the whole file unreadable.
  Its connection strings, folders, secret settings and tokens were then missed, and no rescan could produce the
  settings ConfigMap. The file is now read as .NET reads it. The image turns such an unquoted token into `null`
  (blanked, it would leave invalid JSON); a token inside a string is blanked as before.
- **Settings with release-pipeline tokens start with another environment's value.** The ConfigMap
  `<component>-settings` no longer starts empty when the repository has a value for the setting. It looks, in
  this order, for:
  - the same key in `appsettings.json` (a value the Production file tokenizes) or an
    `appsettings.<Environment>.json`, development and test environments first;
  - each token by its name as a key (`#{Auth.Authority}#` from `Auth:Authority`);
  - the one value of the settings with the same name.

  The ConfigMap's comment says where each value came from; check them for the environment. Secret-looking settings
  and values never get one: they would be in Git.
- **An update now reaches applications that run a "Make it A" patch.** A scan leaves their folder as it is (the
  patch is newer), so an update's changes to the generated files (the ConfigMap and secret settings of 0.35.5 and
  0.35.6, say) never reached them until someone pressed Try again. The queue runner now builds the patched copy
  of each application's latest order again by itself, once per version (the same patch on the same commit, no
  LLM).

## 0.35.6 (2026-11-11)

- **Settings with release-pipeline tokens come from a ConfigMap unless they look secret.** 0.35.5 read every
  setting with a `#{X}#` or `__X__` token from the secret store. Now only those whose name, a token's name or value
  looks secret (`#{Smtp.Password}#`, `password=#{X}#`; the check replatformed services use) do; the others are
  optional references to the new ConfigMap `<component>-settings` in `k8s.yaml`, one empty key per setting to set
  for the environment.

## 0.35.5 (2026-11-11)

- **Release-pipeline tokens in appsettings.json.** Settings like `"Url": "https://#{Api.Host}#/v1"` or
  `"Mode": "__Example.Mode__"`, which Azure DevOps Replace Tokens or Octopus replaced at deployment, reached the
  container as literal placeholders. The scan now finds the tokens in the settings the container loads
  (`appsettings.json` and `appsettings.Production.json`), the generated Dockerfile blanks exactly those tokens in
  the published `appsettings*.json` (so an unset value is empty, never a placeholder), and every setting that used
  one is an optional environment variable from the component's `<component>-secrets` ExternalSecret (`Api__Url`),
  listed with the other secret store keys in `HARDENING.md`. Applications get it at their next scan.

## 0.35.4 (2026-11-11)

- **Fix: debug mode still did not come on (0.35.3).** Its patch switched a Deployment to strategy Recreate, but Flux
  applies server-side, the Deployment's defaulted `rollingUpdate` stayed and the API server rejected the change
  (`spec.strategy.rollingUpdate: Forbidden: may not be specified when strategy type is 'Recreate'`), so the
  application's apply failed and the pod stuck on the quota stayed. Debug mode now rolls with `maxSurge: 0` and
  `maxUnavailable: 1`: the old pod goes first and the new one fits in the quota the application already has.

## 0.35.3 (2026-11-11)

- **Fix: the namespace quota left no room for a rolling update of a single pod.** The generated ResourceQuota was
  1.5 times the pods' own resources, so the new pod of a one-replica Deployment did not fit next to the old one
  (`exceeded quota: quota, requested: limits.ephemeral-storage=1Gi ... limited: 1536Mi`) and the rollout never
  started; debug mode showed it, because the crashing pod stayed. The quota now has room for the extra pods of a
  rolling update of every Deployment (applications get it at their next scan), and debug mode replaces the pod
  (strategy Recreate) instead of rolling it, so it works with the quota an application already has.

## 0.35.2 (2026-11-11)

- **Debug mode stayed off while a scan was running.** A scan read the applications' sandbox switches once, at its
  start, and wrote `sandbox/` with them after every repository: debug mode (or a sandbox switch) an administrator
  changed meanwhile was written by the queue runner and taken out again by the scan's next commit, and nothing put
  it back. The scan now reads the switches each time it writes `sandbox/`. After an update the queue runner writes the
  debug patches of the applications in debug mode once more.

## 0.35.1 (2026-11-11)

- **Debug mode: the pods start.** On the appliance the tools image was made with the services' umask (077), so the
  application's user could not enter `/cz-debug` and the pod failed with `stat /cz-debug/bin/sleep: permission
  denied`. The image's folders and files are now readable by every user whatever the umask, the init container
  makes its copy readable too, and the image has a new tag, so pods in debug mode pick it up within a few minutes
  of the update.

## 0.35.0 (2026-11-11)

- **Debug mode for an application in the sandbox** (docs/scheduled-scans.md#debug-mode), for containers that crash
  at start. An administrator turns it on under Admin → Applications → the application → Sandbox. Within a few minutes
  the application's pods stay running without starting it (`sleep` in place of the start command, one replica, no
  probes), in the application's own image with its user, environment, mounts and network, and with a static Bash
  and the BusyBox tools in `/cz-debug` (`/cz-debug/shell`, and `/cz-debug/start` for the application's own start
  command). Nothing is built again and the application's folder does not change: it is a patch in `sandbox/` only,
  for components of the shared chart as a post-renderer of their HelmRelease. The OS image gets `bash-static` and
  `busybox-static` for the tools image (`<registry>/cz-debug-tools`). Schema 49 (`Application.SandboxDebug`).
- **Helm on the appliance.** The OS image has the Helm CLI (`helm` 4.3.1, the release tarball checked against its
  SHA-256), and root's shell has `KUBECONFIG` set to the sandbox cluster, so `helm list -A` works as `kubectl` does.

## 0.34.0 (2026-11-11)

- **The output repository is laid out for several clusters** (docs/clusters.md). Next to `sandbox/`, every run writes
  `clusters/development/`, `clusters/acceptance/` and `clusters/production/` (`CONTAINERIZER_CLUSTERS` names them).
  Each has a Flux bootstrap and one overlay per app over the same app folder, images and shared Helm chart.
  - `clusters/<cluster>/cluster.yaml` is yours: which apps the cluster runs (`deploy: all`, or `listed` with `apps`)
    and the registry it pulls from (`<registry>/<namespace>/<component>`, where the generated CI pipelines push).
    Development runs every app; acceptance and production run nothing until you list an app.
  - `clusters/<cluster>/apps/<namespace>/custom/` is yours too: a kustomize Component for the cluster's settings of
    the app. In acceptance and production it starts pinned to the tag and digest the app had when the cluster first ran
    it, so promoting a build is a commit that changes them; it also takes replicas, hosts and the values of chart mode
    components. No run rewrites either file.
  - The clusters keep `wait: true` and the HTTPRoutes, and have no sandbox identity provider. The sandbox's layout
    and the appliance's sync are unchanged.

## 0.33.0 (2026-11-11)

- **Components are deployed from a shared Helm chart by default** (docs/helm-chart.md).
  - An organization scan writes each component as a Flux `HelmRelease` of `charts/containerizer-app/<version>/` (copied
    into the output repository). Its values hold only what the component has beyond the chart's baseline. A component
    becomes a HelmRelease only when the chart renders exactly the objects the generator made and saves at least
    `deploy.min_saving` (30%) of the lines; otherwise it stays `k8s.yaml`. On the lab environment's 39 components the
    HelmReleases are 42% shorter, and `helm template` gives every object back unchanged.
  - The hardening is in the chart's templates, not in the values: user namespace, no token, non-root, seccomp, no
    privilege escalation, read-only root file system, all capabilities dropped. Values cannot change it. Host
    namespaces, hostPath volumes, hostPorts, unsafe sysctls, extra capabilities and containers without a memory limit
    fail the render, so a component with a hardening exception stays plain manifests.
  - The mode: the administrators' choice per application (Admin -> Applications -> Deploy mode, schema 48), else the
    mode the application is deployed with (switching recreates its objects), else `deploy.mode` in
    `rules/60-security.yaml` / `CONTAINERIZER_DEPLOY_MODE` / `containerizer org --deploy-mode`. `containerizer.json`
    records it.
  - Each HelmRelease names its chart version, so a new release changes nothing that runs until the application is
    generated again. Chart versions that no HelmRelease names are removed. A move to the application's own repository
    takes its chart along. The sandbox leaves out the HTTPRoutes of HelmReleases too (`values.skipKinds`).
- **User namespaces for every generated pod** (`hostUsers: false`): root in a container is an unprivileged user on
  the node. The appliance's k3s supports it. Turn it off for older runtimes with `CONTAINERIZER_USER_NAMESPACES=false`,
  or per component with an exception (`host_users: true`). New HARDENING.md control and lint check `user-namespace`.

## 0.32.0 (2026-11-11)

- **Verification, lab and links that fitted the sample applications are general.**
  - The Development-mode retry of the build-and-run verification runs only when Development reaches the dependencies
    another way (its settings take a setting off its external host or name a local stand-in such as SQLite or a
    simulator, or the code branches on `IsDevelopment()`); Development settings that only name other servers end as
    `ok-external` without a second run.
  - The lab's SQL setup scripts: every deploy script that runs `.sql` files counts (a repository of several
    applications), sibling script folders (`billing/db`, `crm/db`) are all run, `migrations` folders and Flyway's
    `db/migration` are found (versions in order, repeatable last, undo/down scripts never), and `sqlcmd` variables get
    the values the script sets with `:setvar` (a database-name variable becomes the app's lab database).
  - `network.internal_domains` in `rules/60-security.yaml` (or `CONTAINERIZER_INTERNAL_DOMAINS`): your own internal
    DNS domains (`corp.contoso.com`), so hosts under a registered domain count as internal for links between
    applications and the migration plan.
  - The sandbox "Open" link goes to a component that has pages for a browser (views, templates, a single-page app;
    recorded as `ui` in `containerizer.json`), with the name (`*.Api`) only as a fallback.
  - The split suggestion for a repository of several applications counts `.slnx` solutions.

- **Analysis and generation that fitted the sample applications are general.**
  - Console tools get one CronJob per sub-command also when the commands are declared with System.CommandLine,
    CommandLineParser, Spectre.Console.Cli or McMaster.Extensions.CommandLineUtils.
  - A console program that runs until it is stopped (sleeps forever, blocks on its host's `Run()`, polls in a loop
    until cancelled) is a worker and gets a Deployment, not a CronJob (role rule `role-runs-until-stopped`); the plan
    says why a component is a Deployment or a CronJob.
  - The share of blocked server components from which an application is rated E is a setting:
    `rating.not_feasible_share` in `rules/45-rating.yaml` (default 0.75, as before).
  - Two drives or shares with the same folder (`\\fs1\in\orders`, `\\fs2\in\orders`) no longer land in one `/data`
    folder: the second keeps its server and share (`/data/fs2-in/orders`).
  - The README given to the LLM is also found as `README.rst`, `.txt`, `.adoc` or without an extension, in any case,
    in `docs/`, or next to the projects when the root has none.
  - A connection string without a port is a destination with its provider's default port (SQL Server 1433,
    PostgreSQL 5432, MySQL 3306, RabbitMQ 5672), so the database server appears in the connectivity data and the
    egress review; `Host=...;Database=...` without a port is read too.
  - The CLI no longer treats a folder named `scenarios` as a folder of applications: each path is one application
    (pass `scenarios/*`).

- **More rules that fitted the sample applications are general.**
  - The console switch of a Windows service (`--console`, `/console`, `-interactive`, `--no-service`) is found however
    the code compares it (`args[0] == "..."`, `string.Equals(args[0], "...")`, `a.Equals("...")`, `args.Contains`,
    `case`), and a job's run-once argument only when the arguments are compared with it, not from any string that
    looks like an option.
  - A vendor SDK loaded from its installation is found whatever the variable is called (Program Files, a path from
    the registry, `SdkRoot`, `InstallationPath`); a loader of the application's own plug-ins is not.
  - The TPM finding matches the TPM types and functions, not words that start with "tpm" or `Get-Tpm` in a message;
    Task Scheduler and SQL Server Agent findings no longer come from prose in Markdown files.
  - A connection string compiled in as a literal (`UseSqlServer("Server=...")`, `new SqlConnection("Data Source=...")`,
    a `const string` of any class) is reported, except in EF Core's design-time factory.
  - The machine-name identity note and the Data Protection key ring folder setting are recognized by their usual
    names (`LeaseHolder`, `AgentId`; `DataProtectionKeysPath`, `KeyStoragePath`), not a fixed list.
  - `rules/packages.yaml` separates packages that work on Linux (`linux_ok`) from Windows-bound or native-dependent
    ones that are known and left to the finding rules (`judged_by_rules`); confidence is unchanged.

- **Lab services for Java, Node.js, Python and Go.** A component is found by the client packages of its own ecosystem
  (`org.postgresql:postgresql`, `pg`, `psycopg`, `pgx`, `spring-boot-starter-amqp`, `kafkajs`, `pymongo`, ...) and
  pointed at the lab through the variables its framework binds (Spring Boot `SPRING_DATASOURCE_URL`/`_USERNAME`/
  `_PASSWORD`, `SPRING_RABBITMQ_*`, `SPRING_DATA_REDIS_*`, `SPRING_DATA_MONGODB_URI`, `SPRING_KAFKA_BOOTSTRAP_SERVERS`;
  Quarkus and Micronaut datasources), else the ones its code reads (`process.env.X`, `os.environ`, `os.Getenv`,
  `System.getenv`, `.env.example`), else a common name (`DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `AMQP_URL`,
  `KAFKA_BROKERS`) with a note in `lab/README.md`. URLs are written in the form the stack's client takes (JDBC,
  `postgresql://`, Go DSNs), with the user name and password as Secret references. When the scan cannot tell which
  setting to use, `lab/README.md` says the service is not wired for the component and names the Secret and its keys.
  Before, these components were not detected at all.
- **Dev databases for the same stacks.** Without the LLM, a Java, Node.js, Python or Go component with a client of the
  database's engine gets its own variables instead of `ConnectionStrings__DefaultConnection`; the LLM is told each
  component's conventions and the variables it reads; a literal password inside a URL is dropped like one in a
  connection string.

- **Rules that fitted the sample applications are general.** A review of the rules and the code against the
  [containerization challenge](https://github.com/onek8s/containerization-challenge) apps they were first written for:
  - Projects named `*.Lab` or `*.Simulator` are applications again, not tools (`*Stubs`, `*Mocks` and `*Fakes` are
    tools).
  - The hardened run of the gate resolves the hosts the component's own configuration names, not `sql01.corp.local`.
  - Run diagnoses read the framework's messages for a missing setting (`Connection string 'X' not found.`,
    `Section 'X' not found in configuration.`) and need a word about configuration, so an unrelated
    `InvalidOperationException: ... is required` is no longer taken for a missing setting; an unreachable host of any
    domain (not `.corp`/`.local` only) and a certificate missing from `CurrentUser` are recognized.
  - A README's prose alone no longer gives the MSDTC and FILESTREAM findings; the gMSA finding no longer matches
    account names like `svc-x$`, the vendor-installer note no longer matches `Install-*.ps1` or `.mrl`, and the IIS
    FTP finding the words "FTP Server".
  - Remote COM activation (`GetTypeFromProgID`/`GetTypeFromCLSID` with a server) is found whatever the variable
    is called.
  - `Dockerfile.dockerignore` keeps `*.ps1` files when a project file or the code names one.

- **Tests run on every pull request, in parallel and without the developer's settings.** The `ci` workflow runs the
  unit tests and the action's gate on pull requests and pushes to `main` (documentation-only changes skip it, and a
  newer push cancels the run before it); the SQL Server, sandbox cluster and one-shot assessment jobs run by hand or
  with the `full-ci` label. The security gate runs on pull requests that change the generators or the security
  rules. The unit tests run with pytest-xdist (`-n auto`): about 3 minutes instead of 23 on the local dev server,
  where `ci/local.sh` also runs the `sql` job next to the others. LLM settings of the machine running the tests
  (`ANTHROPIC_BASE_URL`, API keys, `CONTAINERIZER_LLM_*`) no longer reach them (#256).

- The `tests/test_round*.py` files are named after what they cover (#301).

## 0.31.1 (2026-11-10)

A patch release: an app update for appliances (no ISO).

- **Settings of other environments stay out of the image.** The generated `Dockerfile.dockerignore` left out
  `appsettings.Development.json` but kept `appsettings.Release.json`, `appsettings.Staging.json` and the like. The
  container runs as Production, so .NET never loads them; they only brought another environment's hosts and secrets
  into the image. They are now left out too, unless the code or a project file names the file or builds its name
  (`$"appsettings.{env}.json"`, `appsettings.$(Configuration).json`).

- **The connectivity diagram shows in Azure Repos.** `CONNECTIVITY.md` in the output repository embedded the diagram
  as `connectivity.svg`, which Azure Repos does not show in the markdown preview. The diagram is now a Mermaid block
  in `CONNECTIVITY.md` (Azure Repos, GitHub and GitLab draw it), with the same columns and line colours; the SVG is
  still written and linked.

## 0.31.0 (2026-11-10)

A minor release with the ISO for new and re-installed appliances.

- **NuGet: the registered sources are the build's machine-level sources.** A repository that does not name its
  internal feed at all (no NuGet.Config, or one without package source mapping, and no `<clear/>`) restores it on the
  developers' machines from their own NuGet.Config; its build failed with `NU1101: No packages exist with this id in
  source(s): nuget.org`. The generated Dockerfile now adds the registered NuGet sources to the build's user-level
  NuGet.Config (each URL once, under its first name), and mapped names a repository does not define go there too
  unless it clears the sources. MIGRATION.md lists them.

- **An app update upgrades the database schema.** The schema was upgraded only at boot (`containerizer-db-init`), so
  an app update whose release added a column left the web UI failing on it until the next restart (0.23.1:
  `Invalid column name 'NuGetSources'` on Admin → Source control). The system agent now runs the schema upgrade with
  the new code before the services restart; when it fails, the code that ran before is put back. This takes effect
  for app updates installed by an appliance already running this fix.

## 0.30.0 (2026-11-10)

Not published: its release was cancelled for the fixes in 0.31.0.

## 0.23.1 (2026-11-10)

A patch release: no OS image changes, appliances install it as an app update.

- **NuGet source names for package source mapping.** A NuGet feed on Admin → Source control → Package feeds gets the
  names projects use for it (`internal, Contoso = <source URL>` per line; several names per feed, each name on one
  feed). When a repository's NuGet.Config maps packages to a source it does not define (on developer machines it
  comes from their own NuGet.Config), the generated Dockerfile adds the source registered under that name before
  restore, and MIGRATION.md lists it, along with mapped names no feed has. `nuget.org` is added when `<clear/>`
  removed it. Database schema version 47 (`SourceCredential.NuGetSources`).

## 0.23.0 (2026-11-10)

The OS image changes (`appliance/`: new role settings in the `web.env` defaults): a minor release.

- **Users and roles on the admin pages** (`CONTAINERIZER_ROLE_SOURCE=ui`). Administrators give the viewer, operator
  and product owner roles (scoped to business units and products, chosen from a list) on **Admin → Users and roles**,
  to someone who has signed in or to the e-mail address of someone who has not yet. Roles follow the person's
  account at the identity provider (`sub`): a role given to an address binds at the first sign-in with that address
  verified, and stays with that account. Roles are read on every request, so a removed role is gone at the next
  click; every change is in the change history with the administrator who made it. Administrators still come only
  from `CONTAINERIZER_ADMINS`, and nothing on the page (nor the database) makes anyone one. In this mode
  `CONTAINERIZER_OPERATORS`, `CONTAINERIZER_PRODUCT_OWNERS` and `CONTAINERIZER_VIEWERS` must be unset (the web UI
  names them and does not start), and `CONTAINERIZER_VIEWERS_REQUIRED=true` puts the results pages behind sign-in.
  The default, `CONTAINERIZER_ROLE_SOURCE=env`, works as before; the page then lists the rules of `web.env`.
  The API gives a person's access token the roles of the account with its `sub`. Database schema version 46
  (`UserAccount`, `RoleAssignment`).

## 0.22.1 (2026-11-10)

A patch release: no OS image changes, appliances install it as an app update.

- **State detection: three false positives fixed** (#273). A file whose only reference to the application folder
  loads configuration (`AddJsonFile`/`SetBasePath(AppContext.BaseDirectory)`) is no longer `state-local-files`
  when it also writes an export to a path the operator gives. `lucene-local-index`, `sqlite-local` and
  `state-hangfire-memory` point first at the code that opens the index, database file or storage, then at the
  package line (new rule flag `evidence_from: code`), and that code decides: a component that gets them from a
  shared library is stateful only when it reaches it (without such code the finding counts as before). "Make it
  A" sends that file with the `sqlite-local` finding instead of a separate `move-state-out` task. Reachability is
  finer: a library file reached only through some of its extension methods no longer brings in the bodies of the others
  (`AddDocuments()` next to `AddSearchIndex()` in one registration class), and a plain static method no longer
  counts as mentioned by a property or method of the same name elsewhere (it is reached through its type).
  Library findings that only such name clashes attached to a component are now shown as not referenced.

## 0.22.0 (2026-11-10)

The OS image changes (`appliance/`: the Mailpit image pin for the new Mail lab service): a minor release.

- The **WCF port plan** fits the service it was found in (#267). The CoreWCF packages come from the bindings found:
  `CoreWCF.NetTcp` for netTcpBinding, `CoreWCF.WebHttp` for webHttpBinding and `[WebGet]`/`[WebInvoke]`,
  `CoreWCF.Http` for HTTP bindings and `.svc` endpoints, and `CoreWCF.ConfigurationManager` with a step to keep the
  `<system.serviceModel>` services section instead of rewriting the endpoints in code. The plan no longer says
  "change the using to CoreWCF": contract assemblies that clients also reference keep their `System.ServiceModel`
  attributes, which CoreWCF hosts. `WorkflowServiceHost` and `.xamlx` count as WCF service hosts (`wcf-server`
  instead of `wcf-client`), and the WF4 plan says that CoreWF has no workflow-service hosting. A .NET Framework
  client of a netTcpBinding service no longer gets `wcf-nettcp-msmq`. Migrations can now have `variants`
  (`rules/migrations.yaml`) and rules `superseded_by` (a component that hosts WCF services no longer also gets the
  `wcf-client` info finding).
- **Lab mail** (#280): a new lab service, **Mail (SMTP)**, on by default, gives each application that sends mail
  its own catch-all mailbox in the sandbox ([Mailpit](https://github.com/axllent/mailpit), MIT, pinned by digest;
  never relays). The scan finds mail senders (MailKit, FluentEmail, `SmtpClient`, `SmtpDeliveryMethod`) and their
  SMTP settings in `appsettings.json` and overrides them: host and port from the lab's Secret, TLS off, a pickup
  folder emptied, `DeliveryMethod`/`Mode: Pickup` set to network delivery, so mail written to a pickup folder is
  sent and caught too, with no code change. Administrators and operators read it under the new **Admin → Lab mail**
  (one inbox over all applications, HTML shown as text, never rendered); the results page links to it. The page
  reads the mailboxes through the system agent (`labmail` request), whose only command is `wget` against the
  mailbox's loopback API. Docs: [Lab services → Mail](https://containerizer.eu/lab-services/#mail).
- **Lab services added in a later version** get their default when `lab-services.json` was written before them,
  instead of the lab agent refusing the file.
- Kafka and SFTP no longer get a `ConnectionStrings__DefaultConnection` override (to a Secret key they do not have)
  when no setting of theirs was found.
- **CronJob schedules from the Windows Task Scheduler** (#288). Console tools got one CronJob per sub-command at
  the placeholder `0 2 * * *`, so a job the old server ran on weekdays at 06:30 ran every night at 02:00 until
  someone read the PowerShell. The repository's deploy scripts and exports are now read
  (`containerizer/schedules.py`; the files are data in `rules/20-platform.yaml`, `task_scheduler:`):
  `New-ScheduledTaskTrigger -Daily|-Weekly [-DaysOfWeek] -At` with its repetition and the
  `New-ScheduledTaskAction -Execute -Argument` that `Register-ScheduledTask` pairs it with (also from a table of jobs
  registered in a loop), `schtasks /create /sc /st /d /mo /ri /du /tr` (also splatted `schtasks.exe @taskArgs`) and
  Task Scheduler XML. Each job is matched to the component whose executable it starts and to the CronJob of the
  sub-command in its arguments, which then gets its cron schedule (`30 6 * * 1-5`; a 30-minute repetition for 14 h
  from 06:00 is `*/30 6-19 * * *`) and arguments; several triggers of one command become several CronJobs. A CronJob
  no job matched keeps the placeholder with the annotation `containerizer.io/schedule: placeholder`; logon and
  startup triggers are reported, not scheduled. `MIGRATION.md` and the results page ("Scheduled tasks", from the new
  view `vScheduledTaskLatest`: schema 45, run `containerizer db init`) list each job, its schedule and the CronJob it
  became ([docs](docs/overview.md#scheduled-tasks)).
- Python and Go components get a container build and deployment (`Dockerfile`, `k8s.yaml`, `plan.json`) with the
  same hardening as .NET, Java and Node.js components, instead of only `MIGRATION.md`, and organization scans deploy
  them (#248, [Python and Go](docs/python-go.md)). Python: the dependencies install with the repository's package
  manager (pip requirements, Poetry, uv or Pipenv lockfiles, else the manifest's list) into a virtual environment on
  the slim image of the declared Python line, run as uid 65532 by the server the app declares (Procfile, gunicorn,
  uvicorn, waitress, ...) on the app object found in the code (Flask, FastAPI, Django, ...); gunicorn or uvicorn is
  added only when the app declares none. Go: a static build of each main package (`cmd/*` each a component) on
  distroless static (cgo: distroless base). No application file is changed.
- Python scanning reads every manifest of a folder (`requirements.txt` with includes, `pyproject.toml` PEP 621 and
  Poetry, `Pipfile`, `setup.py`), keeps development dependencies apart and finds the Python version; folders with a
  manifest but no Python code (`docs/requirements.txt`) are no longer components. A Go module without a main package
  is a library.
- Base images: Python 3.11, 3.12 and 3.13 lines (slim runtime, full build image for native packages), Go builds on
  `golang:1.26` (the lock already chose it for the old 1.22 line), distroless `base` for cgo.
- **Gateway API routes** (#278): `containerizer generate` writes an HTTPRoute (`gateway.networking.k8s.io/v1`)
  for every web component into its `k8s.yaml`. The host is `<component>.<app>.<domain>` (`--ingress-domain`, else
  `example.invalid`), and the route attaches to the HTTPS listener of the platform's Gateway (`--gateway
  <namespace>/<name>`, `--gateway-listener`; default `gateway-system/platform-gateway`, `https`). The platform owns
  the Gateway, its certificate and an HTTP listener that only redirects. What IIS did maps to standard fields:
  raised request timeouts set `timeouts` (the grace period follows as before), and HSTS and web.config custom
  headers set `ResponseHeaderModifier`. In-memory session, ARR affinity, SignalR and Blazor Server need cookie
  session affinity: by default `MIGRATION.md` and `HARDENING.md` ask for it at the Gateway implementation (cookie
  name, findings), so every route deploys on the standard-channel CRDs. `gateway.session_persistence.emit: true`
  puts a cookie `sessionPersistence` (experimental channel) on the route instead. Simple `<rewrite>` rules and `<httpRedirect>` become `URLRewrite`
  and `RequestRedirect` filters; HTTP to HTTPS rules are left to the Gateway. Request body and URL limits and
  `<ipSecurity>` lists have no standard field: `MIGRATION.md` and `HARDENING.md` list them with their values, as
  settings of the Gateway implementation. Rules that do not translate are listed in `MIGRATION.md` with their XML.
  `web-config-rewrite` is resolved (`gateway-httproute`) only when everything translated. The mapping is data in
  `rules/60-security.yaml` (`gateway:`). The gate's lint checks every route (`route-parent`, `route-listener`,
  `route-hostname`). The NetworkPolicy admits the Gateway's namespace, and the Flux tenant gets a Role for
  `httproutes`, which `admin` does not cover. The sandbox keeps its Traefik Ingress: the appliance's Traefik has no
  Gateway API provider, so the sandbox drops the routes ([Gateway API routes](docs/gateway-api.md)).
- CI: the check that the results UI serves the assessment no longer fails now and then (`curl | grep -q` under
  `pipefail`); `ci/local.sh` and `ci.yml` read the whole page first.

## 0.21.0 (2026-11-10)

The OS image changes (`appliance/`: the worker, LLM queue and web units set the ingress namespace): a minor release.

- **No more `Dockerfile.windows`** (#271): the project is Linux-only and Windows applications stay in VMs.
  `containerizer generate` no longer writes the Windows Server Core stop-gap (`Dockerfile.windows` and its
  `.dockerignore`) for .NET Framework components, `rules/images.yaml` drops the `windows:` images, `MIGRATION.md`
  drops the "Windows container stop-gap" column, and finding fixes, the migration plan and the application page no
  longer suggest a Windows container (components that cannot run on Linux stay on Windows VMs). The
  `windows_container` rule attribute and `Component.WindowsContainerOk` stay (`containerizer migrate` and the SARIF
  output read the attribute; no schema change).
- **A Data Protection key folder from configuration gets the shared key.** An app that keeps its key ring in a
  configured folder (`PersistKeysToFileSystem(new DirectoryInfo(configuration["DataProtection:KeyFolder"]))`, also
  in a library it references) had that folder on an `emptyDir`, so every restart or rollout signed every user out,
  and the generated key was mounted under `/home/app`, where the app never looked. Now the key Secret that External
  Secrets Operator generates is mounted read-only at the configured folder (re-pointed under `/data`, or set when the
  configuration leaves it empty), with no code change; a folder written in the code is a persistent volume
  (ReadWriteOnce, one replica). `plan.json` and the Dockerfile header say why, and the new lint check
  `dataprotection-volatile` fails a key ring folder setting that points into an `emptyDir`
  ([docs](docs/overview.md#generated-output)).
- **Workers are replaced, not rolled, and CronJobs cannot run forever** ([docs](docs/overview.md#generated-output)).
  A worker (queue consumer, folder poller, scheduler, Windows service) was one process on one server, but its
  Deployment rolled out with the new pod started while the old one still ran: two copies polled the same folder or
  ran the same recurring job. Workers now get `strategy: Recreate` (web components keep `RollingUpdate`; a plan
  rule with `scale_out: true` marks a worker safe to run twice). Pods get a stop grace period per role (web 30 s,
  worker and console 120 s), longer when IIS let requests run for minutes. CronJobs get a retry limit (2), a run
  deadline (1 hour), a start deadline (5 minutes), history limits (3/3) and a TTL for finished Jobs: before, a hung
  run went on forever and, with `Forbid`, every later run was skipped. The values are in `rules/60-security.yaml`
  (`hardening.workloads`), the reasons in `plan.json`, a line per workload in `HARDENING.md`, and the gate warns
  about CronJobs without these limits and workers that roll.
- **Images are deployed by digest** ([docs](docs/build-pipelines.md#the-sandbox-and-gitops)). Tags can be moved in
  the registry; a digest cannot. The generated Flux `ImagePolicy` now reflects the digest of the tag it picks
  (`digestReflectionPolicy: Always`, Flux 2.5+), and `kustomization.yaml` has a name, tag **and** digest setter per
  image, so the image automation writes `<image>:<tag>@sha256:...`. An organization scan writes the digest of
  each image it pushed straight into the kustomization, so the sandbox runs by digest from the first deploy,
  without the image automation. The build pipelines keep the pushed digest as `digests.txt` (an artifact) and a
  job output, for `kustomize edit set image $(cat digests.txt)` in a deploy pipeline. HARDENING.md's *Images are
  deployed by digest* is now *applied* (pinned by Flux after the first automation run); a lint check
  `image-digest-setter` (info) replaces `image-digest` for these images.
- **Memory requests and limits come from what the verification run measured.** Every component got the same
  256Mi request and 512Mi limit, so a large API could be killed for its memory in the sandbox while a small worker
  reserved too much. The build-and-run now samples the container's memory and CPU while its probes are answered and
  records the peak; the generated manifests then ask for the peak × 1.25 and limit it to the peak × 2 (rounded up
  to 64Mi, at most the namespace's LimitRange max; the request at least 128Mi, the limit never below the 512Mi
  baseline, as a few seconds of probes understate real load), with the reason in `plan.json`. A component that was
  not measured keeps the old sizes; exceptions such as `native-rendering-memory` only raise them
  ([docs](docs/overview.md#self-learning-loop)).
- **Verification resolves every host the application is configured to reach to 127.0.0.1.** The build-and-run
  check used to map one fixed name from an example application; now it takes every host name from the
  component's connection strings and configured URLs (the same scan the connectivity model uses, plus
  `appsettings.Development.json` in the smoke run) and maps it to loopback, so a missing database, broker or
  service fails fast with "connection refused" instead of a DNS lookup that hangs. IP addresses and
  well-known public services (`public_hosts` in `rules/60-security.yaml`) are left alone. The run's details list
  the mapped names, and a component that runs but stops at missing services lists what it needs
  (`needs: sql.corp.example:1433`) in the report.
- **Service ports are open to the ingress controller's namespace, not to every namespace.** The generated
  NetworkPolicies let any pod of the cluster call a component's service port; on a shared cluster another tenant's
  pod could call the application directly, around the ingress. Now only the ingress controller's namespace
  can (`network.ingress_namespace` in `rules/60-security.yaml`, default `ingress-nginx`; the environment variable
  `CONTAINERIZER_INGRESS_NAMESPACE` or `--ingress-from` overrides it), besides the sibling components and confirmed
  links as before. The appliance sets `kube-system`, where the sandbox's Traefik runs. `--ingress-from any` keeps
  the old rule; for a controller in the host network, use it with an `ipBlock` of the node CIDR
  ([docs/egress.md](docs/egress.md#inbound)). `CONNECTIVITY.md` and `HARDENING.md` name the namespace, the
  gate's lint warns about a rule open to every namespace, and the egress observer proposes a link for a call from
  another application that a service port now drops.

## 0.20.0 (2026-11-09)

- (The version jumps from 0.16 to 0.20: Containerizer is getting ready for use in real environments. 0.17 to 0.19
  were not released.)

- **Releases have only the installer ISO.** The qcow2 disk image is no longer published (nor built); install on
  KVM, Proxmox and OpenStack from the ISO like everywhere else. SHA256SUMS covers the ISO.
- **Cancel stops a scan run at once.** Before, it waited for the repositories in progress (*cancelling after
  the current repository*). Now the worker sees the cancel within 3 seconds (was the 30-second heartbeat) and
  ends the repositories in progress with every tool they started (git, builds): each repository of a run an
  administrator can cancel is scanned in a process of its own, also with one repository at a time. The ended
  ones are not recorded: they keep their previous result and the next run scans them again.
- **A failed build or run is shown with its log.** An application rated from its source code (for example **A**)
  whose component failed to build or run said only *Build failed*, and its confidence still read *confirmed by
  building and running*. Now the page says the rating is not confirmed, the confidence says the build or run
  failed, and the component's details show why and the end of the build or run log (kept in
  `ComponentAssessment.VerifyDetail` by the next scan) ([docs](docs/overview.md#self-learning-loop)).
- **Package feeds that need a sign-in** ([docs](docs/source-control.md#package-feeds)). Admin → Source control has
  a new section, **Package feeds**: a NuGet, npm or Maven/Gradle feed's URL, an optional user name and a token,
  sealed for the worker like the source control tokens. The token never enters a build: the scan worker and the
  LLM queue runner run a feed proxy that the builds use as `HTTPS_PROXY`; it opens only the connections to the
  registered feeds' hosts (its CA reaches the builds through the existing `ca` build secret) and adds the token to
  the requests under the feed's URL, passes everything else through untouched, and refuses the appliance's own
  addresses and container networks. The appliance firewall lets Docker's bridges reach the proxies (ports 3128 and
  3129 on 169.254.53.53). Schema 44: `SourceCredential.FeedUser`, Purpose `feed`.
- **A static address is kept after a restart.** systemd-networkd could start before `cz-firstboot` had copied
  `/etc/containerizer/network/10-static.network` to `/run/systemd/network`; br0 then got the DHCP default, and
  without a DHCP server the appliance had no address (seen on a Dell server). `cz-firstboot` now runs before
  systemd-networkd itself, and the status check (every 5 minutes) reloads the network when br0 has a file of the
  image although a static file is there. Until then: `networkctl reload && networkctl reconfigure br0`.
- **Platform fixes for refactor findings** ([docs](docs/platform-fixes.md)): findings that the generated
  configuration can satisfy no longer need code changes, and count as `config` in the rating. A plan rule names the
  findings it `resolves`; three techniques are new: code that switches on `Environment.MachineName` gets the pod
  `hostname:` it compares with (`plan-machine-hostname`), certificates looked up in `CurrentUser\My` come from an
  optional Secret mounted where .NET on Linux reads that store (`plan-x509-user-store`), and
  `Path.Combine(GetFolderPath(ProgramFiles), "Acme", ...)`, which is `/app/Acme/...` on Linux, gets a volume there
  (`plan-special-folder-workdir`). Each one is listed with its reason and references in the Dockerfile header and
  `plan.json` (`applied`, `resolved`, `reasons`); the finding keeps its rule severity as `rule_severity` and is
  never sent to a refactoring. An application whose only refactor findings are these goes from B to A at its next
  scan. The page also classifies all 111 refactor rules (platform, partial, code-only) as candidates for more.
- **Apps that keep their own data run as they are, with a persistent volume, and rate A (stateful).** A component
  that is ready in every other way but keeps local data (a SQLite/LiteDB file, uploads under the web root or
  App_Data, a local index, in-memory session or Hangfire storage) was capped at B, left out of the sandbox ("keeps
  local state") and pointed at Make it A, an LLM rewrite that moves the data to SQL Server. Now it rates **A**,
  marked **stateful** next to the rating, and the organization scan deploys it unchanged: one replica with
  `strategy: Recreate`, a PersistentVolumeClaim on each folder it keeps data in, `fsGroup` so the non-root user can
  write it, the root file system still read-only. An embedded database file in the app folder (`Data Source=app.db`)
  moves to `/data`, a volume, with an environment variable over its connection string; no file of the application
  changes and no LLM is called. Local data in a folder Containerizer cannot find still keeps the component at B and
  out of the sandbox. The workload, its pods and volumes get the label `stateful: "true"`; `stateful:` in
  `rules/36-state.yaml` sets the label, StorageClass, size and a node pool (node selector, tolerations). The front
  page and results page show an automatic `stateful` tag that the tag filter finds and nobody can add or remove;
  the migration plan marks such components *runs with a persistent volume, one replica*. `HARDENING.md` and
  `MIGRATION.md` list the volumes: the operator owns their backup, StorageClass and size. Ratings of such
  applications go from B to A at their next scan.

- **Builds of scanned code are isolated from the appliance** ([builds of scanned code](docs/appliance-admin.md#builds-of-scanned-code), #255).
  The scan worker and the LLM queue runner are no longer in the root-equivalent `docker` group: they reach Docker
  through a guard (`containerizer-docker-guard`, `containerizer/dockerguard.py`) that refuses privileged containers,
  host namespaces, devices, extra capabilities, bind mounts outside the worker's folders, non-loopback ports and any
  call on the appliance's own containers. The firewall answers only DNS on Docker's bridges (no SQL Server, registry,
  Grafana, k3s API or kubelet) and keeps them off the k3s networks; builds never use the host network (Docker refuses
  the `network.host` build entitlement too), Docker itself fetches no URL of the appliance's own services for a
  build (`ADD <url>`: `cz-docker-egress`), and Docker runs every container with `no-new-privileges`. No scanned
  application changes; a build that reached an appliance service on purpose (none is known) now fails to connect.
  Outside the appliance, `CONTAINERIZER_BUILD_HOST_NETWORK=1` brings back the host network for builds behind a proxy
  on `127.0.0.1` (it was automatic before).

## 0.16.4 (2026-11-05)

- **Try again** on an application whose sandbox runs a Make it A order's patched copy builds that patch again (the
  same patch on the same commit, no LLM) with this version's generator and gate, and deploys it; before, it queued a
  scan, which leaves a patched copy as it is. The lab's expense-claims frontend stayed out of its patched copy (made
  under 0.16.0's gate) even after 0.16.1 fixed the gate. The queue runner does it (`cz.LlmJob.RedeployRequestedAt`);
  if the new build cannot be deployed, what ran stays and the page says why.

## 0.16.3 (2026-11-05)

- No checks of application code security: the rules **Secrets in configuration files** and **Credentials
  hard-coded in source** (and its migration entry) are removed. Containerizer secures what it generates (non-root,
  no capabilities, read-only root file system, secrets only from the secret store), not the application's code;
  ratings of applications that had those findings go up at their next scan.

## 0.16.2 (2026-11-05)

- Refactoring (LLM orders, Make it A) keeps each project's target framework. The `core-eol` finding of an
  out-of-support .NET Core / .NET 5-7 app told the LLM to retarget to net10.0, and the lab's local model moved
  net6.0, net5.0 and netcoreapp3.1 projects to net10.0: a shared library then gave them other package versions,
  and what built and ran before did not. Now that finding is never sent to the LLM (the container runs the app on
  the framework it targets, rolled forward), the LLM's instructions forbid changing a project's target
  framework, SDK or package versions unless the finding is about the framework itself (a .NET Framework port, a
  -windows framework), and a .NET Core / .NET 5+ project the edits retargeted gets its framework back.
- An app that targets an out-of-support .NET Core / .NET (2.1, 3.1, 5.0, 6.0, 7.0) runs on its own Microsoft
  runtime image (`mcr.microsoft.com/dotnet/aspnet:6.0` and so on), as it was built and tested, no longer rolled
  forward onto .NET 10: no runtime behaviour changes between .NET versions (the lab's retail-backoffice
  Customers.Api failed on .NET 10 with a `Global\` mutex error and runs on .NET 5). Those images are not patched
  any more. Same non-root user and home as before; `ASPNETCORE_URLS` sets the port (ASPNETCORE_HTTP_PORTS is
  .NET 8+). Roll-forward remains for Core 2.2 / 3.0 (no image) and for apps that need OS packages.
- No security-only changes: **Secrets in configuration files** is information only (the app runs with them, and
  the container overrides each setting through an environment variable), and is not sent to the LLM.
  **Credentials hard-coded in source** is about what blocks the container (it cannot point the app at its own
  server), no longer about rotating secrets.
- Generated containers pass a Windows service's console switch (`args.Contains("--console")`, the pattern of the
  .NET docs for running a host as a Windows service): without it such an app starts as a service and stops at once
  in a container (`ServiceBase`: PlatformNotSupportedException).
- Web UI: a light/dark button in the top right corner, next to the sign-in details. The pages follow the system's
  setting until it is used; the choice is kept in the browser (local storage), and pages without the script follow
  the system as before.

## 0.16.1 (2026-11-05)

- Results page: a component the organization scan's security gate left out of the sandbox shows **What failed**
  (the end of the image build's log, the lint errors, or the errors and log of the hardened run) under its
  reason, and administrators and operators get **Try again**: a full scan of only this application's repository,
  with its state on the page until it is done (`cz.vSandboxDeploy` has the new column `Detail`).
- Results page: **Lab services** at the top says what the application needs in the sandbox lab, what the lab
  provides and what is turned off, with the components that run without it; the Sandbox column marks those
  components (`cz.vSandboxDeploy` has the new column `LabServices`).
- Admin -> Lab services: **Applications that need each service**, per service the applications whose latest scan
  needs it, with their components and whether they got it (Provided) or went without it (the service was off).
- Lab services of a repository split into applications (such as containerization-challenge) were dropped from
  the scan's record: Admin -> Lab services did not list those applications under "Needed but off". Each
  application's are now kept, and the list names them.
- Sandbox check: a component that fails and needs a lab service the lab has turned off is diagnosed as such
  ("It needs RabbitMQ, which the lab has turned off"), before the cluster-setting guesses. The lab's control-tower
  CarrierGateway stopped without RabbitMQ and was put down to a missing secret.
- Security gate: a line a container's start-up script marks as information is no longer a hardening failure. The
  nginx image's entrypoint says it cannot modify `default.conf` on the read-only root file system and nginx then
  serves; the lab's expense-claims frontend was left out of the sandbox for it ("does not run with the hardened pod
  security context").
- The scan worker rescans the repositories whose components the security gate left out, once per release, so what a
  newer release lets through is deployed without waiting for the schedule (before: only components left out for
  vulnerabilities).

## 0.16.0 (2026-11-05)

- (0.15.0 was not released: its tag was made on the wrong commit and its build stopped before publishing anything.)

- LLM token usage for the long run: every call an LLM answers is recorded in the results database (`LlmUsage`) with
  the tokens it reported (not estimates), the application, the component, the feature, the model and the cost; the
  views `vLlmUsage` and `vLlmUsageDaily` add the product and business unit. A new Grafana dashboard, **Containerizer:
  LLM token usage**, shows it by business unit, product, application and component, through a read-only login
  (`cz_grafana`) that can read only those views.

## 0.14.0 (2026-11-05)

- Appliance network as olljanat/nomad-qemu-node's `05_network.yaml`: every wired interface in `bond0`
  (active-backup), the bond the port of a bridge `br0` that has the address (DHCP, or static). The USB network
  interface of a server's management controller (Dell iDRAC, HPE iLO, Lenovo XCC) no longer joins the bond: on a
  Dell server it was the active port and nothing reached the network. A static address of 0.13.x moves to `br0`.
- The appliance's `cz` command: `cz network show`, `cz network static <address/prefix> <gateway> <dns>`,
  `cz network dhcp`, `cz upgrade ...` instead of `/usr/lib/containerizer/venv/bin/python -m containerizer.sysagent`;
  the console's sign-in banner shows the network commands.
- A static address is read at boot (the boot copy was root's only and systemd-networkd ignored it) and the DNS
  filter is rebuilt with its DNS servers when it changes.

## 0.13.2 (2026-11-05)

- Turning an application's sandbox off or on (Admin → Applications) reaches the output repository reliably: the
  LLM queue runner applies the switches in a step of its own (a failure of the step before it held them up every
  time), and an output repository it could not open or push to is tried again a minute later; before, the switch
  was recorded as applied and waited for the next change of any switch.

## 0.13.1 (2026-11-05)

- Lab services: an app's SQL Server database is set up from the repository's own SQL scripts (the DBA's
  `db/*.sql`, in the order its deploy script runs them), once, as the app's own login; what needs server-wide
  rights is left out and a failing batch does not stop the rest. Before, an app that does not create its tables
  itself failed in the sandbox (the lab's expense-claims: Quartz's "Invalid object name 'quartz.QRTZ_JOB_DETAILS'").

## 0.13.0 (2026-11-05)

- A minor release with the installer ISO and the disk images, for new appliances (physical servers too) with
  everything since 0.12.0. Appliances on 0.12.x install it as an OS upgrade (a restart), not as an app update.
- Appliance: a static address from the console, `python -m containerizer.sysagent network static <address/prefix>
  <gateway> <dns> [...]` (also `network show` and `network dhcp`): checked, applied at once without a restart, and
  kept over restarts and upgrades; the DNS filter and the HTTPS certificate follow. Before, a static address
  meant writing a systemd-networkd file by hand and restarting.

## 0.12.10 (2026-11-05)

- The components earlier scans left out for vulnerabilities ("not deployed: security gate: 2 fixable
  vulnerabilities ...") are deployed without waiting for the schedule: the scan worker queues a full scan of only
  those repositories (one run per organization scan, again while a run of it is busy, once per repository).
- Vulnerability scans are off by default when Containerizer deploys (organization scans, Make it A, platform
  migrations): they took long and vulnerabilities are outside its aim. The security gate still lints, builds and
  runs every image with the hardened security context; SECURITY.md says the scans are off. `scan.enabled: true`
  (`rules/60-security.yaml`) turns them on; `containerizer gate` and `images --update` scan when run.
- Verification and the security gate's hardened run name their containers uniquely: jobs of one LLM queue runner
  that verified in the same second got "Conflict. The container name ... is already in use" (Make it A of the lab's
  control-tower, "Run failed ... unexplained").
- LLM queue: **Requeue** of a job rejected for waiting too long works: "Reject automatically after" counted from the
  job's approval when it had one, so an approved job requeued was rejected again at once. It counts from the later
  of the approval and the (last) queueing now, and a job the runner puts back in the queue (a restart, an app update)
  starts its wait again too: the lab's product-returns order was rejected that way after a restart.

## 0.12.9 (2026-11-05)

- App updates: the drained LLM queue runner waits only for the LLM call in progress, not for whole jobs, then puts
  its jobs back in the queue and restarts with the new code; they continue there with the answers they already had.
  Since 0.12.5 it waited for its jobs to finish, and an LLM-heavy Make it A order kept every other job in the
  queue for up to the plan's wait (2 hours by default).
- Vulnerabilities no longer keep a component out of the sandbox. Containerizer's aim is the application running
  in containers with as few changes as possible; its developers fix vulnerable packages on the new platform. Scans,
  Make it A orders and platform migrations deploy the component and report the vulnerabilities in `SECURITY.md`
  (with the packages to upgrade). `scan.block_deploy: true` in `rules/60-security.yaml` brings the old behaviour
  back; `containerizer gate` as a CI check still fails on them. Build failures, lint errors and the hardened run
  still keep a component out.

## 0.12.8 (2026-11-05)

- Security gate: a component stopped by vulnerabilities says what to upgrade and where: "2 fixable vulnerabilities
  at or above the gate threshold in the application's packages: Refit 6.3.2 (fixed in 7.2.22),
  System.Drawing.Common 5.0.0 (fixed in 4.7.2, 5.0.3)" instead of only the count (the lab's retail-backoffice).
- Front page: **Running in the sandbox** lists every application that runs there by its latest check, whole or in
  part ("12 of 16 components"), with a link to open it (a component with a user interface before an API); the
  application's page says the same at the top. Before, what ran of an application that still needs changes was
  only in its migration plan.
- Rules: Windows sign-in set up in code (the ASP.NET Core Negotiate handler, `AddNegotiate`) is now "Windows
  (Kerberos/NTLM) authentication" that needs a change (refactor), like IIS Windows authentication in web.config.
  A "Make it A" patch could turn windowsAuthentication off in web.config (only IIS reads it), keep Negotiate and
  rate A, and nobody could sign in in the sandbox (the lab's trade-rebates portal). The fix it asks for is
  OpenID Connect bound to an "OpenIdConnect" configuration section, which the sandbox identity provider fills.

## 0.12.7 (2026-11-05)

- "Make it A": the **Open** link of a patched copy in the sandbox goes to its first component that is not an API by
  its name (the portal of trade-rebates, not its API, whose "/" answers 404). Copies already running get the new
  link at their next state refresh.

## 0.12.6 (2026-11-05)

- Security gate: the hardened run no longer fails ASP.NET Core components on their Data Protection key ring.
  Since the key ring became a Secret the cluster makes, the run mounted that folder empty and read-only, the app
  wrote a key there and was denied, and the gate dropped the component ("does not run with the hardened pod
  security context"): scans and Make it A patched copies lost working components (the lab's trade-rebates lost
  its API). The run now gives that folder to the app writable; other Secrets stay empty and read-only.
- "Make it A": the patched copy deploys the components the patch does not change as the application's folder
  deployed them (no new build-and-run; the gate's hardened run is waived for them, not the build, lint or
  vulnerability checks), so a patch for one component cannot take another one out of the sandbox.
- "Make it A": a NuGet error that needs no LLM (an ASP.NET Core framework package such as
  `Microsoft.AspNetCore.HttpOverrides` that an LLM added, a package downgrade) is fixed also when the order's repair
  rounds or LLM calls are used up, with up to two more builds. Before, an order whose last build failed only on
  that stopped as "Does not build".

## 0.12.5 (2026-11-05)

- Appliance app updates no longer interrupt LLM jobs. The LLM queue runner is drained instead of restarted: it
  starts no new job, finishes the ones in progress (the LLM's answer in progress included) on the code they started
  on, and then restarts with the new code by itself; a planned app update waits only for the scans. The plan's
  wait still cuts off jobs that take longer (they go back to the queue). This works for updates made from 0.12.5
  on: the update to 0.12.5 itself still restarts the runner.
- Release workflow: a patch release no longer builds the OS image. Its OS image tag (`containerizer-appliance:vX.Y.Z`,
  which appliances look for) is the series' `vX.Y.0` image, copied in the registry, so a patch release takes about
  half as long. An appliance of another series that upgrades to it gets the `vX.Y.0` OS and then installs the patch
  release as an app update. The signature check after signing tries again for up to two minutes (GHCR sometimes
  shows a new signature late: 0.12.4's release stopped there).

## 0.12.4 (2026-11-05)

- The front page loads faster (about 0.3 s less per view, also when filtered by business unit or tag): the "Made
  A by a patch" list no longer joins the orders to the applications in SQL, which made SQL Server parse every
  order's stored prompts for each pair.

## 0.12.3 (2026-11-05)

- "Make it A" orders: the sandbox state of a patched copy no longer stays as it was when it was deployed. The queue
  runner reads the health again (*In the sandbox (health not checked)*, as after a restart, every 10 minutes;
  running or failing every hour), shows **Sandbox turned off** while the application's sandbox is turned off, and
  takes the state from the output repository: a copy whose application folder runs it is in the sandbox (also one
  recorded as removed), one whose folder runs something else is not.

## 0.12.2 (2026-11-05)

- Patch releases (`vX.Y.Z`, Z > 0) publish only the app update and the appliance image, no ISO, qcow2 or
  checksums (built for nothing: the series' `vX.Y.0` has the same OS); the release workflow is faster for them.
- SQL Server connections name their part of Containerizer (`program_name`): `containerizer-web`, `containerizer-worker`,
  `containerizer-llm-queue`, `containerizer-db`, `containerizer-sysagent`, `containerizer-labagent` or
  `containerizer-<command>`, instead of `containerizer` for all of them; `Application Name=` in the connection
  string or `CONTAINERIZER_SQL_APP_NAME` sets one name. The lab and dev database connection strings Containerizer
  gives apps name the app (`Application Name=<app>`, SQL Server and PostgreSQL), and the database browser's
  PostgreSQL sessions are `containerizer-db-browser`.

## 0.12.1 (2026-11-05)

- The first patch release installed as an app update: appliances on 0.12.0 install it from **Admin → System**
  without an OS upgrade (only the containerizer services restart). No OS change since 0.12.0.

## 0.12.0 (2026-11-05)

- Appliance: patch releases are installed as **app updates**, without an OS upgrade. A full upgrade downloads the
  whole OS image, writes a new snapshot and restarts the server, which takes long on a physical server. Within a
  release series (vX.Y) the OS no longer changes: every release now also publishes its application alone (the code
  and the rules, a few MB) as `ghcr.io/olljanat-ai/containerizer-app:vX.Y.Z`, signed by the same release
  workflow, and **Admin → System** installs a newer patch release of the running series from it
  (`containerizer/apppatch.py`): verified with cosign, fetched by digest, unpacked on the persistent partition,
  checked to import with the OS's Python packages, mounted read-only over the code
  (`/run/containerizer/app-patch`, first in the venv's `containerizer.pth`), and only the containerizer services
  restart; if they do not come up, the previous code is put back. **Remove the app update** goes back to the OS
  image's code. Minor and major releases stay OS upgrades, and an app update is not used on another series's OS
  (`containerizer-app-patch.service` checks at every start, with the OS image's own code). The release workflow
  refuses a patch release that changes the OS image since its vX.Y.0 (`appliance/`, `monitoring/`:
  `appliance/ci/patch-release-check.sh`); those changes go into a minor release. The first app update can be
  installed on the OS of the next minor release (older OS images take one OS upgrade first). The new GHCR
  package `containerizer-app` must be made public, as `containerizer-appliance` is.

## 0.11.1 (2026-11-05)

- Appliance: one DHCP address from the first boot on. Since 0.9.3 the DHCP client ID came from the machine-id,
  and the recovery system that installs the appliance has another machine-id than the installed system, so a new
  appliance moved to a second address after installing itself (and a reservation by MAC address did not apply).
  The client ID is the bond's MAC address again, and that is its first NIC's MAC: udev's default policy
  (`MACAddressPolicy=persistent`) gave the bond a MAC made from the machine-id, which the bond then set on the NIC,
  so hypervisors that allow only the MAC they assigned (Hyper-V without MAC spoofing, vSphere rejecting forged
  transmits) could drop the appliance's traffic. The console's sign-in banner shows `bond0`'s address, not the
  DNS filter's internal 169.254.53.53. Found by the appliance boot test, which could not reach the installed system.
- The cluster-level kit (`cluster/`: the API server audit policy, the `ClusterSecretStore`, the Kyverno policy that
  admits only signed images) is written once at the root of an organization scan's output repository, for every
  app, instead of a copy in every app folder: the audit policy and the store were the same everywhere, the store
  access Role is in each app's `gitops/flux/tenant.yaml`, and one image policy now covers every namespace
  Containerizer manages with each app's image path. The next scan removes the app folders' `cluster/`.
  `containerizer generate` on a single app keeps writing it into its output folder.

## 0.11.0 (2026-11-05)

- Appliance: a push to the output repository deploys at once instead of at Flux's next poll (up to 5 minutes).
  `cz-sandbox` keeps a Flux webhook Receiver (`flux-system/containerizer-sandbox`, type generic) over the root
  sync's GitRepository and every app's own, with a token it makes once in the secret store
  (`flux-system--cz-webhook`); the scan worker and the LLM queue runner call it after every successful push (scans,
  Make it A variants, connectivity and link decisions, moved applications, sandbox switches, configuration backup),
  through `/run/containerizer/flux-webhook` (root:containerizer 0640, the receiver's cluster address: reachable from
  the appliance only). Best effort: a failed call is logged once and never fails the push, and polling stays as the
  fallback. Existing appliances get it after the upgrade: `cz-sandbox` makes the Receiver within 2 minutes and the
  URL on a later run, once the Receiver is ready. docs/scheduled-scans.md#flux-webhook also shows a Receiver for a
  cluster of your own.
- A "Make it A" patched copy that rates A and runs is deployed to the sandbox **in place** of the application's scan
  output: into the application's own folder of the output repository and its own namespace, so it has the
  application's URLs, IdP clients, lab database, `connectivity.yaml` and egress and link decisions (one folder, one Git
  history, one namespace per application), no longer a separate `<app>-refactor-<job>` application. The images keep
  the application's image path with the tag `1.<date>.<time>-refactor.<job>`; `containerizer.json` records the
  order, its source commit and the output repository's commit before it (`patched`). A scan of the same commit leaves
  the folder as it is (and still records its assessment); a scan of newer code writes its own output and the order
  becomes *replaced by newer code*; a newer order overwrites an older one in place; **Remove from the sandbox** puts
  the scan's output back from the output repository's history. Existing variants move by themselves: the LLM queue
  runner's housekeeping generates the latest running `<app>-refactor-<job>` of each application again in the
  application's folder (from the source at its commit with its patch, with the images it was built as), deletes the
  `-refactor-` folders and regenerates `sandbox/` in one commit; Flux prunes the old namespaces (and their lab
  databases), and the orders' pages show the application's own namespace and URL. Schema 42: `cz.vSandboxNamespace`
  has one row per namespace and a column `Own`. ([refactoring.md](docs/refactoring.md#the-sandbox-variant))
- The Containerizer logo and name sit in the top bar's right corner of every results page, above the sign-in links,
  instead of a line of their own above the front page's title.
- The Refactoring box on a B application's results page has one button, **Make it A**. The separate **Request a
  refactoring patch** (targeted changes) and **Make it stateless** (data to SQL Server) orders, which Make it A
  includes, are gone from the page, also from each component's migration assistant ("How to fix" points to Make
  it A). They remain on the command line (`containerizer refactor --goal fix|stateless`), and earlier orders still
  show with their patches.
- **LLM queue: a job holds an LLM only while it asks.** Before, the runner gave each job one of an LLM's requests
  for the job's whole life, so two Make it A orders that were building, verifying or deploying (or reusing answers
  and asking nothing) kept both built-in LLM servers "Asking" while a job that needed the LLM waited. Now each LLM
  call takes a request of the first LLM in the order that takes the call's size and has a free one, and gives it
  back as soon as it is answered; calls that wait are answered in the queue's order, and an answer in the cache
  needs no request. How many jobs run at once is a setting of its own, **Jobs at once** (LLM queue → Settings; 0,
  the default: automatic, every LLM request at once plus one, kept modest because builds compete with a CPU LLM for
  the machine). A job that needs the LLM starts while an LLM that takes it has a spare request; the jobs after it
  that need no LLM start meanwhile. An LLM's size limit (**Calls up to**, formerly *Jobs up to*) is now per LLM call:
  a refactoring order's files can go to different LLMs. Schema 41 (`containerizer db init`; the appliance runs it at
  boot) adds the setting and what a running job's call does now.
  - The queue page says **Asking** and the LLM only while a call of the job is answered, **Waiting for an LLM**
    while a call waits for a request, else **Running** with the job's progress (generating, verifying, deploying);
    the LLMs table shows the requests in progress on each (**Asking now**).
  - Speed statistics are learned per call: each LLM's figures from the calls it answered (their size, tokens and
    time and the requests at once on it), no longer from the job's whole time with its builds. A job's **Answered
    by** is the LLM that answered most of its calls, none when it asked nothing. The metric
    `containerizer_llm_queue_llm_jobs` counts the requests in progress per LLM; the new
    `containerizer_llm_queue_llm_waiting` counts the calls waiting for one.

## 0.10.0 (2026-11-04)

- **Breaking: ratings C and D swap meaning.** **C** is now *Partial*: some components must stay on Windows and the
  ones that can move need at most minor changes, so that part can run in Linux containers now. **D** is now *Major
  refactoring*: a framework port is needed before anything runs, also when other components must stay on Windows
  (the worse of the two). A, B and E do not change (E: no server component, or three quarters or more of them must
  stay on Windows). A partial application ranks better than a framework port because its Linux part can run today.
  - Stored history keeps its meaning: schema 40 (`containerizer db init`; the appliance runs it at boot) rewrites,
    once, every stored rating. An assessment rated C (framework port) becomes D; one rated D (partial) becomes C,
    or stays D when its stored report shows a server component that needs a port (blocked and port, D on the new
    scale). The copies of a rating elsewhere (a repository's last rating on the scan pages, the ratings of Make it A
    orders and of split repositories' folders) swap C and D plainly, so a repository that was partial *and* needed a
    port shows C there until its next scan. Trends and history pages show the new meaning. Upgrade every
    `containerizer assess --sql` writer (pipelines, workers) with the database: an older one still writes the old
    letters.
  - CI gates: `containerizer check --max-rating` and the action's `max-rating` follow the new order. `--max-rating C`
    now lets partial applications pass but fails framework ports (it was the other way round); `--max-rating D`
    lets both pass as before. A gate set to C should be set to D to keep passing framework ports. A rating drop
    from C to D on a pull request (the PR adds a port to a partial application) now fails `fail-on-rating-drop`.
  - The front page tiles group by meaning: **Need code changes (B, D)** and **Partly or not feasible (C, E)**.
  - The benchmark labels (`bench/labels.yaml`, `bench/realworld.yaml`) are rewritten for the new scale; the
    benchmark's easy/hard split stays A–C against D–E, which now means a port or not feasible against the rest.
- The front page leaves out applications not mapped to a product for everyone but administrators: nobody has said
  whose they are yet. Administrators see them with a note and a link to map them. Without sign-in (no admin pages)
  everything is shown as before.
- Sandbox IdP: the sync job (`cz-idp-sync`) trusts the Sandbox HTTPS certificate, also one from an internal CA or
  self-signed. It calls the IdP through Traefik, which serves that certificate, and failed every 5 minutes with
  `certificate verify failed: self-signed certificate`, so users, groups and app registrations were not applied.
  The appliance publishes the certificate's chain (never the key) as ConfigMap `containerizer-sandbox-ca` in
  `containerizer-idp`, and the job trusts exactly it.
- Appliance, kubemg: the sandbox cluster gets its kubemg agent again ("No agent tunnel right now"). The loopback
  certificate kubemg serves had no authority key identifier, which Python 3.13 (the appliance's) refuses by default
  (`certificate verify failed: Missing Authority Key Identifier`; kubemg logged `tls: bad record MAC`), so the
  sandbox registration never connected, while Caddy did. The certificates now carry the key identifiers; an
  existing one is issued again with the same keys when kubemg starts, so Caddy keeps trusting it.
- Appliance, kubemg: when the sandbox cluster's registration in kubemg cannot complete the TLS handshake with kubemg
  (loopback HTTPS), it stops at once and says why in `journalctl -u containerizer-kubemg-sandbox`, instead of retrying
  every 5 seconds for 10 minutes (a `tls: bad record MAC` line in kubemg's log each time) and starting over.
- **Migration plan** on the results page of every application that does not rate A, right after the main
  obstacles: its components in waves. *Wave 1, now*: the components that rate A on their own, with
  whether each is in the sandbox (the check's result, "deployed, not checked yet", or "not deployed" and why: the
  application's sandbox is off, the scan left it out). *Wave 2, after code changes*: what to fix (pointing
  to Make it A where the page has it) and what the part that can run in Linux containers rates once it is fixed
  (the application rating rule, `assess.rating_of`). *After a framework port*, *Stays on Windows (VMs)* with the
  main obstacle, and *Between the parts*: the calls from one part to the other from the connectivity data. A
  summary line on top ("2 of 6 components can run in Linux containers now; 1 more after code changes; 3 stay on
  Windows."). The rating still grades the whole application's end state (docs: overview, Migration plan).
- The Components table shows the **Sandbox cluster** column whenever a component is deployed to the sandbox, with
  "deployed, not checked yet" until a sandbox check has a result. New view `cz.vSandboxDeploy` (schema 39, readable
  by the reader role): the application's sandbox switch and what the latest organization scan deployed and left
  out, from the repository's scan record.
- The front page shows "2/6 ready now" next to the rating of an application that does not rate A but has
  components that do on their own.
- The results page no longer shows the "Prompt for an AI coding agent" (and `/app/<id>/component/<id>/agent-prompt.md`
  is gone): Make it A replaces it. The output repository keeps `agent-prompts/` and `MIGRATION.md`; the migration
  assistant's plan stays on the page. The results pages have no script any more.

- An application's results page links to its admin pages for those who may open them (Admin: Application settings for
  administrators and the product's owners, Dev databases and Refactoring orders for administrators and operators),
  and Admin → Applications links each application to its results page.
- Security: no application gets a namespace of the cluster, the platform or Containerizer itself. Only `default`,
  `kube-*`, `openshift*` and a few add-ons were reserved, so a scanned repository called `external-secrets` (a fork of
  External Secrets Operator) or `containerizer-secrets` (or project `containerizer` + repository `secrets`, or a
  split repository's folder) became that namespace: its Flux tenant got the `admin` role there, its default-deny
  NetworkPolicies cut the operator off, and removing the application deleted the namespace. Such names now get
  `app-` in front (`app-external-secrets`), for organization scans, split folders and `containerizer generate`
  alike, and the sandbox leaves out any app folder that names a reserved namespace
  ([app names](docs/scheduled-scans.md)).
- The web UI says it is Containerizer: the front page has the logo and the name above its title, linking to
  [containerizer.eu](https://containerizer.eu), every page ends with a link to it, and browser tabs read
  "… · Containerizer". The front page asks "How ready are our applications to run in Linux containers?" (it had
  no question mark), with the last assessment and Trends over time on a line of their own.
- Sandbox apps' Flux Kustomizations become Ready when their workloads are. They waited for every applied object
  (`wait: true`), including the ExternalSecrets of the components' secret settings, files and keytabs, whose remote
  keys nobody fills in the sandbox: ESO never synced them, so the health check timed out after 5 minutes at every
  retry although the pods ran (their references are optional). `sandbox/flux/apps` now sets `wait: false` with
  `healthChecks` of each app's Deployments and StatefulSets and of the ExternalSecrets of Secrets a pod cannot start
  without (Data Protection keys, the image pull credential, any reference that is not optional), so those still
  fail it. The app folder's own `gitops/flux/git/sync.yaml`, for real clusters, keeps `wait: true`. The next scan
  rewrites `sandbox/` for every app in the output repository, and the root sync applies it.
- The appliance's scans now check the sandbox at the end: the scan worker never had the read-only verifier
  kubeconfig, so the sandbox check (`--verify-sandbox`) never ran and the results pages showed nothing about the
  sandbox. The worker now gets it (`CONTAINERIZER_SANDBOX_KUBECONFIG`, as the LLM queue runner) and checks while
  `cz-sandbox` finds the sandbox connected to the output repository, up to 15 minutes; **Stop** ends the wait
  without recording the check.

## 0.9.5 (2026-11-04)

- **Browse and fix the sandbox databases** (appliance): Admin → Dev databases now opens each application's
  database in the sandbox, a lab-service database (SQL Server, PostgreSQL, MySQL) or a restored dev database, in
  its namespace or a Make it A variant's (the latest first). Tables, rows (50 a page, sort, filter), a row editor
  (change, add, delete by primary key, NULL and default boxes), a SQL box, and **Delete database** after typing
  its name: a lab-service database is created again empty with the same login and the application restarts; a
  restored dev database is restored again from its backup. Administrators and operators only. The web UI asks the
  system agent and waits for its answer (`/run/containerizer/system/answers`); the agent checks that the namespace
  is the application's and runs each statement with the engine's own client in the server's container, as the
  application's own login, in its own database, the password on stdin only. At most 500 rows or 1 MB, 15 seconds
  a statement. Every change is recorded before it runs, with its values, in the change history (**Sandbox
  databases**); needs schema 38 (`containerizer db init`; the appliance runs it at boot). MongoDB, Redis and the
  other lab services are not browsed ([Browse and fix the data](docs/dev-databases.md#browse-and-fix-the-data)).

## 0.9.4 (2026-11-04)

- Application tags: administrators and operators tag an application on its results page (`customer-facing, pci,
  wave 1`), and everyone filters the front page by a tag, alone or with a business unit (`/?bu=3&tag=pci`); the
  tiles and bars then count only those applications. The change history records the tags, and the API returns
  them and filters by one (`?tag=`). Needs schema 37 (`containerizer db init`; the appliance runs it at boot)
  ([Application tags](docs/sign-in.md#application-tags)).
- **Make it A: every B application** can turn [LLM-heavy mode](docs/source-control.md#llm-heavy-for-a-while) on
  for each application it orders, for the hours chosen, with the same button: their orders and the jobs that
  follow go first in the LLM queue, approved ([Make it A](docs/refactoring.md#make-it-a)).
- Appliance: kubemg (`CZ_KUBEMG=true`) starts again; https://kubemg.<appliance>/ gave HTTP 502. Its loopback HTTPS
  certificate was made under cz-firstboot's umask 077, so its folder was 0700 root and kubemg, which does not run as
  root, could not read it (`tls setup failed: stat /etc/kubemg/ssl/tls.crt: permission denied`). The modes are now
  set explicitly: the folder and the key are open to kubemg's group only, the local CA's key stays root's. Every
  start of kubemg sets them again, so an appliance with the broken folder heals without a reboot.
- Generated web components run **one replica** (was two). A second replica needs shared state first, which is a
  code change (the findings say which: sessions, caches, SignalR). With two, an ASP.NET Core app's forms failed
  whenever the post landed on the other pod: `The antiforgery token could not be decrypted ... The key {…} was not
  found in the key ring` (parts-catalog in the lab).
- ASP.NET Core **Data Protection keys** are shared and survive restarts, without a code change: when the code does
  not persist them (`PersistKeysTo*`), the key folder gets one key, read-only, from a Secret that External Secrets
  Operator generates once in the cluster (Password generator; no secret store, nothing to set up). Before, each pod
  kept its own keys in an `emptyDir`, so every restart or redeploy logged users out and broke open forms.
- Make it A: only the sandbox variant of an application's latest order stays. Two orders of the same application on
  the same commit were both deployed and both stayed (in the lab, trade-rebates ran as `...-refactor-168` and
  `...-refactor-172`), because a variant was retired only when a scan assessed another commit. The queue runner now
  takes the older variants of an application out of the output repository when a newer order's variant is
  deployed, whatever commit each was made for, the same way **Remove from the sandbox** does (the folder deleted,
  `sandbox/` regenerated: Flux prunes the namespace), and the order and results pages show them as **Replaced by
  newer code** (by order #N). Variants already deployed twice are cleaned up the same way.
- Make it A keeps an edit whose search text escapes backslashes once more than the file does. A JSON-escaped
  path in the file (`"\\\\fsfile01\\FieldService\\Photos"` in appsettings.json) came back with every run of
  backslashes doubled, so the edit did not apply and the answer was lost: in the lab, field-service lost its
  appsettings.json edit and with it the findings it fixed (sql-integrated-security, unc-shares). Such an edit now
  applies when the search text, un-escaped one level, occurs exactly once and the replacement was escaped the same
  way. It applies with the replacement un-escaped to match. When the match is ambiguous it is still refused with the
  error that shows the line from the file. An edit that applies only once its backslashes or line-end spaces are
  corrected goes through the same checks as any other: a credential it adds is cut out, and an edit that removes
  `Directory.CreateDirectory` is refused.

## 0.9.3 (2026-11-04)

- Make it A keeps more of the LLM's work. An answer was applied all or nothing, so one harmless slip threw
  away all of its edits: an edit that changes nothing, removing a package the project does not reference, or a
  connection string with `User ID=sa;Password=…` in place of Windows authentication. The first two are now left
  out, and the credential is cut out of the edit, which then applies: the sandbox gives the connection string
  with its credentials from a secret (`ConnectionStrings__<Name>`). In the lab, field-service and
  document-control lost every edit of a round this way. An edit whose search lines end with a space the file
  does not have (`using System; `) applies too, where it said the line is not in the file and showed the same line.
- Appliance on a physical server: every wired interface joins one active-backup bond (`bond0`), with the
  address on it, as olljanat/nomad-qemu-node does. Cable several NICs and the appliance stays reachable when
  one link fails ([Network](docs/appliance-admin.md#network)). The bond keeps its first NIC's MAC, so VMs on
  Hyper-V and vSphere work as before, and NICs without a cable no longer hold up the boot. LLDP tells the
  switch which port the appliance is on. A static address now goes on `bond0`; a file that names a NIC keeps that
  NIC out of the bond. The DHCP client ID is now that of `bond0`, so the DHCP server may hand out a new
  address after the upgrade unless it is reserved.
- The appliance has `net-tools` (`ifconfig`, `netstat`, `route`, `arp`) and `bridge-utils` (`brctl`) for those
  used to them; `ip`, `ss` and `bridge` remain the ones the docs use.
- The appliance's configuration files (`/etc/containerizer`: the `.env` files, `egress.json`, `network/`) are copied
  without their secrets to `.appliance/<CZ_HOSTNAME>/config/` of every output repository at every boot, in one commit
  when something changed: their history is in Git ([backup](docs/appliance-admin.md#backup)).
- An output repository registered twice under Admin → Source control (another spelling of its URL) uses the write
  token set last, the one that most likely replaced an expired or revoked one, instead of the first in the list.
- The output repository's clone and push are tried again after a transient failure (a GitHub outage: HTTP 5xx,
  `[remote rejected] (Internal Server Error)`, a dropped connection), after 10, 30 and 90 seconds. Before, the three
  push attempts came back to back, so a short outage failed a scan's or a Make it A order's deploy. A write token
  the server refuses is said plainly ("github.com refused the write token for … : expired, revoked, or no write
  access (Admin → Source control)") instead of git's `could not read Username … terminal prompts disabled`, and is
  not tried again.
- A scan's sandbox check waits for the namespaces of apps it just added: they are forbidden to read until Flux
  creates them and the verifier gets its Role there (`cz-sandbox`, within minutes). Before, every new app's
  components came back as errors at once. A namespace that never becomes readable within the timeout (the sandbox
  not connected to the output repository) is now *not checked*, with that hint, instead of an error, and a Make it A
  variant that could not be checked at all shows **Deployed, health not checked** instead of **Failing**.
- A Make it A variant whose scheduled job (CronJob) has not run yet is no longer **Failing**: its schedule is a
  placeholder until it is set (HARDENING.md), so the job is deployed as it should be and the variant is **Running**.
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

