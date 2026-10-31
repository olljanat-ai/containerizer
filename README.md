# Containerizer

A tool that tells you whether an application can run as a Linux container on Kubernetes, explains why,
and generates hardened container builds and Kubernetes manifests for the parts that can. It was built
for the [onek8s containerization challenge](https://github.com/onek8s/containerization-challenge)
(33 Windows-era .NET business applications, about half of them purposely hard or impossible to
containerize) and for real-life portfolios.

Design principles:

- **Rules first, AI last.** Classification is done by a data-driven rule set (`rules/*.yaml`). An LLM
  is consulted only for components the rules are unsure about, and what it says is validated before
  it is used or learned.
- **Learns by doing.** When unsure, the tool builds and runs the generated container, matches failures
  against failure rules, patches the build plan and retries. Fixes that work are proposed as rules
  with their evidence; once a person approves them ([rule review](docs/rule-review.md)), the next run
  needs no retries and no AI.
- **No application changes.** Dockerfiles use the application folder as build context with their own
  `Dockerfile.dockerignore`; configuration is overridden with environment variables and volumes.
- **Secure by default.** Multi-stage builds, chiseled (distroless) .NET images, non-root user,
  read-only application files, read-only root filesystem, all capabilities dropped, seccomp,
  secrets only as Kubernetes Secret references, base images pinned to a version line.

## Getting started

Containerizer ships as an appliance: one virtual machine with an immutable OS image, the web UI and
API, the scan worker, SQL Server, a single-node k3s sandbox cluster with Flux, a local container
registry, Prometheus and Grafana. Everything day to day is done in the web UI.

1. **Download** the ISO, qcow2 or VHD from the latest
   [release](https://github.com/olljanat-ai/containerizer/releases), check it against the signed
   `SHA256SUMS` and install it ([install](docs/appliance.md#install)).
2. **First boot**: set the host name and single sign-on, then open `https://<host name>/admin`
   ([first boot](docs/appliance.md#first-boot), [sign-in and roles](docs/sign-in.md)).
3. **Admin → Firewall**: allow the Git servers, package feeds and registries your scans need.
4. **Admin → Source control & LLM**: register a read-only token for each organization and a write token
   for each output repository ([making the tokens](docs/source-control.md#making-the-tokens)), and
   optionally the LLM.
5. **Admin → Organization scans**: schedule the scans ([organization scans](docs/scheduled-scans.md)),
   then read the results and approve what the learning loop proposes ([rule review](docs/rule-review.md)).

The rest of this page explains how the assessment works and what it generates.

## How it works

```
 scan ──► roles ──► facts ──► findings ──► reachability ──► confidence ──► rating
  │        rules     rules     rules        (type graph)      unknowns         │
  │                                                              │ low          ▼
  │                                                     verify (build+run) ──► report / generate
  │                                                              │ unexplained
  │                                                     Claude (validated) ──► rules/learned/
```

1. **Scan** reads project files (.csproj/.vbproj incl. old-style and imported
   `.props`, package.json, requirements.txt/pyproject, go.mod, pom.xml/gradle, BizTalk/SQL/SSIS
   projects, ASP.NET Web Site projects listed in a .sln), source and configuration. Nothing from the scanned repository is executed.
   Java and Node.js have their own parsers ([docs/java-node.md](docs/java-node.md)): Maven parents,
   profiles and modules, Gradle version catalogs and `subprojects {}`, npm/yarn/pnpm workspaces, and
   the lockfile's Windows-only and native packages.
2. **Role rules** (`rules/00-roles.yaml`) decide what each project is: web, worker, console, spa,
   desktop, library, test, tool, BizTalk, SharePoint, Sitecore XP, SQL CLR, SSIS.
3. **Fact rules** (`rules/05-facts.yaml`) extract ports, health endpoints, run-once arguments,
   connection strings, folders the app writes to, Kestrel endpoints.
4. **Finding rules** (`rules/10-runtime.yaml`, `20-platform.yaml`, `30-integration.yaml`) detect
   blockers and work items with a severity:
   `info < config < refactor < rewrite < blocker`, an effort estimate, an explanation, a fix, and
   whether a Windows container would be a workable stop-gap.
5. **Reachability**: findings in shared libraries only count for components whose code actually
   reaches the offending types (a type/extension-method mention graph) and that it compiles for its
   target framework, and Windows-only calls guarded by `OperatingSystem.IsWindows()` (directly, through
   a helper, or at every caller) are ignored.
6. **Confidence**: packages and references unknown to `rules/packages*.yaml`, and uncertain rules,
   lower a component's confidence. Low confidence triggers verification and, optionally, Claude.
7. **Rating** per application: **A** lift and shift, **B** minor refactoring, **C** framework port,
   **D** partial (some components must stay on Windows), **E** not feasible.
   **A** also requires every server component to be **stateless**: persistent data may live in
   services that are available as managed cloud services (SQL Server, PostgreSQL, MySQL, MongoDB,
   Redis, blob storage, queues), but not on the component's own disk or in its process memory. Rules
   that find such data carry `state: local` or `state: memory` (`rules/36-state.yaml`, `sqlite-local`,
   `lucene-local-index`): a local SQLite/LiteDB file with no server database wired up, a local
   Lucene/Examine index, uploads or data files written under the content root or App_Data,
   ASP.NET Core session without a distributed cache, and Hangfire in-memory storage. An app that is
   otherwise ready but keeps such data is rated **B**, and the report lists what keeps it stateful.
   Not counted: SQLite next to a server database provider (`sqlite-optional`), a read-only SQLite
   file shipped with the app, Lucene used only for text analysis, temp files and logs, and the
   ASP.NET Core Data Protection key ring (one `PersistKeysTo*` line; reported separately).


### Rules are data

```yaml
- id: com-office-automation
  when:
    any:
      - code: 'GetTypeFromProgID\("(Word|Excel|Outlook)\.Application'
      - reference: 'Microsoft\.Office\.Interop\..*'
  severity: blocker
  category: com
  windows_container: false
  title: Microsoft Office automation (COM)
  why: Drives Word/Excel through COM ...
  fix: Replace with a document library (OpenXML SDK, ClosedXML, ...)
  refs:
    - https://learn.microsoft.com/en-us/dotnet/core/porting/
```

Every finding is explained without AI: `why` says what breaks in a Linux container, `fix` what to
do, and `refs` link to the documentation or upstream issue behind it. All three are shown with the
finding in the web UI and in the generated `MIGRATION.md`. Findings
observed at run time carry the explanation and links of the failure rule that recognised them, and
every non-default build decision (a plan rule, a config override, a fix learned while verifying) is
listed with its reason and links at the top of the generated `Dockerfile` and in `plan.json`.

Condition primitives: `sdk`, `tfm`, `package`, `reference`, `framework_ref`, `property`,
`output_type`, `kind`, `role`, `name`, `path` (regex on the project file's path relative to the
repository root), `file` (glob), `code` / `config` / `text` (regex with optional `in:` glob and
`unguarded`), `readme`, `closure` (a condition that holds for the project or any project it
references, e.g. a file-system class elsewhere in the solution), `references` (a condition that holds
for a project this one references directly), combined with `any` / `all` / `not`.
`unguarded: true` skips Windows-only hits the code already keeps off Linux: a few lines after an
`OperatingSystem.IsWindows()`/`IsOSPlatform(...)` check or after a call of a project helper whose body is
one (`bool IsWindows { get; } = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)`,
`static bool IsModuleLoaded() => OperatingSystem.IsWindows() && ...`, also from referenced projects),
inside `if (<OS check> && ...) { }` or the `else` of `if (!<OS check>)`, after
`if (!<OS check>) return/throw`, inside a method/type marked `[SupportedOSPlatform("windows")]`, or in a
member/type whose every caller is guarded. Callers are searched in the project and the projects that
reference it (test projects excluded), two levels deep: calls of a static member or a P/Invoke,
constructions (`new T(...)`) and static accesses of the type for instance members. A virtual/override
member, a method group, a type created through `typeof`/a generic method argument (DI) or subclassed
has callers that cannot be followed, so the hit counts. `unguarded: callers` applies only the caller
check (for an annotation on the type itself, as `supported-os-windows` does). `same_file: true` next to
an `all` requires its `code`/`config`/`text` conditions to match in the same file (e.g. an assembly
loader *and* an install path probe, not two unrelated files).

The scanner evaluates the target-framework part of MSBuild conditions: an item under
`Condition="'$(TargetFramework)' == 'net472'"` (also `TargetFrameworkIdentifier`,
`GetTargetPlatformIdentifier(...)`, `$(TargetFramework.StartsWith(...))`, properties whose value is a TFM
such as `$(SAMPLES_TFM)`) is dropped when no TFM of the project gets it, and recorded per TFM otherwise;
conditions on anything else (Configuration, `Exists()`, OS) count as possibly true. The same holds for
`<Compile Remove/Include>` in SDK-style projects. A consumer follows a multi-targeted library along the
TFM it compiles against (NuGet's nearest framework), so a net8.0 app does not inherit the net472-only
references, project references or source files of a `net472;net8.0` library. C# `#if` branches that none
of the project's TFMs compile are blanked before code rules run (`NETFRAMEWORK`, `NETCOREAPP`,
`NETSTANDARD`, `NETx_y[_OR_GREATER]`, `NET4xx`, platform symbols such as `WINDOWS`, and legacy platforms
`NETCF`, `MONO`, `SSCLI`, `SILVERLIGHT` that no current SDK defines); symbols the project defines in any
configuration (`DefineConstants`), `#define`d in the file, or unknown stay possibly active.

Properties the scanner sets on projects (usable with `property:`):

| Property | Meaning |
| --- | --- |
| `RunByBuild` | an MSBuild `<Exec>` elsewhere in the repository runs this executable (`dotnet Name.dll`, `Name.exe`, `dotnet run --project ...`): a build-time helper; the value is that build file |
| `RunFromSourceBy` | a repository script starts it with `dotnet run` (compiled from the checkout): a developer utility; the value is the script |
| `ReferencedBy` | the first project that references this one (`ProjectReference`): it is compiled into something else |
| `HostedBy` | a front-end (Node) or Blazor WebAssembly project served by a .NET project: nested in its folder, referenced by it, or writing its bundles into its folder (webpack `output.path: "../Web/Scripts"`, `"destination": "../Web/Styles"`, a `copyfiles ... ../Web/...` script; Visual Studio `.esproj` projects) |
| `SpaRoot` | on the .NET host: the folder of the nested front-end project |
| `WebSiteProject` | an ASP.NET Web Site project (no project file) found in this solution |

ASP.NET **Web Site projects** (Visual Studio "New Web Site", solution entries with project type
`{E24C65DC-7377-472B-9ABA-BC803B73C61A}` and no .csproj) are read from the `.sln`: the folder becomes a
.NET project named after the entry, with the target framework from `TargetFrameworkMoniker` and the
solution's `ProjectReferences`/`ProjectDependencies` of the entry as project references. Its project
path is shown as `<folder>/<name>.website` (there is no such file).

Next to `title` / `why` / `fix`, a finding rule takes `refs:`, a
list of verified https links (docs page, upstream issue, vendor statement) shown with each finding;
`tests/test_rule_docs.py` enforces that every refactor/rewrite/blocker rule has one or is on its
commented allowlist.
Later files override earlier rules with the same id; `rules/learned/` is loaded last.


### Migration assistant

For every component that is not ready (verdict refactor, rewrite or blocker), each blocking finding is
mapped to a concrete Linux-compatible replacement from [`rules/migrations.yaml`](rules/migrations.yaml):
System.Drawing → SkiaSharp/ImageSharp, WCF → CoreWCF, Windows Service → worker service, Office
automation → Open XML SDK/ClosedXML, registry → configuration, Event Log → ILogger, MSMQ → a broker,
and so on, with packages to add and remove, steps, checks, an effort estimate and references. Parts
with no Linux replacement (desktop UI, hardware, vendor COM SDKs, BizTalk) are marked "keep on Windows"
instead of being forced into a code change.

```yaml
- id: replace-system-drawing
  for: [system-drawing-core, pkg-mschart, pkg-qrcoder-gdi]
  kind: replace                    # replace | port | externalize | isolate
  replace: System.Drawing (GDI+)
  with: SkiaSharp or ImageSharp for images, QuestPDF for documents
  packages: {add: [SkiaSharp, SkiaSharp.NativeAssets.Linux.NoDependencies], remove: [System.Drawing.Common]}
  steps: [...]
  verify: [...]
```

The plan is also rendered as a self-contained **prompt for AI coding agents** (Claude Code, GitHub
Copilot, ...): the findings with their evidence, the replacements in order, constraints (minimal
changes, no secrets in code, non-root and read-only file system) and how to verify. The web UI shows
it on the component's migration assistant with a copy button.

### Self-learning loop

For each component that can be containerized the scan:

1. builds the generated Dockerfile (application folder as context);
2. runs it hardened (read-only root filesystem, all capabilities dropped, no new privileges, non-root,
   only the writable folders mounted) and probes the health endpoint. Writable folders are host
   directories during the test, so apps that log only to files can still be diagnosed;
3. matches the log against `rules/50-failures.yaml`:
   - `retry`: patch the build plan (e.g. remove a pinned `global.json`, retarget an out-of-support
     TFM to net10.0, add Kerberos libraries, make a folder writable) and try again;
   - `external`: the container works, it only lacks a database/broker/directory/identity provider —
     then the tool retries in a dependency-free smoke mode (`Development` environment, which many apps
     map to SQLite and simulators) to prove the app actually serves requests. For the smoke run only,
     `appsettings.Development.json` is mounted read-only (the image never contains it), relative
     SQLite paths are made absolute and writable, and sample input files are mounted from the repo.
     An app that never answers HTTP gets the same smoke retry;
   - `platform` / `code`: a runtime finding the static rules missed;
4. if nothing matches and the scan has **Ask the LLM** on, the LLM proposes a diagnosis, a regex and a
   plan patch; it is applied only if the regex matches the log and the patch uses whitelisted plan keys;
5. learns what worked: plan patches → plan rules, confirmed AI failure rules → failure rules, runtime
   findings → finding rules, and packages of components that ran → Linux-safe packages (raising
   confidence next time). The run uses them right away; for everything else they wait as candidates
   with their evidence until an administrator approves or rejects them under **Admin → Rule review**.
   Approved rules go to your internal (private) rules repository, never into this public one
   ([rule review](docs/rule-review.md)).

### AI fallback (Claude or a self-hosted LLM)

The LLM is set once under **Admin → Source control & LLM**
([the LLM](docs/source-control.md#the-llm)): the Claude API, or any self-hosted OpenAI-compatible
server such as Ollama, vLLM, LM Studio or llama.cpp. It is asked only about components the rules are
unsure of and failures no failure rule explains. Every answer is validated against its schema before
it is used or learned, responses are cached, and usage and cost are tracked.

## Generated output

Per component: `Dockerfile` (+ `Dockerfile.dockerignore`), `k8s.yaml` (Deployment or CronJob,
Service, NetworkPolicy, PVCs where state must persist, ExternalSecrets for every credential),
`plan.json` (the build plan). For .NET Framework components that could work in Windows Server
containers, a `Dockerfile.windows` stop-gap. Per app: `kustomization.yaml` and `MIGRATION.md`.
Java (Maven/Gradle; Spring Boot, Quarkus, plain JVM programs, WARs on Tomcat) and Node.js
(npm/pnpm/yarn; Express, NestJS, Next.js and others) components get distroless, non-root images
built on the runtime line they declare; see [docs/java-node.md](docs/java-node.md#containers).

GitOps: every app also gets `gitops/` with Argo CD and Flux configuration built from the same data:

| | Argo CD | Flux |
| --- | --- | --- |
| Scope | `AppProject` pinned to the repo, the app namespace and the generated kinds | `tenant.yaml`: namespace, ServiceAccount, `admin` RoleBinding in that namespace only; `Kustomization` applies as that ServiceAccount |
| Namespace | `CreateNamespace` with the Pod Security "restricted" labels | created by `tenant.yaml` with the same labels |
| Sync | automated, prune, self-heal, server-side apply, retries | `GitRepository` (read-only key, optional signed-commit check) or cosign-verified `OCIRepository`; prune, wait |
| Image updates | Argo CD Image Updater annotations (semver, Git write-back) | `ImageRepository`, `ImagePolicy`, `ImageUpdateAutomation` with `$imagepolicy` markers in `kustomization.yaml` |

Techniques used to avoid application changes:

- out-of-support .NET (Core 3.1, 5, 6, 7): build with the .NET 10 SDK and run on the supported .NET 10
  runtime with `DOTNET_ROLL_FORWARD=Major`; if the old target can't be built, retarget with
  `net10.0` in the build stage's copy of the entry project (its netstandard libraries keep their targets);
- `global.json` SDK pins are removed inside the build stage only;
- Kestrel endpoints from `appsettings.json` are re-pointed with `Kestrel__Endpoints__X__Url`;
- connection strings and secret settings become `ConnectionStrings__X` env vars from a Secret;
- folders the app writes to (logs, App_Data, Data Protection keys) become volumes;
- Windows paths in configuration (`D:\\Archive`, `\\\\fs01\\share`) are re-pointed to `/data/...` volumes
  with `Section__Key` env vars; key and certificate files go to `/secrets` from a Kubernetes Secret;
- Serilog file-only sinks are switched to the console (logs to stdout) with `Serilog__WriteTo__N__Name`;
- custom listen-address settings (`"WebhookUrls": "http://*:8085"`) are re-pointed to port 8080;
- NLog folders from `${configsetting:...}` / `${environment:...}` with Windows defaults are re-pointed
  by env var, and `${basedir}/logs` becomes a writable folder;
- installed Windows tools (`C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe`) map to the Linux binary on PATH;
- console tools with sub-commands (usage text, verb arrays, `case "x":`) get one CronJob per command;
- workers that use the ASP.NET Core shared framework get the aspnet base image;
- old netstandard1.x packages that break a linux-x64 restore (NU1605) get a portable publish;
- corporate TLS-inspecting proxies: an optional `ca` build secret is honoured.


## Security gate

Everything here is data in [`rules/60-security.yaml`](rules/60-security.yaml).

**Hardened manifests.** Every generated pod gets the baseline: runs as the image's own non-root UID
(`runAsUser`/`runAsGroup`/`fsGroup`: 1654 for .NET, 101 for nginx), read-only root filesystem, all
capabilities dropped, no privilege escalation, seccomp `RuntimeDefault`, no service account token, no
service links, CPU/memory/ephemeral-storage requests and limits, and a `sizeLimit` on every `emptyDir`.
`namespace.yaml` enforces Pod Security `restricted` for the whole app.

**Exceptions only when the app needs them**, decided by rule conditions and recorded on the pod as
`containerizer.io/exception.<id>` annotations with the reason:

| Exception | When | What changes |
| --- | --- | --- |
| `nginx-writable-dirs` | single-page app | `/tmp` and `/var/cache/nginx` writable |
| `kerberos-keytab` | Negotiate (Windows) authentication | keytab from a Secret at `/etc/krb5/keytab`, credential cache in `/tmp` |
| `native-rendering-memory` | PDF/image libraries (DinkToPdf, QuestPDF, ImageSharp, ...) in the component or a library it references | 1 GiB memory limit, writable font cache |
| `file-uploads` | `IFormFile` / `MultipartReader` | 1 GiB `/tmp`, 2 GiB ephemeral storage |
| `icmp-ping` | `System.Net.NetworkInformation.Ping` | `net.ipv4.ping_group_range` sysctl (no `NET_RAW`) |
| `kubernetes-api-client` | KubernetesClient and similar | service account token mounted, `sa-token` check waived |
| `privileged-port` | plan port below 1024 | `NET_BIND_SERVICE` |

**Lint.** The gate checks the manifests against Pod Security `restricted` (host namespaces, privileged,
capabilities, volume types, host ports, privilege escalation, non-root, seccomp, sysctls) plus read-only
root FS, resources, secret literals (in env, `ENV` and Secrets), the service account token, `emptyDir`
limits, image tags and NetworkPolicies, and the Dockerfiles for a non-root final stage, tagged base
images, `ADD <url>`/`curl | sh` and base image end of support. Errors fail the gate. A pod annotation
`containerizer.io/waives: "check,check"` relaxes named checks for hand-made exceptions.

The gate favours accuracy over speed: it builds every image, scans it with every available scanner and merges the
results, and starts it with the docker equivalent of its pod spec (user, read-only root, dropped
capabilities, sysctls, `emptyDir` mounts) to prove the exceptions are enough; read-only or permission
errors in the log fail the gate. A lock older than 14 days is refreshed first.


**Vulnerability scan.** The gate scans the final base image of every component and the built image;
findings missing from the base are attributed to the application's own packages (upgrade them) rather
than the base (bump it). It fails on vulnerabilities at or above `scan.fail_on` (default `CRITICAL`)
that have a fix; accepted risks go in `scan.allowlist` with a reason and an expiry date. Trivy and
Grype both scan, and their results are merged. When even the newest base tag still ships a vulnerable
OS package with a fix, the gate upgrades just that package in the final stage (`apk upgrade` /
`apt-get --only-upgrade`; chiseled images have no package manager and need a newer tag). Results go to
`SECURITY.md` and `security.json` next to the generated files.

**SBOM and licences.** Every built image gets a CycloneDX SBOM from Syft, with NuGet licences looked
up from the feed, each package checked against the licence policy (deny fails the gate, warn is
reported; GPL/AGPL warn by default) and the scan's CVEs attached to the package they are in. The SBOM
is attached to the pushed image and stored with the results; the web UI shows the packages of each
component and a portfolio page of licences and CVEs. See [docs/sbom.md](docs/sbom.md).

### NSA/CISA hardening

The manifests follow the [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
and CIS Kubernetes Benchmark section 5 as far as an application repository can. Every generated app
gets a `HARDENING.md` that lists each control as applied, applied with an exception, not applicable,
or an action for the cluster operator, with the guide section and CIS number.

- **Pods**: on top of the baseline above, AppArmor `RuntimeDefault` and a ServiceAccount per component
  (token not mounted). A component that needs the API gets an empty `Role` + `RoleBinding` to fill in
  with least privilege.
- **Network**: `security.yaml` holds a default-deny policy for the namespace. Each component has its own
  policy: ingress only on its port, egress to DNS, sibling components, and the external ports the
  code needs. Those ports are inferred from packages, code and configuration, for example SQL Server
  1433, SMTP, LDAP/Kerberos, message brokers, or a port in a connection string. Cloud metadata
  endpoints are always blocked, and single-page apps get no external egress. The inferred list is
  recorded in a `containerizer.io/egress` annotation and in the report.
- **Namespace**: a `LimitRange` (defaults without a CPU limit, so pods are not throttled) and a
  `ResourceQuota` sized from the workloads with 50 % headroom.
- **Secrets**: no generated file is a `Secret` or holds a value. Component settings, Flux source and
  registry credentials and the sandbox's Git token are [External Secrets](https://external-secrets.io)
  `ExternalSecret`s from the `ClusterSecretStore` `app-secrets` (remote keys `<namespace>--<name>`). Each
  namespace reads the store as its own ServiceAccount and only gets its own keys. `cluster/secret-store.yaml`
  defines the store (kubernetes provider by default; Vault, Azure Key Vault or AWS Secrets Manager by
  setting), and the gate fails on any plain Secret or Secret reference that no ExternalSecret produces. See
  [docs/external-secrets.md](docs/external-secrets.md).
- **Cluster kit** (`cluster/`): an API server audit policy (metadata only for Secrets, full requests and
  responses for RBAC, every write and every exec) and a Kyverno `verifyImages` policy that only admits images signed with your cosign
  key. These are for the cluster operator to apply. The report also lists the cluster controls the
  generator can't set, such as etcd encryption, kubelet authentication and control plane TLS.
- **GitOps**: Argo CD's `AppProject` allows only the `Namespace` cluster kind, no plain Secrets and no
  other source namespaces, and warns on orphaned resources. Applications sync with
  `ServerSideApply`, `PruneLast` and `FailOnSharedResource`. On Flux, the quota, LimitRange and
  default-deny policy move into the platform-owned `flux/tenant.yaml`. The synced Kustomization
  deletes them from its set with `$patch: delete` and doesn't `force`, so the app repository can't
  loosen them under the tenant's impersonated ServiceAccount.


**Patched base images.** `rules/images.yaml` lists the base image lines and
`rules/images.lock.yaml` the newest patch tag of each line that passed the vulnerability policy, with
its digest; the generator uses the exact tag. The bump policy is per image: patch releases of the same
line by default, newer stable lines for nginx, and the successor line for toolchains past end of
support (node, golang). .NET majors are never moved automatically. A lock older than 14 days is
refreshed before the gate runs.

## Results on the challenge

See [`bench/RESULTS.md`](bench/RESULTS.md) for the current numbers (rule accuracy, verification
results and the model comparison). The labels used for scoring are in
[`bench/labels.yaml`](bench/labels.yaml), written from each scenario's README and code.


## Layout

```
containerizer/   scan, rules engine, assess, reach, confidence, facts, generate, harden, imagescan, verify, ai, report
                 webui.py, admin*.py, api*.py: web UI, admin pages and API; worker.py: scheduled organization scans
containerizer/sql/  results database schema
rules/           curated rules (roles, facts, findings, plan, failures, security, images + images.lock, packages)
appliance/       the appliance OS image (Elemental), its services, system agent and boot tests
monitoring/      Grafana dashboard, Prometheus scrape config and alert rules
bench/           labels and results of the challenge
docs/            this documentation site (containerizer.eu)
```
