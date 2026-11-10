---
title: How it works
description: How Containerizer assesses applications, learns from failed builds, and generates hardened container builds and Kubernetes manifests.
---

# How Containerizer works

Containerizer tells you whether an application can run as a Linux container on Kubernetes, explains why,
and generates hardened container builds and Kubernetes manifests for the parts that can. This page
explains how the assessment works and what it generates. To install and use it, start with
[Getting started](appliance.md).

## Design principles

- **Rules first, AI last.** Classification is done by a data-driven rule set (`rules/*.yaml`). An LLM
  is consulted only for components the rules are unsure about, and what it says is validated before
  it is used or learned.
- **Learns by doing.** When unsure, the tool builds and runs the generated container, matches failures
  against failure rules, patches the build plan and retries. Fixes that work are proposed as rules
  with their evidence; once a person approves them ([rule review](rule-review.md)), the next run
  needs no retries and no AI.
- **No application changes.** Dockerfiles use the application folder as build context with their own
  `Dockerfile.dockerignore`; configuration is overridden with environment variables and volumes.
- **Secure by default.** Multi-stage builds, chiseled (distroless) .NET images, non-root user,
  read-only application files, read-only root filesystem, all capabilities dropped, seccomp,
  secrets only as Kubernetes Secret references, base images pinned to a version line.

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
   Java and Node.js have their own parsers (see [Java and Node.js](java-node.md)): Maven parents,
   profiles and modules, Gradle version catalogs and `subprojects {}`, npm/yarn/pnpm workspaces, and
   the lockfile's Windows-only and native packages. Python and Go too (see [Python and Go](python-go.md)):
   every manifest and lockfile of a Python folder, and one component per Go main package.
2. **Role rules** (`rules/00-roles.yaml`) decide what each project is: web, worker, console, spa,
   desktop, library, test, tool, BizTalk, SharePoint, Sitecore XP, SQL CLR, SSIS.
3. **Fact rules** (`rules/05-facts.yaml`) extract ports, health endpoints, run-once arguments,
   connection strings, folders the app writes to, Kestrel endpoints.
4. **Finding rules** (`rules/10-runtime.yaml`, `20-platform.yaml`, `30-integration.yaml`) detect
   blockers and work items with a severity:
   `info < config < refactor < rewrite < blocker`, an explanation, a fix, and
   `windows_container` (whether the technology would run on Windows Server at all; a hint for
   the migration plan and the SARIF output, not an output target: containerizer generates Linux
   images only, and components that must stay on Windows stay on VMs).
5. **Reachability**: findings in shared libraries only count for components whose code actually
   reaches the offending types (a type/extension-method mention graph) and that it compiles for its
   target framework, and Windows-only calls guarded by `OperatingSystem.IsWindows()` (directly, through
   a helper, or at every caller) are ignored.
6. **Confidence**: packages and references unknown to `rules/packages*.yaml`, and uncertain rules,
   lower a component's confidence. Low confidence triggers verification and, optionally, Claude.
7. **Rating** per application: **A** container-ready (built on a modern stack and libraries, runs in
   containers with configuration only, no code changes), **B** minor refactoring, **C** partial (some
   components must stay on Windows; the rest need at most minor changes, so that part can run in Linux
   containers now), **D** major refactoring (a framework port is needed, also when other components must
   stay on Windows), **E** not feasible (no server component, or three quarters or more of them must stay
   on Windows).
   **Stateful** is shown next to the rating, not taken from it: a server component that keeps its own
   data on its disk or in its process memory still rates **A** when it runs with configuration only,
   because it runs as it is with that data on a persistent volume and one replica (see
   [Application data on persistent volumes](#application-data-on-persistent-volumes)). Rules that find
   such data carry `state: local` or `state: memory` (`rules/36-state.yaml`, `sqlite-local`,
   `lucene-local-index`): a local SQLite/LiteDB file with no server database wired up, a local
   Lucene/Examine index, uploads or data files written under the content root or App_Data,
   ASP.NET Core session without a distributed cache, and Hangfire in-memory storage. The application is
   marked **stateful** (next to its rating, an automatic `stateful` tag the front page filters by) and the
   report lists what it keeps; scaling it out needs that data in a shared service first. Only data on its
   own disk in a folder Containerizer cannot find (so no volume can hold it) keeps a component at **B**.
   Not counted: SQLite next to a server database provider (`sqlite-optional`), a read-only SQLite
   file shipped with the app, Lucene used only for text analysis, temp files and logs, and the
   ASP.NET Core Data Protection key ring (one `PersistKeysTo*` line; reported separately).

   The letter grades the **whole application's end state**: an application with one component that must stay
   on Windows is rated for that, even when its other components run in Linux containers today. What can go
   first is on the results page's [migration plan](#migration-plan).

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
`superseded_by: [<rule id>, ...]` drops a finding when the component also has an active finding of one of
those rules, because that finding says more (`wcf-client` gives way to `wcf-server` in a component that
hosts WCF services and reaches client code through its libraries).

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

### Migration plan

The components of an application do not have to move together. What of an application runs in the sandbox now, by its latest
check, is shown at the top of its results page ("4 of 9 components run there now", with a link to open it: a
component with a user interface before an API) and on the front page under **Running in the sandbox**, for every
application, also the ones that need changes for the rest. The results page of every application that
does not rate A has a **Migration plan**, right after the main obstacles, that splits it into waves:

- **Wave 1, now** (to Kubernetes): the server components that rate A on their own (the application rating
  rule applied to the one component: configuration only) and did not fail to build and run. A component that keeps its own data is marked *runs with a persistent volume, one
  replica* with what it keeps; it needs no code change. These are the components an organization scan deploys to the sandbox, so each shows whether it is there:
  the sandbox check's result, *deployed, not checked yet* (the scan deployed it, no check has a result yet), or
  *not deployed* with why (the application's sandbox is turned off, the scan left it out, or no organization
  scan deploys the application).
- **Wave 2, after code changes**: components whose findings can be fixed in code (targeted changes, a failed
  build or run), with what to fix, and what the part that can run in
  Linux containers rates once they are fixed. Where the page has the Refactoring box,
  [Make it A](refactoring.md#make-it-a) makes these changes.
- **After a framework port or rewrite**: components that need one, with their main obstacle.
- **Stays on Windows (VMs)**: components that cannot run in a Linux container, with their main obstacle.
- **Between the parts**: the calls from a component of one part to a component of the other, from the
  destinations the assessment found in the components' configuration and code (a service name, the sandbox URL,
  or an internal host whose name is the end of the component's name, such as `lending-api.corp.local` for
  `Lucerne.Lending.Api`) and links within the application: "CustomerPortal calls Api over HTTPS: the Windows part
  must be reachable from the cluster". Left out when nothing crosses.

A line at the top sums it up: *2 of 6 components can run in Linux containers now; 1 more after code changes;
3 stay on Windows.* (or *Nothing runs in a Linux container until the framework port is done.*). The part that can
run in Linux containers is rated with the same rule as the application (`assess.rating_of`), as it is and with
the changes made. The front page shows the first wave next to the rating of such an application,
*2/6 ready now* (*, 1 with a volume* when wave 1 has components that keep their own data).

![Migration plan of an application with components that must stay on Windows: two components ready and in the sandbox, one after code changes, three that stay on Windows, and the calls between the parts](images/results-migration-plan.png#only-light){ .cz-shot }
![Migration plan of an application with components that must stay on Windows: two components ready and in the sandbox, one after code changes, three that stay on Windows, and the calls between the parts](images/results-migration-plan-dark.png#only-dark){ .cz-shot }

The Components table has the **Sandbox cluster** column whenever a component of the application is deployed to the
sandbox. Whether it is comes from the latest sandbox check (`cz.vSandboxLatest`) and, before a check has a result,
from what the latest organization scan put in the output repository and left out (`cz.vSandboxDeploy`, read from
the scan's record of the repository) together with the application's sandbox switch.

A component the scan left out at its security gate shows the reason and **What failed**: what the gate saw, such
as the end of the image build's log, the lint errors, or the errors and log of the run with the pod's hardened
security context (non-root, read-only root file system, no capabilities). Administrators and operators get
**Try again** under the table: it queues a full scan of only this application's repository, the page says while
that scan is queued or running, and afterwards the Sandbox column shows the new result, with what failed if a
component is still left out.

![Components table with a component the security gate left out: the reason, What failed with the hardened run's error, and the Try again button](images/results-try-again.png#only-light){ .cz-shot }
![Components table with a component the security gate left out: the reason, What failed with the hardened run's error, and the Try again button](images/results-try-again-dark.png#only-dark){ .cz-shot }

When a component that crashes in the sandbox needs a [lab service](lab-services.md) the lab has turned off, its
sandbox result says so first ("It needs RabbitMQ, which the lab has turned off: turn it on under Admin -> Lab
services"): an app without its message broker often just stops, and its other symptoms (an empty log, a secret
store key that is not there) point elsewhere.

### Application data on persistent volumes

A component that is ready in every other way but keeps its own data (a SQLite/LiteDB file, a local Lucene index,
uploads under the web root or App_Data, in-memory session or Hangfire storage) is deployed as it is: keeping
data is an orchestration concern, not a reason to change the application's code. The generator
(`generate.state_plan`):

- runs it as **one replica** with `strategy: Recreate`, so two pods never write the same files;
- mounts a **PersistentVolumeClaim** (`ReadWriteOnce`, 1Gi from the cluster's default StorageClass) on each folder
  the component keeps data in: folders its code and configuration write to (`Path.Combine(ContentRootPath, ...)`,
  `Path.Combine(env.WebRootPath, "uploads")`, folder settings, a SQLite `Data Source=data/app.db`), and App_Data
  when the code names data folders under it;
- moves an embedded database file that sits in the app folder (`"Data Source=app.db"`, `"Filename=app.litedb"`)
  to `/data`, a volume, with an environment variable that overrides the connection string
  (`ConnectionStrings__Default=Data Source=/data/app.db`): no file of the application changes;
- keeps the root file system read-only and the user non-root; `fsGroup` (with `fsGroupChangePolicy:
  OnRootMismatch`) lets that user write the volumes;
- labels the workload, its pods and its volumes `stateful: "true"` (not in the selector), so the platform can
  find them for backup and scheduling.

`stateful:` in `rules/36-state.yaml` sets the platform side without editing manifests: the labels, the
StorageClass (`storage_class`, empty for the cluster's default) and size of the volumes, and a `node_selector`
and `tolerations` for a dedicated node pool. A separate cluster is not needed: a stateful component is still
application tier (with an embedded database its data tier is in the same process), and what it needs from the
platform is storage with backups. A `ReadWriteOnce` volume ties the pod to the node or zone that holds it.

State kept only in memory (session, Hangfire in-memory storage) gets one replica and no volume. A component that
writes local data to a folder the generator cannot find rates B and is left out ("keeps local state in a folder
Containerizer could not find"): with a read-only root file system its writes would fail. The volumes hold
application data: `HARDENING.md` and `MIGRATION.md` in the output say so, and the operator owns their backup,
StorageClass and size. A volume starts empty: data shipped in that folder of the image (a seed database) is not
copied into it. Moving the data to SQL Server, to scale out, is a code
change and left to the application's developers (or a refactoring order, on request).

### Migration assistant

For every component that is not ready (verdict refactor, rewrite or blocker), each blocking finding is
mapped to a concrete Linux-compatible replacement from [`rules/migrations.yaml`](../rules/migrations.yaml):
System.Drawing → SkiaSharp/ImageSharp, WCF → CoreWCF, Windows Service → worker service, Office
automation → Open XML SDK/ClosedXML, registry → configuration, Event Log → ILogger, MSMQ → a broker,
and so on, with packages to add and remove, steps, checks and references. Parts
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

An entry can have `variants`, each a `when` condition (as a finding rule's) with its own packages and
steps, added when the condition holds for the component. The WCF port plan uses them to pick the CoreWCF
packages from the bindings found (`CoreWCF.NetTcp` for netTcpBinding, `CoreWCF.WebHttp` for
webHttpBinding and `[WebGet]`/`[WebInvoke]`, `CoreWCF.Http` for HTTP bindings and `.svc` endpoints) and to
keep a `<system.serviceModel>` services section with `CoreWCF.ConfigurationManager` instead of rewriting
it in code. The plan keeps the `System.ServiceModel` attributes in contract assemblies that clients also
reference, since CoreWCF hosts them as they are; WF4 workflow services (`WorkflowServiceHost`, `.xamlx`)
count as WCF services, and their plan says that CoreWF does not host them as endpoints.

The plan is also rendered as a self-contained **prompt for AI coding agents** (Claude Code, GitHub
Copilot, ...): the findings with their evidence, the replacements in order, constraints (minimal
changes, no secrets in code, non-root and read-only file system) and how to verify. It is in the output
repository (`agent-prompts/`, linked from `MIGRATION.md`); the results page shows the plan, and
[Make it A](refactoring.md#make-it-a) has Containerizer make the changes itself.

For a **B-rated** application Containerizer can also make the changes: a
[refactoring patch](refactoring.md) has the LLM change the code for its refactor findings, one file
at a time with structured edits, then applies the patch to the assessed commit, runs the rules on it
again and builds and runs the changed components. The patch is offered for download as *verified*
(applies, builds and runs) or *applies only*, with how to apply it with `git am`; one that does not
apply cleanly is never offered.

### Self-learning loop

For each component that can be containerized the scan:

1. builds the generated Dockerfile (application folder as context);
2. runs it hardened (read-only root filesystem, all capabilities dropped, no new privileges, non-root,
   only the writable folders mounted) and probes the health endpoint. Writable folders are host
   directories during the test, so apps that log only to files can still be diagnosed. Every host name
   the component's connection strings and configured URLs name (the [connectivity](egress.md#network-connectivity)
   scan; well-known public services in `public_hosts` of `rules/60-security.yaml` excepted) resolves to
   `127.0.0.1` in the run, so a missing database or broker fails fast with *connection refused* instead
   of a DNS lookup that hangs; the run's details list them (`mapped_hosts`), and a run stopped only by
   external services reports what it needs (`needs: sql.corp.example:1433`);
3. matches the log against `rules/50-failures.yaml`:
   - `retry`: patch the build plan (e.g. remove a pinned `global.json`, retarget an out-of-support
     TFM to net10.0, add Kerberos libraries, make a folder writable) and try again;
   - `external`: the container works, it only lacks a database/broker/directory/identity provider —
     then the tool retries in a dependency-free smoke mode (`Development` environment, which many apps
     map to SQLite and simulators) to prove the app actually serves requests. For the smoke run only,
     `appsettings.Development.json` is mounted read-only (the image never contains it), its host names
     resolve to `127.0.0.1` too, relative
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
   ([rule review](rule-review.md)).

While the container runs and its probes are answered, the run samples its memory and CPU (`docker stats`, every
few seconds) and records the peak in the verification result (`usage` in `assessment.json`). The generated
manifests size the component from it: `requests.memory` is the peak × 1.25 and `limits.memory` the peak × 2, both
rounded up to 64Mi, never above the namespace LimitRange's max; the request never below 128Mi and the limit never
below the 512Mi baseline, because a few seconds of probes understate real load (`hardening.measured_memory` in
`rules/60-security.yaml`), with the reason in `plan.json` (*measured 310Mi peak in the verification run*). A
component that was not measured keeps the fixed 256Mi/512Mi, and exceptions such as `native-rendering-memory` only
ever raise the sizes. `containerizer generate --verification DIR` takes the measurement from a folder that
`containerizer verify --out DIR` wrote.

When the build or the run still fails, the rating stays the one the source code gives (a build can fail for a
reason outside the application, such as a package feed the scan cannot reach), but the application's page says it
is not confirmed, the confidence is not counted as confirmed by building and running, and the component is left out
of the generated files and the sandbox. Its **Build and run** column links to *why*: the component's details show
the reason (the failure rule, or *no known cause*) and the end of the build or run log.

![A component whose build failed: the page says the rating is not confirmed and shows the end of the build log](images/results-verify-failed.png#only-light){ .cz-shot }
![A component whose build failed: the page says the rating is not confirmed and shows the end of the build log](images/results-verify-failed-dark.png#only-dark){ .cz-shot }

### AI fallback (Claude or a self-hosted LLM)

The LLM is set once under **Admin → Source control & LLM**
([the LLM](source-control.md#the-llm)): the Claude API, or any self-hosted OpenAI-compatible
server such as Ollama, vLLM, LM Studio or llama.cpp. It is asked only about components the rules are
unsure of and failures no failure rule explains. Every answer is validated against its schema before
it is used or learned, responses are cached, and usage and cost are tracked.

### Light or dark

The web UI follows the system's light or dark setting. The button in the top right corner, next to the sign-in
details, switches between them; the choice is kept in that browser until it is switched again. (It needs no
cookie: the browser's local storage keeps it, and the server never sees it.)

![The top right corner of a results page in light mode, with the light/dark button next to the sign-in details](images/theme-toggle.png#only-light){ .cz-shot }
![The top right corner of a results page in dark mode, with the light/dark button next to the sign-in details](images/theme-toggle-dark.png#only-dark){ .cz-shot }

## Generated output

Per component: `Dockerfile` (+ `Dockerfile.dockerignore`), `k8s.yaml` (Deployment or CronJob,
Service, NetworkPolicy, PVCs where state must persist, ExternalSecrets for every credential),
`plan.json` (the build plan). Linux only: .NET Framework components that are not ported get no
container files (they stay on Windows VMs, see the migration plan). Per app: `kustomization.yaml`
and `MIGRATION.md`.
Java (Maven/Gradle; Spring Boot, Quarkus, plain JVM programs, WARs on Tomcat) and Node.js
(npm/pnpm/yarn; Express, NestJS, Next.js and others) components get distroless, non-root images
built on the runtime line they declare; see [Java and Node.js](java-node.md#containers).
Python (pip, Poetry, uv, Pipenv; Flask, FastAPI, Django and others, on the server they declare) and Go
(static builds on distroless) components too; see [Python and Go](python-go.md#containers).

GitOps: every app also gets `gitops/flux/`, its Flux configuration (Flux is the only GitOps tool):

| | Flux |
| --- | --- |
| Scope | `tenant.yaml`: namespace, ServiceAccount, `admin` RoleBinding in that namespace only; `Kustomization` applies as that ServiceAccount |
| Namespace | created by `tenant.yaml` with the Pod Security "restricted" labels |
| Sync | `GitRepository` (read-only key, optional signed-commit check) or cosign-verified `OCIRepository`; prune, wait |
| Image updates | `ImageRepository`, `ImagePolicy` (digest reflection `Always`), `ImageUpdateAutomation` with `$imagepolicy` name, tag and digest markers in `kustomization.yaml`: deployed as `<image>:<tag>@sha256:...` (an organization scan writes the pushed digest itself) |

Techniques used to avoid application changes:

- out-of-support .NET (Core 2.1, 3.1, 5, 6, 7): build for the framework the project targets, with the .NET 10
  SDK, and run on that framework's own Microsoft runtime image (`mcr.microsoft.com/dotnet/aspnet:6.0` and so on),
  as the app was built and tested; those images are no longer patched. The image runs as the same non-root user
  as the supported ones (uid 1654, `HOME=/home/app`) and listens through `ASPNETCORE_URLS` (before .NET 8,
  `ASPNETCORE_HTTP_PORTS` is ignored). Only when there is no such image (Core 2.2, 3.0) or the app needs OS
  packages (the old images' Debian versions are archived) does it roll forward onto the .NET 10 runtime
  (`DOTNET_ROLL_FORWARD=Major`); if the old target can't be built at all, the build stage's copy of the entry
  project is retargeted to `net10.0` (its netstandard libraries keep their targets). The project itself is never
  retargeted;
- `global.json` SDK pins are removed inside the build stage only;
- Kestrel endpoints from `appsettings.json` are re-pointed with `Kestrel__Endpoints__X__Url`;
- connection strings and secret settings become `ConnectionStrings__X` env vars from a Secret;
- folders the app writes to (logs, App_Data) become volumes;
- the ASP.NET Core Data Protection key folder gets one key, read-only, from a Secret that External Secrets Operator
  generates once in the cluster (Password generator, no secret store): cookies and antiforgery tokens survive
  restarts and work on every replica. That is the default folder under `/home/app` when no code (the component or
  a library it references) persists the keys, or the folder the code reads from configuration for
  `PersistKeysToFileSystem` (`DataProtection:KeyFolder`, re-pointed under `/data`; set when the configuration does
  not). A folder written in the code itself is a persistent volume (ReadWriteOnce, one replica). The lint check
  `dataprotection-volatile` fails a key ring folder setting that points into an `emptyDir`;
- every web component runs one replica: more need shared state first (sessions, caches; the findings say which);
- workers (queue consumers, folder pollers, schedulers, Windows services) are replaced on update (`strategy:
  Recreate`), not rolled, so two copies never run the same job; web components keep `RollingUpdate`. A plan rule
  with `scale_out: true` marks a worker safe to run twice. Pods get a stop grace period per role (web 30 s, worker
  and console 120 s), raised to cover raised IIS request timeouts (`host-long-request-timeout`, at most 600 s).
  CronJobs retry twice, stop a run after an hour, skip a run that could not start within 5 minutes, keep 3
  succeeded and 3 failed Jobs and delete finished ones after a day. All of it is data in
  `rules/60-security.yaml` (`hardening.workloads`), and each decision has its reason in `plan.json`;
- Windows paths in configuration (`D:\\Archive`, `\\\\fs01\\share`) are re-pointed to `/data/...` volumes
  with `Section__Key` env vars; key and certificate files go to `/secrets` from a Kubernetes Secret;
- Serilog file-only sinks are switched to the console (logs to stdout) with `Serilog__WriteTo__N__Name`;
- custom listen-address settings (`"WebhookUrls": "http://*:8085"`) are re-pointed to port 8080;
- NLog folders from `${configsetting:...}` / `${environment:...}` with Windows defaults are re-pointed
  by env var, and `${basedir}/logs` becomes a writable folder;
- installed Windows tools (`C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe`) map to the Linux binary on PATH;
- console tools with sub-commands (usage text, verb arrays, `case "x":`) get one CronJob per command;
- each CronJob gets the schedule and arguments of the repository's Windows Task Scheduler job that starts it
  ([below](#scheduled-tasks));
- workers that use the ASP.NET Core shared framework get the aspnet base image;
- old netstandard1.x packages that break a linux-x64 restore (NU1605) get a portable publish;
- corporate TLS-inspecting proxies: an optional `ca` build secret is honoured.
- code that switches on `Environment.MachineName` gets the pod `hostname:` it compares with; certificates looked up
  in `CurrentUser\My` come from an optional Secret mounted at `~/.dotnet/corefx/cryptography/x509stores/my`;
  `Path.Combine(GetFolderPath(ProgramFiles), "Acme", ...)` (`/app/Acme/...` on Linux) gets a volume there. These
  findings then count as `config` ([Platform fixes for refactor findings](platform-fixes.md)).

### Scheduled tasks

A console tool that the Windows Task Scheduler started gets its schedule and arguments from the repository's own
deploy scripts and exports instead of a placeholder (`containerizer/schedules.py`; which files are read is data in
`rules/20-platform.yaml`, `task_scheduler:`). Three shapes are read:

| Shape | Schedule | Command |
| --- | --- | --- |
| PowerShell (`*.ps1`, `*.psm1`, `*.psd1`) | `New-ScheduledTaskTrigger -Daily` or `-Weekly [-DaysOfWeek ...]`, with `-At HH:mm`; optionally a repetition (`-RepetitionInterval`/`-RepetitionDuration`, or `$t.Repetition = (New-ScheduledTaskTrigger -Once ...).Repetition`) | `New-ScheduledTaskAction -Execute ... -Argument ...`, paired by `Register-ScheduledTask`, also from a table of jobs (`@{ Name = ...; Verb = ...; Trigger = ... }`) registered in a `foreach` |
| `schtasks /create` (in `*.cmd`, `*.bat` or PowerShell, also splatted `schtasks.exe @taskArgs`) | `/sc` (`DAILY`, `WEEKLY`, `MONTHLY`, `MINUTE`, `HOURLY`) with `/st HH:mm [/d MON,TUE] [/mo n] [/ri n /du HH:mm]` | `/tr` |
| Task Scheduler XML export (`*.xml`) | `CalendarTrigger` (`StartBoundary`, `ScheduleByDay`, `ScheduleByWeek`, `ScheduleByMonth`), `Repetition` (`Interval`, `Duration`) | `Exec` (`Command`, `Arguments`) |

Each trigger becomes a cron schedule: weekdays 06:30 is `30 6 * * 1-5`, every 30 minutes from 06:00 for 14 hours
`*/30 6-19 * * *`. A job belongs to the component whose executable or assembly it starts (`Jobs.exe`, `dotnet
Jobs.dll`), and to the CronJob of the sub-command (`commands` fact) or run-once switch (`oneshot_arg`) in its
arguments; the CronJob runs with the job's own arguments. Several triggers of one command become several CronJobs
(`<name>-2`, ...); a tool without sub-commands whose jobs pass different arguments gets one CronJob per argument
(`<name>-<first argument>`). The CronJob says where its schedule came from (a comment and the
`containerizer.io/schedule-source: <file>:<line>` annotation). A CronJob that no job matched keeps the placeholder
`0 2 * * *` and the annotation `containerizer.io/schedule: placeholder`, so a reviewer sees it. Logon and startup
triggers (`-AtLogOn`, `-AtStartup`, `ONLOGON`, `BootTrigger`) never become CronJobs: they are reported ("runs at
logon: a Deployment, or not a server job"). Task Scheduler runs at the server's local time and the schedule keeps
those hours; no `timeZone:` is set, so the CronJob runs in the cluster's time zone (usually UTC) until an
organization time zone setting sets it.

`MIGRATION.md` (section "Windows Task Scheduler jobs") and the application page of the results web UI ("Scheduled
tasks") list every job found, its trigger, its schedule and the CronJob it became, or why it did not become one.

## Security gate

Everything here is data in [`rules/60-security.yaml`](../rules/60-security.yaml).

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
limits, no Data Protection key ring on an `emptyDir` (`dataprotection-volatile`), image tags, NetworkPolicies (warning
on a service port open to every namespace, `namespaceSelector: {}`, unless generated with `--ingress-from any`:
[inbound](egress.md#inbound)), CronJob limits and worker rollouts (warnings: a CronJob without `backoffLimit`,
`activeDeadlineSeconds`, `startingDeadlineSeconds` or history limits; a Deployment without ports that is not
`Recreate`, unless annotated `containerizer.io/scale-out`), and the Dockerfiles for a non-root final stage, tagged base
images, `ADD <url>`/`curl | sh` and base image end of support. Errors fail the gate. A pod annotation
`containerizer.io/waives: "check,check"` relaxes named checks for hand-made exceptions.

The gate favours accuracy over speed: it builds every image, scans it with every available scanner and merges the
results, and starts it with the docker equivalent of its pod spec (user, read-only root, dropped
capabilities, sysctls, `emptyDir` mounts) to prove the exceptions are enough; read-only or permission
errors in the log fail the gate. A lock older than 14 days is refreshed first.

**Vulnerability scan.** Off by default when Containerizer deploys (organization scans, Make it A, platform
migrations): vulnerabilities are outside its aim, and the scans took long. `scan.enabled: true` in
`rules/60-security.yaml` turns them on; `containerizer gate` and `containerizer images --update` scan when they are
run. When on, the gate scans the final base image of every component and the built image;
findings missing from the base are attributed to the application's own packages (upgrade them) rather
than the base (bump it). It fails on vulnerabilities at or above `scan.fail_on` (default `CRITICAL`)
that have a fix; accepted risks go in `scan.allowlist` with a reason and an expiry date. Trivy and
Grype both scan, and their results are merged. When even the newest base tag still ships a vulnerable
OS package with a fix, the gate upgrades just that package in the final stage (`apk upgrade` /
`apt-get --only-upgrade`; chiseled images have no package manager and need a newer tag). Results go to
`SECURITY.md` and `security.json` next to the generated files.

Even when scans are on, vulnerabilities do not keep a component out of the sandbox: Containerizer's aim is the application running in
containers with as few changes as possible, and its developers fix vulnerable packages on the new platform. An
organization scan, a Make it A order or a platform migration deploys the component and reports them in
`SECURITY.md`, which names each package to upgrade and its fixed version. Set `scan.block_deploy: true`
(`rules/60-security.yaml`) to keep such components out instead; `containerizer gate` as a CI check fails on them
either way.

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
  [Secrets (External Secrets)](external-secrets.md).
- **Cluster kit** (`cluster/`, once at the root of an organization scan's output repository for every app; in the
  output folder with `containerizer generate`): an API server audit policy (metadata only for Secrets, full requests and
  responses for RBAC, every write and every exec) and a Kyverno `verifyImages` policy that only admits images signed with your cosign
  key. These are for the cluster operator to apply. The report also lists the cluster controls the
  generator can't set, such as etcd encryption, kubelet authentication and control plane TLS.
- **GitOps**: the quota, LimitRange and default-deny policy move into the platform-owned `flux/tenant.yaml`. The synced Kustomization
  deletes them from its set with `$patch: delete` and doesn't `force`, so the app repository can't
  loosen them under the tenant's impersonated ServiceAccount.

**Patched base images.** `rules/images.yaml` lists the base image lines and
`rules/images.lock.yaml` the newest patch tag of each line that passed the vulnerability policy, with
its digest; the generator uses the exact tag. The bump policy is per image: patch releases of the same
line by default, newer stable lines for nginx, and the successor line for toolchains past end of
support (node, golang). .NET majors are never moved automatically. A lock older than 14 days is
refreshed before the gate runs.

## Results on the challenge

See [`bench/RESULTS.md`](../bench/RESULTS.md) for the current numbers (rule accuracy, verification
results and the model comparison). The labels used for scoring are in
[`bench/labels.yaml`](../bench/labels.yaml), written from each scenario's README and code.
