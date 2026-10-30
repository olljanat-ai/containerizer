# containerizer

A tool that tells you whether an application can run as a Linux container on Kubernetes, explains why,
and generates hardened container builds and Kubernetes manifests for the parts that can. It was built
for the [onek8s containerization challenge](https://github.com/onek8s/containerization-challenge)
(33 Windows-era .NET business applications, about half of them purposely hard or impossible to
containerize) and for real-life portfolios.

Design principles:

- **Rules first, AI last.** Classification is done by a data-driven rule set (`rules/*.yaml`). Claude
  is consulted only for components the rules are unsure about, and what it says is validated before
  it is used or learned.
- **Learns by doing.** When unsure, the tool builds and runs the generated container, matches failures
  against failure rules, patches the build plan and retries. Fixes that work are written back as
  rules (`rules/learned/`), so the next run needs no retries and no AI.
- **No application changes.** Dockerfiles use the application folder as build context with their own
  `Dockerfile.dockerignore`; configuration is overridden with environment variables and volumes.
- **Secure by default.** Multi-stage builds, chiseled (distroless) .NET images, non-root user,
  read-only application files, read-only root filesystem, all capabilities dropped, seccomp,
  secrets only as Kubernetes Secret references, base images pinned to a version line.

## Quick start

```bash
pip install -r requirements.txt            # PyYAML; `anthropic` optional for the API backend

# the recommended one-shot run per repository: assess, build and run every feasible component,
# learn from failures, re-assess with what was learned, write reports + Dockerfiles + manifests
python -m containerizer analyze <repo> --out out/            # add --ai --model claude-sonnet-5-5 for Claude review

# assess: one app, or a folder with scenarios/
python -m containerizer assess ../containerization-challenge -v
python -m containerizer assess ../containerization-challenge --out reports/   # md + html + json

# generate Dockerfiles, Kubernetes manifests and MIGRATION.md
python -m containerizer generate ../containerization-challenge/scenarios/parts-catalog --out out/
python -m containerizer generate <app> --out out/ --pin-digests --registry myregistry.example.com   # immutable base images

# build + run the generated containers, learn from failures
python -m containerizer verify ../containerization-challenge/scenarios/parts-catalog --learn

# ask Claude about the components the rules are unsure of
python -m containerizer assess ../containerization-challenge/scenarios/document-control --ai --model claude-sonnet-5-5

# security gate: lint the manifests, build + scan the images (Trivy and Grype), run them hardened,
# fail on fixable CRITICAL CVEs (--no-build: scan only the base images)
python -m containerizer gate ../containerization-challenge/scenarios/parts-catalog --out out/
python -m containerizer images --update        # pick patched base image tags -> rules/images.lock.yaml

# measure against the hand-made labels
python -m containerizer bench
python -m containerizer bench --technique hybrid --model claude-haiku-5-5
```

## How it works

```
 scan ──► roles ──► facts ──► findings ──► reachability ──► confidence ──► rating
  │        rules     rules     rules        (type graph)      unknowns         │
  │                                                              │ low          ▼
  │                                                     verify (build+run) ──► report / generate
  │                                                              │ unexplained
  │                                                     Claude (validated) ──► rules/learned/
```

1. **Scan** (`containerizer/scan.py`) reads project files (.csproj/.vbproj incl. old-style and imported
   `.props`, package.json, requirements.txt/pyproject, go.mod, pom.xml/gradle, BizTalk/SQL/SSIS
   projects), source and configuration. Nothing from the scanned repository is executed.
2. **Role rules** (`rules/00-roles.yaml`) decide what each project is: web, worker, console, spa,
   desktop, library, test, tool, BizTalk, SharePoint, SQL CLR, SSIS.
3. **Fact rules** (`rules/05-facts.yaml`) extract ports, health endpoints, run-once arguments,
   connection strings, folders the app writes to, Kestrel endpoints.
4. **Finding rules** (`rules/10-runtime.yaml`, `20-platform.yaml`, `30-integration.yaml`) detect
   blockers and work items with a severity:
   `info < config < refactor < rewrite < blocker`, an effort estimate, an explanation, a fix, and
   whether a Windows container would be a workable stop-gap.
5. **Reachability**: findings in shared libraries only count for components whose code actually
   reaches the offending types (a type/extension-method mention graph), and Windows-only calls
   guarded by `OperatingSystem.IsWindows()` are ignored.
6. **Confidence**: packages and references unknown to `rules/packages*.yaml`, and uncertain rules,
   lower a component's confidence. Low confidence triggers verification and, optionally, Claude.
7. **Rating** per application: **A** lift and shift, **B** minor refactoring, **C** framework port,
   **D** partial (some components must stay on Windows), **E** not feasible.

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
do, and `refs` link to the documentation or upstream issue behind it. All three are shown in the
migration report, the HTML portfolio, the PR comment and SARIF (`help`, `helpUri`). Findings
observed at run time carry the explanation and links of the failure rule that recognised them, and
every non-default build decision (a plan rule, a config override, a fix learned while verifying) is
listed with its reason and links at the top of the generated `Dockerfile` and in `plan.json`.

Condition primitives: `sdk`, `tfm`, `package`, `reference`, `framework_ref`, `property`,
`output_type`, `kind`, `role`, `name`, `file` (glob), `code` / `config` / `text` (regex with optional
`in:` glob and `unguarded: true`), `readme`, combined with `any` / `all` / `not`.
`unguarded: true` skips hits right after an `OperatingSystem.IsWindows()` check or inside a method/type
marked `[SupportedOSPlatform("windows")]`. `same_file: true` next to an `all` requires its
`code`/`config`/`text` conditions to match in the same file (e.g. an assembly loader *and* an install
path probe, not two unrelated files).
Later files override earlier rules with the same id; `rules/learned/` is loaded last.

### Self-learning loop (`verify --learn`)

For each component that can be containerized the tool:

1. builds the generated Dockerfile (`docker build`, application folder as context);
2. runs it hardened (`--read-only --cap-drop ALL --security-opt no-new-privileges`, non-root, only
   the writable folders mounted) and probes the health endpoint. Writable folders are host
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
4. if nothing matches and `--ai` is on, Claude proposes a diagnosis, a regex and a plan patch; it is
   applied only if the regex matches the log and the patch uses whitelisted plan keys;
5. persists what worked: plan patches → `rules/learned/plan.yaml`, confirmed AI failure rules →
   `rules/learned/failures.yaml`, runtime findings → `rules/learned/findings.yaml`, and packages of
   components that ran → `rules/learned/packages.yaml` (raising confidence next time).

### Claude fallback

`containerizer/ai.py` has two backends: the Anthropic Python SDK with structured outputs
(`CONTAINERIZER_AI_BACKEND=api`, needs credentials) and the `claude` CLI in print mode
(`CONTAINERIZER_AI_BACKEND=cli`). The model is configurable with `--model` or `CONTAINERIZER_MODEL`
(default `claude-opus-5-5`). Responses are cached in `.work/ai-cache/`, usage and cost are tracked.

Three AI techniques can be compared with `bench --technique`:

| Technique | What Claude sees | What decides |
| --- | --- | --- |
| `rules` | nothing | rules only |
| `hybrid` | evidence pack (findings, code snippets, Program.cs, README) for low-confidence components | rules, overridden by Claude where confident |
| `ai-only` | project inventory + README | Claude only |
| `ai+rules` | inventory + README + rule verdicts | Claude, informed by the rules |

## Generated output

Per component: `Dockerfile` (+ `Dockerfile.dockerignore`), `k8s.yaml` (Deployment or CronJob,
Service, NetworkPolicy, Secret skeleton, PVCs where state must persist), `plan.json` (the build
plan, editable and re-usable). For .NET Framework components that could work in Windows Server
containers, a `Dockerfile.windows` stop-gap. Per app: `kustomization.yaml` and `MIGRATION.md`.

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

**Lint.** `gate` checks the manifests against Pod Security `restricted` (host namespaces, privileged,
capabilities, volume types, host ports, privilege escalation, non-root, seccomp, sysctls) plus read-only
root FS, resources, secret literals (in env, `ENV` and Secrets), the service account token, `emptyDir`
limits, image tags and NetworkPolicies, and the Dockerfiles for a non-root final stage, tagged base
images, `ADD <url>`/`curl | sh` and base image end of support. Errors fail the gate. A pod annotation
`containerizer.io/waives: "check,check"` relaxes named checks for hand-made exceptions.

The tool is meant to be run once or a few times per repository, so `gate` favours accuracy over
speed: by default it builds every image, scans it with every available scanner and merges the
results, and starts it with the docker equivalent of its pod spec (user, read-only root, dropped
capabilities, sysctls, `emptyDir` mounts) to prove the exceptions are enough; read-only or permission
errors in the log fail the gate. A lock older than 14 days is refreshed first.

**Vulnerability scan.** `gate` scans the final base image of every component and the built image; findings missing from the base are attributed to the application's
own packages (upgrade them) rather than the base (bump it). It fails on vulnerabilities at or above
`scan.fail_on` (default `CRITICAL`, `--fail-on HIGH` to tighten) that have a fix; accepted risks go in
`scan.allowlist` with a reason and an expiry date. Trivy is used if installed, then Grype, then either
one as a container (`aquasec/trivy`, `anchore/grype`); `scan.default_scanner: all` uses all of them. When even the newest base tag still ships a
vulnerable OS package with a fix, the gate upgrades just that package in the final stage (`apk upgrade`
/ `apt-get --only-upgrade`; chiseled images have no package manager and need a newer tag). Results go
to `SECURITY.md` and `security.json` next to the generated files.

**Patched base images.** `images --update` lists the registry tags of every line in `images.yaml`,
scans the newest patch tags and writes the first one that passes the policy to
`rules/images.lock.yaml` with its digest; the generator then uses the exact tag (and
`--pin-digests` the locked digest). The bump policy is per image: patch releases of the same line by
default, newer stable lines for nginx, and the successor line for toolchains past end of support (node,
golang). .NET majors are never moved automatically. `images` alone shows each line and its end of
support. `CONTAINERIZER_IMAGES_LOCK=0` ignores the lock; the gate warns when it is older than 14 days.

## CI/CD gate

`check` compares the current tree with a base branch (or a saved baseline) and fails when a change makes
an application harder to containerize: a new finding of severity `rewrite` or worse (Windows-only APIs,
COM, Office automation, WCF server, ...), or a worse rating. It also writes the PR comment, SARIF 2.1.0
and inline annotations. The base is read with `git archive`, so the working tree is never touched, and
findings in library code the app never reaches don't count.

```bash
python -m containerizer check src/ --base-ref origin/main --markdown comment.md --sarif out.sarif
python -m containerizer check src/ --save-baseline baseline.json          # later: --baseline baseline.json
python -m containerizer check src/ --max-rating B --fail-on blocker      # absolute limit, no base needed
```

Exit code 0 = pass, 1 = gate failed, anything else = error. Options: `--fail-on none|config|refactor|rewrite|blocker`,
`--allow-rating-drop`, `--max-rating A-E`, `--annotations github|azure`, `--json`, `--link <blob URL prefix>`.

### GitHub Actions

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write          # for the PR comment
jobs:
  containerizer:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: olljanat-ai/containerizer@main
        with:
          path: src              # app folder(s), space separated
          fail-on: rewrite       # default
          # max-rating: C        # optional absolute limit
          # upload-sarif: true   # code scanning (needs security-events: write)
```

On pull requests the action compares with the PR's base commit (fetched if the checkout is shallow), posts
one comment that it keeps updating, writes the job summary, annotates the offending lines, and fails the
job when the gate fails. Outputs: `rating`, `failed`, `new-findings`, `markdown-file`, `sarif-file`.
This repository dogfoods it in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) on
[`examples/ci-demo`](examples/ci-demo) and self-tests it on a challenge app with a Windows-only change.

### Azure DevOps

[`ci/azure/containerizer-steps.yml`](ci/azure/containerizer-steps.yml) is a steps template. Copy it into
your repository (or reference it through a repository resource):

```yaml
trigger: none
pr: [main]
pool:
  vmImage: ubuntu-latest
steps:
  - checkout: self
    fetchDepth: 0
  - template: ci/azure/containerizer-steps.yml
    parameters:
      path: src
      failOn: rewrite
```

It compares with the PR target branch, adds the report to the build summary, annotates the offending
files, publishes SARIF as the `CodeAnalysisLogs` artifact (shown by the SARIF SAST Scans Tab
extension), comments on Azure Repos pull requests with `System.AccessToken` (give the build service
"Contribute to pull requests"), and fails the build when the gate fails.

## Results on the challenge

See [`bench/RESULTS.md`](bench/RESULTS.md) for the current numbers (rule accuracy, verification
results and the model comparison). The labels used for scoring are in
[`bench/labels.yaml`](bench/labels.yaml), written from each scenario's README and code.

## Layout

```
containerizer/   scan, rules engine, assess, reach, confidence, facts, generate, harden, imagescan, verify, ai, report, bench
rules/           curated rules (roles, facts, findings, plan, failures, security, images + images.lock, packages)
rules/learned/   rules written by the learning loop (reviewable, safe to delete)
bench/           labels and results
action.yml       GitHub Action; ci/azure/ has the Azure DevOps template
```
