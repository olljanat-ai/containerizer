# Source control tokens and the LLM

Organization scans ([scheduled-scans.md](scheduled-scans.md)) read Azure DevOps, GitHub and GitLab
organizations and push the generated files to an output Git repository. The tokens for both are
registered by administrators under **Admin → Source control & LLM**, together with the LLM the scans
ask (see [The LLM](#the-llm) below):

- **Organizations (read-only)**: one token for each Azure DevOps organization (or Azure DevOps Server
  collection), GitHub organization or GitLab group the scans may read, on the cloud service or a
  self-hosted server. **This is the allow-list**: a scan of an organization without a registered,
  enabled token does not run, and nothing is ever read anonymously.
- **Output repositories (write)**: one token for each repository the generated Dockerfiles, manifests
  and GitOps files are pushed to, matched by the repository's URL. The internal rules repository of
  the [rule review](rule-review.md#setting-up-the-internal-rules-repository) gets its write token here
  too.
- **Package feeds**: a token for each NuGet, npm or Maven/Gradle feed that needs a sign-in, which the builds of
  scanned code restore packages from ([below](#package-feeds)). The builds never see it.

## How the tokens are protected

- **Sealed for the worker.** The moment a token is saved, the web UI seals it for the scan worker's
  public key (X25519 key agreement, HKDF-SHA256, AES-256-GCM). The web UI has only the public key, so
  it cannot open what it stored; only the worker, with the private key, opens a token, just before a
  run. The sealed token is bound to its purpose, provider, server and organization or repository: it
  does not open if it is moved to another row or another purpose in the database.
- **Never shown again.** The page has a password field to enter a token and a button to replace it,
  nothing that shows it. The admin database role may write the sealed token but is not granted
  `SELECT` on it.
- **Audited, without the token.** Adding, replacing (*Token saved* changes), enabling, disabling and
  removing a token are in the change history with who did it. The token itself is never copied there.
- **Only sent where it belongs.**
  - The read-only token goes to its own server's API, and with the clone URLs of its own organization
    only (`https://github.com/<org>/…`, `https://gitlab.com/<group>/…`, `https://dev.azure.com/<org>/…`
    or `https://<org>.visualstudio.com/…`, or the self-hosted server's equivalent). A repository whose
    clone URL is elsewhere is refused. An API redirect or pagination link to another host does not get
    the token, and https is never followed down to http.
  - The write token is chosen by the output repository's URL, never by host or organization, and is only
    used to clone and push that repository. The output repository can therefore be in a scanned
    organization: it is never scanned itself, and the read-only token is never used to push.
  - Git gets each token as an `http.<repository URL>.extraHeader` in its environment, so it is valid for
    that one repository URL only, is not written to disk or the process list, and no credential helper
    sees it. Errors and logs are redacted.
- **Least privilege is checked where the provider allows it.** The worker records on the page when a
  token last worked, and warns when a GitHub classic token has scopes that can write or a GitLab token
  has more than `read_api` / `read_repository`. Registering the same token as both an organization's
  read-only token and its output repository's write token is refused.
- **Admins only.** The Source control page is for administrators; operators can schedule scans, but
  only of organizations an administrator registered.

## The sealing key

The appliance makes the key pair at first boot: `/etc/containerizer/secrets/credential-key` for the
worker and `credential-key.pub` for the web UI. Back up `credential-key` with the database: the
registered tokens open only with it. A new key pair means entering every token again (the page marks
tokens sealed for another key). Also allow each Git server's host on **Admin → Firewall**.

## Making the tokens

Give every token an expiration date and enter the same date on the page: it warns 14 days before, and
an expired token stops its scans with a clear message. Revoke a token where it was made when you
replace or remove it here.

### Read-only token for an organization

| Provider | Token | Permissions | Server (self-hosted) |
| --- | --- | --- | --- |
| GitHub | [Fine-grained personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token): resource owner the organization, repository access *All repositories* | **Contents: Read-only** and **Metadata: Read-only**, nothing else | `https://ghe.example.com/api/v3` |
| GitLab | [Group access token](https://docs.gitlab.com/user/group/settings/group_access_tokens/) on the group, role **Reporter** (on GitLab.com group tokens need Premium or Ultimate; otherwise a [personal access token](https://docs.gitlab.com/user/profile/personal_access_tokens/) of a Reporter in the group) | scopes **read_api** and **read_repository** | `https://gitlab.example.com` |
| Azure DevOps | [Personal access token](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate) for **this organization only** | Custom defined: **Code: Read** and **Project and Team: Read** ([scopes](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth#scopes)) | `https://tfs.example.com/tfs`, the collection as the organization |

Notes:

- GitHub organizations can require approval of fine-grained tokens, or forbid them
  ([token policy](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)).
  A classic token needs the `repo` scope for private repositories, which can also write: avoid it.
- GitLab: the organization is the group path; subgroups are included (`acme` covers `acme/platform/*`),
  or register a subgroup alone (`acme/platform`).
- Azure DevOps is retiring PATs for *All accessible organizations*: make one per organization. Use a
  dedicated account that can read the repositories but not change them.

### Write token for an output repository

| Provider | Token | Permissions |
| --- | --- | --- |
| GitHub | A separate fine-grained personal access token with repository access *Only select repositories*: the output repository alone | **Contents: Read and write** |
| GitLab | [Project access token](https://docs.gitlab.com/user/project/settings/project_access_tokens/) on the output project, role **Developer** (Maintainer if Developers may not push to the branch) | scopes **read_repository** and **write_repository** |
| Azure DevOps | Personal access token of a dedicated account whose only **Contribute** permission is on the output repository ([repository permissions](https://learn.microsoft.com/en-us/azure/devops/repos/git/set-git-repository-permissions)) | **Code: Read & write** |

Enter the repository's https URL exactly as on the scan's *Output repository* (with or without `.git`).

## Package feeds

Applications that restore packages from a private feed (an internal NuGet feed on Azure Artifacts, npm packages
on GitHub Packages, a Maven repository on Nexus) do not build without its credentials, and verification then
reports *Build failed*. Register the feed under **Admin → Source control & LLM → Package feeds**: its kind (NuGet,
npm, Maven or Gradle), its URL, a user name if the feed wants one, and a read-only token.

![Package feeds on Admin → Source control: three feeds with their state, and the form to add one](images/admin-package-feeds.png#only-light){ .cz-shot }
![Package feeds on Admin → Source control: three feeds with their state, and the form to add one](images/admin-package-feeds-dark.png#only-dark){ .cz-shot }

The token never enters a build, an image or the generated files. The scan worker (and the LLM queue runner, for
refactoring orders) runs a small HTTPS proxy, the **feed proxy**, and hands its builds its address as `HTTPS_PROXY`,
which dotnet, npm, Maven and Gradle use (the generated Dockerfiles pass a proxy on to Maven and Gradle themselves):

- A connection to the host of a registered feed is opened by the proxy: it answers with a certificate of its own CA,
  checks the feed's real certificate itself, and adds `Authorization` to the requests whose URL is under the feed's
  URL: `Basic` with the user name and the token, or `Bearer` with the token alone when the user name is empty.
  Requests to other paths of that host get nothing. The builds trust the proxy's CA through the optional build
  secret `ca` the generated Dockerfiles already read for TLS-inspecting corporate proxies (the bundle holds the
  system's CAs, the corporate bundle if one is set, and the proxy's CA).
- Connections to every other host pass through untouched (a plain tunnel).
- The proxy refuses this machine's own addresses, loopback and link-local addresses, and the networks of Docker
  and the sandbox cluster, so it opens nothing to a build that the build could not reach itself. On the appliance
  the [firewall](appliance-admin.md#firewall) lets Docker's bridges reach the proxies' ports (3128 for the scan
  worker, 3129 for the LLM queue runner, on the DNS filter's address) and nothing else on the host, and the feed's
  host must be on the Firewall page as before. Elsewhere it listens on `docker0`'s address
  (`CONTAINERIZER_FEED_PROXY_LISTEN=host:port` to choose); a corporate `HTTPS_PROXY` of the worker is used upstream.

Which URL to register: the token goes with every request under it, so register the narrowest URL that still covers
the downloads. Azure Artifacts downloads packages by the feed's id rather than its name, so register the
organization's packaging URL, e.g. `https://pkgs.dev.azure.com/contoso/` (or `https://pkgs.dev.azure.com/contoso/project/`
for a project-scoped feed). The repository's own `nuget.config`, `.npmrc`, `pom.xml` or `build.gradle` still names
the feed as before; a credentials entry it has (for example `%NUGET_PAT%`) is replaced by the proxy's.

| Feed | Token | User name |
| --- | --- | --- |
| Azure Artifacts | Personal access token with **Packaging: Read**, for this organization | any text, e.g. `containerizer` |
| GitHub Packages | Personal access token (classic) with **read:packages** | the token's account (npm: empty) |
| GitLab package registry | Deploy token or group access token with **read_package_registry** | the deploy token's user name |
| Nexus, Artifactory, ProGet | A read-only user's password or token | the user |

The page shows when a feed was last used and whether the feed accepted the token (*Working*, or *Last use failed*
with the HTTP status). Yarn 2 and later (`.yarnrc.yml`) and the Maven wrapper's own download of Maven do not use
`HTTPS_PROXY`: their feeds are not covered.

### NuGet source names

A NuGet.Config with [package source mapping](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)
maps packages to a source by its name (`<packageSource key="Contoso">`). Often the repository does not define that
source: the developers and build agents have it in their own user or machine NuGet.Config, under whatever name the
project chose, so one feed may be `internal` in one repository and `Contoso` in another. A container build has none
of those files, and restore cannot find the mapped packages (`NU1100 ... PackageSourceMapping is enabled`).

Give a NuGet feed the names projects use for it in **NuGet source names**, one source per line:

```text
internal, Contoso, AzureArtifacts = https://pkgs.dev.azure.com/contoso/_packaging/main/nuget/v3/index.json
ContosoLegacy = https://pkgs.dev.azure.com/contoso/_packaging/legacy/nuget/v3/index.json
```

The URL is the source's own (`index.json` for v3), and must be under the feed's URL so the proxy signs its requests;
a line of names alone means the feed's URL itself. A name belongs to one feed only (names compare case-insensitively,
as NuGet's do).

For each .NET component the scan reads the NuGet.Config files of the project's folder and the folders above it, up to
the repository's root. A mapped name no `<packageSources>` defines gets the source registered under that name: the
generated Dockerfile adds it before restore (`dotnet nuget add source ... --configfile`, into the config nearest to
the project; the URL only, never a token), and MIGRATION.md lists it under *NuGet package sources*, so the real
build pipeline gets it too, or you add it to the repository's NuGet.Config and the step goes. `nuget.org` needs no
registration: it is added with its own URL when the repository's `<clear/>` removed it. MIGRATION.md also lists:

- a mapped name no registered feed has: restore cannot find its packages until a feed gets the name or the
  repository defines the source;
- a name whose URL is already a source of the repository under another name: NuGet uses a URL once (the first
  name wins), so it is not added, and its packages must be mapped to the other name.

## The LLM

Scans with **Ask the LLM** on consult an LLM about the components the rules are unsure of and the
build or run failures no failure rule explains. Scans with **LLM-heavy mode** also let it translate,
review and fix [platform migrations](platform-migration.md#llm-heavy-mode); every call is counted on the
Grafana dashboard. Set it once on the same page:

| Kind | Server | Model | API key |
| --- | --- | --- | --- |
| Claude API | empty, or the https URL of a gateway in front of it | e.g. `claude-sonnet-5-5` | required: a key from the Claude Console, in a workspace only for Containerizer, with a spend limit |
| OpenAI-compatible server (Ollama, vLLM, LM Studio, llama.cpp `llama-server`, LocalAI, TGI, ...) | the URL up to and including `/v1` | the name the server knows | optional; only sent over https, or plain http to the appliance itself |

The key is sealed for the worker like the tokens and never shown again; the model can be changed
without re-entering it, while a different server means removing it and adding it again. The worker
hands the setting to the AI code for the run only, never through its environment, so the git and
docker processes a scan starts never see the key. Allow the server's host on **Admin → Firewall**.

**Several LLMs at once.** More than one LLM can be registered: a GPU server, a CPU server, the Claude API.
Each one has an **Order**, **Jobs up to** (the biggest LLM call it takes, in estimated input tokens; 0: any
size) and **Requests at once**. The [LLM queue](#queued-llm-reviews) gives each LLM call of a job to the first LLM
in the order that takes the call's size and has a free request, and they all answer at the same time: put the
small, cheap servers first with a size limit and a big one last with any size. A review, an egress or a link
review is one call, so the limit is the job's size; a refactoring order makes one call per file (and per repair
round), each of its own size, which may go to different LLMs. A job whose estimated size no LLM takes waits (the
LLM queue page warns about it). On the appliance the built-in LLM can join the list too (LLM queue → Settings: its
order and the biggest call it takes), with one request per server it runs. Scans that ask the LLM directly,
outside the queue, use the first LLM in the order. Two LLMs on the same server need different hosts (one
registration per server). See [how jobs and LLM requests are scheduled](#how-jobs-and-llm-requests-are-scheduled).

| Example | Order | Jobs up to | At once |
| --- | --- | --- | --- |
| Built-in LLM (CPU, two NUMA nodes) | 10 | 4,000 tokens | 2 (its servers) |
| A CPU server with a bigger model | 20 | 15,000 tokens | 1 |
| A GPU server | 30 | any size | 4 |

![The LLM queue's LLMs in order: the built-in LLM for jobs up to 4,000 tokens, a CPU server up to 15,000, a GPU server for any size](images/admin-llm-queue-llms.png#only-light){ .cz-shot }
![The LLM queue's LLMs in order: the built-in LLM for jobs up to 4,000 tokens, a CPU server up to 15,000, a GPU server for any size](images/admin-llm-queue-llms-dark.png#only-dark){ .cz-shot }

**The appliance's built-in LLM.** Without an LLM server of your own, the appliance can run one on its
CPU: Qwen3-Coder 30B-A3B with llama.cpp, turned on under **Admin → Source control & LLM** (off by
default; it needs a machine with at least 40 GB of memory, see
[Running the appliance](appliance-admin.md#built-in-llm)). Scans with **Ask the LLM** use it when no LLM is
set on that page; an LLM set there is used instead, unless the built-in LLM has a place in the LLM queue's order
(see *Several LLMs at once* above). Expect about 7 to 12 tokens per second and a few
minutes per answer: fine for the components the rules are unsure of, too slow for LLM-heavy mode. Use the
queued LLM mode for organization scans where it is offered, so the scans do not wait for each answer.

**Choosing a model.** The quality of the fallback follows the quality of the model. With a self-hosted
server, use the largest instruction-tuned model your hardware serves comfortably, ideally one that
knows .NET well (a 30B+ Qwen, Llama, Mistral or DeepSeek model). Smaller models propose more wrong
regexes; the scan keeps only ones that compile, do not match trivial code and fire on the code they
were learned from, and an administrator still reviews every learned rule ([rule review](rule-review.md)).

**How answers are kept reliable.**

- The rules stay first: the LLM never decides alone what the rules are sure of.
- Every request carries the JSON schema of the answer, as `response_format` (which Ollama, vLLM, LM
  Studio and llama.cpp enforce with constrained decoding) and in the prompt. A server that refuses
  `json_schema` gets `json_object`, then plain text.
- Every answer is checked against the schema. An invalid answer is retried once with the errors
  listed; a second one is an error, and the component keeps the rules' verdict. `<think>` blocks of
  reasoning models are ignored.
- A self-hosted server that is restarting or still loading its model (connection refused or reset,
  HTTP 429, 502, 503 or 504) is retried with growing waits, for up to 10 minutes in all
  (`CONTAINERIZER_LLM_RETRY_SECONDS`), so a restart does not cost the scan its answers. Timeouts and
  other errors are not retried: the component keeps the rules' verdict.
- Requests use `temperature: 0` and answers are cached by prompt, model and server, so runs repeat.
- The LLM never runs commands or edits the application: it returns JSON, and build-plan patches are
  limited to an allow-list of plan keys. What it proposes is recorded with `source: ai` and the model.

**What it sees.** Evidence packs contain source code excerpts, project files and the README of the
assessed application. A self-hosted server keeps them inside your network.

### Queued LLM reviews

A self-hosted LLM on CPUs can take five minutes or more per answer, which would hold up every scan. Set
**LLM reviews** on the scan (Admin → Organization scans) to **Queued** and the scan asks the LLM nothing
while it runs: the rules decide, and the questions go to the **LLM queue** instead
(Admin → LLM queue, [organization scans](scheduled-scans.md#the-llm-queue)). The queue runner answers
them when the queue's settings let it, for example at night or only while no scan runs.

![The LLM queue: totals with token and time estimates learned from earlier answers, then the jobs in order](images/admin-llm-queue.png#only-light){ .cz-shot }
![The LLM queue: totals with token and time estimates learned from earlier answers, then the jobs in order](images/admin-llm-queue-dark.png#only-dark){ .cz-shot }

In queued mode the scan does not ask the LLM about build or run failures, dev databases, platform
migrations or the sandbox tester either, so **LLM-heavy mode** needs inline reviews.

#### LLM-heavy for a while

When one application, or one of its components, needs the LLM's full attention for a while (a migration being
worked on, a component the rules keep getting wrong), an administrator turns **LLM-heavy mode** on for it on
its page (**Admin → Applications** → the application → **LLM-heavy mode**): the whole application or one
component, for 1 hour to 7 days.

![LLM-heavy mode on an application's page: the window open now, with End now, and the form for another](images/admin-app-llm-heavy.png#only-light){ .cz-shot }
![LLM-heavy mode on an application's page: the window open now, with End now, and the form for another](images/admin-app-llm-heavy-dark.png#only-dark){ .cz-shot }

Until it ends:

- its LLM jobs of every kind need no approval: those waiting are approved at once, new ones are queued
  approved (*automatic: LLM-heavy until …*);
- they go before every other job in the queue, whatever their priority or position;
- scans with queued LLM reviews queue a review of **every** component it covers, not only the uncertain ones and
  the second opinions (reason *LLM-heavy*; the answer changes a verdict when the LLM is at least 0.85 sure, as
  for a second opinion);
- scans run LLM-heavy mode for it (platform migrations and the sandbox tester ask the LLM as often as they need,
  even in a scan with queued reviews) when the appliance allows LLM-heavy mode (`CZ_LLM_HEAVY=true`) and the scan
  has **Ask the LLM** on. These calls are made during the scan, as for a scan in LLM-heavy mode.

- a [Make it A](refactoring.md#make-it-a) order of the whole application keeps going, one order after another,
  until its patched copy runs in the sandbox or the window ends;
- a [refactoring order](refactoring.md#llm-heavy-refactoring-orders) of chosen findings (of the whole application,
  or of the component the window is on) makes up to 40 LLM calls instead of 8 and keeps going, with repairs and the
  findings left, until every finding is fixed and the patched copy builds and runs, or the window ends.

**Scan its repository now** (ticked by default) starts a scan of its repository at once, so the reviews are
queued without waiting for the schedule. The windows open now are listed on the application's page and on the
LLM queue page (**LLM-heavy now**), each with **End now**; their jobs then take their usual place again.
Turning a window on or ending it is in the audit log.

![The LLM queue with two LLM-heavy windows: their jobs first, each marked LLM-heavy until its end](images/admin-llm-queue-heavy.png#only-light){ .cz-shot }
![The LLM queue with two LLM-heavy windows: their jobs first, each marked LLM-heavy until its end](images/admin-llm-queue-heavy-dark.png#only-dark){ .cz-shot }

Each job's page shows the question sent, the answer with its reasoning per finding, and the actual tokens
and time against the estimate:

![An answered job: the LLM's verdict and reasoning, actual tokens and time against the estimate](images/admin-llm-queue-job.png#only-light){ .cz-shot }
![An answered job: the LLM's verdict and reasoning, actual tokens and time against the estimate](images/admin-llm-queue-job-dark.png#only-dark){ .cz-shot }

**What is queued.** The components an inline scan would ask about (server and platform components the
rules are less than 85 % sure of) are queued as *uncertain*. Server and platform components the rules
rate *blocker* or *rewrite* with confidence are queued too, as a *second opinion*. Each gets a
priority; the runner takes the highest first, and administrators can move any job:

| | Priority |
| --- | --- |
| Uncertain | 1000 + 400 × (1 − the rules' confidence) |
| Second opinion | 0 + 400 × (1 − the rules' confidence) |
| Both: the component keeps no state and only its verdict keeps it from rating A | + 300 |
| Both: a server component (not a Windows platform product) | + 100 |

So every uncertain review comes before every second opinion, the less sure the rules the sooner, and
a review whose answer can get a component deployed comes first.

**How an answer takes effect.** The queue keeps the exact question the scan would have asked. The
runner asks it with the same model, so the answer is stored in the answer cache under the same key as
an inline answer. The answer shows on the queue page at once, and on the component in the results
pages. The next scan of the repository asks the same question, finds the answer (in the cache, or in
the queue) without calling the LLM, and applies it as an inline scan would: the component's verdict
changes when the LLM is at least 0.6 sure and disagrees with the rules (0.85 for a second opinion, as it
goes against rules that were sure). Assessments already stored never change. **Re-scan now** on the queue
page scans a repository whose reviews are all answered, without waiting for the schedule. When the
code or the rules change before the answer, the next scan asks a new question and the old one is
skipped as superseded. Changing the LLM (another server or model) means new questions too.

The command line does the same with `--ai-queue` (with `--ai`, on `assess`, `analyze` and `org`): with
`--sql` or `CONTAINERIZER_SQL` the jobs go to the same queue; without SQL Server they are written to
`llm-queue.json` in the output folder (`--work-dir` for `org`), and
`containerizer llm-queue --file <that file>` answers them once each, in queue order. Run the command
again afterwards to apply the answers.

**Kinds of jobs.** The queue holds every kind of LLM job; the page filters by kind:

| Kind | Queued by | Priority | Result |
| --- | --- | --- | --- |
| Component review (`review`) | a scan with queued LLM reviews | as above | the LLM's verdict, applied by the next scan |
| Refactoring (`refactor`) | a person, on a B-rated application's results page, or `containerizer refactor --queue` | 1800: before the automatic reviews (move it like any job) | a [refactoring patch](refactoring.md), verified by building and running it |
| Make it A (`refactor`, goal `rating-a`) | a person, on a B-rated application's results page, or an administrator for every B app (**Make it A: every B application**, smallest first) | 1800, as a refactoring | one patch for every finding, repaired and assessed again in a loop; a [sandbox variant](refactoring.md#the-sandbox-variant) when the patched copy rates A |

A refactoring asks the LLM once per file it changes (at most 8), so it is a long job; its estimate is
made from the size of what it will send, and the output tokens are learned per kind like the reviews'.
While it runs, the queue page says how far it is (generating, verifying, deploying; for Make it A also the
pass and the repair round), and the job links to its patch page (Admin → Refactoring). A Make it A order
makes up to 16 LLM calls.

#### How jobs and LLM requests are scheduled

The queue holds LLM work and other work side by side: a refactoring order spends most of its time building,
running and assessing its patched copy and deploying its sandbox variant, and a rebuild or an order whose answers
are reused from other orders makes no LLM call at all. The runner keeps two limits apart:

- **Jobs at once** (LLM queue → Settings; 0, the default: automatic, every LLM request at once of the LLMs in the
  order plus one): how many jobs it works on at the same time, whatever they do. A build takes CPU and memory, as
  does the appliance's built-in LLM on a CPU, so the automatic number stays modest; raise it on a big machine with
  a GPU LLM elsewhere, lower it when builds and the built-in LLM slow each other down.
- **Requests at once** of each LLM (Admin → Source control & LLM, and **Parallel requests** for the built-in LLM
  or the worker's own LLM settings): an LLM call takes one only while it is answered, and gives it back at once. A
  job that builds, verifies or deploys holds none.

The runner starts the jobs in the queue's order (LLM-heavy first, then priority and the administrators' moves)
while a job slot is free and the hours, idle check and pause allow it. A job whose estimate needs the LLM starts
only when an LLM that takes its size has a request no call is waiting for and no job just started is about to use;
until then the jobs after it that need no LLM start in its place, so work without LLM calls does not wait for an
LLM, and LLM work does not wait for builds while an LLM is free. Each call of a running job goes to the first LLM
in the order that takes the call's size and has a free request; when none is free, the call waits, and waiting
calls are answered in the order their jobs started. An answer already in the cache needs no request.

On the queue page a running job says what it does now: **Asking** and the LLM while one of its calls is answered,
**Waiting for an LLM** while a call waits for a request, else **Running** with its progress (generating,
verifying, deploying). The LLMs table shows the requests in progress on each (**Asking now**). The speed
statistics are learned per call: each LLM's figures come from the calls it answered (their size, tokens and time,
and the requests at once on it), not from the job's time with its builds.

