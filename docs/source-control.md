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

**The appliance's built-in LLM.** Without an LLM server of your own, the appliance can run one on its
CPU: Qwen3-Coder 30B-A3B with llama.cpp, turned on under **Admin → Source control & LLM** (off by
default; it needs a machine with at least 40 GB of memory, see
[Running the appliance](appliance-admin.md#built-in-llm)). Scans with **Ask the LLM** use it when no LLM is
set on that page; an LLM set there is always used instead. Expect about 7 to 12 tokens per second and a few
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
| Make it A (`refactor`, goal `rating-a`) | a person, on a B-rated application's results page, or an administrator for every B app (**Make all B apps A**) | 1800, as a refactoring | one patch for every finding, repaired and assessed again in a loop; a [sandbox variant](refactoring.md#the-sandbox-variant) when the patched copy rates A |

A refactoring asks the LLM once per file it changes (at most 8), so it is a long job; its estimate is
made from the size of what it will send, and the output tokens are learned per kind like the reviews'.
While it runs, the queue page says how far it is (generating, verifying, deploying; for Make it A also the
pass and the repair round), and the job links to its patch page (Admin → Refactoring). A Make it A order
makes up to 16 LLM calls.
