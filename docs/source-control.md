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
  and GitOps files are pushed to, matched by the repository's URL.

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

## Setting it up

The appliance makes the key pair at first boot (`/etc/containerizer/secrets/credential-key` for the
worker, `credential-key.pub` for the web UI, handed over as systemd credentials). Elsewhere, make it
once:

```sh
python -m containerizer credentials keygen --private worker-credential.key --public worker-credential.pub
```

| Process | Variable | File |
| --- | --- | --- |
| scan worker | `CONTAINERIZER_CREDENTIAL_KEY_FILE` | the private key: mode 600, readable by the worker's user only |
| web UI | `CONTAINERIZER_CREDENTIAL_PUBLIC_KEY_FILE` | the public key |

Several workers share the same private key. Do not give the private key to the web UI. Making a new
key pair means entering every token again: the page marks tokens sealed for another key.

Then upgrade the database (`containerizer db init`, schema version 10), open **Admin → Source
control** and add the tokens. On the appliance, also allow the hosts on the **Firewall** page.

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

Scans with **Ask the LLM** on consult an LLM about the components the rules are unsure of
([self-hosted-llm.md](self-hosted-llm.md)). Set it on the same page, once:

| Kind | Server | Model | API key |
| --- | --- | --- | --- |
| Claude API | empty, or the https URL of a gateway in front of it | e.g. `claude-sonnet-5-5` | required: a key from the Claude Console, in a workspace only for Containerizer, with a spend limit |
| OpenAI-compatible server (Ollama, vLLM, LM Studio, llama.cpp, LocalAI, ...) | the URL up to and including `/v1` | the name the server knows | optional; only sent over https, or plain http to the worker's own machine |

The key is sealed for the worker like the tokens and never shown again; the model can be changed
without re-entering it, while a different server means removing it and adding it again. The worker
hands the setting to the AI code for the run only, never through its environment, so the git and
docker processes a scan starts never see the key. With no LLM set here, scans fall back to the
worker's own environment variables (`CONTAINERIZER_LLM_BASE_URL`, `ANTHROPIC_API_KEY`, ...), as before.
On the appliance, allow the server's host on the Firewall page.

## Command line runs

`containerizer org` outside the worker ([organization-run.md](organization-run.md)) has no database, so
it still takes the tokens from environment variables (`GITHUB_TOKEN`, `GITLAB_TOKEN`,
`AZURE_DEVOPS_TOKEN`, `OUTPUT_GIT_TOKEN`, or `--token-env`, `--output-token-env`). The same rules apply:
no token, no run; the read-only token only with the organization's URLs; the write token only for the
output repository, which is not scanned.

## Upgrading from token variables

Earlier versions had the worker read the tokens from its environment (`CZ_TOKEN_*`, `GITHUB_TOKEN`,
`OUTPUT_GIT_TOKEN`, ...) and each scan named the variables (*Token variable*, *Output token variable*).
The worker no longer reads them: register each organization's token and each output repository's token
under **Source control**, then remove the variables from `worker.env`. Until then the scans show
*Token missing* and do not run. The old `TokenEnv` / `OutputTokenEnv` columns are kept in the
database but unused.
