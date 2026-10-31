# Running the tool across a whole organization

`containerizer org` runs the one-shot `analyze` on every Git repository of one Azure DevOps
organization, GitHub organization or GitLab group, keeps only the components rated **A**, builds and
pushes their images, and commits the generated files plus Argo CD and Flux configuration for a sandbox
Kubernetes cluster to a Git repository of your choice.

```sh
export GITHUB_TOKEN=...            # read access to the organization's repositories (private ones too)
export OUTPUT_GIT_TOKEN=...        # push access to the output repository only
export REGISTRY_USERNAME=... REGISTRY_PASSWORD=...   # or an existing `docker login`

python -m containerizer org --provider github --org acme \
  --registry acmeregistry.azurecr.io/sandbox \
  --output-repo https://github.com/acme/sandbox-deployments.git \
  --image-pull-secret regcred
```

| Provider | `--org` | Token (default variable) | Self-hosted `--api-url` |
| --- | --- | --- | --- |
| `azure-devops` | organization (Azure DevOps Server: the collection) | `AZURE_DEVOPS_TOKEN`, `AZURE_DEVOPS_EXT_PAT` or `SYSTEM_ACCESSTOKEN`: PAT with Code (Read) and Project (Read) | `https://tfs.example.com/tfs` |
| `github` | organization (a user account works too) | `GITHUB_TOKEN` or `GH_TOKEN`: fine-grained token with Contents (read) and Metadata (read) on all repositories | `https://ghe.example.com/api/v3` |
| `gitlab` | group path, e.g. `acme` or `acme/platform` (subgroups included) | `GITLAB_TOKEN`: `read_api` + `read_repository` | `https://gitlab.example.com` |

`--token-env NAME` reads the token from another variable. Tokens are never accepted on the command
line.

## What happens to each repository

1. **Listed** through the provider's API, including private and internal repositories the token can read.
   Archived/disabled and empty repositories are skipped; `--skip-forks` skips forks, `--include` /
   `--exclude` filter by a regex on `<project>/<repository>`.
2. **Skipped when not updated in 6 months** (`--stale-days`, default 183; `0` turns it off). "Updated"
   means the newest commit on the default branch. The provider's activity date is checked first
   (GitHub `pushed_at`, GitLab `last_activity_at`, Azure DevOps: the newest commit of the default
   branch), so stale repositories are not cloned; the commit date of the cloned `HEAD` is checked as well.
3. **Cloned** shallow (default branch only, no tags, no submodules, no symlinks, no LFS objects).
4. **Skipped when it already has a Dockerfile**: any `Dockerfile`, `Dockerfile.*`, `*.Dockerfile` or
   `Containerfile` anywhere in the repository (outside `node_modules`). Such an application is
   already containerized by its team.
5. **Analyzed** with `analyze`: assess, build and run every feasible component on the machine, learn
   from failures, re-assess. `--ai`, `--model`, `--timeout` and `--pin-digests` are passed through, and
   with `--sql` (or `CONTAINERIZER_SQL`) every assessment is written to the results database, A or not.
6. **Selected**: a component is kept only when
   - it is a server component (web, worker, console, SPA) rated **A** on its own: the application rating
     of a one-component application, so every rule that keeps an application from A applies, including
     the stateless requirement (no SQLite/LiteDB files, local uploads, local indexes or in-memory
     session/job state);
   - a Linux image can be generated for it; and
   - it built and ran in the verification (`ok`, or `ok-external` when it only lacks its database or
     broker). `--no-verify` skips this (less accurate).
7. **Security gate** (`gate`): Dockerfile and manifest lint, image build, vulnerability scan (fails on
   fixable vulnerabilities at `--fail-on`, default from `rules/60-security.yaml`), and a run with the
   pod's security context. A component that fails is dropped and the rest are gated again, so the
   generated namespace, network policies and GitOps files only cover what is deployed. `--no-gate`
   skips it.
8. **Images** are pushed as `<registry>/<app>/<component>:<tag>` and `:git-<commit>`. The default tag
   is `1.<yyyymmdd>.<hhmm>` of the run (semver, so the generated Flux/Argo CD image automation can
   follow it); `--tag` sets one. `--cosign-key` signs every pushed digest (the generated Kyverno policy
   only admits signed images). `--no-push-images` builds and gates without pushing.
9. **Written** to the output repository and committed (and pushed) after every repository, so a long
   run can be followed and survives interruptions. When the output branch moved meanwhile, the commit
   is rebased and pushed again.

A repository that is skipped or has no A component loses its folder in the output repository, so the
sandbox stops deploying it. A repository that fails to clone or analyze keeps its previous folder and
is reported as `error`.

## Output repository layout

```
<Organization>/
  README.md                  every repository: status, rating, deployed and excluded components with reasons
  org-run.json               the same as data (merged across runs)
  <Project>/<Repository>/    one application (namespace <app>)
    kustomization.yaml       namespace, security policies, components, image tags
    namespace.yaml security.yaml HARDENING.md SECURITY.md MIGRATION.md cluster/
    containerizer.json       source URL, commit, images, digests, verification
    gitops/argocd/           AppProject + Application for this app (+ kustomization.yaml)
    gitops/flux/             tenant.yaml, git/sync.yaml (+ kustomization.yaml), oci/, image automation
    <component>/             Dockerfile, Dockerfile.dockerignore, k8s.yaml, plan.json
sandbox/
  README.md namespaces.txt
  argocd/bootstrap.yaml      app-of-apps
  argocd/apps/               kustomization over every <app>/gitops/argocd
  flux/bootstrap.yaml        GitRepository + root Kustomization
  flux/apps/                 kustomization over every <app>/gitops/flux
```

The project level:

- **Azure DevOps**: the project name (spaces kept).
- **GitHub** has no projects: the project folder is `_`, e.g. `acme/_/billing-api/`.
- **GitLab**: the subgroup path below `--org`, one folder with `--` for `/` (`acme/team/sub/repo` ->
  `acme/team--sub/repo/`); projects directly in the group use `_`.

Folder names keep the original names; characters outside letters, digits, space, `.`, `_` and `-` become
`_`. The **app name** (Kubernetes namespace, Argo CD application, image path) is
`<project>-<repository>` in DNS form (`<repository>` without a project), prefixed with `app-` when it
would be a system namespace (`default`, `kube-*`, `argocd`, `flux-system`, ...), shortened with a hash
past 63 characters, and given a hash suffix when two repositories would map to the same name.

## Deploying to the sandbox cluster

`sandbox/README.md` in the output repository has the commands. In short:

- **Argo CD**: register the output repository with a read-only token and apply
  `sandbox/argocd/bootstrap.yaml`. Its AppProject may only create AppProjects and Applications in
  `argocd` from that repository; each app's own AppProject is pinned to its namespace and generated kinds.
- **Flux**: create the `containerizer-sandbox-git` secret in `flux-system` and a `<app>-git` secret in
  each namespace in `sandbox/namespaces.txt`, then apply `sandbox/flux/bootstrap.yaml`. The root
  Kustomization creates each tenant (namespace with Pod Security "restricted", ServiceAccount,
  namespace-only RoleBinding); each app then reconciles as its own ServiceAccount.
- **Registry**: with `--image-pull-secret regcred` every workload references that pull secret; create it
  in each namespace from `namespaces.txt` (or give the nodes registry credentials).
- **Secrets**: apps get their connection strings through External Secrets (`ClusterSecretStore`
  `app-secrets`), see each app's `HARDENING.md`.

## Security

- Tokens come from environment variables only. Git receives them as an `http.<host>.extraHeader` in
  environment variables (`GIT_CONFIG_COUNT`), scoped to the provider's host: not in `.git/config`, not
  in the process list, not in clone URLs, and not sent to other hosts. Every error message is redacted.
- Use separate tokens: read-only for the organization, write for the output repository only, push-only
  for the registry. In a pipeline, take them from the secret store (GitHub Actions secrets, Azure
  DevOps secret variables or a variable group linked to Key Vault, GitLab masked + protected variables).
- Registry credentials (`REGISTRY_USERNAME`/`REGISTRY_PASSWORD`) are written only to a temporary docker
  config directory (mode 700, password through stdin) that is deleted at the end of the run.
- Clones are made with symlinks off, no submodules, and the `file`/`ext` transports disabled; scanned
  code is not executed by the scanner. Building and running the images does execute the repositories'
  build steps, as `analyze` and `gate` always do: run the tool on a disposable build agent that has
  no other credentials.
- The work folder (`--work-dir`, default `.work/org`) is mode 700 and clones are deleted after each
  repository unless `--keep-work`.
- Nothing secret is written to the output repository: the generated manifests reference Secrets via
  External Secrets, and build logs are not copied.

## Running it from a pipeline

The run is long (each component is built, run, scanned): schedule it, for example weekly, on an agent
with Docker.

```yaml
# GitHub Actions
on:
  schedule: [{cron: "0 2 * * 6"}]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  org:
    runs-on: ubuntu-latest
    timeout-minutes: 1440
    steps:
      - uses: actions/checkout@v4
        with: {repository: olljanat-ai/containerizer, path: tool}
      - run: pip install -r tool/requirements.txt
      - working-directory: tool
        env:
          GITHUB_TOKEN: ${{ secrets.ORG_READ_TOKEN }}
          OUTPUT_GIT_TOKEN: ${{ secrets.SANDBOX_REPO_TOKEN }}
          REGISTRY_USERNAME: ${{ secrets.REGISTRY_USERNAME }}
          REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}
        run: >
          python -m containerizer org --provider github --org ${{ github.repository_owner }}
          --registry acmeregistry.azurecr.io/sandbox --image-pull-secret regcred
          --output-repo https://github.com/${{ github.repository_owner }}/sandbox-deployments.git
```

```yaml
# Azure DevOps
schedules:
  - cron: "0 2 * * 6"
    branches: {include: [main]}
pool: {vmImage: ubuntu-latest}
steps:
  - checkout: self
  - script: pip install -r requirements.txt
  - script: >
      python -m containerizer org --provider azure-devops --org contoso
      --registry acmeregistry.azurecr.io/sandbox
      --output-repo https://dev.azure.com/contoso/Platform/_git/sandbox-deployments
    env:
      AZURE_DEVOPS_TOKEN: $(OrgReadPat)          # secret variable
      OUTPUT_GIT_TOKEN: $(System.AccessToken)    # build service needs Contribute on the output repo
      REGISTRY_USERNAME: $(RegistryUser)
      REGISTRY_PASSWORD: $(RegistryPassword)
```

Exit code 0: every repository was processed (deployed or skipped), 1: at least one repository failed
(see `<Organization>/README.md`), 3: the organization could not be listed or the output repository or
registry could not be reached.

`--dry-run` lists the repositories and the decisions that need no clone (archived, empty, forks,
stale by the provider's date): a quick check of the token and filters.
