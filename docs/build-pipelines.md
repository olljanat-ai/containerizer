# Build pipelines

Containerizer generates the Dockerfiles that build an application's components, and builds them itself
during a scan. For the application team to build the images themselves, from their own repository, it also
generates a **container image build pipeline** for the CI system the code lives on: **GitHub Actions**,
**GitLab CI/CD** or **Azure Pipelines**.

The pipeline is made without an LLM, from what the assessment generated: the same Dockerfiles, the same
image names as the generated Kubernetes manifests, and the same tag scheme the sandbox's GitOps image
automation follows. Containerizer never writes to the repository: you get the files, or a patch to apply
with `git am`, and open the pull request yourself.

## Where to get it

![The Build pipeline box on an application's results page: the provider, the files it adds, Download .patch and how to apply it](images/results-build-pipeline.png#only-light){ .cz-shot }
![The Build pipeline box on an application's results page: the provider, the files it adds, Download .patch and how to apply it](images/results-build-pipeline-dark.png#only-dark){ .cz-shot }

- **The results page**: the application's **Build pipeline** box. Administrators, operators and the
  application's product owners see where the code lives, the files the pipeline adds, **Download .patch**,
  the same files as a `.tar.gz`, how to apply it and the files themselves as a diff. Choose another provider
  or signing there. Everyone else sees that the pipeline exists.
- **The output repository** of an organization scan: `<organization>/<project>/<repository>/pipeline/`, next
  to the generated manifests. `pipeline/<provider>/` mirrors the application's repository: copy its contents
  to the repository root. `pipeline/README.md` says what to do.
- **The command line**, on a checkout:

  ```sh
  containerizer pipeline <app-path> [--provider github|gitlab|azure-devops] [--registry R] \
      [--sign none|keyless|key] [--out DIR] [--patch]
  ```

  Without `--patch` it writes `DIR/pipeline/<provider>/...`; with `--patch` a `git am` patch made on a
  scratch copy of the checkout's HEAD commit and checked by applying it to another clean copy.

| Role | The Build pipeline box | Downloads (`/admin/build-pipeline/<id>.patch`, `.tar.gz`) |
| --- | --- | --- |
| Admin, Operator | Everything | Every application |
| Product owner | Everything, for the applications of their products | Those applications |
| Viewer, anyone without sign-in | That it exists (and for which provider, from the repository URL) | No access |

## Which provider

The provider comes from, in this order: the organization scan that has the repository (its **Provider**:
GitHub, GitLab or Azure DevOps, also self-hosted ones through its API URL: GitHub Enterprise Server, GitLab
self-managed, Azure DevOps Server / TFS); then the repository URL: `github.com`, `*.ghe.com` or a host named
`github`/`ghe`; `gitlab.com` or a host named `gitlab`; `dev.azure.com`, `*.visualstudio.com`, or a URL with
`/_git/` or `/tfs/`. When neither tells, all three are offered (the output repository gets all three folders,
the results page a download per provider). `--provider` or the box's provider list overrides it.

## What it adds to the repository

| File | |
| --- | --- |
| `containerizer/<component>/Dockerfile` | The generated Dockerfile, as the scan built it |
| `containerizer/<component>/Dockerfile.dockerignore` | The generated context filter, plus `containerizer/` |
| `containerizer/README.md` | The components, images, what to set up first, the pins |
| `.github/workflows/containerizer-images.yml` | GitHub Actions |
| `.gitlab-ci.yml`, or `containerizer.gitlab-ci.yml` | GitLab CI/CD: when the repository has a `.gitlab-ci.yml`, a file to `include:` from it (add `include: [{local: containerizer.gitlab-ci.yml}]`, and the stage `build` if your `stages:` list lacks it) |
| `azure-pipelines.containerizer.yml` | Azure Pipelines |

For an application in a subfolder of its repository, the `containerizer/` folder is in that subfolder; the
CI file is at the repository root. If the application already has an entry called `containerizer`, the
folder is `containerizer-build/`.

**The build context** is the application's folder, as in the scans (`docker build -f
<generated>/<component>/Dockerfile <application folder>`): the generated Dockerfiles copy paths relative to
it. `Dockerfile.dockerignore` next to the Dockerfile is the context filter: BuildKit (the default builder of
current Docker, and of all three pipelines) reads `<Dockerfile>.dockerignore` instead of the context's
`.dockerignore`. It leaves out `bin/`, `obj/`, `node_modules/`, secrets files and the pipeline's own
`containerizer/` folder. Build locally the same way:

```sh
DOCKER_BUILDKIT=1 docker build -f containerizer/<component>/Dockerfile .
```

## What the pipeline does

| | Pull / merge requests | The default branch |
| --- | --- | --- |
| Build | Yes, each changed component | Yes, each changed component |
| SBOM (Syft, CycloneDX JSON) | Kept as a pipeline artifact | Kept as an artifact (and attested to the image when signing) |
| Vulnerability scan (Trivy) | Fails the job on the gate's severities | Fails the job before anything is pushed |
| Push | No | `1.<yyyymmdd>.<hhmm>` and `sha-<commit>` (and `latest` when asked) |
| Sign (cosign) | No | Optional: keyless or with a key |

- **Monorepos**: one job per component. A component is rebuilt when its project folder, the folders of the
  projects it references, the application folder's shared build files (`Directory.Build.props`,
  `global.json`, `NuGet.config`, root `package.json`, ...) or its own `containerizer/<component>/` files
  change. GitHub: a first job compares the push or pull request with its base and starts the components that
  changed (a change to the workflow, a new branch or a manual run builds all). GitLab: `rules: changes:` per
  job. Azure Pipelines has no per-job path filters: the trigger's path filter is the union, and every
  component is built.
- **Scanning** uses the security gate's settings ([rules/60-security.yaml](https://github.com/olljanat-ai/containerizer/blob/main/rules/60-security.yaml)
  `scan`): it fails on `fail_on` and above (default `CRITICAL`), only for vulnerabilities with a fix
  (`ignore_unfixed`). Change it per repository without editing the file: GitHub repository variables
  `CONTAINERIZER_TRIVY_SEVERITY` and `CONTAINERIZER_TRIVY_IGNORE_UNFIXED`, GitLab CI/CD variables or Azure
  pipeline variables `TRIVY_SEVERITY` and `TRIVY_IGNORE_UNFIXED`. Trivy and Syft run as containers that read
  the image from the job's Docker daemon (on GitLab: from the Docker-in-Docker service), so nothing is
  installed on the runner.
- **The image** is `<registry>/<app>/<component>`, the name in the generated manifests. The registry is the
  organization scan's **Registry** setting when it has one; otherwise GitHub Container Registry
  (`ghcr.io/<owner>`), the GitLab project's registry (`$CI_REGISTRY_IMAGE`), or on Azure a placeholder
  (`REPLACE-ME.azurecr.io`) that fails the push job with a message until you set it. The variable
  `CONTAINERIZER_REGISTRY` overrides it in each provider.
- **Tags**: `1.<yyyymmdd>.<hhmm>` (UTC, when the pipeline started) is the same semver scheme as the scans'
  own images, and `sha-<first 12 characters of the commit>`. `latest` is off by default
  (`CONTAINERIZER_PUSH_LATEST=true`).

## Permissions and secrets

### GitHub Actions

- `permissions: {}` for the workflow, and per job only what it needs: `contents: read` for the change
  detection and the pull request builds; the push job adds `packages: write` (only when the registry is
  GitHub Container Registry) and `id-token: write` (only with keyless signing). Pull requests from forks get
  no secrets, and the pull request job uses none.
- GitHub Container Registry: nothing to set up, the job's `GITHUB_TOKEN` pushes. After the first push, link
  each package to the repository (package settings) and make it public, or give the cluster a pull secret.
- Another registry: repository secrets `CONTAINERIZER_REGISTRY_USERNAME` and
  `CONTAINERIZER_REGISTRY_PASSWORD`; the repository variable `CONTAINERIZER_REGISTRY` for another registry or
  path.
- Key-based signing: secrets `COSIGN_PRIVATE_KEY` (the contents of `cosign.key`) and `COSIGN_PASSWORD`.
- Actions are pinned by full commit SHA with the version in a comment (`actions/checkout`,
  `actions/upload-artifact`; the rest is plain `docker`). Checkouts do not keep the token
  (`persist-credentials: false`). Protect the default branch so that only reviewed changes publish images.

### GitLab CI/CD

- The jobs run `docker:<version>-cli` with a `docker:<version>-dind` service (both pinned by digest): the
  runner needs a privileged Docker executor (GitLab.com's hosted runners have one).
- The project's registry: nothing to set up, the job token (`CI_REGISTRY_USER`, `CI_REGISTRY_PASSWORD`)
  pushes. Another registry: CI/CD variables `CONTAINERIZER_REGISTRY_USER` and
  `CONTAINERIZER_REGISTRY_PASSWORD`, **protected** and **masked**, and `CONTAINERIZER_REGISTRY`.
- Push jobs run only for the default branch when it is **protected** (`$CI_COMMIT_REF_PROTECTED`); merge
  request jobs never push, and protected variables do not reach them.
- Keyless signing: the push jobs get an `id_tokens: SIGSTORE_ID_TOKEN` (audience `sigstore`); the merge
  request jobs do not. Key-based: a protected *File* variable `COSIGN_PRIVATE_KEY` and a masked
  `COSIGN_PASSWORD`.
- The template jobs set their variables on the jobs only, so an including `.gitlab-ci.yml` is not changed.

### Azure Pipelines

- Push with a **Docker Registry service connection** named `containerizer-registry` (Project settings →
  Service connections; change the name in the `registryConnection` variable): `Docker@2` logs in with it, so
  no password or PAT is in the YAML or the variables. Allow the pipeline to use it.
- Create the pipeline from `azure-pipelines.containerizer.yml` (Pipelines → New pipeline → Existing Azure
  Pipelines YAML file). Azure Repos pull requests: add it as a **build validation** policy of the default
  branch (the `pr:` trigger applies to GitHub and Bitbucket repositories only).
- Signing is key-based only (Azure Pipelines has no OIDC token Sigstore accepts): upload `cosign.key` as the
  secure file `cosign.key` (Pipelines → Library) and set the secret variable `COSIGN_PASSWORD`.
- `pool: vmImage: ubuntu-latest`. **Self-hosted agents**: replace it with `pool: name: <your pool>`; the
  agent needs Linux, bash and Docker. Tasks are pinned to their major version (`Docker@2`,
  `DownloadSecureFile@1`): Azure Pipelines cannot pin a task by digest.

## Signing

`--sign` on the command line, **Signing** in the box:

- `none` (default): no signature.
- `keyless`: cosign signs with the pipeline's OIDC identity (GitHub `id-token: write`, GitLab `id_tokens`);
  Fulcio issues a short-lived certificate and the signature is recorded in the public Rekor transparency
  log. Verify with, for example, `cosign verify --certificate-identity-regexp
  '^https://github.com/<owner>/<repo>/' --certificate-oidc-issuer https://token.actions.githubusercontent.com
  <image>`. Not for images whose names must not appear in a public log.
- `key`: cosign signs with your key (`cosign generate-key-pair`). The signature is recorded in Rekor unless
  `sbom.cosign_tlog_upload` in `rules/60-security.yaml` is `false` (then `--tlog-upload=false`). This is the
  same key the generated `cluster/verify-images.yaml` (Kyverno) can enforce.

When signing, the SBOM is also attached to the image as a signed CycloneDX attestation
(`cosign attest --type cyclonedx`). cosign is the release binary, checked against the release's SHA-256.

## The sandbox and GitOps

The generated GitOps files follow new images by tag: Flux's `gitops/flux/git/image-automation.yaml`
(an `ImageRepository` and an `ImagePolicy` per component, semver range `>=1.0.0`, and an
`ImageUpdateAutomation` that writes the new tag to the `kustomization.yaml` setters of the output
repository), and the Argo CD Image Updater annotations (semver tags `^v?\d+\.\d+\.\d+$`). The pipeline's
version tag `1.<yyyymmdd>.<hhmm>` is that scheme, the same as the scans' own pushes (`org.default_tag`), so:

1. a merge to the default branch pushes `<registry>/<app>/<component>:1.20261101.1530`;
2. Flux sees it within the `ImageRepository` interval (10 minutes) and commits the tag to the output
   repository within the automation interval (30 minutes); the sandbox then rolls it out.

This needs the pipeline and the generated manifests to use the same registry: the organization scan's
Registry setting, which is the pipeline's default. The `sha-<commit>` tag does not match the policy and is
never rolled out by itself: it is for finding the image of a commit. No pipeline step writes to the output
repository.

## Pins and updates

| What | Pinned to |
| --- | --- |
| Trivy | `aquasec/trivy:0.67.2@sha256:e2b22eac59c02003d8749f5b8d9bd073b62e30fefaef5b7c8371204e0a4b0c08` (the security gate's version) |
| Syft | `anchore/syft:v1.33.0@sha256:f94e5d9fce1f2278491a8e3a63bd5f6ddb81fdfdbb8bf7a1637565c1d5344357` (the SBOM generator's version) |
| Docker CLI and Docker-in-Docker (GitLab) | `docker:29.9.2-cli@sha256:5e6baf67…`, `docker:29.9.2-dind@sha256:9e79b879…` |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) |
| `actions/upload-artifact` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (v7.0.2) |
| cosign | v2.6.1, `cosign-linux-amd64` SHA-256 `064954c5d8c7e3b2…` |

Digests are of the multi-architecture index. To update: generate the pipeline again with a newer
Containerizer, or by hand: `docker buildx imagetools inspect <image>:<tag>` for an image's digest,
`git ls-remote https://github.com/<action> refs/tags/<tag>` for an action's commit (a Dependabot or Renovate
configuration keeps both current). In Containerizer itself the pins are in `containerizer/pipelines.py`;
the Trivy and Syft versions come from `rules/60-security.yaml`, and a test fails when a version there has no
digest in the code.

## How the patch is made

The results page makes the patch from what the scan recorded with the assessment (the generated
Dockerfiles, the components' folders, which of the files the repository already has, the default branch):
nothing is cloned and no LLM is asked. The patch only **adds** files, so it is made on an empty commit and
`git am` applies it on the assessed commit and on later commits that do not have these files (the box
warns when the scan found one of them already). If one exists, use the `.tar.gz` and merge by hand.
`containerizer pipeline --patch` makes it on the checkout's HEAD commit and checks it with `git am` on a
clean copy.

An assessment made before this feature, or by `containerizer assess` (which generates nothing), has no
build pipeline: scan the repository again, or run `containerizer pipeline` on a checkout.

## What it does not do

- It does not run on Windows runners: Windows containers (`Dockerfile.windows`) are not included.
- It does not include the scan's last-minute changes that are not in the generated Dockerfile at
  assessment time (the security gate's OS package upgrades); the output repository's
  `pipeline/` copy does have them. The pipeline's own scan catches what they fixed.
- It is not tested on GitHub, GitLab or Azure DevOps by Containerizer's CI: the files are checked against
  the providers' schemas and linters, and the build, SBOM, scan, push and key-based signing steps are run
  locally with Docker (docs: the tests in `tests/test_pipelines.py`).
