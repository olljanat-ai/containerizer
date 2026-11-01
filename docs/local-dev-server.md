# Local development server

How to set up a Debian 13 (trixie) server where Claude Code (or you) can develop Containerizer and run
the whole end-to-end test suite locally, instead of pushing and waiting for GitHub workflows. Everything
the workflows in [`.github/workflows`](../.github/workflows) do, except publishing (GHCR push, cosign
signing, release assets, gh-pages), runs here with one command:

```sh
ci/local.sh            # the fast set, about 10-15 minutes
ci/local.sh all        # everything, including the one-shot assessment and the appliance boot test
```

## What the workflows need

Derived from the workflows themselves, so the local run matches CI:

| Workflow job | Needs on the server | `ci/local.sh` job |
| --- | --- | --- |
| `ci.yml` test | Python 3.12, `requirements.txt`, pytest | `test` |
| `docs.yml` build | `mkdocs==1.6.1`, `mkdocs-material==9.8.0` | `docs` |
| `ci.yml` containerizer, containerizer-head | Python, git (the composite action is `python -m containerizer check`) | `gate` |
| `ci.yml` action-selftest | git, network access to `github.com/onek8s/containerization-challenge` | `selftest` |
| `security.yml` gate | Docker; Trivy and Grype run as containers (`aquasec/trivy`, `anchore/grype`, pinned in [`rules/60-security.yaml`](../rules/60-security.yaml)) | `security` |
| `ci.yml` sql | Docker, `mcr.microsoft.com/mssql/server:2025-latest`, `requirements-sql.txt` (pymssql) | `sql` |
| `ci.yml` sandbox | Docker, kind, kubectl | `sandbox` |
| `ci.yml` assess-oneshot | Docker with BuildKit (builds and runs every generated container), a lot of disk | `assess` |
| `release.yml` appliance | Docker + buildx, KVM, `qemu-system-x86`, `qemu-utils`, `ovmf`, `zstd`, `expect` (the boot test changes the expired root password over SSH); the Elemental toolkit is built inside `appliance/Dockerfile`, so it needs no install | `appliance` |

Not needed: Node.js (the repository has no JavaScript build), Syft as a binary (it runs as the
`anchore/syft` container), and cosign / oras unless you test `sbom attach` or release signing by hand.

## Hardware

x86_64 only: the SQL Server image, OVMF and the appliance are amd64.

| | Fast set | Everything (`all`) | With Ollama |
| --- | --- | --- | --- |
| CPU | 4 cores | 8+ cores | 8+ cores, or a GPU |
| RAM | 16 GB | 32 GB | 64 GB on CPU, or a 24 GB GPU for a 30B model ([Qwen3-Coder 30B-A3B on CPU](#optional-qwen3-coder-30b-a3b-on-cpu-only-no-gpu): + 20 GB) |
| Disk (SSD/NVMe) | 100 GB | 250 GB | + 20-40 GB per model |

The appliance boot test gives its VM all CPUs and the free memory less 1 GiB (at most 11 GiB, at least
4 GiB; SQL Server inside it needs 2 GiB), and grows the disk image to 96 GB (sparse). The one-shot
assessment builds .NET images for three apps; Docker's build cache grows quickly, so prune it now and
then (`docker system prune -af --volumes` when nothing else runs).

If the server is itself a VM, turn on nested virtualization so `/dev/kvm` exists: CPU type `host` on
Proxmox / libvirt, `Set-VMProcessor -VMName <vm> -ExposeVirtualizationExtensions $true` on Hyper-V.
Check with `ls -l /dev/kvm`.

## Install

Start from a minimal Debian 13 install with SSH. As root (or with sudo), once:

```sh
# a dedicated, unprivileged user for development; Claude Code runs as this user
adduser --disabled-password --gecos "" dev
install -d -m 700 -o dev -g dev /home/dev/.ssh
cp ~/.ssh/authorized_keys /home/dev/.ssh/ && chown dev:dev /home/dev/.ssh/authorized_keys

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git jq make openssh-client \
  qemu-system-x86 qemu-utils ovmf zstd expect nftables unattended-upgrades

# Docker Engine with BuildKit / buildx, from Docker's repository (Debian's docker.io has no buildx plugin)
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# kind and kubectl for the sandbox test (ci.yml uses helm/kind-action; any recent kind works)
curl -fsSLo /usr/local/bin/kind https://github.com/kubernetes-sigs/kind/releases/download/v0.26.0/kind-linux-amd64
curl -fsSLo /usr/local/bin/kubectl https://dl.k8s.io/release/v1.32.0/bin/linux/amd64/kubectl
chmod 0755 /usr/local/bin/kind /usr/local/bin/kubectl

# docker: run containers without sudo (see Security); kvm: the appliance boot test
usermod -aG docker,kvm dev
```

Debian 13 ships Python 3.13; the workflows use 3.12. `ci/local.sh` creates its environment with
[uv](https://docs.astral.sh/uv/), which fetches 3.12 for the user, so the system Python is left alone.
As `dev` (log in again first, so the new groups apply):

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh      # installs to ~/.local/bin
uv python install 3.12
docker run --rm hello-world && ls -l /dev/kvm        # both must work without sudo
```

Without uv the script falls back to `python3 -m venv` with Debian's 3.13 (install `python3-venv` for
it), which works for development
but is not exactly what CI runs. If `.venv-ci/` was created that way and uv is installed later, the next
`ci/local.sh` run notices the version and recreates it with 3.12.

### Optional: cosign

Only for testing release signing or `containerizer sbom attach` by hand. The same pinned version and
checksum as `release.yml`:

```sh
curl -fsSLo /tmp/cosign https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /tmp/cosign" | sha256sum -c -
sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign
```

### Optional: Ollama for the self-hosted LLM backend

To test `--ai` against a local model ([the LLM](source-control.md#the-llm)):

```sh
curl -fsSL https://ollama.com/install.sh | sh       # a systemd service on 127.0.0.1:11434
ollama pull qwen3:32b                                # or a smaller model for quick checks, e.g. qwen3:8b

export CONTAINERIZER_LLM_BASE_URL=http://localhost:11434/v1
export CONTAINERIZER_MODEL=qwen3:32b
.venv-ci/bin/python -m containerizer assess examples/ci-demo --ai
```

### Optional: Qwen3-Coder 30B-A3B on CPU only (no GPU)

For a lab server without a GPU. This is for development and testing only: real environments use an
external LLM, or the appliance's [built-in LLM](appliance-admin.md#built-in-llm), which runs the same
model and server with the settings below (on port 8082, sized from the machine's memory). [ByteShape](https://byteshape.com/blogs/Devstral-Small-2-24B-Instruct-2512/) publishes
quantized builds of Qwen3-Coder 30B-A3B tuned for CPUs (Apache 2.0). The model is a mixture of experts
with only 3B of its 30B parameters active per token, so it is several times faster on a CPU than a dense
model of similar quality. Their dense Devstral Small 2 24B builds stay under 10 tokens/s on CPUs.

| Build (file) | Size | Quality (vs. baseline) | Intel Core i7 | Memory with a 32K context |
| --- | --- | --- | --- | --- |
| `Qwen3-Coder-30B-A3B-Instruct-IQ4_XS-4.20bpw.gguf` | 16 GB | 99.0% | 15.9 tokens/s | about 20 GB |
| `Qwen3-Coder-30B-A3B-Instruct-Q3_K_M-3.31bpw.gguf` | 12.7 GB | 97.5% | 18.3 tokens/s | about 16 GB |

The quality and speed figures are ByteShape's. Generation speed follows memory bandwidth, so a
dual-channel desktop is slower than a many-channel server. Reading the prompt is slower too: the
evidence packs are 5,000 to 15,000 tokens, so expect up to a few minutes per answer. LLM-heavy mode makes
many calls and turns a scan into hours. Use the 4.20 bpw build when the memory is there, and stay above
about 3 bpw.

Run llama.cpp's server on loopback, as an unprivileged container. The model file is read-only:

```sh
sudo install -d -m 0755 /srv/llm
cd /srv/llm
f=Qwen3-Coder-30B-A3B-Instruct-IQ4_XS-4.20bpw.gguf
sudo curl -fL -C - -o $f \
  https://huggingface.co/byteshape/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/0436a5b1e12e051e8a8568d56a1526734d3ed572/$f
echo "618f0a45a5a85f099106c80e44e0eb8ce9ee094b6268395b84e8b5b729f865dd  $f" | sha256sum -c -
sudo chmod 0644 $f

docker run -d --name llm --restart unless-stopped --network host \
  --volume /srv/llm:/models:ro --memory 24g --cpu-shares 256 \
  --user 65534:65534 --read-only --tmpfs /tmp:size=64m --cap-drop ALL --cap-add IPC_LOCK --ulimit memlock=-1:-1 \
  --security-opt no-new-privileges \
  -e LLAMA_ARG_HOST=127.0.0.1 -e LLAMA_ARG_PORT=8081 \
  --health-cmd 'curl -fsS http://127.0.0.1:8081/health' --health-start-period 5m \
  ghcr.io/ggml-org/llama.cpp:server-b12030@sha256:e67d88af487390098c76d7982b1761484339fa147b7e41d3c64ae1318759f78b \
  --model /models/$f --alias qwen3-coder-30b-a3b \
  --ctx-size 32768 --parallel 1 --jinja --load-mode mmap+mlock --lazy-mode off \
  --cors-origins localhost --no-cors-credentials --cache-ram 1024
curl -fsS http://127.0.0.1:8081/health                 # {"status":"ok"} once the model is loaded
sudo grep VmLck /proc/$(docker inspect llm --format '{{.State.Pid}}')/status   # about 15 GB: the model is pinned
```

Why the options:

- `--load-mode mmap+mlock` with `IPC_LOCK` and an unlimited `memlock` keeps the model in RAM. The file
  is memory-mapped, so its 16 GB is page cache, not container memory (`docker stats` shows only the
  3 GB or so of context buffers), and without the lock the kernel drops it when the test suite's builds
  fill the cache, so the next answer first reads the model from disk again. `--lazy-mode off` keeps
  large tensors resident too. This build has no `--mlock`: it fails with `invalid argument`.
- The image sets `LLAMA_ARG_HOST=0.0.0.0` and `LLAMA_ARG_PORT=8080`. Setting the variables, instead of
  `--host` and `--port`, avoids a warning that they are overridden, and `--health-cmd` replaces the
  image's health check, which probes port 8080 and would mark the container `unhealthy`.
- `--cache-ram 1024`: llama.cpp keeps up to 8 GiB of earlier prompts in RAM by default (its RSS grows
  from about 6 to 11 GiB and more over a scan). Review prompts rarely repeat, so a small cache is enough.
- `--cors-origins localhost --no-cors-credentials`: by default any web page can call the server
  (the `no API key is set and CORS allows all origins` warning). Containerizer is not a browser, so it
  is not affected. The remaining warning, `control-looking token: 128247 '</s>' was not control-type`,
  comes from the model file's metadata and is harmless.

`--threads N` limits the CPU it takes (the default is about one thread per core). `--cpu-shares 256`
gives the test suite's builds the CPU first when both want it. For several scans at once (one shard
of apps per process, or an organization scan with several workers), `--parallel N` with
`--ctx-size` N times as large decodes N answers together for about the cost of one, since speed follows
memory bandwidth; keep the context per slot (`n_ctx_slot` in the log) above about 20,000 tokens, use a
multiple of 256 per slot to avoid a rounding warning (`--parallel 3 --ctx-size 66048`), and raise
`--memory` by about 3 GB per extra slot. Restarting the container while a scan runs is safe: requests
are retried while the model loads. Then point Containerizer at it. Raise
the timeout, because the default of 15 minutes per call is tight on a CPU:

```sh
export CONTAINERIZER_LLM_BASE_URL=http://localhost:8081/v1
export CONTAINERIZER_MODEL=qwen3-coder-30b-a3b
export CONTAINERIZER_LLM_TIMEOUT=3600
.venv-ci/bin/python -m containerizer assess examples/ci-demo --ai
```

`--ai` asks the LLM only about server and platform components with a confidence below 0.85, and
`examples/ci-demo` has none, so the command above checks the configuration but never calls the model.
To see a real answer, scan a challenge scenario with a low-confidence component, for example
`freight-rates` (after `ci/local.sh selftest` or `assess` has cloned the challenge repository):

```sh
cp -r .work/ci-local/challenge/scenarios/freight-rates /tmp/freight-rates
.venv-ci/bin/python -m containerizer assess /tmp/freight-rates --ai -v
```

Answers are cached in `.work/ai-cache/` (`CONTAINERIZER_AI_CACHE`), so delete the entry, or point the
variable at an empty folder, to make the model answer again.

To test it from an appliance VM on the same server, enter the same server URL (the server's address
instead of `localhost`, with `LLAMA_ARG_HOST` set to match) and model on **Admin → Source control**, and allow
the address on **Admin → Firewall**. Plain http is accepted only when there is no API key: put TLS and
a key (llama.cpp `--api-key`, behind a reverse proxy) in front of it otherwise.

With Ollama instead of llama.cpp, run
`ollama pull hf.co/byteshape/Qwen3-Coder-30B-A3B-Instruct-GGUF:Qwen3-Coder-30B-A3B-Instruct-IQ4_XS-4.20bpw.gguf`
and use that name as the model, with the base URL `http://localhost:11434/v1`.

## Claude Code

As `dev`:

```sh
curl -fsSL https://claude.ai/install.sh | bash        # native installer, to ~/.local/bin/claude
claude                                               # first start: choose a login method
```

Ways to sign in on a headless server:

- **Claude subscription**: start `claude`, pick the Claude account login, open the URL it prints in a
  browser on your own machine, and paste the code back into the SSH session.
- **Long-lived token**: on a machine with a browser run `claude setup-token`, then put
  `export CLAUDE_CODE_OAUTH_TOKEN=...` in `~dev/.bashrc` (mode 600) on the server.
- **API key**: `export ANTHROPIC_API_KEY=...` from the Anthropic Console.

`claude doctor` checks the install. With `claude` on `PATH`, Containerizer's `--ai` option can also use
it as its backend (`CONTAINERIZER_AI_BACKEND=cli`).

## Clone and run

```sh
# GitHub access for git push and pull requests: a fine-grained token for this one repository
# (Contents and Pull requests: read and write), or an SSH deploy key with write access
git clone https://github.com/olljanat-ai/containerizer.git ~/containerizer
cd ~/containerizer
ci/local.sh --list
ci/local.sh
```

The first run creates `.venv-ci/` with Python 3.12, the requirements, pytest and the pinned MkDocs.
Use that environment for ad hoc runs too: `.venv-ci/bin/python -m pytest -q tests/test_engine.py`.

| Command | Runs |
| --- | --- |
| `ci/local.sh` | `test docs gate selftest security sql sandbox` |
| `ci/local.sh all` | the above, then `assess` (up to about an hour) and `appliance` (one to two hours) |
| `ci/local.sh sql sandbox` | only the jobs named, in that order |
| `KEEP=1 ci/local.sh sql` | leaves SQL Server (`cz-ci-mssql`) and the web UI (`cz-ci-web`) running for debugging |

Each job keeps going after another fails; the summary at the end lists pass / FAIL and the time per
job, and the exit code is non-zero if any failed. Logs are in `.work/ci-local/logs/<job>.log`, and
reports, SARIF files, the kind kubeconfig and the appliance images in `.work/ci-local/` (git ignores
`.work/`).

Differences from the GitHub runners, on purpose:

- SQL Server is published on `127.0.0.1:11433` only (`CI_LOCAL_SQL_PORT`), and the web UI smoke test
  uses port 18080 instead of 8080, so nothing on the server's network can reach them, and the `sql` job
  runs while [the web UI without an appliance](#the-web-ui-without-an-appliance) holds 1433 and 8080.
- The kind cluster is called `cz-sandbox`, as in CI; it is deleted after the test unless it already
  existed or `KEEP=1` is set. Keep one running between runs to save a minute or two.
- The appliance job builds, boots and tests the image but never pushes, signs or publishes it. It
  hands the root-owned Elemental output back to `dev` through a container, so it needs no sudo.
- The `gate` job compares `HEAD` with its merge base on `origin/main`, as `containerizer-head` does on
  a pull request.

### Telling Claude Code about it

Put this in `~dev/.claude/CLAUDE.md` on the server (your own instructions, not committed), so every
session tests locally before pushing:

```markdown
This server can run the whole CI suite locally: see docs/local-dev-server.md.
Before pushing, run `ci/local.sh` (and `ci/local.sh assess` or `ci/local.sh appliance` when the change
touches the assessment or the appliance). Use .venv-ci/bin/python for ad hoc test runs.
```

## Security

- **Use a dedicated machine or VM**, not your workstation, and keep no other credentials on it. The
  tests build and run third-party code (the challenge apps, base images, scanner images), and Claude
  Code runs commands as `dev`.
- **The docker group is root.** Anyone in it can start a privileged container and mount `/`, and the
  appliance and kind jobs need exactly that (`--privileged`). So `dev` is effectively root on this
  machine: that is acceptable only because the machine is dedicated to this. Do not add other users
  to `docker`, and do not give `dev` sudo as well; nothing here needs it after the install. Rootless
  Docker does not work for the appliance build or kind.
- **Docker bypasses the host firewall for published ports.** `-p 1433:1433` would open SQL Server to the
  network even with ufw or an nftables `input` policy of drop, because Docker inserts its own rules.
  `ci/local.sh` binds everything to `127.0.0.1`; do the same in anything you run by hand.
- **Firewall**: allow only SSH in, for example with nftables:

  ```sh
  cat > /etc/nftables.conf <<'EOF'
  #!/usr/sbin/nft -f
  flush ruleset
  table inet filter {
    chain input {
      type filter hook input priority 0; policy drop;
      iif lo accept
      ct state established,related accept
      ip protocol icmp accept
      ip6 nexthdr icmpv6 accept
      udp dport 68 accept     # DHCP client (offers and acknowledgements can be broadcasts)
      udp dport 546 accept    # DHCPv6 client
      tcp dport 22 accept
    }
  }
  EOF
  systemctl enable --now nftables && systemctl restart docker   # Docker re-adds its own tables
  ```

  The DHCP lines matter on a server that gets its address by DHCP: renewals are answered as established
  traffic, but a new lease (after a reboot or a lost lease) can arrive as a broadcast that conntrack does
  not match, and the server would lose its address. Restarting Docker restarts the containers that have a
  restart policy; give long-running ones you started by hand one (`docker update --restart unless-stopped
  <name>`), or they stay stopped. A kind cluster does not survive it: the `sandbox` job creates it again.

- **SSH**: key login only. In `/etc/ssh/sshd_config.d/hardening.conf` set `PasswordAuthentication no`
  and `PermitRootLogin no`, then `systemctl reload ssh`.
- **Ollama** listens on `127.0.0.1:11434` only, and the llama.cpp container on `127.0.0.1:8081`; leave `OLLAMA_HOST` unset unless you put TLS and a key in
  front of it.
- **GitHub**: give the server a fine-grained token (or deploy key) scoped to this repository only, with
  no admin or workflow permissions, so a mistake on the server cannot change other repositories or
  the release workflow's secrets.
- **Claude Code permissions**: on this dedicated VM it is reasonable to allow the commands the suite
  needs (`ci/local.sh`, `docker`, `kind`, `kubectl`, `git`, `.venv-ci/bin/python`) in
  `~/.claude/settings.json` instead of approving each one. Keep `git push` behind a prompt if you want
  to review before anything leaves the machine.
- The SQL Server and web passwords in `ci/local.sh` are the throwaway values from `ci.yml`; the
  database is recreated on every run and is reachable from localhost only.
- Keep the OS patched: `dpkg-reconfigure -plow unattended-upgrades`.

## The web UI without an appliance

`results/compose.yaml` runs SQL Server 2025 Developer edition, creates the database, the schema and the
three logins (`cz_scanner`, `cz_web`, `cz_admin`), and starts the web UI hardened, all on 127.0.0.1:

```sh
cp results/.env.example results/.env          # four strong passwords, and sign-in (docs/sign-in.md)
docker compose -f results/compose.yaml up -d --build
# http://127.0.0.1:8080/ shows the (empty) portfolio

# scan an app into it, static analysis only (mount it under its real folder name)
docker compose -f results/compose.yaml run --rm -v "$PWD/../my-app:/apps/my-app:ro" scan assess /apps/my-app
```

### Admin pages without sign-in

The admin pages need [sign-in](sign-in.md) through an OpenID Connect provider. For development, a lab or
your own machine, **development mode** skips it: set in `results/.env`

```sh
CONTAINERIZER_DEV_NO_AUTH=1
CONTAINERIZER_PUBLIC_URL=http://127.0.0.1:8080   # the address you open in the browser (forms check it)
# optional: who you are and your roles (admin, operator, viewer); default John Doe, admin
CONTAINERIZER_DEV_USER=john.doe@example.com
CONTAINERIZER_DEV_NAME=John Doe
CONTAINERIZER_DEV_ROLES=admin
```

and restart the web UI (`docker compose -f results/compose.yaml up -d`). Opening `/admin` then signs you in
as that person at once. Everything else works as with sign-in: the roles decide what you see, every form
needs its CSRF token, and the change history records the changes as made by that person in development
mode. A red banner on every page says so. The [JSON API](api.md) works with API keys made on
**Admin → API** (access tokens need sign-in).

!!! danger "Never on a shared network"
    Everyone who reaches the web UI is an administrator. The web UI refuses to start in development mode
    on the appliance, and when sign-in (`CONTAINERIZER_OIDC_ISSUER`) is set as well. Keep it on 127.0.0.1,
    or limit who reaches it with the firewall, as for the rest of this server.

## Building the appliance image

```sh
docker build -f appliance/Dockerfile --build-arg VERSION=v0.0.0-dev -t containerizer-appliance:dev .
# disk image (expandable), ISO
docker run --rm --privileged -v /dev:/dev -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/build:/build" \
  --entrypoint /usr/bin/elemental containerizer-appliance:dev build-disk --expandable --local \
  --system containerizer-appliance:dev -n containerizer -o /build
docker run --rm --privileged -v /dev:/dev -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/build:/build" \
  --entrypoint /usr/bin/elemental containerizer-appliance:dev build-iso --local --bootloader-in-rootfs \
  --extra-cmdline "console=tty1 console=ttyS0" -n containerizer -o /build containerizer-appliance:dev
```

A fork that publishes its own images sets `--build-arg IMAGE=ghcr.io/<owner>/containerizer-appliance
--build-arg SIGNER_REPO=<owner>/<repo>`, so its appliances accept only its own signed releases.
`.github/workflows/release.yml` builds, boot-tests (QEMU: firewall, DNS filter, services, sandbox cluster,
registry, roll back) and, on a `vX.Y.Z` tag, pushes, signs and publishes.

## Lab sandbox (k3s, Flux, Git server)

A persistent copy of the appliance's sandbox deployment path on this server, for testing features that
deploy applications to the sandbox through GitOps end to end: the same k3s, Flux and External Secrets
versions and settings as the appliance, a Git server for the output repository, and what the appliance's
`cz-sandbox` timer does. It is not the `sandbox` job of `ci/local.sh` (a throwaway kind cluster
`cz-sandbox`): the two run side by side. The scripts are in [`ci/lab-sandbox/`](../ci/lab-sandbox/); its
state lives in `LAB_DIR` (default `/home/dev/lab-sandbox`):

```sh
mkdir -p ~/lab-sandbox && cp -r ci/lab-sandbox/. ~/lab-sandbox/   # the timer runs sync.sh from where up.sh ran
~/lab-sandbox/up.sh        # install or start everything; idempotent, needs sudo; about 3 minutes the first time
~/lab-sandbox/status.sh
~/lab-sandbox/smoke.sh     # the end-to-end test below
~/lab-sandbox/down.sh      # stop, data kept (--purge: remove the cluster, Gitea and all state)
```

### What runs where

| What | How | Reached at |
| --- | --- | --- |
| k3s v1.37.1+k3s1, the appliance's binary and checksum, single node `lab` | systemd `k3s-lab`, config `/etc/rancher/k3s-lab/config.yaml` | API `https://127.0.0.1:6443`; admin kubeconfig `$LAB_DIR/kubeconfig` (mode 600) |
| Flux v2.10.0 (the appliance's `install.yaml` and checksum, images pinned by digest in `lib.sh`) | k3s, `flux-system` | |
| External Secrets Operator 2.14.0 (the appliance's chart digest and values), ClusterSecretStore `app-secrets` over namespace `containerizer-secrets` | k3s; the store is made by the appliance's own `lib/secret-store.sh` | `secret.sh <remote-key> <json-or-literal>` |
| Gitea 28.3 (rootless, pinned by digest), HTTPS with a certificate from the lab CA | container `lab-git`, runs as `dev`, data in `$LAB_DIR/state/gitea` | `https://lab-git:3001/`: published on 127.0.0.1:3001 and on the Docker bridge address 172.17.0.1:3001 |
| Output repository | Gitea organization `lab`, private | `https://lab-git:3001/lab/sandbox-deployments.git` |
| Traefik (k3s's, as on the appliance) | NodePorts 30080 / 30443 on loopback only, default certificate `*.sandbox.lab.test` from the lab CA | `https://<component>-<app>.sandbox.lab.test` through `127.0.0.1:30443` |
| The `cz-sandbox` equivalent (`sync.sh`) | systemd `lab-sandbox-sync.timer`, every 2 minutes, as `dev` | `systemctl status lab-sandbox-sync.timer`; `sudo systemctl stop lab-sandbox-sync.timer` to pause it |
| Read-only verifier for `containerizer sandbox verify` | ServiceAccount from the output repository's `sandbox/verify-rbac.yaml` | `$LAB_DIR/verifier.kubeconfig` (24-hour token, renewed every 12 hours) |

`$LAB_DIR/secrets.env` (mode 600) holds the Gitea administrator `lab-admin`'s generated password, a
write token for the output repository (`write:repository`) and a read-only token
(`read:repository`, `read:organization`) that Flux uses.

The Git URL is the same everywhere because the GitOps files name it: `/etc/hosts` maps `lab-git` to the
Docker bridge address, CoreDNS in k3s does the same (ConfigMap `coredns-custom`), and Gitea is published
on that address. git on the host trusts the lab CA for this one URL (`http.https://lab-git:3001/.sslCAInfo`
in `~/.gitconfig`); Flux gets it as `ca.crt` next to the token in `<namespace>--cz-git` (on the appliance
the Git servers have public certificates). The appliance's `cz-sandbox` accepts only https URLs, so the
lab uses HTTPS too.

### Differences from the appliance

- **Images come from Docker's image store, not a registry.** k3s runs with `docker: true` (its embedded
  cri-dockerd), so a pod can run any image `docker build` made on this host, and the manifests
  containerizer generates use `imagePullPolicy: IfNotPresent`: nothing is pushed or pulled. The kubelet's
  image garbage collection is off, because the store is shared with the builds and `ci/local.sh`. Pods
  show up in `docker ps` as `k8s_*` containers. The appliance still pushes to its registry at
  `localhost:5000/<path>`.
- The appliance's k3s settings are kept (`servicelb` off, secrets encryption, no anonymous API access),
  except `resolv-conf`, the audit log and `protect-kernel-defaults`, which depend on the appliance's OS.
- Traefik is on loopback NodePorts instead of behind Caddy on 443, without the HTTP-to-HTTPS redirect.
- Flux runs only; there is no Argo CD, so `sync.sh` leaves the Argo CD part out of `verify-rbac.yaml`.
- The k3s system images (pause, CoreDNS, Traefik, metrics-server, local-path, klipper-helm) are pinned
  by the k3s release's tags, as on the appliance, not by digest.

### Firewall

k3s runs on the host network. Its pods reach the host (the API server, Gitea through the Docker bridge)
through `cni0`, so the input chain of `/etc/nftables.conf` gets two accept rules, which `up.sh` adds
to the file and to the running rule set (with `nft add rule`, not by loading the file again: its `flush
ruleset` would also remove Docker's and k3s's tables):

```
    iifname { "cni0", "flannel.1" } accept
    ip saddr { 10.42.0.0/16, 10.43.0.0/16 } accept
```

The API server (6443) and the kubelet (10250) listen on every address and are kept off the network by
the input chain's drop policy. NodePorts answer on loopback only (`nodeport-addresses=127.0.0.1/32`):
Docker-style DNAT traffic to them would pass the forward chain, which accepts by default. Reach Traefik
or Gitea from another machine with SSH port forwarding, e.g. `ssh -L 30443:127.0.0.1:30443 -L
3001:127.0.0.1:3001 dev@<server>`.

To open the sandbox's HTTPS entry to your own subnet instead, limit it in the forward chain first, then let
k3s answer on the server's address too:

```sh
# /etc/nftables.conf, forward chain (and the same with `sudo nft add rule inet filter forward ...` to apply it now,
# without reloading the file: that would drop Docker's tables)
iifname "eth0" ct original proto-dst 30443 ip saddr != $LAB drop
iifname "eth0" ct original proto-dst 30443 meta nfproto ipv6 drop
# /etc/rancher/k3s-lab/config.yaml, then: sudo systemctl restart k3s-lab
kube-proxy-arg:
  - "nodeport-addresses=127.0.0.1/32,<server address>/32"
```

### Pointing a scan or a runner at it

```sh
. ~/lab-sandbox/env.sh
```

| Setting | Value |
| --- | --- |
| Registry (image prefix) | `localhost/lab` (`$LAB_REGISTRY`): images `localhost/lab/<app>/<component>:<tag>`, built and tagged locally, not pushed |
| Output repository | `--output-repo $LAB_OUTPUT_REPO --output-username lab-admin`, write token in `OUTPUT_GIT_TOKEN` |
| `sandbox.env` equivalents | `CZ_SANDBOX_GIT_URL`, `CZ_SANDBOX_GIT_USERNAME`, `CZ_SANDBOX_GIT_TOKEN` (read-only); `sync.sh` puts them in the store |
| Sandbox verification | `--verify-sandbox --kubeconfig $LAB_VERIFIER_KUBECONFIG` (or `containerizer sandbox verify --kubeconfig ...`) |
| Ingress | `--ingress-domain sandbox.lab.test`; verify with `--ingress-address 127.0.0.1:30443 --ingress-ca $LAB_CA` |
| Secrets the apps need | `secret.sh <namespace>--<name> '{"key": "value"}'` |

Two things the lab does not cover yet: `containerizer org` has no Gitea provider (scan sources from
GitHub, GitLab or Azure DevOps and write the output to the lab), and `--no-push-images` does not tag the
gate's image as `<registry>/<app>/<component>:<tag>`, so for local images that tag has to be added
(`docker tag`) by whatever replaces the push.

### The smoke test

`smoke.sh` checks the whole path without a scan: it builds `localhost/lab/smoke:1` (nginx answering 200
on 8080) with `docker build`, writes an app `smoke` into a clone of the output repository in the layout
`containerizer org` writes, generated by containerizer from `examples/ci-demo` with that image
(`smoke_app.py`: `lab/_/smoke/`, its `gitops/flux` tenant, ExternalSecret, GitRepository and
Kustomization, `containerizer.json`, and `sandbox/` from `write_sandbox`), and pushes it. Then Flux syncs
the root Kustomization, `sync.sh` puts `smoke--cz-git` in the store, the app's own Kustomization
deploys it as `smoke-reconciler`, the pods become Ready with no `Pulling` event, and `containerizer
sandbox verify` reads the result back as the verifier:

```
smoke/Demo.Web: healthy - 2/2 ready
sandbox health: healthy=1
```

`smoke.sh --remove` takes the app out of the repository again, and Flux prunes it.
