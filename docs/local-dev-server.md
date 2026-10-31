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
| `release.yml` appliance | Docker + buildx, KVM, `qemu-system-x86`, `qemu-utils`, `ovmf`, `zstd`; the Elemental toolkit is built inside `appliance/Dockerfile`, so it needs no install | `appliance` |

Not needed: Node.js (the repository has no JavaScript build), Syft as a binary (it runs as the
`anchore/syft` container), and cosign / oras unless you test `sbom attach` or release signing by hand.

## Hardware

x86_64 only: the SQL Server image, OVMF and the appliance are amd64.

| | Fast set | Everything (`all`) | With Ollama |
| --- | --- | --- | --- |
| CPU | 4 cores | 8+ cores | 8+ cores, or a GPU |
| RAM | 16 GB | 32 GB | 64 GB on CPU, or a 24 GB GPU for a 30B model |
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
  qemu-system-x86 qemu-utils ovmf zstd nftables unattended-upgrades

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

Without uv the script falls back to `python3 -m venv` with Debian's 3.13, which works for development
but is not exactly what CI runs.

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

- SQL Server is published on `127.0.0.1:1433` only, and the web UI smoke test uses port 18080 instead
  of 8080, so nothing on the server's network can reach them.
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
      tcp dport 22 accept
    }
  }
  EOF
  systemctl enable --now nftables && systemctl restart docker   # Docker re-adds its own tables
  ```

- **SSH**: key login only. In `/etc/ssh/sshd_config.d/hardening.conf` set `PasswordAuthentication no`
  and `PermitRootLogin no`, then `systemctl reload ssh`.
- **Ollama** listens on `127.0.0.1:11434` only; leave `OLLAMA_HOST` unset unless you put TLS and a key in
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
