# syntax=docker/dockerfile:1.7
# containerizer appliance: an immutable Debian 13 OS image built with the Elemental toolkit. The same image
# is the upgrade (`elemental upgrade --system oci:...`) and the source of the ISO and disk images.
# Build from the repository root:
#   docker build -f appliance/Dockerfile --build-arg VERSION=v1.2.3 -t containerizer-appliance .
ARG DEBIAN=debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
ARG GOLANG=golang:1.26-trixie@sha256:a050dcceee6eb9bf110151662dfac7662f3bec40927c7dee48731e3d92083d42

# ---------------------------------------------------------------------------- Elemental CLI from source
FROM ${GOLANG} AS elemental
ARG ELEMENTAL_VERSION=v2.3.5
ARG ELEMENTAL_COMMIT=66a0d43154760440b674c94949cc212fb236b423
RUN git clone --depth 1 --branch "${ELEMENTAL_VERSION}" https://github.com/rancher/elemental-toolkit.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${ELEMENTAL_COMMIT}"
WORKDIR /src
# go:embed needs the feature tarballs (pkg/features/generated), as in upstream `make build`
RUN go generate ./... && CGO_ENABLED=0 go build -trimpath -ldflags "-w -s \
      -X github.com/rancher/elemental-toolkit/v2/internal/version.version=${ELEMENTAL_VERSION} \
      -X github.com/rancher/elemental-toolkit/v2/internal/version.gitCommit=${ELEMENTAL_COMMIT}" \
      -o /elemental .

# ---------------------------------------------------------------------------- the OS
FROM ${DEBIAN} AS os
# Fixed ids for everything that owns files on the persistent partition
RUN groupadd --system --gid 912 docker \
 && groupadd --system --gid 910 caddy \
 && useradd --system --uid 910 --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy \
 && useradd --system --uid 911 --gid nogroup --home-dir /nonexistent --shell /usr/sbin/nologin dnsmasq
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    linux-image-amd64 systemd systemd-sysv systemd-timesyncd systemd-resolved dbus-daemon polkitd \
    dracut-core dracut-live dracut-network dracut-squash \
    grub2-common grub-efi-amd64-signed shim-signed \
    btrfs-progs btrfsmaintenance dosfstools e2fsprogs fdisk gdisk parted lvm2 dmsetup mtools squashfs-tools xorriso \
    rsync findutils kmod kbd tzdata less vim-tiny bash-completion \
    ca-certificates curl gpg iproute2 iputils-ping nftables iptables conntrack dnsmasq-base \
    openssh-server openssh-client \
    apparmor docker.io docker-cli docker-buildx git caddy \
    python3 python3-venv \
    xz-utils zstd \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* /etc/mdadm /boot/initrd.img* /etc/machine-id /var/lib/dbus/machine-id \
 && ln -s /etc/machine-id /var/lib/dbus/machine-id \
 && echo > /etc/motd \
 && ln -sf /usr/bin/grub-editenv /usr/bin/grub2-editenv \
 && systemctl mask systemd-journald-audit.socket \
 && test -x /usr/bin/docker && command -v dockerd \
 && test "$(id -u caddy)" = 910 && test "$(id -u dnsmasq)" = 911 && test "$(getent group docker | cut -d: -f3)" = 912

# k3s (single binary) and the Flux install manifest, verified by checksum; cosign for upgrade signatures
ADD --chmod=0755 --checksum=sha256:92b94582eb7b34a8cf532e6006842b9ed215a6783cf56a3dd6271fd35243b2c0 \
    https://github.com/k3s-io/k3s/releases/download/v1.37.1%2Bk3s1/k3s /usr/bin/k3s
ADD --chmod=0644 --checksum=sha256:a8c838ccd9be5d30eba9df87cd229b7c4eb80c0049fba1bc3b9840829f267f28 \
    https://github.com/fluxcd/flux2/releases/download/v2.10.0/install.yaml /var/lib/rancher/k3s/server/manifests/flux.yaml
ADD --chmod=0755 --checksum=sha256:424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa \
    https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 /usr/bin/cosign
# ORAS: the scan worker attaches each pushed image's SBOM to it as an OCI referrer (docs/sbom.md)
ADD --chmod=0644 --checksum=sha256:66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0 \
    https://github.com/oras-project/oras/releases/download/v1.3.6/oras_1.3.6_linux_amd64.tar.gz /tmp/oras.tar.gz
RUN tar -xzf /tmp/oras.tar.gz -C /usr/bin --no-same-owner oras && chmod 0755 /usr/bin/oras && rm /tmp/oras.tar.gz \
 && ln -s k3s /usr/bin/kubectl && ln -s k3s /usr/bin/crictl
# External Secrets Operator Helm chart 2.14.0 (ghcr.io OCI artifact, fetched by its content digest and
# checked), served to the k3s Helm controller from the API server (static/charts); see
# /var/lib/rancher/k3s/server/manifests/external-secrets.yaml
ARG ESO_CHART=external-secrets/charts/external-secrets
ARG ESO_CHART_DIGEST=sha256:0a6d9e91b1ff50adfdbf24b50b582babfa7c5b7df42b21974ca4b3fb88ee5e34
RUN set -eu; mkdir -p /var/lib/rancher/k3s/server/static/charts; \
    f=/var/lib/rancher/k3s/server/static/charts/external-secrets-2.14.0.tgz; \
    token=$(curl -fsS "https://ghcr.io/token?scope=repository:${ESO_CHART}:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'); \
    curl -fsSL -H "Authorization: Bearer ${token}" -o "$f" "https://ghcr.io/v2/${ESO_CHART}/blobs/${ESO_CHART_DIGEST}"; \
    echo "${ESO_CHART_DIGEST#sha256:}  $f" | sha256sum -c -; chmod 0644 "$f"

COPY --from=elemental /elemental /usr/bin/elemental

# The application: Python packages pinned by hash, the code and rules read-only in /usr
COPY appliance/requirements.lock /tmp/requirements.lock
RUN python3 -m venv /usr/lib/containerizer/venv \
 && /usr/lib/containerizer/venv/bin/pip install --no-cache-dir --no-compile --require-hashes --only-binary=:all: \
      -r /tmp/requirements.lock \
 && rm /tmp/requirements.lock
COPY containerizer/ /usr/lib/containerizer/app/containerizer/
COPY rules/ /usr/lib/containerizer/app/rules/
RUN mv /usr/lib/containerizer/app/rules/learned /usr/lib/containerizer/learned-seed \
 && ln -s /var/lib/containerizer/learned /usr/lib/containerizer/app/rules/learned \
 && echo /usr/lib/containerizer/app > "$(/usr/lib/containerizer/venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/containerizer.pth" \
 && /usr/lib/containerizer/venv/bin/python -m compileall -q /usr/lib/containerizer/app/containerizer \
 && /usr/lib/containerizer/venv/bin/python -c "import containerizer.webui, containerizer.admin, containerizer.sysagent, yaml, pymssql, jwt"

# The appliance's configuration, units and scripts
COPY appliance/rootfs/ /
COPY monitoring/prometheus/containerizer-alerts.yml /usr/lib/containerizer/prometheus/
COPY monitoring/grafana/ /usr/lib/containerizer/grafana/dashboards/
RUN chmod 0755 /usr/lib/containerizer/bin/* /usr/libexec/elemental-checker/containerizer \
 && chmod 0600 /etc/rancher/k3s/config.yaml \
 && mkdir -p /etc/tmpfiles.d \
 && for f in $(grep -l '/etc/resolv\.conf' /usr/lib/tmpfiles.d/*.conf | grep -v containerizer); do \
      ln -sf /dev/null "/etc/tmpfiles.d/$(basename "$f")"; done \
 && systemd-sysusers \
 && test "$(id -u containerizer)" = 900 && test "$(id -u cz-web)" = 901 \
 && systemctl enable systemd-networkd.service systemd-resolved.service ssh.service docker.service caddy.service \
      containerizer-firstboot.service containerizer-firewall.service containerizer-dns.service \
      containerizer-dns-upstream.path containerizer-addresses.service \
      containerizer-sysagent.path containerizer-sysagent-status.service containerizer-sysagent-status.timer \
      containerizer-mssql.service containerizer-db-init.service containerizer-web.service \
      containerizer-worker.service containerizer-registry.service \
      containerizer-prometheus.service containerizer-grafana.service \
      k3s.service containerizer-sandbox.timer containerizer-lab.timer

# Elemental: snapshots, layout, boot assessment, initrd
COPY appliance/elemental/snapshotter.yaml /etc/elemental/config.d/snapshotter.yaml
COPY appliance/elemental/config.yaml /etc/elemental/config.yaml
COPY appliance/elemental/dracut.conf /etc/dracut.conf.d/50-elemental-initrd.conf
RUN elemental --debug init -f
COPY appliance/elemental/bootargs.cfg /etc/elemental/bootargs.cfg
COPY appliance/oem/ /system/oem/
RUN mkdir -p /usr/lib/elemental/bootloader \
 && cp /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed /usr/lib/elemental/bootloader/grubx64.efi \
 && cp /usr/lib/shim/shimx64.efi.signed /usr/lib/elemental/bootloader/shimx64.efi \
 && cp /usr/lib/shim/mmx64.efi /usr/lib/elemental/bootloader/mmx64.efi

ARG VERSION=dev
ARG IMAGE=ghcr.io/olljanat-ai/containerizer-appliance
ARG SIGNER_REPO=olljanat-ai/containerizer
RUN echo "IMAGE_TAG=\"${VERSION}\"" >> /etc/os-release \
 && printf 'CZ_OS_IMAGE=%s\nCZ_SIGNER_REPO=%s\n' "${IMAGE}" "${SIGNER_REPO}" > /usr/lib/containerizer/appliance.conf \
 && sed -i "s#oci:ghcr.io/olljanat-ai/containerizer-appliance:latest#oci:${IMAGE}:latest#" /etc/elemental/config.yaml

LABEL org.opencontainers.image.title="containerizer appliance" \
      org.opencontainers.image.description="Immutable OS image (Elemental toolkit, Debian 13) running the containerizer web UI, scan worker, SQL Server, k3s sandbox cluster with Flux, local registry, Prometheus and Grafana" \
      org.opencontainers.image.source="https://github.com/olljanat-ai/containerizer" \
      org.opencontainers.image.version="${VERSION}"
CMD ["/bin/bash"]
