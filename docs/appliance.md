# Getting started

Containerizer ships as one virtual machine, the appliance: an immutable OS image with the web UI and API,
the scan worker, SQL Server, a sandbox cluster and monitoring. You install it, set up sign-in, and do
everything else in the web UI. This page is the short path from download to the first scan; what the
appliance runs and how to operate it is in [Running the appliance](appliance-admin.md).

## Requirements

- x86-64 VM (or server) with **UEFI** firmware (Secure Boot works: the shim and GRUB are Debian's signed
  ones). Hyper-V: generation 2 with the Secure Boot template **Microsoft UEFI Certificate Authority**, installed
  from the ISO. VMware: EFI firmware.
- 4 vCPU and 16 GB memory or more (SQL Server takes 4 GB, `CZ_MSSQL_MEMORY`), more for parallel builds.
- One disk of **64 GB or more**: 16 GB for the OS snapshots, the rest is the persistent partition.
- Optional, for the [built-in LLM](appliance-admin.md#built-in-llm) (off by default, for sites without an
  LLM server of their own): **40 GB memory or more** (16 GB for the appliance, about 24 GB for the model)
  and **about 20 GB more disk** for the model file. 48 GB and 64 GB let it answer two and three requests at
  once.
- Outbound HTTPS to the hosts on the Firewall page (the image registries the appliance uses are allowed
  by default) and DNS servers from DHCP or `CZ_DNS_SERVERS`.

## Install

Every minor or major [release](https://github.com/olljanat-ai/containerizer/releases) (`vX.Y.0`) has the files
below. A patch release (`vX.Y.Z`, Z > 0) has none: it is an app update that appliances of its series install
from **Admin → System**, so install a new appliance from the series' `vX.Y.0` and let it update itself.

| File | For |
| --- | --- |
| `containerizer-vX.Y.Z.iso` | Installer: boot it, answer the questions on the console. |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Check the downloads (command in the release notes). |

Every hypervisor installs from the ISO, KVM, Proxmox and OpenStack too (releases before 0.17.0 also had a
qcow2 disk image).

Check what you downloaded:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/olljanat-ai/containerizer/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Boot the ISO: the console (screen or serial) shows the installer: the disk to install to (it is
erased), an SSH public key for `root` (optional), and a host name. It installs and restarts; remove the ISO.

For unattended installs, see [Running the appliance](appliance-admin.md#unattended-installs).

## First boot

Sign in as `root` with the password **`containerizer`**, over SSH (`ssh root@<appliance>`) or on the
console. In 0.3.4 the default password is not expired, so change it yourself with `passwd` after the
first sign-in (it is kept like any change). Otherwise, the first sign-in asks for the current password once more and then a new one; SSH closes the
connection after the change if the login did not continue, so sign in again with the new password. Until
the password is changed, an SSH key alone may be refused too. The new password is kept on the persistent
partition, so it survives restarts, upgrades and roll backs.

The first boot created `/etc/containerizer/` with the configuration
files ([configuration files](appliance-admin.md#configuration-files)). Then:

1. Set `CZ_HOSTNAME` in `appliance.env` to the DNS name users will open (usually the FQDN), and register
   `https://<CZ_HOSTNAME>/auth/callback` as the redirect URI of an app registration at your identity
   provider (Entra ID, Okta, Keycloak, ...).
2. Fill in `web.env` (issuer, client id and secret, `CONTAINERIZER_ADMINS`; [sign-in and roles](sign-in.md)). Allow the identity
   provider's host on the Firewall page once you are in (or add it to `egress.json` now: e.g.
   `login.microsoftonline.com`), since the web UI fetches its keys.
3. `systemctl reboot` (or `systemctl restart containerizer-web caddy`).
4. Open `https://<CZ_HOSTNAME>/admin`. With the default certificate from the appliance's own CA, browsers
   warn until you trust its root: `/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt`.
   With `CZ_ACME_EMAIL`, allow `acme-v02.api.letsencrypt.org` on the Firewall page first; the name must
   resolve to the appliance from the internet (TLS-ALPN challenge on 443). For a certificate from your own
   CA, see [HTTPS certificate](appliance-admin.md#https-certificate).
5. **Admin → Firewall**: allow the hosts your scans need (Git servers, package feeds, registries).
6. **Admin → Source control & LLM**: a read-only token for each organization to scan and a write token
   for each output repository ([source-control.md](source-control.md)), and the LLM if scans should ask one.
7. **Admin → Organization scans**: define the scans ([organization scans](scheduled-scans.md)), and
   fill in `sandbox.env` so the sandbox cluster deploys what they generate.

Grafana is at `https://<CZ_HOSTNAME>/grafana/`, user `admin`, password in
`/etc/containerizer/secrets/grafana-admin` (change it in Grafana, or set up sign-in in `grafana.env`:
[Grafana sign-in](sign-in.md)). It opens on the **Containerizer: organization scans** dashboard.

## Next steps

- [Organization scans](scheduled-scans.md): what a scan does and where its results go.
- [Rule review](rule-review.md): approve what the learning loop proposes.
- [How it works](overview.md): how applications are assessed and what is generated.
