# SBOMs, licences and CVEs per package

Every image a scan builds gets a **software bill of materials** (SBOM) in CycloneDX JSON. Each package
in it is checked against a **licence policy** and gets the **vulnerabilities** the security gate's image
scan found in it. The SBOM is written next to the component's generated files in the output repository
(`sbom.cdx.json`), stored with the results, and shown in
the web UI and the [API](api.md). A denied licence fails the gate, so the component is not deployed.

![Dependencies and licences](images/sbom-portfolio.png)

The web UI shows a *Packages* column per component on the application page, every package with its
licence, policy status and CVEs on the component page (with *Download CycloneDX JSON*), and licences and
CVEs across the portfolio under **Dependencies and licences**.

## How an SBOM is made

**Image SBOM.** [Syft](https://github.com/anchore/syft) reads the built image from the local Docker
daemon: OS packages (dpkg, apk, rpm) with the licences
from their copyright files, .NET packages from the `*.deps.json` files of the application and the
runtime, npm, Python, Java and Go packages.

**NuGet licences.** Syft does not read NuGet licences, so Containerizer looks them up in each
package's `.nuspec` on the NuGet feed (`sbom.nuget_feed`, the v3 service index; nuget.org by default):
the licence expression when there is one, else the licence URL of older packages, mapped to an SPDX
identifier where the URL names one licence unambiguously (`licenses.nuget.org/MIT`, the Apache and
Open Source Initiative pages, the old .NET Library licence). Answers are cached under `.work/` so a
package version is looked up once. The licence found is also written into the SBOM file.
`nuget_licenses: false` turns this off for runners without access to the feed; private feeds that
need credentials are not queried (those packages show as *unknown*).

**Source SBOM.** For components that are not built, the scan stores the packages the component's project files declare, including those of the projects it references:

- a **lock file** gives every runtime package with its exact version: `package-lock.json` (npm,
  lockfile v2/v3 also carry the licence; development packages are left out) or `packages.lock.json`
  (NuGet, when the project restores with a lock file);
- otherwise the declared references (`PackageReference`, `packages.config`, `package.json`
  dependencies, `requirements.txt`, ...). A version range or floating version (`8.0.*`, `^1.2.0`) is
  kept as written and left out of the package URL; transitive packages appear only in the image SBOM.

Nothing from the repository is executed. Source SBOMs have no CVE data: nothing was scanned. Turn
them off with `sbom.source: false`. On the component page and in the API, the image SBOM wins when
both exist for the latest assessment.

## Licence policy

The policy is in [`rules/60-security.yaml`](../rules/60-security.yaml) under `sbom:`.

Each package's licence is normalised to an SPDX expression where the data allows it. Several
licences listed on one package all apply (`A AND B`): a Debian package lists the licence of every
file it ships. An expression is judged as written: `A OR B` passes when either passes, `A AND B`
needs both, and `WITH <exception>` is judged by the licence it modifies.

```yaml
sbom:
  os_packages: report         # report | evaluate
  licenses:
    deny: []                  # fail the gate
    warn: ['AGPL(-.*)?', 'GPL(-.*)?', 'SSPL(-.*)?', 'CC-BY-NC(-.*)?', 'BUSL(-.*)?|Elastic-2\.0|Commons-Clause']
    allow: ['LicenseRef-public-domain', 'LicenseRef-Microsoft-NET-Library']
    unknown: report           # report | warn | deny
    accepted:                 # exceptions with a reason and an optional expiry
      - {package: 'Ghostscript\.NET', reason: 'separate commercial licence, contract 2026-114', expires: 2027-06-30}
```

The lists hold regular expressions matched against each whole SPDX identifier (case-insensitive), so
`GPL(-.*)?` matches `GPL-2.0-only` and `GPL-3.0-or-later` but not `LGPL-2.1-only`. The result per
package is one of:

| Status | Meaning |
| --- | --- |
| **Allowed** | an SPDX licence the lists do not deny or flag, or one on `allow` |
| **Review** (`warn`) | the policy asks for a decision, for example a copyleft licence |
| **Denied** | the policy does not allow it: the security gate fails |
| **Unknown** | no licence found, only a link to a licence page, or a name that is not an SPDX identifier (`unknown:` decides whether that warns or fails) |

Shown but **not counted**: OS packages of the base image (unless `os_packages: evaluate`; the
copyright files make glibc read "GPL AND LGPL", which says little about an application that runs on
it), the application's own assembly, and packages with an accepted exception (until it expires).
SPDX identifiers are recognised from [`rules/spdx-licenses.yaml`](../rules/spdx-licenses.yaml), a copy
of the SPDX License List.

## CVEs per package

The gate's image scan (Trivy and Grype, merged; see [Security gate](../README.md#security-gate))
reports each finding with its package URL. Findings are matched to SBOM packages by package URL
(ignoring qualifiers such as `distro=`), else by name and version. A vulnerable package the SBOM does
not list is added as its own row (*found by the vulnerability scan*), so no CVE is dropped. The SBOM
does not change what fails the gate on vulnerabilities: that is still `scan.fail_on` and
`scan.allowlist`.

## In the registry

A scan attaches the SBOM to each image it pushes with [ORAS](https://oras.land), which the appliance
includes: an OCI referrer artifact of type `application/vnd.cyclonedx+json`, addressed by the image
digest (list it with `oras discover <image>@<digest>`, fetch it with `oras pull`). The component page
shows whether it was attached, or why not (for example a registry that does not accept referrers).
