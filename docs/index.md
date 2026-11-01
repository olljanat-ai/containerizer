---
title: Containerizer for Kubernetes
description: Find out which of your applications can run as Linux containers on Kubernetes, why, and get hardened builds and manifests for the ones that can.
hide:
  - navigation
  - toc
---

<div class="cz-hero" markdown>

# Which of your applications can run in containers?

Containerizer scans your whole application portfolio, rates every application from **A** (container-ready: a modern
stack that moves to containers without code changes) to **E** (not feasible: stays on Windows), explains each obstacle with a fix and references, and generates hardened
Dockerfiles and Kubernetes manifests for everything that can move. Then it proves them by building,
running and deploying them in its own sandbox cluster.

[Get started](appliance.md){ .md-button .md-button--primary }
[How it works](overview.md#how-it-works){ .md-button }
[GitHub](https://github.com/olljanat-ai/containerizer){ .md-button }

</div>

![Containerization readiness overview: business units, products and applications with their ratings](images/results-overview.png#only-light){ .cz-shot .cz-hero-shot }
![Containerization readiness overview: business units, products and applications with their ratings](images/results-overview-dark.png#only-dark){ .cz-shot .cz-hero-shot }

<div class="cz-stats" markdown>

<div markdown>
**33 / 33**
<span>challenge applications rated correctly by the rules alone</span>
</div>

<div markdown>
**0**
<span>AI calls needed for that, in 32 seconds</span>
</div>

<div markdown>
**A–E**
<span>a rating per application, with the why behind it</span>
</div>

<div markdown>
**1 VM**
<span>web UI, scanner, SQL Server, k3s sandbox, registry, Grafana</span>
</div>

</div>

## Why Containerizer?

<div class="grid cards" markdown>

-   :material-scale-balance:{ .lg .middle } **Rules first, AI last**

    ---

    A data-driven rule set classifies every component, so results are repeatable, explainable and
    free. An LLM is asked only about what the rules are unsure of, and its answers are validated first.

    [:octicons-arrow-right-24: How it works](overview.md#how-it-works)

-   :material-school:{ .lg .middle } **Learns by doing**

    ---

    When unsure, it builds and runs the container, matches failures, patches the plan and retries.
    Fixes that work become rule proposals that a person approves, so the next run needs no retries.

    [:octicons-arrow-right-24: Rule review](rule-review.md)

-   :material-shield-check:{ .lg .middle } **Secure by default**

    ---

    Chiseled images, non-root, read-only root filesystem, no capabilities, seccomp, Pod Security
    `restricted`, and a gate that scans with Trivy and Grype. Every exception is recorded with its reason.

    [:octicons-arrow-right-24: Security gate](overview.md#security-gate)

-   :material-source-branch:{ .lg .middle } **Your whole organization**

    ---

    Schedule scans of Azure DevOps, GitHub and GitLab organizations. New repositories are found
    automatically, and the A-rated ones are pushed and committed for Argo CD or Flux.

    [:octicons-arrow-right-24: Organization scans](scheduled-scans.md)

-   :material-kubernetes:{ .lg .middle } **Proven in a sandbox**

    ---

    A built-in k3s cluster deploys what was generated and reports "deployed and healthy" or exactly why
    not, even with a restored copy of the application's development database.

    [:octicons-arrow-right-24: The sandbox cluster](scheduled-scans.md#the-sandbox-cluster)

-   :material-wrench:{ .lg .middle } **A migration plan, not just a verdict**

    ---

    Every blocker maps to a Linux replacement: System.Drawing to SkiaSharp, WCF to CoreWCF, Windows
    Service to a worker service, with packages, steps and checks.

    [:octicons-arrow-right-24: Migration assistant](overview.md#migration-assistant)

-   :material-server-security:{ .lg .middle } **Runs in your network**

    ---

    One immutable appliance with signed upgrades and roll back, only SSH and HTTPS in, and outgoing
    traffic blocked except for hosts an admin allows. Use Claude or your own self-hosted LLM.

    [:octicons-arrow-right-24: Appliance](appliance.md) · [The LLM](source-control.md#the-llm)

-   :material-account-lock:{ .lg .middle } **Built for management and audit**

    ---

    Single sign-on, admins, product owners and operators, an audit log of every change, an access log,
    trends over time, and SBOMs with licences and CVEs per package.

    [:octicons-arrow-right-24: Sign-in and roles](sign-in.md)

</div>

## See it in action

<div class="cz-feature" markdown>

<div markdown>

### Every application, explained

Open an application to see its components, the rating, the main obstacles, and for each finding what
to change, why, and where to read more. Everything links back to the rule that decided it.

[How it works :octicons-arrow-right-24:](overview.md#how-it-works)

</div>

![Application page with components, findings, fixes and references](images/results-application.png#only-light){ .cz-shot }
![Application page with components, findings, fixes and references](images/results-application-dark.png#only-dark){ .cz-shot }

</div>

<div class="cz-feature cz-reverse" markdown>

<div markdown>

### From blocker to a concrete plan

The migration assistant turns each blocking finding into a Linux-compatible replacement with
packages to add and remove, steps and checks. What can't move is marked "keep on
Windows" instead of being forced.

[Migration assistant :octicons-arrow-right-24:](overview.md#migration-assistant)

</div>

![Migration assistant with replacements and steps](images/results-migration-assistant.png#only-light){ .cz-shot }
![Migration assistant with replacements and steps](images/results-migration-assistant-dark.png#only-dark){ .cz-shot }

</div>

<div class="cz-feature" markdown>

<div markdown>

### Watch the portfolio move

Trends show how ratings change over time per business unit and product, so you can see the effect
of each fix and each newly learned rule.

[Install the appliance :octicons-arrow-right-24:](appliance.md)

</div>

![Readiness trends over time](images/results-trends.png#only-light){ .cz-shot }
![Readiness trends over time](images/results-trends-dark.png#only-dark){ .cz-shot }

</div>

<div class="cz-feature cz-reverse" markdown>

<div markdown>

### Scans that run themselves

Define organization scans on the admin pages, by day and time or on demand. **Discover** first lists
the projects, repositories and latest commits without cloning anything, so deprecated ones can be
disabled before the full scan. Every repository shows its last result, and skipped ones are listed with
the reason, such as "no source code".

[Organization scans :octicons-arrow-right-24:](scheduled-scans.md)

</div>

![Repositories of an organization scan, skipped ones disabled with the reason](images/admin-repositories-disabled.png#only-light){ .cz-shot }
![Repositories of an organization scan, skipped ones disabled with the reason](images/admin-repositories-disabled-dark.png#only-dark){ .cz-shot }

</div>

<div class="cz-feature" markdown>

<div markdown>

### A person approves what the AI learns

Fixes the learning loop discovers arrive as rule proposals with their evidence. Approve, edit or
reject them; approved rules make the next run faster and AI-free.

[Rule review :octicons-arrow-right-24:](rule-review.md)

</div>

![Rule review with a proposed rule and its evidence](images/rule-review-detail.png#only-light){ .cz-shot }
![Rule review with a proposed rule and its evidence](images/rule-review-detail-dark.png#only-dark){ .cz-shot }

</div>

<div class="cz-feature cz-reverse" markdown>

<div markdown>

### Know what's inside every image

CycloneDX SBOMs for each built image, licences checked against your policy, and CVEs per package
across the whole portfolio.

[SBOM, licences and CVEs :octicons-arrow-right-24:](sbom.md)

</div>

![SBOM portfolio with licences and CVEs](images/sbom-portfolio.png#only-light){ .cz-shot }
![SBOM portfolio with licences and CVEs](images/sbom-portfolio-dark.png#only-dark){ .cz-shot }

</div>

<div class="cz-feature" markdown>

<div markdown>

### Operations you can see

The scan worker exports Prometheus metrics about scans, the process and the VM, with a Grafana
dashboard included in the appliance.

[Metrics and Grafana :octicons-arrow-right-24:](scheduled-scans.md#metrics-and-grafana)

</div>

![Grafana dashboard of the scans](images/grafana-scans-dashboard.png#only-light){ .cz-shot }
![Grafana dashboard of the scans](images/grafana-scans-dashboard-dark.png#only-dark){ .cz-shot }

</div>

## Try it

<div class="cz-cta" markdown>

Download the appliance from the latest release, boot it, and point it at your source control.

[Install the appliance](appliance.md){ .md-button .md-button--primary }
[How it works](overview.md#how-it-works){ .md-button }
[Releases](https://github.com/olljanat-ai/containerizer/releases){ .md-button }

</div>
