# Refactoring patches

An application rated **B** needs *targeted code changes*: findings of severity **refactor** such as a
certificate read from the Windows certificate store, Windows authentication, the Event Log, Win32 calls or
hard-coded Windows paths. Every such rule says in plain text how to fix it (its `fix:`), and the
[migration assistant](overview.md#migration-assistant) turns that into guidance. A **refactoring patch** goes
one step further: the LLM makes the changes, and Containerizer applies the patch, checks it with the rules
and builds and runs the changed components before it offers the patch as a download, with how to apply it.

Containerizer never writes to your repository: no branches, no pull requests, and the source control
credentials stay read only. You review the patch, apply it yourself and open the pull request.

![A verified refactoring patch: the order, Download .patch and the result per finding, as the rules see the patched copy](images/admin-refactoring-patch.png#only-light){ .cz-shot }
![A verified refactoring patch: the order, Download .patch and the result per finding, as the rules see the patched copy](images/admin-refactoring-patch-dark.png#only-dark){ .cz-shot }

## Who can order one

| Role | On the application's results page | Admin → Refactoring |
| --- | --- | --- |
| Admin, Operator | The **Refactoring** box: the orders and their status, and **Request a refactoring patch** | Every order: the patch, the coloured diff, Download .patch |
| Product owner, Viewer, anyone without sign-in | The orders and their status only | No access |

Patches contain the application's source code, so only operators and administrators see them, like the
other pages that act on the source (organization scans, the LLM queue). The order button posts to the admin
pages (`/admin/refactoring/new`), which check the role and the form's CSRF token; on a results page served
without sign-in the button does not show.

The box shows on applications rated **B**. Choose **All components that need changes** or one component, and
whether to **also change code for configuration findings** (below). The order needs the assessment's
commit and the repository's clone on this machine: it works for applications that an
[organization scan](scheduled-scans.md) assessed here. For anything else, use the command line on a
checkout.

![The Refactoring box on a B-rated application's results page: the orders and Request a refactoring patch](images/results-refactoring-box.png#only-light){ .cz-shot }
![The Refactoring box on a B-rated application's results page: the orders and Request a refactoring patch](images/results-refactoring-box-dark.png#only-dark){ .cz-shot }

## What is sent to the LLM

- **Refactor findings** of the chosen components, and **configuration findings in the same files** (they
  often go with them: the LocalMachine store finding and the certificate store finding are one change).
  With *also change code for configuration findings*, configuration findings in other files too (drive
  paths as defaults, credentials, local folders): many of these are better solved in the deployment, and
  the LLM may say so instead of changing code.
- Never *blocker* or *rewrite* findings (a port, or a part that stays on Windows), findings whose fix is to
  keep the part on Windows, findings in library code the component never reaches, and findings whose
  evidence names no file. The order's page lists them under *Findings not sent to the LLM*.
- **One LLM call per file**, with every finding in that file, never the whole application, and at most 8
  calls per order (`--max-calls` on the command line). A call has the rules' *why* and *fix*, the evidence
  lines, the file (or, when it is large, the part around the evidence lines), the component's
  `appsettings.json`, its target framework and packages, and strict instructions. Each call is kept under
  about 12,000 tokens so that it fits a slot of the [built-in CPU LLM](appliance-admin.md#built-in-llm).

The LLM answers with **structured edits**, not with a diff (diffs written by LLMs are often malformed):

```json
{"edits": [{"file": "src/Jobs/Bank/BankGatewayClient.cs",
            "search": "using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);",
            "replace": "..."}],
 "new_files": [], "package_changes": [{"action": "add", "package": "...", "version": "..."}],
 "fixed": ["cert-store-localmachine-code"], "not_fixed": [{"rule": "...", "reason": "..."}],
 "notes": "Mount the certificate from a Secret and set Bank__CertificatePath."}
```

Containerizer applies the edits itself: each search text must occur **exactly once** in the file, and only
the files shown may be edited (new files stay inside the application folder). An answer that does not apply
is sent back once with the errors ("not found", "occurs 3 times: include more lines"); if it still does not
apply, that file is left unchanged and its findings are *not fixed*. The errors name the first line of the
search text that is not in the file and the file's closest line. One slip is forgiven: models often get
backslashes wrong when they write code into JSON (`"LocalMachine\\My"` in C# comes back with one
backslash), so a search text that matches exactly once with every run of backslashes scaled the same way
applies, with the replacement's backslashes scaled alike. Each answer may be at most 4,096 tokens plus
half of the question's (8,192 at most), so a model that rambles cannot hold a CPU slot for an hour. Line endings, the byte order mark and
the encoding of each file are kept. Package changes go into the component's `.csproj`; for other project
types they are listed in the notes to make by hand.

The changes become one commit in a scratch copy ("Containerizer: &lt;app&gt;: &lt;findings fixed&gt;", author
`Containerizer <containerizer@localhost>`), and the patch is `git format-patch` of it, so `git am` applies it
as a commit with that message.

## How it is verified

The patch is applied to a second, **clean copy at the assessed commit**: `git apply --check`, then
`git am`. Then:

1. **The rules run again** on the patched copy. Each finding shows whether it is *gone from this file*, in
   *fewer places* or *still found*, and any new finding of the changed components is listed: check whether
   the patch caused it.
2. **Each changed component is built and run** with the same build-and-run step as the scans
   ([verify](overview.md#self-learning-loop)): the generated Dockerfile, a hardened container, an HTTP probe.

| Status | Meaning |
| --- | --- |
| Queued | Waiting in the [LLM queue](scheduled-scans.md#the-llm-queue) |
| Generating | The LLM is writing the changes (the page says which file) |
| Verifying | Applying the patch, running the rules, building and running |
| **Verified** | The patch applies cleanly, and every changed component builds and runs |
| **Applies only** | The patch applies cleanly, but a build or a run failed, or could not be done (no Docker, a component that is not built in a Linux container as it is): the log tail says why |
| **Failed** | No patch: the LLM made no usable edits, or the patch did not apply cleanly (never offered) |
| Cancelled | Skipped on the LLM queue page |

A failure to reach the LLM, or a source that is gone, is a failed attempt of the queue job: it is tried
again up to three times (the LLM queue page shows the error), then the order fails. A commit that is no
longer in the clone (the repository moved on, and the scan worker keeps shallow clones) fails with a
message: scan the repository again and order a new refactoring.

The page shows every change as a coloured diff per file, here a real patch the dev server's CPU LLM wrote
for the challenge app `expense-claims`:

![The coloured diff of a refactoring patch: the certificate loaded from a mounted file instead of the Windows store](images/admin-refactoring-diff.png#only-light){ .cz-shot }
![The coloured diff of a refactoring patch: the certificate loaded from a mounted file instead of the Windows store](images/admin-refactoring-diff-dark.png#only-dark){ .cz-shot }

## How to apply it

The order's page has **Download .patch** (`<app>-<component>-containerizer.patch`, or `-all-` for every
component) and the steps:

```sh
git checkout -b containerizer-refactor <assessed commit>
git am --keep-cr < expense-claims-ExpenseClaims.Jobs-containerizer.patch
# or, if your branch has moved on since the assessed commit:
git apply --3way expense-claims-ExpenseClaims.Jobs-containerizer.patch
```

`--keep-cr` keeps Windows line endings in files that have them (without it `git am` drops them and the
patch does not apply). Then review every change, build and run your tests, set the configuration the notes
mention (paths, certificates, credentials as Kubernetes Secrets), push the branch and open a pull request
yourself.

![How to apply a refactoring patch: git checkout, git am, review, test and open the pull request yourself](images/admin-refactoring-apply.png#only-light){ .cz-shot }
![How to apply a refactoring patch: git checkout, git am, review, test and open the pull request yourself](images/admin-refactoring-apply-dark.png#only-dark){ .cz-shot }

## Make it A

**Make it A** is one order for everything that keeps a B-rated application from A: its refactor findings,
its configuration findings that name a file, and, for the server components that keep their own data, the
move of that data to SQL Server (the same guidance as **Make it stateless**). It runs on request only:
**Make it A** in the Refactoring box of the results page (operators, administrators and the application's
product owners, with the queue's estimate), or **Make all B apps A** for administrators (below). A scan
never orders one by itself.

![The Refactoring box: an order with its tokens and time, Make it A with its estimate, and a stateless patch that was already made offered instead of a new order](images/results-make-it-a.png#only-light){ .cz-shot }
![The Refactoring box: an order with its tokens and time, Make it A with its estimate, and a stateless patch that was already made offered instead of a new order](images/results-make-it-a-dark.png#only-dark){ .cz-shot }

Where an order of the same kind is already waiting, running or has a patch, the box offers that order (its
status, **Open the patch**, **Download .patch** and the commit it was made for) instead of a new one;
**Request a new one** is for code that has changed since.

The order is one `refactor` job (goal `rating-a`) that loops in the queue runner:

1. **Generate.** The LLM is asked about every file with findings, as for a refactoring patch; the files of
   a stateful component that open its embedded database get the stateless guidance.
2. **Apply and verify.** Everything changed so far becomes one commit for the assessed commit; it is applied
   to a clean copy, and the changed components are built and run.
3. **Repair.** When a build or run fails, a repair round in the same job gives the LLM the compiler errors
   (or the run log), the files they are in and the patch, and the combined patch is verified again: at most
   **2 repair rounds** a pass.
4. **Assess again.** The patched copy is assessed with every rule. A is reached when it rates A and builds
   and runs.
5. **Second pass.** Still B with findings left (still found by the rules, or a component that still keeps
   its data) and LLM calls left: one more pass on what remains, then steps 2 to 4 again. At most **2 passes**.

Every LLM call of the job, retries and repair rounds included, counts against its limit of **16 calls**;
files beyond it are *not attempted*. The order page shows each pass and round (files, calls, changes, the
build and run, the rating), the rating before and after (`B → A: Rating A reached`, or `B → B: 4 of 6 fixed;
still keeps data in Api (Embedded file database)`), the result per finding as the rules see the final patched
copy, and the one patch to download, as for any refactoring patch. Its statuses are the same (verified,
does not build, does not start, ...).

**Estimates.** The button and the bulk page show the queue's estimate of the first pass (the size of what
it sends, a typical file for each stateful component, at the speed the queue learned); repair rounds and a
second pass, when needed, take more, up to the limit of 16 calls.

**Make all B apps A** (Admin → Refactoring, administrators): a confirmation page lists every B-rated
application with what changes, its estimate, and whether it will wait for approval under the
LLM queue's approval policy (Admin → LLM queue), with the total; **Queue** places one order per
application (an application that already has the same order waiting is left alone). Nothing is queued by
opening the page.

## The sandbox variant

A Make it A order whose patched copy rates A and is verified is **deployed to the sandbox beside the
original**, never in its place, the way an [organization scan](scheduled-scans.md) deploys (the same code):

- **Its own name.** The patched copy's folder is `<app>-refactor-<job>` (a DNS label of at most 63
  characters), and everything that an organization scan derives from an application's name derives from it:
  the **namespace** `<app>-refactor-<job>`, the images `<registry>/<app>-refactor-<job>/<component>`, the
  Ingress hosts, the sandbox IdP clients and the lab services, so the variant shares nothing with the
  original or with another order. The image tag is `1.<yyyymmdd>.<hhmm>-refactor.<job>`, a semver pre-release
  that the original's image automation never picks up.
- **Where.** A sibling folder of the original in the output repository of the organization scan that
  assessed the application, `<Organization>/<Project>/<Repository>-refactor-<job>/`, with `sandbox/`
  regenerated, in one commit; Flux (or Argo CD) deploys it from there. The registry, output repository and
  branch, image pull secret, security gate and *Push images* are that scan's; the output repository's write
  token is its registered credential. An application that no organization scan with an output repository
  assessed here is not deployed, and the order page says so (`no output repository: ...`).
- **Data.** Only the components that rate A are deployed, with no uploaded dev database: the variant gets
  a **new, empty lab database** of its own (when the [lab services](lab-services.md) are on), as a new
  application would.
- **Health.** The runner reads the variant's namespace back with a read-only kubeconfig
  (`CONTAINERIZER_SANDBOX_KUBECONFIG`, optional `CONTAINERIZER_SANDBOX_CONTEXT`; on the appliance the
  verifier account of `sandbox/verify-rbac.yaml`, below) and records it in the order: **running in the
  sandbox**, **failing in the sandbox**, or *deployed, health not checked* without a kubeconfig. The
  original's sandbox results on its results page stay as they are: the variant is not a sandbox check of the
  application and teaches the learning loop nothing.
- **Expiry and removal.** A variant expires after **7 days** (`CONTAINERIZER_SANDBOX_VARIANT_DAYS`). **Remove
  from the sandbox** on the order page (administrators, operators, the application's product owners) asks for
  its removal; the queue runner takes expired and requested variants out of the output repository within a few
  minutes (the folder deleted, `sandbox/` regenerated, one commit: the cluster removes the namespace) and records
  it: **removed** or **expired**. The patch stays available.

The results page shows the variant's state next to the order, with its URL (**open ↗**) while it runs.

**Images without a registry.** When the organization scan's *Push images* is off and the sandbox cluster
shares the image builder's Docker image store (a lab: k3s with `--docker` on the machine that builds), set
`CONTAINERIZER_LOCAL_IMAGES=1` for the scan worker and the LLM queue runner: each image is then tagged with its
deploy reference (`docker tag`, no push) and the manifests run it with `imagePullPolicy: IfNotPresent`. Such
images have no digest, signature or SBOM attestation (they need a registry). Without the setting, nothing
changes: with *Push images* on the images are pushed (the appliance pushes to its own registry).

## The command line

```sh
containerizer refactor path/to/app [--component NAME] [--out DIR] [--include-config] [--max-calls 8] [--no-verify]
containerizer refactor path/to/app --queue [--sql ...]
```

Without `--queue` it runs at once with the LLM of the environment (`CONTAINERIZER_LLM_BASE_URL` and
`CONTAINERIZER_MODEL` for a self-hosted one; [the LLM](source-control.md#the-llm)), and writes the patch and
a summary (`<app>-<component>-containerizer.json`: every finding's result, the verification, the payload)
to `--out`. The application folder must be a git checkout for `git am` to work: the patch is made for its
`HEAD` commit, and uncommitted changes are not in it. A folder without git gets a patch for
`git apply -p1` in that folder. With `--queue` the order goes to the LLM queue in SQL Server (`--sql` or
`CONTAINERIZER_SQL`), or to `llm-queue.json` in `--out`, which `containerizer llm-queue --file` works through.

`--goal rating-a` runs [Make it A](#make-it-a) on the checkout (the loop, the repair rounds and the second
pass; `--max-calls` is then the limit of the whole order, 16 by default); the command line never deploys a
sandbox variant.

## On the appliance

The LLM queue runner (`containerizer-llm-queue`) carries out the orders. For them it

- reads the scan worker's clones (`/var/lib/containerizer/worker/scan-<id>/repos/<app>`) read only, and makes
  its scratch copies with `git clone --shared` in `/var/lib/containerizer/refactor`, the only folder it may
  write to besides the LLM answer cache. It reads no other folder: a job that names another source is
  refused (`CONTAINERIZER_REFACTOR_SOURCES`), so a row in the database cannot make it read the machine's
  files;
- is in the **docker** group, like the scan worker, to build and run the patched components. The docker
  group is root-equivalent: the runner builds the same repositories' code in the same hardened containers
  as the scan worker, which is why the appliance is a dedicated machine with an egress allow-list
  ([appliance](appliance.md)). Without Docker the patches are *applies only*.
- for [sandbox variants](#the-sandbox-variant): clones the scan's output repository into its scratch space
  with the registered write token, pushes the variant's images to the appliance's registry, reads the lab
  services that are on, and reads the variant's health with the kubeconfig of the read-only verifier
  account, `/run/containerizer/sandbox-verifier.kubeconfig`. `cz-sandbox` (root, every 2 minutes) gives that
  account its Role in every namespace Containerizer generated (`sandbox/verify-rbac.yaml`: workloads, pods,
  their logs and events, the namespace's Flux Kustomization; no Secrets, nothing cluster-wide) and writes the
  kubeconfig with a 24-hour token (`root:containerizer`, 0640). A new variant's namespace gets its Role at the
  next run of `cz-sandbox`; the runner waits for it within its health check (15 minutes,
  `CONTAINERIZER_SANDBOX_VARIANT_TIMEOUT`).

## Limits

- **The LLM can be wrong.** A patch that builds and runs is not a patch that is correct: the build and a
  start-up probe do not run your tests. Review every change.
- **APIs the component cannot use.** Models suggest APIs of newer frameworks than the component targets
  (on a `net6.0` component, Qwen3-Coder used `X509CertificateLoader`, which is .NET 9 and later). The build
  catches it: such a patch is *applies only*, with the compiler error in the log tail. **Fix it with the
  LLM** on the order page asks again with the errors; Make it A does so by itself (at most 2 rounds a pass).
- **Speed.** On the built-in CPU LLM each file takes five minutes or more, and the verification build takes
  minutes too; an order of a few files takes most of an hour. The queue runs it when its settings allow.
- **Small context.** The LLM sees one file (or part of a large one) and the component's settings, not the
  whole application: changes that span several files (a new option class wired up in `Program.cs`) may be
  left as *not fixed* with a reason, or made in one file only.
- **What is verified** is the component's container as Containerizer generates it, with the
  production services it needs missing (a smoke test in Development mode when they are), not the
  application in its real environment.
- **Make it A** stops at its limits (16 LLM calls, 2 passes, 2 repair rounds a pass): an application whose
  findings need more stays B, and the order says what is left. The rating after is the rules' rating of the
  patched copy and the build and run of its components, not a test of the application.
- **A sandbox variant** runs the patched code with a new, empty lab database: it shows that the application
  starts and answers as a stateless container, not that its data or its integrations work.
