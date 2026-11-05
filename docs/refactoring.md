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
| Admin, Operator | The **Refactoring** box: the orders and their status, and **Make it A** | Every order: the patch, the coloured diff, Download .patch |
| Product owner, Viewer, anyone without sign-in | The orders and their status only | No access |

Patches contain the application's source code, so only operators and administrators see them, like the
other pages that act on the source (organization scans, the LLM queue). The order button posts to the admin
pages (`/admin/refactoring/new`), which check the role and the form's CSRF token; on a results page served
without sign-in the button does not show.

The box shows on applications rated **B**, with one button: [**Make it A**](#make-it-a), one order for every
change the application needs. The narrower orders it replaced on the page (the targeted changes of one component,
or moving one component's data to SQL Server) are still there on the command line (`containerizer refactor
--goal fix|stateless`, with `--component`), and orders made earlier keep showing with their patches. The order needs the assessment's
commit and the repository's clone on this machine: it works for applications that an
[organization scan](scheduled-scans.md) assessed here. For anything else, use the command line on a
checkout.

![The Refactoring box on a B-rated application's results page: the orders and Make it A](images/results-refactoring-box.png#only-light){ .cz-shot }
![The Refactoring box on a B-rated application's results page: the orders and Make it A](images/results-refactoring-box-dark.png#only-dark){ .cz-shot }

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
  calls per order (`--max-calls` on the command line; 40 in an [LLM-heavy window](#llm-heavy-refactoring-orders)). A call has the rules' *why* and *fix*, the evidence
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
apply, that file is left unchanged and its findings are *not fixed*. **An edit that takes away what the
application does is refused the same way**, with the reason: a `Directory.CreateDirectory` or a file write
(`File.Write…`, `File.Create`, `File.Move`, a `FileStream`) that the edit removes and does not write elsewhere
(the folder of an embedded database file may go, when it moves to SQL Server). So is a user name or password it
writes into a file (`User Id=sa`, `Password=…`; a placeholder such as `Password=<from a secret>` is fine), because
credentials come from a secret (`ConnectionStrings__<Name>`). The instructions say the same: never remove a feature to make a
finding go away, keep the application's own database setup, and for Windows integrated security leave the setting
for Windows and let the container's connection string come from the secret. The errors name the first line of the
search text that is not in the file and the file's closest line. One slip is forgiven: models often get
backslashes wrong when they write code into JSON (`"LocalMachine\\My"` in C# comes back with one
backslash), so a search text that matches exactly once with every run of backslashes scaled the same way
applies, with the replacement's backslashes scaled alike. Each answer may be at most 4,096 tokens plus
half of the question's (8,192 at most), so a model that rambles cannot hold a CPU slot for an hour. Line endings, the byte order mark and
the encoding of each file are kept. Package changes go into the component's `.csproj`; for other project
types they are listed in the notes to make by hand.

**The same code is changed once.** A library file used by several components of one application is one call
(the calls are per file). Across orders, of the same application or of others, even in other repositories: an
answer that fixed everything in its file is kept (next to the LLM answer cache), under a key made of the file's
text, its findings (rule, why, fix and evidence lines), the component's `appsettings.json` shown with it, its
language, target framework and packages, not of the application, the component or the file's path. An order that
meets the same key gets that change, moved to where the file is in its own application, without asking the LLM;
if the edits do not apply, the LLM is asked as usual. Each order still verifies its own patched copy, and the
order page says which files had a change reused (*no LLM call*). Changed code, other findings or other packages
make another key: those are asked about. Start "Make it A" with the smallest orders (Admin → Refactoring) and the
ones after them reuse what the shared libraries got.

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

**NuGet package versions are fixed without the LLM.** The LLM sees only the file it edits, so it may add a
package reference at a lower version than a project the component references (or a package it uses) needs.
NuGet refuses that build (NU1605, *Detected package downgrade*). Right after the LLM's edits, a direct reference
below the version of a referenced project is raised to it. A downgrade the build still reports is raised to the
version NuGet names in the next repair round, without an LLM call. The patch's notes list each version raised. The
prompt also lists the packages the referenced projects bring in, so that they are not added again. Since .NET Core 3.0,
ASP.NET Core's own parts (`Microsoft.AspNetCore.HttpOverrides`, `.Mvc`, `.Hosting`, ...) come with the shared
framework, and their NuGet packages end at 2.x. An answer that adds one to such a project does not add it, and
when the build cannot find one (NU1101, NU1102), the reference is removed (outside the Web SDK, a
`FrameworkReference` to `Microsoft.AspNetCore.App` replaces it), without an LLM call.

| Status | Meaning |
| --- | --- |
| Queued | Waiting in the [LLM queue](scheduled-scans.md#the-llm-queue) |
| Generating | The LLM is writing the changes (the page says which file) |
| Verifying | Applying the patch, running the rules, building and running |
| **Verified** | The patch applies cleanly, and every changed component builds and runs |
| **Applies only** | The patch applies cleanly, but a build or a run failed, or could not be done (no Docker, a component that is not built in a Linux container as it is): the log tail says why |
| **Failed** | No patch: the LLM made no usable edits, or the patch did not apply cleanly (never offered) |
| Cancelled | Skipped, or cancelled while it ran, on the LLM queue page |

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
move of that data to SQL Server. It runs on request only:
**Make it A** in the Refactoring box of the results page (operators, administrators and the application's
product owners, with the queue's estimate), or **Make it A: every B application** for administrators (below). A scan
never orders one by itself.

The results page's [migration plan](overview.md#migration-plan) points here from its second wave: the
components that rate A once their code changes are made. For an application with components that cannot run in
a Linux container (no Refactoring box), the plan lists the same changes with the findings to make them by hand,
and shows the components that are ready already in the sandbox.

![The Refactoring box: Make it A with its estimate](images/results-make-it-a.png#only-light){ .cz-shot }
![The Refactoring box: Make it A with its estimate](images/results-make-it-a-dark.png#only-dark){ .cz-shot }

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
files beyond it are *not attempted*. Each pass leaves a quarter of the calls (at most 4) for its repair rounds,
so a patch that does not build always gets a repair round. The order page shows each pass and round (files, calls, changes, the
build and run, the rating), the rating before and after (`B → A: Rating A reached`, or `B → B: 4 of 6 fixed;
still keeps data in Api (Embedded file database)`), the result per finding as the rules see the final patched
copy, and the one patch to download, as for any refactoring patch. Its statuses are the same (verified,
does not build, does not start, ...).

**Reading the order page.** `B → A: Rating A reached` is the goal: the rules rate the patched copy A *and* it
builds and runs, so it is deployed to the sandbox. `B → A` with **A by the rules, but the patched copy does not
build or run** means the code changes remove what kept it from A, but the copy is not A yet and is not deployed: the
errors are under **Verification**; **Fix it with the LLM** orders a repair. **Findings left (they do not keep it
from A)** are configuration findings an A application may still have.

**Build again (no LLM).** A build or run can fail for a reason outside the code: the appliance's firewall blocks
a package mirror (`E: Unable to locate package ...`), a registry was down. Once that is fixed, **Build again (no
LLM)** on the order page (any finished Make it A order with a patch) places a new order with the same patch: it is
applied, built, run and assessed, and deployed to the sandbox when it rates A and runs, as the first time. It makes
no LLM call (no repair round either, and no LLM-heavy chain), so it needs no approval; it still waits for its turn in
the LLM queue (its hours and free requests, as any job). When it still fails, **Fix it with the LLM** on its page is there as usual.

**Newer code starts from the earlier patch.** When the application has a working Make it A patch (it builds,
runs and rates A) for an older commit, a new order for the newer code starts from it. The patch is applied file by
file (with a 3-way merge where git can). The files it still applies to are kept as they are and the LLM is not asked
about them; the files it no longer applies to are put back and edited again, with every file the newer code
needs. Then the copy is verified and assessed as usual, and a second pass takes what is still found. When the
newer code did not touch the patched files, the order makes no LLM call at all. The order page says which order's
patch it started from, how many files were kept and which were edited again. A chain that starts over
(below) does not use the earlier patch again.

**Until it runs in the sandbox (LLM-heavy mode).** With an [LLM-heavy window](source-control.md#llm-heavy-for-a-while)
on the whole application (Admin → Applications), a Make it A order may do more (40 LLM calls, 4 passes, 4 repair
rounds a pass) and stops making LLM calls when the window ends. An order whose copy does not end up running in the
sandbox queues the next one at once, approved and first in the queue, which continues from its patch with what went
wrong: the compiler errors or the run log, or, when it was deployed but failed there, the sandbox's state and
log of each failing component (its failing copy is taken out of the sandbox first: the scan's output goes back). The chain ends when a
copy runs in the sandbox, when the window ends, after 30 orders, or when two orders in a row changed nothing.
Each order's page links the one before and the next.

**A chain stuck on the same errors starts over.** Repairs build on the patch before them, so an early wrong edit
is carried by every order after it. When 3 orders in a row fail with the same errors (the same compiler errors,
or the same run or sandbox error, apart from times and line numbers), the next order starts again from the
original code. Its prompt says what kept failing, and no answer of the stuck attempt is reused. A chain starts
over at most twice; stuck a third time, it stops and says so. This applies to the refactoring orders below too.

<a id="llm-heavy-refactoring-orders"></a>**Refactoring orders in an LLM-heavy window.** With an
[LLM-heavy window](source-control.md#llm-heavy-for-a-while) on the whole application, or on the component of an
order of one component, a refactoring order of chosen findings makes up to 40 LLM calls (files) instead of 8, and
makes no LLM call after the window ends (the files left say *not attempted: the LLM-heavy window ended*). An order
that does not finish the job queues the next one at once, approved and first in the queue:

- its patch does not build or run: a **repair** order (as **Fix it with the LLM**), with the build errors or the run
  log, which carries the findings that are left for after the repair;
- it builds and runs, but findings are left (not attempted, not fixed, or an LLM error): an order for the files of
  those findings, which continues from its patch, so the result is one patch with every change (its subject ends
  in *(continued)*).

The chain ends when every finding is fixed and the patched copy builds and runs, when the window ends, after 30
orders, or when two orders in a row changed nothing. Each order's page says where it is in the chain and links the
one before and the next; the queue's result line ends with *LLM-heavy: continues as #n*.

**Estimates.** The button and the bulk page show the queue's estimate of the first pass (the size of what
it sends, a typical file for each stateful component, at the speed the queue learned); repair rounds and a
second pass, when needed, take more, up to the limit of 16 calls.

**Make it A: every B application** (Admin → Refactoring, administrators) lists every B-rated application with what
changes and its order's estimate (tokens and LLM time), **smallest first**, with the running total of the LLM time
up to each row, so the LLM's time goes to the cheapest wins first; a local LLM gets the most applications to A for
its hours. Applications with an order in the queue already say so and link to it. The ones that a verified patch
makes A already (*Made A by a patch* on the front page: it builds, runs and rates A, merged or not, for the commit
the latest scan assessed) link to that
patch and are not queued again from here (order one on its application page for a new patch). The ones that cannot be ordered
(no commit recorded, source not kept on this machine) are at the bottom with the reason. **Orders under** a number
of tokens each (20,000 to begin with) marks the ones that fit, and **Queue … approved** places one order for each of
them, approved by you at once: they do not wait for approval, whatever the LLM queue's approval policy says, and
run by the queue's settings (hours, idle, parallel requests). Nothing is queued by opening the page.

Tick **Also LLM-heavy mode for these applications, for** (8 hours to begin with, up to 7 days) to turn
[LLM-heavy mode](source-control.md#llm-heavy-for-a-while) on for each application ordered, with the same button:
until the window ends, their orders and the LLM jobs that follow (egress and link reviews) go before every other job
in the LLM queue, approved, and their scans review each of their components. Admin → LLM queue lists the windows,
each with **End now**. Applications that already had an order waiting are not turned LLM-heavy.

![Make it A: every B application, with the LLM-heavy option above the Queue button](images/admin-make-all-a-heavy.png#only-light){ .cz-shot }
![Make it A: every B application, with the LLM-heavy option above the Queue button](images/admin-make-all-a-heavy-dark.png#only-dark){ .cz-shot }

## The sandbox variant

A Make it A order whose patched copy rates A and is verified is **deployed to the sandbox in place of the
application's scan output**, the way an [organization scan](scheduled-scans.md) deploys (the same code): an
organization scan deploys only an application's components that rate A on their own, so a B application has only
those in the sandbox, often none; the patched copy takes the application's place. There is one folder, one Git
history, one namespace, one set of URLs, IdP clients, lab databases and egress decisions per application.

- **Where.** The application's own folder in the output repository of the organization scan that assessed it,
  `<Organization>/<Project>/<Repository>/` (or `<Repository>@<folder>/` for one application of a split
  repository), the folder the scan writes. The scan's output there is replaced, `sandbox/` is regenerated, in one
  commit: `sandbox: <app> runs the Make it A patch of order #<job> (commit <sha>)`; Flux rolls the application
  over to it. Its images go to the appliance's own registry, as the scan's do; the output repository and branch and
  the security gate are that scan's; the output repository's write token is its registered credential. An
  application that no organization scan with an output repository assessed here is not deployed, and the order page
  says so (`no output repository: ...`).
- **The application's name.** Everything an organization scan derives from an application's name is the
  application's own: the **namespace**, the images `<registry>/<app>/<component>`, the Ingress hosts (so the
  application's sandbox URLs), the sandbox IdP clients, the lab services, the `connectivity.yaml` with its approved
  egress and confirmed links, and the NetworkPolicies. The image tag says it is the patch:
  `1.<yyyymmdd>.<hhmm>-refactor.<job>`, a semver pre-release that the application's image automation never picks up.
- **What it records.** `containerizer.json` in the folder has `patched`: the order (`job`), the source commit the
  patch was made for (`commit`), the tag, and `previous_revision`, the output repository's commit before the
  first patch ran there, whose folder is the scan's output. The scan's output is never lost: it stays in the output
  repository's history.
- **Data.** Only the components that rate A are deployed, with no uploaded dev database: the patched copy uses
  **the application's lab database** (when the [lab services](lab-services.md) are on), the one its scan output
  uses, as the lab services are per namespace.
- **Health.** The runner reads the application's namespace back with a read-only kubeconfig
  (`CONTAINERIZER_SANDBOX_KUBECONFIG`, optional `CONTAINERIZER_SANDBOX_CONTEXT`; on the appliance the
  verifier account of `sandbox/verify-rbac.yaml`, below) and records it in the order: **running in the
  sandbox**, **failing in the sandbox**, or *deployed, health not checked* without a kubeconfig. From then on the
  scan's sandbox checks of the application see the patched copy, and the results page's Migration plan says the
  sandbox runs the patch.
- **Kept up to date.** The queue runner checks again what runs: a copy whose health is not known yet
  (*deployed, health not checked*: the cluster could not be read in time, as after a restart) every 10 minutes,
  one running or failing every hour, a few per pass. While an administrator has the application's sandbox turned
  off, the order says **sandbox turned off**; when it is on again, the health is read at once. The application's
  folder in the output repository decides whether the copy is there: when it no longer runs the order's patch
  (a scan or another order wrote it), the order says **removed from the sandbox**; when the latest removed copy of
  an application turns out to run there after all, it is back, with the date (**Back**) on the order page.
- **Scans.** A scan that assesses the commit the patch was made for leaves the folder as it is (the patch is newer
  than what the scan would write) and still records its assessment; its result says the folder runs the patch. A
  scan that assesses **newer code** writes its own output into the folder, and the order's state becomes
  **replaced by newer code**: the patch was made for code the application no longer is. Without scheduled scans,
  the code an order was made for stays the code the scans know, and so does the patched copy.
- **One per application.** A newer order's patched copy overwrites the older one in place (on the same commit or
  another; it keeps the scan's commit to go back to), and the older order's state becomes **replaced by newer
  code**, with the newer order.
- **Try again** on the application's results page (administrators and operators, when a component is not in
  the sandbox) builds the patched copy again: the same patch on the same commit, generated, built, checked and
  deployed with the version the appliance runs now (no LLM), within a few minutes by the queue runner. A scan does
  not: it leaves the patched copy as it is. Use it after an update that lets a component through, such as a gate
  fix. If the new build cannot be deployed, what ran stays and the page says why.
- **Remove from the sandbox** on the order page (administrators, operators, the application's product owners)
  puts the scan's output back: the queue runner, within a few minutes, checks the folder out of
  `previous_revision` (no folder there, as when no component rated A on its own: the folder goes), regenerates
  `sandbox/` and commits; the sandbox runs the application as the scan deployed it. The patch stays available on its
  order (in the results database), and a new Make it A order for the new code starts from it (above).

**Variants of before: `<app>-refactor-<job>`.** Until 0.10.0 patched copies ran beside the application, in a folder
`<Organization>/<Project>/<Repository>-refactor-<job>/` and a namespace of their own. The LLM queue runner's
housekeeping moves them: the latest one of each application that still runs is generated again under the
application's name from the source at its commit with its patch (its images as they were built: nothing is built
again) into the application's folder, the `-refactor-` folders are deleted and `sandbox/` regenerated, in one
commit; Flux prunes the old namespaces (with their lab database). The order keeps its history; its sandbox
namespace, folder and URL become the application's (the old ones under *Before* on the order page). One that cannot
be moved (its source is gone) is taken out of the sandbox, and **Build again (no LLM)** on its order deploys it in
place. Variants deployed before 0.9.1 had an expiry date, which no longer applies.

The folder also holds the order's patch, `make-it-a.patch`, so developers who look in the output repository find
the code change next to its manifests (`git am` it on the commit it was made for).

The results page shows the patched copy's state next to the order, with its URL (**open ↗**, the application's own)
while it runs; the front page lists it under **Made A by a patch**.

**Images without a registry.** In a lab whose sandbox cluster shares the image builder's Docker image store (k3s
with `--docker` on the machine that builds), set `CONTAINERIZER_LOCAL_IMAGES=1` for the scan worker and the LLM
queue runner: each image is then tagged with its deploy reference (`docker tag`, no push) and the manifests run it
with `imagePullPolicy: IfNotPresent`. Such images have no digest or signature (they need a registry). Without the
setting (the appliance), the images are pushed to the appliance's own registry.

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
- for the [sandbox deployment](#the-sandbox-variant) of patched copies: clones the scan's output repository into its scratch space
  with the registered write token, pushes the patched copy's images to the appliance's registry, reads the lab
  services that are on, and reads its health with the kubeconfig of the read-only verifier
  account, `/run/containerizer/sandbox-verifier.kubeconfig`. `cz-sandbox` (root, every 2 minutes) gives that
  account its Role in every namespace Containerizer generated (`sandbox/verify-rbac.yaml`: workloads, pods,
  their logs and events, the namespace's Flux Kustomization; no Secrets, nothing cluster-wide) and writes the
  kubeconfig with a 24-hour token (`root:containerizer`, 0640). A namespace new to the sandbox gets its Role at the
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
- **A patched copy in the sandbox** runs with the application's lab database (the one its scan output uses): it
  shows that the application starts and answers as a stateless container, not that its data or its integrations work.
