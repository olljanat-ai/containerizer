# Refactoring patches

An application rated **B** needs *targeted code changes*: findings of severity **refactor** such as a
certificate read from the Windows certificate store, Windows authentication, the Event Log, Win32 calls or
hard-coded Windows paths. Every such rule says in plain text how to fix it (its `fix:`), and the
[migration assistant](overview.md#migration-assistant) turns that into guidance. A **refactoring patch** goes
one step further: the LLM makes the changes, and Containerizer applies the patch, checks it with the rules
and builds and runs the changed components before it offers the patch as a download, with how to apply it.

Containerizer never writes to your repository: no branches, no pull requests, and the source control
credentials stay read only. You review the patch, apply it yourself and open the pull request.

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
apply, that file is left unchanged and its findings are *not fixed*. Line endings, the byte order mark and
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

## Limits

- **The LLM can be wrong.** A patch that builds and runs is not a patch that is correct: the build and a
  start-up probe do not run your tests. Review every change.
- **Speed.** On the built-in CPU LLM each file takes five minutes or more, and the verification build takes
  minutes too; an order of a few files takes most of an hour. The queue runs it when its settings allow.
- **Small context.** The LLM sees one file (or part of a large one) and the component's settings, not the
  whole application: changes that span several files (a new option class wired up in `Program.cs`) may be
  left as *not fixed* with a reason, or made in one file only.
- **What is verified** is the component's container as Containerizer generates it, with the
  production services it needs missing (a smoke test in Development mode when they are), not the
  application in its real environment.
