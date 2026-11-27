# Bug reports

Sometimes a build or a run fails in the scan's verification because of Containerizer itself, not because of the
application: a generated Dockerfile that cannot work, a setting the tool misread, a `docker` command it put
together wrongly. Administrators can **flag** such a case where they see it and later **export** every flagged
case as one JSON file for whoever maintains Containerizer, with the names you choose replaced.

Nothing is sent anywhere: the export is a file you download and pass on yourself.

## Flag a failed build or run

On an application's page, a component whose build or run failed has **Flag as a Containerizer bug** at the end of
its *Build and run* block, with room for a short note on why it looks like the tool's fault.

![The Build and run block of a failed component, with the note field and Flag as a Containerizer bug](images/results-bug-flag.png#only-light){ .cz-shot }
![The Build and run block of a failed component, with the note field and Flag as a Containerizer bug](images/results-bug-flag-dark.png#only-dark){ .cz-shot }

The case is copied at that moment, because the next scan of the application replaces the component's logs:

- the component's facts (name, project path, role, target framework, verdict) and the application's rating, commit
  and the version that scanned it;
- the verification result and its excerpt;
- every attempt's Dockerfile, `docker build` command and log (up to 300,000 characters each: its start and its end);
- the component's findings (rule, severity, title, evidence).

The application's source code is not copied. Secrets are masked in the logs when the scan stores them. A component
has one open report: flagging it again replaces the copy, and **Remove the flag** deletes it (a report that has
tries is closed and kept instead, see below).

## Bug reports

**Admin → Bug reports** lists the flagged cases with their notes. **Close** keeps a report out of the next export
once it is dealt with, **JSON** exports one report alone, and **Remove** deletes it.

![Admin, Bug reports: the flagged cases, Export JSON and the anonymization keywords](images/admin-bug-reports.png#only-light){ .cz-shot }
![Admin, Bug reports: the flagged cases, Export JSON and the anonymization keywords](images/admin-bug-reports-dark.png#only-dark){ .cz-shot }

## Let the LLM try

Often you already have an idea of what would fix the case. Write it under the report in **Let the LLM try**, in your
own words (*build on the full image and add libgdiplus*), choose whether the LLM may change code, and Containerizer
tests the idea for you:

![Let the LLM try: tries with their ratings, the LLM's changes, and Continue from this try](images/admin-bug-tries.png#only-light){ .cz-shot }
![Let the LLM try: tries with their ratings, the LLM's changes, and Continue from this try](images/admin-bug-tries-dark.png#only-dark){ .cz-shot }

1. The LLM queue (a job of the kind *Bug report try*; it needs no approval unless you tick that kind in the
   queue's settings, since an administrator asked for it) takes the
   application's source at the flagged commit from the scan worker's clone.
2. It builds and runs the component as it is, with the version installed now. If that works, the result is
   **Already fixed** and the LLM is not asked.
3. It asks the LLM for a change that follows your words (below).
4. It builds and runs the component again with that change, and compares.

### What the LLM may change

- **The build plan**, always: the base image, OS packages, environment variables, writable folders, build
  arguments, files removed in the build, the runtime line.
- **The application's code**, when you choose *Code changes: up to 25, 50 or 100 lines*. The LLM first names up to
  three files it needs to read (from the application's file list), then gives edits of those files; together they
  may change at most the lines you allowed. Edits that change more, that do not match the file, or that remove
  what the application does are refused; the LLM gets one more chance, then the try goes on without a code change.

A try makes at most three LLM calls and two builds, so it cannot run for long. The scan's own Dockerfile text is
not edited directly: it follows from the plan.

### Every try is kept, and any of them can be continued

Nothing of a try is thrown away: your words, the LLM's diagnosis, its plan change, the code change as a diff (with
**Download .patch**) and the result stay with the report, and all of it goes into the export. A report that has
tries cannot be removed, only closed; flagging the component again after a new scan closes the old report and
keeps it.

**Continue from this try** under any finished try starts the next one from that try's changes (its plan change and
its code change), not from the flagged commit and not necessarily from the latest try: when the third idea made it
worse, go on from the second. The page shows each try under the one it continues. A continued try takes its
parent's result as its starting point, so it builds once.

### The rating

Each try has a result, compared with where it started, and stars for how far the build and run got:

| Stars | The build and run with the change |
|---|---|
| ★☆☆☆☆ | the build fails |
| ★★☆☆☆ | it builds, the run fails |
| ★★★☆☆ | it builds and runs into a known finding |
| ★★★★☆ | it runs, and stops only at missing external services |
| ★★★★★ | it builds and runs |

| Result | Meaning |
|---|---|
| **Helped** | It builds and runs with the change |
| **Got further** | It still fails, but later than before (more stars) |
| **Did not help** | It fails as before |
| **Worse** | It gets less far than before |
| **Already fixed** | It builds and runs with this version without any change |
| **Nothing to try** | The LLM found no change that does what you wrote (its reasoning is shown) |
| **Not tried** | The source at the flagged commit is gone, the component is no longer built in Linux, Docker is away, or the parent's code change no longer applies |

**Best so far** marks the try to go on from: the most stars, then the smallest change, then the earliest.

A try changes nothing for the application itself: its next scan builds it as before, and the repository is never
written to. What a try found is feedback for whoever fixes Containerizer, and a patch you can apply yourself.

The try needs an LLM (Admin → Source control & LLM) and an organization scan on this machine that still has the
commit; scan and flag the application again when it has moved on.

## System prompts

![System prompts on the Bug reports page: one replaced, with its text, Save and Back to the built-in text](images/admin-system-prompts.png#only-light){ .cz-shot }
![System prompts on the Bug reports page: one replaced, with its text, Save and Back to the built-in text](images/admin-system-prompts-dark.png#only-dark){ .cz-shot }

A system prompt is what Containerizer tells the LLM about its role, for one kind of question. **System prompts**
on the same page shows each of them, and lets an administrator replace the text when the LLM goes wrong in a way
a better instruction would prevent (it removes something it should keep, it reads a rule too strictly):

| Prompt | Used for |
|---|---|
| Assessment and build diagnosis | Component reviews where the rules are unsure, proposals of new rules, the diagnosis of a failed build or run, and the plan change of a bug report try |
| Refactoring patches and Make it A | Every code change the LLM makes for a refactoring order, and the code change of a bug report try |
| Egress reviews | The review of the connections the sandbox blocked |
| Link reviews | Which application an internal-looking destination is |
| Platform migrations | Moving containerized applications from another platform, and the sandbox tester |

- **Save** puts your text in place of the built-in one. The scan worker uses it from its next scan and the LLM
  queue from its next job; nothing restarts. The built-in text stays visible below yours, to compare.
- **Back to the built-in text** removes the replacement. So does saving an empty text.
- The question itself (the evidence, the file, your hint) and the form of the answer are not part of a system
  prompt: an answer must still be the JSON its question asks for, so keep that instruction when you rewrite one.
- A replaced prompt changes every question of its kind, for every application. Answers the LLM gave under the old
  text are not reused: the same question is asked again.
- Replaced prompts go into the export (`replaced_system_prompts`), anonymized like the rest, so the maintainers see
  which wording worked better. A new version of Containerizer does not overwrite your text; go back to the
  built-in one to get its improvements.

## Anonymization keywords

Give the words the export must not carry, one per line: company, product, project, host and people's names.

- Each keyword is replaced everywhere in the export (logs, paths, Dockerfiles, application and component names,
  your notes) by a random word such as `maple-3f9a`.
- The same keyword gets the same word within one file, whatever its case, so the case stays readable: a feed
  host is still the same host in every line.
- Every export draws new words, and the mapping is neither in the file nor kept.
- Longer keywords are replaced first, so `build01.contoso.local` goes as a whole before `contoso`.
- Application and component names are replaced only when they are listed.

Open the file before you send it: a name that is not listed stays.

## The export

**Export JSON** downloads the open reports as `containerizer-bug-reports-<date>.json`:

```json
{
 "format": "containerizer-bug-reports/1",
 "containerizer": "0.54.7",
 "exported_at": "2026-11-27T12:10:00Z",
 "anonymized": {"keywords": 3, "replacements": 41, "how": "each keyword is replaced by one random word, the same within this file"},
 "replaced_system_prompts": {"refactor": "..."},
 "reports": [
  {
   "id": 3, "status": "open", "flagged_at": "2026-11-27T12:04:00", "note": "restore asks a Windows folder",
   "application": "maple-3f9a", "rating": "B", "commit": "abcdef012345", "scanned_with": "0.54.6",
   "component": {"name": "maple-3f9a.Api", "project": "src/maple-3f9a.Api/maple-3f9a.Api.csproj", "role": "web"},
   "verification": {"status": "build-failed", "detail": "..."},
   "attempts": [{"attempt": 1, "stage": "build", "dockerfile_and_command": "...", "log": "..."}],
   "findings": [{"rule": "cert-store", "severity": "config", "title": "...", "evidence": "..."}],
   "tries": [{"id": 412, "continues": null, "hint": "build on the full image and add libgdiplus", "state": "done",
              "outcome": "further", "score": 2, "code_lines_allowed": 0,
              "before": {"status": "build-failed", "steps": "...", "log_tail": "..."},
              "llm": {"diagnosis": "...", "plan_patch": {"base": "full", "add_packages": ["libgdiplus"]}},
              "after": {"status": "run-failed", "steps": "...", "log_tail": "..."},
              "plan_patch_total": {"base": "full", "add_packages": ["libgdiplus"]}, "code_patch": ""},
             {"id": 418, "continues": 412, "hint": "log to the console instead of d:\\logs", "state": "done",
              "outcome": "helped", "score": 5, "best": true, "code_lines_allowed": 50, "code_lines_changed": 7,
              "code_patch": "diff --git ..."}]
  }
 ]
}
```

Reports are kept in the database (`cz.BugReport`, schema 65) until an administrator removes them; only
administrators can flag, read and export them.
