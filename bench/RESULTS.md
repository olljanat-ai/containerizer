# Results on the containerization challenge

Scored against [`labels.yaml`](labels.yaml) (33 apps, hand-labelled from each scenario's README and code).
Run with `python -m containerizer bench [--technique T --model M]`.

## Classification: techniques and models

| Technique | Model | Rating accuracy | Easy/hard split | Blocker precision | Blocker recall | Feasible components | Claude calls | Cost (USD) | Time (s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rules | none | **1.00** | 0.97 | 1.00 | 1.00 | 1.00 | 0 | 0 | 32 |
| hybrid | claude-haiku-5-5 | 1.00 | 0.97 | 1.00 | 1.00 | 1.00 | 11 | 0.11 | 267 |
| hybrid | claude-sonnet-5-5 | 1.00 | 0.97 | 1.00 | 1.00 | 1.00 | 11 | 1.00 | 139 |
| ai+rules | claude-haiku-5-5 | 0.94 | 0.91 | 1.00 | 1.00 | 1.00 | 33 | 0.18 | 199 |
| ai+rules | claude-sonnet-5-5 | 1.00 | 0.97 | 1.00 | 1.00 | 1.00 | 33 | 2.35 | 173 |
| ai-only | claude-haiku-5-5 | 0.91 | 0.94 | 0.96 | 1.00 | 0.98 | 33 | 0.18 | 220 |

The Opus 5.5 and Fable 5.1 runs, and the Sonnet AI-only run, are still in progress; this table is updated as they finish.

Notes:

- *Rating accuracy* counts a rating as right when it is one of the labelled ratings (some apps are
  honestly C-or-D). *Easy/hard split* is whether the app lands in A–C versus D–E; the one miss is
  an app labelled C/D that both rules and Claude rate C.
- The rules-only score was 0.97 until command-aware reachability was added: in `document-control`,
  the Indexer's proprietary `dtzip.dll` is used only by the optional `--import-doctrack` command.
  Hybrid mode with Haiku already caught that. The rule engine now catches it on its own, without Claude.
- Hybrid mode asks Claude only about the 11 components whose confidence is low (unknown packages,
  uncertain rules). It costs less than any whole-app AI technique and is never worse than rules.
- AI-only (Claude sees the project inventory and README, but no rules) is the weakest. It
  over-blocks one feasible component and misrates three apps.

## Verification: building and running the generated containers

`python -m containerizer verify <challenge> --learn` builds every component the rules call
feasible and runs it hardened (read-only root filesystem, non-root, all capabilities dropped,
no-new-privileges). The first full pass, before the fixes it led to, ended like this:

| Outcome | Components |
| --- | --- |
| runs and answers HTTP / stays up | 18 |
| runs, stops only at a missing database or other external service | 6 |
| runtime finding the static rules missed (System.Management) | 1 |
| build or run failed | 18 |
| not built (blocker, .NET Framework, library, test) | 59 |

Failures from that pass became generator features and failure rules: Docker Hub rate limits
(mirror fallback), NU1605 restore downgrades (portable publish), XML-doc and enum values taken for
folders, Windows paths and listen URLs in `appsettings.json` (env overrides), file-only Serilog
(stdout), and certificate-store lookups (finding + Development-mode smoke test). A second pass with
these fixes is next.
