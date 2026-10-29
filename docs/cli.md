# oxaudit-cli reference

Every subcommand and option of `oxaudit-cli`, taken from its `--help` output
(`oxaudit 0.2.6`). `oxaudit-cli <command> --help` prints the same text for
the binary you have installed, and is authoritative if the two ever differ.
The [README](../README.md#command-line) shows the common workflows; this page
is the complete list.

```text
oxaudit-cli [OPTIONS] <COMMAND>
```

`-q`/`--quiet` is accepted by every command and suppresses progress output on
stderr; report output on stdout is unaffected. `-h`/`--help` and
`-V`/`--version` behave as usual.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran to completion; nothing at or above the failure threshold |
| `1` | Ran to completion; findings at or above `--fail-on` (or `--fail-on-new`, `--min-*` thresholds) |
| `2` | Usage error: bad path, flag or format |
| `3` | The scan or command itself failed |

## Shared values

**Output formats** (`--format` on `scan`, `history`, `deps`, `image` and
`monitor`; default `text`):

| Value | Output |
| --- | --- |
| `text` | Human-readable summary, grouped by file |
| `json` | oxAudit's own finding list |
| `sarif` | SARIF 2.1.0, for GitHub code scanning and most CI viewers |
| `oxaudit-json` | The full canonical run graph |
| `cyclonedx` | CycloneDX 1.6 inventory |
| `spdx` | SPDX 2.3 inventory |
| `openvex` | OpenVEX assertions |
| `cyclonedx-vex` | CycloneDX VEX assertions |

**Severities** (`--fail-on`, `--fail-on-new`): `none`, `info`, `low`,
`medium`, `high`, `critical`. `none` never fails on findings and is the
default everywhere except `scan --staged`: reporting does not break a build
until someone asks it to.

## Commands

| Command | Purpose |
| --- | --- |
| [`scan`](#scan) | Scan source files for dangerous patterns and leaked secrets |
| [`history`](#history) | Scan Git history for secrets committed at any point, including in files deleted long ago |
| [`deps`](#deps) | Resolve lockfiles and check every pinned package against OSV |
| [`image`](#image) | Scan a container image, firmware archive or binary tree with the native scanner, including its OS package database |
| [`export`](#export) | Re-export a stored run in a standards format |
| [`runs`](#runs) | List stored runs |
| [`benchmark`](#benchmark) | Measure the scanners against the committed ground-truth corpus |
| [`rule-pack`](#rule-pack) | Install, list, enable, disable, remove or update rule packs in a pack store |
| [`import`](#import) | Import a report's external claims (SARIF, CycloneDX VEX, OpenVEX) into a findings database |
| [`vex`](#vex) | Trust imported VEX documents and turn their claims into triage suggestions |
| [`advisory-db`](#advisory-db) | Build, inspect or refresh the local advisory database |
| [`languages`](#languages) | List the language grammars compiled into this binary |
| [`hook`](#hook) | Install, remove or inspect the pre-commit secrets hook |
| [`external-benchmark`](#external-benchmark) | Score against the OWASP Benchmark |
| [`monitor`](#monitor) | Re-match stored dependency inventories against a local advisory database and report the delta |
| [`compliance`](#compliance) | Assess project evidence against built-in readiness profiles, record reviewer decisions and compile PDF, HTML, Markdown, CSV or JSON reports |

## scan

```text
oxaudit-cli scan [OPTIONS] [PATH]
```

`PATH` is the directory to scan. With `--staged` it only locates the
repository and defaults to the current directory.

| Option | Default | Meaning |
| --- | --- | --- |
| `--staged` | off | Scan the staged Git index — what a commit would record — for secrets instead of the working tree. In memory only, so `--format` is limited to `text` and `json`, and `--fail-on` defaults to `high`. Intended for pre-commit hooks; see [`hook`](#hook) |
| `--format <FORMAT>` | `text` | Output format |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--fail-on <SEVERITY>` | `none` (`high` with `--staged`) | Exit 1 when a finding at this severity or higher is reported |
| `--baseline <FILE>` | — | A previous `--format json` report; findings present in it are pre-existing, the rest are new |
| `--fail-on-new <SEVERITY>` | `none` | Exit 1 only for findings this change introduced, at this severity or higher. Requires `--baseline` |
| `--db <DB>` | in memory | Keep the run in this database so the desktop app can open it. Without it the scan leaves nothing behind |
| `--no-secrets` | off | Skip secret detection |
| `--no-patterns` | off | Skip dangerous-pattern detection |
| `--include-git` | off | Scan inside `.git` as well |
| `--follow-symlinks` | off | Follow symbolic links only when their canonical targets remain in the project |
| `--max-file-size <KB>` | `1024` | Skip files larger than this many kilobytes (see below) |
| `--ignore-dir <NAME>` | — | Directory name to ignore. Repeatable |
| `--ignore-invalid-policy` | off | Run even when the project's policy file is invalid |
| `--rule-pack-file <FILE>` | — | Validate and apply this rule-pack file for this run only, never installing it. Repeatable; fixtures resolve beside the file |
| `--rule-pack <ID>` | — | Apply these pack ids from the store named by `--rule-pack-db`. Explicit selection applies the pack as stored, enabled or not |
| `--rule-pack-db <FILE>` | — | Rule-pack store holding the packs `--rule-pack` selects |

A file larger than `--max-file-size` is not read at all: it produces no
findings and claims no rule coverage, and the JSON summary counts it in
`filesSkipped` rather than `filesScanned`. A clean result therefore says
nothing about such files; raise the limit to include them. A value of `0` is
treated as `1`, so the option cannot silently skip every file.

## history

```text
oxaudit-cli history [OPTIONS] <PATH>
```

`PATH` is a Git repository, or any directory inside one, whose history to scan.

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <DB>` | — | Save the historical Git-object run for reload and standards exports |
| `--format <FORMAT>` | `text` | Output format |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--fail-on <SEVERITY>` | `none` | Exit 1 when a finding at this severity or higher is reported |
| `--baseline <FILE>` | — | A previous `history --format json` report to compare against |
| `--fail-on-new <SEVERITY>` | `none` | Exit 1 only for findings this run added over `--baseline` |
| `--validate-secrets` | off | Send each found credential to its own provider (fixed endpoints, TLS) and record whether it was accepted. Opt-in: a default run never puts a credential on the wire |

## deps

```text
oxaudit-cli deps [OPTIONS] <PATH>
```

`PATH` is the directory to search for lockfiles.

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <DB>` | — | Persist this run and complete advisory receipts in a shared database |
| `--advisory-db <FILE>` | — | Answer advisories from this local advisory database (built with `advisory-db update`) instead of the OSV API. Works offline |
| `--offline` | off | Reuse a validated receipt from `--db`; never contact providers |
| `--baseline <FILE>` | — | Previous complete dependency JSON report |
| `--fail-on-new <SEVERITY>` | `none` | Gate only advisory/package/version identities absent from `--baseline` |
| `--format <FORMAT>` | `text` | Output format, including canonical standards exports |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--fail-on <SEVERITY>` | `none` | Exit 1 when a vulnerability at this severity or higher is reported |
| `--ignore-dir <NAME>` | — | Directory name to ignore. Repeatable |

## image

```text
oxaudit-cli image [OPTIONS] <PATH>
```

`PATH` is a saved docker/OCI image tar, an OCI layout directory, a firmware
archive, any binary file or tree — or a registry reference
(`registry.example.com/ns/repo:tag`), whose manifest and layers are pulled
directly.

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <DB>` | — | Save the scan receipt to this database for later reload/export |
| `--format <FORMAT>` | `text` | Output format; standards exports use the saved canonical graph |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--fail-on <SEVERITY>` | `none` | Exit 1 when a vulnerability at this severity or higher is reported |
| `--advisory-db <FILE>` | — | Answer distribution-package advisories from this local advisory database, with no network |
| `--offline` | off | Never contact advisory providers: advisories come only from `--advisory-db`. A registry reference still downloads the image; this flag governs advisory lookups |

## export

```text
oxaudit-cli export [OPTIONS] --db <DB> --run <RUN>
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <DB>` | required | Database holding the run |
| `--run <RUN>` | required | Run to export |
| `--format <FORMAT>` | `sarif` | One of `sarif`, `oxaudit-json`, `cyclonedx`, `spdx`, `openvex`, `cyclonedx-vex` |
| `-o`, `--output <FILE>` | stdout | Write here |

## runs

```text
oxaudit-cli runs [OPTIONS] --db <DB>
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <DB>` | required | Database to list runs from |
| `--kind <KIND>` | — | Explicit canonical run listing: `source`, `dependencies`, `binary`, `image`, `history` or `all`. Omit it to keep the source project summary format |
| `--limit <LIMIT>` | `20` | Most runs to list |
| `--json` | off | Emit JSON instead of a table |

## benchmark

```text
oxaudit-cli benchmark [OPTIONS]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--corpus <DIR>` | `benchmarks/corpus` | Corpus directory holding `suite.json` and the fixtures |
| `--json` | off | Emit the full report as JSON instead of a table |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--min-precision <PERCENT>` | — | Exit 1 if precision falls below this percentage |
| `--min-recall <PERCENT>` | — | Exit 1 if recall falls below this percentage |

## rule-pack

Every `rule-pack` subcommand takes `--db <FILE>`, the rule-pack store
database (required).

| Subcommand | Usage | Meaning |
| --- | --- | --- |
| `install` | `rule-pack install --db <FILE> <PATH>` | Validate a pack TOML file and install (or replace) it in the store. Fixtures must sit beside the file |
| `list` | `rule-pack list --db <FILE> [--json]` | List the packs in a store; `--json` emits JSON instead of a table |
| `enable` | `rule-pack enable --db <FILE> <ID>` | Enable a pack for default application (desktop scans) |
| `disable` | `rule-pack disable --db <FILE> <ID>` | Disable a pack for default application (desktop scans) |
| `remove` | `rule-pack remove --db <FILE> <ID>` | Remove a pack from the store |
| `update` | `rule-pack update --db <FILE> --feed <URL> [--only <ID>]… [--json]` | Install or update packs from a feed: an index URL listing packs, each a digest-verified zip of `pack.toml` and its fixtures. `--only <ID>` restricts the update to that pack id and is repeatable; `--json` emits the outcome as JSON |

Enabled and disabled state governs default application in desktop scans;
`scan --rule-pack <ID>` applies a selected pack regardless of that state.

## import

```text
oxaudit-cli import [OPTIONS] --db <FILE> <PATH>
```

Imports a report's external claims into a findings database. `PATH` is a
SARIF 2.1.0, OpenVEX or CycloneDX VEX file. Inventory-only SBOM import stays
in the desktop Export Center.

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <FILE>` | required | Findings database holding the imported claims run |
| `--json` | off | Emit JSON (run id, format, content hash, claim counts) instead of text |

## vex

Turns trusted imported VEX documents into triage suggestions. Suggestions
never change reviews automatically ([ADR 0003](architecture/adr/0003-trusted-external-vex-claims.md)).

| Subcommand | Usage | Meaning |
| --- | --- | --- |
| `claims` | `vex claims --db <FILE> [--json]` | List imported claim documents and their trust state |
| `trust` | `vex trust --db <FILE> --sha <SHA256> --by <NAME> [--note <TEXT>]` | Grant trust to one imported document by its content hash, as shown by `vex claims`. `--by` records who granted it and `--note` why |
| `revoke` | `vex revoke --db <FILE> --sha <SHA256>` | Revoke a document's trust grant; its suggestions stop appearing |
| `suggest` | `vex suggest --db <FILE> --run <ID> [--json]` | Map trusted claims against the advisories of a stored dependency run |

`--db` is the findings database holding the imported runs.

## advisory-db

See [the advisory database guide](advisory-database.md) for coverage and
matching rules.

| Subcommand | Usage | Meaning |
| --- | --- | --- |
| `update` | `advisory-db update --db <FILE> [--ecosystem <NAME>]… [--source <URL>] [--json]` | Download OSV's ecosystem dumps and build or refresh the database. Parent directories are created owner-only. `--ecosystem` adds an ecosystem to the defaults and is repeatable (for example `--ecosystem Debian:12 --ecosystem 'Alpine:v3.20'`); `--source` replaces OSV's published bucket with a mirror; `--json` emits the build report as JSON |
| `status` | `advisory-db status --db <FILE> [--json]` | Show what the database covers and how fresh it is |

## languages

```text
oxaudit-cli languages
```

Lists the language grammars compiled into this binary. A language without
one is scanned on text alone.

## hook

| Subcommand | Meaning |
| --- | --- |
| `hook install` | Write, or idempotently refresh, the oxAudit block in `.git/hooks/pre-commit`, preserving any hook already there |
| `hook uninstall` | Remove the oxAudit block from the pre-commit hook, leaving the rest of the hook — and the file, when anything else remains — untouched |
| `hook status` | Report whether the hook is installed and the exact command it runs |

The hook runs `scan --staged`.

## external-benchmark

```text
oxaudit-cli external-benchmark [OPTIONS]
```

Scores against the OWASP Benchmark: ground truth oxAudit did not write.

| Option | Default | Meaning |
| --- | --- | --- |
| `--path <PATH>` | `benchmarks/external/owasp-benchmark` | Directory holding the fetched OWASP Benchmark checkout |
| `--json` | off | Emit the full report as JSON instead of a table |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--min-score <INDEX>` | — | Exit 1 if the Youden index over covered categories falls below this |

## monitor

```text
oxaudit-cli monitor [OPTIONS] --db <DB> --advisory-db <DB>
```

Re-matches stored dependency inventories against a local advisory database
and reports advisories the stored runs did not report. The stored runs are
never modified.

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <DB>` | required | Findings database holding the stored dependency runs to monitor |
| `--advisory-db <DB>` | required | Local advisory database to re-match against |
| `--update` | off | Refresh the advisory database first, for exactly the ecosystems the monitored inventories use |
| `--source <URL>` | OSV bucket | Dump base for `--update` (a mirror, or a local test server). Ignored without `--update` |
| `--run <ID>` | latest completed dependency run per target | Monitor these run ids instead. Every id must name a completed dependencies run |
| `--format <FORMAT>` | `text` | Output format |
| `-o`, `--output <FILE>` | stdout | Write the report here |
| `--fail-on <SEVERITY>` | `none` | Exit 1 when newly matching advisories reach this severity |
| `--webhook <URL>` | — | POST a Slack-compatible `{"text": …}` digest of the delta. A delivery failure fails the command |

## compliance

The desktop Compliance Center and Report Studio from the command line,
through the same engine functions: bounded evidence collection, immutable
assessments, the append-only review log, the same report generator for every
format (PDF included), atomic report writes and report receipts. Evidence
readiness only: not certification, legal advice or a conformity
determination. Every text result ends with that claim boundary, and every
report format carries it. See
[Compliance readiness and professional reporting](compliance-and-reporting.md).

| Subcommand | Usage | Meaning |
| --- | --- | --- |
| `profiles` | `compliance profiles [--json]` | List the built-in readiness profiles (frameworks) and their controls; `--json` emits the full profiles, controls and disclaimers included |
| `assess` | `compliance assess --db <FILE> --profile <ID>… --organization <TEXT> --assessor <NAME> [--title <TEXT>] [--scope <TEXT>] [--json] <PATH>` | Collect bounded evidence from a project directory and assess it against one or more profiles. Each profile becomes a separate, immutable assessment saved in `--db` |
| `list` | `compliance list --db <FILE> [--limit <LIMIT>] [--json]` | List stored assessments, newest first |
| `show` | `compliance show --db <FILE> (--assessment <ID> \| --latest [--profile <ID>]) [--json]` | Show one assessment: coverage summary, control matrix, matched evidence and recorded reviewer decisions |
| `review` | `compliance review --db <FILE> --assessment <ID> --control <ID> --status <STATUS> --note <TEXT> --by <NAME> [--json]` | Record a reviewer decision on one control. Reviews are append-only and never change the automated status |
| `report` | `compliance report --db <FILE> (--assessment <ID> \| --latest [--profile <ID>]) -o <FILE> [OPTIONS]` | Compile one assessment into a report, written atomically, with a receipt recorded in `--db` |

`--db` is the findings database. For `assess`, completed runs of the same
project stored in it count as evidence: run `deps <PATH> --db <FILE>` (or
another stored scan) first, then assess with the same `--db`.

**`assess` options**

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <FILE>` | required | Findings database. Completed runs of this project stored in it count as evidence, and the assessments are saved to it |
| `--profile <ID>` | required | Profile to assess against, as listed by `compliance profiles`. Repeatable; each profile at most once |
| `--organization <TEXT>` | required | Organization or program the assessment is for |
| `--assessor <NAME>` | required | Responsible reviewer |
| `--title <TEXT>` | `Compliance evidence readiness assessment` | Assessment title |
| `--scope <TEXT>` | `Product software, supporting development lifecycle, and available project evidence.` | Scope and boundaries of the assessment |
| `--json` | off | Emit the new assessments as JSON instead of a summary |

Every profile is resolved before anything is saved, so an unknown id exits 2
without storing assessments for the valid ones.

**`list` and `show` options**

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <FILE>` | required | Findings database holding the assessments |
| `--limit <LIMIT>` | `50` | `list` only: most assessments to list, 1 to 100 |
| `--assessment <ID>` | — | `show` only: assessment id, as listed by `compliance list` |
| `--latest` | off | `show` only: use the newest stored assessment instead of naming one |
| `--profile <ID>` | — | `show` only, with `--latest`: the newest assessment of this profile |
| `--json` | off | Emit JSON instead of text |

**`review` options**

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <FILE>` | required | Findings database holding the assessment |
| `--assessment <ID>` | required | Assessment holding the control |
| `--control <ID>` | required | Control id, as shown by `compliance show` |
| `--status <STATUS>` | required | `supported` (supported by review), `partial` (partially supported), `gap` (gap confirmed), `manual-review` (manual review needed) or `not-applicable` |
| `--note <TEXT>` | required | Why: explain the decision and point to authoritative evidence (4 characters or more) |
| `--by <NAME>` | required | Who decided, recorded for audit (2 characters or more) |
| `--json` | off | Emit the recorded review as JSON instead of text |

**`report` options**

| Option | Default | Meaning |
| --- | --- | --- |
| `--db <FILE>` | required | Findings database holding the assessment. The report receipt is recorded here |
| `--assessment <ID>` | — | Assessment id, as listed by `compliance list`. One of `--assessment` and `--latest` is required |
| `--latest` | off | Use the newest stored assessment instead of naming one |
| `--profile <ID>` | — | With `--latest`: the newest assessment of this profile |
| `--format <FORMAT>` | `pdf` | `pdf` (paginated executive report), `html` (self-contained, print-ready), `markdown` (alias `md`), `csv` (control matrix) or `json` (canonical machine-readable report) |
| `-o`, `--output <FILE>` | required | File to write. Its directory must exist; the file is written to a temporary file beside it, synced, then renamed into place, replacing any file already there |
| `--title <TEXT>` | `<profile name> readiness report` | Report title |
| `--organization <TEXT>` | the assessment's | Organization |
| `--assessor <NAME>` | the assessment's | Assessor |
| `--classification <TEXT>` | `Confidential` | Document classification |
| `--executive-summary <TEXT>` | Report Studio's standard summary | Executive summary. The default states that the report is not a certification |
| `--no-evidence` | off | Leave evidence references out of the report |
| `--no-reviews` | off | Leave reviewer decisions, names and notes out of the report |
| `--no-references` | off | Leave official source references out of the report |
| `--json` | off | Emit the report receipt (id, path, SHA-256 of the written bytes, metadata) as JSON instead of text |

The report defaults match Report Studio's. A report always goes to a file,
never stdout, so every report has a receipt. When no reviewer decision is
recorded, `report` warns on stderr (silenced by `--quiet`) that automated
evidence coverage is not a conformity decision.

An unknown profile or assessment id, `--latest` with no matching assessment,
a missing target or output directory, a control outside the assessment, a
review note shorter than 4 characters or out-of-bounds report metadata exits
`2`. Nothing is written in those cases.
