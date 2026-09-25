# oxAudit

**Find vulnerabilities and leaked credentials in source, dependencies, and
binaries — on your machine, in your pipeline, and without sending your code
anywhere.**

A desktop workbench and a command line over the same engine, so a finding in CI
and a finding on a workstation are the same finding.

<!-- SCREENSHOT: a populated Source Scan — findings list, one finding selected,
     detail pane showing the review gates. 1440x900, both themes if practical.
     Capture with `npm run tauri dev` against benchmarks/corpus. -->

![Tauri 2](https://img.shields.io/badge/Tauri-2-24c8db)
![React 19](https://img.shields.io/badge/React-19-61dafb)
![Rust 1.97](https://img.shields.io/badge/Rust-1.97-dea584)
![Licence Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)

---

## Install

Build the **local pilot from source** using the exact platform prerequisites and
commands in [Getting started](docs/getting-started.md). Repository read access is
required; no published release or public CLI download is available yet. Start
with Node 22.22.2, the pinned Rust 1.97.1 toolchain, and the platform's Tauri
prerequisites.

```bash
npm ci
rustup show active-toolchain
cargo build --locked --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli
npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli
```

The guide includes desktop bundle/install commands and the first-project wizard.
The [inert demo](examples/pilot/README.md), [pilot protocol](docs/pilot-validation.md),
and [complete CI workflow](examples/ci/oxaudit.yml) make the first check repeatable.
AI is optional. Local pilot bundles do not establish native signing or
notarization; [the QA log](docs/qa/2026-09-07-everyday-workflow.md) records observed
artifacts and limits.

Publishable release tags still require macOS signing/notarization and Windows
Authenticode signing. Missing credentials stop publication; unsigned manual dry
runs cannot publish. Release artifacts receive SHA-256 checksums, provenance
attestations, and SBOMs when the release workflow actually runs. No release is
claimed by these local pilot instructions.

## Project home

The desktop opens to durable project history. Choose a folder, click **Open
project**, or select a recent project. The selected folder is remembered across
restarts and validated again before use. **Resume project** opens saved source
or dependency results; opening a project never starts a scan.

**Check project** runs source scanning with the project's saved options (or your
saved scan defaults), discovers supported lockfiles, then checks dependencies.
The status bar shows the target and current stage and offers cancellation even
when you leave home. Source and dependency scan buttons share ownership so a
second scan cannot interfere with active work. If settings cannot be loaded,
open Settings and save usable scan settings before retrying.

Home distinguishes the latest attempt from the last completed results. Source
open/critical/high counts and new findings come from durable source history;
dependency counts remain unknown on home until you open the saved results.
Failed, cancelled, unsaved, or incomplete work is labelled explicitly. No
supported lockfiles means **not applicable**, and zero findings is not a claim
that a project is safe. Refresh projects to reload history after external work.

## Sixty seconds

```bash
# What is in this project?
oxaudit-cli scan .

# Put it in a pipeline. --fail-on is opt-in, so this reports without
# breaking your build until you ask it to.
oxaudit-cli scan . --format sarif --output oxaudit.sarif --fail-on high
```

For GitHub Actions use the [complete pinned example](examples/ci/oxaudit.yml)
and its [access/baseline instructions](docs/getting-started.md#complete-consumer-ci-example).
It builds a trusted CLI, checks PR code as data, preserves reports on findings,
and fails on missing baselines or incomplete scans.

Adopting a scanner on an existing codebase means meeting a backlog. Gate on what
the change introduced and leave the rest visible:

```bash
# On main, once: capture where you are today.
oxaudit-cli scan . --format json --output baseline.json

# On every pull request: fail only on what this change added.
oxaudit-cli scan . --baseline baseline.json --fail-on-new high
```

Source Scan’s **Review changes** panel compares a completed saved run with an
older compatible run. Automatic baseline selection remains the default; choosing
another baseline is read-only. **New since baseline** intersects the existing
Open, Other scopes, Closed, and Resolved views. A first scan without a compatible
baseline does not attribute findings to a commit. Missing files without compatible
scan coverage remain **not evaluated**.

Git path modes select findings in all files, changes since a chosen base (using
the merge base), staged paths, or unstaged/untracked paths. Every scan still reads
the full working tree. Staged paths include current working-tree content, including
unstaged edits to partially staged files; oxAudit does not scan index contents.
The panel separates the run’s captured revision from the current checkout and
shows scanned/skipped coverage. Old runs show revision unavailable. Git context
expires on focus changes or after a minute; refresh after editing or staging.
An empty changed-path view is not evidence of a clean project.

Git inspection uses read-only object/index commands with a cleared Git environment,
optional locks and fsmonitor disabled, and no network protocols. It compares raw
file hashes without running repository clean/process filters, external diff, or
textconv. Attribute normalization can therefore add conservative changed paths.
Inspection is bounded to ten seconds, 16 MiB per command/file, 128 MiB of file
content and 100,000 paths. Unsupported Git state (including unresolved merges,
symlinks/submodules or non-UTF-8 paths) and exceeded limits leave normal results
available. Pre/post HEAD and index metadata checks do not promise an atomic
snapshot: the stored artifact content hashes remain the scan evidence.

CLI report baselines are loaded and validated before scanning or writing output,
including when baseline and output paths alias. Report-file-only absence is
labelled **no longer observed (coverage unverified)**, covering skipped/deleted
files; only durable comparisons with compatible coverage claim resolution.
Missing or invalid fingerprint identities are rejected.

For a finding-to-fix workflow, choose **Settings → Editor → Visual Studio Code**
and save, then use **Open file** in a finding. The default **System opener** opens
only the file. VS Code navigation uses its registered `vscode` URL handler; no
shell template or editor CLI installation is needed. Paths stay within the
captured scan root. Stored columns are UTF-8 byte offsets; the opener converts
the current UTF-8 line to VS Code's UTF-16 column with an 8 MiB read limit.
Changed files may move the recorded location, and missing lines, invalid byte
boundaries, unsupported encoding or an unavailable handler produce visible
errors. Windows VS Code navigation supports local drive paths; select the system
opener for network/device paths. Editor navigation cannot freeze a file against edits after it is opened.

The finding detail includes constrained before/after examples for JavaScript
code evaluation, command execution and SQL, Python shell execution and SQL, and
secret rotation. Adapt examples to your input contract and driver; JSON parsing
only replaces evaluation of JSON data, SQL value bindings do not bind identifiers,
and scan absence does not prove a credential was revoked.

After saving your change, select **Recheck finding** on a saved completed run.
It repeats the full source scan with that run's captured effective options,
including ignored directories, then compares against that exact original run
under current policy. The outcome retains the original fingerprint/evidence,
shows the captured options, and links the original and new runs. It distinguishes
still detected, no longer detected in covered file/rule-family evidence, and not
evaluated. A same-rule finding within 20 lines is called out as changed context,
not a verified fix. Deleted/skipped files, missing coverage, cancellation,
failures, unsaved results and invalid policy cannot establish absence. Rechecks
share the normal source/project-check cancellation and ownership controls, and
never change a review decision or create an independent verification record.

Reviewed something and decided it is not a problem? Record it in
[`.oxaudit/policy.json`](#suppressing-a-finding) and it stops failing the build —
with a reason, an expiry, and a pull request.

## What makes it different

- **It tells you how accurate it is.** [Detection quality](#detection-quality) is
  measured against a committed corpus and published per rule, including the
  numbers that are not flattering. CI fails if they regress.
- **Every finding says how far it was verified** — `syntax` when a parser
  confirmed the match sits in code rather than a comment, `text` when no grammar
  was available.
- **Scanning is local.** oxAudit contacts NVD, OSV, CISA KEV, FIRST EPSS, and
  Exploit-DB only for the network-backed features you invoke, plus whatever AI
  endpoint you configure. There is no telemetry to opt out of.
- **Findings are ranked by exploitability-in-context.** CISA KEV says a CVE was
  exploited in the wild, EPSS predicts it, a public Exploit-DB entry proves
  working exploit code exists, and direct-usage reachability says whether *your*
  source actually references the vulnerable package — each signal kept separate
  and stated honestly, because none of them substitutes for the others.
- **Dismissals are decisions, not deletions.** A suppressed finding stays in the
  report with its reason and its author, and expires.
- **The assistant asks before every model-selected network action.** Its general
  web fetcher is restricted to approved public hosts and cannot reach your own
  machine or private network. See [Security notes](#security-notes).

---

## Features

| Capability | What it does |
|---|---|
| **Source code scanning** | 79 dangerous-code patterns across JavaScript/TS, Python, Java, Go, C/C++, C#, Kotlin, Swift, PHP, Ruby, Rust, plus generic rules (eval, exec, SQL injection, unsafe deserialization, `shell=True`, `strcpy`, XXE, weak randomness, weak crypto, hardcoded passwords, …), each mapped to a CWE with remediation guidance, and flagged when that weakness class is actively exploited in the wild (CISA KEV) |
| **Infrastructure-as-code scanning** | 14 misconfiguration rules across Dockerfiles, Terraform, Kubernetes manifests, and GitHub Actions workflows — unpinned base images and actions, `curl \| sh` installs, credentials copied into image layers, public S3 buckets and RDS instances, wildcard IAM policies, security groups open to `0.0.0.0/0`, privileged containers, `hostPath` mounts, and `github.event.*` script injection — each mapped to a CWE with remediation, ranked as infrastructure findings even under `test/` directories |
| **Secret scanning** | 30+ regex rules (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm/PyPI tokens, private keys, JWTs, bearer tokens, generic high-entropy API keys/passwords…) with **Shannon entropy** filtering and placeholder suppression |
| **Dependency scanning** | Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`, `pom.xml`, `requirements.txt`, `gradle.lockfile`, `packages.lock.json`, `poetry.lock` and checks every pinned package against the **OSV** vulnerability database (batch queries, matching-package advisory range evidence, CVSS score computation from vector strings), then ranks findings using optional signals: CISA KEV, public exploit availability (Exploit-DB), EPSS, and whether the project's own source directly references the package (imports/requires across JavaScript/TS, Python, Rust, Go, Ruby, and PHP) — same exploitation signal as the binary scanner; alternatively answers from a [locally built advisory database](docs/advisory-database.md) with ecosystem-correct version matching and no network at all |
| **CVE research** | Search the **NVD** API (keyword search, recent-modified filter, pagination, rate-limit aware, optional NVD API key), per-package OSV advisories, full CVE detail pages with affected products, references, CWEs, raw OSV records, and a CISA KEV / EPSS exploitation badge |
| **AI assistant** | Chat with any **OpenAI-compatible** endpoint (OpenAI, Ollama, LM Studio, vLLM, Groq, OpenRouter…). **Streaming responses** with live reasoning display, typed error handling with automatic retry, **per-conversation token & cost tracking**, cancellable turns, and an **agentic tool loop**: the AI can read files, grep/glob the scanned project, run scans, search NVD, query OSV, and fetch web pages — every tool call rendered live with a status card, gated by an allow/ask/deny permission pipeline with HITL approval, a loop guard, and dual iteration/call budgets. One-click "Ask AI" on every finding and "Generate research briefing" on every CVE |
| **Binary scanning** | Detects vulnerable components bundled inside compiled binaries, firmware images, archives, packages, and saved container images (statically linked OpenSSL, zlib, zstd, sqlite, …) with oxAudit's **own scanner** — no database to download, no external tool required. Archives open in memory — tar, tar.gz/xz/zst/bz2, zip, `ar` (so `.deb` and `.a`), RPM, CramFS, squashfs v4 (via the fuzzed `backhand` reader), and a saved `docker`/OCI image's layer tars — plus a bounded sliding search for squashfs embedded in raw firmware blobs at any offset, all under depth/count/size budgets that a decompression bomb trips loudly, with findings at member paths like `fw.bin!sqfs@0x1f8718!/bin/busybox`. Extracted images also read their own OS package databases — `/var/lib/dpkg/status`, `/lib/apk/db/installed` — against the `os-release` beside them, so a stripped-binary image with an intact package inventory still gets release-qualified distro CVE matching (`Debian:12`, `Alpine:v3.20`); JARs report their embedded Maven coordinates from `pom.properties` (nested fat-JARs included), matched against the Maven ecosystem online or from the local advisory database Each component is then looked up in NVD and OSV, and every finding ranked by CISA KEV (actively exploited?), public exploit availability (Exploit-DB), and EPSS (exploitation probability). Optionally also runs [cve-bin-tool](https://github.com/ossf/cve-bin-tool) or [grype](https://github.com/anchore/grype) if you have them installed; neither is bundled. UBI/UBIFS and squashfs v3 are not unpacked |
| **Durable evidence and inventory** | Source, Dependency, Binary, and imported SBOM runs use one persisted Artifact → Component → Observation → Evidence → Finding graph. Runs survive restart, unflagged components remain visible, provider/rule snapshots preserve historical meaning, and every scan family shares the same lifecycle timeline |
| **Rules, data, and quality** | A GUI Rule Library exposes provenance and fixture health and safely validates bounded declarative packs; Data Sources exposes immutable advisory snapshots and offline readiness; Quality Lab runs committed ground truth and reports precision, recall, misses, runtime, corpus size, and regression honestly |
| **Standards and verification** | Preview and export oxAudit JSON, SARIF 2.1.0, CycloneDX 1.6, SPDX 2.3, OpenVEX, and CycloneDX VEX. Preview bounded imports with conflict/unmapped records, import SBOM inventory separately, and retain strictly mapped SARIF/VEX assertions as immutable `external-unverified` claims that cannot alter local findings or reviews. Independent verification records bind a separate verifier to an immutable input hash |
| **Compliance readiness and reports** | GUI-first evidence checks for ISO 26262, ISO/SAE 21434, UNECE R155/R156, GDPR, CCPA/CPRA, NIST Privacy Framework, ISO/IEC 27001, OWASP Top 10:2021, and SOC 2 Trust Services Criteria; append-only qualified reviews; and professional JSON, CSV, Markdown, self-contained HTML, and paginated PDF reports. Readiness is never presented as certification or legal conformity |
| **Dashboard** | At-a-glance stats, quick actions, recent scan history |
| **Sessions** | Every AI conversation is **persisted** (JSONL transcripts + index) with a searchable session sidebar, resume-on-launch, auto-titles, per-session token/cost totals, and tool-call history that survives reload |

## Screens

- **Portfolio** — every known project with its latest evidence, staleness, and a re-scan cadence (hourly to monthly): scheduled scans run while the app is open, one at a time, through the same engine and enabled rule packs as a manual scan, and a failed or policy-blocked scheduled scan surfaces instead of silently skipping
- **Dashboard** — overview and quick actions
- **Source Scan** — folder picker, scan options, live progress, filterable findings grouped by file, JSON report export, and a severity trend over stored runs (findings by severity per completed scan, oldest to newest, with the latest run's new/resolved counts against its baseline)
- **History Scan** — the same secret rules over every blob reachable from any ref; findings at their historical paths, redacted evidence, truncation stated when a budget stopped the scan
- **Dependencies** — lockfile discovery, OSV check, vulnerable-package table with fixed versions and reference links
- **Binary Scan** — file/folder target, cve-bin-tool detection with a first-class "not installed" state, live progress, components grouped with their CVEs
- **Inventory** — all normalized components, versions, aliases, purl/CPE identities, source artifacts, confidence, and advisory matches—including components with no match
- **Rule Library** — built-in provenance/fixture health plus safe validation and installation of external declarative TOML packs: enabled packs' text-engine rules run beside the built-ins in every source scan (findings carry a `pack/rule` id), with per-pack enable/disable and stated engine limits — nothing executes
- **Quality Lab** — reproducible ground-truth metrics, misses, false positives, limitations, history, and regression state
- **Data Sources** — provider source/terms, immutable snapshot hashes, refresh state, and honest offline readiness
- **Export Center** — validated JSON/SARIF/SBOM/VEX preview/export plus bounded import and conflict preview, and ticket handoff: GitHub Issues and Jira CSV exports with one importable row per finding (severity-mapped priorities, RFC 4180 escaping, the finding fingerprint carried for traceability)
- **Verification** — producer-independent human verification bound to immutable finding evidence
- **Compliance Center** — framework selection, bounded local evidence collection, durable control matrices, and append-only human decisions
- **Report Studio** — professional multi-format report metadata, disclosure controls, preview, atomic save, and content receipts
- **CVE Research** — NVD search + OSV package lookup + detail view with AI briefing
- **AI Assistant** — chat with code/context attachment
- **Settings** — AI endpoint config, scan defaults, ignored directories, NVD API key, allowed fetch hosts, diagnostics

Press <kbd>⌘K</kbd> (<kbd>Ctrl</kbd>+<kbd>K</kbd> on Windows and Linux) to reach any
screen — or any project you have scanned before — from the keyboard. Type what
you know it as: `sarif`, `lockfile`, `precision`, `epss`, or a client directory
name. Each project shows what is still open beside it, so switching between a
dozen codebases does not mean opening a file dialog.

In a findings list, <kbd>j</kbd>/<kbd>k</kbd> move, <kbd>x</kbd> selects, and
<kbd>shift</kbd> extends a selection — then review the whole selection at once
with one reason.

## Command line

`oxaudit-cli` runs the same scanners, rules, and policy evaluation as the desktop
app — it is a second adapter over the same core, not a second engine, so a
finding reported in CI and a finding reported in the window are the same finding.

```bash
# Human-readable, grouped by file
oxaudit-cli scan .

# SARIF for GitHub code scanning and most CI viewers
oxaudit-cli scan . --format sarif --output oxaudit.sarif

# Gate a build. Opt-in: --fail-on defaults to `none`
oxaudit-cli scan . --fail-on high

# Fail only on what this change introduced, not the existing backlog
oxaudit-cli scan . --baseline baseline.json --fail-on-new high

# Lockfiles against OSV
oxaudit-cli deps . --format json

# Was this credential ever committed — including in files deleted long ago?
oxaudit-cli history .

# Gate incident response: report every historical leak at high or above
oxaudit-cli history . --fail-on high --format json --output history.json

# After a purge, prove the history is clean against the pre-purge report
oxaudit-cli history . --baseline history.json --fail-on-new high

# Complete dependency baseline and a new-only CI gate
oxaudit-cli deps . --db ~/.oxaudit/findings.sqlite3 --format json --output deps-baseline.json
oxaudit-cli deps . --db ~/.oxaudit/findings.sqlite3 --baseline deps-baseline.json --fail-on-new high

# Offline dependency scan from a complete receipt in the same database
oxaudit-cli deps . --db ~/.oxaudit/findings.sqlite3 --offline --format cyclonedx

# Or build a real advisory database once and match without the network at all
oxaudit-cli advisory-db update --db ~/.oxaudit/advisories.sqlite3
oxaudit-cli deps . --advisory-db ~/.oxaudit/advisories.sqlite3 --offline --format json

# What is inside this container image? Distro packages included, fully offline
oxaudit-cli advisory-db update --db ~/.oxaudit/advisories.sqlite3 --ecosystem Debian:12
oxaudit-cli image saved-image.tar --advisory-db ~/.oxaudit/advisories.sqlite3 --offline --fail-on high

# Or pull it straight from the registry — no docker save step. Layers are
# digest-verified; auth is the registry's token flow plus docker login's
# config.json. Findings name the reference and layer they came from.
oxaudit-cli image registry-1.docker.io/library/nginx:1.25 --advisory-db ~/.oxaudit/advisories.sqlite3

# List actual canonical dependency runs; use each returned id with export
oxaudit-cli runs --db ~/.oxaudit/findings.sqlite3 --kind dependencies --json

# Keep the run so the desktop app can open it
oxaudit-cli scan . --db ~/.oxaudit/findings.sqlite3
oxaudit-cli export --db ~/.oxaudit/findings.sqlite3 --run <id> --format cyclonedx

# Apply a rule pack committed to the repo, validated and compiled for this
# run only — the CI-native form, nothing installed
oxaudit-cli scan . --rule-pack-file .oxaudit/rules.toml

# Or manage packs in an explicit store and select them by id; explicit
# selection applies the pack as stored, enabled or not
oxaudit-cli rule-pack install --db packs.sqlite3 .oxaudit/rules.toml
oxaudit-cli rule-pack list --db packs.sqlite3 --json
oxaudit-cli scan . --rule-pack rulepack.e2e --rule-pack-db packs.sqlite3

# Or subscribe to a feed: an index URL listing packs as digest-verified zips
# of pack.toml + fixtures. Same validation as a hand install; disabled packs
# stay disabled across updates.
oxaudit-cli rule-pack update --db packs.sqlite3 --feed https://example.com/oxaudit/feed/index.json
```

Rule packs resolve before any scanning starts: an invalid pack file is a
usage error (exit 2), and a selected pack that cannot be applied fails the
run loudly (exit 3) — a pipeline never reports clean with rules silently
missing. Pack findings carry `pack/rule` ids, run under the same budgets,
span gates, and redaction as built-in rules, and only the text engines
(`source_regex`, `secret_regex`) apply today.

Progress goes to stderr and the report to stdout, so `oxaudit-cli scan . --format
sarif > out.sarif` needs no extra flags.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran to completion; nothing at or above `--fail-on` |
| `1` | Ran to completion; findings at or above `--fail-on` |
| `2` | The command was not usable — bad path, bad flag, bad format |
| `3` | The scan itself failed |

### Dependency coverage

`oxaudit-cli deps` reports advisory results only after every discovered lockfile
parses successfully. A malformed lockfile, incomplete offline OSV snapshot, or
incomplete OSV response exits with code `3` and names the coverage problem;
oxAudit does not describe that run as having no known vulnerabilities. The
desktop keeps the last completed dependency result visible when a new run fails.

Desktop and CLI dependency scans share the same durable workflow. `--db` writes
canonical dependency runs and validated full-detail advisory receipts to the
selected database. Its directory must be private to your user; a missing directory
is created privately. Without `--db`, storage and optional enrichment caches are
temporary. Offline scans contact no providers and require a complete receipt that
covers every selected query; an empty inventory needs no cached receipt. Cached
records are checked for integrity and filtered to the selected inventory.

Dependency JSON reports use `schemaVersion: 1`, `kind: "dependencies"`, and
`summary`, `dependencies`, and `vulnerabilities`. The summary includes `runId`,
complete advisory coverage, distinct query and occurrence counts, advisory receipt
freshness, and optional enrichment status/warnings. Unavailable exploitation
signals remain unknown even when legacy boolean fields are false. Every parsed
lockfile occurrence remains in the inventory; provider queries alone are deduplicated.

`deps --baseline FILE --fail-on-new high` compares advisory ID plus ecosystem,
package name, and installed version. Another lockfile occurrence of an existing
identity does not trip a new-only gate; a newly affected package or version does.
Baselines must be complete versioned dependency reports with valid inventory and
advisory identities. Invalid, missing, incompatible, or incomplete baselines exit
`2` before output or database writes. A dependency report is read before an output
path can overwrite it. `--fail-on` still gates all current advisories independently.

`runs --kind dependencies --json` returns canonical run objects with `id`, `kind`,
`state`, and `targetLabel`; `--kind all` includes every stored run kind. Omitting
`--kind` preserves the existing source-project summary format, whose
`lastCompletedRunId` refers to source history. Use a canonical `id` with `export`.
Dependency scans also accept the same standards output names as `scan`.

### Dependency paths and upgrade decisions

The desktop groups related advisories by package installation, lockfile, workspace,
and direct manifest update entry point. Select a group to inspect its declaration
chains or open the original advisory. **Recheck dependencies** uses the same shared
scan workflow and ownership controls as the main scan button.

For npm package-lock v2/v3, inventory identity and relationships come from the same
bounded JSON read. The `packages` map is authoritative; legacy `dependencies` is
compatibility data. Nested, scoped, alias and hoisted installations retain their
actual package identity and installation path. Root and linked workspace declarations
retain runtime/dev/optional/peer types when supplied. A versionless named workspace
is inventory metadata only when its local link target and root workspace declaration
agree; it is not queried as an unknown registry version. Invalid or escaping links
fail inventory coverage. Missing declaration targets, cycles and truncated traversal
remain explicit relationship unknowns. npm v1 and other supported inventory formats
retain lockfile locations with relationship evidence unavailable.

Relationship traversal is bounded to 20,000 visits/edges, depth 64, 32 chains per
occurrence and 4 MiB of chain evidence per lockfile. Workspace matching supports
literal directories and a single `*` path segment; unsupported versionless workspace
patterns require a supported lockfile before advisory coverage can be complete.
All inspection reads metadata; oxAudit never runs npm install/explain or repository
scripts during a scan.

Dependency JSON retains `occurrence` on each inventory/advisory record
(`installPath`, `localWorkspace`, `status`, `paths`, `warnings`) and
`affectedEvidence` on advisories. Matching OSV affected records preserve all range
events and explicit affected versions. CLI and stored projections carry this evidence;
the desktop derives the explanatory groups from it. Existing baseline identity and
schema 1 envelope stay unchanged. Older projections default relationships/range
proof to unknown and require a manual decision.

A combined candidate must be an advisory-reported fixed version that clears every
supplied supported range and explicit affected-version list. Numeric npm `SEMVER`
ranges support sorted, disjoint introduced/fixed intervals, inclusive `last_affected`,
and exclusive `limit` boundaries. Other ecosystems/range types, prereleases, ambiguous
versions and historical flattened strings stay manual. Patch/minor/major labels
classify only the version change; neither a fixed string nor this proof establishes
that a release exists or is compatible. A last-affected/limit boundary alone does
not supply a fixed-release candidate.

Copyable npm commands are limited to precisely identified direct runtime/dev/optional
declarations with supported numeric specs and complete relationship evidence. They
include `--ignore-scripts`, preserve the dependency type/workspace and are displayed
for review and manual use from the lockfile directory. Transitive packages, aliases,
peers and unknown declarations receive a remediation checklist. No command is executed
and no manifests are changed. The UI shows advisory source/time, optional enrichment
availability and warnings beside these decisions; absent optional signals in partial,
offline or historical data are unknown.

Parser and range semantics follow the [npm lockfile documentation](https://github.com/npm/cli/blob/latest/docs/lib/content/configuring-npm/package-lock-json.md),
[npm workspaces documentation](https://docs.npmjs.com/cli/using-npm/workspaces/), and
[OSV evaluation schema](https://ossf.github.io/osv-schema/#evaluation).

### In GitHub Actions

Use the [complete consumer workflow](examples/ci/oxaudit.yml). The
[installation guide](docs/getting-started.md#complete-consumer-ci-example) explains
private tool access, fork restrictions, main baseline authority, canonical
single-run JSON/SARIF export, and report retention. Setting the repository
variable `OXAUDIT_CODE_SCANNING=true` additionally uploads the SARIF to code
scanning, so findings appear inline in pull requests and in the Security tab —
opt-in because repositories without that capability would fail the step. oxAudit's
own [self-scan](.github/workflows/self-scan.yml) retains downloadable SARIF on
every completed scan; its publication uses the same variable.

## Detection quality

Measured, not asserted. `oxaudit-cli benchmark` runs the committed corpus in
[`benchmarks/corpus/`](benchmarks/corpus) and reports precision and recall per
rule. See the [corpus documentation](docs/corpus.md) for provenance and limits.

| | Before | After |
|---|---|---|
| Corpus precision | 46.2% | **100% on the committed authored scenarios** |
| Corpus recall | 85.7% | **100% on the committed authored scenarios** |
| Corpus size | 26 fixtures | **198 fixtures** |

The corpus is 198 fixtures: 89 positives and 109 negatives. It includes observed
false-positive shapes from oxAudit's own source or dependency trees — type
declarations, prose in Markdown, comments, environment lookups, function
parameters, JSON schemas, UI labels, hardened XML parsers, non-security uses of
`Math.random()`, the detector code that searches for PEM headers, and the benign
halves of the misconfiguration rules. It also includes six repository-authored
everyday pairs for request-derived versus constant command invocation,
concatenated versus parameterized SQL, and request-derived versus fixed outbound
URLs. Those pairs are executable regression scenarios, not an independent or
representative real-world accuracy benchmark.

The intentionally vulnerable `benchmarks` and `examples/pilot` fixtures are
excluded from production self-scans with `--ignore-dir benchmarks --ignore-dir pilot` (along with generated `node_modules`, `target`, and `dist`). Old self-scan
figures of 142 → 33 findings, six after scope triage, and 122 with the then-current
fixtures are historical observations from an earlier checkout. They are not
current counts or detection-accuracy evidence. Some historical findings were
synthetic credentials, prose, UI labels and detector strings in this repository.
Use the authored corpus only within its stated limits; this changing repository
is not an independent accuracy benchmark.

### Measured against ground truth nobody here wrote

The corpus above is written by the same people who write the rules. It answers
*"does it still do what we meant?"* and cannot answer *"is it any good?"* — so
100% on it proves less than the number looks like.

The [OWASP Benchmark](https://owasp.org/www-project-benchmark/) is the
counterweight: 2,740 generated Java servlets, each labelled vulnerable or safe
by the project that generated them. It is fetched rather than vendored, because
it is GPL-2.0 (oxAudit is Apache-2.0) and 239MB.

```bash
node tools/fetch-external-benchmark.mjs
cargo run --release --bin oxaudit-cli -- external-benchmark
```

Over the six categories oxAudit has Java rules for — 1,998 of the 2,740 cases:

| | First run | After acting on it |
|---|---|---|
| Cases with a rule to score | 1,998 of 2,740 | **2,740 of 2,740** |
| Precision | 67.0% | 65.0% |
| Recall | 6.1% | **95.1%** |
| False positive rate | 3.0% | 54.6% |
| Youden index (recall − FPR) | 0.030 | 0.405 |

The two columns do not measure the same population. Rules were written for all
five categories that had none, moving 742 cases *into* the scored set, and they
arrived carrying the same false positives as everything else here — so the
Youden index reads lower than an intermediate run that covered fewer
categories. Coverage went from 73% of the benchmark to all of it; that is the
row to read.

The first column is what a corpus written by the rules' own authors had been
reporting as 100%. Five rules were wrong in ways no internal fixture caught,
and the two columns are the before and after of fixing them:

| Category | First run | Now | What was wrong |
|---|---|---|---|
| `xss` | no rule | **237 / 246** | Nothing was written for it |
| `ldapi` | no rule | **27 / 27** | Nothing was written for it |
| `xpathi` | no rule | **15 / 15** | Nothing was written for it |
| `securecookie` | no rule | **36 / 36** | Nothing was written for it |
| `trustbound` | no rule | 33 / 83 | Nothing was written for it |
| `crypto` | 0 / 130 | **130 / 130** | The rule read the *mode*, so `DES/CBC/PKCS5Padding` passed |
| `weakrand` | 0 / 218 | **218 / 218** | The rule needed a secret-ish variable name nearby |
| `cmdi` | 33 / 126 | **126 / 126** | The rule needed the whole `Runtime.getRuntime().exec(` chain in one expression |
| `sqli` | 0 / 272 | **272 / 272** | The rule needed the concatenation *inside* the execute call, and knew nothing about Spring |
| `hash` | 28 / 129 | **129 / 129** | `SHA1` and `SHA-1` name the same hash; only one was matched, and the algorithm is often not in the source at all |
| `pathtraver` | 0 / 133 | **123 / 133** | The rule needed the concatenation *inside* the constructor, and could not match `new java.io.File` at all |

Every one of those is the same kind of mistake: a rule written against the
shape its author pictured, and a fixture written by the same person to match.
`Runtime r = Runtime.getRuntime(); r.exec(cmd)` is not an exotic way to write
Java, and oxAudit missed 100% of command injections written that way.

`crypto` and `weakrand` reached 100% precision *and* 100% recall — those
discriminators are exact (an algorithm name, a class name), so there was
nothing to trade. The remaining figures are not good, and two separate things
produce them.

**The benchmark is built to require what oxAudit deliberately does not do.**
Its safe and vulnerable cases are frequently identical in the file being
scanned. This pair differs in nothing a reader of either file could see:

```java
// BenchmarkTest00008 — labelled vulnerable
String param = request.getHeader("BenchmarkTest00008");
String sql = "{call " + param + "}";
connection.prepareCall(sql);

// BenchmarkTest00052 — labelled safe
String param = scr.getTheValue("BenchmarkTest00052");   // returns "bar",
String sql = "{call " + param + "}";                    // in another file
connection.prepareCall(sql, TYPE_FORWARD_ONLY, ...);
```

Telling those apart requires a cross-file call graph. oxAudit is
intraprocedural on purpose — the limitation is stated above, and the reason is
that a wrong call graph produces confident nonsense. So a share of this
benchmark is not measuring accuracy oxAudit lacks; it is measuring an analysis
oxAudit declines to attempt. Scores here are not comparable with a tool that
builds one.

**The rest is real, and worth having found.** `sqli` scored 0 true positives
out of 272, because `java-sql-concat` required the concatenation to appear
*inside* the execute call while the benchmark — like most code — builds the
query into a variable first. That is a recall hole in the flagship Java rule
that the internal corpus never revealed, because every fixture written for it
happened to use the inline shape: they were written by someone who already knew
what the rule matched. Widening it to any prepare-or-execute taking a variable,
and letting dataflow resolve what that variable holds, took sqli from 0 to 174
true positives and the overall recall from 6.1% to 23.3%.

The remaining 98 were a second hole of the same kind, and a larger one: the
rule matched a `Statement` receiver, and Spring's `JdbcTemplate` has none. It
takes the whole statement as a string —

```java
jdbcTemplate.queryForObject(sql, Long.class);
```

— so oxAudit found no SQL injection at all in the most widely used data-access
layer in Java, along with none in Hibernate or JPA. `java-sql-helper` covers
those, and pins the statement to the first argument, because the values bound
beside a `?` are attacker-controlled exactly as they should be and reading them
would mean reporting the remediation. `query` and `update` are too ordinary a
pair of method names to match alone, so those two want a receiver that says
JDBC. sqli is now 272 of 272.

Not one of the 82 safe cases that use these helpers binds a parameter; they are
the same dead-branch puzzles described below.

That is the second column, and it cost precision. The rule now also reports 232
of the benchmark's safe cases, and those false positives turned out not to be
fixable — an attempt and what it cost is written up under *A trade that was
measured and refused* below. On ordinary code it still discriminates, and there
are fixtures and tests holding that line:

```java
String sql = "SELECT * FROM users WHERE id = ?";   // not reported
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");  // reported
```

Taking the trade follows from a principle stated further up rather than from
the score: undetermined keeps the finding, because a false negative in a
security scanner costs more than a false positive.

Every category the Benchmark scores now has a rule, so nothing is counted in
the separate "no rule" column. It still exists, because which categories belong
there is read from the rule table rather than listed anywhere: each rule added
moved its category on its own, and each time the test asserting that category
was uncovered failed exactly as it should have.

`securecookie` reached 100% precision and 100% recall — `setSecure(false)` is
an unambiguous statement about a cookie, and 36 of 36 vulnerable cases make it.

`trustbound` is at 39.8% recall on purpose. The Benchmark counts two things
under CWE-501: an attacker choosing the *session key*, and any request value
stored in the session at all. oxAudit reports the first and not the second,
because the second is what every login form does:

```java
session.setAttribute(request.getParameter("key"), value);   // reported
session.setAttribute("userId", request.getParameter("id"));  // not reported
```

That costs 50 true positives here. It is the same trade already made for path
traversal and SSRF, for the same reason: a rule nobody leaves switched on
catches nothing.

`pathtraver` went from 0 true positives to 123 of 133, and the whole of that
came from finding out that the rule could not fire at all. It matched
`new File(` and a `+` in the same parentheses; a servlet writes the
concatenation a statement earlier and spells the type `new java.io.File`, so
the pattern was unfirable on every one of the 133 vulnerable cases. Rewriting
it to match the sink and let the dataflow analysis decide exposed four things
the analysis could not follow — a loop variable bound by `for (Cookie c :
request.getCookies())`, a value read back out of an array or a cast, a method
called on tainted data, and a value handed through any unmodelled call at all.
Each is now followed, and the last one only in the direction that adds taint:
a tainted operand makes the call tainted, while a constant one still leaves it
`Unknown`. Folding the operands and returning the fold is the textbook version
and it stays refused, for the reason under *A trade that was measured and
refused*.

The cost is 114 false positives out of 135 safe cases, and they are the same
dead-branch puzzles that defeat `cmdi` below — a `switch` on `"ABC".charAt(1)`,
a `list.remove(0)` before a `get(1)`. Not one of the 135 uses a real defense;
the rule's own remediation, canonicalise and check containment, is recognised
and suppresses the finding when it appears. What keeps the rule usable on
ordinary code is unchanged: CWE-22 still requires an inbound origin, so a path
that merely arrives as a parameter is not reported.

`hash` reached 129 of 129 at 100% precision by reading the properties file.
The 40 cases that were missed all say

```java
String algorithm = props.getProperty("hashAlg1", "SHA512");
MessageDigest.getInstance(algorithm);
```

and `benchmark.properties` says `hashAlg1=MD5`. The literal in the source is
the value that applies only when the key is *absent*, so reading the source
alone gets the answer exactly backwards — it reports SHA-512 for an
application that ships MD5. 33 safe cases have the identical shape with a key
that resolves to SHA-256, and they stay silent.

So oxAudit now indexes the `.properties` files in the scan target and resolves
`getProperty` against them. Three rules follow from that, and the direction is
the opposite of this scanner's usual one: an algorithm name that cannot be
resolved produces no finding at all, because the finding asserts that a broken
algorithm is in use and asserting that without knowing the algorithm would be
making it up. A key two files disagree about resolves to nothing, for the same
reason — which one runs is a deployment decision.

The same mechanism now covers ciphers. `crypto` was already at 130 of 130, but
by luck: the vulnerable cases happen to write `DESede/ECB/PKCS5Padding` as the
literal default beside the configuration key. An application whose code
defaults to AES and whose properties file says DES was being missed, and is
not any more.

And `cmdi` now scores a Youden index of **0.000** — it finds all 126
vulnerable cases and flags all 125 safe ones. That is worth being plain about
rather than burying, because it looks like the rule discriminates nothing. On
ordinary code it does: a literal command is suppressed and a request-derived
one is reported, and there are fixtures for both. What defeats it here is how
the Benchmark builds a safe case:

```java
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;                    // dead: 294 − 86 is always > 200
String[] args = {a1, a2, "echo " + bar};
```

Separating that from the vulnerable version needs constant folding and
dead-branch elimination. oxAudit's documented behaviour is the exact opposite
— *a variable reassigned in a branch counts as tainted if any reaching
definition is tainted* — chosen deliberately to over-approximate toward
reporting. So these are the stated design producing the result it was designed
to produce, and the fix is not a better `cmdi` rule.

Taking the recall was still right. Missing every command injection written in
two statements is a hole no amount of benchmark score justifies keeping.

#### A trade that was measured and refused

The 150 false SQL reports break down as 105 values passed through a helper
resolved by reflection, 33 carried through a `HashMap` or `StringBuilder` and
back out, and the rest dead branches guarded by arithmetic that is always true.

The first group has an obvious fix, and it is the standard one: treat an
unmodelled callee as a function of its arguments, so `doSomething("literal")`
is constant and `doSomething(param)` is not. Implemented and measured, that
removed **28 false positives** — and introduced **11 false negatives**:

```java
String param = scr.getTheParameter("BenchmarkTest00043");   // request data
String sql = "INSERT INTO users ... '" + param + "'";       // no longer reported
```

An accessor taking a constant key and returning request data is not a corner
case; `getProperty`, `config.get`, and every framework's parameter helper have
that shape. The trade was 28 reports a reviewer dismisses in a second against
11 hidden SQL injections, so it was reverted. A test pins the shape, and names
the measurement, so the same trade cannot be made again by accident.

Two smaller findings from the same investigation *were* sound, and both fix
real code even though the Benchmark cannot show it — its SQL values are never
constant, so an unresolved argument beside them changes nothing there:

```java
statement.execute(sql, Statement.RETURN_GENERATED_KEYS);  // was reported
runtime.exec(new String[] {"ls", "-la"});                 // was reported
```

One unresolved argument makes a whole call unresolved, so a flags constant or
a literal array sitting *next to* the argument a rule cares about was deciding
the outcome. A SCREAMING_SNAKE_CASE member now reads as the compile-time
constant it is, and a collection of literals as the constant it is. The second
needs no convention; the first is drawn tightly enough that `config.userInput`
cannot qualify, and there is a test for that.

Whether a weak generator matters is a question the tool refuses to answer on
its own. `java-insecure-random` asks whether a *secret* came from one and is
high severity when it can tell; `java-weak-prng` says only that the generator
is not cryptographic, at low severity, and asks a person to decide. The precise
rule supersedes the broad one at the same site, so a reviewer is never asked
the vague question and the sharp one about the same line.

### Scope: which files, and where inside them

Scope ranks and annotates rather than deleting, because "usually noise" is not
"always noise". A hardcoded credential in a fixture is nearly always benign; a
misconfigured `nginx.conf` under `test/` is not, so infrastructure outranks
every exclusion.

Path answers *which file*, and it is right about files. It is silent about
*position*, and in Rust that silence was most of the noise: `#[cfg(test)]`
modules sit at the bottom of the production file they exercise, so their fixture
credentials were reported at full production priority — 20 of 32 findings here,
the largest single category of benign results and indistinguishable from real
ones. A further five sit in `*_tests.rs` files, where the `#[cfg(test)]` marker
is in the *parent* module and the file name is the only local evidence.

Reclassifying hides findings from the default view, so every position signal is
one a compiler or test framework enforces, never a naming habit:

| Language | Signal |
|---|---|
| Rust | `#[cfg(test)]`, `#[test]` — not compiled into a release binary at all |
| Java | JUnit's `@Test` family, including lifecycle annotations that build fixtures |
| Python | `def test_*`, `class Test*` — what pytest and unittest collect on |
| Go | `func TestXxx(t *testing.T)`, keyed on the `testing` parameter, not the name |

`#[cfg(not(test))]` is the opposite claim and is explicitly not matched: it marks
code that exists *only* in release builds, which is the last place to hide a
finding.

JavaScript and TypeScript are deliberately absent. `describe`, `it`, and `test`
are ordinary identifiers an application file may legitimately define, and the
path rules already cover `.test.ts`, `.spec.ts`, and `__tests__/`. The marginal
recall was not worth a rule that could hide a real finding in shipped code.

Two defects the corpus found on its first run:

- `generic-password` matched `\bpassword\b`, and an underscore is a word
  character, so `DB_PASSWORD` and `DATABASE_PASSWORD` never matched. The rule
  responsible for 111 of the 142 findings here also missed the commonest real
  credential shape there is.
- Its separator class `[^A-Za-z0-9]{0,10}` included newlines, so the word
  "secret" on one line paired with an unrelated token three lines below.

### Throughput

`cargo bench --bench scanning` measures the per-file work. Figures below are the
median of a run on an Apple M-series laptop, so treat them as ratios rather than
absolutes:

| Stage | Throughput |
|---|---|
| Source pattern rules | 400–840 MiB/s |
| Secret rules (33 rules over every file) | 210–290 MiB/s |
| Syntax analysis (tree-sitter parse + span collection) | 15–21 MiB/s |

Throughput is flat across three orders of magnitude of input size, which is the
property that actually matters: a rule change that made matching quadratic would
show up here as throughput falling as files grow.

Syntax analysis is roughly 40× more expensive than rule matching and dominates
scan time — it is the entire cost of the precision improvement above. End to
end, this repository (576 files, 4.8 MB) scans in about 2.4 seconds.

### Dataflow

A pattern rule can say "this is `eval(`". It cannot say whether the argument is
a string literal or something a request body controls — and that is the whole
difference between a finding and a nuisance.

For the supported languages, oxAudit now traces the value reaching a sink within
its enclosing function:

```js
eval("2 + 2")               // constant — not reported
const E = "1 + 1"; eval(E)  // resolves to a literal — not reported
eval(userInput)             // parameter — reported
eval(req.body.expr)         // request data — reported
```

A call chain is one expression: if any link takes a value an attacker chooses,
the whole chain does.

```rust
Command::new("sh").arg("-lc").arg("ls").status()   // fixed — not reported
Command::new("sh").arg("-lc").arg(user).status()   // reported
```

A transform that neutralizes the sink's weakness clears it:

```js
eval(parseInt(userInput, 10))   // coerced to a number — not reported
eval(escapeHtml(userInput))     // escapes markup, not code — still reported
```

Sanitizers are matched to the CWE they actually neutralize, never applied
generically. `escapeHtml` clears an XSS sink and nothing else; `shlex.quote`
clears command injection and nothing else. A transform that is merely *named*
like a sanitizer counts for nothing — guessing there produces a false negative,
which is the expensive direction.

### When the weakness is the call, not its input

Two classes added in this round are not about a value flowing into a sink at
all, which is what makes them worth stating separately.

**XXE (CWE-611)** is a property of how a parser was *configured*.
`DocumentBuilderFactory.newInstance()` takes no arguments; there is no input to
trace. What decides it is whether the hardening appears anywhere in the file:

```java
var factory = DocumentBuilderFactory.newInstance();                  // reported
factory.setFeature(DISALLOW_DOCTYPE_DECL, true);                     // not reported
```

**Weak randomness (CWE-338)** depends on what the value is *for*, not where it
came from. `Math.random()` is correct for animation jitter and wrong for a
session token, and the same call site is both.

Rule guards are matched against code **and string literals, but never
comments**. The distinction is load-bearing in both directions: a
`// TODO: switch to defusedxml` is a plan rather than a mitigation, while
`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` puts
the only evidence of the real fix inside a quoted feature URI.

Both directions were caught by fixtures rather than by reasoning — first a
fixture whose own explanatory comment suppressed the finding it existed to
prove, then a hardened-parser fixture that passed only because it happened to
call `setExpandEntityReferences(false)` as well, masking a guard that could
never fire on the commonest spelling of the fix.

### When the call is the defect, restated

The XXE and weak-randomness work above established that some weaknesses are
about the call rather than its input. Adding three languages showed that the
same idea has a second half: for those classes, argument taint must not be
allowed to *clear* a finding either.

```js
crypto.createHash("md5")                      // reported
Math.random().toString(36).slice(2)           // reported
```

Both were being suppressed. `createHash("md5")` takes one argument and it is
the constant naming the broken hash — read as "nobody can choose this value,
so nothing can go wrong". `Math.random()` was cleared by the constant `2` in a
downstream `.slice(2)`, because the chain it sits in is what supplies the
arguments.

Neither is subtle once stated, and both hid for the same reason: the first only
misreported when the call stood alone, since a chained `.update(data)` made the
chain tainted and reported it anyway. Weakness classes CWE-338, CWE-611,
CWE-327, and CWE-295 are now exempt from argument-based clearing.

### What the analysis tells a reviewer

The review model treats a finding as a *candidate* until something tries to
disprove it, through five falsification gates. The dataflow analysis is an
automated attempt at exactly that, so it answers the gates in the same
vocabulary a person uses, and the review form starts from its answers:

| What it found | Gate | Verdict |
|---|---|---|
| The value traces to a parameter or external input | Attacker control | survives |
| Sanitization is present but covers a different weakness | Effective sanitization | survives |

The second row is the one worth having. `eval(escapeHtml(userInput))` reports
with *"passes through `escapeHtml()`, which neutralizes CWE-79 and not CWE-95"* —
someone wrote that call believing it made the line safe, and saying so is more
useful than either hiding the finding or reporting it bare.

**No suggestion ever eliminates a finding.** An eliminating verdict is a
dismissal, and the review model requires a person to make one — the same line
the assistant is held to. A recorded human answer is never overwritten by a
machine one.

### Known limitation: caller-supplied values

For two weakness classes, a caller-supplied value is the ordinary case rather
than the defect. An HTTP helper takes a URL; a path helper takes a name.

```js
async function get(url) { return fetch(url); }        // NOT reported
app.get("/p", (req) => fetch(req.query.url));         // reported
```

Path traversal (CWE-22) and SSRF (CWE-918) are therefore reported only when the
value traces to an inbound source — a request, argv, an environment read —
rather than to any parameter. Whether a parameter is reachable from a request
handler needs a call graph oxAudit does not build.

This is a deliberate trade of recall for usability, and it is a large one:
reporting these on any parameter fired 148 times across a single dependency
tree, half of every finding. A rule nobody leaves switched on catches nothing.
Every other weakness class still reports on any non-constant value.

Three limits, stated because they bound what the result means:

- **Twelve languages.** JavaScript/TypeScript, Python, Java, Rust, Go, PHP,
  Ruby, C, C++, C#, Kotlin, and Swift. A language without a grammar is never
  suppressed on a guess — it is scanned on text alone, and every match stands.
  Grammars are selected at build time, so `oxaudit-cli languages` tells you
  which ones are in the binary you are holding.
- **Infrastructure file kinds at the text tier.** Dockerfiles, Terraform,
  Kubernetes/YAML manifests, and CI workflow files are scanned with dedicated
  misconfiguration rules. No grammar covers them yet, so nothing in them is
  suppressed on a guess — the rules anchor on the format's structure (block
  windows, line-anchored keys, `run:` lines) instead.
- **Intraprocedural.** Analysis stops at the enclosing function. Following a
  value across call boundaries needs a call graph, and a wrong one produces
  confident nonsense.
- **Undetermined keeps the finding.** Only a value *positively shown* to be
  constant is suppressed. Every case the analysis cannot decide is still
  reported — a false negative in a security scanner costs more than a false
  positive.
- **Not flow-sensitive.** A variable reassigned in a branch counts as tainted if
  any reaching definition is tainted, which over-approximates toward reporting.

Adding the constant-argument cases to the corpus dropped precision from 100% to
71.4% without changing a single rule. Dataflow returns it to 100% with recall
unchanged.

### Confidence tiers

Every finding records how far oxAudit could qualify it:

- **`syntax`** — a grammar parsed the file and the match sits in code, not in a
  comment or a string literal. Available for JavaScript/TypeScript, Python,
  Java, Rust, and Go.
- **`text`** — the rule matched raw file text; no grammar was available.

A language without a grammar is never suppressed on a guess. A false negative in
a security scanner is worse than a false positive, so the absence of a parser
means every match stands and says so.

## Git history secret scanning

`scan` answers *what is in the project now*. `history` answers the
incident-response question: **was this credential ever committed?** — including
in files deleted long ago. A key removed from the working tree is still live
until rotated and purged from history, and the first step of that response is
seeing the leak at all.

```bash
oxaudit-cli history .
```

Every blob reachable from any ref — branches, tags, and remote refs — is read
through the same hardened, read-only git plumbing the review panel uses (no
hooks, no network, no filters) and run through the same secret rules, entropy
floors, and placeholder filtering as a working-tree scan. Findings keep plain
repository-relative paths, so a leak both scanners can see is the same finding
by fingerprint, and `.oxaudit/policy.json` suppressions apply. One credential
in one file is one finding, however many revisions it survived.

Four limits, stated because they bound what the result means:

- **Reachable objects only.** Dangling objects that no ref points at are not
  enumerated; `git fsck --lost-found` is the tool for those.
- **Text blobs at the text tier.** Non-UTF-8 content is skipped, and there is
  no grammar parse, so a credential in a comment is still reported — history
  scanning errs toward recall.
- **Bounded work.** Distinct blobs (100,000), per-blob size (1 MiB), total
  scanned bytes (256 MiB), and wall clock (120 s) all have budgets. Exceeding
  one keeps the findings already collected and reports `truncated` with the
  reason; a history that silently stopped early would be worse than one that
  says so.
- **No introducing commit.** Which commit first carried a blob is not computed
  — per-object `--find-object` walks are prohibitively expensive on real
  histories, and "rotate, then purge" does not need it. `git log --all --
  <path>` finds the commit once you have the path.

`--fail-on`, `--baseline`, and `--fail-on-new` behave exactly as they do for
`scan`, so a post-purge history can be gated against the pre-purge report.
The desktop workbench runs the same engine from **History Scan** — results
appear at their historical paths with redacted evidence and are not saved;
leaving the page discards them. History runs are not stored as canonical runs
and export no standards formats; they are an incident-response surface, not a
second workbench. Rotation, not deletion, closes a leaked credential —
deleting the file never revoked anything.

### Live validation, opt-in

`--validate-secrets` sends each found credential to **its own provider** and
records whether it was accepted — the difference between an emergency and a
hygiene item.

```bash
oxaudit-cli history . --validate-secrets
```

The rules it runs under, because a tool that promises your code never leaves
your machine does not get to put your credentials on the wire casually:

- **Opt-in only.** A default scan never sends a credential anywhere.
- **Fixed endpoints.** A GitHub token validates against `api.github.com` and
  nowhere else; there is no configurable URL, so the secret cannot be aimed
  at another host by a typo or a setting. Only the HTTP status is read —
  response bodies and account identities are discarded, and nothing about the
  credential is logged. One measured exception: Slack reports a failed check
  as HTTP 200 with `{"ok": false}` in the body, so for Slack exactly that
  one boolean is read and the rest of the body is discarded like everything
  else.
- **Honest verdicts.** `VERIFIED LIVE` means the provider authenticated it:
  rotate now. `rejected by provider` is **not** a licence to skip rotation —
  the credential may work elsewhere or be re-enabled. Unchecked stays
  unchecked: no validator exists for that credential type, or the provider
  could not answer. At most twenty credentials leave the machine per run.
- **Raw values are transient.** Credential material exists only between the
  scanner hit and the validation call; findings, reports, and logs carry
  redacted evidence only.

Two provider shapes exist. Bearer-token credentials travel as
`Authorization: Bearer …` to their one fixed endpoint: GitHub classic and
fine-grained tokens (`api.github.com/user`), GitLab PATs
(`gitlab.com/api/v4/user`), OpenAI (`api.openai.com/v1/models`), Anthropic
(`api.anthropic.com/v1/models`, with the `anthropic-version` header its API
requires), Hugging Face (`huggingface.co/api/whoami-v2`), npm tokens
(`registry.npmjs.org/-/whoami`), Stripe secret and restricted keys
(`api.stripe.com/v1/charges`), and Slack tokens
(`slack.com/api/auth.test`, the body-verdict case above). AWS keys are a
pair — an access key id alone is only a username — so an `aws-access-key-id`
finding is validated only when an `aws-secret-key` finding sits in the same
file within ten lines and is unambiguously its nearest key; the pair is then
Signature Version 4-signed (verified against AWS's official SigV4 test-suite
vectors) onto an STS `GetCallerIdentity` call to `sts.amazonaws.com`, the one
AWS API every valid credential may call with no permissions attached. A
verdict lands on both findings of the pair. Temporary `ASIA…` keys are
skipped — they need a session token the scanner does not pair — and an AWS
key with no secret nearby reports `unpaired` rather than guessing.

Rules deliberately left without validators, each for a reason sharper than
a TODO: Slack **webhooks** (the only check is posting a visible message into
the channel), Google **API keys** (service-scoped — a key valid for one API
fails every other, so no single endpoint returns an honest verdict), **PyPI**
tokens (they only authenticate uploads), and **private keys** (proving one
live means signing for whichever service it belongs to). Stripe's regex also
matches `pk_…` publishable keys, which are public by design; those values
are never sent.

The desktop workbench exposes the same opt-in on the **History Scan** page:
a *Validate live against providers* switch, off by default, with the same
fixed endpoints, the same twenty-credential cap, and a verdict banner
(`live / rejected / no answer / not attempted`) plus per-finding badges.

## Suppressing a finding

A finding that has been reviewed and dismissed should not be raised again on
every push. `.oxaudit/policy.json` records that decision **in the repository**,
so it arrives through a pull request, is reviewed like any other change, and is
attributed to the project rather than to whoever last ran a scan.

```json
{
  "version": 1,
  "entries": [
    {
      "kind": "suppression",
      "ruleId": "generic-password",
      "pathPattern": "tests/**",
      "state": "suppressed",
      "reason": "Synthetic credential fixtures; see tests/README.md.",
      "expiresAt": "2027-01-01T00:00:00Z"
    },
    {
      "kind": "finding",
      "fingerprintVersion": 1,
      "fingerprint": "…",
      "category": "vulnerability",
      "state": "falsePositive",
      "reason": "The affected branch is excluded from production builds.",
      "gates": [
        {
          "gate": "reachable",
          "verdict": "eliminates",
          "evidence": "The production feature manifest excludes this branch."
        }
      ],
      "decidingGate": "reachable"
    }
  ]
}
```

A `suppression` entry dismisses a rule across a path pattern. A `finding` entry
dismisses one specific finding by fingerprint, and for a vulnerability it must
name the gate that eliminates it and show the evidence — asserting "false
positive" is not the same as arguing it.

Four properties this has, and why:

- **A reason is required.** A dismissal with no justification looks reviewed
  without being reviewed.
- **`expiresAt` is honoured.** An expired decision returns the finding to the
  queue, so a temporary exception cannot quietly become permanent.
- **A dismissed finding still appears in reports**, marked with its state and
  `"origin": "projectPolicy"`. Suppression changes whether something gates the
  build, not whether it happened — the decision has to stay auditable.
- **A malformed policy stops the scan.** Ignoring an unparseable file would
  silently un-suppress everything the team agreed to, and the run would not mean
  what it appears to mean. Pass `--ignore-invalid-policy` to scan anyway.

## Architecture

```
src/                  React + TypeScript + Tailwind v4 frontend
  pages/              one file per screen
  features/           domain-focused GUI workflows and pure view models
  components/         shared workbench UI (findings, badges, progress…)
  lib/                typed invoke() wrappers, zustand stores, formatting
src-tauri/            Rust backend (Tauri v2)
  crates/             compiler-enforced domain, application, scanner, and benchmark cores
    oxaudit-domain/       stable records, identities, evidence and state invariants
    oxaudit-application/  ports, run coordinator, manifests and sequenced events
    oxaudit-scanners/     bounded declarative rules and optional object analysis
    oxaudit-benchmark/    resumable ground-truth contracts and metrics
    oxaudit-compliance/   declarative readiness profiles and evidence evaluation
  src/adapters/       SQLite, scanner mapping, providers and standards reporting
  src/presentation/   canonical Tauri event projection
  src/models.rs       shared serde models (camelCase ⇄ TypeScript types)
  src/scanners/       secrets.rs (rules + entropy engine), patterns.rs (source rules)
  src/deps/           lockfiles.rs (parsers), osv.rs (OSV client + CVSS math)
  src/binscan/        native binary scanner plus optional external-tool adapters
  src/findings/       durable runs, evidence, review, policy, diff and SQLite storage
  src/triage/         scope, falsification gates and silent-drop manifest
  src/agent/          bounded read-only tool loop and permission guardrails
  src/cve.rs          NVD client with rate limiting + caching, OSV enrichment
  src/ai/             OpenAI-compatible chat client + prompt builders
  src/commands.rs     Tauri presentation commands
```

All *oxAudit* scanning is local. oxAudit itself contacts only NVD, OSV, CISA KEV,
FIRST.org EPSS, Exploit-DB, the AI endpoint you configure, and — when you
deliberately run `advisory-db update` — OSV's published dump bucket — all free and
key-less except the optional NVD API key. The Exploit-DB index is cached locally
and refreshed weekly, so the public-exploit signal keeps working offline.

The default **native binary scanner is local and needs no external tool or advisory
database bootstrap**. If you explicitly select cve-bin-tool, that separate program
makes its own network calls—to its mirror at `cveb.in` and the advisory feeds it
aggregates—unless you tick **Offline**. The optional external adapter is inert until
you install cve-bin-tool; the native scanner is not.

The application now has a compiler-enforced domain/application core and one durable
run/evidence pipeline for source, dependency, binary, and inventory-import workflows.
The full
[upstream architecture study](docs/architecture/2026-08-21-upstream-architecture-study.md),
[GUI-first target architecture](docs/architecture/2026-08-21-gui-first-target-architecture.md),
the [implementation plan](docs/superpowers/plans/2026-08-21-oxaudit-architecture-strengthening.md),
and the [implementation status](docs/architecture/2026-08-21-implementation-status.md)
record what is being adopted from cve-bin-tool, VulHunt, and VulnHunter, what is
deliberately rejected, and how licence-safe provenance is preserved.

The [compliance and reporting architecture](docs/compliance-and-reporting.md)
documents profile licensing boundaries, status semantics, bounded evidence collection,
append-only review history, and the shared professional report model.

## Development

Use Node 22.22.2 and the Rust 1.97.1 pin in `rust-toolchain.toml`. See
[Getting started](docs/getting-started.md) for native prerequisites and exact
platform install paths.

```bash
npm ci
rustup show active-toolchain
npm run tauri dev        # run the app with hot reload
npm run build            # type-check + build the frontend
cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-features
npm run tauri build      # produce a local bundle for this platform
```

### Choosing grammars at build time

Each language grammar is an optional dependency behind a Cargo feature. The
default is every grammar, which is what a release ships; a size-constrained
build can take fewer.

```bash
cargo build --release --bin oxaudit-cli                        # all twelve
cargo build --release --bin oxaudit-cli \
  --no-default-features --features grammars-core               # the original five
cargo build --release --bin oxaudit-cli \
  --no-default-features --features grammar-python,grammar-go   # pick your own
```

Leaving a grammar out does not make oxAudit quieter about that language — it
makes it **louder**. With no grammar, nothing can prove a match sits in a
comment or a string, so every match stands and the analysis answers Unknown
rather than suppressing on a guess. The trade is precision for size, never
recall — and the corpus measures that rather than asserting it:

| Build | CLI binary | Corpus precision | Corpus recall |
|---|---|---|---|
| `default` — all twelve | 29.2 MB | 100% | 100% |
| `grammars-core` — the original five | 10.2 MB | 82.6% | **100%** |
| `--no-default-features` | 7.6 MB | text tier throughout | **100%** |

Recall does not move. Kotlin, Swift, and C# account for most of the difference;
the original five grammars cost 2.6 MB between them.

Because two binaries of the same version can therefore disagree about how
precisely they read a language, `oxaudit-cli languages` prints what is
compiled in, and `oxaudit-cli benchmark` names any grammar it is missing
rather than letting the score be read as a rule regression.

`cargo test` expects the default feature set — most of the suite asserts what a
grammar does with a language. CI checks that the reduced configurations still
compile.

## Configuring the AI

1. Open **Settings → AI engine**.
2. Pick any OpenAI-compatible endpoint: set **Base URL** (e.g. `https://api.openai.com/v1`,
   `http://localhost:11434/v1` for Ollama, `http://localhost:1234/v1` for LM Studio),
   the **model** name, and an API key if required.
3. Enable the toggle and press **Test connection**.
4. Findings and CVEs now get an **Ask AI / Generate research briefing** button.

> The NVD API key (optional) raises the NVD rate limit from 5 to 50 requests per
> 30 seconds — get one free at https://nvd.nist.gov/developers/request-an-api-key.

## Binary scanning (cve-bin-tool)

oxAudit does **not** bundle [cve-bin-tool](https://github.com/ossf/cve-bin-tool). It is
GPL-3.0-or-later; bundling it would make oxAudit a distributor of GPL software, whereas
invoking a copy you installed is arms-length. Install it yourself:

```bash
pipx install cve-bin-tool     # recommended
# or: pip install cve-bin-tool
```

oxAudit finds it on PATH, falling back to `python3 -m cve_bin_tool`. If you keep it in a
specific environment, set the path in **Settings → Binary Scanning**; an explicit path
suppresses the fallbacks so you always scan with the copy you meant.

The first run downloads a CVE database and can take several minutes — the page shows
cve-bin-tool's own progress while it works, and the scan is cancellable.

> **Upstream bugs, and the workaround (checked 2026-08-20).** cve-bin-tool 3.4 cannot
> populate its CVE database out of the box: its NVD bootstrap aborts on a `403` from
> `nvd.nist.gov/rest/public/dashboard/statistics`, and a failed run then records an
> update timestamp that routes every later run into an empty incremental fetch. Both
> are small bugs — the container image in `docker/cve-bin-tool/` carries the fix, after
> which the fetch runs normally. **Set an NVD API key first**: the unauthenticated rate
> limit makes the initial download take hours. Full investigation, and a measured
> comparison against grype, in
> [`docs/binary-scanning-runtime.md`](docs/binary-scanning-runtime.md).

An experimental container runtime lives in `docker/cve-bin-tool/Dockerfile`. It supplies
the external programs cve-bin-tool needs but does not declare (`gsutil` for its mirror,
plus `cabextract`, `rpm2cpio`, `p7zip`, `zstd`). Build it yourself — the file is a
recipe, so oxAudit never distributes GPL software:

```bash
docker build -t oxaudit/cve-bin-tool:3.4 docker/cve-bin-tool
```

Lockfile scanning is deliberately **not** routed through it: **Dependencies** already
parses ten lockfile formats natively and queries OSV directly.

## Security notes

- Model-selected NVD search, OSV queries, dependency scans, general web fetches,
  and external binary-scanner runs always enter the approval queue before they
  can use the network. Local source/secret scans remain automatic. The approved
  fetch-host list in Settings extends the built-in advisory/reference hosts; it
  never overrides the block on private, loopback, link-local, or otherwise
  non-routable addresses. Redirects are checked and DNS-pinned again at every hop.
- Symbolic links are ignored by default. When **Follow in-project symlinks** (or
  `--follow-symlinks`) is enabled, a link is followed only if its canonical target
  remains inside the selected project. A link cannot widen the scan boundary.
- API keys are stored by the operating system credential manager, never in ordinary
  settings or the scanned project. Public settings are committed atomically and use
  owner-only Unix permissions. Upgrades checkpoint a safe, idempotent migration from
  `com.vulncompanion.app` to `com.oxaudit.desktop`, retain a sanitized legacy backup,
  and fail closed on symlinks or conflicting destination files.
- The secret scanner is heuristic: always confirm a finding is a real credential
  before rotating anything, and beware false positives from test fixtures.
- Binary scanning shells out to cve-bin-tool with arguments passed directly — never
  through a shell — and the target is canonicalized to an absolute path first. Note that
  cve-bin-tool extracts archives (ZIP/RPM/DEB/CAB/APK) to inspect them, so pointing it at
  untrusted firmware runs third-party extraction code on attacker-supplied input.
- Live verification of secrets (calling AWS/GitHub to check tokens) is intentionally
  **not** performed; treat findings as candidates.

### Safety budgets

Untrusted repositories are bounded deliberately. A source run stops at 100,000
eligible files or 20 GiB of eligible file metadata, 5,000 findings in one file,
or 100,000 findings in the run. Dependency discovery stops at 256 lockfiles;
each lockfile is capped at 16 MiB and the combined inventory at 100,000 package
occurrences. Only provider queries deduplicate ecosystem/name/version identities.

Native binary discovery stops at 100,000 files or 20 GiB, uses at most four
dedicated workers, and examines at most the first 128 MiB of any one binary.
External scanner stdout and report files are capped at 64 MiB. Assistant file
reads reject inputs over 2 MiB, and general web fetches retain at most 256 KiB.

Crossing a scan budget is an incomplete run, never a clean result: oxAudit stops,
names the exceeded ceiling, and does not persist the run as completed. Scan a
smaller subdirectory or exclude generated/vendor paths with the ignored-directory
setting or repeated CLI `--ignore-dir` flags.

## Measured next steps

- Expand deterministic source, secret, dependency, binary, and cross-platform
  corpora before making representative recall claims.
- Add an explicit trust/mapping workflow before SARIF or VEX imports can affect
  local findings or review state.
- Migrate built-in source/secret snapshots into the declarative pack format only
  as each rule gains positive/negative fixture provenance.
- Consider CFG/data-flow work only if the bounded object tier demonstrates
  benchmark value; it is intentionally not a decompiler today.

See the [implementation status](docs/architecture/2026-08-21-implementation-status.md)
for shipped evidence and deliberate limits.

## Licence

oxAudit is licensed under the **[Apache License 2.0](LICENSE)**. See
[`NOTICE`](NOTICE) for attribution, which the licence requires derivative works
to carry forward.

Two things the notice records, because they are easy to get wrong:

- **The external scanners are not distributed with oxAudit.** Binary scanning
  executes a copy of [cve-bin-tool](https://github.com/ossf/cve-bin-tool)
  (GPL-3.0-or-later) or [grype](https://github.com/anchore/grype) (Apache-2.0)
  that *you* installed. Invoking a program at arm's length carries no licensing
  obligation; bundling one would. `docker/cve-bin-tool/Dockerfile` is a recipe
  built on your machine, not an image we publish.
- **The detection signatures are original work.** They were derived from
  binaries whose versions were known independently — see
  [`docs/binary-signatures.md`](docs/binary-signatures.md) — and deliberately
  not transcribed from cve-bin-tool's GPL checkers.

Methodology studied and reimplemented from
[VulnHunter](https://github.com/capitalone/VulnHunter),
[VulHunt](https://github.com/vulhunt-re/vulhunt) and
[y-agent](https://github.com/gorgiaxx/y-agent) is credited in `NOTICE`. No source
was copied from any of them.
