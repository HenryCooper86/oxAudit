# oxAudit upstream architecture study

> Reviewed 2026-08-21. This is a source-level study of the three projects named
> below, not a README comparison and not an installation recommendation.

## Decision

oxAudit should not make cve-bin-tool, VulHunt, or VulnHunter a required runtime.
It should adopt their strongest architectural ideas behind oxAudit-owned Rust
contracts and make those capabilities visible through the desktop GUI.

The target is not to beat each project at its narrow specialty immediately.
cve-bin-tool has much broader component-signature coverage, and VulHunt has a
real disassembler/decompiler stack. oxAudit can become the stronger product by
combining deterministic source, secret, dependency, binary, advisory, evidence,
review, and reporting workflows in one approachable local application. Raw
coverage and semantic depth still need measured investment; they must not be
claimed from architecture alone.

## Study baseline

The review was pinned so later changes upstream do not silently change these
conclusions.

| Project | Commit reviewed | What was inspected |
|---|---|---|
| [ossf/cve-bin-tool](https://github.com/ossf/cve-bin-tool/tree/82dd1b050170e1ea0aaf2621b19762ce6aa5fd95) | `82dd1b050170e1ea0aaf2621b19762ce6aa5fd95` (2026-08-04) | checker metaclass and entry points, version scanner, archive recursion, CVE database and source adapters, SBOM/VEX managers, output engines, tests, contributor process, 17 CI/supply-chain workflows |
| [vulhunt-re/vulhunt](https://github.com/vulhunt-re/vulhunt/tree/53b825969c5e3aed65360410b15475ced7e01574) | `53b825969c5e3aed65360410b15475ced7e01574` (2026-07-16) | 13-crate workspace, BIAS pipeline, loaders, IR/CFG/SSA/decompiler, checker database and rule scopes, report sinks, JSONL stream, MCP session, tests, build/release workflows, per-crate licences |
| [capitalone/VulnHunter](https://github.com/capitalone/VulnHunter/tree/4042d34609ff85e0029dd55743b9c3f677cc984a) | `4042d34609ff85e0029dd55743b9c3f677cc984a` (2026-08-15) | Hunt/Fix/Verify phases, candidate manifest, schema contracts, headless agent, sandbox/auth seams, resumable benchmark harness, 83 Python test modules, PR test workflow, contribution and security guidance |

The local oxAudit comparison uses commit
`da420ee3215dd68ce7256692f21c7b0ac3391b3b` plus the uncommitted Source Results
work present on 2026-08-21. Existing user changes were treated as part of the
current product and were not rewritten during this study.

## What each project gets right

### cve-bin-tool: coverage, interchange, and operating discipline

Its core separation is useful:

1. discover components from binaries, package manifests, or existing SBOMs;
2. normalize them into vendor/product/version identities;
3. enrich them from replaceable advisory sources;
4. apply triage/history data;
5. render several output formats.

The checker contract is intentionally small. A checker declares filename,
identity, contains, version, and ignore patterns. A metaclass validates and
compiles it, while Python entry points allow additional checkers. At the pinned
commit there are 448 built-in checker modules. The advisory database collects
multiple feeds through a source abstraction. The product also imports and
generates SPDX/CycloneDX SBOMs, imports and generates VEX, supports offline use,
and has multiple reporting formats.

Its engineering process is the most mature of the three: about 500 Python test
modules and 2,080 files in the test tree, cross-version/OS testing, separate
long and external tests, scheduled fuzzing, CodeQL, dependency review, OpenSSF
Scorecard, runner hardening, automated SBOM maintenance, formatting, linting,
spelling, YAML validation, and build workflows.

What should not be copied:

- The checker code is GPL-3.0-or-later. Translating its regexes into Rust is not
  a licence-safe shortcut.
- Every checker can rescan the same extracted strings. oxAudit's compiled
  `RegexSet` design is already materially more efficient.
- Detection, database refresh, triage, and output are coordinated by a large
  CLI-first path. oxAudit should keep these capabilities independently usable.
- The first-use database lifecycle is operationally heavy. Detection must remain
  usable without an advisory download, and stale/offline state must be explicit.

### VulHunt: a real analysis pipeline and evidence-bearing rules

VulHunt's strongest architectural idea is the BIAS source → analysis groups →
sink pipeline. Loaders produce packages/components, analyzers attach typed
properties, and report sinks can collect complete results or emit bounded JSONL
streams. That makes analysis independent of presentation and gives large runs a
streaming path.

Its checker database compiles rules before a scan and filters them by platform,
architecture, project conditions, scope, signature availability, and required
extensions. The engine caches symbol and type work shared by applicable rules.
Rules can combine raw byte patterns, function signatures, calls, source syntax,
IR/dataflow, and decompiler context. Findings carry classifications, metrics,
references, variants, provenance, and evidence instead of only a message.

The analysis core goes much deeper than oxAudit today: loaders for several
binary/container types, architecture lifters, CFG/call-graph/SSA models,
function naming through FLIRT, decompilation, and architecture-independent
PCode-style reasoning. Its MCP adapter also demonstrates that a secondary
interface can sit on top of one stateful project model instead of rebuilding
analysis logic.

What should not be copied:

- `bias-vulhunt-engine`, the CLI, and MCP server are GPL-3.0. The Lua engine is
  not suitable for direct inclusion in Apache-licensed oxAudit.
- The rule VM is created with an unsafe Lua context. An end-user rule system in
  a desktop security app should begin with a bounded declarative schema, not
  executable scripts.
- The toolchain is large: LLVM, patched LuaJIT, a Ghidra-derived decompiler, and
  platform data. It would turn basic oxAudit scans into a specialist build.
- The product remains CLI/MCP-first and has only build/release workflows at the
  pinned commit; it does not provide oxAudit's desktop workflow or equivalent
  PR test discipline.

The permissively licensed `bias-core`, `bias`, and `bias-compat-*` crates remain
valid references or possible optional dependencies, subject to a separate
dependency and provenance decision. They are not required to adopt the pipeline
and rule-contract ideas.

### VulnHunter: falsification, independent verification, and measurement

VulnHunter's durable lesson is phase separation:

`Recon → Hunt → Adversarial verification → Reproduce/Test → Fix → Independent verify`

Candidates are not findings until they survive explicit falsification gates.
Before verification, a manifest fixes the candidate population; the verdict
set must account for every candidate exactly once. Fix verification is a
separate, read-only role rather than the actor that produced the fix approving
its own work.

The headless agent adds useful implementation discipline around the prompts:
schema-validated scan and verify manifests, one authentication seam, provider
interfaces, sandbox settings, JSONL audit events, retry handling, deduplicated
publishing, and stable result-directory contracts. The harness persists state
atomically after each phase, resumes interrupted batches, scans targets pinned
to exact commits, judges against ground truth, and reports detection rate,
misses, time, cost, tokens, and turns. Its latest repository has 83 Python test
modules and over 1,600 test functions/cases by static count.

What should not be copied:

- The core hunt is prompt-driven and deliberately tied to a frontier Claude
  model. oxAudit's baseline must remain deterministic and provider-neutral.
- The shipped ground-truth corpus is intentionally minimal and uses an LLM
  judge. oxAudit needs deterministic assertions wherever exact evidence exists,
  with model judging limited to semantic cases and sampled for variance.
- Automatic cloning, GitHub issue creation, fixes, commits, and PRs are useful
  automation adapters, not safe defaults for a local GUI.
- One Linux pytest workflow is not enough for a cross-platform desktop app.

## Current oxAudit architecture: strengths and gaps

### Strengths already present

- Tauri v2 + React makes the GUI the real application, not a viewer bolted onto
  a CLI.
- Native source, secret, dependency, binary, and advisory capabilities work
  without installing the three studied projects.
- The binary scanner already reimplements the component/version method with 71
  original signatures, a one-pass candidate matcher, ELF package-note parsing,
  architecture-specific byte patterns, numeric version decoding, evidence
  ranking, plausible ranges, CPE tripwires, and NVD/OSV/KEV/EPSS enrichment.
- cve-bin-tool and Grype remain optional, arms-length adapters rather than core
  dependencies.
- VulnHunter-inspired gates, scope classification, and the silent-drop manifest
  are enforced in Rust. The durable Source Results GUI exposes evidence-backed
  human review and prevents AI from silently changing disposition.
- Source runs, reviews, coverage, diff state, retention, policy, retry, and
  interrupted-run recovery are durable in SQLite with extensive Rust tests.
- The agent layer already has read-only project tools, permission gates,
  cancellation, budgets, and typed streaming events.

### Structural gaps

The main issue is not missing capability; it is inconsistent boundaries.

- Source runs use the durable findings service, while dependency and binary
  scans still have separate result and lifecycle models.
- `findings/repository.rs` (~5,700 lines), `findings/policy.rs` (~5,675),
  `findings/service.rs` (~3,400), and `commands.rs` (~1,950) contain too many
  responsibilities. They are difficult extension points even though they are
  well tested.
- Domain types can depend directly on scanner, Tauri, SQLite, HTTP, and screen-
  specific DTO concerns. There is no single port boundary for detectors,
  advisory providers, persistence, report writers, or run events.
- Each page coordinates progress, cancellation, loading, and result state in
  its own way. There is no shared durable run state machine for the GUI.
- Findings are the common object, but artifacts, components, observations,
  evidence, advisory matches, and verification are not yet one normalized
  graph.
- Rules are compiled into Rust or one internal TOML file. There is no versioned,
  validated, testable rule-pack contract or GUI rule library.
- SBOM, VEX, SARIF, and schema-versioned native exports remain roadmap items.
- NVD, OSV, KEV, and EPSS work, but they are not exposed as one provider registry
  with snapshot provenance, health, age, offline status, and atomic refresh.
- There is no committed GitHub Actions workflow. Local coverage is strong (483
  Rust test attributes and 14 frontend test files), but it is not a merge gate.
- There is no shared ground-truth benchmark for precision, recall, cross-build
  binary coverage, performance, or triage accuracy.

## Adoption matrix

Status meanings: **keep** is already suitable, **strengthen** exists but lacks a
shared contract or GUI surface, **build** is missing, **later** is intentionally
deferred, and **reject** should not enter the core product.

| Source idea | oxAudit status | Decision | GUI-first application |
|---|---|---|---|
| cve-bin-tool checker contract and extension entry points | Internal TOML signatures only | **Strengthen** into an oxAudit-owned declarative rule-pack schema with validation, provenance, fixtures, versioning, and compatibility checks | Rule Library: enable/disable, origin, supported targets, test health, last update |
| cve-bin-tool's 448-component breadth | 71 original native signatures plus package metadata | **Build**, without copying GPL patterns | Coverage dashboard and evidence-backed signature derivation queue |
| Independent advisory-source adapters | NVD/OSV/KEV/EPSS exist separately | **Strengthen** behind `AdvisoryProvider` and snapshot contracts | Data Sources: health, age, provenance, refresh, offline readiness |
| SBOM import/generation | Missing | **Build** CycloneDX + SPDX after normalized inventory lands | Inventory and Export Center |
| VEX import/generation and reusable triage | oxAudit policy/reviews are local-native only | **Build** mappings to OpenVEX and CycloneDX VEX | Review workflow can import/export dispositions with conflict preview |
| SARIF and versioned machine output | JSON only and screen-specific | **Build** report writers over one schema | Export Center with format explanation and validation result |
| cve-bin-tool CI, fuzzing, and supply-chain workflows | No repository workflows | **Build first** with cross-platform test/build, parser fuzzing, dependency review, CodeQL, SBOM, release signing/attestation | Quality screen can show released rule/data versions; CI itself remains developer infrastructure |
| VulHunt source/analyzer/sink pipeline | Per-feature orchestration | **Build** as an application `RunCoordinator` plus ports | One run timeline and consistent cancel/retry/failure behavior for every scan type |
| VulHunt typed package/component/property reporting | Partial `Finding` model | **Build** normalized Artifact → Component → Observation → Finding → Evidence relationships | Evidence Explorer and component inventory linked to findings |
| VulHunt precompiled, filtered rules | Native signatures compile once; source rules are embedded | **Strengthen** and apply across source, secret, dependency, and binary rules | Advanced users can inspect exactly why a rule applied |
| VulHunt IR/dataflow/decompiler depth | Only bounded byte decoding | **Later**, behind a `SemanticAnalyzer` port and capability tier | “Deep binary analysis” is explicit, optional, local, and progress-heavy—not hidden inside normal scan |
| VulHunt MCP adapter | oxAudit has an internal assistant tool loop | **Later** as a secondary adapter only | GUI remains authoritative; MCP never becomes required for desktop use |
| VulHunt GPL Lua engine | Not present | **Reject** | Use a bounded declarative rule format; no arbitrary rule scripts by default |
| VulnHunter falsification gates | Enforced in Rust and exposed in Source Results | **Keep and extend** to every finding family with category-appropriate gates | Guided review forms, evidence requirements, and visible deciding gate |
| VulnHunter candidate manifest | Enforced for persisted source observations | **Extend** to every run and every adapter | Run completion shows accounted-for observations; dropped/invented records are hard failures |
| Independent read-only verification | Human review exists; AI drafting is not independent verification | **Build** as a distinct use case and record type | “Verify” action, verifier identity, evidence delta, and never self-approval |
| Resumable ground-truth benchmark | Missing | **Build first** with deterministic and semantic suites | Quality Lab: precision, recall, misses, false positives, speed, cost, rule regressions |
| Hunt → auto-fix → PR | Read-only AI tools by design | **Reject as a default**; consider an opt-in future adapter only | The GUI may prepare a remediation plan, but code mutation requires a separate explicit product decision |
| Headless cloning/publishing/issues | Not core | **Later**, as automation adapters over stable contracts | Desktop workflows remain complete without GitHub or cloud accounts |

## Licence and provenance boundary

The architectural study permits reimplementation of methods, not copying code
or rule data.

- Do not translate or transcribe cve-bin-tool checker patterns.
- Do not include VulHunt's GPL rule engine, CLI, MCP server, or GPL rule code.
- If a permissive VulHunt/BIAS crate is ever evaluated, record its exact crate,
  commit, licence, transitive dependency graph, maintenance status, and why an
  internal implementation is inferior before adding it.
- Every oxAudit rule pack must declare author, source/provenance, licence,
  creation method, engine compatibility, fixtures, and a content hash.
- Component signatures continue to be derived from independently known-version
  binaries and clean fixtures. Public component names can define a coverage
  backlog; upstream GPL regexes cannot define the implementation.
- Keep external cve-bin-tool/Grype adapters optional for users who need a second
  opinion. The native path must remain complete enough for ordinary GUI use.

## How oxAudit becomes stronger

oxAudit's defensible advantage should be **trustworthy synthesis**:

1. deterministic native scanning is the baseline;
2. every result retains its artifact, detector, rule, evidence, advisory source,
   confidence, and transformation history;
3. no candidate can disappear between detection, enrichment, review, and export;
4. AI can explain, correlate, and propose evidence but cannot silently alter
   authoritative state;
5. every major capability can be run, configured, understood, and exported from
   the GUI;
6. quality claims are backed by visible benchmarks rather than rule counts;
7. standard formats make oxAudit interoperable without making other tools runtime
   dependencies.

That would make oxAudit easier to use than all three, more integrated than any
one of them, less model-dependent than VulnHunter, operationally lighter than
cve-bin-tool, and safer to extend than a Lua-based desktop rule engine. It will
not make the binary engine semantically deeper than VulHunt until the later IR
work is actually built and benchmarked.

## Traceability to existing studies

This document supersedes the old point-in-time conclusions where upstream or
oxAudit changed, but retains their implementation evidence:

- [`docs/binary-scanning-runtime.md`](../binary-scanning-runtime.md)
- [`docs/binary-signatures.md`](../binary-signatures.md)
- [`docs/vulhunt-study.md`](../vulhunt-study.md)
- [`docs/vulnhunter-study.md`](../vulnhunter-study.md)

The corresponding target architecture and implementation order are in
[`2026-08-21-gui-first-target-architecture.md`](2026-08-21-gui-first-target-architecture.md).
