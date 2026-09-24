# Architecture strengthening implementation status

> Status on 2026-08-21. This document records what the repository implements;
> it is not a claim that oxAudit already matches specialist projects in corpus
> breadth or full-program binary semantics.

## Implemented architecture

| Area | Repository evidence | GUI workflow |
|---|---|---|
| Compiler boundaries | `oxaudit-domain`, `oxaudit-application`, `oxaudit-scanners`, and `oxaudit-benchmark` workspace crates plus dependency-wall tests | Capabilities are presented through feature workbenches rather than crate concepts |
| Shared durable runs | Canonical SQLite runs, artifacts, components, observations, evidence, findings, projections, provider snapshots, benchmark history, and verification records | Source, Dependency, and Binary screens rehydrate completed results and share a run timeline |
| Run integrity | Typed state machine, sequenced events, persistence retries/recovery, stage manifest reconciliation, cancellation, and explicit warnings | Lifecycle, cancellation, warnings, and retained last results remain visible |
| Rules and provenance | Bounded declarative TOML compiler, immutable content hashes, fixture hashes, provenance validation, path containment, signature provenance registry, parser fuzz target, and a managed install store with per-pack enable state | Rule Library shows built-ins, validates a selected public pack, and installs it; enabled packs' source_regex/secret_regex rules apply to every source scan with pack-qualified rule ids |
| Quality | Resumable ground-truth runner, committed source smoke corpus, precision/recall/miss/runtime output, and persisted regression baseline | Quality Lab states corpus size and limitations rather than presenting a vanity score |
| Advisory data | Immutable content-addressed provider records; exact OSV query snapshots for Dependency scans; binary advisory receipts; representative NVD/OSV/EPSS refresh and full KEV snapshot | Data Sources shows source, terms, hash, age, validation, offline readiness, and limitations |
| Inventory | Components persist independently of advisory matches with identities, artifacts, aliases, confidence, and purl/CPE fields | Inventory shows vulnerable and unflagged components from durable Dependency, Binary, and Import runs |
| Standards | Validated oxAudit JSON, SARIF 2.1.0, CycloneDX 1.6, SPDX 2.3, OpenVEX, and CycloneDX VEX writers; bounded structural import inspection; separate immutable SBOM import runs with hash confirmation and conflict preservation | Export Center previews exports, validates imports, lists conflicts/unmapped records, and never silently applies VEX/SARIF review state |
| Verification | Immutable verification records, input snapshot hashes, producer/verifier independence check, and Completed → Verifying → Completed lifecycle | Verification workbench requires a separate human identity and makes limitations explicit |
| Optional semantic tier | Bounded object metadata/symbol/relocation analyzer with typed call evidence and no external runtime | Binary Scan exposes an opt-in Deep analysis switch and limitations |
| Engineering gates | Cross-platform CI, strict Clippy, frontend checks/tests/build, schema/provenance/benchmark gates, CodeQL, dependency review, Dependabot, and scheduled rule-pack fuzzing | Failures remain repository gates rather than hidden runtime behavior |

## Deliberate limits

- The committed benchmark corpus is a deterministic smoke corpus, not evidence
  of representative security recall. Its size is visible in Quality Lab.
- Built-in source and secret rules remain compiled snapshots while the public
  declarative compiler and safe validation boundary mature. The Rule Library
  labels fixture gaps instead of claiming complete provenance coverage.
- Installed packs apply only their text-engine (source_regex, secret_regex)
  rules today; dependency, binary, and semantic engine rules validate and
  display but do not run. Runs record the pack ids they applied; snapshot
  hashes live in the pack store, and CLI application of installed packs is
  future work.
- OSV dependency snapshots are exact query receipts, not a bundled mirror of
  the entire OSV corpus. The Data Sources page reports that distinction.
- SARIF and VEX imports stop at a conflict/unmapped preview. They cannot mutate
  findings or reviews until an explicit trust and mapping workflow exists.
- Semantic binary analysis reads object-level symbols and relocations. It does
  not implement lifting, CFG/SSA reconstruction, decompilation, or VulHunt-level
  semantic depth.
- Optional cve-bin-tool and Grype adapters remain external and clearly labelled;
  no GPL code or rule data is bundled or translated.

These limits preserve the GUI-first, local-first, clean-room product boundary.
Future depth should be accepted only with fixtures, provenance, bounded resource
behavior, and a complete GUI workflow.
