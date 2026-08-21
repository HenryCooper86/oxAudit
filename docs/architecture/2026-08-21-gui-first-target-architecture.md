# oxAudit GUI-first target architecture

> Architecture direction derived from the pinned upstream study in
> [`2026-08-21-upstream-architecture-study.md`](2026-08-21-upstream-architecture-study.md).

## Product rule

The desktop GUI is the primary product and must expose a complete workflow for
non-specialists. CLI, MCP, CI, and automation integrations may be added as
adapters over the same application use cases; they must not contain unique
scanning or review logic.

A normal user should be able to install oxAudit, choose a target, run useful
native scans, understand the evidence, review findings, and export results
without installing cve-bin-tool, VulHunt, VulnHunter, Python, Docker, an LLM, or
a cloud account.

## Architectural principles

1. **One domain, several engines.** Source, secret, dependency, binary, firmware,
   advisory, and semantic analyzers produce the same durable domain records.
2. **Detection is independent from enrichment.** A stale or absent advisory
   database must not prevent local inventory and evidence collection.
3. **Observations are immutable evidence.** Review changes disposition; it does
   not rewrite what a detector observed.
4. **No silent drops.** Every candidate entering a stage is accounted for at
   its exit. A missing, duplicate, or invented record is a failed run.
5. **AI is optional and non-authoritative.** AI may draft analysis and correlate
   evidence but cannot create hidden detections, expose raw secrets, approve its
   own work, or mutate policy without explicit review.
6. **Capabilities advertise themselves.** Engines, providers, rule packs, and
   exporters report version, health, provenance, and limitations. The GUI never
   presents unavailable capability as an unexplained disabled control.
7. **Bounded untrusted input.** Archive, binary, manifest, report, rule, and
   provider parsers have size/depth/time limits and fuzz targets.
8. **Standards at the boundary.** Internal models prioritize fidelity; SARIF,
   CycloneDX, SPDX, OpenVEX, and JSON schemas are import/export adapters.
9. **Compiler-enforced direction.** Core domain and application crates do not
   depend on Tauri, React, SQLite, HTTP clients, operating-system dialogs, or
   external scanners.
10. **Migration, not rewrite.** Existing scanners remain operational while they
    are wrapped behind ports one capability at a time.

## System shape

```text
┌──────────────────────────────── GUI: React feature workbenches ────────────────────────────────┐
│ Projects · New Scan · Run Timeline · Findings · Inventory · Evidence · Rules · Data · Quality │
└──────────────────────────────────── typed commands/events ─────────────────────────────────────┘
                                                │
┌────────────────────────────── Presentation adapters ───────────────────────────────────────────┐
│ Tauri commands · Tauri event bridge · DTO mapper · future CLI/MCP/CI adapters                  │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
┌────────────────────────────── Application layer ───────────────────────────────────────────────┐
│ RunCoordinator · scan/verify/review/export use cases · manifest reconciliation · policy        │
│ Ports: Detector · AdvisoryProvider · Repository · EventSink · ReportWriter · RulePackStore     │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
┌──────────────────────────────── Domain layer ──────────────────────────────────────────────────┐
│ Target · Run · Artifact · Component · Observation · Finding · Evidence · Advisory · Review    │
│ stable IDs · state transitions · provenance · confidence · schema versions                    │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
┌──────────────────────────────── Adapters and engines ──────────────────────────────────────────┐
│ Native source/secret/dependency/binary engines · optional semantic engine                      │
│ NVD/OSV/KEV/EPSS providers · SQLite · filesystem · report formats · optional external tools   │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The dependency arrows point inward. Adapters implement application ports; the
application layer does not import adapters.

## Rust package boundaries

Do not reproduce VulHunt's 13-crate layout immediately. Four compilation
boundaries are enough to make dependencies honest:

```text
src-tauri/
  crates/
    oxaudit-domain/       pure domain records, IDs, transitions, invariants
    oxaudit-application/  use cases, ports, coordinator, stage manifests
    oxaudit-scanners/     native deterministic scanners and rule compilation
  src/                    Tauri host and concrete adapters
    adapters/
      advisory/           NVD, OSV, KEV, EPSS
      persistence/        SQLite repositories and migration
      reporting/          JSON, SARIF, SBOM, VEX
      external/           optional cve-bin-tool and Grype processes
      filesystem/         bounded discovery/extraction and OS integration
    presentation/         Tauri commands, event mapping, DTOs
```

`oxaudit-domain` should have only small serialization/identity dependencies.
`oxaudit-application` depends on the domain. `oxaudit-scanners` depends on the
domain and implements application ports through a thin composition layer. The
Tauri host may depend on all three.

This split should begin by extracting new contracts and wrapping existing code.
Moving all existing files before the seam is proven would produce a large diff
without improving behavior.

## Canonical domain

### Target and Run

`Target` records what the user selected and its resolved safety properties:
canonical local path, target kind, display label, authorization acknowledgement
where relevant, and enabled scan profile.

`Run` is the durable state machine for every scan kind:

```text
queued
  → discovering
  → detecting
  → normalizing
  → enriching
  → assessing
  → persisting
  → completed

Any active stage → cancelling → cancelled
Any active stage → incomplete or failed
Completed → verifying → completed (with a new Verification record)
```

Runs record engine/rule/provider snapshot IDs, coverage, timing, warnings,
failure codes, and cancellation. A terminal run is immutable; a retry creates a
new attempt or completes a reserved persistence operation with the same run ID,
according to the existing durable-save contract.

### Artifact and Component

`Artifact` is a concrete input: source file, lockfile, binary, archive member,
container layer, SBOM, or report. It has a content identity where practical,
parent/container relationships, size/type, and normalized project-relative
location.

`Component` is a software identity inferred or declared from artifacts. It can
carry CPE, purl, ecosystem, package aliases, version, supplier, and confidence.
Different evidence can support one component; conflicting identities remain
visible rather than being silently merged.

### Observation, Finding, and Evidence

`Observation` is an immutable output from a detector. Kinds include:

- source weakness candidate;
- secret candidate (always redacted at the scanner boundary);
- dependency declaration;
- binary component evidence;
- advisory match;
- policy or configuration concern;
- semantic data-flow candidate.

`Finding` is the durable security issue assembled from one or more observations.
It carries stable fingerprint/version, scope, severity inputs, classifications,
diff status, current review projection, and references to all contributing
evidence. It does not embed adapter-specific result structures.

`Evidence` is typed rather than a free-form string:

| Evidence kind | Minimum fields |
|---|---|
| file location | artifact ID, normalized path, range, content hash/context hash |
| sanitized excerpt | artifact ID, redacted text, redaction reason |
| binary match | artifact ID, offset/section, matcher ID, encoding, captured value |
| package declaration | artifact ID, ecosystem, declared identity/version |
| component identity | component ID, method, value, confidence, aliases |
| advisory match | component ID, provider snapshot ID, advisory ID, affected-range decision |
| data flow | ordered nodes/edges, entry point, sink, unresolved edges |
| gate decision | gate, verdict, rationale, supporting evidence IDs |
| tool receipt | engine/version, rule/version, bounded invocation metadata |

Raw credentials are never valid evidence payloads. Hashes used for correlation
must be keyed or otherwise resistant to offline recovery when the input has low
entropy.

### Review and Verification

`Review` is an analyst disposition: candidate, confirmed, false positive,
accepted risk, or suppressed. It preserves the current gate contract, author,
origin, evidence references, reason, expiry, and policy projection.

`Verification` is separate. It records the claim being checked, verifier kind
and identity, input snapshot, result, evidence delta, limitations, and time. A
producer cannot mark its own result independently verified. AI-generated text
is a draft until a user or explicitly separate verifier accepts it.

## Application ports

Interfaces should be narrow, async only where the operation is genuinely async,
and return typed errors safe to map into GUI messages.

```rust
trait Detector {
    fn descriptor(&self) -> CapabilityDescriptor;
    fn supports(&self, artifact: &ArtifactDescriptor) -> bool;
    fn detect(&self, input: DetectionInput, sink: &dyn ObservationSink)
        -> Result<DetectionSummary, DetectionError>;
}

trait AdvisoryProvider {
    async fn snapshot(&self, request: SnapshotRequest)
        -> Result<ProviderSnapshot, ProviderError>;
    async fn query(&self, snapshot: &ProviderSnapshot, component: &Component)
        -> Result<Vec<AdvisoryMatch>, ProviderError>;
}

trait RunRepository { /* start, append observations, complete, recover, load */ }
trait RulePackStore { /* discover, validate, enable, resolve compatible snapshot */ }
trait ReportWriter { /* describe, validate options, write from canonical run */ }
trait RunEventSink { /* emit sequenced lifecycle/progress/domain events */ }
trait Verifier { /* verify a claim from an immutable input snapshot */ }
```

The exact Rust signatures can change during implementation; the dependency
direction and responsibilities cannot.

## Run coordinator and event contract

`RunCoordinator` owns stage transitions, cancellation, manifests, persistence,
and event sequencing. Detectors do not emit Tauri events or write SQLite
directly.

Events use a versioned envelope:

```json
{
  "schemaVersion": 1,
  "runId": "...",
  "sequence": 42,
  "occurredAt": "...",
  "type": "observation.recorded",
  "stage": "detecting",
  "payload": {}
}
```

Required events include run/stage started and completed, artifact discovered,
observation recorded, finding projected, warning, cancellation requested, and
terminal completion/failure. Sequence numbers let the GUI reject duplicates or
notice a gap. Events are progress hints, not authoritative storage: after a
reload or missed event, the UI rehydrates from `load_run`.

Each stage receives a manifest and returns an accounting result. Completion
fails if inputs are missing, duplicated, or replaced by records without a
declared relationship. This generalizes the existing VulnHunter-inspired
candidate manifest to every adapter.

## Rule-pack architecture

The first public rule system should be declarative and bounded. It should not
load native dynamic libraries, execute shell commands, or run arbitrary Lua,
JavaScript, Python, or WebAssembly.

```text
rule-pack/
  manifest.toml       pack ID/version, author, licence, provenance, engines
  rules/
    *.toml            rule metadata and engine-specific bounded expressions
  tests/
    positives/
    negatives/
    expectations.json
  NOTICE
```

Every rule declares:

- stable rule ID and revision;
- engine/schema version;
- title, category, CWE/classifications, remediation, and severity inputs;
- applicable artifact kinds, languages/platforms, architectures, and conditions;
- identity and evidence requirements;
- patterns/decoders within the selected bounded engine;
- provenance, author, licence, and creation method;
- positive and negative fixtures or references to a maintained clean corpus.

Initial engine schemas:

- `source.regex.v1` with language/scope guards and bounded context;
- `secret.regex.v1` with entropy, placeholder, and redaction policies;
- `binary.signature.v1` with contains/filename/package-note/byte evidence,
  identity constraints, architecture, decoder, and plausible ranges;
- `policy.check.v1` for deterministic project-configuration checks.

Packs compile once into immutable snapshots. A run stores the snapshot hashes,
so later rule updates cannot change historical meaning.

The GUI Rule Library shows installed/built-in packs, provenance, compatibility,
enabled state, rules, test health, coverage, last update, and validation errors.
Advanced editing can come later; inspectability comes first.

## Advisory and offline data architecture

NVD, OSV, CISA KEV, and EPSS become adapters in a provider registry. A provider
snapshot records:

- provider and schema version;
- source URL/identity and licence/terms reference;
- fetched/generated time and age policy;
- content hash and record count;
- full vs incremental refresh ancestry;
- validation result and last successful snapshot;
- online, stale, offline-ready, disabled, or failed state.

Refresh writes to a new snapshot, validates it, and switches the active pointer
atomically. A failed refresh never destroys the last known-good data. Detection
can complete without enrichment and mark it deferred. The GUI Data Sources page
shows these states and lets the user refresh, select offline mode, or retry.

## Standard interchange

Report writers consume the canonical run; scanners never know output formats.

Priority order:

1. versioned oxAudit JSON schema with complete provenance and evidence;
2. SARIF for source/secret/configuration findings;
3. CycloneDX and SPDX for normalized inventory/SBOM;
4. OpenVEX and CycloneDX VEX for review disposition exchange;
5. concise HTML/PDF only after the data formats are stable.

Imports first produce a preview with validation errors, conflicts, and records
that cannot be mapped. No VEX or policy import silently overwrites a newer local
review.

## GUI information architecture

The existing workbench remains the visual foundation. New architecture appears
as coherent workflows, not as a developer-facing module list.

### Projects and New Scan

- recent/local projects and target picker;
- Quick, Standard, and Deep profiles with plain-language cost/depth descriptions;
- capability check before start;
- advanced engine/rule/provider selection behind disclosure;
- no external-tool setup in the default path.

### Run Timeline

- one stage timeline for every scan kind;
- files/artifacts processed, observations, warnings, elapsed time;
- cancel, retry persistence, resume supported work, and failure recovery;
- last completed results stay visible during the next run.

### Findings and Evidence

- persistent Open / Other scopes / Closed / Resolved views;
- a dossier linking location, detector/rule, evidence, component, advisory,
  exploit signals, gates, reviews, verification, and history;
- progressive detail so a non-specialist sees “what, why, what next” before raw
  offsets, CPEs, CVSS vectors, or provider payloads;
- every confidence label explains which evidence supports it.

### Inventory

- components and dependencies regardless of vulnerability status;
- aliases, versions, artifacts, confidence, and advisory coverage;
- SBOM import/export and conflict inspection.

### Rule Library, Data Sources, Quality Lab, Export Center

- Rule Library manages rule packs and shows test/coverage health.
- Data Sources manages advisory snapshots and offline readiness.
- Quality Lab displays benchmark precision/recall, missed cases, false positives,
  cross-platform/build coverage, runtime, and regressions.
- Export Center generates and validates JSON/SARIF/SBOM/VEX with a preview of
  included/redacted data.

## Work method and repository gates

Architecture is only credible if the repository continuously enforces it.

### Pull request gates

- frontend format/type/test/build;
- Rust format, unit/integration tests, and a warning-free Clippy baseline;
- architecture dependency tests preventing domain/application imports of host
  adapters;
- JSON/TOML/schema fixture validation;
- rule-pack positive and negative fixtures;
- licence/provenance metadata checks for every new rule or corpus artifact;
- Linux, macOS, and Windows coverage appropriate to changed code;
- failure artifacts retained for diagnosis.

### Scheduled and release gates

- fuzz untrusted parsers and decoders;
- ground-truth benchmark and historical regression comparison;
- dependency/security review and code scanning;
- generated release SBOM;
- signed/notarized platform artifacts and published checksums;
- rule/data snapshot version and provenance included in release metadata;
- smoke-test clean install, first native scan, cancel, reopen run, and export.

### Contribution method

- architecture decisions live in short ADRs;
- a new detector starts with its port contract and fixtures, not a page-specific
  API;
- a new rule requires positive and negative evidence plus provenance;
- a new provider requires a snapshot lifecycle and offline/failure tests;
- a new report format maps from the canonical domain and includes round-trip or
  schema validation where the standard permits;
- benchmark changes report both improvements and regressions; raw rule count is
  never accepted as a quality metric.

## Phased migration

### Phase 0 — enforce the baseline

Deliverables:

- committed cross-platform CI for current frontend and Rust suites;
- pay down the inherited Clippy warning baseline and make warnings a gate;
- architecture ADR and module dependency check;
- versioned rule/provenance validation for the existing native signatures;
- benchmark skeleton with atomic state and a GUI-neutral result schema.

Exit: every pull request receives deterministic test/build feedback, and current
behavior has a measurable baseline before files move.

### Phase 1 — establish the domain and coordinator seam

Deliverables:

- `oxaudit-domain` and `oxaudit-application` crates;
- canonical IDs, Artifact/Observation/Evidence/Run records, state transitions,
  port traits, typed errors, and sequenced run events;
- adapters wrapping the existing source scanner and findings repository;
- Source Results behavior unchanged at the GUI level.

Exit: the current source workflow runs through `RunCoordinator`; domain crates
contain no Tauri, SQLite, HTTP, or screen dependencies.

### Phase 2 — unify scan families

Deliverables:

- wrap native dependency and binary scanners as `Detector` implementations;
- persist their runs, observations, inventory, evidence, and history;
- one shared run timeline/cancel/retry implementation in React;
- extend manifest accounting, policy, diff, retention, and redaction to every
  scan family.

Exit: source, secret, dependency, and binary results are durable projections of
the same domain and reopen identically after restart.

### Phase 3 — rule packs and coverage program

Deliverables:

- declarative pack schemas and compiler;
- migrate built-in source/secret/binary rules into versioned built-in packs;
- Rule Library GUI and pack snapshot history;
- clean-room signature derivation pipeline and prioritized corpus expansion;
- rule-level precision, recall, and performance reports.

Exit: adding a rule does not require changing Tauri commands or React pages, and
every built-in rule has provenance plus positive/negative test evidence.

### Phase 4 — providers and standards

Deliverables:

- provider registry and atomic snapshot lifecycle;
- Data Sources GUI and real offline mode;
- normalized inventory;
- oxAudit JSON schema, SARIF, CycloneDX/SPDX, and VEX adapters;
- Export Center with validation and redaction preview.

Exit: scan evidence is still useful offline, provider age/provenance is visible,
and standards exchange does not alter internal detector logic.

### Phase 5 — verification and quality

Deliverables:

- independent `Verifier` use case and immutable verification records;
- deterministic source/secret/dependency/binary ground truth;
- semantic benchmark lane with repeated model judging only where necessary;
- Quality Lab GUI showing accuracy, misses, false positives, speed, and cost;
- release gates against historical regressions.

Exit: “stronger” is supported by tracked metrics, and confirmation/verification
cannot silently approve incomplete evidence.

### Phase 6 — optional semantic binary tier

Deliverables:

- architecture decision on building an internal IR or using specific permissive
  BIAS components;
- `SemanticAnalyzer` adapter with resource budgets and capability reporting;
- function signatures, call graph, and bounded dataflow before decompilation;
- cross-architecture ground truth and GUI progress/evidence views;
- decompiler work only if earlier tiers show measured value.

Exit: deep analysis is optional and benchmarked. The ordinary native scan remains
fast, small, and dependency-free.

## First implementation slice

The strongest next slice is **Phase 0 plus the narrow Phase 1 seam**, not SBOM,
MCP, or a decompiler.

1. Add CI and make the current suite reproducible.
2. Define `Run`, `Artifact`, `Observation`, `Evidence`, `CapabilityDescriptor`,
   `Detector`, `RunRepository`, and `RunEventSink` in new core crates.
3. Write state-transition, manifest-accounting, redaction, and dependency-wall
   tests first.
4. Wrap the existing source scanner/findings service without changing the GUI.
5. Only after parity, route dependency and binary scans through the coordinator.

This gives every later adoption point a safe place to attach and avoids another
feature-specific subsystem.

## Definition of “stronger than these projects”

The claim is earned only when all of the following are true:

- a first useful scan needs no external tool or model;
- every ordinary capability is available in the GUI;
- all scan families share durable evidence, review, history, and export;
- no stage can silently lose candidates;
- provider/rule/engine provenance is visible per finding and per run;
- standard SBOM/VEX/SARIF exchange is validated;
- cross-platform CI, fuzzing, and release supply-chain controls are active;
- precision, recall, misses, performance, and coverage are measured over pinned
  ground truth;
- native signature breadth continues to grow through clean-room evidence;
- any claim of VulHunt-level semantic depth is made only after equivalent
  cross-architecture benchmarks pass.

Until then, the accurate statement is: oxAudit has a stronger GUI and integrated
workflow direction, with narrower binary signature coverage and much shallower
semantic binary analysis than the specialist projects.
