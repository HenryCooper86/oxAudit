# ADR 0001: GUI-first ports and adapters

- Status: Accepted
- Date: 2026-08-21

## Context

oxAudit has capable native source, secret, dependency, binary, and advisory
features, but their orchestration and persistence models have grown separately.
The three upstream projects studied in August 2026 demonstrate the value of a
small detector contract, a staged analysis pipeline, explicit manifests,
independent verification, and measured ground truth. Their CLI, GPL-licensed
rules, model dependency, and heavyweight runtimes do not fit oxAudit's product
or licence boundary.

## Decision

The desktop GUI is the primary product. Every ordinary workflow—target
selection, scanning, progress, cancellation, durable history, evidence review,
verification, data and rule management, quality inspection, and export—must be
usable without a CLI, cloud account, AI provider, or separately installed
scanner.

The Rust code is split into inward-pointing ports and adapters:

1. `oxaudit-domain` owns stable records, identities, state transitions,
   provenance, and invariants.
2. `oxaudit-application` owns use cases, ports, stage manifests, event
   sequencing, and run coordination.
3. `oxaudit-scanners` owns deterministic native detectors and declarative rule
   compilation.
4. The Tauri host owns SQLite, HTTP, filesystem, operating-system, optional
   external-process, and presentation adapters.
5. React workbenches invoke application use cases through typed Tauri commands
   and treat durable backend state as authoritative.

Automation interfaces may be added later over the same application use cases.
They may not contain scanner, policy, review, or export behavior unavailable in
the GUI.

All scan families produce the same canonical run, artifact, component,
observation, evidence, finding, review, and verification graph. Stage manifests
reject dropped, invented, or duplicate candidates. Detection remains useful
offline and independent from advisory enrichment. AI output is advisory and
cannot self-verify or silently mutate authoritative review state.

## Consequences

- Dependency direction is enforced by Cargo packages and dependency-wall
  tests, not by naming convention.
- Existing workflows migrate behind the ports one at a time; this is not a
  repository-wide rewrite.
- Events are a versioned GUI projection, never the source of truth.
- Rule packs and provider snapshots require version, provenance, compatibility,
  health, and content identities.
- JSON, SARIF, SBOM, and VEX live at adapter boundaries over canonical records.
- Optional cve-bin-tool and Grype integrations remain labelled external
  evidence. No GPL source or rule data is copied into the Apache-2.0 core.
- Quality claims must name their corpus size and come from reproducible,
  offline-capable benchmarks.

## Rejected alternatives

- Installing the studied tools as required runtimes: rejects the GUI-first,
  offline, lightweight, and licensing requirements.
- Keeping screen-specific orchestration: preserves inconsistent lifecycle,
  durability, and evidence behavior.
- A scriptable rule VM as the first extension mechanism: broadens the desktop
  trust boundary before bounded declarative packs are proven.
- A CLI-first core with a thin desktop wrapper: leaves ordinary users unable to
  understand or operate important capabilities.
