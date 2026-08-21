# ADR 0002: bounded semantic object analysis

- Status: Accepted
- Date: 2026-08-21

## Context

The upstream architecture study found real value in VulHunt's typed binary
analysis pipeline, but its disassembly, lifting, CFG, SSA, decompilation, and
rule stack are a large specialist system with licence and maintenance boundaries
that oxAudit must not blur. A GUI-first desktop scan also needs predictable
resource use and useful native behavior without a model or external tool.

## Decision

oxAudit adds an optional **Deep analysis** tier implemented as an original,
bounded adapter in `oxaudit-scanners`. It uses the permissively licensed
`object` crate (`Apache-2.0 OR MIT`) only to parse native object metadata,
symbols, and relocations. The adapter builds typed function/call evidence and
flags references to a small, explicitly maintained dangerous-sink set.

The analyzer enforces all of these budgets before returning evidence:

- at most 16 MiB of object input;
- configured function and call-edge ceilings;
- a wall-clock deadline checked during analysis;
- bounded unresolved-edge accounting;
- no archive extraction, process execution, network access, model call,
  dynamic library, rule script, IR lifting, or decompiler.

Deep evidence uses the same immutable Artifact → Observation → Evidence graph
as every other scan and is persisted before the GUI renders it. The Binary Scan
screen explains the tier's limitations and keeps it off by default.

## Consequences

- oxAudit gains function-signature and bounded call-reference evidence without
  installing or copying VulHunt.
- Ordinary binary component scanning remains the fast default.
- This tier must be described as object-level semantic evidence, not
  VulHunt-equivalent program understanding.
- A future CFG, data-flow, IR, or decompiler tier requires a new ADR, dedicated
  cross-architecture ground truth, fuzzing, and measured benefit over this tier.
- Malformed-object handling and budget exhaustion are explicit outcomes, never
  permission to continue with unbounded work.

## Rejected alternatives

- Porting or translating VulHunt internals: unnecessary licence and maintenance
  risk, and incompatible with the incremental clean-room boundary.
- Requiring a decompiler or LLM: breaks first-run, offline, and predictable-cost
  product requirements.
- Running deep analysis automatically: hides a meaningful performance/depth
  choice from the user.
