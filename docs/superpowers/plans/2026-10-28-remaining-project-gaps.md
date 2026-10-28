# Remaining project gaps implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans for implementation and review.

**Goal:** Address the six follow-ups explicitly approved in the conversation: standards validation, PDF text, SBOM fidelity, portfolio access/recovery, CSV qualifications, and human pilot readiness.

**Architecture:** Preserve existing command contracts where possible. Validate exports offline against bundled versioned schemas; preserve imported identities and graph links in canonical storage; retain existing report disclosure controls. Extend portfolio retrieval without replacing its schedule ownership logic.

**Tech Stack:** Rust, SQLite, React/TypeScript, existing test harnesses.

**Spec:** The six-item gap assessment and user's approval in this conversation.

## Constraints and review focus

- Preserve existing uncommitted fixes. No publication, outreach, or invented participant evidence.
- Exports must validate nested records and work without network access.
- Unicode output must preserve text or explicitly reject unsupported glyphs, never silently replace them.
- Import references must map to the correct canonical IDs; dangling references must be visible.
- Pagination must expose older projects and recover from transient errors without stale response overwrite.
- CSV must carry its evidence-only qualification without breaking tabular parsing.
- Human acceptance remains pending until actual participants run sessions.

## Tasks

- [x] Add offline standards-schema validation and malformed nested-record regression tests in reporting; verify every generated format.
- [x] Embed licensed Unicode fonts for PDF output, verify extracted text and rendered output, and add CSV claim qualification with parser-based tests.
- [x] Preserve SBOM licenses and dependency relationships through parser, command, persistence, and export; test graph/reference edge cases.
- [x] Add portfolio pagination and loading retry using existing UI conventions; test access beyond 50 projects and transient failures.
- [x] Prepare a concrete first human pilot session and technical preflight; leave actual observations pending.
- [x] Review changes independently and run frontend, Rust workspace, build, lint, and real browser/CLI checks.

## Implementation decisions and remaining human work

- Official standards schemas and their referenced schemas are embedded with
  source/license hashes; validation performs no remote or filesystem retrieval.
- Empty OpenVEX exports are rejected, because the format requires statements.
- The embedded PDF font supports the tested Chinese and accented Latin text.
  Unsupported glyphs, supplementary code points, or shaping sequences fail with
  an explicit error; HTML/JSON remain lossless alternatives for those inputs.
- Raw licenses and unsupported/ambiguous relationship evidence survive native
  JSON intermediary imports. They do not become invented canonical graph edges.
- The user selected a self-run maintainer pilot on oxAudit. The tailored guide
  is in `docs/daily-workbench-pilot.md`; observations remain zero until the user
  records actual task results. No participant feedback or acceptance was fabricated.

## Final verification

- `npm test`: 172 Node tests and 510 component tests passed.
- Rust workspace, all features: 1,493 passed, zero failed, one existing ignored test.
- Six real Chromium/backend scenarios passed, including portfolio page two and retry.
- Ten CI shell tests and the rebuilt CLI fixture pilot passed.
- Frontend build, CLI/server build, strict Clippy, formatting and diff checks passed.
- Three-page PDF inspected visually; independent extraction and metadata checks
  retained Chinese/accented text and all 4,903 rendered glyphs stayed in margins.
- Independent review found native intermediary fidelity issues; regressions were
  added and licenses, source relationships and unmapped diagnostics now survive.
- Ten bundled schema/license files independently matched their recorded hashes.
