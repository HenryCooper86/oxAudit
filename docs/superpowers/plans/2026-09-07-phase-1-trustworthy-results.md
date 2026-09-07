# Trustworthy Results Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to execute this task, with a review before the phase is pushed.

**Goal:** Prevent incomplete dependency parsing from looking clean and expose source detection evidence honestly.

**Architecture:** Both dependency entry points fail before network lookup when any discovered lockfile cannot be parsed, using a shared completeness validator in the dependency module. Source finding details display the existing analysis tier. Paired authored workflow fixtures extend the regression corpus without claiming independent representative accuracy.

**Tech Stack:** Rust, Tauri, React, TypeScript, Vitest, existing corpus runner.

**Spec:** `docs/superpowers/specs/2026-09-07-everyday-engineering.md`

## Global Constraints

- Main-branch work and push after each verified phase are user-authorized; controller owns commits/pushes.
- Preserve scan limits, containment, redaction, policy semantics, and stored projection compatibility.
- Incomplete work cannot be reported as a completed clean scan.
- Do not claim the authored fixtures are an independent or representative benchmark.
- Do not spawn additional agents. Use behavior tests and run them before and after implementation.

### Task 1: Complete dependency coverage and honest source evidence

**Files:**
- Modify `src-tauri/src/deps/mod.rs` or create a focused completeness module exported from it.
- Modify `src-tauri/src/cli/mod.rs` and `src-tauri/src/commands/dependencies.rs`.
- Modify `src/components/FindingDetail.tsx`; add its component tests.
- Add fixtures under `benchmarks/corpus/source/`; regenerate `benchmarks/corpus/suite.json`.
- Update README coverage/error semantics and corpus documentation.

**Interfaces:**
- Shared validator consumes parser errors and returns `Result<(), String>`; empty errors succeed; any error returns a bounded message naming incomplete dependency coverage and failed lockfiles. Existing resource-limit errors remain unchanged.
- CLI consumes validator failure through `failure(...)`, preserving exit code 3. Desktop propagates the same error so its managed run terminates Failed and its existing previous-result UI remains available.
- Finding detail consumes existing `finding.analysis` and `analysisGates` only; no new persisted model field is needed.

- [x] Reproduce incomplete coverage with an invalid package-lock fixture and CLI `deps` execution. Add a test that uses a real temporary directory and calls `run_deps` with invalid JSON; require exit 3 with a lockfile parsing explanation before network lookup. Add a mixed valid/invalid lockfile case. A valid empty inventory must not be described as parsing failure.
- [x] Implement the shared completeness check immediately after parsing and cancellation checks, before usage indexing, OSV, or completed-run persistence. Remove unreachable warning-only parsing code. Preserve last completed results through existing UI failure behavior.
- [x] Cover missing advisory evidence too: a failed OSV lookup or offline cache miss must not render as no published vulnerabilities. Fail the required lookup and retain previous completed results, or propagate explicit incomplete coverage to the result/UI. Old projections lacking coverage evidence must not acquire a new completeness claim. Full-detail failures must remain visible or fail consistently.
- [x] Render source finding detail with syntax and text tiers in a component test. Assert the syntax case explains that the match is in parsed code and does not prove exploitability; the text case explains that syntax was not verified. Preserve redaction and human-review state.
- [x] Add the analysis evidence section near the evidence itself, using plain language and accessible section naming. Existing run hashes/IDs can stay available without dominating remediation.
- [x] Add paired authored everyday source scenarios: request-derived versus constant command invocation, parameterized versus concatenated SQL, and request-derived versus fixed outbound URL, choosing supported rules and inspecting their existing fixtures first. Run the corpus to establish actual outcomes. If a negative reveals a real detector defect, fix only with sound bounded evidence; do not weaken fixture expectations to retain a perfect score.
- [x] Regenerate the manifest using `node tools/build-corpus-suite.mjs`. Record provenance and limitations of the scenarios and exact measured results, avoiding unverified general accuracy claims.
- [x] Run `npm run check`, `npm test`, focused Rust completeness/CLI tests, and the committed corpus benchmark. The controller runs broader checks and review before commit and push.

**Acceptance:** Invalid or partially parsed dependency targets fail consistently before advisory requests; source evidence level is visible and honest; paired fixtures are executable, hash tracked, and measured. No source/secret review policy or raw-secret behavior changes.

Verification: full Rust workspace/all-features passed (912 tests before the final parser amendment); amended parser/CLI tests passed afterward. Frontend type-check, 120 Node tests, 96 Vitest tests and production build passed. Final strict workspace/all-target/all-feature Clippy and formatting passed. Two scoped review rounds resolved cache migration, valid-empty versus malformed inventory, and parser resource-use findings.
