# Fix and Verify Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. Controller reviews, commits and pushes the phase.

**Goal:** Jump from finding to the exact editor location, understand a concrete remediation, and verify the observed finding against a new completed scan.
**Architecture:** Extend the existing contained file opener with a small typed editor setting, passed as argument vectors without a shell. A finding-recheck action uses existing full source scan and coverage-aware comparison with the original run; it is a scan observation, never a human review or independent verification record. Add curated remediation examples for common rules.
**Tech Stack:** Rust/Tauri settings and process arguments; React source result workflow and tests.
**Spec:** docs/superpowers/specs/2026-09-07-everyday-engineering.md

## Global Constraints
- Keep default system opener available. Editor commands must use an allowlisted executable/typed adapter, no command-template strings or shell evaluation. Preserve resolve_scan_finding_path containment and file existence validation. Pass validated positive line/column and support spaces in paths.
- Persist settings through existing settings publication/revision flow; older files default to system opener.
- A successful recheck does not prove exploitability absent. Distinguish still detected, no longer detected in covered file/rule-family, not evaluated, failed/cancelled and unsaved results. Never claim resolution from a missing/skipped file or incompatible scan options.
- No auto-fix or automatic review dismissal. No raw secrets in examples/handoffs. Controller commits/pushes; no child agents.

### Task 1: Editor navigation, examples and recheck

Files: commands/mod.rs opener or focused editor module, models.rs/settings adapters as necessary, src/lib/api.ts/types.ts, SettingsPage.tsx, FindingDetail.tsx, SourceScan.tsx, focused remediation/recheck model/tests, README.

- [x] Write backend behavior tests for exact file/line/column argument generation, invalid editor/positions, contained paths with spaces, removed files and escapes. Write frontend interaction test for preferred editor and exact finding-position IPC payload. Use documented VS Code '--goto file:line:column' argument vectors or a percent-encoded vscode://file URI (with exact positive line/column), and documented adapters for the user's chosen editor; plain system open remains fallback only if explicitly selected, with errors visible otherwise.
- [x] Add a clearly labelled Editor section to Settings. Selected editor is saved using existing transactional settings mechanisms, including defaults and schema/contract tests where needed. Update openScanFinding signature to carry location, wire SourceScan's captured run root and finding position, and keep original path validator.
- [x] Add curated before/after remediation examples and short verification steps for JS eval/command execution/SQL, Python shell=True and SQL patterns, and secret rotation. Use rule IDs actually shipped; unsupported rules keep existing recommendations. Do not imply JSON.parse replaces arbitrary JS evaluation or identifier interpolation can be fixed by value placeholders. Explain input/behavior constraints. Examples never include actual detected secret content.
- [x] Add Recheck finding action. Capture original project/run/fingerprint/category; rerun with original run scan options (fetch captured options through backend if unavailable in response). Use the explicit coverage-aware comparison established in phase3 against that original run. Retain evidence and selected fingerprint after completion. Require a saved completed run and actual coverage; failed, cancelled or unsaved runs cannot resolve. If the code shifted context and a same-rule finding remains nearby, distinguish original no-longer-detected from verified fix; do not assert broad safety.
- [x] A visible outcome links original/new runs and says what was measured. Prevent overlap with project checks and other source scans; guard against project switches and stale completions. Use tests for still-present, covered absence, skipped/deleted file, no matching coverage, cancellation, failure and wrong-project response.
- [x] Run relevant Rust, npm check/test/build and corpus checks. Update daily workflow documentation.

Rule catalog pointer: src-tauri/src/scanners/patterns.rs contains shipped IDs js-eval, js-function-ctor, js-child-process, js-exec-concat, js-sql-concat, py-subprocess-shell, py-os-system, py-sql-fstring, py-sql-concat. Keep curated examples consistent with each native recommendation; if the existing recommendation for a curated rule suggests a conflicting substitute (js-eval currently mentions Function constructors), update that short recommendation too. Do not broaden into unrelated scanner rules.

Platform boundary: avoid passing repository-controlled filenames through cmd.exe/.cmd wrappers on Windows. The documented percent-encoded vscode://file URI is an acceptable typed, allowlisted adapter if it preserves validated canonical containment/position and reports unavailable handlers. Native launchers may have a different PATH from terminal shells, so do not imply installing the editor always installs its CLI. Verify scanner column units before claiming exact editor character positions; where byte offsets differ from editor character columns, convert using captured/validated line content or disclose the position limitation.

Confirmed stored source columns are byte offsets: scanners/mod.rs calls fs_utils::line_col(starts, hit.offset), whose implementation computes offset - starts[idx] + 1. Editor navigation must convert UTF-8 byte column to the editor's character convention for Unicode-containing lines. Keep historic finding coordinates/evidence immutable; convert at the opener boundary, with bounded reads and clear behavior when current line differs from the scanned file.

Primary editor references checked: https://code.visualstudio.com/docs/configure/command-line documents vscode://file/{full path}:line:column, and https://code.visualstudio.com/api/references/vscode-api#Position defines character offsets in UTF-16 code units. Include a non-BMP Unicode prefix test when converting byte columns.

Controller native editor validation is available: /Applications/Visual Studio Code.app is installed and its Info.plist registers the vscode URL scheme. Controller can use an owned QA source file with spaces/Unicode to observe exact-line navigation after building the phase. Do not change user editor preferences until explicit settings UI action in QA; restore original preference if changed for test.
