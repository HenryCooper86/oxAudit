# Workbench usability implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement task by task.

**Goal:** Finish UX-06 through UX-08 from the accepted UI/UX source review.

**Architecture:** Keep the existing React/Tailwind layout. Reuse command-palette navigation and the paged canonical-results API; fetch dependency metadata and at most one vulnerability per severity only for the selected project. Preserve unknown coverage, latest-attempt state, and exact saved-run identity.

**Tech stack:** React, TypeScript, Zustand, Vitest/Testing Library. No dependencies, backend changes, or new scroll owner.

**Spec:** `output/ui-ux-review-2026-11-04/review.json`, UX-06 through UX-08. This continues the accepted review and the instruction to resume.

## Global constraints and review focus

- Preserve existing branding, keyboard navigation, explicit scan starts and saved-evidence boundaries.
- Keep local audit/planning files out of commit history; use descriptive commit metadata without attribution trailers.
- Live browser/native access remains unavailable or denied. Do not claim visual or screen-reader verification.
- Review selected older runs, history project changes, search focus restoration and competing modals, late summary responses across A→B→A and refresh, corrupt/missing projections and unknown coverage.

### Task 1: Compact run history

Files: `src/features/source-scan/RunHistory.tsx` and new component tests.
Interface: existing RunHistory props unchanged.

- [x] Test that a 50-run history initially renders at most three rows including the selected older run; expansion reaches every run; collapse preserves the selected run and control focus; changing projects resets expansion.
- [x] Run tests and confirm missing compact behavior fails.
- [x] Show three rows by default, reserving one for an older selection. Add an explicit Show all/Show fewer control without creating another scrolling region.
- [x] Run targeted tests and the full suite; expect all passing.

### Task 2: Visible command search

Files: `src/App.tsx`, `AppShell.tsx`, `WorkbenchHeader.tsx`, shell and actual-app integration tests.
Interface: App owns opening the existing palette; AppShell/Header receive an opening callback.

- [x] Test mouse/keyboard header entry, search navigation and Escape focus return. Extend the actual Assistant modal integration to prevent competing palette opening through the new button.
- [x] Run affected tests and observe missing entry/behavior failures.
- [x] Add a labeled Search control and shortcut hint, using the current modal-ownership guard for both entry paths. Retain compact header behavior at narrow widths.
- [x] Run affected tests and the full suite; expect all passing.

### Task 3: Saved dependency summary

Files: new `dependencySummary.ts` and `DependencyHomeSummary.tsx` under project-home, `ProjectHome.tsx`, and tests.
Interfaces: loader consumes a completed dependency CanonicalRun; validates its ID and target, then returns its ID, total/critical/high counts, packages and advisory coverage. Component consumes the selected project's last completed run, refresh revision and loading state.

- [x] Test exact run/target identity and bounded metadata/page queries; severity counts beyond the first page; zero/unknown coverage; missing/corrupt metadata; one failed severity query; no completed receipt; late A→B→A responses; refresh/retry recovery.
- [x] Run tests and observe missing summary behavior failures.
- [x] Load selected-project metadata and severity counts only, retaining the newest attempt state separately. Display saved counts/coverage, loading and retry states. Failures preserve usable project controls and unknown counts.
- [x] Run affected tests and the full suite; expect all passing.

### Final verification

- [x] Run full tests, build, lint and diff checks.
- [x] Obtain an independent whole-diff review; address material findings using failing-then-passing regressions.
- [x] Record exact verification and remaining visual-testing limits.

## Completion evidence

- 906 tests passed: 178 node tests and 728 Vitest tests in 71 files.
- Production build, ESLint and diff checks passed. The existing non-module `/env.js` build warning remains.
- Independent review found one Important completion-order mismatch; regression tests observed RED→GREEN and the shared selection policy now aligns Home with dependency results. No Critical or Minor findings were reported.
- Additional verification found and fixed initial palette focus delayed until an animation frame, plus deferred Assistant focus restoration stealing a later action. Both have controlled-frame RED→GREEN regressions. Temporary diagnostics were removed.
- Commit `de663589c268704b20c332d007492069a097b9f4` was fast-forwarded to main and pushed to origin with the existing author identity and no attribution trailers. Planning/audit files were excluded.
- Live layout, native interaction, VoiceOver and user observations remain unverified because browser/native access was unavailable or denied.
