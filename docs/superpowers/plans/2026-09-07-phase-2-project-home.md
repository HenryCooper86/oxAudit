# Project Home Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. Controller reviews, commits, and pushes this phase.

**Goal:** Reopen durable project work and run a source/dependency project check from home.
**Architecture:** A dashboard view model combines source project summaries and canonical run history. Persist only the selected project preference, not another findings database. A request-scoped project-check coordinator survives page navigation and drives existing APIs sequentially with cancellation and truthful per-family outcomes.
**Tech Stack:** React, Zustand, existing Tauri APIs, Vitest.
**Spec:** docs/superpowers/specs/2026-09-07-everyday-engineering.md

## Global Constraints
- No new scanner implementation; use inspectSourceProject, listSourceProjects, listCanonicalRuns, scanProject, findLockfiles and scanDependencies.
- No backend runtime-project authority from localStorage; validate a restored path through resolveRuntimeProject/inspectSourceProject before use.
- Do not mutate review or policy semantics. Partial project-check success stays partial.
- Only controller commits and pushes; no additional subagents.

### Task 1: Durable project home and project checks

Files: src/pages/Dashboard.tsx, focused src/features/project-home modules/components/tests, src/lib/stores.ts, src/pages/SourceScan.tsx, src/pages/DepsScan.tsx, src/components/workbench/StatusBar.tsx, README.md. Touch App.tsx only if necessary for an always-mounted coordinator. Use existing UI tokens/components.

Interfaces: project home reads durable source projects, canonical runs, and latest source run summaries. Restore selected path with validated storage parsing. Explicit handoff should carry path and optionally run ID; latest results may be used when the UI says Resume project. Project checks use saved source options/settings and use the canonical root returned by inspection.

- [x] Add behavior tests for durable home load, loading/error/empty states, failed/latest completed run distinction, source counts versus unknown dependency counts, source-only and dependency-only history, restored selection, switching projects and stale asynchronous replies.
- [x] Replace the dashboard launch-card-first surface with selected project summary, recent project buttons, last checked timestamp, source open/critical/high counts, new source findings where available, per-family latest run state, and a refresh action. Never label a zero finding count safe or treat failed scans as current clean evidence.
- [x] Keep tool launch actions available below the project workflow. A visible project folder chooser supports first use. Resume a project routes to its source/dependency results with correct canonical path; recent rows are buttons. Persist selected project separately from ephemeral assistant runtime context, handling unavailable paths visibly. Fix SourceScanPage initialization/subscription so palette and home project handoffs work even when already on Source Scan. Do not erase a user-entered pending path due to an asynchronous own-store update.
- [x] Implement Check project as source scan followed by lockfile discovery/dependency check. No supported lockfiles means dependency stage 'not applicable', never 'clean'. Source failure does not masquerade as successful project check. Check result offers links to source and dependency findings and keeps errors and last results. Respect saved scan settings and per-project options; require usable settings or show an actionable load error.
- [x] Running project checks survive leaving home; global status exposes target/stage and cancel. Avoid concurrent source/dependency scans conflicting with shared cancellation flags; check and scan buttons must honor active run ownership. Cancellation between stages stops the next stage. No duplicate launches on double click; stale completion cannot update a newer target. Do not auto-run merely when opening or restoring a project.
- [x] Add component tests driving project selection and check success/failure/cancellation with mocked IPC boundary; add coordinator tests covering stage ordering, no-lockfile state, failures and stale outcomes. Run npm run check and npm test. Update README with the workflow.

Acceptance: restart/restoration and palette/home navigation lead to the selected project, durable history is actionable, one explicit project check covers source and dependencies with truthful outcomes and cancellable work.

Implementation notes from inspection: SourceScanPage currently initializes path to an empty string and never subscribes to activeProject; its empty-path effect clears runtime selection. Canonical source runs currently store a display name as targetLabel (not a path), so map source history using listSourceProjects/listSourceRuns rather than treating the label as a directory. Canonical dependency runs store canonical paths. SourceProjectLoader already provides latest-wins project loading. resolveRuntimeProject already serializes runtime mutations. Reuse these protections.

Native baseline observation (existing installed app, not current changes): Dashboard says No recent activity while Source Scan lists durable prior targets, including oxAudit and two QA folders. This confirms the two home/history sources disagree. Use durable repository history as the home authority. SourceProjectLoader is src/features/source-scan/projectLoader.ts; it already has latest-wins load/refresh/invalidate.

Validation: npm type-check,121 Node tests,131 Vitest tests,production build and native debug bundle passed. Native checks covered Browse, explicit combined check, navigation, exact result links, restart without auto-run, global cancellation from Settings, and saved dependency restoration after restart. Scoped review fixes addressed late native selection, unsaved receipt reconciliation, and same-path history reload.
