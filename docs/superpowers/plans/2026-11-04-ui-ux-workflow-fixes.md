# UI/UX workflow fixes implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. Steps use checkbox syntax for tracking.

**Goal:** Fix the five reproduced interaction and recovery issues from the accepted source review.

**Architecture:** Extend the existing React components and Zustand session state. Preserve explicit review saves, run identity, unknown counts and the existing visual system. Apply the existing onboarding modal's isolation pattern to command navigation.

**Tech Stack:** React 19, TypeScript, Zustand, Vitest, Testing Library, Tailwind.

**Spec:** `output/ui-ux-review-2026-11-04/review.json`, accepted in the conversation, findings UX-01 through UX-05.

## Global constraints

- No new dependencies or backend changes.
- Drafts live only in memory and are keyed by project, fingerprint version and fingerprint. A different saved review invalidates a stale draft; explicit save/discard clears the appropriate draft.
- Do not autosave a human review decision or expose secret material.
- Keep the existing workspace scroll owner and visual design.
- Live browser and desktop verification remain unavailable; do not claim them.
- Work on `codex/ui-ux-workflow-fixes` in the current checkout; leave changes uncommitted for review.

## Review focus

- Palette Tab/Shift+Tab, Escape from its close control, prior background inert state and restoration on close/unmount.
- Draft isolation across project/fingerprint/version and superseding saved reviews; failed and late saves must retain newer edits.
- Review entry focus, cancel focus return and draft discard after component remount.
- One project's failed history must preserve other projects and canonical dependency evidence; retry must recover honestly.
- Error/hint IDs must reach the correct control without dropping caller descriptions; corrected fields must lose invalid state.

### Task 1: Command palette keyboard operation

**Files:** `src/components/workbench/CommandPalette.tsx`, its component tests.
**Interfaces:** Consumes `open`/`onClose`; produces no new public API.

- [x] Add tests for Tab containment in both directions, Escape outside the search field, close focus restoration and background isolation.
- [x] Run `npx vitest run src/components/workbench/CommandPalette.test.tsx`; expect failures for the missing containment/close behavior.
- [x] Add modal isolation/focus trapping using the existing onboarding pattern, a visible close button and cleanup that restores prior state.
- [x] Run the targeted file and `npm test`; expect all passing.

### Task 2: Review entry and session drafts

**Files:** `src/components/FindingDetail.tsx`, `src/features/source-scan/FindingReviewForm.tsx`, new `reviewDrafts.ts`, associated component tests.
**Interfaces:** Session draft entries contain `ReviewDraft` and saved-review identity. Cache identity includes project ID, fingerprint version and fingerprint.

- [x] Add tests for opening/revealing the editor and returning focus on close; draft restoration on finding switch and page remount; project isolation; saved-review invalidation; save failure/newer edits; explicit discard.
- [x] Run affected tests; expect failures for focus and draft restoration.
- [x] Implement in-memory drafts, explicit discard, and focus/reveal on explicit editor entry. Preserve the existing durable-save callback and errors.
- [x] Run affected tests and `npm test`; expect all passing.

### Task 3: Partial project history recovery

**Files:** `src/features/project-home/history.ts`, `ProjectHome.tsx` and their tests.
**Interfaces:** Add optional per-project history error to `HomeProject`; preserve `loadProjectHome(): Promise<HomeProject[]>`.

- [x] Add tests showing one failed project still allows a healthy project and dependency evidence, with an affected-project warning that clears on retry.
- [x] Run home tests; expect aggregate rejection/absence of warning.
- [x] Settle per-project run requests independently, retain projects, distinguish unavailable history from no history, and render the affected-row warning.
- [x] Run home tests and `npm test`; expect all passing.

### Task 4: Accessible validation feedback

**Files:** `src/components/workbench/Field.tsx`, new `Field.test.tsx`, review form tests.
**Interfaces:** Preserve Field props; associate generated hints/errors with the child control matching `htmlFor`.

- [x] Add tests for expiry invalid state/error description and correction, deciding-gate association, and preserving caller descriptions.
- [x] Run affected tests; expect missing description/invalid state.
- [x] Wire hints/errors through Field without overwriting existing descriptions or unrelated children.
- [x] Run affected tests and `npm test`; expect all passing.

### Final verification and review

- [x] Run `npm test`, `npm run build`, and `npm run lint`; inspect every result.
- [x] Inspect the full diff and obtain an independent review under the execution skill's final-review instruction.
- [x] Address material findings with a failing regression test before the fix, then rerun checks as needed.
- [x] Report implemented behavior, verification, scope and outstanding native visual testing.

## Completion evidence

- All 887 tests passed: 178 node tests and 709 Vitest tests in 69 files.
- TypeScript and Vite production build passed; the pre-existing non-module `/env.js` bundling warning remains. ESLint and `git diff --check` passed.
- The independent reviewer found two Important issues, both addressed with RED-to-GREEN regressions: preventing competing modal focus traps, and preserving newer edits across unchanged/baseline-reverting save acknowledgements.
- Changes remain uncommitted on `codex/ui-ux-workflow-fixes`. The original source review is retained as evidence of the baseline, not as the current implementation status.
- UX-06 through UX-08 remain for a later batch: shorter history, visible command search, and saved dependency summaries.
- Browser, native WebView and VoiceOver checks remain outstanding because live access was unavailable/denied.
