# oxAudit Source Scan and Results Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace transient Source Scan results with a durable target, run-history, result-view, and evidence-backed review workflow backed by the completed Rust foundation.

**Architecture:** SourceScanPage remains the route-level coordinator but delegates target selection, results, detail, review, history, and policy status to focused feature components. Typed Tauri DTOs are normalized by pure TypeScript helpers; view membership and review validation are deterministic state functions tested with the existing node:test harness. The backend remains authoritative for projects, runs, findings, reviews, policy, and persistence.

**Tech Stack:** React 19, TypeScript 5.8, Zustand 5, Tailwind CSS 4, Lucide React, Tauri JavaScript API 2, existing node:test + tsx test harness.

**Spec:** docs/superpowers/specs/2026-08-20-oxaudit-durable-findings-settings-design.md

**Depends on:** docs/superpowers/plans/2026-08-20-oxaudit-durable-scan-foundation.md

**Native API reference:** Tauri webview drag/drop events and cleanup: https://v2.tauri.app/reference/javascript/api/namespacewebview/#ondragdropevent

## Global Constraints

- The Rust findings service is the source of truth. Do not put scan history or reviews in Zustand or localStorage.
- Keep every candidate accessible through Open, Other scopes, Closed, or Resolved.
- Confirmed findings appear in Open regardless of scope.
- Test, fixture, generated, vendored, and documentation candidates remain visible in Other scopes.
- A resolved row is shown only when the backend returns diffStatus resolved; the frontend never infers resolution.
- Raw detected secrets must never be rendered, copied, logged, sent to Assistant, placed in accessible labels, or included in exports.
- AI may draft review evidence but cannot submit a review or write project policy.
- The last completed run remains visible while a new scan runs, fails, or is cancelled.
- NotSaved results remain visible and expose an explicit Retry save action.
- Invalid project policy is visible and preserved; scanning without it requires an explicit action.
- Existing Dependency Scan, Binary Scan, CVE Research, Assistant, Settings, and shell behavior remain unchanged.
- Preserve the current workbench tokens, two-step radius system, focus treatment, and responsive SplitWorkspace behavior.
- The existing untracked artifacts/ directory must not be staged.
- Before every commit, inspect git status and the staged diff, then stage only paths named by the current task. Do not absorb unrelated user changes through directory-wide staging.

## File Structure

### New Source Scan feature files

- src/features/source-scan/types.ts — frontend-only view and controller types.
- src/features/source-scan/resultsModel.ts — result membership, counts, filters, and selection.
- src/features/source-scan/reviewModel.ts — review draft reducer, validation, and request construction.
- src/features/source-scan/projectLoader.ts — latest-request-safe project and run loading.
- src/features/source-scan/useProjectDrop.ts — native drag/drop listener with cleanup.
- src/features/source-scan/SourceTargetPanel.tsx — recent targets, picker, options, policy state, and primary action.
- src/features/source-scan/RunHistory.tsx — completed/incomplete run list and selection.
- src/features/source-scan/ResultViewTabs.tsx — Open, Other scopes, Closed, and Resolved navigation.
- src/features/source-scan/FindingList.tsx — accessible result rows and badges.
- src/features/source-scan/FindingReviewForm.tsx — vulnerability gates and secret disposition form.
- src/features/source-scan/PolicyStatus.tsx — valid, missing, and invalid repository policy state.

### Existing files modified

- src/lib/types.ts — durable Rust DTO mirror.
- src/lib/api.ts — project, run, retry, and review commands.
- src/lib/sourceScanOptions.ts — invalid-policy override in the submitted request.
- src/lib/stores.ts — no new durable state; keep recentScans only for legacy Dashboard/Dependency compatibility.
- src/pages/SourceScan.tsx — route coordinator and durable state loading.
- src/components/FindingDetail.tsx — scope, diff, review, history, sanitized Assistant handoff, and review form.
- src/index.css — only feature-specific responsive utilities that cannot be expressed with existing tokens.

### New tests

- tests/commandError.test.ts
- tests/sourceResults.test.ts
- tests/sourceReview.test.ts
- tests/sourceProjectLoader.test.ts
- tests/sourceDrop.test.ts

---

### Task 1: Mirror the durable Rust contract in TypeScript

**Files:**
- Modify: src/lib/types.ts:3-70
- Modify: src/lib/api.ts:1-40
- Create: src/lib/commandError.ts
- Create: tests/commandError.test.ts

**Interfaces:**
- Consumes: Rust camelCase DTOs from the durable foundation.
- Produces: FindingScope, ReviewState, DiffStatus, RunStatus, ReviewOrigin, PolicyStatus, RunPersistence, ScanRunDetail, ScanRunSummary, ProjectContext, RecentProject, ReviewRequest, CommandError, and normalizeCommandError.

- [ ] **Step 1: Write typed-error normalization tests**

~~~ts
test("a native typed error keeps its code and safe message", () => {
  assert.deepEqual(
    normalizeCommandError({
      code: "policyInvalid",
      message: "Project policy is invalid",
      detail: "entries[0].reason is required",
      retryable: false,
    }),
    {
      code: "policyInvalid",
      message: "Project policy is invalid",
      detail: "entries[0].reason is required",
      retryable: false,
    },
  );
});

test("an unknown rejection becomes a safe scan failure", () => {
  assert.deepEqual(normalizeCommandError("bridge unavailable"), {
    code: "scanFailed",
    message: "bridge unavailable",
    detail: null,
    retryable: true,
  });
});
~~~

- [ ] **Step 2: Run the test and verify the module is missing**

~~~bash
npx tsx --test tests/commandError.test.ts
~~~

Expected: FAIL because src/lib/commandError.ts does not exist.

- [ ] **Step 3: Define the exact frontend domain**

Add:

~~~ts
export type FindingScope =
  | "production"
  | "infrastructure"
  | "test"
  | "fixture"
  | "generated"
  | "vendored"
  | "documentation"
  | "unknown";

export type ReviewState =
  | "candidate"
  | "confirmed"
  | "falsePositive"
  | "acceptedRisk"
  | "suppressed";

export type DiffStatus = "new" | "unchanged" | "resolved" | "notEvaluated";
export type RunStatus = "running" | "completed" | "incomplete";
export type ReviewOrigin = "local" | "projectPolicy";
export type Gate =
  | "intended"
  | "reachable"
  | "attackerControlled"
  | "sanitized"
  | "newCapability";
export type GateVerdict = "survives" | "eliminates" | "unknown";

export interface GateNote {
  gate: Gate;
  verdict: GateVerdict;
  evidence: string;
}

export type PolicyStatus =
  | { status: "missing" }
  | { status: "valid"; hash: string }
  | { status: "invalid"; message: string };

export type RunPersistence =
  | { status: "saved" }
  | { status: "notSaved"; retryToken: string };

export type ErrorCode =
  | "invalidTarget"
  | "scanCancelled"
  | "scanFailed"
  | "scanAlreadyRunning"
  | "persistenceUnavailable"
  | "policyInvalid"
  | "policyWriteFailed"
  | "reviewInvalid"
  | "notFound"
  | "credentialUnavailable"
  | "credentialRollbackFailed"
  | "migrationFailed"
  | "dataOperationFailed";

export interface CommandError {
  code: ErrorCode;
  message: string;
  detail: string | null;
  retryable: boolean;
}
~~~

Extend Finding with required observationRunId, resolvedByRunId, fingerprintVersion, fingerprint, scope, scopeReason, review, reviewHistory, and diffStatus. Define the project, run, and review interfaces with the exact field names from the foundation plan. ReviewRecord includes id, entryPoint, dataFlow, policyHash, updatedAt, and supersededAt.

- [ ] **Step 4: Extend the scan request and API**

ScanOptions gains ignoreInvalidPolicy: boolean. Add:

~~~ts
inspectSourceProject: (path: string) =>
  invoke<ProjectContext>("inspect_source_project", { path }),
listSourceProjects: (limit = 12) =>
  invoke<RecentProject[]>("list_source_projects", { limit }),
listSourceRuns: (projectId: string, limit = 50) =>
  invoke<ScanRunSummary[]>("list_source_runs", { projectId, limit }),
loadSourceRun: (runId: string) =>
  invoke<ScanRunDetail>("load_source_run", { runId }),
retrySourceRunSave: (retryToken: string) =>
  invoke<ScanRunDetail>("retry_source_run_save", { retryToken }),
saveFindingReview: (request: ReviewRequest) =>
  invoke<ReviewRecord>("save_finding_review", { request }),
~~~

Change scanProject to return ScanRunDetail.

- [ ] **Step 5: Implement safe error normalization**

normalizeCommandError accepts unknown, validates code/message/retryable without stringifying object payloads as [object Object], and never copies unknown object properties into detail.

- [ ] **Step 6: Verify and commit the contract**

~~~bash
npx tsx --test tests/commandError.test.ts
npm run check
git add src/lib/types.ts src/lib/api.ts src/lib/commandError.ts tests/commandError.test.ts
git commit -m "feat(scan): add durable frontend contract"
~~~

---

### Task 2: Build deterministic result views and filters

**Files:**
- Create: src/features/source-scan/types.ts
- Create: src/features/source-scan/resultsModel.ts
- Create: tests/sourceResults.test.ts

**Interfaces:**
- Consumes: Finding[] and ResultsQuery.
- Produces: ResultView, findingView, countViews, filterFindings, nextSelection, and sanitizeExport.

- [ ] **Step 1: Write view-membership tests**

~~~ts
test("every candidate belongs to exactly one durable view", () => {
  const findings = [
    finding({ fingerprint: "prod", scope: "production", review: null }),
    finding({ fingerprint: "fixture", scope: "fixture", review: null }),
    finding({ fingerprint: "confirmed", scope: "test", review: review("confirmed") }),
    finding({ fingerprint: "closed", scope: "production", review: review("acceptedRisk") }),
    finding({ fingerprint: "resolved", diffStatus: "resolved", review: null }),
  ];
  assert.deepEqual(findings.map(findingView), [
    "open",
    "otherScopes",
    "open",
    "closed",
    "resolved",
  ]);
  assert.equal(Object.values(countViews(findings)).reduce((sum, count) => sum + count, 0), 5);
});
~~~

Also test Unknown in Open, false positive and suppressed in Closed, category/severity/scope/search filters, stable selection after filtering, and no mutation of the input array.

- [ ] **Step 2: Run the test and observe the missing module**

~~~bash
npx tsx --test tests/sourceResults.test.ts
~~~

Expected: FAIL because resultsModel.ts is absent.

- [ ] **Step 3: Define the view query**

~~~ts
export type ResultView = "open" | "otherScopes" | "closed" | "resolved";

export interface ResultsQuery {
  view: ResultView;
  category: "all" | "secret" | "vulnerability";
  severity: "all" | Severity;
  scope: "all" | FindingScope;
  language: "all" | string;
  search: string;
}
~~~

- [ ] **Step 4: Implement membership before filtering**

~~~ts
export function findingView(finding: Finding): ResultView {
  if (finding.diffStatus === "resolved") return "resolved";
  const state = finding.review?.state ?? "candidate";
  if (state === "confirmed") return "open";
  if (state === "falsePositive" || state === "acceptedRisk" || state === "suppressed") {
    return "closed";
  }
  return finding.scope === "production" ||
    finding.scope === "infrastructure" ||
    finding.scope === "unknown"
    ? "open"
    : "otherScopes";
}
~~~

filterFindings first applies findingView, then category, severity, scope, language, and case-insensitive text over ruleName, ruleId, filePath, title, and safe matchText.

- [ ] **Step 5: Sanitize exports defensively**

sanitizeExport maps findings to explicit allowlisted fields and replaces matchText/context with "[REDACTED]" for category secret even if a malformed backend response contains other text. It never spreads a Finding object.

- [ ] **Step 6: Verify and commit the results model**

~~~bash
npx tsx --test tests/sourceResults.test.ts
npm run check
git add src/features/source-scan/types.ts src/features/source-scan/resultsModel.ts tests/sourceResults.test.ts
git commit -m "feat(scan): model durable result views"
~~~

---

### Task 3: Load projects and runs without stale path races

**Files:**
- Create: src/features/source-scan/projectLoader.ts
- Create: tests/sourceProjectLoader.test.ts
- Modify: src/lib/sourceScanOptions.ts:3-95
- Modify: tests/sourceScanOptions.test.ts

**Interfaces:**
- Consumes: inspectSourceProject, loadSourceRun, listSourceRuns, and existing LatestRequestQueue.
- Produces: SourceProjectLoader.load(path), refreshRuns(projectId), invalidate(), and SourceProjectLoad.

- [ ] **Step 1: Write delayed-response race tests**

Use deferred promises to start /project-a, then /project-b. Resolve B first and A last. Assert only B publishes context, run, and options. Add cases for no prior run, invalid policy, failed run load, and unmount invalidation.

- [ ] **Step 2: Run the test and observe the failure**

~~~bash
npx tsx --test tests/sourceProjectLoader.test.ts
~~~

Expected: FAIL because SourceProjectLoader is undefined.

- [ ] **Step 3: Define one atomic load result**

~~~ts
export interface SourceProjectLoad {
  context: ProjectContext;
  run: ScanRunDetail | null;
  runs: ScanRunSummary[];
}
~~~

SourceProjectLoader.load canonicalizes only through inspectSourceProject, then concurrently loads the last run and run summaries. It publishes only if its LatestRequestQueue token remains current.

- [ ] **Step 4: Restore last successful options without overwriting edits**

Add hydrateSourceScanOptionsFromProject(state, context.lastOptions). It follows the existing edited-field rule: untouched controls hydrate, user-edited controls stay unchanged. buildSourceScanRequest receives an optional ignoreInvalidPolicy argument and always emits the boolean.

- [ ] **Step 5: Verify loader and options**

~~~bash
npx tsx --test tests/sourceProjectLoader.test.ts tests/sourceScanOptions.test.ts
npm run check
~~~

Expected: all focused tests pass.

- [ ] **Step 6: Commit the project loader**

~~~bash
git add src/features/source-scan/projectLoader.ts src/lib/sourceScanOptions.ts tests/sourceProjectLoader.test.ts tests/sourceScanOptions.test.ts
git commit -m "feat(scan): load durable project context"
~~~

---

### Task 4: Add native project-folder drag and drop

**Files:**
- Create: src/features/source-scan/useProjectDrop.ts
- Create: tests/sourceDrop.test.ts

**Interfaces:**
- Consumes: getCurrentWebview().onDragDropEvent.
- Produces: chooseDroppedPath(event), useProjectDrop(onPath, onError), and visible over/drop state.

- [ ] **Step 1: Write pure drop-selection tests**

~~~ts
test("a dropped path list selects exactly the first path", () => {
  assert.equal(
    chooseDroppedPath({ type: "drop", paths: ["/projects/a", "/projects/b"], position: { x: 1, y: 2 } }),
    "/projects/a",
  );
});

test("hover and leave events never select a path", () => {
  assert.equal(chooseDroppedPath({ type: "over", position: { x: 1, y: 2 } }), null);
  assert.equal(chooseDroppedPath({ type: "leave" }), null);
});
~~~

- [ ] **Step 2: Run the test and observe the missing module**

~~~bash
npx tsx --test tests/sourceDrop.test.ts
~~~

Expected: FAIL because useProjectDrop.ts is absent.

- [ ] **Step 3: Implement the listener with required cleanup**

~~~ts
import { getCurrentWebview, type DragDropEvent } from "@tauri-apps/api/webview";

export function chooseDroppedPath(event: DragDropEvent): string | null {
  return event.type === "drop" ? event.paths[0] ?? null : null;
}
~~~

The hook registers once, sets hovering true on over, false on leave/drop, sends the chosen path to onPath, and calls the returned unlisten during cleanup. A rejected listener calls onError once and leaves folder browsing usable.

- [ ] **Step 4: Verify and commit drag/drop**

~~~bash
npx tsx --test tests/sourceDrop.test.ts
npm run check
git add src/features/source-scan/useProjectDrop.ts tests/sourceDrop.test.ts
git commit -m "feat(scan): accept dropped project folders"
~~~

---

### Task 5: Build the review draft state machine

**Files:**
- Create: src/features/source-scan/reviewModel.ts
- Create: tests/sourceReview.test.ts

**Interfaces:**
- Consumes: Finding and user edits.
- Produces: ReviewDraft, createReviewDraft, updateGate, validateReviewDraft, and buildReviewRequest.

- [ ] **Step 1: Write the complete validation matrix**

Test all five vulnerability gates, a non-empty reason for every non-Candidate decision, Confirmed requiring every gate to Survive with evidence, one deciding eliminating gate for FalsePositive, expiry parsing, local/project policy origin, Confirmed project-policy rejection, and AcceptedRisk/Suppressed reason requirements.

Include this safety assertion:

~~~ts
const request = buildReviewRequest("project-1", secretFinding, {
  ...createReviewDraft(secretFinding),
  state: "falsePositive",
  reason: "Synthetic test token",
});
assert.equal(JSON.stringify(request).includes("oxaudit-secret-canary"), false);
~~~

- [ ] **Step 2: Run the tests and observe the missing state machine**

~~~bash
npx tsx --test tests/sourceReview.test.ts
~~~

Expected: FAIL because reviewModel.ts is absent.

- [ ] **Step 3: Define the draft**

~~~ts
export interface ReviewDraft {
  state: ReviewState;
  reason: string;
  evidence: string;
  entryPoint: string;
  dataFlow: string;
  gates: GateNote[];
  decidingGate: Gate | null;
  expiresAt: string;
  origin: ReviewOrigin;
}

export interface ReviewValidation {
  valid: boolean;
  fieldErrors: Partial<Record<"reason" | "evidence" | "gates" | "decidingGate" | "expiresAt" | "origin", string>>;
}
~~~

- [ ] **Step 4: Construct allowlisted requests**

buildReviewRequest(projectId, finding, draft) copies only the supplied project ID, fingerprint identity, category, selected state, trimmed reason/evidence/entryPoint/dataFlow fields, validated gates, deciding gate, ISO expiry, and origin. It never includes matchText, context, title, description, recommendation, entropy, or file content.

- [ ] **Step 5: Verify and commit review logic**

~~~bash
npx tsx --test tests/sourceReview.test.ts
npm run check
git add src/features/source-scan/reviewModel.ts tests/sourceReview.test.ts
git commit -m "feat(scan): validate finding review drafts"
~~~

---

### Task 6: Build target, policy, and run-history components

**Files:**
- Create: src/features/source-scan/SourceTargetPanel.tsx
- Create: src/features/source-scan/PolicyStatus.tsx
- Create: src/features/source-scan/RunHistory.tsx
- Modify: src/pages/SourceScan.tsx:316-473

**Interfaces:**
- Consumes: RecentProject[], ProjectContext, ScanRunSummary[], SourceScanOptionsState, progress, and route-level callbacks.
- Produces: accessible target selection, policy status, prior-run selection, and Run scan/Cancel/Retry actions.

- [ ] **Step 1: Create the exact component signatures**

~~~tsx
export function SourceTargetPanel(props: {
  path: string;
  recentProjects: RecentProject[];
  project: ProjectContext | null;
  options: SourceScanOptionsState;
  running: boolean;
  cancelling: boolean;
  dropping: boolean;
  progress: ScanProgress | null;
  onPathChange(path: string): void;
  onOptionChange<K extends SourceScanOptionKey>(key: K, value: SourceScanOptionValues[K]): void;
  onRun(ignoreInvalidPolicy: boolean): void;
  onCancel(): void;
}): JSX.Element;

export function PolicyStatusView(props: {
  policy: PolicyStatus;
  running: boolean;
  onRunWithoutPolicy(): void;
}): JSX.Element;

export function RunHistory(props: {
  runs: ScanRunSummary[];
  selectedRunId: string | null;
  loadingRunId: string | null;
  onSelect(runId: string): void;
}): JSX.Element;
~~~

- [ ] **Step 2: Render recent projects as real target buttons**

Each row shows displayName, canonicalPath, last completed time, open count, critical/high count, and aria-current when selected. An empty state says No previous source scans and keeps Browse plus drag/drop available.

- [ ] **Step 3: Make policy status truthful**

Missing is neutral. Valid shows Project policy active and a shortened non-secret hash. Invalid is an alert containing the backend validation message and an explicit Scan without project policy button; the ordinary Run scan button remains disabled until the user chooses that action or fixes/reloads the file.

- [ ] **Step 4: Render run history without implying incomplete baselines**

Completed rows show timestamp, total, new, and resolved counts. Incomplete rows say Incomplete and never show resolved count. Selecting a run calls loadSourceRun; keyboard focus stays on the selected history button.

- [ ] **Step 5: Integrate the target area**

Replace the path/options JSX in SourceScan.tsx with SourceTargetPanel and place RunHistory beside or below it using existing responsive workbench layout. Keep previous completed results mounted while running.

- [ ] **Step 6: Verify and commit target/history UI**

~~~bash
npm run check
npm run build
git add src/features/source-scan/SourceTargetPanel.tsx src/features/source-scan/PolicyStatus.tsx src/features/source-scan/RunHistory.tsx src/pages/SourceScan.tsx
git commit -m "feat(scan): add durable targets and run history"
~~~

---

### Task 7: Build result views and accessible finding rows

**Files:**
- Create: src/features/source-scan/ResultViewTabs.tsx
- Create: src/features/source-scan/FindingList.tsx
- Modify: src/pages/SourceScan.tsx:475-648

**Interfaces:**
- Consumes: ViewCounts, ResultsQuery, filtered Finding[], selected fingerprint.
- Produces: result-view navigation and accessible list selection.

- [ ] **Step 1: Create the view-tab contract**

~~~tsx
export function ResultViewTabs(props: {
  value: ResultView;
  counts: Record<ResultView, number>;
  onChange(view: ResultView): void;
}): JSX.Element;
~~~

Render a tablist with four buttons, role tab, aria-selected, aria-controls, text labels, and numeric counts.

- [ ] **Step 2: Create stable fingerprint-based rows**

~~~tsx
export function FindingList(props: {
  findings: Finding[];
  selectedFingerprint: string | null;
  onSelect(fingerprint: string): void;
}): JSX.Element;
~~~

Use fingerprint, not random observation ID, for key and selection. Each row shows severity text, review state text, scope text, diff text, rule name, and file:line. Secret match text renders the backend redacted preview only.

- [ ] **Step 3: Replace category tabs with durable views**

SourceScan.tsx computes counts from the complete run, filters through filterFindings, and renders ResultViewTabs before category/severity/scope/language/search controls. Empty-state copy names the current durable view.

- [ ] **Step 4: Keep selection valid across filters and run changes**

Use nextSelection(filtered, selectedFingerprint). When a run changes, preserve the fingerprint selection only if that fingerprint exists in the newly loaded run; otherwise choose the first visible result.

- [ ] **Step 5: Verify and commit result navigation**

~~~bash
npx tsx --test tests/sourceResults.test.ts
npm run check
npm run build
git add src/features/source-scan/ResultViewTabs.tsx src/features/source-scan/FindingList.tsx src/pages/SourceScan.tsx
git commit -m "feat(scan): add durable result views"
~~~

---

### Task 8: Add evidence-backed review to finding detail

**Files:**
- Create: src/features/source-scan/FindingReviewForm.tsx
- Modify: src/components/FindingDetail.tsx:8-144
- Modify: src/pages/SourceScan.tsx

**Interfaces:**
- Consumes: Finding, ReviewDraft, saveFindingReview, and refreshed ScanRunDetail.
- Produces: review form, review history summary, saved review refresh, and safe Assistant draft.

- [ ] **Step 1: Create the review form signature**

~~~tsx
export function FindingReviewForm(props: {
  projectId: string;
  finding: Finding;
  saving: boolean;
  error: CommandError | null;
  onSubmit(request: ReviewRequest): Promise<void>;
  onCancel(): void;
}): JSX.Element;
~~~

- [ ] **Step 2: Render category-specific evidence**

For vulnerability findings, render reason, entry point, and data flow fields followed by all five gate questions in fixed order with Survives, Eliminates, and Unknown radios plus evidence text. False positive requires the deciding eliminating gate. Confirmed disables submit until every gate is Survives with non-empty evidence.

For secret findings, render state, reason, optional expiry, and origin only. Do not render a reveal action, live-validation action, original-value field, or full context.

- [ ] **Step 3: Render review and diff metadata in detail**

FindingDetail receives projectId from the loaded ScanRunDetail and shows scope plus rationale, diff status, observed run, resolution-boundary run when applicable, current review state/origin/reason/expiry, entry point/data flow, append-only review history, and location. Resolved findings are read-only projections of the baseline observation; the user can navigate to a current observation with the same fingerprint when one exists.

- [ ] **Step 4: Keep AI as an editable draft source**

Discuss in Assistant constructs an allowlisted payload. For secrets it includes rule, severity, redacted location, scope, and recommendation; it omits matchText and context entirely. For vulnerabilities it may include sanitized match/context. Returning AI text populates evidence only after an explicit user copy; it never calls saveFindingReview.

- [ ] **Step 5: Refresh from backend after save**

After saveFindingReview succeeds, reload the selected run and replace the complete run snapshot. Do not mutate a single frontend Finding as if it were authoritative. Keep fingerprint selection and announce Review saved with aria-live.

- [ ] **Step 6: Verify and commit finding review**

~~~bash
npx tsx --test tests/sourceReview.test.ts tests/sourceResults.test.ts
npm run check
npm run build
git add src/features/source-scan/FindingReviewForm.tsx src/components/FindingDetail.tsx src/pages/SourceScan.tsx
git commit -m "feat(scan): add evidence-backed finding review"
~~~

---

### Task 9: Finish durable scan orchestration and failure recovery

**Files:**
- Modify: src/pages/SourceScan.tsx:31-315
- Modify: src/lib/stores.ts:6-71
- Modify: src/features/source-scan/projectLoader.ts

**Interfaces:**
- Consumes: all Source feature components and durable API commands.
- Produces: complete SourceScanPage state transitions for target load, run, cancel, retry save, run selection, and review refresh.

- [ ] **Step 1: Replace transient result state with a run snapshot**

Use:

~~~ts
const [project, setProject] = useState<ProjectContext | null>(null);
const [recentProjects, setRecentProjects] = useState<RecentProject[]>([]);
const [runs, setRuns] = useState<ScanRunSummary[]>([]);
const [run, setRun] = useState<ScanRunDetail | null>(null);
const [loadingRunId, setLoadingRunId] = useState<string | null>(null);
const [operationError, setOperationError] = useState<CommandError | null>(null);
~~~

The currently loaded completed run is not cleared at scan start.

- [ ] **Step 2: Load durable recent projects on mount**

Call listSourceProjects(12). Failure produces a compact Recent projects unavailable state without disabling Browse or scanning. Selecting/browsing/dropping a target goes through SourceProjectLoader and resolveRuntimeProject.

- [ ] **Step 3: Handle every scan terminal state**

On success, replace run with the returned snapshot, refresh project/runs/recent projects, and set truthful page status.

On scanCancelled, retain run and show the cancelled attempt.

On policyInvalid, retain run and show PolicyStatusView.

On any other typed error, retain run, show message/detail plus retry when retryable, and never label it complete.

- [ ] **Step 4: Implement Retry save**

When run.persistence.status is notSaved, show a warning banner and Retry save. Call retrySourceRunSave once per click, disable while pending, replace the full snapshot on success, and keep the banner on failure.

- [ ] **Step 5: Keep the legacy Dashboard cache non-authoritative**

After a saved completed run only, continue addRecentScan for Dashboard compatibility. Use run ID as cache ID. Source target selection and result loading never read recentScans. Add a comment naming its removal/migration in the identity plan; do not add new Source fields to localStorage.

- [ ] **Step 6: Verify and commit orchestration**

~~~bash
npm test
npm run check
npm run build
git add src/pages/SourceScan.tsx src/features/source-scan/projectLoader.ts src/lib/stores.ts
git commit -m "feat(scan): finish durable source workflow"
~~~

---

### Task 10: Verify native workflow, keyboard behavior, and secret safety

**Files:**
- Create: docs/superpowers/qa/2026-08-20-oxaudit-source-results-workflow.md
- Modify: docs/superpowers/plans/2026-08-20-oxaudit-source-results-workflow.md (checkboxes only during execution)

**Interfaces:**
- Consumes: completed Source workflow.
- Produces: reproducible automated and native acceptance evidence.

- [ ] **Step 1: Run all frontend and Rust checks**

~~~bash
npm test
npm run check
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets
~~~

Expected: all commands exit 0; no new warning originates in Source workflow or findings foundation files.

- [ ] **Step 2: Run the packaged native application**

~~~bash
npm run tauri build -- --debug
~~~

Launch the generated debug app, not only the Vite browser preview.

- [ ] **Step 3: Execute the durable run scenario**

Use a disposable fixture project containing one vulnerability, one test fixture secret, one generated-file candidate, and one ordinary clean file. Run scan, record run ID and counts, quit the app, relaunch, select the project, and verify the same run and counts load.

Insert lines above the vulnerability, remove the generated candidate, add a new production candidate, and rescan. Verify unchanged, resolved, and new labels. Disable the scanner family that found the prior secret and verify it is not called resolved.

- [ ] **Step 4: Execute the review and policy scenario**

Confirm the vulnerability by answering all five gates. Mark the fixture secret false positive locally. Add an accepted-risk policy decision with expiry. Quit and relaunch; verify local and project-policy origins, reasons, and expiry remain visible.

Corrupt .oxaudit/policy.json deliberately in the disposable fixture. Verify the error is visible, the file remains byte-identical, normal Run scan is blocked, and Scan without project policy works.

- [ ] **Step 5: Inspect every secret output path**

Copy one finding, copy the JSON report, open Assistant handoff, inspect toast/error text, and query the disposable database through the foundation canary test. The raw canary must be absent from every output.

- [ ] **Step 6: Verify keyboard and narrow desktop behavior**

At 1440x900, 1180x760, and 900x700, use only keyboard controls to select target, start/cancel scan, switch all four result tabs, filter, move through findings, open detail, complete a review, return to list, and select history. Confirm visible focus and text labels for severity, scope, review, and diff.

- [ ] **Step 7: Record and commit QA evidence**

Record app build path, fixture layout, run IDs, counts, restart results, policy byte-preservation check, canary result, viewport results, and commands with exit codes. Do not record private source excerpts.

~~~bash
git add docs/superpowers/qa/2026-08-20-oxaudit-source-results-workflow.md
git commit -m "docs: verify durable source workflow"
~~~

## Workflow Completion Gate

Do not begin the Settings/identity plan until:

- target history and the selected completed run survive process restart;
- every candidate appears in exactly one durable result view;
- review changes reload from the backend and survive restart;
- invalid policy requires an explicit scan-without-policy action;
- a NotSaved result can be retried idempotently;
- secret values are absent from copy, export, Assistant, errors, accessibility text, and SQLite;
- the packaged native workflow passes at all three desktop sizes.
