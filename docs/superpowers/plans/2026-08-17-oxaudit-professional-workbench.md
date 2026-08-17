# oxAudit Professional Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the existing React/Tauri UI as the approved Professional Workbench while keeping Source Scan, Dependency Scan, CVE Research, and AI Assistant independently usable.

**Architecture:** Keep the existing Zustand page switch and Tauri API boundary. Introduce a fixed application shell plus small layout-only workbench components, then migrate one page at a time while each page continues to own its domain state and call the existing `api` layer. Cross-tool AI handoff is an explicit, inspectable draft payload rather than ambient global workflow state.

**Tech Stack:** React 19, TypeScript 5.8, Zustand 5, Tailwind CSS 4, Lucide React, Tauri 2, existing Rust backend commands.

## Global Constraints

- Preserve the product as a collection of independent tools; do not add a wizard, audit score, compliance flow, or mandatory global project.
- Source Scan and Dependency Scan are project-aware; CVE Research is standalone; AI Assistant defaults to standalone and accepts explicit optional context.
- Keep existing Tauri commands, backend protocols, settings persistence, scan engines, advisory sources, and AI streaming behavior.
- Use warm near-black surfaces and a restrained muted-gold accent. Semantic red, amber, green, and blue-neutral remain distinct from the accent.
- Working text is generally 13–14 px; metadata is 11–12 px when contrast remains sufficient.
- Use approximately 6 px control radii and 8–10 px panel radii; avoid nested rounded-card layouts.
- The desktop shell targets a 208 px sidebar, 52 px header, 28 px status bar, and 20–24 px content inset.
- Every visible primary control must be functional. Omit conceptual Search, Help, export, or health controls when no implementation exists.
- Every tool provides idle, running, success, empty, error, and unavailable states in context.
- Add visible `:focus-visible` treatment, semantic selected/current state, keyboard navigation, restrained live announcements, AA contrast, and reduced-motion handling.
- Verify at 1440×900, 1180×760, and 900×700. Below 900 px, use a labeled navigation drawer and stacked list/detail views.
- Do not add a test framework solely for this UI pass. Use the existing TypeScript/build checks plus focused browser and Tauri-native acceptance checks.
- Do not rename the Rust crate, bundle identifier, settings directory, or persisted keys during this UI pass. Visible product copy and window title become `oxAudit`.

## Repository Preconditions

- `/Users/cooph2o/oxAudit` currently has no `.git` directory. Do not initialize Git or rewrite repository history without user authorization.
- The commit commands below are required checkpoints once the correct repository root is restored or Git initialization is authorized. Until then, run each verification step and record the task as an uncommitted checkpoint.
- Preserve `.superpowers/brainstorm/` only as local visual reference material; add `.superpowers/` to `.gitignore` before the first real commit.

## File Structure

### New shared workbench files

- `src/lib/workbench.ts` — page metadata, page-status types, and assistant handoff type.
- `src/components/workbench/AppShell.tsx` — fixed sidebar/header/content/status layout and responsive drawer state.
- `src/components/workbench/WorkbenchHeader.tsx` — 52 px shell header and mobile navigation trigger.
- `src/components/workbench/StatusBar.tsx` — truthful current-page status, AI readiness, and app version.
- `src/components/workbench/ToolPage.tsx` — page identity, optional context, actions, and content inset.
- `src/components/workbench/TargetBar.tsx` — target/input slot plus secondary and primary actions.
- `src/components/workbench/ResultsToolbar.tsx` — count, filters, search, and supported actions.
- `src/components/workbench/SplitWorkspace.tsx` — accessible list/detail layout and narrow-window stacking.
- `src/components/workbench/InlineState.tsx` — compact idle, progress, empty, error, and unavailable state.
- `src/components/workbench/ToolLaunchCard.tsx` — equal Dashboard launcher card.
- `src/components/workbench/Field.tsx` — settings field label, hint, and error relationship.
- `src/components/workbench/Switch.tsx` — semantic shared switch.
- `src/components/FindingDetail.tsx` — selected source finding detail and explicit Assistant handoff.
- `src/components/CveDossier.tsx` — selected CVE detail, source attribution, and explicit Assistant handoff.

### Existing files modified throughout

- `src/index.css` — tokens, focus, reduced motion, scrollbars, markdown colors, and responsive shell helpers.
- `src/App.tsx` — wraps the current page switch in `AppShell`.
- `src/lib/stores.ts` — current-page status plus one-time Assistant handoff; existing recent scan/settings state remains.
- `src/components/Sidebar.tsx` — grouped navigation and responsive drawer behavior.
- `src/components/TopBar.tsx` — removed after all pages use `ToolPage`.
- `src/components/EmptyState.tsx`, `ProgressBar.tsx`, `SeverityBadge.tsx`, `Toasts.tsx` — aligned with shared states and accessibility.
- `src/components/FindingCard.tsx`, `StatCard.tsx` — removed after their consumers migrate.
- `src/components/chat/*.tsx` — visual tokens, dialog focus/labels, and readable density.
- `src/pages/Dashboard.tsx`, `SourceScan.tsx`, `DepsScan.tsx`, `CveResearch.tsx`, `Assistant.tsx`, `SettingsPage.tsx` — page migrations.
- `index.html`, `src-tauri/tauri.conf.json` — visible oxAudit title and supported minimum window size.
- `.gitignore` — excludes `.superpowers/` from future commits.

---

### Task 1: Establish the visual and accessibility foundation

**Files:**
- Modify: `src/index.css:1-165`
- Modify: `.gitignore:1-28`

**Interfaces:**
- Consumes: Tailwind CSS 4 `@theme` tokens already used by existing utility classes.
- Produces: `ink-*` warm-neutral tokens, `accent-*` muted-gold tokens, global focus behavior, and reduced-motion behavior used by every later task.

- [ ] **Step 1: Record the current verification baseline**

Run:

```bash
npm run check
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
```

Expected: all three commands exit 0. If one fails before UI edits, preserve its exact output as a baseline issue and do not attribute it to this redesign.

- [ ] **Step 2: Replace the blue-black/teal theme with the approved warm-neutral/gold tokens**

Update the `@theme` block in `src/index.css` to this semantic base:

```css
@theme {
  --font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

  --color-ink-950: #0f0f0f;
  --color-ink-900: #141414;
  --color-ink-850: #181818;
  --color-ink-800: #202020;
  --color-ink-750: #242424;
  --color-ink-700: #303030;
  --color-ink-600: #454545;

  --color-accent-300: #e2d58a;
  --color-accent-400: #d4c26e;
  --color-accent-500: #c8b560;
  --color-accent-600: #a99649;
}
```

Keep semantic Tailwind colors for error, warning, success, and informational content. Do not remap red/amber/emerald/sky to gold.

- [ ] **Step 3: Add the focus, selection, scrollbar, and reduced-motion contract**

Add this base behavior below the root styles and update the existing scrollbar/markdown colors to use the new neutral/accent tokens:

```css
:where(button, a, input, select, textarea, [tabindex]):focus-visible {
  outline: 2px solid var(--color-accent-400) !important;
  outline-offset: 2px;
}

::selection {
  background: color-mix(in srgb, var(--color-accent-500) 35%, transparent);
  color: #f4f1e9;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
    transition-duration: 0.01ms !important;
  }
}
```

Set body text to `#e8e6e1`, muted working text to at least `#aaa59e`, and essential borders to at least `#303030`. Preserve `.selectable` for code and research content.

- [ ] **Step 4: Exclude brainstorming artifacts from future commits**

Append exactly:

```gitignore

# Local design brainstorming artifacts
.superpowers/
```

- [ ] **Step 5: Verify the foundation**

Run:

```bash
npm run check
npm run build
```

Expected: both commands exit 0. Start the existing app and confirm keyboard focus is visible even on controls that still contain `outline-none`; the global rule must win until page migrations remove those utilities.

- [ ] **Step 6: Commit the foundation checkpoint when Git is available**

```bash
git add .gitignore src/index.css
git commit -m "style: establish professional workbench tokens"
```

---

### Task 2: Build the fixed application shell and grouped navigation

**Files:**
- Create: `src/lib/workbench.ts`
- Create: `src/components/workbench/AppShell.tsx`
- Create: `src/components/workbench/WorkbenchHeader.tsx`
- Create: `src/components/workbench/StatusBar.tsx`
- Modify: `src/lib/stores.ts:1-65`
- Modify: `src/components/Sidebar.tsx:1-66`
- Modify: `src/components/TopBar.tsx:1-13`
- Modify: `src/App.tsx:1-62`
- Modify: `index.html:6`
- Modify: `src-tauri/tauri.conf.json:3-20`

**Interfaces:**
- Consumes: existing `Page`, `aiReady`, recent scans, settings load, and current page switch.
- Produces: `PAGE_META`, `WorkbenchStatus`, `setPageStatus(page, status)`, `clearPageStatus(page)`, and the persistent shell all page tasks use.

- [ ] **Step 1: Define stable page metadata and status types**

Create `src/lib/workbench.ts`:

```ts
export type Page =
  | "dashboard"
  | "source-scan"
  | "deps-scan"
  | "cve-research"
  | "assistant"
  | "settings";

export interface PageMeta {
  title: string;
  group: "Overview" | "Scanning" | "Research" | "System";
}

export type StatusTone = "neutral" | "running" | "success" | "error";

export interface WorkbenchStatus {
  label: string;
  tone: StatusTone;
  detail?: string;
}

export const PAGE_META: Record<Page, PageMeta> = {
  dashboard: { title: "Dashboard", group: "Overview" },
  "source-scan": { title: "Source Scan", group: "Scanning" },
  "deps-scan": { title: "Dependencies", group: "Scanning" },
  "cve-research": { title: "CVE Research", group: "Research" },
  assistant: { title: "AI Assistant", group: "Research" },
  settings: { title: "Settings", group: "System" },
};
```

Move the `Page` type out of `stores.ts` and import it from this module everywhere that needs it.

- [ ] **Step 2: Add truthful current-page status to Zustand**

Extend `AppStore` and its initializer:

```ts
pageStatus: Partial<Record<Page, WorkbenchStatus>>;
setPageStatus: (page: Page, status: WorkbenchStatus) => void;
clearPageStatus: (page: Page) => void;
```

```ts
pageStatus: {},
setPageStatus: (page, status) =>
  set((state) => ({ pageStatus: { ...state.pageStatus, [page]: status } })),
clearPageStatus: (page) =>
  set((state) => {
    const pageStatus = { ...state.pageStatus };
    delete pageStatus[page];
    return { pageStatus };
  }),
```

Do not move per-page results or filters into the shared store.

- [ ] **Step 3: Create the shell components**

Implement these exact public signatures:

```tsx
export function AppShell({ children }: { children: React.ReactNode }): JSX.Element;
export function WorkbenchHeader({ onOpenNavigation }: { onOpenNavigation: () => void }): JSX.Element;
export function StatusBar(): JSX.Element;
```

`AppShell` owns `navigationOpen`, renders `<Sidebar open={navigationOpen} onClose={...} />`, and uses this structure:

```tsx
<div className="grid h-full grid-cols-[208px_minmax(0,1fr)] overflow-hidden bg-ink-950 max-[899px]:grid-cols-1">
  <Sidebar open={navigationOpen} onClose={() => setNavigationOpen(false)} />
  <section className="grid min-w-0 grid-rows-[52px_minmax(0,1fr)_28px] overflow-hidden">
    <WorkbenchHeader onOpenNavigation={() => setNavigationOpen(true)} />
    <main id="main-content" className="min-h-0 overflow-y-auto">{children}</main>
    <StatusBar />
  </section>
</div>
```

`WorkbenchHeader` derives `PAGE_META[page]`, renders `Group / Title`, and includes a labeled `Menu` button visible only below 900 px. Do not add Search or Help controls.

`StatusBar` renders the current page's `pageStatus[page]`, AI readiness, and `oxAudit v0.1.0`. Use text plus a semantic tone marker; do not claim NVD or OSV is connected without request state.

- [ ] **Step 4: Rebuild the Sidebar with explicit groups**

Change its signature to:

```tsx
export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }): JSX.Element;
```

Use `oxAudit` as the visible brand, three navigation groups—Overview, Scanning, Research—and keep Settings in the footer. Each button must set `aria-current={page === item.page ? "page" : undefined}`. Selecting a page closes the narrow-window drawer. Use Lucide icons already installed; icons remain supporting cues, never unlabeled controls.

- [ ] **Step 5: Wrap the current page switch and soften the legacy TopBar**

In `App.tsx`, replace the outer layout with:

```tsx
return (
  <AppShell>
    <Page />
    <Toasts />
  </AppShell>
);
```

Temporarily restyle `TopBar` as an unbordered in-content identity row so pages do not show two shell headers during staged migration. It is deleted in Task 8 after the last consumer is removed.

- [ ] **Step 6: Update visible product identity and supported window size**

Set the HTML title and Tauri visible names to:

```html
<title>oxAudit — Security Research Workbench</title>
```

```json
"productName": "oxAudit",
"title": "oxAudit — Security Research Workbench",
"minWidth": 900,
"minHeight": 700
```

Keep `identifier: "com.vulncompanion.app"`, Cargo package names, persisted keys, and backend user-agent strings unchanged.

- [ ] **Step 7: Verify the shell before migrating pages**

Run:

```bash
npm run check
npm run build
```

Expected: both exit 0. At 1440×900, verify the 208/52/28 px shell geometry. At the supported 900×700 native minimum, verify the labeled sidebar remains usable. In a browser-only 899×700 check, verify the menu button opens and closes the labeled navigation drawer, Escape closes it, and focus returns to the menu button.

- [ ] **Step 8: Commit the shell checkpoint when Git is available**

```bash
git add index.html src-tauri/tauri.conf.json src/App.tsx src/lib/workbench.ts src/lib/stores.ts src/components/Sidebar.tsx src/components/TopBar.tsx src/components/workbench/AppShell.tsx src/components/workbench/WorkbenchHeader.tsx src/components/workbench/StatusBar.tsx
git commit -m "feat: add professional workbench shell"
```

---

### Task 3: Rebuild Dashboard as an independent-tool launchpad

**Files:**
- Create: `src/components/workbench/ToolPage.tsx`
- Create: `src/components/workbench/ToolLaunchCard.tsx`
- Modify: `src/pages/Dashboard.tsx:1-144`
- Keep until its Source Scan and Dependency Scan consumers migrate: `src/components/StatCard.tsx`

**Interfaces:**
- Consumes: `Page`, `setPage`, `recentScans`, `aiReady`, and `fmtDate`.
- Produces: the shared page identity/inset contract, equal tool launch cards, and compact recent activity with no aggregate audit score.

- [ ] **Step 1: Implement the page and launch-card contracts**

Create the shared page wrapper:

```tsx
export function ToolPage(props: {
  title: string;
  description: string;
  context?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
}): JSX.Element;
```

It renders the approved 20–24 px content inset, compact title/description, optional context/actions, and a single content column without adding a rounded container around the whole page.

Create:

```tsx
interface ToolLaunchCardProps {
  category: "Scanning" | "Research";
  title: string;
  description: string;
  actionLabel: string;
  icon: React.ReactNode;
  onOpen: () => void;
}

export function ToolLaunchCard(props: ToolLaunchCardProps): JSX.Element;
```

Render a semantic `<button>` with a minimum 108 px height, 13–14 px working text, gold only on the category/active affordance, and a visible focus state inherited from the global contract.

- [ ] **Step 2: Replace score cards and quick actions with four equal tools**

Use this source data in `Dashboard.tsx`:

```ts
const tools = [
  ["Scanning", "Source Scan", "Inspect code for dangerous patterns, secrets, and risky APIs.", "Start source scan", "source-scan"],
  ["Scanning", "Dependency Scan", "Check pinned packages against the OSV advisory database.", "Check dependencies", "deps-scan"],
  ["Research", "CVE Research", "Search NVD and OSV without requiring an active project.", "Research vulnerabilities", "cve-research"],
  ["Research", "AI Assistant", "Ask security questions with optional project or finding context.", "Open assistant", "assistant"],
] as const;
```

Remove aggregate Findings, Critical, and High cards. The Dashboard must not imply a single audit score.

Wrap the page in:

```tsx
<ToolPage title="Research Workbench" description="Choose a tool or resume recent work.">
  {/* four launch cards and recent activity */}
</ToolPage>
```

- [ ] **Step 3: Rebuild recent activity and compact empty state**

Render the latest six `recentScans` entries in a bordered table/list with Target, Tool, Findings, and When. With no history, render a compact bordered row containing the text `No activity yet` and two functional buttons: Start source scan and Check dependencies. Keep the AI configuration message compact and route its action to Settings or Assistant based on `aiReady`.

- [ ] **Step 4: Verify the Dashboard contract**

Run:

```bash
npm run check
npm run build
```

Expected: both exit 0. Manually verify all four tools have equal visual weight, each card opens exactly one tool, no global project is requested, and the empty-history state occupies less than one-third of the 900 px-high content canvas.

- [ ] **Step 5: Commit the Dashboard checkpoint when Git is available**

```bash
git add src/pages/Dashboard.tsx src/components/workbench/ToolPage.tsx src/components/workbench/ToolLaunchCard.tsx
git commit -m "feat: rebuild dashboard as tool launchpad"
```

---

### Task 4: Create shared tool-page primitives and migrate Source Scan

**Files:**
- Reuse: `src/components/workbench/ToolPage.tsx`
- Create: `src/components/workbench/TargetBar.tsx`
- Create: `src/components/workbench/ResultsToolbar.tsx`
- Create: `src/components/workbench/SplitWorkspace.tsx`
- Create: `src/components/workbench/InlineState.tsx`
- Create: `src/components/workbench/Switch.tsx`
- Create: `src/components/FindingDetail.tsx`
- Modify: `src/pages/SourceScan.tsx:1-377`
- Modify: `src/components/FolderPicker.tsx:1-40`
- Modify: `src/components/ProgressBar.tsx:1-37`
- Modify: `src/components/SeverityBadge.tsx:1-14`
- Delete: `src/components/FindingCard.tsx`

**Interfaces:**
- Consumes: existing scan options, scan events, `api.scanProject`, `api.cancelScan`, `Finding`, `ScanResult`, and page-status store methods.
- Produces: shared page layout contracts and the approved list/detail Source Scan workspace used as the reference implementation for later pages.

- [ ] **Step 1: Implement exact shared component signatures**

```tsx
export function TargetBar(props: {
  children: React.ReactNode;
  secondary?: React.ReactNode;
  primary: React.ReactNode;
}): JSX.Element;

export function ResultsToolbar(props: {
  countLabel: string;
  filters?: React.ReactNode;
  search?: React.ReactNode;
  actions?: React.ReactNode;
}): JSX.Element;

export function SplitWorkspace(props: {
  listLabel: string;
  list: React.ReactNode;
  detailLabel: string;
  detail: React.ReactNode;
  hasSelection: boolean;
  onBackToList?: () => void;
}): JSX.Element;

export function InlineState(props: {
  tone: "idle" | "running" | "empty" | "error" | "unavailable";
  title: string;
  description?: string;
  action?: React.ReactNode;
  progress?: React.ReactNode;
  compact?: boolean;
}): JSX.Element;

export function Switch(props: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}): JSX.Element;
```

`SplitWorkspace` uses a real list region and detail region. At widths below 900 px it shows one region at a time and exposes a labeled Back to findings button. `Switch` uses a native checkbox input or a button with `role="switch"`, `type="button"`, and `aria-checked`.

- [ ] **Step 2: Convert FolderPicker and ProgressBar to shared behavior**

Add `disabled?: boolean` and `buttonLabel?: string` to `FolderPicker`; ensure the input has an accessible label from the caller and the Browse button is `type="button"`. Give `ProgressBar` `role="progressbar"`, `aria-valuemin`, `aria-valuemax`, `aria-valuenow` when determinate, and a nearby polite live label.

- [ ] **Step 3: Replace accordion findings with selected list/detail state**

In `SourceScanPage`, add:

```ts
const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
const selectedFinding = filtered.find((finding) => finding.id === selectedFindingId) ?? filtered[0] ?? null;
```

Render each finding as a list button with `aria-current={selectedFinding?.id === finding.id}`. Render `FindingDetail` with:

```tsx
export function FindingDetail({
  finding,
  onCopy,
  onOpenFile,
}: {
  finding: Finding;
  onCopy: (finding: Finding) => void;
  onOpenFile: (finding: Finding) => void;
}): JSX.Element;
```

Display rule, severity text, CWE, file/line, description, match/context evidence, and recommendation. Omit Ask Assistant until Task 7 provides a functional handoff.

Use the already-installed opener plugin for the functional file action:

```ts
import { openPath } from "@tauri-apps/plugin-opener";

const openFindingFile = (finding: Finding) => openPath(finding.filePath);
```

- [ ] **Step 4: Preserve completed results during a new scan**

Remove `setResult(null)` from the start of `run()`. Disable duplicate submission, show progress inside the target/results region, and replace results only after `api.scanProject` succeeds. When the path changes, clear `result`, filters, selection, and stale page status because the previous result no longer belongs to the selected project.

Map status transitions exactly:

```ts
setPageStatus("source-scan", { label: "Scanning", tone: "running", detail: progress?.file });
setPageStatus("source-scan", { label: "Scan complete", tone: "success", detail: `${res.summary.totalFindings} findings` });
setPageStatus("source-scan", { label: "Scan failed", tone: "error" });
```

- [ ] **Step 5: Recompose the page into the approved anatomy**

Use `ToolPage`, `TargetBar`, `ResultsToolbar`, and `SplitWorkspace`. Place scan toggles and max size inside a functional `<details>` labeled Advanced scan settings. Put category, severity, language, and search controls directly above results. Replace the export modal with a single functional Copy JSON action; do not render unsupported file export.

For idle, filtered-empty, result-empty, error, and unavailable behavior, use `InlineState` rather than large dashed cards. Keep raw exception details out of the main copy when a concise message such as `The selected folder could not be scanned` is available; include the original string in a selectable Details disclosure.

- [ ] **Step 6: Verify Source Scan before using it as the pattern**

Run:

```bash
npm run check
npm run build
npm run tauri dev
```

Expected: check/build exit 0. In the native app, verify Browse, manual path input, scan, cancel, progress, filters, selection, Copy JSON, Copy finding, and Open file. Start a second scan against the same path and confirm the previous results remain visible until success. Trigger an invalid path and confirm an inline retry/correction state appears.

- [ ] **Step 7: Commit the Source Scan checkpoint when Git is available**

```bash
git add src/pages/SourceScan.tsx src/components/FolderPicker.tsx src/components/ProgressBar.tsx src/components/SeverityBadge.tsx src/components/FindingCard.tsx src/components/FindingDetail.tsx src/components/workbench
git commit -m "feat: migrate source scan to workbench layout"
```

---

### Task 5: Migrate Dependency Scan to a package table and advisory detail

**Files:**
- Modify: `src/pages/DepsScan.tsx:1-304`
- Reuse: `src/components/workbench/ToolPage.tsx`
- Reuse: `src/components/workbench/TargetBar.tsx`
- Reuse: `src/components/workbench/ResultsToolbar.tsx`
- Reuse: `src/components/workbench/SplitWorkspace.tsx`
- Reuse: `src/components/workbench/InlineState.tsx`

**Interfaces:**
- Consumes: `api.findLockfiles`, `api.scanDependencies`, dependency progress events, `DependencyScanResult`, and shared workbench components.
- Produces: a project-aware dependency workspace with a compact vulnerability table and selected advisory detail.

- [ ] **Step 1: Replace accordion state with a stable selected vulnerability key**

Replace `expanded` with:

```ts
const [selectedKey, setSelectedKey] = useState<string | null>(null);
const vulnerabilityKey = (v: Vulnerability) => `${v.id}:${v.packageName}:${v.installedVersion}`;
const selected = filteredVulns.find((v) => vulnerabilityKey(v) === selectedKey) ?? filteredVulns[0] ?? null;
```

Reset `selectedKey` when the selected path changes or a new result replaces the old one.

- [ ] **Step 2: Preserve prior results and map truthful page status**

Remove `setResult(null)` at scan start. Keep the existing result visible while progress renders above it. On success set `Dependencies checked · N vulnerabilities`; on failure set `Dependency check failed`; clear stale result/status when the path changes.

- [ ] **Step 3: Build the package table and detail pane**

Render columns Package, Installed, Fixed, Ecosystem, and Risk. Each row is a keyboard-operable selection control using `aria-current`. The detail pane renders summary/details, advisory aliases, CVSS, affected range, fixed versions, published date, lockfile, and existing external reference buttons.

Do not add Export SBOM because no supported export currently exists. Keep Find lockfiles and Check dependencies as distinct functional actions in `TargetBar`.

- [ ] **Step 4: Use compact inline states**

Implement these exact meanings:

- Idle: `Choose a project to detect supported lockfiles.`
- Preview empty: `No supported lockfiles were found in this project.`
- Success empty: `OSV returned no published vulnerabilities for the queried packages.`
- Error: `Dependency checking failed` plus retry and selectable technical details.

- [ ] **Step 5: Verify Dependency Scan**

Run:

```bash
npm run check
npm run build
npm run tauri dev
```

Expected: check/build exit 0. In the native app, verify folder selection, lockfile discovery, progress, a clean result, a vulnerable result, table row selection, reference opening, and an invalid-path error. Confirm CVE Research remains directly usable without visiting this page.

- [ ] **Step 6: Commit the Dependency Scan checkpoint when Git is available**

```bash
git add src/pages/DepsScan.tsx
git commit -m "feat: migrate dependency scan to package workspace"
```

---

### Task 6: Migrate CVE Research to a standalone dossier workspace

**Files:**
- Create: `src/components/CveDossier.tsx`
- Modify: `src/pages/CveResearch.tsx:1-466`

**Interfaces:**
- Consumes: `api.searchCves`, `api.cveDetail`, `api.osvPackageVulns`, `api.researchCve`, `CveItem`, `CveDetail`, and workbench primitives.
- Produces: standalone search/list/dossier behavior with visible NVD/OSV attribution and no project dependency.

- [ ] **Step 1: Keep search results and detail in one page**

Remove the early `if (detail) return <CveDetailView ... />` branch. Maintain:

```ts
const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
const selectedItem = result?.items.find((item) => item.id === selectedCveId) ?? result?.items[0] ?? null;
```

Selecting a result calls `openDetail(id)` and fills the detail region without replacing the search/list context.

- [ ] **Step 2: Implement the dossier component**

Create this interface:

```tsx
export function CveDossier({
  detail,
  loading,
  aiReady,
  onGenerateBriefing,
}: {
  detail: CveDetail | null;
  loading: boolean;
  aiReady: boolean;
  onGenerateBriefing: () => Promise<string | null>;
}): JSX.Element;
```

Render Overview, NVD record, OSV record, References, and AI briefing as clearly labeled sections. Keep verified `CveItem` fields visually separate from raw OSV JSON and generated prose. Every external reference remains a functional `openUrl` button.

- [ ] **Step 3: Recompose search and package lookup without a project selector**

Use `ToolPage` with context text `No project required`. The primary target row remains CVE/keyword search. Keep OSV package lookup as a secondary disclosure labeled Package lookup, not a second competing primary form. Enter submits the currently focused form only.

- [ ] **Step 4: Add local loading, empty, pagination, and error states**

Keep the last completed result list visible during a new search. Disable duplicate requests. Map search and detail failures separately so a failed detail request does not erase the list. Use:

```ts
setPageStatus("cve-research", { label: "Searching NVD", tone: "running" });
setPageStatus("cve-research", { label: "Research ready", tone: "success", detail: `${res.total} results` });
setPageStatus("cve-research", { label: "Research unavailable", tone: "error" });
```

- [ ] **Step 5: Verify standalone research behavior**

Run:

```bash
npm run check
npm run build
npm run tauri dev
```

Expected: check/build exit 0. Launch directly into CVE Research with `activeProject === null`; search by keyword and CVE ID, paginate, select another result, open NVD/OSV references, run package lookup, and generate an AI briefing when configured. Verify failure in one source stays in the affected section.

- [ ] **Step 6: Commit the CVE Research checkpoint when Git is available**

```bash
git add src/pages/CveResearch.tsx src/components/CveDossier.tsx
git commit -m "feat: migrate cve research to dossier workspace"
```

---

### Task 7: Make Assistant context explicit and add cross-tool handoff

**Files:**
- Modify: `src/lib/workbench.ts`
- Modify: `src/lib/stores.ts`
- Modify: `src/components/FindingDetail.tsx`
- Modify: `src/components/CveDossier.tsx`
- Modify: `src/pages/Assistant.tsx:1-591`
- Modify: `src/components/chat/SessionSidebar.tsx:1-177`
- Modify: `src/components/chat/ThinkingCard.tsx:1-72`
- Modify: `src/components/chat/ToolCallCard.tsx:1-82`

**Interfaces:**
- Consumes: existing session APIs, streaming events, agent approval/ask-user flows, selected Finding/CVE data, and current AI readiness.
- Produces: `AssistantHandoff`, `openAssistant(handoff)`, explicit context review, and a balanced conversation workspace.

- [ ] **Step 1: Define the one-time handoff payload**

Add to `src/lib/workbench.ts`:

```ts
export interface AssistantHandoff {
  id: string;
  label: string;
  content: string;
  projectPath: string | null;
}
```

Add to the app store:

```ts
assistantHandoff: AssistantHandoff | null;
openAssistant: (handoff: AssistantHandoff) => void;
clearAssistantHandoff: () => void;
```

```ts
assistantHandoff: null,
openAssistant: (assistantHandoff) => set({ assistantHandoff, page: "assistant" }),
clearAssistantHandoff: () => set({ assistantHandoff: null }),
```

- [ ] **Step 2: Add only functional Discuss in Assistant actions**

In `FindingDetail`, format the inspectable handoff content from rule name, severity, path/line, description, evidence, and recommendation. In `CveDossier`, format it from CVE ID, severity/CVSS, description, affected products, CWEs, and source references. Call `openAssistant(...)`; do not send the content automatically.

- [ ] **Step 3: Require review before attaching a handoff**

In `AssistantPage`, observe the handoff once:

```ts
useEffect(() => {
  if (!assistantHandoff) return;
  setContextText(assistantHandoff.content);
  setContextLabel(assistantHandoff.label);
  setContextOpen(true);
  clearAssistantHandoff();
}, [assistantHandoff, clearAssistantHandoff]);
```

The context dialog shows the label and full editable/selectable content. Attach adds the context to the current session only after the user confirms. Cancel discards it. This is especially important because findings may contain source code or secrets.

When Attach is confirmed, append the formatted context as a visible user-source message and persist the same `StoredMessage` through `api.sessionAppend`. It must survive session reload and must not be sent until the user's next explicit Send action.

- [ ] **Step 4: Make new chats standalone by default**

Change `api.sessionCreate(null, activeProject)` to `api.sessionCreate(null, null)`. A loaded session displays its existing `projectPath` as an explicit context chip, but simply visiting Source Scan or Dependency Scan must not silently bind future chats to that path. Removing or changing a persisted session project is outside this UI-only pass because no existing API supports that mutation.

Do not remove the backend `set_active_project` behavior needed by agent tools for a session that already has an explicit project. Make the session's project visible whenever it is applied.

- [ ] **Step 5: Recompose the Assistant workspace without breaking streaming**

Keep `SessionSidebar`, messages, streaming reasoning, tool cards, approval modal, ask-user modal, usage, cancel, and persistence behavior. Remove the legacy `TopBar`; the shell header already identifies AI Assistant, and model/context/Clear controls belong in a compact conversation toolbar. Apply the workbench tokens, keep the composer fixed within the page, reduce the oversized empty illustration, and show AI unavailable/configuration feedback in context.

Replace index-based message keys with stored IDs where available; for transient messages, add an `id` when constructing `UiMessage`. Ensure the composer has an accessible label and Send/Cancel buttons have visible or `aria-label` names.

- [ ] **Step 6: Verify explicit-context and streaming behavior**

Run:

```bash
npm run check
npm run build
npm run tauri dev
```

Expected: check/build exit 0. Verify standalone new chat, finding handoff review/cancel/attach, CVE handoff review, session switch, streaming response, tool start/result, permission decision, ask-user response, cancel, clear, and unavailable AI. Confirm a handoff does not change Source Scan, Dependency Scan, or CVE Research state.

- [ ] **Step 7: Commit the Assistant checkpoint when Git is available**

```bash
git add src/lib/workbench.ts src/lib/stores.ts src/components/FindingDetail.tsx src/components/CveDossier.tsx src/pages/Assistant.tsx src/components/chat
git commit -m "feat: add explicit assistant context handoff"
```

---

### Task 8: Migrate Settings and finish shared component cleanup

**Files:**
- Create: `src/components/workbench/Field.tsx`
- Modify: `src/pages/SettingsPage.tsx:1-344`
- Modify: `src/components/EmptyState.tsx:1-28`
- Modify: `src/components/Toasts.tsx:1-36`
- Modify: `src/components/chat/ApprovalModal.tsx:1-66`
- Modify: `src/components/chat/AskUserModal.tsx:1-133`
- Delete: `src/components/TopBar.tsx`
- Delete when no imports remain: `src/components/StatCard.tsx`

**Interfaces:**
- Consumes: existing settings load/save/test/reset APIs and the shared `Switch`/`InlineState` visual behavior.
- Produces: labeled compact settings groups, inline save/test feedback, accessible dialogs, and no remaining legacy page-header dependency.

- [ ] **Step 1: Implement the Field contract**

```tsx
export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}): JSX.Element;
```

Generate deterministic `${htmlFor}-hint` and `${htmlFor}-error` IDs. Each control supplies `id={htmlFor}` and `aria-describedby` for the rendered hint/error.

- [ ] **Step 2: Recompose Settings into compact groups**

Use `ToolPage` with functional Reset and Save actions. Keep AI Engine, Scan Defaults, Data Sources, and Usage as separate bordered sections with 8–10 px radii. Replace the local `Field` and `Toggle` helpers with shared `Field` and `Switch`.

Add page-local feedback state:

```ts
const [saveState, setSaveState] = useState<
  { tone: "success" | "error"; message: string } | null
>(null);
```

Render save and connection-test feedback beside the affected controls. Keep a success toast as secondary confirmation; do not use a toast as the only error surface.

- [ ] **Step 3: Replace the loading page and remaining oversized empty state styling**

Use `InlineState` for Settings loading/unavailable state. Refactor `EmptyState` into a compatibility wrapper around `InlineState` while remaining consumers migrate, then remove it if `rg "EmptyState" src` returns no imports.

- [ ] **Step 4: Fix dialog semantics and focus behavior**

For `ApprovalModal`, `AskUserModal`, and the Assistant context dialog:

- render `role="dialog"` and `aria-modal="true"`;
- connect `aria-labelledby` and optional `aria-describedby`;
- focus the first safe action on open;
- trap Tab/Shift+Tab inside the dialog;
- close only when the flow permits Escape;
- restore focus to the invoking control on close;
- replace text-symbol close controls with the existing Lucide `X` icon and an `aria-label="Close"`.

- [ ] **Step 5: Remove legacy components and visible VulnCompanion copy**

Run:

```bash
rg -n "TopBar|StatCard|FindingCard|VulnCompanion" src index.html src-tauri/tauri.conf.json
```

Delete unused `TopBar`, `StatCard`, and `FindingCard` files. Replace remaining visible frontend copy with `oxAudit`. Keep internal Cargo crate names, the bundle identifier, storage key `vc.recentScans`, and backend user agents unchanged.

- [ ] **Step 6: Verify Settings and shared cleanup**

Run:

```bash
npm run check
npm run build
rg -n "outline-none|text-\[9px\]|text-\[10px\]" src
```

Expected: check/build exit 0. Any remaining `outline-none` must have the global focus contract and a documented local reason; essential information must not remain at 9–10 px. In Tauri, verify load, dirty state, reset, save success/failure, AI test success/failure, password field behavior, and dialog keyboard focus.

- [ ] **Step 7: Commit the Settings/cleanup checkpoint when Git is available**

```bash
git add src/pages/SettingsPage.tsx src/components src/index.css index.html src-tauri/tauri.conf.json
git commit -m "feat: finish workbench settings and shared states"
```

---

### Task 9: Complete responsive, visual, accessibility, and native acceptance

**Files:**
- Review against every acceptance item: `src/index.css`
- Review against every acceptance item: `src/components/workbench/*.tsx`
- Review against every acceptance item: `src/pages/*.tsx`
- Create: `docs/superpowers/qa/2026-08-17-oxaudit-workbench-acceptance.md`

**Interfaces:**
- Consumes: all migrated pages and the three approved visual artifacts.
- Produces: verified desktop breakpoints, keyboard behavior, truthful state handling, native smoke evidence, and a final acceptance record.

- [ ] **Step 1: Create the acceptance record before final fixes**

Create a checklist with these exact sections and mark each item during verification:

```markdown
# oxAudit Workbench Acceptance

## Automated
- [ ] npm run check
- [ ] npm run build
- [ ] cargo test --manifest-path src-tauri/Cargo.toml
- [ ] cargo check --manifest-path src-tauri/Cargo.toml

## Viewports
- [ ] 1440x900
- [ ] 1180x760
- [ ] 900x700
- [ ] 899x700 browser-only drawer boundary

## Keyboard and accessibility
- [ ] Sidebar and drawer
- [ ] Tool target and result controls
- [ ] List/detail selection
- [ ] Assistant composer and sessions
- [ ] Settings forms
- [ ] Dialog focus trap and restoration

## Native flows
- [ ] Source success and failure
- [ ] Dependency success and failure
- [ ] CVE/OSV success and failure
- [ ] Assistant success, unavailable, cancel, permission, ask-user
- [ ] Settings load, test, save, failure
```

- [ ] **Step 2: Run the complete automated baseline**

```bash
npm run check
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
cargo check --manifest-path src-tauri/Cargo.toml
```

Expected: all commands exit 0. Record each command and result in the acceptance file.

- [ ] **Step 3: Compare the rendered UI with all three approved artifacts**

At 1440×900, capture Dashboard, populated Source Scan, populated Dependency Scan, populated CVE Research, active Assistant, and Settings. Compare shell geometry, warm-neutral palette, gold restraint, content inset, type scale, toolbar placement, list/detail density, and status bar against the approved shell/workspace/adaptation artifacts. Fix visible mismatches and recapture.

- [ ] **Step 4: Verify responsive desktop behavior**

At 1180×760, confirm labeled sidebar, readable detail pane, and no shell-level horizontal scroll. At the native 900×700 minimum, confirm the labeled sidebar and table-local horizontal scrolling remain usable. In a browser-only 899×700 check, confirm drawer behavior, focus restoration, and stacked list/detail navigation. Fix any clipped controls, double scrollbars, or unreachable actions.

- [ ] **Step 5: Complete keyboard and accessibility traversal**

Tab through every primary flow. Confirm visible focus, `aria-current` on active navigation/results, semantic table headers, live progress that does not chatter, error association, severity text, reduced motion, and modal focus trap/restoration. Use browser accessibility inspection plus native keyboard behavior; screenshots alone do not satisfy this step.

- [ ] **Step 6: Complete native success/failure smoke tests**

Run `npm run tauri dev` and exercise one successful and one failed operation in every tool. Verify folder picker, file opening, clipboard, backend progress events, external URLs, settings persistence, AI stream/cancel/approval/ask-user, and explicit context handoff. Record any environment-dependent test that cannot run and the exact missing prerequisite.

- [ ] **Step 7: Re-run the full verification after fixes**

```bash
npm run check
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
cargo check --manifest-path src-tauri/Cargo.toml
```

Expected: all exit 0 and every acceptance checkbox is resolved with evidence or a concrete environment prerequisite.

- [ ] **Step 8: Commit the final acceptance checkpoint when Git is available**

```bash
git add src docs/superpowers/qa/2026-08-17-oxaudit-workbench-acceptance.md
git commit -m "test: verify professional workbench experience"
```

## Completion Definition

The work is complete only when:

- all four tools remain directly usable and independent;
- the shell, Dashboard, shared workspace, and tool adaptations match the approved direction;
- no visible primary action is decorative;
- CVE Research and a new Assistant chat work with no project selected;
- project/finding/CVE handoff to Assistant is visible, editable, removable, and confirmed before attachment;
- inline state/error behavior covers success and failure in each tool;
- keyboard, focus, contrast, reduced motion, responsive desktop, browser visual, and Tauri-native checks are recorded;
- TypeScript, frontend build, Rust tests, and Rust check pass.
