# oxAudit Professional Workbench UI Design

Date: 2026-08-17  
Status: Approved design  
Reference: [oxfuzz](https://github.com/HenryCooper86/oxfuzz/)

## Objective

Refine oxAudit into a balanced, professional desktop workbench while preserving its identity as a collection of independent security research tools.

The redesign should make the application feel cohesive without turning Source Scan, Dependency Scan, CVE Research, and AI Assistant into a forced end-to-end audit workflow. A user must be able to open any tool directly, use only that tool, and understand its state without configuring unrelated parts of the application.

## Approved Direction

The approved direction is **Professional Workbench**:

- compact, grouped navigation;
- warm black and neutral surfaces with a restrained muted-gold accent;
- balanced information density suitable for research work;
- equal prominence for the four primary tools;
- persistent, in-context results instead of oversized empty states or modal-heavy flows;
- predictable shared page anatomy with tool-specific result models.

The oxfuzz UI is a design reference, not a product model to copy. oxAudit adopts its strongest workbench qualities—compact chrome, clear navigation groups, disciplined tokens, strong focus states, and status visibility—while retaining oxAudit's independent-tool architecture.

## Scope

This design covers the existing React/Tauri application shell and these existing pages:

- Dashboard
- Source Scan
- Dependency Scan
- CVE Research
- AI Assistant
- Settings

The initial implementation is a UI and frontend-structure refactor. Existing Tauri commands, scan engines, advisory integrations, settings persistence, and AI behavior remain the source of truth.

## Non-goals

- No aggregate security score or compliance dashboard.
- No mandatory audit project, guided wizard, or enforced sequence between tools.
- No new scanner, advisory source, agent capability, or backend protocol.
- No global project requirement for CVE Research or AI Assistant.
- No decorative global Search or Help controls unless they have functional behavior in the same implementation. The conceptual mockup showed their possible placement; the first implementation should omit dead controls.
- No unrelated refactor of Rust commands or domain logic.

## Information Architecture

The primary navigation is grouped by job:

1. Dashboard
2. Scanning
   - Source Scan
   - Dependencies
3. Research
   - CVE Research
   - AI Assistant
4. Settings, anchored at the bottom

The Dashboard is a launchpad, not a summary verdict. It contains four equal tool cards, recent activity, and service/application status that can be derived from real state. It does not rank tools, compute a global risk score, or require an active project.

## Application Shell

The desktop shell has three stable regions:

### Sidebar

- Target width: 208 px in the normal desktop layout.
- Displays the oxAudit brand and grouped navigation.
- Active state uses a subtle raised surface, border, and muted-gold marker.
- Settings remains visually separated at the bottom.
- Labels remain visible at normal desktop widths; the first pass does not introduce an icon-only mode.

### Work area

- A compact 52 px page header provides breadcrumb or page identity and functional page-level actions.
- The content canvas uses a consistent 20–24 px desktop inset.
- Pages own their internal scrolling. The shell itself stays fixed.

### Status bar

- Target height: 28 px.
- Shows only truthful, useful state for the current page: active operation status, result counts when relevant, AI readiness, and application version.
- NVD and OSV connectivity is shown only while or after a real request provides that signal; the UI must not invent permanent health checks.
- Status text is not the sole indication of errors or progress.

## Shared Tool-page Anatomy

Each tool page follows the same rhythm while retaining its own content model:

1. **Identity:** title, one-sentence purpose, and optional context chip.
2. **Target and primary action:** one compact row containing the path, query, manifest, or composer context plus one clear primary action.
3. **Result controls:** count, filters, sort, and export actions directly above results.
4. **Results workspace:** persistent output region using the structure best suited to that tool.
5. **Focused detail:** selected evidence, metadata, remediation, or source attribution when applicable.
6. **Local status:** progress, completion, empty, and failure states appear inside the affected workspace and, when useful, in the status bar.

Project context is optional at the architecture level. Source Scan and Dependency Scan are project-aware. CVE Research is standalone. AI Assistant may run standalone or accept a project, finding, code excerpt, or advisory as explicit context.

## Tool-specific Adaptations

### Source Scan

- Input: local project path and existing scan options.
- Primary action: Run scan.
- Results: severity and rule filters above a list-and-detail workspace.
- List items show the finding title, severity, and file location.
- Detail shows rule/CWE metadata, description, code evidence, remediation guidance, and functional actions such as Copy, Open file, and Ask Assistant.
- Running a new scan does not erase the last completed results until replacement results are available, unless the selected project changes.

### Dependency Scan

- Input: project path or detected manifest/lockfile.
- Primary action: Check dependencies.
- Results: a compact package table optimized for package, installed version, fixed version, ecosystem, and severity.
- Selecting a vulnerable package opens advisory detail without leaving the page.
- Export actions appear only when an export format is currently supported.

### CVE Research

- Input: CVE identifier, package/advisory identifier, or search terms.
- Primary action: Research.
- No project selection is required.
- Results use a dossier model with a result/source list and a structured detail surface.
- Verified NVD/OSV fields, references, and analyst notes are visually separated. Source attribution remains visible near the data it supports.

### AI Assistant

- Input: conversation composer.
- Context is explicit and removable: none, project, finding, code excerpt, or advisory.
- The main surface remains a conversation, with session navigation retained where useful.
- Tool calls, approval requests, failures, and source material remain distinguishable from assistant prose.
- Attaching context must not silently make it the global context for unrelated tools.

### Settings

- Retains all existing settings and persistence behavior.
- Uses clear groups, compact fields, and inline connection tests.
- Save, test, and validation feedback appears beside the affected group; global toasts are secondary confirmation only.

## Dashboard

The Dashboard contains:

- four equal launch cards for Source Scan, Dependency Scan, CVE Research, and AI Assistant;
- short, task-oriented descriptions and one direct action per card;
- recent activity drawn from real local history;
- honest service/application state.

The Dashboard must work when there is no recent activity, no project, and no configured AI provider. Empty content remains compact and provides a direct next action.

## Visual System

### Color

- App background: warm near-black.
- Sidebar, panels, and controls: stepped neutral surfaces separated primarily by 1 px borders.
- Primary accent: muted gold, reserved for the selected navigation marker, primary actions, active filters, and important focus/selection states.
- Semantic colors: red for high-risk/error, amber for warning/medium risk, green for success/ready, and blue-neutral for information.
- Severity must always include text; color alone is insufficient.

Exact token values should be centralized in `src/index.css` and adjusted during visual verification rather than scattered through page components.

### Typography

- Use the existing system sans-serif stack unless the project already includes a locally available typeface.
- Working text should generally remain 13–14 px.
- Metadata may use 11–12 px when contrast remains sufficient.
- Avoid the current pattern of relying heavily on 9–10 px low-contrast text for essential information.
- Page titles are compact, not marketing-style headings.

### Shape and depth

- Controls: approximately 6 px radius.
- Panels/cards: approximately 8–10 px radius.
- Application-level frames may use up to 14–16 px in visual materials, but production pages should avoid nested rounded containers.
- Depth comes from surface steps and borders; shadows are reserved for overlays and the outer desktop frame.

### Motion

- Motion is functional and brief: progress, accordion expansion, or selection transitions.
- Respect `prefers-reduced-motion`.
- Avoid decorative entrance animations on routine tool pages.

## Frontend Architecture

The current state-driven page navigation can remain. This redesign does not require a routing library.

Introduce small, reusable presentation boundaries:

- `AppShell`: fixed sidebar, header region, work area, and status bar.
- `Sidebar`: grouped navigation data and active state.
- `WorkbenchHeader`: page identity, breadcrumb, optional context, and functional actions.
- `ToolPage`: shared content inset and vertical page rhythm.
- `TargetBar`: tool-specific input slot plus primary and secondary actions.
- `ResultsToolbar`: count, filters, sort, and supported exports.
- `SplitWorkspace`: accessible list-and-detail layout with a stacked narrow-window fallback.
- `InlineState`: idle, running, empty, success, and error content within the result region.
- Existing domain components such as severity badges, progress bars, finding content, and chat tool-call cards remain specialized.

These components define layout and behavior, not domain data. Each page continues to own its tool-specific state and call the existing `api` layer. The shared store should contain only cross-page concerns such as current page, truthful service readiness, recent activity, and an explicit one-time handoff payload. A selected project must not become a prerequisite for standalone tools.

## Data and Interaction Flow

For each tool:

1. The page gathers and validates its own input.
2. The page invokes the existing API/Tauri command.
3. Progress is rendered locally without blocking navigation.
4. Successful data is normalized only as much as the shared presentation component requires.
5. The page renders its own result model.
6. Optional cross-tool actions pass explicit, inspectable context—for example, a Source Scan finding passed to AI Assistant.

Cross-tool handoffs are conveniences, not workflow gates. They must never be required to complete the originating tool's task. A handoff payload may prefill a destination tool or assistant session, after which that destination owns the context; it must not silently update ambient context for other tools.

## State and Error Handling

Every tool must define these states:

- **Idle:** compact instruction and the next useful action.
- **Running:** visible progress and disabled duplicate submission; retain prior completed output when safe.
- **Success:** result count and timestamp/duration when available.
- **Empty:** explain that the operation succeeded but found no matching data.
- **Error:** concise cause, affected operation, and a retry or correction action.
- **Unavailable:** distinguish unconfigured services from temporary connection failures.

Errors stay in the affected workspace. Toasts are reserved for short-lived confirmation or a background event whose origin is otherwise not visible. Raw exception strings should be mapped to useful user-facing messages where the frontend has enough context to do so.

## Accessibility and Keyboard Behavior

- Add a global, high-contrast `:focus-visible` treatment.
- Do not use `outline: none` unless an equivalent visible focus indicator is present.
- All interactive controls use semantic buttons, inputs, links, tables, and dialogs.
- Navigation and result selection work by keyboard.
- Selected navigation, tabs, filters, and rows expose their selected/current state programmatically.
- Progress and completion feedback uses restrained `aria-live` announcements.
- Text and essential borders target WCAG AA contrast.
- Dialog focus is trapped and restored to the invoking control.
- Reduced-motion preferences are honored.

## Responsive Desktop Behavior

oxAudit remains desktop-first.

- At 1180 px and wider: full sidebar and side-by-side list/detail workspaces.
- From 900–1179 px: preserve the labeled sidebar, tighten content insets, and allow detail panes to narrow.
- Below 900 px: navigation moves into a labeled drawer opened by a functional menu button, and list/detail layouts stack so the selected detail replaces or follows the list.
- Data tables may scroll horizontally inside their own region; the application shell must not create page-level horizontal scrolling.
- The implementation should verify at least 1440×900, 1180×760, and 900×700 desktop window sizes.

## Implementation Sequence

1. Centralize tokens, typography, focus styles, and reduced-motion behavior.
2. Build the shell, grouped navigation, page header, and truthful status bar.
3. Rebuild the Dashboard as the independent-tool launchpad.
4. Add shared tool-page primitives and inline states.
5. Migrate Source Scan and Dependency Scan.
6. Migrate CVE Research and AI Assistant.
7. Restyle Settings and remaining shared components.
8. Perform visual, keyboard, responsive, and Tauri-native verification.

The migration should preserve existing behavior page by page. Do not replace all pages in one unverified visual rewrite.

## Verification and Acceptance Criteria

### Automated checks

- `npm run check` passes.
- `npm run build` passes.
- Existing Rust/Tauri checks used by the project continue to pass.
- No new automated test framework is required solely for this UI pass. Pure helpers or state logic introduced during implementation should receive focused tests when a compatible test setup already exists or is added for a concrete need.

### Visual checks

- Compare the implementation with the approved shell, shared workspace, and tool-adaptation mockups at the same viewport sizes.
- Verify consistent sidebar, header, content inset, toolbar, result, and status-bar dimensions.
- Verify no clipped controls, accidental nested scroll regions, unreadably small text, or empty-state layouts that dominate the viewport.

### Interaction checks

- Every visible primary control performs a real action.
- Every tool can be opened and used directly from the sidebar.
- CVE Research works without an active project.
- AI Assistant works without project context and clearly shows when context is attached.
- Source and dependency results remain readable while a new operation is running.
- Errors appear in context with a correction or retry path.

### Accessibility checks

- Complete keyboard traversal of the shell and each tool's primary flow.
- Visible focus on every interactive element.
- Screen-reader state for active navigation, selected filters/rows, dialogs, progress, and errors.
- Contrast review for muted text, borders, severity states, and disabled controls.

### Native smoke checks

- Launch the Tauri desktop build, because folder selection, file opening, clipboard behavior, settings loading, and backend events cannot be fully validated in a browser-only preview.
- Exercise at least one successful and one failed operation in each tool.

## Approved Visual Artifacts

The brainstorming companion contains three approved artifacts:

- Professional Workbench application shell
- Shared tool workspace using Source Scan
- Independent tool adaptations for all four primary tools

They are visual references for hierarchy, density, grouping, and state placement. Production controls must remain functional and may omit illustrative controls that are outside the scope defined above.
