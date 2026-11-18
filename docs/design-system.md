# oxAudit Design System

Since 2026-11-18 the desktop workbench follows the visual structure of
[oxFuzz](https://github.com/HenryCooper86/oxfuzz/)'s GUI (`crates/hf-gui`): the
same shell, token values, radii, elevation, focus ring, motion and page
primitives, adapted to oxAudit's content, so the two products read as one
family. Where an oxFuzz value would break one of oxAudit's accessibility or
privacy rules, oxAudit keeps its own; each such departure is listed in
[section 11](#11-departures-from-oxfuzz). This document is the contract; the
enforcement lives in [`tests/designSystem.test.ts`](../tests/designSystem.test.ts)
and [`tests/themeContrast.test.ts`](../tests/themeContrast.test.ts).

---

## 1. Two-layer token model

`src/index.css` defines tokens twice, on purpose:

| Layer | What it is | Why |
|---|---|---|
| **Runtime** | Plain CSS variables on `:root` / `[data-theme="light"]` | These are what the theme switch swaps at runtime |
| **Tailwind** | `@theme inline` aliases (`--color-surface-primary: var(--surface-primary)`) | `inline` makes each utility emit `var(--surface-primary)` instead of baking a literal, so utilities follow the live theme |

Consequence: **never write a raw Tailwind palette color.** `bg-slate-800`,
`text-red-400`, `border-stone-600` are all rejected by the contract test. Use
`bg-surface-tertiary`, `text-error`, `border-border`.

### Token families

```
surface-primary  secondary  tertiary  hover  active  code
text-primary     secondary  muted
accent           accent-hover  accent-subtle  accent-glow  accent-contrast
success / error / warning / info     (each with -subtle and -border)
border           border-strong  border-focus  control-border
sev-critical / -high / -medium / -low / -info / -unknown   (each with -subtle and -border)
elevation-sm / -md / -lg             (Tailwind shadow-sm / -md / -lg)
```

Surfaces, text, accent, borders and elevation take oxFuzz's values: warm
near-black (`#0f0f0f` / `#141414` / `#1c1c1c`) and white / `#f5f4f1` /
`#edecea` surfaces, `#e8e6e1` / `#aaa59e` / `#8c8881` text in dark, the
`#c8b560` gold accent in dark, 8% (dark) and 13% (light) hairline borders, and
oxFuzz's `0 2px 8px` / `0 8px 24px` / `0 16px 48px` shadows.

oxAudit adds what a scanner needs and oxFuzz does not have: the `-subtle` /
`-border` pairs for every semantic colour, `control-border` (the 3:1 boundary
of editable fields), and the `sev-*` axis. `sev-*` carries **five
distinguishable steps**, because badge-size severity is the primary signal in a
scanner UI. It is consumed only through `severityColor()` / `severityDot()` in
`src/lib/format.ts`; never inline it.

### Usage discipline

- `text-primary`: interactive control labels, headings, body copy that matters.
- `text-secondary`: descriptions under titles, supporting copy, outline and
  ghost button labels, the header's page title.
- `text-muted`: metadata, section labels, icon glyphs at rest, placeholders,
  the status bar.
- **Accent is used sparingly.** It marks the active nav item's icon, links,
  header toggles while pressed, icon chips, and exactly one primary action per
  view. A full-width solid accent block is a smell.

---

## 2. Radius

| Token | Value | Applies to |
|---|---|---|
| `rounded-sm` | 4px | badges, chips, `kbd`, small inline tags |
| `rounded-md` | 8px | every control (buttons, fields, selects, header toggles), nav items, list rows, sub-panels inside a card |
| `rounded-lg` | 12px | cards (`surface-card`), dialogs, the command palette, toasts |
| `rounded-composer` | 16px | the AI assistant's floating composer, and nothing else |

`rounded-full` is for dots, avatars, icon circles and the switch.
`rounded-xl`/`2xl`/`3xl` fail the contract test. The composer radius is the one
sanctioned step above the card radius (oxFuzz's chat composer uses 16px); the
contract test allows `rounded-composer` only in `src/pages/Assistant.tsx` and
`src/components/chat/`.

## 3. Cards and elevation

`surface-card` is the one content card, oxFuzz's shortcut of the same name:

```css
.surface-card {            /* @layer components */
  background-color: var(--surface-primary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--elevation-sm);
}
```

It lives in the components layer, so any utility on the same element wins:
`border-l-[3px] border-l-accent` for a status stripe, `shadow-lg` for a dialog,
`shadow-none` for a card nested inside another. Content cards are flat with a
hairline; a heavy shadow on every card was visually noisy in oxFuzz too.

Only `shadow-sm` / `shadow-md` / `shadow-lg` exist, mapped to `--elevation-*` so
they darken correctly per theme. `shadow-sm` is the card default, `shadow-md`
is for toasts, `shadow-lg` for dialogs, the command palette and the drawer.
`shadow-xl`/`shadow-2xl` fail the contract test.

## 4. Type

Body is 13px at zero letter-spacing (oxFuzz's base is 14px with 12–13px
working text, so the density matches). Sizes are explicit px (`text-[12px]`).

| Use | Style |
|---|---|
| Brand wordmark "oxAudit" | display font, 15px, bold |
| Header page title | display font, 14px, 500, `text-secondary` |
| Page `h1` (ToolPage) | 18px semibold, `text-primary` |
| Page description | 13px `text-secondary` |
| Nav items | 13px/500 |
| Section labels | 10.5px uppercase, 600, `0.08em` |
| Controls | 12px (`md`), 11px (`sm`) |
| Status bar | 11px `text-muted` |

The stacks are oxFuzz's (`Inter` → system UI; `SF Pro Display` for display;
`SF Mono` for code). No font is fetched: the CSP is `font-src 'self'` and
oxAudit only talks to NVD, OSV and the configured AI endpoint, so the stacks
fall back to the same system faces.

## 5. Motion and focus

Keyframes from oxFuzz, as Tailwind utilities: `animate-fade-in` (pages, 0.2s),
`animate-slide-in-up` (toasts), `animate-dialog-in` (dialogs, the palette),
`animate-status-pulse` (running status dots; oxFuzz's `pulse`, renamed so it
cannot replace Tailwind's own `animate-pulse`). The
`prefers-reduced-motion` block neutralises every animation and transition.

The keyboard focus ring is oxFuzz's: a 2px surface-coloured gap inside a 2px
accent ring, drawn with `box-shadow` on `:focus-visible` for buttons, links,
fields, tabs, switches and anything with `tabindex`. It is `!important` so a
card's `shadow-sm` cannot replace it while focused, and a transparent outline
backs it up for forced-colours mode.

Scrollbars are 4px with a 2px-radius thumb; selection uses `accent-subtle`.

## 6. Theming

`settings.theme` holds `"dark" | "light" | "system"`. Resolution is pure logic in
`src/lib/theme.ts`; `src/lib/useTheme.ts` binds it to `<html data-theme>`.
`src/main.tsx` applies the cached preference before React mounts so a light-theme
user never sees a dark flash.

Theme is a **live preference, not a draft field**. Both the header theme button
and the Settings → General → Appearance control write immediately via
`savePersistedThemePreference()`, which joins the same serialized write queue as a
full settings save but **skips the AI connection test**: flipping the theme must
not touch the network. Settings mirrors the value into its draft so `dirty` never
reports a phantom diff and a later Save cannot revert the theme.

## 7. Shell

```
#root > div (grid: sidebar | column)
  a  "Skip to workspace"            first Tab stop, focuses main
  aside#primary-navigation          "Primary navigation", 240px
  section (rows 52px | 1fr | 28px)  inert while the drawer is open
    header                          the document's first <header>
    main#main-content               the only vertical scroller
    footer                          the status bar, the only <footer>
```

Overlays (command palette, readiness wizard, the Assistant's context dialog)
isolate the background by walking `main` → section → grid and making every
sibling inert; keep that nesting. The sidebar therefore never contains a
`header`, `footer`, heading or list item of its own.

### Sidebar (240px, `surface-secondary`, right hairline)

Top to bottom, as in oxFuzz:

1. A 28px spacer, **macOS desktop only**, where the traffic lights sit; it is
   a window drag region.
2. Brand row: the oxAudit mark (20px, accent) and the wordmark **oxAudit**.
3. **Open project** (accent plus icon). Desktop: the native folder picker,
   then the same selection Project home's "Open project" makes, landing on the
   Dashboard. Server mode has no native picker, so it goes to the Dashboard and
   focuses the typed project folder field.
4. **Recent**: the five most recent projects from `api.listSourceProjects`
   (the command palette's source). Choosing one does what the palette does:
   make it the active project and open Source Scan. With none, a one-line hint.
5. Tool groups: **Workspace** (Dashboard, Portfolio, AI Assistant),
   **Scanning** (Source, History, Dependencies, Binary, Image, YARA, Template),
   **Results** (Inventory, Verification, Export Center, Report Studio,
   Compliance Center), **Intelligence** (CVE Research, Advisory Database, Data
   Sources, VEX Trust), **Quality** (Rule Library, Quality Lab).
   `NAVIGATION_SECTIONS` and `PAGE_META` in `src/lib/workbench.ts` are the one
   source for the sidebar, the header and the command palette's groups.
6. Footer, pinned above a hairline: Settings as an ordinary item, a
   **Press ⌘K to search** button (accessible name "Search tools and
   projects", `aria-haspopup="dialog"`, `aria-keyshortcuts="Meta+K
   Control+K"`) that opens the command palette, and the version.

Items 2 to 5 scroll as one region; the footer never covers an item, at any
window height. Nav items: 13px/500 labels, 18px icons, 8px radius; active =
`surface-active` with a hairline border and the icon in accent; hover =
`accent-subtle`.

**Show / hide.** At 900px and wider the sidebar is either shown at 240px or
hidden entirely; there is no icon rail and no page changes it (the Assistant
used to force a narrow rail). The toggle is the first header button ("Collapse
navigation" / "Expand navigation", `aria-expanded`, `aria-controls` =
`primary-navigation`). The choice persists in `localStorage` under
`oxaudit.navigationHidden.v1`; the retired rail key
(`oxaudit.navigationCollapsed.v1`) is ignored, so nobody starts with hidden
navigation because they once chose the rail. Below 900px the sidebar is a
drawer: the header's hamburger (`#navigation-menu-button`, "Open
navigation"), a blurred backdrop, focus moved into the drawer and trapped,
Escape and two "Close navigation" buttons, and an inert workspace.

### Header (52px, `surface-primary`, bottom hairline)

Left: the sidebar toggle (or the hamburger below 900px), the current page's
icon and its title in the display font. No brand, breadcrumb or search box.
Right: page toggles, then the theme button. Every header button is oxFuzz's
`HeaderToggle`: 32px square, 8px radius, muted at rest, accent on
`accent-subtle` while pressed.

**Page toggles.** A page registers its own header buttons with
`useHeaderActions(owner, actions)` from `src/lib/headerActions.ts`:

```ts
interface HeaderAction {
  id: string;            // stable within the owner
  label: string;         // accessible name and tooltip
  icon: LucideIcon;
  pressed?: boolean;     // a toggle (aria-pressed); omit for a one-shot action
  controls?: string;     // id of the region it shows or hides
  keyShortcuts?: string; // aria-keyshortcuts
  disabled?: boolean;
  onSelect: () => void;
}
```

Pass a memoized array; the buttons disappear when the page unmounts.

**Headings.** A page's single `h1` is its ToolPage title; the header title is
plain text. Pages without a ToolPage (`SHELL_HEADING_PAGES`, today the AI
Assistant) get their `h1` from the header instead. Settings is the third case:
see [Settings](#settings).

**Labelled header actions.** `HeaderAction` also takes an optional `kind`:
`"button"` renders a 28px labelled `Button` (`text`, `variant`
`"primary"|"outline"`, `busy`), and `"status"` renders a short live-region
message (`text`, `tone`). Settings uses both for **Reset**, **Save** and the
save status; a page that registers only icon toggles is unaffected.

### Status bar (28px, `surface-secondary`, top hairline, 11px muted)

Left, the live status (`role="status"`): a 6px dot (muted, accent and pulsing
while running, success, error), the label and detail, and **Cancel** for an
active scan. Right: AI readiness ("AI ready", "AI not configured", "AI not in
this build", …) with a status dot, then a clock. The version lives in the
sidebar footer.

### Window chrome

On macOS the desktop window uses the overlay title bar (`titleBarStyle:
"Overlay"`, `hiddenTitle: true` in `src-tauri/tauri.conf.json`): the traffic
lights float over the sidebar above the brand. `main.tsx` stamps
`data-host` (`tauri` | `web`) and `data-platform` on `<html>`; only
`html[data-host="tauri"][data-platform="macos"]` shows the 28px spacer, and a
hidden sidebar gives the header a 78px left inset. The header, its title, the
sidebar spacer and the brand row carry `data-tauri-drag-region`
(`core:window:allow-start-dragging` in `capabilities/default.json`); Windows,
Linux and the headless server's browser build keep their native or absent
title bars and are unaffected. Surfaces stay opaque: no vibrancy and no
private macOS API.

### Scroll ownership

The document and app frame stay within the viewport. The workspace owns page
scrolling; its header and status bar stay visible. The sidebar's middle region
scrolls independently when it does not fit. Result lists and assessment
controls flow with the page rather than adding vertical scroll boxes. Wide
tables retain horizontal scrolling; raw code/report previews and the
assistant's independent panes may retain bounded scrolling. Explicit result
activation reveals an offscreen detail without moving focus; arrow-key
selection keeps following the list row. Pagination returns the results
container to its beginning after the requested page has rendered.
Programmatic detail and page navigation scroll the workspace explicitly:
`overflow: hidden` does not prevent `scrollIntoView` from scrolling the
document. Tool navigation resets the workspace to the new page heading without
moving keyboard focus. Positioned frame and scroll containers also contain
absolute screen-reader labels, so clipped navigation or long result rows cannot
enlarge the document.

**Source result ownership:** automatic context refreshes for the same run
preserve the displayed findings, selection, page, and unsaved review draft.
Explicit run selection and review save/retry still refresh the displayed data.

## 8. Page anatomy

`ToolPage` (`src/components/workbench/ToolPage.tsx`): 24px padding (16px
below 768px), an 18px semibold `h1` with a one-line secondary description and
right-aligned actions, then the page's content on a 16px rhythm; the page
fades in. Content is a stack of `surface-card`s:

- the target bar (`TargetBar`) and every page panel are cards;
- a results card holds its tabs and `ResultsToolbar` strip, then a
  `SplitWorkspace`: a list column of card rows (`listRowClassName`: bordered,
  8px, the selected row on `border-focus` and `surface-active`) beside a
  detail card;
- empty and idle states are a centred card with a 48px icon circle; running,
  error and unavailable states are a card with a 3px left status stripe.

The Dashboard follows oxFuzz's composition: the header row, an active-project
bar (a card with a 3px left stripe: accent and "No project selected" with
**Open project…** when nothing is selected, success with the project's name
and path once one is), then Project home, the tool launch cards and the AI
Assistant card.

**Page-level conventions** (every tool page, checked by eye against oxFuzz's
Triage, Run, Corpus and Dashboard views):

- Header row: the title and a one-line description on the left; actions on the
  right as small outline `Button`s with 13px icons, and exactly one `primary`.
- Controls: the target bar is the page's one input card. Everything else uses
  the shared primitives, never a native-looking element: `Input` / `Textarea`
  (36px), `Select` (36px; `compact` 28px in a toolbar), `Checkbox` (16px box with its
  label), `Switch`, `SearchField` (28px with a magnifier, always given an
  `aria-label`). Inline classes that restate a radius, height or border on a raw
  `<input>` are a defect.
- Summary numbers are `MetricTile`s in a `MetricGrid` (an auto-fit grid that
  wraps instead of squeezing; a labelled region). A tile says what was counted;
  `attention` is for counts that need action, never for a verdict. A count that
  was not evaluated is "unknown", not 0.
- Tables sit in a card, scroll horizontally inside it, and use an 11px
  uppercase muted header, hairline row borders and mono for hashes and paths.
- Tabs are oxFuzz's tab cards: a hairline under the row, the active tab on
  `surface-active` with a border and rounded top corners, the count in muted
  text. They keep `role="tablist"` / `tab`, roving `tabIndex` and arrow, Home
  and End keys.
- Radii: 8px for panels, notices, code boxes and controls; 4px only for badges
  and chips. Spacing: 16px between sections, 12px inside cards, 8px in toolbars.
- Type: 18px title, 13px body, 12px controls and secondary text, 11px labels
  and metadata, 10.5px uppercase section labels at `0.08em`.

Dialogs (`ReadinessWizard`, `ServerTokenGate`, the command palette) use one
recipe: a 40% black overlay blurred by 2px, a `surface-card` with `shadow-lg`,
and `animate-dialog-in`. The command palette is 560px wide at 12vh.

### Settings

Choosing Settings changes the shell, as in oxFuzz, without a second frame:

- **Sidebar.** While `page === "settings"` the scroll region holds a **Back**
  row (arrow-left, 16px) and one item per section instead of Open project,
  Recent and the tools. The brand row, the macOS spacer, the search hint and
  the version stay; the footer Settings item is hidden because you are in it.
  Items use the main navigation's style with 16px icons; the current section
  has `aria-current="true"`. The sections are in `src/lib/settingsSections.ts`:
  General (editor, theme), AI (engine, generation, allowed fetch hosts, usage),
  Scan defaults, Live scanning, Data sources, Binary scanner, Diagnostics,
  About (version, readiness setup). Below 900px the same list is the drawer and
  choosing a section or Back closes it.
- **State.** `settingsSection`, `settingsReturnPage`, `openSettings(section?)`
  and `closeSettings()` live in `useAppStore`. `setPage("settings")` from
  another page records where to go back to and keeps the last section;
  `openSettings("ai")` is the deep link ("Configure AI", the readiness wizard)
  and `openSettings("scan-defaults")` the scan-settings recovery button.
- **Header.** The title is the section's name in the display font, 17px, weight
  400, italic, and it is the page's `h1`. **Reset** and **Save** (primary) are
  header actions on its right, with "Unsaved changes" or the save result
  beside them.
- **Pane.** Each section is a scrolling pane of `SettingsGroup`s: an uppercase
  11px title, an optional 12px description, then a bordered card of
  `SettingsItem` rows (minimum 44px, label and description left, control right,
  hairline between). `stacked` puts a wide control (a textarea, a path, the key
  field) beneath its label. A row given `htmlFor` also describes its control
  with its description and, given an `error`, marks it `aria-invalid` and
  announces the message, as `Field` does. Controls are right-aligned at fixed
  widths: selects 240px, numbers 112px, the theme a three-way segmented control.
- **Drafts.** One draft spans every section, so unsaved edits survive a section
  change and Save writes them all. Leaving Settings (Back, the palette, any
  link) discards them silently, as before; the header's "Unsaved changes"
  marker is the only warning. The theme is not part of the draft: it saves as
  soon as it is chosen.

### Assistant

The AI Assistant follows oxFuzz's `ChatView`. It is not a `ToolPage`: it fills
the workspace edge to edge, and its `h1` is the shell header's title
(`SHELL_HEADING_PAGES`).

```
div (relative, h-full)
  section "Assistant conversation"     one full-width column
    ChatSearchToolbar                  while searching
    messages                           the only scroller, 16px gutters
    composer wrapper                   8px 16px 16px: notices, queued steers,
                                       slash menu, composer card, helper line
  AssistantPanelDock                   320px, right, at most one panel
    aside "Chat sessions" | aside "Assistant activity"
```

- **Header toggles.** The page registers **Search conversation**,
  **Conversations** and **Activity** with `useHeaderActions("assistant", …)`.
  The panels are mutually exclusive and closed by default; the open one is
  remembered (`oxaudit.panel.assistant.v1`). Docked, a panel is oxFuzz's
  `PanelShell`: 320px, `surface-secondary`, left hairline, `animate-fade-in`.
  Below 1100px (`ASSISTANT_DRAWER_QUERY`) it is a drawer over the conversation:
  a blurred backdrop, focus moved in, Escape and a close button in the panel,
  the conversation inert meanwhile, and focus returned on close. A remembered
  panel never reopens as a drawer. A failed conversation load opens
  Conversations, where Retry lives.
- **Welcome.** An empty conversation shows the mark at 84px with an
  `accent-glow` drop shadow, "Welcome to oxAudit" (display font, 22px, 500,
  italic), a two-line tagline, the conversation's project selector (bordered
  260px trigger, recent projects from `api.listSourceProjects`, then Browse on
  the desktop or a typed server path in server mode) and outline `sm` chips
  that fill the composer without sending. A session's project is fixed at
  creation, so choosing one starts the conversation in it (the replaced empty,
  auto-titled conversation is deleted) through the runtime-project coordinator.
- **Messages.** The person's turns: right-aligned, at most 80% wide,
  `accent-subtle` with a hairline, 12px radius, 8px 16px padding, the time
  inside at 10px. The assistant's: a 28px round avatar (`surface-active`,
  hairline, the mark in accent) beside a column, at most 80%, holding tool
  chips, the thinking chip, the answer card (`surface-secondary`, hairline,
  12px radius, 8px 16px) and its time. Rows enter with `animate-slide-in-up`.
  What is not model prose keeps its own shape: tool calls are `surface-code`
  chips with an 8px radius; attached source context is a right-aligned
  `surface-code` card titled "User-attached source context"; compaction is a
  dashed divider card; approvals and questions are dialogs. Rewind is a small
  icon button revealed beside the person's bubble.
- **Markdown** (`.md-body`): paragraphs and lists with 0.5em after, headings
  demoted to 1.1/1.05/1em, a 3px quote rule, inline code as a `surface-active`
  chip, code blocks on `surface-active` with a hairline and 6px radius at
  12px, and tables with a tinted header that scroll sideways rather than
  crushing their columns. Answers and the CVE briefing parse GitHub-flavoured
  markdown (`remark-gfm`): pipe tables, strikethrough, inert task-list
  checkboxes and bare-URL autolinks. Raw HTML stays disabled and every link,
  autolinks included, still passes `safeMarkdownHref` (http, https, mailto).
- **Composer.** `rounded-composer` (16px) on `surface-secondary` with a
  hairline, padding 10px 12px 8px; the card, not the borderless textarea,
  shows focus: a 1px accent border and a soft `accent-glow` shadow, no ring
  (a transparent outline keeps it visible in forced-colours mode). Toolbar
  buttons inside keep the global ring. Top: the conversation's project as a mono chip
  (removable only while the conversation is empty). Middle: the textarea, auto-growing
  per `composerLayout` (76px at rest, up to 40% of the window; expanded 200px
  to 50%). Toolbar, left: the Auto / Plan & act pills, Context, and Clear when
  there is something to clear. Right: expand, usage and the context meter
  (shown by the composer's own width, container queries), the model or the
  readiness label with its dot, and the 30px round button: send (accent once
  there is text), or stop plus steer while a turn runs. Below: the Enter hint
  and "Project reads run without asking; other tools ask for approval".
- **Plan & act** prefixes `PLAN_PREFIX` to the model's copy of a new message
  only (`applyMode`). The transcript, the session file, rewind, search, steers,
  a declined steer re-sent as its own turn, and attached context keep the typed
  text. The choice is remembered (`oxaudit.assistant.mode.v1`).
- **Notices.** Readiness (`unconfigured`, `offline`, `unsupported`, …) and an
  unavailable project are `AssistantNotice`s above the composer: a flat card
  with a 3px stripe, title, explanation and, where it helps, Open Settings.
  Offline, unavailable readiness and the server build are alerts.
- **Dialogs.** Tool approval, the AI's questions, rewind and context review
  use the dialog recipe above (`dialogRecipe.ts`): title with a right-aligned
  countdown, the requested tool as a code chip, outline Deny/Skip/Cancel
  focused first, then the primary action.

## 9. Component primitives

`src/components/ui/` and `src/components/workbench/`.

| Primitive | Shape |
|---|---|
| `Button` | `primary` `accent` `ghost` `danger` `warning` `outline` `icon` × `sm` (28px) `md` (32px), 8px radius |
| `Input` / `Textarea` | shared `fieldClassName`: 36px minimum height, 8px radius, primary surface, `control-border` at rest, one hover, the global focus ring |
| `Select` | a native `<select>` with `appearance: none` and a 14px `ChevronDown` in a wrapper; `field` (36px) / `compact` (results toolbar, 28px). Width, margin and display utilities passed in `className` move to the wrapper |
| `Switch` | 36×20 pill, 14px knob, native `role="switch"` checkbox; `hideLabel` keeps the name for assistive tech when the row shows the title |
| `Checkbox` | native checkbox, 16px box, accent when checked, label to its right |
| `SearchField` | 28px toolbar search with a leading magnifier |
| Segmented controls (theme, Template Scan mode) | 36px, `control-border`, 3px inset, 28px segments with the `sm` radius, accent when selected |
| `SectionLabel` | 10.5px uppercase label |
| `SettingsGroup` / `SettingsItem` | uppercase group title above a bordered card of 44px rows, label left and control right, hairline separators, `stacked` for wide controls |
| `MetricTile` / `MetricGrid` | card with a 32px icon chip, label, value and detail (`attention` for counts that need action); the grid is an auto-fit, labelled region |
| `SeverityBadge` | severity tint on a 4px pill with a dot |
| `HeaderToggle` | 32px header icon button, `pressed` state |
| `ToolPage`, `TargetBar`, `TargetInput`, `ResultsToolbar`, `ResultPagination`, `SplitWorkspace`, `InlineState`, `ToolLaunchCard` | page anatomy above |

Every primitive in the barrel is in use. Unadopted primitives are deleted rather
than shipped dead.

**Not yet adopted:** the bespoke fields in `SessionSidebar`, `AskUserModal` and
`FolderPicker` still carry inline classes. They are token-correct but have not
been routed through `Input`/`Select`.

---

## 10. What the contract test enforces

`npm test` fails on any of these:

1. Radius tokens are exactly `--radius-sm: 4px`, `--radius-md: 8px`,
   `--radius-lg: 12px` and `--radius-composer: 16px`, and no other.
2. No `rounded-xl`/`2xl`/`3xl` anywhere in `src/`; `rounded-composer` only in
   the Assistant page and `src/components/chat/`.
3. `surface-card` is the primary surface, a 1px `border` hairline, the 12px
   radius and `elevation-sm`.
4. No gradients.
5. No `shadow-xl`/`shadow-2xl`.
6. `body` at zero letter-spacing, no negative tracking in the stylesheet.
7. No raw Tailwind palette color in any `.tsx` (reports `file:line`).
8. Every dark token has a light counterpart.
9. No dead token: each is either aliased into Tailwind or used by a rule.
10. **No hover state resolving to its own base color.** Collapsing a palette
    onto semantic tokens once silently mapped 26 buttons' hover and base onto
    the same value, leaving them with no feedback.

`tests/themeContrast.test.ts` holds every text, accent, semantic and severity
colour at 4.5:1 on all three surfaces (and on their own tinted badge fill),
button text at 4.5:1 on the accent and its hover, and editable control borders
at 3:1, in both themes. `tests/navigation.test.ts` keeps the sidebar, page
groups and command palette in agreement.

## 11. Departures from oxFuzz

- **Light-theme accent and semantic colours.** oxFuzz's light accent `#9a7c2a`
  and its light success, warning, error and info fall below 4.5:1 as text on
  the tertiary surface, so oxAudit keeps `#7b601e` and its darker semantic set.
  Dark-theme values are oxFuzz's, and its lighter dark muted and secondary text
  pass.
- **Editable field borders** use `control-border` (3:1 on every surface, WCAG
  1.4.11) instead of oxFuzz's hairline. Inputs, textareas, selects, the search
  field and the segmented controls share it, one hover (the border steps to
  `text-muted`) and the same focus treatment.
- **Letter-spacing stays 0.** oxFuzz tightens body text by `-0.01em`; at 13px
  on system fonts the difference is not visible and the contract forbids
  negative tracking.
- **Focus ring keeps the element's radius** rather than forcing 4px, so it
  follows 12px cards and round switches.
- **`danger` buttons are tinted**, not solid red, because they sit next to
  severity badges in dense result views; `accent` and `warning` variants are
  oxAudit's own.
- **The switch knob** is `text-secondary` off and `accent-contrast` on, rather
  than always white, so it stays visible on the light theme's tertiary track.
- **No vibrancy.** oxFuzz's frosted macOS sidebar needs the private
  `macOSPrivateApi` window effect; oxAudit keeps opaque surfaces.
- **The sidebar's top spacer appears only on the macOS desktop**; oxFuzz
  renders it on every host.
- **Severity badges keep a dot** beside the label, oxAudit's own signal.
