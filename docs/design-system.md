# oxAudit Design System

The visual language is deliberately aligned with
[y-agent](https://github.com/gorgiaxx/y-agent)'s `y-gui` shell so the two products
read as one family. This document is the contract; the enforcement lives in
[`tests/designSystem.test.ts`](../tests/designSystem.test.ts).

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
border           border-strong  border-focus
sev-critical / -high / -medium / -low / -info / -unknown   (each with -subtle and -border)
```

`sev-*` is oxAudit's own axis and has no y-agent counterpart — it is shaped like
the semantic triplets but carries **five distinguishable steps**, because badge-size
severity is the primary signal in a scanner UI. It is consumed only through
`severityColor()` / `severityDot()` in `src/lib/format.ts`; never inline it.

### Usage discipline

- `text-primary` — interactive control labels, headings, body copy that matters.
- `text-secondary` — supporting copy, ghost-button labels.
- `text-muted` — metadata, descriptions, icon glyphs at rest, placeholder text.
- **Accent is used sparingly.** It marks the active nav item's icon, links, and
  exactly one primary action per view. A full-width solid accent block is a smell.

---

## 2. Radius: two steps, no third

| Token | Value | Applies to |
|---|---|---|
| `rounded-sm` | 4px | every control, card, panel, badge, list row |
| `rounded-md` | 8px | overlays only — modals and toasts |

There is no `--radius-lg`. `rounded-lg`/`xl`/`2xl`/`3xl` fail the contract test.

## 3. Elevation

Only `shadow-sm` / `shadow-md` / `shadow-lg`, mapped to `--elevation-*` so they
darken correctly per theme. `shadow-xl`/`shadow-2xl` fail the contract test.
`shadow-lg` is reserved for modals; `shadow-md` for toasts and popovers.

## 4. Type

Body is 13px at zero letter-spacing. Sizes are written as explicit px
(`text-[12px]`), matching y-agent's px-based scale rather than a rem ramp.

Font stacks mirror y-agent's — with **one deliberate deviation**: y-agent
`@import`s Inter and Instrument Serif from Google Fonts. oxAudit does not.
The README states network calls go only to NVD, OSV, and the configured AI
endpoint, and a remote font fetch would break that. The stacks degrade to the
same system faces (`-apple-system`, `SF Pro Display`, `SF Mono`).

## 5. Theming

`settings.theme` holds `"dark" | "light" | "system"`. Resolution is pure logic in
`src/lib/theme.ts`; `src/lib/useTheme.ts` binds it to `<html data-theme>`.
`src/main.tsx` applies the cached preference before React mounts so a light-theme
user never sees a dark flash.

Theme is a **live preference, not a draft field**. Both the header toggle and the
Settings → Appearance control write immediately via
`savePersistedThemePreference()`, which joins the same serialized write queue as a
full settings save but **skips the AI connection test** — flipping the theme must
not touch the network. Settings mirrors the value into its draft so `dirty` never
reports a phantom diff and a later Save cannot revert the theme.

## 6. Shell

- **Sidebar** (240px, `surface-secondary`): Finder/Notes-style. 10px uppercase
  `0.08em` section headers, 13px/500 items on 4px radius, 18px icon slot.
  Active = `surface-active` + border, with the icon in `accent`. Hover =
  `accent-subtle`. Settings is pinned in a bordered footer.
- **Header** (52px): app title in `font-display` italic, then the breadcrumb,
  then 32×32 header action buttons on the right.
- **Status bar** (28px): page status dot, AI readiness, version.

## 7. Component primitives

`src/components/ui/` — the barrel holds only what is actually used; unadopted
primitives are deleted rather than shipped dead.

| Primitive | Variants |
|---|---|
| `Button` | `primary` `accent` `ghost` `danger` `warning` `outline` `icon` × `sm` `md` |
| `Input` / `Textarea` | shared `fieldClassName` chrome |
| `Select` | `field` (form) / `compact` (results toolbar) |
| `Switch` | — |
| `SectionLabel` | — |

Two `Button` variants deviate from y-agent: `danger` is tinted rather than solid
(a solid red block would outshout the severity badges next to it in a results
table), and `accent` is new (the subtle-tinted "Ask AI" hand-off affordance).

**Not yet adopted:** the bespoke fields in `SessionSidebar`, `AskUserModal`,
`FolderPicker`, `CveResearch` and `DepsScan` still carry inline classes. They are
token-correct but have not been routed through `Input`/`Select`; each needs a
per-site look at its icon padding and sizing.

---

## 8. What the contract test enforces

`npm test` fails on any of these:

1. `--radius-sm: 4px` / `--radius-md: 8px` present, no `--radius-lg`.
2. No `rounded-lg`/`xl`/`2xl`/`3xl` anywhere in `src/`.
3. No gradients.
4. No `shadow-xl`/`shadow-2xl`.
5. `body` at zero letter-spacing, no negative tracking anywhere.
6. No raw Tailwind palette color in any `.tsx` (reports `file:line`).
7. Every dark token has a light counterpart.
8. No dead token — each is either aliased into Tailwind or used by a rule.
9. **No hover state resolving to its own base color.** This one is a real
   regression guard: collapsing a palette onto semantic tokens silently mapped 26
   buttons' hover and base onto the same value, leaving them with no feedback.
