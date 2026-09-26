# oxAudit mark v2 — the magnifier-x

Date: 2026-09-26
Supersedes: `oxaudit-geometric-ox-concept.md` (the v1 geometric ox, whose
fragmented silhouette read as an insect at small sizes).

## Concept

One glyph carries both the name and the job: the lens is the **O** of
oxAudit and the act of auditing; the **x** sits inside it and completes the
name. Gold `#C8B560` on the graphite `#151719` rounded tile, unchanged —
the palette is the app's own accent, so the mark stays glued to the
product.

## Construction

Four closed filled paths (no strokes), generated from
`src/components/brand/geometry.ts` via `npm run brand:generate`:

- `lens` — an annulus (outer r 146, inner r 90 around 232,226); the inner
  circle is counter-wound so a plain nonzero fill knocks it out.
- `handle` — a 58-wide capsule from (318,312) to (402,396), embedded in
  the ring at 45 degrees.
- `cross-first`, `cross-second` — 38-wide capsules crossing in the lens.

Verified legible at 16 px (favicon) through 1024 px (app icon source);
native icon sets regenerated with `tauri icon`. Candidate exploration,
including the runner-up directions (bull head, ox monogram, shield-x),
is kept in `design/logo/drafts/`.
