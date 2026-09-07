# oxAudit brand assets

The geometric ox pairs broad, bracket-like horns with a compact central face.
The horns recall code delimiters; the quiet, symmetrical silhouette suits a
local engineering audit workbench and remains recognizable at small sizes.

`src/components/brand/geometry.ts` is the shared source for the React mark and
all six standalone SVGs. Regenerate them with `npm run brand:generate`.

- `oxaudit-mark.svg`: transparent gold symbol.
- `oxaudit-lockup.svg`: gold mark and wordmark for a dark background.
- `oxaudit-app-icon-v1.svg`: native icon master, with a graphite rounded tile
  and transparent outer margins. The filename is retained for compatibility.
- `design/logo/ox-mark.svg`, `design/logo/ox-icon.svg` and `public/favicon.svg`
  are generated from the same geometry.

Use warm gold `#C8B560` on graphite `#151719`. The inline React mark inherits
the existing theme accent, including `#9A7C2A` on light backgrounds. Keep the
mark's square viewBox and internal spacing; do not stretch or rotate it.
Use the tile version for standalone icons. Avoid additional outlines, gradients,
shadows or details that weaken its silhouette at 16–32 px.

Generate platform icon sizes with the installed Tauri CLI from the SVG master:

```sh
npm run tauri -- icon src/assets/brand/oxaudit-app-icon-v1.svg --output src-tauri/icons
```

The desktop app consumes the PNG, ICNS and ICO files in `src-tauri/icons`.
The generated concept in `design/brand/concepts/oxaudit-geometric-ox-concept.png`
is reference material, not a runtime dependency. It was created with the built-in
image-generation tool; the production vector is a simplified reconstruction.
The concept brief and generation prompt are recorded beside that reference.
