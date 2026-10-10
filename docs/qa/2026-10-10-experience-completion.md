# Experience completion checks — 2026-10-10

This records maintainer checks of the six approved experience and maintenance
refinements. External participant feedback is unavailable. The
[pilot workflow](../pilot-validation.md) is prepared; these observations do not
establish external acceptance.

## Saved results and target setup

All five scan workspaces share labelled target controls, server filesystem
guidance, explicit scan actions and owned progress. Selecting or typing a target
does not start a scan. Saved results initially request metadata and bounded SQL
pages. Complete exports and dependency upgrade decisions retain explicit full
report reads.

The [HTTP measurement receipt](../saved-result-paging-2026-10-10.json) records
10,000 inert Source findings and 1,000 Image components. Deep pages contain 50
rows. A Source search returns 100 matching findings while keeping the 10,000
global total. Response sizes and elapsed times are single loopback observations,
not stable performance budgets or browser memory measurements.

Real Chrome checks used an isolated loopback server, owned fixture database and
the built frontend. Viewport widths were 320, 768, 1,024 and 1,440 CSS pixels:

- Source: last page showed rows 9,951–10,000, page 200/200; filtering to
  `handler-099` showed 50 visible rows, 100 filtered results and 10,000 globally.
  **Copy JSON** from that filtered page returned all 10,000 saved findings and
  the matching summary total. The empty browser-session clipboard was restored.
- Image: last page showed rows 951–1,000, page 20/20, with 50 component rows.
  The evidence summary retained the offline advisory limitation.
- Dependencies: restored 2,000 queried packages and an empty synthetic advisory
  receipt. Enter on **Load complete upgrade decisions** loaded the complete
  inventory and showed zero groups with the original cache provenance.
- History: selecting the synthetic finding retained its Git blob identity,
  historical `app.js:2:16` location, redacted match and redacted related context.
- Binary: after the offline enforcement fix, the explicit archive scan retained
  1,000 components in 287 ms and reported unknown advisory coverage. The missing
  optional Docker image returned a stated failure without a pull. Saved deep
  paging showed rows 951–1,000, page 20/20; narrow controls fitted at 320 pixels.
- Mobile navigation: Enter opened the drawer and made the workspace inert;
  Escape closed it and restored focus to the opener. The skip link moved focus
  to the workspace. Keyboard Space changed binary scan switches.
- Source, dependency, image and history controls remained inside the checked
  viewports. Source view tabs wrap on narrow screens. Both Source themes were
  inspected. No browser warning or error was recorded during these checks.

Saved dependency/history/binary restoration compares normalized target strings.
An alternate filesystem alias, such as macOS `/var` versus `/private/var`, may
require the recorded canonical path to restore the same receipt. This check
does not establish arbitrary symlink equivalence.

## Readability and evidence

Independent luminance tests check normal text against theme surfaces and badge
fills at 4.5:1, and input boundaries at 3:1. Measured failures led to palette and
input-border changes. Meaningful regressions cover focus restoration, delayed
native picker results, stale page/run responses, complete redacted exports,
review/diff parity and malformed progress events.

These checks do not constitute a complete WCAG audit. Native desktop bundles,
200% browser zoom, VoiceOver/screen-reader output and external participant
acceptance were not tested in this pass.

## Final automated verification

- Frontend: 173 Node tests and 358 Vitest tests passed; production build passed.
- Rust: 1,389 workspace/all-feature tests passed, with one existing ignored test.
  Strict all-target Clippy and formatting checks passed.
- Offline regression: the native available-client network trap recorded zero
  offline connections; the positive online control reached both OSV and NVD
  through that trap. An executable Grype fixture retained its cached CVE and
  database date while verifying the five documented offline overrides. Docker
  prepared-command tests require both disabled networking and no image pulls.
- Fresh authored corpus, pinned external category gates, CLI pilot and saved
  HTTP population checks passed using the preserved final binaries.
- Reduced builds without grammars and with core grammars passed. The real CLI
  consumer shell checks passed 10/10 with none skipped.
- Independent review found no unresolved validated findings after fixes.

## Retained artifacts

- [Source desktop, dark](assets/source-paging-desktop-dark-2026-10-10.png)
- [Source narrow, dark](assets/source-filter-narrow-dark-2026-10-10.png)
- [Source narrow, light](assets/source-filter-narrow-light-2026-10-10.png)
- [Image saved receipt, light](assets/image-saved-light-2026-10-10.png)
- [Binary offline receipt, light](assets/binary-offline-light-2026-10-10.png)
- [Binary offline metadata and warnings](binary-offline-2026-10-10.json)
- [CLI pilot receipt](experience-pilot-2026-10-10.json)
- [Owned workload receipt](../../benchmarks/performance/experience-debug-2026-10-10.json)
- [Pinned external quality result](../../benchmarks/results/experience-2026-10-10.json)

Receipts identify the exact measured binary checksum and pre-commit working-tree
provenance. The workload receipt uses synthetic complete empty dependency
queries; it does not measure real advisory accuracy. The pinned corpus contains
2,740 labelled cases across 11 categories. The authored corpus contains 234
cases.

## Maintenance

[Dependency maintenance](../dependency-maintenance.md) explains compatible
minor/patch groups and the keyring 3.x boundary. Major-only security fixes need
explicit migration review. The [release checklist](../release-checklist.md)
records actual published assets separately from configured future outputs.
No release, tag, repository visibility or draft was changed.
