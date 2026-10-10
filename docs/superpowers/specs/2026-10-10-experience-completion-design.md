# Complete the remaining experience improvements

## Intended outcome

The user approved all four remaining experience areas and the two maintenance
items: target selection, progress, large saved-result loading, broader usability
validation, dependency automation and release documentation. The earlier scan
reliability and evidence-summary work remains the foundation. Delivery includes
verification, a human-authored commit and a push to `main`.

## Constraints

- Keep Rust/Tauri and the headless HTTP transport consistent on all platforms.
- Preserve operation ownership, exact scoped cancellation and stale-request guards.
- Selecting, typing or browsing a target never starts a scan automatically.
- Preserve saved receipt identity, status, warnings, evidence, review and export.
- Never present a page of findings as a complete export or a complete result set.
- Keep original complete-result APIs for exports and explicit whole-run operations.
- Use bounded database reads for ordinary browsing of saved results.
- Show only observed progress; do not invent percentages, counts or ETA.
- Do not publish releases, retag versions, alter repository visibility or delete drafts.
- Do not invent external pilot observations or claim comprehensive WCAG compliance.

## Design

### Target controls

A shared input provides a visible label, associated instructions, explicitly
supported file/folder pickers, accessible picker errors and wrapping actions.
Source, Dependencies and History select folders. Binary accepts files or folders.
Image accepts saved archives, OCI folders or a typed registry reference. In server
mode native pickers disappear and instructions identify the server filesystem.
The existing FolderPicker contract remains supported. Start remains a distinct
action. Paths and modes continue to be validated by the existing backend.

### Progress

A shared observed-stage view consumes operation-scoped canonical events. It
accepts supported schema versions, known stages and increasing event sequence
numbers, ignores other operations and resets for a new operation. Native progress
messages and valid phase-specific counters supplement stages. A lack of events
means progress is not yet available. Old saved evidence stays visible and clearly
distinct from the latest attempt. Source string phases and binary lifecycle events
must pass through the same ownership tagging as other scan kinds.

### Saved-result pagination

Add metadata and page APIs; leave existing complete APIs intact. Metadata has a
distinct type, without the source findings collection. Canonical metadata is
explicitly marked as a paged projection with section counts. Source page queries
retain review precedence/expiry, scope, diff and coverage semantics, global view
counts and supported filtering/sorting. Canonical sections retain original row
payloads, order, summaries and related history evidence.

Normalize canonical list rows and small headers transactionally on save, with
idempotent legacy backfill. Use SQL filtering, counts, stable ordering and
LIMIT/OFFSET before deserializing requested row payloads. Bound page size to 200.
Count and page observe a consistent database snapshot. Preserve complete exports,
baseline comparison and upgrade decisions; whole-run loading, when required for
an explicit operation, must be visible rather than an implicit restore cost.

### Maintenance

Keep keyring 3.x's tested native platform backends. Its incompatible 4.x major
requires a separate persistence migration. Ignore only that automatic major
upgrade, group compatible npm/Cargo minor and patch updates, and allow unrelated
major updates to be reviewed individually. Document the migration boundary.
Replace the obsolete visibility/first-release instructions with dated observations
of the public repository, published release assets, current workflow capabilities
and the duplicate draft awaiting owner review.

### Usability and pilot evidence

Check both theme palettes against actual normal-text and component contrast
requirements, fix measured failures and preserve visible focus. Exercise changed
flows with keyboard and real browser layout at narrow and desktop sizes, including
200% zoom/reflow where supported. Inspect accessible names, roles, errors and live
updates. Record the exact assistive-technology scope actually exercised.
Run the prepared pilot smoke on the final CLI. Provide a reproducible acceptance
matrix and a ready external participant form; external acceptance remains pending
until a person supplies genuine observations.

## Acceptance

Meaningful RED/GREEN tests cover selection without submission, picker errors,
ownership/sequence progress guards, bounded SQL reads, legacy compatibility,
source review/diff parity, filtering and stale page requests. Complete Rust and
frontend checks, appropriate reduced-feature builds, actual CLI smoke, pinned
quality gates and hosted checks validate the integrated change. Browser artifacts
and resource observations record their own environment and limitations.
