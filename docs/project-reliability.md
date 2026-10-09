# Scan reliability and recovery

[Validation evidence and limits](project-reliability-validation.md) records the
automated checks, live lifecycle probes and measured workloads for this change.

The desktop and headless server share one process-local scan owner across source,
dependency, binary, image and Git-history work. Each operation has a fresh UUID
and cancellation token. An ID-scoped cancellation request cannot affect a later
operation. Scheduled scans wait until that process is available; separate CLI
processes have separate owners.
Operation IDs remain reserved for the process lifetime, including cancellation
that arrives before registration. The bounded bookkeeping allows one million
IDs; reaching that allowance requires restarting the process before new work.

The workbench reconciles backend status after reconnecting or missing event
frames, and while work remains active. Saved receipts are the authority for
results after navigation or restart. Image and history pages can reload those
receipts and send their run IDs to Export Center. A failed attempt remains a
failed attempt even if it collected some evidence.

Research source scans use the existing source service, project configuration,
enabled packs, policy and durable storage. A subdirectory keeps project-relative
paths and records coverage for that scope. Rechecking preserves the original
scope. Enabled packs that could not be applied remain visible in saved coverage
warnings. Malformed lockfiles show an unknown count and parser error; a parsed
empty inventory shows zero.

## Saved image and history receipts

CLI storage is explicit, matching the existing source/dependency commands:

```bash
oxaudit-cli image ./saved-image.tar --offline --db ./evidence.sqlite --format json
oxaudit-cli history ./project --db ./evidence.sqlite --format json
oxaudit-cli runs --db ./evidence.sqlite --kind image --json
oxaudit-cli runs --db ./evidence.sqlite --kind history --json
oxaudit-cli export --run RUN_ID --db ./evidence.sqlite --format sarif --output ./history.sarif
```

Without `--db`, a CLI run uses an in-memory repository for its report and is not
available to another invocation. A persistent database can be reopened without
reading the original target. Standards formats express only the evidence their
schemas support; image component inventories and historical secret findings
have different report contents.

Registry receipts retain the resolved manifest digest, verified layer digests,
actual layer sizes, effective offline option, query context, returned advisory
evidence and coverage notes. An offline component with no matched advisory is
inventory evidence; it does not establish that the component is safe.

Local image receipts record [bounded pre-scan identities](local-image-identity.md).
Full-file hashes, prefix-only hashes, OCI descriptor verification and unavailable
directory identities remain distinguishable. These observations do not prove
that a mutable local path remained unchanged during later native scanning.

Saved standard reports preserve canonical run state and coverage warnings.
SARIF records whether execution completed successfully; SBOM metadata retains
the receipt state. A completed operation may still have limited coverage.
Ticket CSV exports require completed runs because their importer format cannot
represent an empty partial attempt; other saved formats retain that attempt.

History receipts retain Git context, scanned blob IDs/content hashes and the
blob identities associated with each redacted finding. Canonical artifact paths
use `git:<object-id>!<repository-path>`, with no current filesystem location.
The scanner enumerates objects reachable from refs; dangling objects remain
outside coverage. It deduplicates the same credential across revisions and
retains the selected blob association for each finding. Live credential validation remains opt-in. Raw
credential values are never stored in the receipt.

## Resource and usability limits

Registry pulls enforce request/overall deadlines, cancellation and checked
actual byte limits. Layers are written to private temporary files, verified and
scanned one at a time. Native extraction streams members under a process-shared
payload allowance and retains coverage notes when budgets stop work. Its
precise limits and excluded allocations are documented in
[binary extraction reliability](binary-extraction-reliability.md).

Source reads stop at the configured byte allowance even if files grow. Source
workers aggregate bounded outcomes as they finish, enforcing the finding limit
before accepting later findings. The existing source resource-limit contract
returns an incomplete attempt when a finding budget is exceeded.

Source, dependency, binary and history lists render bounded pages. Source bulk
selection spans the filtered data, including records on other pages. Pagination
limits DOM work; complete result data and filtering still occupy frontend
memory. [Measured list interactions](result-list-performance-2026-10-09.json)
describe the jsdom method and its limits; browser paint and screen-reader
acceptance require a real pilot.

[Quality/performance validation](quality-performance-validation.md) describes
the pinned per-category external benchmark and owned CLI workload measurements.
[Pilot validation](pilot-validation.md) provides participant instructions and
validated feedback capture. Participant observations remain empty until real
feedback is supplied.
