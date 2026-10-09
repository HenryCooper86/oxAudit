# Quality and performance validation

The internal corpus remains a regression test authored with the rules. The
scheduled [benchmark workflow](../.github/workflows/quality-benchmarks.yml)
adds independently labelled OWASP Java cases and separately records owned local
CLI performance workloads. These checks do not establish external usability
acceptance; participant observations belong in the [pilot protocol](pilot-validation.md).

## Pinned external quality

The workflow runs weekly on Sunday at 03:23 UTC and supports manual dispatch.
It fetches OWASP BenchmarkJava commit
`550021e915c06cbcf994d97bc258128b78d890db`, builds oxAudit's release CLI,
and reads the source without building, installing or executing OWASP.
The external source is ignored by Git and is not redistributed in this project.

To reproduce with an already built CLI:

```bash
node tools/fetch-external-benchmark.mjs
node tools/record-quality-benchmark.mjs \
  --cli ./src-tauri/target/release/oxaudit-cli \
  --corpus benchmarks/external/owasp-benchmark --output /tmp/oxaudit-quality
node tools/compare-quality-benchmark.mjs \
  --result /tmp/oxaudit-quality/result.json \
  --baseline benchmarks/baselines/owasp-java-550021e9.json \
  --output /tmp/oxaudit-quality-comparison
```

Use new recording and comparison directories; existing directories are refused
to prevent silent reuse of previous receipts. The recorder verifies the corpus HEAD and clean
working tree, records the expected-results SHA-256, exact CLI SHA-256, tool commit,
working-tree dirty flag and measurement date. It retains the raw CLI JSON and
command elapsed time/RSS/error output. The comparator requires the same suite,
pin, ground-truth hash, evaluator, category set, CWE and vulnerable/safe
populations. A changed fixture or evaluator needs a reviewed new baseline.

Each category gets a retained JSON artifact with its confusion matrix,
vulnerable/safe population, coverage flags, metrics, deltas and gate outcomes.
Aggregate totals are checked against the category sums. Summary JSON explicitly
separates all, covered, uncovered and baseline-covered case populations. Added
rule coverage is reported separately; it cannot silently change the population
used for the previous baseline's covered metrics. Lost rule coverage fails.

The committed baseline is an actual fresh pinned measurement with provenance,
not a number copied from an older README. Thresholds are absolute differences
in rates, applied separately to every previously covered category:

| Metric | Maximum permitted deterioration |
| --- | --- |
| Precision | 0.005 (0.5 percentage points) |
| Recall | 0.005 (0.5 percentage points) |
| False positive rate | increase of 0.005 |
| Youden index (recall minus false positive rate) | decrease of 0.01 |

Undefined metrics are stored as `null`. A metric that becomes undefined after
being defined fails, so suppressing every finding cannot erase a precision
regression. Previously undefined metrics cannot support a numeric comparison;
recall, false positive rate and coverage still apply where defined. Comparison
exits 0 on pass, 1 on regression, and 2 on incompatible/invalid evidence.

Coverage means that a Java rule exists for the category, not that analysis is
complete. Several categories in the measured baseline flag most or all safe
cases; their false positive rates and Youden scores remain visible. Improving one
category cannot hide another category's regression. This scanner is not a full
interprocedural taint analyzer, and the internal corpus's perfect score does not
describe OWASP performance.

Workflow artifacts retain raw JSON, provenance, command receipts, the per-category
comparisons and local performance JSON for 90 days, including a comparison that
fails. Build or fetch failure remains a failed job; missing artifacts are not
evidence of success. The first hosted run passed on 2026-10-09: [Quality and performance benchmarks](https://github.com/HenryCooper86/oxAudit/actions/runs/37938034829).
Each later revision still needs its own successful run.

## Owned CLI performance workloads

Node 22.22.2 or newer in the 22 series supplies the SQLite seed capability used by
the dependency fixture. Use a built CLI; the tool does not acquire or rebuild it:

```bash
node tools/cli-performance.mjs --cli ./src-tauri/target/debug/oxaudit-cli \
  --output /tmp/oxaudit-performance.json
# Retain only the tool's copied/generated workspace for manual inspection:
node tools/cli-performance.mjs --cli ./src-tauri/target/debug/oxaudit-cli \
  --output /tmp/oxaudit-performance-retained.json --keep
```

On Windows, use the `.exe` path. The tool creates and removes its own temporary
workspace; `--keep` preserves it. Inputs are deterministic text/tar recipes in
[workloads.json](../benchmarks/performance/workloads.json), with per-workload
content hashes. No scanned code, fixture scripts, package installation, Docker
daemon, registry pull, or public advisory service is required.

| Workload | Population and required evidence |
| --- | --- |
| Source/findings | 128 JavaScript files, 16 planted `js-eval` calls each; all files covered and 2,048 findings retained |
| Nested archive | Two tar levels with Debian metadata and 1,000 generated package records; all package identities retained |
| Saved image | A local Docker-save-shaped tar with one layer and 1,000 package records; all identities retained |
| Dependency cache | One npm lockfile, 2,000 distinct package queries; validated synthetic empty OSV receipt reused offline |

The dependency receipt is deliberately synthetic, lives only in the owned test
database and makes no provider accuracy claim. Native workloads measure inventory
only; zero vulnerabilities there cannot imply clean advisory coverage. Source
optional enrichment is refused by a loopback proxy. Both cases retain actual
coverage evidence and cannot pass by returning a fast empty report.

Each workload starts a fresh CLI process and measures wall time around launch
through exit, including startup, database/report writes and refused enrichment
attempts. Linux `/usr/bin/time -v` reports maximum RSS in KiB, converted to bytes;
macOS `/usr/bin/time -l` reports bytes. Missing or unsupported memory capability,
including Windows, is an explicit `null` with a reason. RSS is the command's
resource usage, not aggregate simultaneously resident process-tree memory.
Measurements have bounded output and a deadline; Unix timeout kills the owned
process group. The proxy never forwards HTTP or CONNECT, clears child NO_PROXY
bypasses and leaves the parent's environment unchanged. This is the supplied
CLI's proxy boundary, not an OS network sandbox for arbitrary programs.

Receipts record CLI checksum/version, platform/architecture/OS/CPU/Node, fixture
hashes, populations, elapsed time, RSS capability, report paths, stderr, refused
requests and observed counts. One run yields single observations, not stable
performance budgets. Compare repeated runs on the same machine, build profile,
fixture version and coverage before setting a performance threshold. Do not gate
Ubuntu release performance against a macOS debug sample. Registry pull memory,
provider latency, real advisory matching, desktop rendering and process-tree
memory remain unmeasured by this tool.

Portable contracts run as part of `npm test`; they exercise process spawning,
RSS unit conversion/unknown capability, timeout, isolated cleanup, malformed
receipts, exact category populations and participant-data validation. The
existing consumer workflow Bash/jq contracts remain separate.

The retained [2026-10-09 local receipt](../benchmarks/performance/local-debug-2026-10-09.json)
records the final macOS arm64 debug CLI with default grammars and the server
feature, identified by SHA-256. Its owned paths are replaced by placeholders;
the four workloads passed their population and identity checks. This single
sample observed:

| Workload | Elapsed | Maximum RSS |
| --- | --- | --- |
| Source/findings | 956.842 ms | 112,427,008 bytes |
| Nested archive | 275.537 ms | 41,959,424 bytes |
| Saved image | 274.313 ms | 42,270,720 bytes |
| Dependency cache | 220.872 ms | 45,154,304 bytes |

These measurements include the final image identity and durable receipt work.
They remain local observations, with no cross-host or release-profile budget.
