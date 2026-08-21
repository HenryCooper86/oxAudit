# oxAudit Durable Scan Foundation QA

Date: 2026-08-21

Status: Passed

## Candidate and environment

- Tested base commit: `73c900d113bd3ce1c32afb5b2f0000ddfc45fe31`.
- Tested candidate: that commit plus the Task 11 restart/canary integration test and this verification record.
- Host: macOS 26.6.1, Apple silicon (`Darwin arm64`).
- Rust: `rustc 1.97.1`, `cargo 1.97.1`.
- Frontend runtime: Node.js `v22.22.2`, npm `12.0.1`.
- Disposable database: a test-owned temporary app-data root using the authoritative relative location `findings/findings.sqlite3`. The temporary root is destroyed after the test; no transient absolute path is reusable.
- Canary identifier: `restart-github-pat-canary`, a synthetic GitHub-PAT-shaped value. Its raw value is intentionally omitted.

## Required verification matrix

| Command | Exit | Evidence |
|---|---:|---|
| `cargo test --manifest-path src-tauri/Cargo.toml redaction` | 0 | 5 passed, 0 failed, 0 ignored; 488 filtered out. |
| `cargo test --manifest-path src-tauri/Cargo.toml fingerprint` | 0 | 11 passed, 0 failed, 0 ignored; 482 filtered out. |
| `cargo test --manifest-path src-tauri/Cargo.toml policy` | 0 | 92 passed, 0 failed, 0 ignored; 401 filtered out. |
| `cargo test --manifest-path src-tauri/Cargo.toml findings::service::tests::file_database_survives_restart_and_contains_no_secret_canary -- --exact --nocapture` | 0 | 1 passed, 0 failed; the real file database reopened successfully. |
| `npm test` | 0 | 62 passed, 0 failed. |
| `npm run check` | 0 | TypeScript completed with no diagnostics. |
| `npm run build` | 0 | Production build completed; Vite transformed 1,798 modules. |
| `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` | 0 | No formatting differences. |
| `cargo test --manifest-path src-tauri/Cargo.toml` | 0 | 492 passed, 0 failed, 1 ignored. The ignored live OSV test is the established compiled-binary outbound-network fixture. |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets` | 0 | 20 library warnings and 32 library-test warnings, including 20 duplicates. No warning remains in `findings`, scope/manifest, or modified Source Scan command code. The unchanged cast warning in `scanners/mod.rs` predates the foundation base. |
| `git diff --check` | 0 | No whitespace errors. |

## Restart, schema, fingerprint, and redaction evidence

The Task 11 integration test performs a real sanitized service scan, closes the service and repository, reopens the file database, and loads the same completed run. It confirms that:

- `schema_migrations`, `projects`, `scan_runs`, `findings`, and `reviews` exist through `sqlite_master`;
- the sanitized secret finding remains present after restart;
- the stable fingerprint is nonempty and unchanged after restart;
- the frontend-facing saved and restarted DTOs contain no raw canary;
- every column discovered through `PRAGMA table_info` for all five logical tables is searched with a parameterized canary query, and no persisted value matches;
- the redaction marker remains visible in sanitized evidence.

The test was characterization-green on the existing production boundary. To prove the absence assertion was live, the database probe was temporarily changed to search for the known persisted redaction marker. The exact test then failed with exit 101 at `findings.payload_json` and a count of one. Restoring the raw-canary parameter returned the exact test to 1 passed. No production code was changed for this mutation check, and no raw canary was printed.

## Foundation completion gate

| Gate | Direct evidence | Result |
|---|---|---|
| Sanitized completed scan survives a real restart | Task 11 exact file-database test: 1 passed; schema, reloaded run, sanitized evidence, and fingerprint verified after all service/repository handles were closed. | Pass |
| Line insertion preserves finding identity | Exact `file_database_scan_survives_restart_and_line_insertion_is_unchanged`: 1 passed. The fingerprint-filtered suite also passed 11 tests. | Pass |
| Disabled or failed coverage cannot create a resolved finding | `findings::coverage`: 3 passed; `run_comparison`: 4 passed, including disabled coverage, unreadable/missing paths, incomplete runs, and incompatible versions. | Pass |
| Every non-production candidate remains queryable | `triage::scope`: 12 passed, covering test, fixture, generated, vendored, documentation, and unknown classification. Full repository/comparison tests passed without scope filtering of stored observations. | Pass |
| Review and policy validation pass | `findings::review`: 24 passed; policy-filtered suite: 92 passed. | Pass |
| Failed completion returns `NotSaved` and idempotent retry succeeds | Exact `failed_completion_is_bounded_and_retry_is_idempotent`: 1 passed. | Pass |
| Existing Source Scan compatibility UI still builds | `npm test`, `npm run check`, and `npm run build` all exited 0; production build completed across 1,798 modules. | Pass |

Additional focused evidence:

- `cargo test --manifest-path src-tauri/Cargo.toml findings::coverage`: 3 passed.
- `cargo test --manifest-path src-tauri/Cargo.toml run_comparison`: 4 passed.
- `cargo test --manifest-path src-tauri/Cargo.toml triage::scope`: 12 passed.
- `cargo test --manifest-path src-tauri/Cargo.toml findings::review`: 24 passed.

## Known limitations

- Clippy is not warning-free. It reports 20 library warnings and 32 library-test warnings, including 20 duplicates, outside the foundation-owned gate. No warning remains in `findings`, `triage/scope.rs`, `triage/manifest.rs`, or modified Source Scan command code. The sole warning in another explicitly checked file, an unnecessary cast in `scanners/mod.rs`, is unchanged from the pre-foundation root commit.
- Native Windows policy/database runtime behavior was not executed on this macOS host. Cross-platform Rust code compiled for the current target, and prior isolated Windows compile evidence remains documented in the task reports, but this QA pass does not claim Windows runtime verification.
- The one intentionally ignored live OSV test was not converted into an offline assertion; the foundation's deterministic tests do not depend on it.

All Foundation Completion Gate items passed. The durable backend foundation is ready for the separate Source Scan/Results workflow plan.
