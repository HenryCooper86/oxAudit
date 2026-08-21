# oxAudit Source Results Workflow QA

Date: 2026-08-21

Status: Passed with one inherited lint-baseline exception

## Candidate and environment

- Tested candidate: the uncommitted Source Results workflow changes on top of `da420ee3215dd68ce7256692f21c7b0ac3391b3b`.
- Host: macOS 26.6.1, Apple silicon (`arm64`).
- Rust: `rustc 1.97.1`, `cargo 1.97.1`.
- Frontend runtime: Node.js `v22.22.2`, npm `12.0.1`.
- Native debug application: `src-tauri/target/debug/bundle/macos/oxAudit.app`.
- Native debug image: `src-tauri/target/debug/bundle/dmg/oxAudit_0.1.0_aarch64.dmg`.
- Disposable native fixture: `/tmp/oxaudit-source-qa2.fguHIU`.
- Secret fixture: a synthetic GitHub-token-shaped value under `tests/fixtures/credential.js`. Its raw value is intentionally omitted from this record.

## Required verification matrix

| Command or check | Result | Evidence |
|---|---:|---|
| `npm run check` | Pass | TypeScript completed with no diagnostics. |
| `npm run build` | Pass | Vite transformed 1,813 modules and emitted the production bundle. |
| `npm test -- --run` | Pass | 82 passed, 0 failed. |
| `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` | Pass | No formatting differences. |
| `cargo test --manifest-path src-tauri/Cargo.toml` | Pass | 492 passed, 0 failed, 1 ignored. The ignored live OSV test is the established outbound-network fixture. |
| `npm run tauri build -- --debug` | Pass | macOS application and DMG bundles completed. |
| `git diff --check` | Pass | No whitespace errors. |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings` | Baseline exception | Exit 101: 20 library errors and 31 library-test errors, including duplicates. No Rust file was changed by this workflow; the reported locations are inherited repository-wide warnings outside the new frontend workflow. |

Vite also reports the existing advisory that the main JavaScript chunk exceeds 500 kB after minification. The build remains successful.

## Durable run and comparison evidence

The fixture contained production `eval()` and `innerHTML` candidates, a generated-file candidate, and a synthetic credential under a fixture directory.

| Scenario | Run ID | Result |
|---|---|---|
| Baseline | `ba4ee4e6-18f7-41f3-814a-c6a34593bf7f` | 4 files, 3 findings: 1 secret and 2 vulnerabilities. |
| Production line insertion plus a new DOM sink | `21568e60-7acd-4ced-81a6-874c4e917d80` | The production `eval()` moved to line 8 but retained fingerprint `253b7f0117cb5d8856053e5a4401b633063338a98b6189c926654e6df93dbe4a` and remained `Unchanged`. The new `innerHTML` finding appeared as `New`. |
| Generated candidate restored | `2f9f5d27-867e-465a-8148-8ce564765578` | 4 findings with 1 new candidate. |
| Generated candidate removed within covered input | `0382c3e3-7a56-4b2b-bfb9-eb7cf0d02fa8` | 3 current findings and 1 `Resolved` generated projection with a read-only resolution boundary. |
| Secrets scanner disabled | `31c4dd59-47ff-4399-bd33-6e7958ec2c00` | 2 current vulnerabilities; the prior secret became `Not evaluated`, not falsely resolved. |
| Invalid policy explicitly bypassed | `2f1f3878-9437-4ff6-9dd6-286a9dde216b` | 2 current vulnerabilities; scan completed through the explicit recovery action. |

The application was quit and relaunched after the baseline and again after reviews. Selecting the fixture from Recent targets restored the latest completed run, full history, stable fingerprints, local decisions, and the active project-policy decision.

## Review workflow evidence

- The production `eval()` was saved as `Confirmed`, origin `Local`, with entry point, data flow, overall evidence, and all five falsification gates marked `Survives` with evidence. It remained the single item in Open after restart.
- The `innerHTML` candidate was saved as `Accepted risk`, origin `Project policy`, with the reason: “Risk accepted for the isolated fixture renderer; the production path will migrate to textContent.” It moved to Closed, created `.oxaudit/policy.json`, and reloaded with a one-entry review history.
- The synthetic credential was saved as `False positive`, origin `Local`, with the reason: “Synthetic fixture credential is not deployable.” It moved from Other scopes to Closed and reloaded with a one-entry review history.
- The optional-expiry validation and serialization path is covered by the frontend review tests for both rejected past dates and an accepted future `datetime-local` value. The backend suite also covers strict expiry boundaries and expired-review projection behavior.
- Invalid project policy makes the file-backed accepted-risk decision inactive while leaving the local confirmed review and audit history intact. Restoring the exact policy bytes reapplies the project decision.

## Invalid-policy recovery evidence

The valid project-policy checksum was:

`3fc9c937a4e520512f646dfec153b7d84c36349045ef7e1b948b17dce62621c7`

Removing the closing JSON brace produced the malformed checksum:

`196987bc4570f1afa7cc9980f0d2011e5f2eb399a02a5f14cc2b00e98a495ef0`

After relaunch, the native UI showed “Project policy needs attention,” disabled the ordinary Run scan action, and exposed the explicit `Scan without project policy` recovery action. The recovery scan completed, and the malformed checksum remained byte-for-byte unchanged. The valid closing brace was then restored, returning the file to the original checksum and the UI to `Project policy active`.

## Secret-safety evidence

- Native list and detail views displayed `[REDACTED]`; the raw fixture value did not appear in the accessibility tree.
- `Copy finding` produced an allowlisted JSON object whose `matchText` and `context` were both `[REDACTED]` when pasted into a scratch TextEdit document.
- `Copy JSON` produced the run export with the secret projection redacted in the same two fields.
- `Discuss in Assistant` opened the review-before-attaching dialog with metadata, description, and recommendation only. No match or source context containing the credential was present.
- Automated frontend and Rust suites cover export redaction, review-request redaction, persisted redaction, pending-save redaction, and Assistant handoff redaction.

## GUI-first and accessibility evidence

- The Source screen was verified in the browser fallback at 1440×900 with the full navigation, target panel, fallback notices, and no visible horizontal overflow.
- The native application was resized to its exact 900×700 minimum. Navigation collapsed to a menu button, the target and recent sections stacked cleanly, and results used a single-pane list/detail flow with a visible `Back to findings` action.
- Result view tabs responded to Right Arrow, Home, and End, selecting Other scopes, Open, and Resolved respectively.
- The browser-only Source screen renders without a Tauri runtime and without console errors. A synchronous `getCurrentWebview()` fallback crash discovered during this pass was fixed so drag-and-drop unavailability is reported without taking down the page.
- Successful rescans keep the prior durable result workspace mounted until the replacement run completes, and typed retry states preserve the correct operation category.

## NotSaved retry evidence

Native persistence failure is deterministically exercised by the Rust service suite rather than by corrupting the user's application-data database. The passing suite includes:

- `failed_completion_is_bounded_and_retry_is_idempotent`;
- `retry_recovers_when_completion_committed_before_the_error_was_observed`;
- `post_maintenance_reload_failure_is_pending_and_retry_keeps_token`;
- `retry_returns_post_retention_projection_that_matches_restart`.

Together these checks verify the `NotSaved` retry token, bounded pending queue, successful retry, idempotent completion, redacted pending payloads, and restart-equivalent saved projection. The GUI renders the `Scan complete, but history was not saved` notice and `Retry save` action for this typed state.

## Known limitations

- Strict Clippy remains red because of the inherited repository lint baseline described above. This task changes no Rust files and introduces none of the reported locations.
- Native runtime acceptance was performed on macOS arm64 only; Windows and Linux runtime behavior was not executed in this pass.
- The optional expiry was verified through deterministic frontend and backend tests. The manual native review exercised both origin types and durable dispositions without setting an expiry.

The GUI-first durable Source Results workflow is ready for inspection and the next prioritized improvement.
