# Dependency maintenance

Reviewed **2026-11-07**. Dependabot checks npm, Cargo, and GitHub Actions
weekly. npm and Cargo group minor/patch version updates; other major updates
remain eligible for individual review. Grouping does not merge updates or
replace CI. GitHub documents these controls in its
[Dependabot options reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#groups).

## keyring 3.x compatibility boundary

[Dependabot run 37962106521](https://github.com/HenryCooper86/oxAudit/actions/runs/37962106521)
failed while attempting `keyring` 3.6.3 → 4.2.0. Cargo rejected the retained
`apple-native` feature because 4.2.0 no longer exposes it. This is a
dependency/store migration, rather than a transient registry failure.

The current manifest explicitly selects these 3.x stores:

| Platform | Feature contract |
| --- | --- |
| macOS/iOS | `apple-native` (Keychain) |
| Windows | `windows-native` (Credential Store) |
| Linux | `linux-native-sync-persistent`, `crypto-rust`, `vendored` (keyutils with synchronous Secret Service backing) |

These features are documented by
[keyring 3.6.3](https://docs.rs/keyring/3.6.3/keyring/). The
[4.2.0 manifest](https://github.com/open-source-cooperative/keyring-rs/blob/v4.2.0/Cargo.toml)
instead exposes store-crate features and defaults to `v1`; its
[v1 interface](https://docs.rs/keyring/4.2.0/keyring/v1/index.html) uses
Secret Service on Unix. Replacing feature names or enabling the new default
would not establish equivalence with the selected Linux persistent store.

`.github/dependabot.yml` therefore ignores only keyring's
`version-update:semver-major`. Compatible 3.x minor/patch updates remain
eligible, and no other dependency's majors are ignored. Cargo manifests,
lockfiles, and credential code retain their current platform behavior.

## Explicit migration follow-up

Before removing that exception, review keyring-core and the platform store
crates recommended by the
[keyring 4.2.0 documentation](https://docs.rs/keyring/4.2.0/keyring/).
Choose equivalent stores deliberately, check toolchain requirements, and
validate read/set/delete plus restart persistence and existing-credential
compatibility on macOS, Windows, and Linux. Include Linux Secret Service
availability and the current vendored/crypto behavior. Update every target
dependency declaration and the lockfile together, then remove the exception
after platform validation.

This policy does not disable repository security alerts or change the
existing npm audit/Rust security workflow. It also does not promise an
automatic fix for an advisory that requires a keyring major migration:
review such an alert promptly and perform the migration or another verified
remediation. The next hosted Dependabot run must confirm update generation;
local YAML validation cannot reproduce GitHub's update service.

## November 2026 refresh

The workspace and separate fuzz workspace were checked against the stable,
non-yanked releases published on crates.io on 2026-11-07. Direct requirements
and both lockfiles are updated together; transitive dependencies remain subject
to the upstream crates' compatible requirements. The pinned Rust 1.97.1
toolchain is retained.

The manifests now declare dependency-imposed Rust floors of 1.90 for the host,
archive crate and fuzz workspace (Tauri/backhand), and 1.89 for the other workspace
crates (uuid/serde-saphyr). Verification uses the pinned 1.97.1 toolchain;
these floors have not separately been tested as complete toolchains.

Bzip2 0.6 replaces its native implementation with `libbz2-rs-sys`. Its
permissive [bzip2-1.0.6 license](https://spdx.org/licenses/bzip2-1.0.6.html)
was reviewed and permitted by a crate-scoped cargo-deny license exception.
The source notice and origin requirements remain applicable; no GPL-only
dependency is introduced.

Reqwest 0.13 replaces the `rustls-tls` feature with `rustls`; query serialization
also requires the explicit `query` feature. JSON, gzip and streaming remain
enabled with default features disabled. The upstream
[0.13.5 manifest](https://github.com/seanmonstar/reqwest/blob/v0.13.5/Cargo.toml)
wires `rustls` to `rustls-platform-verifier` and AWS-LC; the
[TLS documentation](https://docs.rs/reqwest/0.13.5/reqwest/tls/)
describes AWS-LC as the default crypto provider. This adopts platform trust
verification instead of the bundled WebPKI roots/ring selection in the previous
0.12 configuration. Local HTTP, advisory, AI, registry, redirect and SSRF
regression tests passed on macOS. Live HTTPS against every provider and
Windows/Linux trust-store behavior were not separately exercised; the local
tests do not establish equivalence for custom enterprise roots or OS trust
configuration.

Keyring 3.6.3 remains the sole direct Rust version exception. The current
[keyring 4.2.0 documentation](https://docs.rs/keyring/4.2.0/keyring/)
explicitly directs applications that select credential stores to
`keyring-core` and individual store crates. Its `v1` feature selects the zbus
Secret Service store on Linux rather than the existing keyutils plus
synchronous persistent Secret Service contract. Renaming features therefore
does not preserve this application's saved-credential behavior. No Windows or
Linux credential migration was validated during this refresh; the existing
store selection is preserved on every target. The migration follow-up above
continues to apply.

## JavaScript compiler and lint compatibility

The same refresh updates the app and VS Code extension to stable npm releases,
including React 19.3.1, Vite 8.3.6, Vitest 5.1.0, TypeScript 7.0.2, jsdom 31,
and the current Tauri packages. Compatible transitive dependencies were refreshed
with `npm update`, followed by clean `npm ci` installs. Node 22.22.2 remains the
validated local runtime; `package.json` records the supported engine ranges.

TypeScript 7 does not expose the compiler API required by typescript-eslint.
Following Microsoft's [side-by-side migration guidance](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/#running-side-by-side-with-typescript-6-0),
`typescript` aliases the TypeScript 6 compatibility API and `typescript-7` aliases
the native 7 compiler. Build/check scripts and the container invoke
`node node_modules/typescript-7/bin/tsc` explicitly: a transitive legacy compiler
can otherwise win the shared `tsc` executable name. ESLint still consumes the
compatible API while production checks run the native compiler.

ESLint and `@eslint/js` remain on 9.39.5 because the latest
`eslint-plugin-jsx-a11y` 6.10.2 declares support through ESLint 9. Accessibility
rules remain enabled, and installs do not force incompatible peer dependencies.
The scoped minimatch override under `@typescript-eslint/typescript-estree`
selects patched 11.0.5 or newer; lint and a type-aware project-service glob check
were verified with it. Both npm projects report zero audit vulnerabilities.

Tailwind's latest optional WASM package bundles `@napi-rs/wasm-runtime` 1.2.2
inside its published tarball. npm cannot independently refresh that bundled copy;
its upstream package must publish a replacement. Other transitive major versions
remain constrained by their parent packages' supported ranges.

The Vite configuration keeps the previous browser targets explicitly, and the
extension still compiles against VS Code 1.85 API definitions as well as the
latest 1.145 definitions. Vitest 5 requires a matcher type augmentation for
jest-dom 7, and jsdom 31 requires pending focus timers to be flushed before the
tests restore real timers. Compiler strictness and coverage thresholds remain
unchanged.

## CI dependencies and verification

Action releases were resolved to full commit SHAs, including setup-node 7.1.0,
dependency-review-action 5.0.0, CodeQL Action 4.39.3, artifact upload 7.0.2,
artifact download 8.0.2, and cosign-installer 4.1.3. The Rust toolchain action was
also refreshed to its current commit. All 49 action references stay SHA-pinned.
The dependency-review action now uses Node 24 internally on GitHub-hosted
runners; application jobs continue to select Node 22.

The release SBOM tool advances to cargo-cyclonedx 0.5.10. cargo-deny 0.20.2,
cargo-fuzz 0.13.2, and cyclonedx-npm 6.0.1 were already current and retain exact
version pins. The existing corpus manifest was regenerated to reconcile stale
counts and its normalized quoted-block fixture ID; fixtures and scanner rules
were unchanged.

Verification includes clean npm installs, build/type checks/lint, unit and
component tests, coverage, extension API compatibility, Rust workspace tests,
fuzz-target compilation, and cargo-deny's advisory/license/source checks. The
updated CLI pilot, all six Chromium workflows against the real server, and all
11 CI shell tests with the real CLI passed. The Linux/amd64 container release build also passed for both CLI and server.
Native tests here use macOS; the hosted CI matrix remains responsible for
Windows and Linux platform tests.
