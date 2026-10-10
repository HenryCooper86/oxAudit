# Dependency maintenance

Reviewed **2026-10-10**. Dependabot checks npm, Cargo, and GitHub Actions
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
