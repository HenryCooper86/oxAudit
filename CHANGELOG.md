# Changelog

Notable changes to oxAudit, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Not every tag became a GitHub release. Published releases are v0.1.0,
v0.2.0, v0.2.1 and v0.2.6. The v0.2.2 release exists only as an unpublished
draft, the v0.2.3 and v0.2.5 release workflows were cancelled before
publication, and 0.2.4 was prepared but never tagged. A user moving between
published releases receives every intermediate entry below. The
[release checklist](docs/release-checklist.md) records the verified
publication state, and the
[platform matrix](docs/getting-started.md#platform-availability-and-verification)
lists what each release ships.

## [Unreleased]

Nothing yet.

## [0.2.7] - 2026-10-29

Release notes: [docs/releases/v0.2.7.md](docs/releases/v0.2.7.md).

### Added

- `oxaudit-cli compliance` (`profiles`, `assess`, `list`, `show`, `review`,
  `report`) brings the Compliance Center and Report Studio to the command
  line, using the same engine, report generator and claim boundary. See
  [the CLI reference](docs/cli.md#compliance).
- Local advisory matching compares RPM distributions (Rocky Linux,
  AlmaLinux, Red Hat, SUSE, openSUSE, Mageia, Azure Linux, openEuler,
  Photon OS) with `rpmvercmp` ordering instead of reporting every advisory
  regardless of version.
- Fuzz targets for every lockfile parser, report import (SARIF, CycloneDX,
  SPDX, OpenVEX, native) and package metadata (ELF package notes,
  os-release, dpkg/apk databases, rule-pack feed index). The parsers moved
  into the lean `oxaudit-parsers` crate so they can be fuzzed.
- ESLint (TypeScript, React hooks, accessibility) and component coverage
  thresholds run in CI.

### Changed

- The default advisory-database ecosystems add Hex and Pub, making ten:
  npm, PyPI, Maven, crates.io, Go, RubyGems, Packagist, NuGet, Hex and Pub.
- Local advisory matching compares Hex versions as SemVer and Pub versions in
  Dart's `pub_semver` order, where build metadata is significant and sorts
  after its release (`1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build`).
  Bare `Debian` and `Ubuntu` ecosystem names use the Debian comparator;
  Alpine, Wolfi and Chainguard use apk ordering, and RPM distributions use
  `rpmvercmp` (see Added).
- Maven versions with unknown qualifiers (for example `-jre`, `-android`,
  `.v20210629`, `LATEST`) are compared in `ComparableVersion` order,
  case-insensitively and after every known qualifier, instead of being
  refused. Only empty versions and versions with whitespace or non-ASCII
  characters are still refused. See
  [the advisory database guide](docs/advisory-database.md#matching-rules-and-stated-limits).
- Dependency scans recognise `uv.lock` (PyPI). Editable, virtual, path, git
  and URL packages are inventoried but not looked up in the registry.
- Maven `pom.xml` versions written as `${property}` resolve from the POM's
  own `<properties>` and `project.*`/`parent.*` values. Dependencies whose
  version is inherited from a parent POM or BOM, or uses an undefined
  property, are named in an inventory note instead of being passed through
  as literal versions or failing the scan.
- Container image scans map Ubuntu to the standard OSV ecosystems
  (`Ubuntu:22.04:LTS`, `Ubuntu:23.10`) instead of `Ubuntu:Pro:…`, which
  missed every main-archive advisory, and recognise Debian 10 (buster).
- The GitHub Action passes `target` and `args` through the environment
  instead of interpolating them into its shell script, verifies with
  `sha256sum` where `shasum` is missing, and supports Linux ARM64 runners.
- The container image creates `/data` owned by the unprivileged `scanner`
  user, so `oxaudit-server` starts on a fresh named volume.

### Fixed

- pip requirements files no longer fail the whole dependency scan on lines
  that pin no single release. Ranges (`flask>=2.0`), unpinned names,
  editable installs (`-e .`) and direct URL or path references are named in
  inventory notes as not checked; malformed lines still fail.
- Dependency scans discover `requirements-*.txt`, `*-requirements.txt` and
  `requirements/*.txt`, and follow `-r` includes inside the project, whatever
  the included file is called. Remote, missing and out-of-project includes
  are reported as unscanned and never read.
- Alpine, Wolfi and Chainguard versions use apk-tools ordering, so a
  pre-release such as `1.2.3_rc1` is affected by an advisory fixed in
  `1.2.3`; the Debian-style comparator ranked it above the release.
- A malformed ELF package note with a program-header offset near the
  address limit no longer panics debug and test builds (found by fuzzing).
- Compliance assessments count stored source scans as evidence; they were
  never matched to the assessed directory, so controls expecting source
  evidence stayed gaps. Every built-in profile can be assessed in one run,
  which is the Compliance Center's default selection.
- When Assistant conversations cannot be loaded, the sidebar shows a
  persistent error with Retry; deleting the active conversation when its
  replacement cannot be created no longer sends turns to the deleted one.
- The command palette's arrow keys, screen-reader announcement and Enter
  follow the same, visible order; Enter could open a different page than the
  one highlighted.
- Source and history scan views no longer reset a run that changed while
  its results were loading.
- Real Alpine images (`VERSION_ID=3.20.3`) are matched against OSV's
  `Alpine:v3.20` instead of a non-existent `Alpine:v3.20.3`, which left
  image packages unmatched.
- An offline scan of image binaries whose package notes name only the
  distribution (`Debian`, `Ubuntu`, `Alpine`) now reads every release's
  advisories, as OSV's online API does. These packages previously matched
  nothing and appeared clean. A database built from a bare distribution dump
  also covers release-qualified queries such as `Debian:12`.
- Offline matching of `mix.lock` (Hex) and `pubspec.lock` (Pub) packages no
  longer reports every advisory regardless of version.
- Cargo workspace members, path and git crates, Poetry and uv git/path/URL
  packages, and npm workspace members are no longer queried against the
  public registry, which produced false positives when an internal package
  shared a public name.
- Structurally valid lockfiles with no registry packages (an empty
  `gradle.lockfile`, `composer.lock`, `poetry.lock`, `mix.lock`,
  `Pipfile.lock`, `packages.lock.json`, `pubspec.lock`, `yarn.lock` or
  `requirements.txt`) are an empty inventory instead of failing the whole
  dependency scan. Malformed files still fail.
- Lockfile discovery reports unreadable directories as incomplete
  dependency coverage instead of skipping them silently.
- A failed CISA KEV download is no longer cached for an hour as "nothing is
  known exploited"; source scans record an `exploitation_signal_unavailable`
  coverage warning and retry after a minute.
- CVE research lists affected products as `vendor:product` (it showed the
  CPE part and vendor, such as `a:apache`) and prefers NVD's primary CVSS
  score over a secondary source listed first.
- Links in Assistant answers and CVE briefings open in the system browser
  (http, https and mailto only) instead of replacing the app window.
- Settings list fields accept Enter and spaces while typing; number fields
  validate whole numbers within range instead of snapping back or failing
  on save.
- Command errors show their message instead of `[object Object]`.
- The browser GUI works over plain HTTP from another machine, where
  `crypto.randomUUID` is unavailable.
- Rewinding an Assistant conversation asks for confirmation before deleting
  messages and warns before replacing a draft.
- In server mode, Settings no longer offers AI configuration the server
  cannot use.
- Error toasts stay until dismissed, other toasts pause while hovered or
  focused, at most five show at once, and they fit narrow screens.

- SARIF 2.1.0, CycloneDX 1.6, SPDX 2.3 and OpenVEX 0.2 exports are validated
  offline against bundled official schemas, including nested records, before
  delivery. OpenVEX requires at least one advisory statement.
- Inventory import keeps dependency relationships, mapped to the new run's
  component IDs, and retains the original detailed licence metadata for
  same-format re-export. Duplicate or dangling references and relationship
  types without a canonical equivalent are disclosed and kept as evidence.
- PDF compliance reports embed a licensed font, so precomposed Latin accents
  and supported Chinese characters stay searchable; characters the font
  cannot represent fail before the report is saved. Compliance CSV carries
  the claim boundary on every control row.
- Scan cancellation and scan recovery are more reliable. Scheduled entries
  are rechecked immediately before launch, so disabling or removing one
  while an earlier scan runs takes effect.
- Portfolio pages through saved projects in groups of 50 in desktop and
  server modes, with in-place retry of a failed page.

## [0.2.6] - 2026-10-26

Published release; GitHub's latest release at the time of writing. The first
published release after v0.2.1, so it also delivers the 0.2.2–0.2.5 entries
below. Notes: [docs/releases/v0.2.6.md](docs/releases/v0.2.6.md).

### Fixed

- Release packaging selects the application SBOM
  (`src-tauri/oxaudit.cdx.json`) explicitly and checks its name, version and
  non-empty dependency list before upload. Recursive selection had picked a
  workspace helper, which stopped v0.2.5.

## [0.2.5] - 2026-10-26

Tagged; the release workflow was cancelled and no GitHub release exists. Its
changes shipped in v0.2.6. Notes:
[docs/releases/v0.2.5.md](docs/releases/v0.2.5.md).

### Fixed

- Rust SQL detection distinguishes `+`, `format!` and `write!` inside strings
  or comments from real statement construction, including inside macros.
- Alternative Rust match-pattern labels no longer look like generic credential
  assignments. A paired scan of three unchanged files went from 21 findings to
  18, with no unrelated detections removed.

### Added

- A one-week daily-workbench pilot guide and blank scorecard, with a recorded
  agent-run technical rehearsal. These records do not claim human usability
  acceptance or measured time savings.

### 0.2.4 (prepared, never tagged)

Commit `7b5e1b8` moved the version declarations to 0.2.4 but was never
tagged; its changes first shipped in 0.2.5:

- Rust dependency updates, including `zip` 9. ZIP member names in legacy
  CP437 and UTF-8 encodings are decoded during binary-scan extraction, and
  an unreadable member name is counted as skipped. Advisory dumps and
  rule-pack archives with unreadable member names fail with a stated error.

## [0.2.3] - 2026-10-25

Tagged; the release workflow was cancelled and no GitHub release exists. Its
changes shipped in v0.2.6.

### Fixed

- A damaged rule-pack or schedule store is reported as an error instead of
  being read as an empty or partial list. A scheduled scan whose installed
  rule packs cannot be loaded completes with a coverage warning saying so.
- The VEX trust and Portfolio pages ignore superseded responses, so a stale
  read cannot overwrite or unlock controls showing newer state.

## [0.2.2] - 2026-10-25

Tagged; the release exists only as an unpublished draft. Its changes shipped
in v0.2.6.

### Fixed

- GUI copy and states match delivered behaviour; scanner, policy and storage
  behaviour are unchanged. The browser build no longer offers **Open file**
  and reports AI as unsupported rather than offline. Assistant clear, rename
  and delete adopt their new state only after the write succeeds. Export
  previews show the backend's validity flag. History Scan states its budgets,
  and list caps are stated when reached. Disabled controls state why.

## [0.2.1] - 2026-10-25

Published release.

### Fixed

- `oxaudit-cli monitor` selects the latest completed dependency run of every
  target. It previously considered only the newest hundred runs, so older
  targets silently left monitoring while the command reported success.

## [0.2.0] - 2026-10-25

Published release. The first with a Linux aarch64 CLI and a
multi-architecture container image.

### Added

- `oxaudit-cli monitor`: re-match stored dependency inventories against a local
  advisory database and report advisories the stored runs did not, with
  `--update`, `--fail-on` and a Slack-compatible `--webhook` digest.
- `oxaudit-server`, the headless server that serves the desktop GUI to a
  browser, and a linux/amd64 + linux/arm64 container image carrying it and
  the CLI.
- A Linux aarch64 CLI in every release.
- Pre-commit secrets gate (`scan --staged`, `hook install`), GitHub Actions
  annotations and job summaries, dependency fix suggestions, and the VS Code
  extension.
- Desktop: one-off rule-pack files for source scans, resetting a finding
  review to candidate, OWASP Benchmark scoring and compiled grammars in
  Quality Lab, and dependency scans answered from the local advisory
  database.
- Browser import/export, server-side report saving and paged inventory.

### Changed

- The unmaintained YAML parser was replaced with bounded deserialization.
- Java alert noise was reduced.

### Fixed

- Server access hardening, scan rechecks, dependency parsing, scan lifecycle
  and cancellation, binary extraction efficiency, durable evidence, and
  workbench recovery and result ownership.
- Maintenance fixes of 2026-10-22:
  - Scan and tool durations carry rounded seconds into the minute count
    rather than displaying `1m 60s`. Unused path, truncation and
    pluralization helpers were removed from the shared formatting module.
  - AI streaming accepts LF, CRLF and CR event framing, including line
    endings split between network chunks, ignores one stream-leading UTF-8
    BOM, and preserves data-field whitespace after the single optional space
    defined by the
    [SSE format](https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation).
  - Dependency recovery retains the complete live inventory when durable
    history still identifies the same run, but restores a genuinely newer
    run. Target edits are local drafts: **Find lockfiles** or **Check
    dependencies** activates and remembers the project, avoiding
    per-keystroke runtime updates and input corruption. Failed activation
    clears runtime context and offers a retry. Upgrade decision requests
    belong to saved-run lifetimes.
  - npm v1 registry aliases use the real package name and pinned version.
    npm v1 and pnpm git, file, link and tarball coordinates are excluded from
    registry inventory and OSV queries rather than treated as package
    versions. A valid empty pnpm inventory is accepted; malformed sections
    and registry declarations without a readable packages inventory remain
    coverage errors.

## [0.1.0] - 2026-09-26

First published release: the desktop workbench and `oxaudit-cli` over one
engine. Source pattern and secret scanning, Git history secret scanning,
dependency scanning against OSV or a local advisory database, native binary,
archive and container-image scanning (including registry pulls), rule packs
and rule-pack feeds, VEX import and trust, and SARIF, CycloneDX, SPDX and
OpenVEX exports. Releases carry CLIs for Linux x86_64, macOS (universal) and
Windows x86_64, unsigned Linux desktop packages, SBOMs, checksums, minisign
and Sigstore signatures, and build-provenance attestations, plus the
composite GitHub Action and the installer script.

[Unreleased]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.3...v0.2.5
[0.2.3]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/HenryCooper86/oxAudit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/HenryCooper86/oxAudit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HenryCooper86/oxAudit/releases/tag/v0.1.0
