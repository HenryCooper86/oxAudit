# Changelog

Notable changes to oxAudit, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Not every tag became a GitHub release. Published releases are v0.1.0,
v0.2.0, v0.2.1, v0.2.6 and v0.2.7. The v0.2.2 release exists only as an unpublished
draft, the v0.2.3 and v0.2.5 release workflows were cancelled before
publication, and 0.2.4 was prepared but never tagged. A user moving between
published releases receives every intermediate entry below. The
[release checklist](docs/release-checklist.md) records the verified
publication state, and the
[platform matrix](docs/getting-started.md#platform-availability-and-verification)
lists what each release ships.

## [Unreleased]

### Added

- Go standard-library and toolchain advisories. Compiled Go binaries (ELF,
  Mach-O, PE) in images and directories report the exact Go version they
  were built with as OSV's `stdlib` package, plus every linked module, read
  from the binary's build information (pre-1.18 binaries are named in a
  note). A `go.mod` with a `toolchain` directive adds `stdlib` and
  `toolchain` at that version; the `go` line alone adds a note instead,
  since it is only a minimum. Go version spellings (`go1.22rc1`, `1.21`) are
  normalized to OSV's form, which otherwise matches every advisory, including
  GOEXPERIMENT builds (`go1.25.3 X:boringcrypto`). A program's own module is
  reported when its build recorded a release. OSV's Go records carry no
  severity, so standard-library findings are `unknown` and do not trip
  `--fail-on`.
- Dependency scans read `npm-shrinkwrap.json`, `gems.locked`, `pdm.lock`,
  `deno.lock` (npm packages; JSR and remote modules are counted in a note)
  and .NET project files (`*.csproj`, `*.fsproj`, `*.vbproj`) with what
  MSBuild brings in beside them: central versions and global references from
  the nearest `Directory.Packages.props`, references in the nearest
  `Directory.Build.props`/`.targets`, and a sibling `packages.config`. Only exact .NET
  versions are queried; floating, ranged and property versions are listed as
  unchecked. A shrinkwrap shadows its sibling `package-lock.json`, `gems.locked`
  its `Gemfile.lock` and a `packages.lock.json` its project file, each with a
  note. A lone binary `bun.lockb` is named in the notes instead of silently
  skipped.
- `scan` (including `--staged`) and `deps` read a committed
  `.oxaudit/config.toml` from the scanned directory: ignored directories,
  `fail_on` and `fail_on_new` gates, maximum file size, the secret and
  pattern scanners, and rule-pack files. A flag wins over the file and ignore
  lists combine; unknown keys are a usage error; every setting the file
  changes is printed on stderr even with `--quiet` (and in the `scan` step
  summary); `fail_on_new` applies only with `--baseline`; `scan --staged`
  takes only `fail_on`; `--no-config` ignores the file. The consumer CI
  example passes `--fail-on none` so a target's config cannot change its
  new-findings-only gate. The repository's own self-scan now takes its ignored directories from
  it.
- A committed `.oxaudit/advisory-policy.json` dismisses dependency and
  container-image advisories by advisory id or alias, optionally narrowed to
  a package, ecosystem and installed version, with a required reason and an
  optional expiry. Dismissed advisories are still reported — `review` in
  JSON, SARIF `suppressions`, a marker in text output and a "Dismissed by
  policy" badge in the app — but no longer count toward `deps`/`image`
  `--fail-on` or `--fail-on-new`. `deps` reads the project's file;
  `--advisory-policy <FILE>` names another for `deps` and one for `image`.
  An invalid file stops the scan unless `--ignore-invalid-policy` is passed.
- `--sarif-uri-prefix` on `scan`, `deps` and `export` prefixes SARIF result
  paths, so GitHub code scanning places alerts correctly when a subdirectory
  was scanned. Under GitHub Actions, `scan` and `deps` apply the scan root's
  path inside `GITHUB_WORKSPACE` automatically, as workflow annotations
  already did; `--sarif-uri-prefix ""` turns that off. The example workflow
  keeps its `jq` prefix step until a published release carries the flag.
- `tools/check-versions.mjs` (run by CI) fails when the README, the
  installation guide, the consumer CI example or the CLI reference name a
  release other than the latest published one listed above, or a CLI
  version other than `Cargo.toml`'s.
- `export` and `--format` accept `github-issues-csv` and `jira-csv`, the
  ticket hand-off formats the desktop Export Center already offered, so CI
  can produce them.
- `.pre-commit-hooks.yaml` defines an `oxaudit-secrets` hook for the
  pre-commit framework, running the installed `oxaudit-cli scan --staged`.
- Image scans read rpm package databases — `rpmdb.sqlite` (RHEL 9 and 10,
  Rocky and Alma 9, Fedora-era layouts under `/usr/lib/sysimage/rpm`) and the
  older Berkeley DB `Packages` (RHEL 7 and 8, Rocky and Alma 8, Amazon Linux
  2, openSUSE Leap up to 15.2) — in memory, and map RHEL, Rocky Linux,
  AlmaLinux, openSUSE Leap, Azure Linux and openEuler `os-release` files to
  their OSV ecosystems. RHEL packages are asked about wherever Red Hat files
  them: the `baseos`, `appstream` and `crb` streams for RHEL 8 and 9, the
  `server` variant for RHEL 6 and 7, and the minor release from RHEL 10. The
  NDB database of newer SUSE releases is named in a note rather than read,
  SUSE Linux Enterprise is not matched (OSV files it under product modules
  the image does not name), and an uncheckpointed rpm write-ahead log is
  noted. A crafted rpm database cannot stall the scan or exhaust memory: a
  `Packages` view is refused, every row counts toward the package cap, and
  SQLite runs under a step budget and value-size limit.

### Fixed

- Image scans report only the topmost copy of a package database when a later
  layer rewrites it at the same location (layer order from the registry pull
  or a saved image's `manifest.json`), so an upgraded package no longer also
  appears at its old version; a chroot or sysroot database elsewhere in a
  layer never replaces the OS's own.
- Online image scans look up OSV with up to eight requests in flight,
  keeping results in order; images full of Go binaries finish in seconds.
- OpenVEX and CycloneDX VEX exports carry advisory-policy dismissals: a false
  positive is `not_affected`/`false_positive`, an accepted or suppressed risk
  is stated with its reason.
- CBL-Mariner 2.0 images map to `Azure Linux:2` and openSUSE Tumbleweed to
  `openSUSE:Tumbleweed`; a RHEL component missing streams in an offline
  database is counted once.
- .NET: conditional `<Version>` children and `<Choose>` blocks are noted, an
  id pinned twice in `Directory.Packages.props` is noted, and a symlinked
  nearest `Directory.*` file stops the search with a note.
- Go: unframed module information is ignored like Go's own reader does, and
  the standard library is shown as `go-stdlib`.
- `--advisory-policy` may name a symlinked file; policy and config read
  errors say what is wrong once ("is a directory, not a file"); an unreadable
  `.oxaudit` directory is a failure (exit 3) again; config TOML errors name
  the line; the agent's dependency tool marks dismissed advisories; the
  "Dismissed by policy" badge exposes its reason to assistive technology.
- SARIF URI prefixes are percent-encoded; grype keeps `1.0~rc1` apart from
  `1.0`; the pre-commit block goes after a hook's plain environment setup
  (`export`, assignments, `set`) and before any sourced file or command;
  `core.hooksPath` is found in every git config scope and `include` file;
  flow-style workflow steps (`- {run: …}`) are checked for script injection
  (a `run:` whose script holds a `{…}` literal is still a script);
  credential URLs are judged by their password, not a placeholder-looking
  user name; `.pre-commit-hooks.yaml` declares pre-commit 3.2.0.
- A requirements file line of `-` followed by a non-ASCII character no longer
  aborts the dependency scan (found by fuzzing).
- Debian, Ubuntu and Alpine image packages are now looked up by their source
  package (dpkg `Source:`, apk origin), which is what OSV files those
  distributions' advisories under. Packages whose binary name differs from
  their source — `libc6` from `glibc`, `libssl3` and `libcrypto3` from
  `openssl` — previously matched nothing and were reported clean. Binaries
  built from one source share one OSV lookup.
- The README, installation guide, server guide, CLI reference, release
  checklist and consumer CI example named v0.2.6 as the latest release after
  v0.2.7 was published, so copy-paste installs and the example CI gate
  pinned a CLI without 0.2.7's fixes. They now point at v0.2.7, with its
  commit, checksum and image digest, and the release checklist records what
  was verified for it on 2026-11-02.
- Offline (`--advisory-db`) matching no longer reports advisories that OSV
  marks withdrawn, and sorts a range's events by version before evaluating
  them; a record that listed its events out of order could previously miss
  an affected version.
- NuGet and Packagist versions are compared in their registries' own orders.
  The shared "loose" ordering compared prerelease labels as plain text
  (`rc.10` before `rc.9`, Composer `RC1` before `beta2`), sorted Composer
  `-patch` releases below the release they patch, and ranked a NuGet
  prerelease above a higher fourth segment. Offline matching and the desktop
  fix-candidate proofs both use the corrected orders.
- yarn workspace, `file:`, `link:`, `portal:`, git and tarball entries,
  Composer path repositories and `dev-*` branch versions, and Pub git
  packages are inventoried but no longer queried against the public registry,
  where an internal package sharing a public name produced false positives.
  Yarn `patch:` entries are checked as the package they patch instead of
  under a garbled name.
- Workflow script-injection detection (`gha-script-injection`) covers
  multi-line `run: |` blocks, quoted expressions, `github.head_ref` and
  `actions/github-script` scripts. It previously fired only on an unquoted
  expression on the `run:` line itself, and treated
  `run: echo "${{ github.event.issue.title }}"` as safe, though GitHub
  expands the expression before the shell sees the quotes. The benchmark
  corpus's negative fixture carried the same mistake and is corrected.
- Working-tree scans report vendor-prefixed tokens (`ghp_…`, `AKIA…`,
  `xoxb-…` and the like) and private keys found inside comments. Every secret
  in a comment was dropped, so a commented-out credential went unreported,
  although history and `--staged` scans found it. Generic `password =` and
  `api_key =` matches in comments stay suppressed.
- HashiCorp Vault's current `hvs.`/`hvb.`/`hvr.` tokens are detected (only the
  legacy `s.` form was), and credentials in PostgreSQL, MySQL/MariaDB,
  MongoDB, Redis and AMQP connection strings are reported alongside HTTP and
  FTP URLs. Templated passwords (`${DB_PASSWORD}`, `%(pw)s`, `{{password}}`,
  `<password>`) are not.
- The README's secret-rule count is corrected to 42, and every secret rule
  now has a regression test.
- grype's Debian, RPM and apk components merge with oxAudit's native and
  cve-bin-tool rows: their epoch and packaging revision
  (`1:11.8.6-0+deb13u1`) are reduced to the upstream version before merging,
  so one component no longer appears twice with its CVEs split between rows.
- Findings dismissed in `.oxaudit/policy.json` (false positive, accepted risk,
  suppressed) no longer become GitHub pull-request annotations or VS Code
  diagnostics. They never failed `--fail-on`, but were still shown as errors.
  The job summary lists them as a count.
- `hook install` no longer reports success where git never looks. With
  `core.hooksPath` set (husky sets it), git ignores `.git/hooks`; install now
  refuses and names the line to add to the configured hook instead, and
  `hook status` says the hook is not active. The managed block now goes
  directly after the shebang and no longer uses `exec`, so a user hook that
  ends in `exec` cannot skip the scan and lines after the block still run;
  reinstalling moves a block that earlier releases appended.

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
