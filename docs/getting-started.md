# Install and run the local pilot

The available path is a local source build with repository read access. There is
no published release or public CLI download to rely on. This repository is
currently private. A locally built desktop bundle is a pilot artifact; it does
not establish Developer ID notarization or Windows Authenticode signing.

## Build prerequisites

Use **Node 22.22.2** (Node 22 at least 22.12 for the installed Vite 7 toolchain),
npm, Git, and rustup. `rust-toolchain.toml` pins **Rust 1.97.1**, clippy and
rustfmt. Running `rustup show active-toolchain` inside this checkout installs that
pin. Cargo's manifest MSRV field is not a claim that the entire current locked
dependency tree builds with Rust 1.77. The local pilot was exercised with Node
22.22.2/npm 12.0.1; CI uses Node 22.

Install the native prerequisites even for the CLI: it currently links the shared
Tauri library. The CI matrix is Ubuntu 24.04, macOS 15 and Windows Server 2025;
these are build targets, not a claim that every desktop OS version was tested.

- macOS: install Xcode Command Line Tools with `xcode-select --install`.
- Windows: install Microsoft C++ Build Tools with **Desktop development with
  C++**, a Windows SDK, and WebView2. Use rustup's MSVC host. MSI packaging also
  requires the VBSCRIPT optional Windows feature.
- Ubuntu 24.04: install the following packages.

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential curl file libayatana-appindicator3-dev librsvg2-dev \
  libssl-dev libwebkit2gtk-4.1-dev libxdo-dev wget
```

See the primary [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
for installer links and other Linux distributions. See the installed
`node_modules/vite/package.json` engine declaration for the Node floor.

## Exact build and install commands

Clone with an account that can read the repository, then run from its root:

```bash
git clone https://github.com/HenryCooper86/oxAudit.git
cd oxAudit
rustup show active-toolchain
npm ci
npm run check
npm test
npm run build
cargo build --locked --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli
```

On macOS/Linux, the development CLI is `src-tauri/target/debug/oxaudit-cli`.
On Windows it is `src-tauri\target\debug\oxaudit-cli.exe`. No AI provider or
external binary scanner is required for source checks.

```bash
# Development CLI and deterministic fixture checks, macOS/Linux:
npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli
# Optimized CLI installed into rustup/Cargo's bin directory:
cargo install --locked --path src-tauri --bin oxaudit-cli
oxaudit-cli --version
```

PowerShell uses the same `cargo install` command; for the development smoke use:

```powershell
npm run pilot:smoke -- --cli .\src-tauri\target\debug\oxaudit-cli.exe
```

Build desktop bundles on their own platform:

| Platform | Command | Output / installation |
| --- | --- | --- |
| macOS | `npm run tauri build -- --bundles app,dmg` | `src-tauri/target/release/bundle/macos/oxAudit.app` and `bundle/dmg/`; copy the app to Applications or open the DMG |
| Linux | `npm run tauri build -- --bundles deb,appimage` | `src-tauri/target/release/bundle/deb/` and `bundle/appimage/`; install the generated `.deb` with `sudo apt install ./<filename>.deb`, or make the AppImage executable and launch it |
| Windows | `npm run tauri build -- --bundles nsis,msi` | `src-tauri\target\release\bundle\nsis\` and `bundle\msi\`; run the generated installer for your architecture |

`npm run tauri dev` is the development app with hot reload. Bundle production
runs the configured frontend build automatically. The standalone CLI is built
or installed separately with the commands above. A local bundle may encounter
platform trust prompts; it is not a signed public release. Record the exact
artifact and environment when reporting installation problems.

Publishable release tags remain fail-closed: macOS requires signing and
notarization, Windows requires Authenticode configuration, and missing credentials
stop the release. Manual release dry runs can be unsigned and cannot publish.
Do not treat a local checksum as proof of publisher identity. Native pilot QA,
artifact hashes, and observed platform limits are recorded in
[the QA log](qa/2026-09-07-everyday-workflow.md).

## First useful check

Copy the [inert demo](../examples/pilot/README.md) into writable temporary space.
In the readiness wizard, continue without AI, choose that copied project and
click **Check project**. Home shows the source/dependency stages; the status bar
owns cancellation across pages. Open **View source findings**, inspect `js-eval`,
then use your configured editor to apply the correction. **Recheck finding**
provides covered-file evidence when compatible saved runs support it. A changed
or skipped scope must remain not evaluated. Skip/Escape closes setup, and
Settings can reopen it; choosing a folder alone never starts scanning.

Core source detection is local. Ordinary source scans may request optional CISA
KEV enrichment; this is not a source `--offline` mode. Dependencies normally need
advisory access, or a complete compatible saved receipt with `deps --offline`.
The smoke harness explicitly refuses optional network requests in its child
processes and does not supply fake advisory data.

## Complete consumer CI example

Copy [examples/ci/oxaudit.yml](../examples/ci/oxaudit.yml) to
`.github/workflows/oxaudit.yml` in a consuming repository whose protected main
branch is named `main`. This is a source finding gate; it does not claim a
complete dependency audit. Every action and the trusted tool checkout are pinned
to full commits. The CLI is built from trusted oxAudit commit
`e709594f25d3398592ebce4d35f374b9240e4113`, independently of target PR files.
The target checkout is data only: no npm install, build scripts, project commands,
submodules, or PR-supplied binaries are run. Review changes to the workflow and
`.oxaudit/policy.json` as changes to your security gate.

1. Provide `OXAUDIT_READ_TOKEN` with **read-only contents access to oxAudit**.
   A narrowly scoped fine-grained repository token is sufficient when its owner
   can access that private repository. The consuming repository's default token
   does not automatically read a different private repository. The token is used
   only by trusted checkout and is not persisted in Git config.
2. Merge the workflow to main and let a **push** run finish successfully. It
   publishes a baseline artifact named for that exact main commit, with tool
   commit, target commit, workflow run ID, and completed canonical source run ID.
   Main records the backlog without a severity gate. A PR downloads the baseline
   only from this workflow's successful **push-to-main** run at the PR's base SHA,
   validates its provenance, and gates new high/critical findings. No PR step
   publishes the authoritative baseline. Missing, expired, inaccessible, or
   incompatible baselines fail and require a successful main run before retry.
   Artifacts retain baselines for 90 days (subject to repository retention caps);
   keep main's baseline available, rerun its workflow if expired, and update/rebase
   old PRs to a supported base. Change the tool pin deliberately and regenerate
   main's baseline before relying on it in PRs.
3. Require the `source` job in branch protection. The scan runs once to JSON in
   a fresh isolated database. It lists the completed canonical source run and
   exports SARIF from that same run. Exit **0** passes, **1** retains reports then
   fails the findings gate; **2** (usage/invalid baseline) and **3** (scan or
   coverage failure), missing output, failed export, or no completed run fail.
   Reports still upload on scan failure when present. An artifact upload failure
   remains a workflow failure.

A report from a reused desktop/history database may include resolved historical
rows while `summary.totalFindings` counts current observations. The example and
pilot use a fresh database per source scan, so their JSON baselines contain that
scan's observations. File-only baseline absence is **no longer observed (coverage
unverified)**; it does not prove a verified fix. Canonical `targetLabel` is a
human display name, not a trusted absolute project identifier.

**Fork PR constraint:** GitHub does not provide repository secrets to normal fork
PR workflows. A fork cannot acquire this private tool with the example token; the
job intentionally fails with “no scan performed.” A maintainer with access must
run the pinned CLI locally against a separate PR checkout and a trusted main
baseline, then record the evidence through the team's review process. Do not
silently mark the automated job passed or expose the token with
`pull_request_target`. A reusable public tool artifact or an approved isolated
maintainer workflow is future work; this example does not invent either.
See GitHub's [fork workflow restrictions](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflows-in-forked-repositories).

The example uploads downloadable Actions artifacts and requires `contents: read`
and `actions: read`. It does not require paid code-scanning publication. In this
repository, CodeQL analysis and SARIF artifact retention stay required, as does
the self-scan. Only publication to GitHub code scanning is optional, enabled by
the explicit repository variable **`OXAUDIT_CODE_SCANNING=true`** after an owner
has verified availability and enabled the capability. On 2026-09-07 the repository
API returned 403, “Code scanning is not enabled for this repository.” No capability,
payment, or visibility setting was changed. Upload jobs include `actions: read`,
`contents: read`, and `security-events: write`; unavailable opt-in uploads fail
visibly. See GitHub's [SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

Local actionlint and executable shell checks validate the example, but do not
establish that it ran in a consumer's GitHub repository. The pilot record states
what was actually exercised.

## Contributor workflow shell tests

`npm test` and `npm run test:unit` do not require Bash or jq. The consumer
workflow's executable shell contracts are separate:

```bash
npm run test:ci-shell
```

Run that command in Ubuntu 24.04 with Node 22, the locked npm dependencies,
Bash, and jq. Install the shell tools with
`sudo apt-get update && sudo apt-get install --no-install-recommends -y bash jq`.
These tests use POSIX executable fixtures; Windows contributors should use an
Ubuntu environment for this command. It is optional for local desktop installation
but a required step in the repository's Ubuntu CI frontend job, which installs
Bash and jq explicitly. Missing prerequisites fail the command; the contracts
are not silently skipped. Only the additional real-CLI integration case requires
`PILOT_REAL_CLI` and remains opt-in, as recorded in the pilot evidence.

## Existing CI corrections and their verification boundary

Linux CI disables dev/test debug symbols and incremental objects, removes the
redundant benchmark/provenance test build (both still run in the complete workspace
suite), and runs the same detection threshold command using the dev build.
Formatting, all-feature workspace tests, strict Clippy, reduced grammar builds,
and precision/recall thresholds remain required. Release build profiles and
native signing policy are unchanged.

Windows MSVC links the Common-Controls v6 manifest into executable targets,
including the library unit-test harness, following
[Tauri's upstream workaround](https://github.com/tauri-apps/tauri/blob/dev/examples/api/src-tauri/build.rs)
for [STATUS_ENTRYPOINT_NOT_FOUND](https://github.com/tauri-apps/tauri/issues/13419).
Tauri's duplicate app resource manifest is disabled only on that MSVC path; other
targets keep the ordinary build behavior. The manifest source is
[Tauri's tauri-build manifest](https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-build/src/windows-app-manifest.xml),
adopted under Apache-2.0 with attribution in NOTICE. A failure-only Windows step
captures executable imports and embedded manifest diagnostics. macOS compilation
does not verify Windows loading; the pushed Windows job is the acceptance check.
