# Security Policy

oxAudit is a security tool. It reads source code, parses untrusted lockfiles and
binaries, talks to remote advisory services, and — when you enable it — sends
context to an AI endpoint. A bug in any of those paths is a security bug, and we
would rather hear about it from you than from someone else.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub Security Advisories:

> **[Report a vulnerability](https://github.com/HenryCooper86/oxAudit/security/advisories/new)**
> (Security → Advisories → Report a vulnerability)

If that is not available to you, email the maintainer listed in
[`Cargo.toml`](src-tauri/Cargo.toml) with `oxAudit security` in the subject.

Useful things to include, to whatever extent you have them:

- The oxAudit version (`oxaudit-cli --version`, or the release you downloaded) and your OS.
- What an attacker gains, and what they need in order to attempt it.
- A reproduction — a fixture repository, a crafted lockfile, or a scan target.
- Whether you have published anything about it already.

You do not need a working exploit. A clear description of the flaw is enough.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement that a human has read your report | 3 working days |
| Initial assessment, with a severity and a plan | 10 working days |
| Fix released for a confirmed high or critical issue | 30 days from confirmation |
| Public advisory | With the fix, or sooner if already public |

If a deadline is going to slip, we will tell you before it does rather than
after. You will be credited in the advisory unless you ask not to be.

We do not currently run a bug bounty.

## Supported versions

oxAudit is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Everything else | No — upgrade |

## Scope

**In scope**

- Anything that lets a **scan target** affect the machine running oxAudit —
  malicious source files, lockfiles, SBOMs, binaries, or rule packs that cause
  code execution, path traversal outside the target, resource exhaustion, or
  file writes.
- **Prompt injection through scanned content** that causes the AI assistant to
  take an action the user did not approve — particularly anything that exfiltrates
  data through a tool call.
- Bypasses of the agent permission pipeline, the HITL approval gate, or the
  `web_fetch` egress allow-list.
- **Credential exposure**: API keys leaking into logs, transcripts, exported
  reports, crash output, or diagnostics bundles.
- Failures of the redaction path that let a detected secret reach a report,
  transcript, or event payload in cleartext.
- Tauri IPC or CSP weaknesses that let page content reach a privileged command.
- Findings integrity: anything that lets an imported document silently mutate
  local findings or review history, which the evidence model forbids by design.

**Out of scope**

- False positives and false negatives in scan rules. These are quality bugs —
  please file them as normal issues, they are genuinely welcome, and the
  Quality Lab screen exists because we take them seriously.
- Vulnerabilities in software oxAudit *invokes* but does not ship — cve-bin-tool
  and grype. Report those upstream.
- Vulnerabilities in the AI endpoint you configure.
- Attacks that need an already-compromised machine or an already-root attacker.
- Advisory data that is wrong upstream at NVD, OSV, KEV, or EPSS.

## Our own supply chain

The measures below are enforced in CI, not aspirational:

- Every GitHub Action is pinned to a full commit SHA, checked in CI by
  `tools/check-action-pins.mjs`. A tag can be repointed by whoever controls
  the action, and these workflows hold the signing keys.
- `cargo-deny` gates advisories, licences, and unexpected sources.
- `npm audit` and `dependency-review` gate JavaScript dependencies.
- CodeQL runs `security-extended` on the TypeScript surface.
- `cargo-fuzz` smoke-runs the bounded rule-pack parser on a schedule.
- The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

Release artifacts are signed, and each release publishes a CycloneDX SBOM of
oxAudit itself alongside SHA-256 checksums. If you are evaluating oxAudit for use
in a regulated environment, that SBOM is the artifact to point your reviewers at.

## Reporting a vulnerability *found by* oxAudit

If oxAudit found a vulnerability in someone else's project, report it to that
project, not here. If you need a starting point, most repositories expose a
private reporting channel at `https://github.com/<owner>/<repo>/security/advisories/new`.
