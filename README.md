# VulnCompanion — AI Vulnerability Research Companion

A cross-platform desktop app (Tauri v2 + React + Rust) that helps security analysts
and developers find CVEs, scan source code for vulnerabilities and leaked secrets,
scan applications for known vulnerable dependencies, and research vulnerabilities
with the help of an AI assistant.

![stack](https://img.shields.io/badge/Tauri-2-24c8db) ![stack](https://img.shields.io/badge/React-19-61dafb) ![stack](https://img.shields.io/badge/Rust-1.95-dea584)

---

## Features

| Capability | What it does |
|---|---|
| **Source code scanning** | 50+ dangerous-code patterns across JavaScript/TS, Python, Java, Go, C/C++, PHP, Ruby, Rust, plus generic rules (eval, exec, SQL injection, unsafe deserialization, `shell=True`, `strcpy`, weak crypto, hardcoded passwords, …), each mapped to a CWE with remediation guidance |
| **Secret scanning** | 30+ regex rules (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm/PyPI tokens, private keys, JWTs, bearer tokens, generic high-entropy API keys/passwords…) with **Shannon entropy** filtering and placeholder suppression |
| **Dependency scanning** | Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`, `pom.xml`, `requirements.txt` and checks every pinned package against the **OSV** vulnerability database (batch queries, fixed-version extraction, CVSS score computation from vector strings) |
| **CVE research** | Search the **NVD** API (keyword search, recent-modified filter, pagination, rate-limit aware, optional NVD API key), per-package OSV advisories, full CVE detail pages with affected products, references, CWEs and raw OSV records |
| **AI assistant** | Chat with any **OpenAI-compatible** endpoint (OpenAI, Ollama, LM Studio, vLLM, Groq, OpenRouter…). **Streaming responses** with live reasoning display, typed error handling with automatic retry, **per-conversation token & cost tracking**, cancellable turns, and an **agentic tool loop**: the AI can read files, grep/glob the scanned project, run scans, search NVD, query OSV, and fetch web pages — every tool call rendered live with a status card, gated by an allow/ask/deny permission pipeline with HITL approval, a loop guard, and dual iteration/call budgets. One-click "Ask AI" on every finding and "Generate research briefing" on every CVE |
| **Binary scanning** | Detects vulnerable components bundled inside compiled binaries and firmware images (statically linked OpenSSL, zlib, zstd, sqlite, …) with oxAudit's **own scanner** — no database to download, no external tool required — then looks each component up in NVD and OSV. Optionally also runs [cve-bin-tool](https://github.com/ossf/cve-bin-tool) or [grype](https://github.com/anchore/grype) if you have them installed; neither is bundled |
| **Dashboard** | At-a-glance stats, quick actions, recent scan history |
| **Sessions** | Every AI conversation is **persisted** (JSONL transcripts + index) with a searchable session sidebar, resume-on-launch, auto-titles, per-session token/cost totals, and tool-call history that survives reload |

## Screens

- **Dashboard** — overview and quick actions
- **Source Scan** — folder picker, scan options, live progress, filterable findings grouped by file, JSON report export
- **Dependencies** — lockfile discovery, OSV check, vulnerable-package table with fixed versions and reference links
- **Binary Scan** — file/folder target, cve-bin-tool detection with a first-class "not installed" state, live progress, components grouped with their CVEs
- **CVE Research** — NVD search + OSV package lookup + detail view with AI briefing
- **AI Assistant** — chat with code/context attachment
- **Settings** — AI endpoint config, scan defaults, ignored directories, NVD API key

## Architecture

```
src/                  React + TypeScript + Tailwind v4 frontend
  pages/              one file per screen
  components/         shared UI (finding cards, badges, progress…)
  lib/                typed invoke() wrappers, zustand stores, formatting
src-tauri/            Rust backend (Tauri v2)
  src/models.rs       shared serde models (camelCase ⇄ TypeScript types)
  src/scanners/       secrets.rs (rules + entropy engine), patterns.rs (source rules)
  src/deps/           lockfiles.rs (parsers), osv.rs (OSV client + CVSS math)
  src/binscan/        detect.rs (find cve-bin-tool), run.rs (spawn), report.rs (json2)
  src/cve.rs          NVD client with rate limiting + caching, OSV enrichment
  src/ai.rs           OpenAI-compatible chat client + prompt builders
  src/commands.rs     Tauri commands (scan, deps, cve, ai, settings)
```

All *oxAudit* scanning is local. oxAudit itself contacts only NVD, OSV, and the AI
endpoint you configure.

**Binary scanning is the exception**, because it runs a separate program. When you use
it, [cve-bin-tool](https://github.com/ossf/cve-bin-tool) makes its own network calls —
to its mirror at `cveb.in` and the advisory feeds it aggregates (NVD, OSV, GitLab
Advisory Database, Red Hat, curl) — unless you tick **Offline**, which restricts it to
its already-downloaded database. The feature is inert until you install cve-bin-tool.

## Development

Prerequisites: [Node.js ≥ 20](https://nodejs.org), [Rust ≥ 1.77](https://rustup.rs),
and the platform Tauri prerequisites (Xcode CLT on macOS, WebView2 on Windows,
webkit2gtk on Linux — see [Tauri docs](https://v2.tauri.app/start/prerequisites/)).

```bash
npm install
npm run tauri dev        # run the app with hot reload
npm run build            # type-check + build the frontend
cd src-tauri && cargo test   # run the scanner test-suite
npm run tauri build      # produce a distributable bundle
```

## Configuring the AI

1. Open **Settings → AI engine**.
2. Pick any OpenAI-compatible endpoint: set **Base URL** (e.g. `https://api.openai.com/v1`,
   `http://localhost:11434/v1` for Ollama, `http://localhost:1234/v1` for LM Studio),
   the **model** name, and an API key if required.
3. Enable the toggle and press **Test connection**.
4. Findings and CVEs now get an **Ask AI / Generate research briefing** button.

> The NVD API key (optional) raises the NVD rate limit from 5 to 50 requests per
> 30 seconds — get one free at https://nvd.nist.gov/developers/request-an-api-key.

## Binary scanning (cve-bin-tool)

oxAudit does **not** bundle [cve-bin-tool](https://github.com/ossf/cve-bin-tool). It is
GPL-3.0-or-later; bundling it would make oxAudit a distributor of GPL software, whereas
invoking a copy you installed is arms-length. Install it yourself:

```bash
pipx install cve-bin-tool     # recommended
# or: pip install cve-bin-tool
```

oxAudit finds it on PATH, falling back to `python3 -m cve_bin_tool`. If you keep it in a
specific environment, set the path in **Settings → Binary Scanning**; an explicit path
suppresses the fallbacks so you always scan with the copy you meant.

The first run downloads a CVE database and can take several minutes — the page shows
cve-bin-tool's own progress while it works, and the scan is cancellable.

> **Upstream bugs, and the workaround (checked 2026-08-20).** cve-bin-tool 3.4 cannot
> populate its CVE database out of the box: its NVD bootstrap aborts on a `403` from
> `nvd.nist.gov/rest/public/dashboard/statistics`, and a failed run then records an
> update timestamp that routes every later run into an empty incremental fetch. Both
> are small bugs — the container image in `docker/cve-bin-tool/` carries the fix, after
> which the fetch runs normally. **Set an NVD API key first**: the unauthenticated rate
> limit makes the initial download take hours. Full investigation, and a measured
> comparison against grype, in
> [`docs/binary-scanning-runtime.md`](docs/binary-scanning-runtime.md).

An experimental container runtime lives in `docker/cve-bin-tool/Dockerfile`. It supplies
the external programs cve-bin-tool needs but does not declare (`gsutil` for its mirror,
plus `cabextract`, `rpm2cpio`, `p7zip`, `zstd`). Build it yourself — the file is a
recipe, so oxAudit never distributes GPL software:

```bash
docker build -t oxaudit/cve-bin-tool:3.4 docker/cve-bin-tool
```

Lockfile scanning is deliberately **not** routed through it: **Dependencies** already
parses ten lockfile formats natively and queries OSV directly.

## Security notes

- API keys you configure are stored in the app config directory
  (`~/Library/Application Support/com.vulncompanion.app/settings.json` on macOS) —
  never in the scanned project.
- The secret scanner is heuristic: always confirm a finding is a real credential
  before rotating anything, and beware false positives from test fixtures.
- Binary scanning shells out to cve-bin-tool with arguments passed directly — never
  through a shell — and the target is canonicalized to an absolute path first. Note that
  cve-bin-tool extracts archives (ZIP/RPM/DEB/CAB/APK) to inspect them, so pointing it at
  untrusted firmware runs third-party extraction code on attacker-supplied input.
- Live verification of secrets (calling AWS/GitHub to check tokens) is intentionally
  **not** performed; treat findings as candidates.

## Roadmap ideas

- Git history / commit-grep scanning
- Semgrep-style rule packs + custom rules
- SARIF export, SBOM (CycloneDX/SPDX) generation
- Streamed AI responses, offline CVE mirror

## Licence

oxAudit is licensed under the **[Apache License 2.0](LICENSE)**. See
[`NOTICE`](NOTICE) for attribution, which the licence requires derivative works
to carry forward.

Two things the notice records, because they are easy to get wrong:

- **The external scanners are not distributed with oxAudit.** Binary scanning
  executes a copy of [cve-bin-tool](https://github.com/ossf/cve-bin-tool)
  (GPL-3.0-or-later) or [grype](https://github.com/anchore/grype) (Apache-2.0)
  that *you* installed. Invoking a program at arm's length carries no licensing
  obligation; bundling one would. `docker/cve-bin-tool/Dockerfile` is a recipe
  built on your machine, not an image we publish.
- **The detection signatures are original work.** They were derived from
  binaries whose versions were known independently — see
  [`docs/binary-signatures.md`](docs/binary-signatures.md) — and deliberately
  not transcribed from cve-bin-tool's GPL checkers.

Methodology studied and reimplemented from
[VulnHunter](https://github.com/capitalone/VulnHunter),
[VulHunt](https://github.com/vulhunt-re/vulhunt) and
[y-agent](https://github.com/gorgiaxx/y-agent) is credited in `NOTICE`. No source
was copied from any of them.
