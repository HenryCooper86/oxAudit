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
| **Dashboard** | At-a-glance stats, quick actions, recent scan history |
| **Sessions** | Every AI conversation is **persisted** (JSONL transcripts + index) with a searchable session sidebar, resume-on-launch, auto-titles, per-session token/cost totals, and tool-call history that survives reload |

## Screens

- **Dashboard** — overview and quick actions
- **Source Scan** — folder picker, scan options, live progress, filterable findings grouped by file, JSON report export
- **Dependencies** — lockfile discovery, OSV check, vulnerable-package table with fixed versions and reference links
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
  src/cve.rs          NVD client with rate limiting + caching, OSV enrichment
  src/ai.rs           OpenAI-compatible chat client + prompt builders
  src/commands.rs     Tauri commands (scan, deps, cve, ai, settings)
```

All scanning is local. Network calls go only to: NVD, OSV, and the AI endpoint you configure.

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

## Security notes

- API keys you configure are stored in the app config directory
  (`~/Library/Application Support/com.vulncompanion.app/settings.json` on macOS) —
  never in the scanned project.
- The secret scanner is heuristic: always confirm a finding is a real credential
  before rotating anything, and beware false positives from test fixtures.
- Live verification of secrets (calling AWS/GitHub to check tokens) is intentionally
  **not** performed; treat findings as candidates.

## Roadmap ideas

- Git history / commit-grep scanning
- Semgrep-style rule packs + custom rules
- SARIF export, SBOM (CycloneDX/SPDX) generation
- Streamed AI responses, offline CVE mirror
