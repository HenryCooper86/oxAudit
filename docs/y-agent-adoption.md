# Adopting y-agent into VulnCompanion — Design, Architecture & AI-Harness Study

> Research date: 2026-08. Source studied: https://github.com/gorgiaxx/y-agent (`main`).
> **Update 2026-08-19:** the visual layer is now ported — see
> [`design-system.md`](./design-system.md). Remaining feature candidates are ranked in
> [`y-agent-port-candidates.md`](./y-agent-port-candidates.md).
> Deep-dive reports with full code sketches: [`yagent-research/adoption-report.md`](../yagent-research/adoption-report.md)
> (tool loop, guardrails, transcripts) plus the three subsystem studies summarized here.

y-agent is a Rust-first, model-agnostic agent harness (Codex-class): it wraps LLMs
with context management, tools, planning, delegation, permissions, persistence and
diagnostics. It is a **20-crate monorepo** — far bigger than VulnCompanion needs.
This document is the "what do we steal" filter: the ideas, contracts, and patterns
worth adopting, and — just as importantly — the machinery that exists to manage
scale we do not have.

---

## 1. The one architectural idea to steal first

**y-agent's entire "agent feel" comes from a single architecture decision:**

> The Rust backend emits a **typed, run-correlated progress event stream**
> (`chat:started` / `chat:progress` with `TurnEvent` variants / `chat:complete` /
> `chat:error`), and the frontend consumes it into a **per-session ordered list of
> display segments**.

Every UX feature in their GUI — streaming text, thinking blocks, tool cards,
steer chips, status bar — is just a renderer over that event stream.

VulnCompanion already uses exactly this pattern for scans (`scan://progress`,
`deps://progress`). **Extending it to the AI chat is the single highest-leverage
change**: it turns the Assistant from "a chat page" into "an agent tool" and is
the foundation for everything else below.

---

## 2. Design principles worth adopting (from `docs/guides/ARCHITECTURE.md`)

| y-agent principle | What it means | Adopt? |
|---|---|---|
| **Strict layering, mechanically enforced** | Core traits (`y-core`) ← infrastructure (`y-provider/y-context/y-storage`) ← capabilities (`y-tools/…`) ← orchestration ← service (`y-service`) ← presentation (GUI/TUI/CLI). Enforced by a cargo xtask that rejects outward edges. | **Yes, informally.** Our equivalent: `models`/`ai`/`scanners` = core; `commands.rs` = service; React = presentation. Keep business logic out of the UI. A tiny `cargo test` that greps for forbidden imports is enough to enforce it. |
| **Contracts over ad-hoc code** | Cross-cutting wire formats are typed and documented: Tool Call Protocol, Provider Attempt Contract, Safe File Mutation Contract, Session Event Contract. | **Yes.** Our AI ↔ Rust ↔ React contract should be one typed `TurnEvent` enum, not ad-hoc payloads. |
| **Bounded loops with dual budgets** | Model-turn loop capped by `max_iterations` (default 10) **and** `max_tool_calls` (≈20–30); trip → blunt system message "budget exhausted — finish with what you have". | **Yes.** The #1 protection against runaway AI. |
| **Fail closed for security** | Deny is bypass-immune; unknown → ask or deny; explicit rules beat mode overrides. | **Yes.** Our permission model: read-only tools auto-allowed, everything else asks. |
| **Optimistic streaming, reconciled to a snapshot** | Streaming events are a live projection; the final `TurnResult.tool_calls_executed` snapshot is the source of truth on reload. | **Yes.** Don't lose executed tools on a dropped event. |
| **Provider attempt contract** | Retry only transient pre-output failures (5xx/network); never replay partial stream content; auth/quota never auto-retried; `Retry-After` honored. | **Yes.** Small, testable, big robustness win. |
| **Compaction lifecycle** | Estimate before every request (preflight) → background compaction when over threshold → safe ranges never split a tool call from its result → fingerprint-guarded cache → emergency in-memory compaction + one retry on overflow. | **Yes, simplified.** Preflight + summarize-old-turns + "never compact the system prompt". |
| **Per-turn checkpoints** | State is persisted *before* each LLM call so cancel/error resumes from real state. | **Yes, light version.** Persist partial tool results on cancel; JSONL transcript per session. |
| **Fail-closed provenance/trust** | Project config is only merged after the user trusts the workspace identity. | **Later.** Relevant when AI tools can act on scanned projects. |

---

## 3. AI harness — what to adopt (y-provider / y-context / y-prompt / y-diagnostics)

### Adopt — high value

| # | Item | Verdict | Why | Effort | Sketch |
|---|---|---|---|---|---|
| 1 | **SSE streaming chat** | **MUST** | Biggest UX jump; foundation for tools + usage. ~150 lines. | S (1 day) | `stream: true` POST → `resp.bytes_stream()` → incremental UTF-8 `SseDecoder` (copy `sse.rs`: `extract_sse_data`, multi-byte remainder) → parse `choices[0].delta.content` → emit `ai://delta`, `ai://usage`, `ai://done`, `ai://error`; React appends to a streaming bubble. |
| 2 | **Error classification + bounded retry** | **MUST** | Turns flaky/misconfigured endpoints into usable app. | S | `enum LlmError { RateLimited{retry_after}, Auth, ModelNotFound, ContextWindowExceeded, Server, Network, Parse }`; classify from status + body heuristics; RateLimited → honor `Retry-After` once; 5xx/network → 1s/2s/4s backoff (max 2, 60s budget); streaming retries only the handshake. |
| 3 | **Tool-call accumulation from streamed deltas** | **MUST** | The mechanism that makes tools work over streaming. ~60 lines, copyable. | S | `ToolCallAccumulatorSet` keyed by delta `index`, appends argument fragments, handles `index: None` by allocating sequential slots (their Gemini-compat fix); flush on `[DONE]`. |
| 4 | **Token budget preflight + compaction** | **MUST** | Long vuln-research chats (findings + CVE text + code) are our core case; prevents silent context-window failures. | M (1–2 d) | `estimate_tokens` (chars/4 + 4/msg overhead) → if ≥85% of user-editable `context_window` → `compact_history(messages, retain=10)`: same backend summarizes the old prefix into one `[Compaction summary]` system message (never compacted again); preserve CVE IDs / file paths / URLs in the summary; truncation fallback on failure — never fail the turn. |
| 5 | **Multi-provider via one trait + OpenAI-compat backend** | VALUABLE | One `base_url`+`model` covers OpenAI, all OpenAI-compatible gateways, Gemini's compat surface, Ollama `/v1/chat/completions`. | M | `trait LlmBackend { async fn chat_stream(...) }` + `OpenAiCompatBackend`; a future `AnthropicBackend` plugs in behind the same trait. |
| 6 | **Prompt sections + budget truncation** | VALUABLE | Deterministic prompt assembly instead of magic constants; truncate long embedded code head+tail. | S | `PromptBuilder { sections: Vec<{id, content, priority}> }` assembled in Rust under a budget; settings `system_prompt` becomes "custom instructions" appended last; `truncate_tool_result(content, 20k)`. |
| 7 | **Per-conversation token + cost tracking** | VALUABLE | "#1 user-trust feature" — "this analysis cost $0.03"; seed of budgeting. | S | `conversation_usage` rows (model, in/out tokens, `cost_usd` via per-model price table); `stream_options.include_usage`; chat footer "Tokens · $". |
| 8 | **"Test connection" health check** | VALUABLE | 1-token probe with classified result in Settings. | S | Reuse our existing `test_ai_with`; return classified `LlmError` instead of raw HTTP status. |

### Deliberately skip (scale machinery we don't have)

- **Provider pool / router / freeze-thaw / health checker** — exists to manage many providers with failover; we have one endpoint.
- **Progressive / intra-turn / superseded pruning** — agent-loop machinery for tool-heavy multi-step workflows. *Revisit `superseded.rs`'s "blank a superseded tool result" pattern when we add file-reading tools.*
- **`RecallStore` hybrid text/vector memory** — needs embeddings; only with a memory feature.
- **Full Trace/Observation/Score SQLite store + replay/search** — overkill vs. a usage table.
- **Prompt SectionStore / TOML / hot-reload / mode overlays** — single-screen app.

---

## 4. Tools & the agent loop — what to adopt (y-tools / y-service / y-guardrails)

### Tool system: adopt the *shape*, 10 tools, all read-only except ask_user/todo

`ToolDefinition` = `{name, description, help?, parameters (JSON Schema Draft 7 — injects verbatim into OpenAI `tools[]`), result_schema?, category, is_dangerous}` + `Tool::execute(ToolInput) -> Result<ToolOutput, ToolError>` with `is_read_only()` / `is_destructive()` flags and stable `ToolError` codes (`permission_denied`, `rate_limited`, …) + `is_retryable()`. This is **MUST** — it is exactly OpenAI function-calling.

**Proposed tool set (modeled on y-agent builtins):**

| Tool | Modeled on | Spec (1 line) |
|---|---|---|
| `read_file` | FileRead | path, line_offset, limit ≤2000, include_line_numbers → content + has_more_lines; rooted in the scanned project |
| `grep_project` | Grep | pattern, path?, output_mode (content/files/count), context lines, head_limit ≤250 |
| `glob` | Glob | pattern, max_results ≤200, mtime-sorted |
| `run_scan` | custom | scan_type ∈ source/secret/deps, path? → findings JSON (reuses existing scanners) |
| `search_cve` | custom | query, limit ≤25 → compact NVD/OSV list |
| `get_cve_detail` | custom | cve_id → full record (already have the command) |
| `query_osv_package` | custom | ecosystem, name, version? → OSV vulns (already have the command) |
| `web_fetch` | WebFetch minus Chrome | url, max_bytes ≤256KB → text; deny non-http(s); rate-limited |
| `ask_user` | AskUser | 1–4 questions × 2–6 options → answers (blocks loop on modal, 3-min timeout) |
| `todo` | Todo | op add/update/complete → list; loop stops cleanly if model stops with open items |

**Safety posture:** read-only-by-default means the whole security model is
"read-only tools auto-allowed; destructive/ask tools require user click-through."

### Bounded agent loop (MUST — minimal, single-agent)

State machine: `enum TurnState { Model, Tool, Done }` + `TurnBudget { iterations: 10, tool_calls: 30 }`.
Loop: check `AtomicBool` cancel → iteration budget → `chat(messages, tools)` →
no tool_calls → todo-reminder check → `Done`; else for each tool_call → call
budget → `permission::classify` (Allow/Ask/Deny) → execute or HITL modal →
loop-guard record → append `Role::Tool` result → back to Model.
History messages are the single source of truth.
**Skip** plan/loop orchestration, sub-agents, workflow DAGs — vuln research
(read → grep → scan → CVE → summarize) fits one bounded turn.

### Guardrails (MUST subset)

- **Permission allow-list**: `dangerous → Ask, read_only → Allow, else Deny (fail closed)`; Deny appends "blocked by policy — do NOT retry this tool".
- **HITL modal**: `PermissionRequest` event → React overlay (tool name, args preview, reason, Approve/Deny, 120s auto-deny) → `respond_permission(request_id, decision)` resolving a Rust `oneshot`.
- **Loop guard**: redundant tool call (same tool + args-hash ×3) → force-stop "stop and reassess". ~40 lines; the key one for a research agent that could re-grep the same pattern forever.
- **Output guard** (VALUABLE): filter LLM output through our existing secret-regex rules so the model can't echo raw secrets into the transcript.

**Skip:** exec-policy DSL (until a shell/file-edit tool exists — the DSL design is worth copying then), taint, risk scoring, permission modes, LLM-output middleware stack.

---

## 5. Product surface — what to adopt (y-gui / y-storage / y-knowledge / y-skills / y-scheduler)

| # | Item | Verdict | Why | Sketch |
|---|---|---|---|---|
| 1 | **Streaming bubble with interleaved segments** | **MUST** | The "agent feel" (see §1). | `InterleavedSegment = {text | reasoning | tool_result}` built from events in arrival order; a `streaming-{id}` placeholder message so tool cards render before first text; persist per-iteration metadata so history replays the exact segment order. |
| 2 | **Tool-call cards, live status** | **MUST** | Users must *see* tools run or it feels like magic. | Card = icon + name + running/success/error + duration; click → args (pretty JSON) + result with raw/formatted toggle + copy; **upsert by `tool_call_id` in place**; cancelled → "Cancelled before result". |
| 3 | **Session persistence + sidebar + resume** | **MUST** | Research continuity is the product; in-memory chat makes sessions disposable. | SQLite `sessions` + `chat_messages` (or JSONL per session + `sessions.json` index); commands `session_list/create/get_messages/rename/delete/truncate/fork`; auto-title + `session:title_updated`; sidebar with search/sort/streaming dot/context menu; resume dialog on launch. |
| 4 | **Thinking/reasoning blocks** | VALUABLE | OpenAI-compat endpoints increasingly stream `reasoning_content`; ~40 lines. | `ThinkingCard`: pulsing dot + elapsed timer while streaming → static "Thought" + expand. Fallback: strip `<think>` tags from final content. |
| 5 | **Status bar: model + tokens + cost + context-occupancy** | VALUABLE | The most "pro tool" element per line of code in their repo. | Footer shows model, cumulative tokens/cost, context-used bar (warn >80%). |
| 6 | **Knowledge base of findings/CVEs + `kb_search` tool** | **MUST (minimal)** | Turns one-off scans into an accumulating, AI-queryable corpus — "what did I already find about this CVE?". | After each scan/CVE view, chunk findings/CVEs into `kb_chunks` (kind/source/title/chunk, ~300–600 chars); in-process TF/BM25 index (~150 lines, lift `bm25.rs`); register `kb_search(query, kind?, limit)` as a tool; optional top-3 auto-inject into the prompt. Skip embeddings, L0/L1 tiers, collections. |
| 7 | **Skills as markdown packs** | VALUABLE | Users add analysis methodologies without code changes; y-agent ships a real security pack (drozer usage). | `skills/` dir; parse `name/description/domain/enabled/max_tokens` frontmatter; inject enabled `root.md` into the system prompt under budget; ship starter packs ("CVE triage methodology", "OSV vs NVD data quality", optionally a drozer pack modeled on theirs). Skip versioning/lineage/evolution. |
| 8 | **Scheduler for recurring scans** | VALUABLE | "Re-scan weekly / re-check deps nightly" is high-trust for a security tool. | `scheduled_scans` table; tokio tick loop evaluating Interval/Cron triggers; **missed-fire recovery on startup** (skip/catch_up/backfill — their `recovery.rs`); results → KB entries; "Scheduled" section on Dashboard. Skip Event triggers and DAG workflow editor. |
| 9 | **Steer chips / follow-up queue** | VALUABLE (simplified) | Type while the agent works; tap to inject. | Queue per session; "steer" = inject as next turn input; `SteerChip` rendered inline at injection position. |
| 10 | **Message feedback + turn-level undo** | VALUABLE | Copy-final-answer + thumbs; "rewind to turn N" = truncate messages after checkpoint. | Skip the file-journal restore machinery (our AI reads code, doesn't edit user files). |
| 11 | **Design tokens + compliance test** | VALUABLE (cheap) | Semantic naming (`surface-*`, `text-*`, `accent-*`, status colors), strict 4px/8px radius rule, one test grepping CSS/TSX for violations. | Adopt the token discipline; skip custom window chrome for now. |

---

## 6. What NOT to adopt (and why)

- **Provider pool / router / freeze-thaw / health daemon** — multi-provider failover machinery for a single-endpoint app.
- **Plan / Loop orchestrators, sub-agents, agent swarm** — orchestration scale; vuln research fits one bounded loop.
- **ToolSearch lazy loading / taxonomy / dynamic tools / MCP** — pays off only at 25+ tools; revisit MCP only if you want external tool servers.
- **exec-policy DSL, taint tracking, risk scoring** — until we have a shell/file-write tool.
- **Full file-journal rewind** — our AI doesn't mutate user files.
- **Workspaces + trust control, capability packs, bot adapters, web API, agent studio, image generation** — different product.
- **Full knowledge pipeline (embeddings, L0/L1 chunk tiers, collections, lifecycle)** — BM25 over plain chunks is enough.
- **Skills evolution/lineage/experience journals** — one manifest parser + folder is enough.

---

## 7. Consolidated adoption roadmap

> **Status (2026-08):** P1 — **implemented**. SSE streaming chat with a typed
> `ai://started|event|done|error` event bus, `LlmError` classification with
> bounded retry (429 `Retry-After`, 5xx/network backoff, never retry auth),
> per-conversation token+cost tracking (`usage.json` + Settings totals),
> streaming UI with live `ThinkingCard` for `reasoning_content`, and chat
> cancellation. Tests: 24 passing (SSE decoder, error classifier, cost model).
>
> P2 — **implemented**. Agentic layer: 10 read-only research tools
> (`read_file`, `grep_project`, `glob`, `run_scan`, `search_cve`,
> `get_cve_detail`, `query_osv_package`, `web_fetch`, `ask_user`, `todo`) with
> JSON-Schema definitions injected into the stream; tool-call accumulation from
> streamed deltas (`index: None` sequential-slot fix); bounded agent loop
> (10 iterations / 30 tool calls, budget-exhaustion note, `AtomicBool` cancel);
> allow/ask/deny permission pipeline with HITL `ApprovalModal` (120s auto-deny,
> deny appends "do NOT retry"); `LoopGuard` (redundant ×3 + oscillation A,B,A,B);
> live `ToolCallCard` rendering with in-place status updates and per-turn tool
> records attached to assistant messages; `ask_user` interaction modal;
> `set_active_project` wiring so tools operate on the scanned project. Tests:
> 32 passing (added accumulator + guardrails suites).
>
> P3 — **implemented**. Session persistence: JSONL transcript per session +
> `sessions.json` index (modeled on y-agent's `transcript.rs` — append-only,
> corrupt lines skipped on read), commands
> `session_list/create/get_messages/append/rename/delete/truncate`, heuristic
> auto-title from the first user message, session sidebar with search/active
> highlight/streaming dot/inline rename/two-step delete/New Chat, resume-most-
> recent on launch, per-session usage aggregation (session id = conversation
> id), per-turn persistence of user + assistant messages including tool
> records (tool cards survive reload), Clear = truncate-to-0, and per-session
> project path restored on resume. Tests: 37 passing (added session-store
> suite).
>
> **P-design — implemented (2026-08-19).** y-agent's two-layer token model
> (`:root`/`[data-theme]` runtime variables aliased into Tailwind via `@theme
> inline`), both themes, the 4px/8px radius contract, the sm/md/lg elevation
> scale, the NavSidebar-style 240px rail, the 52px header with display-italic
> title, `ui/` primitives (Button/Input/Textarea/Select/Switch/SectionLabel), and
> a port of their `designSystemCompliance.test.ts`. Deviations: no Google Fonts
> import (offline/privacy), a five-step `sev-*` severity scale with no y-agent
> counterpart, and a tinted rather than solid `danger` button. Tests: 47 passing
> (added design-contract + theme suites).
>
> > P1 left over for later: per-model `context_window` field (P5 preflight), and
> wiring `analyze_finding`/`research_cve` onto the streaming path.

| Phase | Contents | Est. effort | Outcome |
|---|---|---|---|
| **P1 — AI harness core** | SSE streaming chat + typed `TurnEvent` bus · error classification + bounded retry · test-connection · thinking blocks · per-conversation token/cost tracking | ~1 wk | Assistant feels fast & robust; usage visible |
| **P2 — Agentic** | Tool registry (10 tools, JSON-schema) · bounded loop (10 iters / 30 calls) · permission allow-list + HITL modal · loop guard · tool-call cards | ~1–1.5 wk | AI can actually research: read/grep/scan/CVE tools with visible, gated execution |
| **P3 — Product** | Session persistence (SQLite/JSONL) + sidebar + resume + auto-title · status bar | ~1 wk | Research continuity; "real tool" feel |
| **P4 — Companion value** | Knowledge base (BM25) + `kb_search` · skills packs (CVE triage, drozer) · scheduler for recurring scans | ~1.5 wk | Accumulating, queryable security memory; scheduled re-scans |
| **P5 — Polish** | Context compaction (preflight + summarize) · steer/follow-up queue · message feedback · rewind-to-turn · output guard (secret filter) · rate limiters | ~1 wk | Long-session safety; trust features |

Total ≈ **5–7 weeks of focused work**, P1+P2 being the highest value/effort
slice (~2–2.5 weeks). Each phase is independently shippable.

---

## 8. First concrete step (P1, ~1 day)

1. `src-tauri/src/ai/sse.rs` — `SseDecoder` (copy y-agent's `extract_sse_data` + UTF-8 remainder handling).
2. `src-tauri/src/ai/errors.rs` — `LlmError` enum + classifier (status/body heuristics) + `RetryPolicy`.
3. `src-tauri/src/ai/chat.rs` — `stream_chat` command: POST `stream:true`, parse chunks, `app.emit("ai://delta" | "ai://usage" | "ai://done" | "ai://error")`, keep `stream:false` fallback.
4. `src/lib/chatStream.ts` + `src/components/chat/StreamingBubble.tsx` — listen, append, replace the current blocking send in `Assistant.tsx`.
5. `src-tauri/src/ai/usage.rs` — `conversation_usage` table + footer.

Reference implementation files to lift from: `y-provider/src/sse.rs`,
`y-provider/src/error_classifier.rs`, `y-provider/src/pool.rs` (retry loop),
`y-provider/src/tool_call_accumulator.rs`, `y-context/src/sampling.rs` +
`compaction.rs` (P5), `y-service/src/loop_orchestrator.rs` (P2), `y-tools/src/builtin/*` (P2), `y-storage/src/transcript.rs` + `y-gui` `ChatSidebarPanel.tsx`/`StreamingBubble.tsx` (P3), `y-knowledge/src/bm25.rs` (P4), `y-scheduler/src/recovery.rs` (P4).
