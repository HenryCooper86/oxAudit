# What's left to port from y-agent

> Reviewed 2026-08-19 against `gorgiaxx/y-agent@main`.
> Companion to [`y-agent-adoption.md`](./y-agent-adoption.md) (the original study)
> and [`design-system.md`](./design-system.md) (the visual layer, now done).

P1–P3 of the original roadmap are **implemented**: SSE streaming with a typed
event bus, error classification + bounded retry, token/cost tracking, the 10-tool
registry, the bounded agent loop, the allow/ask/deny permission pipeline with HITL,
the loop guard, live tool cards, and JSONL session transcripts with a sidebar.

The visual layer is now also done — tokens, dual theme, radius/elevation contract,
shell, and primitives, enforced by `tests/designSystem.test.ts`.

What follows is everything else worth taking, ranked.

---

## Tier 1 — status

**Items 1–5 are implemented** (completed 2026-08-21). What shipped, and the one
design decision in each that is not obvious from the diff:

- **Steer** — the loop drains queued messages only at iteration boundaries, and
  `awaiting_tool_results()` asserts that placement, because injecting a `user`
  turn between an assistant `tool_calls` message and its `tool` results is
  rejected by the provider. The queue *closes atomically while empty* just
  before a run finishes, so a message is either taken by the run or refused and
  sent as a new turn — never silently dropped, and never both. A steer also tops
  the budgets back up to half and clears the loop guard, since the guard exists
  to catch the model circling, not a human redirecting it.
- **Rewind** — `planRewind()` decides the truncation as pure data. It refuses
  assistant turns: rewinding onto the model's own output would leave the
  preceding question answered by nothing. The transcript is truncated before the
  in-memory view, so a failed write never claims to have discarded turns that are
  still on disk.
- **Todo panel** — the `todo` tool now emits the whole list on every mutation, so
  the UI never reconstructs state from a sequence of operations, and
  `todo_list` restores it when switching back to a session between turns.

Full tier below.

### ~~1. Steer / follow-up queue~~ — DONE · value: high · effort: S–M
**y-agent:** `chat-panel/steerCoalescing.ts`, `chat-box/SteerChip.tsx`, `FollowUpQueue.tsx`.

Was the biggest quality-of-life gap: the composer was disabled for the whole
agent loop, so watching the model grep the wrong directory for 30s with no way to
redirect it was the common case.

*Shipped as:* `SteerQueue` (`agent/tool.rs`), `drain_steers`/`close_steers` and
`awaiting_tool_results` (`agent/loop_engine.rs`), the `steer_chat` command, an
`AiStreamEvent::Steer` variant, and queued chips plus a Steer button in the
composer.

### ~~2. Rewind to a turn~~ — DONE · value: high · effort: S
**y-agent:** `chat-panel/RewindPanel.tsx`, `hooks/useRewind.ts`, `y-storage/checkpoint.rs`.

Serves the "I asked the wrong question, back up" loop that dominates vuln triage.
We deliberately did **not** take y-agent's file-journal rewind — our tools are
read-only, so there is nothing to un-write.

*Shipped as:* `src/lib/rewind.ts` (`planRewind`) over the existing
`session_truncate` command, plus a hover control on every user turn.

### ~~3. Chat search~~ — DONE · value: medium-high · effort: S
**y-agent:** `ChatSearchToolbar.tsx`, `chat-box/searchHighlightUtils.ts`, `HighlightedText.tsx`.

Find-in-conversation with case-insensitive highlighting, wrapped next/previous
navigation, Enter/Shift+Enter controls, Escape, and Cmd/Ctrl+F. Highlighting is
deferred so long Markdown transcripts do not make the search input stutter.

*Shipped as:* `ChatSearchToolbar`, `SearchHighlight`, and pure navigation/split
helpers in `src/lib/chatSearch.ts`, using oxAudit's existing semantic tokens.

### ~~4. Todo panel~~ — DONE · value: medium · effort: S
**y-agent:** `chat-panel/AgentTodoPanel.tsx`, `agentTodoState.ts`, `agentTodoResult.ts`.

The `todo` tool was already callable but its output rendered as a generic tool
card, so multi-step research was hard to follow.

*Shipped as:* an `AiStreamEvent::Todos` variant emitted by the tool, the
`todo_list` command for restoring a plan between turns, and
`components/chat/AgentTodoPanel.tsx` pinned above the composer.

### ~~5. Per-tool rate limiter~~ — DONE · value: medium · effort: S
**y-agent:** `y-tools/rate_limiter.rs` (~40-line token bucket).

`cve.rs` already rate-limits NVD. Agent-driven network tools now also use shared,
per-tool token buckets from `AppState`, so separate conversations cannot each
start with a fresh burst. A refusal is emitted as a failed tool result with a
bounded retry time, which makes the limit visible in the existing tool card.

---

## Tier 2 — real value, bigger builds

### 6. Context compaction · value: high · effort: M
**y-agent:** `y-context` sampling + compaction, `chat-box/ContextResetDivider.tsx`, `contextResetUndo`.

Long sessions currently just grow until the provider rejects the request. y-agent
does a preflight token estimate, summarizes the older half, and marks the seam with
an undoable divider.

*Shipped:* settings carry a backward-compatible `context_window`, every agent
model turn emits estimated input + reserved output metadata, local preflight
stops requests that cannot fit, and the composer shows a live budget meter.
Automatic compaction is in: when the conversation exceeds the window, `run_turn`
summarizes the older turns into one dense system message (`agent/compaction.rs`)
and keeps the newest turns verbatim. The seam is durable — the answer records a
`compaction` marker (folded count + summary) in the transcript, so the
`ContextCompactedNotice` reappears after a reload — and the divider is undoable:
the most recent turn offers **Retry with full context**, which re-sends the
question uncompacted (`allowCompaction: false`) after a rewind, so a user who
raised the window or switched models can get a complete-context answer without
manual re-prompting. What remains open is only y-agent's heavier scaffolding —
regeneration/checkpointing beyond the last turn — which the transcript-preserving
model still does not need.

### ~~7. Command palette / slash commands~~ — DONE · value: medium · effort: S
**y-agent:** `input-area/CommandMenu.tsx`, `lib/commandMap.ts` (31KB — most of it is theirs, not ours).

*Shipped as:* `/scan`, `/cve`, `/resume`, `/clear`, `/copy` typed into the
composer, with a small listbox menu above the composer (`SlashCommandMenu`) and
a prefix matcher in `src/lib/slashCommands.ts`. Each command maps onto an action
that already existed — navigation, session switch, clear, clipboard copy — so a
slash command is a shortcut, never a second implementation. The global ⌘K
palette (`commandPalette.ts`) was already shipped separately.

### 8. Keyboard shortcuts · value: medium · effort: M
**y-agent:** `shortcuts/shortcutRegistry.ts`, `useKeyboardShortcuts.ts`, `settings/KeyboardShortcutsTab.tsx`.

A registry plus a rebindable settings tab. Worth it once the palette exists;
before that, a handful of hardcoded bindings is enough.

### 9. Knowledge base (BM25) · value: medium · effort: M–L
**y-agent:** `y-knowledge` (`bm25.rs`), `KnowledgePanel.tsx`, `useKnowledge.ts`.

This was P4 in the original plan and still reads right: a local corpus of advisories,
past findings, and notes with a `kb_search` tool, so the agent accumulates
project memory. **Skip** their embeddings/Qdrant path and L0/L1 chunk tiers — BM25
over plain chunks is enough at our scale.

### 10. Skills packs · value: medium · effort: M
**y-agent:** `y-skills`, `SkillsPanel.tsx`, `SkillImportDialog.tsx`.

Reusable prompt+tool bundles ("CVE triage", "auth review", "mobile drozer pass").
Take the manifest parser and folder convention only. **Skip** skill evolution,
lineage, and experience journals — that machinery exists to manage a scale we do not have.

---

## Tier 3 — worth knowing about, not now

| Feature | y-agent source | Why it waits |
|---|---|---|
| Scheduler / recurring scans | `y-scheduler`, `AutomationPanel`, `DagGraph` | Real value (nightly re-scan of a repo) but a large surface; wants the knowledge base first so results accumulate somewhere |
| Diagnostics / trace panel | `observation/DiagnosticsPanel.tsx` (41KB), `ObservabilityPanel.tsx` | We already track tokens and cost; full local tracing + Langfuse export is more than we need |
| ~~Setup wizard~~ — DONE | `wizard/SetupWizard.tsx` | A four-step GUI-first readiness flow now checks native scanning and advisory sources, treats AI as optional, persists completion, and can be reopened from Settings |
| Message feedback | `assistantFeedback.ts`, `messageFeedbackRendering` | Thumbs up/down only pays off if the signal goes somewhere |
| Mermaid + Monaco rendering | `MermaidBlock.tsx`, `MonacoEditorCore.tsx` | Monaco is a heavy dep for read-only code display; revisit if we add an editor |
| Background tasks panel | `BackgroundTasksPanel.tsx`, `ansiOutputParser.ts` | Belongs with the scheduler |
| Workspace trust | `WorkspaceTrustControl.tsx`, `y-core/trust.rs` | Their tools write files and run shell; ours are read-only, so the threat it mitigates does not exist here |

---

## Explicitly not porting

Unchanged from the original study, and re-confirmed on this pass:

- **Provider pool / router / freeze-thaw / health daemon** — multi-provider failover for a single-endpoint app.
- **Plan & Loop orchestrators, sub-agents, task delegation** — vuln research fits one bounded loop.
- **ToolSearch lazy loading, tool taxonomy, dynamic tools** — pays off at 25+ tools; we have 10.
- **exec-policy DSL, taint tracking, risk scoring** — all guard a shell/file-write sink we deliberately do not have.
- **MCP** — revisit only if external tool servers become a goal.
- **Bot adapters, web API, agent studio, capability packs, image generation** — different product.

---

## Suggested order

The Tier 1 chat slice is complete, along with the first-launch readiness wizard
and context-window metadata/preflight foundation.

**Context compaction (6)** is the next structural piece. It can now build on the
configured context window and live estimates rather than inventing another
parallel token-budget contract.
