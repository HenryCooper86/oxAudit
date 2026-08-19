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

## Tier 1 — take these next

### 1. Steer / follow-up queue · value: high · effort: S–M
**y-agent:** `chat-panel/steerCoalescing.ts`, `chat-box/SteerChip.tsx`, `FollowUpQueue.tsx`.

Today, sending a message while a turn is running is impossible — the composer is
disabled for the whole agent loop. y-agent lets you type mid-run; the message is
coalesced into a steer chip and injected at the next loop iteration boundary.

For a research agent this is the single biggest quality-of-life gap: watching the
model grep the wrong directory for 30s with no way to redirect it is the common case.

*Needs:* a pending-steer slot on the loop state, a check at the top of each
iteration in `loop_engine.rs`, and a chip above the composer. No new backend
concepts — the loop already has iteration boundaries and an `AtomicBool` cancel.

### 2. Rewind to a turn · value: high · effort: S
**y-agent:** `chat-panel/RewindPanel.tsx`, `hooks/useRewind.ts`, `y-storage/checkpoint.rs`.

`sessions.truncate(id, keep)` already exists and is already used by Clear. Rewind
is that primitive plus a UI: hover a user message → "rewind here" → truncate to
that index and re-prime the composer with the original text.

Cheap, and it directly serves the "I asked the wrong question, back up" loop that
dominates vuln triage. We do **not** need y-agent's file-journal rewind — our tools
are read-only, so there is nothing to un-write.

### 3. Chat search · value: medium-high · effort: S
**y-agent:** `ChatSearchToolbar.tsx`, `chat-box/searchHighlightUtils.ts`, `HighlightedText.tsx`.

Find-in-conversation with match highlighting and next/prev. Sessions get long fast
when the agent is dumping grep output; scrolling is currently the only option.

*Note:* the `--search-match-bg` / `--search-match-active-bg` tokens were removed
from `index.css` because nothing consumed them. Re-add them (values are in
y-agent's `styles/index.css`) when this lands.

### 4. Todo panel · value: medium · effort: S
**y-agent:** `chat-panel/AgentTodoPanel.tsx`, `agentTodoState.ts`, `agentTodoResult.ts`.

The `todo` tool is already implemented and callable — its output just renders as a
generic tool card. y-agent pins it as a live checklist panel. Nearly free given the
tool exists, and it makes multi-step research legible.

### 5. Per-tool rate limiter · value: medium · effort: S
**y-agent:** `y-tools/rate_limiter.rs` (~40-line token bucket).

`cve.rs` already rate-limits NVD. There is no bucket in front of `web_fetch` or
`query_osv_package`, so a looping agent can hammer OSV. The bucket is small and
self-contained.

---

## Tier 2 — real value, bigger builds

### 6. Context compaction · value: high · effort: M
**y-agent:** `y-context` sampling + compaction, `chat-box/ContextResetDivider.tsx`, `contextResetUndo`.

Long sessions currently just grow until the provider rejects the request. y-agent
does a preflight token estimate, summarizes the older half, and marks the seam with
an undoable divider.

*Blocker to note:* this needs a per-model `context_window` value, which the original
P1 notes already flagged as unfinished. That's the first step.

### 7. Command palette / slash commands · value: medium · effort: M
**y-agent:** `input-area/CommandMenu.tsx`, `lib/commandMap.ts` (31KB — most of it is theirs, not ours).

`/scan`, `/cve`, `/resume`, `/clear`, `/copy` typed into the composer. Take the
menu mechanics and define our own small command map; do not port their command set.

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
| Setup wizard | `wizard/SetupWizard.tsx` | Nice first-run polish; Settings already does the job |
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

`1 → 2 → 4` is one cohesive slice (steer, rewind, todo panel) that lands entirely
in the chat surface and needs no new backend concepts — roughly a week, and it is
where the day-to-day friction is. `3` and `5` are small enough to ride along.

`6` (compaction) is the next structural piece and should start with the
`context_window` field that P1 left unfinished.
