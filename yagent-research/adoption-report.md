# y-agent → VulnCompanion Adoption Report

**Research basis:** raw source of `gorgiaxx/y-agent@main` — `y-tools` (registry/index/taxonomy/parser/validator/executor/rate_limiter/dynamic + 10 builtin tools), `y-service` (loop_orchestrator, plan_orchestrator, chat, agent_service/{mod,executor,llm,tool_dispatch,tool_handling,subagent}, user_interaction_orchestrator, task_delegation_orchestrator, message_builder), `y-guardrails` (permission_pipeline, exec_policy DSL, loop_guard, taint, risk, hitl, mode_manager, config), `y-core` (tool, permission_types, hook, agent, session, trust), `y-storage` (chat_message, transcript, session_store, checkpoint), plus `config/prompts/*` hints.
Local copies of every file cited: `yagent-research/`.

**Bottom line up front:** y-agent is a heavyweight multi-agent harness; VulnCompanion should adopt its *shape* (ToolDefinition + JSON Schema, a bounded model-turn loop with dual iteration/call budgets, an allow/ask/deny permission pipeline with HITL, per-session JSONL persistence) and skip everything that exists to manage scale (lazy tool loading, taxonomy, MCP, dynamic tools, plan/loop orchestration, taint, risk scoring, session trees, SQLite checkpointing).

---

## A. Tool system

### How y-agent does it

**Definition.** `y-core::tool::ToolDefinition` (y-core/tool.rs) is a plain serializable struct:
`name`, `description`, optional `help`, `parameters` (JSON Schema Draft 7, injected verbatim into the OpenAI `tools[]` array), optional `result_schema`, `category`, `tool_type` (BuiltIn/Mcp/Custom/Dynamic), `capabilities`, and `is_dangerous: bool`. Tools implement the `Tool` trait:

```rust
#[async_trait]
pub trait Tool: Send + Sync {
    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError>;
    fn definition(&self) -> &ToolDefinition;
    fn check_permissions(&self, input: &ToolInput, ctx: &PermissionContext) -> PermissionResult; // default: read-only→Allow, else Passthrough
    fn is_read_only(&self) -> bool;      // FileRead/Glob/Grep override → true
    fn is_destructive(&self) -> bool;    // ShellExec overrides → true
    fn as_any(&self) -> &dyn Any;
}
```

`ToolInput` carries `call_id`, validated `arguments`, `session_id`, `working_dir`, `additional_read_dirs`, an injected `command_runner` (so tools never spawn processes themselves), and `permission_mode`. `ToolOutput` = `{success, content: Value, warnings, metadata}`. `ToolError` has stable machine codes (`tool_not_found`, `permission_denied`, `stale_file`, `timeout`, `rate_limited`, …) and `is_retryable()` (Timeout/RateLimited/ExternalServiceError) so the loop can tell the LLM what is safe to retry.

**Registry & dispatch.** `y-tools::ToolRegistryImpl` (registry.rs) stores `Arc<dyn Tool>` + definitions in an `RwLock`, keeps a compact `ToolIndex` (name+description+category only — "60–90% token reduction"), rejects duplicate names, supports keyword/category search with a limit, and gates tools behind `check_fn` availability closures (cached 30 s, panic → fail-open 60 s grace) so schemas of unavailable tools are never sent to the LLM. `ToolExecutor` runs: validate arguments via `JsonSchemaValidator` (compiled `jsonschema::Validator` with a hash-keyed cache) → pre-execution middleware → execute → post-execution middleware. `RateLimiter` (rate_limiter.rs) is a per-tool non-blocking token bucket (`max_requests` per `window`, `retry_after` on deny).

**Lazy loading.** Only the compact index is injected at session start; the LLM calls the `ToolSearch` meta-tool to pull full definitions into a session-scoped `ToolActivationSet` (LRU, ceiling 20).

**Builtins (41–43 registered in builtin/mod.rs):** FileRead, FileWrite, FileEdit, ShellExec, Glob, Grep, WebFetch, Browser, AskUser, ToolSearch, Task, Plan, Loop, Todo (feature), Workflow/Schedule (16), agent-management (8), dynamic-tool lifecycle (5), skill-evolution (3), KnowledgeSearch (optional).

**Representative builtin specs (what to copy):**
- **FileRead** (file_read.rs): max 2000 lines/call, `path`, `line_offset`/`offset`, `limit`, `include_line_numbers`; when no range given it returns a *structural summary* (elided lines, `has_more_lines`, `total_lines`); returns `content_hash` for staleness checks on later edits. Long `help` field teaches usage (grep first, then read ranges).
- **Grep** (grep.rs): ripgrep-based, `pattern`, `path`, `Glob` filter, `output_mode` ∈ {content, files_with_matches, count}, `-A/-B/-C`, `-i`, `type`, `head_limit` (default 250), `offset`, `multiline`. Description explicitly forbids shell `rg`. `is_read_only()`.
- **Glob** (glob.rs): `ignore`-crate walk, `pattern`, `path`, `max_results` (default 50, hard cap), sorted by mtime.
- **AskUser** (user_interaction.rs): validates 1–4 questions × 2–6 options, `multi_select`; signals an `interaction` request; `user_interaction_orchestrator.rs` emits a `UserInteractionRequest` event, awaits a oneshot with a 3-minute timeout, formats answers for the LLM.
- **Todo** (todo/mod.rs): pure *signal* tool — validates an op (`add/update/complete`), returns `{action:"todo",...}`; the service owns the per-session `TodoStore` and applies the mutation; if the model stops while todos remain, `inject_todo_reminder` re-prompts it (bounded reminder count).
- **ShellExec** (shell_exec.rs): `is_dangerous: true`, `is_destructive`, executes through the injected `CommandRunner`, consulted by the exec-policy DSL.
- **WebFetch** (web_fetch.rs): shares one Chrome session with the Browser tool; fetches a URL to markdown/text.

### Verdicts per concept

| Concept | Verdict | Rationale |
|---|---|---|
| `ToolDefinition` + JSON-Schema params passed as OpenAI `tools[]` | **MUST** | This is exactly the OpenAI-compatible function-calling shape VulnCompanion already targets; zero protocol friction. |
| `Tool` trait with `is_read_only` / `is_destructive` / `is_dangerous` | **MUST** | These three flags drive the whole guardrail story; without them every tool needs bespoke checks. |
| Registry (`HashMap` + index + duplicate rejection + `check_fn` gating) | **VALUABLE** | With ~10 tools a `HashMap` registry is enough, but `check_fn` gating (hide `run_scan` until a project is loaded, hide `web_fetch` when offline) is a cheap, high-value copy. |
| `JsonSchemaValidator` with compiled cache | **MUST** | The `jsonschema` crate is one dependency; malformed args become a clean `validation_error` the LLM can self-correct instead of a panic. |
| Lazy loading via `ToolSearch` meta-tool + LRU activation | **SKIP (v1)** | Saves tokens only at 25+ tools; with 10 tools it adds a round-trip and a failure mode. Revisit if the tool count grows. |
| `ToolTaxonomy` (TOML category tree) | **SKIP** | Exists for prompt-based discovery at scale; 10 tools don't need it. |
| `RateLimiter` token bucket | **VALUABLE** | NVD/OSV API quotas are real; it's ~40 lines and per-tool config is natural (`search_cve: 10/min`). |
| Dynamic/MCP tools | **SKIP (v1)** | No agent-created tools in a desktop vuln companion; MCP can come later via Tauri sidecar if ever needed. |
| `result_schema` on definitions | **VALUABLE** | Documents output contract; lets the React side type tool-result cards without guessing. |
| `ToolError` codes + `is_retryable()` | **VALUABLE** | Feed back into the loop ("tool timed out — retryable" vs "permission denied — do not retry") to stop the model from hammering denied tools. |
| Prompt-based tool-call parser (parser.rs XML dialect) | **SKIP** | VulnCompanion's provider is OpenAI-compatible with native tool calls; keep a thin fallback later if models without tool-calling are allowed. |

### Proposed tool set for VulnCompanion (10 tools)

Model-maintained research loop; every tool is **read-only except `ask_user`/`todo`** (no file writes, no shell — that's the safety posture that makes the guardrails trivial).

| # | Tool | Spec (params → output) | Model on |
|---|---|---|---|
| 1 | `read_file` | `path`, `line_offset`?, `limit`? (≤2000), `include_line_numbers`? → content, `has_more_lines`, `total_lines`; **path must resolve inside the scanned project root**. | y-agent `FileRead` |
| 2 | `grep_project` | `pattern` (regex), `path`?, `output_mode` ∈ content/files_with_matches/count, `-C`?, `head_limit`? (≤500) → matches with file:line; **rooted at project dir**. | y-agent `Grep` |
| 3 | `glob` | `pattern`, `path`?, `max_results`? (≤200) → absolute paths, sorted by mtime. | y-agent `Glob` |
| 4 | `run_scan` | `scan_type` ∈ source/secret/deps (or `all`), `path`? (subdir filter), `severity`? filter → reuses VulnCompanion's existing 50-pattern / 30-regex / OSV scanners; returns findings JSON. **Read-only, idempotent.** | custom (no y-agent equivalent) |
| 5 | `search_cve` | `query` (keyword or CVE id), `limit`? (≤25) → compact list of id/severity/date/summary from NVD/OSV. | custom (≈ `knowledge_search` pattern: compact, top-k) |
| 6 | `get_cve_detail` | `cve_id` → full record (description, CVSS vector/score, references, affected configs) from NVD. | custom |
| 7 | `query_osv_package` | `ecosystem`, `name`, `version`? → OSV vulns for that package@version (used when dep scan flags something). | custom |
| 8 | `web_fetch` | `url`, `max_bytes`? (≤256 KB) → markdown/text; **deny non-http(s) schemes**; rate-limited. | y-agent `WebFetch` (minus Chrome: plain reqwest) |
| 9 | `ask_user` | `questions[1..4]` each `{question, options[2..6], multi_select?}` → answers keyed by question; **blocks the loop on a UI modal with timeout**. | y-agent `AskUser` |
| 10 | `todo` | `op` ∈ add/update/complete, `items[]` → current list; service owns the store and injects a "finish or update todos" reminder if the model stops with open items. | y-agent `Todo` |

(`search_cve` + `get_cve_detail` + `query_osv_package` could collapse into one `cve` tool with a `mode` param if you want 8 tools; keeping them separate gives sharper schemas and per-call rate limits.)

### Sketch: minimal `ToolSpec` registry in Rust

The `#[derive(ToolSpec)]`-style ergonomics can be done with a small `macro_rules!` that generates `tool_definition()` + `Tool` impl from one struct. Definitions are plain `serde_json::json!` schemas — this is exactly the OpenAI `tools[]` payload, so a Tauri command serializes the registry and passes it through.

```rust
// src-tauri/src/agent/tool.rs
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: Value,          // JSON Schema Draft 7 (object)
    pub read_only: bool,
    pub dangerous: bool,            // requires HITL click-through
}

// A tool's execute() runs in the Tauri command layer where it can call the
// existing scanners / NVD / OSV / fs code. The agent core only sees specs.
pub trait Tool: Send + Sync {
    fn spec(&self) -> &ToolSpec;
    async fn run(&self, args: Value) -> Result<Value, ToolErr>; // Tauri command body
}

pub struct ToolErr { pub code: &'static str, pub message: String, pub retryable: bool }

// ---- registry -----------------------------------------------------------
#[derive(Default)]
pub struct ToolRegistry { tools: HashMap<&'static str, Arc<dyn Tool>> }

impl ToolRegistry {
    pub fn register(&mut self, t: Arc<dyn Tool>) { self.tools.insert(t.spec().name, t); }
    pub fn openai_tools(&self) -> Vec<Value> {          // → chat.completions tools[]
        self.tools.values().map(|t| json!({
            "type": "function",
            "function": { "name": t.spec().name, "description": t.spec().description,
                          "parameters": t.spec().parameters }
        })).collect()
    }
    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> { self.tools.get(name).cloned() }
}

// ---- macro --------------------------------------------------------------
#[macro_export]
macro_rules! tool {
    ($name:literal, $desc:literal, read_only=$ro:literal, dangerous=$dg:literal,
     schema=$schema:expr, run=$run:expr $(,)?) => {{
        struct T;
        impl $crate::tool::Tool for T {
            fn spec(&self) -> &$crate::tool::ToolSpec {
                static S: $crate::tool::ToolSpec = $crate::tool::ToolSpec {
                    name: $name, description: $desc, parameters: $schema,
                    read_only: $ro, dangerous: $dg,
                };
                &S
            }
            async fn run(&self, args: serde_json::Value)
                -> Result<serde_json::Value, $crate::tool::ToolErr> { ($run)(args).await }
        }
        std::sync::Arc::new(T) as std::sync::Arc<dyn $crate::tool::Tool>
    }};
}

// ---- registration (in a Tauri setup/command) ----------------------------
fn build_registry(project_root: Arc<Mutex<Option<PathBuf>>>) -> ToolRegistry {
    let mut reg = ToolRegistry::default();
    reg.register(tool!("read_file",
        "Read a file from the scanned project. Use grep_project first to locate ranges.",
        read_only = true, dangerous = false,
        schema = json!({"type":"object","properties":{
            "path":{"type":"string"},"line_offset":{"type":"integer","minimum":0},
            "limit":{"type":"integer","minimum":1,"maximum":2000},
            "include_line_numbers":{"type":"boolean"}},
            "required":["path"]}),
        run = |args| async move { read_file(&project_root, &args).await }));
    // ... grep_project, glob, run_scan, search_cve, get_cve_detail,
    //     query_osv_package, web_fetch, ask_user, todo
    reg
}
```

Execution is a Tauri command (`#[tauri::command] fn execute_tool(state, name, args)`) whose body is exactly y-agent's `execute_tool_call_isolated` minus the middleware: **validate JSON Schema → permission check (allow/ask/deny) → run → format result** as a `Role::Tool` message with `tool_call_id`.

---

## B. Agent loop

### How y-agent structures it

Two layers:

1. **The model-turn loop** — `chat.rs::execute_turn_inner` → `AgentService::execute` → `agent_service/executor.rs::execute_inner`. One `loop { }` per turn:
   - check cancel token (`tokio_util::sync::CancellationToken`) → return `Cancelled` with all partial messages/tokens/cost preserved;
   - drain queued user "steer" messages mid-loop (they may interrupt and redirect a running turn);
   - **intra-turn pruning** of `working_history` (drop failed tool branches, merge old tool results, strip historical `<think>` chains) so context doesn't blow up;
   - `ctx.iteration += 1; if ctx.iteration > max_iterations { return ToolLoopLimitExceeded }`;
   - LLM call;
   - if the response has `tool_calls` → append assistant msg, execute each call (in order) through `tool_dispatch`, append `Role::Tool` results, `continue`;
   - fallback: parse prompt-based XML tool calls if the provider didn't emit native ones;
   - otherwise (no tool calls) → final text result (natural stop). **Stop conditions: no tool calls ∧ no queued steer/follow-up ∧ todo list done-or-reminded, or iteration budget, or per-call budget, or cancellation.**
   - **Dual budgets:** `max_iterations` (guardrails `max_tool_iterations` default **10**; agent default 60) bounds LLM round-trips; `max_tool_calls` (agents commonly set 20) is enforced *per tool call* in `tool_dispatch.rs` with a blunt system message: *"Tool call limit reached. Do NOT request more tools. Finish with the information already available."*
   - `max_tool_calls` is checked **before** the permission gate, so budget is never spent on a blocked call.

2. **Orchestration layer** — `Plan` and `Loop` tools each spawn *sub-agent sessions*:
   - **Plan mode** (`plan_orchestrator/mod.rs`, modes fast/plan/auto — auto runs a lightweight complexity classifier): a `plan-writer` sub-agent emits a **structured JSON plan** (title, overview, scope_in/out, guardrails, tasks with phase/estimated iterations); a review policy decides auto-approve vs structured user approval (HITL); approved phases execute in child sessions with bounded parallelism; lifecycle state machine; interrupted plans auto-resume from orchestrator checkpoints.
   - **Loop mode** (`loop_orchestrator.rs`): `Loop` tool takes `request`, `context`, `max_rounds` (default **10**, clamped [2,25]); writes a `PROGRESS.md` file with front-matter (`converged: true/false`) + done/in-progress/todo lists as **persistent inter-round memory**; spawns a *fresh sub-agent per round* that reads the file, works remaining tasks, updates it; when the file says converged, runs a **mandatory self-review round**; outcomes `Converged | BudgetExhausted | Cancelled`.
   - **Todo tracking:** per-session `TodoStore`; `inject_todo_reminder` fires when the model would otherwise stop with open items (bounded reminders).

### Verdict

Adopt the **minimal bounded single-agent loop** — not plan/loop orchestration, not sub-agents:

> **"max 10 model iterations (tool-call rounds), max 30 tool calls, todo list maintained by the model via the `todo` tool, stop when the model emits a final text answer with no tool calls, or when a budget trips, or when the user cancels (AtomicBool)."**

That is almost exactly `execute_inner` with pruning/middleware/steering stripped out. Plan mode, Loop tool, and sub-agents are **SKIP**: VulnCompanion's research tasks (read → grep → scan → CVE lookup → summarize) fit one bounded turn; the progress-file/round machinery exists to keep *long-running* work alive across context resets, which a 10-iteration cap doesn't need.

### Sketch: loop state machine in Rust

```rust
// src-tauri/src/agent/loop.rs
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub enum TurnState { Model, Tool, Done }        // the task's enum

pub struct TurnBudget { iterations_left: u32, tool_calls_left: u32 }
pub struct TurnStats { iterations: u32, tool_calls: u32, tokens_in: u64, tokens_out: u64, cost_usd: f64 }

pub struct AgentLoop {
    cancel: Arc<AtomicBool>,                    // existing VulnCompanion cancel flag
    budget: TurnBudget,
    stats: TurnStats,
    messages: Vec<Message>,                     // system + user + assistant + tool msgs
    todos: TodoStore,                           // owned here, mutated by todo tool
}

impl AgentLoop {
    pub async fn run(mut self, client: &OpenAiClient, tools: &ToolRegistry) -> TurnOutcome {
        loop {
            if self.cancel.load(Ordering::SeqCst) { return TurnOutcome::Cancelled(self.stats); }

            // --- Model turn -------------------------------------------------
            if self.budget.iterations_left == 0 {
                return TurnOutcome::BudgetExhausted(self.stats);
            }
            self.budget.iterations_left -= 1;
            self.stats.iterations += 1;

            let resp = client.chat(&self.messages, tools.openai_tools()).await?;
            self.stats.tokens_in += resp.usage.input_tokens;
            self.stats.tokens_out += resp.usage.output_tokens;

            if resp.tool_calls.is_empty() {
                // natural stop — but respect the todo checklist first
                if !self.todos.is_empty() && self.todo_reminders < MAX_TODO_REMINDERS {
                    self.todo_reminders += 1;
                    self.messages.push(reminder_msg(&self.todos));   // "finish or update todos"
                    continue;                                        // one more model turn
                }
                return TurnOutcome::Done(resp.content, self.stats);
            }

            // --- Tool turns (one per call; budget & guardrails apply) -------
            for call in &resp.tool_calls {
                if self.budget.tool_calls_left == 0 {
                    self.messages.push(limit_msg());                 // blunt "finish now" msg
                    break;
                }
                self.budget.tool_calls_left -= 1;
                self.stats.tool_calls += 1;

                let decision = permission::classify(call.name, &call.args, tools); // Allow/Ask/Deny
                let output = match decision {
                    Permission::Deny => deny_output(call.name),       // tell model: do NOT retry
                    Permission::Ask  => ask_user_modal(call).await,   // HITL, blocks w/ timeout
                    Permission::Allow => tools.get(&call.name).unwrap().run(call.args).await,
                };
                // loop-guard check (see C-b): record & possibly force-stop
                if loop_guard::record(call.name, &call.args).is_some() { return TurnOutcome::LoopDetected(...); }
                self.messages.push(ToolMessage { tool_call_id: &call.id, content: output });
            }
            // loop back to Model turn
        }
    }
}
```

Message history is the single source of truth (y-agent's `working_history`); no separate state needed at this size. Cancellation mid-tool should still append the partial messages so "resume" keeps context.

---

## C. Guardrails

### What y-agent has

- **Permission pipeline** (`permission_pipeline.rs`, explicitly Claude-Code-style ordering): Stage 0 exec-policy DSL (ShellExec only) → Stage 1 **Deny** rules (cannot be overridden, even by bypass mode) → Stage 2 Ask/Allow/Notify rules → global-default-deny → Stage 3 tool's own `check_permissions()` → Stage 4 **mode** overrides (BypassPermissions / Plan: only read-only tools pass without asking) → dangerous auto-ask (`is_dangerous && dangerous_auto_ask` → Ask) → passthrough→Ask conversion. Rules live in a layered `PermissionRuleStore` (global/session/tool precedence); `PermissionResult { behavior: Allow|Notify|Ask|Deny, reason, message, updated_input }`. In `tool_dispatch.rs`: **Deny → tool NOT executed**, system message *"blocked by security policy … Do NOT ask the user for permission or retry this tool"*; **Ask/Passthrough → emit `TurnEvent::PermissionRequest` to the GUI, register a oneshot in `pending_permissions`, block until response / 120 s HITL timeout / cancel**; user response (approve/deny/always-allow/always-deny) is returned to the loop and the tool runs or not.
- **exec_policy DSL** (exec_policy/, Codex-inspired): `prefix_rule(pattern=["git",["push","commit"]], decision="ask", match=[["git","push"]], not_match=[["git","status"]], justification=…)`; strictest-wins aggregation (Deny > Ask > Allow); match/not_match examples **validated at parse time**; hot-reload + auto-amended rules from HITL "Always Allow".
- **LoopGuard** (`loop_guard.rs`): 4 detectors over a bounded action history — **Repetition** (same action key ×5), **Oscillation** (A→B→A→B, ×3), **Drift** (no progress-metric change over 10 steps; progress resets history), **RedundantToolCall** (same tool + args-hash ×3). Runs as middleware (priority 20) that can abort the loop.
- **Taint** (taint.rs): user input / external data tagged tainted; propagates through derived data; sanitizers; dangerous sinks (filesystem_write, shell_execute, network_send) → `Blocked`.
- **Risk** (risk.rs): composite 0–1 score from factors (write-capable, network, destructive, shell, custom); threshold escalation.
- **HITL** (hitl.rs): `HitlProtocol`/`HitlHandler` channel pair; `HitlResponse {Approve, ApproveAlways, Deny, DenyAlways}`; 120 s timeout default → deny.
- **Mode manager** (mode_manager.rs): validated `PermissionMode` transitions; **LLM output guard** middleware (priority 900).

### Verdicts for VulnCompanion

| Guardrail | Verdict | Why |
|---|---|---|
| Allow-list policy: read-only tools auto-allowed, destructive require click-through | **MUST** | With a read-only-by-default tool set, this *is* the whole security model: `read_only` tools pass, `dangerous` tools always Ask, everything else Deny-by-default. |
| Pipeline ordering (Deny > Ask > Allow; deny is bypass-immune; "do not retry" system message) | **MUST** | The "do NOT retry" message is what actually stops model loops against blocked tools. Copy it verbatim. |
| HITL modal (React) with timeout → deny | **MUST** | Desktop app; `ask_user` and destructive approvals both need it; y-agent's oneshot + timeout pattern is the right shape. |
| Loop guard — N identical tool calls → stop | **MUST** | ~40 lines (see sketch); protects against model thrash; **redundant-tool detection (same tool+args) is the key one** for a research agent that re-greps the same pattern. |
| exec_policy DSL | **SKIP (v1)** | It gates shell commands; VulnCompanion v1 has no shell tool. Revisit the day `shell_exec`/`file_edit` are added — the DSL design (prefix rules, parse-time examples, auto-amend from HITL) is a good one to copy then. |
| Taint tracking | **SKIP** | Meaningful only with write/shell sinks. All v1 tools are reads (fs, network, scanners); taint adds complexity with nothing to block. |
| Risk scoring | **SKIP** | A 0–1 score adds nothing over Allow/Ask/Deny classification for 10 known tools. |
| LLM output guard | **VALUABLE** | Cheap text filter on final output: refuse to render raw secrets/credentials (VulnCompanion has a secret scanner; mirror a light version on LLM output so the assistant can't dump `apiKey=` lines). |
| Mode manager / permission modes | **SKIP** | Single-user desktop; no plan-vs-normal modes in v1. |

### Sketches

**(a) Allow-list policy** — the y-agent pipeline reduced to ~60 lines, called before every tool execution:

```rust
// src-tauri/src/agent/guardrails.rs
pub enum Decision { Allow, Ask, Deny }
pub struct DecisionOut { pub decision: Decision, pub reason: String }

pub fn classify(spec: &ToolSpec, _args: &Value) -> DecisionOut {
    if spec.dangerous { return DecisionOut { decision: Decision::Ask, reason: "destructive tool".into() } }
    if spec.read_only { return DecisionOut { decision: Decision::Allow, reason: "read-only".into() } }
    DecisionOut { decision: Decision::Deny, reason: "not in allow-list".into() } // fail-closed
}
// Deny  → skip execution, append: "Tool 'X' is blocked by policy (reason).
//         Do NOT ask the user or retry. Use an alternative approach."
// Ask   → pending_approvals.insert(id, oneshot); emit PermissionRequest{id, tool, args_preview} to frontend;
//         await with 120s timeout → on timeout, treat as Deny.
// Allow → run.
```

**(b) Loop guard** — repetition + redundant-call detection:

```rust
#[derive(Default)]
pub struct LoopGuard {
    last_key: Option<String>, last_args: Option<String>, same_run: usize, // consecutive identical
    recent: VecDeque<String>,  // last 12 action keys, for oscillation
}
impl LoopGuard {
    pub fn record(&mut self, tool: &str, args: &Value) -> Option<&'static str> {
        let key = format!("{tool}:{}", compact_args(args));          // args hash (first 128 chars)
        let run = if self.last_key.as_deref() == Some(&key) { self.same_run + 1 } else { 1 };
        self.last_key = Some(key.clone()); self.same_run = run;
        self.recent.push_back(tool.to_string());
        if self.recent.len() > 12 { self.recent.pop_front(); }
        if run >= 3 { return Some("same tool+args repeated 3x — stop and reassess"); }   // redundant
        if self.recent.len() >= 5 && self.recent.iter().rev().take(5).all(|t| t == &self.recent[0].clone()) {
            return Some("5 identical tool calls — stop and reassess");                     // repetition
        }
        None
    }
}
```

**(c) HITL modal in React** — `PermissionRequest` events arrive on the same channel the chat stream already uses:

```tsx
// src/components/ApprovalModal.tsx
export function ApprovalModal({ req, onDecide }: { req: PermissionRequest; onDecide: (d: 'approve'|'deny') => void }) {
  const [countdown, setCountdown] = useState(120);
  useEffect(() => { const t = setInterval(() => setCountdown(c => c - 1), 1000);
                    return () => clearInterval(t); }, []);
  useEffect(() => { if (countdown <= 0) onDecide('deny'); }, [countdown]);   // timeout → deny
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/40">
      <div className="rounded-xl border bg-white p-6 shadow-xl dark:bg-zinc-900">
        <h2 className="font-semibold">Approve tool call</h2>
        <p className="mt-1 text-sm text-zinc-500">{req.tool} — {req.reason}</p>
        <pre className="mt-2 max-h-40 overflow-auto rounded bg-zinc-100 p-2 text-xs dark:bg-zinc-800">{req.args_preview}</pre>
        <div className="mt-4 flex gap-2">
          <button onClick={() => onDecide('deny')} className="rounded bg-zinc-200 px-3 py-1.5 text-sm">Deny</button>
          <button onClick={() => onDecide('approve')} className="rounded bg-emerald-600 px-3 py-1.5 text-sm text-white">Approve</button>
        </div>
        <p className="mt-2 text-xs text-zinc-400">auto-denies in {countdown}s</p>
      </div>
    </div>
  );
}
```

The Rust side mirrors `await_permission_response`: `pending_permissions: Mutex<HashMap<String, oneshot::Sender<Approval>>>`; the modal's `onDecide` invokes `#[tauri::command] respond_permission(request_id, decision)`.

---

## D. Persistence of turns

### What y-agent does

- **Chat messages → SQLite** (`chat_message.rs`): `chat_messages(id, session_id, role, content, status, checkpoint_id, model, input_tokens, output_tokens, cost_usd, context_window, parent_message_id, pruning_group_id, has_tool_calls, created_at)`. `status` = active/tombstoned enables **branching & regeneration** (tombstone-after + `swap_branches` + `restore_tombstoned`); checkpoint_id links messages to turn checkpoints; pruning_group_id lets pruned content be restored.
- **Transcript → JSONL per session** (`transcript.rs`): append-only `{session_id}.jsonl`, `read_all` **skips corrupt/truncated lines** (crash mid-append never breaks the whole read), `read_last(n)`, `truncate`, `update_message`. This is the raw protocol stream the LLM needs on resume.
- **Sessions → SQLite tree** (`session_store.rs`): `session_metadata` with `parent_id/root_id/depth` (sessions form a tree — sub-agents are child sessions you can drill into), `session_type` (User/SubAgent/Internal), `state`, `workspace_path`, `title`, custom system prompt, settings, branch summary.
- **Orchestrator checkpoints → SQLite** (`checkpoint.rs`): `orchestrator_checkpoints(workflow_id, session_id, step_number, status, committed_state, pending_state, versions_seen)` — two-phase (pending → commit) so interrupted workflows resume exactly (plan/loop tools use this).
- **Turn-level persistence** (`chat.rs`): `persist_turn_checkpoint` anchors every turn *before* the LLM call; on LLM error or cancellation, partial assistant/tool messages are persisted so a retry `prepare_resend_turn` resumes from the last checkpoint instead of resending the whole turn.

### Verdict

**Adopt a lightweight version — YES, worth it.** VulnCompanion's chat is in-memory today; a Tauri window close or app update loses the whole research session, which is exactly when a vuln-research conversation is most valuable (multi-hour deep-dives). But the full SQLite+checkpoint+session-tree machinery is overkill for a single-session desktop chat.

**Recommended: JSONL per session (copy `transcript.rs`), not SQLite, for v1:**
- One file per session: `<data_dir>/sessions/<session_id>.jsonl`, one JSON message per line (user/assistant/tool roles with `tool_call_id`, timestamps, metadata).
- Append-only writes; on load, skip corrupt lines (crash-safe, exactly y-agent's design).
- A tiny `sessions.json` index (id, title, created_at, project_path, message_count) for the sidebar — replace with rusqlite later if you want search/branching.
- **Resume = load the JSONL + a fresh system prompt**; no turn checkpoints needed at 10-iteration turns. The one y-agent trick worth copying: on cancel/error, still persist the partial tool results that already happened, so "continue" starts from real state rather than a regenerated turn.
- Persist tool-call records with their results in metadata (like y-agent's `tool_results` array) so the UI can render tool cards after reload.

Verdict table: JSONL transcript **MUST-ish (cheap, high value)**; SQLite sessions/branching **later**; orchestrator checkpoints **SKIP**.

```rust
// src-tauri/src/storage/transcript.rs  (JSONL per session, modeled on y-storage/transcript.rs)
pub struct Transcript { path: PathBuf, w: Mutex<File> }
impl Transcript {
    pub fn open(session_id: &str) -> Self { /* create file, append-only */ }
    pub fn append(&self, m: &Message) -> io::Result<()> {   // one JSON line, flush
        let mut w = self.w.lock().unwrap();
        serde_json::to_writer(&mut *w, m)?; w.write_all(b"\n")?; w.flush()
    }
    pub fn read_all(&self) -> Vec<Message> {                 // skip corrupt lines
        BufReader::new(File::open(&self.path)?).lines()
            .filter_map(|l| l.ok().and_then(|s| serde_json::from_str(&s).ok()))
            .collect()
    }
}
// Message = { id, role: user|assistant|tool|system, content, tool_call_id?,
//             tool_calls?: [{id,name,arguments}], ts, meta: {tool_results?...} }
```

---

## E. Top 6 concrete adoption actions (ranked by value/effort)

**1. Tool registry + schemas for the 10 tools — value: MUST · effort: M**
*What:* `ToolSpec`/`Tool` trait, `ToolRegistry` with `openai_tools()`, `JsonSchemaValidator` (jsonschema crate), `ToolErr` codes; implement the 10 tools in Tauri commands reusing existing scanners/NVD/OSV code.
*Why:* Everything else hangs off this; converts CHAT ONLY into tool-calling in one step.
*Outline:* `src-tauri/src/agent/tool.rs` (trait/spec/registry), `src-tauri/src/agent/tools/*.rs` (read_file, grep_project via `ignore`+regex, run_scan wrapping existing scanners, search_cve/get_cve_detail/query_osv_package wrapping existing NVD/OSV clients, web_fetch via reqwest, ask_user signal, todo signal); `#[tauri::command] fn chat_completions_tools(state)` for the frontend; extend `src-tauri/src/commands/chat.rs` to send `tools[]` and handle `tool_calls`.

**2. Bounded agent loop — value: MUST · effort: M**
*What:* The `AgentLoop` state machine (B-sketch): 10 iterations / 30 tool calls, todo-reminder stop check, AtomicBool cancellation, tool results appended as `Role::Tool` messages, "budget exhausted — finish now" system message.
*Why:* This *is* the "AI can actually ACT" feature; without it tools are inert.
*Outline:* `src-tauri/src/agent/loop.rs`, `src-tauri/src/agent/messages.rs`; move chat streaming loop in `src-tauri/src/commands/chat.rs` behind `AgentLoop::run`.

**3. Permission allow-list + HITL modal — value: MUST · effort: M**
*What:* `classify()` (read-only→Allow, dangerous→Ask, else Deny), pending-approval oneshot map, `PermissionRequest`/`respond_permission` Tauri events, React `ApprovalModal` with 120 s auto-deny, "do NOT retry" denial message.
*Why:* The desktop-app trust boundary; the modal is also reused by `ask_user`.
*Outline:* `src-tauri/src/agent/guardrails.rs`, events in `src-tauri/src/events.rs`, `src/components/ApprovalModal.tsx`, wire into `Chat.tsx` event stream.

**4. Loop guard — value: VALUABLE · effort: S**
*What:* Redundant-tool (same tool+args ×3) and repetition (5 identical) detectors force-stopping the loop with a "stop and reassess" message.
*Why:* Cheapest insurance against a research agent re-grepping the same pattern forever; also catches accidental prompt loops.
*Outline:* `src-tauri/src/agent/loop_guard.rs` (sketch C-b), one call site in `AgentLoop`.

**5. JSONL per-session transcript + resume — value: VALUABLE · effort: S–M**
*What:* `Transcript` (D-sketch), `sessions.json` index, load-on-open, persist partial tool results on cancel, sidebar lists sessions.
*Why:* Survives app restarts; a vuln-research session is exactly the long-lived state users expect to resume.
*Outline:* `src-tauri/src/storage/transcript.rs`, `src-tauri/src/storage/sessions.rs`, `src/components/Sidebar.tsx`, chat-load command.

**6. Rate limiter + check_fn gating + output guard — value: VALUABLE · effort: S**
*What:* Token-bucket per tool (`search_cve`/`web_fetch`/`query_osv_package` limits; protects NVD/OSV quota), `available` closures (hide `run_scan` until project loaded), light LLM-output filter blocking raw secret strings.
*Why:* Cheap robustness: API-quota safety, leaner schemas, and no accidental credential dumps in chat.
*Outline:* `src-tauri/src/agent/rate_limiter.rs` (copy the ~40-line bucket), `available` field on `ToolSpec`, `src-tauri/src/agent/output_guard.rs` reusing secret-regex rules from the existing scanner.

**Deliberately NOT adopting (with reasons):** ToolSearch lazy loading & taxonomy (tool count too small), dynamic/MCP tools, Plan/Loop orchestration & sub-agents (single bounded turn suffices), exec_policy DSL (no shell tool yet), taint & risk scoring (no write/shell sinks), permission modes, SQLite chat_messages + orchestrator checkpoints + session trees (JSONL covers v1 needs; the checkpoint/branching machinery pays off only with long-running sub-agent workflows).

*File paths above are suggestions for a conventional Tauri layout; adjust to VulnCompanion's actual structure. All claims trace to the local copies under `yagent-research/`.*
