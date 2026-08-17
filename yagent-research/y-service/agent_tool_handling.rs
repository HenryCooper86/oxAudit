//! Native and prompt-based tool call handling, dynamic tool sync.

use y_core::provider::ToolCallingMode;
use y_core::types::{Message, Role, ToolCallRequest};
use y_tools::{format_tool_result_dialect, strip_tool_call_blocks, ParseResult};

use crate::container::ServiceContainer;

use super::result;
use super::tool_dispatch;
use super::{pruning, AgentExecutionConfig, LlmIterationData, ToolExecContext, TurnEventSender};

pub(super) fn parse_tool_arguments<T: serde::de::DeserializeOwned>(
    request: &ToolCallRequest,
) -> Result<T, y_core::tool::ToolError> {
    serde_json::from_value(request.arguments.clone()).map_err(|error| {
        y_core::tool::ToolError::ValidationError {
            message: format!("invalid {} arguments: {error}", request.name),
        }
    })
}

fn build_native_tool_result(
    request: &ToolCallRequest,
    content: String,
    metadata: serde_json::Value,
) -> Message {
    Message {
        message_id: y_core::types::generate_message_id(),
        role: Role::Tool,
        content,
        tool_call_id: Some(request.id.clone()),
        tool_calls: vec![],
        timestamp: y_core::types::now(),
        metadata,
    }
}

// ---------------------------------------------------------------------------
// Ordered execution with parallel read-only batches
// ---------------------------------------------------------------------------

/// Built-in tools that only read, and may therefore share a concurrent batch.
///
/// This is an allowlist on purpose. `is_dangerous` and the declared filesystem
/// capability do not capture every side effect: workflow, schedule, agent, and
/// skill tools mutate durable stores without touching the filesystem, browser
/// tools drive one shared session, and MCP or agent-created tools have unknown
/// effects entirely. Anything not named here runs alone, so the failure mode of
/// an unrecognised tool is lost parallelism rather than a race.
const PARALLEL_SAFE_TOOLS: &[&str] = &["FileRead", "Glob", "Grep", "KnowledgeSearch"];

/// Whether `tc` may run alongside its neighbours in the same LLM response.
///
/// Requires all of: named in [`PARALLEL_SAFE_TOOLS`], still registered, still
/// free of the dangerous flag and of a declared filesystem mutation, and a
/// permission decision that needs no human input. The registry checks are a
/// second gate, so a tool that later gains a side effect stops being batched
/// even if this list is not updated. The permission decision is re-evaluated
/// authoritatively during execution; this check only decides batching.
async fn is_parallel_safe(
    container: &ServiceContainer,
    config: &AgentExecutionConfig,
    tc: &ToolCallRequest,
    ctx: &ToolExecContext,
) -> bool {
    if !PARALLEL_SAFE_TOOLS.contains(&tc.name.as_str()) {
        return false;
    }

    let Some(definition) = container
        .tool_registry
        .get_definition(&y_core::types::ToolName::from_string(&tc.name))
        .await
    else {
        return false;
    };
    if definition.is_dangerous || definition.capabilities.filesystem.mutation.is_some() {
        return false;
    }

    let decision = tool_dispatch::evaluate_agent_tool_permission(container, config, tc, ctx).await;
    matches!(
        decision.behavior,
        y_core::permission_types::PermissionBehavior::Allow
            | y_core::permission_types::PermissionBehavior::Notify
    )
}

/// Number of leading calls in `calls` that may run as one concurrent batch.
///
/// Returns the run of consecutive parallel-safe calls, or 1 when the first call
/// must run alone. Never returns 0 for a non-empty slice, so the caller always
/// makes progress.
async fn next_batch_len(
    container: &ServiceContainer,
    config: &AgentExecutionConfig,
    calls: &[ToolCallRequest],
    ctx: &ToolExecContext,
) -> usize {
    let mut len = 0;
    while len < calls.len() && is_parallel_safe(container, config, &calls[len], ctx).await {
        len += 1;
    }
    len.max(1)
}

/// Execute every tool call, preserving input order in the results.
///
/// Consecutive parallel-safe calls run concurrently; anything else runs alone,
/// in order. Records are appended to `ctx` in input order, so the transcript is
/// identical to serial execution regardless of completion order.
async fn execute_tool_calls_ordered(
    container: &ServiceContainer,
    config: &AgentExecutionConfig,
    calls: &[ToolCallRequest],
    progress: Option<&TurnEventSender>,
    ctx: &mut ToolExecContext,
) -> Vec<(bool, String, serde_json::Value)> {
    let mut results = Vec::with_capacity(calls.len());
    let mut index = 0;

    while index < calls.len() {
        let batch_len = next_batch_len(container, config, &calls[index..], ctx).await;
        let batch_end = index + batch_len;
        let batch = &calls[index..batch_end];

        let outcomes = {
            let executed_before = ctx.tool_calls_executed.len();
            let futures = batch.iter().enumerate().map(|(offset, tc)| {
                let env = tool_dispatch::ToolExecEnv::borrow_at(ctx, executed_before + offset);
                async move {
                    tool_dispatch::execute_tool_call_isolated(container, config, tc, progress, &env)
                        .await
                }
            });
            futures::future::join_all(futures).await
        };

        for outcome in outcomes {
            results.push(outcome.apply_to(ctx));
        }
        index = batch_end;
    }

    results
}

/// Handle native (function-calling) tool calls from an LLM response.
pub(crate) async fn handle_native_tool_calls(
    container: &ServiceContainer,
    config: &AgentExecutionConfig,
    response: &y_core::provider::ChatResponse,
    progress: Option<&TurnEventSender>,
    data: &LlmIterationData,
    ctx: &mut ToolExecContext,
    context_window: usize,
) {
    let tc_names: Vec<String> = response
        .tool_calls
        .iter()
        .map(|tc| tc.name.clone())
        .collect();

    result::emit_llm_response(
        progress,
        response,
        data,
        ctx.iteration,
        tc_names,
        context_window,
        &config.agent_name,
    );

    // Track new messages added in this iteration for mid-loop persistence.
    let msgs_before = ctx.new_messages.len();

    // Even with Native tool calling, some providers/models embed XML tool
    // call blocks in the text content alongside structured tool_calls.
    // Strip them so raw protocol XML never leaks into the conversation.
    let iter_content = {
        let raw = response.content.clone().unwrap_or_default();
        let stripped = strip_tool_call_blocks(&raw);
        if stripped.is_empty() {
            raw
        } else {
            stripped
        }
    };

    // Accumulate this iteration's text so the final persisted message
    // includes all iterations' content. The raw content is preserved
    // as-is -- the frontend renders it sequentially.
    let out_content = if iter_content.trim().is_empty() {
        String::new()
    } else {
        format!("{}\n", iter_content.trim())
    };
    ctx.accumulated_content.push_str(&out_content);
    // Store per-iteration text separately so the frontend can interleave
    // text and tool cards by iteration order (without character offsets).
    // Always push (even empty) to stay parallel with iteration_reasonings.
    ctx.iteration_texts.push(out_content.clone());
    ctx.iteration_tool_counts.push(response.tool_calls.len());

    let assistant_msg =
        result::build_assistant_msg(response, out_content, response.tool_calls.clone());

    ctx.working_history.push(assistant_msg.clone());
    ctx.new_messages.push(assistant_msg);

    let outcomes =
        execute_tool_calls_ordered(container, config, &response.tool_calls, progress, ctx).await;
    for (tc, (_success, result_content, tool_meta)) in response.tool_calls.iter().zip(outcomes) {
        let tool_msg = build_native_tool_result(tc, result_content, tool_meta);
        ctx.working_history.push(tool_msg.clone());
        ctx.new_messages.push(tool_msg);
    }

    // If ToolSearch was called this iteration, sync newly activated
    // tool definitions so they appear in the next ChatRequest.tools.
    if response.tool_calls.iter().any(|tc| tc.name == "ToolSearch") {
        sync_dynamic_tool_defs(container, ctx).await;
    }

    // Mid-loop pruning: truncate large tool results from previous
    // iterations so context is managed at tool-call granularity.
    if config.use_context_pipeline {
        pruning::prune_working_history_mid_loop(container, ctx, msgs_before);
    }
}

/// Handle prompt-based tool calls parsed from LLM response text.
///
/// The fallback only affects how tool calls are *detected* (parsing XML from
/// text). The *result format* sent back to the LLM always follows the
/// provider's configured `tool_calling_mode`:
/// - **Native**: results are sent as `Role::Tool` messages with `tool_call_id`,
///   and the assistant message carries structured `tool_calls`.
/// - **`PromptBased`**: results are wrapped in `<tool_result>` XML and sent as a
///   single `Role::User` message.
pub(crate) async fn handle_prompt_based_tool_calls(
    container: &ServiceContainer,
    config: &AgentExecutionConfig,
    response: &y_core::provider::ChatResponse,
    parse_result: &ParseResult,
    text: &str,
    progress: Option<&TurnEventSender>,
    data: &LlmIterationData,
    ctx: &mut ToolExecContext,
    context_window: usize,
) {
    let tc_names: Vec<String> = parse_result
        .tool_calls
        .iter()
        .map(|ptc| ptc.name.clone())
        .collect();

    result::emit_llm_response(
        progress,
        response,
        data,
        ctx.iteration,
        tc_names,
        context_window,
        &config.agent_name,
    );

    // Track new messages added in this iteration for mid-loop persistence.
    let msgs_before = ctx.new_messages.len();

    // The result format follows the provider config, not the detection method.
    let use_native_results = config.tool_calling_mode == ToolCallingMode::Native;

    // In Native mode, strip XML tool call blocks from the assistant content
    // so the working history stays in pure native format (the parsed calls
    // are attached via the `tool_calls` field instead). In PromptBased mode,
    // keep the raw text as-is (the XML blocks are the protocol).
    let out_content = if use_native_results {
        let stripped = strip_tool_call_blocks(text);
        if stripped.trim().is_empty() {
            String::new()
        } else {
            format!("{}\n", stripped.trim())
        }
    } else if text.trim().is_empty() {
        String::new()
    } else {
        format!("{}\n", text.trim())
    };

    ctx.accumulated_content.push_str(&out_content);
    // Always push (even empty) to stay parallel with iteration_reasonings.
    ctx.iteration_texts.push(out_content.clone());
    ctx.iteration_tool_counts
        .push(parse_result.tool_calls.len());

    // Pre-build ToolCallRequest objects with synthetic IDs.
    let tool_call_requests: Vec<ToolCallRequest> = parse_result
        .tool_calls
        .iter()
        .map(|ptc| ToolCallRequest {
            id: format!("call_{}", &uuid::Uuid::new_v4().simple().to_string()[..24]),
            name: ptc.name.clone(),
            arguments: ptc.arguments.clone(),
        })
        .collect();

    // In Native mode, attach parsed tool calls to the assistant message so
    // providers serialize them as structured function calls. In PromptBased
    // mode, the tool calls live in the text content.
    let assistant_tool_calls = if use_native_results {
        tool_call_requests.clone()
    } else {
        vec![]
    };

    let assistant_msg = result::build_assistant_msg(response, out_content, assistant_tool_calls);

    ctx.working_history.push(assistant_msg.clone());
    ctx.new_messages.push(assistant_msg);

    if use_native_results {
        // Native mode: execute each tool and send results as Role::Tool
        // messages with tool_call_id, matching handle_native_tool_calls.
        let outcomes =
            execute_tool_calls_ordered(container, config, &tool_call_requests, progress, ctx).await;
        for (tc, (_success, result_content, tool_meta)) in tool_call_requests.iter().zip(outcomes) {
            let tool_msg = build_native_tool_result(tc, result_content, tool_meta);
            ctx.working_history.push(tool_msg.clone());
            ctx.new_messages.push(tool_msg);
        }
    } else {
        // PromptBased mode: wrap results in XML and send as a single
        // Role::User message (original behavior).
        let outcomes =
            execute_tool_calls_ordered(container, config, &tool_call_requests, progress, ctx).await;
        let mut result_blocks = Vec::new();
        for (tc, (tool_success, result_content, _tool_meta)) in
            tool_call_requests.iter().zip(outcomes)
        {
            let result_value: serde_json::Value = serde_json::from_str(&result_content)
                .unwrap_or(serde_json::Value::String(result_content));
            result_blocks.push(format_tool_result_dialect(
                &tc.name,
                tool_success,
                &result_value,
                config.tool_dialect,
            ));
        }

        let results_text = result_blocks.join("\n");
        let user_msg = Message {
            message_id: y_core::types::generate_message_id(),
            role: Role::User,
            content: results_text,
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: y_core::types::now(),
            metadata: serde_json::json!({ "type": "tool_result" }),
        };
        ctx.working_history.push(user_msg.clone());
        ctx.new_messages.push(user_msg);
    }

    // If ToolSearch was called this iteration, sync newly activated
    // tool definitions so they appear in the next ChatRequest.tools.
    if parse_result
        .tool_calls
        .iter()
        .any(|ptc| ptc.name == "ToolSearch")
    {
        sync_dynamic_tool_defs(container, ctx).await;
    }

    // Mid-loop pruning: truncate large tool results from previous
    // iterations so context is managed at tool-call granularity.
    if config.use_context_pipeline {
        pruning::prune_working_history_mid_loop(container, ctx, msgs_before);
    }
}

/// Sync dynamically activated tool definitions from the `ToolActivationSet`
/// into `ctx.dynamic_tool_defs` so they appear in subsequent `ChatRequest.tools`.
///
/// Called after a `ToolSearch` call activates new tools. Also sets the
/// `orchestration.enabled` prompt flag when workflow/schedule tools are active.
pub(crate) async fn sync_dynamic_tool_defs(
    container: &ServiceContainer,
    ctx: &mut ToolExecContext,
) {
    use crate::container::ESSENTIAL_TOOL_NAMES;

    let essential: std::collections::HashSet<&str> = ESSENTIAL_TOOL_NAMES.iter().copied().collect();

    let set = container.tool_activation_set.read().await;
    let active = set.active_definitions();

    ctx.dynamic_tool_defs = active
        .iter()
        .filter(|def| {
            let name = def.name.as_str();
            !essential.contains(name)
        })
        .map(|def| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": def.name.as_str(),
                    "description": def.description,
                    "parameters": def.parameters,
                }
            })
        })
        .collect();

    // If workflow/schedule tools were activated, set the orchestration
    // flag so the system prompt includes orchestration instructions on
    // subsequent turns.
    let has_orchestration = active.iter().any(|d| {
        let n = d.name.as_str();
        n.starts_with("workflow_") || n.starts_with("schedule_")
    });
    if has_orchestration {
        let mut pctx = container.prompt_context.write().await;
        pctx.config_flags
            .insert("orchestration.enabled".into(), true);
    }

    tracing::debug!(
        dynamic_count = ctx.dynamic_tool_defs.len(),
        "synced dynamic tool definitions from activation set"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tool_arguments_names_the_invalid_tool_call() {
        #[derive(Debug, serde::Deserialize)]
        struct RequiredName {
            name: String,
        }
        let request = ToolCallRequest {
            id: "call-1".into(),
            name: "AgentCreate".into(),
            arguments: serde_json::json!({}),
        };

        let error = parse_tool_arguments::<RequiredName>(&request).unwrap_err();

        assert!(error.to_string().contains("AgentCreate"));

        let valid = ToolCallRequest {
            id: "call-2".into(),
            name: "AgentCreate".into(),
            arguments: serde_json::json!({"name": "demo"}),
        };
        let parsed = parse_tool_arguments::<RequiredName>(&valid).unwrap();

        assert_eq!(parsed.name, "demo");
    }

    #[test]
    fn test_build_native_tool_result_preserves_call_identity_and_metadata() {
        let request = ToolCallRequest {
            id: "call-42".into(),
            name: "lookup".into(),
            arguments: serde_json::json!({}),
        };
        let metadata = serde_json::json!({"duration_ms": 12});

        let message = build_native_tool_result(&request, "done".into(), metadata.clone());

        assert_eq!(message.role, Role::Tool);
        assert_eq!(message.tool_call_id.as_deref(), Some("call-42"));
        assert_eq!(message.content, "done");
        assert_eq!(message.metadata, metadata);
    }

    // -- Ordered execution with parallel read-only batches -------------------

    async fn batching_test_container(temp: &tempfile::TempDir) -> ServiceContainer {
        let service_config = crate::ServiceConfig {
            storage: y_storage::StorageConfig {
                db_path: ":memory:".to_string(),
                pool_size: 1,
                wal_enabled: false,
                transcript_dir: temp.path().join("transcripts"),
                ..y_storage::StorageConfig::default()
            },
            ..Default::default()
        };
        ServiceContainer::from_config(&service_config)
            .await
            .unwrap()
    }

    fn call(id: &str, name: &str, arguments: serde_json::Value) -> ToolCallRequest {
        ToolCallRequest {
            id: id.to_string(),
            name: name.to_string(),
            arguments,
        }
    }

    fn batching_ctx(
        session_id: &y_core::types::SessionId,
        workspace: &std::path::Path,
    ) -> ToolExecContext {
        ToolExecContext {
            iteration: 0,
            last_gen_id: None,
            tool_calls_executed: Vec::new(),
            new_messages: Vec::new(),
            cumulative_input_tokens: 0,
            cumulative_output_tokens: 0,
            cumulative_cost: 0.0,
            last_input_tokens: 0,
            last_cache_read_tokens: 0,
            last_cache_write_tokens: 0,
            trace_id: None,
            session_id: session_id.clone(),
            working_directory: Some(workspace.display().to_string()),
            additional_read_dirs: Vec::new(),
            working_history: Vec::new(),
            accumulated_content: String::new(),
            iteration_texts: Vec::new(),
            iteration_reasonings: Vec::new(),
            iteration_reasoning_durations_ms: Vec::new(),
            iteration_tool_counts: Vec::new(),
            dynamic_tool_defs: Vec::new(),
            pending_interactions: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            pending_permissions: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            cancel_token: None,
            injected_steers: Vec::new(),
            todo_reminders: 0,
        }
    }

    fn execution_config(session_id: y_core::types::SessionId) -> AgentExecutionConfig {
        AgentExecutionConfig {
            agent_name: "test-agent".to_string(),
            system_prompt: String::new(),
            max_iterations: 12,
            max_tool_calls: 20,
            tool_definitions: Vec::new(),
            tool_calling_mode: y_core::provider::ToolCallingMode::Native,
            tool_dialect: y_core::provider::ToolDialect::default(),
            messages: Vec::new(),
            provider_id: None,
            preferred_models: Vec::new(),
            provider_tags: Vec::new(),
            fallback_provider_tags: Vec::new(),
            request_mode: y_core::provider::RequestMode::TextChat,
            working_directory: None,
            additional_read_dirs: Vec::new(),
            temperature: None,
            max_tokens: Some(2_048),
            thinking: None,
            session_id: Some(session_id),
            session_uuid: uuid::Uuid::new_v4(),
            knowledge_collections: Vec::new(),
            use_context_pipeline: false,
            user_query: String::new(),
            external_trace_id: None,
            trust_tier: Some(y_core::trust::TrustTier::BuiltIn),
            agent_allowed_tools: Vec::new(),
            prune_tool_history: false,
            response_format: None,
            image_generation_options: None,
            inherited_constraints: None,
            trace_metadata: serde_json::Value::Null,
        }
    }

    /// Results and records must follow input order even though the reads run
    /// concurrently, or the transcript stops matching the assistant message.
    #[tokio::test]
    async fn test_read_only_calls_are_batched_but_stay_in_input_order() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();
        for (name, body) in [("a.txt", "alpha"), ("b.txt", "beta"), ("c.txt", "gamma")] {
            std::fs::write(workspace.join(name), body).unwrap();
        }
        let container = batching_test_container(&temp).await;
        let session_id = y_core::types::SessionId("session-batch".to_string());
        let mut ctx = batching_ctx(&session_id, &workspace);
        let config = execution_config(session_id);

        let calls = vec![
            call("r1", "FileRead", serde_json::json!({ "path": "a.txt" })),
            call("r2", "FileRead", serde_json::json!({ "path": "b.txt" })),
            call("r3", "FileRead", serde_json::json!({ "path": "c.txt" })),
        ];

        let results = execute_tool_calls_ordered(&container, &config, &calls, None, &mut ctx).await;

        assert_eq!(results.len(), 3);
        assert!(results[0].1.contains("alpha"), "got {}", results[0].1);
        assert!(results[1].1.contains("beta"), "got {}", results[1].1);
        assert!(results[2].1.contains("gamma"), "got {}", results[2].1);

        let recorded: Vec<&str> = ctx
            .tool_calls_executed
            .iter()
            .map(|record| record.tool_call_id.as_str())
            .collect();
        assert_eq!(recorded, vec!["r1", "r2", "r3"]);
    }

    /// A write must not share a batch with the reads around it: batching it
    /// would let a read observe the file mid-write.
    #[tokio::test]
    async fn test_mutating_calls_are_never_batched_with_reads() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();
        std::fs::write(workspace.join("a.txt"), "alpha").unwrap();
        let container = batching_test_container(&temp).await;
        let session_id = y_core::types::SessionId("session-mixed".to_string());
        let ctx = batching_ctx(&session_id, &workspace);
        let config = execution_config(session_id);

        let read = call("r1", "FileRead", serde_json::json!({ "path": "a.txt" }));
        let write = call(
            "w1",
            "FileWrite",
            serde_json::json!({ "file_path": "new.txt", "content": "written" }),
        );

        assert!(is_parallel_safe(&container, &config, &read, &ctx).await);
        assert!(!is_parallel_safe(&container, &config, &write, &ctx).await);
    }

    /// State-mutating tools that the registry does not flag as dangerous and
    /// that declare no filesystem capability are exactly the case a denylist
    /// gets wrong: workflow and agent tools write durable stores, meta-tools
    /// re-enter the agent loop, and MCP or agent-created tools are opaque.
    #[tokio::test]
    async fn test_only_known_read_only_tools_are_batched() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();
        let container = batching_test_container(&temp).await;
        let session_id = y_core::types::SessionId("session-meta".to_string());
        let ctx = batching_ctx(&session_id, &workspace);
        let config = execution_config(session_id);

        let never_batched = [
            // Meta-tools: re-enter the agent loop or block on the user.
            "AskUser",
            "AgentSwarm",
            "Plan",
            "Task",
            "ToolSearch",
            // Durable-store mutations with no filesystem capability.
            "WorkflowCreate",
            "WorkflowUpdate",
            "WorkflowDelete",
            "ScheduleCreate",
            // Shared stateful session.
            "Browser",
            // Unregistered, MCP, or agent-created: unknown effects.
            "SomeMcpServer__do_thing",
        ];
        for name in never_batched {
            let tc = call("m1", name, serde_json::json!({}));
            assert!(
                !is_parallel_safe(&container, &config, &tc, &ctx).await,
                "{name} must not be batched"
            );
        }

        for name in PARALLEL_SAFE_TOOLS {
            let tc = call("s1", name, serde_json::json!({}));
            assert!(
                is_parallel_safe(&container, &config, &tc, &ctx).await,
                "{name} is on the allowlist but was not batchable"
            );
        }
    }

    /// The batch span is what makes the reads concurrent: a run of independent
    /// reads must be reported as one batch, and a write must cut it.
    #[tokio::test]
    async fn test_batch_span_groups_reads_and_is_cut_by_a_write() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();
        let container = batching_test_container(&temp).await;
        let session_id = y_core::types::SessionId("session-span".to_string());
        let ctx = batching_ctx(&session_id, &workspace);
        let config = execution_config(session_id);

        let reads = vec![
            call("r1", "FileRead", serde_json::json!({ "path": "a.txt" })),
            call("r2", "Grep", serde_json::json!({ "pattern": "x" })),
            call("r3", "Glob", serde_json::json!({ "pattern": "*" })),
        ];
        assert_eq!(
            next_batch_len(&container, &config, &reads, &ctx).await,
            3,
            "independent reads must form a single batch"
        );

        let mixed = vec![
            call("r1", "FileRead", serde_json::json!({ "path": "a.txt" })),
            call(
                "w1",
                "FileWrite",
                serde_json::json!({ "file_path": "new.txt", "content": "x" }),
            ),
            call("r2", "FileRead", serde_json::json!({ "path": "b.txt" })),
        ];
        assert_eq!(
            next_batch_len(&container, &config, &mixed, &ctx).await,
            1,
            "a write must terminate the batch"
        );
        assert_eq!(
            next_batch_len(&container, &config, &mixed[1..], &ctx).await,
            1,
            "a leading write runs alone"
        );
    }

    /// The tool-call limit is enforced per position, so a batch cannot overshoot
    /// it by the size of the batch.
    #[tokio::test]
    async fn test_batch_respects_the_tool_call_limit_exactly() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(workspace.join(name), "body").unwrap();
        }
        let container = batching_test_container(&temp).await;
        let session_id = y_core::types::SessionId("session-limit".to_string());
        let mut ctx = batching_ctx(&session_id, &workspace);
        let mut config = execution_config(session_id);
        config.max_tool_calls = 2;

        let calls = vec![
            call("r1", "FileRead", serde_json::json!({ "path": "a.txt" })),
            call("r2", "FileRead", serde_json::json!({ "path": "b.txt" })),
            call("r3", "FileRead", serde_json::json!({ "path": "c.txt" })),
        ];

        let results = execute_tool_calls_ordered(&container, &config, &calls, None, &mut ctx).await;

        assert!(results[0].0, "first call should run");
        assert!(results[1].0, "second call should run");
        assert!(!results[2].0, "third call must be blocked by the limit");
        assert!(results[2].1.contains("Tool call limit"));
        assert_eq!(ctx.tool_calls_executed.len(), 2);
    }
}
