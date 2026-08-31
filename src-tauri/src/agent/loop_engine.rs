//! The bounded agent loop (y-agent `execute_inner`, trimmed): model turn →
//! execute tool calls → repeat, with dual iteration/call budgets, permission
//! gate + HITL, loop guard, and cancellation.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use super::guardrails::{classify, LoopGuard, Permission};
use super::rate_limit::RateLimitDecision;
use super::tool::{
    wait_for_pending_response, PendingWaitError, RunCancellation, SteerQueue, ToolContext,
    ToolRegistry,
};
use crate::ai::errors::LlmError;
use crate::ai::{AiClient, AiStreamEvent};
use crate::commands::AppState;
use crate::credentials::ResolvedAiSettings;
use crate::models::Usage;
use tauri::Manager;

pub const MAX_ITERATIONS: usize = 10;
pub const MAX_TOOL_CALLS: usize = 30;
const HITL_TIMEOUT_SECS: u64 = 120;
const TOOL_RESULT_MAX_CHARS: usize = 20000;

fn truncate(s: &str, n: usize) -> String {
    crate::scanners::secrets::truncate(s, n)
}

struct SafeToolResult {
    success: bool,
    payload: String,
    preview: String,
}

fn safe_tool_result(result: Result<Value, String>) -> SafeToolResult {
    let (success, raw) = match result {
        Ok(value) => (true, value.to_string()),
        Err(error) => (false, json!({ "error": error }).to_string()),
    };
    let payload = crate::scanners::redact_secrets_in_text(&raw);
    let preview = truncate(&payload, 500);
    SafeToolResult {
        success,
        payload,
        preview,
    }
}

/// True while the most recent assistant message has requested tool calls that
/// are not all answered yet.
///
/// This is the window in which a `user` message must not be inserted: providers
/// require every `tool_calls` entry to be followed by its matching `tool`
/// results before any other role appears.
fn awaiting_tool_results(messages: &[Value]) -> bool {
    let Some(index) = messages
        .iter()
        .rposition(|m| m.get("role").and_then(Value::as_str) == Some("assistant"))
    else {
        return false;
    };

    let requested = messages[index]
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if requested == 0 {
        return false;
    }

    let answered = messages[index + 1..]
        .iter()
        .filter(|m| m.get("role").and_then(Value::as_str) == Some("tool"))
        .count();
    answered < requested
}

/// Append steered messages as `user` turns and tell the UI about each one.
///
/// Only ever called at an iteration boundary, where every `tool` result for the
/// preceding assistant turn has already been appended. The debug assertion keeps
/// that guarantee honest if a call site ever moves.
fn fold_steers(
    pending: Vec<String>,
    messages: &mut Vec<Value>,
    emit: &Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
) -> usize {
    debug_assert!(
        !awaiting_tool_results(messages),
        "a steer must never be folded in between requested tool calls and their results",
    );
    for text in &pending {
        messages.push(json!({ "role": "user", "content": text }));
        emit(AiStreamEvent::Steer { text: text.clone() });
    }
    pending.len()
}

/// Fold whatever is queued right now, leaving the queue open for more.
fn drain_steers(
    steer: Option<&Arc<SteerQueue>>,
    messages: &mut Vec<Value>,
    emit: &Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
) -> usize {
    match steer {
        Some(queue) => fold_steers(queue.drain(), messages, emit),
        None => 0,
    }
}

/// Fold anything left and stop accepting more. Used on the wrap-up paths, where
/// one final model call still happens and can carry a late steer.
fn close_steers(
    steer: Option<&Arc<SteerQueue>>,
    messages: &mut Vec<Value>,
    emit: &Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
) -> usize {
    match steer {
        Some(queue) => fold_steers(queue.close(), messages, emit),
        None => 0,
    }
}

/// Run one user turn: streams text events, executes any tool calls the model
/// requests (with guardrails), and continues until the model answers or the
/// budgets are exhausted. Returns the final answer text + last usage.
pub struct RunTurnRequest<'a> {
    pub client: &'a AiClient,
    pub settings: &'a ResolvedAiSettings,
    pub registry: &'a ToolRegistry,
    pub user_messages: Vec<Value>,
    pub conversation_id: Option<String>,
    pub project_root: Option<PathBuf>,
    pub app: tauri::AppHandle,
    pub cancel: Option<Arc<RunCancellation>>,
    pub steer: Option<Arc<SteerQueue>>,
    pub emit: Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
    /// When false, skip auto-compaction and let the preflight report the true
    /// error if the conversation does not fit (used by "retry with full context").
    pub allow_compaction: bool,
}

pub async fn run_turn(request: RunTurnRequest<'_>) -> Result<(String, Option<Usage>), LlmError> {
    let RunTurnRequest {
        client,
        settings,
        registry,
        user_messages,
        conversation_id,
        project_root,
        app,
        cancel,
        steer,
        emit,
        allow_compaction,
    } = request;
    let hint = "You are running inside oxAudit, a security research desktop app. \
You have research tools available: read_file, grep_project, glob, run_scan, run_dependency_scan, search_cve, \
get_cve_detail, query_osv_package, web_fetch, ask_user, todo. \
Use them when they genuinely help — never invent file contents, scan results, or CVE data \
you did not obtain from a tool. Prefer run_scan / search_cve over guessing. Reply in Markdown.";
    let mut messages = vec![json!({
        "role": "system",
        "content": format!("{}\n\n{}", settings.system_prompt, hint),
    })];
    messages.extend(user_messages);

    let tools = registry.openai_definitions();

    // A long conversation no longer fits: summarize the older turns into one
    // dense message and keep the newest turns verbatim, so the turn can proceed
    // instead of failing the preflight. A failed summarization falls through
    // uncompacted — `stream_chat` then reports the real cause.
    let needs_compaction = AiClient::estimate_context_tokens(&messages, &tools)
        .saturating_add(settings.max_tokens)
        > settings.context_window;
    if allow_compaction && needs_compaction {
        if let Some(selection) = super::compaction::plan_compaction(
            &messages,
            &tools,
            settings.context_window,
            settings.max_tokens,
        ) {
            let head: Vec<Value> = messages[1..selection.keep_from].to_vec();
            if let Ok(summary) =
                super::compaction::summarize_messages(client, settings, &head).await
            {
                messages = super::compaction::apply(&messages, selection.keep_from, &summary);
                emit(AiStreamEvent::ContextCompacted {
                    summarized_messages: selection.summarized as u32,
                    summary,
                });
            }
        }
    }

    let mut iterations_left = MAX_ITERATIONS;
    let mut tool_calls_left = MAX_TOOL_CALLS;
    let mut guard = LoopGuard::new();
    let mut guard_trips = 0usize;
    let mut final_usage: Option<Usage> = None;

    loop {
        // A steer is fresh human input, so it re-opens the budgets rather than
        // inheriting a run that has already spent them, and clears the loop
        // guard. Budgets stay bounded per steer; they are topped up to half the
        // limit, not reset to full.
        if drain_steers(steer.as_ref(), &mut messages, &emit) > 0 {
            iterations_left = iterations_left.max(MAX_ITERATIONS / 2);
            tool_calls_left = tool_calls_left.max(MAX_TOOL_CALLS / 2);
            guard.reset();
            guard_trips = 0;
        }

        if iterations_left == 0 {
            close_steers(steer.as_ref(), &mut messages, &emit);
            messages.push(json!({
                "role": "system",
                "content": "Iteration budget exhausted. Stop and finish with what you have.",
            }));
            // one last chance to answer without tools
            let outcome = client
                .stream_chat(
                    settings,
                    messages.clone(),
                    vec![],
                    cancel.as_ref().map(|c| c.flag()),
                    |ev| emit(ev),
                )
                .await?;
            if let Some(u) = &outcome.usage {
                final_usage = Some(u.clone());
            }
            return Ok((outcome.content, final_usage));
        }
        iterations_left -= 1;

        if let Some(c) = &cancel {
            if c.is_cancelled() {
                return Err(LlmError::Cancelled);
            }
        }

        let outcome = client
            .stream_chat(
                settings,
                messages.clone(),
                tools.clone(),
                cancel.as_ref().map(|c| c.flag()),
                |ev| emit(ev),
            )
            .await?;
        if let Some(u) = &outcome.usage {
            final_usage = Some(u.clone());
        }

        if outcome.tool_calls.is_empty() {
            // The model produced an answer. Closing only succeeds while the
            // queue is empty, so this cannot drop a steer that raced the
            // decision: if one is pending we keep the run alive and let the
            // model respond to it instead of ending the turn here.
            let finished = steer.as_ref().map_or(true, |queue| queue.close_if_empty());
            if finished {
                return Ok((outcome.content, final_usage));
            }
            messages.push(json!({ "role": "assistant", "content": outcome.content }));
            continue;
        }

        // assistant message carrying the requested tool calls
        let tcs: Vec<Value> = outcome
            .tool_calls
            .iter()
            .map(|tc| {
                json!({
                    "id": tc.id,
                    "type": "function",
                    "function": { "name": tc.name, "arguments": tc.arguments.to_string() },
                })
            })
            .collect();
        messages.push(json!({
            "role": "assistant",
            "content": outcome.content,
            "tool_calls": tcs,
        }));

        let mut force_stop = false;
        for tc in outcome.tool_calls {
            if tool_calls_left == 0 {
                messages.push(json!({
                    "role": "system",
                    "content": "Tool call limit reached. Do NOT request more tools. Finish with the information already available.",
                }));
                force_stop = true;
                break;
            }
            tool_calls_left -= 1;

            if guard.record(&tc.name, &tc.arguments) {
                guard_trips += 1;
                if guard_trips >= 2 {
                    return Ok((
                        format!(
                            "I stopped because I kept repeating the same tool call (`{}`). \
Let me summarize what I have and ask you how to proceed.",
                            tc.name
                        ),
                        final_usage,
                    ));
                }
                messages.push(json!({
                    "role": "system",
                    "content": format!(
                        "Loop guard: you are repeating the same tool call (`{}`). Stop calling tools and reason from what you already have.",
                        tc.name
                    ),
                }));
                force_stop = true;
                break;
            }

            let Some(tool) = registry.get(&tc.name) else {
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": "{\"error\":\"unknown tool\"}",
                }));
                continue;
            };

            // ---- permission pipeline ----
            let decision = match classify(&tool.spec) {
                Permission::Allow => Permission::Allow,
                Permission::Deny => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": "{\"error\":\"blocked by security policy — this tool is not permitted. Do NOT ask the user for permission or retry it.\"}",
                    }));
                    continue;
                }
                Permission::Ask => {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let req_id = uuid::Uuid::new_v4().to_string();
                    if let Some(st) = app.try_state::<AppState>() {
                        st.pending_permissions
                            .lock()
                            .unwrap()
                            .insert(req_id.clone(), tx);
                    }
                    emit(AiStreamEvent::PermissionRequest {
                        request_id: req_id.clone(),
                        tool: tc.name.clone(),
                        arguments: truncate(&tc.arguments.to_string(), 400),
                    });
                    let response = if let Some(st) = app.try_state::<AppState>() {
                        wait_for_pending_response(
                            &st.pending_permissions,
                            &req_id,
                            rx,
                            std::time::Duration::from_secs(HITL_TIMEOUT_SECS),
                            cancel.as_deref(),
                        )
                        .await
                    } else {
                        Err(PendingWaitError::ChannelClosed)
                    };
                    match response {
                        Ok(true) => Permission::Allow,
                        Err(PendingWaitError::Cancelled) => return Err(LlmError::Cancelled),
                        _ => {
                            messages.push(json!({
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "content": "{\"error\":\"denied by user\"}",
                            }));
                            continue;
                        }
                    }
                }
            };
            if decision != Permission::Allow {
                continue;
            }

            // ---- execute ----
            let started = std::time::Instant::now();
            emit(AiStreamEvent::ToolStart {
                tool_call_id: tc.id.clone(),
                name: tc.name.clone(),
                arguments: truncate(&tc.arguments.to_string(), 400),
            });
            if let Some(RateLimitDecision::Limited { retry_after }) = app
                .try_state::<AppState>()
                .map(|state| state.tool_rate_limiter.check(&tc.name))
            {
                let retry_after_ms = retry_after.as_millis().max(1) as u64;
                let retry_after_secs = retry_after.as_secs_f64().ceil() as u64;
                let message = format!(
                    "Per-tool rate limit reached. Retry `{}` in about {}s.",
                    tc.name,
                    retry_after_secs.max(1)
                );
                emit(AiStreamEvent::ToolResult {
                    tool_call_id: tc.id.clone(),
                    name: tc.name.clone(),
                    success: false,
                    duration_ms: started.elapsed().as_millis() as u64,
                    result_preview: message.clone(),
                });
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json!({
                        "error": "rate_limited",
                        "message": message,
                        "retryAfterMs": retry_after_ms,
                    }).to_string(),
                }));
                continue;
            }
            let ctx = ToolContext {
                app: app.clone(),
                conversation_id: conversation_id.clone(),
                project_root: project_root.clone(),
                cancellation: cancel.clone(),
                emit: emit.clone(),
            };
            let result = (tool.run)(ctx, tc.arguments.clone()).await;
            if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                return Err(LlmError::Cancelled);
            }
            let duration_ms = started.elapsed().as_millis() as u64;
            let safe_result = safe_tool_result(result);
            emit(AiStreamEvent::ToolResult {
                tool_call_id: tc.id.clone(),
                name: tc.name.clone(),
                success: safe_result.success,
                duration_ms,
                result_preview: safe_result.preview,
            });
            messages.push(json!({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": truncate(&safe_result.payload, TOOL_RESULT_MAX_CHARS),
            }));
        }

        if force_stop {
            // one more model call so the model can answer from what it has
            close_steers(steer.as_ref(), &mut messages, &emit);
            let outcome = client
                .stream_chat(
                    settings,
                    messages.clone(),
                    vec![],
                    cancel.as_ref().map(|c| c.flag()),
                    |ev| emit(ev),
                )
                .await?;
            if let Some(u) = &outcome.usage {
                final_usage = Some(u.clone());
            }
            return Ok((outcome.content, final_usage));
        }
    }
}

#[cfg(test)]
mod steer_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    type RecordedSteers = (
        Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
        Arc<StdMutex<Vec<String>>>,
    );

    fn assistant_requesting(names: &[&str]) -> Value {
        json!({
            "role": "assistant",
            "content": "",
            "tool_calls": names.iter().enumerate().map(|(i, n)| json!({
                "id": format!("call-{i}"),
                "type": "function",
                "function": { "name": n, "arguments": "{}" },
            })).collect::<Vec<_>>(),
        })
    }

    fn tool_result(id: &str) -> Value {
        json!({ "role": "tool", "tool_call_id": id, "content": "{}" })
    }

    #[test]
    fn tool_payload_and_preview_share_the_same_secret_redaction() {
        const CANARY: &str = "oxaudit-agent-secret-canary-7D4zP9q2";
        let result = Ok(json!({ "content": format!("token = \"{CANARY}\"") }));

        let safe = safe_tool_result(result);

        assert!(safe.success);
        assert!(!safe.payload.contains(CANARY));
        assert!(!safe.preview.contains(CANARY));
        assert!(safe.payload.contains("[REDACTED]"));
        assert_eq!(safe.preview, truncate(&safe.payload, 500));
    }

    /// Collects emitted events so tests can assert on what the UI would see.
    fn recorder() -> RecordedSteers {
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let sink = seen.clone();
        let emit: Arc<dyn Fn(AiStreamEvent) + Send + Sync> = Arc::new(move |ev| {
            if let AiStreamEvent::Steer { text } = ev {
                sink.lock().unwrap().push(text);
            }
        });
        (emit, seen)
    }

    #[test]
    fn pending_tool_calls_are_detected_until_every_result_lands() {
        let mut messages = vec![json!({ "role": "user", "content": "hi" })];
        assert!(!awaiting_tool_results(&messages));

        messages.push(assistant_requesting(&["grep_project", "read_file"]));
        assert!(awaiting_tool_results(&messages));

        messages.push(tool_result("call-0"));
        assert!(
            awaiting_tool_results(&messages),
            "one of two results is not enough to reopen the window"
        );

        messages.push(tool_result("call-1"));
        assert!(!awaiting_tool_results(&messages));
    }

    #[test]
    fn an_assistant_message_without_tool_calls_never_blocks_a_steer() {
        let messages = vec![
            json!({ "role": "user", "content": "hi" }),
            json!({ "role": "assistant", "content": "hello" }),
        ];
        assert!(!awaiting_tool_results(&messages));
    }

    #[test]
    fn queued_steers_are_folded_in_order_and_surfaced_to_the_ui() {
        let queue = Arc::new(SteerQueue::new());
        queue.push("check the auth module instead".into());
        queue.push("and skip the tests directory".into());

        let (emit, seen) = recorder();
        let mut messages = vec![json!({ "role": "user", "content": "audit this repo" })];
        let folded = drain_steers(Some(&queue), &mut messages, &emit);

        assert_eq!(folded, 2);
        assert_eq!(
            messages[1..]
                .iter()
                .map(|m| (m["role"].as_str().unwrap(), m["content"].as_str().unwrap()))
                .collect::<Vec<_>>(),
            vec![
                ("user", "check the auth module instead"),
                ("user", "and skip the tests directory"),
            ],
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                "check the auth module instead".to_string(),
                "and skip the tests directory".to_string()
            ],
        );
    }

    #[test]
    fn draining_twice_does_not_replay_messages_already_folded_in() {
        let queue = Arc::new(SteerQueue::new());
        queue.push("first".into());

        let (emit, _) = recorder();
        let mut messages = Vec::new();
        assert_eq!(drain_steers(Some(&queue), &mut messages, &emit), 1);
        assert_eq!(drain_steers(Some(&queue), &mut messages, &emit), 0);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn a_run_without_a_steer_queue_is_unaffected() {
        let (emit, _) = recorder();
        let mut messages = vec![json!({ "role": "user", "content": "hi" })];
        assert_eq!(drain_steers(None, &mut messages, &emit), 0);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn a_queue_stops_accepting_once_closed_so_the_caller_can_fall_back() {
        let queue = SteerQueue::new();
        assert!(queue.push("first".into()));

        assert!(
            !queue.close_if_empty(),
            "a queue holding a message must refuse to close"
        );
        assert!(
            queue.push("second".into()),
            "a refused close must leave the queue open"
        );

        assert_eq!(queue.drain(), vec!["first".to_string(), "second".into()]);
        assert!(queue.close_if_empty(), "an empty queue closes");
        assert!(
            !queue.push("too late".into()),
            "a closed queue rejects further messages"
        );
        assert!(queue.drain().is_empty());
    }

    #[test]
    fn closing_hands_back_anything_still_queued_instead_of_dropping_it() {
        let queue = Arc::new(SteerQueue::new());
        queue.push("late steer".into());

        let (emit, seen) = recorder();
        let mut messages = vec![json!({ "role": "user", "content": "audit" })];
        assert_eq!(close_steers(Some(&queue), &mut messages, &emit), 1);

        assert_eq!(messages[1]["content"], "late steer");
        assert_eq!(*seen.lock().unwrap(), vec!["late steer".to_string()]);
        assert!(!queue.push("after close".into()));
    }
}
