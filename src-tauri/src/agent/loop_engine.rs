//! The bounded agent loop (y-agent `execute_inner`, trimmed): model turn →
//! execute tool calls → repeat, with dual iteration/call budgets, permission
//! gate + HITL, loop guard, and cancellation.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use super::guardrails::{classify, LoopGuard, Permission};
use super::tool::{
    wait_for_pending_response, PendingWaitError, RunCancellation, ToolContext, ToolRegistry,
};
use crate::ai::errors::LlmError;
use crate::ai::{AiClient, AiStreamEvent};
use crate::commands::AppState;
use crate::models::{AiSettings, Usage};
use tauri::Manager;

pub const MAX_ITERATIONS: usize = 10;
pub const MAX_TOOL_CALLS: usize = 30;
const HITL_TIMEOUT_SECS: u64 = 120;
const TOOL_RESULT_MAX_CHARS: usize = 20000;

fn truncate(s: &str, n: usize) -> String {
    crate::scanners::secrets::truncate(s, n)
}

/// Run one user turn: streams text events, executes any tool calls the model
/// requests (with guardrails), and continues until the model answers or the
/// budgets are exhausted. Returns the final answer text + last usage.
pub async fn run_turn(
    client: &AiClient,
    settings: &AiSettings,
    registry: &ToolRegistry,
    user_messages: Vec<Value>,
    conversation_id: Option<String>,
    project_root: Option<PathBuf>,
    app: tauri::AppHandle,
    cancel: Option<Arc<RunCancellation>>,
    emit: Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
) -> Result<(String, Option<Usage>), LlmError> {
    let hint = "You are running inside VulnCompanion, a security research desktop app. \
You have research tools available: read_file, grep_project, glob, run_scan, search_cve, \
get_cve_detail, query_osv_package, web_fetch, ask_user, todo. \
Use them when they genuinely help — never invent file contents, scan results, or CVE data \
you did not obtain from a tool. Prefer run_scan / search_cve over guessing. Reply in Markdown.";
    let mut messages = vec![json!({
        "role": "system",
        "content": format!("{}\n\n{}", settings.system_prompt, hint),
    })];
    messages.extend(user_messages);

    let tools = registry.openai_definitions();
    let mut iterations_left = MAX_ITERATIONS;
    let mut tool_calls_left = MAX_TOOL_CALLS;
    let mut guard = LoopGuard::new();
    let mut guard_trips = 0usize;
    let mut final_usage: Option<Usage> = None;

    loop {
        if iterations_left == 0 {
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
            return Ok((outcome.content, final_usage));
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
            let (success, payload) = match result {
                Ok(v) => (true, v.to_string()),
                Err(e) => (false, json!({ "error": e }).to_string()),
            };
            emit(AiStreamEvent::ToolResult {
                tool_call_id: tc.id.clone(),
                name: tc.name.clone(),
                success,
                duration_ms,
                result_preview: truncate(&payload, 500),
            });
            messages.push(json!({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": truncate(&payload, TOOL_RESULT_MAX_CHARS),
            }));
        }

        if force_stop {
            // one more model call so the model can answer from what it has
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
