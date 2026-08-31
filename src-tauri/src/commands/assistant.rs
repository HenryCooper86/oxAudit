//! AI assistant chat, streaming, and usage commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;

#[tauri::command]
pub async fn chat(
    state: State<'_, AppState>,
    request: ChatRequest,
) -> Result<ChatResponse, String> {
    let public = state.settings.lock().unwrap().ai.clone();
    if !public.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let settings =
        crate::credentials::resolve_ai_settings(&public, state.credentials.as_ref(), None)
            .map_err(|error| error.to_string())?;
    state.ai.chat(&settings, request).await
}

#[tauri::command]
pub async fn analyze_finding(
    state: State<'_, AppState>,
    finding: Finding,
) -> Result<ChatResponse, String> {
    let public = state.settings.lock().unwrap().ai.clone();
    if !public.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let settings =
        crate::credentials::resolve_ai_settings(&public, state.credentials.as_ref(), None)
            .map_err(|error| error.to_string())?;
    let messages = crate::ai::analyze_finding_messages(&finding, &public);
    state
        .ai
        .chat(
            &settings,
            ChatRequest {
                messages,
                temperature: None,
                max_tokens: None,
                conversation_id: None,
                allow_compaction: true,
            },
        )
        .await
}

#[tauri::command]
pub async fn research_cve(
    state: State<'_, AppState>,
    cve: crate::models::CveItem,
    osv: Option<Value>,
) -> Result<ChatResponse, String> {
    let public = state.settings.lock().unwrap().ai.clone();
    if !public.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let settings =
        crate::credentials::resolve_ai_settings(&public, state.credentials.as_ref(), None)
            .map_err(|error| error.to_string())?;
    let messages = crate::ai::research_cve_messages(&cve, osv.as_ref(), &public);
    state
        .ai
        .chat(
            &settings,
            ChatRequest {
                messages,
                temperature: None,
                max_tokens: None,
                conversation_id: None,
                allow_compaction: true,
            },
        )
        .await
}

/// Start a streaming chat turn. Returns immediately with a `run_id`; the turn
/// runs on a background task that emits events:
///   `ai://started` { runId } · `ai://event` { runId, type, ... }
///   `ai://done`    { runId, content, model, usage }
///   `ai://error`   { runId, message }
#[tauri::command]
pub async fn stream_chat(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ChatRequest,
    run_id: Option<String>,
) -> Result<StreamStarted, String> {
    let public = state.settings.lock().unwrap().ai.clone();
    if !public.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let settings =
        crate::credentials::resolve_ai_settings(&public, state.credentials.as_ref(), None)
            .map_err(|error| error.to_string())?;
    let run_id = resolve_stream_run_id(run_id)?;
    let run_id_response = run_id.clone();
    let cancel = Arc::new(crate::agent::tool::RunCancellation::new());
    let steer = Arc::new(crate::agent::tool::SteerQueue::new());
    let project_root = capture_active_project(&state);
    {
        let mut active_chats = state.active_chats.lock().unwrap();
        if active_chats.contains_key(&run_id) {
            return Err("a chat stream with that run id is already active".into());
        }
        active_chats.insert(run_id.clone(), cancel.clone());
        state
            .pending_steers
            .lock()
            .unwrap()
            .insert(run_id.clone(), steer.clone());
    }

    let client = crate::ai::AiClient::new(state.http.clone());
    let registry = crate::agent::tool::ToolRegistry::from_tools(crate::agent::tools::builtins());
    let app2 = app.clone();
    let usage_path = usage_path(&app)?;
    let conversation_id = request.conversation_id.clone();
    let user_messages: Vec<Value> = request
        .messages
        .into_iter()
        .map(|m| json!({ "role": m.role, "content": m.content }))
        .collect();

    tokio::spawn(async move {
        let _ = app2.emit("ai://started", json!({ "runId": run_id.clone() }));
        let app2_emit = app2.clone();
        let event_run_id = run_id.clone();
        let emitter: Arc<dyn Fn(crate::ai::AiStreamEvent) + Send + Sync> = Arc::new(move |ev| {
            if let Ok(payload) = stream_event_payload(&event_run_id, ev) {
                let _ = app2_emit.emit("ai://event", payload);
            }
        });
        let result =
            crate::agent::loop_engine::run_turn(crate::agent::loop_engine::RunTurnRequest {
                client: &client,
                settings: &settings,
                registry: &registry,
                user_messages,
                conversation_id: conversation_id.clone(),
                project_root,
                app: app2.clone(),
                cancel: Some(cancel.clone()),
                steer: Some(steer.clone()),
                emit: emitter,
                allow_compaction: request.allow_compaction,
            })
            .await;
        match result {
            Ok((content, usage)) => {
                if let (Some(cid), Some(usage)) = (&conversation_id, &usage) {
                    if let Err(error) = UsageStore::record_persisted(
                        &usage_path,
                        cid,
                        crate::ai::usage::UsageRecord {
                            at: chrono::Utc::now().to_rfc3339(),
                            model: settings.model.clone(),
                            prompt_tokens: usage.prompt_tokens,
                            completion_tokens: usage.completion_tokens,
                            cost_usd: crate::ai::usage::estimate_cost(
                                &settings.model,
                                usage.prompt_tokens,
                                usage.completion_tokens,
                            ),
                        },
                    ) {
                        log::error!("cannot persist assistant usage: {error}");
                    }
                }
                let _ = app2.emit(
                    "ai://done",
                    json!({
                        "runId": run_id.clone(),
                        "content": content,
                        "model": settings.model,
                        "usage": usage,
                    }),
                );
            }
            Err(e) => {
                let _ = app2.emit(
                    "ai://error",
                    json!({ "runId": run_id.clone(), "message": e.user_message() }),
                );
            }
        }
        if let Some(app_state) = app2.try_state::<AppState>() {
            if let Ok(mut chats) = app_state.active_chats.lock() {
                chats.remove(&run_id);
            }
            if let Ok(mut steers) = app_state.pending_steers.lock() {
                steers.remove(&run_id);
            }
        }
    });

    Ok(StreamStarted {
        run_id: run_id_response,
    })
}

/// Request cancellation of an in-flight chat stream.
#[tauri::command]
pub fn cancel_chat(state: State<'_, AppState>, run_id: String) -> Result<(), String> {
    if let Some(cancellation) = state.active_chats.lock().unwrap().get(&run_id) {
        cancellation.cancel();
    }
    Ok(())
}

/// The agent's todo list for one conversation.
///
/// The live list arrives on the event stream while a turn runs; this is how the
/// UI recovers it when switching back to a session between turns.
#[tauri::command]
pub fn todo_list(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<crate::agent::tools::TodoItem>, String> {
    Ok(state
        .todos
        .lock()
        .unwrap()
        .get(&conversation_id)
        .cloned()
        .unwrap_or_default())
}

/// Queue a message for a turn that is already running.
///
/// Returns `false` when the run is no longer active, which is the signal for the
/// caller to send the text as an ordinary new turn instead. This races by
/// nature: the turn can finish between the user pressing Enter and this landing.
#[tauri::command]
pub fn steer_chat(
    state: State<'_, AppState>,
    run_id: String,
    message: String,
) -> Result<bool, String> {
    let message = message.trim().to_string();
    if message.is_empty() {
        return Err("steer message must not be empty".into());
    }
    if message.len() > MAX_STEER_CHARS {
        return Err(format!(
            "steer message is too long (limit {MAX_STEER_CHARS} characters)"
        ));
    }

    // The queue itself is the authority on whether the run can still take a
    // message: it is removed when the run tears down, and closed atomically
    // while empty just before the run finishes. No separate liveness check can
    // be as precise, because the run could finish between the two lookups.
    match state.pending_steers.lock().unwrap().get(&run_id) {
        Some(queue) => Ok(queue.push(message)),
        None => Ok(false),
    }
}

/// Resolve a pending HITL permission request.
#[tauri::command]
pub fn respond_permission(
    state: State<'_, AppState>,
    request_id: String,
    approve: bool,
) -> Result<(), String> {
    if let Some(tx) = state
        .pending_permissions
        .lock()
        .unwrap()
        .remove(&request_id)
    {
        let _ = tx.send(approve);
    }
    Ok(())
}

/// Resolve a pending `ask_user` interaction with the user's answers.
#[tauri::command]
pub fn respond_interaction(
    state: State<'_, AppState>,
    request_id: String,
    answers: Value,
) -> Result<(), String> {
    if let Some(tx) = state
        .pending_interactions
        .lock()
        .unwrap()
        .remove(&request_id)
    {
        let _ = tx.send(answers);
    }
    Ok(())
}

#[tauri::command]
pub fn get_conversation_usage(
    app: AppHandle,
    conversation_id: String,
) -> Result<UsageSummary, String> {
    let store = UsageStore::load(&usage_path(&app)?)?;
    Ok(store.conversation_summary(&conversation_id))
}

#[tauri::command]
pub fn get_total_usage(app: AppHandle) -> Result<UsageSummary, String> {
    let store = UsageStore::load(&usage_path(&app)?)?;
    Ok(store.total())
}

#[tauri::command]
pub async fn test_ai(state: State<'_, AppState>) -> Result<crate::models::AiStatus, String> {
    let public = state.settings.lock().unwrap().ai.clone();
    if public.base_url.trim().is_empty() {
        return Err("no AI endpoint configured".into());
    }
    let settings =
        crate::credentials::resolve_ai_settings(&public, state.credentials.as_ref(), None)
            .map_err(|error| error.to_string())?;
    state.ai.test_connection(&settings).await
}

#[tauri::command]
pub async fn test_ai_with(
    state: State<'_, AppState>,
    request: TestAiRequest,
) -> Result<crate::models::AiStatus, String> {
    let settings = crate::credentials::resolve_ai_settings(
        &request.settings,
        state.credentials.as_ref(),
        Some(&request.ai_api_key),
    )
    .map_err(|error| error.to_string())?;
    state.ai.test_connection(&settings).await
}
