//! Sub-agent runner and prompt construction.
//!
//! Contains `ServiceAgentRunner` (bridges `AgentPool.delegate()` to
//! `AgentService.execute()`) and `build_subagent_system_prompt`.

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;
use uuid::Uuid;

use y_core::agent::{AgentRunConfig, AgentRunOutput, AgentRunner, DelegationError};
use y_core::provider::ToolCallingMode;
use y_core::runtime::{RuntimeAdapter, RuntimeBackend};
use y_core::template::RuntimeTemplateVars;
use y_core::types::{Message, Role};

use crate::container::ServiceContainer;
use crate::workspace_isolation::{tools_are_write_capable, DelegatedWorkspace};

use super::{AgentExecutionConfig, AgentExecutionError, AgentService};

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

/// Map an execution failure onto the delegation error that best describes it.
///
/// Provider rate limiting stays a distinct variant so batch schedulers can
/// throttle and requeue instead of burning the item's retry budget on what is
/// really back-pressure.
fn classify_delegation_failure(agent_name: &str, error: &AgentExecutionError) -> DelegationError {
    if let AgentExecutionError::LlmError {
        provider_error:
            Some(y_core::provider::ProviderError::RateLimited {
                provider,
                retry_after_secs,
            }),
        ..
    } = error
    {
        return DelegationError::RateLimited {
            provider: provider.clone(),
            retry_after_secs: *retry_after_secs,
        };
    }

    DelegationError::DelegationFailed {
        message: format!("AgentService execution failed for agent '{agent_name}': {error}"),
    }
}

// ---------------------------------------------------------------------------
// Sub-agent prompt augmentation
// ---------------------------------------------------------------------------

/// Build the effective system prompt for a sub-agent.
///
/// When `filtered_defs` is empty the base prompt is returned unchanged.
///
/// In [`ToolCallingMode::Native`] the base prompt is returned unchanged
/// because tools are sent via the API `tools` field -- no prompt injection
/// needed.
///
/// In [`ToolCallingMode::PromptBased`] the XML tool protocol and an
/// available-tools summary table are appended to the base prompt.
pub(crate) fn build_subagent_system_prompt(
    base_prompt: &str,
    filtered_defs: &[y_core::tool::ToolDefinition],
    tool_calling_mode: ToolCallingMode,
    tool_dialect: y_core::provider::ToolDialect,
    runtime_backend: RuntimeBackend,
    template_vars: &RuntimeTemplateVars,
) -> String {
    let base = if RuntimeTemplateVars::content_has_templates(base_prompt) {
        template_vars.expand(base_prompt)
    } else {
        base_prompt.to_string()
    };

    if filtered_defs.is_empty() {
        return base;
    }

    let tool_protocol = y_prompt::tool_protocol_for(runtime_backend);

    match tool_calling_mode {
        ToolCallingMode::Native => {
            format!("{base}\n\n{tool_protocol}")
        }
        ToolCallingMode::PromptBased => {
            let tools_summary = crate::container::build_agent_tools_summary(filtered_defs);
            let syntax = y_tools::prompt_tool_call_syntax_for(tool_dialect);
            format!("{base}\n\n{tool_protocol}\n\n{syntax}\n\n{tools_summary}")
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceAgentRunner -- bridges AgentPool.delegate() -> AgentService.execute()
// ---------------------------------------------------------------------------

/// `AgentRunner` implementation that uses `AgentService::execute()`.
///
/// Replaces `SingleTurnRunner` -- sub-agents now get the same execution loop
/// as the root chat agent (with capabilities controlled by `AgentRunConfig`).
pub struct ServiceAgentRunner {
    container: Arc<ServiceContainer>,
}

impl ServiceAgentRunner {
    /// Create a new `ServiceAgentRunner` backed by the given `ServiceContainer`.
    pub fn new(container: Arc<ServiceContainer>) -> Self {
        Self { container }
    }

    /// Validate a caller-supplied child session and load its persisted turns.
    ///
    /// The handle is honoured only when the session still exists, is a
    /// `SubAgent` session, is a direct child of `parent_id`, and was created
    /// for the same agent. Any mismatch returns `None`, which makes the caller
    /// create a fresh child -- a stale or forged handle must never hand one
    /// session's transcript to another.
    ///
    /// A freshly bound session has no turns yet, so an empty transcript is a
    /// normal result, not a rejection.
    async fn adoptable_child(
        &self,
        parent_id: &y_core::types::SessionId,
        candidate: &y_core::types::SessionId,
        agent_name: &str,
    ) -> Option<(y_core::types::SessionId, Vec<Message>)> {
        let child = match self.container.session_manager.get_session(candidate).await {
            Ok(child) => child,
            Err(error) => {
                warn!(%error, session_id = %candidate, "child session handle names an unknown session");
                return None;
            }
        };

        let owned = child.parent_id.as_ref() == Some(parent_id);
        let is_subagent = child.session_type == y_core::session::SessionType::SubAgent;
        let same_agent = child
            .agent_id
            .as_ref()
            .is_some_and(|id| id.as_str() == agent_name);
        if !(owned && is_subagent && same_agent) {
            warn!(
                session_id = %candidate,
                parent_id = %parent_id,
                owned,
                is_subagent,
                same_agent,
                "rejected child session handle; creating a fresh child"
            );
            return None;
        }

        let prior = self
            .container
            .session_manager
            .read_transcript(candidate)
            .await
            .unwrap_or_else(|error| {
                warn!(%error, session_id = %candidate, "could not read sub-agent transcript to resume");
                Vec::new()
            });

        Some((child.id, prior))
    }
}

#[async_trait::async_trait]
impl AgentRunner for ServiceAgentRunner {
    async fn run(&self, config: AgentRunConfig) -> Result<AgentRunOutput, DelegationError> {
        let start = std::time::Instant::now();

        // Filter tool definitions from the agent allowlist.
        // When allowed_tools is non-empty, agents can make tool calls across
        // multiple iterations (e.g. skill-ingestion reading companion files).
        let filtered_defs =
            AgentService::filter_tool_definitions(&self.container, &config.allowed_tools).await;
        let write_capable = tools_are_write_capable(&filtered_defs);

        // Convert filtered definitions to OpenAI function-calling JSON.
        let tool_definitions: Vec<serde_json::Value> = filtered_defs
            .iter()
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

        // Determine max_iterations: if tools are available, use the agent
        // definition's max_iterations; otherwise single-turn.
        let max_iterations = if tool_definitions.is_empty() {
            1
        } else {
            config.max_iterations
        };

        // Determine tool calling mode: use Native when tools are available.
        let tool_calling_mode = if tool_definitions.is_empty() {
            ToolCallingMode::default()
        } else {
            ToolCallingMode::Native
        };

        let user_content = match &config.input {
            serde_json::Value::String(s) => s.clone(),
            other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
        };

        // Pick up a pre-created trace_id from the diagnostics context
        // (set via DIAGNOSTICS_CTX task-local by DiagnosticsAgentDelegator).
        let external_trace_id = y_diagnostics::DIAGNOSTICS_CTX
            .try_with(|ctx| ctx.trace_id)
            .ok();

        // Pick up the parent turn's interaction context (set at the `Task`
        // interception in tool_dispatch). When present, the sub-agent runs
        // under a dedicated child session so its transcript is drill-in-able
        // from the info panel -- mirroring the plan / loop orchestrators.
        // Tool permissions follow the parent session's mode (incl. HITL), and
        // progress / cancel are wired to the parent turn. When absent (internal
        // / system delegations), the sub-agent stays detached as before.
        let interaction = crate::agent_service::delegation_ctx::DELEGATION_INTERACTION_CTX
            .try_with(Clone::clone)
            .ok();
        let interactive = interaction.is_some();
        let parent_workspace = if let Some(working_directory) = interaction
            .as_ref()
            .and_then(|context| context.working_directory.clone())
        {
            Some(working_directory)
        } else {
            let prompt_context = self.container.prompt_context.read().await;
            prompt_context.working_directory.clone()
        };

        // Resolve the child session for this delegation. When an interaction
        // context is present (Task tool), run under a SubAgent child session
        // of the parent so the delegation is visible in the info panel and its
        // transcript can be opened as a drill-in sub-chat. The child also
        // inherits the parent's permission / operation modes so HITL and
        // "allow all for session" behave identically.
        //
        // A caller holding a durable execution identity may name the child
        // session instead; `adoptable_child` validates ownership first.
        let (session_id, session_uuid, progress, cancel, child_session_handle, prior_messages) =
            match interaction {
                Some(ctx) => {
                    let parent_id = ctx.session_id.clone();
                    let adopted = match ctx.child_session_id.as_ref() {
                        Some(candidate) => {
                            self.adoptable_child(&parent_id, candidate, &config.agent_name)
                                .await
                        }
                        None => None,
                    };

                    let (child_id, prior_messages) = match adopted {
                        Some(adopted) => adopted,
                        None => (
                            create_child_session(&self.container, &parent_id, &config.agent_name)
                                .await?,
                            Vec::new(),
                        ),
                    };

                    let child_uuid =
                        Uuid::parse_str(child_id.as_str()).unwrap_or_else(|_| Uuid::nil());

                    // Inherit the parent's permission / operation modes so the
                    // sub-agent's tool gatekeeper resolves the same overrides the
                    // parent session has (e.g. BypassPermissions, FullAccess).
                    inherit_parent_modes(&self.container, &parent_id, &child_id).await;

                    (
                        Some(child_id.clone()),
                        child_uuid,
                        ctx.progress,
                        ctx.cancel,
                        Some(ChildSessionHandle {
                            id: child_id,
                            user_query: user_content.clone(),
                        }),
                        prior_messages,
                    )
                }
                None => (None, Uuid::nil(), None, None, None, Vec::new()),
            };

        let delegated_workspace = DelegatedWorkspace::prepare(
            &self.container,
            parent_workspace,
            config.workspace_isolation,
            config.workspace_snapshot_id.clone(),
            write_capable,
            interactive,
        )
        .await?;
        let workspace = delegated_workspace.working_directory();

        // Build the prompt only after isolation is provisioned so template
        // expansion and every delegated tool see the effective worktree path.
        let runtime_backend = self.container.runtime_manager.backend();
        let template_vars = RuntimeTemplateVars::from_runtime(workspace.as_deref());
        let system_prompt = build_subagent_system_prompt(
            &config.system_prompt,
            &filtered_defs,
            tool_calling_mode,
            y_core::provider::ToolDialect::default(),
            runtime_backend,
            &template_vars,
        );
        // A resumed child replays its persisted turns between the fresh system
        // prompt and the new instruction, so the model sees what it already did
        // instead of starting over. The stored system message is dropped: the
        // effective prompt is rebuilt from the current agent definition and
        // workspace, which may have moved since the interrupted attempt.
        let mut messages = Vec::with_capacity(prior_messages.len() + 2);
        messages.push(Message {
            message_id: y_core::types::generate_message_id(),
            role: Role::System,
            content: system_prompt.clone(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: y_core::types::now(),
            metadata: serde_json::Value::Null,
        });
        messages.extend(
            prior_messages
                .into_iter()
                .filter(|message| message.role != Role::System),
        );
        messages.push(Message {
            message_id: y_core::types::generate_message_id(),
            role: Role::User,
            content: user_content.clone(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: y_core::types::now(),
            metadata: serde_json::Value::Null,
        });

        let exec_config = AgentExecutionConfig {
            agent_name: config.agent_name.clone(),
            system_prompt,
            max_iterations,
            max_tool_calls: usize::MAX,
            tool_definitions,
            tool_calling_mode,
            tool_dialect: y_core::provider::ToolDialect::default(),
            messages,
            provider_id: None,
            preferred_models: config.preferred_models.clone(),
            provider_tags: config.provider_tags.clone(),
            fallback_provider_tags: config.fallback_provider_tags.clone(),
            request_mode: y_core::provider::RequestMode::TextChat,
            working_directory: workspace,
            additional_read_dirs: vec![],
            temperature: config.temperature,
            max_tokens: config.max_tokens,
            thinking: None,
            session_id,
            session_uuid,
            knowledge_collections: vec![],
            use_context_pipeline: false,
            user_query: user_content,
            external_trace_id,
            trust_tier: config.trust_tier,
            agent_allowed_tools: config.allowed_tools.clone(),
            prune_tool_history: config.prune_tool_history,
            response_format: config.response_format.clone(),
            image_generation_options: None,
            inherited_constraints: None,
            trace_metadata: self
                .container
                .dynamic_agent_service
                .execution_trace_metadata(&config.agent_name),
        };

        // Bound the child run. Without this the agent definition's
        // `timeout_secs` is inert, so one hung child pins a swarm slot (and its
        // global concurrency permit) for the lifetime of the parent turn.
        let run_timeout = Duration::from_secs(config.timeout_secs.max(1));
        let (result, timed_out) = match tokio::time::timeout(
            run_timeout,
            AgentService::execute(&self.container, &exec_config, progress, cancel),
        )
        .await
        {
            Ok(result) => (result, false),
            Err(_) => (
                Err(AgentExecutionError::LlmError {
                    message: format!(
                        "agent '{}' exceeded its {}s run timeout",
                        config.agent_name, config.timeout_secs
                    ),
                    provider_error: None,
                    partial_messages: Vec::new(),
                }),
                true,
            ),
        };

        // When running under a child session, persist the transcript so the
        // drill-in view is populated. The SubagentCompleted broadcast (which
        // triggers info-panel child-session reload) is already emitted by the
        // surrounding DiagnosticsAgentDelegator with the parent session's UUID.
        if let Some(handle) = child_session_handle.as_ref() {
            match &result {
                Ok(exec_result) if exec_result.content.is_empty() => {
                    persist_failed_subagent_turn(
                        &self.container,
                        handle,
                        &AgentExecutionError::LlmError {
                            message: format!(
                                "agent '{}' returned empty response",
                                config.agent_name
                            ),
                            provider_error: None,
                            partial_messages: Vec::new(),
                        },
                    )
                    .await;
                }
                Ok(exec_result) => {
                    crate::chat::ChatService::persist_subagent_turn(
                        &self.container,
                        &handle.id,
                        &handle.user_query,
                        exec_result,
                    )
                    .await;
                }
                Err(err) => {
                    persist_failed_subagent_turn(&self.container, handle, err).await;
                }
            }
        }

        let workspace_isolation = delegated_workspace.finalize(&self.container).await;

        let result = result.map_err(|error| {
            if timed_out {
                DelegationError::Timeout {
                    duration_ms: u64::try_from(run_timeout.as_millis()).unwrap_or(u64::MAX),
                }
            } else {
                classify_delegation_failure(&config.agent_name, &error)
            }
        })?;

        if result.content.is_empty() {
            return Err(DelegationError::DelegationFailed {
                message: format!("agent '{}' returned empty response", config.agent_name),
            });
        }

        let tokens_used = result.input_tokens + result.output_tokens;

        Ok(AgentRunOutput {
            text: result.content,
            tokens_used,
            input_tokens: result.input_tokens,
            output_tokens: result.output_tokens,
            model_used: result.model,
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(0),
            workspace_isolation,
            child_session_id: child_session_handle.map(|handle| handle.id),
        })
    }
}

// ---------------------------------------------------------------------------
// Child-session finalisation helpers (Task delegation only)
// ---------------------------------------------------------------------------

/// Bookkeeping for a child session created for a Task delegation.
struct ChildSessionHandle {
    id: y_core::types::SessionId,
    user_query: String,
}

/// Create the `SubAgent` session a delegated child runs under.
///
/// Shared with `AgentSwarmOrchestrator`, which binds the session before the
/// child starts so an interrupted item keeps a resumable identity.
pub(crate) async fn create_child_session(
    container: &ServiceContainer,
    parent_id: &y_core::types::SessionId,
    agent_name: &str,
) -> Result<y_core::types::SessionId, DelegationError> {
    container
        .session_manager
        .create_session(y_core::session::CreateSessionOptions {
            parent_id: Some(parent_id.clone()),
            session_type: y_core::session::SessionType::SubAgent,
            agent_id: Some(y_core::types::AgentId::from_string(agent_name)),
            title: Some(agent_name.to_string()),
        })
        .await
        .map(|child| child.id)
        .map_err(|error| DelegationError::DelegationFailed {
            message: format!("failed to create sub-agent session for '{agent_name}': {error}"),
        })
}

/// Copy the parent session's permission and operation modes onto the child so
/// the sub-agent's tool gatekeeper resolves the same overrides (e.g.
/// `BypassPermissions`, `FullAccess`) without re-prompting the user.
async fn inherit_parent_modes(
    container: &ServiceContainer,
    parent_id: &y_core::types::SessionId,
    child_id: &y_core::types::SessionId,
) {
    if let Some(mode) =
        crate::agent_service::tool_dispatch::session_permission_mode(container, parent_id).await
    {
        crate::agent_service::tool_dispatch::set_session_permission_mode(container, child_id, mode)
            .await;
    }
    if let Some(mode) =
        crate::agent_service::tool_dispatch::session_operation_mode(container, parent_id).await
    {
        let mut modes = container
            .session_state
            .session_operation_modes
            .write()
            .await;
        modes.insert(child_id.clone(), mode);
    }
}

/// Persist a failed delegation's partial transcript to the child session so
/// the drill-in view shows what was accomplished before the error. Mirrors
/// `persist_partial_subagent_turn` in the plan orchestrator.
async fn persist_failed_subagent_turn(
    container: &ServiceContainer,
    handle: &ChildSessionHandle,
    error: &AgentExecutionError,
) {
    use y_core::types::Role;
    let user_msg = Message {
        message_id: y_core::types::generate_message_id(),
        role: Role::User,
        content: handle.user_query.clone(),
        tool_call_id: None,
        tool_calls: vec![],
        timestamp: y_core::types::now(),
        metadata: serde_json::json!({}),
    };
    if let Err(e) = container
        .session_manager
        .append_message(&handle.id, &user_msg)
        .await
    {
        tracing::warn!(error = %e, session_id = %handle.id, "failed to persist sub-agent prompt on error");
    }

    let empty: Vec<Message> = Vec::new();
    let partial_messages: &[Message] = match error {
        AgentExecutionError::LlmError {
            partial_messages, ..
        }
        | AgentExecutionError::Cancelled {
            partial_messages, ..
        } => partial_messages,
        _ => &empty,
    };

    if partial_messages.is_empty() {
        let error_msg = Message {
            message_id: y_core::types::generate_message_id(),
            role: Role::Assistant,
            content: format!(
                "[Sub-agent execution failed before any output was produced: {error}]"
            ),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: y_core::types::now(),
            metadata: serde_json::json!({
                "error": format!("{error}"),
                "partial": true,
            }),
        };
        if let Err(e) = container
            .session_manager
            .append_message(&handle.id, &error_msg)
            .await
        {
            tracing::warn!(error = %e, session_id = %handle.id, "failed to persist sub-agent error message");
        }
        return;
    }

    for msg in partial_messages {
        if let Err(e) = container
            .session_manager
            .append_message(&handle.id, msg)
            .await
        {
            tracing::warn!(error = %e, session_id = %handle.id, "failed to persist partial sub-agent message");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_service::delegation_ctx::{
        DelegationInteractionCtx, DELEGATION_INTERACTION_CTX,
    };
    use crate::config::ServiceConfig;
    use crate::container::ServiceContainer;
    use tempfile::TempDir;
    use y_core::permission_types::PermissionMode;
    use y_core::session::{CreateSessionOptions, SessionState, SessionType};

    /// Provider back-pressure must stay distinguishable from a real failure, or
    /// batch schedulers treat a 429 as a permanent child error.
    #[test]
    fn test_rate_limited_provider_error_is_classified_as_rate_limited() {
        let error = AgentExecutionError::LlmError {
            message: "429".to_string(),
            provider_error: Some(y_core::provider::ProviderError::RateLimited {
                provider: "anthropic".to_string(),
                retry_after_secs: 12,
            }),
            partial_messages: Vec::new(),
        };

        match classify_delegation_failure("coder", &error) {
            DelegationError::RateLimited {
                provider,
                retry_after_secs,
            } => {
                assert_eq!(provider, "anthropic");
                assert_eq!(retry_after_secs, 12);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn test_other_execution_errors_stay_delegation_failures() {
        let error = AgentExecutionError::ToolLoopLimitExceeded { max_iterations: 7 };

        match classify_delegation_failure("coder", &error) {
            DelegationError::DelegationFailed { message } => {
                assert!(
                    message.contains("coder"),
                    "message lost the agent: {message}"
                );
            }
            other => panic!("expected DelegationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_llm_error_without_provider_error_stays_a_delegation_failure() {
        let error = AgentExecutionError::LlmError {
            message: "socket closed".to_string(),
            provider_error: None,
            partial_messages: Vec::new(),
        };

        assert!(matches!(
            classify_delegation_failure("coder", &error),
            DelegationError::DelegationFailed { .. }
        ));
    }

    async fn make_test_container() -> (ServiceContainer, TempDir) {
        let tmpdir = tempfile::TempDir::new().expect("tempdir");
        let config = ServiceConfig {
            storage: y_storage::StorageConfig {
                db_path: ":memory:".to_string(),
                pool_size: 1,
                wal_enabled: false,
                transcript_dir: tmpdir.path().join("transcripts"),
                ..y_storage::StorageConfig::default()
            },
            ..Default::default()
        };
        let container = ServiceContainer::from_config(&config)
            .await
            .expect("test container should build");
        (container, tmpdir)
    }

    fn make_run_config(agent_name: &str, prompt: &str) -> AgentRunConfig {
        AgentRunConfig {
            agent_name: agent_name.to_string(),
            system_prompt: "You are a helper.".to_string(),
            input: serde_json::json!({ "task": prompt }),
            preferred_models: vec![],
            fallback_models: vec![],
            provider_tags: vec![],
            fallback_provider_tags: vec![],
            temperature: None,
            max_tokens: None,
            timeout_secs: 30,
            allowed_tools: vec![],
            max_iterations: 1,
            trust_tier: None,
            trace_id: None,
            prune_tool_history: false,
            response_format: None,
            workspace_isolation: y_core::agent::WorkspaceIsolationPreference::default(),
            workspace_snapshot_id: None,
        }
    }

    /// A Task delegation (interaction context present) must create a `SubAgent`
    /// child session under the parent so the `InfoPanel` can surface it.
    #[tokio::test]
    async fn task_delegation_creates_subagent_child_session() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);

        // Parent session (the active chat session).
        let parent = container
            .session_manager
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("Parent".into()),
            })
            .await
            .unwrap();

        let runner = ServiceAgentRunner::new(Arc::clone(&container));
        let config = make_run_config("general-purpose", "do something");

        // Run inside a Task-delegation interaction context.
        let ctx = DelegationInteractionCtx {
            session_id: parent.id.clone(),
            progress: None,
            cancel: None,
            working_directory: None,
            child_session_id: None,
        };
        // The run fails (no provider configured), but the child session must
        // still be created and persisted.
        let _ = DELEGATION_INTERACTION_CTX
            .scope(ctx, runner.run(config))
            .await;

        // A SubAgent child session must exist under the parent.
        let children = container
            .session_manager
            .children(&parent.id)
            .await
            .unwrap();
        let sub = children
            .iter()
            .find(|c| c.session_type == SessionType::SubAgent)
            .expect("a SubAgent child session should be created");

        assert_eq!(sub.parent_id, Some(parent.id.clone()));
        assert_eq!(sub.state, SessionState::Active);
        assert_eq!(sub.title.as_deref(), Some("general-purpose"));

        // The child's transcript must contain the user prompt (persisted even
        // on failure so the drill-in view is not blank).
        let transcript = container
            .session_manager
            .read_transcript(&sub.id)
            .await
            .unwrap_or_default();
        assert!(
            transcript
                .iter()
                .any(|m| m.role == Role::User && m.content.contains("do something")),
            "child transcript should contain the delegation prompt"
        );
    }

    /// A Task delegation must inherit the parent session's permission mode so
    /// HITL / "allow all for session" applies to the sub-agent's tools.
    #[tokio::test]
    async fn task_delegation_inherits_parent_permission_mode() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);

        let parent = container
            .session_manager
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("Parent".into()),
            })
            .await
            .unwrap();

        // Set a bypass-permissions override on the parent session.
        crate::agent_service::tool_dispatch::set_session_permission_mode(
            &container,
            &parent.id,
            PermissionMode::BypassPermissions,
        )
        .await;
        let runner = ServiceAgentRunner::new(Arc::clone(&container));
        let config = make_run_config("general-purpose", "task");

        let ctx = DelegationInteractionCtx {
            session_id: parent.id.clone(),
            progress: None,
            cancel: None,
            working_directory: None,
            child_session_id: None,
        };
        let _ = DELEGATION_INTERACTION_CTX
            .scope(ctx, runner.run(config))
            .await;

        let children = container
            .session_manager
            .children(&parent.id)
            .await
            .unwrap();
        let sub = children
            .iter()
            .find(|c| c.session_type == SessionType::SubAgent)
            .expect("child session should exist");

        let child_mode =
            crate::agent_service::tool_dispatch::session_permission_mode(&container, &sub.id).await;
        assert_eq!(
            child_mode,
            Some(PermissionMode::BypassPermissions),
            "child session should inherit the parent's permission mode"
        );
    }

    /// An internal delegation (no interaction context) must NOT create a child
    /// session -- the detached behaviour is preserved for system agents.
    #[tokio::test]
    async fn internal_delegation_does_not_create_child_session() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);

        let parent = container
            .session_manager
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("Parent".into()),
            })
            .await
            .unwrap();

        let runner = ServiceAgentRunner::new(Arc::clone(&container));
        let config = make_run_config("title-generator", "summarise");

        // No DELEGATION_INTERACTION_CTX scope -- simulates an internal call.
        let _ = runner.run(config).await;

        let children = container
            .session_manager
            .children(&parent.id)
            .await
            .unwrap();
        assert!(
            children.is_empty(),
            "internal delegation must not create a child session"
        );
    }

    /// Create a `Main` session to act as a delegation parent.
    async fn parent_session(container: &ServiceContainer, title: &str) -> y_core::types::SessionId {
        container
            .session_manager
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some(title.to_string()),
            })
            .await
            .unwrap()
            .id
    }

    /// Run one delegation under `ctx` and return the `SubAgent` children of
    /// `parent` afterwards.
    async fn run_under(
        container: &Arc<ServiceContainer>,
        parent: &y_core::types::SessionId,
        child_session_id: Option<y_core::types::SessionId>,
    ) -> Vec<y_core::session::SessionNode> {
        let runner = ServiceAgentRunner::new(Arc::clone(container));
        let ctx = DelegationInteractionCtx {
            session_id: parent.clone(),
            progress: None,
            cancel: None,
            working_directory: None,
            child_session_id,
        };
        // The run itself fails (no provider configured); session resolution,
        // which is what these tests assert on, happens first.
        let _ = DELEGATION_INTERACTION_CTX
            .scope(ctx, runner.run(make_run_config("general-purpose", "task")))
            .await;

        container
            .session_manager
            .children(parent)
            .await
            .unwrap()
            .into_iter()
            .filter(|node| node.session_type == SessionType::SubAgent)
            .collect()
    }

    /// A caller that owns a child session must have it adopted, not duplicated.
    /// This is what lets a swarm retry resume the interrupted child.
    #[tokio::test]
    async fn caller_supplied_child_session_is_adopted() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);
        let parent = parent_session(&container, "Parent").await;

        let bound = create_child_session(&container, &parent, "general-purpose")
            .await
            .expect("bind child session");

        let children = run_under(&container, &parent, Some(bound.clone())).await;
        assert_eq!(
            children.len(),
            1,
            "adopting a bound child must not create a second one"
        );
        assert_eq!(children[0].id, bound);
    }

    /// A handle naming another parent's child must be refused: honouring it
    /// would hand one session's transcript to an unrelated delegation.
    #[tokio::test]
    async fn child_session_owned_by_another_parent_is_refused() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);
        let parent = parent_session(&container, "Parent").await;
        let stranger = parent_session(&container, "Stranger").await;

        let foreign = create_child_session(&container, &stranger, "general-purpose")
            .await
            .expect("bind child session");

        let children = run_under(&container, &parent, Some(foreign.clone())).await;
        assert_eq!(children.len(), 1, "a fresh child must be created instead");
        assert_ne!(
            children[0].id, foreign,
            "another parent's child must never be adopted"
        );
    }

    /// A handle for a different agent is refused: the stored transcript belongs
    /// to a different system prompt and toolset.
    #[tokio::test]
    async fn child_session_for_another_agent_is_refused() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);
        let parent = parent_session(&container, "Parent").await;

        let other_agent = create_child_session(&container, &parent, "code-reviewer")
            .await
            .expect("bind child session");

        // The refused session stays a child of the parent, so adoption is
        // proven by the count: a refusal means a second, fresh child exists.
        let children = run_under(&container, &parent, Some(other_agent.clone())).await;
        assert_eq!(
            children.len(),
            2,
            "a child bound to a different agent must not be adopted"
        );
        assert!(
            children.iter().any(|node| node.id != other_agent),
            "a fresh child must have been created for the requested agent"
        );
    }

    /// An unknown session id degrades to a fresh child rather than failing the
    /// delegation.
    #[tokio::test]
    async fn unknown_child_session_falls_back_to_a_fresh_child() {
        let (container, _tmp) = make_test_container().await;
        let container = Arc::new(container);
        let parent = parent_session(&container, "Parent").await;

        let children = run_under(
            &container,
            &parent,
            Some(y_core::types::SessionId::from_string("does-not-exist")),
        )
        .await;
        assert_eq!(children.len(), 1);
    }
}
