//! `Todo` tool: the agent's own task checklist.
//!
//! This is a **signal tool** -- `execute()` validates the operation and echoes
//! it back. The mutation is applied by `todo_tools` in `y-service`, which owns
//! the per-session [`TodoStore`](y_core::agent_todo::TodoStore) shared with the
//! context pipeline. Same pattern as `Plan` / `PlanOrchestrator`.

use async_trait::async_trait;

use y_core::agent_todo::TodoOp;
use y_core::runtime::RuntimeCapability;
use y_core::tool::{
    Tool, ToolCategory, ToolDefinition, ToolError, ToolInput, ToolOutput, ToolType,
};
use y_core::types::ToolName;

use super::lifecycle_signal::signal_output;

/// The `Todo` tool for agent-owned task tracking.
pub struct TodoTool {
    def: ToolDefinition,
}

impl TodoTool {
    /// Create a new `Todo` tool.
    pub fn new() -> Self {
        Self {
            def: Self::tool_definition(),
        }
    }

    /// The tool definition for `Todo`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: ToolName::from_string("Todo"),
            description: "Track your own multi-step work as a phased checklist. \
                Tasks are addressed by their verbatim content string -- there are \
                no generated IDs. The list is re-injected into your context every \
                turn, and a turn that ends with open tasks is continued instead \
                of finished. \
                \n\n\
                Create a list when the work needs 3 or more distinct steps, when \
                the user supplies a set of tasks, or when new instructions arrive \
                mid-task. After each `done`, the earliest remaining task is \
                promoted to in-progress automatically. Use `block` for work \
                waiting on external input: blocked tasks stay visible but do not \
                force a continuation."
                .into(),
            help: Some(
                "Operations (field `op`):\n\
                 - init: replace the list. `list` = [{phase, items[]}], or \
                   `items` = [..] for a single default phase.\n\
                 - append: add `items` to `phase`, creating the phase if needed.\n\
                 - start: mark `task` in progress.\n\
                 - done / drop / block / unblock: target `task` or a whole \
                   `phase`; `block` also takes `reason`.\n\
                 - rm: remove `task`, or `phase`, or the entire list when \
                   neither is given.\n\
                 - view: echo the list without changing it.\n\
                 \n\
                 Task content should be 5-10 words describing what, not how, and \
                 must stay stable once introduced."
                    .into(),
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "op": {
                        "type": "string",
                        "enum": [
                            "init", "append", "start", "done",
                            "drop", "block", "unblock", "rm", "view"
                        ],
                        "description": "The operation to apply"
                    },
                    "list": {
                        "type": "array",
                        "description": "Phased task list for `init`",
                        "items": {
                            "type": "object",
                            "properties": {
                                "phase": {
                                    "type": "string",
                                    "description": "Short noun phrase naming the phase"
                                },
                                "items": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Task contents in execution order"
                                }
                            },
                            "required": ["phase", "items"]
                        }
                    },
                    "items": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Task contents for `init` (flat form) or `append`"
                    },
                    "task": {
                        "type": "string",
                        "description": "Verbatim task content to target"
                    },
                    "phase": {
                        "type": "string",
                        "description": "Phase name to target"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why a task is blocked (`block` only)"
                    }
                },
                "required": ["op"]
            }),
            result_schema: None,
            category: ToolCategory::Agent,
            tool_type: ToolType::BuiltIn,
            capabilities: RuntimeCapability::default(),
            is_dangerous: false,
        }
    }
}

impl Default for TodoTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for TodoTool {
    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError> {
        // Validate here so a malformed call fails before reaching the service
        // layer; the accepted operation is applied by `todo_tools`.
        let op = TodoOp::from_arguments(&input.arguments).map_err(|error| {
            ToolError::ValidationError {
                message: error.to_string(),
            }
        })?;

        Ok(signal_output(serde_json::json!({
            "action": "todo",
            "op": op.name(),
            "status": "pending"
        })))
    }

    fn definition(&self) -> &ToolDefinition {
        &self.def
    }
}

#[cfg(test)]
mod tests;
