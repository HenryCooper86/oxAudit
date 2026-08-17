//! Tool abstraction: y-agent-style `ToolDefinition` + registry, adapted to
//! Tauri. Tools are read-only by default; the safety posture is
//! "read-only/interactive auto-allowed, dangerous asks" (see guardrails).

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{json, Value};
use tauri::Manager;

use crate::ai::AiStreamEvent;
use crate::commands::AppState;

/// Everything a tool needs at execution time.
pub struct ToolContext {
    pub app: tauri::AppHandle,
    pub conversation_id: Option<String>,
    pub emit: Arc<dyn Fn(AiStreamEvent) + Send + Sync>,
}

impl ToolContext {
    pub fn state(&self) -> Option<tauri::State<'_, AppState>> {
        self.app.try_state::<AppState>()
    }
}

pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    /// JSON Schema (Draft 7) for the arguments object.
    pub parameters: Value,
    /// Read-only tools never modify anything — auto-allowed.
    pub read_only: bool,
    /// Interactive tools surface UI (ask_user) or own local state (todo).
    pub interactive: bool,
    /// Dangerous tools require explicit human approval.
    pub dangerous: bool,
}

pub type ToolFn = Box<
    dyn Fn(ToolContext, Value) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>
        + Send
        + Sync,
>;

pub struct Tool {
    pub spec: ToolSpec,
    pub run: ToolFn,
}

impl Tool {
    /// OpenAI function-calling definition (injected verbatim into `tools[]`).
    pub fn openai_definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": self.spec.name,
                "description": self.spec.description,
                "parameters": self.spec.parameters,
            }
        })
    }
}

/// Macro that builds a `Tool` from a spec + an async body.
#[macro_export]
macro_rules! tool {
    ($name:literal, $desc:literal, $params:expr, $read_only:expr, $interactive:expr, $dangerous:expr, |$ctx:ident, $args:ident| $body:block) => {
        $crate::agent::tool::Tool {
            spec: $crate::agent::tool::ToolSpec {
                name: $name,
                description: $desc,
                parameters: $params,
                read_only: $read_only,
                interactive: $interactive,
                dangerous: $dangerous,
            },
            run: Box::new(|$ctx, $args| Box::pin(async move { $body })),
        }
    };
}

pub struct ToolRegistry {
    tools: HashMap<&'static str, Tool>,
}

impl ToolRegistry {
    pub fn from_tools(tools: Vec<Tool>) -> Self {
        let mut map = HashMap::new();
        for t in tools {
            map.insert(t.spec.name, t);
        }
        Self { tools: map }
    }

    pub fn get(&self, name: &str) -> Option<&Tool> {
        self.tools.get(name)
    }

    pub fn openai_definitions(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|t| t.openai_definition())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Argument validation helpers (lightweight JSON-Schema enforcement)
// ---------------------------------------------------------------------------

pub fn arg_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing or invalid string argument `{key}`"))
}

pub fn arg_str_opt(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

pub fn arg_str_default(args: &Value, key: &str, default: &str) -> String {
    arg_str_opt(args, key).unwrap_or_else(|| default.to_string())
}

pub fn arg_u64_opt(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(|v| v.as_u64())
}

pub fn arg_u64_default(args: &Value, key: &str, default: u64) -> u64 {
    arg_u64_opt(args, key).unwrap_or(default)
}

pub fn arg_bool_default(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Project-scoped path helpers
// ---------------------------------------------------------------------------

/// The currently active project root (set by scans / `set_active_project`).
pub fn project_root(ctx: &ToolContext) -> Result<PathBuf, String> {
    let st = ctx.state().ok_or("app state unavailable")?;
    let project = st.active_project.lock().unwrap().clone();
    drop(st);
    project.ok_or_else(|| "no active project — run a scan or set the project folder first".into())
}

/// Resolve a (possibly relative) path and ensure it stays inside the project
/// root (canonicalized prefix check — no traversal).
pub fn resolve_in_project(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let requested = Path::new(rel);
    let full = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    let canon_root = root
        .canonicalize()
        .map_err(|e| format!("cannot resolve project root: {e}"))?;
    let canon = full
        .canonicalize()
        .map_err(|e| format!("path not found or unreadable: {e}"))?;
    if !canon.starts_with(&canon_root) {
        return Err("path escapes the project root".into());
    }
    Ok(canon)
}

/// Display path relative to the project root.
pub fn display_rel(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .to_string_lossy()
        .replace('\\', "/")
}
