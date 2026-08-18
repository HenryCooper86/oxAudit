//! Tool abstraction: y-agent-style `ToolDefinition` + registry, adapted to
//! Tauri. Tools are read-only by default; the safety posture is
//! "read-only/interactive auto-allowed, dangerous asks" (see guardrails).

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::Manager;
use tokio::sync::{oneshot, Notify};

use crate::ai::AiStreamEvent;
use crate::commands::AppState;

/// Cancellation state for one chat run. The atomic flag keeps the existing
/// streaming-client contract while the notification wakes HITL waits promptly.
pub struct RunCancellation {
    flag: Arc<AtomicBool>,
    notify: Notify,
}

impl RunCancellation {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Notify::new(),
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    pub fn flag(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }

    pub async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PendingWaitError {
    Cancelled,
    TimedOut,
    ChannelClosed,
}

/// Wait for one permission or interaction response and always remove any
/// pending sender left behind by cancellation, timeout, or channel closure.
pub async fn wait_for_pending_response<T>(
    pending: &Mutex<HashMap<String, oneshot::Sender<T>>>,
    request_id: &str,
    receiver: oneshot::Receiver<T>,
    timeout: Duration,
    cancellation: Option<&RunCancellation>,
) -> Result<T, PendingWaitError> {
    let receive = async {
        match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(PendingWaitError::ChannelClosed),
            Err(_) => Err(PendingWaitError::TimedOut),
        }
    };
    tokio::pin!(receive);

    let result = match cancellation {
        Some(cancellation) => {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(PendingWaitError::Cancelled),
                response = &mut receive => response,
            }
        }
        None => receive.await,
    };

    pending.lock().unwrap().remove(request_id);
    result
}

/// Everything a tool needs at execution time.
pub struct ToolContext {
    pub app: tauri::AppHandle,
    pub conversation_id: Option<String>,
    pub project_root: Option<PathBuf>,
    pub cancellation: Option<Arc<RunCancellation>>,
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

pub fn project_root_from_snapshot(project: &Option<PathBuf>) -> Result<PathBuf, String> {
    project
        .clone()
        .ok_or_else(|| "no active project — run a scan or set the project folder first".into())
}

/// The project root captured when this run started.
pub fn project_root(ctx: &ToolContext) -> Result<PathBuf, String> {
    project_root_from_snapshot(&ctx.project_root)
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

#[cfg(test)]
mod lifecycle_tests {
    use super::{
        project_root_from_snapshot, wait_for_pending_response, PendingWaitError, RunCancellation,
    };
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;

    #[tokio::test]
    async fn cancellation_wakes_permission_wait_and_removes_pending_entry() {
        let cancellation = RunCancellation::new();
        let pending = Mutex::new(HashMap::new());
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        pending.lock().unwrap().insert("permission-1".into(), tx);

        let wait = wait_for_pending_response(
            &pending,
            "permission-1",
            rx,
            Duration::from_secs(120),
            Some(&cancellation),
        );
        tokio::pin!(wait);
        tokio::select! {
            result = &mut wait => panic!("permission wait ended before cancellation: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_millis(100), &mut wait)
            .await
            .expect("a cancelled permission wait must wake promptly");

        assert_eq!(result, Err(PendingWaitError::Cancelled));
        assert!(pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancellation_wakes_interaction_wait_and_removes_pending_entry() {
        let cancellation = RunCancellation::new();
        let pending = Mutex::new(HashMap::new());
        let (tx, rx) = tokio::sync::oneshot::channel::<Value>();
        pending.lock().unwrap().insert("interaction-1".into(), tx);

        let wait = wait_for_pending_response(
            &pending,
            "interaction-1",
            rx,
            Duration::from_secs(180),
            Some(&cancellation),
        );
        tokio::pin!(wait);
        tokio::select! {
            result = &mut wait => panic!("interaction wait ended before cancellation: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_millis(100), &mut wait)
            .await
            .expect("a cancelled interaction wait must wake promptly");

        assert_eq!(result, Err(PendingWaitError::Cancelled));
        assert!(pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn timed_out_hitl_wait_removes_its_pending_sender() {
        let pending = Mutex::new(HashMap::new());
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        pending.lock().unwrap().insert("permission-timeout".into(), tx);

        let result = wait_for_pending_response(
            &pending,
            "permission-timeout",
            rx,
            Duration::from_millis(1),
            None,
        )
        .await;

        assert_eq!(result, Err(PendingWaitError::TimedOut));
        assert!(pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn answered_hitl_wait_returns_response_and_leaves_no_pending_sender() {
        let pending = Mutex::new(HashMap::new());
        let (tx, rx) = tokio::sync::oneshot::channel();
        pending.lock().unwrap().insert("interaction-answer".into(), tx);
        let sender = pending
            .lock()
            .unwrap()
            .remove("interaction-answer")
            .unwrap();
        sender.send(json!({ "choice": "continue" })).unwrap();

        let result = wait_for_pending_response(
            &pending,
            "interaction-answer",
            rx,
            Duration::from_secs(1),
            None,
        )
        .await;

        assert_eq!(result, Ok(json!({ "choice": "continue" })));
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn project_root_comes_from_the_run_snapshot() {
        let captured = Some(PathBuf::from("/captured/project"));
        let later_global_project = Some(PathBuf::from("/different/project"));

        assert_eq!(
            project_root_from_snapshot(&captured).unwrap(),
            PathBuf::from("/captured/project")
        );
        assert_ne!(captured, later_global_project);
    }
}
