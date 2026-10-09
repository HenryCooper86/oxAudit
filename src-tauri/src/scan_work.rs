//! Backend ownership of scan work, independent of page mounts and clients.
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::error::CommandError;
use crate::findings::service::ScanEventSink;

const RECENT_LIMIT: usize = 32;
const MAX_OPERATION_IDS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    Source,
    Dependencies,
    Binary,
    Image,
    History,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkDescriptor {
    pub operation_id: String,
    pub kind: WorkKind,
    pub target: String,
    pub status: String,
    pub run_id: Option<String>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkSnapshot {
    pub active: Option<WorkDescriptor>,
    pub recent: Vec<WorkDescriptor>,
}

struct ActiveWork {
    descriptor: WorkDescriptor,
    cancel: Arc<AtomicBool>,
}

/// Parent cancellation flows into an operation; scan cancellation cannot
/// poison the parent chat or a later operation using that parent's token.
struct CancellationRelay {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl CancellationRelay {
    fn start(parent: Arc<AtomicBool>, child: Arc<AtomicBool>) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::Builder::new()
            .name("scan-cancellation".into())
            .spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    if parent.load(Ordering::SeqCst) {
                        child.store(true, Ordering::SeqCst);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            })
            .map_err(|error| format!("cannot supervise scan cancellation: {error}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for CancellationRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
#[derive(Default)]
struct WorkState {
    active: Option<ActiveWork>,
    recent: VecDeque<WorkDescriptor>,
    used_ids: HashSet<uuid::Uuid>,
    cancelled_before_start: HashSet<uuid::Uuid>,
}

#[derive(Default)]
pub struct ScanWorkRegistry {
    state: Mutex<WorkState>,
}

impl ScanWorkRegistry {
    pub fn begin<'a>(
        &'a self,
        kind: WorkKind,
        target: &str,
        operation_id: Option<&str>,
        events: &'a dyn ScanEventSink,
    ) -> Result<WorkLease<'a>, String> {
        self.begin_with_cancel(kind, target, operation_id, None, events)
    }

    pub fn begin_with_cancel<'a>(
        &'a self,
        kind: WorkKind,
        target: &str,
        operation_id: Option<&str>,
        cancellation: Option<Arc<AtomicBool>>,
        events: &'a dyn ScanEventSink,
    ) -> Result<WorkLease<'a>, String> {
        let operation_id = match operation_id {
            Some(id) => uuid::Uuid::parse_str(id)
                .map_err(|_| "invalid scan operation ID")?
                .to_string(),
            None => uuid::Uuid::new_v4().to_string(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| "scan ownership unavailable")?;
        if let Some(active) = &state.active {
            return Err(format!(
                "A {:?} scan is already running for {}. Wait for it to finish or cancel it.",
                active.descriptor.kind, active.descriptor.target
            ));
        }
        let identity =
            uuid::Uuid::parse_str(&operation_id).map_err(|_| "invalid scan operation ID")?;
        if state.cancelled_before_start.contains(&identity) {
            return Err("scan cancelled before it started".into());
        }
        if state.used_ids.contains(&identity) {
            return Err(
                "This scan operation ID has already been used. Start a new operation.".into(),
            );
        }
        if state.used_ids.len() >= MAX_OPERATION_IDS {
            return Err("The scan owner reached its operation-ID allowance. Restart this process before starting another scan.".into());
        }
        let now = crate::commands::epoch_millis();
        let cancel = Arc::new(AtomicBool::new(
            cancellation
                .as_ref()
                .is_some_and(|parent| parent.load(Ordering::SeqCst)),
        ));
        let relay = cancellation
            .map(|parent| CancellationRelay::start(parent, cancel.clone()))
            .transpose()?;
        state.used_ids.insert(identity);
        state.active = Some(ActiveWork {
            descriptor: WorkDescriptor {
                operation_id: operation_id.clone(),
                kind,
                target: target.into(),
                status: "running".into(),
                run_id: None,
                started_at_ms: now,
                updated_at_ms: now,
            },
            cancel: cancel.clone(),
        });
        drop(state);
        let lease = WorkLease {
            registry: self,
            operation_id,
            cancel,
            events,
            finished: false,
            _cancellation_relay: relay,
        };
        lease.publish();
        Ok(lease)
    }

    pub fn snapshot(&self) -> Result<WorkSnapshot, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "scan ownership unavailable")?;
        Ok(WorkSnapshot {
            active: state.active.as_ref().map(|work| work.descriptor.clone()),
            recent: state.recent.iter().cloned().collect(),
        })
    }

    /// An explicit ID never falls back to cancelling whatever replaced it.
    pub fn cancel(&self, operation_id: Option<&str>, kinds: &[WorkKind]) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "scan ownership unavailable")?;
        let identity = operation_id
            .map(uuid::Uuid::parse_str)
            .transpose()
            .map_err(|_| "invalid scan operation ID")?;
        // A cancellation can overtake its HTTP scan request. Reserve that
        // exact ID so delayed registration cannot start the cancelled work.
        if let Some(identity) = identity {
            if !state.used_ids.contains(&identity) {
                if state.used_ids.len() >= MAX_OPERATION_IDS {
                    return Err("scan operation-ID allowance reached".into());
                }
                state.used_ids.insert(identity);
                state.cancelled_before_start.insert(identity);
                return Ok(true);
            }
        }
        let operation_id = identity.map(|id| id.to_string());
        let Some(active) = state.active.as_mut() else {
            return Ok(false);
        };
        if operation_id
            .as_ref()
            .is_some_and(|id| id != &active.descriptor.operation_id)
            || (!kinds.is_empty() && !kinds.contains(&active.descriptor.kind))
        {
            return Ok(false);
        }
        active.cancel.store(true, Ordering::SeqCst);
        active.descriptor.status = "cancelling".into();
        active.descriptor.updated_at_ms = crate::commands::epoch_millis();
        Ok(true)
    }
}

pub struct WorkLease<'a> {
    registry: &'a ScanWorkRegistry,
    operation_id: String,
    cancel: Arc<AtomicBool>,
    events: &'a dyn ScanEventSink,
    finished: bool,
    _cancellation_relay: Option<CancellationRelay>,
}

impl WorkLease<'_> {
    pub fn id(&self) -> &str {
        &self.operation_id
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }
    pub fn bind_run(&self, run_id: &str) {
        let changed = if let Ok(mut state) = self.registry.state.lock() {
            if let Some(active) = state.active.as_mut().filter(|active| {
                active.descriptor.operation_id == self.operation_id
                    && active.descriptor.run_id.as_deref() != Some(run_id)
            }) {
                active.descriptor.run_id = Some(run_id.into());
                active.descriptor.updated_at_ms = crate::commands::epoch_millis();
                true
            } else {
                false
            }
        } else {
            false
        };
        if changed {
            self.publish();
        }
    }
    pub fn finish(&mut self, status: &str, run_id: Option<&str>) {
        if let Some(run_id) = run_id {
            self.bind_run(run_id);
        }
        self.finish_inner(status);
    }
    fn finish_inner(&mut self, status: &str) {
        if self.finished {
            return;
        }
        if let Ok(mut state) = self.registry.state.lock() {
            if state
                .active
                .as_ref()
                .is_some_and(|active| active.descriptor.operation_id == self.operation_id)
            {
                let mut work = state.active.take().expect("active work checked").descriptor;
                work.status = status.into();
                work.updated_at_ms = crate::commands::epoch_millis();
                state.recent.push_front(work);
                state.recent.truncate(RECENT_LIMIT);
            }
        }
        self.finished = true;
        self.publish();
    }
    fn publish(&self) {
        if let Ok(snapshot) = self.registry.snapshot() {
            if let Ok(payload) = serde_json::to_value(snapshot) {
                let _ = self.events.emit("work://changed", payload);
            }
        }
    }
}

impl ScanEventSink for WorkLease<'_> {
    fn emit(&self, event: &str, mut payload: Value) -> Result<(), CommandError> {
        if event == "run://event" {
            if let Some(id) = payload.get("runId").and_then(Value::as_str) {
                self.bind_run(id);
            }
        }
        if let Some(object) = payload.as_object_mut() {
            object.insert(
                "operationId".into(),
                Value::String(self.operation_id.clone()),
            );
        }
        self.events.emit(event, payload)
    }
}

impl Drop for WorkLease<'_> {
    fn drop(&mut self) {
        let status = if self.cancel.load(Ordering::SeqCst) {
            "cancelled"
        } else {
            "failed"
        };
        if !self.finished {
            self.cancel.store(true, Ordering::SeqCst);
        }
        self.finish_inner(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Quiet;
    impl ScanEventSink for Quiet {
        fn emit(&self, _: &str, _: Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    #[test]
    fn conflicting_kinds_and_clients_cannot_replace_ownership() {
        let registry = ScanWorkRegistry::default();
        let first = registry
            .begin(WorkKind::Image, "first", None, &Quiet)
            .unwrap();
        assert!(registry
            .begin(WorkKind::Source, "second", None, &Quiet)
            .is_err());
        assert_eq!(
            registry.snapshot().unwrap().active.unwrap().operation_id,
            first.id()
        );
    }

    #[test]
    fn cancelled_token_is_never_revived_and_stale_id_cannot_cancel_next_run() {
        let registry = ScanWorkRegistry::default();
        let mut first = registry
            .begin(WorkKind::Image, "first", None, &Quiet)
            .unwrap();
        let first_id = first.id().to_owned();
        let token = first.cancellation();
        assert!(registry.cancel(Some(&first_id), &[]).unwrap());
        first.finish("cancelled", Some("receipt-one"));
        let second = registry
            .begin(WorkKind::Image, "second", None, &Quiet)
            .unwrap();
        assert!(token.load(Ordering::SeqCst));
        assert!(!registry.cancel(Some(&first_id), &[]).unwrap());
        assert!(!second.cancellation().load(Ordering::SeqCst));
        assert_eq!(
            registry.snapshot().unwrap().recent[0].run_id.as_deref(),
            Some("receipt-one")
        );
    }

    #[test]
    fn legacy_category_cancel_does_not_cross_scan_kinds() {
        let registry = ScanWorkRegistry::default();
        let work = registry
            .begin(WorkKind::History, "repo", None, &Quiet)
            .unwrap();
        assert!(!registry.cancel(None, &[WorkKind::Source]).unwrap());
        assert!(!work.cancellation().load(Ordering::SeqCst));
        assert!(registry.cancel(None, &[WorkKind::History]).unwrap());
    }

    #[test]
    fn evicting_recent_receipts_never_allows_an_old_operation_id_to_be_reused() {
        let registry = ScanWorkRegistry::default();
        let original = uuid::Uuid::new_v4().to_string();
        let mut first = registry
            .begin(WorkKind::Source, "first", Some(&original), &Quiet)
            .unwrap();
        first.finish("completed", None);
        for _ in 0..RECENT_LIMIT + 1 {
            registry
                .begin(WorkKind::Source, "later", None, &Quiet)
                .unwrap()
                .finish("completed", None);
        }
        assert!(!registry
            .snapshot()
            .unwrap()
            .recent
            .iter()
            .any(|work| work.operation_id == original));
        assert!(registry
            .begin(WorkKind::Source, "reuse", Some(&original), &Quiet)
            .is_err());
        assert!(!registry.cancel(Some(&original), &[]).unwrap());
    }

    #[test]
    fn cancellation_that_overtakes_registration_cannot_start_or_cancel_replacement_work() {
        let registry = ScanWorkRegistry::default();
        let delayed = uuid::Uuid::new_v4().to_string();
        assert!(registry.cancel(Some(&delayed), &[]).unwrap());
        assert!(registry
            .begin(WorkKind::Image, "delayed", Some(&delayed), &Quiet)
            .err()
            .unwrap()
            .contains("cancelled"));
        let replacement = registry
            .begin(WorkKind::Source, "replacement", None, &Quiet)
            .unwrap();
        assert!(!registry.cancel(Some(&delayed), &[]).unwrap());
        assert!(!replacement.cancellation().load(Ordering::SeqCst));
    }

    #[test]
    fn dropped_work_releases_owner_with_explicit_terminal_state() {
        let registry = ScanWorkRegistry::default();
        {
            let work = registry
                .begin(WorkKind::Source, "repo", None, &Quiet)
                .unwrap();
            work.bind_run("saved-attempt");
        }
        let snapshot = registry.snapshot().unwrap();
        assert!(snapshot.active.is_none());
        assert_eq!(snapshot.recent[0].status, "failed");
        assert_eq!(snapshot.recent[0].run_id.as_deref(), Some("saved-attempt"));
    }

    #[test]
    fn operation_cancellation_does_not_cancel_its_parent_and_parent_cancellation_propagates() {
        let registry = ScanWorkRegistry::default();
        let parent = Arc::new(AtomicBool::new(false));
        let mut first = registry
            .begin_with_cancel(WorkKind::Source, "tool", None, Some(parent.clone()), &Quiet)
            .unwrap();
        assert!(registry.cancel(Some(first.id()), &[]).unwrap());
        assert!(!parent.load(Ordering::SeqCst));
        first.finish("cancelled", None);
        drop(first);
        let second = registry
            .begin_with_cancel(
                WorkKind::Source,
                "next tool",
                None,
                Some(parent.clone()),
                &Quiet,
            )
            .unwrap();
        assert!(!second.cancellation().load(Ordering::SeqCst));
        parent.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !second.cancellation().load(Ordering::SeqCst) && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(second.cancellation().load(Ordering::SeqCst));
    }
}
