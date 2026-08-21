use oxaudit_application::{EventEnvelope, RunEventSink};
use tauri::{AppHandle, Emitter};

use crate::findings::service::ScanEventSink;

/// Versioned canonical events for the shared GUI run controller. Existing
/// `scan://*` events remain as a compatibility projection during migration.
pub struct CanonicalRunEvents<'a, E: ?Sized> {
    events: &'a E,
}

impl<'a, E: ?Sized> CanonicalRunEvents<'a, E> {
    pub fn new(events: &'a E) -> Self {
        Self { events }
    }
}

impl<E: ScanEventSink + ?Sized> RunEventSink for CanonicalRunEvents<'_, E> {
    fn publish(&self, event: &EventEnvelope) -> Result<(), String> {
        let payload = serde_json::to_value(event).map_err(|error| error.to_string())?;
        self.events
            .emit("run://event", payload)
            .map_err(|error| error.to_string())
    }
}

pub struct TauriRunEvents {
    app: AppHandle,
}

impl TauriRunEvents {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl RunEventSink for TauriRunEvents {
    fn publish(&self, event: &EventEnvelope) -> Result<(), String> {
        self.app
            .emit("run://event", event)
            .map_err(|error| error.to_string())
    }
}
