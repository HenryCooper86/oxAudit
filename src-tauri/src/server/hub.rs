//! The server's event hub: a broadcast channel standing in for the Tauri
//! app's `emit`. Every subscribed SSE stream receives every event; the
//! browser filters by name exactly as it would with per-event listeners.

use serde_json::Value;
use tokio::sync::broadcast;

const HUB_CAPACITY: usize = 512;

#[derive(Clone)]
pub struct EventHub {
    tx: broadcast::Sender<(String, Value)>,
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(HUB_CAPACITY);
        Self { tx }
    }

    pub fn publish(&self, event: &str, payload: Value) {
        // A send with no receivers is fine: progress emitted before any
        // browser subscribed is not observable anyway.
        let _ = self.tx.send((event.to_string(), payload));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(String, Value)> {
        self.tx.subscribe()
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

/// The `ScanEventSink` every extracted engine function receives, so the
/// server drives the identical scan paths over the hub.
#[derive(Clone)]
pub struct HubEvents {
    hub: std::sync::Arc<EventHub>,
}

impl HubEvents {
    pub fn new(hub: std::sync::Arc<EventHub>) -> Self {
        Self { hub }
    }
}

impl crate::findings::service::ScanEventSink for HubEvents {
    fn emit(
        &self,
        event: &str,
        payload: Value,
    ) -> Result<(), crate::findings::error::CommandError> {
        self.hub.publish(event, payload);
        Ok(())
    }
}

/// `RunEventSink` for the run coordinator, projecting canonical run events
/// onto the hub under the same `run://event` name the desktop emits.
pub struct HubRunEvents {
    hub: std::sync::Arc<EventHub>,
}

impl HubRunEvents {
    pub fn new(hub: std::sync::Arc<EventHub>) -> Self {
        Self { hub }
    }
}

impl oxaudit_application::RunEventSink for HubRunEvents {
    fn publish(&self, event: &oxaudit_application::EventEnvelope) -> Result<(), String> {
        let payload = serde_json::to_value(event).map_err(|error| error.to_string())?;
        self.hub.publish("run://event", payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_published_event_reaches_every_subscriber() {
        let hub = std::sync::Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        hub.publish("scan://progress", serde_json::json!({ "done": 1 }));
        let (name, payload) = rx.try_recv().expect("event delivered");
        assert_eq!(name, "scan://progress");
        assert_eq!(payload["done"], 1);
    }

    #[test]
    fn the_sink_impl_publishes_under_the_callers_event_name() {
        use crate::findings::service::ScanEventSink;
        let hub = std::sync::Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        let sink = HubEvents::new(hub.clone());
        sink.emit("deps://progress", serde_json::json!({ "phase": "parsing" }))
            .expect("emit succeeds");
        let (name, payload) = rx.try_recv().expect("event delivered");
        assert_eq!(name, "deps://progress");
        assert_eq!(payload["phase"], "parsing");
    }
}
