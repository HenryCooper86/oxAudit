//! Per-conversation token + cost accounting (modeled on y-diagnostics' cost
//! model, minus the full Trace/Observation schema). Persisted as a JSON file
//! in the app config directory.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

static USAGE_IO_LOCK: Mutex<()> = Mutex::new(());

fn lock_usage_io() -> Result<MutexGuard<'static, ()>, String> {
    USAGE_IO_LOCK
        .lock()
        .map_err(|_| "usage storage lock is unavailable".to_string())
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UsageRecord {
    pub at: String,
    pub model: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub cost_usd: f64,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct UsageSummary {
    pub turns: u32,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub cost_usd: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct UsageStore {
    pub conversations: HashMap<String, Vec<UsageRecord>>,
}

impl UsageStore {
    pub fn record(&mut self, conversation_id: &str, rec: UsageRecord) {
        let list = self
            .conversations
            .entry(conversation_id.to_string())
            .or_default();
        list.push(rec);
        if list.len() > 5000 {
            let excess = list.len() - 5000;
            list.drain(..excess);
        }
    }

    pub fn conversation_summary(&self, conversation_id: &str) -> UsageSummary {
        let mut s = UsageSummary::default();
        if let Some(records) = self.conversations.get(conversation_id) {
            for r in records {
                s.turns += 1;
                s.prompt_tokens += r.prompt_tokens;
                s.completion_tokens += r.completion_tokens;
                s.cost_usd += r.cost_usd;
            }
        }
        s.total_tokens = s.prompt_tokens + s.completion_tokens;
        s
    }

    pub fn total(&self) -> UsageSummary {
        let mut s = UsageSummary::default();
        for records in self.conversations.values() {
            for r in records {
                s.turns += 1;
                s.prompt_tokens += r.prompt_tokens;
                s.completion_tokens += r.completion_tokens;
                s.cost_usd += r.cost_usd;
            }
        }
        s.total_tokens = s.prompt_tokens + s.completion_tokens;
        s
    }

    fn load_unlocked(path: &Path) -> Result<Self, String> {
        let content = match crate::private_storage::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => return Err(format!("cannot read usage: {error}")),
        };
        serde_json::from_str(&content).map_err(|error| format!("cannot parse usage: {error}"))
    }

    fn save_unlocked(&self, path: &Path) -> Result<(), String> {
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::private_storage::atomic_write(path, content.as_bytes())
            .map_err(|error| format!("cannot write usage: {error}"))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let _guard = lock_usage_io()?;
        Self::load_unlocked(path)
    }

    #[cfg(test)]
    fn save(&self, path: &Path) -> Result<(), String> {
        let _guard = lock_usage_io()?;
        self.save_unlocked(path)
    }

    pub fn record_persisted(
        path: &Path,
        conversation_id: &str,
        record: UsageRecord,
    ) -> Result<(), String> {
        let _guard = lock_usage_io()?;
        let mut store = Self::load_unlocked(path)?;
        store.record(conversation_id, record);
        store.save_unlocked(path)
    }
}

/// Estimate USD cost from a model name (prefix match) and token counts.
/// Prices are per-1M-tokens (input / output), approximate list prices.
pub fn estimate_cost(model: &str, prompt_tokens: u32, completion_tokens: u32) -> f64 {
    let m = model.to_ascii_lowercase();
    let (in_price, out_price) = if m.contains("gpt-4o-mini") {
        (0.15, 0.60)
    } else if m.contains("gpt-4o") {
        (2.50, 10.00)
    } else if m.contains("o3-mini") {
        (1.10, 4.40)
    } else if m.contains("o1") || m.contains("o3") {
        (15.00, 60.00)
    } else if m.contains("gpt-4") || m.contains("gpt-3.5") {
        (30.00, 60.00)
    } else if m.contains("claude") {
        (3.00, 15.00)
    } else if m.contains("gemini") {
        (1.25, 5.00)
    } else if m.contains("deepseek") {
        (0.27, 1.10)
    } else if m.contains("llama") || m.contains("qwen") || m.contains("mistral") {
        (0.0, 0.0) // typical local models
    } else {
        (1.00, 3.00) // unknown — conservative estimate
    };
    prompt_tokens as f64 / 1_000_000.0 * in_price
        + completion_tokens as f64 / 1_000_000.0 * out_price
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_estimates_by_model() {
        // gpt-4o-mini: $0.15/1M in, $0.60/1M out
        let cost = estimate_cost("gpt-4o-mini", 1_000_000, 500_000);
        assert!((cost - (0.15 + 0.30)).abs() < 1e-6, "got {cost}");
        // local model is free
        assert_eq!(estimate_cost("llama3.1", 100_000, 100_000), 0.0);
    }

    #[test]
    fn store_roundtrip_and_summaries() {
        let mut store = UsageStore::default();
        store.record(
            "conv-1",
            UsageRecord {
                at: "t".into(),
                model: "gpt-4o-mini".into(),
                prompt_tokens: 1000,
                completion_tokens: 500,
                cost_usd: 0.001,
            },
        );
        store.record(
            "conv-1",
            UsageRecord {
                at: "t2".into(),
                model: "gpt-4o-mini".into(),
                prompt_tokens: 2000,
                completion_tokens: 500,
                cost_usd: 0.002,
            },
        );
        let s = store.conversation_summary("conv-1");
        assert_eq!(s.turns, 2);
        assert_eq!(s.total_tokens, 4000);
        assert!((s.cost_usd - 0.003).abs() < 1e-9);
        assert_eq!(store.conversation_summary("nope").turns, 0);
    }

    #[test]
    fn retention_keeps_the_latest_five_thousand_records() {
        let mut store = UsageStore::default();
        for index in 0..=5000 {
            store.record(
                "conversation",
                UsageRecord {
                    at: index.to_string(),
                    model: "test".into(),
                    prompt_tokens: 1,
                    completion_tokens: 1,
                    cost_usd: 0.0,
                },
            );
        }

        let records = &store.conversations["conversation"];
        assert_eq!(records.len(), 5000);
        assert_eq!(records.first().expect("first retained").at, "1");
        assert_eq!(records.last().expect("last retained").at, "5000");
    }

    #[test]
    fn malformed_usage_is_reported_instead_of_silently_reset() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("usage.json");
        std::fs::write(&path, "{not-json").expect("fixture");

        assert!(UsageStore::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn persisted_usage_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("usage.json");
        UsageStore::default().save(&path).expect("save usage");

        assert_eq!(
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn concurrent_persisted_records_are_not_lost() {
        use std::sync::{Arc, Barrier};

        const RECORDS: usize = 32;
        let directory = tempfile::tempdir().expect("tempdir");
        let path = Arc::new(directory.path().join("usage.json"));
        let barrier = Arc::new(Barrier::new(RECORDS));
        let mut workers = Vec::new();

        for index in 0..RECORDS {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                UsageStore::record_persisted(
                    &path,
                    "conversation",
                    UsageRecord {
                        at: index.to_string(),
                        model: "test".into(),
                        prompt_tokens: 1,
                        completion_tokens: 1,
                        cost_usd: 0.0,
                    },
                )
                .expect("persist record");
            }));
        }

        for worker in workers {
            worker.join().expect("worker");
        }

        assert_eq!(
            UsageStore::load(&path)
                .expect("load usage")
                .conversation_summary("conversation")
                .turns,
            RECORDS as u32
        );
    }
}
