//! Per-conversation token + cost accounting (modeled on y-diagnostics' cost
//! model, minus the full Trace/Observation schema). Persisted as a JSON file
//! in the app config directory.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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
        let list = self.conversations.entry(conversation_id.to_string()).or_default();
        list.push(rec);
        if list.len() > 5000 {
            let _ = list.split_off(list.len() - 5000);
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

    pub fn load(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create dir: {e}"))?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, content).map_err(|e| format!("cannot write usage: {e}"))
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
}
