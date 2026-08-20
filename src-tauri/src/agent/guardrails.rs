//! Guardrails: allow/ask/deny permission pipeline + loop guard.
//! Modeled on y-agent's permission_pipeline and LoopGuard, minus the
//! exec-policy DSL, taint and risk scoring (no shell/file-write tools yet).

use std::collections::{HashMap, VecDeque};

use serde_json::Value;

use super::tool::ToolSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Allow,
    Ask,
    Deny,
}

/// Decide whether a tool call may execute.
///
/// Fail-closed posture: read-only and interactive tools are allowed (they
/// cannot damage anything); dangerous tools always ask; anything unclassified
/// is denied.
pub fn classify(spec: &ToolSpec) -> Permission {
    if spec.dangerous {
        Permission::Ask
    } else if spec.read_only || spec.interactive {
        Permission::Allow
    } else {
        Permission::Deny
    }
}

/// Detects degenerate agent behavior (y-agent LoopGuard, trimmed):
/// * redundant — same tool + same arguments called 3+ times
/// * oscillation — A,B,A,B pattern across the last 4 calls
pub struct LoopGuard {
    counts: HashMap<(String, String), u32>,
    last_four: VecDeque<String>,
}

impl Default for LoopGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopGuard {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            last_four: VecDeque::new(),
        }
    }

    /// Forget the call history.
    ///
    /// Called when the user steers mid-run: the guard exists to detect the
    /// *model* going in circles, and once a human has redirected it the prior
    /// history is no longer evidence of a stuck loop.
    pub fn reset(&mut self) {
        self.counts.clear();
        self.last_four.clear();
    }

    /// Record a tool call; returns `true` when the loop should stop.
    pub fn record(&mut self, name: &str, args: &Value) -> bool {
        let key = (name.to_string(), args.to_string());
        let count = self.counts.entry(key).or_insert(0);
        *count += 1;
        if *count >= 3 {
            return true;
        }
        self.last_four.push_back(name.to_string());
        if self.last_four.len() > 4 {
            self.last_four.pop_front();
        }
        self.last_four.len() == 4
            && self.last_four[0] == self.last_four[2]
            && self.last_four[1] == self.last_four[3]
            && self.last_four[0] != self.last_four[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(read_only: bool, interactive: bool, dangerous: bool) -> ToolSpec {
        ToolSpec {
            name: "t",
            description: "",
            parameters: json!({}),
            read_only,
            interactive,
            dangerous,
        }
    }

    #[test]
    fn classify_matrix() {
        assert_eq!(classify(&spec(true, false, false)), Permission::Allow);
        assert_eq!(classify(&spec(false, true, false)), Permission::Allow);
        assert_eq!(classify(&spec(false, false, true)), Permission::Ask);
        assert_eq!(classify(&spec(false, false, false)), Permission::Deny);
    }

    #[test]
    fn redundant_call_detected() {
        let mut g = LoopGuard::new();
        let args = json!({"pattern": "eval"});
        assert!(!g.record("grep_project", &args));
        assert!(!g.record("grep_project", &args));
        assert!(
            g.record("grep_project", &args),
            "3x same tool+args must stop"
        );
    }

    #[test]
    fn different_args_do_not_trip() {
        let mut g = LoopGuard::new();
        assert!(!g.record("read_file", &json!({"path": "a.rs"})));
        assert!(!g.record("read_file", &json!({"path": "b.rs"})));
        assert!(!g.record("read_file", &json!({"path": "c.rs"})));
        assert!(!g.record("read_file", &json!({"path": "d.rs"})));
    }

    #[test]
    fn oscillation_detected() {
        let mut g = LoopGuard::new();
        assert!(!g.record("grep_project", &json!({})));
        assert!(!g.record("glob", &json!({})));
        assert!(!g.record("grep_project", &json!({})));
        assert!(g.record("glob", &json!({})), "A,B,A,B must stop");
    }
}
