//! Payload generation for `batteringram`, `pitchfork` and `clusterbomb`.
//!
//! Combinations are addressed by index, never materialised, so a large
//! cluster-bomb costs nothing until requests are actually produced.
//!
//! Order:
//! * batteringram: one set drives every placeholder; the first set is used.
//! * pitchfork: set sizes are zipped, stopping at the shortest.
//! * clusterbomb: nested loops, the first declared set varies slowest.

use crate::model::{AttackType, Payloads, Protocol};
use crate::result::Truncation;

/// Default cap on combinations per request template.
pub const DEFAULT_MAX_COMBINATIONS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct PayloadPlan<'a> {
    payloads: &'a Payloads,
    total: usize,
    truncated: bool,
    /// The uncapped count; `None` when it overflows `usize`.
    requested: Option<usize>,
}

impl<'a> PayloadPlan<'a> {
    /// `cap` bounds the number of combinations produced.
    pub fn new(payloads: &'a Payloads, cap: usize) -> Self {
        let sets = &payloads.sets;
        let raw_total: Option<usize> = if sets.is_empty() {
            Some(1)
        } else {
            match payloads.attack {
                AttackType::BatteringRam => sets.first().map(|(_, v)| v.len()),
                AttackType::Pitchfork => sets.iter().map(|(_, v)| v.len()).min(),
                AttackType::ClusterBomb => sets
                    .iter()
                    .try_fold(1usize, |acc, (_, v)| acc.checked_mul(v.len())),
            }
        };
        let (total, truncated) = match raw_total {
            Some(n) if n <= cap => (n, false),
            _ => (cap, true),
        };
        PayloadPlan {
            payloads,
            total,
            truncated,
            requested: raw_total,
        }
    }

    /// The number of combinations the template asked for, before the cap
    /// (`None` when it does not fit in a `usize`).
    pub fn requested(&self) -> Option<usize> {
        self.requested
    }

    /// The truncation to report for block `request_index`, when the cap cut
    /// the combination list short.
    pub fn truncation(&self, protocol: Protocol, request_index: usize) -> Option<Truncation> {
        self.truncated.then(|| Truncation {
            protocol,
            request_index,
            message: format!(
                "{} request {request_index}: only {} of {} payload combinations were sent (the cap is {})",
                protocol.as_str(),
                self.total,
                self.requested
                    .map_or_else(|| "more than 2^64".to_owned(), |n| n.to_string()),
                self.total
            ),
        })
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// The cap cut the combination list short.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Name/value pairs for combination `index`, in declaration order.
    pub fn combination(&self, index: usize) -> Vec<(String, String)> {
        let sets = &self.payloads.sets;
        if sets.is_empty() || index >= self.total {
            return Vec::new();
        }
        match self.payloads.attack {
            AttackType::BatteringRam => {
                let value = sets
                    .first()
                    .and_then(|(_, v)| v.get(index))
                    .cloned()
                    .unwrap_or_default();
                sets.iter()
                    .map(|(n, _)| (n.clone(), value.clone()))
                    .collect()
            }
            AttackType::Pitchfork => sets
                .iter()
                .map(|(n, v)| (n.clone(), v.get(index).cloned().unwrap_or_default()))
                .collect(),
            AttackType::ClusterBomb => {
                let mut remaining = index;
                let mut picks: Vec<(String, String)> = Vec::with_capacity(sets.len());
                for (n, v) in sets.iter().rev() {
                    let len = v.len().max(1);
                    let pick = v.get(remaining % len).cloned().unwrap_or_default();
                    remaining /= len;
                    picks.push((n.clone(), pick));
                }
                picks.reverse();
                picks
            }
        }
    }
}

use crate::support::Reasons;
use crate::yaml::Yaml;

/// Reads `payloads` and `attack` from a request block. Wordlist files are
/// not supported, and a block that names one is reported as not evaluated.
pub(crate) fn build_payloads(y: &Yaml, reasons: &mut Reasons) -> Payloads {
    let mut out = Payloads::default();
    match y
        .string("attack")
        .map(|a| a.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("batteringram") => {}
        Some("pitchfork") => out.attack = AttackType::Pitchfork,
        Some("clusterbomb") => out.attack = AttackType::ClusterBomb,
        Some(other) => reasons.add(format!("uses unknown payload attack type `{other}`")),
    }
    if let Some(entries) = y.get("payloads").and_then(Yaml::as_map) {
        for (name, value) in entries {
            match value {
                Yaml::Seq(items) => out.sets.push((
                    name.clone(),
                    items.iter().filter_map(Yaml::scalar_text).collect(),
                )),
                Yaml::Null => {}
                _ => reasons.add(format!(
                    "payload `{name}` refers to a wordlist file; only inline lists are supported"
                )),
            }
        }
    } else if y.has("payloads") {
        reasons.add("has a payloads block that is not a mapping");
    }
    if matches!(out.attack, AttackType::Pitchfork | AttackType::ClusterBomb) && out.sets.len() < 2 {
        reasons.add("uses pitchfork/clusterbomb with fewer than two payload sets");
    }
    out
}
