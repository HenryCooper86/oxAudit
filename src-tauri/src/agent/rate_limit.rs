//! Per-tool token buckets for network-backed agent tools.
//!
//! The limiter lives in `AppState`, so separate conversations share the same
//! polite request budget instead of each run starting with a fresh allowance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub capacity: u32,
    pub refill_per_minute: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited { retry_after: Duration },
}

#[derive(Debug)]
struct TokenBucket {
    config: RateLimitConfig,
    tokens: f64,
    last_refill: Instant,
}

#[derive(Clone, Debug)]
pub struct ToolRateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
}

impl ToolRateLimiter {
    pub fn oxaudit_defaults() -> Self {
        Self::new([
            (
                "web_fetch",
                RateLimitConfig {
                    capacity: 4,
                    refill_per_minute: 8,
                },
            ),
            (
                "query_osv_package",
                RateLimitConfig {
                    capacity: 8,
                    refill_per_minute: 30,
                },
            ),
            (
                "run_dependency_scan",
                RateLimitConfig {
                    capacity: 2,
                    refill_per_minute: 6,
                },
            ),
            (
                "search_cve",
                RateLimitConfig {
                    capacity: 5,
                    refill_per_minute: 15,
                },
            ),
            (
                "get_cve_detail",
                RateLimitConfig {
                    capacity: 8,
                    refill_per_minute: 20,
                },
            ),
        ])
    }

    pub fn new<const N: usize>(limits: [(&str, RateLimitConfig); N]) -> Self {
        let now = Instant::now();
        let buckets = limits
            .into_iter()
            .map(|(name, config)| {
                (
                    name.to_string(),
                    TokenBucket {
                        config,
                        tokens: config.capacity as f64,
                        last_refill: now,
                    },
                )
            })
            .collect();
        Self {
            buckets: Arc::new(Mutex::new(buckets)),
        }
    }

    pub fn check(&self, tool: &str) -> RateLimitDecision {
        self.check_at(tool, Instant::now())
    }

    fn check_at(&self, tool: &str, now: Instant) -> RateLimitDecision {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(bucket) = buckets.get_mut(tool) else {
            return RateLimitDecision::Allowed;
        };

        let elapsed = now.saturating_duration_since(bucket.last_refill);
        let refill_per_second = bucket.config.refill_per_minute as f64 / 60.0;
        bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * refill_per_second)
            .min(bucket.config.capacity as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateLimitDecision::Allowed;
        }

        let wait_seconds = if refill_per_second > 0.0 {
            (1.0 - bucket.tokens) / refill_per_second
        } else {
            60.0
        };
        RateLimitDecision::Limited {
            retry_after: Duration::from_millis((wait_seconds * 1000.0).ceil() as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> ToolRateLimiter {
        ToolRateLimiter::new([(
            "network_tool",
            RateLimitConfig {
                capacity: 2,
                refill_per_minute: 60,
            },
        )])
    }

    #[test]
    fn allows_burst_then_returns_a_retry_time() {
        let limiter = limiter();
        let now = Instant::now();
        assert_eq!(
            limiter.check_at("network_tool", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_at("network_tool", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_at("network_tool", now),
            RateLimitDecision::Limited {
                retry_after: Duration::from_secs(1)
            }
        );
    }

    #[test]
    fn refills_without_blocking_and_leaves_local_tools_unlimited() {
        let limiter = limiter();
        let now = Instant::now();
        assert_eq!(
            limiter.check_at("network_tool", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_at("network_tool", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_at("network_tool", now + Duration::from_secs(1)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_at("read_file", now),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn dependency_scans_share_a_network_request_budget() {
        let limiter = ToolRateLimiter::oxaudit_defaults();
        let now = Instant::now();
        assert_eq!(
            limiter.check_at("run_dependency_scan", now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_at("run_dependency_scan", now),
            RateLimitDecision::Allowed
        );
        assert!(matches!(
            limiter.check_at("run_dependency_scan", now),
            RateLimitDecision::Limited { .. }
        ));
    }
}
