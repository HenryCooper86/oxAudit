//! Run limits and the gate every outbound attempt passes.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub(crate) const MAX_RESPONSE_BYTES_CAP: usize = 32 * 1024 * 1024;
pub(crate) const MAX_REDIRECTS_CAP: u32 = 10;

/// Live-scan limits (settings). Defaults: 50 requests/s overall, 10
/// concurrent requests per host, 10 s timeout, 4 MiB response cap, 100,000
/// requests per run, at most 10 redirects, 30 consecutive connection failures
/// before a target is treated as unreachable, no proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveLimits {
    /// 1..=1000, shared across every protocol and host.
    pub requests_per_second: u32,
    /// 1..=100 requests in flight to one host.
    pub per_host_concurrency: u32,
    /// Connect and overall timeout of one attempt, 1..=120 s.
    pub timeout: Duration,
    /// Response body (HTTP) or total read (TCP) cap, 1 byte..=32 MiB.
    pub max_response_bytes: usize,
    /// Outbound attempts per run; reaching it stops the run (incomplete).
    pub max_requests: u64,
    /// Upper bound on a template's `max-redirects`, 0..=10.
    pub max_redirects_cap: u32,
    /// Consecutive connection failures after which a target is unreachable
    /// and its remaining templates are not evaluated, 1..=1000.
    pub max_host_errors: u32,
    /// An explicit HTTP(S) proxy for HTTP templates only. When set, scope is
    /// still enforced on every request URL before sending, the proxy's own
    /// host is resolved once and pinned like a target, and the proxy resolves
    /// the target names itself (recorded as a run note). DNS, TCP and SSL
    /// templates always connect directly. Proxy environment variables are
    /// never read.
    pub proxy: Option<Url>,
}

impl Default for LiveLimits {
    fn default() -> Self {
        LiveLimits {
            requests_per_second: 50,
            per_host_concurrency: 10,
            timeout: Duration::from_secs(10),
            max_response_bytes: 4 * 1024 * 1024,
            max_requests: 100_000,
            max_redirects_cap: MAX_REDIRECTS_CAP,
            max_host_errors: 30,
            proxy: None,
        }
    }
}

impl LiveLimits {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !(1..=1000).contains(&self.requests_per_second) {
            return Err("requests per second must be between 1 and 1000".into());
        }
        if !(1..=100).contains(&self.per_host_concurrency) {
            return Err("concurrent requests per host must be between 1 and 100".into());
        }
        if self.timeout < Duration::from_secs(1) || self.timeout > Duration::from_secs(120) {
            return Err("the timeout must be between 1 and 120 seconds".into());
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES_CAP {
            return Err("the response cap must be between 1 byte and 32 MiB".into());
        }
        if self.max_requests == 0 {
            return Err("the request budget must be at least 1".into());
        }
        if self.max_redirects_cap > MAX_REDIRECTS_CAP {
            return Err("at most 10 redirects can be followed".into());
        }
        if !(1..=1000).contains(&self.max_host_errors) {
            return Err("the unreachable cut-off must be between 1 and 1000".into());
        }
        if let Some(proxy) = &self.proxy {
            if proxy.scheme() != "http" && proxy.scheme() != "https" {
                return Err("the proxy must be an http:// or https:// URL".into());
            }
            if proxy.host_str().is_none() {
                return Err("the proxy URL has no host".into());
            }
        }
        Ok(())
    }
}

/// Why the run stopped sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Halt {
    Cancelled,
    BudgetExhausted,
    /// Not a run halt: the attempt's target hit the unreachable cut-off while
    /// the attempt waited for admission. Never returned by `halted()`.
    TargetUnreachable,
}

impl fmt::Display for Halt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Halt::Cancelled => f.write_str("the run was cancelled"),
            Halt::BudgetExhausted => f.write_str("the run's request budget was used up"),
            Halt::TargetUnreachable => f.write_str("the target stopped answering"),
        }
    }
}

/// A token bucket holding one token, refilled at `rate` per second: requests
/// are spaced at least `1/rate` apart across the whole run.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    pub(crate) fn new(per_second: u32) -> Self {
        RateLimiter {
            interval: Duration::from_secs(1) / per_second.max(1),
            next: Mutex::new(Instant::now()),
        }
    }

    /// Reserves the next slot and returns when it starts.
    fn reserve(&self) -> Instant {
        let now = Instant::now();
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let slot = (*next).max(now);
        *next = slot + self.interval;
        slot
    }
}

/// Holds a per-host permit for the duration of one attempt.
#[derive(Debug)]
pub(crate) struct Admission {
    _permit: OwnedSemaphorePermit,
}

/// The gate every outbound attempt passes: cancellation, request budget,
/// rate limiter and per-host concurrency.
#[derive(Debug)]
pub(crate) struct Governor {
    rate: RateLimiter,
    per_host: usize,
    hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
    sent: AtomicU64,
    max: u64,
    exhausted: AtomicBool,
    cancel: Arc<AtomicBool>,
}

const POLL: Duration = Duration::from_millis(25);

impl Governor {
    pub(crate) fn new(limits: &LiveLimits, cancel: Arc<AtomicBool>) -> Self {
        Governor {
            rate: RateLimiter::new(limits.requests_per_second),
            per_host: limits.per_host_concurrency.max(1) as usize,
            hosts: Mutex::new(HashMap::new()),
            sent: AtomicU64::new(0),
            max: limits.max_requests,
            exhausted: AtomicBool::new(false),
            cancel,
        }
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// The reason the run is stopping, if it is.
    pub(crate) fn halted(&self) -> Option<Halt> {
        if self.cancelled() {
            Some(Halt::Cancelled)
        } else if self.exhausted.load(Ordering::SeqCst) {
            Some(Halt::BudgetExhausted)
        } else {
            None
        }
    }

    /// Attempts admitted so far (each one was, or is being, sent).
    pub(crate) fn sent(&self) -> u64 {
        self.sent.load(Ordering::SeqCst)
    }

    fn semaphore(&self, host: &str) -> Arc<Semaphore> {
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        hosts
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_host)))
            .clone()
    }

    /// Waits for a per-host slot and a rate token, then counts the attempt.
    /// Returns `Err` without counting when the run is stopping, or when
    /// `abort` (the attempt's target is unreachable) is set by the time the
    /// attempt would be sent.
    pub(crate) async fn admit(
        &self,
        host_key: &str,
        abort: Option<&AtomicBool>,
    ) -> Result<Admission, Halt> {
        let stop = || {
            self.halted().or_else(|| {
                abort
                    .is_some_and(|a| a.load(Ordering::SeqCst))
                    .then_some(Halt::TargetUnreachable)
            })
        };
        if let Some(h) = stop() {
            return Err(h);
        }
        let sem = self.semaphore(host_key);
        let permit = loop {
            match tokio::time::timeout(POLL, sem.clone().acquire_owned()).await {
                Ok(Ok(p)) => break p,
                Ok(Err(_)) => return Err(Halt::Cancelled),
                Err(_) => {
                    if let Some(h) = stop() {
                        return Err(h);
                    }
                }
            }
        };
        let slot = self.rate.reserve();
        loop {
            if let Some(h) = stop() {
                return Err(h);
            }
            let now = Instant::now();
            if now >= slot {
                break;
            }
            tokio::time::sleep((slot - now).min(POLL)).await;
        }
        let counted = self
            .sent
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max).then_some(n + 1)
            });
        if counted.is_err() {
            self.exhausted.store(true, Ordering::SeqCst);
            return Err(Halt::BudgetExhausted);
        }
        Ok(Admission { _permit: permit })
    }
}
