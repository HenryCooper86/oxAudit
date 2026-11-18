//! Live-target networking for Template scans.
//!
//! This module is the only code in oxAudit that opens connections to targets
//! a user names for an authorized assessment. The pure `oxaudit-nuclei` crate
//! plans requests and evaluates responses; this module sends them, and its
//! main job is to make it impossible for a template, a redirect or a DNS
//! answer to send traffic anywhere the user did not put in scope.
//!
//! The rules, in one place:
//!
//! * [`scope::Scope`] holds what the user typed. Every connection (each HTTP
//!   request and each redirect hop, each TCP session, each TLS probe) is
//!   checked against it immediately before it is opened, and every DNS
//!   question a template asks is checked too. A refusal is counted and
//!   reported, never silently dropped.
//! * Host names are resolved once per run ([`resolve`]) and every connection
//!   to a name uses only those pinned addresses. The HTTP client is given a
//!   resolver that knows only the pinned names and fails for anything else,
//!   so it cannot perform a lookup of its own.
//! * The connection destination is always derived from the checked URL or
//!   host. A template's `Host` header, `@Host` annotation or `@tls-sni`
//!   cannot move the socket: `@Host` becomes the request URL (and is checked
//!   like any URL), a `Host` header is only a header value sent to the
//!   in-scope server, and `@tls-sni` is ignored (the SNI is the URL host).
//! * Proxy environment variables are never read. An explicit proxy from the
//!   settings applies to HTTP only; see [`limits::LiveLimits::proxy`].
//! * Every outbound attempt goes through [`limits::Governor`]: cancellation,
//!   the run-wide request budget, the shared rate limiter and the per-host
//!   concurrency limit.
//!
//! Outcome honesty: a template that could not be evaluated, a target that
//! could not be reached or resolved, and requests refused by scope are each
//! reported. Zero matches is not a statement that a target is safe.

pub(crate) mod dns;
pub(crate) mod exchange;
pub(crate) mod http;
pub(crate) mod limits;
pub(crate) mod resolve;
pub(crate) mod run;
pub(crate) mod scope;
pub(crate) mod ssl;
pub(crate) mod tcp;
mod tls;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::pin::Pin;

// The facade `template::live` uses.
pub(crate) use limits::{Halt, LiveLimits};
pub(crate) use run::{run_live, LiveProgress, LiveRunInput, LiveRunOutput, LiveTemplate};
pub(crate) use scope::{Refusal, Scope, ScopeLimits};

/// What every protocol executor needs: the scope, the pinned addresses, the
/// governor and the limits of the run.
#[derive(Clone)]
pub(crate) struct Net {
    pub scope: std::sync::Arc<Scope>,
    pub pinned: std::sync::Arc<resolve::PinnedHosts>,
    pub gov: std::sync::Arc<limits::Governor>,
    pub limits: LiveLimits,
    /// Set when the target this work belongs to hit the unreachable cut-off;
    /// queued attempts then give up instead of being sent.
    pub abort: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Net {
    /// Admits one attempt to `host_key` (see [`limits::Governor::admit`]).
    pub(crate) async fn admit(&self, host_key: &str) -> Result<limits::Admission, Halt> {
        self.gov.admit(host_key, self.abort.as_deref()).await
    }
}

/// A boxed, sendable future. Used by the injectable resolver traits so the
/// tests need no real DNS.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why one outbound attempt produced no response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetFailure {
    /// Scope refused the destination; nothing was sent.
    Refused(Refusal),
    /// The run is stopping (cancelled or out of request budget); nothing was
    /// sent.
    Halted(Halt),
    /// The host name has no pinned addresses for this run.
    Unresolved(String),
    /// The connection could not be opened or timed out. Counts towards the
    /// target's unreachable cut-off.
    Connect(String),
    /// The request could not be built or the exchange failed after the
    /// connection was made.
    Protocol(String),
    /// The probe needs something this client cannot do (for example TLS
    /// older than 1.2).
    Unsupported(String),
}

impl std::fmt::Display for NetFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetFailure::Refused(r) => write!(f, "refused by scope: {r}"),
            NetFailure::Halted(h) => write!(f, "{h}"),
            NetFailure::Unresolved(m) => write!(f, "could not resolve: {m}"),
            NetFailure::Connect(m) => write!(f, "connection failed: {m}"),
            NetFailure::Protocol(m) => write!(f, "exchange failed: {m}"),
            NetFailure::Unsupported(m) => write!(f, "not supported: {m}"),
        }
    }
}
