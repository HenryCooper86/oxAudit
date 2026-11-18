//! Resolve each in-scope host name once per run and pin the answer.
//!
//! Every connection to a name uses only its pinned addresses; there is no
//! second lookup, so a DNS change mid-run (rebinding) cannot move a request.
//! The HTTP client gets [`PinnedResolve`], which answers from the pinned map
//! and fails for every other name.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{LookupIpStrategy, ResolveHosts};
use hickory_resolver::TokioResolver;

use super::scope::{
    forbidden_ip, is_link_local, is_metadata_ip, is_metadata_name, nat64_embedded, HostId, Scope,
};
use super::BoxFuture;

/// At most this many addresses are kept per name.
const MAX_ADDRESSES_PER_HOST: usize = 16;
/// Names resolved at once while pinning.
const PIN_CONCURRENCY: usize = 16;

/// Looks up the addresses of a name. Injected so tests need no real DNS.
pub(crate) trait HostResolver: Send + Sync {
    fn lookup_ip<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>>;
}

/// The system resolver configuration (`/etc/resolv.conf`, the registry, the
/// hosts file), via hickory.
pub(crate) struct SystemResolver {
    inner: TokioResolver,
}

impl SystemResolver {
    pub(crate) fn new(timeout: Duration) -> Result<Self, String> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|e| format!("cannot read the system DNS configuration: {e}"))?;
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        // Internal names commonly live in the hosts file.
        opts.use_hosts_file = ResolveHosts::Always;
        let inner = builder
            .build()
            .map_err(|e| format!("cannot start the DNS resolver: {e}"))?;
        Ok(SystemResolver { inner })
    }
}

impl HostResolver for SystemResolver {
    fn lookup_ip<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            // A trailing dot makes the name absolute: no search-domain
            // expansion can turn `intranet` into somebody else's host.
            let fqdn = format!("{name}.");
            match self.inner.lookup_ip(fqdn.as_str()).await {
                Ok(lookup) => Ok(lookup.iter().collect()),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

/// The pinned address set of every in-scope name for one run.
#[derive(Debug, Clone, Default)]
pub(crate) struct PinnedHosts {
    addrs: BTreeMap<String, Vec<IpAddr>>,
    failed: BTreeMap<String, String>,
    notes: Vec<String>,
}

impl PinnedHosts {
    /// Pinned addresses of a name (already normalised), if it resolved.
    pub(crate) fn get(&self, name: &str) -> Option<&[IpAddr]> {
        self.addrs.get(name).map(Vec::as_slice)
    }

    /// Why a name has no addresses.
    pub(crate) fn failure(&self, name: &str) -> Option<&str> {
        self.failed.get(name).map(String::as_str)
    }

    /// Every pinned name and its addresses, for the run record.
    pub(crate) fn resolved(&self) -> Vec<(String, Vec<IpAddr>)> {
        self.addrs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub(crate) fn notes(&self) -> &[String] {
        &self.notes
    }

    /// The addresses to connect to for `host`: pinned addresses of a name, or
    /// the IP itself.
    pub(crate) fn addresses_for(&self, host: &HostId) -> Result<Vec<IpAddr>, String> {
        match host {
            HostId::Ip(ip) => Ok(vec![*ip]),
            HostId::Name(n) => match self.get(n) {
                Some(a) if !a.is_empty() => Ok(a.to_vec()),
                _ => Err(self
                    .failure(n)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{n} was not resolved for this run"))),
            },
        }
    }

    /// Pins a name the caller vouches for (the configured proxy).
    fn insert(&mut self, name: String, addrs: Vec<IpAddr>) {
        self.addrs.insert(name, addrs);
    }
}

fn is_non_public(ip: IpAddr) -> bool {
    crate::agent::egress::check_address("", ip).is_err()
}

/// Resolves every in-scope name once, filters the answers and pins them.
///
/// Answers that could never be typed as a target (unspecified, multicast,
/// broadcast) are always dropped. Metadata and link-local answers are
/// dropped unless the name is itself a metadata name typed as a target. A
/// NAT64 answer is judged by the IPv4 address it embeds as well as by
/// itself. Other non-public answers (private, loopback) are kept, because
/// the user typed the name, and recorded in a note so it is visible. Every
/// dropped answer is named in a note.
pub(crate) async fn pin_hosts(
    scope: &Scope,
    resolver: &dyn HostResolver,
    timeout: Duration,
    proxy_host: Option<&str>,
) -> PinnedHosts {
    use futures::StreamExt;

    let names = scope.host_names();
    let lookups: Vec<(String, Result<Vec<IpAddr>, String>)> = futures::stream::iter(names)
        .map(|name| async move {
            let answer = match tokio::time::timeout(timeout, resolver.lookup_ip(&name)).await {
                Ok(r) => r,
                Err(_) => Err("DNS lookup timed out".to_string()),
            };
            (name, answer)
        })
        .buffer_unordered(PIN_CONCURRENCY)
        .collect()
        .await;

    let mut pinned = PinnedHosts::default();
    for (name, answer) in lookups {
        let addrs = match answer {
            Ok(a) => a,
            Err(e) => {
                pinned.failed.insert(name, e);
                continue;
            }
        };
        let metadata_typed =
            is_metadata_name(&name) && scope.metadata_typed(&HostId::Name(name.clone()));
        let mut kept: Vec<IpAddr> = Vec::new();
        let mut dropped: Vec<IpAddr> = Vec::new();
        let mut never: Vec<IpAddr> = Vec::new();
        for ip in addrs.into_iter().map(|ip| ip.to_canonical()) {
            if kept.contains(&ip) || dropped.contains(&ip) || never.contains(&ip) {
                continue;
            }
            // The address itself and, for NAT64, the IPv4 address it reaches.
            let reached: Vec<IpAddr> = std::iter::once(ip)
                .chain(nat64_embedded(ip).into_iter().map(IpAddr::V4))
                .collect();
            if reached.iter().any(|a| forbidden_ip(*a).is_some()) {
                never.push(ip);
            } else if !metadata_typed
                && reached
                    .iter()
                    .any(|a| is_metadata_ip(*a) || is_link_local(*a))
            {
                dropped.push(ip);
            } else if kept.len() < MAX_ADDRESSES_PER_HOST {
                kept.push(ip);
            }
        }
        if !dropped.is_empty() {
            pinned.notes.push(format!(
                "{name} resolved to cloud metadata or link-local address(es) {}; they were not used",
                join_ips(&dropped)
            ));
        }
        if !never.is_empty() {
            pinned.notes.push(format!(
                "{name} resolved to unspecified, multicast or broadcast address(es) {}, which can never be a target; they were not used",
                join_ips(&never)
            ));
        }
        dropped.extend(never);
        if kept.is_empty() {
            pinned.failed.insert(
                name,
                if dropped.is_empty() {
                    "no addresses".to_string()
                } else {
                    "resolves only to cloud metadata, link-local, unspecified, multicast or broadcast addresses, which are refused (metadata and link-local unless typed as a target)".to_string()
                },
            );
            continue;
        }
        let private: Vec<IpAddr> = kept
            .iter()
            .copied()
            .filter(|ip| is_non_public(*ip))
            .collect();
        if !private.is_empty() {
            pinned.notes.push(format!(
                "{name} resolved to non-public address(es) {}; used because the name was typed as a target",
                join_ips(&private)
            ));
        }
        pinned.addrs.insert(name, kept);
    }

    if let Some(proxy) = proxy_host {
        match HostId::parse(proxy) {
            Ok(HostId::Name(n)) if !pinned.addrs.contains_key(&n) => {
                match tokio::time::timeout(timeout, resolver.lookup_ip(&n)).await {
                    Ok(Ok(a)) if !a.is_empty() => {
                        let a: Vec<IpAddr> = a
                            .into_iter()
                            .map(|ip| ip.to_canonical())
                            .take(MAX_ADDRESSES_PER_HOST)
                            .collect();
                        pinned.insert(n, a);
                    }
                    _ => pinned
                        .notes
                        .push(format!("the proxy host {n} could not be resolved")),
                }
            }
            _ => {}
        }
    }
    pinned
}

fn join_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// reqwest resolver that answers only from the pinned map. A name that is
/// not pinned fails, so the HTTP client can never look a name up itself.
pub(crate) struct PinnedResolve {
    pub(crate) pinned: Arc<PinnedHosts>,
}

impl reqwest::dns::Resolve for PinnedResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let key = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        let found = self.pinned.get(&key).map(<[IpAddr]>::to_vec);
        Box::pin(async move {
            match found {
                Some(addrs) if !addrs.is_empty() => {
                    // Port 0: the connector substitutes the URL's port.
                    let iter = addrs.into_iter().map(|ip| SocketAddr::new(ip, 0));
                    Ok(Box::new(iter) as reqwest::dns::Addrs)
                }
                _ => {
                    Err(format!("{key} is not pinned for this run; refusing to resolve it").into())
                }
            }
        })
    }
}
