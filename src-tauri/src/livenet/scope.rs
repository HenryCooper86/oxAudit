//! What the user put in scope, and the checks every outbound attempt passes.
//!
//! # Accepted target forms
//!
//! * `http://` / `https://` URL with optional port and path (no userinfo).
//! * `host`, `host:port`, IPv4, IPv6 (`::1` or `[::1]`), `ip:port`,
//!   `[v6]:port`.
//! * CIDR (`10.0.0.0/28`, `fd00::/124`), expanded to its addresses; at most
//!   [`MAX_CIDR_ADDRESSES`] addresses across all targets. For IPv4 blocks of
//!   /30 and wider the network and broadcast addresses are skipped.
//!
//! At most [`MAX_TARGETS`] targets. Rejected: empty entries, URLs with
//! credentials, other schemes, wildcards, names that are not valid DNS names,
//! numeric hosts that are not plain dotted quads (`127.1`), port 0, and
//! unspecified (`0.0.0.0`, `::`, `0/8`), multicast and broadcast addresses.
//!
//! # What a target puts in scope
//!
//! A host identity: an exact lowercase host name (IDNA-normalised to
//! punycode, trailing dot stripped) or an IP address (IPv4-mapped IPv6 is
//! treated as the IPv4 address). Subdomains are not in scope.
//!
//! Ports:
//! * a bare host or IP (no port): **any port** on that host, because network
//!   templates probe service ports;
//! * `host:port` / `ip:port`: only that port;
//! * a URL with an explicit non-default port: only that port;
//! * a URL on the scheme's default port (written or not): ports 80 and 443,
//!   so the common http-to-https upgrade redirect stays in scope.
//!
//! Several targets naming the same host merge (any bare-host entry makes every
//! port of the host in scope).
//!
//! # DNS questions
//!
//! A DNS question for an in-scope host name or any subdomain of it is
//! allowed: asking the system resolver about a name sends nothing to a
//! third-party host chosen by the template. A reverse (`PTR`) name of an
//! in-scope IP is allowed too. Connecting to a subdomain is still refused.
//!
//! # Cloud metadata endpoints
//!
//! The well-known metadata addresses and names (see [`is_metadata_ip`],
//! [`is_metadata_name`]) are refused with a specific reason unless that exact
//! address or name was typed as a target. A CIDR range that covers one does
//! not count as typing it: the address is left out of the expansion and a
//! note says so. The resolved addresses of host names are filtered the same
//! way in `resolve.rs` (metadata and link-local answers are dropped unless
//! the name itself is a typed metadata name).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reqwest::Url;

pub(crate) const MAX_TARGETS: usize = 1_000;
pub(crate) const MAX_CIDR_ADDRESSES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScopeLimits {
    pub max_targets: usize,
    pub max_cidr_addresses: usize,
}

impl Default for ScopeLimits {
    fn default() -> Self {
        ScopeLimits {
            max_targets: MAX_TARGETS,
            max_cidr_addresses: MAX_CIDR_ADDRESSES,
        }
    }
}

/// A normalised host identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum HostId {
    /// Lowercase, punycode, no trailing dot.
    Name(String),
    /// Canonical form (IPv4-mapped IPv6 becomes IPv4).
    Ip(IpAddr),
}

impl HostId {
    /// Normalises a host as it would be connected to. The same function is
    /// used for typed targets and for every host a template, a redirect or a
    /// URL names, so the identity checked is the identity connected to.
    pub(crate) fn parse(host: &str) -> Result<HostId, String> {
        let host = host.trim();
        if host.is_empty() {
            return Err("empty host".into());
        }
        if host.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '/' | '\\' | '@' | '?' | '#' | '%' | '*' | ',')
        }) {
            return Err(format!("`{host}` is not a valid host"));
        }
        let unbracketed = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(HostId::Ip(ip.to_canonical()));
        }
        if unbracketed.contains(':') || unbracketed.contains('[') || unbracketed.contains(']') {
            return Err(format!("`{host}` is not a valid host"));
        }
        let url = Url::parse(&format!("http://{unbracketed}/"))
            .map_err(|_| format!("`{host}` is not a valid host name"))?;
        Self::from_url_host(&url).ok_or_else(|| format!("`{host}` is not a valid host name"))
    }

    /// The host of a parsed URL, normalised. The URL parser has already
    /// applied IDNA and lowercasing to a domain.
    pub(crate) fn from_url_host(url: &Url) -> Option<HostId> {
        let s = url.host_str()?;
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            return inner
                .parse::<Ipv6Addr>()
                .ok()
                .map(|v6| HostId::Ip(IpAddr::V6(v6).to_canonical()));
        }
        // The URL parser turns every numeric host form (`127.1`, `0x7f.1`)
        // into a dotted quad, so a host that parses as IPv4 here is one.
        if let Ok(v4) = s.parse::<Ipv4Addr>() {
            return Some(HostId::Ip(IpAddr::V4(v4)));
        }
        let d = s.trim_end_matches('.').to_ascii_lowercase();
        valid_dns_name(&d).then_some(HostId::Name(d))
    }

    /// The host as a key and for display: a name, or an IP without brackets.
    pub(crate) fn key(&self) -> String {
        match self {
            HostId::Name(n) => n.clone(),
            HostId::Ip(ip) => ip.to_string(),
        }
    }

    /// The host as it appears in a URL authority (IPv6 bracketed).
    pub(crate) fn url_host(&self) -> String {
        match self {
            HostId::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
            other => other.key(),
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            HostId::Name(n) => Some(n),
            HostId::Ip(_) => None,
        }
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

/// Letters, digits, hyphen and underscore; labels of 1 to 63 bytes that do
/// not start or end with a hyphen; at most 253 bytes; not all-numeric.
pub(crate) fn valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let well_formed = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    });
    // A last label of digits only is an IP-like string the URL parser did
    // not accept as an address; it is ambiguous, not a name.
    let numeric_tld = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    well_formed && !numeric_tld
}

/// Well-known cloud metadata addresses.
pub(crate) fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => matches!(
            v4.octets(),
            [169, 254, 169, 254] | [169, 254, 170, 2] | [169, 254, 170, 23] | [100, 100, 100, 200]
        ),
        // AWS IMDS (fd00:ec2::254) and the Amazon Time Sync / DNS address
        // on Nitro (fd00:ec2::23).
        IpAddr::V6(v6) => {
            v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
                || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0023)
        }
    }
}

/// The IPv4 addresses a NAT64 address may embed: the last 32 bits for the
/// well-known prefix `64:ff9b::/96` (RFC 6052). For the local-use prefix
/// `64:ff9b:1::/48` (RFC 8215) the operator chooses the prefix length, so
/// an address well formed for the `/48` layout (the `u` octet and the
/// suffix are zero) is decoded from bits 48..64 and 72..88, and any other
/// from its last 32 bits (the `/96` layout). Empty for any other address.
pub(crate) fn nat64_embedded(ip: IpAddr) -> Vec<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return Vec::new();
    };
    let s = v6.segments();
    let o = v6.octets();
    let last32 = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        vec![last32]
    } else if s[..3] == [0x0064, 0xff9b, 0x0001] {
        if o[8] == 0 && o[11..].iter().all(|b| *b == 0) {
            vec![Ipv4Addr::new(o[6], o[7], o[9], o[10])]
        } else {
            vec![last32]
        }
    } else {
        Vec::new()
    }
}

/// Link-local: 169.254.0.0/16 and fe80::/10.
pub(crate) fn is_link_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Well-known cloud metadata host names.
pub(crate) fn is_metadata_name(name: &str) -> bool {
    matches!(
        name,
        "metadata.google.internal"
            | "metadata.goog"
            | "metadata.azure.com"
            | "metadata"
            | "instance-data"
            | "instance-data.ec2.internal"
    )
}

fn is_metadata_host(host: &HostId) -> bool {
    match host {
        HostId::Name(n) => is_metadata_name(n),
        HostId::Ip(ip) => is_metadata_ip(*ip),
    }
}

/// Addresses that can never be a target.
pub(crate) fn forbidden_ip(ip: IpAddr) -> Option<&'static str> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.octets()[0] == 0 {
                Some("unspecified address")
            } else if v4.is_broadcast() {
                Some("broadcast address")
            } else if v4.is_multicast() {
                Some("multicast address")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                Some("unspecified address")
            } else if v6.is_multicast() {
                Some("multicast address")
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// Typed as a URL: HTTP templates use it as written.
    Url { scheme: String, path: String },
    /// Typed as a host, `host:port`, IP or CIDR member.
    Host,
}

/// One typed (or CIDR-expanded) target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanTarget {
    /// The target as typed (or the address, for a CIDR member).
    pub input: String,
    pub host: HostId,
    /// The port as written (for a URL: only an explicit non-default port).
    pub port: Option<u16>,
    pub kind: TargetKind,
}

impl ScanTarget {
    /// The port network templates see: as written, or the URL scheme's
    /// default for a URL target.
    pub(crate) fn network_port(&self) -> Option<u16> {
        match (&self.kind, self.port) {
            (_, Some(p)) => Some(p),
            (TargetKind::Url { scheme, .. }, None) => {
                Some(if scheme == "https" { 443 } else { 80 })
            }
            (TargetKind::Host, None) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PortRule {
    Any,
    Only(BTreeSet<u16>),
}

impl PortRule {
    fn allows(&self, port: u16) -> bool {
        match self {
            PortRule::Any => true,
            PortRule::Only(set) => set.contains(&port),
        }
    }

    fn merge(&mut self, other: PortRule) {
        match (&mut *self, other) {
            (PortRule::Any, _) => {}
            (_, PortRule::Any) => *self = PortRule::Any,
            (PortRule::Only(a), PortRule::Only(b)) => a.extend(b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ScopeError {
    #[error("no targets were given")]
    Empty,
    #[error("target {index} (`{input}`): {reason}")]
    Invalid {
        index: usize,
        input: String,
        reason: String,
    },
    #[error("{given} targets were given; at most {max} are allowed")]
    TooManyTargets { given: usize, max: usize },
    #[error("the CIDR ranges cover {given} addresses; at most {max} are allowed in total")]
    TooManyAddresses { given: usize, max: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefusalReason {
    /// The host is not one the user typed.
    NotInScope,
    /// The host is in scope, the port is not.
    PortNotInScope,
    /// A cloud metadata endpoint that was not typed as a target.
    CloudMetadata,
    /// The host could not be parsed.
    InvalidHost(String),
    /// The URL scheme is not http or https.
    UnsupportedScheme(String),
}

/// A destination scope refused. Nothing was sent to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The refused host only (never a full URL, which may carry secrets).
    pub host: String,
    pub port: Option<u16>,
    pub reason: RefusalReason,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dest = match self.port {
            Some(p) if self.host.contains(':') => format!("[{}]:{p}", self.host),
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        };
        match &self.reason {
            RefusalReason::NotInScope => write!(f, "{dest} is not a target of this run"),
            RefusalReason::PortNotInScope => {
                write!(f, "{dest}: the port is not in scope for this host")
            }
            RefusalReason::CloudMetadata => write!(
                f,
                "{dest} is a cloud metadata endpoint; it is refused unless typed as a target"
            ),
            RefusalReason::InvalidHost(m) => write!(f, "invalid host: {m}"),
            RefusalReason::UnsupportedScheme(s) => {
                write!(f, "{dest}: scheme `{s}` is not http or https")
            }
        }
    }
}

/// The user's targets and the rules derived from them.
#[derive(Debug, Clone)]
pub(crate) struct Scope {
    targets: Vec<ScanTarget>,
    hosts: BTreeMap<HostId, PortRule>,
    /// Metadata addresses or names typed exactly.
    explicit_metadata: BTreeSet<HostId>,
    notes: Vec<String>,
}

impl Scope {
    pub(crate) fn parse(targets: &[String], limits: ScopeLimits) -> Result<Scope, ScopeError> {
        let given: Vec<&String> = targets.iter().collect();
        if given.is_empty() {
            return Err(ScopeError::Empty);
        }
        if given.len() > limits.max_targets {
            return Err(ScopeError::TooManyTargets {
                given: given.len(),
                max: limits.max_targets,
            });
        }
        let mut scope = Scope {
            targets: Vec::new(),
            hosts: BTreeMap::new(),
            explicit_metadata: BTreeSet::new(),
            notes: Vec::new(),
        };
        let mut cidr_addresses = 0usize;
        for (i, raw) in given.iter().enumerate() {
            let index = i + 1;
            let invalid = |reason: String| ScopeError::Invalid {
                index,
                input: raw.to_string(),
                reason,
            };
            let input = raw.trim();
            if input.is_empty() {
                return Err(invalid("empty target".into()));
            }
            if input.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(invalid("targets may not contain spaces".into()));
            }
            if input.contains('*') {
                return Err(invalid("wildcards are not accepted".into()));
            }
            if input.contains("://") {
                let target = parse_url_target(input).map_err(invalid)?;
                let rule = match target.port {
                    Some(p) => PortRule::Only([p].into()),
                    None => PortRule::Only([80, 443].into()),
                };
                scope.add(target, rule, true);
            } else if input.contains('/') {
                let addresses = expand_cidr(input).map_err(invalid)?;
                cidr_addresses += addresses.len();
                if cidr_addresses > limits.max_cidr_addresses {
                    return Err(ScopeError::TooManyAddresses {
                        given: cidr_addresses,
                        max: limits.max_cidr_addresses,
                    });
                }
                for ip in addresses {
                    if is_metadata_ip(ip) {
                        scope.notes.push(format!(
                            "{ip} (in {input}) is a cloud metadata address and was left out; type it as its own target to include it"
                        ));
                        continue;
                    }
                    let target = ScanTarget {
                        input: ip.to_string(),
                        host: HostId::Ip(ip),
                        port: None,
                        kind: TargetKind::Host,
                    };
                    scope.add(target, PortRule::Any, false);
                }
            } else {
                let (host, port) = parse_host_port(input).map_err(invalid)?;
                let rule = match port {
                    Some(p) => PortRule::Only([p].into()),
                    None => PortRule::Any,
                };
                let target = ScanTarget {
                    input: input.to_string(),
                    host,
                    port,
                    kind: TargetKind::Host,
                };
                scope.add(target, rule, true);
            }
        }
        if scope.targets.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(scope)
    }

    fn add(&mut self, target: ScanTarget, rule: PortRule, typed: bool) {
        if typed && is_metadata_host(&target.host) {
            self.explicit_metadata.insert(target.host.clone());
        }
        match self.hosts.get_mut(&target.host) {
            Some(existing) => existing.merge(rule),
            None => {
                self.hosts.insert(target.host.clone(), rule);
            }
        }
        if !self.targets.contains(&target) {
            self.targets.push(target);
        }
    }

    pub(crate) fn targets(&self) -> &[ScanTarget] {
        &self.targets
    }

    /// Notes from parsing (for example a metadata address left out of a
    /// CIDR range).
    pub(crate) fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Every in-scope host name (not IPs), once each.
    pub(crate) fn host_names(&self) -> Vec<String> {
        self.hosts
            .keys()
            .filter_map(|h| h.name().map(str::to_string))
            .collect()
    }

    /// True when this metadata host was typed as a target.
    pub(crate) fn metadata_typed(&self, host: &HostId) -> bool {
        self.explicit_metadata.contains(host)
    }

    /// May a connection be opened to `host` on `port`? Returns the normalised
    /// identity to connect to; callers must connect to that identity (its
    /// pinned addresses), never to the raw string.
    pub(crate) fn check_connect(&self, host: &str, port: u16) -> Result<HostId, Refusal> {
        let id = HostId::parse(host).map_err(|m| Refusal {
            host: truncate_host(host),
            port: Some(port),
            reason: RefusalReason::InvalidHost(m),
        })?;
        self.check_connect_id(&id, port).map(|()| id)
    }

    pub(crate) fn check_connect_id(&self, host: &HostId, port: u16) -> Result<(), Refusal> {
        let refuse = |reason| Refusal {
            host: host.key(),
            port: Some(port),
            reason,
        };
        if is_metadata_host(host) && !self.explicit_metadata.contains(host) {
            return Err(refuse(RefusalReason::CloudMetadata));
        }
        match self.hosts.get(host) {
            None => Err(refuse(RefusalReason::NotInScope)),
            Some(rule) if !rule.allows(port) => Err(refuse(RefusalReason::PortNotInScope)),
            Some(_) => Ok(()),
        }
    }

    /// Checks a URL about to be requested: scheme, host and effective port.
    pub(crate) fn check_url(&self, url: &Url) -> Result<(HostId, u16), Refusal> {
        let scheme = url.scheme();
        let port = url.port_or_known_default();
        let Some(host) = HostId::from_url_host(url) else {
            return Err(Refusal {
                host: truncate_host(url.host_str().unwrap_or_default()),
                port,
                reason: RefusalReason::InvalidHost("the URL has no valid host".into()),
            });
        };
        if scheme != "http" && scheme != "https" {
            return Err(Refusal {
                host: host.key(),
                port,
                reason: RefusalReason::UnsupportedScheme(scheme.to_string()),
            });
        }
        let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        self.check_connect_id(&host, port)?;
        Ok((host, port))
    }

    /// May a template ask the resolver about `name`? Allowed for in-scope
    /// names and their subdomains, and for reverse names of in-scope IPs.
    ///
    /// Returns the normalised name (IDNA, lower case, no trailing dot) that
    /// was checked; that exact name, never the raw text, is what may be
    /// sent to the resolver.
    pub(crate) fn check_dns_question(&self, name: &str) -> Result<String, Refusal> {
        let trimmed = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let refuse = |reason| Refusal {
            host: truncate_host(&trimmed),
            port: None,
            reason,
        };
        if let Some(ip) = reverse_name_ip(&trimmed) {
            return if self.hosts.contains_key(&HostId::Ip(ip.to_canonical())) {
                Ok(trimmed)
            } else {
                Err(refuse(RefusalReason::NotInScope))
            };
        }
        let id = match HostId::parse(&trimmed) {
            Ok(HostId::Name(n)) => n,
            Ok(HostId::Ip(_)) => {
                return Err(refuse(RefusalReason::InvalidHost(
                    "a DNS question must be a name".into(),
                )))
            }
            Err(m) => return Err(refuse(RefusalReason::InvalidHost(m))),
        };
        let allowed = self.hosts.keys().any(|h| match h {
            HostId::Name(n) => id == *n || id.ends_with(&format!(".{n}")),
            HostId::Ip(_) => false,
        });
        if allowed {
            Ok(id)
        } else {
            Err(refuse(RefusalReason::NotInScope))
        }
    }
}

fn truncate_host(host: &str) -> String {
    let mut s: String = host.chars().take(255).collect();
    if s.len() < host.len() {
        s.push('…');
    }
    s
}

/// `4.3.2.1.in-addr.arpa` and nibble-format `ip6.arpa` names.
fn reverse_name_ip(name: &str) -> Option<IpAddr> {
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let parts: Vec<u8> = rest
            .split('.')
            .map(|p| p.parse::<u8>().ok())
            .collect::<Option<_>>()?;
        if parts.len() != 4 {
            return None;
        }
        return Some(IpAddr::V4(Ipv4Addr::new(
            parts[3], parts[2], parts[1], parts[0],
        )));
    }
    if let Some(rest) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<u8> = rest
            .split('.')
            .map(|p| {
                (p.len() == 1)
                    .then(|| u8::from_str_radix(p, 16).ok())
                    .flatten()
            })
            .collect::<Option<_>>()?;
        if nibbles.len() != 32 {
            return None;
        }
        // The reverse name lists nibbles least-significant first.
        let mut forward = [0u8; 16];
        for (i, chunk) in nibbles.chunks(2).enumerate() {
            forward[15 - i] = (chunk[1] << 4) | chunk[0];
        }
        return Some(IpAddr::V6(Ipv6Addr::from(forward)));
    }
    None
}

fn check_ip_target(ip: IpAddr) -> Result<IpAddr, String> {
    let ip = ip.to_canonical();
    match forbidden_ip(ip) {
        Some(why) => Err(format!("{ip} is a {why}")),
        None => Ok(ip),
    }
}

fn parse_url_target(input: &str) -> Result<ScanTarget, String> {
    let (scheme, _) = input.split_once("://").unwrap_or_default();
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "only http:// and https:// URLs are accepted, not `{scheme}://`"
        ));
    }
    let url = Url::parse(input).map_err(|e| format!("not a valid URL: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs with credentials (user:password@) are not accepted".into());
    }
    let host_str = url.host_str().unwrap_or_default();
    let host = HostId::from_url_host(&url)
        .ok_or_else(|| format!("`{host_str}` is not a valid host name"))?;
    let host = match host {
        HostId::Ip(ip) => {
            // A numeric host must be written as a plain address: the URL
            // parser accepts `127.1` and `0x7f.1` and rewrites them.
            let rest = input.split_once("://").map_or(input, |(_, r)| r);
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            let written = match authority.strip_prefix('[') {
                Some(r) => r.split(']').next().unwrap_or_default(),
                None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
            };
            if written.parse::<IpAddr>().is_err() {
                return Err(format!("`{written}` is an ambiguous numeric host"));
            }
            HostId::Ip(check_ip_target(ip)?)
        }
        name => name,
    };
    if url.port() == Some(0) {
        return Err("port 0 is not a valid port".into());
    }
    Ok(ScanTarget {
        input: input.to_string(),
        host,
        port: url.port(),
        kind: TargetKind::Url {
            scheme,
            path: url.path().to_string(),
        },
    })
}

fn parse_port(p: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("`{p}` is not a valid port")),
        Ok(n) => Ok(n),
    }
}

fn parse_host_port(input: &str) -> Result<(HostId, Option<u16>), String> {
    if input.contains(['@', '?', '#', '\\', '%', ',']) {
        return Err("not a host, host:port, IP or URL".into());
    }
    // [v6] or [v6]:port
    if let Some(rest) = input.strip_prefix('[') {
        let (inner, tail) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let ip: Ipv6Addr = inner
            .parse()
            .map_err(|_| format!("`{inner}` is not an IPv6 address"))?;
        let port = match tail {
            "" => None,
            t => Some(parse_port(
                t.strip_prefix(':').ok_or("unexpected text after `]`")?,
            )?),
        };
        return Ok((HostId::Ip(check_ip_target(IpAddr::V6(ip))?), port));
    }
    // Unbracketed IPv6 (two or more colons) cannot carry a port.
    if input.matches(':').count() >= 2 {
        let ip: Ipv6Addr = input
            .parse()
            .map_err(|_| format!("`{input}` is not an IPv6 address; write [addr]:port"))?;
        return Ok((HostId::Ip(check_ip_target(IpAddr::V6(ip))?), None));
    }
    let (host, port) = match input.rsplit_once(':') {
        Some((h, p)) => (h, Some(parse_port(p)?)),
        None => (input, None),
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok((HostId::Ip(check_ip_target(IpAddr::V4(ip))?), port));
    }
    match HostId::parse(host)? {
        HostId::Name(n) => Ok((HostId::Name(n), port)),
        HostId::Ip(_) => Err(format!("`{host}` is an ambiguous numeric host")),
    }
}

/// Expands a CIDR block. Refuses blocks larger than the overall cap before
/// expanding anything.
fn expand_cidr(input: &str) -> Result<Vec<IpAddr>, String> {
    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| "not a CIDR range".to_string())?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| format!("`{prefix}` is not a prefix length"))?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("`{addr}` is not an IP address"))?;
    let (bits, total) = match ip {
        IpAddr::V4(_) => (32u32, 32u32),
        IpAddr::V6(_) => (128, 128),
    };
    if prefix > total {
        return Err(format!("/{prefix} is not a valid prefix length"));
    }
    let host_bits = bits - prefix;
    if host_bits > 8 {
        return Err(format!(
            "/{prefix} covers more than {MAX_CIDR_ADDRESSES} addresses"
        ));
    }
    let count = 1u32 << host_bits;
    let mut out = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            let base = u32::from(v4) & (u32::MAX.checked_shl(host_bits).unwrap_or(0));
            for i in 0..count {
                // Skip the network and broadcast address of /30 and wider.
                if host_bits >= 2 && (i == 0 || i == count - 1) {
                    continue;
                }
                let a = IpAddr::V4(Ipv4Addr::from(base + i));
                check_ip_target(a).map_err(|e| format!("{input}: {e}"))?;
                out.push(a);
            }
        }
        IpAddr::V6(v6) => {
            let base = u128::from(v6) & (u128::MAX.checked_shl(host_bits).unwrap_or(0));
            for i in 0..count {
                let a = IpAddr::V6(Ipv6Addr::from(base + u128::from(i))).to_canonical();
                check_ip_target(a).map_err(|e| format!("{input}: {e}"))?;
                out.push(a);
            }
        }
    }
    Ok(out)
}
