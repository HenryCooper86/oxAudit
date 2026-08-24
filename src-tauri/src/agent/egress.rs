//! Egress policy for the assistant's `web_fetch` tool.
//!
//! The agent's context is filled with source code from the project under scan —
//! code the user is scanning *precisely because they do not trust it*. A comment
//! in a scanned file is therefore attacker-controlled text sitting in the model's
//! prompt, and an outbound fetch is the channel that turns a prompt injection
//! into an exfiltration. It is also the channel that turns the agent into an SSRF
//! pivot on the developer's own machine and network.
//!
//! Three controls, in order of who can override them:
//!
//! 1. **The address guard cannot be overridden by anyone.** A host that resolves
//!    into private, loopback, link-local, or otherwise non-routable space is
//!    refused even if the user approves the call and even if the host is on the
//!    allow-list. This is what stops `http://169.254.169.254/` and
//!    `http://localhost:8080/admin`, including via a public hostname that
//!    resolves inward (DNS rebinding's first hop).
//! 2. **The host allow-list is set by the user**, seeded with the advisory
//!    sources oxAudit already talks to. Everything else is refused with a message
//!    naming the setting to change.
//! 3. **Every fetch is approved by a human.** `web_fetch` is registered
//!    `dangerous`, so the permission pipeline routes it to HITL and the user sees
//!    the URL before it is requested.
//!
//! Redirects are re-validated hop by hop against all three, because a permitted
//! host redirecting to an internal address is the obvious way around a check
//! applied only to the URL the model supplied.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Hosts the assistant may fetch without the user adding anything.
///
/// These are the advisory and reference sources oxAudit already contacts, plus
/// the places vendor advisories and PoC write-ups actually live. Anything else
/// is a deliberate decision the user makes.
pub const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "nvd.nist.gov",
    "services.nvd.nist.gov",
    "osv.dev",
    "api.osv.dev",
    "cisa.gov",
    "www.cisa.gov",
    "first.org",
    "api.first.org",
    "cve.org",
    "www.cve.org",
    "cve.mitre.org",
    "cwe.mitre.org",
    "capec.mitre.org",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "gitlab.com",
    "security.snyk.io",
    "access.redhat.com",
    "ubuntu.com",
    "security-tracker.debian.org",
    "www.openwall.com",
    "seclists.org",
    "openssf.org",
    "rustsec.org",
    "docs.rs",
    "crates.io",
    "pypi.org",
    "www.npmjs.com",
];

/// The most redirect hops a single `web_fetch` will follow.
///
/// Each hop is re-validated, so this is a cost bound rather than a safety one —
/// but an unbounded chain is its own denial-of-service.
pub const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressError {
    /// Not `http`/`https` — `file:`, `gopher:`, `data:` and friends never reach
    /// the network layer in a form we are willing to reason about.
    UnsupportedScheme(String),
    /// A URL with no host at all (`http:///path`).
    MissingHost,
    /// The host is well-formed and public but not permitted.
    HostNotAllowed(String),
    /// The host resolves somewhere that is not on the public internet.
    NonRoutableAddress { host: String, address: IpAddr },
    /// DNS gave us nothing to check.
    UnresolvableHost(String),
    /// The redirect chain outlived its budget.
    TooManyRedirects,
    /// A `Location` header that is not a URL we can validate.
    InvalidRedirect(String),
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme(scheme) => write!(
                f,
                "only http(s) URLs can be fetched; '{scheme}:' is not supported"
            ),
            Self::MissingHost => write!(f, "the URL has no host to fetch from"),
            Self::HostNotAllowed(host) => write!(
                f,
                "'{host}' is not an allowed fetch destination. Add it under \
                 Settings → AI engine → Allowed fetch hosts if you intend the \
                 assistant to read from it."
            ),
            Self::NonRoutableAddress { host, address } => write!(
                f,
                "'{host}' resolves to {address}, which is not on the public \
                 internet. Fetching private, loopback, or link-local addresses \
                 is refused: it would let content in a scanned project reach \
                 services on your machine or network."
            ),
            Self::UnresolvableHost(host) => write!(f, "'{host}' could not be resolved"),
            Self::TooManyRedirects => write!(
                f,
                "the URL redirected more than {MAX_REDIRECTS} times; giving up"
            ),
            Self::InvalidRedirect(location) => {
                write!(f, "the redirect target could not be parsed: {location}")
            }
        }
    }
}

impl std::error::Error for EgressError {}

/// Which hosts the assistant may fetch from.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allowed: Vec<String>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl EgressPolicy {
    /// Build the policy from the built-in defaults plus whatever the user added.
    ///
    /// User entries are normalized the same way host names are, so a pasted
    /// `HTTPS://Example.COM/advisories` still yields `example.com`.
    pub fn new(user_hosts: &[String]) -> Self {
        let mut allowed: Vec<String> = DEFAULT_ALLOWED_HOSTS
            .iter()
            .map(|host| (*host).to_owned())
            .collect();
        for entry in user_hosts {
            if let Some(host) = normalize_host_entry(entry) {
                allowed.push(host);
            }
        }
        allowed.sort();
        allowed.dedup();
        Self { allowed }
    }

    /// The effective list, defaults plus user entries. Consumed by the tests
    /// today; the Settings screen will surface it when the list becomes
    /// editable in the GUI.
    #[cfg(test)]
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed
    }

    /// Check the scheme and host of a URL the agent wants to fetch.
    ///
    /// This deliberately does not look at the path, query, or port: the identity
    /// that matters for egress is who receives the bytes.
    pub fn check_url(&self, url: &url_lite::Url) -> Result<(), EgressError> {
        let scheme = url.scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(EgressError::UnsupportedScheme(scheme));
        }
        let host = normalize_host(&url.host).ok_or(EgressError::MissingHost)?;
        if self.is_allowed(&host) {
            Ok(())
        } else {
            Err(EgressError::HostNotAllowed(host))
        }
    }

    /// A host matches when it equals an allow-list entry or is a subdomain of
    /// one. `raw.githubusercontent.com` is listed explicitly rather than relying
    /// on a `github.com` suffix match, because suffix matching across a registrar
    /// boundary is how allow-lists quietly become useless.
    fn is_allowed(&self, host: &str) -> bool {
        self.allowed.iter().any(|entry| {
            host == entry
                || host
                    .strip_suffix(entry)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

/// Reject any address that is not on the public internet.
///
/// Rust's `IpAddr::is_global` is still unstable, so the ranges are spelled out.
/// The bias is deliberate: anything we are not sure is publicly routable is
/// treated as internal.
pub fn check_address(host: &str, address: IpAddr) -> Result<(), EgressError> {
    let routable = match address {
        IpAddr::V4(v4) => is_routable_v4(v4),
        IpAddr::V6(v6) => is_routable_v6(v6),
    };
    if routable {
        Ok(())
    } else {
        Err(EgressError::NonRoutableAddress {
            host: host.to_owned(),
            address,
        })
    }
}

/// Every resolved address must be routable, not merely one of them.
///
/// A host that answers with both a public and a private address would otherwise
/// pass the check and then connect to whichever the resolver returned first.
pub fn check_addresses(host: &str, addresses: &[IpAddr]) -> Result<(), EgressError> {
    if addresses.is_empty() {
        return Err(EgressError::UnresolvableHost(host.to_owned()));
    }
    for address in addresses {
        check_address(host, *address)?;
    }
    Ok(())
}

fn is_routable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()                       // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()                 // 127/8
        || ip.is_link_local()               // 169.254/16 — cloud metadata
        || ip.is_broadcast()                // 255.255.255.255
        || ip.is_documentation()            // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()                // 224/4
        || ip.is_unspecified()              // 0.0.0.0
        || a == 0                           // 0/8 "this network"
        || a == 100 && (64..128).contains(&b) // 100.64/10 carrier-grade NAT
        || a == 192 && b == 0 && c == 0     // 192.0.0/24 IETF protocol assignments
        || a == 198 && (b == 18 || b == 19) // 198.18/15 benchmarking
        || a >= 240) // 240/4 reserved, includes 255/8
}

fn is_routable_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let segments = ip.segments();
    // An IPv4-mapped or IPv4-compatible address is an IPv4 address wearing a
    // costume; judge it as one rather than letting ::ffff:127.0.0.1 through.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_routable_v4(v4);
    }
    if let Some(v4) = ip.to_ipv4() {
        return is_routable_v4(v4);
    }
    let unique_local = segments[0] & 0xfe00 == 0xfc00; // fc00::/7
    let link_local = segments[0] & 0xffc0 == 0xfe80; // fe80::/10
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8; // 2001:db8::/32
    !(unique_local || link_local || documentation)
}

/// Lower-case a host and drop the trailing dot of a fully-qualified name, so
/// `NVD.NIST.GOV.` and `nvd.nist.gov` are the same destination.
fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Accept an allow-list entry written as a bare host, or pasted as a full URL.
fn normalize_host_entry(entry: &str) -> Option<String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let host_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    // Strip userinfo and any port, and unwrap a bracketed IPv6 literal.
    let host = host_port.rsplit('@').next().unwrap_or(host_port);
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    normalize_host(host)
}

/// A deliberately small URL view.
///
/// `reqwest::Url` is the type actually used at the call site; this mirror keeps
/// the policy pure so it can be exhaustively tested without a network stack,
/// and keeps the rules readable in one place.
pub mod url_lite {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Url {
        pub scheme: String,
        pub host: String,
    }

    impl Url {
        #[cfg(test)]
        pub fn new(scheme: impl Into<String>, host: impl Into<String>) -> Self {
            Self {
                scheme: scheme.into(),
                host: host.into(),
            }
        }
    }

    impl From<&reqwest::Url> for Url {
        fn from(url: &reqwest::Url) -> Self {
            Self {
                scheme: url.scheme().to_owned(),
                host: url.host_str().unwrap_or_default().to_owned(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::url_lite::Url;
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::default()
    }

    fn v4(address: &str) -> IpAddr {
        IpAddr::V4(address.parse().unwrap())
    }

    fn v6(address: &str) -> IpAddr {
        IpAddr::V6(address.parse().unwrap())
    }

    // ------------------------------------------------------------ scheme

    #[test]
    fn permits_http_and_https_only() {
        assert!(policy().check_url(&Url::new("https", "osv.dev")).is_ok());
        assert!(policy().check_url(&Url::new("http", "osv.dev")).is_ok());
        assert!(policy().check_url(&Url::new("HTTPS", "osv.dev")).is_ok());
    }

    #[test]
    fn refuses_schemes_that_are_not_http() {
        for scheme in ["file", "ftp", "gopher", "data", "javascript"] {
            assert_eq!(
                policy().check_url(&Url::new(scheme, "osv.dev")),
                Err(EgressError::UnsupportedScheme(scheme.into())),
                "{scheme} should be refused"
            );
        }
    }

    // -------------------------------------------------------------- host

    #[test]
    fn permits_the_advisory_sources_by_default() {
        for host in ["nvd.nist.gov", "osv.dev", "github.com", "rustsec.org"] {
            assert!(
                policy().check_url(&Url::new("https", host)).is_ok(),
                "{host} should be allowed out of the box"
            );
        }
    }

    #[test]
    fn refuses_a_host_nobody_allowed() {
        assert_eq!(
            policy().check_url(&Url::new("https", "attacker.example")),
            Err(EgressError::HostNotAllowed("attacker.example".into()))
        );
    }

    #[test]
    fn host_matching_ignores_case_and_a_trailing_dot() {
        assert!(policy()
            .check_url(&Url::new("https", "NVD.NIST.GOV."))
            .is_ok());
    }

    #[test]
    fn permits_subdomains_of_an_allowed_host() {
        assert!(policy()
            .check_url(&Url::new("https", "advisories.github.com"))
            .is_ok());
    }

    #[test]
    fn a_suffix_that_is_not_a_subdomain_does_not_match() {
        // The bug this guards: `host.ends_with("github.com")` would happily
        // accept `evilgithub.com` and `github.com.attacker.example`.
        for host in [
            "evilgithub.com",
            "notosv.dev",
            "github.com.attacker.example",
        ] {
            assert_eq!(
                policy().check_url(&Url::new("https", host)),
                Err(EgressError::HostNotAllowed(host.into())),
                "{host} must not match by suffix alone"
            );
        }
    }

    #[test]
    fn an_empty_host_is_refused() {
        assert_eq!(
            policy().check_url(&Url::new("https", "")),
            Err(EgressError::MissingHost)
        );
    }

    // -------------------------------------------------------- user entries

    #[test]
    fn user_entries_extend_the_allow_list() {
        let policy = EgressPolicy::new(&["vendor.example".to_string()]);
        assert!(policy
            .check_url(&Url::new("https", "vendor.example"))
            .is_ok());
        assert!(policy
            .check_url(&Url::new("https", "psirt.vendor.example"))
            .is_ok());
    }

    #[test]
    fn a_user_entry_pasted_as_a_url_still_yields_a_host() {
        let policy = EgressPolicy::new(&[
            "https://Vendor.Example/security/advisories?x=1".to_string(),
            "  http://user:pw@other.example:8443/  ".to_string(),
        ]);
        assert!(policy
            .check_url(&Url::new("https", "vendor.example"))
            .is_ok());
        assert!(policy
            .check_url(&Url::new("https", "other.example"))
            .is_ok());
    }

    #[test]
    fn blank_user_entries_are_ignored_rather_than_widening_the_list() {
        let policy = EgressPolicy::new(&["".into(), "   ".into()]);
        assert_eq!(policy.allowed_hosts().len(), DEFAULT_ALLOWED_HOSTS.len());
        assert_eq!(
            policy.check_url(&Url::new("https", "attacker.example")),
            Err(EgressError::HostNotAllowed("attacker.example".into()))
        );
    }

    #[test]
    fn a_user_entry_never_reaches_the_network_without_the_address_guard() {
        // Allow-listing a host does not permit it to resolve inward. This is the
        // ordering that matters: the address guard is not overridable.
        let policy = EgressPolicy::new(&["internal.example".to_string()]);
        assert!(policy
            .check_url(&Url::new("https", "internal.example"))
            .is_ok());
        assert_eq!(
            check_address("internal.example", v4("10.0.0.5")),
            Err(EgressError::NonRoutableAddress {
                host: "internal.example".into(),
                address: v4("10.0.0.5"),
            })
        );
    }

    // ----------------------------------------------------------- addresses

    #[test]
    fn refuses_the_cloud_metadata_address() {
        assert!(check_address("meta", v4("169.254.169.254")).is_err());
    }

    #[test]
    fn refuses_loopback_private_and_reserved_v4() {
        for address in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.5.4",
            "172.31.255.255",
            "192.168.1.1",
            "0.0.0.0",
            "100.64.0.1", // carrier-grade NAT
            "192.0.0.1",  // IETF protocol assignments
            "198.18.0.1", // benchmarking
            "224.0.0.1",  // multicast
            "240.0.0.1",  // reserved
            "255.255.255.255",
        ] {
            assert!(
                check_address("h", v4(address)).is_err(),
                "{address} must be refused"
            );
        }
    }

    #[test]
    fn permits_ordinary_public_v4() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "140.82.121.4",
            "172.15.0.1",
            "172.32.0.1",
        ] {
            assert!(
                check_address("h", v4(address)).is_ok(),
                "{address} should be reachable"
            );
        }
    }

    #[test]
    fn refuses_internal_v6() {
        for address in [
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "2001:db8::1",
            "ff02::1",
        ] {
            assert!(
                check_address("h", v6(address)).is_err(),
                "{address} must be refused"
            );
        }
    }

    #[test]
    fn refuses_v4_addresses_disguised_as_v6() {
        // ::ffff:127.0.0.1 and ::127.0.0.1 both reach loopback.
        assert!(check_address("h", v6("::ffff:127.0.0.1")).is_err());
        assert!(check_address("h", v6("::ffff:169.254.169.254")).is_err());
        assert!(check_address("h", v6("::ffff:10.0.0.1")).is_err());
    }

    #[test]
    fn permits_ordinary_public_v6() {
        assert!(check_address("h", v6("2606:4700:4700::1111")).is_ok());
    }

    #[test]
    fn every_resolved_address_must_be_routable() {
        // A split-horizon answer must not pass because one record is public.
        assert!(check_addresses("h", &[v4("1.1.1.1"), v4("127.0.0.1")]).is_err());
        assert!(check_addresses("h", &[v4("1.1.1.1"), v4("8.8.8.8")]).is_ok());
    }

    #[test]
    fn a_host_that_resolves_to_nothing_is_an_error() {
        assert_eq!(
            check_addresses("nowhere.example", &[]),
            Err(EgressError::UnresolvableHost("nowhere.example".into()))
        );
    }

    // ------------------------------------------------------------ messages

    #[test]
    fn the_refusal_message_names_the_setting_to_change() {
        let message = EgressError::HostNotAllowed("vendor.example".into()).to_string();
        assert!(message.contains("vendor.example"));
        assert!(message.contains("Allowed fetch hosts"));
    }

    #[test]
    fn the_address_refusal_explains_why_rather_than_just_refusing() {
        let message = EgressError::NonRoutableAddress {
            host: "internal.example".into(),
            address: v4("169.254.169.254"),
        }
        .to_string();
        assert!(message.contains("169.254.169.254"));
        assert!(message.contains("public internet"));
    }
}
