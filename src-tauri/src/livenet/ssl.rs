//! SSL/TLS probes and certificate facts.
//!
//! A rustls handshake without verification, then the leaf certificate parsed
//! with x509-parser. rustls speaks TLS 1.2 and 1.3 only: a probe that needs
//! an older version is reported as not evaluated, never as a clean result.

use md5::Md5;
use oxaudit_nuclei::model::TlsVersion;
use oxaudit_nuclei::{SslProbeSpec, SslResponseData};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use x509_parser::extensions::GeneralName;
use x509_parser::x509::X509Name;

use super::tcp::{open, TlsFacts};
use super::{Net, NetFailure};

/// The rustls versions a probe may use, or why it cannot run.
pub(crate) fn versions_for(
    min: Option<TlsVersion>,
    max: Option<TlsVersion>,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, String> {
    let lo = min.unwrap_or(TlsVersion::Tls12);
    let hi = max.unwrap_or(TlsVersion::Tls13);
    if hi < TlsVersion::Tls12 {
        return Err(format!(
            "the probe requires {} or older; only TLS 1.2 and 1.3 are available",
            hi.as_str()
        ));
    }
    if lo > hi {
        return Err("the minimum TLS version is above the maximum".into());
    }
    let mut out: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if lo <= TlsVersion::Tls12 && hi >= TlsVersion::Tls12 {
        out.push(&rustls::version::TLS12);
    }
    if hi >= TlsVersion::Tls13 {
        out.push(&rustls::version::TLS13);
    }
    Ok(out)
}

/// Runs one handshake.
pub(crate) async fn execute_ssl(
    net: &Net,
    spec: &SslProbeSpec,
) -> Result<SslResponseData, NetFailure> {
    let versions =
        versions_for(spec.min_version, spec.max_version).map_err(NetFailure::Unsupported)?;
    let host = net
        .scope
        .check_connect(&spec.host, spec.port)
        .map_err(NetFailure::Refused)?;
    let _admission = net.admit(&host.key()).await.map_err(NetFailure::Halted)?;
    let deadline = Instant::now() + net.limits.timeout;
    let (_io, host, peer, facts) = open(net, &host.key(), spec.port, true, &versions, deadline)
        .await
        .map_err(|(f, _)| f)?;
    let facts = facts.unwrap_or_default();
    let mut data = facts
        .leaf_der
        .as_deref()
        .and_then(cert_facts)
        .unwrap_or_default();
    apply_session(&mut data, &facts);
    data.host = host.key();
    data.ip = peer.ip().to_string();
    data.port = spec.port;
    data.sni = host.name().unwrap_or_default().to_string();
    data.probe_status = true;
    Ok(data)
}

fn apply_session(data: &mut SslResponseData, facts: &TlsFacts) {
    data.tls_version = facts.version.clone();
    data.cipher = facts.cipher.clone();
    data.key_exchange = facts.key_exchange.clone();
    data.tls_connection = "rustls".into();
}

fn name_cn(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn name_orgs(name: &X509Name<'_>) -> Vec<String> {
    name.iter_organization()
        .filter_map(|a| a.as_str().ok().map(str::to_string))
        .collect()
}

/// Certificate fields of a DER leaf. `None` when it does not parse.
pub(crate) fn cert_facts(der: &[u8]) -> Option<SslResponseData> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let subject = cert.subject();
    let issuer = cert.issuer();
    let mut data = SslResponseData {
        subject_cn: name_cn(subject),
        subject_dn: subject.to_string(),
        subject_org: name_orgs(subject),
        issuer_cn: name_cn(issuer),
        issuer_dn: issuer.to_string(),
        issuer_org: name_orgs(issuer),
        serial: cert
            .raw_serial()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        fingerprint_md5: hex::encode(Md5::digest(der)),
        fingerprint_sha1: hex::encode(Sha1::digest(der)),
        fingerprint_sha256: hex::encode(Sha256::digest(der)),
        self_signed: subject.as_raw() == issuer.as_raw(),
        ..SslResponseData::default()
    };
    for email in subject.iter_email().filter_map(|a| a.as_str().ok()) {
        data.emails.push(email.to_string());
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(d) => data.subject_an.push((*d).to_string()),
                GeneralName::IPAddress(bytes) => {
                    let ip = match bytes.len() {
                        4 => <[u8; 4]>::try_from(*bytes)
                            .ok()
                            .map(|b| std::net::IpAddr::from(b).to_string()),
                        16 => <[u8; 16]>::try_from(*bytes)
                            .ok()
                            .map(|b| std::net::IpAddr::from(b).to_string()),
                        _ => None,
                    };
                    data.subject_an.extend(ip);
                }
                GeneralName::RFC822Name(e) => data.emails.push((*e).to_string()),
                _ => {}
            }
        }
    }
    data.emails.dedup();
    Some(data)
}

/// Certificate facts for an HTTPS response (leaf only; reqwest does not
/// report the cipher).
pub(crate) fn http_tls_facts(
    der: &[u8],
    host: &str,
    sni: &str,
    peer: Option<std::net::SocketAddr>,
    port: u16,
) -> Option<SslResponseData> {
    let mut data = cert_facts(der)?;
    data.host = host.to_string();
    data.sni = sni.to_string();
    data.ip = peer.map(|p| p.ip().to_string()).unwrap_or_default();
    data.port = port;
    data.probe_status = true;
    Some(data)
}
