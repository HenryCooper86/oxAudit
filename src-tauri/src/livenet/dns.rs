//! DNS queries for `dns` templates.
//!
//! Questions go to the system resolvers only; a template cannot choose the
//! resolver address (the template crate has no `resolvers` field, so there is
//! nothing to ignore). Each question is checked with
//! `Scope::check_dns_question` first and admitted by the governor.
//! `recursion: false` is not honoured (the stub resolver always asks for
//! recursion) and `retries` is the resolver's own; both are recorded as run
//! notes by the caller when a template sets them.

use std::fmt::Write as _;
use std::time::Duration;

use hickory_resolver::config::ResolveHosts;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Record, RecordType};
use hickory_resolver::TokioResolver;
use oxaudit_nuclei::model::{DnsClass, DnsType};
use oxaudit_nuclei::{DnsQuerySpec, DnsResponseData};

use super::{BoxFuture, Net, NetFailure};

/// Answers one DNS question. Injected so tests need no real DNS.
pub(crate) trait DnsQuerier: Send + Sync {
    fn query<'a>(
        &'a self,
        name: &'a str,
        qtype: DnsType,
    ) -> BoxFuture<'a, Result<DnsResponseData, String>>;
}

/// The system resolver configuration via hickory, hosts file off (a hosts
/// entry is not a DNS answer).
pub(crate) struct SystemDns {
    inner: TokioResolver,
}

impl SystemDns {
    pub(crate) fn new(timeout: Duration) -> Result<Self, String> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|e| format!("cannot read the system DNS configuration: {e}"))?;
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.preserve_intermediates = true;
        let inner = builder
            .build()
            .map_err(|e| format!("cannot start the DNS resolver: {e}"))?;
        Ok(SystemDns { inner })
    }
}

fn record_type(t: DnsType) -> RecordType {
    match t {
        DnsType::A => RecordType::A,
        DnsType::Aaaa => RecordType::AAAA,
        DnsType::Cname => RecordType::CNAME,
        DnsType::Ns => RecordType::NS,
        DnsType::Mx => RecordType::MX,
        DnsType::Txt => RecordType::TXT,
        DnsType::Soa => RecordType::SOA,
        DnsType::Ptr => RecordType::PTR,
        DnsType::Caa => RecordType::CAA,
        DnsType::Srv => RecordType::SRV,
    }
}

/// `NOERROR`, `NXDOMAIN`, ... as dig prints them.
fn rcode_name(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        ResponseCode::Refused => "REFUSED".into(),
        ResponseCode::YXDomain => "YXDOMAIN".into(),
        ResponseCode::YXRRSet => "YXRRSET".into(),
        ResponseCode::NXRRSet => "NXRRSET".into(),
        ResponseCode::NotAuth => "NOTAUTH".into(),
        ResponseCode::NotZone => "NOTZONE".into(),
        other => format!("RCODE{}", u16::from(other)),
    }
}

/// `name<TAB>ttl<TAB>IN<TAB>TYPE<TAB>data`, the layout the template crate
/// documents.
fn record_line(r: &Record) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        r.name,
        r.ttl,
        r.dns_class,
        r.record_type(),
        r.data
    )
}

/// Builds the response, including the dig-style `raw` text.
pub(crate) fn response_data(
    name: &str,
    qtype: DnsType,
    rcode: &str,
    answers: Vec<String>,
    authority: Vec<String>,
    additional: Vec<String>,
) -> DnsResponseData {
    let fqdn = format!("{}.", name.trim_end_matches('.'));
    let question = format!(";{fqdn}\tIN\t{}", qtype.as_str());
    let mut raw = String::new();
    let _ = writeln!(raw, ";; ->>HEADER<<- opcode: QUERY, status: {rcode}");
    let _ = writeln!(raw, "\n;; QUESTION SECTION:\n{question}");
    for (title, lines) in [
        ("ANSWER", &answers),
        ("AUTHORITY", &authority),
        ("ADDITIONAL", &additional),
    ] {
        if !lines.is_empty() {
            let _ = writeln!(raw, "\n;; {title} SECTION:");
            for l in lines {
                let _ = writeln!(raw, "{l}");
            }
        }
    }
    DnsResponseData {
        rcode: rcode.to_string(),
        question,
        answers,
        authority,
        additional,
        raw,
    }
}

impl DnsQuerier for SystemDns {
    fn query<'a>(
        &'a self,
        name: &'a str,
        qtype: DnsType,
    ) -> BoxFuture<'a, Result<DnsResponseData, String>> {
        Box::pin(async move {
            let fqdn = format!("{}.", name.trim_end_matches('.'));
            match self.inner.lookup(fqdn.as_str(), record_type(qtype)).await {
                Ok(lookup) => {
                    let msg = lookup.message();
                    Ok(response_data(
                        name,
                        qtype,
                        &rcode_name(msg.metadata.response_code),
                        lookup.answers().iter().map(record_line).collect(),
                        lookup.authorities().iter().map(record_line).collect(),
                        lookup.additionals().iter().map(record_line).collect(),
                    ))
                }
                Err(NetError::Dns(DnsError::NoRecordsFound(nr))) => {
                    let authority: Vec<String> = match &nr.soa {
                        Some(soa) => {
                            vec![record_line(&soa.as_ref().clone().into_record_of_rdata())]
                        }
                        None => Vec::new(),
                    };
                    Ok(response_data(
                        name,
                        qtype,
                        &rcode_name(nr.response_code),
                        Vec::new(),
                        authority,
                        Vec::new(),
                    ))
                }
                Err(NetError::Dns(DnsError::ResponseCode(code))) => Ok(response_data(
                    name,
                    qtype,
                    &rcode_name(code),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

/// Asks one template question, after the scope check and the governor.
pub(crate) async fn execute_dns(
    net: &Net,
    dns: &dyn DnsQuerier,
    spec: &DnsQuerySpec,
) -> Result<DnsResponseData, NetFailure> {
    if spec.class != DnsClass::Inet {
        return Err(NetFailure::Unsupported(format!(
            "DNS class {:?} (only IN is supported)",
            spec.class
        )));
    }
    // The question sent is the name scope checked (IDNA-normalised), never
    // the template's raw text, so the two cannot differ.
    let name = net
        .scope
        .check_dns_question(&spec.name)
        .map_err(NetFailure::Refused)?;
    let _admission = net.admit(&name).await.map_err(NetFailure::Halted)?;
    match tokio::time::timeout(net.limits.timeout, dns.query(&name, spec.qtype)).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(NetFailure::Protocol(format!("DNS query failed: {e}"))),
        Err(_) => Err(NetFailure::Protocol("DNS query timed out".into())),
    }
}
