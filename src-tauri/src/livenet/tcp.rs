//! TCP (`tcp` / `network`) sessions.
//!
//! The destination is the scope-checked host's pinned addresses (or the
//! typed IP); the template's host string is only an input to that check.
//! Every session is bounded by one overall deadline (the run timeout) and by
//! the response cap across everything it reads, so a slow or endless peer
//! cannot hold it open.

use std::net::{IpAddr, SocketAddr};

use oxaudit_nuclei::{TcpResponseData, TcpSessionSpec, TcpStep};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

use super::scope::HostId;
use super::{tls, Net, NetFailure};

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Connects to the first address that answers before `deadline`.
pub(crate) async fn connect(
    addrs: &[IpAddr],
    port: u16,
    deadline: Instant,
) -> Result<(TcpStream, SocketAddr), String> {
    let mut last = "no addresses".to_string();
    for ip in addrs {
        let addr = SocketAddr::new(*ip, port);
        match timeout_at(deadline, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok((stream, addr)),
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => return Err(format!("{addr}: connection timed out")),
        }
    }
    Err(last)
}

/// Opens a scope-checked, admitted connection to `host_text:port`, wrapped
/// in TLS when asked. Returns the stream, the checked host and the peer.
pub(crate) async fn open(
    net: &Net,
    host_text: &str,
    port: u16,
    tls_wrap: bool,
    tls_versions: &[&'static rustls::SupportedProtocolVersion],
    deadline: Instant,
) -> Result<(Box<dyn Io>, HostId, SocketAddr, Option<TlsFacts>), (NetFailure, Option<HostId>)> {
    let host = net
        .scope
        .check_connect(host_text, port)
        .map_err(|r| (NetFailure::Refused(r), None))?;
    let addrs = net
        .pinned
        .addresses_for(&host)
        .map_err(|m| (NetFailure::Unresolved(m), Some(host.clone())))?;
    let (stream, peer) = connect(&addrs, port, deadline)
        .await
        .map_err(|m| (NetFailure::Connect(m), Some(host.clone())))?;
    if !tls_wrap {
        return Ok((Box::new(stream), host, peer, None));
    }
    let config = tls::client_config(tls_versions)
        .map_err(|m| (NetFailure::Unsupported(m), Some(host.clone())))?;
    let name =
        tls::server_name(&host).map_err(|m| (NetFailure::Protocol(m), Some(host.clone())))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let stream = match timeout_at(deadline, connector.connect(name, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err((
                NetFailure::Protocol(format!("TLS handshake failed: {e}")),
                Some(host),
            ))
        }
        Err(_) => {
            return Err((
                NetFailure::Connect("TLS handshake timed out".into()),
                Some(host),
            ))
        }
    };
    let facts = TlsFacts::from_connection(stream.get_ref().1);
    Ok((Box::new(stream), host, peer, Some(facts)))
}

/// What a finished handshake revealed.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsFacts {
    pub version: String,
    pub cipher: String,
    pub key_exchange: String,
    pub leaf_der: Option<Vec<u8>>,
}

impl TlsFacts {
    fn from_connection(conn: &rustls::ClientConnection) -> Self {
        TlsFacts {
            version: conn
                .protocol_version()
                .map(tls::version_name)
                .unwrap_or_default(),
            cipher: conn
                .negotiated_cipher_suite()
                .map(|s| {
                    let id = s.suite();
                    id.as_str()
                        .map(|n| n.replacen("TLS13_", "TLS_", 1))
                        .unwrap_or_else(|| format!("{id:?}"))
                })
                .unwrap_or_default(),
            key_exchange: conn
                .negotiated_key_exchange_group()
                .map(|g| {
                    let n = g.name();
                    n.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{n:?}"))
                })
                .unwrap_or_default(),
            leaf_der: conn
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec()),
        }
    }
}

/// Reads once (whatever arrives first), up to `max` bytes, before `deadline`.
/// A timeout is an empty read, not an error.
async fn read_once(io: &mut Box<dyn Io>, max: usize, deadline: Instant) -> Result<Vec<u8>, String> {
    if max == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; max.min(64 * 1024)];
    match timeout_at(deadline, io.read(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Ok(Vec::new()),
    }
}

/// Reads until the peer closes, `max` bytes, or `deadline`.
async fn read_all(io: &mut Box<dyn Io>, max: usize, deadline: Instant) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    while out.len() < max {
        let want = (max - out.len()).min(buf.len());
        match timeout_at(deadline, io.read(&mut buf[..want])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

/// Runs one TCP session. The result is everything sent and received.
pub(crate) async fn execute_tcp(
    net: &Net,
    spec: &TcpSessionSpec,
) -> Result<TcpResponseData, NetFailure> {
    // Scope first, so a refused host never takes a token.
    let host = net
        .scope
        .check_connect(&spec.host, spec.port)
        .map_err(NetFailure::Refused)?;
    let _admission = net.admit(&host.key()).await.map_err(NetFailure::Halted)?;
    let deadline = Instant::now() + net.limits.timeout;
    let versions = [&rustls::version::TLS12, &rustls::version::TLS13];
    let (mut io, _, _, _) = open(net, &host.key(), spec.port, spec.tls, &versions, deadline)
        .await
        .map_err(|(f, _)| f)?;

    let cap = net.limits.max_response_bytes;
    let mut resp = TcpResponseData::default();
    for step in &spec.steps {
        match step {
            TcpStep::Send(bytes) => {
                match timeout_at(deadline, io.write_all(bytes)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(NetFailure::Protocol(format!("write failed: {e}"))),
                    Err(_) => return Err(NetFailure::Protocol("write timed out".into())),
                }
                let _ = timeout_at(deadline, io.flush()).await;
                resp.request.extend_from_slice(bytes);
            }
            TcpStep::Read { size, name } => {
                let room = cap.saturating_sub(resp.raw.len());
                let data = read_once(&mut io, (*size).min(room), deadline)
                    .await
                    .map_err(|e| NetFailure::Protocol(format!("read failed: {e}")))?;
                resp.raw.extend_from_slice(&data);
                if let Some(n) = name {
                    resp.named.push((n.clone(), data.clone()));
                }
                resp.data = data;
            }
        }
    }
    let room = cap.saturating_sub(resp.raw.len());
    let last = if spec.read_all {
        read_all(&mut io, room, deadline).await
    } else {
        read_once(&mut io, spec.read_size.min(room), deadline)
            .await
            .unwrap_or_default()
    };
    if !last.is_empty() || spec.steps.iter().all(|s| matches!(s, TcpStep::Send(_))) {
        resp.raw.extend_from_slice(&last);
        resp.data = last;
    }
    let _ = timeout_at(deadline, io.shutdown()).await;
    Ok(resp)
}
