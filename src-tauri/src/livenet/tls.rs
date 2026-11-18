//! The TLS client used by TCP (`tls://`) and SSL templates.
//!
//! Certificates are not verified: targets are commonly self-signed and the
//! tool is assessing them, not trusting them. Nothing the target says is
//! believed beyond being reported. The crypto provider is the aws-lc-rs one
//! reqwest already uses; it is passed explicitly, so the process-wide default
//! provider does not matter.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme, SupportedProtocolVersion};

use super::scope::HostId;

#[derive(Debug)]
struct AcceptAnyCertificate {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A client configuration that accepts any certificate, for the given
/// protocol versions (TLS 1.2 and/or 1.3).
pub(crate) fn client_config(
    versions: &[&'static SupportedProtocolVersion],
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| format!("TLS configuration: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate { schemes }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The server name for a host: SNI for a name, none for an IP.
pub(crate) fn server_name(host: &HostId) -> Result<ServerName<'static>, String> {
    match host {
        HostId::Name(n) => {
            ServerName::try_from(n.clone()).map_err(|e| format!("invalid TLS server name: {e}"))
        }
        HostId::Ip(ip) => Ok(ServerName::IpAddress((*ip).into())),
    }
}

/// `tls12` / `tls13`, as Nuclei names them.
pub(crate) fn version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_2 => "tls12".into(),
        rustls::ProtocolVersion::TLSv1_3 => "tls13".into(),
        rustls::ProtocolVersion::TLSv1_1 => "tls11".into(),
        rustls::ProtocolVersion::TLSv1_0 => "tls10".into(),
        rustls::ProtocolVersion::SSLv3 => "sslv3".into(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}
