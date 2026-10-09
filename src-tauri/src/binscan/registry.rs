//! Pulling image layers straight from an OCI/Docker v2 registry.
//!
//! `oxaudit-cli image` accepts a registry reference
//! (`registry.example.com/ns/repo:tag`) and fetches the manifest and layers
//! itself, so scanning an image no longer starts with `docker save`. The
//! bytes then go through the same in-memory pipeline a saved tar does —
//! package databases, os-release, JAR coordinates, signatures.
//!
//! Trust and limits:
//! - Every blob is verified against its `sha256:` digest from the manifest
//!   before it is scanned; a registry that answers with different bytes
//!   fails the pull loudly.
//! - Auth is the registry's own challenge (bearer token flow) plus whatever
//!   `docker login` left in the docker config — Basic credentials and
//!   identity tokens. Desktop credential helpers are not consulted; a
//!   registry that needs one says so instead of being asked anonymously.
//! - Manifests are capped at 16 MiB, layers at 1 GiB each, 8 GiB and 128
//!   layers per image — the same posture as archive extraction.

use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static NEVER_CANCEL: AtomicBool = AtomicBool::new(false);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

async fn registry_wait<F: std::future::Future>(
    cancel: &AtomicBool,
    future: F,
) -> Result<F::Output, String> {
    tokio::select! {
        biased;
        _ = async {
            while !cancel.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(25)).await; }
        } => Err("image scan cancelled".into()),
        result = tokio::time::timeout(REQUEST_TIMEOUT, future) => {
            let result = result.map_err(|_| "registry request timed out".to_string())?;
            if cancel.load(Ordering::SeqCst) { return Err("image scan cancelled".into()); }
            Ok(result)
        }
    }
}

const MANIFEST_TYPES: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_LAYER_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_TOTAL_LAYER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_LAYERS: usize = 128;

/// A parsed registry reference. `reference` is the tag or `sha256:…` digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRef {
    pub registry: String,
    pub name: String,
    pub reference: String,
}

/// A first path segment that names a registry rather than a local directory:
/// `localhost`, a dotted hostname with non-empty labels, or host:port.
/// Relative segments like `.` or `..` are paths, not hosts.
fn looks_like_registry(first_segment: &str) -> bool {
    if first_segment == "localhost" {
        return true;
    }
    if let Some((host, port)) = first_segment.split_once(':') {
        let port_ok = !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
        return !host.is_empty() && (port_ok || host_is_dotted(host));
    }
    host_is_dotted(first_segment)
}

fn host_is_dotted(segment: &str) -> bool {
    let labels: Vec<&str> = segment.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|label| !label.is_empty())
}

fn valid_repository_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/')
        })
}

/// Parse `registry.example.com/ns/repo:tag` (or `…@sha256:…`). Returns
/// `None` when the string does not name a registry, so callers treat it as a
/// local path.
pub fn parse_ref(raw: &str) -> Option<RegistryRef> {
    let raw = raw.trim().trim_end_matches('/');
    let (registry, rest) = raw.split_once('/')?;
    if !looks_like_registry(registry) {
        return None;
    }
    // A digest reference beats a tag; both may be present (`:tag@sha256:…`).
    let (path, reference) = match rest.split_once('@') {
        Some((path, digest)) => (path, digest.to_string()),
        None => match rest.rsplit_once(':') {
            // Only in the last segment — a colon earlier would be part of
            // the registry host, already consumed above.
            Some((path, tag)) if !tag.contains('/') => (path, tag.to_string()),
            _ => (rest, "latest".to_string()),
        },
    };
    if !valid_repository_name(path) {
        return None;
    }
    if !(reference == "latest"
        || reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-')))
    {
        return None;
    }
    Some(RegistryRef {
        registry: registry.to_string(),
        name: path.to_string(),
        reference,
    })
}

/// Is the `docker.io` family? Official images live under `library/` and the
/// API host is `registry-1.docker.io`.
fn is_docker_hub(registry: &str) -> bool {
    matches!(
        registry,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    )
}

/// Normalize for API calls: hub API host and the `library/` namespace.
fn api_host(reference: &RegistryRef) -> String {
    if is_docker_hub(&reference.registry) {
        "registry-1.docker.io".to_string()
    } else {
        reference.registry.clone()
    }
}

fn api_name(reference: &RegistryRef) -> String {
    if is_docker_hub(&reference.registry) && !reference.name.contains('/') {
        format!("library/{}", reference.name)
    } else {
        reference.name.clone()
    }
}

/// localhost registries speak plain HTTP; everything else is HTTPS.
fn scheme_for(registry: &str) -> &'static str {
    let host = registry.split(':').next().unwrap_or(registry);
    if host == "localhost" || host.starts_with("127.") {
        "http"
    } else {
        "https"
    }
}

/// What `docker login` recorded for a registry, from the docker config —
/// Basic credentials and identity tokens. Credential-helper entries are
/// recognized as unhandled so a private registry says so rather than being
/// asked anonymously.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DockerConfigAuth {
    pub basic: Option<String>,
    pub identity_token: Option<String>,
    pub helper_unavailable: bool,
}

pub fn load_docker_config_auth(registry: &str) -> DockerConfigAuth {
    let config_path = std::env::var_os("DOCKER_CONFIG")
        .map(std::path::PathBuf::from)
        .map(|dir| dir.join("config.json"))
        .or_else(|| dirs::home_dir().map(|home| home.join(".docker").join("config.json")));
    let Some(config_path) = config_path else {
        return DockerConfigAuth::default();
    };
    let Ok(raw) = crate::private_storage::read_to_string(&config_path) else {
        return DockerConfigAuth::default();
    };
    let Ok(config) = serde_json::from_str::<Value>(&raw) else {
        return DockerConfigAuth::default();
    };
    let Some(auths) = config.get("auths").and_then(Value::as_object) else {
        return DockerConfigAuth::default();
    };

    // Config keys carry schemes and paths ("https://index.docker.io/v1/");
    // match on the host inside the key, plus the hub aliases.
    let wanted = |key: &str| -> bool {
        let key = key
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let key_host = key.split('/').next().unwrap_or(key);
        key_host == registry || (is_docker_hub(registry) && is_docker_hub(key_host))
    };

    for (key, entry) in auths {
        if !wanted(key) {
            continue;
        }
        let auth = DockerConfigAuth {
            basic: entry.get("auth").and_then(Value::as_str).map(String::from),
            identity_token: entry
                .get("identitytoken")
                .and_then(Value::as_str)
                .map(String::from),
            helper_unavailable: false,
        };
        // A credsStore entry means the credentials sit in a helper we do not
        // read — but a static credential beside it still works.
        let helper_unavailable = entry.get("credsStore").is_some()
            && auth.basic.is_none()
            && auth.identity_token.is_none();
        return DockerConfigAuth {
            helper_unavailable,
            ..auth
        };
    }
    DockerConfigAuth::default()
}

/// One downloaded layer: the name its members should carry
/// (`layer-0000.tar.gz`) and its bytes.
pub struct Layer {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A pulled image, ready for the native scanner.
pub struct ImageLayers {
    /// Human-facing identity, used as the finding-path prefix.
    pub display: String,
    pub digest: String,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerReceipt {
    pub name: String,
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
}

/// Owns the private spool directory until scanning has finished. All layer
/// files have been digest-verified; extracted member paths never reach disk.
pub struct ImageLayerFiles {
    pub display: String,
    pub digest: String,
    pub layers: Vec<(String, std::path::PathBuf)>,
    pub receipts: Vec<LayerReceipt>,
    _directory: tempfile::TempDir,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Verify downloaded bytes against a `sha256:…` digest.
fn verify_digest(digest: &str, bytes: &[u8]) -> Result<(), String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(format!(
            "unsupported digest {digest}; only sha256 is handled"
        ));
    };
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(hex) {
        return Err(format!(
            "blob digest mismatch: manifest says {digest}, registry served sha256:{actual}"
        ));
    }
    Ok(())
}

struct RegistryClient<'a> {
    http: &'a reqwest::Client,
    host: String,
    scheme: &'static str,
    name: String,
    /// `Authorization` header for manifest and blob requests.
    authorization: Option<String>,
    cancel: &'a AtomicBool,
}

#[derive(Debug)]
struct Manifest {
    bytes: Vec<u8>,
    digest: String,
}

impl<'a> RegistryClient<'a> {
    fn url(&self, suffix: &str) -> String {
        format!("{}://{}/v2/{}{suffix}", self.scheme, self.host, self.name)
    }

    async fn fetch_limited(
        &self,
        url: &str,
        accept: Option<&str>,
        max_bytes: u64,
    ) -> Result<reqwest::Response, String> {
        let mut request = self.http.get(url);
        if let Some(authorization) = &self.authorization {
            request = request.header("Authorization", authorization);
        }
        if let Some(accept) = accept {
            request = request.header("Accept", accept);
        }
        let response = registry_wait(self.cancel, request.timeout(REQUEST_TIMEOUT).send())
            .await?
            .map_err(|error| format!("registry request failed for {url}: {error}"))?;
        let length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if let Some(length) = length {
            if length > max_bytes {
                return Err(format!(
                    "resource limit: {url} is {length} bytes (cap {max_bytes})"
                ));
            }
        }
        Ok(response)
    }

    async fn read_capped(
        &self,
        response: reqwest::Response,
        max_bytes: u64,
        what: &str,
    ) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        let mut stream = response;
        while let Some(chunk) = registry_wait(self.cancel, stream.chunk())
            .await?
            .map_err(|error| format!("registry download failed for {what}: {error}"))?
        {
            if (bytes.len() as u64) + (chunk.len() as u64) > max_bytes {
                return Err(format!("resource limit: {what} exceeds {max_bytes} bytes"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Resolve the auth challenge: bearer token flow, identity token, or
    /// Basic from the docker config. An open registry answers 200 and needs
    /// none of them.
    async fn authenticate(&mut self, config: &DockerConfigAuth) -> Result<(), String> {
        let probe = format!("{}://{}/v2/", self.scheme, self.host);
        let basic_header = config.basic.as_ref().map(|auth| format!("Basic {auth}"));
        let mut request = self.http.get(&probe);
        if let Some(header) = &basic_header {
            request = request.header("Authorization", header);
        }
        let response = registry_wait(self.cancel, request.timeout(REQUEST_TIMEOUT).send())
            .await?
            .map_err(|error| format!("registry is unreachable ({probe}): {error}"))?;
        match response.status() {
            status if status.is_success() => {
                // Open registry, or Basic already satisfied it.
                self.authorization = basic_header;
                return Ok(());
            }
            reqwest::StatusCode::UNAUTHORIZED => {}
            status => {
                return Err(format!("registry answered {status} for {probe}"));
            }
        }

        // Prefer an identity token: it is itself the bearer credential.
        if let Some(token) = &config.identity_token {
            self.authorization = Some(format!("Bearer {token}"));
            return Ok(());
        }

        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "registry demands auth but sent no challenge".to_string())?
            .to_string();
        let (realm, service) = parse_bearer_challenge(&challenge)?;
        let scope = format!("repository:{}:pull", self.name);
        let token_url = format!(
            "{}{}service={}&scope={}",
            realm,
            if realm.contains('?') { '&' } else { '?' },
            urlencode(&service),
            urlencode(&scope)
        );
        let mut request = self.http.get(&token_url);
        if let Some(header) = &basic_header {
            request = request.header("Authorization", header);
        }
        let response = registry_wait(self.cancel, request.timeout(REQUEST_TIMEOUT).send())
            .await?
            .map_err(|error| format!("token service is unreachable: {error}"))?;
        if !response.status().is_success() {
            if config.helper_unavailable {
                return Err(format!(
                    "registry requires credentials that sit in a docker credential helper oxAudit does not read; docker login against {} in a way that writes config.json, or scan a saved image",
                    self.host
                ));
            }
            return Err(format!(
                "token service answered {} for {token_url}",
                response.status()
            ));
        }
        let body = self
            .read_capped(response, MAX_MANIFEST_BYTES, "token response")
            .await?;
        let token: Value = serde_json::from_slice(&body)
            .map_err(|error| format!("token response is not JSON: {error}"))?;
        let token = token
            .get("token")
            .or_else(|| token.get("access_token"))
            .and_then(Value::as_str)
            .ok_or_else(|| "token response carries no token".to_string())?;
        self.authorization = Some(format!("Bearer {token}"));
        Ok(())
    }

    async fn fetch_manifest(&self, reference: &str) -> Result<Manifest, String> {
        let url = self.url(&format!("/manifests/{reference}"));
        let response = self
            .fetch_limited(&url, Some(MANIFEST_TYPES), MAX_MANIFEST_BYTES)
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!("registry has no manifest for {url}"));
        }
        if !response.status().is_success() {
            return Err(format!("registry answered {} for {url}", response.status()));
        }
        let digest = response
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|value| value.to_str().ok())
            .map(String::from);
        let bytes = self
            .read_capped(response, MAX_MANIFEST_BYTES, "manifest")
            .await?;
        // A digest reference pins the manifest itself; verify it.
        if let Some(expected) = reference.strip_prefix("sha256:") {
            verify_digest(&format!("sha256:{expected}"), &bytes)?;
        }
        let digest = digest.unwrap_or_else(|| format!("sha256:{}", sha256_hex(&bytes)));
        Ok(Manifest { bytes, digest })
    }
}

fn urlencode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// `Bearer realm="…",service="…"` — the challenge a v2 registry sends.
fn parse_bearer_challenge(challenge: &str) -> Result<(String, String), String> {
    let challenge = challenge.trim().strip_prefix("Bearer").unwrap_or(challenge);
    let mut realm = None;
    let mut service = String::new();
    for part in challenge.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "realm" => realm = Some(value.to_string()),
            "service" => service = value.to_string(),
            _ => {}
        }
    }
    Ok((
        realm.ok_or_else(|| "auth challenge names no realm".to_string())?,
        service,
    ))
}

fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// The file suffix that tells extraction which decompressor to use.
fn layer_suffix(media_type: &str) -> Option<&'static str> {
    match media_type {
        "application/vnd.oci.image.layer.v1.tar+gzip"
        | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Some(".tar.gz"),
        "application/vnd.oci.image.layer.v1.tar+zstd" => Some(".tar.zst"),
        "application/vnd.oci.image.layer.v1.tar"
        | "application/vnd.docker.image.rootfs.diff.tar" => Some(".tar"),
        _ => None,
    }
}

/// Fetch the manifest (following an index to this host's platform) and every
/// layer, digest-verified, under the size and count budgets.
pub async fn fetch_image_layers<F>(
    http: &reqwest::Client,
    reference: &RegistryRef,
    on_progress: F,
) -> Result<ImageLayers, String>
where
    F: FnMut(String),
{
    let image = fetch_image_layer_files(http, reference, &NEVER_CANCEL, on_progress).await?;
    let layers = image
        .layers
        .iter()
        .map(|(name, path)| {
            std::fs::read(path)
                .map(|bytes| Layer {
                    name: name.clone(),
                    bytes,
                })
                .map_err(|error| format!("cannot read verified layer: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ImageLayers {
        display: image.display,
        digest: image.digest,
        layers,
    })
}

pub async fn fetch_image_layer_files<F: FnMut(String)>(
    http: &reqwest::Client,
    reference: &RegistryRef,
    cancel: &AtomicBool,
    on_progress: F,
) -> Result<ImageLayerFiles, String> {
    tokio::time::timeout(
        Duration::from_secs(20 * 60),
        fetch_image_files_bounded(
            http,
            reference,
            cancel,
            MAX_LAYER_BYTES,
            MAX_TOTAL_LAYER_BYTES,
            on_progress,
        ),
    )
    .await
    .map_err(|_| "image pull exceeded the 20-minute deadline".to_string())?
}

async fn fetch_image_files_bounded<F: FnMut(String)>(
    http: &reqwest::Client,
    reference: &RegistryRef,
    cancel: &AtomicBool,
    max_layer_bytes: u64,
    max_total_bytes: u64,
    mut on_progress: F,
) -> Result<ImageLayerFiles, String> {
    let config = load_docker_config_auth(&reference.registry);
    let mut client = RegistryClient {
        http,
        host: api_host(reference),
        scheme: scheme_for(&reference.registry),
        name: api_name(reference),
        authorization: None,
        cancel,
    };
    client.authenticate(&config).await?;

    on_progress(format!(
        "fetching manifest for {}/{}:{}",
        reference.registry, reference.name, reference.reference
    ));
    let mut manifest = client.fetch_manifest(&reference.reference).await?;
    let mut manifest_json: Value = serde_json::from_slice(&manifest.bytes)
        .map_err(|error| format!("manifest is not JSON: {error}"))?;

    // A manifest list / image index points at platform manifests; pick this
    // machine's (linux, host arch) so the layers match what would run here.
    if manifest_json.get("manifests").is_some() {
        let arch = host_architecture();
        let empty = Vec::new();
        let digest = manifest_json["manifests"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter(|entry| {
                let os = entry.pointer("/platform/os").and_then(Value::as_str);
                let architecture = entry
                    .pointer("/platform/architecture")
                    .and_then(Value::as_str);
                os == Some("linux") && architecture == Some(arch)
            })
            .find_map(|entry| entry.get("digest").and_then(Value::as_str))
            .ok_or_else(|| format!("image index carries no linux/{arch} manifest"))?;
        manifest = client.fetch_manifest(digest).await?;
        manifest_json = serde_json::from_slice(&manifest.bytes)
            .map_err(|error| format!("platform manifest is not JSON: {error}"))?;
    }

    let layers = manifest_json["layers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if layers.is_empty() {
        return Err("manifest lists no layers".into());
    }
    if layers.len() > MAX_LAYERS {
        return Err(format!(
            "resource limit: the image carries {} layers (cap {MAX_LAYERS})",
            layers.len()
        ));
    }
    let total = layers.iter().try_fold(0u64, |total, layer| {
        total
            .checked_add(layer.get("size").and_then(Value::as_u64).unwrap_or(0))
            .ok_or_else(|| "resource limit: declared image byte count overflow".to_string())
    })?;
    if total > max_total_bytes {
        return Err(format!(
            "resource limit: the image's layers total {total} bytes (cap {max_total_bytes})"
        ));
    }

    let digest12 = manifest
        .digest
        .strip_prefix("sha256:")
        .map(|hex| hex[..12.min(hex.len())].to_string())
        .unwrap_or_else(|| "unknown".into());
    let display = format!(
        "{}/{}:{}@{digest12}",
        reference.registry, reference.name, reference.reference
    );

    let directory = tempfile::Builder::new()
        .prefix("oxaudit-image-")
        .tempdir()
        .map_err(|error| format!("cannot prepare private image spool: {error}"))?;
    let mut downloaded = Vec::new();
    let mut receipts = Vec::new();
    let mut actual_total = 0u64;
    for (index, layer) in layers.iter().enumerate() {
        let media_type = layer
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(suffix) = layer_suffix(media_type) else {
            return Err(format!(
                "layer {index} has unsupported media type {media_type:?}; nothing is scanned partially"
            ));
        };
        let digest = layer
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("layer {index} carries no digest"))?;
        let size = layer.get("size").and_then(Value::as_u64).unwrap_or(0);
        if size > max_layer_bytes {
            return Err(format!(
                "resource limit: layer {index} is {size} bytes (cap {max_layer_bytes})"
            ));
        }
        on_progress(format!(
            "downloading layer {}/{} ({} MiB)",
            index + 1,
            layers.len(),
            size / (1024 * 1024)
        ));
        let url = client.url(&format!("/blobs/{digest}"));
        let response = client
            .fetch_limited(
                &url,
                None,
                max_layer_bytes.min(max_total_bytes.saturating_sub(actual_total)),
            )
            .await
            .map_err(|error| format!("layer {index}: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "layer {index}: registry answered {} for {url}",
                response.status()
            ));
        }
        let name = format!("layer-{index:04}{suffix}");
        let path = directory.path().join(&name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|error| format!("cannot spool layer {index}: {error}"))?;
        use sha2::Digest;
        use std::io::Write;
        let mut hasher = sha2::Sha256::new();
        let allowance = max_layer_bytes.min(max_total_bytes.saturating_sub(actual_total));
        let mut actual = 0u64;
        let mut response = response;
        while let Some(chunk) = registry_wait(cancel, response.chunk())
            .await?
            .map_err(|error| format!("registry download failed for layer {index}: {error}"))?
        {
            actual = actual
                .checked_add(chunk.len() as u64)
                .ok_or("resource limit: actual layer byte count overflow")?;
            if actual > allowance {
                return Err(format!("resource limit: actual downloaded layer {index} bytes exceed the remaining image allowance ({allowance} bytes)"));
            }
            file.write_all(&chunk)
                .map_err(|error| format!("cannot spool layer {index}: {error}"))?;
            hasher.update(&chunk);
        }
        file.flush()
            .map_err(|error| format!("cannot flush layer {index}: {error}"))?;
        let actual_digest = format!("sha256:{:x}", hasher.finalize());
        if !digest.eq_ignore_ascii_case(&actual_digest) {
            return Err(format!("layer {index}: blob digest mismatch: manifest says {digest}, registry served {actual_digest}"));
        }
        actual_total = actual_total
            .checked_add(actual)
            .ok_or("resource limit: actual image byte count overflow")?;
        receipts.push(LayerReceipt {
            name: name.clone(),
            digest: digest.into(),
            size_bytes: actual,
            media_type: media_type.into(),
        });
        downloaded.push((name, path));
    }

    if cancel.load(Ordering::SeqCst) {
        return Err("image scan cancelled".into());
    }
    Ok(ImageLayerFiles {
        display,
        digest: manifest.digest,
        layers: downloaded,
        receipts,
        _directory: directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_that_name_registries_parse() {
        let parsed = parse_ref("registry-1.docker.io/library/nginx:1.25").unwrap();
        assert_eq!(parsed.registry, "registry-1.docker.io");
        assert_eq!(parsed.name, "library/nginx");
        assert_eq!(parsed.reference, "1.25");

        let parsed = parse_ref("localhost:5000/app").unwrap();
        assert_eq!(parsed.registry, "localhost:5000");
        assert_eq!(parsed.name, "app");
        assert_eq!(parsed.reference, "latest");

        let parsed = parse_ref("ghcr.io/owner/tool@sha256:0123abcd").unwrap();
        assert_eq!(parsed.reference, "sha256:0123abcd");

        let parsed = parse_ref("example.com:8443/team/api:v2.1.0").unwrap();
        assert_eq!(parsed.reference, "v2.1.0");
    }

    #[test]
    fn local_paths_are_not_registry_references() {
        for path in [
            "saved-image.tar",
            "./image.tar",
            "/tmp/image.tar",
            "ubuntu",
            "src/main.rs",
        ] {
            assert!(parse_ref(path).is_none(), "{path}");
        }
    }

    #[test]
    fn hub_references_normalize_to_the_api_host_and_library_namespace() {
        let reference = RegistryRef {
            registry: "docker.io".into(),
            name: "nginx".into(),
            reference: "1.25".into(),
        };
        assert_eq!(api_host(&reference), "registry-1.docker.io");
        assert_eq!(api_name(&reference), "library/nginx");
        // An explicit namespace survives; other registries are untouched.
        let reference = RegistryRef {
            registry: "ghcr.io".into(),
            name: "owner/tool".into(),
            reference: "latest".into(),
        };
        assert_eq!(api_host(&reference), "ghcr.io");
        assert_eq!(api_name(&reference), "owner/tool");
    }

    #[test]
    fn localhost_registries_use_plain_http() {
        assert_eq!(scheme_for("localhost:5000"), "http");
        assert_eq!(scheme_for("127.0.0.1:5000"), "http");
        assert_eq!(scheme_for("ghcr.io"), "https");
    }

    #[test]
    fn bearer_challenges_parse_with_and_without_service() {
        let (realm, service) =
            parse_bearer_challenge("Bearer realm=\"https://auth.example/token\",service=\"reg\"")
                .unwrap();
        assert_eq!(realm, "https://auth.example/token");
        assert_eq!(service, "reg");
        let (realm, _) =
            parse_bearer_challenge("Bearer realm=\"https://auth.example/token\"").unwrap();
        assert_eq!(realm, "https://auth.example/token");
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_err());
    }

    #[test]
    fn layer_media_types_map_to_decompression_suffixes() {
        assert_eq!(
            layer_suffix("application/vnd.oci.image.layer.v1.tar+gzip"),
            Some(".tar.gz")
        );
        assert_eq!(
            layer_suffix("application/vnd.docker.image.rootfs.diff.tar.gzip"),
            Some(".tar.gz")
        );
        assert_eq!(
            layer_suffix("application/vnd.oci.image.layer.v1.tar+zstd"),
            Some(".tar.zst")
        );
        assert_eq!(
            layer_suffix("application/vnd.oci.image.layer.v1.tar"),
            Some(".tar")
        );
        assert_eq!(layer_suffix("application/x-unknown"), None);
    }

    #[test]
    fn digests_verify_and_mismatches_fail_loudly() {
        let bytes = b"layer bytes";
        verify_digest(&format!("sha256:{}", sha256_hex(bytes)), bytes).unwrap();
        let error = verify_digest("sha256:0000000000000000000000000000000000000000", bytes)
            .expect_err("mismatch");
        assert!(error.contains("mismatch"), "{error}");
        assert!(verify_digest("blake3:xyz", bytes).is_err());
    }

    #[test]
    fn docker_config_matching_covers_hub_aliases_and_identity_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.json");
        std::fs::write(
            &config,
            serde_json::json!({
                "auths": {
                    "https://index.docker.io/v1/": { "identitytoken": "dockertoken" },
                    "registry.example.com": { "auth": "dXNlcjpwYXNz" }
                }
            })
            .to_string(),
        )
        .unwrap();
        // SAFETY: tests run single-threaded per process; restore after.
        let guard = EnvGuard::set("DOCKER_CONFIG", directory.path());
        let auth = load_docker_config_auth("registry-1.docker.io");
        assert_eq!(auth.identity_token.as_deref(), Some("dockertoken"));
        let auth = load_docker_config_auth("registry.example.com");
        assert_eq!(auth.basic.as_deref(), Some("dXNlcjpwYXNz"));
        let auth = load_docker_config_auth("ghcr.io");
        assert_eq!(auth, DockerConfigAuth::default());
        drop(guard);
    }

    /// Set an environment variable for the duration of a test and restore the
    /// previous value afterwards. The registry tests that touch the
    /// environment run single-threaded per process.
    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    enum RegistryReply {
        Body(Vec<u8>),
        Chunked(Vec<u8>),
        StallHeaders(std::sync::Arc<tokio::sync::Notify>),
        StallBody(std::sync::Arc<tokio::sync::Notify>),
    }

    struct LocalRegistry {
        reference: RegistryRef,
        requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for LocalRegistry {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn local_registry(replies: Vec<(String, RegistryReply)>) -> LocalRegistry {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let task = tokio::spawn(async move {
            for (expected_path, reply) in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0 && request.len() + read <= 64 * 1024);
                    request.extend_from_slice(&chunk[..read]);
                }
                let line = std::str::from_utf8(&request)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_owned();
                recorded.lock().unwrap().push(path.clone());
                assert_eq!(path, expected_path);
                match reply {
                    RegistryReply::Body(body) => {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(header.as_bytes()).await.unwrap();
                        stream.write_all(&body).await.unwrap();
                    }
                    RegistryReply::Chunked(body) => {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                        stream
                            .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                            .await
                            .unwrap();
                        stream.write_all(&body).await.unwrap();
                        stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
                    }
                    RegistryReply::StallHeaders(ready) => {
                        ready.notify_one();
                        std::future::pending::<()>().await;
                    }
                    RegistryReply::StallBody(ready) => {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n").await.unwrap();
                        ready.notify_one();
                        std::future::pending::<()>().await;
                    }
                }
            }
        });
        LocalRegistry {
            reference: RegistryRef {
                registry: address.to_string(),
                name: "app".into(),
                reference: "latest".into(),
            },
            requests,
            task,
        }
    }

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn local_manifest(sizes: &[u64]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "layers": sizes.iter().map(|size| serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": ABC_DIGEST,
                "size": size,
            })).collect::<Vec<_>>()
        }))
        .unwrap()
    }

    fn manifest_replies(sizes: &[u64]) -> Vec<(String, RegistryReply)> {
        vec![
            ("/v2/".into(), RegistryReply::Body(Vec::new())),
            (
                "/v2/app/manifests/latest".into(),
                RegistryReply::Body(local_manifest(sizes)),
            ),
        ]
    }

    async fn assert_stalled_pull_cancels(server: &LocalRegistry, ready: &tokio::sync::Notify) {
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let cancel = AtomicBool::new(false);
        let pull = fetch_image_files_bounded(&http, &server.reference, &cancel, 32, 64, |_| {});
        tokio::pin!(pull);
        tokio::select! {
            _ = ready.notified() => {},
            result = &mut pull => panic!("fixture pull finished before reaching the stalled response: {}", result.err().unwrap_or_default()),
            _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("pull did not reach the stalled response"),
        }
        cancel.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_millis(500), &mut pull)
            .await
            .expect("cancellation must interrupt the stalled registry request within 500 ms");
        let error = result.err().expect("cancelled pull must not succeed");
        assert!(error.contains("cancelled"), "{error}");
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_stalled_manifest_response() {
        let ready = std::sync::Arc::new(tokio::sync::Notify::new());
        let server = local_registry(vec![
            ("/v2/".into(), RegistryReply::Body(Vec::new())),
            (
                "/v2/app/manifests/latest".into(),
                RegistryReply::StallHeaders(ready.clone()),
            ),
        ])
        .await;
        assert_stalled_pull_cancels(&server, &ready).await;
        assert_eq!(server.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_stalled_layer_body() {
        let ready = std::sync::Arc::new(tokio::sync::Notify::new());
        let mut replies = manifest_replies(&[3]);
        replies.push((
            format!("/v2/app/blobs/{ABC_DIGEST}"),
            RegistryReply::StallBody(ready.clone()),
        ));
        let server = local_registry(replies).await;
        assert_stalled_pull_cancels(&server, &ready).await;
        assert_eq!(server.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn understated_declared_layer_sizes_cannot_bypass_the_actual_image_budget() {
        let mut replies = manifest_replies(&[1, 1]);
        for _ in 0..2 {
            replies.push((
                format!("/v2/app/blobs/{ABC_DIGEST}"),
                RegistryReply::Chunked(b"abc".to_vec()),
            ));
        }
        let server = local_registry(replies).await;
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let result = fetch_image_files_bounded(
            &http,
            &server.reference,
            &AtomicBool::new(false),
            4,
            5,
            |_| {},
        )
        .await;
        let error = result
            .err()
            .expect("two three-byte bodies exceed a five-byte actual aggregate cap");
        assert!(
            error.contains("actual downloaded layer 1") && error.contains("2 bytes"),
            "{error}"
        );
        assert_eq!(server.requests.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn an_understated_chunked_layer_stops_at_the_actual_member_limit() {
        let mut replies = manifest_replies(&[0]);
        replies.push((
            format!("/v2/app/blobs/{ABC_DIGEST}"),
            RegistryReply::Chunked(b"abc".to_vec()),
        ));
        let server = local_registry(replies).await;
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let result = fetch_image_files_bounded(
            &http,
            &server.reference,
            &AtomicBool::new(false),
            2,
            64,
            |_| {},
        )
        .await;
        let error = result
            .err()
            .expect("three actual bytes exceed the two-byte layer limit");
        assert!(
            error.contains("actual downloaded layer 0") && error.contains("2 bytes"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn declared_layer_size_overflow_stops_before_requesting_any_blob() {
        let server = local_registry(manifest_replies(&[u64::MAX, 1])).await;
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let result = fetch_image_files_bounded(
            &http,
            &server.reference,
            &AtomicBool::new(false),
            u64::MAX,
            u64::MAX,
            |_| {},
        )
        .await;
        let error = result
            .err()
            .expect("overflowed advertised totals cannot wrap to a small image");
        assert!(error.contains("overflow"), "{error}");
        assert_eq!(server.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn verified_layer_spools_keep_digest_bytes_permissions_and_owned_cleanup() {
        let mut replies = manifest_replies(&[1]);
        replies.push((
            format!("/v2/app/blobs/{ABC_DIGEST}"),
            RegistryReply::Chunked(b"abc".to_vec()),
        ));
        let server = local_registry(replies).await;
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let image = fetch_image_files_bounded(
            &http,
            &server.reference,
            &AtomicBool::new(false),
            4,
            64,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(image.layers[0].0, "layer-0000.tar");
        assert_eq!(std::fs::read(&image.layers[0].1).unwrap(), b"abc");
        assert_eq!(image.receipts[0].digest, ABC_DIGEST);
        assert_eq!(image.receipts[0].size_bytes, 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&image.layers[0].1)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let directory = image.layers[0].1.parent().unwrap().to_path_buf();
        assert!(directory.is_dir());
        drop(image);
        assert!(
            !directory.exists(),
            "the layer owner must clean its private spool after use"
        );
    }
}
