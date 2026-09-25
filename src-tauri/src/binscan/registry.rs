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
        let response = request
            .send()
            .await
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
        while let Some(chunk) = stream
            .chunk()
            .await
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
        let response = request
            .send()
            .await
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
        let response = request
            .send()
            .await
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
    mut on_progress: F,
) -> Result<ImageLayers, String>
where
    F: FnMut(String),
{
    let config = load_docker_config_auth(&reference.registry);
    let mut client = RegistryClient {
        http,
        host: api_host(reference),
        scheme: scheme_for(&reference.registry),
        name: api_name(reference),
        authorization: None,
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
    let total: u64 = layers
        .iter()
        .filter_map(|layer| layer.get("size").and_then(Value::as_u64))
        .sum();
    if total > MAX_TOTAL_LAYER_BYTES {
        return Err(format!(
            "resource limit: the image's layers total {total} bytes (cap {MAX_TOTAL_LAYER_BYTES})"
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

    let mut downloaded = Vec::new();
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
        if size > MAX_LAYER_BYTES {
            return Err(format!(
                "resource limit: layer {index} is {size} bytes (cap {MAX_LAYER_BYTES})"
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
            .fetch_limited(&url, None, MAX_LAYER_BYTES)
            .await
            .map_err(|error| format!("layer {index}: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "layer {index}: registry answered {} for {url}",
                response.status()
            ));
        }
        let bytes = client
            .read_capped(response, MAX_LAYER_BYTES, &format!("layer {index}"))
            .await?;
        verify_digest(digest, &bytes).map_err(|error| format!("layer {index}: {error}"))?;
        downloaded.push(Layer {
            name: format!("layer-{index:04}{suffix}"),
            bytes,
        });
    }

    Ok(ImageLayers {
        display,
        digest: manifest.digest,
        layers: downloaded,
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
}
