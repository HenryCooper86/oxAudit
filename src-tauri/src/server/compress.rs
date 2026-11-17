//! Gzip for the server's own responses: the GUI's static assets and the
//! JSON envelopes of `/api/invoke`.
//!
//! The headless server exists so a browser on another machine can be the
//! workbench, and over a network the uncompressed GUI is about a megabyte
//! and a page of findings is mostly repeated JSON keys. Both compress to a
//! fraction. The event stream is never compressed: its frames must reach
//! the browser as they are written.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use axum::http::{header, HeaderMap, HeaderValue};

/// Below this a response costs more to compress than it saves.
pub const MIN_COMPRESS_BYTES: usize = 1024;
/// Compressed assets kept in memory, and the most they may hold together.
const MAX_CACHED_ASSETS: usize = 256;
const MAX_CACHED_BYTES: usize = 32 * 1024 * 1024;

/// Whether the request accepts gzip: a `gzip` (or `*`) coding that is not
/// refused with `q=0`.
pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| {
            let mut parts = coding.split(';').map(str::trim);
            let name = parts.next().unwrap_or("");
            let refused = parts.any(|parameter| {
                parameter
                    .strip_prefix("q=")
                    .and_then(|quality| quality.trim().parse::<f32>().ok())
                    .is_some_and(|quality| quality <= 0.0)
            });
            (name.eq_ignore_ascii_case("gzip") || name == "*") && !refused
        })
}

/// Whether a media type is worth compressing. Images and fonts in the GUI
/// are already compressed formats.
pub fn compressible(media_type: &str) -> bool {
    let media_type = media_type.to_ascii_lowercase();
    media_type.starts_with("text/")
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
        || matches!(
            media_type.as_str(),
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "application/wasm"
                | "application/manifest+json"
        )
}

/// Gzip `bytes`. `None` when compression fails or does not make the body
/// smaller, in which case the caller sends the body as it is.
pub fn gzip(bytes: &[u8], level: u32) -> Option<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(
        Vec::with_capacity(bytes.len() / 3),
        flate2::Compression::new(level),
    );
    encoder.write_all(bytes).ok()?;
    let compressed = encoder.finish().ok()?;
    (compressed.len() < bytes.len()).then_some(compressed)
}

/// Mark a response as gzip-encoded and varying by the request's codings.
pub fn mark_gzip(headers: &mut HeaderMap) {
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    mark_vary(headers);
}

/// A response that would have been compressed for another client still
/// varies by `Accept-Encoding`, so a cache does not hand gzip to a client
/// that refused it.
pub fn mark_vary(headers: &mut HeaderMap) {
    headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
}

struct CachedAsset {
    modified: Option<SystemTime>,
    length: u64,
    compressed: Arc<Vec<u8>>,
}

fn asset_cache() -> &'static Mutex<HashMap<PathBuf, CachedAsset>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedAsset>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// The gzip form of a static asset, compressed once and reused while the
/// file's size and modification time are unchanged. `None` when the asset
/// does not shrink.
pub fn gzip_asset(path: &Path, bytes: &[u8]) -> Option<Arc<Vec<u8>>> {
    let metadata = std::fs::metadata(path).ok();
    let modified = metadata
        .as_ref()
        .and_then(|metadata| metadata.modified().ok());
    let length = bytes.len() as u64;
    if let Ok(cache) = asset_cache().lock() {
        if let Some(cached) = cache.get(path) {
            if cached.modified == modified && cached.length == length {
                return Some(cached.compressed.clone());
            }
        }
    }
    // Assets are compressed once, so the best ratio is worth its time.
    let compressed = Arc::new(gzip(bytes, 9)?);
    if let Ok(mut cache) = asset_cache().lock() {
        cache.remove(path);
        let held: usize = cache.values().map(|asset| asset.compressed.len()).sum();
        if cache.len() < MAX_CACHED_ASSETS && held + compressed.len() <= MAX_CACHED_BYTES {
            cache.insert(
                path.to_path_buf(),
                CachedAsset {
                    modified,
                    length,
                    compressed: compressed.clone(),
                },
            );
        }
    }
    Some(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_ENCODING, value.parse().unwrap());
        headers
    }

    #[test]
    fn gzip_is_used_only_when_the_client_accepts_it() {
        assert!(accepts_gzip(&headers("gzip, deflate, br")));
        assert!(accepts_gzip(&headers("br;q=1.0, GZIP;q=0.8")));
        assert!(accepts_gzip(&headers("*")));
        assert!(!accepts_gzip(&headers("br, deflate")));
        assert!(!accepts_gzip(&headers("gzip;q=0, br")));
        assert!(!accepts_gzip(&headers("gzip;q=0.0")));
        assert!(!accepts_gzip(&headers("identity")));
        assert!(!accepts_gzip(&HeaderMap::new()));
    }

    #[test]
    fn only_text_like_media_types_are_compressed() {
        for kind in [
            "text/html",
            "text/javascript",
            "application/json",
            "image/svg+xml",
            "application/wasm",
            "Text/CSS",
        ] {
            assert!(compressible(kind), "{kind}");
        }
        for kind in [
            "image/png",
            "font/woff2",
            "application/octet-stream",
            "image/x-icon",
        ] {
            assert!(!compressible(kind), "{kind}");
        }
    }

    #[test]
    fn gzip_round_trips_and_declines_when_it_does_not_shrink() {
        let body = br#"{"filePath":"src/a.js","ruleId":"js-eval"}"#.repeat(200);
        let compressed = gzip(&body, 1).expect("repetitive JSON shrinks");
        assert!(compressed.len() < body.len() / 5);
        let mut restored = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut restored)
            .unwrap();
        assert_eq!(restored, body);
        // Bytes with no pattern do not shrink; the caller sends them as they are.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let dense: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        assert!(gzip(&dense, 9).is_none());
        assert!(gzip(b"", 9).is_none());
    }

    #[test]
    fn a_cached_asset_is_recompressed_when_the_file_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.js");
        let first = b"console.log('one');\n".repeat(200);
        std::fs::write(&path, &first).unwrap();
        let once = gzip_asset(&path, &first).unwrap();
        let again = gzip_asset(&path, &first).unwrap();
        assert!(
            Arc::ptr_eq(&once, &again),
            "an unchanged file is served from the cache"
        );

        let second = b"console.log('two, and longer');\n".repeat(200);
        std::fs::write(&path, &second).unwrap();
        let changed = gzip_asset(&path, &second).unwrap();
        assert!(!Arc::ptr_eq(&once, &changed));
        let mut restored = Vec::new();
        flate2::read::GzDecoder::new(&changed[..])
            .read_to_end(&mut restored)
            .unwrap();
        assert_eq!(restored, second);
    }
}
