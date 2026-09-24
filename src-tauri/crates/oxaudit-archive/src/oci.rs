//! On-disk OCI image layouts: `oci-layout`, `index.json`, and content-addressed
//! blobs — the form a container image takes when it is unpacked beside
//! source instead of saved as one tarball.
//!
//! Reading the layout turns a folder of opaque `blobs/sha256/<hash>` files
//! into ordered image layers with names a human can read in a finding:
//! members surface as `image@<manifest12>!layer-0003!/bin/busybox` instead
//! of a 64-character hash. Every blob's digest is verified against its name
//! before it is treated as a layer — a renamed or truncated blob is skipped
//! with its reason, never scanned under a digest it does not have.
//!
//! Bounds mirror the extractor's posture: index and manifest documents are
//! tiny (64 KiB / 256 KiB), manifest and layer counts are capped, digests
//! are strictly `sha256:` + 64 hex so a digest can never walk out of
//! `blobs/`, and nothing outside the layout root is touched.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MAX_INDEX_BYTES: u64 = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_MANIFEST_ENTRIES: usize = 8;
const MAX_LAYERS_PER_IMAGE: usize = 64;
const MAX_TOTAL_LAYERS: usize = 128;

/// One layer of one image, resolved to its blob and given its display alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayer {
    /// The blob file, already verified to match `digest`.
    pub blob_path: PathBuf,
    pub digest: String,
    /// The virtual name members of this layer carry, e.g.
    /// `service@1a2b3c4d5e6f!layer-0003`.
    pub alias: String,
}

/// One image manifest and its ordered layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciImage {
    pub digest: String,
    pub layers: Vec<OciLayer>,
}

/// A recognized layout: the root directory and the images it indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayout {
    pub root: PathBuf,
    pub images: Vec<OciImage>,
    /// Why individual blobs were skipped: digest mismatches and budget
    /// stops, surfaced rather than silently narrowing the image.
    pub notes: Vec<String>,
}

/// A directory is an OCI layout when it carries both markers. Anything else
/// is just a folder that happens to contain blobs.
pub fn is_layout(root: &Path) -> bool {
    root.join("oci-layout").is_file() && root.join("index.json").is_file()
}

pub fn read_layout(root: &Path) -> Result<OciLayout, String> {
    let index_path = root.join("index.json");
    let index_bytes = read_bounded(&index_path, MAX_INDEX_BYTES)
        .map_err(|error| format!("cannot read the layout index: {error}"))?;
    let index: serde_json::Value = serde_json::from_slice(&index_bytes)
        .map_err(|error| format!("the layout index is not valid JSON: {error}"))?;
    let entries = index
        .get("manifests")
        .and_then(|manifests| manifests.as_array())
        .ok_or_else(|| "the layout index lists no manifests".to_string())?;
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(format!(
            "the layout indexes more than {MAX_MANIFEST_ENTRIES} manifests"
        ));
    }

    let mut notes = Vec::new();
    let mut images = Vec::new();
    let mut total_layers = 0usize;
    let mut seen_blobs = BTreeSet::new();

    // Manifest entries expand one level: an image index (manifest list)
    // resolves to the image manifests it selects.
    let mut manifest_digests: Vec<String> = Vec::new();
    for entry in entries {
        let Some(digest) = entry_digest(entry)? else {
            continue;
        };
        let media_type = entry
            .get("mediaType")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if media_type.contains("index") || media_type.contains("manifest.list") {
            let blob = root.join("blobs").join(&digest);
            let bytes = read_bounded(&blob, MAX_MANIFEST_BYTES)
                .map_err(|error| format!("cannot read the image index {digest}: {error}"))?;
            let nested: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("the image index {digest} is not valid JSON: {error}"))?;
            let nested_entries = nested
                .get("manifests")
                .and_then(|manifests| manifests.as_array())
                .ok_or_else(|| format!("the image index {digest} lists no manifests"))?;
            if nested_entries.len() > MAX_MANIFEST_ENTRIES {
                return Err(format!(
                    "the image index {digest} lists more than {MAX_MANIFEST_ENTRIES} manifests"
                ));
            }
            for nested_entry in nested_entries {
                if let Some(nested_digest) = entry_digest(nested_entry)? {
                    manifest_digests.push(nested_digest);
                }
            }
        } else {
            manifest_digests.push(digest);
        }
    }
    if manifest_digests.is_empty() {
        return Err("the layout indexes no image manifests".into());
    }
    if manifest_digests.len() > MAX_MANIFEST_ENTRIES * 2 {
        return Err(format!(
            "the layout resolves to more than {} image manifests",
            MAX_MANIFEST_ENTRIES * 2
        ));
    }

    let image_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("oci-image");

    for manifest_digest in manifest_digests {
        let blob = root.join("blobs").join(&manifest_digest);
        let bytes = match read_bounded(&blob, MAX_MANIFEST_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                notes.push(format!("manifest {manifest_digest} skipped: {error}"));
                continue;
            }
        };
        let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(error) => {
                notes.push(format!(
                    "manifest {manifest_digest} skipped: not valid JSON: {error}"
                ));
                continue;
            }
        };
        let mut layers = Vec::new();
        let empty: Vec<serde_json::Value> = Vec::new();
        let layer_entries = manifest
            .get("layers")
            .and_then(|layers| layers.as_array())
            .unwrap_or(&empty);
        for (position, layer) in layer_entries.iter().enumerate() {
            if position >= MAX_LAYERS_PER_IMAGE {
                notes.push(format!(
                    "manifest {manifest_digest} stopped at {MAX_LAYERS_PER_IMAGE} layers"
                ));
                break;
            }
            if total_layers >= MAX_TOTAL_LAYERS {
                notes.push(format!("layout stopped at {MAX_TOTAL_LAYERS} total layers"));
                break;
            }
            let Some(digest) = layer
                .get("digest")
                .and_then(|value| value.as_str())
                .and_then(parse_digest)
            else {
                notes.push(format!(
                    "manifest {manifest_digest} has a layer without a valid sha256 digest"
                ));
                continue;
            };
            if !seen_blobs.insert(digest.clone()) {
                continue;
            }
            let blob_path = root.join("blobs").join(&digest);
            match verify_blob(&blob_path, &digest) {
                Ok(()) => {
                    total_layers += 1;
                    layers.push(OciLayer {
                        blob_path,
                        alias: format!(
                            "{image_name}@{}!layer-{:04}",
                            &manifest_digest[7..19],
                            position
                        ),
                        digest,
                    });
                }
                Err(error) => notes.push(format!("layer {digest} skipped: {error}")),
            }
        }
        images.push(OciImage {
            digest: manifest_digest,
            layers,
        });
    }

    if images.iter().all(|image| image.layers.is_empty()) {
        return Err("the layout contains no verifiable layers".into());
    }
    Ok(OciLayout {
        root: root.to_path_buf(),
        images,
        notes,
    })
}

/// `sha256:<64 hex>` → the `sha256/<64 hex>` relative blob path, or None for
/// anything a digest must never be.
fn entry_digest(entry: &serde_json::Value) -> Result<Option<String>, String> {
    let Some(digest) = entry
        .get("digest")
        .and_then(|value| value.as_str())
        .and_then(parse_digest)
    else {
        return Ok(None);
    };
    Ok(Some(digest))
}

fn parse_digest(value: &str) -> Option<String> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(format!("sha256/{hex}"))
    } else {
        None
    }
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.len() > limit {
        return Err(format!(
            "{} is {} bytes, over the {}-byte limit",
            path.display(),
            metadata.len(),
            limit
        ));
    }
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// A blob qualifies as its digest only when its content hashes to the name
/// it sits under.
fn verify_blob(path: &Path, digest: &str) -> Result<(), String> {
    let expected = digest.rsplit('/').next().unwrap_or_default();
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    use std::io::Read;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err(format!(
            "content hashes to {actual}, not the {expected} it is named for"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// A minimal but real layout: one manifest, two tar layers, every digest
    /// computed from actual content.
    fn write_layout(root: &Path) {
        let layer = |content: &[u8]| {
            let mut tar_bytes = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut tar_bytes);
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                builder
                    .append_data(&mut header, "bin/tool", std::io::Cursor::new(content))
                    .unwrap();
                builder.finish().unwrap();
            }
            tar_bytes
        };
        let first = layer(b"first-layer");
        let second = layer(b"second-layer");

        std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        let write_blob = |bytes: &[u8]| -> String {
            let digest = sha256_hex(bytes);
            std::fs::write(root.join(format!("blobs/sha256/{digest}")), bytes).unwrap();
            digest
        };

        let first_digest = write_blob(&first);
        let second_digest = write_blob(&second);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{first_digest}"}},{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{second_digest}"}}]}}"#
        );
        let manifest_digest = write_blob(manifest.as_bytes());
        std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        std::fs::write(
            root.join("index.json"),
            format!(
                r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{manifest_digest}"}}]}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn a_real_layout_resolves_to_ordered_verified_layers() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("service-image");
        std::fs::create_dir_all(&root).unwrap();
        write_layout(&root);

        assert!(is_layout(&root));
        let layout = read_layout(&root).expect("layout reads");
        assert_eq!(layout.images.len(), 1);
        let image = &layout.images[0];
        assert_eq!(image.layers.len(), 2);
        // Order and naming: layer-0000 before layer-0001, under the image.
        assert!(image.layers[0].alias.starts_with("service-image@"));
        assert!(image.layers[0].alias.ends_with("!layer-0000"));
        assert!(image.layers[1].alias.ends_with("!layer-0001"));
        assert!(image.layers[0].blob_path.is_file());
        assert!(layout.notes.is_empty());
    }

    #[test]
    fn a_blob_that_does_not_hash_to_its_name_is_skipped_with_its_reason() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("liar");
        std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        let tampered = b"not the content the digest claims";
        let honest_digest = sha256_hex(tampered);
        // Named after one digest, containing another's bytes.
        let wrong_name = format!("{}ff", &honest_digest[..63]);
        std::fs::write(root.join(format!("blobs/sha256/{wrong_name}")), tampered).unwrap();
        let manifest =
            format!(r#"{{"schemaVersion":2,"layers":[{{"digest":"sha256:{wrong_name}"}}]}}"#);
        let manifest_digest = sha256_hex(manifest.as_bytes());
        std::fs::write(
            root.join(format!("blobs/sha256/{manifest_digest}")),
            &manifest,
        )
        .unwrap();
        std::fs::write(root.join("oci-layout"), "{}").unwrap();
        std::fs::write(
            root.join("index.json"),
            format!(r#"{{"manifests":[{{"digest":"sha256:{manifest_digest}"}}]}}"#),
        )
        .unwrap();

        let error = read_layout(&root).expect_err("no verifiable layers");
        assert!(error.contains("no verifiable layers"));
    }

    #[test]
    fn a_digest_that_tries_to_walk_out_of_blobs_is_rejected() {
        assert!(parse_digest("sha256:../../etc/passwd").is_none());
        assert!(parse_digest("sha256:abc").is_none());
        assert!(parse_digest(
            "md5:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_none());
        assert!(parse_digest(&format!("sha256:{}", "a".repeat(64))).is_some());
    }

    #[test]
    fn an_index_can_nest_one_level_through_an_image_index() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("nested");
        std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_cksum();
            builder
                .append_data(&mut header, "bin/tool", std::io::Cursor::new(b"data"))
                .unwrap();
            builder.finish().unwrap();
        }
        let layer_digest = sha256_hex(&tar_bytes);
        std::fs::write(
            root.join(format!("blobs/sha256/{layer_digest}")),
            &tar_bytes,
        )
        .unwrap();
        let manifest =
            format!(r#"{{"schemaVersion":2,"layers":[{{"digest":"sha256:{layer_digest}"}}]}}"#);
        let manifest_digest = sha256_hex(manifest.as_bytes());
        std::fs::write(
            root.join(format!("blobs/sha256/{manifest_digest}")),
            &manifest,
        )
        .unwrap();
        let image_index = format!(
            r#"{{"manifests":[{{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:{manifest_digest}"}}]}}"#
        );
        let index_digest = sha256_hex(image_index.as_bytes());
        std::fs::write(
            root.join(format!("blobs/sha256/{index_digest}")),
            &image_index,
        )
        .unwrap();
        std::fs::write(root.join("oci-layout"), "{}").unwrap();
        std::fs::write(
            root.join("index.json"),
            format!(r#"{{"manifests":[{{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:{index_digest}"}}]}}"#),
        )
        .unwrap();

        let layout = read_layout(&root).expect("nested layout reads");
        assert_eq!(layout.images.len(), 1);
        assert_eq!(layout.images[0].layers.len(), 1);
    }

    #[test]
    fn a_directory_without_both_markers_is_not_a_layout() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!is_layout(directory.path()));
        std::fs::write(directory.path().join("index.json"), "{}").unwrap();
        assert!(!is_layout(directory.path()));
    }
}
