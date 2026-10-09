//! Bounded content identities observed before a local image scan.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const HASH_BYTE_LIMIT: u64 = 128 * 1024 * 1024;
const INDEX_BYTE_LIMIT: u64 = 64 * 1024;
const MANIFEST_BYTE_LIMIT: u64 = 256 * 1024;
const ROOT_ENTRY_LIMIT: usize = 8;
const MANIFEST_LIMIT: usize = 16;
const LAYERS_PER_IMAGE: usize = 64;
const LAYER_LIMIT: usize = 128;
const SNAPSHOT_NOTE: &str = "Identity was observed before native scanning; a mutable local path may change afterward. These hashes do not prove that later scanned bytes remained identical.";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalImageEvidence {
    pub kind: String,
    pub complete: bool,
    pub hash_byte_limit: u64,
    pub file: Option<LocalFileEvidence>,
    pub oci: Option<LocalOciEvidence>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalFileEvidence {
    pub size_bytes: u64,
    pub size_source: String,
    pub bytes_hashed: u64,
    pub sha256: Option<String>,
    pub prefix_sha256: Option<String>,
    pub changed_during_read: Option<bool>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalOciEvidence {
    pub index_sha256: Option<String>,
    pub indexes: Vec<LocalDescriptorEvidence>,
    pub manifests: Vec<LocalManifestEvidence>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalDescriptorEvidence {
    pub digest: String,
    pub declared_size: Option<u64>,
    pub observed_size: Option<u64>,
    pub actual_sha256: Option<String>,
    pub prefix_sha256: Option<String>,
    pub bytes_hashed: u64,
    pub verified: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalManifestEvidence {
    pub descriptor: LocalDescriptorEvidence,
    pub config: Option<LocalDescriptorEvidence>,
    pub layers: Vec<LocalDescriptorEvidence>,
}

pub fn inspect_local_identity(
    target: &Path,
    cancel: &AtomicBool,
) -> Result<LocalImageEvidence, String> {
    inspect_with_limit(target, cancel, HASH_BYTE_LIMIT)
}

fn inspect_with_limit(
    target: &Path,
    cancel: &AtomicBool,
    byte_limit: u64,
) -> Result<LocalImageEvidence, String> {
    check_cancel(cancel)?;
    let metadata = fs::symlink_metadata(target).map_err(|error| error.to_string())?;
    let mut evidence = LocalImageEvidence {
        kind: "unavailable".into(),
        complete: false,
        hash_byte_limit: byte_limit,
        file: None,
        oci: None,
        notes: vec![SNAPSHOT_NOTE.into()],
    };
    if metadata.file_type().is_symlink() {
        evidence
            .notes
            .push("Local identity unavailable for a symlink target; no bytes were read.".into());
    } else if metadata.is_file() {
        evidence.kind = "file".into();
        match hash_file(target, byte_limit, cancel) {
            Ok(file) => {
                evidence.complete = file.complete;
                if file.sha256.is_none() {
                    evidence.notes.push(format!("Only a {byte_limit}-byte prefix was hashed; the full file digest is unknown."));
                }
                if file.changed_during_read != Some(false) {
                    evidence.notes.push("File metadata changed during reading or stability was unavailable; content identity is incomplete.".into());
                }
                evidence.file = Some(file);
            }
            Err(error) => {
                check_cancel(cancel)?;
                evidence
                    .notes
                    .push(format!("Local file identity unavailable: {error}"));
            }
        }
    } else if metadata.is_dir() && oxaudit_archive::oci::is_layout(target) {
        evidence.kind = "oci-layout".into();
        inspect_oci(target, cancel, byte_limit, &mut evidence)?;
    } else if metadata.is_dir() {
        evidence.kind = "directory".into();
        evidence.notes.push(
            "Directory content identity is unknown; a mutable tree path is not a content digest."
                .into(),
        );
    } else {
        evidence.notes.push(
            "Local identity unavailable: the target is not an ordinary file or directory.".into(),
        );
    }
    Ok(evidence)
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::SeqCst) {
        Err("local image identity inspection cancelled".into())
    } else {
        Ok(())
    }
}

fn open_regular(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("symlink content is not a verified local blob".into());
    }
    if !metadata.is_file() {
        return Err("identity requires an ordinary file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A concurrently substituted FIFO must not block open, and a final
        // path symlink must not redirect this inspection.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("identity target changed to a non-regular file".into());
    }
    Ok(file)
}

fn metadata_changed(before: &Metadata, after: &Metadata) -> Option<bool> {
    if before.len() != after.len() {
        return Some(true);
    }
    match (before.modified().ok(), after.modified().ok()) {
        (Some(a), Some(b)) => Some(a != b),
        _ => None,
    }
}

fn hash_stream(
    reader: &mut impl Read,
    limit: u64,
    cancel: &AtomicBool,
) -> Result<(u64, String, bool), String> {
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        check_cancel(cancel)?;
        let remaining = limit.saturating_sub(bytes);
        let wanted = remaining.min(buffer.len() as u64).max(1) as usize;
        let count = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Ok((bytes, format!("{:x}", hasher.finalize()), true));
        }
        if remaining == 0 {
            return Ok((bytes, format!("{:x}", hasher.finalize()), false));
        }
        hasher.update(&buffer[..count]);
        bytes = bytes
            .checked_add(count as u64)
            .ok_or("identity byte count overflow")?;
    }
}

fn hash_file(path: &Path, limit: u64, cancel: &AtomicBool) -> Result<LocalFileEvidence, String> {
    let mut file = open_regular(path)?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    let (bytes_hashed, hash, eof) = hash_stream(&mut file, limit, cancel)?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let changed_during_read = metadata_changed(&before, &after);
    Ok(LocalFileEvidence {
        size_bytes: if eof { bytes_hashed } else { after.len() },
        size_source: if eof {
            "streamed to EOF"
        } else {
            "open-file metadata; whole file not streamed"
        }
        .into(),
        bytes_hashed,
        sha256: eof.then(|| hash.clone()),
        prefix_sha256: (!eof).then_some(hash),
        changed_during_read,
        complete: eof
            && changed_during_read == Some(false)
            && bytes_hashed == before.len()
            && bytes_hashed == after.len(),
    })
}

fn safe_layout_path(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    let mut current = root.to_path_buf();
    for part in relative.components() {
        let std::path::Component::Normal(part) = part else {
            return Err("invalid OCI blob path".into());
        };
        current.push(part);
        if fs::symlink_metadata(&current)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("symlink content is not a verified OCI layout blob".into());
        }
    }
    // Defend against a parent-component substitution between the checks. The
    // open also refuses final symlinks; a later replacement remains outside
    // the immutable-content guarantee, as the receipt explicitly says.
    let canonical = current.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.starts_with(root.canonicalize().map_err(|error| error.to_string())?) {
        return Err("OCI content is outside the selected layout".into());
    }
    Ok(canonical)
}

fn read_document(path: &Path, limit: u64, cancel: &AtomicBool) -> Result<(Vec<u8>, bool), String> {
    let mut file = open_regular(path)?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    while bytes.len() as u64 <= limit {
        check_cancel(cancel)?;
        let remaining = limit + 1 - bytes.len() as u64;
        let count = file
            .read(&mut buffer[..remaining.min(8192) as usize])
            .map_err(|error| error.to_string())?;
        if count == 0 {
            let after = file.metadata().map_err(|error| error.to_string())?;
            return Ok((bytes, metadata_changed(&before, &after) == Some(false)));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Err(format!(
        "OCI metadata exceeds the {limit}-byte limit; no prefix is parsed"
    ))
}

fn descriptor(entry: &Value) -> LocalDescriptorEvidence {
    LocalDescriptorEvidence {
        digest: entry
            .get("digest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        declared_size: entry.get("size").and_then(Value::as_u64),
        observed_size: None,
        actual_sha256: None,
        prefix_sha256: None,
        bytes_hashed: 0,
        verified: false,
        notes: if entry
            .get("size")
            .is_some_and(|size| size.as_u64().is_none())
        {
            vec!["invalid declared size".into()]
        } else {
            Vec::new()
        },
    }
}

fn blob_path(root: &Path, descriptor: &LocalDescriptorEvidence) -> Result<PathBuf, String> {
    let Some(hex) = descriptor.digest.strip_prefix("sha256:") else {
        return Err("only SHA256 OCI descriptors are supported".into());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid SHA256 OCI descriptor; no blob path was read".into());
    }
    safe_layout_path(root, &Path::new("blobs/sha256").join(hex))
}

fn verify_descriptor(record: &mut LocalDescriptorEvidence, actual: &str, size: u64, stable: bool) {
    record.observed_size = Some(size);
    record.actual_sha256 = Some(actual.into());
    record.bytes_hashed = size;
    if record.digest != format!("sha256:{actual}") {
        record.notes.push("descriptor digest mismatch".into());
    }
    if record
        .declared_size
        .is_some_and(|declared| declared != size)
    {
        record.notes.push("descriptor size mismatch".into());
    }
    if !stable {
        record
            .notes
            .push("blob metadata changed while reading or stability is unknown".into());
    }
    record.verified = record.notes.is_empty();
}

fn descriptor_document(
    root: &Path,
    entry: &Value,
    cancel: &AtomicBool,
    budget: &mut u64,
) -> Result<(LocalDescriptorEvidence, Option<Value>), String> {
    let mut record = descriptor(entry);
    let result = (|| {
        let path = blob_path(root, &record)?;
        let (bytes, stable) = read_document(&path, MANIFEST_BYTE_LIMIT.min(*budget), cancel)?;
        *budget = budget
            .checked_sub(bytes.len() as u64)
            .ok_or("identity byte allowance exhausted")?;
        verify_descriptor(
            &mut record,
            &format!("{:x}", Sha256::digest(&bytes)),
            bytes.len() as u64,
            stable,
        );
        serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| format!("OCI document is not valid JSON: {error}"))
    })();
    match result {
        Ok(document) => Ok((record, Some(document))),
        Err(error) => {
            check_cancel(cancel)?;
            record.verified = false;
            record.notes.push(error);
            Ok((record, None))
        }
    }
}

fn content_descriptor(
    root: &Path,
    entry: &Value,
    cancel: &AtomicBool,
    budget: &mut u64,
) -> Result<LocalDescriptorEvidence, String> {
    let mut record = descriptor(entry);
    let result = (|| {
        let path = blob_path(root, &record)?;
        let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
        record.observed_size = Some(metadata.len());
        if metadata.len() > *budget {
            return Err(format!("blob identity exceeds the remaining {budget}-byte hash limit; declared digest is unverified"));
        }
        let file = hash_file(&path, *budget, cancel)?;
        *budget = budget
            .checked_sub(file.bytes_hashed)
            .ok_or("identity byte allowance exhausted")?;
        if let Some(hash) = &file.sha256 {
            verify_descriptor(&mut record, hash, file.size_bytes, file.complete);
        } else {
            record.bytes_hashed = file.bytes_hashed;
            record.prefix_sha256 = file.prefix_sha256;
            record
                .notes
                .push("blob grew past the hash allowance; prefix only, full digest unknown".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        check_cancel(cancel)?;
        record.notes.push(error);
    }
    Ok(record)
}

fn inspect_oci(
    root: &Path,
    cancel: &AtomicBool,
    byte_limit: u64,
    evidence: &mut LocalImageEvidence,
) -> Result<(), String> {
    let mut oci = LocalOciEvidence {
        index_sha256: None,
        indexes: Vec::new(),
        manifests: Vec::new(),
    };
    let mut complete = true;
    let mut budget = byte_limit;
    let result: Result<(), String> = (|| {
        let path = safe_layout_path(root, Path::new("index.json"))?;
        let (bytes, stable) = read_document(&path, INDEX_BYTE_LIMIT.min(budget), cancel)?;
        budget = budget
            .checked_sub(bytes.len() as u64)
            .ok_or("identity byte allowance exhausted")?;
        oci.index_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
        if !stable {
            complete = false;
            evidence
                .notes
                .push("OCI index changed while reading or stability is unknown.".into());
        }
        let index: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid OCI index JSON: {error}"))?;
        let entries = index
            .get("manifests")
            .and_then(Value::as_array)
            .ok_or("OCI index has no manifests array")?;
        if entries.len() > ROOT_ENTRY_LIMIT {
            complete = false;
            evidence.notes.push(format!("OCI root index exceeds the {ROOT_ENTRY_LIMIT}-entry limit; later entries are unknown."));
        }
        let mut manifests = Vec::new();
        for entry in entries.iter().take(ROOT_ENTRY_LIMIT) {
            check_cancel(cancel)?;
            let media = entry
                .get("mediaType")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if media.contains("index") || media.contains("manifest.list") {
                let (record, document) = descriptor_document(root, entry, cancel, &mut budget)?;
                complete &= record.verified;
                oci.indexes.push(record);
                if let Some(document) = document {
                    if let Some(children) = document.get("manifests").and_then(Value::as_array) {
                        if children.len() > ROOT_ENTRY_LIMIT {
                            complete = false;
                            evidence.notes.push("Nested OCI index exceeds the entry limit; later entries are unknown.".into());
                        }
                        manifests.extend(children.iter().take(ROOT_ENTRY_LIMIT).cloned());
                    } else {
                        complete = false;
                        evidence
                            .notes
                            .push("Nested OCI index has no manifest list.".into());
                    }
                }
            } else {
                manifests.push(entry.clone());
            }
        }
        if manifests.is_empty() {
            return Err("OCI index resolved no image manifests".into());
        }
        if manifests.len() > MANIFEST_LIMIT {
            complete = false;
            evidence.notes.push(format!("OCI manifests exceed the {MANIFEST_LIMIT}-manifest limit; later descriptors are unknown."));
        }
        let mut layers = 0usize;
        for entry in manifests.iter().take(MANIFEST_LIMIT) {
            check_cancel(cancel)?;
            let (record, document) = descriptor_document(root, entry, cancel, &mut budget)?;
            complete &= record.verified && document.is_some();
            let mut manifest = LocalManifestEvidence {
                descriptor: record,
                config: None,
                layers: Vec::new(),
            };
            if let Some(document) = document {
                if let Some(config) = document.get("config").filter(|config| config.is_object()) {
                    let record = content_descriptor(root, config, cancel, &mut budget)?;
                    complete &= record.verified;
                    manifest.config = Some(record);
                } else {
                    complete = false;
                    evidence.notes.push("OCI manifest has no valid configuration descriptor; configuration identity is unknown.".into());
                }
                if let Some(entries) = document.get("layers").and_then(Value::as_array) {
                    if entries.len() > LAYERS_PER_IMAGE
                        || entries.len() > LAYER_LIMIT.saturating_sub(layers)
                    {
                        complete = false;
                        evidence.notes.push(format!("OCI layer descriptor limit reached ({LAYERS_PER_IMAGE} per image, {LAYER_LIMIT} total); later layers are unknown."));
                    }
                    for layer in entries
                        .iter()
                        .take(LAYERS_PER_IMAGE)
                        .take(LAYER_LIMIT.saturating_sub(layers))
                    {
                        let record = content_descriptor(root, layer, cancel, &mut budget)?;
                        complete &= record.verified;
                        manifest.layers.push(record);
                        layers += 1;
                    }
                } else {
                    complete = false;
                    evidence.notes.push(
                        "OCI manifest has no layers array; layer identity is unknown.".into(),
                    );
                }
            }
            oci.manifests.push(manifest);
        }
        Ok(())
    })();
    if let Err(error) = result {
        check_cancel(cancel)?;
        complete = false;
        evidence.notes.push(error);
    }
    if !complete {
        evidence.notes.push("Local OCI identity is incomplete; descriptor notes distinguish verified hashes from declared or unavailable content.".into());
    }
    evidence.complete = complete;
    evidence.oci = Some(oci);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn digest(bytes: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(bytes))
    }

    fn layout() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("blobs/sha256")).unwrap();
        fs::write(
            root.path().join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let blob = |bytes: &[u8]| {
            let hash = digest(bytes);
            fs::write(root.path().join("blobs/sha256").join(&hash), bytes).unwrap();
            json!({"digest": format!("sha256:{hash}"), "size": bytes.len()})
        };
        let layer = blob(b"inert layer content");
        let config = blob(br#"{"architecture":"amd64","os":"linux"}"#);
        let manifest =
            serde_json::to_vec(&json!({"schemaVersion":2, "config": config, "layers":[layer]}))
                .unwrap();
        let mut descriptor = blob(&manifest);
        descriptor["mediaType"] = json!("application/vnd.oci.image.manifest.v1+json");
        fs::write(
            root.path().join("index.json"),
            serde_json::to_vec(&json!({"schemaVersion":2,"manifests":[descriptor]})).unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn local_file_hash_identifies_observed_content_and_changes_when_content_changes() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("image.tar");
        fs::write(&file, b"inert saved image").unwrap();
        let before = inspect_local_identity(&file, &AtomicBool::new(false)).unwrap();
        assert!(before.complete);
        let identity = before.file.as_ref().unwrap();
        assert_eq!(identity.sha256, Some(digest(b"inert saved image")));
        assert_eq!(identity.size_bytes, 17);
        assert_eq!(identity.bytes_hashed, 17);
        assert!(identity.prefix_sha256.is_none());
        fs::write(&file, b"changed saved image").unwrap();
        let after = inspect_local_identity(&file, &AtomicBool::new(false)).unwrap();
        assert_ne!(before.file.unwrap().sha256, after.file.unwrap().sha256);
    }

    #[test]
    fn capped_identity_never_labels_a_prefix_digest_as_whole_file() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("firmware.bin");
        fs::write(&file, b"0123456789abcdef").unwrap();
        let evidence = inspect_with_limit(&file, &AtomicBool::new(false), 8).unwrap();
        assert!(!evidence.complete);
        let identity = evidence.file.unwrap();
        assert_eq!(identity.size_bytes, 16);
        assert_eq!(identity.bytes_hashed, 8);
        assert!(identity.sha256.is_none());
        assert_eq!(identity.prefix_sha256, Some(digest(b"01234567")));
        assert!(evidence.notes.iter().any(|note| note.contains("prefix")));
    }

    #[test]
    fn local_oci_identity_retains_verified_manifest_config_and_layer_descriptors() {
        let root = layout();
        let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert!(evidence.complete, "{:?}", evidence.notes);
        assert_eq!(evidence.kind, "oci-layout");
        let oci = evidence.oci.unwrap();
        assert_eq!(
            oci.index_sha256,
            Some(digest(&fs::read(root.path().join("index.json")).unwrap()))
        );
        assert_eq!(oci.manifests.len(), 1);
        let manifest = &oci.manifests[0];
        assert!(manifest.descriptor.verified);
        assert!(manifest.config.as_ref().unwrap().verified);
        assert_eq!(manifest.layers.len(), 1);
        assert!(manifest.layers[0].verified);
        assert_eq!(
            manifest.layers[0].actual_sha256,
            Some(digest(b"inert layer content"))
        );
    }

    #[test]
    fn changed_oci_blob_keeps_declared_identity_and_records_digest_mismatch() {
        let root = layout();
        let before = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        let original = before.oci.as_ref().unwrap().manifests[0].layers[0].clone();
        fs::write(
            root.path()
                .join("blobs/sha256")
                .join(original.digest.strip_prefix("sha256:").unwrap()),
            b"tampered layer",
        )
        .unwrap();
        let after = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert!(!after.complete);
        let changed = &after.oci.as_ref().unwrap().manifests[0].layers[0];
        assert_eq!(changed.digest, original.digest);
        assert!(!changed.verified);
        assert_ne!(changed.actual_sha256, original.actual_sha256);
        assert!(changed.notes.iter().any(|note| note.contains("mismatch")));
        assert!(before.oci.as_ref().unwrap().manifests[0].layers[0].verified);
    }

    #[test]
    fn directory_without_oci_descriptors_has_explicitly_unknown_content_identity() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("file.bin"), b"inert content").unwrap();
        let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert_eq!(evidence.kind, "directory");
        assert!(!evidence.complete);
        assert!(evidence.file.is_none() && evidence.oci.is_none());
        assert!(evidence.notes.iter().any(|note| note.contains("mutable")));
    }

    #[test]
    fn pre_cancelled_identity_performs_no_file_discovery() {
        let error = inspect_local_identity(Path::new("does-not-exist"), &AtomicBool::new(true))
            .unwrap_err();
        assert!(error.contains("cancelled"));
    }

    #[test]
    fn oversized_oci_metadata_records_unknown_identity_without_parsing_a_prefix() {
        let root = layout();
        fs::write(root.path().join("index.json"), vec![b' '; 64 * 1024 + 1]).unwrap();
        let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert!(!evidence.complete);
        assert!(evidence.oci.unwrap().index_sha256.is_none());
        assert!(evidence.notes.iter().any(|note| note.contains("limit")));
    }

    #[test]
    fn oci_layer_hash_allowance_retains_only_unverified_declared_digest_when_too_large() {
        let root = layout();
        let original = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        let layer = &original.oci.unwrap().manifests[0].layers[0];
        fs::write(
            root.path()
                .join("blobs/sha256")
                .join(layer.digest.strip_prefix("sha256:").unwrap()),
            vec![0u8; 2048],
        )
        .unwrap();
        let evidence = inspect_with_limit(root.path(), &AtomicBool::new(false), 1024).unwrap();
        assert!(!evidence.complete);
        let oci = evidence.oci.unwrap();
        let layer = &oci.manifests[0].layers[0];
        assert_eq!(layer.observed_size, Some(2048));
        assert_eq!(layer.bytes_hashed, 0);
        assert!(!layer.verified);
        assert!(layer.actual_sha256.is_none());
        assert!(layer.notes.iter().any(|note| note.contains("unverified")));
    }

    #[test]
    fn invalid_declared_manifest_size_is_not_reported_as_verified() {
        let root = layout();
        let path = root.path().join("index.json");
        let mut index: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        index["manifests"][0]["size"] = json!(1);
        fs::write(path, serde_json::to_vec(&index).unwrap()).unwrap();
        let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert!(!evidence.complete);
        let descriptor = &evidence.oci.unwrap().manifests[0].descriptor;
        assert!(descriptor.actual_sha256.is_some());
        assert!(!descriptor.verified);
        assert!(descriptor
            .notes
            .iter()
            .any(|note| note.contains("size mismatch")));
    }

    #[test]
    fn malformed_manifest_without_a_configuration_descriptor_is_explicitly_incomplete() {
        for configuration in [None, Some(Value::Null), Some(json!("invalid descriptor"))] {
            let root = layout();
            let index_path = root.path().join("index.json");
            let mut index: Value = serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
            let original = index["manifests"][0]["digest"]
                .as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap();
            let mut manifest: Value = serde_json::from_slice(
                &fs::read(root.path().join("blobs/sha256").join(original)).unwrap(),
            )
            .unwrap();
            if let Some(value) = configuration {
                manifest["config"] = value;
            } else {
                manifest.as_object_mut().unwrap().remove("config");
            }
            let bytes = serde_json::to_vec(&manifest).unwrap();
            let hash = digest(&bytes);
            fs::write(root.path().join("blobs/sha256").join(&hash), &bytes).unwrap();
            index["manifests"][0]["digest"] = json!(format!("sha256:{hash}"));
            index["manifests"][0]["size"] = json!(bytes.len());
            fs::write(index_path, serde_json::to_vec(&index).unwrap()).unwrap();
            let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
            assert!(
                !evidence.complete,
                "a malformed OCI manifest cannot establish complete identity"
            );
            let manifest = &evidence.oci.as_ref().unwrap().manifests[0];
            assert!(manifest.descriptor.verified && manifest.layers[0].verified);
            assert!(manifest.config.is_none());
            assert!(evidence
                .notes
                .iter()
                .any(|note| note.contains("configuration descriptor")));
        }
    }

    #[test]
    fn excessive_root_descriptors_preserve_bounded_identity_without_claiming_completeness() {
        let root = layout();
        let path = root.path().join("index.json");
        let mut index: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        index["manifests"] = json!(vec![index["manifests"][0].clone(); ROOT_ENTRY_LIMIT + 1]);
        fs::write(path, serde_json::to_vec(&index).unwrap()).unwrap();
        let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert!(!evidence.complete);
        assert_eq!(evidence.oci.unwrap().manifests.len(), ROOT_ENTRY_LIMIT);
        assert!(evidence
            .notes
            .iter()
            .any(|note| note.contains("entry limit")));
    }

    #[test]
    fn content_hashing_stops_at_the_next_read_boundary_after_cancellation() {
        struct CancelAfterRead<'a> {
            cancel: &'a AtomicBool,
            reads: usize,
        }
        impl Read for CancelAfterRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                buffer[0] = b'x';
                self.cancel.store(true, Ordering::SeqCst);
                Ok(1)
            }
        }
        let cancel = AtomicBool::new(false);
        let mut reader = CancelAfterRead {
            cancel: &cancel,
            reads: 0,
        };
        assert!(hash_stream(&mut reader, 1024, &cancel)
            .unwrap_err()
            .contains("cancelled"));
        assert_eq!(reader.reads, 1);
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_layer_is_not_hashed_as_content_of_the_oci_layout() {
        let root = layout();
        let evidence = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        let descriptor = &evidence.oci.unwrap().manifests[0].layers[0];
        let file = root
            .path()
            .join("blobs/sha256")
            .join(descriptor.digest.strip_prefix("sha256:").unwrap());
        fs::remove_file(&file).unwrap();
        let external = tempfile::NamedTempFile::new().unwrap();
        fs::write(external.path(), b"inert outside bytes").unwrap();
        std::os::unix::fs::symlink(external.path(), file).unwrap();
        let after = inspect_local_identity(root.path(), &AtomicBool::new(false)).unwrap();
        assert!(!after.complete);
        let layer = &after.oci.as_ref().unwrap().manifests[0].layers[0];
        assert!(!layer.verified);
        assert_eq!(layer.bytes_hashed, 0);
        assert!(layer.notes.iter().any(|note| note.contains("symlink")));
    }
}
