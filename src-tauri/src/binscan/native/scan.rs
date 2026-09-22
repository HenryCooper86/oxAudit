//! Walking a target and turning detections into components.
//!
//! Two detectors run over every scannable file, and they are complementary
//! rather than redundant:
//!
//! - the **ELF package note**, which is what the builder declared, and is
//!   exact where it exists;
//! - **string signatures**, which are inference, and are all you have for a
//!   stripped or vendor-built binary — the firmware case.
//!
//! Where both fire, the note wins on version and the signature still counts as
//! corroboration. That ordering is deliberate: a declared version beats one
//! scraped out of a string table.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;

use super::extract;
use super::filetype::{self, Classification, PROBE_BYTES};
use super::package_note::{self, upstream_version};
use super::signature::{Evidence, SignatureSet, SIGNATURES};
use super::strings;
use crate::binscan::report::{BinaryComponent, BinaryScanResult, BinaryScanSummary};

/// Scanner identifier, so a merged result says where a component came from.
pub const NATIVE: &str = "oxaudit";
pub const MAX_BINARY_FILES: usize = 100_000;
pub const MAX_BINARY_BYTES: u64 = 20 * 1024 * 1024 * 1024;
pub const NATIVE_WORKERS: usize = 4;

/// How a component was recognized, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectionSource {
    /// Inferred from a string in the binary.
    Content,
    /// Inferred from the file's name.
    Filename,
    /// Declared by the builder in the ELF package note.
    PackageNote,
}

impl From<Evidence> for DetectionSource {
    fn from(evidence: Evidence) -> Self {
        match evidence {
            Evidence::Filename => DetectionSource::Filename,
            Evidence::Content => DetectionSource::Content,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub vendor: String,
    pub product: String,
    /// Upstream version, with any distribution packaging stripped.
    pub version: Option<String>,
    /// The version exactly as declared, packaging intact — `1.5.7+dfsg-1`.
    ///
    /// Kept alongside the upstream form because the two advisory sources want
    /// different ones: NVD's CPE data is keyed on upstream, and OSV's
    /// distribution ecosystems compare against the packaged version, so
    /// normalizing to one would make the other silently return nothing.
    pub raw_version: Option<String>,
    /// OSV ecosystem this came from, when the package note named a
    /// distribution we can query.
    pub ecosystem: Option<String>,
    /// The distribution's own package name, when it differs from the canonical
    /// product. OSV is keyed on this; NVD is keyed on the canonical one.
    pub package_name: Option<String>,
    pub path: String,
    pub source: DetectionSource,
    /// The file was larger than the read cap and only a prefix was examined.
    pub truncated: bool,
}

/// Read a file's prefix, decide whether it is worth scanning, and if so pull
/// out its detections — including everything inside it, when it is an
/// archive. Notes about extraction budgets land in `notes`.
pub fn scan_file(
    path: &Path,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
) -> Vec<Detection> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    // One read, capped. Reading twice — once to classify, once to scan — is
    // the obvious shape and it doubles the I/O on a tree of 20,000 files.
    let Ok(extracted) = strings::read_capped(file) else {
        return Vec::new();
    };

    let display = path.to_string_lossy().into_owned();
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    scan_buffer(
        &display,
        &file_name,
        &extracted.bytes,
        extracted.truncated,
        signatures,
        notes,
    )
}

/// The scan of one already-read buffer: classification, extraction when the
/// buffer is an archive, package-note and signature detection otherwise.
fn scan_buffer(
    display: &str,
    file_name: &str,
    bytes: &[u8],
    truncated: bool,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
) -> Vec<Detection> {
    let classification = filetype::classify(&bytes[..bytes.len().min(PROBE_BYTES)]);
    if !classification.is_scannable() {
        return Vec::new();
    }

    // A raw firmware blob is usually a header, a kernel, and a squashfs
    // partition bolted together — opaque to magic classification, but the
    // filesystem inside is the entire finding surface. The search is the
    // smallest useful slice of binwalk: one magic at erase-block alignment,
    // behind the same budgets as every other container.
    if classification == Classification::OpaqueBinary {
        let budget = extract::ExtractBudget::default();
        let embedded = extract::extract_embedded_squashfs(file_name, bytes, &budget);
        if !embedded.members.is_empty() {
            if let Some(note) = embedded.stats.note(display) {
                notes.push(note);
            }
            let mut detections = Vec::new();
            for member in &embedded.members {
                let member_name = member
                    .path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&member.path)
                    .to_string();
                detections.extend(scan_buffer(
                    &member.path,
                    &member_name,
                    &member.bytes,
                    false,
                    signatures,
                    notes,
                ));
            }
            return detections;
        }
    }

    if let Classification::Archive(_) = classification {
        let budget = extract::ExtractBudget::default();
        let extracted = extract::extract(file_name, bytes, &budget);
        if !extracted.members.is_empty() {
            if let Some(note) = extracted.stats.note(display) {
                notes.push(note);
            }
            let mut detections = Vec::new();
            for member in &extracted.members {
                let member_name = member
                    .path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&member.path)
                    .to_string();
                detections.extend(scan_buffer(
                    &member.path,
                    &member_name,
                    &member.bytes,
                    false,
                    signatures,
                    notes,
                ));
            }
            return detections;
        }
        // An archive that yielded nothing — empty, unreadable, or stopped by
        // a budget before the first member — falls back to scanning its own
        // bytes, which is what this scanner did before extraction existed.
        if let Some(note) = extracted.stats.note(display) {
            notes.push(note);
        }
    }

    let mut detections = Vec::new();

    if matches!(
        classification,
        Classification::Executable(filetype::Format::Elf)
    ) {
        if let Some(note) = package_note::read(bytes) {
            let version = upstream_version(&note.version);
            let raw = note.version.trim().to_string();
            // Debian says `libzstd`; NVD says `facebook:zstandard`. Resolving
            // gives the note a CPE identity it otherwise lacks entirely, and
            // stops it becoming a second row beside the same library found by
            // signature.
            let (vendor, product) = match signatures.resolve_alias(&note.name) {
                Some((vendor, product)) => (vendor.to_string(), product.to_string()),
                None => (String::new(), note.name.clone()),
            };
            detections.push(Detection {
                vendor,
                product,
                version: (!version.is_empty()).then_some(version),
                raw_version: (!raw.is_empty()).then_some(raw),
                ecosystem: super::enrich::osv_ecosystem(&note.kind, &note.os),
                package_name: Some(note.name),
                path: display.to_string(),
                source: DetectionSource::PackageNote,
                truncated,
            });
        }
    }

    let blob = strings::extract(bytes);

    for hit in signatures.detect(file_name, &blob, bytes) {
        detections.push(Detection {
            vendor: hit.vendor,
            product: hit.product,
            raw_version: hit.version.clone(),
            version: hit.version,
            ecosystem: None,
            package_name: None,
            path: display.to_string(),
            source: hit.evidence.into(),
            truncated,
        });
    }

    detections
}

/// Collect every file under `root` (or `root` itself, if it is a file).
fn candidates_with_budget(
    root: &Path,
    max_files: usize,
    max_bytes: u64,
    cancel: &AtomicBool,
) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;

    if root.is_file() {
        let size = std::fs::metadata(root)
            .map_err(|error| format!("cannot inspect {}: {error}", root.display()))?
            .len();
        if max_files == 0 {
            return Err(format!(
                "binary inventory exceeds the safety limit of {max_files} files; scan a smaller \
                 subdirectory or ignore generated/vendor paths"
            ));
        }
        if size > max_bytes {
            return Err(format!(
                "binary inventory exceeds the safety limit of {max_bytes} bytes; scan a smaller \
                 subdirectory or ignore generated/vendor paths"
            ));
        }
        return Ok(vec![root.to_path_buf()]);
    }

    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        if cancel.load(Ordering::Relaxed) {
            return Err("scan cancelled".into());
        }
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        if files.len() >= max_files {
            return Err(format!(
                "binary inventory exceeds the safety limit of {max_files} files; scan a smaller \
                 subdirectory or ignore generated/vendor paths"
            ));
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
            format!(
                "binary inventory exceeds the safety limit of {max_bytes} bytes; scan a smaller \
                 subdirectory or ignore generated/vendor paths"
            )
        })?;
        if total_bytes > max_bytes {
            return Err(format!(
                "binary inventory exceeds the safety limit of {max_bytes} bytes; scan a smaller \
                 subdirectory or ignore generated/vendor paths"
            ));
        }
        files.push(entry.into_path());
    }

    Ok(files)
}

/// Fold detections into one component per (product, version).
///
/// A product detected both with and without a version stays split: "openssl,
/// version unknown" is a different statement from "openssl 3.0.2", and merging
/// them would let the unknown disappear behind the known one.
pub fn fold(detections: Vec<Detection>) -> Vec<BinaryComponent> {
    let mut grouped: BTreeMap<(String, String), (BinaryComponent, DetectionSource)> =
        BTreeMap::new();

    for detection in detections {
        let key = (
            detection.product.to_ascii_lowercase(),
            detection.version.clone().unwrap_or_default(),
        );
        match grouped.get_mut(&key) {
            None => {
                grouped.insert(
                    key,
                    (
                        BinaryComponent {
                            vendor: detection.vendor,
                            product: detection.product,
                            version: detection.version.unwrap_or_default(),
                            paths: vec![detection.path],
                            vulnerabilities: Vec::new(),
                            detected_by: vec![NATIVE.to_string()],
                        },
                        detection.source,
                    ),
                );
            }
            Some((component, best)) => {
                if !component.paths.contains(&detection.path) {
                    component.paths.push(detection.path);
                }
                // A signature knows the vendor; the package note does not.
                if component.vendor.is_empty() && !detection.vendor.is_empty() {
                    component.vendor = detection.vendor;
                }
                if detection.source > *best {
                    *best = detection.source;
                }
            }
        }
    }

    let mut components: Vec<BinaryComponent> = grouped
        .into_values()
        .map(|(component, _)| component)
        .collect();
    components.sort_by(|a, b| a.product.cmp(&b.product).then(a.version.cmp(&b.version)));
    components
}

/// A completed native scan, plus what would need asking to enrich it.
#[derive(Debug)]
pub struct NativeScan {
    pub result: BinaryScanResult,
    /// One entry per component that can be looked up, carrying both version
    /// forms and the ecosystem — see [`super::enrich`].
    pub queries: Vec<super::enrich::ComponentQuery>,
    /// What extraction did, when it did anything: budgets hit, members
    /// skipped. Honest coverage statements, not decoration.
    pub notes: Vec<String>,
}

/// Scan a file or directory.
pub fn scan(
    root: &Path,
    cancel: Arc<AtomicBool>,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<NativeScan, String> {
    let started = std::time::Instant::now();
    let files = candidates_with_budget(root, MAX_BINARY_FILES, MAX_BINARY_BYTES, &cancel)?;
    on_progress(format!("{} files to examine", files.len()));

    let signatures: &SignatureSet = &SIGNATURES;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(NATIVE_WORKERS)
        .thread_name(|index| format!("oxaudit-binscan-{index}"))
        .build()
        .map_err(|error| format!("cannot prepare binary scan workers: {error}"))?;
    let extraction_notes = std::sync::Mutex::new(Vec::<String>::new());
    let detections: Vec<Detection> = pool.install(|| {
        files
            .par_iter()
            .flat_map_iter(|path| {
                if cancel.load(Ordering::Relaxed) {
                    return Vec::new().into_iter();
                }
                let mut file_notes = Vec::new();
                let detections = scan_file(path, signatures, &mut file_notes);
                if !file_notes.is_empty() {
                    if let Ok(mut notes) = extraction_notes.lock() {
                        notes.extend(file_notes);
                    }
                }
                detections.into_iter()
            })
            .collect()
    });

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".into());
    }

    let queries = super::enrich::queries_from(&detections);
    let components = fold(detections);
    on_progress(format!("{} components detected", components.len()));
    let notes = extraction_notes.into_inner().unwrap_or_default();

    Ok(NativeScan {
        queries,
        notes,
        result: BinaryScanResult {
            target: root.to_string_lossy().into_owned(),
            summary: BinaryScanSummary {
                components: components.len(),
                ..BinaryScanSummary::default()
            },
            components,
            database_last_updated: None,
            duration_ms: started.elapsed().as_millis() as u64,
            scanners: vec![NATIVE.to_string()],
            semantic_analysis: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(
        product: &str,
        version: Option<&str>,
        path: &str,
        source: DetectionSource,
    ) -> Detection {
        Detection {
            vendor: String::new(),
            product: product.to_string(),
            version: version.map(str::to_string),
            raw_version: version.map(str::to_string),
            ecosystem: None,
            package_name: None,
            path: path.to_string(),
            source,
            truncated: false,
        }
    }

    #[test]
    fn one_component_gathers_every_file_it_was_seen_in() {
        let folded = fold(vec![
            detection(
                "openssl",
                Some("3.0.2"),
                "/fw/lib/libcrypto.so.3",
                DetectionSource::Filename,
            ),
            detection(
                "openssl",
                Some("3.0.2"),
                "/fw/bin/vendord",
                DetectionSource::Content,
            ),
        ]);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].paths.len(), 2);
    }

    #[test]
    fn a_versionless_detection_does_not_hide_behind_a_versioned_one() {
        // "there is an OpenSSL here and I cannot tell which" is a finding in
        // its own right; folding it into the known version would erase it.
        let folded = fold(vec![
            detection(
                "openssl",
                Some("3.0.2"),
                "/fw/lib/libcrypto.so.3",
                DetectionSource::Content,
            ),
            detection("openssl", None, "/fw/bin/blob", DetectionSource::Content),
        ]);
        assert_eq!(folded.len(), 2);
        assert!(folded.iter().any(|c| c.version.is_empty()));
    }

    #[test]
    fn the_same_path_is_not_recorded_twice() {
        // Both detectors firing on one file is the normal case, not an error.
        let folded = fold(vec![
            detection(
                "zlib",
                Some("1.3.1"),
                "/fw/lib/libz.so.1",
                DetectionSource::PackageNote,
            ),
            detection(
                "zlib",
                Some("1.3.1"),
                "/fw/lib/libz.so.1",
                DetectionSource::Content,
            ),
        ]);
        assert_eq!(folded[0].paths, vec!["/fw/lib/libz.so.1"]);
    }

    #[test]
    fn a_vendor_from_a_signature_fills_in_what_the_package_note_lacks() {
        let mut from_signature = detection(
            "openssl",
            Some("3.0.2"),
            "/fw/lib/libcrypto.so.3",
            DetectionSource::Content,
        );
        from_signature.vendor = "openssl".into();
        let from_note = detection(
            "openssl",
            Some("3.0.2"),
            "/fw/lib/libcrypto.so.3",
            DetectionSource::PackageNote,
        );

        // Order must not matter: the note is read first in a real scan.
        let folded = fold(vec![from_note, from_signature]);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].vendor, "openssl");
    }

    #[test]
    fn declared_metadata_outranks_an_inferred_string() {
        assert!(DetectionSource::PackageNote > DetectionSource::Filename);
        assert!(DetectionSource::Filename > DetectionSource::Content);
    }

    #[test]
    fn scanning_a_directory_of_text_finds_nothing() {
        // A source tree is full of version numbers in changelogs. Reporting
        // them as components would make the scanner useless on real projects.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("CHANGELOG.md"),
            "## 3.0.2\nUpgraded to OpenSSL 3.0.2 and zlib 1.3.1.\n",
        )
        .expect("write");

        let result = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan")
        .result;
        assert!(
            result.components.is_empty(),
            "text matched as a component: {:?}",
            result.components
        );
    }

    #[test]
    fn a_binary_carrying_a_known_banner_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vendord");
        // A NUL-bearing blob so the file reads as binary, with the banner a
        // real busybox carries.
        let mut bytes = vec![0u8, 0, 0, 0];
        bytes.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.38.0 (2026-05-13)\0");
        std::fs::write(&path, &bytes).expect("write");

        let result = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan")
        .result;
        assert_eq!(result.components.len(), 1);
        assert_eq!(result.components[0].product, "busybox");
        assert_eq!(result.components[0].version, "1.38.0");
        assert_eq!(result.components[0].detected_by, vec![NATIVE]);
    }

    #[test]
    fn a_firmware_archive_is_scanned_through_its_members() {
        // The gap this closes: a vendor firmware image is one opaque file,
        // and the components inside it used to be invisible.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut member = vec![0u8, 0, 0, 0];
        member.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.38.0 (2026-05-13)\0");
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(member.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "bin/busybox", member.as_slice())
            .expect("tar member");
        let tar = builder.into_inner().expect("tar bytes");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar).expect("gzip");
        let gz = encoder.finish().expect("gzip bytes");
        std::fs::write(dir.path().join("fw.tar.gz"), &gz).expect("write archive");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");
        assert_eq!(scanned.result.components.len(), 1);
        assert_eq!(scanned.result.components[0].product, "busybox");
        assert_eq!(scanned.result.components[0].version, "1.38.0");
        // The finding names the member, not the container.
        assert_eq!(
            scanned.result.components[0].paths,
            vec!["fw.tar!/bin/busybox".to_string()]
        );
        // Extraction did something worth saying.
        assert!(
            scanned
                .notes
                .iter()
                .any(|note| note.contains("extracted 1 member")),
            "{:?}",
            scanned.notes
        );
    }

    #[test]
    fn a_saved_container_image_finds_components_in_its_layers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut member = vec![0u8, 0, 0, 0];
        member.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.36.1 (2024-01-01)\0");
        let mut layer_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(member.len() as u64);
        header.set_cksum();
        layer_builder
            .append_data(&mut header, "bin/busybox", member.as_slice())
            .expect("layer member");
        let layer = layer_builder.into_inner().expect("layer tar");
        let mut image_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(layer.len() as u64);
        header.set_cksum();
        image_builder
            .append_data(&mut header, "layer.tar", layer.as_slice())
            .expect("image member");
        let image = image_builder.into_inner().expect("image tar");
        std::fs::write(dir.path().join("image.tar"), &image).expect("write image");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");
        assert_eq!(scanned.result.components.len(), 1);
        assert_eq!(
            scanned.result.components[0].paths,
            vec!["image.tar!/layer.tar!/bin/busybox".to_string()]
        );
    }

    #[test]
    fn a_raw_firmware_blob_finds_components_in_its_embedded_squashfs() {
        // The Archer-C7 shape this scanner used to score zero on: junk
        // first, squashfs at an erase-block boundary.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut member = vec![0u8, 0, 0, 0];
        member.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.33.2\0");
        let mut writer = backhand::FilesystemWriter::default();
        writer.set_compressor(
            backhand::FilesystemCompressor::new(backhand::v4::compressor::Compressor::Gzip, None)
                .expect("gzip compressor"),
        );
        let header = backhand::NodeHeader {
            permissions: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        writer
            .push_dir_all(std::path::Path::new("/bin"), header)
            .expect("dir");
        writer
            .push_file(
                member.as_slice(),
                std::path::Path::new("/bin/busybox"),
                header,
            )
            .expect("member");
        let mut image = Vec::new();
        writer
            .write(&mut std::io::Cursor::new(&mut image))
            .expect("squashfs");
        let mut blob = vec![0x00u8; 8192];
        blob.extend_from_slice(&image);
        std::fs::write(dir.path().join("vendor-firmware.bin"), &blob).expect("write");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");
        assert_eq!(scanned.result.components.len(), 1);
        assert_eq!(scanned.result.components[0].product, "busybox");
        assert_eq!(scanned.result.components[0].version, "1.33.2");
        assert_eq!(
            scanned.result.components[0].paths,
            vec!["vendor-firmware.bin!sqfs@0x2000!/bin/busybox".to_string()]
        );
    }

    #[test]
    fn a_cramfs_image_finds_components_through_its_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/crates/oxaudit-archive/tests/fixtures/rootfs.cramfs"
        ))
        .expect("fixture");
        std::fs::write(dir.path().join("vendorfs"), &image).expect("write");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");
        assert_eq!(scanned.result.components.len(), 1);
        assert_eq!(scanned.result.components[0].product, "busybox");
        assert_eq!(scanned.result.components[0].version, "1.36.1");
        assert_eq!(
            scanned.result.components[0].paths,
            vec!["vendorfs!/bin/busybox".to_string()]
        );
    }

    #[test]
    fn a_cancelled_scan_reports_cancellation_rather_than_an_empty_result() {
        // Returning Ok with no components would be indistinguishable from a
        // clean scan, which is the worst possible outcome for a security tool.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("blob"), b"\0\0\0\0BusyBox v1.38.0\0").expect("write");

        let error = scan(
            dir.path(),
            Arc::new(AtomicBool::new(true)),
            Arc::new(|_| {}),
        )
        .expect_err("must not report success");
        assert!(error.contains("cancelled"), "{error}");
    }

    #[test]
    fn binary_inventory_rejects_file_and_byte_overflow() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("one.bin"), b"1234").expect("fixture");
        std::fs::write(dir.path().join("two.bin"), b"5678").expect("fixture");
        let cancel = AtomicBool::new(false);

        let file_error = candidates_with_budget(dir.path(), 1, 1024, &cancel)
            .expect_err("file inventory overflow");
        assert!(file_error.contains("1 files"), "{file_error}");
        assert!(file_error.contains("smaller subdirectory"), "{file_error}");

        let byte_error = candidates_with_budget(dir.path(), 10, 7, &cancel)
            .expect_err("byte inventory overflow");
        assert!(byte_error.contains("7 bytes"), "{byte_error}");
        assert!(byte_error.contains("ignore"), "{byte_error}");
    }
}
