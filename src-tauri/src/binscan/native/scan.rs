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

use super::filetype::{self, Classification, PROBE_BYTES};
use super::package_note::{self, upstream_version};
use super::signature::{Evidence, SignatureSet, SIGNATURES};
use super::strings;
use crate::binscan::report::{BinaryComponent, BinaryScanResult, BinaryScanSummary};

/// Scanner identifier, so a merged result says where a component came from.
pub const NATIVE: &str = "oxaudit";

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
/// out its detections.
pub fn scan_file(path: &Path, signatures: &SignatureSet) -> Vec<Detection> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    // One read, capped. Reading twice — once to classify, once to scan — is
    // the obvious shape and it doubles the I/O on a tree of 20,000 files.
    let Ok(extracted) = strings::read_capped(file) else {
        return Vec::new();
    };
    let bytes = &extracted.bytes;

    let classification = filetype::classify(&bytes[..bytes.len().min(PROBE_BYTES)]);
    if !classification.is_scannable() {
        return Vec::new();
    }

    let display = path.to_string_lossy().into_owned();
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
                path: display.clone(),
                source: DetectionSource::PackageNote,
                truncated: extracted.truncated,
            });
        }
    }

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let blob = strings::extract(bytes);

    for hit in signatures.detect(&file_name, &blob, bytes) {
        detections.push(Detection {
            vendor: hit.vendor,
            product: hit.product,
            raw_version: hit.version.clone(),
            version: hit.version,
            ecosystem: None,
            package_name: None,
            path: display.clone(),
            source: hit.evidence.into(),
            truncated: extracted.truncated,
        });
    }

    detections
}

/// Collect every file under `root` (or `root` itself, if it is a file).
fn candidates(root: &Path) -> Vec<std::path::PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect()
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
}

/// Scan a file or directory.
pub fn scan(
    root: &Path,
    cancel: Arc<AtomicBool>,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<NativeScan, String> {
    let started = std::time::Instant::now();
    let files = candidates(root);
    on_progress(format!("{} files to examine", files.len()));

    let signatures: &SignatureSet = &SIGNATURES;
    let detections: Vec<Detection> = files
        .par_iter()
        .flat_map_iter(|path| {
            if cancel.load(Ordering::Relaxed) {
                return Vec::new().into_iter();
            }
            scan_file(path, signatures).into_iter()
        })
        .collect();

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }

    let queries = super::enrich::queries_from(&detections);
    let components = fold(detections);
    on_progress(format!("{} components detected", components.len()));

    Ok(NativeScan {
        queries,
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
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(product: &str, version: Option<&str>, path: &str, source: DetectionSource) -> Detection {
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
            detection("openssl", Some("3.0.2"), "/fw/lib/libcrypto.so.3", DetectionSource::Filename),
            detection("openssl", Some("3.0.2"), "/fw/bin/vendord", DetectionSource::Content),
        ]);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].paths.len(), 2);
    }

    #[test]
    fn a_versionless_detection_does_not_hide_behind_a_versioned_one() {
        // "there is an OpenSSL here and I cannot tell which" is a finding in
        // its own right; folding it into the known version would erase it.
        let folded = fold(vec![
            detection("openssl", Some("3.0.2"), "/fw/lib/libcrypto.so.3", DetectionSource::Content),
            detection("openssl", None, "/fw/bin/blob", DetectionSource::Content),
        ]);
        assert_eq!(folded.len(), 2);
        assert!(folded.iter().any(|c| c.version.is_empty()));
    }

    #[test]
    fn the_same_path_is_not_recorded_twice() {
        // Both detectors firing on one file is the normal case, not an error.
        let folded = fold(vec![
            detection("zlib", Some("1.3.1"), "/fw/lib/libz.so.1", DetectionSource::PackageNote),
            detection("zlib", Some("1.3.1"), "/fw/lib/libz.so.1", DetectionSource::Content),
        ]);
        assert_eq!(folded[0].paths, vec!["/fw/lib/libz.so.1"]);
    }

    #[test]
    fn a_vendor_from_a_signature_fills_in_what_the_package_note_lacks() {
        let mut from_signature =
            detection("openssl", Some("3.0.2"), "/fw/lib/libcrypto.so.3", DetectionSource::Content);
        from_signature.vendor = "openssl".into();
        let from_note =
            detection("openssl", Some("3.0.2"), "/fw/lib/libcrypto.so.3", DetectionSource::PackageNote);

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
}
