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
//!
//! Extracted filesystem images carry a third surface: their own **package
//! databases** (`/var/lib/dpkg/status`, `/lib/apk/db/installed`), read against
//! the `os-release` in the same image. Those produce one detection per
//! installed package, keyed to a release-qualified distribution ecosystem —
//! see [`super::os_packages`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;

use super::extract;
use super::filetype::{self, Classification, PROBE_BYTES};
use super::os_packages::{self, DistroIdentity};
use super::package_note::{self, upstream_version};
use super::signature::{Evidence, SignatureSet, SIGNATURES};
use super::strings;
use crate::binscan::report::{BinaryComponent, BinaryScanResult, BinaryScanSummary};

/// Scanner identifier, so a merged result says where a component came from.
pub const NATIVE: &str = "oxaudit";
pub const MAX_BINARY_FILES: usize = 100_000;
pub const MAX_BINARY_BYTES: u64 = 20 * 1024 * 1024 * 1024;
pub const NATIVE_WORKERS: usize = 4;
/// Payload reservation includes input, two buffers per extraction level
/// (nested member and RPM staging), and at most two input sizes of strings.
/// Codec internals and result metadata are outside this payload allowance.
pub const NATIVE_WORKSPACE_BYTES: usize = (2 * 3 + 3) * (strings::MAX_FILE_BYTES + 1) + 1024 * 1024;
pub const NATIVE_RETAINED_BYTES: usize = 2 * NATIVE_WORKSPACE_BYTES;

fn native_allowance() -> &'static NativeAllowance {
    static ALLOWANCE: std::sync::OnceLock<NativeAllowance> = std::sync::OnceLock::new();
    ALLOWANCE.get_or_init(|| NativeAllowance::new(NATIVE_RETAINED_BYTES))
}

struct NativeAllowance {
    limit: usize,
    retained: std::sync::Mutex<usize>,
    available: std::sync::Condvar,
}

struct NativeReservation<'a> {
    allowance: &'a NativeAllowance,
    bytes: usize,
}

impl NativeAllowance {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            retained: std::sync::Mutex::new(0),
            available: std::sync::Condvar::new(),
        }
    }

    fn acquire(&self, bytes: usize, cancel: &AtomicBool) -> Result<NativeReservation<'_>, String> {
        if bytes > self.limit {
            return Err("native workspace exceeds the shared payload allowance".into());
        }
        let mut retained = self
            .retained
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("scan cancelled".into());
            }
            if bytes <= self.limit.saturating_sub(*retained) {
                *retained += bytes;
                return Ok(NativeReservation {
                    allowance: self,
                    bytes,
                });
            }
            let (next, _) = self
                .available
                .wait_timeout(retained, std::time::Duration::from_millis(50))
                .unwrap_or_else(|error| error.into_inner());
            retained = next;
        }
    }
}

impl Drop for NativeReservation<'_> {
    fn drop(&mut self) {
        *self
            .allowance
            .retained
            .lock()
            .unwrap_or_else(|error| error.into_inner()) -= self.bytes;
        self.allowance.available.notify_all();
    }
}

/// How a component was recognized, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectionSource {
    /// Inferred from a string in the binary.
    Content,
    /// Inferred from the file's name.
    Filename,
    /// Declared by a JAR's `MANIFEST.MF` attributes (title and version).
    JarManifest,
    /// Declared by a JAR's embedded Maven `pom.properties`.
    PomProperties,
    /// Declared by the image's own package database (`dpkg`/`apk`).
    OsPackageDatabase,
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
    scan_file_as(path, None, signatures, notes)
}

/// The same scan where this file is known to be a blob of an OCI image
/// layout: its members carry the layout's ordered alias
/// (`image@<digest12>!layer-0003!/bin/busybox`) instead of the blob's
/// 64-character hash filename, so findings name the image they came from.
pub fn scan_file_as(
    path: &Path,
    alias: Option<&str>,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
) -> Vec<Detection> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            notes.push(format!(
                "{}: cannot open file; not scanned: {error}",
                path.display()
            ));
            return Vec::new();
        }
    };

    scan_reader_as(file, path, alias, signatures, notes)
}

fn scan_reader_as(
    reader: impl std::io::Read,
    path: &Path,
    alias: Option<&str>,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
) -> Vec<Detection> {
    let mut distro = None;
    let cancel = AtomicBool::new(false);
    let mut detections =
        scan_reader_in_context(reader, path, alias, signatures, notes, &mut distro, &cancel);
    finish_metadata(&mut detections, &distro, notes);
    detections
}

fn scan_reader_in_context(
    mut reader: impl std::io::Read,
    path: &Path,
    alias: Option<&str>,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
    distro: &mut Option<DistroIdentity>,
    cancel: &AtomicBool,
) -> Vec<Detection> {
    use std::io::Read;

    // Classify before loading the full file. The prefix is replayed from
    // memory, so scannable files still read each byte from disk only once.
    let mut prefix = Vec::with_capacity(PROBE_BYTES);
    if let Err(error) = (&mut reader)
        .take(PROBE_BYTES as u64)
        .read_to_end(&mut prefix)
    {
        notes.push(format!(
            "{}: cannot read file; not scanned: {error}",
            path.display()
        ));
        return Vec::new();
    }
    let classification = filetype::classify(&prefix);
    if !classification.is_scannable() {
        return Vec::new();
    }
    if classification == Classification::Archive(filetype::ArchiveKind::Tar) {
        let name = alias.map(str::to_owned).unwrap_or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        return scan_layer_reader(
            &mut prefix.as_slice().chain(reader),
            path,
            &name,
            signatures,
            notes,
            distro,
            cancel,
        );
    }
    let reservation = if matches!(
        classification,
        Classification::Archive(_) | Classification::OpaqueBinary
    ) {
        NATIVE_WORKSPACE_BYTES
    } else {
        3 * (strings::MAX_FILE_BYTES + 1) + 1024 * 1024
    };
    let _reservation = match native_allowance().acquire(reservation, cancel) {
        Ok(reservation) => reservation,
        Err(error) => {
            notes.push(error);
            return Vec::new();
        }
    };
    let extracted = match strings::read_capped_cancellable(prefix.as_slice().chain(reader), cancel)
    {
        Ok(extracted) => extracted,
        Err(error) => {
            notes.push(format!(
                "{}: cannot read file; not scanned: {error}",
                path.display()
            ));
            return Vec::new();
        }
    };

    let display = alias
        .map(str::to_owned)
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let file_name = alias.map(str::to_owned).unwrap_or_else(|| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    scan_buffer_at_depth(
        &display,
        &file_name,
        &extracted.bytes,
        extracted.truncated,
        signatures,
        notes,
        distro,
        0,
        cancel,
    )
}

/// The scan of one already-read buffer: classification, extraction when the
/// buffer is an archive, package-note and signature detection otherwise.
#[cfg(test)]
fn scan_buffer(
    display: &str,
    file_name: &str,
    bytes: &[u8],
    truncated: bool,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
    distro: &mut Option<DistroIdentity>,
) -> Vec<Detection> {
    let mut detections = scan_buffer_at_depth(
        display,
        file_name,
        bytes,
        truncated,
        signatures,
        notes,
        distro,
        0,
        &AtomicBool::new(false),
    );
    finish_metadata(&mut detections, distro, notes);
    detections
}

#[allow(clippy::too_many_arguments)]
fn scan_buffer_at_depth(
    display: &str,
    file_name: &str,
    bytes: &[u8],
    truncated: bool,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
    distro: &mut Option<DistroIdentity>,
    depth: usize,
    cancel: &AtomicBool,
) -> Vec<Detection> {
    if truncated {
        notes.push(format!(
            "{display}: scanned only the first {} bytes (prefix); later content was not examined",
            bytes.len()
        ));
    }
    let classification = filetype::classify(&bytes[..bytes.len().min(PROBE_BYTES)]);
    if !classification.is_scannable() {
        return Vec::new();
    }

    // A raw firmware blob is usually a header, a kernel, and a squashfs
    // partition bolted together — opaque to magic classification, but the
    // filesystem inside is the entire finding surface. The search is the
    // smallest useful slice of binwalk: a bounded sliding magic search,
    // behind the same budgets as every other container.
    let budget = extract::ExtractBudget {
        max_depth: extract::ExtractBudget::default()
            .max_depth
            .saturating_sub(depth),
        ..extract::ExtractBudget::default()
    };
    if classification == Classification::OpaqueBinary
        || matches!(classification, Classification::Archive(_))
    {
        let mut detections = Vec::new();
        let mut maven_artifacts = 0;
        let mut maven_bounded = false;
        let mut visitor = |member: extract::ExtractedMember| {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            scan_member(
                &member,
                signatures,
                notes,
                distro,
                &mut detections,
                &mut maven_artifacts,
                &mut maven_bounded,
                depth + member.depth,
                cancel,
            );
            !cancel.load(Ordering::Relaxed)
        };
        let stats = if classification == Classification::OpaqueBinary {
            extract::extract_embedded_squashfs_visit_cancellable(
                file_name,
                bytes,
                &budget,
                cancel,
                &mut visitor,
            )
        } else {
            extract::extract_visit_cancellable(file_name, bytes, &budget, cancel, &mut visitor)
        };
        if let Some(note) = stats.note(display) {
            notes.push(note);
        }
        if stats.entries > 0 {
            annotate_packages(&mut detections, distro);
            supersede_manifest_identities(&mut detections);
            return detections;
        }
        if matches!(classification, Classification::Archive(_)) {
            notes.push(format!("{display}: no members were extracted; scanning raw archive bytes only; member coverage is unavailable"));
        }
    }

    // The compatible in-memory layer API can borrow inputs larger than the
    // ordinary file cap. Archive extraction remains member-bounded, and a
    // raw fallback must also bound its additional string buffer.
    let raw_truncated = bytes.len() > strings::MAX_FILE_BYTES;
    if raw_truncated {
        notes.push(format!(
            "{display}: scanned only the first {} bytes (prefix); later content was not examined",
            strings::MAX_FILE_BYTES
        ));
    }
    let bytes = &bytes[..bytes.len().min(strings::MAX_FILE_BYTES)];
    let truncated = truncated || raw_truncated;

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

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".into());
    }
    let metadata = std::fs::metadata(root)
        .map_err(|error| format!("cannot inspect {}: {error}", root.display()))?;
    if metadata.is_file() {
        let size = metadata.len();
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
    if !metadata.is_dir() {
        return Err(format!(
            "{} is not a regular file or directory",
            root.display()
        ));
    }

    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        if cancel.load(Ordering::Relaxed) {
            return Err("scan cancelled".into());
        }
        let entry = entry.map_err(|error| {
            format!("cannot walk binary scan target {}: {error}", root.display())
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        if files.len() >= max_files {
            return Err(format!(
                "binary inventory exceeds the safety limit of {max_files} files; scan a smaller \
                 subdirectory or ignore generated/vendor paths"
            ));
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
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

/// Consume one decoded member immediately. Metadata becomes detections,
/// which can be annotated after later identity members arrive.
#[allow(clippy::too_many_arguments)]
fn scan_member(
    member: &extract::ExtractedMember,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
    distro: &mut Option<DistroIdentity>,
    detections: &mut Vec<Detection>,
    maven_artifacts: &mut usize,
    maven_bounded: &mut bool,
    depth: usize,
    cancel: &AtomicBool,
) {
    if os_packages::is_os_release_path(&member.path) {
        match os_packages::parse_os_release(&member.bytes) {
            os_packages::OsReleaseMatch::Distro(identity) if distro.is_none() => {
                *distro = Some(identity)
            }
            os_packages::OsReleaseMatch::Unsupported(reason) => notes.push(reason),
            _ => {}
        }
        return;
    }
    let package_list = if os_packages::is_dpkg_status_path(&member.path) {
        Some(os_packages::parse_dpkg_status(&member.bytes))
    } else if os_packages::is_apk_installed_path(&member.path) {
        Some(os_packages::parse_apk_installed(&member.bytes))
    } else {
        None
    };
    if let Some(packages) = package_list {
        if packages.len() >= os_packages::MAX_PACKAGES_PER_DATABASE {
            notes.push(format!(
                "package database {} is bounded at {} packages; later entries are not reported",
                member.path,
                os_packages::MAX_PACKAGES_PER_DATABASE
            ));
        }
        let ecosystem = distro
            .as_ref()
            .map(|identity| identity.osv_ecosystem.clone());
        for (name, version) in packages {
            detections.push(Detection {
                vendor: String::new(),
                product: name.clone(),
                version: Some(version.clone()),
                raw_version: Some(version),
                ecosystem: ecosystem.clone(),
                package_name: Some(name),
                path: member.path.clone(),
                source: DetectionSource::OsPackageDatabase,
                truncated: false,
            });
        }
        return;
    }
    if is_manifest_path(&member.path) {
        // Inventory only: a manifest declares a name and a version but
        // never Maven coordinates or an ecosystem, and an advisory
        // query on a guessed identity would answer the wrong package.
        if let Some((name, version)) = parse_manifest_identity(&member.bytes) {
            detections.push(Detection {
                vendor: String::new(),
                product: name,
                version: Some(version.clone()),
                raw_version: Some(version),
                ecosystem: None,
                package_name: None,
                path: member.path.clone(),
                source: DetectionSource::JarManifest,
                truncated: false,
            });
        }
        return;
    }
    if is_pom_properties_path(&member.path) {
        if *maven_artifacts >= MAX_MAVEN_ARTIFACTS {
            if !*maven_bounded {
                *maven_bounded = true;
                notes.push(format!(
                        "Maven coordinates are bounded at {MAX_MAVEN_ARTIFACTS} artifacts per archive; later pom.properties members are not reported"
                    ));
            }
            return;
        }
        if let Some((group, artifact, version)) = parse_pom_properties(&member.bytes) {
            // OSV's Maven ecosystem keys on group:artifact; the bare
            // artifactId would answer for whichever project owns it.
            let coordinates = format!("{group}:{artifact}");
            detections.push(Detection {
                vendor: String::new(),
                product: coordinates.clone(),
                version: Some(version.clone()),
                raw_version: Some(version),
                ecosystem: Some("Maven".to_string()),
                package_name: Some(coordinates),
                path: member.path.clone(),
                source: DetectionSource::PomProperties,
                truncated: false,
            });
            *maven_artifacts += 1;
        }
        return;
    }
    let member_name = member
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&member.path)
        .to_string();
    detections.extend(scan_buffer_at_depth(
        &member.path,
        &member_name,
        &member.bytes,
        false,
        signatures,
        notes,
        distro,
        depth,
        cancel,
    ));
}

fn annotate_packages(detections: &mut [Detection], distro: &Option<DistroIdentity>) {
    if let Some(identity) = distro {
        for detection in detections {
            if detection.source == DetectionSource::OsPackageDatabase
                && detection.ecosystem.is_none()
            {
                detection.ecosystem = Some(identity.osv_ecosystem.clone());
            }
        }
    }
}

fn finish_metadata(
    detections: &mut Vec<Detection>,
    distro: &Option<DistroIdentity>,
    notes: &mut Vec<String>,
) {
    annotate_packages(detections, distro);
    let unannotated = detections
        .iter()
        .filter(|detection| {
            detection.source == DetectionSource::OsPackageDatabase && detection.ecosystem.is_none()
        })
        .count();
    if unannotated > 0 {
        notes.push(format!("{unannotated} package(s) from a package database carry no distribution identity (no usable os-release in this target); they are reported as components but not matched against a distribution advisory source"));
    }
    supersede_manifest_identities(detections);
}

fn supersede_manifest_identities(detections: &mut Vec<Detection>) {
    let maven_artifacts: Vec<String> = detections
        .iter()
        .filter(|detection| detection.source == DetectionSource::PomProperties)
        .map(|detection| {
            detection
                .product
                .rsplit(':')
                .next()
                .unwrap_or(&detection.product)
                .to_ascii_lowercase()
        })
        .collect();
    detections.retain(|detection| {
        detection.source != DetectionSource::JarManifest
            || !maven_artifacts
                .iter()
                .any(|artifact| *artifact == detection.product.to_ascii_lowercase())
    });
}

/// Cap on Maven artifacts read from one member list, so a crafted archive
/// cannot flood the detection list — or the one-request-per-package OSV
/// enrichment loop — with pom.properties members.
const MAX_MAVEN_ARTIFACTS: usize = 2_000;

/// `META-INF/maven/<group>/<artifact>/pom.properties` — the coordinates a
/// Maven- or Gradle-built JAR embeds beside its classes. The layout is the
/// contract: shallower pom.properties files are not Maven coordinates.
fn is_pom_properties_path(path: &str) -> bool {
    let mut segments = path.rsplit('/');
    if segments.next() != Some("pom.properties") {
        return false;
    }
    if segments.next().is_none() || segments.next().is_none() {
        return false;
    }
    segments.next() == Some("maven")
}

/// `META-INF/MANIFEST.MF` at the root of a JAR.
fn is_manifest_path(path: &str) -> bool {
    path.ends_with("META-INF/MANIFEST.MF")
}

/// The identity a JAR's manifest declares: (name, version). The name
/// prefers the build title (`Implementation-Title`), falling back to the
/// OSGi symbolic name and the Java module name. A manifest never carries
/// Maven `group:artifact` coordinates, so callers report this identity as
/// inventory only — never as an advisory query, which would guess.
fn parse_manifest_identity(bytes: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut title = None;
    let mut symbolic_name = None;
    let mut module_name = None;
    let mut version = None;
    // Manifest headers fold continuation lines starting with a single
    // space onto the previous value.
    let mut folded = String::new();
    for line in text.lines() {
        if let Some(continuation) = line.strip_prefix(' ') {
            folded.push_str(continuation.trim_end());
            continue;
        }
        if let Some((key, value)) = folded.split_once(':') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key.trim() {
                "Implementation-Title" | "Bundle-Name" => title = Some(value.to_string()),
                "Bundle-SymbolicName" => {
                    // `symbolic-name; directive=…` — take the name before `;`.
                    symbolic_name = Some(value.split(';').next().unwrap_or(value).to_string());
                }
                "Automatic-Module-Name" => module_name = Some(value.to_string()),
                "Implementation-Version" | "Bundle-Version" => version = Some(value.to_string()),
                _ => {}
            }
        }
        folded = line.to_string();
    }
    // The final folded line never loops back through the parser.
    if let Some((key, value)) = folded.split_once(':') {
        let value = value.trim();
        match key.trim() {
            "Implementation-Title" | "Bundle-Name" if !value.is_empty() => {
                title = Some(value.to_string())
            }
            "Bundle-SymbolicName" if !value.is_empty() => {
                symbolic_name = Some(value.split(';').next().unwrap_or(value).to_string())
            }
            "Automatic-Module-Name" if !value.is_empty() => module_name = Some(value.to_string()),
            "Implementation-Version" | "Bundle-Version" if !value.is_empty() => {
                version = Some(value.to_string())
            }
            _ => {}
        }
    }
    let name = title
        .or(symbolic_name)
        .or(module_name)
        .filter(|name| !name.is_empty() && name.len() <= 200)?;
    let version = version.filter(|version| !version.is_empty() && version.len() <= 64)?;
    Some((name, version))
}

/// group, artifact, version — only when all three are present, because an
/// advisory query needs every coordinate.
fn parse_pom_properties(bytes: &[u8]) -> Option<(String, String, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut group = None;
    let mut artifact = None;
    let mut version = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "groupId" => group = Some(value.to_string()),
            "artifactId" => artifact = Some(value.to_string()),
            "version" => version = Some(value.to_string()),
            _ => {}
        }
    }
    Some((group?, artifact?, version?))
}

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
    let (oci_aliases, oci_notes) = oci_aliases_for(&files);
    if !oci_aliases.is_empty() {
        on_progress(format!(
            "{} OCI layout layer blob(s) recognized",
            oci_aliases.len()
        ));
    }

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
                let mut distro = None;
                let mut detections = match std::fs::File::open(path) {
                    Ok(file) => scan_reader_in_context(
                        file,
                        path,
                        oci_aliases.get(path).map(String::as_str),
                        signatures,
                        &mut file_notes,
                        &mut distro,
                        &cancel,
                    ),
                    Err(error) => {
                        file_notes.push(format!(
                            "{}: cannot open file; not scanned: {error}",
                            path.display()
                        ));
                        Vec::new()
                    }
                };
                finish_metadata(&mut detections, &distro, &mut file_notes);
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
    let mut notes = extraction_notes.into_inner().unwrap_or_default();
    notes.extend(oci_notes);

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

/// Scan the already-downloaded layers of a registry image.
///
/// Layers arrive in memory in manifest order and share one distro context,
/// for the same reason the context crosses layer tars inside a saved image:
/// the base layer usually states the distribution the app layers build on.
pub fn scan_image_layers(
    display: &str,
    layers: &[super::super::registry::Layer],
    cancel: &Arc<AtomicBool>,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<NativeScan, String> {
    use std::sync::atomic::Ordering;

    let started = std::time::Instant::now();
    let signatures: &SignatureSet = &SIGNATURES;
    let mut notes = Vec::new();
    let mut detections = Vec::new();
    let mut distro = None;
    for (index, layer) in layers.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("scan cancelled".into());
        }
        on_progress(format!("scanning layer {}/{}", index + 1, layers.len()));
        let chain = format!("{display}!{}", layer.name);
        let _reservation = native_allowance().acquire(NATIVE_WORKSPACE_BYTES, cancel)?;
        detections.extend(scan_buffer_at_depth(
            &chain,
            &chain,
            &layer.bytes,
            false,
            signatures,
            &mut notes,
            &mut distro,
            0,
            cancel,
        ));
    }

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".into());
    }

    finish_metadata(&mut detections, &distro, &mut notes);
    let queries = super::enrich::queries_from(&detections);
    let components = fold(detections);
    on_progress(format!("{} components detected", components.len()));

    Ok(NativeScan {
        queries,
        notes,
        result: BinaryScanResult {
            target: display.to_string(),
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

#[allow(clippy::too_many_arguments)]
fn scan_layer_reader(
    mut reader: &mut dyn std::io::Read,
    path: &Path,
    chain: &str,
    signatures: &SignatureSet,
    notes: &mut Vec<String>,
    distro: &mut Option<DistroIdentity>,
    cancel: &AtomicBool,
) -> Vec<Detection> {
    use std::io::Read;
    let mut prefix = Vec::with_capacity(PROBE_BYTES);
    if let Err(error) = (&mut reader)
        .take(PROBE_BYTES as u64)
        .read_to_end(&mut prefix)
    {
        notes.push(format!("{chain}: cannot read layer; not scanned: {error}"));
        return Vec::new();
    }
    let kind = match filetype::classify(&prefix) {
        Classification::Archive(
            kind @ (filetype::ArchiveKind::Tar
            | filetype::ArchiveKind::Gzip
            | filetype::ArchiveKind::Bzip2
            | filetype::ArchiveKind::Xz
            | filetype::ArchiveKind::Zstd),
        ) => kind,
        _ => {
            return scan_reader_in_context(
                prefix.as_slice().chain(reader),
                path,
                Some(chain),
                signatures,
                notes,
                distro,
                cancel,
            )
        }
    };
    let _reservation = match native_allowance().acquire(NATIVE_WORKSPACE_BYTES, cancel) {
        Ok(reservation) => reservation,
        Err(error) => {
            notes.push(error);
            return Vec::new();
        }
    };
    let mut detections = Vec::new();
    let mut maven_artifacts = 0;
    let mut maven_bounded = false;
    let mut visitor = |member: extract::ExtractedMember| {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        scan_member(
            &member,
            signatures,
            notes,
            distro,
            &mut detections,
            &mut maven_artifacts,
            &mut maven_bounded,
            member.depth,
            cancel,
        );
        !cancel.load(Ordering::Relaxed)
    };
    let stats = extract::extract_layer_visit(
        chain,
        &mut prefix.as_slice().chain(reader),
        kind,
        &extract::ExtractBudget::default(),
        cancel,
        &mut visitor,
    );
    if let Some(note) = stats.note(chain) {
        notes.push(note);
    }
    if stats.entries == 0 {
        notes.push(format!(
            "{chain}: no layer members were extracted; member coverage is unavailable"
        ));
    }
    annotate_packages(&mut detections, distro);
    supersede_manifest_identities(&mut detections);
    detections
}

/// Scan verified registry layers from owned spool files, in manifest order.
/// Tar and compressed tar layers stream without a whole-layer buffer, under
/// the same process-wide native payload allowance used by directory scans.
/// The caller owns spool cleanup.
pub fn scan_image_layer_files(
    display: &str,
    layers: &[(String, std::path::PathBuf)],
    cancel: &Arc<AtomicBool>,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<NativeScan, String> {
    let started = std::time::Instant::now();
    let signatures: &SignatureSet = &SIGNATURES;
    let mut notes = Vec::new();
    let mut detections = Vec::new();
    let mut distro = None;
    for (index, (name, path)) in layers.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("scan cancelled".into());
        }
        on_progress(format!("scanning layer {}/{}", index + 1, layers.len()));
        let mut file = std::fs::File::open(path)
            .map_err(|error| format!("cannot open registry layer {name}: {error}"))?;
        let chain = format!("{display}!{name}");
        detections.extend(scan_layer_reader(
            &mut file,
            path,
            &chain,
            signatures,
            &mut notes,
            &mut distro,
            cancel,
        ));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".into());
    }
    finish_metadata(&mut detections, &distro, &mut notes);
    let queries = super::enrich::queries_from(&detections);
    let components = fold(detections);
    on_progress(format!("{} components detected", components.len()));

    Ok(NativeScan {
        queries,
        notes,
        result: BinaryScanResult {
            target: display.to_string(),
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

/// Map the blobs of any OCI image layouts among the candidate files to the
/// ordered aliases their members should carry. Layouts are found by walking
/// each file's ancestors for the two-marker test — cached per directory so
/// a tree of blobs costs one check per directory, not per file.
fn oci_aliases_for(
    files: &[std::path::PathBuf],
) -> (
    std::collections::HashMap<std::path::PathBuf, String>,
    Vec<String>,
) {
    let mut aliases = std::collections::HashMap::new();
    let mut notes = Vec::new();
    let mut layout_cache: std::collections::HashMap<
        std::path::PathBuf,
        Option<std::path::PathBuf>,
    > = std::collections::HashMap::new();
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for file in files {
        let mut current = file.parent().map(Path::to_path_buf);
        while let Some(directory) = current {
            if let Some(found) = layout_cache.get(&directory) {
                if let Some(root) = found {
                    if !roots.contains(root) {
                        roots.push(root.clone());
                    }
                }
                break;
            }
            let is_root = oxaudit_archive::oci::is_layout(&directory);
            layout_cache.insert(directory.clone(), is_root.then(|| directory.clone()));
            if is_root {
                if !roots.contains(&directory) {
                    roots.push(directory);
                }
                break;
            }
            current = directory.parent().map(Path::to_path_buf);
        }
    }
    for root in roots {
        match oxaudit_archive::oci::read_layout(&root) {
            Ok(layout) => {
                for note in &layout.notes {
                    notes.push(format!("{}: {note}", root.display()));
                }
                for image in &layout.images {
                    for layer in &image.layers {
                        // First alias wins: a blob shared by two images is
                        // one physical layer; it scans once either way.
                        aliases
                            .entry(layer.blob_path.clone())
                            .or_insert_with(|| layer.alias.clone());
                    }
                }
            }
            Err(error) => notes.push(format!(
                "{}: not scanned as an OCI layout: {error}",
                root.display()
            )),
        }
    }
    (aliases, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_native_allowance_waits_until_a_retained_workspace_is_released() {
        let allowance = Arc::new(NativeAllowance::new(64));
        let cancel = Arc::new(AtomicBool::new(false));
        let first = allowance.acquire(64, &cancel).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let worker_allowance = allowance.clone();
        let worker_cancel = cancel.clone();
        let worker = std::thread::spawn(move || {
            let _permit = worker_allowance.acquire(64, &worker_cancel).unwrap();
            send.send(()).unwrap();
        });
        assert!(
            receive
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "a second workspace must wait while the allowance is exhausted"
        );
        drop(first);
        receive
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
        assert_eq!(*allowance.retained.lock().unwrap(), 0);
    }

    #[test]
    fn cancellation_while_waiting_for_native_memory_releases_no_unowned_bytes() {
        let allowance = Arc::new(NativeAllowance::new(64));
        let cancel = Arc::new(AtomicBool::new(false));
        let first = allowance.acquire(64, &cancel).unwrap();
        let worker_allowance = allowance.clone();
        let worker_cancel = cancel.clone();
        let worker =
            std::thread::spawn(move || worker_allowance.acquire(64, &worker_cancel).err().unwrap());
        cancel.store(true, Ordering::Relaxed);
        assert!(worker.join().unwrap().contains("cancelled"));
        assert_eq!(*allowance.retained.lock().unwrap(), 64);
        drop(first);
        assert_eq!(*allowance.retained.lock().unwrap(), 0);
    }

    #[test]
    fn legacy_in_memory_layers_bound_raw_fallback_and_report_the_prefix() {
        let mut bytes = vec![0; strings::MAX_FILE_BYTES + 16];
        let banner = b"\x7fELF\x02\x01\x01\0BusyBox is a multi-call binary\0BusyBox v1.38.0\0";
        bytes[..banner.len()].copy_from_slice(banner);
        let layers = [super::super::super::registry::Layer {
            name: "layer-0000.tar".into(),
            bytes,
        }];
        let scanned = scan_image_layers(
            "legacy-image",
            &layers,
            &Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .unwrap();
        assert!(scanned
            .result
            .components
            .iter()
            .any(|c| c.product == "busybox" && c.version == "1.38.0"));
        assert!(scanned.notes.iter().any(|note| note.contains("prefix") && note.contains("later content")),
            "caller-owned oversized raw layers still require bounded string extraction and honest coverage");
    }

    #[test]
    fn an_image_identity_in_a_later_layer_annotates_earlier_package_inventory() {
        let layers = vec![
            super::super::super::registry::Layer {
                name: "layer-0000.tar".into(),
                bytes: tar_with(
                    "var/lib/dpkg/status",
                    b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\n",
                ),
            },
            super::super::super::registry::Layer {
                name: "layer-0001.tar".into(),
                bytes: tar_with("etc/os-release", b"ID=debian\nVERSION_ID=12\n"),
            },
        ];
        let scanned = scan_image_layers(
            "image",
            &layers,
            &Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .unwrap();
        let package = scanned
            .queries
            .iter()
            .find(|q| q.product == "libc6")
            .unwrap();
        assert_eq!(package.ecosystem.as_deref(), Some("Debian:12"));
        assert!(scanned
            .notes
            .iter()
            .all(|note| !note.contains("no distribution identity")));
    }

    #[test]
    fn a_spooled_tar_layer_detects_members_beyond_the_file_prefix_cap() {
        use std::io::{Seek, SeekFrom, Write};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.tar");
        let mut file = std::fs::File::create(&path).unwrap();
        let size = strings::MAX_FILE_BYTES as u64 + 512;
        let mut header = tar::Header::new_gnu();
        header.set_path("oversized.bin").unwrap();
        header.set_mode(0o755);
        header.set_size(size);
        header.set_cksum();
        file.write_all(header.as_bytes()).unwrap();
        file.seek(SeekFrom::Current(size as i64)).unwrap();
        let banner = b"\x7fELF\x02\x01\x01\0BusyBox is a multi-call binary\0BusyBox v1.38.0\0";
        header.set_path("bin/busybox").unwrap();
        header.set_size(banner.len() as u64);
        header.set_cksum();
        file.write_all(header.as_bytes()).unwrap();
        file.write_all(banner).unwrap();
        file.write_all(&vec![0; 512 - banner.len() + 1024]).unwrap();
        drop(file);
        let scanned = scan_image_layer_files(
            "image",
            &[("layer-0000.tar".into(), path)],
            &Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .unwrap();
        assert!(scanned
            .result
            .components
            .iter()
            .any(|c| c.product == "busybox" && c.version == "1.38.0"));
        assert!(scanned
            .notes
            .iter()
            .any(|note| note.contains("per-member cap")));
        assert!(scanned.notes.iter().all(|note| !note.contains("prefix")));
    }

    #[test]
    fn spooled_layers_preserve_aliases_and_late_distribution_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let packages = directory.path().join("packages.tar");
        let identity = directory.path().join("identity.tar");
        std::fs::write(
            &packages,
            tar_with(
                "var/lib/dpkg/status",
                b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\n",
            ),
        )
        .unwrap();
        std::fs::write(
            &identity,
            tar_with("etc/os-release", b"ID=debian\nVERSION_ID=12\n"),
        )
        .unwrap();
        let scanned = scan_image_layer_files(
            "image@immutable",
            &[
                ("layer-0000.tar".into(), packages),
                ("layer-0001.tar".into(), identity),
            ],
            &Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .unwrap();
        let package = scanned
            .queries
            .iter()
            .find(|q| q.product == "libc6")
            .unwrap();
        assert_eq!(package.ecosystem.as_deref(), Some("Debian:12"));
        assert!(
            scanned.result.components[0].paths[0].starts_with("image@immutable!layer-0000.tar!/")
        );
        assert!(scanned
            .notes
            .iter()
            .all(|note| !note.contains("no distribution identity")));
    }

    #[test]
    fn a_missing_spooled_layer_prevents_a_successful_empty_scan() {
        let directory = tempfile::tempdir().unwrap();
        let result = scan_image_layer_files(
            "image",
            &[("layer-0000.tar".into(), directory.path().join("missing"))],
            &Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        );
        assert!(result.unwrap_err().contains("cannot open registry layer"));
    }

    #[test]
    fn text_files_are_skipped_after_reading_only_the_classification_prefix() {
        let mut reader = std::io::Cursor::new(vec![b'A'; 64 * 1024]);
        let mut notes = Vec::new();
        let detections = scan_reader_as(
            &mut reader,
            Path::new("README.txt"),
            None,
            &SIGNATURES,
            &mut notes,
        );
        assert!(detections.is_empty());
        assert!(notes.is_empty());
        assert_eq!(reader.position(), PROBE_BYTES as u64);
    }

    #[test]
    fn a_binary_banner_after_the_classification_prefix_is_still_detected() {
        let mut bytes = vec![0; PROBE_BYTES + 200];
        bytes.extend_from_slice(b"BusyBox is a multi-call binary\0BusyBox v1.38.0\0");
        let size = bytes.len();
        let mut reader = std::io::Cursor::new(bytes);
        let detections = scan_reader_as(
            &mut reader,
            Path::new("vendord"),
            None,
            &SIGNATURES,
            &mut Vec::new(),
        );
        assert!(detections
            .iter()
            .any(|detection| detection.product == "busybox"
                && detection.version.as_deref() == Some("1.38.0")));
        assert_eq!(reader.position(), size as u64);
    }

    #[test]
    fn a_file_that_cannot_be_opened_has_a_coverage_note() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.bin");
        let mut notes = Vec::new();
        assert!(scan_file(&path, &SIGNATURES, &mut notes).is_empty());
        assert!(notes
            .iter()
            .any(|note| note.contains("cannot open") && note.contains("missing.bin")));
    }

    #[test]
    fn a_file_read_error_has_a_coverage_note() {
        struct Unreadable;
        impl std::io::Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("unreadable fixture"))
            }
        }
        let mut notes = Vec::new();
        assert!(scan_reader_as(
            Unreadable,
            Path::new("broken.bin"),
            None,
            &SIGNATURES,
            &mut notes
        )
        .is_empty());
        assert!(notes
            .iter()
            .any(|note| note.contains("cannot read") && note.contains("broken.bin")));
    }

    #[test]
    fn a_truncated_file_reports_coverage_even_when_no_component_was_detected() {
        let mut notes = Vec::new();
        let detections = scan_buffer(
            "/fw.bin",
            "fw.bin",
            &[0; 8],
            true,
            &SIGNATURES,
            &mut notes,
            &mut None,
        );
        assert!(detections.is_empty());
        assert!(notes
            .iter()
            .any(|note| note.contains("prefix") && note.contains("/fw.bin")));
    }

    #[test]
    fn an_embedded_magic_search_stop_reaches_the_scan_notes() {
        let mut bytes = vec![0; 4];
        for _ in 0..100 {
            bytes.extend_from_slice(b"hsqs");
        }
        let mut notes = Vec::new();
        scan_buffer(
            "/fw.bin",
            "fw.bin",
            &bytes,
            false,
            &SIGNATURES,
            &mut notes,
            &mut None,
        );
        assert!(notes.iter().any(|note| note.contains("magic search")));
    }

    #[test]
    fn an_archive_that_cannot_be_extracted_reports_the_raw_fallback() {
        let mut notes = Vec::new();
        scan_buffer(
            "/broken.zip",
            "broken.zip",
            b"PK\x03\x04broken",
            false,
            &SIGNATURES,
            &mut notes,
            &mut None,
        );
        assert!(notes
            .iter()
            .any(|note| note.contains("no members") && note.contains("raw")));
    }

    #[test]
    fn a_missing_scan_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let result = scan(&missing, Arc::new(AtomicBool::new(false)), Arc::new(|_| {}));
        assert!(
            result.is_err(),
            "an inaccessible target must not appear to have no components"
        );
    }

    #[test]
    fn cancellation_during_the_last_image_layer_prevents_success() {
        let cancel = Arc::new(AtomicBool::new(false));
        let progress_cancel = Arc::clone(&cancel);
        let layers = vec![super::super::super::registry::Layer {
            name: "layer-0000.tar".into(),
            bytes: vec![0; 8],
        }];
        let result = scan_image_layers(
            "image",
            &layers,
            &cancel,
            Arc::new(move |_| {
                progress_cancel.store(true, Ordering::Relaxed);
            }),
        );
        assert!(result.unwrap_err().contains("cancelled"));
    }

    /// A whole on-disk OCI layout — marker, index, manifest, one tar layer
    /// carrying a detectable busybox banner — scanned as a tree: the layer's
    /// members must surface under the image's ordered alias, not the blob's
    /// 64-character hash filename.
    #[test]
    fn an_oci_layout_directory_scans_as_named_image_layers() {
        use sha2::{Digest, Sha256};
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("router-image");
        std::fs::create_dir_all(root.join("blobs/sha256")).expect("blobs");

        // A real busybox is an ELF, and text members are deliberately
        // skipped — a banner in a README is not evidence. The fixture
        // mirrors the real shape: ELF magic around the banner.
        let mut tool = Vec::new();
        tool.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
        tool.extend_from_slice(&[0_u8; 16]);
        tool.extend_from_slice(b"BusyBox v1.36.1 (2024-01-01 00:00:00 UTC) multi-call binary.\n");
        tool.extend_from_slice(&[0x5a, 0x00, 0xff, 0x00]);
        let banner = &tool;
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(banner.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "bin/busybox", std::io::Cursor::new(banner))
                .expect("layer member");
            builder.finish().expect("layer done");
        }
        let sha = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
        let layer_digest = sha(&tar_bytes);
        std::fs::write(
            root.join(format!("blobs/sha256/{layer_digest}")),
            &tar_bytes,
        )
        .expect("layer");
        let manifest = format!(
            r#"{{"schemaVersion":2,"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{layer_digest}"}}]}}"#
        );
        let manifest_digest = sha(manifest.as_bytes());
        std::fs::write(
            root.join(format!("blobs/sha256/{manifest_digest}")),
            &manifest,
        )
        .expect("manifest");
        std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
            .expect("marker");
        std::fs::write(
            root.join("index.json"),
            format!(
                r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{manifest_digest}"}}]}}"#
            ),
        )
        .expect("index");

        let mut notes = Vec::new();
        let files = candidates_with_budget(
            &root,
            MAX_BINARY_FILES,
            MAX_BINARY_BYTES,
            &std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .expect("candidates");
        let (aliases, _notes) = oci_aliases_for(&files);
        assert_eq!(aliases.len(), 1, "exactly the layer blob is aliased");
        let blob_path = root.join(format!("blobs/sha256/{layer_digest}"));
        let alias = aliases.get(&blob_path).cloned().expect("layer aliased");
        assert!(
            alias.starts_with("router-image@"),
            "alias names the image: {alias}"
        );
        assert!(alias.ends_with("!layer-0000"));

        let detections = scan_file_as(&blob_path, Some(&alias), &SIGNATURES, &mut notes);
        let busybox = detections
            .iter()
            .find(|detection| detection.product == "busybox")
            .expect("busybox detected through the layout");
        assert_eq!(busybox.version.as_deref(), Some("1.36.1"));
        assert!(
            busybox.path.contains("router-image@"),
            "the finding names the image, not the hash: {}",
            busybox.path
        );
        assert!(busybox.path.contains("!layer-0000!/bin/busybox"));
    }

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

    fn tar_with(path: &str, body: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, body)
            .expect("tar member");
        builder.into_inner().expect("tar bytes")
    }

    #[test]
    fn package_databases_inside_an_image_are_matched_to_their_distribution() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A saved Docker/OCI image is a tar of layer tars; the package
        // database and os-release ride along like any other member.
        let layer = {
            let mut builder = tar::Builder::new(Vec::new());
            let mut add = |path: &str, body: &[u8]| {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, body)
                    .expect("layer member");
            };
            add(
                "etc/os-release",
                b"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
            );
            add(
                "var/lib/dpkg/status",
                b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\n\nPackage: leftbehind\nVersion: 1.0-1\nStatus: deinstall ok config-files\n",
            );
            add("bin/busybox", b"\0\0BusyBox v1.38.0\0");
            builder.into_inner().expect("layer tar")
        };
        let image = tar_with("layer.tar", &layer);
        std::fs::write(dir.path().join("image.tar"), &image).expect("write image");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");

        let products: Vec<&str> = scanned
            .result
            .components
            .iter()
            .map(|c| c.product.as_str())
            .collect();
        assert!(products.contains(&"libc6"), "{products:?}");
        assert!(
            !products.contains(&"leftbehind"),
            "a deinstalled leftover is not inventory: {products:?}"
        );
        assert!(products.contains(&"busybox"), "{products:?}");

        let query = scanned
            .queries
            .iter()
            .find(|q| q.product == "libc6")
            .expect("libc6 is askable");
        assert_eq!(query.ecosystem.as_deref(), Some("Debian:12"));
        assert_eq!(query.osv_name.as_deref(), Some("libc6"));
        // OSV's distribution ecosystems compare the packaged version.
        assert_eq!(query.raw_version, "2.36-9+deb12u3");
    }

    #[test]
    fn alpine_images_read_the_apk_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let members: Vec<(&str, Vec<u8>)> = vec![
            (
                "etc/os-release",
                b"NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20\n".to_vec(),
            ),
            (
                "lib/apk/db/installed",
                b"P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r7\n".to_vec(),
            ),
        ];
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in &members {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, path, body.as_slice())
                .expect("member");
        }
        std::fs::write(
            dir.path().join("alpine.tar"),
            builder.into_inner().expect("tar"),
        )
        .expect("write");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");

        let musl = scanned
            .queries
            .iter()
            .find(|q| q.product == "musl")
            .expect("musl is askable");
        assert_eq!(musl.ecosystem.as_deref(), Some("Alpine:v3.20"));
        assert_eq!(musl.raw_version, "1.2.5-r0");
    }

    #[test]
    fn package_databases_without_a_distribution_identity_say_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = tar_with(
            "var/lib/dpkg/status",
            b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\n",
        );
        std::fs::write(dir.path().join("mystery.tar"), &image).expect("write");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");

        // The inventory is real and reported…
        assert!(scanned
            .result
            .components
            .iter()
            .any(|c| c.product == "libc6"));
        // …but it cannot be asked about, and the run says why.
        let query = scanned
            .queries
            .iter()
            .find(|q| q.product == "libc6")
            .expect("still askable as a component query");
        assert_eq!(query.ecosystem, None);
        assert!(scanned
            .notes
            .iter()
            .any(|note| note.contains("no distribution identity")));
    }

    #[test]
    fn nested_jars_report_their_maven_coordinates() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A Spring-Boot-shaped fat JAR: the library with its pom.properties
        // is itself a zip member of the outer jar.
        let inner = {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let properties = b"groupId=org.example\nartifactId=library\nversion=1.2.3\n";
            writer
                .start_file(
                    "META-INF/maven/org.example/library/pom.properties".to_string(),
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("zip member");
            std::io::Write::write_all(&mut writer, properties).expect("properties");
            writer.finish().expect("inner zip").into_inner()
        };
        let outer = {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            writer
                .start_file(
                    "BOOT-INF/lib/library.jar".to_string(),
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("outer member");
            std::io::Write::write_all(&mut writer, &inner).expect("nested jar");
            writer.finish().expect("outer zip").into_inner()
        };
        std::fs::write(dir.path().join("app.jar"), &outer).expect("write jar");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");

        let component = scanned
            .result
            .components
            .iter()
            .find(|c| c.product == "org.example:library")
            .expect("maven coordinates as a component");
        assert_eq!(component.version, "1.2.3");
        let query = scanned
            .queries
            .iter()
            .find(|q| q.product == "org.example:library")
            .expect("askable as Maven");
        assert_eq!(query.ecosystem.as_deref(), Some("Maven"));
        assert_eq!(query.osv_name.as_deref(), Some("org.example:library"));
    }

    #[test]
    fn incomplete_pom_properties_are_ignored_rather_than_guessed() {
        assert!(is_pom_properties_path(
            "app.jar!/META-INF/maven/org.example/library/pom.properties"
        ));
        assert!(!is_pom_properties_path("META-INF/maven/pom.properties"));
        assert!(!is_pom_properties_path("pom.properties"));
        // Missing any coordinate is not a partial query.
        assert_eq!(parse_pom_properties(b"artifactId=only\n"), None);
        assert_eq!(
            parse_pom_properties(b"groupId=g\nartifactId=a\nversion=1\n"),
            Some(("g".into(), "a".into(), "1".into()))
        );
    }

    #[test]
    fn maven_artifacts_are_answered_from_the_local_database() {
        let mut db = crate::advisories::store::AdvisoryDb::open_in_memory().unwrap();
        let record = serde_json::json!({
            "id": "CVE-2099-3333",
            "severity": [{ "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            "affected": [{
                "package": { "ecosystem": "Maven", "name": "org.example:library" },
                "ranges": [{ "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.3.0"}] }]
            }]
        });
        let packages = vec![("Maven".to_string(), "org.example:library".to_string())];
        db.insert_record("CVE-2099-3333", None, &record, &packages)
            .unwrap();
        db.finish_update(&["Maven".to_string()], 900, 900).unwrap();

        let queries = vec![super::super::enrich::ComponentQuery {
            key: super::super::enrich::component_key("org.example:library", "1.2.3"),
            vendor: String::new(),
            product: "org.example:library".to_string(),
            version: "1.2.3".to_string(),
            raw_version: "1.2.3".to_string(),
            ecosystem: Some("Maven".to_string()),
            osv_name: Some("org.example:library".to_string()),
        }];
        let enrichment = super::super::enrich::enrich_local(&db, &queries);
        assert!(enrichment.notes.is_empty(), "{:?}", enrichment.notes);
        let found = enrichment
            .found
            .get(&queries[0].key)
            .expect("answered offline");
        assert_eq!(found[0].cve_id, "CVE-2099-3333");
        assert_eq!(found[0].fixed_in.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn manifest_only_jars_report_their_declared_identity_as_inventory() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No pom.properties: a Gradle-built JAR declaring title and version.
        let jar = {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            writer
                .start_file(
                    "META-INF/MANIFEST.MF".to_string(),
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("member");
            std::io::Write::write_all(
                &mut writer,
                b"Manifest-Version: 1.0\nImplementation-Title: Company Util Lib\nImplementation-Version: 2.4.1\n",
            )
            .expect("manifest");
            writer.finish().expect("jar").into_inner()
        };
        std::fs::write(dir.path().join("util.jar"), &jar).expect("write jar");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");
        let component = scanned
            .result
            .components
            .iter()
            .find(|c| c.product == "Company Util Lib")
            .expect("manifest identity as inventory");
        assert_eq!(component.version, "2.4.1");
        // No ecosystem: the manifest never names one, so the identity is
        // inventory — present as a component, never answered.
        assert!(scanned
            .queries
            .iter()
            .all(|query| query.product != "Company Util Lib" || query.ecosystem.is_none()));
        assert!(component.vulnerabilities.is_empty());
    }

    #[test]
    fn bundle_identities_and_continuation_lines_parse() {
        assert_eq!(
            parse_manifest_identity(
                b"Bundle-SymbolicName: org.example.lib;singleton:=true\nBundle-Version: 1.4.0\n"
            ),
            Some(("org.example.lib".into(), "1.4.0".into()))
        );
        // Continuation joins by consuming the marker space — the manifest
        // spec's rule, not a lost character.
        assert_eq!(
            parse_manifest_identity(
                b"Implementation-Title: Spring\n Core\nImplementation-Version: 6.1.0\n"
            ),
            Some(("SpringCore".into(), "6.1.0".into()))
        );
        // A name without a version is not a versioned identity.
        assert_eq!(
            parse_manifest_identity(b"Implementation-Title: only-title\n"),
            None
        );
    }

    #[test]
    fn maven_coordinates_supersede_the_same_jars_manifest_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let jar = {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            writer
                .start_file(
                    "META-INF/MANIFEST.MF".to_string(),
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("member");
            std::io::Write::write_all(
                &mut writer,
                b"Implementation-Title: library\nImplementation-Version: 1.2.3\n",
            )
            .expect("manifest");
            writer
                .start_file(
                    "META-INF/maven/org.example/library/pom.properties".to_string(),
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("member");
            std::io::Write::write_all(
                &mut writer,
                b"groupId=org.example\nartifactId=library\nversion=1.2.3\n",
            )
            .expect("properties");
            writer.finish().expect("jar").into_inner()
        };
        std::fs::write(dir.path().join("both.jar"), &jar).expect("write jar");

        let scanned = scan(
            dir.path(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(|_| {}),
        )
        .expect("scan");
        // One identity, the queryable one.
        assert!(scanned
            .result
            .components
            .iter()
            .any(|c| c.product == "org.example:library"));
        assert!(scanned
            .result
            .components
            .iter()
            .all(|c| c.product != "library" || c.product == "org.example:library"));
    }
}
