//! Matching component signatures against a binary's strings.
//!
//! The method is cve-bin-tool's, and it is a good one: a component is present
//! if the binary carries a string only that component emits, and its version is
//! whatever a capture group pulls out of a nearby string. What is different
//! here is the execution.
//!
//! cve-bin-tool evaluates its checkers one at a time — 365 checkers, each with
//! several patterns, re-scanning the same strings blob for every one. Measured
//! on a 21,000-file Debian tree that is about five minutes. Here every pattern
//! from every signature goes into a single [`RegexSet`], so one pass over the
//! blob says which signatures could possibly match, and only those few get
//! their capture-bearing patterns run. The expensive regexes are executed on a
//! handful of candidates instead of all of them.
//!
//! Rust's `regex` crate also guarantees linear-time matching, so a pathological
//! pattern cannot make a scan hang on attacker-supplied firmware — which is a
//! real consideration when the input is an untrusted image.

use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::bytes::{BytePattern, Encoding, VersionFormula};

/// How a component was recognized. A filename match is much stronger evidence
/// than a string match, and the UI says which one it was rather than presenting
/// a guess and a certainty identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Evidence {
    /// The file contains a string characteristic of the component.
    Content,
    /// The file is named like the component (`libssl.so.3`).
    Filename,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub vendor: String,
    pub product: String,
    /// `None` when the component was recognized but no version could be read.
    /// That is a real and useful state — "there is an OpenSSL in this image and
    /// I cannot tell which" is worth showing — so it is not silently dropped.
    pub version: Option<String>,
    pub evidence: Evidence,
}

/// One component's detection rules, as authored in `signatures.toml`.
#[derive(Debug, Deserialize)]
pub struct SignatureSpec {
    pub vendor: String,
    pub product: String,
    /// Regexes matched against the file's *name*, not its path.
    #[serde(default)]
    pub filename_patterns: Vec<String>,
    /// Regexes whose presence marks the component, without giving a version.
    #[serde(default)]
    pub contains: Vec<String>,
    /// Regexes with exactly one capture group: the version.
    #[serde(default)]
    pub version_patterns: Vec<String>,
    /// Captured versions to reject — build identifiers and the like that look
    /// like versions but are not.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Byte patterns over the file's raw content, for libraries that compile
    /// their version in as a number and never spell it out.
    #[serde(default)]
    pub byte_patterns: Vec<BytePatternSpec>,
    /// Whether a version pattern matching is enough to say the component is
    /// present.
    ///
    /// True for almost every signature, because a version pattern normally
    /// names the library — `OpenSSL 3.5.6 7 Apr 2026`, `libpng version 1.6.48`.
    /// pcre2 is the exception: its version string is `10.47 2025-10-21`, which
    /// says nothing about pcre2 and would claim any file carrying a similar
    /// date-suffixed number. Such a signature must earn its identity from a
    /// `contains` or filename match and use the version pattern only to read
    /// the number.
    #[serde(default = "default_true")]
    pub version_implies_identity: bool,
    /// Distribution package names that mean this component.
    ///
    /// Debian calls zstd `libzstd`; NVD's CPE calls it `facebook:zstandard`.
    /// Without a mapping the same library detected by an ELF package note and
    /// by a signature becomes two rows that never merge — and the note-derived
    /// one can never be looked up in NVD, because a package note carries no
    /// CPE vendor.
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// A version read out of code rather than text.
#[derive(Debug, Deserialize)]
pub struct BytePatternSpec {
    /// Hex with nibble wildcards: `f3 0f 1e fa b8 .. .. 00 00 c3`.
    pub pattern: String,
    /// Where inside the match the number begins.
    pub capture_offset: usize,
    pub encoding: Encoding,
    pub formula: VersionFormula,
    /// The version-number range this library could plausibly report.
    ///
    /// Required, not optional. Measured on a real libzstd.1.5.7.dylib, the
    /// pattern for `movz w0, #imm; ret` matches 34 times and yields three
    /// "versions": the real 1.5.7 plus 2.73.52 and 6.55.34, both of which are
    /// ordinary functions returning a small constant. Bounding the range is
    /// what separates the one from the other, and asking the author for it
    /// forces them to think about the library's version space.
    pub min: u64,
    pub max: u64,
    /// A second field to read, for libraries that expose major and minor
    /// through separate accessors and have no combined constant.
    ///
    /// nettle is the case: `nettle_version_major()` and
    /// `nettle_version_minor()` are two one-instruction functions the compiler
    /// emits adjacently. The two are packed as `(first << 8) | second`, which
    /// `major-minor` then renders.
    #[serde(default)]
    pub capture_offset_2: Option<usize>,
    /// What the pattern is, for whoever reads the file next.
    #[serde(default)]
    pub note: String,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct SignatureFile {
    #[serde(default)]
    signature: Vec<SignatureSpec>,
}

#[derive(Debug, Deserialize)]
struct SignatureProvenanceFile {
    pack: SignaturePackProvenance,
    fixtures: SignatureFixtureCoverage,
}

#[derive(Debug, Deserialize)]
struct SignaturePackProvenance {
    schema_version: u32,
    id: String,
    version: String,
    authors: Vec<String>,
    source: String,
    license: String,
    creation_method: String,
    signatures_sha256: String,
    architectures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SignatureFixtureCoverage {
    positive_suites: Vec<String>,
    negative_suites: Vec<String>,
    verified_products: Vec<String>,
    unverified_products: Vec<String>,
    unverified_reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureProvenanceStatus {
    pub pack_id: String,
    pub version: String,
    pub authors: Vec<String>,
    pub source: String,
    pub license: String,
    pub creation_method: String,
    pub content_sha256: String,
    pub architectures: Vec<String>,
    pub signature_count: usize,
    pub verified_fixture_count: usize,
    pub verified_products: Vec<String>,
    pub unverified_products: Vec<String>,
    pub unverified_reason: String,
    pub positive_suites: Vec<String>,
    pub negative_suites: Vec<String>,
}

#[derive(Debug)]
struct Compiled {
    vendor: String,
    product: String,
    aliases: Vec<String>,
    version_patterns: Vec<Regex>,
    ignore: Vec<Regex>,
    byte_patterns: Vec<CompiledBytePattern>,
}

#[derive(Debug)]
struct CompiledBytePattern {
    pattern: BytePattern,
    capture_offset: usize,
    capture_offset_2: Option<usize>,
    encoding: Encoding,
    formula: VersionFormula,
    min: u64,
    max: u64,
}

impl CompiledBytePattern {
    /// Every plausible version this pattern finds in `raw`.
    fn versions(&self, raw: &[u8]) -> Vec<String> {
        let mut found = Vec::new();
        for offset in self.pattern.find_all(raw) {
            let Some(window) = raw.get(offset + self.capture_offset..) else {
                continue;
            };
            let Some(mut value) = self.encoding.read(window) else {
                continue;
            };
            if let Some(second) = self.capture_offset_2 {
                let Some(window2) = raw.get(offset + second..) else {
                    continue;
                };
                let Some(low) = self.encoding.read(window2) else {
                    continue;
                };
                // Both halves must fit a byte; anything else means this is not
                // the accessor pair the pattern was written for.
                if value > 0xff || low > 0xff {
                    continue;
                }
                value = (value << 8) | low;
            }
            if value < self.min || value > self.max {
                continue;
            }
            if let Some(version) = self.formula.render(value) {
                if !found.contains(&version) {
                    found.push(version);
                }
            }
        }
        found
    }
}

#[derive(Debug)]
pub struct SignatureSet {
    compiled: Vec<Compiled>,
    /// Every `contains` and `version_patterns` entry, flattened.
    content_set: RegexSet,
    /// `content_set` pattern index → index into `compiled`.
    content_owner: Vec<usize>,
    filename_set: RegexSet,
    filename_owner: Vec<usize>,
}

impl SignatureSet {
    pub fn compile(specs: Vec<SignatureSpec>) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(specs.len());
        let mut content_patterns = Vec::new();
        let mut content_owner = Vec::new();
        let mut filename_patterns = Vec::new();
        let mut filename_owner = Vec::new();

        for (index, spec) in specs.into_iter().enumerate() {
            if spec.product.trim().is_empty() {
                return Err(format!("signature {index} has no product"));
            }
            // Byte patterns cannot identify a component on their own, so one
            // that has nothing else can never fire and would sit in the file
            // looking like coverage it does not provide.
            if !spec.byte_patterns.is_empty()
                && spec.contains.is_empty()
                && spec.filename_patterns.is_empty()
            {
                return Err(format!(
                    "signature {} has byte patterns but nothing to identify it by; a byte \
pattern supplies a version, never an identity",
                    spec.product
                ));
            }
            if spec.version_patterns.is_empty()
                && spec.contains.is_empty()
                && spec.filename_patterns.is_empty()
            {
                return Err(format!(
                    "signature {} has no way to match anything",
                    spec.product
                ));
            }

            let mut version_patterns = Vec::with_capacity(spec.version_patterns.len());
            for pattern in &spec.version_patterns {
                let regex = Regex::new(pattern).map_err(|e| {
                    format!("{}: bad version pattern {pattern:?}: {e}", spec.product)
                })?;
                // A version pattern with no capture group would match and then
                // yield nothing, which reads downstream as "detected, version
                // unknown" — a silent failure that is hard to spot in data.
                if regex.captures_len() != 2 {
                    return Err(format!(
                        "{}: version pattern {pattern:?} must have exactly one capture group, has {}",
                        spec.product,
                        regex.captures_len() - 1
                    ));
                }
                version_patterns.push(regex);
            }

            let identity_patterns: Vec<&String> = if spec.version_implies_identity {
                spec.contains
                    .iter()
                    .chain(spec.version_patterns.iter())
                    .collect()
            } else {
                if spec.contains.is_empty() && spec.filename_patterns.is_empty() {
                    return Err(format!(
                        "{}: version_implies_identity is false but there is nothing else to \
identify it by",
                        spec.product
                    ));
                }
                spec.contains.iter().collect()
            };
            for pattern in identity_patterns {
                Regex::new(pattern)
                    .map_err(|e| format!("{}: bad pattern {pattern:?}: {e}", spec.product))?;
                content_patterns.push(pattern.clone());
                content_owner.push(index);
            }
            for pattern in &spec.filename_patterns {
                Regex::new(pattern).map_err(|e| {
                    format!("{}: bad filename pattern {pattern:?}: {e}", spec.product)
                })?;
                filename_patterns.push(pattern.clone());
                filename_owner.push(index);
            }

            let ignore = spec
                .ignore
                .iter()
                .map(|pattern| {
                    Regex::new(pattern).map_err(|e| {
                        format!("{}: bad ignore pattern {pattern:?}: {e}", spec.product)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let mut byte_patterns = Vec::with_capacity(spec.byte_patterns.len());
            for byte_spec in &spec.byte_patterns {
                let pattern = BytePattern::parse(&byte_spec.pattern).map_err(|e| {
                    format!(
                        "{}: bad byte pattern {:?}: {e}",
                        spec.product, byte_spec.pattern
                    )
                })?;
                if byte_spec.min >= byte_spec.max {
                    return Err(format!(
                        "{}: byte pattern {:?} has an empty plausible range ({}..{})",
                        spec.product, byte_spec.pattern, byte_spec.min, byte_spec.max
                    ));
                }
                if byte_spec.capture_offset >= pattern.len() {
                    return Err(format!(
                        "{}: byte pattern {:?} captures at {} but is only {} bytes long",
                        spec.product,
                        byte_spec.pattern,
                        byte_spec.capture_offset,
                        pattern.len()
                    ));
                }
                if let Some(second) = byte_spec.capture_offset_2 {
                    if second >= pattern.len() {
                        return Err(format!(
                            "{}: byte pattern {:?} has a second capture at {} but is only {} bytes long",
                            spec.product, byte_spec.pattern, second, pattern.len()
                        ));
                    }
                }
                byte_patterns.push(CompiledBytePattern {
                    pattern,
                    capture_offset_2: byte_spec.capture_offset_2,
                    capture_offset: byte_spec.capture_offset,
                    encoding: byte_spec.encoding,
                    formula: byte_spec.formula,
                    min: byte_spec.min,
                    max: byte_spec.max,
                });
            }

            compiled.push(Compiled {
                aliases: spec
                    .aliases
                    .iter()
                    .map(|alias| alias.to_ascii_lowercase())
                    .collect(),
                vendor: spec.vendor,
                product: spec.product,
                version_patterns,
                ignore,
                byte_patterns,
            });
        }

        Ok(Self {
            content_set: RegexSet::new(&content_patterns).map_err(|e| e.to_string())?,
            content_owner,
            filename_set: RegexSet::new(&filename_patterns).map_err(|e| e.to_string())?,
            filename_owner,
            compiled,
        })
    }

    pub fn parse_toml(raw: &str) -> Result<Self, String> {
        let file: SignatureFile =
            toml::from_str(raw).map_err(|e| format!("signatures.toml is not valid TOML: {e}"))?;
        Self::compile(file.signature)
    }

    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    pub fn products(&self) -> impl Iterator<Item = &str> {
        self.compiled.iter().map(|c| c.product.as_str())
    }

    /// The canonical `(vendor, product)` for a distribution package name.
    ///
    /// A package note says `libzstd`; NVD is keyed on `facebook:zstandard`.
    /// Resolving one to the other is what lets a note-detected component be
    /// looked up at all, and what stops it appearing twice alongside the same
    /// library found by signature.
    pub fn resolve_alias(&self, package_name: &str) -> Option<(&str, &str)> {
        let needle = package_name.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        self.compiled
            .iter()
            .find(|c| {
                c.product.eq_ignore_ascii_case(&needle)
                    || c.aliases.iter().any(|alias| alias == &needle)
            })
            .map(|c| (c.vendor.as_str(), c.product.as_str()))
    }

    /// Match one file. `file_name` is the base name; `blob` is its strings.
    ///
    /// A component detected at several versions inside one file yields one
    /// detection per version: firmware images genuinely do carry two builds of
    /// the same library, and collapsing them would hide the older one.
    pub fn detect(&self, file_name: &str, blob: &str, raw: &[u8]) -> Vec<Detection> {
        let mut candidates: Vec<Option<Evidence>> = vec![None; self.compiled.len()];

        // Byte patterns deliberately do not appear here. A code shape says
        // nothing about *which* library it is: measured across a 21,000-file
        // tree, `movz w0,#imm; ret` bounded to zstd's version range fires in
        // about forty unrelated binaries. Identity has to come from a string
        // or a filename; byte patterns only supply the version once it has.
        for index in self.content_set.matches(blob) {
            candidates[self.content_owner[index]] = Some(Evidence::Content);
        }
        for index in self.filename_set.matches(file_name) {
            candidates[self.filename_owner[index]] = Some(Evidence::Filename);
        }

        let mut detections = Vec::new();
        for (index, evidence) in candidates.into_iter().enumerate() {
            let Some(evidence) = evidence else { continue };
            let signature = &self.compiled[index];

            let mut versions: Vec<String> = Vec::new();
            for byte_pattern in &signature.byte_patterns {
                for version in byte_pattern.versions(raw) {
                    if signature.ignore.iter().any(|i| i.is_match(&version)) {
                        continue;
                    }
                    if !versions.contains(&version) {
                        versions.push(version);
                    }
                }
            }
            for pattern in &signature.version_patterns {
                for capture in pattern.captures_iter(blob) {
                    let Some(found) = capture.get(1) else {
                        continue;
                    };
                    let version = found.as_str().trim().to_string();
                    if version.is_empty() {
                        continue;
                    }
                    if signature.ignore.iter().any(|i| i.is_match(&version)) {
                        continue;
                    }
                    if !versions.contains(&version) {
                        versions.push(version);
                    }
                }
            }
            versions.sort();

            if versions.is_empty() {
                detections.push(Detection {
                    vendor: signature.vendor.clone(),
                    product: signature.product.clone(),
                    version: None,
                    evidence,
                });
                continue;
            }
            for version in versions {
                detections.push(Detection {
                    vendor: signature.vendor.clone(),
                    product: signature.product.clone(),
                    version: Some(version),
                    evidence,
                });
            }
        }
        detections
    }
}

/// The signature data shipped with oxAudit.
///
/// These patterns are our own, derived from binaries with known versions — see
/// `docs/binary-signatures.md`. They are deliberately *not* transcribed from
/// cve-bin-tool, whose checkers are GPL-3.0-or-later.
pub static SIGNATURES_TOML: &str = include_str!("signatures.toml");
pub static SIGNATURES_PROVENANCE_TOML: &str = include_str!("signatures.provenance.toml");

pub fn signature_provenance_status() -> Result<SignatureProvenanceStatus, String> {
    validate_signature_provenance(SIGNATURES_TOML, SIGNATURES_PROVENANCE_TOML)
}

fn validate_signature_provenance(
    signatures_toml: &str,
    provenance_toml: &str,
) -> Result<SignatureProvenanceStatus, String> {
    let signatures: SignatureFile =
        toml::from_str(signatures_toml).map_err(|error| error.to_string())?;
    let provenance: SignatureProvenanceFile =
        toml::from_str(provenance_toml).map_err(|error| error.to_string())?;
    let pack = provenance.pack;
    let fixtures = provenance.fixtures;
    if pack.schema_version != 1 {
        return Err(format!(
            "unsupported signature provenance schema {}",
            pack.schema_version
        ));
    }
    for (field, value) in [
        ("pack id", pack.id.as_str()),
        ("version", pack.version.as_str()),
        ("source", pack.source.as_str()),
        ("license", pack.license.as_str()),
        ("creation method", pack.creation_method.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("signature provenance {field} is empty"));
        }
    }
    if pack.authors.is_empty()
        || pack.authors.iter().any(|author| author.trim().is_empty())
        || pack.architectures.is_empty()
    {
        return Err("signature provenance authors and architectures are required".into());
    }
    if pack.license != "Apache-2.0" || pack.creation_method != "independently-derived" {
        return Err(
            "signature provenance must preserve the Apache-2.0 independently-derived boundary"
                .into(),
        );
    }
    let actual_hash = format!("{:x}", Sha256::digest(signatures_toml.as_bytes()));
    if actual_hash != pack.signatures_sha256.to_ascii_lowercase() {
        return Err("signature data changed without a provenance hash update".into());
    }
    if fixtures.positive_suites.is_empty()
        || fixtures.negative_suites.is_empty()
        || fixtures.unverified_reason.trim().is_empty()
    {
        return Err("signature fixture suites and unverified rationale are required".into());
    }

    let products: std::collections::BTreeSet<String> = signatures
        .signature
        .iter()
        .map(|signature| signature.product.clone())
        .collect();
    if products.len() != signatures.signature.len() {
        return Err("signature products must be unique for provenance accounting".into());
    }
    let verified: std::collections::BTreeSet<String> =
        fixtures.verified_products.iter().cloned().collect();
    let unverified: std::collections::BTreeSet<String> =
        fixtures.unverified_products.iter().cloned().collect();
    if verified.len() != fixtures.verified_products.len()
        || unverified.len() != fixtures.unverified_products.len()
        || !verified.is_disjoint(&unverified)
    {
        return Err("fixture coverage contains duplicate product declarations".into());
    }
    let declared: std::collections::BTreeSet<String> =
        verified.union(&unverified).cloned().collect();
    if declared != products {
        let missing: Vec<_> = products.difference(&declared).cloned().collect();
        let invented: Vec<_> = declared.difference(&products).cloned().collect();
        return Err(format!(
            "fixture coverage does not account for every signature; missing={missing:?}, invented={invented:?}"
        ));
    }

    Ok(SignatureProvenanceStatus {
        pack_id: pack.id,
        version: pack.version,
        authors: pack.authors,
        source: pack.source,
        license: pack.license,
        creation_method: pack.creation_method,
        content_sha256: actual_hash,
        architectures: pack.architectures,
        signature_count: products.len(),
        verified_fixture_count: verified.len(),
        verified_products: verified.into_iter().collect(),
        unverified_products: unverified.into_iter().collect(),
        unverified_reason: fixtures.unverified_reason,
        positive_suites: fixtures.positive_suites,
        negative_suites: fixtures.negative_suites,
    })
}

pub static SIGNATURES: Lazy<SignatureSet> = Lazy::new(|| {
    signature_provenance_status().expect("bundled signature provenance must validate");
    SignatureSet::parse_toml(SIGNATURES_TOML).expect("bundled signatures must compile")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_signature_provenance_accounts_for_verified_and_unverified_health() {
        let status = signature_provenance_status().unwrap();
        assert_eq!(status.signature_count, 71);
        assert_eq!(status.verified_fixture_count, 69);
        assert_eq!(status.unverified_products.len(), 2);
        assert_eq!(
            status.signature_count,
            status.verified_fixture_count + status.unverified_products.len()
        );
    }

    fn spec(
        product: &str,
        contains: &[&str],
        versions: &[&str],
        filenames: &[&str],
    ) -> SignatureSpec {
        SignatureSpec {
            vendor: product.to_string(),
            product: product.to_string(),
            filename_patterns: filenames.iter().map(|s| s.to_string()).collect(),
            contains: contains.iter().map(|s| s.to_string()).collect(),
            version_patterns: versions.iter().map(|s| s.to_string()).collect(),
            ignore: Vec::new(),
            byte_patterns: Vec::new(),
            aliases: Vec::new(),
            version_implies_identity: true,
        }
    }

    #[test]
    fn a_version_pattern_without_a_capture_group_is_rejected_at_compile_time() {
        // It would otherwise match happily and report every hit as
        // "version unknown", which looks like a detection problem rather than
        // an authoring mistake.
        let error = SignatureSet::compile(vec![spec("zlib", &[], &[r"zlib [0-9.]+"], &[])])
            .expect_err("must not compile");
        assert!(error.contains("capture group"), "{error}");
    }

    #[test]
    fn a_signature_that_can_never_match_is_rejected() {
        let error = SignatureSet::compile(vec![spec("ghost", &[], &[], &[])])
            .expect_err("must not compile");
        assert!(error.contains("no way to match"), "{error}");
    }

    #[test]
    fn a_byte_pattern_with_nothing_to_identify_it_by_is_rejected() {
        // It can never fire, and it would sit in the signature file looking
        // like coverage that is not there.
        let mut signature = spec("ghost", &[], &[], &[]);
        signature.byte_patterns = vec![BytePatternSpec {
            pattern: "f3 0f 1e fa b8 .. .. .. 00 c3".into(),
            capture_offset: 5,
            encoding: Encoding::U32Le,
            formula: VersionFormula::Decimal10000,
            min: 10000,
            max: 19999,
            capture_offset_2: None,
            note: String::new(),
        }];
        let error = SignatureSet::compile(vec![signature]).expect_err("must not compile");
        assert!(error.contains("never an identity"), "{error}");
    }

    #[test]
    fn a_byte_pattern_alone_does_not_claim_a_component() {
        // Measured across a 21,000-file tree: `movz w0,#imm; ret` bounded to
        // zstd's range fires in about forty unrelated binaries. Identity must
        // come from a string or a filename.
        let set = &*SIGNATURES;
        // The exact bytes of `movz w0,#0x290b; ret` — a real zstd version
        // constant — in a file with nothing else to say it is zstd.
        let raw = [0x60u8, 0x21, 0x85, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
        let hits = set.detect("vendor-blob", "nothing to see here\n", &raw);
        assert!(
            !hits.iter().any(|d| d.product == "zstandard"),
            "a bare code shape claimed zstd: {hits:?}"
        );

        // With zstd's own error string present, both identity and version follow.
        let hits = set.detect(
            "vendor-blob",
            "Frame requires too much memory for decoding\n",
            &raw,
        );
        let zstd: Vec<_> = hits.iter().filter(|d| d.product == "zstandard").collect();
        assert_eq!(zstd.len(), 1, "expected one zstd detection, got {hits:?}");
        assert_eq!(zstd[0].version.as_deref(), Some("1.5.7"));
    }

    #[test]
    fn a_content_match_yields_the_captured_version() {
        let set = SignatureSet::compile(vec![spec(
            "openssl",
            &[r"part of OpenSSL"],
            &[r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+)"],
            &[],
        )])
        .expect("compiles");

        let hits = set.detect(
            "libcrypto.so.3",
            "part of OpenSSL\nOpenSSL 3.0.2 15 Mar 2022\n",
            &[],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].product, "openssl");
        assert_eq!(hits[0].version.as_deref(), Some("3.0.2"));
        assert_eq!(hits[0].evidence, Evidence::Content);
    }

    #[test]
    fn filename_evidence_outranks_content_evidence() {
        // Both hold here. Reporting the weaker one would understate what we
        // know, and the UI ranks findings by exactly this.
        let set = SignatureSet::compile(vec![spec(
            "openssl",
            &[r"part of OpenSSL"],
            &[r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+)"],
            &[r"^libcrypto\.so"],
        )])
        .expect("compiles");

        let hits = set.detect("libcrypto.so.3", "part of OpenSSL\nOpenSSL 3.0.2 x\n", &[]);
        assert_eq!(hits[0].evidence, Evidence::Filename);
    }

    #[test]
    fn a_component_recognized_without_a_version_is_still_reported() {
        // Silence here would be the worst outcome: the component is present
        // and unidentifiable, which is precisely what a firmware auditor needs
        // to be told.
        let set = SignatureSet::compile(vec![spec(
            "busybox",
            &[r"BusyBox is a multi-call binary"],
            &[r"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)"],
            &[],
        )])
        .expect("compiles");

        let hits = set.detect("busybox", "BusyBox is a multi-call binary\n", &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].version, None);
    }

    #[test]
    fn two_builds_of_one_library_in_a_single_image_are_both_reported() {
        // Vendor firmware routinely ships a second, older copy alongside the
        // one the SDK links. Collapsing to a single version hides it.
        let set = SignatureSet::compile(vec![spec(
            "openssl",
            &[],
            &[r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)"],
            &[],
        )])
        .expect("compiles");

        let hits = set.detect("firmware.bin", "OpenSSL 1.0.2k x\nOpenSSL 3.0.2 y\n", &[]);
        let versions: Vec<_> = hits.iter().filter_map(|h| h.version.as_deref()).collect();
        assert_eq!(versions, vec!["1.0.2k", "3.0.2"]);
    }

    #[test]
    fn an_ignored_capture_does_not_become_a_version() {
        let mut signature = spec("linux", &[], &[r"Linux version ([0-9][0-9.]+)"], &[]);
        signature.ignore = vec![r"^0\.0".to_string()];
        let set = SignatureSet::compile(vec![signature]).expect("compiles");

        let hits = set.detect("vmlinuz", "Linux version 0.0.0 junk\n", &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].version, None, "the only candidate was ignored");
    }

    #[test]
    fn signatures_from_different_components_do_not_bleed_into_each_other() {
        // The prefilter maps pattern indices back to signatures; getting that
        // mapping wrong attributes one library's version to another, which is
        // the kind of error that is invisible until someone checks by hand.
        let set = SignatureSet::compile(vec![
            spec("zlib", &[], &[r"inflate ([0-9.]+) Copyright"], &[]),
            spec("curl", &[], &[r"\ncurl ([0-9.]+)"], &[]),
        ])
        .expect("compiles");

        let hits = set.detect("blob", "inflate 1.2.11 Copyright\n\ncurl 8.7.1\n", &[]);
        let mut pairs: Vec<_> = hits
            .iter()
            .map(|h| (h.product.as_str(), h.version.as_deref().unwrap_or("")))
            .collect();
        pairs.sort();
        assert_eq!(pairs, vec![("curl", "8.7.1"), ("zlib", "1.2.11")]);
    }

    #[test]
    fn a_version_pattern_that_names_nothing_cannot_claim_the_component() {
        // pcre2's version string is `10.47 2025-10-21`. Letting that stand as
        // identity would attribute any file carrying a similar date-suffixed
        // number to pcre2.
        let set = &*SIGNATURES;
        let bare = set.detect("firmware.bin", "\n10.47 2025-10-21\n", &[]);
        assert!(
            !bare.iter().any(|d| d.product == "pcre2"),
            "a bare version-and-date claimed pcre2: {bare:?}"
        );

        // With a real pcre2 marker present, both identity and version follow.
        let real = set.detect(
            "firmware.bin",
            "BSR_ANYCRLF)\nLIMIT_DEPTH=\n10.47 2025-10-21\n",
            &[],
        );
        let pcre2: Vec<_> = real.iter().filter(|d| d.product == "pcre2").collect();
        assert_eq!(pcre2.len(), 1, "expected one pcre2 detection, got {real:?}");
        assert_eq!(pcre2[0].version.as_deref(), Some("10.47"));
    }

    #[test]
    fn a_signature_with_no_identity_of_its_own_is_refused_at_compile_time() {
        let mut signature = spec("ghost", &[], &[r"v([0-9.]+)"], &[]);
        signature.version_implies_identity = false;
        let error = SignatureSet::compile(vec![signature]).expect_err("must not compile");
        assert!(error.contains("nothing else to identify it by"), "{error}");
    }

    #[test]
    fn a_distribution_package_name_resolves_to_its_cpe_identity() {
        // Debian ships zstd as `libzstd`; NVD knows it as facebook:zstandard.
        // Without this the same library is two rows, and the one found by ELF
        // package note can never be looked up.
        let set = &*SIGNATURES;
        assert_eq!(
            set.resolve_alias("libzstd"),
            Some(("facebook", "zstandard"))
        );
        assert_eq!(
            set.resolve_alias("LIBZSTD"),
            Some(("facebook", "zstandard"))
        );
        // A product name resolves to itself, so callers need only one path.
        assert_eq!(
            set.resolve_alias("zstandard"),
            Some(("facebook", "zstandard"))
        );
    }

    #[test]
    fn an_unknown_package_name_resolves_to_nothing_rather_than_a_guess() {
        let set = &*SIGNATURES;
        assert_eq!(set.resolve_alias("some-vendor-blob"), None);
        assert_eq!(set.resolve_alias(""), None);
        assert_eq!(set.resolve_alias("   "), None);
    }

    /// Every bundled signature's CPE identity, checked once against NVD's live
    /// API and recorded here.
    ///
    /// This is a tripwire, not a restatement of the data file. A vendor or
    /// product that is not NVD's spelling returns zero CVEs rather than an
    /// error, so the scan reads as clean instead of broken. `sqlite3` cost
    /// exactly that: `cpe:2.3:a:sqlite:sqlite:3.46.1` returns 7 CVEs and
    /// `cpe:2.3:a:sqlite:sqlite3:3.46.1` returns none. Renaming a product must
    /// fail this test and send whoever did it back to the API.
    const VERIFIED_CPE_IDENTITIES: [(&str, &str); 37] = [
        ("openssl", "openssl"),
        ("sqlite", "sqlite"),
        ("tukaani", "xz"),
        ("pcre", "pcre2"),
        // Firmware staples, each resolved against NVD's CPE dictionary and
        // then confirmed to return CVEs for a real version.
        ("dropbear_ssh_project", "dropbear_ssh"),
        ("thekelleys", "dnsmasq"),
        ("lighttpd", "lighttpd"),
        ("w1.fi", "wpa_supplicant"),
        ("w1.fi", "hostapd"),
        ("openbsd", "openssh"),
        ("net-snmp", "net-snmp"),
        ("libssh", "libssh"),
        ("strongswan", "strongswan"),
        ("tcpdump", "libpcap"),
        ("lua", "lua"),
        ("openvpn", "openvpn"),
        ("avahi", "avahi"),
        ("libjpeg-turbo", "libjpeg-turbo"),
        ("denx", "u-boot"),
        ("nghttp2", "nghttp2"),
        ("c-ares", "c-ares"),
        ("arm", "mbed_tls"),
        ("eclipse", "mosquitto"),
        ("nettle_project", "nettle"),
        ("gnu", "libmicrohttpd"),
        ("freetype", "freetype"),
        ("jansson_project", "jansson"),
        ("wolfssl", "wolfssl"),
        ("netfilter", "iptables"),
        ("libarchive", "libarchive"),
        ("libcap_project", "libcap"),
        ("samba", "ppp"),
        ("gnu", "libtasn1"),
        ("freedesktop", "dbus"),
        ("gmplib", "gmp"),
        ("openldap", "openldap"),
        ("e2fsprogs_project", "e2fsprogs"),
    ];

    #[test]
    fn products_with_a_verified_cpe_identity_keep_it() {
        let set = &*SIGNATURES;
        for (vendor, product) in VERIFIED_CPE_IDENTITIES {
            assert_eq!(
                set.resolve_alias(product),
                Some((vendor, product)),
                "{vendor}:{product} was verified against NVD; changing it silently returns \
zero CVEs rather than an error"
            );
        }
    }

    /// One real string per firmware signature, copied out of a Debian trixie
    /// binary whose version dpkg recorded, with the version that must come out.
    ///
    /// Every entry was checked end to end against the binary it came from —
    /// this is the record of that, so a later edit to a pattern cannot quietly
    /// stop reading a version that used to work.
    const FIRMWARE_GROUND_TRUTH: [(&str, &str, &str, &str); 22] = [
        (
            "dropbear_ssh",
            "dropbear",
            "\nSSH-2.0-dropbear_2025.89\n",
            "2025.89",
        ),
        ("dnsmasq", "dnsmasq", "\ndnsmasq-2.91\n", "2.91"),
        (
            "lighttpd",
            "lighttpd",
            "\nlighttpd/1.4.79 (ssl) - a light and fast webserver\n",
            "1.4.79",
        ),
        (
            "wpa_supplicant",
            "wpa_supplicant",
            "\nwpa_supplicant v2.10\n",
            "2.10",
        ),
        ("hostapd", "hostapd_cli", "\nhostapd_cli v2.10\n", "2.10"),
        (
            "openssh",
            "sshd",
            "\nOpenSSH_10.0p2 Debian-7+deb13u4\n",
            "10.0p2",
        ),
        ("net-snmp", "snmpd", "\nnet-snmp-5.9.4+dfsg=.\n", "5.9.4"),
        ("libssh", "libssh.so.4", "\nlibssh_0.11.5\n", "0.11.5"),
        (
            "strongswan",
            "charon",
            "\nstrongSwan 6.0.1, %s %s, %s)\n",
            "6.0.1",
        ),
        (
            "libpcap",
            "libpcap.so.1",
            "\nlibpcap version 1.10.5 (with TPACKET_V3)\n",
            "1.10.5",
        ),
        (
            "lua",
            "lua5.4",
            "\nLua 5.4.7  Copyright (C) 1994-2024 Lua.org, PUC-Rio\n",
            "5.4.7",
        ),
        (
            "openvpn",
            "openvpn",
            "\nOpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO]\n",
            "2.6.14",
        ),
        (
            "avahi",
            "avahi-daemon",
            "\nSTATUS=%s 0.8 starting up.\navahi 0.8\n",
            "0.8",
        ),
        (
            "libjpeg-turbo",
            "libjpeg.so.62",
            "\nlibjpeg-turbo version 2.1.5 (build 20250503)\n",
            "2.1.5",
        ),
        (
            "u-boot",
            "u-boot.bin",
            "\nU-Boot 2025.01-3 (Apr 08 2025 - 23:07:41 +0000)\n",
            "2025.01",
        ),
        // Both architectures, because wolfSSL is the one component whose
        // absence cost the most: adding it took a real router image from 28
        // CVEs to 91.
        (
            "wolfssl",
            "libwolfssl.so.5.5.3.99a5b54a",
            "\nwolfSSL PEM routines\nwolfSSL 5.5.3\n",
            "5.5.3",
        ),
        (
            "wolfssl",
            "libwolfssl.so.42.2.0",
            "\nwolfSSL_Debugging_ON\nwolfSSL 5.7.2\n",
            "5.7.2",
        ),
        (
            "libarchive",
            "libarchive.so.13",
            "\nlibarchive 3.7.4\n",
            "3.7.4",
        ),
        (
            "libcap",
            "libcap.so.2",
            "\n%s is the shared library version: libcap-2.75.\n",
            "2.75",
        ),
        (
            "libevent",
            "libevent-2.1.so.7",
            "\n%s: %d events finalizing\n2.1.12-stable\n",
            "2.1.12",
        ),
        (
            "libpsl",
            "libpsl.so.5",
            "\n0.21.2 (+libidn2/2.3.7)\n",
            "0.21.2",
        ),
        ("ppp", "pppd", "\npppd version %s\npppd.so.2.5.2\n", "2.5.2"),
    ];

    #[test]
    fn every_firmware_signature_reads_the_version_its_binary_carries() {
        let set = &*SIGNATURES;
        for (product, file_name, blob, expected) in FIRMWARE_GROUND_TRUTH {
            let hits: Vec<_> = set
                .detect(file_name, blob, &[])
                .into_iter()
                .filter(|d| d.product == product)
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "{product}: expected exactly one detection, got {hits:?}"
            );
            assert_eq!(
                hits[0].version.as_deref(),
                Some(expected),
                "{product}: wrong version read from its own banner"
            );
        }
    }

    /// The exact accessor bytes for each library whose version exists only as
    /// a numeric constant, lifted from a Debian trixie binary whose version
    /// dpkg recorded.
    ///
    /// `(product, identifying string, accessor bytes, expected version)`.
    const CONSTANT_GROUND_TRUTH: [(&str, &str, &[u8], &str); 11] = [
        (
            "nghttp2",
            "nghttp2_session_client_new",
            // endbr64; cmp edi, 0x14000; mov edx, 0
            &[
                0xf3, 0x0f, 0x1e, 0xfa, 0x81, 0xff, 0x00, 0x40, 0x01, 0x00, 0xba, 0x00, 0x00, 0x00,
                0x00,
            ],
            "1.64.0",
        ),
        (
            "c-ares",
            "ares_getaddrinfo",
            // endbr64; test rdi,rdi; je +6; mov [rdi], 0x12205; lea rax,[rip+..]
            &[
                0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x85, 0xff, 0x74, 0x06, 0xc7, 0x07, 0x05, 0x22, 0x01,
                0x00, 0x48, 0x8d, 0x05,
            ],
            "1.34.5",
        ),
        (
            "mbed_tls",
            "mbedtls_ssl_setup",
            // endbr64; mov eax, 0x03060500; ret
            &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x00, 0x05, 0x06, 0x03, 0xc3],
            "3.6.5",
        ),
        (
            "mosquitto",
            "mosquitto_lib_version",
            // je +6; mov [rdx], 21; mov eax, 2000021; ret
            &[
                0x74, 0x06, 0xc7, 0x02, 0x15, 0x00, 0x00, 0x00, 0xb8, 0x95, 0x84, 0x1e, 0x00, 0xc3,
            ],
            "2.0.21",
        ),
        (
            "nettle",
            "nettle_pbkdf2",
            // nettle_version_major() -> 3, nopw padding, nettle_version_minor() -> 10
            &[
                0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3, 0x66, 0x0f, 0x1f, 0x44,
                0x00, 0x00, 0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3,
            ],
            "3.10",
        ),
        (
            "sqlite",
            "attempt to write a readonly database",
            // OpenWrt 23.05.5 libsqlite3-0_3410200 (mips_24kc, MIPS16e2):
            // PC-relative load; jrc ra; the constant itself in the literal
            // pool as raw big-endian bytes, 0x2E66EA = 3041002.
            &[0xb2, 0x01, 0xe8, 0xa0, 0x00, 0x2e, 0x66, 0xea],
            "3.41.2",
        ),
        (
            "xz",
            "Unsupported flags to lzma_str_to_filters()",
            // OpenWrt 23.05.5 liblzma_5.4.6-1 (mips_24kc, MIPS16e2): the same
            // literal-pool shape, 0x2FB8CFE = 50040062 — the stability digit
            // the formula drops, leaving 5.4.6.
            &[0xb2, 0x01, 0xe8, 0xa0, 0x02, 0xfb, 0x8c, 0xfe],
            "5.4.6",
        ),
        (
            "zstandard",
            "Frame requires too much memory for decoding",
            // OpenWrt 23.05.5 libzstd 1.5.2 (arm_cortex-a7, ARM A32):
            // movw r0, #0x2906; bx lr — the immediate split across the
            // instruction word, imm4 over imm12, recombined by the decoder.
            &[0x06, 0x09, 0x02, 0xe3, 0x1e, 0xff, 0x2f, 0xe1],
            "1.5.2",
        ),
        (
            "zstandard",
            "Frame requires too much memory for decoding",
            // OpenWrt 23.05.5 libzstd 1.5.2 (mips_24kc, MIPS16e2):
            // EXTEND; li v0, 10502; jrc ra — the immediate recombined from
            // scattered fields: 0xF105 → fields 0x0A5 → upper 0x145 →
            // (0x145 << 5) | 6 = 10502.
            &[0xf1, 0x05, 0x6a, 0x06, 0xe8, 0xa0],
            "1.5.2",
        ),
        (
            "sqlite",
            "attempt to write a readonly database",
            // OpenWrt 23.05.5 libsqlite3 3.41.2 (arm_cortex-a7, ARM A32):
            // ldr r0, [pc, #0]; bx lr; then 0x002E66EA in the pool as four
            // little-endian bytes = 3041002.
            &[
                0x00, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1, 0xea, 0x66, 0x2e, 0x00,
            ],
            "3.41.2",
        ),
        (
            "xz",
            "Unsupported flags to lzma_str_to_filters()",
            // OpenWrt 23.05.5 liblzma 5.4.6 (arm_cortex-a7, ARM A32): the
            // same pool shape, little-endian this time — 0x02FB8CFE.
            &[
                0x00, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1, 0xfe, 0x8c, 0xfb, 0x02,
            ],
            "5.4.6",
        ),
    ];

    /// Positive detection fixtures for the legacy signature set, every one
    /// taken from a real binary whose version was known independently — the
    /// package manager that installed it, or a second binary reporting the
    /// shared library's version. This is the table that moves a product out
    /// of `unverified_products` in the pack provenance.
    ///
    /// `raw` participates only where the version lives in code (sqlite).
    struct RealFixture {
        product: &'static str,
        filename: &'static str,
        blob: &'static str,
        raw: &'static [u8],
        expected: Option<&'static str>,
    }

    const REAL_BUILD_GROUND_TRUTH: [RealFixture; 22] = [
        // Debian 13 "trixie" (dpkg-known versions), aarch64.
        RealFixture {
            product: "bash",
            filename: "bash",
            blob: "\nBash version 5.2.37(1)-release\n",
            raw: &[],
            expected: Some("5.2.37"),
        },
        RealFixture {
            product: "binutils",
            filename: "strings",
            blob: "\n(GNU Binutils for Debian) 2.44\n",
            raw: &[],
            expected: Some("2.44"),
        },
        RealFixture {
            product: "busybox",
            filename: "busybox",
            blob: "\nBusyBox v1.37.0 (Debian 1:1.37.0-6+b9) multi-call binary.\n",
            raw: &[],
            expected: Some("1.37.0"),
        },
        RealFixture {
            product: "bzip2",
            filename: "bzip2recover",
            blob: "\nbzip2recover 1.0.8: extracts blocks from damaged .bz2 files.\n",
            raw: &[],
            expected: Some("1.0.8"),
        },
        RealFixture {
            product: "expat",
            filename: "libexpat.so.1",
            blob: "\nexpat_2.8.3\n",
            raw: &[],
            expected: Some("2.8.3"),
        },
        RealFixture {
            product: "git",
            filename: "git",
            blob: "\ngit/2.47.3\n",
            raw: &[],
            expected: Some("2.47.3"),
        },
        RealFixture {
            product: "glibc",
            filename: "libc.so.6",
            blob: "\nGNU C Library (Debian GLIBC 2.41-12+deb13u4) stable release version 2.41.\n",
            raw: &[],
            expected: Some("2.41"),
        },
        RealFixture {
            product: "gnupg",
            filename: "gpg",
            blob: "\nGNU Privacy Guard's OpenPGP server 2.4.7 ready\n",
            raw: &[],
            expected: Some("2.4.7"),
        },
        RealFixture {
            product: "kerberos_5",
            filename: "libkrb5.so.3",
            blob: "\nKRB5_BRAND: krb5-1.21.3-final 1.21.3 20240626\n",
            raw: &[],
            expected: Some("1.21.3"),
        },
        RealFixture {
            product: "libcurl",
            filename: "libcurl.so.4",
            blob: "\nlibcurl/8.14.1\n",
            raw: &[],
            expected: Some("8.14.1"),
        },
        RealFixture {
            product: "openssl",
            filename: "libcrypto.so.3",
            blob: "\nOpenSSL 3.5.7 9 Jun 2026\n",
            raw: &[],
            expected: Some("3.5.7"),
        },
        RealFixture {
            product: "perl",
            filename: "perl",
            blob: "\nBuiltin version bundle \"%s\" is not supported by Perl 5.40.1\n",
            raw: &[],
            expected: Some("5.40.1"),
        },
        RealFixture {
            product: "sqlite",
            filename: "libsqlite3.so.0",
            blob: "\nattempt to write a readonly database\n",
            // sqlite3_libversion_number for 3.46.1: movz w0,#0xe691 / movk w0,#0x2e,lsl#16 / ret.
            raw: &[
                0x20, 0x4e, 0x8f, 0x52, 0xc0, 0x05, 0xa0, 0x72, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            expected: Some("3.46.1"),
        },
        RealFixture {
            product: "util-linux",
            filename: "nsenter",
            blob: "\nutil-linux 2.41.5\n",
            raw: &[],
            expected: Some("2.41.5"),
        },
        RealFixture {
            product: "zlib",
            filename: "libz.so.1",
            blob: "\ndeflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler\n",
            raw: &[],
            expected: Some("1.3.1"),
        },
        // Homebrew (brew-known versions), arm64 macOS.
        RealFixture {
            product: "curl",
            filename: "curl",
            blob: "\ncurl 8.7.1 (x86_64-apple-darwin26.0) %s\n",
            raw: &[],
            expected: Some("8.7.1"),
        },
        RealFixture {
            product: "gnutls",
            filename: "libgnutls.so.30",
            blob: "\nEnabled GnuTLS 3.8.13 logging...\n",
            raw: &[],
            expected: Some("3.8.13"),
        },
        RealFixture {
            product: "libgcrypt",
            filename: "libgcrypt.so.20",
            blob: "\nThis is Libgcrypt 1.12.2 - The GNU Crypto Library\n",
            raw: &[],
            expected: Some("1.12.2"),
        },
        RealFixture {
            product: "libmicrohttpd",
            filename: "libmicrohttpd.so.12",
            blob: "\nMHD-worker\n1.0.1\n@LIBMICROHTTPD\n",
            raw: &[],
            expected: Some("1.0.1"),
        },
        RealFixture {
            product: "libpng",
            filename: "libpng16.so.16",
            blob: "\nlibpng version 1.6.58\n",
            raw: &[],
            expected: Some("1.6.58"),
        },
        RealFixture {
            product: "libssh2",
            filename: "libssh2.so.1",
            blob: "\nSSH-2.0-libssh2_1.11.1\n",
            raw: &[],
            expected: Some("1.11.1"),
        },
        RealFixture {
            product: "xz",
            filename: "xz",
            blob: "\nxz (XZ Utils) 5.8.4\nliblzma 5.8.4\n",
            raw: &[],
            expected: Some("5.8.4"),
        },
    ];

    #[test]
    fn every_legacy_signature_detects_its_real_build() {
        let set = &*SIGNATURES;
        for fixture in REAL_BUILD_GROUND_TRUTH {
            let hits: Vec<_> = set
                .detect(fixture.filename, fixture.blob, fixture.raw)
                .into_iter()
                .filter(|d| d.product == fixture.product)
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "{}: expected exactly one detection, got {:?}",
                fixture.product,
                hits.iter()
                    .map(|d| (&d.version, d.evidence))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                hits[0].version.as_deref(),
                fixture.expected,
                "{}: version mismatch",
                fixture.product
            );
        }
    }

    #[test]
    fn every_numeric_version_constant_is_read_from_its_real_accessor() {
        let set = &*SIGNATURES;
        for (product, marker, bytes, expected) in CONSTANT_GROUND_TRUTH {
            let blob = format!("\n{marker}\n");
            let hits: Vec<_> = set
                .detect("blob.so", &blob, bytes)
                .into_iter()
                .filter(|d| d.product == product)
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "{product}: expected one detection, got {hits:?}"
            );
            assert_eq!(
                hits[0].version.as_deref(),
                Some(expected),
                "{product}: wrong version decoded from its accessor"
            );
        }
    }

    /// Components identified by a data string alone, with no version anywhere
    /// in the binary. `(product, identifying string)`.
    const IDENTITY_ONLY: [(&str, &str); 20] = [
        ("freetype", "autofitter"),
        ("readline", "unrecognized history modifier"),
        ("jansson", "%s near end of file"),
        ("libwebsockets", "Out of mem in lws_daemonize"),
        ("chrony", "chronyd exiting"),
        // iptables builds its banner from `%s v%s (legacy): ` at runtime. The
        // bare version that is present has no stable neighbour — measured, it
        // sits between `-N %s` and `append` on one build and between `help` and
        // `unexpected '!' flag` on another.
        ("iptables", "Failed to initialize xtables"),
        // OpenWrt's own userspace. None embeds a version — OpenWrt versions
        // these as dated git snapshots — so identity is all there is, and all
        // that is wanted.
        ("ubus", "ubus.object.add"),
        ("libuci", "commit    [<config>]"),
        ("netifd", "external device handler"),
        ("odhcp6c", "Usage: odhcp6c [options] <interface>"),
        ("libtasn1", "LIBTASN1 ERROR: %s"),
        ("dbus", "D-Bus Message Bus Daemon"),
        ("gmp", "GNU MP assertion failed"),
        ("openldap", "Can't contact LDAP server"),
        ("libtirpc", "rpc_broadcast_exp: uaddr %s"),
        (
            "libnftnl",
            "libnftnl: attribute %d > %d (maximum) assertion fail",
        ),
        ("json-c", "json-c aborts with error: %s"),
        ("libidn2", "input A-label is not valid"),
        ("e2fsprogs", "Journal superblock magic number invalid!"),
        // libcap also identifies from its version string above; this checks the
        // versionless data path is not the only one that works — skip a dup.
        ("libtasn1", "ASN1_MAX_NAME_SIZE"),
    ];

    #[test]
    fn a_component_with_no_version_anywhere_is_still_reported() {
        // "freetype is in this image" is a lead even without a version, and
        // reporting nothing would be indistinguishable from it being absent.
        let set = &*SIGNATURES;
        for (product, marker) in IDENTITY_ONLY {
            let hits: Vec<_> = set
                .detect("blob.so", &format!("\n{marker}\n"), &[])
                .into_iter()
                .filter(|d| d.product == product)
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "{product}: expected one detection, got {hits:?}"
            );
            assert_eq!(
                hits[0].version, None,
                "{product} has no version to read; claiming one would be invention"
            );
        }
    }

    #[test]
    fn identity_only_components_still_resolve_a_package_name_to_their_cpe() {
        // They cannot read a version themselves, so the one route to a version
        // is an ELF package note — which only helps if the distribution's
        // package name resolves to the same component.
        let set = &*SIGNATURES;
        for (package, product) in [
            ("libwolfssl42t64", "wolfssl"),
            ("ip6tables", "iptables"),
            ("libfreetype6", "freetype"),
            ("libreadline8t64", "readline"),
            ("libjansson4", "jansson"),
            ("libwebsockets19t64", "libwebsockets"),
            ("chrony", "chrony"),
        ] {
            assert_eq!(
                set.resolve_alias(package).map(|(_, p)| p),
                Some(product),
                "{package} must fold onto {product} rather than becoming a second row"
            );
        }
    }

    #[test]
    fn a_second_capture_landing_on_an_opcode_yields_nothing_rather_than_a_number() {
        // nettle's minor sits at offset 21, not 20 — 20 is the `mov` opcode
        // itself. Authoring that wrong should produce silence, not a version
        // invented out of an instruction byte. It caught exactly that mistake.
        let set = &*SIGNATURES;
        let mut bytes = [
            0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3, 0x66, 0x0f, 0x1f, 0x44,
            0x00, 0x00, 0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3,
        ];
        // Break the minor so it cannot fit a byte when read as a u32.
        bytes[22] = 0xff;
        let versions: Vec<_> = set
            .detect("blob.so", "\nnettle_pbkdf2\n", &bytes)
            .into_iter()
            .filter(|d| d.product == "nettle")
            .filter_map(|d| d.version)
            .collect();
        assert!(
            versions.is_empty(),
            "decoded a version from junk: {versions:?}"
        );
    }

    #[test]
    fn sshds_bug_compatibility_list_is_not_read_as_installed_versions() {
        // sshd carries patterns for negotiating around old peers. A pattern
        // matching `OpenSSH_<version>` captures every one of them and reports
        // a router as running eight OpenSSH releases at once.
        let set = &*SIGNATURES;
        let compat = "\nOpenSSH_10.0\nOpenSSH_3.*\nOpenSSH_6.6.1*\nOpenSSH_6.5*,OpenSSH_6.6*\n\
OpenSSH_7.0*,OpenSSH_7.1*\nOpenSSH_10.0p2 Debian-7+deb13u4\n";
        let versions: Vec<_> = set
            .detect("sshd", compat, &[])
            .into_iter()
            .filter(|d| d.product == "openssh")
            .filter_map(|d| d.version)
            .collect();
        assert_eq!(versions, vec!["10.0p2"], "compat patterns leaked in");
    }

    #[test]
    fn openvpns_minimum_version_sentence_is_not_read_as_a_build() {
        // "OpenVPN 2.6.0 or higher)" is a requirement the binary states, not a
        // version it is. Same shape as OpenSSL's "3.0.0 and newer" prose.
        let set = &*SIGNATURES;
        let blob =
            "\nOpenVPN 2.6.0 or higher)\nOpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)]\n";
        let versions: Vec<_> = set
            .detect("openvpn", blob, &[])
            .into_iter()
            .filter(|d| d.product == "openvpn")
            .filter_map(|d| d.version)
            .collect();
        assert_eq!(versions, vec!["2.6.14"]);
    }

    #[test]
    fn the_bundled_signatures_compile_and_cover_the_common_firmware_libraries() {
        let set = &*SIGNATURES;
        assert!(set.len() >= 20, "only {} signatures bundled", set.len());
        let products: Vec<&str> = set.products().collect();
        for expected in [
            "openssl",
            "zlib",
            "curl",
            "busybox",
            "glibc",
            "expat",
            // The firmware set: what an actual router image is made of.
            "dropbear_ssh",
            "dnsmasq",
            "lighttpd",
            "wpa_supplicant",
            "hostapd",
            "openssh",
            "u-boot",
            "libpcap",
            "lua",
            "openvpn",
            // The TLS library an embedded image actually ships, and the
            // firewall every one of them has.
            "wolfssl",
            "iptables",
        ] {
            assert!(
                products.contains(&expected),
                "{expected} is a staple of embedded firmware and must be covered"
            );
        }
    }

    #[test]
    fn a_documented_minimum_version_is_not_read_as_a_linked_one() {
        // Both strings are real, taken from a Debian tree: the first is
        // OPENSSL_VERSION_TEXT out of libcrypto, the second is a sentence in
        // Python's _hashlib. Only the first describes what is linked here.
        let set = &*SIGNATURES;

        let real = set.detect(
            "libcrypto.so.3",
            "part of OpenSSL\nOpenSSL 3.5.6 7 Apr 2026\n",
            &[],
        );
        assert_eq!(
            real.iter()
                .filter_map(|d| d.version.as_deref())
                .collect::<Vec<_>>(),
            vec!["3.5.6"]
        );

        let prose = set.detect(
            "_hashlib.cpython-313-aarch64-linux-gnu.so",
            "For OpenSSL 3.0.0 and newer it returns the state of the digest\n",
            &[],
        );
        assert!(
            prose.is_empty(),
            "a documented minimum became a component: {prose:?}"
        );
    }

    #[test]
    fn elf_symbol_version_tags_are_never_read_as_library_versions() {
        // libcrypto.so.3 carries nine OPENSSL_3.x symbol tags and libz carries
        // fourteen ZLIB_1.2.x ones. They are the ABI versions a library can
        // serve, not the version it is; capturing them would report a dozen
        // phantom components for every real one.
        let set = &*SIGNATURES;
        let blob =
            "OPENSSL_3.0.0\nOPENSSL_3.5.0\nZLIB_1.2.12\nGLIBC_2.26\nXZ_5.4\nLIBXML2_2.9.11\n";
        let hits = set.detect("libcrypto.so.3", blob, &[]);
        assert!(
            hits.iter().all(|h| h.version.is_none()),
            "a symbol-version tag was captured as a version: {hits:?}"
        );
    }
}
