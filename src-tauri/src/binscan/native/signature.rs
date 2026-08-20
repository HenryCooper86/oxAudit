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

/// How a component was recognized. A filename match is much stronger evidence
/// than a string match, and the UI says which one it was rather than presenting
/// a guess and a certainty identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Evidence {
    /// The file is named like the component (`libssl.so.3`).
    Filename,
    /// The file contains a string characteristic of the component.
    Content,
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
}

#[derive(Deserialize)]
struct SignatureFile {
    #[serde(default)]
    signature: Vec<SignatureSpec>,
}

#[derive(Debug)]
struct Compiled {
    vendor: String,
    product: String,
    version_patterns: Vec<Regex>,
    ignore: Vec<Regex>,
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
            if spec.version_patterns.is_empty() && spec.contains.is_empty() {
                return Err(format!(
                    "signature {} has no way to match anything",
                    spec.product
                ));
            }

            let mut version_patterns = Vec::with_capacity(spec.version_patterns.len());
            for pattern in &spec.version_patterns {
                let regex = Regex::new(pattern)
                    .map_err(|e| format!("{}: bad version pattern {pattern:?}: {e}", spec.product))?;
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

            for pattern in spec.contains.iter().chain(spec.version_patterns.iter()) {
                Regex::new(pattern)
                    .map_err(|e| format!("{}: bad pattern {pattern:?}: {e}", spec.product))?;
                content_patterns.push(pattern.clone());
                content_owner.push(index);
            }
            for pattern in &spec.filename_patterns {
                Regex::new(pattern)
                    .map_err(|e| format!("{}: bad filename pattern {pattern:?}: {e}", spec.product))?;
                filename_patterns.push(pattern.clone());
                filename_owner.push(index);
            }

            let ignore = spec
                .ignore
                .iter()
                .map(|pattern| {
                    Regex::new(pattern)
                        .map_err(|e| format!("{}: bad ignore pattern {pattern:?}: {e}", spec.product))
                })
                .collect::<Result<Vec<_>, _>>()?;

            compiled.push(Compiled {
                vendor: spec.vendor,
                product: spec.product,
                version_patterns,
                ignore,
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

    /// Match one file. `file_name` is the base name; `blob` is its strings.
    ///
    /// A component detected at several versions inside one file yields one
    /// detection per version: firmware images genuinely do carry two builds of
    /// the same library, and collapsing them would hide the older one.
    pub fn detect(&self, file_name: &str, blob: &str) -> Vec<Detection> {
        let mut candidates: Vec<Option<Evidence>> = vec![None; self.compiled.len()];

        for index in self.content_set.matches(blob) {
            candidates[self.content_owner[index]] = Some(Evidence::Content);
        }
        // Filename evidence is applied second so it wins where both hold.
        for index in self.filename_set.matches(file_name) {
            candidates[self.filename_owner[index]] = Some(Evidence::Filename);
        }

        let mut detections = Vec::new();
        for (index, evidence) in candidates.into_iter().enumerate() {
            let Some(evidence) = evidence else { continue };
            let signature = &self.compiled[index];

            let mut versions: Vec<String> = Vec::new();
            for pattern in &signature.version_patterns {
                for capture in pattern.captures_iter(blob) {
                    let Some(found) = capture.get(1) else { continue };
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

pub static SIGNATURES: Lazy<SignatureSet> = Lazy::new(|| {
    SignatureSet::parse_toml(SIGNATURES_TOML).expect("bundled signatures must compile")
});

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(product: &str, contains: &[&str], versions: &[&str], filenames: &[&str]) -> SignatureSpec {
        SignatureSpec {
            vendor: product.to_string(),
            product: product.to_string(),
            filename_patterns: filenames.iter().map(|s| s.to_string()).collect(),
            contains: contains.iter().map(|s| s.to_string()).collect(),
            version_patterns: versions.iter().map(|s| s.to_string()).collect(),
            ignore: Vec::new(),
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
        let error = SignatureSet::compile(vec![spec("ghost", &[], &[], &["^ghost$"])])
            .expect_err("must not compile");
        assert!(error.contains("no way to match"), "{error}");
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

        let hits = set.detect("libcrypto.so.3", "part of OpenSSL\nOpenSSL 3.0.2 15 Mar 2022\n");
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

        let hits = set.detect("libcrypto.so.3", "part of OpenSSL\nOpenSSL 3.0.2 x\n");
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

        let hits = set.detect("busybox", "BusyBox is a multi-call binary\n");
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

        let hits = set.detect("firmware.bin", "OpenSSL 1.0.2k x\nOpenSSL 3.0.2 y\n");
        let versions: Vec<_> = hits.iter().filter_map(|h| h.version.as_deref()).collect();
        assert_eq!(versions, vec!["1.0.2k", "3.0.2"]);
    }

    #[test]
    fn an_ignored_capture_does_not_become_a_version() {
        let mut signature = spec("linux", &[], &[r"Linux version ([0-9][0-9.]+)"], &[]);
        signature.ignore = vec![r"^0\.0".to_string()];
        let set = SignatureSet::compile(vec![signature]).expect("compiles");

        let hits = set.detect("vmlinuz", "Linux version 0.0.0 junk\n");
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

        let hits = set.detect("blob", "inflate 1.2.11 Copyright\n\ncurl 8.7.1\n");
        let mut pairs: Vec<_> = hits
            .iter()
            .map(|h| (h.product.as_str(), h.version.as_deref().unwrap_or("")))
            .collect();
        pairs.sort();
        assert_eq!(pairs, vec![("curl", "8.7.1"), ("zlib", "1.2.11")]);
    }

    #[test]
    fn the_bundled_signatures_compile_and_cover_the_common_firmware_libraries() {
        let set = &*SIGNATURES;
        assert!(set.len() >= 20, "only {} signatures bundled", set.len());
        let products: Vec<&str> = set.products().collect();
        for expected in ["openssl", "zlib", "curl", "busybox", "glibc", "expat"] {
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

        let real = set.detect("libcrypto.so.3", "part of OpenSSL\nOpenSSL 3.5.6 7 Apr 2026\n");
        assert_eq!(
            real.iter().filter_map(|d| d.version.as_deref()).collect::<Vec<_>>(),
            vec!["3.5.6"]
        );

        let prose = set.detect(
            "_hashlib.cpython-313-aarch64-linux-gnu.so",
            "For OpenSSL 3.0.0 and newer it returns the state of the digest\n",
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
        let blob = "OPENSSL_3.0.0\nOPENSSL_3.5.0\nZLIB_1.2.12\nGLIBC_2.26\nXZ_5.4\nLIBXML2_2.9.11\n";
        let hits = set.detect("libcrypto.so.3", blob);
        assert!(
            hits.iter().all(|h| h.version.is_none()),
            "a symbol-version tag was captured as a version: {hits:?}"
        );
    }
}
