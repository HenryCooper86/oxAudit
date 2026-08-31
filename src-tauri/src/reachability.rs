//! Direct-usage reachability: does the project's own code reference a
//! vulnerable package?
//!
//! A package sitting in a lockfile is *present*; a package the project's
//! source imports is *in use*. The second is the stronger triage signal, so
//! the dependency scan builds one usage index from the scanned project's
//! source files and asks it about every vulnerable package.
//!
//! What it can and cannot say is stated precisely, because overstating either
//! direction costs more than the signal is worth:
//!
//! - `Some(true)` — project source references this package. Direct usage is
//!   *confirmed*, whatever else the graph does.
//! - `Some(false)` — the ecosystem's import forms were scanned and none
//!   reference this package. This does **not** mean the package is
//!   unreachable: a transitive dependency can load it without any import in
//!   this project.
//! - `None` — the ecosystem's import forms are not mapped (Maven artifact ids
//!   do not correspond to import statements, NuGet's do only loosely), so
//!   nothing is said in either direction.

use std::collections::{BTreeSet, HashMap};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// The answer for one vulnerable package.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectUsage {
    /// See the module docs: `true` confirms direct use, `false` means the
    /// ecosystem was mapped and no reference was found, `null` means the
    /// ecosystem cannot be mapped from source imports.
    pub referenced: Option<bool>,
    /// Source files that reference the package (0 when not referenced).
    #[serde(default)]
    pub referenced_files: usize,
    /// One referencing file, for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_file: Option<String>,
}

/// Which ecosystems have a mapping from source imports to package names.
pub fn mappable(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "npm" | "PyPI" | "crates.io" | "Go" | "RubyGems" | "Packagist"
    )
}

/// One scanned project's worth of references, keyed `ecosystem \0 canonical-name`.
#[derive(Default)]
pub struct UsageIndex {
    references: HashMap<String, PackageUsage>,
    complete: bool,
}

#[derive(Default)]
struct PackageUsage {
    files: BTreeSet<String>,
}

impl UsageIndex {
    /// Build an index over one project's own source, walking with the same
    /// collection policy a scan uses. Bounded so a hundred-thousand-file
    /// monorepo does not pay a second full source scan; best-effort by
    /// construction — a walk or read failure simply leaves answers unmapped,
    /// never guessed.
    pub fn for_project(root: &std::path::Path, ignored_dirs: &[String]) -> Self {
        const MAX_FILES: usize = 5_000;
        const MAX_FILE_BYTES: u64 = 256 * 1024;
        let collection = match crate::fs_utils::collect_source_files_bounded(
            root,
            crate::fs_utils::CollectFilesOptions {
                project_root: root,
                include_git: false,
                follow_symlinks: false,
                extra_ignored: ignored_dirs,
            },
            crate::fs_utils::CollectionBudget::default(),
            None,
        ) {
            Ok(collection) => collection,
            Err(_) => return Self::default(),
        };
        let mut complete = collection.files.len() <= MAX_FILES;
        let mut entries = Vec::new();
        for file in collection.files.into_iter().take(MAX_FILES) {
            let Some(language) = crate::fs_utils::detect_language(&file.canonical_path) else {
                continue;
            };
            if !matches!(
                language,
                "javascript" | "python" | "rust" | "go" | "ruby" | "php"
            ) {
                continue;
            }
            if let Some(content) =
                crate::fs_utils::read_text_file(&file.canonical_path, MAX_FILE_BYTES)
            {
                entries.push((
                    file.project_relative_path
                        .to_string_lossy()
                        .replace('\\', "/"),
                    content,
                ));
            } else {
                complete = false;
            }
        }
        let mut index = Self::build(&entries);
        index.complete = complete;
        index
    }

    /// Build an index from `(path, content)` pairs of the project's source
    /// files. Files that do not look like a mapped language contribute
    /// nothing; no error is possible because a reference found in one file
    /// must not fail the scan for another.
    pub fn build(entries: &[(String, String)]) -> Self {
        let mut index = UsageIndex {
            complete: true,
            ..UsageIndex::default()
        };
        for (path, content) in entries {
            for (ecosystem, references) in extract(content) {
                for reference in references {
                    index
                        .references
                        .entry(key(ecosystem, &reference))
                        .or_default()
                        .files
                        .insert(path.clone());
                }
            }
        }
        index
    }

    /// The direct-usage answer for one package.
    pub fn lookup(&self, ecosystem: &str, package_name: &str) -> DirectUsage {
        match canonical_candidates(ecosystem, package_name).and_then(|candidates| {
            candidates
                .iter()
                .find_map(|candidate| self.references.get(&key(ecosystem, candidate)))
        }) {
            Some(usage) => DirectUsage {
                referenced: Some(true),
                referenced_files: usage.files.len(),
                example_file: usage.files.iter().next().cloned(),
            },
            None => DirectUsage {
                referenced: (self.complete && mappable(ecosystem)).then_some(false),
                referenced_files: 0,
                example_file: None,
            },
        }
    }
}

fn key(ecosystem: &str, name: &str) -> String {
    format!("{ecosystem}\0{name}")
}

/// The spelling extraction stores for one ecosystem, so lookup and build can
/// only disagree by accident. `None` = not mapped (Maven, NuGet, …).
fn canonical_name(ecosystem: &str, package_name: &str) -> Option<String> {
    match ecosystem {
        "npm" => Some(package_name.to_ascii_lowercase()),
        // Package names and imports disagree about `-` and `_` in these three.
        "PyPI" | "crates.io" | "RubyGems" => {
            Some(package_name.to_ascii_lowercase().replace('-', "_"))
        }
        "Go" => Some(package_name.to_string()),
        // Composer names are vendor/package; PHP namespaces use backslashes.
        "Packagist" => Some(package_name.to_ascii_lowercase().replace('/', "\\")),
        _ => None,
    }
}

/// Every index key a package can legitimately match under.
///
/// The special case is Packagist's `vendor/vendor` convention: `monolog/monolog`
/// owns the `Monolog\…` namespace, so `use Monolog\Logger;` is a use of the
/// package even though the namespace prefix is only one segment deep. The bare
/// vendor prefix counts only when vendor and package are the same name, or
/// `use Illuminate\Foundation\…` would credit `illuminate/support`.
fn canonical_candidates(ecosystem: &str, package_name: &str) -> Option<Vec<String>> {
    let canonical = canonical_name(ecosystem, package_name)?;
    if ecosystem != "Packagist" {
        return Some(vec![canonical]);
    }
    let mut candidates = vec![canonical.clone()];
    if let Some((vendor, package)) = canonical.split_once('\\') {
        if vendor == package {
            candidates.push(vendor.to_string());
        }
    }
    Some(candidates)
}

// ---------------------------------------------------------------------------
// extraction
// ---------------------------------------------------------------------------

/// Extract every package reference in one file, per ecosystem, in canonical
/// form. The canonical form is what `lookup` normalizes a package name to.
fn extract(content: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("npm", npm_references(content)),
        ("PyPI", pypi_references(content)),
        ("crates.io", cargo_references(content)),
        ("Go", go_references(content)),
        ("RubyGems", rubygems_references(content)),
        ("Packagist", composer_references(content)),
    ]
}

static FROM_SPECIFIER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\bfrom\s+["']([^"']+)["']"#).expect("valid"));
static BARE_IMPORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\bimport\s+["']([^"']+)["']"#).expect("valid"));
static REQUIRE_CALL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\brequire\s*\(\s*["']([^"']+)["']\s*\)"#).expect("valid"));
static DYNAMIC_IMPORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\bimport\s*\(\s*["']([^"']+)["']\s*\)"#).expect("valid"));

/// The package a JS/TS module specifier names: the bare name, or the scope
/// plus name for `@scope/name`. Relative specifiers name no package.
fn npm_package(specifier: &str) -> Option<String> {
    if specifier.starts_with('.') || specifier.starts_with('/') || specifier.is_empty() {
        return None;
    }
    let mut segments = specifier.split('/');
    let first = segments.next().unwrap_or_default();
    let package = if first.starts_with('@') {
        let second = segments.next().unwrap_or_default();
        if second.is_empty() {
            return None;
        }
        format!("{first}/{second}")
    } else {
        first.to_string()
    };
    Some(package.to_ascii_lowercase())
}

fn npm_references(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pattern in [
        FROM_SPECIFIER.captures_iter(content),
        BARE_IMPORT.captures_iter(content),
        REQUIRE_CALL.captures_iter(content),
        DYNAMIC_IMPORT.captures_iter(content),
    ] {
        for captures in pattern {
            if let Some(package) = captures.get(1).and_then(|m| npm_package(m.as_str())) {
                out.push(package);
            }
        }
    }
    out
}

static PY_IMPORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*import\s+([\w.]+)").expect("valid"));
static PY_FROM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*from\s+([\w.]+)\s+import").expect("valid"));

/// PyPI names and imports disagree about `-` and `_`: the package is
/// `requests-cache` and the import is `requests_cache`. Canonicalising both
/// to the underscore spelling makes either reference the other.
fn pypi_references(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pattern in [
        PY_IMPORT.captures_iter(content),
        PY_FROM.captures_iter(content),
    ] {
        for captures in pattern {
            let Some(module) = captures.get(1) else {
                continue;
            };
            let module = module.as_str();
            if module.starts_with('.') {
                continue; // relative import names no package
            }
            let package = module.split('.').next().unwrap_or_default();
            if !package.is_empty() {
                out.push(package.to_ascii_lowercase().replace('-', "_"));
            }
        }
    }
    out
}

static RS_USE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*use\s+([a-zA-Z_]\w*)").expect("valid"));
static RS_EXTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*extern\s+crate\s+([a-zA-Z_]\w*)").expect("valid"));

/// Crates and imports disagree about `-` and `_` exactly as PyPI does, so the
/// same canonical form applies. `use crate::`, `use self::` and `use super::`
/// are paths inside the project, not crates.
fn cargo_references(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for captures in RS_USE
        .captures_iter(content)
        .chain(RS_EXTERN.captures_iter(content))
    {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let name = name.as_str();
        if matches!(name, "crate" | "self" | "super") {
            continue;
        }
        out.push(name.to_ascii_lowercase().replace('-', "_"));
    }
    out
}

static GO_SINGLE_IMPORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"]+)""#).expect("valid"));
static GO_IMPORT_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)\bimport\s*\(([^)]*)\)"#).expect("valid"));
static GO_QUOTED: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]+)""#).expect("valid"));

/// Go module paths are matched by prefix: the module `github.com/gin-gonic/gin`
/// is imported as itself or any sub-path of it. Prefixes are expanded at build
/// time so lookup stays an exact-set test, and so `/v2` module suffixes work:
/// the import `…/gin/v2/binding` contributes `…/gin/v2` as well.
fn go_references(content: &str) -> Vec<String> {
    let mut imports = Vec::new();
    for captures in GO_SINGLE_IMPORT.captures_iter(content) {
        if let Some(path) = captures.get(1) {
            imports.push(path.as_str().to_string());
        }
    }
    for captures in GO_IMPORT_BLOCK.captures_iter(content) {
        if let Some(block) = captures.get(1) {
            for quoted in GO_QUOTED.captures_iter(block.as_str()) {
                if let Some(path) = quoted.get(1) {
                    imports.push(path.as_str().to_string());
                }
            }
        }
    }
    expand_prefixes(&imports, '/')
}

static RB_REQUIRE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\brequire\s+["']([^"']+)["']"#).expect("valid"));
static RB_GEM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\bgem\s+["']([^"']+)["']"#).expect("valid"));

/// `require "x/y"` names the gem `x` by convention, and a `gem "x"` entry in
/// the Gemfile is a direct declaration. The `-`/`_` spelling disagreement is
/// handled the same way as PyPI and Cargo.
fn rubygems_references(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pattern in [
        RB_REQUIRE.captures_iter(content),
        RB_GEM.captures_iter(content),
    ] {
        for captures in pattern {
            let Some(requirement) = captures.get(1) else {
                continue;
            };
            let gem = requirement.as_str().split('/').next().unwrap_or_default();
            if !gem.is_empty() {
                out.push(gem.to_ascii_lowercase().replace('-', "_"));
            }
        }
    }
    out
}

static PHP_USE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\buse\s+\\?([A-Za-z_][\w\\]*)\s*;").expect("valid"));

/// Composer names are `vendor/package`; PHP namespaces are `Vendor\Package\…`
/// and are case-insensitive. Prefixes are expanded on `\` so
/// `use Illuminate\Support\Facades\Log;` matches `illuminate/support`.
fn composer_references(content: &str) -> Vec<String> {
    let mut namespaces = Vec::new();
    for captures in PHP_USE.captures_iter(content) {
        if let Some(namespace) = captures.get(1) {
            namespaces.push(namespace.as_str().to_ascii_lowercase());
        }
    }
    expand_prefixes(&namespaces, '\\')
}

/// Every leading prefix of every path, so a package lookup is an exact-set
/// test even where the language matches packages by prefix. Prefixes exclude
/// the separator itself: `a/b/c` contributes `a`, `a/b`, and the full path.
fn expand_prefixes(paths: &[String], separator: char) -> Vec<String> {
    let mut out = Vec::new();
    for path in paths {
        for (position, ch) in path.char_indices() {
            if ch == separator {
                let segment = &path[..position];
                if !segment.is_empty() {
                    out.push(segment.to_string());
                }
            }
        }
        out.push(path.clone());
    }
    out
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn index(files: &[(&str, &str)]) -> UsageIndex {
        UsageIndex::build(
            &files
                .iter()
                .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
                .collect::<Vec<_>>(),
        )
    }

    fn usage(index: &UsageIndex, ecosystem: &str, package: &str) -> DirectUsage {
        index.lookup(ecosystem, package)
    }

    #[test]
    fn npm_references_cover_import_require_and_scoped_forms() {
        let idx = index(&[(
            "src/app.ts",
            "import express from \"express\";\n\
             import { join } from \"node:path\";\n\
             const x = require(\"lodash/sub\");\n\
             import(\"next\");\n\
             import \"@scope/left-pad/extra\";\n\
             import relative from \"./local\";\n",
        )]);
        assert_eq!(
            usage(&idx, "npm", "express").referenced,
            Some(true),
            "import … from"
        );
        assert_eq!(
            usage(&idx, "npm", "lodash").referenced,
            Some(true),
            "require sub-path"
        );
        assert_eq!(
            usage(&idx, "npm", "next").referenced,
            Some(true),
            "dynamic import"
        );
        assert_eq!(
            usage(&idx, "npm", "@scope/left-pad").referenced,
            Some(true),
            "scoped package"
        );
        // Relative specifiers name no package, and a sub-path never counts as
        // a package of its own.
        assert_eq!(usage(&idx, "npm", "local").referenced, Some(false));
        assert_eq!(usage(&idx, "npm", "lodash/sub").referenced, Some(false));
    }

    #[test]
    fn pypi_matches_across_the_hyphen_underscore_spelling() {
        let idx = index(&[(
            "m.py",
            "import requests_cache\nfrom django.conf import settings\nfrom . import local\nimport os\n",
        )]);
        assert_eq!(
            usage(&idx, "PyPI", "requests-cache").referenced,
            Some(true),
            "the package spells it with a hyphen, the import with an underscore"
        );
        assert_eq!(usage(&idx, "PyPI", "django").referenced, Some(true));
        // Only the module counts, not the thing imported from it.
        assert_eq!(usage(&idx, "PyPI", "settings").referenced, Some(false));
        assert_eq!(usage(&idx, "PyPI", "local").referenced, Some(false));
    }

    #[test]
    fn cargo_matches_use_and_extern_and_skips_project_paths() {
        let idx = index(&[(
            "lib.rs",
            "use serde::Serialize;\nuse crate::x;\nuse self::y;\nextern crate rayon;\n",
        )]);
        assert_eq!(usage(&idx, "crates.io", "serde").referenced, Some(true));
        assert_eq!(usage(&idx, "crates.io", "rayon").referenced, Some(true));
        assert_eq!(usage(&idx, "crates.io", "crate").referenced, Some(false));
        assert_eq!(usage(&idx, "crates.io", "tokio").referenced, Some(false));
    }

    #[test]
    fn go_matches_module_paths_by_prefix() {
        let idx = index(&[(
            "main.go",
            "package main\nimport \"github.com/gin-gonic/gin\"\nimport (\n  \"github.com/spf13/cobra/cmd\"\n)\n",
        )]);
        assert_eq!(
            usage(&idx, "Go", "github.com/gin-gonic/gin").referenced,
            Some(true)
        );
        assert_eq!(
            usage(&idx, "Go", "github.com/spf13/cobra").referenced,
            Some(true),
            "an import of a sub-package is a use of the module"
        );
        assert_eq!(
            usage(&idx, "Go", "github.com/spf13/viper").referenced,
            Some(false)
        );
    }

    #[test]
    fn rubygems_matches_requires_and_gem_declarations() {
        let idx = index(&[(
            "a.rb",
            "require \"nokogiri\"\nrequire_relative \"helper\"\ngem \"rspec-core\"\n",
        )]);
        assert_eq!(usage(&idx, "RubyGems", "nokogiri").referenced, Some(true));
        assert_eq!(usage(&idx, "RubyGems", "rspec-core").referenced, Some(true));
        assert_eq!(usage(&idx, "RubyGems", "helper").referenced, Some(false));
    }

    #[test]
    fn composer_matches_namespaces_by_vendor_prefix() {
        let idx = index(&[(
            "x.php",
            "<?php\nuse Illuminate\\Support\\Facades\\Log;\nuse Monolog\\Logger;\n",
        )]);
        assert_eq!(
            usage(&idx, "Packagist", "illuminate/support").referenced,
            Some(true),
            "the use statement names a class under the package's namespace"
        );
        assert_eq!(
            usage(&idx, "Packagist", "monolog/monolog").referenced,
            Some(true)
        );
        assert_eq!(
            usage(&idx, "Packagist", "laravel/framework").referenced,
            Some(false)
        );
    }

    #[test]
    fn an_unmapped_ecosystem_says_nothing_either_way() {
        let idx = index(&[("pom.xml", "<dependency>log4j-core</dependency>")]);
        assert_eq!(usage(&idx, "Maven", "log4j-core").referenced, None);
        assert_eq!(usage(&idx, "Maven", "anything").referenced, None);
    }

    #[test]
    fn an_incomplete_source_index_never_claims_a_package_is_absent() {
        let idx = UsageIndex {
            references: HashMap::new(),
            complete: false,
        };

        assert_eq!(usage(&idx, "npm", "unseen-package").referenced, None);
    }

    #[test]
    fn an_unknown_reachability_answer_serializes_as_explicit_null() {
        let idx = UsageIndex {
            references: HashMap::new(),
            complete: false,
        };
        let serialized = serde_json::to_value(usage(&idx, "npm", "unseen-package"))
            .expect("serialize direct usage");

        assert!(serialized.get("referenced").is_some());
        assert!(serialized["referenced"].is_null());
    }

    #[test]
    fn a_reference_in_one_of_many_files_counts_each_file() {
        let idx = index(&[
            ("a.js", "import express from \"express\";"),
            ("b.js", "const express = require(\"express\");"),
            ("c.js", "const nothing = 1;"),
        ]);
        let usage = usage(&idx, "npm", "express");
        assert_eq!(usage.referenced, Some(true));
        assert_eq!(usage.referenced_files, 2);
        assert!(usage.example_file.is_some());
    }
}
