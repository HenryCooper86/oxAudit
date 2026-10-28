use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use crate::models::Dependency;

pub const MAX_LOCKFILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_LOCKFILES: usize = 256;
pub const MAX_DEPENDENCIES: usize = 100_000;
const RESOURCE_LIMIT_PREFIX: &str = "resource limit:";

pub fn is_resource_limit_error(error: &str) -> bool {
    error.starts_with(RESOURCE_LIMIT_PREFIX)
}

/// Kind identifiers returned to the UI.
pub fn lockfile_kind(name: &str) -> &'static str {
    match name {
        "package-lock.json" => "npm",
        "yarn.lock" => "yarn",
        "pnpm-lock.yaml" => "pnpm",
        "Cargo.lock" => "cargo",
        "go.sum" => "go",
        "Pipfile.lock" => "pipenv",
        "Gemfile.lock" => "bundler",
        "composer.lock" => "composer",
        "pom.xml" => "maven",
        "requirements.txt" => "pip",
        "gradle.lockfile" => "gradle",
        "packages.lock.json" => "nuget",
        "poetry.lock" => "poetry",
        "go.mod" => "gomod",
        "bun.lock" => "bun",
        "mix.lock" => "mix",
        "pubspec.lock" => "pubspec",
        _ => "unknown",
    }
}

/// Map a lockfile kind to the OSV ecosystem name.
pub fn ecosystem_for_kind(kind: &str) -> &'static str {
    match kind {
        "npm" | "yarn" | "pnpm" => "npm",
        "cargo" => "crates.io",
        "go" => "Go",
        "pipenv" | "pip" | "poetry" => "PyPI",
        "bundler" => "RubyGems",
        "gomod" => "Go",
        "bun" => "npm",
        "mix" => "Hex",
        "pubspec" => "Pub",
        "composer" => "Packagist",
        "maven" | "gradle" => "Maven",
        "nuget" => "NuGet",
        _ => "unknown",
    }
}

/// Parse a lockfile into dependencies. Returns Err with a human-readable
/// reason when the file cannot be understood.
pub fn parse_lockfile(path: &Path, kind: &str) -> Result<Vec<Dependency>, String> {
    parse_lockfile_with_limit(path, kind, MAX_LOCKFILE_BYTES)
}

fn parse_lockfile_with_limit(
    path: &Path,
    kind: &str,
    max_bytes: u64,
) -> Result<Vec<Dependency>, String> {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let ecosystem = ecosystem_for_kind(kind).to_string();
    let lockfile = path.to_string_lossy().replace('\\', "/");
    let metadata = std::fs::metadata(path).map_err(|error| format!("read failed: {error}"))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{RESOURCE_LIMIT_PREFIX} lockfile exceeds {max_bytes} bytes; scan a smaller \
             subdirectory or exclude that generated/vendor path"
        ));
    }
    let file = std::fs::File::open(path).map_err(|error| format!("read failed: {error}"))?;
    let mut content = String::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_string(&mut content)
        .map_err(|error| format!("read failed: {error}"))?;
    if content.len() as u64 > max_bytes {
        return Err(format!(
            "{RESOURCE_LIMIT_PREFIX} lockfile exceeds {max_bytes} bytes; scan a smaller \
             subdirectory or exclude that generated/vendor path"
        ));
    }

    if name == "package-lock.json" {
        let root: serde_json::Value = serde_json::from_str(&content)
            .map_err(|error| format!("invalid package-lock.json: {error}"))?;
        if root.get("packages").is_some() {
            let mut dependencies = super::relationships::parse_packages(&root)?;
            for dependency in &mut dependencies {
                dependency.lockfile = lockfile.clone();
            }
            return Ok(dependencies);
        }
    }
    if name == "go.mod" {
        return super::go_inventory::parse(&content, &lockfile);
    }
    if name == "go.sum" {
        if !path.with_file_name("go.mod").is_file() {
            return Err(
                "go.sum is checksum history, not an installed inventory; supply the sibling go.mod"
                    .into(),
            );
        }
        super::go_inventory::validate_sums(&content)?;
        return Ok(Vec::new());
    }
    if name == "Gemfile.lock" {
        return parse_gemfile_lock(&content, &lockfile);
    }
    let deps = match name {
        "package-lock.json" => parse_package_lock(&content)?,
        "yarn.lock" => parse_yarn_lock(&content)?,
        "pnpm-lock.yaml" => parse_pnpm_lock(&content)?,
        "Cargo.lock" => parse_cargo_lock(&content)?,
        "Pipfile.lock" => parse_pipfile_lock(&content)?,
        "composer.lock" => parse_composer_lock(&content)?,
        "pom.xml" => parse_pom_xml(&content)?,
        "requirements.txt" => parse_requirements(&content)?,
        "gradle.lockfile" => parse_gradle_lockfile(&content)?,
        "packages.lock.json" => parse_packages_lock_json(&content)?,
        "poetry.lock" => parse_poetry_lock(&content)?,
        "bun.lock" => parse_bun_lock(&content)?,
        "mix.lock" => parse_mix_lock(&content)?,
        "pubspec.lock" => parse_pubspec_lock(&content)?,
        _ => return Err("unsupported lockfile".into()),
    };

    Ok(deps
        .into_iter()
        .map(|(n, v)| Dependency {
            license: None,
            occurrence: crate::models::DependencyOccurrence {
                status: "unavailable".into(),
                ..Default::default()
            },
            ecosystem: ecosystem.clone(),
            name: n,
            version: v,
            lockfile: lockfile.clone(),
        })
        .collect())
}

pub fn extend_dependencies_bounded(
    aggregate: &mut Vec<Dependency>,
    incoming: Vec<Dependency>,
    max_dependencies: usize,
) -> Result<(), String> {
    if aggregate
        .len()
        .checked_add(incoming.len())
        .map_or(true, |total| total > max_dependencies)
    {
        return Err(format!(
            "{RESOURCE_LIMIT_PREFIX} dependency scan exceeds {max_dependencies} packages; scan a \
             smaller subdirectory or add ignore rules"
        ));
    }
    aggregate.extend(incoming);
    Ok(())
}

fn dependency_key(dependency: &Dependency) -> (String, String, String) {
    (
        dependency.ecosystem.clone(),
        dependency.name.clone(),
        dependency.version.clone(),
    )
}

fn strip_version_ops(v: &str) -> String {
    v.trim()
        .trim_start_matches(['=', '~', '^', '>', '<', '!', ' '])
        .trim_matches(['"', '\'', ' '])
        .to_string()
}

// ------------------------------------------------------------------ parsers

fn parse_package_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid package-lock.json: {e}"))?;
    let root_object = root
        .as_object()
        .ok_or_else(|| "invalid package-lock.json: expected an object".to_string())?;
    if !root_object.contains_key("packages") && !root_object.contains_key("dependencies") {
        return Err(
            "invalid package-lock.json: expected packages or dependencies inventory".into(),
        );
    }
    let mut out = Vec::new();

    if root.get("packages").is_some() {
        return super::relationships::parse_packages(&root)
            .map(|deps| deps.into_iter().map(|d| (d.name, d.version)).collect());
    }

    // v1: "dependencies" object (recursive)
    fn walk_deps(node: &serde_json::Value, out: &mut Vec<(String, String)>) -> Result<(), String> {
        if let Some(deps_value) = node.get("dependencies") {
            let deps = deps_value.as_object().ok_or_else(|| {
                "invalid package-lock.json: dependencies must be an object".to_string()
            })?;
            for (name, val) in deps {
                let dependency = val.as_object().ok_or_else(|| {
                    format!("invalid package-lock.json: dependency {name:?} must be an object")
                })?;
                let version = dependency
                    .get("version")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        format!("invalid package-lock.json: dependency {name:?} has no version")
                    })?;
                if name.trim().is_empty() || version.trim().is_empty() {
                    return Err(format!(
                        "invalid package-lock.json: dependency {name:?} has no version"
                    ));
                }
                // v1 aliases record the registry identity as `npm:name@version`.
                // An alias that cannot resolve to a real registry identity —
                // a bare scope, a missing name or version, or a version that
                // is a local or remote source — is malformed data, not an
                // entry to fabricate or silently drop.
                if let Some(aliased) = version.strip_prefix("npm:") {
                    let (target, target_version) = split_name_range(aliased);
                    let readable_name = !target.is_empty()
                        && !target.contains('\\')
                        && if let Some(scoped) = target.strip_prefix('@') {
                            scoped
                                .split_once('/')
                                .is_some_and(|(scope, name)| !scope.is_empty() && !name.is_empty())
                        } else {
                            !target.contains('@')
                        };
                    if !readable_name
                        || target_version.is_empty()
                        || nonregistry_protocol(&target_version)
                    {
                        return Err(format!(
                            "invalid package-lock.json: dependency {name:?} has an unresolved alias version"
                        ));
                    }
                    out.push((target, target_version));
                } else if !version.contains(':') && !version.contains('/') {
                    // Git, file, and link resolutions keep their URL or path
                    // in the version field; they have no registry version to
                    // query and are excluded from the inventory rather than
                    // reported with a false one.
                    out.push((name.clone(), version.to_string()));
                }
                walk_deps(val, out)?;
            }
        }
        Ok(())
    }
    walk_deps(&root, &mut out)?;

    // A supported lockfile that declares an empty inventory is complete: it
    // should yield zero OSV queries, not be recast as a parser failure.
    Ok(out)
}

fn parse_yarn_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;
    let mut field_indent: Option<usize> = None;
    let mut classic = false;

    fn flush(
        names: &[String],
        version: Option<&String>,
        classic: bool,
        out: &mut Vec<(String, String)>,
    ) {
        if let Some(v) = version {
            for selector in names {
                // Classic's npm: descriptor names the aliased package.
                // Berry also uses npm: for ordinary semver descriptors.
                let target = match selector.split_once("@npm:") {
                    Some((_, target)) if classic || target.contains('@') => target,
                    _ => selector.as_str(),
                };
                let name = split_name_range(target).0;
                if !name.is_empty() {
                    out.push((name, v.clone()));
                }
            }
        }
    }

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let is_header = trimmed.ends_with(':') && !line.starts_with([' ', '\t']);
        if is_header {
            flush(&current_names, current_version.as_ref(), classic, &mut out);
            current_names.clear();
            current_version = None;
            field_indent = None;
            classic = false;
            if trimmed == "__metadata:" {
                continue;
            }
            let header = trimmed.trim_end_matches(':');
            for part in header.split(',') {
                let part = part.trim().trim_matches(['"', '\'']);
                if part.is_empty() {
                    continue;
                }
                current_names.push(part.to_owned());
            }
        } else if !current_names.is_empty() {
            let indent = line.len() - line.trim_start().len();
            if indent != *field_indent.get_or_insert(indent) {
                continue;
            }
            // Classic uses `version "1.2.3"`; Berry uses `version: 1.2.3`.
            if let Some(value) = trimmed
                .strip_prefix("version ")
                .or_else(|| trimmed.strip_prefix("version:"))
            {
                let value = value.trim().trim_matches(['"', '\'']);
                if !value.is_empty() {
                    classic = trimmed.starts_with("version ");
                    current_version = Some(value.to_string());
                }
            }
        }
    }
    flush(&current_names, current_version.as_ref(), classic, &mut out);

    if out.is_empty() {
        return Err("no packages found in yarn.lock".into());
    }
    Ok(out)
}

/// Split '"@scope/name@^1.2.3"' into ("@scope/name", "^1.2.3").
fn split_name_range(s: &str) -> (String, String) {
    let s = s.trim();
    if let Some((name, range)) = s.rsplit_once('@') {
        if name.is_empty() {
            // string starts with @ but has no @range (e.g. "@scope/name")
            (s.to_string(), String::new())
        } else {
            (name.to_string(), range.to_string())
        }
    } else {
        (s.to_string(), String::new())
    }
}

// Only YAML inventories retain source order; JSON inventories keep their
// existing deterministic key order.
type YamlPackages = indexmap::IndexMap<String, serde_json::Value>;

#[derive(serde::Deserialize)]
struct YamlPackageLockfile {
    packages: Option<YamlPackages>,
}

/// pnpm lockfiles across versions carry a `lockfileVersion` marker plus one
/// of a few known inventory sections. The envelope check separates a real
/// lockfile (possibly empty) from arbitrary YAML that happens to sit in a
/// file named `pnpm-lock.yaml`.
#[derive(serde::Deserialize)]
struct PnpmLockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<serde_json::Value>,
    packages: Option<YamlPackages>,
    importers: Option<serde_json::Value>,
    snapshots: Option<serde_json::Value>,
    specifiers: Option<serde_json::Value>,
}

/// pnpm writes its format marker as an unquoted YAML number (`5.4`) or a
/// quoted string (`'6.0'`, `'9.0'`); YAML numbers arrive as f64 and string
/// forms must parse as numbers. Any positive numeric marker identifies a
/// pnpm lockfile — a whitelist would reject valid past (5.2) and future
/// markers, and f64 round-trips like 6.0/9.0 would not match a string list.
fn positive_pnpm_lockfile_version(value: &serde_json::Value) -> bool {
    let number = match value {
        serde_json::Value::Number(number) => number.as_f64(),
        serde_json::Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    };
    number.is_some_and(|number| number.is_finite() && number > 0.0)
}

/// Explicit non-registry resolution specifiers. `git@` covers scp-style git
/// URLs, `github:`/`gitlab:`/`bitbucket:` the npm shorthand host forms.
fn nonregistry_protocol(text: &str) -> bool {
    [
        "link:",
        "file:",
        "workspace:",
        "git+",
        "http://",
        "https://",
        "git://",
        "git@",
        "github:",
        "gitlab:",
        "bitbucket:",
    ]
    .iter()
    .any(|protocol| text.starts_with(protocol))
}

/// Registry evidence inside an importer or specifier value. The default is
/// registry: numbers and plain strings — including alias identities such as
/// `@aspect-test/a@5.0.2` and peer-suffixed versions like
/// `18.2.0(react@18.2.0)`, which contain slashes — prove a registry
/// dependency. Only the explicit non-registry protocols above are local
/// resolutions that carry no registry version.
fn registry_version_evidence(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(_) => true,
        serde_json::Value::String(text) => !nonregistry_protocol(text),
        _ => false,
    }
}

#[derive(serde::Deserialize)]
struct PipfileLockfile {
    default: Option<YamlPackages>,
    develop: Option<YamlPackages>,
}

fn parse_yaml_lockfile<T: serde::de::DeserializeOwned>(
    content: &str,
    name: &str,
) -> Result<T, String> {
    // Lockfiles are untrusted. Bound expansion as well as the file bytes
    // checked by the caller, and retain the previous YAML 1.2 scalar/merge behavior.
    let options = serde_saphyr::options! {
        strict_booleans: true,
        ignore_binary_tag_for_string: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        emit_comments: false,
        with_snippet: false,
        budget: serde_saphyr::budget! {
            max_depth: 64,
            max_documents: 1,
            max_nodes: MAX_DEPENDENCIES * 16,
            max_events: MAX_DEPENDENCIES * 32,
            max_anchors: 1_024,
            max_aliases: 1_024,
            max_recorded_anchor_events: 100_000,
            max_recorded_anchor_bytes: MAX_LOCKFILE_BYTES as usize,
            max_total_scalar_bytes: MAX_LOCKFILE_BYTES as usize,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 100_000,
            max_replay_stack_depth: 32,
            max_alias_expansions_per_anchor: 1_024,
        },
    };
    serde_saphyr::from_str_with_options(content, options).map_err(|error| {
        use serde_saphyr::Error;
        if matches!(
            error.without_snippet(),
            Error::Budget { .. }
                | Error::AliasReplayCounterOverflow { .. }
                | Error::AliasReplayLimitExceeded { .. }
                | Error::AliasExpansionLimitExceeded { .. }
                | Error::AliasReplayStackDepthExceeded { .. }
        ) {
            format!("{RESOURCE_LIMIT_PREFIX} {name}: {error}")
        } else {
            format!("invalid {name}: {error}")
        }
    })
}

fn parse_pnpm_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: PnpmLockfile = parse_yaml_lockfile(content, "pnpm-lock.yaml")?;
    // A real pnpm lockfile always declares its format version and at least
    // one of the known inventory sections; without both, the document is not
    // a readable pnpm inventory and must not scan as a complete empty one.
    if !root
        .lockfile_version
        .as_ref()
        .is_some_and(positive_pnpm_lockfile_version)
    {
        return Err("invalid pnpm-lock.yaml: unsupported or missing lockfileVersion".into());
    }
    if root.packages.is_none()
        && root.importers.is_none()
        && root.snapshots.is_none()
        && root.specifiers.is_none()
    {
        return Err("invalid pnpm-lock.yaml: no packages or importers inventory".into());
    }
    // The inventory sections are mappings in every pnpm format; a scalar
    // in their place (e.g. `importers: false`) is not a readable inventory.
    if let Some(importers) = &root.importers {
        if importers.as_object().is_none() {
            return Err("invalid pnpm-lock.yaml: importers must be a mapping".into());
        }
    }
    if let Some(snapshots) = &root.snapshots {
        if snapshots.as_object().is_none() {
            return Err("invalid pnpm-lock.yaml: snapshots must be a mapping".into());
        }
    }
    if let Some(specifiers) = &root.specifiers {
        if specifiers.as_object().is_none() {
            return Err("invalid pnpm-lock.yaml: specifiers must be a mapping".into());
        }
    }
    // An omitted or empty packages map is only a complete empty inventory
    // when nothing else declares a registry dependency. Importers and
    // specifiers that still pin registry versions, or a non-empty snapshots
    // map, mean the packages section was lost or truncated.
    if root
        .packages
        .as_ref()
        .map_or(true, |packages| packages.is_empty())
    {
        if let Some(importers) = root
            .importers
            .as_ref()
            .and_then(serde_json::Value::as_object)
        {
            for importer in importers.values() {
                let importer = importer
                    .as_object()
                    .ok_or("invalid pnpm-lock.yaml: importer entries must be mappings")?;
                for field in ["dependencies", "devDependencies", "optionalDependencies"] {
                    let Some(declarations) = importer.get(field) else {
                        continue;
                    };
                    let declarations = declarations.as_object().ok_or(
                        "invalid pnpm-lock.yaml: importer dependency sections must be mappings",
                    )?;
                    for entry in declarations.values() {
                        let evidence = match entry {
                            serde_json::Value::String(_) | serde_json::Value::Number(_) => {
                                registry_version_evidence(entry)
                            }
                            serde_json::Value::Object(_) => {
                                let entry = entry.as_object().expect("matched object");
                                for key in ["version", "specifier"] {
                                    if let Some(field_value) = entry.get(key) {
                                        if !matches!(
                                            field_value,
                                            serde_json::Value::String(_)
                                                | serde_json::Value::Number(_)
                                        ) {
                                            return Err(format!(
                                                "invalid pnpm-lock.yaml: importer {key} must be a string or number"
                                            ));
                                        }
                                    }
                                }
                                // The actual resolution wins: a local link
                                // version overrides a registry-looking
                                // specifier, and a registry version survives
                                // a non-registry specifier (tarballs keep
                                // their URL in the specifier).
                                match entry.get("version") {
                                    Some(version) => registry_version_evidence(version),
                                    None => match entry.get("specifier") {
                                        Some(specifier) => registry_version_evidence(specifier),
                                        None => {
                                            return Err("invalid pnpm-lock.yaml: importer dependency entry declares neither version nor specifier".into())
                                        }
                                    },
                                }
                            }
                            _ => {
                                return Err("invalid pnpm-lock.yaml: importer dependency entries must be strings, numbers, or specifier/version objects".into())
                            }
                        };
                        if evidence {
                            return Err("invalid pnpm-lock.yaml: importers declare registry dependencies but the packages inventory is missing".into());
                        }
                    }
                }
            }
        }
        if let Some(specifiers) = root
            .specifiers
            .as_ref()
            .and_then(serde_json::Value::as_object)
        {
            for spec in specifiers.values() {
                if !matches!(
                    spec,
                    serde_json::Value::String(_) | serde_json::Value::Number(_)
                ) {
                    return Err(
                        "invalid pnpm-lock.yaml: specifier values must be strings or numbers"
                            .into(),
                    );
                }
                if registry_version_evidence(spec) {
                    return Err("invalid pnpm-lock.yaml: specifiers declare registry dependencies but the packages inventory is missing".into());
                }
            }
        }
        if let Some(snapshots) = root
            .snapshots
            .as_ref()
            .and_then(serde_json::Value::as_object)
        {
            if !snapshots.is_empty() {
                return Err(
                    "invalid pnpm-lock.yaml: snapshots exist but the packages inventory is missing"
                        .into(),
                );
            }
        }
    }
    let mut out = Vec::new();
    if let Some(packages) = root.packages {
        for k in packages.keys() {
            // v5 uses /name/version; v6+ uses name@version. Peer
            // contexts are install identities, not advisory versions.
            let coordinate = k.trim_start_matches('/').split('(').next().unwrap_or("");
            let name_start = if coordinate.starts_with('@') {
                coordinate
                    .find('/')
                    .map(|slash| slash + 1)
                    .unwrap_or(coordinate.len())
            } else {
                0
            };
            let Some(separator) = coordinate[name_start..]
                .find(['@', '/'])
                .map(|offset| name_start + offset)
            else {
                return Err(format!(
                    "invalid pnpm-lock.yaml: unreadable package coordinate {k:?}"
                ));
            };
            let name = &coordinate[..separator];
            // The `_` peer suffix is an install identity, not part of the
            // version; split it before inspecting the version itself.
            let version = coordinate[separator + 1..].split('_').next().unwrap_or("");
            if name.is_empty() || version.is_empty() {
                return Err(format!(
                    "invalid pnpm-lock.yaml: unreadable package coordinate {k:?}"
                ));
            }
            // Git, link, and tarball resolutions keep their URL or path in
            // the coordinate; the same skip as bun.lock's: local and remote
            // sources have no registry version to query, and reporting the
            // URL or commit as an installed version would fabricate an
            // identity. These packages are excluded from the inventory and
            // from OSV queries, not reported with a false version.
            if version.contains(':') || version.contains('/') {
                continue;
            }
            out.push((name.to_string(), version.to_string()));
        }
    }
    // A supported lockfile that declares no registry packages (a project
    // with no dependencies, or only local/git sources) is a complete empty
    // inventory: it should yield zero OSV queries, not be recast as a
    // parser failure.
    Ok(out)
}

fn parse_cargo_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: toml::Value =
        toml::from_str(content).map_err(|e| format!("invalid Cargo.lock: {e}"))?;
    let mut out = Vec::new();
    if let Some(packages) = root.get("package").and_then(|p| p.as_array()) {
        for pkg in packages {
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    "invalid Cargo.lock package: name must be a nonempty string".to_string()
                })?
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    format!("invalid Cargo.lock package {name}: version must be a nonempty string")
                })?
                .to_string();
            out.push((name, version));
        }
    }
    if out.is_empty() {
        return Err("no packages found in Cargo.lock".into());
    }
    Ok(out)
}

/// Bun's JSONC package map is keyed by installation location (including
/// aliases). The first tuple element carries the resolved package identity.
fn parse_bun_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root = parse_bun_jsonc(content)?;
    let packages = root
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "bun.lock has no packages object".to_string())?;
    let mut out = Vec::new();
    for (key, entry) in packages {
        let invalid =
            || format!("invalid bun.lock package {key}: expected a resolved name@version tuple");
        let resolution = entry
            .as_array()
            .and_then(|tuple| tuple.first())
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        let start = usize::from(resolution.starts_with('@'));
        let at = resolution[start..].find('@').ok_or_else(invalid)? + start;
        let (name, version) = (&resolution[..at], &resolution[at + 1..]);
        if name.is_empty() || version.is_empty() {
            return Err(invalid());
        }
        // Local, git and tarball resolutions have no registry version to query.
        if version.contains(':') || version.contains('/') || version.starts_with("git+") {
            continue;
        }
        if !version.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(invalid());
        }
        out.push((name.to_string(), version.to_string()));
    }
    Ok(out)
}

/// Normalize only JSONC comments and trailing commas, outside quoted strings.
/// Replacing bytes with whitespace preserves locations for serde diagnostics.
fn parse_bun_jsonc(content: &str) -> Result<serde_json::Value, String> {
    let mut bytes = content.as_bytes().to_vec();
    let mut quoted = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quoted => i += 2,
            b'"' => {
                quoted = !quoted;
                i += 1;
            }
            b'/' if !quoted && bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && !matches!(bytes[i], b'\r' | b'\n') {
                    bytes[i] = b' ';
                    i += 1;
                }
            }
            b'/' if !quoted && bytes.get(i + 1) == Some(&b'*') => {
                bytes[i..i + 2].fill(b' ');
                i += 2;
                while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                    if !matches!(bytes[i], b'\r' | b'\n') {
                        bytes[i] = b' ';
                    }
                    i += 1;
                }
                if i + 1 >= bytes.len() {
                    return Err("invalid bun.lock: unterminated comment".into());
                }
                bytes[i..i + 2].fill(b' ');
                i += 2;
            }
            _ => i += 1,
        }
    }
    quoted = false;
    i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quoted => i += 2,
            b'"' => {
                quoted = !quoted;
                i += 1;
            }
            b',' if !quoted => {
                let next = bytes[i + 1..]
                    .iter()
                    .find(|byte| !byte.is_ascii_whitespace());
                let previous = bytes[..i]
                    .iter()
                    .rev()
                    .find(|byte| !byte.is_ascii_whitespace());
                if matches!(next, Some(b'}' | b']'))
                    && !matches!(previous, None | Some(b'{' | b'[' | b','))
                {
                    bytes[i] = b' ';
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid bun.lock: {error}"))
}

/// `mix.lock`: an Erlang map of `"name" => {:hex, :name, "version", …}`.
/// `:path` entries are local code, not registry packages.
fn parse_mix_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for line in content.lines() {
        // One package per line; the shape is fixed enough to read without an
        // Erlang term parser, and anything that does not fit is skipped.
        let rest = match line.trim_start().strip_prefix('"') {
            Some(rest) => rest,
            None => continue,
        };
        // The key ends with `": ` before the tuple; keep only real entries.
        let Some((name, rest)) = rest.split_once("\": ") else {
            continue;
        };
        let Some(rest) = rest.strip_prefix("{:hex,") else {
            continue;
        };
        // :atom, "version" — the version is the first quoted token after
        // the atom; the hash and deps follow in later fields.
        let Some((atom, tail)) = rest.split_once(',') else {
            continue;
        };
        if !atom.trim().starts_with(':') {
            continue;
        }
        let tail = tail.trim();
        let Some(after_open) = tail.strip_prefix('"') else {
            continue;
        };
        let version = after_open.split('"').next().unwrap_or_default();
        if !name.is_empty() && !version.is_empty() {
            out.push((name.to_string(), version.to_string()));
        }
    }
    if out.is_empty() {
        return Err("no hex packages found in mix.lock".into());
    }
    Ok(out)
}

/// `pubspec.lock`: YAML, one entry per package under `packages:`. Hosted and
/// git packages carry a registry version; `path` is local code and `sdk` is
/// the Dart/Flutter SDK itself — neither is a Pub advisory target.
fn parse_pubspec_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: YamlPackageLockfile = parse_yaml_lockfile(content, "pubspec.lock")?;
    let packages = root
        .packages
        .ok_or_else(|| "pubspec.lock has no packages map".to_string())?;
    let mut out = Vec::new();
    for (name, entry) in packages {
        let entry = entry
            .as_object()
            .ok_or_else(|| format!("invalid pubspec.lock package {name}: expected an object"))?;
        let source = entry
            .get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if matches!(source, "path" | "sdk") {
            continue;
        }
        let version = entry
            .get("version")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                format!("invalid pubspec.lock package {name}: version must be a nonempty string")
            })?;
        if name.trim().is_empty() {
            return Err("invalid pubspec.lock package: name must be nonempty".into());
        }
        out.push((name.to_string(), version.to_string()));
    }
    if out.is_empty() {
        return Err("no packages found in pubspec.lock".into());
    }
    Ok(out)
}

fn parse_pipfile_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: PipfileLockfile = parse_yaml_lockfile(content, "Pipfile.lock")?;
    let mut out = Vec::new();
    for map in [root.default, root.develop].into_iter().flatten() {
        for (name, val) in map {
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .map(strip_version_ops)
                .unwrap_or_default();
            if !name.is_empty() && !version.is_empty() {
                out.push((name.to_string(), version));
            }
        }
    }
    if out.is_empty() {
        return Err("no packages found in Pipfile.lock".into());
    }
    Ok(out)
}

fn parse_gemfile_lock(content: &str, lockfile: &str) -> Result<Vec<Dependency>, String> {
    static VERSION: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| regex::Regex::new(r"^[0-9]+(?:\.[0-9A-Za-z]+)*$").unwrap());
    static NAME: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| regex::Regex::new(r"^[A-Za-z0-9_.-]+$").unwrap());
    let mut out = Vec::new();
    let mut source = None;
    let mut in_specs = false;
    let mut saw_specs = false;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            source = match trimmed {
                "GEM" => Some("registry"),
                "GIT" => Some("git"),
                "PATH" => Some("local"),
                _ => None,
            };
            in_specs = false;
            continue;
        }
        let Some(source) = source else {
            continue;
        };
        if line == "  specs:" {
            in_specs = true;
            saw_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if indent == 6 {
            continue;
        } // Nested gem requirements, never resolved versions.
        let invalid = || format!("invalid Gemfile.lock specification on line {}", index + 1);
        if indent != 4 {
            return Err(invalid());
        }
        let (name, version) = trimmed.split_once(" (").ok_or_else(invalid)?;
        let version = version.strip_suffix(')').ok_or_else(invalid)?;
        let (version, platform) = version
            .split_once('-')
            .map_or((version, None), |(v, p)| (v, Some(p)));
        if !NAME.is_match(name) || !VERSION.is_match(version) || platform == Some("") {
            return Err(invalid());
        }
        let mut warnings = Vec::new();
        if source != "registry" {
            warnings.push(format!("{name} is from a {source} source; its declared gem version does not prove a RubyGems release. Registry advisory lookup is skipped; review its source code."));
        }
        if let Some(platform) = platform {
            warnings.push(format!("Ruby platform variant: {platform}; the lockfile may include platforms other than the current installation."));
        }
        out.push(Dependency {
            ecosystem: "RubyGems".into(),
            name: name.into(),
            version: version.into(),
            lockfile: lockfile.into(),
            license: None,
            occurrence: crate::models::DependencyOccurrence {
                source: Some(source.into()),
                platform: platform.map(str::to_string),
                local_workspace: source == "local",
                status: "unavailable".into(),
                warnings,
                ..Default::default()
            },
        });
    }
    if !saw_specs {
        return Err("no specification section found in Gemfile.lock".into());
    }
    Ok(out)
}

fn parse_composer_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid composer.lock: {e}"))?;
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        if let Some(value) = root.get(section) {
            let arr = value
                .as_array()
                .ok_or_else(|| format!("invalid composer.lock: {section} must be an array"))?;
            for pkg in arr {
                let name = pkg
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        "invalid composer.lock package: name must be a nonempty string".to_string()
                    })?
                    .to_string();
                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|value| !value.trim_start_matches('v').trim().is_empty())
                    .ok_or_else(|| format!("invalid composer.lock package {name}: version must be a nonempty string"))?
                    .trim_start_matches('v').to_string();
                out.push((name, version));
            }
        }
    }
    if out.is_empty() {
        return Err("no packages found in composer.lock".into());
    }
    Ok(out)
}

fn parse_pom_xml(content: &str) -> Result<Vec<(String, String)>, String> {
    use quick_xml::events::Event;
    use quick_xml::{Reader, XmlVersion};

    let mut reader = Reader::from_str(content);
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<(String, String, String)> = None; // groupId, artifactId, version
    let mut in_dependency = false;
    let mut in_dependencies = false;
    let mut pending_text = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                pending_text.clear();
                match name.as_str() {
                    "dependencies" | "dependencyManagement" => {
                        in_dependencies = true;
                        current = None;
                    }
                    "dependency" if in_dependencies => {
                        in_dependency = true;
                        current = None;
                    }
                    _ => {}
                }
                depth += 1;
            }
            Ok(Event::Empty(e)) => {
                let _ = e;
            }
            Ok(Event::Text(t)) => {
                if in_dependency {
                    pending_text.push_str(&t.xml_content(XmlVersion::Implicit1_0));
                }
            }
            // `&amp;` and `&#38;` arrive as their own events. A group or
            // artifact id containing one is unusual but legal, and dropping the
            // reference would silently corrupt the coordinate we look up.
            Ok(Event::GeneralRef(r)) => {
                if in_dependency {
                    match r.resolve_char_ref() {
                        Ok(Some(ch)) => pending_text.push(ch),
                        Ok(None) => {
                            if let Some(resolved) = quick_xml::escape::resolve_predefined_entity(&r)
                            {
                                pending_text.push_str(resolved);
                            }
                            // An unresolvable entity is defined in a DTD oxAudit
                            // does not read. Skipping it is the safe reading; a
                            // partial coordinate simply fails to match later.
                        }
                        Err(_) => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().as_ref().to_string();
                let text = std::mem::take(&mut pending_text).trim().to_string();
                if in_dependency && !text.is_empty() {
                    match name.as_str() {
                        "groupId" => match &mut current {
                            Some(c) => c.0 = text,
                            None => current = Some((text, String::new(), String::new())),
                        },
                        "artifactId" => match &mut current {
                            Some(c) => c.1 = text,
                            None => current = Some((String::new(), text, String::new())),
                        },
                        "version" => {
                            if let Some(c) = &mut current {
                                c.2 = text;
                            }
                        }
                        _ => {}
                    }
                }
                if name == "dependency" && in_dependency {
                    if let Some((g, a, v)) = current.take() {
                        if !a.is_empty() && !v.is_empty() {
                            let full = if g.is_empty() {
                                a.clone()
                            } else {
                                format!("{g}:{a}")
                            };
                            out.push((full, v));
                        }
                    }
                    in_dependency = false;
                }
                if name == "dependencies" || name == "dependencyManagement" {
                    in_dependencies = false;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("invalid pom.xml: {e}")),
            _ => {}
        }
    }

    if out.is_empty() {
        return Err("no dependencies with versions found in pom.xml".into());
    }
    Ok(out)
}

fn parse_requirements(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let logical_lines = content.replace("\\\r\n", " ").replace("\\\n", " ");
    for line in logical_lines.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Index options do not change inventory. Includes and editable
        // requirements do, and cannot be silently omitted from coverage.
        if [
            "--index-url",
            "--extra-index-url",
            "--no-index",
            "--find-links",
            "--trusted-host",
            "--require-hashes",
            "--pre",
            "--only-binary",
            "--no-binary",
        ]
        .iter()
        .any(|option| {
            line == *option
                || line
                    .strip_prefix(option)
                    .is_some_and(|suffix| suffix.starts_with([' ', '=']))
        }) {
            continue;
        }
        // strip environment markers: "pkg==1.0; python_version < '3.8'"
        let base = line.split(';').next().unwrap_or(line);
        let base = base.split(" #").next().unwrap_or(base);
        let base = base.split(" --hash").next().unwrap_or(base).trim();
        // strip extras: pkg[extra]==1.0
        let unresolved = || {
            format!("unresolved requirement {line:?}: pin every package to an exact version and scan included files separately; advisory coverage is incomplete")
        };
        let (name, version) = base.split_once("==").ok_or_else(unresolved)?;
        let name = name.trim();
        let name = match name.split_once('[') {
            Some((name, extras)) if extras.ends_with(']') => name.trim(),
            Some(_) => return Err(unresolved()),
            None => name,
        };
        let version = version.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            || version.is_empty()
            || !version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '!' | '+'))
        {
            return Err(unresolved());
        }
        out.push((name.to_string(), version.to_string()));
    }
    if out.is_empty() {
        return Err(
            "no pinned requirements found (unpinned packages can't be checked against OSV)".into(),
        );
    }
    Ok(out)
}

/// Gradle's dependency-locking format: one `group:artifact:version=classifiers`
/// entry per resolved module, grouped by module with a blank line and a
/// `# comment` header between groups. Coordinates become the same
/// `group:artifact` OSV Maven name a `pom.xml` produces.
fn parse_gradle_lockfile(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((coordinate, _classifiers)) = line.split_once('=') else {
            continue;
        };
        // `empty=` is Gradle's marker for a module with no dependencies.
        if coordinate == "empty" {
            continue;
        }
        let parts: Vec<&str> = coordinate.split(':').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            continue;
        }
        // Extra colon-separated segments exist for classifier coordinates
        // (`group:artifact:version:classifier`); the first three fields are
        // the identity OSV matches on.
        out.push((format!("{}:{}", parts[0], parts[1]), parts[2].to_string()));
    }
    if out.is_empty() {
        return Err("no locked modules found in gradle.lockfile".into());
    }
    Ok(out)
}

/// NuGet's restore lock format. Every target framework (including RID-specific
/// ones like `net8.0/linux-x64`) repeats the packages that apply to it; the
/// same pinned package under several targets is one dependency. Project
/// references carry no `resolved` version and are not registry packages.
fn parse_packages_lock_json(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid packages.lock.json: {e}"))?;
    let dependencies = root
        .get("dependencies")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "invalid packages.lock.json: no dependencies inventory".to_string())?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (_framework, packages) in dependencies {
        let Some(packages) = packages.as_object() else {
            return Err("invalid packages.lock.json: framework inventory must be an object".into());
        };
        for (name, details) in packages {
            if details.get("type").and_then(|value| value.as_str()) == Some("Project") {
                continue;
            }
            let version = details.get("resolved").and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("invalid packages.lock.json package {name}: resolved must be a nonempty string"))?;
            if name.trim().is_empty() {
                return Err("invalid packages.lock.json package: name must be nonempty".into());
            }
            if seen.insert((name.clone(), version.to_string())) {
                out.push((name.clone(), version.to_string()));
            }
        }
    }
    if out.is_empty() {
        return Err("no packages found in packages.lock.json".into());
    }
    Ok(out)
}

/// Poetry's lock format: `[[package]]` tables with `name` and `version`, the
/// same shape a `Cargo.lock` carries. Optional and dev packages are pinned
/// too, so they stay in the inventory.
fn parse_poetry_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: toml::Value =
        toml::from_str(content).map_err(|e| format!("invalid poetry.lock: {e}"))?;
    let mut out = Vec::new();
    if let Some(packages) = root.get("package").and_then(|p| p.as_array()) {
        for pkg in packages {
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    "invalid poetry.lock package: name must be a nonempty string".to_string()
                })?
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    format!("invalid poetry.lock package {name}: version must be a nonempty string")
                })?
                .to_string();
            out.push((name, version));
        }
    }
    if out.is_empty() {
        return Err("no packages found in poetry.lock".into());
    }
    Ok(out)
}

/// Deduplicate dependencies by (ecosystem, name, version), keeping first occurrence.
pub fn dedupe_dependencies(deps: Vec<Dependency>) -> Vec<Dependency> {
    let mut seen: BTreeMap<(String, String, String), Dependency> = BTreeMap::new();
    for d in deps {
        let key = dependency_key(&d);
        seen.entry(key).or_insert(d);
    }
    seen.into_values().collect()
}

#[cfg(test)]
mod pom_tests {
    use super::{
        extend_dependencies_bounded, parse_gradle_lockfile, parse_lockfile,
        parse_lockfile_with_limit, parse_package_lock, parse_packages_lock_json, parse_poetry_lock,
        parse_pom_xml,
    };

    /// A `pom.xml` comes from the repository under scan, so every property
    /// asserted here is a property of parsing *untrusted* input.
    fn pom(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
{body}
</project>"#
        )
    }

    fn lockfile_packages(name: &str, content: &str) -> Result<Vec<(String, String)>, String> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        std::fs::write(&path, content).unwrap();
        super::parse_lockfile(&path, super::lockfile_kind(name)).map(|dependencies| {
            dependencies
                .into_iter()
                .map(|d| (d.name, d.version))
                .collect()
        })
    }

    #[test]
    fn yarn_classic_resolved_versions_are_queryable() {
        let packages = lockfile_packages(
            "yarn.lock",
            r#"
# yarn lockfile v1
lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@scope/tool@^2.0.0":
  version "2.3.0"
"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("lodash".into(), "4.17.21".into()),
                ("@scope/tool".into(), "2.3.0".into()),
            ]
        );
    }

    #[test]
    fn nested_yarn_dependencies_cannot_overwrite_the_resolved_version() {
        for content in [
            r#"
tool@^1.0.0:
  version "1.2.3"
  dependencies:
    version "^0.1.0"
"#,
            r#"
"tool@npm:^1.0.0":
  version: 1.2.3
  dependencies:
    version: "npm:^0.1.0"
"#,
        ] {
            assert_eq!(
                lockfile_packages("yarn.lock", content).unwrap(),
                vec![("tool".into(), "1.2.3".into())]
            );
        }
    }

    #[test]
    fn yarn_npm_aliases_use_the_registry_package_name() {
        let packages = lockfile_packages(
            "yarn.lock",
            r#"
"my-tool@npm:tool@1.2.3":
  version "1.2.3"
"my-scoped@npm:@scope/tool@^2":
  version "2.3.4"
"my-any@npm:tool":
  version "3.4.5"
"my-scoped-any@npm:@scope/tool":
  version "4.5.6"
"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("tool".into(), "1.2.3".into()),
                ("@scope/tool".into(), "2.3.4".into()),
                ("tool".into(), "3.4.5".into()),
                ("@scope/tool".into(), "4.5.6".into()),
            ]
        );
        let berry = lockfile_packages(
            "yarn.lock",
            r#"
"tool@npm:^1":
  version: 1.2.3
"alias@npm:@scope/tool@^2":
  version: 2.3.4
"#,
        )
        .unwrap();
        assert_eq!(
            berry,
            vec![
                ("tool".into(), "1.2.3".into()),
                ("@scope/tool".into(), "2.3.4".into())
            ]
        );
    }

    #[test]
    fn pnpm_peer_context_does_not_become_part_of_the_package_coordinate() {
        let packages = lockfile_packages(
            "pnpm-lock.yaml",
            r#"
lockfileVersion: '6.0'
packages:
  /plugin@1.2.3(react@18.2.0): {}
  /@scope/tool@2.3.4(@scope/peer@1.0.0): {}
"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("plugin".into(), "1.2.3".into()),
                ("@scope/tool".into(), "2.3.4".into()),
            ]
        );
    }

    #[test]
    fn pnpm_legacy_slash_coordinates_and_peer_suffixes_are_queryable() {
        let packages = lockfile_packages(
            "pnpm-lock.yaml",
            r#"
lockfileVersion: 5.4
packages:
  /lodash/4.17.21: {}
  /@scope/tool/2.3.4_react@18.2.0: {}
"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("lodash".into(), "4.17.21".into()),
                ("@scope/tool".into(), "2.3.4".into()),
            ]
        );
    }

    #[test]
    fn pnpm_package_names_keep_underscores_and_scoped_peer_paths() {
        let packages = lockfile_packages(
            "pnpm-lock.yaml",
            r#"
lockfileVersion: 5.4
packages:
  /some_pkg@1.2.3: {}
  /@my_scope/tool_name/2.3.4_@peer/lib@1.0.0: {}
"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("some_pkg".into(), "1.2.3".into()),
                ("@my_scope/tool_name".into(), "2.3.4".into()),
            ]
        );
    }

    #[test]
    fn pnpm_git_and_link_coordinates_are_not_fabricated_versions() {
        // Real pnpm v9 git coordinates keep the repository URL and commit in
        // the key; reporting that as an installed version is a false identity.
        let packages = lockfile_packages(
            "pnpm-lock.yaml",
            r#"
lockfileVersion: '9.0'
packages:
  left-pad@git+https://git@github.com:stevemao/left-pad.git#2fca6157fcca165438e0f9495cf0e5a4e6f71349:
    resolution: {commit: 2fca6157fcca165438e0f9495cf0e5a4e6f71349, repo: git@github.com:stevemao/left-pad.git, type: git}
  express@4.19.2: {}
"#,
        )
        .unwrap();
        assert_eq!(packages, vec![("express".into(), "4.19.2".into())]);

        // v5 path-like git coordinates are skipped for the same reason.
        let packages = lockfile_packages(
            "pnpm-lock.yaml",
            "lockfileVersion: 5.4\npackages:\n  /github.com/stevemao/left-pad/2fca6157fcca: {}\n  /lodash/4.17.21: {}\n",
        )
        .unwrap();
        assert_eq!(packages, vec![("lodash".into(), "4.17.21".into())]);
    }

    #[test]
    fn pnpm_empty_and_local_only_inventories_are_complete() {
        // A zero-dependency pnpm project omits the packages map entirely;
        // local/git-only projects skip every coordinate. Neither is a parser
        // failure: the registry inventory is complete and empty.
        for content in [
            "lockfileVersion: '9.0'\nsettings: {}\nimporters:\n  .: {}\n",
            "lockfileVersion: '9.0'\npackages: {}\n",
            "lockfileVersion: '9.0'\npackages:\n  left-pad@git+https://github.com/stevemao/left-pad.git#2fca6157fcca: {}\n",
        ] {
            assert!(
                lockfile_packages("pnpm-lock.yaml", content)
                    .unwrap()
                    .is_empty(),
                "{content}"
            );
        }
    }

    #[test]
    fn pnpm_rejects_documents_that_are_not_lockfiles() {
        for (content, expected) in [
            ("name: just some yaml\n", "lockfileVersion"),
            ("metadata: {}\n", "lockfileVersion"),
            ("lockfileVersion: '9.0'\n", "inventory"),
            ("lockfileVersion: wat\npackages: {}\n", "lockfileVersion"),
            ("lockfileVersion: '9.0'\nimporters: false\n", "mapping"),
            ("lockfileVersion: '9.0'\nsnapshots: false\n", "mapping"),
            ("lockfileVersion: '9.0'\nspecifiers: false\n", "mapping"),
        ] {
            let error = lockfile_packages("pnpm-lock.yaml", content).unwrap_err();
            assert!(error.contains(expected), "{content}: {error}");
        }
    }

    #[test]
    fn pnpm_inventory_declaring_registry_dependencies_without_packages_is_truncated() {
        for content in [
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.18.0\n        version: 4.19.2\n",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.18.0\n",
            "lockfileVersion: 5.4\nspecifiers:\n  express: ^4.18.0\n",
            "lockfileVersion: 5.4\nimporters:\n  .:\n    dependencies:\n      express: 4.19.2\n",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      my-alias:\n        specifier: npm:@aspect-test/a@5.0.2\n        version: '@aspect-test/a@5.0.2'\n",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      tb:\n        specifier: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\n        version: left-pad@1.3.0\n",
            "lockfileVersion: '9.0'\nsnapshots:\n  express@4.19.2: {}\n",
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: {}\nsnapshots:\n  express@4.19.2: {}\n",
        ] {
            let error = lockfile_packages("pnpm-lock.yaml", content).unwrap_err();
            assert!(error.contains("packages inventory"), "{content}: {error}");
        }
    }

    #[test]
    fn pnpm_importer_sections_and_entries_are_type_checked() {
        for (content, expected) in [
            (
                "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: false\n",
                "sections must be mappings",
            ),
            (
                "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express:\n        version: {}\n",
                "version must be a string or number",
            ),
            (
                "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: []\n",
                "specifier must be a string or number",
            ),
            (
                "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express: {}\n",
                "neither version nor specifier",
            ),
            (
                "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express: true\n",
                "strings, numbers, or specifier/version objects",
            ),
            (
                "lockfileVersion: '9.0'\nspecifiers:\n  express: {version: 1.0.0}\n",
                "specifier values must be strings or numbers",
            ),
        ] {
            let error = lockfile_packages("pnpm-lock.yaml", content).unwrap_err();
            assert!(error.contains(expected), "{content}: {error}");
        }
    }

    #[test]
    fn pnpm_version_markers_accept_numeric_strings_and_legacy_versions() {
        // Unquoted YAML floats deserialize as numbers; string markers quote
        // '6.0'/'9.0'. All are the same marker and all must be readable,
        // including the 5.2 era predating the v5+ slash format.
        for content in [
            "lockfileVersion: 5.2\npackages: {}\n",
            "lockfileVersion: 5.4\npackages: {}\n",
            "lockfileVersion: 6.0\npackages: {}\n",
            "lockfileVersion: 9.0\npackages: {}\n",
            "lockfileVersion: '6.0'\npackages: {}\n",
            "lockfileVersion: '9.0'\npackages: {}\n",
            "lockfileVersion: '6.1'\npackages: {}\n",
            // Local-only importers are a complete empty inventory.
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ui:\n        specifier: workspace:*\n        version: link:../ui\n",
            "lockfileVersion: 5.4\nspecifiers:\n  ui: workspace:*\n",
            // The actual local resolution overrides a registry-looking
            // specifier: the package is not a registry install.
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ui:\n        specifier: ^4.0.0\n        version: file:../ui\n",
        ] {
            assert!(
                lockfile_packages("pnpm-lock.yaml", content)
                    .unwrap()
                    .is_empty(),
                "{content}"
            );
        }
    }

    #[test]
    fn pnpm_unreadable_package_coordinates_are_malformed_not_ignored() {
        for coordinate in ["tool", "'@1.2.3'", "tool@", "/tool/", "'@scope@1.2.3'"] {
            let content = format!("lockfileVersion: '9.0'\npackages:\n  {coordinate}: {{}}\n");
            let error = lockfile_packages("pnpm-lock.yaml", &content).unwrap_err();
            assert!(error.contains("coordinate"), "{content}: {error}");
        }
    }

    #[test]
    fn yaml_lockfiles_preserve_aliases_and_package_order() {
        for (name, content, expected) in [
            (
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\nmetadata: &metadata {integrity: sha512-example}\npackages:\n  zebra@2.0.0: *metadata\n  alpha@1.0.0: *metadata\n",
                vec![("zebra", "2.0.0"), ("alpha", "1.0.0")],
            ),
            (
                "pubspec.lock",
                "version: &version '1.2.3'\npackages:\n  zebra: {source: hosted, version: *version}\n  no: {source: git, version: '2.3.4'}\n  local: {source: path, version: '3.4.5'}\n  flutter: {source: sdk, version: '4.5.6'}\n",
                vec![("zebra", "1.2.3"), ("no", "2.3.4")],
            ),
            (
                "Pipfile.lock",
                r#"{"_meta":{"pipfile-spec":6},"default":{"zebra":{"version":"==2.0.0","hashes":["sha256:example"]},"alpha":{"version":"==1.0.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}"#,
                vec![("zebra", "2.0.0"), ("alpha", "1.0.0"), ("pytest", "8.0.0")],
            ),
        ] {
            let packages = lockfile_packages(name, content).unwrap();
            let packages: Vec<_> = packages
                .iter()
                .map(|(name, version)| (name.as_str(), version.as_str()))
                .collect();
            assert_eq!(packages, expected, "{name}");
        }
    }

    #[test]
    fn yaml_lockfiles_keep_binary_tagged_versions_as_literal_strings() {
        for (name, content, version) in [
            (
                "pubspec.lock",
                "packages: {tool: {source: hosted, version: !!binary 'MS4yLjM='}}",
                "MS4yLjM=",
            ),
            (
                "Pipfile.lock",
                "default: {tool: {version: !!binary '==1.2.3'}}",
                "1.2.3",
            ),
        ] {
            assert_eq!(
                lockfile_packages(name, content).unwrap(),
                vec![("tool".to_string(), version.to_string())],
                "{name}"
            );
        }
    }

    #[test]
    fn yaml_lockfiles_reject_malformed_and_ambiguous_documents() {
        for (name, inventory) in [
            ("pnpm-lock.yaml", "packages: {tool@1.2.3: {}}\n"),
            (
                "pubspec.lock",
                "packages: {tool: {source: hosted, version: '1.2.3'}}\n",
            ),
            ("Pipfile.lock", "default: {tool: {version: '==1.2.3'}}\n"),
        ] {
            for suffix in [
                "metadata: [unterminated",
                "metadata: *undefined",
                "metadata: &cycle {self: *cycle}",
                "metadata: {}\nmetadata: {}",
                "---\nmetadata: {}",
            ] {
                let content = format!("{inventory}{suffix}");
                assert!(
                    lockfile_packages(name, &content).is_err(),
                    "accepted {name}: {content}"
                );
            }
        }
    }

    #[test]
    fn yaml_lockfiles_report_excessive_nesting_as_a_resource_limit() {
        let content = format!("metadata: {}0{}\n", "[".repeat(96), "]".repeat(96));
        for name in ["pnpm-lock.yaml", "pubspec.lock", "Pipfile.lock"] {
            let error = lockfile_packages(name, &content).unwrap_err();
            assert!(super::is_resource_limit_error(&error), "{name}: {error}");
        }
    }

    #[test]
    fn yaml_lockfiles_bound_alias_expansion() {
        let content = format!(
            "base: &base [a, b, c, d]\nmetadata: [{}]\n",
            vec!["*base"; 2_000].join(", ")
        );
        for name in ["pnpm-lock.yaml", "pubspec.lock", "Pipfile.lock"] {
            let error = lockfile_packages(name, &content).unwrap_err();
            assert!(super::is_resource_limit_error(&error), "{name}: {error}");
        }
    }

    #[test]
    fn pinned_requirements_strip_extras_comments_and_hash_options() {
        let packages = lockfile_packages(
            "requirements.txt",
            r#"requests[security,socks]==2.31.0 # pinned
example==1.0+local \
    --hash=sha256:abcdef
"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("requests".into(), "2.31.0".into()),
                ("example".into(), "1.0+local".into()),
            ]
        );
    }

    #[test]
    fn requirement_ranges_and_unread_includes_cannot_look_like_complete_inventory() {
        for unresolved in [
            "flask>=2.0",
            "flask<=2.0",
            "flask~=2.0",
            "flask",
            "flask==2.*",
            "-r more.txt",
        ] {
            let error = lockfile_packages(
                "requirements.txt",
                &format!("requests==2.31.0\n{unresolved}\n"),
            )
            .expect_err("unresolved requirements must leave coverage incomplete");
            assert!(error.contains(unresolved), "{error}");
        }
    }

    #[test]
    fn npm_relationships_preserve_workspace_nested_paths_types_and_unknowns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        std::fs::write(&path, r#"{"lockfileVersion":3,"packages":{
          "":{"workspaces":["packages/*"],"dependencies":{"parent":"1.0.0","leaf":"1.0.0"}},
          "packages/worker":{"name":"@qa/worker","devDependencies":{"leaf":"1.0.0"}},
          "node_modules/@qa/worker":{"resolved":"packages/worker","link":true},
          "node_modules/parent":{"version":"1.0.0","optionalDependencies":{"leaf":"2.0.0"},"peerDependencies":{"missing":"*"}},
          "node_modules/parent/node_modules/leaf":{"version":"2.0.0","dependencies":{"parent":"1.0.0"}},
          "node_modules/leaf":{"version":"1.0.0"}}}"#).unwrap();
        let deps = parse_lockfile(&path, "npm").unwrap();
        assert_eq!(deps.len(), 4);
        let leaf = deps
            .iter()
            .find(|d| d.name == "leaf" && d.version == "1.0.0")
            .unwrap();
        let json = serde_json::to_value(leaf).unwrap();
        assert_eq!(json["occurrence"]["installPath"], "node_modules/leaf");
        let paths = json["occurrence"]["paths"].as_array().unwrap();
        assert!(paths.iter().any(
            |p| p["workspace"] == "packages/worker" && p["chain"][0]["dependencyType"] == "dev"
        ));
        assert!(paths
            .iter()
            .any(|p| p["workspace"] == "" && p["entryPoint"] == "leaf"));
        let nested = deps.iter().find(|d| d.version == "2.0.0").unwrap();
        let json = serde_json::to_value(nested).unwrap();
        assert_eq!(json["occurrence"]["paths"][0]["entryPoint"], "parent");
        assert_eq!(
            json["occurrence"]["paths"][0]["chain"][1]["dependencyType"],
            "optional"
        );
        assert!(json["occurrence"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("missing")));
        assert!(deps
            .iter()
            .any(|d| d.name == "@qa/worker" && d.version.is_empty()));
    }

    #[test]
    fn npm_authoritative_inventory_uses_nested_and_alias_identity() {
        let packages = parse_package_lock(
            r#"{"lockfileVersion":2,"packages":{
          "":{},"node_modules/parent":{"version":"1.0.0"},
          "node_modules/parent/node_modules/@scope/child":{"version":"2.0.0"},
          "node_modules/alias":{"name":"actual","version":"3.0.0"}},
          "dependencies":{"ghost":{"version":"9.0.0"}}}"#,
        )
        .unwrap();
        assert_eq!(
            packages,
            vec![
                ("actual".into(), "3.0.0".into()),
                ("parent".into(), "1.0.0".into()),
                ("@scope/child".into(), "2.0.0".into())
            ]
        );
    }

    #[test]
    fn aggregate_preserves_repeated_lockfile_occurrences_and_budgets_them() {
        let first = crate::models::Dependency {
            license: None,
            occurrence: Default::default(),
            ecosystem: "npm".into(),
            name: "example".into(),
            version: "1.0.0".into(),
            lockfile: "a/package-lock.json".into(),
        };
        let mut second = first.clone();
        second.lockfile = "b/package-lock.json".into();
        let mut aggregate = vec![first];
        extend_dependencies_bounded(&mut aggregate, vec![second.clone()], 2).unwrap();
        assert_eq!(aggregate.len(), 2, "inventory must preserve both locations");
        assert!(extend_dependencies_bounded(&mut aggregate, vec![second], 2).is_err());
    }

    #[test]
    fn oversized_lockfiles_are_rejected_before_their_contents_are_read() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("requirements.txt");
        std::fs::write(&path, "package==1.0\n").expect("fixture");

        let error = parse_lockfile_with_limit(&path, "pip", 8).expect_err("oversized");

        assert!(error.contains("resource limit"), "{error}");
        assert!(error.contains("8 bytes"), "{error}");
    }

    #[test]
    fn npm_v3_root_only_inventory_is_a_valid_empty_result() {
        let empty = parse_package_lock(
            r#"{"name":"empty-app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"empty-app","version":"1.0.0"}}}"#,
        )
        .expect("a root-only npm lockfile is a complete empty inventory");
        assert!(empty.is_empty());

        let populated = parse_package_lock(
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/example":{"version":"1.2.3"}}}"#,
        )
        .expect("a populated npm lockfile parses alongside the empty form");
        assert_eq!(populated, vec![("example".into(), "1.2.3".into())]);
    }

    #[test]
    fn valid_empty_and_populated_npm_lockfiles_parse_together() {
        let directory = tempfile::tempdir().expect("temporary monorepo");
        let empty_path = directory.path().join("package-lock.json");
        let populated_path = directory.path().join("package").join("package-lock.json");
        std::fs::create_dir_all(populated_path.parent().expect("nested package"))
            .expect("nested directory");
        std::fs::write(
            &empty_path,
            r#"{"lockfileVersion":3,"packages":{"":{"name":"empty-app","version":"1.0.0"}}}"#,
        )
        .expect("empty lockfile");
        std::fs::write(
            &populated_path,
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/example":{"version":"1.2.3"}}}"#,
        )
        .expect("populated lockfile");

        assert!(parse_lockfile(&empty_path, "npm")
            .expect("valid empty inventory")
            .is_empty());
        assert_eq!(
            parse_lockfile(&populated_path, "npm")
                .expect("populated inventory")
                .len(),
            1
        );
    }

    #[test]
    fn npm_v1_dependency_without_a_version_is_malformed_not_queryable() {
        let error = parse_package_lock(r#"{"dependencies":{"example":{"version":""}}}"#)
            .expect_err("an unqueryable v1 dependency must not look complete");
        assert!(error.contains("example"), "{error}");
        assert!(error.contains("no version"), "{error}");
    }

    #[test]
    fn npm_v3_rejects_missing_null_and_empty_package_versions() {
        for package in [r#"{}"#, r#"{"version":null}"#, r#"{"version":""}"#] {
            let error = parse_package_lock(&format!(
                r#"{{"lockfileVersion":3,"packages":{{"node_modules/example":{package}}}}}"#
            ))
            .expect_err("a non-link package needs a queryable version");
            assert!(error.contains("node_modules/example"), "{error}");
            assert!(error.contains("version"), "{error}");
        }
    }

    #[test]
    fn npm_v3_validates_root_metadata_and_preserves_workspace_links() {
        for root in [r#"null"#, r#"{"version":null}"#, r#"{"version":""}"#] {
            let error = parse_package_lock(&format!(
                r#"{{"lockfileVersion":3,"packages":{{"":{root}}}}}"#
            ))
            .expect_err("malformed root metadata must not make an empty inventory clean");
            assert!(error.contains("root package"), "{error}");
        }

        let packages = parse_package_lock(
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "workspace-root", "version": "1.0.0", "workspaces":["packages/*"] },
                "packages/workspace-package": { "name":"workspace-package" },
                "node_modules/workspace-package": {
                  "resolved": "packages/workspace-package",
                  "link": true
                },
                "node_modules/registry-package": { "version": "2.0.0" }
              }
            }"#,
        )
        .expect("workspace links are metadata rather than unversioned registry packages");

        assert_eq!(
            packages,
            vec![
                ("registry-package".into(), "2.0.0".into()),
                ("workspace-package".into(), "".into())
            ]
        );
    }

    #[test]
    fn npm_v1_nested_dependencies_are_walked_without_rebuilding_subtrees() {
        let packages = parse_package_lock(
            r#"{"dependencies":{"outer":{"version":"1.0.0","dependencies":{"inner":{"version":"2.0.0"}}}}}"#,
        )
        .expect("nested v1 dependencies parse");
        assert_eq!(
            packages,
            vec![
                ("outer".into(), "1.0.0".into()),
                ("inner".into(), "2.0.0".into()),
            ]
        );
    }

    #[test]
    fn npm_v1_aliases_resolve_to_the_registry_package() {
        // npm 6 writes aliases as "version": "npm:name@version"; the JSON
        // key is the alias, not the registry identity.
        let packages = parse_package_lock(
            r#"{"lockfileVersion":1,"dependencies":{
                "my-lodash":{"version":"npm:lodash@4.17.21"},
                "my-scoped":{"version":"npm:@babel/core@7.0.0"},
                "plain":{"version":"3.0.0"}
            }}"#,
        )
        .expect("v1 aliases pin a registry version");
        assert_eq!(
            packages,
            vec![
                ("lodash".into(), "4.17.21".into()),
                ("@babel/core".into(), "7.0.0".into()),
                ("plain".into(), "3.0.0".into()),
            ]
        );
    }

    #[test]
    fn npm_v1_non_registry_versions_are_skipped_not_fabricated() {
        // npm 6 keeps git and file resolutions as "version" strings. They
        // have no registry version to query.
        let packages = parse_package_lock(
            r#"{"lockfileVersion":1,"dependencies":{
                "left-pad":{"version":"git+https://github.com/stevemao/left-pad.git#2fca6157fcca165438e0f9495cf0e5a4e6f71349"},
                "locdep":{"version":"file:local"},
                "regular":{"version":"1.2.3","dependencies":{"nested":{"version":"npm:lodash@2.0.0"}}}
            }}"#,
        )
        .expect("non-registry v1 entries are skipped, not fabricated");
        assert_eq!(
            packages,
            vec![
                ("regular".into(), "1.2.3".into()),
                ("lodash".into(), "2.0.0".into()),
            ]
        );
    }

    #[test]
    fn npm_v1_unresolved_aliases_are_malformed_not_skipped() {
        for version in [
            "npm:",
            "npm:lodash",
            "npm:@babel/core",
            "npm:@scope@1.0.0",
            "npm:lodash@file:../local",
        ] {
            let error = parse_package_lock(&format!(
                r#"{{"dependencies":{{"alias":{{"version":"{version}"}}}}}}"#
            ))
            .expect_err("an alias without a pinned registry version must not vanish");
            assert!(error.contains("alias"), "{version}: {error}");
        }
    }

    #[test]
    fn aggregate_dependency_overflow_is_rejected_before_extension() {
        let dependency = crate::models::Dependency {
            license: None,
            occurrence: Default::default(),
            ecosystem: "npm".into(),
            name: "package".into(),
            version: "1.0.0".into(),
            lockfile: "package-lock.json".into(),
        };
        let distinct = crate::models::Dependency {
            license: None,
            occurrence: Default::default(),
            name: "other-package".into(),
            ..dependency.clone()
        };
        let mut aggregate = vec![dependency.clone()];

        let error = extend_dependencies_bounded(&mut aggregate, vec![distinct], 1)
            .expect_err("aggregate overflow");

        assert!(error.contains("resource limit"), "{error}");
        assert_eq!(aggregate.len(), 1, "overflow must not partially extend");
        assert!(error.contains("smaller subdirectory"), "{error}");
    }

    #[test]
    fn duplicate_dependencies_consume_the_occurrence_budget() {
        let dependency = crate::models::Dependency {
            license: None,
            occurrence: Default::default(),
            ecosystem: "npm".into(),
            name: "package".into(),
            version: "1.0.0".into(),
            lockfile: "package-lock.json".into(),
        };
        let mut aggregate = vec![dependency.clone()];

        extend_dependencies_bounded(&mut aggregate, vec![dependency], 1)
            .expect_err("every inventory occurrence consumes budget");

        assert_eq!(aggregate.len(), 1);
    }

    #[test]
    fn reads_group_artifact_and_version() {
        let out = parse_pom_xml(&pom(r#"  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>"#))
        .expect("a well-formed pom with one dependency parses");
        assert_eq!(
            out,
            vec![("org.apache.commons:commons-lang3".into(), "3.12.0".into())]
        );
    }

    #[test]
    fn reads_every_dependency_in_order() {
        let out = parse_pom_xml(&pom(r#"  <dependencies>
    <dependency>
      <groupId>com.example</groupId><artifactId>alpha</artifactId><version>1.0</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId><artifactId>beta</artifactId><version>2.0</version>
    </dependency>
  </dependencies>"#))
        .expect("two dependencies parse");
        assert_eq!(
            out,
            vec![
                ("com.example:alpha".into(), "1.0".into()),
                ("com.example:beta".into(), "2.0".into()),
            ]
        );
    }

    #[test]
    fn reads_dependency_management_section() {
        let out = parse_pom_xml(&pom(r#"  <dependencyManagement>
    <dependency>
      <groupId>io.netty</groupId><artifactId>netty-all</artifactId><version>4.1.68.Final</version>
    </dependency>
  </dependencyManagement>"#))
        .expect("dependencyManagement is treated as a dependency source");
        assert_eq!(
            out,
            vec![("io.netty:netty-all".into(), "4.1.68.Final".into())]
        );
    }

    #[test]
    fn skips_a_dependency_with_no_version() {
        // Version comes from a parent POM or a property oxAudit does not resolve.
        // Reporting it as unversioned would produce a bogus advisory query.
        let err = parse_pom_xml(&pom(r#"  <dependencies>
    <dependency>
      <groupId>com.example</groupId><artifactId>inherited</artifactId>
    </dependency>
  </dependencies>"#))
        .expect_err("a dependency with no version yields no packages");
        assert!(err.contains("no dependencies with versions"), "got: {err}");
    }

    #[test]
    fn falls_back_to_artifact_id_when_group_is_absent() {
        let out = parse_pom_xml(&pom(r#"  <dependencies>
    <dependency><artifactId>lonely</artifactId><version>0.1</version></dependency>
  </dependencies>"#))
        .expect("an artifactId with a version is still identifiable");
        assert_eq!(out, vec![("lonely".into(), "0.1".into())]);
    }

    #[test]
    fn ignores_dependency_elements_outside_a_dependencies_block() {
        let err = parse_pom_xml(&pom(r#"  <build>
    <dependency>
      <groupId>com.example</groupId><artifactId>stray</artifactId><version>9.9</version>
    </dependency>
  </build>"#))
        .expect_err("a <dependency> outside <dependencies> is not a declared dependency");
        assert!(err.contains("no dependencies with versions"), "got: {err}");
    }

    #[test]
    fn unescapes_xml_entities_in_values() {
        let out = parse_pom_xml(&pom(r#"  <dependencies>
    <dependency>
      <groupId>a&amp;b</groupId><artifactId>c&amp;d</artifactId><version>1.0</version>
    </dependency>
  </dependencies>"#))
        .expect("entities are decoded rather than passed through");
        assert_eq!(out, vec![("a&b:c&d".into(), "1.0".into())]);
    }

    #[test]
    fn rejects_a_pom_with_no_dependencies() {
        let err = parse_pom_xml(&pom("  <name>empty</name>"))
            .expect_err("a pom with no dependencies is reported, not silently empty");
        assert!(err.contains("no dependencies with versions"), "got: {err}");
    }

    #[test]
    fn reports_malformed_xml_as_an_error() {
        let err = parse_pom_xml("<project><dependencies><dependency>")
            .expect_err("an unterminated document is an error, not a panic");
        assert!(
            err.contains("invalid pom.xml") || err.contains("no dependencies"),
            "got: {err}"
        );
    }

    #[test]
    fn deeply_nested_input_terminates_without_exhausting_the_stack() {
        // A scan target can ship a hostile pom.xml. The parser is iterative, so
        // nesting depth must cost heap, not stack. This is a regression guard
        // for the class of bug RUSTSEC-2026-0187 describes in lopdf.
        let depth = 50_000;
        let mut xml = String::with_capacity(depth * 8);
        xml.push_str("<project>");
        for _ in 0..depth {
            xml.push_str("<x>");
        }
        for _ in 0..depth {
            xml.push_str("</x>");
        }
        xml.push_str("</project>");

        // Either outcome is acceptable; hanging or aborting is not.
        let _ = parse_pom_xml(&xml);
    }

    #[test]
    fn repeated_attributes_do_not_stall_the_parser() {
        // RUSTSEC-2026-0194 is quadratic only for callers that read attributes.
        // oxAudit never does, and this locks that in: a start tag carrying many
        // duplicate attributes must still parse promptly.
        let attributes = (0..2_000)
            .map(|index| format!(r#"a{index}="v""#))
            .collect::<Vec<_>>()
            .join(" ");
        let xml = format!(
            r#"<project><dependencies><dependency {attributes}>
                 <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
               </dependency></dependencies></project>"#
        );
        let out = parse_pom_xml(&xml).expect("attributes are skipped, not enumerated");
        assert_eq!(out, vec![("g:a".into(), "1".into())]);
    }

    // ------------------------------------------------------ gradle.lockfile

    #[test]
    fn gradle_locked_modules_become_maven_coordinates() {
        let out = parse_gradle_lockfile(
            "# This is a Gradle generated file for dependency locking.\n\
             # Manual edits can break the build and are not advised.\n\
             com.google.guava:guava:32.1.1-jre=compileClasspath,runtimeClasspath\n\
             org.slf4j:slf4j-api:1.7.36=compileClasspath\n\
             \n\
             # Another module's block\n\
             org.junit.jupiter:junit-jupiter:5.10.1=testCompileClasspath\n\
             empty=\n",
        )
        .expect("a generated gradle.lockfile parses");
        assert_eq!(
            out,
            vec![
                ("com.google.guava:guava".into(), "32.1.1-jre".into()),
                ("org.slf4j:slf4j-api".into(), "1.7.36".into()),
                ("org.junit.jupiter:junit-jupiter".into(), "5.10.1".into()),
            ]
        );
    }

    #[test]
    fn gradle_classifier_coordinates_keep_their_identity() {
        let out = parse_gradle_lockfile(
            "org.example:lib:1.0.0:sources=compileClasspath\norg.example:lib:1.0.0=runtimeClasspath\n",
        )
        .expect("classifier and plain entries both parse");
        assert_eq!(
            out,
            vec![
                ("org.example:lib".into(), "1.0.0".into()),
                ("org.example:lib".into(), "1.0.0".into()),
            ]
        );
    }

    #[test]
    fn a_gradle_lockfile_with_no_modules_is_reported() {
        let error = parse_gradle_lockfile("# only comments\n\nempty=\n")
            .expect_err("an empty inventory must not look like a parsed one");
        assert!(error.contains("no locked modules"), "got: {error}");
    }

    #[test]
    fn gradle_kind_maps_to_the_maven_ecosystem() {
        assert_eq!(super::lockfile_kind("gradle.lockfile"), "gradle");
        assert_eq!(super::ecosystem_for_kind("gradle"), "Maven");
    }

    // --------------------------------------------------- packages.lock.json

    #[test]
    fn nuget_lock_parses_frameworks_and_deduplicates_targets() {
        let out = parse_packages_lock_json(
            r#"{
              "version": 1,
              "dependencies": {
                "net8.0": {
                  "Newtonsoft.Json": {
                    "type": "Direct",
                    "requested": "[13.0.3, )",
                    "resolved": "13.0.3",
                    "contentHash": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3vDE+f5sL6xRx9GmnNlbA5J6JpPj4iGH9MDm5fzq"
                  },
                  "Microsoft.Extensions.Primitives": {
                    "type": "Transitive",
                    "resolved": "2.2.0"
                  }
                },
                "net8.0/linux-x64": {
                  "Newtonsoft.Json": {
                    "type": "Direct",
                    "resolved": "13.0.3"
                  }
                },
                "netstandard2.0": {}
              }
            }"#,
        )
        .expect("a restore lock with two targets parses");
        assert_eq!(
            out,
            vec![
                ("Microsoft.Extensions.Primitives".into(), "2.2.0".into()),
                ("Newtonsoft.Json".into(), "13.0.3".into()),
            ]
        );
    }

    #[test]
    fn nuget_project_references_have_no_version_and_are_skipped() {
        let out = parse_packages_lock_json(
            r#"{"version":1,"dependencies":{"net8.0":{
              "MyApp.Core":{"type":"Project"},
              "Serilog":{"type":"Direct","resolved":"3.1.1"}
            }}}"#,
        )
        .expect("project entries are not registry packages");
        assert_eq!(out, vec![("Serilog".into(), "3.1.1".into())]);
    }

    #[test]
    fn a_nuget_lock_without_an_inventory_is_malformed() {
        let error = parse_packages_lock_json(r#"{"version":1}"#)
            .expect_err("no dependencies key means the file is not a restore lock");
        assert!(error.contains("no dependencies inventory"), "got: {error}");
    }

    #[test]
    fn nuget_kind_maps_to_its_own_ecosystem() {
        assert_eq!(super::lockfile_kind("packages.lock.json"), "nuget");
        assert_eq!(super::ecosystem_for_kind("nuget"), "NuGet");
    }

    // ---------------------------------------------------------- poetry.lock

    #[test]
    fn malformed_registry_records_cannot_be_silently_dropped() {
        let cases = [
            ("packages.lock.json", r#"{"version":1,"dependencies":{"net8.0":{"Good":{"type":"Direct","resolved":"1.0.0"},"Broken":{"type":"Transitive"}}}}"#),
            ("packages.lock.json", r#"{"version":1,"dependencies":{"net8.0":{"Good":{"resolved":"1.0.0"},"Broken":null}}}"#),
            ("Cargo.lock", "[[package]]\nname = \"good\"\nversion = \"1.0.0\"\n[[package]]\nname = \"broken\"\n"),
            ("poetry.lock", "[[package]]\nname = \"good\"\nversion = \"1.0.0\"\n[[package]]\nname = \"broken\"\nversion = 123\n"),
            ("composer.lock", r#"{"packages":[{"name":"vendor/good","version":"1.0.0"},{"name":"vendor/broken"}]}"#),
            ("composer.lock", r#"{"packages":[{"name":"vendor/good","version":"1.0.0"}],"packages-dev":{}}"#),
            ("pubspec.lock", "packages:\n  good:\n    source: hosted\n    version: '1.0.0'\n  broken:\n    source: hosted\n"),
            ("pubspec.lock", "packages:\n  good:\n    source: hosted\n    version: '1.0.0'\n  broken: null\n"),
        ];
        let failures = cases
            .into_iter()
            .filter_map(|(name, content)| {
                lockfile_packages(name, content)
                    .ok()
                    .map(|packages| format!("{name}: {packages:?}"))
            })
            .collect::<Vec<_>>();
        assert!(
            failures.is_empty(),
            "malformed inventories were accepted: {failures:?}"
        );
    }

    #[test]
    fn poetry_lock_parses_packages_and_ignores_metadata() {
        let out = parse_poetry_lock(
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\noptional = false\n\n\
             [[package]]\nname = \"certifi\"\nversion = \"2024.2.2\"\n\n\
             [metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
        )
        .expect("a poetry lock with two packages parses");
        assert_eq!(
            out,
            vec![
                ("requests".into(), "2.31.0".into()),
                ("certifi".into(), "2024.2.2".into()),
            ]
        );
    }

    #[test]
    fn a_poetry_lock_with_no_packages_is_reported() {
        let error = parse_poetry_lock("[metadata]\nlock-version = \"2.0\"\n")
            .expect_err("an empty poetry lock must not look complete");
        assert!(error.contains("no packages"), "got: {error}");
    }

    #[test]
    fn poetry_kind_maps_to_the_pypi_ecosystem() {
        assert_eq!(super::lockfile_kind("poetry.lock"), "poetry");
        assert_eq!(super::ecosystem_for_kind("poetry"), "PyPI");
    }

    // ------------------------------------------- end-to-end through the CLI path

    #[test]
    fn new_lockfiles_parse_through_the_shared_entry_point_with_kinds() {
        let directory = tempfile::tempdir().expect("tempdir");
        let gradle = directory.path().join("gradle.lockfile");
        std::fs::write(
            &gradle,
            "org.apache.commons:commons-text:1.9=runtimeClasspath\n",
        )
        .expect("gradle fixture");
        let deps = parse_lockfile(&gradle, "gradle").expect("gradle parses");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Maven");
        assert_eq!(deps[0].name, "org.apache.commons:commons-text");
        assert_eq!(deps[0].version, "1.9");

        let nuget = directory.path().join("packages.lock.json");
        std::fs::write(
            &nuget,
            r#"{"version":1,"dependencies":{"net6.0":{"NLog":{"type":"Direct","resolved":"5.2.8"}}}}"#,
        )
        .expect("nuget fixture");
        let deps = parse_lockfile(&nuget, "nuget").expect("nuget parses");
        assert_eq!(deps[0].ecosystem, "NuGet");
        assert_eq!(deps[0].name, "NLog");

        let poetry = directory.path().join("poetry.lock");
        std::fs::write(
            &poetry,
            "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n",
        )
        .expect("poetry fixture");
        let deps = parse_lockfile(&poetry, "poetry").expect("poetry parses");
        assert_eq!(deps[0].ecosystem, "PyPI");
        assert_eq!(deps[0].name, "flask");
    }

    #[test]
    fn the_new_lockfile_names_are_discovered() {
        for name in ["gradle.lockfile", "packages.lock.json", "poetry.lock"] {
            assert!(
                crate::fs_utils::is_lockfile_name(name),
                "{name} must be discovered"
            );
        }
    }

    fn parse(name: &str, content: &str) -> Vec<(String, String)> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        std::fs::write(&path, content).unwrap();
        let deps = parse_lockfile(&path, super::lockfile_kind(name)).unwrap();
        deps.into_iter().map(|d| (d.name, d.version)).collect()
    }

    #[test]
    fn ruby_inventory_ignores_nested_constraints_and_normalizes_platform_versions() {
        assert_eq!(parse("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n    rack-protection (3.0.6)\n      rack (~> 2.2, >= 2.2.4)\n    nokogiri (1.16.0-x86_64-linux)\n\nPLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  rack-protection\n"),
            [("rack".into(), "2.2.8".into()), ("rack-protection".into(), "3.0.6".into()), ("nokogiri".into(), "1.16.0".into())]);
    }

    #[test]
    fn ruby_inventory_rejects_malformed_specification_rows() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("Gemfile.lock");
        for row in ["    broken", "    broken (>= 1.0)", "    broken ()"] {
            std::fs::write(&path, format!("GEM\n  specs:\n    rack (2.2.8)\n{row}\n")).unwrap();
            assert!(parse_lockfile(&path, "bundler").is_err(), "{row}");
        }
    }

    #[test]
    fn go_inventory_applies_replacements_without_promoting_checksum_history() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("go.mod"), "module example.com/app\nrequire example.com/original v1.0.0\nreplace example.com/original => example.com/fork v1.2.0\n").unwrap();
        std::fs::write(
            root.path().join("go.sum"),
            "example.com/original v0.1.0 h1:old\nexample.com/fork v1.2.0 h1:new\n",
        )
        .unwrap();
        let deps = parse_lockfile(&root.path().join("go.mod"), "gomod").unwrap();
        assert_eq!(
            deps.iter()
                .map(|d| (d.name.as_str(), d.version.as_str()))
                .collect::<Vec<_>>(),
            [("example.com/fork", "1.2.0")]
        );
        assert!(parse_lockfile(&root.path().join("go.sum"), "go")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn go_inventory_rejects_standalone_checksums_and_malformed_directives() {
        let root = tempfile::tempdir().unwrap();
        let sum = root.path().join("go.sum");
        std::fs::write(&sum, "example.com/old v0.1.0 h1:old\n").unwrap();
        assert!(parse_lockfile(&sum, "go").is_err());
        let path = root.path().join("go.mod");
        for body in [
            "require broken",
            "require example.com/a latest",
            "require (\nexample.com/a v1.0.0",
            "replace example.com/a =>",
            "require example.com/a v1.0.0\nexclude example.com/a v1.0.0",
        ] {
            std::fs::write(&path, format!("module example.com/app\n{body}\n")).unwrap();
            assert!(parse_lockfile(&path, "gomod").is_err(), "{body}");
        }
    }

    #[test]
    fn go_replacements_are_version_scoped_and_local_sources_are_unqueryable() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("go.mod");
        std::fs::write(
            &path,
            r#"module example.com/app
require (
 example.com/a v1.0.0
 example.com/b v2.0.0+incompatible
 example.com/c v0.0.0-20260101000000-abcdefabcdef
)
replace (
 example.com/a v0.9.0 => example.com/unused v8.0.0
 example.com/a => example.com/fallback v1.1.0
 example.com/a v1.0.0 => example.com/exact v1.2.0
 example.com/b => `../local//with spaces`
)
"#,
        )
        .unwrap();
        let deps = parse_lockfile(&path, "gomod").unwrap();
        assert_eq!(deps[0].name, "example.com/exact");
        assert_eq!(deps[0].version, "1.2.0");
        assert!(deps[1].occurrence.local_workspace);
        assert!(deps[1].version.is_empty());
        assert!(!crate::deps::osv::is_queryable_dependency(&deps[1]));
        assert_eq!(deps[2].version, "0.0.0-20260101000000-abcdefabcdef");
        assert!(deps[1]
            .occurrence
            .warnings
            .iter()
            .any(|s| s.contains("../local//with spaces")));
    }

    #[test]
    fn go_inventory_accepts_local_dot_paths_empty_blocks_and_go_string_escapes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("go.mod");
        for target in [".", "..", r#""../\x61""#, r#""../\141""#, r#""../\u0061""#] {
            std::fs::write(&path, format!("module example.com/app\ngo 1.22\nrequire example.com/a v1.0.0\nreplace example.com/a => {target}\n")).unwrap();
            let deps = parse_lockfile(&path, "gomod").unwrap();
            assert!(deps[0].version.is_empty(), "{target}");
            assert!(deps[0].occurrence.local_workspace, "{target}");
        }
        assert!(parse(
            "go.mod",
            "module example.com/app\nrequire ()\nreplace ()\nexclude ()\n"
        )
        .is_empty());
    }

    #[test]
    fn go_inventory_rejects_invalid_prereleases_and_language_versions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("go.mod");
        for body in [
            "require example.com/a v1.2.3-..",
            "require example.com/a v1.2.3-01",
            "require example.com/a v1.2.3-a..b",
            "go garbage",
            "go 1.22 trailing",
        ] {
            std::fs::write(&path, format!("module example.com/app\n{body}\n")).unwrap();
            assert!(parse_lockfile(&path, "gomod").is_err(), "{body}");
        }
    }

    #[test]
    fn go_inventory_handles_metadata_and_escaped_utf8_paths_without_guessing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("go.mod");
        std::fs::write(
            &path,
            r#"module example.com/app
go 1.26rc1
toolchain default
godebug panicnil=1
tool example.com/tool/cmd
ignore ./generated
retract [v0.1.0, v0.2.0]
require example.com/a v1.0.0-rc.1
replace example.com/a=>"../\xC3\xA9\U00000061"
"#,
        )
        .unwrap();
        let deps = parse_lockfile(&path, "gomod").unwrap();
        assert!(deps[0]
            .occurrence
            .warnings
            .iter()
            .any(|s| s.contains("../éa")));
        for target in [
            r#""../\q""#,
            r#""../\777""#,
            r#""../\uD800""#,
            r#""../\xF""#,
        ] {
            std::fs::write(&path, format!("module example.com/app\nrequire example.com/a v1.0.0\nreplace example.com/a=>{target}\n")).unwrap();
            assert!(parse_lockfile(&path, "gomod").is_err(), "{target}");
        }
    }

    #[test]
    fn ruby_source_and_platform_evidence_survive_without_registry_claims() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("Gemfile.lock");
        std::fs::write(&path, "GIT\n  remote: https://example.com/project.git\n  revision: abcdef\n  specs:\n    private-gem (1.2.0)\nPATH\n  remote: ../local\n  specs:\n    local-gem (2.0.0)\nGEM\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n").unwrap();
        let deps = parse_lockfile(&path, "bundler").unwrap();
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].occurrence.source.as_deref(), Some("git"));
        assert_eq!(deps[1].occurrence.source.as_deref(), Some("local"));
        assert_eq!(deps[2].occurrence.platform.as_deref(), Some("x86_64-linux"));
        assert_eq!(crate::deps::osv::queryable_dependencies(&deps).count(), 1);
        assert!(deps[..2].iter().all(|d| !d.occurrence.warnings.is_empty()));
    }

    #[test]
    fn go_mod_yields_requires_from_lines_and_blocks() {
        let deps = parse(
            "go.mod",
            "module example.com/m\n\ngo 1.21\n\nrequire github.com/spf13/cobra v1.8.0\n\nrequire (\n\tgopkg.in/yaml.v3 v3.0.1 // indirect\n\tgithub.com/pkg/errors v0.9.1\n)\n\nreplace github.com/x/y => ../y\nexclude github.com/bad/dep v1.0.0\n",
        );
        assert_eq!(
            deps,
            vec![
                ("github.com/spf13/cobra".to_string(), "1.8.0".to_string()),
                ("gopkg.in/yaml.v3".to_string(), "3.0.1".to_string()),
                ("github.com/pkg/errors".to_string(), "0.9.1".to_string()),
            ]
        );
    }

    #[test]
    fn go_mod_without_requires_is_a_valid_empty_inventory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("go.mod");
        std::fs::write(&path, "module example.com/m\n").unwrap();
        assert!(parse_lockfile(&path, super::lockfile_kind("go.mod"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn bun_lock_uses_resolved_tuple_identity_for_aliases_and_nested_packages() {
        let deps = parse(
            "bun.lock",
            r#"{"lockfileVersion":1,"packages":{
                "alias": ["@scope/pkg@2.0.0", "", {}, "sha512-test"],
                "left-pad": ["left-pad@1.3.0", "", {}, "sha512-test"],
                "parent/left-pad": ["left-pad@1.1.0", "", {}, "sha512-test"],
                "local": ["local@workspace:packages/local"],
                "file-pkg": ["file-pkg@file:../pkg", {}],
                "git-pkg": ["git-pkg@github:owner/repo#abc", {}, "owner-repo-abc"]
            }}"#,
        );
        assert_eq!(
            deps,
            vec![
                ("@scope/pkg".to_string(), "2.0.0".to_string()),
                ("left-pad".to_string(), "1.3.0".to_string()),
                ("left-pad".to_string(), "1.1.0".to_string()),
            ]
        );
    }

    #[test]
    fn bun_lock_accepts_jsonc_without_rewriting_strings() {
        let deps = parse(
            "bun.lock",
            r#"{
            // Generated by Bun
            "lockfileVersion": 1,
            "packages": {
                "example": ["example@1.2.3", "https://registry.npmjs.org/example", {
                    "note": "escaped quote: \" // /* ,} ,] λ",
                }, "sha512-test", /* comment after comma */],
            },
        }"#,
        );
        assert_eq!(deps, vec![("example".into(), "1.2.3".into())]);
    }

    #[test]
    fn bun_lock_empty_and_local_only_inventories_are_valid() {
        for content in [
            r#"{"lockfileVersion":1,"packages":{}}"#,
            r#"{"lockfileVersion":1,"packages":{"local":["local@workspace:pkg"]}}"#,
        ] {
            assert!(parse("bun.lock", content).is_empty());
        }
    }

    #[test]
    fn bun_lock_rejects_malformed_entries_instead_of_partial_inventory() {
        for entry in ["{}", "[]", "[5]", r#"["no-version"]"#, r#"["pkg@"]"#] {
            let content = format!(
                r#"{{"packages":{{"valid":["valid@1.0.0","",{{}},"hash"],"bad@2.0.0":{entry}}}}}"#
            );
            assert!(
                super::parse_bun_lock(&content).is_err(),
                "accepted {content}"
            );
        }
        assert!(super::parse_bun_lock("{ /* unterminated").is_err());
        for content in [r#"{"packages":{,}}"#, r#"{"packages":{},,"workspaces":{}}"#] {
            assert!(
                super::parse_bun_lock(content).is_err(),
                "accepted {content}"
            );
        }
    }

    #[test]
    fn mix_lock_reads_hex_packages_and_skips_paths() {
        let deps = parse(
            "mix.lock",
            "%{\n  \"phoenix\": {:hex, :phoenix, \"1.7.10\", \"abcdef0123\", [:mix], [{:castore, \"~> 1.0\", [hex: :castore]}], \"hexpm\", \"hash\"},\n  \"my_lib\": {:path, \"libs/my_lib\"},\n}\n",
        );
        assert_eq!(deps, vec![("phoenix".to_string(), "1.7.10".to_string())]);
    }

    #[test]
    fn pubspec_lock_keeps_hosted_packages_only() {
        let deps = parse(
            "pubspec.lock",
            "packages:\n  http:\n    dependency: transitive\n    description:\n      name: http\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.1.2\"\n  local_widget:\n    dependency: \"direct main\"\n    source: path\n  flutter:\n    dependency: \"direct main\"\n    source: sdk\n",
        );
        assert_eq!(deps, vec![("http".to_string(), "1.1.2".to_string())]);
    }

    #[test]
    fn new_lockfiles_map_to_their_osv_ecosystems() {
        assert_eq!(super::ecosystem_for_kind("gomod"), "Go");
        assert_eq!(super::ecosystem_for_kind("bun"), "npm");
        assert_eq!(super::ecosystem_for_kind("mix"), "Hex");
        assert_eq!(super::ecosystem_for_kind("pubspec"), "Pub");
    }
}
