use std::collections::BTreeMap;
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
        _ => "unknown",
    }
}

/// Map a lockfile kind to the OSV ecosystem name.
pub fn ecosystem_for_kind(kind: &str) -> &'static str {
    match kind {
        "npm" | "yarn" | "pnpm" => "npm",
        "cargo" => "crates.io",
        "go" => "Go",
        "pipenv" | "pip" => "PyPI",
        "bundler" => "RubyGems",
        "composer" => "Packagist",
        "maven" => "Maven",
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
    let deps = match name {
        "package-lock.json" => parse_package_lock(&content)?,
        "yarn.lock" => parse_yarn_lock(&content)?,
        "pnpm-lock.yaml" => parse_pnpm_lock(&content)?,
        "Cargo.lock" => parse_cargo_lock(&content)?,
        "go.sum" => parse_go_sum(&content)?,
        "Pipfile.lock" => parse_pipfile_lock(&content)?,
        "Gemfile.lock" => parse_gemfile_lock(&content)?,
        "composer.lock" => parse_composer_lock(&content)?,
        "pom.xml" => parse_pom_xml(&content)?,
        "requirements.txt" => parse_requirements(&content)?,
        _ => return Err("unsupported lockfile".into()),
    };

    Ok(deps
        .into_iter()
        .map(|(n, v)| Dependency {
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
                out.push((name.clone(), version.to_string()));
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

    fn flush(names: &[String], version: Option<&String>, out: &mut Vec<(String, String)>) {
        if let Some(v) = version {
            for n in names {
                if !n.is_empty() {
                    out.push((n.clone(), v.clone()));
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
            flush(&current_names, current_version.as_ref(), &mut out);
            current_names.clear();
            current_version = None;
            if trimmed == "__metadata:" {
                continue;
            }
            let header = trimmed.trim_end_matches(':');
            for part in header.split(',') {
                let part = part.trim().trim_matches(['"', '\'']);
                if part.is_empty() {
                    continue;
                }
                current_names.push(split_name_range(part).0);
            }
        } else if !current_names.is_empty() {
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim().trim_matches(['"', '\'']);
                let value = value.trim().trim_matches(['"', '\'']);
                if key == "version" {
                    current_version = Some(value.to_string());
                }
            }
        }
    }
    flush(&current_names, current_version.as_ref(), &mut out);

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

fn parse_pnpm_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|e| format!("invalid pnpm-lock.yaml: {e}"))?;
    let mut out = Vec::new();
    if let Some(packages) = root.get("packages").and_then(|p| p.as_mapping()) {
        for (key, _val) in packages {
            if let Some(k) = key.as_str() {
                // key format: /name@1.2.3 or /@scope/name@1.2.3
                let k = k.trim_start_matches('/');
                let (name, version) = split_name_range(k);
                if !name.is_empty() && !version.is_empty() {
                    out.push((name, version));
                }
            }
        }
    }
    if out.is_empty() {
        return Err("no packages found in pnpm-lock.yaml".into());
    }
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
                .unwrap_or("")
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !name.is_empty() && !version.is_empty() {
                out.push((name, version));
            }
        }
    }
    if out.is_empty() {
        return Err("no packages found in Cargo.lock".into());
    }
    Ok(out)
}

fn parse_go_sum(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let version = parts[1];
        // skip /go.mod pseudo entries
        if version.ends_with("/go.mod") {
            continue;
        }
        let version = version.trim_start_matches("v");
        out.push((parts[0].to_string(), version.to_string()));
    }
    if out.is_empty() {
        return Err("no packages found in go.sum".into());
    }
    Ok(out)
}

fn parse_pipfile_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|e| format!("invalid Pipfile.lock: {e}"))?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        if let Some(map) = root.get(section).and_then(|v| v.as_mapping()) {
            for (key, val) in map {
                let name = key.as_str().unwrap_or("").to_string();
                let version = val
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(strip_version_ops)
                    .unwrap_or_default();
                if !name.is_empty() && !version.is_empty() {
                    out.push((name, version));
                }
            }
        }
    }
    if out.is_empty() {
        return Err("no packages found in Pipfile.lock".into());
    }
    Ok(out)
}

fn parse_gemfile_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut in_gem_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // top-level section header
            in_gem_section =
                trimmed == "GEM" || trimmed.starts_with("GIT") || trimmed.starts_with("PATH");
            continue;
        }
        if !in_gem_section {
            continue;
        }
        // indented "    name (version)"
        if let Some(open) = trimmed.find('(') {
            if trimmed.ends_with(')') {
                let name = trimmed[..open].trim();
                let version = &trimmed[open + 1..trimmed.len() - 1];
                if !name.is_empty() && !version.is_empty() {
                    out.push((name.to_string(), version.to_string()));
                }
            }
        }
    }
    if out.is_empty() {
        return Err("no gems found in Gemfile.lock".into());
    }
    Ok(out)
}

fn parse_composer_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let root: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid composer.lock: {e}"))?;
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        if let Some(arr) = root.get(section).and_then(|v| v.as_array()) {
            for pkg in arr {
                let name = pkg
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim_start_matches('v').to_string())
                    .unwrap_or_default();
                if !name.is_empty() && !version.is_empty() {
                    out.push((name, version));
                }
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
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // strip environment markers: "pkg==1.0; python_version < '3.8'"
        let base = line.split(';').next().unwrap_or(line).trim();
        // strip extras: pkg[extra]==1.0
        let (name, version) = if let Some((n, v)) = base.split_once("==") {
            (n.trim(), Some(v.trim().to_string()))
        } else if let Some((n, v)) = base.split_once(">=") {
            (n.trim(), Some(v.trim().to_string()))
        } else if let Some((n, v)) = base.split_once("<=") {
            (n.trim(), Some(v.trim().to_string()))
        } else if let Some((n, v)) = base.split_once("~=") {
            (n.trim(), Some(v.trim().to_string()))
        } else {
            (base.trim(), None)
        };
        let name = name.trim_matches(['[', ']', ' ', '\'', '"']).to_string();
        if let Some(v) = version {
            let v = v.trim_matches([' ', '\'', '"', ',']);
            if !name.is_empty()
                && !v.is_empty()
                && v.chars().all(|c| {
                    c.is_ascii_digit()
                        || c.is_ascii_alphabetic()
                        || matches!(c, '.' | '-' | '_' | '!')
                })
            {
                out.push((name, v.to_string()));
            }
        }
    }
    if out.is_empty() {
        return Err(
            "no pinned requirements found (unpinned packages can't be checked against OSV)".into(),
        );
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
        extend_dependencies_bounded, parse_lockfile, parse_lockfile_with_limit, parse_package_lock,
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
    fn aggregate_dependency_overflow_is_rejected_before_extension() {
        let dependency = crate::models::Dependency {
            occurrence: Default::default(),
            ecosystem: "npm".into(),
            name: "package".into(),
            version: "1.0.0".into(),
            lockfile: "package-lock.json".into(),
        };
        let distinct = crate::models::Dependency {
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
}
