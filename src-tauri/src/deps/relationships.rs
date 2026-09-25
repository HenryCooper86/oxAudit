//! Bounded npm v2/v3 metadata only. Inventory and declarations share one parsed value.
use crate::models::{Dependency, DependencyOccurrence, DependencyPath, DependencyStep};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_VISITS: usize = 20_000;
const MAX_DEPTH: usize = 64;
const MAX_PATHS: usize = 32;
const MAX_WARNINGS: usize = 8;
const MAX_PATH_BYTES: usize = 4 * 1024 * 1024;

fn warning(warnings: &mut BTreeSet<String>, message: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.insert(message.chars().take(240).collect());
    }
}
fn local_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}
fn package_name(path: &str) -> &str {
    path.rsplit_once("node_modules/")
        .map_or(path, |(_, name)| name)
}
// npm omits a name only when package and folder names agree. A local
// directory is never itself a registry name: confirm its name through all
// installed links, retaining explicit metadata for aliases.
fn folder_name(path: &str) -> &str {
    let (parent, leaf) = path.rsplit_once('/').unwrap_or(("", path));
    match parent.rsplit('/').next() {
        Some(scope) if scope.starts_with('@') => &path[path.len() - scope.len() - leaf.len() - 1..],
        _ => leaf,
    }
}
fn installed_name(path: &str) -> Option<&str> {
    let (parent, name) = path.rsplit_once("node_modules/")?;
    if !parent.is_empty() && !parent.ends_with('/') {
        return None;
    }
    let valid_part = |part: &str| {
        !part.is_empty()
            && !matches!(part, "." | "..")
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b))
    };
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped.split_once('/')?;
        (valid_part(scope) && valid_part(package)).then_some(name)
    } else {
        valid_part(name).then_some(name)
    }
}
fn string<'a>(value: &'a Value, field: &str, subject: &str) -> Result<Option<&'a str>, String> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s)),
        Some(_) => Err(format!(
            "invalid package-lock.json: {subject} has an invalid {field}"
        )),
    }
}
fn workspace_declared(root: &Value, path: &str) -> bool {
    root.get("workspaces")
        .and_then(Value::as_array)
        .is_some_and(|patterns| {
            patterns.iter().any(|p| {
                p.as_str().is_some_and(|pattern| {
                    // Conservative common workspace syntax. Unsupported patterns are not evidence.
                    if let Some((prefix, suffix)) = pattern.split_once('*') {
                        !suffix.contains('*')
                            && path
                                .strip_prefix(prefix)
                                .and_then(|p| p.strip_suffix(suffix))
                                .is_some_and(|middle| !middle.is_empty() && !middle.contains('/'))
                    } else {
                        pattern == path
                    }
                })
            })
        })
}
fn link_target<'a>(packages: &'a Map<String, Value>, path: &'a str) -> Option<&'a str> {
    let mut current = path;
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_DEPTH {
        let value = packages.get(current)?;
        if value.get("link") != Some(&Value::Bool(true)) {
            return Some(current);
        }
        if !seen.insert(current) {
            return None;
        }
        current = value.get("resolved")?.as_str()?;
        if !local_path(current) {
            return None;
        }
    }
    None
}
fn resolve(packages: &Map<String, Value>, from: &str, name: &str) -> Option<String> {
    if name.is_empty() || name.starts_with('.') || name.contains('\\') || package_name(name) != name
    {
        return None;
    }
    let parts = name.split('/').collect::<Vec<_>>();
    if (name.starts_with('@') && parts.len() != 2) || (!name.starts_with('@') && parts.len() != 1) {
        return None;
    }
    let mut directory = from;
    loop {
        if directory.rsplit('/').next() != Some("node_modules") {
            let key = if directory.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{directory}/node_modules/{name}")
            };
            if packages.contains_key(&key) {
                return link_target(packages, &key).map(str::to_owned);
            }
        }
        if directory.is_empty() {
            return None;
        }
        directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

pub fn parse_packages(root: &Value) -> Result<Vec<Dependency>, String> {
    let packages = root
        .get("packages")
        .and_then(Value::as_object)
        .ok_or("invalid package-lock.json: packages must be an object")?;
    if packages.len() > super::lockfiles::MAX_DEPENDENCIES {
        return Err("resource limit: npm package metadata exceeds node budget".into());
    }
    let empty = serde_json::json!({});
    let manifest = packages.get("").unwrap_or(&empty);
    if !manifest.is_object() {
        return Err("invalid package-lock.json: root package metadata must be an object".into());
    }
    string(manifest, "name", "root package")?;
    string(manifest, "version", "root package")?;
    let mut warnings = BTreeSet::new();
    let mut locals = BTreeSet::new();
    let mut linked_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, value) in packages {
        if !value.is_object() {
            return Err(format!(
                "invalid package-lock.json: package {path:?} must be an object"
            ));
        }
        if !path.is_empty() && !local_path(path) {
            return Err(format!(
                "invalid package-lock.json: unsafe package path {path:?}"
            ));
        }
        if let Some(link) = value.get("link") {
            if !link.is_boolean() {
                return Err(format!(
                    "invalid package-lock.json: package {path:?} has invalid link flag"
                ));
            }
        }
        if value.get("link") == Some(&Value::Bool(true)) {
            if let Some(target) = link_target(packages, path) {
                if let Some(name) = installed_name(path) {
                    linked_names
                        .entry(target.into())
                        .or_default()
                        .insert(name.into());
                }
                if workspace_declared(manifest, target) && !target.contains("node_modules/") {
                    locals.insert(target.to_owned());
                }
            } else {
                return Err(format!(
                    "invalid package-lock.json: unresolved, escaping or cyclic link: {path}"
                ));
            }
        }
    }
    let mut out = Vec::new();
    let mut indices = BTreeMap::new();
    for (path, value) in packages {
        if path.is_empty() || value.get("link") == Some(&Value::Bool(true)) {
            continue;
        }
        let version = string(value, "version", &format!("package {path:?}"))?;
        if version.is_none() && !locals.contains(path) {
            return Err(format!(
                "invalid package-lock.json: package {path:?} has no version"
            ));
        }
        let name = match string(value, "name", &format!("package {path:?}"))? {
            Some(name) => name,
            None => match installed_name(path) {
                Some(name) => name,
                None => {
                    let names=linked_names.get(path).ok_or_else(||format!(
                        "invalid package-lock.json: local package {path:?} has no validated package name"))?;
                    if names.len() != 1
                        || names.first().map(String::as_str) != Some(folder_name(path))
                    {
                        return Err(format!("invalid package-lock.json: local package {path:?} has ambiguous link identity"));
                    }
                    names.first().expect("validated single link identity")
                }
            },
        };
        indices.insert(path.clone(), out.len());
        // npm >=7 writes the resolved license beside the version; when it
        // is absent the license is simply unknown, never guessed.
        let license = value
            .get("license")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|license| !license.is_empty() && license.len() <= 64)
            .map(str::to_string);
        out.push(Dependency {
            ecosystem: "npm".into(),
            name: name.into(),
            version: version.unwrap_or("").into(),
            lockfile: String::new(),
            license,
            occurrence: DependencyOccurrence {
                local_workspace: locals.contains(path),
                install_path: Some(path.clone()),
                status: "unresolved".into(),
                paths: Vec::new(),
                warnings: Vec::new(),
            },
        });
    }
    if !matches!(
        root.get("lockfileVersion").and_then(Value::as_u64),
        Some(2 | 3)
    ) {
        for dependency in &mut out {
            dependency.occurrence.status = "unavailable".into();
            dependency.occurrence.warnings =
                vec!["Relationship support requires npm package-lock v2/v3 metadata".into()];
        }
        return Ok(out);
    }
    // Each direct manifest entry starts its own bounded walk. Keep distinct entrypoints,
    // workspace origins and installation paths, including cycles' already reached nodes.
    let mut visits = 0;
    let mut edges = 0;
    let mut path_bytes = 0;
    let roots = std::iter::once(String::new())
        .chain(locals)
        .collect::<Vec<_>>();
    'workspaces: for workspace in roots {
        let mut stack = vec![(
            workspace.clone(),
            Vec::<DependencyStep>::new(),
            BTreeSet::new(),
        )];
        while let Some((from, chain, mut seen)) = stack.pop() {
            visits += 1;
            if visits > MAX_VISITS {
                warning(
                    &mut warnings,
                    "Relationship traversal limit reached; additional paths are unknown".into(),
                );
                break;
            }
            if chain.len() >= MAX_DEPTH {
                warning(
                    &mut warnings,
                    "Relationship depth limit reached; additional paths are unknown".into(),
                );
                continue;
            }
            if !seen.insert(from.clone()) {
                warning(
                    &mut warnings,
                    format!("Dependency cycle at {from}; additional paths are unknown"),
                );
                continue;
            }
            let Some(value) = packages.get(&from) else {
                continue;
            };
            for (field, kind) in [
                ("dependencies", "runtime"),
                ("devDependencies", "dev"),
                ("optionalDependencies", "optional"),
                ("peerDependencies", "peer"),
            ] {
                // Registry package dev dependencies are not part of its installed dependency tree.
                if kind == "dev" && !chain.is_empty() {
                    continue;
                }
                let Some(declarations) = value.get(field) else {
                    continue;
                };
                let Some(declarations) = declarations.as_object() else {
                    warning(
                        &mut warnings,
                        format!("Invalid {field} declarations at {from}"),
                    );
                    continue;
                };
                for (name, spec) in declarations {
                    edges += 1;
                    if edges > MAX_VISITS {
                        warning(
                            &mut warnings,
                            "Relationship edge limit reached; additional paths are unknown".into(),
                        );
                        break 'workspaces;
                    }
                    if kind == "runtime"
                        && value
                            .get("optionalDependencies")
                            .and_then(Value::as_object)
                            .is_some_and(|d| d.contains_key(name))
                    {
                        continue;
                    }
                    let Some(spec) = spec.as_str() else {
                        warning(
                            &mut warnings,
                            format!("Unknown declaration {name} at {from}"),
                        );
                        continue;
                    };
                    if name.len() > 256 || spec.len() > 2048 {
                        warning(&mut warnings,"Relationship declaration size limit reached; additional paths are unknown".into());
                        continue;
                    }
                    let start = if kind == "peer" && !chain.is_empty() {
                        from.rsplit_once("/node_modules/").map_or("", |(p, _)| p)
                    } else {
                        &from
                    };
                    let Some(target) = resolve(packages, start, name) else {
                        warning(
                            &mut warnings,
                            format!("Unresolved {kind} dependency {name} at {from}"),
                        );
                        continue;
                    };
                    let Some(&index) = indices.get(&target) else {
                        continue;
                    };
                    let mut next = chain.clone();
                    next.push(DependencyStep {
                        name: name.clone(),
                        package_name: out[index].name.clone(),
                        install_path: target.clone(),
                        dependency_type: kind.into(),
                        declared: spec.into(),
                    });
                    path_bytes += next
                        .iter()
                        .map(|s| {
                            s.name.len()
                                + s.package_name.len()
                                + s.install_path.len()
                                + s.declared.len()
                                + 128
                        })
                        .sum::<usize>();
                    if path_bytes > MAX_PATH_BYTES {
                        warning(&mut warnings,"Relationship evidence size limit reached; additional paths are unknown".into());
                        break 'workspaces;
                    }
                    if out[index].occurrence.paths.len() < MAX_PATHS {
                        out[index].occurrence.paths.push(DependencyPath {
                            workspace: workspace.clone(),
                            entry_point: next[0].name.clone(),
                            chain: next.clone(),
                        });
                        out[index].occurrence.status = "available".into();
                        stack.push((target, next, seen.clone()));
                    } else {
                        warning(
                            &mut warnings,
                            "Relationship path limit reached; additional paths are unknown".into(),
                        );
                    }
                }
            }
        }
        if visits > MAX_VISITS {
            break;
        }
    }
    for dependency in &mut out {
        dependency.occurrence.warnings = if warnings.is_empty() {
            Vec::new()
        } else {
            vec![warnings
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
                .chars()
                .take(1024)
                .collect()]
        };
        if !warnings.is_empty() && dependency.occurrence.status == "available" {
            dependency.occurrence.status = "partial".into();
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unnamed_local_targets_use_consistent_scoped_link_identity_and_preserve_alias_names() {
        for version in [2, 3] {
            for declared_version in [Some("1.0.0"), None] {
                let target = declared_version.map_or_else(
                    || serde_json::json!({}),
                    |v| serde_json::json!({"version":v}),
                );
                let result=parse_packages(&serde_json::json!({"lockfileVersion":version,"packages":{
                    "":{"workspaces":["packages/@scope/*"],"dependencies":{"@scope/a":"*"}},
                    "node_modules/@scope/a":{"link":true,"resolved":"packages/@scope/a"},"packages/@scope/a":target
                }})).unwrap();
                assert_eq!(result[0].name, "@scope/a");
                assert_eq!(result[0].version, declared_version.unwrap_or(""));
                assert!(result[0].occurrence.local_workspace);
                assert_eq!(
                    result[0].occurrence.paths[0].chain[0].package_name,
                    "@scope/a"
                );
            }
        }
        let packages = serde_json::json!({"":{"workspaces":["packages/*"]},
            "node_modules/alias":{"link":true,"resolved":"packages/a"},
            "node_modules/other-alias":{"link":true,"resolved":"packages/a"},
            "packages/a":{"name":"@scope/actual","version":"1.0.0"}});
        let result =
            parse_packages(&serde_json::json!({"lockfileVersion":3,"packages":packages})).unwrap();
        assert_eq!(result[0].name, "@scope/actual");
        let mut ambiguous = packages;
        ambiguous["packages/a"]
            .as_object_mut()
            .unwrap()
            .remove("name");
        assert!(
            parse_packages(&serde_json::json!({"lockfileVersion":3,"packages":ambiguous})).is_err()
        );
        assert!(
            parse_packages(&serde_json::json!({"lockfileVersion":3,"packages":{
            "packages/a":{"version":"1.0.0"}}}))
            .is_err()
        );
    }

    #[test]
    fn unsupported_lockfile_schema_does_not_claim_known_relationships() {
        let dependencies = parse_packages(&serde_json::json!({"lockfileVersion":99,"packages":{
          "":{"dependencies":{"leaf":"1.0.0"}},"node_modules/leaf":{"version":"1.0.0"}}}))
        .unwrap();
        assert_eq!(dependencies[0].occurrence.status, "unavailable");
        assert!(dependencies[0].occurrence.paths.is_empty());
    }
    #[test]
    fn invalid_links_cannot_hide_missing_inventory() {
        for packages in [
            serde_json::json!({"node_modules/work":{"link":true,"resolved":"../escape"}}),
            serde_json::json!({"node_modules/work":{"link":true,"resolved":"packages/missing"}}),
            serde_json::json!({"node_modules/a":{"link":true,"resolved":"node_modules/b"},"node_modules/b":{"link":true,"resolved":"node_modules/a"}}),
        ] {
            assert!(
                parse_packages(&serde_json::json!({"lockfileVersion":3,"packages":packages}))
                    .is_err()
            );
        }
    }
    #[test]
    fn relationship_bounds_stop_broad_and_deep_metadata_without_inventing_paths() {
        let mut packages = serde_json::Map::new();
        let mut declarations = serde_json::Map::new();
        for i in 0..MAX_VISITS + 1 {
            declarations.insert(format!("item{i}"), Value::String("1.0.0".into()));
            packages.insert(
                format!("node_modules/item{i}"),
                serde_json::json!({"version":"1.0.0"}),
            );
        }
        packages.insert("".into(), serde_json::json!({"dependencies":declarations}));
        let dependencies =
            parse_packages(&serde_json::json!({"lockfileVersion":3,"packages":packages})).unwrap();
        let path_count: usize = dependencies.iter().map(|d| d.occurrence.paths.len()).sum();
        assert!(path_count <= MAX_VISITS);
        assert!(dependencies.iter().any(|d| d
            .occurrence
            .warnings
            .iter()
            .any(|w| w.contains("limit"))));
        let mut packages = serde_json::Map::new();
        packages.insert(
            "".into(),
            serde_json::json!({"dependencies":{"item0":"1.0.0"}}),
        );
        for i in 0..MAX_DEPTH + 2 {
            packages.insert(format!("node_modules/item{i}"),serde_json::json!({"version":"1.0.0","dependencies":{format!("item{}",i+1):"1.0.0"}}));
        }
        let dependencies =
            parse_packages(&serde_json::json!({"lockfileVersion":3,"packages":packages})).unwrap();
        assert!(dependencies.iter().all(|d| d
            .occurrence
            .paths
            .iter()
            .all(|p| p.chain.len() <= MAX_DEPTH)));
        assert!(dependencies.iter().any(|d| d
            .occurrence
            .warnings
            .iter()
            .any(|w| w.contains("depth"))));
    }

    #[test]
    fn package_lock_licenses_ride_along_when_declared() {
        let deps = parse_packages(&serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/marked": { "version": "12.0.0", "license": "MIT" },
                "node_modules/silent": { "version": "1.0.0" }
            }
        }))
        .unwrap();
        let marked = deps.iter().find(|d| d.name == "marked").unwrap();
        assert_eq!(marked.license.as_deref(), Some("MIT"));
        let silent = deps.iter().find(|d| d.name == "silent").unwrap();
        assert_eq!(silent.license, None, "absent stays unknown, never guessed");
    }
}
