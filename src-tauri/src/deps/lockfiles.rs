use std::collections::BTreeMap;
use std::path::Path;

use crate::models::Dependency;

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
        "pipenv" => "PyPI",
        "bundler" => "RubyGems",
        "composer" => "Packagist",
        "maven" => "Maven",
        _ => "unknown",
    }
}

/// Parse a lockfile into dependencies. Returns Err with a human-readable
/// reason when the file cannot be understood.
pub fn parse_lockfile(path: &Path, kind: &str) -> Result<Vec<Dependency>, String> {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let ecosystem = ecosystem_for_kind(kind).to_string();
    let lockfile = path.to_string_lossy().replace('\\', "/");
    let content = std::fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;

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
            ecosystem: ecosystem.clone(),
            name: n,
            version: v,
            lockfile: lockfile.clone(),
        })
        .collect())
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
    let mut out = Vec::new();

    // v2/v3: "packages" object keyed by node_modules/... path
    if let Some(packages) = root.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            if key.is_empty() {
                continue;
            }
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    key.trim_start_matches("node_modules/")
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join("/")
                });
            if !name.is_empty() && !version.is_empty() {
                out.push((name, version));
            }
        }
    }

    // v1: "dependencies" object (recursive)
    fn walk_deps(node: &serde_json::Value, out: &mut Vec<(String, String)>) {
        if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
            for (name, val) in deps {
                if let Some(v) = val.get("version").and_then(|v| v.as_str()) {
                    out.push((name.clone(), v.to_string()));
                }
                walk_deps(val, out);
            }
        }
    }
    walk_deps(&root, &mut out);

    if out.is_empty() {
        return Err("no packages found in package-lock.json".into());
    }
    Ok(out)
}

fn parse_yarn_lock(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;

    fn flush(
        names: &[String],
        version: Option<&String>,
        out: &mut Vec<(String, String)>,
    ) {
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
            in_gem_section = trimmed == "GEM" || trimmed.starts_with("GIT") || trimmed.starts_with("PATH");
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
    use quick_xml::Reader;

    let mut reader = Reader::from_str(content);
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<(String, String, String)> = None; // groupId, artifactId, version
    let mut in_dependency = false;
    let mut in_dependencies = false;
    let mut tag_stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                tag_stack.push(name.clone());
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
                    let text = t.unescape().unwrap_or_default().into_owned().trim().to_string();
                    if text.is_empty() {
                        buf.clear();
                        continue;
                    }
                    let last = tag_stack.last().cloned().unwrap_or_default();
                    match last.as_str() {
                        "groupId" => {
                            if let Some(c) = &mut current {
                                c.0 = text;
                            } else {
                                current = Some((text, String::new(), String::new()));
                            }
                        }
                        "artifactId" => {
                            if let Some(c) = &mut current {
                                c.1 = text;
                            } else {
                                current = Some((String::new(), text, String::new()));
                            }
                        }
                        "version" => {
                            if let Some(c) = &mut current {
                                c.2 = text;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
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
                tag_stack.pop();
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("invalid pom.xml: {e}")),
            _ => {}
        }
        buf.clear();
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
            if !name.is_empty() && !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c.is_ascii_alphabetic() || matches!(c, '.' | '-' | '_' | '!')) {
                out.push((name, v.to_string()));
            }
        }
    }
    if out.is_empty() {
        return Err("no pinned requirements found (unpinned packages can't be checked against OSV)".into());
    }
    Ok(out)
}

/// Deduplicate dependencies by (ecosystem, name, version), keeping first occurrence.
pub fn dedupe_dependencies(deps: Vec<Dependency>) -> Vec<Dependency> {
    let mut seen: BTreeMap<(String, String, String), Dependency> = BTreeMap::new();
    for d in deps {
        let key = (d.ecosystem.clone(), d.name.clone(), d.version.clone());
        seen.entry(key).or_insert(d);
    }
    seen.into_values().collect()
}
