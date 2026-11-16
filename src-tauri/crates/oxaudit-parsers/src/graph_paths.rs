//! Format-neutral relationship evidence for lockfiles that record both the
//! dependency edges and the project's own direct declarations.
//!
//! A format builder turns its lockfile into a [`Graph`] (nodes, typed edges,
//! roots) and [`compute`] derives bounded, deterministic chains from each
//! root to each node. The semantics mirror the npm walk in `relationships.rs`:
//!
//! * `available`: at least one chain from a declared root was found and
//!   nothing is known to be missing.
//! * `partial`: chains exist or the node is not reachable, but a cycle,
//!   unresolved edge, bound or declared-root gap means more paths may exist.
//! * `unavailable`: the lockfile carries no declared roots to walk from.
//!
//! A chain is ordered from the direct declaration (`chain[0]`, whose `name`
//! is the `entry_point`) to the package itself. Absence of a chain is never
//! proof: a node no root reaches gets no fabricated chain, only a warning.
use crate::lockfiles::{nonregistry_protocol, parse_yaml_lockfile, pnpm_coordinate};
use crate::models::{DependencyPath, DependencyStep};
use crate::relationships::{
    warning, MAX_DEPTH, MAX_PATHS, MAX_PATH_BYTES, MAX_VISITS, MAX_WARNINGS,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) struct GraphNode {
    pub name: String,
    pub version: String,
    /// Origin identity when the lockfile distinguishes it (used to tell
    /// same-named, same-versioned packages from different sources apart).
    pub source: Option<String>,
    /// Project code (workspace member, editable package). It needs no chain.
    pub project: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GraphEdge {
    /// Name as written by the declaring side (an alias may differ from the node name).
    pub name: String,
    pub to: usize,
    pub dependency_type: String,
    pub declared: String,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GraphRoot {
    /// `""` for the single root manifest, otherwise the member, importer or target name.
    pub workspace: String,
    /// The project node that owns the declaration, so a chain returning to it is a cycle.
    pub owner: Option<usize>,
    pub edge: GraphEdge,
}

#[derive(Default)]
pub(crate) struct Graph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<Vec<GraphEdge>>,
    pub roots: Vec<GraphRoot>,
    pub warnings: BTreeSet<String>,
}

impl Graph {
    pub fn add_node(&mut self, node: GraphNode) -> usize {
        self.nodes.push(node);
        self.edges.push(Vec::new());
        self.nodes.len() - 1
    }
    pub fn add_edge(&mut self, from: usize, edge: GraphEdge) {
        self.edges[from].push(edge);
    }
    pub fn add_root(&mut self, workspace: String, owner: Option<usize>, edge: GraphEdge) {
        self.roots.push(GraphRoot {
            workspace,
            owner,
            edge,
        });
    }
    pub fn warn(&mut self, message: String) {
        warning(&mut self.warnings, message);
    }
}

pub(crate) struct NodeEvidence {
    pub status: &'static str,
    pub paths: Vec<DependencyPath>,
    pub warnings: Vec<String>,
}

struct State {
    node: usize,
    parent: Option<usize>,
    root: usize,
    depth: usize,
    step: DependencyStep,
}

fn step_bytes(step: &DependencyStep) -> usize {
    step.name.len() + step.package_name.len() + step.install_path.len() + step.declared.len() + 128
}

fn coordinate(node: &GraphNode) -> String {
    if node.version.is_empty() {
        node.name.clone()
    } else {
        format!("{}@{}", node.name, node.version)
    }
}

/// Derive bounded chains for every node. Output is indexed like `graph.nodes`.
pub(crate) fn compute(mut graph: Graph) -> Vec<NodeEvidence> {
    for edges in &mut graph.edges {
        edges.sort();
        edges.dedup();
    }
    graph.roots.sort();
    graph.roots.dedup();
    let node_count = graph.nodes.len();
    let mut warnings = std::mem::take(&mut graph.warnings);
    let mut paths: Vec<Vec<DependencyPath>> = (0..node_count).map(|_| Vec::new()).collect();
    if graph.roots.is_empty() {
        warning(
            &mut warnings,
            "The lockfile records no direct declarations to start from; relationship evidence is unavailable".into(),
        );
        return finish(&graph, paths, &warnings, false);
    }

    let mut arena: Vec<State> = Vec::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    let mut visits = 0usize;
    let mut edge_budget = 0usize;
    let mut path_bytes = 0usize;
    let mut stop = false;

    // Breadth-first so the MAX_PATHS cap keeps the shortest chains. Roots are
    // processed in sorted order, then each level in sorted edge order, so the
    // result does not depend on lockfile key order.
    macro_rules! visit {
        ($parent:expr, $root:expr, $edge:expr) => {{
            let edge: &GraphEdge = $edge;
            edge_budget += 1;
            if edge_budget > MAX_VISITS {
                warning(
                    &mut warnings,
                    "Relationship edge limit reached; additional paths are unknown".into(),
                );
                stop = true;
            } else {
                let step = DependencyStep {
                    name: edge.name.clone(),
                    package_name: graph.nodes[edge.to].name.clone(),
                    install_path: coordinate(&graph.nodes[edge.to]),
                    dependency_type: edge.dependency_type.clone(),
                    declared: edge.declared.clone(),
                };
                let parent: Option<usize> = $parent;
                let mut chain_steps = vec![step.clone()];
                let mut cursor = parent;
                while let Some(index) = cursor {
                    chain_steps.push(arena[index].step.clone());
                    cursor = arena[index].parent;
                }
                chain_steps.reverse();
                path_bytes += chain_steps.iter().map(step_bytes).sum::<usize>();
                if path_bytes > MAX_PATH_BYTES {
                    warning(
                        &mut warnings,
                        "Relationship evidence size limit reached; additional paths are unknown"
                            .into(),
                    );
                    stop = true;
                } else if paths[edge.to].len() < MAX_PATHS {
                    paths[edge.to].push(DependencyPath {
                        workspace: graph.roots[$root].workspace.clone(),
                        entry_point: chain_steps[0].name.clone(),
                        chain: chain_steps,
                    });
                    arena.push(State {
                        node: edge.to,
                        parent,
                        root: $root,
                        depth: parent.map_or(0, |p| arena[p].depth) + 1,
                        step,
                    });
                    queue.push_back(arena.len() - 1);
                } else {
                    warning(
                        &mut warnings,
                        "Relationship path limit reached; additional paths are unknown".into(),
                    );
                }
            }
        }};
    }

    for root in 0..graph.roots.len() {
        if stop {
            break;
        }
        let edge = graph.roots[root].edge.clone();
        visit!(None, root, &edge);
    }
    while let Some(index) = queue.pop_front() {
        if stop {
            break;
        }
        visits += 1;
        if visits > MAX_VISITS {
            warning(
                &mut warnings,
                "Relationship traversal limit reached; additional paths are unknown".into(),
            );
            break;
        }
        let (node, root, depth) = (arena[index].node, arena[index].root, arena[index].depth);
        if depth >= MAX_DEPTH {
            warning(
                &mut warnings,
                "Relationship depth limit reached; additional paths are unknown".into(),
            );
            continue;
        }
        let mut cycle = graph.roots[root].owner == Some(node);
        let mut cursor = arena[index].parent;
        while let Some(ancestor) = cursor {
            cycle |= arena[ancestor].node == node;
            cursor = arena[ancestor].parent;
        }
        if cycle {
            warning(
                &mut warnings,
                format!(
                    "Dependency cycle at {}; additional paths are unknown",
                    coordinate(&graph.nodes[node])
                ),
            );
            continue;
        }
        let outgoing = graph.edges[node].clone();
        for edge in &outgoing {
            if stop {
                break;
            }
            visit!(Some(index), root, edge);
        }
    }

    for list in &mut paths {
        list.sort_by_cached_key(|path| {
            (
                path.chain.len(),
                path.workspace.clone(),
                path.chain
                    .iter()
                    .map(|s| format!("{}\u{0}{}\u{0}{}", s.name, s.install_path, s.dependency_type))
                    .collect::<Vec<_>>(),
            )
        });
    }
    finish(&graph, paths, &warnings, true)
}

fn finish(
    graph: &Graph,
    paths: Vec<Vec<DependencyPath>>,
    warnings: &BTreeSet<String>,
    has_roots: bool,
) -> Vec<NodeEvidence> {
    paths
        .into_iter()
        .enumerate()
        .map(|(index, paths)| {
            let node = &graph.nodes[index];
            let mut notes = Vec::new();
            let status = if !has_roots {
                "unavailable"
            } else if !paths.is_empty() {
                if warnings.is_empty() {
                    "available"
                } else {
                    "partial"
                }
            } else if node.project {
                // The project's own code is the starting point, not a dependency.
                "available"
            } else {
                notes.push(format!(
                    "{} is not reachable from a declared root in this lockfile; its relationship evidence is unknown",
                    coordinate(node)
                ));
                "partial"
            };
            if !(node.project && paths.is_empty() && has_roots) {
                notes.extend(warnings.iter().cloned());
            }
            let joined: String = notes.join("; ").chars().take(1024).collect();
            NodeEvidence {
                status,
                paths,
                warnings: if joined.is_empty() {
                    Vec::new()
                } else {
                    vec![joined]
                },
            }
        })
        .collect()
}

fn edge(name: &str, to: usize, dependency_type: &str, declared: &str) -> GraphEdge {
    GraphEdge {
        name: name.into(),
        to,
        dependency_type: dependency_type.into(),
        declared: declared.chars().take(2048).collect(),
    }
}

fn names_index(graph: &Graph) -> BTreeMap<String, Vec<usize>> {
    let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, node) in graph.nodes.iter().enumerate() {
        by_name.entry(node.name.clone()).or_default().push(index);
    }
    by_name
}

/// Cargo.lock: `[[package]]` entries with `dependencies` arrays. Packages with
/// no `source` are the project's own crates; their dependencies are the roots
/// and `workspace` is the crate name. The lock does not separate normal, build
/// and dev dependencies, so every type is `unknown`.
pub(crate) fn cargo_graph(content: &str) -> Result<Graph, String> {
    let root: toml::Value =
        toml::from_str(content).map_err(|e| format!("invalid Cargo.lock: {e}"))?;
    let mut graph = Graph::default();
    let packages = root
        .get("package")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut raw: Vec<Vec<String>> = Vec::new();
    for pkg in packages {
        let text = |key: &str| pkg.get(key).and_then(toml::Value::as_str);
        graph.add_node(GraphNode {
            name: text("name").unwrap_or("").into(),
            version: text("version").unwrap_or("").into(),
            source: text("source").map(str::to_owned),
            project: pkg.get("source").is_none(),
        });
        raw.push(
            pkg.get("dependencies")
                .and_then(toml::Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        );
    }
    let by_name = names_index(&graph);
    for (from, entries) in raw.iter().enumerate() {
        for entry in entries {
            let mut parts = entry.splitn(3, ' ');
            let name = parts.next().unwrap_or("");
            let version = parts.next();
            let source = parts
                .next()
                .map(|s| s.trim_start_matches('(').trim_end_matches(')'));
            let candidates: Vec<usize> = by_name
                .get(name)
                .map(|list| {
                    list.iter()
                        .copied()
                        .filter(|&i| {
                            version.is_none_or(|v| graph.nodes[i].version == v)
                                && source.is_none_or(|s| graph.nodes[i].source.as_deref() == Some(s))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let from_name = graph.nodes[from].name.clone();
            let [to] = candidates[..] else {
                let why = if candidates.is_empty() {
                    "Unresolved"
                } else {
                    "Ambiguous"
                };
                graph.warn(format!("{why} dependency {entry} at {from_name}"));
                continue;
            };
            let e = edge(name, to, "unknown", "");
            if graph.nodes[from].project {
                graph.add_root(from_name, Some(from), e.clone());
            }
            graph.add_edge(from, e);
        }
    }
    Ok(graph)
}

fn yaml_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// pnpm: `importers` are the roots (each importer is a workspace), `snapshots`
/// (v9) and `packages` (older) carry the edges. Peer contexts are stripped as
/// in the inventory, so variants of one release are one node.
pub(crate) fn pnpm_graph(content: &str) -> Result<Graph, String> {
    let root: Value = parse_yaml_lockfile(content, "pnpm-lock.yaml")?;
    let root = root
        .as_object()
        .ok_or("invalid pnpm-lock.yaml: document must be a mapping")?;
    let mut graph = Graph::default();
    let mut by_coordinate: BTreeMap<(String, String), usize> = BTreeMap::new();
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        for key in packages.keys() {
            let Some((name, version)) = pnpm_coordinate(key) else {
                continue;
            };
            // The inventory skips git, link and tarball coordinates.
            if version.contains(':') || version.contains('/') {
                continue;
            }
            by_coordinate
                .entry((name.into(), version.into()))
                .or_insert_with(|| {
                    graph.add_node(GraphNode {
                        name: name.into(),
                        version: version.into(),
                        source: None,
                        project: false,
                    })
                });
        }
    }
    enum Target {
        Node(usize),
        Local,
        Unresolved,
    }
    let resolve = |name: &str, value: &Value| -> Target {
        let Some(text) = yaml_scalar(value) else {
            return Target::Unresolved;
        };
        if nonregistry_protocol(&text) {
            return Target::Local;
        }
        let base = text.split('(').next().unwrap_or("");
        let plain = base.split('_').next().unwrap_or("");
        let found = by_coordinate
            .get(&(name.to_owned(), plain.to_owned()))
            .copied()
            .or_else(|| {
                pnpm_coordinate(base)
                    .and_then(|(n, v)| by_coordinate.get(&(n.to_owned(), v.to_owned())).copied())
            });
        found.map_or(Target::Unresolved, Target::Node)
    };
    for section in ["packages", "snapshots"] {
        let Some(entries) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (key, entry) in entries {
            let Some((name, version)) = pnpm_coordinate(key) else {
                continue;
            };
            let Some(&from) = by_coordinate.get(&(name.to_owned(), version.to_owned())) else {
                continue;
            };
            let optional = entry.get("optionalDependencies").and_then(Value::as_object);
            for (field, kind) in [
                ("dependencies", "runtime"),
                ("optionalDependencies", "optional"),
            ] {
                let Some(declared) = entry.get(field).and_then(Value::as_object) else {
                    continue;
                };
                for (dep, value) in declared {
                    if kind == "runtime" && optional.is_some_and(|o| o.contains_key(dep)) {
                        continue;
                    }
                    match resolve(dep, value) {
                        Target::Node(to) => {
                            let spec = yaml_scalar(value).unwrap_or_default();
                            graph.add_edge(from, edge(dep, to, kind, &spec));
                        }
                        Target::Local => {}
                        Target::Unresolved => graph.warn(format!(
                            "Unresolved {kind} dependency {dep} at {name}@{version}"
                        )),
                    }
                }
            }
        }
    }
    // Single-project lockfiles (v5 and older) keep the importer fields at the top level.
    let top = Value::Object(root.clone());
    let mut importers: Vec<(String, &Value)> = Vec::new();
    match root.get("importers").and_then(Value::as_object) {
        Some(map) => importers.extend(map.iter().map(|(k, v)| (k.clone(), v))),
        None => importers.push((".".into(), &top)),
    }
    for (path, importer) in importers {
        let workspace = if path == "." { String::new() } else { path };
        let specifiers = importer
            .get("specifiers")
            .or_else(|| root.get("specifiers"))
            .and_then(Value::as_object);
        for (field, kind) in [
            ("dependencies", "runtime"),
            ("devDependencies", "dev"),
            ("optionalDependencies", "optional"),
        ] {
            let Some(declared) = importer.get(field).and_then(Value::as_object) else {
                continue;
            };
            for (dep, entry) in declared {
                let (version, spec) = match entry {
                    Value::Object(object) => (
                        object.get("version"),
                        object.get("specifier").and_then(yaml_scalar),
                    ),
                    other => (
                        Some(other),
                        specifiers.and_then(|s| s.get(dep)).and_then(yaml_scalar),
                    ),
                };
                let Some(version) = version else {
                    graph.warn(format!("Unknown declaration {dep} at importer {workspace:?}"));
                    continue;
                };
                match resolve(dep, version) {
                    Target::Node(to) => graph.add_root(
                        workspace.clone(),
                        None,
                        edge(dep, to, kind, &spec.unwrap_or_default()),
                    ),
                    Target::Local => {}
                    Target::Unresolved => {
                        graph.warn(format!("Unresolved {kind} dependency {dep} at importer {workspace:?}"))
                    }
                }
            }
        }
    }
    Ok(graph)
}

/// uv.lock: `editable` and `virtual` packages are the project (roots, with the
/// package name as `workspace`); every package's `dependencies` are edges.
/// Optional and dev dependency groups are typed edges; dev groups only count
/// for the project itself.
pub(crate) fn uv_graph(content: &str) -> Result<Graph, String> {
    let root: toml::Table = toml::from_str(content).map_err(|e| format!("invalid uv.lock: {e}"))?;
    let mut graph = Graph::default();
    let packages: Vec<&toml::Table> = root
        .get("package")
        .and_then(toml::Value::as_array)
        .map(|list| list.iter().filter_map(toml::Value::as_table).collect())
        .unwrap_or_default();
    for pkg in &packages {
        let source = pkg.get("source").and_then(toml::Value::as_table);
        let project = source.is_some_and(|s| s.contains_key("editable") || s.contains_key("virtual"));
        graph.add_node(GraphNode {
            name: pkg.get("name").and_then(toml::Value::as_str).unwrap_or("").into(),
            version: pkg.get("version").and_then(toml::Value::as_str).unwrap_or("").into(),
            source: source.and_then(|s| s.keys().next().cloned()),
            project,
        });
    }
    let by_name = names_index(&graph);
    // Declared specifiers exist only for project packages (`[package.metadata]`).
    let specifier = |pkg: &toml::Table, kind: &str, group: &str, dep: &str| -> String {
        let metadata = pkg.get("metadata").and_then(toml::Value::as_table);
        let list = if kind == "dev" {
            metadata
                .and_then(|m| m.get("requires-dev"))
                .and_then(toml::Value::as_table)
                .and_then(|t| t.get(group))
        } else {
            metadata.and_then(|m| m.get("requires-dist"))
        };
        list.and_then(toml::Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .filter_map(toml::Value::as_table)
                    .find(|t| t.get("name").and_then(toml::Value::as_str) == Some(dep))
            })
            .and_then(|t| t.get("specifier").and_then(toml::Value::as_str))
            .unwrap_or("")
            .to_owned()
    };
    for (from, pkg) in packages.iter().enumerate() {
        let from_label = coordinate(&graph.nodes[from]);
        let mut groups: Vec<(&str, String, &toml::Value)> = Vec::new();
        if let Some(list) = pkg.get("dependencies") {
            groups.push(("runtime", String::new(), list));
        }
        for (field, kind) in [("optional-dependencies", "optional"), ("dev-dependencies", "dev")] {
            if kind == "dev" && !graph.nodes[from].project {
                continue;
            }
            if let Some(table) = pkg.get(field).and_then(toml::Value::as_table) {
                for (group, list) in table {
                    groups.push((kind, group.clone(), list));
                }
            }
        }
        for (kind, group, list) in groups {
            let Some(items) = list.as_array() else {
                graph.warn(format!("Invalid {kind} declarations at {from_label}"));
                continue;
            };
            for item in items {
                let Some(dep) = item.as_table() else {
                    graph.warn(format!("Unknown declaration at {from_label}"));
                    continue;
                };
                let Some(name) = dep.get("name").and_then(toml::Value::as_str) else {
                    graph.warn(format!("Unknown declaration at {from_label}"));
                    continue;
                };
                let version = dep.get("version").and_then(toml::Value::as_str);
                let candidates: Vec<usize> = by_name
                    .get(name)
                    .map(|list| {
                        list.iter()
                            .copied()
                            .filter(|&i| version.is_none_or(|v| graph.nodes[i].version == v))
                            .collect()
                    })
                    .unwrap_or_default();
                let [to] = candidates[..] else {
                    let why = if candidates.is_empty() { "Unresolved" } else { "Ambiguous" };
                    graph.warn(format!("{why} {kind} dependency {name} at {from_label}"));
                    continue;
                };
                let declared = if graph.nodes[from].project {
                    specifier(pkg, kind, &group, name)
                } else {
                    String::new()
                };
                let e = edge(name, to, kind, &declared);
                if graph.nodes[from].project {
                    let workspace = graph.nodes[from].name.clone();
                    graph.add_root(workspace, Some(from), e.clone());
                }
                graph.add_edge(from, e);
            }
        }
    }
    Ok(graph)
}

/// Gemfile.lock / gems.locked: `DEPENDENCIES` are the roots, the indented
/// requirement lines under each `specs:` entry are the edges. Platform
/// variants of one release are one node. The lock does not record dependency
/// groups, so types are `unknown`.
pub(crate) fn gemfile_graph(content: &str) -> Result<Graph, String> {
    let mut graph = Graph::default();
    let mut node_of: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut raw_edges: Vec<(usize, String, String)> = Vec::new();
    let mut raw_roots: Vec<(String, String)> = Vec::new();
    let mut section = "";
    let mut source: Option<&str> = None;
    let mut in_specs = false;
    let mut current: Option<usize> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            section = trimmed;
            source = match trimmed {
                "GEM" => Some("registry"),
                "GIT" => Some("git"),
                "PATH" => Some("local"),
                _ => None,
            };
            in_specs = false;
            current = None;
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if section == "DEPENDENCIES" && indent == 2 {
            let entry = trimmed.trim_end_matches('!');
            let (name, requirement) = entry.split_once(" (").map_or((entry, ""), |(n, r)| {
                (n, r.strip_suffix(')').unwrap_or(r))
            });
            raw_roots.push((name.into(), requirement.into()));
            continue;
        }
        let Some(source) = source else { continue };
        if line == "  specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        let (name, rest) = trimmed.split_once(" (").map_or((trimmed, ""), |(n, r)| {
            (n, r.strip_suffix(')').unwrap_or(r))
        });
        if indent == 4 {
            let version = rest.split_once('-').map_or(rest, |(v, _)| v);
            let key = (name.to_owned(), version.to_owned());
            let index = *node_of.entry(key).or_insert_with(|| {
                graph.add_node(GraphNode {
                    name: name.into(),
                    version: version.into(),
                    source: Some(source.into()),
                    project: false,
                })
            });
            current = Some(index);
        } else if indent == 6 {
            if let Some(from) = current {
                raw_edges.push((from, name.into(), rest.into()));
            }
        }
    }
    let by_name = names_index(&graph);
    let resolve = |name: &str| -> Result<usize, &'static str> {
        match by_name.get(name).map(Vec::as_slice) {
            Some([only]) => Ok(*only),
            Some(_) => Err("Ambiguous"),
            None => Err("Unresolved"),
        }
    };
    for (from, name, requirement) in raw_edges {
        match resolve(&name) {
            Ok(to) => graph.add_edge(from, edge(&name, to, "unknown", &requirement)),
            Err(why) => {
                let at = coordinate(&graph.nodes[from]);
                graph.warn(format!("{why} dependency {name} at {at}"));
            }
        }
    }
    for (name, requirement) in raw_roots {
        match resolve(&name) {
            Ok(to) => graph.add_root(String::new(), None, edge(&name, to, "unknown", &requirement)),
            Err(why) => graph.warn(format!("{why} direct dependency {name}")),
        }
    }
    Ok(graph)
}

/// NuGet packages.lock.json: `Direct` entries are roots per target framework
/// (`workspace` is the framework moniker); `Project` references contribute
/// their own dependencies as roots (`workspace` is `framework/project`).
/// `dependencies` maps are edges, resolved within the same framework.
pub(crate) fn nuget_graph(content: &str) -> Result<Graph, String> {
    let root: Value =
        serde_json::from_str(content).map_err(|e| format!("invalid packages.lock.json: {e}"))?;
    let frameworks = root
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or("invalid packages.lock.json: no dependencies inventory")?;
    let mut graph = Graph::default();
    // Per framework: package name -> node.
    let mut resolved: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    for (framework, packages) in frameworks {
        let Some(packages) = packages.as_object() else {
            continue;
        };
        for (name, details) in packages {
            if details.get("type").and_then(Value::as_str) == Some("Project") {
                continue;
            }
            let Some(version) = details.get("resolved").and_then(Value::as_str) else {
                continue;
            };
            // One node per target framework: frameworks may resolve different
            // versions, so edges must not leak between them. Equal coordinates
            // are folded together again when evidence is attached.
            let index = graph.add_node(GraphNode {
                name: name.clone(),
                version: version.into(),
                source: None,
                project: false,
            });
            resolved.entry(framework).or_default().insert(name, index);
        }
    }
    for (framework, packages) in frameworks {
        let Some(packages) = packages.as_object() else {
            continue;
        };
        let known = resolved.get(framework.as_str());
        for (name, details) in packages {
            let kind = details.get("type").and_then(Value::as_str);
            let from = known.and_then(|k| k.get(name.as_str())).copied();
            let declared = details.get("dependencies").and_then(Value::as_object);
            let project = kind == Some("Project");
            for (dep, requirement) in declared.into_iter().flatten() {
                let requirement = requirement.as_str().unwrap_or("");
                let Some(&to) = known.and_then(|k| k.get(dep.as_str())) else {
                    graph.warn(format!("Unresolved dependency {dep} at {name} ({framework})"));
                    continue;
                };
                let e = edge(dep, to, "unknown", requirement);
                if project {
                    graph.add_root(format!("{framework}/{name}"), None, e);
                } else if let Some(from) = from {
                    graph.add_edge(from, e);
                }
            }
            if kind == Some("Direct") {
                if let Some(to) = from {
                    let requested = details.get("requested").and_then(Value::as_str).unwrap_or("");
                    graph.add_root(framework.clone(), None, edge(name, to, "unknown", requested));
                }
            }
        }
    }
    Ok(graph)
}

/// Build the relationship graph for a lockfile name, or `None` when the format
/// does not record both edges and declared roots.
pub(crate) fn build(name: &str, content: &str) -> Option<Result<Graph, String>> {
    Some(match name {
        "Cargo.lock" => cargo_graph(content),
        "pnpm-lock.yaml" => pnpm_graph(content),
        "uv.lock" => uv_graph(content),
        "Gemfile.lock" | "gems.locked" => gemfile_graph(content),
        "packages.lock.json" => nuget_graph(content),
        _ => return None,
    })
}

/// Fold evidence for every graph node that shares a name and version into one
/// occurrence update (a NuGet package restored for several target frameworks
/// is one node per framework). Entries whose sources differ are different
/// packages that the inventory cannot tell apart, so the merge is reported
/// and the result is `partial`.
pub(crate) fn merge(parts: Vec<(&Option<String>, &NodeEvidence)>) -> NodeEvidence {
    if let [(_, only)] = parts[..] {
        return NodeEvidence {
            status: only.status,
            paths: only.paths.clone(),
            warnings: only.warnings.clone(),
        };
    }
    let mut paths: Vec<DependencyPath> = parts.iter().flat_map(|(_, p)| p.paths.clone()).collect();
    paths.sort_by_cached_key(|p| (p.chain.len(), p.workspace.clone(), p.entry_point.clone()));
    let same = |a: &DependencyPath, b: &DependencyPath| {
        a.workspace == b.workspace
            && a.chain.len() == b.chain.len()
            && a.chain.iter().zip(&b.chain).all(|(x, y)| {
                (&x.name, &x.install_path, &x.dependency_type, &x.declared)
                    == (&y.name, &y.install_path, &y.dependency_type, &y.declared)
            })
    };
    paths.dedup_by(|a, b| same(a, b));
    let mut warnings: Vec<String> = parts
        .iter()
        .flat_map(|(_, p)| p.warnings.clone())
        .collect();
    let sources: BTreeSet<_> = parts.iter().map(|(source, _)| source).collect();
    let mut status = if parts.iter().all(|(_, p)| p.status == parts[0].1.status) {
        parts[0].1.status
    } else {
        "partial"
    };
    if sources.len() > 1 {
        status = "partial";
        warnings.push(
            "Several lockfile entries from different sources share this name and version; their chains are merged"
                .into(),
        );
    }
    if paths.len() > MAX_PATHS {
        status = "partial";
        paths.truncate(MAX_PATHS);
        warnings.push("Relationship path limit reached; additional paths are unknown".into());
    }
    warnings.sort();
    warnings.dedup();
    warnings.truncate(MAX_WARNINGS);
    NodeEvidence {
        status,
        paths,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfiles::parse_lockfile_content;
    use crate::models::Dependency;

    fn parse(name: &str, content: &str) -> Vec<Dependency> {
        parse_lockfile_content(name, content).unwrap().dependencies
    }
    fn find<'a>(deps: &'a [Dependency], name: &str, version: &str) -> &'a Dependency {
        deps.iter()
            .find(|d| d.name == name && d.version == version)
            .unwrap_or_else(|| panic!("{name}@{version} missing"))
    }
    /// `workspace:entry>step>...>target` per path, in emitted order.
    fn rendered(dep: &Dependency) -> Vec<String> {
        dep.occurrence
            .paths
            .iter()
            .map(|p| {
                let steps: Vec<_> = p.chain.iter().map(|s| s.package_name.as_str()).collect();
                format!("{}:{}", p.workspace, steps.join(">"))
            })
            .collect()
    }

    const CARGO: &str = r#"
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["left", "right", "gitdep", "shared 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "tool"
version = "0.2.0"
dependencies = ["shared 2.0.0", "app"]

[[package]]
name = "left"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["shared 1.0.0"]

[[package]]
name = "right"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["shared 1.0.0"]

[[package]]
name = "shared"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "shared"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "gitdep"
version = "0.3.0"
source = "git+https://example.com/gitdep?rev=abc#abc"
dependencies = ["left"]
"#;

    #[test]
    fn cargo_diamond_two_versions_members_and_git_source() {
        let deps = parse("Cargo.lock", CARGO);
        // The same dependency set and order as before relationship evidence.
        let names: Vec<_> = deps
            .iter()
            .map(|d| format!("{}@{}", d.name, d.version))
            .collect();
        assert_eq!(
            names,
            [
                "app@0.1.0",
                "tool@0.2.0",
                "left@1.0.0",
                "right@1.0.0",
                "shared@1.0.0",
                "shared@2.0.0",
                "gitdep@0.3.0"
            ]
        );
        let shared1 = find(&deps, "shared", "1.0.0");
        assert_eq!(shared1.occurrence.status, "available");
        assert_eq!(
            rendered(shared1),
            [
                "app:shared",
                "app:left>shared",
                "app:right>shared",
                "tool:app>shared",
                "app:gitdep>left>shared",
                "tool:app>left>shared",
                "tool:app>right>shared",
                "tool:app>gitdep>left>shared",
            ]
        );
        // The other version is only reached from the second member.
        let shared2 = find(&deps, "shared", "2.0.0");
        assert_eq!(rendered(shared2), ["tool:shared"]);
        assert_eq!(shared2.occurrence.paths[0].entry_point, "shared");
        assert_eq!(
            shared2.occurrence.paths[0].chain[0].dependency_type,
            "unknown"
        );
        // Non-registry packages keep their warning and gain evidence.
        let git = find(&deps, "gitdep", "0.3.0");
        assert_eq!(git.occurrence.source.as_deref(), Some("git"));
        assert!(git.occurrence.warnings[0].contains("git source"));
        assert_eq!(rendered(git), ["app:gitdep", "tool:app>gitdep"]);
        // Project crates are the starting points, not dependencies to explain.
        let tool = find(&deps, "tool", "0.2.0");
        assert_eq!(tool.occurrence.status, "available");
        assert!(tool.occurrence.paths.is_empty());
    }

    #[test]
    fn cargo_cycle_and_unresolved_edges_are_explicit_warnings() {
        let cyc = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["a"]
[[package]]
name = "a"
version = "1.0.0"
source = "registry+x"
dependencies = ["b"]
[[package]]
name = "b"
version = "1.0.0"
source = "registry+x"
dependencies = ["a"]
"#;
        let deps = parse("Cargo.lock", cyc);
        let b = find(&deps, "b", "1.0.0");
        assert_eq!(b.occurrence.status, "partial");
        assert_eq!(rendered(b), ["app:a>b"]);
        assert!(b.occurrence.warnings[0].contains("Dependency cycle at a@1.0.0"));

        let missing = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["a 1.0.0", "a", "ghost 9.9.9"]
[[package]]
name = "a"
version = "1.0.0"
source = "registry+x"
[[package]]
name = "a"
version = "2.0.0"
source = "registry+x"
"#;
        let deps = parse("Cargo.lock", missing);
        // Bare `a` is ambiguous (two versions) and `ghost` is absent.
        let a1 = find(&deps, "a", "1.0.0");
        assert_eq!(a1.occurrence.status, "partial");
        assert_eq!(rendered(a1), ["app:a"]);
        let w = &a1.occurrence.warnings[0];
        assert!(w.contains("Ambiguous dependency a at app"), "{w}");
        assert!(w.contains("Unresolved dependency ghost 9.9.9 at app"), "{w}");
        // The version no declared root reaches gets no chain, only a warning.
        let a2 = find(&deps, "a", "2.0.0");
        assert_eq!(a2.occurrence.status, "partial");
        assert!(a2.occurrence.paths.is_empty());
        assert!(a2.occurrence.warnings[0].contains("a@2.0.0 is not reachable from a declared root"));

        // Every declaration unresolved: no root at all, so nothing is claimed.
        let none = parse("Cargo.lock", &missing.replace("\"a 1.0.0\", \"a\", ", ""));
        assert!(none.iter().all(|d| d.occurrence.status == "unavailable" || d.name == "app"));
        assert!(none.iter().all(|d| d.occurrence.paths.is_empty()));
    }

    const PNPM: &str = r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      right:
        specifier: ^1.0.0
        version: 1.0.0(peer@1.0.0)
      localdep:
        specifier: link:../localdep
        version: link:../localdep
  packages/web:
    dependencies:
      shared:
        specifier: ^2.0.0
        version: 2.0.0
packages:
  left@1.0.0:
    resolution: {integrity: sha512-a}
  right@1.0.0:
    resolution: {integrity: sha512-b}
  peer@1.0.0:
    resolution: {integrity: sha512-p}
  shared@1.0.0:
    resolution: {integrity: sha512-c}
  shared@2.0.0:
    resolution: {integrity: sha512-d}
snapshots:
  left@1.0.0:
    dependencies:
      shared: 1.0.0
  right@1.0.0(peer@1.0.0):
    dependencies:
      shared: 1.0.0
      peer: 1.0.0
    optionalDependencies:
      gone: 1.0.0
  peer@1.0.0: {}
  shared@1.0.0: {}
  shared@2.0.0: {}
"#;

    #[test]
    fn pnpm_importers_snapshots_diamond_versions_and_local_links() {
        let deps = parse("pnpm-lock.yaml", PNPM);
        let names: Vec<_> = deps
            .iter()
            .map(|d| format!("{}@{}", d.name, d.version))
            .collect();
        assert_eq!(
            names,
            [
                "left@1.0.0",
                "right@1.0.0",
                "peer@1.0.0",
                "shared@1.0.0",
                "shared@2.0.0"
            ]
        );
        // `gone` is an unresolved optional edge: everything is partial, never silent.
        let shared1 = find(&deps, "shared", "1.0.0");
        assert_eq!(shared1.occurrence.status, "partial");
        assert_eq!(rendered(shared1), [":left>shared", ":right>shared"]);
        assert!(shared1.occurrence.warnings[0]
            .contains("Unresolved optional dependency gone at right@1.0.0"));
        let right = find(&deps, "right", "1.0.0");
        assert_eq!(right.occurrence.paths[0].chain[0].dependency_type, "dev");
        assert_eq!(right.occurrence.paths[0].chain[0].declared, "^1.0.0");
        // The second importer is its own workspace and the other version stays separate.
        let shared2 = find(&deps, "shared", "2.0.0");
        assert_eq!(rendered(shared2), ["packages/web:shared"]);
        let peer = find(&deps, "peer", "1.0.0");
        assert_eq!(rendered(peer), [":right>peer"]);
    }

    #[test]
    fn pnpm_cycle_and_unreachable_package() {
        let lock = r#"
lockfileVersion: 5.4
specifiers:
  a: ^1.0.0
dependencies:
  a: 1.0.0
packages:
  /a/1.0.0:
    dependencies:
      b: 1.0.0
  /b/1.0.0:
    dependencies:
      a: 1.0.0
  /orphan/1.0.0:
    resolution: {integrity: sha512-x}
"#;
        let deps = parse("pnpm-lock.yaml", lock);
        let b = find(&deps, "b", "1.0.0");
        assert_eq!(rendered(b), [":a>b"]);
        assert_eq!(b.occurrence.paths[0].chain[0].declared, "^1.0.0");
        assert_eq!(b.occurrence.status, "partial");
        assert!(b.occurrence.warnings[0].contains("Dependency cycle at a@1.0.0"));
        let orphan = find(&deps, "orphan", "1.0.0");
        assert!(orphan.occurrence.paths.is_empty());
        assert_eq!(orphan.occurrence.status, "partial");
        assert!(orphan.occurrence.warnings[0]
            .contains("orphan@1.0.0 is not reachable from a declared root"));
    }

    const UV: &str = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "left" }, { name = "right" }, { name = "gitlib" }]

[package.optional-dependencies]
extra = [{ name = "shared", version = "2.0.0" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[package.metadata]
requires-dist = [{ name = "left", specifier = ">=1" }]

[package.metadata.requires-dev]
dev = [{ name = "pytest", specifier = ">=8" }]

[[package]]
name = "member"
source = { virtual = "packages/member" }
dependencies = [{ name = "shared", version = "1.0.0" }]

[[package]]
name = "left"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "shared", version = "1.0.0" }]

[[package]]
name = "right"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "shared", version = "1.0.0" }]

[[package]]
name = "shared"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "shared"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "gitlib"
version = "0.1.0"
source = { git = "https://example.com/gitlib#abc" }
"#;

    #[test]
    fn uv_editable_and_virtual_roots_typed_groups_and_versions() {
        let deps = parse("uv.lock", UV);
        let shared1 = find(&deps, "shared", "1.0.0");
        assert_eq!(shared1.occurrence.status, "available");
        assert_eq!(
            rendered(shared1),
            ["member:shared", "app:left>shared", "app:right>shared"]
        );
        let shared2 = find(&deps, "shared", "2.0.0");
        assert_eq!(rendered(shared2), ["app:shared"]);
        assert_eq!(
            shared2.occurrence.paths[0].chain[0].dependency_type,
            "optional"
        );
        let pytest = find(&deps, "pytest", "8.0.0");
        assert_eq!(pytest.occurrence.paths[0].chain[0].dependency_type, "dev");
        assert_eq!(pytest.occurrence.paths[0].chain[0].declared, ">=8");
        let left = find(&deps, "left", "1.0.0");
        assert_eq!(left.occurrence.paths[0].chain[0].declared, ">=1");
        let git = find(&deps, "gitlib", "0.1.0");
        assert_eq!(rendered(git), ["app:gitlib"]);
        assert!(git.occurrence.warnings[0].contains("git source"));
    }

    #[test]
    fn uv_cycle_and_missing_target() {
        let lock = r#"
version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "a" }, { name = "ghost" }]
[[package]]
name = "a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "b" }]
[[package]]
name = "b"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "a" }]
"#;
        let deps = parse("uv.lock", lock);
        let b = find(&deps, "b", "1.0.0");
        assert_eq!(rendered(b), ["app:a>b"]);
        assert_eq!(b.occurrence.status, "partial");
        let w = &b.occurrence.warnings[0];
        assert!(w.contains("Dependency cycle at a@1.0.0"), "{w}");
        assert!(
            w.contains("Unresolved runtime dependency ghost at app@0.1.0"),
            "{w}"
        );
    }

    const GEMS: &str = r#"GIT
  remote: https://example.com/gitgem.git
  revision: abc
  specs:
    gitgem (0.1.0)
      left (>= 1.0)

PATH
  remote: vendor/pathgem
  specs:
    pathgem (0.0.1)

GEM
  remote: https://rubygems.org/
  specs:
    left (1.0.0)
      shared (~> 1.0)
    right (1.0.0)
      shared (>= 1.0, < 3)
    shared (1.0.0)
    nokogiri (1.15.0)
    nokogiri (1.15.0-x86_64-linux)

PLATFORMS
  ruby

DEPENDENCIES
  gitgem!
  left (~> 1.0)
  nokogiri
  pathgem!
  right
"#;

    #[test]
    fn gemfile_dependencies_roots_specs_edges_and_sources() {
        let deps = parse("Gemfile.lock", GEMS);
        let shared = find(&deps, "shared", "1.0.0");
        assert_eq!(shared.occurrence.status, "available");
        assert_eq!(
            rendered(shared),
            [":left>shared", ":right>shared", ":gitgem>left>shared"]
        );
        let left = &find(&deps, "left", "1.0.0").occurrence.paths;
        let declared: Vec<_> = left.iter().map(|p| p.chain[0].declared.as_str()).collect();
        assert!(declared.contains(&"~> 1.0"));
        assert_eq!(
            shared.occurrence.paths[0].chain[0].dependency_type,
            "unknown"
        );
        // Both platform variants share one release identity and one chain.
        let nokogiri: Vec<_> = deps.iter().filter(|d| d.name == "nokogiri").collect();
        assert_eq!(nokogiri.len(), 2);
        assert!(nokogiri.iter().all(|d| rendered(d) == [":nokogiri"]));
        let path = find(&deps, "pathgem", "0.0.1");
        assert_eq!(path.occurrence.source.as_deref(), Some("local"));
        assert_eq!(rendered(path), [":pathgem"]);
        assert!(path.occurrence.warnings[0].contains("local source"));
    }

    #[test]
    fn gemfile_cycle_missing_target_and_unknown_roots() {
        let lock = r#"GEM
  remote: https://rubygems.org/
  specs:
    a (1.0.0)
      b
      ghost (>= 1)
    b (1.0.0)
      a

DEPENDENCIES
  a
  vanished
"#;
        let deps = parse("gems.locked", lock);
        let b = find(&deps, "b", "1.0.0");
        assert_eq!(rendered(b), [":a>b"]);
        assert_eq!(b.occurrence.status, "partial");
        let w = &b.occurrence.warnings[0];
        assert!(w.contains("Dependency cycle at a@1.0.0"), "{w}");
        assert!(w.contains("Unresolved dependency ghost at a@1.0.0"), "{w}");
        assert!(w.contains("Unresolved direct dependency vanished"), "{w}");
        // No DEPENDENCIES section: nothing is claimed.
        let none = "GEM\n  remote: https://rubygems.org/\n  specs:\n    a (1.0.0)\n";
        let deps = parse("Gemfile.lock", none);
        assert_eq!(deps[0].occurrence.status, "unavailable");
        assert!(deps[0].occurrence.paths.is_empty());
        assert!(deps[0].occurrence.warnings[0].contains("no direct declarations"));
    }

    const NUGET: &str = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Left": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0",
               "dependencies": {"Shared": "1.0.0"}},
      "Right": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0",
                "dependencies": {"Shared": "[1.0.0, )"}},
      "Shared": {"type": "Transitive", "resolved": "1.0.0"},
      "Lib.Project": {"type": "Project", "dependencies": {"Projdep": "2.0.0"}},
      "Projdep": {"type": "Transitive", "resolved": "2.0.0"}
    },
    "net6.0": {
      "Left": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0",
               "dependencies": {"Shared": "1.0.0"}},
      "Shared": {"type": "Transitive", "resolved": "0.9.0"}
    }
  }
}"#;

    #[test]
    fn nuget_direct_roots_per_framework_and_versions() {
        let deps = parse("packages.lock.json", NUGET);
        let shared = find(&deps, "Shared", "1.0.0");
        assert_eq!(
            rendered(shared),
            ["net8.0:Left>Shared", "net8.0:Right>Shared"]
        );
        assert_eq!(shared.occurrence.status, "available");
        let old = find(&deps, "Shared", "0.9.0");
        assert_eq!(rendered(old), ["net6.0:Left>Shared"]);
        let left = find(&deps, "Left", "1.0.0");
        assert_eq!(rendered(left), ["net6.0:Left", "net8.0:Left"]);
        assert_eq!(left.occurrence.paths[0].chain[0].declared, "[1.0.0, )");
        let proj = find(&deps, "Projdep", "2.0.0");
        assert_eq!(rendered(proj), ["net8.0/Lib.Project:Projdep"]);
    }

    #[test]
    fn nuget_cycle_missing_target_and_unreachable() {
        let lock = r#"{"version":1,"dependencies":{"net8.0":{
          "A":{"type":"Direct","resolved":"1.0.0","dependencies":{"B":"1.0.0","Ghost":"1.0.0"}},
          "B":{"type":"Transitive","resolved":"1.0.0","dependencies":{"A":"1.0.0"}},
          "Orphan":{"type":"Transitive","resolved":"3.0.0"}}}}"#;
        let deps = parse("packages.lock.json", lock);
        let b = find(&deps, "B", "1.0.0");
        assert_eq!(rendered(b), ["net8.0:A>B"]);
        assert_eq!(b.occurrence.status, "partial");
        let w = &b.occurrence.warnings[0];
        assert!(w.contains("Dependency cycle at A@1.0.0"), "{w}");
        assert!(w.contains("Unresolved dependency Ghost at A (net8.0)"), "{w}");
        let orphan = find(&deps, "Orphan", "3.0.0");
        assert!(orphan.occurrence.paths.is_empty());
        assert_eq!(orphan.occurrence.status, "partial");
    }

    #[test]
    fn formats_without_roots_and_edges_stay_unavailable() {
        let yarn = "# yarn lockfile v1\n\n\"a@^1.0.0\":\n  version \"1.0.0\"\n";
        let deps = parse("yarn.lock", yarn);
        assert_eq!(deps[0].occurrence.status, "unavailable");
        assert!(deps[0].occurrence.paths.is_empty());
        let poetry = "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n";
        let deps = parse("poetry.lock", poetry);
        assert_eq!(deps[0].occurrence.status, "unavailable");
    }

    fn plain(name: &str) -> GraphNode {
        GraphNode {
            name: name.into(),
            version: "1".into(),
            source: None,
            project: false,
        }
    }

    /// `width` hubs, all reachable from the root and all pointing at node 0
    /// (`target`), which then continues `depth` hops further.
    fn chain_graph(width: usize, depth: usize) -> Graph {
        let mut g = Graph::default();
        let target = g.add_node(plain("target"));
        for i in 0..width {
            let hub = g.add_node(plain(&format!("hub{i:03}")));
            g.add_root(
                String::new(),
                None,
                edge(&format!("hub{i:03}"), hub, "runtime", "1"),
            );
            g.add_edge(hub, edge("target", target, "runtime", "1"));
        }
        let mut previous = target;
        for i in 0..depth {
            let next = g.add_node(plain(&format!("deep{i}")));
            g.add_edge(previous, edge("deep", next, "runtime", "1"));
            previous = next;
        }
        g
    }

    #[test]
    fn path_cap_keeps_the_shortest_chains_deterministically_with_a_warning() {
        let mut g = chain_graph(40, 0);
        // A long way round that must lose to the 40 short chains.
        let a = g.add_node(plain("a"));
        let b = g.add_node(plain("b"));
        g.add_root(String::new(), None, edge("a", a, "runtime", "1"));
        g.add_edge(a, edge("b", b, "runtime", "1"));
        g.add_edge(b, edge("target", 0, "runtime", "1"));
        let out = compute(g);
        let target = &out[0];
        assert_eq!(target.paths.len(), MAX_PATHS);
        assert!(target.paths.iter().all(|p| p.chain.len() == 2));
        assert_eq!(target.status, "partial");
        assert!(target.warnings[0].contains("path limit"));
        let entries: Vec<_> = target.paths.iter().map(|p| p.entry_point.clone()).collect();
        let mut sorted = entries.clone();
        sorted.sort();
        assert_eq!(entries, sorted);
        assert_eq!(entries[0], "hub000");
    }

    #[test]
    fn depth_bound_stops_deep_chains_and_says_so() {
        let out = compute(chain_graph(1, MAX_DEPTH + 5));
        assert!(out
            .iter()
            .all(|n| n.paths.iter().all(|p| p.chain.len() <= MAX_DEPTH)));
        assert!(out
            .iter()
            .any(|n| n.warnings.iter().any(|w| w.contains("depth limit"))));
        // Nodes beyond the bound have no fabricated chain.
        let last = out.last().unwrap();
        assert!(last.paths.is_empty());
        assert_eq!(last.status, "partial");
    }

    #[test]
    fn traversal_bound_is_reported_not_silent() {
        let out = compute(chain_graph(MAX_VISITS + 10, 0));
        assert!(out[0].warnings[0].contains("limit"));
        assert_eq!(out[0].status, "partial");
    }
}
