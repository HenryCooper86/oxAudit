//! NuGet references in .NET project files (`*.csproj`, `*.fsproj`,
//! `*.vbproj`), with central package management.
//!
//! `packages.lock.json` is opt-in, so most .NET repositories declare their
//! packages only here: `<PackageReference Include="X" Version="1.2.3" />`
//! (or a `<Version>` child), or with no version at all when a
//! `Directory.Packages.props` pins it centrally with `<PackageVersion>`; a
//! `VersionOverride` on the reference wins over the central pin.
//!
//! Only exact versions are queried. Floating versions (`1.*`), ranges
//! (`[1.0,2.0)`) and MSBuild properties (`$(NewtonsoftVersion)`) do not name
//! one installed release, so they are recorded as unchecked rather than
//! guessed. Conditions are not evaluated: a conditional reference is read
//! like any other, and noted.

use std::collections::BTreeMap;

/// `<PackageVersion>` pins from a `Directory.Packages.props`, keyed by
/// lowercased package id (NuGet ids are case-insensitive).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CentralVersions {
    versions: BTreeMap<String, String>,
    /// `<GlobalPackageReference>` items: packages every project references.
    globals: Vec<(String, String)>,
    /// Caveats about the pins themselves (an id pinned more than once).
    notes: Vec<String>,
}

impl CentralVersions {
    /// Caveats to carry into each project's inventory notes.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// `(package id, version)` of every `<GlobalPackageReference>`.
    pub fn global_references(&self) -> Vec<(String, String)> {
        self.globals.clone()
    }
}

/// What one project file declares.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MsbuildInventory {
    /// `(package id, exact version)` pairs to query.
    pub packages: Vec<(String, String)>,
    /// References that could not be checked, each naming the package and why.
    pub unchecked: Vec<String>,
}

/// Whether `path` is a .NET project file oxAudit reads references from.
pub fn is_msbuild_project(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "csproj" | "fsproj" | "vbproj"
            )
        })
}

/// Read the `<PackageVersion>` pins of a `Directory.Packages.props`.
pub fn parse_central_versions(content: &str) -> Result<CentralVersions, String> {
    let mut versions = BTreeMap::new();
    let mut notes = Vec::new();
    // Include declares a pin, Update changes one; either sets the version.
    for item in read_items(content, "PackageVersion", "Directory.Packages.props")? {
        if item.action == Action::Remove {
            versions.remove(&item.include.to_ascii_lowercase());
        } else if let Some(version) = item.version {
            let previous = versions.insert(item.include.to_ascii_lowercase(), version);
            // Two Include pins of one id: conditions are not evaluated, so
            // which one applies is not known; the last is used.
            if previous.is_some() && item.action == Action::Include {
                notes.push(format!(
                    "{} is pinned more than once in Directory.Packages.props; the last pin is used",
                    item.include
                ));
            }
        }
    }
    let globals = read_items(
        content,
        "GlobalPackageReference",
        "Directory.Packages.props",
    )?
    .into_iter()
    .filter(|item| item.action == Action::Include)
    .filter_map(|item| item.version.map(|version| (item.include, version)))
    .collect();
    Ok(CentralVersions {
        versions,
        globals,
        notes,
    })
}

/// A legacy `packages.config`: `<packages><package id=… version=…/></packages>`.
/// Its versions are exact by construction; anything else is noted.
pub fn parse_packages_config(content: &str) -> Result<MsbuildInventory, String> {
    use quick_xml::events::Event;
    use quick_xml::{Reader, XmlVersion};
    let invalid = |reason: String| format!("invalid packages.config: {reason}");
    let mut reader = Reader::from_str(content.trim_start_matches('\u{feff}'));
    let mut inventory = MsbuildInventory::default();
    let mut depth = 0usize;
    let mut saw_root = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| invalid(error.to_string()))?;
        let (element, opens) = match event {
            Event::Start(element) => (element, true),
            Event::Empty(element) => (element, false),
            Event::End(_) => {
                depth = depth.saturating_sub(1);
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let name = element.local_name().as_ref().to_string();
        if depth == 0 {
            if name != "packages" {
                return Err(invalid("the root element must be <packages>".into()));
            }
            saw_root = true;
        } else if name == "package" {
            let mut id = None;
            let mut version = None;
            for attribute in element.attributes() {
                let attribute = attribute.map_err(|error| invalid(error.to_string()))?;
                let value = attribute
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map_err(|error| invalid(error.to_string()))?
                    .trim()
                    .to_string();
                match attribute.key.local_name().as_ref() {
                    "id" => id = Some(value),
                    "version" => version = Some(value),
                    _ => {}
                }
            }
            let id = id
                .filter(|id| !id.is_empty())
                .ok_or_else(|| invalid("a <package> has no id".into()))?;
            match version.as_deref().and_then(exact_version) {
                Some(exact) => inventory.add(id, exact.to_string()),
                None => inventory.unchecked.push(format!(
                    "{id} {} is not an exact version and was not checked",
                    version.unwrap_or_default()
                )),
            }
        }
        if opens {
            depth += 1;
        }
    }
    if !saw_root || depth != 0 {
        return Err(invalid(
            "the document is not a complete <packages> list".into(),
        ));
    }
    Ok(inventory)
}

impl MsbuildInventory {
    /// Add a package once: NuGet ids are case-insensitive, and the first
    /// declaration of an id wins.
    fn add(&mut self, id: String, version: String) {
        if !self
            .packages
            .iter()
            .any(|(known, _)| known.eq_ignore_ascii_case(&id))
        {
            self.packages.push((id, version));
        }
    }

    /// Fold another file's packages in (`Directory.Build.props`, global
    /// references, `packages.config`); ids already present are kept as they
    /// are, so the project's own declaration wins.
    pub fn merge(&mut self, other: MsbuildInventory) {
        for (id, version) in other.packages {
            self.add(id, version);
        }
        self.unchecked.extend(other.unchecked);
    }

    /// Exact-version packages from a list such as global references, with
    /// anything else noted.
    pub fn from_pins(pins: Vec<(String, String)>) -> MsbuildInventory {
        let mut inventory = MsbuildInventory::default();
        for (id, version) in pins {
            match exact_version(&version) {
                Some(exact) => inventory.add(id, exact.to_string()),
                None => inventory.unchecked.push(format!(
                    "{id} {version} is not an exact version and was not checked"
                )),
            }
        }
        inventory
    }
}

/// Read the package references of one project file.
pub fn parse_project(
    content: &str,
    central: Option<&CentralVersions>,
) -> Result<MsbuildInventory, String> {
    let mut inventory = MsbuildInventory::default();
    // Include declares a reference; Update changes one declared here or an
    // implicit one (F#'s FSharp.Core); Remove drops one. An Update without a
    // version changes only metadata and adds nothing to look up.
    let mut references: Vec<Item> = Vec::new();
    for item in read_items(content, "PackageReference", "project file")? {
        let existing = references
            .iter()
            .position(|known| known.include.eq_ignore_ascii_case(&item.include));
        match (item.action, existing) {
            (Action::Include, None) => references.push(item),
            (Action::Include, Some(_)) => {}
            (Action::Update, Some(at)) => {
                let known = &mut references[at];
                if item.version.is_some() {
                    known.version = item.version;
                }
                if item.version_override.is_some() {
                    known.version_override = item.version_override;
                }
                known.conditional |= item.conditional;
            }
            (Action::Update, None) => {
                if item.version.is_some() || item.version_override.is_some() {
                    references.push(item);
                }
            }
            (Action::Remove, Some(at)) => {
                references.remove(at);
            }
            (Action::Remove, None) => {}
        }
    }
    for item in references {
        let id = item.include;
        if id.contains("$(") || id.contains("@(") || id.contains("%(") {
            inventory.unchecked.push(format!(
                "{id} is an MSBuild property or item expression, not a package id, and was not checked"
            ));
            continue;
        }
        let declared = item.version_override.or(item.version).or_else(|| {
            central.and_then(|central| central.versions.get(&id.to_ascii_lowercase()).cloned())
        });
        match declared {
            None => inventory.unchecked.push(format!(
                "{id} has no version here or in a Directory.Packages.props and was not checked"
            )),
            Some(version) => match exact_version(&version) {
                Some(exact) => inventory.add(id.clone(), exact.to_string()),
                None => inventory.unchecked.push(format!(
                    "{id} {version} is not an exact version and was not checked"
                )),
            },
        }
        if item.conditional {
            inventory.unchecked.push(format!(
                "{id} is declared under an MSBuild condition, which is not evaluated; it is reported as if the condition held"
            ));
        }
    }
    Ok(inventory)
}

/// `1.2.3`, `1.2.3.4`, `1.0.0-beta.2`, or a pinned `[1.2.3]`. Floating
/// versions, ranges and `$(Property)` values are not exact.
fn exact_version(version: &str) -> Option<&str> {
    let version = version.trim();
    let version = match version.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        Some(inner) if !inner.contains(',') => inner.trim(),
        Some(_) => return None,
        None => version,
    };
    let (core, rest) = match version.find(['-', '+']) {
        Some(at) => (&version[..at], &version[at..]),
        None => (version, ""),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let numeric = (1..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    let label_ok = rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    (numeric && label_ok && (rest.is_empty() || rest.len() > 1)).then_some(version)
}

/// One `<PackageReference>` or `<PackageVersion>` item.
#[derive(Debug, Default, Clone)]
struct Item {
    action: Action,
    /// The package id (from Include, Update or Remove).
    include: String,
    version: Option<String>,
    version_override: Option<String>,
    /// The item or an enclosing element carries a `Condition`.
    conditional: bool,
}

/// How an item element names its package.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Action {
    #[default]
    Include,
    Update,
    Remove,
}

/// Every `item` element of an MSBuild file, with its attributes and its
/// `<Version>`/`<VersionOverride>` children. The root must be `<Project>`.
fn read_items(content: &str, item: &str, what: &str) -> Result<Vec<Item>, String> {
    use quick_xml::events::{BytesStart, Event};
    use quick_xml::{Reader, XmlVersion};

    let invalid = |reason: String| format!("invalid {what}: {reason}");
    let content = content.trim_start_matches('\u{feff}');
    let mut reader = Reader::from_str(content);
    // (element name, carries a Condition)
    let mut stack: Vec<(String, bool)> = Vec::new();
    let mut items = Vec::new();
    let mut current: Option<(Vec<Item>, usize)> = None;
    let mut text = String::new();
    let mut saw_root = false;

    let attribute = |element: &BytesStart, key: &str| -> Result<Option<String>, String> {
        for attribute in element.attributes() {
            let attribute = attribute.map_err(|error| invalid(error.to_string()))?;
            if attribute.key.local_name().as_ref() == key {
                let value = attribute
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map_err(|error| invalid(error.to_string()))?;
                return Ok(Some(value.trim().to_string()));
            }
        }
        Ok(None)
    };
    let open = |element: &BytesStart,
                stack: &Vec<(String, bool)>,
                saw_root: &mut bool|
     -> Result<(String, bool, Option<Vec<Item>>), String> {
        let name = element.local_name().as_ref().to_string();
        if stack.is_empty() {
            if name != "Project" {
                return Err(invalid("the root element must be <Project>".into()));
            }
            *saw_root = true;
        }
        // `<Otherwise>` carries no Condition attribute but is just as
        // conditional as its sibling `<When>`.
        let conditional = attribute(element, "Condition")?.is_some() || name == "Otherwise";
        let found = if name == item {
            let mut named = None;
            for (key, action) in [
                ("Include", Action::Include),
                ("Update", Action::Update),
                ("Remove", Action::Remove),
            ] {
                if let Some(value) = attribute(element, key)?.filter(|value| !value.is_empty()) {
                    named = Some((action, value));
                    break;
                }
            }
            let (action, ids) = named
                .ok_or_else(|| invalid(format!("a <{item}> has no Include, Update or Remove")))?;
            let template = Item {
                action,
                include: String::new(),
                version: attribute(element, "Version")?.filter(|v| !v.is_empty()),
                version_override: attribute(element, "VersionOverride")?.filter(|v| !v.is_empty()),
                conditional: conditional || stack.iter().any(|(_, conditional)| *conditional),
            };
            // `Include="A;B"` declares two items.
            Some(
                ids.split(';')
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(|id| Item {
                        include: id.to_string(),
                        ..template.clone()
                    })
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        Ok((name, conditional, found))
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let (name, conditional, found) = open(&element, &stack, &mut saw_root)?;
                stack.push((name, conditional));
                if let Some(found) = found {
                    current = Some((found, stack.len()));
                }
                text.clear();
            }
            Ok(Event::Empty(element)) => {
                let (_, _, found) = open(&element, &stack, &mut saw_root)?;
                if let Some(found) = found {
                    items.extend(found);
                }
            }
            Ok(Event::Text(content)) => {
                text.push_str(&content.xml_content(XmlVersion::Implicit1_0))
            }
            Ok(Event::End(_)) => {
                let depth = stack.len();
                let (name, child_conditional) = stack
                    .pop()
                    .ok_or_else(|| invalid("unbalanced elements".into()))?;
                let value = std::mem::take(&mut text).trim().to_string();
                if let Some((open_items, item_depth)) = &mut current {
                    if depth == *item_depth + 1 && !value.is_empty() {
                        for open_item in open_items.iter_mut() {
                            // A version chosen under a condition makes the
                            // reference conditional too.
                            if child_conditional
                                && matches!(name.as_str(), "Version" | "VersionOverride")
                            {
                                open_item.conditional = true;
                            }
                            match name.as_str() {
                                "Version" => open_item.version = Some(value.clone()),
                                "VersionOverride" => {
                                    open_item.version_override = Some(value.clone())
                                }
                                _ => {}
                            }
                        }
                    } else if depth == *item_depth {
                        let (done, _) = current.take().expect("an open item");
                        items.extend(done);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(invalid(error.to_string())),
        }
    }
    if !saw_root {
        return Err(invalid("the root element must be <Project>".into()));
    }
    if !stack.is_empty() {
        return Err(invalid("the document ends inside an element".into()));
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(references: &str) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n  <ItemGroup>\n{references}\n  </ItemGroup>\n</Project>\n"
        )
    }

    fn packages(inventory: &MsbuildInventory) -> Vec<(&str, &str)> {
        inventory
            .packages
            .iter()
            .map(|(name, version)| (name.as_str(), version.as_str()))
            .collect()
    }

    #[test]
    fn package_references_with_exact_versions_are_queried() {
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
    <PackageReference Include="Pinned" Version="[2.0.0]" />
    <PackageReference Include="Pre" Version="1.0.0-beta.2" />
    <ProjectReference Include="..\Other\Other.csproj" />"#,
            ),
            None,
        )
        .expect("project");
        assert_eq!(
            packages(&inventory),
            [
                ("Newtonsoft.Json", "13.0.1"),
                ("Serilog", "3.1.1"),
                ("Pinned", "2.0.0"),
                ("Pre", "1.0.0-beta.2"),
            ]
        );
        assert!(inventory.unchecked.is_empty(), "{:?}", inventory.unchecked);
    }

    #[test]
    fn floating_ranged_and_property_versions_are_unchecked_notes() {
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Include="Floating" Version="1.*" />
    <PackageReference Include="Ranged" Version="[1.0,2.0)" />
    <PackageReference Include="Prop" Version="$(NewtonsoftVersion)" />
    <PackageReference Include="Unpinned" />"#,
            ),
            None,
        )
        .expect("project");
        assert!(inventory.packages.is_empty());
        for name in ["Floating", "Ranged", "Prop", "Unpinned"] {
            assert!(
                inventory.unchecked.iter().any(|note| note.contains(name)),
                "{name}: {:?}",
                inventory.unchecked
            );
        }
    }

    #[test]
    fn central_versions_fill_missing_versions_and_version_override_wins() {
        let central = parse_central_versions(
            r#"<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageVersion Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>"#,
        )
        .expect("props");
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Include="newtonsoft.json" />
    <PackageReference Include="Serilog" VersionOverride="2.12.0" />"#,
            ),
            Some(&central),
        )
        .expect("project");
        assert_eq!(
            packages(&inventory),
            [("newtonsoft.json", "13.0.3"), ("Serilog", "2.12.0")]
        );
    }

    #[test]
    fn a_bom_and_conditions_do_not_break_parsing() {
        let content = format!(
            "\u{feff}{}",
            project(
                r#"    <PackageReference Include="A" Version="1.0.0" Condition="'$(TargetFramework)' == 'net8.0'" />
    <PackageReference Include="B" Version="2.0.0" />"#
            )
        );
        let inventory = parse_project(&content, None).expect("project");
        assert_eq!(packages(&inventory), [("A", "1.0.0"), ("B", "2.0.0")]);
        assert!(
            inventory
                .unchecked
                .iter()
                .any(|note| note.contains("A") && note.contains("condition")),
            "{:?}",
            inventory.unchecked
        );
        // An ItemGroup condition is noted the same way.
        let grouped = "<Project><ItemGroup Condition=\"'$(Os)' == 'win'\"><PackageReference Include=\"W\" Version=\"1.0.0\" /></ItemGroup></Project>";
        let inventory = parse_project(grouped, None).expect("project");
        assert_eq!(packages(&inventory), [("W", "1.0.0")]);
        assert!(inventory.unchecked.iter().any(|note| note.contains("W")));
    }

    #[test]
    fn malformed_projects_are_errors() {
        assert!(parse_project("<Project><ItemGroup>", None).is_err());
        assert!(parse_project("<NotAProject />", None).is_err());
        assert!(parse_project(
            &project(r#"    <PackageReference Version="1.0.0" />"#),
            None
        )
        .is_err());
        assert!(parse_central_versions("<Project><ItemGroup>").is_err());
        // An empty project is a valid empty inventory.
        assert_eq!(
            parse_project("<Project Sdk=\"Microsoft.NET.Sdk\" />", None),
            Ok(MsbuildInventory::default())
        );
    }

    #[test]
    fn update_and_remove_items_are_understood() {
        // F# projects pin the implicit FSharp.Core with Update; Remove drops
        // an implicit reference. Neither has an Include.
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Update="FSharp.Core" Version="6.0.7" />
    <PackageReference Include="Serilog" Version="3.1.1" />
    <PackageReference Update="Serilog" Version="3.1.2" />
    <PackageReference Remove="System.ValueTuple" />
    <PackageReference Update="NETStandard.Library" PrivateAssets="all" />"#,
            ),
            None,
        )
        .expect("project");
        assert_eq!(
            packages(&inventory),
            [("FSharp.Core", "6.0.7"), ("Serilog", "3.1.2")]
        );
        let central = parse_central_versions(
            "<Project><ItemGroup><PackageVersion Include=\"A\" Version=\"1.0.0\" /><PackageVersion Update=\"A\" Version=\"1.0.1\" /></ItemGroup></Project>",
        )
        .expect("props");
        let inventory = parse_project(
            &project(r#"<PackageReference Include="A" />"#),
            Some(&central),
        )
        .unwrap();
        assert_eq!(packages(&inventory), [("A", "1.0.1")]);
    }

    #[test]
    fn property_and_list_includes_are_not_queried_as_names() {
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Include="$(JsonPackage)" Version="12.0.1" />
    <PackageReference Include="Newtonsoft.Json;Serilog" Version="12.0.1" />
    <PackageReference Include="@(Items)" Version="1.0.0" />"#,
            ),
            None,
        )
        .expect("project");
        assert_eq!(
            packages(&inventory),
            [("Newtonsoft.Json", "12.0.1"), ("Serilog", "12.0.1")]
        );
        assert!(
            inventory
                .unchecked
                .iter()
                .any(|note| note.contains("$(JsonPackage)")),
            "{:?}",
            inventory.unchecked
        );
        assert!(
            inventory
                .unchecked
                .iter()
                .any(|note| note.contains("@(Items)")),
            "{:?}",
            inventory.unchecked
        );
    }

    #[test]
    fn ids_differing_only_in_case_are_one_package() {
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="newtonsoft.json" Version="13.0.1" />"#,
            ),
            None,
        )
        .expect("project");
        assert_eq!(packages(&inventory), [("Newtonsoft.Json", "13.0.1")]);
    }

    #[test]
    fn global_package_references_and_packages_config_are_read() {
        let central = parse_central_versions(
            "<Project><ItemGroup><GlobalPackageReference Include=\"System.Text.Encodings.Web\" Version=\"4.5.0\" /></ItemGroup></Project>",
        )
        .expect("props");
        assert_eq!(
            central.global_references(),
            [("System.Text.Encodings.Web".to_string(), "4.5.0".to_string())]
        );
        let legacy = parse_packages_config(
            r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="12.0.1" targetFramework="net472" />
  <package id="Floating" version="1.*" />
</packages>"#,
        )
        .expect("packages.config");
        assert_eq!(packages(&legacy), [("Newtonsoft.Json", "12.0.1")]);
        assert!(legacy
            .unchecked
            .iter()
            .any(|note| note.contains("Floating")));
        assert!(parse_packages_config("<notpackages/>").is_err());
    }

    #[test]
    fn conditional_version_children_and_choose_blocks_are_noted() {
        let inventory = parse_project(
            &project(
                r#"    <PackageReference Include="A">
      <Version Condition="'$(X)' == 'y'">1.0.0</Version>
    </PackageReference>
  </ItemGroup>
  <Choose>
    <When Condition="'$(Os)' == 'win'">
      <ItemGroup><PackageReference Include="B" Version="2.0.0" /></ItemGroup>
    </When>
    <Otherwise>
      <ItemGroup><PackageReference Include="C" Version="3.0.0" /></ItemGroup>
    </Otherwise>
  </Choose>
  <ItemGroup>"#,
            ),
            None,
        )
        .expect("project");
        for id in ["A", "B", "C"] {
            assert!(
                inventory
                    .unchecked
                    .iter()
                    .any(|note| note.starts_with(&format!("{id} ")) && note.contains("condition")),
                "{id}: {:?}",
                inventory.unchecked
            );
        }
    }

    #[test]
    fn duplicate_central_pins_are_noted() {
        let central = parse_central_versions(
            "<Project><ItemGroup><PackageVersion Include=\"A\" Version=\"1.0.0\" Condition=\"'$(X)'=='1'\" /><PackageVersion Include=\"A\" Version=\"2.0.0\" /></ItemGroup></Project>",
        )
        .expect("props");
        assert!(
            central
                .notes()
                .iter()
                .any(|note| note.contains("A") && note.contains("pinned more than once")),
            "{:?}",
            central.notes()
        );
    }

    #[test]
    fn project_files_are_recognised_by_extension() {
        for name in ["App.csproj", "Lib.fsproj", "Legacy.vbproj", "UPPER.CSPROJ"] {
            assert!(is_msbuild_project(std::path::Path::new(name)), "{name}");
        }
        for name in [
            "App.sln",
            "Directory.Packages.props",
            "csproj",
            "x.csproj.user",
        ] {
            assert!(!is_msbuild_project(std::path::Path::new(name)), "{name}");
        }
    }
}
