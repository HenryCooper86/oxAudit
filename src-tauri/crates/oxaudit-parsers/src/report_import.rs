use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_IMPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct ImportedComponent {
    pub name: String,
    pub version: Option<String>,
    pub supplier: Option<String>,
    pub ecosystem: Option<String>,
    pub purl: Option<String>,
    pub cpes: Vec<String>,
    pub aliases: Vec<String>,
    pub confidence: f32,
    pub source_ref: Option<String>,
    /// Indices in this analysis, resolved only for unambiguous source references.
    pub depends_on: Vec<usize>,
    pub license: Option<String>,
    pub license_metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalClaimLocation {
    pub uri: String,
    pub start_line: Option<u64>,
    pub start_column: Option<u64>,
}

/// A bounded, semantically mapped assertion from an external report.
///
/// These records are deliberately not local Findings or Reviews. Their trust
/// level remains explicit when persisted so a third-party status can never
/// silently close or confirm locally produced evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalClaim {
    pub record_id: String,
    pub claim_kind: String,
    pub producer: String,
    pub rule_id: Option<String>,
    pub vulnerability_id: Option<String>,
    pub subject_ids: Vec<String>,
    pub status: String,
    pub summary: String,
    pub location: Option<ExternalClaimLocation>,
    pub trust: String,
}

impl ImportedComponent {
    pub fn conflict_key(&self) -> String {
        self.purl.clone().unwrap_or_else(|| {
            format!(
                "{}\0{}",
                self.name.trim().to_ascii_lowercase(),
                self.version
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportAnalysis {
    pub format: &'static str,
    pub media_type: &'static str,
    pub content_sha256: String,
    pub components: Vec<ImportedComponent>,
    pub external_claims: Vec<ExternalClaim>,
    pub finding_records: usize,
    pub review_records: usize,
    pub unmapped_records: Vec<String>,
    pub warnings: Vec<String>,
}

impl ImportAnalysis {
    pub fn can_import_inventory(&self) -> bool {
        !self.components.is_empty()
            && matches!(
                self.format,
                "oxaudit-json" | "cyclonedx" | "cyclonedx-vex" | "spdx"
            )
    }
}

pub fn inspect(bytes: &[u8]) -> Result<ImportAnalysis, String> {
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err("the selected report exceeds the 16 MiB import limit".into());
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("the selected report is not valid bounded JSON: {error}"))?;
    let content_sha256 = format!("{:x}", Sha256::digest(bytes));
    if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        return inspect_cyclonedx(&value, content_sha256);
    }
    if value.get("spdxVersion").and_then(Value::as_str) == Some("SPDX-2.3") {
        return inspect_spdx(&value, content_sha256);
    }
    if value.get("version").and_then(Value::as_str) == Some("2.1.0")
        && value.get("runs").and_then(Value::as_array).is_some()
    {
        return inspect_sarif(&value, content_sha256);
    }
    if value.get("@context").is_some()
        && value.get("statements").and_then(Value::as_array).is_some()
    {
        return inspect_openvex(&value, content_sha256);
    }
    if value.get("schemaVersion").and_then(Value::as_u64) == Some(1)
        && value.get("run").is_some()
        && value.get("components").and_then(Value::as_array).is_some()
    {
        return inspect_oxaudit(&value, content_sha256);
    }
    Err("the report is not a supported oxAudit JSON, SARIF 2.1.0, CycloneDX, SPDX 2.3, or OpenVEX document".into())
}

fn inspect_oxaudit(value: &Value, content_sha256: String) -> Result<ImportAnalysis, String> {
    // Keep earlier mapping losses visible when a native export is used as an
    // intermediary. These are imported limitations, not trusted review results.
    let mut unmapped = value
        .pointer("/projection/unmappedRecords")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut components = parse_components(
        value
            .get("components")
            .and_then(Value::as_array)
            .expect("shape checked by caller"),
        ComponentDialect::OxAudit,
        &mut unmapped,
    );
    map_dependencies(
        value,
        ComponentDialect::OxAudit,
        &mut components,
        &mut unmapped,
    );
    if let Some(projection) = native_license_projection(value) {
        let dialect = if projection["sourceLicenseFormat"] == "spdx" {
            ComponentDialect::Spdx
        } else {
            ComponentDialect::CycloneDx
        };
        // Native exports retain rich source licenses in the projection, keyed
        // by the previous canonical ID. Never join these records by name/purl.
        let mut entries = std::collections::BTreeMap::new();
        for entry in projection
            .get("componentMetadata")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = entry.get("componentId").and_then(Value::as_str) {
                entries
                    .entry(id)
                    .and_modify(|value| *value = None)
                    .or_insert(Some(entry));
            }
        }
        let mut counts = std::collections::BTreeMap::new();
        for component in value["components"].as_array().into_iter().flatten() {
            if let Some(id) = source_reference(component, ComponentDialect::OxAudit) {
                *counts.entry(id).or_insert(0) += 1;
            }
        }
        for component in &mut components {
            let Some(id) = component.source_ref.as_deref() else {
                continue;
            };
            match entries.get(id) {
                Some(Some(entry)) if counts.get(id) == Some(&1) => {
                    component.license_metadata = license_metadata(entry, dialect);
                }
                Some(_) => unmapped.push(format!(
                    "native license metadata for {id:?} is ambiguous and was not mapped"
                )),
                None => (),
            }
        }
    }
    let finding_records = value
        .get("observations")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(ImportAnalysis {
        format: "oxaudit-json",
        media_type: "application/vnd.oxaudit.run+json",
        content_sha256,
        components,
        external_claims: Vec::new(),
        finding_records,
        review_records: 0,
        unmapped_records: unmapped,
        warnings: vec![
            "Import creates a separate immutable inventory run; source observations and original identities remain in the previewed report and are not trusted as local detector output.".into(),
        ],
    })
}

/// Recognized source-license projection from a native inventory export. These
/// records remain imported evidence; they do not create local review decisions.
pub fn native_license_projection(document: &Value) -> Option<&Value> {
    let projection = document.get("projection")?;
    matches!(
        projection
            .get("sourceLicenseFormat")
            .and_then(Value::as_str),
        Some("spdx" | "cyclonedx")
    )
    .then_some(projection)
}

fn inspect_cyclonedx(value: &Value, content_sha256: String) -> Result<ImportAnalysis, String> {
    let spec = value
        .get("specVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| "CycloneDX specVersion is required".to_string())?;
    if !matches!(spec, "1.4" | "1.5" | "1.6") {
        return Err(format!(
            "CycloneDX {spec} is not supported; expected 1.4, 1.5, or 1.6"
        ));
    }
    let mut unmapped = Vec::new();
    let mut components = value
        .get("components")
        .and_then(Value::as_array)
        .map(|items| parse_components(items, ComponentDialect::CycloneDx, &mut unmapped))
        .unwrap_or_default();
    if let Some(root) = value.pointer("/metadata/component") {
        components.extend(parse_components(
            std::slice::from_ref(root),
            ComponentDialect::CycloneDx,
            &mut unmapped,
        ));
    }
    map_dependencies(
        value,
        ComponentDialect::CycloneDx,
        &mut components,
        &mut unmapped,
    );
    let vulnerabilities = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let external_claims = map_cyclonedx_vex(value, vulnerabilities, &content_sha256, &mut unmapped);
    let review_records = external_claims.len();
    let format = if vulnerabilities.is_empty() {
        "cyclonedx"
    } else {
        "cyclonedx-vex"
    };
    let mut warnings = Vec::new();
    if !vulnerabilities.is_empty() {
        warnings.push("Mapped CycloneDX VEX records can be retained as external-unverified claims. They never overwrite local reviews or findings.".into());
    }
    Ok(ImportAnalysis {
        format,
        media_type: "application/vnd.cyclonedx+json",
        content_sha256,
        components,
        external_claims,
        finding_records: 0,
        review_records,
        unmapped_records: unmapped,
        warnings,
    })
}

fn inspect_spdx(value: &Value, content_sha256: String) -> Result<ImportAnalysis, String> {
    if value
        .get("documentNamespace")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("SPDX documentNamespace is required".into());
    }
    let packages = value
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "SPDX packages must be an array".to_string())?;
    let mut unmapped = Vec::new();
    let mut components = parse_components(packages, ComponentDialect::Spdx, &mut unmapped);
    map_dependencies(
        value,
        ComponentDialect::Spdx,
        &mut components,
        &mut unmapped,
    );
    Ok(ImportAnalysis {
        format: "spdx",
        media_type: "application/spdx+json",
        content_sha256,
        components,
        external_claims: Vec::new(),
        finding_records: 0,
        review_records: 0,
        unmapped_records: unmapped,
        warnings: Vec::new(),
    })
}

fn inspect_sarif(value: &Value, content_sha256: String) -> Result<ImportAnalysis, String> {
    let runs = value
        .get("runs")
        .and_then(Value::as_array)
        .ok_or_else(|| "SARIF runs must be an array".to_string())?;
    let mut finding_records = 0;
    let mut unmapped = Vec::new();
    let mut external_claims = Vec::new();
    for (run_index, run) in runs.iter().enumerate() {
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            unmapped.push(format!("SARIF run {run_index} has no results array"));
            continue;
        };
        let producer = run
            .pointer("/tool/driver/name")
            .and_then(Value::as_str)
            .and_then(|name| bounded_text(name, 256))
            .map(|name| {
                let version = run
                    .pointer("/tool/driver/semanticVersion")
                    .or_else(|| run.pointer("/tool/driver/version"))
                    .and_then(Value::as_str)
                    .and_then(|version| bounded_text(version, 128));
                version.map_or(name.clone(), |version| format!("{name}@{version}"))
            });
        for (result_index, result) in results.iter().enumerate() {
            let coordinate = format!("SARIF result {run_index}:{result_index}");
            let Some(producer) = producer.as_ref() else {
                unmapped.push(format!("{coordinate} has no bounded tool.driver.name"));
                continue;
            };
            let Some(rule_id) = result
                .get("ruleId")
                .and_then(Value::as_str)
                .and_then(valid_external_identifier)
            else {
                unmapped.push(format!("{coordinate} has no usable ruleId"));
                continue;
            };
            let Some(summary) = result
                .pointer("/message/text")
                .and_then(Value::as_str)
                .and_then(|text| bounded_text(text, 16 * 1024))
            else {
                unmapped.push(format!("{coordinate} has no bounded message.text"));
                continue;
            };
            let Some(location) = map_sarif_location(result) else {
                unmapped.push(format!("{coordinate} has no safe physical location"));
                continue;
            };
            let status = match result.get("level").and_then(Value::as_str) {
                Some("error") => "error",
                Some("warning") => "warning",
                Some("note") => "note",
                Some("none") | None => "unspecified",
                Some(_) => {
                    unmapped.push(format!("{coordinate} has an unsupported level"));
                    continue;
                }
            };
            external_claims.push(ExternalClaim {
                record_id: mapped_record_id(
                    &content_sha256,
                    &format!("sarif\0{run_index}\0{result_index}\0{rule_id}"),
                ),
                claim_kind: "sarif-result".into(),
                producer: producer.clone(),
                rule_id: Some(rule_id),
                vulnerability_id: None,
                subject_ids: vec![location.uri.clone()],
                status: status.into(),
                summary,
                location: Some(location),
                trust: "external-unverified".into(),
            });
            finding_records += 1;
        }
    }
    Ok(ImportAnalysis {
        format: "sarif",
        media_type: "application/sarif+json",
        content_sha256,
        components: Vec::new(),
        external_claims,
        finding_records,
        review_records: 0,
        unmapped_records: unmapped,
        warnings: vec!["Mapped SARIF results can be retained as external-unverified claims. They never become local findings or inherit trust without independent verification.".into()],
    })
}

fn inspect_openvex(value: &Value, content_sha256: String) -> Result<ImportAnalysis, String> {
    let statements = value
        .get("statements")
        .and_then(Value::as_array)
        .ok_or_else(|| "OpenVEX statements must be an array".to_string())?;
    let mut mapped = 0;
    let mut unmapped = Vec::new();
    let mut external_claims = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        let vulnerability = statement
            .get("vulnerability")
            .and_then(|item| item.get("name"))
            .and_then(Value::as_str)
            .and_then(valid_external_identifier);
        let status = statement.get("status").and_then(Value::as_str);
        let allowed_status = status.filter(|status| {
            matches!(
                *status,
                "not_affected" | "affected" | "fixed" | "under_investigation"
            )
        });
        let product_records = statement
            .get("products")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let products = product_records
            .iter()
            .filter_map(|product| product.get("@id").and_then(Value::as_str))
            .filter_map(valid_subject_identifier)
            .collect::<Vec<_>>();
        let detail = statement
            .get("impact_statement")
            .or_else(|| statement.get("status_notes"))
            .and_then(Value::as_str)
            .and_then(|text| bounded_text(text, 16 * 1024));
        let justification = statement
            .get("justification")
            .and_then(Value::as_str)
            .and_then(valid_external_identifier);
        let not_affected_is_qualified =
            allowed_status != Some("not_affected") || justification.is_some() || detail.is_some();
        if let (Some(vulnerability), Some(status)) = (vulnerability, allowed_status) {
            if products.is_empty()
                || products.len() != product_records.len()
                || !not_affected_is_qualified
            {
                unmapped.push(format!(
                    "OpenVEX statement {index} lacks a valid vulnerability, supported status, qualified not_affected rationale, or product @id"
                ));
                continue;
            }
            let summary = detail.unwrap_or_else(|| {
                justification.clone().map_or_else(
                    || format!("External VEX status: {status}"),
                    |justification| format!("External VEX status: {status} ({justification})"),
                )
            });
            external_claims.push(ExternalClaim {
                record_id: mapped_record_id(
                    &content_sha256,
                    &format!("openvex\0{index}\0{vulnerability}"),
                ),
                claim_kind: "vex-statement".into(),
                producer: "OpenVEX document".into(),
                rule_id: None,
                vulnerability_id: Some(vulnerability),
                subject_ids: products,
                status: status.into(),
                summary,
                location: None,
                trust: "external-unverified".into(),
            });
            mapped += 1;
        } else {
            unmapped.push(format!(
                "OpenVEX statement {index} lacks a valid vulnerability, supported status, qualified not_affected rationale, or product @id"
            ));
        }
    }
    Ok(ImportAnalysis {
        format: "openvex",
        media_type: "application/openvex+json",
        content_sha256,
        components: Vec::new(),
        external_claims,
        finding_records: 0,
        review_records: mapped,
        unmapped_records: unmapped,
        warnings: vec!["Mapped VEX statements can be retained as external-unverified claims. A third-party status never overwrites a local review or finding state.".into()],
    })
}

fn map_cyclonedx_vex(
    document: &Value,
    vulnerabilities: &[Value],
    content_sha256: &str,
    unmapped: &mut Vec<String>,
) -> Vec<ExternalClaim> {
    let mut component_refs = std::collections::BTreeSet::new();
    collect_cyclonedx_refs(document.get("components"), &mut component_refs);
    let producer = document
        .pointer("/metadata/tools/components/0/name")
        .and_then(Value::as_str)
        .and_then(|name| bounded_text(name, 256))
        .map(|name| {
            let version = document
                .pointer("/metadata/tools/components/0/version")
                .and_then(Value::as_str)
                .and_then(|version| bounded_text(version, 128));
            version.map_or(name.clone(), |version| format!("{name}@{version}"))
        })
        .unwrap_or_else(|| "CycloneDX document".into());

    vulnerabilities
        .iter()
        .enumerate()
        .filter_map(|(index, vulnerability)| {
            let identifier = vulnerability
                .get("id")
                .and_then(Value::as_str)
                .and_then(valid_external_identifier);
            let status = vulnerability
                .pointer("/analysis/state")
                .and_then(Value::as_str)
                .filter(|status| {
                    matches!(
                        *status,
                        "resolved"
                            | "resolved_with_pedigree"
                            | "exploitable"
                            | "in_triage"
                            | "false_positive"
                            | "not_affected"
                    )
                });
            let affected_records = vulnerability
                .get("affects")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let subjects = affected_records
                        .iter()
                        .filter_map(|affected| affected.get("ref").and_then(Value::as_str))
                        .filter_map(valid_subject_identifier)
                        .collect::<Vec<_>>();
            let subjects_are_known = !subjects.is_empty()
                && subjects.len() == affected_records.len()
                && subjects
                    .iter()
                    .all(|subject| component_refs.contains(subject));
            let detail = vulnerability
                .pointer("/analysis/detail")
                .and_then(Value::as_str)
                .and_then(|text| bounded_text(text, 16 * 1024));
            let justification = vulnerability
                .pointer("/analysis/justification")
                .and_then(Value::as_str)
                .and_then(valid_external_identifier);
            let qualified = !matches!(status, Some("false_positive" | "not_affected"))
                || justification.is_some()
                || detail.is_some();

            let (Some(identifier), Some(status)) = (identifier, status) else {
                unmapped.push(format!(
                    "CycloneDX vulnerability {index} lacks a valid id or supported analysis.state"
                ));
                return None;
            };
            if !subjects_are_known || !qualified {
                unmapped.push(format!(
                    "CycloneDX vulnerability {index} lacks exact component refs or a qualified non-affected rationale"
                ));
                return None;
            }
            let summary = detail.unwrap_or_else(|| {
                justification.clone().map_or_else(
                    || format!("External CycloneDX VEX status: {status}"),
                    |justification| {
                        format!("External CycloneDX VEX status: {status} ({justification})")
                    },
                )
            });
            Some(ExternalClaim {
                record_id: mapped_record_id(
                    content_sha256,
                    &format!("cyclonedx-vex\0{index}\0{identifier}"),
                ),
                claim_kind: "vex-statement".into(),
                producer: producer.clone(),
                rule_id: None,
                vulnerability_id: Some(identifier),
                subject_ids: subjects,
                status: status.into(),
                summary,
                location: None,
                trust: "external-unverified".into(),
            })
        })
        .collect()
}

fn collect_cyclonedx_refs(
    components: Option<&Value>,
    collected: &mut std::collections::BTreeSet<String>,
) {
    let Some(components) = components.and_then(Value::as_array) else {
        return;
    };
    for component in components {
        if let Some(reference) = component
            .get("bom-ref")
            .and_then(Value::as_str)
            .and_then(valid_subject_identifier)
        {
            collected.insert(reference);
        }
        collect_cyclonedx_refs(component.get("components"), collected);
    }
}

fn map_sarif_location(result: &Value) -> Option<ExternalClaimLocation> {
    result
        .get("locations")?
        .as_array()?
        .iter()
        .find_map(|location| {
            let physical = location.get("physicalLocation")?;
            let uri = physical
                .pointer("/artifactLocation/uri")?
                .as_str()
                .and_then(normalize_sarif_uri)?;
            let start_line = positive_u64(physical.pointer("/region/startLine"));
            let start_column = positive_u64(physical.pointer("/region/startColumn"));
            Some(ExternalClaimLocation {
                uri,
                start_line,
                start_column,
            })
        })
}

fn positive_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).filter(|value| *value > 0)
}

fn normalize_sarif_uri(value: &str) -> Option<String> {
    let normalized = valid_subject_identifier(value)?.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    if (lower.contains("://") && !lower.starts_with("file://"))
        || normalized.split('/').any(|segment| segment == "..")
    {
        return None;
    }
    Some(normalized)
}

fn valid_external_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'#' | b'@' | b'+' | b'-')
        }))
    .then(|| value.to_owned())
}

fn valid_subject_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace))
    .then(|| value.to_owned())
}

fn bounded_text(value: &str, max_bytes: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= max_bytes
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t')))
    .then(|| value.to_owned())
}

fn mapped_record_id(content_sha256: &str, coordinate: &str) -> String {
    format!(
        "external_claim_{:x}",
        Sha256::digest(format!("{content_sha256}\0{coordinate}").as_bytes())
    )
}

#[derive(Clone, Copy)]
enum ComponentDialect {
    OxAudit,
    CycloneDx,
    Spdx,
}

fn parse_components(
    values: &[Value],
    dialect: ComponentDialect,
    unmapped: &mut Vec<String>,
) -> Vec<ImportedComponent> {
    let mut components = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if let Some(component) = parse_component(value, dialect) {
            components.push(component);
        } else {
            unmapped.push(format!("component/package {index} has no usable name"));
        }
        // A CycloneDX component may contain a complete nested inventory. A
        // malformed parent must not hide independently usable descendants.
        if matches!(dialect, ComponentDialect::CycloneDx) {
            if let Some(children) = value.get("components").and_then(Value::as_array) {
                components.extend(parse_components(children, dialect, unmapped));
            }
        }
    }
    components
}

fn parse_component(value: &Value, dialect: ComponentDialect) -> Option<ImportedComponent> {
    let name = value.get("name")?.as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    let version_key = if matches!(dialect, ComponentDialect::Spdx) {
        "versionInfo"
    } else {
        "version"
    };
    let version = string_field(value, version_key);
    let supplier = match dialect {
        ComponentDialect::CycloneDx => value
            .get("supplier")
            .and_then(|supplier| supplier.get("name").or(Some(supplier)))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|supplier| !supplier.is_empty())
            .map(str::to_owned),
        ComponentDialect::Spdx => string_field(value, "supplier")
            .filter(|supplier| supplier != "NOASSERTION")
            .map(|supplier| supplier.trim_start_matches("Organization: ").to_string()),
        ComponentDialect::OxAudit => string_field(value, "supplier"),
    };
    let purl = match dialect {
        ComponentDialect::Spdx => value
            .get("externalRefs")
            .and_then(Value::as_array)
            .and_then(|references| {
                references.iter().find_map(|reference| {
                    (reference.get("referenceType").and_then(Value::as_str) == Some("purl"))
                        .then(|| string_field(reference, "referenceLocator"))
                        .flatten()
                })
            }),
        _ => string_field(value, "purl"),
    };
    let mut cpes = match value.get("cpes").and_then(Value::as_array) {
        Some(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        None => Vec::new(),
    };
    if let Some(cpe) = string_field(value, "cpe") {
        cpes.push(cpe);
    }
    cpes.sort();
    cpes.dedup();
    let aliases = value
        .get("aliases")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let confidence = value
        .get("properties")
        .and_then(Value::as_array)
        .and_then(|properties| {
            properties.iter().find_map(|property| {
                (property.get("name").and_then(Value::as_str) == Some("oxaudit:identityConfidence"))
                    .then(|| {
                        property
                            .get("value")
                            .and_then(Value::as_str)?
                            .parse::<f32>()
                            .ok()
                    })
                    .flatten()
            })
        })
        .unwrap_or(0.7)
        .clamp(0.0, 1.0);
    Some(ImportedComponent {
        name: name.to_string(),
        version,
        supplier,
        ecosystem: string_field(value, "ecosystem"),
        purl,
        cpes,
        aliases,
        confidence,
        source_ref: source_reference(value, dialect),
        depends_on: Vec::new(),
        license: match dialect {
            ComponentDialect::OxAudit => string_field(value, "license"),
            ComponentDialect::Spdx => string_field(value, "licenseDeclared"),
            ComponentDialect::CycloneDx => value
                .get("licenses")
                .and_then(Value::as_array)
                .filter(|licenses| licenses.len() == 1)
                .and_then(|licenses| {
                    string_field(&licenses[0], "expression").or_else(|| {
                        licenses[0].get("license").and_then(|license| {
                            string_field(license, "id").or_else(|| string_field(license, "name"))
                        })
                    })
                }),
        },
        license_metadata: license_metadata(value, dialect),
    })
}

fn license_metadata(value: &Value, dialect: ComponentDialect) -> Value {
    let fields: &[&str] = match dialect {
        ComponentDialect::CycloneDx => &["licenses"],
        ComponentDialect::Spdx => &[
            "licenseDeclared",
            "licenseConcluded",
            "licenseInfoFromFiles",
            "licenseComments",
            "copyrightText",
            "attributionTexts",
        ],
        ComponentDialect::OxAudit => &["license"],
    };
    Value::Object(
        fields
            .iter()
            .filter_map(|key| {
                value
                    .get(*key)
                    .map(|value| ((*key).to_string(), value.clone()))
            })
            .collect(),
    )
}

fn source_reference(value: &Value, dialect: ComponentDialect) -> Option<String> {
    let key = match dialect {
        ComponentDialect::CycloneDx => "bom-ref",
        ComponentDialect::Spdx => "SPDXID",
        ComponentDialect::OxAudit => "id",
    };
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn map_dependencies(
    document: &Value,
    dialect: ComponentDialect,
    components: &mut [ImportedComponent],
    unmapped: &mut Vec<String>,
) {
    use std::collections::{BTreeMap, BTreeSet};
    // Count source references before filtering malformed components: even an
    // unusable record makes a duplicate reference ambiguous.
    fn count_refs(value: &Value, dialect: ComponentDialect, counts: &mut BTreeMap<String, usize>) {
        if let Some(reference) = source_reference(value, dialect) {
            *counts.entry(reference).or_default() += 1;
        }
        if matches!(dialect, ComponentDialect::CycloneDx) {
            if let Some(children) = value.get("components").and_then(Value::as_array) {
                for child in children {
                    count_refs(child, dialect, counts);
                }
            }
        }
    }
    let mut counts = BTreeMap::new();
    let component_key = if matches!(dialect, ComponentDialect::Spdx) {
        "packages"
    } else {
        "components"
    };
    if let Some(values) = document.get(component_key).and_then(Value::as_array) {
        for value in values {
            count_refs(value, dialect, &mut counts);
        }
    }
    if matches!(dialect, ComponentDialect::CycloneDx) {
        if let Some(root) = document.pointer("/metadata/component") {
            count_refs(root, dialect, &mut counts);
        }
    }
    for (reference, count) in &counts {
        if *count > 1 {
            unmapped.push(format!("duplicate component reference {reference:?}; dependent relationships are ambiguous and were not mapped"));
        }
    }
    let refs = components
        .iter()
        .enumerate()
        .filter_map(|(index, component)| {
            let reference = component.source_ref.as_ref()?;
            (counts.get(reference) == Some(&1)).then(|| (reference.clone(), index))
        })
        .collect::<BTreeMap<_, _>>();
    let mut edges = Vec::<(String, String)>::new();
    match dialect {
        ComponentDialect::CycloneDx => {
            if let Some(dependencies) = document.get("dependencies") {
                if let Some(dependencies) = dependencies.as_array() {
                    let mut sources = BTreeSet::new();
                    for (index, dependency) in dependencies.iter().enumerate() {
                        let Some(source) = dependency.get("ref").and_then(Value::as_str) else {
                            unmapped.push(format!("dependency {index} has no string ref"));
                            continue;
                        };
                        if !sources.insert(source) {
                            unmapped.push(format!("duplicate dependency record for {source:?}; valid edges were merged"));
                        }
                        if !refs.contains_key(source) {
                            unmapped.push(format!(
                                "dependency source {source:?} is dangling or ambiguous"
                            ));
                        }
                        if let Some(targets) = dependency.get("dependsOn") {
                            if let Some(targets) = targets.as_array() {
                                for target in targets {
                                    if let Some(target) = target.as_str() {
                                        edges.push((source.into(), target.into()));
                                    } else {
                                        unmapped.push(format!("dependency {source:?} has a non-string dependsOn reference"));
                                    }
                                }
                            } else {
                                unmapped.push(format!(
                                    "dependency {source:?} dependsOn is not an array"
                                ));
                            }
                        }
                        if dependency.get("provides").is_some() {
                            unmapped.push(format!("dependency {source:?} provides relationships have no canonical equivalent"));
                        }
                    }
                } else {
                    unmapped.push("CycloneDX dependencies is not an array".into());
                }
            }
        }
        ComponentDialect::Spdx => {
            if let Some(relationships) = document.get("relationships") {
                if let Some(relationships) = relationships.as_array() {
                    for (index, relationship) in relationships.iter().enumerate() {
                        let kind = relationship.get("relationshipType").and_then(Value::as_str);
                        let source = relationship.get("spdxElementId").and_then(Value::as_str);
                        let target = relationship
                            .get("relatedSpdxElement")
                            .and_then(Value::as_str);
                        match (kind, source, target) {
                            (Some("DEPENDS_ON"), Some(source), Some(target)) => edges.push((source.into(), target.into())),
                            (Some("DEPENDENCY_OF"), Some(source), Some(target)) => edges.push((target.into(), source.into())),
                            // Document membership is not a dependency assertion.
                            (Some("DESCRIBES"), Some("SPDXRef-DOCUMENT"), Some(_)) => (),
                            _ => unmapped.push(format!("SPDX relationship {index} ({}) has no canonical dependency mapping", kind.unwrap_or("missing type"))),
                        }
                    }
                } else {
                    unmapped.push("SPDX relationships is not an array".into());
                }
            }
        }
        ComponentDialect::OxAudit => {
            for component in document
                .get("components")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(targets) = component.get("dependsOn") {
                    if let (Some(source), Some(targets)) =
                        (source_reference(component, dialect), targets.as_array())
                    {
                        for target in targets {
                            if let Some(target) = target.as_str() {
                                edges.push((source.clone(), target.into()));
                            } else {
                                unmapped.push(format!(
                                    "dependency {source:?} has a non-string reference"
                                ));
                            }
                        }
                    } else {
                        unmapped.push("component dependencies have no source id or array".into());
                    }
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    for (source, target) in edges {
        match (refs.get(&source), refs.get(&target)) {
            (Some(&source_index), Some(&target_index)) => {
                if seen.insert((source_index, target_index)) {
                    components[source_index].depends_on.push(target_index);
                } else {
                    unmapped.push(format!(
                        "duplicate dependency edge {source:?} -> {target:?}; retained once"
                    ));
                }
            }
            _ => unmapped.push(format!(
                "dependency {source:?} -> {target:?} is dangling or ambiguous and was not mapped"
            )),
        }
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclonedx_import_retains_nested_components_even_under_an_unmapped_parent() {
        let analysis = inspect(br#"{
          "bomFormat":"CycloneDX","specVersion":"1.6",
          "components":[
            {"bom-ref":"parent","name":"parent","components":[
              {"bom-ref":"child","name":"child","version":"2","components":[
                {"bom-ref":"leaf","name":"leaf","version":"3"}
              ]}
            ]},
            {"bom-ref":"nameless","components":[{"bom-ref":"orphan","name":"orphan"}]}
          ],
          "dependencies":[{"ref":"parent","dependsOn":["child"]},{"ref":"child","dependsOn":["leaf"]}]
        }"#).unwrap();
        assert_eq!(
            analysis
                .components
                .iter()
                .map(|component| component.name.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child", "leaf", "orphan"]
        );
        assert_eq!(analysis.unmapped_records.len(), 1);
        assert_eq!(analysis.components[0].depends_on, [1]);
        assert_eq!(analysis.components[1].depends_on, [2]);
    }

    #[test]
    fn cyclonedx_inventory_and_vex_are_detected_without_applying_reviews() {
        let bytes = br#"{
          "bomFormat":"CycloneDX","specVersion":"1.6",
          "components":[{"bom-ref":"pkg:generic/openssl@3.0.1","type":"library","name":"openssl","version":"3.0.1","purl":"pkg:generic/openssl@3.0.1"}],
          "vulnerabilities":[{"id":"CVE-2024-1000","affects":[{"ref":"pkg:generic/openssl@3.0.1"}],"analysis":{"state":"exploitable","detail":"Reachable in the deployed configuration."}}]
        }"#;
        let analysis = inspect(bytes).unwrap();
        assert_eq!(analysis.format, "cyclonedx-vex");
        assert_eq!(analysis.components.len(), 1);
        assert_eq!(analysis.review_records, 1);
        assert_eq!(analysis.external_claims[0].trust, "external-unverified");
        assert!(analysis.can_import_inventory());
        assert!(analysis.warnings[0].contains("never overwrite"));
    }

    #[test]
    fn dependency_mapping_refuses_ambiguous_and_dangling_refs_and_deduplicates_edges() {
        let analysis = inspect(br#"{
            "bomFormat":"CycloneDX","specVersion":"1.6",
            "metadata":{"component":{"bom-ref":"root","name":"root"}},
            "components":[{"bom-ref":"child","name":"child"},{"bom-ref":"dup","name":"a"},{"bom-ref":"dup"}],
            "dependencies":[
                {"ref":"root","dependsOn":["child","child","missing","dup"]},
                {"ref":"root","dependsOn":["child"]},
                {"ref":"missing","dependsOn":[]}
            ]
        }"#).unwrap();
        let root = analysis
            .components
            .iter()
            .find(|component| component.name == "root")
            .unwrap();
        assert_eq!(root.depends_on, [0]);
        for diagnostic in [
            "duplicate component reference",
            "duplicate dependency edge",
            "duplicate dependency record",
            "dangling or ambiguous",
            "no usable name",
        ] {
            assert!(
                analysis
                    .unmapped_records
                    .iter()
                    .any(|record| record.contains(diagnostic)),
                "missing {diagnostic}"
            );
        }
    }

    #[test]
    fn spdx_dependencies_preserve_direction_and_license_assertions() {
        let analysis = inspect(br#"{
            "spdxVersion":"SPDX-2.3","documentNamespace":"https://example.test/bom",
            "packages":[
                {"SPDXID":"SPDXRef-a","name":"a","licenseDeclared":"MIT OR Apache-2.0","licenseConcluded":"NOASSERTION"},
                {"SPDXID":"SPDXRef-b","name":"b","licenseDeclared":"NONE"},
                {"SPDXID":"SPDXRef-c","name":"c","licenseConcluded":"BSD-3-Clause"}
            ],
            "relationships":[
                {"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-b"},
                {"spdxElementId":"SPDXRef-c","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-b"},
                {"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-missing"},
                {"spdxElementId":"SPDXRef-a","relationshipType":"OPTIONAL_DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-b"}
            ]
        }"#).unwrap();
        assert_eq!(analysis.components[0].depends_on, [1]);
        assert_eq!(analysis.components[1].depends_on, [2]);
        assert_eq!(
            analysis.components[0].license.as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(analysis.components[1].license.as_deref(), Some("NONE"));
        // A conclusion must never be relabeled as a declaration.
        assert_eq!(analysis.components[2].license, None);
        assert_eq!(
            analysis.components[2].license_metadata["licenseConcluded"],
            "BSD-3-Clause"
        );
        assert_eq!(analysis.unmapped_records.len(), 2);
    }

    #[test]
    fn native_import_remaps_forward_references_and_cycles_without_purl_guessing() {
        let analysis = inspect(br#"{
            "schemaVersion":1,"run":{},"components":[
                {"id":"old-a","name":"same","purl":"pkg:generic/same@1","license":"MIT","dependsOn":["old-b"]},
                {"id":"old-b","name":"same","purl":"pkg:generic/same@1","dependsOn":["old-a"]}
            ]
        }"#).unwrap();
        assert_eq!(analysis.components[0].depends_on, [1]);
        assert_eq!(analysis.components[1].depends_on, [0]);
        assert_eq!(analysis.components[0].license.as_deref(), Some("MIT"));
        assert!(analysis.unmapped_records.is_empty());
    }

    #[test]
    fn sarif_without_messages_reports_unmapped_records() {
        let analysis = inspect(br#"{"version":"2.1.0","runs":[{"results":[{}]}]}"#).unwrap();
        assert_eq!(analysis.finding_records, 0);
        assert_eq!(analysis.unmapped_records.len(), 1);
        assert!(!analysis.can_import_inventory());
    }

    #[test]
    fn sarif_mapping_requires_tool_rule_message_and_safe_physical_location() {
        let analysis = inspect(
            br#"{"version":"2.1.0","runs":[{
              "tool":{"driver":{"name":"Semgrep","semanticVersion":"1.2.3"}},
              "results":[{"ruleId":"python.sql-injection","level":"error","message":{"text":"Untrusted input reaches SQL."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.py"},"region":{"startLine":42,"startColumn":7}}}]}]
            }]}"#,
        )
        .unwrap();
        assert_eq!(analysis.finding_records, 1);
        assert_eq!(analysis.external_claims.len(), 1);
        assert_eq!(analysis.external_claims[0].producer, "Semgrep@1.2.3");
        assert_eq!(analysis.external_claims[0].subject_ids, ["src/app.py"]);
        assert_eq!(analysis.external_claims[0].trust, "external-unverified");
    }

    #[test]
    fn vex_non_affected_status_needs_a_product_and_rationale() {
        let analysis = inspect(
            br#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
              {"vulnerability":{"name":"CVE-2024-1000"},"products":[{"@id":"pkg:generic/app@1"}],"status":"not_affected"},
              {"vulnerability":{"name":"CVE-2024-1001"},"products":[{"@id":"pkg:generic/app@1"}],"status":"not_affected","justification":"vulnerable_code_not_present"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(analysis.review_records, 1);
        assert_eq!(analysis.unmapped_records.len(), 1);
        assert_eq!(
            analysis.external_claims[0].vulnerability_id.as_deref(),
            Some("CVE-2024-1001")
        );
    }

    #[test]
    fn unsupported_documents_fail_closed() {
        assert!(inspect(br#"{"hello":"world"}"#).is_err());
    }
}
