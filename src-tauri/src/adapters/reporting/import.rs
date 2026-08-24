use serde::Serialize;
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    let mut unmapped = Vec::new();
    let components = parse_components(
        value
            .get("components")
            .and_then(Value::as_array)
            .expect("shape checked by caller"),
        ComponentDialect::OxAudit,
        &mut unmapped,
    );
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
    let components = value
        .get("components")
        .and_then(Value::as_array)
        .map(|items| parse_components(items, ComponentDialect::CycloneDx, &mut unmapped))
        .unwrap_or_default();
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
    let components = parse_components(packages, ComponentDialect::Spdx, &mut unmapped);
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
    values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            parse_component(value, dialect).or_else(|| {
                unmapped.push(format!("component/package {index} has no usable name"));
                None
            })
        })
        .collect()
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
    })
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
