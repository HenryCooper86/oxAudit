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
    let review_records = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let format = if review_records > 0 {
        "cyclonedx-vex"
    } else {
        "cyclonedx"
    };
    let mut warnings = Vec::new();
    if review_records > 0 {
        warnings.push("Vulnerability analysis records are previewed but never overwrite local reviews; explicit finding mapping is required before VEX can affect disposition.".into());
    }
    Ok(ImportAnalysis {
        format,
        media_type: "application/vnd.cyclonedx+json",
        content_sha256,
        components,
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
    for (run_index, run) in runs.iter().enumerate() {
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            unmapped.push(format!("SARIF run {run_index} has no results array"));
            continue;
        };
        for (result_index, result) in results.iter().enumerate() {
            if result
                .get("message")
                .and_then(|message| message.get("text"))
                .and_then(Value::as_str)
                .is_some()
            {
                finding_records += 1;
            } else {
                unmapped.push(format!(
                    "SARIF result {run_index}:{result_index} has no message.text"
                ));
            }
        }
    }
    Ok(ImportAnalysis {
        format: "sarif",
        media_type: "application/sarif+json",
        content_sha256,
        components: Vec::new(),
        finding_records,
        review_records: 0,
        unmapped_records: unmapped,
        warnings: vec!["SARIF findings are preview-only until detector trust and path mapping are explicitly accepted; they are not silently promoted to local findings.".into()],
    })
}

fn inspect_openvex(value: &Value, content_sha256: String) -> Result<ImportAnalysis, String> {
    let statements = value
        .get("statements")
        .and_then(Value::as_array)
        .ok_or_else(|| "OpenVEX statements must be an array".to_string())?;
    let mut mapped = 0;
    let mut unmapped = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        let vulnerability = statement
            .get("vulnerability")
            .and_then(|item| item.get("name"))
            .and_then(Value::as_str);
        let status = statement.get("status").and_then(Value::as_str);
        if vulnerability.is_some() && status.is_some() {
            mapped += 1;
        } else {
            unmapped.push(format!(
                "OpenVEX statement {index} lacks vulnerability.name or status"
            ));
        }
    }
    Ok(ImportAnalysis {
        format: "openvex",
        media_type: "application/openvex+json",
        content_sha256,
        components: Vec::new(),
        finding_records: 0,
        review_records: mapped,
        unmapped_records: unmapped,
        warnings: vec!["VEX statements are previewed but never overwrite local reviews; explicit finding mapping and conflict resolution are required.".into()],
    })
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
          "components":[{"type":"library","name":"openssl","version":"3.0.1","purl":"pkg:generic/openssl@3.0.1"}],
          "vulnerabilities":[{"id":"CVE-1","analysis":{"state":"exploitable"}}]
        }"#;
        let analysis = inspect(bytes).unwrap();
        assert_eq!(analysis.format, "cyclonedx-vex");
        assert_eq!(analysis.components.len(), 1);
        assert_eq!(analysis.review_records, 1);
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
    fn unsupported_documents_fail_closed() {
        assert!(inspect(br#"{"hello":"world"}"#).is_err());
    }
}
