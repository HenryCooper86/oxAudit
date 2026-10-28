//! Complete, version-pinned standards schemas. All references resolve from
//! embedded bytes; neither network nor filesystem retrieval is permitted.
use super::ReportFormat;
use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;
use std::sync::OnceLock;

struct BundledOnly;

impl Retrieve for BundledOnly {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = match uri.as_str() {
            "http://cyclonedx.org/schema/spdx.schema.json" => {
                include_str!("schemas/cyclonedx-spdx.json")
            }
            "http://cyclonedx.org/schema/jsf-0.82.schema.json" => {
                include_str!("schemas/cyclonedx-jsf-0.82.json")
            }
            _ => {
                return Err(
                    format!("Unbundled schema reference (retrieval disabled): {uri}").into(),
                )
            }
        };
        Ok(serde_json::from_str(bytes)?)
    }
}

fn compile(schema: &str) -> Result<Validator, String> {
    let value: Value = serde_json::from_str(schema).map_err(|error| error.to_string())?;
    jsonschema::options()
        .with_retriever(BundledOnly)
        .should_validate_formats(true)
        .build(&value)
        .map_err(|error| format!("Cannot compile bundled report schema: {error}"))
}

pub(super) fn validate(value: &Value, format: ReportFormat) -> Result<(), String> {
    static SARIF: OnceLock<Result<Validator, String>> = OnceLock::new();
    static CYCLONEDX: OnceLock<Result<Validator, String>> = OnceLock::new();
    static SPDX: OnceLock<Result<Validator, String>> = OnceLock::new();
    static OPENVEX: OnceLock<Result<Validator, String>> = OnceLock::new();
    let (slot, source) = match format {
        ReportFormat::Sarif => (&SARIF, include_str!("schemas/sarif-2.1.0.json")),
        ReportFormat::CycloneDx | ReportFormat::CycloneDxVex => {
            (&CYCLONEDX, include_str!("schemas/cyclonedx-1.6.json"))
        }
        ReportFormat::Spdx => (&SPDX, include_str!("schemas/spdx-2.3.json")),
        ReportFormat::OpenVex => (&OPENVEX, include_str!("schemas/openvex-0.2.0.json")),
        _ => return Err("No standards schema for this report format".into()),
    };
    // The official SPDX/OpenVEX schemas leave their version/context marker
    // as a generic string. Keep the selected dialect pinned in addition to
    // validating every schema constraint.
    let marker_matches = match format {
        ReportFormat::Spdx => value.get("spdxVersion").and_then(Value::as_str) == Some("SPDX-2.3"),
        ReportFormat::OpenVex => {
            value.get("@context").and_then(Value::as_str) == Some("https://openvex.dev/ns/v0.2.0")
        }
        _ => true,
    };
    if !marker_matches {
        return Err(format!(
            "Generated {format:?} report declares an unsupported schema version"
        ));
    }
    let validator = slot
        .get_or_init(|| compile(source))
        .as_ref()
        .map_err(Clone::clone)?;
    // Paths and schema constraints make failures actionable without echoing
    // potentially sensitive report values into logs or UI error messages.
    if let Some(error) = validator.iter_errors(value).next() {
        return Err(format!(
            "Generated {format:?} report failed schema validation at {} (constraint {})",
            error.instance_path, error.schema_path
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spdx_version_must_match_the_bundled_dialect() {
        // The official SPDX schema types this field as a string, so the
        // selected export dialect additionally pins its version marker.
        let value = serde_json::json!({
            "spdxVersion":"SPDX-9.9", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
            "name":"fixture", "documentNamespace":"https://example.com/fixture",
            "creationInfo":{"creators":["Tool: oxAudit"], "created":"2026-10-28T00:00:00Z"}
        });
        assert!(validate(&value, ReportFormat::Spdx).is_err());
    }

    #[test]
    fn unknown_remote_and_file_references_cannot_be_fetched() {
        for reference in ["https://example.com/unbundled.json", "file:///etc/passwd"] {
            let source = serde_json::json!({"$ref": reference}).to_string();
            assert!(compile(&source).is_err());
        }
    }

    #[test]
    fn cyclonedx_external_license_schema_is_enforced() {
        let mut value = serde_json::json!({
            "bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
            "components":[{"type":"library", "name":"example", "licenses":[{"license":{"id":"MIT"}}]}]
        });
        validate(&value, ReportFormat::CycloneDx).unwrap();
        value["components"][0]["licenses"][0]["license"]["id"] =
            serde_json::json!("invented-license-id");
        assert!(validate(&value, ReportFormat::CycloneDx).is_err());
    }
}
