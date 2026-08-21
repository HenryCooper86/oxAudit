use std::time::{Duration, Instant};

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SymbolKind};
use oxaudit_domain::{
    ArtifactId, CapabilityAvailability, CapabilityDescriptor, CapabilityKind, CreationMethod,
    DataFlowEdge, DataFlowEvidence, DataFlowNode, Evidence, Provenance,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticAnalysisLimits {
    pub max_input_bytes: u64,
    pub max_functions: u32,
    pub max_basic_blocks: u32,
    pub max_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct SemanticInput {
    pub artifact_id: String,
    pub architecture: String,
    pub bytes: Vec<u8>,
    pub limits: SemanticAnalysisLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFinding {
    pub rule_id: String,
    pub function_address: u64,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticAnalysisReport {
    pub architecture: String,
    pub functions_analyzed: u32,
    pub call_edges: u32,
    pub unresolved_edges: u32,
    pub findings: Vec<SemanticFinding>,
    pub limitations: Vec<String>,
}

pub trait SemanticAnalyzer: Send + Sync {
    fn descriptor(&self) -> CapabilityDescriptor;
    fn analyze(&self, input: SemanticInput) -> Result<SemanticAnalysisReport, String>;
}

/// Bounded symbol and relocation analysis. This intentionally stops short of
/// lifting instructions or presenting call presence as attacker-controlled flow.
pub struct BoundedObjectAnalyzer;

impl SemanticAnalyzer for BoundedObjectAnalyzer {
    fn descriptor(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: "oxaudit.semantic.object-calls.v1".into(),
            name: "Bounded object call analysis".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            kind: CapabilityKind::SemanticAnalyzer,
            provenance: Provenance {
                authors: vec!["oxAudit contributors".into()],
                source: "Clean-room object symbol and relocation analysis".into(),
                license: "Apache-2.0".into(),
                creation_method: CreationMethod::Authored,
                content_sha256: "a2d1be87a9871a7c12237808159e500cb22b92283dfa7a6d87ccbe1660e8101f".into(),
            },
            supports_offline: true,
            availability: CapabilityAvailability::Available,
            limitations: vec![
                "Uses symbol tables and relocations only; stripped or statically resolved calls may be invisible.".into(),
                "Does not decompile, lift instructions, or infer attacker-controlled data flow.".into(),
            ],
        }
    }

    fn analyze(&self, input: SemanticInput) -> Result<SemanticAnalysisReport, String> {
        if input.limits.max_input_bytes == 0
            || input.limits.max_functions == 0
            || input.limits.max_basic_blocks == 0
            || input.limits.max_seconds == 0
        {
            return Err("semantic analysis limits must be non-zero".into());
        }
        if input.bytes.len() as u64 > input.limits.max_input_bytes {
            return Err("input exceeds the semantic-analysis byte budget".into());
        }
        let started = Instant::now();
        let deadline = Duration::from_secs(u64::from(input.limits.max_seconds));
        let artifact_id =
            ArtifactId::parse(input.artifact_id).map_err(|error| error.to_string())?;
        let file = object::File::parse(input.bytes.as_slice())
            .map_err(|error| format!("unsupported object file: {error}"))?;
        let mut functions = file
            .symbols()
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.address() > 0)
            .filter_map(|symbol| {
                let name = symbol.name().ok()?.to_owned();
                Some((symbol.address(), symbol.size().max(1), name))
            })
            .take(input.limits.max_functions as usize)
            .collect::<Vec<_>>();
        functions.sort_by_key(|(address, _, _)| *address);
        let dangerous = [
            ("system", "semantic.call.system"),
            ("popen", "semantic.call.popen"),
            ("strcpy", "semantic.call.strcpy"),
            ("gets", "semantic.call.gets"),
            ("sprintf", "semantic.call.sprintf"),
        ];
        let mut findings = Vec::new();
        let mut call_edges = 0_u32;
        let mut unresolved_edges = 0_u32;
        'sections: for section in file.sections() {
            for (offset, relocation) in section.relocations() {
                if started.elapsed() > deadline {
                    return Err("semantic analysis exceeded its time budget".into());
                }
                if call_edges >= input.limits.max_basic_blocks {
                    break 'sections;
                }
                let RelocationTarget::Symbol(index) = relocation.target() else {
                    unresolved_edges = unresolved_edges.saturating_add(1);
                    continue;
                };
                let Ok(target) = file.symbol_by_index(index) else {
                    unresolved_edges = unresolved_edges.saturating_add(1);
                    continue;
                };
                let Ok(target_name) = target.name() else {
                    unresolved_edges = unresolved_edges.saturating_add(1);
                    continue;
                };
                let call_site = section.address().saturating_add(offset);
                let caller = functions.iter().find(|(address, size, _)| {
                    call_site >= *address && call_site < address.saturating_add(*size)
                });
                let Some((caller_address, _, caller_name)) = caller else {
                    unresolved_edges = unresolved_edges.saturating_add(1);
                    continue;
                };
                call_edges = call_edges.saturating_add(1);
                let normalized_target = target_name.trim_start_matches('_');
                if let Some((sink, rule_id)) = dangerous
                    .iter()
                    .find(|(sink, _)| normalized_target == *sink)
                {
                    findings.push(SemanticFinding {
                        rule_id: (*rule_id).into(),
                        function_address: *caller_address,
                        confidence: 0.75,
                        evidence: vec![Evidence::DataFlow(DataFlowEvidence {
                            artifact_id: artifact_id.clone(),
                            entry_point: *caller_address,
                            sink: (*sink).into(),
                            nodes: vec![
                                DataFlowNode {
                                    address: *caller_address,
                                    label: caller_name.clone(),
                                    kind: "function".into(),
                                },
                                DataFlowNode {
                                    address: target.address(),
                                    label: target_name.into(),
                                    kind: "external_sink".into(),
                                },
                            ],
                            edges: vec![DataFlowEdge {
                                from_address: *caller_address,
                                to_address: Some(target.address()),
                                relationship: "relocation_call".into(),
                            }],
                            unresolved_edges: 0,
                        })],
                        limitations: vec![
                            "The call is present; reachability and attacker control were not established.".into(),
                        ],
                    });
                }
            }
        }
        Ok(SemanticAnalysisReport {
            architecture: if input.architecture.trim().is_empty() {
                format!("{:?}", file.architecture())
            } else {
                input.architecture
            },
            functions_analyzed: functions.len() as u32,
            call_edges,
            unresolved_edges,
            findings,
            limitations: self.descriptor().limitations,
        })
    }
}

pub struct DisabledSemanticAnalyzer {
    descriptor: CapabilityDescriptor,
}

impl DisabledSemanticAnalyzer {
    pub fn new(descriptor: CapabilityDescriptor) -> Self {
        Self { descriptor }
    }
}

impl SemanticAnalyzer for DisabledSemanticAnalyzer {
    fn descriptor(&self) -> CapabilityDescriptor {
        self.descriptor.clone()
    }

    fn analyze(&self, _input: SemanticInput) -> Result<SemanticAnalysisReport, String> {
        Err("semantic analysis is not available in this build".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_enforced_before_parsing() {
        let error = BoundedObjectAnalyzer
            .analyze(SemanticInput {
                artifact_id: ArtifactId::new().to_string(),
                architecture: "test".into(),
                bytes: vec![0; 2],
                limits: SemanticAnalysisLimits {
                    max_input_bytes: 1,
                    max_functions: 1,
                    max_basic_blocks: 1,
                    max_seconds: 1,
                },
            })
            .unwrap_err();
        assert!(error.contains("byte budget"));
    }
}
