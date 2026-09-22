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

    /// Build a minimal ELF64 little-endian relocatable object: one function
    /// symbol in `.text`, external calls through `.rela.text` relocations.
    /// Assembling the bytes by hand keeps the fixture deterministic and
    /// cross-platform — no toolchain needed at test time — while still being
    /// a structurally real object file that the `object` crate parses.
    struct Reloc {
        offset: u64,
        symbol: u32,
    }

    fn object_file(relocations: &[Reloc], symbols: &[(&str, Option<u64>, u64)]) -> Vec<u8> {
        // symbols: (name, Some(function byte range start), size) for defined
        // functions; (name, None, _) for undefined externals.
        let mut text = vec![0x90u8; 64];
        text[8] = 0xc3; // somewhere inside the function, for realism
        let mut symtab = Vec::new();
        // Null symbol first, as the format requires.
        symtab.extend_from_slice(&[0u8; 24]);
        let mut strtab = vec![0u8];
        let name_offset = |strtab: &mut Vec<u8>, name: &str| -> u32 {
            let offset = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            offset
        };
        for (name, address, size) in symbols {
            let st_name = name_offset(&mut strtab, name);
            let (st_info, st_shndx, st_value) = match address {
                Some(start) => (0x12u8, 1u16, *start), // GLOBAL FUNC, .text
                None => (0x10, 0, 0),                  // GLOBAL NOTYPE, UNDEF
            };
            symtab.extend_from_slice(&st_name.to_le_bytes());
            symtab.push(st_info);
            symtab.push(0);
            symtab.extend_from_slice(&st_shndx.to_le_bytes());
            symtab.extend_from_slice(&st_value.to_le_bytes());
            symtab.extend_from_slice(&size.to_le_bytes());
        }
        let mut rela = Vec::new();
        for reloc in relocations {
            rela.extend_from_slice(&reloc.offset.to_le_bytes());
            rela.extend_from_slice(&((u64::from(reloc.symbol) << 32) | 4).to_le_bytes()); // R_X86_64_PLT32
            rela.extend_from_slice(&0i64.to_le_bytes());
        }
        let shstrtab_names = [".text", ".rela.text", ".symtab", ".strtab", ".shstrtab"];
        let mut shstrtab = vec![0u8];
        let offsets: Vec<u32> = shstrtab_names
            .iter()
            .map(|name| name_offset(&mut shstrtab, name))
            .collect();

        let mut out = Vec::new();
        let mut ehdr = [0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2; // ELFCLASS64
        ehdr[5] = 1; // little-endian
        ehdr[6] = 1; // version
        ehdr[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        ehdr[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out.extend_from_slice(&ehdr);
        let text_off = out.len() as u64;
        out.extend_from_slice(&text);
        let rela_off = out.len() as u64;
        out.extend_from_slice(&rela);
        let symtab_off = out.len() as u64;
        out.extend_from_slice(&symtab);
        let strtab_off = out.len() as u64;
        out.extend_from_slice(&strtab);
        let shstrtab_off = out.len() as u64;
        out.extend_from_slice(&shstrtab);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let shoff = out.len() as u64;
        let section = |name: u32,
                       kind: u32,
                       offset: u64,
                       size: u64,
                       link: u32,
                       info: u32,
                       entsize: u64,
                       out: &mut Vec<u8>| {
            let mut header = [0u8; 64];
            header[0..4].copy_from_slice(&name.to_le_bytes());
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[0x18..0x20].copy_from_slice(&offset.to_le_bytes());
            header[0x20..0x28].copy_from_slice(&size.to_le_bytes());
            header[0x28..0x2c].copy_from_slice(&link.to_le_bytes());
            header[0x2c..0x30].copy_from_slice(&info.to_le_bytes());
            header[0x38..0x40].copy_from_slice(&entsize.to_le_bytes());
            out.extend_from_slice(&header);
        };
        let text_size = text.len() as u64;
        let rela_size = rela.len() as u64;
        let symtab_size = symtab.len() as u64;
        let strtab_size = strtab.len() as u64;
        let shstrtab_size = shstrtab.len() as u64;
        // NULL section, then the five real ones, in index order.
        out.extend_from_slice(&[0u8; 64]);
        section(offsets[0], 1, text_off, text_size, 0, 0, 0, &mut out);
        section(offsets[1], 4, rela_off, rela_size, 3, 1, 24, &mut out);
        section(offsets[2], 2, symtab_off, symtab_size, 4, 1, 24, &mut out);
        section(offsets[3], 3, strtab_off, strtab_size, 0, 0, 0, &mut out);
        section(
            offsets[4],
            3,
            shstrtab_off,
            shstrtab_size,
            0,
            0,
            0,
            &mut out,
        );
        let shnum = 6u16;
        let shstrndx = 5u16;
        let total = out.len() as u64;
        out[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&shnum.to_le_bytes());
        out[0x3e..0x40].copy_from_slice(&shstrndx.to_le_bytes());
        let _ = total;
        out
    }

    fn limits() -> SemanticAnalysisLimits {
        SemanticAnalysisLimits {
            max_input_bytes: 1024 * 1024,
            max_functions: 100,
            max_basic_blocks: 100,
            max_seconds: 10,
        }
    }

    #[test]
    fn a_call_relocation_to_system_is_reported_with_data_flow_evidence() {
        // worker_fn occupies [8, 40) of .text; the relocation to the external
        // `system` sits at offset 16, inside it.
        let bytes = object_file(
            &[Reloc {
                offset: 16,
                symbol: 2,
            }],
            &[("worker_fn", Some(8), 32), ("system", None, 0)],
        );
        let report = BoundedObjectAnalyzer
            .analyze(SemanticInput {
                artifact_id: ArtifactId::new().to_string(),
                architecture: String::new(),
                bytes,
                limits: limits(),
            })
            .expect("analysis");
        assert_eq!(report.functions_analyzed, 1);
        assert_eq!(report.call_edges, 1);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "semantic.call.system");
        assert_eq!(finding.function_address, 8);
        assert_eq!(finding.confidence, 0.75);
        let Evidence::DataFlow(evidence) = &finding.evidence[0] else {
            panic!("expected data-flow evidence");
        };
        assert_eq!(evidence.entry_point, 8);
        assert_eq!(evidence.sink, "system");
        assert_eq!(evidence.nodes[0].label, "worker_fn");
        assert_eq!(evidence.nodes[1].kind, "external_sink");
        assert_eq!(evidence.edges[0].relationship, "relocation_call");
        assert!(
            finding
                .limitations
                .iter()
                .any(|note| note.contains("reachability and attacker control were not established")),
            "the honesty clause must ride with the finding"
        );
    }

    #[test]
    fn a_call_relocation_to_a_benign_external_counts_but_reports_nothing() {
        let bytes = object_file(
            &[Reloc {
                offset: 20,
                symbol: 2,
            }],
            &[("allocator_init", Some(8), 32), ("malloc", None, 0)],
        );
        let report = BoundedObjectAnalyzer
            .analyze(SemanticInput {
                artifact_id: ArtifactId::new().to_string(),
                architecture: String::new(),
                bytes,
                limits: limits(),
            })
            .expect("analysis");
        assert_eq!(report.call_edges, 1, "the edge is counted");
        assert!(report.findings.is_empty(), "malloc is not a sink");
    }

    #[test]
    fn a_relocation_outside_any_function_is_unresolved_not_a_finding() {
        // Offset 48 sits past worker_fn's [8, 40) range.
        let bytes = object_file(
            &[Reloc {
                offset: 48,
                symbol: 2,
            }],
            &[("worker_fn", Some(8), 32), ("system", None, 0)],
        );
        let report = BoundedObjectAnalyzer
            .analyze(SemanticInput {
                artifact_id: ArtifactId::new().to_string(),
                architecture: String::new(),
                bytes,
                limits: limits(),
            })
            .expect("analysis");
        assert_eq!(report.call_edges, 0);
        assert_eq!(report.unresolved_edges, 1);
        assert!(report.findings.is_empty());
    }

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
