//! Which templates a scan runs. Shared by local-path and live-target scans:
//! the user's filters first, then the rules oxAudit applies whatever the
//! filters say. Every template the user's filters selected that is left out
//! is listed as not evaluated with its reason; nothing is dropped quietly.

use std::collections::BTreeSet;
use std::sync::Arc;

use oxaudit_nuclei::{Protocol, Support, Template};

use super::{severity_label, NotEvaluatedRow, ScanMode, TemplateScanRequest};

/// A loaded template and where it came from.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub pack: String,
    pub file: String,
    pub template: Template,
}

/// A template the scan will run.
#[derive(Debug, Clone)]
pub(crate) struct Selected {
    pub pack: String,
    pub file: String,
    pub template: Arc<Template>,
    /// `<pack>/<templateId>`.
    pub rule_id: String,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Filters {
    pub tags: BTreeSet<String>,
    pub exclude_tags: BTreeSet<String>,
    pub severities: BTreeSet<String>,
    pub ids: BTreeSet<String>,
    pub include_intrusive: bool,
}

fn normalised(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

impl Filters {
    pub fn from_request(request: &TemplateScanRequest) -> Self {
        Self {
            tags: normalised(&request.tags),
            exclude_tags: normalised(&request.exclude_tags),
            severities: normalised(&request.severities),
            ids: normalised(&request.template_ids),
            include_intrusive: request.include_intrusive,
        }
    }

    fn admits(&self, template: &Template) -> bool {
        if !self.ids.is_empty() && !self.ids.contains(&template.id.to_ascii_lowercase()) {
            return false;
        }
        if !self.severities.is_empty()
            && !self
                .severities
                .contains(severity_label(template.info.severity))
        {
            return false;
        }
        if !self.tags.is_empty() && !self.tags.iter().any(|tag| template.has_tag(tag)) {
            return false;
        }
        !self.exclude_tags.iter().any(|tag| template.has_tag(tag))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Selection {
    pub selected: Vec<Selected>,
    pub not_evaluated: Vec<NotEvaluatedRow>,
    pub exclusions: Exclusions,
}

/// Why loaded templates did not become runnable, counted by cause. Filtered
/// templates are not listed as not evaluated (the user asked for them to be
/// left out), so they are only counted here.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exclusions {
    /// Left out by the user's tag, severity or id filters.
    pub filtered: usize,
    /// Tagged `dos`; never run.
    pub dos: usize,
    /// Use features this engine does not evaluate, or have no request blocks.
    pub unsupported: usize,
    /// Tagged `intrusive` or `fuzz` without the switch.
    pub intrusive: usize,
    /// Not applicable to the scan mode (file vs network).
    pub wrong_mode: usize,
}

fn protocol_list(protocols: &BTreeSet<Protocol>) -> String {
    protocols
        .iter()
        .map(|protocol| protocol.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn select(candidates: Vec<Candidate>, filters: &Filters, mode: ScanMode) -> Selection {
    let mut out = Selection::default();
    for candidate in candidates {
        let template = &candidate.template;
        if !filters.admits(template) {
            out.exclusions.filtered += 1;
            continue;
        }
        let row = |protocol: Option<String>, reason: String| NotEvaluatedRow {
            template_id: template.id.clone(),
            pack: candidate.pack.clone(),
            file: candidate.file.clone(),
            protocol,
            target: None,
            reason,
        };
        if template.is_destructive() {
            out.exclusions.dos += 1;
            out.not_evaluated.push(row(
                None,
                "tagged `dos` (denial of service); oxAudit never runs these templates".into(),
            ));
            continue;
        }
        if let Support::NotEvaluated(reasons) = template.support() {
            out.exclusions.unsupported += 1;
            out.not_evaluated.push(row(None, reasons.join("; ")));
            continue;
        }
        if template.is_intrusive() && !filters.include_intrusive {
            out.exclusions.intrusive += 1;
            let tag = if template.has_tag("intrusive") {
                "intrusive"
            } else {
                "fuzz"
            };
            out.not_evaluated.push(row(
                None,
                format!(
                    "tagged `{tag}`; not run unless intrusive templates are switched on for the scan"
                ),
            ));
            continue;
        }
        let protocols = template.protocols();
        if protocols.is_empty() {
            out.exclusions.unsupported += 1;
            out.not_evaluated
                .push(row(None, "has no request blocks to run".into()));
            continue;
        }
        let has_file = protocols.contains(&Protocol::File);
        let has_network = protocols.iter().any(|p| *p != Protocol::File);
        match (mode, has_file, has_network) {
            (ScanMode::Path, false, _) => {
                out.exclusions.wrong_mode += 1;
                out.not_evaluated.push(row(
                    Some(protocol_list(&protocols)),
                    "needs a live target; a local path scan runs file templates only".into(),
                ));
                continue;
            }
            (ScanMode::Targets, _, false) => {
                out.exclusions.wrong_mode += 1;
                out.not_evaluated.push(row(
                    Some(protocol_list(&protocols)),
                    "needs a local path (file protocol only); a live-target scan runs network templates only"
                        .into(),
                ));
                continue;
            }
            _ => {}
        }
        out.selected.push(Selected {
            rule_id: format!("{}/{}", candidate.pack, template.id),
            pack: candidate.pack,
            file: candidate.file,
            template: Arc::new(candidate.template),
        });
    }
    out
}
