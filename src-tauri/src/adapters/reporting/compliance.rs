use std::collections::BTreeMap;

use printpdf::{
    BuiltinFont, Color, Mm, Op, PdfDocument, PdfPage, PdfSaveOptions, Point, Pt, Rgb, TextItem,
};

use crate::compliance::{ComplianceReportFormat, ComplianceReportMetadata, ComplianceReview};

pub struct ReportDocument {
    pub assessment: oxaudit_compliance::ComplianceAssessment,
    pub reviews: Vec<ComplianceReview>,
    pub metadata: ComplianceReportMetadata,
    pub generated_at_ms: u64,
}

pub struct GeneratedReport {
    pub bytes: Vec<u8>,
    pub warnings: Vec<String>,
}

pub fn generate(
    report: &ReportDocument,
    format: ComplianceReportFormat,
) -> Result<GeneratedReport, String> {
    let bytes = match format {
        ComplianceReportFormat::Json => generate_json(report)?,
        ComplianceReportFormat::Csv => generate_csv(report).into_bytes(),
        ComplianceReportFormat::Markdown => generate_markdown(report).into_bytes(),
        ComplianceReportFormat::Html => generate_html(report).into_bytes(),
        ComplianceReportFormat::Pdf => generate_pdf(report),
    };
    let mut warnings = Vec::new();
    if report.reviews.is_empty() {
        warnings.push("No human review decisions are recorded; automated evidence coverage is not a conformity decision.".into());
    }
    Ok(GeneratedReport { bytes, warnings })
}

fn generate_json(report: &ReportDocument) -> Result<Vec<u8>, String> {
    let reviews = if report.metadata.include_reviews {
        serde_json::to_value(&report.reviews).map_err(|error| error.to_string())?
    } else {
        serde_json::Value::Array(Vec::new())
    };
    let mut assessment =
        serde_json::to_value(&report.assessment).map_err(|error| error.to_string())?;
    if !report.metadata.include_evidence {
        if let Some(controls) = assessment
            .get_mut("controls")
            .and_then(serde_json::Value::as_array_mut)
        {
            for control in controls {
                control["evidence"] = serde_json::Value::Array(Vec::new());
            }
        }
    }
    let value = serde_json::json!({
        "schemaVersion": 1,
        "documentType": "oxAudit compliance readiness report",
        "claimBoundary": "Evidence readiness only - not certification, legal advice, or a conformity determination.",
        "generatedAtMs": report.generated_at_ms,
        "report": report.metadata,
        "assessment": assessment,
        "reviews": reviews
    });
    serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())
}

fn generate_csv(report: &ReportDocument) -> String {
    let latest = latest_reviews(report);
    let mut output = String::from("control_id,reference,title,automated_status,reviewed_status,assurance,evidence_count,evidence_locators,reviewer,review_note\r\n");
    for control in &report.assessment.controls {
        let review = latest.get(control.control_id.as_str()).copied();
        let evidence = if report.metadata.include_evidence {
            control
                .evidence
                .iter()
                .map(|item| item.locator.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        } else {
            String::new()
        };
        let row = [
            control.control_id.clone(),
            control.reference.clone(),
            control.title.clone(),
            enum_label(control.automated_status),
            review
                .map(|item| enum_label(item.status))
                .unwrap_or_default(),
            format!("{:?}", control.assurance),
            control.evidence.len().to_string(),
            evidence,
            if report.metadata.include_reviews {
                review.map(|item| item.author.clone()).unwrap_or_default()
            } else {
                String::new()
            },
            if report.metadata.include_reviews {
                review.map(|item| item.note.clone()).unwrap_or_default()
            } else {
                String::new()
            },
        ];
        output.push_str(
            &row.iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push_str("\r\n");
    }
    output
}

fn generate_markdown(report: &ReportDocument) -> String {
    let summary = &report.assessment.summary;
    let latest = latest_reviews(report);
    let mut output = format!(
        "# {}\n\n**Organization:** {}  \n**Framework:** {} ({})  \n**Assessment:** `{}`  \n**Target:** `{}`  \n**Assessor:** {}  \n**Classification:** {}  \n**Generated:** {}\n\n> **Readiness boundary:** Evidence coverage is not certification, legal advice, or a determination of conformity.\n\n## Executive summary\n\n{}\n\n## Scope and method\n\n{}\n\nThe bounded collector evaluates filenames, metadata, hashes for eligible evidence documents, and completed oxAudit runs. It does not interpret copyrighted standard text or silently infer human decisions.\n\n## Evidence readiness summary\n\n| Coverage | Supported | Partial | Gap | Manual review | Not applicable |\n|---:|---:|---:|---:|---:|---:|\n| {}% | {} | {} | {} | {} | {} |\n\n## Control matrix\n\n| Reference | Control | Automated evidence | Latest review | Evidence |\n|---|---|---|---|---:|\n",
        md(&report.metadata.title), md(&report.metadata.organization), md(&report.assessment.profile_name), md(&report.assessment.profile_version), md(&report.assessment.id), md(&report.assessment.target_label), md(&report.metadata.assessor), md(&report.metadata.classification), display_time(report.generated_at_ms), md(&report.metadata.executive_summary), md(&report.assessment.metadata.scope), summary.evidence_coverage_percent, summary.supported, summary.partial, summary.gap, summary.manual_review, summary.not_applicable
    );
    for control in &report.assessment.controls {
        let reviewed = latest
            .get(control.control_id.as_str())
            .map(|review| enum_label(review.status))
            .unwrap_or_else(|| "Not reviewed".into());
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md(&control.reference),
            md(&control.title),
            enum_label(control.automated_status),
            reviewed,
            control.evidence.len()
        ));
    }
    output.push_str("\n## Detailed observations\n");
    for control in &report.assessment.controls {
        output.push_str(&format!(
            "\n### {} - {}\n\n{}\n\n- Automated evidence: **{}**\n- Rationale: {}\n",
            md(&control.reference),
            md(&control.title),
            md(&control.objective),
            enum_label(control.automated_status),
            md(&control.rationale)
        ));
        if report.metadata.include_evidence {
            if control.evidence.is_empty() {
                output.push_str("- Evidence: none matched\n");
            } else {
                for evidence in &control.evidence {
                    output.push_str(&format!(
                        "- Evidence: `{}` ({}){}\n",
                        md(&evidence.locator),
                        md(&evidence.kind),
                        evidence
                            .content_sha256
                            .as_ref()
                            .map(|hash| format!(", SHA-256 `{}`", md(hash)))
                            .unwrap_or_default()
                    ));
                }
            }
        }
        if report.metadata.include_reviews {
            if let Some(review) = latest.get(control.control_id.as_str()) {
                output.push_str(&format!(
                    "- Latest review: **{}** by {} - {}\n",
                    enum_label(review.status),
                    md(&review.author),
                    md(&review.note)
                ));
            }
        }
    }
    if report.metadata.include_references {
        output.push_str(&format!(
            "\n## Source reference\n\n- [{}]({})\n\n{}\n",
            md(&report.assessment.source_label),
            report.assessment.source_url,
            md(&report.assessment.disclaimer)
        ));
    }
    output
}

fn generate_html(report: &ReportDocument) -> String {
    let latest = latest_reviews(report);
    let summary = &report.assessment.summary;
    let rows = report.assessment.controls.iter().map(|control| {
        let review = latest.get(control.control_id.as_str()).copied();
        let evidence = if report.metadata.include_evidence && !control.evidence.is_empty() {
            format!("<ul>{}</ul>", control.evidence.iter().map(|item| format!("<li><code>{}</code> <span>{}</span></li>", html(&item.locator), html(&item.kind))).collect::<String>())
        } else { "<p class=muted>No matching evidence displayed.</p>".into() };
        let review_html = if report.metadata.include_reviews {
            review.map(|item| format!("<div class=review><b>{}</b> by {}<br>{}</div>", html(&enum_label(item.status)), html(&item.author), html(&item.note))).unwrap_or_else(|| "<p class=muted>No human decision recorded.</p>".into())
        } else { String::new() };
        format!("<article class=control><header><div><span class=ref>{}</span><h3>{}</h3></div><span class=badge>{}</span></header><p>{}</p><p class=muted>{}</p>{}{}</article>", html(&control.reference), html(&control.title), html(&enum_label(control.automated_status)), html(&control.objective), html(&control.rationale), evidence, review_html)
    }).collect::<String>();
    let references = if report.metadata.include_references {
        format!("<section><h2>Source and boundary</h2><p><a href=\"{}\">{}</a></p><p class=notice>{}</p></section>", html_attr(&report.assessment.source_url), html(&report.assessment.source_label), html(&report.assessment.disclaimer))
    } else {
        String::new()
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#d8dee9;--panel:#f7f9fc;--accent:#2563eb;--warn:#92400e}}*{{box-sizing:border-box}}body{{margin:0;background:#eef2f7;color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}}main{{max-width:1040px;margin:32px auto;background:white;box-shadow:0 16px 48px #1e293b18}}.cover{{padding:64px;background:linear-gradient(135deg,#10213f,#1f4b83);color:white}}.eyebrow,.ref{{font-size:11px;text-transform:uppercase;letter-spacing:.12em;font-weight:700}}h1{{font-size:38px;line-height:1.1;margin:18px 0}}h2{{font-size:19px;margin:0 0 16px}}h3{{font-size:15px;margin:4px 0}}.meta{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:36px}}.meta div{{padding:12px;border:1px solid #ffffff35}}section{{padding:30px 40px;border-bottom:1px solid var(--line)}}.notice{{padding:14px 16px;background:#fff7ed;border-left:4px solid #f59e0b;color:var(--warn)}}.metrics{{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}}.metric{{padding:12px;background:var(--panel);border:1px solid var(--line)}}.metric strong{{display:block;font-size:24px}}.control{{padding:20px 0;border-top:1px solid var(--line)}}.control header{{display:flex;justify-content:space-between;gap:16px}}.badge{{height:max-content;padding:4px 9px;border-radius:99px;background:#e8efff;color:#174ea6;font-size:11px;font-weight:700}}.muted{{color:var(--muted)}}code{{overflow-wrap:anywhere}}.review{{padding:12px;background:#eef8f1;border-left:3px solid #22a06b}}footer{{padding:24px 40px;color:var(--muted);font-size:11px}}@media(max-width:700px){{main{{margin:0}}.cover,section{{padding:24px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.meta{{grid-template-columns:1fr}}}}@media print{{body{{background:white}}main{{margin:0;box-shadow:none}}.control{{break-inside:avoid}}}}</style></head><body><main>
<header class="cover"><div class="eyebrow">oxAudit - Compliance Readiness</div><h1>{}</h1><p>{}</p><div class="meta"><div><small>Framework</small><br><b>{} {}</b></div><div><small>Organization</small><br><b>{}</b></div><div><small>Assessor</small><br><b>{}</b></div><div><small>Classification</small><br><b>{}</b></div></div></header>
<section><h2>Readiness boundary</h2><p class="notice">Evidence coverage is not certification, legal advice, or a determination of conformity. Human and legal review remains required.</p><h2>Executive summary</h2><p>{}</p><p class="muted">Target: <code>{}</code><br>Generated: {}</p></section>
<section><h2>Evidence readiness summary</h2><div class="metrics"><div class="metric"><strong>{}%</strong>Coverage</div><div class="metric"><strong>{}</strong>Supported</div><div class="metric"><strong>{}</strong>Partial</div><div class="metric"><strong>{}</strong>Gaps</div><div class="metric"><strong>{}</strong>Manual</div><div class="metric"><strong>{}</strong>N/A</div></div></section>
<section><h2>Detailed controls</h2>{}</section>{}<footer>Assessment {} - generated by oxAudit - {}</footer></main></body></html>"#,
        html(&report.metadata.title),
        html(&report.metadata.title),
        html(&report.metadata.executive_summary),
        html(&report.assessment.profile_name),
        html(&report.assessment.profile_version),
        html(&report.metadata.organization),
        html(&report.metadata.assessor),
        html(&report.metadata.classification),
        html(&report.metadata.executive_summary),
        html(&report.assessment.target_label),
        display_time(report.generated_at_ms),
        summary.evidence_coverage_percent,
        summary.supported,
        summary.partial,
        summary.gap,
        summary.manual_review,
        summary.not_applicable,
        rows,
        references,
        html(&report.assessment.id),
        html(&display_time(report.generated_at_ms))
    )
}

#[derive(Clone, Copy)]
enum PdfStyle {
    Title,
    Heading,
    Body,
    Muted,
    Status,
}

struct PdfLine {
    text: String,
    style: PdfStyle,
}

fn generate_pdf(report: &ReportDocument) -> Vec<u8> {
    let mut lines = Vec::new();
    push_wrapped(&mut lines, &report.metadata.title, PdfStyle::Title, 48);
    lines.push(PdfLine {
        text: format!(
            "{} - {}",
            report.assessment.profile_name, report.assessment.profile_version
        ),
        style: PdfStyle::Heading,
    });
    lines.push(PdfLine {
        text: format!("Organization: {}", report.metadata.organization),
        style: PdfStyle::Body,
    });
    lines.push(PdfLine {
        text: format!(
            "Assessor: {} | Classification: {}",
            report.metadata.assessor, report.metadata.classification
        ),
        style: PdfStyle::Body,
    });
    lines.push(PdfLine {
        text: format!("Generated: {}", display_time(report.generated_at_ms)),
        style: PdfStyle::Muted,
    });
    lines.push(PdfLine {
        text: String::new(),
        style: PdfStyle::Body,
    });
    lines.push(PdfLine {
        text: "READINESS BOUNDARY".into(),
        style: PdfStyle::Heading,
    });
    push_wrapped(&mut lines, "Evidence coverage is not certification, legal advice, or a determination of conformity. Qualified human review remains required.", PdfStyle::Status, 88);
    lines.push(PdfLine {
        text: "EXECUTIVE SUMMARY".into(),
        style: PdfStyle::Heading,
    });
    push_wrapped(
        &mut lines,
        &report.metadata.executive_summary,
        PdfStyle::Body,
        88,
    );
    lines.push(PdfLine {
        text: "SCOPE".into(),
        style: PdfStyle::Heading,
    });
    push_wrapped(
        &mut lines,
        &report.assessment.metadata.scope,
        PdfStyle::Body,
        88,
    );
    lines.push(PdfLine {
        text: "EVIDENCE READINESS".into(),
        style: PdfStyle::Heading,
    });
    lines.push(PdfLine {
        text: format!(
            "Coverage {}% | Supported {} | Partial {} | Gap {} | Manual {} | N/A {}",
            report.assessment.summary.evidence_coverage_percent,
            report.assessment.summary.supported,
            report.assessment.summary.partial,
            report.assessment.summary.gap,
            report.assessment.summary.manual_review,
            report.assessment.summary.not_applicable
        ),
        style: PdfStyle::Status,
    });
    lines.push(PdfLine {
        text: "CONTROL DETAILS".into(),
        style: PdfStyle::Heading,
    });
    let latest = latest_reviews(report);
    for control in &report.assessment.controls {
        lines.push(PdfLine {
            text: format!("{} - {}", control.reference, control.title),
            style: PdfStyle::Heading,
        });
        lines.push(PdfLine {
            text: format!(
                "Automated evidence: {}",
                enum_label(control.automated_status)
            ),
            style: PdfStyle::Status,
        });
        push_wrapped(&mut lines, &control.objective, PdfStyle::Body, 88);
        push_wrapped(&mut lines, &control.rationale, PdfStyle::Muted, 88);
        if report.metadata.include_evidence {
            for evidence in &control.evidence {
                push_wrapped(
                    &mut lines,
                    &format!("Evidence: {} ({})", evidence.locator, evidence.kind),
                    PdfStyle::Muted,
                    88,
                );
            }
        }
        if report.metadata.include_reviews {
            if let Some(review) = latest.get(control.control_id.as_str()) {
                push_wrapped(
                    &mut lines,
                    &format!(
                        "Review: {} by {} - {}",
                        enum_label(review.status),
                        review.author,
                        review.note
                    ),
                    PdfStyle::Body,
                    88,
                );
            }
        }
        lines.push(PdfLine {
            text: String::new(),
            style: PdfStyle::Body,
        });
    }
    if report.metadata.include_references {
        lines.push(PdfLine {
            text: "SOURCE REFERENCE".into(),
            style: PdfStyle::Heading,
        });
        push_wrapped(
            &mut lines,
            &report.assessment.source_label,
            PdfStyle::Body,
            88,
        );
        push_wrapped(
            &mut lines,
            &report.assessment.source_url,
            PdfStyle::Muted,
            88,
        );
        push_wrapped(
            &mut lines,
            &report.assessment.disclaimer,
            PdfStyle::Status,
            88,
        );
    }
    render_pdf(&report.metadata.title, &report.assessment.id, &lines)
}

fn render_pdf(title: &str, assessment_id: &str, lines: &[PdfLine]) -> Vec<u8> {
    const TOP: f32 = 267.0;
    const BOTTOM: f32 = 24.0;
    let mut page_lines: Vec<Vec<&PdfLine>> = vec![Vec::new()];
    let mut y = TOP;
    for line in lines {
        let height = match line.style {
            PdfStyle::Title => 13.0,
            PdfStyle::Heading => 8.0,
            _ => 6.0,
        };
        let heading_needs_detail_space = matches!(line.style, PdfStyle::Heading) && y < 72.0;
        if y - height < BOTTOM || heading_needs_detail_space {
            page_lines.push(Vec::new());
            y = TOP;
        }
        page_lines.last_mut().unwrap().push(line);
        y -= height;
    }
    let total = page_lines.len();
    let pages = page_lines
        .into_iter()
        .enumerate()
        .map(|(index, page)| {
            let mut ops = Vec::new();
            text_op(
                &mut ops,
                "oxAudit | Compliance Readiness",
                18.0,
                284.0,
                8.0,
                BuiltinFont::HelveticaBold,
                (0.13, 0.29, 0.52),
            );
            text_op(
                &mut ops,
                &format!("{} | Page {} of {}", ascii(assessment_id), index + 1, total),
                18.0,
                12.0,
                7.5,
                BuiltinFont::Helvetica,
                (0.40, 0.44, 0.52),
            );
            let mut y = TOP;
            for line in page {
                let (size, font, color, height) = match line.style {
                    PdfStyle::Title => (24.0, BuiltinFont::HelveticaBold, (0.08, 0.16, 0.28), 13.0),
                    PdfStyle::Heading => {
                        (11.0, BuiltinFont::HelveticaBold, (0.13, 0.29, 0.52), 8.0)
                    }
                    PdfStyle::Body => (9.2, BuiltinFont::Helvetica, (0.10, 0.13, 0.19), 6.0),
                    PdfStyle::Muted => (8.4, BuiltinFont::Helvetica, (0.40, 0.44, 0.52), 6.0),
                    PdfStyle::Status => (9.0, BuiltinFont::HelveticaBold, (0.55, 0.28, 0.05), 6.0),
                };
                if !line.text.is_empty() {
                    text_op(&mut ops, &line.text, 18.0, y, size, font, color);
                }
                y -= height;
            }
            PdfPage::new(Mm(210.0), Mm(297.0), ops)
        })
        .collect::<Vec<_>>();
    let mut document = PdfDocument::new(&ascii(title));
    document
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut Vec::new())
}

fn text_op(
    ops: &mut Vec<Op>,
    text: &str,
    x: f32,
    y: f32,
    size: f32,
    font: BuiltinFont,
    color: (f32, f32, f32),
) {
    ops.extend([
        Op::StartTextSection,
        Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(y)),
        },
        Op::SetFontSizeBuiltinFont {
            size: Pt(size),
            font,
        },
        Op::SetFillColor {
            col: Color::Rgb(Rgb {
                r: color.0,
                g: color.1,
                b: color.2,
                icc_profile: None,
            }),
        },
        Op::WriteTextBuiltinFont {
            items: vec![TextItem::Text(ascii(text))],
            font,
        },
        Op::EndTextSection,
    ]);
}

fn push_wrapped(lines: &mut Vec<PdfLine>, value: &str, style: PdfStyle, width: usize) {
    for paragraph in value.lines() {
        let mut current = String::new();
        for word in ascii(paragraph).split_whitespace() {
            if !current.is_empty() && current.len() + word.len() + 1 > width {
                lines.push(PdfLine {
                    text: current,
                    style,
                });
                current = String::new();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        lines.push(PdfLine {
            text: current,
            style,
        });
    }
}

fn latest_reviews(report: &ReportDocument) -> BTreeMap<&str, &ComplianceReview> {
    let mut latest = BTreeMap::new();
    for review in &report.reviews {
        latest.entry(review.control_id.as_str()).or_insert(review);
    }
    latest
}

fn enum_label<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn display_time(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|time| time.to_rfc3339())
        .unwrap_or_else(|| value.to_string())
}

fn csv_cell(value: &str) -> String {
    let first_non_whitespace = value.trim_start().chars().next();
    let safe = if first_non_whitespace.is_some_and(|character| "=+-@".contains(character)) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}

fn md(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_attr(value: &str) -> String {
    html(value)
}

fn ascii(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\u{2013}' | '\u{2014}' | '\u{2212}' => '-',
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201c}' | '\u{201d}' => '"',
            character if character.is_ascii() && !character.is_control() => character,
            '\n' | '\r' | '\t' => ' ',
            _ => '?',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_compliance::{assess, builtin_profile, AssessmentMetadata, EvidenceSnapshot};

    fn fixture() -> ReportDocument {
        let assessment = assess(
            &builtin_profile("gdpr").unwrap(),
            &EvidenceSnapshot {
                root_label: "/project".into(),
                files: vec![],
                completed_runs: vec![],
                collection_limits: vec!["bounded".into()],
            },
            AssessmentMetadata {
                title: "Readiness".into(),
                organization: "Example".into(),
                assessor: "Reviewer".into(),
                scope: "Product and service".into(),
            },
            "assessment-test".into(),
            1,
        )
        .unwrap();
        ReportDocument {
            assessment,
            reviews: vec![],
            metadata: ComplianceReportMetadata {
                title: "Privacy Readiness Report".into(),
                organization: "Example".into(),
                assessor: "Reviewer".into(),
                classification: "Confidential".into(),
                executive_summary:
                    "This report summarizes evidence readiness and open human-review work.".into(),
                include_evidence: true,
                include_reviews: true,
                include_references: true,
            },
            generated_at_ms: 1,
        }
    }

    #[test]
    fn every_format_has_a_stable_signature() {
        let report = fixture();
        let json = generate(&report, ComplianceReportFormat::Json)
            .unwrap()
            .bytes;
        let csv = generate(&report, ComplianceReportFormat::Csv)
            .unwrap()
            .bytes;
        let markdown = generate(&report, ComplianceReportFormat::Markdown)
            .unwrap()
            .bytes;
        let html = generate(&report, ComplianceReportFormat::Html)
            .unwrap()
            .bytes;
        let pdf = generate(&report, ComplianceReportFormat::Pdf)
            .unwrap()
            .bytes;
        assert!(json.starts_with(b"{"));
        assert!(csv.starts_with(b"control_id"));
        assert!(markdown.starts_with(b"# "));
        assert!(html.starts_with(b"<!doctype html>"));
        assert!(pdf.starts_with(b"%PDF"));
        if let Ok(output_path) = std::env::var("OXAUDIT_PDF_QA_OUTPUT") {
            let output_path = std::path::PathBuf::from(output_path);
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(output_path, pdf).unwrap();
        }
    }

    #[test]
    fn html_escapes_user_controlled_values() {
        let mut report = fixture();
        report.metadata.title = "<script>alert(1)</script>".into();
        let html = String::from_utf8(
            generate(&report, ComplianceReportFormat::Html)
                .unwrap()
                .bytes,
        )
        .unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn csv_cells_neutralize_spreadsheet_formulas() {
        for value in ["=1+1", "+SUM(A1:A2)", "-2+3", "@cmd", " \t=1+1"] {
            let cell = csv_cell(value);
            assert!(
                cell.starts_with("\"'"),
                "formula was not neutralized: {cell}"
            );
            assert!(cell.ends_with('"'));
        }

        assert_eq!(csv_cell("ordinary text"), "\"ordinary text\"");
        assert_eq!(csv_cell("a \"quote\""), "\"a \"\"quote\"\"\"");
    }
}
